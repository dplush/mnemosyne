"""Safe, offline restore of one explicit Backup Format v2 SQLite store.

The API deliberately has no configured/default target.  It restores into an
absent caller-supplied directory and publishes that directory atomically only
after every selected byte and SQLite check has passed.  The destination parent
must be owned by the effective UID and have no group/world write bits; the
restore never changes caller-owned parent permissions.  An unsafe parent fails
with the redacted ``staging_failed``/``stage`` diagnostic.  Detected staging
mutation fails closed, but an actively malicious same-UID process remains
outside the threat model.  Every pre-publication failure therefore leaves the
private staging namespace in place for operator inspection rather than risking
pathname-based cleanup of a replacement.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import sqlite3
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Collection, NoReturn

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from mnemosyne.dr import artifact_inspector
from mnemosyne.dr.artifact_inspector import InspectionLimits, inspect_backup_artifact
from mnemosyne.dr.backup_v2 import (
    _CatalogLimitExceeded,
    _MANIFEST_FORMAT_CHECKER,
    _catalog,
    _manifest_schema,
    _schema_rows,
    _virtual_modules,
)

_CHUNK_SIZE = 1024 * 1024
_RENAME_NOREPLACE = 1
_SQLITE_HEADER = b"SQLite format 3\x00"
_BLOB_REFERENCE = re.compile(rb"blob://sha256/([0-9a-fA-F]{64})(?![0-9a-fA-F])")
_REFERENCE_SCAN_TABLES = 4_096
_REFERENCE_SCAN_COLUMNS_PER_TABLE = 2_048
_REFERENCE_SCAN_CELLS = 1_000_000
_REFERENCE_SCAN_BYTES = 256 * 1024 * 1024
_REFERENCE_VALUE_BYTES = 16 * 1024 * 1024
_REFERENCE_SCAN_VM_STEPS = 50_000_000
_REFERENCE_SCAN_PROGRESS_INTERVAL = 1_000
_EXTENSION_CAPABILITIES = {"fts5": "fts5", "vec0": "sqlite-vec"}
_SUPPORTED_CAPABILITIES = {"sqlite", *_EXTENSION_CAPABILITIES.values()}


class OfflineRestoreV2Error(RuntimeError):
    """A redacted restore failure with a stable v2 code and phase."""

    def __init__(self, code: str, phase: str) -> None:
        self.code = code
        self.phase = phase
        super().__init__(f"backup v2 restore {phase} failed: {code}")

    def as_diagnostic(self) -> dict[str, str]:
        return {"code": self.code, "phase": self.phase}


def _fail(code: str, phase: str, _error: BaseException | None = None) -> NoReturn:
    raise OfflineRestoreV2Error(code, phase) from None


@dataclass
class _Directory:
    fd: int
    parent: _Directory | None
    name: str
    identity: tuple[int, int]

    def close(self) -> None:
        os.close(self.fd)


@dataclass
class _File:
    fd: int
    parent: _Directory
    name: str
    identity: tuple[int, int]

    def close(self) -> None:
        os.close(self.fd)


def _close_all_best_effort(items: list[object | None]) -> None:
    """Attempt each final close once without replacing the primary outcome."""

    for item in items:
        if item is None:
            continue
        try:
            item.close()  # type: ignore[attr-defined]
        except Exception:
            pass


class _DirectoryMap(dict[tuple[str, ...], _Directory]):
    """Directory lookup kept distinct from the descriptor owner list."""


class _DirectoryList(list[_Directory]):
    """Descriptors owned by extraction until its successful return."""


class _FileList(list[_File]):
    """Descriptors owned by extraction until its successful return."""


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _directory_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _open_directory_path(path: Path) -> _Directory:
    absolute = Path(os.path.abspath(os.fspath(path)))
    descriptor = os.open(os.path.sep, _directory_flags())
    for component in absolute.parts[1:]:
        try:
            child = os.open(component, _directory_flags(), dir_fd=descriptor)
        except Exception:
            os.close(descriptor)
            raise
        try:
            os.close(descriptor)
        except Exception:
            try:
                os.close(child)
            except Exception:
                pass
            raise
        descriptor = child
    try:
        observed = os.fstat(descriptor)
        if not stat.S_ISDIR(observed.st_mode):
            raise NotADirectoryError
        return _Directory(descriptor, None, absolute.name, _identity(observed))
    except Exception:
        os.close(descriptor)
        raise


def _entry_stat(parent: _Directory, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _entry_matches(parent: _Directory, name: str, identity: tuple[int, int]) -> bool:
    observed = _entry_stat(parent, name)
    return observed is not None and _identity(observed) == identity


def _directory_path_matches(path: Path, bound: _Directory) -> bool:
    try:
        reopened = _open_directory_path(path)
    except OSError:
        return False
    try:
        return reopened.identity == bound.identity
    finally:
        reopened.close()


def _require_safe_destination_parent(parent: _Directory) -> None:
    """Reject namespaces where another UID could replace the staging entry."""
    try:
        observed = os.fstat(parent.fd)
        if (
            not stat.S_ISDIR(observed.st_mode)
            or observed.st_uid != os.geteuid()
            or stat.S_IMODE(observed.st_mode) & 0o022
        ):
            raise OSError(errno.EPERM, "unsafe destination parent")
    except OSError as error:
        _fail("staging_failed", "stage", error)


def _open_archive(path: Path) -> tuple[_Directory, _File]:
    try:
        parent = _open_directory_path(path.parent)
    except OSError as error:
        _fail("source_not_found", "verify", error)
    descriptor = -1
    try:
        descriptor = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent.fd,
        )
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode):
            raise OSError(errno.EINVAL, "not regular")
        return parent, _File(descriptor, parent, path.name, _identity(observed))
    except FileNotFoundError as error:
        if descriptor >= 0:
            os.close(descriptor)
        parent.close()
        _fail("source_not_found", "verify", error)
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        parent.close()
        _fail("invalid_argument", "verify", error)


def _file_handle(bound: _File, mode: str) -> BinaryIO:
    descriptor = os.dup(bound.fd)
    try:
        handle = os.fdopen(descriptor, mode)
        handle.seek(0)
        return handle
    except Exception:
        os.close(descriptor)
        raise


def _validated_manifest(
    archive_file: _File, limits: InspectionLimits
) -> dict[str, Any]:
    """Repeat the inspector contract against the retained archive inode."""
    try:
        with _file_handle(archive_file, "rb") as handle:
            result = artifact_inspector._inspect_v2(handle, limits)
        if (
            result.get("status") != "valid"
            or result.get("artifact_format") != "backup-v2"
        ):
            diagnostic = result.get("diagnostics", [{}])[0]
            _fail(str(diagnostic.get("code", "invalid_manifest")), "verify")
        with _file_handle(archive_file, "rb") as handle:
            artifact_inspector._preflight_zip(handle, limits)
            with zipfile.ZipFile(handle, "r", allowZip64=True) as archive:
                infos = archive.infolist()
                artifact_inspector._bounded_zip_metadata(infos, limits)
                manifest_info = next(
                    (info for info in infos if info.filename == "manifest.json"), None
                )
                if manifest_info is None:
                    _fail("missing_entry", "verify")
                raw = artifact_inspector._read_member(
                    archive, manifest_info, limits.manifest_bytes
                )
                manifest = artifact_inspector._json_no_duplicates(raw)
                manifest = artifact_inspector._validate_manifest(manifest, limits)
                Draft202012Validator(
                    _manifest_schema(), format_checker=_MANIFEST_FORMAT_CHECKER
                ).validate(manifest)
                artifact_inspector._enforce_declared_limits(manifest, infos)
                return manifest
    except OfflineRestoreV2Error:
        raise
    except artifact_inspector._InspectionFailure as error:
        _fail(error.code, "verify", error)
    except (
        OSError,
        ValueError,
        KeyError,
        RuntimeError,
        SchemaError,
        ValidationError,
        zipfile.BadZipFile,
    ) as error:
        _fail("invalid_manifest", "verify", error)


def _validate_arguments(
    archive: Path,
    destination: Path,
    store_id: str,
    known_schemas: Collection[tuple[int, str]],
) -> frozenset[tuple[int, str]]:
    if not archive.name or not destination.name or destination.name in {".", ".."}:
        _fail("invalid_argument", "verify")
    if not isinstance(store_id, str) or not artifact_inspector._STORE_ID.fullmatch(
        store_id
    ):
        _fail("invalid_argument", "verify")
    accepted: set[tuple[int, str]] = set()
    try:
        for user_version, fingerprint in known_schemas:
            if (
                isinstance(user_version, bool)
                or not isinstance(user_version, int)
                or user_version < 0
                or not isinstance(fingerprint, str)
                or artifact_inspector._SHA256.fullmatch(fingerprint) is None
            ):
                _fail("invalid_argument", "verify")
            accepted.add((user_version, fingerprint))
    except OfflineRestoreV2Error:
        raise
    except Exception as error:
        _fail("invalid_argument", "verify", error)
    if not accepted:
        _fail("invalid_argument", "verify")
    return frozenset(accepted)


def _select_scope(
    manifest: dict[str, Any],
    store_id: str,
    *,
    allow_partial: bool,
    allow_database_only: bool,
    allow_degraded_capabilities: bool,
) -> tuple[dict[str, Any], list[dict[str, Any]], bool, frozenset[str]]:
    stores = manifest["stores"]
    store_ids = [store["store_id"] for store in stores]
    if len(store_ids) != len(set(store_ids)) or any(
        not isinstance(identifier, str)
        or artifact_inspector._STORE_ID.fullmatch(identifier) is None
        for identifier in store_ids
    ):
        _fail("invalid_manifest", "verify")
    by_store_id = dict(zip(store_ids, stores, strict=True))
    for store in stores:
        dependencies = store.get("dependencies", [])
        if (
            not isinstance(dependencies, list)
            or len(dependencies) != len(set(dependencies))
            or any(
                not isinstance(dependency, str)
                or artifact_inspector._STORE_ID.fullmatch(dependency) is None
                for dependency in dependencies
            )
            or store["store_id"] in dependencies
            or any(dependency not in by_store_id for dependency in dependencies)
        ):
            _fail("invalid_manifest", "verify")

    # Validate the complete declared graph, including optional stores outside
    # the selected scope. A cycle can otherwise hide an incomplete transitive
    # closure behind individually valid dependency IDs.
    states: dict[str, int] = {}
    for root in store_ids:
        if states.get(root, 0) != 0:
            continue
        stack: list[tuple[str, int]] = [(root, 0)]
        while stack:
            current, index = stack[-1]
            if states.get(current, 0) == 0:
                states[current] = 1
            dependencies = by_store_id[current]["dependencies"]
            if index == len(dependencies):
                states[current] = 2
                stack.pop()
                continue
            dependency = dependencies[index]
            stack[-1] = (current, index + 1)
            dependency_state = states.get(dependency, 0)
            if dependency_state == 1:
                _fail("invalid_manifest", "verify")
            if dependency_state == 0:
                stack.append((dependency, 0))

    sqlite_stores = [store for store in stores if store["kind"] == "sqlite"]
    if len(sqlite_stores) != 1 or sqlite_stores[0]["store_id"] != store_id:
        _fail("unknown_store", "verify")
    if any(store["kind"] not in {"sqlite", "blob"} for store in stores):
        _fail("unsupported_format", "verify")
    selected = sqlite_stores[0]
    all_blobs = [store for store in stores if store["kind"] == "blob"]
    closure = {selected["store_id"]}
    pending = list(selected["dependencies"])
    while pending:
        dependency = pending.pop()
        if dependency in closure:
            continue
        closure.add(dependency)
        pending.extend(by_store_id[dependency]["dependencies"])
    blobs = [
        store
        for store in stores
        if store["store_id"] in closure and store["store_id"] != selected["store_id"]
    ]
    if any(blob["kind"] != "blob" for blob in blobs):
        _fail("invalid_manifest", "verify")

    for blob in all_blobs:
        if not blob["required"]:
            continue
        verification = blob["verification"]
        if verification["status"] in {"failed", "unverifiable"} or any(
            check["status"] in {"fail", "unverifiable"}
            for check in verification["checks"]
        ):
            _fail("checksum_mismatch", "verify")
        if blob["store_id"] not in closure:
            # Required package entries cannot be silently omitted, even from a
            # caller-approved partial restore.
            _fail("invalid_manifest", "verify")

    database_only = manifest["self_contained"] is not True
    if database_only and not allow_database_only:
        _fail("blob_missing", "verify")
    if database_only and not allow_partial:
        _fail("discovery_incomplete", "verify")
    incomplete = (
        manifest["status"] != "complete"
        or manifest["discovery"]["state"] != "complete"
        or manifest["coverage"]["state"] != "complete"
    )
    if incomplete and not allow_partial:
        _fail("discovery_incomplete", "verify")

    selected_verification = selected["verification"]
    verification = selected_verification["status"]
    if verification in {"failed", "unverifiable"}:
        _fail("schema_mismatch", "verify")
    metadata = selected["sqlite"]
    required_capabilities = set(metadata.get("required_capabilities", ["sqlite"]))
    optional_capabilities = set(metadata.get("optional_capabilities", []))
    unavailable_capabilities = {
        capability
        for capability in required_capabilities | optional_capabilities
        if any(
            check["name"] == capability.replace("-", "_")
            and check["status"] in {"degraded", "fail", "unverifiable"}
            and check.get("code") == "capability_unavailable"
            for check in selected_verification["checks"]
        )
    }
    if unavailable_capabilities & required_capabilities:
        _fail("capability_unavailable", "verify")
    degraded = frozenset(unavailable_capabilities & optional_capabilities)
    if degraded and not allow_degraded_capabilities:
        _fail("capability_unavailable", "verify")
    if selected["required"] and any(
        check["status"] in {"fail", "unverifiable"}
        for check in selected_verification["checks"]
    ):
        _fail("schema_mismatch", "verify")
    if verification == "verified_degraded":
        # A degraded package is restorable only when every declared degradation
        # is an explicitly optional unavailable capability.
        degraded_checks = {
            check["name"]
            for check in selected_verification["checks"]
            if check["status"] == "degraded"
        }
        optional_check_names = {
            capability.replace("-", "_")
            for capability in unavailable_capabilities & optional_capabilities
        }
        if degraded_checks != optional_check_names or not degraded:
            _fail("capability_unavailable", "verify")
    if manifest["status"] == "failed":
        _fail("discovery_incomplete", "verify")
    return selected, blobs, database_only, degraded


def _create_stage(parent: _Directory) -> _Directory:
    name = f".mnbak-restore-{os.urandom(16).hex()}"
    descriptor = -1
    try:
        os.mkdir(name, 0o700, dir_fd=parent.fd)
        created = _entry_stat(parent, name)
        if created is None or not stat.S_ISDIR(created.st_mode):
            raise OSError(errno.EPERM, "unsafe stage")
        descriptor = os.open(name, _directory_flags(), dir_fd=parent.fd)
        os.fchmod(descriptor, 0o700)
        observed = os.fstat(descriptor)
        if (
            _identity(observed) != _identity(created)
            or observed.st_uid != os.geteuid()
            or stat.S_IMODE(observed.st_mode) != 0o700
        ):
            raise OSError(errno.EPERM, "unsafe stage")
        return _Directory(descriptor, parent, name, _identity(observed))
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        _fail("staging_failed", "stage", error)


def _create_directory(parent: _Directory, name: str) -> _Directory:
    descriptor = -1
    try:
        os.mkdir(name, 0o700, dir_fd=parent.fd)
        created = _entry_stat(parent, name)
        descriptor = os.open(name, _directory_flags(), dir_fd=parent.fd)
        os.fchmod(descriptor, 0o700)
        observed = os.fstat(descriptor)
        if (
            created is None
            or _identity(created) != _identity(observed)
            or observed.st_uid != os.geteuid()
            or stat.S_IMODE(observed.st_mode) != 0o700
        ):
            raise OSError(errno.EPERM, "unsafe directory")
        return _Directory(descriptor, parent, name, _identity(observed))
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        _fail("staging_failed", "extract", error)


def _reserve_file(parent: _Directory, name: str) -> _File:
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent.fd,
        )
        os.fchmod(descriptor, 0o600)
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != os.geteuid()
            or observed.st_nlink != 1
            or stat.S_IMODE(observed.st_mode) != 0o600
        ):
            raise OSError(errno.EPERM, "unsafe file")
        return _File(descriptor, parent, name, _identity(observed))
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        _fail("staging_failed", "extract", error)


def _extract(
    archive_file: _File,
    stage: _Directory,
    stores: list[dict[str, Any]],
) -> tuple[list[_Directory], list[_File]]:
    directories = _DirectoryMap({(): stage})
    created_directories = _DirectoryList()
    files = _FileList()
    try:
        with (
            _file_handle(archive_file, "rb") as handle,
            zipfile.ZipFile(handle) as archive,
        ):
            by_name = {info.filename: info for info in archive.infolist()}
            for store in stores:
                parts = tuple(store["archive_path"].split("/"))
                parent = stage
                for depth in range(1, len(parts)):
                    key = parts[:depth]
                    directory = directories.get(key)
                    if directory is None:
                        directory = _create_directory(parent, parts[depth - 1])
                        enrolled = False
                        try:
                            directories[key] = directory
                            created_directories.append(directory)
                            enrolled = True
                        finally:
                            if not enrolled:
                                directory.close()
                    parent = directory
                target = _reserve_file(parent, parts[-1])
                enrolled = False
                try:
                    files.append(target)
                    enrolled = True
                finally:
                    if not enrolled:
                        target.close()
                digest = hashlib.sha256()
                size = 0
                with archive.open(by_name[store["archive_path"]]) as source:
                    while chunk := source.read(_CHUNK_SIZE):
                        size += len(chunk)
                        if size > store["bytes"]:
                            _fail("size_mismatch", "extract")
                        view = memoryview(chunk)
                        while view:
                            written = os.write(target.fd, view)
                            if written <= 0:
                                raise OSError(errno.EIO, "short write")
                            view = view[written:]
                        digest.update(chunk)
                if size != store["bytes"]:
                    _fail("size_mismatch", "extract")
                if digest.hexdigest() != store["sha256"]:
                    _fail("checksum_mismatch", "extract")
                os.fsync(target.fd)
                if not _entry_matches(target.parent, target.name, target.identity):
                    _fail("staging_failed", "extract")
        return created_directories, files
    except BaseException as error:
        # These descriptors are locally owned until the complete collection is
        # returned to restore_backup_v2. The caller cannot close a partial
        # collection when extraction fails before that ownership transfer.
        for item in files:
            try:
                item.close()
            except BaseException:
                pass
        for directory in reversed(created_directories):
            try:
                directory.close()
            except BaseException:
                pass
        if isinstance(error, OfflineRestoreV2Error):
            raise
        if isinstance(error, (OSError, KeyError, RuntimeError, zipfile.BadZipFile)):
            _fail("checksum_mismatch", "extract", error)
        raise


def _seal_files(files: list[_File]) -> None:
    """Drop every writable stage descriptor before final verification."""
    try:
        for item in files:
            descriptor = -1
            try:
                os.fchmod(item.fd, 0o400)
                os.fsync(item.fd)
                descriptor = os.open(
                    item.name,
                    os.O_RDONLY
                    | getattr(os, "O_BINARY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=item.parent.fd,
                )
                observed = os.fstat(descriptor)
                if (
                    _identity(observed) != item.identity
                    or not stat.S_ISREG(observed.st_mode)
                    or observed.st_uid != os.geteuid()
                    or observed.st_nlink != 1
                    or stat.S_IMODE(observed.st_mode) != 0o400
                ):
                    raise OSError(errno.EPERM, "unsafe sealed file")
                old_descriptor = item.fd
                item.fd = descriptor
                descriptor = -1
                os.close(old_descriptor)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
    except OSError as error:
        _fail("staging_failed", "stage", error)


def _restore_file_modes(files: list[_File]) -> None:
    try:
        for item in files:
            os.fchmod(item.fd, 0o600)
        # fchmod dirties inode metadata. Flush every published regular file
        # after all files have reached their final output mode.
        for item in files:
            os.fsync(item.fd)
    except OSError as error:
        _fail("publish_failed", "publish", error)


def _sealed_files_match(files: list[_File]) -> bool:
    try:
        return all(
            _identity(observed := os.fstat(item.fd)) == item.identity
            and stat.S_ISREG(observed.st_mode)
            and observed.st_uid == os.geteuid()
            and observed.st_nlink == 1
            and stat.S_IMODE(observed.st_mode) == 0o400
            and _entry_matches(item.parent, item.name, item.identity)
            for item in files
        )
    except OSError:
        return False


def _sqlite_uri(descriptor: int) -> str:
    return f"file:/proc/self/fd/{descriptor}?mode=ro&immutable=1"


def _schema_digest(connection: sqlite3.Connection, *, catalog_limit: int) -> str:
    rows = _schema_rows(connection, limit=catalog_limit)
    encoded = json.dumps(rows, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def _quote_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _load_optional_sqlite_vec(connection: sqlite3.Connection) -> bool:
    """Register the packaged sqlite-vec module on this validation connection."""

    extension_loading_enabled = False
    loaded = False
    try:
        import sqlite_vec

        connection.enable_load_extension(True)
        extension_loading_enabled = True
        sqlite_vec.load(connection)
        loaded = True
    except Exception:
        loaded = False
    finally:
        if extension_loading_enabled:
            try:
                connection.enable_load_extension(False)
            except Exception:
                loaded = False
    return loaded


def _actual_blob_references(
    connection: sqlite3.Connection,
    *,
    unavailable_virtual_tables: Collection[str] = (),
) -> frozenset[str]:
    """Enumerate owned blob digests from every stored SQLite byte string.

    Table and column names come from SQLite's catalog but are used only as
    quoted identifiers. Stored generated columns are scanned; views, triggers,
    schema SQL, and virtual/hidden columns are never evaluated. Hard catalog,
    cell, byte, value-size, and VM-step caps turn an incomplete scan into a
    restore failure instead of a completeness claim.
    """
    progress_calls = 0

    def progress() -> int:
        nonlocal progress_calls
        progress_calls += 1
        return int(
            progress_calls * _REFERENCE_SCAN_PROGRESS_INTERVAL
            > _REFERENCE_SCAN_VM_STEPS
        )

    connection.set_progress_handler(progress, _REFERENCE_SCAN_PROGRESS_INTERVAL)
    cells = 0
    scanned_bytes = 0
    digests: set[str] = set()
    try:
        tables = list(
            connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "ORDER BY name LIMIT ?",
                (_REFERENCE_SCAN_TABLES + 1,),
            )
        )
        if len(tables) > _REFERENCE_SCAN_TABLES:
            _fail("limit_exceeded", "restore")
        for (table_name,) in tables:
            if not isinstance(table_name, str):
                _fail("product_smoke_failed", "restore")
            # A declared optional extension may be unavailable under the
            # caller's explicit degraded-restore opt-in. Its virtual table
            # cannot be introspected, but its persisted shadow tables remain
            # ordinary tables and are still scanned below.
            if table_name in unavailable_virtual_tables:
                continue
            columns = list(
                connection.execute(
                    "SELECT name, hidden FROM pragma_table_xinfo(?) "
                    "ORDER BY cid LIMIT ?",
                    (table_name, _REFERENCE_SCAN_COLUMNS_PER_TABLE + 1),
                )
            )
            if len(columns) > _REFERENCE_SCAN_COLUMNS_PER_TABLE:
                _fail("limit_exceeded", "restore")
            quoted_table = _quote_identifier(table_name)
            for column_name, hidden in columns:
                # table_xinfo hidden=3 is GENERATED STORED. hidden=1 belongs to
                # virtual tables and hidden=2 is GENERATED VIRTUAL; neither has
                # an independently stored value to inspect.
                if hidden not in (0, 3):
                    continue
                if not isinstance(column_name, str):
                    _fail("product_smoke_failed", "restore")
                quoted_column = _quote_identifier(column_name)
                # SQLite affinity does not determine the storage class of an
                # individual value.  In particular, bytes bound into a TEXT
                # affinity column remain BLOB values and must not escape the
                # owned-blob completeness check.
                predicate = f"typeof({quoted_column}) IN ('text','blob')"
                count, size, largest = connection.execute(
                    "SELECT COUNT(*), "
                    f"COALESCE(SUM(length(CAST({quoted_column} AS BLOB))), 0), "
                    f"COALESCE(MAX(length(CAST({quoted_column} AS BLOB))), 0) "
                    f"FROM {quoted_table} WHERE {predicate}"
                ).fetchone()
                cells += int(count)
                scanned_bytes += int(size)
                if (
                    cells > _REFERENCE_SCAN_CELLS
                    or scanned_bytes > _REFERENCE_SCAN_BYTES
                    or int(largest) > _REFERENCE_VALUE_BYTES
                ):
                    _fail("limit_exceeded", "restore")
                values = connection.execute(
                    f"SELECT CAST({quoted_column} AS BLOB) "
                    f"FROM {quoted_table} WHERE {predicate}"
                )
                for (value,) in values:
                    if not isinstance(value, bytes):
                        _fail("product_smoke_failed", "restore")
                    digests.update(
                        match.group(1).decode("ascii").lower()
                        for match in _BLOB_REFERENCE.finditer(value)
                    )
        return frozenset(digests)
    finally:
        connection.set_progress_handler(None, 0)


def _capabilities(
    connection: sqlite3.Connection,
    virtual_modules: dict[str, str],
) -> set[str]:
    modules = {str(row[0]).lower() for row in connection.execute("PRAGMA module_list")}
    available = {"sqlite"}
    for module, capability in (("fts5", "fts5"), ("vec0", "sqlite-vec")):
        if module not in modules:
            continue
        try:
            for table, declared_module in virtual_modules.items():
                if declared_module == module:
                    quoted = _quote_identifier(table)
                    connection.execute(f"SELECT 1 FROM {quoted} LIMIT 0")
        except sqlite3.Error:
            # Registration alone is insufficient: an incompatible extension
            # can advertise the module while failing to open its persisted
            # virtual-table representation.
            continue
        available.add(capability)
    return available


def _reconciled_capabilities(
    metadata: dict[str, Any],
    virtual_modules: dict[str, str],
) -> tuple[set[str], set[str]]:
    """Bind manifest capability policy to extension use in staged schema."""

    required = set(metadata.get("required_capabilities", ["sqlite"]))
    optional = set(metadata.get("optional_capabilities", []))
    declared = required | optional
    modules = set(virtual_modules.values())
    if modules - _EXTENSION_CAPABILITIES.keys():
        _fail("capability_unavailable", "restore")
    inferred = {"sqlite"} | {
        _EXTENSION_CAPABILITIES[module] for module in modules
    }
    if (
        required & optional
        or declared - _SUPPORTED_CAPABILITIES
        or declared != inferred
    ):
        _fail("capability_unavailable", "restore")
    return required, optional


def _verify_sqlite(
    image: _File,
    store: dict[str, Any],
    known_schemas: frozenset[tuple[int, str]],
    expected_blob_digests: frozenset[str],
    *,
    catalog_limit: int,
    allow_unpacked_blob_references: bool,
    allow_degraded_capabilities: bool,
) -> tuple[int, frozenset[str]]:
    try:
        _verify_payload(image, store)
        if os.pread(image.fd, len(_SQLITE_HEADER), 0) != _SQLITE_HEADER:
            _fail("sqlite_integrity_failed", "restore")
        connection = sqlite3.connect(_sqlite_uri(image.fd), uri=True)
        try:
            connection.execute("PRAGMA query_only=ON")
            metadata = store["sqlite"]
            schema_rows = _schema_rows(connection, limit=catalog_limit)
            virtual_modules = _virtual_modules(schema_rows)
            required, optional = _reconciled_capabilities(metadata, virtual_modules)
            if "sqlite-vec" in required | optional:
                _load_optional_sqlite_vec(connection)
            available = _capabilities(connection, virtual_modules)
            if not required <= available:
                _fail("capability_unavailable", "restore")
            degraded = frozenset(optional - available)
            if degraded and not allow_degraded_capabilities:
                _fail("capability_unavailable", "restore")
            unavailable_virtual_tables = {
                table
                for table, module in virtual_modules.items()
                if _EXTENSION_CAPABILITIES[module] in degraded
            }
            if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                _fail("sqlite_integrity_failed", "restore")
            if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                _fail("foreign_key_failed", "restore")
            user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            fingerprint = _schema_digest(connection, catalog_limit=catalog_limit)
            if (
                user_version != metadata["user_version"]
                or fingerprint != metadata["schema_sha256"]
            ):
                _fail("schema_mismatch", "restore")
            if (user_version, fingerprint) not in known_schemas:
                _fail("schema_mismatch", "restore")
            if (
                int(connection.execute("PRAGMA page_size").fetchone()[0])
                != metadata["page_size"]
            ):
                _fail("schema_mismatch", "restore")
            if (
                int(connection.execute("PRAGMA page_count").fetchone()[0])
                != metadata["page_count"]
            ):
                _fail("schema_mismatch", "restore")
            if (
                "application_id" in metadata
                and int(connection.execute("PRAGMA application_id").fetchone()[0])
                != metadata["application_id"]
            ):
                _fail("schema_mismatch", "restore")
            catalog, _rows, _unknown, _caps = _catalog(connection, limit=catalog_limit)
            if catalog != store["catalog"]:
                _fail("schema_mismatch", "restore")
            actual_blob_digests = _actual_blob_references(
                connection, unavailable_virtual_tables=unavailable_virtual_tables
            )
            if (
                expected_blob_digests != actual_blob_digests
                and not (
                    allow_unpacked_blob_references
                    and expected_blob_digests <= actual_blob_digests
                )
            ):
                _fail("blob_missing", "restore")
            omitted_blob_count = len(actual_blob_digests - expected_blob_digests)
            # Bounded, non-mutating product smoke: touch the catalog and at most
            # one declared ordinary table without returning any row value.
            connection.execute("SELECT COUNT(*) FROM sqlite_schema").fetchone()
            ordinary = next(
                (
                    item["name"]
                    for item in store["catalog"]
                    if item["object_type"] == "table"
                ),
                None,
            )
            if ordinary is not None:
                quoted = _quote_identifier(ordinary)
                connection.execute(f"SELECT 1 FROM {quoted} LIMIT 1").fetchone()
            return omitted_blob_count, degraded
        finally:
            connection.close()
    except OfflineRestoreV2Error:
        raise
    except _CatalogLimitExceeded as error:
        _fail("limit_exceeded", "restore", error)
    except sqlite3.Error as error:
        _fail("product_smoke_failed", "restore", error)
    except OSError as error:
        _fail("sqlite_integrity_failed", "restore", error)


def _verify_payload(item: _File, store: dict[str, Any]) -> None:
    expected = store["sha256"]
    before = os.fstat(item.fd)
    digest = hashlib.sha256()
    size = 0
    offset = 0
    while chunk := os.pread(item.fd, _CHUNK_SIZE, offset):
        offset += len(chunk)
        size += len(chunk)
        if size > store["bytes"]:
            _fail("size_mismatch", "restore")
        digest.update(chunk)
    after = os.fstat(item.fd)
    if (
        _identity(before) != item.identity
        or _identity(after) != item.identity
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ctime_ns != after.st_ctime_ns
        or size != store["bytes"]
        or digest.hexdigest() != expected
    ):
        _fail("checksum_mismatch", "restore")


def _verify_blob(blob: _File, store: dict[str, Any]) -> None:
    if blob.name != store["sha256"]:
        _fail("invalid_manifest", "restore")
    _verify_payload(blob, store)


def _fsync_tree(stage: _Directory, directories: list[_Directory]) -> None:
    try:
        for directory in reversed(directories):
            os.fsync(directory.fd)
        os.fsync(stage.fd)
    except OSError as error:
        _fail("staging_failed", "stage", error)


def _fsync_published_tree(stage: _Directory, directories: list[_Directory]) -> None:
    try:
        for directory in reversed(directories):
            os.fsync(directory.fd)
        os.fsync(stage.fd)
    except OSError as error:
        _fail("publish_failed", "publish", error)


def _tree_matches(
    stage: _Directory,
    directories: list[_Directory],
    files: list[_File],
) -> bool:
    """Verify the complete retained staging namespace before name-based action."""
    try:
        if stage.parent is None or not _entry_matches(
            stage.parent, stage.name, stage.identity
        ):
            return False
        expected: dict[int, set[str]] = {stage.fd: set()}
        for directory in directories:
            if directory.parent is None or not _entry_matches(
                directory.parent, directory.name, directory.identity
            ):
                return False
            expected.setdefault(directory.parent.fd, set()).add(directory.name)
            expected.setdefault(directory.fd, set())
        for item in files:
            if not _entry_matches(item.parent, item.name, item.identity):
                return False
            expected.setdefault(item.parent.fd, set()).add(item.name)
        return all(
            set(os.listdir(descriptor)) == names
            for descriptor, names in expected.items()
        )
    except OSError:
        return False


def _rename_no_replace_os(parent: _Directory, source: str, destination: str) -> None:
    if os.name != "posix":
        raise OSError(errno.ENOSYS, "renameat2 unavailable")
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "renameat2 unavailable")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if (
        renameat2(
            parent.fd,
            os.fsencode(source),
            parent.fd,
            os.fsencode(destination),
            _RENAME_NOREPLACE,
        )
        != 0
    ):
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number))


def _rename_no_replace(parent: _Directory, source: str, destination: str) -> None:
    try:
        _rename_no_replace_os(parent, source, destination)
    except OSError as error:
        if error.errno == errno.EEXIST:
            _fail("destination_exists", "publish", error)
        _fail("publish_failed", "publish", error)


def restore_backup_v2(
    archive_path: str | os.PathLike[str],
    destination_root: str | os.PathLike[str],
    *,
    store_id: str,
    known_schemas: Collection[tuple[int, str]],
    allow_partial: bool = False,
    allow_database_only: bool = False,
    allow_degraded_capabilities: bool = False,
    limits: InspectionLimits | None = None,
) -> dict[str, Any]:
    """Restore one selected SQLite image and package-declared owned blobs.

    ``destination_root`` must be absent and its parent must already exist.
    ``known_schemas`` is an explicit allowlist of ``(user_version,
    schema_sha256)`` pairs; an empty or unknown policy fails closed.
    """
    try:
        archive_path = Path(archive_path)
        destination_root = Path(destination_root)
    except Exception as error:
        _fail("invalid_argument", "verify", error)
    if (
        (limits is not None and not isinstance(limits, InspectionLimits))
        or not isinstance(allow_partial, bool)
        or not isinstance(allow_database_only, bool)
        or not isinstance(allow_degraded_capabilities, bool)
    ):
        _fail("invalid_argument", "verify")
    accepted_schemas = _validate_arguments(
        archive_path, destination_root, store_id, known_schemas
    )
    limit = limits or InspectionLimits()

    # Required public inspector classification occurs before destination writes.
    inspected = inspect_backup_artifact(archive_path, limits=limit)
    if (
        inspected.get("status") != "valid"
        or inspected.get("artifact_format") != "backup-v2"
    ):
        code = (
            inspected.get("diagnostics", [{}])[0].get("code", "unsupported_format")
            if inspected.get("artifact_format") != "legacy-v1"
            else "unsupported_format"
        )
        _fail(str(code), "verify")

    archive_parent: _Directory | None = None
    archive_file: _File | None = None
    destination_parent: _Directory | None = None
    stage: _Directory | None = None
    directories: list[_Directory] = []
    files: list[_File] = []
    publish_attempted = False
    try:
        archive_parent, archive_file = _open_archive(archive_path)
        manifest = _validated_manifest(archive_file, limit)
        selected, blobs, database_only, manifest_degraded = _select_scope(
            manifest,
            store_id,
            allow_partial=allow_partial,
            allow_database_only=allow_database_only,
            allow_degraded_capabilities=allow_degraded_capabilities,
        )
        try:
            destination_parent = _open_directory_path(destination_root.parent)
        except OSError as error:
            _fail("staging_failed", "stage", error)
        _require_safe_destination_parent(destination_parent)
        if _entry_stat(destination_parent, destination_root.name) is not None:
            _fail("destination_exists", "stage")
        stage = _create_stage(destination_parent)
        directories, files = _extract(archive_file, stage, [selected, *blobs])
        by_path = {
            store["archive_path"]: item
            for store, item in zip([selected, *blobs], files, strict=True)
        }
        expected_blob_digests = frozenset(blob["sha256"] for blob in blobs)
        omitted_blob_count, degraded_capabilities = _verify_sqlite(
            by_path[selected["archive_path"]],
            selected,
            accepted_schemas,
            expected_blob_digests,
            catalog_limit=limit.catalog_objects_per_store,
            allow_unpacked_blob_references=database_only,
            allow_degraded_capabilities=allow_degraded_capabilities,
        )
        for blob in blobs:
            _verify_blob(by_path[blob["archive_path"]], blob)
        _seal_files(files)
        _fsync_tree(stage, directories)
        if not _tree_matches(stage, directories, files) or not _directory_path_matches(
            destination_root.parent, destination_parent
        ):
            _fail("staging_failed", "stage")
        # Re-read every byte from sealed, retained descriptors after all other
        # staging work. Publication is therefore bound to these verified inodes.
        _verify_sqlite(
            by_path[selected["archive_path"]],
            selected,
            accepted_schemas,
            expected_blob_digests,
            catalog_limit=limit.catalog_objects_per_store,
            allow_unpacked_blob_references=database_only,
            allow_degraded_capabilities=allow_degraded_capabilities,
        )
        for blob in blobs:
            _verify_blob(by_path[blob["archive_path"]], blob)
        if not _sealed_files_match(files):
            _fail("staging_failed", "stage")
        publish_attempted = True
        try:
            _rename_no_replace(destination_parent, stage.name, destination_root.name)
        except OfflineRestoreV2Error as error:
            if error.code == "destination_exists":
                # RENAME_NOREPLACE + EEXIST is a certain non-publication.
                publish_attempted = False
            raise
        if not _entry_matches(
            destination_parent, destination_root.name, stage.identity
        ) or not _directory_path_matches(destination_root.parent, destination_parent):
            _fail("publish_failed", "publish")
        _verify_sqlite(
            by_path[selected["archive_path"]],
            selected,
            accepted_schemas,
            expected_blob_digests,
            catalog_limit=limit.catalog_objects_per_store,
            allow_unpacked_blob_references=database_only,
            allow_degraded_capabilities=allow_degraded_capabilities,
        )
        for blob in blobs:
            _verify_blob(by_path[blob["archive_path"]], blob)
        if not _sealed_files_match(files):
            _fail("publish_failed", "publish")
        _restore_file_modes(files)
        # The final mode transition above changes file inode metadata. Flush
        # the published tree bottom-up before committing its name in the
        # destination parent directory.
        _fsync_published_tree(stage, directories)
        os.fsync(destination_parent.fd)
        status = (
            "partial"
            if database_only
            or manifest_degraded
            or degraded_capabilities
            or manifest["status"] != "complete"
            else "complete"
        )
        diagnostics: list[dict[str, Any]] = []
        if omitted_blob_count:
            diagnostics.append(
                {
                    "code": "blob_bytes_excluded",
                    "phase": "restore",
                    "role": "owned_blob",
                    "count": omitted_blob_count,
                }
            )
        degraded_count = len(manifest_degraded | degraded_capabilities)
        if degraded_count:
            diagnostics.append(
                {
                    "code": "capability_unavailable",
                    "phase": "restore",
                    "role": "optional_capability",
                    "count": degraded_count,
                }
            )
        return {
            "status": status,
            "phase": "publish",
            "destination": "explicit_destination",
            "self_contained": False
            if database_only or manifest_degraded or degraded_capabilities
            else bool(manifest["self_contained"]),
            "stores": [
                {
                    "store": "selected_store",
                    "verification": "verified_degraded"
                    if manifest_degraded or degraded_capabilities
                    else "verified",
                },
                *[
                    {
                        "store": "selected_blob",
                        "verification": "verified",
                    }
                    for blob in blobs
                ],
            ],
            "diagnostics": diagnostics,
        }
    except OfflineRestoreV2Error:
        raise
    except OSError as error:
        _fail(
            "publish_failed" if publish_attempted else "staging_failed",
            "publish" if publish_attempted else "stage",
            error,
        )
    except Exception as error:
        _fail(
            "publish_failed" if publish_attempted else "staging_failed",
            "publish" if publish_attempted else "stage",
            error,
        )
    finally:
        # Safe leakage is deliberate.  Before publication, any validation,
        # identity, or operational failure preserves the private stage.  Once
        # publication was attempted, preserve both possible names as uncertain.
        # No failure path unlinks, removes, or renames a pathname after checking
        # its identity because a same-UID replacement can win that gap.
        # Attempt every independently owned descriptor exactly once.  Cleanup
        # close errors must neither mask the primary redacted outcome nor stop
        # teardown of the remaining descriptors.
        _close_all_best_effort(
            [
                *files,
                *reversed(directories),
                stage,
                destination_parent,
                archive_file,
                archive_parent,
            ]
        )
