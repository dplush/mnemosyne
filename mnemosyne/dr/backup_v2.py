"""Additive Backup Format v2 writer.

This module intentionally has no CLI or restore integration. It snapshots one
explicit SQLite database into a bounded, private ``.mnbak`` package and leaves
the legacy disaster-recovery path unchanged.
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
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path
from typing import Any, BinaryIO, NoReturn

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError, ValidationError

from mnemosyne import __version__

_FORMAT = "org.mnemosyne.backup"
_STORE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SOURCE_REVISION = re.compile(r"^[0-9a-f]{7,64}$")
_LOCATION_HINT = re.compile(
    r"^(?:default|shared|triples|query-cache|bank:[0-9a-f]{16,64})$"
)
_VIRTUAL_TABLE = re.compile(
    r"^\s*CREATE\s+VIRTUAL\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+.*?\s+USING\s+([A-Za-z0-9_]+)\b",
    re.IGNORECASE | re.DOTALL,
)
_CHUNK_SIZE = 1024 * 1024
_AT_EMPTY_PATH = 0x1000
_RENAME_NOREPLACE = 1
_MANIFEST_FORMAT_CHECKER = FormatChecker()
_SCHEMA_SQL_VALUE_BYTES = 1024 * 1024
_SCHEMA_SQL_TOTAL_BYTES = 8 * 1024 * 1024


@_MANIFEST_FORMAT_CHECKER.checks("date-time", raises=ValueError)
def _valid_rfc3339_datetime(value: object) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    return parsed.tzinfo is not None


# Writer defaults are the v2 contract's bounded-reader defaults, not its hard
# maxima. This first slice writes one SQLite image and no blob payloads.
_LIMITS = {
    "manifest_bytes": 1024 * 1024,
    "archive_members": 100_000,
    "sqlite_stores": 128,
    "catalog_objects_per_store": 4_096,
    "single_member_bytes": 16 * 1024**3,
    "total_uncompressed_bytes": 64 * 1024**3,
    "compression_ratio": 200,
    "path_bytes": 240,
    "path_depth": 8,
    "diagnostics": 1_000,
    "external_reference_buckets": 64,
}

_AUTHORITATIVE_TABLES = {
    "annotations",
    "audit_log",
    "canonical_facts",
    "conflicts",
    "consolidated_facts",
    "consolidation_log",
    "episodic_memory",
    "facts",
    "gists",
    "graph_edges",
    "harmonic_beliefs",
    "hygiene_audit_log",
    "media_assets",
    "media_moments",
    "memoria_facts",
    "memoria_instructions",
    "memoria_kg",
    "memoria_persona",
    "memoria_preferences",
    "memoria_timelines",
    "memories",
    "memory_audit_events",
    "memory_events",
    "memory_resonance_log",
    "memory_validations",
    "scratchpad",
    "triples",
    "working_memory",
}
_DERIVED_TABLES = {
    "binary_vectors",
    "fts_episodes",
    "fts_facts",
    "fts_working",
    "memory_embeddings",
    "query_cache",
    "vec_episodes",
    "vec_facts",
    "vec_working",
}
_OWNER_DECISION_TABLES = {
    "cost_entries",
    "sync_memory_state",
    "sync_meta",
    "sync_outbox_ack",
}
_FTS5_SHADOW_SUFFIXES = {"config", "content", "data", "docsize", "idx"}
_VEC0_SHADOW_SUFFIXES = {"chunks", "info", "rowids"}
_VEC0_NUMBERED_SHADOW = re.compile(r"^(?:vector_chunks|metadatachunks)[0-9]{2}$")


class BackupV2Error(RuntimeError):
    """A PII-safe v2 writer failure with a stable contract code and phase."""

    def __init__(self, code: str, phase: str) -> None:
        self.code = code
        self.phase = phase
        self.cleanup: dict[str, Any] | None = None
        super().__init__(f"backup v2 {phase} failed: {code}")

    def as_diagnostic(self) -> dict[str, Any]:
        diagnostic: dict[str, Any] = {"code": self.code, "phase": self.phase}
        if self.cleanup is not None:
            diagnostic["cleanup"] = dict(self.cleanup)
        return diagnostic

    def note_cleanup_residual(self, temporary_directory: str | None) -> None:
        self.cleanup = {
            "status": "not_completed",
            "temporary_directory": temporary_directory,
        }


def _fail(code: str, phase: str, _error: BaseException | None = None) -> NoReturn:
    failure = BackupV2Error(code, phase)
    # Underlying SQLite/OS/schema errors can contain paths, values, or URLs.
    raise failure from None


@dataclass
class _BoundDirectory:
    fd: int
    path: Path
    identity: tuple[int, int]

    def close(self) -> None:
        os.close(self.fd)


@dataclass
class _BoundFile:
    fd: int
    parent: _BoundDirectory
    name: str
    identity: tuple[int, int]

    def close(self) -> None:
        os.close(self.fd)


@dataclass
class _WorkingDirectory:
    """A private staging namespace retained independently of its pathname."""

    directory: _BoundDirectory
    parent: _BoundDirectory
    name: str

    @property
    def fd(self) -> int:
        return self.directory.fd

    @property
    def path(self) -> Path:
        return self.directory.path

    @property
    def identity(self) -> tuple[int, int]:
        return self.directory.identity

    def close(self) -> None:
        self.directory.close()


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _directory_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _open_directory(path: Path, *, create: bool) -> _BoundDirectory:
    """Walk to a directory one no-follow component at a time and retain it."""
    absolute = Path(os.path.abspath(os.fspath(path)))
    descriptor = os.open(os.path.sep, _directory_flags())
    for component in absolute.parts[1:]:
        try:
            try:
                child = os.open(component, _directory_flags(), dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(component, 0o777, dir_fd=descriptor)
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
        return _BoundDirectory(descriptor, absolute, _identity(observed))
    except Exception:
        os.close(descriptor)
        raise


def _entry_stat(parent: _BoundDirectory, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _entry_matches(bound: _BoundFile) -> bool:
    observed = _entry_stat(bound.parent, bound.name)
    return observed is not None and _identity(observed) == bound.identity


def _directory_path_matches(bound: _BoundDirectory) -> bool:
    try:
        reopened = _open_directory(bound.path, create=False)
    except OSError:
        return False
    try:
        return reopened.identity == bound.identity
    finally:
        reopened.close()


def _validate_arguments(
    source: Path,
    destination: Path,
    store_id: str,
    location_hint: str,
    source_revision: str | None,
) -> None:
    if not isinstance(store_id, str) or not _STORE_ID.fullmatch(store_id):
        _fail("invalid_argument", "discover")
    if not isinstance(location_hint, str) or not _LOCATION_HINT.fullmatch(
        location_hint
    ):
        _fail("invalid_argument", "discover")
    if source_revision is not None and (
        not isinstance(source_revision, str)
        or not _SOURCE_REVISION.fullmatch(source_revision)
    ):
        _fail("invalid_argument", "discover")
    if destination.suffix != ".mnbak" or source == destination:
        _fail("invalid_argument", "discover")
    if not isinstance(__version__, str) or not 1 <= len(__version__) <= 128:
        _fail("invalid_argument", "discover")


def _open_source(path: Path) -> _BoundFile:
    parent: _BoundDirectory
    try:
        parent = _open_directory(path.parent, create=False)
    except FileNotFoundError as error:
        _fail("source_not_found", "discover", error)
    except OSError as error:
        _fail("invalid_argument", "discover", error)
    name = path.name
    if not name or name in {".", ".."}:
        parent.close()
        _fail("invalid_argument", "discover")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(name, flags, dir_fd=parent.fd)
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        return _BoundFile(descriptor, parent, name, _identity(observed))
    except FileNotFoundError as error:
        if descriptor >= 0:
            os.close(descriptor)
        parent.close()
        _fail("source_not_found", "discover", error)
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        parent.close()
        _fail("invalid_argument", "discover", error)


def _open_destination_parent(path: Path) -> _BoundDirectory:
    try:
        return _open_directory(path.parent, create=True)
    except OSError as error:
        _fail("staging_failed", "stage", error)


def _create_working_directory(parent: _BoundDirectory) -> _WorkingDirectory:
    """Create and retain a private namespace for every temporary artifact."""
    name = f".mnbak-work-{uuid.uuid4().hex}"
    descriptor = -1
    directory_created = False
    created_identity: tuple[int, int] | None = None
    try:
        os.mkdir(name, 0o700, dir_fd=parent.fd)
        directory_created = True
        created = _entry_stat(parent, name)
        if created is None or (
            not stat.S_ISDIR(created.st_mode) or created.st_uid != os.geteuid()
        ):
            raise OSError(errno.EPERM, "unsafe working directory")
        created_identity = _identity(created)
        descriptor = os.open(name, _directory_flags(), dir_fd=parent.fd)
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(observed.st_mode)
            or observed.st_uid != os.geteuid()
            or _identity(observed) != _identity(created)
        ):
            raise OSError(errno.EPERM, "unsafe working directory")
        os.fchmod(descriptor, 0o700)
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(observed.st_mode)
            or stat.S_IMODE(observed.st_mode) != 0o700
            or observed.st_uid != os.geteuid()
            or _identity(observed) != _identity(created)
        ):
            raise OSError(errno.EPERM, "unsafe working directory")
        directory = _BoundDirectory(descriptor, parent.path / name, _identity(observed))
        return _WorkingDirectory(directory, parent, name)
    except OSError as error:
        if descriptor >= 0 and created_identity is not None:
            retained = _retained_directory_path(descriptor, created_identity)
            try:
                os.close(descriptor)
            except OSError:
                pass
        else:
            retained = None
        if not directory_created:
            _fail("staging_failed", "stage", error)
        # If mkdir succeeded but the directory could not be retained, leave
        # its uncertain pathname untouched rather than risk removing a
        # replacement by name, and expose only the required local cleanup path.
        failure = BackupV2Error("staging_failed", "stage")
        failure.note_cleanup_residual(retained)
        raise failure from None
    except BaseException:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except BaseException:
                pass
        raise


def _reserve_file(parent: _BoundDirectory, name: str, phase: str) -> _BoundFile:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=parent.fd)
        os.fchmod(descriptor, 0o600)
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISREG(observed.st_mode)
            or stat.S_IMODE(observed.st_mode) != 0o600
            or observed.st_uid != os.geteuid()
            or observed.st_nlink != 1
        ):
            raise OSError(errno.EINVAL, "unsafe staging inode")
        return _BoundFile(descriptor, parent, name, _identity(observed))
    except OSError as error:
        if descriptor >= 0:
            # The pathname may have been replaced after validation failed.
            # Closing the retained descriptor is safe; unlinking by name is not.
            os.close(descriptor)
        _fail("staging_failed", phase, error)


def _file_handle(bound: _BoundFile, mode: str) -> BinaryIO:
    descriptor = os.dup(bound.fd)
    try:
        handle = os.fdopen(descriptor, mode)
        handle.seek(0)
        return handle
    except Exception:
        os.close(descriptor)
        raise


def _sqlite_fd_uri(descriptor: int, mode: str) -> str:
    return f"file:/proc/self/fd/{descriptor}?mode={mode}"


def _open_source_connection(source: _BoundFile) -> sqlite3.Connection:
    """Open and pin a read transaction while the retained name is unchanged."""
    connection: sqlite3.Connection | None = None
    try:
        if not _entry_matches(source):
            _fail("snapshot_failed", "snapshot")
        connection = sqlite3.connect(_sqlite_fd_uri(source.fd, "ro"), uri=True)
        connection.execute("BEGIN")
        connection.execute("SELECT COUNT(*) FROM sqlite_schema").fetchone()
        if not _entry_matches(source):
            _fail("snapshot_failed", "snapshot")
        return connection
    except BackupV2Error:
        if connection is not None:
            connection.close()
        raise
    except sqlite3.Error as error:
        if connection is not None:
            connection.close()
        _fail("snapshot_failed", "snapshot", error)


def _snapshot(
    source: _BoundFile,
    snapshot: _BoundFile,
    source_connection: sqlite3.Connection,
) -> None:
    try:
        snapshot_connection = sqlite3.connect(
            _sqlite_fd_uri(snapshot.fd, "rw"), uri=True
        )
        try:
            source_connection.backup(snapshot_connection)
        finally:
            snapshot_connection.close()
        if not _entry_matches(source):
            _fail("snapshot_failed", "snapshot")
        os.fchmod(snapshot.fd, 0o600)
        os.fsync(snapshot.fd)
        if not _entry_matches(snapshot):
            _fail("staging_failed", "stage")
    except BackupV2Error:
        raise
    except sqlite3.Error as error:
        _fail("snapshot_failed", "snapshot", error)
    except OSError as error:
        _fail("staging_failed", "stage", error)


def _quote_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


class _CatalogLimitExceeded(RuntimeError):
    """The bounded SQLite schema query returned its overflow sentinel."""


def _schema_rows(
    connection: sqlite3.Connection,
    *,
    limit: int,
) -> list[tuple[str, str, str, str | None]]:
    # Read only the SQL byte lengths in the bounded catalog pass.  Selecting
    # ``sql`` here would hand an arbitrarily large value to Python before it
    # could enforce either limit.
    cursor = connection.execute(
        "SELECT rowid, type, name, tbl_name, "
        "CASE WHEN sql IS NULL THEN NULL ELSE length(CAST(sql AS BLOB)) END "
        "FROM sqlite_schema "
        "WHERE name NOT LIKE 'sqlite_stat%' ORDER BY type, name LIMIT ?",
        (limit + 1,),
    )
    metadata: list[tuple[int, str, str, str, int | None]] = []
    total_sql_bytes = 0
    for rowid, kind, name, table, sql_bytes in cursor:
        if len(metadata) == limit:
            raise _CatalogLimitExceeded from None
        rendered_kind = str(kind)
        rendered_name = str(name)
        rendered_table = str(table)
        if not (1 <= len(rendered_name) <= 255 and 1 <= len(rendered_table) <= 255):
            raise _CatalogLimitExceeded from None
        if sql_bytes is not None:
            if (
                not isinstance(sql_bytes, int)
                or sql_bytes < 0
                or sql_bytes > _SCHEMA_SQL_VALUE_BYTES
            ):
                raise _CatalogLimitExceeded from None
            total_sql_bytes += sql_bytes
            if total_sql_bytes > _SCHEMA_SQL_TOTAL_BYTES:
                raise _CatalogLimitExceeded from None
        metadata.append(
            (int(rowid), rendered_kind, rendered_name, rendered_table, sql_bytes)
        )

    result: list[tuple[str, str, str, str | None]] = []
    for rowid, kind, name, table, expected_bytes in metadata:
        row = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE rowid = ? "
            "AND (sql IS NULL OR length(CAST(sql AS BLOB)) <= ?)",
            (rowid, _SCHEMA_SQL_VALUE_BYTES),
        ).fetchone()
        if row is None:
            raise _CatalogLimitExceeded from None
        sql = row[0]
        if sql is not None and (
            not isinstance(sql, str) or len(sql.encode("utf-8")) != expected_bytes
        ):
            raise _CatalogLimitExceeded from None
        result.append((kind, name, table, sql))
    return result


def _virtual_modules(
    rows: list[tuple[str, str, str, str | None]],
) -> dict[str, str]:
    modules: dict[str, str] = {}
    for kind, name, _table, sql in rows:
        if kind != "table" or not sql:
            continue
        match = _VIRTUAL_TABLE.match(sql)
        if match:
            modules[name] = match.group(1).lower()
    return modules


def _recognized_shadow(name: str, virtual_modules: dict[str, str]) -> bool:
    for parent, module in virtual_modules.items():
        prefix = parent + "_"
        if not name.startswith(prefix):
            continue
        suffix = name[len(prefix) :]
        if module == "fts5" and suffix in _FTS5_SHADOW_SUFFIXES:
            return True
        if module == "vec0" and (
            suffix in _VEC0_SHADOW_SUFFIXES or _VEC0_NUMBERED_SHADOW.fullmatch(suffix)
        ):
            return True
    return False


def _table_classification(name: str, virtual_modules: dict[str, str]) -> str:
    if name in _AUTHORITATIVE_TABLES or name == "sqlite_sequence":
        return "authoritative"
    if name in _DERIVED_TABLES:
        return "derived/rebuildable"
    if name in _OWNER_DECISION_TABLES:
        return "unknown/owner decision required"
    if _recognized_shadow(name, virtual_modules):
        return "derived/rebuildable"
    return "unknown/owner decision required"


def _catalog(
    connection: sqlite3.Connection,
    *,
    limit: int,
) -> tuple[
    list[dict[str, Any]], list[tuple[str, str, str, str | None]], bool, list[str]
]:
    rows = _schema_rows(connection, limit=limit)
    virtual_modules = _virtual_modules(rows)
    table_classes = {
        name: _table_classification(name, virtual_modules)
        for kind, name, _table, _sql in rows
        if kind == "table"
    }
    result: list[dict[str, Any]] = []
    unknown = False
    capabilities = {"sqlite"}
    for kind, name, table, _sql in rows:
        module = virtual_modules.get(name)
        if module == "fts5":
            capabilities.add("fts5")
        if module == "vec0":
            capabilities.add("sqlite-vec")
        classification = table_classes.get(name) or table_classes.get(
            table, "unknown/owner decision required"
        )
        if classification == "unknown/owner decision required":
            unknown = True
        object_type = (
            "virtual-table"
            if name in virtual_modules
            else (kind if kind in {"table", "view", "index", "trigger"} else "unknown")
        )
        item: dict[str, Any] = {
            "name": name,
            "object_type": object_type,
            "classification": classification,
            "handling": "snapshot",
        }
        if kind == "table" and name not in virtual_modules:
            try:
                item["row_count"] = connection.execute(
                    f"SELECT COUNT(*) FROM {_quote_identifier(name)}"
                ).fetchone()[0]
            except sqlite3.Error:
                item["row_count"] = None
        if table != name:
            item["dependencies"] = [table]
        result.append(item)
    return result, rows, unknown, sorted(capabilities)


def _hash_file(bound: _BoundFile) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with _file_handle(bound, "rb") as handle:
        while chunk := handle.read(_CHUNK_SIZE):
            size += len(chunk)
            if size > _LIMITS["single_member_bytes"]:
                _fail("limit_exceeded", "package")
            digest.update(chunk)
    return size, digest.hexdigest()


def _artifact_hash(bound: _BoundFile) -> str:
    digest = hashlib.sha256()
    with _file_handle(bound, "rb") as handle:
        while chunk := handle.read(_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def _external_references(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    table = connection.execute(
        "SELECT 1 FROM sqlite_schema WHERE type='table' AND name='media_assets'"
    ).fetchone()
    if not table:
        return []
    columns = {row[1] for row in connection.execute("PRAGMA table_info(media_assets)")}
    if "ref_kind" not in columns:
        return []
    counts: dict[str, int] = {}
    bucket_limit = _LIMITS["external_reference_buckets"]
    # Stream source rows instead of asking SQLite to materialize an unbounded
    # GROUP BY. The accumulator reaches at most limit + 1 distinct normalized
    # schemes, and the extra bucket aborts discovery immediately.
    for (value,) in connection.execute("SELECT lower(ref_kind) FROM media_assets"):
        scheme = str(value or "unknown")
        if not re.fullmatch(r"[a-z0-9+.-]{1,32}", scheme):
            scheme = "unknown"
        counts[scheme] = counts.get(scheme, 0) + 1
        if len(counts) > bucket_limit:
            _fail("limit_exceeded", "discover")
    return [
        {"scheme": scheme, "count": counts[scheme], "owned": scheme == "blob"}
        for scheme in sorted(counts)
    ]


def _inspect_snapshot(snapshot: _BoundFile) -> dict[str, Any]:
    try:
        connection = sqlite3.connect(_sqlite_fd_uri(snapshot.fd, "ro"), uri=True)
        try:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()
            if integrity != ("ok",):
                _fail("sqlite_integrity_failed", "verify")
            if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                _fail("foreign_key_failed", "verify")
            catalog, schema_rows, unknown, capabilities = _catalog(
                connection, limit=_LIMITS["catalog_objects_per_store"]
            )
            schema_bytes = json.dumps(
                schema_rows, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
            metadata = {
                "page_size": int(connection.execute("PRAGMA page_size").fetchone()[0]),
                "page_count": int(
                    connection.execute("PRAGMA page_count").fetchone()[0]
                ),
                "user_version": int(
                    connection.execute("PRAGMA user_version").fetchone()[0]
                ),
                "application_id": int(
                    connection.execute("PRAGMA application_id").fetchone()[0]
                ),
                "schema_sha256": hashlib.sha256(schema_bytes).hexdigest(),
                "required_capabilities": capabilities,
            }
            if (
                not 512 <= metadata["page_size"] <= 65_536
                or metadata["page_count"] < 0
                or metadata["user_version"] < 0
                or metadata["application_id"] < 0
            ):
                _fail("limit_exceeded", "discover")
            references = _external_references(connection)
        finally:
            connection.close()
    except BackupV2Error:
        raise
    except _CatalogLimitExceeded as error:
        _fail("limit_exceeded", "discover", error)
    except sqlite3.Error as error:
        _fail("snapshot_failed", "verify", error)
    return {
        "catalog": catalog,
        "sqlite": metadata,
        "unknown_catalog": unknown,
        "external_references": references,
    }


def _manifest(
    *,
    store_id: str,
    location_hint: str,
    size: int,
    digest: str,
    inspection: dict[str, Any],
    source_revision: str | None,
) -> dict[str, Any]:
    discovery_reasons = ["unknown_store"] if inspection["unknown_catalog"] else []
    coverage_reasons = ["blob_bytes_excluded"]
    warnings = [{"code": "discovery_incomplete", "phase": "discover"}]
    if inspection["unknown_catalog"]:
        warnings.append(
            {"code": "unknown_store", "phase": "discover", "store_id": store_id}
        )
    producer = {"product": "mnemosyne", "version": __version__}
    if source_revision is not None:
        producer["source_revision"] = source_revision
    return {
        "format": _FORMAT,
        "format_version": 2,
        "manifest_version": 1,
        "backup_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "producer": producer,
        "status": "partial",
        "discovery": {
            "state": "unknown" if inspection["unknown_catalog"] else "partial",
            "reason_codes": discovery_reasons + ["blob_discovery_not_implemented"],
        },
        "coverage": {"state": "partial", "reason_codes": coverage_reasons},
        "consistency": "transactional",
        "self_contained": False,
        "scope": {
            "requested": [store_id],
            "discovered": [store_id, "owned-blobs"],
            "included": [store_id],
            "excluded": [
                {"store_id": "owned-blobs", "reason_code": "blob_bytes_excluded"}
            ],
        },
        "stores": [
            {
                "store_id": store_id,
                "kind": "sqlite",
                "classification": "authoritative",
                "required": True,
                "location_hint": location_hint,
                "archive_path": f"stores/{store_id}.sqlite",
                "media_type": "application/vnd.sqlite3",
                "bytes": size,
                "sha256": digest,
                "dependencies": [],
                "handling": "snapshot",
                "privacy": "high",
                "sqlite": inspection["sqlite"],
                "catalog": inspection["catalog"],
                "verification": {
                    "status": "verified",
                    "checks": [
                        {"name": "sha256", "status": "pass"},
                        {"name": "sqlite_integrity", "status": "pass"},
                        {"name": "foreign_key", "status": "pass"},
                        {"name": "schema_catalog", "status": "pass"},
                    ],
                },
            }
        ],
        "external_references": inspection["external_references"],
        "warnings": warnings,
        "errors": [],
        "limits": dict(_LIMITS),
    }


def _manifest_schema() -> dict[str, Any]:
    schema_path = files("mnemosyne.dr").joinpath(
        "backup-format-v2-manifest.schema.json"
    )
    return json.loads(schema_path.read_text(encoding="utf-8"))


def _validate_manifest(manifest: dict[str, Any]) -> None:
    try:
        validator = Draft202012Validator(
            _manifest_schema(), format_checker=_MANIFEST_FORMAT_CHECKER
        )
        validator.validate(manifest)
    except (OSError, ValueError, SchemaError, ValidationError) as error:
        _fail("invalid_manifest", "package", error)


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o600) << 16
    return info


def _write_archive(
    stage: _BoundFile, snapshot: _BoundFile, manifest: dict[str, Any]
) -> bytes:
    _validate_manifest(manifest)
    raw_manifest = json.dumps(
        manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if len(raw_manifest) > _LIMITS["manifest_bytes"]:
        _fail("limit_exceeded", "package")
    try:
        with _file_handle(stage, "r+b") as handle:
            handle.truncate(0)
            with zipfile.ZipFile(handle, "w", allowZip64=True) as archive:
                archive.writestr(
                    _zip_info("manifest.json"),
                    raw_manifest,
                    compress_type=zipfile.ZIP_STORED,
                )
                with (
                    archive.open(
                        _zip_info(manifest["stores"][0]["archive_path"]),
                        "w",
                        force_zip64=True,
                    ) as target,
                    _file_handle(snapshot, "rb") as source,
                ):
                    while chunk := source.read(_CHUNK_SIZE):
                        target.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())
        if not _entry_matches(stage):
            _fail("staging_failed", "package")
    except BackupV2Error:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        _fail("staging_failed", "package", error)
    return raw_manifest


def _verify_archive(
    archive_file: _BoundFile,
    raw_manifest: bytes,
    member: str,
    size: int,
    digest: str,
) -> None:
    try:
        with (
            _file_handle(archive_file, "rb") as handle,
            zipfile.ZipFile(handle) as archive,
        ):
            infos = archive.infolist()
            if [info.filename for info in infos] != ["manifest.json", member]:
                _fail("invalid_manifest", "verify")
            if infos[0].compress_type != zipfile.ZIP_STORED:
                _fail("unsupported_format", "verify")
            for info in infos:
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_IFMT(mode) != stat.S_IFREG or info.flag_bits & 0x1:
                    _fail("unsafe_archive_path", "verify")
                if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    _fail("unsupported_format", "verify")
            if archive.read("manifest.json") != raw_manifest:
                _fail("checksum_mismatch", "verify")
            observed = hashlib.sha256()
            observed_size = 0
            with archive.open(member) as payload:
                while chunk := payload.read(_CHUNK_SIZE):
                    observed_size += len(chunk)
                    if observed_size > _LIMITS["single_member_bytes"]:
                        _fail("limit_exceeded", "verify")
                    observed.update(chunk)
            if observed_size != size:
                _fail("size_mismatch", "verify")
            if observed.hexdigest() != digest:
                _fail("checksum_mismatch", "verify")
    except BackupV2Error:
        raise
    except (OSError, KeyError, zipfile.BadZipFile, RuntimeError) as error:
        _fail("checksum_mismatch", "verify", error)


def _fsync_directory(directory: _BoundDirectory) -> None:
    os.fsync(directory.fd)


def _link_fd_to_name(source_fd: int, parent_fd: int, name: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    linkat = libc.linkat
    linkat.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
    ]
    linkat.restype = ctypes.c_int
    if linkat(source_fd, b"", parent_fd, os.fsencode(name), _AT_EMPTY_PATH) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _rename_no_replace(parent_fd: int, source: str, destination: str) -> None:
    """Atomically claim an entry under a fresh name without overwriting."""
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = libc.renameat2
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
            parent_fd,
            os.fsencode(source),
            parent_fd,
            os.fsencode(destination),
            _RENAME_NOREPLACE,
        )
        != 0
    ):
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _publish_no_replace(
    stage: _BoundFile,
    destination_parent: _BoundDirectory,
    destination_name: str,
) -> _BoundFile:
    """Publish the retained stage inode without reopening its pathname."""
    try:
        _link_fd_to_name(stage.fd, destination_parent.fd, destination_name)
    except FileExistsError as error:
        _fail("destination_exists", "publish", error)
    except OSError as error:
        if error.errno == errno.EEXIST:
            _fail("destination_exists", "publish", error)
        _fail("publish_failed", "publish", error)
    observed = _entry_stat(destination_parent, destination_name)
    if observed is None or _identity(observed) != stage.identity:
        _fail("publish_failed", "publish")
    return _BoundFile(stage.fd, destination_parent, destination_name, stage.identity)


def _retained_directory_path(
    descriptor: int, expected_identity: tuple[int, int]
) -> str | None:
    """Return a verified current absolute name for one retained directory.

    A caller must still hold ``descriptor``. Falling back to a remembered
    pathname is unsafe: the directory may have been displaced and that name may
    now identify an unrelated replacement.
    """
    try:
        observed = os.fstat(descriptor)
        if _identity(observed) != expected_identity or not stat.S_ISDIR(
            observed.st_mode
        ):
            return None
        current = os.readlink(f"/proc/self/fd/{descriptor}")
        if not os.path.isabs(current) or current.endswith(" (deleted)"):
            return None
        current_path = Path(current)
        named = os.stat(current_path, follow_symlinks=False)
        if stat.S_ISDIR(named.st_mode) and _identity(named) == expected_identity:
            return str(current_path)
    except OSError:
        pass
    return None


def _cleanup_residual(working: _WorkingDirectory) -> dict[str, Any]:
    return {
        "status": "not_completed",
        "temporary_directory": _retained_directory_path(working.fd, working.identity),
    }


def _cleanup_parent_protects_entries(parent: _BoundDirectory) -> bool:
    """Whether foreign UIDs cannot replace entries in this directory.

    The pragmatic cleanup below deliberately accepts same-UID substitution.
    It is only safe when the retained parent is owned by that UID and does not
    grant namespace write access to its group or to everyone. Sticky-directory
    semantics are intentionally not inferred here.
    """
    try:
        observed = os.fstat(parent.fd)
    except OSError:
        return False
    return (
        stat.S_ISDIR(observed.st_mode)
        and observed.st_uid == os.geteuid()
        and not stat.S_IMODE(observed.st_mode) & 0o022
        and _identity(observed) == parent.identity
    )


def _cleanup_working_directory(
    working: _WorkingDirectory,
    expected: dict[str, tuple[int, int]],
) -> dict[str, Any]:
    """Remove validated private staging, retaining it on cleanup failures.

    Cleanup is deliberately pragmatic after publication: in a parent whose
    entry namespace is protected from foreign UIDs, once the private 0700
    directory and its known regular files have been validated, removal uses
    their names. A malicious same-UID process can race those final pathname
    operations; that process is outside the writer's reduced threat model.
    Unprotected parents, symlinks, foreign-UID entries, unexpected names, and
    the published destination remain outside the cleanup set.
    """
    if not _cleanup_parent_protects_entries(working.parent):
        return _cleanup_residual(working)

    cleanup_name = f".mnbak-cleanup-{uuid.uuid4().hex}"
    try:
        _rename_no_replace(working.parent.fd, working.name, cleanup_name)
    except OSError:
        return _cleanup_residual(working)

    named = _entry_stat(working.parent, cleanup_name)
    if named is None or _identity(named) != working.identity:
        return _cleanup_residual(working)

    try:
        observed = os.fstat(working.fd)
        if (
            not stat.S_ISDIR(observed.st_mode)
            or observed.st_uid != os.geteuid()
            or stat.S_IMODE(observed.st_mode) != 0o700
            or _identity(observed) != working.identity
        ):
            raise OSError(errno.EPERM, "unsafe cleanup directory")
        present = set(os.listdir(working.fd))
        sidecars = {
            "snapshot.sqlite-journal",
            "snapshot.sqlite-wal",
            "snapshot.sqlite-shm",
        }
        if not set(expected) <= present or not present <= set(expected) | sidecars:
            raise OSError(errno.EPERM, "unexpected cleanup entry")
        for name in sorted(present):
            entry = _entry_stat(working.directory, name)
            if (
                entry is None
                or not stat.S_ISREG(entry.st_mode)
                or entry.st_uid != os.geteuid()
                or stat.S_IMODE(entry.st_mode) & 0o077
                or (name in expected and _identity(entry) != expected[name])
            ):
                raise OSError(errno.EPERM, "unsafe cleanup entry")

        # These pathname operations intentionally accept a same-UID substitution
        # race. No recursive traversal is used, and every permitted name is a
        # fixed writer-controlled basename within the retained directory FD.
        for name in sorted(present):
            os.unlink(name, dir_fd=working.fd)
        os.fsync(working.fd)
        os.rmdir(cleanup_name, dir_fd=working.parent.fd)
        os.fsync(working.parent.fd)
    except OSError:
        return _cleanup_residual(working)
    return {"status": "complete"}


def _close_all_best_effort(
    *items: object | None, suppress_base_exceptions: bool = False
) -> bool:
    """Attempt each final close once without replacing the primary outcome.

    Base exceptions are suppressed only while an earlier interruption is already
    propagating; otherwise an interrupt raised by ``close`` keeps its semantics.
    """

    failed = False
    for item in items:
        if item is None:
            continue
        try:
            item.close()  # type: ignore[attr-defined]
        except Exception:
            failed = True
        except BaseException:
            if not suppress_base_exceptions:
                raise
            failed = True
    return failed


def create_backup_v2(
    db_path: Path | str,
    destination: Path | str,
    *,
    store_id: str = "default",
    location_hint: str = "default",
    source_revision: str | None = None,
) -> dict[str, Any]:
    """Write one explicit SQLite source as a private, bounded v2 package.

    The result includes ``cleanup.status``. ``complete`` means the private
    snapshot/archive aliases and working directory were removed. A
    ``not_completed`` status adds a PII-safe warning and preserves whatever
    private namespace remains after a genuine cleanup failure or any primary
    writer failure;
    ``temporary_directory`` is null unless an absolute path to that retained
    writer directory can be verified while its FD is held. Successful cleanup
    accepts final pathname races from malicious same-UID processes as outside
    the reduced threat model, but only when the destination parent namespace is
    not writable by foreign UIDs.
    """
    source_path = Path(db_path)
    target_path = Path(destination)
    _validate_arguments(
        source_path, target_path, store_id, location_hint, source_revision
    )

    source = _open_source(source_path)
    source_connection: sqlite3.Connection | None = None
    target_parent: _BoundDirectory | None = None
    working: _WorkingDirectory | None = None
    snapshot: _BoundFile | None = None
    stage: _BoundFile | None = None
    published: _BoundFile | None = None
    result: dict[str, Any] | None = None
    primary_failure: BackupV2Error | None = None
    primary_interruption: BaseException | None = None
    try:
        source_connection = _open_source_connection(source)
        target_parent = _open_destination_parent(target_path)
        target_name = target_path.name
        if not target_name or target_name in {".", ".."}:
            _fail("invalid_argument", "discover")
        if _entry_stat(target_parent, target_name) is not None:
            _fail("destination_exists", "publish")

        working = _create_working_directory(target_parent)
        snapshot = _reserve_file(working.directory, "snapshot.sqlite", "stage")
        stage = _reserve_file(working.directory, "archive.mnbak", "package")
        _snapshot(source, snapshot, source_connection)
        source_connection.close()
        source_connection = None
        inspection = _inspect_snapshot(snapshot)
        size, digest = _hash_file(snapshot)
        manifest = _manifest(
            store_id=store_id,
            location_hint=location_hint,
            size=size,
            digest=digest,
            inspection=inspection,
            source_revision=source_revision,
        )
        raw_manifest = _write_archive(stage, snapshot, manifest)
        member = manifest["stores"][0]["archive_path"]
        _verify_archive(stage, raw_manifest, member, size, digest)
        _fsync_directory(working.directory)
        published = _publish_no_replace(stage, target_parent, target_name)
        # Publication transfers ownership of the one retained archive FD.
        stage = None
        _verify_archive(published, raw_manifest, member, size, digest)
        if not _entry_matches(published) or not _directory_path_matches(target_parent):
            _fail("publish_failed", "publish")
        _fsync_directory(target_parent)
        result = {
            "status": manifest["status"],
            "backup_path": str(target_path),
            "format_version": 2,
            "backup_id": manifest["backup_id"],
            "bytes": os.fstat(published.fd).st_size,
            "sha256": _artifact_hash(published),
            "self_contained": False,
            "coverage": manifest["coverage"],
            "warnings": manifest["warnings"],
        }
    except BackupV2Error as error:
        primary_failure = error
    except MemoryError as error:
        primary_interruption = error
        raise
    except OSError:
        primary_failure = BackupV2Error(
            "publish_failed" if published is not None else "staging_failed",
            "publish" if published is not None else "stage",
        )
    except Exception:
        primary_failure = BackupV2Error(
            "publish_failed" if published is not None else "staging_failed",
            "publish" if published is not None else "stage",
        )
    except BaseException as error:
        primary_interruption = error
        raise
    finally:
        expected: dict[str, tuple[int, int]] = {}
        if snapshot is not None:
            expected["snapshot.sqlite"] = snapshot.identity
        archive = published if published is not None else stage
        if archive is not None:
            expected["archive.mnbak"] = archive.identity

        cleanup_working: _WorkingDirectory | None = None
        retained_before_close: str | None = None
        if working is not None and primary_interruption is None:
            retained_before_close = _retained_directory_path(
                working.fd, working.identity
            )
            try:
                parent_fd = os.dup(working.parent.fd)
                try:
                    working_fd = os.dup(working.fd)
                except Exception:
                    os.close(parent_fd)
                    raise
                cleanup_parent = _BoundDirectory(
                    parent_fd, working.parent.path, working.parent.identity
                )
                cleanup_directory = _BoundDirectory(
                    working_fd, working.path, working.identity
                )
                cleanup_working = _WorkingDirectory(
                    cleanup_directory, cleanup_parent, working.name
                )
            except Exception:
                cleanup_working = None

        close_failed = _close_all_best_effort(
            stage,
            published,
            snapshot,
            source_connection,
            source,
            source.parent,
            working,
            target_parent,
            suppress_base_exceptions=primary_interruption is not None,
        )

        cleanup: dict[str, Any] | None = None
        if working is not None and primary_interruption is None:
            # Pathname cleanup deliberately accepts same-UID substitution and
            # is therefore permitted only after the writer has completed
            # successfully. On every structured primary failure, safe-leak the
            # private staging namespace unchanged and report its verified path.
            if (
                primary_failure is not None
                or close_failed
                or cleanup_working is None
            ):
                cleanup = {
                    "status": "not_completed",
                    "temporary_directory": (
                        _retained_directory_path(
                            cleanup_working.fd, cleanup_working.identity
                        )
                        if cleanup_working is not None
                        else retained_before_close
                    ),
                }
            else:
                cleanup = _cleanup_working_directory(cleanup_working, expected)

        if cleanup_working is not None:
            _close_all_best_effort(cleanup_working.directory, cleanup_working.parent)

        if cleanup is not None and cleanup["status"] == "not_completed":
            temporary_directory = cleanup["temporary_directory"]
            if result is not None:
                result["cleanup"] = cleanup
                result["warnings"].append(
                    {
                        "code": "cleanup_not_completed",
                        "phase": "cleanup",
                        "temporary_directory": temporary_directory,
                    }
                )
            if primary_failure is not None:
                primary_failure.note_cleanup_residual(temporary_directory)
        elif result is not None:
            result["cleanup"] = {"status": "complete"}

    if primary_failure is not None:
        raise primary_failure from None
    if result is not None:
        return result
    raise AssertionError("unreachable")
