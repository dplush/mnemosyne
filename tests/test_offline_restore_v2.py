from __future__ import annotations

import gzip
import hashlib
import json
import os
import sqlite3
import stat
import struct
import zipfile
from pathlib import Path
from typing import cast

import pytest

from mnemosyne.dr import offline_restore_v2
from mnemosyne.dr import backup_v2 as backup_v2_module
from mnemosyne.dr.artifact_inspector import InspectionLimits
from mnemosyne.dr.backup_v2 import create_backup_v2
from mnemosyne.dr.offline_restore_v2 import OfflineRestoreV2Error, restore_backup_v2


def _database(
    path: Path,
    *,
    content: str | bytes = "private value",
    quoted_reference: str | None = None,
    generated_reference_digest: str | None = None,
) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA user_version=17")
        connection.execute("PRAGMA application_id=42")
        connection.execute(
            "CREATE TABLE working_memory (id TEXT PRIMARY KEY, content TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO working_memory VALUES ('one', ?)",
            (content,),
        )
        if quoted_reference is not None:
            connection.execute('CREATE TABLE "odd""table" ("blob""cell" TEXT)')
            connection.execute(
                'INSERT INTO "odd""table" ("blob""cell") VALUES (?)',
                (quoted_reference,),
            )
        if generated_reference_digest is not None:
            connection.execute(
                "CREATE TABLE generated_reference ("
                "digest TEXT NOT NULL, "
                "reference TEXT GENERATED ALWAYS AS "
                "('blob://sha256/' || digest) STORED)"
            )
            connection.execute(
                "INSERT INTO generated_reference (digest) VALUES (?)",
                (generated_reference_digest,),
            )
        connection.commit()
    finally:
        connection.close()


def _manifest_and_payload(path: Path) -> tuple[dict, bytes]:
    with zipfile.ZipFile(path) as archive:
        return json.loads(archive.read("manifest.json")), archive.read(
            "stores/default.sqlite"
        )


def _schema_policy(manifest: dict) -> set[tuple[int, str]]:
    metadata = manifest["stores"][0]["sqlite"]
    return {(metadata["user_version"], metadata["schema_sha256"])}


def _backup(
    tmp_path: Path,
    *,
    content: str | bytes = "private value",
    quoted_reference: str | None = None,
    generated_reference_digest: str | None = None,
) -> tuple[Path, dict]:
    source = tmp_path / "source.sqlite"
    _database(
        source,
        content=content,
        quoted_reference=quoted_reference,
        generated_reference_digest=generated_reference_digest,
    )
    archive = tmp_path / "backup.mnbak"
    create_backup_v2(source, archive)
    manifest, _payload = _manifest_and_payload(archive)
    return archive, manifest


def _extension_backup(tmp_path: Path, capability: str) -> tuple[Path, dict]:
    return _extensions_backup(tmp_path, (capability,))


def _extensions_backup(
    tmp_path: Path, capabilities: tuple[str, ...]
) -> tuple[Path, dict]:
    source = tmp_path / f"{'-'.join(capabilities)}-source.sqlite"
    _database(source)
    connection = sqlite3.connect(source)
    try:
        for capability in capabilities:
            if capability == "fts5":
                try:
                    connection.execute(
                        "CREATE VIRTUAL TABLE fts_items USING fts5(content)"
                    )
                except sqlite3.OperationalError:
                    pytest.skip("SQLite FTS5 unavailable")
                connection.execute("INSERT INTO fts_items(content) VALUES ('searchable')")
            elif capability == "sqlite-vec":
                sqlite_vec = pytest.importorskip("sqlite_vec")
                connection.enable_load_extension(True)
                sqlite_vec.load(connection)
                connection.enable_load_extension(False)
                connection.execute(
                    "CREATE VIRTUAL TABLE vec_items USING vec0(embedding float[2])"
                )
                connection.execute(
                    "INSERT INTO vec_items(rowid, embedding) VALUES (1, ?)",
                    (sqlite_vec.serialize_float32([1.0, 2.0]),),
                )
            else:
                raise AssertionError(f"unsupported test capability: {capability}")
        connection.commit()
    finally:
        connection.close()
    archive = tmp_path / f"{'-'.join(capabilities)}-backup.mnbak"
    create_backup_v2(source, archive)
    manifest, _payload = _manifest_and_payload(archive)
    return archive, manifest


def _rewrite(path: Path, transform) -> dict:
    with zipfile.ZipFile(path) as source:
        manifest = json.loads(source.read("manifest.json"))
        payloads = {
            info.filename: source.read(info)
            for info in source.infolist()
            if info.filename != "manifest.json"
        }
    transform(manifest, payloads)
    with zipfile.ZipFile(path, "w", allowZip64=True) as target:
        target.writestr(
            "manifest.json",
            json.dumps(manifest, sort_keys=True, separators=(",", ":")),
            compress_type=zipfile.ZIP_STORED,
        )
        for name, payload in payloads.items():
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            target.writestr(info, payload, compress_type=zipfile.ZIP_STORED)
    return manifest


def _rewrite_compressed_and_corrupt(path: Path, member: str) -> None:
    with zipfile.ZipFile(path) as source:
        entries = [(info.filename, source.read(info)) for info in source.infolist()]
    with zipfile.ZipFile(path, "w", allowZip64=True) as target:
        for name, payload in entries:
            target.writestr(
                name,
                payload,
                compress_type=(
                    zipfile.ZIP_DEFLATED if name == member else zipfile.ZIP_STORED
                ),
            )
    with zipfile.ZipFile(path) as archive:
        info = archive.getinfo(member)
    raw = bytearray(path.read_bytes())
    name_size, extra_size = struct.unpack_from("<HH", raw, info.header_offset + 26)
    raw[info.header_offset + 30 + name_size + extra_size] = 0x07
    path.write_bytes(raw)


def _append_blob(
    doc: dict,
    payloads: dict[str, bytes],
    *,
    store_id: str,
    dependencies: list[str],
    required: bool = True,
    verification_status: str = "verified",
    check_status: str = "pass",
) -> str:
    blob = f"bytes for {store_id}".encode()
    digest = hashlib.sha256(blob).hexdigest()
    member = f"blobs/sha256/{digest[:2]}/{digest[:4]}/{digest}"
    payloads[member] = blob
    doc["stores"].append(
        {
            "store_id": store_id,
            "kind": "blob",
            "classification": "external/blob",
            "required": required,
            "location_hint": "default",
            "archive_path": member,
            "media_type": "application/octet-stream",
            "bytes": len(blob),
            "sha256": digest,
            "dependencies": dependencies,
            "handling": "snapshot",
            "privacy": "high",
            "verification": {
                "status": verification_status,
                "checks": [{"name": "sha256", "status": check_status}],
            },
        }
    )
    doc["scope"]["discovered"].append(store_id)
    doc["scope"]["included"].append(store_id)
    return member


def _restore(archive: Path, destination: Path, manifest: dict, **kwargs):
    return restore_backup_v2(
        archive,
        destination,
        store_id="default",
        known_schemas=_schema_policy(manifest),
        allow_partial=True,
        allow_database_only=True,
        **kwargs,
    )


def _assert_database(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        assert connection.execute(
            "SELECT id, content FROM working_memory"
        ).fetchall() == [("one", "private value")]
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        connection.close()


def _stages(parent: Path) -> list[Path]:
    return list(parent.glob(".mnbak-restore-*"))


def test_restore_schema_sql_limit_fails_closed_and_redacted(tmp_path, monkeypatch):
    archive, manifest = _backup(tmp_path)
    destination = tmp_path / "restored"
    monkeypatch.setattr(backup_v2_module, "_SCHEMA_SQL_VALUE_BYTES", 16)

    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, manifest)

    assert caught.value.as_diagnostic() == {
        "code": "limit_exceeded",
        "phase": "restore",
    }
    assert not destination.exists()
    assert len(_stages(tmp_path)) == 1


@pytest.mark.parametrize("primary_failure", [False, True])
def test_final_close_failure_does_not_mask_outcome_or_stop_restore_teardown(
    tmp_path, monkeypatch, primary_failure
):
    archive, manifest = _backup(tmp_path)
    destination = tmp_path / "restored"
    real_file_close = offline_restore_v2._File.close
    real_directory_close = offline_restore_v2._Directory.close
    real_close_all = offline_restore_v2._close_all_best_effort
    close_calls: list[int] = []
    injected = False
    armed = False

    def close_and_fail_once(item, real_close):
        nonlocal armed, injected
        if armed:
            close_calls.append(item.fd)
        real_close(item)
        if armed and not injected:
            injected = True
            raise OSError("injected final close failure")

    monkeypatch.setattr(
        offline_restore_v2._File,
        "close",
        lambda item: close_and_fail_once(item, real_file_close),
    )
    monkeypatch.setattr(
        offline_restore_v2._Directory,
        "close",
        lambda item: close_and_fail_once(item, real_directory_close),
    )

    def arm_and_close(items):
        nonlocal armed
        armed = True
        real_close_all(items)

    monkeypatch.setattr(offline_restore_v2, "_close_all_best_effort", arm_and_close)
    if primary_failure:

        def fail_verify(*_args, **_kwargs):
            nonlocal armed
            armed = True
            raise OfflineRestoreV2Error("checksum_mismatch", "restore")

        monkeypatch.setattr(offline_restore_v2, "_verify_sqlite", fail_verify)

    before = len(os.listdir("/proc/self/fd"))
    if primary_failure:
        with pytest.raises(OfflineRestoreV2Error) as caught:
            _restore(archive, destination, manifest)
        assert caught.value.as_diagnostic() == {
            "code": "checksum_mismatch",
            "phase": "restore",
        }
    else:
        assert _restore(archive, destination, manifest)["phase"] == "publish"

    assert injected
    assert len(close_calls) == 6
    assert len(set(close_calls)) == len(close_calls)
    assert len(os.listdir("/proc/self/fd")) == before


def test_failed_multicomponent_directory_traversal_closes_each_descriptor_once(
    tmp_path, monkeypatch
):
    existing = tmp_path / "existing"
    existing.mkdir()
    target = existing / "missing" / "later"
    real_open = offline_restore_v2.os.open
    real_close = offline_restore_v2.os.close
    open_counts: dict[int, int] = {}
    close_counts: dict[int, int] = {}

    def tracked_open(*args, **kwargs):
        descriptor = real_open(*args, **kwargs)
        open_counts[descriptor] = open_counts.get(descriptor, 0) + 1
        return descriptor

    def tracked_close(descriptor):
        close_counts[descriptor] = close_counts.get(descriptor, 0) + 1
        return real_close(descriptor)

    before = len(os.listdir("/proc/self/fd"))
    monkeypatch.setattr(offline_restore_v2.os, "open", tracked_open)
    monkeypatch.setattr(offline_restore_v2.os, "close", tracked_close)

    with pytest.raises(FileNotFoundError):
        offline_restore_v2._open_directory_path(target)

    assert open_counts
    assert close_counts == open_counts
    assert len(os.listdir("/proc/self/fd")) == before


def test_post_open_parent_close_failure_closes_child_once(tmp_path, monkeypatch):
    target = tmp_path / "existing"
    target.mkdir()
    real_open = offline_restore_v2.os.open
    real_close = offline_restore_v2.os.close
    opened: list[int] = []
    close_calls: list[int] = []
    failure = OSError("injected parent close failure")

    def tracked_open(*args, **kwargs):
        descriptor = real_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def failing_close(descriptor):
        close_calls.append(descriptor)
        real_close(descriptor)
        if len(opened) == 2 and descriptor == opened[0]:
            raise failure

    before = len(os.listdir("/proc/self/fd"))
    monkeypatch.setattr(offline_restore_v2.os, "open", tracked_open)
    monkeypatch.setattr(offline_restore_v2.os, "close", failing_close)

    with pytest.raises(OSError) as exc_info:
        offline_restore_v2._open_directory_path(target)

    assert exc_info.value is failure
    assert len(opened) == 2
    assert close_calls == opened
    assert len(os.listdir("/proc/self/fd")) == before


def test_writer_to_offline_restore_round_trip_is_staged_private_and_partial(tmp_path):
    archive, manifest = _backup(tmp_path)
    destination = tmp_path / "restored"

    result = _restore(archive, destination, manifest)

    assert result == {
        "status": "partial",
        "phase": "publish",
        "destination": "explicit_destination",
        "self_contained": False,
        "stores": [{"store": "selected_store", "verification": "verified"}],
        "diagnostics": [],
    }
    _assert_database(destination / "stores" / "default.sqlite")
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert (
        stat.S_IMODE((destination / "stores" / "default.sqlite").stat().st_mode)
        == 0o600
    )
    assert not _stages(tmp_path)


@pytest.mark.parametrize(
    ("allow_partial", "allow_database_only", "expected_code"),
    [
        (False, False, "blob_missing"),
        (True, False, "blob_missing"),
        (False, True, "discovery_incomplete"),
    ],
)
def test_database_only_restore_requires_both_explicit_opt_ins(
    tmp_path,
    allow_partial,
    allow_database_only,
    expected_code,
):
    archive, manifest = _backup(tmp_path)

    def declare_valid_database_only(doc, _payloads):
        doc["status"] = "complete"
        doc["discovery"] = {"state": "complete", "reason_codes": []}
        doc["coverage"] = {"state": "complete", "reason_codes": []}
        doc["self_contained"] = False
        doc["warnings"] = []

    manifest = _rewrite(archive, declare_valid_database_only)
    destination = tmp_path / "restored"

    with pytest.raises(OfflineRestoreV2Error) as caught:
        restore_backup_v2(
            archive,
            destination,
            store_id="default",
            known_schemas=_schema_policy(manifest),
            allow_partial=allow_partial,
            allow_database_only=allow_database_only,
        )

    assert caught.value.as_diagnostic() == {
        "code": expected_code,
        "phase": "verify",
    }
    assert not destination.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and permission bits")
def test_restore_preserves_accepted_destination_parent_mode(tmp_path):
    archive, manifest = _backup(tmp_path)
    parent = tmp_path / "restore-parent"
    parent.mkdir(mode=0o750)
    parent.chmod(0o750)
    destination = parent / "restored"

    _restore(archive, destination, manifest)

    assert stat.S_IMODE(parent.stat().st_mode) == 0o750
    _assert_database(destination / "stores" / "default.sqlite")


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and permission bits")
def test_restore_rejects_non_sticky_world_writable_destination_parent(tmp_path):
    archive, manifest = _backup(tmp_path)
    parent = tmp_path / "unsafe-parent"
    parent.mkdir()
    parent.chmod(0o777)
    destination = parent / "restored"

    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, manifest)

    assert caught.value.as_diagnostic() == {
        "code": "staging_failed",
        "phase": "stage",
    }
    assert stat.S_IMODE(parent.stat().st_mode) == 0o777
    assert not destination.exists()
    assert not _stages(parent)


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership")
def test_restore_rejects_destination_parent_not_owned_by_effective_uid(
    tmp_path, monkeypatch
):
    archive, manifest = _backup(tmp_path)
    parent = tmp_path / "foreign-parent"
    parent.mkdir(mode=0o700)
    destination = parent / "restored"
    effective_uid = os.geteuid()
    monkeypatch.setattr(offline_restore_v2.os, "geteuid", lambda: effective_uid + 1)

    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, manifest)

    assert caught.value.as_diagnostic() == {
        "code": "staging_failed",
        "phase": "stage",
    }
    assert stat.S_IMODE(parent.stat().st_mode) == 0o700
    assert not destination.exists()
    assert not _stages(parent)


def test_preexisting_destination_is_never_merged_or_replaced(tmp_path):
    archive, manifest = _backup(tmp_path)
    destination = tmp_path / "restored"
    destination.mkdir()
    canary = destination / "keep"
    canary.write_bytes(b"keep")

    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, manifest)

    assert caught.value.as_diagnostic() == {
        "code": "destination_exists",
        "phase": "stage",
    }
    assert canary.read_bytes() == b"keep"
    assert not _stages(tmp_path)


@pytest.mark.parametrize("corruption", ["hash", "truncated"])
def test_corrupt_or_hash_mismatched_archive_publishes_nothing(tmp_path, corruption):
    archive, manifest = _backup(tmp_path)
    if corruption == "hash":
        manifest = _rewrite(
            archive,
            lambda doc, _payloads: doc["stores"][0].__setitem__("sha256", "f" * 64),
        )
    else:
        archive.write_bytes(archive.read_bytes()[:80])
    destination = tmp_path / "restored"

    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, manifest)

    assert caught.value.code in {"checksum_mismatch", "unsupported_format"}
    assert not destination.exists()
    assert not _stages(tmp_path)


def test_extract_failure_closes_every_locally_owned_descriptor(tmp_path, monkeypatch):
    archive, manifest = _backup(tmp_path)
    destination = tmp_path / "restored"
    descriptors: list[int] = []
    real_create_directory = offline_restore_v2._create_directory
    real_reserve_file = offline_restore_v2._reserve_file

    def record_directory(*args, **kwargs):
        directory = real_create_directory(*args, **kwargs)
        descriptors.append(directory.fd)
        return directory

    def record_file(*args, **kwargs):
        item = real_reserve_file(*args, **kwargs)
        descriptors.append(item.fd)
        return item

    monkeypatch.setattr(offline_restore_v2, "_create_directory", record_directory)
    monkeypatch.setattr(offline_restore_v2, "_reserve_file", record_file)
    monkeypatch.setattr(offline_restore_v2.os, "write", lambda *_args: 0)
    before = len(os.listdir("/proc/self/fd"))

    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, manifest)

    assert caught.value.as_diagnostic() == {
        "code": "checksum_mismatch",
        "phase": "extract",
    }
    assert descriptors
    for descriptor in descriptors:
        with pytest.raises(OSError, match="Bad file descriptor"):
            os.fstat(descriptor)
    assert len(os.listdir("/proc/self/fd")) <= before
    assert not destination.exists()


@pytest.mark.parametrize(
    ("failure_point", "collection_type", "method_name", "created_kind"),
    [
        (
            "directory mapping",
            offline_restore_v2._DirectoryMap,
            "__setitem__",
            "directory",
        ),
        (
            "directory list",
            offline_restore_v2._DirectoryList,
            "append",
            "directory",
        ),
        ("file list", offline_restore_v2._FileList, "append", "file"),
    ],
)
def test_extract_enrollment_failure_closes_just_created_descriptor_once(
    tmp_path,
    monkeypatch,
    failure_point,
    collection_type,
    method_name,
    created_kind,
):
    archive, manifest = _backup(tmp_path)
    destination = tmp_path / "restored"
    created_descriptor: int | None = None
    close_count = 0
    real_create_directory = offline_restore_v2._create_directory
    real_reserve_file = offline_restore_v2._reserve_file
    real_close = offline_restore_v2.os.close

    def record_directory(*args, **kwargs):
        nonlocal created_descriptor
        directory = real_create_directory(*args, **kwargs)
        if created_kind == "directory" and created_descriptor is None:
            created_descriptor = directory.fd
        return directory

    def record_file(*args, **kwargs):
        nonlocal created_descriptor
        item = real_reserve_file(*args, **kwargs)
        if created_kind == "file" and created_descriptor is None:
            created_descriptor = item.fd
        return item

    def record_close(descriptor):
        nonlocal close_count
        if descriptor == created_descriptor:
            close_count += 1
        return real_close(descriptor)

    def fail_enrollment(*_args, **_kwargs):
        raise MemoryError(f"injected {failure_point} failure")

    monkeypatch.setattr(offline_restore_v2, "_create_directory", record_directory)
    monkeypatch.setattr(offline_restore_v2, "_reserve_file", record_file)
    monkeypatch.setattr(offline_restore_v2.os, "close", record_close)
    monkeypatch.setattr(collection_type, method_name, fail_enrollment)
    before = len(os.listdir("/proc/self/fd"))

    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, manifest)

    assert caught.value.as_diagnostic() == {
        "code": "staging_failed",
        "phase": "stage",
    }
    assert created_descriptor is not None
    assert close_count == 1
    with pytest.raises(OSError, match="Bad file descriptor"):
        os.fstat(created_descriptor)
    assert len(os.listdir("/proc/self/fd")) == before
    assert not destination.exists()


def test_malformed_and_legacy_artifacts_are_rejected_without_sql_execution(
    tmp_path, monkeypatch
):
    malformed = tmp_path / "malformed.mnbak"
    malformed.write_bytes(b"not an archive")
    legacy = tmp_path / "legacy.db.gz"
    with gzip.open(legacy, "wb") as output:
        output.write(b"BEGIN TRANSACTION;\nCREATE TABLE secret(value);\nCOMMIT;\n")
    monkeypatch.setattr(
        offline_restore_v2.sqlite3,
        "connect",
        lambda *_args, **_kwargs: pytest.fail("opened SQLite for legacy SQL"),
    )

    for artifact in (malformed, legacy):
        with pytest.raises(OfflineRestoreV2Error) as caught:
            restore_backup_v2(
                artifact,
                tmp_path / f"restore-{artifact.name}",
                store_id="default",
                known_schemas={(17, "0" * 64)},
                allow_partial=True,
                allow_database_only=True,
            )
        assert caught.value.code in {
            "unsupported_format",
            "legacy_v1_restore_unverifiable",
        }
        assert not (tmp_path / f"restore-{artifact.name}").exists()


def test_malformed_deflate_fails_in_verify_before_staging(tmp_path):
    archive, manifest = _backup(tmp_path)
    _rewrite_compressed_and_corrupt(archive, "stores/default.sqlite")
    destination = tmp_path / "restored"

    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, manifest)

    assert caught.value.as_diagnostic() == {
        "code": "checksum_mismatch",
        "phase": "verify",
    }
    assert not destination.exists()
    assert not _stages(tmp_path)


def test_unknown_schema_policy_and_future_manifest_schema_fail_closed(tmp_path):
    archive, manifest = _backup(tmp_path)
    destination = tmp_path / "restored"

    with pytest.raises(OfflineRestoreV2Error) as caught:
        restore_backup_v2(
            archive,
            destination,
            store_id="default",
            known_schemas={(18, "0" * 64)},
            allow_partial=True,
            allow_database_only=True,
        )
    assert caught.value.code == "schema_mismatch"
    assert not destination.exists()

    future = _rewrite(
        archive,
        lambda doc, _payloads: doc.__setitem__("manifest_version", 2),
    )
    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, future)
    assert caught.value.code == "invalid_manifest"
    assert not destination.exists()


def test_required_unavailable_capability_cannot_be_degraded_by_caller_opt_in(
    tmp_path, monkeypatch
):
    archive, manifest = _backup(tmp_path)

    def require_future_capability(doc, _payloads):
        doc["stores"][0]["sqlite"]["required_capabilities"] = ["sqlite", "sqlite-vec"]
        doc["stores"][0]["verification"] = {
            "status": "verified_degraded",
            "checks": [
                {"name": "sqlite", "status": "pass"},
                {
                    "name": "sqlite_vec",
                    "status": "degraded",
                    "code": "capability_unavailable",
                },
            ],
        }

    manifest = _rewrite(archive, require_future_capability)
    monkeypatch.setattr(
        offline_restore_v2, "_load_optional_sqlite_vec", lambda _connection: False
    )
    destination = tmp_path / "restored"
    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(
            archive,
            destination,
            manifest,
            allow_degraded_capabilities=True,
        )

    assert caught.value.as_diagnostic() == {
        "code": "capability_unavailable",
        "phase": "verify",
    }
    assert not destination.exists()


@pytest.mark.parametrize("capability", ["fts5", "sqlite-vec"])
def test_schema_inferred_extension_omitted_from_manifest_prevents_publication(
    tmp_path, capability
):
    archive, manifest = _extension_backup(tmp_path, capability)
    assert capability in manifest["stores"][0]["sqlite"]["required_capabilities"]

    def omit_inferred_capability(doc, _payloads):
        doc["stores"][0]["sqlite"]["required_capabilities"].remove(capability)

    manifest = _rewrite(archive, omit_inferred_capability)
    destination = tmp_path / "restored"

    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(
            archive,
            destination,
            manifest,
            allow_degraded_capabilities=True,
        )

    assert caught.value.as_diagnostic() == {
        "code": "capability_unavailable",
        "phase": "restore",
    }
    assert not destination.exists()
    assert len(_stages(tmp_path)) == 1


@pytest.mark.parametrize("capability", ["fts5", "sqlite-vec"])
def test_declared_extension_without_inferred_schema_use_is_rejected(
    tmp_path, capability
):
    archive, manifest = _backup(tmp_path)

    def add_mismatched_capability(doc, _payloads):
        doc["stores"][0]["sqlite"]["required_capabilities"].append(capability)

    manifest = _rewrite(archive, add_mismatched_capability)
    destination = tmp_path / "restored"

    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, manifest)

    assert caught.value.as_diagnostic() == {
        "code": "capability_unavailable",
        "phase": "restore",
    }
    assert not destination.exists()
    assert len(_stages(tmp_path)) == 1


def test_optional_unavailable_capability_requires_explicit_degraded_opt_in(
    tmp_path, monkeypatch
):
    archive, manifest = _extension_backup(tmp_path, "fts5")

    def declare_optional_degradation(doc, _payloads):
        metadata = doc["stores"][0]["sqlite"]
        metadata["required_capabilities"] = ["sqlite"]
        metadata["optional_capabilities"] = ["fts5"]
        doc["stores"][0]["verification"] = {
            "status": "verified_degraded",
            "checks": [
                {"name": "sqlite", "status": "pass"},
                {
                    "name": "fts5",
                    "status": "degraded",
                    "code": "capability_unavailable",
                },
            ],
        }
        doc["status"] = "complete"
        doc["discovery"] = {"state": "complete", "reason_codes": []}
        doc["coverage"] = {"state": "complete", "reason_codes": []}
        doc["self_contained"] = True
        doc["scope"] = {
            "requested": ["default"],
            "discovered": ["default"],
            "included": ["default"],
            "excluded": [],
        }
        doc["warnings"] = []

    manifest = _rewrite(archive, declare_optional_degradation)
    monkeypatch.setattr(
        offline_restore_v2,
        "_capabilities",
        lambda _connection, _virtual_modules: {"sqlite"},
    )

    blocked = tmp_path / "blocked"
    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, blocked, manifest)
    assert caught.value.as_diagnostic() == {
        "code": "capability_unavailable",
        "phase": "verify",
    }
    assert not blocked.exists()

    destination = tmp_path / "restored"
    result = _restore(
        archive,
        destination,
        manifest,
        allow_degraded_capabilities=True,
    )

    assert result["status"] == "partial"
    assert result["self_contained"] is False
    assert result["stores"] == [
        {"store": "selected_store", "verification": "verified_degraded"}
    ]
    assert result["diagnostics"] == [
        {
            "code": "capability_unavailable",
            "phase": "restore",
            "role": "optional_capability",
            "count": 1,
        }
    ]
    _assert_database(destination / "stores" / "default.sqlite")


def test_manifest_degraded_diagnostic_counts_every_optional_capability(
    tmp_path, monkeypatch
):
    archive, manifest = _extensions_backup(tmp_path, ("fts5", "sqlite-vec"))

    def declare_two_optional_degradations(doc, _payloads):
        metadata = doc["stores"][0]["sqlite"]
        metadata["required_capabilities"] = ["sqlite"]
        metadata["optional_capabilities"] = ["fts5", "sqlite-vec"]
        doc["stores"][0]["verification"] = {
            "status": "verified_degraded",
            "checks": [
                {"name": "sqlite", "status": "pass"},
                {
                    "name": "fts5",
                    "status": "degraded",
                    "code": "capability_unavailable",
                },
                {
                    "name": "sqlite_vec",
                    "status": "degraded",
                    "code": "capability_unavailable",
                },
            ],
        }
        doc["status"] = "complete"
        doc["discovery"] = {"state": "complete", "reason_codes": []}
        doc["coverage"] = {"state": "complete", "reason_codes": []}
        doc["self_contained"] = True
        doc["scope"] = {
            "requested": ["default"],
            "discovered": ["default"],
            "included": ["default"],
            "excluded": [],
        }
        doc["warnings"] = []

    manifest = _rewrite(archive, declare_two_optional_degradations)
    monkeypatch.setattr(
        offline_restore_v2,
        "_capabilities",
        lambda _connection, _virtual_modules: {"sqlite", "fts5", "sqlite-vec"},
    )

    result = _restore(
        archive,
        tmp_path / "restored",
        manifest,
        allow_degraded_capabilities=True,
    )

    assert result["diagnostics"] == [
        {
            "code": "capability_unavailable",
            "phase": "restore",
            "role": "optional_capability",
            "count": 2,
        }
    ]


def test_registered_extension_must_operationally_open_each_declared_virtual_table():
    queries: list[str] = []

    class AdvertisedButIncompatibleConnection:
        def execute(self, sql):
            queries.append(sql)
            if sql == "PRAGMA module_list":
                return [("fts5",), ("vec0",)]
            if sql == 'SELECT 1 FROM "odd""vec" LIMIT 0':
                raise sqlite3.OperationalError("incompatible persisted vec table")
            return iter(())

    available = offline_restore_v2._capabilities(
        cast(sqlite3.Connection, AdvertisedButIncompatibleConnection()),
        {"fts_working": "fts5", 'odd"vec': "vec0"},
    )

    assert available == {"sqlite", "fts5"}
    assert queries == [
        "PRAGMA module_list",
        'SELECT 1 FROM "fts_working" LIMIT 0',
        'SELECT 1 FROM "odd""vec" LIMIT 0',
    ]


def test_writer_to_restore_round_trip_loads_sqlite_vec_per_validation_connection(
    tmp_path, monkeypatch
):
    sqlite_vec = pytest.importorskip("sqlite_vec")
    source = tmp_path / "vec-source.sqlite"
    connection = sqlite3.connect(source)
    try:
        connection.enable_load_extension(True)
        sqlite_vec.load(connection)
        connection.enable_load_extension(False)
        connection.execute("PRAGMA user_version=17")
        connection.execute(
            "CREATE VIRTUAL TABLE vec_items USING vec0(embedding float[2])"
        )
        connection.execute(
            "INSERT INTO vec_items(rowid, embedding) VALUES (1, ?)",
            (sqlite_vec.serialize_float32([1.0, 2.0]),),
        )
        connection.commit()
    finally:
        connection.close()
    archive = tmp_path / "vec-backup.mnbak"
    create_backup_v2(source, archive)
    manifest, _payload = _manifest_and_payload(archive)
    loads = 0
    real_loader = offline_restore_v2._load_optional_sqlite_vec

    def tracked_loader(validation_connection):
        nonlocal loads
        loads += 1
        return real_loader(validation_connection)

    monkeypatch.setattr(offline_restore_v2, "_load_optional_sqlite_vec", tracked_loader)
    destination = tmp_path / "vec-restored"

    _restore(archive, destination, manifest)

    assert loads == 3
    restored = sqlite3.connect(destination / "stores" / "default.sqlite")
    try:
        restored.enable_load_extension(True)
        sqlite_vec.load(restored)
        restored.enable_load_extension(False)
        assert restored.execute("SELECT rowid FROM vec_items LIMIT 1").fetchone() == (
            1,
        )
    finally:
        restored.close()


def test_required_sqlite_vec_unavailable_fails_capability_check(tmp_path, monkeypatch):
    sqlite_vec = pytest.importorskip("sqlite_vec")
    source = tmp_path / "vec-source.sqlite"
    connection = sqlite3.connect(source)
    try:
        connection.enable_load_extension(True)
        sqlite_vec.load(connection)
        connection.enable_load_extension(False)
        connection.execute(
            "CREATE VIRTUAL TABLE vec_items USING vec0(embedding float[2])"
        )
        connection.commit()
    finally:
        connection.close()
    archive = tmp_path / "vec-backup.mnbak"
    create_backup_v2(source, archive)
    manifest, _payload = _manifest_and_payload(archive)
    monkeypatch.setattr(
        offline_restore_v2, "_load_optional_sqlite_vec", lambda _connection: False
    )
    destination = tmp_path / "vec-restored"

    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, manifest)

    assert caught.value.as_diagnostic() == {
        "code": "capability_unavailable",
        "phase": "restore",
    }
    assert not destination.exists()
    assert len(_stages(tmp_path)) == 1


def test_omitted_blobs_require_both_database_only_and_partial_opt_in(tmp_path):
    archive, manifest = _backup(tmp_path)
    destination = tmp_path / "restored"

    for kwargs, code in [
        ({}, "blob_missing"),
        ({"allow_partial": True}, "blob_missing"),
        ({"allow_database_only": True}, "discovery_incomplete"),
    ]:
        with pytest.raises(OfflineRestoreV2Error) as caught:
            restore_backup_v2(
                archive,
                destination,
                store_id="default",
                known_schemas=_schema_policy(manifest),
                **kwargs,
            )
        assert caught.value.code == code
        assert not destination.exists()


def test_writer_blob_references_restore_database_only_with_redacted_omission_count(
    tmp_path,
):
    digest = hashlib.sha256(b"intentionally not packaged").hexdigest()
    archive, manifest = _backup(
        tmp_path,
        content=f"blob://sha256/{digest}",
    )
    destination = tmp_path / "restored"

    result = restore_backup_v2(
        archive,
        destination,
        store_id="default",
        known_schemas=_schema_policy(manifest),
        allow_partial=True,
        allow_database_only=True,
    )

    assert result["status"] == "partial"
    assert result["self_contained"] is False
    assert result["diagnostics"] == [
        {
            "code": "blob_bytes_excluded",
            "phase": "restore",
            "role": "owned_blob",
            "count": 1,
        }
    ]
    assert digest not in json.dumps(result)
    restored = sqlite3.connect(destination / "stores" / "default.sqlite")
    try:
        assert restored.execute("SELECT content FROM working_memory").fetchone() == (
            f"blob://sha256/{digest}",
        )
    finally:
        restored.close()


def test_declared_owned_blob_is_verified_and_published_with_store(tmp_path):
    blob = b"private owned bytes"
    digest = hashlib.sha256(blob).hexdigest()
    member = f"blobs/sha256/{digest[:2]}/{digest[:4]}/{digest}"
    reference = f"prefix blob://sha256/{digest} suffix"
    archive, manifest = _backup(tmp_path, quoted_reference=reference)

    def add_blob(doc, payloads):
        payloads[member] = blob
        doc["stores"][0]["dependencies"] = ["owned-blob"]
        doc["stores"].append(
            {
                "store_id": "owned-blob",
                "kind": "blob",
                "classification": "external/blob",
                "required": True,
                "location_hint": "default",
                "archive_path": member,
                "media_type": "application/octet-stream",
                "bytes": len(blob),
                "sha256": digest,
                "dependencies": [],
                "handling": "snapshot",
                "privacy": "high",
                "verification": {
                    "status": "verified",
                    "checks": [{"name": "sha256", "status": "pass"}],
                },
            }
        )
        doc["status"] = "complete"
        doc["discovery"] = {"state": "complete", "reason_codes": []}
        doc["coverage"] = {"state": "complete", "reason_codes": []}
        doc["self_contained"] = True
        # Counts are advisory: actual distinct references, not this value,
        # determine whether the selected blob dependencies are complete.
        doc["external_references"] = [{"scheme": "blob", "count": 99, "owned": True}]
        doc["scope"] = {
            "requested": ["default"],
            "discovered": ["default", "owned-blob"],
            "included": ["default", "owned-blob"],
            "excluded": [],
        }
        doc["warnings"] = []

    manifest = _rewrite(archive, add_blob)
    destination = tmp_path / "restored"
    result = restore_backup_v2(
        archive,
        destination,
        store_id="default",
        known_schemas=_schema_policy(manifest),
    )

    assert result["status"] == "complete"
    assert result["self_contained"] is True
    assert result["stores"] == [
        {"store": "selected_store", "verification": "verified"},
        {"store": "selected_blob", "verification": "verified"},
    ]
    assert (destination / member).read_bytes() == blob
    _assert_database(destination / "stores" / "default.sqlite")


def test_actual_owned_blob_reference_missing_from_dependencies_blocks_publish(tmp_path):
    missing_digest = hashlib.sha256(b"not packaged").hexdigest()
    archive, manifest = _backup(
        tmp_path,
        content=f"blob://sha256/{missing_digest}",
    )

    def claim_complete(doc, _payloads):
        doc["status"] = "complete"
        doc["discovery"] = {"state": "complete", "reason_codes": []}
        doc["coverage"] = {"state": "complete", "reason_codes": []}
        doc["self_contained"] = True
        # Deliberately plausible but false: the old restore trusted this count.
        doc["external_references"] = []
        doc["warnings"] = []

    manifest = _rewrite(archive, claim_complete)
    destination = tmp_path / "restored"

    with pytest.raises(OfflineRestoreV2Error) as caught:
        restore_backup_v2(
            archive,
            destination,
            store_id="default",
            known_schemas=_schema_policy(manifest),
        )

    assert caught.value.as_diagnostic() == {
        "code": "blob_missing",
        "phase": "restore",
    }
    assert not destination.exists()
    assert len(_stages(tmp_path)) == 1


def test_blob_storage_reference_missing_from_dependencies_blocks_publish(tmp_path):
    missing_digest = hashlib.sha256(b"not packaged blob storage").hexdigest()
    archive, manifest = _backup(
        tmp_path,
        content=f"blob://sha256/{missing_digest}".encode("ascii"),
    )
    source = sqlite3.connect(tmp_path / "source.sqlite")
    try:
        assert source.execute(
            "SELECT typeof(content) FROM working_memory"
        ).fetchone() == ("blob",)
    finally:
        source.close()

    def claim_complete(doc, _payloads):
        doc["status"] = "complete"
        doc["discovery"] = {"state": "complete", "reason_codes": []}
        doc["coverage"] = {"state": "complete", "reason_codes": []}
        doc["self_contained"] = True
        doc["external_references"] = []
        doc["warnings"] = []

    manifest = _rewrite(archive, claim_complete)
    destination = tmp_path / "restored"

    with pytest.raises(OfflineRestoreV2Error) as caught:
        restore_backup_v2(
            archive,
            destination,
            store_id="default",
            known_schemas=_schema_policy(manifest),
        )

    assert caught.value.as_diagnostic() == {
        "code": "blob_missing",
        "phase": "restore",
    }
    assert not destination.exists()
    assert len(_stages(tmp_path)) == 1


def test_stored_generated_blob_reference_requires_selected_dependency(tmp_path):
    blob_store_id = "generated-owned-blob"
    digest = hashlib.sha256(f"bytes for {blob_store_id}".encode()).hexdigest()
    archive, manifest = _backup(
        tmp_path,
        generated_reference_digest=digest,
    )

    def add_unselected_blob(doc, payloads):
        _append_blob(
            doc,
            payloads,
            store_id=blob_store_id,
            dependencies=[],
        )

    # The blob exists and is required, but the selected SQLite store does not
    # depend on it. Required dependency closure must reject the package.
    manifest = _rewrite(archive, add_unselected_blob)
    destination = tmp_path / "restored"

    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, manifest)

    assert caught.value.as_diagnostic() == {
        "code": "invalid_manifest",
        "phase": "verify",
    }
    assert not destination.exists()


@pytest.mark.parametrize(
    ("limit_name", "limit"),
    [
        ("_REFERENCE_SCAN_TABLES", 0),
        ("_REFERENCE_SCAN_COLUMNS_PER_TABLE", 1),
    ],
)
def test_actual_reference_catalog_limits_fail_closed_before_publish(
    tmp_path, monkeypatch, limit_name, limit
):
    archive, manifest = _backup(tmp_path)
    destination = tmp_path / "restored"
    monkeypatch.setattr(offline_restore_v2, limit_name, limit)

    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, manifest)

    assert caught.value.as_diagnostic() == {
        "code": "limit_exceeded",
        "phase": "restore",
    }
    assert not destination.exists()


def test_restored_schema_catalog_limit_fails_before_publication(tmp_path):
    archive, manifest = _backup(tmp_path)
    catalog_limit = len(manifest["stores"][0]["catalog"])

    def add_undeclared_schema_object(doc, payloads):
        member = doc["stores"][0]["archive_path"]
        database = tmp_path / "expanded-catalog.sqlite"
        database.write_bytes(payloads[member])
        connection = sqlite3.connect(database)
        try:
            connection.execute("CREATE TABLE extra_catalog_object (value TEXT)")
            connection.commit()
        finally:
            connection.close()
        payloads[member] = database.read_bytes()
        doc["stores"][0]["bytes"] = len(payloads[member])
        doc["stores"][0]["sha256"] = hashlib.sha256(payloads[member]).hexdigest()

    manifest = _rewrite(archive, add_undeclared_schema_object)
    destination = tmp_path / "restored"

    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(
            archive,
            destination,
            manifest,
            limits=InspectionLimits(catalog_objects_per_store=catalog_limit),
        )

    assert caught.value.as_diagnostic() == {
        "code": "limit_exceeded",
        "phase": "restore",
    }
    assert not destination.exists()


def test_actual_reference_catalog_queries_are_bounded_before_iteration(
    tmp_path, monkeypatch
):
    database = tmp_path / "bounded.sqlite"
    _database(database)
    connection = sqlite3.connect(database)
    catalog_queries: list[tuple[str, tuple]] = []

    class CursorWithoutFetchall:
        def __init__(self, cursor):
            self.cursor = cursor

        def __iter__(self):
            return iter(self.cursor)

        def fetchone(self):
            return self.cursor.fetchone()

        def fetchall(self):
            pytest.fail("catalog scan used fetchall")

    class RecordingConnection:
        def execute(self, sql, parameters=()):
            if "sqlite_master" in sql or "pragma_table_xinfo" in sql:
                catalog_queries.append((sql, parameters))
            return CursorWithoutFetchall(connection.execute(sql, parameters))

        def set_progress_handler(self, handler, steps):
            connection.set_progress_handler(handler, steps)

    monkeypatch.setattr(offline_restore_v2, "_REFERENCE_SCAN_TABLES", 1)
    monkeypatch.setattr(
        offline_restore_v2,
        "_REFERENCE_SCAN_COLUMNS_PER_TABLE",
        2,
    )
    try:
        recording_connection = cast(sqlite3.Connection, RecordingConnection())
        assert (
            offline_restore_v2._actual_blob_references(recording_connection)
            == frozenset()
        )
    finally:
        connection.close()

    assert len(catalog_queries) == 2
    assert "LIMIT ?" in catalog_queries[0][0]
    assert catalog_queries[0][1] == (2,)
    assert "LIMIT ?" in catalog_queries[1][0]
    assert catalog_queries[1][1] == ("working_memory", 3)


def test_incomplete_actual_reference_scan_fails_closed_before_publish(
    tmp_path, monkeypatch
):
    archive, manifest = _backup(tmp_path)
    destination = tmp_path / "restored"
    monkeypatch.setattr(offline_restore_v2, "_REFERENCE_SCAN_CELLS", 0)

    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, manifest)

    assert caught.value.as_diagnostic() == {
        "code": "limit_exceeded",
        "phase": "restore",
    }
    assert not destination.exists()


def test_unlinked_blob_is_not_extracted_or_reported(tmp_path):
    archive, manifest = _backup(tmp_path)
    member: str | None = None

    def add_unlinked_blob(doc, payloads):
        nonlocal member
        member = _append_blob(
            doc,
            payloads,
            store_id="unlinked-blob",
            dependencies=[],
            required=False,
        )

    manifest = _rewrite(archive, add_unlinked_blob)
    destination = tmp_path / "restored"
    result = _restore(archive, destination, manifest)

    assert member is not None
    assert not (destination / member).exists()
    assert result["stores"] == [{"store": "selected_store", "verification": "verified"}]
    _assert_database(destination / "stores" / "default.sqlite")


def test_required_unlinked_blob_blocks_even_claimed_complete_restore(tmp_path):
    archive, manifest = _backup(tmp_path)

    def add_required_unlinked_blob(doc, payloads):
        _append_blob(
            doc,
            payloads,
            store_id="required-unlinked-blob",
            dependencies=[],
        )
        doc["status"] = "complete"
        doc["discovery"] = {"state": "complete", "reason_codes": []}
        doc["coverage"] = {"state": "complete", "reason_codes": []}
        doc["self_contained"] = True
        doc["warnings"] = []

    manifest = _rewrite(archive, add_required_unlinked_blob)
    destination = tmp_path / "restored"

    with pytest.raises(OfflineRestoreV2Error) as caught:
        restore_backup_v2(
            archive,
            destination,
            store_id="default",
            known_schemas=_schema_policy(manifest),
        )

    assert caught.value.as_diagnostic() == {
        "code": "invalid_manifest",
        "phase": "verify",
    }
    assert not destination.exists()
    assert not _stages(tmp_path)


def test_transitive_blob_dependency_closure_is_verified_and_published(tmp_path):
    direct_digest = hashlib.sha256(b"bytes for direct-blob").hexdigest()
    transitive_digest = hashlib.sha256(b"bytes for transitive-blob").hexdigest()
    archive, manifest = _backup(
        tmp_path,
        content=(f"blob://sha256/{direct_digest} blob://sha256/{transitive_digest}"),
    )
    members: list[str] = []

    def add_transitive_blobs(doc, payloads):
        members.append(
            _append_blob(
                doc,
                payloads,
                store_id="direct-blob",
                dependencies=["transitive-blob"],
            )
        )
        members.append(
            _append_blob(
                doc,
                payloads,
                store_id="transitive-blob",
                dependencies=[],
            )
        )
        doc["stores"][0]["dependencies"] = ["direct-blob"]

    manifest = _rewrite(archive, add_transitive_blobs)
    destination = tmp_path / "restored"
    result = _restore(archive, destination, manifest)

    assert all((destination / member).exists() for member in members)
    assert result["stores"] == [
        {"store": "selected_store", "verification": "verified"},
        {"store": "selected_blob", "verification": "verified"},
        {"store": "selected_blob", "verification": "verified"},
    ]


def test_transitive_dependency_cycle_is_invalid_before_staging(tmp_path):
    archive, manifest = _backup(tmp_path)

    def add_cycle(doc, payloads):
        _append_blob(doc, payloads, store_id="cycle-a", dependencies=["cycle-b"])
        _append_blob(doc, payloads, store_id="cycle-b", dependencies=["cycle-a"])
        doc["stores"][0]["dependencies"] = ["cycle-a"]

    manifest = _rewrite(archive, add_cycle)
    destination = tmp_path / "restored"

    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, manifest)

    assert caught.value.as_diagnostic() == {
        "code": "invalid_manifest",
        "phase": "verify",
    }
    assert not destination.exists()
    assert not _stages(tmp_path)


def test_restore_uses_selected_store_dependencies_not_inverse_blob_references(tmp_path):
    selected_blob = b"bytes for selected-secret-id"
    selected_digest = hashlib.sha256(selected_blob).hexdigest()
    archive, manifest = _backup(
        tmp_path,
        content=f"blob://sha256/{selected_digest}",
    )
    selected_member: str | None = None
    inverse_member: str | None = None

    def add_blobs(doc, payloads):
        nonlocal selected_member, inverse_member
        selected_member = _append_blob(
            doc, payloads, store_id="selected-secret-id", dependencies=[]
        )
        inverse_member = _append_blob(
            doc,
            payloads,
            store_id="inverse-secret-id",
            dependencies=["default"],
            required=False,
        )
        doc["stores"][0]["dependencies"] = ["selected-secret-id"]

    manifest = _rewrite(archive, add_blobs)
    destination = tmp_path / "restored"
    result = _restore(archive, destination, manifest)

    assert selected_member is not None and inverse_member is not None
    assert (destination / selected_member).exists()
    assert not (destination / inverse_member).exists()
    rendered = json.dumps(result)
    assert "selected-secret-id" not in rendered
    assert "inverse-secret-id" not in rendered
    assert result["stores"] == [
        {"store": "selected_store", "verification": "verified"},
        {"store": "selected_blob", "verification": "verified"},
    ]


@pytest.mark.parametrize("dependency", ["missing-store", "default"])
def test_selected_store_dependencies_must_name_declared_blobs(tmp_path, dependency):
    archive, manifest = _backup(tmp_path)
    manifest = _rewrite(
        archive,
        lambda doc, _payloads: doc["stores"][0].__setitem__(
            "dependencies", [dependency]
        ),
    )
    destination = tmp_path / "restored"

    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, manifest)

    assert caught.value.as_diagnostic() == {
        "code": "invalid_manifest",
        "phase": "verify",
    }
    assert not destination.exists()


@pytest.mark.parametrize(
    ("verification_status", "check_status", "dependencies", "expected_code"),
    [
        ("failed", "fail", ["default"], "invalid_manifest"),
        ("unverifiable", "unverifiable", ["default"], "invalid_manifest"),
        ("failed", "fail", [], "checksum_mismatch"),
        ("verified", "fail", ["default"], "invalid_manifest"),
    ],
)
def test_required_blob_failed_verification_blocks_partial_restore(
    tmp_path, verification_status, check_status, dependencies, expected_code
):
    archive, manifest = _backup(tmp_path)

    def add_failed_blob(doc, payloads):
        _append_blob(
            doc,
            payloads,
            store_id="required-blob",
            dependencies=dependencies,
            verification_status=verification_status,
            check_status=check_status,
        )
        if dependencies == ["default"]:
            doc["stores"][0]["dependencies"] = ["required-blob"]
        if verification_status == "failed":
            doc["status"] = "failed"

    manifest = _rewrite(archive, add_failed_blob)
    destination = tmp_path / "restored"

    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, manifest)

    assert caught.value.as_diagnostic() == {
        "code": expected_code,
        "phase": "verify",
    }
    assert not destination.exists()


@pytest.mark.parametrize("bad_dependency", ["missing-store", "required-blob"])
def test_all_dependency_ids_must_resolve_and_cannot_be_self_referential(
    tmp_path, bad_dependency
):
    archive, manifest = _backup(tmp_path)

    def add_invalid_blob(doc, payloads):
        _append_blob(
            doc,
            payloads,
            store_id="required-blob",
            dependencies=[bad_dependency],
        )

    manifest = _rewrite(archive, add_invalid_blob)
    destination = tmp_path / "restored"

    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, manifest)

    assert caught.value.as_diagnostic() == {
        "code": "invalid_manifest",
        "phase": "verify",
    }
    assert not destination.exists()


def test_failed_manifest_rejects_even_with_partial_opt_in_before_staging(tmp_path):
    archive, manifest = _backup(tmp_path)
    manifest = _rewrite(
        archive, lambda doc, _payloads: doc.__setitem__("status", "failed")
    )
    destination = tmp_path / "restored"

    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, manifest)

    assert caught.value.as_diagnostic() == {
        "code": "discovery_incomplete",
        "phase": "verify",
    }
    assert not destination.exists()
    assert not _stages(tmp_path)


def test_prepublish_failure_leaves_destination_absent_and_preserves_private_stage(
    tmp_path, monkeypatch
):
    archive, manifest = _backup(tmp_path)
    destination = tmp_path / "restored"

    def fail(*_args, **_kwargs):
        raise OfflineRestoreV2Error("sqlite_integrity_failed", "restore")

    def unsafe_cleanup(*_args, **_kwargs):
        pytest.fail("pre-publication failure attempted pathname cleanup")

    monkeypatch.setattr(offline_restore_v2, "_verify_sqlite", fail)
    monkeypatch.setattr(offline_restore_v2, "_rename_no_replace_os", unsafe_cleanup)
    monkeypatch.setattr(offline_restore_v2.os, "unlink", unsafe_cleanup)
    monkeypatch.setattr(offline_restore_v2.os, "rmdir", unsafe_cleanup)
    with pytest.raises(OfflineRestoreV2Error):
        _restore(archive, destination, manifest)

    assert not destination.exists()
    stage = next(iter(_stages(tmp_path)))
    _assert_database(stage / "stores" / "default.sqlite")


def test_success_preserves_destination_parent_mode_and_ownership(tmp_path):
    archive, manifest = _backup(tmp_path)
    parent = tmp_path / "destination-parent"
    parent.mkdir(mode=0o751)
    parent.chmod(0o751)
    before = parent.stat()

    _restore(archive, parent / "restored", manifest)

    after = parent.stat()
    assert stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode) == 0o751
    assert (after.st_uid, after.st_gid) == (before.st_uid, before.st_gid)


def test_prepublish_failure_preserves_destination_parent_mode_and_ownership(
    tmp_path, monkeypatch
):
    archive, manifest = _backup(tmp_path)
    parent = tmp_path / "destination-parent"
    parent.mkdir(mode=0o751)
    parent.chmod(0o751)
    before = parent.stat()

    def fail(*_args, **_kwargs):
        raise OfflineRestoreV2Error("sqlite_integrity_failed", "restore")

    monkeypatch.setattr(offline_restore_v2, "_verify_sqlite", fail)
    with pytest.raises(OfflineRestoreV2Error):
        _restore(archive, parent / "restored", manifest)

    after = parent.stat()
    assert stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode) == 0o751
    assert (after.st_uid, after.st_gid) == (before.st_uid, before.st_gid)


def test_replaced_staging_name_is_never_cleaned(tmp_path, monkeypatch):
    archive, manifest = _backup(tmp_path)
    destination = tmp_path / "restored"
    displaced = tmp_path / "displaced-stage"
    replacement: Path | None = None

    def replace_and_fail(image, *_args, **_kwargs):
        nonlocal replacement
        stage = tmp_path / image.parent.parent.name
        stage.rename(displaced)
        stage.mkdir(mode=0o700)
        replacement = stage
        (stage / "canary").write_bytes(b"keep")
        raise OfflineRestoreV2Error("sqlite_integrity_failed", "restore")

    monkeypatch.setattr(offline_restore_v2, "_verify_sqlite", replace_and_fail)
    with pytest.raises(OfflineRestoreV2Error):
        _restore(archive, destination, manifest)

    assert replacement is not None
    assert (replacement / "canary").read_bytes() == b"keep"
    assert (displaced / "stores" / "default.sqlite").exists()
    assert not destination.exists()


def test_staging_replacement_after_validation_is_not_published_or_cleaned(
    tmp_path, monkeypatch
):
    archive, manifest = _backup(tmp_path)
    destination = tmp_path / "restored"
    displaced = tmp_path / "validated-stage"
    original = offline_restore_v2._fsync_tree

    def replace_after_validation(stage, directories):
        original(stage, directories)
        (tmp_path / stage.name).rename(displaced)
        replacement = tmp_path / stage.name
        replacement.mkdir(mode=0o700)
        (replacement / "canary").write_bytes(b"do not publish or delete")

    monkeypatch.setattr(offline_restore_v2, "_fsync_tree", replace_after_validation)
    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, manifest)

    assert caught.value.as_diagnostic() == {"code": "staging_failed", "phase": "stage"}
    assert not destination.exists()
    replacement = next(tmp_path.glob(".mnbak-restore-*"))
    assert (replacement / "canary").read_bytes() == b"do not publish or delete"
    _assert_database(displaced / "stores" / "default.sqlite")


def test_in_place_mutation_after_initial_verification_is_not_published(
    tmp_path, monkeypatch
):
    archive, manifest = _backup(tmp_path)
    destination = tmp_path / "restored"
    original = offline_restore_v2._fsync_tree

    def mutate_after_verification(stage, directories):
        original(stage, directories)
        image = Path(f"/proc/self/fd/{stage.fd}") / "stores" / "default.sqlite"
        image.chmod(0o600)
        connection = sqlite3.connect(image)
        try:
            connection.execute(
                "UPDATE working_memory SET content = 'tampered data' WHERE id = 'one'"
            )
            connection.commit()
        finally:
            connection.close()

    monkeypatch.setattr(offline_restore_v2, "_fsync_tree", mutate_after_verification)
    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, manifest)

    assert caught.value.code == "checksum_mismatch"
    assert not destination.exists()


@pytest.mark.parametrize("replacement_kind", ["file", "directory"])
def test_prepublish_replacement_after_final_tree_check_survives_safe_leakage(
    tmp_path, monkeypatch, replacement_kind
):
    archive, manifest = _backup(tmp_path)
    destination = tmp_path / "restored"
    original_tree_matches = offline_restore_v2._tree_matches
    checked = False

    def replace_after_tree_check(stage, directories, files):
        nonlocal checked
        matches = original_tree_matches(stage, directories, files)
        if matches and not checked:
            checked = True
            stores = Path(f"/proc/self/fd/{stage.fd}") / "stores"
            if replacement_kind == "file":
                (stores / "default.sqlite").rename(stores / "verified-original")
                (stores / "default.sqlite").write_bytes(b"concurrent replacement")
            else:
                stores.rename(stores.parent / "verified-stores")
                stores.mkdir()
                (stores / "canary").write_bytes(b"concurrent replacement")
            # Model detection immediately after the final complete identity
            # check.  Failure cleanup must not act on either replaced name.
            return False
        return matches

    monkeypatch.setattr(offline_restore_v2, "_tree_matches", replace_after_tree_check)
    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, manifest)

    assert checked
    assert caught.value.as_diagnostic() == {"code": "staging_failed", "phase": "stage"}
    leaked = next(iter(_stages(tmp_path)))
    if replacement_kind == "file":
        replacement = leaked / "stores" / "default.sqlite"
        assert replacement.read_bytes() == b"concurrent replacement"
        _assert_database(leaked / "stores" / "verified-original")
    else:
        replacement = leaked / "stores"
        assert (replacement / "canary").read_bytes() == b"concurrent replacement"
        _assert_database(leaked / "verified-stores" / "default.sqlite")
    assert not destination.exists()


def test_postpublish_uncertainty_preserves_published_destination(tmp_path, monkeypatch):
    archive, manifest = _backup(tmp_path)
    destination = tmp_path / "restored"
    original = offline_restore_v2._rename_no_replace

    def publish_then_report_uncertainty(parent, source, target):
        original(parent, source, target)
        raise OfflineRestoreV2Error("publish_failed", "publish")

    monkeypatch.setattr(
        offline_restore_v2, "_rename_no_replace", publish_then_report_uncertainty
    )
    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, manifest)

    assert caught.value.code == "publish_failed"
    _assert_database(destination / "stores" / "default.sqlite")


def test_final_mode_metadata_is_flushed_before_tree_and_parent(tmp_path, monkeypatch):
    archive, manifest = _backup(tmp_path)
    destination = tmp_path / "restored"
    events: list[tuple[str, int, int]] = []
    real_fchmod = os.fchmod
    real_fsync = os.fsync

    def record_fchmod(descriptor, mode):
        events.append(("chmod", descriptor, mode))
        return real_fchmod(descriptor, mode)

    def record_fsync(descriptor):
        observed = os.fstat(descriptor)
        events.append(("fsync", descriptor, stat.S_IFMT(observed.st_mode)))
        return real_fsync(descriptor)

    monkeypatch.setattr(offline_restore_v2.os, "fchmod", record_fchmod)
    monkeypatch.setattr(offline_restore_v2.os, "fsync", record_fsync)

    _restore(archive, destination, manifest)

    final_chmod = max(
        index
        for index, event in enumerate(events)
        if event[0] == "chmod" and event[2] == 0o600
    )
    final_events = events[final_chmod + 1 :]
    assert [event[2] for event in final_events if event[0] == "fsync"] == [
        stat.S_IFREG,
        stat.S_IFDIR,
        stat.S_IFDIR,
        stat.S_IFDIR,
    ]
    assert (
        stat.S_IMODE((destination / "stores" / "default.sqlite").stat().st_mode)
        == 0o600
    )


def test_final_metadata_fsync_failure_is_a_postpublish_failure(tmp_path, monkeypatch):
    archive, manifest = _backup(tmp_path)
    destination = tmp_path / "restored"
    real_fchmod = os.fchmod
    real_fsync = os.fsync
    sealed = False
    final_modes = False
    final_fsync_kinds: list[int] = []

    def track_fchmod(descriptor, mode):
        nonlocal sealed, final_modes
        result = real_fchmod(descriptor, mode)
        if mode == 0o400:
            sealed = True
        elif sealed and mode == 0o600:
            final_modes = True
        return result

    def fail_tree_fsync(descriptor):
        kind = stat.S_IFMT(os.fstat(descriptor).st_mode)
        if final_modes:
            final_fsync_kinds.append(kind)
            if kind == stat.S_IFDIR:
                raise OSError("injected final tree fsync failure")
        return real_fsync(descriptor)

    monkeypatch.setattr(offline_restore_v2.os, "fchmod", track_fchmod)
    monkeypatch.setattr(offline_restore_v2.os, "fsync", fail_tree_fsync)

    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, manifest)

    assert caught.value.as_diagnostic() == {
        "code": "publish_failed",
        "phase": "publish",
    }
    assert final_fsync_kinds == [stat.S_IFREG, stat.S_IFDIR]
    assert (
        stat.S_IMODE((destination / "stores" / "default.sqlite").stat().st_mode)
        == 0o600
    )


def test_failures_and_reports_never_disclose_paths_hashes_or_exception_text(
    tmp_path, monkeypatch
):
    archive, manifest = _backup(tmp_path)
    destination = tmp_path / "customer-alice-secret"

    def sensitive(*_args, **_kwargs):
        raise sqlite3.OperationalError("token=super-secret /private/alice")

    monkeypatch.setattr(offline_restore_v2, "_verify_sqlite", sensitive)
    with pytest.raises(OfflineRestoreV2Error) as caught:
        _restore(archive, destination, manifest)

    rendered = str(caught.value) + json.dumps(caught.value.as_diagnostic())
    assert "customer-alice" not in rendered
    assert "super-secret" not in rendered
    assert manifest["stores"][0]["sha256"] not in rendered
    assert not destination.exists()

    class SensitivePath:
        def __fspath__(self):
            raise RuntimeError("token=argument-secret /private/input")

    with pytest.raises(OfflineRestoreV2Error) as caught:
        restore_backup_v2(
            SensitivePath(),
            destination,
            store_id="default",
            known_schemas=_schema_policy(manifest),
        )
    assert caught.value.as_diagnostic() == {
        "code": "invalid_argument",
        "phase": "verify",
    }
    assert "argument-secret" not in str(caught.value)


def test_restore_reports_never_disclose_package_store_ids(tmp_path, monkeypatch):
    archive, manifest = _backup(tmp_path)

    def rename_store(doc, payloads):
        store = doc["stores"][0]
        payloads["stores/package-local-secret.sqlite"] = payloads.pop(
            store["archive_path"]
        )
        store["store_id"] = "package-local-secret"
        store["archive_path"] = "stores/package-local-secret.sqlite"
        doc["scope"]["requested"] = ["package-local-secret"]
        doc["scope"]["discovered"] = [
            "package-local-secret",
            "owned-blobs",
        ]
        doc["scope"]["included"] = ["package-local-secret"]

    manifest = _rewrite(archive, rename_store)
    success = restore_backup_v2(
        archive,
        tmp_path / "successful-restore",
        store_id="package-local-secret",
        known_schemas=_schema_policy(manifest),
        allow_partial=True,
        allow_database_only=True,
    )
    assert "package-local-secret" not in json.dumps(success)

    def fail_restore(*_args, **_kwargs):
        raise OfflineRestoreV2Error("schema_mismatch", "restore")

    monkeypatch.setattr(offline_restore_v2, "_verify_sqlite", fail_restore)
    with pytest.raises(OfflineRestoreV2Error) as caught:
        restore_backup_v2(
            archive,
            tmp_path / "failed-restore",
            store_id="package-local-secret",
            known_schemas=_schema_policy(manifest),
            allow_partial=True,
            allow_database_only=True,
        )

    rendered = str(caught.value) + json.dumps(caught.value.as_diagnostic())
    assert "package-local-secret" not in rendered
