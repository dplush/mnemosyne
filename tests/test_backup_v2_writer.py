from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import zipfile
from pathlib import Path
from typing import cast

import pytest
from jsonschema import Draft202012Validator

from mnemosyne.dr import backup_v2
from mnemosyne.dr.backup_v2 import BackupV2Error, create_backup_v2


def _database(path: Path, *, journal_mode: str = "delete") -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute(f"PRAGMA journal_mode={journal_mode}")
    connection.execute("PRAGMA user_version=17")
    connection.execute("PRAGMA application_id=42")
    connection.execute(
        "CREATE TABLE working_memory (id TEXT PRIMARY KEY, content TEXT NOT NULL)"
    )
    connection.execute("CREATE INDEX idx_working_content ON working_memory(content)")
    connection.execute(
        "CREATE TRIGGER working_no_delete BEFORE DELETE ON working_memory "
        "BEGIN SELECT RAISE(ABORT, 'no'); END"
    )
    connection.commit()
    return connection


def _package(path: Path) -> tuple[dict, bytes]:
    with zipfile.ZipFile(path) as archive:
        assert archive.namelist() == ["manifest.json", "stores/default.sqlite"]
        assert archive.getinfo("manifest.json").compress_type == zipfile.ZIP_STORED
        manifest = json.loads(archive.read("manifest.json"))
        payload = archive.read("stores/default.sqlite")
    return manifest, payload


def _working_rows(path: Path) -> list[tuple[str, str]]:
    connection = sqlite3.connect(path)
    try:
        return connection.execute(
            "SELECT id, content FROM working_memory ORDER BY id"
        ).fetchall()
    finally:
        connection.close()


def _assert_no_staging(directory: Path) -> None:
    assert not [path for path in directory.iterdir() if path.name.startswith(".")]


def _private_stages(directory: Path) -> list[Path]:
    return [
        path for path in directory.iterdir() if path.name.startswith(".mnbak-work-")
    ]


def _assert_private_staging_retained(directory: Path) -> Path:
    stages = _private_stages(directory)
    assert len(stages) == 1
    stage = stages[0]
    observed = stage.stat()
    assert stat.S_IMODE(observed.st_mode) == 0o700
    assert observed.st_uid == os.geteuid()
    return stage


def _assert_failure_staging_retained(error: BackupV2Error, directory: Path) -> Path:
    stage = _assert_private_staging_retained(directory)
    assert error.as_diagnostic()["cleanup"] == {
        "status": "not_completed",
        "temporary_directory": str(stage),
    }
    return stage


def test_post_open_parent_close_failure_closes_child_once(tmp_path, monkeypatch):
    target = tmp_path / "existing"
    target.mkdir()
    caller_owned = os.open(tmp_path, backup_v2._directory_flags())
    real_open = backup_v2.os.open
    real_close = backup_v2.os.close
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
    monkeypatch.setattr(backup_v2.os, "open", tracked_open)
    monkeypatch.setattr(backup_v2.os, "close", failing_close)

    try:
        with pytest.raises(OSError) as exc_info:
            backup_v2._open_directory(target, create=False)

        assert exc_info.value is failure
        assert len(opened) == 2
        assert close_calls == opened
        assert len(os.listdir("/proc/self/fd")) == before
        os.fstat(caller_owned)
    finally:
        real_close(caller_owned)


@pytest.mark.parametrize(
    "failure",
    [KeyboardInterrupt("injected interrupt"), MemoryError("injected exhaustion")],
    ids=["keyboard-interrupt", "memory-error"],
)
def test_working_directory_fstat_base_exception_closes_descriptor_once(
    tmp_path, monkeypatch, failure
):
    parent = backup_v2._open_directory(tmp_path, create=False)
    real_open = backup_v2.os.open
    real_fstat = backup_v2.os.fstat
    real_close = backup_v2.os.close
    real_unlink = backup_v2.os.unlink
    real_rmdir = backup_v2.os.rmdir
    opened: list[int] = []
    close_calls: list[int] = []
    pathname_cleanup_calls: list[tuple[str, object]] = []
    close_failure = OSError("injected close failure")

    def tracked_open(*args, **kwargs):
        descriptor = real_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def interrupt_fstat(descriptor):
        if opened and descriptor == opened[-1]:
            raise failure
        return real_fstat(descriptor)

    def tracked_close(descriptor):
        close_calls.append(descriptor)
        real_close(descriptor)
        raise close_failure

    def track_unlink(path, *args, **kwargs):
        pathname_cleanup_calls.append(("unlink", path))
        return real_unlink(path, *args, **kwargs)

    def track_rmdir(path, *args, **kwargs):
        pathname_cleanup_calls.append(("rmdir", path))
        return real_rmdir(path, *args, **kwargs)

    before = len(os.listdir("/proc/self/fd"))
    monkeypatch.setattr(backup_v2.os, "open", tracked_open)
    monkeypatch.setattr(backup_v2.os, "fstat", interrupt_fstat)
    monkeypatch.setattr(backup_v2.os, "close", tracked_close)
    monkeypatch.setattr(backup_v2.os, "unlink", track_unlink)
    monkeypatch.setattr(backup_v2.os, "rmdir", track_rmdir)

    try:
        with pytest.raises(type(failure)) as caught:
            backup_v2._create_working_directory(parent)

        assert caught.value is failure
        assert len(opened) == 1
        assert close_calls == opened
        assert len(os.listdir("/proc/self/fd")) == before
        assert pathname_cleanup_calls == []
        assert len(_private_stages(tmp_path)) == 1
    finally:
        real_close(parent.fd)


def test_writes_v2_snapshot_manifest_full_hashes_and_catalog(tmp_path):
    source = tmp_path / "source.sqlite"
    connection = _database(source)
    connection.execute(
        "INSERT INTO working_memory(id, content) VALUES (?, ?)",
        ("one", "private-content-do-not-copy-to-manifest"),
    )
    connection.commit()
    connection.close()
    destination = tmp_path / "private" / "backup.mnbak"

    result = create_backup_v2(
        source, destination, source_revision="5f3d7df84b6eea1c127a448aa4eedb600f0cec8e"
    )

    manifest, payload = _package(destination)
    assert result["status"] == "partial"
    assert result["self_contained"] is False
    assert result["sha256"] == hashlib.sha256(destination.read_bytes()).hexdigest()
    assert manifest["format"] == "org.mnemosyne.backup"
    assert (manifest["format_version"], manifest["manifest_version"]) == (2, 1)
    assert (
        manifest["producer"]["source_revision"]
        == "5f3d7df84b6eea1c127a448aa4eedb600f0cec8e"
    )
    assert manifest["status"] == "partial"
    assert manifest["consistency"] == "transactional"
    assert manifest["self_contained"] is False
    assert manifest["coverage"] == {
        "state": "partial",
        "reason_codes": ["blob_bytes_excluded"],
    }
    assert manifest["scope"]["excluded"] == [
        {"store_id": "owned-blobs", "reason_code": "blob_bytes_excluded"}
    ]
    store = manifest["stores"][0]
    assert store["bytes"] == len(payload)
    assert store["sha256"] == hashlib.sha256(payload).hexdigest()
    assert len(store["sha256"]) == 64
    assert store["sqlite"]["user_version"] == 17
    assert store["sqlite"]["application_id"] == 42
    assert store["sqlite"]["page_size"] >= 512
    assert store["sqlite"]["page_count"] > 0
    assert len(store["sqlite"]["schema_sha256"]) == 64
    catalog = {entry["name"]: entry for entry in store["catalog"]}
    assert catalog["working_memory"]["classification"] == "authoritative"
    assert catalog["working_memory"]["row_count"] == 1
    assert catalog["idx_working_content"]["dependencies"] == ["working_memory"]
    assert catalog["working_no_delete"]["object_type"] == "trigger"
    assert "private-content-do-not-copy-to-manifest" not in json.dumps(manifest)
    snapshot = tmp_path / "snapshot.sqlite"
    snapshot.write_bytes(payload)
    restored = sqlite3.connect(snapshot)
    try:
        assert restored.execute("SELECT content FROM working_memory").fetchone() == (
            "private-content-do-not-copy-to-manifest",
        )
        schema_rows = restored.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_stat%' ORDER BY type, name"
        ).fetchall()
        expected_schema_hash = hashlib.sha256(
            json.dumps(schema_rows, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()
        assert store["sqlite"]["schema_sha256"] == expected_schema_hash
    finally:
        restored.close()


def test_online_backup_includes_committed_wal_rows(tmp_path):
    source = tmp_path / "wal.sqlite"
    writer = _database(source, journal_mode="wal")
    writer.execute(
        "INSERT INTO working_memory(id, content) VALUES ('wal-row', 'visible in wal')"
    )
    writer.commit()
    assert source.with_name(source.name + "-wal").exists()
    destination = tmp_path / "output" / "wal.mnbak"

    create_backup_v2(source, destination)

    _, payload = _package(destination)
    snapshot = tmp_path / "wal-snapshot.sqlite"
    snapshot.write_bytes(payload)
    reader = sqlite3.connect(snapshot)
    try:
        assert reader.execute("SELECT id, content FROM working_memory").fetchall() == [
            ("wal-row", "visible in wal")
        ]
        assert reader.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        reader.close()
        writer.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_private_directory_archive_and_members(tmp_path):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    directory = tmp_path / "backup-dir"
    directory.mkdir(mode=0o755)
    destination = directory / "private.mnbak"

    create_backup_v2(source, destination)

    assert stat.S_IMODE(directory.stat().st_mode) == 0o755
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    with zipfile.ZipFile(destination) as archive:
        for info in archive.infolist():
            assert stat.S_IFMT((info.external_attr >> 16) & 0xFFFF) == stat.S_IFREG
            assert stat.S_IMODE((info.external_attr >> 16) & 0xFFFF) == 0o600
    _assert_no_staging(directory)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
@pytest.mark.parametrize("mode", [0o711, 0o750])
def test_preexisting_destination_parent_mode_is_preserved(tmp_path, mode):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    directory = tmp_path / "caller-owned"
    directory.mkdir()
    directory.chmod(mode)

    create_backup_v2(source, directory / "backup.mnbak")

    assert stat.S_IMODE(directory.stat().st_mode) == mode
    _assert_no_staging(directory)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
@pytest.mark.parametrize("mode", [0o770, 0o775, 0o777, 0o1777])
def test_writable_destination_parent_retains_writer_state(tmp_path, mode):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    directory = tmp_path / "caller-owned"
    directory.mkdir()
    directory.chmod(mode)
    destination = directory / "backup.mnbak"

    result = create_backup_v2(source, destination)

    _package(destination)
    assert stat.S_IMODE(directory.stat().st_mode) == mode
    retained = Path(result["cleanup"]["temporary_directory"])
    assert result["cleanup"]["status"] == "not_completed"
    assert retained.parent == directory
    assert retained.name.startswith(".mnbak-work-")
    assert {path.name for path in retained.iterdir()} == {
        "archive.mnbak",
        "snapshot.sqlite",
    }
    assert result["warnings"][-1] == {
        "code": "cleanup_not_completed",
        "phase": "cleanup",
        "temporary_directory": str(retained),
    }


def test_unknown_catalog_is_preserved_but_never_claimed_complete(tmp_path):
    source = tmp_path / "source.sqlite"
    connection = _database(source)
    connection.execute("CREATE TABLE plugin_secret_state (value TEXT)")
    connection.execute("INSERT INTO plugin_secret_state VALUES ('sensitive')")
    connection.commit()
    connection.close()
    destination = tmp_path / "out" / "unknown.mnbak"

    create_backup_v2(source, destination)

    manifest, payload = _package(destination)
    unknown = next(
        item
        for item in manifest["stores"][0]["catalog"]
        if item["name"] == "plugin_secret_state"
    )
    assert unknown["classification"] == "unknown/owner decision required"
    assert manifest["discovery"]["state"] == "unknown"
    assert "unknown_store" in manifest["discovery"]["reason_codes"]
    assert "sensitive" not in json.dumps(manifest)
    snapshot = tmp_path / "unknown-snapshot.sqlite"
    snapshot.write_bytes(payload)
    restored = sqlite3.connect(snapshot)
    try:
        assert restored.execute("SELECT value FROM plugin_secret_state").fetchone() == (
            "sensitive",
        )
    finally:
        restored.close()


def test_external_reference_manifest_is_count_only_and_blob_exclusion_is_explicit(
    tmp_path,
):
    source = tmp_path / "source.sqlite"
    connection = _database(source)
    connection.execute("CREATE TABLE media_assets (ref_kind TEXT, ref_value TEXT)")
    connection.executemany(
        "INSERT INTO media_assets VALUES (?, ?)",
        [
            ("url", "https://user:secret@example.invalid/private?q=token"),
            ("blob", "blob://sha256/" + "a" * 64),
            ("file", "/home/alice/private.mov"),
        ],
    )
    connection.commit()
    connection.close()
    destination = tmp_path / "out" / "refs.mnbak"

    create_backup_v2(source, destination)

    manifest, _ = _package(destination)
    assert manifest["external_references"] == [
        {"scheme": "blob", "count": 1, "owned": True},
        {"scheme": "file", "count": 1, "owned": False},
        {"scheme": "url", "count": 1, "owned": False},
    ]
    rendered = json.dumps(manifest)
    for secret in ("user:secret", "example.invalid", "/home/alice", "a" * 64):
        assert secret not in rendered
    assert manifest["self_contained"] is False
    assert manifest["coverage"]["state"] == "partial"


def test_external_reference_scheme_normalization_matches_sqlite_lower(tmp_path):
    source = tmp_path / "source.sqlite"
    connection = _database(source)
    connection.execute("CREATE TABLE media_assets (ref_kind TEXT, ref_value TEXT)")
    connection.executemany(
        "INSERT INTO media_assets VALUES (?, '')",
        [(b"URL",), ("url",), ("K",), ("!",)],
    )
    connection.commit()
    try:
        assert backup_v2._external_references(connection) == [
            {"scheme": "unknown", "count": 2, "owned": False},
            {"scheme": "url", "count": 2, "owned": False},
        ]
    finally:
        connection.close()


def test_external_reference_bucket_discovery_streams_and_fails_on_first_excess(
    tmp_path, monkeypatch
):
    source = tmp_path / "source.sqlite"
    connection = _database(source)
    connection.execute("CREATE TABLE media_assets (ref_kind TEXT, ref_value TEXT)")
    connection.executemany(
        "INSERT INTO media_assets VALUES (?, '')",
        [(f"scheme-{index}",) for index in range(10_000)],
    )
    connection.commit()
    streamed = 0

    class BoundedCursor:
        def __init__(self, cursor):
            self.cursor = cursor

        def __iter__(self):
            nonlocal streamed
            for row in self.cursor:
                streamed += 1
                if streamed > 4:
                    pytest.fail(
                        "external-reference discovery scanned past first excess bucket"
                    )
                yield row

    class RecordingConnection:
        def execute(self, sql, parameters=()):
            assert "GROUP BY" not in sql.upper()
            cursor = connection.execute(sql, parameters)
            if sql == "SELECT lower(ref_kind) FROM media_assets":
                return BoundedCursor(cursor)
            return cursor

    monkeypatch.setitem(backup_v2._LIMITS, "external_reference_buckets", 3)
    try:
        with pytest.raises(BackupV2Error) as caught:
            backup_v2._external_references(
                cast(sqlite3.Connection, RecordingConnection())
            )
    finally:
        connection.close()

    assert caught.value.as_diagnostic() == {
        "code": "limit_exceeded",
        "phase": "discover",
    }
    assert streamed == 4


def test_prepublication_verification_failure_safe_leaks_without_pathname_cleanup(
    tmp_path, monkeypatch
):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    directory = tmp_path / "out"
    destination = directory / "failed.mnbak"

    def fail(*_args, **_kwargs):
        raise BackupV2Error("checksum_mismatch", "verify")

    pathname_cleanup_calls: list[tuple[str, object]] = []
    original_unlink = backup_v2.os.unlink
    original_rmdir = backup_v2.os.rmdir

    def track_unlink(path, *args, **kwargs):
        pathname_cleanup_calls.append(("unlink", path))
        return original_unlink(path, *args, **kwargs)

    def track_rmdir(path, *args, **kwargs):
        pathname_cleanup_calls.append(("rmdir", path))
        return original_rmdir(path, *args, **kwargs)

    monkeypatch.setattr(backup_v2, "_verify_archive", fail)
    monkeypatch.setattr(backup_v2.os, "unlink", track_unlink)
    monkeypatch.setattr(backup_v2.os, "rmdir", track_rmdir)
    with pytest.raises(BackupV2Error) as caught:
        create_backup_v2(source, destination)

    retained = _assert_failure_staging_retained(caught.value, directory)
    assert caught.value.as_diagnostic() == {
        "code": "checksum_mismatch",
        "phase": "verify",
        "cleanup": {
            "status": "not_completed",
            "temporary_directory": str(retained),
        },
    }
    assert not destination.exists()
    assert {path.name for path in retained.iterdir()} == {
        "archive.mnbak",
        "snapshot.sqlite",
    }
    assert pathname_cleanup_calls == []


@pytest.mark.parametrize(
    "failure",
    [KeyboardInterrupt("injected interrupt"), MemoryError("injected exhaustion")],
    ids=["keyboard-interrupt", "memory-error"],
)
def test_prepublication_base_exception_safe_leaks_without_pathname_cleanup(
    tmp_path, monkeypatch, failure
):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    directory = tmp_path / "out"
    destination = directory / "interrupted.mnbak"

    def fail(*_args, **_kwargs):
        raise failure

    pathname_cleanup_calls: list[tuple[str, object]] = []
    original_unlink = backup_v2.os.unlink
    original_rmdir = backup_v2.os.rmdir

    def track_unlink(path, *args, **kwargs):
        pathname_cleanup_calls.append(("unlink", path))
        return original_unlink(path, *args, **kwargs)

    def track_rmdir(path, *args, **kwargs):
        pathname_cleanup_calls.append(("rmdir", path))
        return original_rmdir(path, *args, **kwargs)

    monkeypatch.setattr(backup_v2, "_verify_archive", fail)
    monkeypatch.setattr(backup_v2.os, "unlink", track_unlink)
    monkeypatch.setattr(backup_v2.os, "rmdir", track_rmdir)
    before = len(os.listdir("/proc/self/fd"))
    with pytest.raises(type(failure)) as caught:
        create_backup_v2(source, destination)

    assert caught.value is failure
    retained = _assert_private_staging_retained(directory)
    assert not destination.exists()
    assert {path.name for path in retained.iterdir()} == {
        "archive.mnbak",
        "snapshot.sqlite",
    }
    assert pathname_cleanup_calls == []
    assert len(os.listdir("/proc/self/fd")) <= before


def test_postpublication_verification_failure_preserves_publication(
    tmp_path, monkeypatch
):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    directory = tmp_path / "out"
    destination = directory / "failed.mnbak"
    original = backup_v2._verify_archive
    calls = 0

    def fail_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise BackupV2Error("checksum_mismatch", "verify")
        return original(*args, **kwargs)

    monkeypatch.setattr(backup_v2, "_verify_archive", fail_second)
    with pytest.raises(BackupV2Error) as caught:
        create_backup_v2(source, destination)

    assert calls == 2
    assert destination.exists()
    _package(destination)
    _assert_failure_staging_retained(caught.value, directory)


def test_existing_destination_is_not_replaced(tmp_path):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    directory = tmp_path / "out"
    directory.mkdir()
    destination = directory / "exists.mnbak"
    destination.write_bytes(b"keep me")

    with pytest.raises(BackupV2Error) as caught:
        create_backup_v2(source, destination)

    assert caught.value.code == "destination_exists"
    assert destination.read_bytes() == b"keep me"
    _assert_no_staging(directory)


def test_diagnostics_do_not_disclose_paths_or_underlying_errors(tmp_path, monkeypatch):
    private_name = "customer-alice-secret.sqlite"
    missing = tmp_path / private_name
    destination = tmp_path / "out" / "backup.mnbak"

    with pytest.raises(BackupV2Error) as caught:
        create_backup_v2(missing, destination)

    assert private_name not in str(caught.value)
    assert private_name not in json.dumps(caught.value.as_diagnostic())

    source = tmp_path / "source.sqlite"
    _database(source).close()

    def sensitive_failure(_source, _snapshot):
        underlying = sqlite3.OperationalError("token=super-secret path=/private/alice")
        raise BackupV2Error("snapshot_failed", "snapshot") from underlying

    monkeypatch.setattr(backup_v2, "_snapshot", sensitive_failure)
    with pytest.raises(BackupV2Error) as caught:
        create_backup_v2(source, destination)
    assert "super-secret" not in str(caught.value)
    assert "private/alice" not in str(caught.value)


def test_rejects_unbounded_identifiers_and_non_mnbak_destination(tmp_path):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    for destination, kwargs in [
        (tmp_path / "bad.zip", {}),
        (tmp_path / "bad.mnbak", {"store_id": "../escape"}),
        (tmp_path / "bad.mnbak", {"location_hint": "/private/source"}),
        (tmp_path / "bad.mnbak", {"source_revision": "not-a-revision"}),
    ]:
        with pytest.raises(BackupV2Error) as caught:
            create_backup_v2(source, destination, **kwargs)
        assert caught.value.code == "invalid_argument"


@pytest.mark.parametrize(
    "location_hint",
    [
        "bank/customer",
        "bank\\customer",
        "../default",
        "default/child",
        "C:\\private",
        "token=super-secret",
        "customer-alice-secret",
        "bank:customer-name",
        "bank:" + "a" * 65,
        "default\nsecret",
        None,
    ],
)
def test_location_hint_rejects_paths_controls_and_arbitrary_labels(
    tmp_path, location_hint
):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    destination = tmp_path / "out" / "bad.mnbak"

    with pytest.raises(BackupV2Error) as caught:
        create_backup_v2(source, destination, location_hint=location_hint)

    assert caught.value.code == "invalid_argument"
    assert not destination.exists()


def test_location_hint_accepts_fixed_roles_and_redacted_bank_ids(tmp_path):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    for index, hint in enumerate(
        ["default", "shared", "triples", "query-cache", "bank:" + "a1" * 8]
    ):
        create_backup_v2(source, tmp_path / f"out-{index}.mnbak", location_hint=hint)


def test_manifest_validates_as_a_whole_against_packaged_normative_schema(tmp_path):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    destination = tmp_path / "out" / "schema.mnbak"

    create_backup_v2(source, destination)

    manifest, _ = _package(destination)
    Draft202012Validator(
        backup_v2._manifest_schema(),
        format_checker=backup_v2._MANIFEST_FORMAT_CHECKER,
    ).validate(manifest)


def test_schema_invalid_manifest_is_rejected_before_publication(tmp_path, monkeypatch):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    destination = tmp_path / "out" / "invalid-schema.mnbak"
    original_manifest = backup_v2._manifest

    def invalid_manifest(**kwargs):
        manifest = original_manifest(**kwargs)
        manifest["unexpected"] = True
        return manifest

    monkeypatch.setattr(backup_v2, "_manifest", invalid_manifest)
    with pytest.raises(BackupV2Error) as caught:
        create_backup_v2(source, destination)

    diagnostic = caught.value.as_diagnostic()
    assert diagnostic["code"] == "invalid_manifest"
    assert diagnostic["phase"] == "package"
    assert not destination.exists()
    _assert_failure_staging_retained(caught.value, destination.parent)


def test_overlong_catalog_metadata_is_rejected_before_archive_publication(tmp_path):
    source = tmp_path / "source.sqlite"
    connection = _database(source)
    connection.execute(f'CREATE TABLE "{"x" * 256}" (value TEXT)')
    connection.commit()
    connection.close()
    directory = tmp_path / "out"
    destination = directory / "too-long.mnbak"

    with pytest.raises(BackupV2Error) as caught:
        create_backup_v2(source, destination)

    diagnostic = caught.value.as_diagnostic()
    assert diagnostic["code"] == "limit_exceeded"
    assert diagnostic["phase"] == "discover"
    assert not destination.exists()
    _assert_failure_staging_retained(caught.value, directory)


def test_catalog_object_limit_fails_before_archive_publication(tmp_path, monkeypatch):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    directory = tmp_path / "out"
    destination = directory / "too-many-objects.mnbak"
    monkeypatch.setitem(backup_v2._LIMITS, "catalog_objects_per_store", 2)

    with pytest.raises(BackupV2Error) as caught:
        create_backup_v2(source, destination)

    diagnostic = caught.value.as_diagnostic()
    assert diagnostic["code"] == "limit_exceeded"
    assert diagnostic["phase"] == "discover"
    assert not destination.exists()
    _assert_failure_staging_retained(caught.value, directory)


def test_schema_catalog_query_uses_limit_sentinel_before_materializing():
    queries: list[tuple[str, tuple[int]]] = []

    class BoundedConnection:
        def execute(self, sql, parameters=()):
            queries.append((sql, parameters))
            return iter(
                [
                    (1, "index", "a", "a", 14),
                    (2, "table", "b", "b", 14),
                    (3, "table", "c", "c", 14),
                ]
            )

    with pytest.raises(backup_v2._CatalogLimitExceeded):
        backup_v2._schema_rows(BoundedConnection(), limit=2)  # type: ignore[arg-type]

    assert queries == [
        (
            "SELECT rowid, type, name, tbl_name, "
            "CASE WHEN sql IS NULL THEN NULL ELSE length(CAST(sql AS BLOB)) END "
            "FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_stat%' ORDER BY type, name LIMIT ?",
            (3,),
        )
    ]


@pytest.mark.parametrize(
    ("value_limit", "total_limit"),
    [(16, 1024 * 1024), (1024 * 1024, 32)],
)
def test_schema_sql_limits_fail_redacted_before_publication(
    tmp_path, monkeypatch, value_limit, total_limit
):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    destination = tmp_path / "out" / "schema-limit.mnbak"
    monkeypatch.setattr(backup_v2, "_SCHEMA_SQL_VALUE_BYTES", value_limit)
    monkeypatch.setattr(backup_v2, "_SCHEMA_SQL_TOTAL_BYTES", total_limit)

    with pytest.raises(BackupV2Error) as caught:
        create_backup_v2(source, destination)

    diagnostic = caught.value.as_diagnostic()
    assert diagnostic["code"] == "limit_exceeded"
    assert diagnostic["phase"] == "discover"
    assert not destination.exists()
    _assert_failure_staging_retained(caught.value, destination.parent)


def test_success_removes_all_private_staging_artifacts(tmp_path):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    directory = tmp_path / "out"
    destination = directory / "backup.mnbak"

    result = create_backup_v2(source, destination)

    assert destination.exists()
    assert destination.stat().st_nlink == 1
    assert result["cleanup"] == {"status": "complete"}
    assert not any(
        warning["code"] == "cleanup_not_completed" for warning in result["warnings"]
    )
    _assert_no_staging(directory)


def test_replacement_before_atomic_cleanup_claim_is_retained_and_reported(
    tmp_path, monkeypatch
):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    destination = tmp_path / "out" / "backup.mnbak"
    canary = b"replacement before atomic cleanup claim"
    original_rename = backup_v2._rename_no_replace
    replaced = False

    def replace_before_claim(parent_fd, source_name, cleanup_name):
        nonlocal replaced
        working = _private_stages(destination.parent)[0]
        staged_archive = working / "archive.mnbak"
        staged_archive.unlink()
        staged_archive.write_bytes(canary)
        replaced = True
        return original_rename(parent_fd, source_name, cleanup_name)

    monkeypatch.setattr(backup_v2, "_rename_no_replace", replace_before_claim)
    result = create_backup_v2(source, destination)

    assert result["backup_path"] == str(destination)
    _package(destination)
    assert replaced
    assert result["cleanup"]["status"] == "not_completed"
    stage = Path(result["cleanup"]["temporary_directory"])
    assert stage.is_absolute()
    assert stage.parent == destination.parent
    assert stage.name.startswith(".mnbak-cleanup-")
    assert (stage / "archive.mnbak").read_bytes() == canary
    assert (stage / "snapshot.sqlite").exists()
    assert result["warnings"][-1] == {
        "code": "cleanup_not_completed",
        "phase": "cleanup",
        "temporary_directory": str(stage),
    }


@pytest.mark.parametrize("primary_failure", [False, True])
def test_final_close_failure_preserves_outcome_and_reports_cleanup_residual(
    tmp_path, monkeypatch, primary_failure
):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    destination = tmp_path / "out" / "backup.mnbak"
    real_file_close = backup_v2._BoundFile.close
    close_calls: list[int] = []
    injected = False

    def close_and_fail_once(item):
        nonlocal injected
        close_calls.append(item.fd)
        real_file_close(item)
        if not injected:
            injected = True
            raise OSError("injected final close failure")

    monkeypatch.setattr(backup_v2._BoundFile, "close", close_and_fail_once)
    if primary_failure:

        def fail_verify(*_args, **_kwargs):
            raise BackupV2Error("checksum_mismatch", "verify")

        monkeypatch.setattr(backup_v2, "_verify_archive", fail_verify)

    before = len(os.listdir("/proc/self/fd"))
    if primary_failure:
        with pytest.raises(BackupV2Error) as caught:
            create_backup_v2(source, destination)
        stage = _assert_private_staging_retained(destination.parent)
        assert caught.value.as_diagnostic() == {
            "code": "checksum_mismatch",
            "phase": "verify",
            "cleanup": {
                "status": "not_completed",
                "temporary_directory": str(stage),
            },
        }
    else:
        result = create_backup_v2(source, destination)
        stage = _assert_private_staging_retained(destination.parent)
        assert result["backup_path"] == str(destination)
        assert result["cleanup"] == {
            "status": "not_completed",
            "temporary_directory": str(stage),
        }
        assert result["warnings"][-1]["code"] == "cleanup_not_completed"

    assert injected
    assert len(close_calls) == 3
    assert len(set(close_calls)) == len(close_calls)
    assert len(os.listdir("/proc/self/fd")) <= before


@pytest.mark.parametrize("operation", ["unlink", "rmdir"])
def test_cleanup_operation_failure_keeps_publication_and_reports_residual(
    tmp_path, monkeypatch, operation
):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    destination = tmp_path / "out" / "backup.mnbak"
    if operation == "unlink":
        original_unlink = backup_v2.os.unlink

        def fail_cleanup_unlink(name, *args, **kwargs):
            if name == "archive.mnbak":
                raise OSError("sensitive unlink detail")
            return original_unlink(name, *args, **kwargs)

        monkeypatch.setattr(backup_v2.os, "unlink", fail_cleanup_unlink)
    else:
        original_rmdir = backup_v2.os.rmdir

        def fail_cleanup_rmdir(name, *args, **kwargs):
            if str(name).startswith(".mnbak-cleanup-"):
                raise OSError("sensitive rmdir detail")
            return original_rmdir(name, *args, **kwargs)

        monkeypatch.setattr(backup_v2.os, "rmdir", fail_cleanup_rmdir)

    result = create_backup_v2(source, destination)

    _package(destination)
    assert result["cleanup"]["status"] == "not_completed"
    retained = Path(result["cleanup"]["temporary_directory"])
    assert retained.is_absolute() and retained.is_dir()
    if operation == "unlink":
        assert {path.name for path in retained.iterdir()} == {
            "archive.mnbak",
            "snapshot.sqlite",
        }
    else:
        assert list(retained.iterdir()) == []
    assert "sensitive" not in json.dumps(result)


def test_repeated_success_does_not_accumulate_staging(tmp_path):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    directory = tmp_path / "out"

    for index in range(8):
        result = create_backup_v2(source, directory / f"backup-{index}.mnbak")
        assert result["cleanup"] == {"status": "complete"}

    assert sorted(path.name for path in directory.iterdir()) == [
        f"backup-{index}.mnbak" for index in range(8)
    ]


def test_cleanup_warning_redacts_errors_except_required_local_path(
    tmp_path, monkeypatch
):
    source = tmp_path / "customer-alice-secret.sqlite"
    _database(source).close()
    destination = tmp_path / "out" / "backup.mnbak"

    def fail_claim(*_args, **_kwargs):
        raise OSError("token=super-secret path=/private/alice")

    monkeypatch.setattr(backup_v2, "_rename_no_replace", fail_claim)
    result = create_backup_v2(source, destination)

    retained = result["cleanup"]["temporary_directory"]
    assert Path(retained).is_absolute()
    rendered = json.dumps(result)
    assert retained in rendered
    for secret in ("customer-alice-secret", "super-secret", "/private/alice"):
        assert secret not in rendered


def test_unknown_prefix_table_is_not_misclassified_as_fts5_shadow(tmp_path):
    source = tmp_path / "source.sqlite"
    connection = _database(source)
    try:
        connection.execute("CREATE VIRTUAL TABLE fts_working USING fts5(content)")
    except sqlite3.OperationalError:
        pytest.skip("SQLite FTS5 unavailable")
    connection.execute("CREATE TABLE fts_working_credentials (value TEXT)")
    connection.commit()
    connection.close()
    destination = tmp_path / "out" / "fts.mnbak"

    create_backup_v2(source, destination)

    manifest, _ = _package(destination)
    catalog = {item["name"]: item for item in manifest["stores"][0]["catalog"]}
    for suffix in ("config", "content", "data", "docsize", "idx"):
        assert (
            catalog[f"fts_working_{suffix}"]["classification"] == "derived/rebuildable"
        )
    assert catalog["fts_working_credentials"]["classification"] == (
        "unknown/owner decision required"
    )
    assert manifest["discovery"]["state"] == "unknown"


def test_source_final_and_ancestor_symlinks_are_rejected(tmp_path):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    real_source = real_dir / "source.sqlite"
    _database(real_source).close()
    source_link = tmp_path / "source-link.sqlite"
    source_link.symlink_to(real_source)
    parent_link = tmp_path / "parent-link"
    parent_link.symlink_to(real_dir, target_is_directory=True)

    for source in (source_link, parent_link / "source.sqlite"):
        destination = tmp_path / f"{source.parent.name}.mnbak"
        with pytest.raises(BackupV2Error) as caught:
            create_backup_v2(source, destination)
        assert caught.value.code == "invalid_argument"
        assert not destination.exists()


def test_destination_ancestor_symlink_is_rejected_without_writing_through_it(tmp_path):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    real_dir = tmp_path / "real-output"
    real_dir.mkdir()
    linked_dir = tmp_path / "linked-output"
    linked_dir.symlink_to(real_dir, target_is_directory=True)
    destination = linked_dir / "backup.mnbak"

    with pytest.raises(BackupV2Error) as caught:
        create_backup_v2(source, destination)

    assert caught.value.as_diagnostic() == {
        "code": "staging_failed",
        "phase": "stage",
    }
    assert not (real_dir / "backup.mnbak").exists()


def test_retained_source_inode_fails_closed_after_final_name_replacement(
    tmp_path, monkeypatch
):
    source = tmp_path / "source.sqlite"
    original_connection = _database(source)
    original_connection.execute(
        "INSERT INTO working_memory VALUES ('original', 'retained inode')"
    )
    original_connection.commit()
    original_connection.close()
    attacker = tmp_path / "attacker.sqlite"
    attacker_connection = _database(attacker)
    attacker_connection.execute(
        "INSERT INTO working_memory VALUES ('attacker', 'replacement inode')"
    )
    attacker_connection.commit()
    attacker_connection.close()
    displaced = tmp_path / "displaced.sqlite"
    destination = tmp_path / "out" / "bound.mnbak"
    original_snapshot = backup_v2._snapshot

    def replace_final_name(bound_source, bound_snapshot, source_connection):
        source.rename(displaced)
        attacker.rename(source)
        return original_snapshot(bound_source, bound_snapshot, source_connection)

    monkeypatch.setattr(backup_v2, "_snapshot", replace_final_name)
    with pytest.raises(BackupV2Error) as caught:
        create_backup_v2(source, destination)

    diagnostic = caught.value.as_diagnostic()
    assert diagnostic["code"] == "snapshot_failed"
    assert diagnostic["phase"] == "snapshot"
    assert not destination.exists()
    assert _working_rows(displaced) == [("original", "retained inode")]
    assert _working_rows(source) == [("attacker", "replacement inode")]
    _assert_failure_staging_retained(caught.value, destination.parent)


def test_retained_source_parent_survives_directory_swap(tmp_path, monkeypatch):
    source_dir = tmp_path / "source-dir"
    source_dir.mkdir()
    source = source_dir / "source.sqlite"
    connection = _database(source)
    connection.execute("INSERT INTO working_memory VALUES ('original', 'bound parent')")
    connection.commit()
    connection.close()
    displaced = tmp_path / "displaced-source-dir"
    destination = tmp_path / "out" / "bound-parent.mnbak"
    original_snapshot = backup_v2._snapshot

    def swap_parent(bound_source, bound_snapshot, source_connection):
        source_dir.rename(displaced)
        source_dir.mkdir()
        replacement = source_dir / source.name
        attacker = _database(replacement)
        attacker.execute(
            "INSERT INTO working_memory VALUES ('attacker', 'replacement parent')"
        )
        attacker.commit()
        attacker.close()
        return original_snapshot(bound_source, bound_snapshot, source_connection)

    monkeypatch.setattr(backup_v2, "_snapshot", swap_parent)
    create_backup_v2(source, destination)

    _, payload = _package(destination)
    extracted = tmp_path / "extracted.sqlite"
    extracted.write_bytes(payload)
    assert _working_rows(extracted) == [("original", "bound parent")]
    assert _working_rows(source) == [("attacker", "replacement parent")]


def test_destination_directory_swap_fails_without_touching_replacement(
    tmp_path, monkeypatch
):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    directory = tmp_path / "out"
    destination = directory / "backup.mnbak"
    displaced = tmp_path / "displaced-output"
    original_verify = backup_v2._verify_archive
    calls = 0

    def swap_after_publication(*args, **kwargs):
        nonlocal calls
        calls += 1
        result = original_verify(*args, **kwargs)
        if calls == 2:
            directory.rename(displaced)
            directory.mkdir()
            destination.write_bytes(b"attacker replacement")
        return result

    monkeypatch.setattr(backup_v2, "_verify_archive", swap_after_publication)
    with pytest.raises(BackupV2Error) as caught:
        create_backup_v2(source, destination)

    diagnostic = caught.value.as_diagnostic()
    assert diagnostic["code"] == "publish_failed"
    assert diagnostic["phase"] == "publish"
    assert destination.read_bytes() == b"attacker replacement"
    _package(displaced / destination.name)
    _assert_failure_staging_retained(caught.value, displaced)


def test_private_staging_is_retained_after_forced_snapshot_failure(
    tmp_path, monkeypatch
):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    destination = tmp_path / "out" / "backup.mnbak"
    observed_working: Path | None = None

    def fail_snapshot(_source, snapshot, _connection):
        nonlocal observed_working
        observed_working = snapshot.parent.path
        working_stat = snapshot.parent.path.stat()
        snapshot_stat = (snapshot.parent.path / snapshot.name).stat()
        assert stat.S_IMODE(working_stat.st_mode) == 0o700
        assert working_stat.st_uid == os.geteuid()
        assert stat.S_IMODE(snapshot_stat.st_mode) == 0o600
        assert snapshot_stat.st_uid == os.geteuid()
        raise BackupV2Error("snapshot_failed", "snapshot")

    monkeypatch.setattr(backup_v2, "_snapshot", fail_snapshot)
    with pytest.raises(BackupV2Error) as caught:
        create_backup_v2(source, destination)

    assert observed_working is not None
    retained = _assert_failure_staging_retained(caught.value, destination.parent)
    assert observed_working == retained
    assert retained.exists()
    assert not destination.exists()


def test_replacement_after_last_identity_check_survives(tmp_path, monkeypatch):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    directory = tmp_path / "out"
    destination = directory / "backup.mnbak"
    canary = b"replacement after final identity check"
    original_directory_check = backup_v2._directory_path_matches
    replaced: Path | None = None

    def replace_staged_entry(bound_directory):
        nonlocal replaced
        result = original_directory_check(bound_directory)
        working = _private_stages(directory)[0]
        staged_archive = working / "archive.mnbak"
        staged_archive.unlink()
        staged_archive.write_bytes(canary)
        replaced = staged_archive
        return result

    monkeypatch.setattr(backup_v2, "_directory_path_matches", replace_staged_entry)

    result = create_backup_v2(source, destination)

    _package(destination)
    assert replaced is not None
    stage = Path(result["cleanup"]["temporary_directory"])
    assert result["cleanup"]["status"] == "not_completed"
    assert stage.name.startswith(".mnbak-cleanup-")
    assert (stage / "archive.mnbak").read_bytes() == canary
    assert (stage / "snapshot.sqlite").exists()


def test_unverified_working_directory_replacement_is_never_cleaned(
    tmp_path, monkeypatch
):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    directory = tmp_path / "out"
    destination = directory / "backup.mnbak"
    displaced = tmp_path / "displaced-working"
    canaries = {
        "snapshot.sqlite": b"replacement snapshot",
        "snapshot.sqlite-journal": b"replacement journal",
        "snapshot.sqlite-wal": b"replacement wal",
        "snapshot.sqlite-shm": b"replacement shm",
        "archive.mnbak": b"replacement archive",
    }
    original_open = backup_v2.os.open
    replacement: Path | None = None

    def replace_before_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal replacement
        if replacement is None and str(path).startswith(".mnbak-work-"):
            created = directory / str(path)
            created.rename(displaced)
            created.mkdir(mode=0o700)
            created.chmod(0o750)
            for name, payload in canaries.items():
                (created / name).write_bytes(payload)
            replacement = created
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(backup_v2.os, "open", replace_before_open)
    with pytest.raises(BackupV2Error) as caught:
        create_backup_v2(source, destination)

    assert caught.value.code == "staging_failed"
    assert replacement is not None
    diagnostic = caught.value.as_diagnostic()
    assert diagnostic["phase"] == "stage"
    assert diagnostic["cleanup"] == {
        "status": "not_completed",
        "temporary_directory": None,
    }
    assert not destination.exists()
    assert stat.S_IMODE(replacement.stat().st_mode) == 0o750
    for name, payload in canaries.items():
        assert (replacement / name).read_bytes() == payload


def test_replacements_at_all_previous_cleanup_names_survive(tmp_path, monkeypatch):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    directory = tmp_path / "out"
    destination = directory / "backup.mnbak"
    token = "1" * 32
    previous_names = [
        f".{destination.name}.{token}.sqlite.tmp",
        f".{destination.name}.{token}.mnbak.tmp",
        f".mnbak-cleanup-{token}",
        f".mnbak-remove-{token}",
    ]
    original_write = backup_v2._write_archive

    def install_replacements(*args, **kwargs):
        raw_manifest = original_write(*args, **kwargs)
        for index, name in enumerate(previous_names):
            (directory / name).write_bytes(f"replacement-{index}".encode())
        return raw_manifest

    def fail_prepublication(*_args, **_kwargs):
        raise BackupV2Error("checksum_mismatch", "verify")

    monkeypatch.setattr(backup_v2, "_write_archive", install_replacements)
    monkeypatch.setattr(backup_v2, "_verify_archive", fail_prepublication)
    with pytest.raises(BackupV2Error) as caught:
        create_backup_v2(source, destination)

    assert not destination.exists()
    for index, name in enumerate(previous_names):
        assert (directory / name).read_bytes() == f"replacement-{index}".encode()
    retained = _assert_failure_staging_retained(caught.value, directory)
    assert {path.name for path in directory.iterdir()} == set(previous_names) | {
        retained.name
    }


@pytest.mark.skipif(os.name == "nt", reason="POSIX UID and permission model")
def test_foreign_uid_parent_replacement_is_retained_and_reported(
    tmp_path, monkeypatch
):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    directory = tmp_path / "out"
    destination = directory / "backup.mnbak"
    canary = b"foreign replacement must survive"
    original_artifact_hash = backup_v2._artifact_hash
    original_parent_check = backup_v2._cleanup_parent_protects_entries
    real_geteuid = backup_v2.os.geteuid
    replacement_installed = False

    def install_replacement(bound):
        nonlocal replacement_installed
        digest = original_artifact_hash(bound)
        working = _private_stages(directory)[0]
        staged_archive = working / "archive.mnbak"
        staged_archive.unlink()
        staged_archive.write_bytes(canary)
        staged_archive.chmod(0o600)
        replacement_installed = True
        return digest

    def observe_foreign_owner(parent):
        monkeypatch.setattr(backup_v2.os, "geteuid", lambda: real_geteuid() + 1)
        try:
            return original_parent_check(parent)
        finally:
            monkeypatch.setattr(backup_v2.os, "geteuid", real_geteuid)

    monkeypatch.setattr(backup_v2, "_artifact_hash", install_replacement)
    monkeypatch.setattr(
        backup_v2, "_cleanup_parent_protects_entries", observe_foreign_owner
    )
    result = create_backup_v2(source, destination)

    _package(destination)
    assert replacement_installed
    retained = Path(result["cleanup"]["temporary_directory"])
    assert result["cleanup"] == {
        "status": "not_completed",
        "temporary_directory": str(retained),
    }
    assert retained.name.startswith(".mnbak-work-")
    assert (retained / "archive.mnbak").read_bytes() == canary
    assert (retained / "snapshot.sqlite").exists()
    assert result["warnings"][-1] == {
        "code": "cleanup_not_completed",
        "phase": "cleanup",
        "temporary_directory": str(retained),
    }


def test_same_uid_replacement_during_cleanup_is_outside_threat_model(
    tmp_path, monkeypatch
):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    directory = tmp_path / "out"
    destination = directory / "backup.mnbak"
    original_unlink = backup_v2.os.unlink
    canary = b"replacement after entry validation"
    injected = False

    def replace_before_unlink(name, *args, **kwargs):
        nonlocal injected
        if not injected and name == "archive.mnbak":
            retained = next(
                path
                for path in directory.iterdir()
                if path.name.startswith(".mnbak-cleanup-")
            )
            original_unlink(name, *args, **kwargs)
            (retained / name).write_bytes(canary)
            (retained / name).chmod(0o600)
            injected = True
        return original_unlink(name, *args, **kwargs)

    monkeypatch.setattr(backup_v2.os, "unlink", replace_before_unlink)
    result = create_backup_v2(source, destination)

    _package(destination)
    assert injected
    assert result["cleanup"] == {"status": "complete"}
    _assert_no_staging(directory)


def test_known_private_sqlite_sidecar_is_removed_by_normal_cleanup(
    tmp_path, monkeypatch
):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    destination = tmp_path / "out" / "backup.mnbak"
    original_write = backup_v2._write_archive
    canary = b"unrecorded sidecar"

    def write_with_sidecar(stage, snapshot, manifest):
        raw_manifest = original_write(stage, snapshot, manifest)
        sidecar = snapshot.parent.path / "snapshot.sqlite-wal"
        sidecar.write_bytes(canary)
        sidecar.chmod(0o600)
        return raw_manifest

    monkeypatch.setattr(backup_v2, "_write_archive", write_with_sidecar)
    result = create_backup_v2(source, destination)

    _package(destination)
    assert result["cleanup"] == {"status": "complete"}
    _assert_no_staging(destination.parent)


def test_fd_dup_failure_reports_verified_writer_directory(tmp_path, monkeypatch):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    destination = tmp_path / "out" / "backup.mnbak"

    real_dup = backup_v2.os.dup
    original_artifact_hash = backup_v2._artifact_hash
    armed = False

    def arm_after_hash(*args, **kwargs):
        nonlocal armed
        result = original_artifact_hash(*args, **kwargs)
        armed = True
        return result

    def fail_dup(descriptor):
        if armed:
            raise OSError("injected dup failure")
        return real_dup(descriptor)

    monkeypatch.setattr(backup_v2.os, "dup", fail_dup)
    monkeypatch.setattr(backup_v2, "_artifact_hash", arm_after_hash)
    result = create_backup_v2(source, destination)

    retained = Path(result["cleanup"]["temporary_directory"])
    assert retained.is_absolute() and retained.is_dir()
    assert retained.name.startswith(".mnbak-work-")
    _package(destination)


def test_fd_dup_and_path_derivation_failure_reports_null(tmp_path, monkeypatch):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    destination = tmp_path / "out" / "backup.mnbak"
    real_readlink = backup_v2.os.readlink
    real_dup = backup_v2.os.dup
    original_artifact_hash = backup_v2._artifact_hash
    armed = False

    def arm_after_hash(*args, **kwargs):
        nonlocal armed
        result = original_artifact_hash(*args, **kwargs)
        armed = True
        return result

    def fail_dup(descriptor):
        if armed:
            raise OSError("injected dup failure")
        return real_dup(descriptor)

    def fail_proc_readlink(path):
        if str(path).startswith("/proc/self/fd/"):
            raise OSError("proc unavailable")
        return real_readlink(path)

    monkeypatch.setattr(backup_v2.os, "dup", fail_dup)
    monkeypatch.setattr(backup_v2, "_artifact_hash", arm_after_hash)
    monkeypatch.setattr(backup_v2.os, "readlink", fail_proc_readlink)
    result = create_backup_v2(source, destination)

    assert result["cleanup"] == {
        "status": "not_completed",
        "temporary_directory": None,
    }
    assert result["warnings"][-1]["temporary_directory"] is None
    _package(destination)


def test_postpublication_destination_replacement_is_never_deleted(
    tmp_path, monkeypatch
):
    source = tmp_path / "source.sqlite"
    _database(source).close()
    destination = tmp_path / "out" / "backup.mnbak"
    original_verify = backup_v2._verify_archive
    calls = 0

    def replace_then_fail(archive_file, *args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            os.unlink(archive_file.name, dir_fd=archive_file.parent.fd)
            destination.write_bytes(b"do not delete")
            raise BackupV2Error("checksum_mismatch", "verify")
        return original_verify(archive_file, *args, **kwargs)

    monkeypatch.setattr(backup_v2, "_verify_archive", replace_then_fail)
    with pytest.raises(BackupV2Error) as caught:
        create_backup_v2(source, destination)

    assert destination.read_bytes() == b"do not delete"
    _assert_failure_staging_retained(caught.value, destination.parent)
