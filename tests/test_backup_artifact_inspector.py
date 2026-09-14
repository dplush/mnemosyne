from __future__ import annotations

import contextlib
import gzip
import hashlib
import json
import sqlite3
import stat
import struct
import zipfile
from pathlib import Path

import pytest

from mnemosyne.dr import artifact_inspector
from mnemosyne.dr.artifact_inspector import InspectionLimits, inspect_backup_artifact


def store(name: str, member: str, payload: bytes, *, kind: str = "sqlite") -> dict:
    value = {
        "store_id": name,
        "kind": kind,
        "classification": "authoritative" if kind == "sqlite" else "external/blob",
        "required": True,
        "location_hint": "default",
        "archive_path": member,
        "media_type": "application/vnd.sqlite3" if kind == "sqlite" else "application/octet-stream",
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "dependencies": [],
        "handling": "snapshot",
        "privacy": "high",
        "verification": {"status": "verified", "checks": [{"name": "sqlite", "status": "pass"}]},
    }
    if kind == "sqlite":
        value.update({
            "sqlite": {
                "page_size": 4096,
                "page_count": 1,
                "user_version": 7,
                "schema_sha256": "0" * 64,
                "required_capabilities": ["sqlite"],
            },
            "catalog": [{
                "name": "working_memory",
                "object_type": "table",
                "classification": "authoritative",
                "handling": "snapshot",
                "row_count": 2,
            }],
        })
    return value


def manifest(stores: list[dict]) -> dict:
    names = [item["store_id"] for item in stores]
    return {
        "format": "org.mnemosyne.backup",
        "format_version": 2,
        "manifest_version": 1,
        "backup_id": "5ec44e25-99d7-41e7-97df-f711d19d39ae",
        "created_at": "2026-09-13T10:00:00Z",
        "producer": {"product": "mnemosyne", "version": "3.14.0", "source_revision": "5f3d7df"},
        "status": "complete",
        "discovery": {"state": "complete", "reason_codes": []},
        "coverage": {"state": "complete", "reason_codes": []},
        "consistency": "transactional",
        "self_contained": True,
        "scope": {"requested": names, "discovered": names, "included": names, "excluded": []},
        "stores": stores,
        "external_references": [],
        "warnings": [],
        "errors": [],
        "limits": {
            "manifest_bytes": 1048576,
            "archive_members": 100000,
            "sqlite_stores": 128,
            "catalog_objects_per_store": 4096,
            "single_member_bytes": 17179869184,
            "total_uncompressed_bytes": 68719476736,
            "compression_ratio": 200,
            "path_bytes": 240,
            "path_depth": 8,
            "diagnostics": 1000,
            "external_reference_buckets": 64,
        },
    }


def package(path: Path, doc: dict, payloads: dict[str, bytes], extras=()) -> None:
    with zipfile.ZipFile(path, "w", allowZip64=True) as archive:
        archive.writestr("manifest.json", json.dumps(doc), compress_type=zipfile.ZIP_STORED)
        for name, payload in payloads.items():
            archive.writestr(name, payload, compress_type=zipfile.ZIP_STORED)
        for name, payload in extras:
            archive.writestr(name, payload, compress_type=zipfile.ZIP_STORED)


def corrupt_deflate_member(path: Path, member: str) -> None:
    with zipfile.ZipFile(path) as archive:
        info = archive.getinfo(member)
    raw = bytearray(path.read_bytes())
    name_size, extra_size = struct.unpack_from("<HH", raw, info.header_offset + 26)
    payload_offset = info.header_offset + 30 + name_size + extra_size
    raw[payload_offset] = 0x07  # BFINAL=1 and reserved BTYPE=3.
    path.write_bytes(raw)


def legacy_artifact(path: Path, content: bytes = b"private legacy content") -> None:
    with gzip.GzipFile(filename=str(path), mode="wb") as backup:
        backup.write(b"BEGIN TRANSACTION;\n-- " + content + b"\nCOMMIT;\n")


def assert_no_legacy_content(result: dict, *secrets: str) -> None:
    rendered = json.dumps(result)
    for secret in secrets:
        assert secret not in rendered


def test_valid_v2_full_check_is_read_only_and_pii_safe(tmp_path, monkeypatch):
    payload = b"not opened as sqlite; checksum only"
    item = store("default", "stores/default.sqlite", payload)
    doc = manifest([item])
    doc["warnings"] = [{
        "code": "capability_unavailable",
        "phase": "verify",
        "store_id": "default",
        "message": "secret-message",
    }]
    artifact = tmp_path / "backup.mnbak"
    package(artifact, doc, {item["archive_path"]: payload})
    before = hashlib.sha256(artifact.read_bytes()).digest()
    monkeypatch.setattr(sqlite3, "connect", lambda *args, **kwargs: pytest.fail("database opened"))
    monkeypatch.setattr(zipfile.ZipFile, "extract", lambda *args, **kwargs: pytest.fail("member extracted"))
    monkeypatch.setattr(zipfile.ZipFile, "extractall", lambda *args, **kwargs: pytest.fail("archive extracted"))

    result = inspect_backup_artifact(artifact)

    assert result["status"] == "valid"
    assert (result["member_count"], result["store_count"]) == (2, 1)
    assert result["stores"][0]["store_name"] == "default"
    assert result["stores"][0]["catalog"][0]["name"] == "working_memory"
    rendered = json.dumps(result)
    assert "5ec44e25" not in rendered
    assert item["sha256"] not in rendered
    assert "secret-message" not in rendered
    assert "not opened as sqlite" not in rendered
    assert hashlib.sha256(artifact.read_bytes()).digest() == before
    assert [entry.name for entry in tmp_path.iterdir()] == ["backup.mnbak"]


def test_valid_v2_dependency_graph_is_accepted(tmp_path):
    payloads = {
        "stores/root.sqlite": b"root",
        "stores/middle.sqlite": b"middle",
        "stores/leaf.sqlite": b"leaf",
    }
    stores = [
        store(Path(member).stem, member, payload)
        for member, payload in payloads.items()
    ]
    stores[0]["dependencies"] = ["middle"]
    stores[1]["dependencies"] = ["leaf"]
    artifact = tmp_path / "dependency-graph.mnbak"
    package(artifact, manifest(stores), payloads)

    result = inspect_backup_artifact(artifact)

    assert result["status"] == "valid"
    assert result["store_count"] == 3


@pytest.mark.parametrize(
    "dependencies",
    [
        [["unknown"], [], []],
        [["root"], [], []],
        [["middle"], ["leaf"], ["root"]],
        ["not-a-list", [], []],
        [["INVALID"], [], []],
        [["middle", "middle"], [], []],
    ],
    ids=[
        "unknown",
        "self",
        "transitive-cycle",
        "invalid-shape",
        "invalid-id",
        "duplicate",
    ],
)
def test_invalid_v2_dependency_graph_is_rejected(tmp_path, dependencies):
    payloads = {
        "stores/root.sqlite": b"root",
        "stores/middle.sqlite": b"middle",
        "stores/leaf.sqlite": b"leaf",
    }
    stores = [
        store(Path(member).stem, member, payload)
        for member, payload in payloads.items()
    ]
    for item, declared_dependencies in zip(stores, dependencies, strict=True):
        item["dependencies"] = declared_dependencies
    artifact = tmp_path / "invalid-dependency-graph.mnbak"
    package(artifact, manifest(stores), payloads)

    result = inspect_backup_artifact(artifact)

    assert result == {
        "status": "invalid",
        "artifact_format": "backup-v2",
        "diagnostics": [{"code": "invalid_manifest", "phase": "verify"}],
    }


def test_unknown_major_is_unsupported_without_payload_inspection(tmp_path, monkeypatch):
    payload = b"payload"
    item = store("default", "stores/default.sqlite", payload)
    doc = manifest([item])
    doc["format_version"] = 3
    artifact = tmp_path / "future.mnbak"
    package(artifact, doc, {item["archive_path"]: payload})
    opened = []
    original_open = zipfile.ZipFile.open

    def tracked_open(archive, member, *args, **kwargs):
        opened.append(member.filename if isinstance(member, zipfile.ZipInfo) else member)
        return original_open(archive, member, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "open", tracked_open)

    assert inspect_backup_artifact(artifact) == {
        "status": "unsupported",
        "artifact_format": "backup-v2",
        "format_version": 3,
        "diagnostics": [{"code": "unsupported_format", "phase": "verify"}],
    }
    assert opened == ["manifest.json"]


@pytest.mark.parametrize("extra, code", [
    (("../escape", b"x"), "unsafe_archive_path"),
    (("stores/default.sqlite", b"duplicate"), "duplicate_archive_member"),
])
def test_traversal_and_duplicate_members_are_rejected(tmp_path, extra, code):
    payload = b"payload"
    item = store("default", "stores/default.sqlite", payload)
    artifact = tmp_path / "unsafe.mnbak"
    warning = pytest.warns(UserWarning) if code == "duplicate_archive_member" else contextlib.nullcontext()
    with warning:
        package(artifact, manifest([item]), {item["archive_path"]: payload}, extras=[extra])

    result = inspect_backup_artifact(artifact)

    assert result["status"] == "invalid"
    assert result["diagnostics"][0]["code"] == code


def test_member_size_limit_is_enforced_from_central_directory(tmp_path):
    payload = b"x" * 6000
    item = store("default", "stores/default.sqlite", payload)
    artifact = tmp_path / "large.mnbak"
    package(artifact, manifest([item]), {item["archive_path"]: payload})

    result = inspect_backup_artifact(artifact, limits=InspectionLimits(single_member_bytes=5000))

    assert result["diagnostics"][0]["code"] == "limit_exceeded"


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_inspection_limits_reject_non_finite_compression_ratio(value):
    with pytest.raises(ValueError, match="compression_ratio must be finite"):
        InspectionLimits(compression_ratio=value)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_legacy_inspection_rejects_non_finite_compression_ratio(
    tmp_path, value
):
    artifact = tmp_path / "mnemosyne_backup_20260913_100000.db.gz"
    legacy_artifact(artifact)

    with pytest.raises(ValueError, match="compression_ratio must be finite"):
        inspect_backup_artifact(
            artifact,
            limits=InspectionLimits(compression_ratio=value),
        )


def test_member_count_is_preflighted_before_zipfile_materializes_directory(tmp_path, monkeypatch):
    payload = b"payload"
    item = store("default", "stores/default.sqlite", payload)
    artifact = tmp_path / "members.mnbak"
    package(artifact, manifest([item]), {item["archive_path"]: payload})
    monkeypatch.setattr(
        zipfile.ZipFile,
        "__init__",
        lambda *args, **kwargs: pytest.fail("ZipFile constructed before count limit"),
    )

    result = inspect_backup_artifact(artifact, limits=InspectionLimits(archive_members=1))

    assert result["diagnostics"][0]["code"] == "limit_exceeded"


def test_symlink_member_is_rejected_before_payload_access(tmp_path):
    payload = b"payload"
    item = store("default", "stores/default.sqlite", payload)
    artifact = tmp_path / "symlink.mnbak"
    link = zipfile.ZipInfo(item["archive_path"])
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest([item])))
        archive.writestr(link, b"outside")

    result = inspect_backup_artifact(artifact)

    assert result["diagnostics"][0]["code"] == "unsafe_archive_path"


def test_manifest_schema_rejects_unknown_fields(tmp_path):
    payload = b"payload"
    item = store("default", "stores/default.sqlite", payload)
    doc = manifest([item])
    doc["secret"] = "must not pass schema validation"
    artifact = tmp_path / "invalid-manifest.mnbak"
    package(artifact, doc, {item["archive_path"]: payload})

    result = inspect_backup_artifact(artifact)

    assert result["diagnostics"][0]["code"] == "invalid_manifest"


def test_manifest_rejects_absolute_location_and_contradictory_complete_status(tmp_path):
    payload = b"payload"
    item = store("default", "stores/default.sqlite", payload)
    item["location_hint"] = "/private/host/path"
    doc = manifest([item])
    doc["coverage"] = {"state": "unknown", "reason_codes": ["unknown_store"]}
    artifact = tmp_path / "contradictory.mnbak"
    package(artifact, doc, {item["archive_path"]: payload})

    result = inspect_backup_artifact(artifact)

    assert result["diagnostics"][0]["code"] == "invalid_manifest"


def test_manifest_rejects_non_json_number_and_contradictory_verification(tmp_path):
    payload = b"payload"
    item = store("default", "stores/default.sqlite", payload)
    item["verification"]["checks"] = [{"name": "sqlite", "status": "fail"}]
    doc = manifest([item])
    doc["limits"]["compression_ratio"] = float("nan")
    artifact = tmp_path / "invalid-values.mnbak"
    package(artifact, doc, {item["archive_path"]: payload})

    result = inspect_backup_artifact(artifact)

    assert result["diagnostics"][0]["code"] == "invalid_manifest"


def test_manifest_declared_limits_are_enforced(tmp_path):
    payload = b"payload"
    item = store("default", "stores/default.sqlite", payload)
    doc = manifest([item])
    doc["limits"]["archive_members"] = 1
    artifact = tmp_path / "declared-limit.mnbak"
    package(artifact, doc, {item["archive_path"]: payload})

    result = inspect_backup_artifact(artifact)

    assert result["diagnostics"][0]["code"] == "limit_exceeded"


def test_full_checksum_mismatch_is_rejected(tmp_path):
    payload = b"payload"
    item = store("default", "stores/default.sqlite", payload)
    item["sha256"] = "f" * 64
    artifact = tmp_path / "mismatch.mnbak"
    package(artifact, manifest([item]), {item["archive_path"]: payload})

    result = inspect_backup_artifact(artifact)

    assert result["status"] == "invalid"
    assert result["diagnostics"][0]["code"] == "checksum_mismatch"


def test_malformed_v2_deflate_is_bounded_invalid_diagnostic(tmp_path):
    payload = b"private compressed payload"
    item = store("default", "stores/default.sqlite", payload)
    artifact = tmp_path / "malformed-deflate.mnbak"
    with zipfile.ZipFile(artifact, "w", allowZip64=True) as archive:
        archive.writestr("manifest.json", json.dumps(manifest([item])))
        archive.writestr(
            item["archive_path"], payload, compress_type=zipfile.ZIP_DEFLATED
        )
    corrupt_deflate_member(artifact, item["archive_path"])

    assert inspect_backup_artifact(artifact) == {
        "status": "invalid",
        "artifact_format": "backup-v2",
        "diagnostics": [{"code": "checksum_mismatch", "phase": "verify"}],
    }


def test_malformed_legacy_deflate_is_bounded_invalid_diagnostic(tmp_path):
    artifact = tmp_path / "malformed.db.gz"
    raw = bytearray(
        gzip.compress(b"BEGIN TRANSACTION;\n-- private\nCOMMIT;\n", mtime=0)
    )
    raw[10] = 0x07  # BFINAL=1 and reserved BTYPE=3.
    artifact.write_bytes(raw)

    assert inspect_backup_artifact(artifact) == {
        "status": "invalid",
        "artifact_format": "legacy-v1",
        "diagnostics": [{"code": "checksum_mismatch", "phase": "verify"}],
    }


def test_missing_legacy_sidecar_reports_unknown_capabilities_without_sql_replay(tmp_path):
    artifact = tmp_path / "mnemosyne_backup_20260913_100000.db.gz"
    legacy_artifact(artifact, b"CREATE TABLE private_data(value)")

    result = inspect_backup_artifact(artifact)

    assert result["status"] == "valid_with_warnings"
    assert result["artifact_format"] == "legacy-v1"
    assert result["sidecar_present"] is False
    assert result["checksum_prefix_status"] == "missing"
    assert result["capabilities"]["sqlite_replay"] == "not_executed"
    assert result["capabilities"]["blob_coverage"] == "unknown"
    assert {item["code"] for item in result["diagnostics"]} >= {
        "legacy_v1_metadata_missing",
        "legacy_v1_completeness_unknown",
        "legacy_v1_restore_unverifiable",
    }
    assert_no_legacy_content(result, "private_data")


@pytest.mark.parametrize(
    ("sidecar_bytes", "limits", "checksum_status", "diagnostic"),
    [
        (b'{"note":"sidecar-secret"', None, "invalid", "invalid_manifest"),
        (
            b'{"note":"sidecar-secret-padding"}',
            InspectionLimits(manifest_bytes=16),
            "invalid",
            "limit_exceeded",
        ),
        (
            json.dumps({"note": "sidecar-secret"}).encode(),
            None,
            "not_declared",
            "invalid_manifest",
        ),
        (
            json.dumps({"backup_checksum": "not-a-checksum", "note": "sidecar-secret"}).encode(),
            None,
            "invalid",
            "invalid_manifest",
        ),
    ],
    ids=["malformed", "oversized", "missing-checksum", "invalid-checksum"],
)
def test_present_unverifiable_legacy_sidecar_fails_closed_without_content_leakage(
    tmp_path, sidecar_bytes, limits, checksum_status, diagnostic
):
    artifact = tmp_path / "mnemosyne_backup_20260913_100000.db.gz"
    legacy_artifact(artifact)
    artifact.with_suffix(".gz.json").write_bytes(sidecar_bytes)

    result = inspect_backup_artifact(artifact, limits=limits)

    assert result["status"] == "invalid"
    assert result["sidecar_present"] is True
    assert result["checksum_prefix_status"] == checksum_status
    assert result["diagnostics"][0]["code"] == diagnostic
    assert_no_legacy_content(result, "private legacy content", "sidecar-secret")


def test_unreadable_legacy_sidecar_fails_closed_without_content_leakage(
    tmp_path, monkeypatch
):
    artifact = tmp_path / "mnemosyne_backup_20260913_100000.db.gz"
    legacy_artifact(artifact)
    sidecar = artifact.with_suffix(".gz.json")
    sidecar.write_text(json.dumps({"note": "sidecar-secret"}))
    real_open = artifact_inspector.os.open

    def deny_sidecar(path, flags):
        if Path(path) == sidecar:
            raise PermissionError("sidecar-secret")
        return real_open(path, flags)

    monkeypatch.setattr(artifact_inspector.os, "open", deny_sidecar)

    result = inspect_backup_artifact(artifact)

    assert result["status"] == "invalid"
    assert result["sidecar_present"] is True
    assert result["checksum_prefix_status"] == "invalid"
    assert result["diagnostics"][0]["code"] == "invalid_manifest"
    assert_no_legacy_content(result, "private legacy content", "sidecar-secret")


def test_non_regular_legacy_sidecar_fails_closed_without_content_leakage(tmp_path):
    artifact = tmp_path / "mnemosyne_backup_20260913_100000.db.gz"
    legacy_artifact(artifact)
    artifact.with_suffix(".gz.json").mkdir()

    result = inspect_backup_artifact(artifact)

    assert result["status"] == "invalid"
    assert result["sidecar_present"] is True
    assert result["checksum_prefix_status"] == "invalid"
    assert result["diagnostics"][0]["code"] == "invalid_manifest"
    assert_no_legacy_content(result, "private legacy content")


def test_legacy_checksum_prefix_match_and_mismatch_do_not_leak_content(tmp_path):
    artifact = tmp_path / "mnemosyne_backup_20260913_100000.db.gz"
    legacy_artifact(artifact)
    sidecar = artifact.with_suffix(".gz.json")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    sidecar.write_text(json.dumps({"backup_checksum": digest[:16], "note": "sidecar-secret"}))
    matched = inspect_backup_artifact(artifact)
    assert matched["status"] == "valid_with_warnings"
    assert matched["checksum_prefix_status"] == "matched"
    assert_no_legacy_content(matched, "private legacy content", "sidecar-secret", digest[:16])

    sidecar.write_text(json.dumps({"backup_checksum": "0" * 16, "note": "sidecar-secret"}))
    result = inspect_backup_artifact(artifact)
    assert result["status"] == "invalid"
    assert result["checksum_prefix_status"] == "mismatch"
    assert result["diagnostics"][0]["code"] == "legacy_v1_checksum_mismatch"
    assert_no_legacy_content(result, "private legacy content", "sidecar-secret", "0" * 16)


def test_legacy_compression_ratio_limit_is_enforced(tmp_path):
    artifact = tmp_path / "ratio.db.gz"
    with gzip.GzipFile(filename=str(artifact), mode="wb") as backup:
        backup.write(b"BEGIN TRANSACTION;\n" + b" " * 20_000 + b"COMMIT;\n")

    result = inspect_backup_artifact(artifact, limits=InspectionLimits(compression_ratio=2))

    assert result["diagnostics"][0]["code"] == "limit_exceeded"


def test_vec0_and_blob_fixture_classifies_manifest_capabilities_only(tmp_path):
    sqlite_payload = b"opaque sqlite bytes"
    sqlite_store = store("default", "stores/default.sqlite", sqlite_payload)
    sqlite_store["sqlite"]["required_capabilities"] = ["sqlite"]
    sqlite_store["sqlite"]["optional_capabilities"] = ["sqlite-vec"]
    sqlite_store["catalog"].append({
        "name": "vec_working",
        "object_type": "virtual-table",
        "classification": "derived/rebuildable",
        "handling": "rebuild",
    })
    sqlite_store["verification"] = {
        "status": "verified_degraded",
        "checks": [
            {"name": "sqlite", "status": "pass"},
            {"name": "sqlite_vec", "status": "degraded", "code": "capability_unavailable"},
        ],
    }
    blob_payload = b"private blob bytes"
    digest = hashlib.sha256(blob_payload).hexdigest()
    blob_path = f"blobs/sha256/{digest[:2]}/{digest[:4]}/{digest}"
    blob_store = store("owned-blob", blob_path, blob_payload, kind="blob")
    blob_store["verification"] = {
        "status": "verified",
        "checks": [{"name": "sha256", "status": "pass"}],
    }
    artifact = tmp_path / "capabilities.mnbak"
    package(artifact, manifest([sqlite_store, blob_store]), {
        sqlite_store["archive_path"]: sqlite_payload,
        blob_path: blob_payload,
    })

    result = inspect_backup_artifact(artifact)

    assert result["status"] == "valid"
    assert result["blob_capability"] == {"state": "included", "member_count": 1}
    default = next(item for item in result["stores"] if item["store_name"] == "default")
    assert default["capabilities"] == {"sqlite": "available", "sqlite-vec": "unavailable"}
    assert default["catalog"][-1]["name"] == "vec_working"
    assert digest not in json.dumps(result)
    assert "private blob bytes" not in json.dumps(result)


def test_capability_cannot_be_both_required_and_optional(tmp_path):
    payload = b"opaque sqlite bytes"
    sqlite_store = store("default", "stores/default.sqlite", payload)
    sqlite_store["sqlite"]["optional_capabilities"] = ["sqlite"]
    artifact = tmp_path / "overlapping-capabilities.mnbak"
    package(
        artifact,
        manifest([sqlite_store]),
        {sqlite_store["archive_path"]: payload},
    )

    result = inspect_backup_artifact(artifact)

    assert result["status"] == "invalid"
    assert result["diagnostics"] == [
        {"code": "invalid_manifest", "phase": "verify"}
    ]


def test_implicit_required_sqlite_cannot_also_be_optional(tmp_path):
    payload = b"opaque sqlite bytes"
    sqlite_store = store("default", "stores/default.sqlite", payload)
    sqlite_store["sqlite"].pop("required_capabilities")
    sqlite_store["sqlite"]["optional_capabilities"] = ["sqlite"]
    artifact = tmp_path / "implicit-overlapping-capabilities.mnbak"
    package(
        artifact,
        manifest([sqlite_store]),
        {sqlite_store["archive_path"]: payload},
    )

    result = inspect_backup_artifact(artifact)

    assert result["status"] == "invalid"
    assert result["diagnostics"] == [
        {"code": "invalid_manifest", "phase": "verify"}
    ]
