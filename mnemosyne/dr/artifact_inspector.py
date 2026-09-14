"""Bounded, read-only inspection of Mnemosyne backup artifacts.

This module deliberately does not share code with backup or restore execution.  It
opens artifacts read-only, never creates a SQLite connection, and never extracts
archive members to disk.
"""

from __future__ import annotations

import codecs
import gzip
import hashlib
import json
import math
import os
import re
import stat
import struct
import uuid
import zipfile
import zlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO

_FORMAT = "org.mnemosyne.backup"
_SUPPORTED_FORMAT_VERSION = 2
_SUPPORTED_MANIFEST_VERSION = 1
_CHUNK_SIZE = 1024 * 1024
_STORE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REASON = re.compile(r"^[a-z0-9_]+$")
_SOURCE_REVISION = re.compile(r"^[0-9a-f]{7,64}$")
_SCHEME = re.compile(r"^[a-z0-9+.-]+$")
_STORE_MEMBER = re.compile(r"^stores/([a-z0-9][a-z0-9._-]{0,63})\.sqlite$")
_BLOB_MEMBER = re.compile(r"^blobs/sha256/([0-9a-f]{2})/([0-9a-f]{4})/([0-9a-f]{64})$")
_UTC_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$"
)

_DIAGNOSTIC_CODES = {
    "invalid_argument", "unsupported_format", "invalid_manifest", "unsafe_archive_path",
    "duplicate_archive_member", "limit_exceeded", "source_not_found", "source_busy",
    "maintenance_required", "discovery_incomplete", "unknown_store", "snapshot_failed",
    "missing_entry", "size_mismatch", "checksum_mismatch", "sqlite_integrity_failed",
    "foreign_key_failed", "schema_mismatch", "blob_missing", "capability_unavailable",
    "product_smoke_failed", "destination_exists", "staging_failed", "publish_failed",
    "rollback_failed", "legacy_v1_metadata_missing", "legacy_v1_checksum_mismatch",
    "legacy_v1_completeness_unknown", "legacy_v1_restore_unverifiable",
}
_PHASES = {"discover", "snapshot", "package", "verify", "extract", "stage", "restore", "publish"}
_CLASSIFICATIONS = {
    "authoritative", "derived/rebuildable", "external/blob",
    "unknown/owner decision required",
}
_HANDLING = {"snapshot", "rebuild", "reference-only", "exclude"}
_CAPABILITIES = {"sqlite", "fts5", "sqlite-vec"}


@dataclass(frozen=True)
class InspectionLimits:
    """Reader limits, capped by the v2 contract's hard maxima."""

    manifest_bytes: int = 1024 * 1024
    archive_members: int = 100_000
    sqlite_stores: int = 128
    catalog_objects_per_store: int = 4_096
    single_member_bytes: int = 16 * 1024**3
    total_uncompressed_bytes: int = 64 * 1024**3
    compression_ratio: float = 200.0
    diagnostics: int = 1_000
    external_reference_buckets: int = 64

    def __post_init__(self) -> None:
        bounds = {
            "manifest_bytes": (self.manifest_bytes, 1, 16 * 1024**2),
            "archive_members": (self.archive_members, 1, 1_000_000),
            "sqlite_stores": (self.sqlite_stores, 0, 1_024),
            "catalog_objects_per_store": (self.catalog_objects_per_store, 1, 65_536),
            "single_member_bytes": (self.single_member_bytes, 1, 64 * 1024**3),
            "total_uncompressed_bytes": (self.total_uncompressed_bytes, 1, 1024**4),
            "compression_ratio": (self.compression_ratio, 0, 1_000),
            "diagnostics": (self.diagnostics, 1, 10_000),
            "external_reference_buckets": (self.external_reference_buckets, 1, 256),
        }
        for name, (value, minimum, maximum) in bounds.items():
            expected_type = (int, float) if name == "compression_ratio" else (int,)
            if isinstance(value, bool) or not isinstance(value, expected_type):
                raise ValueError(f"{name} must be numeric")
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError(f"{name} must be finite")
            below_minimum = value <= minimum if name == "compression_ratio" else value < minimum
            if below_minimum:
                raise ValueError(f"{name} is below the supported minimum")
            if value > maximum:
                raise ValueError(f"{name} exceeds the format hard maximum")


class _InspectionFailure(Exception):
    def __init__(self, code: str, *, status: str = "invalid") -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def _failure_result(code: str, *, artifact_format: str = "unknown", status: str = "invalid") -> dict[str, Any]:
    return {
        "status": status,
        "artifact_format": artifact_format,
        "diagnostics": [{"code": code, "phase": "verify"}],
    }


def _open_regular_readonly(path: Path) -> BinaryIO:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as error:
        raise _InspectionFailure("source_not_found") from error
    except OSError as error:
        raise _InspectionFailure("invalid_argument") from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise _InspectionFailure("invalid_argument")
        return os.fdopen(descriptor, "rb")
    except Exception:
        os.close(descriptor)
        raise


def _json_no_duplicates(raw: bytes) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-JSON constant: {value}")

    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=pairs,
        parse_constant=reject_constant,
    )


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _object(value: Any, required: set[str], allowed: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or not required <= value.keys() or not value.keys() <= allowed:
        raise _InspectionFailure("invalid_manifest")
    return value


def _string(value: Any, minimum: int = 1, maximum: int | None = None, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or len(value) < minimum or (maximum is not None and len(value) > maximum):
        raise _InspectionFailure("invalid_manifest")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise _InspectionFailure("invalid_manifest")
    return value


def _integer(value: Any, minimum: int = 0, maximum: int | None = None) -> int:
    if not _is_int(value) or value < minimum or (maximum is not None and value > maximum):
        raise _InspectionFailure("invalid_manifest")
    return value


def _enum(value: Any, choices: set[str]) -> str:
    if not isinstance(value, str) or value not in choices:
        raise _InspectionFailure("invalid_manifest")
    return value


def _list(value: Any, maximum: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        raise _InspectionFailure("invalid_manifest")
    return value


def _unique_strings(value: Any, maximum: int, pattern: re.Pattern[str], *, item_maximum: int = 64) -> list[str]:
    values = _list(value, maximum)
    checked = [_string(item, maximum=item_maximum, pattern=pattern) for item in values]
    if len(set(checked)) != len(checked):
        raise _InspectionFailure("invalid_manifest")
    return checked


def _validate_archive_path(value: Any) -> str:
    name = _string(value, maximum=240)
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError as error:
        raise _InspectionFailure("invalid_manifest") from error
    parts = name.split("/")
    if (
        len(encoded) > 240 or len(parts) > 8 or name.startswith("/") or "\\" in name
        or "\x00" in name or any(part in {"", ".."} for part in parts)
    ):
        raise _InspectionFailure("invalid_manifest")
    return name


def _validate_state(value: Any) -> None:
    item = _object(value, {"state", "reason_codes"}, {"state", "reason_codes"})
    _enum(item["state"], {"complete", "partial", "unknown"})
    _unique_strings(item["reason_codes"], 1_000, _REASON)


def _validate_diagnostic(value: Any) -> None:
    item = _object(value, {"code", "phase"}, {"code", "phase", "store_id", "message"})
    _enum(item["code"], _DIAGNOSTIC_CODES)
    _enum(item["phase"], _PHASES)
    if "store_id" in item:
        _string(item["store_id"], maximum=64, pattern=_STORE_ID)
    if "message" in item:
        _string(item["message"], minimum=0, maximum=512)


def _validate_verification(value: Any) -> None:
    item = _object(value, {"status", "checks"}, {"status", "checks"})
    _enum(item["status"], {"verified", "verified_degraded", "unverifiable", "failed"})
    for check in _list(item["checks"], 1_000):
        checked = _object(check, {"name", "status"}, {"name", "status", "code"})
        _string(checked["name"], maximum=64, pattern=_REASON)
        _enum(checked["status"], {"pass", "degraded", "unverifiable", "fail"})
        if "code" in checked:
            _string(checked["code"], maximum=64, pattern=_REASON)


def _validate_catalog(value: Any, limit: InspectionLimits) -> None:
    for catalog in _list(value, min(65_536, limit.catalog_objects_per_store)):
        item = _object(
            catalog,
            {"name", "object_type", "classification", "handling"},
            {"name", "object_type", "classification", "handling", "row_count", "dependencies"},
        )
        _string(item["name"], maximum=255)
        _enum(item["object_type"], {"table", "virtual-table", "view", "index", "trigger", "unknown"})
        _enum(item["classification"], _CLASSIFICATIONS)
        _enum(item["handling"], _HANDLING)
        if "row_count" in item and item["row_count"] is not None:
            _integer(item["row_count"])
        if "dependencies" in item:
            dependencies = _list(item["dependencies"], 1_024)
            checked = [_string(dep, maximum=255) for dep in dependencies]
            if len(set(checked)) != len(checked):
                raise _InspectionFailure("invalid_manifest")


def _validate_sqlite(value: Any) -> None:
    item = _object(
        value,
        {"page_size", "page_count", "user_version", "schema_sha256"},
        {
            "page_size",
            "page_count",
            "user_version",
            "application_id",
            "schema_sha256",
            "required_capabilities",
            "optional_capabilities",
        },
    )
    _integer(item["page_size"], 512, 65_536)
    _integer(item["page_count"])
    _integer(item["user_version"])
    if "application_id" in item:
        _integer(item["application_id"])
    _string(item["schema_sha256"], 64, 64, _SHA256)
    capability_sets = []
    for field, default in (
        ("required_capabilities", ["sqlite"]),
        ("optional_capabilities", []),
    ):
        values = _list(item.get(field, default), 64)
        if any(not isinstance(value, str) or value not in _CAPABILITIES for value in values):
            raise _InspectionFailure("invalid_manifest")
        if len(set(values)) != len(values):
            raise _InspectionFailure("invalid_manifest")
        capability_sets.append(set(values))
    if capability_sets[0] & capability_sets[1]:
        raise _InspectionFailure("invalid_manifest")


def _validate_store(value: Any, limit: InspectionLimits) -> None:
    required = {
        "store_id", "kind", "classification", "required", "location_hint", "archive_path",
        "media_type", "bytes", "sha256", "dependencies", "handling", "privacy", "verification",
    }
    item = _object(value, required, required | {"sqlite", "catalog"})
    _string(item["store_id"], maximum=64, pattern=_STORE_ID)
    kind = _enum(item["kind"], {"sqlite", "blob-index", "blob", "json", "text", "other"})
    _enum(item["classification"], _CLASSIFICATIONS)
    if not isinstance(item["required"], bool):
        raise _InspectionFailure("invalid_manifest")
    location_hint = _string(item["location_hint"], maximum=128)
    if (
        location_hint.startswith(("/", "\\"))
        or "\\" in location_hint
        or "\x00" in location_hint
        or re.match(r"^[A-Za-z]:", location_hint)
    ):
        raise _InspectionFailure("invalid_manifest")
    _validate_archive_path(item["archive_path"])
    _string(item["media_type"], maximum=128)
    _integer(item["bytes"], 0, 1024**4)
    _string(item["sha256"], 64, 64, _SHA256)
    _unique_strings(item["dependencies"], 1_024, _STORE_ID)
    _enum(item["handling"], _HANDLING)
    _enum(item["privacy"], {"high", "moderate", "low"})
    _validate_verification(item["verification"])
    if kind == "sqlite":
        if "sqlite" not in item or "catalog" not in item:
            raise _InspectionFailure("invalid_manifest")
        _validate_sqlite(item["sqlite"])
        _validate_catalog(item["catalog"], limit)
    else:
        if "sqlite" in item:
            _validate_sqlite(item["sqlite"])
        if "catalog" in item:
            _validate_catalog(item["catalog"], limit)


def _validate_dependency_graph(stores: list[dict[str, Any]]) -> None:
    """Require a bounded, closed, acyclic graph of declared stores."""

    by_store_id = {store["store_id"]: store for store in stores}
    if len(by_store_id) != len(stores):
        raise _InspectionFailure("invalid_manifest")

    for store_id, store in by_store_id.items():
        dependencies = store["dependencies"]
        if store_id in dependencies or any(
            dependency not in by_store_id for dependency in dependencies
        ):
            raise _InspectionFailure("invalid_manifest")

    # Store and per-store dependency counts were bounded by _validate_manifest
    # and _validate_store. Iterative traversal avoids recursion-depth failures.
    states: dict[str, int] = {}
    for root in by_store_id:
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
                raise _InspectionFailure("invalid_manifest")
            if dependency_state == 0:
                stack.append((dependency, 0))


def _validate_limits(value: Any) -> None:
    fields = {
        "manifest_bytes", "archive_members", "sqlite_stores", "catalog_objects_per_store",
        "single_member_bytes", "total_uncompressed_bytes", "compression_ratio", "path_bytes",
        "path_depth", "diagnostics", "external_reference_buckets",
    }
    item = _object(value, fields, fields)
    _integer(item["manifest_bytes"], 1, 16 * 1024**2)
    _integer(item["archive_members"], 1, 1_000_000)
    _integer(item["sqlite_stores"], 0, 1_024)
    _integer(item["catalog_objects_per_store"], 1, 65_536)
    _integer(item["single_member_bytes"], 1, 64 * 1024**3)
    _integer(item["total_uncompressed_bytes"], 1, 1024**4)
    ratio = item["compression_ratio"]
    if (
        isinstance(ratio, bool)
        or not isinstance(ratio, (int, float))
        or not math.isfinite(ratio)
        or ratio <= 0
        or ratio > 1_000
    ):
        raise _InspectionFailure("invalid_manifest")
    if item["path_bytes"] != 240 or item["path_depth"] != 8:
        raise _InspectionFailure("invalid_manifest")
    _integer(item["diagnostics"], 1, 10_000)
    _integer(item["external_reference_buckets"], 1, 256)


def _validate_manifest(manifest: Any, limit: InspectionLimits) -> dict[str, Any]:
    required = {
        "format", "format_version", "manifest_version", "backup_id", "created_at", "producer",
        "status", "discovery", "coverage", "consistency", "self_contained", "scope", "stores",
        "external_references", "warnings", "errors", "limits",
    }
    manifest = _object(manifest, required, required | {"lineage"})
    if manifest["format"] != _FORMAT or manifest["format_version"] != 2 or manifest["manifest_version"] != 1:
        raise _InspectionFailure("invalid_manifest")
    backup_id = _string(manifest["backup_id"], maximum=36)
    try:
        if str(uuid.UUID(backup_id)) != backup_id.lower():
            raise ValueError
    except ValueError as error:
        raise _InspectionFailure("invalid_manifest") from error
    created_at = _string(manifest["created_at"], maximum=64, pattern=_UTC_TIMESTAMP)
    try:
        if not created_at.endswith("Z"):
            raise ValueError
        datetime.fromisoformat(created_at[:-1] + "+00:00")
    except ValueError as error:
        raise _InspectionFailure("invalid_manifest") from error
    producer = _object(manifest["producer"], {"product", "version"}, {"product", "version", "source_revision"})
    if producer["product"] != "mnemosyne":
        raise _InspectionFailure("invalid_manifest")
    _string(producer["version"], maximum=128)
    if "source_revision" in producer:
        _string(producer["source_revision"], 7, 64, _SOURCE_REVISION)
    _enum(manifest["status"], {"complete", "partial", "failed"})
    _validate_state(manifest["discovery"])
    _validate_state(manifest["coverage"])
    _enum(manifest["consistency"], {"transactional", "quiesced", "fuzzy"})
    if manifest["self_contained"] is not None and not isinstance(manifest["self_contained"], bool):
        raise _InspectionFailure("invalid_manifest")

    scope = _object(manifest["scope"], {"requested", "discovered", "included", "excluded"}, {"requested", "discovered", "included", "excluded"})
    for key in ("requested", "discovered", "included"):
        _unique_strings(scope[key], 1_024, _STORE_ID)
    for excluded in _list(scope["excluded"], 1_024):
        item = _object(excluded, {"store_id", "reason_code"}, {"store_id", "reason_code"})
        _string(item["store_id"], maximum=64, pattern=_STORE_ID)
        _string(item["reason_code"], maximum=64, pattern=_REASON)

    stores = _list(manifest["stores"], 1_024)
    if len(stores) > limit.sqlite_stores + sum(1 for store in stores if isinstance(store, dict) and store.get("kind") != "sqlite"):
        raise _InspectionFailure("limit_exceeded")
    for store in stores:
        _validate_store(store, limit)
    names = [store["store_id"] for store in stores]
    paths = [store["archive_path"] for store in stores]
    if len(set(names)) != len(names) or len(set(paths)) != len(paths):
        raise _InspectionFailure("invalid_manifest")
    _validate_dependency_graph(stores)

    for store in stores:
        path = store["archive_path"]
        store_match = _STORE_MEMBER.fullmatch(path)
        blob_match = _BLOB_MEMBER.fullmatch(path)
        if store["kind"] == "sqlite" and (
            store_match is None or store_match.group(1) != store["store_id"]
        ):
            raise _InspectionFailure("invalid_manifest")
        if store["kind"] == "blob" and (
            blob_match is None or blob_match.group(3) != store["sha256"]
        ):
            raise _InspectionFailure("invalid_manifest")
        if store["kind"] == "blob-index" and path != "blobs/index.ndjson":
            raise _InspectionFailure("invalid_manifest")
        if store["kind"] not in {"sqlite", "blob", "blob-index"}:
            raise _InspectionFailure("unsupported_format", status="unsupported")
    if set(scope["included"]) != set(names):
        raise _InspectionFailure("invalid_manifest")

    references = _list(manifest["external_references"], min(256, limit.external_reference_buckets))
    for reference in references:
        item = _object(reference, {"scheme", "count", "owned"}, {"scheme", "count", "owned"})
        _string(item["scheme"], maximum=32, pattern=_SCHEME)
        _integer(item["count"])
        if not isinstance(item["owned"], bool):
            raise _InspectionFailure("invalid_manifest")

    diagnostics = _list(manifest["warnings"], min(10_000, limit.diagnostics)) + _list(manifest["errors"], min(10_000, limit.diagnostics))
    if len(diagnostics) > limit.diagnostics:
        raise _InspectionFailure("limit_exceeded")
    for diagnostic in diagnostics:
        _validate_diagnostic(diagnostic)
    for store in stores:
        check_states = {check["status"] for check in store["verification"]["checks"]}
        verification_status = store["verification"]["status"]
        if (
            (verification_status == "verified" and check_states - {"pass"})
            or (verification_status == "verified_degraded" and (
                "degraded" not in check_states or check_states & {"fail", "unverifiable"}
            ))
            or (verification_status == "unverifiable" and (
                "unverifiable" not in check_states or "fail" in check_states
            ))
            or (verification_status == "failed" and "fail" not in check_states)
        ):
            raise _InspectionFailure("invalid_manifest")
    verification_states = {store["verification"]["status"] for store in stores}
    if manifest["status"] == "complete" and (
        manifest["discovery"]["state"] != "complete"
        or manifest["coverage"]["state"] != "complete"
        or manifest["errors"]
        or verification_states & {"failed", "unverifiable"}
    ):
        raise _InspectionFailure("invalid_manifest")
    if "failed" in verification_states and manifest["status"] != "failed":
        raise _InspectionFailure("invalid_manifest")
    if "unverifiable" in verification_states and manifest["coverage"]["state"] == "complete":
        raise _InspectionFailure("invalid_manifest")
    if manifest["self_contained"] is True and any(
        diagnostic["code"] == "blob_missing" for diagnostic in diagnostics
    ):
        raise _InspectionFailure("invalid_manifest")
    _validate_limits(manifest["limits"])
    if "lineage" in manifest:
        lineage = _object(manifest["lineage"], {"source_format", "source_sha256"}, {"source_format", "source_sha256"})
        _enum(lineage["source_format"], {"legacy-v1", "backup-v2"})
        _string(lineage["source_sha256"], 64, 64, _SHA256)
    return manifest


def _safe_zip_member(info: zipfile.ZipInfo) -> None:
    name = info.filename
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError as error:
        raise _InspectionFailure("unsafe_archive_path") from error
    parts = name.split("/")
    if (
        not name or name.startswith("/") or "\\" in name or "\x00" in name
        or len(encoded) > 240 or len(parts) > 8 or any(part in {"", ".."} for part in parts)
    ):
        raise _InspectionFailure("unsafe_archive_path")
    mode = (info.external_attr >> 16) & 0xFFFF
    kind = stat.S_IFMT(mode)
    if info.is_dir() or (kind and kind != stat.S_IFREG):
        raise _InspectionFailure("unsafe_archive_path")
    if info.flag_bits & 0x1:
        raise _InspectionFailure("unsupported_format", status="unsupported")
    if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
        raise _InspectionFailure("unsupported_format", status="unsupported")
    store_match = _STORE_MEMBER.fullmatch(name)
    blob_match = _BLOB_MEMBER.fullmatch(name)
    if name not in {"manifest.json", "blobs/index.ndjson"} and store_match is None and blob_match is None:
        raise _InspectionFailure("unsafe_archive_path")
    if blob_match and (not blob_match.group(3).startswith(blob_match.group(1)) or not blob_match.group(3).startswith(blob_match.group(2))):
        raise _InspectionFailure("unsafe_archive_path")


def _preflight_zip(handle: BinaryIO, limit: InspectionLimits) -> None:
    """Bound the central directory before ``zipfile`` materializes it."""

    size = os.fstat(handle.fileno()).st_size
    tail_size = min(size, 22 + 65_535)
    handle.seek(size - tail_size)
    tail = handle.read(tail_size)
    search_end = len(tail)
    eocd = None
    eocd_position = 0
    while True:
        index = tail.rfind(b"PK\x05\x06", 0, search_end)
        if index < 0:
            break
        if index + 22 <= len(tail):
            candidate = struct.unpack_from("<4s4H2LH", tail, index)
            comment_size = candidate[-1]
            if index + 22 + comment_size == len(tail):
                eocd = candidate
                eocd_position = size - tail_size + index
                break
        search_end = index
    if eocd is None:
        raise _InspectionFailure("unsupported_format", status="unsupported")

    _, disk, central_disk, disk_entries, entries, central_size, central_offset, _ = eocd
    if disk != 0 or central_disk != 0 or disk_entries != entries:
        raise _InspectionFailure("unsupported_format", status="unsupported")
    central_end = eocd_position
    if entries == 0xFFFF or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
        locator_position = eocd_position - 20
        if locator_position < 0:
            raise _InspectionFailure("unsupported_format", status="unsupported")
        handle.seek(locator_position)
        locator = handle.read(20)
        if len(locator) != 20:
            raise _InspectionFailure("unsupported_format", status="unsupported")
        signature, zip64_disk, zip64_offset, disk_count = struct.unpack("<4sLQL", locator)
        if signature != b"PK\x06\x07" or zip64_disk != 0 or disk_count != 1:
            raise _InspectionFailure("unsupported_format", status="unsupported")
        handle.seek(zip64_offset)
        record = handle.read(56)
        if len(record) != 56:
            raise _InspectionFailure("unsupported_format", status="unsupported")
        fields = struct.unpack("<4sQ2H2L4Q", record)
        if fields[0] != b"PK\x06\x06" or fields[1] < 44:
            raise _InspectionFailure("unsupported_format", status="unsupported")
        _, _, _, _, disk, central_disk, disk_entries, entries, central_size, central_offset = fields
        if disk != 0 or central_disk != 0 or disk_entries != entries:
            raise _InspectionFailure("unsupported_format", status="unsupported")
        central_end = zip64_offset

    if entries > limit.archive_members:
        raise _InspectionFailure("limit_exceeded")
    maximum_central_size = 65_536 + entries * 512
    if central_size > maximum_central_size:
        raise _InspectionFailure("limit_exceeded")
    if central_offset + central_size != central_end:
        raise _InspectionFailure("unsupported_format", status="unsupported")
    handle.seek(0)


def _bounded_zip_metadata(infos: list[zipfile.ZipInfo], limit: InspectionLimits) -> None:
    if len(infos) > limit.archive_members:
        raise _InspectionFailure("limit_exceeded")
    total = 0
    seen: set[str] = set()
    for info in infos:
        if info.filename in seen:
            raise _InspectionFailure("duplicate_archive_member")
        seen.add(info.filename)
        _safe_zip_member(info)
        if info.file_size > limit.single_member_bytes:
            raise _InspectionFailure("limit_exceeded")
        total += info.file_size
        if total > limit.total_uncompressed_bytes:
            raise _InspectionFailure("limit_exceeded")
        if info.file_size:
            if info.compress_size == 0 or info.file_size / info.compress_size > limit.compression_ratio:
                raise _InspectionFailure("limit_exceeded")


def _enforce_declared_limits(
    manifest: dict[str, Any], infos: list[zipfile.ZipInfo]
) -> None:
    declared = manifest["limits"]
    if len(infos) > declared["archive_members"]:
        raise _InspectionFailure("limit_exceeded")
    total = 0
    for info in infos:
        if info.file_size > declared["single_member_bytes"]:
            raise _InspectionFailure("limit_exceeded")
        total += info.file_size
        if total > declared["total_uncompressed_bytes"]:
            raise _InspectionFailure("limit_exceeded")
        if info.file_size and (
            info.compress_size == 0
            or info.file_size / info.compress_size > declared["compression_ratio"]
        ):
            raise _InspectionFailure("limit_exceeded")
    manifest_info = next(info for info in infos if info.filename == "manifest.json")
    if manifest_info.file_size > declared["manifest_bytes"]:
        raise _InspectionFailure("limit_exceeded")
    sqlite_stores = [store for store in manifest["stores"] if store["kind"] == "sqlite"]
    if len(sqlite_stores) > declared["sqlite_stores"]:
        raise _InspectionFailure("limit_exceeded")
    if any(
        len(store.get("catalog", [])) > declared["catalog_objects_per_store"]
        for store in sqlite_stores
    ):
        raise _InspectionFailure("limit_exceeded")
    if len(manifest["warnings"]) + len(manifest["errors"]) > declared["diagnostics"]:
        raise _InspectionFailure("limit_exceeded")
    if len(manifest["external_references"]) > declared["external_reference_buckets"]:
        raise _InspectionFailure("limit_exceeded")


def _read_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, maximum: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    try:
        with archive.open(info, "r") as source:
            while True:
                chunk = source.read(min(_CHUNK_SIZE, maximum - size + 1))
                if not chunk:
                    break
                size += len(chunk)
                if size > maximum:
                    raise _InspectionFailure("limit_exceeded")
                chunks.append(chunk)
    except (zipfile.BadZipFile, zlib.error) as error:
        raise _InspectionFailure("checksum_mismatch") from error
    if size != info.file_size:
        raise _InspectionFailure("size_mismatch")
    return b"".join(chunks)


def _hash_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, expected_size: int) -> str:
    digest = hashlib.sha256()
    size = 0
    try:
        with archive.open(info, "r") as source:
            while True:
                chunk = source.read(_CHUNK_SIZE)
                if not chunk:
                    break
                size += len(chunk)
                if size > expected_size:
                    raise _InspectionFailure("size_mismatch")
                digest.update(chunk)
    except (zipfile.BadZipFile, zlib.error) as error:
        raise _InspectionFailure("checksum_mismatch") from error
    if size != expected_size or size != info.file_size:
        raise _InspectionFailure("size_mismatch")
    return digest.hexdigest()


def _capability_states(store: dict[str, Any]) -> dict[str, str]:
    metadata = store.get("sqlite", {})
    declared = [
        *metadata.get("required_capabilities", []),
        *metadata.get("optional_capabilities", []),
    ]
    checks = store["verification"]["checks"]
    result: dict[str, str] = {}
    for capability in declared:
        check_name = capability.replace("-", "_")
        matches = [check for check in checks if check["name"] == check_name]
        if any(check["status"] in {"degraded", "fail"} and check.get("code") == "capability_unavailable" for check in matches):
            result[capability] = "unavailable"
        elif any(check["status"] == "pass" for check in matches):
            result[capability] = "available"
        else:
            result[capability] = "declared"
    return result


def _safe_v2_result(manifest: dict[str, Any], member_count: int) -> dict[str, Any]:
    stores = []
    blob_count = 0
    for store in manifest["stores"]:
        if store["kind"] == "blob":
            blob_count += 1
        stores.append({
            "store_name": store["store_id"],
            "kind": store["kind"],
            "classification": store["classification"],
            "required": store["required"],
            "handling": store["handling"],
            "verification_status": store["verification"]["status"],
            "capabilities": _capability_states(store),
            "catalog": [
                {
                    "name": item["name"],
                    "object_type": item["object_type"],
                    "classification": item["classification"],
                    "handling": item["handling"],
                }
                for item in store.get("catalog", [])
            ],
        })
    diagnostics = [
        {key: value for key, value in diagnostic.items() if key in {"code", "phase"}}
        for diagnostic in manifest["warnings"] + manifest["errors"]
    ]
    blob_state = "included" if blob_count else "not_present"
    if manifest["self_contained"] is False or any(item["code"] == "blob_missing" for item in manifest["warnings"] + manifest["errors"]):
        blob_state = "partial"
    return {
        "status": "valid",
        "artifact_format": "backup-v2",
        "format_version": manifest["format_version"],
        "manifest_version": manifest["manifest_version"],
        "artifact_status": manifest["status"],
        "member_count": member_count,
        "store_count": len(stores),
        "stores": stores,
        "blob_capability": {"state": blob_state, "member_count": blob_count},
        "diagnostics": diagnostics,
    }


def _inspect_v2(handle: BinaryIO, limit: InspectionLimits) -> dict[str, Any]:
    try:
        _preflight_zip(handle, limit)
        with zipfile.ZipFile(handle, "r", allowZip64=True) as archive:
            infos = archive.infolist()
            _bounded_zip_metadata(infos, limit)
            by_name = {info.filename: info for info in infos}
            manifest_info = by_name.get("manifest.json")
            if manifest_info is None:
                raise _InspectionFailure("missing_entry")
            if manifest_info.compress_type != zipfile.ZIP_STORED:
                raise _InspectionFailure("invalid_manifest")
            if manifest_info.file_size > limit.manifest_bytes:
                raise _InspectionFailure("limit_exceeded")
            try:
                manifest = _json_no_duplicates(_read_member(archive, manifest_info, limit.manifest_bytes))
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
                raise _InspectionFailure("invalid_manifest") from error
            if not isinstance(manifest, dict) or manifest.get("format") != _FORMAT:
                raise _InspectionFailure("unsupported_format", status="unsupported")
            format_version = manifest.get("format_version")
            if not _is_int(format_version) or format_version != _SUPPORTED_FORMAT_VERSION:
                return {
                    "status": "unsupported",
                    "artifact_format": "backup-v2",
                    "format_version": format_version if _is_int(format_version) else None,
                    "diagnostics": [{"code": "unsupported_format", "phase": "verify"}],
                }
            if manifest.get("manifest_version") != _SUPPORTED_MANIFEST_VERSION:
                raise _InspectionFailure("invalid_manifest")
            manifest = _validate_manifest(manifest, limit)
            _enforce_declared_limits(manifest, infos)
            declared = {store["archive_path"]: store for store in manifest["stores"]}
            actual = set(by_name) - {"manifest.json"}
            if set(declared) != actual:
                raise _InspectionFailure("missing_entry")
            for name, store in declared.items():
                info = by_name[name]
                if info.file_size != store["bytes"]:
                    raise _InspectionFailure("size_mismatch")
                if _hash_member(archive, info, store["bytes"]) != store["sha256"]:
                    raise _InspectionFailure("checksum_mismatch")
            return _safe_v2_result(manifest, len(infos))
    except zipfile.BadZipFile as error:
        raise _InspectionFailure("unsupported_format", status="unsupported") from error


def _legacy_sidecar(path: Path, digest: str, limit: InspectionLimits) -> tuple[bool, str, list[dict[str, str]]]:
    sidecar = path.with_suffix(".gz.json")
    try:
        handle = _open_regular_readonly(sidecar)
    except _InspectionFailure as error:
        if error.code == "source_not_found":
            return False, "missing", [{"code": "legacy_v1_metadata_missing", "phase": "verify"}]
        return True, "invalid", [{"code": "invalid_manifest", "phase": "verify"}]
    try:
        with handle:
            if os.fstat(handle.fileno()).st_size > limit.manifest_bytes:
                return True, "invalid", [{"code": "limit_exceeded", "phase": "verify"}]
            try:
                metadata = _json_no_duplicates(handle.read(limit.manifest_bytes + 1))
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                return True, "invalid", [{"code": "invalid_manifest", "phase": "verify"}]
    except OSError:
        return True, "invalid", [{"code": "invalid_manifest", "phase": "verify"}]
    if not isinstance(metadata, dict):
        return True, "invalid", [{"code": "invalid_manifest", "phase": "verify"}]
    if "backup_checksum" not in metadata:
        return True, "not_declared", [{"code": "invalid_manifest", "phase": "verify"}]
    expected = metadata["backup_checksum"]
    if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{16}", expected) is None:
        return True, "invalid", [{"code": "invalid_manifest", "phase": "verify"}]
    if digest.startswith(expected):
        return True, "matched", []
    return True, "mismatch", [{"code": "legacy_v1_checksum_mismatch", "phase": "verify"}]


def _inspect_legacy(handle: BinaryIO, path: Path, limit: InspectionLimits) -> dict[str, Any]:
    compressed_size = os.fstat(handle.fileno()).st_size
    if compressed_size > limit.single_member_bytes:
        raise _InspectionFailure("limit_exceeded")
    digest = hashlib.sha256()
    while True:
        chunk = handle.read(_CHUNK_SIZE)
        if not chunk:
            break
        digest.update(chunk)
    handle.seek(0)
    uncompressed_size = 0
    prefix = bytearray()
    suffix = bytearray()
    utf8_decoder = codecs.getincrementaldecoder("utf-8")()
    try:
        with gzip.GzipFile(fileobj=handle, mode="rb") as source:
            while True:
                chunk = source.read(_CHUNK_SIZE)
                if not chunk:
                    break
                uncompressed_size += len(chunk)
                if (
                    uncompressed_size > limit.single_member_bytes
                    or uncompressed_size > limit.total_uncompressed_bytes
                    or uncompressed_size > compressed_size * limit.compression_ratio
                ):
                    raise _InspectionFailure("limit_exceeded")
                utf8_decoder.decode(chunk, final=False)
                if len(prefix) < 4096:
                    prefix.extend(chunk[: 4096 - len(prefix)])
                suffix.extend(chunk)
                if len(suffix) > 4096:
                    del suffix[:-4096]
            utf8_decoder.decode(b"", final=True)
    except (gzip.BadGzipFile, EOFError, OSError, UnicodeDecodeError, zlib.error) as error:
        raise _InspectionFailure("checksum_mismatch") from error

    if not bytes(prefix).lstrip().startswith(b"BEGIN TRANSACTION;") or not bytes(suffix).rstrip().endswith(b"COMMIT;"):
        raise _InspectionFailure("unsupported_format", status="unsupported")
    sidecar_present, checksum_status, diagnostics = _legacy_sidecar(path, digest.hexdigest(), limit)
    status = (
        "valid_with_warnings"
        if not sidecar_present or checksum_status == "matched"
        else "invalid"
    )
    diagnostics.extend([
        {"code": "legacy_v1_completeness_unknown", "phase": "verify"},
        {"code": "legacy_v1_restore_unverifiable", "phase": "verify"},
    ])
    return {
        "status": status,
        "artifact_format": "legacy-v1",
        "format_version": 1,
        "compressed_bytes": compressed_size,
        "uncompressed_bytes": uncompressed_size,
        "sidecar_present": sidecar_present,
        "checksum_prefix_status": checksum_status,
        "capabilities": {
            "store_coverage": "unknown",
            "blob_coverage": "unknown",
            "multi_store_consistency": "unknown",
            "sqlite_replay": "not_executed",
            "sqlite_vec": "unverifiable",
            "restore": "unverifiable",
        },
        "diagnostics": diagnostics,
    }


def inspect_backup_artifact(path: str | os.PathLike[str], *, limits: InspectionLimits | None = None) -> dict[str, Any]:
    """Inspect a v2 ``.mnbak`` or legacy v1 gzip artifact without executing it.

    The returned mapping intentionally excludes paths, backup/row IDs, hashes,
    content, embeddings, and diagnostic messages.
    """

    limit = limits or InspectionLimits()
    artifact = Path(path)
    try:
        handle = _open_regular_readonly(artifact)
        with handle:
            magic = handle.read(4)
            handle.seek(0)
            if magic.startswith(b"PK\x03\x04") or magic.startswith(b"PK\x05\x06"):
                return _inspect_v2(handle, limit)
            if magic[:2] == b"\x1f\x8b":
                return _inspect_legacy(handle, artifact, limit)
            return _failure_result("unsupported_format", status="unsupported")
    except _InspectionFailure as error:
        artifact_format = "legacy-v1" if artifact.suffix == ".gz" else "backup-v2" if artifact.suffix == ".mnbak" else "unknown"
        return _failure_result(error.code, artifact_format=artifact_format, status=error.status)
    except (OSError, RuntimeError, zipfile.LargeZipFile, zlib.error):
        return _failure_result("unsupported_format", status="unsupported")
