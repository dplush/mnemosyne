"""Regression coverage for accepted issue #821 review blockers."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HERMES_SRC = ROOT / "integrations" / "hermes" / "src"


def _run(script: str, env: dict[str, str]) -> dict:
    process_env = os.environ.copy()
    process_env.update(env)
    process_env["PYTHONPATH"] = os.pathsep.join((str(ROOT), str(HERMES_SRC)))
    result = subprocess.run(
        [sys.executable, "-c", script],
        env=process_env,
        text=True,
        capture_output=True,
        check=True,
    )
    assert env.get("SECRET", "not-present") not in result.stderr
    return json.loads(result.stdout)


def test_file_import_restore_exemption_and_null_accounting(tmp_path: Path):
    from mnemosyne.core.filters import WritePolicySnapshot, write_policy_operation
    from mnemosyne.core.importers.base import import_from_file
    from mnemosyne.core.memory import Mnemosyne

    source = tmp_path / "restore.json"
    source.write_text(json.dumps([{"content": "ISSUE821 restored row"}]))
    memory = Mnemosyne(session_id="restore", db_path=tmp_path / "restore.db")
    strict = WritePolicySnapshot((r"^ISSUE821",), "strict")
    try:
        with write_policy_operation(strict):
            result = import_from_file(str(source), memory)
        assert result.imported == 1 and result.skipped == 0
        assert len(result.memory_ids) == 1 and result.memory_ids[0]
        assert memory.beam.get(result.memory_ids[0])["content"] == "ISSUE821 restored row"
    finally:
        memory.conn.close()

    class RejectingMemory:
        def remember(self, **_kwargs):
            return None

    rejected = import_from_file(str(source), RejectingMemory())
    assert (rejected.imported, rejected.skipped, rejected.memory_ids) == (0, 1, [])


def test_update_boundary_provider_batch_and_importance_only(tmp_path: Path):
    import hermes_memory_provider
    from mnemosyne.core.beam import BeamMemory
    from mnemosyne.core.filters import WritePolicySnapshot, write_policy_operation

    beam = BeamMemory(session_id="updates", db_path=tmp_path / "updates.db")
    provider = hermes_memory_provider.MnemosyneMemoryProvider.__new__(
        hermes_memory_provider.MnemosyneMemoryProvider
    )
    provider._beam = beam
    provider._default_scope = "session"
    provider._audit_event = lambda *_args, **_kwargs: None
    strict = WritePolicySnapshot((r"^ISSUE821",), "strict")
    try:
        memory_id = beam.remember("allowed original")
        with write_policy_operation(strict):
            direct = json.loads(provider._handle_update({
                "memory_id": memory_id, "content": "ISSUE821 provider secret"
            }))
            batch = json.loads(provider._handle_batch({"operations": [{
                "action": "update", "memory_id": memory_id,
                "content": "ISSUE821 batch secret",
            }]}))
            assert beam.update_working(memory_id, importance=0.91) is True
        assert direct == {"status": "filtered", "memory_id": memory_id}
        assert batch["results"] == [
            {"index": 0, "action": "update", "status": "filtered"}
        ]
        assert "ISSUE821" not in json.dumps((direct, batch))
        row = beam.get(memory_id)
        assert row["content"] == "allowed original"
        assert row["importance"] == pytest.approx(0.91)
    finally:
        beam.conn.close()


def test_facade_update_rejects_before_both_sql_stores(tmp_path: Path, monkeypatch):
    from mnemosyne.core import filters
    from mnemosyne.core.filters import WritePolicySnapshot
    from mnemosyne.core.memory import Mnemosyne

    memory = Mnemosyne(session_id="facade-update", db_path=tmp_path / "facade-update.db")
    memory_id = memory.remember("allowed facade original")
    strict = WritePolicySnapshot((r"^ISSUE821",), "strict")
    resolutions = 0

    def resolve_once():
        nonlocal resolutions
        resolutions += 1
        return strict

    monkeypatch.setattr(filters, "resolve_write_policy", resolve_once)
    try:
        assert memory.update(memory_id, content="ISSUE821 facade replacement") is None
        assert resolutions == 1
        assert memory.beam.get(memory_id)["content"] == "allowed facade original"
        legacy = memory.conn.execute(
            "SELECT content FROM memories WHERE id = ?", (memory_id,)
        ).fetchone()
        assert legacy[0] == "allowed facade original"
    finally:
        memory.conn.close()


def test_direct_mcp_rejections_are_content_free(tmp_path: Path, monkeypatch, caplog):
    from mnemosyne import mcp_tools
    from mnemosyne.core.beam import BeamMemory
    from mnemosyne.core.filters import WritePolicySnapshot, write_policy_operation
    from mnemosyne.core.memory import Mnemosyne

    private = Mnemosyne(session_id="mcp_default", db_path=tmp_path / "private.db")
    surface = BeamMemory(session_id="mcp_shared_surface", db_path=tmp_path / "surface.db")
    monkeypatch.setattr(mcp_tools, "_create_instance", lambda **_kwargs: private)
    monkeypatch.setattr(mcp_tools, "_create_surface_instance", lambda: surface)
    secret = "ISSUE821 sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"
    strict = WritePolicySnapshot((r"^ISSUE821",), "strict")
    try:
        with write_policy_operation(strict), caplog.at_level("DEBUG"):
            normal = mcp_tools._handle_remember({"content": secret})
            shared = mcp_tools._handle_shared_remember({"content": secret, "kind": "meta"})
        assert normal == {"status": "filtered", "bank": "default"}
        assert shared == {"status": "filtered_shared", "kind": "meta"}
        assert "memory_id" not in json.dumps((normal, shared))
        assert secret not in caplog.text
        assert private.conn.execute("SELECT COUNT(*) FROM working_memory").fetchone()[0] == 0
        assert surface.conn.execute("SELECT COUNT(*) FROM working_memory").fetchone()[0] == 0
    finally:
        private.conn.close()
        surface.conn.close()


def test_sleep_proposal_is_system_derived_exempt(tmp_path: Path, monkeypatch):
    from mnemosyne.core import model_refresh
    from mnemosyne.core.beam import BeamMemory
    from mnemosyne.core.filters import WritePolicySnapshot, write_policy_operation

    beam = BeamMemory(session_id="derived", db_path=tmp_path / "derived.db")
    old = (datetime.now() - timedelta(hours=200)).isoformat()
    for index in range(2):
        beam.conn.execute(
            "INSERT INTO working_memory (id, content, source, timestamp, session_id) "
            "VALUES (?, ?, 'conversation', ?, 'derived')",
            (f"source-{index}", f"evidence {index}", old),
        )
    beam.conn.commit()
    monkeypatch.setattr(model_refresh, "infer_model_update_proposals", lambda _items: [{
        "category": "model:workflow", "name": "issue821",
        "body": "ISSUE821 derived proposal", "confidence": 0.5,
        "evidence_ids": ["source-0", "source-1"], "action": "update",
        "reason": "derived",
    }])
    try:
        with write_policy_operation(WritePolicySnapshot(("ISSUE821",), "strict")):
            result = beam.sleep(dry_run=False)
        proposals = model_refresh.list_model_refresh_proposals(beam, status="all", limit=10)
        assert result["model_refresh"]["proposals"] == 1
        assert len(proposals) == 1 and proposals[0]["id"]
    finally:
        beam.conn.close()


def test_consolidate_rejects_raw_summary_before_all_mutation(
    tmp_path: Path, monkeypatch, caplog
):
    from mnemosyne.core import beam as beam_module
    from mnemosyne.core import filters
    from mnemosyne.core.beam import BeamMemory
    from mnemosyne.core.filters import WritePolicySnapshot

    marker = "ISSUE821 rejected episodic summary"
    strict = WritePolicySnapshot((r"^ISSUE821",), "strict")
    resolutions = 0
    embedding_calls = 0
    events = []

    def resolve_once():
        nonlocal resolutions
        resolutions += 1
        return strict

    def embedding_available():
        nonlocal embedding_calls
        embedding_calls += 1
        return True

    monkeypatch.setattr(filters, "resolve_write_policy", resolve_once)
    monkeypatch.setattr(beam_module._embeddings, "available", embedding_available)
    beam = BeamMemory(
        session_id="episodic-admission",
        db_path=tmp_path / "episodic-admission.db",
        event_emitter=events.append,
    )
    try:
        with caplog.at_level("DEBUG"):
            result = beam.consolidate_to_episodic(
                marker,
                source_wm_ids=[],
                source="sleep_consolidation",
            )
        assert result is None
        assert resolutions == 1
        assert embedding_calls == 0
        assert events == []
        assert beam.conn.execute("SELECT COUNT(*) FROM episodic_memory").fetchone()[0] == 0
        assert beam.conn.execute("SELECT COUNT(*) FROM memory_embeddings").fetchone()[0] == 0
        assert marker not in caplog.text
    finally:
        beam.conn.close()


def test_sleep_consolidation_is_system_derived_exempt(tmp_path: Path, monkeypatch):
    from mnemosyne.core import beam as beam_module
    from mnemosyne.core import filters
    from mnemosyne.core import local_llm, model_refresh
    from mnemosyne.core.beam import BeamMemory
    from mnemosyne.core.filters import WritePolicySnapshot

    beam = BeamMemory(session_id="derived-summary", db_path=tmp_path / "derived-summary.db")
    old = (datetime.now() - timedelta(hours=200)).isoformat()
    for index in range(2):
        beam.conn.execute(
            "INSERT INTO working_memory (id, content, source, timestamp, session_id) "
            "VALUES (?, ?, 'conversation', ?, 'derived-summary')",
            (f"summary-source-{index}", f"allowed evidence {index}", old),
        )
    beam.conn.commit()
    monkeypatch.setattr(local_llm, "llm_available", lambda: False)
    monkeypatch.setattr(model_refresh, "infer_model_update_proposals", lambda _items: [])
    monkeypatch.setattr(beam_module._embeddings, "available", lambda: False)
    strict = WritePolicySnapshot((r"^\[conversation\]",), "strict")
    resolutions = 0

    def resolve_once():
        nonlocal resolutions
        resolutions += 1
        return strict

    monkeypatch.setattr(filters, "resolve_write_policy", resolve_once)
    try:
        result = beam.sleep(dry_run=False)
        rows = beam.conn.execute(
            "SELECT content FROM episodic_memory ORDER BY rowid"
        ).fetchall()
        assert resolutions == 1
        assert result["items_consolidated"] == 2
        assert result["summaries_created"] == 1
        assert len(rows) == 1
        assert rows[0][0].startswith("[conversation]")
    finally:
        beam.conn.close()


def test_direct_mcp_triple_add_admits_annotation_and_triple_objects(
    tmp_path: Path, monkeypatch, caplog
):
    from mnemosyne import mcp_tools
    from mnemosyne.core.annotations import AnnotationStore
    from mnemosyne.core.filters import WritePolicySnapshot, write_policy_operation
    from mnemosyne.core.memory import Mnemosyne
    from mnemosyne.core.triples import TripleStore

    memory = Mnemosyne(session_id="mcp-triples", db_path=tmp_path / "mcp-triples.db")
    monkeypatch.setattr(mcp_tools, "_create_instance", lambda **_kwargs: memory)
    annotations = AnnotationStore(db_path=memory.beam.db_path, conn=memory.beam.conn)
    triples = TripleStore(db_path=memory.beam.db_path)
    existing_id = triples.add("user", "prefers", "allowed old value")
    marker = "ISSUE821 rejected triple object"
    strict = WritePolicySnapshot((r"^ISSUE821",), "strict")
    try:
        with write_policy_operation(strict), caplog.at_level("DEBUG"):
            annotation = mcp_tools._handle_triple_add({
                "subject": "memory-1", "predicate": "mentions", "object": marker,
            })
            triple = mcp_tools._handle_triple_add({
                "subject": "user", "predicate": "prefers", "object": marker,
            })
            allowed = mcp_tools._handle_triple_add({
                "subject": "memory-1", "predicate": "mentions", "object": "Alice",
            })
        assert annotation == {"status": "filtered", "store": "annotations"}
        assert triple == {"status": "filtered", "store": "triples"}
        assert "ISSUE821" not in json.dumps((annotation, triple))
        assert marker not in caplog.text
        annotation_rows = annotations.query_by_kind("mentions", memory_id="memory-1")
        assert [row["value"] for row in annotation_rows] == ["Alice"]
        rows = triples.conn.execute(
            "SELECT id, object, valid_until FROM triples WHERE subject = ? AND predicate = ?",
            ("user", "prefers"),
        ).fetchall()
        assert [(row[0], row[1], row[2]) for row in rows] == [
            (existing_id, "allowed old value", None)
        ]
        assert allowed["status"] == "added" and allowed["store"] == "annotations"
    finally:
        triples.conn.close()
        memory.conn.close()


@pytest.mark.parametrize("provider_name", ["hermes_memory_provider", "mnemosyne_hermes"])
def test_provider_triple_add_admits_object_before_supersede(
    tmp_path: Path, provider_name: str, caplog
):
    import importlib

    from mnemosyne.core.beam import BeamMemory
    from mnemosyne.core.filters import WritePolicySnapshot
    from mnemosyne.core.triples import TripleStore

    module = importlib.import_module(provider_name)
    provider = module.MnemosyneMemoryProvider.__new__(module.MnemosyneMemoryProvider)
    provider._beam = BeamMemory(
        session_id=f"provider-triples-{provider_name}",
        db_path=tmp_path / f"{provider_name}.db",
    )
    provider._write_policy = WritePolicySnapshot((r"^ISSUE821",), "strict")
    triples = TripleStore(db_path=provider._beam.db_path)
    existing_id = triples.add("user", "prefers", "allowed old value")
    marker = "ISSUE821 rejected provider triple object"
    try:
        with caplog.at_level("DEBUG"):
            rejected = json.loads(provider._handle_triple_add({
                "subject": "user", "predicate": "prefers", "object": marker,
            }))
        assert rejected == {"status": "filtered"}
        assert marker not in caplog.text
        rows = triples.conn.execute(
            "SELECT id, object, valid_until FROM triples WHERE subject = ? AND predicate = ?",
            ("user", "prefers"),
        ).fetchall()
        assert [(row[0], row[1], row[2]) for row in rows] == [
            (existing_id, "allowed old value", None)
        ]
    finally:
        triples.conn.close()
        provider._beam.conn.close()


_SYNC_SCRIPT = r"""
import importlib, json, os, sys, types
from pathlib import Path
h = types.ModuleType("hermes_constants")
h.get_hermes_home = lambda: Path(os.environ["HERMES_HOME"])
sys.modules.setdefault("hermes_constants", h)
m = importlib.import_module(os.environ["PROVIDER"])
p = m.MnemosyneMemoryProvider()
before = {k: os.environ.get(k) for k in ("MNEMOSYNE_IGNORE_PATTERNS", "MNEMOSYNE_WRITE_CLASSIFIER")}
kwargs = dict(hermes_home=os.environ["HERMES_HOME"], sync_roles=["user", "assistant"], auto_sleep=False)
if os.environ.get("INIT_PATTERN"): kwargs["ignore_patterns"] = [os.environ["INIT_PATTERN"]]
p.initialize("issue821", **kwargs)
p.sync_turn(os.environ["SECRET"], "allowed assistant response")
rows = [r[0] for r in p._beam.conn.execute("SELECT content FROM working_memory ORDER BY rowid")]
after = {k: os.environ.get(k) for k in before}
print(json.dumps({"rows": rows, "same_env": before == after, "mode": p._write_policy.classifier_mode,
                  "patterns": p._write_policy.ignore_patterns}))
"""


@pytest.mark.parametrize("provider", ["hermes_memory_provider", "mnemosyne_hermes"])
@pytest.mark.parametrize("case", ["hermes", "initialize", "builtin"])
def test_provider_sync_effective_config_and_raw_admission(
    tmp_path: Path, provider: str, case: str
):
    home = tmp_path / "hermes"
    data = tmp_path / "data"
    home.mkdir(); data.mkdir()
    pattern = "^ISSUE821"
    if case == "hermes":
        config = "memory:\n  mnemosyne:\n    ignore_patterns: ['^ISSUE821']\n    write_classifier: strict\n"
        init_pattern, secret, expected = "", "ISSUE821 raw anchored", [pattern]
    elif case == "initialize":
        config = "memory:\n  mnemosyne: {}\n"
        init_pattern, secret, expected = pattern, "ISSUE821 kwargs anchored", [pattern]
    else:
        config = "memory:\n  mnemosyne:\n    write_classifier: strict\n"
        init_pattern, secret, expected = "", "$ pip install requests --quiet", ["CONFLICT"]
    (home / "config.yaml").write_text(config)
    payload = _run(_SYNC_SCRIPT, {
        "PROVIDER": provider, "HERMES_HOME": str(home), "MNEMOSYNE_DATA_DIR": str(data),
        "MNEMOSYNE_IGNORE_PATTERNS": "CONFLICT", "MNEMOSYNE_WRITE_CLASSIFIER": "off",
        "MNEMOSYNE_NO_EMBEDDINGS": "1", "MNEMOSYNE_HOST_LLM_ENABLED": "0",
        "INIT_PATTERN": init_pattern, "SECRET": secret,
    })
    assert payload == {
        "rows": ["[ASSISTANT] allowed assistant response"], "same_env": True,
        "mode": "strict", "patterns": expected,
    }


_APPROVAL_SCRIPT = r"""
import importlib, json, logging, os, sys, types
from pathlib import Path

h = types.ModuleType("hermes_constants")
h.get_hermes_home = lambda: Path(os.environ["HERMES_HOME"])
sys.modules.setdefault("hermes_constants", h)
hc = types.ModuleType("hermes_cli.config")
hc.load_config = lambda: {"memory": {"write_approval": True}}
hc.cfg_get = lambda cfg, *keys, default=None: (
    cfg.get(keys[0], {}).get(keys[1], default) if len(keys) == 2 else default
)
hp = types.ModuleType("hermes_cli")
hp.__path__ = []
hp.config = hc
sys.modules.setdefault("hermes_cli", hp)
sys.modules.setdefault("hermes_cli.config", hc)

module = importlib.import_module(os.environ["PROVIDER"])
provider = module.MnemosyneMemoryProvider()
provider.initialize(
    "issue821-approval",
    hermes_home=os.environ["HERMES_HOME"],
    ignore_patterns=[r"^ISSUE821"],
    write_classifier="strict",
    auto_sleep=False,
)
allowed_id = provider._beam.remember(
    "allowed original", _write_policy=type(provider._write_policy)((), "off")
)

class Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.messages = []
    def emit(self, record):
        self.messages.append(self.format(record))

capture = Capture()
logging.getLogger().addHandler(capture)
marker = os.environ["SECRET"]
remember = provider.handle_tool_call("mnemosyne_remember", {"content": marker})
batch = provider.handle_tool_call("mnemosyne_batch", {"operations": [
    {"action": "remember", "content": marker + " remember"},
    {"action": "update", "memory_id": allowed_id, "content": marker + " update"},
]})
pending_root = Path(os.environ["HERMES_HOME"]) / "pending"
pending_files = list(pending_root.rglob("*")) if pending_root.exists() else []
pending_text = "\n".join(
    path.read_text(errors="replace") for path in pending_files if path.is_file()
)
non_content = json.loads(provider.handle_tool_call("mnemosyne_batch", {"operations": [
    {"action": "update", "memory_id": allowed_id, "importance": 0.9},
    {"action": "forget", "memory_id": allowed_id},
]}))
non_content_records = []
for result in non_content["results"]:
    record_path = pending_root / "memory" / (result["pending_id"] + ".json")
    non_content_records.append(json.loads(record_path.read_text())["payload"])
    record_path.unlink()
rejected_pending = module._stage_pending_write({
    "tool": "mnemosyne_remember", "content": marker + " apply"
})
allowed_pending = module._stage_pending_write({
    "tool": "mnemosyne_remember", "content": "allowed pending content"
})
apply_response = provider.handle_tool_call(
    "mnemosyne_apply_pending", {"pending_ids": [rejected_pending, allowed_pending]}
)
print(json.dumps({
    "remember": json.loads(remember),
    "batch": json.loads(batch),
    "pending_exists": pending_root.exists(),
    "pending_entries": [str(path.relative_to(pending_root)) for path in pending_files],
    "pending_text": pending_text,
    "non_content": non_content,
    "non_content_records": non_content_records,
    "apply_response": json.loads(apply_response),
    "pending_after_apply": [str(path) for path in pending_root.rglob("*.json")],
    "marker_rows": provider._beam.conn.execute(
        "SELECT COUNT(*) FROM working_memory WHERE content LIKE '%ISSUE821%'"
    ).fetchone()[0],
    "allowed_rows": provider._beam.conn.execute(
        "SELECT COUNT(*) FROM working_memory WHERE content = 'allowed pending content'"
    ).fetchone()[0],
    "logs": capture.messages,
    "original": provider._beam.get(allowed_id)["content"],
}))
"""


@pytest.mark.parametrize("provider", ["hermes_memory_provider", "mnemosyne_hermes"])
def test_write_approval_rejects_before_pending_persistence(
    tmp_path: Path, provider: str
):
    home = tmp_path / "hermes"
    data = tmp_path / "data"
    home.mkdir(); data.mkdir()
    (home / "config.yaml").write_text("memory:\n  write_approval: true\n")
    marker = "ISSUE821 pending persistence marker"
    payload = _run(_APPROVAL_SCRIPT, {
        "PROVIDER": provider,
        "HERMES_HOME": str(home),
        "MNEMOSYNE_DATA_DIR": str(data),
        "MNEMOSYNE_NO_EMBEDDINGS": "1",
        "MNEMOSYNE_HOST_LLM_ENABLED": "0",
        "SECRET": marker,
    })
    assert payload["remember"] == {"status": "filtered"}
    assert payload["batch"]["status"] == "filtered"
    assert payload["batch"]["results"] == [
        {"index": 0, "action": "remember", "status": "filtered"},
        {"index": 1, "action": "update", "status": "filtered"},
    ]
    assert payload["pending_entries"] == []
    assert payload["original"] == "allowed original"
    assert payload["non_content"]["status"] == "staged"
    assert [result["status"] for result in payload["non_content"]["results"]] == [
        "staged", "staged",
    ]
    assert [record["memory_id"] for record in payload["non_content_records"]] == [
        payload["non_content_records"][0]["memory_id"],
        payload["non_content_records"][0]["memory_id"],
    ]
    assert payload["apply_response"]["applied_count"] == 1
    assert payload["apply_response"]["failed_count"] == 1
    assert payload["apply_response"]["failed"][0]["error"] == "filtered"
    assert payload["pending_after_apply"] == []
    assert payload["marker_rows"] == 0
    assert payload["allowed_rows"] == 1
    assert marker not in json.dumps(payload)


def test_facade_data_uri_is_admitted_before_blob_or_sql_mutation(
    tmp_path: Path, monkeypatch
):
    from mnemosyne.core import filters
    from mnemosyne.core.filters import WritePolicySnapshot
    from mnemosyne.core.memory import Mnemosyne

    blob_dir = tmp_path / "blobs"
    monkeypatch.setenv("MNEMOSYNE_BLOB_DIR", str(blob_dir))
    raw = b"issue 821 binary"
    content = "data:image/png;base64," + base64.b64encode(raw).decode("ascii")
    strict = WritePolicySnapshot((r"^data:",), "strict")
    resolutions = 0

    def resolve_once():
        nonlocal resolutions
        resolutions += 1
        return strict

    monkeypatch.setattr(filters, "resolve_write_policy", resolve_once)
    memory = Mnemosyne(session_id="facade-data-uri", db_path=tmp_path / "facade.db")
    try:
        assert memory.remember(content) is None
        assert resolutions == 1
        assert memory.conn.execute("SELECT COUNT(*) FROM working_memory").fetchone()[0] == 0
        assert memory.conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0] == 0
        assert not blob_dir.exists()
    finally:
        memory.conn.close()


def test_remember_media_data_uri_is_admitted_before_blob_or_sql_mutation(
    tmp_path: Path, monkeypatch
):
    from mnemosyne.core import filters
    from mnemosyne.core.beam import BeamMemory
    from mnemosyne.core.filters import WritePolicySnapshot

    blob_dir = tmp_path / "media-blobs"
    monkeypatch.setenv("MNEMOSYNE_BLOB_DIR", str(blob_dir))
    content = "data:image/png;base64," + base64.b64encode(
        b"issue 821 media binary"
    ).decode("ascii")
    strict = WritePolicySnapshot((r"^data:",), "strict")
    resolutions = 0

    def resolve_once():
        nonlocal resolutions
        resolutions += 1
        return strict

    monkeypatch.setattr(filters, "resolve_write_policy", resolve_once)
    beam = BeamMemory(session_id="media-data-uri", db_path=tmp_path / "media.db")
    try:
        result = beam.remember_media(content)
        assert result.status == "filtered"
        assert result.asset_id == ""
        assert resolutions == 1
        assert beam.conn.execute("SELECT COUNT(*) FROM media_assets").fetchone()[0] == 0
        assert beam.conn.execute("SELECT COUNT(*) FROM working_memory").fetchone()[0] == 0
        assert not blob_dir.exists()
    finally:
        beam.conn.close()


def test_remember_media_allowed_data_uri_reuses_operation_snapshot(
    tmp_path: Path, monkeypatch
):
    from mnemosyne.core import filters
    from mnemosyne.core.beam import BeamMemory
    from mnemosyne.core.filters import WritePolicySnapshot

    blob_dir = tmp_path / "allowed-media-blobs"
    monkeypatch.setenv("MNEMOSYNE_BLOB_DIR", str(blob_dir))
    content = "data:image/png;base64," + base64.b64encode(
        b"allowed issue 821 media binary"
    ).decode("ascii")
    allowed = WritePolicySnapshot((), "off")
    resolutions = 0

    def resolve_once():
        nonlocal resolutions
        resolutions += 1
        return allowed

    monkeypatch.setattr(filters, "resolve_write_policy", resolve_once)
    beam = BeamMemory(
        session_id="allowed-media-data-uri", db_path=tmp_path / "allowed-media.db"
    )
    try:
        result = beam.remember_media(content)
        assert result.status == "unavailable"
        assert resolutions == 1
        asset = beam.media.get_asset(result.asset_id)
        assert asset is not None
        assert asset["ref_value"].startswith("blob://sha256/")
        assert "anchor_memory_id" in json.loads(asset["metadata"])
        assert beam.conn.execute("SELECT COUNT(*) FROM media_assets").fetchone()[0] == 1
        assert beam.conn.execute("SELECT COUNT(*) FROM working_memory").fetchone()[0] == 1
        assert any(path.is_file() for path in blob_dir.rglob("*"))
    finally:
        beam.conn.close()


def test_facade_allowed_data_uri_preserves_blob_extraction(
    tmp_path: Path, monkeypatch
):
    from mnemosyne.core.filters import WritePolicySnapshot, write_policy_operation
    from mnemosyne.core.memory import Mnemosyne

    blob_dir = tmp_path / "allowed-blobs"
    monkeypatch.setenv("MNEMOSYNE_BLOB_DIR", str(blob_dir))
    content = "data:image/png;base64," + base64.b64encode(b"allowed binary").decode("ascii")
    memory = Mnemosyne(session_id="facade-data-uri-allowed", db_path=tmp_path / "allowed.db")
    try:
        with write_policy_operation(WritePolicySnapshot((), "off")):
            memory_id = memory.remember(content)
        assert memory_id is not None
        row = memory.beam.get(memory_id)
        assert row is not None
        assert row["content"].startswith("[Binary content extracted")
        metadata = json.loads(row["metadata"]) if isinstance(row["metadata"], str) else row["metadata"]
        assert metadata["_blob"]["blob_ref"].startswith("blob://sha256/")
        assert any(path.is_file() for path in blob_dir.rglob("*"))
    finally:
        memory.conn.close()
