"""Regression coverage for accepted issue #821 review blockers."""

from __future__ import annotations

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
