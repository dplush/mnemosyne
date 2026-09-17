"""#936 review: staged pending writes are not bound to their originating session.

dplush's 2026-09-16 review on PR #936:

  "Before merge, bind staged records to their originating Hermes scope and
   restore/validate that scope during replay; otherwise an approval after a
   session switch can write to or mutate the wrong session."

Mechanism: `_stage_pending_write` stores the tool payload but records no session.
`_handle_apply_pending` replays through `self._beam` — the beam of whatever
session is active when the approval arrives. A record staged in session A and
approved while session B is active is therefore written with B's scope.

Harness mirrors tests/test_apply_pending_replay_926.py: a `hermes_constants`
stub points the pending store at tmp_path, and `_import_provider` loads the
provider from its own source root so the repo-root stub cannot shadow the core.
"""
from __future__ import annotations

import importlib
import json
import sqlite3
import sys
import types
from contextlib import contextmanager
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]

STAGED_CONTENT = "belongs to session A"


def _import_provider(package: str):
    for name in list(sys.modules):
        if name == package or name.startswith(f"{package}."):
            del sys.modules[name]
    for name in list(sys.modules):
        if name == "mnemosyne" or name.startswith("mnemosyne."):
            del sys.modules[name]
    sys.path.insert(0, str(PROJECT_ROOT))
    try:
        module = importlib.import_module(package)
        import mnemosyne.core.beam as _beam_mod

        module._BEAM_CLS = _beam_mod.BeamMemory
        return module
    finally:
        try:
            sys.path.remove(str(PROJECT_ROOT))
        except ValueError:
            pass


@contextmanager
def _pending_home(monkeypatch, tmp_path):
    stub = types.ModuleType("hermes_constants")
    stub.get_hermes_home = lambda: tmp_path
    monkeypatch.setitem(sys.modules, "hermes_constants", stub)
    yield tmp_path / "pending" / "memory"


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch, tmp_path):
    data = tmp_path / "mnemosyne-data" / "private"
    data.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("MNEMOSYNE_DATA_DIR", str(data))
    monkeypatch.setenv("MNEMOSYNE_HOST_LLM_ENABLED", "0")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    yield


def _provider(module, home: Path, session_id: str):
    p = module.MnemosyneMemoryProvider()
    p.initialize(session_id=session_id, hermes_home=str(home), agent_identity="main")
    assert p._beam is not None
    return p


def _staged_ids(resp):
    """Pending IDs across provider surfaces.

    Legacy `hermes_memory_provider` returns a single `pending_id`; the batch
    path returns `pending_ids`; the standalone surface returns a `staged` list.
    """
    if isinstance(resp.get("staged"), list):
        return [s["pending_id"] if isinstance(s, dict) else s for s in resp["staged"]]
    if resp.get("pending_ids"):
        return list(resp["pending_ids"])
    if resp.get("pending_id"):
        return [resp["pending_id"]]
    return []


def _force_approval_gate(module, monkeypatch):
    monkeypatch.setattr(module, "_write_approval_enabled", lambda: True, raising=True)


def test_staged_payload_records_the_originating_session(monkeypatch, tmp_path):
    """The staged record must identify the session it was staged from."""
    module = _import_provider("hermes_memory_provider")
    _force_approval_gate(module, monkeypatch)
    with _pending_home(monkeypatch, tmp_path) as pending_dir:
        prov = _provider(module, tmp_path, "sess-a")
        resp = json.loads(prov.handle_tool_call(
            "mnemosyne_remember", {"content": STAGED_CONTENT, "scope": "session"}
        ))
        assert resp.get("status") == "staged", resp
        pid = _staged_ids(resp)[0]
        record = json.loads((pending_dir / f"{pid}.json").read_text())

    print("record keys:", sorted(record.keys()))
    print("payload keys:", sorted(record.get("payload", {}).keys()))

    blob = {**record, **record.get("payload", {})}
    session_ish = {k: v for k, v in blob.items() if "session" in k.lower()}
    assert session_ish, (
        "the staged record must carry the originating session so replay can "
        "restore it"
    )
    assert record.get("session_scope") == "hermes_sess-a", (
        f"unexpected recorded scope: {record.get('session_scope')!r}"
    )


def test_replay_restores_the_staging_session_not_the_active_one(monkeypatch, tmp_path):
    """A record staged in A, approved while B is active, must land in A."""
    module = _import_provider("hermes_memory_provider")
    _force_approval_gate(module, monkeypatch)
    with _pending_home(monkeypatch, tmp_path):
        a = _provider(module, tmp_path, "sess-a")
        resp = json.loads(a.handle_tool_call(
            "mnemosyne_remember",
            {"content": STAGED_CONTENT, "scope": "session", "importance": 0.5},
        ))
        pid = _staged_ids(resp)[0]

        # Session switch before the approval arrives.
        b = _provider(module, tmp_path, "sess-b")
        applied = json.loads(b.handle_tool_call(
            "mnemosyne_apply_pending", {"pending_ids": [pid]}
        ))
    print("apply result:", applied)

    db = tmp_path / "mnemosyne-data" / "private" / "mnemosyne.db"
    conn = sqlite3.connect(str(db))
    try:
        rows = conn.execute(
            "SELECT session_id FROM working_memory WHERE content LIKE ?",
            (f"%{STAGED_CONTENT}%",),
        ).fetchall()
    finally:
        conn.close()
    sessions = {r[0] for r in rows}
    print("row session(s):", sessions)
    assert sessions, "the replayed row should exist"
    assert sessions == {"hermes_sess-a"}, (
        "the record staged from sess-a must be replayed into sess-a, not the "
        f"session active at approval time; got {sessions}"
    )
    # The switch must be reported, not silently absorbed.
    entry = (applied.get("applied") or [{}])[0]
    print("applied entry:", entry)
    assert entry.get("session_replayed_into") == "hermes_sess-a"
    assert entry.get("session_redirected_from") == "hermes_sess-b"
    assert applied.get("session_redirected_count") == 1
