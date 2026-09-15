"""
Tests for after-commit event emission in forget() (issue #963).

Pre-fix, ``Mnemosyne.forget()`` emitted ``MEMORY_INVALIDATED``
immediately after the ``_deferred_commits`` block. When a caller-owned
transaction was still open, the event fired before the caller's commit
— a phantom event if the caller then rolled back.

Post-fix, ``forget()`` emits at once when it owned the transaction and
queues an after-commit hook on the connection otherwise. The hook fires
on the next real commit and is discarded unseen on rollback.
"""
from __future__ import annotations

from pathlib import Path

from mnemosyne.core.memory import Mnemosyne


def _mem_with_events(tmp_path: Path, name: str = "forget_ac.db"):
    """Mnemosyne with a capturing emitter; returns (mem, events)."""
    mem = Mnemosyne(session_id="ac-test", db_path=tmp_path / name)
    events: list = []
    mem._emit_wrapper = lambda *args, **kwargs: events.append((args, kwargs))  # noqa: SLF001
    return mem, events


def test_owned_transaction_emits_immediately(tmp_path: Path):
    """Without a caller transaction, the event fires on return (unchanged)."""
    mem, events = _mem_with_events(tmp_path)
    mid = mem.beam.remember("owned row", source="test")

    assert mem.forget(mid) is True
    assert events == [(("MEMORY_INVALIDATED", mid), {})]


def test_caller_owned_commit_fires_event_after_commit(tmp_path: Path):
    """With a caller transaction open, no event until the caller commits."""
    mem, events = _mem_with_events(tmp_path)
    mid = mem.beam.remember("caller row", source="test")
    mem.conn.execute("BEGIN")

    assert mem.forget(mid) is True
    assert events == []

    mem.conn.commit()
    assert events == [(("MEMORY_INVALIDATED", mid), {})]


def test_caller_owned_rollback_suppresses_event(tmp_path: Path):
    """A caller rollback discards the queued event; the row survives."""
    mem, events = _mem_with_events(tmp_path)
    mid = mem.beam.remember("rollback row", source="test")
    mem.conn.execute("BEGIN")

    assert mem.forget(mid) is True
    mem.conn.rollback()

    assert events == []
    assert mem.conn.execute(
        "SELECT COUNT(*) FROM working_memory WHERE id = ?", (mid,)
    ).fetchone()[0] == 1


def test_rollback_clears_stale_hooks(tmp_path: Path):
    """Hooks queued before a rollback never fire on a later commit."""
    mem, events = _mem_with_events(tmp_path)
    mid = mem.beam.remember("stale row", source="test")
    mem.conn.execute("BEGIN")
    assert mem.forget(mid) is True
    mem.conn.rollback()

    mem.beam.remember("unrelated row", source="test")
    mem.conn.commit()

    assert events == []


def test_failing_hook_does_not_break_commit(tmp_path: Path):
    """A raising hook is skipped; the commit itself still succeeds."""
    mem, _ = _mem_with_events(tmp_path)
    mem.conn.execute("BEGIN")
    mem.conn.execute(
        "INSERT INTO working_memory (id, content) VALUES ('hook-row', 'x')"
    )
    mem.conn._after_commit_hooks.append(lambda: 1 / 0)  # noqa: SLF001

    mem.conn.commit()  # must not raise

    assert mem.conn.execute(
        "SELECT COUNT(*) FROM working_memory WHERE id = 'hook-row'"
    ).fetchone()[0] == 1
