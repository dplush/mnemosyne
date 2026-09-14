"""Fresh-process regressions for issue #821 write admission."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HERMES_SRC = ROOT / "integrations" / "hermes" / "src"


def _run(script: str, *, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update(env)
    environment.pop("PYTHONHOME", None)
    environment["PYTHONPATH"] = os.pathsep.join(
        [str(ROOT), str(HERMES_SRC), environment.get("PYTHONPATH", "")]
    )
    return subprocess.run(
        [sys.executable, "-c", script],
        text=True,
        capture_output=True,
        env=environment,
        check=True,
    )


@pytest.mark.parametrize(
    ("yaml", "env_mode", "env_patterns", "expected"),
    [
        ("write_classifier: off\nignore_patterns: ''\n", "strict", "ISSUE821", True),
        ("write_classifier: warn\nignore_patterns: ISSUE821\n", "strict", "NO_MATCH", True),
        ("write_classifier: strict\nignore_patterns: ISSUE821\n", "off", "NO_MATCH", False),
    ],
)
def test_facade_write_path_honors_yaml_allow_warn_and_strict(
    tmp_path: Path,
    yaml: str,
    env_mode: str,
    env_patterns: str,
    expected: bool,
):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "config.yaml").write_text(yaml)
    result = _run(
        """
import os
from mnemosyne.core.memory import Mnemosyne

memory = Mnemosyne(session_id="issue-821", db_path=os.environ["TEST_DB"])
try:
    memory_id = memory.remember("ISSUE821 private facade sentinel", source="user")
    count = memory.conn.execute(
        "SELECT COUNT(*) FROM working_memory WHERE content = ?",
        ("ISSUE821 private facade sentinel",),
    ).fetchone()[0]
    print(bool(memory_id) and count == 1)
finally:
    memory.conn.close()
""",
        env={
            "MNEMOSYNE_DATA_DIR": str(data_dir),
            "MNEMOSYNE_WRITE_CLASSIFIER": env_mode,
            "MNEMOSYNE_IGNORE_PATTERNS": env_patterns,
            "MNEMOSYNE_NO_EMBEDDINGS": "1",
            "TEST_DB": str(tmp_path / "facade.db"),
        },
    )
    assert result.stdout.strip() == str(expected)


_GATEWAY_SCRIPT = r"""
import importlib
import json
import os
import sys
import types
from pathlib import Path

hermes_constants = types.ModuleType("hermes_constants")
hermes_constants.get_hermes_home = lambda: Path(os.environ["HERMES_HOME"])
sys.modules.setdefault("hermes_constants", hermes_constants)

module = importlib.import_module(os.environ["PROVIDER_MODULE"])
Provider = module.MnemosyneMemoryProvider
provider = Provider()
provider.initialize(
    "issue-821",
    hermes_home=os.environ["HERMES_HOME"],
    shared_surface_path=os.environ["SHARED_DB"],
)
assert provider._beam is not None
marker = "ISSUE821 private gateway sentinel"
response = None
if os.environ["GATEWAY"] == "sync_turn":
    provider.sync_turn(marker, "acknowledged response")
elif os.environ["GATEWAY"] == "tool":
    response = provider.handle_tool_call("mnemosyne_remember", {"content": marker})
elif os.environ["GATEWAY"] == "pending_apply":
    pending_id = module._stage_pending_write({"tool": "mnemosyne_remember", "content": marker})
    response = provider.handle_tool_call("mnemosyne_apply_pending", {"pending_ids": [pending_id]})
elif os.environ["GATEWAY"] == "shared_surface":
    response = provider.handle_tool_call(
        "mnemosyne_shared_remember", {"content": marker, "kind": "meta"}
    )
elif os.environ["GATEWAY"] == "batch":
    response = provider.handle_tool_call(
        "mnemosyne_batch",
        {"operations": [{"action": "remember", "content": marker}]},
    )
else:
    raise AssertionError(os.environ["GATEWAY"])
beam = provider._surface_beam if os.environ["GATEWAY"] == "shared_surface" else provider._beam
count = beam.conn.execute(
    "SELECT COUNT(*) FROM working_memory WHERE content LIKE ?", ("%ISSUE821%",)
).fetchone()[0]
print(json.dumps({"count": count, "response": json.loads(response) if response else None}))
"""


@pytest.mark.parametrize("provider_module", ["hermes_memory_provider", "mnemosyne_hermes"])
@pytest.mark.parametrize(
    "gateway", ["sync_turn", "tool", "pending_apply", "shared_surface", "batch"]
)
def test_every_provider_gateway_honors_yaml_strict_over_conflicting_env(
    tmp_path: Path, gateway: str, provider_module: str
):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "config.yaml").write_text(
        "write_classifier: strict\nignore_patterns: ISSUE821\n"
    )
    hermes_home = tmp_path / "hermes"
    hermes_home.mkdir()
    result = _run(
        _GATEWAY_SCRIPT,
        env={
            "GATEWAY": gateway,
            "PROVIDER_MODULE": provider_module,
            "HERMES_HOME": str(hermes_home),
            "MNEMOSYNE_DATA_DIR": str(data_dir),
            "MNEMOSYNE_WRITE_CLASSIFIER": "off",
            "MNEMOSYNE_IGNORE_PATTERNS": "NO_MATCH",
            "MNEMOSYNE_NO_EMBEDDINGS": "1",
            "MNEMOSYNE_HOST_LLM_ENABLED": "0",
            "SHARED_DB": str(tmp_path / "shared.db"),
        },
    )
    payload = json.loads(result.stdout)
    assert payload["count"] == 0
    assert "ISSUE821" not in result.stderr
    assert "ISSUE821" not in result.stdout


def test_only_restore_and_system_derived_writes_are_exempt():
    from mnemosyne.core.filters import WritePolicySnapshot, admit_memory_write

    strict = WritePolicySnapshot(("ISSUE821",), "strict")
    assert admit_memory_write("ISSUE821", policy=strict)[0] is False
    assert admit_memory_write("ISSUE821", write_kind="batch", policy=strict)[0] is False
    assert admit_memory_write("ISSUE821", write_kind="restore", policy=strict)[0] is True
    assert admit_memory_write(
        "ISSUE821", write_kind="system_derived", policy=strict
    )[0] is True


def test_batch_uses_one_immutable_policy_snapshot(tmp_path: Path, monkeypatch):
    from mnemosyne.batch_tool import apply_beam_batch, validate_batch_operations
    from mnemosyne.core.beam import BeamMemory

    class ChangingConfig:
        calls = 0

        def get_many(self, defaults):
            self.calls += 1
            if self.calls > 1:
                return {"ignore_patterns": "", "write_classifier": "off"}
            return {"ignore_patterns": "ISSUE821", "write_classifier": "strict"}

    config = ChangingConfig()
    monkeypatch.setattr("mnemosyne.core.filters.get_config", lambda: config)
    beam = BeamMemory(session_id="issue-821", db_path=tmp_path / "batch.db")
    try:
        operations = validate_batch_operations(
            [
                {"action": "remember", "content": "ISSUE821 first"},
                {"action": "remember", "content": "ISSUE821 second"},
            ]
        )
        result = apply_beam_batch(beam, operations)
        assert [item["status"] for item in result["results"]] == ["filtered", "filtered"]
        assert config.calls == 1
        assert beam.conn.execute("SELECT COUNT(*) FROM working_memory").fetchone()[0] == 0
    finally:
        beam.conn.close()
