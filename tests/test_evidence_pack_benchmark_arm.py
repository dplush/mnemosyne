"""Deterministic coverage for the BEAM evidence-pack benchmark arm."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))


class _FakeBeam:
    """No-DB recall double: records exactly which public API is used."""

    use_cloud = False
    db_path = None

    def __init__(self, packed=None):
        self.recall_calls = []
        self.evidence_pack_calls = []
        self._packed = packed or {
            "primary": [{"id": "primary-1", "content": "primary evidence", "score": 0.9}],
            "evidence_pack": [],
        }

    def recall(self, query, **kwargs):
        self.recall_calls.append((query, kwargs))
        return [{"id": "primary-1", "content": "primary evidence", "score": 0.9}]

    def recall_with_evidence_pack(self, query, **kwargs):
        self.evidence_pack_calls.append((query, kwargs))
        return self._packed

    def memoria_retrieve(self, *args, **kwargs):
        return {"source": "fallback", "context": "", "facts": []}


@pytest.fixture
def fake_llm():
    llm = MagicMock()
    llm.chat.return_value = "answer"
    return llm


def _answer(harness, fake_llm, beam):
    return harness.answer_with_memory(
        llm=fake_llm,
        beam=beam,
        question="Where is the primary evidence?",
        conversation_messages=[],
        top_k=3,
        ability="ABS",
        return_memories=True,
        return_retrieval_metadata=True,
    )


def test_default_benchmark_arm_uses_normal_recall_only(monkeypatch, fake_llm):
    """The default retains the existing normal-recall path exactly."""
    monkeypatch.setenv("MNEMOSYNE_BENCHMARK_PURE_RECALL", "1")
    monkeypatch.delenv("MNEMOSYNE_BENCHMARK_EVIDENCE_PACK", raising=False)
    import _benchmarks.evaluate_beam_end_to_end as harness

    beam = _FakeBeam()
    answer, memories, retrieval = _answer(harness, fake_llm, beam)

    assert answer == "answer"
    assert beam.recall_calls
    assert beam.evidence_pack_calls == []
    assert memories == [{"id": "primary-1", "content": "primary evidence", "score": pytest.approx(0.54), "fact_density": 0.0}]
    assert retrieval["mode"] == "primary_only"
    assert retrieval["primary"] == memories
    assert retrieval["evidence_pack"] == []


def test_enabled_arm_calls_evidence_pack_and_uses_disjoint_bounded_context(
    monkeypatch, fake_llm
):
    """The opt-in arm renders primary + API-returned supplemental evidence.

    The API double returns a pack already bounded to two supplemental rows and
    disjoint from primary. The harness must preserve that division in its
    diagnostics rather than merging it into the primary ranking metric.
    """
    monkeypatch.setenv("MNEMOSYNE_BENCHMARK_PURE_RECALL", "1")
    monkeypatch.setenv("MNEMOSYNE_BENCHMARK_EVIDENCE_PACK", "on")
    import _benchmarks.evaluate_beam_end_to_end as harness

    packed = {
        "primary": [{"id": "primary-1", "content": "PRIMARY sentinel", "score": 0.9}],
        "evidence_pack": [
            {"id": "supplement-1", "content": "SUPPLEMENT one", "score": 0.4},
            {"id": "supplement-2", "content": "SUPPLEMENT two", "score": 0.3},
        ],
    }
    beam = _FakeBeam(packed)
    multi_strategy = MagicMock(side_effect=AssertionError("evidence arm must not fall back to recall()"))
    monkeypatch.setattr(harness, "_multi_strategy_recall", multi_strategy)

    answer, combined, retrieval = _answer(harness, fake_llm, beam)

    assert answer == "answer"
    assert beam.recall_calls == []
    assert len(beam.evidence_pack_calls) == 1
    _, kwargs = beam.evidence_pack_calls[0]
    assert kwargs == {
        "top_k": 3,
        "candidate_k": 6,
        "pack_k": 5,
        "temporal_weight": 0.0,
    }
    assert multi_strategy.call_count == 0
    assert [row["id"] for row in retrieval["primary"]] == ["primary-1"]
    assert [row["id"] for row in retrieval["evidence_pack"]] == ["supplement-1", "supplement-2"]
    assert {row["id"] for row in retrieval["primary"]}.isdisjoint(
        row["id"] for row in retrieval["evidence_pack"]
    )
    assert retrieval["combined_evidence_count"] == 3
    assert [row["id"] for row in combined] == ["primary-1", "supplement-1", "supplement-2"]

    prompt = fake_llm.chat.call_args[0][0][-1]["content"]
    assert "[Primary memory] PRIMARY sentinel" in prompt
    assert "[Supplemental evidence] SUPPLEMENT one" in prompt
    assert "[Supplemental evidence] SUPPLEMENT two" in prompt


def test_evidence_arm_counts_and_labels_primary_pack_memoria_and_cloud_fact(
    monkeypatch, fake_llm
):
    """Combined diagnostics count every row actually rendered into context."""
    monkeypatch.setenv("MNEMOSYNE_BENCHMARK_PURE_RECALL", "1")
    monkeypatch.setenv("MNEMOSYNE_BENCHMARK_EVIDENCE_PACK", "on")
    import _benchmarks.evaluate_beam_end_to_end as harness

    beam = _FakeBeam({
        "primary": [{"id": "primary-1", "content": "PRIMARY sentinel", "score": 0.9}],
        "evidence_pack": [{"id": "pack-1", "content": "PACK sentinel", "score": 0.4}],
    })
    beam.memoria_retrieve = MagicMock(return_value={
        "source": "facts",
        "context": "MEMORIA sentinel",
        "facts": [{"id": "memoria-1"}],
    })
    beam.use_cloud = True
    beam.fact_recall = MagicMock(return_value=[
        {"id": "cloud-fact-1", "content": "CLOUD FACT sentinel", "score": 0.5},
    ])

    answer, combined, retrieval = _answer(harness, fake_llm, beam)

    assert answer == "answer"
    assert retrieval["primary"] == [{"id": "primary-1", "content": "PRIMARY sentinel", "score": 0.9}]
    assert retrieval["evidence_pack"] == [{"id": "pack-1", "content": "PACK sentinel", "score": 0.4}]
    assert retrieval["combined_evidence_count"] == 4
    assert len(combined) == 4

    prompt = fake_llm.chat.call_args[0][0][-1]["content"]
    assert "[Primary memory] PRIMARY sentinel" in prompt
    assert "[Supplemental evidence] PACK sentinel" in prompt
    assert "[MEMORIA fact] [MEMORIA facts]" in prompt
    assert "[Cloud fact] FACT: CLOUD FACT sentinel" in prompt


def test_evidence_arm_treats_empty_safe_recall_failure_as_empty_context(
    monkeypatch, fake_llm
):
    """The timeout/error sentinel from _recall_safe must not abort this arm."""
    monkeypatch.setenv("MNEMOSYNE_BENCHMARK_PURE_RECALL", "1")
    monkeypatch.setenv("MNEMOSYNE_BENCHMARK_EVIDENCE_PACK", "on")
    import _benchmarks.evaluate_beam_end_to_end as harness

    safe_recall = MagicMock(return_value=[])
    monkeypatch.setattr(harness, "_recall_safe", safe_recall)

    answer, combined, retrieval = _answer(harness, fake_llm, _FakeBeam())

    assert answer == "answer"
    assert safe_recall.call_count == 1
    assert combined == []
    assert retrieval == {
        "mode": "evidence_pack",
        "primary": [],
        "evidence_pack": [],
        "combined_evidence_count": 0,
    }
    prompt = fake_llm.chat.call_args[0][0][-1]["content"]
    assert "[No memories found]" in prompt
    assert "[Primary memory]" not in prompt
    assert "[Supplemental evidence]" not in prompt



@pytest.mark.parametrize(
    ("packed", "message"),
    [
        ({"unexpected": "value"}, "missing required field"),
        ({"primary": [], "evidence_pack": "not-a-list"}, "must be a list"),
        ({"primary": ["not-a-mapping"], "evidence_pack": []}, "must be a mapping"),
    ],
)
def test_evidence_arm_rejects_malformed_nonempty_pack_responses(
    monkeypatch, fake_llm, packed, message
):
    """Only _recall_safe's [] sentinel may become an empty evidence context."""
    monkeypatch.setenv("MNEMOSYNE_BENCHMARK_PURE_RECALL", "1")
    monkeypatch.setenv("MNEMOSYNE_BENCHMARK_EVIDENCE_PACK", "on")
    import _benchmarks.evaluate_beam_end_to_end as harness

    beam = _FakeBeam(packed)

    with pytest.raises((TypeError, ValueError), match=message):
        _answer(harness, fake_llm, beam)

    assert len(beam.evidence_pack_calls) == 1
    assert fake_llm.chat.call_count == 0


def test_help_exposes_opt_in_evidence_pack_switch():
    harness = _REPO_ROOT / "_benchmarks" / "evaluate_beam_end_to_end.py"
    result = subprocess.run(
        [sys.executable, str(harness), "--help"],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    assert "--evidence-pack" in result.stdout


def test_resume_rejects_prior_results_from_different_evidence_pack_arm(
    monkeypatch, tmp_path, capsys
):
    """A primary-only artifact must not be relabeled as an evidence-pack run."""
    import _benchmarks.evaluate_beam_end_to_end as harness

    results_file = tmp_path / "beam_e2e_results.json"
    results_file.write_text(json.dumps({
        "metadata": {"config": {"evidence_pack": False}},
        "results": [{"results": [{"qid": "already-evaluated"}]}],
    }))
    load_dataset = MagicMock(side_effect=AssertionError("dataset must not load"))
    llm_client = MagicMock(side_effect=AssertionError("LLM must not initialize"))
    monkeypatch.setattr(harness, "RESULTS_FILE", results_file)
    monkeypatch.setattr(harness, "load_beam_dataset", load_dataset)
    monkeypatch.setattr(harness, "LLMClient", llm_client)
    monkeypatch.delenv("MNEMOSYNE_BENCHMARK_EVIDENCE_PACK", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "evaluate_beam_end_to_end.py",
            "--pure-recall",
            "--evidence-pack",
            "--resume",
        ],
    )

    original_evidence_pack = os.environ.get("MNEMOSYNE_BENCHMARK_EVIDENCE_PACK")
    original_pure_recall = os.environ.get("MNEMOSYNE_BENCHMARK_PURE_RECALL")
    try:
        with pytest.raises(SystemExit) as exc_info:
            harness.main()
    finally:
        for name, original_value in (
            ("MNEMOSYNE_BENCHMARK_EVIDENCE_PACK", original_evidence_pack),
            ("MNEMOSYNE_BENCHMARK_PURE_RECALL", original_pure_recall),
        ):
            if original_value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = original_value

    assert exc_info.value.code == 2
    assert load_dataset.call_count == 0
    assert llm_client.call_count == 0
    assert "Run without --resume or use a matching results artifact" in capsys.readouterr().err


def test_result_preserves_primary_provenance_and_records_combined_evidence(
    monkeypatch, fake_llm
):
    """Per-question records distinguish the stable primary metric from context."""
    import _benchmarks.evaluate_beam_end_to_end as harness

    primary = [{"id": "primary-1", "content": "primary", "score": 0.9}]
    supplemental = [{"id": "supplement-1", "content": "supplement", "score": 0.4}]
    monkeypatch.setattr(
        harness,
        "answer_with_memory",
        MagicMock(return_value=(
            "answer",
            primary + supplemental,
            {
                "mode": "evidence_pack",
                "primary": primary,
                "evidence_pack": supplemental,
                "combined_evidence_count": 2,
            },
        )),
    )
    monkeypatch.setattr(
        harness,
        "judge_with_rubrics",
        MagicMock(return_value={"overall_score": 1.0}),
    )
    monkeypatch.setattr(harness.time, "sleep", lambda _: None)

    result = harness.evaluate_conversation(
        fake_llm,
        fake_llm,
        _FakeBeam(),
        {
            "id": "conversation-1",
            "scale": "100K",
            "messages": [],
            "questions": [{"question": "q", "ideal_answer": "a", "ability": "IE"}],
        },
    )["results"][0]

    assert result["recall_provenance"]["kept_count"] == 1
    assert result["evidence_pack_diagnostics"] == {
        "enabled": True,
        "primary_recall_count": 1,
        "supplemental_evidence_count": 1,
        "combined_evidence_count": 2,
    }
