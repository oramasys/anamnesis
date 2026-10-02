"""Anamnesis building-block tests: ledger, pre-write gate, promotion."""

import pytest

from anamnesis import (
    Ledger,
    MemoryEntry,
    PromotionPipeline,
    PromotionState,
)


def _entry(run_id: str = "run-1") -> MemoryEntry:
    return MemoryEntry(
        run_id=run_id,
        lesson="captured lesson",
        provenance_ref=f"prov:{run_id}",
    )


def test_ledger_records_with_utc_timestamp_and_is_append_only():
    ledger = Ledger()
    ledger.record(_entry("run-1"))
    first = ledger.records()
    ledger.record(_entry("run-2"))
    second = ledger.records()

    assert len(second) == len(first) + 1
    assert second[: len(first)] == first  # history never rewritten
    assert all(r.recorded_at.endswith("+00:00") for r in second)  # UTC
    assert all(r.accepted_by_gate == "none-configured" for r in second)


def test_pre_write_gate_is_fail_closed():
    class RejectingGate:
        name = "phylax-redaction"

        def gate(self, entry):
            raise ValueError("unredacted content rejected")

    ledger = Ledger(gate=RejectingGate())
    with pytest.raises(ValueError, match="unredacted"):
        ledger.record(_entry())
    assert ledger.records() == ()  # nothing persisted on gate failure


def test_pre_write_gate_can_transform_before_acceptance():
    class RedactingGate:
        name = "phylax-redaction"

        def gate(self, entry):
            return type(entry)(
                run_id=entry.run_id,
                lesson="redacted: [policy-filtered]",
                provenance_ref=entry.provenance_ref,
                recorded_at=entry.recorded_at,
            )

    ledger = Ledger(gate=RedactingGate())
    ledger.record(_entry())
    assert ledger.records()[0].entry.lesson.startswith("redacted:")
    assert ledger.records()[0].accepted_by_gate == "phylax-redaction"


def test_promotion_state_machine_is_forward_only_with_graduation_gate():
    ledger = Ledger()
    pipeline = PromotionPipeline(ledger)
    record = pipeline_state = None
    record = ledger.record(_entry("run-promote"))
    pipeline.submit(record)

    assert pipeline.state_of("prov:run-promote") is PromotionState.CANDIDATE

    state = pipeline.advance("prov:run-promote", reviewer="kimi", reason="verified")
    assert state is PromotionState.REVIEWED

    with pytest.raises(ValueError, match="decision_ref"):
        pipeline.advance("prov:run-promote", reviewer="operator", reason="no evidence")

    state = pipeline.advance(
        "prov:run-promote", reviewer="operator", reason="approved", decision_ref="dec-1"
    )
    assert state is PromotionState.GRADUATED
    with pytest.raises(ValueError, match="terminal"):
        pipeline.advance("prov:run-promote", reviewer="x", reason="again")


def test_rejection_is_recorded_and_terminal():
    ledger = Ledger()
    pipeline = PromotionPipeline(ledger)
    pipeline.submit(ledger.record(_entry("run-reject")))
    state = pipeline.reject("prov:run-reject", reviewer="operator", reason="superseded")
    assert state is PromotionState.REJECTED
    with pytest.raises(ValueError, match="cannot be promoted"):
        pipeline.advance("prov:run-reject", reviewer="x", reason="retry")
    assert pipeline.history[0].reason == "superseded"
