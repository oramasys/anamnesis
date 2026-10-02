"""Controlled promotion pipeline (candidate -> reviewed -> graduated).

Promotion is fail-closed and state-machine-enforced: an entry can only move
forward one state at a time, every transition requires a reviewer identity
and a reason, and graduation additionally requires a promotion decision
reference (the human or gate that authorized it). States never skip.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum

from .ledger import Ledger, LedgerRecord, MemoryEntry


class PromotionState(StrEnum):
    CANDIDATE = "candidate"
    REVIEWED = "reviewed"
    GRADUATED = "graduated"
    REJECTED = "rejected"


_FORWARD = {
    PromotionState.CANDIDATE: PromotionState.REVIEWED,
    PromotionState.REVIEWED: PromotionState.GRADUATED,
}


@dataclass(frozen=True, slots=True)
class PromotionRecord:
    entry: MemoryEntry
    from_state: PromotionState
    to_state: PromotionState
    reviewer: str
    reason: str
    decision_ref: str | None
    at: str


class PromotionPipeline:
    """Controlled promotion over a ledger's accepted records.

    The pipeline does not mutate the ledger -- ledger history is append-only
    and immutable. Promotion state is tracked per provenance_ref alongside
    the ledger, and graduation requires an explicit decision_ref (the human
    or gate that authorized it).
    """

    def __init__(self, ledger: Ledger) -> None:
        self._ledger = ledger
        self._state: dict[str, tuple[PromotionState, MemoryEntry]] = {}
        self._history: list[PromotionRecord] = []

    def submit(self, record: LedgerRecord) -> PromotionState:
        provenance = record.entry.provenance_ref
        if provenance in self._state:
            raise ValueError(f"entry already tracked: {provenance}")
        self._state[provenance] = (PromotionState.CANDIDATE, record.entry)
        return PromotionState.CANDIDATE

    def advance(
        self,
        provenance_ref: str,
        *,
        reviewer: str,
        reason: str,
        decision_ref: str | None = None,
    ) -> PromotionState:
        if not reviewer.strip():
            raise ValueError("reviewer is required")
        if not reason.strip():
            raise ValueError("reason is required")
        state, entry = self._state.get(
            provenance_ref,
            (PromotionState.REJECTED, MemoryEntry(run_id="x", lesson="x", provenance_ref=provenance_ref)),
        )
        if provenance_ref not in self._state:
            raise ValueError(f"unknown provenance_ref: {provenance_ref!r}")
        if state is PromotionState.REJECTED:
            raise ValueError("rejected entries cannot be promoted")
        if state not in _FORWARD:
            raise ValueError(f"terminal state: {state}")
        if state is PromotionState.REVIEWED and not decision_ref:
            raise ValueError("graduation requires a decision_ref (authorization evidence)")
        target = _FORWARD[state]
        self._state[provenance_ref] = (target, entry)
        self._history.append(
            PromotionRecord(
                entry=entry,
                from_state=state,
                to_state=target,
                reviewer=reviewer,
                reason=reason,
                decision_ref=decision_ref,
                at=datetime.now(UTC).isoformat(),
            )
        )
        return target

    def reject(self, provenance_ref: str, *, reviewer: str, reason: str) -> PromotionState:
        if provenance_ref not in self._state:
            raise ValueError(f"unknown provenance_ref: {provenance_ref!r}")
        state, entry = self._state[provenance_ref]
        if state is PromotionState.GRADUATED:
            raise ValueError("graduated entries cannot be rejected")
        self._state[provenance_ref] = (PromotionState.REJECTED, entry)
        self._history.append(
            PromotionRecord(
                entry=entry,
                from_state=state,
                to_state=PromotionState.REJECTED,
                reviewer=reviewer,
                reason=reason,
                decision_ref=None,
                at=datetime.now(UTC).isoformat(),
            )
        )
        return PromotionState.REJECTED

    def state_of(self, provenance_ref: str) -> PromotionState:
        return self._state[provenance_ref][0]

    @property
    def history(self) -> tuple[PromotionRecord, ...]:
        return tuple(self._history)
