"""Epistemic memory for Oramasys.

Anamnesis owns: the append-only provenance/audit ledger for captured
lessons and memory entries, and the controlled promotion pipeline that
moves entries through reviewed states into the durable store.

Anamnesis does NOT own: security admission/redaction policy (Phylax owns
that -- a configured PreWriteGate is invoked fail-closed before any record
is accepted), runtime orchestration (perpetua-core), or endpoint/transport
decisions (telos).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Protocol


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True, slots=True)
class MemoryEntry:
    """One captured lesson/memory record, append-only once recorded."""

    run_id: str
    lesson: str
    provenance_ref: str
    source: str = "agent"
    recorded_at: str = ""

    def __post_init__(self) -> None:
        if not self.run_id.strip():
            raise ValueError("run_id is required")
        if not self.lesson.strip():
            raise ValueError("lesson is required")
        if not self.provenance_ref.strip():
            raise ValueError("provenance_ref is required")


@dataclass(frozen=True, slots=True)
class LedgerRecord:
    """A ledger row: the entry plus its acceptance metadata."""

    entry: MemoryEntry
    accepted_by_gate: str
    recorded_at: str


class PreWriteGate(Protocol):
    """Phylax-owned pre-write/redaction boundary (fail-closed).

    Implemented by Phylax; anamnesis only knows the protocol. A gate that
    raises means the record is NOT persisted -- anamnesis never strips or
    redacts content itself, and never falls back to writing unreviewed.
    """

    def gate(self, entry: MemoryEntry) -> MemoryEntry: ...

    @property
    def name(self) -> str: ...


class Ledger:
    """Thread-safe, append-only provenance/audit ledger.

    ``gate`` (Phylax-owned) is fail-closed: when configured, every record
    passes through it before acceptance; a gate failure rejects the record
    and raises. History is never rewritten.
    """

    def __init__(self, gate: PreWriteGate | None = None) -> None:
        self._lock = threading.Lock()
        self._records: list[LedgerRecord] = []
        self._gate = gate

    def record(self, entry: MemoryEntry) -> LedgerRecord:
        stamped_entry = entry
        if not entry.recorded_at:
            stamped_entry = replace(entry, recorded_at=_utc_now_iso())
        if self._gate is not None:
            gated = self._gate.gate(stamped_entry)
            gate_name = self._gate.name
        else:
            gated = stamped_entry
            gate_name = "none-configured"
        record = LedgerRecord(
            entry=gated, accepted_by_gate=gate_name, recorded_at=_utc_now_iso()
        )
        with self._lock:
            self._records.append(record)
        return record

    def records(self) -> tuple[LedgerRecord, ...]:
        with self._lock:
            return tuple(self._records)
