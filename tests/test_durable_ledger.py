"""PR2 durable provenance: secure admission, SQLite backend, hash chain, restart."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from anamnesis import Ledger, MemoryEntry
from anamnesis.ledger import (
    GENESIS_HASH,
    MemoryLedgerBackend,
    SQLiteLedgerBackend,
    compute_record_hash,
    verify_hash_chain,
)


class _AcceptGate:
    name = "test-gate"

    def gate(self, entry: MemoryEntry) -> MemoryEntry:
        return entry


class _RejectGate:
    name = "reject-gate"

    def gate(self, entry: MemoryEntry) -> MemoryEntry:
        raise ValueError("denied by policy")


def _entry(run_id: str = "run-1", *, lesson: str = "lesson") -> MemoryEntry:
    return MemoryEntry(
        run_id=run_id,
        lesson=lesson,
        provenance_ref=f"prov:{run_id}",
    )


# --- Mandatory secure construction -----------------------------------------


def test_ledger_secure_requires_gate():
    with pytest.raises(TypeError, match="gate"):
        Ledger.secure(gate=None)  # type: ignore[arg-type]


def test_ledger_secure_rejects_missing_gate_kw():
    with pytest.raises(TypeError):
        Ledger.secure()  # type: ignore[call-arg]


def test_require_gate_true_without_gate_raises():
    with pytest.raises(ValueError, match="gate is required"):
        Ledger(gate=None, require_gate=True)


def test_plain_ledger_constructor_does_not_silently_accept_none_gate():
    """Production default must not be gate=None without an explicit escape hatch."""
    with pytest.raises(ValueError, match="unrestricted_for_tests|require_gate|secure"):
        Ledger()


def test_unrestricted_for_tests_allows_none_gate():
    ledger = Ledger.unrestricted_for_tests()
    rec = ledger.record(_entry())
    assert rec.accepted_by_gate == "none-configured"
    assert rec.record_hash
    assert rec.previous_record_hash == GENESIS_HASH


def test_secure_ledger_records_with_gate_name():
    ledger = Ledger.secure(gate=_AcceptGate())
    rec = ledger.record(_entry())
    assert rec.accepted_by_gate == "test-gate"
    assert len(rec.record_hash) == 64


def test_secure_ledger_gate_failure_persists_nothing():
    backend = MemoryLedgerBackend()
    ledger = Ledger.secure(gate=_RejectGate(), backend=backend)
    with pytest.raises(ValueError, match="denied"):
        ledger.record(_entry())
    assert backend.load() == ()


# --- Hash chain -------------------------------------------------------------


def test_record_hash_chains_to_previous():
    ledger = Ledger.secure(gate=_AcceptGate())
    r1 = ledger.record(_entry("a"))
    r2 = ledger.record(_entry("b"))

    assert r1.previous_record_hash == GENESIS_HASH
    assert r2.previous_record_hash == r1.record_hash
    assert r1.record_hash != r2.record_hash
    assert r1.record_hash == compute_record_hash(
        r1.entry, r1.accepted_by_gate, r1.recorded_at, r1.previous_record_hash
    )
    assert verify_hash_chain(ledger.records()) is True


def test_tampered_record_breaks_hash_chain_verification():
    ledger = Ledger.secure(gate=_AcceptGate())
    ledger.record(_entry("a"))
    ledger.record(_entry("b"))
    records = list(ledger.records())
    # Mutate lesson after the fact (simulating storage rewrite).
    from dataclasses import replace

    bad_entry = replace(records[0].entry, lesson="tampered")
    records[0] = replace(records[0], entry=bad_entry)
    assert verify_hash_chain(tuple(records)) is False


def test_append_order_is_monotonic_sequence():
    ledger = Ledger.secure(gate=_AcceptGate())
    for i in range(5):
        ledger.record(_entry(f"run-{i}"))
    seqs = [r.sequence for r in ledger.records()]
    assert seqs == [1, 2, 3, 4, 5]


# --- SQLite transactional append + crash/restart ----------------------------


def test_sqlite_transactional_append_and_restart(tmp_path: Path):
    db = tmp_path / "ledger.db"
    backend = SQLiteLedgerBackend(db)
    ledger = Ledger.secure(gate=_AcceptGate(), backend=backend)
    ledger.record(_entry("persist-1", lesson="first"))
    ledger.record(_entry("persist-2", lesson="second"))
    hashes = [r.record_hash for r in ledger.records()]

    # Simulate process restart: new Ledger + backend on same path.
    backend2 = SQLiteLedgerBackend(db)
    ledger2 = Ledger.secure(gate=_AcceptGate(), backend=backend2)
    restored = ledger2.records()
    assert len(restored) == 2
    assert [r.entry.lesson for r in restored] == ["first", "second"]
    assert [r.record_hash for r in restored] == hashes
    assert verify_hash_chain(restored) is True

    # Further append continues the chain.
    r3 = ledger2.record(_entry("persist-3", lesson="third"))
    assert r3.previous_record_hash == hashes[-1]
    assert r3.sequence == 3


def test_sqlite_crash_during_append_rolls_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A mid-transaction failure must not leave a partial / orphan row."""
    db = tmp_path / "crash.db"
    backend = SQLiteLedgerBackend(db)
    ledger = Ledger.secure(gate=_AcceptGate(), backend=backend)
    ledger.record(_entry("ok"))

    def boom(_conn: sqlite3.Connection) -> None:
        raise sqlite3.OperationalError("simulated crash before commit")

    monkeypatch.setattr(backend, "_commit", boom)
    with pytest.raises(sqlite3.OperationalError, match="simulated crash"):
        ledger.record(_entry("crash-me"))

    # Reopen: only the committed record survives.
    restored = SQLiteLedgerBackend(db).load()
    assert len(restored) == 1
    assert restored[0].entry.provenance_ref == "prov:ok"
    assert verify_hash_chain(restored) is True


def test_sqlite_ordering_stable_across_reopen(tmp_path: Path):
    db = tmp_path / "order.db"
    ledger = Ledger.secure(gate=_AcceptGate(), backend=SQLiteLedgerBackend(db))
    for i in range(10):
        ledger.record(_entry(f"o-{i}", lesson=f"L{i}"))

    again = Ledger.secure(gate=_AcceptGate(), backend=SQLiteLedgerBackend(db))
    lessons = [r.entry.lesson for r in again.records()]
    assert lessons == [f"L{i}" for i in range(10)]
    assert [r.sequence for r in again.records()] == list(range(1, 11))
