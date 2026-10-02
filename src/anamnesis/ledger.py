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

import hashlib
import json
import os
import sqlite3
import threading
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

GENESIS_HASH = "0" * 64

# Existing databases created before previous_record_hash was UNIQUE still
# open: CREATE TABLE IF NOT EXISTS leaves the old schema in place, and
# ``CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_previous_record_hash``
# adds the uniqueness rule. Open fails closed if a fork is already stored.
_PREVIOUS_HASH_INDEX = "idx_ledger_previous_record_hash"


class HashChainIntegrityError(ValueError):
    """Raised when the append-only hash chain does not verify (fail closed)."""


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
    """A ledger row: the entry plus acceptance metadata and hash-chain links."""

    entry: MemoryEntry
    accepted_by_gate: str
    recorded_at: str
    record_hash: str = ""
    previous_record_hash: str = ""
    sequence: int = 0


class PreWriteGate(Protocol):
    """Phylax-owned pre-write/redaction boundary (fail-closed).

    Implemented by Phylax; anamnesis only knows the protocol. A gate that
    raises means the record is NOT persisted -- anamnesis never strips or
    redacts content itself, and never falls back to writing unreviewed.
    """

    def gate(self, entry: MemoryEntry) -> MemoryEntry: ...

    @property
    def name(self) -> str: ...


def compute_record_hash(
    entry: MemoryEntry,
    accepted_by_gate: str,
    recorded_at: str,
    previous_record_hash: str,
) -> str:
    """SHA-256 over a canonical record payload chained to the previous hash.

    Proves history continuity (tamper-evident append-only chain), not
    content truth. ``record_hash`` itself is never included in the input.
    """
    canonical = json.dumps(
        {
            "accepted_by_gate": accepted_by_gate,
            "entry_recorded_at": entry.recorded_at,
            "lesson": entry.lesson,
            "previous_record_hash": previous_record_hash,
            "provenance_ref": entry.provenance_ref,
            "recorded_at": recorded_at,
            "run_id": entry.run_id,
            "source": entry.source,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_hash_chain(records: tuple[LedgerRecord, ...] | list[LedgerRecord]) -> bool:
    """Return True iff every record's hash matches and links to the prior hash."""
    prev = GENESIS_HASH
    for record in records:
        if record.previous_record_hash != prev:
            return False
        expected = compute_record_hash(
            record.entry,
            record.accepted_by_gate,
            record.recorded_at,
            record.previous_record_hash,
        )
        if record.record_hash != expected:
            return False
        prev = record.record_hash
    return True


def assert_hash_chain(records: tuple[LedgerRecord, ...] | list[LedgerRecord]) -> None:
    """Fail closed if the hash chain does not verify."""
    if not verify_hash_chain(records):
        raise HashChainIntegrityError("ledger hash chain integrity check failed")


class LedgerBackend(Protocol):
    """Persistence boundary for ledger records (memory or SQLite)."""

    def append(self, record: LedgerRecord) -> LedgerRecord:
        """Persist ``record`` transactionally; may assign ``sequence``."""
        ...

    def load(self) -> tuple[LedgerRecord, ...]:
        """Return all records in append order."""
        ...

    def last_hash(self) -> str:
        """Hash of the tip record, or ``GENESIS_HASH`` if empty."""
        ...


class MemoryLedgerBackend:
    """In-process list backend (tests / ephemeral use)."""

    def __init__(self) -> None:
        self._records: list[LedgerRecord] = []
        self._lock = threading.Lock()

    def append(self, record: LedgerRecord) -> LedgerRecord:
        with self._lock:
            assert_hash_chain(self._records)
            previous = (
                self._records[-1].record_hash if self._records else GENESIS_HASH
            )
            record_hash = compute_record_hash(
                record.entry,
                record.accepted_by_gate,
                record.recorded_at,
                previous,
            )
            seq = len(self._records) + 1
            stored = replace(
                record,
                sequence=seq,
                record_hash=record_hash,
                previous_record_hash=previous,
            )
            self._records.append(stored)
            return stored

    def load(self) -> tuple[LedgerRecord, ...]:
        with self._lock:
            records = tuple(self._records)
        assert_hash_chain(records)
        return records

    def last_hash(self) -> str:
        with self._lock:
            assert_hash_chain(self._records)
            if not self._records:
                return GENESIS_HASH
            return self._records[-1].record_hash


class SQLiteLedgerBackend:
    """Local-first durable backend with transactional append and hash chain."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS ledger_records (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL,
        lesson TEXT NOT NULL,
        provenance_ref TEXT NOT NULL,
        source TEXT NOT NULL,
        entry_recorded_at TEXT NOT NULL,
        accepted_by_gate TEXT NOT NULL,
        recorded_at TEXT NOT NULL,
        record_hash TEXT NOT NULL UNIQUE,
        previous_record_hash TEXT NOT NULL UNIQUE,
        UNIQUE (provenance_ref)
    );
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        try:
            conn.execute(self._SCHEMA)
            try:
                conn.execute(
                    f"CREATE UNIQUE INDEX IF NOT EXISTS {_PREVIOUS_HASH_INDEX} "
                    "ON ledger_records(previous_record_hash)"
                )
            except sqlite3.IntegrityError as exc:
                raise HashChainIntegrityError(
                    "cannot enforce unique previous_record_hash; "
                    "a chain fork is already present in this database"
                ) from exc
            self._assert_chain(conn)
        finally:
            conn.close()

    def _chmod_db_files(self) -> None:
        for suffix in ("", "-wal", "-shm"):
            path = Path(f"{self._path}{suffix}") if suffix else self._path
            if path.exists():
                os.chmod(path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        old_umask = os.umask(0o077)
        try:
            conn = sqlite3.connect(
                self._path,
                isolation_level=None,
                timeout=30.0,
            )
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA busy_timeout=5000")
        finally:
            os.umask(old_umask)
        self._chmod_db_files()
        return conn

    @staticmethod
    def _commit(conn: sqlite3.Connection) -> None:
        """Commit hook (patchable in tests to simulate crash-before-commit)."""
        conn.commit()

    def _load_records(self, conn: sqlite3.Connection) -> tuple[LedgerRecord, ...]:
        rows = conn.execute(
            """
            SELECT sequence, run_id, lesson, provenance_ref, source,
                   entry_recorded_at, accepted_by_gate, recorded_at,
                   record_hash, previous_record_hash
            FROM ledger_records
            ORDER BY sequence ASC
            """
        ).fetchall()
        return tuple(self._row_to_record(row) for row in rows)

    def _assert_chain(self, conn: sqlite3.Connection) -> tuple[LedgerRecord, ...]:
        records = self._load_records(conn)
        assert_hash_chain(records)
        return records

    def _tip_hash(self, conn: sqlite3.Connection) -> str:
        row = conn.execute(
            "SELECT record_hash FROM ledger_records ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else GENESIS_HASH

    def append(self, record: LedgerRecord) -> LedgerRecord:
        entry = record.entry
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                self._assert_chain(conn)
                previous = self._tip_hash(conn)
                record_hash = compute_record_hash(
                    entry,
                    record.accepted_by_gate,
                    record.recorded_at,
                    previous,
                )
                cur = conn.execute(
                    """
                    INSERT INTO ledger_records (
                        run_id, lesson, provenance_ref, source,
                        entry_recorded_at, accepted_by_gate, recorded_at,
                        record_hash, previous_record_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry.run_id,
                        entry.lesson,
                        entry.provenance_ref,
                        entry.source,
                        entry.recorded_at,
                        record.accepted_by_gate,
                        record.recorded_at,
                        record_hash,
                        previous,
                    ),
                )
                seq = int(cur.lastrowid)
                self._commit(conn)
                return replace(
                    record,
                    sequence=seq,
                    record_hash=record_hash,
                    previous_record_hash=previous,
                )
            except sqlite3.IntegrityError as exc:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise HashChainIntegrityError(
                    "append rejected: unique chain constraint violated "
                    "(forked previous_record_hash or duplicate provenance)"
                ) from exc
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            finally:
                conn.close()

    def load(self) -> tuple[LedgerRecord, ...]:
        with self._lock:
            conn = self._connect()
            try:
                return self._assert_chain(conn)
            finally:
                conn.close()

    def last_hash(self) -> str:
        with self._lock:
            conn = self._connect()
            try:
                self._assert_chain(conn)
                return self._tip_hash(conn)
            finally:
                conn.close()

    @staticmethod
    def _row_to_record(row: tuple) -> LedgerRecord:
        (
            sequence,
            run_id,
            lesson,
            provenance_ref,
            source,
            entry_recorded_at,
            accepted_by_gate,
            recorded_at,
            record_hash,
            previous_record_hash,
        ) = row
        return LedgerRecord(
            entry=MemoryEntry(
                run_id=run_id,
                lesson=lesson,
                provenance_ref=provenance_ref,
                source=source,
                recorded_at=entry_recorded_at,
            ),
            accepted_by_gate=accepted_by_gate,
            recorded_at=recorded_at,
            record_hash=record_hash,
            previous_record_hash=previous_record_hash,
            sequence=int(sequence),
        )


class Ledger:
    """Thread-safe, append-only provenance/audit ledger.

    Secure production use: ``Ledger.secure(gate=...)``.
    Test-only ungated use: ``Ledger.unrestricted_for_tests()``.
    ``gate=None`` is never a silent production default.
    """

    def __init__(
        self,
        gate: PreWriteGate | None = None,
        backend: LedgerBackend | None = None,
        *,
        require_gate: bool = False,
        _allow_ungated: bool = False,
    ) -> None:
        if require_gate and gate is None:
            raise ValueError("gate is required when require_gate=True")
        if gate is None and not _allow_ungated and not require_gate:
            raise ValueError(
                "Ledger() refuses silent gate=None; use Ledger.secure(gate=...) "
                "for production or Ledger.unrestricted_for_tests() for tests "
                "(or pass require_gate=True with an explicit gate)"
            )
        self._lock = threading.Lock()
        self._gate = gate
        self._backend: LedgerBackend = backend if backend is not None else MemoryLedgerBackend()
        self._require_gate = require_gate or (gate is not None and not _allow_ungated)

    @classmethod
    def secure(
        cls,
        gate: PreWriteGate,
        backend: LedgerBackend | None = None,
    ) -> Ledger:
        """Mandatory-gate construction path for production / fail-closed admission."""
        if gate is None:
            raise TypeError("Ledger.secure requires a non-None gate")
        return cls(gate=gate, backend=backend, require_gate=True)

    @classmethod
    def unrestricted_for_tests(
        cls,
        backend: LedgerBackend | None = None,
    ) -> Ledger:
        """Explicit test-only escape hatch when no PreWriteGate is configured."""
        return cls(gate=None, backend=backend, require_gate=False, _allow_ungated=True)

    def record(self, entry: MemoryEntry) -> LedgerRecord:
        if self._require_gate and self._gate is None:
            raise ValueError("gate is required")
        stamped_entry = entry
        if not entry.recorded_at:
            stamped_entry = replace(entry, recorded_at=_utc_now_iso())
        if self._gate is not None:
            gated = self._gate.gate(stamped_entry)
            gate_name = self._gate.name
        else:
            gated = stamped_entry
            gate_name = "none-configured"
        recorded_at = _utc_now_iso()
        record = LedgerRecord(
            entry=gated,
            accepted_by_gate=gate_name,
            recorded_at=recorded_at,
        )
        with self._lock:
            return self._backend.append(record)

    def records(self) -> tuple[LedgerRecord, ...]:
        with self._lock:
            loaded = self._backend.load()
        assert_hash_chain(loaded)
        return loaded

    def record_for_provenance(self, provenance_ref: str) -> LedgerRecord | None:
        """Return the unique ledger record for ``provenance_ref``, if present.

        Reads through ``records()`` so a broken hash chain fails closed.
        """
        matches = [
            rec for rec in self.records() if rec.entry.provenance_ref == provenance_ref
        ]
        if not matches:
            return None
        return matches[0]
