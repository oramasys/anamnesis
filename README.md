# anamnesis

Epistemic memory for Oramasys: the append-only provenance/audit ledger for
captured lessons and memory entries, plus the controlled promotion pipeline
(candidate -> reviewed -> graduated) that moves records into the durable
store on explicit, evidenced decisions.

**Canonical boundary:** anamnesis owns memory persistence, provenance, and
promotion. It does NOT own security admission/redaction policy (Phylax owns
that via the fail-closed PreWriteGate protocol), runtime orchestration
(perpetua-core), or endpoint/transport decisions (telos).

Version 1.9.0 — coordinated pre-release baseline cohort.

**Secure admission:** use `Ledger.secure(gate=...)`. `gate=None` is not a
silent production default; tests may use `Ledger.unrestricted_for_tests()`.

**Durable provenance (PR2):** `SQLiteLedgerBackend` provides transactional
append and a SHA-256 `record_hash` / `previous_record_hash` chain that
survives process restart.
