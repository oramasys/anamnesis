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
survives process restart. The chain is verified on open, read, and before
linking a new record (fail closed). `previous_record_hash` is UNIQUE;
existing databases receive `idx_ledger_previous_record_hash` on open.
Append reads the tip hash inside `BEGIN IMMEDIATE` on the same connection.
Database, WAL, and SHM files are mode 0600.

**Read-side retrieval (PR3):** `TrustTier` is orthogonal to
`PromotionState`. `RetrievalGate` enforces an explicit principal registry
(empty registry denies all), scope, trust floor, expiry, and revocation
(fail-closed) and appends a retrieval audit trail.
`ContextInjectionBoundary` is the only path that may surface lesson text
into agent context; lesson text is resolved from the verified ledger by
`provenance_ref` (caller-supplied text is never trusted). Denials raise or
omit content and never leak payloads.
