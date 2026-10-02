# anamnesis boundaries

## Always do
- Append-only ledger: records are never rewritten or removed.
- Fail-closed pre-write gate (Phylax-owned protocol): a gate failure means
  the record is not persisted. No fallback, no self-redaction.
- Production construction via `Ledger.secure(gate=...)` (or
  `require_gate=True`); never silently default to `gate=None`.
- Durable backends (SQLite) use transactional append with a tamper-evident
  `record_hash` / `previous_record_hash` chain. The chain is verified on
  open, on `load()` / `records()`, and inside `BEGIN IMMEDIATE` before a
  new row is linked. Mismatch raises `HashChainIntegrityError`.
- `previous_record_hash` is UNIQUE so two writers cannot fork the chain.
  New databases declare that in `CREATE TABLE`. Existing databases get
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_ledger_previous_record_hash` on
  open (fails closed if a fork is already stored).
- SQLite last-hash is read on the same connection inside the append
  transaction; `record_hash` is computed from that tip, not from a stale
  snapshot on another connection.
- SQLite database, `-wal`, and `-shm` files are created 0600 (umask 077
  plus chmod after WAL files appear).
- UTC timestamps on every record; promotion transitions require reviewer +
  reason; graduation requires a decision_ref.

## Never do
- Never strip/redact memory content inside anamnesis (Phylax owns policy).
- Never import runtime orchestration (perpetua-core), endpoint/transport
  (telos), or hardware selection (agate) into this repo.
- Never promote without evidence (decision_ref) or skip states.
- Never push/merge without operator authorization (program control).
