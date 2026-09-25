# anamnesis boundaries

## Always do
- Append-only ledger: records are never rewritten or removed.
- Fail-closed pre-write gate (Phylax-owned protocol): a gate failure means
  the record is not persisted. No fallback, no self-redaction.
- Production construction via `Ledger.secure(gate=...)` (or
  `require_gate=True`); never silently default to `gate=None`.
- Durable backends (SQLite) use transactional append with a tamper-evident
  `record_hash` / `previous_record_hash` chain.
- UTC timestamps on every record; promotion transitions require reviewer +
  reason; graduation requires a decision_ref.
- Trust tiers are orthogonal to promotion lifecycle; graduation never
  grants retrieval trust, and trust never implies graduation.
- Retrieval checks expiry and revocation fail-closed; every evaluate /
  inject attempt is append-only audited.
- Agent context receives lesson text only via `ContextInjectionBoundary`
  (unauthorized / expired / revoked content is never injected).

## Never do
- Never strip/redact memory content inside anamnesis (Phylax owns policy).
- Never import runtime orchestration (perpetua-core), endpoint/transport
  (telos), or hardware selection (agate) into this repo.
- Never promote without evidence (decision_ref) or skip states.
- Never treat graduated lifecycle as sufficient for retrieval trust.
- Never inject unauthorized, expired, or revoked memory into agent context.
- Never push/merge without operator authorization (program control).
