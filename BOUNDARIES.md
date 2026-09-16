# anamnesis boundaries

## Always do
- Append-only ledger: records are never rewritten or removed.
- Fail-closed pre-write gate (Phylax-owned protocol): a gate failure means
  the record is not persisted. No fallback, no self-redaction.
- UTC timestamps on every record; promotion transitions require reviewer +
  reason; graduation requires a decision_ref.

## Never do
- Never strip/redact memory content inside anamnesis (Phylax owns policy).
- Never import runtime orchestration (perpetua-core), endpoint/transport
  (telos), or hardware selection (agate) into this repo.
- Never promote without evidence (decision_ref) or skip states.
- Never push/merge without operator authorization (program control).
