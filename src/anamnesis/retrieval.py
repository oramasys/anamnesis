"""Read-side retrieval authorization for Anamnesis.

Trust tiers are orthogonal to promotion lifecycle states
(candidate / reviewed / graduated / rejected). Graduation never implies
trust, and trust never implies graduation.

Retrieval checks expiry and revocation fail-closed. Every evaluate /
inject attempt is recorded in an append-only retrieval audit trail.
Context injection is the only path that may surface lesson text into an
agent context, and it never returns unauthorized or expired content.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Callable

from .ledger import HashChainIntegrityError, Ledger
from .promotion import PromotionState


class TrustTier(StrEnum):
    """Retrieval trust — independent of ``PromotionState``."""

    UNTRUSTED = "untrusted"
    INTERNAL = "internal"
    VERIFIED = "verified"


_TRUST_RANK: dict[TrustTier, int] = {
    TrustTier.UNTRUSTED: 0,
    TrustTier.INTERNAL: 1,
    TrustTier.VERIFIED: 2,
}


class RetrievalDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class DenyReason(StrEnum):
    UNKNOWN_ENTRY = "unknown_entry"
    REVOKED = "revoked"
    EXPIRED = "expired"
    TRUST_INSUFFICIENT = "trust_insufficient"
    SCOPE_DENIED = "scope_denied"
    EMPTY_PRINCIPAL = "empty_principal"
    EMPTY_SCOPE = "empty_scope"
    UNKNOWN_PRINCIPAL = "unknown_principal"
    LESSON_MISMATCH = "lesson_mismatch"
    EVALUATION_ERROR = "evaluation_error"


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _parse_iso(ts: str) -> datetime:
    # Accept both +00:00 and Z.
    normalized = ts.replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def trust_satisfies(actual: TrustTier, required: TrustTier) -> bool:
    return _TRUST_RANK[actual] >= _TRUST_RANK[required]


@dataclass(frozen=True, slots=True)
class RetrievalPrincipal:
    """Caller identity for a retrieval / context-injection attempt."""

    principal_id: str
    task_scope: str
    min_trust: TrustTier = TrustTier.UNTRUSTED

    def __post_init__(self) -> None:
        if not self.principal_id.strip():
            raise ValueError("principal_id is required")
        if not self.task_scope.strip():
            raise ValueError("task_scope is required")


class PrincipalRegistry:
    """Explicit allowlist of retrieval principals.

    Fail closed: an empty registry denies every principal.
    """

    def __init__(self, principal_ids: Iterable[str] = ()) -> None:
        self._ids = frozenset(pid.strip() for pid in principal_ids if str(pid).strip())

    def contains(self, principal_id: str) -> bool:
        return principal_id in self._ids


@dataclass(frozen=True, slots=True)
class AuthorizationRecord:
    """Read-side ACL metadata for one ledger provenance_ref.

    Orthogonal to promotion lifecycle: a graduated entry may still be
    UNTRUSTED; a candidate may be VERIFIED if decision evidence exists.
    """

    provenance_ref: str
    trust_tier: TrustTier
    author_principal: str
    allowed_scopes: frozenset[str]
    decision_ref: str | None
    expires_at: str | None = None
    revoked_at: str | None = None
    revoked_by: str | None = None
    revoke_reason: str | None = None

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None


@dataclass(frozen=True, slots=True)
class RetrievalAuditEvent:
    provenance_ref: str
    principal_id: str
    task_scope: str
    decision: RetrievalDecision
    reason: str
    at: str
    trust_tier: TrustTier | None
    promotion_state: PromotionState | None
    min_trust_required: TrustTier


@dataclass(frozen=True, slots=True)
class RetrievalVerdict:
    decision: RetrievalDecision
    reason: str
    auth: AuthorizationRecord | None
    audit: RetrievalAuditEvent

    @property
    def allowed(self) -> bool:
        return self.decision is RetrievalDecision.ALLOW


@dataclass(frozen=True, slots=True)
class ContextFragment:
    """Lesson text cleared for injection into agent context."""

    provenance_ref: str
    lesson: str
    trust_tier: TrustTier
    promotion_state: PromotionState | None
    decision_ref: str | None


class UnauthorizedContextError(PermissionError):
    """Raised when context injection is denied (fail-closed)."""

    def __init__(self, verdict: RetrievalVerdict) -> None:
        self.verdict = verdict
        super().__init__(
            f"context injection denied for {verdict.audit.provenance_ref!r}: "
            f"{verdict.reason}"
        )


class AuthorizationRegistry:
    """In-memory registry of read-side authorization records.

    Elevation above ``UNTRUSTED`` always requires a non-empty
    ``decision_ref`` (evidence of who/what authorized the trust).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, AuthorizationRecord] = {}

    def register(
        self,
        provenance_ref: str,
        *,
        author_principal: str,
        allowed_scopes: frozenset[str] | set[str],
        trust_tier: TrustTier = TrustTier.UNTRUSTED,
        decision_ref: str | None = None,
        expires_at: str | None = None,
    ) -> AuthorizationRecord:
        if not provenance_ref.strip():
            raise ValueError("provenance_ref is required")
        if not author_principal.strip():
            raise ValueError("author_principal is required")
        scopes = frozenset(s for s in allowed_scopes if s.strip())
        if not scopes:
            raise ValueError("allowed_scopes must be non-empty")
        if trust_tier is not TrustTier.UNTRUSTED and not (
            decision_ref and decision_ref.strip()
        ):
            raise ValueError(
                "elevating trust_tier above untrusted requires decision_ref"
            )
        if expires_at is not None:
            _parse_iso(expires_at)  # validate format early
        record = AuthorizationRecord(
            provenance_ref=provenance_ref,
            trust_tier=trust_tier,
            author_principal=author_principal,
            allowed_scopes=scopes,
            decision_ref=decision_ref.strip() if decision_ref else None,
            expires_at=expires_at,
        )
        with self._lock:
            if provenance_ref in self._records:
                raise ValueError(f"already registered: {provenance_ref}")
            self._records[provenance_ref] = record
        return record

    def set_trust_tier(
        self,
        provenance_ref: str,
        trust_tier: TrustTier,
        *,
        decision_ref: str,
    ) -> AuthorizationRecord:
        if not decision_ref.strip():
            raise ValueError("decision_ref is required to change trust_tier")
        with self._lock:
            current = self._require(provenance_ref)
            if current.is_revoked:
                raise ValueError("revoked entries cannot change trust_tier")
            updated = replace(
                current,
                trust_tier=trust_tier,
                decision_ref=decision_ref.strip(),
            )
            self._records[provenance_ref] = updated
            return updated

    def revoke(
        self,
        provenance_ref: str,
        *,
        revoked_by: str,
        reason: str,
    ) -> AuthorizationRecord:
        if not revoked_by.strip():
            raise ValueError("revoked_by is required")
        if not reason.strip():
            raise ValueError("reason is required")
        with self._lock:
            current = self._require(provenance_ref)
            if current.is_revoked:
                raise ValueError("entry already revoked")
            updated = replace(
                current,
                revoked_at=_utc_now_iso(),
                revoked_by=revoked_by.strip(),
                revoke_reason=reason.strip(),
            )
            self._records[provenance_ref] = updated
            return updated

    def get(self, provenance_ref: str) -> AuthorizationRecord | None:
        with self._lock:
            return self._records.get(provenance_ref)

    def _require(self, provenance_ref: str) -> AuthorizationRecord:
        record = self._records.get(provenance_ref)
        if record is None:
            raise ValueError(f"unknown provenance_ref: {provenance_ref!r}")
        return record


class RetrievalAuditor:
    """Append-only retrieval audit trail (never rewritten)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: list[RetrievalAuditEvent] = []

    def append(self, event: RetrievalAuditEvent) -> RetrievalAuditEvent:
        with self._lock:
            self._events.append(event)
            return event

    @property
    def events(self) -> tuple[RetrievalAuditEvent, ...]:
        with self._lock:
            return tuple(self._events)


class RetrievalGate:
    """Evaluate whether a principal may retrieve a memory entry.

    ``promotion_state`` is recorded for audit only — it never grants access.
    Unknown principals are denied. An empty ``PrincipalRegistry`` denies all.
    """

    def __init__(
        self,
        registry: AuthorizationRegistry,
        auditor: RetrievalAuditor | None = None,
        *,
        principals: PrincipalRegistry | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._registry = registry
        self._auditor = auditor if auditor is not None else RetrievalAuditor()
        self._principals = principals if principals is not None else PrincipalRegistry()
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def auditor(self) -> RetrievalAuditor:
        return self._auditor

    def evaluate(
        self,
        provenance_ref: str,
        principal: RetrievalPrincipal,
        *,
        promotion_state: PromotionState | None = None,
    ) -> RetrievalVerdict:
        auth: AuthorizationRecord | None = None
        try:
            auth = self._registry.get(provenance_ref)
            decision, reason = self._decide(auth, principal)
        except Exception:
            event = RetrievalAuditEvent(
                provenance_ref=provenance_ref,
                principal_id=getattr(principal, "principal_id", ""),
                task_scope=getattr(principal, "task_scope", ""),
                decision=RetrievalDecision.DENY,
                reason=DenyReason.EVALUATION_ERROR,
                at=_utc_now_iso(),
                trust_tier=auth.trust_tier if auth else None,
                promotion_state=promotion_state,
                min_trust_required=getattr(principal, "min_trust", TrustTier.UNTRUSTED),
            )
            self._auditor.append(event)
            raise
        event = RetrievalAuditEvent(
            provenance_ref=provenance_ref,
            principal_id=principal.principal_id,
            task_scope=principal.task_scope,
            decision=decision,
            reason=reason,
            at=_utc_now_iso(),
            trust_tier=auth.trust_tier if auth else None,
            promotion_state=promotion_state,
            min_trust_required=principal.min_trust,
        )
        self._auditor.append(event)
        return RetrievalVerdict(
            decision=decision,
            reason=reason,
            auth=auth,
            audit=event,
        )

    def _decide(
        self,
        auth: AuthorizationRecord | None,
        principal: RetrievalPrincipal,
    ) -> tuple[RetrievalDecision, str]:
        if not principal.principal_id.strip():
            return RetrievalDecision.DENY, DenyReason.EMPTY_PRINCIPAL
        if not principal.task_scope.strip():
            return RetrievalDecision.DENY, DenyReason.EMPTY_SCOPE
        if not self._principals.contains(principal.principal_id):
            return RetrievalDecision.DENY, DenyReason.UNKNOWN_PRINCIPAL
        if auth is None:
            return RetrievalDecision.DENY, DenyReason.UNKNOWN_ENTRY
        if auth.is_revoked:
            return RetrievalDecision.DENY, DenyReason.REVOKED
        if auth.expires_at is not None:
            if self._clock() >= _parse_iso(auth.expires_at):
                return RetrievalDecision.DENY, DenyReason.EXPIRED
        if principal.task_scope not in auth.allowed_scopes:
            return RetrievalDecision.DENY, DenyReason.SCOPE_DENIED
        if not trust_satisfies(auth.trust_tier, principal.min_trust):
            return RetrievalDecision.DENY, DenyReason.TRUST_INSUFFICIENT
        return RetrievalDecision.ALLOW, "authorized"


@dataclass(frozen=True, slots=True)
class InjectCandidate:
    provenance_ref: str
    lesson: str
    promotion_state: PromotionState | None = None


@dataclass(frozen=True, slots=True)
class InjectedContext:
    """Result of a context-injection attempt (only allowed fragments)."""

    fragments: tuple[ContextFragment, ...]
    denied: tuple[RetrievalVerdict, ...]


class ContextInjectionBoundary:
    """Fail-closed boundary between memory storage and agent context.

    Lesson text reaches agent context only through ``inject`` /
    ``inject_one``. Denied or expired entries are audited and omitted
    (batch) or raise (single). Lesson text is taken from the verified
    ledger by ``provenance_ref``; caller-supplied ``InjectCandidate.lesson``
    is never injected. Raw ledger reads are not a substitute.
    """

    def __init__(self, gate: RetrievalGate, ledger: Ledger) -> None:
        self._gate = gate
        self._ledger = ledger

    def _audit_deny(
        self,
        provenance_ref: str,
        principal: RetrievalPrincipal,
        reason: str,
        *,
        promotion_state: PromotionState | None,
        auth: AuthorizationRecord | None,
    ) -> RetrievalVerdict:
        event = RetrievalAuditEvent(
            provenance_ref=provenance_ref,
            principal_id=principal.principal_id,
            task_scope=principal.task_scope,
            decision=RetrievalDecision.DENY,
            reason=reason,
            at=_utc_now_iso(),
            trust_tier=auth.trust_tier if auth else None,
            promotion_state=promotion_state,
            min_trust_required=principal.min_trust,
        )
        self._gate.auditor.append(event)
        return RetrievalVerdict(
            decision=RetrievalDecision.DENY,
            reason=reason,
            auth=auth,
            audit=event,
        )

    def _lesson_from_ledger(
        self,
        provenance_ref: str,
        claimed_lesson: str,
        principal: RetrievalPrincipal,
        *,
        promotion_state: PromotionState | None,
        auth: AuthorizationRecord | None,
    ) -> tuple[str, RetrievalVerdict | None]:
        try:
            stored = self._ledger.record_for_provenance(provenance_ref)
        except HashChainIntegrityError:
            return "", self._audit_deny(
                provenance_ref,
                principal,
                DenyReason.UNKNOWN_ENTRY,
                promotion_state=promotion_state,
                auth=auth,
            )
        if stored is None:
            return "", self._audit_deny(
                provenance_ref,
                principal,
                DenyReason.UNKNOWN_ENTRY,
                promotion_state=promotion_state,
                auth=auth,
            )
        lesson = stored.entry.lesson
        if claimed_lesson != lesson:
            return "", self._audit_deny(
                provenance_ref,
                principal,
                DenyReason.LESSON_MISMATCH,
                promotion_state=promotion_state,
                auth=auth,
            )
        return lesson, None

    def inject_one(
        self,
        candidate: InjectCandidate,
        principal: RetrievalPrincipal,
    ) -> ContextFragment:
        verdict = self._gate.evaluate(
            candidate.provenance_ref,
            principal,
            promotion_state=candidate.promotion_state,
        )
        if not verdict.allowed or verdict.auth is None:
            raise UnauthorizedContextError(verdict)
        lesson, deny = self._lesson_from_ledger(
            candidate.provenance_ref,
            candidate.lesson,
            principal,
            promotion_state=candidate.promotion_state,
            auth=verdict.auth,
        )
        if deny is not None:
            raise UnauthorizedContextError(deny)
        return ContextFragment(
            provenance_ref=candidate.provenance_ref,
            lesson=lesson,
            trust_tier=verdict.auth.trust_tier,
            promotion_state=candidate.promotion_state,
            decision_ref=verdict.auth.decision_ref,
        )

    def inject(
        self,
        candidates: list[InjectCandidate] | tuple[InjectCandidate, ...],
        principal: RetrievalPrincipal,
        *,
        require_all: bool = False,
    ) -> InjectedContext:
        """Inject authorized candidates only.

        When ``require_all`` is True, any denial raises and no fragments
        are returned (strict fail-closed for a required set).
        """
        allowed: list[ContextFragment] = []
        denied: list[RetrievalVerdict] = []
        for candidate in candidates:
            verdict = self._gate.evaluate(
                candidate.provenance_ref,
                principal,
                promotion_state=candidate.promotion_state,
            )
            if not verdict.allowed or verdict.auth is None:
                denied.append(verdict)
                continue
            lesson, deny = self._lesson_from_ledger(
                candidate.provenance_ref,
                candidate.lesson,
                principal,
                promotion_state=candidate.promotion_state,
                auth=verdict.auth,
            )
            if deny is not None:
                denied.append(deny)
                continue
            allowed.append(
                ContextFragment(
                    provenance_ref=candidate.provenance_ref,
                    lesson=lesson,
                    trust_tier=verdict.auth.trust_tier,
                    promotion_state=candidate.promotion_state,
                    decision_ref=verdict.auth.decision_ref,
                )
            )
        if require_all and denied:
            raise UnauthorizedContextError(denied[0])
        return InjectedContext(fragments=tuple(allowed), denied=tuple(denied))
