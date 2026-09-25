"""PR4 read-side retrieval authorization: trust, expiry, audit, injection."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from anamnesis import (
    AuthorizationRegistry,
    ContextInjectionBoundary,
    InjectCandidate,
    PromotionState,
    RetrievalGate,
    RetrievalPrincipal,
    TrustTier,
    UnauthorizedContextError,
)
from anamnesis.retrieval import DenyReason, RetrievalDecision


def _principal(
    *,
    principal_id: str = "agent-runner",
    task_scope: str = "general",
    min_trust: TrustTier = TrustTier.UNTRUSTED,
) -> RetrievalPrincipal:
    return RetrievalPrincipal(
        principal_id=principal_id,
        task_scope=task_scope,
        min_trust=min_trust,
    )


def _register(
    registry: AuthorizationRegistry,
    provenance_ref: str = "prov:1",
    **kwargs,
):
    defaults = dict(
        author_principal="author-1",
        allowed_scopes=frozenset({"general", "ops"}),
        trust_tier=TrustTier.UNTRUSTED,
    )
    defaults.update(kwargs)
    return registry.register(provenance_ref, **defaults)


# --- Trust tier orthogonal to lifecycle ------------------------------------


def test_trust_tier_independent_of_graduated_lifecycle():
    """Graduated + UNTRUSTED must still deny a VERIFIED-min request."""
    registry = AuthorizationRegistry()
    _register(registry, "prov:grad-untrusted", trust_tier=TrustTier.UNTRUSTED)
    gate = RetrievalGate(registry)
    principal = _principal(min_trust=TrustTier.VERIFIED)

    verdict = gate.evaluate(
        "prov:grad-untrusted",
        principal,
        promotion_state=PromotionState.GRADUATED,
    )

    assert verdict.decision is RetrievalDecision.DENY
    assert verdict.reason == DenyReason.TRUST_INSUFFICIENT
    assert verdict.audit.promotion_state is PromotionState.GRADUATED
    assert verdict.audit.trust_tier is TrustTier.UNTRUSTED


def test_candidate_with_verified_trust_can_pass_when_evidence_present():
    registry = AuthorizationRegistry()
    _register(
        registry,
        "prov:cand-verified",
        trust_tier=TrustTier.VERIFIED,
        decision_ref="dec-trust-1",
    )
    gate = RetrievalGate(registry)
    verdict = gate.evaluate(
        "prov:cand-verified",
        _principal(min_trust=TrustTier.VERIFIED),
        promotion_state=PromotionState.CANDIDATE,
    )
    assert verdict.allowed is True
    assert verdict.audit.promotion_state is PromotionState.CANDIDATE


def test_elevating_trust_without_decision_ref_fails():
    registry = AuthorizationRegistry()
    with pytest.raises(ValueError, match="decision_ref"):
        registry.register(
            "prov:x",
            author_principal="a",
            allowed_scopes=frozenset({"general"}),
            trust_tier=TrustTier.INTERNAL,
            decision_ref=None,
        )


def test_set_trust_tier_requires_decision_ref():
    registry = AuthorizationRegistry()
    _register(registry, "prov:elevate")
    with pytest.raises(ValueError, match="decision_ref"):
        registry.set_trust_tier("prov:elevate", TrustTier.VERIFIED, decision_ref="  ")
    updated = registry.set_trust_tier(
        "prov:elevate", TrustTier.VERIFIED, decision_ref="dec-2"
    )
    assert updated.trust_tier is TrustTier.VERIFIED
    assert updated.decision_ref == "dec-2"


# --- Expiry / revocation ---------------------------------------------------


def test_expired_entry_denied_even_if_verified_and_graduated():
    registry = AuthorizationRegistry()
    past = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    _register(
        registry,
        "prov:expired",
        trust_tier=TrustTier.VERIFIED,
        decision_ref="dec-e",
        expires_at=past,
    )
    gate = RetrievalGate(registry)
    verdict = gate.evaluate(
        "prov:expired",
        _principal(min_trust=TrustTier.VERIFIED),
        promotion_state=PromotionState.GRADUATED,
    )
    assert verdict.decision is RetrievalDecision.DENY
    assert verdict.reason == DenyReason.EXPIRED


def test_not_yet_expired_entry_allowed(monkeypatch: pytest.MonkeyPatch):
    registry = AuthorizationRegistry()
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    _register(
        registry,
        "prov:fresh",
        trust_tier=TrustTier.INTERNAL,
        decision_ref="dec-f",
        expires_at=future,
    )
    fixed_now = datetime.now(UTC)
    gate = RetrievalGate(registry, clock=lambda: fixed_now)
    assert gate.evaluate("prov:fresh", _principal(min_trust=TrustTier.INTERNAL)).allowed


def test_exact_expiry_boundary_is_denied():
    """At expires_at exactly, entry is expired (fail closed)."""
    registry = AuthorizationRegistry()
    boundary = datetime(2026, 9, 25, 12, 0, 0, tzinfo=UTC)
    _register(
        registry,
        "prov:boundary",
        trust_tier=TrustTier.INTERNAL,
        decision_ref="dec-b",
        expires_at=boundary.isoformat(),
    )
    gate = RetrievalGate(registry, clock=lambda: boundary)
    verdict = gate.evaluate("prov:boundary", _principal(min_trust=TrustTier.INTERNAL))
    assert verdict.reason == DenyReason.EXPIRED


def test_revoked_entry_denied_and_cannot_retrust():
    registry = AuthorizationRegistry()
    _register(
        registry,
        "prov:rev",
        trust_tier=TrustTier.VERIFIED,
        decision_ref="dec-r",
    )
    registry.revoke("prov:rev", revoked_by="operator", reason="poisoned")
    gate = RetrievalGate(registry)
    verdict = gate.evaluate("prov:rev", _principal(min_trust=TrustTier.UNTRUSTED))
    assert verdict.reason == DenyReason.REVOKED
    with pytest.raises(ValueError, match="revoked"):
        registry.set_trust_tier("prov:rev", TrustTier.VERIFIED, decision_ref="dec-retry")


# --- Scope / unknown / principal validation --------------------------------


def test_scope_mismatch_denied():
    registry = AuthorizationRegistry()
    _register(registry, "prov:scope", allowed_scopes=frozenset({"ops"}))
    gate = RetrievalGate(registry)
    verdict = gate.evaluate("prov:scope", _principal(task_scope="security"))
    assert verdict.reason == DenyReason.SCOPE_DENIED


def test_unknown_provenance_denied():
    gate = RetrievalGate(AuthorizationRegistry())
    verdict = gate.evaluate("prov:missing", _principal())
    assert verdict.reason == DenyReason.UNKNOWN_ENTRY


def test_empty_principal_rejected_at_construction():
    with pytest.raises(ValueError, match="principal_id"):
        RetrievalPrincipal(principal_id=" ", task_scope="general")
    with pytest.raises(ValueError, match="task_scope"):
        RetrievalPrincipal(principal_id="a", task_scope="")


# --- Retrieval audit trail -------------------------------------------------


def test_every_evaluate_appends_audit_including_denials():
    registry = AuthorizationRegistry()
    _register(registry, "prov:audit")
    gate = RetrievalGate(registry)

    gate.evaluate("prov:audit", _principal())
    gate.evaluate("prov:missing", _principal())

    events = gate.auditor.events
    assert len(events) == 2
    assert events[0].decision is RetrievalDecision.ALLOW
    assert events[1].decision is RetrievalDecision.DENY
    assert events[1].reason == DenyReason.UNKNOWN_ENTRY
    # audit trail is append-only: prior event unchanged
    assert events[0].provenance_ref == "prov:audit"


# --- Context-injection boundary (fail closed) ------------------------------


def test_inject_one_raises_on_unauthorized_and_exposes_no_lesson():
    registry = AuthorizationRegistry()
    _register(registry, "prov:secret", trust_tier=TrustTier.UNTRUSTED)
    boundary = ContextInjectionBoundary(RetrievalGate(registry))
    candidate = InjectCandidate(
        provenance_ref="prov:secret",
        lesson="SECRET_LESSON_SHOULD_NOT_LEAK",
        promotion_state=PromotionState.GRADUATED,
    )
    with pytest.raises(UnauthorizedContextError, match="trust_insufficient") as exc:
        boundary.inject_one(
            candidate,
            _principal(min_trust=TrustTier.VERIFIED),
        )
    assert "SECRET_LESSON_SHOULD_NOT_LEAK" not in str(exc.value)
    assert exc.value.verdict.reason == DenyReason.TRUST_INSUFFICIENT


def test_inject_one_returns_fragment_when_authorized():
    registry = AuthorizationRegistry()
    _register(
        registry,
        "prov:ok",
        trust_tier=TrustTier.INTERNAL,
        decision_ref="dec-ok",
    )
    boundary = ContextInjectionBoundary(RetrievalGate(registry))
    frag = boundary.inject_one(
        InjectCandidate(provenance_ref="prov:ok", lesson="safe lesson"),
        _principal(min_trust=TrustTier.INTERNAL),
    )
    assert frag.lesson == "safe lesson"
    assert frag.trust_tier is TrustTier.INTERNAL
    assert frag.decision_ref == "dec-ok"


def test_inject_batch_omits_denied_and_audits_them():
    registry = AuthorizationRegistry()
    _register(
        registry,
        "prov:a",
        trust_tier=TrustTier.INTERNAL,
        decision_ref="dec-a",
    )
    _register(registry, "prov:b", trust_tier=TrustTier.UNTRUSTED)
    gate = RetrievalGate(registry)
    boundary = ContextInjectionBoundary(gate)

    result = boundary.inject(
        [
            InjectCandidate(provenance_ref="prov:a", lesson="A"),
            InjectCandidate(provenance_ref="prov:b", lesson="B-SECRET"),
            InjectCandidate(provenance_ref="prov:gone", lesson="GHOST"),
        ],
        _principal(min_trust=TrustTier.INTERNAL),
    )

    assert [f.lesson for f in result.fragments] == ["A"]
    assert all("SECRET" not in f.lesson for f in result.fragments)
    assert len(result.denied) == 2
    assert {d.reason for d in result.denied} == {
        DenyReason.TRUST_INSUFFICIENT,
        DenyReason.UNKNOWN_ENTRY,
    }
    assert len(gate.auditor.events) == 3


def test_inject_require_all_fails_closed_with_zero_fragments():
    registry = AuthorizationRegistry()
    _register(
        registry,
        "prov:a",
        trust_tier=TrustTier.INTERNAL,
        decision_ref="dec-a",
    )
    _register(registry, "prov:b", trust_tier=TrustTier.UNTRUSTED)
    boundary = ContextInjectionBoundary(RetrievalGate(registry))
    with pytest.raises(UnauthorizedContextError):
        boundary.inject(
            [
                InjectCandidate(provenance_ref="prov:a", lesson="A"),
                InjectCandidate(provenance_ref="prov:b", lesson="B"),
            ],
            _principal(min_trust=TrustTier.INTERNAL),
            require_all=True,
        )


def test_adversarial_expired_injection_fails_closed():
    registry = AuthorizationRegistry()
    past = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
    _register(
        registry,
        "prov:poison",
        trust_tier=TrustTier.VERIFIED,
        decision_ref="dec-p",
        expires_at=past,
    )
    boundary = ContextInjectionBoundary(RetrievalGate(registry))
    with pytest.raises(UnauthorizedContextError) as exc:
        boundary.inject_one(
            InjectCandidate(
                provenance_ref="prov:poison",
                lesson="expired-but-verified-payload",
                promotion_state=PromotionState.GRADUATED,
            ),
            _principal(min_trust=TrustTier.VERIFIED),
        )
    assert exc.value.verdict.reason == DenyReason.EXPIRED


def test_adversarial_revoked_injection_fails_closed():
    registry = AuthorizationRegistry()
    _register(
        registry,
        "prov:revoked-inj",
        trust_tier=TrustTier.VERIFIED,
        decision_ref="dec-ri",
    )
    registry.revoke("prov:revoked-inj", revoked_by="secops", reason="t1-poison")
    boundary = ContextInjectionBoundary(RetrievalGate(registry))
    with pytest.raises(UnauthorizedContextError) as exc:
        boundary.inject_one(
            InjectCandidate(
                provenance_ref="prov:revoked-inj",
                lesson="should-not-reach-context",
            ),
            _principal(),
        )
    assert exc.value.verdict.reason == DenyReason.REVOKED
