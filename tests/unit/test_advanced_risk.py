from __future__ import annotations

import hashlib
from dataclasses import fields, replace
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal, localcontext
from typing import Any

import pytest

from packages.domain.advanced_risk import (
    ADVANCED_RISK_CONTRACT_VERSION,
    MAX_ADVANCED_RISK_RULES,
    MAX_ADVANCED_RISK_SOURCES,
    AdvancedRiskEffect,
    AdvancedRiskError,
    AdvancedRiskEvaluationGate,
    AdvancedRiskEvidenceBundle,
    AdvancedRiskEvidenceSource,
    AdvancedRiskFactConflict,
    AdvancedRiskObservationCompleteness,
    AdvancedRiskPolicyCandidate,
    AdvancedRiskPolicyReadiness,
    AdvancedRiskPolicyUnapproved,
    AdvancedRiskRuleBinding,
    AdvancedRiskRuleKind,
    AdvancedRiskRuleObservation,
    assess_advanced_risk_policy,
    bind_advanced_risk_evidence,
    require_activated_advanced_risk_policy,
)
from packages.domain.batch_risk import BATCH_RISK_CONTRACT_VERSION, BATCH_RISK_RULES
from packages.domain.operational_control import OPERATIONAL_CONTROL_POLICY_SHA256

NOW = datetime(2026, 7, 28, 15, 0, tzinfo=UTC)
WINDOW_START = NOW - timedelta(hours=1)
PROPOSED_AT = WINDOW_START - timedelta(hours=1)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def rule(
    *,
    rule_id: str = "01-session-loss",
    kind: AdvancedRiskRuleKind = AdvancedRiskRuleKind.SESSION_LOSS,
) -> AdvancedRiskRuleBinding:
    return AdvancedRiskRuleBinding(
        rule_id=rule_id,
        kind=kind,
        calculator_id=f"{kind.value}-calculator",
        calculator_version="candidate-v1",
        calculator_sha256=digest(f"{kind.value}-calculator"),
        source_schema_id=f"{kind.value}-sources",
        source_schema_version="candidate-v1",
        source_schema_sha256=digest(f"{kind.value}-sources"),
        measurement_scope="account-session",
        measurement_unit="unapproved-unit",
    )


def candidate(
    *rules: AdvancedRiskRuleBinding,
) -> AdvancedRiskPolicyCandidate:
    selected = rules or (rule(),)
    return AdvancedRiskPolicyCandidate(
        policy_id="advanced-risk-paper-candidate",
        policy_version="candidate-v1",
        environment="paper",
        scope_profile_id="rth-long-only-us-etf-candidate",
        scope_profile_sha256=digest("scope"),
        rules=tuple(selected),
        proposed_at=PROPOSED_AT,
    )


def source(index: int = 0) -> AdvancedRiskEvidenceSource:
    effective_at = WINDOW_START + timedelta(seconds=index)
    return AdvancedRiskEvidenceSource(
        source_kind="account-projection",
        source_id=f"source-{index:04d}",
        source_sha256=digest(f"source-{index}"),
        effective_at=effective_at,
        available_at=effective_at,
    )


def observation(
    binding: AdvancedRiskRuleBinding | None = None,
    *,
    account_id: str = "paper-account",
    idempotency_key: str = "observe-0001",
    value: Decimal = Decimal("1.25"),
    sources: tuple[AdvancedRiskEvidenceSource, ...] = (source(),),
) -> AdvancedRiskRuleObservation:
    selected_rule = binding or rule()
    return AdvancedRiskRuleObservation(
        account_id=account_id,
        environment="paper",
        idempotency_key=idempotency_key,
        rule=selected_rule,
        producer_id="advanced-risk-observer",
        producer_version="candidate-v1",
        producer_authority_sha256=digest("observer-authority"),
        window_started_at=WINDOW_START,
        window_ended_at=NOW,
        observed_at=NOW,
        recorded_at=NOW + timedelta(seconds=1),
        completeness=AdvancedRiskObservationCompleteness.COMPLETE,
        value=value,
        incomplete_reason=None,
        sources=sources,
        source_count=len(sources),
    )


def test_observe_only_contract_is_separate_and_explicitly_non_authorizing() -> None:
    bindings = (
        rule(),
        rule(
            rule_id="02-session-drawdown",
            kind=AdvancedRiskRuleKind.SESSION_DRAWDOWN,
        ),
    )
    proposal = candidate(*bindings)
    gate = assess_advanced_risk_policy(
        proposal,
        assessed_at=PROPOSED_AT + timedelta(seconds=1),
    )

    assert ADVANCED_RISK_CONTRACT_VERSION == "phase5b-advanced-risk-observe-only-v1"
    assert proposal.owner_approved is False
    assert proposal.missing_rule_kinds == tuple(
        kind
        for kind in AdvancedRiskRuleKind
        if kind
        not in {
            AdvancedRiskRuleKind.SESSION_LOSS,
            AdvancedRiskRuleKind.SESSION_DRAWDOWN,
        }
    )
    assert gate == AdvancedRiskEvaluationGate(
        policy_candidate_id=proposal.candidate_id,
        policy_candidate_sha256=proposal.semantic_sha256,
        assessed_at=PROPOSED_AT + timedelta(seconds=1),
        readiness=AdvancedRiskPolicyReadiness.OWNER_APPROVAL_REQUIRED,
        missing_rule_kinds=proposal.missing_rule_kinds,
    )
    assert gate.can_evaluate is False
    for value in (*bindings, proposal, gate):
        assert value.trading_effect is AdvancedRiskEffect.NONE
        assert value.control_effect is AdvancedRiskEffect.NONE
        assert value.activation_effect is AdvancedRiskEffect.NONE

    with pytest.raises(AdvancedRiskPolicyUnapproved, match="no owner activation"):
        require_activated_advanced_risk_policy(proposal)


def test_rule_families_match_the_plan_without_threshold_or_action_fields() -> None:
    assert tuple(AdvancedRiskRuleKind) == (
        AdvancedRiskRuleKind.SESSION_LOSS,
        AdvancedRiskRuleKind.SESSION_DRAWDOWN,
        AdvancedRiskRuleKind.CONCENTRATION,
        AdvancedRiskRuleKind.LEVERAGE,
        AdvancedRiskRuleKind.VOLATILITY,
        AdvancedRiskRuleKind.SPREAD,
        AdvancedRiskRuleKind.SLIPPAGE,
        AdvancedRiskRuleKind.BROKER_REJECT_RATE,
        AdvancedRiskRuleKind.BROKER_RATE_LIMIT,
        AdvancedRiskRuleKind.CLOCK_HEALTH,
        AdvancedRiskRuleKind.DATA_HEALTH,
        AdvancedRiskRuleKind.UNKNOWN_DURATION,
        AdvancedRiskRuleKind.RECONCILIATION_DURATION,
    )
    forbidden = {
        "passed",
        "approved",
        "enabled",
        "threshold",
        "comparator",
        "target_state",
        "trip",
        "authorization",
    }
    for contract in (
        AdvancedRiskRuleBinding,
        AdvancedRiskPolicyCandidate,
        AdvancedRiskRuleObservation,
        AdvancedRiskEvidenceBundle,
    ):
        assert forbidden.isdisjoint(field.name for field in fields(contract))


@pytest.mark.parametrize(
    ("replacement", "message"),
    (
        ({"rule_id": " trim "}, "trimmed"),
        ({"kind": "session_loss"}, "kind"),
        ({"calculator_sha256": "f" * 63}, "SHA-256"),
        ({"measurement_unit": "bad\nunit"}, "unsupported text"),
    ),
)
def test_rule_binding_rejects_malformed_proposals(
    replacement: dict[str, Any],
    message: str,
) -> None:
    with pytest.raises(AdvancedRiskError, match=message):
        replace(rule(), **replacement)


def test_policy_candidate_requires_bounded_canonical_unique_rules() -> None:
    loss = rule()
    drawdown = rule(
        rule_id="02-session-drawdown",
        kind=AdvancedRiskRuleKind.SESSION_DRAWDOWN,
    )
    proposal = candidate(loss, drawdown)

    assert proposal == candidate(loss, drawdown)
    assert proposal.semantic_sha256 == candidate(loss, drawdown).semantic_sha256
    assert len(proposal.candidate_id) == 36

    with pytest.raises(AdvancedRiskError, match="canonically ordered"):
        candidate(drawdown, loss)
    with pytest.raises(AdvancedRiskFactConflict, match="rule ID"):
        candidate(loss, replace(drawdown, rule_id=loss.rule_id))
    with pytest.raises(AdvancedRiskFactConflict, match="rule kind"):
        candidate(loss, replace(drawdown, kind=loss.kind))
    with pytest.raises(AdvancedRiskError, match="non-empty"):
        replace(proposal, rules=())
    with pytest.raises(AdvancedRiskError, match="rule bound"):
        replace(
            proposal,
            rules=tuple(
                replace(
                    loss,
                    rule_id=f"rule-{index:03d}",
                    kind=list(AdvancedRiskRuleKind)[index % len(AdvancedRiskRuleKind)],
                )
                for index in range(MAX_ADVANCED_RISK_RULES + 1)
            ),
        )
    with pytest.raises(AdvancedRiskError, match="UTC"):
        replace(proposal, proposed_at=PROPOSED_AT.replace(tzinfo=timezone(timedelta(hours=1))))


def test_source_reference_is_exact_and_causal() -> None:
    retained = source()

    assert retained == source()
    assert len(retained.semantic_sha256) == 64
    with pytest.raises(AdvancedRiskError, match="availability"):
        replace(retained, available_at=retained.effective_at - timedelta(microseconds=1))
    with pytest.raises(AdvancedRiskError, match="SHA-256"):
        replace(retained, source_sha256="not-a-digest")
    with pytest.raises(AdvancedRiskError, match="timezone-aware"):
        replace(retained, effective_at=retained.effective_at.replace(tzinfo=None))


def test_complete_observation_binds_exact_value_sources_and_identity() -> None:
    retained = observation(value=Decimal("1.2500000000"))
    changed = replace(retained, value=Decimal("1.26"))

    assert retained.value == Decimal("1.25")
    assert retained.observation_id == changed.observation_id
    assert retained.semantic_sha256 != changed.semantic_sha256
    assert retained.source_set_sha256 == observation().source_set_sha256
    assert retained.trading_effect is AdvancedRiskEffect.NONE
    assert retained.control_effect is AdvancedRiskEffect.NONE
    assert retained.activation_effect is AdvancedRiskEffect.NONE

    with pytest.raises(AdvancedRiskError, match="requires an exact value"):
        replace(retained, value=None)
    with pytest.raises(AdvancedRiskError, match="incomplete reason"):
        replace(retained, incomplete_reason="not actually complete")
    with pytest.raises(AdvancedRiskError, match="every retained source"):
        replace(retained, source_count=2)
    with pytest.raises(AdvancedRiskError, match="finite exact Decimal"):
        replace(retained, value=1.25)  # type: ignore[arg-type]
    with pytest.raises(AdvancedRiskError, match="NUMERIC"):
        replace(retained, value=Decimal("1000000000000000000"))
    with pytest.raises(AdvancedRiskError, match="NUMERIC"):
        replace(retained, value=Decimal("0.00000000001"))


@pytest.mark.parametrize(
    "completeness",
    (
        AdvancedRiskObservationCompleteness.INSUFFICIENT,
        AdvancedRiskObservationCompleteness.UNAVAILABLE,
    ),
)
def test_incomplete_observation_is_explicit_and_cannot_carry_a_value(
    completeness: AdvancedRiskObservationCompleteness,
) -> None:
    incomplete = replace(
        observation(),
        completeness=completeness,
        value=None,
        incomplete_reason="authoritative source is unavailable",
    )

    assert incomplete.value is None
    assert incomplete.source_count == 1
    with pytest.raises(AdvancedRiskError, match="cannot carry a value"):
        replace(incomplete, value=Decimal("0"))
    with pytest.raises(AdvancedRiskError, match="incomplete reason"):
        replace(incomplete, incomplete_reason=None)
    with pytest.raises(AdvancedRiskError, match="source_count"):
        replace(incomplete, source_count=2)


def test_overflow_is_sticky_structural_incompleteness_not_a_measurement() -> None:
    retained_sources = tuple(source(index) for index in range(MAX_ADVANCED_RISK_SOURCES))
    overflowed = replace(
        observation(sources=retained_sources),
        completeness=AdvancedRiskObservationCompleteness.OVERFLOWED,
        value=None,
        incomplete_reason="source window exceeded retained membership bound",
        source_count=MAX_ADVANCED_RISK_SOURCES + 1,
        overflow_source_set_sha256=digest("full-overflow-source-set"),
    )

    assert overflowed.value is None
    assert overflowed.source_set_sha256 == digest("full-overflow-source-set")
    assert overflowed.trading_effect is AdvancedRiskEffect.NONE
    with pytest.raises(AdvancedRiskError, match="bounded prefix"):
        replace(overflowed, sources=overflowed.sources[:-1])
    with pytest.raises(AdvancedRiskError, match="SHA-256"):
        replace(overflowed, overflow_source_set_sha256=None)


def test_observation_rejects_noncausal_duplicate_or_misordered_sources() -> None:
    first = source()
    second = source(1)
    retained = observation(sources=(first, second))

    with pytest.raises(AdvancedRiskError, match="canonically ordered"):
        replace(retained, sources=(second, first))
    with pytest.raises(AdvancedRiskFactConflict, match="repeats a source"):
        replace(retained, sources=(first, first))
    with pytest.raises(AdvancedRiskFactConflict, match="causal window"):
        replace(
            retained,
            sources=(replace(first, effective_at=WINDOW_START - timedelta(seconds=1)),),
            source_count=1,
        )
    with pytest.raises(AdvancedRiskError, match="chronology"):
        replace(retained, observed_at=NOW - timedelta(microseconds=1))
    with pytest.raises(AdvancedRiskError, match="safe visible"):
        replace(retained, idempotency_key="short")


def test_structurally_complete_bundle_still_has_no_policy_effect() -> None:
    loss = rule()
    drawdown = rule(
        rule_id="02-session-drawdown",
        kind=AdvancedRiskRuleKind.SESSION_DRAWDOWN,
    )
    proposal = candidate(loss, drawdown)
    observations = (
        observation(loss, idempotency_key="observe-loss-0001"),
        observation(drawdown, idempotency_key="observe-drawdown-0001"),
    )
    bundle = bind_advanced_risk_evidence(
        account_id="paper-account",
        environment="paper",
        policy_candidate=proposal,
        observations=observations,
        bound_at=NOW + timedelta(seconds=2),
    )

    assert isinstance(bundle, AdvancedRiskEvidenceBundle)
    assert len(bundle.bundle_id) == 36
    assert len(bundle.semantic_sha256) == 64
    assert bundle.trading_effect is AdvancedRiskEffect.NONE
    assert bundle.control_effect is AdvancedRiskEffect.NONE
    assert bundle.activation_effect is AdvancedRiskEffect.NONE

    with pytest.raises(AdvancedRiskFactConflict, match="exactly one"):
        replace(bundle, observations=observations[:1])
    with pytest.raises(AdvancedRiskError, match="observations must be exact"):
        replace(bundle, observations=("not-an-observation", observations[1]))  # type: ignore[arg-type]
    with pytest.raises(AdvancedRiskError, match="canonically ordered"):
        replace(bundle, observations=tuple(reversed(observations)))
    with pytest.raises(AdvancedRiskFactConflict, match="idempotency identity"):
        replace(
            bundle,
            observations=(
                observations[0],
                replace(
                    observations[1],
                    producer_id=observations[0].producer_id,
                    idempotency_key=observations[0].idempotency_key,
                ),
            ),
        )
    with pytest.raises(AdvancedRiskFactConflict, match="scope or rule"):
        replace(
            bundle,
            observations=(
                replace(observations[0], account_id="other-account"),
                observations[1],
            ),
        )
    with pytest.raises(AdvancedRiskError, match="structurally complete"):
        replace(
            bundle,
            observations=(
                replace(
                    observations[0],
                    completeness=AdvancedRiskObservationCompleteness.UNAVAILABLE,
                    value=None,
                    incomplete_reason="missing source",
                ),
                observations[1],
            ),
        )
    with pytest.raises(AdvancedRiskFactConflict, match="predates"):
        replace(bundle, bound_at=NOW)
    with pytest.raises(AdvancedRiskFactConflict, match="policy candidate"):
        replace(bundle, bound_at=PROPOSED_AT - timedelta(microseconds=1))


def test_decimal_canonicalization_is_independent_of_ambient_context() -> None:
    maximum = Decimal("999999999999999999.9999999999")
    with localcontext() as context:
        context.prec = 6
        low_context = observation(value=maximum)
    with localcontext() as context:
        context.prec = 60
        high_context = observation(value=maximum)

    assert low_context.value == maximum
    assert low_context.canonical_json == high_context.canonical_json
    assert low_context.semantic_sha256 == high_context.semantic_sha256


def test_policy_gate_rejects_wrong_type_time_and_fabricated_readiness() -> None:
    proposal = candidate()

    with pytest.raises(AdvancedRiskError, match="exact candidate"):
        assess_advanced_risk_policy("candidate", assessed_at=NOW)  # type: ignore[arg-type]
    with pytest.raises(AdvancedRiskError, match="cannot predate"):
        assess_advanced_risk_policy(
            proposal,
            assessed_at=PROPOSED_AT - timedelta(microseconds=1),
        )
    with pytest.raises(AdvancedRiskError, match="unsupported"):
        AdvancedRiskEvaluationGate(
            policy_candidate_id=proposal.candidate_id,
            policy_candidate_sha256=proposal.semantic_sha256,
            assessed_at=NOW,
            readiness="ready",  # type: ignore[arg-type]
            missing_rule_kinds=proposal.missing_rule_kinds,
        )
    with pytest.raises(AdvancedRiskError, match="canonically ordered"):
        AdvancedRiskEvaluationGate(
            policy_candidate_id=proposal.candidate_id,
            policy_candidate_sha256=proposal.semantic_sha256,
            assessed_at=NOW,
            readiness=AdvancedRiskPolicyReadiness.OWNER_APPROVAL_REQUIRED,
            missing_rule_kinds=tuple(reversed(proposal.missing_rule_kinds)),
        )
    with pytest.raises(AdvancedRiskError, match="exact rule kinds"):
        AdvancedRiskEvaluationGate(
            policy_candidate_id=proposal.candidate_id,
            policy_candidate_sha256=proposal.semantic_sha256,
            assessed_at=NOW,
            readiness=AdvancedRiskPolicyReadiness.OWNER_APPROVAL_REQUIRED,
            missing_rule_kinds=([],),  # type: ignore[arg-type]
        )


def test_legacy_batch_risk_and_phase5a_digests_remain_pinned() -> None:
    assert BATCH_RISK_CONTRACT_VERSION == "phase2-atomic-batch-risk-v2"
    assert BATCH_RISK_RULES == (
        "operational_state",
        "active_instrument",
        "instrument_allow_list",
        "instrument_halt",
        "session",
        "snapshot_freshness",
        "reference_price_freshness",
        "intent_freshness",
        "quantity",
        "order_notional",
        "batch_notional",
        "cash_buffer",
        "sell_capacity",
        "instrument_gross_exposure",
        "account_gross_exposure",
        "daily_order_count",
        "open_order_count",
    )
    assert (
        OPERATIONAL_CONTROL_POLICY_SHA256
        == "2f977287c78f590335b6176e67967d23cb55d22ad88ba6b09a40c4cdcf70759e"
    )
