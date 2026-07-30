from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from typing import cast

import pytest

from packages.adapters.broker.alpaca_paper_inbox import (
    AlpacaPaperInboxConflict,
    AlpacaPaperInboxError,
    create_alpaca_paper_inbox_admission_request,
)
from packages.adapters.broker.alpaca_paper_reconciliation import (
    normalize_authenticated_alpaca_paper_lookup,
)
from packages.domain.broker_inbox import (
    BROKER_INBOX_IDENTITY_PROFILE_ID,
    BROKER_INBOX_IDENTITY_PROFILE_SHA256,
    BROKER_INBOX_NON_APPLICATION_POLICY_ID,
    BROKER_INBOX_NON_APPLICATION_POLICY_SHA256,
    BrokerInboxAdmissionBundle,
    BrokerInboxAdmissionRequest,
    BrokerInboxConflict,
    BrokerInboxDisposition,
    BrokerInboxNonApplicationDecisionReceipt,
    _broker_inbox_admission_request,
    _broker_inbox_non_application_decision,
    decide_broker_inbox_admission,
)
from packages.domain.broker_reconciliation import (
    BrokerReconciliationFact,
    _broker_reconciliation_fact,
)
from tests.unit.test_alpaca_paper_lookup_runtime import (
    LookupScenario,
    LookupTransport,
    _body_override,
    _fixture,
    _scenario,
)

_AUTHORITY_PROPERTIES = (
    "provider_revision_identity_qualified",
    "provider_deduplication_authorized",
    "normalized_fact_authorized",
    "inbox_application_authorized",
    "lifecycle_application_authorized",
    "reconciliation_application_authorized",
    "unknown_resolution_authorized",
    "resubmission_authorized",
    "reservation_release_authorized",
    "canonical_execution_fact_authorized",
    "transport_authorized",
    "broker_call_authorized",
    "trading_effect_authorized",
)


def _fact(
    scenario: LookupScenario,
    *,
    delivery_idempotency_key: str = "phase4l-delivery-001",
) -> BrokerReconciliationFact:
    receipt = scenario.run(
        delivery_idempotency_key=delivery_idempotency_key,
    )
    evidence = normalize_authenticated_alpaca_paper_lookup(
        receipt,
        scenario.lookups.evidence[-1].persisted_observation,
    )
    return _broker_reconciliation_fact(
        evidence,
        normalized_at=receipt.commit_checked_at,
        account_sequence=1,
        previous_fact_sha256=None,
    )


@pytest.mark.parametrize(
    ("status", "body", "expected_disposition"),
    (
        (
            200,
            _fixture("lookup_found.json"),
            BrokerInboxDisposition.WITHHELD_UNQUALIFIED_REVISION_IDENTITY,
        ),
        (
            200,
            _body_override(qty="11"),
            BrokerInboxDisposition.QUARANTINED_ECONOMIC_MISMATCH,
        ),
        (
            200,
            _body_override(asset_id=None),
            BrokerInboxDisposition.QUARANTINED_SECURITY_MISMATCH,
        ),
        (
            404,
            _fixture("lookup_not_found.json"),
            BrokerInboxDisposition.INCONCLUSIVE_NOT_VISIBLE,
        ),
    ),
)
def test_phase4k_outcomes_map_to_closed_non_application_decisions(
    status: int,
    body: bytes,
    expected_disposition: BrokerInboxDisposition,
) -> None:
    fact = _fact(
        _scenario(
            transport=LookupTransport(
                status=status,
                body=body,
            )
        )
    )

    request = create_alpaca_paper_inbox_admission_request(fact)
    decided_at = fact.normalized_at + timedelta(seconds=1)
    decision = decide_broker_inbox_admission(
        request,
        decided_at=decided_at,
    )
    bundle = BrokerInboxAdmissionBundle(request=request, decision=decision)

    assert decision.disposition is expected_disposition
    assert decision.decided_at == decided_at
    assert decision.application_withheld is True
    assert bundle.decision == decision
    assert len(request.identity.observation_id) == 36
    assert len(request.request_id) == 36
    assert len(decision.decision_id) == 36
    for value in (request.identity, request, decision, bundle):
        for property_name in _AUTHORITY_PROPERTIES:
            assert getattr(value, property_name) is False


def test_request_preserves_exact_phase4k_payload_digest_and_lineage() -> None:
    fact = _fact(_scenario())

    request = create_alpaca_paper_inbox_admission_request(fact)
    identity = request.identity
    evidence = fact.evidence

    assert request.source_fact is fact
    assert request.source_evidence is evidence
    assert request.source_evidence_sha256 == evidence.semantic_sha256
    assert request.source_evidence_payload == evidence._semantic_material()
    assert identity.source_reconciliation_fact_id == fact.fact_id
    assert identity.source_reconciliation_fact_sha256 == fact.semantic_sha256
    assert identity.source_lookup_receipt_id == evidence.source_lookup_receipt_id
    assert identity.source_lookup_receipt_sha256 == evidence.source_lookup_receipt_sha256
    assert identity.source_ingress_receipt_id == evidence.source_ingress_receipt_id
    assert identity.source_ingress_receipt_sha256 == evidence.source_ingress_receipt_sha256
    assert identity.source_observation_sha256 == evidence.source_observation_sha256
    assert identity.identity_profile_id == BROKER_INBOX_IDENTITY_PROFILE_ID
    assert identity.identity_profile_sha256 == BROKER_INBOX_IDENTITY_PROFILE_SHA256
    assert identity.provider_revision_id is None
    assert identity.source_scoped is True


def test_non_application_decision_pins_frozen_policy() -> None:
    fact = _fact(_scenario())
    request = create_alpaca_paper_inbox_admission_request(fact)

    decision = decide_broker_inbox_admission(
        request,
        decided_at=fact.normalized_at,
    )

    assert decision.policy_id == BROKER_INBOX_NON_APPLICATION_POLICY_ID
    assert decision.policy_sha256 == BROKER_INBOX_NON_APPLICATION_POLICY_SHA256
    assert decision.quarantined is False
    assert decision.disposition is BrokerInboxDisposition.WITHHELD_UNQUALIFIED_REVISION_IDENTITY


def test_identical_separate_lookups_remain_distinct_source_observations() -> None:
    first = _fact(
        _scenario(),
        delivery_idempotency_key="phase4l-delivery-a",
    )
    second = _fact(
        _scenario(),
        delivery_idempotency_key="phase4l-delivery-b",
    )

    first_request = create_alpaca_paper_inbox_admission_request(first)
    second_request = create_alpaca_paper_inbox_admission_request(second)

    assert first.evidence.provider_order_id == second.evidence.provider_order_id
    assert first.evidence.cumulative_filled_quantity == second.evidence.cumulative_filled_quantity
    assert first.fact_id != second.fact_id
    assert first_request.identity.observation_id != (second_request.identity.observation_id)
    assert first_request.request_id != second_request.request_id


def test_request_and_decision_construction_are_protected() -> None:
    with pytest.raises(
        TypeError,
        match="BrokerInboxAdmissionRequest must be proof-constructed",
    ):
        BrokerInboxAdmissionRequest()
    with pytest.raises(
        TypeError,
        match="BrokerInboxNonApplicationDecisionReceipt must be reducer-produced",
    ):
        BrokerInboxNonApplicationDecisionReceipt()


def test_source_identity_substitution_fails_closed() -> None:
    fact = _fact(_scenario())
    request = create_alpaca_paper_inbox_admission_request(fact)
    substituted = replace(
        request.identity,
        source_observation_sha256="f" * 64,
    )

    with pytest.raises(
        BrokerInboxConflict,
        match="identity conflicts",
    ):
        _broker_inbox_admission_request(fact, substituted)


def test_disposition_substitution_and_backdated_decision_fail_closed() -> None:
    fact = _fact(_scenario())
    request = create_alpaca_paper_inbox_admission_request(fact)

    with pytest.raises(BrokerInboxConflict, match="reconciliation outcome"):
        _broker_inbox_non_application_decision(
            request,
            BrokerInboxDisposition.QUARANTINED_SECURITY_MISMATCH,
            decided_at=fact.normalized_at,
        )
    with pytest.raises(BrokerInboxConflict, match="cannot predate"):
        decide_broker_inbox_admission(
            request,
            decided_at=fact.normalized_at - timedelta(microseconds=1),
        )


def test_adapter_rejects_non_fact_and_non_alpaca_sources() -> None:
    fact = _fact(_scenario())
    with pytest.raises(AlpacaPaperInboxError, match="exact Phase 4K"):
        create_alpaca_paper_inbox_admission_request(cast(BrokerReconciliationFact, fact.evidence))

    other_evidence = replace(fact.evidence, provider_id="other-broker")
    other_fact = _broker_reconciliation_fact(
        other_evidence,
        normalized_at=fact.normalized_at,
        account_sequence=1,
        previous_fact_sha256=None,
    )
    with pytest.raises(AlpacaPaperInboxConflict, match="paper adapter"):
        create_alpaca_paper_inbox_admission_request(other_fact)
