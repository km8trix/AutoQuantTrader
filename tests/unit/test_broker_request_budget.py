from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, replace
from datetime import UTC, datetime, timedelta

import pytest

from packages.domain.broker_request_budget import (
    BROKER_REQUEST_BUDGET_CONTRACT_VERSION,
    DEFAULT_BROKER_REQUEST_WINDOW,
    BrokerRequestBudgetError,
    BrokerRequestBudgetExhausted,
    BrokerRequestBudgetPolicy,
    BrokerRequestDemand,
    BrokerRequestPermit,
    BrokerRequestPermitConflict,
    BrokerRequestPermitExpired,
    BrokerRequestPermitFreshnessReceipt,
    BrokerRequestPurpose,
    _broker_request_permit_freshness_receipt,
    issue_broker_request_permit,
    require_fresh_broker_request_permit,
)

BASE = datetime(2026, 7, 26, 13, 30, tzinfo=UTC)
CORRELATION_SHA256 = "a" * 64


def policy(
    *,
    policy_version: str = "1.0.0",
    window_duration: timedelta = DEFAULT_BROKER_REQUEST_WINDOW,
    permit_ttl: timedelta = timedelta(seconds=5),
    submission_capacity: int = 2,
    recovery_capacity: int = 3,
    total_capacity: int = 4,
) -> BrokerRequestBudgetPolicy:
    return BrokerRequestBudgetPolicy(
        policy_id="alpaca-paper-request-budget",
        policy_version=policy_version,
        provider_id="alpaca",
        environment="paper",
        window_duration=window_duration,
        permit_ttl=permit_ttl,
        submission_capacity=submission_capacity,
        recovery_capacity=recovery_capacity,
        total_capacity=total_capacity,
    )


def demand(
    purpose: BrokerRequestPurpose,
    ordinal: int = 1,
    *,
    account_id: str = "paper-account",
    requested_at: datetime = BASE,
) -> BrokerRequestDemand:
    return BrokerRequestDemand(
        account_id=account_id,
        idempotency_key=f"broker-request-{ordinal:04d}",
        operation=f"{purpose.value}-{ordinal}",
        purpose=purpose,
        correlation_sha256=CORRELATION_SHA256,
        requested_at=requested_at,
    )


def issue(
    request: BrokerRequestDemand,
    *,
    configured_policy: BrokerRequestBudgetPolicy | None = None,
    issued_at: datetime = BASE,
    active_permits: tuple[BrokerRequestPermit, ...] = (),
    previous_permit: BrokerRequestPermit | None = None,
    previous_policy: BrokerRequestBudgetPolicy | None = None,
) -> BrokerRequestPermit:
    selected_policy = configured_policy or policy()
    selected_previous_policy = (
        selected_policy
        if previous_permit is not None and previous_policy is None
        else previous_policy
    )
    return issue_broker_request_permit(
        policy=selected_policy,
        demand=request,
        issued_at=issued_at,
        active_permits=active_permits,
        previous_permit=previous_permit,
        previous_policy=selected_previous_policy,
    )


def test_policy_demand_and_permit_are_deterministic_immutable_offline_evidence() -> None:
    configured_policy = policy()
    request = demand(BrokerRequestPurpose.SUBMISSION)

    first = issue(request, configured_policy=configured_policy)
    replay = issue(request, configured_policy=configured_policy)

    assert BROKER_REQUEST_BUDGET_CONTRACT_VERSION in configured_policy.canonical_json
    assert configured_policy == policy()
    assert configured_policy.semantic_sha256 == policy().semantic_sha256
    assert request == demand(BrokerRequestPurpose.SUBMISSION)
    assert request.demand_id == demand(BrokerRequestPurpose.SUBMISSION).demand_id
    assert len(request.demand_id) == 64
    assert request.semantic_sha256 == demand(BrokerRequestPurpose.SUBMISSION).semantic_sha256
    conflicting_request = replace(request, operation="different-operation")
    assert conflicting_request.demand_id == request.demand_id
    assert conflicting_request.semantic_sha256 != request.semantic_sha256
    assert first == replay
    assert first.permit_id == replay.permit_id
    assert len(first.permit_id) == 64
    assert first.semantic_sha256 == replay.semantic_sha256
    assert len(first.semantic_sha256) == 64
    assert first.sequence_number == 1
    assert first.previous_permit_sha256 is None
    assert first.expires_at == BASE + configured_policy.permit_ttl
    assert first.transport_authorized is False
    assert first.refundable is False
    assert not hasattr(first, "refund")
    with pytest.raises(FrozenInstanceError):
        first.sequence_number = 2  # type: ignore[misc]


def test_closed_purposes_map_to_total_active_capacity_tiers() -> None:
    configured_policy = policy()

    assert tuple(BrokerRequestPurpose) == (
        BrokerRequestPurpose.SUBMISSION,
        BrokerRequestPurpose.UNKNOWN_LOOKUP,
        BrokerRequestPurpose.CANCEL,
        BrokerRequestPurpose.RECONCILIATION,
    )
    assert (
        configured_policy.capacity_for(BrokerRequestPurpose.SUBMISSION)
        == configured_policy.submission_capacity
    )
    assert (
        configured_policy.capacity_for(BrokerRequestPurpose.UNKNOWN_LOOKUP)
        == configured_policy.recovery_capacity
    )
    assert (
        configured_policy.capacity_for(BrokerRequestPurpose.CANCEL)
        == configured_policy.total_capacity
    )
    assert (
        configured_policy.capacity_for(BrokerRequestPurpose.RECONCILIATION)
        == configured_policy.total_capacity
    )
    with pytest.raises(BrokerRequestBudgetError, match="exact BrokerRequestPurpose"):
        configured_policy.capacity_for("submission")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"policy_id": " policy"}, "trimmed"),
        ({"provider_id": "alpaca\u007f"}, "unsupported text"),
        ({"environment": "e" * 33}, "unsupported text"),
        ({"window_duration": timedelta(0)}, "positive exact timedelta"),
        ({"window_duration": timedelta(seconds=60, microseconds=1)}, "whole-second"),
        ({"permit_ttl": timedelta(seconds=61)}, "cannot exceed"),
        ({"submission_capacity": True}, "positive exact integer"),
        ({"submission_capacity": 3}, "capacity tiers"),
        ({"recovery_capacity": 4}, "capacity tiers"),
        ({"total_capacity": 3}, "capacity tiers"),
        ({"total_capacity": 100_001}, "bounded active-permit"),
    ],
)
def test_policy_strictly_rejects_unsafe_or_unpersistable_values(
    changes: dict[str, object],
    message: str,
) -> None:
    values: dict[str, object] = {
        "policy_id": "policy",
        "policy_version": "1",
        "provider_id": "alpaca",
        "environment": "paper",
        "window_duration": timedelta(seconds=60),
        "permit_ttl": timedelta(seconds=5),
        "submission_capacity": 2,
        "recovery_capacity": 3,
        "total_capacity": 4,
    }
    values.update(changes)

    with pytest.raises(BrokerRequestBudgetError, match=message):
        BrokerRequestBudgetPolicy(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"account_id": "x" * 65}, "unsupported text"),
        ({"idempotency_key": "short"}, "8-128"),
        ({"operation": " lookup"}, "trimmed"),
        ({"purpose": "unknown_lookup"}, "exact BrokerRequestPurpose"),
        ({"correlation_sha256": "A" * 64}, "lowercase SHA-256"),
        ({"requested_at": BASE.replace(tzinfo=None)}, "timezone-aware"),
        (
            {
                "requested_at": BASE.astimezone(
                    tz=__import__("datetime").timezone(timedelta(hours=-4))
                )
            },
            "must be UTC",
        ),
    ],
)
def test_demand_requires_exact_bounded_canonical_inputs(
    changes: dict[str, object],
    message: str,
) -> None:
    values: dict[str, object] = {
        "account_id": "paper-account",
        "idempotency_key": "request-0001",
        "operation": "get-order-by-client-id",
        "purpose": BrokerRequestPurpose.UNKNOWN_LOOKUP,
        "correlation_sha256": CORRELATION_SHA256,
        "requested_at": BASE,
    }
    values.update(changes)

    with pytest.raises(BrokerRequestBudgetError, match=message):
        BrokerRequestDemand(**values)  # type: ignore[arg-type]


def test_total_active_traffic_preserves_submission_recovery_and_control_reserves() -> None:
    configured_policy = policy()
    first = issue(
        demand(BrokerRequestPurpose.RECONCILIATION, 1),
        configured_policy=configured_policy,
    )
    second = issue(
        demand(BrokerRequestPurpose.CANCEL, 2),
        configured_policy=configured_policy,
        active_permits=(first,),
        previous_permit=first,
    )
    active_two = (first, second)

    with pytest.raises(BrokerRequestBudgetExhausted, match="submission"):
        issue(
            demand(BrokerRequestPurpose.SUBMISSION, 3),
            configured_policy=configured_policy,
            active_permits=active_two,
            previous_permit=second,
        )

    third = issue(
        demand(BrokerRequestPurpose.UNKNOWN_LOOKUP, 3),
        configured_policy=configured_policy,
        active_permits=active_two,
        previous_permit=second,
    )
    active_three = (*active_two, third)
    with pytest.raises(BrokerRequestBudgetExhausted, match="unknown_lookup"):
        issue(
            demand(BrokerRequestPurpose.UNKNOWN_LOOKUP, 4),
            configured_policy=configured_policy,
            active_permits=active_three,
            previous_permit=third,
        )

    fourth = issue(
        demand(BrokerRequestPurpose.CANCEL, 4),
        configured_policy=configured_policy,
        active_permits=active_three,
        previous_permit=third,
    )
    assert fourth.sequence_number == 4
    with pytest.raises(BrokerRequestBudgetExhausted, match="reconciliation"):
        issue(
            demand(BrokerRequestPurpose.RECONCILIATION, 5),
            configured_policy=configured_policy,
            active_permits=(*active_three, fourth),
            previous_permit=fourth,
        )


def test_accounting_horizon_includes_ttl_and_window_then_expires_strictly_after() -> None:
    configured_policy = policy(
        submission_capacity=1,
        recovery_capacity=2,
        total_capacity=3,
    )
    first = issue(
        demand(BrokerRequestPurpose.SUBMISSION, 1),
        configured_policy=configured_policy,
    )
    boundary = first.expires_at + configured_policy.window_duration

    with pytest.raises(BrokerRequestBudgetExhausted):
        issue(
            demand(
                BrokerRequestPurpose.SUBMISSION,
                2,
                requested_at=boundary,
            ),
            configured_policy=configured_policy,
            issued_at=boundary,
            active_permits=(first,),
            previous_permit=first,
        )

    after_boundary = boundary + timedelta(microseconds=1)
    second = issue(
        demand(
            BrokerRequestPurpose.SUBMISSION,
            2,
            requested_at=after_boundary,
        ),
        configured_policy=configured_policy,
        issued_at=after_boundary,
        active_permits=(),
        previous_permit=first,
    )
    assert second.sequence_number == 2
    assert second.previous_permit_sha256 == first.semantic_sha256


def test_active_and_rotation_predecessors_require_the_policy_bound_expiry() -> None:
    configured_policy = policy()
    first = issue(
        demand(BrokerRequestPurpose.CANCEL, 1),
        configured_policy=configured_policy,
    )
    forged = replace(first, expires_at=first.expires_at - timedelta(seconds=1))

    with pytest.raises(BrokerRequestPermitConflict, match="exact budget policy TTL"):
        issue(
            demand(BrokerRequestPurpose.CANCEL, 2),
            configured_policy=configured_policy,
            active_permits=(forged,),
            previous_permit=forged,
        )

    replacement = replace(configured_policy, policy_version="2.0.0")
    after_horizon = first.expires_at + configured_policy.window_duration + timedelta(microseconds=1)
    with pytest.raises(BrokerRequestPermitConflict, match="exact budget policy TTL"):
        issue(
            demand(
                BrokerRequestPurpose.CANCEL,
                2,
                requested_at=after_horizon,
            ),
            configured_policy=replacement,
            issued_at=after_horizon,
            previous_permit=forged,
            previous_policy=configured_policy,
        )


def test_account_sequence_and_predecessor_are_strict_and_demand_cannot_repeat() -> None:
    configured_policy = policy()
    request = demand(BrokerRequestPurpose.CANCEL, 1)
    first = issue(request, configured_policy=configured_policy)
    second_request = demand(BrokerRequestPurpose.CANCEL, 2)
    second = issue(
        second_request,
        configured_policy=configured_policy,
        active_permits=(first,),
        previous_permit=first,
    )

    assert second.sequence_number == first.sequence_number + 1
    assert second.previous_permit_sha256 == first.semantic_sha256
    with pytest.raises(BrokerRequestPermitConflict, match="more than one permit"):
        issue(
            request,
            configured_policy=configured_policy,
            active_permits=(first,),
            previous_permit=first,
        )
    with pytest.raises(BrokerRequestPermitConflict, match="account-local"):
        issue(
            demand(BrokerRequestPurpose.CANCEL, 3, account_id="other-account"),
            configured_policy=configured_policy,
            active_permits=(first, second),
            previous_permit=second,
        )
    with pytest.raises(BrokerRequestPermitConflict, match="canonical sequence order"):
        issue(
            demand(BrokerRequestPurpose.CANCEL, 3),
            configured_policy=configured_policy,
            active_permits=(second, first),
            previous_permit=second,
        )
    forged = replace(second, previous_permit_sha256="f" * 64)
    with pytest.raises(BrokerRequestPermitConflict, match="conflicting predecessor"):
        issue(
            demand(BrokerRequestPurpose.CANCEL, 3),
            configured_policy=configured_policy,
            active_permits=(first, forged),
            previous_permit=forged,
        )


def test_policy_rotation_waits_for_old_inclusive_window_to_drain() -> None:
    original = policy()
    first = issue(
        demand(BrokerRequestPurpose.RECONCILIATION, 1),
        configured_policy=original,
    )
    replacement = policy(
        policy_version="2.0.0",
        window_duration=timedelta(seconds=120),
        submission_capacity=3,
        recovery_capacity=4,
        total_capacity=5,
    )
    boundary = first.expires_at + original.window_duration

    with pytest.raises(BrokerRequestPermitConflict, match="previous rolling window"):
        issue(
            demand(
                BrokerRequestPurpose.RECONCILIATION,
                2,
                requested_at=boundary,
            ),
            configured_policy=replacement,
            issued_at=boundary,
            previous_permit=first,
            previous_policy=original,
        )

    after_boundary = boundary + timedelta(microseconds=1)
    rotated = issue(
        demand(
            BrokerRequestPurpose.RECONCILIATION,
            2,
            requested_at=after_boundary,
        ),
        configured_policy=replacement,
        issued_at=after_boundary,
        previous_permit=first,
        previous_policy=original,
    )
    assert rotated.policy_sha256 == replacement.semantic_sha256
    assert rotated.sequence_number == 2
    rotated_horizon = rotated.expires_at + replacement.window_duration
    with pytest.raises(BrokerRequestPermitConflict, match="provider or environment"):
        issue(
            demand(
                BrokerRequestPurpose.RECONCILIATION,
                3,
                requested_at=rotated_horizon + timedelta(microseconds=1),
            ),
            configured_policy=replace(replacement, provider_id="other"),
            issued_at=rotated_horizon + timedelta(microseconds=1),
            previous_permit=rotated,
            previous_policy=replacement,
        )


def test_freshness_revalidates_exact_policy_demand_ttl_and_half_open_time() -> None:
    configured_policy = policy()
    request = demand(BrokerRequestPurpose.UNKNOWN_LOOKUP)
    permit = issue(request, configured_policy=configured_policy)

    require_fresh_broker_request_permit(
        permit=permit,
        policy=configured_policy,
        demand=request,
        checked_at=BASE,
    )
    require_fresh_broker_request_permit(
        permit=permit,
        policy=configured_policy,
        demand=request,
        checked_at=permit.expires_at - timedelta(microseconds=1),
    )
    assert permit.is_fresh(BASE)
    assert not permit.is_fresh(BASE - timedelta(microseconds=1))
    assert not permit.is_fresh(permit.expires_at)

    for checked_at in (BASE - timedelta(microseconds=1), permit.expires_at):
        with pytest.raises(BrokerRequestPermitExpired, match="not fresh"):
            require_fresh_broker_request_permit(
                permit=permit,
                policy=configured_policy,
                demand=request,
                checked_at=checked_at,
            )
    with pytest.raises(BrokerRequestPermitConflict, match="exact demand"):
        require_fresh_broker_request_permit(
            permit=permit,
            policy=configured_policy,
            demand=demand(BrokerRequestPurpose.UNKNOWN_LOOKUP, 2),
            checked_at=BASE,
        )
    with pytest.raises(BrokerRequestPermitConflict, match="exact budget policy TTL"):
        require_fresh_broker_request_permit(
            permit=permit,
            policy=replace(configured_policy, permit_ttl=timedelta(seconds=4)),
            demand=request,
            checked_at=BASE,
        )
    maximum = datetime.max.replace(tzinfo=UTC)
    near_maximum_permit = replace(
        permit,
        issued_at=maximum - timedelta(seconds=1),
        expires_at=maximum,
    )
    with pytest.raises(BrokerRequestBudgetError, match="supported datetime"):
        require_fresh_broker_request_permit(
            permit=near_maximum_permit,
            policy=replace(configured_policy, permit_ttl=timedelta(seconds=2)),
            demand=request,
            checked_at=near_maximum_permit.issued_at,
        )


def test_freshness_receipt_is_deterministic_secret_free_non_authorizing_proof() -> None:
    configured_policy = policy()
    request = demand(BrokerRequestPurpose.UNKNOWN_LOOKUP)
    permit = issue(request, configured_policy=configured_policy)
    checked_at = BASE + timedelta(seconds=1)

    with pytest.raises(TypeError, match="proof-constructed"):
        BrokerRequestPermitFreshnessReceipt(
            permit_id=permit.permit_id,
            permit_sha256=permit.semantic_sha256,
            policy_sha256=configured_policy.semantic_sha256,
            demand_sha256=request.semantic_sha256,
            checked_at=checked_at,
            expires_at=permit.expires_at,
        )

    receipt = _broker_request_permit_freshness_receipt(
        permit=permit,
        policy=configured_policy,
        demand=request,
        checked_at=checked_at,
    )
    replay = _broker_request_permit_freshness_receipt(
        permit=permit,
        policy=configured_policy,
        demand=request,
        checked_at=checked_at,
    )

    assert tuple(field.name for field in fields(receipt)) == (
        "permit_id",
        "permit_sha256",
        "policy_sha256",
        "demand_sha256",
        "checked_at",
        "expires_at",
    )
    assert receipt == replay
    assert receipt.permit_id == permit.permit_id
    assert receipt.permit_sha256 == permit.semantic_sha256
    assert receipt.policy_sha256 == configured_policy.semantic_sha256
    assert receipt.demand_sha256 == request.semantic_sha256
    assert receipt.checked_at == checked_at
    assert receipt.expires_at == permit.expires_at
    assert receipt.is_fresh is True
    assert receipt.transport_authorized is False
    assert len(receipt.semantic_sha256) == 64
    assert len(receipt.receipt_id) == 64
    assert "credential" not in receipt.canonical_json
    assert "secret" not in receipt.canonical_json
    with pytest.raises(FrozenInstanceError):
        receipt.checked_at = BASE  # type: ignore[misc]

    later = _broker_request_permit_freshness_receipt(
        permit=permit,
        policy=configured_policy,
        demand=request,
        checked_at=checked_at + timedelta(seconds=1),
    )
    assert later.semantic_sha256 != receipt.semantic_sha256
    assert later.receipt_id != receipt.receipt_id

    with pytest.raises(BrokerRequestPermitExpired, match="not fresh"):
        _broker_request_permit_freshness_receipt(
            permit=permit,
            policy=configured_policy,
            demand=request,
            checked_at=permit.expires_at,
        )


def test_permit_constructor_rejects_impossible_structural_evidence() -> None:
    configured_policy = policy()
    request = demand(BrokerRequestPurpose.CANCEL)
    permit = issue(request, configured_policy=configured_policy)
    values: dict[str, object] = {
        "account_id": permit.account_id,
        "purpose": permit.purpose,
        "demand_id": permit.demand_id,
        "demand_sha256": permit.demand_sha256,
        "policy_sha256": permit.policy_sha256,
        "sequence_number": permit.sequence_number,
        "previous_permit_sha256": permit.previous_permit_sha256,
        "issued_at": permit.issued_at,
        "expires_at": permit.expires_at,
    }

    for changes, message in (
        ({"purpose": "cancel"}, "exact BrokerRequestPurpose"),
        ({"demand_id": "not-a-digest"}, "lowercase SHA-256"),
        ({"demand_sha256": "0" * 63}, "lowercase SHA-256"),
        ({"sequence_number": True}, "positive exact integer"),
        ({"sequence_number": 1, "previous_permit_sha256": "f" * 64}, "cannot have"),
        ({"sequence_number": 2, "previous_permit_sha256": None}, "requires"),
        ({"issued_at": BASE.replace(tzinfo=None)}, "timezone-aware"),
        ({"expires_at": BASE}, "expiry must follow"),
    ):
        invalid = dict(values)
        invalid.update(changes)
        with pytest.raises(BrokerRequestBudgetError, match=message):
            BrokerRequestPermit(**invalid)  # type: ignore[arg-type]


def test_issue_rejects_noncanonical_snapshots_and_datetime_overflow() -> None:
    configured_policy = policy()
    request = demand(BrokerRequestPurpose.CANCEL)
    first = issue(request, configured_policy=configured_policy)

    with pytest.raises(BrokerRequestPermitConflict, match="immutable tuple"):
        issue_broker_request_permit(
            policy=configured_policy,
            demand=demand(BrokerRequestPurpose.CANCEL, 2),
            issued_at=BASE,
            active_permits=[first],  # type: ignore[arg-type]
            previous_permit=first,
            previous_policy=configured_policy,
        )
    with pytest.raises(BrokerRequestPermitConflict, match="latest active permit"):
        issue(
            demand(
                BrokerRequestPurpose.CANCEL,
                2,
                requested_at=BASE + timedelta(seconds=1),
            ),
            configured_policy=configured_policy,
            issued_at=BASE + timedelta(seconds=1),
            active_permits=(),
            previous_permit=first,
        )

    near_maximum = datetime.max.replace(tzinfo=UTC)
    with pytest.raises(BrokerRequestBudgetError, match="expiry"):
        issue(
            demand(
                BrokerRequestPurpose.CANCEL,
                2,
                requested_at=near_maximum,
            ),
            configured_policy=configured_policy,
            issued_at=near_maximum,
            active_permits=(),
            previous_permit=first,
        )
