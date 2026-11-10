from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from packages.adapters.broker.alpaca_paper import (
    ALPACA_DOCUMENTED_TRADING_REQUESTS_PER_MINUTE,
    ALPACA_PAPER_CAPABILITIES,
    AlpacaPaperContractError,
)
from packages.adapters.broker.alpaca_paper_budget import (
    ALPACA_PAPER_OPERATION_PURPOSES,
    ALPACA_PAPER_PERMIT_TTL,
    ALPACA_PAPER_RECOVERY_CAPACITY,
    ALPACA_PAPER_REQUEST_BUDGET_POLICY,
    ALPACA_PAPER_SUBMISSION_CAPACITY,
    AlpacaPaperBudgetOperation,
    create_alpaca_paper_request_demand,
)
from packages.domain.broker_request_budget import (
    DEFAULT_BROKER_REQUEST_WINDOW,
    BrokerRequestPurpose,
)

REQUESTED_AT = datetime(2026, 7, 26, 14, 30, tzinfo=UTC)


def test_alpaca_policy_preserves_progressively_protected_capacity() -> None:
    policy = ALPACA_PAPER_REQUEST_BUDGET_POLICY

    assert policy.provider_id == "alpaca-paper"
    assert policy.environment == "paper"
    assert policy.window_duration == DEFAULT_BROKER_REQUEST_WINDOW
    assert policy.permit_ttl == ALPACA_PAPER_PERMIT_TTL == timedelta(seconds=3)
    assert policy.submission_capacity == ALPACA_PAPER_SUBMISSION_CAPACITY == 160
    assert policy.recovery_capacity == ALPACA_PAPER_RECOVERY_CAPACITY == 180
    assert (
        policy.total_capacity
        == ALPACA_DOCUMENTED_TRADING_REQUESTS_PER_MINUTE
        == ALPACA_PAPER_CAPABILITIES.documented_trading_requests_per_minute
        == 200
    )
    assert policy.capacity_for(BrokerRequestPurpose.SUBMISSION) == 160
    assert policy.capacity_for(BrokerRequestPurpose.UNKNOWN_LOOKUP) == 180
    assert policy.capacity_for(BrokerRequestPurpose.CANCEL) == 200
    assert policy.capacity_for(BrokerRequestPurpose.RECONCILIATION) == 200
    assert ALPACA_PAPER_CAPABILITIES.request_budget_enforced is False


@pytest.mark.parametrize(
    ("operation", "purpose"),
    tuple(ALPACA_PAPER_OPERATION_PURPOSES.items()),
)
def test_alpaca_operations_have_closed_non_caller_selected_purposes(
    operation: AlpacaPaperBudgetOperation,
    purpose: BrokerRequestPurpose,
) -> None:
    demand = create_alpaca_paper_request_demand(
        account_id="paper-account",
        idempotency_key=f"budget-{operation.value}",
        operation=operation,
        correlation_sha256="a" * 64,
        requested_at=REQUESTED_AT,
    )

    assert demand.operation == operation.value
    assert demand.purpose is purpose


def test_alpaca_demand_factory_rejects_untyped_operation() -> None:
    with pytest.raises(AlpacaPaperContractError, match="exact"):
        create_alpaca_paper_request_demand(
            account_id="paper-account",
            idempotency_key="budget-submit-order",
            operation="submit_order",  # type: ignore[arg-type]
            correlation_sha256="a" * 64,
            requested_at=REQUESTED_AT,
        )
