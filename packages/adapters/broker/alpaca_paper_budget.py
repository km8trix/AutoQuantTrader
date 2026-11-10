"""Offline Alpaca paper mapping into durable request-budget purposes.

This module selects a conservative local policy beneath the provider ceiling
reviewed by Phase 4A.  It constructs demand evidence only; neither a demand nor
a later permit authorizes transport.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta
from enum import StrEnum
from types import MappingProxyType

from packages.adapters.broker.alpaca_paper import (
    ALPACA_DOCUMENTED_TRADING_REQUESTS_PER_MINUTE,
    ALPACA_PAPER_ADAPTER_ID,
    AlpacaPaperContractError,
)
from packages.domain.broker_request_budget import (
    DEFAULT_BROKER_REQUEST_WINDOW,
    BrokerRequestBudgetPolicy,
    BrokerRequestDemand,
    BrokerRequestPurpose,
)

ALPACA_PAPER_REQUEST_BUDGET_POLICY_ID = "alpaca-paper-trading-api-budget"
ALPACA_PAPER_REQUEST_BUDGET_POLICY_VERSION = "phase4d-alpaca-paper-budget-v1"
ALPACA_PAPER_SUBMISSION_CAPACITY = 160
ALPACA_PAPER_RECOVERY_CAPACITY = 180
ALPACA_PAPER_PERMIT_TTL = timedelta(seconds=3)


class AlpacaPaperBudgetOperation(StrEnum):
    """Closed logical operations admitted by the Phase 4D budget policy."""

    SUBMIT_ORDER = "submit_order"
    OBSERVE_ACCOUNT = "observe_account"
    OBSERVE_ASSET = "observe_asset"
    LOOKUP_UNKNOWN_BY_CLIENT_ORDER_ID = "lookup_unknown_by_client_order_id"
    CANCEL_ORDER = "cancel_order"
    RECONCILE_ACCOUNT = "reconcile_account"


ALPACA_PAPER_OPERATION_PURPOSES: Mapping[AlpacaPaperBudgetOperation, BrokerRequestPurpose] = (
    MappingProxyType(
        {
            AlpacaPaperBudgetOperation.SUBMIT_ORDER: BrokerRequestPurpose.SUBMISSION,
            AlpacaPaperBudgetOperation.OBSERVE_ACCOUNT: (BrokerRequestPurpose.RECONCILIATION),
            AlpacaPaperBudgetOperation.OBSERVE_ASSET: (BrokerRequestPurpose.RECONCILIATION),
            AlpacaPaperBudgetOperation.LOOKUP_UNKNOWN_BY_CLIENT_ORDER_ID: (
                BrokerRequestPurpose.UNKNOWN_LOOKUP
            ),
            AlpacaPaperBudgetOperation.CANCEL_ORDER: BrokerRequestPurpose.CANCEL,
            AlpacaPaperBudgetOperation.RECONCILE_ACCOUNT: (BrokerRequestPurpose.RECONCILIATION),
        }
    )
)

ALPACA_PAPER_REQUEST_BUDGET_POLICY = BrokerRequestBudgetPolicy(
    policy_id=ALPACA_PAPER_REQUEST_BUDGET_POLICY_ID,
    policy_version=ALPACA_PAPER_REQUEST_BUDGET_POLICY_VERSION,
    provider_id=ALPACA_PAPER_ADAPTER_ID,
    environment="paper",
    window_duration=DEFAULT_BROKER_REQUEST_WINDOW,
    permit_ttl=ALPACA_PAPER_PERMIT_TTL,
    submission_capacity=ALPACA_PAPER_SUBMISSION_CAPACITY,
    recovery_capacity=ALPACA_PAPER_RECOVERY_CAPACITY,
    total_capacity=ALPACA_DOCUMENTED_TRADING_REQUESTS_PER_MINUTE,
)


def create_alpaca_paper_request_demand(
    *,
    account_id: str,
    idempotency_key: str,
    operation: AlpacaPaperBudgetOperation,
    correlation_sha256: str,
    requested_at: datetime,
) -> BrokerRequestDemand:
    """Create one purpose-mapped Alpaca paper demand without transport authority."""

    if type(operation) is not AlpacaPaperBudgetOperation:
        raise AlpacaPaperContractError(
            "Alpaca budget operation must be an exact AlpacaPaperBudgetOperation"
        )
    return BrokerRequestDemand(
        account_id=account_id,
        idempotency_key=idempotency_key,
        operation=operation.value,
        purpose=ALPACA_PAPER_OPERATION_PURPOSES[operation],
        correlation_sha256=correlation_sha256,
        requested_at=requested_at,
    )
