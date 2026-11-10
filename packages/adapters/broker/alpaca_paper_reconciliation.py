"""Pure normalization of authenticated Alpaca paper lookup history.

This adapter accepts no credentials, performs no I/O, and applies no order
lifecycle transition.  It cross-authenticates a durable Phase 4I scalar receipt
against the exact raw-first decoded source and emits only provider-neutral
Phase 4K historical evidence.
"""

from __future__ import annotations

from packages.adapters.broker.alpaca_paper import (
    ALPACA_PAPER_ADAPTER_ID,
    ALPACA_PAPER_ADAPTER_VERSION,
    AlpacaPaperContractError,
)
from packages.adapters.broker.alpaca_paper_ingress import (
    ALPACA_PAPER_LOOKUP_INGRESS_CHANNEL,
    ALPACA_PAPER_LOOKUP_INGRESS_OPERATION,
    PersistedAlpacaClientOrderLookupObservation,
)
from packages.adapters.broker.alpaca_paper_lookup_runtime import (
    AlpacaPaperAuthenticatedLookupOutcome,
    AlpacaPaperAuthenticatedLookupReceipt,
)
from packages.adapters.broker.alpaca_paper_observations import (
    AlpacaClientOrderLookupOutcome,
    AlpacaOrderObservation,
    AlpacaProviderTimestamp,
)
from packages.domain.broker_reconciliation import (
    BrokerProviderTimestampEvidence,
    BrokerReconciliationEvidence,
    BrokerReconciliationOutcome,
)

ALPACA_PAPER_RECONCILIATION_NORMALIZATION_CONTRACT_VERSION = (
    "phase4k-alpaca-paper-authenticated-lookup-normalization-v1"
)

_TIMESTAMP_FIELDS = (
    "created_at",
    "updated_at",
    "submitted_at",
    "filled_at",
    "expired_at",
    "expires_at",
    "canceled_at",
    "failed_at",
    "replaced_at",
)


class AlpacaPaperReconciliationError(AlpacaPaperContractError):
    """Authenticated Alpaca reconciliation sources are malformed."""


class AlpacaPaperReconciliationConflict(AlpacaPaperReconciliationError):
    """Authenticated Alpaca sources conflict with one another."""


def _outcome(
    receipt_outcome: AlpacaPaperAuthenticatedLookupOutcome,
) -> BrokerReconciliationOutcome:
    outcomes = {
        AlpacaPaperAuthenticatedLookupOutcome.FOUND_MATCHED: (
            BrokerReconciliationOutcome.ORDER_OBSERVED_CANDIDATE
        ),
        AlpacaPaperAuthenticatedLookupOutcome.FOUND_MISMATCH: (
            BrokerReconciliationOutcome.QUARANTINED_ECONOMIC_MISMATCH
        ),
        AlpacaPaperAuthenticatedLookupOutcome.SECURITY_IDENTITY_MISMATCH: (
            BrokerReconciliationOutcome.QUARANTINED_SECURITY_MISMATCH
        ),
        AlpacaPaperAuthenticatedLookupOutcome.NOT_VISIBLE_INCONCLUSIVE: (
            BrokerReconciliationOutcome.INCONCLUSIVE_NOT_VISIBLE
        ),
    }
    try:
        return outcomes[receipt_outcome]
    except (KeyError, TypeError):
        raise AlpacaPaperReconciliationError(
            "authenticated lookup has an unsupported reconciliation outcome"
        ) from None


def _provider_timestamp(
    field_name: str,
    timestamp: AlpacaProviderTimestamp,
) -> BrokerProviderTimestampEvidence:
    if type(timestamp) is not AlpacaProviderTimestamp:
        raise AlpacaPaperReconciliationError(
            f"Alpaca order {field_name} must be an exact provider timestamp"
        )
    timestamp.__post_init__()
    return BrokerProviderTimestampEvidence(
        field_name=field_name,
        raw=timestamp.raw,
        normalized_utc=timestamp.normalized_utc,
        nanosecond=timestamp.nanosecond,
    )


def _provider_timestamps(
    order: AlpacaOrderObservation | None,
) -> tuple[BrokerProviderTimestampEvidence, ...]:
    if order is None:
        return ()
    result: list[BrokerProviderTimestampEvidence] = []
    for field_name in _TIMESTAMP_FIELDS:
        timestamp = getattr(order, field_name)
        if timestamp is not None:
            result.append(_provider_timestamp(field_name, timestamp))
    return tuple(result)


def _require_source_binding(
    receipt: AlpacaPaperAuthenticatedLookupReceipt,
    source: PersistedAlpacaClientOrderLookupObservation,
) -> None:
    raw_receipt = source.receipt
    delivery = raw_receipt.delivery
    observation = source.observation
    description = observation.description
    submission = description.submission
    order = observation.order

    expected_pairs = (
        (receipt.account_id, description.account_id, "account ID"),
        (receipt.account_id, delivery.account_id, "raw account ID"),
        (receipt.provider_id, delivery.provider_id, "provider ID"),
        (receipt.environment, delivery.environment, "environment"),
        (
            ALPACA_PAPER_ADAPTER_VERSION,
            delivery.adapter_version,
            "adapter version",
        ),
        (
            ALPACA_PAPER_LOOKUP_INGRESS_CHANNEL,
            delivery.channel,
            "ingress channel",
        ),
        (
            ALPACA_PAPER_LOOKUP_INGRESS_OPERATION,
            delivery.operation,
            "ingress operation",
        ),
        (
            receipt.ingress_receipt_id,
            raw_receipt.receipt_id,
            "raw ingress receipt ID",
        ),
        (
            receipt.ingress_receipt_sha256,
            raw_receipt.semantic_sha256,
            "raw ingress receipt digest",
        ),
        (
            receipt.observation_sha256,
            observation.semantic_sha256,
            "lookup observation digest",
        ),
        (
            receipt.description_sha256,
            description.semantic_sha256,
            "lookup description digest",
        ),
        (
            receipt.submission_sha256,
            submission.semantic_sha256,
            "submission description digest",
        ),
        (
            receipt.client_order_id,
            submission.request.client_order_id,
            "client order ID",
        ),
        (receipt.order_id, submission.request.order_id, "local order ID"),
        (
            receipt.instrument_id,
            submission.intent.instrument_id,
            "instrument ID",
        ),
        (receipt.symbol, submission.intent.symbol, "symbol"),
        (receipt.http_status, observation.http_status, "HTTP status"),
        (
            receipt.provider_request_id,
            observation.provider_request_id,
            "provider request ID",
        ),
        (receipt.received_at, observation.received_at, "received_at"),
        (
            receipt.raw_recorded_at,
            delivery.recorded_at,
            "raw recorded_at",
        ),
        (
            receipt.provider_order_id,
            None if order is None else order.provider_order_id,
            "provider order ID",
        ),
        (
            receipt.provider_order_status,
            None if order is None else order.status.value,
            "provider order status",
        ),
        (
            receipt.observed_provider_asset_id,
            None if order is None else order.asset_id,
            "observed provider asset ID",
        ),
        (
            receipt.mismatch_fields,
            observation.mismatch_fields,
            "economic mismatch fields",
        ),
    )
    for actual, expected, field_name in expected_pairs:
        if actual != expected:
            raise AlpacaPaperReconciliationConflict(
                f"authenticated lookup conflicts with its exact {field_name} source"
            )

    if delivery.correlation_sha256 != receipt.description_sha256:
        raise AlpacaPaperReconciliationConflict(
            "authenticated lookup raw correlation conflicts with its description"
        )
    if delivery.transport_status != receipt.http_status:
        raise AlpacaPaperReconciliationConflict(
            "authenticated lookup raw transport status conflicts"
        )
    if delivery.provider_request_id != receipt.provider_request_id:
        raise AlpacaPaperReconciliationConflict(
            "authenticated lookup raw provider request ID conflicts"
        )
    if delivery.body != observation.response_body:
        raise AlpacaPaperReconciliationConflict(
            "authenticated lookup decoded bytes conflict with raw ingress"
        )


def _require_closed_outcome(
    receipt: AlpacaPaperAuthenticatedLookupReceipt,
    source: PersistedAlpacaClientOrderLookupObservation,
) -> BrokerReconciliationOutcome:
    observation = source.observation
    order = observation.order
    outcome = _outcome(receipt.outcome)

    if receipt.outcome is AlpacaPaperAuthenticatedLookupOutcome.NOT_VISIBLE_INCONCLUSIVE:
        if (
            observation.outcome is not AlpacaClientOrderLookupOutcome.NOT_VISIBLE_INCONCLUSIVE
            or order is not None
        ):
            raise AlpacaPaperReconciliationConflict(
                "not-visible receipt conflicts with its exact observation"
            )
        return outcome
    if order is None:
        raise AlpacaPaperReconciliationConflict(
            "observed-order reconciliation outcome lacks an exact order"
        )

    security_mismatch = order.asset_id != receipt.expected_provider_asset_id
    if receipt.outcome is AlpacaPaperAuthenticatedLookupOutcome.SECURITY_IDENTITY_MISMATCH:
        if not security_mismatch:
            raise AlpacaPaperReconciliationConflict(
                "security quarantine lacks an independently pinned asset mismatch"
            )
        if observation.outcome not in {
            AlpacaClientOrderLookupOutcome.FOUND_MATCHED,
            AlpacaClientOrderLookupOutcome.FOUND_MISMATCH,
        }:
            raise AlpacaPaperReconciliationConflict(
                "security quarantine lacks an exact found-order observation"
            )
        return outcome
    if security_mismatch:
        raise AlpacaPaperReconciliationConflict(
            "non-security reconciliation outcome hides a provider asset mismatch"
        )
    if (
        receipt.outcome is AlpacaPaperAuthenticatedLookupOutcome.FOUND_MATCHED
        and observation.outcome is not AlpacaClientOrderLookupOutcome.FOUND_MATCHED
    ):
        raise AlpacaPaperReconciliationConflict(
            "order-observed candidate conflicts with economic comparison"
        )
    if (
        receipt.outcome is AlpacaPaperAuthenticatedLookupOutcome.FOUND_MISMATCH
        and observation.outcome is not AlpacaClientOrderLookupOutcome.FOUND_MISMATCH
    ):
        raise AlpacaPaperReconciliationConflict(
            "economic quarantine conflicts with exact comparison fields"
        )
    return outcome


def normalize_authenticated_alpaca_paper_lookup(
    receipt: AlpacaPaperAuthenticatedLookupReceipt,
    source: PersistedAlpacaClientOrderLookupObservation,
) -> BrokerReconciliationEvidence:
    """Normalize one exact authenticated lookup into non-applying evidence."""

    if type(receipt) is not AlpacaPaperAuthenticatedLookupReceipt:
        raise AlpacaPaperReconciliationError(
            "Alpaca reconciliation requires an exact authenticated lookup receipt"
        )
    if type(source) is not PersistedAlpacaClientOrderLookupObservation:
        raise AlpacaPaperReconciliationError(
            "Alpaca reconciliation requires an exact persisted lookup source"
        )
    try:
        receipt._validate()
        receipt_digest = receipt.semantic_sha256
        source.__post_init__()
        _require_source_binding(receipt, source)
        outcome = _require_closed_outcome(receipt, source)
    except AlpacaPaperReconciliationError:
        raise
    except AlpacaPaperContractError as error:
        raise AlpacaPaperReconciliationError(
            "Alpaca reconciliation source authentication failed"
        ) from error
    except (TypeError, ValueError) as error:
        raise AlpacaPaperReconciliationError(
            "Alpaca reconciliation source authentication failed"
        ) from error

    raw_receipt = source.receipt
    delivery = raw_receipt.delivery
    observation = source.observation
    order = observation.order
    evidence = BrokerReconciliationEvidence(
        account_id=receipt.account_id,
        provider_id=ALPACA_PAPER_ADAPTER_ID,
        environment="paper",
        attempt_id=receipt.attempt_id,
        order_id=receipt.order_id,
        client_order_id=receipt.client_order_id,
        instrument_id=receipt.instrument_id,
        symbol=receipt.symbol,
        outcome=outcome,
        expected_provider_asset_id=receipt.expected_provider_asset_id,
        provider_order_id=None if order is None else order.provider_order_id,
        provider_order_status=None if order is None else order.status.value,
        provider_replaced_by=None if order is None else order.replaced_by,
        provider_replaces=None if order is None else order.replaces,
        observed_provider_asset_id=None if order is None else order.asset_id,
        mismatch_fields=observation.mismatch_fields,
        provider_timestamps=_provider_timestamps(order),
        requested_quantity=None if order is None else order.quantity,
        requested_notional=None if order is None else order.notional,
        cumulative_filled_quantity=(None if order is None else order.filled_quantity),
        cumulative_filled_average_price=(None if order is None else order.filled_average_price),
        provider_source=None if order is None else order.source,
        source_lookup_receipt_id=receipt.receipt_id,
        source_lookup_receipt_sha256=receipt_digest,
        source_ingress_receipt_id=raw_receipt.receipt_id,
        source_ingress_receipt_sha256=raw_receipt.semantic_sha256,
        source_ingress_sequence=raw_receipt.ingress_sequence,
        source_delivery_idempotency_key=delivery.delivery_idempotency_key,
        source_observation_sha256=observation.semantic_sha256,
        source_body_sha256=delivery.body_sha256,
        http_status=observation.http_status,
        provider_request_id=observation.provider_request_id,
        received_at=observation.received_at,
        raw_recorded_at=delivery.recorded_at,
        authenticated_at=receipt.authenticated_at,
        source_committed_at=receipt.commit_checked_at,
    )
    evidence.__post_init__()
    return evidence


__all__ = [
    "ALPACA_PAPER_RECONCILIATION_NORMALIZATION_CONTRACT_VERSION",
    "AlpacaPaperReconciliationConflict",
    "AlpacaPaperReconciliationError",
    "normalize_authenticated_alpaca_paper_lookup",
]
