"""Application workflow for durable, non-applying Alpaca reconciliation.

The workflow composes authenticated persistence loaders, reconstructs the exact
historical UNKNOWN attempt and raw-first lookup observation, invokes the pure
Phase 4K adapter normalizer, and records the resulting provider-neutral fact.
It performs no broker I/O and grants no lifecycle or trading authority.
"""

from __future__ import annotations

from typing import Protocol

from packages.adapters.broker.alpaca_paper import (
    AlpacaPaperContractError,
    create_alpaca_paper_submission_description,
)
from packages.adapters.broker.alpaca_paper_ingress import (
    PersistedAlpacaClientOrderLookupObservation,
)
from packages.adapters.broker.alpaca_paper_lookup_runtime import (
    AlpacaPaperAuthenticatedLookupReceipt,
)
from packages.adapters.broker.alpaca_paper_observations import (
    create_alpaca_client_order_lookup_description,
    decode_alpaca_client_order_lookup_response,
)
from packages.adapters.broker.alpaca_paper_reconciliation import (
    normalize_authenticated_alpaca_paper_lookup,
)
from packages.domain.broker_ingress import BrokerIngressReceipt
from packages.domain.broker_reconciliation import (
    BrokerReconciliationFact,
    BrokerReconciliationRepository,
)
from packages.domain.submission_attempt import (
    CanonicalSubmissionAttempt,
    SubmissionAttemptError,
    reduce_submission_attempt,
)


class AlpacaPaperReconciliationNormalizationError(RuntimeError):
    """The requested reconciliation source cannot be normalized safely."""


class AlpacaPaperReconciliationSourceMissing(AlpacaPaperReconciliationNormalizationError):
    """An immutable source referenced by the lookup receipt is absent."""


class AlpacaPaperReconciliationSourceConflict(AlpacaPaperReconciliationNormalizationError):
    """Loaded reconciliation sources conflict with authenticated identities."""


class AlpacaPaperAuthenticatedLookupLoader(Protocol):
    """Load a fully authenticated Phase 4I lookup receipt."""

    def load(
        self,
        receipt_id: str,
    ) -> AlpacaPaperAuthenticatedLookupReceipt | None: ...


class AlpacaPaperSubmissionAttemptLoader(Protocol):
    """Load the complete current history for one submission attempt."""

    def get(self, attempt_id: str) -> CanonicalSubmissionAttempt | None: ...


class AlpacaPaperIngressReceiptLoader(Protocol):
    """Load an authenticated raw broker-ingress receipt."""

    def load(self, receipt_id: str) -> BrokerIngressReceipt | None: ...


def _historical_unknown_attempt(
    current: CanonicalSubmissionAttempt,
    receipt: AlpacaPaperAuthenticatedLookupReceipt,
) -> CanonicalSubmissionAttempt:
    if type(current) is not CanonicalSubmissionAttempt:
        raise AlpacaPaperReconciliationSourceConflict(
            "submission loader returned a non-canonical attempt"
        )
    try:
        reconstructed_current = reduce_submission_attempt(
            current.preparation,
            current.events,
        )
    except SubmissionAttemptError as error:
        raise AlpacaPaperReconciliationSourceConflict(
            "submission loader returned invalid reducer history"
        ) from error
    if reconstructed_current != current:
        raise AlpacaPaperReconciliationSourceConflict(
            "submission loader returned history inconsistent with its reducer"
        )
    terminal_position = next(
        (
            position
            for position, event in enumerate(current.events)
            if event.event_id == receipt.terminal_event_id
        ),
        None,
    )
    if terminal_position is None:
        raise AlpacaPaperReconciliationSourceConflict(
            "lookup receipt terminal UNKNOWN event is absent from submission history"
        )
    try:
        historical = reduce_submission_attempt(
            current.preparation,
            current.events[: terminal_position + 1],
        )
    except SubmissionAttemptError as error:
        raise AlpacaPaperReconciliationSourceConflict(
            "lookup receipt historical attempt cannot be reconstructed"
        ) from error
    event = historical.events[-1]
    if (
        historical.attempt_id != receipt.attempt_id
        or historical.preparation.account_id != receipt.account_id
        or historical.semantic_sha256 != receipt.attempt_sha256
        or event.event_id != receipt.terminal_event_id
        or event.semantic_sha256 != receipt.terminal_event_sha256
        or event.sequence_number != receipt.terminal_event_sequence
    ):
        raise AlpacaPaperReconciliationSourceConflict(
            "lookup receipt conflicts with historical submission evidence"
        )
    return historical


def _persisted_source(
    *,
    receipt: AlpacaPaperAuthenticatedLookupReceipt,
    attempt: CanonicalSubmissionAttempt,
    ingress: BrokerIngressReceipt,
) -> PersistedAlpacaClientOrderLookupObservation:
    try:
        submission = create_alpaca_paper_submission_description(attempt.preparation.intent)
        if (
            submission.request != attempt.preparation.request
            or submission.semantic_sha256 != receipt.submission_sha256
        ):
            raise AlpacaPaperReconciliationSourceConflict(
                "lookup receipt conflicts with its historical submission description"
            )
        description = create_alpaca_client_order_lookup_description(
            account_id=receipt.account_id,
            submission=submission,
        )
        if description.semantic_sha256 != receipt.description_sha256:
            raise AlpacaPaperReconciliationSourceConflict(
                "lookup receipt conflicts with its reconstructed lookup description"
            )
        observation = decode_alpaca_client_order_lookup_response(
            description,
            http_status=receipt.http_status,
            provider_request_id=receipt.provider_request_id,
            response_body=ingress.delivery.body,
            received_at=receipt.received_at,
        )
        return PersistedAlpacaClientOrderLookupObservation(
            receipt=ingress,
            observation=observation,
        )
    except AlpacaPaperReconciliationNormalizationError:
        raise
    except (AlpacaPaperContractError, TypeError, ValueError) as error:
        raise AlpacaPaperReconciliationSourceConflict(
            "lookup raw source failed deterministic reconstruction"
        ) from error


def normalize_and_record_authenticated_alpaca_paper_lookup(
    receipt_id: str,
    *,
    lookup_loader: AlpacaPaperAuthenticatedLookupLoader,
    attempt_loader: AlpacaPaperSubmissionAttemptLoader,
    ingress_loader: AlpacaPaperIngressReceiptLoader,
    reconciliation_repository: BrokerReconciliationRepository,
) -> BrokerReconciliationFact:
    """Load, normalize, and durably append one authenticated lookup source."""

    if (
        type(receipt_id) is not str
        or not receipt_id
        or receipt_id != receipt_id.strip()
        or len(receipt_id) > 128
    ):
        raise AlpacaPaperReconciliationNormalizationError(
            "reconciliation lookup receipt ID must be bounded trimmed text"
        )
    for port, method_name, port_name in (
        (lookup_loader, "load", "authenticated lookup loader"),
        (attempt_loader, "get", "submission attempt loader"),
        (ingress_loader, "load", "raw ingress loader"),
        (
            reconciliation_repository,
            "record",
            "reconciliation repository",
        ),
    ):
        if not callable(getattr(port, method_name, None)):
            raise AlpacaPaperReconciliationNormalizationError(
                f"{port_name} does not implement {method_name}"
            )

    receipt = lookup_loader.load(receipt_id)
    if receipt is None:
        raise AlpacaPaperReconciliationSourceMissing("authenticated lookup receipt is absent")
    if type(receipt) is not AlpacaPaperAuthenticatedLookupReceipt:
        raise AlpacaPaperReconciliationSourceConflict(
            "lookup loader returned a non-canonical receipt"
        )
    try:
        receipt._validate()
        if receipt.receipt_id != receipt_id:
            raise AlpacaPaperReconciliationSourceConflict(
                "lookup loader returned a different receipt identity"
            )
    except AlpacaPaperReconciliationNormalizationError:
        raise
    except (AlpacaPaperContractError, TypeError, ValueError) as error:
        raise AlpacaPaperReconciliationSourceConflict(
            "lookup loader returned an invalid authenticated receipt"
        ) from error

    current_attempt = attempt_loader.get(receipt.attempt_id)
    if current_attempt is None:
        raise AlpacaPaperReconciliationSourceMissing("lookup receipt submission history is absent")
    attempt = _historical_unknown_attempt(current_attempt, receipt)

    ingress = ingress_loader.load(receipt.ingress_receipt_id)
    if ingress is None:
        raise AlpacaPaperReconciliationSourceMissing("lookup receipt raw ingress source is absent")
    if type(ingress) is not BrokerIngressReceipt:
        raise AlpacaPaperReconciliationSourceConflict(
            "raw ingress loader returned a non-canonical receipt"
        )
    try:
        ingress.__post_init__()
    except (TypeError, ValueError) as error:
        raise AlpacaPaperReconciliationSourceConflict(
            "raw ingress loader returned invalid source evidence"
        ) from error
    if (
        ingress.receipt_id != receipt.ingress_receipt_id
        or ingress.semantic_sha256 != receipt.ingress_receipt_sha256
    ):
        raise AlpacaPaperReconciliationSourceConflict(
            "lookup receipt conflicts with loaded raw ingress identity"
        )

    source = _persisted_source(
        receipt=receipt,
        attempt=attempt,
        ingress=ingress,
    )
    try:
        evidence = normalize_authenticated_alpaca_paper_lookup(receipt, source)
        fact = reconciliation_repository.record(evidence)
    except AlpacaPaperReconciliationNormalizationError:
        raise
    except (AlpacaPaperContractError, TypeError, ValueError) as error:
        raise AlpacaPaperReconciliationSourceConflict(
            "reconciliation normalization or durable append failed"
        ) from error
    if type(fact) is not BrokerReconciliationFact:
        raise AlpacaPaperReconciliationSourceConflict(
            "reconciliation repository returned a non-canonical fact"
        )
    try:
        fact._validate()
    except (TypeError, ValueError) as error:
        raise AlpacaPaperReconciliationSourceConflict(
            "reconciliation repository returned invalid durable evidence"
        ) from error
    if fact.evidence != evidence:
        raise AlpacaPaperReconciliationSourceConflict(
            "reconciliation repository changed normalized evidence"
        )
    return fact


__all__ = [
    "AlpacaPaperAuthenticatedLookupLoader",
    "AlpacaPaperIngressReceiptLoader",
    "AlpacaPaperReconciliationNormalizationError",
    "AlpacaPaperReconciliationSourceConflict",
    "AlpacaPaperReconciliationSourceMissing",
    "AlpacaPaperSubmissionAttemptLoader",
    "normalize_and_record_authenticated_alpaca_paper_lookup",
]
