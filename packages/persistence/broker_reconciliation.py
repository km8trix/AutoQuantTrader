"""Durable non-applying broker reconciliation evidence."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError

from packages.adapters.broker.alpaca_paper import (
    AlpacaPaperContractError,
    create_alpaca_paper_submission_description,
)
from packages.adapters.broker.alpaca_paper_ingress import (
    PersistedAlpacaClientOrderLookupObservation,
)
from packages.adapters.broker.alpaca_paper_observations import (
    create_alpaca_client_order_lookup_description,
    decode_alpaca_client_order_lookup_response,
)
from packages.adapters.broker.alpaca_paper_reconciliation import (
    normalize_authenticated_alpaca_paper_lookup,
)
from packages.domain.account_coordinator import AccountCoordinatorError
from packages.domain.broker_ingress import BrokerIngressError
from packages.domain.broker_reconciliation import (
    BrokerProviderTimestampEvidence,
    BrokerReconciliationConflict,
    BrokerReconciliationError,
    BrokerReconciliationEvidence,
    BrokerReconciliationFact,
    BrokerReconciliationOutcome,
    _broker_reconciliation_fact,
)
from packages.domain.canonical import (
    canonical_decimal,
    canonical_decimal_text,
    canonical_json_text,
)
from packages.domain.clock import Clock
from packages.persistence.account_coordinator import (
    _write_transaction,
    lock_account_capacity_serialization,
)
from packages.persistence.alpaca_paper_lookup_observation import (
    _authenticate_durable_sources as _authenticate_lookup_sources,
)
from packages.persistence.alpaca_paper_lookup_observation import (
    _historical_unknown_attempt,
)
from packages.persistence.alpaca_paper_lookup_observation import (
    _receipt_by_id as _lookup_receipt_by_id,
)
from packages.persistence.broker_ingress import (
    _authenticate_receipt_position as _authenticate_ingress_position,
)
from packages.persistence.broker_ingress import (
    _receipt_by_id as _ingress_receipt_by_id,
)
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.immutable import as_aware_utc, assert_immutable
from packages.persistence.schema import (
    phase4_broker_reconciliation_facts,
    phase4_broker_reconciliation_heads,
)

BROKER_RECONCILIATION_PERSISTENCE_CONTRACT_VERSION = "phase4k-broker-reconciliation-persistence-v1"
_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})

BrokerReconciliationRow = Mapping[str, object] | RowMapping


class BrokerReconciliationPersistenceError(BrokerReconciliationError):
    """Durable broker reconciliation history is malformed or unavailable."""


class BrokerReconciliationPersistenceConflict(
    BrokerReconciliationConflict,
    BrokerReconciliationPersistenceError,
):
    """Durable broker reconciliation history conflicts with immutable evidence."""


@dataclass(frozen=True, slots=True)
class _BrokerReconciliationHead:
    account_id: str
    last_account_sequence: int
    last_fact_id: str
    last_fact_sha256: str
    last_normalized_at: datetime


def _required_text(row: BrokerReconciliationRow, field_name: str) -> str:
    value = row[field_name]
    if type(value) is not str or not value:
        raise BrokerReconciliationPersistenceError(
            f"persisted broker reconciliation {field_name} is malformed"
        )
    return value


def _optional_text(
    row: BrokerReconciliationRow,
    field_name: str,
) -> str | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not str:
        raise BrokerReconciliationPersistenceError(
            f"persisted broker reconciliation {field_name} is malformed"
        )
    return value


def _required_integer(
    row: BrokerReconciliationRow,
    field_name: str,
) -> int:
    value = row[field_name]
    if type(value) is not int:
        raise BrokerReconciliationPersistenceError(
            f"persisted broker reconciliation {field_name} is malformed"
        )
    return value


def _required_datetime(
    row: BrokerReconciliationRow,
    field_name: str,
) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise BrokerReconciliationPersistenceError(
            f"persisted broker reconciliation {field_name} is malformed"
        )
    return as_aware_utc(value)


def _trusted_utc(value: object, field_name: str) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise BrokerReconciliationPersistenceError(
            f"broker reconciliation {field_name} must be an exact UTC datetime"
        )
    return value


def _json_payload(value: object) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, RecursionError) as error:
        raise BrokerReconciliationPersistenceError(
            "broker reconciliation SQL payload is not canonical JSON"
        ) from error


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BrokerReconciliationPersistenceError(
                "persisted broker reconciliation JSON has a duplicate key"
            )
        result[key] = value
    return result


def _decode_json_payload(value: object, field_name: str) -> object:
    if type(value) is not str:
        raise BrokerReconciliationPersistenceError(
            f"persisted broker reconciliation {field_name} is malformed"
        )
    try:
        decoded = json.loads(value, object_pairs_hook=_reject_duplicate_keys)
    except BrokerReconciliationPersistenceError:
        raise
    except (TypeError, ValueError, RecursionError) as error:
        raise BrokerReconciliationPersistenceError(
            f"persisted broker reconciliation {field_name} is malformed"
        ) from error
    return decoded


def _mismatch_fields_payload(values: tuple[str, ...]) -> str:
    if type(values) is not tuple or any(type(value) is not str for value in values):
        raise BrokerReconciliationPersistenceError(
            "broker reconciliation mismatch fields must be an exact tuple"
        )
    return _json_payload(values)


def _mismatch_fields_from_payload(value: object) -> tuple[str, ...]:
    decoded = _decode_json_payload(value, "mismatch fields payload")
    if type(decoded) is not list or any(type(item) is not str for item in decoded):
        raise BrokerReconciliationPersistenceError(
            "persisted broker reconciliation mismatch fields are malformed"
        )
    result = tuple(decoded)
    if len(set(result)) != len(result) or _mismatch_fields_payload(result) != value:
        raise BrokerReconciliationPersistenceError(
            "persisted broker reconciliation mismatch fields are not canonical"
        )
    return result


def _provider_timestamps_payload(
    timestamps: tuple[BrokerProviderTimestampEvidence, ...],
) -> str:
    if type(timestamps) is not tuple or any(
        type(timestamp) is not BrokerProviderTimestampEvidence for timestamp in timestamps
    ):
        raise BrokerReconciliationPersistenceError(
            "broker reconciliation provider timestamps must be an exact tuple"
        )
    return _json_payload(
        tuple(
            (
                timestamp.field_name,
                timestamp.raw,
                timestamp.normalized_utc,
                timestamp.nanosecond,
            )
            for timestamp in timestamps
        )
    )


def _provider_timestamps_from_payload(
    value: object,
) -> tuple[BrokerProviderTimestampEvidence, ...]:
    decoded = _decode_json_payload(value, "provider timestamps payload")
    if type(decoded) is not list:
        raise BrokerReconciliationPersistenceError(
            "persisted broker reconciliation provider timestamps are malformed"
        )
    timestamps: list[BrokerProviderTimestampEvidence] = []
    for item in decoded:
        if (
            type(item) is not list
            or len(item) != 4
            or type(item[0]) is not str
            or type(item[1]) is not str
            or type(item[2]) is not str
            or type(item[3]) is not int
        ):
            raise BrokerReconciliationPersistenceError(
                "persisted broker reconciliation provider timestamps are malformed"
            )
        timestamps.append(
            BrokerProviderTimestampEvidence(
                field_name=item[0],
                raw=item[1],
                normalized_utc=item[2],
                nanosecond=item[3],
            )
        )
    result = tuple(timestamps)
    if _provider_timestamps_payload(result) != value:
        raise BrokerReconciliationPersistenceError(
            "persisted broker reconciliation provider timestamps are not canonical"
        )
    return result


def _optional_decimal_text(value: Decimal | None) -> str | None:
    if value is None:
        return None
    if type(value) is not Decimal or not value.is_finite():
        raise BrokerReconciliationPersistenceError(
            "broker reconciliation Decimal must be exact and finite"
        )
    return canonical_decimal_text(value)


def _optional_decimal_from_row(
    row: BrokerReconciliationRow,
    field_name: str,
) -> Decimal | None:
    raw = _optional_text(row, field_name)
    if raw is None:
        return None
    try:
        result = canonical_decimal(Decimal(raw))
    except (InvalidOperation, ValueError) as error:
        raise BrokerReconciliationPersistenceError(
            f"persisted broker reconciliation {field_name} is not a finite Decimal"
        ) from error
    if canonical_decimal_text(result) != raw:
        raise BrokerReconciliationPersistenceError(
            f"persisted broker reconciliation {field_name} is not canonical"
        )
    return result


def _fact_payload(fact: BrokerReconciliationFact) -> tuple[object, ...]:
    return (
        BROKER_RECONCILIATION_PERSISTENCE_CONTRACT_VERSION,
        "fact",
        fact.fact_id,
        fact.evidence.semantic_sha256,
        fact.normalized_at,
        fact.account_sequence,
        fact.previous_fact_sha256,
    )


def immutable_broker_reconciliation_values(
    fact: BrokerReconciliationFact,
) -> dict[str, object]:
    """Return the complete canonical SQL representation of one fact."""

    if type(fact) is not BrokerReconciliationFact:
        raise BrokerReconciliationPersistenceError(
            "broker reconciliation persistence requires an exact fact"
        )
    fact._validate()
    evidence = fact.evidence
    return {
        "fact_id": fact.fact_id,
        "account_id": evidence.account_id,
        "account_sequence": fact.account_sequence,
        "previous_fact_sha256": fact.previous_fact_sha256,
        "provider_id": evidence.provider_id,
        "environment": evidence.environment,
        "attempt_id": evidence.attempt_id,
        "order_id": evidence.order_id,
        "client_order_id": evidence.client_order_id,
        "instrument_id": evidence.instrument_id,
        "symbol": evidence.symbol,
        "outcome": evidence.outcome.value,
        "expected_provider_asset_id": evidence.expected_provider_asset_id,
        "provider_order_id": evidence.provider_order_id,
        "provider_order_status": evidence.provider_order_status,
        "provider_replaced_by": evidence.provider_replaced_by,
        "provider_replaces": evidence.provider_replaces,
        "observed_provider_asset_id": evidence.observed_provider_asset_id,
        "mismatch_fields_payload": _mismatch_fields_payload(evidence.mismatch_fields),
        "provider_timestamps_payload": _provider_timestamps_payload(evidence.provider_timestamps),
        "requested_quantity": _optional_decimal_text(evidence.requested_quantity),
        "requested_notional": _optional_decimal_text(evidence.requested_notional),
        "cumulative_filled_quantity": _optional_decimal_text(evidence.cumulative_filled_quantity),
        "cumulative_filled_average_price": _optional_decimal_text(
            evidence.cumulative_filled_average_price
        ),
        "provider_source": evidence.provider_source,
        "source_lookup_receipt_id": evidence.source_lookup_receipt_id,
        "source_lookup_receipt_sha256": (evidence.source_lookup_receipt_sha256),
        "source_ingress_receipt_id": evidence.source_ingress_receipt_id,
        "source_ingress_receipt_sha256": (evidence.source_ingress_receipt_sha256),
        "source_ingress_sequence": evidence.source_ingress_sequence,
        "source_delivery_idempotency_key": (evidence.source_delivery_idempotency_key),
        "source_observation_sha256": evidence.source_observation_sha256,
        "source_body_sha256": evidence.source_body_sha256,
        "http_status": evidence.http_status,
        "provider_request_id": evidence.provider_request_id,
        "received_at": evidence.received_at,
        "raw_recorded_at": evidence.raw_recorded_at,
        "authenticated_at": evidence.authenticated_at,
        "source_committed_at": evidence.source_committed_at,
        "normalized_at": fact.normalized_at,
        "canonical_payload": canonical_json_text(_fact_payload(fact)),
        "semantic_sha256": fact.semantic_sha256,
    }


def broker_reconciliation_fact_from_row(
    row: BrokerReconciliationRow,
) -> BrokerReconciliationFact:
    """Strictly rehydrate and authenticate one persisted fact."""

    try:
        outcome = BrokerReconciliationOutcome(_required_text(row, "outcome"))
        evidence = BrokerReconciliationEvidence(
            account_id=_required_text(row, "account_id"),
            provider_id=_required_text(row, "provider_id"),
            environment=_required_text(row, "environment"),
            attempt_id=_required_text(row, "attempt_id"),
            order_id=_required_text(row, "order_id"),
            client_order_id=_required_text(row, "client_order_id"),
            instrument_id=_required_text(row, "instrument_id"),
            symbol=_required_text(row, "symbol"),
            outcome=outcome,
            expected_provider_asset_id=_required_text(
                row,
                "expected_provider_asset_id",
            ),
            provider_order_id=_optional_text(row, "provider_order_id"),
            provider_order_status=_optional_text(
                row,
                "provider_order_status",
            ),
            provider_replaced_by=_optional_text(
                row,
                "provider_replaced_by",
            ),
            provider_replaces=_optional_text(
                row,
                "provider_replaces",
            ),
            observed_provider_asset_id=_optional_text(
                row,
                "observed_provider_asset_id",
            ),
            mismatch_fields=_mismatch_fields_from_payload(row["mismatch_fields_payload"]),
            provider_timestamps=_provider_timestamps_from_payload(
                row["provider_timestamps_payload"]
            ),
            requested_quantity=_optional_decimal_from_row(
                row,
                "requested_quantity",
            ),
            requested_notional=_optional_decimal_from_row(
                row,
                "requested_notional",
            ),
            cumulative_filled_quantity=_optional_decimal_from_row(
                row,
                "cumulative_filled_quantity",
            ),
            cumulative_filled_average_price=_optional_decimal_from_row(
                row,
                "cumulative_filled_average_price",
            ),
            provider_source=_optional_text(row, "provider_source"),
            source_lookup_receipt_id=_required_text(
                row,
                "source_lookup_receipt_id",
            ),
            source_lookup_receipt_sha256=_required_text(
                row,
                "source_lookup_receipt_sha256",
            ),
            source_ingress_receipt_id=_required_text(
                row,
                "source_ingress_receipt_id",
            ),
            source_ingress_receipt_sha256=_required_text(
                row,
                "source_ingress_receipt_sha256",
            ),
            source_ingress_sequence=_required_integer(
                row,
                "source_ingress_sequence",
            ),
            source_delivery_idempotency_key=_required_text(
                row,
                "source_delivery_idempotency_key",
            ),
            source_observation_sha256=_required_text(
                row,
                "source_observation_sha256",
            ),
            source_body_sha256=_required_text(
                row,
                "source_body_sha256",
            ),
            http_status=_required_integer(row, "http_status"),
            provider_request_id=_required_text(row, "provider_request_id"),
            received_at=_required_datetime(row, "received_at"),
            raw_recorded_at=_required_datetime(row, "raw_recorded_at"),
            authenticated_at=_required_datetime(row, "authenticated_at"),
            source_committed_at=_required_datetime(
                row,
                "source_committed_at",
            ),
        )
        fact = _broker_reconciliation_fact(
            evidence,
            normalized_at=_required_datetime(row, "normalized_at"),
            account_sequence=_required_integer(row, "account_sequence"),
            previous_fact_sha256=_optional_text(
                row,
                "previous_fact_sha256",
            ),
        )
        duplicated_values = (
            ("fact_id", fact.fact_id),
            (
                "canonical_payload",
                canonical_json_text(_fact_payload(fact)),
            ),
            ("semantic_sha256", fact.semantic_sha256),
        )
        for field_name, expected in duplicated_values:
            if row[field_name] != expected:
                raise BrokerReconciliationPersistenceConflict(
                    f"persisted broker reconciliation {field_name} conflicts"
                )
        return fact
    except BrokerReconciliationError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise BrokerReconciliationPersistenceError(
            "persisted broker reconciliation fact is malformed"
        ) from error


def _head_from_row(
    row: BrokerReconciliationRow,
) -> _BrokerReconciliationHead:
    try:
        fact_id = _required_text(row, "last_fact_id")
        parsed = UUID(fact_id)
        head = _BrokerReconciliationHead(
            account_id=_required_text(row, "account_id"),
            last_account_sequence=_required_integer(
                row,
                "last_account_sequence",
            ),
            last_fact_id=fact_id,
            last_fact_sha256=_required_text(row, "last_fact_sha256"),
            last_normalized_at=_required_datetime(
                row,
                "last_normalized_at",
            ),
        )
        if (
            str(parsed) != fact_id
            or head.last_account_sequence <= 0
            or len(head.last_fact_sha256) != 64
        ):
            raise BrokerReconciliationPersistenceError(
                "persisted broker reconciliation head is malformed"
            )
        return head
    except BrokerReconciliationError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise BrokerReconciliationPersistenceError(
            "persisted broker reconciliation head is malformed"
        ) from error


def _head(
    connection: Connection,
    account_id: str,
) -> _BrokerReconciliationHead | None:
    row = (
        connection.execute(
            sa.select(phase4_broker_reconciliation_heads).where(
                phase4_broker_reconciliation_heads.c.account_id == account_id
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else _head_from_row(row)


def _fact_by_id(
    connection: Connection,
    fact_id: str,
) -> BrokerReconciliationFact | None:
    row = (
        connection.execute(
            sa.select(phase4_broker_reconciliation_facts).where(
                phase4_broker_reconciliation_facts.c.fact_id == fact_id
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else broker_reconciliation_fact_from_row(row)


def _fact_by_lookup_source(
    connection: Connection,
    source_lookup_receipt_id: str,
) -> BrokerReconciliationFact | None:
    row = (
        connection.execute(
            sa.select(phase4_broker_reconciliation_facts).where(
                phase4_broker_reconciliation_facts.c.source_lookup_receipt_id
                == source_lookup_receipt_id
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else broker_reconciliation_fact_from_row(row)


def _fact_by_ingress_source(
    connection: Connection,
    source_ingress_receipt_id: str,
) -> BrokerReconciliationFact | None:
    row = (
        connection.execute(
            sa.select(phase4_broker_reconciliation_facts).where(
                phase4_broker_reconciliation_facts.c.source_ingress_receipt_id
                == source_ingress_receipt_id
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else broker_reconciliation_fact_from_row(row)


def _expected_evidence_from_sources(
    connection: Connection,
    evidence: BrokerReconciliationEvidence,
) -> BrokerReconciliationEvidence:
    lookup = _lookup_receipt_by_id(
        connection,
        evidence.source_lookup_receipt_id,
    )
    if lookup is None:
        raise BrokerReconciliationPersistenceConflict(
            "reconciliation fact references a missing authenticated lookup"
        )
    _authenticate_lookup_sources(connection, lookup)
    ingress = _ingress_receipt_by_id(
        connection,
        evidence.source_ingress_receipt_id,
    )
    if ingress is None:
        raise BrokerReconciliationPersistenceConflict(
            "reconciliation fact references a missing raw ingress receipt"
        )
    _authenticate_ingress_position(connection, ingress)
    if (
        lookup.account_id != evidence.account_id
        or lookup.attempt_id != evidence.attempt_id
        or lookup.semantic_sha256 != evidence.source_lookup_receipt_sha256
        or lookup.ingress_receipt_id != ingress.receipt_id
        or lookup.ingress_receipt_sha256 != ingress.semantic_sha256
        or ingress.receipt_id != evidence.source_ingress_receipt_id
        or ingress.semantic_sha256 != evidence.source_ingress_receipt_sha256
    ):
        raise BrokerReconciliationPersistenceConflict(
            "reconciliation fact conflicts with its exact durable sources"
        )

    attempt = _historical_unknown_attempt(connection, lookup)
    submission = create_alpaca_paper_submission_description(attempt.preparation.intent)
    description = create_alpaca_client_order_lookup_description(
        account_id=lookup.account_id,
        submission=submission,
    )
    observation = decode_alpaca_client_order_lookup_response(
        description,
        http_status=lookup.http_status,
        provider_request_id=lookup.provider_request_id,
        response_body=ingress.delivery.body,
        received_at=lookup.received_at,
    )
    source = PersistedAlpacaClientOrderLookupObservation(
        receipt=ingress,
        observation=observation,
    )
    expected = normalize_authenticated_alpaca_paper_lookup(lookup, source)
    if type(expected) is not BrokerReconciliationEvidence:
        raise BrokerReconciliationPersistenceConflict(
            "broker reconciliation normalizer returned non-canonical evidence"
        )
    expected.__post_init__()
    return expected


def _authenticate_durable_sources(
    connection: Connection,
    fact: BrokerReconciliationFact,
) -> None:
    try:
        expected = _expected_evidence_from_sources(connection, fact.evidence)
    except BrokerReconciliationError:
        raise
    except (AlpacaPaperContractError, BrokerIngressError):
        raise BrokerReconciliationPersistenceConflict(
            "broker reconciliation durable source authentication failed"
        ) from None
    if expected != fact.evidence:
        raise BrokerReconciliationPersistenceConflict(
            "broker reconciliation fact conflicts with source normalization"
        )


def _validate_history(
    connection: Connection,
    *,
    account_id: str,
    facts: Iterable[BrokerReconciliationFact],
    head: _BrokerReconciliationHead | None,
) -> tuple[BrokerReconciliationFact, ...]:
    result: list[BrokerReconciliationFact] = []
    previous: BrokerReconciliationFact | None = None
    for expected_sequence, fact in enumerate(facts, start=1):
        if (
            fact.evidence.account_id != account_id
            or fact.account_sequence != expected_sequence
            or fact.previous_fact_sha256 != (None if previous is None else previous.semantic_sha256)
            or (previous is not None and fact.normalized_at < previous.normalized_at)
        ):
            raise BrokerReconciliationPersistenceConflict(
                "broker reconciliation account history is discontinuous"
            )
        _authenticate_durable_sources(connection, fact)
        result.append(fact)
        previous = fact
    if previous is None:
        if head is not None:
            raise BrokerReconciliationPersistenceConflict(
                "broker reconciliation head exists without facts"
            )
        return ()
    if (
        head is None
        or head.account_id != account_id
        or head.last_account_sequence != len(result)
        or head.last_fact_id != previous.fact_id
        or head.last_fact_sha256 != previous.semantic_sha256
        or head.last_normalized_at != previous.normalized_at
    ):
        raise BrokerReconciliationPersistenceConflict(
            "broker reconciliation head conflicts with terminal history"
        )
    return tuple(result)


def _history(
    connection: Connection,
    account_id: str,
) -> tuple[BrokerReconciliationFact, ...]:
    rows = (
        connection.execute(
            sa.select(phase4_broker_reconciliation_facts)
            .where(phase4_broker_reconciliation_facts.c.account_id == account_id)
            .order_by(phase4_broker_reconciliation_facts.c.account_sequence)
        )
        .mappings()
        .all()
    )
    return _validate_history(
        connection,
        account_id=account_id,
        facts=(broker_reconciliation_fact_from_row(row) for row in rows),
        head=_head(connection, account_id),
    )


def _verify_broker_reconciliation_integrity(
    connection: Connection,
) -> None:
    fact_without_head = connection.scalar(
        sa.select(phase4_broker_reconciliation_facts.c.fact_id)
        .where(
            ~sa.exists(
                sa.select(1).where(
                    phase4_broker_reconciliation_heads.c.account_id
                    == phase4_broker_reconciliation_facts.c.account_id
                )
            )
        )
        .limit(1)
    )
    if fact_without_head is not None:
        raise BrokerReconciliationPersistenceConflict(
            "broker reconciliation facts exist without durable heads"
        )
    head_rows = connection.execute(
        sa.select(phase4_broker_reconciliation_heads)
        .order_by(phase4_broker_reconciliation_heads.c.account_id)
        .execution_options(yield_per=128)
    ).mappings()
    for head_row in head_rows:
        head = _head_from_row(head_row)
        rows = connection.execute(
            sa.select(phase4_broker_reconciliation_facts)
            .where(phase4_broker_reconciliation_facts.c.account_id == head.account_id)
            .order_by(phase4_broker_reconciliation_facts.c.account_sequence)
            .execution_options(yield_per=128)
        ).mappings()
        _validate_history(
            connection,
            account_id=head.account_id,
            facts=(broker_reconciliation_fact_from_row(row) for row in rows),
            head=head,
        )


def verify_broker_reconciliation_integrity(engine: Engine) -> None:
    """Authenticate every normalization chain in one stable snapshot."""

    if not isinstance(engine, Engine):
        raise BrokerReconciliationPersistenceError(
            "broker reconciliation verification requires an Engine"
        )
    if engine.dialect.name not in _SUPPORTED_DIALECTS:
        raise BrokerReconciliationPersistenceError(
            f"broker reconciliation verification does not support dialect {engine.dialect.name!r}"
        )
    with _repeatable_read_transaction(engine) as connection:
        _verify_broker_reconciliation_integrity(connection)


def _require_identifier(
    value: object,
    field_name: str,
    *,
    maximum: int,
) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise BrokerReconciliationPersistenceError(
            f"broker reconciliation {field_name} must be bounded trimmed text"
        )
    return value


class SqlBrokerReconciliationRepository:
    """Append exact non-applying evidence under the shared account lock."""

    __slots__ = ("_clock", "_engine")

    def __init__(
        self,
        *,
        engine: Engine,
        clock: Clock,
    ) -> None:
        if not isinstance(engine, Engine):
            raise BrokerReconciliationPersistenceError(
                "SQL broker reconciliation requires an Engine"
            )
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise BrokerReconciliationPersistenceError(
                f"SQL broker reconciliation does not support dialect {engine.dialect.name!r}"
            )
        if not callable(getattr(clock, "now", None)):
            raise BrokerReconciliationPersistenceError(
                "SQL broker reconciliation requires a trusted Clock"
            )
        self._engine = engine
        self._clock = clock

    @property
    def runtime_store_identity(self) -> int:
        """Identify the shared SQL engine for process-local composition checks."""

        return id(self._engine)

    def record(
        self,
        evidence: BrokerReconciliationEvidence,
    ) -> BrokerReconciliationFact:
        """Append normalized evidence or return its identical durable retry."""

        if type(evidence) is not BrokerReconciliationEvidence:
            raise BrokerReconciliationPersistenceError(
                "broker reconciliation recording requires exact evidence"
            )
        evidence.__post_init__()
        try:
            with _write_transaction(self._engine) as connection:
                lock_account_capacity_serialization(
                    connection,
                    evidence.account_id,
                )
                history = _history(connection, evidence.account_id)
                previous = None if not history else history[-1]
                expected_sequence = 1 if previous is None else previous.account_sequence + 1
                expected_predecessor = None if previous is None else previous.semantic_sha256
                existing_lookup = _fact_by_lookup_source(
                    connection,
                    evidence.source_lookup_receipt_id,
                )
                existing_ingress = _fact_by_ingress_source(
                    connection,
                    evidence.source_ingress_receipt_id,
                )
                if existing_lookup is not None or existing_ingress is not None:
                    if (
                        existing_lookup is None
                        or existing_ingress is None
                        or existing_lookup != existing_ingress
                    ):
                        raise BrokerReconciliationPersistenceConflict(
                            "broker reconciliation source was reused by another fact"
                        )
                    expected = _broker_reconciliation_fact(
                        evidence,
                        normalized_at=existing_lookup.normalized_at,
                        account_sequence=existing_lookup.account_sequence,
                        previous_fact_sha256=(existing_lookup.previous_fact_sha256),
                    )
                    if expected != existing_lookup:
                        raise BrokerReconciliationPersistenceConflict(
                            "broker reconciliation source identity conflicts"
                        )
                    _authenticate_durable_sources(connection, existing_lookup)
                    return existing_lookup

                try:
                    normalized_at = _trusted_utc(
                        self._clock.now(),
                        "normalization time",
                    )
                except BrokerReconciliationError:
                    raise
                except Exception:
                    raise BrokerReconciliationPersistenceError(
                        "broker reconciliation trusted clock failed"
                    ) from None
                if normalized_at < evidence.source_committed_at:
                    raise BrokerReconciliationPersistenceConflict(
                        "broker reconciliation normalization predates its source"
                    )
                fact = _broker_reconciliation_fact(
                    evidence,
                    normalized_at=normalized_at,
                    account_sequence=expected_sequence,
                    previous_fact_sha256=expected_predecessor,
                )
                by_id = _fact_by_id(connection, fact.fact_id)
                if by_id is not None:
                    raise BrokerReconciliationPersistenceConflict(
                        "broker reconciliation fact identity conflicts"
                    )
                if previous is not None and fact.normalized_at < previous.normalized_at:
                    raise BrokerReconciliationPersistenceConflict(
                        "broker reconciliation normalization time regressed"
                    )
                _authenticate_durable_sources(connection, fact)
                values = immutable_broker_reconciliation_values(fact)
                try:
                    connection.execute(
                        sa.insert(phase4_broker_reconciliation_facts).values(**values)
                    )
                except IntegrityError as error:
                    raise BrokerReconciliationPersistenceConflict(
                        "broker reconciliation fact conflicts with durable history"
                    ) from error

                if previous is None:
                    try:
                        connection.execute(
                            sa.insert(phase4_broker_reconciliation_heads).values(
                                account_id=evidence.account_id,
                                last_account_sequence=fact.account_sequence,
                                last_fact_id=fact.fact_id,
                                last_fact_sha256=fact.semantic_sha256,
                                last_normalized_at=fact.normalized_at,
                            )
                        )
                    except IntegrityError as error:
                        raise BrokerReconciliationPersistenceConflict(
                            "broker reconciliation head conflicts with history"
                        ) from error
                else:
                    updated = connection.execute(
                        sa.update(phase4_broker_reconciliation_heads)
                        .where(
                            phase4_broker_reconciliation_heads.c.account_id == evidence.account_id,
                            phase4_broker_reconciliation_heads.c.last_account_sequence
                            == previous.account_sequence,
                            phase4_broker_reconciliation_heads.c.last_fact_id == previous.fact_id,
                            phase4_broker_reconciliation_heads.c.last_fact_sha256
                            == previous.semantic_sha256,
                            phase4_broker_reconciliation_heads.c.last_normalized_at
                            == previous.normalized_at,
                        )
                        .values(
                            last_account_sequence=fact.account_sequence,
                            last_fact_id=fact.fact_id,
                            last_fact_sha256=fact.semantic_sha256,
                            last_normalized_at=fact.normalized_at,
                        )
                    )
                    if updated.rowcount != 1:
                        raise BrokerReconciliationPersistenceConflict(
                            "broker reconciliation head changed during append"
                        )

                row = (
                    connection.execute(
                        sa.select(phase4_broker_reconciliation_facts).where(
                            phase4_broker_reconciliation_facts.c.fact_id == fact.fact_id
                        )
                    )
                    .mappings()
                    .one()
                )
                persisted = broker_reconciliation_fact_from_row(row)
                if persisted != fact:
                    raise BrokerReconciliationPersistenceConflict(
                        "broker reconciliation failed exact SQL readback"
                    )
                assert_immutable(
                    phase4_broker_reconciliation_facts,
                    fact.fact_id,
                    row,
                    values,
                )
                terminal_history = _history(connection, evidence.account_id)
                if not terminal_history or terminal_history[-1] != fact:
                    raise BrokerReconciliationPersistenceConflict(
                        "broker reconciliation head failed exact SQL readback"
                    )
                return persisted
        except BrokerReconciliationError:
            raise
        except (AccountCoordinatorError, BrokerIngressError):
            raise BrokerReconciliationPersistenceConflict(
                "durable broker reconciliation source authentication failed"
            ) from None

    def load(self, fact_id: str) -> BrokerReconciliationFact | None:
        """Load one fact only after authenticating its complete account chain."""

        fact_id = _require_identifier(
            fact_id,
            "fact ID",
            maximum=36,
        )
        try:
            parsed = UUID(fact_id)
        except ValueError as error:
            raise BrokerReconciliationPersistenceError(
                "broker reconciliation fact ID must be a canonical UUID"
            ) from error
        if str(parsed) != fact_id:
            raise BrokerReconciliationPersistenceError(
                "broker reconciliation fact ID must be a canonical UUID"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            fact = _fact_by_id(connection, fact_id)
            if fact is None:
                return None
            history = _history(connection, fact.evidence.account_id)
            if fact not in history:
                raise BrokerReconciliationPersistenceConflict(
                    "broker reconciliation fact exists outside its durable head"
                )
            return fact

    def history(
        self,
        account_id: str,
    ) -> tuple[BrokerReconciliationFact, ...]:
        """Return one authenticated account-local normalization chain."""

        account_id = _require_identifier(
            account_id,
            "account ID",
            maximum=64,
        )
        with _repeatable_read_transaction(self._engine) as connection:
            return _history(connection, account_id)

    def load_by_lookup_receipt_id(
        self,
        lookup_receipt_id: str,
    ) -> BrokerReconciliationFact | None:
        """Load an authenticated fact selected by its exact Phase 4I source."""

        lookup_receipt_id = _require_identifier(
            lookup_receipt_id,
            "lookup receipt ID",
            maximum=36,
        )
        try:
            parsed = UUID(lookup_receipt_id)
        except ValueError as error:
            raise BrokerReconciliationPersistenceError(
                "broker reconciliation lookup receipt ID must be a canonical UUID"
            ) from error
        if str(parsed) != lookup_receipt_id:
            raise BrokerReconciliationPersistenceError(
                "broker reconciliation lookup receipt ID must be a canonical UUID"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            fact = _fact_by_lookup_source(
                connection,
                lookup_receipt_id,
            )
            if fact is None:
                return None
            history = _history(connection, fact.evidence.account_id)
            if fact not in history:
                raise BrokerReconciliationPersistenceConflict(
                    "broker reconciliation lookup source exists outside its durable head"
                )
            return fact


__all__ = [
    "BROKER_RECONCILIATION_PERSISTENCE_CONTRACT_VERSION",
    "BrokerReconciliationPersistenceConflict",
    "BrokerReconciliationPersistenceError",
    "SqlBrokerReconciliationRepository",
    "broker_reconciliation_fact_from_row",
    "immutable_broker_reconciliation_values",
    "verify_broker_reconciliation_integrity",
]
