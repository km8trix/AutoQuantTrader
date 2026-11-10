"""Durable source-scoped broker inbox admission evidence."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError

from packages.adapters.broker.alpaca_paper_inbox import (
    AlpacaPaperInboxError,
    create_alpaca_paper_inbox_admission_request,
)
from packages.domain.account_coordinator import AccountCoordinatorError
from packages.domain.broker_inbox import (
    BrokerInboxAdmissionRequest,
    BrokerInboxConflict,
    BrokerInboxError,
    BrokerInboxHistoricalObservationIdentity,
    BrokerInboxNonApplicationDecisionReceipt,
    BrokerInboxSourceKind,
    _broker_inbox_admission_request,
    decide_broker_inbox_admission,
)
from packages.domain.broker_ingress import BrokerIngressError
from packages.domain.broker_reconciliation import BrokerReconciliationError
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.clock import Clock
from packages.domain.identifiers import canonical_id
from packages.persistence.account_coordinator import (
    _write_transaction,
    lock_account_capacity_serialization,
)
from packages.persistence.broker_ingress import (
    _authenticate_receipt_position as _authenticate_ingress_position,
)
from packages.persistence.broker_ingress import (
    _receipt_by_id as _ingress_receipt_by_id,
)
from packages.persistence.broker_reconciliation import (
    _fact_by_id as _reconciliation_fact_by_id,
)
from packages.persistence.broker_reconciliation import (
    _history as _reconciliation_history,
)
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.immutable import (
    ImmutableFactConflict,
    as_aware_utc,
    assert_immutable,
)
from packages.persistence.schema import (
    phase4_broker_inbox_application_receipts,
    phase4_broker_inbox_heads,
    phase4_broker_inbox_source_links,
    phase4_broker_normalized_facts,
)

BROKER_INBOX_PERSISTENCE_CONTRACT_VERSION = "phase4l-broker-inbox-persistence-v1"
_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})

BrokerInboxRow = Mapping[str, object] | RowMapping


class BrokerInboxPersistenceError(BrokerInboxError):
    """Durable broker inbox evidence is malformed or unavailable."""


class BrokerInboxPersistenceConflict(
    BrokerInboxConflict,
    BrokerInboxPersistenceError,
):
    """Durable broker inbox evidence conflicts with immutable source history."""


def _required_text(row: BrokerInboxRow, field_name: str) -> str:
    value = row[field_name]
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise BrokerInboxPersistenceError(f"persisted broker inbox {field_name} is malformed")
    return value


def _optional_text(row: BrokerInboxRow, field_name: str) -> str | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not str:
        raise BrokerInboxPersistenceError(f"persisted broker inbox {field_name} is malformed")
    return value


def _required_integer(row: BrokerInboxRow, field_name: str) -> int:
    value = row[field_name]
    if type(value) is not int:
        raise BrokerInboxPersistenceError(f"persisted broker inbox {field_name} is malformed")
    return value


def _required_datetime(row: BrokerInboxRow, field_name: str) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise BrokerInboxPersistenceError(f"persisted broker inbox {field_name} is malformed")
    return as_aware_utc(value)


def _trusted_utc(value: object, field_name: str) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise BrokerInboxPersistenceError(
            f"broker inbox {field_name} must be an exact UTC datetime"
        )
    return value


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
        raise BrokerInboxPersistenceError(f"broker inbox {field_name} must be bounded trimmed text")
    return value


def _canonical_uuid(value: str, field_name: str) -> str:
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise BrokerInboxPersistenceError(
            f"broker inbox {field_name} must be a canonical UUID"
        ) from error
    if str(parsed) != value:
        raise BrokerInboxPersistenceError(f"broker inbox {field_name} must be a canonical UUID")
    return value


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class _BrokerInboxSourceLink:
    request: BrokerInboxAdmissionRequest
    account_sequence: int
    previous_link_sha256: str | None
    linked_at: datetime

    def __post_init__(self) -> None:
        if type(self.request) is not BrokerInboxAdmissionRequest:
            raise BrokerInboxPersistenceError(
                "broker inbox source link requires an exact admission request"
            )
        self.request._validate()
        if type(self.account_sequence) is not int or self.account_sequence <= 0:
            raise BrokerInboxPersistenceError("broker inbox source link sequence must be positive")
        if self.account_sequence == 1:
            if self.previous_link_sha256 is not None:
                raise BrokerInboxPersistenceConflict(
                    "first broker inbox source link cannot name a predecessor"
                )
        elif (
            type(self.previous_link_sha256) is not str
            or len(self.previous_link_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.previous_link_sha256)
        ):
            raise BrokerInboxPersistenceConflict(
                "broker inbox source link predecessor is malformed"
            )
        linked_at = _trusted_utc(self.linked_at, "source-link time")
        if linked_at < self.request.source_fact.normalized_at:
            raise BrokerInboxPersistenceConflict(
                "broker inbox source link predates its normalized source"
            )

    @property
    def account_id(self) -> str:
        return self.request.identity.account_id

    @property
    def link_id(self) -> str:
        return canonical_id(
            "broker-inbox-source-link",
            self.request.request_id,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        identity = self.request.identity
        source_fact = self.request.source_fact
        return (
            BROKER_INBOX_PERSISTENCE_CONTRACT_VERSION,
            "source_link",
            self.link_id,
            self.account_id,
            self.account_sequence,
            self.previous_link_sha256,
            self.request.request_id,
            self.request.semantic_sha256,
            identity.observation_id,
            source_fact.fact_id,
            source_fact.semantic_sha256,
            source_fact.evidence.semantic_sha256,
            source_fact.account_sequence,
            identity.source_lookup_receipt_id,
            identity.source_lookup_receipt_sha256,
            identity.source_ingress_receipt_id,
            identity.source_ingress_receipt_sha256,
            identity.source_observation_sha256,
            self.linked_at,
        )

    @property
    def semantic_sha256(self) -> str:
        self.__post_init__()
        return _semantic_sha256(self._semantic_material())


@dataclass(frozen=True, slots=True)
class _BrokerInboxHead:
    account_id: str
    last_account_sequence: int
    last_link_id: str
    last_link_sha256: str
    last_linked_at: datetime


def immutable_broker_inbox_request_values(
    request: BrokerInboxAdmissionRequest,
) -> dict[str, Any]:
    """Return the complete canonical SQL representation of one normalized request."""

    if type(request) is not BrokerInboxAdmissionRequest:
        raise BrokerInboxPersistenceError(
            "broker inbox persistence requires an exact admission request"
        )
    request._validate()
    identity = request.identity
    source_fact = request.source_fact
    return {
        "request_id": request.request_id,
        "observation_id": identity.observation_id,
        "account_id": identity.account_id,
        "provider_id": identity.provider_id,
        "environment": identity.environment,
        "source_kind": identity.source_kind.value,
        "identity_profile_id": identity.identity_profile_id,
        "identity_profile_sha256": identity.identity_profile_sha256,
        "identity_sha256": identity.semantic_sha256,
        "source_reconciliation_fact_id": source_fact.fact_id,
        "source_reconciliation_fact_sha256": source_fact.semantic_sha256,
        "source_reconciliation_evidence_sha256": source_fact.evidence.semantic_sha256,
        "source_reconciliation_account_sequence": source_fact.account_sequence,
        "source_fact_normalized_at": source_fact.normalized_at,
        "source_lookup_receipt_id": identity.source_lookup_receipt_id,
        "source_lookup_receipt_sha256": identity.source_lookup_receipt_sha256,
        "source_ingress_receipt_id": identity.source_ingress_receipt_id,
        "source_ingress_receipt_sha256": identity.source_ingress_receipt_sha256,
        "source_observation_sha256": identity.source_observation_sha256,
        "canonical_payload": canonical_json_text(request._semantic_material()),
        "semantic_sha256": request.semantic_sha256,
    }


def immutable_broker_inbox_source_link_values(
    link: _BrokerInboxSourceLink,
) -> dict[str, Any]:
    """Return the complete canonical SQL representation of one source link."""

    if type(link) is not _BrokerInboxSourceLink:
        raise BrokerInboxPersistenceError("broker inbox persistence requires an exact source link")
    link.__post_init__()
    identity = link.request.identity
    source_fact = link.request.source_fact
    return {
        "link_id": link.link_id,
        "account_id": link.account_id,
        "account_sequence": link.account_sequence,
        "previous_link_sha256": link.previous_link_sha256,
        "request_id": link.request.request_id,
        "request_sha256": link.request.semantic_sha256,
        "observation_id": identity.observation_id,
        "source_reconciliation_fact_id": source_fact.fact_id,
        "source_reconciliation_fact_sha256": source_fact.semantic_sha256,
        "source_reconciliation_evidence_sha256": source_fact.evidence.semantic_sha256,
        "source_reconciliation_account_sequence": source_fact.account_sequence,
        "source_lookup_receipt_id": identity.source_lookup_receipt_id,
        "source_lookup_receipt_sha256": identity.source_lookup_receipt_sha256,
        "source_ingress_receipt_id": identity.source_ingress_receipt_id,
        "source_ingress_receipt_sha256": identity.source_ingress_receipt_sha256,
        "source_observation_sha256": identity.source_observation_sha256,
        "linked_at": link.linked_at,
        "canonical_payload": canonical_json_text(link._semantic_material()),
        "semantic_sha256": link.semantic_sha256,
    }


def immutable_broker_inbox_decision_values(
    decision: BrokerInboxNonApplicationDecisionReceipt,
    source_link: _BrokerInboxSourceLink,
) -> dict[str, Any]:
    """Return the complete canonical SQL representation of one non-application receipt."""

    if type(decision) is not BrokerInboxNonApplicationDecisionReceipt:
        raise BrokerInboxPersistenceError(
            "broker inbox persistence requires an exact non-application decision"
        )
    if type(source_link) is not _BrokerInboxSourceLink:
        raise BrokerInboxPersistenceError("broker inbox decision requires an exact source link")
    decision._validate()
    source_link.__post_init__()
    if decision.request != source_link.request or decision.decided_at != source_link.linked_at:
        raise BrokerInboxPersistenceConflict(
            "broker inbox decision conflicts with its exact source link"
        )
    return {
        "decision_id": decision.decision_id,
        "account_id": decision.request.identity.account_id,
        "request_id": decision.request.request_id,
        "request_sha256": decision.request.semantic_sha256,
        "observation_id": decision.request.identity.observation_id,
        "source_link_id": source_link.link_id,
        "source_link_sha256": source_link.semantic_sha256,
        "disposition": decision.disposition.value,
        "policy_id": decision.policy_id,
        "policy_sha256": decision.policy_sha256,
        "decided_at": decision.decided_at,
        "recorded_at": decision.decided_at,
        "canonical_payload": canonical_json_text(decision._semantic_material()),
        "semantic_sha256": decision.semantic_sha256,
    }


def _assert_row_values(
    table: sa.Table,
    identifier: str,
    row: BrokerInboxRow,
    values: Mapping[str, Any],
) -> None:
    try:
        assert_immutable(table, identifier, row, values)
    except (ImmutableFactConflict, KeyError, TypeError, ValueError) as error:
        raise BrokerInboxPersistenceConflict(
            f"persisted {table.name} evidence conflicts with canonical reconstruction"
        ) from error


def _authenticate_request_sources(
    connection: Connection,
    request: BrokerInboxAdmissionRequest,
) -> None:
    try:
        durable_fact = _reconciliation_fact_by_id(
            connection,
            request.source_fact.fact_id,
        )
        if durable_fact is None:
            raise BrokerInboxPersistenceConflict(
                "broker inbox request references a missing Phase 4K fact"
            )
        durable_history = _reconciliation_history(
            connection,
            request.identity.account_id,
        )
        if durable_fact not in durable_history:
            raise BrokerInboxPersistenceConflict(
                "broker inbox request references a Phase 4K fact outside its durable head"
            )
        if durable_fact != request.source_fact:
            raise BrokerInboxPersistenceConflict(
                "broker inbox request substitutes its immutable Phase 4K source"
            )
        ingress = _ingress_receipt_by_id(
            connection,
            request.identity.source_ingress_receipt_id,
        )
        if ingress is None:
            raise BrokerInboxPersistenceConflict(
                "broker inbox request references a missing raw ingress receipt"
            )
        _authenticate_ingress_position(connection, ingress)
        if (
            ingress.account_id != request.identity.account_id
            or ingress.receipt_id != request.identity.source_ingress_receipt_id
            or ingress.semantic_sha256 != request.identity.source_ingress_receipt_sha256
        ):
            raise BrokerInboxPersistenceConflict(
                "broker inbox request substitutes its immutable raw ingress source"
            )
        expected = create_alpaca_paper_inbox_admission_request(durable_fact)
        if expected != request:
            raise BrokerInboxPersistenceConflict(
                "broker inbox request conflicts with the frozen source adapter"
            )
    except BrokerInboxPersistenceError:
        raise
    except (
        AlpacaPaperInboxError,
        BrokerIngressError,
        BrokerReconciliationError,
        TypeError,
        ValueError,
    ) as error:
        raise BrokerInboxPersistenceConflict(
            "broker inbox durable source authentication failed"
        ) from error


def _request_row_by_id(
    connection: Connection,
    request_id: str,
) -> RowMapping | None:
    return (
        connection.execute(
            sa.select(phase4_broker_normalized_facts).where(
                phase4_broker_normalized_facts.c.request_id == request_id
            )
        )
        .mappings()
        .one_or_none()
    )


def broker_inbox_request_from_row(
    connection: Connection,
    row: BrokerInboxRow,
) -> BrokerInboxAdmissionRequest:
    """Strictly rehydrate and authenticate one normalized inbox request."""

    try:
        source_fact_id = _required_text(row, "source_reconciliation_fact_id")
        durable_fact = _reconciliation_fact_by_id(connection, source_fact_id)
        if durable_fact is None:
            raise BrokerInboxPersistenceConflict(
                "persisted broker inbox request references a missing Phase 4K fact"
            )
        identity = BrokerInboxHistoricalObservationIdentity(
            account_id=_required_text(row, "account_id"),
            provider_id=_required_text(row, "provider_id"),
            environment=_required_text(row, "environment"),
            source_kind=BrokerInboxSourceKind(_required_text(row, "source_kind")),
            identity_profile_id=_required_text(row, "identity_profile_id"),
            identity_profile_sha256=_required_text(
                row,
                "identity_profile_sha256",
            ),
            source_reconciliation_fact_id=source_fact_id,
            source_reconciliation_fact_sha256=_required_text(
                row,
                "source_reconciliation_fact_sha256",
            ),
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
            source_observation_sha256=_required_text(
                row,
                "source_observation_sha256",
            ),
        )
        request = _broker_inbox_admission_request(durable_fact, identity)
        values = immutable_broker_inbox_request_values(request)
        _assert_row_values(
            phase4_broker_normalized_facts,
            request.request_id,
            row,
            values,
        )
        _authenticate_request_sources(connection, request)
        return request
    except BrokerInboxPersistenceError:
        raise
    except (
        BrokerInboxError,
        BrokerIngressError,
        BrokerReconciliationError,
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise BrokerInboxPersistenceConflict(
            "persisted broker inbox normalized request is malformed"
        ) from error


def _request_by_id(
    connection: Connection,
    request_id: str,
) -> BrokerInboxAdmissionRequest | None:
    row = _request_row_by_id(connection, request_id)
    return None if row is None else broker_inbox_request_from_row(connection, row)


def _request_by_reconciliation_source(
    connection: Connection,
    reconciliation_fact_id: str,
) -> BrokerInboxAdmissionRequest | None:
    row = (
        connection.execute(
            sa.select(phase4_broker_normalized_facts).where(
                phase4_broker_normalized_facts.c.source_reconciliation_fact_id
                == reconciliation_fact_id
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else broker_inbox_request_from_row(connection, row)


def broker_inbox_source_link_from_row(
    connection: Connection,
    row: BrokerInboxRow,
) -> _BrokerInboxSourceLink:
    """Strictly rehydrate and authenticate one account-local source link."""

    try:
        request_id = _required_text(row, "request_id")
        request = _request_by_id(connection, request_id)
        if request is None:
            raise BrokerInboxPersistenceConflict(
                "persisted broker inbox source link has no normalized request"
            )
        link = _BrokerInboxSourceLink(
            request=request,
            account_sequence=_required_integer(row, "account_sequence"),
            previous_link_sha256=_optional_text(row, "previous_link_sha256"),
            linked_at=_required_datetime(row, "linked_at"),
        )
        values = immutable_broker_inbox_source_link_values(link)
        _assert_row_values(
            phase4_broker_inbox_source_links,
            link.link_id,
            row,
            values,
        )
        return link
    except BrokerInboxPersistenceError:
        raise
    except (
        BrokerInboxError,
        BrokerIngressError,
        BrokerReconciliationError,
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise BrokerInboxPersistenceConflict(
            "persisted broker inbox source link is malformed"
        ) from error


def _source_link_by_id(
    connection: Connection,
    link_id: str,
) -> _BrokerInboxSourceLink | None:
    row = (
        connection.execute(
            sa.select(phase4_broker_inbox_source_links).where(
                phase4_broker_inbox_source_links.c.link_id == link_id
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else broker_inbox_source_link_from_row(connection, row)


def broker_inbox_decision_from_row(
    connection: Connection,
    row: BrokerInboxRow,
    *,
    source_link: _BrokerInboxSourceLink | None = None,
) -> BrokerInboxNonApplicationDecisionReceipt:
    """Strictly rehydrate and authenticate one explicit non-application receipt."""

    try:
        link_id = _required_text(row, "source_link_id")
        durable_link = (
            _source_link_by_id(connection, link_id) if source_link is None else source_link
        )
        if durable_link is None or durable_link.link_id != link_id:
            raise BrokerInboxPersistenceConflict(
                "persisted broker inbox decision has no exact source link"
            )
        decided_at = _required_datetime(row, "decided_at")
        decision = decide_broker_inbox_admission(
            durable_link.request,
            decided_at=decided_at,
        )
        values = immutable_broker_inbox_decision_values(decision, durable_link)
        _assert_row_values(
            phase4_broker_inbox_application_receipts,
            decision.decision_id,
            row,
            values,
        )
        return decision
    except BrokerInboxPersistenceError:
        raise
    except (
        BrokerInboxError,
        BrokerIngressError,
        BrokerReconciliationError,
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise BrokerInboxPersistenceConflict(
            "persisted broker inbox decision receipt is malformed"
        ) from error


def _head_from_row(row: BrokerInboxRow) -> _BrokerInboxHead:
    try:
        account_id = _required_text(row, "account_id")
        sequence = _required_integer(row, "last_account_sequence")
        link_id = _canonical_uuid(
            _required_text(row, "last_link_id"),
            "head link ID",
        )
        digest = _required_text(row, "last_link_sha256")
        linked_at = _required_datetime(row, "last_linked_at")
        if (
            sequence <= 0
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise BrokerInboxPersistenceError("persisted broker inbox head is malformed")
        return _BrokerInboxHead(
            account_id=account_id,
            last_account_sequence=sequence,
            last_link_id=link_id,
            last_link_sha256=digest,
            last_linked_at=linked_at,
        )
    except BrokerInboxPersistenceError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise BrokerInboxPersistenceError("persisted broker inbox head is malformed") from error


def _head(
    connection: Connection,
    account_id: str,
) -> _BrokerInboxHead | None:
    row = (
        connection.execute(
            sa.select(phase4_broker_inbox_heads).where(
                phase4_broker_inbox_heads.c.account_id == account_id
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else _head_from_row(row)


def _history(
    connection: Connection,
    account_id: str,
) -> tuple[BrokerInboxNonApplicationDecisionReceipt, ...]:
    normalized_rows = (
        connection.execute(
            sa.select(phase4_broker_normalized_facts.c.request_id).where(
                phase4_broker_normalized_facts.c.account_id == account_id
            )
        )
        .scalars()
        .all()
    )
    link_rows = (
        connection.execute(
            sa.select(phase4_broker_inbox_source_links)
            .where(phase4_broker_inbox_source_links.c.account_id == account_id)
            .order_by(phase4_broker_inbox_source_links.c.account_sequence)
        )
        .mappings()
        .all()
    )
    application_rows = (
        connection.execute(
            sa.select(phase4_broker_inbox_application_receipts).where(
                phase4_broker_inbox_application_receipts.c.account_id == account_id
            )
        )
        .mappings()
        .all()
    )
    head = _head(connection, account_id)

    normalized_ids = tuple(
        _require_identifier(value, "request ID", maximum=36) for value in normalized_rows
    )
    link_request_ids = tuple(_required_text(row, "request_id") for row in link_rows)
    application_link_ids = tuple(_required_text(row, "source_link_id") for row in application_rows)
    link_ids = tuple(_required_text(row, "link_id") for row in link_rows)
    if (
        len(set(normalized_ids)) != len(normalized_ids)
        or set(normalized_ids) != set(link_request_ids)
        or len(application_link_ids) != len(link_ids)
        or len(set(application_link_ids)) != len(application_link_ids)
        or set(application_link_ids) != set(link_ids)
    ):
        raise BrokerInboxPersistenceConflict(
            "broker inbox normalized, source-link, and application histories are incomplete"
        )
    if not link_rows:
        if normalized_rows or application_rows or head is not None:
            raise BrokerInboxPersistenceConflict(
                "broker inbox evidence exists without a complete durable head"
            )
        return ()

    applications_by_link = {_required_text(row, "source_link_id"): row for row in application_rows}
    decisions: list[BrokerInboxNonApplicationDecisionReceipt] = []
    previous: _BrokerInboxSourceLink | None = None
    for expected_sequence, row in enumerate(link_rows, start=1):
        link = broker_inbox_source_link_from_row(connection, row)
        if (
            link.account_id != account_id
            or link.account_sequence != expected_sequence
            or link.previous_link_sha256 != (None if previous is None else previous.semantic_sha256)
            or (previous is not None and link.linked_at < previous.linked_at)
        ):
            raise BrokerInboxPersistenceConflict(
                "broker inbox account-local source-link history is discontinuous"
            )
        application_row = applications_by_link.get(link.link_id)
        if application_row is None:
            raise BrokerInboxPersistenceConflict(
                "broker inbox source link lacks an application receipt"
            )
        decision = broker_inbox_decision_from_row(
            connection,
            application_row,
            source_link=link,
        )
        if decision.request != link.request:
            raise BrokerInboxPersistenceConflict(
                "broker inbox decision substitutes its source link request"
            )
        decisions.append(decision)
        previous = link

    assert previous is not None
    if (
        head is None
        or head.account_id != account_id
        or head.last_account_sequence != len(link_rows)
        or head.last_link_id != previous.link_id
        or head.last_link_sha256 != previous.semantic_sha256
        or head.last_linked_at != previous.linked_at
    ):
        raise BrokerInboxPersistenceConflict(
            "broker inbox head conflicts with terminal source-link history"
        )
    return tuple(decisions)


def _verify_broker_inbox_integrity(connection: Connection) -> None:
    """Authenticate every Phase 4L row inside a caller-owned stable transaction."""

    account_ids: set[str] = set()
    for table in (
        phase4_broker_normalized_facts,
        phase4_broker_inbox_source_links,
        phase4_broker_inbox_heads,
        phase4_broker_inbox_application_receipts,
    ):
        for value in connection.scalars(sa.select(table.c.account_id).distinct()):
            account_ids.add(
                _require_identifier(
                    value,
                    "account ID",
                    maximum=64,
                )
            )
    for account_id in sorted(account_ids):
        _history(connection, account_id)


def verify_broker_inbox_integrity(engine: Engine) -> None:
    """Authenticate every source-scoped inbox chain in one stable snapshot."""

    if not isinstance(engine, Engine):
        raise BrokerInboxPersistenceError("broker inbox verification requires an Engine")
    if engine.dialect.name not in _SUPPORTED_DIALECTS:
        raise BrokerInboxPersistenceError(
            f"broker inbox verification does not support dialect {engine.dialect.name!r}"
        )
    with _repeatable_read_transaction(engine) as connection:
        _verify_broker_inbox_integrity(connection)


def _collides_with_request(
    persisted: BrokerInboxAdmissionRequest,
    incoming: BrokerInboxAdmissionRequest,
) -> bool:
    persisted_identity = persisted.identity
    incoming_identity = incoming.identity
    return any(
        (
            persisted.request_id == incoming.request_id,
            persisted.semantic_sha256 == incoming.semantic_sha256,
            persisted_identity.observation_id == incoming_identity.observation_id,
            persisted_identity.semantic_sha256 == incoming_identity.semantic_sha256,
            persisted.source_fact.fact_id == incoming.source_fact.fact_id,
            persisted_identity.source_lookup_receipt_id
            == incoming_identity.source_lookup_receipt_id,
            persisted_identity.source_ingress_receipt_id
            == incoming_identity.source_ingress_receipt_id,
        )
    )


class SqlBrokerInboxRepository:
    """Atomically retain source-scoped facts, links, and non-application receipts."""

    __slots__ = ("_clock", "_engine")

    def __init__(
        self,
        *,
        engine: Engine,
        clock: Clock,
    ) -> None:
        if not isinstance(engine, Engine):
            raise BrokerInboxPersistenceError("SQL broker inbox requires an Engine")
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise BrokerInboxPersistenceError(
                f"SQL broker inbox does not support dialect {engine.dialect.name!r}"
            )
        if not callable(getattr(clock, "now", None)):
            raise BrokerInboxPersistenceError("SQL broker inbox requires a trusted Clock")
        self._engine = engine
        self._clock = clock

    @property
    def runtime_store_identity(self) -> int:
        """Identify the shared SQL engine for process-local composition checks."""

        return id(self._engine)

    def record(
        self,
        request: BrokerInboxAdmissionRequest,
    ) -> BrokerInboxNonApplicationDecisionReceipt:
        """Record one request or return its exact durable retry without reading time."""

        if type(request) is not BrokerInboxAdmissionRequest:
            raise BrokerInboxPersistenceError(
                "broker inbox recording requires an exact admission request"
            )
        try:
            request._validate()
            if create_alpaca_paper_inbox_admission_request(request.source_fact) != request:
                raise BrokerInboxPersistenceConflict(
                    "broker inbox request conflicts with the frozen source adapter"
                )
            account_id = request.identity.account_id
            with _write_transaction(self._engine) as connection:
                lock_account_capacity_serialization(connection, account_id)
                history = _history(connection, account_id)
                for existing in history:
                    if not _collides_with_request(existing.request, request):
                        continue
                    if existing.request != request:
                        raise BrokerInboxPersistenceConflict(
                            "broker inbox source identity conflicts with durable evidence"
                        )
                    return existing

                collision = connection.scalar(
                    sa.select(phase4_broker_normalized_facts.c.request_id)
                    .where(
                        sa.or_(
                            phase4_broker_normalized_facts.c.request_id == request.request_id,
                            phase4_broker_normalized_facts.c.observation_id
                            == request.identity.observation_id,
                            phase4_broker_normalized_facts.c.identity_sha256
                            == request.identity.semantic_sha256,
                            phase4_broker_normalized_facts.c.source_reconciliation_fact_id
                            == request.source_fact.fact_id,
                            phase4_broker_normalized_facts.c.source_lookup_receipt_id
                            == request.identity.source_lookup_receipt_id,
                            phase4_broker_normalized_facts.c.source_ingress_receipt_id
                            == request.identity.source_ingress_receipt_id,
                            phase4_broker_normalized_facts.c.semantic_sha256
                            == request.semantic_sha256,
                        )
                    )
                    .limit(1)
                )
                if collision is not None:
                    raise BrokerInboxPersistenceConflict(
                        "broker inbox source identity exists outside its durable account history"
                    )

                _authenticate_request_sources(connection, request)
                previous_decision = None if not history else history[-1]
                previous_link: _BrokerInboxSourceLink | None = None
                if previous_decision is not None:
                    previous_link = _source_link_by_id(
                        connection,
                        canonical_id(
                            "broker-inbox-source-link",
                            previous_decision.request.request_id,
                        ),
                    )
                    if previous_link is None:
                        raise BrokerInboxPersistenceConflict(
                            "broker inbox terminal decision lacks its source link"
                        )
                try:
                    decided_at = _trusted_utc(
                        self._clock.now(),
                        "decision time",
                    )
                except BrokerInboxError:
                    raise
                except Exception:
                    raise BrokerInboxPersistenceError("broker inbox trusted clock failed") from None
                if decided_at < request.source_fact.normalized_at:
                    raise BrokerInboxPersistenceConflict(
                        "broker inbox decision predates its normalized source"
                    )
                if previous_link is not None and decided_at < previous_link.linked_at:
                    raise BrokerInboxPersistenceConflict("broker inbox decision time regressed")

                link = _BrokerInboxSourceLink(
                    request=request,
                    account_sequence=(
                        1 if previous_link is None else previous_link.account_sequence + 1
                    ),
                    previous_link_sha256=(
                        None if previous_link is None else previous_link.semantic_sha256
                    ),
                    linked_at=decided_at,
                )
                decision = decide_broker_inbox_admission(
                    request,
                    decided_at=decided_at,
                )
                try:
                    connection.execute(
                        sa.insert(phase4_broker_normalized_facts).values(
                            **immutable_broker_inbox_request_values(request)
                        )
                    )
                    connection.execute(
                        sa.insert(phase4_broker_inbox_source_links).values(
                            **immutable_broker_inbox_source_link_values(link)
                        )
                    )
                    connection.execute(
                        sa.insert(phase4_broker_inbox_application_receipts).values(
                            **immutable_broker_inbox_decision_values(
                                decision,
                                link,
                            )
                        )
                    )
                except IntegrityError as error:
                    raise BrokerInboxPersistenceConflict(
                        "broker inbox append conflicts with durable evidence"
                    ) from error

                if previous_link is None:
                    try:
                        connection.execute(
                            sa.insert(phase4_broker_inbox_heads).values(
                                account_id=account_id,
                                last_account_sequence=link.account_sequence,
                                last_link_id=link.link_id,
                                last_link_sha256=link.semantic_sha256,
                                last_linked_at=link.linked_at,
                            )
                        )
                    except IntegrityError as error:
                        raise BrokerInboxPersistenceConflict(
                            "broker inbox head conflicts with durable history"
                        ) from error
                else:
                    updated = connection.execute(
                        sa.update(phase4_broker_inbox_heads)
                        .where(
                            phase4_broker_inbox_heads.c.account_id == account_id,
                            phase4_broker_inbox_heads.c.last_account_sequence
                            == previous_link.account_sequence,
                            phase4_broker_inbox_heads.c.last_link_id == previous_link.link_id,
                            phase4_broker_inbox_heads.c.last_link_sha256
                            == previous_link.semantic_sha256,
                            phase4_broker_inbox_heads.c.last_linked_at == previous_link.linked_at,
                        )
                        .values(
                            last_account_sequence=link.account_sequence,
                            last_link_id=link.link_id,
                            last_link_sha256=link.semantic_sha256,
                            last_linked_at=link.linked_at,
                        )
                    )
                    if updated.rowcount != 1:
                        raise BrokerInboxPersistenceConflict(
                            "broker inbox head changed during append"
                        )

                terminal_history = _history(connection, account_id)
                if (
                    not terminal_history
                    or terminal_history[-1] != decision
                    or len(terminal_history) != len(history) + 1
                ):
                    raise BrokerInboxPersistenceConflict(
                        "broker inbox append failed exact SQL readback"
                    )
                return terminal_history[-1]
        except BrokerInboxError:
            raise
        except (
            AccountCoordinatorError,
            AlpacaPaperInboxError,
            BrokerIngressError,
            BrokerReconciliationError,
            TypeError,
            ValueError,
        ) as error:
            raise BrokerInboxPersistenceConflict(
                "broker inbox append or source authentication failed"
            ) from error

    def load(
        self,
        decision_id: str,
    ) -> BrokerInboxNonApplicationDecisionReceipt | None:
        """Load one decision only after authenticating its complete account chain."""

        decision_id = _canonical_uuid(
            _require_identifier(
                decision_id,
                "decision ID",
                maximum=36,
            ),
            "decision ID",
        )
        with _repeatable_read_transaction(self._engine) as connection:
            row = (
                connection.execute(
                    sa.select(phase4_broker_inbox_application_receipts).where(
                        phase4_broker_inbox_application_receipts.c.decision_id == decision_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                return None
            account_id = _required_text(row, "account_id")
            history = _history(connection, account_id)
            for decision in history:
                if decision.decision_id == decision_id:
                    return decision
            raise BrokerInboxPersistenceConflict(
                "broker inbox decision exists outside its durable head"
            )

    def history(
        self,
        account_id: str,
    ) -> tuple[BrokerInboxNonApplicationDecisionReceipt, ...]:
        """Return one authenticated account-local inbox history."""

        account_id = _require_identifier(
            account_id,
            "account ID",
            maximum=64,
        )
        with _repeatable_read_transaction(self._engine) as connection:
            return _history(connection, account_id)

    def load_by_reconciliation_fact_id(
        self,
        reconciliation_fact_id: str,
    ) -> BrokerInboxNonApplicationDecisionReceipt | None:
        """Load an authenticated decision selected by its exact Phase 4K source."""

        reconciliation_fact_id = _canonical_uuid(
            _require_identifier(
                reconciliation_fact_id,
                "reconciliation fact ID",
                maximum=36,
            ),
            "reconciliation fact ID",
        )
        with _repeatable_read_transaction(self._engine) as connection:
            request = _request_by_reconciliation_source(
                connection,
                reconciliation_fact_id,
            )
            if request is None:
                return None
            history = _history(connection, request.identity.account_id)
            matches = tuple(
                decision
                for decision in history
                if decision.request.source_fact.fact_id == reconciliation_fact_id
            )
            if len(matches) != 1 or matches[0].request != request:
                raise BrokerInboxPersistenceConflict(
                    "broker inbox reconciliation source exists outside its durable head"
                )
            return matches[0]


__all__ = [
    "BROKER_INBOX_PERSISTENCE_CONTRACT_VERSION",
    "BrokerInboxPersistenceConflict",
    "BrokerInboxPersistenceError",
    "SqlBrokerInboxRepository",
    "broker_inbox_decision_from_row",
    "broker_inbox_request_from_row",
    "broker_inbox_source_link_from_row",
    "immutable_broker_inbox_decision_values",
    "immutable_broker_inbox_request_values",
    "immutable_broker_inbox_source_link_values",
    "verify_broker_inbox_integrity",
]
