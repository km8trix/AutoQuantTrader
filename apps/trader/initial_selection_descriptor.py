"""Detached initial-selection metadata, never ownership or command authority.

This pure bridge does not sample time, read private evidence, or prepare effects.
Every copy/conversion consumes one completely validated native field snapshot.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from packages.domain.continuous_persistence_contracts import (
    ContinuousAccountScope,
    ContinuousEvidenceRef,
)
from packages.domain.durable_journal_contracts import journal_identifier
from packages.domain.personal_contracts import require_digest
from packages.domain.reconciliation_contracts import (
    MAX_RECONCILIATION_COUNTER,
    ReconciliationHeads,
)
from packages.domain.research_job_contracts import ObjectRef
from packages.domain.runtime_owner_dependency_contracts import (
    MAX_OWNER_DEPENDENCIES_BYTES,
    OWNER_DEPENDENCIES_SCHEMA,
)

_ERROR = "INITIAL_SELECTION_DESCRIPTOR_INVALID"

type _DescriptorValues = tuple[
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    int,
    str,
    int,
    int,
    Literal["runtime-owner-dependencies/1"],
    str,
    int,
    Literal["personal-record/1"],
    str,
    datetime,
    datetime,
    str,
    str | None,
    str,
]


@dataclass(frozen=True, slots=True, kw_only=True)
class InitialSelectionDescriptor:
    account_id: str
    account_binding_sha256: str
    stream_id: str
    after_assignment_sha256: str
    ledger_sha256: str
    order_sha256: str
    capacity_sha256: str
    effect_watermark: int
    attempt_sha256: str
    control_revision: int
    lease_generation: int
    dependency_schema_id: Literal["runtime-owner-dependencies/1"]
    dependency_object_sha256: str
    dependency_byte_count: int
    dependency_codec_version: Literal["personal-record/1"]
    dependency_semantic_sha256: str
    checked_at: datetime
    valid_until: datetime
    c1_receipt_sha256: str
    control_sha256: str | None
    original_lease_sha256: str

    def __post_init__(self) -> None:
        _descriptor_values(self)


def _validated_values(values: object) -> _DescriptorValues:
    if type(values) is not tuple or len(values) != 21:
        raise ValueError(_ERROR)
    (
        account_id,
        account_binding_sha256,
        stream_id,
        after_assignment_sha256,
        ledger_sha256,
        order_sha256,
        capacity_sha256,
        effect_watermark,
        attempt_sha256,
        control_revision,
        lease_generation,
        dependency_schema_id,
        dependency_object_sha256,
        dependency_byte_count,
        dependency_codec_version,
        dependency_semantic_sha256,
        checked_at,
        valid_until,
        c1_receipt_sha256,
        control_sha256,
        original_lease_sha256,
    ) = values
    if (
        any(
            type(value) is not str
            for value in (
                account_id,
                account_binding_sha256,
                stream_id,
                after_assignment_sha256,
                ledger_sha256,
                order_sha256,
                capacity_sha256,
                attempt_sha256,
                dependency_schema_id,
                dependency_object_sha256,
                dependency_codec_version,
                dependency_semantic_sha256,
                c1_receipt_sha256,
                original_lease_sha256,
            )
        )
        or any(
            type(value) is not int
            for value in (
                effect_watermark,
                control_revision,
                lease_generation,
                dependency_byte_count,
            )
        )
        or type(checked_at) is not datetime
        or type(valid_until) is not datetime
        or (control_sha256 is not None and type(control_sha256) is not str)
    ):
        raise ValueError(_ERROR)
    try:
        journal_identifier(account_id)
        journal_identifier(stream_id)
        for value in (
            account_binding_sha256,
            after_assignment_sha256,
            ledger_sha256,
            order_sha256,
            capacity_sha256,
            attempt_sha256,
            dependency_object_sha256,
            dependency_semantic_sha256,
            c1_receipt_sha256,
            original_lease_sha256,
        ):
            require_digest(value, "initial selection metadata")
        if control_sha256 is not None:
            require_digest(control_sha256, "initial selection control metadata")
        if (
            dependency_schema_id != OWNER_DEPENDENCIES_SCHEMA
            or dependency_schema_id != "runtime-owner-dependencies/1"
            or dependency_codec_version != "personal-record/1"
            or not 1 <= dependency_byte_count <= MAX_OWNER_DEPENDENCIES_BYTES
            or any(
                not 0 <= value <= MAX_RECONCILIATION_COUNTER
                for value in (effect_watermark, control_revision, lease_generation)
            )
            or checked_at.tzinfo is not UTC
            or valid_until.tzinfo is not UTC
            or not checked_at < valid_until
            or valid_until - checked_at > timedelta(seconds=60)
        ):
            raise ValueError(_ERROR)
    except ValueError:
        raise ValueError(_ERROR) from None
    return (
        account_id,
        account_binding_sha256,
        stream_id,
        after_assignment_sha256,
        ledger_sha256,
        order_sha256,
        capacity_sha256,
        effect_watermark,
        attempt_sha256,
        control_revision,
        lease_generation,
        dependency_schema_id,
        dependency_object_sha256,
        dependency_byte_count,
        dependency_codec_version,
        dependency_semantic_sha256,
        checked_at,
        valid_until,
        c1_receipt_sha256,
        control_sha256,
        original_lease_sha256,
    )


def _descriptor_values(value: object) -> _DescriptorValues:
    if type(value) is not InitialSelectionDescriptor:
        raise ValueError(_ERROR)
    return _validated_values(
        (
            value.account_id,
            value.account_binding_sha256,
            value.stream_id,
            value.after_assignment_sha256,
            value.ledger_sha256,
            value.order_sha256,
            value.capacity_sha256,
            value.effect_watermark,
            value.attempt_sha256,
            value.control_revision,
            value.lease_generation,
            value.dependency_schema_id,
            value.dependency_object_sha256,
            value.dependency_byte_count,
            value.dependency_codec_version,
            value.dependency_semantic_sha256,
            value.checked_at,
            value.valid_until,
            value.c1_receipt_sha256,
            value.control_sha256,
            value.original_lease_sha256,
        )
    )


def _from_values(values: _DescriptorValues) -> InitialSelectionDescriptor:
    return InitialSelectionDescriptor(
        account_id=values[0],
        account_binding_sha256=values[1],
        stream_id=values[2],
        after_assignment_sha256=values[3],
        ledger_sha256=values[4],
        order_sha256=values[5],
        capacity_sha256=values[6],
        effect_watermark=values[7],
        attempt_sha256=values[8],
        control_revision=values[9],
        lease_generation=values[10],
        dependency_schema_id=values[11],
        dependency_object_sha256=values[12],
        dependency_byte_count=values[13],
        dependency_codec_version=values[14],
        dependency_semantic_sha256=values[15],
        checked_at=values[16],
        valid_until=values[17],
        c1_receipt_sha256=values[18],
        control_sha256=values[19],
        original_lease_sha256=values[20],
    )


def copy_initial_selection_descriptor(
    value: InitialSelectionDescriptor,
) -> InitialSelectionDescriptor:
    """Copy admitted native data; this does not authenticate the source."""
    values = _descriptor_values(value)
    return _from_values(values)


def initial_selection_request_data(
    value: InitialSelectionDescriptor,
) -> tuple[ContinuousAccountScope, ReconciliationHeads, ContinuousEvidenceRef]:
    """Reconstruct fresh original request data, never a prepared command."""
    values = _descriptor_values(value)
    try:
        scope = ContinuousAccountScope(values[0], values[1], values[2])
        heads = ReconciliationHeads(
            values[4], values[5], values[6], values[7], values[8], values[9], values[10]
        )
        reference = ContinuousEvidenceRef(
            values[11], ObjectRef(values[12], values[13], values[14]), values[15]
        )
    except ValueError:
        raise ValueError(_ERROR) from None
    return scope, heads, reference
