"""Durable prepare/confirm journal for external trusted-time head anchors.

The repository owns only local SQL evidence.  ``prepare_or_read_pending``
commits one immutable signed-object intent before the caller performs remote
I/O.  ``confirm_remote_readback`` starts a new transaction only after the
caller has obtained exact remote bytes.  No method accepts a provider or a
network callback, so a database transaction can never span remote I/O.

The rows are evidence only.  They grant no readiness, control, exposure,
arming, resume, re-arm, or broker authority.
"""

from __future__ import annotations

import hashlib
import os
import threading
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from packages.application.trusted_time_head_anchor import (
    TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS as APPLICATION_CHECKPOINT_INTERVAL_SECONDS,
)
from packages.application.trusted_time_head_anchor import (
    AuthenticatedTrustedTimeHeadJournalTip,
    AuthenticatedTrustedTimeHeadTransition,
    CommittedTrustedTimeHeadAnchorIntentEvidence,
    PreparedTrustedTimeHeadAnchorReconciliation,
    TrustedTimeHeadAnchorCheckpointReason,
    TrustedTimeHeadAnchorEd25519Verifier,
    TrustedTimeHeadAnchorError,
    TrustedTimeHeadAnchorProviderReadbackEvidence,
    TrustedTimeHeadAnchorRecord,
    _advance_authenticated_trusted_time_head_journal_tip,
    _claim_trusted_time_head_anchor_provider_readback,
    _consume_trusted_time_head_anchor_provider_readback,
    _issue_authenticated_trusted_time_head_journal_tip,
    _new_committed_trusted_time_head_anchor_intent_evidence,
    _release_trusted_time_head_anchor_provider_readback,
    _validate_local_chain,
    trusted_time_head_anchor_object_name,
    trusted_time_head_anchor_object_prefix,
)
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.persistence.account_coordinator import _write_transaction
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.immutable import as_aware_utc, same_value
from packages.persistence.schema import (
    phase6_trusted_time_epoch_registrations,
    phase6_trusted_time_head_anchor_intents,
    phase6_trusted_time_head_anchor_receipts,
    phase6_trusted_time_host_heads,
    phase6_trusted_time_probe_evaluations,
)
from packages.persistence.trusted_time import (
    TRUSTED_TIME_PERSISTENCE_CONTRACT_VERSION,
    TrustedTimePersistenceError,
    _authenticated_head_transitions,
    _consume_authenticated_head_full_replay,
    _epoch_from_row,
    _evaluation_from_row,
    _head_from_row,
    _new_head,
    _verified_host,
    _verified_host_suffix_from_boundary,
    _VerifiedHost,
    _verify_global_integrity,
)

TRUSTED_TIME_HEAD_ANCHOR_SQL_CONTRACT_VERSION = (
    "phase6d-durable-trusted-time-head-anchor-persistence-v1"
)
TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS = APPLICATION_CHECKPOINT_INTERVAL_SECONDS

_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})
AnchorRow = Mapping[str, object] | RowMapping


class TrustedTimeHeadAnchorPersistenceError(RuntimeError):
    """Durable external-anchor evidence is malformed or unavailable."""


class TrustedTimeHeadAnchorPersistenceConflict(TrustedTimeHeadAnchorPersistenceError):
    """An immutable anchor fact or authenticated replay conflicts."""


class TrustedTimeHeadAnchorSnapshotAdvanced(TrustedTimeHeadAnchorPersistenceConflict):
    """An authenticated local append benignly advanced a compact CAS snapshot."""

    def __init__(
        self,
        message: str,
        *,
        refreshed_snapshot: TrustedTimeHeadAnchorPersistenceSnapshot | None = None,
    ) -> None:
        super().__init__(message)
        self.refreshed_snapshot = refreshed_snapshot


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(value: object) -> str:
    return _sha256_bytes(canonical_json_bytes(value))


def _require_text(value: object, field_name: str, *, maximum: int = 128) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise TrustedTimeHeadAnchorPersistenceError(f"trusted-time anchor {field_name} is invalid")
    return value


def _require_sha256(value: object, field_name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise TrustedTimeHeadAnchorPersistenceError(f"trusted-time anchor {field_name} is invalid")
    return value


def _require_uuid(value: object, field_name: str) -> str:
    if type(value) is not str:
        raise TrustedTimeHeadAnchorPersistenceError(f"trusted-time anchor {field_name} is invalid")
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError):
        raise TrustedTimeHeadAnchorPersistenceError(
            f"trusted-time anchor {field_name} is invalid"
        ) from None
    if parsed.int == 0 or str(parsed) != value:
        raise TrustedTimeHeadAnchorPersistenceError(f"trusted-time anchor {field_name} is invalid")
    return value


def _require_utc(value: object, field_name: str) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise TrustedTimeHeadAnchorPersistenceError(f"trusted-time anchor {field_name} must be UTC")
    return value


def _required_text(row: AnchorRow, field_name: str) -> str:
    value = row[field_name]
    if type(value) is not str:
        raise TrustedTimeHeadAnchorPersistenceConflict(
            f"persisted trusted-time anchor {field_name} is malformed"
        )
    return value


def _required_integer(row: AnchorRow, field_name: str) -> int:
    value = row[field_name]
    if type(value) is not int:
        raise TrustedTimeHeadAnchorPersistenceConflict(
            f"persisted trusted-time anchor {field_name} is malformed"
        )
    return value


def _required_datetime(row: AnchorRow, field_name: str) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise TrustedTimeHeadAnchorPersistenceConflict(
            f"persisted trusted-time anchor {field_name} is malformed"
        )
    return as_aware_utc(value)


def _required_bytes(row: AnchorRow, field_name: str) -> bytes:
    value = row[field_name]
    if type(value) is not bytes:
        raise TrustedTimeHeadAnchorPersistenceConflict(
            f"persisted trusted-time anchor {field_name} is malformed"
        )
    return value


def _assert_exact_row(
    row: AnchorRow,
    expected: Mapping[str, object],
    subject: str,
) -> None:
    for field_name, expected_value in expected.items():
        if not same_value(row[field_name], expected_value):
            raise TrustedTimeHeadAnchorPersistenceConflict(
                f"persisted trusted-time anchor {subject} conflicts in {field_name}"
            )


def _host_identity_sha256(record: TrustedTimeHeadAnchorRecord) -> str:
    prefix = trusted_time_head_anchor_object_prefix(
        deployment_identity_sha256=record.deployment_identity_sha256,
        host_id=record.host_id,
    )
    components = prefix.split("/")
    if len(components) != 4 or components[-1] != "":
        raise TrustedTimeHeadAnchorPersistenceError(
            "trusted-time anchor object prefix is malformed"
        )
    return _require_sha256(components[-2], "host identity SHA-256")


def _intent_material(
    *,
    anchor_intent_id: str,
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason,
    checkpoint_interval_seconds: int,
    anchor_authority_sha256: str,
    record: TrustedTimeHeadAnchorRecord,
    object_name: str,
    signed_envelope_bytes: bytes,
    created_at_utc: datetime,
) -> tuple[object, ...]:
    return (
        TRUSTED_TIME_HEAD_ANCHOR_SQL_CONTRACT_VERSION,
        "trusted_time_head_anchor_intent",
        anchor_intent_id,
        checkpoint_reason.value,
        checkpoint_interval_seconds,
        anchor_authority_sha256,
        record.semantic_sha256,
        object_name,
        signed_envelope_bytes,
        record.byte_sha256,
        created_at_utc,
    )


@dataclass(frozen=True, slots=True)
class PersistedTrustedTimeHeadAnchorIntent:
    """One committed local intent to publish exact signed bytes."""

    anchor_intent_id: str
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason
    checkpoint_interval_seconds: int
    anchor_authority_sha256: str
    record: TrustedTimeHeadAnchorRecord
    object_name: str
    signed_envelope_bytes: bytes
    created_at_utc: datetime
    semantic_sha256: str

    def __post_init__(self) -> None:
        _require_uuid(self.anchor_intent_id, "intent ID")
        if type(self.checkpoint_reason) is not TrustedTimeHeadAnchorCheckpointReason:
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor checkpoint reason is invalid"
            )
        if (
            type(self.checkpoint_interval_seconds) is not int
            or self.checkpoint_interval_seconds
            != TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
        ):
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor checkpoint interval is invalid"
            )
        _require_sha256(self.anchor_authority_sha256, "authority SHA-256")
        if type(self.record) is not TrustedTimeHeadAnchorRecord:
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor intent record is invalid"
            )
        try:
            self.record.__post_init__()
            decoded = TrustedTimeHeadAnchorRecord.from_canonical_bytes(self.record.canonical_bytes)
        except TrustedTimeHeadAnchorError:
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor intent record is invalid"
            ) from None
        if decoded != self.record:
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor intent record is not byte-exact"
            )
        if (
            self.checkpoint_reason is not self.record.checkpoint_reason
            or self.checkpoint_interval_seconds != self.record.checkpoint_interval_seconds
            or self.anchor_authority_sha256 != self.record.anchor_authority_sha256
        ):
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor intent checkpoint binding conflicts"
            )
        if type(self.signed_envelope_bytes) is not bytes or (
            self.signed_envelope_bytes != self.record.canonical_bytes
        ):
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor intent signed bytes conflict"
            )
        prefix = trusted_time_head_anchor_object_prefix(
            deployment_identity_sha256=self.record.deployment_identity_sha256,
            host_id=self.record.host_id,
        )
        expected_name = trusted_time_head_anchor_object_name(
            prefix=prefix,
            anchor_sequence=self.record.anchor_sequence,
            signed_envelope_sha256=self.record.byte_sha256,
        )
        if self.object_name != expected_name:
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor intent object name conflicts"
            )
        _require_utc(self.created_at_utc, "intent creation instant")
        if (self.record.anchor_sequence == 1) != (
            self.checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT
        ):
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor enrollment reason conflicts with its sequence"
            )
        _require_sha256(self.semantic_sha256, "intent semantic SHA-256")
        if self.semantic_sha256 != _sha256(self._semantic_material()):
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor intent semantic SHA-256 conflicts"
            )

    def _semantic_material(self) -> tuple[object, ...]:
        return _intent_material(
            anchor_intent_id=self.anchor_intent_id,
            checkpoint_reason=self.checkpoint_reason,
            checkpoint_interval_seconds=self.checkpoint_interval_seconds,
            anchor_authority_sha256=self.anchor_authority_sha256,
            record=self.record,
            object_name=self.object_name,
            signed_envelope_bytes=self.signed_envelope_bytes,
            created_at_utc=self.created_at_utc,
        )

    @property
    def canonical_payload(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def signed_envelope_text(self) -> str:
        return self.signed_envelope_bytes.decode("utf-8")

    @property
    def signed_envelope_sha256(self) -> str:
        return self.record.byte_sha256

    @property
    def host_identity_sha256(self) -> str:
        return _host_identity_sha256(self.record)


def _new_intent(
    *,
    anchor_intent_id: str,
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason,
    checkpoint_interval_seconds: int,
    anchor_authority_sha256: str,
    record: TrustedTimeHeadAnchorRecord,
    object_name: str,
    signed_envelope_bytes: bytes,
    created_at_utc: datetime,
) -> PersistedTrustedTimeHeadAnchorIntent:
    material = _intent_material(
        anchor_intent_id=anchor_intent_id,
        checkpoint_reason=checkpoint_reason,
        checkpoint_interval_seconds=checkpoint_interval_seconds,
        anchor_authority_sha256=anchor_authority_sha256,
        record=record,
        object_name=object_name,
        signed_envelope_bytes=signed_envelope_bytes,
        created_at_utc=created_at_utc,
    )
    return PersistedTrustedTimeHeadAnchorIntent(
        anchor_intent_id=anchor_intent_id,
        checkpoint_reason=checkpoint_reason,
        checkpoint_interval_seconds=checkpoint_interval_seconds,
        anchor_authority_sha256=anchor_authority_sha256,
        record=record,
        object_name=object_name,
        signed_envelope_bytes=signed_envelope_bytes,
        created_at_utc=created_at_utc,
        semantic_sha256=_sha256(material),
    )


def _intent_values(intent: PersistedTrustedTimeHeadAnchorIntent) -> dict[str, object]:
    record = intent.record
    return {
        "anchor_intent_id": intent.anchor_intent_id,
        "host_id": record.host_id,
        "anchor_sequence": record.anchor_sequence,
        "previous_anchor_sha256": record.previous_anchor_sha256,
        "previous_anchored_host_head_sha256": (record.previous_anchored_host_head_sha256),
        "checkpoint_reason": intent.checkpoint_reason.value,
        "checkpoint_interval_seconds": intent.checkpoint_interval_seconds,
        "anchor_authority_sha256": intent.anchor_authority_sha256,
        "deployment_identity_sha256": record.deployment_identity_sha256,
        "runtime_database_identity_sha256": record.runtime_database_identity_sha256,
        "anchor_project_identity_sha256": record.anchor_project_identity_sha256,
        "anchor_project_ref": record.anchor_project_ref,
        "bucket_name": record.bucket_name,
        "principal_id": record.principal_id,
        "signing_key_id": record.signing_key_id,
        "signing_public_key_sha256": record.signing_public_key_sha256,
        "head_authenticated_at_utc": record.head_authenticated_at_utc,
        "source_id": record.source_id,
        "source_authority_sha256": record.source_authority_sha256,
        "policy_sha256": record.policy_sha256,
        "persistence_contract_version": record.persistence_contract_version,
        "epoch_sequence": record.epoch_sequence,
        "monitor_epoch_id": record.monitor_epoch_id,
        "epoch_sha256": record.epoch_sha256,
        "evaluation_sequence": record.evaluation_sequence,
        "evaluation_id": record.evaluation_id,
        "evaluation_record_sha256": record.evaluation_record_sha256,
        "state_sha256": record.state_sha256,
        "probe_status": None if record.probe_status is None else record.probe_status.value,
        "health": None if record.health is None else record.health.value,
        "reason": None if record.reason is None else record.reason.value,
        "hard_failure_latched": record.hard_failure_latched,
        "clock_recovery_qualified": record.clock_recovery_qualified,
        "evaluated_at_utc": record.evaluated_at_utc,
        "evaluated_at_monotonic_ns": record.evaluated_at_monotonic_ns,
        "local_previous_host_head_sha256": record.local_previous_host_head_sha256,
        "current_host_head_sha256": record.current_host_head_sha256,
        "host_identity_sha256": intent.host_identity_sha256,
        "object_name": intent.object_name,
        "signed_envelope_bytes": intent.signed_envelope_bytes,
        "signed_envelope_text": intent.signed_envelope_text,
        "signed_envelope_sha256": intent.signed_envelope_sha256,
        "created_at_utc": intent.created_at_utc,
        "canonical_payload": intent.canonical_payload,
        "semantic_sha256": intent.semantic_sha256,
    }


def _receipt_material(
    *,
    anchor_receipt_id: str,
    intent: PersistedTrustedTimeHeadAnchorIntent,
    readback_bytes_sha256: str,
    observed_at_utc: datetime,
) -> tuple[object, ...]:
    record = intent.record
    return (
        TRUSTED_TIME_HEAD_ANCHOR_SQL_CONTRACT_VERSION,
        "trusted_time_head_anchor_receipt",
        anchor_receipt_id,
        intent.anchor_intent_id,
        intent.semantic_sha256,
        intent.signed_envelope_sha256,
        record.deployment_identity_sha256,
        record.runtime_database_identity_sha256,
        record.anchor_project_identity_sha256,
        record.anchor_project_ref,
        record.bucket_name,
        record.principal_id,
        intent.object_name,
        readback_bytes_sha256,
        observed_at_utc,
    )


@dataclass(frozen=True, slots=True)
class PersistedTrustedTimeHeadAnchorReceipt:
    """One committed byte-exact remote readback receipt."""

    anchor_receipt_id: str
    intent: PersistedTrustedTimeHeadAnchorIntent
    readback_bytes_sha256: str
    observed_at_utc: datetime
    semantic_sha256: str

    def __post_init__(self) -> None:
        _require_uuid(self.anchor_receipt_id, "receipt ID")
        if type(self.intent) is not PersistedTrustedTimeHeadAnchorIntent:
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor receipt intent is invalid"
            )
        try:
            self.intent.__post_init__()
        except TrustedTimeHeadAnchorPersistenceError:
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor receipt intent is invalid"
            ) from None
        readback = _require_sha256(
            self.readback_bytes_sha256,
            "receipt readback SHA-256",
        )
        if readback != self.intent.signed_envelope_sha256:
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor receipt readback conflicts"
            )
        _require_utc(self.observed_at_utc, "receipt observation instant")
        _require_sha256(self.semantic_sha256, "receipt semantic SHA-256")
        if self.semantic_sha256 != _sha256(self._semantic_material()):
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor receipt semantic SHA-256 conflicts"
            )

    def _semantic_material(self) -> tuple[object, ...]:
        return _receipt_material(
            anchor_receipt_id=self.anchor_receipt_id,
            intent=self.intent,
            readback_bytes_sha256=self.readback_bytes_sha256,
            observed_at_utc=self.observed_at_utc,
        )

    @property
    def canonical_payload(self) -> str:
        return canonical_json_text(self._semantic_material())


def _new_receipt(
    *,
    anchor_receipt_id: str,
    intent: PersistedTrustedTimeHeadAnchorIntent,
    readback_bytes_sha256: str,
    observed_at_utc: datetime,
) -> PersistedTrustedTimeHeadAnchorReceipt:
    material = _receipt_material(
        anchor_receipt_id=anchor_receipt_id,
        intent=intent,
        readback_bytes_sha256=readback_bytes_sha256,
        observed_at_utc=observed_at_utc,
    )
    return PersistedTrustedTimeHeadAnchorReceipt(
        anchor_receipt_id=anchor_receipt_id,
        intent=intent,
        readback_bytes_sha256=readback_bytes_sha256,
        observed_at_utc=observed_at_utc,
        semantic_sha256=_sha256(material),
    )


def _receipt_values(receipt: PersistedTrustedTimeHeadAnchorReceipt) -> dict[str, object]:
    intent = receipt.intent
    record = intent.record
    return {
        "anchor_receipt_id": receipt.anchor_receipt_id,
        "anchor_intent_id": intent.anchor_intent_id,
        "anchor_intent_sha256": intent.semantic_sha256,
        "signed_envelope_sha256": intent.signed_envelope_sha256,
        "deployment_identity_sha256": record.deployment_identity_sha256,
        "runtime_database_identity_sha256": record.runtime_database_identity_sha256,
        "anchor_project_identity_sha256": record.anchor_project_identity_sha256,
        "anchor_project_ref": record.anchor_project_ref,
        "bucket_name": record.bucket_name,
        "principal_id": record.principal_id,
        "object_name": intent.object_name,
        "readback_bytes_sha256": receipt.readback_bytes_sha256,
        "observed_at_utc": receipt.observed_at_utc,
        "canonical_payload": receipt.canonical_payload,
        "semantic_sha256": receipt.semantic_sha256,
    }


def _verify_signature(
    record: TrustedTimeHeadAnchorRecord,
    verifier: TrustedTimeHeadAnchorEd25519Verifier,
) -> None:
    try:
        verify = getattr(verifier, "verify_ed25519", None)
    except Exception:
        verify = None
    if not callable(verify):
        raise TrustedTimeHeadAnchorPersistenceError(
            "trusted-time anchor Ed25519 verifier is unavailable"
        )
    try:
        verified = verify(
            signing_key_id=record.signing_key_id,
            signing_public_key_sha256=record.signing_public_key_sha256,
            payload=record.signed_payload,
            signature=bytes.fromhex(record.signature_ed25519),
        )
    except Exception:
        raise TrustedTimeHeadAnchorPersistenceError(
            "trusted-time anchor Ed25519 verification failed"
        ) from None
    if type(verified) is not bool or not verified:
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "trusted-time anchor Ed25519 signature is invalid"
        )


def _intent_from_row(
    row: AnchorRow,
    *,
    verifier: TrustedTimeHeadAnchorEd25519Verifier,
) -> PersistedTrustedTimeHeadAnchorIntent:
    try:
        payload = _required_bytes(row, "signed_envelope_bytes")
        record = TrustedTimeHeadAnchorRecord.from_canonical_bytes(payload)
        _verify_signature(record, verifier)
        reason = TrustedTimeHeadAnchorCheckpointReason(_required_text(row, "checkpoint_reason"))
        intent = PersistedTrustedTimeHeadAnchorIntent(
            anchor_intent_id=_required_text(row, "anchor_intent_id"),
            checkpoint_reason=reason,
            checkpoint_interval_seconds=_required_integer(
                row,
                "checkpoint_interval_seconds",
            ),
            anchor_authority_sha256=_required_text(row, "anchor_authority_sha256"),
            record=record,
            object_name=_required_text(row, "object_name"),
            signed_envelope_bytes=payload,
            created_at_utc=_required_datetime(row, "created_at_utc"),
            semantic_sha256=_required_text(row, "semantic_sha256"),
        )
        _assert_exact_row(row, _intent_values(intent), "intent")
        return intent
    except TrustedTimeHeadAnchorPersistenceConflict:
        raise
    except (TrustedTimeHeadAnchorError, TrustedTimeHeadAnchorPersistenceError, ValueError):
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "persisted trusted-time anchor intent is malformed"
        ) from None


def _receipt_from_row(
    row: AnchorRow,
    *,
    intent: PersistedTrustedTimeHeadAnchorIntent,
) -> PersistedTrustedTimeHeadAnchorReceipt:
    try:
        receipt = PersistedTrustedTimeHeadAnchorReceipt(
            anchor_receipt_id=_required_text(row, "anchor_receipt_id"),
            intent=intent,
            readback_bytes_sha256=_required_text(row, "readback_bytes_sha256"),
            observed_at_utc=_required_datetime(row, "observed_at_utc"),
            semantic_sha256=_required_text(row, "semantic_sha256"),
        )
        _assert_exact_row(row, _receipt_values(receipt), "receipt")
        return receipt
    except TrustedTimeHeadAnchorPersistenceConflict:
        raise
    except TrustedTimeHeadAnchorPersistenceError:
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "persisted trusted-time anchor receipt is malformed"
        ) from None


def _validate_complete_local_chain(
    local_transitions: object,
) -> tuple[AuthenticatedTrustedTimeHeadTransition, ...]:
    try:
        return _validate_local_chain(local_transitions)
    except TrustedTimeHeadAnchorError:
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "trusted-time anchor requires a complete authenticated local chain"
        ) from None


def _expected_journal_transitions(
    connection: Connection,
    template: AuthenticatedTrustedTimeHeadTransition,
) -> tuple[AuthenticatedTrustedTimeHeadTransition, ...]:
    epoch_rows = (
        connection.execute(
            sa.select(phase6_trusted_time_epoch_registrations)
            .where(phase6_trusted_time_epoch_registrations.c.host_id == template.host_id)
            .order_by(phase6_trusted_time_epoch_registrations.c.epoch_sequence)
        )
        .mappings()
        .all()
    )
    expected: list[AuthenticatedTrustedTimeHeadTransition] = []
    previous_host_head_sha256: str | None = None
    for epoch_row in epoch_rows:
        epoch = _epoch_from_row(epoch_row)
        genesis_head = _new_head(epoch, None)
        expected.append(
            AuthenticatedTrustedTimeHeadTransition(
                deployment_identity_sha256=template.deployment_identity_sha256,
                runtime_database_identity_sha256=template.runtime_database_identity_sha256,
                anchor_project_identity_sha256=template.anchor_project_identity_sha256,
                anchor_project_ref=template.anchor_project_ref,
                bucket_name=template.bucket_name,
                principal_id=template.principal_id,
                head_authenticated_at_utc=epoch.registered_at_utc,
                host_id=epoch.host_id,
                source_id=epoch.source_id,
                source_authority_sha256=epoch.source_authority_sha256,
                policy_sha256=template.policy_sha256,
                persistence_contract_version=TRUSTED_TIME_PERSISTENCE_CONTRACT_VERSION,
                epoch_sequence=epoch.epoch_sequence,
                monitor_epoch_id=epoch.monitor_epoch_id,
                epoch_sha256=epoch.semantic_sha256,
                evaluation_sequence=0,
                evaluation_id=None,
                evaluation_record_sha256=None,
                state_sha256=None,
                probe_status=None,
                health=None,
                reason=None,
                hard_failure_latched=None,
                clock_recovery_qualified=None,
                evaluated_at_utc=None,
                evaluated_at_monotonic_ns=None,
                previous_host_head_sha256=previous_host_head_sha256,
                current_host_head_sha256=genesis_head.semantic_sha256,
            )
        )
        previous_host_head_sha256 = genesis_head.semantic_sha256
        evaluation_rows = (
            connection.execute(
                sa.select(phase6_trusted_time_probe_evaluations)
                .where(
                    phase6_trusted_time_probe_evaluations.c.host_id == template.host_id,
                    phase6_trusted_time_probe_evaluations.c.monitor_epoch_id
                    == epoch.monitor_epoch_id,
                )
                .order_by(phase6_trusted_time_probe_evaluations.c.evaluation_sequence)
            )
            .mappings()
            .all()
        )
        prior = None
        previous_evaluation = None
        for sequence, evaluation_row in enumerate(evaluation_rows, start=1):
            current_evaluation = _evaluation_from_row(
                evaluation_row,
                epoch=epoch,
                prior=prior,
                previous=previous_evaluation,
                expected_sequence=sequence,
            )
            state = current_evaluation.result.state
            head = _new_head(epoch, current_evaluation)
            expected.append(
                AuthenticatedTrustedTimeHeadTransition(
                    deployment_identity_sha256=template.deployment_identity_sha256,
                    runtime_database_identity_sha256=(template.runtime_database_identity_sha256),
                    anchor_project_identity_sha256=(template.anchor_project_identity_sha256),
                    anchor_project_ref=template.anchor_project_ref,
                    bucket_name=template.bucket_name,
                    principal_id=template.principal_id,
                    head_authenticated_at_utc=state.evaluated_at_utc,
                    host_id=epoch.host_id,
                    source_id=epoch.source_id,
                    source_authority_sha256=epoch.source_authority_sha256,
                    policy_sha256=template.policy_sha256,
                    persistence_contract_version=TRUSTED_TIME_PERSISTENCE_CONTRACT_VERSION,
                    epoch_sequence=epoch.epoch_sequence,
                    monitor_epoch_id=epoch.monitor_epoch_id,
                    epoch_sha256=epoch.semantic_sha256,
                    evaluation_sequence=current_evaluation.evaluation_sequence,
                    evaluation_id=current_evaluation.evaluation_id,
                    evaluation_record_sha256=current_evaluation.semantic_sha256,
                    state_sha256=state.semantic_sha256,
                    probe_status=current_evaluation.result.status,
                    health=state.health,
                    reason=state.reason,
                    hard_failure_latched=state.hard_failure_latched,
                    clock_recovery_qualified=state.clock_recovery_qualified,
                    evaluated_at_utc=state.evaluated_at_utc,
                    evaluated_at_monotonic_ns=state.evaluated_at_monotonic_ns,
                    previous_host_head_sha256=previous_host_head_sha256,
                    current_host_head_sha256=head.semantic_sha256,
                )
            )
            previous_host_head_sha256 = head.semantic_sha256
            prior = state
            previous_evaluation = current_evaluation
    return tuple(expected)


def _verify_local_journal(
    connection: Connection,
    transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    *,
    classify_proper_prefix_advance: bool = False,
) -> _VerifiedHost:
    try:
        _verify_global_integrity(connection)
        verified = _verified_host(
            connection,
            transitions[-1].host_id,
            for_update=False,
            collect_transitions=True,
        )
        if verified is None:
            raise TrustedTimePersistenceError("trusted-time anchor local journal is absent")
        template = transitions[0]
        expected = _authenticated_head_transitions(
            verified,
            deployment_identity_sha256=template.deployment_identity_sha256,
            runtime_database_identity_sha256=template.runtime_database_identity_sha256,
            anchor_project_identity_sha256=template.anchor_project_identity_sha256,
            anchor_project_ref=template.anchor_project_ref,
            bucket_name=template.bucket_name,
            principal_id=template.principal_id,
        )
    except TrustedTimePersistenceError:
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "trusted-time anchor local journal authentication failed"
        ) from None
    except TrustedTimeHeadAnchorError:
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "trusted-time anchor local journal projection failed"
        ) from None
    if expected != transitions:
        if (
            classify_proper_prefix_advance
            and len(transitions) < len(expected)
            and expected[: len(transitions)] == transitions
        ):
            raise TrustedTimeHeadAnchorSnapshotAdvanced(
                "trusted-time anchor complete SQL replay was advanced by an "
                "authenticated local append"
            )
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "trusted-time anchor local chain is not the complete SQL replay"
        )
    return verified


def _record_matches_transition(
    record: TrustedTimeHeadAnchorRecord,
    transition: AuthenticatedTrustedTimeHeadTransition,
) -> bool:
    return (
        record.deployment_identity_sha256 == transition.deployment_identity_sha256
        and record.runtime_database_identity_sha256 == transition.runtime_database_identity_sha256
        and record.anchor_project_identity_sha256 == transition.anchor_project_identity_sha256
        and record.anchor_project_ref == transition.anchor_project_ref
        and record.bucket_name == transition.bucket_name
        and record.principal_id == transition.principal_id
        and record.head_authenticated_at_utc == transition.head_authenticated_at_utc
        and record.host_id == transition.host_id
        and record.source_id == transition.source_id
        and record.source_authority_sha256 == transition.source_authority_sha256
        and record.policy_sha256 == transition.policy_sha256
        and record.persistence_contract_version == transition.persistence_contract_version
        and record.epoch_sequence == transition.epoch_sequence
        and record.monitor_epoch_id == transition.monitor_epoch_id
        and record.epoch_sha256 == transition.epoch_sha256
        and record.evaluation_sequence == transition.evaluation_sequence
        and record.evaluation_id == transition.evaluation_id
        and record.evaluation_record_sha256 == transition.evaluation_record_sha256
        and record.state_sha256 == transition.state_sha256
        and record.probe_status == transition.probe_status
        and record.health == transition.health
        and record.reason == transition.reason
        and record.hard_failure_latched == transition.hard_failure_latched
        and record.clock_recovery_qualified == transition.clock_recovery_qualified
        and record.evaluated_at_utc == transition.evaluated_at_utc
        and record.evaluated_at_monotonic_ns == transition.evaluated_at_monotonic_ns
        and record.local_previous_host_head_sha256 == transition.previous_host_head_sha256
        and record.current_host_head_sha256 == transition.current_host_head_sha256
    )


def _transition_template_from_record(
    record: TrustedTimeHeadAnchorRecord,
) -> AuthenticatedTrustedTimeHeadTransition:
    return AuthenticatedTrustedTimeHeadTransition(
        deployment_identity_sha256=record.deployment_identity_sha256,
        runtime_database_identity_sha256=record.runtime_database_identity_sha256,
        anchor_project_identity_sha256=record.anchor_project_identity_sha256,
        anchor_project_ref=record.anchor_project_ref,
        bucket_name=record.bucket_name,
        principal_id=record.principal_id,
        head_authenticated_at_utc=record.head_authenticated_at_utc,
        host_id=record.host_id,
        source_id=record.source_id,
        source_authority_sha256=record.source_authority_sha256,
        policy_sha256=record.policy_sha256,
        persistence_contract_version=record.persistence_contract_version,
        epoch_sequence=record.epoch_sequence,
        monitor_epoch_id=record.monitor_epoch_id,
        epoch_sha256=record.epoch_sha256,
        evaluation_sequence=record.evaluation_sequence,
        evaluation_id=record.evaluation_id,
        evaluation_record_sha256=record.evaluation_record_sha256,
        state_sha256=record.state_sha256,
        probe_status=record.probe_status,
        health=record.health,
        reason=record.reason,
        hard_failure_latched=record.hard_failure_latched,
        clock_recovery_qualified=record.clock_recovery_qualified,
        evaluated_at_utc=record.evaluated_at_utc,
        evaluated_at_monotonic_ns=record.evaluated_at_monotonic_ns,
        previous_host_head_sha256=record.local_previous_host_head_sha256,
        current_host_head_sha256=record.current_host_head_sha256,
    )


def _committed_evidence(
    intent: PersistedTrustedTimeHeadAnchorIntent,
) -> CommittedTrustedTimeHeadAnchorIntentEvidence:
    record = intent.record
    return _new_committed_trusted_time_head_anchor_intent_evidence(
        intent_id=intent.anchor_intent_id,
        committed_at_utc=intent.created_at_utc,
        deployment_identity_sha256=record.deployment_identity_sha256,
        runtime_database_identity_sha256=record.runtime_database_identity_sha256,
        anchor_project_identity_sha256=record.anchor_project_identity_sha256,
        anchor_project_ref=record.anchor_project_ref,
        bucket_name=record.bucket_name,
        principal_id=record.principal_id,
        anchor_sequence=record.anchor_sequence,
        signed_envelope_sha256=intent.signed_envelope_sha256,
        semantic_sha256=record.semantic_sha256,
        previous_anchor_sha256=record.previous_anchor_sha256,
        current_host_head_sha256=record.current_host_head_sha256,
        checkpoint_reason=record.checkpoint_reason,
        checkpoint_interval_seconds=record.checkpoint_interval_seconds,
        anchor_authority_sha256=record.anchor_authority_sha256,
    )


def _require_provider_readback_evidence(
    intent: PersistedTrustedTimeHeadAnchorIntent,
    provider_readback: object,
) -> TrustedTimeHeadAnchorProviderReadbackEvidence:
    if type(provider_readback) is not TrustedTimeHeadAnchorProviderReadbackEvidence:
        raise TrustedTimeHeadAnchorPersistenceError(
            "trusted-time anchor confirmation requires exact provider-readback evidence"
        )
    evidence = provider_readback
    try:
        evidence.__post_init__()
    except TrustedTimeHeadAnchorError:
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "trusted-time anchor provider-readback evidence is invalid"
        ) from None
    if evidence._consumed:
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "trusted-time anchor provider-readback evidence was already consumed"
        )
    record = intent.record
    identity = evidence.provider_identity
    if (
        evidence.anchor_intent_id != intent.anchor_intent_id
        or evidence.anchor_intent_semantic_sha256 != intent.semantic_sha256
        or evidence.bucket_name != record.bucket_name
        or evidence.object_name != intent.object_name
        or evidence.candidate_record != record
        or evidence.candidate_bytes != intent.signed_envelope_bytes
        or evidence.candidate_bytes_sha256 != intent.signed_envelope_sha256
        or evidence.candidate_semantic_sha256 != record.semantic_sha256
        or identity.anchor_project_identity_sha256 != record.anchor_project_identity_sha256
        or identity.anchor_project_ref != record.anchor_project_ref
        or identity.principal_id != record.principal_id
        or identity.bucket_name != record.bucket_name
    ):
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "trusted-time anchor provider-readback evidence conflicts with the durable intent"
        )
    return evidence


def _claim_provider_readback_evidence(
    evidence: TrustedTimeHeadAnchorProviderReadbackEvidence,
) -> object:
    try:
        return _claim_trusted_time_head_anchor_provider_readback(evidence)
    except TrustedTimeHeadAnchorError:
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "trusted-time anchor provider-readback evidence was already consumed or is in use"
        ) from None


def _release_provider_readback_evidence(
    evidence: TrustedTimeHeadAnchorProviderReadbackEvidence,
    claim_token: object,
) -> None:
    try:
        _release_trusted_time_head_anchor_provider_readback(
            evidence,
            claim_token,
        )
    except TrustedTimeHeadAnchorError:
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "trusted-time anchor provider-readback evidence cannot be released"
        ) from None


def _consume_provider_readback_evidence(
    evidence: TrustedTimeHeadAnchorProviderReadbackEvidence,
    claim_token: object,
) -> None:
    try:
        _consume_trusted_time_head_anchor_provider_readback(
            evidence,
            claim_token,
        )
    except TrustedTimeHeadAnchorError:
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "trusted-time anchor provider-readback evidence cannot be consumed"
        ) from None


@dataclass(frozen=True, slots=True)
class _AnchorHistory:
    intents: tuple[PersistedTrustedTimeHeadAnchorIntent, ...]
    receipts: tuple[PersistedTrustedTimeHeadAnchorReceipt, ...]
    pending: PersistedTrustedTimeHeadAnchorIntent | None


@dataclass(frozen=True, slots=True, init=False)
class TrustedTimeHeadAnchorPersistenceSnapshot:
    """Opaque compact cursor plus one authenticated local/anchor delta batch."""

    local_transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...]
    confirmed_anchor_records: tuple[TrustedTimeHeadAnchorRecord, ...]
    pending_intent: PersistedTrustedTimeHeadAnchorIntent | None
    pending_intent_local_transition_ordinal: int | None
    committed_pending_evidence: CommittedTrustedTimeHeadAnchorIntentEvidence | None
    authenticated_journal_tip: AuthenticatedTrustedTimeHeadJournalTip
    local_transition_count: int
    confirmed_anchor_count: int
    current_host_head_sha256: str
    complete_replay: bool

    def __init__(self) -> None:
        raise TypeError("TrustedTimeHeadAnchorPersistenceSnapshot is issued by anchor persistence")

    @property
    def operational_control_authorized(self) -> bool:
        return False

    @property
    def readiness_authorized(self) -> bool:
        return False

    @property
    def broker_action_authorized(self) -> bool:
        return False


def _new_head_anchor_persistence_snapshot(
    *,
    local_transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    confirmed_anchor_records: tuple[TrustedTimeHeadAnchorRecord, ...],
    pending_intent: PersistedTrustedTimeHeadAnchorIntent | None,
    pending_intent_local_transition_ordinal: int | None,
    authenticated_journal_tip: AuthenticatedTrustedTimeHeadJournalTip,
    complete_replay: bool,
) -> TrustedTimeHeadAnchorPersistenceSnapshot:
    snapshot = object.__new__(TrustedTimeHeadAnchorPersistenceSnapshot)
    object.__setattr__(snapshot, "local_transitions", local_transitions)
    object.__setattr__(
        snapshot,
        "confirmed_anchor_records",
        confirmed_anchor_records,
    )
    object.__setattr__(snapshot, "pending_intent", pending_intent)
    object.__setattr__(
        snapshot,
        "pending_intent_local_transition_ordinal",
        pending_intent_local_transition_ordinal,
    )
    object.__setattr__(
        snapshot,
        "committed_pending_evidence",
        None if pending_intent is None else _committed_evidence(pending_intent),
    )
    object.__setattr__(snapshot, "authenticated_journal_tip", authenticated_journal_tip)
    object.__setattr__(
        snapshot,
        "local_transition_count",
        authenticated_journal_tip.local_transition_count,
    )
    object.__setattr__(
        snapshot,
        "confirmed_anchor_count",
        authenticated_journal_tip.confirmed_anchor_count,
    )
    object.__setattr__(
        snapshot,
        "current_host_head_sha256",
        authenticated_journal_tip.current_local_host_head_sha256,
    )
    object.__setattr__(snapshot, "complete_replay", complete_replay)
    return snapshot


@dataclass(frozen=True, slots=True)
class _AnchorSnapshotState:
    snapshot: TrustedTimeHeadAnchorPersistenceSnapshot
    process_id: int
    repository_token: object
    local_boundary: _VerifiedHost
    intent_count: int
    receipt_count: int
    terminal_intent: PersistedTrustedTimeHeadAnchorIntent | None
    terminal_receipt: PersistedTrustedTimeHeadAnchorReceipt | None
    terminal_intent_local_transition_ordinal: int | None
    pending: PersistedTrustedTimeHeadAnchorIntent | None
    journal_tip: AuthenticatedTrustedTimeHeadJournalTip


def _load_anchor_history(
    connection: Connection,
    transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    *,
    verifier: TrustedTimeHeadAnchorEd25519Verifier,
    anchor_authority_sha256: str,
    signing_key_id: str,
    signing_public_key_sha256: str,
) -> _AnchorHistory:
    host_id = transitions[-1].host_id
    intent_rows = (
        connection.execute(
            sa.select(phase6_trusted_time_head_anchor_intents)
            .where(phase6_trusted_time_head_anchor_intents.c.host_id == host_id)
            .order_by(phase6_trusted_time_head_anchor_intents.c.anchor_sequence)
        )
        .mappings()
        .all()
    )
    intents = tuple(_intent_from_row(row, verifier=verifier) for row in intent_rows)
    positions = {
        transition.current_host_head_sha256: index for index, transition in enumerate(transitions)
    }
    previous: PersistedTrustedTimeHeadAnchorIntent | None = None
    previous_position: int | None = None
    for expected_sequence, intent in enumerate(intents, start=1):
        record = intent.record
        position = positions.get(record.current_host_head_sha256)
        if (
            intent.anchor_authority_sha256 != anchor_authority_sha256
            or record.anchor_authority_sha256 != anchor_authority_sha256
            or record.signing_key_id != signing_key_id
            or record.signing_public_key_sha256 != signing_public_key_sha256
            or record.anchor_sequence != expected_sequence
            or position is None
            or not _record_matches_transition(record, transitions[position])
        ):
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "persisted trusted-time anchor intent conflicts with authenticated history"
            )
        if previous_position is not None and position <= previous_position:
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "persisted trusted-time anchor checkpoints do not advance"
            )
        if record.previous_anchor_sha256 != (
            None if previous is None else previous.signed_envelope_sha256
        ) or record.previous_anchored_host_head_sha256 != (
            None if previous is None else previous.record.current_host_head_sha256
        ):
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "persisted trusted-time anchor predecessor chain conflicts"
            )
        previous = intent
        previous_position = position

    receipt_rows = (
        connection.execute(
            sa.select(phase6_trusted_time_head_anchor_receipts)
            .select_from(
                phase6_trusted_time_head_anchor_receipts.join(
                    phase6_trusted_time_head_anchor_intents,
                    phase6_trusted_time_head_anchor_receipts.c.anchor_intent_id
                    == phase6_trusted_time_head_anchor_intents.c.anchor_intent_id,
                )
            )
            .where(phase6_trusted_time_head_anchor_intents.c.host_id == host_id)
        )
        .mappings()
        .all()
    )
    intents_by_id = {intent.anchor_intent_id: intent for intent in intents}
    receipts_by_intent: dict[str, PersistedTrustedTimeHeadAnchorReceipt] = {}
    for row in receipt_rows:
        intent_id = _required_text(row, "anchor_intent_id")
        receipt_intent = intents_by_id.get(intent_id)
        if receipt_intent is None or intent_id in receipts_by_intent:
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "persisted trusted-time anchor receipt chain conflicts"
            )
        decoded_receipt = _receipt_from_row(row, intent=receipt_intent)
        receipts_by_intent[intent_id] = decoded_receipt

    receipts: list[PersistedTrustedTimeHeadAnchorReceipt] = []
    pending_intents: list[PersistedTrustedTimeHeadAnchorIntent] = []
    observed_pending = False
    for candidate_intent in intents:
        candidate_receipt = receipts_by_intent.get(candidate_intent.anchor_intent_id)
        if candidate_receipt is None:
            observed_pending = True
            pending_intents.append(candidate_intent)
            continue
        if observed_pending:
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "persisted trusted-time anchor receipt history is not a prefix"
            )
        receipts.append(candidate_receipt)
    if len(pending_intents) > 1:
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "persisted trusted-time anchor history has multiple unresolved intents"
        )
    return _AnchorHistory(
        intents=intents,
        receipts=tuple(receipts),
        pending=None if not pending_intents else pending_intents[0],
    )


_ANCHOR_FULL_REPLAY_PAGE_SIZE = 256


@dataclass(frozen=True, slots=True)
class _BoundedAnchorEntry:
    intent: PersistedTrustedTimeHeadAnchorIntent
    receipt: PersistedTrustedTimeHeadAnchorReceipt | None


@dataclass(frozen=True, slots=True)
class _BoundedAnchorReplayResult:
    intent_count: int
    receipt_count: int
    terminal_intent: PersistedTrustedTimeHeadAnchorIntent | None
    terminal_receipt: PersistedTrustedTimeHeadAnchorReceipt | None
    terminal_intent_local_transition_ordinal: int | None
    pending: PersistedTrustedTimeHeadAnchorIntent | None
    first_confirmed_local_transition_ordinal: int | None
    terminal_confirmed_local_transition_ordinal: int | None


class _BoundedAnchorReplay:
    """Merge bounded durable anchor pages into one authenticated local replay."""

    def __init__(
        self,
        connection: Connection,
        *,
        host_id: str,
        verifier: TrustedTimeHeadAnchorEd25519Verifier,
        anchor_authority_sha256: str,
        signing_key_id: str,
        signing_public_key_sha256: str,
    ) -> None:
        self._connection = connection
        self._host_id = host_id
        self._verifier = verifier
        self._anchor_authority_sha256 = anchor_authority_sha256
        self._signing_key_id = signing_key_id
        self._signing_public_key_sha256 = signing_public_key_sha256
        self._page: tuple[_BoundedAnchorEntry, ...] = ()
        self._page_index = 0
        self._exhausted = False
        self._intent_count = 0
        self._receipt_count = 0
        self._previous_intent: PersistedTrustedTimeHeadAnchorIntent | None = None
        self._terminal_receipt: PersistedTrustedTimeHeadAnchorReceipt | None = None
        self._pending: PersistedTrustedTimeHeadAnchorIntent | None = None
        self._local_ordinal = 0
        self._terminal_intent_ordinal: int | None = None
        self._first_confirmed_ordinal: int | None = None
        self._terminal_confirmed_ordinal: int | None = None

    def _load_page(self) -> None:
        if self._exhausted:
            return
        rows = (
            self._connection.execute(
                sa.select(phase6_trusted_time_head_anchor_intents)
                .where(
                    phase6_trusted_time_head_anchor_intents.c.host_id == self._host_id,
                    phase6_trusted_time_head_anchor_intents.c.anchor_sequence > self._intent_count,
                )
                .order_by(phase6_trusted_time_head_anchor_intents.c.anchor_sequence)
                .limit(_ANCHOR_FULL_REPLAY_PAGE_SIZE)
            )
            .mappings()
            .all()
        )
        if not rows:
            self._exhausted = True
            self._page = ()
            self._page_index = 0
            return
        intents = tuple(_intent_from_row(row, verifier=self._verifier) for row in rows)
        intent_ids = tuple(intent.anchor_intent_id for intent in intents)
        receipt_rows = (
            self._connection.execute(
                sa.select(phase6_trusted_time_head_anchor_receipts).where(
                    phase6_trusted_time_head_anchor_receipts.c.anchor_intent_id.in_(intent_ids)
                )
            )
            .mappings()
            .all()
        )
        raw_receipts: dict[str, AnchorRow] = {}
        for row in receipt_rows:
            intent_id = _required_text(row, "anchor_intent_id")
            if intent_id in raw_receipts:
                raise TrustedTimeHeadAnchorPersistenceConflict(
                    "persisted trusted-time anchor receipt page contains duplicates"
                )
            raw_receipts[intent_id] = row
        entries: list[_BoundedAnchorEntry] = []
        previous = self._previous_intent
        for offset, intent in enumerate(intents, start=1):
            expected_sequence = self._intent_count + offset
            record = intent.record
            if (
                record.anchor_sequence != expected_sequence
                or intent.anchor_authority_sha256 != self._anchor_authority_sha256
                or record.anchor_authority_sha256 != self._anchor_authority_sha256
                or record.signing_key_id != self._signing_key_id
                or record.signing_public_key_sha256 != self._signing_public_key_sha256
                or record.previous_anchor_sha256
                != (None if previous is None else previous.signed_envelope_sha256)
                or record.previous_anchored_host_head_sha256
                != (None if previous is None else previous.record.current_host_head_sha256)
            ):
                raise TrustedTimeHeadAnchorPersistenceConflict(
                    "persisted trusted-time anchor bounded intent chain conflicts"
                )
            raw_receipt = raw_receipts.pop(intent.anchor_intent_id, None)
            receipt = None if raw_receipt is None else _receipt_from_row(raw_receipt, intent=intent)
            if self._pending is not None or (entries and entries[-1].receipt is None):
                raise TrustedTimeHeadAnchorPersistenceConflict(
                    "persisted trusted-time anchor receipt history is not a prefix"
                )
            if receipt is None:
                self._pending = intent
            else:
                self._receipt_count += 1
                self._terminal_receipt = receipt
            entries.append(_BoundedAnchorEntry(intent=intent, receipt=receipt))
            previous = intent
        if raw_receipts:
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "persisted trusted-time anchor receipt page contains foreign intents"
            )
        self._intent_count += len(entries)
        self._previous_intent = previous
        self._page = tuple(entries)
        self._page_index = 0
        if len(entries) < _ANCHOR_FULL_REPLAY_PAGE_SIZE:
            self._exhausted = True

    def _next_entry(self) -> _BoundedAnchorEntry | None:
        if self._page_index >= len(self._page):
            self._load_page()
        if self._page_index >= len(self._page):
            return None
        return self._page[self._page_index]

    def consume_local_page(
        self,
        page: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    ) -> None:
        if not page or len(page) > _ANCHOR_FULL_REPLAY_PAGE_SIZE:
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "trusted-time anchor local replay page is invalid"
            )
        for transition in page:
            self._local_ordinal += 1
            entry = self._next_entry()
            if entry is None or entry.intent.record.current_host_head_sha256 != (
                transition.current_host_head_sha256
            ):
                continue
            if not _record_matches_transition(entry.intent.record, transition):
                raise TrustedTimeHeadAnchorPersistenceConflict(
                    "persisted trusted-time anchor intent conflicts with its local head"
                )
            self._terminal_intent_ordinal = self._local_ordinal
            if entry.receipt is not None:
                if self._first_confirmed_ordinal is None:
                    self._first_confirmed_ordinal = self._local_ordinal
                self._terminal_confirmed_ordinal = self._local_ordinal
            self._page_index += 1

    def finish(self) -> _BoundedAnchorReplayResult:
        if self._next_entry() is not None:
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "persisted trusted-time anchor head is absent from local history"
            )
        if self._intent_count - self._receipt_count not in (0, 1):
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "persisted trusted-time anchor history has multiple pending intents"
            )
        if (self._pending is None) != (self._intent_count == self._receipt_count):
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "persisted trusted-time anchor pending tip conflicts"
            )
        if self._intent_count and self._terminal_intent_ordinal is None:
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "persisted trusted-time anchor terminal lacks a local ordinal"
            )
        receipt_join = phase6_trusted_time_head_anchor_receipts.join(
            phase6_trusted_time_head_anchor_intents,
            phase6_trusted_time_head_anchor_receipts.c.anchor_intent_id
            == phase6_trusted_time_head_anchor_intents.c.anchor_intent_id,
        )
        exact_receipt_count = self._connection.scalar(
            sa.select(sa.func.count())
            .select_from(receipt_join)
            .where(phase6_trusted_time_head_anchor_intents.c.host_id == self._host_id)
        )
        if exact_receipt_count != self._receipt_count:
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "persisted trusted-time anchor receipt count conflicts"
            )
        return _BoundedAnchorReplayResult(
            intent_count=self._intent_count,
            receipt_count=self._receipt_count,
            terminal_intent=self._previous_intent,
            terminal_receipt=self._terminal_receipt,
            terminal_intent_local_transition_ordinal=(self._terminal_intent_ordinal),
            pending=self._pending,
            first_confirmed_local_transition_ordinal=(self._first_confirmed_ordinal),
            terminal_confirmed_local_transition_ordinal=(self._terminal_confirmed_ordinal),
        )


def _lock_and_assert_snapshot_unchanged(
    connection: Connection,
    transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    history: _AnchorHistory,
) -> None:
    """Take the short host serialization lock and compare compact SQL tips."""

    host_id = transitions[-1].host_id
    head_statement = sa.select(phase6_trusted_time_host_heads.c.semantic_sha256).where(
        phase6_trusted_time_host_heads.c.host_id == host_id
    )
    if connection.dialect.name == "postgresql":
        head_statement = head_statement.with_for_update()
    current_head = connection.scalar(head_statement)
    if current_head != transitions[-1].current_host_head_sha256:
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "trusted-time anchor local head changed after integrity replay"
        )

    intent_count = connection.scalar(
        sa.select(sa.func.count())
        .select_from(phase6_trusted_time_head_anchor_intents)
        .where(phase6_trusted_time_head_anchor_intents.c.host_id == host_id)
    )
    terminal_intent = connection.execute(
        sa.select(
            phase6_trusted_time_head_anchor_intents.c.anchor_intent_id,
            phase6_trusted_time_head_anchor_intents.c.semantic_sha256,
        )
        .where(phase6_trusted_time_head_anchor_intents.c.host_id == host_id)
        .order_by(phase6_trusted_time_head_anchor_intents.c.anchor_sequence.desc())
        .limit(1)
    ).one_or_none()
    expected_terminal_intent = (
        None
        if not history.intents
        else (
            history.intents[-1].anchor_intent_id,
            history.intents[-1].semantic_sha256,
        )
    )
    if (
        intent_count != len(history.intents)
        or (None if terminal_intent is None else tuple(terminal_intent)) != expected_terminal_intent
    ):
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "trusted-time anchor intent history changed after integrity replay"
        )

    receipt_join = phase6_trusted_time_head_anchor_receipts.join(
        phase6_trusted_time_head_anchor_intents,
        phase6_trusted_time_head_anchor_receipts.c.anchor_intent_id
        == phase6_trusted_time_head_anchor_intents.c.anchor_intent_id,
    )
    receipt_count = connection.scalar(
        sa.select(sa.func.count())
        .select_from(receipt_join)
        .where(phase6_trusted_time_head_anchor_intents.c.host_id == host_id)
    )
    terminal_receipt = connection.execute(
        sa.select(
            phase6_trusted_time_head_anchor_receipts.c.anchor_receipt_id,
            phase6_trusted_time_head_anchor_receipts.c.semantic_sha256,
        )
        .select_from(receipt_join)
        .where(phase6_trusted_time_head_anchor_intents.c.host_id == host_id)
        .order_by(phase6_trusted_time_head_anchor_intents.c.anchor_sequence.desc())
        .limit(1)
    ).one_or_none()
    expected_terminal_receipt = (
        None
        if not history.receipts
        else (
            history.receipts[-1].anchor_receipt_id,
            history.receipts[-1].semantic_sha256,
        )
    )
    if (
        receipt_count != len(history.receipts)
        or (None if terminal_receipt is None else tuple(terminal_receipt))
        != expected_terminal_receipt
    ):
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "trusted-time anchor receipt history changed after integrity replay"
        )


@dataclass(frozen=True, slots=True)
class _AnchorSuffix:
    intent_count: int
    receipt_count: int
    terminal_intent: PersistedTrustedTimeHeadAnchorIntent | None
    terminal_receipt: PersistedTrustedTimeHeadAnchorReceipt | None
    terminal_intent_local_transition_ordinal: int | None
    pending: PersistedTrustedTimeHeadAnchorIntent | None
    newly_confirmed_records: tuple[TrustedTimeHeadAnchorRecord, ...]
    newly_confirmed_ordinals: tuple[int, ...]


def _lock_and_assert_compact_snapshot(
    connection: Connection,
    state: _AnchorSnapshotState,
    *,
    verifier: TrustedTimeHeadAnchorEd25519Verifier,
) -> None:
    """Serialize one mutation and compare only indexed compact SQL tips."""

    host_id = state.journal_tip.current_transition.host_id
    head_statement = sa.select(phase6_trusted_time_host_heads).where(
        phase6_trusted_time_host_heads.c.host_id == host_id
    )
    if connection.dialect.name == "postgresql":
        head_statement = head_statement.with_for_update()
    head_row = connection.execute(head_statement).mappings().one_or_none()
    if head_row is None:
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "trusted-time anchor compact local head disappeared"
        )
    try:
        locked_head = _head_from_row(head_row)
    except TrustedTimePersistenceError:
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "trusted-time anchor compact local head authentication failed"
        ) from None
    try:
        exact_local_tip = _verified_host_suffix_from_boundary(
            connection,
            host_id=host_id,
            epoch=state.local_boundary.epoch,
            head_boundary=state.local_boundary.head,
            prior=state.local_boundary.prior,
            terminal_evaluation=state.local_boundary.terminal_evaluation,
        )
    except TrustedTimePersistenceError:
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "trusted-time anchor compact local suffix authentication failed"
        ) from None
    if locked_head != state.local_boundary.head:
        if exact_local_tip.head == locked_head and exact_local_tip.head_transitions:
            raise TrustedTimeHeadAnchorSnapshotAdvanced(
                "trusted-time anchor compact snapshot was advanced by an authenticated local append"
            )
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "trusted-time anchor compact local head conflicts"
        )
    if exact_local_tip.head_transitions:
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "trusted-time anchor compact local suffix conflicts with its unchanged head"
        )

    if state.terminal_intent is not None:
        exact_intent_row = (
            connection.execute(
                sa.select(phase6_trusted_time_head_anchor_intents).where(
                    phase6_trusted_time_head_anchor_intents.c.anchor_intent_id
                    == state.terminal_intent.anchor_intent_id
                )
            )
            .mappings()
            .one_or_none()
        )
        if exact_intent_row is None:
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "trusted-time anchor compact intent tip disappeared"
            )
        if _intent_from_row(exact_intent_row, verifier=verifier) != (state.terminal_intent):
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "trusted-time anchor compact intent tip conflicts"
            )
    if state.terminal_receipt is not None:
        exact_receipt_row = (
            connection.execute(
                sa.select(phase6_trusted_time_head_anchor_receipts).where(
                    phase6_trusted_time_head_anchor_receipts.c.anchor_receipt_id
                    == state.terminal_receipt.anchor_receipt_id
                )
            )
            .mappings()
            .one_or_none()
        )
        if exact_receipt_row is None:
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "trusted-time anchor compact receipt tip disappeared"
            )
        if (
            _receipt_from_row(
                exact_receipt_row,
                intent=state.terminal_receipt.intent,
            )
            != state.terminal_receipt
        ):
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "trusted-time anchor compact receipt tip conflicts"
            )

    intent_tip = connection.execute(
        sa.select(
            phase6_trusted_time_head_anchor_intents.c.anchor_intent_id,
            phase6_trusted_time_head_anchor_intents.c.semantic_sha256,
            phase6_trusted_time_head_anchor_intents.c.anchor_sequence,
        )
        .where(phase6_trusted_time_head_anchor_intents.c.host_id == host_id)
        .order_by(phase6_trusted_time_head_anchor_intents.c.anchor_sequence.desc())
        .limit(1)
    ).one_or_none()
    expected_intent_tip = (
        None
        if state.terminal_intent is None
        else (
            state.terminal_intent.anchor_intent_id,
            state.terminal_intent.semantic_sha256,
            state.intent_count,
        )
    )
    if (None if intent_tip is None else tuple(intent_tip)) != expected_intent_tip:
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "trusted-time anchor compact intent tip changed"
        )

    receipt_join = phase6_trusted_time_head_anchor_receipts.join(
        phase6_trusted_time_head_anchor_intents,
        phase6_trusted_time_head_anchor_receipts.c.anchor_intent_id
        == phase6_trusted_time_head_anchor_intents.c.anchor_intent_id,
    )
    receipt_tip = connection.execute(
        sa.select(
            phase6_trusted_time_head_anchor_receipts.c.anchor_receipt_id,
            phase6_trusted_time_head_anchor_receipts.c.semantic_sha256,
            phase6_trusted_time_head_anchor_intents.c.anchor_sequence,
        )
        .select_from(receipt_join)
        .where(phase6_trusted_time_head_anchor_intents.c.host_id == host_id)
        .order_by(phase6_trusted_time_head_anchor_intents.c.anchor_sequence.desc())
        .limit(1)
    ).one_or_none()
    expected_receipt_tip = (
        None
        if state.terminal_receipt is None
        else (
            state.terminal_receipt.anchor_receipt_id,
            state.terminal_receipt.semantic_sha256,
            state.receipt_count,
        )
    )
    if (None if receipt_tip is None else tuple(receipt_tip)) != expected_receipt_tip:
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "trusted-time anchor compact receipt tip changed"
        )


def _load_anchor_suffix(
    connection: Connection,
    state: _AnchorSnapshotState,
    local_suffix: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    *,
    verifier: TrustedTimeHeadAnchorEd25519Verifier,
    anchor_authority_sha256: str,
    signing_key_id: str,
    signing_public_key_sha256: str,
) -> _AnchorSuffix:
    """Authenticate compact SQL tips and rows appended after one sealed cursor."""

    if state.terminal_intent is not None:
        row = (
            connection.execute(
                sa.select(phase6_trusted_time_head_anchor_intents).where(
                    phase6_trusted_time_head_anchor_intents.c.anchor_intent_id
                    == state.terminal_intent.anchor_intent_id
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None or _intent_from_row(row, verifier=verifier) != state.terminal_intent:
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "trusted-time anchor compact intent tip conflicts"
            )
    if state.terminal_receipt is not None:
        row = (
            connection.execute(
                sa.select(phase6_trusted_time_head_anchor_receipts).where(
                    phase6_trusted_time_head_anchor_receipts.c.anchor_receipt_id
                    == state.terminal_receipt.anchor_receipt_id
                )
            )
            .mappings()
            .one_or_none()
        )
        if (
            row is None
            or _receipt_from_row(row, intent=state.terminal_receipt.intent)
            != state.terminal_receipt
        ):
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "trusted-time anchor compact receipt tip conflicts"
            )

    local_by_head: dict[str, tuple[int, AuthenticatedTrustedTimeHeadTransition]] = {
        state.journal_tip.current_transition.current_host_head_sha256: (
            state.journal_tip.local_transition_count,
            state.journal_tip.current_transition,
        )
    }
    for offset, transition in enumerate(local_suffix, start=1):
        local_by_head[transition.current_host_head_sha256] = (
            state.journal_tip.local_transition_count + offset,
            transition,
        )

    intent_rows = (
        connection.execute(
            sa.select(phase6_trusted_time_head_anchor_intents)
            .where(
                phase6_trusted_time_head_anchor_intents.c.host_id
                == state.journal_tip.current_transition.host_id,
                phase6_trusted_time_head_anchor_intents.c.anchor_sequence > state.intent_count,
            )
            .order_by(phase6_trusted_time_head_anchor_intents.c.anchor_sequence)
        )
        .mappings()
        .all()
    )
    new_intents: list[PersistedTrustedTimeHeadAnchorIntent] = []
    intent_ordinals: dict[str, int] = {}
    if state.pending is not None:
        if state.terminal_intent_local_transition_ordinal is None:
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "trusted-time anchor pending intent lacks a local ordinal"
            )
        intent_ordinals[state.pending.anchor_intent_id] = (
            state.terminal_intent_local_transition_ordinal
        )
    previous_intent = state.terminal_intent
    previous_ordinal = state.terminal_intent_local_transition_ordinal
    for offset, row in enumerate(intent_rows, start=1):
        intent = _intent_from_row(row, verifier=verifier)
        record = intent.record
        local_match = local_by_head.get(record.current_host_head_sha256)
        if (
            record.anchor_sequence != state.intent_count + offset
            or intent.anchor_authority_sha256 != anchor_authority_sha256
            or record.anchor_authority_sha256 != anchor_authority_sha256
            or record.signing_key_id != signing_key_id
            or record.signing_public_key_sha256 != signing_public_key_sha256
            or local_match is None
            or not _record_matches_transition(record, local_match[1])
            or local_match[0] <= (0 if previous_ordinal is None else previous_ordinal)
            or record.previous_anchor_sha256
            != (None if previous_intent is None else previous_intent.signed_envelope_sha256)
            or record.previous_anchored_host_head_sha256
            != (
                None if previous_intent is None else previous_intent.record.current_host_head_sha256
            )
        ):
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "trusted-time anchor incremental intent suffix conflicts"
            )
        new_intents.append(intent)
        intent_ordinals[intent.anchor_intent_id] = local_match[0]
        previous_intent = intent
        previous_ordinal = local_match[0]

    intents_by_id = {intent.anchor_intent_id: intent for intent in new_intents}
    if state.pending is not None:
        intents_by_id[state.pending.anchor_intent_id] = state.pending
    receipt_join = phase6_trusted_time_head_anchor_receipts.join(
        phase6_trusted_time_head_anchor_intents,
        phase6_trusted_time_head_anchor_receipts.c.anchor_intent_id
        == phase6_trusted_time_head_anchor_intents.c.anchor_intent_id,
    )
    receipt_rows = (
        connection.execute(
            sa.select(
                phase6_trusted_time_head_anchor_receipts,
                phase6_trusted_time_head_anchor_intents.c.anchor_sequence.label("_anchor_sequence"),
            )
            .select_from(receipt_join)
            .where(
                phase6_trusted_time_head_anchor_intents.c.host_id
                == state.journal_tip.current_transition.host_id,
                phase6_trusted_time_head_anchor_intents.c.anchor_sequence > state.receipt_count,
            )
            .order_by(phase6_trusted_time_head_anchor_intents.c.anchor_sequence)
        )
        .mappings()
        .all()
    )
    new_receipts: list[PersistedTrustedTimeHeadAnchorReceipt] = []
    new_confirmed_ordinals: list[int] = []
    for offset, row in enumerate(receipt_rows, start=1):
        sequence = _required_integer(row, "_anchor_sequence")
        intent_id = _required_text(row, "anchor_intent_id")
        receipt_intent = intents_by_id.get(intent_id)
        ordinal = intent_ordinals.get(intent_id)
        if sequence != state.receipt_count + offset or receipt_intent is None or ordinal is None:
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "trusted-time anchor incremental receipt suffix is not a prefix"
            )
        new_receipts.append(_receipt_from_row(row, intent=receipt_intent))
        new_confirmed_ordinals.append(ordinal)

    final_intent_count = state.intent_count + len(new_intents)
    final_receipt_count = state.receipt_count + len(new_receipts)
    terminal_intent = previous_intent
    terminal_receipt = state.terminal_receipt if not new_receipts else new_receipts[-1]
    if final_intent_count == final_receipt_count:
        pending = None
    elif final_intent_count == final_receipt_count + 1:
        pending = terminal_intent
    else:
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "trusted-time anchor incremental history has multiple pending intents"
        )

    terminal_intent_row = connection.execute(
        sa.select(
            phase6_trusted_time_head_anchor_intents.c.anchor_intent_id,
            phase6_trusted_time_head_anchor_intents.c.semantic_sha256,
            phase6_trusted_time_head_anchor_intents.c.anchor_sequence,
        )
        .where(
            phase6_trusted_time_head_anchor_intents.c.host_id
            == state.journal_tip.current_transition.host_id
        )
        .order_by(phase6_trusted_time_head_anchor_intents.c.anchor_sequence.desc())
        .limit(1)
    ).one_or_none()
    expected_intent_tip = (
        None
        if terminal_intent is None
        else (
            terminal_intent.anchor_intent_id,
            terminal_intent.semantic_sha256,
            final_intent_count,
        )
    )
    if (None if terminal_intent_row is None else tuple(terminal_intent_row)) != (
        expected_intent_tip
    ):
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "trusted-time anchor incremental intent tip changed"
        )

    terminal_receipt_row = connection.execute(
        sa.select(
            phase6_trusted_time_head_anchor_receipts.c.anchor_receipt_id,
            phase6_trusted_time_head_anchor_receipts.c.semantic_sha256,
            phase6_trusted_time_head_anchor_intents.c.anchor_sequence,
        )
        .select_from(receipt_join)
        .where(
            phase6_trusted_time_head_anchor_intents.c.host_id
            == state.journal_tip.current_transition.host_id
        )
        .order_by(phase6_trusted_time_head_anchor_intents.c.anchor_sequence.desc())
        .limit(1)
    ).one_or_none()
    expected_receipt_tip = (
        None
        if terminal_receipt is None
        else (
            terminal_receipt.anchor_receipt_id,
            terminal_receipt.semantic_sha256,
            final_receipt_count,
        )
    )
    if (None if terminal_receipt_row is None else tuple(terminal_receipt_row)) != (
        expected_receipt_tip
    ):
        raise TrustedTimeHeadAnchorPersistenceConflict(
            "trusted-time anchor incremental receipt tip changed"
        )

    return _AnchorSuffix(
        intent_count=final_intent_count,
        receipt_count=final_receipt_count,
        terminal_intent=terminal_intent,
        terminal_receipt=terminal_receipt,
        terminal_intent_local_transition_ordinal=previous_ordinal,
        pending=pending,
        newly_confirmed_records=tuple(receipt.intent.record for receipt in new_receipts),
        newly_confirmed_ordinals=tuple(new_confirmed_ordinals),
    )


class SqlTrustedTimeHeadAnchorRepository:
    """Prepare signed anchor objects and confirm exact remote readback."""

    __slots__ = (
        "_anchor_authority_sha256",
        "_engine",
        "_lock",
        "_owner_process_id",
        "_repository_token",
        "_signing_key_id",
        "_signing_public_key_sha256",
        "_snapshots",
        "_verifier",
    )

    def __init__(
        self,
        engine: Engine,
        *,
        verifier: TrustedTimeHeadAnchorEd25519Verifier,
        anchor_authority_sha256: str,
        signing_key_id: str,
        signing_public_key_sha256: str,
    ) -> None:
        if not isinstance(engine, Engine):
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor SQL repository requires an Engine"
            )
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor SQL repository uses an unsupported dialect"
            )
        try:
            verify = getattr(verifier, "verify_ed25519", None)
        except Exception:
            verify = None
        if not callable(verify):
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor Ed25519 verifier is unavailable"
            )
        self._engine = engine
        self._verifier = verifier
        self._owner_process_id = os.getpid()
        self._repository_token = object()
        self._lock = threading.RLock()
        self._snapshots: dict[int, _AnchorSnapshotState] = {}
        self._anchor_authority_sha256 = _require_sha256(
            anchor_authority_sha256,
            "authority SHA-256",
        )
        self._signing_key_id = _require_text(signing_key_id, "signing-key ID")
        self._signing_public_key_sha256 = _require_sha256(
            signing_public_key_sha256,
            "signing public-key SHA-256",
        )

    def _require_owner_process(self) -> int:
        process_id = os.getpid()
        if process_id != self._owner_process_id:
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "trusted-time anchor repository cannot cross process identity"
            )
        return process_id

    def _require_snapshot(
        self,
        snapshot: TrustedTimeHeadAnchorPersistenceSnapshot,
    ) -> _AnchorSnapshotState:
        if type(snapshot) is not TrustedTimeHeadAnchorPersistenceSnapshot:
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "trusted-time anchor snapshot must be repository-issued"
            )
        process_id = self._require_owner_process()
        state = self._snapshots.get(id(snapshot))
        if (
            state is None
            or state.snapshot is not snapshot
            or state.process_id != process_id
            or state.repository_token is not self._repository_token
            or snapshot.authenticated_journal_tip is not state.journal_tip
            or snapshot.local_transition_count != state.journal_tip.local_transition_count
            or snapshot.confirmed_anchor_count != state.receipt_count
            or snapshot.current_host_head_sha256 != state.local_boundary.head.semantic_sha256
            or snapshot.pending_intent != state.pending
            or snapshot.pending_intent_local_transition_ordinal
            != (None if state.pending is None else state.terminal_intent_local_transition_ordinal)
        ):
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "trusted-time anchor snapshot is stale or foreign"
            )
        state.journal_tip.__post_init__()
        return state

    def _replace_snapshot(
        self,
        *,
        previous: TrustedTimeHeadAnchorPersistenceSnapshot | None,
        local_transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
        confirmed_anchor_records: tuple[TrustedTimeHeadAnchorRecord, ...],
        complete_replay: bool,
        local_boundary: _VerifiedHost,
        intent_count: int,
        receipt_count: int,
        terminal_intent: PersistedTrustedTimeHeadAnchorIntent | None,
        terminal_receipt: PersistedTrustedTimeHeadAnchorReceipt | None,
        terminal_intent_local_transition_ordinal: int | None,
        pending: PersistedTrustedTimeHeadAnchorIntent | None,
        journal_tip: AuthenticatedTrustedTimeHeadJournalTip,
    ) -> TrustedTimeHeadAnchorPersistenceSnapshot:
        snapshot = _new_head_anchor_persistence_snapshot(
            local_transitions=local_transitions,
            confirmed_anchor_records=confirmed_anchor_records,
            pending_intent=pending,
            pending_intent_local_transition_ordinal=(
                None if pending is None else terminal_intent_local_transition_ordinal
            ),
            authenticated_journal_tip=journal_tip,
            complete_replay=complete_replay,
        )
        compact_boundary = _VerifiedHost(
            epoch=local_boundary.epoch,
            head=local_boundary.head,
            prior=local_boundary.prior,
            terminal_evaluation=local_boundary.terminal_evaluation,
            head_transitions=(),
        )
        self._snapshots[id(snapshot)] = _AnchorSnapshotState(
            snapshot=snapshot,
            process_id=self._owner_process_id,
            repository_token=self._repository_token,
            local_boundary=compact_boundary,
            intent_count=intent_count,
            receipt_count=receipt_count,
            terminal_intent=terminal_intent,
            terminal_receipt=terminal_receipt,
            terminal_intent_local_transition_ordinal=(terminal_intent_local_transition_ordinal),
            pending=pending,
            journal_tip=journal_tip,
        )
        if previous is not None:
            self._snapshots.pop(id(previous), None)
        return snapshot

    def _history(
        self,
        connection: Connection,
        transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    ) -> _AnchorHistory:
        _verify_local_journal(connection, transitions)
        return _load_anchor_history(
            connection,
            transitions,
            verifier=self._verifier,
            anchor_authority_sha256=self._anchor_authority_sha256,
            signing_key_id=self._signing_key_id,
            signing_public_key_sha256=self._signing_public_key_sha256,
        )

    def _read_history(
        self,
        transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    ) -> _AnchorHistory:
        with _repeatable_read_transaction(self._engine) as connection:
            return self._history(connection, transitions)

    def load_head_anchor_startup_snapshot(
        self,
        *,
        host_id: str,
        deployment_identity_sha256: str,
        runtime_database_identity_sha256: str,
        anchor_project_identity_sha256: str,
        anchor_project_ref: str,
        bucket_name: str,
        principal_id: str,
    ) -> TrustedTimeHeadAnchorPersistenceSnapshot:
        """Stream local and durable anchor history in one bounded stable replay."""

        try:
            with self._lock:
                self._require_owner_process()
                with _repeatable_read_transaction(self._engine) as connection:
                    anchor_replay = _BoundedAnchorReplay(
                        connection,
                        host_id=host_id,
                        verifier=self._verifier,
                        anchor_authority_sha256=self._anchor_authority_sha256,
                        signing_key_id=self._signing_key_id,
                        signing_public_key_sha256=(self._signing_public_key_sha256),
                    )
                    local_replay = _consume_authenticated_head_full_replay(
                        connection,
                        host_id=host_id,
                        deployment_identity_sha256=deployment_identity_sha256,
                        runtime_database_identity_sha256=(runtime_database_identity_sha256),
                        anchor_project_identity_sha256=(anchor_project_identity_sha256),
                        anchor_project_ref=anchor_project_ref,
                        bucket_name=bucket_name,
                        principal_id=principal_id,
                        page_consumer=anchor_replay.consume_local_page,
                        page_size=_ANCHOR_FULL_REPLAY_PAGE_SIZE,
                    )
                    if local_replay is None:
                        raise TrustedTimeHeadAnchorPersistenceConflict(
                            "trusted-time anchor startup replay requires local history"
                        )
                    history = anchor_replay.finish()
                journal_tip = _issue_authenticated_trusted_time_head_journal_tip(
                    current_transition=local_replay.current_transition,
                    local_transition_count=local_replay.transition_count,
                    first_local_host_head_sha256=(
                        local_replay.first_transition.current_host_head_sha256
                    ),
                    confirmed_anchor_count=history.receipt_count,
                    confirmed_anchor_tip=(
                        None
                        if history.terminal_receipt is None
                        else history.terminal_receipt.intent.record
                    ),
                    first_anchored_local_transition_ordinal=(
                        history.first_confirmed_local_transition_ordinal
                    ),
                    confirmed_anchor_local_transition_ordinal=(
                        history.terminal_confirmed_local_transition_ordinal
                    ),
                )
                return self._replace_snapshot(
                    previous=None,
                    local_transitions=(),
                    confirmed_anchor_records=(),
                    complete_replay=True,
                    local_boundary=local_replay.verified,
                    intent_count=history.intent_count,
                    receipt_count=history.receipt_count,
                    terminal_intent=history.terminal_intent,
                    terminal_receipt=history.terminal_receipt,
                    terminal_intent_local_transition_ordinal=(
                        history.terminal_intent_local_transition_ordinal
                    ),
                    pending=history.pending,
                    journal_tip=journal_tip,
                )
        except TrustedTimeHeadAnchorPersistenceError:
            raise
        except (SQLAlchemyError, TrustedTimePersistenceError):
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor startup snapshot replay failed"
            ) from None

    def compact_head_anchor_snapshot(
        self,
        snapshot: TrustedTimeHeadAnchorPersistenceSnapshot,
    ) -> TrustedTimeHeadAnchorPersistenceSnapshot:
        """Release consumed replay/delta tuples while preserving sealed tips."""

        with self._lock:
            state = self._require_snapshot(snapshot)
            if (
                not snapshot.local_transitions
                and not snapshot.confirmed_anchor_records
                and not snapshot.complete_replay
            ):
                return snapshot
            return self._replace_snapshot(
                previous=snapshot,
                local_transitions=(),
                confirmed_anchor_records=(),
                complete_replay=False,
                local_boundary=state.local_boundary,
                intent_count=state.intent_count,
                receipt_count=state.receipt_count,
                terminal_intent=state.terminal_intent,
                terminal_receipt=state.terminal_receipt,
                terminal_intent_local_transition_ordinal=(
                    state.terminal_intent_local_transition_ordinal
                ),
                pending=state.pending,
                journal_tip=state.journal_tip,
            )

    def discard_head_anchor_snapshot(
        self,
        snapshot: TrustedTimeHeadAnchorPersistenceSnapshot,
    ) -> None:
        """Release one no-longer-used on-demand/startup cursor explicitly."""

        with self._lock:
            self._require_snapshot(snapshot)
            self._snapshots.pop(id(snapshot), None)

    def refresh_head_anchor_snapshot(
        self,
        snapshot: TrustedTimeHeadAnchorPersistenceSnapshot,
    ) -> TrustedTimeHeadAnchorPersistenceSnapshot:
        """Authenticate only local and anchor rows appended after this cursor."""

        try:
            with self._lock:
                state = self._require_snapshot(snapshot)
                template = state.journal_tip.current_transition
                with _repeatable_read_transaction(self._engine) as connection:
                    local_boundary = _verified_host_suffix_from_boundary(
                        connection,
                        host_id=template.host_id,
                        epoch=state.local_boundary.epoch,
                        head_boundary=state.local_boundary.head,
                        prior=state.local_boundary.prior,
                        terminal_evaluation=state.local_boundary.terminal_evaluation,
                    )
                    if local_boundary.head_transitions:
                        local_suffix = _authenticated_head_transitions(
                            local_boundary,
                            deployment_identity_sha256=(template.deployment_identity_sha256),
                            runtime_database_identity_sha256=(
                                template.runtime_database_identity_sha256
                            ),
                            anchor_project_identity_sha256=(
                                template.anchor_project_identity_sha256
                            ),
                            anchor_project_ref=template.anchor_project_ref,
                            bucket_name=template.bucket_name,
                            principal_id=template.principal_id,
                            initial_previous_host_head_sha256=(
                                state.local_boundary.head.semantic_sha256
                            ),
                        )
                    else:
                        local_suffix = ()
                    anchor_suffix = _load_anchor_suffix(
                        connection,
                        state,
                        local_suffix,
                        verifier=self._verifier,
                        anchor_authority_sha256=self._anchor_authority_sha256,
                        signing_key_id=self._signing_key_id,
                        signing_public_key_sha256=self._signing_public_key_sha256,
                    )
                if (
                    not local_suffix
                    and not anchor_suffix.newly_confirmed_records
                    and anchor_suffix.intent_count == state.intent_count
                    and anchor_suffix.receipt_count == state.receipt_count
                    and anchor_suffix.pending == state.pending
                ):
                    return snapshot
                journal_tip = _advance_authenticated_trusted_time_head_journal_tip(
                    state.journal_tip,
                    appended_local_transitions=local_suffix,
                    newly_confirmed_anchor_records=(anchor_suffix.newly_confirmed_records),
                    newly_confirmed_anchor_local_transition_ordinals=(
                        anchor_suffix.newly_confirmed_ordinals
                    ),
                )
                return self._replace_snapshot(
                    previous=snapshot,
                    local_transitions=local_suffix,
                    confirmed_anchor_records=(anchor_suffix.newly_confirmed_records),
                    complete_replay=False,
                    local_boundary=local_boundary,
                    intent_count=anchor_suffix.intent_count,
                    receipt_count=anchor_suffix.receipt_count,
                    terminal_intent=anchor_suffix.terminal_intent,
                    terminal_receipt=anchor_suffix.terminal_receipt,
                    terminal_intent_local_transition_ordinal=(
                        anchor_suffix.terminal_intent_local_transition_ordinal
                    ),
                    pending=anchor_suffix.pending,
                    journal_tip=journal_tip,
                )
        except TrustedTimeHeadAnchorPersistenceError:
            raise
        except (SQLAlchemyError, TrustedTimePersistenceError):
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor incremental snapshot refresh failed"
            ) from None

    def commit_prepared_intent(
        self,
        snapshot: TrustedTimeHeadAnchorPersistenceSnapshot,
        *,
        prepared: PreparedTrustedTimeHeadAnchorReconciliation,
        created_at_utc: datetime,
        allow_enrollment: bool = False,
    ) -> tuple[
        TrustedTimeHeadAnchorPersistenceSnapshot,
        CommittedTrustedTimeHeadAnchorIntentEvidence,
    ]:
        """Commit a prepared candidate against compact tips before provider I/O."""

        created_at = _require_utc(created_at_utc, "intent creation instant")
        if type(allow_enrollment) is not bool:
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor enrollment permission is invalid"
            )
        if type(prepared) is not PreparedTrustedTimeHeadAnchorReconciliation:
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor prepared reconciliation is invalid"
            )
        try:
            prepared.__post_init__()
        except TrustedTimeHeadAnchorError:
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor prepared reconciliation is invalid"
            ) from None
        candidate = prepared.candidate_record
        if candidate is None:
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "trusted-time anchor reconciliation has no intent to commit"
            )

        try:
            with self._lock:
                state = self._require_snapshot(snapshot)
                tip = state.journal_tip
                if (
                    prepared.local_transition_count != tip.local_transition_count
                    or prepared.current_host_head_sha256 != tip.current_local_host_head_sha256
                    or prepared.confirmed_anchor_count != state.receipt_count
                ):
                    raise TrustedTimeHeadAnchorPersistenceConflict(
                        "trusted-time anchor preparation conflicts with compact tips"
                    )
                if state.pending is not None:
                    if state.pending.record != candidate:
                        raise TrustedTimeHeadAnchorPersistenceConflict(
                            "trusted-time anchor pending intent must be recovered first"
                        )
                    with _write_transaction(self._engine) as connection:
                        _lock_and_assert_compact_snapshot(
                            connection,
                            state,
                            verifier=self._verifier,
                        )
                    return snapshot, _committed_evidence(state.pending)
                if (state.intent_count == 0) != allow_enrollment:
                    raise TrustedTimeHeadAnchorPersistenceConflict(
                        "trusted-time anchor enrollment permission conflicts with compact history"
                    )
                if prepared.confirmed_anchor_records:
                    terminal = prepared.confirmed_anchor_records[-1]
                    if (
                        state.terminal_receipt is None
                        or terminal != state.terminal_receipt.intent.record
                    ):
                        raise TrustedTimeHeadAnchorPersistenceConflict(
                            "trusted-time anchor prepared confirmed tip conflicts with SQL"
                        )
                elif state.receipt_count != 0:
                    raise TrustedTimeHeadAnchorPersistenceConflict(
                        "trusted-time anchor preparation omitted its confirmed tip"
                    )
                candidate.__post_init__()
                _verify_signature(candidate, self._verifier)
                previous = state.terminal_intent
                if (
                    candidate.signing_key_id != self._signing_key_id
                    or candidate.signing_public_key_sha256 != self._signing_public_key_sha256
                    or candidate.anchor_authority_sha256 != self._anchor_authority_sha256
                    or candidate.checkpoint_interval_seconds
                    != TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
                    or not _record_matches_transition(
                        candidate,
                        tip.current_transition,
                    )
                    or candidate.anchor_sequence != state.intent_count + 1
                    or candidate.previous_anchor_sha256
                    != (None if previous is None else previous.signed_envelope_sha256)
                    or candidate.previous_anchored_host_head_sha256
                    != (None if previous is None else previous.record.current_host_head_sha256)
                ):
                    raise TrustedTimeHeadAnchorPersistenceConflict(
                        "trusted-time anchor candidate conflicts with compact history"
                    )
                prefix = trusted_time_head_anchor_object_prefix(
                    deployment_identity_sha256=(candidate.deployment_identity_sha256),
                    host_id=candidate.host_id,
                )
                intent = _new_intent(
                    anchor_intent_id=str(uuid.uuid4()),
                    checkpoint_reason=candidate.checkpoint_reason,
                    checkpoint_interval_seconds=(candidate.checkpoint_interval_seconds),
                    anchor_authority_sha256=self._anchor_authority_sha256,
                    record=candidate,
                    object_name=trusted_time_head_anchor_object_name(
                        prefix=prefix,
                        anchor_sequence=candidate.anchor_sequence,
                        signed_envelope_sha256=candidate.byte_sha256,
                    ),
                    signed_envelope_bytes=candidate.canonical_bytes,
                    created_at_utc=created_at,
                )
                with _write_transaction(self._engine) as connection:
                    _lock_and_assert_compact_snapshot(
                        connection,
                        state,
                        verifier=self._verifier,
                    )
                    connection.execute(
                        sa.insert(phase6_trusted_time_head_anchor_intents).values(
                            **_intent_values(intent)
                        )
                    )
                    row = (
                        connection.execute(
                            sa.select(phase6_trusted_time_head_anchor_intents).where(
                                phase6_trusted_time_head_anchor_intents.c.anchor_intent_id
                                == intent.anchor_intent_id
                            )
                        )
                        .mappings()
                        .one()
                    )
                    if _intent_from_row(row, verifier=self._verifier) != intent:
                        raise TrustedTimeHeadAnchorPersistenceConflict(
                            "trusted-time anchor intent exact readback conflicts"
                        )
                advanced = self._replace_snapshot(
                    previous=snapshot,
                    local_transitions=(),
                    confirmed_anchor_records=(),
                    complete_replay=False,
                    local_boundary=state.local_boundary,
                    intent_count=state.intent_count + 1,
                    receipt_count=state.receipt_count,
                    terminal_intent=intent,
                    terminal_receipt=state.terminal_receipt,
                    terminal_intent_local_transition_ordinal=(tip.local_transition_count),
                    pending=intent,
                    journal_tip=tip,
                )
                return advanced, _committed_evidence(intent)
        except TrustedTimeHeadAnchorPersistenceError:
            raise
        except IntegrityError:
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "trusted-time anchor intent conflicts"
            ) from None
        except (SQLAlchemyError, TrustedTimePersistenceError):
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor compact intent persistence failed"
            ) from None

    def confirm_remote_readback_from_snapshot(
        self,
        snapshot: TrustedTimeHeadAnchorPersistenceSnapshot,
        *,
        intent: PersistedTrustedTimeHeadAnchorIntent,
        provider_readback: TrustedTimeHeadAnchorProviderReadbackEvidence,
        observed_at_utc: datetime,
    ) -> tuple[
        TrustedTimeHeadAnchorPersistenceSnapshot,
        PersistedTrustedTimeHeadAnchorReceipt,
    ]:
        """Commit one application-sealed provider-GET proof against a pending snapshot."""

        if type(intent) is not PersistedTrustedTimeHeadAnchorIntent:
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor confirmation intent is invalid"
            )
        try:
            intent.__post_init__()
        except TrustedTimeHeadAnchorPersistenceError:
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor confirmation intent is invalid"
            ) from None
        evidence = _require_provider_readback_evidence(intent, provider_readback)
        readback_sha256 = evidence.candidate_bytes_sha256
        observed_at = _require_utc(
            observed_at_utc,
            "receipt observation instant",
        )
        claim_token = _claim_provider_readback_evidence(evidence)
        evidence_consumed = False

        try:
            with self._lock:
                refreshed = self.refresh_head_anchor_snapshot(snapshot)
                state = self._require_snapshot(refreshed)
                if (
                    state.pending is None
                    and state.terminal_receipt is not None
                    and state.terminal_receipt.intent == intent
                ):
                    _consume_provider_readback_evidence(evidence, claim_token)
                    evidence_consumed = True
                    return refreshed, state.terminal_receipt
                if state.pending != intent:
                    raise TrustedTimeHeadAnchorPersistenceConflict(
                        "trusted-time anchor confirmation is not for the compact pending intent"
                    )
                ordinal = state.terminal_intent_local_transition_ordinal
                if ordinal is None:
                    raise TrustedTimeHeadAnchorPersistenceConflict(
                        "trusted-time anchor pending intent lacks a local ordinal"
                    )
                receipt = _new_receipt(
                    anchor_receipt_id=str(uuid.uuid4()),
                    intent=intent,
                    readback_bytes_sha256=readback_sha256,
                    observed_at_utc=observed_at,
                )
                try:
                    with _write_transaction(self._engine) as connection:
                        _lock_and_assert_compact_snapshot(
                            connection,
                            state,
                            verifier=self._verifier,
                        )
                        connection.execute(
                            sa.insert(phase6_trusted_time_head_anchor_receipts).values(
                                **_receipt_values(receipt)
                            )
                        )
                        row = (
                            connection.execute(
                                sa.select(phase6_trusted_time_head_anchor_receipts).where(
                                    phase6_trusted_time_head_anchor_receipts.c.anchor_receipt_id
                                    == receipt.anchor_receipt_id
                                )
                            )
                            .mappings()
                            .one()
                        )
                        if _receipt_from_row(row, intent=intent) != receipt:
                            raise TrustedTimeHeadAnchorPersistenceConflict(
                                "trusted-time anchor receipt exact readback conflicts"
                            )
                except TrustedTimeHeadAnchorSnapshotAdvanced as exc:
                    raise TrustedTimeHeadAnchorSnapshotAdvanced(
                        str(exc),
                        refreshed_snapshot=refreshed,
                    ) from None
                journal_tip = _advance_authenticated_trusted_time_head_journal_tip(
                    state.journal_tip,
                    appended_local_transitions=(),
                    newly_confirmed_anchor_records=(intent.record,),
                    newly_confirmed_anchor_local_transition_ordinals=(ordinal,),
                )
                confirmed = self._replace_snapshot(
                    previous=refreshed,
                    local_transitions=(),
                    confirmed_anchor_records=(intent.record,),
                    complete_replay=False,
                    local_boundary=state.local_boundary,
                    intent_count=state.intent_count,
                    receipt_count=state.receipt_count + 1,
                    terminal_intent=intent,
                    terminal_receipt=receipt,
                    terminal_intent_local_transition_ordinal=ordinal,
                    pending=None,
                    journal_tip=journal_tip,
                )
                _consume_provider_readback_evidence(evidence, claim_token)
                evidence_consumed = True
                return confirmed, receipt
        except TrustedTimeHeadAnchorPersistenceError:
            raise
        except IntegrityError:
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "trusted-time anchor receipt conflicts"
            ) from None
        except (SQLAlchemyError, TrustedTimePersistenceError):
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor compact receipt persistence failed"
            ) from None
        finally:
            if not evidence_consumed:
                _release_provider_readback_evidence(evidence, claim_token)

    def read_pending(
        self,
        local_transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    ) -> PersistedTrustedTimeHeadAnchorIntent | None:
        """Return the exact unresolved object, including after local head advance."""

        transitions = _validate_complete_local_chain(local_transitions)
        try:
            return self._read_history(transitions).pending
        except TrustedTimeHeadAnchorPersistenceError:
            raise
        except (SQLAlchemyError, TrustedTimePersistenceError):
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor pending-intent read failed"
            ) from None

    def read_pending_with_committed_evidence(
        self,
        local_transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    ) -> (
        tuple[
            PersistedTrustedTimeHeadAnchorIntent,
            CommittedTrustedTimeHeadAnchorIntentEvidence,
        ]
        | None
    ):
        """Return exact restart evidence for the sole unresolved SQL intent."""

        pending = self.read_pending(local_transitions)
        if pending is None:
            return None
        return pending, _committed_evidence(pending)

    def issue_committed_intent_evidence(
        self,
        local_transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
        *,
        intent: PersistedTrustedTimeHeadAnchorIntent,
    ) -> CommittedTrustedTimeHeadAnchorIntentEvidence:
        """Issue sealed application evidence only after exact SQL replay/readback."""

        transitions = _validate_complete_local_chain(local_transitions)
        if type(intent) is not PersistedTrustedTimeHeadAnchorIntent:
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor committed-evidence intent is invalid"
            )
        try:
            intent.__post_init__()
            history = self._read_history(transitions)
        except TrustedTimeHeadAnchorPersistenceError:
            raise
        except (SQLAlchemyError, TrustedTimePersistenceError):
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor committed-evidence read failed"
            ) from None
        persisted = next(
            (
                candidate
                for candidate in history.intents
                if candidate.anchor_intent_id == intent.anchor_intent_id
            ),
            None,
        )
        if persisted is None or persisted != intent:
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "trusted-time anchor intent lacks exact durable commit evidence"
            )
        return _committed_evidence(persisted)

    def commit_trusted_time_head_anchor_intent(
        self,
        *,
        prepared: PreparedTrustedTimeHeadAnchorReconciliation,
    ) -> CommittedTrustedTimeHeadAnchorIntentEvidence:
        """Implement the application intent journal port before remote upload."""

        if type(prepared) is not PreparedTrustedTimeHeadAnchorReconciliation:
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor prepared reconciliation is invalid"
            )
        try:
            prepared.__post_init__()
        except TrustedTimeHeadAnchorError:
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor prepared reconciliation is invalid"
            ) from None
        candidate = prepared.candidate_record
        if candidate is None:
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "trusted-time anchor reconciliation has no intent to commit"
            )
        template = _transition_template_from_record(candidate)
        try:
            with _repeatable_read_transaction(self._engine) as connection:
                _verify_global_integrity(connection)
                transitions = _expected_journal_transitions(connection, template)
        except (SQLAlchemyError, TrustedTimePersistenceError):
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor intent journal replay failed"
            ) from None
        if not transitions:
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "trusted-time anchor intent journal is absent"
            )
        persisted = self.prepare_or_read_pending(
            transitions,
            record=candidate,
            checkpoint_reason=candidate.checkpoint_reason,
            checkpoint_interval_seconds=candidate.checkpoint_interval_seconds,
            created_at=datetime.now(UTC),
            allow_enrollment=(candidate.anchor_sequence == 1),
        )
        if persisted.record != candidate:
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "trusted-time anchor pending intent must be recovered before a successor"
            )
        return _committed_evidence(persisted)

    def read_confirmed_anchor_records(
        self,
        local_transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    ) -> tuple[TrustedTimeHeadAnchorRecord, ...]:
        """Return the byte-exact confirmed prefix after complete integrity replay."""

        transitions = _validate_complete_local_chain(local_transitions)
        try:
            history = self._read_history(transitions)
            return tuple(receipt.intent.record for receipt in history.receipts)
        except TrustedTimeHeadAnchorPersistenceError:
            raise
        except (SQLAlchemyError, TrustedTimePersistenceError):
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor confirmed-record read failed"
            ) from None

    def prepare_or_read_pending(
        self,
        local_transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
        *,
        record: TrustedTimeHeadAnchorRecord,
        checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason,
        created_at: datetime,
        checkpoint_interval_seconds: int = (TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS),
        allow_enrollment: bool = False,
    ) -> PersistedTrustedTimeHeadAnchorIntent:
        """Commit one intent, or return the existing unresolved intent unchanged.

        Enrollment defaults closed.  The one-shot permission can create only
        sequence one while durable local anchor history is completely empty;
        recovering that already-committed pending intent does not consume the
        permission again.
        """

        transitions = _validate_complete_local_chain(local_transitions)
        if type(checkpoint_reason) is not TrustedTimeHeadAnchorCheckpointReason:
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor checkpoint reason is invalid"
            )
        if (
            type(checkpoint_interval_seconds) is not int
            or checkpoint_interval_seconds != TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
        ):
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor checkpoint interval is invalid"
            )
        if type(allow_enrollment) is not bool:
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor enrollment permission is invalid"
            )
        created_at_utc = _require_utc(created_at, "intent creation instant")
        try:
            history = self._read_history(transitions)
            if history.pending is not None:
                return history.pending
            if (not history.intents) != allow_enrollment:
                raise TrustedTimeHeadAnchorPersistenceConflict(
                    "trusted-time anchor enrollment permission conflicts with durable history"
                )
            if type(record) is not TrustedTimeHeadAnchorRecord:
                raise TrustedTimeHeadAnchorPersistenceError(
                    "trusted-time anchor proposed record is invalid"
                )
            try:
                record.__post_init__()
                if (
                    TrustedTimeHeadAnchorRecord.from_canonical_bytes(record.canonical_bytes)
                    != record
                ):
                    raise TrustedTimeHeadAnchorError(
                        "trusted-time anchor record round-trip conflicts"
                    )
            except TrustedTimeHeadAnchorError:
                raise TrustedTimeHeadAnchorPersistenceError(
                    "trusted-time anchor proposed record is invalid"
                ) from None
            _verify_signature(record, self._verifier)
            if (
                record.signing_key_id != self._signing_key_id
                or record.signing_public_key_sha256 != self._signing_public_key_sha256
                or record.checkpoint_reason is not checkpoint_reason
                or record.checkpoint_interval_seconds != checkpoint_interval_seconds
                or record.anchor_authority_sha256 != self._anchor_authority_sha256
                or not _record_matches_transition(record, transitions[-1])
            ):
                raise TrustedTimeHeadAnchorPersistenceConflict(
                    "trusted-time anchor proposed record does not bind the current local head"
                )
            previous = None if not history.intents else history.intents[-1]
            expected_sequence = len(history.intents) + 1
            if (
                record.anchor_sequence != expected_sequence
                or record.previous_anchor_sha256
                != (None if previous is None else previous.signed_envelope_sha256)
                or record.previous_anchored_host_head_sha256
                != (None if previous is None else previous.record.current_host_head_sha256)
            ):
                raise TrustedTimeHeadAnchorPersistenceConflict(
                    "trusted-time anchor proposed predecessor chain conflicts"
                )
            prefix = trusted_time_head_anchor_object_prefix(
                deployment_identity_sha256=record.deployment_identity_sha256,
                host_id=record.host_id,
            )
            object_name = trusted_time_head_anchor_object_name(
                prefix=prefix,
                anchor_sequence=record.anchor_sequence,
                signed_envelope_sha256=record.byte_sha256,
            )
            intent = _new_intent(
                anchor_intent_id=str(uuid.uuid4()),
                checkpoint_reason=checkpoint_reason,
                checkpoint_interval_seconds=checkpoint_interval_seconds,
                anchor_authority_sha256=self._anchor_authority_sha256,
                record=record,
                object_name=object_name,
                signed_envelope_bytes=record.canonical_bytes,
                created_at_utc=created_at_utc,
            )
            with _write_transaction(self._engine) as connection:
                _lock_and_assert_snapshot_unchanged(
                    connection,
                    transitions,
                    history,
                )
                connection.execute(
                    sa.insert(phase6_trusted_time_head_anchor_intents).values(
                        **_intent_values(intent)
                    )
                )
                row = (
                    connection.execute(
                        sa.select(phase6_trusted_time_head_anchor_intents).where(
                            phase6_trusted_time_head_anchor_intents.c.anchor_intent_id
                            == intent.anchor_intent_id
                        )
                    )
                    .mappings()
                    .one()
                )
                persisted = _intent_from_row(row, verifier=self._verifier)
                if persisted != intent:
                    raise TrustedTimeHeadAnchorPersistenceConflict(
                        "trusted-time anchor intent exact readback conflicts"
                    )
                return intent
        except TrustedTimeHeadAnchorPersistenceError:
            raise
        except IntegrityError:
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "trusted-time anchor intent conflicts"
            ) from None
        except (SQLAlchemyError, TrustedTimePersistenceError):
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor intent persistence failed"
            ) from None

    def confirm_remote_readback(
        self,
        local_transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
        *,
        intent: PersistedTrustedTimeHeadAnchorIntent,
        provider_readback: TrustedTimeHeadAnchorProviderReadbackEvidence,
        observed_at: datetime,
    ) -> PersistedTrustedTimeHeadAnchorReceipt:
        """Confirm application-sealed provider GET evidence after the readback."""

        transitions = _validate_complete_local_chain(local_transitions)
        if type(intent) is not PersistedTrustedTimeHeadAnchorIntent:
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor confirmation intent is invalid"
            )
        try:
            intent.__post_init__()
        except TrustedTimeHeadAnchorPersistenceError:
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor confirmation intent is invalid"
            ) from None
        evidence = _require_provider_readback_evidence(intent, provider_readback)
        readback_sha256 = evidence.candidate_bytes_sha256
        observed_at_utc = _require_utc(observed_at, "receipt observation instant")
        claim_token = _claim_provider_readback_evidence(evidence)
        evidence_consumed = False
        try:
            history = self._read_history(transitions)
            persisted_by_id = {item.anchor_intent_id: item for item in history.intents}
            persisted = persisted_by_id.get(intent.anchor_intent_id)
            if persisted is None or persisted != intent:
                raise TrustedTimeHeadAnchorPersistenceConflict(
                    "trusted-time anchor confirmation intent conflicts with SQL"
                )
            existing_by_intent = {
                receipt.intent.anchor_intent_id: receipt for receipt in history.receipts
            }
            existing = existing_by_intent.get(intent.anchor_intent_id)
            if existing is not None:
                _consume_provider_readback_evidence(evidence, claim_token)
                evidence_consumed = True
                return existing
            if history.pending != intent:
                raise TrustedTimeHeadAnchorPersistenceConflict(
                    "trusted-time anchor confirmation is not for the sole pending intent"
                )
            receipt = _new_receipt(
                anchor_receipt_id=str(uuid.uuid4()),
                intent=intent,
                readback_bytes_sha256=readback_sha256,
                observed_at_utc=observed_at_utc,
            )
            with _write_transaction(self._engine) as connection:
                _lock_and_assert_snapshot_unchanged(
                    connection,
                    transitions,
                    history,
                )
                connection.execute(
                    sa.insert(phase6_trusted_time_head_anchor_receipts).values(
                        **_receipt_values(receipt)
                    )
                )
                row = (
                    connection.execute(
                        sa.select(phase6_trusted_time_head_anchor_receipts).where(
                            phase6_trusted_time_head_anchor_receipts.c.anchor_receipt_id
                            == receipt.anchor_receipt_id
                        )
                    )
                    .mappings()
                    .one()
                )
                persisted_receipt = _receipt_from_row(row, intent=intent)
                if persisted_receipt != receipt:
                    raise TrustedTimeHeadAnchorPersistenceConflict(
                        "trusted-time anchor receipt exact readback conflicts"
                    )
            _consume_provider_readback_evidence(evidence, claim_token)
            evidence_consumed = True
            return receipt
        except TrustedTimeHeadAnchorPersistenceError:
            raise
        except IntegrityError:
            raise TrustedTimeHeadAnchorPersistenceConflict(
                "trusted-time anchor receipt conflicts"
            ) from None
        except (SQLAlchemyError, TrustedTimePersistenceError):
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor receipt persistence failed"
            ) from None
        finally:
            if not evidence_consumed:
                _release_provider_readback_evidence(evidence, claim_token)

    def verify_integrity(
        self,
        local_transitions: tuple[AuthenticatedTrustedTimeHeadTransition, ...],
    ) -> None:
        """Replay the complete local journal and every local anchor fact."""

        transitions = _validate_complete_local_chain(local_transitions)
        try:
            with _repeatable_read_transaction(self._engine) as connection:
                self._history(connection, transitions)
        except TrustedTimeHeadAnchorPersistenceError:
            raise
        except (SQLAlchemyError, TrustedTimePersistenceError):
            raise TrustedTimeHeadAnchorPersistenceError(
                "trusted-time anchor integrity verification failed"
            ) from None


__all__ = [
    "TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS",
    "TRUSTED_TIME_HEAD_ANCHOR_SQL_CONTRACT_VERSION",
    "PersistedTrustedTimeHeadAnchorIntent",
    "PersistedTrustedTimeHeadAnchorReceipt",
    "SqlTrustedTimeHeadAnchorRepository",
    "TrustedTimeHeadAnchorCheckpointReason",
    "TrustedTimeHeadAnchorPersistenceConflict",
    "TrustedTimeHeadAnchorPersistenceError",
    "TrustedTimeHeadAnchorPersistenceSnapshot",
    "TrustedTimeHeadAnchorSnapshotAdvanced",
]
