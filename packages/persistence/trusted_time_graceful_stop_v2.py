"""Injected, no-real-root lifecycle-v2 repository for ADR 0121 milestone-one core.

The repository owns ordering and namespace validation but has no filesystem
implementation.  Tests supply the in-memory artifact store.  A native owned-
file implementation is deliberately deferred to ADR-0121 milestone two.
"""

from __future__ import annotations

import json
import os
import threading
from enum import StrEnum
from typing import Protocol, cast

from packages.domain.trusted_time_graceful_stop_v2 import (
    LIFECYCLE_ROOT_FILE_NAME,
    LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME,
    LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION,
    LIFECYCLE_V2_ROOT_CONTRACT_VERSION,
    NORMAL_STAGE_BY_ORDINAL,
    LifecycleV2CleanStopRequestBasis,
    LifecycleV2Outcome,
    LifecycleV2OutcomeCommit,
    LifecycleV2ProgressRecord,
    LifecycleV2Root,
    LifecycleV2Stage,
    LifecycleV2Transcript,
    LifecycleV2TranscriptEntry,
    TrustedTimeGracefulStopV2Rejected,
    UnverifiedLifecycleV2TransportEnvelope,
    _FakeAuthenticatedLifecycleV2TransportEnvelope,
    _require_fake_authenticated_lifecycle_v2_transport_envelope,
    decode_lifecycle_v2_clean_stop_request_basis,
    decode_lifecycle_v2_outcome,
    decode_lifecycle_v2_outcome_commit,
    decode_lifecycle_v2_progress_record,
    decode_lifecycle_v2_root,
    decode_lifecycle_v2_transcript,
    decode_unverified_lifecycle_v2_transport_envelope,
    lifecycle_v2_progress_file_name,
    lifecycle_v2_wire_file_name,
)

_V1_ROOT_CONTRACT_VERSION = "phase6d-post-enrollment-graceful-stop-attempt-v1"
_ROOT_STAGING_NAME = ".post-enrollment-graceful-stop-v2-root-staging"
_RECORD_STAGING_NAME = ".post-enrollment-graceful-stop-v2-record-staging"
_TRANSCRIPT_STAGING_NAME = ".post-enrollment-graceful-stop-v2-transcript-staging"
_WIRE_RESULT_STAGING_NAME = ".post-enrollment-graceful-stop-v2-wire-result-staging"
_WIRE_ERROR_STAGING_NAME = ".post-enrollment-graceful-stop-v2-wire-error-staging"
_OUTCOME_STAGING_NAME = ".post-enrollment-graceful-stop-v2-outcome-staging"
_COMMIT_STAGING_NAME = ".post-enrollment-graceful-stop-v2-outcome-commit-staging"
_STAGING_NAMES = frozenset(
    {
        _ROOT_STAGING_NAME,
        _RECORD_STAGING_NAME,
        _TRANSCRIPT_STAGING_NAME,
        _WIRE_RESULT_STAGING_NAME,
        _WIRE_ERROR_STAGING_NAME,
        _OUTCOME_STAGING_NAME,
        _COMMIT_STAGING_NAME,
    }
)


class LifecycleV2RepositoryRejected(RuntimeError):
    """The injected repository invocation or durable transition was rejected."""


class LifecycleV2SlotConsumed(LifecycleV2RepositoryRejected):
    """The one v1/v2 lifecycle root is already consumed."""


class LifecycleV2RetentionUnconfirmed(LifecycleV2RepositoryRejected):
    """Storage may have changed and only incident-preserving inspection is safe."""


class LifecycleV2ArtifactAlreadyExists(RuntimeError):
    """The injected no-replace store found an existing name."""


class LifecycleV2ArtifactPublicationUncertain(RuntimeError):
    """An injected publication failed before its durable result was knowable."""


class LifecycleV2RepositoryStatus(StrEnum):
    UNRESERVED = "unreserved"
    ROOT_RESERVED = "root_reserved"
    RECOVERY_REQUIRED = "recovery_required"
    OUTCOME_COMMITTED = "outcome_committed"
    RETENTION_UNCONFIRMED = "retention_unconfirmed"


class LifecycleV2ArtifactStore(Protocol):
    """Milestone-one storage seam; no production implementation exists."""

    def inventory(self) -> tuple[str, ...]: ...

    def read_stable(self, file_name: str) -> bytes: ...

    def create_root_exclusive(self, file_name: str, encoded: bytes) -> None: ...

    def publish_immutable(
        self,
        *,
        staging_name: str,
        final_name: str,
        encoded: bytes,
    ) -> None: ...


def _safe_artifact_directory_path(value: object) -> str:
    if (
        type(value) is not str
        or not value.startswith("/")
        or not value.endswith("/trusted-time")
        or "//" in value
        or "/../" in value
        or "/./" in value
        or "\0" in value
    ):
        raise LifecycleV2RepositoryRejected("artifact directory path is not exact")
    return value


def _contract_version(encoded: bytes) -> object:
    try:
        value = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if type(value) is not dict:
        return None
    return value.get("contract_version")


def _known_v2_name(name: str) -> bool:
    return (
        name in (LIFECYCLE_ROOT_FILE_NAME, LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME)
        or name in _STAGING_NAMES
        or name.startswith("trusted-time-post-enrollment-graceful-stop-v2-record-")
        or name.startswith("trusted-time-post-enrollment-graceful-stop-v2-transcript-")
        or name.startswith("trusted-time-post-enrollment-graceful-stop-v2-wire-result-")
        or name.startswith("trusted-time-post-enrollment-graceful-stop-v2-wire-error-")
        or name.startswith("trusted-time-post-enrollment-graceful-stop-v2-outcome-")
    )


class _LifecycleV2Repository:
    """One process/thread-bound repository over an explicitly injected store."""

    __slots__ = (
        "_artifact_directory_path",
        "_commit",
        "_origin_pid",
        "_origin_thread",
        "_outcome",
        "_poisoned",
        "_records",
        "_root",
        "_store",
        "_wire",
    )

    def __init__(self, store: LifecycleV2ArtifactStore, *, artifact_directory_path: str) -> None:
        self._store = store
        self._artifact_directory_path = _safe_artifact_directory_path(artifact_directory_path)
        self._origin_pid = os.getpid()
        self._origin_thread = threading.current_thread()
        self._poisoned = False
        self._root: LifecycleV2Root | None = None
        self._records: tuple[LifecycleV2ProgressRecord, ...] = ()
        self._wire: UnverifiedLifecycleV2TransportEnvelope | None = None
        self._outcome: LifecycleV2Outcome | None = None
        self._commit: LifecycleV2OutcomeCommit | None = None
        self._load_namespace()

    def _require_owner(self) -> None:
        if (
            self._poisoned
            or os.getpid() != self._origin_pid
            or threading.current_thread() is not self._origin_thread
        ):
            raise LifecycleV2RetentionUnconfirmed("repository owner is invalid or burned")

    def _burn(self) -> None:
        self._poisoned = True

    def _load_namespace(self) -> None:
        try:
            names = self._store.inventory()
            if type(names) is not tuple or any(type(name) is not str for name in names):
                raise ValueError
            if names != tuple(sorted(names)) or len(names) != len(frozenset(names)):
                raise ValueError
            if any(name in _STAGING_NAMES for name in names):
                raise LifecycleV2RetentionUnconfirmed("staging artifact is retention ambiguity")
            unknown = tuple(name for name in names if _known_v2_name(name) is False)
            if unknown:
                raise LifecycleV2RetentionUnconfirmed("unknown lifecycle namespace entry")
            if LIFECYCLE_ROOT_FILE_NAME not in names:
                if names:
                    raise LifecycleV2RetentionUnconfirmed("orphan lifecycle-v2 artifact")
                return
            root_encoded = self._store.read_stable(LIFECYCLE_ROOT_FILE_NAME)
            contract = _contract_version(root_encoded)
            if contract == _V1_ROOT_CONTRACT_VERSION:
                raise LifecycleV2SlotConsumed("the shared root is already v1")
            if contract != LIFECYCLE_V2_ROOT_CONTRACT_VERSION:
                raise LifecycleV2RetentionUnconfirmed("shared root version is unknown or mixed")
            self._root = decode_lifecycle_v2_root(root_encoded)
            record_names = tuple(
                name
                for name in names
                if name.startswith("trusted-time-post-enrollment-graceful-stop-v2-record-")
            )
            records: list[LifecycleV2ProgressRecord] = []
            predecessor = self._root.sha256
            for name in record_names:
                record = decode_lifecycle_v2_progress_record(self._store.read_stable(name))
                if (
                    name != lifecycle_v2_progress_file_name(record)
                    or record.ordinal != len(records) + 1
                    or record.root_sha256 != self._root.sha256
                    or record.graceful_stop_operation_id != self._root.graceful_stop_operation_id
                    or record.predecessor_sha256 != predecessor
                ):
                    raise LifecycleV2RetentionUnconfirmed("progress lineage is mixed or gapped")
                if record.ordinal == 1:
                    self._require_derived_request_intent(record)
                self._require_stage_transition(record, records=tuple(records))
                records.append(record)
                predecessor = record.sha256
            self._records = tuple(records)
            self._load_wire(names)
            self._load_outcome(names)
            self._validate_transcripts(names)
        except (LifecycleV2SlotConsumed, LifecycleV2RetentionUnconfirmed):
            self._burn()
            raise
        except BaseException as error:
            self._burn()
            if not isinstance(error, Exception):
                raise
            raise LifecycleV2RetentionUnconfirmed(
                "lifecycle namespace cannot be authenticated"
            ) from None

    def _load_wire(self, names: tuple[str, ...]) -> None:
        wire_names = tuple(
            name
            for name in names
            if name.startswith("trusted-time-post-enrollment-graceful-stop-v2-wire-")
        )
        if not wire_names:
            if len(self._records) >= 2 and self._records[1].stage in {
                LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED,
                LifecycleV2Stage.CLEAN_STOP_ERROR_RETAINED,
            }:
                raise LifecycleV2RetentionUnconfirmed("ordinal two has no immutable wire artifact")
            return
        if len(wire_names) != 1 or len(self._records) < 2:
            raise LifecycleV2RetentionUnconfirmed("wire artifact is orphaned or conflicting")
        envelope = decode_unverified_lifecycle_v2_transport_envelope(
            self._store.read_stable(wire_names[0])
        )
        if wire_names[0] != lifecycle_v2_wire_file_name(envelope):
            raise LifecycleV2RetentionUnconfirmed("wire artifact name or digest disagrees")
        record = self._records[1]
        evidence = record.evidence.to_dict()
        prefix = (
            "clean_stop_result"
            if envelope.frame_type == "clean_stop_result"
            else "clean_stop_error"
        )
        if (
            record.stage.value != f"{prefix}_retained"
            or evidence[f"{prefix}_sha256"] != envelope.sha256
            or evidence[f"{prefix}_artifact_name"] != wire_names[0]
            or evidence["frame_type"] != envelope.frame_type
        ):
            raise LifecycleV2RetentionUnconfirmed("ordinal-two record and wire bytes disagree")
        raise LifecycleV2RetentionUnconfirmed(
            "partial milestone-one cannot reauthenticate retained wire signatures"
        )

    def _load_outcome(self, names: tuple[str, ...]) -> None:
        outcome_names = tuple(
            name
            for name in names
            if name.startswith("trusted-time-post-enrollment-graceful-stop-v2-outcome-")
        )
        if len(outcome_names) > 1:
            raise LifecycleV2RetentionUnconfirmed("multiple outcome candidates exist")
        if outcome_names:
            outcome = decode_lifecycle_v2_outcome(self._store.read_stable(outcome_names[0]))
            if outcome_names[0] != outcome.file_name:
                raise LifecycleV2RetentionUnconfirmed("outcome name or digest disagrees")
            self._outcome = outcome
        if LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME in names:
            if self._outcome is None:
                raise LifecycleV2RetentionUnconfirmed("commit has no outcome candidate")
            self._commit = decode_lifecycle_v2_outcome_commit(
                self._store.read_stable(LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME),
                outcome=self._outcome,
            )

    def _validate_transcripts(self, names: tuple[str, ...]) -> None:
        transcript_names = tuple(
            name
            for name in names
            if name.startswith("trusted-time-post-enrollment-graceful-stop-v2-transcript-")
        )
        retained_transcripts: dict[str, LifecycleV2Transcript] = {}
        for name in transcript_names:
            transcript = decode_lifecycle_v2_transcript(self._store.read_stable(name))
            if name != transcript.file_name:
                raise LifecycleV2RetentionUnconfirmed("transcript name or digest disagrees")
            expected = self._transcript(last_ordinal=transcript.entries[-1].ordinal)
            if transcript != expected:
                raise LifecycleV2RetentionUnconfirmed("transcript is not an exact stable prefix")
            retained_transcripts[transcript.sha256] = transcript
        for record in self._records:
            if record.stage is LifecycleV2Stage.RECOVERY_CLASSIFICATION_INTENT_RETAINED:
                classified_transcript = self._transcript(last_ordinal=record.ordinal - 1)
                if (
                    record.evidence.to_dict()["classified_transcript_sha256"]
                    != classified_transcript.sha256
                    or retained_transcripts.get(classified_transcript.sha256)
                    != classified_transcript
                ):
                    raise LifecycleV2RetentionUnconfirmed(
                        "recovery intent does not bind its exact predecessor prefix"
                    )
        if self._outcome is not None:
            self._validate_loaded_outcome(retained_transcripts)

    def _validate_loaded_outcome(
        self,
        retained_transcripts: dict[str, LifecycleV2Transcript],
    ) -> None:
        if self._root is None or self._outcome is None:
            raise LifecycleV2RetentionUnconfirmed("terminal artifacts have no lifecycle root")
        if not self._records:
            raise LifecycleV2RetentionUnconfirmed(
                "terminal artifacts cannot classify a root-only namespace"
            )
        full_transcript = self._transcript()
        retained_full_transcript = retained_transcripts.get(full_transcript.sha256)
        if retained_full_transcript != full_transcript:
            raise LifecycleV2RetentionUnconfirmed(
                "outcome does not bind the exact complete retained prefix"
            )
        last_record = self._records[-1]
        outcome_fields = self._outcome.to_dict()
        if (
            outcome_fields["graceful_stop_operation_id"] != self._root.graceful_stop_operation_id
            or outcome_fields["root_sha256"] != self._root.sha256
            or outcome_fields["ordinal"] != len(self._records) + 1
            or outcome_fields["predecessor_sha256"] != last_record.sha256
            or outcome_fields["final_stage"] != last_record.stage.value
            or outcome_fields["transcript_sha256"] != full_transcript.sha256
            or outcome_fields["admission_started_boottime_ns"]
            != self._root.admission_started_boottime_ns
            or outcome_fields["operation_deadline_boottime_ns"]
            != self._root.operation_deadline_boottime_ns
        ):
            raise LifecycleV2RetentionUnconfirmed(
                "outcome does not bind the loaded root and complete retained prefix"
            )
        if self._outcome.status == "recovery_required":
            if (
                last_record.stage is not LifecycleV2Stage.RECOVERY_CLASSIFICATION_INTENT_RETAINED
                or outcome_fields["reason_code"] != last_record.evidence.to_dict()["reason_code"]
            ):
                raise LifecycleV2RetentionUnconfirmed(
                    "recovery outcome has no exact classification intent"
                )
        elif (
            len(self._records) != 22
            or last_record.stage is not LifecycleV2Stage.TERMINAL_CLEANUP_CONFIRMED
        ):
            raise LifecycleV2RetentionUnconfirmed(
                "confirmed success has no complete terminal-cleanup prefix"
            )
        if self._commit is not None:
            commit_fields = self._commit.to_dict()
            if (
                commit_fields["graceful_stop_operation_id"] != self._root.graceful_stop_operation_id
                or commit_fields["root_sha256"] != self._root.sha256
                or commit_fields["outcome_sha256"] != self._outcome.sha256
                or commit_fields["outcome_status"] != self._outcome.status
                or commit_fields["transcript_sha256"] != full_transcript.sha256
                or commit_fields["admission_started_boottime_ns"]
                != self._root.admission_started_boottime_ns
                or commit_fields["operation_deadline_boottime_ns"]
                != self._root.operation_deadline_boottime_ns
            ):
                raise LifecycleV2RetentionUnconfirmed(
                    "commit marker does not bind the loaded terminal lineage"
                )

    def _require_stage_transition(
        self,
        record: LifecycleV2ProgressRecord,
        *,
        records: tuple[LifecycleV2ProgressRecord, ...] | None = None,
    ) -> None:
        exact_records = self._records if records is None else records
        if record.ordinal != len(exact_records) + 1:
            raise LifecycleV2RepositoryRejected("progress ordinal is not next")
        if records is None and (self._outcome is not None or self._commit is not None):
            raise LifecycleV2RepositoryRejected("terminal outcome already retained")
        if record.stage is LifecycleV2Stage.RECOVERY_CLASSIFICATION_INTENT_RETAINED:
            if any(
                item.stage is LifecycleV2Stage.RECOVERY_CLASSIFICATION_INTENT_RETAINED
                for item in exact_records
            ):
                raise LifecycleV2RepositoryRejected(
                    "recovery classification intent is already retained"
                )
            if (
                exact_records
                and exact_records[-1].stage is LifecycleV2Stage.TERMINAL_CLEANUP_CONFIRMED
            ):
                raise LifecycleV2RepositoryRejected(
                    "recovery classification cannot follow a terminal stage"
                )
            return
        if any(
            item.stage
            in {
                LifecycleV2Stage.CLEAN_STOP_ERROR_RETAINED,
                LifecycleV2Stage.RECOVERY_CLASSIFICATION_INTENT_RETAINED,
            }
            for item in exact_records
        ):
            raise LifecycleV2RepositoryRejected("normal continuation after failure is forbidden")
        expected = NORMAL_STAGE_BY_ORDINAL.get(record.ordinal)
        if record.ordinal == 2 and record.stage is LifecycleV2Stage.CLEAN_STOP_ERROR_RETAINED:
            return
        if record.stage is not expected:
            raise LifecycleV2RepositoryRejected("normal lifecycle stage is out of order")

    def _require_record_binding(self, record: LifecycleV2ProgressRecord) -> None:
        if type(record) is not LifecycleV2ProgressRecord or self._root is None:
            raise LifecycleV2RepositoryRejected("lifecycle root is not reserved")
        try:
            verified_record = decode_lifecycle_v2_progress_record(record.encoded)
        except (AttributeError, TypeError, TrustedTimeGracefulStopV2Rejected):
            raise LifecycleV2RepositoryRejected(
                "progress record is not canonically valid"
            ) from None
        if verified_record != record:
            raise LifecycleV2RepositoryRejected(
                "progress record changed under canonical validation"
            )
        predecessor = self._records[-1].sha256 if self._records else self._root.sha256
        if (
            record.root_sha256 != self._root.sha256
            or record.graceful_stop_operation_id != self._root.graceful_stop_operation_id
            or record.predecessor_sha256 != predecessor
            or record.deadline_boottime_ns != self._root.operation_deadline_boottime_ns
        ):
            raise LifecycleV2RepositoryRejected("progress record does not bind this lifecycle")
        self._require_stage_transition(record)

    def _require_derived_request_intent(
        self,
        record: LifecycleV2ProgressRecord,
        *,
        basis: LifecycleV2CleanStopRequestBasis | None = None,
    ) -> None:
        if self._root is None:
            raise LifecycleV2RepositoryRejected("request intent requires a lifecycle root")
        try:
            derived_basis = LifecycleV2CleanStopRequestBasis.from_root(self._root)
            if basis is not None:
                if type(basis) is not LifecycleV2CleanStopRequestBasis:
                    raise TrustedTimeGracefulStopV2Rejected("request basis type is invalid")
                decoded_basis = decode_lifecycle_v2_clean_stop_request_basis(basis.encoded)
                if decoded_basis != basis or decoded_basis != derived_basis:
                    raise TrustedTimeGracefulStopV2Rejected("request basis is not root-derived")
            expected_evidence = {
                "target_identity_sha256": self._root.supervisor_container_id,
                "arguments_sha256": derived_basis.sha256,
                "admission_sha256": self._root.admission_sha256,
                "channel_id": self._root.channel_id,
                "call_deadline_boottime_ns": (self._root.clean_stop_result_deadline_boottime_ns),
                "admission_started_boottime_ns": self._root.admission_started_boottime_ns,
                "operation_deadline_boottime_ns": self._root.operation_deadline_boottime_ns,
            }
            if (
                record.ordinal != 1
                or record.stage is not LifecycleV2Stage.CLEAN_STOP_REQUEST_INTENT_RETAINED
                or record.effect_kind != "clean_stop_request"
                or record.evidence.to_dict() != expected_evidence
            ):
                raise TrustedTimeGracefulStopV2Rejected(
                    "request intent is not exactly root/basis-derived"
                )
        except (AttributeError, TypeError, TrustedTimeGracefulStopV2Rejected):
            raise LifecycleV2RepositoryRejected(
                "request intent is not exactly root/basis-derived"
            ) from None

    @property
    def status(self) -> LifecycleV2RepositoryStatus:
        if self._poisoned:
            return LifecycleV2RepositoryStatus.RETENTION_UNCONFIRMED
        if self._commit is not None:
            return LifecycleV2RepositoryStatus.OUTCOME_COMMITTED
        if self._outcome is not None:
            return LifecycleV2RepositoryStatus.RECOVERY_REQUIRED
        if self._root is None:
            return LifecycleV2RepositoryStatus.UNRESERVED
        if self._records and self._records[-1].stage in {
            LifecycleV2Stage.CLEAN_STOP_ERROR_RETAINED,
            LifecycleV2Stage.RECOVERY_CLASSIFICATION_INTENT_RETAINED,
        }:
            return LifecycleV2RepositoryStatus.RECOVERY_REQUIRED
        return LifecycleV2RepositoryStatus.ROOT_RESERVED

    def reserve_root(self, root: LifecycleV2Root) -> None:
        self._require_owner()
        if type(root) is not LifecycleV2Root:
            raise LifecycleV2RepositoryRejected("root must be an exact lifecycle-v2 value")
        try:
            verified_root = decode_lifecycle_v2_root(root.encoded)
        except (AttributeError, TypeError, TrustedTimeGracefulStopV2Rejected):
            raise LifecycleV2RepositoryRejected("root is not canonically valid") from None
        if verified_root != root:
            raise LifecycleV2RepositoryRejected("root changed under canonical validation")
        root = verified_root
        if self._root is not None or self._store.inventory():
            raise LifecycleV2SlotConsumed("the shared lifecycle slot is consumed")
        try:
            self._store.create_root_exclusive(LIFECYCLE_ROOT_FILE_NAME, root.encoded)
            if self._store.read_stable(LIFECYCLE_ROOT_FILE_NAME) != root.encoded:
                raise LifecycleV2ArtifactPublicationUncertain
        except BaseException as error:
            self._burn()
            if not isinstance(error, Exception):
                raise
            raise LifecycleV2RetentionUnconfirmed("root creation may have begun") from None
        self._root = root

    def _retain_progress(
        self,
        record: LifecycleV2ProgressRecord,
        *,
        authenticated_envelope: _FakeAuthenticatedLifecycleV2TransportEnvelope | None = None,
    ) -> None:
        self._require_owner()
        self._require_record_binding(record)
        envelope: UnverifiedLifecycleV2TransportEnvelope | None = None
        if record.stage in {
            LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED,
            LifecycleV2Stage.CLEAN_STOP_ERROR_RETAINED,
        }:
            try:
                envelope = _require_fake_authenticated_lifecycle_v2_transport_envelope(
                    authenticated_envelope
                )
            except TrustedTimeGracefulStopV2Rejected as error:
                raise LifecycleV2RepositoryRejected(
                    "ordinal two requires fake-authenticated signed wire bytes"
                ) from error
            expected_frame = (
                "clean_stop_result"
                if record.stage is LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED
                else "clean_stop_error"
            )
            evidence = record.evidence.to_dict()
            if (
                envelope.frame_type != expected_frame
                or evidence[f"{expected_frame}_sha256"] != envelope.sha256
                or evidence[f"{expected_frame}_artifact_name"]
                != lifecycle_v2_wire_file_name(envelope)
            ):
                raise LifecycleV2RepositoryRejected("wire envelope and ordinal two disagree")
        elif authenticated_envelope is not None:
            raise LifecycleV2RepositoryRejected("only ordinal two may retain wire bytes")
        try:
            if envelope is not None:
                self._store.publish_immutable(
                    staging_name=(
                        _WIRE_RESULT_STAGING_NAME
                        if envelope.frame_type == "clean_stop_result"
                        else _WIRE_ERROR_STAGING_NAME
                    ),
                    final_name=lifecycle_v2_wire_file_name(envelope),
                    encoded=envelope.encoded,
                )
            self._store.publish_immutable(
                staging_name=_RECORD_STAGING_NAME,
                final_name=lifecycle_v2_progress_file_name(record),
                encoded=record.encoded,
            )
            if self._store.read_stable(lifecycle_v2_progress_file_name(record)) != record.encoded:
                raise LifecycleV2ArtifactPublicationUncertain
        except BaseException as error:
            self._burn()
            if not isinstance(error, Exception):
                raise
            raise LifecycleV2RetentionUnconfirmed("progress retention may have begun") from None
        self._records = (*self._records, record)
        if envelope is not None:
            self._wire = envelope

    def retain_request_intent(
        self,
        record: LifecycleV2ProgressRecord,
        basis: LifecycleV2CleanStopRequestBasis,
    ) -> None:
        if record.stage is not LifecycleV2Stage.CLEAN_STOP_REQUEST_INTENT_RETAINED:
            raise LifecycleV2RepositoryRejected("request-intent method received another stage")
        self._require_derived_request_intent(record, basis=basis)
        self._retain_progress(record)

    def retain_authenticated_terminal_wire(
        self,
        record: LifecycleV2ProgressRecord,
        authenticated_envelope: _FakeAuthenticatedLifecycleV2TransportEnvelope,
    ) -> None:
        if record.stage not in {
            LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED,
            LifecycleV2Stage.CLEAN_STOP_ERROR_RETAINED,
        }:
            raise LifecycleV2RepositoryRejected("terminal-wire method received another stage")
        self._retain_progress(record, authenticated_envelope=authenticated_envelope)

    def retain_transport_cleanup_commitment(self, record: LifecycleV2ProgressRecord) -> None:
        if record.stage is not LifecycleV2Stage.TRANSPORT_CLEANUP_COMMITMENT_RETAINED:
            raise LifecycleV2RepositoryRejected("cleanup-commitment stage is wrong")
        self._retain_progress(record)

    def retain_transport_quiescence(self, record: LifecycleV2ProgressRecord) -> None:
        if record.stage is not LifecycleV2Stage.TRANSPORT_CHANNEL_QUIESCED:
            raise LifecycleV2RepositoryRejected("transport-quiescence stage is wrong")
        self._retain_progress(record)

    def retain_reauthentication_intent(self, record: LifecycleV2ProgressRecord) -> None:
        if record.stage not in {
            LifecycleV2Stage.PRE_EFFECT_REAUTHENTICATION_INTENT_RETAINED,
            LifecycleV2Stage.POST_TEARDOWN_REAUTHENTICATION_INTENT_RETAINED,
        }:
            raise LifecycleV2RepositoryRejected("reauthentication-intent stage is wrong")
        self._retain_progress(record)

    def retain_reauthentication_result(self, record: LifecycleV2ProgressRecord) -> None:
        if record.stage not in {
            LifecycleV2Stage.PRE_EFFECT_REAUTHENTICATION_BOUND,
            LifecycleV2Stage.POST_TEARDOWN_TERMINAL_REAUTHENTICATION_BOUND,
        }:
            raise LifecycleV2RepositoryRejected("reauthentication-result stage is wrong")
        self._retain_progress(record)

    def retain_effect_intent(self, record: LifecycleV2ProgressRecord) -> None:
        if record.stage not in {
            LifecycleV2Stage.SUPERVISOR_CONTAINER_STOP_INTENT_RETAINED,
            LifecycleV2Stage.SOURCE_CONTAINER_STOP_INTENT_RETAINED,
            LifecycleV2Stage.SUPERVISOR_CONTAINER_REMOVE_INTENT_RETAINED,
            LifecycleV2Stage.SOURCE_CONTAINER_REMOVE_INTENT_RETAINED,
            LifecycleV2Stage.PROJECT_NETWORK_REMOVE_INTENT_RETAINED,
            LifecycleV2Stage.NAMED_VOLUME_PRESERVATION_INTENT_RETAINED,
        }:
            raise LifecycleV2RepositoryRejected("effect-intent stage is wrong")
        self._retain_progress(record)

    def retain_effect_result(self, record: LifecycleV2ProgressRecord) -> None:
        if record.stage not in {
            LifecycleV2Stage.SUPERVISOR_CONTAINER_STOP_RESULT_RETAINED,
            LifecycleV2Stage.SOURCE_CONTAINER_STOP_RESULT_RETAINED,
            LifecycleV2Stage.SUPERVISOR_CONTAINER_REMOVE_RESULT_RETAINED,
            LifecycleV2Stage.SOURCE_CONTAINER_REMOVE_RESULT_RETAINED,
            LifecycleV2Stage.PROJECT_NETWORK_REMOVE_RESULT_RETAINED,
            LifecycleV2Stage.NAMED_VOLUMES_PRESERVED,
        }:
            raise LifecycleV2RepositoryRejected("effect-result stage is wrong")
        self._retain_progress(record)

    def retain_terminal_cleanup_intent(self, record: LifecycleV2ProgressRecord) -> None:
        if record.stage is not LifecycleV2Stage.TERMINAL_CLEANUP_INTENT_RETAINED:
            raise LifecycleV2RepositoryRejected("terminal-cleanup intent stage is wrong")
        self._retain_progress(record)

    def retain_terminal_cleanup_result(self, record: LifecycleV2ProgressRecord) -> None:
        if record.stage is not LifecycleV2Stage.TERMINAL_CLEANUP_CONFIRMED:
            raise LifecycleV2RepositoryRejected("terminal-cleanup result stage is wrong")
        self._retain_progress(record)

    def retain_recovery_classification_intent(self, record: LifecycleV2ProgressRecord) -> None:
        if record.stage is not LifecycleV2Stage.RECOVERY_CLASSIFICATION_INTENT_RETAINED:
            raise LifecycleV2RepositoryRejected("recovery-classification stage is wrong")
        self._require_owner()
        self._require_record_binding(record)
        classified_transcript = self._transcript()
        if (
            record.evidence.to_dict()["classified_transcript_sha256"]
            != classified_transcript.sha256
        ):
            raise LifecycleV2RepositoryRejected(
                "recovery intent does not bind the classified prefix"
            )
        try:
            if self._store.read_stable(classified_transcript.file_name) != (
                classified_transcript.encoded
            ):
                raise LifecycleV2ArtifactPublicationUncertain
        except BaseException as error:
            self._burn()
            if not isinstance(error, Exception):
                raise
            raise LifecycleV2RetentionUnconfirmed(
                "classified transcript retention is unconfirmed"
            ) from None
        self._retain_progress(record)

    def _transcript(self, *, last_ordinal: int | None = None) -> LifecycleV2Transcript:
        if self._root is None:
            raise LifecycleV2RepositoryRejected("transcript requires a lifecycle root")
        selected = self._records if last_ordinal is None else self._records[:last_ordinal]
        if last_ordinal is not None and (last_ordinal < 0 or len(selected) != last_ordinal):
            raise LifecycleV2RetentionUnconfirmed("transcript references an absent prefix")
        entries = [
            LifecycleV2TranscriptEntry(
                ordinal=0,
                stage=LifecycleV2Stage.ROOT_RESERVED,
                record_artifact_kind="root",
                record_contract_version=LIFECYCLE_V2_ROOT_CONTRACT_VERSION,
                record_artifact_sha256=self._root.sha256,
                predecessor_sha256=None,
            )
        ]
        for record in selected:
            wire_kind: str | None = None
            wire_path: str | None = None
            wire_name: str | None = None
            wire_sha256: str | None = None
            if record.stage in {
                LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED,
                LifecycleV2Stage.CLEAN_STOP_ERROR_RETAINED,
            }:
                evidence = record.evidence.to_dict()
                prefix = (
                    "clean_stop_result"
                    if record.stage is LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED
                    else "clean_stop_error"
                )
                wire_kind = (
                    "signed_result_envelope"
                    if prefix == "clean_stop_result"
                    else "signed_error_envelope"
                )
                wire_path = cast(str, evidence[f"{prefix}_artifact_path"])
                wire_name = cast(str, evidence[f"{prefix}_artifact_name"])
                wire_sha256 = cast(str, evidence[f"{prefix}_sha256"])
            entries.append(
                LifecycleV2TranscriptEntry(
                    ordinal=record.ordinal,
                    stage=record.stage,
                    record_artifact_kind="progress",
                    record_contract_version=LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION,
                    record_artifact_sha256=record.sha256,
                    predecessor_sha256=record.predecessor_sha256,
                    wire_artifact_kind=wire_kind,
                    wire_artifact_path=wire_path,
                    wire_artifact_file_name=wire_name,
                    wire_artifact_sha256=wire_sha256,
                )
            )
        return LifecycleV2Transcript(
            environment=self._root.environment,
            graceful_stop_operation_id=self._root.graceful_stop_operation_id,
            root_sha256=self._root.sha256,
            entries=tuple(entries),
        )

    def publish_transcript(self) -> LifecycleV2Transcript:
        self._require_owner()
        if self._outcome is not None or self._commit is not None:
            raise LifecycleV2RepositoryRejected("terminal outcome already retained")
        transcript = self._transcript()
        try:
            self._store.publish_immutable(
                staging_name=_TRANSCRIPT_STAGING_NAME,
                final_name=transcript.file_name,
                encoded=transcript.encoded,
            )
            if self._store.read_stable(transcript.file_name) != transcript.encoded:
                raise LifecycleV2ArtifactPublicationUncertain
        except BaseException as error:
            self._burn()
            if not isinstance(error, Exception):
                raise
            raise LifecycleV2RetentionUnconfirmed("transcript publication may have begun") from None
        return transcript

    def commit_recovery_outcome(
        self,
        outcome: LifecycleV2Outcome,
        commit: LifecycleV2OutcomeCommit,
    ) -> None:
        self._require_owner()
        if self._commit is not None:
            raise LifecycleV2RepositoryRejected("terminal outcome already committed")
        if self._root is None or type(outcome) is not LifecycleV2Outcome:
            raise LifecycleV2RepositoryRejected("recovery outcome requires an exact root")
        if type(commit) is not LifecycleV2OutcomeCommit:
            raise LifecycleV2RepositoryRejected("milestone-one repository writes recovery only")
        try:
            verified_outcome = decode_lifecycle_v2_outcome(outcome.encoded)
        except (AttributeError, TypeError, TrustedTimeGracefulStopV2Rejected):
            raise LifecycleV2RepositoryRejected("outcome proof is not canonically valid") from None
        if verified_outcome != outcome:
            raise LifecycleV2RepositoryRejected("outcome proof changed under canonical validation")
        outcome = verified_outcome
        if outcome.status != "recovery_required":
            raise LifecycleV2RepositoryRejected("milestone-one repository writes recovery only")
        if self._outcome is not None and self._outcome != outcome:
            raise LifecycleV2RepositoryRejected("a different outcome candidate is retained")
        try:
            verified_commit = decode_lifecycle_v2_outcome_commit(
                commit.encoded,
                outcome=outcome,
            )
        except (AttributeError, TypeError, TrustedTimeGracefulStopV2Rejected):
            raise LifecycleV2RepositoryRejected("commit proof is not canonically valid") from None
        if verified_commit != commit:
            raise LifecycleV2RepositoryRejected("commit proof changed under canonical validation")
        commit = verified_commit
        if (
            not self._records
            or self._records[-1].stage
            is not LifecycleV2Stage.RECOVERY_CLASSIFICATION_INTENT_RETAINED
        ):
            raise LifecycleV2RepositoryRejected(
                "recovery outcome requires a retained classification intent"
            )
        transcript = self._transcript()
        outcome_fields = outcome.to_dict()
        recovery_fields = self._records[-1].evidence.to_dict()
        if (
            outcome_fields["root_sha256"] != self._root.sha256
            or outcome_fields["graceful_stop_operation_id"] != self._root.graceful_stop_operation_id
            or outcome_fields["ordinal"] != len(self._records) + 1
            or outcome_fields["predecessor_sha256"]
            != (self._records[-1].sha256 if self._records else self._root.sha256)
            or outcome_fields["transcript_sha256"] != transcript.sha256
            or outcome_fields["final_stage"] != self._records[-1].stage.value
            or outcome_fields["reason_code"] != recovery_fields["reason_code"]
        ):
            raise LifecycleV2RepositoryRejected("recovery outcome is not the exact next terminal")
        LifecycleV2OutcomeCommit.capture(commit.to_dict(), outcome=outcome)
        try:
            self._store.publish_immutable(
                staging_name=_TRANSCRIPT_STAGING_NAME,
                final_name=transcript.file_name,
                encoded=transcript.encoded,
            )
            self._store.publish_immutable(
                staging_name=_OUTCOME_STAGING_NAME,
                final_name=outcome.file_name,
                encoded=outcome.encoded,
            )
            self._store.publish_immutable(
                staging_name=_COMMIT_STAGING_NAME,
                final_name=LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME,
                encoded=commit.encoded,
            )
            if self._store.read_stable(LIFECYCLE_V2_OUTCOME_COMMIT_FILE_NAME) != commit.encoded:
                raise LifecycleV2ArtifactPublicationUncertain
        except BaseException as error:
            self._burn()
            if not isinstance(error, Exception):
                raise
            raise LifecycleV2RetentionUnconfirmed("outcome commit may have begun") from None
        self._outcome = outcome
        self._commit = commit


def _open_injected_lifecycle_v2_repository(
    store: LifecycleV2ArtifactStore,
    *,
    artifact_directory_path: str,
) -> _LifecycleV2Repository:
    """Test-only builder; deliberately private and without a default root."""

    return _LifecycleV2Repository(store, artifact_directory_path=artifact_directory_path)


def lifecycle_v2_repository_non_authority_facts() -> dict[str, bool]:
    return {
        "production_store_implemented": False,
        "default_artifact_root_present": False,
        "confirmed_success_writer_present": False,
        "effect_adapter_present": False,
        "automatic_recovery_present": False,
    }


__all__ = [
    "LifecycleV2ArtifactAlreadyExists",
    "LifecycleV2ArtifactPublicationUncertain",
    "LifecycleV2ArtifactStore",
    "LifecycleV2RepositoryRejected",
    "LifecycleV2RepositoryStatus",
    "LifecycleV2RetentionUnconfirmed",
    "LifecycleV2SlotConsumed",
    "lifecycle_v2_repository_non_authority_facts",
]
