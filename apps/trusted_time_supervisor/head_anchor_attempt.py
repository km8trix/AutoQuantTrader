"""Repository-backed composition for one trusted-head anchor work request.

The composition keeps remote I/O outside SQL transactions, durably commits an
exact signed-object intent before any upload, and writes a receipt only after a
second byte-exact provider readback.  It is evidence only and grants no runtime
or trading authority.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from apps.trusted_time_supervisor.head_anchor_config import (
    TrustedTimeHeadAnchorAuthority,
)
from packages.application.trusted_time_head_anchor import (
    TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
    PreparedTrustedTimeHeadAnchorReconciliation,
    TrustedTimeHeadAnchorCheckpointReason,
    TrustedTimeHeadAnchorConflict,
    TrustedTimeHeadAnchorEd25519Signer,
    TrustedTimeHeadAnchorEd25519Verifier,
    TrustedTimeHeadAnchorEnrollmentNotApproved,
    TrustedTimeHeadAnchorProvider,
    TrustedTimeHeadAnchorProviderUnavailable,
    TrustedTimeHeadAnchorReconciliationResult,
    TrustedTimeHeadAnchorRecord,
    complete_trusted_time_head_anchor_reconciliation,
    prepare_bounded_persisted_trusted_time_head_anchor_intent_recovery,
    prepare_bounded_trusted_time_head_anchor_reconciliation,
    prepare_incremental_trusted_time_head_anchor_reconciliation,
    verify_bounded_first_enrollment_remote_postcondition,
    verify_bounded_post_enrollment_start_remote_postcondition,
    verify_trusted_time_head_anchor_provider_readback,
)
from packages.application.trusted_time_head_anchor_worker import (
    TrustedTimeHeadAnchorAttemptResult,
    TrustedTimeHeadAnchorEnrollmentNotApprovedFailure,
    TrustedTimeHeadAnchorFatalFailure,
    TrustedTimeHeadAnchorTransientFailure,
    TrustedTimeHeadAnchorWorkRequest,
)
from packages.domain.trusted_time_enrollment_evidence import (
    trusted_time_first_enrollment_identity_sha256,
)
from packages.persistence.trusted_time_head_anchor import (
    PersistedTrustedTimeHeadAnchorReceipt,
    SqlTrustedTimeHeadAnchorRepository,
    TrustedTimeHeadAnchorPersistenceSnapshot,
    TrustedTimeHeadAnchorSnapshotAdvanced,
)

TRUSTED_TIME_HEAD_ANCHOR_ATTEMPT_CONTRACT_VERSION = (
    "phase6d-repository-backed-trusted-head-anchor-attempt-v1"
)


def _authority_is_never_granted(_: object) -> bool:
    return False


class TrustedTimeHeadAnchorFirstEnrollmentAlreadyCompleted(TrustedTimeHeadAnchorFatalFailure):
    """A one-shot enrollment was invoked after durable enrollment existed."""


class TrustedTimeHeadAnchorFirstEnrollmentStateConflict(TrustedTimeHeadAnchorFatalFailure):
    """Durable state cannot represent exactly one recoverable first enrollment."""


class TrustedTimeHeadAnchorFirstEnrollmentRecoveryRequired(TrustedTimeHeadAnchorFatalFailure):
    """A durable intent or remote effect may exist and needs separate recovery."""


class TrustedTimeHeadAnchorFirstEnrollmentDisposition(StrEnum):
    NEW_INTENT_COMPLETED = "new_intent_completed"
    PENDING_INTENT_RECOVERED = "pending_intent_recovered"
    CONFIRMED_RECEIPT_REOBSERVED = "confirmed_receipt_reobserved"


@dataclass(frozen=True, slots=True)
class TrustedTimeHeadAnchorFirstEnrollmentResult:
    """Sanitized durable sequence-one evidence; never an authority grant."""

    anchor_sequence: int
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason
    current_host_head_sha256: str
    current_anchor_sha256: str
    current_anchor_semantic_sha256: str
    completed_at_utc: datetime
    full_audit_completed: bool
    completion_disposition: TrustedTimeHeadAnchorFirstEnrollmentDisposition
    uploaded_anchor_count: int | None
    idempotent_duplicate_count: int | None
    anchor_intent_semantic_sha256: str
    candidate_remote_readback_sha256: str
    receipt_semantic_sha256: str

    def __post_init__(self) -> None:
        digests = (
            self.current_host_head_sha256,
            self.current_anchor_sha256,
            self.current_anchor_semantic_sha256,
            self.anchor_intent_semantic_sha256,
            self.candidate_remote_readback_sha256,
            self.receipt_semantic_sha256,
        )
        if (
            type(self.anchor_sequence) is not int
            or self.anchor_sequence != 1
            or self.checkpoint_reason is not TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT
            or any(
                type(value) is not str
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
                for value in digests
            )
            or self.candidate_remote_readback_sha256 != self.current_anchor_sha256
            or type(self.completed_at_utc) is not datetime
            or self.completed_at_utc.tzinfo is None
            or self.completed_at_utc.utcoffset() is None
            or self.completed_at_utc.utcoffset() != UTC.utcoffset(self.completed_at_utc)
            or self.full_audit_completed is not True
            or type(self.completion_disposition)
            is not TrustedTimeHeadAnchorFirstEnrollmentDisposition
        ):
            raise TrustedTimeHeadAnchorFirstEnrollmentStateConflict(
                "trusted-time first enrollment result is invalid"
            )
        counts = (self.uploaded_anchor_count, self.idempotent_duplicate_count)
        if self.completion_disposition is (
            TrustedTimeHeadAnchorFirstEnrollmentDisposition.CONFIRMED_RECEIPT_REOBSERVED
        ):
            if counts != (None, None):
                raise TrustedTimeHeadAnchorFirstEnrollmentStateConflict(
                    "trusted-time first enrollment reobservation counts are invalid"
                )
        elif (
            any(type(value) is not int or value not in (0, 1) for value in counts)
            or sum(value for value in counts if value is not None) != 1
        ):
            raise TrustedTimeHeadAnchorFirstEnrollmentStateConflict(
                "trusted-time first enrollment completion counts are invalid"
            )

    @property
    def pending_intent_recovered(self) -> bool:
        return self.completion_disposition is (
            TrustedTimeHeadAnchorFirstEnrollmentDisposition.PENDING_INTENT_RECOVERED
        )

    operational_control_authorized = property(_authority_is_never_granted)
    readiness_authorized = property(_authority_is_never_granted)
    arming_authorized = property(_authority_is_never_granted)
    new_exposure_authorized = property(_authority_is_never_granted)
    broker_action_authorized = property(_authority_is_never_granted)
    automatic_rearm_authorized = property(_authority_is_never_granted)
    rearm_authorized = property(_authority_is_never_granted)
    automatic_resume_authorized = property(_authority_is_never_granted)
    alert_delivery_authorized = property(_authority_is_never_granted)
    exposure_authorized = property(_authority_is_never_granted)
    paper_trading_authorized = property(_authority_is_never_granted)
    live_trading_authorized = property(_authority_is_never_granted)


@dataclass(frozen=True, slots=True)
class TrustedTimeHeadAnchorFirstEnrollmentPostcondition:
    """Fresh read-only proof that sequence one is still the complete head.

    The proof contains only digest and count projections.  Constructing it
    never grants permission to prepare a successor, register an epoch, or
    invoke the signer or provider upload port.
    """

    anchor_sequence: int
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason
    confirmed_anchor_count: int
    local_transition_count: int
    confirmed_anchor_local_transition_ordinal: int
    remote_object_count: int
    current_host_head_sha256: str
    current_anchor_sha256: str
    current_anchor_semantic_sha256: str
    anchor_intent_semantic_sha256: str
    candidate_remote_readback_sha256: str
    receipt_semantic_sha256: str
    remote_namespace_sha256: str
    anchor_authority_sha256: str
    deployment_identity_sha256: str
    runtime_database_identity_sha256: str
    anchor_project_identity_sha256: str
    source_authority_sha256: str
    signing_public_key_sha256: str
    host_identity_sha256: str
    principal_identity_sha256: str
    bucket_identity_sha256: str
    full_audit_completed: bool
    pending_intent_present: bool

    def __post_init__(self) -> None:
        digests = (
            self.current_host_head_sha256,
            self.current_anchor_sha256,
            self.current_anchor_semantic_sha256,
            self.anchor_intent_semantic_sha256,
            self.candidate_remote_readback_sha256,
            self.receipt_semantic_sha256,
            self.remote_namespace_sha256,
            self.anchor_authority_sha256,
            self.deployment_identity_sha256,
            self.runtime_database_identity_sha256,
            self.anchor_project_identity_sha256,
            self.source_authority_sha256,
            self.signing_public_key_sha256,
            self.host_identity_sha256,
            self.principal_identity_sha256,
            self.bucket_identity_sha256,
        )
        if (
            type(self.anchor_sequence) is not int
            or self.anchor_sequence != 1
            or self.checkpoint_reason is not TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT
            or type(self.confirmed_anchor_count) is not int
            or self.confirmed_anchor_count != 1
            or type(self.local_transition_count) is not int
            or self.local_transition_count < 1
            or type(self.confirmed_anchor_local_transition_ordinal) is not int
            or self.confirmed_anchor_local_transition_ordinal != self.local_transition_count
            or type(self.remote_object_count) is not int
            or self.remote_object_count != 1
            or any(
                type(value) is not str
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
                for value in digests
            )
            or self.candidate_remote_readback_sha256 != self.current_anchor_sha256
            or self.full_audit_completed is not True
            or self.pending_intent_present is not False
        ):
            raise TrustedTimeHeadAnchorFirstEnrollmentStateConflict(
                "trusted-time first enrollment postcondition is invalid"
            )

    operational_control_authorized = property(_authority_is_never_granted)
    readiness_authorized = property(_authority_is_never_granted)
    arming_authorized = property(_authority_is_never_granted)
    new_exposure_authorized = property(_authority_is_never_granted)
    broker_action_authorized = property(_authority_is_never_granted)
    automatic_rearm_authorized = property(_authority_is_never_granted)
    rearm_authorized = property(_authority_is_never_granted)
    automatic_resume_authorized = property(_authority_is_never_granted)
    alert_delivery_authorized = property(_authority_is_never_granted)
    exposure_authorized = property(_authority_is_never_granted)
    paper_trading_authorized = property(_authority_is_never_granted)
    live_trading_authorized = property(_authority_is_never_granted)


class TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed(
    TrustedTimeHeadAnchorFatalFailure
):
    """A sequence-one receipt exists but later in-process checks did not finish."""

    def __init__(
        self,
        evidence: TrustedTimeHeadAnchorFirstEnrollmentResult | None,
    ) -> None:
        if evidence is not None and type(evidence) is not (
            TrustedTimeHeadAnchorFirstEnrollmentResult
        ):
            raise TrustedTimeHeadAnchorFirstEnrollmentStateConflict(
                "trusted-time first enrollment uncertain evidence is invalid"
            )
        self.evidence = evidence
        super().__init__("trusted-time first enrollment postconditions are unconfirmed")


class TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed(
    TrustedTimeHeadAnchorFatalFailure
):
    """A sequence-two effect cannot be qualified without separate recovery."""

    def __init__(self) -> None:
        super().__init__("trusted-time post-enrollment start postconditions are unconfirmed")


@dataclass(frozen=True, slots=True)
class TrustedTimeHeadAnchorPostEnrollmentStartPostcondition:
    """Digest-only sequence-two observation that grants no runtime authority."""

    anchor_sequence: int
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason
    confirmed_anchor_count: int
    local_transition_count: int
    confirmed_anchor_local_transition_ordinal: int
    remote_object_count: int
    predecessor_anchor_sha256: str
    current_host_head_sha256: str
    current_anchor_sha256: str
    current_anchor_semantic_sha256: str
    anchor_intent_semantic_sha256: str
    candidate_remote_readback_sha256: str
    receipt_semantic_sha256: str
    remote_namespace_sha256: str
    anchor_authority_sha256: str
    deployment_identity_sha256: str
    runtime_database_identity_sha256: str
    anchor_project_identity_sha256: str
    source_authority_sha256: str
    signing_public_key_sha256: str
    host_identity_sha256: str
    principal_identity_sha256: str
    bucket_identity_sha256: str
    full_audit_completed: bool
    pending_intent_present: bool

    def __post_init__(self) -> None:
        digests = (
            self.predecessor_anchor_sha256,
            self.current_host_head_sha256,
            self.current_anchor_sha256,
            self.current_anchor_semantic_sha256,
            self.anchor_intent_semantic_sha256,
            self.candidate_remote_readback_sha256,
            self.receipt_semantic_sha256,
            self.remote_namespace_sha256,
            self.anchor_authority_sha256,
            self.deployment_identity_sha256,
            self.runtime_database_identity_sha256,
            self.anchor_project_identity_sha256,
            self.source_authority_sha256,
            self.signing_public_key_sha256,
            self.host_identity_sha256,
            self.principal_identity_sha256,
            self.bucket_identity_sha256,
        )
        if (
            type(self.anchor_sequence) is not int
            or self.anchor_sequence != 2
            or self.checkpoint_reason is not TrustedTimeHeadAnchorCheckpointReason.EPOCH_ROTATION
            or type(self.confirmed_anchor_count) is not int
            or self.confirmed_anchor_count != 2
            or type(self.local_transition_count) is not int
            or self.local_transition_count < 2
            or type(self.confirmed_anchor_local_transition_ordinal) is not int
            or self.confirmed_anchor_local_transition_ordinal < 2
            or self.confirmed_anchor_local_transition_ordinal > self.local_transition_count
            or type(self.remote_object_count) is not int
            or self.remote_object_count != 2
            or any(
                type(value) is not str
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
                for value in digests
            )
            or self.predecessor_anchor_sha256 == self.current_anchor_sha256
            or self.candidate_remote_readback_sha256 != self.current_anchor_sha256
            or self.full_audit_completed is not True
            or self.pending_intent_present is not False
        ):
            raise TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed()

    operational_control_authorized = property(_authority_is_never_granted)
    readiness_authorized = property(_authority_is_never_granted)
    arming_authorized = property(_authority_is_never_granted)
    new_exposure_authorized = property(_authority_is_never_granted)
    broker_action_authorized = property(_authority_is_never_granted)
    automatic_rearm_authorized = property(_authority_is_never_granted)
    rearm_authorized = property(_authority_is_never_granted)
    automatic_resume_authorized = property(_authority_is_never_granted)
    alert_delivery_authorized = property(_authority_is_never_granted)
    exposure_authorized = property(_authority_is_never_granted)
    paper_trading_authorized = property(_authority_is_never_granted)
    live_trading_authorized = property(_authority_is_never_granted)


class RepositoryBackedTrustedTimeHeadAnchorAttempt:
    """Own one compact authenticated cursor for the background worker thread."""

    __slots__ = (
        "_anchor_repository",
        "_authority",
        "_closed",
        "_provider",
        "_signer",
        "_snapshot",
        "_utc_clock",
        "_verifier",
    )

    def __init__(
        self,
        *,
        anchor_repository: SqlTrustedTimeHeadAnchorRepository,
        provider: TrustedTimeHeadAnchorProvider,
        signer: TrustedTimeHeadAnchorEd25519Signer,
        verifier: TrustedTimeHeadAnchorEd25519Verifier,
        authority: TrustedTimeHeadAnchorAuthority,
        utc_clock: Callable[[], datetime],
    ) -> None:
        if type(authority) is not TrustedTimeHeadAnchorAuthority or not callable(utc_clock):
            raise TrustedTimeHeadAnchorFatalFailure(
                "trusted-time anchor attempt dependencies are invalid"
            )
        try:
            authority.__post_init__()
            required = (
                (
                    anchor_repository,
                    (
                        "load_head_anchor_startup_snapshot",
                        "compact_head_anchor_snapshot",
                        "discard_head_anchor_snapshot",
                        "refresh_head_anchor_snapshot",
                        "commit_prepared_intent",
                        "confirm_remote_readback_from_snapshot",
                    ),
                ),
                (
                    provider,
                    (
                        "attest_identity",
                        "list_object_names_page",
                        "list_sequence_object_names",
                        "download_object",
                        "upload_object_no_overwrite",
                    ),
                ),
                (signer, ("sign_ed25519",)),
                (verifier, ("verify_ed25519",)),
            )
            if any(
                not callable(getattr(dependency, method, None))
                for dependency, methods in required
                for method in methods
            ):
                raise TypeError
        except Exception:
            raise TrustedTimeHeadAnchorFatalFailure(
                "trusted-time anchor attempt dependencies are invalid"
            ) from None
        self._anchor_repository = anchor_repository
        self._provider = provider
        self._signer = signer
        self._verifier = verifier
        self._authority = authority
        self._utc_clock = utc_clock
        self._snapshot: TrustedTimeHeadAnchorPersistenceSnapshot | None = None
        self._closed = False

    def _now(self) -> datetime:
        try:
            value = self._utc_clock()
        except Exception:
            raise TrustedTimeHeadAnchorFatalFailure(
                "trusted-time anchor UTC clock failed"
            ) from None
        if (
            type(value) is not datetime
            or value.tzinfo is None
            or value.utcoffset() is None
            or value.utcoffset() != UTC.utcoffset(value)
        ):
            raise TrustedTimeHeadAnchorFatalFailure("trusted-time anchor UTC clock is invalid")
        return value

    def _replace_with_full_snapshot(
        self,
    ) -> TrustedTimeHeadAnchorPersistenceSnapshot:
        authority = self._authority
        replacement = self._anchor_repository.load_head_anchor_startup_snapshot(
            host_id=authority.host_id,
            deployment_identity_sha256=authority.deployment_identity_sha256,
            runtime_database_identity_sha256=(authority.runtime_database_identity_sha256),
            anchor_project_identity_sha256=(authority.anchor_project_identity_sha256),
            anchor_project_ref=authority.anchor_project_ref,
            bucket_name=authority.bucket_name,
            principal_id=authority.principal_id,
        )
        previous = self._snapshot
        if previous is not None and previous is not replacement:
            try:
                self._anchor_repository.discard_head_anchor_snapshot(previous)
            except Exception:
                # Do not retain a second repository-issued cursor when the
                # prior cursor cannot be released exactly.
                with suppress(Exception):
                    self._anchor_repository.discard_head_anchor_snapshot(replacement)
                raise
        self._snapshot = replacement
        return replacement

    def prime_startup(self) -> None:
        """Full-authenticate local SQL only; never touch signer or provider."""

        if self._closed or self._snapshot is not None:
            raise TrustedTimeHeadAnchorFatalFailure(
                "trusted-time anchor startup cursor cannot be primed"
            )
        try:
            self._replace_with_full_snapshot()
        except Exception:
            raise TrustedTimeHeadAnchorFatalFailure(
                "trusted-time anchor startup cursor authentication failed"
            ) from None

    def _require_snapshot(self) -> TrustedTimeHeadAnchorPersistenceSnapshot:
        snapshot = self._snapshot
        if self._closed or snapshot is None:
            raise TrustedTimeHeadAnchorFatalFailure("trusted-time anchor attempt is not primed")
        return snapshot

    def _compact_snapshot(self) -> None:
        snapshot = self._require_snapshot()
        self._snapshot = self._anchor_repository.compact_head_anchor_snapshot(snapshot)

    def _refresh_snapshot(self) -> TrustedTimeHeadAnchorPersistenceSnapshot:
        snapshot = self._require_snapshot()
        refreshed = self._anchor_repository.refresh_head_anchor_snapshot(snapshot)
        self._snapshot = refreshed
        return refreshed

    def _prepare_recovery(
        self,
        *,
        full_audit: bool,
    ) -> PreparedTrustedTimeHeadAnchorReconciliation:
        snapshot = self._require_snapshot()
        if not snapshot.complete_replay:
            snapshot = self._replace_with_full_snapshot()
        pending = snapshot.pending_intent
        evidence = snapshot.committed_pending_evidence
        if pending is None or evidence is None:
            raise TrustedTimeHeadAnchorFatalFailure(
                "trusted-time anchor pending recovery evidence is incomplete"
            )
        pending_ordinal = snapshot.pending_intent_local_transition_ordinal
        if pending_ordinal is None:
            raise TrustedTimeHeadAnchorFatalFailure(
                "trusted-time anchor pending recovery ordinal is incomplete"
            )
        return prepare_bounded_persisted_trusted_time_head_anchor_intent_recovery(
            snapshot.authenticated_journal_tip,
            pending_record=pending.record,
            pending_local_transition_ordinal=pending_ordinal,
            committed_intent=evidence,
            provider=self._provider,
            verifier=self._verifier,
            signing_key_id=self._authority.signing_key_id,
            signing_public_key_sha256=self._authority.signing_public_key_sha256,
            full_audit=full_audit,
        )

    def _complete_pending(
        self,
        prepared: PreparedTrustedTimeHeadAnchorReconciliation,
    ) -> tuple[
        TrustedTimeHeadAnchorReconciliationResult,
        PersistedTrustedTimeHeadAnchorReceipt,
    ]:
        snapshot = self._require_snapshot()
        intent = snapshot.pending_intent
        evidence = snapshot.committed_pending_evidence
        if intent is None or evidence is None or prepared.candidate_record != intent.record:
            raise TrustedTimeHeadAnchorFatalFailure(
                "trusted-time anchor pending completion conflicts"
            )
        result = complete_trusted_time_head_anchor_reconciliation(
            prepared,
            provider=self._provider,
            committed_intent=evidence,
        )
        provider_readback = verify_trusted_time_head_anchor_provider_readback(
            provider=self._provider,
            verifier=self._verifier,
            anchor_intent_id=intent.anchor_intent_id,
            anchor_intent_semantic_sha256=intent.semantic_sha256,
            record=intent.record,
            object_name=intent.object_name,
        )
        confirmed, receipt = self._anchor_repository.confirm_remote_readback_from_snapshot(
            snapshot,
            intent=intent,
            provider_readback=provider_readback,
            observed_at_utc=self._now(),
        )
        self._snapshot = confirmed
        self._compact_snapshot()
        return result, receipt

    def _prepare_current(
        self,
        *,
        checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason,
        full_audit: bool,
        allow_enrollment: bool,
    ) -> PreparedTrustedTimeHeadAnchorReconciliation:
        authority = self._authority
        if full_audit:
            snapshot = self._require_snapshot()
            if not snapshot.complete_replay:
                snapshot = self._replace_with_full_snapshot()
            return prepare_bounded_trusted_time_head_anchor_reconciliation(
                snapshot.authenticated_journal_tip,
                provider=self._provider,
                signer=self._signer,
                verifier=self._verifier,
                signing_key_id=authority.signing_key_id,
                signing_public_key_sha256=authority.signing_public_key_sha256,
                checkpoint_reason=checkpoint_reason,
                checkpoint_interval_seconds=(TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS),
                anchor_authority_sha256=authority.anchor_authority_sha256,
                pending_anchor_intent=None,
                allow_enrollment=allow_enrollment,
            )
        snapshot = self._refresh_snapshot()
        return prepare_incremental_trusted_time_head_anchor_reconciliation(
            snapshot.authenticated_journal_tip,
            provider=self._provider,
            signer=self._signer,
            verifier=self._verifier,
            signing_key_id=authority.signing_key_id,
            signing_public_key_sha256=authority.signing_public_key_sha256,
            checkpoint_reason=checkpoint_reason,
            checkpoint_interval_seconds=(TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS),
            anchor_authority_sha256=authority.anchor_authority_sha256,
            pending_anchor_intent=None,
        )

    def _complete_current(
        self,
        prepared: PreparedTrustedTimeHeadAnchorReconciliation,
        *,
        allow_enrollment: bool,
    ) -> tuple[
        TrustedTimeHeadAnchorReconciliationResult,
        PersistedTrustedTimeHeadAnchorReceipt | None,
    ]:
        candidate = prepared.candidate_record
        if candidate is None:
            result = complete_trusted_time_head_anchor_reconciliation(
                prepared,
                provider=self._provider,
                committed_intent=None,
            )
            self._compact_snapshot()
            return result, None

        snapshot, evidence = self._anchor_repository.commit_prepared_intent(
            self._require_snapshot(),
            prepared=prepared,
            created_at_utc=self._now(),
            allow_enrollment=allow_enrollment,
        )
        self._snapshot = snapshot
        if snapshot.committed_pending_evidence != evidence:
            raise TrustedTimeHeadAnchorFatalFailure(
                "trusted-time anchor committed intent readback conflicts"
            )
        # From this line onward the exact intent is durable.  Any interruption
        # leaves it discoverable and forces recovery before a successor.
        return self._complete_pending(prepared)

    def _adopt_snapshot_advance(
        self,
        error: TrustedTimeHeadAnchorSnapshotAdvanced,
    ) -> None:
        refreshed = error.refreshed_snapshot
        if refreshed is not None:
            if type(refreshed) is not TrustedTimeHeadAnchorPersistenceSnapshot:
                raise TrustedTimeHeadAnchorFatalFailure(
                    "trusted-time anchor advanced snapshot is invalid"
                )
            self._snapshot = refreshed
            self._compact_snapshot()
            return
        # A prepare/commit race does not consume the original cursor.  Refresh
        # and authenticate the winning local suffix before the bounded retry.
        self._refresh_snapshot()
        self._compact_snapshot()

    def _run(
        self,
        request: TrustedTimeHeadAnchorWorkRequest,
    ) -> TrustedTimeHeadAnchorAttemptResult:
        snapshot = self._require_snapshot()
        recovered = False
        full_audit_completed = False
        receipt: PersistedTrustedTimeHeadAnchorReceipt | None = None
        result: TrustedTimeHeadAnchorReconciliationResult | None = None

        if snapshot.pending_intent is not None:
            recovery = self._prepare_recovery(full_audit=request.full_audit)
            result, receipt = self._complete_pending(recovery)
            recovered = True
            full_audit_completed = request.full_audit

        # A recovered enrollment is already sequence one.  If the newly
        # registered epoch advanced the local head, its successor truthfully
        # records an epoch rotation and never reopens enrollment.
        current_reason = request.checkpoint_reason
        if recovered and current_reason is TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT:
            current_reason = TrustedTimeHeadAnchorCheckpointReason.EPOCH_ROTATION

        prepared = self._prepare_current(
            checkpoint_reason=current_reason,
            full_audit=(request.full_audit and not full_audit_completed),
            allow_enrollment=request.allow_enrollment and not recovered,
        )
        current_result, current_receipt = self._complete_current(
            prepared,
            allow_enrollment=request.allow_enrollment and not recovered,
        )
        result = current_result
        if current_receipt is not None:
            receipt = current_receipt
        full_audit_completed = full_audit_completed or prepared.full_audit
        if request.full_audit and not full_audit_completed:
            raise TrustedTimeHeadAnchorFatalFailure(
                "trusted-time anchor full audit was not completed"
            )

        return TrustedTimeHeadAnchorAttemptResult(
            request_sequence=request.request_sequence,
            checkpoint_reason=request.checkpoint_reason,
            current_host_head_sha256=result.current_host_head_sha256,
            current_anchor_sha256=result.current_anchor_sha256,
            current_anchor_semantic_sha256=(result.current_anchor_semantic_sha256),
            completed_at_utc=self._now(),
            full_audit_completed=full_audit_completed,
            pending_intent_recovered=recovered,
            candidate_remote_readback_sha256=(
                None if receipt is None else receipt.readback_bytes_sha256
            ),
            receipt_semantic_sha256=(None if receipt is None else receipt.semantic_sha256),
        )

    @staticmethod
    def _validate_first_enrollment_pending(
        snapshot: TrustedTimeHeadAnchorPersistenceSnapshot,
    ) -> None:
        pending = snapshot.pending_intent
        if pending is None or snapshot.confirmed_anchor_count != 0:
            raise TrustedTimeHeadAnchorFirstEnrollmentStateConflict(
                "trusted-time first enrollment pending state is absent"
            )
        try:
            pending.__post_init__()
        except Exception:
            raise TrustedTimeHeadAnchorFirstEnrollmentStateConflict(
                "trusted-time first enrollment pending state is invalid"
            ) from None
        if (
            pending.record.anchor_sequence != 1
            or pending.record.checkpoint_reason
            is not TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT
        ):
            raise TrustedTimeHeadAnchorFirstEnrollmentStateConflict(
                "trusted-time first enrollment pending state conflicts"
            )

    @staticmethod
    def _first_enrollment_result(
        *,
        receipt: PersistedTrustedTimeHeadAnchorReceipt,
        reconciliation: TrustedTimeHeadAnchorReconciliationResult | None,
        disposition: TrustedTimeHeadAnchorFirstEnrollmentDisposition,
    ) -> TrustedTimeHeadAnchorFirstEnrollmentResult:
        try:
            receipt.__post_init__()
            record = receipt.intent.record
            if reconciliation is not None:
                reconciliation.__post_init__()
                if (
                    reconciliation.current_host_head_sha256 != record.current_host_head_sha256
                    or reconciliation.current_anchor_sha256 != record.byte_sha256
                    or reconciliation.current_anchor_semantic_sha256 != record.semantic_sha256
                ):
                    raise TrustedTimeHeadAnchorFirstEnrollmentStateConflict(
                        "trusted-time first enrollment result conflicts with its receipt"
                    )
            return TrustedTimeHeadAnchorFirstEnrollmentResult(
                anchor_sequence=record.anchor_sequence,
                checkpoint_reason=record.checkpoint_reason,
                current_host_head_sha256=record.current_host_head_sha256,
                current_anchor_sha256=record.byte_sha256,
                current_anchor_semantic_sha256=record.semantic_sha256,
                completed_at_utc=receipt.observed_at_utc,
                full_audit_completed=True,
                completion_disposition=disposition,
                uploaded_anchor_count=(
                    None if reconciliation is None else reconciliation.uploaded_anchor_count
                ),
                idempotent_duplicate_count=(
                    None if reconciliation is None else reconciliation.idempotent_duplicate_count
                ),
                anchor_intent_semantic_sha256=receipt.intent.semantic_sha256,
                candidate_remote_readback_sha256=receipt.readback_bytes_sha256,
                receipt_semantic_sha256=receipt.semantic_sha256,
            )
        except TrustedTimeHeadAnchorFirstEnrollmentStateConflict:
            raise
        except Exception:
            raise TrustedTimeHeadAnchorFirstEnrollmentStateConflict(
                "trusted-time first enrollment result is invalid"
            ) from None

    def _complete_first_enrollment_pending(
        self,
        prepared: PreparedTrustedTimeHeadAnchorReconciliation,
        *,
        disposition: TrustedTimeHeadAnchorFirstEnrollmentDisposition,
    ) -> TrustedTimeHeadAnchorFirstEnrollmentResult:
        snapshot = self._require_snapshot()
        intent = snapshot.pending_intent
        evidence = snapshot.committed_pending_evidence
        if intent is None or evidence is None or prepared.candidate_record != intent.record:
            raise TrustedTimeHeadAnchorFirstEnrollmentRecoveryRequired(
                "trusted-time first enrollment pending completion conflicts"
            )
        result = complete_trusted_time_head_anchor_reconciliation(
            prepared,
            provider=self._provider,
            committed_intent=evidence,
        )
        provider_readback = verify_trusted_time_head_anchor_provider_readback(
            provider=self._provider,
            verifier=self._verifier,
            anchor_intent_id=intent.anchor_intent_id,
            anchor_intent_semantic_sha256=intent.semantic_sha256,
            record=intent.record,
            object_name=intent.object_name,
        )
        confirmed, receipt = self._anchor_repository.confirm_remote_readback_from_snapshot(
            snapshot,
            intent=intent,
            provider_readback=provider_readback,
            observed_at_utc=self._now(),
        )
        self._snapshot = confirmed
        enrollment_result: TrustedTimeHeadAnchorFirstEnrollmentResult | None = None
        try:
            enrollment_result = self._first_enrollment_result(
                receipt=receipt,
                reconciliation=result,
                disposition=disposition,
            )
            if confirmed.confirmed_anchor_count != 1 or confirmed.pending_intent is not None:
                raise TrustedTimeHeadAnchorFirstEnrollmentStateConflict(
                    "trusted-time first enrollment durable confirmation conflicts"
                )
            self._compact_snapshot()
            compact = self._require_snapshot()
            if (
                compact.confirmed_anchor_count != 1
                or compact.pending_intent is not None
                or compact.confirmed_anchor_receipt != receipt
            ):
                raise TrustedTimeHeadAnchorFirstEnrollmentStateConflict(
                    "trusted-time first enrollment compact confirmation conflicts"
                )
        except Exception:
            raise TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed(
                enrollment_result
            ) from None
        return enrollment_result

    def _run_new_first_enrollment(self) -> TrustedTimeHeadAnchorFirstEnrollmentResult:
        snapshot = self._require_snapshot()
        if snapshot.confirmed_anchor_count != 0:
            raise TrustedTimeHeadAnchorFirstEnrollmentAlreadyCompleted(
                "trusted-time first enrollment is already complete"
            )
        if snapshot.pending_intent is not None:
            raise TrustedTimeHeadAnchorFirstEnrollmentRecoveryRequired(
                "trusted-time first enrollment has a durable pending intent"
            )
        prepared = self._prepare_current(
            checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT,
            full_audit=True,
            allow_enrollment=True,
        )
        candidate = prepared.candidate_record
        if (
            prepared.full_audit is not True
            or candidate is None
            or candidate.anchor_sequence != 1
            or candidate.checkpoint_reason is not TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT
        ):
            raise TrustedTimeHeadAnchorFirstEnrollmentStateConflict(
                "trusted-time first enrollment candidate is invalid"
            )
        try:
            pending, evidence = self._anchor_repository.commit_prepared_intent(
                self._require_snapshot(),
                prepared=prepared,
                created_at_utc=self._now(),
                allow_enrollment=True,
            )
            self._snapshot = pending
            if pending.committed_pending_evidence != evidence:
                raise TrustedTimeHeadAnchorFirstEnrollmentStateConflict(
                    "trusted-time first enrollment committed intent conflicts"
                )
        except TrustedTimeHeadAnchorSnapshotAdvanced:
            raise
        except Exception:
            raise TrustedTimeHeadAnchorFirstEnrollmentRecoveryRequired(
                "trusted-time first enrollment intent outcome is unconfirmed"
            ) from None
        try:
            return self._complete_first_enrollment_pending(
                prepared,
                disposition=(TrustedTimeHeadAnchorFirstEnrollmentDisposition.NEW_INTENT_COMPLETED),
            )
        except TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed:
            raise
        except Exception:
            raise TrustedTimeHeadAnchorFirstEnrollmentRecoveryRequired(
                "trusted-time first enrollment remote outcome is unconfirmed"
            ) from None

    def perform_first_enrollment(self) -> TrustedTimeHeadAnchorFirstEnrollmentResult:
        """Create sequence one once; an existing pending intent always needs recovery."""

        try:
            return self._run_new_first_enrollment()
        except TrustedTimeHeadAnchorSnapshotAdvanced as error:
            try:
                self._adopt_snapshot_advance(error)
            except Exception:
                raise TrustedTimeHeadAnchorFatalFailure(
                    "trusted-time anchor advanced snapshot recovery failed"
                ) from None
            raise TrustedTimeHeadAnchorFirstEnrollmentStateConflict(
                "trusted-time anchor local head advanced before enrollment commit"
            ) from None
        except TrustedTimeHeadAnchorProviderUnavailable:
            try:
                self._compact_snapshot()
            except Exception:
                raise TrustedTimeHeadAnchorFatalFailure(
                    "trusted-time anchor provider failure cleanup failed"
                ) from None
            raise TrustedTimeHeadAnchorTransientFailure(
                "trusted-time anchor provider is unavailable before enrollment commit"
            ) from None
        except TrustedTimeHeadAnchorEnrollmentNotApproved:
            raise TrustedTimeHeadAnchorFirstEnrollmentStateConflict(
                "trusted-time first enrollment permission was not applied"
            ) from None
        except TrustedTimeHeadAnchorConflict:
            raise TrustedTimeHeadAnchorFirstEnrollmentStateConflict(
                "trusted-time first enrollment pre-commit state conflicts"
            ) from None
        except (TrustedTimeHeadAnchorFatalFailure, TrustedTimeHeadAnchorTransientFailure):
            raise
        except Exception:
            raise TrustedTimeHeadAnchorFatalFailure(
                "trusted-time first enrollment reconciliation failed"
            ) from None

    def recover_first_enrollment(self) -> TrustedTimeHeadAnchorFirstEnrollmentResult:
        """Recover only a separately approved sequence-one pending/confirmed outcome."""

        snapshot = self._require_snapshot()
        if snapshot.confirmed_anchor_count == 1 and snapshot.pending_intent is None:
            receipt = snapshot.confirmed_anchor_receipt
            if receipt is None:
                raise TrustedTimeHeadAnchorFirstEnrollmentStateConflict(
                    "trusted-time first enrollment confirmed receipt is absent"
                )
            return self._first_enrollment_result(
                receipt=receipt,
                reconciliation=None,
                disposition=(
                    TrustedTimeHeadAnchorFirstEnrollmentDisposition.CONFIRMED_RECEIPT_REOBSERVED
                ),
            )
        self._validate_first_enrollment_pending(snapshot)
        try:
            prepared = self._prepare_recovery(full_audit=True)
            if prepared.full_audit is not True:
                raise TrustedTimeHeadAnchorFirstEnrollmentStateConflict(
                    "trusted-time first enrollment recovery omitted its full audit"
                )
            return self._complete_first_enrollment_pending(
                prepared,
                disposition=(
                    TrustedTimeHeadAnchorFirstEnrollmentDisposition.PENDING_INTENT_RECOVERED
                ),
            )
        except TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed:
            raise
        except Exception:
            raise TrustedTimeHeadAnchorFirstEnrollmentRecoveryRequired(
                "trusted-time first enrollment recovery outcome is unconfirmed"
            ) from None

    def reauthenticate_first_enrollment_postcondition(
        self,
    ) -> TrustedTimeHeadAnchorFirstEnrollmentPostcondition:
        """Reauthenticate exact local and remote sequence one without mutation."""

        prior = self._require_snapshot()
        prior_receipt = prior.confirmed_anchor_receipt
        if prior_receipt is None:
            raise TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed(None)
        prior_evidence = self._first_enrollment_result(
            receipt=prior_receipt,
            reconciliation=None,
            disposition=(
                TrustedTimeHeadAnchorFirstEnrollmentDisposition.CONFIRMED_RECEIPT_REOBSERVED
            ),
        )
        try:
            snapshot = self._replace_with_full_snapshot()
        except Exception:
            raise TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed(
                prior_evidence
            ) from None
        receipt = snapshot.confirmed_anchor_receipt
        tip = snapshot.authenticated_journal_tip
        terminal_ordinal = getattr(tip, "confirmed_anchor_local_transition_ordinal", None)
        if (
            snapshot.complete_replay is not True
            or type(snapshot.confirmed_anchor_count) is not int
            or snapshot.confirmed_anchor_count != 1
            or snapshot.pending_intent is not None
            or receipt is None
            or receipt != prior_receipt
            or type(snapshot.local_transition_count) is not int
            or snapshot.local_transition_count < 1
            or type(terminal_ordinal) is not int
            or terminal_ordinal != snapshot.local_transition_count
        ):
            raise TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed(
                prior_evidence
            )
        fresh_evidence = self._first_enrollment_result(
            receipt=receipt,
            reconciliation=None,
            disposition=(
                TrustedTimeHeadAnchorFirstEnrollmentDisposition.CONFIRMED_RECEIPT_REOBSERVED
            ),
        )
        if snapshot.current_host_head_sha256 != fresh_evidence.current_host_head_sha256:
            raise TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed(
                prior_evidence
            )
        authority = self._authority
        try:
            namespace_sha256 = verify_bounded_first_enrollment_remote_postcondition(
                snapshot.authenticated_journal_tip,
                provider=self._provider,
                verifier=self._verifier,
                signing_key_id=authority.signing_key_id,
                signing_public_key_sha256=authority.signing_public_key_sha256,
                checkpoint_interval_seconds=(TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS),
                anchor_authority_sha256=authority.anchor_authority_sha256,
            )
        except Exception:
            raise TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed(
                prior_evidence
            ) from None
        try:
            final_snapshot = self._replace_with_full_snapshot()
        except Exception:
            raise TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed(
                prior_evidence
            ) from None
        final_receipt = final_snapshot.confirmed_anchor_receipt
        final_tip = final_snapshot.authenticated_journal_tip
        final_terminal_ordinal = getattr(
            final_tip,
            "confirmed_anchor_local_transition_ordinal",
            None,
        )
        if (
            final_snapshot.complete_replay is not True
            or type(final_snapshot.confirmed_anchor_count) is not int
            or final_snapshot.confirmed_anchor_count != 1
            or final_snapshot.pending_intent is not None
            or final_receipt is None
            or final_receipt != receipt
            or final_tip != tip
            or final_snapshot.current_host_head_sha256 != snapshot.current_host_head_sha256
            or type(final_snapshot.local_transition_count) is not int
            or final_snapshot.local_transition_count != snapshot.local_transition_count
            or type(final_terminal_ordinal) is not int
            or final_terminal_ordinal != final_snapshot.local_transition_count
        ):
            raise TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed(
                prior_evidence
            )
        try:
            return TrustedTimeHeadAnchorFirstEnrollmentPostcondition(
                anchor_sequence=fresh_evidence.anchor_sequence,
                checkpoint_reason=fresh_evidence.checkpoint_reason,
                confirmed_anchor_count=final_snapshot.confirmed_anchor_count,
                local_transition_count=final_snapshot.local_transition_count,
                confirmed_anchor_local_transition_ordinal=final_terminal_ordinal,
                remote_object_count=1,
                current_host_head_sha256=fresh_evidence.current_host_head_sha256,
                current_anchor_sha256=fresh_evidence.current_anchor_sha256,
                current_anchor_semantic_sha256=(fresh_evidence.current_anchor_semantic_sha256),
                anchor_intent_semantic_sha256=(fresh_evidence.anchor_intent_semantic_sha256),
                candidate_remote_readback_sha256=(fresh_evidence.candidate_remote_readback_sha256),
                receipt_semantic_sha256=fresh_evidence.receipt_semantic_sha256,
                remote_namespace_sha256=namespace_sha256,
                anchor_authority_sha256=authority.anchor_authority_sha256,
                deployment_identity_sha256=authority.deployment_identity_sha256,
                runtime_database_identity_sha256=(authority.runtime_database_identity_sha256),
                anchor_project_identity_sha256=authority.anchor_project_identity_sha256,
                source_authority_sha256=authority.source_authority_sha256,
                signing_public_key_sha256=authority.signing_public_key_sha256,
                host_identity_sha256=trusted_time_first_enrollment_identity_sha256(
                    kind="host",
                    value=authority.host_id,
                ),
                principal_identity_sha256=trusted_time_first_enrollment_identity_sha256(
                    kind="principal",
                    value=authority.principal_id,
                ),
                bucket_identity_sha256=trusted_time_first_enrollment_identity_sha256(
                    kind="bucket",
                    value=authority.bucket_name,
                ),
                full_audit_completed=True,
                pending_intent_present=False,
            )
        except Exception:
            raise TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed(
                prior_evidence
            ) from None

    @staticmethod
    def _require_post_enrollment_start_terminal(
        snapshot: TrustedTimeHeadAnchorPersistenceSnapshot,
    ) -> tuple[
        PersistedTrustedTimeHeadAnchorReceipt,
        TrustedTimeHeadAnchorRecord,
        int,
    ]:
        receipt = snapshot.confirmed_anchor_receipt
        tip = snapshot.authenticated_journal_tip
        terminal_ordinal = getattr(
            tip,
            "confirmed_anchor_local_transition_ordinal",
            None,
        )
        if (
            snapshot.complete_replay is not True
            or type(snapshot.confirmed_anchor_count) is not int
            or snapshot.confirmed_anchor_count != 2
            or snapshot.pending_intent is not None
            or receipt is None
            or type(snapshot.local_transition_count) is not int
            or snapshot.local_transition_count < 2
            or type(terminal_ordinal) is not int
            or terminal_ordinal < 2
            or terminal_ordinal > snapshot.local_transition_count
            or getattr(tip, "confirmed_anchor_count", None) != 2
            or getattr(tip, "confirmed_anchor_tip", None) != receipt.intent.record
            or getattr(tip, "local_transition_count", None) != snapshot.local_transition_count
            or getattr(tip, "current_local_host_head_sha256", None)
            != snapshot.current_host_head_sha256
        ):
            raise TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed()
        try:
            receipt.__post_init__()
            record = receipt.intent.record
            record.__post_init__()
        except Exception:
            raise TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed() from None
        if (
            record.anchor_sequence != 2
            or record.checkpoint_reason is not TrustedTimeHeadAnchorCheckpointReason.EPOCH_ROTATION
        ):
            raise TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed()
        return receipt, record, terminal_ordinal

    @staticmethod
    def _require_post_enrollment_start_probe_suffix(
        snapshot: TrustedTimeHeadAnchorPersistenceSnapshot,
        *,
        record: TrustedTimeHeadAnchorRecord,
        terminal_ordinal: int,
    ) -> None:
        """Require every local transition after sequence two to be a same-epoch probe."""

        transition = getattr(snapshot.authenticated_journal_tip, "current_transition", None)
        suffix_count = snapshot.local_transition_count - terminal_ordinal
        transition_evaluation_sequence = getattr(transition, "evaluation_sequence", None)
        record_epoch = (
            record.source_id,
            record.source_authority_sha256,
            record.policy_sha256,
            record.persistence_contract_version,
            record.epoch_sequence,
            record.monitor_epoch_id,
            record.epoch_sha256,
        )
        transition_epoch = tuple(
            getattr(transition, field_name, None)
            for field_name in (
                "source_id",
                "source_authority_sha256",
                "policy_sha256",
                "persistence_contract_version",
                "epoch_sequence",
                "monitor_epoch_id",
                "epoch_sha256",
            )
        )
        if (
            suffix_count < 0
            or transition_epoch != record_epoch
            or type(transition_evaluation_sequence) is not int
            or transition_evaluation_sequence != record.evaluation_sequence + suffix_count
        ):
            raise TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed()

    def reauthenticate_post_enrollment_start_successor(
        self,
    ) -> TrustedTimeHeadAnchorPostEnrollmentStartPostcondition:
        """Observe an exact sequence-two successor without signing or uploading."""

        try:
            self._require_snapshot()
            snapshot = self._replace_with_full_snapshot()
            receipt, record, terminal_ordinal = self._require_post_enrollment_start_terminal(
                snapshot
            )
            self._require_post_enrollment_start_probe_suffix(
                snapshot,
                record=record,
                terminal_ordinal=terminal_ordinal,
            )
            authority = self._authority
            if (
                record.anchor_authority_sha256 != authority.anchor_authority_sha256
                or record.deployment_identity_sha256 != authority.deployment_identity_sha256
                or record.runtime_database_identity_sha256
                != authority.runtime_database_identity_sha256
                or record.anchor_project_identity_sha256 != authority.anchor_project_identity_sha256
                or record.anchor_project_ref != authority.anchor_project_ref
                or record.source_authority_sha256 != authority.source_authority_sha256
                or record.signing_key_id != authority.signing_key_id
                or record.signing_public_key_sha256 != authority.signing_public_key_sha256
                or record.host_id != authority.host_id
                or record.principal_id != authority.principal_id
                or record.bucket_name != authority.bucket_name
                or record.checkpoint_interval_seconds
                != TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
            ):
                raise TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed()
            predecessor_anchor_sha256 = record.previous_anchor_sha256
            if type(predecessor_anchor_sha256) is not str:
                raise TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed()
            initial_local_transition_count = snapshot.local_transition_count
            initial_local_host_head_sha256 = snapshot.current_host_head_sha256
            namespace_sha256 = verify_bounded_post_enrollment_start_remote_postcondition(
                snapshot.authenticated_journal_tip,
                provider=self._provider,
                verifier=self._verifier,
                signing_key_id=authority.signing_key_id,
                signing_public_key_sha256=authority.signing_public_key_sha256,
                checkpoint_interval_seconds=(TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS),
                anchor_authority_sha256=authority.anchor_authority_sha256,
            )
            final_snapshot = self._replace_with_full_snapshot()
            final_receipt, final_record, final_terminal_ordinal = (
                self._require_post_enrollment_start_terminal(final_snapshot)
            )
            self._require_post_enrollment_start_probe_suffix(
                final_snapshot,
                record=final_record,
                terminal_ordinal=final_terminal_ordinal,
            )
            if (
                final_receipt != receipt
                or final_receipt.intent != receipt.intent
                or final_record != record
                or final_terminal_ordinal != terminal_ordinal
                or final_snapshot.local_transition_count < initial_local_transition_count
                or (
                    final_snapshot.local_transition_count == initial_local_transition_count
                    and final_snapshot.current_host_head_sha256 != initial_local_host_head_sha256
                )
            ):
                raise TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed()
            return TrustedTimeHeadAnchorPostEnrollmentStartPostcondition(
                anchor_sequence=record.anchor_sequence,
                checkpoint_reason=record.checkpoint_reason,
                confirmed_anchor_count=final_snapshot.confirmed_anchor_count,
                local_transition_count=final_snapshot.local_transition_count,
                confirmed_anchor_local_transition_ordinal=final_terminal_ordinal,
                remote_object_count=2,
                predecessor_anchor_sha256=predecessor_anchor_sha256,
                current_host_head_sha256=record.current_host_head_sha256,
                current_anchor_sha256=record.byte_sha256,
                current_anchor_semantic_sha256=record.semantic_sha256,
                anchor_intent_semantic_sha256=receipt.intent.semantic_sha256,
                candidate_remote_readback_sha256=receipt.readback_bytes_sha256,
                receipt_semantic_sha256=receipt.semantic_sha256,
                remote_namespace_sha256=namespace_sha256,
                anchor_authority_sha256=authority.anchor_authority_sha256,
                deployment_identity_sha256=authority.deployment_identity_sha256,
                runtime_database_identity_sha256=(authority.runtime_database_identity_sha256),
                anchor_project_identity_sha256=(authority.anchor_project_identity_sha256),
                source_authority_sha256=authority.source_authority_sha256,
                signing_public_key_sha256=authority.signing_public_key_sha256,
                host_identity_sha256=trusted_time_first_enrollment_identity_sha256(
                    kind="host",
                    value=authority.host_id,
                ),
                principal_identity_sha256=trusted_time_first_enrollment_identity_sha256(
                    kind="principal",
                    value=authority.principal_id,
                ),
                bucket_identity_sha256=trusted_time_first_enrollment_identity_sha256(
                    kind="bucket",
                    value=authority.bucket_name,
                ),
                full_audit_completed=True,
                pending_intent_present=False,
            )
        except TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed:
            raise
        except Exception:
            raise TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed() from None

    def verify_first_enrollment_remote_postcondition(self) -> str:
        """Compatibility wrapper for the exact read-only sequence-one proof."""

        return self.reauthenticate_first_enrollment_postcondition().remote_namespace_sha256

    def __call__(
        self,
        request: TrustedTimeHeadAnchorWorkRequest,
    ) -> TrustedTimeHeadAnchorAttemptResult:
        if type(request) is not TrustedTimeHeadAnchorWorkRequest:
            raise TrustedTimeHeadAnchorFatalFailure("trusted-time anchor work request is invalid")
        try:
            request.__post_init__()
            return self._run(request)
        except TrustedTimeHeadAnchorSnapshotAdvanced as error:
            try:
                self._adopt_snapshot_advance(error)
            except Exception:
                raise TrustedTimeHeadAnchorFatalFailure(
                    "trusted-time anchor advanced snapshot recovery failed"
                ) from None
            raise TrustedTimeHeadAnchorTransientFailure(
                "trusted-time anchor local head advanced"
            ) from None
        except TrustedTimeHeadAnchorProviderUnavailable:
            try:
                self._compact_snapshot()
            except Exception:
                raise TrustedTimeHeadAnchorFatalFailure(
                    "trusted-time anchor provider failure cleanup failed"
                ) from None
            raise TrustedTimeHeadAnchorTransientFailure(
                "trusted-time anchor provider is unavailable"
            ) from None
        except TrustedTimeHeadAnchorEnrollmentNotApproved:
            raise TrustedTimeHeadAnchorEnrollmentNotApprovedFailure(
                "trusted-time remote anchor history is absent and enrollment is not approved"
            ) from None
        except (TrustedTimeHeadAnchorFatalFailure, TrustedTimeHeadAnchorTransientFailure):
            raise
        except Exception:
            raise TrustedTimeHeadAnchorFatalFailure(
                "trusted-time anchor reconciliation failed"
            ) from None

    def close(self) -> None:
        """Release the repository-issued cursor after the worker has joined."""

        if self._closed:
            return
        snapshot = self._snapshot
        if snapshot is not None:
            self._anchor_repository.discard_head_anchor_snapshot(snapshot)
            self._snapshot = None
        self._closed = True

    operational_control_authorized = property(_authority_is_never_granted)
    readiness_authorized = property(_authority_is_never_granted)
    arming_authorized = property(_authority_is_never_granted)
    new_exposure_authorized = property(_authority_is_never_granted)
    broker_action_authorized = property(_authority_is_never_granted)
    automatic_rearm_authorized = property(_authority_is_never_granted)
    rearm_authorized = property(_authority_is_never_granted)
    automatic_resume_authorized = property(_authority_is_never_granted)
    alert_delivery_authorized = property(_authority_is_never_granted)
    exposure_authorized = property(_authority_is_never_granted)
    paper_trading_authorized = property(_authority_is_never_granted)
    live_trading_authorized = property(_authority_is_never_granted)


__all__ = [
    "TRUSTED_TIME_HEAD_ANCHOR_ATTEMPT_CONTRACT_VERSION",
    "RepositoryBackedTrustedTimeHeadAnchorAttempt",
    "TrustedTimeHeadAnchorFirstEnrollmentAlreadyCompleted",
    "TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed",
    "TrustedTimeHeadAnchorFirstEnrollmentDisposition",
    "TrustedTimeHeadAnchorFirstEnrollmentPostcondition",
    "TrustedTimeHeadAnchorFirstEnrollmentRecoveryRequired",
    "TrustedTimeHeadAnchorFirstEnrollmentResult",
    "TrustedTimeHeadAnchorFirstEnrollmentStateConflict",
    "TrustedTimeHeadAnchorPostEnrollmentStartPostcondition",
    "TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed",
]
