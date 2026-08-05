"""Repository-backed composition for one trusted-head anchor work request.

The composition keeps remote I/O outside SQL transactions, durably commits an
exact signed-object intent before any upload, and writes a receipt only after a
second byte-exact provider readback.  It is evidence only and grants no runtime
or trading authority.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime

from apps.trusted_time_supervisor.head_anchor_config import (
    TrustedTimeHeadAnchorAuthority,
)
from packages.application.trusted_time_head_anchor import (
    TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
    PreparedTrustedTimeHeadAnchorReconciliation,
    TrustedTimeHeadAnchorCheckpointReason,
    TrustedTimeHeadAnchorEd25519Signer,
    TrustedTimeHeadAnchorEd25519Verifier,
    TrustedTimeHeadAnchorEnrollmentNotApproved,
    TrustedTimeHeadAnchorProvider,
    TrustedTimeHeadAnchorProviderUnavailable,
    TrustedTimeHeadAnchorReconciliationResult,
    complete_trusted_time_head_anchor_reconciliation,
    prepare_bounded_persisted_trusted_time_head_anchor_intent_recovery,
    prepare_bounded_trusted_time_head_anchor_reconciliation,
    prepare_incremental_trusted_time_head_anchor_reconciliation,
    verify_trusted_time_head_anchor_provider_readback,
)
from packages.application.trusted_time_head_anchor_worker import (
    TrustedTimeHeadAnchorAttemptResult,
    TrustedTimeHeadAnchorEnrollmentNotApprovedFailure,
    TrustedTimeHeadAnchorFatalFailure,
    TrustedTimeHeadAnchorTransientFailure,
    TrustedTimeHeadAnchorWorkRequest,
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
]
