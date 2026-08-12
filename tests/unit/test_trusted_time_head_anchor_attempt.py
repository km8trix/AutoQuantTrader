from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

import pytest

from apps.trusted_time_supervisor.head_anchor_attempt import (
    DeadlineBoundTrustedTimeHeadAnchorProvider,
    RepositoryBackedTrustedTimeHeadAnchorAttempt,
    TrustedTimeHeadAnchorFirstEnrollmentAlreadyCompleted,
    TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed,
    TrustedTimeHeadAnchorFirstEnrollmentPostcondition,
    TrustedTimeHeadAnchorFirstEnrollmentRecoveryRequired,
    TrustedTimeHeadAnchorFirstEnrollmentStateConflict,
    TrustedTimeHeadAnchorPostEnrollmentStartPostcondition,
    TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed,
    TrustedTimeHeadAnchorStartupEffectDeadlineExceeded,
    TrustedTimeHeadAnchorStartupEffectDeadlineGuard,
)
from apps.trusted_time_supervisor.head_anchor_config import (
    TrustedTimeHeadAnchorAuthority,
)
from packages.application.trusted_time_head_anchor import (
    TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
    TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
    TrustedTimeHeadAnchorCheckpointReason,
    TrustedTimeHeadAnchorConflict,
    TrustedTimeHeadAnchorEnrollmentNotApproved,
    TrustedTimeHeadAnchorProviderUnavailable,
)
from packages.application.trusted_time_head_anchor_worker import (
    TrustedTimeHeadAnchorEnrollmentNotApprovedFailure,
    TrustedTimeHeadAnchorFatalFailure,
    TrustedTimeHeadAnchorTransientFailure,
    TrustedTimeHeadAnchorWorkRequest,
)
from packages.domain.trusted_time_enrollment_evidence import (
    trusted_time_first_enrollment_identity_sha256,
)
from packages.persistence.trusted_time import SqlTrustedTimeRepository
from packages.persistence.trusted_time_head_anchor import (
    SqlTrustedTimeHeadAnchorRepository,
    TrustedTimeHeadAnchorPersistenceConflict,
    TrustedTimeHeadAnchorPersistenceSnapshot,
    TrustedTimeHeadAnchorSnapshotAdvanced,
)

BASE = datetime(2026, 8, 1, 16, 0, tzinfo=UTC)
PUBLIC_KEY = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")


class _MonotonicClock:
    def __init__(self, value: int = 0) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


def _authority() -> TrustedTimeHeadAnchorAuthority:
    return TrustedTimeHeadAnchorAuthority(
        anchor_authority_sha256="a" * 64,
        deployment_identity_sha256="b" * 64,
        host_id="local-paper-docker-primary-v1",
        source_authority_sha256="c" * 64,
        runtime_database_project_ref="abcdefghijklmnopqrst",
        runtime_database_identity_sha256="d" * 64,
        anchor_project_ref="bcdefghijklmnopqrstu",
        anchor_project_url="https://bcdefghijklmnopqrstu.supabase.co",
        anchor_project_identity_sha256="e" * 64,
        bucket_name=TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
        principal_id="12345678-1234-4234-9234-123456789abc",
        signing_key_id="trusted-time-anchor-key-v1",
        signing_public_key_sha256=hashlib.sha256(PUBLIC_KEY).hexdigest(),
        signing_public_key_bytes=PUBLIC_KEY,
    )


def _snapshot(
    *,
    pending: object | None = None,
    evidence: object | None = None,
    complete_replay: bool,
    confirmed_anchor_count: int = 1,
    confirmed_anchor_receipt: object | None = None,
) -> TrustedTimeHeadAnchorPersistenceSnapshot:
    snapshot = object.__new__(TrustedTimeHeadAnchorPersistenceSnapshot)
    object.__setattr__(snapshot, "local_transitions", ("local-transition",))
    object.__setattr__(
        snapshot,
        "confirmed_anchor_records",
        () if confirmed_anchor_count == 0 else ("confirmed-anchor",),
    )
    object.__setattr__(snapshot, "confirmed_anchor_receipt", confirmed_anchor_receipt)
    object.__setattr__(snapshot, "pending_intent", pending)
    object.__setattr__(
        snapshot,
        "pending_intent_local_transition_ordinal",
        None if pending is None else 1,
    )
    object.__setattr__(snapshot, "committed_pending_evidence", evidence)
    object.__setattr__(snapshot, "authenticated_journal_tip", object())
    object.__setattr__(snapshot, "local_transition_count", 1)
    object.__setattr__(snapshot, "confirmed_anchor_count", confirmed_anchor_count)
    object.__setattr__(snapshot, "current_host_head_sha256", "1" * 64)
    object.__setattr__(snapshot, "complete_replay", complete_replay)
    return snapshot


def _request(*, sequence: int = 1, full_audit: bool = True):  # type: ignore[no-untyped-def]
    return TrustedTimeHeadAnchorWorkRequest(
        request_sequence=sequence,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.EPOCH_ROTATION,
        full_audit=full_audit,
        allow_enrollment=False,
        scheduled_monotonic_ns=0,
    )


def _application_result(host: str = "4") -> SimpleNamespace:
    return SimpleNamespace(
        current_host_head_sha256=host * 64,
        current_anchor_sha256="5" * 64,
        current_anchor_semantic_sha256="6" * 64,
        uploaded_anchor_count=1,
        idempotent_duplicate_count=0,
        __post_init__=lambda: None,
    )


def _enrollment_candidate() -> SimpleNamespace:
    return SimpleNamespace(
        anchor_sequence=1,
        bucket_name=TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT,
        current_host_head_sha256="4" * 64,
        byte_sha256="5" * 64,
        semantic_sha256="6" * 64,
        __post_init__=lambda: None,
    )


def _enrollment_receipt(candidate: SimpleNamespace) -> SimpleNamespace:
    return SimpleNamespace(
        intent=SimpleNamespace(
            record=candidate,
            semantic_sha256="9" * 64,
        ),
        readback_bytes_sha256="5" * 64,
        observed_at_utc=BASE,
        semantic_sha256="8" * 64,
        __post_init__=lambda: None,
    )


def _confirmed_postcondition_snapshot(
    receipt: SimpleNamespace,
    *,
    complete_replay: bool = True,
    confirmed_anchor_count: int = 1,
    local_transition_count: int = 1,
    terminal_ordinal: int = 1,
    current_host_head_sha256: str = "4" * 64,
    pending: object | None = None,
) -> TrustedTimeHeadAnchorPersistenceSnapshot:
    snapshot = _snapshot(
        pending=pending,
        evidence=None,
        complete_replay=complete_replay,
        confirmed_anchor_count=confirmed_anchor_count,
        confirmed_anchor_receipt=receipt,
    )
    object.__setattr__(snapshot, "local_transition_count", local_transition_count)
    object.__setattr__(snapshot, "current_host_head_sha256", current_host_head_sha256)
    object.__setattr__(
        snapshot,
        "authenticated_journal_tip",
        SimpleNamespace(
            confirmed_anchor_local_transition_ordinal=terminal_ordinal,
        ),
    )
    return snapshot


def _postcondition() -> TrustedTimeHeadAnchorFirstEnrollmentPostcondition:
    authority = _authority()
    return TrustedTimeHeadAnchorFirstEnrollmentPostcondition(
        anchor_sequence=1,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT,
        confirmed_anchor_count=1,
        local_transition_count=1,
        confirmed_anchor_local_transition_ordinal=1,
        remote_object_count=1,
        current_host_head_sha256="4" * 64,
        current_anchor_sha256="5" * 64,
        current_anchor_semantic_sha256="6" * 64,
        anchor_intent_semantic_sha256="9" * 64,
        candidate_remote_readback_sha256="5" * 64,
        receipt_semantic_sha256="8" * 64,
        remote_namespace_sha256="7" * 64,
        anchor_authority_sha256=authority.anchor_authority_sha256,
        deployment_identity_sha256=authority.deployment_identity_sha256,
        runtime_database_identity_sha256=authority.runtime_database_identity_sha256,
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


def _post_enrollment_record() -> SimpleNamespace:
    authority = _authority()
    return SimpleNamespace(
        anchor_sequence=2,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.EPOCH_ROTATION,
        checkpoint_interval_seconds=TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
        anchor_authority_sha256=authority.anchor_authority_sha256,
        deployment_identity_sha256=authority.deployment_identity_sha256,
        runtime_database_identity_sha256=authority.runtime_database_identity_sha256,
        anchor_project_identity_sha256=authority.anchor_project_identity_sha256,
        anchor_project_ref=authority.anchor_project_ref,
        source_id="chrony-nts-system76-virginia-v2",
        source_authority_sha256=authority.source_authority_sha256,
        policy_sha256="d" * 64,
        persistence_contract_version="phase6a-durable-trusted-time-persistence-v1",
        epoch_sequence=2,
        monitor_epoch_id="22345678-1234-4234-9234-123456789abc",
        epoch_sha256="e" * 64,
        evaluation_sequence=0,
        signing_key_id=authority.signing_key_id,
        signing_public_key_sha256=authority.signing_public_key_sha256,
        host_id=authority.host_id,
        principal_id=authority.principal_id,
        bucket_name=authority.bucket_name,
        previous_anchor_sha256="5" * 64,
        current_host_head_sha256="4" * 64,
        byte_sha256="6" * 64,
        semantic_sha256="7" * 64,
        __post_init__=lambda: None,
    )


def _post_enrollment_receipt(
    record: SimpleNamespace,
    *,
    intent_semantic_sha256: str = "8" * 64,
    receipt_semantic_sha256: str = "9" * 64,
) -> SimpleNamespace:
    return SimpleNamespace(
        intent=SimpleNamespace(
            record=record,
            semantic_sha256=intent_semantic_sha256,
        ),
        readback_bytes_sha256=record.byte_sha256,
        semantic_sha256=receipt_semantic_sha256,
        __post_init__=lambda: None,
    )


def _post_enrollment_snapshot(
    receipt: SimpleNamespace,
    *,
    local_transition_count: int = 2,
    terminal_ordinal: int = 2,
    current_local_host_head_sha256: str | None = None,
    confirmed_anchor_count: int = 2,
    pending: object | None = None,
    current_transition_overrides: dict[str, object] | None = None,
) -> TrustedTimeHeadAnchorPersistenceSnapshot:
    current_head = (
        receipt.intent.record.current_host_head_sha256
        if current_local_host_head_sha256 is None
        else current_local_host_head_sha256
    )
    snapshot = _snapshot(
        pending=pending,
        complete_replay=True,
        confirmed_anchor_count=confirmed_anchor_count,
        confirmed_anchor_receipt=receipt,
    )
    # A complete startup replay authenticates the entire durable history into
    # the sealed tip but intentionally returns no replay tuple to its caller.
    object.__setattr__(snapshot, "confirmed_anchor_records", ())
    object.__setattr__(snapshot, "local_transition_count", local_transition_count)
    object.__setattr__(snapshot, "current_host_head_sha256", current_head)
    record = receipt.intent.record
    transition_fields: dict[str, object] = {
        "source_id": record.source_id,
        "source_authority_sha256": record.source_authority_sha256,
        "policy_sha256": record.policy_sha256,
        "persistence_contract_version": record.persistence_contract_version,
        "epoch_sequence": record.epoch_sequence,
        "monitor_epoch_id": record.monitor_epoch_id,
        "epoch_sha256": record.epoch_sha256,
        "evaluation_sequence": (
            record.evaluation_sequence + local_transition_count - terminal_ordinal
        ),
    }
    transition_fields.update(current_transition_overrides or {})
    object.__setattr__(
        snapshot,
        "authenticated_journal_tip",
        SimpleNamespace(
            confirmed_anchor_count=confirmed_anchor_count,
            confirmed_anchor_tip=receipt.intent.record,
            confirmed_anchor_local_transition_ordinal=terminal_ordinal,
            local_transition_count=local_transition_count,
            current_local_host_head_sha256=current_head,
            current_transition=SimpleNamespace(**transition_fields),
        ),
    )
    return snapshot


def _post_enrollment_postcondition(
    *,
    local_transition_count: int = 2,
) -> TrustedTimeHeadAnchorPostEnrollmentStartPostcondition:
    authority = _authority()
    return TrustedTimeHeadAnchorPostEnrollmentStartPostcondition(
        anchor_sequence=2,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.EPOCH_ROTATION,
        confirmed_anchor_count=2,
        local_transition_count=local_transition_count,
        confirmed_anchor_local_transition_ordinal=2,
        remote_object_count=2,
        predecessor_anchor_sha256="5" * 64,
        current_host_head_sha256="4" * 64,
        current_anchor_sha256="6" * 64,
        current_anchor_semantic_sha256="7" * 64,
        anchor_intent_semantic_sha256="8" * 64,
        candidate_remote_readback_sha256="6" * 64,
        receipt_semantic_sha256="9" * 64,
        remote_namespace_sha256="0" * 64,
        anchor_authority_sha256=authority.anchor_authority_sha256,
        deployment_identity_sha256=authority.deployment_identity_sha256,
        runtime_database_identity_sha256=authority.runtime_database_identity_sha256,
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


def _dependencies():  # type: ignore[no-untyped-def]
    local = Mock(spec=SqlTrustedTimeRepository)
    anchor = Mock(spec=SqlTrustedTimeHeadAnchorRepository)
    provider = Mock()
    for method in (
        "attest_identity",
        "list_object_names",
        "list_object_names_page",
        "list_sequence_object_names",
        "download_object",
        "upload_object_no_overwrite",
    ):
        setattr(provider, method, Mock())
    signer = Mock()
    signer.sign_ed25519 = Mock()
    verifier = Mock()
    verifier.verify_ed25519 = Mock()
    anchor.compact_head_anchor_snapshot.side_effect = lambda snapshot: snapshot
    anchor.refresh_head_anchor_snapshot.side_effect = lambda snapshot: snapshot
    return local, anchor, provider, signer, verifier


def _attempt(  # type: ignore[no-untyped-def]
    local,
    anchor,
    provider,
    signer,
    verifier,
    *,
    startup_effect_guard=None,
):
    return RepositoryBackedTrustedTimeHeadAnchorAttempt(
        anchor_repository=anchor,
        provider=provider,
        signer=signer,
        verifier=verifier,
        authority=_authority(),
        utc_clock=lambda: BASE,
        startup_effect_guard=startup_effect_guard,
    )


def test_startup_effect_guard_is_one_shot_and_fails_closed_at_reserve() -> None:
    logical = _MonotonicClock()
    wall = _MonotonicClock(1_000)
    guard = TrustedTimeHeadAnchorStartupEffectDeadlineGuard(
        deadline_monotonic_ns=120_000_000_000,
        monotonic_clock=logical,
        wall_monotonic_clock=wall,
    )
    guard.require_effect_window(minimum_remaining_ns=119_000_000_000)
    logical.value = 104_000_000_000
    wall.value += 104_000_000_000

    with pytest.raises(
        TrustedTimeHeadAnchorStartupEffectDeadlineExceeded,
        match="deadline is exhausted",
    ):
        guard.require_effect_window(minimum_remaining_ns=16_000_000_000)
    with pytest.raises(
        TrustedTimeHeadAnchorStartupEffectDeadlineExceeded,
        match="guard is poisoned",
    ):
        guard.require_effect_window()
    with pytest.raises(
        TrustedTimeHeadAnchorStartupEffectDeadlineExceeded,
        match="cannot be released",
    ):
        guard.release_after_startup_terminal()


def test_deadline_bound_provider_blocks_io_without_full_provider_reserve() -> None:
    logical = _MonotonicClock()
    wall = _MonotonicClock()
    guard = TrustedTimeHeadAnchorStartupEffectDeadlineGuard(
        deadline_monotonic_ns=120_000_000_000,
        monotonic_clock=logical,
        wall_monotonic_clock=wall,
    )
    provider = Mock()
    for method in (
        "attest_identity",
        "list_object_names",
        "list_object_names_page",
        "list_sequence_object_names",
        "download_object",
        "upload_object_no_overwrite",
    ):
        setattr(provider, method, Mock())
    bounded = DeadlineBoundTrustedTimeHeadAnchorProvider(
        provider=provider,
        startup_effect_guard=guard,
    )
    logical.value = 104_000_000_000
    wall.value = 104_000_000_000

    with pytest.raises(TrustedTimeHeadAnchorStartupEffectDeadlineExceeded):
        bounded.upload_object_no_overwrite(
            bucket_name="trusted-time-head-anchors",
            object_name="v1/object.json",
            payload=b"payload",
            content_type="application/json",
        )

    provider.upload_object_no_overwrite.assert_not_called()


def test_deadline_bound_provider_detects_io_that_crosses_the_absolute_cutoff() -> None:
    logical = _MonotonicClock(103_000_000_000)
    wall = _MonotonicClock(103_000_000_000)
    guard = TrustedTimeHeadAnchorStartupEffectDeadlineGuard(
        deadline_monotonic_ns=120_000_000_000,
        monotonic_clock=logical,
        wall_monotonic_clock=wall,
    )
    provider = Mock()
    for method in (
        "attest_identity",
        "list_object_names",
        "list_object_names_page",
        "list_sequence_object_names",
        "download_object",
        "upload_object_no_overwrite",
    ):
        setattr(provider, method, Mock())

    def cross_deadline(**_: object) -> None:
        logical.value = 120_000_000_000
        wall.value = 120_000_000_000

    provider.upload_object_no_overwrite.side_effect = cross_deadline
    bounded = DeadlineBoundTrustedTimeHeadAnchorProvider(
        provider=provider,
        startup_effect_guard=guard,
    )

    with pytest.raises(
        TrustedTimeHeadAnchorStartupEffectDeadlineExceeded,
        match="deadline is exhausted",
    ):
        bounded.upload_object_no_overwrite(
            bucket_name="trusted-time-head-anchors",
            object_name="v1/object.json",
            payload=b"payload",
            content_type="application/json",
        )

    provider.upload_object_no_overwrite.assert_called_once()
    with pytest.raises(TrustedTimeHeadAnchorStartupEffectDeadlineExceeded):
        guard.require_effect_window()


def test_startup_effect_guard_rejects_a_forked_process_copy() -> None:
    guard = TrustedTimeHeadAnchorStartupEffectDeadlineGuard(
        deadline_monotonic_ns=120_000_000_000,
        monotonic_clock=lambda: 0,
        wall_monotonic_clock=lambda: 0,
    )

    with (
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt.os.getpid",
            return_value=guard._owner_pid + 1,
        ),
        pytest.raises(
            TrustedTimeHeadAnchorStartupEffectDeadlineExceeded,
            match="process boundary",
        ),
    ):
        guard.require_effect_window()


def test_released_startup_effect_guard_remains_process_bound() -> None:
    guard = TrustedTimeHeadAnchorStartupEffectDeadlineGuard(
        deadline_monotonic_ns=120_000_000_000,
        monotonic_clock=lambda: 0,
        wall_monotonic_clock=lambda: 0,
    )
    guard.release_after_startup_terminal()

    with (
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt.os.getpid",
            return_value=guard._owner_pid + 1,
        ),
        pytest.raises(
            TrustedTimeHeadAnchorStartupEffectDeadlineExceeded,
            match="process boundary",
        ),
    ):
        guard.require_effect_window()


def test_released_startup_effect_guard_allows_long_lived_provider_io() -> None:
    logical = _MonotonicClock()
    wall = _MonotonicClock()
    guard = TrustedTimeHeadAnchorStartupEffectDeadlineGuard(
        deadline_monotonic_ns=120_000_000_000,
        monotonic_clock=logical,
        wall_monotonic_clock=wall,
    )
    provider = Mock()
    for method in (
        "attest_identity",
        "list_object_names",
        "list_object_names_page",
        "list_sequence_object_names",
        "download_object",
        "upload_object_no_overwrite",
    ):
        setattr(provider, method, Mock())
    bounded = DeadlineBoundTrustedTimeHeadAnchorProvider(
        provider=provider,
        startup_effect_guard=guard,
    )
    guard.release_after_startup_terminal()
    logical.value = 200_000_000_000
    wall.value = 200_000_000_000

    bounded.upload_object_no_overwrite(
        bucket_name="trusted-time-head-anchors",
        object_name="v1/object.json",
        payload=b"payload",
        content_type="application/json",
    )

    provider.upload_object_no_overwrite.assert_called_once()


def test_startup_sql_effect_is_not_started_without_its_deadline_reserve() -> None:
    local, anchor, provider, signer, verifier = _dependencies()
    full = _snapshot(complete_replay=True)
    prepared = SimpleNamespace(candidate_record=object(), full_audit=True)
    anchor.load_head_anchor_startup_snapshot.return_value = full
    logical = _MonotonicClock()
    wall = _MonotonicClock()
    guard = TrustedTimeHeadAnchorStartupEffectDeadlineGuard(
        deadline_monotonic_ns=120_000_000_000,
        monotonic_clock=logical,
        wall_monotonic_clock=wall,
    )
    attempt = _attempt(
        local,
        anchor,
        provider,
        signer,
        verifier,
        startup_effect_guard=guard,
    )
    attempt.prime_startup()
    logical.value = 100_000_000_000
    wall.value = 100_000_000_000

    with (
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "prepare_bounded_trusted_time_head_anchor_reconciliation",
            return_value=prepared,
        ),
        pytest.raises(TrustedTimeHeadAnchorStartupEffectDeadlineExceeded),
    ):
        attempt(_request())

    anchor.commit_prepared_intent.assert_not_called()


def test_startup_sql_effect_crossing_the_deadline_is_detected_and_poisoned() -> None:
    local, anchor, provider, signer, verifier = _dependencies()
    full = _snapshot(complete_replay=True)
    pending = _snapshot(complete_replay=False)
    prepared = SimpleNamespace(candidate_record=object(), full_audit=True)
    evidence = object()
    anchor.load_head_anchor_startup_snapshot.return_value = full
    logical = _MonotonicClock(69_000_000_000)
    wall = _MonotonicClock(69_000_000_000)
    guard = TrustedTimeHeadAnchorStartupEffectDeadlineGuard(
        deadline_monotonic_ns=120_000_000_000,
        monotonic_clock=logical,
        wall_monotonic_clock=wall,
    )

    def commit(*_: object, **__: object) -> tuple[object, object]:
        logical.value = 120_000_000_000
        wall.value = 120_000_000_000
        return pending, evidence

    anchor.commit_prepared_intent.side_effect = commit
    attempt = _attempt(
        local,
        anchor,
        provider,
        signer,
        verifier,
        startup_effect_guard=guard,
    )
    attempt.prime_startup()

    with (
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "prepare_bounded_trusted_time_head_anchor_reconciliation",
            return_value=prepared,
        ),
        pytest.raises(
            TrustedTimeHeadAnchorStartupEffectDeadlineExceeded,
            match="deadline is exhausted",
        ),
    ):
        attempt(_request())

    anchor.commit_prepared_intent.assert_called_once()
    with pytest.raises(TrustedTimeHeadAnchorStartupEffectDeadlineExceeded):
        guard.require_effect_window()


def test_attempt_commits_before_upload_then_confirms_a_second_exact_readback() -> None:
    local, anchor, provider, signer, verifier = _dependencies()
    full = _snapshot(complete_replay=True)
    candidate = SimpleNamespace(bucket_name=TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME)
    intent_evidence = object()
    intent = SimpleNamespace(
        record=candidate,
        object_name="v1/object.json",
        signed_envelope_bytes=b"signed-object",
        semantic_sha256="9" * 64,
        anchor_intent_id="11111111-1111-4111-8111-111111111111",
        __post_init__=lambda: None,
    )
    pending = _snapshot(
        pending=intent,
        evidence=intent_evidence,
        complete_replay=False,
    )
    confirmed = _snapshot(complete_replay=False)
    prepared = SimpleNamespace(candidate_record=candidate, full_audit=True)
    receipt = SimpleNamespace(
        readback_bytes_sha256="7" * 64,
        semantic_sha256="8" * 64,
    )
    events: list[str] = []
    anchor.load_head_anchor_startup_snapshot.return_value = full
    anchor.commit_prepared_intent.side_effect = lambda *args, **kwargs: (
        events.append("intent_committed") or (pending, intent_evidence)
    )
    provider_readback = object()
    anchor.confirm_remote_readback_from_snapshot.side_effect = lambda *args, **kwargs: (
        events.append("receipt_committed") or (confirmed, receipt)
    )

    def complete(*args: object, **kwargs: object) -> SimpleNamespace:
        events.append("remote_completion")
        return _application_result()

    attempt = _attempt(local, anchor, provider, signer, verifier)
    attempt.prime_startup()
    with (
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "prepare_bounded_trusted_time_head_anchor_reconciliation",
            return_value=prepared,
        ),
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "verify_trusted_time_head_anchor_provider_readback",
            side_effect=lambda **_: events.append("second_readback") or provider_readback,
        ),
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "complete_trusted_time_head_anchor_reconciliation",
            side_effect=complete,
        ) as completed,
    ):
        result = attempt(_request())

    assert events == [
        "intent_committed",
        "remote_completion",
        "second_readback",
        "receipt_committed",
    ]
    completed.assert_called_once_with(
        prepared,
        provider=provider,
        committed_intent=intent_evidence,
    )
    anchor.confirm_remote_readback_from_snapshot.assert_called_once_with(
        pending,
        intent=intent,
        provider_readback=provider_readback,
        observed_at_utc=BASE,
    )
    assert result.full_audit_completed is True
    assert result.pending_intent_recovered is False
    assert result.candidate_remote_readback_sha256 == "7" * 64
    assert result.receipt_semantic_sha256 == "8" * 64
    for field_name in (
        "alert_delivery_authorized",
        "arming_authorized",
        "automatic_rearm_authorized",
        "automatic_resume_authorized",
        "broker_action_authorized",
        "exposure_authorized",
        "live_trading_authorized",
        "new_exposure_authorized",
        "operational_control_authorized",
        "paper_trading_authorized",
        "readiness_authorized",
        "rearm_authorized",
    ):
        assert getattr(attempt, field_name) is False


def test_retry_recovers_durable_pending_before_incremental_successor_without_resigning() -> None:
    local, anchor, provider, signer, verifier = _dependencies()
    initial = _snapshot(complete_replay=True)
    candidate = SimpleNamespace(bucket_name=TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME)
    evidence = object()
    intent = SimpleNamespace(
        record=candidate,
        object_name="v1/object.json",
        signed_envelope_bytes=b"signed-object",
        semantic_sha256="9" * 64,
        anchor_intent_id="11111111-1111-4111-8111-111111111111",
    )
    compact_pending = _snapshot(
        pending=intent,
        evidence=evidence,
        complete_replay=False,
    )
    recovery_full = _snapshot(
        pending=intent,
        evidence=evidence,
        complete_replay=True,
    )
    confirmed = _snapshot(complete_replay=False)
    first_prepared = SimpleNamespace(candidate_record=candidate, full_audit=True)
    recovered_prepared = SimpleNamespace(candidate_record=candidate, full_audit=True)
    verified_prepared = SimpleNamespace(candidate_record=None, full_audit=False)
    receipt = SimpleNamespace(
        readback_bytes_sha256="7" * 64,
        semantic_sha256="8" * 64,
    )
    events: list[str] = []
    anchor.load_head_anchor_startup_snapshot.side_effect = [initial, recovery_full]
    anchor.commit_prepared_intent.return_value = (compact_pending, evidence)
    anchor.confirm_remote_readback_from_snapshot.return_value = (confirmed, receipt)

    def complete(prepared: object, **kwargs: object) -> SimpleNamespace:
        if prepared is first_prepared:
            events.append("first_remote_attempt")
            raise TrustedTimeHeadAnchorProviderUnavailable("bounded outage")
        if prepared is recovered_prepared:
            events.append("pending_recovered")
            return _application_result()
        assert prepared is verified_prepared
        events.append("successor_verified")
        return _application_result()

    attempt = _attempt(local, anchor, provider, signer, verifier)
    attempt.prime_startup()
    with (
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "prepare_bounded_trusted_time_head_anchor_reconciliation",
            return_value=first_prepared,
        ) as prepare_full,
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "prepare_bounded_persisted_trusted_time_head_anchor_intent_recovery",
            return_value=recovered_prepared,
        ) as prepare_recovery,
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "verify_trusted_time_head_anchor_provider_readback",
            return_value=object(),
        ),
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "prepare_incremental_trusted_time_head_anchor_reconciliation",
            return_value=verified_prepared,
        ) as prepare_incremental,
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "complete_trusted_time_head_anchor_reconciliation",
            side_effect=complete,
        ),
    ):
        with pytest.raises(TrustedTimeHeadAnchorTransientFailure):
            attempt(_request())
        result = attempt(_request(sequence=2))

    assert events == [
        "first_remote_attempt",
        "pending_recovered",
        "successor_verified",
    ]
    assert prepare_full.call_count == 1
    prepare_recovery.assert_called_once()
    assert prepare_recovery.call_args.kwargs["full_audit"] is True
    prepare_incremental.assert_called_once()
    assert anchor.commit_prepared_intent.call_count == 1
    assert anchor.discard_head_anchor_snapshot.call_args_list == [call(compact_pending)]
    assert result.pending_intent_recovered is True
    assert result.full_audit_completed is True
    assert result.candidate_remote_readback_sha256 == "7" * 64


def test_only_typed_provider_outage_and_authenticated_snapshot_advance_retry() -> None:
    local, anchor, provider, signer, verifier = _dependencies()
    full = _snapshot(complete_replay=True)
    refreshed = _snapshot(complete_replay=False)
    anchor.load_head_anchor_startup_snapshot.return_value = full
    attempt = _attempt(local, anchor, provider, signer, verifier)
    attempt.prime_startup()

    with (
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "prepare_bounded_trusted_time_head_anchor_reconciliation",
            side_effect=TrustedTimeHeadAnchorProviderUnavailable("retryable"),
        ),
        pytest.raises(TrustedTimeHeadAnchorTransientFailure),
    ):
        attempt(_request())
    anchor.compact_head_anchor_snapshot.assert_called_with(full)

    marker = TrustedTimeHeadAnchorSnapshotAdvanced(
        "authenticated append",
        refreshed_snapshot=refreshed,
    )
    with (
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "prepare_bounded_trusted_time_head_anchor_reconciliation",
            side_effect=marker,
        ),
        pytest.raises(TrustedTimeHeadAnchorTransientFailure),
    ):
        attempt(_request(sequence=2))
    anchor.compact_head_anchor_snapshot.assert_called_with(refreshed)

    with (
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "prepare_bounded_trusted_time_head_anchor_reconciliation",
            side_effect=TrustedTimeHeadAnchorPersistenceConflict("integrity conflict"),
        ),
        pytest.raises(TrustedTimeHeadAnchorFatalFailure),
    ):
        attempt(_request(sequence=3))


def test_absent_remote_without_enrollment_approval_translates_to_exact_typed_fatal() -> None:
    local, anchor, provider, signer, verifier = _dependencies()
    full = _snapshot(complete_replay=True)
    anchor.load_head_anchor_startup_snapshot.return_value = full
    attempt = _attempt(local, anchor, provider, signer, verifier)
    attempt.prime_startup()

    with (
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "prepare_bounded_trusted_time_head_anchor_reconciliation",
            side_effect=TrustedTimeHeadAnchorEnrollmentNotApproved(
                "secret provider response must not cross the attempt boundary"
            ),
        ),
        pytest.raises(TrustedTimeHeadAnchorEnrollmentNotApprovedFailure) as captured,
    ):
        attempt(_request())

    assert str(captured.value) == (
        "trusted-time remote anchor history is absent and enrollment is not approved"
    )
    assert "secret" not in str(captured.value)


def test_first_enrollment_creates_and_confirms_only_sequence_one() -> None:
    local, anchor, provider, signer, verifier = _dependencies()
    initial = _snapshot(complete_replay=True, confirmed_anchor_count=0)
    candidate = _enrollment_candidate()
    evidence = object()
    intent = SimpleNamespace(
        record=candidate,
        object_name="v1/object.json",
        signed_envelope_bytes=b"signed-object",
        semantic_sha256="9" * 64,
        anchor_intent_id="11111111-1111-4111-8111-111111111111",
    )
    pending = _snapshot(
        pending=intent,
        evidence=evidence,
        complete_replay=False,
        confirmed_anchor_count=0,
    )
    receipt = _enrollment_receipt(candidate)
    confirmed = _snapshot(
        complete_replay=False,
        confirmed_anchor_count=1,
        confirmed_anchor_receipt=receipt,
    )
    prepared = SimpleNamespace(candidate_record=candidate, full_audit=True)
    anchor.load_head_anchor_startup_snapshot.return_value = initial
    anchor.commit_prepared_intent.return_value = (pending, evidence)
    anchor.confirm_remote_readback_from_snapshot.return_value = (confirmed, receipt)

    attempt = _attempt(local, anchor, provider, signer, verifier)
    attempt.prime_startup()
    with (
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "prepare_bounded_trusted_time_head_anchor_reconciliation",
            return_value=prepared,
        ) as prepare,
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "prepare_incremental_trusted_time_head_anchor_reconciliation"
        ) as prepare_incremental,
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "complete_trusted_time_head_anchor_reconciliation",
            return_value=_application_result(),
        ),
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "verify_trusted_time_head_anchor_provider_readback",
            return_value=object(),
        ),
    ):
        result = attempt.perform_first_enrollment()

    assert prepare.call_args.kwargs["checkpoint_reason"] is (
        TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT
    )
    assert prepare.call_args.kwargs["allow_enrollment"] is True
    anchor.commit_prepared_intent.assert_called_once_with(
        initial,
        prepared=prepared,
        created_at_utc=BASE,
        allow_enrollment=True,
    )
    prepare_incremental.assert_not_called()
    assert result.anchor_sequence == 1
    assert result.checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT
    assert result.pending_intent_recovered is False
    assert result.full_audit_completed is True
    assert result.candidate_remote_readback_sha256 == "5" * 64
    assert result.receipt_semantic_sha256 == "8" * 64


def test_first_enrollment_commit_snapshot_advance_is_a_precommit_state_conflict() -> None:
    local, anchor, provider, signer, verifier = _dependencies()
    initial = _snapshot(complete_replay=True, confirmed_anchor_count=0)
    refreshed = _snapshot(complete_replay=False, confirmed_anchor_count=0)
    prepared = SimpleNamespace(
        candidate_record=_enrollment_candidate(),
        full_audit=True,
    )
    anchor.load_head_anchor_startup_snapshot.return_value = initial
    anchor.commit_prepared_intent.side_effect = TrustedTimeHeadAnchorSnapshotAdvanced(
        "authenticated concurrent advance",
        refreshed_snapshot=refreshed,
    )
    attempt = _attempt(local, anchor, provider, signer, verifier)
    attempt.prime_startup()

    with (
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "prepare_bounded_trusted_time_head_anchor_reconciliation",
            return_value=prepared,
        ),
        pytest.raises(TrustedTimeHeadAnchorFirstEnrollmentStateConflict),
    ):
        attempt.perform_first_enrollment()

    anchor.compact_head_anchor_snapshot.assert_called_with(refreshed)
    provider.put_if_absent.assert_not_called()


def test_first_enrollment_precommit_audit_conflict_is_a_state_conflict() -> None:
    local, anchor, provider, signer, verifier = _dependencies()
    initial = _snapshot(complete_replay=True, confirmed_anchor_count=0)
    anchor.load_head_anchor_startup_snapshot.return_value = initial
    attempt = _attempt(local, anchor, provider, signer, verifier)
    attempt.prime_startup()

    with (
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "prepare_bounded_trusted_time_head_anchor_reconciliation",
            side_effect=TrustedTimeHeadAnchorConflict("authenticated state conflict"),
        ),
        pytest.raises(TrustedTimeHeadAnchorFirstEnrollmentStateConflict),
    ):
        attempt.perform_first_enrollment()

    anchor.commit_prepared_intent.assert_not_called()
    provider.put_if_absent.assert_not_called()


def test_first_enrollment_recovers_sequence_one_and_never_prepares_a_successor() -> None:
    local, anchor, provider, signer, verifier = _dependencies()
    candidate = _enrollment_candidate()
    evidence = object()
    intent = SimpleNamespace(
        record=candidate,
        object_name="v1/object.json",
        signed_envelope_bytes=b"signed-object",
        semantic_sha256="9" * 64,
        anchor_intent_id="11111111-1111-4111-8111-111111111111",
        __post_init__=lambda: None,
    )
    pending = _snapshot(
        pending=intent,
        evidence=evidence,
        complete_replay=True,
        confirmed_anchor_count=0,
    )
    receipt = _enrollment_receipt(candidate)
    confirmed = _snapshot(
        complete_replay=False,
        confirmed_anchor_count=1,
        confirmed_anchor_receipt=receipt,
    )
    prepared = SimpleNamespace(candidate_record=candidate, full_audit=True)
    anchor.load_head_anchor_startup_snapshot.return_value = pending
    anchor.confirm_remote_readback_from_snapshot.return_value = (confirmed, receipt)

    attempt = _attempt(local, anchor, provider, signer, verifier)
    attempt.prime_startup()
    with (
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "prepare_bounded_persisted_trusted_time_head_anchor_intent_recovery",
            return_value=prepared,
        ) as recover,
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "prepare_bounded_trusted_time_head_anchor_reconciliation"
        ) as prepare_current,
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "prepare_incremental_trusted_time_head_anchor_reconciliation"
        ) as prepare_incremental,
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "complete_trusted_time_head_anchor_reconciliation",
            return_value=_application_result(),
        ),
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "verify_trusted_time_head_anchor_provider_readback",
            return_value=object(),
        ),
    ):
        result = attempt.recover_first_enrollment()

    assert recover.call_args.kwargs["full_audit"] is True
    prepare_current.assert_not_called()
    prepare_incremental.assert_not_called()
    anchor.commit_prepared_intent.assert_not_called()
    assert result.pending_intent_recovered is True
    assert result.checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT


def test_first_enrollment_refuses_confirmed_history_before_provider_or_signer_use() -> None:
    local, anchor, provider, signer, verifier = _dependencies()
    confirmed = _snapshot(complete_replay=True, confirmed_anchor_count=1)
    anchor.load_head_anchor_startup_snapshot.return_value = confirmed
    attempt = _attempt(local, anchor, provider, signer, verifier)
    attempt.prime_startup()

    with pytest.raises(TrustedTimeHeadAnchorFirstEnrollmentAlreadyCompleted):
        attempt.perform_first_enrollment()

    signer.sign_ed25519.assert_not_called()
    provider.attest_identity.assert_not_called()
    anchor.commit_prepared_intent.assert_not_called()


def test_new_first_enrollment_requires_separate_recovery_for_pending_intent() -> None:
    local, anchor, provider, signer, verifier = _dependencies()
    candidate = _enrollment_candidate()
    intent = SimpleNamespace(
        record=candidate,
        __post_init__=lambda: None,
    )
    pending = _snapshot(
        pending=intent,
        evidence=object(),
        complete_replay=True,
        confirmed_anchor_count=0,
    )
    anchor.load_head_anchor_startup_snapshot.return_value = pending
    attempt = _attempt(local, anchor, provider, signer, verifier)
    attempt.prime_startup()

    with pytest.raises(TrustedTimeHeadAnchorFirstEnrollmentRecoveryRequired):
        attempt.perform_first_enrollment()

    provider.attest_identity.assert_not_called()
    anchor.commit_prepared_intent.assert_not_called()


@pytest.mark.parametrize(
    ("sequence", "reason"),
    [
        (2, TrustedTimeHeadAnchorCheckpointReason.EPOCH_ROTATION),
        (1, TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP),
    ],
)
def test_first_enrollment_refuses_non_enrollment_pending_state(
    sequence: int,
    reason: TrustedTimeHeadAnchorCheckpointReason,
) -> None:
    local, anchor, provider, signer, verifier = _dependencies()
    candidate = SimpleNamespace(
        anchor_sequence=sequence,
        checkpoint_reason=reason,
        __post_init__=lambda: None,
    )
    intent = SimpleNamespace(record=candidate, __post_init__=lambda: None)
    pending = _snapshot(
        pending=intent,
        evidence=object(),
        complete_replay=True,
        confirmed_anchor_count=0,
    )
    anchor.load_head_anchor_startup_snapshot.return_value = pending
    attempt = _attempt(local, anchor, provider, signer, verifier)
    attempt.prime_startup()

    with pytest.raises(TrustedTimeHeadAnchorFirstEnrollmentStateConflict):
        attempt.recover_first_enrollment()

    provider.attest_identity.assert_not_called()
    anchor.commit_prepared_intent.assert_not_called()


def test_first_enrollment_postcondition_reauthenticates_exact_current_sequence_one_read_only() -> (
    None
):
    local, anchor, provider, signer, verifier = _dependencies()
    candidate = _enrollment_candidate()
    receipt = _enrollment_receipt(candidate)
    prior = _confirmed_postcondition_snapshot(receipt)
    fresh = _confirmed_postcondition_snapshot(receipt)
    final = _confirmed_postcondition_snapshot(receipt)
    anchor.load_head_anchor_startup_snapshot.side_effect = (prior, fresh, final)
    attempt = _attempt(local, anchor, provider, signer, verifier)
    attempt.prime_startup()

    with patch(
        "apps.trusted_time_supervisor.head_anchor_attempt."
        "verify_bounded_first_enrollment_remote_postcondition",
        return_value="7" * 64,
    ) as verify_remote:
        evidence = attempt.reauthenticate_first_enrollment_postcondition()

    assert evidence == _postcondition()
    verify_remote.assert_called_once_with(
        fresh.authenticated_journal_tip,
        provider=provider,
        verifier=verifier,
        signing_key_id=_authority().signing_key_id,
        signing_public_key_sha256=_authority().signing_public_key_sha256,
        checkpoint_interval_seconds=TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
        anchor_authority_sha256=_authority().anchor_authority_sha256,
    )
    signer.sign_ed25519.assert_not_called()
    provider.upload_object_no_overwrite.assert_not_called()
    anchor.commit_prepared_intent.assert_not_called()
    anchor.confirm_remote_readback_from_snapshot.assert_not_called()
    for field_name in (
        "alert_delivery_authorized",
        "arming_authorized",
        "automatic_rearm_authorized",
        "automatic_resume_authorized",
        "broker_action_authorized",
        "exposure_authorized",
        "live_trading_authorized",
        "new_exposure_authorized",
        "operational_control_authorized",
        "paper_trading_authorized",
        "readiness_authorized",
        "rearm_authorized",
    ):
        assert getattr(evidence, field_name) is False
    for raw_identity_field in ("host_id", "principal_id", "bucket_name"):
        assert not hasattr(evidence, raw_identity_field)


def test_first_enrollment_remote_postcondition_wrapper_preserves_digest_api() -> None:
    local, anchor, provider, signer, verifier = _dependencies()
    attempt = _attempt(local, anchor, provider, signer, verifier)
    with patch.object(
        RepositoryBackedTrustedTimeHeadAnchorAttempt,
        "reauthenticate_first_enrollment_postcondition",
        return_value=_postcondition(),
    ) as reauthenticate:
        assert attempt.verify_first_enrollment_remote_postcondition() == "7" * 64

    reauthenticate.assert_called_once_with()


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("anchor_sequence", True),
        ("confirmed_anchor_count", True),
        ("local_transition_count", True),
        ("confirmed_anchor_local_transition_ordinal", True),
        ("remote_object_count", True),
        ("full_audit_completed", 1),
        ("pending_intent_present", 0),
    ],
)
def test_first_enrollment_postcondition_rejects_boolean_or_integer_substitution(
    field_name: str,
    value: object,
) -> None:
    with pytest.raises(
        TrustedTimeHeadAnchorFirstEnrollmentStateConflict,
        match="postcondition is invalid",
    ):
        replace(_postcondition(), **{field_name: value})


def test_first_enrollment_postcondition_rejects_string_subclass_and_readback_drift() -> None:
    class Digest(str):
        pass

    for change in (
        {"remote_namespace_sha256": Digest("7" * 64)},
        {"candidate_remote_readback_sha256": "0" * 64},
    ):
        with pytest.raises(
            TrustedTimeHeadAnchorFirstEnrollmentStateConflict,
            match="postcondition is invalid",
        ):
            replace(_postcondition(), **change)


@pytest.mark.parametrize(
    "fresh",
    [
        _confirmed_postcondition_snapshot(
            _enrollment_receipt(_enrollment_candidate()),
            complete_replay=False,
        ),
        _confirmed_postcondition_snapshot(
            _enrollment_receipt(_enrollment_candidate()),
            confirmed_anchor_count=True,
        ),
        _confirmed_postcondition_snapshot(
            _enrollment_receipt(_enrollment_candidate()),
            local_transition_count=2,
            terminal_ordinal=1,
        ),
        _confirmed_postcondition_snapshot(
            _enrollment_receipt(_enrollment_candidate()),
            local_transition_count=2,
            terminal_ordinal=2,
            current_host_head_sha256="0" * 64,
        ),
        _confirmed_postcondition_snapshot(
            _enrollment_receipt(_enrollment_candidate()),
            pending=object(),
        ),
    ],
)
def test_first_enrollment_postcondition_rejects_local_drift_before_remote_io(
    fresh: TrustedTimeHeadAnchorPersistenceSnapshot,
) -> None:
    local, anchor, provider, signer, verifier = _dependencies()
    receipt = fresh.confirmed_anchor_receipt
    assert receipt is not None
    prior = _confirmed_postcondition_snapshot(receipt)
    anchor.load_head_anchor_startup_snapshot.side_effect = (prior, fresh)
    attempt = _attempt(local, anchor, provider, signer, verifier)
    attempt.prime_startup()

    with (
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "verify_bounded_first_enrollment_remote_postcondition"
        ) as verify_remote,
        pytest.raises(TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed),
    ):
        attempt.reauthenticate_first_enrollment_postcondition()

    verify_remote.assert_not_called()
    signer.sign_ed25519.assert_not_called()
    provider.upload_object_no_overwrite.assert_not_called()
    anchor.commit_prepared_intent.assert_not_called()


def test_first_enrollment_postcondition_rejects_nonexact_remote_namespace_closed() -> None:
    local, anchor, provider, signer, verifier = _dependencies()
    candidate = _enrollment_candidate()
    receipt = _enrollment_receipt(candidate)
    prior = _confirmed_postcondition_snapshot(receipt)
    fresh = _confirmed_postcondition_snapshot(receipt)
    final = _confirmed_postcondition_snapshot(receipt)
    anchor.load_head_anchor_startup_snapshot.side_effect = (prior, fresh, final)
    attempt = _attempt(local, anchor, provider, signer, verifier)
    attempt.prime_startup()

    with (
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "verify_bounded_first_enrollment_remote_postcondition",
            return_value=True,
        ) as verify_remote,
        pytest.raises(TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed),
    ):
        attempt.reauthenticate_first_enrollment_postcondition()

    verify_remote.assert_called_once()
    assert anchor.load_head_anchor_startup_snapshot.call_count == 3
    signer.sign_ed25519.assert_not_called()
    provider.upload_object_no_overwrite.assert_not_called()
    anchor.commit_prepared_intent.assert_not_called()


def test_first_enrollment_postcondition_rejects_local_advance_during_remote_audit() -> None:
    local, anchor, provider, signer, verifier = _dependencies()
    candidate = _enrollment_candidate()
    receipt = _enrollment_receipt(candidate)
    prior = _confirmed_postcondition_snapshot(receipt)
    before_remote = _confirmed_postcondition_snapshot(receipt)
    after_remote = _confirmed_postcondition_snapshot(
        receipt,
        current_host_head_sha256="0" * 64,
    )
    anchor.load_head_anchor_startup_snapshot.side_effect = (
        prior,
        before_remote,
        after_remote,
    )
    attempt = _attempt(local, anchor, provider, signer, verifier)
    attempt.prime_startup()

    with (
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "verify_bounded_first_enrollment_remote_postcondition",
            return_value="7" * 64,
        ) as verify_remote,
        pytest.raises(TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed),
    ):
        attempt.reauthenticate_first_enrollment_postcondition()

    verify_remote.assert_called_once()
    signer.sign_ed25519.assert_not_called()
    provider.upload_object_no_overwrite.assert_not_called()
    anchor.commit_prepared_intent.assert_not_called()


def test_post_enrollment_successor_allows_authenticated_probe_suffixes() -> None:
    local, anchor, provider, signer, verifier = _dependencies()
    record = _post_enrollment_record()
    receipt = _post_enrollment_receipt(record)
    primed = _post_enrollment_snapshot(receipt)
    before_remote = _post_enrollment_snapshot(
        receipt,
        local_transition_count=3,
        current_local_host_head_sha256="a" * 64,
    )
    after_remote = _post_enrollment_snapshot(
        receipt,
        local_transition_count=4,
        current_local_host_head_sha256="b" * 64,
    )
    anchor.load_head_anchor_startup_snapshot.side_effect = (
        primed,
        before_remote,
        after_remote,
    )
    attempt = _attempt(local, anchor, provider, signer, verifier)
    attempt.prime_startup()

    assert before_remote.complete_replay is True
    assert before_remote.confirmed_anchor_records == ()

    with patch(
        "apps.trusted_time_supervisor.head_anchor_attempt."
        "verify_bounded_post_enrollment_start_remote_postcondition",
        return_value="0" * 64,
    ) as verify_remote:
        observed = attempt.reauthenticate_post_enrollment_start_successor()

    assert observed == _post_enrollment_postcondition(local_transition_count=4)
    assert observed.current_host_head_sha256 == record.current_host_head_sha256
    assert observed.current_host_head_sha256 != after_remote.current_host_head_sha256
    verify_remote.assert_called_once_with(
        before_remote.authenticated_journal_tip,
        provider=provider,
        verifier=verifier,
        signing_key_id=_authority().signing_key_id,
        signing_public_key_sha256=_authority().signing_public_key_sha256,
        checkpoint_interval_seconds=TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
        anchor_authority_sha256=_authority().anchor_authority_sha256,
    )
    signer.sign_ed25519.assert_not_called()
    provider.upload_object_no_overwrite.assert_not_called()
    anchor.commit_prepared_intent.assert_not_called()
    anchor.confirm_remote_readback_from_snapshot.assert_not_called()
    for field_name in (
        "alert_delivery_authorized",
        "arming_authorized",
        "automatic_rearm_authorized",
        "automatic_resume_authorized",
        "broker_action_authorized",
        "exposure_authorized",
        "live_trading_authorized",
        "new_exposure_authorized",
        "operational_control_authorized",
        "paper_trading_authorized",
        "readiness_authorized",
        "rearm_authorized",
    ):
        assert getattr(observed, field_name) is False
    for raw_identity_field in ("host_id", "principal_id", "bucket_name"):
        assert not hasattr(observed, raw_identity_field)


def test_post_enrollment_start_successor_converts_provider_outage_to_fixed_fatal_recovery() -> None:
    local, anchor, provider, signer, verifier = _dependencies()
    receipt = _post_enrollment_receipt(_post_enrollment_record())
    primed = _post_enrollment_snapshot(receipt)
    before_remote = _post_enrollment_snapshot(receipt)
    anchor.load_head_anchor_startup_snapshot.side_effect = (primed, before_remote)
    attempt = _attempt(local, anchor, provider, signer, verifier)
    attempt.prime_startup()

    with (
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "verify_bounded_post_enrollment_start_remote_postcondition",
            side_effect=TrustedTimeHeadAnchorProviderUnavailable("secret provider detail"),
        ),
        pytest.raises(
            TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed
        ) as captured,
    ):
        attempt.reauthenticate_post_enrollment_start_successor()

    assert type(captured.value) is (
        TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed
    )
    assert isinstance(captured.value, TrustedTimeHeadAnchorFatalFailure)
    assert not isinstance(captured.value, TrustedTimeHeadAnchorTransientFailure)
    assert str(captured.value) == (
        "trusted-time post-enrollment start postconditions are unconfirmed"
    )
    assert "secret" not in str(captured.value)
    assert anchor.load_head_anchor_startup_snapshot.call_count == 2
    anchor.compact_head_anchor_snapshot.assert_not_called()


@pytest.mark.parametrize(
    "case",
    (
        "sequence_three",
        "local_count_rollback",
        "terminal_receipt_drift",
        "terminal_ordinal_drift",
        "same_count_head_drift",
        "epoch_rotated",
    ),
)
def test_post_enrollment_start_successor_rejects_terminal_or_monotonicity_drift(
    case: str,
) -> None:
    local, anchor, provider, signer, verifier = _dependencies()
    record = _post_enrollment_record()
    receipt = _post_enrollment_receipt(record)
    primed = _post_enrollment_snapshot(receipt)
    before_remote = _post_enrollment_snapshot(
        receipt,
        local_transition_count=3,
        current_local_host_head_sha256="a" * 64,
    )
    if case == "sequence_three":
        final_snapshot = _post_enrollment_snapshot(
            receipt,
            local_transition_count=3,
            current_local_host_head_sha256="a" * 64,
            confirmed_anchor_count=3,
        )
    elif case == "local_count_rollback":
        final_snapshot = _post_enrollment_snapshot(receipt, local_transition_count=2)
    elif case == "terminal_receipt_drift":
        final_snapshot = _post_enrollment_snapshot(
            _post_enrollment_receipt(
                record,
                receipt_semantic_sha256="c" * 64,
            ),
            local_transition_count=3,
            current_local_host_head_sha256="a" * 64,
        )
    elif case == "terminal_ordinal_drift":
        final_snapshot = _post_enrollment_snapshot(
            receipt,
            local_transition_count=3,
            terminal_ordinal=3,
            current_local_host_head_sha256="a" * 64,
        )
    elif case == "epoch_rotated":
        final_snapshot = _post_enrollment_snapshot(
            receipt,
            local_transition_count=4,
            current_local_host_head_sha256="b" * 64,
            current_transition_overrides={
                "epoch_sequence": 3,
                "monitor_epoch_id": "32345678-1234-4234-9234-123456789abc",
                "epoch_sha256": "f" * 64,
                "evaluation_sequence": 0,
            },
        )
    else:
        assert case == "same_count_head_drift"
        final_snapshot = _post_enrollment_snapshot(
            receipt,
            local_transition_count=3,
            current_local_host_head_sha256="b" * 64,
        )
    anchor.load_head_anchor_startup_snapshot.side_effect = (
        primed,
        before_remote,
        final_snapshot,
    )
    attempt = _attempt(local, anchor, provider, signer, verifier)
    attempt.prime_startup()

    with (
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "verify_bounded_post_enrollment_start_remote_postcondition",
            return_value="0" * 64,
        ) as verify_remote,
        pytest.raises(TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed),
    ):
        attempt.reauthenticate_post_enrollment_start_successor()

    verify_remote.assert_called_once()
    signer.sign_ed25519.assert_not_called()
    provider.upload_object_no_overwrite.assert_not_called()
    anchor.commit_prepared_intent.assert_not_called()


def test_post_enrollment_start_successor_rejects_a_preexisting_new_epoch_before_remote_io() -> None:
    local, anchor, provider, signer, verifier = _dependencies()
    receipt = _post_enrollment_receipt(_post_enrollment_record())
    primed = _post_enrollment_snapshot(receipt)
    next_epoch = _post_enrollment_snapshot(
        receipt,
        local_transition_count=3,
        current_local_host_head_sha256="a" * 64,
        current_transition_overrides={
            "epoch_sequence": 3,
            "monitor_epoch_id": "32345678-1234-4234-9234-123456789abc",
            "epoch_sha256": "f" * 64,
            "evaluation_sequence": 0,
        },
    )
    anchor.load_head_anchor_startup_snapshot.side_effect = (primed, next_epoch)
    attempt = _attempt(local, anchor, provider, signer, verifier)
    attempt.prime_startup()

    with (
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "verify_bounded_post_enrollment_start_remote_postcondition"
        ) as verify_remote,
        pytest.raises(TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed),
    ):
        attempt.reauthenticate_post_enrollment_start_successor()

    verify_remote.assert_not_called()
    signer.sign_ed25519.assert_not_called()
    provider.upload_object_no_overwrite.assert_not_called()


def test_post_enrollment_start_successor_rejects_pending_intent_before_remote_io() -> None:
    local, anchor, provider, signer, verifier = _dependencies()
    receipt = _post_enrollment_receipt(_post_enrollment_record())
    primed = _post_enrollment_snapshot(receipt)
    pending = _post_enrollment_snapshot(receipt, pending=object())
    anchor.load_head_anchor_startup_snapshot.side_effect = (primed, pending)
    attempt = _attempt(local, anchor, provider, signer, verifier)
    attempt.prime_startup()

    with (
        patch(
            "apps.trusted_time_supervisor.head_anchor_attempt."
            "verify_bounded_post_enrollment_start_remote_postcondition"
        ) as verify_remote,
        pytest.raises(TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed),
    ):
        attempt.reauthenticate_post_enrollment_start_successor()

    verify_remote.assert_not_called()
    signer.sign_ed25519.assert_not_called()
    provider.upload_object_no_overwrite.assert_not_called()


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("anchor_sequence", True),
        ("confirmed_anchor_count", True),
        ("local_transition_count", True),
        ("confirmed_anchor_local_transition_ordinal", 5),
        ("remote_object_count", True),
        ("candidate_remote_readback_sha256", "f" * 64),
        ("full_audit_completed", 1),
        ("pending_intent_present", 0),
    ],
)
def test_post_enrollment_start_postcondition_rejects_nonexact_projection(
    field_name: str,
    value: object,
) -> None:
    with pytest.raises(
        TrustedTimeHeadAnchorPostEnrollmentStartPostconditionsUnconfirmed,
        match="post-enrollment start postconditions are unconfirmed",
    ):
        replace(_post_enrollment_postcondition(), **{field_name: value})
