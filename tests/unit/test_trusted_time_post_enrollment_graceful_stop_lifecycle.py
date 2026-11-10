from __future__ import annotations

import copy
import fcntl
import gc
import hashlib
import json
import os
import pickle
import threading
import weakref
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import pytest

import packages.adapters.trusted_time.ed25519_graceful_stop_operator_attestation as verifier_adapter
import scripts.trusted_time_post_enrollment_graceful_stop_lifecycle as lifecycle
import scripts.trusted_time_post_enrollment_shutdown_locator as shutdown_locator
from packages.adapters.trusted_time.ed25519_graceful_stop_operator_attestation import (
    TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerification,
)
from packages.domain.trusted_time_enrollment_evidence import (
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_graceful_stop_operator_attestation import (
    TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope,
    build_post_enrollment_graceful_stop_operator_attestation_envelope,
    build_post_enrollment_graceful_stop_operator_attestation_statement,
    decode_post_enrollment_graceful_stop_operator_attestation_envelope,
)
from packages.domain.trusted_time_post_enrollment_graceful_stop_operator_authority import (
    build_post_enrollment_graceful_stop_operator_authority,
)
from scripts.trusted_time_post_enrollment_graceful_stop import (
    POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS,
    TrustedTimePostEnrollmentGracefulStopDecision,
    decode_post_enrollment_graceful_stop_decision,
)
from tests.unit import (
    test_trusted_time_post_enrollment_graceful_stop_operator_attestation_artifacts as artifact_fx,
)

PUBLIC_KEY = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
SIGNATURE = bytes(range(64))


@dataclass(frozen=True, slots=True)
class _Evidence:
    authority_artifact_sha256: str
    decision_encoded: bytes
    envelope_encoded: bytes
    operator_attestation_signature_sha256: str
    operator_attestation_statement_sha256: str
    public_key_sha256: str


@dataclass(frozen=True, slots=True)
class _Inputs:
    ignored_root: Path
    artifact_directory: Path
    decision: TrustedTimePostEnrollmentGracefulStopDecision
    envelope: TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope
    verification: TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerification


@pytest.fixture(scope="module")
def base_evidence() -> _Evidence:
    decision = decode_post_enrollment_graceful_stop_decision(artifact_fx._fixed_decision_bytes())
    authority = build_post_enrollment_graceful_stop_operator_authority(PUBLIC_KEY)
    statement = build_post_enrollment_graceful_stop_operator_attestation_statement(
        authority=authority,
        graceful_stop_decision_v1_sha256=decision.decision_sha256,
        graceful_stop_operation_id=decision.operation_id,
        graceful_stop_target_sha256=decision.target.target_sha256,
    )
    envelope = build_post_enrollment_graceful_stop_operator_attestation_envelope(
        graceful_stop_decision_v1=decision.encoded,
        statement=statement,
        signature_ed25519=SIGNATURE,
    )
    verification = TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerification(
        authority_artifact_sha256=authority.authority_sha256,
        public_key_sha256=authority.public_key_sha256,
        graceful_stop_decision_v1_sha256=decision.decision_sha256,
        graceful_stop_operation_id=decision.operation_id,
        graceful_stop_target_sha256=decision.target.target_sha256,
        operator_attestation_statement_sha256=statement.statement_sha256,
        operator_attestation_signature_sha256=hashlib.sha256(SIGNATURE).hexdigest(),
        operator_attestation_envelope_sha256=envelope.envelope_sha256,
        _construction_capability=(verifier_adapter._VERIFICATION_RESULT_CONSTRUCTION_CAPABILITY),
    )
    return _Evidence(
        authority_artifact_sha256=verification.authority_artifact_sha256,
        decision_encoded=decision.encoded,
        envelope_encoded=envelope.encoded,
        operator_attestation_signature_sha256=(verification.operator_attestation_signature_sha256),
        operator_attestation_statement_sha256=(verification.operator_attestation_statement_sha256),
        public_key_sha256=verification.public_key_sha256,
    )


def _inputs(base_evidence: _Evidence, tmp_path: Path, *, name: str = "lifecycle") -> _Inputs:
    decision = decode_post_enrollment_graceful_stop_decision(base_evidence.decision_encoded)
    envelope = decode_post_enrollment_graceful_stop_operator_attestation_envelope(
        base_evidence.envelope_encoded
    )
    verification = TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerification(
        authority_artifact_sha256=base_evidence.authority_artifact_sha256,
        public_key_sha256=base_evidence.public_key_sha256,
        graceful_stop_decision_v1_sha256=decision.decision_sha256,
        graceful_stop_operation_id=decision.operation_id,
        graceful_stop_target_sha256=decision.target.target_sha256,
        operator_attestation_statement_sha256=(base_evidence.operator_attestation_statement_sha256),
        operator_attestation_signature_sha256=(base_evidence.operator_attestation_signature_sha256),
        operator_attestation_envelope_sha256=envelope.envelope_sha256,
        _construction_capability=(verifier_adapter._VERIFICATION_RESULT_CONSTRUCTION_CAPABILITY),
    )
    ignored_root = tmp_path / name
    ignored_root.mkdir(mode=0o700)
    artifact_directory = ignored_root / "trusted-time"
    artifact_directory.mkdir(mode=0o700)
    return _Inputs(
        ignored_root=ignored_root,
        artifact_directory=artifact_directory,
        decision=decision,
        envelope=envelope,
        verification=verification,
    )


def _repository(inputs: _Inputs) -> Any:
    return lifecycle._build_post_enrollment_graceful_stop_lifecycle_repository(
        ignored_root=inputs.ignored_root
    )


def _reserve(inputs: _Inputs, repository: Any) -> Any:
    return repository._reserve_attempt(
        decision=inputs.decision,
        envelope=inputs.envelope,
        verification=inputs.verification,
    )


def _mutated_ordinal(encoded: bytes, ordinal: bool) -> bytes:
    payload = json.loads(encoded)
    payload["progress_ordinal"] = ordinal
    return canonical_first_enrollment_json_bytes(payload)


def test_attempt_validation_work_is_operation_scoped(
    base_evidence: _Evidence,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _inputs(base_evidence, tmp_path)
    repository = _repository(inputs)
    counts = {"topology": 0, "envelope": 0, "decision": 0, "locator": 0}

    original_topology = shutdown_locator._validate_persistent_topology_payload
    original_envelope = lifecycle.decode_post_enrollment_graceful_stop_operator_attestation_envelope
    original_decision = lifecycle.decode_post_enrollment_graceful_stop_decision
    original_locator = lifecycle.decode_post_enrollment_graceful_stop_shutdown_locator

    def count_topology(payload: object) -> Any:
        counts["topology"] += 1
        return original_topology(payload)

    def count_envelope(encoded: object) -> Any:
        counts["envelope"] += 1
        return original_envelope(encoded)

    def count_decision(encoded: object) -> Any:
        counts["decision"] += 1
        return original_decision(encoded)

    def count_locator(encoded: object) -> Any:
        counts["locator"] += 1
        return original_locator(encoded)

    monkeypatch.setattr(shutdown_locator, "_validate_persistent_topology_payload", count_topology)
    monkeypatch.setattr(
        lifecycle,
        "decode_post_enrollment_graceful_stop_operator_attestation_envelope",
        count_envelope,
    )
    monkeypatch.setattr(lifecycle, "decode_post_enrollment_graceful_stop_decision", count_decision)
    monkeypatch.setattr(
        lifecycle,
        "decode_post_enrollment_graceful_stop_shutdown_locator",
        count_locator,
    )

    attempt = _reserve(inputs, repository)
    initial_reserve_counts = counts.copy()
    assert 0 < initial_reserve_counts["topology"] <= 1_400
    assert all(
        1 <= initial_reserve_counts[name] <= 3 for name in ("envelope", "decision", "locator")
    )

    counts.update(dict.fromkeys(counts, 0))
    attempt.record.payload()
    assert 0 < counts["topology"] <= 400
    assert {name: counts[name] for name in ("envelope", "decision", "locator")} == {
        "envelope": 1,
        "decision": 1,
        "locator": 1,
    }

    counts.update(dict.fromkeys(counts, 0))
    lifecycle.canonical_post_enrollment_graceful_stop_attempt_bytes(attempt.record)
    assert 0 < counts["topology"] <= 400
    assert {name: counts[name] for name in ("envelope", "decision", "locator")} == {
        "envelope": 1,
        "decision": 1,
        "locator": 1,
    }

    replay_repository = _repository(inputs)
    counts.update(dict.fromkeys(counts, 0))
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopAttemptConsumed):
        _reserve(inputs, replay_repository)
    assert 0 < counts["topology"] <= 1_400
    assert all(1 <= counts[name] <= 3 for name in ("envelope", "decision", "locator"))


def test_attempt_validation_is_fresh_after_exact_nested_tamper(
    base_evidence: _Evidence,
    tmp_path: Path,
) -> None:
    inputs = _inputs(base_evidence, tmp_path)
    record = _reserve(inputs, _repository(inputs)).record
    record.payload()
    object.__setattr__(record, "_locator_encoded", b"{}\n")
    object.__setattr__(record, "_sealed_fields", record._seal_values())
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
        record.payload()


def test_exact_append_only_chain_round_trips_and_never_opens_authority(
    base_evidence: _Evidence,
    tmp_path: Path,
) -> None:
    inputs = _inputs(base_evidence, tmp_path)
    initial = lifecycle.inspect_post_enrollment_graceful_stop_recovery_state(
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert (
        initial.status
        is lifecycle.TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.UNRESERVED
    )
    assert initial.recovery_required is False
    assert initial.retry_authorized is False

    repository = _repository(inputs)
    attempt = _reserve(inputs, repository)
    attempt_path = (
        inputs.artifact_directory / lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME
    )
    assert attempt_path.read_bytes() == attempt.encoded
    assert attempt_path.stat().st_mode & 0o777 == 0o600
    assert attempt.record.payload()["progress_ordinal"] == 0
    assert attempt.record.payload()["operator_attestation_envelope"] == inputs.envelope.payload()
    assert attempt.record.payload()["durable_shutdown_locator"] == (
        inputs.decision.target.durable_shutdown_locator.payload()
    )
    assert attempt.record.payload()["predecessor_record_sha256"] is None
    assert all(
        attempt.record.payload()[name] is False
        for name in POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS
    )
    first_decode = lifecycle.decode_post_enrollment_graceful_stop_attempt_bytes(attempt.encoded)
    second_decode = lifecycle.decode_post_enrollment_graceful_stop_attempt_bytes(attempt.encoded)
    assert first_decode is not second_decode
    assert first_decode != second_decode
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
        lifecycle.decode_post_enrollment_graceful_stop_attempt_bytes(
            _mutated_ordinal(attempt.encoded, False)
        )

    root_state = lifecycle.inspect_post_enrollment_graceful_stop_recovery_state(
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert (
        root_state.status
        is lifecycle.TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.RECOVERY_REQUIRED
    )
    assert root_state.attempt is not None and root_state.progress is None
    assert root_state.retry_authorized is False

    progress = repository._retain_bridge_required_progress(attempt)
    assert progress.record.payload()["phase"] == "operation_bound_supervisor_bridge_required"
    assert progress.record.payload()["operation_bound_supervisor_bridge_available"] is False
    assert progress.record.predecessor_record_sha256 == attempt.artifact_sha256
    assert progress.record.attempt_slot_sha256 == attempt.artifact_sha256
    assert lifecycle.decode_post_enrollment_graceful_stop_progress_bytes(progress.encoded) != (
        lifecycle.decode_post_enrollment_graceful_stop_progress_bytes(progress.encoded)
    )
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
        lifecycle.decode_post_enrollment_graceful_stop_progress_bytes(
            _mutated_ordinal(progress.encoded, True)
        )
    progressed_replay_repository = _repository(inputs)
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed):
        _reserve(inputs, progressed_replay_repository)
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
        _reserve(inputs, progressed_replay_repository)

    orphan_outcome_record = cast(Any, lifecycle)._new_outcome_record(
        attempt.record,
        progress.record,
    )
    orphan_outcome_path = inputs.artifact_directory / cast(Any, lifecycle)._outcome_file_name(
        orphan_outcome_record.record_sha256
    )
    orphan_outcome_path.write_bytes(orphan_outcome_record.encoded)
    orphan_outcome_path.chmod(0o600)
    orphan_outcome_state = lifecycle.inspect_post_enrollment_graceful_stop_recovery_state(
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert orphan_outcome_state.status is (
        lifecycle.TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.RETENTION_UNCONFIRMED
    )
    assert orphan_outcome_state.attempt is None
    assert orphan_outcome_state.progress is None
    assert orphan_outcome_state.outcome is None
    orphan_outcome_path.unlink()

    outcome = repository._retain_recovery_required_outcome(attempt, progress)
    assert outcome.record.payload()["qualified"] is False
    assert outcome.record.payload()["recovery_required"] is True
    assert outcome.record.payload()["retry_authorized"] is False
    assert outcome.record.payload()["terminal_outcome_success_confirmed"] is False
    assert outcome.record.payload()["latest_progress_record_sha256"] == progress.artifact_sha256
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
        lifecycle.decode_post_enrollment_graceful_stop_outcome_bytes(
            _mutated_ordinal(outcome.encoded, True)
        )
    terminal_replay_repository = _repository(inputs)
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed):
        _reserve(inputs, terminal_replay_repository)
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
        _reserve(inputs, terminal_replay_repository)

    for staging_name in (
        lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_STAGING_FILE_NAME,
        lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_COMMIT_STAGING_FILE_NAME,
    ):
        staging_path = inputs.artifact_directory / staging_name
        staging_path.write_bytes(b"partial\n")
        staging_path.chmod(0o600)
        staging_state = lifecycle.inspect_post_enrollment_graceful_stop_recovery_state(
            artifact_directory=inputs.artifact_directory,
            ignored_root=inputs.ignored_root,
        )
        assert staging_state.status is (
            lifecycle.TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.RETENTION_UNCONFIRMED
        )
        assert staging_state.attempt is None
        assert staging_state.progress is None
        assert staging_state.outcome is None
        staging_path.unlink()

    final = lifecycle.inspect_post_enrollment_graceful_stop_recovery_state(
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert final.status is (
        lifecycle.TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.TERMINAL_OUTCOME_RETAINED
    )
    assert final.terminal_outcome_retained is True
    assert final.continuation_authorized is False
    assert lifecycle.revalidate_retained_post_enrollment_graceful_stop_attempt(
        attempt,
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert lifecycle.revalidate_retained_post_enrollment_graceful_stop_progress(
        progress,
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert lifecycle.revalidate_retained_post_enrollment_graceful_stop_outcome(
        outcome,
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )


def test_fixed_root_is_permanently_consumed_and_partial_evidence_is_withheld(
    base_evidence: _Evidence,
    tmp_path: Path,
) -> None:
    inputs = _inputs(base_evidence, tmp_path)
    attempt = _reserve(inputs, _repository(inputs))
    second = _repository(inputs)
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopAttemptConsumed):
        _reserve(inputs, second)
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
        _reserve(inputs, second)

    staging = (
        inputs.artifact_directory
        / lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_STAGING_FILE_NAME
    )
    staging.write_bytes(b"partial\n")
    staging.chmod(0o600)
    state = lifecycle.inspect_post_enrollment_graceful_stop_recovery_state(
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert (
        state.status
        is lifecycle.TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.RETENTION_UNCONFIRMED
    )
    assert state.attempt is None and state.progress is None and state.outcome is None
    assert state.recovery_required is True and state.retry_authorized is False
    assert attempt.artifact_path.exists()
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable):
        lifecycle.load_retained_post_enrollment_graceful_stop_attempt(
            artifact_directory=inputs.artifact_directory,
            ignored_root=inputs.ignored_root,
        )

    corrupt = _inputs(base_evidence, tmp_path, name="corrupt-root")
    corrupt_path = (
        corrupt.artifact_directory / lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME
    )
    corrupt_path.write_bytes(b"{}\n")
    corrupt_path.chmod(0o600)
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed):
        _reserve(corrupt, _repository(corrupt))
    assert corrupt_path.read_bytes() == b"{}\n"


def test_exact_receipt_identity_replay_thread_pid_and_object_seals(
    base_evidence: _Evidence,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _inputs(base_evidence, tmp_path)
    repository = _repository(inputs)
    attempt = _reserve(inputs, repository)
    loaded = lifecycle.load_retained_post_enrollment_graceful_stop_attempt(
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert loaded is not attempt and loaded != attempt
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
        repository._retain_bridge_required_progress(loaded)
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
        repository._retain_bridge_required_progress(attempt)

    for operation in (
        lambda: copy.copy(attempt),
        lambda: copy.deepcopy(attempt),
        lambda: pickle.dumps(attempt),
        lambda: copy.copy(repository),
        lambda: copy.deepcopy(repository),
        lambda: pickle.dumps(repository),
    ):
        with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
            operation()

    thread_root = tmp_path / "thread"
    thread_root.mkdir(mode=0o700)
    (thread_root / "trusted-time").mkdir(mode=0o700)
    thread_repository = lifecycle._build_post_enrollment_graceful_stop_lifecycle_repository(
        ignored_root=thread_root
    )
    thread_attempt = _reserve(
        _Inputs(
            thread_root,
            thread_root / "trusted-time",
            inputs.decision,
            inputs.envelope,
            inputs.verification,
        ),
        thread_repository,
    )
    errors: list[BaseException] = []

    def cross_thread() -> None:
        try:
            thread_repository._retain_bridge_required_progress(thread_attempt)
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=cross_thread)
    worker.start()
    worker.join()
    assert len(errors) == 1
    assert type(errors[0]) is lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
        thread_repository._retain_bridge_required_progress(thread_attempt)

    pid_root = tmp_path / "pid"
    pid_root.mkdir(mode=0o700)
    (pid_root / "trusted-time").mkdir(mode=0o700)
    pid_repository = lifecycle._build_post_enrollment_graceful_stop_lifecycle_repository(
        ignored_root=pid_root
    )
    pid_attempt = _reserve(
        _Inputs(
            pid_root,
            pid_root / "trusted-time",
            inputs.decision,
            inputs.envelope,
            inputs.verification,
        ),
        pid_repository,
    )

    class _ForbiddenLock:
        def __enter__(self) -> None:
            raise AssertionError("inherited process lock was touched")

        def __exit__(self, *_: object) -> None:
            return None

    real_getpid = os.getpid
    module_os = cast(Any, lifecycle).os
    with monkeypatch.context() as context:
        context.setattr(module_os, "getpid", lambda: real_getpid() + 1)
        context.setattr(lifecycle, "_PROCESS_LOCK", _ForbiddenLock())
        with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
            pid_repository._retain_bridge_required_progress(pid_attempt)


def test_fault_after_exclusive_create_is_unconfirmed_and_never_retryable(
    base_evidence: _Evidence,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _inputs(base_evidence, tmp_path)
    repository = _repository(inputs)
    module_os = cast(Any, lifecycle).os
    with monkeypatch.context() as context:
        context.setattr(module_os, "fsync", lambda _descriptor: (_ for _ in ()).throw(OSError()))
        with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed):
            _reserve(inputs, repository)
    assert (
        inputs.artifact_directory / lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME
    ).exists()
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopAttemptConsumed):
        _reserve(inputs, _repository(inputs))
    state = lifecycle.inspect_post_enrollment_graceful_stop_recovery_state(
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert (
        state.status
        is lifecycle.TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.RECOVERY_REQUIRED
    )
    assert state.attempt is not None
    assert state.attempt.artifact_path == (
        inputs.artifact_directory / lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME
    )
    assert state.retry_authorized is False


def test_paths_inventory_nested_state_and_registry_tamper_fail_closed(
    base_evidence: _Evidence,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _inputs(base_evidence, tmp_path)
    repository = _repository(inputs)
    attempt = _reserve(inputs, repository)
    progress = repository._retain_bridge_required_progress(attempt)
    repository._retain_recovery_required_outcome(attempt, progress)
    state = lifecycle.inspect_post_enrollment_graceful_stop_recovery_state(
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert state.outcome is not None
    object.__setattr__(state.outcome.record, "attempt_slot_sha256", "0" * 64)
    for property_name in (
        "recovery_required",
        "retry_authorized",
        "continuation_authorized",
        "terminal_outcome_retained",
    ):
        with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
            getattr(state, property_name)

    foreign_root = tmp_path / "foreign"
    foreign_root.mkdir(mode=0o700)
    foreign_artifacts = foreign_root / "trusted-time"
    foreign_artifacts.mkdir(mode=0o700)
    clean_repository = lifecycle._build_post_enrollment_graceful_stop_lifecycle_repository(
        ignored_root=foreign_root
    )
    redirected_root = tmp_path / "redirected"
    redirected_root.mkdir(mode=0o700)
    object.__setattr__(clean_repository, "_ignored_root", redirected_root)
    object.__setattr__(
        clean_repository,
        "_sealed_configuration",
        (
            type(clean_repository),
            redirected_root,
            clean_repository._owner_pid,
            clean_repository._owner_thread_id,
        ),
    )
    redirected_inputs = _Inputs(
        foreign_root,
        foreign_artifacts,
        inputs.decision,
        inputs.envelope,
        inputs.verification,
    )
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
        _reserve(redirected_inputs, clean_repository)
    assert not (redirected_root / "trusted-time").exists()

    symlink_root = tmp_path / "symlink-root"
    symlink_root.mkdir(mode=0o700)
    (symlink_root / "trusted-time").symlink_to(inputs.artifact_directory, target_is_directory=True)
    symlink_state = lifecycle.inspect_post_enrollment_graceful_stop_recovery_state(
        artifact_directory=symlink_root / "trusted-time",
        ignored_root=symlink_root,
    )
    assert (
        symlink_state.status
        is lifecycle.TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.RETENTION_UNCONFIRMED
    )

    bounded_root = tmp_path / "bounded"
    bounded_root.mkdir(mode=0o700)
    bounded_directory = bounded_root / "trusted-time"
    bounded_directory.mkdir(mode=0o700)
    for ordinal in range(lifecycle.MAXIMUM_POST_ENROLLMENT_GRACEFUL_STOP_LIFECYCLE_ENTRIES + 1):
        path = bounded_directory / f"trusted-time-post-enrollment-graceful-stop-junk-{ordinal}"
        path.write_bytes(b"x")
        path.chmod(0o600)
    bounded_state = lifecycle.inspect_post_enrollment_graceful_stop_recovery_state(
        artifact_directory=bounded_directory,
        ignored_root=bounded_root,
    )
    assert (
        bounded_state.status
        is lifecycle.TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.RETENTION_UNCONFIRMED
    )


def test_post_persistence_and_preclose_interruptions_burn_repository(
    base_evidence: _Evidence,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    progress_inputs = _inputs(base_evidence, tmp_path, name="progress-interrupt")
    progress_repository = _repository(progress_inputs)
    progress_attempt = _reserve(progress_inputs, progress_repository)
    real_persist_progress = cast(Any, lifecycle)._persist_progress

    def persist_progress_then_interrupt(*args: object, **kwargs: object) -> Any:
        real_persist_progress(*args, **kwargs)
        raise KeyboardInterrupt

    with monkeypatch.context() as context:
        context.setattr(lifecycle, "_persist_progress", persist_progress_then_interrupt)
        with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed):
            progress_repository._retain_bridge_required_progress(progress_attempt)
    progress_state = lifecycle.inspect_post_enrollment_graceful_stop_recovery_state(
        artifact_directory=progress_inputs.artifact_directory,
        ignored_root=progress_inputs.ignored_root,
    )
    assert progress_state.attempt is not None and progress_state.progress is not None
    assert progress_state.outcome is None and progress_state.retry_authorized is False
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
        progress_repository._retain_bridge_required_progress(progress_attempt)

    outcome_inputs = _inputs(base_evidence, tmp_path, name="outcome-interrupt")
    outcome_repository = _repository(outcome_inputs)
    outcome_attempt = _reserve(outcome_inputs, outcome_repository)
    outcome_progress = outcome_repository._retain_bridge_required_progress(outcome_attempt)
    real_persist_outcome = cast(Any, lifecycle)._persist_outcome

    def persist_outcome_then_interrupt(*args: object, **kwargs: object) -> Any:
        real_persist_outcome(*args, **kwargs)
        raise KeyboardInterrupt

    with monkeypatch.context() as context:
        context.setattr(lifecycle, "_persist_outcome", persist_outcome_then_interrupt)
        with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed):
            outcome_repository._retain_recovery_required_outcome(
                outcome_attempt,
                outcome_progress,
            )
    outcome_state = lifecycle.inspect_post_enrollment_graceful_stop_recovery_state(
        artifact_directory=outcome_inputs.artifact_directory,
        ignored_root=outcome_inputs.ignored_root,
    )
    assert outcome_state.terminal_outcome_retained is True
    assert outcome_state.retry_authorized is False

    preclose_inputs = _inputs(base_evidence, tmp_path, name="preclose-interrupt")
    preclose_repository = _repository(preclose_inputs)
    preclose_attempt = _reserve(preclose_inputs, preclose_repository)
    preclose_progress = preclose_repository._retain_bridge_required_progress(preclose_attempt)
    real_transition = cast(Any, lifecycle)._replace_repository_state

    def transition_then_interrupt(*args: object, **kwargs: object) -> Any:
        real_transition(*args, **kwargs)
        raise KeyboardInterrupt

    with monkeypatch.context() as context:
        context.setattr(lifecycle, "_replace_repository_state", transition_then_interrupt)
        with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed):
            preclose_repository._retain_recovery_required_outcome(
                preclose_attempt,
                preclose_progress,
            )
    preclose_state = lifecycle.inspect_post_enrollment_graceful_stop_recovery_state(
        artifact_directory=preclose_inputs.artifact_directory,
        ignored_root=preclose_inputs.ignored_root,
    )
    assert preclose_state.attempt is not None and preclose_state.progress is not None
    assert preclose_state.outcome is None and preclose_state.retry_authorized is False

    drift_inputs = _inputs(base_evidence, tmp_path, name="terminal-mirror-drift")
    drift_repository = _repository(drift_inputs)
    drift_attempt = _reserve(drift_inputs, drift_repository)
    drift_progress = drift_repository._retain_bridge_required_progress(drift_attempt)
    real_resolve = cast(Any, lifecycle)._registered_repository_state

    def resolve_then_drift(repository: Any) -> Any:
        observed = real_resolve(repository)
        if observed.closed and observed.outcome is not None:
            object.__setattr__(
                repository,
                "_sealed_state",
                (drift_attempt, drift_progress, None, True),
            )
        return observed

    with monkeypatch.context() as context:
        context.setattr(lifecycle, "_registered_repository_state", resolve_then_drift)
        with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed):
            drift_repository._retain_recovery_required_outcome(
                drift_attempt,
                drift_progress,
            )
    drift_state = lifecycle.inspect_post_enrollment_graceful_stop_recovery_state(
        artifact_directory=drift_inputs.artifact_directory,
        ignored_root=drift_inputs.ignored_root,
    )
    assert drift_state.terminal_outcome_retained is True
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
        drift_repository._check_context()


def test_weak_registry_thread_identity_and_cleanup_error_order(
    base_evidence: _Evidence,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cardinality = cast(Any, lifecycle)._repository_state_registry_cardinality
    gc.collect()
    baseline = cardinality()
    unused_inputs = _inputs(base_evidence, tmp_path, name="unused-repository")
    unused_repository = _repository(unused_inputs)
    unused_reference = weakref.ref(unused_repository)
    assert cardinality() == baseline + 1
    gc.collect()
    assert unused_reference() is unused_repository
    assert cardinality() == baseline + 1
    snapshot = cast(Any, unused_repository)._check_context()
    forged_snapshot = snapshot._replace(generation=object())
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
        cast(Any, lifecycle)._replace_repository_state(
            unused_repository,
            forged_snapshot,
            attempt=None,
            progress=None,
            outcome=None,
            closed=False,
        )
    del unused_repository
    gc.collect()
    assert unused_reference() is None
    assert cardinality() == baseline

    burned_inputs = _inputs(base_evidence, tmp_path, name="burned-repository")
    burned_repository = _repository(burned_inputs)
    burned_reference = weakref.ref(burned_repository)
    cast(Any, lifecycle)._burn_repository(burned_repository)
    del burned_repository
    gc.collect()
    assert burned_reference() is None
    assert cardinality() == baseline

    terminal_inputs = _inputs(base_evidence, tmp_path, name="terminal-repository")
    terminal_repository = _repository(terminal_inputs)
    terminal_attempt = _reserve(terminal_inputs, terminal_repository)
    terminal_progress = terminal_repository._retain_bridge_required_progress(terminal_attempt)
    terminal_repository._retain_recovery_required_outcome(
        terminal_attempt,
        terminal_progress,
    )
    terminal_reference = weakref.ref(terminal_repository)
    assert cardinality() == baseline + 1
    del terminal_repository
    gc.collect()
    assert terminal_reference() is None
    assert cardinality() == baseline

    class _ForbiddenLock:
        def __enter__(self) -> None:
            raise AssertionError("inherited process lock was touched")

        def __exit__(self, *_: object) -> None:
            return None

    real_getpid = os.getpid
    fork_inputs = _inputs(base_evidence, tmp_path, name="fork-registration")
    with monkeypatch.context() as context:
        context.setattr(cast(Any, lifecycle).os, "getpid", lambda: real_getpid() + 1)
        context.setattr(lifecycle, "_PROCESS_LOCK", _ForbiddenLock())
        with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
            cardinality()
        with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
            _repository(fork_inputs)

    thread_inputs = _inputs(base_evidence, tmp_path, name="thread-object")
    thread_repository = _repository(thread_inputs)
    replacement_thread = threading.Thread()
    with monkeypatch.context() as context:
        context.setattr(
            cast(Any, lifecycle).threading,
            "current_thread",
            lambda: replacement_thread,
        )
        with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
            thread_repository._check_context()
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
        thread_repository._check_context()

    primary = KeyboardInterrupt()
    first_cleanup = SystemExit()
    second_cleanup = MemoryError()
    observed: list[str] = []

    def fail_first() -> None:
        observed.append("first")
        raise first_cleanup

    def fail_second() -> None:
        observed.append("second")
        raise second_cleanup

    cast(Any, lifecycle)._run_cleanup_operations(primary, (fail_first, fail_second))
    assert observed == ["first", "second"]
    observed.clear()
    with pytest.raises(SystemExit) as raised:
        cast(Any, lifecycle)._run_cleanup_operations(None, (fail_first, fail_second))
    assert raised.value is first_cleanup
    assert observed == ["first", "second"]

    close_calls: list[int] = []
    owner = cast(Any, lifecycle)._OwnedFileDescriptor(987)

    def ambiguous_close(descriptor: int) -> None:
        close_calls.append(descriptor)
        raise KeyboardInterrupt

    with monkeypatch.context() as context:
        context.setattr(cast(Any, lifecycle).os, "close", ambiguous_close)
        with pytest.raises(KeyboardInterrupt):
            owner.close()
        owner.close()
    assert close_calls == [987]


def test_invalid_paths_types_and_secure_flags_invoke_no_callbacks(
    base_evidence: _Evidence,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _inputs(base_evidence, tmp_path, name="callback-gates")
    callbacks: list[str] = []

    class ExplodingPath(type(Path())):  # type: ignore[misc]
        def __fspath__(self) -> str:
            callbacks.append("fspath")
            raise AssertionError

    candidate = ExplodingPath(str(inputs.ignored_root))
    state = lifecycle.inspect_post_enrollment_graceful_stop_recovery_state(
        artifact_directory=cast(Path, candidate),
        ignored_root=inputs.ignored_root,
    )
    assert (
        state.status
        is lifecycle.TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.RETENTION_UNCONFIRMED
    )
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
        lifecycle._build_post_enrollment_graceful_stop_lifecycle_repository(
            ignored_root=cast(Path, candidate)
        )
    assert callbacks == []

    class Sentinel:
        def __post_init__(self) -> None:
            callbacks.append("post_init")
            raise AssertionError

    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
        cast(Any, lifecycle)._new_attempt_record(
            decision=Sentinel(),
            envelope=inputs.envelope,
            verification=inputs.verification,
        )
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
        lifecycle.TrustedTimePostEnrollmentGracefulStopRecoveryState(
            status=(
                lifecycle.TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.RECOVERY_REQUIRED
            ),
            attempt=cast(Any, Sentinel()),
            progress=None,
            outcome=None,
            _construction_capability=cast(Any, lifecycle)._RECEIPT_CONSTRUCTION_CAPABILITY,
        )
    assert callbacks == []

    open_calls: list[object] = []

    def forbidden_open(*args: object, **kwargs: object) -> int:
        open_calls.append((args, kwargs))
        raise AssertionError

    with monkeypatch.context() as context:
        context.setattr(cast(Any, lifecycle).os, "O_NOFOLLOW", 0)
        context.setattr(cast(Any, lifecycle).os, "open", forbidden_open)
        with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable):
            lifecycle.load_retained_post_enrollment_graceful_stop_attempt(
                artifact_directory=inputs.artifact_directory,
                ignored_root=inputs.ignored_root,
            )
    assert open_calls == []


def test_public_load_close_faults_are_typed_and_async_identity_is_preserved(
    base_evidence: _Evidence,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _inputs(base_evidence, tmp_path, name="load-close-faults")
    repository = _repository(inputs)
    attempt = _reserve(inputs, repository)
    repository._retain_bridge_required_progress(attempt)
    owner_type = cast(Any, lifecycle)._OwnedFileDescriptor
    real_close = owner_type.close
    real_load_from_directory = cast(Any, lifecycle)._load_chain_from_directory
    armed: list[BaseException] = []

    def load_then_arm(*args: object, **kwargs: object) -> Any:
        retained = real_load_from_directory(*args, **kwargs)
        armed.append(OSError())
        return retained

    def faulting_close(owner: Any) -> None:
        real_close(owner)
        if armed:
            raise armed.pop()

    with monkeypatch.context() as context:
        context.setattr(lifecycle, "_load_chain_from_directory", load_then_arm)
        context.setattr(owner_type, "close", faulting_close)
        with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable):
            lifecycle.load_retained_post_enrollment_graceful_stop_attempt(
                artifact_directory=inputs.artifact_directory,
                ignored_root=inputs.ignored_root,
            )
        assert not lifecycle.revalidate_retained_post_enrollment_graceful_stop_attempt(
            attempt,
            artifact_directory=inputs.artifact_directory,
            ignored_root=inputs.ignored_root,
        )

    async_error = KeyboardInterrupt()

    def load_then_arm_async(*args: object, **kwargs: object) -> Any:
        retained = real_load_from_directory(*args, **kwargs)
        armed.append(async_error)
        return retained

    with monkeypatch.context() as context:
        context.setattr(lifecycle, "_load_chain_from_directory", load_then_arm_async)
        context.setattr(owner_type, "close", faulting_close)
        with pytest.raises(KeyboardInterrupt) as raised:
            lifecycle.load_retained_post_enrollment_graceful_stop_attempt(
                artifact_directory=inputs.artifact_directory,
                ignored_root=inputs.ignored_root,
            )
    assert raised.value is async_error

    real_read_descriptor = cast(Any, lifecycle)._read_descriptor

    def read_progress_then_arm(*args: object, **kwargs: object) -> Any:
        retained = real_read_descriptor(*args, **kwargs)
        file_name = kwargs.get("file_name")
        if type(file_name) is str and file_name.startswith(
            lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_FILE_PREFIX
        ):
            armed.append(OSError())
        return retained

    with monkeypatch.context() as context:
        context.setattr(lifecycle, "_read_descriptor", read_progress_then_arm)
        context.setattr(owner_type, "close", faulting_close)
        with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable):
            lifecycle.load_retained_post_enrollment_graceful_stop_progress(
                artifact_directory=inputs.artifact_directory,
                ignored_root=inputs.ignored_root,
            )


def test_noncanonical_preexisting_namespace_and_post_open_eexist_are_unconfirmed(
    base_evidence: _Evidence,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    template_inputs = _inputs(base_evidence, tmp_path, name="namespace-template")
    template_record = cast(Any, lifecycle)._new_attempt_record(
        decision=template_inputs.decision,
        envelope=template_inputs.envelope,
        verification=template_inputs.verification,
    )

    for case_name in (
        "root-plus-staging",
        "junk-without-root",
        "orphan-progress",
        "orphan-commit",
        "wrong-mode-root",
        "symlink-root",
        "hardlink-root",
    ):
        inputs = _inputs(base_evidence, tmp_path, name=case_name)
        root_path = (
            inputs.artifact_directory
            / lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME
        )
        if case_name == "root-plus-staging":
            root_path.write_bytes(template_record.encoded)
            root_path.chmod(0o600)
            staging = (
                inputs.artifact_directory
                / lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_STAGING_FILE_NAME
            )
            staging.write_bytes(b"partial\n")
            staging.chmod(0o600)
        elif case_name == "junk-without-root":
            junk = inputs.artifact_directory / ".post-enrollment-graceful-stop-junk"
            junk.write_bytes(b"junk\n")
            junk.chmod(0o600)
        elif case_name == "orphan-progress":
            orphan = inputs.artifact_directory / (
                f"{lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_PROGRESS_FILE_PREFIX}"
                f"{'0' * 64}{lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_FILE_SUFFIX}"
            )
            orphan.write_bytes(b"{}\n")
            orphan.chmod(0o600)
        elif case_name == "orphan-commit":
            orphan = (
                inputs.artifact_directory
                / lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_OUTCOME_COMMIT_FILE_NAME
            )
            orphan.write_bytes(b"{}\n")
            orphan.chmod(0o600)
        elif case_name == "wrong-mode-root":
            root_path.write_bytes(template_record.encoded)
            root_path.chmod(0o644)
        else:
            source = inputs.artifact_directory / "source"
            source.write_bytes(template_record.encoded)
            source.chmod(0o600)
            if case_name == "symlink-root":
                root_path.symlink_to(source)
            else:
                os.link(source, root_path)
        repository = _repository(inputs)
        with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed):
            _reserve(inputs, repository)
        with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
            _reserve(inputs, repository)

    post_open = _inputs(base_evidence, tmp_path, name="post-open-eexist")
    post_open_repository = _repository(post_open)

    def post_open_file_exists(_descriptor: int, _encoded: bytes) -> None:
        raise FileExistsError

    with monkeypatch.context() as context:
        context.setattr(lifecycle, "_write_all", post_open_file_exists)
        with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed):
            _reserve(post_open, post_open_repository)
    post_open_root = (
        post_open.artifact_directory
        / lifecycle.POST_ENROLLMENT_GRACEFUL_STOP_ATTEMPT_SLOT_FILE_NAME
    )
    assert post_open_root.exists() and post_open_root.stat().st_size == 0
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed):
        _reserve(post_open, _repository(post_open))


def test_nonblocking_lock_contention_and_primary_cleanup_identity(
    base_evidence: _Evidence,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _inputs(base_evidence, tmp_path, name="lock-contention")
    repository = _repository(inputs)
    attempt = _reserve(inputs, repository)

    def under_child_lock(path: Path, operation: Any) -> None:
        ready_read, ready_write = os.pipe()
        release_read, release_write = os.pipe()
        child_pid = os.fork()
        if child_pid == 0:
            try:
                os.close(ready_read)
                os.close(release_write)
                descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                os.write(ready_write, b"1")
                os.read(release_read, 1)
                os.close(descriptor)
            finally:
                os._exit(0)
        os.close(ready_write)
        os.close(release_read)
        watchdog_fired = threading.Event()

        def watchdog_release() -> None:
            watchdog_fired.set()
            os.write(release_write, b"1")

        watchdog = threading.Timer(60.0, watchdog_release)
        try:
            assert os.read(ready_read, 1) == b"1"
            watchdog.start()
            operation()
        finally:
            watchdog.cancel()
            watchdog.join()
            if not watchdog_fired.is_set():
                os.write(release_write, b"1")
            os.close(ready_read)
            os.close(release_write)
            _, status = os.waitpid(child_pid, 0)
            assert status == 0
        assert not watchdog_fired.is_set()

    def inspect_contended_directory() -> None:
        state = lifecycle.inspect_post_enrollment_graceful_stop_recovery_state(
            artifact_directory=inputs.artifact_directory,
            ignored_root=inputs.ignored_root,
        )
        assert state.status is (
            lifecycle.TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.RETENTION_UNCONFIRMED
        )

    under_child_lock(inputs.artifact_directory, inspect_contended_directory)

    def load_contended_slot() -> None:
        with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopEvidenceUnavailable):
            lifecycle.load_retained_post_enrollment_graceful_stop_attempt(
                artifact_directory=inputs.artifact_directory,
                ignored_root=inputs.ignored_root,
            )

    under_child_lock(attempt.artifact_path, load_contended_slot)

    def write_during_contended_slot() -> None:
        with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopRetentionUnconfirmed):
            repository._retain_bridge_required_progress(attempt)

    under_child_lock(attempt.artifact_path, write_during_contended_slot)
    with pytest.raises(lifecycle.TrustedTimePostEnrollmentGracefulStopLifecycleRejected):
        repository._retain_bridge_required_progress(attempt)

    directory_owner = cast(Any, lifecycle)._open_owner_only_artifact_directory(
        inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
        create=False,
    )
    primary = KeyboardInterrupt()
    cleanup_events: list[str] = []
    real_flock = fcntl.flock
    owner_type = cast(Any, lifecycle)._OwnedFileDescriptor
    real_close = owner_type.close

    def raise_primary(_descriptor: int) -> frozenset[str]:
        raise primary

    def faulting_flock(descriptor: int, operation: int) -> None:
        if operation == fcntl.LOCK_UN:
            cleanup_events.append("unlock")
            raise SystemExit
        real_flock(descriptor, operation)

    def faulting_close(owner: Any) -> None:
        cleanup_events.append("close")
        real_close(owner)
        raise MemoryError

    with monkeypatch.context() as context:
        context.setattr(cast(Any, lifecycle), "_lifecycle_names", raise_primary)
        context.setattr(cast(Any, lifecycle).fcntl, "flock", faulting_flock)
        context.setattr(owner_type, "close", faulting_close)
        with (
            pytest.raises(KeyboardInterrupt) as raised,
            cast(Any, lifecycle)._locked_attempt_slot(
                directory_owner.fileno(),
                exclusive=False,
            ),
        ):
            raise AssertionError
    directory_owner.close()
    assert raised.value is primary
    assert cleanup_events.count("unlock") == 2
    assert cleanup_events.count("close") == 1


def test_public_surface_has_no_writer_success_signal_or_default_root() -> None:
    assert "_build_post_enrollment_graceful_stop_lifecycle_repository" not in lifecycle.__all__
    assert all("retain_" not in name and "reserve" not in name for name in lifecycle.__all__)
    assert not any("success" in name or "signal" in name for name in lifecycle.__all__)
    for function in (
        lifecycle.load_retained_post_enrollment_graceful_stop_attempt,
        lifecycle.load_retained_post_enrollment_graceful_stop_progress,
        lifecycle.load_retained_post_enrollment_graceful_stop_outcome,
        lifecycle.inspect_post_enrollment_graceful_stop_recovery_state,
    ):
        assert function.__kwdefaults__ in (None, {})
