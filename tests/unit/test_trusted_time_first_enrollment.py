from __future__ import annotations

import json
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest

import apps.trusted_time_supervisor.first_enrollment as enrollment
from apps.trusted_time_supervisor.config import (
    TrustedTimeSupervisorConfigurationError,
)
from apps.trusted_time_supervisor.head_anchor_attempt import (
    TrustedTimeHeadAnchorFirstEnrollmentAlreadyCompleted,
    TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed,
    TrustedTimeHeadAnchorFirstEnrollmentDisposition,
    TrustedTimeHeadAnchorFirstEnrollmentRecoveryRequired,
    TrustedTimeHeadAnchorFirstEnrollmentResult,
    TrustedTimeHeadAnchorFirstEnrollmentStateConflict,
)
from packages.application.trusted_time_head_anchor import (
    TrustedTimeHeadAnchorCheckpointReason,
)
from packages.application.trusted_time_head_anchor_worker import (
    TrustedTimeHeadAnchorFatalFailure,
    TrustedTimeHeadAnchorTransientFailure,
)

BASE = datetime(2026, 8, 8, 16, 0, tzinfo=UTC)
DATABASE_SECRET_CANARY = "postgresql://enrollment-database-secret-canary.invalid"
EXCEPTION_SECRET_CANARY = "enrollment-exception-secret-canary"


def _result(
    *,
    disposition: TrustedTimeHeadAnchorFirstEnrollmentDisposition = (
        TrustedTimeHeadAnchorFirstEnrollmentDisposition.NEW_INTENT_COMPLETED
    ),
) -> TrustedTimeHeadAnchorFirstEnrollmentResult:
    return TrustedTimeHeadAnchorFirstEnrollmentResult(
        anchor_sequence=1,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT,
        current_host_head_sha256="1" * 64,
        current_anchor_sha256="2" * 64,
        current_anchor_semantic_sha256="3" * 64,
        completed_at_utc=BASE,
        full_audit_completed=True,
        completion_disposition=disposition,
        uploaded_anchor_count=(
            None
            if disposition
            is TrustedTimeHeadAnchorFirstEnrollmentDisposition.CONFIRMED_RECEIPT_REOBSERVED
            else 1
        ),
        idempotent_duplicate_count=(
            None
            if disposition
            is TrustedTimeHeadAnchorFirstEnrollmentDisposition.CONFIRMED_RECEIPT_REOBSERVED
            else 0
        ),
        anchor_intent_semantic_sha256="4" * 64,
        candidate_remote_readback_sha256="2" * 64,
        receipt_semantic_sha256="5" * 64,
    )


def _authorities() -> tuple[SimpleNamespace, SimpleNamespace]:
    deployment = SimpleNamespace(
        host_id="trusted-time-host-canary",
        source_authority_sha256="6" * 64,
    )
    anchor = SimpleNamespace(
        anchor_authority_sha256="7" * 64,
        anchor_project_identity_sha256="8" * 64,
        bucket_name="trusted-time-anchor-bucket-canary",
        deployment_identity_sha256="9" * 64,
        host_id="trusted-time-host-canary",
        principal_id="trusted-time-principal-canary",
        runtime_database_identity_sha256="a" * 64,
        signing_key_id="trusted-time-signing-key-v1",
        signing_public_key_sha256="b" * 64,
    )
    return deployment, anchor


def _configuration() -> tuple[SimpleNamespace, SimpleNamespace]:
    deployment, anchor = _authorities()
    return deployment, SimpleNamespace(
        authority=anchor,
        credentials=object(),
        signer=object(),
        verifier=object(),
    )


@pytest.mark.parametrize(
    "mode",
    [
        enrollment.TrustedTimeFirstEnrollmentOperationMode.NEW,
        enrollment.TrustedTimeFirstEnrollmentOperationMode.RECOVER_PENDING,
    ],
)
def test_release_marker_round_trips_exact_mode_with_owner_only_metadata(
    mode: enrollment.TrustedTimeFirstEnrollmentOperationMode,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    release_path = tmp_path / "release"
    monkeypatch.setattr(enrollment, "FIRST_ENROLLMENT_RELEASE_PATH", str(release_path))

    enrollment._write_release(mode)

    assert enrollment._read_exact_release() is mode
    metadata = release_path.stat()
    assert stat.S_ISREG(metadata.st_mode)
    assert stat.S_IMODE(metadata.st_mode) == 0o400
    assert metadata.st_nlink == 1
    assert metadata.st_size == len(enrollment._release_bytes(mode))


def test_release_marker_is_exclusive_and_rejects_tampering_with_fixed_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    release_path = tmp_path / "release"
    monkeypatch.setattr(enrollment, "FIRST_ENROLLMENT_RELEASE_PATH", str(release_path))
    enrollment._write_release(enrollment.TrustedTimeFirstEnrollmentOperationMode.NEW)

    with pytest.raises(TrustedTimeSupervisorConfigurationError) as duplicate:
        enrollment._write_release(
            enrollment.TrustedTimeFirstEnrollmentOperationMode.RECOVER_PENDING
        )
    assert str(duplicate.value) == "trusted-time first enrollment release failed"

    release_path.chmod(0o600)
    with pytest.raises(TrustedTimeSupervisorConfigurationError) as invalid_metadata:
        enrollment._read_exact_release()
    assert str(invalid_metadata.value) == "trusted-time first enrollment release is invalid"

    release_path.chmod(0o600)
    release_path.write_bytes(b"wrong-release-secret-canary\n")
    release_path.chmod(0o400)
    with pytest.raises(TrustedTimeSupervisorConfigurationError) as invalid_payload:
        enrollment._read_exact_release()
    assert str(invalid_payload.value) == "trusted-time first enrollment release is invalid"
    assert "secret-canary" not in str(invalid_payload.value)


def test_release_mode_requires_the_exact_enum_before_writing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    release_path = tmp_path / "release"
    monkeypatch.setattr(enrollment, "FIRST_ENROLLMENT_RELEASE_PATH", str(release_path))

    with pytest.raises(TrustedTimeSupervisorConfigurationError) as captured:
        enrollment._write_release("new")  # type: ignore[arg-type]

    assert str(captured.value) == "trusted-time first enrollment release mode is invalid"
    assert not release_path.exists()


def test_wait_for_release_polls_then_returns_the_exact_observed_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads = iter(
        [
            FileNotFoundError(),
            enrollment.TrustedTimeFirstEnrollmentOperationMode.RECOVER_PENDING,
        ]
    )
    monotonic_values = iter([10.0, 10.1])
    sleeper = Mock()

    def read_release() -> enrollment.TrustedTimeFirstEnrollmentOperationMode:
        observed = next(reads)
        if isinstance(observed, BaseException):
            raise observed
        return observed

    monkeypatch.setattr(enrollment, "_read_exact_release", read_release)

    assert (
        enrollment._wait_for_release(
            monotonic_clock=lambda: next(monotonic_values),
            sleeper=sleeper,
        )
        is enrollment.TrustedTimeFirstEnrollmentOperationMode.RECOVER_PENDING
    )
    sleeper.assert_called_once_with(enrollment.FIRST_ENROLLMENT_RELEASE_POLL_SECONDS)


def test_wait_for_release_times_out_with_a_fixed_secret_free_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monotonic_values = iter([0.0, 0.1, 0.2])
    sleeper = Mock()
    monkeypatch.setattr(enrollment, "FIRST_ENROLLMENT_RELEASE_WAIT_SECONDS", 0.2)
    monkeypatch.setattr(enrollment, "FIRST_ENROLLMENT_RELEASE_POLL_SECONDS", 0.1)
    monkeypatch.setattr(
        enrollment,
        "_read_exact_release",
        Mock(side_effect=FileNotFoundError(EXCEPTION_SECRET_CANARY)),
    )

    with pytest.raises(TrustedTimeSupervisorConfigurationError) as captured:
        enrollment._wait_for_release(
            monotonic_clock=lambda: next(monotonic_values),
            sleeper=sleeper,
        )

    assert str(captured.value) == "trusted-time first enrollment release was not observed"
    assert EXCEPTION_SECRET_CANARY not in str(captured.value)
    assert sleeper.call_args_list == [call(0.1), call(0.1)]


def test_wait_for_release_rejects_a_regressing_monotonic_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monotonic_values = iter([10.0, 9.0])
    monkeypatch.setattr(enrollment, "_read_exact_release", Mock(side_effect=FileNotFoundError))

    with pytest.raises(TrustedTimeSupervisorConfigurationError) as captured:
        enrollment._wait_for_release(
            monotonic_clock=lambda: next(monotonic_values),
            sleeper=lambda _: None,
        )

    assert str(captured.value) == "trusted-time first enrollment release clock regressed"


@pytest.mark.parametrize(
    ("mode", "selected_method", "unselected_method"),
    [
        (
            enrollment.TrustedTimeFirstEnrollmentOperationMode.NEW,
            "perform_first_enrollment",
            "recover_first_enrollment",
        ),
        (
            enrollment.TrustedTimeFirstEnrollmentOperationMode.RECOVER_PENDING,
            "recover_first_enrollment",
            "perform_first_enrollment",
        ),
    ],
)
def test_one_shot_dispatches_only_the_approved_boundary_and_never_the_normal_worker_path(
    mode: enrollment.TrustedTimeFirstEnrollmentOperationMode,
    selected_method: str,
    unselected_method: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, configuration = _configuration()
    evidence = _result(
        disposition=(
            TrustedTimeHeadAnchorFirstEnrollmentDisposition.NEW_INTENT_COMPLETED
            if mode is enrollment.TrustedTimeFirstEnrollmentOperationMode.NEW
            else TrustedTimeHeadAnchorFirstEnrollmentDisposition.PENDING_INTENT_RECOVERED
        )
    )
    engine = Mock()
    provider = Mock()
    attempt = Mock()
    getattr(attempt, selected_method).return_value = evidence
    attempt.verify_first_enrollment_remote_postcondition.return_value = "c" * 64
    engine_factory = Mock(return_value=engine)
    repository_factory = Mock(return_value=object())
    provider_factory = Mock(return_value=provider)
    attempt_factory = Mock(return_value=attempt)
    verify_schema = Mock()
    monkeypatch.setattr(enrollment, "verify_operational_schema", verify_schema)
    monkeypatch.setattr(enrollment, "SqlTrustedTimeHeadAnchorRepository", repository_factory)
    monkeypatch.setattr(
        enrollment,
        "SupabaseStorageTrustedTimeAnchorProvider",
        provider_factory,
    )
    monkeypatch.setattr(
        enrollment,
        "RepositoryBackedTrustedTimeHeadAnchorAttempt",
        attempt_factory,
    )

    execution = enrollment._run_one_shot(
        operation_mode=mode,
        database_url="postgresql://nonsecret.invalid",
        configuration=configuration,
        engine_factory=engine_factory,
    )

    assert execution == enrollment.TrustedTimeFirstEnrollmentExecution(
        operation_mode=mode,
        result=evidence,
        remote_namespace_sha256="c" * 64,
    )
    engine_factory.assert_called_once_with("postgresql://nonsecret.invalid")
    verify_schema.assert_called_once_with(engine, require_phase_zero_facts=False)
    getattr(attempt, selected_method).assert_called_once_with()
    getattr(attempt, unselected_method).assert_not_called()
    attempt.assert_not_called()
    assert attempt.method_calls == [
        call.prime_startup(),
        getattr(call, selected_method)(),
        call.verify_first_enrollment_remote_postcondition(),
        call.close(),
    ]
    provider.close.assert_called_once_with()
    engine.dispose.assert_called_once_with()


@pytest.mark.parametrize("cleanup_name", ["attempt", "provider", "engine"])
def test_cleanup_failure_after_durable_success_preserves_uncertain_evidence_and_closes_all(
    cleanup_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, configuration = _configuration()
    evidence = _result()
    engine = Mock()
    provider = Mock()
    attempt = Mock()
    attempt.perform_first_enrollment.return_value = evidence
    attempt.verify_first_enrollment_remote_postcondition.return_value = "c" * 64
    targets = {
        "attempt": attempt.close,
        "provider": provider.close,
        "engine": engine.dispose,
    }
    targets[cleanup_name].side_effect = RuntimeError(EXCEPTION_SECRET_CANARY)
    monkeypatch.setattr(enrollment, "verify_operational_schema", Mock())
    monkeypatch.setattr(enrollment, "SqlTrustedTimeHeadAnchorRepository", Mock())
    monkeypatch.setattr(
        enrollment,
        "SupabaseStorageTrustedTimeAnchorProvider",
        Mock(return_value=provider),
    )
    monkeypatch.setattr(
        enrollment,
        "RepositoryBackedTrustedTimeHeadAnchorAttempt",
        Mock(return_value=attempt),
    )

    with pytest.raises(
        TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed
    ) as captured:
        enrollment._run_one_shot(
            operation_mode=enrollment.TrustedTimeFirstEnrollmentOperationMode.NEW,
            database_url=DATABASE_SECRET_CANARY,
            configuration=configuration,
            engine_factory=Mock(return_value=engine),
        )

    assert captured.value.evidence is evidence
    assert EXCEPTION_SECRET_CANARY not in str(captured.value)
    attempt.close.assert_called_once_with()
    provider.close.assert_called_once_with()
    engine.dispose.assert_called_once_with()


def test_cleanup_failure_before_durable_success_has_a_fixed_fatal_taxonomy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, configuration = _configuration()
    engine = Mock()
    provider = Mock()
    attempt = Mock()
    attempt.prime_startup.side_effect = RuntimeError(EXCEPTION_SECRET_CANARY)
    provider.close.side_effect = RuntimeError("secondary-cleanup-secret-canary")
    monkeypatch.setattr(enrollment, "verify_operational_schema", Mock())
    monkeypatch.setattr(enrollment, "SqlTrustedTimeHeadAnchorRepository", Mock())
    monkeypatch.setattr(
        enrollment,
        "SupabaseStorageTrustedTimeAnchorProvider",
        Mock(return_value=provider),
    )
    monkeypatch.setattr(
        enrollment,
        "RepositoryBackedTrustedTimeHeadAnchorAttempt",
        Mock(return_value=attempt),
    )

    with pytest.raises(TrustedTimeHeadAnchorFatalFailure) as captured:
        enrollment._run_one_shot(
            operation_mode=enrollment.TrustedTimeFirstEnrollmentOperationMode.NEW,
            database_url=DATABASE_SECRET_CANARY,
            configuration=configuration,
            engine_factory=Mock(return_value=engine),
        )

    assert str(captured.value) == "trusted-time first enrollment cleanup failed"
    assert "secret-canary" not in str(captured.value)
    attempt.close.assert_called_once_with()
    provider.close.assert_called_once_with()
    engine.dispose.assert_called_once_with()


def test_terminal_payload_is_canonical_sanitized_evidence_with_all_authority_false(
    capsys: pytest.CaptureFixture[str],
) -> None:
    deployment, configuration = _configuration()
    evidence = _result()

    payload = enrollment._terminal_payload(
        status="confirmed",
        reason="first_enrollment_confirmed",
        operation_mode=enrollment.TrustedTimeFirstEnrollmentOperationMode.NEW,
        authority=deployment,
        configuration=configuration,
        result=evidence,
        remote_namespace_sha256="c" * 64,
    )
    enrollment._print_payload(payload)
    output = capsys.readouterr().out

    assert output.count("\n") == 1
    assert output == (
        json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )
    decoded = json.loads(output)
    assert decoded["anchor_sequence"] == 1
    assert decoded["checkpoint_reason"] == "enrollment"
    assert decoded["completion_disposition"] == "new_intent_completed"
    assert decoded["full_audit_completed"] is True
    assert decoded["database_secret_disclosed"] is False
    assert decoded["operation_mode"] == "new"
    assert decoded["remote_namespace_sha256"] == "c" * 64
    for field_name in enrollment._AUTHORITY_FIELDS:
        assert decoded[field_name] is False
    for raw_identity in (
        configuration.authority.bucket_name,
        configuration.authority.host_id,
        configuration.authority.principal_id,
    ):
        assert raw_identity not in output


def _install_main_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    *,
    outcome: object,
) -> tuple[SimpleNamespace, SimpleNamespace, Mock]:
    deployment, configuration = _configuration()
    run_one_shot = Mock()
    if isinstance(outcome, BaseException):
        run_one_shot.side_effect = outcome
    else:
        run_one_shot.return_value = outcome
    monkeypatch.setattr(enrollment, "_require_fixed_runtime_paths", Mock())
    monkeypatch.setattr(enrollment, "load_trusted_time_authority", Mock(return_value=deployment))
    monkeypatch.setattr(
        enrollment,
        "load_database_url_secret",
        Mock(return_value=DATABASE_SECRET_CANARY),
    )
    monkeypatch.setattr(
        enrollment,
        "load_trusted_time_head_anchor_runtime_configuration",
        Mock(return_value=configuration),
    )
    monkeypatch.setattr(enrollment, "_record_database_secret_consumed", Mock())
    monkeypatch.setattr(
        enrollment,
        "_wait_for_release",
        Mock(return_value=enrollment.TrustedTimeFirstEnrollmentOperationMode.NEW),
    )
    monkeypatch.setattr(enrollment, "_run_one_shot", run_one_shot)
    return deployment, configuration, run_one_shot


def test_main_emits_confirmed_enrollment_metadata_without_secret_or_authority(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    evidence = _result()
    execution = enrollment.TrustedTimeFirstEnrollmentExecution(
        operation_mode=enrollment.TrustedTimeFirstEnrollmentOperationMode.NEW,
        result=evidence,
        remote_namespace_sha256="c" * 64,
    )
    _, configuration, run_one_shot = _install_main_dependencies(
        monkeypatch,
        outcome=execution,
    )

    enrollment.main()

    output = capsys.readouterr().out
    payload = json.loads(output)
    assert payload["status"] == "confirmed"
    assert payload["reason"] == "first_enrollment_confirmed"
    assert payload["anchor_sequence"] == 1
    assert payload["checkpoint_reason"] == "enrollment"
    assert payload["remote_namespace_sha256"] == "c" * 64
    assert DATABASE_SECRET_CANARY not in output
    for field_name in enrollment._AUTHORITY_FIELDS:
        assert payload[field_name] is False
    run_one_shot.assert_called_once_with(
        operation_mode=enrollment.TrustedTimeFirstEnrollmentOperationMode.NEW,
        database_url=DATABASE_SECRET_CANARY,
        configuration=configuration,
    )


@pytest.mark.parametrize(
    ("error", "reason", "has_evidence"),
    [
        (
            TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed(_result()),
            "first_enrollment_completed_postconditions_unconfirmed",
            True,
        ),
        (
            TrustedTimeHeadAnchorFirstEnrollmentRecoveryRequired(EXCEPTION_SECRET_CANARY),
            "first_enrollment_recovery_required",
            False,
        ),
        (
            TrustedTimeHeadAnchorFirstEnrollmentAlreadyCompleted(EXCEPTION_SECRET_CANARY),
            "first_enrollment_already_completed",
            False,
        ),
        (
            TrustedTimeHeadAnchorTransientFailure(EXCEPTION_SECRET_CANARY),
            "provider_unavailable_before_commit",
            False,
        ),
        (
            TrustedTimeHeadAnchorFirstEnrollmentStateConflict(EXCEPTION_SECRET_CANARY),
            "first_enrollment_precondition_rejected",
            False,
        ),
        (
            TrustedTimeSupervisorConfigurationError(EXCEPTION_SECRET_CANARY),
            "configuration_rejected",
            False,
        ),
        (RuntimeError(EXCEPTION_SECRET_CANARY), "first_enrollment_failed", False),
    ],
)
def test_main_maps_failures_to_fixed_secret_free_terminal_taxonomy(
    error: BaseException,
    reason: str,
    has_evidence: bool,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _install_main_dependencies(monkeypatch, outcome=error)

    with pytest.raises(SystemExit) as captured:
        enrollment.main()

    assert captured.value.code == 2
    output = capsys.readouterr().out
    payload = json.loads(output)
    assert payload["status"] == "fatal"
    assert payload["reason"] == reason
    assert payload["anchor_sequence"] == (1 if has_evidence else None)
    assert payload["database_secret_disclosed"] is False
    assert DATABASE_SECRET_CANARY not in output
    assert EXCEPTION_SECRET_CANARY not in output
    for field_name in enrollment._AUTHORITY_FIELDS:
        assert payload[field_name] is False


@pytest.mark.parametrize(
    ("argv", "expected_mode"),
    [
        (
            ["autoquant-trusted-time-first-enrollment-release"],
            enrollment.TrustedTimeFirstEnrollmentOperationMode.NEW,
        ),
        (
            ["autoquant-trusted-time-first-enrollment-release", "--recover-pending"],
            enrollment.TrustedTimeFirstEnrollmentOperationMode.RECOVER_PENDING,
        ),
    ],
)
def test_release_cli_selects_only_the_explicit_new_or_recovery_marker(
    argv: list[str],
    expected_mode: enrollment.TrustedTimeFirstEnrollmentOperationMode,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = Mock()
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(enrollment, "_write_release", writer)

    enrollment.release_main()

    writer.assert_called_once_with(expected_mode)


def test_release_cli_fails_closed_without_disclosing_writer_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["autoquant-trusted-time-first-enrollment-release"])
    monkeypatch.setattr(
        enrollment,
        "_write_release",
        Mock(side_effect=TrustedTimeSupervisorConfigurationError(EXCEPTION_SECRET_CANARY)),
    )

    with pytest.raises(SystemExit) as captured:
        enrollment.release_main()

    assert captured.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == ""


def test_execution_evidence_rejects_noncanonical_namespace_digest() -> None:
    with pytest.raises(TrustedTimeSupervisorConfigurationError) as captured:
        enrollment.TrustedTimeFirstEnrollmentExecution(
            operation_mode=enrollment.TrustedTimeFirstEnrollmentOperationMode.NEW,
            result=_result(),
            remote_namespace_sha256="C" * 64,
        )

    assert str(captured.value) == "trusted-time first enrollment execution evidence is invalid"


def test_identity_digest_rejects_control_characters_and_has_domain_separation() -> None:
    bucket = enrollment.first_enrollment_identity_sha256(kind="bucket", value="same")
    host = enrollment.first_enrollment_identity_sha256(kind="host", value="same")
    assert bucket != host
    assert len(bucket) == 64

    for invalid in ("", " value", "value\n", "value\x7f"):
        with pytest.raises(TrustedTimeSupervisorConfigurationError):
            enrollment.first_enrollment_identity_sha256(kind="host", value=invalid)

    with pytest.raises(TrustedTimeSupervisorConfigurationError):
        enrollment.first_enrollment_identity_sha256(
            kind="unsupported",  # type: ignore[arg-type]
            value="same",
        )
