"""Approval-gated one-shot trusted-time first enrollment runtime."""

from __future__ import annotations

import argparse
import json
import math
import os
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy import Engine

from apps.trusted_time_supervisor.config import (
    TrustedTimeDeploymentAuthority,
    TrustedTimeSupervisorConfigurationError,
    load_database_url_secret,
    load_trusted_time_authority,
)
from apps.trusted_time_supervisor.head_anchor_attempt import (
    RepositoryBackedTrustedTimeHeadAnchorAttempt,
    TrustedTimeHeadAnchorFirstEnrollmentAlreadyCompleted,
    TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed,
    TrustedTimeHeadAnchorFirstEnrollmentRecoveryRequired,
    TrustedTimeHeadAnchorFirstEnrollmentResult,
    TrustedTimeHeadAnchorFirstEnrollmentStateConflict,
)
from apps.trusted_time_supervisor.head_anchor_config import (
    TrustedTimeHeadAnchorRuntimeConfiguration,
    load_trusted_time_head_anchor_runtime_configuration,
)
from apps.trusted_time_supervisor.main import (
    _create_head_anchor_database_engine,
    _record_database_secret_consumed,
    _require_fixed_runtime_paths,
    _utc_now,
)
from packages.adapters.trusted_time import SupabaseStorageTrustedTimeAnchorProvider
from packages.application.trusted_time_head_anchor_worker import (
    TrustedTimeHeadAnchorFatalFailure,
    TrustedTimeHeadAnchorTransientFailure,
)
from packages.domain.trusted_time_enrollment_evidence import (
    TRUSTED_TIME_FIRST_ENROLLMENT_CONTRACT_VERSION,
    TrustedTimeEnrollmentEvidenceError,
    TrustedTimeFirstEnrollmentOperationMode,
    trusted_time_first_enrollment_identity_sha256,
)
from packages.persistence.database import verify_operational_schema
from packages.persistence.trusted_time_head_anchor import SqlTrustedTimeHeadAnchorRepository

FIRST_ENROLLMENT_RELEASE_PATH = "/tmp/first-enrollment-release"
FIRST_ENROLLMENT_RELEASE_WAIT_SECONDS = 120.0
FIRST_ENROLLMENT_RELEASE_POLL_SECONDS = 0.1
_NEW_RELEASE_BYTES = b"phase6d-one-shot-first-enrollment-release-new-v1\n"
_RECOVERY_RELEASE_BYTES = b"phase6d-one-shot-first-enrollment-release-recovery-v1\n"


@dataclass(frozen=True, slots=True)
class TrustedTimeFirstEnrollmentExecution:
    """Exact one-shot result after SQL and remote postconditions were reauthenticated."""

    operation_mode: TrustedTimeFirstEnrollmentOperationMode
    result: TrustedTimeHeadAnchorFirstEnrollmentResult
    remote_namespace_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.operation_mode) is not TrustedTimeFirstEnrollmentOperationMode
            or type(self.result) is not TrustedTimeHeadAnchorFirstEnrollmentResult
            or type(self.remote_namespace_sha256) is not str
            or len(self.remote_namespace_sha256) != 64
            or any(
                character not in "0123456789abcdef" for character in self.remote_namespace_sha256
            )
        ):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time first enrollment execution evidence is invalid"
            )
        self.result.__post_init__()


_AUTHORITY_FIELDS = (
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
)


def first_enrollment_identity_sha256(*, kind: str, value: str) -> str:
    """Hash one nonsecret identity with an exact domain-separated label."""

    try:
        return trusted_time_first_enrollment_identity_sha256(
            kind=kind,
            value=value,
        )
    except TrustedTimeEnrollmentEvidenceError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment identity binding is invalid"
        ) from None


def _release_bytes(mode: TrustedTimeFirstEnrollmentOperationMode) -> bytes:
    if mode is TrustedTimeFirstEnrollmentOperationMode.NEW:
        return _NEW_RELEASE_BYTES
    if mode is TrustedTimeFirstEnrollmentOperationMode.RECOVER_PENDING:
        return _RECOVERY_RELEASE_BYTES
    raise TrustedTimeSupervisorConfigurationError(
        "trusted-time first enrollment release mode is invalid"
    )


def _write_release(mode: TrustedTimeFirstEnrollmentOperationMode) -> None:
    payload = _release_bytes(mode)
    descriptor: int | None = None
    try:
        descriptor = os.open(
            FIRST_ENROLLMENT_RELEASE_PATH,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError
            view = view[written:]
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    except OSError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment release failed"
        ) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_exact_release() -> TrustedTimeFirstEnrollmentOperationMode:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            FIRST_ENROLLMENT_RELEASE_PATH,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        maximum = max(len(_NEW_RELEASE_BYTES), len(_RECOVERY_RELEASE_BYTES))
        payload = os.read(descriptor, maximum + 1)
        if os.read(descriptor, 1):
            raise OSError
        after = os.fstat(descriptor)
        stable = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) == (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if (
            not stable
            or not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o400
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or before.st_gid != os.getegid()
            or before.st_size != len(payload)
        ):
            raise OSError
    except FileNotFoundError:
        raise
    except OSError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment release is invalid"
        ) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if payload == _NEW_RELEASE_BYTES:
        return TrustedTimeFirstEnrollmentOperationMode.NEW
    if payload == _RECOVERY_RELEASE_BYTES:
        return TrustedTimeFirstEnrollmentOperationMode.RECOVER_PENDING
    raise TrustedTimeSupervisorConfigurationError(
        "trusted-time first enrollment release is invalid"
    )


def _wait_for_release(
    *,
    monotonic_clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> TrustedTimeFirstEnrollmentOperationMode:
    try:
        started = float(monotonic_clock())
    except Exception:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment release clock failed"
        ) from None
    if not math.isfinite(started):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment release clock failed"
        )
    deadline = started + FIRST_ENROLLMENT_RELEASE_WAIT_SECONDS
    observed = started
    while observed < deadline:
        try:
            return _read_exact_release()
        except FileNotFoundError:
            pass
        sleeper(min(FIRST_ENROLLMENT_RELEASE_POLL_SECONDS, deadline - observed))
        try:
            current = float(monotonic_clock())
        except Exception:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time first enrollment release clock failed"
            ) from None
        if not math.isfinite(current) or current < observed:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time first enrollment release clock regressed"
            )
        observed = current
    raise TrustedTimeSupervisorConfigurationError(
        "trusted-time first enrollment release was not observed"
    )


def _run_one_shot(
    *,
    operation_mode: TrustedTimeFirstEnrollmentOperationMode,
    database_url: str,
    configuration: TrustedTimeHeadAnchorRuntimeConfiguration,
    engine_factory: Callable[[str], Engine] = _create_head_anchor_database_engine,
) -> TrustedTimeFirstEnrollmentExecution:
    engine: Engine | None = None
    provider: SupabaseStorageTrustedTimeAnchorProvider | None = None
    attempt: RepositoryBackedTrustedTimeHeadAnchorAttempt | None = None
    result: TrustedTimeHeadAnchorFirstEnrollmentResult | None = None
    remote_namespace_sha256: str | None = None
    primary_error: Exception | None = None
    try:
        engine = engine_factory(database_url)
        verify_operational_schema(engine, require_phase_zero_facts=False)
        authority = configuration.authority
        repository = SqlTrustedTimeHeadAnchorRepository(
            engine,
            verifier=configuration.verifier,
            anchor_authority_sha256=authority.anchor_authority_sha256,
            signing_key_id=authority.signing_key_id,
            signing_public_key_sha256=authority.signing_public_key_sha256,
        )
        provider = SupabaseStorageTrustedTimeAnchorProvider(credentials=configuration.credentials)
        attempt = RepositoryBackedTrustedTimeHeadAnchorAttempt(
            anchor_repository=repository,
            provider=provider,
            signer=configuration.signer,
            verifier=configuration.verifier,
            authority=authority,
            utc_clock=_utc_now,
        )
        attempt.prime_startup()
        if operation_mode is TrustedTimeFirstEnrollmentOperationMode.NEW:
            result = attempt.perform_first_enrollment()
        elif operation_mode is TrustedTimeFirstEnrollmentOperationMode.RECOVER_PENDING:
            result = attempt.recover_first_enrollment()
        else:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time first enrollment operation mode is invalid"
            )
        remote_namespace_sha256 = attempt.verify_first_enrollment_remote_postcondition()
    except Exception as error:
        primary_error = error

    cleanup_error: Exception | None = None
    for cleanup in (
        None if attempt is None else attempt.close,
        None if provider is None else provider.close,
        None if engine is None else engine.dispose,
    ):
        if cleanup is None:
            continue
        try:
            cleanup()
        except Exception as error:
            if cleanup_error is None:
                cleanup_error = error
    if cleanup_error is not None:
        if result is not None:
            raise TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed(
                result
            ) from None
        if isinstance(
            primary_error,
            (
                TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed,
                TrustedTimeHeadAnchorFirstEnrollmentRecoveryRequired,
            ),
        ):
            raise primary_error
        raise TrustedTimeHeadAnchorFatalFailure(
            "trusted-time first enrollment cleanup failed"
        ) from None
    if primary_error is not None:
        raise primary_error
    if result is None or remote_namespace_sha256 is None:
        raise TrustedTimeHeadAnchorFatalFailure(
            "trusted-time first enrollment result is unavailable"
        )
    return TrustedTimeFirstEnrollmentExecution(
        operation_mode=operation_mode,
        result=result,
        remote_namespace_sha256=remote_namespace_sha256,
    )


def _identity_payload(
    authority: TrustedTimeDeploymentAuthority | None,
    configuration: TrustedTimeHeadAnchorRuntimeConfiguration | None,
) -> dict[str, object]:
    if authority is None or configuration is None:
        return {
            "anchor_authority_sha256": None,
            "anchor_project_identity_sha256": None,
            "bucket_identity_sha256": None,
            "deployment_identity_sha256": None,
            "host_identity_sha256": None,
            "principal_identity_sha256": None,
            "runtime_database_identity_sha256": None,
            "signing_public_key_sha256": None,
            "source_authority_sha256": None,
        }
    anchor = configuration.authority
    return {
        "anchor_authority_sha256": anchor.anchor_authority_sha256,
        "anchor_project_identity_sha256": anchor.anchor_project_identity_sha256,
        "bucket_identity_sha256": first_enrollment_identity_sha256(
            kind="bucket", value=anchor.bucket_name
        ),
        "deployment_identity_sha256": anchor.deployment_identity_sha256,
        "host_identity_sha256": first_enrollment_identity_sha256(kind="host", value=anchor.host_id),
        "principal_identity_sha256": first_enrollment_identity_sha256(
            kind="principal", value=anchor.principal_id
        ),
        "runtime_database_identity_sha256": anchor.runtime_database_identity_sha256,
        "signing_public_key_sha256": anchor.signing_public_key_sha256,
        "source_authority_sha256": authority.source_authority_sha256,
    }


def _terminal_payload(
    *,
    status: str,
    reason: str,
    operation_mode: TrustedTimeFirstEnrollmentOperationMode | None,
    authority: TrustedTimeDeploymentAuthority | None,
    configuration: TrustedTimeHeadAnchorRuntimeConfiguration | None,
    result: TrustedTimeHeadAnchorFirstEnrollmentResult | None = None,
    remote_namespace_sha256: str | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {field_name: False for field_name in _AUTHORITY_FIELDS}
    payload.update(_identity_payload(authority, configuration))
    payload.update(
        {
            "anchor_intent_semantic_sha256": (
                None if result is None else result.anchor_intent_semantic_sha256
            ),
            "anchor_sequence": None if result is None else result.anchor_sequence,
            "candidate_remote_readback_sha256": (
                None if result is None else result.candidate_remote_readback_sha256
            ),
            "checkpoint_reason": (None if result is None else result.checkpoint_reason.value),
            "completion_disposition": (
                None if result is None else result.completion_disposition.value
            ),
            "contract_version": TRUSTED_TIME_FIRST_ENROLLMENT_CONTRACT_VERSION,
            "current_anchor_semantic_sha256": (
                None if result is None else result.current_anchor_semantic_sha256
            ),
            "current_anchor_sha256": (None if result is None else result.current_anchor_sha256),
            "current_host_head_sha256": (
                None if result is None else result.current_host_head_sha256
            ),
            "database_secret_disclosed": False,
            "full_audit_completed": (False if result is None else result.full_audit_completed),
            "idempotent_duplicate_count": (
                None if result is None else result.idempotent_duplicate_count
            ),
            "operation_mode": None if operation_mode is None else operation_mode.value,
            "pending_intent_recovered": (
                False if result is None else result.pending_intent_recovered
            ),
            "reason": reason,
            "receipt_semantic_sha256": (None if result is None else result.receipt_semantic_sha256),
            "remote_namespace_sha256": remote_namespace_sha256,
            "service": "trusted-time-first-enrollment",
            "status": status,
            "uploaded_anchor_count": (None if result is None else result.uploaded_anchor_count),
        }
    )
    return payload


def _print_payload(payload: dict[str, object]) -> None:
    print(
        json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ),
        flush=True,
    )


def release_main() -> None:
    parser = argparse.ArgumentParser(description="Release one admitted enrollment container.")
    parser.add_argument("--recover-pending", action="store_true")
    arguments = parser.parse_args()
    mode = (
        TrustedTimeFirstEnrollmentOperationMode.RECOVER_PENDING
        if arguments.recover_pending
        else TrustedTimeFirstEnrollmentOperationMode.NEW
    )
    try:
        _write_release(mode)
    except TrustedTimeSupervisorConfigurationError:
        raise SystemExit(2) from None


def main() -> None:
    authority: TrustedTimeDeploymentAuthority | None = None
    configuration: TrustedTimeHeadAnchorRuntimeConfiguration | None = None
    operation_mode: TrustedTimeFirstEnrollmentOperationMode | None = None
    database_url = ""
    try:
        _require_fixed_runtime_paths()
        authority = load_trusted_time_authority()
        database_url = load_database_url_secret()
        configuration = load_trusted_time_head_anchor_runtime_configuration(
            database_url=database_url,
            expected_host_id=authority.host_id,
            expected_source_authority_sha256=authority.source_authority_sha256,
            authority_owner_uid=os.geteuid(),
            secret_owner_uid=os.geteuid(),
        )
        _record_database_secret_consumed()
        operation_mode = _wait_for_release()
        execution = _run_one_shot(
            operation_mode=operation_mode,
            database_url=database_url,
            configuration=configuration,
        )
        _print_payload(
            _terminal_payload(
                status="confirmed",
                reason="first_enrollment_confirmed",
                operation_mode=operation_mode,
                authority=authority,
                configuration=configuration,
                result=execution.result,
                remote_namespace_sha256=execution.remote_namespace_sha256,
            )
        )
        return
    except TrustedTimeHeadAnchorFirstEnrollmentCompletedPostconditionsUnconfirmed as error:
        _print_payload(
            _terminal_payload(
                status="fatal",
                reason="first_enrollment_completed_postconditions_unconfirmed",
                operation_mode=operation_mode,
                authority=authority,
                configuration=configuration,
                result=error.evidence,
            )
        )
    except TrustedTimeHeadAnchorFirstEnrollmentRecoveryRequired:
        _print_payload(
            _terminal_payload(
                status="fatal",
                reason="first_enrollment_recovery_required",
                operation_mode=operation_mode,
                authority=authority,
                configuration=configuration,
            )
        )
    except TrustedTimeHeadAnchorFirstEnrollmentAlreadyCompleted:
        _print_payload(
            _terminal_payload(
                status="fatal",
                reason="first_enrollment_already_completed",
                operation_mode=operation_mode,
                authority=authority,
                configuration=configuration,
            )
        )
    except TrustedTimeHeadAnchorTransientFailure:
        _print_payload(
            _terminal_payload(
                status="fatal",
                reason="provider_unavailable_before_commit",
                operation_mode=operation_mode,
                authority=authority,
                configuration=configuration,
            )
        )
    except TrustedTimeHeadAnchorFirstEnrollmentStateConflict:
        _print_payload(
            _terminal_payload(
                status="fatal",
                reason="first_enrollment_precondition_rejected",
                operation_mode=operation_mode,
                authority=authority,
                configuration=configuration,
            )
        )
    except TrustedTimeSupervisorConfigurationError:
        _print_payload(
            _terminal_payload(
                status="fatal",
                reason="configuration_rejected",
                operation_mode=operation_mode,
                authority=authority,
                configuration=configuration,
            )
        )
    except Exception:
        _print_payload(
            _terminal_payload(
                status="fatal",
                reason="first_enrollment_failed",
                operation_mode=operation_mode,
                authority=authority,
                configuration=configuration,
            )
        )
    finally:
        database_url = ""
    raise SystemExit(2)


if __name__ == "__main__":
    main()
