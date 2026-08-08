"""Run one bounded, read-only Phase 6 trusted-time runtime diagnostic.

The diagnostic authenticates local PostgreSQL evidence before contacting the
external anchor provider.  It never registers an epoch, prepares or confirms
an anchor, uploads an object, enrolls a prefix, or emits a secret-bearing
identifier.  Standard output is one fixed-shape canonical JSON document.
"""

# ruff: noqa: E402 -- CLI runtime attestation must precede project imports.

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import NoReturn

CONTRACT_VERSION = "phase6d-bounded-read-only-runtime-diagnostic-v5"
_AUTHORITY_DENIALS = {
    "alert_delivery_authorized": False,
    "arming_authorized": False,
    "automatic_rearm_authorized": False,
    "automatic_resume_authorized": False,
    "broker_action_authorized": False,
    "database_secret_disclosed": False,
    "exposure_authorized": False,
    "external_head_anchor_authorized": False,
    "live_trading_authorized": False,
    "new_exposure_authorized": False,
    "operational_control_authorized": False,
    "paper_trading_authorized": False,
    "readiness_authorized": False,
    "rearm_authorized": False,
}
_BOOTSTRAP_FAILURE_BYTES = (
    json.dumps(
        {
            **_AUTHORITY_DENIALS,
            "contract_version": CONTRACT_VERSION,
            "outcome_code": "diagnostic_failed",
            "status": "failed",
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    + "\n"
).encode("ascii")


def _fail_bootstrap() -> None:
    """Emit no interpreter or path detail when early attestation fails."""

    try:
        if sys.stdout.buffer.write(_BOOTSTRAP_FAILURE_BYTES) != len(_BOOTSTRAP_FAILURE_BYTES):
            raise OSError
        sys.stdout.buffer.flush()
    except Exception:
        pass
    raise SystemExit(2)


def _require_isolated_cli_source_runtime(
    *,
    expected_relative_path: Path,
    module_file: str = __file__,
) -> Path:
    """Fail closed unless this CLI is canonical source in an isolated runtime."""

    try:
        repository_root = Path.cwd()
        expected_source = repository_root / expected_relative_path
        actual_source = Path(os.path.abspath(module_file))
        source_metadata = expected_source.lstat()
        canonical_root = repository_root.resolve(strict=True)
        canonical_source = expected_source.resolve(strict=True)
        runtime_prefix = Path(sys.prefix).resolve(strict=True)
        base_prefix = Path(sys.base_prefix).resolve(strict=True)
        reusable_repository_venv = (canonical_root / ".venv").resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        raise RuntimeError("trusted-time diagnostic runtime attestation failed") from None
    if (
        repository_root != canonical_root
        or expected_source != canonical_source
        or actual_source != expected_source
        or not stat.S_ISREG(source_metadata.st_mode)
        or source_metadata.st_nlink != 1
        or sys.flags.isolated != 1
        or sys.flags.dont_write_bytecode != 1
        or sys.pycache_prefix != "/dev/null"
        or runtime_prefix in (base_prefix, reusable_repository_venv)
        or runtime_prefix.is_relative_to(reusable_repository_venv)
    ):
        raise RuntimeError("trusted-time diagnostic runtime attestation failed")
    for raw_path in sys.path:
        if not raw_path:
            continue
        try:
            candidate = Path(raw_path).resolve(strict=False)
        except (OSError, RuntimeError, ValueError):
            raise RuntimeError("trusted-time diagnostic runtime attestation failed") from None
        if candidate == reusable_repository_venv or candidate.is_relative_to(
            reusable_repository_venv
        ):
            raise RuntimeError("trusted-time diagnostic runtime attestation failed")
    sys.path.insert(0, os.fspath(canonical_root))
    return canonical_root


def _require_repository_first_party_sources(repository_root: Path) -> None:
    """Require loaded first-party modules to originate at canonical source."""

    for module_name, module in tuple(sys.modules.items()):
        if module_name.split(".", 1)[0] not in {"apps", "packages", "scripts"}:
            continue
        origin = getattr(module, "__file__", None)
        if type(origin) is not str:
            raise RuntimeError("trusted-time diagnostic source attestation failed")
        module_path = repository_root.joinpath(*module_name.split("."))
        expected_sources = {module_path.with_suffix(".py"), module_path / "__init__.py"}
        try:
            lexical_origin = Path(os.path.abspath(origin))
            canonical_origin = lexical_origin.resolve(strict=True)
            source_metadata = lexical_origin.lstat()
        except (OSError, RuntimeError, ValueError):
            raise RuntimeError("trusted-time diagnostic source attestation failed") from None
        if (
            lexical_origin != canonical_origin
            or lexical_origin not in expected_sources
            or lexical_origin.suffix != ".py"
            or "__pycache__" in lexical_origin.parts
            or not stat.S_ISREG(source_metadata.st_mode)
            or source_metadata.st_nlink != 1
        ):
            raise RuntimeError("trusted-time diagnostic source attestation failed")


_CLI_REPOSITORY_ROOT: Path | None
if __name__ == "__main__":
    try:
        _CLI_REPOSITORY_ROOT = _require_isolated_cli_source_runtime(
            expected_relative_path=Path("scripts/diagnose_trusted_time_runtime.py")
        )
    except Exception:
        _fail_bootstrap()
else:
    _CLI_REPOSITORY_ROOT = None

import sqlalchemy as sa
from sqlalchemy import Engine

from apps.trusted_time_supervisor.head_anchor_config import (
    TrustedTimeHeadAnchorAuthority,
    decode_trusted_time_head_anchor_auth_secret,
    decode_trusted_time_head_anchor_authority,
)
from packages.adapters.trusted_time.ed25519_anchor import (
    Ed25519TrustedTimeAnchorSigner,
    Ed25519TrustedTimeAnchorVerifier,
)
from packages.adapters.trusted_time.supabase_storage_anchor import (
    SupabaseStorageAnchorAuthenticationError,
    SupabaseStorageAnchorAuthenticationResponseError,
    SupabaseStorageAnchorAuthPasswordTokenRequestTargetError,
    SupabaseStorageAnchorAuthPasswordTokenResponseBoundError,
    SupabaseStorageAnchorAuthPasswordTokenResponseEncodingError,
    SupabaseStorageAnchorAuthPasswordTokenResponseEnvelopeError,
    SupabaseStorageAnchorAuthPasswordTokenResponseError,
    SupabaseStorageAnchorAuthPasswordTokenSessionSchemaError,
    SupabaseStorageAnchorAuthUserVerificationResponseError,
    SupabaseStorageAnchorBoundedListResponseError,
    SupabaseStorageAnchorCredentials,
    SupabaseStorageAnchorError,
    SupabaseStorageAnchorResponseError,
    SupabaseStorageAnchorStorageAccessError,
    SupabaseStorageAnchorUnavailable,
    SupabaseStorageTrustedTimeAnchorProvider,
)
from packages.application.trusted_time_head_anchor import (
    TrustedTimeHeadAnchorProviderIdentity,
    trusted_time_head_anchor_object_prefix,
)
from packages.persistence.database import verify_operational_schema
from packages.persistence.schema import (
    phase6_trusted_time_epoch_registrations,
    phase6_trusted_time_head_anchor_intents,
    phase6_trusted_time_head_anchor_receipts,
    phase6_trusted_time_probe_evaluations,
)
from packages.persistence.trusted_time import verify_trusted_time_integrity
from packages.persistence.trusted_time_head_anchor import (
    SqlTrustedTimeHeadAnchorRepository,
)
from scripts.inspect_trusted_time_qualification import (
    create_read_only_qualification_engine,
    load_checked_in_authority,
)
from scripts.start_trusted_time_supervisor import (
    TrustedTimeRuntimeConfiguration,
    load_trusted_time_runtime_configuration,
)

ROOT = _CLI_REPOSITORY_ROOT or Path(__file__).resolve().parents[1]
if _CLI_REPOSITORY_ROOT is not None:
    try:
        _require_repository_first_party_sources(ROOT)
    except Exception:
        _fail_bootstrap()

OUTCOME_PASSED = "diagnostic_passed"
OUTCOME_LAUNCH_CONFIGURATION_REJECTED = "launch_configuration_rejected"
OUTCOME_DATABASE_CONFIGURATION_REJECTED = "database_configuration_rejected"
OUTCOME_DATABASE_CONNECTION_REJECTED = "database_connection_rejected"
OUTCOME_DATABASE_SCHEMA_REJECTED = "database_schema_rejected"
OUTCOME_TRUSTED_TIME_INTEGRITY_REJECTED = "trusted_time_integrity_rejected"
OUTCOME_LOCAL_AGGREGATE_REJECTED = "local_aggregate_rejected"
OUTCOME_LOCAL_SNAPSHOT_REJECTED = "authenticated_startup_snapshot_rejected"
OUTCOME_LOCAL_ANCHOR_HISTORY_PRESENT = "local_anchor_history_present"
OUTCOME_PROVIDER_IDENTITY_REJECTED = "provider_identity_rejected"
OUTCOME_PROVIDER_ACCESS_REJECTED = "provider_access_rejected"
OUTCOME_PROVIDER_AUTHENTICATION_REJECTED = "provider_authentication_rejected"
OUTCOME_PROVIDER_STORAGE_ACCESS_REJECTED = "provider_storage_access_rejected"
OUTCOME_PROVIDER_UNAVAILABLE = "provider_unavailable"
OUTCOME_PROVIDER_RESPONSE_REJECTED = "provider_response_rejected"
OUTCOME_PROVIDER_AUTHENTICATION_RESPONSE_REJECTED = "provider_authentication_response_rejected"
OUTCOME_PROVIDER_AUTH_PASSWORD_TOKEN_RESPONSE_REJECTED = (
    "provider_auth_password_token_response_rejected"
)
OUTCOME_PROVIDER_AUTH_PASSWORD_TOKEN_REQUEST_TARGET_REJECTED = (
    "provider_auth_password_token_request_target_rejected"
)
OUTCOME_PROVIDER_AUTH_PASSWORD_TOKEN_RESPONSE_ENCODING_REJECTED = (
    "provider_auth_password_token_response_encoding_rejected"
)
OUTCOME_PROVIDER_AUTH_PASSWORD_TOKEN_RESPONSE_BOUND_REJECTED = (
    "provider_auth_password_token_response_bound_rejected"
)
OUTCOME_PROVIDER_AUTH_PASSWORD_TOKEN_RESPONSE_ENVELOPE_REJECTED = (
    "provider_auth_password_token_response_envelope_rejected"
)
OUTCOME_PROVIDER_AUTH_PASSWORD_TOKEN_SESSION_SCHEMA_REJECTED = (
    "provider_auth_password_token_session_schema_rejected"
)
OUTCOME_PROVIDER_AUTH_USER_VERIFICATION_RESPONSE_REJECTED = (
    "provider_auth_user_verification_response_rejected"
)
OUTCOME_PROVIDER_STORAGE_LIST_RESPONSE_REJECTED = "provider_storage_list_response_rejected"
OUTCOME_PROVIDER_CLEANUP_REJECTED = "provider_cleanup_rejected"
OUTCOME_PROVIDER_PREFIX_NOT_STABLE_ZERO = "provider_prefix_not_stable_zero"
OUTCOME_DIAGNOSTIC_FAILED = "diagnostic_failed"

_OUTCOME_CODES = frozenset(
    {
        OUTCOME_PASSED,
        OUTCOME_LAUNCH_CONFIGURATION_REJECTED,
        OUTCOME_DATABASE_CONFIGURATION_REJECTED,
        OUTCOME_DATABASE_CONNECTION_REJECTED,
        OUTCOME_DATABASE_SCHEMA_REJECTED,
        OUTCOME_TRUSTED_TIME_INTEGRITY_REJECTED,
        OUTCOME_LOCAL_AGGREGATE_REJECTED,
        OUTCOME_LOCAL_SNAPSHOT_REJECTED,
        OUTCOME_LOCAL_ANCHOR_HISTORY_PRESENT,
        OUTCOME_PROVIDER_IDENTITY_REJECTED,
        OUTCOME_PROVIDER_ACCESS_REJECTED,
        OUTCOME_PROVIDER_AUTHENTICATION_REJECTED,
        OUTCOME_PROVIDER_STORAGE_ACCESS_REJECTED,
        OUTCOME_PROVIDER_UNAVAILABLE,
        OUTCOME_PROVIDER_RESPONSE_REJECTED,
        OUTCOME_PROVIDER_AUTHENTICATION_RESPONSE_REJECTED,
        OUTCOME_PROVIDER_AUTH_PASSWORD_TOKEN_RESPONSE_REJECTED,
        OUTCOME_PROVIDER_AUTH_PASSWORD_TOKEN_REQUEST_TARGET_REJECTED,
        OUTCOME_PROVIDER_AUTH_PASSWORD_TOKEN_RESPONSE_ENCODING_REJECTED,
        OUTCOME_PROVIDER_AUTH_PASSWORD_TOKEN_RESPONSE_BOUND_REJECTED,
        OUTCOME_PROVIDER_AUTH_PASSWORD_TOKEN_RESPONSE_ENVELOPE_REJECTED,
        OUTCOME_PROVIDER_AUTH_PASSWORD_TOKEN_SESSION_SCHEMA_REJECTED,
        OUTCOME_PROVIDER_AUTH_USER_VERIFICATION_RESPONSE_REJECTED,
        OUTCOME_PROVIDER_STORAGE_LIST_RESPONSE_REJECTED,
        OUTCOME_PROVIDER_CLEANUP_REJECTED,
        OUTCOME_PROVIDER_PREFIX_NOT_STABLE_ZERO,
        OUTCOME_DIAGNOSTIC_FAILED,
    }
)
_MAXIMUM_COUNT = 9_223_372_036_854_775_807


class TrustedTimeRuntimeDiagnosticError(RuntimeError):
    """One fixed, nonsecret diagnostic outcome."""

    def __init__(self, outcome_code: str) -> None:
        if outcome_code not in _OUTCOME_CODES or outcome_code == OUTCOME_PASSED:
            outcome_code = OUTCOME_DIAGNOSTIC_FAILED
        super().__init__(outcome_code)
        self.outcome_code = outcome_code


@dataclass(frozen=True, slots=True)
class _DecodedRuntime:
    database_url: str = field(repr=False)
    authority: TrustedTimeHeadAnchorAuthority
    credentials: SupabaseStorageAnchorCredentials = field(repr=False)
    verifier: Ed25519TrustedTimeAnchorVerifier


@dataclass(frozen=True, slots=True)
class LocalAggregate:
    epoch_count: int
    latest_epoch_evaluation_count: int
    intent_count: int
    receipt_count: int

    def __post_init__(self) -> None:
        values = (
            self.epoch_count,
            self.latest_epoch_evaluation_count,
            self.intent_count,
            self.receipt_count,
        )
        if any(type(value) is not int or value < 0 or value > _MAXIMUM_COUNT for value in values):
            raise TrustedTimeRuntimeDiagnosticError(OUTCOME_LOCAL_AGGREGATE_REJECTED)
        if self.epoch_count == 0 or self.intent_count < self.receipt_count:
            raise TrustedTimeRuntimeDiagnosticError(OUTCOME_LOCAL_AGGREGATE_REJECTED)


@dataclass(frozen=True, slots=True)
class LocalSnapshotSummary:
    local_transition_count: int
    confirmed_anchor_count: int
    pending_intent: bool

    def __post_init__(self) -> None:
        if (
            type(self.local_transition_count) is not int
            or self.local_transition_count <= 0
            or self.local_transition_count > _MAXIMUM_COUNT
            or type(self.confirmed_anchor_count) is not int
            or self.confirmed_anchor_count < 0
            or self.confirmed_anchor_count > _MAXIMUM_COUNT
            or type(self.pending_intent) is not bool
        ):
            raise TrustedTimeRuntimeDiagnosticError(OUTCOME_LOCAL_SNAPSHOT_REJECTED)


def _decode_runtime_configuration(env_file: Path) -> _DecodedRuntime:
    """Load the exact-four launch projection and validate all admitted identities."""

    try:
        runtime = load_trusted_time_runtime_configuration(env_file)
        if type(runtime) is not TrustedTimeRuntimeConfiguration:
            raise TypeError
        deployment = load_checked_in_authority().deployment
        payloads = runtime.head_anchor_payloads
        authority = decode_trusted_time_head_anchor_authority(
            payloads.authority,
            database_url=runtime.database_url,
            expected_host_id=deployment.host_id,
            expected_source_authority_sha256=deployment.source_authority_sha256,
        )
        credentials = decode_trusted_time_head_anchor_auth_secret(
            payloads.auth_secret,
            authority=authority,
        )
        signer = Ed25519TrustedTimeAnchorSigner.from_private_key_bytes(
            signing_key_id=authority.signing_key_id,
            expected_signing_public_key_sha256=authority.signing_public_key_sha256,
            private_key_bytes=payloads.signing_key,
        )
        verifier = Ed25519TrustedTimeAnchorVerifier.from_public_key_bytes(
            signing_key_id=authority.signing_key_id,
            expected_signing_public_key_sha256=authority.signing_public_key_sha256,
            public_key_bytes=authority.signing_public_key_bytes,
        )
        del signer
        return _DecodedRuntime(
            database_url=runtime.database_url,
            authority=authority,
            credentials=credentials,
            verifier=verifier,
        )
    except TrustedTimeRuntimeDiagnosticError:
        raise
    except Exception:
        raise TrustedTimeRuntimeDiagnosticError(OUTCOME_LAUNCH_CONFIGURATION_REJECTED) from None


def _exact_count(value: object) -> int:
    if type(value) is not int or value < 0 or value > _MAXIMUM_COUNT:
        raise TrustedTimeRuntimeDiagnosticError(OUTCOME_LOCAL_AGGREGATE_REJECTED)
    return value


def _verify_database_connection(engine: Engine) -> None:
    """Prove one bounded read-only transaction before broader local checks."""

    try:
        with engine.connect() as raw_connection:
            connection = raw_connection.execution_options(isolation_level="REPEATABLE READ")
            transaction = connection.begin()
            try:
                connection.exec_driver_sql("SET TRANSACTION READ ONLY")
                if connection.scalar(sa.text("SELECT 1")) != 1:
                    raise ValueError
            finally:
                transaction.rollback()
    except Exception:
        raise TrustedTimeRuntimeDiagnosticError(OUTCOME_DATABASE_CONNECTION_REJECTED) from None


def _read_local_aggregate(engine: Engine, *, host_id: str) -> LocalAggregate:
    """Read only fixed host-scoped aggregate values in one rolled-back snapshot."""

    try:
        with engine.connect() as raw_connection:
            connection = raw_connection.execution_options(isolation_level="REPEATABLE READ")
            transaction = connection.begin()
            try:
                connection.exec_driver_sql("SET TRANSACTION READ ONLY")
                epoch_count = _exact_count(
                    connection.scalar(
                        sa.select(sa.func.count())
                        .select_from(phase6_trusted_time_epoch_registrations)
                        .where(phase6_trusted_time_epoch_registrations.c.host_id == host_id)
                    )
                )
                latest_epoch_id = connection.scalar(
                    sa.select(phase6_trusted_time_epoch_registrations.c.monitor_epoch_id)
                    .where(phase6_trusted_time_epoch_registrations.c.host_id == host_id)
                    .order_by(phase6_trusted_time_epoch_registrations.c.epoch_sequence.desc())
                    .limit(1)
                )
                if type(latest_epoch_id) is not str or not latest_epoch_id:
                    raise TrustedTimeRuntimeDiagnosticError(OUTCOME_LOCAL_AGGREGATE_REJECTED)
                evaluation_count = _exact_count(
                    connection.scalar(
                        sa.select(sa.func.count())
                        .select_from(phase6_trusted_time_probe_evaluations)
                        .where(
                            phase6_trusted_time_probe_evaluations.c.host_id == host_id,
                            phase6_trusted_time_probe_evaluations.c.monitor_epoch_id
                            == latest_epoch_id,
                        )
                    )
                )
                intent_count = _exact_count(
                    connection.scalar(
                        sa.select(sa.func.count())
                        .select_from(phase6_trusted_time_head_anchor_intents)
                        .where(phase6_trusted_time_head_anchor_intents.c.host_id == host_id)
                    )
                )
                receipt_count = _exact_count(
                    connection.scalar(
                        sa.select(sa.func.count())
                        .select_from(
                            phase6_trusted_time_head_anchor_receipts.join(
                                phase6_trusted_time_head_anchor_intents,
                                phase6_trusted_time_head_anchor_receipts.c.anchor_intent_id
                                == phase6_trusted_time_head_anchor_intents.c.anchor_intent_id,
                            )
                        )
                        .where(phase6_trusted_time_head_anchor_intents.c.host_id == host_id)
                    )
                )
                return LocalAggregate(
                    epoch_count=epoch_count,
                    latest_epoch_evaluation_count=evaluation_count,
                    intent_count=intent_count,
                    receipt_count=receipt_count,
                )
            finally:
                transaction.rollback()
    except TrustedTimeRuntimeDiagnosticError:
        raise
    except Exception:
        raise TrustedTimeRuntimeDiagnosticError(OUTCOME_LOCAL_AGGREGATE_REJECTED) from None


def _authenticate_local_startup_snapshot(
    engine: Engine,
    *,
    runtime: _DecodedRuntime,
) -> LocalSnapshotSummary:
    """Use the production bounded startup replay without any durable mutation."""

    repository = None
    snapshot = None
    try:
        authority = runtime.authority
        repository = SqlTrustedTimeHeadAnchorRepository(
            engine,
            verifier=runtime.verifier,
            anchor_authority_sha256=authority.anchor_authority_sha256,
            signing_key_id=authority.signing_key_id,
            signing_public_key_sha256=authority.signing_public_key_sha256,
        )
        snapshot = repository.load_head_anchor_startup_snapshot(
            host_id=authority.host_id,
            deployment_identity_sha256=authority.deployment_identity_sha256,
            runtime_database_identity_sha256=authority.runtime_database_identity_sha256,
            anchor_project_identity_sha256=authority.anchor_project_identity_sha256,
            anchor_project_ref=authority.anchor_project_ref,
            bucket_name=authority.bucket_name,
            principal_id=authority.principal_id,
        )
        if snapshot.complete_replay is not True:
            raise TrustedTimeRuntimeDiagnosticError(OUTCOME_LOCAL_SNAPSHOT_REJECTED)
        return LocalSnapshotSummary(
            local_transition_count=snapshot.local_transition_count,
            confirmed_anchor_count=snapshot.confirmed_anchor_count,
            pending_intent=snapshot.pending_intent is not None,
        )
    except TrustedTimeRuntimeDiagnosticError:
        raise
    except Exception:
        raise TrustedTimeRuntimeDiagnosticError(OUTCOME_LOCAL_SNAPSHOT_REJECTED) from None
    finally:
        if repository is not None and snapshot is not None:
            try:
                repository.discard_head_anchor_snapshot(snapshot)
            except Exception:
                raise TrustedTimeRuntimeDiagnosticError(OUTCOME_LOCAL_SNAPSHOT_REJECTED) from None


def _require_local_snapshot_consistency(
    aggregate: LocalAggregate,
    snapshot: LocalSnapshotSummary,
) -> None:
    if (
        snapshot.confirmed_anchor_count != aggregate.receipt_count
        or aggregate.intent_count != aggregate.receipt_count + (1 if snapshot.pending_intent else 0)
    ):
        raise TrustedTimeRuntimeDiagnosticError(OUTCOME_LOCAL_SNAPSHOT_REJECTED)
    if (
        aggregate.intent_count != 0
        or aggregate.receipt_count != 0
        or snapshot.confirmed_anchor_count != 0
        or snapshot.pending_intent
    ):
        raise TrustedTimeRuntimeDiagnosticError(OUTCOME_LOCAL_ANCHOR_HISTORY_PRESENT)


def _provider_failure_outcome(error: Exception) -> str:
    """Map typed adapter failures without inspecting secret-bearing text."""

    if isinstance(error, SupabaseStorageAnchorAuthPasswordTokenRequestTargetError):
        return OUTCOME_PROVIDER_AUTH_PASSWORD_TOKEN_REQUEST_TARGET_REJECTED
    if isinstance(error, SupabaseStorageAnchorAuthPasswordTokenResponseEncodingError):
        return OUTCOME_PROVIDER_AUTH_PASSWORD_TOKEN_RESPONSE_ENCODING_REJECTED
    if isinstance(error, SupabaseStorageAnchorAuthPasswordTokenResponseBoundError):
        return OUTCOME_PROVIDER_AUTH_PASSWORD_TOKEN_RESPONSE_BOUND_REJECTED
    if isinstance(error, SupabaseStorageAnchorAuthPasswordTokenResponseEnvelopeError):
        return OUTCOME_PROVIDER_AUTH_PASSWORD_TOKEN_RESPONSE_ENVELOPE_REJECTED
    if isinstance(error, SupabaseStorageAnchorAuthPasswordTokenSessionSchemaError):
        return OUTCOME_PROVIDER_AUTH_PASSWORD_TOKEN_SESSION_SCHEMA_REJECTED
    if isinstance(error, SupabaseStorageAnchorAuthPasswordTokenResponseError):
        return OUTCOME_PROVIDER_AUTH_PASSWORD_TOKEN_RESPONSE_REJECTED
    if isinstance(error, SupabaseStorageAnchorAuthUserVerificationResponseError):
        return OUTCOME_PROVIDER_AUTH_USER_VERIFICATION_RESPONSE_REJECTED
    if isinstance(error, SupabaseStorageAnchorAuthenticationResponseError):
        return OUTCOME_PROVIDER_AUTHENTICATION_RESPONSE_REJECTED
    if isinstance(error, SupabaseStorageAnchorBoundedListResponseError):
        return OUTCOME_PROVIDER_STORAGE_LIST_RESPONSE_REJECTED
    if isinstance(error, SupabaseStorageAnchorAuthenticationError):
        return OUTCOME_PROVIDER_AUTHENTICATION_REJECTED
    if isinstance(error, SupabaseStorageAnchorStorageAccessError):
        return OUTCOME_PROVIDER_STORAGE_ACCESS_REJECTED
    if isinstance(error, SupabaseStorageAnchorUnavailable):
        return OUTCOME_PROVIDER_UNAVAILABLE
    if isinstance(error, SupabaseStorageAnchorResponseError):
        return OUTCOME_PROVIDER_RESPONSE_REJECTED
    if isinstance(error, SupabaseStorageAnchorError):
        return OUTCOME_PROVIDER_ACCESS_REJECTED
    return OUTCOME_PROVIDER_ACCESS_REJECTED


def _verify_provider_stable_zero(*, runtime: _DecodedRuntime) -> None:
    """Authenticate and observe the exact runtime prefix twice, one item at most."""

    provider = None
    try:
        authority = runtime.authority
        provider = SupabaseStorageTrustedTimeAnchorProvider(credentials=runtime.credentials)
        expected_identity = TrustedTimeHeadAnchorProviderIdentity(
            anchor_project_identity_sha256=authority.anchor_project_identity_sha256,
            anchor_project_ref=authority.anchor_project_ref,
            principal_id=authority.principal_id,
            bucket_name=authority.bucket_name,
        )
        try:
            identity = provider.attest_identity()
        except Exception:
            raise TrustedTimeRuntimeDiagnosticError(OUTCOME_PROVIDER_IDENTITY_REJECTED) from None
        if type(identity) is not TrustedTimeHeadAnchorProviderIdentity or identity != (
            expected_identity
        ):
            raise TrustedTimeRuntimeDiagnosticError(OUTCOME_PROVIDER_IDENTITY_REJECTED)
        prefix = trusted_time_head_anchor_object_prefix(
            deployment_identity_sha256=authority.deployment_identity_sha256,
            host_id=authority.host_id,
        )
        pages: list[tuple[str, ...]] = []
        for _ in range(2):
            try:
                page = provider.list_object_names_page(
                    bucket_name=authority.bucket_name,
                    prefix=prefix,
                    offset=0,
                    limit=1,
                )
            except Exception as error:
                raise TrustedTimeRuntimeDiagnosticError(_provider_failure_outcome(error)) from None
            if type(page) is not tuple:
                raise TrustedTimeRuntimeDiagnosticError(
                    OUTCOME_PROVIDER_STORAGE_LIST_RESPONSE_REJECTED
                )
            pages.append(page)
        if pages != [(), ()]:
            raise TrustedTimeRuntimeDiagnosticError(OUTCOME_PROVIDER_PREFIX_NOT_STABLE_ZERO)
    except TrustedTimeRuntimeDiagnosticError:
        raise
    except Exception as error:
        raise TrustedTimeRuntimeDiagnosticError(_provider_failure_outcome(error)) from None
    finally:
        if provider is not None:
            try:
                provider.close()
            except Exception:
                raise TrustedTimeRuntimeDiagnosticError(OUTCOME_PROVIDER_CLEANUP_REJECTED) from None


def diagnose_trusted_time_runtime(*, env_file: Path) -> dict[str, object]:
    """Run ordered local then provider checks and return only a safe aggregate."""

    engine: Engine | None = None
    database_url = ""
    try:
        runtime = _decode_runtime_configuration(env_file)
        database_url = runtime.database_url
        try:
            engine = create_read_only_qualification_engine(database_url)
            if not isinstance(engine, Engine):
                raise TypeError
        except Exception:
            raise TrustedTimeRuntimeDiagnosticError(
                OUTCOME_DATABASE_CONFIGURATION_REJECTED
            ) from None
        _verify_database_connection(engine)
        try:
            verify_operational_schema(engine, require_phase_zero_facts=False)
        except Exception:
            raise TrustedTimeRuntimeDiagnosticError(OUTCOME_DATABASE_SCHEMA_REJECTED) from None
        try:
            verify_trusted_time_integrity(engine)
        except Exception:
            raise TrustedTimeRuntimeDiagnosticError(
                OUTCOME_TRUSTED_TIME_INTEGRITY_REJECTED
            ) from None
        aggregate_before = _read_local_aggregate(
            engine,
            host_id=runtime.authority.host_id,
        )
        snapshot = _authenticate_local_startup_snapshot(engine, runtime=runtime)
        aggregate_after = _read_local_aggregate(
            engine,
            host_id=runtime.authority.host_id,
        )
        if aggregate_before != aggregate_after:
            raise TrustedTimeRuntimeDiagnosticError(OUTCOME_LOCAL_AGGREGATE_REJECTED)
        _require_local_snapshot_consistency(aggregate_after, snapshot)

        # This is the only provider boundary, deliberately after all local gates.
        _verify_provider_stable_zero(runtime=runtime)

        return {
            **_AUTHORITY_DENIALS,
            "contract_version": CONTRACT_VERSION,
            "database": {
                "exact_schema": True,
                "integrity_verified": True,
                "schema_revision_current": True,
            },
            "head_anchor": {
                "authenticated_startup_snapshot": True,
                "intent_count": aggregate_after.intent_count,
                "provider_identity_authenticated": True,
                "provider_prefix_stable_zero": True,
                "receipt_count": aggregate_after.receipt_count,
            },
            "outcome_code": OUTCOME_PASSED,
            "status": "passed",
            "trusted_time": {
                "epoch_count": aggregate_after.epoch_count,
                "latest_epoch_evaluation_count": (aggregate_after.latest_epoch_evaluation_count),
                "local_transition_count": snapshot.local_transition_count,
            },
        }
    finally:
        database_url = ""
        if engine is not None:
            with suppress(Exception):
                engine.dispose()


def failure_payload(outcome_code: str) -> dict[str, object]:
    """Return a fixed-shape failure without carrying exception material."""

    exact = outcome_code if outcome_code in _OUTCOME_CODES else OUTCOME_DIAGNOSTIC_FAILED
    if exact == OUTCOME_PASSED:
        exact = OUTCOME_DIAGNOSTIC_FAILED
    return {
        **_AUTHORITY_DENIALS,
        "contract_version": CONTRACT_VERSION,
        "outcome_code": exact,
        "status": "failed",
    }


def canonical_json_bytes(payload: dict[str, object]) -> bytes:
    """Encode one deterministic ASCII JSON object with a terminal newline."""

    try:
        return (
            json.dumps(
                payload,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError):
        return (
            json.dumps(
                failure_payload(OUTCOME_DIAGNOSTIC_FAILED),
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")


class _NonRenderingArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> NoReturn:
        raise ValueError


def main() -> None:
    parser = _NonRenderingArgumentParser(description=__doc__)
    parser.add_argument(
        "--env-file",
        required=True,
        type=Path,
        help=(
            "absolute dedicated owner-only exact-four launch environment; "
            "never the general repository .env"
        ),
    )
    exit_status = 0
    try:
        try:
            arguments = parser.parse_args()
        except ValueError:
            raise TrustedTimeRuntimeDiagnosticError(OUTCOME_LAUNCH_CONFIGURATION_REJECTED) from None
        payload = diagnose_trusted_time_runtime(env_file=arguments.env_file)
    except TrustedTimeRuntimeDiagnosticError as error:
        payload = failure_payload(error.outcome_code)
        exit_status = 2
    except Exception:
        payload = failure_payload(OUTCOME_DIAGNOSTIC_FAILED)
        exit_status = 2
    try:
        encoded = canonical_json_bytes(payload)
        if sys.stdout.buffer.write(encoded) != len(encoded):
            raise OSError
        sys.stdout.buffer.flush()
    except Exception:
        raise SystemExit(2) from None
    raise SystemExit(exit_status)


if __name__ == "__main__":
    main()
