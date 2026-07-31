"""Verify the owner-supervised local paper-smoke packaging boundaries.

This command is deliberately narrower than a strategy worker. It verifies the
exact local image, owner-only credential file, distinct Supabase runtime/test
databases, migrated runtime schema, Sentry configuration, and checked-in
no-exposure artifact. It never authorizes a strategy invocation, broker call,
new exposure, automatic re-arm, or Phase 5 activation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import URL, make_url

from apps.trader.main import PaperSmokePreflight
from packages.adapters.broker.alpaca_paper_account_runtime import (
    AlpacaPaperCredentialReference,
)
from packages.application.no_exposure_smoke_strategy import (
    load_no_exposure_smoke_artifact,
)
from packages.application.paper_account_enrollment import (
    PAPER_ACCOUNT_ENROLLMENT_ATTESTATION_CONTRACT_VERSION,
    PaperAccountEnrollmentAttestation,
    PaperAccountEnrollmentAttestationError,
    attest_paper_account_enrollment,
)
from packages.application.paper_deployment import (
    AuthoritativeSourcePin,
    OpaqueSecretReference,
    PaperDeploymentAuthoritativeSources,
    PaperDeploymentEvidence,
    PaperSecretPurpose,
    PaperSourceKind,
    RecommendedPaperDeployment,
    assess_paper_deployment_readiness,
)
from packages.observability.sentry_otlp import (
    SENTRY_OTLP_PROVIDER_ID,
    SentryOtlpConfiguration,
    SentryOtlpConfigurationError,
)
from packages.persistence.alpaca_paper_account_binding import (
    SqlAlpacaPaperAccountBindingRepository,
    verify_alpaca_paper_account_binding_integrity,
)
from packages.persistence.database import (
    EXPECTED_SCHEMA_REVISION,
    verify_operational_schema,
)
from packages.persistence.schema import metadata
from scripts.credential_env import load_owner_only_environment
from scripts.verify_paper_preflight_image import (
    PaperPreflightImageVerificationError,
    verify_image,
)

DEFAULT_LOCAL_IMAGE = "autoquanttrader-runtime:paper-preflight-local"
DEFAULT_DEPLOYMENT_ID = "aqt-local-paper-smoke"
LOCAL_PROFILE_SPEC = (
    Path(__file__).resolve().parents[1]
    / "docs/adr/0088-fail-closed-paper-smoke-deployment-profile.md"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SUPABASE_POOLER_HOST = re.compile(
    r"^[A-Za-z0-9-]+[.]pooler[.]supabase[.]com$",
)
_SUPABASE_PROJECT_REF = re.compile(r"^[a-z0-9]{20}$")
_DATABASE_CONNECT_TIMEOUT_SECONDS = 10
_DATABASE_STATEMENT_TIMEOUT_MILLISECONDS = 30_000
_DATABASE_LOCK_TIMEOUT_MILLISECONDS = 5_000
_MAXIMUM_OWNER_ENVIRONMENT_BYTES = 128 * 1024
_PAPER_ACCOUNT_IDENTITY_VARIABLES = (
    "AQT_PAPER_ACCOUNT_ID",
    "AQT_PAPER_PROVIDER_ACCOUNT_ID",
    "AQT_PAPER_BROKER_SECRET_REF",
    "AQT_PAPER_BROKER_SECRET_VERSION",
)
_PREFLIGHT_ENVIRONMENT_VARIABLES = (
    "AQT_DATABASE_URL",
    "AQT_TEST_POSTGRES_URL",
    "AQT_SENTRY_DSN",
    *_PAPER_ACCOUNT_IDENTITY_VARIABLES,
)
type DatabaseEngineFactory = Callable[[str], Engine]
_LOCAL_VERIFICATION_SEAL = object()


class LocalPaperSmokePreflightError(RuntimeError):
    """A sanitized local preflight boundary failed."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class LocalDatabaseVerification:
    """Public, nonsecret result of the read-only runtime database check."""

    client_tls_active: bool
    schema_revision: str
    public_table_count: int
    runtime_test_separated: bool
    account_binding_head_count: int
    control_head_count: int
    running_control_head_count: int
    account_enrollment: PaperAccountEnrollmentAttestation | None
    binding_sha256: str
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            self._seal is not _LOCAL_VERIFICATION_SEAL
            or self.client_tls_active is not True
            or self.schema_revision != EXPECTED_SCHEMA_REVISION
            or self.public_table_count != len(metadata.tables) + 1
            or self.runtime_test_separated is not True
            or type(self.account_binding_head_count) is not int
            or self.account_binding_head_count < 0
            or type(self.control_head_count) is not int
            or self.control_head_count < 0
            or type(self.running_control_head_count) is not int
            or self.running_control_head_count != 0
            or self.running_control_head_count > self.control_head_count
            or _SHA256.fullmatch(self.binding_sha256) is None
        ):
            raise LocalPaperSmokePreflightError("runtime_database_not_ready")
        if self.account_enrollment is not None:
            if (
                type(self.account_enrollment) is not PaperAccountEnrollmentAttestation
                or self.account_binding_head_count <= 0
            ):
                raise LocalPaperSmokePreflightError("runtime_database_not_ready")
            try:
                self.account_enrollment._validate()
            except PaperAccountEnrollmentAttestationError:
                raise LocalPaperSmokePreflightError("runtime_database_not_ready") from None

    @classmethod
    def _verified(
        cls,
        *,
        client_tls_active: bool,
        schema_revision: str,
        public_table_count: int,
        runtime_test_separated: bool,
        account_binding_head_count: int,
        control_head_count: int,
        running_control_head_count: int,
        account_enrollment: PaperAccountEnrollmentAttestation | None,
        binding_sha256: str,
    ) -> LocalDatabaseVerification:
        return cls(
            client_tls_active=client_tls_active,
            schema_revision=schema_revision,
            public_table_count=public_table_count,
            runtime_test_separated=runtime_test_separated,
            account_binding_head_count=account_binding_head_count,
            control_head_count=control_head_count,
            running_control_head_count=running_control_head_count,
            account_enrollment=account_enrollment,
            binding_sha256=binding_sha256,
            _seal=_LOCAL_VERIFICATION_SEAL,
        )

    @property
    def operational_control_observation(self) -> str:
        if self.control_head_count == 0:
            return "absent_fail_closed"
        return "unbound_non_running_heads_present"

    @property
    def account_binding_observation(self) -> str:
        if self.account_enrollment is not None:
            return "configured_historical_identity_attested_non_authorizing"
        if self.account_binding_head_count == 0:
            return "unbound"
        return "binding_heads_present_unattested"


@dataclass(frozen=True, slots=True)
class LocalRuntimeImageVerification:
    """Exact image ID whose metadata, inputs, and default process were verified."""

    content_sha256: str
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            self._seal is not _LOCAL_VERIFICATION_SEAL
            or _SHA256.fullmatch(self.content_sha256) is None
        ):
            raise LocalPaperSmokePreflightError("runtime_image_contract_invalid")

    @classmethod
    def _verified(cls, content_sha256: str) -> LocalRuntimeImageVerification:
        return cls(
            content_sha256=content_sha256,
            _seal=_LOCAL_VERIFICATION_SEAL,
        )


@dataclass(frozen=True, slots=True)
class LocalTelemetryVerification:
    """Exact telemetry binding whose fixed diagnostic-only shape was verified."""

    binding_sha256: str
    provider_id: str
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            self._seal is not _LOCAL_VERIFICATION_SEAL
            or _SHA256.fullmatch(self.binding_sha256) is None
            or self.provider_id != SENTRY_OTLP_PROVIDER_ID
        ):
            raise LocalPaperSmokePreflightError("sentry_configuration_invalid")

    @classmethod
    def _verified(cls, binding_sha256: str) -> LocalTelemetryVerification:
        return cls(
            binding_sha256=binding_sha256,
            provider_id=SENTRY_OTLP_PROVIDER_ID,
            _seal=_LOCAL_VERIFICATION_SEAL,
        )


def validate_supabase_session_database_url(value: str) -> URL:
    """Return one exact TLS Supabase Session-pooler URL or fail closed."""

    try:
        url = make_url(value)
    except (TypeError, ValueError):
        raise LocalPaperSmokePreflightError("database_url_invalid") from None
    if (
        url.drivername != "postgresql+psycopg"
        or url.host is None
        or _SUPABASE_POOLER_HOST.fullmatch(url.host) is None
        or url.port != 5432
        or not url.database
        or not url.username
        or "." not in url.username
        or _SUPABASE_PROJECT_REF.fullmatch(url.username.rsplit(".", 1)[1]) is None
        or not url.password
        or dict(url.query) != {"sslmode": "require"}
    ):
        raise LocalPaperSmokePreflightError("database_url_not_supabase_session_tls")
    return url


_postgres_url = validate_supabase_session_database_url


def validate_distinct_database_bindings(
    runtime_database_url: str,
    test_database_url: str,
) -> None:
    """Reject malformed, transaction-pooler, non-TLS, or shared DB bindings."""

    runtime = validate_supabase_session_database_url(runtime_database_url)
    test = validate_supabase_session_database_url(test_database_url)
    runtime_identity = (
        runtime.username.rsplit(".", 1)[1] if runtime.username is not None else None,
        runtime.database,
    )
    test_identity = (
        test.username.rsplit(".", 1)[1] if test.username is not None else None,
        test.database,
    )
    if runtime_identity == test_identity:
        raise LocalPaperSmokePreflightError("runtime_test_database_reuse_rejected")


def configured_paper_account_reference(
    environment: Mapping[str, str],
) -> AlpacaPaperCredentialReference | None:
    """Build the all-or-none nonsecret account identity pins."""

    if not isinstance(environment, Mapping):
        raise LocalPaperSmokePreflightError("paper_account_identity_configuration_invalid")
    values: list[str] = []
    for variable in _PAPER_ACCOUNT_IDENTITY_VARIABLES:
        value = environment.get(variable, "")
        if type(value) is not str:
            raise LocalPaperSmokePreflightError("paper_account_identity_configuration_invalid")
        values.append(value)
    present = tuple(bool(value) for value in values)
    if not any(present):
        return None
    if not all(present):
        raise LocalPaperSmokePreflightError("paper_account_identity_configuration_incomplete")
    try:
        return AlpacaPaperCredentialReference(
            account_id=values[0],
            expected_provider_account_id=values[1],
            secret_ref=values[2],
            secret_version=values[3],
        )
    except Exception:
        raise LocalPaperSmokePreflightError(
            "paper_account_identity_configuration_invalid"
        ) from None


def _nonsecret_identity_sha256(label: str, *parts: object) -> str:
    return hashlib.sha256(
        json.dumps(
            ("aqt-local-paper-smoke-nonsecret-identity-v1", label, *parts),
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode(),
    ).hexdigest()


def _owner_environment_version_sha256(path: Path) -> str:
    """Derive an opaque non-content version from one owner-only file snapshot."""

    try:
        metadata = os.stat(path, follow_symlinks=False)
    except OSError:
        raise LocalPaperSmokePreflightError("owner_environment_invalid") from None
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise LocalPaperSmokePreflightError("owner_environment_invalid")
    return _nonsecret_identity_sha256(
        "owner_environment_file_version",
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _load_preflight_environment(path: Path) -> Mapping[str, str]:
    """Load only selected bindings through the hardened owner-file boundary."""

    if not path.is_absolute():
        raise LocalPaperSmokePreflightError("owner_environment_invalid")
    try:
        return load_owner_only_environment(
            path,
            variables=_PREFLIGHT_ENVIRONMENT_VARIABLES,
            maximum_bytes=_MAXIMUM_OWNER_ENVIRONMENT_BYTES,
            reject_duplicate_variables=True,
            reject_symlinked_parents=True,
            require_current_user_owner=True,
        )
    except (OSError, ValueError):
        raise LocalPaperSmokePreflightError("owner_environment_invalid") from None


def _database_target_sha256(
    runtime_database_url: str,
    test_database_url: str,
) -> str:
    """Bind only normalized nonsecret Supabase target identities."""

    runtime = validate_supabase_session_database_url(runtime_database_url)
    test = validate_supabase_session_database_url(test_database_url)

    def identity(url: URL) -> tuple[object, ...]:
        username = url.username
        return (
            url.host,
            url.port,
            url.database,
            username.rsplit(".", 1)[1] if username is not None else None,
            "sslmode=require",
        )

    return _nonsecret_identity_sha256(
        "supabase_runtime_test_targets",
        identity(runtime),
        identity(test),
    )


def _source_version_sha256(
    *,
    purpose: str,
    owner_environment_version_sha256: str,
    target_sha256: str,
) -> str:
    if (
        _SHA256.fullmatch(owner_environment_version_sha256) is None
        or _SHA256.fullmatch(target_sha256) is None
    ):
        raise LocalPaperSmokePreflightError(f"{purpose}_binding_version_invalid")
    return _nonsecret_identity_sha256(
        f"{purpose}_source_version",
        owner_environment_version_sha256,
        target_sha256,
    )


def _client_tls_active(connection: sa.Connection) -> bool:
    try:
        driver_connection = getattr(connection.connection, "driver_connection", None)
        pg_connection = getattr(driver_connection, "pgconn", None)
        return getattr(pg_connection, "ssl_in_use", False) is True
    except TypeError:
        return False


def create_bounded_supabase_runtime_engine(database_url: str) -> Engine:
    """Create the PostgreSQL verifier engine with bounded network and SQL waits."""

    return sa.create_engine(
        make_url(database_url),
        connect_args={
            "connect_timeout": _DATABASE_CONNECT_TIMEOUT_SECONDS,
            "options": (
                f"-c statement_timeout={_DATABASE_STATEMENT_TIMEOUT_MILLISECONDS} "
                f"-c lock_timeout={_DATABASE_LOCK_TIMEOUT_MILLISECONDS}"
            ),
        },
        max_overflow=0,
        pool_pre_ping=True,
        pool_size=1,
        pool_timeout=_DATABASE_CONNECT_TIMEOUT_SECONDS,
    )


_create_bounded_runtime_engine = create_bounded_supabase_runtime_engine


def verify_runtime_database(
    runtime_database_url: str,
    test_database_url: str,
    *,
    owner_environment_version_sha256: str,
    paper_account_reference: AlpacaPaperCredentialReference | None = None,
    engine_factory: object = create_bounded_supabase_runtime_engine,
) -> LocalDatabaseVerification:
    """Verify the exact migrated runtime database without retaining its DSN."""

    validate_distinct_database_bindings(
        runtime_database_url,
        test_database_url,
    )
    if not callable(engine_factory):
        raise LocalPaperSmokePreflightError("database_engine_factory_invalid")
    engine: Engine | None = None
    try:
        candidate = engine_factory(runtime_database_url)
        if not isinstance(candidate, Engine):
            raise LocalPaperSmokePreflightError("database_engine_invalid")
        engine = candidate
        verify_operational_schema(engine, require_phase_zero_facts=False)
        account_enrollment: PaperAccountEnrollmentAttestation | None = None
        if paper_account_reference is None:
            verify_alpaca_paper_account_binding_integrity(engine)
        else:
            try:
                account_enrollment = attest_paper_account_enrollment(
                    paper_account_reference,
                    repository=SqlAlpacaPaperAccountBindingRepository(engine),
                    checked_at=datetime.now(UTC),
                )
            except PaperAccountEnrollmentAttestationError:
                raise LocalPaperSmokePreflightError(
                    "paper_account_enrollment_attestation_failed"
                ) from None
        with engine.connect() as connection:
            revision = connection.scalar(
                sa.text("SELECT version_num FROM public.alembic_version"),
            )
            public_table_count = len(
                sa.inspect(connection).get_table_names(schema="public"),
            )
            tls_active = _client_tls_active(connection)
            account_binding_head_count = int(
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM public.phase4_alpaca_paper_account_binding_heads",
                    ),
                )
                or 0
            )
            control_head_count = int(
                connection.scalar(
                    sa.text(
                        "SELECT count(*) FROM public.phase5_operational_control_heads",
                    ),
                )
                or 0
            )
            running_control_head_count = int(
                connection.scalar(
                    sa.text(
                        "SELECT count(*) "
                        "FROM public.phase5_operational_control_heads "
                        "WHERE effective_state = 'running'",
                    ),
                )
                or 0
            )
        return LocalDatabaseVerification._verified(
            client_tls_active=tls_active,
            schema_revision=str(revision),
            public_table_count=public_table_count,
            runtime_test_separated=True,
            account_binding_head_count=account_binding_head_count,
            control_head_count=control_head_count,
            running_control_head_count=running_control_head_count,
            account_enrollment=account_enrollment,
            binding_sha256=_source_version_sha256(
                purpose="database",
                owner_environment_version_sha256=owner_environment_version_sha256,
                target_sha256=_database_target_sha256(
                    runtime_database_url,
                    test_database_url,
                ),
            ),
        )
    except LocalPaperSmokePreflightError:
        raise
    except Exception:
        raise LocalPaperSmokePreflightError("runtime_database_verification_failed") from None
    finally:
        if engine is not None:
            engine.dispose()


def verify_local_image(image_reference: str) -> LocalRuntimeImageVerification:
    """Resolve one tag, then verify and return its immutable local image ID."""

    if (
        type(image_reference) is not str
        or not image_reference
        or image_reference != image_reference.strip()
    ):
        raise LocalPaperSmokePreflightError("runtime_image_reference_invalid")
    try:
        completed = subprocess.run(
            (
                "docker",
                "image",
                "inspect",
                "--format",
                "{{.Id}}",
                image_reference,
            ),
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        raise LocalPaperSmokePreflightError("runtime_image_inspection_failed") from None
    image_id = completed.stdout.strip()
    if (
        completed.returncode != 0
        or not image_id.startswith("sha256:")
        or _SHA256.fullmatch(image_id.removeprefix("sha256:")) is None
    ):
        raise LocalPaperSmokePreflightError("runtime_image_unavailable")
    try:
        verify_image(image_id)
    except PaperPreflightImageVerificationError:
        raise LocalPaperSmokePreflightError("runtime_image_contract_invalid") from None
    return LocalRuntimeImageVerification._verified(
        image_id.removeprefix("sha256:"),
    )


def _file_sha256(path: Path) -> str:
    try:
        payload = path.read_bytes()
    except OSError:
        raise LocalPaperSmokePreflightError("deployment_spec_unavailable") from None
    if not payload:
        raise LocalPaperSmokePreflightError("deployment_spec_unavailable")
    return hashlib.sha256(payload).hexdigest()


def _verify_sentry_configuration(
    *,
    dsn: str,
    release: str,
    owner_environment_version_sha256: str,
) -> LocalTelemetryVerification:
    try:
        SentryOtlpConfiguration(dsn=dsn, release=release)
    except SentryOtlpConfigurationError:
        raise LocalPaperSmokePreflightError("sentry_configuration_invalid") from None
    parsed = urlsplit(dsn)
    target_sha256 = _nonsecret_identity_sha256(
        "sentry_cloud_target",
        parsed.hostname,
        parsed.path.strip("/"),
    )
    return LocalTelemetryVerification._verified(
        _source_version_sha256(
            purpose="telemetry",
            owner_environment_version_sha256=owner_environment_version_sha256,
            target_sha256=target_sha256,
        ),
    )


def _build_verified_local_preflight(
    *,
    deployment_id: str,
    database: LocalDatabaseVerification,
    runtime_image: LocalRuntimeImageVerification,
    telemetry: LocalTelemetryVerification,
) -> PaperSmokePreflight:
    """Build the pure v2 assessment after external checks have succeeded."""

    if type(database) is not LocalDatabaseVerification:
        raise LocalPaperSmokePreflightError("runtime_database_not_ready")
    if type(runtime_image) is not LocalRuntimeImageVerification:
        raise LocalPaperSmokePreflightError("runtime_image_contract_invalid")
    if type(telemetry) is not LocalTelemetryVerification:
        raise LocalPaperSmokePreflightError("sentry_configuration_invalid")
    database.__post_init__()
    runtime_image.__post_init__()
    telemetry.__post_init__()

    revision_id = f"local-{runtime_image.content_sha256[:16]}"
    decision = RecommendedPaperDeployment.create(
        deployment_id=deployment_id,
        revision_id=revision_id,
    )
    artifact = load_no_exposure_smoke_artifact()
    source_revision = decision.revision_id
    sources = PaperDeploymentAuthoritativeSources(
        database_credentials=OpaqueSecretReference(
            purpose=PaperSecretPurpose.DATABASE,
            reference_id="secret://paper/local-owner-env/AQT_DATABASE_URL",
            version_id=f"sha256-{database.binding_sha256}",
        ),
        telemetry_credentials=OpaqueSecretReference(
            purpose=PaperSecretPurpose.TELEMETRY,
            reference_id="secret://paper/local-owner-env/AQT_SENTRY_DSN",
            version_id=f"sha256-{telemetry.binding_sha256}",
        ),
        deployment_spec=AuthoritativeSourcePin(
            kind=PaperSourceKind.DEPLOYMENT_SPEC,
            source_id="adr-0088-local-paper-smoke-profile",
            revision_id=source_revision,
            content_sha256=_file_sha256(LOCAL_PROFILE_SPEC),
        ),
        runtime_image=AuthoritativeSourcePin(
            kind=PaperSourceKind.RUNTIME_IMAGE,
            source_id="local-docker-paper-preflight-image",
            revision_id=source_revision,
            content_sha256=runtime_image.content_sha256,
        ),
        strategy_artifact=AuthoritativeSourcePin(
            kind=PaperSourceKind.STRATEGY_ARTIFACT,
            source_id="repository-no-exposure-smoke-artifact",
            revision_id=artifact.strategy_version,
            content_sha256=artifact.subprocess_spec.artifact_sha256,
        ),
        strategy_manifest=AuthoritativeSourcePin(
            kind=PaperSourceKind.STRATEGY_MANIFEST,
            source_id="repository-no-exposure-smoke-manifest",
            revision_id=artifact.strategy_version,
            content_sha256=artifact.manifest_sha256,
        ),
    )
    readiness = assess_paper_deployment_readiness(
        decision=decision,
        evidence=PaperDeploymentEvidence(sources=sources),
    )
    return PaperSmokePreflight(
        decision=decision,
        artifact=artifact,
        readiness=readiness,
    )


def _failure_payload(reason_code: str) -> dict[str, object]:
    return {
        "automatic_rearm_authorized": False,
        "broker_action_authorized": False,
        "durable_strategy_invocation": "not_authorized",
        "live_trading_authorized": False,
        "mode": "local_paper_smoke_preflight",
        "new_exposure_authorized": False,
        "phase5_activation_ready": False,
        "public_inbound_authorized": False,
        "reason": reason_code,
        "smoke_deployable": False,
        "status": "not_ready",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--env-file",
        required=True,
        type=Path,
        help="absolute owner-only dotenv path containing the runtime bindings",
    )
    parser.add_argument(
        "--image",
        default=DEFAULT_LOCAL_IMAGE,
        help="exact local production image reference to inspect",
    )
    parser.add_argument(
        "--deployment-id",
        default=DEFAULT_DEPLOYMENT_ID,
        help="nonsecret local deployment identity",
    )
    arguments = parser.parse_args()

    try:
        owner_environment_version_sha256 = _owner_environment_version_sha256(
            arguments.env_file,
        )
        environment = _load_preflight_environment(arguments.env_file)
        if (
            _owner_environment_version_sha256(arguments.env_file)
            != owner_environment_version_sha256
        ):
            raise LocalPaperSmokePreflightError("owner_environment_changed")
        runtime_database_url = environment.get("AQT_DATABASE_URL", "")
        test_database_url = environment.get("AQT_TEST_POSTGRES_URL", "")
        sentry_dsn = environment.get("AQT_SENTRY_DSN", "")
        if not runtime_database_url or not test_database_url:
            raise LocalPaperSmokePreflightError("database_binding_missing")
        if not sentry_dsn:
            raise LocalPaperSmokePreflightError("sentry_binding_missing")
        paper_account_reference = configured_paper_account_reference(environment)

        database = verify_runtime_database(
            runtime_database_url,
            test_database_url,
            owner_environment_version_sha256=owner_environment_version_sha256,
            paper_account_reference=paper_account_reference,
        )
        runtime_image = verify_local_image(arguments.image)
        release = f"local-{runtime_image.content_sha256[:16]}"
        telemetry = _verify_sentry_configuration(
            dsn=sentry_dsn,
            release=release,
            owner_environment_version_sha256=owner_environment_version_sha256,
        )
        preflight = _build_verified_local_preflight(
            deployment_id=arguments.deployment_id,
            database=database,
            runtime_image=runtime_image,
            telemetry=telemetry,
        )
        payload = preflight.public_payload
        payload.update(
            {
                "database": {
                    "client_tls_active": database.client_tls_active,
                    "account_binding_head_count": database.account_binding_head_count,
                    "control_head_count": database.control_head_count,
                    "operational_control_observation": (database.operational_control_observation),
                    "public_table_count": database.public_table_count,
                    "running_control_head_count": database.running_control_head_count,
                    "runtime_test_separated": database.runtime_test_separated,
                    "schema_revision": database.schema_revision,
                    "verified": True,
                },
                "durable_strategy_invocation": "blocked_no_bound_running_control",
                "external_notifications": "unavailable",
                "mode": "local_paper_smoke_preflight",
                "paper_account_enrollment": (
                    database.account_enrollment.public_payload
                    if database.account_enrollment is not None
                    else {
                        "account_status_current": False,
                        "automatic_rearm_authorized": False,
                        "binding_fresh": False,
                        "broker_action_authorized": False,
                        "contract_version": (PAPER_ACCOUNT_ENROLLMENT_ATTESTATION_CONTRACT_VERSION),
                        "current": False,
                        "historical": False,
                        "new_exposure_authorized": False,
                        "operational_control_authenticated": False,
                        "status": "not_configured",
                        "strategy_invocation_authorized": False,
                    }
                ),
                "operational_control": {
                    "account_binding": database.account_binding_observation,
                    "configured_start_state": "paused",
                    "effect_authorized": False,
                    "observed": database.operational_control_observation,
                },
                "telemetry": {
                    "configuration_valid": True,
                    "diagnostic_only": True,
                    "provider_id": telemetry.provider_id,
                    "queryable_ingestion_verified": False,
                },
            },
        )
        print(json.dumps(payload, sort_keys=True), flush=True)
        return 0 if preflight.readiness.smoke_deployable else 2
    except (LocalPaperSmokePreflightError, ValueError) as error:
        reason_code = (
            error.reason_code
            if isinstance(error, LocalPaperSmokePreflightError)
            else "owner_environment_invalid"
        )
        print(json.dumps(_failure_payload(reason_code), sort_keys=True), flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
