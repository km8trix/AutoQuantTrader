from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from packages.adapters.broker.alpaca_paper_account_runtime import (
    AlpacaPaperAccountIdentityContinuityReceipt,
    AlpacaPaperCredentialReference,
)
from packages.application.paper_account_enrollment import (
    PaperAccountEnrollmentAttestation,
    attest_paper_account_enrollment,
)
from packages.application.paper_deployment import PaperDeploymentBlocker
from packages.persistence.database import EXPECTED_SCHEMA_REVISION
from packages.persistence.postgres_tls import SUPABASE_DATABASE_CA_PATH
from packages.persistence.schema import metadata
from scripts import verify_local_paper_smoke_preflight as local_preflight
from scripts.verify_local_paper_smoke_preflight import (
    LocalDatabaseVerification,
    LocalPaperSmokePreflightError,
    LocalRuntimeImageVerification,
    LocalTelemetryVerification,
    validate_distinct_database_bindings,
    verify_local_image,
)
from scripts.verify_paper_preflight_image import (
    PaperPreflightImageVerificationError,
)

RUNTIME_URL = (
    "postgresql+psycopg://postgres.abcdefghijklmnopqrst:runtime-password"
    "@aws-0-us-east-1.pooler.supabase.com:5432/postgres?sslmode=verify-full"
)
TEST_URL = (
    "postgresql+psycopg://postgres.uvwxyzabcdefghijklmn:test-password"
    "@aws-0-us-east-1.pooler.supabase.com:5432/postgres?sslmode=verify-full"
)
IMAGE_SHA256 = "a" * 64
DATABASE_BINDING_SHA256 = "b" * 64
TELEMETRY_BINDING_SHA256 = "c" * 64
OWNER_ENVIRONMENT_VERSION_SHA256 = "e" * 64
SENTRY_DSN = "https://11111111111111111111111111111111@o123.ingest.us.sentry.io/456789"
ACCOUNT_ID = "alpaca-paper-primary"
PROVIDER_ACCOUNT_ID = "734cfc97-320f-49b1-9a50-8ec9f96b569c"
CHECKED_AT = datetime(2026, 7, 31, 14, 30, tzinfo=UTC)


def _account_enrollment_attestation() -> PaperAccountEnrollmentAttestation:
    reference = AlpacaPaperCredentialReference(
        account_id=ACCOUNT_ID,
        expected_provider_account_id=PROVIDER_ACCOUNT_ID,
        secret_ref="secret://paper/alpaca/primary",
        secret_version="2026-07-30",
    )
    receipt = object.__new__(AlpacaPaperAccountIdentityContinuityReceipt)
    for field_name, value in (
        ("account_id", reference.account_id),
        ("binding_id", "9bcb1bf9-30f5-41d7-bfaa-e0a207d7c49c"),
        ("binding_sha256", "1" * 64),
        ("credential_reference_sha256", reference.semantic_sha256),
        ("expected_provider_account_id", reference.expected_provider_account_id),
        ("sequence_number", 1),
        ("binding_qualified_at", CHECKED_AT - timedelta(days=1)),
        ("checked_at", CHECKED_AT),
    ):
        object.__setattr__(receipt, field_name, value)

    class Repository:
        def authenticate_configured_terminal_identity(
            self,
            candidate: AlpacaPaperCredentialReference,
            checked_at: datetime,
        ) -> AlpacaPaperAccountIdentityContinuityReceipt:
            assert candidate == reference
            assert checked_at == CHECKED_AT
            return receipt

    return attest_paper_account_enrollment(
        reference,
        repository=Repository(),
        checked_at=CHECKED_AT,
    )


def _database_verification(
    *,
    binding_sha256: str = DATABASE_BINDING_SHA256,
    client_tls_active: bool = True,
    account_binding_head_count: int = 0,
    control_head_count: int = 0,
    running_control_head_count: int = 0,
    account_enrollment: PaperAccountEnrollmentAttestation | None = None,
) -> LocalDatabaseVerification:
    return LocalDatabaseVerification._verified(
        client_tls_active=client_tls_active,
        schema_revision=EXPECTED_SCHEMA_REVISION,
        public_table_count=len(metadata.tables) + 1,
        runtime_test_separated=True,
        account_binding_head_count=account_binding_head_count,
        control_head_count=control_head_count,
        running_control_head_count=running_control_head_count,
        account_enrollment=account_enrollment,
        binding_sha256=binding_sha256,
    )


def _image_verification() -> LocalRuntimeImageVerification:
    return LocalRuntimeImageVerification._verified(IMAGE_SHA256)


def _telemetry_verification(
    binding_sha256: str = TELEMETRY_BINDING_SHA256,
) -> LocalTelemetryVerification:
    return LocalTelemetryVerification._verified(binding_sha256)


def test_distinct_supabase_session_tls_bindings_are_accepted() -> None:
    validate_distinct_database_bindings(RUNTIME_URL, TEST_URL)


def test_authenticated_binding_heads_are_reported_without_authorizing_control() -> None:
    unbound = _database_verification()
    unattested = _database_verification(account_binding_head_count=1)
    attestation = _account_enrollment_attestation()
    attested = _database_verification(
        account_binding_head_count=1,
        account_enrollment=attestation,
    )

    assert unbound.account_binding_observation == "unbound"
    assert unattested.account_binding_observation == "binding_heads_present_unattested"
    assert (
        attested.account_binding_observation
        == "configured_historical_identity_attested_non_authorizing"
    )
    assert attested.account_enrollment == attestation
    assert unattested.running_control_head_count == 0


def test_paper_account_identity_configuration_is_all_or_none() -> None:
    assert local_preflight.configured_paper_account_reference({}) is None
    environment = {
        "AQT_PAPER_ACCOUNT_ID": "alpaca-paper-primary",
        "AQT_PAPER_PROVIDER_ACCOUNT_ID": "734cfc97-320f-49b1-9a50-8ec9f96b569c",
        "AQT_PAPER_BROKER_SECRET_REF": "secret://paper/alpaca/primary",
        "AQT_PAPER_BROKER_SECRET_VERSION": "2026-07-30",
    }

    reference = local_preflight.configured_paper_account_reference(environment)

    assert reference is not None
    assert reference.account_id == environment["AQT_PAPER_ACCOUNT_ID"]
    assert reference.expected_provider_account_id == environment["AQT_PAPER_PROVIDER_ACCOUNT_ID"]
    assert reference.secret_ref == environment["AQT_PAPER_BROKER_SECRET_REF"]
    assert reference.secret_version == environment["AQT_PAPER_BROKER_SECRET_VERSION"]

    for missing in environment:
        partial = dict(environment)
        partial.pop(missing)
        with pytest.raises(
            LocalPaperSmokePreflightError,
            match="paper_account_identity_configuration_incomplete",
        ):
            local_preflight.configured_paper_account_reference(partial)


def test_invalid_paper_account_identity_configuration_is_sanitized() -> None:
    environment = {
        "AQT_PAPER_ACCOUNT_ID": "alpaca-paper-primary",
        "AQT_PAPER_PROVIDER_ACCOUNT_ID": "not-a-provider-uuid",
        "AQT_PAPER_BROKER_SECRET_REF": "secret://paper/alpaca/primary",
        "AQT_PAPER_BROKER_SECRET_VERSION": "2026-07-30",
    }

    with pytest.raises(
        LocalPaperSmokePreflightError,
        match="paper_account_identity_configuration_invalid",
    ) as failure:
        local_preflight.configured_paper_account_reference(environment)

    assert "not-a-provider-uuid" not in str(failure.value)


def test_database_target_identity_excludes_credentials_but_binds_projects() -> None:
    target = local_preflight._database_target_sha256(RUNTIME_URL, TEST_URL)

    assert target == local_preflight._database_target_sha256(
        RUNTIME_URL.replace("runtime-password", "rotated-runtime-password"),
        TEST_URL.replace("test-password", "rotated-test-password"),
    )
    assert target != local_preflight._database_target_sha256(
        RUNTIME_URL.replace(
            "abcdefghijklmnopqrst",
            "bcdefghijklmnopqrstu",
        ),
        TEST_URL,
    )


def test_sentry_binding_excludes_client_key_but_binds_project() -> None:
    release = f"local-{IMAGE_SHA256[:16]}"
    first = local_preflight._verify_sentry_configuration(
        dsn=SENTRY_DSN,
        release=release,
        owner_environment_version_sha256=OWNER_ENVIRONMENT_VERSION_SHA256,
    )
    rotated_key = local_preflight._verify_sentry_configuration(
        dsn=SENTRY_DSN.replace("1" * 32, "2" * 32),
        release=release,
        owner_environment_version_sha256=OWNER_ENVIRONMENT_VERSION_SHA256,
    )
    different_project = local_preflight._verify_sentry_configuration(
        dsn=SENTRY_DSN.replace("/456789", "/456790"),
        release=release,
        owner_environment_version_sha256=OWNER_ENVIRONMENT_VERSION_SHA256,
    )

    assert first.binding_sha256 == rotated_key.binding_sha256
    assert first.binding_sha256 != different_project.binding_sha256


def test_owner_environment_file_version_is_noncontent_metadata_bound(
    tmp_path: Path,
) -> None:
    path = tmp_path / ".env"
    path.write_text("AQT_DATABASE_URL=first\n", encoding="utf-8")
    path.chmod(0o600)
    first = local_preflight._owner_environment_version_sha256(path)
    path.write_text("AQT_DATABASE_URL=second\n", encoding="utf-8")

    assert first != local_preflight._owner_environment_version_sha256(path)


def test_preflight_environment_loader_is_hardened_and_excludes_alpaca_api_variables(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: dict[str, object] = {}
    expected = {"AQT_DATABASE_URL": "opaque"}

    def load_environment(path: Path, **kwargs: object) -> dict[str, str]:
        captured["path"] = path
        captured.update(kwargs)
        return expected

    path = tmp_path / ".env"
    monkeypatch.setattr(
        local_preflight,
        "load_owner_only_environment",
        load_environment,
    )

    assert local_preflight._load_preflight_environment(path) is expected
    assert captured == {
        "path": path,
        "variables": local_preflight._PREFLIGHT_ENVIRONMENT_VARIABLES,
        "maximum_bytes": local_preflight._MAXIMUM_OWNER_ENVIRONMENT_BYTES,
        "reject_duplicate_variables": True,
        "reject_symlinked_parents": True,
        "require_current_user_owner": True,
    }
    requested = set(local_preflight._PREFLIGHT_ENVIRONMENT_VARIABLES)
    assert requested.isdisjoint(
        {
            "ALPACA_PAPER_API_KEY",
            "ALPACA_PAPER_API_SECRET",
            "ALPACA_PAPER_BASE_URL",
        }
    )


def test_preflight_environment_loader_rejects_relative_path() -> None:
    with pytest.raises(
        LocalPaperSmokePreflightError,
        match="owner_environment_invalid",
    ):
        local_preflight._load_preflight_environment(Path(".env"))


def test_preflight_environment_loader_rejects_duplicate_variables(
    tmp_path: Path,
) -> None:
    path = tmp_path / ".env"
    path.write_text(
        "AQT_PAPER_ACCOUNT_ID=first\nAQT_PAPER_ACCOUNT_ID=second\n",
        encoding="utf-8",
    )
    path.chmod(0o600)

    with pytest.raises(
        LocalPaperSmokePreflightError,
        match="owner_environment_invalid",
    ):
        local_preflight._load_preflight_environment(path)


def test_preflight_environment_loader_rejects_symlinked_parent(
    tmp_path: Path,
) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    path = real_parent / ".env"
    path.write_text("AQT_DATABASE_URL=opaque\n", encoding="utf-8")
    path.chmod(0o600)
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(
        LocalPaperSmokePreflightError,
        match="owner_environment_invalid",
    ):
        local_preflight._load_preflight_environment(linked_parent / ".env")


def test_preflight_environment_loader_rejects_oversized_file(
    tmp_path: Path,
) -> None:
    path = tmp_path / ".env"
    path.write_text(
        "UNUSED_PADDING=" + ("x" * local_preflight._MAXIMUM_OWNER_ENVIRONMENT_BYTES),
        encoding="utf-8",
    )
    path.chmod(0o600)

    with pytest.raises(
        LocalPaperSmokePreflightError,
        match="owner_environment_invalid",
    ):
        local_preflight._load_preflight_environment(path)


def test_partial_paper_identity_fails_before_external_preflight_effects(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / ".env"
    path.write_text(
        "\n".join(
            (
                f"AQT_DATABASE_URL={RUNTIME_URL}",
                f"AQT_TEST_POSTGRES_URL={TEST_URL}",
                f"AQT_SENTRY_DSN={SENTRY_DSN}",
                f"AQT_PAPER_ACCOUNT_ID={ACCOUNT_ID}",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)

    def unexpected_effect(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("external preflight effect must not run")

    monkeypatch.setattr(local_preflight, "verify_runtime_database", unexpected_effect)
    monkeypatch.setattr(local_preflight, "verify_local_image", unexpected_effect)
    monkeypatch.setattr(local_preflight, "_verify_sentry_configuration", unexpected_effect)
    monkeypatch.setattr(
        "sys.argv",
        [
            "verify_local_paper_smoke_preflight.py",
            "--env-file",
            str(path),
        ],
    )

    assert local_preflight.main() == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["reason"] == "paper_account_identity_configuration_incomplete"
    serialized = json.dumps(payload, sort_keys=True)
    for sensitive_value in (
        RUNTIME_URL,
        TEST_URL,
        SENTRY_DSN,
        ACCOUNT_ID,
    ):
        assert sensitive_value not in serialized


def test_runtime_engine_bounds_connect_pool_statement_and_lock_waits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    sentinel = object()

    def create_engine(url: object, **kwargs: object) -> object:
        captured["url"] = url
        captured.update(kwargs)
        return sentinel

    monkeypatch.setattr(local_preflight.sa, "create_engine", create_engine)

    assert local_preflight._create_bounded_runtime_engine(RUNTIME_URL) is sentinel
    assert captured["pool_pre_ping"] is True
    assert captured["pool_size"] == 1
    assert captured["max_overflow"] == 0
    assert captured["pool_timeout"] == 10
    assert captured["connect_args"] == {
        "connect_timeout": 10,
        "sslmode": "verify-full",
        "sslrootcert": str(SUPABASE_DATABASE_CA_PATH),
        "options": "-c statement_timeout=30000 -c lock_timeout=5000",
    }


@pytest.mark.parametrize(
    ("runtime_url", "test_url", "reason"),
    (
        (
            RUNTIME_URL,
            RUNTIME_URL,
            "runtime_test_database_reuse_rejected",
        ),
        (
            RUNTIME_URL.replace(":5432/", ":6543/"),
            TEST_URL,
            "database_url_not_supabase_session_tls",
        ),
        (
            RUNTIME_URL.replace("?sslmode=verify-full", ""),
            TEST_URL,
            "database_url_not_supabase_session_tls",
        ),
        (
            RUNTIME_URL.replace("pooler.supabase.com", "example.invalid"),
            TEST_URL,
            "database_url_not_supabase_session_tls",
        ),
        (
            f"{RUNTIME_URL}&host=attacker.invalid",
            TEST_URL,
            "database_url_not_supabase_session_tls",
        ),
        (
            f"{RUNTIME_URL}&port=443",
            TEST_URL,
            "database_url_not_supabase_session_tls",
        ),
        (
            f"{RUNTIME_URL}&options=-csearch_path%3Dattacker",
            TEST_URL,
            "database_url_not_supabase_session_tls",
        ),
    ),
)
def test_database_binding_drift_fails_closed_without_rendering_credentials(
    runtime_url: str,
    test_url: str,
    reason: str,
) -> None:
    with pytest.raises(LocalPaperSmokePreflightError, match=reason) as failure:
        validate_distinct_database_bindings(runtime_url, test_url)

    rendered = f"{failure.value!s} {failure.value!r}"
    assert "runtime-password" not in rendered
    assert "test-password" not in rendered


def test_bound_local_packaging_is_smoke_ready_but_cannot_activate_phase5() -> None:
    preflight = local_preflight._build_verified_local_preflight(
        deployment_id="local-paper-smoke-test",
        database=_database_verification(),
        runtime_image=_image_verification(),
        telemetry=_telemetry_verification(),
    )

    assert preflight.readiness.smoke_deployable
    assert not preflight.readiness.phase5_activation_ready
    assert preflight.readiness.smoke_blockers == ()
    assert PaperDeploymentBlocker.BROKER_SECRET_SOURCE_MISSING in (
        preflight.readiness.activation_blockers
    )
    assert PaperDeploymentBlocker.EXTERNAL_ALERTS_DEFERRED in (
        preflight.readiness.activation_blockers
    )
    assert PaperDeploymentBlocker.LOCAL_OWNER_SUPERVISION_ONLY in (
        preflight.readiness.activation_blockers
    )
    payload = preflight.public_payload
    assert payload["status"] == "smoke_preflight_ready"
    assert payload["smoke_deployable"] is True
    assert payload["phase5_activation_ready"] is False
    assert payload["broker_action_authorized"] is False
    assert payload["new_exposure_authorized"] is False


def test_historical_enrollment_attestation_cannot_change_smoke_authority() -> None:
    baseline = local_preflight._build_verified_local_preflight(
        deployment_id="local-paper-smoke-test",
        database=_database_verification(account_binding_head_count=1),
        runtime_image=_image_verification(),
        telemetry=_telemetry_verification(),
    )
    attested = local_preflight._build_verified_local_preflight(
        deployment_id="local-paper-smoke-test",
        database=_database_verification(
            account_binding_head_count=1,
            account_enrollment=_account_enrollment_attestation(),
        ),
        runtime_image=_image_verification(),
        telemetry=_telemetry_verification(),
    )

    assert attested == baseline
    assert attested.readiness.smoke_deployable
    assert not attested.readiness.phase5_activation_ready
    assert attested.public_payload["broker_action_authorized"] is False
    assert attested.public_payload["new_exposure_authorized"] is False
    assert attested.public_payload["automatic_rearm_authorized"] is False


def test_local_image_inspection_accepts_only_one_exact_sha256(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verified_references: list[str] = []

    def verify_image(image_reference: str) -> None:
        verified_references.append(image_reference)

    def inspect(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        del args, kwargs
        return subprocess.CompletedProcess(
            args=("docker",),
            returncode=0,
            stdout=f"sha256:{IMAGE_SHA256}\n",
            stderr="",
        )

    monkeypatch.setattr(local_preflight, "verify_image", verify_image)
    monkeypatch.setattr(local_preflight.subprocess, "run", inspect)

    verification = verify_local_image("autoquanttrader-runtime:test")
    assert verification.content_sha256 == IMAGE_SHA256
    assert verified_references == [f"sha256:{IMAGE_SHA256}"]


def test_local_image_inspection_rejects_failed_runtime_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_image(image_reference: str) -> None:
        del image_reference
        raise PaperPreflightImageVerificationError("unsafe image")

    def inspect(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        del args, kwargs
        return subprocess.CompletedProcess(
            args=("docker",),
            returncode=0,
            stdout=f"sha256:{IMAGE_SHA256}\n",
            stderr="",
        )

    monkeypatch.setattr(local_preflight, "verify_image", reject_image)
    monkeypatch.setattr(local_preflight.subprocess, "run", inspect)

    with pytest.raises(
        LocalPaperSmokePreflightError,
        match="runtime_image_contract_invalid",
    ):
        verify_local_image("autoquanttrader-runtime:test")


def test_unsealed_runtime_evidence_is_rejected() -> None:
    with pytest.raises(
        LocalPaperSmokePreflightError,
        match="runtime_image_contract_invalid",
    ):
        LocalRuntimeImageVerification(
            content_sha256=IMAGE_SHA256,
            _seal=object(),
        )


def test_binding_rotation_changes_readiness_evidence_hash() -> None:
    first = local_preflight._build_verified_local_preflight(
        deployment_id="local-paper-smoke-test",
        database=_database_verification(),
        runtime_image=_image_verification(),
        telemetry=_telemetry_verification(),
    )
    rotated = local_preflight._build_verified_local_preflight(
        deployment_id="local-paper-smoke-test",
        database=_database_verification(binding_sha256="d" * 64),
        runtime_image=_image_verification(),
        telemetry=_telemetry_verification(),
    )

    assert first.readiness.evidence_sha256 != rotated.readiness.evidence_sha256
    assert first.readiness.semantic_sha256 != rotated.readiness.semantic_sha256


def test_database_verification_projection_rejects_partial_or_false_evidence() -> None:
    verified = _database_verification()
    assert verified.public_table_count == 129
    assert verified.operational_control_observation == "absent_fail_closed"

    with pytest.raises(LocalPaperSmokePreflightError, match="runtime_database_not_ready"):
        LocalDatabaseVerification._verified(
            client_tls_active=False,
            schema_revision=EXPECTED_SCHEMA_REVISION,
            public_table_count=len(metadata.tables) + 1,
            runtime_test_separated=True,
            account_binding_head_count=0,
            control_head_count=0,
            running_control_head_count=0,
            account_enrollment=None,
            binding_sha256=DATABASE_BINDING_SHA256,
        )

    with pytest.raises(LocalPaperSmokePreflightError, match="runtime_database_not_ready"):
        LocalDatabaseVerification._verified(
            client_tls_active=True,
            schema_revision=EXPECTED_SCHEMA_REVISION,
            public_table_count=len(metadata.tables) + 1,
            runtime_test_separated=True,
            account_binding_head_count=0,
            control_head_count=1,
            running_control_head_count=1,
            account_enrollment=None,
            binding_sha256=DATABASE_BINDING_SHA256,
        )

    with pytest.raises(LocalPaperSmokePreflightError, match="runtime_database_not_ready"):
        LocalDatabaseVerification._verified(
            client_tls_active=True,
            schema_revision=EXPECTED_SCHEMA_REVISION,
            public_table_count=len(metadata.tables) + 1,
            runtime_test_separated=True,
            account_binding_head_count=0,
            control_head_count=0,
            running_control_head_count=0,
            account_enrollment=_account_enrollment_attestation(),
            binding_sha256=DATABASE_BINDING_SHA256,
        )


def test_failure_payload_is_public_and_non_authorizing() -> None:
    payload = local_preflight._failure_payload("runtime_database_verification_failed")
    serialized = json.dumps(payload, sort_keys=True)

    assert payload["status"] == "not_ready"
    assert payload["smoke_deployable"] is False
    assert payload["phase5_activation_ready"] is False
    assert payload["broker_action_authorized"] is False
    assert payload["new_exposure_authorized"] is False
    assert "postgresql" not in serialized
    assert "password" not in serialized
