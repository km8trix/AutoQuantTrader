from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from packages.application.paper_deployment import PaperDeploymentBlocker
from packages.persistence.database import EXPECTED_SCHEMA_REVISION
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
    "@aws-0-us-east-1.pooler.supabase.com:5432/postgres?sslmode=require"
)
TEST_URL = (
    "postgresql+psycopg://postgres.uvwxyzabcdefghijklmn:test-password"
    "@aws-0-us-east-1.pooler.supabase.com:5432/postgres?sslmode=require"
)
IMAGE_SHA256 = "a" * 64
DATABASE_BINDING_SHA256 = "b" * 64
TELEMETRY_BINDING_SHA256 = "c" * 64
OWNER_ENVIRONMENT_VERSION_SHA256 = "e" * 64
SENTRY_DSN = "https://11111111111111111111111111111111@o123.ingest.us.sentry.io/456789"


def _database_verification(
    *,
    binding_sha256: str = DATABASE_BINDING_SHA256,
    client_tls_active: bool = True,
    account_binding_head_count: int = 0,
    control_head_count: int = 0,
    running_control_head_count: int = 0,
) -> LocalDatabaseVerification:
    return LocalDatabaseVerification._verified(
        client_tls_active=client_tls_active,
        schema_revision=EXPECTED_SCHEMA_REVISION,
        public_table_count=len(metadata.tables) + 1,
        runtime_test_separated=True,
        account_binding_head_count=account_binding_head_count,
        control_head_count=control_head_count,
        running_control_head_count=running_control_head_count,
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
    bound = _database_verification(account_binding_head_count=1)

    assert unbound.account_binding_observation == "unbound"
    assert bound.account_binding_observation == "bound_non_authorizing"
    assert bound.running_control_head_count == 0


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
            RUNTIME_URL.replace("?sslmode=require", ""),
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
    assert verified.public_table_count == 124
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
