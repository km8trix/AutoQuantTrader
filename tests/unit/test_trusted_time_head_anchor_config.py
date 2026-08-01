from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import pytest

from apps.trusted_time_supervisor.config import TrustedTimeSupervisorConfigurationError
from apps.trusted_time_supervisor.head_anchor_config import (
    TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_CONTRACT_VERSION,
    TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_CONTRACT_VERSION,
    TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
    TRUSTED_TIME_HEAD_ANCHOR_STALE_AFTER_SECONDS,
    TrustedTimeHeadAnchorAuthority,
    decode_trusted_time_head_anchor_auth_secret,
    decode_trusted_time_head_anchor_authority,
    load_trusted_time_head_anchor_runtime_configuration,
    runtime_database_project_ref,
    trusted_time_head_anchor_deployment_identity_sha256,
    trusted_time_head_anchor_project_identity_sha256,
)
from packages.application.trusted_time_head_anchor import (
    TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
)

HOST_ID = "local-paper-docker-primary-v1"
SOURCE_AUTHORITY_SHA256 = "a" * 64
RUNTIME_PROJECT_REF = "abcdefghijklmnopqrst"
ANCHOR_PROJECT_REF = "bcdefghijklmnopqrstu"
PRINCIPAL_ID = "12345678-1234-4234-9234-123456789abc"
KEY_ID = "aqt-trusted-time-anchor-ed25519-v1"
PRIVATE_KEY = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
PUBLIC_KEY = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
PUBLIC_KEY_SHA256 = hashlib.sha256(PUBLIC_KEY).hexdigest()
DATABASE_URL = (
    "postgresql+psycopg://postgres.abcdefghijklmnopqrst:database-password"
    "@aws-0-us-east-1.pooler.supabase.com:5432/postgres?sslmode=verify-full"
)
PUBLISHABLE_KEY = "sb_publishable_abcdefghijklmnopqrstuvwxyz12345"
EMAIL = "trusted-time-anchor@example.invalid"
PASSWORD = "correct-horse-battery-staple-anchor-1!"


def _authority_object() -> dict[str, object]:
    runtime_identity = trusted_time_head_anchor_project_identity_sha256(
        role="runtime_database",
        project_ref=RUNTIME_PROJECT_REF,
    )
    anchor_identity = trusted_time_head_anchor_project_identity_sha256(
        role="external_anchor",
        project_ref=ANCHOR_PROJECT_REF,
    )
    deployment_identity = trusted_time_head_anchor_deployment_identity_sha256(
        host_id=HOST_ID,
        source_authority_sha256=SOURCE_AUTHORITY_SHA256,
        runtime_database_identity_sha256=runtime_identity,
        anchor_project_identity_sha256=anchor_identity,
        principal_id=PRINCIPAL_ID,
        signing_key_id=KEY_ID,
        signing_public_key_sha256=PUBLIC_KEY_SHA256,
    )
    return {
        "anchor_project_identity_sha256": anchor_identity,
        "anchor_project_ref": ANCHOR_PROJECT_REF,
        "anchor_project_url": f"https://{ANCHOR_PROJECT_REF}.supabase.co",
        "authority": {
            "alert_delivery": False,
            "automatic_rearm": False,
            "external_head_anchor_evidence_only": True,
            "live_trading": False,
            "new_exposure": False,
            "operational_control": False,
            "paper_trading": False,
            "readiness": False,
        },
        "bucket_name": TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
        "checkpoint": {
            "checkpoint_interval_seconds": 300,
            "full_prefix_verification_required": True,
            "no_overwrite_required": True,
            "stale_after_seconds": 360,
        },
        "contract_version": TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_CONTRACT_VERSION,
        "deployment_identity_sha256": deployment_identity,
        "host_id": HOST_ID,
        "principal_id": PRINCIPAL_ID,
        "runtime_database_identity_sha256": runtime_identity,
        "runtime_database_project_ref": RUNTIME_PROJECT_REF,
        "signing": {
            "algorithm": "Ed25519",
            "key_id": KEY_ID,
            "public_key_base64": base64.b64encode(PUBLIC_KEY).decode("ascii"),
            "public_key_sha256": PUBLIC_KEY_SHA256,
        },
        "source_authority_sha256": SOURCE_AUTHORITY_SHA256,
    }


def _authority_payload(value: dict[str, object] | None = None) -> bytes:
    return json.dumps(
        _authority_object() if value is None else value,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _auth_secret_payload(**changes: str) -> bytes:
    value = {
        "contract_version": TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_CONTRACT_VERSION,
        "email": EMAIL,
        "password": PASSWORD,
        "principal_id": PRINCIPAL_ID,
        "project_url": f"https://{ANCHOR_PROJECT_REF}.supabase.co",
        "publishable_key": PUBLISHABLE_KEY,
        **changes,
    }
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("ascii")


def _authority() -> TrustedTimeHeadAnchorAuthority:
    return decode_trusted_time_head_anchor_authority(
        _authority_payload(),
        database_url=DATABASE_URL,
        expected_host_id=HOST_ID,
        expected_source_authority_sha256=SOURCE_AUTHORITY_SHA256,
    )


def test_authority_binds_separate_projects_principal_key_and_policy() -> None:
    authority = _authority()

    assert authority.runtime_database_project_ref == RUNTIME_PROJECT_REF
    assert authority.anchor_project_ref == ANCHOR_PROJECT_REF
    assert authority.anchor_project_ref != authority.runtime_database_project_ref
    assert authority.bucket_name == TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME
    assert authority.principal_id == PRINCIPAL_ID
    assert authority.signing_public_key_bytes == PUBLIC_KEY
    assert authority.checkpoint_interval_seconds == (
        TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
    )
    assert authority.stale_after_seconds == TRUSTED_TIME_HEAD_ANCHOR_STALE_AFTER_SECONDS
    assert authority.anchor_authority_sha256 == hashlib.sha256(_authority_payload()).hexdigest()
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
        assert getattr(authority, field_name) is False


def test_authority_rejects_identity_policy_and_source_drift() -> None:
    for section, field_name, replacement in (
        (None, "deployment_identity_sha256", "f" * 64),
        (None, "principal_id", "not-a-uuid"),
        (None, "host_id", "other-host"),
        ("authority", "readiness", True),
        ("checkpoint", "stale_after_seconds", 361),
    ):
        value = _authority_object()
        target = value if section is None else value[section]
        assert isinstance(target, dict)
        target[field_name] = replacement
        with pytest.raises(TrustedTimeSupervisorConfigurationError):
            decode_trusted_time_head_anchor_authority(
                _authority_payload(value),
                database_url=DATABASE_URL,
                expected_host_id=HOST_ID,
                expected_source_authority_sha256=SOURCE_AUTHORITY_SHA256,
            )


def test_runtime_database_project_ref_rejects_other_database_shapes() -> None:
    assert runtime_database_project_ref(DATABASE_URL) == RUNTIME_PROJECT_REF
    for value in (
        "sqlite+pysqlite:///:memory:",
        DATABASE_URL.replace("postgres.abcdefghijklmnopqrst", "postgres"),
        DATABASE_URL.replace("pooler.supabase.com", "database.invalid"),
    ):
        with pytest.raises(TrustedTimeSupervisorConfigurationError, match="identity"):
            runtime_database_project_ref(value)


def test_auth_secret_accepts_only_the_admitted_publishable_principal() -> None:
    authority = _authority()
    credentials = decode_trusted_time_head_anchor_auth_secret(
        _auth_secret_payload(),
        authority=authority,
    )

    assert credentials.project_ref == ANCHOR_PROJECT_REF
    assert credentials.principal_id == PRINCIPAL_ID
    rendered = repr(credentials)
    assert PASSWORD not in rendered
    assert PUBLISHABLE_KEY not in rendered

    for changes in (
        {"principal_id": "22345678-1234-4234-9234-123456789abc"},
        {"publishable_key": "sb_secret_abcdefghijklmnopqrstuvwxyz12345"},
        {"project_url": f"https://{RUNTIME_PROJECT_REF}.supabase.co"},
    ):
        with pytest.raises(TrustedTimeSupervisorConfigurationError):
            decode_trusted_time_head_anchor_auth_secret(
                _auth_secret_payload(**changes),
                authority=authority,
            )


def test_runtime_loader_binds_secret_key_and_redacts_repr(tmp_path: Path) -> None:
    authority_path = tmp_path / "authority.json"
    auth_path = tmp_path / "auth.json"
    key_path = tmp_path / "signing-key"
    authority_path.write_bytes(_authority_payload())
    auth_path.write_bytes(_auth_secret_payload())
    key_path.write_bytes(PRIVATE_KEY)
    for path in (authority_path, auth_path, key_path):
        path.chmod(0o600)

    runtime = load_trusted_time_head_anchor_runtime_configuration(
        database_url=DATABASE_URL,
        expected_host_id=HOST_ID,
        expected_source_authority_sha256=SOURCE_AUTHORITY_SHA256,
        authority_path=authority_path,
        auth_secret_path=auth_path,
        signing_key_secret_path=key_path,
        authority_owner_uid=os.getuid(),
        secret_owner_uid=os.getuid(),
    )

    signature = runtime.signer.sign_ed25519(
        signing_key_id=KEY_ID,
        signing_public_key_sha256=PUBLIC_KEY_SHA256,
        payload=b"phase6d-anchor",
    )
    assert runtime.verifier.verify_ed25519(
        signing_key_id=KEY_ID,
        signing_public_key_sha256=PUBLIC_KEY_SHA256,
        payload=b"phase6d-anchor",
        signature=signature,
    )
    rendered = repr(runtime)
    assert PRIVATE_KEY.hex() not in rendered
    assert PASSWORD not in rendered
    assert PUBLISHABLE_KEY not in rendered

    key_path.write_bytes(b"x" * 32)
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="signing identity"):
        load_trusted_time_head_anchor_runtime_configuration(
            database_url=DATABASE_URL,
            expected_host_id=HOST_ID,
            expected_source_authority_sha256=SOURCE_AUTHORITY_SHA256,
            authority_path=authority_path,
            auth_secret_path=auth_path,
            signing_key_secret_path=key_path,
            authority_owner_uid=os.getuid(),
            secret_owner_uid=os.getuid(),
        )


def test_runtime_loader_rejects_writable_or_symlinked_secret(tmp_path: Path) -> None:
    authority_path = tmp_path / "authority.json"
    auth_path = tmp_path / "auth.json"
    key_path = tmp_path / "signing-key"
    authority_path.write_bytes(_authority_payload())
    auth_path.write_bytes(_auth_secret_payload())
    key_path.write_bytes(PRIVATE_KEY)
    for path in (authority_path, auth_path, key_path):
        path.chmod(0o600)

    auth_path.chmod(0o622)
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="writable"):
        load_trusted_time_head_anchor_runtime_configuration(
            database_url=DATABASE_URL,
            expected_host_id=HOST_ID,
            expected_source_authority_sha256=SOURCE_AUTHORITY_SHA256,
            authority_path=authority_path,
            auth_secret_path=auth_path,
            signing_key_secret_path=key_path,
            authority_owner_uid=os.getuid(),
            secret_owner_uid=os.getuid(),
        )

    auth_path.chmod(0o600)
    link_path = tmp_path / "signing-key-link"
    link_path.symlink_to(key_path)
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="unavailable"):
        load_trusted_time_head_anchor_runtime_configuration(
            database_url=DATABASE_URL,
            expected_host_id=HOST_ID,
            expected_source_authority_sha256=SOURCE_AUTHORITY_SHA256,
            authority_path=authority_path,
            auth_secret_path=auth_path,
            signing_key_secret_path=link_path,
            authority_owner_uid=os.getuid(),
            secret_owner_uid=os.getuid(),
        )
