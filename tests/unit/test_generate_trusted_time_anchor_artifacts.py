from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apps.trusted_time_supervisor.head_anchor_config import (
    TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_CONTRACT_VERSION,
    TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_CONTRACT_VERSION,
    decode_trusted_time_head_anchor_auth_secret,
    decode_trusted_time_head_anchor_authority,
    trusted_time_head_anchor_deployment_identity_sha256,
    trusted_time_head_anchor_project_identity_sha256,
)
from packages.application.trusted_time_head_anchor import (
    TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
)
from scripts.generate_trusted_time_anchor_artifacts import (
    ALLOW_ENROLLMENT,
    ENROLLMENT_STATUS,
    REPOSITORY_ROOT,
    SIGNING_KEY_ID,
    TrustedTimeAnchorArtifactGenerationError,
    build_trusted_time_anchor_artifact_payloads,
    generate_trusted_time_anchor_artifacts,
    main,
)

ANCHOR_REF = "abcdefghijklmnopqrst"
RUNTIME_REF = "bcdefghijklmnopqrstu"
TEST_REF = "cdefghijklmnopqrstuv"
ANCHOR_URL = f"https://{ANCHOR_REF}.supabase.co"
PUBLISHABLE_KEY = f"sb_publishable_{'A' * 22}_{'b' * 8}"
WRITER_ID = "11111111-1111-4111-8111-111111111111"
AUTH_EMAIL = "trusted-time-writer@example.invalid"
AUTH_PASSWORD = "correct-horse-battery-staple-anchor-1!"
HOST_ID = "local-paper-docker-primary-v1"
SOURCE_AUTHORITY_SHA256 = "9b514dc25b0cd084aedf1841b305260f22b070b70e396defc9ecce2f9545506c"
PRIVATE_KEY_BYTES = bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
)
PUBLIC_KEY_BYTES = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")


def _private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(PRIVATE_KEY_BYTES)


def _payloads() -> object:
    return build_trusted_time_anchor_artifact_payloads(
        anchor_project_url=ANCHOR_URL,
        anchor_project_ref=ANCHOR_REF,
        runtime_project_ref=RUNTIME_REF,
        test_project_ref=TEST_REF,
        publishable_key=PUBLISHABLE_KEY,
        writer_principal_id=WRITER_ID,
        auth_email=AUTH_EMAIL,
        auth_password=AUTH_PASSWORD,
        host_id=HOST_ID,
        source_authority_sha256=SOURCE_AUTHORITY_SHA256,
        private_key=_private_key(),
    )


def _runtime_database_url() -> str:
    return (
        "postgresql+psycopg://postgres."
        f"{RUNTIME_REF}:password@aws-0-us-east-1.pooler.supabase.com:5432/postgres"
        "?sslmode=verify-full"
    )


def _generate(tmp_path: Path) -> tuple[object, Path, Path, Path]:
    signing_key_path = tmp_path / "trusted-time-anchor-signing-key"
    auth_secret_path = tmp_path / "trusted-time-anchor-auth.json"
    authority_path = tmp_path / "trusted-time-anchor-authority.json"
    receipt = generate_trusted_time_anchor_artifacts(
        anchor_project_url=ANCHOR_URL,
        anchor_project_ref=ANCHOR_REF,
        runtime_project_ref=RUNTIME_REF,
        test_project_ref=TEST_REF,
        publishable_key=PUBLISHABLE_KEY,
        writer_principal_id=WRITER_ID,
        auth_email=AUTH_EMAIL,
        auth_password=AUTH_PASSWORD,
        host_id=HOST_ID,
        source_authority_sha256=SOURCE_AUTHORITY_SHA256,
        signing_key_path=signing_key_path,
        auth_secret_path=auth_secret_path,
        authority_path=authority_path,
        private_key_factory=_private_key,
    )
    return receipt, signing_key_path, auth_secret_path, authority_path


def _case_alias(path: Path) -> Path | None:
    parts = list(path.parts)
    for index in range(1, len(parts)):
        replacement = parts[index].swapcase()
        if replacement == parts[index]:
            continue
        candidate_parts = [*parts]
        candidate_parts[index] = replacement
        candidate = Path(*candidate_parts)
        try:
            if candidate != path and os.path.samefile(candidate, path):
                return candidate
        except OSError:
            continue
    return None


def test_payloads_match_exact_runtime_contracts_and_bind_all_nonsecret_identities() -> None:
    payloads = cast(Any, _payloads())
    authority_object = json.loads(payloads.authority)
    auth_secret_object = json.loads(payloads.auth_secret)

    assert payloads.signing_key == PRIVATE_KEY_BYTES
    assert base64.b64decode(payloads.signing_public_key_base64, validate=True) == PUBLIC_KEY_BYTES
    assert payloads.signing_public_key_sha256 == hashlib.sha256(PUBLIC_KEY_BYTES).hexdigest()
    assert set(auth_secret_object) == {
        "contract_version",
        "email",
        "password",
        "principal_id",
        "project_url",
        "publishable_key",
    }
    assert auth_secret_object == {
        "contract_version": TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_CONTRACT_VERSION,
        "email": AUTH_EMAIL,
        "password": AUTH_PASSWORD,
        "principal_id": WRITER_ID,
        "project_url": ANCHOR_URL,
        "publishable_key": PUBLISHABLE_KEY,
    }
    assert authority_object["contract_version"] == (
        TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_CONTRACT_VERSION
    )
    assert authority_object["anchor_project_ref"] == ANCHOR_REF
    assert authority_object["runtime_database_project_ref"] == RUNTIME_REF
    assert authority_object["principal_id"] == WRITER_ID
    assert authority_object["source_authority_sha256"] == SOURCE_AUTHORITY_SHA256
    assert authority_object["host_id"] == HOST_ID
    assert authority_object["bucket_name"] == TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME
    assert authority_object["checkpoint"] == {
        "checkpoint_interval_seconds": 300,
        "full_prefix_verification_required": True,
        "no_overwrite_required": True,
        "stale_after_seconds": 360,
    }
    authority_flags = authority_object["authority"]
    assert authority_flags.pop("external_head_anchor_evidence_only") is True
    assert authority_flags and all(value is False for value in authority_flags.values())
    assert authority_object["signing"] == {
        "algorithm": "Ed25519",
        "key_id": SIGNING_KEY_ID,
        "public_key_base64": payloads.signing_public_key_base64,
        "public_key_sha256": payloads.signing_public_key_sha256,
    }
    runtime_identity = trusted_time_head_anchor_project_identity_sha256(
        role="runtime_database",
        project_ref=RUNTIME_REF,
    )
    anchor_identity = trusted_time_head_anchor_project_identity_sha256(
        role="external_anchor",
        project_ref=ANCHOR_REF,
    )
    assert authority_object["runtime_database_identity_sha256"] == runtime_identity
    assert authority_object["anchor_project_identity_sha256"] == anchor_identity
    assert authority_object["deployment_identity_sha256"] == (
        trusted_time_head_anchor_deployment_identity_sha256(
            host_id=HOST_ID,
            source_authority_sha256=SOURCE_AUTHORITY_SHA256,
            runtime_database_identity_sha256=runtime_identity,
            anchor_project_identity_sha256=anchor_identity,
            principal_id=WRITER_ID,
            signing_key_id=SIGNING_KEY_ID,
            signing_public_key_sha256=payloads.signing_public_key_sha256,
        )
    )

    authority = decode_trusted_time_head_anchor_authority(
        payloads.authority,
        database_url=_runtime_database_url(),
        expected_host_id=HOST_ID,
        expected_source_authority_sha256=SOURCE_AUTHORITY_SHA256,
    )
    credentials = decode_trusted_time_head_anchor_auth_secret(
        payloads.auth_secret,
        authority=authority,
    )
    assert credentials.principal_id == WRITER_ID
    assert AUTH_PASSWORD not in repr(payloads)
    assert PUBLISHABLE_KEY not in repr(payloads)
    assert PRIVATE_KEY_BYTES.hex() not in repr(payloads)


def test_generation_creates_three_distinct_owner_only_no_hardlink_files(tmp_path: Path) -> None:
    receipt, key_path, auth_path, authority_path = _generate(tmp_path)
    public_receipt = cast(Any, receipt).public_payload

    assert key_path.read_bytes() == PRIVATE_KEY_BYTES
    for path in (key_path, auth_path, authority_path):
        metadata = path.stat()
        assert stat.S_ISREG(metadata.st_mode)
        assert metadata.st_uid == os.geteuid()
        assert stat.S_IMODE(metadata.st_mode) == 0o600
        assert metadata.st_nlink == 1
    assert public_receipt["allow_enrollment"] is ALLOW_ENROLLMENT is False
    assert public_receipt["enrollment_status"] == ENROLLMENT_STATUS == "UNRUN"
    assert public_receipt["all_control_authority_flags_false"] is True
    assert public_receipt["external_head_anchor_evidence_only"] is True
    assert (
        public_receipt["authority_artifact_sha256"]
        == hashlib.sha256(authority_path.read_bytes()).hexdigest()
    )
    rendered = json.dumps(public_receipt, sort_keys=True)
    assert AUTH_PASSWORD not in rendered
    assert PUBLISHABLE_KEY not in rendered
    assert PRIVATE_KEY_BYTES.hex() not in rendered


def test_existing_target_rejects_entire_operation_without_overwrite_or_partial_files(
    tmp_path: Path,
) -> None:
    auth_path = tmp_path / "trusted-time-anchor-auth.json"
    auth_path.write_bytes(b"existing")
    auth_path.chmod(0o600)
    key_path = tmp_path / "trusted-time-anchor-signing-key"
    authority_path = tmp_path / "trusted-time-anchor-authority.json"

    with pytest.raises(
        TrustedTimeAnchorArtifactGenerationError,
        match="output_already_exists",
    ):
        generate_trusted_time_anchor_artifacts(
            anchor_project_url=ANCHOR_URL,
            anchor_project_ref=ANCHOR_REF,
            runtime_project_ref=RUNTIME_REF,
            test_project_ref=TEST_REF,
            publishable_key=PUBLISHABLE_KEY,
            writer_principal_id=WRITER_ID,
            auth_email=AUTH_EMAIL,
            auth_password=AUTH_PASSWORD,
            host_id=HOST_ID,
            source_authority_sha256=SOURCE_AUTHORITY_SHA256,
            signing_key_path=key_path,
            auth_secret_path=auth_path,
            authority_path=authority_path,
            private_key_factory=_private_key,
        )

    assert auth_path.read_bytes() == b"existing"
    assert not key_path.exists()
    assert not authority_path.exists()
    assert not tuple(tmp_path.glob(".*.tmp"))


@pytest.mark.parametrize("failed_link_call", [1, 2, 3])
def test_link_stage_failure_rolls_back_every_final_and_temporary_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_link_call: int,
) -> None:
    original_link = os.link
    link_calls = 0

    def failing_link(*args: object, **kwargs: object) -> None:
        nonlocal link_calls
        link_calls += 1
        if link_calls == failed_link_call:
            raise OSError("injected link failure")
        original_link(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        "scripts.generate_trusted_time_anchor_artifacts.os.link",
        failing_link,
    )

    with pytest.raises(
        TrustedTimeAnchorArtifactGenerationError,
        match="output_write_failed",
    ):
        _generate(tmp_path)

    assert link_calls == failed_link_call
    assert not (tmp_path / "trusted-time-anchor-signing-key").exists()
    assert not (tmp_path / "trusted-time-anchor-auth.json").exists()
    assert not (tmp_path / "trusted-time-anchor-authority.json").exists()
    assert not tuple(tmp_path.glob(".*.tmp"))


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"runtime_project_ref": ANCHOR_REF}, "anchor_runtime_test_projects_not_distinct"),
        (
            {"anchor_project_url": f"https://{RUNTIME_REF}.supabase.co"},
            "anchor_project_url_invalid",
        ),
        ({"publishable_key": f"sb_secret_{'A' * 22}_{'b' * 8}"}, "anchor_secret_key_rejected"),
        ({"publishable_key": "eyJhbGciOiJIUzI1NiJ9.service_role.signature"}, "legacy_jwt"),
        ({"writer_principal_id": "00000000-0000-0000-0000-000000000000"}, "principal"),
        ({"source_authority_sha256": "A" * 64}, "sha256_invalid"),
    ],
)
def test_generation_fails_closed_on_project_key_principal_or_source_drift(
    changes: dict[str, object],
    reason: str,
) -> None:
    values: dict[str, object] = {
        "anchor_project_url": ANCHOR_URL,
        "anchor_project_ref": ANCHOR_REF,
        "runtime_project_ref": RUNTIME_REF,
        "test_project_ref": TEST_REF,
        "publishable_key": PUBLISHABLE_KEY,
        "writer_principal_id": WRITER_ID,
        "auth_email": AUTH_EMAIL,
        "auth_password": AUTH_PASSWORD,
        "host_id": HOST_ID,
        "source_authority_sha256": SOURCE_AUTHORITY_SHA256,
        "private_key": _private_key(),
    }
    values.update(changes)

    with pytest.raises(TrustedTimeAnchorArtifactGenerationError, match=reason):
        build_trusted_time_anchor_artifact_payloads(**values)  # type: ignore[arg-type]


def test_output_paths_must_be_absolute_distinct_outside_repository(tmp_path: Path) -> None:
    common: dict[str, object] = {
        "anchor_project_url": ANCHOR_URL,
        "anchor_project_ref": ANCHOR_REF,
        "runtime_project_ref": RUNTIME_REF,
        "test_project_ref": TEST_REF,
        "publishable_key": PUBLISHABLE_KEY,
        "writer_principal_id": WRITER_ID,
        "auth_email": AUTH_EMAIL,
        "auth_password": AUTH_PASSWORD,
        "host_id": HOST_ID,
        "source_authority_sha256": SOURCE_AUTHORITY_SHA256,
        "private_key_factory": _private_key,
    }
    with pytest.raises(TrustedTimeAnchorArtifactGenerationError, match="output_path_invalid"):
        generate_trusted_time_anchor_artifacts(
            **common,  # type: ignore[arg-type]
            signing_key_path=Path("relative-key"),
            auth_secret_path=tmp_path / "auth",
            authority_path=tmp_path / "authority",
        )
    with pytest.raises(
        TrustedTimeAnchorArtifactGenerationError,
        match="output_paths_not_distinct",
    ):
        generate_trusted_time_anchor_artifacts(
            **common,  # type: ignore[arg-type]
            signing_key_path=tmp_path / "same",
            auth_secret_path=tmp_path / "same",
            authority_path=tmp_path / "authority",
        )
    with pytest.raises(
        TrustedTimeAnchorArtifactGenerationError,
        match="output_path_inside_repository",
    ):
        generate_trusted_time_anchor_artifacts(
            **common,  # type: ignore[arg-type]
            signing_key_path=REPOSITORY_ROOT / "forbidden-key",
            auth_secret_path=tmp_path / "auth",
            authority_path=tmp_path / "authority",
        )


def test_repository_case_alias_and_exact_root_are_rejected_by_opened_identity(
    tmp_path: Path,
) -> None:
    repository_alias = _case_alias(REPOSITORY_ROOT)
    if repository_alias is None:
        pytest.skip("filesystem has no case-insensitive alias for the repository")
    assert os.path.samefile(repository_alias, REPOSITORY_ROOT)
    canonical_descendant = REPOSITORY_ROOT / f"forbidden-{tmp_path.name}"
    assert not canonical_descendant.exists()

    for signing_key_path in (repository_alias, repository_alias / canonical_descendant.name):
        with pytest.raises(
            TrustedTimeAnchorArtifactGenerationError,
            match="output_path_inside_repository",
        ):
            generate_trusted_time_anchor_artifacts(
                anchor_project_url=ANCHOR_URL,
                anchor_project_ref=ANCHOR_REF,
                runtime_project_ref=RUNTIME_REF,
                test_project_ref=TEST_REF,
                publishable_key=PUBLISHABLE_KEY,
                writer_principal_id=WRITER_ID,
                auth_email=AUTH_EMAIL,
                auth_password=AUTH_PASSWORD,
                host_id=HOST_ID,
                source_authority_sha256=SOURCE_AUTHORITY_SHA256,
                signing_key_path=signing_key_path,
                auth_secret_path=tmp_path / "auth",
                authority_path=tmp_path / "authority",
                private_key_factory=_private_key,
            )

    assert not canonical_descendant.exists()
    assert not (tmp_path / "auth").exists()
    assert not (tmp_path / "authority").exists()


def test_cli_reads_owner_only_password_file_and_prints_only_sanitized_receipt(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password_path = tmp_path / "password"
    password_path.write_text(AUTH_PASSWORD, encoding="ascii")
    password_path.chmod(0o600)
    monkeypatch.setattr(Ed25519PrivateKey, "generate", _private_key)
    key_path = tmp_path / "key"
    auth_path = tmp_path / "auth.json"
    authority_path = tmp_path / "authority.json"

    result = main(
        [
            "--anchor-project-url",
            ANCHOR_URL,
            "--anchor-project-ref",
            ANCHOR_REF,
            "--runtime-project-ref",
            RUNTIME_REF,
            "--test-project-ref",
            TEST_REF,
            "--publishable-key",
            PUBLISHABLE_KEY,
            "--writer-principal-id",
            WRITER_ID,
            "--auth-email",
            AUTH_EMAIL,
            "--auth-password-file",
            str(password_path),
            "--host-id",
            HOST_ID,
            "--source-authority-sha256",
            SOURCE_AUTHORITY_SHA256,
            "--signing-key-path",
            str(key_path),
            "--auth-secret-path",
            str(auth_path),
            "--authority-path",
            str(authority_path),
        ]
    )

    captured = capsys.readouterr()
    assert result == 0
    assert captured.err == ""
    public_receipt = json.loads(captured.out)
    assert public_receipt["allow_enrollment"] is False
    assert public_receipt["enrollment_status"] == "UNRUN"
    assert public_receipt["all_control_authority_flags_false"] is True
    assert public_receipt["external_head_anchor_evidence_only"] is True
    assert AUTH_PASSWORD not in captured.out
    assert PUBLISHABLE_KEY not in captured.out
    assert PRIVATE_KEY_BYTES.hex() not in captured.out
    assert AUTH_EMAIL not in captured.out
    assert key_path.read_bytes() == PRIVATE_KEY_BYTES


def test_cli_error_is_sanitized_and_never_writes_on_invalid_password(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "too-short-secret"
    monkeypatch.setattr("getpass.getpass", lambda _: secret)

    result = main(
        [
            "--anchor-project-url",
            ANCHOR_URL,
            "--anchor-project-ref",
            ANCHOR_REF,
            "--runtime-project-ref",
            RUNTIME_REF,
            "--test-project-ref",
            TEST_REF,
            "--publishable-key",
            PUBLISHABLE_KEY,
            "--writer-principal-id",
            WRITER_ID,
            "--auth-email",
            AUTH_EMAIL,
            "--host-id",
            HOST_ID,
            "--source-authority-sha256",
            SOURCE_AUTHORITY_SHA256,
            "--signing-key-path",
            str(tmp_path / "key"),
            "--auth-secret-path",
            str(tmp_path / "auth"),
            "--authority-path",
            str(tmp_path / "authority"),
        ]
    )

    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert secret not in captured.err
    assert PUBLISHABLE_KEY not in captured.err
    assert not (tmp_path / "key").exists()
    assert not (tmp_path / "auth").exists()
    assert not (tmp_path / "authority").exists()
