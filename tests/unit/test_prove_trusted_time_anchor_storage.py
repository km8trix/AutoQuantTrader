from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest

from apps.trusted_time_supervisor.head_anchor_config import (
    TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_CONTRACT_VERSION,
)
from packages.application.trusted_time_head_anchor import (
    trusted_time_head_anchor_object_prefix,
)
from scripts.prove_trusted_time_anchor_storage import (
    REAL_OTHER_BUCKET_EXISTENCE_EVIDENCE_CONTRACT_VERSION,
    STORAGE_BEHAVIORAL_PROOF_CONTRACT_VERSION,
    STORAGE_BEHAVIORAL_PROOF_ENVIRONMENT_VARIABLES,
    StorageBehavioralProofConfiguration,
    StorageBehavioralProofError,
    _proof_object,
    execute_storage_behavioral_proof,
    load_configuration_from_auth_secret,
    load_configuration_from_env_file,
    main,
)

PROJECT_REF = "abcdefghijklmnopqrst"
PROJECT_URL = f"https://{PROJECT_REF}.supabase.co"
PUBLISHABLE_KEY = f"sb_publishable_{'A' * 22}_{'b' * 8}"
PRINCIPAL_ID = "12345678-1234-4234-9234-123456789abc"
OTHER_PRINCIPAL_ID = "22345678-1234-4234-9234-123456789abc"
EMAIL = "trusted-time-anchor-writer@example.invalid"
PASSWORD = "correct-horse-battery-staple-anchor-proof-1!"
ACCESS_TOKEN = "a" * 128
PROOF_ID = "42345678-1234-4234-9234-123456789abc"
BUCKET = "aqt-trusted-time-anchors-v1"
REAL_OTHER_BUCKET = "aqt-trusted-time-proof-control-v1"
REAL_OTHER_BUCKET_VERIFIED_AT_UTC = "2026-08-02T17:00:00Z"
REAL_OTHER_BUCKET_SOURCE_EVIDENCE_SHA256 = "e" * 64


def _write_other_bucket_evidence(tmp_path: Path, **changes: object) -> Path:
    path = tmp_path / "real-other-bucket-evidence.json"
    path.write_text(
        json.dumps(
            {
                "bucket_id": REAL_OTHER_BUCKET,
                "contract_version": REAL_OTHER_BUCKET_EXISTENCE_EVIDENCE_CONTRACT_VERSION,
                "project_ref": PROJECT_REF,
                "public": False,
                "source_evidence_sha256": REAL_OTHER_BUCKET_SOURCE_EVIDENCE_SHA256,
                "verification_method": "supabase_dashboard",
                "verified_at_utc": REAL_OTHER_BUCKET_VERIFIED_AT_UTC,
                **changes,
            },
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ),
        encoding="ascii",
    )
    path.chmod(0o600)
    return path


def _load_env(
    path: Path,
    *,
    proof_id: str = PROOF_ID,
) -> StorageBehavioralProofConfiguration:
    return load_configuration_from_env_file(
        path,
        proof_id=proof_id,
        real_other_bucket_evidence_file=_write_other_bucket_evidence(path.parent),
    )


def _load_auth(
    path: Path,
    *,
    proof_id: str = PROOF_ID,
) -> StorageBehavioralProofConfiguration:
    return load_configuration_from_auth_secret(
        path,
        proof_id=proof_id,
        real_other_bucket_evidence_file=_write_other_bucket_evidence(path.parent),
    )


def _environment_payload(**changes: str) -> str:
    values = {
        "AQT_TRUSTED_TIME_HEAD_ANCHOR_PROJECT_URL": PROJECT_URL,
        "AQT_TRUSTED_TIME_HEAD_ANCHOR_PUBLISHABLE_KEY": PUBLISHABLE_KEY,
        "AQT_TRUSTED_TIME_HEAD_ANCHOR_WRITER_PRINCIPAL_ID": PRINCIPAL_ID,
        "AQT_TRUSTED_TIME_HEAD_ANCHOR_WRITER_EMAIL": EMAIL,
        "AQT_TRUSTED_TIME_HEAD_ANCHOR_WRITER_PASSWORD": PASSWORD,
        **changes,
    }
    return "".join(f"{name}={value}\n" for name, value in values.items())


def _write_env(tmp_path: Path, **changes: str) -> Path:
    path = tmp_path / "anchor-proof.env"
    path.write_text(_environment_payload(**changes), encoding="utf-8")
    path.chmod(0o600)
    return path


def _write_auth_secret(tmp_path: Path, **changes: str) -> Path:
    path = tmp_path / "anchor-auth.json"
    path.write_text(
        json.dumps(
            {
                "contract_version": TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_CONTRACT_VERSION,
                "email": EMAIL,
                "password": PASSWORD,
                "principal_id": PRINCIPAL_ID,
                "project_url": PROJECT_URL,
                "publishable_key": PUBLISHABLE_KEY,
                **changes,
            },
            separators=(",", ":"),
            sort_keys=True,
        ),
        encoding="ascii",
    )
    path.chmod(0o600)
    return path


@dataclass
class _StorageHarness:
    principal_id: str = PRINCIPAL_ID
    leak_anonymous_list: bool = False
    allow_upsert: bool = False
    timeout_at_upsert: bool = False
    unavailable_at_auth: bool = False
    denial_shape: str = "access_denied"
    noncanonical_denial_shape: str | None = None
    other_bucket_denial_shape: str | None = None
    known_resource_denial_shape: str | None = None
    stored_name: str | None = None
    stored_payload: bytes | None = None
    calls: list[tuple[str, str, bool, str | None]] = field(default_factory=list)

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def _authenticated(self, request: httpx.Request) -> bool:
        authorization = request.headers.get("authorization")
        return type(authorization) is str and authorization == f"Bearer {ACCESS_TOKEN}"

    def _denial(self, shape: str | None = None) -> httpx.Response:
        selected = self.denial_shape if shape is None else shape
        if selected == "access_denied":
            return httpx.Response(
                403,
                headers={"content-type": "application/json"},
                json={"code": "AccessDenied", "message": "Access denied"},
            )
        if selected == "legacy_rls":
            return httpx.Response(
                400,
                headers={"content-type": "application/json"},
                json={
                    "error": "Unauthorized",
                    "message": "new row violates row-level security policy",
                    "statusCode": "403",
                },
            )
        values = {
            "no_such_bucket": (404, "NoSuchBucket", "Bucket does not exist"),
            "no_such_key": (404, "NoSuchKey", "Key does not exist"),
            "method": (405, "MethodNotAllowed", "Method is not allowed"),
            "validation": (400, "InvalidRequest", "Request is malformed"),
            "conflict": (409, "KeyAlreadyExists", "Object exists"),
        }
        status, code, message = values[selected]
        return httpx.Response(
            status,
            headers={"content-type": "application/json"},
            json={"code": code, "message": message},
        )

    def handle(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/v1/token":
            assert request.method == "POST"
            assert request.url.params["grant_type"] == "password"
            assert request.headers["apikey"] == PUBLISHABLE_KEY
            assert json.loads(request.content) == {"email": EMAIL, "password": PASSWORD}
            if self.unavailable_at_auth:
                return httpx.Response(
                    503,
                    headers={"content-type": "application/json"},
                    content=(f'{{"secret":"{PASSWORD}"}}').encode(),
                )
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json={
                    "access_token": ACCESS_TOKEN,
                    "expires_in": 3600,
                    "token_type": "bearer",
                    "user": {"id": self.principal_id},
                },
            )
        if request.url.path == "/auth/v1/user":
            assert self._authenticated(request)
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json={"id": self.principal_id},
            )

        authenticated = self._authenticated(request)
        self.calls.append(
            (
                request.method,
                request.url.path,
                authenticated,
                request.headers.get("x-upsert"),
            )
        )
        list_path = f"/storage/v1/object/list/{BUCKET}"
        object_path_prefix = f"/storage/v1/object/{BUCKET}/"
        authenticated_path_prefix = f"/storage/v1/object/authenticated/{BUCKET}/"
        delete_path = f"/storage/v1/object/{BUCKET}"

        if request.url.path == list_path:
            body = json.loads(request.content)
            assert body["limit"] == 2
            assert body["offset"] == 0
            if authenticated:
                assert self.stored_name is not None
                assert body["prefix"] == self.stored_name.rsplit("/", 1)[0] + "/"
                return httpx.Response(
                    200,
                    headers={"content-type": "application/json"},
                    json=[{"name": self.stored_name.rsplit("/", 1)[1]}],
                )
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json=(
                    [{"name": self.stored_name.rsplit("/", 1)[1]}]
                    if self.leak_anonymous_list and self.stored_name is not None
                    else []
                ),
            )

        if request.url.path.startswith(authenticated_path_prefix):
            assert self.stored_name is not None
            if not authenticated:
                return self._denial(self.known_resource_denial_shape)
            assert request.url.path == authenticated_path_prefix + self.stored_name
            assert self.stored_payload is not None
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                content=self.stored_payload,
            )

        if request.url.path.startswith(f"/storage/v1/object/public/{BUCKET}/"):
            assert not authenticated
            return self._denial(self.known_resource_denial_shape)

        if request.url.path == delete_path:
            assert request.method == "DELETE"
            assert authenticated
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json=[],
            )

        if request.url.path.startswith(object_path_prefix):
            object_name = request.url.path.removeprefix(object_path_prefix)
            if request.method == "DELETE":
                assert authenticated
                assert request.content == b""
                assert object_name == self.stored_name
                return self._denial()
            assert request.headers["content-type"] == "application/json"
            if not authenticated:
                return self._denial()
            if request.method == "PUT":
                return self._denial()
            assert request.method == "POST"
            if object_name.startswith("proof/"):
                return self._denial(self.noncanonical_denial_shape)
            if self.stored_name is None:
                assert request.headers["x-upsert"] == "false"
                self.stored_name = object_name
                self.stored_payload = request.content
                return httpx.Response(
                    201,
                    headers={"content-type": "application/json"},
                    json={"Key": object_name},
                )
            assert object_name == self.stored_name
            if request.headers["x-upsert"] == "true":
                if self.timeout_at_upsert:
                    raise httpx.ReadTimeout("provider detail must be sanitized")
                if self.allow_upsert:
                    self.stored_payload = request.content
                    return httpx.Response(
                        200,
                        headers={"content-type": "application/json"},
                        json={"Key": object_name},
                    )
                return self._denial()
            return httpx.Response(
                409,
                headers={"content-type": "application/json"},
                json={"code": "KeyAlreadyExists", "message": "exists"},
            )

        if request.url.path.startswith(f"/storage/v1/object/{REAL_OTHER_BUCKET}/"):
            assert authenticated
            return self._denial(self.other_bucket_denial_shape)
        raise AssertionError(f"unexpected proof request: {request.method} {request.url.path}")


def test_complete_proof_is_deterministic_secret_free_and_retains_exact_object(
    tmp_path: Path,
) -> None:
    configuration = _load_env(_write_env(tmp_path))
    first_harness = _StorageHarness()
    first = execute_storage_behavioral_proof(
        configuration,
        transport=first_harness.transport,
    )
    second = execute_storage_behavioral_proof(
        configuration,
        transport=_StorageHarness(denial_shape="legacy_rls").transport,
    )

    assert first.canonical_json == second.canonical_json
    payload = json.loads(first.canonical_json)
    assert payload["contract_version"] == STORAGE_BEHAVIORAL_PROOF_CONTRACT_VERSION
    assert payload["status"] == "passed"
    assert payload["allow_enrollment"] is False
    assert payload["enrollment"] == "UNRUN"
    assert payload["anchor_project_ref"] == PROJECT_REF
    assert payload["principal_id"] == PRINCIPAL_ID
    assert payload["proof_id"] == PROOF_ID
    assert payload["real_other_bucket_id"] == REAL_OTHER_BUCKET
    assert payload["real_other_bucket_existence_evidence_sha256"] == (
        hashlib.sha256((tmp_path / "real-other-bucket-evidence.json").read_bytes()).hexdigest()
    )
    assert payload["real_other_bucket_existence_basis"] == (
        "retained_independent_evidence_plus_access_denied_response"
    )
    assert payload["real_other_bucket_verification_method"] == "supabase_dashboard"
    assert payload["real_other_bucket_verified_at_utc"] == REAL_OTHER_BUCKET_VERIFIED_AT_UTC
    assert payload["real_other_bucket_source_evidence_sha256"] == (
        REAL_OTHER_BUCKET_SOURCE_EVIDENCE_SHA256
    )
    assert payload["object_name"] == first_harness.stored_name
    assert first_harness.stored_payload is not None
    assert (
        payload["object_payload_sha256"] == hashlib.sha256(first_harness.stored_payload).hexdigest()
    )
    assert [operation["name"] for operation in payload["operations"]] == [
        "authenticated_principal_uuid",
        "canonical_insert_x_upsert_false",
        "authenticated_canonical_list",
        "authenticated_canonical_read",
        "overwrite_x_upsert_false",
        "upsert_x_upsert_true",
        "update",
        "delete",
        "noncanonical_namespace_insert",
        "real_other_bucket_insert",
        "anonymous_canonical_insert",
        "anonymous_list",
        "anonymous_read",
        "public_read",
        "canonical_object_retained_unchanged",
        "canonical_namespace_retained_unchanged",
    ]
    rendered = first.canonical_json + repr(configuration)
    for secret in (EMAIL, PASSWORD, PUBLISHABLE_KEY, ACCESS_TOKEN):
        assert secret not in rendered
    assert first_harness.stored_name is not None
    assert first_harness.stored_name.startswith("v1/")
    assert first_harness.stored_name.endswith(".json")
    assert any(
        method == "POST" and upsert == "false" for method, _, _, upsert in first_harness.calls
    )
    delete_calls = [call for call in first_harness.calls if call[0] == "DELETE"]
    assert len(delete_calls) == 1
    assert delete_calls[0][1] != f"/storage/v1/object/{BUCKET}"
    assert delete_calls[0][1] == f"/storage/v1/object/{BUCKET}/{first_harness.stored_name}"
    assert first_harness.calls[-1][0] == "POST"


def test_runtime_auth_secret_loader_is_strict_owner_only_and_redacted(tmp_path: Path) -> None:
    path = _write_auth_secret(tmp_path)
    configuration = _load_auth(path)

    assert configuration.credentials.project_ref == PROJECT_REF
    assert configuration.credentials.principal_id == PRINCIPAL_ID
    assert PASSWORD not in repr(configuration)
    assert PUBLISHABLE_KEY not in repr(configuration)

    path.chmod(0o644)
    with pytest.raises(StorageBehavioralProofError, match="proof_credential_file_invalid"):
        _load_auth(path)

    path.chmod(0o600)
    hard_link = tmp_path / "hard-link.json"
    os.link(path, hard_link)
    with pytest.raises(StorageBehavioralProofError, match="proof_credential_file_invalid"):
        _load_auth(path)


def test_credential_sources_reject_missing_duplicate_and_unsafe_identity(tmp_path: Path) -> None:
    missing = tmp_path / "missing.env"
    missing.write_text(
        _environment_payload().replace(
            f"{STORAGE_BEHAVIORAL_PROOF_ENVIRONMENT_VARIABLES[-1]}={PASSWORD}\n",
            "",
        ),
        encoding="utf-8",
    )
    missing.chmod(0o600)
    with pytest.raises(StorageBehavioralProofError, match="proof_credentials_missing"):
        _load_env(missing)

    duplicate = _write_env(tmp_path)
    with duplicate.open("a", encoding="utf-8") as stream:
        stream.write(f"{STORAGE_BEHAVIORAL_PROOF_ENVIRONMENT_VARIABLES[0]}={PROJECT_URL}\n")
    with pytest.raises(StorageBehavioralProofError, match="proof_credential_file_invalid"):
        _load_env(duplicate)

    unsafe = _write_auth_secret(tmp_path, publishable_key="sb_secret_elevated")
    with pytest.raises(StorageBehavioralProofError, match="proof_credentials_invalid"):
        _load_auth(unsafe)

    with pytest.raises(StorageBehavioralProofError, match="proof_id_invalid"):
        _load_auth(unsafe, proof_id="not-a-uuid")


def test_principal_mismatch_fails_before_any_storage_request(tmp_path: Path) -> None:
    configuration = _load_env(_write_env(tmp_path))
    harness = _StorageHarness(principal_id=OTHER_PRINCIPAL_ID)

    with pytest.raises(
        StorageBehavioralProofError,
        match="proof_principal_identity_conflict",
    ):
        execute_storage_behavioral_proof(configuration, transport=harness.transport)

    assert harness.calls == []


def test_any_allowed_mutation_or_anonymous_disclosure_fails_closed(tmp_path: Path) -> None:
    configuration = _load_env(_write_env(tmp_path))
    upsert = _StorageHarness(allow_upsert=True)
    with pytest.raises(StorageBehavioralProofError, match="proof_upsert_not_denied") as captured:
        execute_storage_behavioral_proof(configuration, transport=upsert.transport)
    assert PASSWORD not in str(captured.value)
    assert captured.value.failure_context is not None
    assert captured.value.failure_context.external_state_outcome == "UNKNOWN_REVIEW_REQUIRED"
    assert captured.value.failure_context.failed_operation == "upsert_x_upsert_true"
    assert ("canonical_insert_x_upsert_false", "allowed") in (
        captured.value.failure_context.completed_operations
    )
    assert not any(method == "DELETE" for method, _, _, _ in upsert.calls)

    timeout = _StorageHarness(timeout_at_upsert=True)
    with pytest.raises(StorageBehavioralProofError, match="proof_request_timed_out") as timed:
        execute_storage_behavioral_proof(configuration, transport=timeout.transport)
    assert timed.value.failure_context is not None
    assert timed.value.failure_context.external_state_outcome == "UNKNOWN_REVIEW_REQUIRED"
    assert timed.value.failure_context.failed_operation == "upsert_x_upsert_true"

    anonymous = _StorageHarness(leak_anonymous_list=True)
    with pytest.raises(StorageBehavioralProofError, match="proof_anonymous_list_exposed"):
        execute_storage_behavioral_proof(configuration, transport=anonymous.transport)


@pytest.mark.parametrize(
    "shape",
    ["no_such_bucket", "no_such_key", "method", "validation", "conflict"],
)
def test_mutation_denials_reject_non_authorization_error_semantics(
    tmp_path: Path,
    shape: str,
) -> None:
    configuration = _load_env(_write_env(tmp_path))
    harness = _StorageHarness(noncanonical_denial_shape=shape)

    with pytest.raises(
        StorageBehavioralProofError,
        match="proof_noncanonical_namespace_not_denied",
    ):
        execute_storage_behavioral_proof(configuration, transport=harness.transport)


def test_real_other_bucket_rejects_no_such_bucket_but_known_key_may_be_hidden(
    tmp_path: Path,
) -> None:
    configuration = _load_env(_write_env(tmp_path))
    missing = _StorageHarness(other_bucket_denial_shape="no_such_bucket")
    with pytest.raises(
        StorageBehavioralProofError,
        match="proof_real_other_bucket_not_denied",
    ):
        execute_storage_behavioral_proof(configuration, transport=missing.transport)

    hidden = execute_storage_behavioral_proof(
        configuration,
        transport=_StorageHarness(known_resource_denial_shape="no_such_key").transport,
    )
    assert hidden.public_payload["status"] == "passed"


def test_delete_probe_uses_single_object_not_ambiguous_bulk_delete(tmp_path: Path) -> None:
    configuration = _load_env(_write_env(tmp_path))
    harness = _StorageHarness()

    evidence = execute_storage_behavioral_proof(configuration, transport=harness.transport)

    delete_calls = [call for call in harness.calls if call[0] == "DELETE"]
    assert evidence.public_payload["status"] == "passed"
    assert delete_calls == [
        (
            "DELETE",
            f"/storage/v1/object/{BUCKET}/{harness.stored_name}",
            True,
            None,
        )
    ]
    assert all(path != f"/storage/v1/object/{BUCKET}" for _, path, _, _ in harness.calls)


def test_real_other_bucket_evidence_is_closed_canonical_and_project_bound(
    tmp_path: Path,
) -> None:
    auth = _write_auth_secret(tmp_path)
    for changes in (
        {"project_ref": "bcdefghijklmnopqrstu"},
        {"public": True},
        {"source_evidence_sha256": "not-a-digest"},
        {"verification_method": "caller_assertion"},
        {"bucket_id": BUCKET},
    ):
        evidence = _write_other_bucket_evidence(tmp_path, **changes)
        with pytest.raises(
            StorageBehavioralProofError,
            match=r"proof_other_bucket_existence_evidence_invalid|proof_other_bucket_id_invalid",
        ):
            load_configuration_from_auth_secret(
                auth,
                proof_id=PROOF_ID,
                real_other_bucket_evidence_file=evidence,
            )


def test_synthetic_proof_prefix_is_domain_separated_from_runtime_audit_prefix(
    tmp_path: Path,
) -> None:
    configuration = _load_env(_write_env(tmp_path))
    object_name, _, _ = _proof_object(configuration)
    proof_prefix = object_name.rsplit("/", 1)[0] + "/"
    runtime_prefix = trusted_time_head_anchor_object_prefix(
        deployment_identity_sha256="f" * 64,
        host_id="local-paper-docker-primary-v1",
    )

    assert proof_prefix != runtime_prefix
    assert not object_name.startswith(runtime_prefix)
    assert proof_prefix.split("/")[1:] != runtime_prefix.split("/")[1:]


def test_cli_emits_only_sanitized_pass_or_failure_evidence(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = _write_env(tmp_path)
    other_bucket_evidence = _write_other_bucket_evidence(tmp_path)
    success = main(
        [
            "--env-file",
            str(path),
            "--proof-id",
            PROOF_ID,
            "--real-other-bucket-evidence-file",
            str(other_bucket_evidence),
        ],
        transport=_StorageHarness().transport,
    )
    success_output = capsys.readouterr().out
    assert success == 0
    assert json.loads(success_output)["status"] == "passed"

    failure = main(
        [
            "--env-file",
            str(path),
            "--proof-id",
            PROOF_ID,
            "--real-other-bucket-evidence-file",
            str(other_bucket_evidence),
        ],
        transport=_StorageHarness(unavailable_at_auth=True).transport,
    )
    failure_output = capsys.readouterr().out
    assert failure == 2
    failure_payload = json.loads(failure_output)
    assert failure_payload["allow_enrollment"] is False
    assert failure_payload["contract_version"] == STORAGE_BEHAVIORAL_PROOF_CONTRACT_VERSION
    assert failure_payload["enrollment"] == "UNRUN"
    assert failure_payload["reason"] == "proof_provider_unavailable"
    assert failure_payload["status"] == "failed"
    assert failure_payload["external_state_outcome"] == "NO_STORAGE_MUTATION_ATTEMPTED"
    assert failure_payload["failed_operation"] == "authenticated_principal_uuid"
    assert failure_payload["completed_operations"] == []
    assert failure_payload["proof_id"] == PROOF_ID

    mutation_failure = main(
        [
            "--env-file",
            str(path),
            "--proof-id",
            PROOF_ID,
            "--real-other-bucket-evidence-file",
            str(other_bucket_evidence),
        ],
        transport=_StorageHarness(allow_upsert=True).transport,
    )
    mutation_output = capsys.readouterr().out
    assert mutation_failure == 2
    mutation_payload = json.loads(mutation_output)
    assert mutation_payload["external_state_outcome"] == "UNKNOWN_REVIEW_REQUIRED"
    assert mutation_payload["failed_operation"] == "upsert_x_upsert_true"
    assert mutation_payload["object_name"].startswith("v1/")
    assert len(mutation_payload["object_payload_sha256"]) == 64
    assert mutation_payload["completed_operations"][-1] == {
        "name": "overwrite_x_upsert_false",
        "result": "denied",
    }
    for output in (success_output, failure_output, mutation_output):
        for secret in (EMAIL, PASSWORD, PUBLISHABLE_KEY, ACCESS_TOKEN):
            assert secret not in output
