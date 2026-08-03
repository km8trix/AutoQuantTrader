"""Prove the separate Supabase trusted-time anchor Storage policy behavior.

The operator consumes writer credentials only from an owner-only dotenv or the
runtime-compatible owner-only Auth-secret JSON.  Secret values, access tokens,
and provider response bodies never enter its evidence or error output.

One canonical proof object is intentionally retained.  The operator has no
cleanup mode: overwrite, upsert, update, and delete are attempted only to prove
that the reviewed policy denies them.  Enrollment is never performed or
authorized by this command.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote
from uuid import UUID

import httpx

from apps.trusted_time_supervisor.head_anchor_config import (
    MAXIMUM_HEAD_ANCHOR_AUTH_SECRET_BYTES,
    TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_CONTRACT_VERSION,
    trusted_time_head_anchor_project_identity_sha256,
)
from packages.adapters.trusted_time.supabase_storage_anchor import (
    SupabaseStorageAnchorCredentials,
)
from packages.application.trusted_time_head_anchor import (
    TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
    TRUSTED_TIME_HEAD_ANCHOR_CONTENT_TYPE,
)
from scripts.credential_env import load_owner_only_environment
from scripts.provision_trusted_time_anchor_project import (
    AnchorProjectProvisioningError,
    validate_principal_uuid,
    validate_project_url,
    validate_publishable_key,
)

STORAGE_BEHAVIORAL_PROOF_CONTRACT_VERSION = "phase6-supabase-storage-anchor-behavioral-proof-v1"
STORAGE_BEHAVIORAL_PROOF_OBJECT_CONTRACT_VERSION = (
    "phase6-supabase-storage-anchor-behavioral-proof-object-v1"
)
REAL_OTHER_BUCKET_EXISTENCE_EVIDENCE_CONTRACT_VERSION = (
    "phase6-supabase-real-other-bucket-existence-evidence-v1"
)
STORAGE_BEHAVIORAL_PROOF_SEQUENCE = 1
STORAGE_BEHAVIORAL_PROOF_TIMEOUT_SECONDS = 5.0
STORAGE_BEHAVIORAL_PROOF_MAXIMUM_RESPONSE_BYTES = 32_768
STORAGE_BEHAVIORAL_PROOF_MAXIMUM_OBJECT_BYTES = 4_096
STORAGE_BEHAVIORAL_PROOF_ENVIRONMENT_VARIABLES = (
    "AQT_TRUSTED_TIME_HEAD_ANCHOR_PROJECT_URL",
    "AQT_TRUSTED_TIME_HEAD_ANCHOR_PUBLISHABLE_KEY",
    "AQT_TRUSTED_TIME_HEAD_ANCHOR_WRITER_PRINCIPAL_ID",
    "AQT_TRUSTED_TIME_HEAD_ANCHOR_WRITER_EMAIL",
    "AQT_TRUSTED_TIME_HEAD_ANCHOR_WRITER_PASSWORD",
)
_BUCKET_ID = re.compile(r"[a-z0-9][a-z0-9-]{2,62}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_UTC_SECONDS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_REAL_OTHER_BUCKET_EVIDENCE_KEYS = frozenset(
    {
        "bucket_id",
        "contract_version",
        "project_ref",
        "public",
        "source_evidence_sha256",
        "verification_method",
        "verified_at_utc",
    }
)
_REAL_OTHER_BUCKET_VERIFICATION_METHODS = frozenset(
    {"supabase_dashboard", "supabase_management_api"}
)

_AUTH_SECRET_KEYS = frozenset(
    {
        "contract_version",
        "email",
        "password",
        "principal_id",
        "project_url",
        "publishable_key",
    }
)


class StorageBehavioralProofError(RuntimeError):
    """One sanitized, stable proof failure reason."""

    def __init__(
        self,
        reason_code: str,
        *,
        failure_context: StorageBehavioralProofFailureContext | None = None,
    ) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.failure_context = failure_context

    def with_context(
        self,
        context: StorageBehavioralProofFailureContext,
    ) -> StorageBehavioralProofError:
        return StorageBehavioralProofError(self.reason_code, failure_context=context)


class _DuplicateJsonKey(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class StorageBehavioralProofFailureContext:
    proof_id: str
    object_name: str
    object_payload_sha256: str
    completed_operations: tuple[tuple[str, str], ...]
    failed_operation: str
    external_state_outcome: str

    @property
    def public_payload(self) -> dict[str, object]:
        return {
            "completed_operations": [
                {"name": name, "result": result} for name, result in self.completed_operations
            ],
            "external_state_outcome": self.external_state_outcome,
            "failed_operation": self.failed_operation,
            "object_name": self.object_name,
            "object_payload_sha256": self.object_payload_sha256,
            "proof_id": self.proof_id,
        }


@dataclass(frozen=True, slots=True)
class StorageBehavioralProofConfiguration:
    """Validated proof configuration with secret fields excluded from repr."""

    credentials: SupabaseStorageAnchorCredentials = field(repr=False)
    proof_id: str
    real_other_bucket_id: str
    real_other_bucket_existence_evidence_sha256: str
    real_other_bucket_source_evidence_sha256: str
    real_other_bucket_verification_method: str
    real_other_bucket_verified_at_utc: str

    def __post_init__(self) -> None:
        if type(self.credentials) is not SupabaseStorageAnchorCredentials:
            raise StorageBehavioralProofError("proof_credentials_invalid")
        try:
            self.credentials.__post_init__()
        except Exception:
            raise StorageBehavioralProofError("proof_credentials_invalid") from None
        _canonical_proof_id(self.proof_id)
        _validated_real_other_bucket_id(self.real_other_bucket_id)
        if (
            type(self.real_other_bucket_existence_evidence_sha256) is not str
            or _SHA256.fullmatch(self.real_other_bucket_existence_evidence_sha256) is None
            or type(self.real_other_bucket_source_evidence_sha256) is not str
            or _SHA256.fullmatch(self.real_other_bucket_source_evidence_sha256) is None
        ):
            raise StorageBehavioralProofError("proof_other_bucket_existence_evidence_invalid")
        _validate_real_other_bucket_verification(
            self.real_other_bucket_verification_method,
            self.real_other_bucket_verified_at_utc,
        )

    def __repr__(self) -> str:
        return (
            "StorageBehavioralProofConfiguration(credentials=<redacted>, "
            f"proof_id={self.proof_id!r}, "
            f"real_other_bucket_id={self.real_other_bucket_id!r}, "
            "real_other_bucket_existence_evidence_sha256="
            f"{self.real_other_bucket_existence_evidence_sha256!r}, "
            "real_other_bucket_source_evidence_sha256="
            f"{self.real_other_bucket_source_evidence_sha256!r}, "
            f"real_other_bucket_verification_method="
            f"{self.real_other_bucket_verification_method!r}, "
            f"real_other_bucket_verified_at_utc="
            f"{self.real_other_bucket_verified_at_utc!r})"
        )


@dataclass(frozen=True, slots=True)
class StorageBehavioralProofEvidence:
    """Deterministic, sanitized evidence for one completed proof object."""

    anchor_project_ref: str
    principal_id: str
    proof_id: str
    real_other_bucket_id: str
    real_other_bucket_existence_evidence_sha256: str
    real_other_bucket_source_evidence_sha256: str
    real_other_bucket_verification_method: str
    real_other_bucket_verified_at_utc: str
    object_name: str
    object_payload_sha256: str
    operations: tuple[tuple[str, str], ...]

    @property
    def evidence_payload(self) -> dict[str, object]:
        return {
            "allow_enrollment": False,
            "anchor_project_ref": self.anchor_project_ref,
            "bucket_id": TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
            "contract_version": STORAGE_BEHAVIORAL_PROOF_CONTRACT_VERSION,
            "enrollment": "UNRUN",
            "object_name": self.object_name,
            "object_payload_sha256": self.object_payload_sha256,
            "operations": [{"name": name, "result": result} for name, result in self.operations],
            "principal_id": self.principal_id,
            "proof_id": self.proof_id,
            "real_other_bucket_existence_basis": (
                "retained_independent_evidence_plus_access_denied_response"
            ),
            "real_other_bucket_existence_evidence_sha256": (
                self.real_other_bucket_existence_evidence_sha256
            ),
            "real_other_bucket_id": self.real_other_bucket_id,
            "real_other_bucket_source_evidence_sha256": (
                self.real_other_bucket_source_evidence_sha256
            ),
            "real_other_bucket_verification_method": (self.real_other_bucket_verification_method),
            "real_other_bucket_verified_at_utc": self.real_other_bucket_verified_at_utc,
            "status": "passed",
        }

    @property
    def public_payload(self) -> dict[str, object]:
        payload = self.evidence_payload
        return {
            **payload,
            "evidence_sha256": hashlib.sha256(_canonical_json_bytes(payload)).hexdigest(),
        }

    @property
    def canonical_json(self) -> str:
        return _canonical_json_bytes(self.public_payload).decode("ascii")


@dataclass(frozen=True, slots=True)
class _Response:
    status_code: int
    media_type: str | None
    body: bytes = field(repr=False)


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError):
        raise StorageBehavioralProofError("proof_serialization_failed") from None


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _decode_json(payload: bytes, *, reason_code: str) -> object:
    try:
        return json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        RecursionError,
        TypeError,
        ValueError,
    ):
        raise StorageBehavioralProofError(reason_code) from None


def _canonical_proof_id(value: object) -> str:
    if type(value) is not str:
        raise StorageBehavioralProofError("proof_id_invalid")
    try:
        parsed = UUID(value)
    except (AttributeError, ValueError):
        raise StorageBehavioralProofError("proof_id_invalid") from None
    if parsed.int == 0 or str(parsed) != value:
        raise StorageBehavioralProofError("proof_id_invalid")
    return value


def _validated_real_other_bucket_id(value: object) -> str:
    if (
        type(value) is not str
        or _BUCKET_ID.fullmatch(value) is None
        or value == TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME
    ):
        raise StorageBehavioralProofError("proof_other_bucket_id_invalid")
    return value


def _validate_real_other_bucket_verification(
    method: object,
    verified_at_utc: object,
) -> tuple[str, str]:
    if method not in _REAL_OTHER_BUCKET_VERIFICATION_METHODS:
        raise StorageBehavioralProofError("proof_other_bucket_existence_evidence_invalid")
    if type(verified_at_utc) is not str or _UTC_SECONDS.fullmatch(verified_at_utc) is None:
        raise StorageBehavioralProofError("proof_other_bucket_existence_evidence_invalid")
    try:
        parsed = datetime.strptime(verified_at_utc, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise StorageBehavioralProofError("proof_other_bucket_existence_evidence_invalid") from None
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != verified_at_utc:
        raise StorageBehavioralProofError("proof_other_bucket_existence_evidence_invalid")
    assert type(method) is str
    return method, verified_at_utc


@dataclass(frozen=True, slots=True)
class _RealOtherBucketEvidence:
    bucket_id: str
    artifact_sha256: str
    source_evidence_sha256: str
    verification_method: str
    verified_at_utc: str


def _reject_symlinked_parent_components(path: Path) -> None:
    cursor = Path(path.anchor)
    for component in path.parts[1:-1]:
        cursor /= component
        try:
            if cursor.is_symlink():
                raise StorageBehavioralProofError("proof_credential_file_invalid")
        except OSError:
            raise StorageBehavioralProofError("proof_credential_file_invalid") from None


def _read_owner_only_file(path: Path, *, maximum_bytes: int) -> bytes:
    if not isinstance(path, Path) or not path.is_absolute():
        raise StorageBehavioralProofError("proof_credential_file_invalid")
    _reject_symlinked_parent_components(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise StorageBehavioralProofError("proof_credential_file_invalid") from None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) not in {0o400, 0o600}
            or before.st_nlink != 1
            or not 1 <= before.st_size <= maximum_bytes
        ):
            raise StorageBehavioralProofError("proof_credential_file_invalid")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(payload) != before.st_size
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            raise StorageBehavioralProofError("proof_credential_file_invalid")
        return payload
    finally:
        os.close(descriptor)


def _load_real_other_bucket_evidence(
    path: Path,
    *,
    expected_project_ref: str,
) -> _RealOtherBucketEvidence:
    payload = _read_owner_only_file(path, maximum_bytes=4_096)
    decoded = _decode_json(
        payload,
        reason_code="proof_other_bucket_existence_evidence_invalid",
    )
    if (
        type(decoded) is not dict
        or set(decoded) != _REAL_OTHER_BUCKET_EVIDENCE_KEYS
        or decoded.get("contract_version") != REAL_OTHER_BUCKET_EXISTENCE_EVIDENCE_CONTRACT_VERSION
        or decoded.get("project_ref") != expected_project_ref
        or decoded.get("public") is not False
        or _canonical_json_bytes(decoded) != payload
    ):
        raise StorageBehavioralProofError("proof_other_bucket_existence_evidence_invalid")
    bucket_id = _validated_real_other_bucket_id(decoded.get("bucket_id"))
    source_evidence_sha256 = decoded.get("source_evidence_sha256")
    if type(source_evidence_sha256) is not str or _SHA256.fullmatch(source_evidence_sha256) is None:
        raise StorageBehavioralProofError("proof_other_bucket_existence_evidence_invalid")
    method, verified_at_utc = _validate_real_other_bucket_verification(
        decoded.get("verification_method"),
        decoded.get("verified_at_utc"),
    )
    return _RealOtherBucketEvidence(
        bucket_id=bucket_id,
        artifact_sha256=hashlib.sha256(payload).hexdigest(),
        source_evidence_sha256=source_evidence_sha256,
        verification_method=method,
        verified_at_utc=verified_at_utc,
    )


def _credentials_from_values(values: Mapping[str, object]) -> SupabaseStorageAnchorCredentials:
    try:
        project_url_value = values["project_url"]
        publishable_key_value = values["publishable_key"]
        principal_id_value = values["principal_id"]
        email_value = values["email"]
        password_value = values["password"]
        if (
            type(project_url_value) is not str
            or type(email_value) is not str
            or type(password_value) is not str
        ):
            raise StorageBehavioralProofError("proof_credentials_invalid")
        host = httpx.URL(project_url_value).host
        if not host.endswith(".supabase.co"):
            raise StorageBehavioralProofError("proof_credentials_invalid")
        project_ref = host.removesuffix(".supabase.co")
        project_url = validate_project_url(project_url_value, project_ref=project_ref)
        publishable_key = validate_publishable_key(publishable_key_value)
        principal_id = validate_principal_uuid(
            principal_id_value,
            field_name="writer_principal_id",
        )
        credentials = SupabaseStorageAnchorCredentials(
            project_url=project_url,
            publishable_key=publishable_key,
            principal_id=principal_id,
            anchor_project_identity_sha256=(
                trusted_time_head_anchor_project_identity_sha256(
                    role="external_anchor",
                    project_ref=project_ref,
                )
            ),
            email=email_value,
            password=password_value,
        )
    except (
        AnchorProjectProvisioningError,
        KeyError,
        StorageBehavioralProofError,
        TypeError,
        ValueError,
    ):
        raise StorageBehavioralProofError("proof_credentials_invalid") from None
    except Exception:
        raise StorageBehavioralProofError("proof_credentials_invalid") from None
    return credentials


def load_configuration_from_env_file(
    path: Path,
    *,
    proof_id: str,
    real_other_bucket_evidence_file: Path,
) -> StorageBehavioralProofConfiguration:
    """Load exactly the five proof credentials from an owner-only dotenv."""

    exact_proof_id = _canonical_proof_id(proof_id)
    if not isinstance(path, Path) or not path.is_absolute():
        raise StorageBehavioralProofError("proof_credential_file_invalid")
    try:
        environment = load_owner_only_environment(
            path,
            variables=STORAGE_BEHAVIORAL_PROOF_ENVIRONMENT_VARIABLES,
            maximum_bytes=16_384,
            reject_duplicate_variables=True,
            reject_symlinked_parents=True,
            require_current_user_owner=True,
        )
    except (OSError, ValueError):
        raise StorageBehavioralProofError("proof_credential_file_invalid") from None
    if set(environment) != set(STORAGE_BEHAVIORAL_PROOF_ENVIRONMENT_VARIABLES):
        raise StorageBehavioralProofError("proof_credentials_missing")
    credentials = _credentials_from_values(
        {
            "email": environment["AQT_TRUSTED_TIME_HEAD_ANCHOR_WRITER_EMAIL"],
            "password": environment["AQT_TRUSTED_TIME_HEAD_ANCHOR_WRITER_PASSWORD"],
            "principal_id": environment["AQT_TRUSTED_TIME_HEAD_ANCHOR_WRITER_PRINCIPAL_ID"],
            "project_url": environment["AQT_TRUSTED_TIME_HEAD_ANCHOR_PROJECT_URL"],
            "publishable_key": environment["AQT_TRUSTED_TIME_HEAD_ANCHOR_PUBLISHABLE_KEY"],
        }
    )
    other_bucket = _load_real_other_bucket_evidence(
        real_other_bucket_evidence_file,
        expected_project_ref=credentials.project_ref,
    )
    return StorageBehavioralProofConfiguration(
        credentials=credentials,
        proof_id=exact_proof_id,
        real_other_bucket_id=other_bucket.bucket_id,
        real_other_bucket_existence_evidence_sha256=other_bucket.artifact_sha256,
        real_other_bucket_source_evidence_sha256=other_bucket.source_evidence_sha256,
        real_other_bucket_verification_method=other_bucket.verification_method,
        real_other_bucket_verified_at_utc=other_bucket.verified_at_utc,
    )


def load_configuration_from_auth_secret(
    path: Path,
    *,
    proof_id: str,
    real_other_bucket_evidence_file: Path,
) -> StorageBehavioralProofConfiguration:
    """Load the exact runtime-compatible writer Auth-secret contract."""

    exact_proof_id = _canonical_proof_id(proof_id)
    payload = _read_owner_only_file(
        path,
        maximum_bytes=MAXIMUM_HEAD_ANCHOR_AUTH_SECRET_BYTES,
    )
    decoded = _decode_json(payload, reason_code="proof_credentials_invalid")
    if (
        type(decoded) is not dict
        or set(decoded) != _AUTH_SECRET_KEYS
        or decoded.get("contract_version") != TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_CONTRACT_VERSION
    ):
        raise StorageBehavioralProofError("proof_credentials_invalid")
    credentials = _credentials_from_values(decoded)
    other_bucket = _load_real_other_bucket_evidence(
        real_other_bucket_evidence_file,
        expected_project_ref=credentials.project_ref,
    )
    return StorageBehavioralProofConfiguration(
        credentials=credentials,
        proof_id=exact_proof_id,
        real_other_bucket_id=other_bucket.bucket_id,
        real_other_bucket_existence_evidence_sha256=other_bucket.artifact_sha256,
        real_other_bucket_source_evidence_sha256=other_bucket.source_evidence_sha256,
        real_other_bucket_verification_method=other_bucket.verification_method,
        real_other_bucket_verified_at_utc=other_bucket.verified_at_utc,
    )


class _StorageProofClient:
    """Exact-target HTTP client that never exposes provider response bodies."""

    __slots__ = ("_access_token", "_credentials", "_timeout_seconds", "_transport")

    def __init__(
        self,
        credentials: SupabaseStorageAnchorCredentials,
        *,
        timeout_seconds: float = STORAGE_BEHAVIORAL_PROOF_TIMEOUT_SECONDS,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if type(credentials) is not SupabaseStorageAnchorCredentials:
            raise StorageBehavioralProofError("proof_credentials_invalid")
        if (
            type(timeout_seconds) not in {int, float}
            or isinstance(timeout_seconds, bool)
            or not 0 < float(timeout_seconds) <= STORAGE_BEHAVIORAL_PROOF_TIMEOUT_SECONDS
        ):
            raise StorageBehavioralProofError("proof_http_bounds_invalid")
        self._credentials = credentials
        self._timeout_seconds = float(timeout_seconds)
        self._transport = transport
        self._access_token: str | None = None

    def __repr__(self) -> str:
        return "_StorageProofClient(credentials=<redacted>, access_token=<redacted>)"

    def close(self) -> None:
        self._access_token = None

    def _request(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None = None,
        maximum_response_bytes: int = STORAGE_BEHAVIORAL_PROOF_MAXIMUM_RESPONSE_BYTES,
    ) -> _Response:
        url = f"{self._credentials.project_url}{path}"
        timeout = httpx.Timeout(
            connect=self._timeout_seconds,
            read=self._timeout_seconds,
            write=self._timeout_seconds,
            pool=self._timeout_seconds,
        )
        try:
            with (
                httpx.Client(
                    verify=True,
                    trust_env=False,
                    follow_redirects=False,
                    timeout=timeout,
                    transport=self._transport,
                ) as client,
                client.stream(method, url, headers=dict(headers), content=body) as response,
            ):
                if response.request.method != method or str(response.request.url) != url:
                    raise StorageBehavioralProofError("proof_request_target_changed")
                if response.is_redirect:
                    raise StorageBehavioralProofError("proof_redirect_rejected")
                encoding = response.headers.get("content-encoding")
                if encoding is not None and encoding.strip().lower() != "identity":
                    raise StorageBehavioralProofError("proof_response_encoding_rejected")
                payload = bytearray()
                chunks = (response.content,) if response.is_stream_consumed else response.iter_raw()
                for chunk in chunks:
                    if len(payload) + len(chunk) > maximum_response_bytes:
                        raise StorageBehavioralProofError("proof_response_too_large")
                    payload.extend(chunk)
                content_type = response.headers.get("content-type")
                media_type = None
                if content_type is not None and len(content_type) <= 128:
                    media_type = content_type.partition(";")[0].strip().lower()
                result = _Response(response.status_code, media_type, bytes(payload))
        except StorageBehavioralProofError:
            raise
        except (httpx.TimeoutException, TimeoutError):
            raise StorageBehavioralProofError("proof_request_timed_out") from None
        except httpx.TransportError:
            raise StorageBehavioralProofError("proof_transport_unavailable") from None
        except Exception:
            raise StorageBehavioralProofError("proof_request_failed") from None
        if result.status_code in {408, 425, 429} or 500 <= result.status_code <= 599:
            raise StorageBehavioralProofError("proof_provider_unavailable")
        return result

    def _base_headers(self, *, access_token: str | None = None) -> dict[str, str]:
        headers = {
            "accept": "application/json",
            "accept-encoding": "identity",
            "apikey": self._credentials.publishable_key,
            "user-agent": "AutoQuantTrader-trusted-time-anchor-proof/1",
        }
        if access_token is not None:
            headers["authorization"] = f"Bearer {access_token}"
        return headers

    def authenticated_headers(self) -> dict[str, str]:
        if self._access_token is None:
            raise StorageBehavioralProofError("proof_principal_not_authenticated")
        return self._base_headers(access_token=self._access_token)

    def anonymous_headers(self) -> dict[str, str]:
        return self._base_headers()

    def authenticate_and_verify_principal(self) -> None:
        request_body = _canonical_json_bytes(
            {
                "email": self._credentials.email,
                "password": self._credentials.password,
            }
        )
        response = self._request(
            "POST",
            "/auth/v1/token?grant_type=password",
            headers={**self._base_headers(), "content-type": "application/json"},
            body=request_body,
        )
        if response.status_code != 200 or response.media_type != "application/json":
            raise StorageBehavioralProofError("proof_authentication_failed")
        decoded = _decode_json(response.body, reason_code="proof_authentication_invalid")
        if type(decoded) is not dict:
            raise StorageBehavioralProofError("proof_authentication_invalid")
        access_token = decoded.get("access_token")
        expires_in = decoded.get("expires_in")
        token_type = decoded.get("token_type")
        user = decoded.get("user")
        if (
            type(access_token) is not str
            or not 64 <= len(access_token) <= 8_192
            or type(expires_in) is not int
            or not 60 <= expires_in <= 86_400
            or token_type != "bearer"
            or type(user) is not dict
            or user.get("id") != self._credentials.principal_id
        ):
            raise StorageBehavioralProofError("proof_principal_identity_conflict")
        user_response = self._request(
            "GET",
            "/auth/v1/user",
            headers=self._base_headers(access_token=access_token),
        )
        if user_response.status_code != 200 or user_response.media_type != "application/json":
            raise StorageBehavioralProofError("proof_principal_verification_failed")
        verified_user = _decode_json(
            user_response.body,
            reason_code="proof_principal_verification_invalid",
        )
        if type(verified_user) is not dict or verified_user.get("id") != (
            self._credentials.principal_id
        ):
            raise StorageBehavioralProofError("proof_principal_identity_conflict")
        self._access_token = access_token

    def request(
        self,
        method: str,
        path: str,
        *,
        authenticated: bool,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        maximum_response_bytes: int = STORAGE_BEHAVIORAL_PROOF_MAXIMUM_RESPONSE_BYTES,
    ) -> _Response:
        base = self.authenticated_headers() if authenticated else self.anonymous_headers()
        return self._request(
            method,
            path,
            headers={**base, **({} if headers is None else headers)},
            body=body,
            maximum_response_bytes=maximum_response_bytes,
        )


def _proof_object(configuration: StorageBehavioralProofConfiguration) -> tuple[str, bytes, str]:
    proof_id = configuration.proof_id
    project_ref = configuration.credentials.project_ref
    deployment_sha256 = hashlib.sha256(
        (f"aqt-trusted-time-storage-policy-proof-deployment-v1:{project_ref}:{proof_id}").encode(
            "ascii"
        )
    ).hexdigest()
    host_sha256 = hashlib.sha256(
        (f"aqt-trusted-time-storage-policy-proof-host-v1:{proof_id}").encode("ascii")
    ).hexdigest()
    payload = _canonical_json_bytes(
        {
            "contract_version": STORAGE_BEHAVIORAL_PROOF_OBJECT_CONTRACT_VERSION,
            "enrollment": "UNRUN",
            "proof_id": proof_id,
            "purpose": "storage_policy_behavioral_proof",
        }
    )
    payload_sha256 = hashlib.sha256(payload).hexdigest()
    object_name = (
        f"v1/{deployment_sha256}/{host_sha256}/"
        f"{STORAGE_BEHAVIORAL_PROOF_SEQUENCE:020d}-{payload_sha256}.json"
    )
    return object_name, payload, payload_sha256


def _storage_object_path(bucket: str, object_name: str, *, authenticated: bool) -> str:
    route = "authenticated/" if authenticated else ""
    return f"/storage/v1/object/{route}{quote(bucket, safe='')}/{quote(object_name, safe='/')}"


def _list_path(bucket: str) -> str:
    return f"/storage/v1/object/list/{quote(bucket, safe='')}"


def _list_request(prefix: str) -> bytes:
    return _canonical_json_bytes(
        {
            "limit": 2,
            "offset": 0,
            "prefix": prefix,
            "sortBy": {"column": "name", "order": "asc"},
        }
    )


def _listed_names(response: _Response, *, reason_code: str) -> tuple[str, ...]:
    if response.status_code != 200 or response.media_type != "application/json":
        raise StorageBehavioralProofError(reason_code)
    decoded = _decode_json(response.body, reason_code=reason_code)
    if type(decoded) is not list or len(decoded) > 2:
        raise StorageBehavioralProofError(reason_code)
    names: list[str] = []
    for item in decoded:
        if type(item) is not dict or type(item.get("name")) is not str:
            raise StorageBehavioralProofError(reason_code)
        names.append(item["name"])
    if len(names) != len(set(names)):
        raise StorageBehavioralProofError(reason_code)
    return tuple(names)


def _forbidden_status(value: object) -> bool:
    return (type(value) is int and value == 403) or value == "403"


def _require_authorization_denied(response: _Response, *, reason_code: str) -> None:
    """Accept only a structured Supabase authorization/RLS denial.

    ``NoSuchBucket``, ``NoSuchKey``, method errors, validation failures, and
    conflicts are deliberately rejected: none proves that the reviewed RLS
    policy evaluated and denied the attempted operation.
    """

    if (
        response.status_code not in {400, 403}
        or response.media_type != "application/json"
        or not response.body
    ):
        raise StorageBehavioralProofError(reason_code)
    decoded = _decode_json(response.body, reason_code=reason_code)
    if type(decoded) is not dict:
        raise StorageBehavioralProofError(reason_code)
    code = decoded.get("code")
    error = decoded.get("error")
    message = decoded.get("message")
    inner_status = decoded.get("statusCode", decoded.get("httpStatusCode"))
    if type(message) is not str or not message or len(message) > 1_024:
        raise StorageBehavioralProofError(reason_code)

    normalized_message = message.lower()
    authorization_message = any(
        marker in normalized_message
        for marker in (
            "access denied",
            "not authorized",
            "permission denied",
            "row-level security policy",
            "unauthorized",
        )
    )
    outer_forbidden = response.status_code == 403
    inner_forbidden = _forbidden_status(inner_status)
    access_denied = (
        code == "AccessDenied" and (outer_forbidden or inner_forbidden) and authorization_message
    )
    legacy_unauthorized = (
        (error == "Unauthorized" or code == "unauthorized")
        and (outer_forbidden or inner_forbidden)
        and authorization_message
    )
    exact_rls_violation = (
        code == "42501"
        and (outer_forbidden or inner_forbidden)
        and "row-level security policy" in normalized_message
    )
    if not (access_denied or legacy_unauthorized or exact_rls_violation):
        raise StorageBehavioralProofError(reason_code)


def _require_known_resource_hidden(
    response: _Response,
    *,
    reason_code: str,
    accepted_not_found_codes: frozenset[str],
) -> None:
    """Accept authorization denial or an exact hidden-resource response.

    This classifier is used only after authenticated operations have positively
    proven the same bucket and/or key.  Supabase documents exact 404
    ``NoSuchBucket``/``NoSuchKey`` responses as also masking denied access.
    """

    if response.status_code != 404:
        _require_authorization_denied(response, reason_code=reason_code)
        return
    if response.media_type != "application/json" or not response.body:
        raise StorageBehavioralProofError(reason_code)
    decoded = _decode_json(response.body, reason_code=reason_code)
    if type(decoded) is not dict:
        raise StorageBehavioralProofError(reason_code)
    code = decoded.get("code")
    message = decoded.get("message")
    if (
        code not in accepted_not_found_codes
        or type(message) is not str
        or not message
        or len(message) > 1_024
    ):
        raise StorageBehavioralProofError(reason_code)


def _require_collision(response: _Response) -> None:
    if response.status_code not in {400, 409} or response.media_type != "application/json":
        raise StorageBehavioralProofError("proof_overwrite_not_denied")
    decoded = _decode_json(response.body, reason_code="proof_overwrite_not_denied")
    if type(decoded) is not dict:
        raise StorageBehavioralProofError("proof_overwrite_not_denied")
    code = decoded.get("error") or decoded.get("code")
    message = decoded.get("message")
    if code not in {"KeyAlreadyExists", "ResourceAlreadyExists"} and not (
        response.status_code == 400 and message == "The resource already exists"
    ):
        raise StorageBehavioralProofError("proof_overwrite_not_denied")


def _require_exact_read(
    client: _StorageProofClient,
    *,
    object_name: str,
    payload: bytes,
) -> None:
    response = client.request(
        "GET",
        _storage_object_path(
            TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
            object_name,
            authenticated=True,
        ),
        authenticated=True,
        maximum_response_bytes=STORAGE_BEHAVIORAL_PROOF_MAXIMUM_OBJECT_BYTES,
    )
    if (
        response.status_code != 200
        or response.media_type != TRUSTED_TIME_HEAD_ANCHOR_CONTENT_TYPE
        or response.body != payload
    ):
        raise StorageBehavioralProofError("proof_canonical_object_changed")


def execute_storage_behavioral_proof(
    configuration: StorageBehavioralProofConfiguration,
    *,
    transport: httpx.BaseTransport | None = None,
) -> StorageBehavioralProofEvidence:
    """Run one no-cleanup proof and return only deterministic sanitized evidence."""

    if type(configuration) is not StorageBehavioralProofConfiguration:
        raise StorageBehavioralProofError("proof_configuration_invalid")
    configuration.__post_init__()
    object_name, payload, payload_sha256 = _proof_object(configuration)
    prefix, basename = object_name.rsplit("/", 1)
    prefix += "/"
    mutation_payload = _canonical_json_bytes(
        {
            "contract_version": STORAGE_BEHAVIORAL_PROOF_OBJECT_CONTRACT_VERSION,
            "enrollment": "UNRUN",
            "proof_id": configuration.proof_id,
            "purpose": "forbidden_storage_policy_mutation",
        }
    )
    anonymous_insert_payload = _canonical_json_bytes(
        {
            "contract_version": STORAGE_BEHAVIORAL_PROOF_OBJECT_CONTRACT_VERSION,
            "enrollment": "UNRUN",
            "proof_id": configuration.proof_id,
            "purpose": "forbidden_anonymous_canonical_insert",
        }
    )
    anonymous_insert_name = (
        f"{prefix}{2:020d}-{hashlib.sha256(anonymous_insert_payload).hexdigest()}.json"
    )
    operations: list[tuple[str, str]] = []
    current_operation = "authenticated_principal_uuid"
    storage_mutation_attempted = False
    client = _StorageProofClient(configuration.credentials, transport=transport)
    try:
        client.authenticate_and_verify_principal()
        operations.append(("authenticated_principal_uuid", "verified"))

        current_operation = "canonical_insert_x_upsert_false"
        storage_mutation_attempted = True
        upload_path = _storage_object_path(
            TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
            object_name,
            authenticated=False,
        )
        response = client.request(
            "POST",
            upload_path,
            authenticated=True,
            headers={
                "cache-control": "no-store",
                "content-type": TRUSTED_TIME_HEAD_ANCHOR_CONTENT_TYPE,
                "x-upsert": "false",
            },
            body=payload,
        )
        if response.status_code not in {200, 201}:
            raise StorageBehavioralProofError("proof_canonical_insert_failed")
        operations.append(("canonical_insert_x_upsert_false", "allowed"))

        current_operation = "authenticated_canonical_list"
        list_response = client.request(
            "POST",
            _list_path(TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME),
            authenticated=True,
            headers={"content-type": "application/json"},
            body=_list_request(prefix),
        )
        if _listed_names(list_response, reason_code="proof_authenticated_list_failed") != (
            basename,
        ):
            raise StorageBehavioralProofError("proof_authenticated_list_failed")
        operations.append(("authenticated_canonical_list", "allowed"))

        current_operation = "authenticated_canonical_read"
        _require_exact_read(client, object_name=object_name, payload=payload)
        operations.append(("authenticated_canonical_read", "allowed"))

        current_operation = "overwrite_x_upsert_false"
        collision = client.request(
            "POST",
            upload_path,
            authenticated=True,
            headers={
                "cache-control": "no-store",
                "content-type": TRUSTED_TIME_HEAD_ANCHOR_CONTENT_TYPE,
                "x-upsert": "false",
            },
            body=mutation_payload,
        )
        _require_collision(collision)
        operations.append(("overwrite_x_upsert_false", "denied"))

        current_operation = "upsert_x_upsert_true"
        upsert = client.request(
            "POST",
            upload_path,
            authenticated=True,
            headers={
                "cache-control": "no-store",
                "content-type": TRUSTED_TIME_HEAD_ANCHOR_CONTENT_TYPE,
                "x-upsert": "true",
            },
            body=mutation_payload,
        )
        _require_authorization_denied(upsert, reason_code="proof_upsert_not_denied")
        operations.append(("upsert_x_upsert_true", "denied"))

        current_operation = "update"
        update = client.request(
            "PUT",
            upload_path,
            authenticated=True,
            headers={
                "cache-control": "no-store",
                "content-type": TRUSTED_TIME_HEAD_ANCHOR_CONTENT_TYPE,
                "x-upsert": "true",
            },
            body=mutation_payload,
        )
        _require_authorization_denied(update, reason_code="proof_update_not_denied")
        operations.append(("update", "denied"))

        current_operation = "delete"
        delete = client.request(
            "DELETE",
            upload_path,
            authenticated=True,
        )
        _require_authorization_denied(delete, reason_code="proof_delete_not_denied")
        operations.append(("delete", "denied"))

        current_operation = "noncanonical_namespace_insert"
        noncanonical_name = f"proof/{payload_sha256}.json"
        noncanonical = client.request(
            "POST",
            _storage_object_path(
                TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
                noncanonical_name,
                authenticated=False,
            ),
            authenticated=True,
            headers={
                "cache-control": "no-store",
                "content-type": TRUSTED_TIME_HEAD_ANCHOR_CONTENT_TYPE,
                "x-upsert": "false",
            },
            body=payload,
        )
        _require_authorization_denied(
            noncanonical,
            reason_code="proof_noncanonical_namespace_not_denied",
        )
        operations.append(("noncanonical_namespace_insert", "denied"))

        current_operation = "real_other_bucket_insert"
        other_bucket = client.request(
            "POST",
            _storage_object_path(
                configuration.real_other_bucket_id,
                object_name,
                authenticated=False,
            ),
            authenticated=True,
            headers={
                "cache-control": "no-store",
                "content-type": TRUSTED_TIME_HEAD_ANCHOR_CONTENT_TYPE,
                "x-upsert": "false",
            },
            body=payload,
        )
        _require_authorization_denied(
            other_bucket,
            reason_code="proof_real_other_bucket_not_denied",
        )
        operations.append(("real_other_bucket_insert", "denied"))

        current_operation = "anonymous_canonical_insert"
        anonymous_insert = client.request(
            "POST",
            _storage_object_path(
                TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
                anonymous_insert_name,
                authenticated=False,
            ),
            authenticated=False,
            headers={
                "cache-control": "no-store",
                "content-type": TRUSTED_TIME_HEAD_ANCHOR_CONTENT_TYPE,
                "x-upsert": "false",
            },
            body=anonymous_insert_payload,
        )
        _require_authorization_denied(
            anonymous_insert,
            reason_code="proof_anonymous_insert_not_denied",
        )
        operations.append(("anonymous_canonical_insert", "denied"))

        current_operation = "anonymous_list"
        anonymous_list = client.request(
            "POST",
            _list_path(TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME),
            authenticated=False,
            headers={"content-type": "application/json"},
            body=_list_request(prefix),
        )
        if anonymous_list.status_code == 200:
            if _listed_names(
                anonymous_list,
                reason_code="proof_anonymous_list_exposed",
            ):
                raise StorageBehavioralProofError("proof_anonymous_list_exposed")
        else:
            _require_known_resource_hidden(
                anonymous_list,
                reason_code="proof_anonymous_list_not_denied",
                accepted_not_found_codes=frozenset({"NoSuchBucket"}),
            )
        operations.append(("anonymous_list", "denied"))

        current_operation = "anonymous_read"
        anonymous_read = client.request(
            "GET",
            _storage_object_path(
                TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
                object_name,
                authenticated=True,
            ),
            authenticated=False,
            maximum_response_bytes=STORAGE_BEHAVIORAL_PROOF_MAXIMUM_OBJECT_BYTES,
        )
        _require_known_resource_hidden(
            anonymous_read,
            reason_code="proof_anonymous_read_not_denied",
            accepted_not_found_codes=frozenset({"NoSuchKey", "NoSuchBucket"}),
        )
        operations.append(("anonymous_read", "denied"))

        current_operation = "public_read"
        public_read = client.request(
            "GET",
            (
                f"/storage/v1/object/public/"
                f"{quote(TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME, safe='')}/"
                f"{quote(object_name, safe='/')}"
            ),
            authenticated=False,
            maximum_response_bytes=STORAGE_BEHAVIORAL_PROOF_MAXIMUM_OBJECT_BYTES,
        )
        _require_known_resource_hidden(
            public_read,
            reason_code="proof_public_read_not_denied",
            accepted_not_found_codes=frozenset({"NoSuchKey", "NoSuchBucket"}),
        )
        operations.append(("public_read", "denied"))

        current_operation = "canonical_object_retained_unchanged"
        _require_exact_read(client, object_name=object_name, payload=payload)
        operations.append(("canonical_object_retained_unchanged", "verified"))

        current_operation = "canonical_namespace_retained_unchanged"
        final_list = client.request(
            "POST",
            _list_path(TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME),
            authenticated=True,
            headers={"content-type": "application/json"},
            body=_list_request(prefix),
        )
        if _listed_names(final_list, reason_code="proof_canonical_namespace_changed") != (
            basename,
        ):
            raise StorageBehavioralProofError("proof_canonical_namespace_changed")
        operations.append(("canonical_namespace_retained_unchanged", "verified"))
    except StorageBehavioralProofError as error:
        raise error.with_context(
            StorageBehavioralProofFailureContext(
                proof_id=configuration.proof_id,
                object_name=object_name,
                object_payload_sha256=payload_sha256,
                completed_operations=tuple(operations),
                failed_operation=current_operation,
                external_state_outcome=(
                    "UNKNOWN_REVIEW_REQUIRED"
                    if storage_mutation_attempted
                    else "NO_STORAGE_MUTATION_ATTEMPTED"
                ),
            )
        ) from None
    except Exception:
        raise StorageBehavioralProofError(
            "proof_execution_failed",
            failure_context=StorageBehavioralProofFailureContext(
                proof_id=configuration.proof_id,
                object_name=object_name,
                object_payload_sha256=payload_sha256,
                completed_operations=tuple(operations),
                failed_operation=current_operation,
                external_state_outcome=(
                    "UNKNOWN_REVIEW_REQUIRED"
                    if storage_mutation_attempted
                    else "NO_STORAGE_MUTATION_ATTEMPTED"
                ),
            ),
        ) from None
    finally:
        client.close()

    return StorageBehavioralProofEvidence(
        anchor_project_ref=configuration.credentials.project_ref,
        principal_id=configuration.credentials.principal_id,
        proof_id=configuration.proof_id,
        real_other_bucket_id=configuration.real_other_bucket_id,
        real_other_bucket_existence_evidence_sha256=(
            configuration.real_other_bucket_existence_evidence_sha256
        ),
        real_other_bucket_source_evidence_sha256=(
            configuration.real_other_bucket_source_evidence_sha256
        ),
        real_other_bucket_verification_method=(configuration.real_other_bucket_verification_method),
        real_other_bucket_verified_at_utc=(configuration.real_other_bucket_verified_at_utc),
        object_name=object_name,
        object_payload_sha256=payload_sha256,
        operations=tuple(operations),
    )


def _failure_payload(
    reason_code: str,
    *,
    context: StorageBehavioralProofFailureContext | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "allow_enrollment": False,
        "completed_operations": [],
        "contract_version": STORAGE_BEHAVIORAL_PROOF_CONTRACT_VERSION,
        "enrollment": "UNRUN",
        "external_state_outcome": "NO_STORAGE_MUTATION_ATTEMPTED",
        "failed_operation": "configuration",
        "reason": reason_code,
        "status": "failed",
    }
    if context is not None:
        payload.update(context.public_payload)
    return payload


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    credentials = parser.add_mutually_exclusive_group(required=True)
    credentials.add_argument(
        "--env-file",
        type=Path,
        help="absolute owner-only dotenv containing the five writer proof variables",
    )
    credentials.add_argument(
        "--auth-secret-file",
        type=Path,
        help="absolute owner-only runtime-compatible writer Auth-secret JSON",
    )
    parser.add_argument(
        "--proof-id",
        required=True,
        help="new canonical lowercase UUID that makes this retained proof object unique",
    )
    parser.add_argument(
        "--real-other-bucket-evidence-file",
        required=True,
        type=Path,
        help=(
            "owner-only canonical JSON from an independent dashboard or supported-API "
            "verification that the separate private bucket exists"
        ),
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    transport: httpx.BaseTransport | None = None,
) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.env_file is not None:
            configuration = load_configuration_from_env_file(
                arguments.env_file,
                proof_id=arguments.proof_id,
                real_other_bucket_evidence_file=arguments.real_other_bucket_evidence_file,
            )
        else:
            configuration = load_configuration_from_auth_secret(
                arguments.auth_secret_file,
                proof_id=arguments.proof_id,
                real_other_bucket_evidence_file=arguments.real_other_bucket_evidence_file,
            )
        evidence = execute_storage_behavioral_proof(configuration, transport=transport)
    except StorageBehavioralProofError as error:
        print(
            _canonical_json_bytes(
                _failure_payload(error.reason_code, context=error.failure_context)
            ).decode("ascii"),
            flush=True,
        )
        return 2
    except Exception:
        print(
            _canonical_json_bytes(_failure_payload("proof_command_failed")).decode("ascii"),
            flush=True,
        )
        return 2
    print(evidence.canonical_json, flush=True)
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())


__all__ = [
    "STORAGE_BEHAVIORAL_PROOF_CONTRACT_VERSION",
    "STORAGE_BEHAVIORAL_PROOF_ENVIRONMENT_VARIABLES",
    "STORAGE_BEHAVIORAL_PROOF_OBJECT_CONTRACT_VERSION",
    "StorageBehavioralProofConfiguration",
    "StorageBehavioralProofError",
    "StorageBehavioralProofEvidence",
    "execute_storage_behavioral_proof",
    "load_configuration_from_auth_secret",
    "load_configuration_from_env_file",
    "main",
]
