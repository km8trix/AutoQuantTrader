"""Strict admission and secret loading for the separate trusted-head anchor."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import make_url
from sqlalchemy.exc import ArgumentError

from apps.trusted_time_supervisor.config import (
    TrustedTimeSupervisorConfigurationError,
    _read_protected_file,
)
from packages.adapters.trusted_time.ed25519_anchor import (
    Ed25519TrustedTimeAnchorSigner,
    Ed25519TrustedTimeAnchorVerifier,
    ed25519_public_key_sha256,
)
from packages.adapters.trusted_time.supabase_storage_anchor import (
    SupabaseStorageAnchorCredentials,
)
from packages.application.trusted_time_head_anchor import (
    TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
    TRUSTED_TIME_HEAD_ANCHOR_CONTRACT_VERSION,
)
from packages.domain.canonical import canonical_json_bytes
from packages.persistence.postgres_tls import is_supabase_session_pooler_url

TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_CONTRACT_VERSION = (
    "phase6d-separate-supabase-trusted-head-authority-v1"
)
TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_CONTRACT_VERSION = (
    "phase6d-supabase-trusted-head-auth-secret-v1"
)
TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_PATH = Path(
    "/etc/autoquant/trusted-time/head-anchor-authority.json"
)
TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_PATH = Path("/run/secrets/trusted_time_head_anchor_auth")
TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_SECRET_PATH = Path(
    "/run/secrets/trusted_time_head_anchor_signing_key"
)
TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_EXPECTED_SHA256_ENVIRONMENT = (
    "AQT_TRUSTED_TIME_EXPECTED_HEAD_ANCHOR_AUTHORITY_SHA256"
)
TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_EXPECTED_SHA256_ENVIRONMENT = (
    "AQT_TRUSTED_TIME_EXPECTED_HEAD_ANCHOR_AUTH_SECRET_SHA256"
)
TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_EXPECTED_SHA256_ENVIRONMENT = (
    "AQT_TRUSTED_TIME_EXPECTED_HEAD_ANCHOR_SIGNING_KEY_SHA256"
)
TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS = 300
TRUSTED_TIME_HEAD_ANCHOR_STALE_AFTER_SECONDS = 360
MAXIMUM_HEAD_ANCHOR_AUTHORITY_BYTES = 16_384
MAXIMUM_HEAD_ANCHOR_AUTH_SECRET_BYTES = 4_096
ED25519_PRIVATE_KEY_BYTES = 32

_PROJECT_REF = re.compile(r"[a-z0-9]{20}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_KEY_ID = re.compile(r"[a-z][a-z0-9._:-]{7,127}\Z")
_AUTHORITY_KEYS = frozenset(
    {
        "anchor_project_identity_sha256",
        "anchor_project_ref",
        "anchor_project_url",
        "authority",
        "bucket_name",
        "checkpoint",
        "contract_version",
        "deployment_identity_sha256",
        "host_id",
        "principal_id",
        "runtime_database_identity_sha256",
        "runtime_database_project_ref",
        "signing",
        "source_authority_sha256",
    }
)
_SIGNING_KEYS = frozenset(
    {
        "algorithm",
        "key_id",
        "public_key_base64",
        "public_key_sha256",
    }
)
_CHECKPOINT_KEYS = frozenset(
    {
        "checkpoint_interval_seconds",
        "full_prefix_verification_required",
        "no_overwrite_required",
        "stale_after_seconds",
    }
)
_AUTHORITY_FLAGS = {
    "alert_delivery": False,
    "automatic_rearm": False,
    "external_head_anchor_evidence_only": True,
    "live_trading": False,
    "new_exposure": False,
    "operational_control": False,
    "paper_trading": False,
    "readiness": False,
}
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


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_sha256(value: object, field_name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise TrustedTimeSupervisorConfigurationError(
            f"trusted-time head-anchor {field_name} is malformed"
        )
    return value


def _require_project_ref(value: object, field_name: str) -> str:
    if type(value) is not str or _PROJECT_REF.fullmatch(value) is None:
        raise TrustedTimeSupervisorConfigurationError(
            f"trusted-time head-anchor {field_name} is malformed"
        )
    return value


def _require_text(value: object, field_name: str, *, maximum: int = 128) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise TrustedTimeSupervisorConfigurationError(
            f"trusted-time head-anchor {field_name} is malformed"
        )
    return value


def _require_uuid(value: object, field_name: str) -> str:
    exact = _require_text(value, field_name, maximum=36)
    try:
        parsed = UUID(exact)
    except (AttributeError, ValueError):
        raise TrustedTimeSupervisorConfigurationError(
            f"trusted-time head-anchor {field_name} is malformed"
        ) from None
    if parsed.int == 0 or str(parsed) != exact:
        raise TrustedTimeSupervisorConfigurationError(
            f"trusted-time head-anchor {field_name} is malformed"
        )
    return exact


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time head-anchor JSON contains a duplicate field"
            )
        value[key] = item
    return value


def _decode_json_object(payload: bytes, *, label: str) -> dict[str, Any]:
    try:
        value: Any = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except TrustedTimeSupervisorConfigurationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise TrustedTimeSupervisorConfigurationError(
            f"trusted-time head-anchor {label} is malformed"
        ) from None
    if type(value) is not dict:
        raise TrustedTimeSupervisorConfigurationError(
            f"trusted-time head-anchor {label} is malformed"
        )
    return value


def trusted_time_head_anchor_project_identity_sha256(
    *,
    role: str,
    project_ref: str,
) -> str:
    exact_role = _require_text(role, "project role", maximum=64)
    if exact_role not in {"runtime_database", "external_anchor"}:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor project role is unsupported"
        )
    exact_ref = _require_project_ref(project_ref, "project reference")
    return _sha256(
        (
            TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_CONTRACT_VERSION,
            "trusted_time_head_anchor_supabase_project_identity",
            exact_role,
            exact_ref,
        )
    )


def trusted_time_head_anchor_deployment_identity_sha256(
    *,
    host_id: str,
    source_authority_sha256: str,
    runtime_database_identity_sha256: str,
    anchor_project_identity_sha256: str,
    principal_id: str,
    signing_key_id: str,
    signing_public_key_sha256: str,
) -> str:
    return _sha256(
        (
            TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_CONTRACT_VERSION,
            TRUSTED_TIME_HEAD_ANCHOR_CONTRACT_VERSION,
            "trusted_time_head_anchor_deployment_identity",
            _require_text(host_id, "host identity"),
            _require_sha256(source_authority_sha256, "source authority SHA-256"),
            _require_sha256(
                runtime_database_identity_sha256,
                "runtime-database identity SHA-256",
            ),
            _require_sha256(
                anchor_project_identity_sha256,
                "anchor-project identity SHA-256",
            ),
            TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
            _require_uuid(principal_id, "principal identity"),
            _require_text(signing_key_id, "signing-key identity"),
            _require_sha256(
                signing_public_key_sha256,
                "signing public-key SHA-256",
            ),
        )
    )


def runtime_database_project_ref(database_url: str) -> str:
    try:
        parsed = make_url(database_url)
    except (ArgumentError, TypeError, ValueError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor runtime database identity is unavailable"
        ) from None
    if not is_supabase_session_pooler_url(parsed) or parsed.username is None:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor runtime database identity is unavailable"
        )
    return _require_project_ref(
        parsed.username.rsplit(".", 1)[1],
        "runtime-database project reference",
    )


@dataclass(frozen=True, slots=True)
class TrustedTimeHeadAnchorAuthority:
    """Exact nonsecret identity and policy baked into the supervisor image."""

    anchor_authority_sha256: str
    deployment_identity_sha256: str
    host_id: str
    source_authority_sha256: str
    runtime_database_project_ref: str
    runtime_database_identity_sha256: str
    anchor_project_ref: str
    anchor_project_url: str
    anchor_project_identity_sha256: str
    bucket_name: str
    principal_id: str
    signing_key_id: str
    signing_public_key_sha256: str
    signing_public_key_bytes: bytes = field(repr=False)
    checkpoint_interval_seconds: int = TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
    stale_after_seconds: int = TRUSTED_TIME_HEAD_ANCHOR_STALE_AFTER_SECONDS

    def __post_init__(self) -> None:
        _require_sha256(self.anchor_authority_sha256, "authority SHA-256")
        _require_sha256(self.deployment_identity_sha256, "deployment identity SHA-256")
        _require_text(self.host_id, "host identity")
        _require_sha256(self.source_authority_sha256, "source authority SHA-256")
        _require_project_ref(
            self.runtime_database_project_ref,
            "runtime-database project reference",
        )
        _require_sha256(
            self.runtime_database_identity_sha256,
            "runtime-database identity SHA-256",
        )
        _require_project_ref(self.anchor_project_ref, "anchor-project reference")
        if self.anchor_project_ref == self.runtime_database_project_ref:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time head-anchor project is not separate from the runtime database"
            )
        if self.anchor_project_url != f"https://{self.anchor_project_ref}.supabase.co":
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time head-anchor project URL is malformed"
            )
        _require_sha256(
            self.anchor_project_identity_sha256,
            "anchor-project identity SHA-256",
        )
        if self.bucket_name != TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time head-anchor bucket identity drifted"
            )
        _require_uuid(self.principal_id, "principal identity")
        if _KEY_ID.fullmatch(self.signing_key_id) is None:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time head-anchor signing-key identity is malformed"
            )
        _require_sha256(
            self.signing_public_key_sha256,
            "signing public-key SHA-256",
        )
        if (
            type(self.signing_public_key_bytes) is not bytes
            or len(self.signing_public_key_bytes) != ED25519_PRIVATE_KEY_BYTES
            or ed25519_public_key_sha256(self.signing_public_key_bytes)
            != self.signing_public_key_sha256
        ):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time head-anchor signing public key is malformed"
            )
        if (
            self.checkpoint_interval_seconds != TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
            or self.stale_after_seconds != TRUSTED_TIME_HEAD_ANCHOR_STALE_AFTER_SECONDS
        ):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time head-anchor checkpoint policy drifted"
            )

    @property
    def readiness_authorized(self) -> bool:
        return False

    @property
    def operational_control_authorized(self) -> bool:
        return False

    @property
    def arming_authorized(self) -> bool:
        return False

    @property
    def new_exposure_authorized(self) -> bool:
        return False

    @property
    def broker_action_authorized(self) -> bool:
        return False

    @property
    def automatic_rearm_authorized(self) -> bool:
        return False

    @property
    def rearm_authorized(self) -> bool:
        return False

    @property
    def automatic_resume_authorized(self) -> bool:
        return False

    @property
    def alert_delivery_authorized(self) -> bool:
        return False

    @property
    def exposure_authorized(self) -> bool:
        return False

    @property
    def paper_trading_authorized(self) -> bool:
        return False

    @property
    def live_trading_authorized(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class TrustedTimeHeadAnchorRuntimeConfiguration:
    """Bound authority, least-privilege Auth session, and admitted signing key."""

    authority: TrustedTimeHeadAnchorAuthority
    credentials: SupabaseStorageAnchorCredentials = field(repr=False)
    signer: Ed25519TrustedTimeAnchorSigner = field(repr=False)
    verifier: Ed25519TrustedTimeAnchorVerifier

    def __repr__(self) -> str:
        return (
            "TrustedTimeHeadAnchorRuntimeConfiguration("
            f"authority={self.authority!r}, credentials=<redacted>, "
            "signer=<redacted>, verifier=<admitted>)"
        )


def decode_trusted_time_head_anchor_authority(
    payload: bytes,
    *,
    database_url: str,
    expected_host_id: str,
    expected_source_authority_sha256: str,
) -> TrustedTimeHeadAnchorAuthority:
    if type(payload) is not bytes or not 1 <= len(payload) <= MAXIMUM_HEAD_ANCHOR_AUTHORITY_BYTES:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor authority is unavailable"
        )
    root = _decode_json_object(payload, label="authority")
    if set(root) != _AUTHORITY_KEYS or root.get("contract_version") != (
        TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_CONTRACT_VERSION
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor authority differs from the approved contract"
        )
    signing = root.get("signing")
    checkpoint = root.get("checkpoint")
    flags = root.get("authority")
    if (
        type(signing) is not dict
        or set(signing) != _SIGNING_KEYS
        or type(checkpoint) is not dict
        or set(checkpoint) != _CHECKPOINT_KEYS
        or flags != _AUTHORITY_FLAGS
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor authority differs from the approved contract"
        )
    public_key_text = signing.get("public_key_base64")
    if type(public_key_text) is not str:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor signing public key is malformed"
        )
    try:
        public_key = base64.b64decode(public_key_text, validate=True)
    except (ValueError, TypeError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor signing public key is malformed"
        ) from None
    if base64.b64encode(public_key).decode("ascii") != public_key_text:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor signing public key is noncanonical"
        )
    host_id = _require_text(root.get("host_id"), "host identity")
    source_authority = _require_sha256(
        root.get("source_authority_sha256"),
        "source authority SHA-256",
    )
    if host_id != expected_host_id or source_authority != expected_source_authority_sha256:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor authority crosses source deployment identity"
        )
    runtime_ref = _require_project_ref(
        root.get("runtime_database_project_ref"),
        "runtime-database project reference",
    )
    if runtime_ref != runtime_database_project_ref(database_url):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor authority crosses runtime database identity"
        )
    anchor_ref = _require_project_ref(
        root.get("anchor_project_ref"),
        "anchor-project reference",
    )
    runtime_identity = trusted_time_head_anchor_project_identity_sha256(
        role="runtime_database",
        project_ref=runtime_ref,
    )
    anchor_identity = trusted_time_head_anchor_project_identity_sha256(
        role="external_anchor",
        project_ref=anchor_ref,
    )
    signing_key_id = _require_text(signing.get("key_id"), "signing-key identity")
    public_key_sha256 = _require_sha256(
        signing.get("public_key_sha256"),
        "signing public-key SHA-256",
    )
    principal_id = _require_uuid(root.get("principal_id"), "principal identity")
    deployment_identity = trusted_time_head_anchor_deployment_identity_sha256(
        host_id=host_id,
        source_authority_sha256=source_authority,
        runtime_database_identity_sha256=runtime_identity,
        anchor_project_identity_sha256=anchor_identity,
        principal_id=principal_id,
        signing_key_id=signing_key_id,
        signing_public_key_sha256=public_key_sha256,
    )
    if (
        root.get("runtime_database_identity_sha256") != runtime_identity
        or root.get("anchor_project_identity_sha256") != anchor_identity
        or root.get("deployment_identity_sha256") != deployment_identity
        or root.get("anchor_project_url") != f"https://{anchor_ref}.supabase.co"
        or root.get("bucket_name") != TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME
        or signing.get("algorithm") != "Ed25519"
        or checkpoint
        != {
            "checkpoint_interval_seconds": TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
            "full_prefix_verification_required": True,
            "no_overwrite_required": True,
            "stale_after_seconds": TRUSTED_TIME_HEAD_ANCHOR_STALE_AFTER_SECONDS,
        }
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor authority differs from the approved contract"
        )
    return TrustedTimeHeadAnchorAuthority(
        anchor_authority_sha256=hashlib.sha256(payload).hexdigest(),
        deployment_identity_sha256=deployment_identity,
        host_id=host_id,
        source_authority_sha256=source_authority,
        runtime_database_project_ref=runtime_ref,
        runtime_database_identity_sha256=runtime_identity,
        anchor_project_ref=anchor_ref,
        anchor_project_url=f"https://{anchor_ref}.supabase.co",
        anchor_project_identity_sha256=anchor_identity,
        bucket_name=TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
        principal_id=principal_id,
        signing_key_id=signing_key_id,
        signing_public_key_sha256=public_key_sha256,
        signing_public_key_bytes=public_key,
    )


def decode_trusted_time_head_anchor_auth_secret(
    payload: bytes,
    *,
    authority: TrustedTimeHeadAnchorAuthority,
) -> SupabaseStorageAnchorCredentials:
    if type(payload) is not bytes or not 1 <= len(payload) <= MAXIMUM_HEAD_ANCHOR_AUTH_SECRET_BYTES:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor Auth secret is unavailable"
        )
    root = _decode_json_object(payload, label="Auth secret")
    if set(root) != _AUTH_SECRET_KEYS or root.get("contract_version") != (
        TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_CONTRACT_VERSION
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor Auth secret is malformed"
        )
    try:
        credentials = SupabaseStorageAnchorCredentials(
            project_url=root["project_url"],
            publishable_key=root["publishable_key"],
            principal_id=root["principal_id"],
            anchor_project_identity_sha256=authority.anchor_project_identity_sha256,
            email=root["email"],
            password=root["password"],
        )
    except Exception:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor Auth secret is malformed"
        ) from None
    if (
        credentials.project_url != authority.anchor_project_url
        or credentials.project_ref != authority.anchor_project_ref
        or credentials.principal_id != authority.principal_id
        or credentials.anchor_project_identity_sha256 != authority.anchor_project_identity_sha256
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor Auth secret crosses admitted identity"
        )
    return credentials


def load_trusted_time_head_anchor_runtime_configuration(
    *,
    database_url: str,
    expected_host_id: str,
    expected_source_authority_sha256: str,
    authority_path: Path = TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_PATH,
    auth_secret_path: Path = TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_PATH,
    signing_key_secret_path: Path = TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_SECRET_PATH,
    authority_owner_uid: int = 0,
    secret_owner_uid: int = 10001,
    expected_authority_sha256: str | None = None,
    expected_auth_secret_sha256: str | None = None,
    expected_signing_key_sha256: str | None = None,
) -> TrustedTimeHeadAnchorRuntimeConfiguration:
    expected_digests = (
        expected_authority_sha256,
        expected_auth_secret_sha256,
        expected_signing_key_sha256,
    )
    if any(value is None for value in expected_digests) != all(
        value is None for value in expected_digests
    ) or any(value is not None and _SHA256.fullmatch(value) is None for value in expected_digests):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor staged-input binding is invalid"
        )
    authority_payload = _read_protected_file(
        authority_path,
        maximum_bytes=MAXIMUM_HEAD_ANCHOR_AUTHORITY_BYTES,
        expected_owner_uid=authority_owner_uid,
        label="trusted-time head-anchor authority",
    )
    if (
        expected_authority_sha256 is not None
        and hashlib.sha256(authority_payload).hexdigest() != expected_authority_sha256
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor authority differs from its staged-input binding"
        )
    authority = decode_trusted_time_head_anchor_authority(
        authority_payload,
        database_url=database_url,
        expected_host_id=expected_host_id,
        expected_source_authority_sha256=expected_source_authority_sha256,
    )
    auth_payload = _read_protected_file(
        auth_secret_path,
        maximum_bytes=MAXIMUM_HEAD_ANCHOR_AUTH_SECRET_BYTES,
        expected_owner_uid=secret_owner_uid,
        label="trusted-time head-anchor Auth secret",
    )
    if (
        expected_auth_secret_sha256 is not None
        and hashlib.sha256(auth_payload).hexdigest() != expected_auth_secret_sha256
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor Auth secret differs from its staged-input binding"
        )
    private_key = _read_protected_file(
        signing_key_secret_path,
        maximum_bytes=ED25519_PRIVATE_KEY_BYTES,
        expected_owner_uid=secret_owner_uid,
        label="trusted-time head-anchor signing secret",
    )
    if (
        expected_signing_key_sha256 is not None
        and hashlib.sha256(private_key).hexdigest() != expected_signing_key_sha256
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor signing secret differs from its staged-input binding"
        )
    if len(private_key) != ED25519_PRIVATE_KEY_BYTES:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor signing secret is malformed"
        )
    credentials = decode_trusted_time_head_anchor_auth_secret(
        auth_payload,
        authority=authority,
    )
    try:
        signer = Ed25519TrustedTimeAnchorSigner.from_private_key_bytes(
            signing_key_id=authority.signing_key_id,
            expected_signing_public_key_sha256=authority.signing_public_key_sha256,
            private_key_bytes=private_key,
        )
        verifier = Ed25519TrustedTimeAnchorVerifier.from_public_key_bytes(
            signing_key_id=authority.signing_key_id,
            expected_signing_public_key_sha256=authority.signing_public_key_sha256,
            public_key_bytes=authority.signing_public_key_bytes,
        )
    except Exception:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor signing identity is malformed"
        ) from None
    return TrustedTimeHeadAnchorRuntimeConfiguration(
        authority=authority,
        credentials=credentials,
        signer=signer,
        verifier=verifier,
    )


__all__ = [
    "ED25519_PRIVATE_KEY_BYTES",
    "MAXIMUM_HEAD_ANCHOR_AUTHORITY_BYTES",
    "MAXIMUM_HEAD_ANCHOR_AUTH_SECRET_BYTES",
    "TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_CONTRACT_VERSION",
    "TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_EXPECTED_SHA256_ENVIRONMENT",
    "TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_PATH",
    "TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_CONTRACT_VERSION",
    "TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_EXPECTED_SHA256_ENVIRONMENT",
    "TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_PATH",
    "TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS",
    "TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_EXPECTED_SHA256_ENVIRONMENT",
    "TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_SECRET_PATH",
    "TRUSTED_TIME_HEAD_ANCHOR_STALE_AFTER_SECONDS",
    "TrustedTimeHeadAnchorAuthority",
    "TrustedTimeHeadAnchorRuntimeConfiguration",
    "decode_trusted_time_head_anchor_auth_secret",
    "decode_trusted_time_head_anchor_authority",
    "load_trusted_time_head_anchor_runtime_configuration",
    "runtime_database_project_ref",
    "trusted_time_head_anchor_deployment_identity_sha256",
    "trusted_time_head_anchor_project_identity_sha256",
]
