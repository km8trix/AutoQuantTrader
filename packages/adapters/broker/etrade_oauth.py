"""Pure, non-I/O E*TRADE OAuth 1.0a and supervised-session contract.

The module canonicalizes and signs the four ADR-0113-pinned OAuth control
requests from caller-injected timestamps and nonces.  Secret values exist only
inside sealed, deliberately non-serializable ephemeral wrappers. Authorization
confirmation issues one in-process exact-verifier-identity capability that
access signing consumes once. Returned evidence contains reference versions and
sanitized protocol identities, never keys, tokens, secrets, verifiers,
signatures, authorization headers, or token-bearing authorization URLs.

The session reducer is caller-supervised and in-memory.  It models protocol
transitions but authenticates no provider response and grants no credential,
browser, callback, transport, persistence, account, broker, or trading
authority.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum
from threading import Lock, current_thread
from types import MappingProxyType
from typing import Any, Never, cast
from urllib.parse import quote

from packages.adapters.broker.etrade import (
    ETRADE_OUT_OF_BAND_CALLBACK_POLICY,
    ETRADE_PROVIDER,
    ETRADE_SHARED_ACCESS_TOKEN_URL,
    ETRADE_SHARED_AUTHORIZATION_PAGE,
    ETRADE_SHARED_RENEW_ACCESS_TOKEN_URL,
    ETRADE_SHARED_REQUEST_TOKEN_URL,
    ETRADE_SHARED_REVOKE_ACCESS_TOKEN_URL,
    EtradeEndpointIsolationProfile,
    EtradeEnvironment,
    EtradeOAuthCallbackPolicy,
    EtradeProviderIdentity,
    EtradeSecretScope,
)
from packages.domain.canonical import canonical_json_bytes

ETRADE_OAUTH_SESSION_CONTRACT_VERSION = "phase4al-etrade-oauth1-supervised-session-v1"
ETRADE_OAUTH_SESSION_REVIEWED_ON = "2026-08-25"
ETRADE_OAUTH_SIGNATURE_METHOD = "HMAC-SHA1"
ETRADE_OAUTH_PROTOCOL_VERSION = "1.0"
ETRADE_OAUTH_HTTP_METHOD = "GET"
ETRADE_OAUTH_INACTIVITY_SECONDS = 7_200
ETRADE_OAUTH_REPLAY_GUARD_MAX_FINGERPRINTS = 4_096

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_NONCE_PATTERN = re.compile(r"[A-Za-z0-9._~-]{16,128}")
_SENSITIVE_TEXT_MAX_UTF8_BYTES = 4_096
_UNRESERVED_SAFE = "-._~"

_AUTHORITY_FIELDS = (
    "credential_resolution_authorized",
    "oauth_session_acquisition_authorized",
    "oauth_token_renewal_authorized",
    "oauth_token_revocation_authorized",
    "durable_replay_protection_authorized",
    "provider_response_authentication_authorized",
    "session_currentness_authorized",
    "ambient_clock_authorized",
    "ambient_randomness_authorized",
    "filesystem_authorized",
    "persistence_authorized",
    "proxy_inheritance_authorized",
    "redirect_authorized",
    "browser_authorization_authorized",
    "callback_handling_authorized",
    "provider_network_authorized",
    "provider_origin_authenticated",
    "account_binding_authorized",
    "broker_call_authorized",
    "broker_mutation_authorized",
    "canonical_fact_application_authorized",
    "paper_startup_authorized",
    "live_startup_authorized",
    "trading_effect_authorized",
)


class EtradeOAuthContractError(ValueError):
    """The pure OAuth signing or session contract was violated."""


class EtradeOAuthOperation(StrEnum):
    """The four exact shared OAuth token-control resources pinned by ADR 0113."""

    REQUEST_TOKEN = "request_token"
    ACCESS_TOKEN = "access_token"
    RENEW_ACCESS_TOKEN = "renew_access_token"
    REVOKE_ACCESS_TOKEN = "revoke_access_token"


class EtradeOAuthTokenKind(StrEnum):
    """Disjoint lifecycle meanings for one environment-bound token reference."""

    REQUEST_TOKEN = "request_token"
    ACCESS_TOKEN = "access_token"


class EtradeOAuthSessionPhase(StrEnum):
    """Closed supervised-session phases; none are provider-authentication facts."""

    NEEDS_REQUEST_TOKEN = "needs_request_token"
    REQUEST_TOKEN_RECEIVED = "request_token_received"
    AUTHORIZATION_PENDING = "authorization_pending"
    AUTHORIZATION_CONFIRMED = "authorization_confirmed"
    ACCESS_TOKEN_ACTIVE = "access_token_active"
    ACCESS_TOKEN_INACTIVE = "access_token_inactive"
    ACCESS_TOKEN_EXPIRED = "access_token_expired"
    ACCESS_TOKEN_REVOKED = "access_token_revoked"
    REAUTHORIZATION_REQUIRED = "reauthorization_required"


class EtradeOAuthReauthorizationReason(StrEnum):
    """Closed reasons that invalidate an access-token session."""

    INACTIVITY = "inactivity"
    DAILY_EXPIRY = "daily_expiry"
    REVOCATION = "revocation"


def _semantic_sha256(material: object) -> str:
    return hashlib.sha256(canonical_json_bytes(material)).hexdigest()


def _require_exact_type(value: object, expected_type: type[object], field_name: str) -> None:
    if type(value) is not expected_type:
        raise EtradeOAuthContractError(
            f"{field_name} must use the exact E*TRADE OAuth provider-specific type"
        )


def _require_sha256(value: object, field_name: str) -> str:
    if type(value) is not str or _SHA256_PATTERN.fullmatch(value) is None:
        raise EtradeOAuthContractError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _require_exact_bool_false(value: object, field_name: str) -> None:
    if type(value) is not bool or value is not False:
        raise EtradeOAuthContractError(f"E*TRADE OAuth authority {field_name} must remain false")


class _EtradeOAuthSealed:
    """Reject ordinary post-construction mutation of ephemeral OAuth objects."""

    __slots__ = ()

    def __setattr__(self, name: str, value: object) -> Never:
        del name, value
        raise AttributeError("ephemeral E*TRADE OAuth objects are sealed")

    def __delattr__(self, name: str) -> Never:
        del name
        raise AttributeError("ephemeral E*TRADE OAuth objects are sealed")


def etrade_oauth_percent_encode(value: str) -> str:
    """Apply RFC 5849 UTF-8 percent encoding to caller-identified nonsecret text."""

    if type(value) is not str:
        raise EtradeOAuthContractError("OAuth percent-encoding input must be exact text")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise EtradeOAuthContractError(
            "OAuth percent-encoding input must be valid Unicode"
        ) from exc
    return quote(value, safe=_UNRESERVED_SAFE, encoding="utf-8", errors="strict")


def _normalize_parameter_pairs(parameters: tuple[tuple[str, str], ...]) -> str:
    """Normalize an exact parameter set and reject duplicate decoded names."""

    if type(parameters) is not tuple:
        raise EtradeOAuthContractError("OAuth parameters must be an exact immutable tuple")
    names: set[str] = set()
    encoded: list[tuple[str, str]] = []
    for parameter in parameters:
        if type(parameter) is not tuple or len(parameter) != 2:
            raise EtradeOAuthContractError("each OAuth parameter must be an exact name/value pair")
        name, value = parameter
        if type(name) is not str or type(value) is not str or not name:
            raise EtradeOAuthContractError("OAuth parameter names and values must be exact text")
        if name in names:
            raise EtradeOAuthContractError("duplicate OAuth parameter names are unsupported")
        names.add(name)
        encoded.append((etrade_oauth_percent_encode(name), etrade_oauth_percent_encode(value)))
    encoded.sort(key=lambda item: (item[0], item[1]))
    return "&".join(f"{name}={value}" for name, value in encoded)


@dataclass(frozen=True, slots=True)
class EtradeOAuthNonsecretParameter:
    """A non-OAuth, nonsecret canonicalization vector parameter."""

    name: str
    value: str

    def __post_init__(self) -> None:
        if (
            type(self.name) is not str
            or not self.name
            or len(self.name.encode("utf-8")) > 128
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in self.name)
            or self.name.startswith("oauth_")
        ):
            raise EtradeOAuthContractError(
                "nonsecret vector parameter names must be safe and cannot use oauth_"
            )
        if type(self.value) is not str or len(self.value.encode("utf-8")) > 4_096:
            raise EtradeOAuthContractError(
                "nonsecret vector parameter value is invalid or oversized"
            )
        etrade_oauth_percent_encode(self.value)


def normalize_etrade_oauth_nonsecret_parameters(
    parameters: tuple[EtradeOAuthNonsecretParameter, ...],
) -> str:
    """Normalize nonsecret test/profile material under the production algorithm."""

    if type(parameters) is not tuple:
        raise EtradeOAuthContractError("nonsecret OAuth parameters must be an exact tuple")
    pairs: list[tuple[str, str]] = []
    for parameter in parameters:
        _require_exact_type(parameter, EtradeOAuthNonsecretParameter, "OAuth parameter")
        parameter.__post_init__()
        pairs.append((parameter.name, parameter.value))
    return _normalize_parameter_pairs(tuple(pairs))


class _EtradeOAuthSensitiveText(_EtradeOAuthSealed):
    """Opaque ephemeral text that refuses useful repr, str, and serialization."""

    __slots__ = ("__value",)
    __value: str

    def __init__(self, value: str) -> None:
        if type(value) is not str:
            raise EtradeOAuthContractError("sensitive OAuth material must be exact text")
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise EtradeOAuthContractError(
                "sensitive OAuth material must be valid Unicode"
            ) from exc
        if (
            not encoded
            or len(encoded) > _SENSITIVE_TEXT_MAX_UTF8_BYTES
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        ):
            raise EtradeOAuthContractError(
                "sensitive OAuth material is empty, invalid, or oversized"
            )
        object.__setattr__(self, "_EtradeOAuthSensitiveText__value", value)

    def _validate(self) -> None:
        value = self.__value
        if type(value) is not str:
            raise EtradeOAuthContractError("sealed sensitive OAuth material was corrupted")
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise EtradeOAuthContractError("sealed sensitive OAuth material was corrupted") from exc
        if (
            not encoded
            or len(encoded) > _SENSITIVE_TEXT_MAX_UTF8_BYTES
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        ):
            raise EtradeOAuthContractError("sealed sensitive OAuth material was corrupted")

    def _ephemeral_value(self) -> str:
        self._validate()
        return self.__value

    def __repr__(self) -> str:
        self._validate()
        return f"{type(self).__name__}(<redacted>)"

    def __str__(self) -> str:
        self._validate()
        return "<redacted>"

    def __reduce__(self) -> Never:
        raise TypeError("sensitive OAuth material is intentionally non-serializable")


class EtradeOAuthConsumerKey(_EtradeOAuthSensitiveText):
    """Ephemeral consumer key; excluded from every evidence object and digest."""

    __slots__ = ()


class EtradeOAuthConsumerSecret(_EtradeOAuthSensitiveText):
    """Ephemeral consumer secret; excluded from every evidence object and digest."""

    __slots__ = ()


class EtradeOAuthToken(_EtradeOAuthSensitiveText):
    """Ephemeral request/access token; excluded from every evidence object and digest."""

    __slots__ = ()


class EtradeOAuthTokenSecret(_EtradeOAuthSensitiveText):
    """Ephemeral token secret; excluded from every evidence object and digest."""

    __slots__ = ()


class EtradeOAuthVerifierValue(_EtradeOAuthSensitiveText):
    """Ephemeral OOB verifier; excluded from every evidence object and digest."""

    __slots__ = ()


@dataclass(frozen=True, slots=True)
class EtradeOAuthTrustedTimestamp:
    """Caller-injected timestamp with an upstream, nonsecret trust-evidence identity."""

    unix_seconds: int
    trust_evidence_sha256: str

    def __post_init__(self) -> None:
        if type(self.unix_seconds) is not int or not 1 <= self.unix_seconds < 2**63:
            raise EtradeOAuthContractError("OAuth timestamp must be positive integer Unix seconds")
        _require_sha256(self.trust_evidence_sha256, "trusted-time evidence identity")

    @property
    def wire_value(self) -> str:
        return str(self.unix_seconds)


@dataclass(frozen=True, slots=True)
class EtradeOAuthNonce:
    """Caller-injected unique nonce; raw text stays out of evidence serialization."""

    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.value) is not str or _NONCE_PATTERN.fullmatch(self.value) is None:
            raise EtradeOAuthContractError("OAuth nonce must contain 16-128 safe ASCII characters")

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.value.encode("ascii")).hexdigest()


def _expected_consumer_scope(environment: EtradeEnvironment) -> EtradeSecretScope:
    return (
        EtradeSecretScope.SANDBOX_CONSUMER
        if environment is EtradeEnvironment.SANDBOX
        else EtradeSecretScope.PRODUCTION_CONSUMER
    )


def _expected_token_scope(environment: EtradeEnvironment) -> EtradeSecretScope:
    return (
        EtradeSecretScope.SANDBOX_TOKEN
        if environment is EtradeEnvironment.SANDBOX
        else EtradeSecretScope.PRODUCTION_TOKEN
    )


@dataclass(frozen=True, slots=True)
class EtradeOAuthConsumerSecretReference:
    """Typed nonsecret consumer-secret reference revision, not credential material."""

    environment: EtradeEnvironment
    scope: EtradeSecretScope
    version: int

    def __post_init__(self) -> None:
        _require_exact_type(self.environment, EtradeEnvironment, "consumer reference environment")
        _require_exact_type(self.scope, EtradeSecretScope, "consumer reference scope")
        if self.scope is not _expected_consumer_scope(self.environment):
            raise EtradeOAuthContractError(
                "consumer secret-reference scope conflicts with the typed environment"
            )
        if type(self.version) is not int or self.version < 1:
            raise EtradeOAuthContractError("consumer secret-reference version must be positive")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ETRADE_OAUTH_SESSION_CONTRACT_VERSION,
                "consumer_secret_reference",
                self.environment,
                self.scope,
                self.version,
            )
        )


@dataclass(frozen=True, slots=True)
class EtradeOAuthTokenSecretReference:
    """Typed nonsecret token-secret reference revision, not token material."""

    environment: EtradeEnvironment
    scope: EtradeSecretScope
    kind: EtradeOAuthTokenKind
    version: int

    def __post_init__(self) -> None:
        _require_exact_type(self.environment, EtradeEnvironment, "token reference environment")
        _require_exact_type(self.scope, EtradeSecretScope, "token reference scope")
        _require_exact_type(self.kind, EtradeOAuthTokenKind, "token reference kind")
        if self.scope is not _expected_token_scope(self.environment):
            raise EtradeOAuthContractError(
                "token secret-reference scope conflicts with the typed environment"
            )
        if type(self.version) is not int or self.version < 1:
            raise EtradeOAuthContractError("token secret-reference version must be positive")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ETRADE_OAUTH_SESSION_CONTRACT_VERSION,
                "token_secret_reference",
                self.environment,
                self.scope,
                self.kind,
                self.version,
            )
        )


class EtradeOAuthConsumerCredentials(_EtradeOAuthSealed):
    """Ephemeral reference-bound consumer material with a fully redacted repr."""

    __slots__ = ("__consumer_key", "__consumer_secret", "reference")
    __consumer_key: EtradeOAuthConsumerKey
    __consumer_secret: EtradeOAuthConsumerSecret
    reference: EtradeOAuthConsumerSecretReference

    def __init__(
        self,
        *,
        reference: EtradeOAuthConsumerSecretReference,
        consumer_key: EtradeOAuthConsumerKey,
        consumer_secret: EtradeOAuthConsumerSecret,
    ) -> None:
        _require_exact_type(reference, EtradeOAuthConsumerSecretReference, "consumer reference")
        reference.__post_init__()
        _require_exact_type(consumer_key, EtradeOAuthConsumerKey, "consumer key")
        _require_exact_type(consumer_secret, EtradeOAuthConsumerSecret, "consumer secret")
        object.__setattr__(self, "reference", reference)
        object.__setattr__(
            self,
            "_EtradeOAuthConsumerCredentials__consumer_key",
            consumer_key,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthConsumerCredentials__consumer_secret",
            consumer_secret,
        )
        self._validate()

    def _validate(self) -> None:
        _require_exact_type(
            self.reference,
            EtradeOAuthConsumerSecretReference,
            "consumer reference",
        )
        self.reference.__post_init__()
        _require_exact_type(self.__consumer_key, EtradeOAuthConsumerKey, "consumer key")
        _require_exact_type(
            self.__consumer_secret,
            EtradeOAuthConsumerSecret,
            "consumer secret",
        )
        self.__consumer_key._validate()
        self.__consumer_secret._validate()

    def _ephemeral_values(self) -> tuple[str, str]:
        self._validate()
        return (
            self.__consumer_key._ephemeral_value(),
            self.__consumer_secret._ephemeral_value(),
        )

    def __repr__(self) -> str:
        self._validate()
        return (
            "EtradeOAuthConsumerCredentials("
            f"reference={self.reference!r}, consumer_key=<redacted>, consumer_secret=<redacted>)"
        )

    def __reduce__(self) -> Never:
        raise TypeError("ephemeral OAuth credentials are intentionally non-serializable")


class EtradeOAuthTokenCredentials(_EtradeOAuthSealed):
    """Ephemeral reference-bound token material with a fully redacted repr."""

    __slots__ = ("__token", "__token_secret", "reference")
    __token: EtradeOAuthToken
    __token_secret: EtradeOAuthTokenSecret
    reference: EtradeOAuthTokenSecretReference

    def __init__(
        self,
        *,
        reference: EtradeOAuthTokenSecretReference,
        token: EtradeOAuthToken,
        token_secret: EtradeOAuthTokenSecret,
    ) -> None:
        _require_exact_type(reference, EtradeOAuthTokenSecretReference, "token reference")
        reference.__post_init__()
        _require_exact_type(token, EtradeOAuthToken, "OAuth token")
        _require_exact_type(token_secret, EtradeOAuthTokenSecret, "OAuth token secret")
        object.__setattr__(self, "reference", reference)
        object.__setattr__(self, "_EtradeOAuthTokenCredentials__token", token)
        object.__setattr__(
            self,
            "_EtradeOAuthTokenCredentials__token_secret",
            token_secret,
        )
        self._validate()

    def _validate(self) -> None:
        _require_exact_type(
            self.reference,
            EtradeOAuthTokenSecretReference,
            "token reference",
        )
        self.reference.__post_init__()
        _require_exact_type(self.__token, EtradeOAuthToken, "OAuth token")
        _require_exact_type(self.__token_secret, EtradeOAuthTokenSecret, "OAuth token secret")
        self.__token._validate()
        self.__token_secret._validate()

    def _ephemeral_values(self) -> tuple[str, str]:
        self._validate()
        return self.__token._ephemeral_value(), self.__token_secret._ephemeral_value()

    def __repr__(self) -> str:
        self._validate()
        return (
            "EtradeOAuthTokenCredentials("
            f"reference={self.reference!r}, token=<redacted>, token_secret=<redacted>)"
        )

    def __reduce__(self) -> Never:
        raise TypeError("ephemeral OAuth credentials are intentionally non-serializable")


class EtradeOAuthBoundVerifier(_EtradeOAuthSealed):
    """One authorization-challenge-bound ephemeral OOB verifier."""

    __slots__ = ("__verifier", "authorization_challenge_sha256")
    __verifier: EtradeOAuthVerifierValue
    authorization_challenge_sha256: str

    def __init__(
        self,
        *,
        authorization_challenge_sha256: str,
        verifier: EtradeOAuthVerifierValue,
    ) -> None:
        object.__setattr__(
            self,
            "authorization_challenge_sha256",
            _require_sha256(
                authorization_challenge_sha256,
                "authorization challenge identity",
            ),
        )
        _require_exact_type(verifier, EtradeOAuthVerifierValue, "OAuth verifier")
        object.__setattr__(self, "_EtradeOAuthBoundVerifier__verifier", verifier)
        self._validate()

    def _validate(self) -> None:
        _require_sha256(
            self.authorization_challenge_sha256,
            "authorization challenge identity",
        )
        _require_exact_type(self.__verifier, EtradeOAuthVerifierValue, "OAuth verifier")
        self.__verifier._validate()

    def _ephemeral_value(self) -> str:
        self._validate()
        return self.__verifier._ephemeral_value()

    def __repr__(self) -> str:
        self._validate()
        return (
            "EtradeOAuthBoundVerifier("
            f"authorization_challenge_sha256={self.authorization_challenge_sha256!r}, "
            "verifier=<redacted>)"
        )

    def __reduce__(self) -> Never:
        raise TypeError("ephemeral OAuth verifier is intentionally non-serializable")


_OPERATION_ENDPOINTS: Mapping[EtradeOAuthOperation, str] = MappingProxyType(
    {
        EtradeOAuthOperation.REQUEST_TOKEN: ETRADE_SHARED_REQUEST_TOKEN_URL,
        EtradeOAuthOperation.ACCESS_TOKEN: ETRADE_SHARED_ACCESS_TOKEN_URL,
        EtradeOAuthOperation.RENEW_ACCESS_TOKEN: ETRADE_SHARED_RENEW_ACCESS_TOKEN_URL,
        EtradeOAuthOperation.REVOKE_ACCESS_TOKEN: ETRADE_SHARED_REVOKE_ACCESS_TOKEN_URL,
    }
)

_OPERATION_TOKEN_KINDS: Mapping[EtradeOAuthOperation, EtradeOAuthTokenKind | None] = (
    MappingProxyType(
        {
            EtradeOAuthOperation.REQUEST_TOKEN: None,
            EtradeOAuthOperation.ACCESS_TOKEN: EtradeOAuthTokenKind.REQUEST_TOKEN,
            EtradeOAuthOperation.RENEW_ACCESS_TOKEN: EtradeOAuthTokenKind.ACCESS_TOKEN,
            EtradeOAuthOperation.REVOKE_ACCESS_TOKEN: EtradeOAuthTokenKind.ACCESS_TOKEN,
        }
    )
)


@dataclass(frozen=True, slots=True)
class EtradeOAuthSigningIntent:
    """Sanitized exact request identity; it contains no secret signing material."""

    provider: EtradeProviderIdentity
    environment: EtradeEnvironment
    endpoint_profile: EtradeEndpointIsolationProfile
    operation: EtradeOAuthOperation
    generation: int
    consumer_reference: EtradeOAuthConsumerSecretReference
    token_reference: EtradeOAuthTokenSecretReference | None
    timestamp: EtradeOAuthTrustedTimestamp
    nonce: EtradeOAuthNonce
    authorization_challenge_sha256: str | None = None
    authorization_state_sha256: str | None = None
    callback_policy: EtradeOAuthCallbackPolicy = ETRADE_OUT_OF_BAND_CALLBACK_POLICY
    http_method: str = ETRADE_OAUTH_HTTP_METHOD
    endpoint_url: str = ""
    extra_parameters: tuple[EtradeOAuthNonsecretParameter, ...] = ()

    def __post_init__(self) -> None:
        _require_exact_type(self.provider, EtradeProviderIdentity, "signing provider")
        self.provider.__post_init__()
        if self.provider is not ETRADE_PROVIDER:
            raise EtradeOAuthContractError(
                "OAuth signing provider must be the canonical E*TRADE value"
            )
        _require_exact_type(self.environment, EtradeEnvironment, "signing environment")
        _require_exact_type(
            self.endpoint_profile, EtradeEndpointIsolationProfile, "endpoint profile"
        )
        self.endpoint_profile.__post_init__()
        if self.endpoint_profile.environment is not self.environment:
            raise EtradeOAuthContractError("OAuth endpoint profile conflicts with the environment")
        _require_exact_type(self.operation, EtradeOAuthOperation, "OAuth operation")
        if type(self.generation) is not int or self.generation < 1:
            raise EtradeOAuthContractError("OAuth signing generation must be positive")
        _require_exact_type(
            self.consumer_reference,
            EtradeOAuthConsumerSecretReference,
            "consumer secret reference",
        )
        self.consumer_reference.__post_init__()
        if self.consumer_reference.environment is not self.environment or (
            self.consumer_reference.scope is not self.endpoint_profile.consumer_secret_scope
        ):
            raise EtradeOAuthContractError(
                "OAuth consumer reference conflicts with the environment"
            )
        _require_exact_type(self.timestamp, EtradeOAuthTrustedTimestamp, "OAuth timestamp")
        self.timestamp.__post_init__()
        _require_exact_type(self.nonce, EtradeOAuthNonce, "OAuth nonce")
        self.nonce.__post_init__()
        _require_exact_type(
            self.callback_policy, EtradeOAuthCallbackPolicy, "OAuth callback policy"
        )
        self.callback_policy.__post_init__()
        if self.callback_policy != self.endpoint_profile.callback_policy or (
            self.callback_policy != ETRADE_OUT_OF_BAND_CALLBACK_POLICY
        ):
            raise EtradeOAuthContractError("OAuth callback policy drifted from exact OOB metadata")
        if type(self.http_method) is not str or self.http_method != ETRADE_OAUTH_HTTP_METHOD:
            raise EtradeOAuthContractError(
                "E*TRADE OAuth token-control method must remain exact GET"
            )
        expected_endpoint = _OPERATION_ENDPOINTS[self.operation]
        if type(self.endpoint_url) is not str or self.endpoint_url != expected_endpoint:
            raise EtradeOAuthContractError(
                "E*TRADE OAuth endpoint does not match the exact operation"
            )
        if type(self.extra_parameters) is not tuple or self.extra_parameters:
            raise EtradeOAuthContractError(
                "E*TRADE OAuth token-control endpoints accept no caller parameters"
            )
        expected_token_kind = _OPERATION_TOKEN_KINDS[self.operation]
        if expected_token_kind is None:
            if self.token_reference is not None:
                raise EtradeOAuthContractError(
                    "request-token signing cannot retain a token reference"
                )
        else:
            _require_exact_type(
                self.token_reference,
                EtradeOAuthTokenSecretReference,
                "token secret reference",
            )
            token_reference = cast(EtradeOAuthTokenSecretReference, self.token_reference)
            token_reference.__post_init__()
            if (
                token_reference.environment is not self.environment
                or token_reference.scope is not self.endpoint_profile.token_secret_scope
                or token_reference.kind is not expected_token_kind
            ):
                raise EtradeOAuthContractError(
                    "OAuth token reference conflicts with operation or environment"
                )
        if self.operation is EtradeOAuthOperation.ACCESS_TOKEN:
            _require_sha256(
                self.authorization_challenge_sha256,
                "authorization challenge identity",
            )
            _require_sha256(
                self.authorization_state_sha256,
                "confirmed authorization state identity",
            )
        elif (
            self.authorization_challenge_sha256 is not None
            or self.authorization_state_sha256 is not None
        ):
            raise EtradeOAuthContractError("only access-token signing can bind authorization state")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ETRADE_OAUTH_SESSION_CONTRACT_VERSION,
                "sanitized_signing_intent",
                self.provider.value,
                self.environment,
                self.endpoint_profile.semantic_sha256,
                self.operation,
                self.generation,
                self.http_method,
                self.endpoint_url,
                self.consumer_reference.semantic_sha256,
                None if self.token_reference is None else self.token_reference.semantic_sha256,
                self.timestamp.unix_seconds,
                self.timestamp.trust_evidence_sha256,
                self.nonce.sha256,
                self.authorization_challenge_sha256,
                self.authorization_state_sha256,
                self.callback_policy.semantic_sha256,
            )
        )

    def to_evidence_bytes(self) -> bytes:
        """Serialize only nonsecret signing intent metadata."""

        return json.dumps(
            {
                "authorization_challenge_sha256": self.authorization_challenge_sha256,
                "authorization_state_sha256": self.authorization_state_sha256,
                "callback_mode": self.callback_policy.mode.value,
                "consumer_reference_sha256": self.consumer_reference.semantic_sha256,
                "consumer_reference_version": self.consumer_reference.version,
                "contract_version": ETRADE_OAUTH_SESSION_CONTRACT_VERSION,
                "endpoint_url": self.endpoint_url,
                "environment": self.environment.value,
                "generation": self.generation,
                "http_method": self.http_method,
                "nonce_sha256": self.nonce.sha256,
                "operation": self.operation.value,
                "provider_id": self.provider.value,
                "semantic_sha256": self.semantic_sha256,
                "timestamp_seconds": self.timestamp.unix_seconds,
                "token_reference_sha256": (
                    None if self.token_reference is None else self.token_reference.semantic_sha256
                ),
                "token_reference_version": (
                    None if self.token_reference is None else self.token_reference.version
                ),
                "trusted_time_evidence_sha256": self.timestamp.trust_evidence_sha256,
            },
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @property
    def authority(self) -> Mapping[str, bool]:
        return MappingProxyType({name: False for name in _AUTHORITY_FIELDS})


def create_etrade_oauth_signing_intent(
    *,
    environment: EtradeEnvironment,
    endpoint_profile: EtradeEndpointIsolationProfile,
    operation: EtradeOAuthOperation,
    generation: int,
    consumer_reference: EtradeOAuthConsumerSecretReference,
    token_reference: EtradeOAuthTokenSecretReference | None,
    timestamp: EtradeOAuthTrustedTimestamp,
    nonce: EtradeOAuthNonce,
    authorization_challenge_sha256: str | None = None,
    authorization_state_sha256: str | None = None,
) -> EtradeOAuthSigningIntent:
    """Build one exact OAuth intent without resolving secrets or performing I/O."""

    _require_exact_type(operation, EtradeOAuthOperation, "OAuth operation")
    return EtradeOAuthSigningIntent(
        provider=ETRADE_PROVIDER,
        environment=environment,
        endpoint_profile=endpoint_profile,
        operation=operation,
        generation=generation,
        consumer_reference=consumer_reference,
        token_reference=token_reference,
        timestamp=timestamp,
        nonce=nonce,
        authorization_challenge_sha256=authorization_challenge_sha256,
        authorization_state_sha256=authorization_state_sha256,
        endpoint_url=_OPERATION_ENDPOINTS[operation],
    )


@dataclass(frozen=True, slots=True)
class EtradeOAuthSigningTimeHighWater:
    """Latest generation and signing timestamp for one sanitized OAuth scope."""

    scope_sha256: str
    generation: int
    unix_seconds: int

    def __post_init__(self) -> None:
        _require_sha256(self.scope_sha256, "OAuth signing-time scope identity")
        if type(self.generation) is not int or self.generation < 1:
            raise EtradeOAuthContractError("OAuth signing-time generation must be positive")
        if type(self.unix_seconds) is not int or not 1 <= self.unix_seconds < 2**63:
            raise EtradeOAuthContractError(
                "OAuth signing-time high-water must be positive Unix seconds"
            )


@dataclass(frozen=True, slots=True)
class EtradeOAuthReplayGuard:
    """Pure bounded replay memory; it is explicitly not durable replay protection."""

    consumed_fingerprints: tuple[str, ...] = ()
    signing_time_high_waters: tuple[EtradeOAuthSigningTimeHighWater, ...] = ()

    def __post_init__(self) -> None:
        if type(self.consumed_fingerprints) is not tuple or (
            len(self.consumed_fingerprints) > ETRADE_OAUTH_REPLAY_GUARD_MAX_FINGERPRINTS
        ):
            raise EtradeOAuthContractError("OAuth replay guard is malformed or over capacity")
        seen: set[str] = set()
        for fingerprint in self.consumed_fingerprints:
            _require_sha256(fingerprint, "OAuth replay fingerprint")
            if fingerprint in seen:
                raise EtradeOAuthContractError("OAuth replay guard contains duplicate fingerprints")
            seen.add(fingerprint)
        if type(self.signing_time_high_waters) is not tuple or (
            len(self.signing_time_high_waters) > ETRADE_OAUTH_REPLAY_GUARD_MAX_FINGERPRINTS
        ):
            raise EtradeOAuthContractError(
                "OAuth signing-time high-water set is malformed or over capacity"
            )
        scopes: set[str] = set()
        for high_water in self.signing_time_high_waters:
            _require_exact_type(
                high_water,
                EtradeOAuthSigningTimeHighWater,
                "OAuth signing-time high-water",
            )
            high_water.__post_init__()
            if high_water.scope_sha256 in scopes:
                raise EtradeOAuthContractError(
                    "OAuth replay guard contains duplicate signing-time scopes"
                )
            scopes.add(high_water.scope_sha256)
        if (
            tuple(sorted(self.signing_time_high_waters, key=lambda value: value.scope_sha256))
            != self.signing_time_high_waters
        ):
            raise EtradeOAuthContractError("OAuth signing-time high-water scopes must be canonical")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ETRADE_OAUTH_SESSION_CONTRACT_VERSION,
                "oauth_replay_guard",
                self.consumed_fingerprints,
                tuple(
                    (entry.scope_sha256, entry.generation, entry.unix_seconds)
                    for entry in self.signing_time_high_waters
                ),
            )
        )

    @property
    def durable_replay_protection_authorized(self) -> bool:
        return False


def _replay_fingerprint(intent: EtradeOAuthSigningIntent) -> str:
    return _semantic_sha256(
        (
            ETRADE_OAUTH_SESSION_CONTRACT_VERSION,
            "nonce_replay_fingerprint",
            intent.environment,
            intent.consumer_reference.semantic_sha256,
            intent.timestamp.unix_seconds,
            intent.nonce.sha256,
        )
    )


def _signing_scope_sha256(intent: EtradeOAuthSigningIntent) -> str:
    return _semantic_sha256(
        (
            ETRADE_OAUTH_SESSION_CONTRACT_VERSION,
            "signing_time_scope",
            intent.provider.value,
            intent.environment,
            intent.endpoint_profile.semantic_sha256,
            intent.consumer_reference.semantic_sha256,
        )
    )


def _consume_replay_fingerprint(
    replay_guard: EtradeOAuthReplayGuard,
    fingerprint: str,
) -> EtradeOAuthReplayGuard:
    _require_exact_type(replay_guard, EtradeOAuthReplayGuard, "OAuth replay guard")
    replay_guard.__post_init__()
    _require_sha256(fingerprint, "OAuth replay fingerprint")
    if fingerprint in replay_guard.consumed_fingerprints:
        raise EtradeOAuthContractError("OAuth replay was rejected")
    if len(replay_guard.consumed_fingerprints) >= ETRADE_OAUTH_REPLAY_GUARD_MAX_FINGERPRINTS:
        raise EtradeOAuthContractError("OAuth replay guard requires supervised rotation")
    return EtradeOAuthReplayGuard(
        consumed_fingerprints=(*replay_guard.consumed_fingerprints, fingerprint),
        signing_time_high_waters=replay_guard.signing_time_high_waters,
    )


def _consume_signing_intent(
    replay_guard: EtradeOAuthReplayGuard,
    intent: EtradeOAuthSigningIntent,
) -> EtradeOAuthReplayGuard:
    """Consume one signing intent and advance its scope/generation time high-water."""

    _require_exact_type(replay_guard, EtradeOAuthReplayGuard, "OAuth replay guard")
    replay_guard.__post_init__()
    intent.__post_init__()
    fingerprint = _replay_fingerprint(intent)
    if fingerprint in replay_guard.consumed_fingerprints:
        raise EtradeOAuthContractError("OAuth replay was rejected")
    if len(replay_guard.consumed_fingerprints) >= ETRADE_OAUTH_REPLAY_GUARD_MAX_FINGERPRINTS:
        raise EtradeOAuthContractError("OAuth replay guard requires supervised rotation")

    scope_sha256 = _signing_scope_sha256(intent)
    high_waters = list(replay_guard.signing_time_high_waters)
    matching_index: int | None = None
    for index, high_water in enumerate(high_waters):
        if high_water.scope_sha256 != scope_sha256:
            continue
        matching_index = index
        if intent.generation < high_water.generation:
            raise EtradeOAuthContractError("OAuth signing generation cannot regress")
        if intent.timestamp.unix_seconds < high_water.unix_seconds:
            raise EtradeOAuthContractError("OAuth signing time cannot regress")
        break
    advanced = EtradeOAuthSigningTimeHighWater(
        scope_sha256=scope_sha256,
        generation=intent.generation,
        unix_seconds=intent.timestamp.unix_seconds,
    )
    if matching_index is None:
        high_waters.append(advanced)
    else:
        high_waters[matching_index] = advanced
    high_waters.sort(key=lambda value: value.scope_sha256)
    return EtradeOAuthReplayGuard(
        consumed_fingerprints=(*replay_guard.consumed_fingerprints, fingerprint),
        signing_time_high_waters=tuple(high_waters),
    )


def reserve_etrade_oauth_signing_intent(
    intent: EtradeOAuthSigningIntent,
    *,
    replay_guard: EtradeOAuthReplayGuard,
) -> EtradeOAuthReplayGuard:
    """Purely derive the exact secret-independent replay state for one intent."""

    _require_exact_type(intent, EtradeOAuthSigningIntent, "OAuth signing intent")
    intent.__post_init__()
    return _consume_signing_intent(replay_guard, intent)


class EtradeOAuthEphemeralSigningResult(_EtradeOAuthSealed):
    """Redacted signature/header result plus sanitized evidence and next replay state."""

    __slots__ = (
        "__authorization_header",
        "__evidence_sha256",
        "__intent_sha256",
        "__replay_guard_sha256",
        "__signature",
        "intent",
        "next_replay_guard",
        "sanitized_evidence_bytes",
    )
    __authorization_header: str
    __evidence_sha256: str
    __intent_sha256: str
    __replay_guard_sha256: str
    __signature: str
    intent: EtradeOAuthSigningIntent
    next_replay_guard: EtradeOAuthReplayGuard
    sanitized_evidence_bytes: bytes

    def __init__(
        self,
        *,
        intent: EtradeOAuthSigningIntent,
        signature: str,
        authorization_header: str,
        next_replay_guard: EtradeOAuthReplayGuard,
    ) -> None:
        _require_exact_type(intent, EtradeOAuthSigningIntent, "OAuth signing result intent")
        intent.__post_init__()
        _require_exact_type(
            next_replay_guard,
            EtradeOAuthReplayGuard,
            "OAuth signing result replay guard",
        )
        next_replay_guard.__post_init__()
        evidence = intent.to_evidence_bytes()
        object.__setattr__(self, "intent", intent)
        object.__setattr__(self, "_EtradeOAuthEphemeralSigningResult__signature", signature)
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralSigningResult__authorization_header",
            authorization_header,
        )
        object.__setattr__(self, "next_replay_guard", next_replay_guard)
        object.__setattr__(self, "sanitized_evidence_bytes", evidence)
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralSigningResult__intent_sha256",
            intent.semantic_sha256,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralSigningResult__replay_guard_sha256",
            next_replay_guard.semantic_sha256,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralSigningResult__evidence_sha256",
            hashlib.sha256(evidence).hexdigest(),
        )
        self._validate()

    def _validate(self) -> None:
        _require_exact_type(self.intent, EtradeOAuthSigningIntent, "OAuth signing result intent")
        self.intent.__post_init__()
        if self.intent.semantic_sha256 != self.__intent_sha256:
            raise EtradeOAuthContractError("sealed OAuth signing result intent was mutated")
        _require_exact_type(
            self.next_replay_guard,
            EtradeOAuthReplayGuard,
            "OAuth signing result replay guard",
        )
        self.next_replay_guard.__post_init__()
        if self.next_replay_guard.semantic_sha256 != self.__replay_guard_sha256:
            raise EtradeOAuthContractError("sealed OAuth signing replay guard was mutated")
        if (
            type(self.sanitized_evidence_bytes) is not bytes
            or hashlib.sha256(self.sanitized_evidence_bytes).hexdigest() != self.__evidence_sha256
            or self.sanitized_evidence_bytes != self.intent.to_evidence_bytes()
        ):
            raise EtradeOAuthContractError("sealed OAuth signing evidence was mutated")
        if (
            type(self.__signature) is not str
            or re.fullmatch(r"[A-Za-z0-9+/]{27}=", self.__signature) is None
            or type(self.__authorization_header) is not str
            or not self.__authorization_header.startswith("OAuth ")
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in self.__authorization_header
            )
        ):
            raise EtradeOAuthContractError("sealed OAuth signing output was corrupted")

    def signature_matches(self, expected: str) -> bool:
        self._validate()
        if type(expected) is not str:
            return False
        return hmac.compare_digest(self.__signature, expected)

    def authorization_header_matches(self, expected: str) -> bool:
        self._validate()
        if type(expected) is not str:
            return False
        return hmac.compare_digest(self.__authorization_header, expected)

    @property
    def authority(self) -> Mapping[str, bool]:
        self._validate()
        return MappingProxyType({name: False for name in _AUTHORITY_FIELDS})

    def __repr__(self) -> str:
        self._validate()
        return (
            "EtradeOAuthEphemeralSigningResult("
            f"intent_sha256={self.intent.semantic_sha256!r}, signature=<redacted>, "
            "authorization_header=<redacted>)"
        )

    def __reduce__(self) -> Never:
        raise TypeError("ephemeral OAuth signing output is intentionally non-serializable")


def sign_etrade_oauth_intent(
    intent: EtradeOAuthSigningIntent,
    *,
    replay_guard: EtradeOAuthReplayGuard,
    consumer_credentials: EtradeOAuthConsumerCredentials,
    token_credentials: EtradeOAuthTokenCredentials | None = None,
    verifier: EtradeOAuthBoundVerifier | None = None,
    access_exchange_capability: EtradeOAuthAccessExchangeCapability | None = None,
    _access_exchange_runtime_reservation: object | None = None,
) -> EtradeOAuthEphemeralSigningResult:
    """Sign once while consuming replay time and any exact access-exchange capability."""

    _require_exact_type(intent, EtradeOAuthSigningIntent, "OAuth signing intent")
    intent.__post_init__()
    _require_exact_type(
        consumer_credentials,
        EtradeOAuthConsumerCredentials,
        "consumer credentials",
    )
    consumer_credentials._validate()
    if consumer_credentials.reference != intent.consumer_reference:
        raise EtradeOAuthContractError("consumer credentials do not match the signing intent")

    expected_token_kind = _OPERATION_TOKEN_KINDS[intent.operation]
    if expected_token_kind is None:
        if token_credentials is not None:
            raise EtradeOAuthContractError("request-token signing cannot accept token credentials")
    else:
        _require_exact_type(token_credentials, EtradeOAuthTokenCredentials, "token credentials")
        bound_token_credentials = cast(EtradeOAuthTokenCredentials, token_credentials)
        bound_token_credentials._validate()
        if bound_token_credentials.reference != intent.token_reference:
            raise EtradeOAuthContractError("token credentials do not match the signing intent")

    if intent.operation is EtradeOAuthOperation.ACCESS_TOKEN:
        _require_exact_type(verifier, EtradeOAuthBoundVerifier, "bound OAuth verifier")
        bound_verifier = cast(EtradeOAuthBoundVerifier, verifier)
        bound_verifier._validate()
        _require_exact_type(
            access_exchange_capability,
            EtradeOAuthAccessExchangeCapability,
            "access-exchange capability",
        )
        bound_capability = cast(
            EtradeOAuthAccessExchangeCapability,
            access_exchange_capability,
        )
    elif (
        verifier is not None
        or access_exchange_capability is not None
        or _access_exchange_runtime_reservation is not None
    ):
        raise EtradeOAuthContractError("only access-token signing can accept a verifier capability")

    next_guard = reserve_etrade_oauth_signing_intent(intent, replay_guard=replay_guard)

    verifier_value = ""
    if intent.operation is EtradeOAuthOperation.ACCESS_TOKEN:
        verifier_value = bound_capability._consume_for(
            intent=intent,
            verifier=bound_verifier,
            runtime_reservation=_access_exchange_runtime_reservation,
        )

    consumer_key, consumer_secret = consumer_credentials._ephemeral_values()
    token = ""
    token_secret = ""
    if token_credentials is not None:
        token, token_secret = token_credentials._ephemeral_values()

    parameters: list[tuple[str, str]] = [
        ("oauth_consumer_key", consumer_key),
        ("oauth_nonce", intent.nonce.value),
        ("oauth_signature_method", ETRADE_OAUTH_SIGNATURE_METHOD),
        ("oauth_timestamp", intent.timestamp.wire_value),
        ("oauth_version", ETRADE_OAUTH_PROTOCOL_VERSION),
    ]
    if intent.operation is EtradeOAuthOperation.REQUEST_TOKEN:
        parameters.append(("oauth_callback", intent.callback_policy.oauth_callback_parameter))
    else:
        parameters.append(("oauth_token", token))
    if intent.operation is EtradeOAuthOperation.ACCESS_TOKEN:
        parameters.append(("oauth_verifier", verifier_value))

    normalized_parameters = _normalize_parameter_pairs(tuple(parameters))
    signature_base_string = "&".join(
        (
            intent.http_method,
            etrade_oauth_percent_encode(intent.endpoint_url),
            etrade_oauth_percent_encode(normalized_parameters),
        )
    )
    signing_key = "&".join(
        (
            etrade_oauth_percent_encode(consumer_secret),
            etrade_oauth_percent_encode(token_secret),
        )
    )
    signature = base64.b64encode(
        hmac.new(
            signing_key.encode("ascii"),
            signature_base_string.encode("ascii"),
            hashlib.sha1,
        ).digest()
    ).decode("ascii")
    header_parameters = [*parameters, ("oauth_signature", signature)]
    header_parameters.sort(key=lambda item: item[0])
    authorization_header = "OAuth " + ", ".join(
        f'{etrade_oauth_percent_encode(name)}="{etrade_oauth_percent_encode(value)}"'
        for name, value in header_parameters
    )
    return EtradeOAuthEphemeralSigningResult(
        intent=intent,
        signature=signature,
        authorization_header=authorization_header,
        next_replay_guard=next_guard,
    )


@dataclass(frozen=True, slots=True)
class EtradeOAuthSessionState:
    """Sanitized pure session state; transitions are not provider-origin evidence."""

    provider: EtradeProviderIdentity
    environment: EtradeEnvironment
    endpoint_profile_sha256: str
    consumer_reference: EtradeOAuthConsumerSecretReference
    phase: EtradeOAuthSessionPhase
    generation: int
    renewal_count: int
    highest_token_reference_version: int
    trusted_time_high_water_seconds: int
    transition_evidence_sha256: str | None = None
    request_token_reference: EtradeOAuthTokenSecretReference | None = None
    access_token_reference: EtradeOAuthTokenSecretReference | None = None
    request_token_intent_sha256: str | None = None
    authorization_challenge_sha256: str | None = None
    access_token_intent_sha256: str | None = None
    issued_at_seconds: int | None = None
    last_activity_at_seconds: int | None = None
    last_observed_at_seconds: int | None = None
    expires_at_seconds: int | None = None
    reauthorization_reason: EtradeOAuthReauthorizationReason | None = None
    predecessor_sha256: str | None = None
    provider_origin_authenticated: bool = False
    credential_resolution_authorized: bool = False
    provider_network_authorized: bool = False
    persistence_authorized: bool = False
    account_binding_authorized: bool = False
    broker_call_authorized: bool = False
    trading_effect_authorized: bool = False

    def __post_init__(self) -> None:
        _require_exact_type(self.provider, EtradeProviderIdentity, "session provider")
        self.provider.__post_init__()
        if self.provider is not ETRADE_PROVIDER:
            raise EtradeOAuthContractError("OAuth session provider must be canonical E*TRADE")
        _require_exact_type(self.environment, EtradeEnvironment, "session environment")
        _require_sha256(self.endpoint_profile_sha256, "endpoint profile identity")
        _require_exact_type(
            self.consumer_reference,
            EtradeOAuthConsumerSecretReference,
            "consumer reference",
        )
        self.consumer_reference.__post_init__()
        if self.consumer_reference.environment is not self.environment:
            raise EtradeOAuthContractError("session consumer reference conflicts with environment")
        _require_exact_type(self.phase, EtradeOAuthSessionPhase, "session phase")
        if type(self.generation) is not int or self.generation < 1:
            raise EtradeOAuthContractError("OAuth session generation must be positive")
        if type(self.renewal_count) is not int or self.renewal_count < 0:
            raise EtradeOAuthContractError("OAuth session renewal count must be nonnegative")
        if (
            type(self.highest_token_reference_version) is not int
            or self.highest_token_reference_version < 0
        ):
            raise EtradeOAuthContractError("highest token reference version must be nonnegative")
        if (
            type(self.trusted_time_high_water_seconds) is not int
            or self.trusted_time_high_water_seconds < 0
        ):
            raise EtradeOAuthContractError("trusted-time high-water must be nonnegative")
        for field_name in (
            "provider_origin_authenticated",
            "credential_resolution_authorized",
            "provider_network_authorized",
            "persistence_authorized",
            "account_binding_authorized",
            "broker_call_authorized",
            "trading_effect_authorized",
        ):
            _require_exact_bool_false(getattr(self, field_name), field_name)
        if self.predecessor_sha256 is not None:
            _require_sha256(self.predecessor_sha256, "session predecessor identity")
        for digest_name in (
            "transition_evidence_sha256",
            "request_token_intent_sha256",
            "authorization_challenge_sha256",
            "access_token_intent_sha256",
        ):
            digest = getattr(self, digest_name)
            if digest is not None:
                _require_sha256(digest, digest_name)
        for reference_name in ("request_token_reference", "access_token_reference"):
            reference = getattr(self, reference_name)
            if reference is not None:
                _require_exact_type(reference, EtradeOAuthTokenSecretReference, reference_name)
                reference.__post_init__()
                if reference.environment is not self.environment:
                    raise EtradeOAuthContractError(
                        f"{reference_name} conflicts with the session environment"
                    )
                if reference.version > self.highest_token_reference_version:
                    raise EtradeOAuthContractError(
                        f"{reference_name} exceeds the recorded reference-version high-water mark"
                    )
        for time_name in (
            "issued_at_seconds",
            "last_activity_at_seconds",
            "last_observed_at_seconds",
            "expires_at_seconds",
        ):
            value = getattr(self, time_name)
            if value is not None and (type(value) is not int or not 1 <= value < 2**63):
                raise EtradeOAuthContractError(f"{time_name} must be positive integer Unix seconds")
        if self.reauthorization_reason is not None:
            _require_exact_type(
                self.reauthorization_reason,
                EtradeOAuthReauthorizationReason,
                "reauthorization reason",
            )
        self._validate_phase_shape()

    def _validate_phase_shape(self) -> None:
        request_phases = {
            EtradeOAuthSessionPhase.REQUEST_TOKEN_RECEIVED,
            EtradeOAuthSessionPhase.AUTHORIZATION_PENDING,
            EtradeOAuthSessionPhase.AUTHORIZATION_CONFIRMED,
        }
        access_phases = {
            EtradeOAuthSessionPhase.ACCESS_TOKEN_ACTIVE,
            EtradeOAuthSessionPhase.ACCESS_TOKEN_INACTIVE,
            EtradeOAuthSessionPhase.ACCESS_TOKEN_EXPIRED,
            EtradeOAuthSessionPhase.ACCESS_TOKEN_REVOKED,
        }
        if self.phase is EtradeOAuthSessionPhase.NEEDS_REQUEST_TOKEN:
            if any(
                value is not None
                for value in (
                    self.request_token_reference,
                    self.access_token_reference,
                    self.request_token_intent_sha256,
                    self.authorization_challenge_sha256,
                    self.access_token_intent_sha256,
                    self.issued_at_seconds,
                    self.last_activity_at_seconds,
                    self.last_observed_at_seconds,
                    self.expires_at_seconds,
                    self.reauthorization_reason,
                )
            ):
                raise EtradeOAuthContractError("needs-request-token state retained lifecycle data")
            if (
                self.renewal_count != 0
                or (
                    self.generation == 1
                    and (
                        self.highest_token_reference_version != 0
                        or self.trusted_time_high_water_seconds != 0
                        or self.transition_evidence_sha256 is not None
                        or self.predecessor_sha256 is not None
                    )
                )
                or (
                    self.generation > 1
                    and (
                        self.highest_token_reference_version < 1
                        or self.trusted_time_high_water_seconds < 1
                        or self.transition_evidence_sha256 is None
                        or self.predecessor_sha256 is None
                    )
                )
            ):
                raise EtradeOAuthContractError("needs-request-token generation evidence is invalid")
        elif self.phase in request_phases:
            if (
                self.request_token_reference is None
                or self.request_token_reference.kind is not EtradeOAuthTokenKind.REQUEST_TOKEN
                or self.request_token_reference.version != self.highest_token_reference_version
                or self.request_token_intent_sha256 is None
                or self.access_token_reference is not None
                or self.access_token_intent_sha256 is not None
                or self.renewal_count != 0
                or self.reauthorization_reason is not None
                or self.trusted_time_high_water_seconds < 1
                or self.transition_evidence_sha256 is None
                or self.predecessor_sha256 is None
                or any(
                    value is not None
                    for value in (
                        self.issued_at_seconds,
                        self.last_activity_at_seconds,
                        self.last_observed_at_seconds,
                        self.expires_at_seconds,
                    )
                )
            ):
                raise EtradeOAuthContractError("request-token session state is incomplete")
            if self.phase is EtradeOAuthSessionPhase.REQUEST_TOKEN_RECEIVED:
                if self.authorization_challenge_sha256 is not None:
                    raise EtradeOAuthContractError(
                        "request-token state cannot retain authorization"
                    )
            elif self.authorization_challenge_sha256 is None:
                raise EtradeOAuthContractError("authorization state lacks a challenge identity")
        elif self.phase in access_phases or (
            self.phase is EtradeOAuthSessionPhase.REAUTHORIZATION_REQUIRED
        ):
            if (
                self.request_token_reference is not None
                or self.access_token_reference is None
                or self.access_token_reference.kind is not EtradeOAuthTokenKind.ACCESS_TOKEN
                or self.access_token_reference.version != self.highest_token_reference_version
                or self.request_token_intent_sha256 is None
                or self.authorization_challenge_sha256 is None
                or self.access_token_intent_sha256 is None
                or self.transition_evidence_sha256 is None
                or self.predecessor_sha256 is None
                or None
                in (
                    self.issued_at_seconds,
                    self.last_activity_at_seconds,
                    self.last_observed_at_seconds,
                    self.expires_at_seconds,
                )
            ):
                raise EtradeOAuthContractError("access-token session state is incomplete")
            issued = cast(int, self.issued_at_seconds)
            activity = cast(int, self.last_activity_at_seconds)
            observed = cast(int, self.last_observed_at_seconds)
            expires = cast(int, self.expires_at_seconds)
            if not issued <= activity <= observed or not issued < expires or activity >= expires:
                raise EtradeOAuthContractError("access-token session timestamps are inconsistent")
            if observed > self.trusted_time_high_water_seconds:
                raise EtradeOAuthContractError("access-token state exceeds trusted-time high-water")
            if self.phase is EtradeOAuthSessionPhase.ACCESS_TOKEN_ACTIVE:
                if (
                    self.reauthorization_reason is not None
                    or observed >= expires
                    or observed - activity >= ETRADE_OAUTH_INACTIVITY_SECONDS
                ):
                    raise EtradeOAuthContractError("active state crossed an OAuth expiry horizon")
            elif self.phase is EtradeOAuthSessionPhase.ACCESS_TOKEN_INACTIVE:
                if (
                    self.reauthorization_reason is not None
                    or observed >= expires
                    or observed - activity < ETRADE_OAUTH_INACTIVITY_SECONDS
                ):
                    raise EtradeOAuthContractError(
                        "inactive state lacks an exact inactivity horizon breach"
                    )
            elif self.phase is EtradeOAuthSessionPhase.ACCESS_TOKEN_EXPIRED:
                if self.reauthorization_reason is not None or observed < expires:
                    raise EtradeOAuthContractError("expired state lacks an expiry horizon breach")
            elif self.phase is EtradeOAuthSessionPhase.ACCESS_TOKEN_REVOKED:
                if self.reauthorization_reason is not None or observed >= expires:
                    raise EtradeOAuthContractError("revoked state crossed the daily expiry horizon")
            elif self.reauthorization_reason is EtradeOAuthReauthorizationReason.INACTIVITY:
                if observed >= expires or observed - activity < ETRADE_OAUTH_INACTIVITY_SECONDS:
                    raise EtradeOAuthContractError(
                        "inactivity reauthorization lacks an exact horizon breach"
                    )
            elif self.reauthorization_reason is EtradeOAuthReauthorizationReason.DAILY_EXPIRY:
                if observed < expires:
                    raise EtradeOAuthContractError(
                        "daily-expiry reauthorization lacks an exact horizon breach"
                    )
            elif self.reauthorization_reason is EtradeOAuthReauthorizationReason.REVOCATION:
                if observed >= expires:
                    raise EtradeOAuthContractError(
                        "revocation reauthorization crossed the daily expiry horizon"
                    )
            else:
                raise EtradeOAuthContractError("reauthorization state lacks an exact reason")
        else:
            raise EtradeOAuthContractError("unsupported E*TRADE OAuth session phase")

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ETRADE_OAUTH_SESSION_CONTRACT_VERSION,
                "sanitized_session_state",
                self.provider.value,
                self.environment,
                self.endpoint_profile_sha256,
                self.consumer_reference.semantic_sha256,
                self.phase,
                self.generation,
                self.renewal_count,
                self.highest_token_reference_version,
                self.trusted_time_high_water_seconds,
                self.transition_evidence_sha256,
                None
                if self.request_token_reference is None
                else self.request_token_reference.semantic_sha256,
                None
                if self.access_token_reference is None
                else self.access_token_reference.semantic_sha256,
                self.request_token_intent_sha256,
                self.authorization_challenge_sha256,
                self.access_token_intent_sha256,
                self.issued_at_seconds,
                self.last_activity_at_seconds,
                self.last_observed_at_seconds,
                self.expires_at_seconds,
                self.reauthorization_reason,
                self.predecessor_sha256,
            )
        )

    def to_evidence_bytes(self) -> bytes:
        return json.dumps(
            {
                "access_token_intent_sha256": self.access_token_intent_sha256,
                "access_token_reference_version": (
                    None
                    if self.access_token_reference is None
                    else self.access_token_reference.version
                ),
                "authorization_challenge_sha256": self.authorization_challenge_sha256,
                "consumer_reference_version": self.consumer_reference.version,
                "contract_version": ETRADE_OAUTH_SESSION_CONTRACT_VERSION,
                "endpoint_profile_sha256": self.endpoint_profile_sha256,
                "environment": self.environment.value,
                "expires_at_seconds": self.expires_at_seconds,
                "generation": self.generation,
                "highest_token_reference_version": self.highest_token_reference_version,
                "issued_at_seconds": self.issued_at_seconds,
                "last_activity_at_seconds": self.last_activity_at_seconds,
                "last_observed_at_seconds": self.last_observed_at_seconds,
                "phase": self.phase.value,
                "predecessor_sha256": self.predecessor_sha256,
                "provider_id": self.provider.value,
                "provider_origin_authenticated": False,
                "reauthorization_reason": (
                    None
                    if self.reauthorization_reason is None
                    else self.reauthorization_reason.value
                ),
                "renewal_count": self.renewal_count,
                "request_token_intent_sha256": self.request_token_intent_sha256,
                "request_token_reference_version": (
                    None
                    if self.request_token_reference is None
                    else self.request_token_reference.version
                ),
                "semantic_sha256": self.semantic_sha256,
                "transition_evidence_sha256": self.transition_evidence_sha256,
                "trusted_time_high_water_seconds": self.trusted_time_high_water_seconds,
            },
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @property
    def authority(self) -> Mapping[str, bool]:
        return MappingProxyType({name: False for name in _AUTHORITY_FIELDS})


_ACCESS_EXCHANGE_CAPABILITY_ISSUER = object()


class EtradeOAuthAccessExchangeCapability(_EtradeOAuthSealed):
    """One-use in-process binding from one exact confirmed verifier to access signing."""

    __slots__ = (
        "__authorization_challenge_sha256",
        "__authorization_state_sha256",
        "__consumed",
        "__consumer_reference_sha256",
        "__endpoint_profile_sha256",
        "__environment",
        "__generation",
        "__lock",
        "__request_token_reference_sha256",
        "__runtime_reservation",
        "__runtime_reservation_owner",
        "__verifier",
    )
    __authorization_challenge_sha256: str
    __authorization_state_sha256: str
    __consumed: bool
    __consumer_reference_sha256: str
    __endpoint_profile_sha256: str
    __environment: EtradeEnvironment
    __generation: int
    __lock: Any
    __request_token_reference_sha256: str
    __runtime_reservation: object | None
    __runtime_reservation_owner: object | None
    __verifier: EtradeOAuthBoundVerifier

    def __init__(
        self,
        *,
        issuer: object,
        state: EtradeOAuthSessionState,
        verifier: EtradeOAuthBoundVerifier,
    ) -> None:
        if issuer is not _ACCESS_EXCHANGE_CAPABILITY_ISSUER:
            raise EtradeOAuthContractError(
                "access-exchange capabilities can only follow authorization confirmation"
            )
        _require_exact_type(state, EtradeOAuthSessionState, "confirmed authorization state")
        state.__post_init__()
        if state.phase is not EtradeOAuthSessionPhase.AUTHORIZATION_CONFIRMED:
            raise EtradeOAuthContractError(
                "access-exchange capability requires confirmed authorization"
            )
        _require_exact_type(verifier, EtradeOAuthBoundVerifier, "bound OAuth verifier")
        verifier._validate()
        if verifier.authorization_challenge_sha256 != state.authorization_challenge_sha256:
            raise EtradeOAuthContractError("OAuth verifier belongs to another authorization state")
        request_reference = cast(
            EtradeOAuthTokenSecretReference,
            state.request_token_reference,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthAccessExchangeCapability__authorization_challenge_sha256",
            state.authorization_challenge_sha256,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthAccessExchangeCapability__authorization_state_sha256",
            state.semantic_sha256,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthAccessExchangeCapability__consumer_reference_sha256",
            state.consumer_reference.semantic_sha256,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthAccessExchangeCapability__endpoint_profile_sha256",
            state.endpoint_profile_sha256,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthAccessExchangeCapability__environment",
            state.environment,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthAccessExchangeCapability__generation",
            state.generation,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthAccessExchangeCapability__request_token_reference_sha256",
            request_reference.semantic_sha256,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthAccessExchangeCapability__verifier",
            verifier,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthAccessExchangeCapability__consumed",
            False,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthAccessExchangeCapability__lock",
            Lock(),
        )
        object.__setattr__(
            self,
            "_EtradeOAuthAccessExchangeCapability__runtime_reservation",
            None,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthAccessExchangeCapability__runtime_reservation_owner",
            None,
        )
        self._validate()

    def _validate(self) -> None:
        _require_sha256(
            self.__authorization_challenge_sha256,
            "capability authorization challenge identity",
        )
        _require_sha256(
            self.__authorization_state_sha256,
            "capability authorization state identity",
        )
        _require_sha256(
            self.__consumer_reference_sha256,
            "capability consumer reference identity",
        )
        _require_sha256(
            self.__endpoint_profile_sha256,
            "capability endpoint profile identity",
        )
        _require_sha256(
            self.__request_token_reference_sha256,
            "capability request token reference identity",
        )
        _require_exact_type(self.__environment, EtradeEnvironment, "capability environment")
        if type(self.__generation) is not int or self.__generation < 1:
            raise EtradeOAuthContractError("capability generation is invalid")
        if type(self.__consumed) is not bool:
            raise EtradeOAuthContractError("capability consumption state is invalid")
        if (self.__runtime_reservation is None) is not (self.__runtime_reservation_owner is None):
            raise EtradeOAuthContractError("capability runtime reservation is malformed")
        _require_exact_type(self.__verifier, EtradeOAuthBoundVerifier, "capability verifier")
        self.__verifier._validate()
        if self.__verifier.authorization_challenge_sha256 != self.__authorization_challenge_sha256:
            raise EtradeOAuthContractError("capability verifier binding was corrupted")

    def _validate_for_state_unlocked(self, state: EtradeOAuthSessionState) -> None:
        _require_exact_type(state, EtradeOAuthSessionState, "confirmed authorization state")
        state.__post_init__()
        request_reference = cast(
            EtradeOAuthTokenSecretReference,
            state.request_token_reference,
        )
        if (
            state.phase is not EtradeOAuthSessionPhase.AUTHORIZATION_CONFIRMED
            or state.semantic_sha256 != self.__authorization_state_sha256
            or state.authorization_challenge_sha256 != self.__authorization_challenge_sha256
            or state.environment is not self.__environment
            or state.endpoint_profile_sha256 != self.__endpoint_profile_sha256
            or state.consumer_reference.semantic_sha256 != self.__consumer_reference_sha256
            or state.generation != self.__generation
            or request_reference.semantic_sha256 != self.__request_token_reference_sha256
        ):
            raise EtradeOAuthContractError(
                "access-exchange capability conflicts with authorization state"
            )

    def _validate_for_state(self, state: EtradeOAuthSessionState) -> None:
        with self.__lock:
            self._validate()
            self._validate_for_state_unlocked(state)

    def _reserve_unused_for_injected_token_runtime(
        self,
        *,
        state: EtradeOAuthSessionState,
        verifier: EtradeOAuthBoundVerifier,
    ) -> object:
        """Reserve, but do not consume, one exact verifier for the injected runtime."""

        _require_exact_type(verifier, EtradeOAuthBoundVerifier, "bound OAuth verifier")
        verifier._validate()
        with self.__lock:
            self._validate()
            self._validate_for_state_unlocked(state)
            if (
                self.__consumed
                or self.__runtime_reservation is not None
                or verifier is not self.__verifier
            ):
                raise EtradeOAuthContractError(
                    "access-exchange capability is unavailable for this exact verifier"
                )
            reservation = object()
            object.__setattr__(
                self,
                "_EtradeOAuthAccessExchangeCapability__runtime_reservation",
                reservation,
            )
            object.__setattr__(
                self,
                "_EtradeOAuthAccessExchangeCapability__runtime_reservation_owner",
                current_thread(),
            )
            return reservation

    def _release_injected_token_runtime_reservation(self, reservation: object) -> None:
        """Release an unconsumed runtime reservation after a fail-closed path."""

        with self.__lock:
            self._validate()
            if self.__runtime_reservation is None:
                return
            if self.__runtime_reservation is not reservation:
                raise EtradeOAuthContractError(
                    "access-exchange runtime reservation identity is invalid"
                )
            object.__setattr__(
                self,
                "_EtradeOAuthAccessExchangeCapability__runtime_reservation",
                None,
            )
            object.__setattr__(
                self,
                "_EtradeOAuthAccessExchangeCapability__runtime_reservation_owner",
                None,
            )

    def _consume_for(
        self,
        *,
        intent: EtradeOAuthSigningIntent,
        verifier: EtradeOAuthBoundVerifier,
        runtime_reservation: object | None = None,
    ) -> str:
        _require_exact_type(intent, EtradeOAuthSigningIntent, "access-token signing intent")
        intent.__post_init__()
        _require_exact_type(verifier, EtradeOAuthBoundVerifier, "bound OAuth verifier")
        verifier._validate()
        with self.__lock:
            self._validate()
            if verifier is not self.__verifier:
                raise EtradeOAuthContractError(
                    "access-token signing requires the exact confirmed verifier identity"
                )
            if self.__runtime_reservation is None:
                if runtime_reservation is not None:
                    raise EtradeOAuthContractError(
                        "access-exchange runtime reservation is not active"
                    )
            elif (
                runtime_reservation is not self.__runtime_reservation
                or current_thread() is not self.__runtime_reservation_owner
            ):
                raise EtradeOAuthContractError(
                    "access-exchange capability is reserved by another runtime"
                )
            token_reference = cast(
                EtradeOAuthTokenSecretReference,
                intent.token_reference,
            )
            if (
                intent.operation is not EtradeOAuthOperation.ACCESS_TOKEN
                or intent.authorization_state_sha256 != self.__authorization_state_sha256
                or intent.authorization_challenge_sha256 != self.__authorization_challenge_sha256
                or intent.environment is not self.__environment
                or intent.endpoint_profile.semantic_sha256 != self.__endpoint_profile_sha256
                or intent.consumer_reference.semantic_sha256 != self.__consumer_reference_sha256
                or intent.generation != self.__generation
                or token_reference.semantic_sha256 != self.__request_token_reference_sha256
            ):
                raise EtradeOAuthContractError(
                    "access-token signing intent conflicts with the verifier capability"
                )
            if self.__consumed:
                raise EtradeOAuthContractError("access-exchange capability was already consumed")
            object.__setattr__(
                self,
                "_EtradeOAuthAccessExchangeCapability__consumed",
                True,
            )
            object.__setattr__(
                self,
                "_EtradeOAuthAccessExchangeCapability__runtime_reservation",
                None,
            )
            object.__setattr__(
                self,
                "_EtradeOAuthAccessExchangeCapability__runtime_reservation_owner",
                None,
            )
            return self.__verifier._ephemeral_value()

    @property
    def authority(self) -> Mapping[str, bool]:
        with self.__lock:
            self._validate()
            return MappingProxyType({name: False for name in _AUTHORITY_FIELDS})

    def __repr__(self) -> str:
        with self.__lock:
            self._validate()
            return "EtradeOAuthAccessExchangeCapability(verifier=<redacted>, one_use=True)"

    def __reduce__(self) -> Never:
        raise TypeError("ephemeral access-exchange capability is intentionally non-serializable")


@dataclass(frozen=True, slots=True)
class EtradeOAuthAuthorizationTransitionResult:
    """One challenge consumption plus the replay guard that must be threaded forward."""

    state: EtradeOAuthSessionState
    next_replay_guard: EtradeOAuthReplayGuard
    access_exchange_capability: EtradeOAuthAccessExchangeCapability = field(
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        _require_exact_type(self.state, EtradeOAuthSessionState, "authorization session state")
        self.state.__post_init__()
        if self.state.phase is not EtradeOAuthSessionPhase.AUTHORIZATION_CONFIRMED:
            raise EtradeOAuthContractError("authorization result must contain a confirmed state")
        _require_exact_type(
            self.next_replay_guard,
            EtradeOAuthReplayGuard,
            "authorization replay guard",
        )
        self.next_replay_guard.__post_init__()
        _require_exact_type(
            self.access_exchange_capability,
            EtradeOAuthAccessExchangeCapability,
            "authorization access-exchange capability",
        )
        self.access_exchange_capability._validate_for_state(self.state)

    @property
    def authority(self) -> Mapping[str, bool]:
        return MappingProxyType({name: False for name in _AUTHORITY_FIELDS})


def _require_session_intent(
    state: EtradeOAuthSessionState,
    intent: EtradeOAuthSigningIntent,
    operation: EtradeOAuthOperation,
) -> None:
    _require_exact_type(state, EtradeOAuthSessionState, "OAuth session state")
    state.__post_init__()
    _require_exact_type(intent, EtradeOAuthSigningIntent, "OAuth signing intent")
    intent.__post_init__()
    if (
        intent.operation is not operation
        or intent.environment is not state.environment
        or intent.endpoint_profile.semantic_sha256 != state.endpoint_profile_sha256
        or intent.consumer_reference != state.consumer_reference
        or intent.generation != state.generation
    ):
        raise EtradeOAuthContractError("OAuth signing intent conflicts with session state")
    if intent.timestamp.unix_seconds < state.trusted_time_high_water_seconds:
        raise EtradeOAuthContractError("OAuth trusted session time cannot regress")


def _trusted_time_transition_evidence_sha256(
    transition: str,
    timestamp: EtradeOAuthTrustedTimestamp,
) -> str:
    return _semantic_sha256(
        (
            ETRADE_OAUTH_SESSION_CONTRACT_VERSION,
            transition,
            timestamp.unix_seconds,
            timestamp.trust_evidence_sha256,
        )
    )


def create_etrade_oauth_session(
    *,
    environment: EtradeEnvironment,
    endpoint_profile: EtradeEndpointIsolationProfile,
    consumer_reference: EtradeOAuthConsumerSecretReference,
) -> EtradeOAuthSessionState:
    """Create one secret-free initial supervised session."""

    _require_exact_type(environment, EtradeEnvironment, "session environment")
    _require_exact_type(endpoint_profile, EtradeEndpointIsolationProfile, "endpoint profile")
    endpoint_profile.__post_init__()
    _require_exact_type(
        consumer_reference,
        EtradeOAuthConsumerSecretReference,
        "consumer reference",
    )
    consumer_reference.__post_init__()
    if endpoint_profile.environment is not environment or (
        consumer_reference.environment is not environment
        or consumer_reference.scope is not endpoint_profile.consumer_secret_scope
    ):
        raise EtradeOAuthContractError(
            "OAuth session environment, endpoint, and consumer reference conflict"
        )
    return EtradeOAuthSessionState(
        provider=ETRADE_PROVIDER,
        environment=environment,
        endpoint_profile_sha256=endpoint_profile.semantic_sha256,
        consumer_reference=consumer_reference,
        phase=EtradeOAuthSessionPhase.NEEDS_REQUEST_TOKEN,
        generation=1,
        renewal_count=0,
        highest_token_reference_version=0,
        trusted_time_high_water_seconds=0,
    )


def record_etrade_oauth_request_token_transition(
    state: EtradeOAuthSessionState,
    *,
    signing_intent: EtradeOAuthSigningIntent,
    request_token_reference: EtradeOAuthTokenSecretReference,
) -> EtradeOAuthSessionState:
    """Record a caller-supervised request-token transition without provider proof."""

    _require_session_intent(state, signing_intent, EtradeOAuthOperation.REQUEST_TOKEN)
    if state.phase is not EtradeOAuthSessionPhase.NEEDS_REQUEST_TOKEN:
        raise EtradeOAuthContractError("request-token transition is unsupported from this phase")
    _require_exact_type(
        request_token_reference,
        EtradeOAuthTokenSecretReference,
        "request token reference",
    )
    request_token_reference.__post_init__()
    if (
        request_token_reference.environment is not state.environment
        or request_token_reference.kind is not EtradeOAuthTokenKind.REQUEST_TOKEN
        or request_token_reference.version <= state.highest_token_reference_version
    ):
        raise EtradeOAuthContractError("request-token reference is cross-scoped or replayed")
    return replace(
        state,
        phase=EtradeOAuthSessionPhase.REQUEST_TOKEN_RECEIVED,
        highest_token_reference_version=request_token_reference.version,
        trusted_time_high_water_seconds=signing_intent.timestamp.unix_seconds,
        transition_evidence_sha256=signing_intent.semantic_sha256,
        request_token_reference=request_token_reference,
        request_token_intent_sha256=signing_intent.semantic_sha256,
        predecessor_sha256=state.semantic_sha256,
    )


def begin_etrade_oauth_out_of_band_authorization(
    state: EtradeOAuthSessionState,
) -> EtradeOAuthSessionState:
    """Open an OOB authorization phase without constructing a token-bearing URL."""

    _require_exact_type(state, EtradeOAuthSessionState, "OAuth session state")
    state.__post_init__()
    if state.phase is not EtradeOAuthSessionPhase.REQUEST_TOKEN_RECEIVED:
        raise EtradeOAuthContractError("authorization transition is unsupported from this phase")
    challenge_sha256 = _semantic_sha256(
        (
            ETRADE_OAUTH_SESSION_CONTRACT_VERSION,
            "oob_authorization_challenge",
            state.semantic_sha256,
            ETRADE_SHARED_AUTHORIZATION_PAGE,
            ETRADE_OUT_OF_BAND_CALLBACK_POLICY.semantic_sha256,
            cast(EtradeOAuthTokenSecretReference, state.request_token_reference).semantic_sha256,
        )
    )
    return replace(
        state,
        phase=EtradeOAuthSessionPhase.AUTHORIZATION_PENDING,
        authorization_challenge_sha256=challenge_sha256,
        transition_evidence_sha256=challenge_sha256,
        predecessor_sha256=state.semantic_sha256,
    )


def record_etrade_oauth_authorization_transition(
    state: EtradeOAuthSessionState,
    *,
    verifier: EtradeOAuthBoundVerifier,
    replay_guard: EtradeOAuthReplayGuard,
) -> EtradeOAuthAuthorizationTransitionResult:
    """Consume one challenge-bound verifier without retaining or hashing its value."""

    _require_exact_type(state, EtradeOAuthSessionState, "OAuth session state")
    state.__post_init__()
    if state.phase is not EtradeOAuthSessionPhase.AUTHORIZATION_PENDING:
        raise EtradeOAuthContractError("authorization confirmation is unsupported from this phase")
    _require_exact_type(verifier, EtradeOAuthBoundVerifier, "bound OAuth verifier")
    verifier._validate()
    if verifier.authorization_challenge_sha256 != state.authorization_challenge_sha256:
        raise EtradeOAuthContractError("OAuth verifier belongs to another authorization state")
    fingerprint = _semantic_sha256(
        (
            ETRADE_OAUTH_SESSION_CONTRACT_VERSION,
            "oob_verifier_consumption_replay_fingerprint",
            state.environment,
            state.consumer_reference.semantic_sha256,
            state.generation,
            state.authorization_challenge_sha256,
        )
    )
    next_guard = _consume_replay_fingerprint(replay_guard, fingerprint)
    confirmed = replace(
        state,
        phase=EtradeOAuthSessionPhase.AUTHORIZATION_CONFIRMED,
        transition_evidence_sha256=fingerprint,
        predecessor_sha256=state.semantic_sha256,
    )
    access_exchange_capability = EtradeOAuthAccessExchangeCapability(
        issuer=_ACCESS_EXCHANGE_CAPABILITY_ISSUER,
        state=confirmed,
        verifier=verifier,
    )
    return EtradeOAuthAuthorizationTransitionResult(
        state=confirmed,
        next_replay_guard=next_guard,
        access_exchange_capability=access_exchange_capability,
    )


def record_etrade_oauth_access_token_transition(
    state: EtradeOAuthSessionState,
    *,
    signing_intent: EtradeOAuthSigningIntent,
    access_token_reference: EtradeOAuthTokenSecretReference,
    expires_at: EtradeOAuthTrustedTimestamp,
) -> EtradeOAuthSessionState:
    """Record caller-supervised access-token availability and fixed horizons."""

    _require_session_intent(state, signing_intent, EtradeOAuthOperation.ACCESS_TOKEN)
    if state.phase is not EtradeOAuthSessionPhase.AUTHORIZATION_CONFIRMED:
        raise EtradeOAuthContractError("access-token transition is unsupported from this phase")
    if signing_intent.authorization_challenge_sha256 != state.authorization_challenge_sha256:
        raise EtradeOAuthContractError("access-token intent belongs to another authorization state")
    if signing_intent.authorization_state_sha256 != state.semantic_sha256:
        raise EtradeOAuthContractError("access-token intent does not bind the confirmed state")
    if signing_intent.token_reference != state.request_token_reference:
        raise EtradeOAuthContractError("access-token intent does not bind the active request token")
    _require_exact_type(
        access_token_reference,
        EtradeOAuthTokenSecretReference,
        "access token reference",
    )
    access_token_reference.__post_init__()
    _require_exact_type(expires_at, EtradeOAuthTrustedTimestamp, "access-token expiry")
    expires_at.__post_init__()
    issued_at = signing_intent.timestamp.unix_seconds
    if (
        access_token_reference.environment is not state.environment
        or access_token_reference.kind is not EtradeOAuthTokenKind.ACCESS_TOKEN
        or access_token_reference.version <= state.highest_token_reference_version
    ):
        raise EtradeOAuthContractError("access-token reference is cross-scoped or replayed")
    if expires_at.unix_seconds <= issued_at or (
        expires_at.trust_evidence_sha256 != signing_intent.timestamp.trust_evidence_sha256
    ):
        raise EtradeOAuthContractError("access-token expiry conflicts with trusted session time")
    return replace(
        state,
        phase=EtradeOAuthSessionPhase.ACCESS_TOKEN_ACTIVE,
        highest_token_reference_version=access_token_reference.version,
        trusted_time_high_water_seconds=issued_at,
        transition_evidence_sha256=signing_intent.semantic_sha256,
        request_token_reference=None,
        access_token_reference=access_token_reference,
        access_token_intent_sha256=signing_intent.semantic_sha256,
        issued_at_seconds=issued_at,
        last_activity_at_seconds=issued_at,
        last_observed_at_seconds=issued_at,
        expires_at_seconds=expires_at.unix_seconds,
        predecessor_sha256=state.semantic_sha256,
    )


def observe_etrade_oauth_session_time(
    state: EtradeOAuthSessionState,
    *,
    observed_at: EtradeOAuthTrustedTimestamp,
) -> EtradeOAuthSessionState:
    """Evaluate inactivity and daily expiry from an injected trusted timestamp."""

    _require_exact_type(state, EtradeOAuthSessionState, "OAuth session state")
    state.__post_init__()
    if state.phase is not EtradeOAuthSessionPhase.ACCESS_TOKEN_ACTIVE:
        raise EtradeOAuthContractError("session-time observation requires an active access token")
    _require_exact_type(observed_at, EtradeOAuthTrustedTimestamp, "session observation time")
    observed_at.__post_init__()
    if observed_at.unix_seconds < state.trusted_time_high_water_seconds:
        raise EtradeOAuthContractError("OAuth trusted session time cannot regress")
    expires = cast(int, state.expires_at_seconds)
    activity = cast(int, state.last_activity_at_seconds)
    if observed_at.unix_seconds >= expires:
        phase = EtradeOAuthSessionPhase.ACCESS_TOKEN_EXPIRED
    elif observed_at.unix_seconds - activity >= ETRADE_OAUTH_INACTIVITY_SECONDS:
        phase = EtradeOAuthSessionPhase.ACCESS_TOKEN_INACTIVE
    else:
        phase = EtradeOAuthSessionPhase.ACCESS_TOKEN_ACTIVE
    return replace(
        state,
        phase=phase,
        last_observed_at_seconds=observed_at.unix_seconds,
        trusted_time_high_water_seconds=observed_at.unix_seconds,
        transition_evidence_sha256=_trusted_time_transition_evidence_sha256(
            "session_time_observation",
            observed_at,
        ),
        predecessor_sha256=state.semantic_sha256,
    )


def record_etrade_oauth_session_activity(
    state: EtradeOAuthSessionState,
    *,
    observed_at: EtradeOAuthTrustedTimestamp,
) -> EtradeOAuthSessionState:
    """Record caller-supervised session activity before either expiry horizon."""

    checked = observe_etrade_oauth_session_time(state, observed_at=observed_at)
    if checked.phase is not EtradeOAuthSessionPhase.ACCESS_TOKEN_ACTIVE:
        raise EtradeOAuthContractError("inactive or expired OAuth sessions cannot record activity")
    return replace(
        checked,
        last_activity_at_seconds=observed_at.unix_seconds,
        transition_evidence_sha256=_trusted_time_transition_evidence_sha256(
            "session_activity",
            observed_at,
        ),
        predecessor_sha256=state.semantic_sha256,
    )


def record_etrade_oauth_renewal_transition(
    state: EtradeOAuthSessionState,
    *,
    signing_intent: EtradeOAuthSigningIntent,
) -> EtradeOAuthSessionState:
    """Renew one active/inactive token before daily expiry without retaining its value."""

    _require_session_intent(state, signing_intent, EtradeOAuthOperation.RENEW_ACCESS_TOKEN)
    if state.phase not in {
        EtradeOAuthSessionPhase.ACCESS_TOKEN_ACTIVE,
        EtradeOAuthSessionPhase.ACCESS_TOKEN_INACTIVE,
    }:
        raise EtradeOAuthContractError("renewal is unsupported after daily expiry or revocation")
    if signing_intent.token_reference != state.access_token_reference:
        raise EtradeOAuthContractError("renewal intent does not bind the active access token")
    timestamp = signing_intent.timestamp.unix_seconds
    if timestamp < state.trusted_time_high_water_seconds:
        raise EtradeOAuthContractError("OAuth trusted session time cannot regress")
    if timestamp >= cast(int, state.expires_at_seconds):
        raise EtradeOAuthContractError("daily-expired OAuth sessions require reauthorization")
    checked = (
        observe_etrade_oauth_session_time(state, observed_at=signing_intent.timestamp)
        if state.phase is EtradeOAuthSessionPhase.ACCESS_TOKEN_ACTIVE
        else replace(
            state,
            last_observed_at_seconds=timestamp,
            trusted_time_high_water_seconds=timestamp,
            transition_evidence_sha256=signing_intent.semantic_sha256,
            predecessor_sha256=state.semantic_sha256,
        )
    )
    return replace(
        checked,
        phase=EtradeOAuthSessionPhase.ACCESS_TOKEN_ACTIVE,
        renewal_count=state.renewal_count + 1,
        last_activity_at_seconds=timestamp,
        last_observed_at_seconds=timestamp,
        trusted_time_high_water_seconds=timestamp,
        transition_evidence_sha256=signing_intent.semantic_sha256,
        predecessor_sha256=state.semantic_sha256,
    )


def record_etrade_oauth_revocation_transition(
    state: EtradeOAuthSessionState,
    *,
    signing_intent: EtradeOAuthSigningIntent,
) -> EtradeOAuthSessionState:
    """Record one active-session revocation through the exact pinned endpoint."""

    _require_session_intent(state, signing_intent, EtradeOAuthOperation.REVOKE_ACCESS_TOKEN)
    if state.phase is not EtradeOAuthSessionPhase.ACCESS_TOKEN_ACTIVE:
        raise EtradeOAuthContractError("revocation is unsupported without an active access token")
    if signing_intent.token_reference != state.access_token_reference:
        raise EtradeOAuthContractError("revocation intent does not bind the active access token")
    checked = observe_etrade_oauth_session_time(state, observed_at=signing_intent.timestamp)
    if checked.phase is not EtradeOAuthSessionPhase.ACCESS_TOKEN_ACTIVE:
        raise EtradeOAuthContractError("inactive or expired OAuth sessions require reauthorization")
    return replace(
        checked,
        phase=EtradeOAuthSessionPhase.ACCESS_TOKEN_REVOKED,
        transition_evidence_sha256=signing_intent.semantic_sha256,
        predecessor_sha256=state.semantic_sha256,
    )


def require_etrade_oauth_reauthorization(
    state: EtradeOAuthSessionState,
) -> EtradeOAuthSessionState:
    """Convert an inactive, expired, or revoked session into an explicit reauth gate."""

    _require_exact_type(state, EtradeOAuthSessionState, "OAuth session state")
    state.__post_init__()
    reasons: Mapping[EtradeOAuthSessionPhase, EtradeOAuthReauthorizationReason] = MappingProxyType(
        {
            EtradeOAuthSessionPhase.ACCESS_TOKEN_INACTIVE: (
                EtradeOAuthReauthorizationReason.INACTIVITY
            ),
            EtradeOAuthSessionPhase.ACCESS_TOKEN_EXPIRED: (
                EtradeOAuthReauthorizationReason.DAILY_EXPIRY
            ),
            EtradeOAuthSessionPhase.ACCESS_TOKEN_REVOKED: (
                EtradeOAuthReauthorizationReason.REVOCATION
            ),
        }
    )
    reason = reasons.get(state.phase)
    if reason is None:
        raise EtradeOAuthContractError("reauthorization is unsupported from this session phase")
    transition_evidence_sha256 = _semantic_sha256(
        (
            ETRADE_OAUTH_SESSION_CONTRACT_VERSION,
            "reauthorization_required",
            state.semantic_sha256,
            reason,
        )
    )
    return replace(
        state,
        phase=EtradeOAuthSessionPhase.REAUTHORIZATION_REQUIRED,
        reauthorization_reason=reason,
        transition_evidence_sha256=transition_evidence_sha256,
        predecessor_sha256=state.semantic_sha256,
    )


def begin_etrade_oauth_reauthorization(
    state: EtradeOAuthSessionState,
) -> EtradeOAuthSessionState:
    """Start a fresh request-token generation while retaining version high-water evidence."""

    _require_exact_type(state, EtradeOAuthSessionState, "OAuth session state")
    state.__post_init__()
    if state.phase is not EtradeOAuthSessionPhase.REAUTHORIZATION_REQUIRED:
        raise EtradeOAuthContractError("reauthorization start is unsupported from this phase")
    return EtradeOAuthSessionState(
        provider=state.provider,
        environment=state.environment,
        endpoint_profile_sha256=state.endpoint_profile_sha256,
        consumer_reference=state.consumer_reference,
        phase=EtradeOAuthSessionPhase.NEEDS_REQUEST_TOKEN,
        generation=state.generation + 1,
        renewal_count=0,
        highest_token_reference_version=state.highest_token_reference_version,
        trusted_time_high_water_seconds=state.trusted_time_high_water_seconds,
        transition_evidence_sha256=_semantic_sha256(
            (
                ETRADE_OAUTH_SESSION_CONTRACT_VERSION,
                "begin_reauthorization",
                state.semantic_sha256,
            )
        ),
        predecessor_sha256=state.semantic_sha256,
    )


__all__ = [
    "ETRADE_OAUTH_HTTP_METHOD",
    "ETRADE_OAUTH_INACTIVITY_SECONDS",
    "ETRADE_OAUTH_PROTOCOL_VERSION",
    "ETRADE_OAUTH_REPLAY_GUARD_MAX_FINGERPRINTS",
    "ETRADE_OAUTH_SESSION_CONTRACT_VERSION",
    "ETRADE_OAUTH_SESSION_REVIEWED_ON",
    "ETRADE_OAUTH_SIGNATURE_METHOD",
    "EtradeOAuthAccessExchangeCapability",
    "EtradeOAuthAuthorizationTransitionResult",
    "EtradeOAuthBoundVerifier",
    "EtradeOAuthConsumerCredentials",
    "EtradeOAuthConsumerKey",
    "EtradeOAuthConsumerSecret",
    "EtradeOAuthConsumerSecretReference",
    "EtradeOAuthContractError",
    "EtradeOAuthEphemeralSigningResult",
    "EtradeOAuthNonce",
    "EtradeOAuthNonsecretParameter",
    "EtradeOAuthOperation",
    "EtradeOAuthReauthorizationReason",
    "EtradeOAuthReplayGuard",
    "EtradeOAuthSessionPhase",
    "EtradeOAuthSessionState",
    "EtradeOAuthSigningIntent",
    "EtradeOAuthSigningTimeHighWater",
    "EtradeOAuthToken",
    "EtradeOAuthTokenCredentials",
    "EtradeOAuthTokenKind",
    "EtradeOAuthTokenSecret",
    "EtradeOAuthTokenSecretReference",
    "EtradeOAuthTrustedTimestamp",
    "EtradeOAuthVerifierValue",
    "begin_etrade_oauth_out_of_band_authorization",
    "begin_etrade_oauth_reauthorization",
    "create_etrade_oauth_session",
    "create_etrade_oauth_signing_intent",
    "etrade_oauth_percent_encode",
    "normalize_etrade_oauth_nonsecret_parameters",
    "observe_etrade_oauth_session_time",
    "record_etrade_oauth_access_token_transition",
    "record_etrade_oauth_authorization_transition",
    "record_etrade_oauth_renewal_transition",
    "record_etrade_oauth_request_token_transition",
    "record_etrade_oauth_revocation_transition",
    "record_etrade_oauth_session_activity",
    "require_etrade_oauth_reauthorization",
    "reserve_etrade_oauth_signing_intent",
    "sign_etrade_oauth_intent",
]
