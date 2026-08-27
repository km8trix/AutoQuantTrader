"""Injected, non-authorizing E*TRADE OAuth token runtime prerequisite.

This boundary composes the pure ADR-0118 signer with ADR-0120's sanitized
durable replay head.  It deliberately has no concrete network transport or
deployed secret resolver.  A caller supplies test-only ports, the runtime burns
the signing replay fingerprint durably before invoking the injected transport,
and an exact request-bound response is retained in a closable in-memory custody
object before strict form decoding.

Token response bytes and decoded token values never enter a durable model,
semantic digest, public evidence payload, exception, or useful representation.
The returned successor session is only a proposal: without a reviewed secret
store commit it must not be advanced into the durable session head.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field, replace
from threading import Lock
from types import MappingProxyType
from typing import Any, Never, Protocol, cast

from packages.adapters.broker.etrade import (
    ETRADE_PROVIDER,
    ETRADE_SHARED_TOKEN_ORIGIN,
    EtradeEnvironment,
    EtradeSecretScope,
)
from packages.adapters.broker.etrade_oauth import (
    EtradeOAuthAccessExchangeCapability,
    EtradeOAuthBoundVerifier,
    EtradeOAuthConsumerCredentials,
    EtradeOAuthConsumerKey,
    EtradeOAuthConsumerSecret,
    EtradeOAuthConsumerSecretReference,
    EtradeOAuthContractError,
    EtradeOAuthEphemeralSigningResult,
    EtradeOAuthOperation,
    EtradeOAuthReplayGuard,
    EtradeOAuthSessionPhase,
    EtradeOAuthSessionState,
    EtradeOAuthSigningIntent,
    EtradeOAuthToken,
    EtradeOAuthTokenCredentials,
    EtradeOAuthTokenKind,
    EtradeOAuthTokenSecret,
    EtradeOAuthTokenSecretReference,
    EtradeOAuthTrustedTimestamp,
    record_etrade_oauth_access_token_transition,
    record_etrade_oauth_request_token_transition,
    reserve_etrade_oauth_signing_intent,
    sign_etrade_oauth_intent,
)
from packages.domain.canonical import canonical_json_bytes
from packages.persistence.etrade_oauth_coordinator import (
    EtradeOAuthDurableSnapshot,
    EtradeOAuthTokenRuntimeCurrentnessReservation,
    authenticate_etrade_oauth_durable_snapshot,
)

ETRADE_OAUTH_TOKEN_RUNTIME_CONTRACT_VERSION = (
    "phase4an-injected-etrade-oauth-token-runtime-prerequisite-v1"
)
ETRADE_OAUTH_TOKEN_RUNTIME_REVIEWED_ON = "2026-08-26"
ETRADE_OAUTH_INJECTED_RESOLVER_ID = "injected-ephemeral-etrade-oauth-secret-resolver"
ETRADE_OAUTH_INJECTED_RESOLVER_VERSION = "1.0.0"
ETRADE_OAUTH_INJECTED_TRANSPORT_ID = "injected-fake-etrade-oauth-token-transport"
ETRADE_OAUTH_INJECTED_TRANSPORT_VERSION = "1.0.0"
ETRADE_OAUTH_TOKEN_RESPONSE_MEDIA_TYPE = "application/x-www-form-urlencoded"
ETRADE_OAUTH_TOKEN_RESPONSE_CHARSET = "utf-8"
ETRADE_OAUTH_TOKEN_RESPONSE_MAX_BYTES = 4_096
ETRADE_OAUTH_TOKEN_RUNTIME_TIMEOUT_MILLISECONDS = 2_000

_MAX_SECRET_BYTES = 1_024
_HEX = frozenset(b"0123456789abcdefABCDEF")
_LOCK_TYPE = type(Lock())
_AUTHORITY_FIELDS = (
    "deployed_credential_resolution_authorized",
    "provider_network_authorized",
    "provider_origin_authenticated",
    "browser_authorization_authorized",
    "callback_handling_authorized",
    "token_secret_persistence_authorized",
    "session_head_transition_authorized",
    "post_transport_secret_store_atomicity_qualified",
    "oauth_token_renewal_authorized",
    "oauth_token_revocation_authorized",
    "account_binding_authorized",
    "broker_call_authorized",
    "broker_mutation_authorized",
    "paper_startup_authorized",
    "live_startup_authorized",
    "trading_effect_authorized",
)


class EtradeOAuthTokenRuntimeError(RuntimeError):
    """The injected OAuth token prerequisite failed closed."""


class EtradeOAuthTokenResolutionError(EtradeOAuthTokenRuntimeError):
    """Ephemeral secret resolution failed without disclosing secret material."""


class EtradeOAuthTokenResolverLifecycleError(EtradeOAuthTokenResolutionError):
    """An ephemeral resolver envelope was stale, reused, or malformed."""


class EtradeOAuthTokenReplayError(EtradeOAuthTokenRuntimeError):
    """The sanitized durable replay-head advance failed closed."""


class EtradeOAuthTokenTransportError(EtradeOAuthTokenRuntimeError):
    """The injected transport failed without disclosing request material."""


class EtradeOAuthTokenResponseError(EtradeOAuthTokenRuntimeError):
    """The request-bound raw response violated the frozen response profile."""


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _authority() -> Mapping[str, bool]:
    return MappingProxyType({field_name: False for field_name in _AUTHORITY_FIELDS})


def _require_exact(value: object, expected: type[object], field_name: str) -> None:
    if type(value) is not expected:
        raise EtradeOAuthTokenRuntimeError(
            f"{field_name} must use the exact Phase 4AN provider-specific type"
        )


def _require_sha256(value: object, field_name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise EtradeOAuthTokenRuntimeError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _require_exact_false(value: object, field_name: str) -> None:
    if type(value) is not bool or value is not False:
        raise EtradeOAuthTokenResponseError(f"injected response {field_name} must remain false")


def _require_exact_true(value: object, field_name: str) -> None:
    if type(value) is not bool or value is not True:
        raise EtradeOAuthTokenResponseError(f"injected response {field_name} must remain true")


@dataclass(frozen=True, slots=True)
class EtradeOAuthTokenResolutionRequest:
    """Secret-free exact resolver demand bound to one durable current head."""

    intent: EtradeOAuthSigningIntent
    durable_scope_sha256: str
    durable_event_sha256: str
    durable_sequence: int
    durable_session_state_sha256: str
    durable_replay_guard_sha256: str

    def __post_init__(self) -> None:
        _require_exact(self.intent, EtradeOAuthSigningIntent, "OAuth resolver intent")
        self.intent.__post_init__()
        for value, field_name in (
            (self.durable_scope_sha256, "durable OAuth scope identity"),
            (self.durable_event_sha256, "durable OAuth event identity"),
            (self.durable_session_state_sha256, "durable OAuth session identity"),
            (self.durable_replay_guard_sha256, "durable OAuth replay identity"),
        ):
            _require_sha256(value, field_name)
        if type(self.durable_sequence) is not int or self.durable_sequence < 1:
            raise EtradeOAuthTokenRuntimeError(
                "durable OAuth sequence must be a positive exact integer"
            )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                ETRADE_OAUTH_TOKEN_RUNTIME_CONTRACT_VERSION,
                "secret_resolution_request",
                self.intent.semantic_sha256,
                self.durable_scope_sha256,
                self.durable_event_sha256,
                self.durable_sequence,
                self.durable_session_state_sha256,
                self.durable_replay_guard_sha256,
            )
        )

    @property
    def authority(self) -> Mapping[str, bool]:
        return _authority()


class _EtradeOAuthResolvedSecretEnvelope:
    """One-use mutable secret custody returned only through the resolver port."""

    __slots__ = (
        "__claimed",
        "__closed",
        "__consumer_key",
        "__consumer_reference",
        "__consumer_secret",
        "__lock",
        "__resolution_request_sha256",
        "__token",
        "__token_reference",
        "__token_secret",
    )
    __claimed: bool
    __closed: bool
    __consumer_key: bytearray
    __consumer_reference: EtradeOAuthConsumerSecretReference
    __consumer_secret: bytearray
    __lock: Any
    __resolution_request_sha256: str
    __token: bytearray
    __token_reference: EtradeOAuthTokenSecretReference | None
    __token_secret: bytearray

    def __init__(
        self,
        *,
        resolution_request: EtradeOAuthTokenResolutionRequest,
        consumer_key: str,
        consumer_secret: str,
        token: str | None,
        token_secret: str | None,
    ) -> None:
        _require_exact(
            resolution_request,
            EtradeOAuthTokenResolutionRequest,
            "secret-envelope resolution request",
        )
        resolution_request.__post_init__()
        object.__setattr__(self, "_EtradeOAuthResolvedSecretEnvelope__lock", Lock())
        object.__setattr__(self, "_EtradeOAuthResolvedSecretEnvelope__claimed", False)
        object.__setattr__(self, "_EtradeOAuthResolvedSecretEnvelope__closed", False)
        object.__setattr__(
            self,
            "_EtradeOAuthResolvedSecretEnvelope__consumer_key",
            bytearray(),
        )
        object.__setattr__(
            self,
            "_EtradeOAuthResolvedSecretEnvelope__consumer_secret",
            bytearray(),
        )
        object.__setattr__(self, "_EtradeOAuthResolvedSecretEnvelope__token", bytearray())
        object.__setattr__(
            self,
            "_EtradeOAuthResolvedSecretEnvelope__token_secret",
            bytearray(),
        )
        try:
            object.__setattr__(
                self,
                "_EtradeOAuthResolvedSecretEnvelope__consumer_key",
                _encode_secret(consumer_key),
            )
            object.__setattr__(
                self,
                "_EtradeOAuthResolvedSecretEnvelope__consumer_secret",
                _encode_secret(consumer_secret),
            )
            if resolution_request.intent.token_reference is None:
                if token is not None or token_secret is not None:
                    raise EtradeOAuthTokenResolutionError(
                        "request-token resolution cannot include token credentials"
                    )
            else:
                if token is None or token_secret is None:
                    raise EtradeOAuthTokenResolutionError(
                        "token-bound resolution requires both token values"
                    )
                object.__setattr__(
                    self,
                    "_EtradeOAuthResolvedSecretEnvelope__token",
                    _encode_secret(token),
                )
                object.__setattr__(
                    self,
                    "_EtradeOAuthResolvedSecretEnvelope__token_secret",
                    _encode_secret(token_secret),
                )
            object.__setattr__(
                self,
                "_EtradeOAuthResolvedSecretEnvelope__resolution_request_sha256",
                resolution_request.semantic_sha256,
            )
            object.__setattr__(
                self,
                "_EtradeOAuthResolvedSecretEnvelope__consumer_reference",
                resolution_request.intent.consumer_reference,
            )
            object.__setattr__(
                self,
                "_EtradeOAuthResolvedSecretEnvelope__token_reference",
                resolution_request.intent.token_reference,
            )
        except Exception:
            self.close()
            raise

    def _consume(
        self,
        request: EtradeOAuthTokenResolutionRequest,
    ) -> tuple[EtradeOAuthConsumerCredentials, EtradeOAuthTokenCredentials | None]:
        with self.__lock:
            if self.__closed or self.__claimed:
                raise EtradeOAuthTokenResolverLifecycleError(
                    "ephemeral OAuth secret envelope is closed or already consumed"
                )
            object.__setattr__(
                self,
                "_EtradeOAuthResolvedSecretEnvelope__claimed",
                True,
            )
            try:
                _require_exact(
                    request,
                    EtradeOAuthTokenResolutionRequest,
                    "secret consumption request",
                )
                request.__post_init__()
                if (
                    request.semantic_sha256 != self.__resolution_request_sha256
                    or request.intent.consumer_reference != self.__consumer_reference
                    or request.intent.token_reference != self.__token_reference
                ):
                    raise EtradeOAuthTokenResolverLifecycleError(
                        "ephemeral OAuth secret envelope belongs to another resolution request"
                    )
                consumer = EtradeOAuthConsumerCredentials(
                    reference=self.__consumer_reference,
                    consumer_key=EtradeOAuthConsumerKey(bytes(self.__consumer_key).decode("ascii")),
                    consumer_secret=EtradeOAuthConsumerSecret(
                        bytes(self.__consumer_secret).decode("ascii")
                    ),
                )
                token_credentials: EtradeOAuthTokenCredentials | None = None
                if self.__token_reference is not None:
                    token_credentials = EtradeOAuthTokenCredentials(
                        reference=self.__token_reference,
                        token=EtradeOAuthToken(bytes(self.__token).decode("ascii")),
                        token_secret=EtradeOAuthTokenSecret(
                            bytes(self.__token_secret).decode("ascii")
                        ),
                    )
                return consumer, token_credentials
            except (UnicodeDecodeError, EtradeOAuthContractError) as error:
                del error
                raise EtradeOAuthTokenResolverLifecycleError(
                    "ephemeral OAuth secret envelope was malformed"
                ) from None
            finally:
                self._close_unlocked()

    def _close_unlocked(self) -> None:
        if self.__closed:
            return
        for secret in (
            self.__consumer_key,
            self.__consumer_secret,
            self.__token,
            self.__token_secret,
        ):
            for index in range(len(secret)):
                secret[index] = 0
        object.__setattr__(self, "_EtradeOAuthResolvedSecretEnvelope__closed", True)

    def close(self) -> None:
        with self.__lock:
            self._close_unlocked()

    @property
    def closed(self) -> bool:
        with self.__lock:
            return self.__closed

    def __enter__(self) -> _EtradeOAuthResolvedSecretEnvelope:
        with self.__lock:
            if self.__closed or self.__claimed:
                raise EtradeOAuthTokenResolverLifecycleError(
                    "ephemeral OAuth secret envelope is closed or already consumed"
                )
            object.__setattr__(
                self,
                "_EtradeOAuthResolvedSecretEnvelope__claimed",
                True,
            )
            return self

    def __exit__(self, *args: object) -> None:
        del args
        self.close()

    def __repr__(self) -> str:
        with self.__lock:
            return f"_EtradeOAuthResolvedSecretEnvelope(<redacted>, closed={self.__closed})"

    def __str__(self) -> str:
        return "<redacted E*TRADE OAuth secret envelope>"

    def __setattr__(self, name: str, value: object) -> Never:
        del name, value
        raise AttributeError("ephemeral OAuth secret envelopes are sealed")

    def __reduce__(self) -> Never:
        raise TypeError("ephemeral OAuth secret envelopes are non-serializable")

    def __copy__(self) -> Never:
        raise TypeError("ephemeral OAuth secret envelopes cannot be copied")

    def __deepcopy__(self, memo: object) -> Never:
        del memo
        raise TypeError("ephemeral OAuth secret envelopes cannot be copied")

    def __del__(self) -> None:
        with suppress(Exception):
            self.close()


def _encode_secret(value: object) -> bytearray:
    if type(value) is not str:
        raise EtradeOAuthTokenResolutionError("resolved OAuth material must be exact text")
    try:
        encoded = value.encode("ascii", errors="strict")
    except UnicodeEncodeError as error:
        del error
        raise EtradeOAuthTokenResolutionError(
            "resolved OAuth material must use visible ASCII"
        ) from None
    if (
        not encoded
        or len(encoded) > _MAX_SECRET_BYTES
        or any(byte < 0x21 or byte > 0x7E for byte in encoded)
    ):
        raise EtradeOAuthTokenResolutionError(
            "resolved OAuth material violates the ephemeral secret bound"
        )
    return bytearray(encoded)


def create_etrade_oauth_token_secret_envelope(
    resolution_request: EtradeOAuthTokenResolutionRequest,
    *,
    consumer_key: str,
    consumer_secret: str,
    token: str | None = None,
    token_secret: str | None = None,
) -> object:
    """Create one opaque test-resolver envelope for an exact resolution request."""

    return _EtradeOAuthResolvedSecretEnvelope(
        resolution_request=resolution_request,
        consumer_key=consumer_key,
        consumer_secret=consumer_secret,
        token=token,
        token_secret=token_secret,
    )


class EtradeOAuthTokenSecretResolver(Protocol):
    """Injected test-only port; no deployed secret-manager implementation exists."""

    @property
    def resolver_id(self) -> str: ...

    @property
    def resolver_version(self) -> str: ...

    def _resolve_for_injected_token_exchange(
        self,
        request: EtradeOAuthTokenResolutionRequest,
    ) -> object: ...


_EPHEMERAL_TRANSPORT_REQUEST_ISSUER = object()


class EtradeOAuthEphemeralTransportRequest:
    """Sealed signed-request capability with no header or URL serialization."""

    __slots__ = (
        "__closed",
        "__durable_event_sha256",
        "__durable_scope_sha256",
        "__durable_sequence",
        "__endpoint_url",
        "__environment",
        "__http_method",
        "__intent_sha256",
        "__lock",
        "__operation",
        "__original_lock",
        "__presented",
        "__replay_guard_sha256",
        "__response_custody",
        "__sealed_binding_sha256",
        "__session_state_sha256",
        "__signing_result",
        "__timeout_milliseconds",
    )
    __closed: bool
    __durable_event_sha256: str
    __durable_scope_sha256: str
    __durable_sequence: int
    __endpoint_url: str
    __environment: EtradeEnvironment
    __http_method: str
    __intent_sha256: str
    __lock: Any
    __original_lock: Any
    __operation: EtradeOAuthOperation
    __presented: bool
    __replay_guard_sha256: str
    __response_custody: _EtradeOAuthRawTokenResponse | None
    __sealed_binding_sha256: str
    __session_state_sha256: str
    __signing_result: EtradeOAuthEphemeralSigningResult | None
    __timeout_milliseconds: int

    def __init__(
        self,
        *,
        issuer: object,
        signing_result: EtradeOAuthEphemeralSigningResult,
        replay_snapshot: EtradeOAuthDurableSnapshot,
    ) -> None:
        if issuer is not _EPHEMERAL_TRANSPORT_REQUEST_ISSUER:
            raise EtradeOAuthTokenTransportError(
                "ephemeral OAuth transport requests require the private runtime issuer"
            )
        _require_exact(
            signing_result,
            EtradeOAuthEphemeralSigningResult,
            "ephemeral signing result",
        )
        signing_result._validate()
        replay_snapshot = _validate_snapshot(replay_snapshot)
        state = replay_snapshot.state
        if (
            signing_result.intent.environment is not state.environment
            or signing_result.intent.endpoint_profile.semantic_sha256
            != state.endpoint_profile_sha256
            or signing_result.intent.consumer_reference != state.consumer_reference
            or signing_result.intent.generation != state.generation
        ):
            raise EtradeOAuthTokenTransportError(
                "signed request conflicts with the replay-only durable head"
            )
        if replay_snapshot.replay_guard != signing_result.next_replay_guard:
            raise EtradeOAuthTokenTransportError(
                "signed request replay guard was not durably committed"
            )
        lock = Lock()
        object.__setattr__(self, "_EtradeOAuthEphemeralTransportRequest__lock", lock)
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTransportRequest__original_lock",
            lock,
        )
        object.__setattr__(self, "_EtradeOAuthEphemeralTransportRequest__closed", False)
        object.__setattr__(self, "_EtradeOAuthEphemeralTransportRequest__presented", False)
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTransportRequest__response_custody",
            None,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTransportRequest__signing_result",
            signing_result,
        )
        intent = signing_result.intent
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTransportRequest__intent_sha256",
            intent.semantic_sha256,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTransportRequest__operation",
            intent.operation,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTransportRequest__environment",
            intent.environment,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTransportRequest__http_method",
            intent.http_method,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTransportRequest__endpoint_url",
            intent.endpoint_url,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTransportRequest__durable_scope_sha256",
            replay_snapshot.scope_sha256,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTransportRequest__durable_event_sha256",
            replay_snapshot.current_event_sha256,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTransportRequest__durable_sequence",
            replay_snapshot.sequence,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTransportRequest__session_state_sha256",
            replay_snapshot.state.semantic_sha256,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTransportRequest__replay_guard_sha256",
            replay_snapshot.replay_guard.semantic_sha256,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTransportRequest__timeout_milliseconds",
            ETRADE_OAUTH_TOKEN_RUNTIME_TIMEOUT_MILLISECONDS,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTransportRequest__sealed_binding_sha256",
            _semantic_sha256(self._binding_material_unlocked()),
        )
        self._validate_before_injected_transport()

    def _exact_lock(self, expected_identity: object | None = None) -> Any:
        lock = object.__getattribute__(
            self,
            "_EtradeOAuthEphemeralTransportRequest__lock",
        )
        original_lock = object.__getattribute__(
            self,
            "_EtradeOAuthEphemeralTransportRequest__original_lock",
        )
        if (
            type(lock) is not _LOCK_TYPE
            or lock is not original_lock
            or (expected_identity is not None and lock is not expected_identity)
        ):
            raise EtradeOAuthTokenTransportError(
                "ephemeral OAuth transport request lock was replaced"
            )
        return lock

    def _lock_identity_for_dispatch_witness(self) -> object:
        return self._exact_lock()

    def _binding_material_unlocked(self) -> tuple[object, ...]:
        return (
            ETRADE_OAUTH_TOKEN_RUNTIME_CONTRACT_VERSION,
            "sealed_injected_transport_request",
            self.__intent_sha256,
            self.__operation,
            self.__environment,
            self.__http_method,
            self.__endpoint_url,
            self.__durable_scope_sha256,
            self.__durable_event_sha256,
            self.__durable_sequence,
            self.__session_state_sha256,
            self.__replay_guard_sha256,
            self.__timeout_milliseconds,
        )

    def _validate_unlocked(self) -> None:
        if self.__closed:
            raise EtradeOAuthTokenTransportError("ephemeral OAuth transport request is closed")
        signing_result = self.__signing_result
        if type(signing_result) is not EtradeOAuthEphemeralSigningResult:
            raise EtradeOAuthTokenTransportError(
                "ephemeral OAuth transport signing custody is closed or malformed"
            )
        try:
            signing_result._validate()
        except Exception:
            raise EtradeOAuthTokenTransportError(
                "sealed OAuth transport signing custody was mutated"
            ) from None
        intent = signing_result.intent
        if (
            type(self.__operation) is not EtradeOAuthOperation
            or type(self.__environment) is not EtradeEnvironment
            or type(self.__http_method) is not str
            or type(self.__endpoint_url) is not str
            or type(self.__durable_sequence) is not int
            or type(self.__timeout_milliseconds) is not int
            or self.__timeout_milliseconds != ETRADE_OAUTH_TOKEN_RUNTIME_TIMEOUT_MILLISECONDS
            or intent.semantic_sha256 != self.__intent_sha256
            or intent.operation is not self.__operation
            or intent.environment is not self.__environment
            or intent.http_method != self.__http_method
            or intent.endpoint_url != self.__endpoint_url
            or signing_result.next_replay_guard.semantic_sha256 != self.__replay_guard_sha256
            or _semantic_sha256(self._binding_material_unlocked()) != self.__sealed_binding_sha256
        ):
            raise EtradeOAuthTokenTransportError(
                "sealed OAuth transport request binding was mutated"
            )
        for value, field_name in (
            (self.__intent_sha256, "transport intent identity"),
            (self.__durable_scope_sha256, "transport durable scope"),
            (self.__durable_event_sha256, "transport durable event"),
            (self.__session_state_sha256, "transport durable state"),
            (self.__replay_guard_sha256, "transport replay guard"),
            (self.__sealed_binding_sha256, "transport sealed binding"),
        ):
            _require_sha256(value, field_name)

    def _validate_before_injected_transport(self) -> None:
        with self._exact_lock():
            self._validate_unlocked()
            if self.__presented or self.__response_custody is not None:
                raise EtradeOAuthTokenTransportError(
                    "ephemeral OAuth transport request was already presented"
                )

    def _validate_after_injected_transport(
        self,
        response: _EtradeOAuthRawTokenResponse,
    ) -> None:
        with self._exact_lock():
            self._validate_unlocked()
            if (
                self.__presented is not True
                or type(response) is not _EtradeOAuthRawTokenResponse
                or self.__response_custody is not response
            ):
                raise EtradeOAuthTokenTransportError(
                    "injected response custody is not bound to the sealed request"
                )

    def _authorization_header_matches_for_test(self, expected: str) -> bool:
        """Constant-time fake-transport assertion without exposing the header."""

        with self._exact_lock():
            self._validate_unlocked()
            signing_result = cast(
                EtradeOAuthEphemeralSigningResult,
                self.__signing_result,
            )
            return signing_result.authorization_header_matches(expected)

    def _present_for_injected_exchange(self) -> None:
        with self._exact_lock():
            self._validate_unlocked()
            if self.__presented or self.__response_custody is not None:
                raise EtradeOAuthTokenTransportError(
                    "ephemeral OAuth transport request was already presented"
                )
            object.__setattr__(
                self,
                "_EtradeOAuthEphemeralTransportRequest__presented",
                True,
            )

    def _require_presented(self) -> None:
        with self._exact_lock():
            self._validate_unlocked()
            if not self.__presented:
                raise EtradeOAuthTokenTransportError(
                    "injected response requires the exact presented signed request"
                )

    def _require_open(self) -> None:
        with self._exact_lock():
            self._validate_unlocked()

    def _sealed_response_binding_material(self) -> tuple[object, ...]:
        with self._exact_lock():
            self._validate_unlocked()
            return self._binding_material_unlocked()

    def _matches_independent_dispatch_witness(
        self,
        *,
        signing_result: EtradeOAuthEphemeralSigningResult,
        binding_material: tuple[object, ...],
        lock_identity: object,
    ) -> bool:
        """Compare against runtime-held values never shared with the transport."""

        with self._exact_lock(lock_identity):
            self._validate_unlocked()
            return (
                self.__lock is lock_identity
                and self.__original_lock is lock_identity
                and self.__signing_result is signing_result
                and self._binding_material_unlocked() == binding_material
            )

    def _bind_response_custody(self, response: _EtradeOAuthRawTokenResponse) -> None:
        with self._exact_lock():
            self._validate_unlocked()
            _require_exact(response, _EtradeOAuthRawTokenResponse, "request-bound raw response")
            if not self.__presented or self.__response_custody is not None:
                raise EtradeOAuthTokenTransportError(
                    "ephemeral OAuth transport request cannot bind response custody"
                )
            object.__setattr__(
                self,
                "_EtradeOAuthEphemeralTransportRequest__response_custody",
                response,
            )

    def _release_response_custody(
        self,
        response: _EtradeOAuthRawTokenResponse,
        *,
        lock_identity: object,
    ) -> None:
        with self._exact_lock(lock_identity):
            self._validate_unlocked()
            _require_exact(response, _EtradeOAuthRawTokenResponse, "released raw response")
            if self.__response_custody is not response:
                raise EtradeOAuthTokenTransportError(
                    "ephemeral OAuth raw response custody is not request-bound"
                )
            object.__setattr__(
                self,
                "_EtradeOAuthEphemeralTransportRequest__response_custody",
                None,
            )

    def _close_unlocked(self) -> _EtradeOAuthRawTokenResponse | None:
        if self.__closed:
            return None
        response = self.__response_custody
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTransportRequest__response_custody",
            None,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTransportRequest__signing_result",
            None,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTransportRequest__closed",
            True,
        )
        return response if type(response) is _EtradeOAuthRawTokenResponse else None

    def _close_with_dispatch_witness(self, lock_identity: object) -> None:
        """Close without entering request lock fields exposed to the transport."""

        if type(lock_identity) is not _LOCK_TYPE:
            raise EtradeOAuthTokenTransportError(
                "ephemeral OAuth transport request cleanup lock is malformed"
            )
        with lock_identity:
            object.__setattr__(
                self,
                "_EtradeOAuthEphemeralTransportRequest__lock",
                lock_identity,
            )
            object.__setattr__(
                self,
                "_EtradeOAuthEphemeralTransportRequest__original_lock",
                lock_identity,
            )
            self._close_unlocked()

    def close(self) -> None:
        original_lock = object.__getattribute__(
            self,
            "_EtradeOAuthEphemeralTransportRequest__original_lock",
        )
        if type(original_lock) is _LOCK_TYPE:
            lock_context = original_lock
            object.__setattr__(
                self,
                "_EtradeOAuthEphemeralTransportRequest__lock",
                original_lock,
            )
        else:
            lock_context = Lock()
            object.__setattr__(
                self,
                "_EtradeOAuthEphemeralTransportRequest__lock",
                lock_context,
            )
            object.__setattr__(
                self,
                "_EtradeOAuthEphemeralTransportRequest__original_lock",
                lock_context,
            )
        with lock_context:
            response = self._close_unlocked()
        if type(response) is _EtradeOAuthRawTokenResponse:
            response.close()

    @property
    def closed(self) -> bool:
        with self._exact_lock():
            return self.__closed

    def __repr__(self) -> str:
        with self._exact_lock():
            return (
                "EtradeOAuthEphemeralTransportRequest("
                f"intent_sha256={self.__intent_sha256!r}, authorization=<redacted>, "
                f"closed={self.__closed})"
            )

    def __str__(self) -> str:
        return "<redacted E*TRADE OAuth signed transport request>"

    def __setattr__(self, name: str, value: object) -> Never:
        del name, value
        raise AttributeError("ephemeral OAuth transport requests are sealed")

    def __reduce__(self) -> Never:
        raise TypeError("ephemeral OAuth transport requests are non-serializable")

    def __copy__(self) -> Never:
        raise TypeError("ephemeral OAuth transport requests cannot be copied")

    def __deepcopy__(self, memo: object) -> Never:
        del memo
        raise TypeError("ephemeral OAuth transport requests cannot be copied")

    def __del__(self) -> None:
        with suppress(Exception):
            self.close()


class _EtradeOAuthTransportDispatchWitness:
    """Independent pre-call binding retained outside the transport-owned graph."""

    __slots__ = (
        "__canonical_intent",
        "__intent_evidence_bytes",
        "__intent_sha256",
        "__presented_intent",
        "__raw_response",
        "__raw_response_binding_lock",
        "__raw_response_claimed",
        "__raw_response_lock_identity",
        "__replay_binding_material",
        "__request",
        "__request_binding_material",
        "__request_lock_identity",
        "__signing_result",
        "__source_replay_guard",
    )
    __canonical_intent: EtradeOAuthSigningIntent
    __intent_evidence_bytes: bytes
    __intent_sha256: str
    __presented_intent: EtradeOAuthSigningIntent
    __raw_response: _EtradeOAuthRawTokenResponse | None
    __raw_response_binding_lock: Any
    __raw_response_claimed: bool
    __raw_response_lock_identity: object | None
    __replay_binding_material: tuple[object, ...]
    __request: EtradeOAuthEphemeralTransportRequest
    __request_binding_material: tuple[object, ...]
    __request_lock_identity: object
    __signing_result: EtradeOAuthEphemeralSigningResult
    __source_replay_guard: EtradeOAuthReplayGuard

    def __init__(
        self,
        *,
        canonical_intent: EtradeOAuthSigningIntent,
        presented_intent: EtradeOAuthSigningIntent,
        signing_result: EtradeOAuthEphemeralSigningResult,
        request: EtradeOAuthEphemeralTransportRequest,
        source_replay_guard: EtradeOAuthReplayGuard,
        replay_snapshot: EtradeOAuthDurableSnapshot,
    ) -> None:
        canonical_intent.__post_init__()
        presented_intent.__post_init__()
        signing_result._validate()
        source_replay_guard.__post_init__()
        replay_snapshot = _validate_snapshot(replay_snapshot)
        if (
            canonical_intent is presented_intent
            or canonical_intent.semantic_sha256 != presented_intent.semantic_sha256
            or canonical_intent.to_evidence_bytes() != presented_intent.to_evidence_bytes()
            or signing_result.intent is not presented_intent
        ):
            raise EtradeOAuthTokenTransportError(
                "OAuth transport intent does not match its private canonical value"
            )
        object.__setattr__(
            self,
            "_EtradeOAuthTransportDispatchWitness__canonical_intent",
            canonical_intent,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthTransportDispatchWitness__intent_evidence_bytes",
            bytes(canonical_intent.to_evidence_bytes()),
        )
        object.__setattr__(
            self,
            "_EtradeOAuthTransportDispatchWitness__intent_sha256",
            canonical_intent.semantic_sha256,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthTransportDispatchWitness__presented_intent",
            presented_intent,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthTransportDispatchWitness__raw_response",
            None,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthTransportDispatchWitness__raw_response_binding_lock",
            Lock(),
        )
        object.__setattr__(
            self,
            "_EtradeOAuthTransportDispatchWitness__raw_response_claimed",
            False,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthTransportDispatchWitness__raw_response_lock_identity",
            None,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthTransportDispatchWitness__request_binding_material",
            request._sealed_response_binding_material(),
        )
        object.__setattr__(
            self,
            "_EtradeOAuthTransportDispatchWitness__request_lock_identity",
            request._lock_identity_for_dispatch_witness(),
        )
        object.__setattr__(
            self,
            "_EtradeOAuthTransportDispatchWitness__request",
            request,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthTransportDispatchWitness__replay_binding_material",
            self._replay_binding(replay_snapshot),
        )
        object.__setattr__(
            self,
            "_EtradeOAuthTransportDispatchWitness__signing_result",
            signing_result,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthTransportDispatchWitness__source_replay_guard",
            source_replay_guard,
        )

    def _bind_constructor_raw_response(
        self,
        *,
        request: EtradeOAuthEphemeralTransportRequest,
        response: _EtradeOAuthRawTokenResponse,
    ) -> None:
        """Record factory-time response custody outside the transport graph."""

        _require_exact(request, EtradeOAuthEphemeralTransportRequest, "witnessed request")
        _require_exact(response, _EtradeOAuthRawTokenResponse, "witnessed raw response")
        lock_identity = response._lock_identity_for_runtime_validation()
        with self.__raw_response_binding_lock:
            if (
                request is not self.__request
                or self.__raw_response is not None
                or self.__raw_response_lock_identity is not None
                or self.__raw_response_claimed
            ):
                raise EtradeOAuthTokenResponseError(
                    "raw OAuth response constructor witness cannot be rebound"
                )
            object.__setattr__(
                self,
                "_EtradeOAuthTransportDispatchWitness__raw_response",
                response,
            )
            object.__setattr__(
                self,
                "_EtradeOAuthTransportDispatchWitness__raw_response_lock_identity",
                lock_identity,
            )

    def _claim_constructor_raw_response_lock_identity(
        self,
        *,
        request: EtradeOAuthEphemeralTransportRequest,
        response: _EtradeOAuthRawTokenResponse,
    ) -> object:
        """Claim the exact factory-time response and lock once after dispatch."""

        with self.__raw_response_binding_lock:
            lock_identity = self.__raw_response_lock_identity
            invalid = (
                request is not self.__request
                or response is not self.__raw_response
                or type(lock_identity) is not _LOCK_TYPE
                or self.__raw_response_claimed
            )
            if not invalid:
                try:
                    invalid = response._lock_identity_for_runtime_validation() is not lock_identity
                except Exception:
                    invalid = True
            if invalid:
                self._close_constructor_raw_response_unlocked()
                raise EtradeOAuthTokenResponseError(
                    "raw OAuth response conflicts with its constructor witness"
                )
            object.__setattr__(
                self,
                "_EtradeOAuthTransportDispatchWitness__raw_response_claimed",
                True,
            )
            return lock_identity

    def _close_constructor_raw_response_unlocked(self) -> None:
        response = self.__raw_response
        lock_identity = self.__raw_response_lock_identity
        if type(response) is _EtradeOAuthRawTokenResponse and type(lock_identity) is _LOCK_TYPE:
            response._close_with_runtime_lock_identity(lock_identity)

    def _close_constructor_raw_response_for_failure(self) -> None:
        """Close bound response custody using only the factory-time lock."""

        with self.__raw_response_binding_lock:
            self._close_constructor_raw_response_unlocked()

    def _release_response_custody_for_result(
        self,
        *,
        request: EtradeOAuthEphemeralTransportRequest,
        response: _EtradeOAuthRawTokenResponse,
    ) -> None:
        """Release result custody only under the witnessed request lock."""

        if request is not self.__request:
            raise EtradeOAuthTokenTransportError(
                "OAuth result custody conflicts with its witnessed request"
            )
        request._release_response_custody(
            response,
            lock_identity=self.__request_lock_identity,
        )

    def _close_request_after_dispatch(self) -> None:
        """Close request custody using only the pre-dispatch lock witness."""

        self.__request._close_with_dispatch_witness(self.__request_lock_identity)

    @staticmethod
    def _replay_binding(snapshot: EtradeOAuthDurableSnapshot) -> tuple[object, ...]:
        return (
            snapshot.scope_sha256,
            snapshot.current_event_sha256,
            snapshot.sequence,
            snapshot.state.semantic_sha256,
            snapshot.replay_guard.semantic_sha256,
        )

    def _validate_after_injected_transport(
        self,
        *,
        presented_intent: EtradeOAuthSigningIntent,
        signing_result: EtradeOAuthEphemeralSigningResult,
        request: EtradeOAuthEphemeralTransportRequest,
        replay_snapshot: EtradeOAuthDurableSnapshot,
    ) -> None:
        try:
            self.__canonical_intent.__post_init__()
            presented_intent.__post_init__()
            signing_result._validate()
            replay_snapshot = _validate_snapshot(replay_snapshot)
            canonical_guard = reserve_etrade_oauth_signing_intent(
                self.__canonical_intent,
                replay_guard=self.__source_replay_guard,
            )
            presented_guard = reserve_etrade_oauth_signing_intent(
                presented_intent,
                replay_guard=self.__source_replay_guard,
            )
            request_matches = request._matches_independent_dispatch_witness(
                signing_result=self.__signing_result,
                binding_material=self.__request_binding_material,
                lock_identity=self.__request_lock_identity,
            )
        except Exception:
            raise EtradeOAuthTokenTransportError(
                "injected OAuth transport mutated its independent dispatch binding"
            ) from None
        if (
            presented_intent is not self.__presented_intent
            or signing_result is not self.__signing_result
            or signing_result.intent is not presented_intent
            or not hmac.compare_digest(
                self.__canonical_intent.semantic_sha256,
                self.__intent_sha256,
            )
            or not hmac.compare_digest(
                presented_intent.semantic_sha256,
                self.__intent_sha256,
            )
            or not hmac.compare_digest(
                self.__canonical_intent.to_evidence_bytes(),
                self.__intent_evidence_bytes,
            )
            or not hmac.compare_digest(
                presented_intent.to_evidence_bytes(),
                self.__intent_evidence_bytes,
            )
            or not request_matches
            or self._replay_binding(replay_snapshot) != self.__replay_binding_material
            or canonical_guard != replay_snapshot.replay_guard
            or presented_guard != canonical_guard
            or signing_result.next_replay_guard != canonical_guard
        ):
            raise EtradeOAuthTokenTransportError(
                "injected OAuth transport mutated its independent dispatch binding"
            )

    def __repr__(self) -> str:
        return "_EtradeOAuthTransportDispatchWitness(<redacted>)"

    def __reduce__(self) -> Never:
        raise TypeError("OAuth transport dispatch witnesses are non-serializable")


_RAW_RESPONSE_DISPATCH_REGISTRY_LOCK = Lock()
_RAW_RESPONSE_DISPATCH_REGISTRY: dict[
    int,
    tuple[EtradeOAuthEphemeralTransportRequest, _EtradeOAuthTransportDispatchWitness],
] = {}


def _register_raw_response_dispatch_witness(
    request: EtradeOAuthEphemeralTransportRequest,
    witness: _EtradeOAuthTransportDispatchWitness,
) -> None:
    _require_exact(request, EtradeOAuthEphemeralTransportRequest, "registered request")
    _require_exact(witness, _EtradeOAuthTransportDispatchWitness, "dispatch witness")
    key = id(request)
    with _RAW_RESPONSE_DISPATCH_REGISTRY_LOCK:
        if key in _RAW_RESPONSE_DISPATCH_REGISTRY:
            raise EtradeOAuthTokenTransportError(
                "raw OAuth response dispatch witness is already registered"
            )
        _RAW_RESPONSE_DISPATCH_REGISTRY[key] = (request, witness)


def _unregister_raw_response_dispatch_witness(
    request: EtradeOAuthEphemeralTransportRequest,
    witness: _EtradeOAuthTransportDispatchWitness,
) -> None:
    key = id(request)
    with _RAW_RESPONSE_DISPATCH_REGISTRY_LOCK:
        binding = _RAW_RESPONSE_DISPATCH_REGISTRY.pop(key, None)
    if binding is None or binding[0] is not request or binding[1] is not witness:
        raise EtradeOAuthTokenTransportError(
            "raw OAuth response dispatch witness registration was mutated"
        )


def _registered_raw_response_dispatch_witness(
    request: EtradeOAuthEphemeralTransportRequest,
) -> _EtradeOAuthTransportDispatchWitness:
    with _RAW_RESPONSE_DISPATCH_REGISTRY_LOCK:
        binding = _RAW_RESPONSE_DISPATCH_REGISTRY.get(id(request))
    if binding is None or binding[0] is not request:
        raise EtradeOAuthTokenResponseError(
            "raw OAuth response factory requires an active runtime witness"
        )
    return binding[1]


_RAW_TOKEN_RESPONSE_ISSUER = object()


class _EtradeOAuthRawTokenResponse:
    """Exact request-bound raw bytes in explicit best-effort mutable custody."""

    __slots__ = (
        "__body",
        "__charset_exact",
        "__closed",
        "__complete",
        "__http_status_exact",
        "__lock",
        "__media_type_exact",
        "__origin_exact",
        "__original_lock",
        "__proxy_used",
        "__redirect_location_present",
        "__redirects_followed",
        "__request",
        "__request_binding_material",
        "__sealed_metadata_sha256",
        "__timed_out",
        "__tls_peer_verified",
        "__transport_error",
    )
    __body: bytearray
    __charset_exact: bool
    __closed: bool
    __complete: bool
    __http_status_exact: bool
    __lock: Any
    __original_lock: Any
    __media_type_exact: bool
    __origin_exact: bool
    __proxy_used: bool
    __redirect_location_present: bool
    __redirects_followed: bool
    __request: EtradeOAuthEphemeralTransportRequest
    __request_binding_material: tuple[object, ...]
    __sealed_metadata_sha256: str
    __timed_out: bool
    __tls_peer_verified: bool
    __transport_error: bool

    def __init__(
        self,
        request: EtradeOAuthEphemeralTransportRequest,
        *,
        issuer: object,
        response_origin: str,
        http_status: int,
        media_type: str,
        charset: str,
        body: bytes,
        tls_peer_verified: bool,
        redirects_followed: bool,
        redirect_location: str | None,
        proxy_used: bool,
        complete: bool,
        timed_out: bool,
        transport_error: bool,
    ) -> None:
        if issuer is not _RAW_TOKEN_RESPONSE_ISSUER:
            raise EtradeOAuthTokenResponseError(
                "raw token response custody requires the private injected factory issuer"
            )
        _require_exact(
            request,
            EtradeOAuthEphemeralTransportRequest,
            "raw-response transport request",
        )
        request._require_presented()
        if type(response_origin) is not str or len(response_origin) > 128:
            raise EtradeOAuthTokenResponseError("injected response origin is malformed")
        if type(http_status) is not int or not 100 <= http_status <= 599:
            raise EtradeOAuthTokenResponseError("injected response status is malformed")
        if type(media_type) is not str or len(media_type) > 128:
            raise EtradeOAuthTokenResponseError("injected response media type is malformed")
        if type(charset) is not str or len(charset) > 32:
            raise EtradeOAuthTokenResponseError("injected response charset is malformed")
        if type(body) is not bytes or not 1 <= len(body) <= ETRADE_OAUTH_TOKEN_RESPONSE_MAX_BYTES:
            raise EtradeOAuthTokenResponseError(
                "injected response body is empty, malformed, or oversized"
            )
        if redirect_location is not None and type(redirect_location) is not str:
            raise EtradeOAuthTokenResponseError("injected redirect metadata is malformed")
        for value, field_name in (
            (tls_peer_verified, "TLS-peer flag"),
            (redirects_followed, "redirect flag"),
            (proxy_used, "proxy flag"),
            (complete, "completion flag"),
            (timed_out, "timeout flag"),
            (transport_error, "transport-error flag"),
        ):
            if type(value) is not bool:
                raise EtradeOAuthTokenResponseError(
                    f"injected response {field_name} must be exact boolean"
                )
        lock = Lock()
        object.__setattr__(self, "_EtradeOAuthRawTokenResponse__lock", lock)
        object.__setattr__(self, "_EtradeOAuthRawTokenResponse__original_lock", lock)
        object.__setattr__(self, "_EtradeOAuthRawTokenResponse__request", request)
        object.__setattr__(
            self,
            "_EtradeOAuthRawTokenResponse__request_binding_material",
            request._sealed_response_binding_material(),
        )
        object.__setattr__(
            self,
            "_EtradeOAuthRawTokenResponse__origin_exact",
            response_origin == ETRADE_SHARED_TOKEN_ORIGIN,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthRawTokenResponse__http_status_exact",
            http_status == 200,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthRawTokenResponse__media_type_exact",
            media_type == ETRADE_OAUTH_TOKEN_RESPONSE_MEDIA_TYPE,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthRawTokenResponse__charset_exact",
            charset == ETRADE_OAUTH_TOKEN_RESPONSE_CHARSET,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthRawTokenResponse__body",
            bytearray(body),
        )
        object.__setattr__(
            self,
            "_EtradeOAuthRawTokenResponse__tls_peer_verified",
            tls_peer_verified,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthRawTokenResponse__redirects_followed",
            redirects_followed,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthRawTokenResponse__redirect_location_present",
            redirect_location is not None,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthRawTokenResponse__proxy_used",
            proxy_used,
        )
        object.__setattr__(self, "_EtradeOAuthRawTokenResponse__complete", complete)
        object.__setattr__(self, "_EtradeOAuthRawTokenResponse__timed_out", timed_out)
        object.__setattr__(
            self,
            "_EtradeOAuthRawTokenResponse__transport_error",
            transport_error,
        )
        object.__setattr__(self, "_EtradeOAuthRawTokenResponse__closed", False)
        object.__setattr__(
            self,
            "_EtradeOAuthRawTokenResponse__sealed_metadata_sha256",
            _semantic_sha256(
                (
                    ETRADE_OAUTH_TOKEN_RUNTIME_CONTRACT_VERSION,
                    "sealed_raw_token_response_metadata",
                    self._sanitized_binding_material_unlocked(),
                )
            ),
        )

    def _exact_lock(self, expected_identity: object | None = None) -> Any:
        lock = object.__getattribute__(
            self,
            "_EtradeOAuthRawTokenResponse__lock",
        )
        original_lock = object.__getattribute__(
            self,
            "_EtradeOAuthRawTokenResponse__original_lock",
        )
        if (
            type(lock) is not _LOCK_TYPE
            or lock is not original_lock
            or (expected_identity is not None and lock is not expected_identity)
        ):
            raise EtradeOAuthTokenResponseError("ephemeral raw token response lock was replaced")
        return lock

    def _lock_identity_for_runtime_validation(self) -> object:
        """Capture the exact post-dispatch lock without entering a foreign context."""

        return self._exact_lock()

    def _require_lock_identity_unlocked(self, expected_identity: object) -> None:
        if (
            type(expected_identity) is not _LOCK_TYPE
            or self.__lock is not expected_identity
            or self.__original_lock is not expected_identity
        ):
            raise EtradeOAuthTokenResponseError(
                "ephemeral raw token response lock identity changed"
            )

    def _validate_for(
        self,
        request: EtradeOAuthEphemeralTransportRequest,
        *,
        lock_identity: object,
    ) -> None:
        _require_exact(request, EtradeOAuthEphemeralTransportRequest, "response request")
        request_binding_material = request._sealed_response_binding_material()
        with self._exact_lock(lock_identity):
            self._require_lock_identity_unlocked(lock_identity)
            self._require_open_unlocked()
            if (
                self.__request is not request
                or self.__request_binding_material != request_binding_material
                or self.__sealed_metadata_sha256
                != _semantic_sha256(
                    (
                        ETRADE_OAUTH_TOKEN_RUNTIME_CONTRACT_VERSION,
                        "sealed_raw_token_response_metadata",
                        self._sanitized_binding_material_unlocked(),
                    )
                )
            ):
                raise EtradeOAuthTokenResponseError(
                    "injected response binding or metadata was mutated"
                )
            _require_exact_true(self.__origin_exact, "exact-origin binding")
            _require_exact_true(self.__http_status_exact, "exact success status")
            _require_exact_true(self.__media_type_exact, "exact media type")
            _require_exact_true(self.__charset_exact, "exact charset")
            _require_exact_true(self.__tls_peer_verified, "TLS-peer verification")
            _require_exact_false(self.__redirects_followed, "redirect-following")
            _require_exact_false(
                self.__redirect_location_present,
                "redirect-location ambiguity",
            )
            _require_exact_false(self.__proxy_used, "proxy use")
            _require_exact_true(self.__complete, "response completeness")
            _require_exact_false(self.__timed_out, "timeout")
            _require_exact_false(self.__transport_error, "transport error")

    def _body_copy(self, *, lock_identity: object) -> bytearray:
        with self._exact_lock(lock_identity):
            self._require_lock_identity_unlocked(lock_identity)
            self._require_open_unlocked()
            expected_length = len(self.__body)
            body = bytearray(self.__body)
            self._require_lock_identity_unlocked(lock_identity)
            self._require_open_unlocked()
            if len(body) != expected_length:
                for index in range(len(body)):
                    body[index] = 0
                raise EtradeOAuthTokenResponseError(
                    "ephemeral raw token response custody changed during its read"
                )
            return body

    def _sanitized_binding_material(self, *, lock_identity: object) -> tuple[object, ...]:
        with self._exact_lock(lock_identity):
            self._require_lock_identity_unlocked(lock_identity)
            self._require_open_unlocked()
            return self._sanitized_binding_material_unlocked()

    def _sanitized_binding_material_unlocked(self) -> tuple[object, ...]:
        return (
            ETRADE_OAUTH_TOKEN_RUNTIME_CONTRACT_VERSION,
            "secret_independent_injected_response_binding",
            *self.__request_binding_material,
            ETRADE_SHARED_TOKEN_ORIGIN,
            200,
            ETRADE_OAUTH_TOKEN_RESPONSE_MEDIA_TYPE,
            ETRADE_OAUTH_TOKEN_RESPONSE_CHARSET,
            self.__tls_peer_verified,
            self.__redirects_followed,
            self.__redirect_location_present,
            self.__proxy_used,
            self.__complete,
            self.__timed_out,
            self.__transport_error,
            "raw_body_and_digest_excluded",
        )

    def _require_open_unlocked(self) -> None:
        if self.__closed:
            raise EtradeOAuthTokenResponseError("ephemeral raw token response is closed")
        if (
            type(self.__body) is not bytearray
            or not 1 <= len(self.__body) <= ETRADE_OAUTH_TOKEN_RESPONSE_MAX_BYTES
        ):
            raise EtradeOAuthTokenResponseError(
                "ephemeral raw token response custody is structurally malformed"
            )

    def _require_open(self, *, lock_identity: object) -> None:
        with self._exact_lock(lock_identity):
            self._require_lock_identity_unlocked(lock_identity)
            self._require_open_unlocked()

    def _is_retained_for_runtime(self, *, lock_identity: object) -> bool:
        with self._exact_lock(lock_identity):
            self._require_lock_identity_unlocked(lock_identity)
            return not self.__closed

    def _close_unlocked(self) -> None:
        if self.__closed:
            return
        body = self.__body
        if type(body) is bytearray:
            for index in range(len(body)):
                body[index] = 0
        else:
            object.__setattr__(self, "_EtradeOAuthRawTokenResponse__body", bytearray())
        object.__setattr__(self, "_EtradeOAuthRawTokenResponse__closed", True)

    def _close_with_runtime_lock_identity(self, lock_identity: object) -> None:
        """Close with a runtime-held factory lock, ignoring replaced lock fields."""

        if type(lock_identity) is not _LOCK_TYPE:
            raise EtradeOAuthTokenResponseError(
                "ephemeral raw token response cleanup lock is malformed"
            )
        with lock_identity:
            object.__setattr__(self, "_EtradeOAuthRawTokenResponse__lock", lock_identity)
            object.__setattr__(
                self,
                "_EtradeOAuthRawTokenResponse__original_lock",
                lock_identity,
            )
            self._close_unlocked()

    def close(self) -> None:
        original_lock = object.__getattribute__(
            self,
            "_EtradeOAuthRawTokenResponse__original_lock",
        )
        if type(original_lock) is _LOCK_TYPE:
            lock_context = original_lock
            object.__setattr__(
                self,
                "_EtradeOAuthRawTokenResponse__lock",
                original_lock,
            )
        else:
            lock_context = Lock()
            object.__setattr__(
                self,
                "_EtradeOAuthRawTokenResponse__lock",
                lock_context,
            )
            object.__setattr__(
                self,
                "_EtradeOAuthRawTokenResponse__original_lock",
                lock_context,
            )
        with lock_context:
            self._close_unlocked()

    @property
    def closed(self) -> bool:
        with self._exact_lock():
            return self.__closed

    def __enter__(self) -> _EtradeOAuthRawTokenResponse:
        with self._exact_lock():
            self._require_open_unlocked()
            return self

    def __exit__(self, *args: object) -> None:
        del args
        self.close()

    def __repr__(self) -> str:
        with self._exact_lock():
            return f"_EtradeOAuthRawTokenResponse(<redacted>, closed={self.__closed})"

    def __str__(self) -> str:
        return "<redacted E*TRADE OAuth raw token response>"

    def __setattr__(self, name: str, value: object) -> Never:
        del name, value
        raise AttributeError("ephemeral raw OAuth responses are sealed")

    def __reduce__(self) -> Never:
        raise TypeError("ephemeral raw OAuth responses are non-serializable")

    def __copy__(self) -> Never:
        raise TypeError("ephemeral raw OAuth responses cannot be copied")

    def __deepcopy__(self, memo: object) -> Never:
        del memo
        raise TypeError("ephemeral raw OAuth responses cannot be copied")

    def __del__(self) -> None:
        with suppress(Exception):
            self.close()


def create_etrade_oauth_injected_token_response(
    request: EtradeOAuthEphemeralTransportRequest,
    *,
    response_origin: str = ETRADE_SHARED_TOKEN_ORIGIN,
    http_status: int = 200,
    media_type: str = ETRADE_OAUTH_TOKEN_RESPONSE_MEDIA_TYPE,
    charset: str = ETRADE_OAUTH_TOKEN_RESPONSE_CHARSET,
    body: bytes,
    tls_peer_verified: bool = True,
    redirects_followed: bool = False,
    redirect_location: str | None = None,
    proxy_used: bool = False,
    complete: bool = True,
    timed_out: bool = False,
    transport_error: bool = False,
) -> object:
    """Bind exact raw test bytes to one presented signed-request capability."""

    _require_exact(request, EtradeOAuthEphemeralTransportRequest, "injected transport request")
    request._present_for_injected_exchange()
    response = _EtradeOAuthRawTokenResponse(
        request,
        issuer=_RAW_TOKEN_RESPONSE_ISSUER,
        response_origin=response_origin,
        http_status=http_status,
        media_type=media_type,
        charset=charset,
        body=body,
        tls_peer_verified=tls_peer_verified,
        redirects_followed=redirects_followed,
        redirect_location=redirect_location,
        proxy_used=proxy_used,
        complete=complete,
        timed_out=timed_out,
        transport_error=transport_error,
    )
    try:
        dispatch_witness = _registered_raw_response_dispatch_witness(request)
        dispatch_witness._bind_constructor_raw_response(
            request=request,
            response=response,
        )
        request._bind_response_custody(response)
    except Exception:
        response.close()
        raise
    return response


class EtradeOAuthInjectedTokenTransport(Protocol):
    """Fake/injected transport port with no concrete provider implementation."""

    @property
    def transport_id(self) -> str: ...

    @property
    def transport_version(self) -> str: ...

    def _exchange_for_token_runtime(
        self,
        request: EtradeOAuthEphemeralTransportRequest,
    ) -> object: ...


_TOKEN_EXCHANGE_RECEIPT_ISSUER = object()


@dataclass(frozen=True, slots=True, init=False)
class EtradeOAuthTokenExchangeReceipt:
    """Sanitized receipt; token bytes and their digest are deliberately absent."""

    environment: EtradeEnvironment
    operation: EtradeOAuthOperation
    signing_intent_sha256: str
    durable_scope_sha256: str
    replay_event_sha256: str
    replay_sequence: int
    replay_guard_sha256: str
    issued_token_reference: EtradeOAuthTokenSecretReference
    secret_independent_response_binding_sha256: str
    resolver_id: str
    resolver_version: str
    transport_id: str
    transport_version: str
    response_origin: str
    media_type: str
    charset: str
    http_status: int
    _sealed_fields_sha256: str = field(init=False, repr=False, compare=False)

    def __init__(
        self,
        *,
        issuer: object,
        environment: EtradeEnvironment,
        operation: EtradeOAuthOperation,
        signing_intent_sha256: str,
        durable_scope_sha256: str,
        replay_event_sha256: str,
        replay_sequence: int,
        replay_guard_sha256: str,
        issued_token_reference: EtradeOAuthTokenSecretReference,
        secret_independent_response_binding_sha256: str,
    ) -> None:
        if issuer is not _TOKEN_EXCHANGE_RECEIPT_ISSUER:
            raise EtradeOAuthTokenRuntimeError(
                "token exchange receipts require the private runtime issuer"
            )
        object.__setattr__(self, "environment", environment)
        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "signing_intent_sha256", signing_intent_sha256)
        object.__setattr__(self, "durable_scope_sha256", durable_scope_sha256)
        object.__setattr__(self, "replay_event_sha256", replay_event_sha256)
        object.__setattr__(self, "replay_sequence", replay_sequence)
        object.__setattr__(self, "replay_guard_sha256", replay_guard_sha256)
        object.__setattr__(self, "issued_token_reference", issued_token_reference)
        object.__setattr__(
            self,
            "secret_independent_response_binding_sha256",
            secret_independent_response_binding_sha256,
        )
        object.__setattr__(self, "resolver_id", ETRADE_OAUTH_INJECTED_RESOLVER_ID)
        object.__setattr__(
            self,
            "resolver_version",
            ETRADE_OAUTH_INJECTED_RESOLVER_VERSION,
        )
        object.__setattr__(self, "transport_id", ETRADE_OAUTH_INJECTED_TRANSPORT_ID)
        object.__setattr__(
            self,
            "transport_version",
            ETRADE_OAUTH_INJECTED_TRANSPORT_VERSION,
        )
        object.__setattr__(self, "response_origin", ETRADE_SHARED_TOKEN_ORIGIN)
        object.__setattr__(self, "media_type", ETRADE_OAUTH_TOKEN_RESPONSE_MEDIA_TYPE)
        object.__setattr__(self, "charset", ETRADE_OAUTH_TOKEN_RESPONSE_CHARSET)
        object.__setattr__(self, "http_status", 200)
        object.__setattr__(
            self,
            "_sealed_fields_sha256",
            _semantic_sha256(
                (
                    ETRADE_OAUTH_TOKEN_RUNTIME_CONTRACT_VERSION,
                    "sealed_token_exchange_receipt_fields",
                    self._semantic_material(),
                )
            ),
        )
        self._validate()

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ETRADE_OAUTH_TOKEN_RUNTIME_CONTRACT_VERSION,
            "sanitized_token_exchange_receipt",
            ETRADE_PROVIDER.value,
            self.environment,
            self.operation,
            self.signing_intent_sha256,
            self.durable_scope_sha256,
            self.replay_event_sha256,
            self.replay_sequence,
            self.replay_guard_sha256,
            self.issued_token_reference.semantic_sha256,
            self.secret_independent_response_binding_sha256,
            self.resolver_id,
            self.resolver_version,
            self.transport_id,
            self.transport_version,
            self.response_origin,
            self.media_type,
            self.charset,
            self.http_status,
            "raw_response_bytes_and_digest_excluded",
        )

    def _validate(self) -> None:
        _require_exact(self.environment, EtradeEnvironment, "token receipt environment")
        _require_exact(self.operation, EtradeOAuthOperation, "token receipt operation")
        if self.operation not in (
            EtradeOAuthOperation.REQUEST_TOKEN,
            EtradeOAuthOperation.ACCESS_TOKEN,
        ):
            raise EtradeOAuthTokenRuntimeError("token receipt operation is unsupported")
        for value, field_name in (
            (self.signing_intent_sha256, "token receipt signing intent"),
            (self.durable_scope_sha256, "token receipt durable scope"),
            (self.replay_event_sha256, "token receipt replay event"),
            (self.replay_guard_sha256, "token receipt replay guard"),
            (
                self.secret_independent_response_binding_sha256,
                "token receipt response binding",
            ),
        ):
            _require_sha256(value, field_name)
        if type(self.replay_sequence) is not int or self.replay_sequence < 2:
            raise EtradeOAuthTokenRuntimeError("token receipt replay sequence is invalid")
        _require_exact(
            self.issued_token_reference,
            EtradeOAuthTokenSecretReference,
            "token receipt issued reference",
        )
        self.issued_token_reference.__post_init__()
        expected_kind = (
            EtradeOAuthTokenKind.REQUEST_TOKEN
            if self.operation is EtradeOAuthOperation.REQUEST_TOKEN
            else EtradeOAuthTokenKind.ACCESS_TOKEN
        )
        expected_scope = (
            EtradeSecretScope.SANDBOX_TOKEN
            if self.environment is EtradeEnvironment.SANDBOX
            else EtradeSecretScope.PRODUCTION_TOKEN
        )
        if (
            self.issued_token_reference.environment is not self.environment
            or self.issued_token_reference.scope is not expected_scope
            or self.issued_token_reference.kind is not expected_kind
        ):
            raise EtradeOAuthTokenRuntimeError(
                "token receipt reference conflicts with environment or operation"
            )
        exact_metadata = (
            (self.resolver_id, ETRADE_OAUTH_INJECTED_RESOLVER_ID),
            (self.resolver_version, ETRADE_OAUTH_INJECTED_RESOLVER_VERSION),
            (self.transport_id, ETRADE_OAUTH_INJECTED_TRANSPORT_ID),
            (self.transport_version, ETRADE_OAUTH_INJECTED_TRANSPORT_VERSION),
            (self.response_origin, ETRADE_SHARED_TOKEN_ORIGIN),
            (self.media_type, ETRADE_OAUTH_TOKEN_RESPONSE_MEDIA_TYPE),
            (self.charset, ETRADE_OAUTH_TOKEN_RESPONSE_CHARSET),
            (self.http_status, 200),
        )
        if any(
            type(value) is not type(expected) or value != expected
            for value, expected in exact_metadata
        ):
            raise EtradeOAuthTokenRuntimeError("token receipt exact metadata drifted")
        _require_sha256(self._sealed_fields_sha256, "token receipt sealed fields")
        if self._sealed_fields_sha256 != _semantic_sha256(
            (
                ETRADE_OAUTH_TOKEN_RUNTIME_CONTRACT_VERSION,
                "sealed_token_exchange_receipt_fields",
                self._semantic_material(),
            )
        ):
            raise EtradeOAuthTokenRuntimeError("token receipt sealed fields were mutated")

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(self._semantic_material())

    @property
    def raw_response_ephemeral_custody_required(self) -> bool:
        return True

    @property
    def raw_response_persisted(self) -> bool:
        return False

    @property
    def raw_response_digest_retained(self) -> bool:
        return False

    @property
    def signed_request_capability_presented(self) -> bool:
        return True

    @property
    def injected_request_response_structurally_bound(self) -> bool:
        return True

    @property
    def provider_origin_authenticated(self) -> bool:
        return False

    @property
    def authority(self) -> Mapping[str, bool]:
        return _authority()

    def __reduce__(self) -> Never:
        raise TypeError("token exchange receipts are runtime-issued and non-serializable")

    def __copy__(self) -> Never:
        raise TypeError("token exchange receipts cannot be copied")

    def __deepcopy__(self, memo: object) -> Never:
        del memo
        raise TypeError("token exchange receipts cannot be copied")


_TOKEN_EXCHANGE_RESULT_ISSUER = object()


class EtradeOAuthEphemeralTokenExchangeResult:
    """Closable raw-first response plus a non-authorizing state proposal."""

    __slots__ = (
        "__claimed",
        "__closed",
        "__issued_token_reference",
        "__lock",
        "__raw_response",
        "__raw_response_binding_sha256",
        "__raw_response_lock_identity",
        "__receipt",
        "__receipt_sha256",
        "__replay_snapshot",
        "__replay_snapshot_sha256",
        "__successor_state",
        "__successor_state_sha256",
        "__token",
        "__token_secret",
    )
    __claimed: bool
    __closed: bool
    __issued_token_reference: EtradeOAuthTokenSecretReference
    __lock: Any
    __raw_response: _EtradeOAuthRawTokenResponse
    __raw_response_binding_sha256: str
    __raw_response_lock_identity: object
    __receipt: EtradeOAuthTokenExchangeReceipt
    __receipt_sha256: str
    __replay_snapshot: EtradeOAuthDurableSnapshot
    __replay_snapshot_sha256: str
    __successor_state: EtradeOAuthSessionState
    __successor_state_sha256: str
    __token: bytearray
    __token_secret: bytearray

    def __init__(
        self,
        *,
        issuer: object,
        receipt: EtradeOAuthTokenExchangeReceipt,
        replay_snapshot: EtradeOAuthDurableSnapshot,
        successor_state: EtradeOAuthSessionState,
        raw_response: _EtradeOAuthRawTokenResponse,
        raw_response_lock_identity: object,
        token: bytearray,
        token_secret: bytearray,
    ) -> None:
        if issuer is not _TOKEN_EXCHANGE_RESULT_ISSUER:
            raise EtradeOAuthTokenResponseError(
                "ephemeral token results require the private runtime issuer"
            )
        _require_exact(receipt, EtradeOAuthTokenExchangeReceipt, "token exchange receipt")
        receipt._validate()
        replay_snapshot = _validate_snapshot(replay_snapshot)
        _require_exact(successor_state, EtradeOAuthSessionState, "token successor state")
        successor_state.__post_init__()
        _require_exact(raw_response, _EtradeOAuthRawTokenResponse, "raw token response")
        raw_response._require_open(lock_identity=raw_response_lock_identity)
        raw_response_binding_sha256 = _semantic_sha256(
            raw_response._sanitized_binding_material(
                lock_identity=raw_response_lock_identity,
            )
        )
        receipt_sha256 = receipt.semantic_sha256
        if type(token) is not bytearray or type(token_secret) is not bytearray:
            raise EtradeOAuthTokenResponseError("decoded token custody is malformed")
        expected_reference = (
            successor_state.request_token_reference
            if receipt.operation is EtradeOAuthOperation.REQUEST_TOKEN
            else successor_state.access_token_reference
        )
        if (
            receipt.environment is not replay_snapshot.state.environment
            or receipt.durable_scope_sha256 != replay_snapshot.scope_sha256
            or receipt.replay_event_sha256 != replay_snapshot.current_event_sha256
            or receipt.replay_sequence != replay_snapshot.sequence
            or receipt.replay_guard_sha256 != replay_snapshot.replay_guard.semantic_sha256
            or receipt.issued_token_reference != expected_reference
            or receipt.secret_independent_response_binding_sha256 != raw_response_binding_sha256
            or successor_state.environment is not receipt.environment
            or successor_state.predecessor_sha256 != replay_snapshot.state.semantic_sha256
            or successor_state.transition_evidence_sha256 != receipt.signing_intent_sha256
        ):
            raise EtradeOAuthTokenResponseError(
                "ephemeral token result cross-bindings are inconsistent"
            )
        object.__setattr__(self, "_EtradeOAuthEphemeralTokenExchangeResult__lock", Lock())
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTokenExchangeResult__receipt",
            receipt,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTokenExchangeResult__receipt_sha256",
            receipt_sha256,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTokenExchangeResult__replay_snapshot",
            replay_snapshot,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTokenExchangeResult__replay_snapshot_sha256",
            _semantic_sha256(
                (
                    replay_snapshot.scope_sha256,
                    replay_snapshot.current_event_sha256,
                    replay_snapshot.sequence,
                    replay_snapshot.state.semantic_sha256,
                    replay_snapshot.replay_guard.semantic_sha256,
                )
            ),
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTokenExchangeResult__successor_state",
            successor_state,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTokenExchangeResult__successor_state_sha256",
            successor_state.semantic_sha256,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTokenExchangeResult__issued_token_reference",
            receipt.issued_token_reference,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTokenExchangeResult__raw_response",
            raw_response,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTokenExchangeResult__raw_response_binding_sha256",
            raw_response_binding_sha256,
        )
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTokenExchangeResult__raw_response_lock_identity",
            raw_response_lock_identity,
        )
        object.__setattr__(self, "_EtradeOAuthEphemeralTokenExchangeResult__token", token)
        object.__setattr__(
            self,
            "_EtradeOAuthEphemeralTokenExchangeResult__token_secret",
            token_secret,
        )
        object.__setattr__(self, "_EtradeOAuthEphemeralTokenExchangeResult__claimed", False)
        object.__setattr__(self, "_EtradeOAuthEphemeralTokenExchangeResult__closed", False)
        with self.__lock:
            self._validate_unlocked()

    def _validate_unlocked(self) -> None:
        if self.__closed:
            raise EtradeOAuthTokenResolverLifecycleError("ephemeral OAuth token result is closed")
        try:
            if (
                type(self.__receipt) is not EtradeOAuthTokenExchangeReceipt
                or type(self.__replay_snapshot) is not EtradeOAuthDurableSnapshot
                or type(self.__successor_state) is not EtradeOAuthSessionState
                or type(self.__issued_token_reference) is not EtradeOAuthTokenSecretReference
                or type(self.__raw_response) is not _EtradeOAuthRawTokenResponse
                or type(self.__raw_response_lock_identity) is not _LOCK_TYPE
                or type(self.__token) is not bytearray
                or type(self.__token_secret) is not bytearray
            ):
                raise TypeError
            self.__receipt._validate()
            replay_snapshot = _validate_snapshot(self.__replay_snapshot)
            self.__successor_state.__post_init__()
            self.__issued_token_reference.__post_init__()
            self.__raw_response._require_open(
                lock_identity=self.__raw_response_lock_identity,
            )
            expected_reference = (
                self.__successor_state.request_token_reference
                if self.__receipt.operation is EtradeOAuthOperation.REQUEST_TOKEN
                else self.__successor_state.access_token_reference
            )
            raw_response_binding_sha256 = _semantic_sha256(
                self.__raw_response._sanitized_binding_material(
                    lock_identity=self.__raw_response_lock_identity,
                )
            )
            invalid = (
                self.__receipt.semantic_sha256 != self.__receipt_sha256
                or self.__receipt.environment is not replay_snapshot.state.environment
                or self.__receipt.durable_scope_sha256 != replay_snapshot.scope_sha256
                or self.__receipt.replay_event_sha256 != replay_snapshot.current_event_sha256
                or self.__receipt.replay_sequence != replay_snapshot.sequence
                or self.__receipt.replay_guard_sha256
                != replay_snapshot.replay_guard.semantic_sha256
                or self.__receipt.issued_token_reference != expected_reference
                or self.__receipt.issued_token_reference != self.__issued_token_reference
                or self.__receipt.secret_independent_response_binding_sha256
                != raw_response_binding_sha256
                or raw_response_binding_sha256 != self.__raw_response_binding_sha256
                or self.__successor_state.environment is not self.__receipt.environment
                or self.__successor_state.predecessor_sha256
                != replay_snapshot.state.semantic_sha256
                or self.__successor_state.transition_evidence_sha256
                != self.__receipt.signing_intent_sha256
                or self.__issued_token_reference != expected_reference
                or self.__issued_token_reference.environment
                is not replay_snapshot.state.environment
                or _semantic_sha256(
                    (
                        replay_snapshot.scope_sha256,
                        replay_snapshot.current_event_sha256,
                        replay_snapshot.sequence,
                        replay_snapshot.state.semantic_sha256,
                        replay_snapshot.replay_guard.semantic_sha256,
                    )
                )
                != self.__replay_snapshot_sha256
                or self.__successor_state.semantic_sha256 != self.__successor_state_sha256
            )
        except Exception:
            raise EtradeOAuthTokenResponseError(
                "sealed ephemeral token result was mutated"
            ) from None
        if invalid:
            raise EtradeOAuthTokenResponseError("sealed ephemeral token result was mutated")

    def _close_unlocked(self) -> None:
        if self.__closed:
            return
        raw_response = self.__raw_response
        if type(raw_response) is _EtradeOAuthRawTokenResponse:
            raw_response._close_with_runtime_lock_identity(
                self.__raw_response_lock_identity,
            )
        for field_name in ("__token", "__token_secret"):
            secret = object.__getattribute__(
                self,
                f"_EtradeOAuthEphemeralTokenExchangeResult{field_name}",
            )
            if type(secret) is bytearray:
                for index in range(len(secret)):
                    secret[index] = 0
            else:
                object.__setattr__(
                    self,
                    f"_EtradeOAuthEphemeralTokenExchangeResult{field_name}",
                    bytearray(),
                )
        object.__setattr__(self, "_EtradeOAuthEphemeralTokenExchangeResult__closed", True)

    def _matches_test_values_once(self, expected_token: str, expected_token_secret: str) -> bool:
        """Consume custody through one constant-time synthetic-vector predicate."""

        with self.__lock:
            self._validate_unlocked()
            if self.__claimed:
                raise EtradeOAuthTokenResolverLifecycleError(
                    "ephemeral OAuth token result was already claimed"
                )
            object.__setattr__(
                self,
                "_EtradeOAuthEphemeralTokenExchangeResult__claimed",
                True,
            )
            if type(expected_token) is not str or type(expected_token_secret) is not str:
                self._close_unlocked()
                return False
            try:
                token = expected_token.encode("ascii", errors="strict")
                token_secret = expected_token_secret.encode("ascii", errors="strict")
            except UnicodeEncodeError:
                self._close_unlocked()
                return False
            try:
                return hmac.compare_digest(
                    bytes(self.__token),
                    token,
                ) and hmac.compare_digest(bytes(self.__token_secret), token_secret)
            finally:
                self._close_unlocked()

    def _require_open(self) -> None:
        with self.__lock:
            self._validate_unlocked()

    @property
    def receipt(self) -> EtradeOAuthTokenExchangeReceipt:
        with self.__lock:
            self._validate_unlocked()
            return self.__receipt

    @property
    def replay_snapshot(self) -> EtradeOAuthDurableSnapshot:
        with self.__lock:
            self._validate_unlocked()
            return self.__replay_snapshot

    @property
    def successor_state(self) -> EtradeOAuthSessionState:
        with self.__lock:
            self._validate_unlocked()
            return self.__successor_state

    @property
    def issued_token_reference(self) -> EtradeOAuthTokenSecretReference:
        with self.__lock:
            self._validate_unlocked()
            return self.__issued_token_reference

    @property
    def closed(self) -> bool:
        with self.__lock:
            return self.__closed

    @property
    def raw_response_retained(self) -> bool:
        with self.__lock:
            if self.__closed:
                return False
            return self.__raw_response._is_retained_for_runtime(
                lock_identity=self.__raw_response_lock_identity,
            )

    @property
    def session_head_transition_authorized(self) -> bool:
        return False

    @property
    def token_secret_persistence_authorized(self) -> bool:
        return False

    @property
    def post_transport_secret_store_atomicity_qualified(self) -> bool:
        return False

    @property
    def provider_network_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False

    @property
    def authority(self) -> Mapping[str, bool]:
        return _authority()

    def close(self) -> None:
        with self.__lock:
            self._close_unlocked()

    def __enter__(self) -> EtradeOAuthEphemeralTokenExchangeResult:
        with self.__lock:
            self._validate_unlocked()
            if self.__claimed:
                raise EtradeOAuthTokenResolverLifecycleError(
                    "ephemeral OAuth token result was already claimed"
                )
            object.__setattr__(
                self,
                "_EtradeOAuthEphemeralTokenExchangeResult__claimed",
                True,
            )
            return self

    def __exit__(self, *args: object) -> None:
        del args
        self.close()

    def __repr__(self) -> str:
        with self.__lock:
            return (
                "EtradeOAuthEphemeralTokenExchangeResult("
                f"receipt_sha256={self.__receipt.semantic_sha256!r}, token=<redacted>, "
                f"token_secret=<redacted>, raw_response=<redacted>, closed={self.__closed})"
            )

    def __str__(self) -> str:
        return "<redacted E*TRADE OAuth token exchange result>"

    def __setattr__(self, name: str, value: object) -> Never:
        del name, value
        raise AttributeError("ephemeral OAuth token results are sealed")

    def __reduce__(self) -> Never:
        raise TypeError("ephemeral OAuth token results are non-serializable")

    def __copy__(self) -> Never:
        raise TypeError("ephemeral OAuth token results cannot be copied")

    def __deepcopy__(self, memo: object) -> Never:
        del memo
        raise TypeError("ephemeral OAuth token results cannot be copied")

    def __del__(self) -> None:
        with suppress(Exception):
            self.close()


def _validate_snapshot(snapshot: object) -> EtradeOAuthDurableSnapshot:
    try:
        return authenticate_etrade_oauth_durable_snapshot(snapshot)
    except Exception:
        raise EtradeOAuthTokenReplayError(
            "sanitized durable OAuth snapshot is inconsistent"
        ) from None


def _clone_signing_intent(intent: object) -> EtradeOAuthSigningIntent:
    """Create an exact value clone that is never shared with an injected port."""

    try:
        _require_exact(intent, EtradeOAuthSigningIntent, "OAuth token signing intent")
        source = cast(EtradeOAuthSigningIntent, intent)
        source.__post_init__()
        callback_policy = replace(source.callback_policy)
        endpoint_profile = replace(
            source.endpoint_profile,
            callback_policy=callback_policy,
        )
        clone = replace(
            source,
            endpoint_profile=endpoint_profile,
            consumer_reference=replace(source.consumer_reference),
            token_reference=(
                None if source.token_reference is None else replace(source.token_reference)
            ),
            timestamp=replace(source.timestamp),
            nonce=replace(source.nonce),
            callback_policy=callback_policy,
        )
        clone.__post_init__()
        if (
            clone is source
            or clone.endpoint_profile is source.endpoint_profile
            or clone.consumer_reference is source.consumer_reference
            or clone.timestamp is source.timestamp
            or clone.nonce is source.nonce
            or clone.callback_policy is source.callback_policy
            or (
                source.token_reference is not None
                and clone.token_reference is source.token_reference
            )
            or clone.semantic_sha256 != source.semantic_sha256
            or clone.to_evidence_bytes() != source.to_evidence_bytes()
        ):
            raise ValueError
        return clone
    except Exception:
        raise EtradeOAuthTokenRuntimeError(
            "OAuth token signing intent could not be independently value-cloned"
        ) from None


def _clone_token_reference(reference: object) -> EtradeOAuthTokenSecretReference:
    try:
        _require_exact(
            reference,
            EtradeOAuthTokenSecretReference,
            "issued OAuth token reference",
        )
        source = cast(EtradeOAuthTokenSecretReference, reference)
        source.__post_init__()
        clone = replace(source)
        clone.__post_init__()
        if clone is source or clone != source:
            raise ValueError
        return clone
    except Exception:
        raise EtradeOAuthTokenRuntimeError(
            "issued OAuth token reference could not be independently value-cloned"
        ) from None


def _clone_optional_timestamp(
    timestamp: EtradeOAuthTrustedTimestamp | None,
) -> EtradeOAuthTrustedTimestamp | None:
    if timestamp is None:
        return None
    try:
        _require_exact(timestamp, EtradeOAuthTrustedTimestamp, "access-token expiry")
        clone = replace(timestamp)
        clone.__post_init__()
        if clone is timestamp or clone != timestamp:
            raise ValueError
        return clone
    except Exception:
        raise EtradeOAuthTokenRuntimeError(
            "access-token expiry could not be independently value-cloned"
        ) from None


def _validate_preflight(
    snapshot: EtradeOAuthDurableSnapshot,
    intent: EtradeOAuthSigningIntent,
    issued_token_reference: EtradeOAuthTokenSecretReference,
    expires_at: EtradeOAuthTrustedTimestamp | None,
    verifier: EtradeOAuthBoundVerifier | None,
    access_exchange_capability: EtradeOAuthAccessExchangeCapability | None,
) -> tuple[EtradeOAuthAccessExchangeCapability | None, object | None]:
    state = snapshot.state
    _require_exact(intent, EtradeOAuthSigningIntent, "OAuth token signing intent")
    intent.__post_init__()
    _require_exact(
        issued_token_reference,
        EtradeOAuthTokenSecretReference,
        "issued OAuth token reference",
    )
    issued_token_reference.__post_init__()
    if intent.operation not in (
        EtradeOAuthOperation.REQUEST_TOKEN,
        EtradeOAuthOperation.ACCESS_TOKEN,
    ):
        raise EtradeOAuthTokenRuntimeError(
            "injected token runtime supports only request-token and access-token exchange"
        )
    if (
        intent.environment is not state.environment
        or intent.endpoint_profile.semantic_sha256 != state.endpoint_profile_sha256
        or intent.consumer_reference != state.consumer_reference
        or intent.generation != state.generation
        or intent.timestamp.unix_seconds < state.trusted_time_high_water_seconds
    ):
        raise EtradeOAuthTokenRuntimeError(
            "OAuth token intent conflicts with the sanitized durable session head"
        )
    expected_kind = (
        EtradeOAuthTokenKind.REQUEST_TOKEN
        if intent.operation is EtradeOAuthOperation.REQUEST_TOKEN
        else EtradeOAuthTokenKind.ACCESS_TOKEN
    )
    expected_token_scope = (
        EtradeSecretScope.SANDBOX_TOKEN
        if state.environment is EtradeEnvironment.SANDBOX
        else EtradeSecretScope.PRODUCTION_TOKEN
    )
    if (
        issued_token_reference.environment is not state.environment
        or issued_token_reference.scope is not expected_token_scope
    ):
        raise EtradeOAuthTokenRuntimeError(
            "issued token reference conflicts with the session environment or scope"
        )
    if (
        issued_token_reference.kind is not expected_kind
        or issued_token_reference.version != state.highest_token_reference_version + 1
    ):
        raise EtradeOAuthTokenRuntimeError(
            "issued token reference kind or revision is not the exact next value"
        )
    if intent.operation is EtradeOAuthOperation.REQUEST_TOKEN:
        if (
            state.phase is not EtradeOAuthSessionPhase.NEEDS_REQUEST_TOKEN
            or intent.token_reference is not None
            or expires_at is not None
            or verifier is not None
            or access_exchange_capability is not None
        ):
            raise EtradeOAuthTokenRuntimeError(
                "request-token runtime inputs conflict with the current session phase"
            )
        return None, None
    else:
        if (
            state.phase is not EtradeOAuthSessionPhase.AUTHORIZATION_CONFIRMED
            or intent.token_reference != state.request_token_reference
            or intent.authorization_challenge_sha256 != state.authorization_challenge_sha256
            or intent.authorization_state_sha256 != state.semantic_sha256
        ):
            raise EtradeOAuthTokenRuntimeError(
                "access-token runtime intent conflicts with the confirmed session"
            )
        _require_exact(verifier, EtradeOAuthBoundVerifier, "access-token verifier")
        cast(EtradeOAuthBoundVerifier, verifier)._validate()
        _require_exact(
            access_exchange_capability,
            EtradeOAuthAccessExchangeCapability,
            "access-exchange capability",
        )
        cast(
            EtradeOAuthAccessExchangeCapability,
            access_exchange_capability,
        )._validate_for_state(state)
        _require_exact(expires_at, EtradeOAuthTrustedTimestamp, "access-token expiry")
        bound_expiry = cast(EtradeOAuthTrustedTimestamp, expires_at)
        bound_expiry.__post_init__()
        if (
            bound_expiry.unix_seconds <= intent.timestamp.unix_seconds
            or bound_expiry.trust_evidence_sha256 != intent.timestamp.trust_evidence_sha256
        ):
            raise EtradeOAuthTokenRuntimeError(
                "access-token expiry conflicts with the trusted signing time"
            )
        bound_capability = cast(
            EtradeOAuthAccessExchangeCapability,
            access_exchange_capability,
        )
        try:
            runtime_reservation = bound_capability._reserve_unused_for_injected_token_runtime(
                state=state,
                verifier=cast(EtradeOAuthBoundVerifier, verifier),
            )
        except Exception:
            raise EtradeOAuthTokenRuntimeError(
                "access-exchange capability is unavailable for exact preflight"
            ) from None
        return bound_capability, runtime_reservation


def _resolution_request(
    snapshot: EtradeOAuthDurableSnapshot,
    intent: EtradeOAuthSigningIntent,
) -> EtradeOAuthTokenResolutionRequest:
    return EtradeOAuthTokenResolutionRequest(
        intent=intent,
        durable_scope_sha256=snapshot.scope_sha256,
        durable_event_sha256=snapshot.current_event_sha256,
        durable_sequence=snapshot.sequence,
        durable_session_state_sha256=snapshot.state.semantic_sha256,
        durable_replay_guard_sha256=snapshot.replay_guard.semantic_sha256,
    )


def _resolve(
    resolver: EtradeOAuthTokenSecretResolver,
    request: EtradeOAuthTokenResolutionRequest,
) -> _EtradeOAuthResolvedSecretEnvelope:
    try:
        resolver_id = resolver.resolver_id
        resolver_version = resolver.resolver_version
        method = resolver._resolve_for_injected_token_exchange
    except Exception:
        raise EtradeOAuthTokenResolutionError(
            "injected OAuth secret resolver metadata access failed"
        ) from None
    if (
        type(resolver_id) is not str
        or resolver_id != ETRADE_OAUTH_INJECTED_RESOLVER_ID
        or type(resolver_version) is not str
        or resolver_version != ETRADE_OAUTH_INJECTED_RESOLVER_VERSION
        or not callable(method)
    ):
        raise EtradeOAuthTokenResolutionError(
            "injected OAuth secret resolver identity is unsupported"
        )
    try:
        envelope = method(request)
    except Exception:
        raise EtradeOAuthTokenResolutionError("injected OAuth secret resolution failed") from None
    if type(envelope) is not _EtradeOAuthResolvedSecretEnvelope:
        with suppress(Exception):
            close = getattr(envelope, "close", None)
            if callable(close):
                close()
        raise EtradeOAuthTokenResolutionError(
            "injected OAuth secret resolver returned unsupported custody"
        )
    return envelope


def _transport_metadata(
    transport: EtradeOAuthInjectedTokenTransport,
) -> Callable[[EtradeOAuthEphemeralTransportRequest], object]:
    try:
        transport_id = transport.transport_id
        transport_version = transport.transport_version
        method = transport._exchange_for_token_runtime
    except Exception:
        raise EtradeOAuthTokenTransportError(
            "injected OAuth transport metadata access failed"
        ) from None
    if (
        type(transport_id) is not str
        or transport_id != ETRADE_OAUTH_INJECTED_TRANSPORT_ID
        or type(transport_version) is not str
        or transport_version != ETRADE_OAUTH_INJECTED_TRANSPORT_VERSION
        or not callable(method)
    ):
        raise EtradeOAuthTokenTransportError("injected OAuth transport identity is unsupported")
    return method


def _reservation_callables(
    reservation: EtradeOAuthTokenRuntimeCurrentnessReservation,
) -> tuple[
    Callable[[], EtradeOAuthDurableSnapshot],
    Callable[[EtradeOAuthSigningIntent], EtradeOAuthDurableSnapshot],
]:
    if type(reservation) is not EtradeOAuthTokenRuntimeCurrentnessReservation:
        raise EtradeOAuthTokenReplayError(
            "OAuth token runtime requires an exact store-issued currentness reservation"
        )
    try:
        claim = reservation._claim_snapshot_for_injected_token_runtime
        reserve = reservation._reserve_signing_intent_for_injected_token_runtime
    except Exception:
        raise EtradeOAuthTokenReplayError(
            "OAuth token-runtime reservation metadata access failed"
        ) from None
    if not callable(claim) or not callable(reserve):
        raise EtradeOAuthTokenReplayError("OAuth token-runtime reservation callables are malformed")
    return claim, reserve


def _percent_decode(value: bytes) -> bytearray:
    decoded = bytearray()
    try:
        index = 0
        while index < len(value):
            byte = value[index]
            if byte == 0x25:
                if (
                    index + 2 >= len(value)
                    or value[index + 1] not in _HEX
                    or value[index + 2] not in _HEX
                ):
                    raise EtradeOAuthTokenResponseError(
                        "token response contains malformed percent encoding"
                    )
                decoded.append(int(value[index + 1 : index + 3], 16))
                index += 3
                continue
            if byte == 0x2B:
                decoded.append(0x20)
            else:
                decoded.append(byte)
            index += 1
        return decoded
    except Exception:
        for index in range(len(decoded)):
            decoded[index] = 0
        raise


def _parse_token_response(
    operation: EtradeOAuthOperation,
    raw_response: _EtradeOAuthRawTokenResponse,
    *,
    raw_response_lock_identity: object,
) -> tuple[bytearray, bytearray]:
    body = raw_response._body_copy(lock_identity=raw_response_lock_identity)
    decoded_values: dict[bytes, bytearray] = {}
    try:
        parts = bytes(body).split(b"&")
        if not parts or any(not part or part.count(b"=") != 1 for part in parts):
            raise EtradeOAuthTokenResponseError("token response form structure is malformed")
        for part in parts:
            encoded_name, encoded_value = part.split(b"=", 1)
            name_bytes = _percent_decode(encoded_name)
            value_bytes = _percent_decode(encoded_value)
            try:
                name = bytes(name_bytes).decode("ascii", errors="strict").encode("ascii")
            except UnicodeDecodeError as error:
                del error
                for index in range(len(value_bytes)):
                    value_bytes[index] = 0
                raise EtradeOAuthTokenResponseError(
                    "token response field name is malformed"
                ) from None
            finally:
                for index in range(len(name_bytes)):
                    name_bytes[index] = 0
            if name in decoded_values:
                for index in range(len(value_bytes)):
                    value_bytes[index] = 0
                raise EtradeOAuthTokenResponseError(
                    "token response contains a duplicate form field"
                )
            if (
                not value_bytes
                or len(value_bytes) > _MAX_SECRET_BYTES
                or any(byte < 0x21 or byte > 0x7E for byte in value_bytes)
            ):
                for index in range(len(value_bytes)):
                    value_bytes[index] = 0
                raise EtradeOAuthTokenResponseError(
                    "token response contains invalid bounded field material"
                )
            decoded_values[name] = value_bytes
        required = {b"oauth_token", b"oauth_token_secret"}
        if operation is EtradeOAuthOperation.REQUEST_TOKEN:
            required.add(b"oauth_callback_confirmed")
        if set(decoded_values) != required:
            raise EtradeOAuthTokenResponseError(
                "token response fields do not match the exact operation schema"
            )
        callback = decoded_values.get(b"oauth_callback_confirmed")
        if callback is not None and bytes(callback) != b"true":
            raise EtradeOAuthTokenResponseError(
                "request-token response did not confirm the exact OOB callback"
            )
        token = decoded_values.pop(b"oauth_token")
        token_secret = decoded_values.pop(b"oauth_token_secret")
        for value in decoded_values.values():
            for index in range(len(value)):
                value[index] = 0
        return token, token_secret
    except Exception:
        for value in decoded_values.values():
            for index in range(len(value)):
                value[index] = 0
        raise
    finally:
        for index in range(len(body)):
            body[index] = 0


def execute_etrade_oauth_injected_token_exchange(
    *,
    currentness_reservation: EtradeOAuthTokenRuntimeCurrentnessReservation,
    signing_intent: EtradeOAuthSigningIntent,
    issued_token_reference: EtradeOAuthTokenSecretReference,
    resolver: EtradeOAuthTokenSecretResolver,
    transport: EtradeOAuthInjectedTokenTransport,
    expires_at: EtradeOAuthTrustedTimestamp | None = None,
    verifier: EtradeOAuthBoundVerifier | None = None,
    access_exchange_capability: EtradeOAuthAccessExchangeCapability | None = None,
) -> EtradeOAuthEphemeralTokenExchangeResult:
    """Run one injected token exchange after a fresh durable replay burn.

    The function has no concrete network or deployed resolver.  It does not
    persist token material and it does not advance the returned successor state.
    """

    claim_current, reserve_signing_intent = _reservation_callables(currentness_reservation)
    envelope: _EtradeOAuthResolvedSecretEnvelope | None = None
    request: EtradeOAuthEphemeralTransportRequest | None = None
    raw_response: _EtradeOAuthRawTokenResponse | None = None
    dispatch_witness: _EtradeOAuthTransportDispatchWitness | None = None
    token: bytearray | None = None
    token_secret: bytearray | None = None
    bound_access_capability: EtradeOAuthAccessExchangeCapability | None = None
    access_runtime_reservation: object | None = None
    result_transferred = False
    try:
        try:
            snapshot = _validate_snapshot(claim_current())
        except EtradeOAuthTokenReplayError:
            raise
        except Exception:
            raise EtradeOAuthTokenReplayError(
                "OAuth token-runtime currentness claim failed"
            ) from None
        canonical_signing_intent = _clone_signing_intent(signing_intent)
        canonical_issued_token_reference = _clone_token_reference(issued_token_reference)
        canonical_expires_at = _clone_optional_timestamp(expires_at)
        bound_access_capability, access_runtime_reservation = _validate_preflight(
            snapshot,
            canonical_signing_intent,
            canonical_issued_token_reference,
            canonical_expires_at,
            verifier,
            access_exchange_capability,
        )
        try:
            expected_next_guard = reserve_etrade_oauth_signing_intent(
                canonical_signing_intent,
                replay_guard=snapshot.replay_guard,
            )
            replay_snapshot = _validate_snapshot(reserve_signing_intent(canonical_signing_intent))
        except EtradeOAuthTokenReplayError:
            raise
        except Exception:
            raise EtradeOAuthTokenReplayError(
                "durable OAuth signing reservation failed before secret resolution"
            ) from None
        if (
            replay_snapshot.scope_sha256 != snapshot.scope_sha256
            or replay_snapshot.sequence != snapshot.sequence + 1
            or replay_snapshot.events[:-1] != snapshot.events
            or replay_snapshot.state != snapshot.state
            or replay_snapshot.replay_guard != expected_next_guard
            or replay_snapshot.events[-1].previous_event_sha256 != snapshot.current_event_sha256
            or replay_snapshot.events[-1].prior_session_state_sha256
            != snapshot.state.semantic_sha256
        ):
            raise EtradeOAuthTokenReplayError(
                "durable OAuth signing reservation returned a conflicting exact prefix"
            )
        transport_exchange = _transport_metadata(transport)
        presented_signing_intent = _clone_signing_intent(canonical_signing_intent)
        resolution_request = _resolution_request(
            replay_snapshot,
            presented_signing_intent,
        )
        envelope = _resolve(resolver, resolution_request)
        try:
            consumer_credentials, token_credentials = envelope._consume(resolution_request)
            signing_result = sign_etrade_oauth_intent(
                presented_signing_intent,
                replay_guard=snapshot.replay_guard,
                consumer_credentials=consumer_credentials,
                token_credentials=token_credentials,
                verifier=verifier,
                access_exchange_capability=access_exchange_capability,
                _access_exchange_runtime_reservation=access_runtime_reservation,
            )
            del consumer_credentials, token_credentials
        except EtradeOAuthTokenRuntimeError:
            raise
        except Exception:
            raise EtradeOAuthTokenResolutionError(
                "ephemeral OAuth signing preparation failed"
            ) from None
        finally:
            envelope.close()
        if signing_result.next_replay_guard != replay_snapshot.replay_guard:
            raise EtradeOAuthTokenReplayError(
                "ephemeral OAuth signing result conflicts with the durable reservation"
            )
        request = EtradeOAuthEphemeralTransportRequest(
            issuer=_EPHEMERAL_TRANSPORT_REQUEST_ISSUER,
            signing_result=signing_result,
            replay_snapshot=replay_snapshot,
        )
        dispatch_witness = _EtradeOAuthTransportDispatchWitness(
            canonical_intent=canonical_signing_intent,
            presented_intent=presented_signing_intent,
            signing_result=signing_result,
            request=request,
            source_replay_guard=snapshot.replay_guard,
            replay_snapshot=replay_snapshot,
        )
        request._validate_before_injected_transport()
        try:
            _register_raw_response_dispatch_witness(request, dispatch_witness)
            try:
                response = transport_exchange(request)
            finally:
                _unregister_raw_response_dispatch_witness(request, dispatch_witness)
        except Exception:
            raise EtradeOAuthTokenTransportError("injected OAuth transport failed") from None
        if type(response) is not _EtradeOAuthRawTokenResponse:
            with suppress(Exception):
                close = getattr(response, "close", None)
                if callable(close):
                    close()
            raise EtradeOAuthTokenTransportError(
                "injected OAuth transport returned unsupported response custody"
            )
        raw_response = response
        try:
            raw_response_lock_identity = (
                dispatch_witness._claim_constructor_raw_response_lock_identity(
                    request=request,
                    response=raw_response,
                )
            )
        except Exception:
            raise EtradeOAuthTokenTransportError(
                "injected raw response conflicts with its constructor witness"
            ) from None
        dispatch_witness._validate_after_injected_transport(
            presented_intent=presented_signing_intent,
            signing_result=signing_result,
            request=request,
            replay_snapshot=replay_snapshot,
        )
        request._validate_after_injected_transport(raw_response)
        raw_response._validate_for(
            request,
            lock_identity=raw_response_lock_identity,
        )
        dispatch_witness._validate_after_injected_transport(
            presented_intent=presented_signing_intent,
            signing_result=signing_result,
            request=request,
            replay_snapshot=replay_snapshot,
        )
        token, token_secret = _parse_token_response(
            canonical_signing_intent.operation,
            raw_response,
            raw_response_lock_identity=raw_response_lock_identity,
        )
        dispatch_witness._validate_after_injected_transport(
            presented_intent=presented_signing_intent,
            signing_result=signing_result,
            request=request,
            replay_snapshot=replay_snapshot,
        )

        if canonical_signing_intent.operation is EtradeOAuthOperation.REQUEST_TOKEN:
            successor = record_etrade_oauth_request_token_transition(
                snapshot.state,
                signing_intent=canonical_signing_intent,
                request_token_reference=canonical_issued_token_reference,
            )
        else:
            successor = record_etrade_oauth_access_token_transition(
                snapshot.state,
                signing_intent=canonical_signing_intent,
                access_token_reference=canonical_issued_token_reference,
                expires_at=cast(EtradeOAuthTrustedTimestamp, canonical_expires_at),
            )
        response_binding_sha256 = _semantic_sha256(
            raw_response._sanitized_binding_material(
                lock_identity=raw_response_lock_identity,
            )
        )
        receipt = EtradeOAuthTokenExchangeReceipt(
            issuer=_TOKEN_EXCHANGE_RECEIPT_ISSUER,
            environment=canonical_signing_intent.environment,
            operation=canonical_signing_intent.operation,
            signing_intent_sha256=canonical_signing_intent.semantic_sha256,
            durable_scope_sha256=replay_snapshot.scope_sha256,
            replay_event_sha256=replay_snapshot.current_event_sha256,
            replay_sequence=replay_snapshot.sequence,
            replay_guard_sha256=replay_snapshot.replay_guard.semantic_sha256,
            issued_token_reference=canonical_issued_token_reference,
            secret_independent_response_binding_sha256=response_binding_sha256,
        )
        result = EtradeOAuthEphemeralTokenExchangeResult(
            issuer=_TOKEN_EXCHANGE_RESULT_ISSUER,
            receipt=receipt,
            replay_snapshot=replay_snapshot,
            successor_state=successor,
            raw_response=raw_response,
            raw_response_lock_identity=raw_response_lock_identity,
            token=token,
            token_secret=token_secret,
        )
        dispatch_witness._release_response_custody_for_result(
            request=request,
            response=raw_response,
        )
        raw_response = None
        token = None
        token_secret = None
        result_transferred = True
        return result
    finally:
        currentness_reservation.close()
        if bound_access_capability is not None and access_runtime_reservation is not None:
            with suppress(Exception):
                bound_access_capability._release_injected_token_runtime_reservation(
                    access_runtime_reservation
                )
        if envelope is not None:
            envelope.close()
        if dispatch_witness is not None:
            if not result_transferred:
                dispatch_witness._close_constructor_raw_response_for_failure()
            dispatch_witness._close_request_after_dispatch()
        elif request is not None:
            request.close()
        if raw_response is not None:
            raw_response.close()
        for secret in (token, token_secret):
            if secret is None:
                continue
            for index in range(len(secret)):
                secret[index] = 0


__all__ = [
    "ETRADE_OAUTH_INJECTED_RESOLVER_ID",
    "ETRADE_OAUTH_INJECTED_RESOLVER_VERSION",
    "ETRADE_OAUTH_INJECTED_TRANSPORT_ID",
    "ETRADE_OAUTH_INJECTED_TRANSPORT_VERSION",
    "ETRADE_OAUTH_TOKEN_RESPONSE_CHARSET",
    "ETRADE_OAUTH_TOKEN_RESPONSE_MAX_BYTES",
    "ETRADE_OAUTH_TOKEN_RESPONSE_MEDIA_TYPE",
    "ETRADE_OAUTH_TOKEN_RUNTIME_CONTRACT_VERSION",
    "ETRADE_OAUTH_TOKEN_RUNTIME_REVIEWED_ON",
    "ETRADE_OAUTH_TOKEN_RUNTIME_TIMEOUT_MILLISECONDS",
    "EtradeOAuthEphemeralTokenExchangeResult",
    "EtradeOAuthEphemeralTransportRequest",
    "EtradeOAuthInjectedTokenTransport",
    "EtradeOAuthTokenExchangeReceipt",
    "EtradeOAuthTokenReplayError",
    "EtradeOAuthTokenResolutionError",
    "EtradeOAuthTokenResolutionRequest",
    "EtradeOAuthTokenResolverLifecycleError",
    "EtradeOAuthTokenResponseError",
    "EtradeOAuthTokenRuntimeError",
    "EtradeOAuthTokenSecretResolver",
    "EtradeOAuthTokenTransportError",
    "create_etrade_oauth_injected_token_response",
    "create_etrade_oauth_token_secret_envelope",
    "execute_etrade_oauth_injected_token_exchange",
]
