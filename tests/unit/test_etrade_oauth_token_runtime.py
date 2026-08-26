from __future__ import annotations

import ast
import copy
import pickle
from dataclasses import replace
from pathlib import Path
from threading import Barrier, Thread
from typing import Any, NoReturn, cast

import pytest
import sqlalchemy as sa

from packages.adapters.broker.etrade import (
    ETRADE_PRODUCTION_ENDPOINT_PROFILE,
    ETRADE_SANDBOX_ENDPOINT_PROFILE,
    EtradeEnvironment,
    EtradeSecretScope,
)
from packages.adapters.broker.etrade_oauth import (
    EtradeOAuthAccessExchangeCapability,
    EtradeOAuthBoundVerifier,
    EtradeOAuthConsumerSecretReference,
    EtradeOAuthNonce,
    EtradeOAuthOperation,
    EtradeOAuthReplayGuard,
    EtradeOAuthSessionPhase,
    EtradeOAuthSigningIntent,
    EtradeOAuthTokenKind,
    EtradeOAuthTokenSecretReference,
    EtradeOAuthTrustedTimestamp,
    EtradeOAuthVerifierValue,
    begin_etrade_oauth_out_of_band_authorization,
    create_etrade_oauth_session,
    create_etrade_oauth_signing_intent,
    record_etrade_oauth_authorization_transition,
    record_etrade_oauth_request_token_transition,
    reserve_etrade_oauth_signing_intent,
)
from packages.application.etrade_oauth_token_runtime import (
    ETRADE_OAUTH_INJECTED_RESOLVER_ID,
    ETRADE_OAUTH_INJECTED_RESOLVER_VERSION,
    ETRADE_OAUTH_INJECTED_TRANSPORT_ID,
    ETRADE_OAUTH_INJECTED_TRANSPORT_VERSION,
    ETRADE_OAUTH_TOKEN_RESPONSE_CHARSET,
    ETRADE_OAUTH_TOKEN_RESPONSE_MEDIA_TYPE,
    ETRADE_OAUTH_TOKEN_RUNTIME_CONTRACT_VERSION,
    EtradeOAuthEphemeralTokenExchangeResult,
    EtradeOAuthEphemeralTransportRequest,
    EtradeOAuthTokenExchangeReceipt,
    EtradeOAuthTokenReplayError,
    EtradeOAuthTokenResolutionError,
    EtradeOAuthTokenResolutionRequest,
    EtradeOAuthTokenResolverLifecycleError,
    EtradeOAuthTokenResponseError,
    EtradeOAuthTokenRuntimeError,
    EtradeOAuthTokenTransportError,
    create_etrade_oauth_injected_token_response,
    create_etrade_oauth_token_secret_envelope,
    execute_etrade_oauth_injected_token_exchange,
)
from packages.persistence.database import create_database_engine
from packages.persistence.etrade_oauth_coordinator import (
    EtradeOAuthCoordinatorConflict,
    EtradeOAuthDurableSnapshot,
    EtradeOAuthTokenRuntimeCurrentnessReservation,
    SqlEtradeOAuthCoordinator,
    _event_from_values,
    _event_values,
    _ReplayDelta,
    authenticate_etrade_oauth_durable_snapshot,
)
from packages.persistence.schema import (
    metadata,
    phase4_etrade_oauth_session_events,
    phase4_etrade_oauth_session_heads,
)

CONSUMER_KEY = "synthetic-consumer-key"
CONSUMER_SECRET = "synthetic-consumer-secret"
REQUEST_TOKEN = "synthetic-request-token"
REQUEST_TOKEN_SECRET = "synthetic-request-secret"
ACCESS_TOKEN = "synthetic-access-token"
ACCESS_TOKEN_SECRET = "synthetic-access-secret"
VERIFIER = "synthetic-verifier"
TRUST_SHA256 = "a" * 64
REQUEST_HEADER = (
    'OAuth oauth_callback="oob", oauth_consumer_key="synthetic-consumer-key", '
    'oauth_nonce="0123456789abcdef", '
    'oauth_signature="uZ%2FPc7jeXduYAMZsxRAjyuJ5Nwo%3D", '
    'oauth_signature_method="HMAC-SHA1", oauth_timestamp="1700000000", '
    'oauth_version="1.0"'
)
ACCESS_HEADER = (
    'OAuth oauth_consumer_key="synthetic-consumer-key", '
    'oauth_nonce="fedcba9876543210", '
    'oauth_signature="RlccBbeg9IEA3n2Ey8D73RfSaGI%3D", '
    'oauth_signature_method="HMAC-SHA1", oauth_timestamp="1700000100", '
    'oauth_token="synthetic-request-token", oauth_verifier="synthetic-verifier", '
    'oauth_version="1.0"'
)


def _consumer_reference(
    environment: EtradeEnvironment = EtradeEnvironment.SANDBOX,
    *,
    version: int = 1,
) -> EtradeOAuthConsumerSecretReference:
    return EtradeOAuthConsumerSecretReference(
        environment=environment,
        scope=(
            EtradeSecretScope.SANDBOX_CONSUMER
            if environment is EtradeEnvironment.SANDBOX
            else EtradeSecretScope.PRODUCTION_CONSUMER
        ),
        version=version,
    )


def _token_reference(
    kind: EtradeOAuthTokenKind,
    version: int,
    environment: EtradeEnvironment = EtradeEnvironment.SANDBOX,
) -> EtradeOAuthTokenSecretReference:
    return EtradeOAuthTokenSecretReference(
        environment=environment,
        scope=(
            EtradeSecretScope.SANDBOX_TOKEN
            if environment is EtradeEnvironment.SANDBOX
            else EtradeSecretScope.PRODUCTION_TOKEN
        ),
        kind=kind,
        version=version,
    )


def _timestamp(value: int) -> EtradeOAuthTrustedTimestamp:
    return EtradeOAuthTrustedTimestamp(
        unix_seconds=value,
        trust_evidence_sha256=TRUST_SHA256,
    )


def _request_intent(
    *,
    nonce: str = "0123456789abcdef",
    environment: EtradeEnvironment = EtradeEnvironment.SANDBOX,
) -> EtradeOAuthSigningIntent:
    endpoint = (
        ETRADE_SANDBOX_ENDPOINT_PROFILE
        if environment is EtradeEnvironment.SANDBOX
        else ETRADE_PRODUCTION_ENDPOINT_PROFILE
    )
    return create_etrade_oauth_signing_intent(
        environment=environment,
        endpoint_profile=endpoint,
        operation=EtradeOAuthOperation.REQUEST_TOKEN,
        generation=1,
        consumer_reference=_consumer_reference(environment),
        token_reference=None,
        timestamp=_timestamp(1_700_000_000),
        nonce=EtradeOAuthNonce(nonce),
    )


def _repository(tmp_path: Path) -> tuple[SqlEtradeOAuthCoordinator, EtradeOAuthDurableSnapshot]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path / 'oauth-runtime.db'}")
    metadata.create_all(engine)
    repository = SqlEtradeOAuthCoordinator(engine)
    initial = create_etrade_oauth_session(
        environment=EtradeEnvironment.SANDBOX,
        endpoint_profile=ETRADE_SANDBOX_ENDPOINT_PROFILE,
        consumer_reference=_consumer_reference(),
    )
    return repository, repository.initialize(initial)


class _Resolver:
    def __init__(
        self,
        *,
        consumer_key: str = CONSUMER_KEY,
        consumer_secret: str = CONSUMER_SECRET,
        token: str | None = None,
        token_secret: str | None = None,
        failure: Exception | None = None,
        closed_envelope: bool = False,
        wrong_result: object | None = None,
    ) -> None:
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.token = token
        self.token_secret = token_secret
        self.failure = failure
        self.closed_envelope = closed_envelope
        self.wrong_result = wrong_result
        self.calls = 0
        self.last_envelope: object | None = None

    @property
    def resolver_id(self) -> str:
        return ETRADE_OAUTH_INJECTED_RESOLVER_ID

    @property
    def resolver_version(self) -> str:
        return ETRADE_OAUTH_INJECTED_RESOLVER_VERSION

    def _resolve_for_injected_token_exchange(self, request: Any) -> object:
        self.calls += 1
        if self.failure is not None:
            raise self.failure
        if self.wrong_result is not None:
            return self.wrong_result
        envelope = create_etrade_oauth_token_secret_envelope(
            request,
            consumer_key=self.consumer_key,
            consumer_secret=self.consumer_secret,
            token=self.token,
            token_secret=self.token_secret,
        )
        self.last_envelope = envelope
        if self.closed_envelope:
            cast(Any, envelope).close()
        return envelope


class _Transport:
    def __init__(
        self,
        *,
        body: bytes,
        expected_header: str = REQUEST_HEADER,
        response_overrides: dict[str, object] | None = None,
        failure: Exception | None = None,
        wrong_result: object | None = None,
    ) -> None:
        self.body = body
        self.expected_header = expected_header
        self.response_overrides = response_overrides or {}
        self.failure = failure
        self.wrong_result = wrong_result
        self.calls = 0
        self.header_matched = False
        self.last_request: object | None = None
        self.last_response: object | None = None

    @property
    def transport_id(self) -> str:
        return ETRADE_OAUTH_INJECTED_TRANSPORT_ID

    @property
    def transport_version(self) -> str:
        return ETRADE_OAUTH_INJECTED_TRANSPORT_VERSION

    def _exchange_for_token_runtime(
        self,
        request: EtradeOAuthEphemeralTransportRequest,
    ) -> object:
        self.calls += 1
        self.last_request = request
        if self.failure is not None:
            raise self.failure
        if self.wrong_result is not None:
            return self.wrong_result
        self.header_matched = request._authorization_header_matches_for_test(self.expected_header)
        response = cast(Any, create_etrade_oauth_injected_token_response)(
            request,
            body=self.body,
            **self.response_overrides,
        )
        self.last_response = response
        return response


def _request_body(
    token: str = REQUEST_TOKEN,
    token_secret: str = REQUEST_TOKEN_SECRET,
) -> bytes:
    return (
        f"oauth_token={token}&oauth_token_secret={token_secret}&oauth_callback_confirmed=true"
    ).encode("ascii")


def _request_exchange(
    tmp_path: Path,
    *,
    resolver: _Resolver | None = None,
    transport: _Transport | None = None,
    intent: Any | None = None,
    issued_reference: EtradeOAuthTokenSecretReference | None = None,
) -> tuple[
    EtradeOAuthEphemeralTokenExchangeResult,
    SqlEtradeOAuthCoordinator,
    _Resolver,
    _Transport,
]:
    repository, _ = _repository(tmp_path)
    resolver = resolver or _Resolver()
    transport = transport or _Transport(body=_request_body())
    result = execute_etrade_oauth_injected_token_exchange(
        currentness_reservation=_reservation(repository),
        signing_intent=intent or _request_intent(),
        issued_token_reference=issued_reference
        or _token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1),
        resolver=resolver,
        transport=transport,
    )
    return result, repository, resolver, transport


def _reservation(
    repository: SqlEtradeOAuthCoordinator,
) -> EtradeOAuthTokenRuntimeCurrentnessReservation:
    return repository.issue_token_runtime_currentness_reservation(
        EtradeEnvironment.SANDBOX,
        EtradeSecretScope.SANDBOX_CONSUMER,
    )


def _confirmed_access_head(
    tmp_path: Path,
) -> tuple[
    SqlEtradeOAuthCoordinator,
    EtradeOAuthDurableSnapshot,
    EtradeOAuthBoundVerifier,
    EtradeOAuthAccessExchangeCapability,
]:
    request_result, repository, _, _ = _request_exchange(tmp_path)
    replay_snapshot = request_result.replay_snapshot
    successor_state = request_result.successor_state
    assert request_result._matches_test_values_once(REQUEST_TOKEN, REQUEST_TOKEN_SECRET)
    snapshot = repository.advance(
        replay_snapshot,
        successor_state,
        replay_snapshot.replay_guard,
    )
    pending = begin_etrade_oauth_out_of_band_authorization(snapshot.state)
    snapshot = repository.advance(snapshot, pending, snapshot.replay_guard)
    assert pending.authorization_challenge_sha256 is not None
    verifier = EtradeOAuthBoundVerifier(
        authorization_challenge_sha256=pending.authorization_challenge_sha256,
        verifier=EtradeOAuthVerifierValue(VERIFIER),
    )
    authorization = record_etrade_oauth_authorization_transition(
        pending,
        verifier=verifier,
        replay_guard=snapshot.replay_guard,
    )
    snapshot = repository.advance(
        snapshot,
        authorization.state,
        authorization.next_replay_guard,
    )
    return repository, snapshot, verifier, authorization.access_exchange_capability


def test_request_token_exchange_burns_replay_and_retains_only_ephemeral_raw_custody(
    tmp_path: Path,
) -> None:
    result, repository, resolver, transport = _request_exchange(tmp_path)

    assert transport.calls == 1
    assert transport.header_matched is True
    assert cast(Any, resolver.last_envelope).closed is True
    assert result.raw_response_retained is True
    assert result.successor_state.phase is EtradeOAuthSessionPhase.REQUEST_TOKEN_RECEIVED
    assert result.successor_state.request_token_reference == result.issued_token_reference
    assert result.replay_snapshot.sequence == 2
    persisted = repository.load(EtradeEnvironment.SANDBOX, EtradeSecretScope.SANDBOX_CONSUMER)
    assert persisted.sequence == 2
    assert persisted.state.phase is EtradeOAuthSessionPhase.NEEDS_REQUEST_TOKEN
    assert persisted.replay_guard == result.replay_snapshot.replay_guard
    assert result.receipt.signed_request_capability_presented is True
    assert result.receipt.injected_request_response_structurally_bound is True
    assert result.receipt.provider_origin_authenticated is False
    assert result.receipt.raw_response_persisted is False
    assert result.receipt.raw_response_digest_retained is False
    assert result.receipt.raw_response_ephemeral_custody_required is True
    assert set(result.authority.values()) == {False}
    assert result.session_head_transition_authorized is False
    assert result.token_secret_persistence_authorized is False
    assert result.post_transport_secret_store_atomicity_qualified is False

    assert result._matches_test_values_once(REQUEST_TOKEN, REQUEST_TOKEN_SECRET)
    with pytest.raises(EtradeOAuthTokenResolverLifecycleError):
        cast(Any, result)._matches_test_values_once(REQUEST_TOKEN, REQUEST_TOKEN_SECRET)
    assert result.closed
    assert not result.raw_response_retained


def test_resolver_envelope_is_context_managed_one_shot_and_cross_request_closed(
    tmp_path: Path,
) -> None:
    _, snapshot = _repository(tmp_path)
    intent = _request_intent()
    request = EtradeOAuthTokenResolutionRequest(
        intent=intent,
        durable_scope_sha256=snapshot.scope_sha256,
        durable_event_sha256=snapshot.current_event_sha256,
        durable_sequence=snapshot.sequence,
        durable_session_state_sha256=snapshot.state.semantic_sha256,
        durable_replay_guard_sha256=snapshot.replay_guard.semantic_sha256,
    )
    envelope = create_etrade_oauth_token_secret_envelope(
        request,
        consumer_key=CONSUMER_KEY,
        consumer_secret=CONSUMER_SECRET,
    )
    with cast(Any, envelope) as custody:
        assert repr(custody) == "_EtradeOAuthResolvedSecretEnvelope(<redacted>, closed=False)"
        assert str(custody) == "<redacted E*TRADE OAuth secret envelope>"
        assert not hasattr(custody, "consumer_key")
        assert not hasattr(custody, "consumer_secret")
        with pytest.raises(TypeError):
            pickle.dumps(custody)
        with pytest.raises(TypeError):
            copy.copy(custody)
        with pytest.raises(TypeError):
            copy.deepcopy(custody)
    assert cast(Any, envelope).closed is True
    with pytest.raises(EtradeOAuthTokenResolverLifecycleError):
        cast(Any, envelope)._consume(request)

    cross_request = replace(
        request,
        intent=_request_intent(nonce="abcdef0123456789"),
    )
    cross_envelope = create_etrade_oauth_token_secret_envelope(
        request,
        consumer_key=CONSUMER_KEY,
        consumer_secret=CONSUMER_SECRET,
    )
    with pytest.raises(EtradeOAuthTokenResolverLifecycleError):
        cast(Any, cross_envelope)._consume(cross_request)
    assert cast(Any, cross_envelope).closed is True


def test_access_token_exchange_composes_confirmed_verifier_without_advancing_session(
    tmp_path: Path,
) -> None:
    repository, snapshot, verifier, capability = _confirmed_access_head(tmp_path)
    request_reference = _token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1)
    intent = create_etrade_oauth_signing_intent(
        environment=EtradeEnvironment.SANDBOX,
        endpoint_profile=ETRADE_SANDBOX_ENDPOINT_PROFILE,
        operation=EtradeOAuthOperation.ACCESS_TOKEN,
        generation=1,
        consumer_reference=_consumer_reference(),
        token_reference=request_reference,
        timestamp=_timestamp(1_700_000_100),
        nonce=EtradeOAuthNonce("fedcba9876543210"),
        authorization_challenge_sha256=snapshot.state.authorization_challenge_sha256,
        authorization_state_sha256=snapshot.state.semantic_sha256,
    )
    resolver = _Resolver(token=REQUEST_TOKEN, token_secret=REQUEST_TOKEN_SECRET)
    transport = _Transport(
        body=(f"oauth_token={ACCESS_TOKEN}&oauth_token_secret={ACCESS_TOKEN_SECRET}").encode(
            "ascii"
        ),
        expected_header=ACCESS_HEADER,
    )

    result = execute_etrade_oauth_injected_token_exchange(
        currentness_reservation=_reservation(repository),
        signing_intent=intent,
        issued_token_reference=_token_reference(EtradeOAuthTokenKind.ACCESS_TOKEN, 2),
        resolver=resolver,
        transport=transport,
        expires_at=_timestamp(1_700_086_400),
        verifier=verifier,
        access_exchange_capability=capability,
    )

    assert transport.header_matched is True
    assert result.successor_state.phase is EtradeOAuthSessionPhase.ACCESS_TOKEN_ACTIVE
    assert result.successor_state.access_token_reference == result.issued_token_reference
    assert (
        repository.load(
            EtradeEnvironment.SANDBOX,
            EtradeSecretScope.SANDBOX_CONSUMER,
        ).state.phase
        is EtradeOAuthSessionPhase.AUTHORIZATION_CONFIRMED
    )
    sanitized_material = (
        repr(result),
        repr(result.receipt),
        result.receipt.semantic_sha256,
        result.receipt.secret_independent_response_binding_sha256,
    )
    for secret in (VERIFIER, ACCESS_TOKEN, ACCESS_TOKEN_SECRET, ACCESS_HEADER):
        assert all(secret not in value for value in sanitized_material)
    with repository._engine.connect() as connection:
        rows = (
            connection.execute(sa.select(phase4_etrade_oauth_session_events)).mappings().all(),
            connection.execute(sa.select(phase4_etrade_oauth_session_heads)).mappings().all(),
        )
    persisted = repr(rows)
    for secret in (VERIFIER, ACCESS_TOKEN, ACCESS_TOKEN_SECRET, ACCESS_HEADER):
        assert secret not in persisted
    assert result._matches_test_values_once(ACCESS_TOKEN, ACCESS_TOKEN_SECRET)


def test_access_token_time_regression_fails_before_secret_resolution(tmp_path: Path) -> None:
    repository, snapshot, verifier, capability = _confirmed_access_head(tmp_path)
    intent = create_etrade_oauth_signing_intent(
        environment=EtradeEnvironment.SANDBOX,
        endpoint_profile=ETRADE_SANDBOX_ENDPOINT_PROFILE,
        operation=EtradeOAuthOperation.ACCESS_TOKEN,
        generation=1,
        consumer_reference=_consumer_reference(),
        token_reference=_token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1),
        timestamp=_timestamp(1_699_999_999),
        nonce=EtradeOAuthNonce("time-regression-01"),
        authorization_challenge_sha256=snapshot.state.authorization_challenge_sha256,
        authorization_state_sha256=snapshot.state.semantic_sha256,
    )
    resolver = _Resolver(token=REQUEST_TOKEN, token_secret=REQUEST_TOKEN_SECRET)
    transport = _Transport(body=_request_body())

    with pytest.raises(EtradeOAuthTokenRuntimeError):
        execute_etrade_oauth_injected_token_exchange(
            currentness_reservation=_reservation(repository),
            signing_intent=intent,
            issued_token_reference=_token_reference(EtradeOAuthTokenKind.ACCESS_TOKEN, 2),
            resolver=resolver,
            transport=transport,
            expires_at=_timestamp(1_700_086_400),
            verifier=verifier,
            access_exchange_capability=capability,
        )

    assert resolver.calls == 0
    assert transport.calls == 0


def test_access_capability_remains_reusable_after_pre_reservation_rejection(
    tmp_path: Path,
) -> None:
    repository, snapshot, verifier, capability = _confirmed_access_head(tmp_path)
    intent = create_etrade_oauth_signing_intent(
        environment=EtradeEnvironment.SANDBOX,
        endpoint_profile=ETRADE_SANDBOX_ENDPOINT_PROFILE,
        operation=EtradeOAuthOperation.ACCESS_TOKEN,
        generation=1,
        consumer_reference=_consumer_reference(),
        token_reference=_token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1),
        timestamp=_timestamp(1_700_000_100),
        nonce=EtradeOAuthNonce("fedcba9876543210"),
        authorization_challenge_sha256=snapshot.state.authorization_challenge_sha256,
        authorization_state_sha256=snapshot.state.semantic_sha256,
    )
    rejected_resolver = _Resolver(
        token=REQUEST_TOKEN,
        token_secret=REQUEST_TOKEN_SECRET,
    )
    rejected_transport = _Transport(
        body=(f"oauth_token={ACCESS_TOKEN}&oauth_token_secret={ACCESS_TOKEN_SECRET}").encode(
            "ascii"
        ),
        expected_header=ACCESS_HEADER,
    )

    with pytest.raises(EtradeOAuthTokenRuntimeError):
        execute_etrade_oauth_injected_token_exchange(
            currentness_reservation=_reservation(repository),
            signing_intent=intent,
            issued_token_reference=_token_reference(EtradeOAuthTokenKind.ACCESS_TOKEN, 3),
            resolver=rejected_resolver,
            transport=rejected_transport,
            expires_at=_timestamp(1_700_086_400),
            verifier=verifier,
            access_exchange_capability=capability,
        )

    assert rejected_resolver.calls == 0
    assert rejected_transport.calls == 0
    assert (
        repository.load(
            EtradeEnvironment.SANDBOX,
            EtradeSecretScope.SANDBOX_CONSUMER,
        )
        == snapshot
    )

    result = execute_etrade_oauth_injected_token_exchange(
        currentness_reservation=_reservation(repository),
        signing_intent=intent,
        issued_token_reference=_token_reference(EtradeOAuthTokenKind.ACCESS_TOKEN, 2),
        resolver=_Resolver(token=REQUEST_TOKEN, token_secret=REQUEST_TOKEN_SECRET),
        transport=_Transport(
            body=(f"oauth_token={ACCESS_TOKEN}&oauth_token_secret={ACCESS_TOKEN_SECRET}").encode(
                "ascii"
            ),
            expected_header=ACCESS_HEADER,
        ),
        expires_at=_timestamp(1_700_086_400),
        verifier=verifier,
        access_exchange_capability=capability,
    )
    assert result._matches_test_values_once(ACCESS_TOKEN, ACCESS_TOKEN_SECRET)


def test_resolver_and_transport_metadata_are_exact_and_checked_before_resolution(
    tmp_path: Path,
) -> None:
    class _WrongResolver(_Resolver):
        @property
        def resolver_id(self) -> str:
            return "wrong-resolver"

    class _WrongTransport(_Transport):
        @property
        def transport_version(self) -> str:
            return "2.0.0"

    repository, _ = _repository(tmp_path / "resolver")
    resolver = _WrongResolver()
    transport = _Transport(body=_request_body())
    with pytest.raises(EtradeOAuthTokenResolutionError):
        execute_etrade_oauth_injected_token_exchange(
            currentness_reservation=_reservation(repository),
            signing_intent=_request_intent(),
            issued_token_reference=_token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1),
            resolver=resolver,
            transport=transport,
        )
    assert resolver.calls == 0
    assert transport.calls == 0

    repository, _ = _repository(tmp_path / "transport")
    valid_resolver = _Resolver()
    wrong_transport = _WrongTransport(body=_request_body())
    with pytest.raises(EtradeOAuthTokenTransportError):
        execute_etrade_oauth_injected_token_exchange(
            currentness_reservation=_reservation(repository),
            signing_intent=_request_intent(),
            issued_token_reference=_token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1),
            resolver=valid_resolver,
            transport=wrong_transport,
        )
    assert valid_resolver.calls == 0
    assert wrong_transport.calls == 0


def test_dynamic_port_metadata_and_transport_callable_are_each_frozen_once(
    tmp_path: Path,
) -> None:
    class _SingleReadResolver:
        def __init__(self) -> None:
            self.backing = _Resolver()
            self.id_reads = 0
            self.version_reads = 0
            self.method_reads = 0

        @property
        def resolver_id(self) -> str:
            self.id_reads += 1
            return ETRADE_OAUTH_INJECTED_RESOLVER_ID if self.id_reads == 1 else "changed-resolver"

        @property
        def resolver_version(self) -> str:
            self.version_reads += 1
            return (
                ETRADE_OAUTH_INJECTED_RESOLVER_VERSION
                if self.version_reads == 1
                else "changed-version"
            )

        @property
        def _resolve_for_injected_token_exchange(self) -> Any:
            self.method_reads += 1
            if self.method_reads == 1:
                return self.backing._resolve_for_injected_token_exchange
            return lambda _request: object()

    class _SingleReadTransport:
        def __init__(self) -> None:
            self.backing = _Transport(body=_request_body())
            self.id_reads = 0
            self.version_reads = 0
            self.method_reads = 0

        @property
        def transport_id(self) -> str:
            self.id_reads += 1
            return ETRADE_OAUTH_INJECTED_TRANSPORT_ID if self.id_reads == 1 else "changed-transport"

        @property
        def transport_version(self) -> str:
            self.version_reads += 1
            return (
                ETRADE_OAUTH_INJECTED_TRANSPORT_VERSION
                if self.version_reads == 1
                else "changed-version"
            )

        @property
        def _exchange_for_token_runtime(self) -> Any:
            self.method_reads += 1
            if self.method_reads == 1:
                return self.backing._exchange_for_token_runtime
            return lambda _request: object()

    repository, _ = _repository(tmp_path)
    resolver = _SingleReadResolver()
    transport = _SingleReadTransport()
    result = execute_etrade_oauth_injected_token_exchange(
        currentness_reservation=_reservation(repository),
        signing_intent=_request_intent(),
        issued_token_reference=_token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1),
        resolver=cast(Any, resolver),
        transport=cast(Any, transport),
    )

    assert (resolver.id_reads, resolver.version_reads, resolver.method_reads) == (1, 1, 1)
    assert (transport.id_reads, transport.version_reads, transport.method_reads) == (1, 1, 1)
    assert result._matches_test_values_once(REQUEST_TOKEN, REQUEST_TOKEN_SECRET)


@pytest.mark.parametrize("tamper", ("scope", "root_replay"))
def test_tampered_durable_snapshot_fails_before_resolution_or_transport(
    tmp_path: Path,
    tamper: str,
) -> None:
    repository, snapshot = _repository(tmp_path)
    if tamper == "scope":
        corrupted = replace(snapshot, scope_sha256="b" * 64)
    else:
        corrupted_event = replace(snapshot.events[0], replay_guard_sha256="c" * 64)
        corrupted = replace(snapshot, events=(corrupted_event,))
    reservation = _reservation(repository)
    object.__setattr__(
        reservation,
        "_EtradeOAuthTokenRuntimeCurrentnessReservation__snapshot",
        corrupted,
    )
    resolver = _Resolver()
    transport = _Transport(body=_request_body())

    with pytest.raises(EtradeOAuthTokenReplayError):
        execute_etrade_oauth_injected_token_exchange(
            currentness_reservation=reservation,
            signing_intent=_request_intent(),
            issued_token_reference=_token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1),
            resolver=resolver,
            transport=transport,
        )

    assert resolver.calls == 0
    assert transport.calls == 0
    assert (
        repository.load(
            EtradeEnvironment.SANDBOX,
            EtradeSecretScope.SANDBOX_CONSUMER,
        ).sequence
        == 1
    )


@pytest.mark.parametrize("tamper", ("root_hash", "later_event_hash", "closed_edge"))
def test_full_snapshot_authentication_rejects_hash_and_closed_graph_forgery_before_ports(
    tmp_path: Path,
    tamper: str,
) -> None:
    repository, snapshot = _repository(tmp_path)
    expected_sequence = 1
    if tamper == "root_hash":
        forged = replace(
            snapshot,
            events=(replace(snapshot.events[0], event_sha256="d" * 64),),
        )
    elif tamper == "later_event_hash":
        competing_intent = _request_intent(nonce="event-hash-00001")
        snapshot = repository.advance(
            snapshot,
            snapshot.state,
            reserve_etrade_oauth_signing_intent(
                competing_intent,
                replay_guard=snapshot.replay_guard,
            ),
        )
        expected_sequence = 2
        forged = replace(
            snapshot,
            events=(
                snapshot.events[0],
                replace(snapshot.events[1], event_sha256="e" * 64),
            ),
        )
    else:
        intent = _request_intent()
        successor = record_etrade_oauth_request_token_transition(
            snapshot.state,
            signing_intent=intent,
            request_token_reference=_token_reference(
                EtradeOAuthTokenKind.REQUEST_TOKEN,
                1,
            ),
        )
        guard = EtradeOAuthReplayGuard()
        delta = _ReplayDelta(None, None)
        values = _event_values(
            scope_sha256=snapshot.scope_sha256,
            sequence=2,
            previous_event_sha256=snapshot.current_event_sha256,
            prior_session_state_sha256=snapshot.state.semantic_sha256,
            state=successor,
            replay_guard=guard,
            delta=delta,
        )
        forged_event = _event_from_values(
            values,
            state=successor,
            replay_guard=guard,
            delta=delta,
        )
        forged = EtradeOAuthDurableSnapshot(
            scope_sha256=snapshot.scope_sha256,
            state=successor,
            replay_guard=guard,
            events=(*snapshot.events, forged_event),
        )

    with pytest.raises(EtradeOAuthCoordinatorConflict):
        authenticate_etrade_oauth_durable_snapshot(forged)
    reservation = _reservation(repository)
    object.__setattr__(
        reservation,
        "_EtradeOAuthTokenRuntimeCurrentnessReservation__snapshot",
        forged,
    )
    resolver = _Resolver()
    transport = _Transport(body=_request_body())
    with pytest.raises(EtradeOAuthTokenReplayError):
        execute_etrade_oauth_injected_token_exchange(
            currentness_reservation=reservation,
            signing_intent=_request_intent(nonce="forged-head-0001"),
            issued_token_reference=_token_reference(
                EtradeOAuthTokenKind.REQUEST_TOKEN,
                1,
            ),
            resolver=resolver,
            transport=transport,
        )

    assert resolver.calls == 0
    assert transport.calls == 0
    assert (
        repository.load(
            EtradeEnvironment.SANDBOX,
            EtradeSecretScope.SANDBOX_CONSUMER,
        ).sequence
        == expected_sequence
    )


def test_cross_store_reservation_substitution_is_rejected_before_ports_or_writes(
    tmp_path: Path,
) -> None:
    first, _ = _repository(tmp_path / "first")
    second, _ = _repository(tmp_path / "second")
    reservation = _reservation(first)
    object.__setattr__(
        reservation,
        "_EtradeOAuthTokenRuntimeCurrentnessReservation__coordinator",
        second,
    )
    resolver = _Resolver()
    transport = _Transport(body=_request_body())

    with pytest.raises(EtradeOAuthTokenReplayError):
        execute_etrade_oauth_injected_token_exchange(
            currentness_reservation=reservation,
            signing_intent=_request_intent(),
            issued_token_reference=_token_reference(
                EtradeOAuthTokenKind.REQUEST_TOKEN,
                1,
            ),
            resolver=resolver,
            transport=transport,
        )

    assert resolver.calls == 0
    assert transport.calls == 0
    for repository in (first, second):
        assert (
            repository.load(
                EtradeEnvironment.SANDBOX,
                EtradeSecretScope.SANDBOX_CONSUMER,
            ).sequence
            == 1
        )


@pytest.mark.parametrize(
    ("intent", "issued_reference"),
    (
        (
            _request_intent(environment=EtradeEnvironment.PRODUCTION),
            _token_reference(
                EtradeOAuthTokenKind.REQUEST_TOKEN,
                1,
                EtradeEnvironment.PRODUCTION,
            ),
        ),
        (_request_intent(), _token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 2)),
        (_request_intent(), _token_reference(EtradeOAuthTokenKind.ACCESS_TOKEN, 1)),
    ),
)
def test_environment_scope_kind_and_revision_mismatch_fail_before_resolution(
    tmp_path: Path,
    intent: Any,
    issued_reference: EtradeOAuthTokenSecretReference,
) -> None:
    repository, _ = _repository(tmp_path)
    resolver = _Resolver()
    transport = _Transport(body=_request_body())

    with pytest.raises(EtradeOAuthTokenRuntimeError):
        execute_etrade_oauth_injected_token_exchange(
            currentness_reservation=_reservation(repository),
            signing_intent=intent,
            issued_token_reference=issued_reference,
            resolver=resolver,
            transport=transport,
        )

    assert resolver.calls == 0
    assert transport.calls == 0


def test_durable_replay_failure_prevents_transport_and_sanitizes_error(tmp_path: Path) -> None:
    repository, snapshot = _repository(tmp_path)
    resolver = _Resolver()
    transport = _Transport(body=_request_body())
    reservation = _reservation(repository)
    competing_intent = _request_intent(nonce="stale-branch-0001")
    repository.advance(
        snapshot,
        snapshot.state,
        reserve_etrade_oauth_signing_intent(
            competing_intent,
            replay_guard=snapshot.replay_guard,
        ),
    )

    with pytest.raises(EtradeOAuthTokenReplayError) as caught:
        execute_etrade_oauth_injected_token_exchange(
            currentness_reservation=reservation,
            signing_intent=_request_intent(),
            issued_token_reference=_token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1),
            resolver=resolver,
            transport=transport,
        )

    assert "credential-looking" not in str(caught.value)
    assert transport.calls == 0
    assert (
        repository.load(
            EtradeEnvironment.SANDBOX,
            EtradeSecretScope.SANDBOX_CONSUMER,
        ).sequence
        == 2
    )
    assert resolver.calls == 0


def test_transport_timeout_burns_replay_but_never_advances_session_state(tmp_path: Path) -> None:
    repository, _ = _repository(tmp_path)
    transport = _Transport(
        body=_request_body(),
        failure=TimeoutError(f"timeout included {CONSUMER_SECRET}"),
    )

    with pytest.raises(EtradeOAuthTokenTransportError) as caught:
        execute_etrade_oauth_injected_token_exchange(
            currentness_reservation=_reservation(repository),
            signing_intent=_request_intent(),
            issued_token_reference=_token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1),
            resolver=_Resolver(),
            transport=transport,
        )

    assert CONSUMER_SECRET not in str(caught.value)
    current = repository.load(EtradeEnvironment.SANDBOX, EtradeSecretScope.SANDBOX_CONSUMER)
    assert current.sequence == 2
    assert current.state.phase is EtradeOAuthSessionPhase.NEEDS_REQUEST_TOKEN

    with pytest.raises(EtradeOAuthTokenReplayError):
        execute_etrade_oauth_injected_token_exchange(
            currentness_reservation=_reservation(repository),
            signing_intent=_request_intent(),
            issued_token_reference=_token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1),
            resolver=_Resolver(),
            transport=transport,
        )
    assert transport.calls == 1


def test_transport_failure_after_raw_construction_closes_request_owned_custody(
    tmp_path: Path,
) -> None:
    class _ResponseThenFailureTransport:
        transport_id = ETRADE_OAUTH_INJECTED_TRANSPORT_ID
        transport_version = ETRADE_OAUTH_INJECTED_TRANSPORT_VERSION

        def __init__(self) -> None:
            self.last_response: object | None = None

        def _exchange_for_token_runtime(
            self,
            request: EtradeOAuthEphemeralTransportRequest,
        ) -> NoReturn:
            self.last_response = create_etrade_oauth_injected_token_response(
                request,
                body=_request_body(),
            )
            raise RuntimeError(f"ambiguous transport failure {REQUEST_TOKEN_SECRET}")

    repository, _ = _repository(tmp_path)
    transport = _ResponseThenFailureTransport()

    with pytest.raises(EtradeOAuthTokenTransportError) as caught:
        execute_etrade_oauth_injected_token_exchange(
            currentness_reservation=_reservation(repository),
            signing_intent=_request_intent(),
            issued_token_reference=_token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1),
            resolver=_Resolver(),
            transport=transport,
        )

    assert REQUEST_TOKEN_SECRET not in str(caught.value)
    assert cast(Any, transport.last_response).closed is True
    current = repository.load(EtradeEnvironment.SANDBOX, EtradeSecretScope.SANDBOX_CONSUMER)
    assert current.sequence == 2
    assert current.state.phase is EtradeOAuthSessionPhase.NEEDS_REQUEST_TOKEN


@pytest.mark.parametrize(
    "overrides",
    (
        {"response_origin": "https://apisb.etrade.com"},
        {"http_status": 201},
        {"media_type": "application/json"},
        {"charset": "iso-8859-1"},
        {"tls_peer_verified": False},
        {"redirects_followed": True},
        {"redirect_location": "https://example.invalid/redirect"},
        {"proxy_used": True},
        {"complete": False},
        {"timed_out": True},
        {"transport_error": True},
    ),
)
def test_response_origin_status_media_charset_redirect_proxy_and_terminal_faults_fail_closed(
    tmp_path: Path,
    overrides: dict[str, object],
) -> None:
    repository, _ = _repository(tmp_path)
    transport = _Transport(body=_request_body(), response_overrides=overrides)

    with pytest.raises(EtradeOAuthTokenResponseError):
        execute_etrade_oauth_injected_token_exchange(
            currentness_reservation=_reservation(repository),
            signing_intent=_request_intent(),
            issued_token_reference=_token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1),
            resolver=_Resolver(),
            transport=transport,
        )

    current = repository.load(EtradeEnvironment.SANDBOX, EtradeSecretScope.SANDBOX_CONSUMER)
    assert current.sequence == 2
    assert current.state.phase is EtradeOAuthSessionPhase.NEEDS_REQUEST_TOKEN
    assert cast(Any, transport.last_response).closed is True


@pytest.mark.parametrize(
    "body",
    (
        b"oauth_token=a&oauth_token_secret=b&oauth_callback_confirmed=false",
        b"oauth_token=a&oauth_token=a&oauth_token_secret=b&oauth_callback_confirmed=true",
        b"oauth_token=a&oauth_token_secret=b&oauth_callback_confirmed=true&unknown=x",
        b"oauth_token=%ZZ&oauth_token_secret=b&oauth_callback_confirmed=true",
        b"oauth_token=a+space&oauth_token_secret=b&oauth_callback_confirmed=true",
        b"oauth_token=a&oauth_token_secret=b",
        b"oauth_token=a&&oauth_token_secret=b&oauth_callback_confirmed=true",
        b"oauth_token=a=tail&oauth_token_secret=b&oauth_callback_confirmed=true",
    ),
)
def test_raw_response_form_decoder_rejects_schema_and_encoding_faults(
    tmp_path: Path,
    body: bytes,
) -> None:
    repository, _ = _repository(tmp_path)
    transport = _Transport(body=body)

    with pytest.raises(EtradeOAuthTokenResponseError):
        execute_etrade_oauth_injected_token_exchange(
            currentness_reservation=_reservation(repository),
            signing_intent=_request_intent(),
            issued_token_reference=_token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1),
            resolver=_Resolver(),
            transport=transport,
        )

    assert (
        repository.load(
            EtradeEnvironment.SANDBOX,
            EtradeSecretScope.SANDBOX_CONSUMER,
        ).state.phase
        is EtradeOAuthSessionPhase.NEEDS_REQUEST_TOKEN
    )
    assert cast(Any, transport.last_response).closed is True


@pytest.mark.parametrize(
    "resolver",
    (
        _Resolver(failure=RuntimeError(f"resolver leaked {CONSUMER_SECRET}")),
        _Resolver(closed_envelope=True),
        _Resolver(wrong_result=object()),
    ),
)
def test_resolver_failure_wrong_custody_and_lifecycle_reuse_are_sanitized(
    tmp_path: Path,
    resolver: _Resolver,
) -> None:
    repository, _ = _repository(tmp_path)
    transport = _Transport(body=_request_body())

    with pytest.raises(EtradeOAuthTokenResolutionError) as caught:
        execute_etrade_oauth_injected_token_exchange(
            currentness_reservation=_reservation(repository),
            signing_intent=_request_intent(),
            issued_token_reference=_token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1),
            resolver=resolver,
            transport=transport,
        )

    assert CONSUMER_SECRET not in str(caught.value)
    assert transport.calls == 0
    assert (
        repository.load(
            EtradeEnvironment.SANDBOX,
            EtradeSecretScope.SANDBOX_CONSUMER,
        ).sequence
        == 2
    )


def test_wrong_transport_result_is_closed_and_session_state_stays_unchanged(tmp_path: Path) -> None:
    class _Wrong:
        closed = False

        def close(self) -> None:
            self.closed = True

    wrong = _Wrong()
    repository, _ = _repository(tmp_path)
    transport = _Transport(body=_request_body(), wrong_result=wrong)

    with pytest.raises(EtradeOAuthTokenTransportError):
        execute_etrade_oauth_injected_token_exchange(
            currentness_reservation=_reservation(repository),
            signing_intent=_request_intent(),
            issued_token_reference=_token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1),
            resolver=_Resolver(),
            transport=transport,
        )

    assert wrong.closed is True
    current = repository.load(EtradeEnvironment.SANDBOX, EtradeSecretScope.SANDBOX_CONSUMER)
    assert current.sequence == 2
    assert current.state.phase is EtradeOAuthSessionPhase.NEEDS_REQUEST_TOKEN


def test_response_bound_to_another_exact_request_is_rejected(tmp_path: Path) -> None:
    first, _, _, first_transport = _request_exchange(tmp_path / "first")
    assert first_transport.last_response is not None
    repository, _ = _repository(tmp_path / "second")
    transport = _Transport(body=_request_body(), wrong_result=first_transport.last_response)

    with pytest.raises(EtradeOAuthTokenTransportError):
        execute_etrade_oauth_injected_token_exchange(
            currentness_reservation=_reservation(repository),
            signing_intent=_request_intent(nonce="abcdef0123456789"),
            issued_token_reference=_token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1),
            resolver=_Resolver(),
            transport=transport,
        )

    assert first.closed is False
    assert first.raw_response_retained is False
    first.close()


@pytest.mark.parametrize(
    ("binding_name", "mutated_value"),
    (
        ("__intent_sha256", "1" * 64),
        ("__durable_event_sha256", "2" * 64),
        ("__durable_scope_sha256", "3" * 64),
        ("__durable_sequence", 99),
        ("__timeout_milliseconds", 99),
        ("__environment", EtradeEnvironment.PRODUCTION),
        ("__http_method", "POST"),
        ("__endpoint_url", "credential-bearing://forbidden"),
    ),
)
def test_sealed_request_binding_mutation_after_transport_is_detected(
    tmp_path: Path,
    binding_name: str,
    mutated_value: object,
) -> None:
    class _MutatingTransport(_Transport):
        def _exchange_for_token_runtime(
            self,
            request: EtradeOAuthEphemeralTransportRequest,
        ) -> object:
            self.calls += 1
            self.last_request = request
            response = create_etrade_oauth_injected_token_response(
                request,
                body=self.body,
            )
            self.last_response = response
            object.__setattr__(
                request,
                f"_EtradeOAuthEphemeralTransportRequest{binding_name}",
                mutated_value,
            )
            return response

    repository, _ = _repository(tmp_path)
    transport = _MutatingTransport(body=_request_body())
    with pytest.raises(EtradeOAuthTokenTransportError):
        execute_etrade_oauth_injected_token_exchange(
            currentness_reservation=_reservation(repository),
            signing_intent=_request_intent(),
            issued_token_reference=_token_reference(
                EtradeOAuthTokenKind.REQUEST_TOKEN,
                1,
            ),
            resolver=_Resolver(),
            transport=transport,
        )

    assert transport.calls == 1
    assert cast(Any, transport.last_request).closed is True
    assert cast(Any, transport.last_response).closed is True
    current = repository.load(
        EtradeEnvironment.SANDBOX,
        EtradeSecretScope.SANDBOX_CONSUMER,
    )
    assert current.sequence == 2
    assert current.state.phase is EtradeOAuthSessionPhase.NEEDS_REQUEST_TOKEN


def test_receipt_and_result_public_bindings_are_read_only(tmp_path: Path) -> None:
    result, _, _, _ = _request_exchange(tmp_path)
    receipt = result.receipt

    for name, value in (
        ("receipt", receipt),
        ("replay_snapshot", result.replay_snapshot),
        ("successor_state", result.successor_state),
        ("issued_token_reference", result.issued_token_reference),
    ):
        with pytest.raises(AttributeError):
            setattr(result, name, value)
    with pytest.raises(AttributeError):
        receipt.http_status = 201  # type: ignore[misc]
    with pytest.raises(TypeError):
        EtradeOAuthTokenExchangeReceipt(  # type: ignore[call-arg]
            environment=receipt.environment,
            operation=receipt.operation,
            signing_intent_sha256=receipt.signing_intent_sha256,
            durable_scope_sha256=receipt.durable_scope_sha256,
            replay_event_sha256=receipt.replay_event_sha256,
            replay_sequence=receipt.replay_sequence,
            replay_guard_sha256=receipt.replay_guard_sha256,
            issued_token_reference=receipt.issued_token_reference,
            secret_independent_response_binding_sha256=(
                receipt.secret_independent_response_binding_sha256
            ),
        )
    object.__setattr__(receipt, "http_status", 201)
    with pytest.raises(EtradeOAuthTokenRuntimeError):
        _ = receipt.semantic_sha256
    result.close()


def test_resolver_envelope_claim_is_atomic_under_barrier_race(tmp_path: Path) -> None:
    _, snapshot = _repository(tmp_path)
    request = EtradeOAuthTokenResolutionRequest(
        intent=_request_intent(),
        durable_scope_sha256=snapshot.scope_sha256,
        durable_event_sha256=snapshot.current_event_sha256,
        durable_sequence=snapshot.sequence,
        durable_session_state_sha256=snapshot.state.semantic_sha256,
        durable_replay_guard_sha256=snapshot.replay_guard.semantic_sha256,
    )
    envelope = create_etrade_oauth_token_secret_envelope(
        request,
        consumer_key=CONSUMER_KEY,
        consumer_secret=CONSUMER_SECRET,
    )
    barrier = Barrier(3)
    outcomes: list[str] = []

    def consume() -> None:
        barrier.wait()
        try:
            credentials = cast(Any, envelope)._consume(request)
            del credentials
            outcomes.append("claimed")
        except EtradeOAuthTokenResolverLifecycleError:
            outcomes.append("rejected")

    workers = (Thread(target=consume), Thread(target=consume))
    for worker in workers:
        worker.start()
    barrier.wait()
    for worker in workers:
        worker.join()

    assert sorted(outcomes) == ["claimed", "rejected"]
    assert cast(Any, envelope).closed is True


def test_transport_response_presentation_is_atomic_under_barrier_race(
    tmp_path: Path,
) -> None:
    class _RacingTransport:
        transport_id = ETRADE_OAUTH_INJECTED_TRANSPORT_ID
        transport_version = ETRADE_OAUTH_INJECTED_TRANSPORT_VERSION

        def __init__(self) -> None:
            self.outcomes: list[tuple[str, object]] = []

        def _exchange_for_token_runtime(
            self,
            request: EtradeOAuthEphemeralTransportRequest,
        ) -> object:
            barrier = Barrier(3)

            def present() -> None:
                barrier.wait()
                try:
                    response = create_etrade_oauth_injected_token_response(
                        request,
                        body=_request_body(),
                    )
                    self.outcomes.append(("presented", response))
                except EtradeOAuthTokenTransportError as error:
                    self.outcomes.append(("rejected", error))

            workers = (Thread(target=present), Thread(target=present))
            for worker in workers:
                worker.start()
            barrier.wait()
            for worker in workers:
                worker.join()
            return next(value for outcome, value in self.outcomes if outcome == "presented")

    repository, _ = _repository(tmp_path)
    transport = _RacingTransport()
    result = execute_etrade_oauth_injected_token_exchange(
        currentness_reservation=_reservation(repository),
        signing_intent=_request_intent(),
        issued_token_reference=_token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1),
        resolver=_Resolver(),
        transport=transport,
    )

    assert sorted(outcome for outcome, _ in transport.outcomes) == [
        "presented",
        "rejected",
    ]
    assert result._matches_test_values_once(REQUEST_TOKEN, REQUEST_TOKEN_SECRET)


def test_currentness_claim_is_atomic_and_binds_the_winning_thread(tmp_path: Path) -> None:
    repository, _ = _repository(tmp_path)
    reservation = _reservation(repository)
    barrier = Barrier(3)
    outcomes: list[str] = []

    def claim() -> None:
        barrier.wait()
        try:
            cast(Any, reservation)._claim_snapshot_for_injected_token_runtime()
            outcomes.append("claimed")
        except EtradeOAuthCoordinatorConflict:
            outcomes.append("rejected")

    workers = (Thread(target=claim), Thread(target=claim))
    for worker in workers:
        worker.start()
    barrier.wait()
    for worker in workers:
        worker.join()

    assert sorted(outcomes) == ["claimed", "rejected"]
    with pytest.raises(EtradeOAuthCoordinatorConflict):
        cast(Any, reservation)._reserve_signing_intent_for_injected_token_runtime(_request_intent())
    reservation.close()
    assert reservation.closed is True


def test_result_claim_and_close_are_atomic_under_barrier_race(tmp_path: Path) -> None:
    result, _, _, _ = _request_exchange(tmp_path)
    barrier = Barrier(3)
    outcomes: list[str] = []

    def consume() -> None:
        barrier.wait()
        try:
            matched = result._matches_test_values_once(
                REQUEST_TOKEN,
                REQUEST_TOKEN_SECRET,
            )
            outcomes.append("matched" if matched else "mismatch")
        except EtradeOAuthTokenResolverLifecycleError:
            outcomes.append("rejected")

    workers = (Thread(target=consume), Thread(target=consume))
    for worker in workers:
        worker.start()
    barrier.wait()
    for worker in workers:
        worker.join()

    assert sorted(outcomes) == ["matched", "rejected"]
    assert result.closed is True
    assert result.raw_response_retained is False


def test_ephemeral_objects_are_redacted_noncopyable_nonserializable_and_secret_free_in_sql(
    tmp_path: Path,
) -> None:
    result, repository, resolver, transport = _request_exchange(tmp_path)
    secrets = (
        CONSUMER_KEY,
        CONSUMER_SECRET,
        REQUEST_TOKEN,
        REQUEST_TOKEN_SECRET,
        REQUEST_HEADER,
    )
    representations = (
        repr(result),
        str(result),
        repr(result.receipt),
        repr(resolver.last_envelope),
        repr(transport.last_request),
        repr(transport.last_response),
        result.receipt.semantic_sha256,
        result.receipt.secret_independent_response_binding_sha256,
    )
    for secret in secrets:
        assert all(secret not in representation for representation in representations)
    assert not hasattr(result, "token")
    assert not hasattr(result, "token_secret")
    assert not hasattr(result, "raw_response")
    assert not hasattr(result, "response_sha256")
    assert not hasattr(transport.last_request, "authorization_header")
    assert not hasattr(transport.last_request, "signature")
    for private_binding in (
        "intent",
        "operation",
        "environment",
        "http_method",
        "endpoint_url",
        "durable_scope_sha256",
        "durable_event_sha256",
        "durable_sequence",
        "timeout_milliseconds",
    ):
        assert not hasattr(transport.last_request, private_binding)
    assert not hasattr(transport.last_response, "body")
    for custody in (result, transport.last_request, transport.last_response):
        with pytest.raises(TypeError):
            pickle.dumps(custody)
        with pytest.raises(TypeError):
            copy.copy(custody)
        with pytest.raises(TypeError):
            copy.deepcopy(custody)

    engine = repository._engine
    with engine.connect() as connection:
        rows = (
            connection.execute(sa.select(phase4_etrade_oauth_session_events)).mappings().all(),
            connection.execute(sa.select(phase4_etrade_oauth_session_heads)).mappings().all(),
        )
    persisted = repr(rows)
    for secret in secrets:
        assert secret not in persisted
    assert result._matches_test_values_once(REQUEST_TOKEN, REQUEST_TOKEN_SECRET)


def test_receipt_digests_are_independent_of_secret_values(tmp_path: Path) -> None:
    first, _, _, _ = _request_exchange(
        tmp_path / "first",
        transport=_Transport(body=_request_body("token-one", "secret-one")),
    )
    second, _, _, _ = _request_exchange(
        tmp_path / "second",
        resolver=_Resolver(consumer_key="other-key", consumer_secret="other-secret"),
        transport=_Transport(body=_request_body("token-two", "secret-two")),
    )

    assert first.receipt.semantic_sha256 == second.receipt.semantic_sha256
    assert (
        first.receipt.secret_independent_response_binding_sha256
        == second.receipt.secret_independent_response_binding_sha256
    )
    assert first._matches_test_values_once("token-one", "secret-one")
    assert second._matches_test_values_once("token-two", "secret-two")


def test_runtime_source_has_no_network_logging_filesystem_or_production_caller_import() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    source_path = repository_root / "packages" / "application" / "etrade_oauth_token_runtime.py"
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported_roots.add(node.module.partition(".")[0])

    assert not imported_roots.intersection(
        {"httpx", "requests", "socket", "urllib3", "logging", "os", "pathlib", "subprocess"}
    )
    assert "SqlEtradeOAuthCoordinator" not in source
    assert "https://" not in source
    assert "def token(" not in source
    assert ETRADE_OAUTH_TOKEN_RUNTIME_CONTRACT_VERSION in source
    assert ETRADE_OAUTH_TOKEN_RESPONSE_MEDIA_TYPE in source
    assert ETRADE_OAUTH_TOKEN_RESPONSE_CHARSET in source
    coordinator_path = repository_root / "packages" / "persistence" / "etrade_oauth_coordinator.py"
    for production_root in (repository_root / "apps", repository_root / "packages"):
        for candidate in production_root.rglob("*.py"):
            candidate_source = candidate.read_text(encoding="utf-8")
            if candidate != source_path:
                assert "execute_etrade_oauth_injected_token_exchange" not in candidate_source
            if candidate != coordinator_path:
                assert "issue_token_runtime_currentness_reservation" not in candidate_source
