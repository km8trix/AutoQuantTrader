from __future__ import annotations

import ast
import json
import pickle
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from typing import Any, cast

import pytest

import packages.adapters.broker as broker_exports
import packages.adapters.broker.etrade_oauth as etrade_oauth_module
from packages.adapters.broker.etrade import (
    ETRADE_OUT_OF_BAND_CALLBACK_POLICY,
    ETRADE_PRODUCTION_ENDPOINT_PROFILE,
    ETRADE_SANDBOX_ENDPOINT_PROFILE,
    ETRADE_SHARED_ACCESS_TOKEN_URL,
    ETRADE_SHARED_AUTHORIZATION_PAGE,
    ETRADE_SHARED_RENEW_ACCESS_TOKEN_URL,
    ETRADE_SHARED_REQUEST_TOKEN_URL,
    ETRADE_SHARED_REVOKE_ACCESS_TOKEN_URL,
    EtradeEndpointIsolationProfile,
    EtradeEnvironment,
    EtradeOAuthCallbackMode,
    EtradeSecretScope,
)
from packages.adapters.broker.etrade_oauth import (
    ETRADE_OAUTH_HTTP_METHOD,
    ETRADE_OAUTH_INACTIVITY_SECONDS,
    ETRADE_OAUTH_PROTOCOL_VERSION,
    ETRADE_OAUTH_SESSION_CONTRACT_VERSION,
    ETRADE_OAUTH_SIGNATURE_METHOD,
    EtradeOAuthBoundVerifier,
    EtradeOAuthConsumerCredentials,
    EtradeOAuthConsumerKey,
    EtradeOAuthConsumerSecret,
    EtradeOAuthConsumerSecretReference,
    EtradeOAuthContractError,
    EtradeOAuthNonce,
    EtradeOAuthNonsecretParameter,
    EtradeOAuthOperation,
    EtradeOAuthReauthorizationReason,
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
    EtradeOAuthVerifierValue,
    begin_etrade_oauth_out_of_band_authorization,
    begin_etrade_oauth_reauthorization,
    create_etrade_oauth_session,
    create_etrade_oauth_signing_intent,
    etrade_oauth_percent_encode,
    normalize_etrade_oauth_nonsecret_parameters,
    observe_etrade_oauth_session_time,
    record_etrade_oauth_access_token_transition,
    record_etrade_oauth_authorization_transition,
    record_etrade_oauth_renewal_transition,
    record_etrade_oauth_request_token_transition,
    record_etrade_oauth_revocation_transition,
    record_etrade_oauth_session_activity,
    require_etrade_oauth_reauthorization,
    sign_etrade_oauth_intent,
)

TRUST_EVIDENCE_SHA256 = "a" * 64
OTHER_TRUST_EVIDENCE_SHA256 = "b" * 64
SYNTHETIC_CONSUMER_KEY = "synthetic-consumer-key"
SYNTHETIC_CONSUMER_SECRET = "synthetic-consumer-secret"
SYNTHETIC_REQUEST_TOKEN = "synthetic-request-token"
SYNTHETIC_REQUEST_TOKEN_SECRET = "synthetic-request-secret"
SYNTHETIC_ACCESS_TOKEN = "synthetic-access-token"
SYNTHETIC_ACCESS_TOKEN_SECRET = "synthetic-access-secret"
SYNTHETIC_VERIFIER = "synthetic-verifier"

REQUEST_TOKEN_SIGNATURE = "uZ/Pc7jeXduYAMZsxRAjyuJ5Nwo="
REQUEST_TOKEN_HEADER = (
    'OAuth oauth_callback="oob", oauth_consumer_key="synthetic-consumer-key", '
    'oauth_nonce="0123456789abcdef", '
    'oauth_signature="uZ%2FPc7jeXduYAMZsxRAjyuJ5Nwo%3D", '
    'oauth_signature_method="HMAC-SHA1", oauth_timestamp="1700000000", '
    'oauth_version="1.0"'
)
ACCESS_TOKEN_SIGNATURE = "RlccBbeg9IEA3n2Ey8D73RfSaGI="
ACCESS_TOKEN_HEADER = (
    'OAuth oauth_consumer_key="synthetic-consumer-key", '
    'oauth_nonce="fedcba9876543210", '
    'oauth_signature="RlccBbeg9IEA3n2Ey8D73RfSaGI%3D", '
    'oauth_signature_method="HMAC-SHA1", oauth_timestamp="1700000100", '
    'oauth_token="synthetic-request-token", oauth_verifier="synthetic-verifier", '
    'oauth_version="1.0"'
)


def _endpoint(environment: EtradeEnvironment) -> EtradeEndpointIsolationProfile:
    return (
        ETRADE_SANDBOX_ENDPOINT_PROFILE
        if environment is EtradeEnvironment.SANDBOX
        else ETRADE_PRODUCTION_ENDPOINT_PROFILE
    )


def _consumer_reference(
    environment: EtradeEnvironment = EtradeEnvironment.SANDBOX,
    *,
    version: int = 1,
) -> EtradeOAuthConsumerSecretReference:
    scope = (
        EtradeSecretScope.SANDBOX_CONSUMER
        if environment is EtradeEnvironment.SANDBOX
        else EtradeSecretScope.PRODUCTION_CONSUMER
    )
    return EtradeOAuthConsumerSecretReference(
        environment=environment,
        scope=scope,
        version=version,
    )


def _token_reference(
    kind: EtradeOAuthTokenKind,
    version: int,
    environment: EtradeEnvironment = EtradeEnvironment.SANDBOX,
) -> EtradeOAuthTokenSecretReference:
    scope = (
        EtradeSecretScope.SANDBOX_TOKEN
        if environment is EtradeEnvironment.SANDBOX
        else EtradeSecretScope.PRODUCTION_TOKEN
    )
    return EtradeOAuthTokenSecretReference(
        environment=environment,
        scope=scope,
        kind=kind,
        version=version,
    )


def _timestamp(
    unix_seconds: int,
    trust_evidence_sha256: str = TRUST_EVIDENCE_SHA256,
) -> EtradeOAuthTrustedTimestamp:
    return EtradeOAuthTrustedTimestamp(
        unix_seconds=unix_seconds,
        trust_evidence_sha256=trust_evidence_sha256,
    )


def _nonce(value: str = "0123456789abcdef") -> EtradeOAuthNonce:
    return EtradeOAuthNonce(value)


def _intent(
    operation: EtradeOAuthOperation,
    *,
    timestamp: int,
    nonce: str,
    environment: EtradeEnvironment = EtradeEnvironment.SANDBOX,
    consumer_reference: EtradeOAuthConsumerSecretReference | None = None,
    token_reference: EtradeOAuthTokenSecretReference | None = None,
    authorization_challenge_sha256: str | None = None,
) -> EtradeOAuthSigningIntent:
    return create_etrade_oauth_signing_intent(
        environment=environment,
        endpoint_profile=_endpoint(environment),
        operation=operation,
        consumer_reference=consumer_reference or _consumer_reference(environment),
        token_reference=token_reference,
        timestamp=_timestamp(timestamp),
        nonce=_nonce(nonce),
        authorization_challenge_sha256=authorization_challenge_sha256,
    )


def _consumer_credentials(
    reference: EtradeOAuthConsumerSecretReference | None = None,
    *,
    key: str = SYNTHETIC_CONSUMER_KEY,
    secret: str = SYNTHETIC_CONSUMER_SECRET,
) -> EtradeOAuthConsumerCredentials:
    return EtradeOAuthConsumerCredentials(
        reference=reference or _consumer_reference(),
        consumer_key=EtradeOAuthConsumerKey(key),
        consumer_secret=EtradeOAuthConsumerSecret(secret),
    )


def _token_credentials(
    reference: EtradeOAuthTokenSecretReference,
    *,
    token: str,
    secret: str,
) -> EtradeOAuthTokenCredentials:
    return EtradeOAuthTokenCredentials(
        reference=reference,
        token=EtradeOAuthToken(token),
        token_secret=EtradeOAuthTokenSecret(secret),
    )


def _authorization_pending_state() -> EtradeOAuthSessionState:
    consumer_reference = _consumer_reference()
    state = create_etrade_oauth_session(
        environment=EtradeEnvironment.SANDBOX,
        endpoint_profile=ETRADE_SANDBOX_ENDPOINT_PROFILE,
        consumer_reference=consumer_reference,
    )
    request_reference = _token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1)
    request_intent = _intent(
        EtradeOAuthOperation.REQUEST_TOKEN,
        timestamp=1_700_000_000,
        nonce="0123456789abcdef",
        consumer_reference=consumer_reference,
    )
    state = record_etrade_oauth_request_token_transition(
        state,
        signing_intent=request_intent,
        request_token_reference=request_reference,
    )
    return begin_etrade_oauth_out_of_band_authorization(state)


def _active_state(
    *, expires_at: int = 1_700_100_000
) -> tuple[EtradeOAuthSessionState, EtradeOAuthTokenSecretReference]:
    pending = _authorization_pending_state()
    assert pending.authorization_challenge_sha256 is not None
    verifier = EtradeOAuthBoundVerifier(
        authorization_challenge_sha256=pending.authorization_challenge_sha256,
        verifier=EtradeOAuthVerifierValue(SYNTHETIC_VERIFIER),
    )
    confirmed = record_etrade_oauth_authorization_transition(
        pending,
        verifier=verifier,
        replay_guard=EtradeOAuthReplayGuard(),
    ).state
    request_reference = cast(
        EtradeOAuthTokenSecretReference,
        confirmed.request_token_reference,
    )
    access_intent = _intent(
        EtradeOAuthOperation.ACCESS_TOKEN,
        timestamp=1_700_000_100,
        nonce="fedcba9876543210",
        token_reference=request_reference,
        authorization_challenge_sha256=confirmed.authorization_challenge_sha256,
    )
    access_reference = _token_reference(EtradeOAuthTokenKind.ACCESS_TOKEN, 2)
    active = record_etrade_oauth_access_token_transition(
        confirmed,
        signing_intent=access_intent,
        access_token_reference=access_reference,
        expires_at=_timestamp(expires_at),
    )
    return active, access_reference


def test_exact_endpoint_method_callback_and_scope_contract_is_pinned() -> None:
    endpoints = {
        EtradeOAuthOperation.REQUEST_TOKEN: ETRADE_SHARED_REQUEST_TOKEN_URL,
        EtradeOAuthOperation.ACCESS_TOKEN: ETRADE_SHARED_ACCESS_TOKEN_URL,
        EtradeOAuthOperation.RENEW_ACCESS_TOKEN: ETRADE_SHARED_RENEW_ACCESS_TOKEN_URL,
        EtradeOAuthOperation.REVOKE_ACCESS_TOKEN: ETRADE_SHARED_REVOKE_ACCESS_TOKEN_URL,
    }
    request_reference = _token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1)
    access_reference = _token_reference(EtradeOAuthTokenKind.ACCESS_TOKEN, 2)
    for index, (operation, endpoint) in enumerate(endpoints.items()):
        token_reference = {
            EtradeOAuthOperation.REQUEST_TOKEN: None,
            EtradeOAuthOperation.ACCESS_TOKEN: request_reference,
            EtradeOAuthOperation.RENEW_ACCESS_TOKEN: access_reference,
            EtradeOAuthOperation.REVOKE_ACCESS_TOKEN: access_reference,
        }[operation]
        challenge = "c" * 64 if operation is EtradeOAuthOperation.ACCESS_TOKEN else None
        intent = _intent(
            operation,
            timestamp=1_700_000_000 + index,
            nonce=f"oauth-nonce-{index:05d}",
            token_reference=token_reference,
            authorization_challenge_sha256=challenge,
        )
        assert intent.http_method == ETRADE_OAUTH_HTTP_METHOD == "GET"
        assert intent.endpoint_url == endpoint
        assert intent.callback_policy is ETRADE_OUT_OF_BAND_CALLBACK_POLICY
        assert intent.callback_policy.mode is EtradeOAuthCallbackMode.OUT_OF_BAND
        assert intent.callback_policy.oauth_callback_parameter == "oob"
        assert intent.extra_parameters == ()
        assert all(value is False for value in intent.authority.values())

    assert ETRADE_OAUTH_SESSION_CONTRACT_VERSION == ("phase4al-etrade-oauth1-supervised-session-v1")
    assert ETRADE_OAUTH_SIGNATURE_METHOD == "HMAC-SHA1"
    assert ETRADE_OAUTH_PROTOCOL_VERSION == "1.0"
    assert ETRADE_SHARED_AUTHORIZATION_PAGE == "https://us.etrade.com/e/t/etws/authorize"


@pytest.mark.parametrize(
    ("value", "encoded"),
    (
        ("Ladies + Gentlemen", "Ladies%20%2B%20Gentlemen"),
        ("An encoded string!", "An%20encoded%20string%21"),
        ("Dogs, Cats & Mice", "Dogs%2C%20Cats%20%26%20Mice"),
        ("☃", "%E2%98%83"),
        ("-._~", "-._~"),
    ),
)
def test_rfc5849_percent_encoding_vectors(value: str, encoded: str) -> None:
    assert etrade_oauth_percent_encode(value) == encoded


def test_parameter_normalization_encodes_then_sorts_and_rejects_duplicates() -> None:
    assert (
        normalize_etrade_oauth_nonsecret_parameters(
            (
                EtradeOAuthNonsecretParameter("z", "last"),
                EtradeOAuthNonsecretParameter("a3", "a"),
                EtradeOAuthNonsecretParameter("a2", "r b"),
                EtradeOAuthNonsecretParameter("c@", ""),
            )
        )
        == "a2=r%20b&a3=a&c%40=&z=last"
    )

    with pytest.raises(EtradeOAuthContractError, match="duplicate"):
        normalize_etrade_oauth_nonsecret_parameters(
            (
                EtradeOAuthNonsecretParameter("same", "one"),
                EtradeOAuthNonsecretParameter("same", "two"),
            )
        )
    with pytest.raises(EtradeOAuthContractError, match="cannot use oauth_"):
        EtradeOAuthNonsecretParameter("oauth_nonce", "injected")


def test_request_token_hmac_sha1_synthetic_vector_is_exact() -> None:
    intent = _intent(
        EtradeOAuthOperation.REQUEST_TOKEN,
        timestamp=1_700_000_000,
        nonce="0123456789abcdef",
    )
    result = sign_etrade_oauth_intent(
        intent,
        replay_guard=EtradeOAuthReplayGuard(),
        consumer_credentials=_consumer_credentials(),
    )

    assert result.signature_matches(REQUEST_TOKEN_SIGNATURE)
    assert result.authorization_header_matches(REQUEST_TOKEN_HEADER)
    assert len(result.next_replay_guard.consumed_fingerprints) == 1
    assert result.sanitized_evidence_bytes == intent.to_evidence_bytes()
    assert all(value is False for value in result.authority.values())


def test_access_token_hmac_sha1_synthetic_vector_and_verifier_binding_are_exact() -> None:
    request_reference = _token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1)
    challenge_sha256 = "c" * 64
    intent = _intent(
        EtradeOAuthOperation.ACCESS_TOKEN,
        timestamp=1_700_000_100,
        nonce="fedcba9876543210",
        token_reference=request_reference,
        authorization_challenge_sha256=challenge_sha256,
    )
    result = sign_etrade_oauth_intent(
        intent,
        replay_guard=EtradeOAuthReplayGuard(),
        consumer_credentials=_consumer_credentials(),
        token_credentials=_token_credentials(
            request_reference,
            token=SYNTHETIC_REQUEST_TOKEN,
            secret=SYNTHETIC_REQUEST_TOKEN_SECRET,
        ),
        verifier=EtradeOAuthBoundVerifier(
            authorization_challenge_sha256=challenge_sha256,
            verifier=EtradeOAuthVerifierValue(SYNTHETIC_VERIFIER),
        ),
    )

    assert result.signature_matches(ACCESS_TOKEN_SIGNATURE)
    assert result.authorization_header_matches(ACCESS_TOKEN_HEADER)

    with pytest.raises(EtradeOAuthContractError, match="another authorization"):
        sign_etrade_oauth_intent(
            intent,
            replay_guard=EtradeOAuthReplayGuard(),
            consumer_credentials=_consumer_credentials(),
            token_credentials=_token_credentials(
                request_reference,
                token=SYNTHETIC_REQUEST_TOKEN,
                secret=SYNTHETIC_REQUEST_TOKEN_SECRET,
            ),
            verifier=EtradeOAuthBoundVerifier(
                authorization_challenge_sha256="d" * 64,
                verifier=EtradeOAuthVerifierValue(SYNTHETIC_VERIFIER),
            ),
        )


def test_timestamp_nonce_replay_is_rejected_across_operations() -> None:
    request_intent = _intent(
        EtradeOAuthOperation.REQUEST_TOKEN,
        timestamp=1_700_000_000,
        nonce="0123456789abcdef",
    )
    first = sign_etrade_oauth_intent(
        request_intent,
        replay_guard=EtradeOAuthReplayGuard(),
        consumer_credentials=_consumer_credentials(),
    )
    with pytest.raises(EtradeOAuthContractError, match="replay"):
        sign_etrade_oauth_intent(
            request_intent,
            replay_guard=first.next_replay_guard,
            consumer_credentials=_consumer_credentials(),
        )

    access_reference = _token_reference(EtradeOAuthTokenKind.ACCESS_TOKEN, 2)
    renew_intent = _intent(
        EtradeOAuthOperation.RENEW_ACCESS_TOKEN,
        timestamp=1_700_000_000,
        nonce="0123456789abcdef",
        token_reference=access_reference,
    )
    with pytest.raises(EtradeOAuthContractError, match="replay"):
        sign_etrade_oauth_intent(
            renew_intent,
            replay_guard=first.next_replay_guard,
            consumer_credentials=_consumer_credentials(),
            token_credentials=_token_credentials(
                access_reference,
                token=SYNTHETIC_ACCESS_TOKEN,
                secret=SYNTHETIC_ACCESS_TOKEN_SECRET,
            ),
        )


def test_secrets_signatures_headers_and_secret_urls_never_enter_evidence_or_repr() -> None:
    intent = _intent(
        EtradeOAuthOperation.REQUEST_TOKEN,
        timestamp=1_700_000_000,
        nonce="0123456789abcdef",
    )
    credentials = _consumer_credentials()
    result = sign_etrade_oauth_intent(
        intent,
        replay_guard=EtradeOAuthReplayGuard(),
        consumer_credentials=credentials,
    )
    serialized = result.sanitized_evidence_bytes
    representations = (
        repr(EtradeOAuthConsumerKey(SYNTHETIC_CONSUMER_KEY)),
        repr(EtradeOAuthConsumerSecret(SYNTHETIC_CONSUMER_SECRET)),
        repr(credentials),
        repr(EtradeOAuthToken(SYNTHETIC_ACCESS_TOKEN)),
        repr(EtradeOAuthTokenSecret(SYNTHETIC_ACCESS_TOKEN_SECRET)),
        repr(EtradeOAuthVerifierValue(SYNTHETIC_VERIFIER)),
        repr(result),
        repr(intent),
    )
    forbidden = (
        SYNTHETIC_CONSUMER_KEY,
        SYNTHETIC_CONSUMER_SECRET,
        SYNTHETIC_REQUEST_TOKEN,
        SYNTHETIC_REQUEST_TOKEN_SECRET,
        SYNTHETIC_ACCESS_TOKEN,
        SYNTHETIC_ACCESS_TOKEN_SECRET,
        SYNTHETIC_VERIFIER,
        REQUEST_TOKEN_SIGNATURE,
        "Authorization",
        "?key=",
        "?token=",
    )
    for secret in forbidden:
        assert secret.encode("utf-8") not in serialized
        assert all(secret not in representation for representation in representations)
    assert b"nonce_sha256" in serialized
    assert b"0123456789abcdef" not in serialized
    assert not hasattr(result, "authorization_header")
    assert not hasattr(result, "signature")
    assert not hasattr(intent, "authorization_url")
    with pytest.raises(TypeError, match="non-serializable"):
        pickle.dumps(credentials)
    with pytest.raises(TypeError, match="non-serializable"):
        pickle.dumps(result)


def test_secret_changes_do_not_change_sanitized_evidence_or_its_digest() -> None:
    intent = _intent(
        EtradeOAuthOperation.REQUEST_TOKEN,
        timestamp=1_700_000_000,
        nonce="0123456789abcdef",
    )
    first = sign_etrade_oauth_intent(
        intent,
        replay_guard=EtradeOAuthReplayGuard(),
        consumer_credentials=_consumer_credentials(),
    )
    changed = sign_etrade_oauth_intent(
        intent,
        replay_guard=EtradeOAuthReplayGuard(),
        consumer_credentials=_consumer_credentials(secret="different-ephemeral-secret"),
    )
    assert first.sanitized_evidence_bytes == changed.sanitized_evidence_bytes
    assert first.intent.semantic_sha256 == changed.intent.semantic_sha256
    assert first.signature_matches(REQUEST_TOKEN_SIGNATURE)
    assert not changed.signature_matches(REQUEST_TOKEN_SIGNATURE)


def test_session_happy_path_is_explicit_secret_free_and_verifier_single_use() -> None:
    initial = create_etrade_oauth_session(
        environment=EtradeEnvironment.SANDBOX,
        endpoint_profile=ETRADE_SANDBOX_ENDPOINT_PROFILE,
        consumer_reference=_consumer_reference(),
    )
    assert initial.phase is EtradeOAuthSessionPhase.NEEDS_REQUEST_TOKEN
    assert initial.generation == 1
    request_reference = _token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1)
    request_intent = _intent(
        EtradeOAuthOperation.REQUEST_TOKEN,
        timestamp=1_700_000_000,
        nonce="0123456789abcdef",
    )
    received = record_etrade_oauth_request_token_transition(
        initial,
        signing_intent=request_intent,
        request_token_reference=request_reference,
    )
    assert received.phase is EtradeOAuthSessionPhase.REQUEST_TOKEN_RECEIVED
    pending = begin_etrade_oauth_out_of_band_authorization(received)
    assert pending.phase is EtradeOAuthSessionPhase.AUTHORIZATION_PENDING
    assert pending.authorization_challenge_sha256 is not None
    assert not hasattr(pending, "authorization_url")
    verifier = EtradeOAuthBoundVerifier(
        authorization_challenge_sha256=pending.authorization_challenge_sha256,
        verifier=EtradeOAuthVerifierValue(SYNTHETIC_VERIFIER),
    )
    transition = record_etrade_oauth_authorization_transition(
        pending,
        verifier=verifier,
        replay_guard=EtradeOAuthReplayGuard(),
    )
    confirmed = transition.state
    assert confirmed.phase is EtradeOAuthSessionPhase.AUTHORIZATION_CONFIRMED
    assert all(value is False for value in transition.authority.values())
    with pytest.raises(EtradeOAuthContractError, match="replay"):
        record_etrade_oauth_authorization_transition(
            pending,
            verifier=verifier,
            replay_guard=transition.next_replay_guard,
        )

    access_intent = _intent(
        EtradeOAuthOperation.ACCESS_TOKEN,
        timestamp=1_700_000_100,
        nonce="fedcba9876543210",
        token_reference=request_reference,
        authorization_challenge_sha256=confirmed.authorization_challenge_sha256,
    )
    active = record_etrade_oauth_access_token_transition(
        confirmed,
        signing_intent=access_intent,
        access_token_reference=_token_reference(EtradeOAuthTokenKind.ACCESS_TOKEN, 2),
        expires_at=_timestamp(1_700_100_000),
    )
    assert active.phase is EtradeOAuthSessionPhase.ACCESS_TOKEN_ACTIVE
    assert active.request_token_reference is None
    assert active.access_token_reference is not None
    assert active.last_activity_at_seconds == 1_700_000_100
    evidence = active.to_evidence_bytes()
    assert json.loads(evidence)["provider_origin_authenticated"] is False
    assert SYNTHETIC_VERIFIER.encode() not in evidence
    assert all(value is False for value in active.authority.values())


def test_session_time_high_water_rejects_pre_access_and_reauthorization_rollback() -> None:
    pending = _authorization_pending_state()
    assert pending.authorization_challenge_sha256 is not None
    confirmed = record_etrade_oauth_authorization_transition(
        pending,
        verifier=EtradeOAuthBoundVerifier(
            authorization_challenge_sha256=pending.authorization_challenge_sha256,
            verifier=EtradeOAuthVerifierValue(SYNTHETIC_VERIFIER),
        ),
        replay_guard=EtradeOAuthReplayGuard(),
    ).state
    request_reference = cast(
        EtradeOAuthTokenSecretReference,
        confirmed.request_token_reference,
    )
    with pytest.raises(EtradeOAuthContractError, match="cannot regress"):
        record_etrade_oauth_access_token_transition(
            confirmed,
            signing_intent=_intent(
                EtradeOAuthOperation.ACCESS_TOKEN,
                timestamp=1_600_000_000,
                nonce="rollback-access-01",
                token_reference=request_reference,
                authorization_challenge_sha256=confirmed.authorization_challenge_sha256,
            ),
            access_token_reference=_token_reference(EtradeOAuthTokenKind.ACCESS_TOKEN, 2),
            expires_at=_timestamp(1_700_100_000),
        )

    active, _ = _active_state()
    inactive = observe_etrade_oauth_session_time(
        active,
        observed_at=_timestamp(
            cast(int, active.last_activity_at_seconds) + ETRADE_OAUTH_INACTIVITY_SECONDS
        ),
    )
    restarted = begin_etrade_oauth_reauthorization(require_etrade_oauth_reauthorization(inactive))
    assert restarted.trusted_time_high_water_seconds == inactive.last_observed_at_seconds
    with pytest.raises(EtradeOAuthContractError, match="cannot regress"):
        record_etrade_oauth_request_token_transition(
            restarted,
            signing_intent=_intent(
                EtradeOAuthOperation.REQUEST_TOKEN,
                timestamp=restarted.trusted_time_high_water_seconds - 1,
                nonce="rollback-reauth-01",
            ),
            request_token_reference=_token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 3),
        )


def test_post_access_transition_evidence_binds_trusted_time_and_signing_intents() -> None:
    active, access_reference = _active_state()
    observed_seconds = cast(int, active.last_observed_at_seconds) + 1
    first_observation = observe_etrade_oauth_session_time(
        active,
        observed_at=_timestamp(observed_seconds, TRUST_EVIDENCE_SHA256),
    )
    other_observation = observe_etrade_oauth_session_time(
        active,
        observed_at=_timestamp(observed_seconds, OTHER_TRUST_EVIDENCE_SHA256),
    )
    assert first_observation.transition_evidence_sha256 != (
        other_observation.transition_evidence_sha256
    )
    assert first_observation.semantic_sha256 != other_observation.semantic_sha256
    assert first_observation.to_evidence_bytes() != other_observation.to_evidence_bytes()
    assert first_observation.trusted_time_high_water_seconds == observed_seconds

    renewal_intent = _intent(
        EtradeOAuthOperation.RENEW_ACCESS_TOKEN,
        timestamp=observed_seconds + 1,
        nonce="evidence-renew-01",
        token_reference=access_reference,
    )
    renewed = record_etrade_oauth_renewal_transition(
        first_observation,
        signing_intent=renewal_intent,
    )
    assert renewed.transition_evidence_sha256 == renewal_intent.semantic_sha256
    assert renewed.trusted_time_high_water_seconds == renewal_intent.timestamp.unix_seconds

    revocation_intent = _intent(
        EtradeOAuthOperation.REVOKE_ACCESS_TOKEN,
        timestamp=observed_seconds + 2,
        nonce="evidence-revoke-1",
        token_reference=access_reference,
    )
    revoked = record_etrade_oauth_revocation_transition(
        renewed,
        signing_intent=revocation_intent,
    )
    assert revoked.transition_evidence_sha256 == revocation_intent.semantic_sha256
    assert revoked.trusted_time_high_water_seconds == revocation_intent.timestamp.unix_seconds


def test_renewal_activity_inactivity_expiry_revocation_and_reauthorization() -> None:
    active, access_reference = _active_state()
    activity_time = cast(int, active.last_activity_at_seconds) + 100
    active = record_etrade_oauth_session_activity(
        active,
        observed_at=_timestamp(activity_time),
    )
    renew_time = activity_time + 100
    renewal_intent = _intent(
        EtradeOAuthOperation.RENEW_ACCESS_TOKEN,
        timestamp=renew_time,
        nonce="renew-nonce-00001",
        token_reference=access_reference,
    )
    renewed = record_etrade_oauth_renewal_transition(
        active,
        signing_intent=renewal_intent,
    )
    assert renewed.phase is EtradeOAuthSessionPhase.ACCESS_TOKEN_ACTIVE
    assert renewed.renewal_count == 1
    assert renewed.last_activity_at_seconds == renew_time
    assert renewed.expires_at_seconds == active.expires_at_seconds

    inactive = observe_etrade_oauth_session_time(
        renewed,
        observed_at=_timestamp(renew_time + ETRADE_OAUTH_INACTIVITY_SECONDS),
    )
    assert inactive.phase is EtradeOAuthSessionPhase.ACCESS_TOKEN_INACTIVE
    inactive_renewal_time = renew_time + ETRADE_OAUTH_INACTIVITY_SECONDS + 1
    renewed_from_inactive = record_etrade_oauth_renewal_transition(
        inactive,
        signing_intent=_intent(
            EtradeOAuthOperation.RENEW_ACCESS_TOKEN,
            timestamp=inactive_renewal_time,
            nonce="renew-inactive-01",
            token_reference=access_reference,
        ),
    )
    assert renewed_from_inactive.phase is EtradeOAuthSessionPhase.ACCESS_TOKEN_ACTIVE
    assert renewed_from_inactive.renewal_count == 2
    assert renewed_from_inactive.last_activity_at_seconds == inactive_renewal_time
    required = require_etrade_oauth_reauthorization(inactive)
    assert required.phase is EtradeOAuthSessionPhase.REAUTHORIZATION_REQUIRED
    assert required.reauthorization_reason is EtradeOAuthReauthorizationReason.INACTIVITY
    restarted = begin_etrade_oauth_reauthorization(required)
    assert restarted.phase is EtradeOAuthSessionPhase.NEEDS_REQUEST_TOKEN
    assert restarted.generation == 2
    assert restarted.highest_token_reference_version == 2
    with pytest.raises(EtradeOAuthContractError, match="replayed"):
        record_etrade_oauth_request_token_transition(
            restarted,
            signing_intent=_intent(
                EtradeOAuthOperation.REQUEST_TOKEN,
                timestamp=renew_time + ETRADE_OAUTH_INACTIVITY_SECONDS + 1,
                nonce="reauth-nonce-0001",
            ),
            request_token_reference=_token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 2),
        )

    expiring, _ = _active_state(expires_at=1_700_000_200)
    expired = observe_etrade_oauth_session_time(
        expiring,
        observed_at=_timestamp(1_700_000_200),
    )
    assert expired.phase is EtradeOAuthSessionPhase.ACCESS_TOKEN_EXPIRED
    assert (
        require_etrade_oauth_reauthorization(expired).reauthorization_reason
        is EtradeOAuthReauthorizationReason.DAILY_EXPIRY
    )

    revocable, revocable_reference = _active_state()
    revoke_intent = _intent(
        EtradeOAuthOperation.REVOKE_ACCESS_TOKEN,
        timestamp=1_700_000_200,
        nonce="revoke-nonce-0001",
        token_reference=revocable_reference,
    )
    revoked = record_etrade_oauth_revocation_transition(
        revocable,
        signing_intent=revoke_intent,
    )
    assert revoked.phase is EtradeOAuthSessionPhase.ACCESS_TOKEN_REVOKED
    assert (
        require_etrade_oauth_reauthorization(revoked).reauthorization_reason
        is EtradeOAuthReauthorizationReason.REVOCATION
    )


def test_time_regression_and_post_daily_expiry_renewal_activity_fail_closed() -> None:
    active, access_reference = _active_state()
    with pytest.raises(EtradeOAuthContractError, match="cannot regress"):
        observe_etrade_oauth_session_time(
            active,
            observed_at=_timestamp(cast(int, active.last_observed_at_seconds) - 1),
        )

    inactivity_time = cast(int, active.last_activity_at_seconds) + ETRADE_OAUTH_INACTIVITY_SECONDS
    with pytest.raises(EtradeOAuthContractError, match="daily-expired"):
        record_etrade_oauth_renewal_transition(
            active,
            signing_intent=_intent(
                EtradeOAuthOperation.RENEW_ACCESS_TOKEN,
                timestamp=cast(int, active.expires_at_seconds),
                nonce="renew-nonce-00002",
                token_reference=access_reference,
            ),
        )
    with pytest.raises(EtradeOAuthContractError, match="cannot record activity"):
        record_etrade_oauth_session_activity(
            active,
            observed_at=_timestamp(inactivity_time),
        )


@pytest.mark.parametrize(
    ("factory", "match"),
    (
        (
            lambda: EtradeOAuthConsumerSecretReference(
                environment=EtradeEnvironment.SANDBOX,
                scope=EtradeSecretScope.PRODUCTION_CONSUMER,
                version=1,
            ),
            "conflicts",
        ),
        (
            lambda: EtradeOAuthTokenSecretReference(
                environment=EtradeEnvironment.PRODUCTION,
                scope=EtradeSecretScope.SANDBOX_TOKEN,
                kind=EtradeOAuthTokenKind.ACCESS_TOKEN,
                version=1,
            ),
            "conflicts",
        ),
        (
            lambda: EtradeOAuthTrustedTimestamp(True, TRUST_EVIDENCE_SHA256),
            "timestamp",
        ),
        (lambda: EtradeOAuthNonce("too-short"), "nonce"),
    ),
)
def test_scope_timestamp_and_nonce_drift_fail_closed(factory: Any, match: str) -> None:
    with pytest.raises(EtradeOAuthContractError, match=match):
        factory()


def test_raw_string_and_cross_environment_substitution_fail_closed() -> None:
    with pytest.raises(EtradeOAuthContractError, match=r"exact E\*TRADE"):
        EtradeOAuthConsumerSecretReference(
            environment="sandbox",  # type: ignore[arg-type]
            scope=EtradeSecretScope.SANDBOX_CONSUMER,
            version=1,
        )
    with pytest.raises(EtradeOAuthContractError, match=r"exact E\*TRADE"):
        EtradeOAuthTokenSecretReference(
            environment=EtradeEnvironment.SANDBOX,
            scope=EtradeSecretScope.SANDBOX_TOKEN,
            kind="access_token",  # type: ignore[arg-type]
            version=1,
        )
    with pytest.raises(EtradeOAuthContractError, match="conflict"):
        create_etrade_oauth_session(
            environment=EtradeEnvironment.SANDBOX,
            endpoint_profile=ETRADE_PRODUCTION_ENDPOINT_PROFILE,
            consumer_reference=_consumer_reference(),
        )

    intent = _intent(
        EtradeOAuthOperation.REQUEST_TOKEN,
        timestamp=1_700_000_000,
        nonce="0123456789abcdef",
    )
    with pytest.raises(EtradeOAuthContractError, match="endpoint"):
        replace(intent, endpoint_url=ETRADE_SHARED_ACCESS_TOKEN_URL)
    with pytest.raises(EtradeOAuthContractError, match="method"):
        replace(intent, http_method="POST")
    with pytest.raises(EtradeOAuthContractError, match=r"exact E\*TRADE"):
        replace(cast(Any, intent), operation="request_token")
    with pytest.raises(EtradeOAuthContractError, match="no caller parameters"):
        replace(
            intent,
            extra_parameters=(EtradeOAuthNonsecretParameter("injected", "value"),),
        )
    with pytest.raises(EtradeOAuthContractError, match="credentials do not match"):
        sign_etrade_oauth_intent(
            intent,
            replay_guard=EtradeOAuthReplayGuard(),
            consumer_credentials=_consumer_credentials(_consumer_reference(version=2)),
        )


def test_token_kind_operation_and_unsupported_transition_substitution_fail_closed() -> None:
    access_reference = _token_reference(EtradeOAuthTokenKind.ACCESS_TOKEN, 2)
    request_reference = _token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1)
    with pytest.raises(EtradeOAuthContractError, match="operation"):
        _intent(
            EtradeOAuthOperation.ACCESS_TOKEN,
            timestamp=1_700_000_100,
            nonce="fedcba9876543210",
            token_reference=access_reference,
            authorization_challenge_sha256="c" * 64,
        )
    with pytest.raises(EtradeOAuthContractError, match="operation"):
        _intent(
            EtradeOAuthOperation.RENEW_ACCESS_TOKEN,
            timestamp=1_700_000_100,
            nonce="renew-nonce-00003",
            token_reference=request_reference,
        )

    active, _ = _active_state()
    with pytest.raises(EtradeOAuthContractError, match="unsupported"):
        begin_etrade_oauth_out_of_band_authorization(active)
    with pytest.raises(EtradeOAuthContractError, match="unsupported"):
        require_etrade_oauth_reauthorization(active)
    with pytest.raises(EtradeOAuthContractError, match="unsupported"):
        begin_etrade_oauth_reauthorization(active)


def test_frozen_values_revalidate_hostile_replace_and_mutation() -> None:
    intent = _intent(
        EtradeOAuthOperation.REQUEST_TOKEN,
        timestamp=1_700_000_000,
        nonce="0123456789abcdef",
    )
    with pytest.raises(FrozenInstanceError):
        intent.endpoint_url = ETRADE_SHARED_ACCESS_TOKEN_URL  # type: ignore[misc]
    with pytest.raises(EtradeOAuthContractError):
        replace(cast(Any, intent.timestamp), trust_evidence_sha256="0")
    with pytest.raises(EtradeOAuthContractError):
        replace(cast(Any, intent.nonce), value="different")
    with pytest.raises(EtradeOAuthContractError, match="must remain false"):
        active, _ = _active_state()
        replace(active, trading_effect_authorized=True)
    active, _ = _active_state()
    with pytest.raises(EtradeOAuthContractError, match="needs-request-token"):
        replace(active, phase=EtradeOAuthSessionPhase.NEEDS_REQUEST_TOKEN)
    with pytest.raises(EtradeOAuthContractError, match="reauthorization"):
        replace(
            active,
            phase=EtradeOAuthSessionPhase.REAUTHORIZATION_REQUIRED,
            reauthorization_reason=EtradeOAuthReauthorizationReason.DAILY_EXPIRY,
        )


def test_module_is_pure_and_broker_root_exports_are_additive() -> None:
    source_path = Path(etrade_oauth_module.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", maxsplit=1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported_roots.add(node.module.split(".", maxsplit=1)[0])
    assert imported_roots.isdisjoint(
        {
            "asyncio",
            "httpx",
            "os",
            "pathlib",
            "random",
            "requests",
            "secrets",
            "socket",
            "sqlalchemy",
            "time",
        }
    )
    for name in etrade_oauth_module.__all__:
        assert getattr(broker_exports, name) is getattr(etrade_oauth_module, name)
    assert broker_exports.ETRADE_PROVIDER.value == "etrade"
    assert broker_exports.ALPACA_PAPER_ADAPTER_ID == "alpaca-paper"
