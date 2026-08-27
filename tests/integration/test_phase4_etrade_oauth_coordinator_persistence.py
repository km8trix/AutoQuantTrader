from __future__ import annotations

import importlib
import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, event
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import Connection, make_url

from packages.adapters.broker.etrade import (
    ETRADE_PRODUCTION_ENDPOINT_PROFILE,
    ETRADE_SANDBOX_ENDPOINT_PROFILE,
    EtradeEnvironment,
    EtradeSecretScope,
)
from packages.adapters.broker.etrade_oauth import (
    ETRADE_OAUTH_INACTIVITY_SECONDS,
    EtradeOAuthBoundVerifier,
    EtradeOAuthOperation,
    EtradeOAuthReplayGuard,
    EtradeOAuthSessionPhase,
    EtradeOAuthSessionState,
    EtradeOAuthSigningTimeHighWater,
    EtradeOAuthTokenKind,
    EtradeOAuthVerifierValue,
    _consume_signing_intent,
    begin_etrade_oauth_out_of_band_authorization,
    begin_etrade_oauth_reauthorization,
    create_etrade_oauth_session,
    observe_etrade_oauth_session_time,
    record_etrade_oauth_access_token_transition,
    record_etrade_oauth_authorization_transition,
    record_etrade_oauth_renewal_transition,
    record_etrade_oauth_request_token_transition,
    record_etrade_oauth_revocation_transition,
    record_etrade_oauth_session_activity,
    require_etrade_oauth_reauthorization,
)
from packages.persistence.database import (
    DatabaseSchemaNotReady,
    create_database_engine,
    verify_operational_schema,
)
from packages.persistence.etrade_oauth_coordinator import (
    EtradeOAuthCoordinatorConflict,
    EtradeOAuthCoordinatorError,
    EtradeOAuthDurableSnapshot,
    SqlEtradeOAuthCoordinator,
    _canonical_signing_scope_sha256,
    _event_values,
    _head_statement,
    _ReplayDelta,
    _verify_etrade_oauth_coordinator_integrity,
    etrade_oauth_coordinator_scope_sha256,
    rotate_etrade_oauth_consumer_reference,
)
from packages.persistence.schema import (
    metadata,
    phase4_etrade_oauth_session_events,
    phase4_etrade_oauth_session_heads,
)
from tests.unit.test_etrade_oauth import (
    SYNTHETIC_ACCESS_TOKEN,
    SYNTHETIC_ACCESS_TOKEN_SECRET,
    SYNTHETIC_CONSUMER_KEY,
    SYNTHETIC_CONSUMER_SECRET,
    SYNTHETIC_REQUEST_TOKEN,
    SYNTHETIC_REQUEST_TOKEN_SECRET,
    SYNTHETIC_VERIFIER,
    _consumer_reference,
    _intent,
    _timestamp,
    _token_reference,
)

ROOT = Path(__file__).resolve().parents[2]
TEST_DATABASE_ENV = "AQT_TEST_POSTGRES_URL"


def _engine(path: Path) -> Engine:
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    metadata.create_all(engine)
    return engine


def _initial(*, consumer_version: int = 1) -> EtradeOAuthSessionState:
    return create_etrade_oauth_session(
        environment=EtradeEnvironment.SANDBOX,
        endpoint_profile=ETRADE_SANDBOX_ENDPOINT_PROFILE,
        consumer_reference=_consumer_reference(version=consumer_version),
    )


def _request_token_advance(
    state: EtradeOAuthSessionState,
    guard: EtradeOAuthReplayGuard,
    *,
    nonce: str = "durable-request-01",
) -> tuple[EtradeOAuthSessionState, EtradeOAuthReplayGuard]:
    intent = _intent(
        EtradeOAuthOperation.REQUEST_TOKEN,
        timestamp=1_700_000_000,
        nonce=nonce,
        consumer_reference=state.consumer_reference,
    )
    return (
        record_etrade_oauth_request_token_transition(
            state,
            signing_intent=intent,
            request_token_reference=_token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1),
        ),
        _consume_signing_intent(guard, intent),
    )


def _active_head(
    repository: SqlEtradeOAuthCoordinator,
) -> tuple[EtradeOAuthDurableSnapshot, EtradeOAuthSessionState]:
    initial = _initial()
    snapshot = repository.initialize(initial)
    received, guard = _request_token_advance(initial, snapshot.replay_guard)
    snapshot = repository.advance(snapshot, received, guard)
    pending = begin_etrade_oauth_out_of_band_authorization(received)
    snapshot = repository.advance(snapshot, pending, guard)
    assert pending.authorization_challenge_sha256 is not None
    authorization = record_etrade_oauth_authorization_transition(
        pending,
        verifier=EtradeOAuthBoundVerifier(
            authorization_challenge_sha256=pending.authorization_challenge_sha256,
            verifier=EtradeOAuthVerifierValue(SYNTHETIC_VERIFIER),
        ),
        replay_guard=guard,
    )
    confirmed = authorization.state
    snapshot = repository.advance(snapshot, confirmed, authorization.next_replay_guard)
    assert confirmed.request_token_reference is not None
    access_intent = _intent(
        EtradeOAuthOperation.ACCESS_TOKEN,
        timestamp=1_700_000_100,
        nonce="durable-access-001",
        consumer_reference=confirmed.consumer_reference,
        token_reference=confirmed.request_token_reference,
        authorization_challenge_sha256=confirmed.authorization_challenge_sha256,
        authorization_state_sha256=confirmed.semantic_sha256,
    )
    access_guard = _consume_signing_intent(authorization.next_replay_guard, access_intent)
    active = record_etrade_oauth_access_token_transition(
        confirmed,
        signing_intent=access_intent,
        access_token_reference=_token_reference(EtradeOAuthTokenKind.ACCESS_TOKEN, 2),
        expires_at=_timestamp(1_700_100_000),
    )
    snapshot = repository.advance(snapshot, active, access_guard)
    return snapshot, active


def _reauthorization_head(
    repository: SqlEtradeOAuthCoordinator,
) -> tuple[EtradeOAuthDurableSnapshot, EtradeOAuthSessionState]:
    snapshot, active = _active_head(repository)
    access_guard = snapshot.replay_guard
    inactive = observe_etrade_oauth_session_time(
        active,
        observed_at=_timestamp(1_700_000_100 + ETRADE_OAUTH_INACTIVITY_SECONDS),
    )
    snapshot = repository.advance(snapshot, inactive, access_guard)
    required = require_etrade_oauth_reauthorization(inactive)
    snapshot = repository.advance(snapshot, required, access_guard)
    restarted = begin_etrade_oauth_reauthorization(required)
    snapshot = repository.advance(snapshot, restarted, access_guard)
    return snapshot, active


def test_sqlite_exact_retry_reconstructs_full_state_and_replay_chain(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "phase4am.sqlite")
    repository = SqlEtradeOAuthCoordinator(engine)
    initial = _initial()
    root = repository.initialize(initial)
    received, guard = _request_token_advance(initial, root.replay_guard)

    advanced = repository.advance(root, received, guard)
    exact_retry = repository.advance(root, received, guard)
    pending = begin_etrade_oauth_out_of_band_authorization(received)
    terminal = repository.advance(advanced, pending, guard)
    reloaded = repository.load(EtradeEnvironment.SANDBOX, EtradeSecretScope.SANDBOX_CONSUMER)
    truncated_expected = replace(advanced, events=(advanced.events[-1],))

    assert exact_retry == advanced
    assert advanced.sequence == 2
    assert terminal == reloaded
    assert reloaded.sequence == 3
    assert reloaded.state == pending
    assert reloaded.replay_guard == guard
    assert tuple(event.sequence for event in reloaded.events) == (1, 2, 3)
    assert all(value is False for value in reloaded.authority.values())
    with pytest.raises(
        EtradeOAuthCoordinatorConflict,
        match="snapshot failed complete authentication",
    ):
        repository.advance(truncated_expected, pending, guard)
    with engine.connect() as connection:
        _verify_etrade_oauth_coordinator_integrity(connection)


def test_initialization_rejects_cross_environment_endpoint_profile(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "phase4am-cross-profile-initialize.sqlite")
    repository = SqlEtradeOAuthCoordinator(engine)
    forged = replace(
        _initial(),
        endpoint_profile_sha256=ETRADE_PRODUCTION_ENDPOINT_PROFILE.semantic_sha256,
    )

    with pytest.raises(EtradeOAuthCoordinatorConflict, match="exact empty generation-one"):
        repository.initialize(forged)

    with engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_etrade_oauth_session_events)
            )
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_etrade_oauth_session_heads)
            )
            == 0
        )


def test_advancement_rejects_phase_skips_missing_replay_and_revoked_resurrection(
    tmp_path: Path,
) -> None:
    source_engine = _engine(tmp_path / "phase4am-forged-active-source.sqlite")
    _, source_active = _active_head(SqlEtradeOAuthCoordinator(source_engine))
    source_engine.dispose()

    skipped_engine = _engine(tmp_path / "phase4am-phase-skip.sqlite")
    skipped_repository = SqlEtradeOAuthCoordinator(skipped_engine)
    skipped_root = skipped_repository.initialize(_initial())
    skipped_active = replace(
        source_active,
        predecessor_sha256=skipped_root.state.semantic_sha256,
    )
    with pytest.raises(EtradeOAuthCoordinatorConflict, match="closed session transition graph"):
        skipped_repository.advance(
            skipped_root,
            skipped_active,
            skipped_root.replay_guard,
        )

    replay_engine = _engine(tmp_path / "phase4am-missing-request-replay.sqlite")
    replay_repository = SqlEtradeOAuthCoordinator(replay_engine)
    initial = _initial()
    root = replay_repository.initialize(initial)
    received, _ = _request_token_advance(initial, root.replay_guard)
    with pytest.raises(EtradeOAuthCoordinatorConflict, match="closed session transition graph"):
        replay_repository.advance(root, received, root.replay_guard)

    resurrection_engine = _engine(tmp_path / "phase4am-revoked-resurrection.sqlite")
    resurrection_repository = SqlEtradeOAuthCoordinator(resurrection_engine)
    active_snapshot, active = _active_head(resurrection_repository)
    assert active.access_token_reference is not None
    assert active.last_activity_at_seconds is not None
    inactivity_boundary = active.last_activity_at_seconds + ETRADE_OAUTH_INACTIVITY_SECONDS
    late_activity = replace(
        active,
        trusted_time_high_water_seconds=inactivity_boundary,
        transition_evidence_sha256="e" * 64,
        last_activity_at_seconds=inactivity_boundary,
        last_observed_at_seconds=inactivity_boundary,
        predecessor_sha256=active.semantic_sha256,
    )
    with pytest.raises(EtradeOAuthCoordinatorConflict, match="closed session transition graph"):
        resurrection_repository.advance(
            active_snapshot,
            late_activity,
            active_snapshot.replay_guard,
        )

    late_revoke_intent = _intent(
        EtradeOAuthOperation.REVOKE_ACCESS_TOKEN,
        timestamp=inactivity_boundary,
        nonce="durable-late-revoke-001",
        consumer_reference=active.consumer_reference,
        token_reference=active.access_token_reference,
    )
    late_revoke_guard = _consume_signing_intent(
        active_snapshot.replay_guard,
        late_revoke_intent,
    )
    late_revoked = replace(
        active,
        phase=EtradeOAuthSessionPhase.ACCESS_TOKEN_REVOKED,
        trusted_time_high_water_seconds=inactivity_boundary,
        transition_evidence_sha256=late_revoke_intent.semantic_sha256,
        last_observed_at_seconds=inactivity_boundary,
        predecessor_sha256=active.semantic_sha256,
    )
    with pytest.raises(EtradeOAuthCoordinatorConflict, match="closed session transition graph"):
        resurrection_repository.advance(
            active_snapshot,
            late_revoked,
            late_revoke_guard,
        )

    revoke_intent = _intent(
        EtradeOAuthOperation.REVOKE_ACCESS_TOKEN,
        timestamp=1_700_000_200,
        nonce="durable-revoke-001",
        consumer_reference=active.consumer_reference,
        token_reference=active.access_token_reference,
    )
    revoked_guard = _consume_signing_intent(active_snapshot.replay_guard, revoke_intent)
    revoked = record_etrade_oauth_revocation_transition(
        active,
        signing_intent=revoke_intent,
    )
    revoked_snapshot = resurrection_repository.advance(
        active_snapshot,
        revoked,
        revoked_guard,
    )
    resurrected = replace(
        revoked,
        phase=EtradeOAuthSessionPhase.ACCESS_TOKEN_ACTIVE,
        transition_evidence_sha256="f" * 64,
        predecessor_sha256=revoked.semantic_sha256,
    )
    with pytest.raises(EtradeOAuthCoordinatorConflict, match="closed session transition graph"):
        resurrection_repository.advance(
            revoked_snapshot,
            resurrected,
            revoked_snapshot.replay_guard,
        )


def test_closed_graph_accepts_activity_renewal_expiry_and_reauthorization(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "phase4am-complete-allowed-graph.sqlite")
    repository = SqlEtradeOAuthCoordinator(engine)
    snapshot, active = _active_head(repository)
    observed = observe_etrade_oauth_session_time(
        active,
        observed_at=_timestamp(1_700_000_200),
    )
    snapshot = repository.advance(snapshot, observed, snapshot.replay_guard)
    activity = record_etrade_oauth_session_activity(
        observed,
        observed_at=_timestamp(1_700_000_300),
    )
    snapshot = repository.advance(snapshot, activity, snapshot.replay_guard)
    assert activity.access_token_reference is not None
    renewal_intent = _intent(
        EtradeOAuthOperation.RENEW_ACCESS_TOKEN,
        timestamp=1_700_000_400,
        nonce="durable-renewal-001",
        consumer_reference=activity.consumer_reference,
        token_reference=activity.access_token_reference,
    )
    renewal_guard = _consume_signing_intent(snapshot.replay_guard, renewal_intent)
    renewed = record_etrade_oauth_renewal_transition(
        activity,
        signing_intent=renewal_intent,
    )
    snapshot = repository.advance(snapshot, renewed, renewal_guard)
    assert renewed.expires_at_seconds is not None
    expired = observe_etrade_oauth_session_time(
        renewed,
        observed_at=_timestamp(renewed.expires_at_seconds),
    )
    snapshot = repository.advance(snapshot, expired, snapshot.replay_guard)
    required = require_etrade_oauth_reauthorization(expired)
    snapshot = repository.advance(snapshot, required, snapshot.replay_guard)
    restarted = begin_etrade_oauth_reauthorization(required)
    snapshot = repository.advance(snapshot, restarted, snapshot.replay_guard)

    assert snapshot.state == restarted
    assert snapshot.sequence == 11


def test_consumer_reference_rotation_stays_on_one_head_and_stale_version_loses(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "phase4am-rotation.sqlite")
    repository = SqlEtradeOAuthCoordinator(engine)
    current, active = _reauthorization_head(repository)
    rotated = rotate_etrade_oauth_consumer_reference(
        current.state,
        _consumer_reference(version=2),
    )
    forged_rotation = replace(rotated, transition_evidence_sha256="e" * 64)

    with pytest.raises(EtradeOAuthCoordinatorConflict, match="exact canonical"):
        repository.advance(current, forged_rotation, current.replay_guard)

    rotation = repository.advance(current, rotated, current.replay_guard)
    exact_retry = repository.advance(current, rotated, current.replay_guard)
    assert rotation.sequence == current.sequence + 1
    assert exact_retry == rotation
    assert rotation.scope_sha256 == current.scope_sha256
    assert rotation.state.consumer_reference.version == 2
    assert (
        repository.load(
            EtradeEnvironment.SANDBOX,
            EtradeSecretScope.SANDBOX_CONSUMER,
        )
        == rotation
    )
    with engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_etrade_oauth_session_heads)
            )
            == 1
        )

    stale_successor = rotate_etrade_oauth_consumer_reference(
        current.state,
        _consumer_reference(version=3),
    )
    with pytest.raises(EtradeOAuthCoordinatorConflict, match="stale branch"):
        repository.advance(current, stale_successor, current.replay_guard)

    with pytest.raises(EtradeOAuthCoordinatorConflict, match="token-empty reauthorization"):
        rotate_etrade_oauth_consumer_reference(active, _consumer_reference(version=2))

    active_engine = _engine(tmp_path / "phase4am-active-rotation.sqlite")
    active_repository = SqlEtradeOAuthCoordinator(active_engine)
    active_snapshot, active_state = _active_head(active_repository)
    forged_active_rotation = replace(
        active_state,
        consumer_reference=_consumer_reference(version=2),
        transition_evidence_sha256="d" * 64,
        predecessor_sha256=active_state.semantic_sha256,
    )
    with pytest.raises(EtradeOAuthCoordinatorConflict, match="token-empty reauthorization"):
        active_repository.advance(
            active_snapshot,
            forged_active_rotation,
            active_snapshot.replay_guard,
        )


def test_replay_only_head_movement_rejects_stale_state_only_advancement(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "phase4am-replay-only-stale.sqlite")
    repository = SqlEtradeOAuthCoordinator(engine)
    initial = _initial()
    root = repository.initialize(initial)
    intent = _intent(
        EtradeOAuthOperation.REQUEST_TOKEN,
        timestamp=1_700_000_000,
        nonce="replay-only-head-01",
        consumer_reference=initial.consumer_reference,
    )
    consumed = _consume_signing_intent(root.replay_guard, intent)
    replay_head = repository.advance(root, initial, consumed)
    received = record_etrade_oauth_request_token_transition(
        initial,
        signing_intent=intent,
        request_token_reference=_token_reference(EtradeOAuthTokenKind.REQUEST_TOKEN, 1),
    )

    with pytest.raises(EtradeOAuthCoordinatorConflict, match="stale branch"):
        repository.advance(root, received, consumed)
    current = repository.advance(replay_head, received, consumed)
    assert current.sequence == 3
    assert current.state == received


def test_split_access_signing_is_one_use_and_then_allows_state_only_transition(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "phase4am-split-access-signing.sqlite")
    repository = SqlEtradeOAuthCoordinator(engine)
    initial = _initial()
    snapshot = repository.initialize(initial)
    received, guard = _request_token_advance(initial, snapshot.replay_guard)
    snapshot = repository.advance(snapshot, received, guard)
    pending = begin_etrade_oauth_out_of_band_authorization(received)
    snapshot = repository.advance(snapshot, pending, guard)
    assert pending.authorization_challenge_sha256 is not None
    authorization = record_etrade_oauth_authorization_transition(
        pending,
        verifier=EtradeOAuthBoundVerifier(
            authorization_challenge_sha256=pending.authorization_challenge_sha256,
            verifier=EtradeOAuthVerifierValue(SYNTHETIC_VERIFIER),
        ),
        replay_guard=guard,
    )
    confirmed = authorization.state
    snapshot = repository.advance(
        snapshot,
        confirmed,
        authorization.next_replay_guard,
    )
    assert confirmed.request_token_reference is not None
    first_intent = _intent(
        EtradeOAuthOperation.ACCESS_TOKEN,
        timestamp=1_700_000_100,
        nonce="split-access-sign-01",
        consumer_reference=confirmed.consumer_reference,
        token_reference=confirmed.request_token_reference,
        authorization_challenge_sha256=confirmed.authorization_challenge_sha256,
        authorization_state_sha256=confirmed.semantic_sha256,
    )
    first_guard = _consume_signing_intent(snapshot.replay_guard, first_intent)
    replay_head = repository.advance(snapshot, confirmed, first_guard)
    second_intent = _intent(
        EtradeOAuthOperation.ACCESS_TOKEN,
        timestamp=1_700_000_100,
        nonce="split-access-sign-02",
        consumer_reference=confirmed.consumer_reference,
        token_reference=confirmed.request_token_reference,
        authorization_challenge_sha256=confirmed.authorization_challenge_sha256,
        authorization_state_sha256=confirmed.semantic_sha256,
    )
    second_guard = _consume_signing_intent(replay_head.replay_guard, second_intent)
    with pytest.raises(EtradeOAuthCoordinatorConflict, match="closed session transition graph"):
        repository.advance(replay_head, confirmed, second_guard)

    active = record_etrade_oauth_access_token_transition(
        confirmed,
        signing_intent=first_intent,
        access_token_reference=_token_reference(EtradeOAuthTokenKind.ACCESS_TOKEN, 2),
        expires_at=_timestamp(1_700_100_000),
    )
    active_head = repository.advance(replay_head, active, replay_head.replay_guard)
    assert active_head.state == active
    assert repository.advance(active_head, active, active_head.replay_guard) == active_head


def test_replay_prefix_removal_reordering_and_high_water_rollback_fail_closed(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "phase4am-replay.sqlite")
    repository = SqlEtradeOAuthCoordinator(engine)
    initial = _initial()
    root = repository.initialize(initial)
    received, guard = _request_token_advance(initial, root.replay_guard)
    advanced = repository.advance(root, received, guard)
    pending = begin_etrade_oauth_out_of_band_authorization(received)

    with pytest.raises(EtradeOAuthCoordinatorConflict, match="cannot disappear"):
        repository.advance(advanced, pending, EtradeOAuthReplayGuard())
    high_water = guard.signing_time_high_waters[0]
    rollback = EtradeOAuthReplayGuard(
        consumed_fingerprints=(*guard.consumed_fingerprints, "f" * 64),
        signing_time_high_waters=(
            type(high_water)(
                scope_sha256=high_water.scope_sha256,
                generation=high_water.generation,
                unix_seconds=high_water.unix_seconds - 1,
            ),
        ),
    )
    with pytest.raises(EtradeOAuthCoordinatorConflict, match="cannot roll back"):
        repository.advance(advanced, pending, rollback)


def test_sqlite_concurrent_conflicting_advancements_have_exactly_one_winner(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "phase4am-concurrency.sqlite")
    repository = SqlEtradeOAuthCoordinator(engine)
    initial = _initial()
    current = repository.initialize(initial)
    first_intent = _intent(
        EtradeOAuthOperation.REQUEST_TOKEN,
        timestamp=1_700_000_000,
        nonce="concurrent-request-01",
        consumer_reference=initial.consumer_reference,
    )
    second_intent = _intent(
        EtradeOAuthOperation.REQUEST_TOKEN,
        timestamp=1_700_000_000,
        nonce="concurrent-request-02",
        consumer_reference=initial.consumer_reference,
    )
    candidates = (
        (initial, _consume_signing_intent(current.replay_guard, first_intent)),
        (initial, _consume_signing_intent(current.replay_guard, second_intent)),
    )
    barrier = Barrier(2)

    def attempt(candidate: tuple[EtradeOAuthSessionState, EtradeOAuthReplayGuard]) -> str:
        barrier.wait()
        try:
            repository.advance(current, *candidate)
        except EtradeOAuthCoordinatorConflict:
            return "conflict"
        return "winner"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(attempt, candidates))

    assert sorted(outcomes) == ["conflict", "winner"]
    reloaded = repository.load(EtradeEnvironment.SANDBOX, EtradeSecretScope.SANDBOX_CONSUMER)
    assert reloaded.sequence == 2
    assert reloaded.state == initial
    assert reloaded.replay_guard in tuple(candidate[1] for candidate in candidates)


def test_tampered_sanitized_payload_or_head_fails_authenticated_load(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "phase4am-tamper.sqlite")
    repository = SqlEtradeOAuthCoordinator(engine)
    root = repository.initialize(_initial())
    with engine.begin() as connection:
        connection.execute(
            sa.update(phase4_etrade_oauth_session_events)
            .where(phase4_etrade_oauth_session_events.c.event_sha256 == root.current_event_sha256)
            .values(session_payload="{}")
        )
    with pytest.raises(EtradeOAuthCoordinatorError, match="sanitized session evidence"):
        repository.load(EtradeEnvironment.SANDBOX, EtradeSecretScope.SANDBOX_CONSUMER)


def test_digest_consistent_cross_environment_scope_forgery_fails_reconstruction(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "phase4am-cross-scope.sqlite")
    production_state = create_etrade_oauth_session(
        environment=EtradeEnvironment.PRODUCTION,
        endpoint_profile=ETRADE_PRODUCTION_ENDPOINT_PROFILE,
        consumer_reference=_consumer_reference(EtradeEnvironment.PRODUCTION),
    )
    forged_scope = etrade_oauth_coordinator_scope_sha256(
        EtradeEnvironment.SANDBOX,
        EtradeSecretScope.SANDBOX_CONSUMER,
    )
    guard = EtradeOAuthReplayGuard()
    values = _event_values(
        scope_sha256=forged_scope,
        sequence=1,
        previous_event_sha256=None,
        prior_session_state_sha256=None,
        state=production_state,
        replay_guard=guard,
        delta=_ReplayDelta(None, None),
    )
    with engine.begin() as connection:
        connection.execute(sa.insert(phase4_etrade_oauth_session_events).values(**values))
        connection.execute(
            sa.insert(phase4_etrade_oauth_session_heads).values(
                scope_sha256=forged_scope,
                environment=production_state.environment.value,
                consumer_scope=production_state.consumer_reference.scope.value,
                consumer_reference_version=production_state.consumer_reference.version,
                consumer_reference_sha256=production_state.consumer_reference.semantic_sha256,
                latest_sequence_number=1,
                latest_event_sha256=values["event_sha256"],
                current_session_state_sha256=production_state.semantic_sha256,
                current_replay_guard_sha256=guard.semantic_sha256,
            )
        )

    repository = SqlEtradeOAuthCoordinator(engine)
    with pytest.raises(EtradeOAuthCoordinatorError, match="authenticated reconstruction"):
        repository.load(EtradeEnvironment.SANDBOX, EtradeSecretScope.SANDBOX_CONSUMER)


def test_digest_consistent_cross_environment_profile_root_fails_schema_verification(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "phase4am-cross-profile-root.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    forged = replace(
        _initial(),
        endpoint_profile_sha256=ETRADE_PRODUCTION_ENDPOINT_PROFILE.semantic_sha256,
    )
    scope_sha256 = etrade_oauth_coordinator_scope_sha256(
        forged.environment,
        forged.consumer_reference.scope,
    )
    guard = EtradeOAuthReplayGuard()
    values = _event_values(
        scope_sha256=scope_sha256,
        sequence=1,
        previous_event_sha256=None,
        prior_session_state_sha256=None,
        state=forged,
        replay_guard=guard,
        delta=_ReplayDelta(None, None),
    )
    with engine.begin() as connection:
        connection.execute(sa.insert(phase4_etrade_oauth_session_events).values(**values))
        connection.execute(
            sa.insert(phase4_etrade_oauth_session_heads).values(
                scope_sha256=scope_sha256,
                environment=forged.environment.value,
                consumer_scope=forged.consumer_reference.scope.value,
                consumer_reference_version=forged.consumer_reference.version,
                consumer_reference_sha256=forged.consumer_reference.semantic_sha256,
                latest_sequence_number=1,
                latest_event_sha256=values["event_sha256"],
                current_session_state_sha256=forged.semantic_sha256,
                current_replay_guard_sha256=guard.semantic_sha256,
            )
        )

    repository = SqlEtradeOAuthCoordinator(engine)
    with pytest.raises(EtradeOAuthCoordinatorError, match="sanitized session evidence"):
        repository.load(EtradeEnvironment.SANDBOX, EtradeSecretScope.SANDBOX_CONSUMER)
    with pytest.raises(DatabaseSchemaNotReady, match=r"Phase 4 E\*TRADE OAuth coordinator"):
        verify_operational_schema(engine, require_phase_zero_facts=False)


def test_digest_consistent_revoked_resurrection_fails_schema_verification(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "phase4am-revoked-resurrection-forgery.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    repository = SqlEtradeOAuthCoordinator(engine)
    active_snapshot, active = _active_head(repository)
    assert active.access_token_reference is not None
    revoke_intent = _intent(
        EtradeOAuthOperation.REVOKE_ACCESS_TOKEN,
        timestamp=1_700_000_200,
        nonce="persisted-revoke-001",
        consumer_reference=active.consumer_reference,
        token_reference=active.access_token_reference,
    )
    revoked_guard = _consume_signing_intent(active_snapshot.replay_guard, revoke_intent)
    revoked = record_etrade_oauth_revocation_transition(
        active,
        signing_intent=revoke_intent,
    )
    revoked_snapshot = repository.advance(active_snapshot, revoked, revoked_guard)
    resurrected = replace(
        revoked,
        phase=EtradeOAuthSessionPhase.ACCESS_TOKEN_ACTIVE,
        transition_evidence_sha256="f" * 64,
        predecessor_sha256=revoked.semantic_sha256,
    )
    values = _event_values(
        scope_sha256=revoked_snapshot.scope_sha256,
        sequence=revoked_snapshot.sequence + 1,
        previous_event_sha256=revoked_snapshot.current_event_sha256,
        prior_session_state_sha256=revoked.semantic_sha256,
        state=resurrected,
        replay_guard=revoked_snapshot.replay_guard,
        delta=_ReplayDelta(None, None),
    )
    with engine.begin() as connection:
        connection.execute(sa.insert(phase4_etrade_oauth_session_events).values(**values))
        connection.execute(
            sa.update(phase4_etrade_oauth_session_heads)
            .where(
                phase4_etrade_oauth_session_heads.c.scope_sha256 == revoked_snapshot.scope_sha256
            )
            .values(
                latest_sequence_number=revoked_snapshot.sequence + 1,
                latest_event_sha256=values["event_sha256"],
                current_session_state_sha256=resurrected.semantic_sha256,
            )
        )

    with pytest.raises(EtradeOAuthCoordinatorError, match="authenticated reconstruction"):
        repository.load(EtradeEnvironment.SANDBOX, EtradeSecretScope.SANDBOX_CONSUMER)
    with pytest.raises(DatabaseSchemaNotReady, match=r"Phase 4 E\*TRADE OAuth coordinator"):
        verify_operational_schema(engine, require_phase_zero_facts=False)


def test_digest_consistent_active_generation_one_root_fails_load_and_schema_verification(
    tmp_path: Path,
) -> None:
    source_engine = _engine(tmp_path / "phase4am-active-root-source.sqlite")
    _, active = _active_head(SqlEtradeOAuthCoordinator(source_engine))
    source_engine.dispose()
    assert active.phase.value == "access_token_active"
    assert active.generation == 1

    database_path = tmp_path / "phase4am-active-root-forgery.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    scope_sha256 = etrade_oauth_coordinator_scope_sha256(
        active.environment,
        active.consumer_reference.scope,
    )
    guard = EtradeOAuthReplayGuard()
    values = _event_values(
        scope_sha256=scope_sha256,
        sequence=1,
        previous_event_sha256=None,
        prior_session_state_sha256=None,
        state=active,
        replay_guard=guard,
        delta=_ReplayDelta(None, None),
    )
    with engine.begin() as connection:
        connection.execute(sa.insert(phase4_etrade_oauth_session_events).values(**values))
        connection.execute(
            sa.insert(phase4_etrade_oauth_session_heads).values(
                scope_sha256=scope_sha256,
                environment=active.environment.value,
                consumer_scope=active.consumer_reference.scope.value,
                consumer_reference_version=active.consumer_reference.version,
                consumer_reference_sha256=active.consumer_reference.semantic_sha256,
                latest_sequence_number=1,
                latest_event_sha256=values["event_sha256"],
                current_session_state_sha256=active.semantic_sha256,
                current_replay_guard_sha256=guard.semantic_sha256,
            )
        )

    repository = SqlEtradeOAuthCoordinator(engine)
    with pytest.raises(EtradeOAuthCoordinatorError, match="authenticated reconstruction"):
        repository.load(EtradeEnvironment.SANDBOX, EtradeSecretScope.SANDBOX_CONSUMER)
    with pytest.raises(DatabaseSchemaNotReady, match=r"Phase 4 E\*TRADE OAuth coordinator"):
        verify_operational_schema(engine, require_phase_zero_facts=False)


def test_digest_consistent_noncanonical_consumer_rotation_fails_reconstruction(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "phase4am-rotation-forgery.sqlite")
    repository = SqlEtradeOAuthCoordinator(engine)
    current, _ = _reauthorization_head(repository)
    canonical = rotate_etrade_oauth_consumer_reference(
        current.state,
        _consumer_reference(version=2),
    )
    forged = replace(canonical, transition_evidence_sha256="e" * 64)
    assert forged != canonical
    values = _event_values(
        scope_sha256=current.scope_sha256,
        sequence=current.sequence + 1,
        previous_event_sha256=current.current_event_sha256,
        prior_session_state_sha256=current.state.semantic_sha256,
        state=forged,
        replay_guard=current.replay_guard,
        delta=_ReplayDelta(None, None),
    )
    with engine.begin() as connection:
        connection.execute(sa.insert(phase4_etrade_oauth_session_events).values(**values))
        connection.execute(
            sa.update(phase4_etrade_oauth_session_heads)
            .where(phase4_etrade_oauth_session_heads.c.scope_sha256 == current.scope_sha256)
            .values(
                consumer_reference_version=forged.consumer_reference.version,
                consumer_reference_sha256=forged.consumer_reference.semantic_sha256,
                latest_sequence_number=current.sequence + 1,
                latest_event_sha256=values["event_sha256"],
                current_session_state_sha256=forged.semantic_sha256,
                current_replay_guard_sha256=current.replay_guard.semantic_sha256,
            )
        )

    with pytest.raises(EtradeOAuthCoordinatorError, match="authenticated reconstruction"):
        repository.load(EtradeEnvironment.SANDBOX, EtradeSecretScope.SANDBOX_CONSUMER)


def test_digest_consistent_persisted_signing_high_water_rollback_fails_reconstruction(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "phase4am-high-water-tamper.sqlite")
    repository = SqlEtradeOAuthCoordinator(engine)
    root = repository.initialize(_initial())
    signing_scope = _canonical_signing_scope_sha256(root.state)
    first_fingerprint = "a" * 64
    second_fingerprint = "b" * 64
    first_high_water = EtradeOAuthSigningTimeHighWater(
        scope_sha256=signing_scope,
        generation=1,
        unix_seconds=1_700_000_000,
    )
    first_guard = EtradeOAuthReplayGuard(
        consumed_fingerprints=(first_fingerprint,),
        signing_time_high_waters=(first_high_water,),
    )
    first_values = _event_values(
        scope_sha256=root.scope_sha256,
        sequence=2,
        previous_event_sha256=root.current_event_sha256,
        prior_session_state_sha256=root.state.semantic_sha256,
        state=root.state,
        replay_guard=first_guard,
        delta=_ReplayDelta(first_fingerprint, first_high_water),
    )
    rolled_back_high_water = EtradeOAuthSigningTimeHighWater(
        scope_sha256=signing_scope,
        generation=1,
        unix_seconds=first_high_water.unix_seconds - 1,
    )
    rolled_back_guard = EtradeOAuthReplayGuard(
        consumed_fingerprints=(first_fingerprint, second_fingerprint),
        signing_time_high_waters=(rolled_back_high_water,),
    )
    second_values = _event_values(
        scope_sha256=root.scope_sha256,
        sequence=3,
        previous_event_sha256=str(first_values["event_sha256"]),
        prior_session_state_sha256=root.state.semantic_sha256,
        state=root.state,
        replay_guard=rolled_back_guard,
        delta=_ReplayDelta(second_fingerprint, rolled_back_high_water),
    )
    with engine.begin() as connection:
        connection.execute(sa.insert(phase4_etrade_oauth_session_events).values(**first_values))
        connection.execute(sa.insert(phase4_etrade_oauth_session_events).values(**second_values))
        connection.execute(
            sa.update(phase4_etrade_oauth_session_heads)
            .where(phase4_etrade_oauth_session_heads.c.scope_sha256 == root.scope_sha256)
            .values(
                latest_sequence_number=3,
                latest_event_sha256=second_values["event_sha256"],
                current_replay_guard_sha256=rolled_back_guard.semantic_sha256,
            )
        )

    with pytest.raises(EtradeOAuthCoordinatorError, match="rolled back"):
        repository.load(EtradeEnvironment.SANDBOX, EtradeSecretScope.SANDBOX_CONSUMER)


def test_persisted_rows_exclude_all_credential_bearing_material(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "phase4am-redaction.sqlite")
    repository = SqlEtradeOAuthCoordinator(engine)
    initial = _initial()
    root = repository.initialize(initial)
    received, guard = _request_token_advance(initial, root.replay_guard)
    repository.advance(root, received, guard)
    with engine.connect() as connection:
        rows = tuple(connection.execute(sa.select(phase4_etrade_oauth_session_events)).mappings())
    persisted_text = repr(tuple(dict(row) for row in rows))
    forbidden = (
        SYNTHETIC_CONSUMER_KEY,
        SYNTHETIC_CONSUMER_SECRET,
        SYNTHETIC_REQUEST_TOKEN,
        SYNTHETIC_REQUEST_TOKEN_SECRET,
        SYNTHETIC_ACCESS_TOKEN,
        SYNTHETIC_ACCESS_TOKEN_SECRET,
        SYNTHETIC_VERIFIER,
        "Authorization",
        "https://",
        "?oauth_",
    )
    assert all(value not in persisted_text for value in forbidden)


def test_sqlite_migration_is_additive_matches_metadata_and_empty_downgrade(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "phase4am-empty-migration.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "0037_phase3_fixture_worker")
    engine = create_database_engine(database_url)
    prior_tables = set(sa.inspect(engine).get_table_names())
    prior_columns = {
        table_name: tuple(column["name"] for column in sa.inspect(engine).get_columns(table_name))
        for table_name in prior_tables
    }
    engine.dispose()

    command.upgrade(config, "0038_phase4_etrade_oauth")

    upgraded = create_database_engine(database_url)
    upgraded_inspector = sa.inspect(upgraded)
    assert set(upgraded_inspector.get_table_names()) == prior_tables | {
        phase4_etrade_oauth_session_events.name,
        phase4_etrade_oauth_session_heads.name,
    }
    assert {
        table_name: tuple(column["name"] for column in upgraded_inspector.get_columns(table_name))
        for table_name in prior_tables
    } == prior_columns
    for table in (
        phase4_etrade_oauth_session_events,
        phase4_etrade_oauth_session_heads,
    ):
        assert tuple(column["name"] for column in upgraded_inspector.get_columns(table.name)) == (
            tuple(table.c.keys())
        )
    upgraded.dispose()

    command.downgrade(config, "0037_phase3_fixture_worker")

    downgraded = create_database_engine(database_url)
    downgraded_inspector = sa.inspect(downgraded)
    assert set(downgraded_inspector.get_table_names()) == prior_tables
    assert {
        table_name: tuple(column["name"] for column in downgraded_inspector.get_columns(table_name))
        for table_name in prior_tables
    } == prior_columns
    downgraded.dispose()


def test_sqlite_migration_refuses_nonempty_downgrade(tmp_path: Path) -> None:
    database_path = tmp_path / "phase4am-migration.sqlite"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{database_path}")
    command.upgrade(config, "head")
    engine = create_database_engine(f"sqlite+pysqlite:///{database_path}")
    SqlEtradeOAuthCoordinator(engine).initialize(_initial())

    with pytest.raises(
        RuntimeError,
        match=r"refusing to downgrade nonempty E\*TRADE OAuth durable history",
    ):
        command.downgrade(config, "0037_phase3_fixture_worker")
    with engine.connect() as connection:
        assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == (
            "0038_phase4_etrade_oauth"
        )


def test_postgresql_head_statement_locks_exact_stable_scope_row() -> None:
    compiled = str(_head_statement("a" * 64, lock=True).compile(dialect=postgresql.dialect()))
    assert "FOR UPDATE OF phase4_etrade_oauth_session_heads" in compiled
    assert "scope_sha256" in compiled


def test_postgresql_downgrade_locks_both_tables_before_nonempty_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = importlib.import_module("migrations.versions.0038_phase4_etrade_oauth_coordinator")
    connection = MagicMock()
    connection.dialect = SimpleNamespace(name="postgresql")
    connection.scalar.side_effect = (1, 0)
    monkeypatch.setattr(migration.op, "get_bind", lambda: connection)

    with pytest.raises(RuntimeError, match="refusing to downgrade nonempty"):
        migration.downgrade()
    connection.exec_driver_sql.assert_called_once_with(
        "LOCK TABLE phase4_etrade_oauth_session_heads, "
        "phase4_etrade_oauth_session_events IN ACCESS EXCLUSIVE MODE"
    )


def _set_postgresql_search_path(schema_name: str):
    def set_search_path(connection: Connection) -> None:
        connection.execute(
            sa.text("SELECT pg_catalog.set_config('search_path', :schema_name, true)"),
            {"schema_name": schema_name},
        )

    return set_search_path


@pytest.fixture
def phase4am_postgres_engine() -> Iterator[Engine]:
    database_url = os.getenv(TEST_DATABASE_ENV)
    if database_url is None:
        pytest.skip(f"set {TEST_DATABASE_ENV} to run PostgreSQL Phase 4AM tests")
    if make_url(database_url).get_backend_name() != "postgresql":
        pytest.fail(f"{TEST_DATABASE_ENV} must select a PostgreSQL test database")
    base_engine = create_database_engine(database_url)
    schema_name = f"aqt_phase4am_{uuid4().hex}"
    isolated: Engine | None = None
    try:
        with base_engine.begin() as connection:
            connection.execute(sa.schema.CreateSchema(schema_name))
        isolated = create_database_engine(database_url)
        event.listen(isolated, "begin", _set_postgresql_search_path(schema_name))
        metadata.create_all(isolated)
        yield isolated
    finally:
        if isolated is not None:
            isolated.dispose()
        with base_engine.begin() as connection:
            connection.execute(sa.schema.DropSchema(schema_name, cascade=True))
        base_engine.dispose()


def test_postgresql_concurrent_conflicting_advancements_have_one_winner(
    phase4am_postgres_engine: Engine,
) -> None:
    repository = SqlEtradeOAuthCoordinator(phase4am_postgres_engine)
    initial = _initial()
    current = repository.initialize(initial)
    first_intent = _intent(
        EtradeOAuthOperation.REQUEST_TOKEN,
        timestamp=1_700_000_000,
        nonce="postgres-concurrent-request-01",
        consumer_reference=initial.consumer_reference,
    )
    second_intent = _intent(
        EtradeOAuthOperation.REQUEST_TOKEN,
        timestamp=1_700_000_000,
        nonce="postgres-concurrent-request-02",
        consumer_reference=initial.consumer_reference,
    )
    candidates = (
        (initial, _consume_signing_intent(current.replay_guard, first_intent)),
        (initial, _consume_signing_intent(current.replay_guard, second_intent)),
    )
    barrier = Barrier(2)

    def attempt(candidate: tuple[EtradeOAuthSessionState, EtradeOAuthReplayGuard]) -> str:
        barrier.wait()
        try:
            repository.advance(current, *candidate)
        except EtradeOAuthCoordinatorConflict:
            return "conflict"
        return "winner"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(attempt, candidates))
    assert sorted(outcomes) == ["conflict", "winner"]
    reloaded = repository.load(EtradeEnvironment.SANDBOX, EtradeSecretScope.SANDBOX_CONSUMER)
    assert reloaded.sequence == 2
    assert reloaded.state == initial
    assert reloaded.replay_guard in tuple(candidate[1] for candidate in candidates)
