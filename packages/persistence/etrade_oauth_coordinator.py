"""Durable, atomic E*TRADE OAuth replay and sanitized session coordination.

This repository is a local SQL boundary.  It stores an authenticated journal
of sanitized session evidence and replay/high-water deltas, with one current
head for each environment and consumer-secret scope.  It never accepts secret
values, signatures, headers, URLs, network clients, provider callbacks, account
identities, or trading commands.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any, cast

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from packages.adapters.broker.etrade import (
    ETRADE_PROVIDER,
    EtradeEnvironment,
    EtradeSecretScope,
)
from packages.adapters.broker.etrade_oauth import (
    EtradeOAuthConsumerSecretReference,
    EtradeOAuthContractError,
    EtradeOAuthReauthorizationReason,
    EtradeOAuthReplayGuard,
    EtradeOAuthSessionPhase,
    EtradeOAuthSessionState,
    EtradeOAuthSigningTimeHighWater,
    EtradeOAuthTokenKind,
    EtradeOAuthTokenSecretReference,
)
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.persistence.account_coordinator import _write_transaction
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.immutable import (
    ImmutableFactConflict,
    assert_immutable,
    insert_or_verify_atomic,
)
from packages.persistence.schema import (
    phase4_etrade_oauth_session_events,
    phase4_etrade_oauth_session_heads,
)

ETRADE_OAUTH_COORDINATOR_CONTRACT_VERSION = "phase4am-durable-etrade-oauth-replay-session-head-v1"

_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})
_AUTHORITY_FIELDS = (
    "credential_resolution_authorized",
    "provider_response_authentication_authorized",
    "browser_authorization_authorized",
    "callback_handling_authorized",
    "provider_network_authorized",
    "provider_origin_authenticated",
    "account_binding_authorized",
    "broker_call_authorized",
    "broker_mutation_authorized",
    "paper_startup_authorized",
    "live_startup_authorized",
    "trading_effect_authorized",
)


class EtradeOAuthCoordinatorError(RuntimeError):
    """Durable sanitized OAuth coordination is unavailable or malformed."""


class EtradeOAuthCoordinatorConflict(EtradeOAuthCoordinatorError):
    """A replay, stale branch, rollback, or immutable reuse was rejected."""


class EtradeOAuthCoordinatorNotFound(EtradeOAuthCoordinatorError):
    """No durable OAuth head exists for the requested stable scope."""


def _is_token_empty_reauthorization_state(state: EtradeOAuthSessionState) -> bool:
    return (
        state.phase is EtradeOAuthSessionPhase.NEEDS_REQUEST_TOKEN
        and state.generation > 1
        and state.request_token_reference is None
        and state.access_token_reference is None
    )


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(value: object) -> str:
    return _sha256_bytes(canonical_json_bytes(value))


def _require_exact_state(value: object, field_name: str) -> EtradeOAuthSessionState:
    if type(value) is not EtradeOAuthSessionState:
        raise EtradeOAuthCoordinatorConflict(
            f"E*TRADE OAuth coordinator {field_name} must be an exact sanitized session state"
        )
    state = cast(EtradeOAuthSessionState, value)
    try:
        state.__post_init__()
    except EtradeOAuthContractError as error:
        raise EtradeOAuthCoordinatorConflict(str(error)) from error
    return state


def _require_exact_guard(value: object) -> EtradeOAuthReplayGuard:
    if type(value) is not EtradeOAuthReplayGuard:
        raise EtradeOAuthCoordinatorConflict(
            "E*TRADE OAuth coordinator replay guard must use the exact sanitized type"
        )
    guard = cast(EtradeOAuthReplayGuard, value)
    try:
        guard.__post_init__()
    except EtradeOAuthContractError as error:
        raise EtradeOAuthCoordinatorConflict(str(error)) from error
    return guard


def etrade_oauth_coordinator_scope_sha256(
    environment: EtradeEnvironment,
    consumer_scope: EtradeSecretScope,
) -> str:
    """Identify one stable environment/consumer-secret scope across revisions."""

    if type(environment) is not EtradeEnvironment or type(consumer_scope) is not EtradeSecretScope:
        raise EtradeOAuthCoordinatorConflict(
            "E*TRADE OAuth durable scope requires exact environment and secret-scope types"
        )
    expected_scope = (
        EtradeSecretScope.SANDBOX_CONSUMER
        if environment is EtradeEnvironment.SANDBOX
        else EtradeSecretScope.PRODUCTION_CONSUMER
    )
    if consumer_scope is not expected_scope:
        raise EtradeOAuthCoordinatorConflict(
            "E*TRADE OAuth durable scope crosses environment and consumer-secret scope"
        )
    return _sha256(
        (
            ETRADE_OAUTH_COORDINATOR_CONTRACT_VERSION,
            "environment_consumer_scope",
            ETRADE_PROVIDER.value,
            environment,
            consumer_scope,
        )
    )


def rotate_etrade_oauth_consumer_reference(
    state: EtradeOAuthSessionState,
    successor_reference: EtradeOAuthConsumerSecretReference,
) -> EtradeOAuthSessionState:
    """Create one sanitized, predecessor-bound consumer-reference rotation."""

    state = _require_exact_state(state, "consumer-reference rotation state")
    if type(successor_reference) is not EtradeOAuthConsumerSecretReference:
        raise EtradeOAuthCoordinatorConflict(
            "consumer-reference rotation requires the exact typed nonsecret reference"
        )
    try:
        successor_reference.__post_init__()
    except EtradeOAuthContractError as error:
        raise EtradeOAuthCoordinatorConflict(str(error)) from error
    if not _is_token_empty_reauthorization_state(state):
        raise EtradeOAuthCoordinatorConflict(
            "consumer-reference rotation requires a token-empty reauthorization generation"
        )
    if (
        successor_reference.environment is not state.environment
        or successor_reference.scope is not state.consumer_reference.scope
        or successor_reference.version <= state.consumer_reference.version
    ):
        raise EtradeOAuthCoordinatorConflict(
            "consumer-reference rotation must advance within the stable environment/scope"
        )
    evidence_sha256 = _sha256(
        (
            ETRADE_OAUTH_COORDINATOR_CONTRACT_VERSION,
            "consumer_reference_rotation",
            state.semantic_sha256,
            state.consumer_reference.semantic_sha256,
            successor_reference.semantic_sha256,
        )
    )
    try:
        return replace(
            state,
            consumer_reference=successor_reference,
            transition_evidence_sha256=evidence_sha256,
            predecessor_sha256=state.semantic_sha256,
        )
    except (TypeError, ValueError, EtradeOAuthContractError) as error:
        raise EtradeOAuthCoordinatorConflict(
            "consumer-reference rotation produced an invalid sanitized session state"
        ) from error


@dataclass(frozen=True, slots=True)
class EtradeOAuthDurableEvent:
    """One authenticated, secret-free journal position."""

    event_sha256: str
    scope_sha256: str
    sequence: int
    previous_event_sha256: str | None
    prior_session_state_sha256: str | None
    state: EtradeOAuthSessionState
    replay_guard_sha256: str
    replay_fingerprint_sha256: str | None
    signing_high_water: EtradeOAuthSigningTimeHighWater | None


@dataclass(frozen=True, slots=True)
class EtradeOAuthDurableSnapshot:
    """Fully reconstructed current head and authenticated journal."""

    scope_sha256: str
    state: EtradeOAuthSessionState
    replay_guard: EtradeOAuthReplayGuard
    events: tuple[EtradeOAuthDurableEvent, ...]

    @property
    def sequence(self) -> int:
        return self.events[-1].sequence

    @property
    def current_event_sha256(self) -> str:
        return self.events[-1].event_sha256

    @property
    def authority(self) -> Mapping[str, bool]:
        return MappingProxyType({name: False for name in _AUTHORITY_FIELDS})


@dataclass(frozen=True, slots=True)
class _ReplayDelta:
    fingerprint_sha256: str | None
    signing_high_water: EtradeOAuthSigningTimeHighWater | None


def _replay_delta(
    current: EtradeOAuthReplayGuard,
    proposed: EtradeOAuthReplayGuard,
) -> _ReplayDelta:
    current = _require_exact_guard(current)
    proposed = _require_exact_guard(proposed)
    prefix_length = len(current.consumed_fingerprints)
    if proposed.consumed_fingerprints[:prefix_length] != current.consumed_fingerprints:
        raise EtradeOAuthCoordinatorConflict(
            "durable OAuth replay fingerprints cannot disappear, reorder, or change"
        )
    additions = proposed.consumed_fingerprints[prefix_length:]
    if len(additions) > 1:
        raise EtradeOAuthCoordinatorConflict(
            "one durable OAuth advancement may consume at most one replay fingerprint"
        )

    current_high_waters = {value.scope_sha256: value for value in current.signing_time_high_waters}
    proposed_high_waters = {
        value.scope_sha256: value for value in proposed.signing_time_high_waters
    }
    if not current_high_waters.keys() <= proposed_high_waters.keys():
        raise EtradeOAuthCoordinatorConflict(
            "durable OAuth signing high-water scopes cannot disappear"
        )
    changed: list[EtradeOAuthSigningTimeHighWater] = []
    for scope_sha256, old in current_high_waters.items():
        new = proposed_high_waters[scope_sha256]
        if new == old:
            continue
        if new.generation < old.generation or new.unix_seconds < old.unix_seconds:
            raise EtradeOAuthCoordinatorConflict(
                "durable OAuth signing generation or time cannot roll back"
            )
        changed.append(new)
    for scope_sha256 in proposed_high_waters.keys() - current_high_waters.keys():
        changed.append(proposed_high_waters[scope_sha256])
    if len(changed) > 1:
        raise EtradeOAuthCoordinatorConflict(
            "one durable OAuth advancement may update at most one signing high-water scope"
        )
    if not additions and changed:
        raise EtradeOAuthCoordinatorConflict(
            "a durable OAuth signing high-water update requires one new replay fingerprint"
        )
    return _ReplayDelta(
        fingerprint_sha256=None if not additions else additions[0],
        signing_high_water=None if not changed else changed[0],
    )


def _apply_replay_delta(
    current: EtradeOAuthReplayGuard,
    delta: _ReplayDelta,
) -> EtradeOAuthReplayGuard:
    fingerprints = current.consumed_fingerprints
    high_waters = {value.scope_sha256: value for value in current.signing_time_high_waters}
    if delta.signing_high_water is not None and delta.fingerprint_sha256 is None:
        raise EtradeOAuthCoordinatorError(
            "persisted E*TRADE OAuth signing high-water lacks its replay fingerprint"
        )
    if delta.fingerprint_sha256 is not None:
        fingerprints = (*fingerprints, delta.fingerprint_sha256)
    if delta.signing_high_water is not None:
        previous = high_waters.get(delta.signing_high_water.scope_sha256)
        if previous is not None and (
            delta.signing_high_water == previous
            or delta.signing_high_water.generation < previous.generation
            or delta.signing_high_water.unix_seconds < previous.unix_seconds
        ):
            raise EtradeOAuthCoordinatorError(
                "persisted E*TRADE OAuth signing high-water is redundant or rolled back"
            )
        high_waters[delta.signing_high_water.scope_sha256] = delta.signing_high_water
    try:
        return EtradeOAuthReplayGuard(
            consumed_fingerprints=fingerprints,
            signing_time_high_waters=tuple(
                sorted(high_waters.values(), key=lambda value: value.scope_sha256)
            ),
        )
    except EtradeOAuthContractError as error:
        raise EtradeOAuthCoordinatorError(
            "persisted E*TRADE OAuth replay delta is malformed"
        ) from error


def _state_payload(state: EtradeOAuthSessionState) -> str:
    try:
        payload = state.to_evidence_bytes().decode("ascii")
        decoded = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EtradeOAuthCoordinatorConflict(
            "sanitized E*TRADE OAuth session evidence is malformed"
        ) from error
    if type(decoded) is not dict:
        raise EtradeOAuthCoordinatorConflict(
            "sanitized E*TRADE OAuth session evidence must be an object"
        )
    return payload


def _event_material(values: Mapping[str, object]) -> tuple[object, ...]:
    return (
        ETRADE_OAUTH_COORDINATOR_CONTRACT_VERSION,
        "durable_event",
        values["scope_sha256"],
        values["sequence_number"],
        values["environment"],
        values["consumer_scope"],
        values["consumer_reference_version"],
        values["consumer_reference_sha256"],
        values["endpoint_profile_sha256"],
        values["previous_event_sha256"],
        values["prior_session_state_sha256"],
        values["session_state_sha256"],
        values["session_payload_sha256"],
        values["replay_guard_sha256"],
        values["replay_fingerprint_sha256"],
        values["signing_scope_sha256"],
        values["signing_generation"],
        values["signing_unix_seconds"],
    )


def _event_values(
    *,
    scope_sha256: str,
    sequence: int,
    previous_event_sha256: str | None,
    prior_session_state_sha256: str | None,
    state: EtradeOAuthSessionState,
    replay_guard: EtradeOAuthReplayGuard,
    delta: _ReplayDelta,
) -> dict[str, object]:
    payload = _state_payload(state)
    high_water = delta.signing_high_water
    values: dict[str, object] = {
        "scope_sha256": scope_sha256,
        "sequence_number": sequence,
        "environment": state.environment.value,
        "consumer_scope": state.consumer_reference.scope.value,
        "consumer_reference_version": state.consumer_reference.version,
        "consumer_reference_sha256": state.consumer_reference.semantic_sha256,
        "endpoint_profile_sha256": state.endpoint_profile_sha256,
        "previous_event_sha256": previous_event_sha256,
        "prior_session_state_sha256": prior_session_state_sha256,
        "session_state_sha256": state.semantic_sha256,
        "session_payload": payload,
        "session_payload_sha256": _sha256_bytes(payload.encode("ascii")),
        "replay_guard_sha256": replay_guard.semantic_sha256,
        "replay_fingerprint_sha256": delta.fingerprint_sha256,
        "signing_scope_sha256": None if high_water is None else high_water.scope_sha256,
        "signing_generation": None if high_water is None else high_water.generation,
        "signing_unix_seconds": None if high_water is None else high_water.unix_seconds,
    }
    material = _event_material(values)
    values["canonical_payload"] = canonical_json_text(material)
    values["event_sha256"] = _sha256(material)
    return values


def _token_scope(environment: EtradeEnvironment) -> EtradeSecretScope:
    return (
        EtradeSecretScope.SANDBOX_TOKEN
        if environment is EtradeEnvironment.SANDBOX
        else EtradeSecretScope.PRODUCTION_TOKEN
    )


def _decode_state(row: RowMapping) -> EtradeOAuthSessionState:
    try:
        payload_text = row["session_payload"]
        if type(payload_text) is not str:
            raise TypeError("session payload is not text")
        payload = json.loads(payload_text)
        if type(payload) is not dict:
            raise TypeError("session payload is not an object")
        environment = EtradeEnvironment(str(row["environment"]))
        consumer_scope = EtradeSecretScope(str(row["consumer_scope"]))
        consumer_reference = EtradeOAuthConsumerSecretReference(
            environment=environment,
            scope=consumer_scope,
            version=int(row["consumer_reference_version"]),
        )
        request_version = payload["request_token_reference_version"]
        access_version = payload["access_token_reference_version"]
        token_scope = _token_scope(environment)
        state = EtradeOAuthSessionState(
            provider=ETRADE_PROVIDER,
            environment=environment,
            endpoint_profile_sha256=str(row["endpoint_profile_sha256"]),
            consumer_reference=consumer_reference,
            phase=EtradeOAuthSessionPhase(str(payload["phase"])),
            generation=int(payload["generation"]),
            renewal_count=int(payload["renewal_count"]),
            highest_token_reference_version=int(payload["highest_token_reference_version"]),
            trusted_time_high_water_seconds=int(payload["trusted_time_high_water_seconds"]),
            transition_evidence_sha256=cast(str | None, payload["transition_evidence_sha256"]),
            request_token_reference=(
                None
                if request_version is None
                else EtradeOAuthTokenSecretReference(
                    environment=environment,
                    scope=token_scope,
                    kind=EtradeOAuthTokenKind.REQUEST_TOKEN,
                    version=int(request_version),
                )
            ),
            access_token_reference=(
                None
                if access_version is None
                else EtradeOAuthTokenSecretReference(
                    environment=environment,
                    scope=token_scope,
                    kind=EtradeOAuthTokenKind.ACCESS_TOKEN,
                    version=int(access_version),
                )
            ),
            request_token_intent_sha256=cast(str | None, payload["request_token_intent_sha256"]),
            authorization_challenge_sha256=cast(
                str | None, payload["authorization_challenge_sha256"]
            ),
            access_token_intent_sha256=cast(str | None, payload["access_token_intent_sha256"]),
            issued_at_seconds=cast(int | None, payload["issued_at_seconds"]),
            last_activity_at_seconds=cast(int | None, payload["last_activity_at_seconds"]),
            last_observed_at_seconds=cast(int | None, payload["last_observed_at_seconds"]),
            expires_at_seconds=cast(int | None, payload["expires_at_seconds"]),
            reauthorization_reason=(
                None
                if payload["reauthorization_reason"] is None
                else EtradeOAuthReauthorizationReason(str(payload["reauthorization_reason"]))
            ),
            predecessor_sha256=cast(str | None, payload["predecessor_sha256"]),
        )
    except (KeyError, TypeError, ValueError, EtradeOAuthContractError) as error:
        raise EtradeOAuthCoordinatorError(
            "persisted E*TRADE OAuth sanitized session evidence is malformed"
        ) from error
    if (
        payload_text != state.to_evidence_bytes().decode("ascii")
        or row["session_payload_sha256"] != _sha256_bytes(payload_text.encode("ascii"))
        or row["session_state_sha256"] != state.semantic_sha256
        or row["consumer_reference_sha256"] != consumer_reference.semantic_sha256
    ):
        raise EtradeOAuthCoordinatorError(
            "persisted E*TRADE OAuth sanitized session evidence failed authentication"
        )
    return state


def _event_from_row(
    row: RowMapping,
    *,
    expected_scope_sha256: str,
    previous: EtradeOAuthDurableEvent | None,
    current_guard: EtradeOAuthReplayGuard,
) -> tuple[EtradeOAuthDurableEvent, EtradeOAuthReplayGuard]:
    try:
        sequence = int(row["sequence_number"])
        previous_event = cast(str | None, row["previous_event_sha256"])
        prior_state = cast(str | None, row["prior_session_state_sha256"])
        fingerprint = cast(str | None, row["replay_fingerprint_sha256"])
        signing_scope = cast(str | None, row["signing_scope_sha256"])
        signing_generation = cast(int | None, row["signing_generation"])
        signing_seconds = cast(int | None, row["signing_unix_seconds"])
        if signing_scope is None:
            if signing_generation is not None or signing_seconds is not None:
                raise TypeError("partial signing high-water")
            high_water = None
        else:
            if signing_generation is None or signing_seconds is None:
                raise TypeError("partial signing high-water")
            high_water = EtradeOAuthSigningTimeHighWater(
                scope_sha256=signing_scope,
                generation=int(signing_generation),
                unix_seconds=int(signing_seconds),
            )
        state = _decode_state(row)
        if row["scope_sha256"] != expected_scope_sha256:
            raise TypeError("scope mismatch")
        if (
            etrade_oauth_coordinator_scope_sha256(
                state.environment,
                state.consumer_reference.scope,
            )
            != expected_scope_sha256
        ):
            raise TypeError("session state does not derive the journal scope")
        if sequence == 1:
            if previous is not None or previous_event is not None or prior_state is not None:
                raise TypeError("malformed journal root")
            if fingerprint is not None or high_water is not None:
                raise TypeError("journal root carries replay delta")
        else:
            if previous is None or sequence != previous.sequence + 1:
                raise TypeError("non-contiguous journal sequence")
            if previous_event != previous.event_sha256:
                raise TypeError("journal predecessor mismatch")
            if prior_state != previous.state.semantic_sha256:
                raise TypeError("session predecessor cursor mismatch")
            if (
                state.semantic_sha256 != previous.state.semantic_sha256
                and state.predecessor_sha256 != previous.state.semantic_sha256
            ):
                raise TypeError("session state forks its durable predecessor")
            if state.environment is not previous.state.environment:
                raise TypeError("session environment changed")
            if state.consumer_reference.scope is not previous.state.consumer_reference.scope:
                raise TypeError("consumer scope changed")
            if state.consumer_reference.version < previous.state.consumer_reference.version:
                raise TypeError("consumer reference version rolled back")
            if state.consumer_reference.version > previous.state.consumer_reference.version and (
                not _is_token_empty_reauthorization_state(previous.state)
                or not _is_token_empty_reauthorization_state(state)
            ):
                raise TypeError("consumer reference rotated outside token-empty reauthorization")
            if state.endpoint_profile_sha256 != previous.state.endpoint_profile_sha256:
                raise TypeError("endpoint profile changed")
            if state.generation < previous.state.generation:
                raise TypeError("session generation rolled back")
            if (
                state.highest_token_reference_version
                < previous.state.highest_token_reference_version
                or state.trusted_time_high_water_seconds
                < previous.state.trusted_time_high_water_seconds
            ):
                raise TypeError("session high-water rolled back")
        delta = _ReplayDelta(fingerprint, high_water)
        next_guard = _apply_replay_delta(current_guard, delta)
        if row["replay_guard_sha256"] != next_guard.semantic_sha256:
            raise TypeError("replay guard digest mismatch")
        values = dict(row)
        material = _event_material(values)
        canonical_payload = canonical_json_text(material)
        event_sha256 = _sha256(material)
        if row["canonical_payload"] != canonical_payload or row["event_sha256"] != event_sha256:
            raise TypeError("event digest mismatch")
    except (KeyError, TypeError, ValueError, EtradeOAuthContractError) as error:
        raise EtradeOAuthCoordinatorError(
            "persisted E*TRADE OAuth journal failed authenticated reconstruction"
        ) from error
    return (
        EtradeOAuthDurableEvent(
            event_sha256=event_sha256,
            scope_sha256=expected_scope_sha256,
            sequence=sequence,
            previous_event_sha256=previous_event,
            prior_session_state_sha256=prior_state,
            state=state,
            replay_guard_sha256=next_guard.semantic_sha256,
            replay_fingerprint_sha256=fingerprint,
            signing_high_water=high_water,
        ),
        next_guard,
    )


def _head_statement(scope_sha256: str, *, lock: bool) -> sa.Select[tuple[Any, ...]]:
    statement = sa.select(phase4_etrade_oauth_session_heads).where(
        phase4_etrade_oauth_session_heads.c.scope_sha256 == scope_sha256
    )
    if lock:
        statement = statement.with_for_update(of=phase4_etrade_oauth_session_heads)
    return statement


def _load_snapshot(
    connection: Connection,
    scope_sha256: str,
    *,
    lock: bool,
) -> EtradeOAuthDurableSnapshot:
    head = connection.execute(_head_statement(scope_sha256, lock=lock)).mappings().one_or_none()
    if head is None:
        raise EtradeOAuthCoordinatorNotFound(
            f"no durable E*TRADE OAuth head exists for scope {scope_sha256!r}"
        )
    rows = tuple(
        connection.execute(
            sa.select(phase4_etrade_oauth_session_events)
            .where(phase4_etrade_oauth_session_events.c.scope_sha256 == scope_sha256)
            .order_by(phase4_etrade_oauth_session_events.c.sequence_number)
        ).mappings()
    )
    if not rows:
        raise EtradeOAuthCoordinatorError("durable E*TRADE OAuth head has no journal root")
    events: list[EtradeOAuthDurableEvent] = []
    guard = EtradeOAuthReplayGuard()
    previous: EtradeOAuthDurableEvent | None = None
    for row in rows:
        event, guard = _event_from_row(
            row,
            expected_scope_sha256=scope_sha256,
            previous=previous,
            current_guard=guard,
        )
        events.append(event)
        previous = event
    latest = events[-1]
    expected_head = {
        "scope_sha256": scope_sha256,
        "environment": latest.state.environment.value,
        "consumer_scope": latest.state.consumer_reference.scope.value,
        "consumer_reference_version": latest.state.consumer_reference.version,
        "consumer_reference_sha256": latest.state.consumer_reference.semantic_sha256,
        "latest_sequence_number": latest.sequence,
        "latest_event_sha256": latest.event_sha256,
        "current_session_state_sha256": latest.state.semantic_sha256,
        "current_replay_guard_sha256": guard.semantic_sha256,
    }
    try:
        assert_immutable(
            phase4_etrade_oauth_session_heads,
            scope_sha256,
            head,
            expected_head,
        )
    except ImmutableFactConflict as error:
        raise EtradeOAuthCoordinatorError(
            "durable E*TRADE OAuth head diverges from authenticated journal"
        ) from error
    return EtradeOAuthDurableSnapshot(
        scope_sha256=scope_sha256,
        state=latest.state,
        replay_guard=guard,
        events=tuple(events),
    )


def _verify_etrade_oauth_coordinator_integrity(connection: Connection) -> None:
    """Authenticate every durable scope and reject orphaned journal history."""

    head_scopes = set(
        connection.scalars(sa.select(phase4_etrade_oauth_session_heads.c.scope_sha256))
    )
    event_scopes = set(
        connection.scalars(sa.select(phase4_etrade_oauth_session_events.c.scope_sha256).distinct())
    )
    if head_scopes != event_scopes:
        raise EtradeOAuthCoordinatorError(
            "durable E*TRADE OAuth journal and current-head scopes diverge"
        )
    for scope_sha256 in sorted(head_scopes):
        _load_snapshot(connection, scope_sha256, lock=False)


class SqlEtradeOAuthCoordinator:
    """Own one atomic current sanitized session/replay head per stable scope."""

    __slots__ = ("_engine",)

    def __init__(self, engine: Engine) -> None:
        if not isinstance(engine, Engine):
            raise EtradeOAuthCoordinatorError(
                "E*TRADE OAuth coordinator requires a SQLAlchemy engine"
            )
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise EtradeOAuthCoordinatorError(
                f"E*TRADE OAuth coordinator does not support {engine.dialect.name!r}"
            )
        self._engine = engine

    def initialize(self, state: EtradeOAuthSessionState) -> EtradeOAuthDurableSnapshot:
        """Commit the exact empty generation-one root, or verify an exact retry."""

        state = _require_exact_state(state, "initial state")
        if (
            state.phase is not EtradeOAuthSessionPhase.NEEDS_REQUEST_TOKEN
            or state.generation != 1
            or state.predecessor_sha256 is not None
            or state.highest_token_reference_version != 0
            or state.trusted_time_high_water_seconds != 0
        ):
            raise EtradeOAuthCoordinatorConflict(
                "durable E*TRADE OAuth initialization requires the exact empty generation-one state"
            )
        scope_sha256 = etrade_oauth_coordinator_scope_sha256(
            state.environment,
            state.consumer_reference.scope,
        )
        guard = EtradeOAuthReplayGuard()
        event_values = _event_values(
            scope_sha256=scope_sha256,
            sequence=1,
            previous_event_sha256=None,
            prior_session_state_sha256=None,
            state=state,
            replay_guard=guard,
            delta=_ReplayDelta(None, None),
        )
        head_values = {
            "scope_sha256": scope_sha256,
            "environment": state.environment.value,
            "consumer_scope": state.consumer_reference.scope.value,
            "consumer_reference_version": state.consumer_reference.version,
            "consumer_reference_sha256": state.consumer_reference.semantic_sha256,
            "latest_sequence_number": 1,
            "latest_event_sha256": event_values["event_sha256"],
            "current_session_state_sha256": state.semantic_sha256,
            "current_replay_guard_sha256": guard.semantic_sha256,
        }
        try:
            with _write_transaction(self._engine) as connection:
                insert_or_verify_atomic(
                    connection,
                    phase4_etrade_oauth_session_events,
                    event_values,
                )
                insert_or_verify_atomic(
                    connection,
                    phase4_etrade_oauth_session_heads,
                    head_values,
                )
                return _load_snapshot(connection, scope_sha256, lock=True)
        except EtradeOAuthCoordinatorError:
            raise
        except (ImmutableFactConflict, IntegrityError) as error:
            raise EtradeOAuthCoordinatorConflict(
                "durable E*TRADE OAuth initialization conflicts with the stable current head"
            ) from error
        except SQLAlchemyError as error:
            raise EtradeOAuthCoordinatorError(
                "durable E*TRADE OAuth initialization failed"
            ) from error

    def load(
        self,
        environment: EtradeEnvironment,
        consumer_scope: EtradeSecretScope,
    ) -> EtradeOAuthDurableSnapshot:
        """Authenticate and reconstruct the full journal before returning its head."""

        scope_sha256 = etrade_oauth_coordinator_scope_sha256(environment, consumer_scope)
        try:
            with _repeatable_read_transaction(self._engine) as connection:
                return _load_snapshot(connection, scope_sha256, lock=False)
        except EtradeOAuthCoordinatorError:
            raise
        except SQLAlchemyError as error:
            raise EtradeOAuthCoordinatorError("durable E*TRADE OAuth load failed") from error

    def advance(
        self,
        expected: EtradeOAuthDurableSnapshot,
        successor_state: EtradeOAuthSessionState,
        next_replay_guard: EtradeOAuthReplayGuard,
    ) -> EtradeOAuthDurableSnapshot:
        """Atomically append one exact state/replay delta and advance its CAS head."""

        if (
            type(expected) is not EtradeOAuthDurableSnapshot
            or type(expected.events) is not tuple
            or not expected.events
            or any(type(event) is not EtradeOAuthDurableEvent for event in expected.events)
        ):
            raise EtradeOAuthCoordinatorConflict(
                "durable E*TRADE OAuth advancement requires the exact expected snapshot"
            )
        expected_state = _require_exact_state(expected.state, "expected state")
        _require_exact_guard(expected.replay_guard)
        successor_state = _require_exact_state(successor_state, "successor state")
        next_replay_guard = _require_exact_guard(next_replay_guard)
        if (
            successor_state.environment is not expected_state.environment
            or successor_state.consumer_reference.scope
            is not expected_state.consumer_reference.scope
        ):
            raise EtradeOAuthCoordinatorConflict(
                "durable E*TRADE OAuth advancement cannot cross environment or consumer scope"
            )
        scope_sha256 = etrade_oauth_coordinator_scope_sha256(
            expected_state.environment,
            expected_state.consumer_reference.scope,
        )
        if expected.scope_sha256 != scope_sha256:
            raise EtradeOAuthCoordinatorConflict(
                "expected E*TRADE OAuth snapshot conflicts with its stable scope"
            )
        try:
            with _write_transaction(self._engine) as connection:
                current = _load_snapshot(connection, scope_sha256, lock=True)
                if (
                    expected.current_event_sha256 != expected.events[-1].event_sha256
                    or expected.sequence != expected.events[-1].sequence
                    or expected.events[-1].state != expected_state
                    or expected.events[-1].replay_guard_sha256
                    != expected.replay_guard.semantic_sha256
                ):
                    raise EtradeOAuthCoordinatorConflict(
                        "expected E*TRADE OAuth snapshot cursor is internally inconsistent"
                    )
                if (
                    successor_state.consumer_reference.version
                    < expected_state.consumer_reference.version
                ):
                    raise EtradeOAuthCoordinatorConflict(
                        "E*TRADE OAuth consumer-reference version cannot roll back"
                    )
                if (
                    successor_state.consumer_reference.version
                    > expected_state.consumer_reference.version
                    and (
                        not _is_token_empty_reauthorization_state(expected_state)
                        or not _is_token_empty_reauthorization_state(successor_state)
                    )
                ):
                    raise EtradeOAuthCoordinatorConflict(
                        "E*TRADE OAuth consumer-reference rotation requires token-empty "
                        "reauthorization states"
                    )
                if (
                    successor_state.endpoint_profile_sha256
                    != expected_state.endpoint_profile_sha256
                ):
                    raise EtradeOAuthCoordinatorConflict(
                        "E*TRADE OAuth endpoint profile cannot change within a durable scope"
                    )
                state_changed = successor_state.semantic_sha256 != expected_state.semantic_sha256
                if (
                    state_changed
                    and successor_state.predecessor_sha256 != expected_state.semantic_sha256
                ):
                    raise EtradeOAuthCoordinatorConflict(
                        "E*TRADE OAuth successor does not bind the exact current state"
                    )
                if (
                    successor_state.generation < expected_state.generation
                    or successor_state.highest_token_reference_version
                    < expected_state.highest_token_reference_version
                    or successor_state.trusted_time_high_water_seconds
                    < expected_state.trusted_time_high_water_seconds
                ):
                    raise EtradeOAuthCoordinatorConflict(
                        "E*TRADE OAuth session generation or high-water cannot roll back"
                    )
                delta = _replay_delta(expected.replay_guard, next_replay_guard)
                values = _event_values(
                    scope_sha256=scope_sha256,
                    sequence=expected.sequence + 1,
                    previous_event_sha256=expected.current_event_sha256,
                    prior_session_state_sha256=expected_state.semantic_sha256,
                    state=successor_state,
                    replay_guard=next_replay_guard,
                    delta=delta,
                )
                if current.current_event_sha256 != expected.current_event_sha256:
                    if (
                        current.sequence == expected.sequence + 1
                        and current.current_event_sha256 == values["event_sha256"]
                        and current.state == successor_state
                        and current.replay_guard == next_replay_guard
                        and current.events[:-1] == expected.events
                    ):
                        return current
                    raise EtradeOAuthCoordinatorConflict(
                        "durable E*TRADE OAuth advancement lost the current head to a stale branch"
                    )
                if current != expected:
                    raise EtradeOAuthCoordinatorConflict(
                        "expected E*TRADE OAuth snapshot conflicts with authenticated current state"
                    )
                if not state_changed and delta.fingerprint_sha256 is None:
                    return current
                insert_or_verify_atomic(
                    connection,
                    phase4_etrade_oauth_session_events,
                    values,
                )
                result = connection.execute(
                    sa.update(phase4_etrade_oauth_session_heads)
                    .where(
                        phase4_etrade_oauth_session_heads.c.scope_sha256 == scope_sha256,
                        phase4_etrade_oauth_session_heads.c.latest_sequence_number
                        == expected.sequence,
                        phase4_etrade_oauth_session_heads.c.latest_event_sha256
                        == expected.current_event_sha256,
                    )
                    .values(
                        consumer_reference_version=successor_state.consumer_reference.version,
                        consumer_reference_sha256=(
                            successor_state.consumer_reference.semantic_sha256
                        ),
                        latest_sequence_number=expected.sequence + 1,
                        latest_event_sha256=values["event_sha256"],
                        current_session_state_sha256=successor_state.semantic_sha256,
                        current_replay_guard_sha256=next_replay_guard.semantic_sha256,
                    )
                )
                if result.rowcount != 1:
                    raise EtradeOAuthCoordinatorConflict(
                        "durable E*TRADE OAuth advancement lost the atomic current-head race"
                    )
                return _load_snapshot(connection, scope_sha256, lock=False)
        except EtradeOAuthCoordinatorError:
            raise
        except (ImmutableFactConflict, IntegrityError) as error:
            raise EtradeOAuthCoordinatorConflict(
                "durable E*TRADE OAuth replay or event identity was already used"
            ) from error
        except SQLAlchemyError as error:
            raise EtradeOAuthCoordinatorError("durable E*TRADE OAuth advancement failed") from error


__all__ = [
    "ETRADE_OAUTH_COORDINATOR_CONTRACT_VERSION",
    "EtradeOAuthCoordinatorConflict",
    "EtradeOAuthCoordinatorError",
    "EtradeOAuthCoordinatorNotFound",
    "EtradeOAuthDurableEvent",
    "EtradeOAuthDurableSnapshot",
    "SqlEtradeOAuthCoordinator",
    "_verify_etrade_oauth_coordinator_integrity",
    "etrade_oauth_coordinator_scope_sha256",
    "rotate_etrade_oauth_consumer_reference",
]
