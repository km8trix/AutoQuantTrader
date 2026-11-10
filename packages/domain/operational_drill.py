"""Pure, non-authorizing Phase 5 operational fault-drill evidence.

This module deliberately models only local evidence.  It can prove that an
injected observation satisfies a bounded drill specification, but it cannot
claim that a provider, broker, deployment, operator roster, or production
environment was exercised.  Durable storage and deployed drill authority are
separate boundaries.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from packages.domain.canonical import canonical_json_text
from packages.domain.identifiers import canonical_id
from packages.domain.operational_control import OperationalControlState

OPERATIONAL_DRILL_CONTRACT_VERSION = "phase5h-local-operational-drill-evidence-v1"
MAX_OPERATIONAL_DRILL_DEADLINE_MICROSECONDS = 900_000_000

_SAFE_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_STATE_SEVERITY = {
    OperationalControlState.RUNNING: 0,
    OperationalControlState.PAUSED: 1,
    OperationalControlState.DRAINING: 2,
    OperationalControlState.FLATTENING: 3,
    OperationalControlState.HALTED: 4,
}


class OperationalDrillError(ValueError):
    """A local operational-drill specification or observation is malformed."""


class OperationalDrillConflict(OperationalDrillError):
    """Operational-drill evidence crosses immutable identities or semantics."""


class OperationalDrillScenario(StrEnum):
    """The six fault classes required by the Phase 5 drill matrix."""

    KILL_STATE = "kill_state"
    STRATEGY_FAILURE = "strategy_failure"
    ALERT_TOTAL_DELIVERY_FAILURE = "alert_total_delivery_failure"
    DATA_GAP = "data_gap"
    BROKER_DISCONNECT = "broker_disconnect"
    RISK_TRIP = "risk_trip"


REQUIRED_OPERATIONAL_DRILL_SCENARIOS = tuple(OperationalDrillScenario)


class OperationalDrillDisposition(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"


def _require_text(value: str, field_name: str) -> None:
    if type(value) is not str or _SAFE_TEXT.fullmatch(value) is None:
        raise OperationalDrillError(f"{field_name} must contain 1-128 safe visible characters")


def _require_sha256(value: str, field_name: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise OperationalDrillError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_utc(value: datetime, field_name: str) -> None:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise OperationalDrillError(f"{field_name} must be a timezone-aware UTC instant")


def _elapsed_microseconds(started_at: datetime, observed_at: datetime) -> int:
    delta = observed_at - started_at
    return delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds


@dataclass(frozen=True, slots=True)
class LocalOperationalDrillCase:
    """One immutable local drill expectation.

    ``KILL_STATE`` may satisfy its safety expectation through fencing alone, so
    it may retain ``RUNNING`` as its minimum durable control state.  Every
    other required fault class must expect at least ``PAUSED``.
    """

    campaign_id: str
    scope_id: str
    scenario: OperationalDrillScenario
    minimum_control_state: OperationalControlState
    response_deadline_microseconds: int
    fixture_spec_sha256: str

    def __post_init__(self) -> None:
        _require_text(self.campaign_id, "operational-drill campaign ID")
        _require_text(self.scope_id, "operational-drill scope ID")
        if type(self.scenario) is not OperationalDrillScenario:
            raise OperationalDrillError("operational-drill scenario is unsupported")
        if type(self.minimum_control_state) is not OperationalControlState:
            raise OperationalDrillError("operational-drill minimum control state is unsupported")
        if (
            type(self.response_deadline_microseconds) is not int
            or not 1
            <= self.response_deadline_microseconds
            <= MAX_OPERATIONAL_DRILL_DEADLINE_MICROSECONDS
        ):
            raise OperationalDrillError(
                "operational-drill response deadline exceeds its bounded range"
            )
        _require_sha256(
            self.fixture_spec_sha256,
            "operational-drill fixture_spec_sha256",
        )
        if (
            self.scenario is not OperationalDrillScenario.KILL_STATE
            and _STATE_SEVERITY[self.minimum_control_state]
            < _STATE_SEVERITY[OperationalControlState.PAUSED]
        ):
            raise OperationalDrillConflict(
                "non-kill operational drills must expect PAUSED or stronger control"
            )

    @property
    def case_id(self) -> str:
        return canonical_id(
            "local-operational-drill-case",
            self.campaign_id,
            self.scope_id,
            self.scenario,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                OPERATIONAL_DRILL_CONTRACT_VERSION,
                "case",
                self.case_id,
                self.campaign_id,
                self.scope_id,
                self.scenario,
                self.minimum_control_state,
                self.response_deadline_microseconds,
                self.fixture_spec_sha256,
                "local_fixture_only",
                "new_exposure_must_be_withheld",
                "automatic_rearm_forbidden",
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json.encode()).hexdigest()

    @property
    def broker_action_authorized(self) -> bool:
        return False

    @property
    def qualifies_phase5_exit_gate(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class LocalOperationalDrillObservation:
    """One exact local observation assessed against its immutable case."""

    case: LocalOperationalDrillCase
    started_at: datetime
    observed_at: datetime
    final_control_state: OperationalControlState
    new_exposure_authorized: bool
    automatic_rearm_observed: bool
    response_evidence_sha256: str | None
    unavailable_reason: str | None

    def __post_init__(self) -> None:
        if type(self.case) is not LocalOperationalDrillCase:
            raise OperationalDrillError("operational-drill observation requires an exact case")
        self.case.__post_init__()
        _require_utc(self.started_at, "operational-drill started_at")
        _require_utc(self.observed_at, "operational-drill observed_at")
        if self.observed_at < self.started_at:
            raise OperationalDrillConflict("operational-drill observation predates its start")
        if type(self.final_control_state) is not OperationalControlState:
            raise OperationalDrillError("operational-drill final control state is unsupported")
        if type(self.new_exposure_authorized) is not bool:
            raise OperationalDrillError("operational-drill exposure observation must be exact bool")
        if type(self.automatic_rearm_observed) is not bool:
            raise OperationalDrillError("operational-drill re-arm observation must be exact bool")
        if self.response_evidence_sha256 is not None:
            _require_sha256(
                self.response_evidence_sha256,
                "operational-drill response_evidence_sha256",
            )
        if self.unavailable_reason is not None:
            _require_text(
                self.unavailable_reason,
                "operational-drill unavailable reason",
            )
        if (self.response_evidence_sha256 is None) == (self.unavailable_reason is None):
            raise OperationalDrillError(
                "operational-drill observation requires exactly one response or unavailable reason"
            )

    @property
    def elapsed_microseconds(self) -> int:
        return _elapsed_microseconds(self.started_at, self.observed_at)

    @property
    def disposition(self) -> OperationalDrillDisposition:
        if self.response_evidence_sha256 is None:
            return OperationalDrillDisposition.UNAVAILABLE
        if (
            self.elapsed_microseconds <= self.case.response_deadline_microseconds
            and _STATE_SEVERITY[self.final_control_state]
            >= _STATE_SEVERITY[self.case.minimum_control_state]
            and not self.new_exposure_authorized
            and not self.automatic_rearm_observed
        ):
            return OperationalDrillDisposition.PASSED
        return OperationalDrillDisposition.FAILED

    @property
    def observation_id(self) -> str:
        return canonical_id(
            "local-operational-drill-observation",
            self.case.case_id,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                OPERATIONAL_DRILL_CONTRACT_VERSION,
                "observation",
                self.observation_id,
                self.case.semantic_sha256,
                self.started_at,
                self.observed_at,
                self.elapsed_microseconds,
                self.final_control_state,
                self.new_exposure_authorized,
                self.automatic_rearm_observed,
                self.response_evidence_sha256,
                self.unavailable_reason,
                self.disposition,
                "local_fixture_only",
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json.encode()).hexdigest()

    @property
    def broker_action_authorized(self) -> bool:
        return False

    @property
    def automatic_rearm_authorized(self) -> bool:
        return False

    @property
    def qualifies_phase5_exit_gate(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class LocalOperationalDrillMatrix:
    """Complete, exactly ordered local evidence for all six required drills."""

    campaign_id: str
    scope_id: str
    observations: tuple[LocalOperationalDrillObservation, ...]

    def __post_init__(self) -> None:
        _require_text(self.campaign_id, "operational-drill matrix campaign ID")
        _require_text(self.scope_id, "operational-drill matrix scope ID")
        if type(self.observations) is not tuple or any(
            type(value) is not LocalOperationalDrillObservation for value in self.observations
        ):
            raise OperationalDrillError(
                "operational-drill matrix observations must be an exact tuple"
            )
        observed_scenarios = tuple(observation.case.scenario for observation in self.observations)
        if observed_scenarios != REQUIRED_OPERATIONAL_DRILL_SCENARIOS:
            raise OperationalDrillConflict(
                "operational-drill matrix must contain the six required scenarios "
                "in canonical order"
            )
        for observation in self.observations:
            observation.__post_init__()
            if (
                observation.case.campaign_id != self.campaign_id
                or observation.case.scope_id != self.scope_id
            ):
                raise OperationalDrillConflict(
                    "operational-drill matrix crosses campaign or scope identities"
                )

    @property
    def matrix_id(self) -> str:
        return canonical_id(
            "local-operational-drill-matrix",
            self.campaign_id,
            self.scope_id,
        )

    @property
    def all_local_checks_passed(self) -> bool:
        return all(
            observation.disposition is OperationalDrillDisposition.PASSED
            for observation in self.observations
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                OPERATIONAL_DRILL_CONTRACT_VERSION,
                "matrix",
                self.matrix_id,
                self.campaign_id,
                self.scope_id,
                tuple(
                    (
                        observation.case.scenario,
                        observation.semantic_sha256,
                        observation.disposition,
                    )
                    for observation in self.observations
                ),
                self.all_local_checks_passed,
                "local_fixture_only",
                "deployed_authoritative_drills_still_required",
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json.encode()).hexdigest()

    @property
    def broker_action_authorized(self) -> bool:
        return False

    @property
    def qualifies_phase5_exit_gate(self) -> bool:
        return False


__all__ = [
    "MAX_OPERATIONAL_DRILL_DEADLINE_MICROSECONDS",
    "OPERATIONAL_DRILL_CONTRACT_VERSION",
    "REQUIRED_OPERATIONAL_DRILL_SCENARIOS",
    "LocalOperationalDrillCase",
    "LocalOperationalDrillMatrix",
    "LocalOperationalDrillObservation",
    "OperationalDrillConflict",
    "OperationalDrillDisposition",
    "OperationalDrillError",
    "OperationalDrillScenario",
]
