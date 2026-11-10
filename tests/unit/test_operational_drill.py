from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from packages.domain.operational_control import OperationalControlState
from packages.domain.operational_drill import (
    MAX_OPERATIONAL_DRILL_DEADLINE_MICROSECONDS,
    REQUIRED_OPERATIONAL_DRILL_SCENARIOS,
    LocalOperationalDrillCase,
    LocalOperationalDrillMatrix,
    LocalOperationalDrillObservation,
    OperationalDrillConflict,
    OperationalDrillDisposition,
    OperationalDrillError,
    OperationalDrillScenario,
)

STARTED_AT = datetime(2026, 7, 28, 20, 0, tzinfo=UTC)
FIXTURE_SHA256 = hashlib.sha256(b"fixture").hexdigest()
RESPONSE_SHA256 = hashlib.sha256(b"response").hexdigest()


def _case(
    scenario: OperationalDrillScenario,
    *,
    campaign_id: str = "campaign-001",
    scope_id: str = "paper-account-001",
    minimum_control_state: OperationalControlState | None = None,
    deadline_microseconds: int = 5_000_000,
) -> LocalOperationalDrillCase:
    if minimum_control_state is None:
        minimum_control_state = (
            OperationalControlState.RUNNING
            if scenario is OperationalDrillScenario.KILL_STATE
            else OperationalControlState.PAUSED
        )
    return LocalOperationalDrillCase(
        campaign_id=campaign_id,
        scope_id=scope_id,
        scenario=scenario,
        minimum_control_state=minimum_control_state,
        response_deadline_microseconds=deadline_microseconds,
        fixture_spec_sha256=FIXTURE_SHA256,
    )


def _observation(
    scenario: OperationalDrillScenario,
    *,
    case: LocalOperationalDrillCase | None = None,
    elapsed_microseconds: int = 5_000_000,
    final_control_state: OperationalControlState = OperationalControlState.PAUSED,
    new_exposure_authorized: bool = False,
    automatic_rearm_observed: bool = False,
    response_evidence_sha256: str | None = RESPONSE_SHA256,
    unavailable_reason: str | None = None,
) -> LocalOperationalDrillObservation:
    return LocalOperationalDrillObservation(
        case=_case(scenario) if case is None else case,
        started_at=STARTED_AT,
        observed_at=STARTED_AT + timedelta(microseconds=elapsed_microseconds),
        final_control_state=final_control_state,
        new_exposure_authorized=new_exposure_authorized,
        automatic_rearm_observed=automatic_rearm_observed,
        response_evidence_sha256=response_evidence_sha256,
        unavailable_reason=unavailable_reason,
    )


def _passing_matrix() -> LocalOperationalDrillMatrix:
    return LocalOperationalDrillMatrix(
        campaign_id="campaign-001",
        scope_id="paper-account-001",
        observations=tuple(
            _observation(
                scenario,
                final_control_state=(
                    OperationalControlState.RUNNING
                    if scenario is OperationalDrillScenario.KILL_STATE
                    else OperationalControlState.PAUSED
                ),
            )
            for scenario in REQUIRED_OPERATIONAL_DRILL_SCENARIOS
        ),
    )


def test_timing_equality_and_stronger_control_pass_without_authority() -> None:
    case = _case(
        OperationalDrillScenario.STRATEGY_FAILURE,
        minimum_control_state=OperationalControlState.PAUSED,
    )
    observation = _observation(
        OperationalDrillScenario.STRATEGY_FAILURE,
        case=case,
        elapsed_microseconds=case.response_deadline_microseconds,
        final_control_state=OperationalControlState.HALTED,
    )

    assert observation.disposition is OperationalDrillDisposition.PASSED
    assert observation.elapsed_microseconds == case.response_deadline_microseconds
    assert not observation.broker_action_authorized
    assert not observation.automatic_rearm_authorized
    assert not observation.qualifies_phase5_exit_gate


@pytest.mark.parametrize(
    ("overrides", "expected"),
    (
        (
            {"elapsed_microseconds": 5_000_001},
            OperationalDrillDisposition.FAILED,
        ),
        (
            {"final_control_state": OperationalControlState.RUNNING},
            OperationalDrillDisposition.FAILED,
        ),
        (
            {"new_exposure_authorized": True},
            OperationalDrillDisposition.FAILED,
        ),
        (
            {"automatic_rearm_observed": True},
            OperationalDrillDisposition.FAILED,
        ),
    ),
)
def test_failed_safety_or_timing_condition_is_explicit(
    overrides: dict[str, object],
    expected: OperationalDrillDisposition,
) -> None:
    observation = _observation(
        OperationalDrillScenario.DATA_GAP,
        **overrides,  # type: ignore[arg-type]
    )

    assert observation.disposition is expected


def test_missing_response_is_unavailable_not_failed() -> None:
    observation = _observation(
        OperationalDrillScenario.BROKER_DISCONNECT,
        response_evidence_sha256=None,
        unavailable_reason="response_evidence_unavailable",
    )

    assert observation.disposition is OperationalDrillDisposition.UNAVAILABLE


def test_observation_requires_exactly_one_response_or_unavailable_reason() -> None:
    with pytest.raises(OperationalDrillError, match="exactly one"):
        _observation(
            OperationalDrillScenario.RISK_TRIP,
            response_evidence_sha256=None,
            unavailable_reason=None,
        )
    with pytest.raises(OperationalDrillError, match="exactly one"):
        _observation(
            OperationalDrillScenario.RISK_TRIP,
            response_evidence_sha256=RESPONSE_SHA256,
            unavailable_reason="conflicting_reason",
        )


def test_non_kill_scenario_cannot_expect_running_control() -> None:
    with pytest.raises(OperationalDrillConflict, match="PAUSED or stronger"):
        _case(
            OperationalDrillScenario.ALERT_TOTAL_DELIVERY_FAILURE,
            minimum_control_state=OperationalControlState.RUNNING,
        )


def test_case_rejects_bool_or_out_of_range_deadlines() -> None:
    for value in (True, 0, MAX_OPERATIONAL_DRILL_DEADLINE_MICROSECONDS + 1):
        with pytest.raises(OperationalDrillError, match="deadline"):
            _case(
                OperationalDrillScenario.KILL_STATE,
                deadline_microseconds=value,  # type: ignore[arg-type]
            )


def test_observation_rejects_time_rollback_and_non_bool_safety_facts() -> None:
    with pytest.raises(OperationalDrillConflict, match="predates"):
        _observation(
            OperationalDrillScenario.KILL_STATE,
            elapsed_microseconds=-1,
            final_control_state=OperationalControlState.RUNNING,
        )
    with pytest.raises(OperationalDrillError, match="exact bool"):
        _observation(
            OperationalDrillScenario.KILL_STATE,
            final_control_state=OperationalControlState.RUNNING,
            new_exposure_authorized=0,  # type: ignore[arg-type]
        )


def test_complete_canonical_matrix_reports_only_local_success() -> None:
    matrix = _passing_matrix()

    assert matrix.all_local_checks_passed
    assert len(matrix.observations) == 6
    assert len(matrix.semantic_sha256) == 64
    assert not matrix.broker_action_authorized
    assert not matrix.qualifies_phase5_exit_gate


def test_matrix_rejects_missing_reordered_or_duplicate_scenarios() -> None:
    observations = _passing_matrix().observations
    for invalid in (
        observations[:-1],
        (observations[1], observations[0], *observations[2:]),
        (observations[0], observations[0], *observations[2:]),
    ):
        with pytest.raises(OperationalDrillConflict, match="six required scenarios"):
            LocalOperationalDrillMatrix(
                campaign_id="campaign-001",
                scope_id="paper-account-001",
                observations=invalid,
            )


def test_matrix_rejects_cross_campaign_or_scope_observation() -> None:
    observations = list(_passing_matrix().observations)
    observations[-1] = _observation(
        OperationalDrillScenario.RISK_TRIP,
        case=_case(
            OperationalDrillScenario.RISK_TRIP,
            campaign_id="campaign-002",
        ),
    )

    with pytest.raises(OperationalDrillConflict, match="campaign or scope"):
        LocalOperationalDrillMatrix(
            campaign_id="campaign-001",
            scope_id="paper-account-001",
            observations=tuple(observations),
        )


def test_canonical_identity_is_stable_and_semantic_changes_are_visible() -> None:
    left = _passing_matrix()
    right = _passing_matrix()
    changed = LocalOperationalDrillMatrix(
        campaign_id=left.campaign_id,
        scope_id=left.scope_id,
        observations=(
            *left.observations[:-1],
            _observation(
                OperationalDrillScenario.RISK_TRIP,
                automatic_rearm_observed=True,
            ),
        ),
    )

    assert left == right
    assert left.semantic_sha256 == right.semantic_sha256
    assert left.matrix_id == changed.matrix_id
    assert left.semantic_sha256 != changed.semantic_sha256
    assert not changed.all_local_checks_passed
