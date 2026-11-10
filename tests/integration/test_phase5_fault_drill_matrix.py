from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = REPOSITORY_ROOT / "tests/fixtures/phase5_fault_drills.json"
ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
REQUIRED_COVERAGE = frozenset(
    {
        "strategy.claim_before_effect",
        "strategy.no_rerun",
        "strategy.finalize_before_commit",
        "strategy.finalize_after_commit",
        "strategy.atomic_finalization",
        "strategy.current_fence_recovery",
        "strategy.start_authorization_freshness",
        "strategy.prestart_running",
        "strategy.claim_time_under_lock",
        "strategy.concurrent_claim_convergence",
        "strategy.start_permit_repository_bound",
        "strategy.start_permit_pid_bound",
        "strategy.start_permit_one_shot",
        "strategy.final_authorization_one_shot",
        "strategy.due_scan_bounded",
        "strategy.due_scan_no_runner",
        "strategy.legacy_writer_lockout",
        "alert.primary_success",
        "alert.primary_failure",
        "alert.fallback_at_15s",
        "alert.unresolved_no_resend",
        "alert.terminal_failure_first_replay",
        "alert.unresolved_failure_at_30s",
        "alert.atomic_paused_receipt",
        "alert.legacy_split_control_disabled",
        "risk.strict_equality",
        "risk.pretrade_reject",
        "risk.runtime_trip",
        "risk.atomic_rollback",
        "data.gap_fail_closed",
        "data.unavailable_fail_closed",
        "exposure.pending_cancel_retained",
        "exposure.unknown_retained",
        "infrastructure.database_loss",
        "infrastructure.lease_loss",
        "control.no_automatic_rearm",
    }
)
LOCAL_DRILL_FIELDS = frozenset({"id", "summary", "fault", "expected", "coverage", "evidence"})
DEPLOYMENT_DRILL_FIELDS = frozenset({"id", "status", "reason", "requires"})


def _load_matrix() -> dict[str, object]:
    value = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


MATRIX = _load_matrix()
LOCAL_DRILLS = MATRIX["local_drills"]
DEPLOYMENT_DRILLS = MATRIX["deployment_drills"]
assert isinstance(LOCAL_DRILLS, list)
assert isinstance(DEPLOYMENT_DRILLS, list)


def _drill_id(value: object) -> str:
    assert isinstance(value, dict)
    identifier = value.get("id")
    assert isinstance(identifier, str)
    return identifier


def test_phase5_fault_drill_matrix_has_a_closed_local_contract() -> None:
    assert set(MATRIX) == {"version", "scope", "local_drills", "deployment_drills"}
    assert MATRIX["version"] == 1
    assert MATRIX["scope"] == "local_deterministic_contract_evidence"
    assert LOCAL_DRILLS
    assert DEPLOYMENT_DRILLS

    local_ids = [_drill_id(drill) for drill in LOCAL_DRILLS]
    deployment_ids = [_drill_id(drill) for drill in DEPLOYMENT_DRILLS]
    assert len(local_ids) == len(set(local_ids))
    assert len(deployment_ids) == len(set(deployment_ids))
    assert set(local_ids).isdisjoint(deployment_ids)
    assert all(ID_PATTERN.fullmatch(identifier) for identifier in (*local_ids, *deployment_ids))


@pytest.mark.parametrize("drill", LOCAL_DRILLS, ids=_drill_id)
def test_local_fault_drill_references_exact_test_contracts(
    drill: object,
) -> None:
    assert isinstance(drill, dict)
    assert set(drill) == LOCAL_DRILL_FIELDS
    for field in ("summary", "fault", "expected"):
        value = drill[field]
        assert isinstance(value, str)
        assert value.strip() == value
        assert 1 <= len(value) <= 500

    coverage = drill["coverage"]
    evidence = drill["evidence"]
    assert isinstance(coverage, list)
    assert isinstance(evidence, list)
    assert coverage and len(coverage) == len(set(coverage))
    assert evidence and len(evidence) == len(set(evidence))
    assert all(isinstance(tag, str) and "." in tag for tag in coverage)

    for node_id in evidence:
        assert isinstance(node_id, str)
        assert node_id.count("::") == 1
        relative_path, function_name = node_id.split("::")
        assert relative_path.startswith("tests/")
        assert relative_path.endswith(".py")
        assert function_name.startswith("test_")
        test_path = (REPOSITORY_ROOT / relative_path).resolve()
        assert test_path.is_relative_to(REPOSITORY_ROOT / "tests")
        assert test_path.is_file()
        module = ast.parse(test_path.read_text(encoding="utf-8"), filename=str(test_path))
        top_level_tests = {
            node.name
            for node in module.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        assert function_name in top_level_tests, f"stale evidence node ID: {node_id}"


def test_local_fault_drills_cover_every_required_phase5_failure_contract() -> None:
    coverage = {
        tag for drill in LOCAL_DRILLS if isinstance(drill, dict) for tag in drill["coverage"]
    }
    assert coverage == REQUIRED_COVERAGE


@pytest.mark.parametrize("drill", DEPLOYMENT_DRILLS, ids=_drill_id)
def test_deployment_drills_are_explicitly_not_claimed_by_local_evidence(
    drill: object,
) -> None:
    assert isinstance(drill, dict)
    assert set(drill) == DEPLOYMENT_DRILL_FIELDS
    assert drill["status"] == "not_run"
    assert isinstance(drill["reason"], str) and drill["reason"]
    requires = drill["requires"]
    assert isinstance(requires, list)
    assert requires
    assert all(isinstance(requirement, str) and requirement for requirement in requires)
    assert "evidence" not in drill
