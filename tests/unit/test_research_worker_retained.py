"""Retained process/application seam with the real reducer and no database."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from apps.worker.research_runner import ResearchProcessRunner
from packages.application.research_worker_v2 import process_one_research_job
from packages.domain.research_job_contracts import ClaimedResearchJob
from packages.domain.research_job_v2 import (
    cancel_research_job,
    claim_research_job,
    finish_research_attempt,
    publish_research_attempt,
    queue_research_job,
    renew_research_claim,
)
from tests.unit.test_retained_research_runner import _execution


class _ReducerWorkflow:
    """Exercise production domain transitions without claiming SQL durability."""

    def __init__(self, request, now: datetime, publication_fault: str | None = None):
        self.state = queue_research_job(request, now)
        self.now = now
        self.publication_fault = publication_fault
        self.claims = 0
        self.heartbeats = []

    def claim_next(self, *, worker_id, worker_instance_id):
        self.claims += 1
        self.state = claim_research_job(
            self.state, worker_id=worker_id, worker_instance_id=worker_instance_id, now=self.now
        )
        return ClaimedResearchJob(self.state.request, self.state.claim)

    def heartbeat(self, claim, *, progress):
        self.heartbeats.append(progress.stage)
        self.state, control = renew_research_claim(
            self.state, claim, progress=progress, now=self.now
        )
        return control

    def publish(self, claim, *, publication):
        if self.publication_fault == "cancel":
            self.state = cancel_research_job(
                self.state,
                owner_id=self.state.request.owner_id,
                idempotency_key="cancel-final-boundary",
                now=self.now,
            )
        elif self.publication_fault == "expired":
            self.now += timedelta(seconds=60)
        self.state = publish_research_attempt(self.state, claim, publication, self.now)
        return self.state.view

    def finish(self, claim, *, outcome, reason_code):
        self.state = finish_research_attempt(
            self.state,
            claim,
            outcome=outcome,
            reason_code=reason_code,
            now=self.now,
        )
        return self.state.view

    def get(self, job_id):
        assert job_id == self.state.request.job_id
        return self.state.view


class _NoParentObjects:
    def read(self, *args, **kwargs):
        raise AssertionError("production orchestration read an input/report object")

    def put(self, *args, **kwargs):
        raise AssertionError("production orchestration materialized an object payload")


class _NoParentCodec:
    def encode_record(self, *args, **kwargs):
        raise AssertionError("production orchestration encoded a financial graph")

    def decode_record(self, *args, **kwargs):
        raise AssertionError("production orchestration decoded a financial graph")


@pytest.mark.parametrize("boundary", [None, "cancel", "expired"])
def test_actual_retained_process_reaches_current_fence_without_parent_graph_work(
    tmp_path: Path,
    boundary: str | None,
) -> None:
    root = tmp_path / "objects"
    execution = _execution(root)
    workflow = _ReducerWorkflow(execution.request, execution.claim.started_at, boundary)
    final = process_one_research_job(
        workflow,
        worker_id="worker",
        worker_instance_id="new-process",
        retained_runner=ResearchProcessRunner(artifact_root=root),
        artifacts=_NoParentObjects(),
        codec=_NoParentCodec(),
    )
    assert final is not None
    assert {None: "completed", "cancel": "cancelled", "expired": "running"}[
        boundary
    ] == final.status
    assert (final.publication is not None) == (boundary is None)
    assert workflow.claims == 1
    assert "loading" in workflow.heartbeats and "publishing" in workflow.heartbeats
    assert len(tuple(root.iterdir())) == 3  # bytes alone are not a terminal publication
    terminals = tuple(
        event for event in workflow.state.events if event.kind in ("completed", "incomplete")
    )
    assert len(terminals) == (1 if boundary is None else 0)


@pytest.mark.parametrize(
    "ports", ["none", "both", "resolver-with-retained", "runner-without-resolver"]
)
def test_execution_port_selection_is_explicit_before_claim(tmp_path: Path, ports: str) -> None:
    root = tmp_path / "objects"
    execution = _execution(root)
    workflow = _ReducerWorkflow(execution.request, execution.claim.started_at)
    arguments = {}
    if ports in ("both", "runner-without-resolver"):
        arguments["runner"] = object()
    if ports in ("both", "resolver-with-retained"):
        arguments["retained_runner"] = object()
    if ports == "resolver-with-retained":
        arguments["resolver"] = object()
    with pytest.raises(ValueError, match="explicit"):
        process_one_research_job(
            workflow,
            worker_id="worker",
            worker_instance_id="unit-process",
            artifacts=_NoParentObjects(),
            codec=_NoParentCodec(),
            **arguments,
        )
    assert workflow.claims == 0
