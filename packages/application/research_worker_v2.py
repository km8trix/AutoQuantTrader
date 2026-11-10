"""One durable job around the injected W2 process, without alternate economics."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from typing import Literal

from packages.domain.report_contracts import ReportArtifact
from packages.domain.research_job_contracts import (
    HEARTBEAT_SECONDS,
    MAX_INPUT_BYTES,
    MAX_OBJECT_BYTES,
    ResearchArtifactStore,
    ResearchExecutionRequest,
    ResearchInputResolver,
    ResearchJobView,
    ResearchProgress,
    ResearchPublication,
    ResearchRecordCodec,
    ResearchRunnerPort,
    ResearchWorkflowPort,
    RetainedResearchExecutionRequest,
    RetainedResearchRunnerPort,
    RunControl,
)
from packages.domain.research_job_v2 import ResearchClaimLost, ResearchJobConflict


def process_one_research_job(
    workflow: ResearchWorkflowPort,
    *,
    worker_id: str,
    worker_instance_id: str,
    resolver: ResearchInputResolver | None = None,
    runner: ResearchRunnerPort | None = None,
    retained_runner: RetainedResearchRunnerPort | None = None,
    artifacts: ResearchArtifactStore,
    codec: ResearchRecordCodec,
    stop_requested: Callable[[], bool] | None = None,
) -> ResearchJobView | None:
    """Require the caller to hold the W2 process guard before claiming work."""
    if (
        (retained_runner is None) == (runner is None)
        or (retained_runner is None and resolver is None)
        or (retained_runner is not None and resolver is not None)
    ):
        raise ValueError("select one explicit retained or resolved execution path")
    if stop_requested is not None and stop_requested():
        return None
    selected = workflow.claim_next(worker_id=worker_id, worker_instance_id=worker_instance_id)
    if selected is None:
        return None
    request, claim = selected.request, selected.claim
    stopped: RunControl | None = None
    last_heartbeat: float | None = None
    last_stage: str | None = None

    def control(progress: ResearchProgress) -> RunControl:
        nonlocal claim, stopped, last_heartbeat, last_stage
        if stopped is not None:
            return stopped
        if stop_requested is not None and stop_requested():
            stopped = RunControl(True, "shutdown")
            return stopped
        observed_at = time.monotonic()
        if (
            last_heartbeat is not None
            and observed_at - last_heartbeat < HEARTBEAT_SECONDS
            and last_stage == progress.stage
        ):
            return RunControl()
        try:
            observed = workflow.heartbeat(claim, progress=progress)
            claim = observed.claim
            last_heartbeat, last_stage = observed_at, progress.stage
        except Exception:
            stopped = RunControl(True, "lease_lost")
            return stopped
        if observed.cancel_requested:
            stopped = RunControl(True, "cancel_requested")
        elif stop_requested is not None and stop_requested():
            stopped = RunControl(True, "shutdown")
        return stopped or RunControl()

    def finish(
        outcome: Literal["failed", "cancelled", "abandoned"], reason: str
    ) -> ResearchJobView:
        if stopped is not None:
            if stopped.reason_code == "lease_lost":
                return workflow.get(request.job_id)
            if stopped.reason_code == "cancel_requested":
                outcome, reason = "cancelled", "owner_cancelled"
            elif stopped.reason_code == "shutdown":
                outcome, reason = "abandoned", "worker_shutdown"
        try:
            return workflow.finish(claim, outcome=outcome, reason_code=reason)
        except ResearchClaimLost:
            return workflow.get(request.job_id)

    try:
        if control(ResearchProgress("loading")).stop:
            return finish("abandoned", "worker_shutdown")
        if retained_runner is not None:
            # The production child resolves, computes and validates; its parent transfers bytes.
            # the claim owner never reconstructs the input or report object graph.
            outcome = retained_runner.run_retained(
                RetainedResearchExecutionRequest(request, claim), control=control
            )
        else:
            # Explicit controlled in-process port, retained for application tests.
            assert resolver is not None and runner is not None
            input_payload = artifacts.read(request.inputs, max_bytes=MAX_INPUT_BYTES)
            inputs = resolver.resolve(request)
            if inputs.spec != request.spec or codec.encode_record(inputs) != input_payload:
                raise ResearchJobConflict("resolved inputs differ from accepted immutable request")
            execution = ResearchExecutionRequest(request, claim, inputs)
            outcome = runner.run(execution, control=control)
        if control(ResearchProgress("validating")).stop:
            return finish("abandoned", "worker_shutdown")
        if outcome.publication is not None:
            publication = outcome.publication
            if retained_runner is None or (
                publication.job_id != request.job_id
                or publication.run_id != request.run_id
                or publication.attempt_id != claim.attempt_id
                or publication.object.byte_count > request.spec.max_output_bytes
            ):
                raise ResearchJobConflict("publication differs from the accepted run and attempt")
            if control(ResearchProgress("publishing")).stop:
                return finish("abandoned", "worker_shutdown")
            # Publish checks the current fence, lease and cancellation atomically.
            return workflow.publish(claim, publication=publication)
        if retained_runner is not None and outcome.artifact is not None:
            raise ResearchJobConflict("retained runner must return only a bounded publication")
        if outcome.artifact is None:
            assert outcome.outcome in ("failed", "cancelled", "abandoned")
            assert outcome.reason_code is not None
            if outcome.outcome == "abandoned" and outcome.reason_code == "shutdown":
                return finish("abandoned", "worker_shutdown")
            return finish(outcome.outcome, outcome.reason_code)
        artifact = outcome.artifact
        report = artifact.report
        if (
            artifact.attempt_id != claim.attempt_id
            or report.run_id != request.run_id
            or report.source.spec != request.spec
            or report.conventions != request.conventions
            or report.result_sha256 != report.source.semantic_sha256
        ):
            raise ResearchJobConflict("report differs from the accepted run and attempt")
        if report.status == "completed" and report.source.status != "completed":
            raise ResearchJobConflict("completed report lacks a completed engine outcome")
        payload = codec.encode_record(artifact)
        if len(payload) > min(MAX_OBJECT_BYTES, request.spec.max_output_bytes):
            raise ResearchJobConflict("report artifact exceeds the accepted output budget")
        if codec.decode_record(payload, ReportArtifact) != artifact:
            raise ResearchJobConflict("report codec round-trip differs")
        if control(ResearchProgress("publishing")).stop:
            return finish("abandoned", "worker_shutdown")
        reference = artifacts.put(
            payload, max_bytes=min(MAX_OBJECT_BYTES, request.spec.max_output_bytes)
        )
        if reference.object_sha256 != hashlib.sha256(
            payload
        ).hexdigest() or reference.byte_count != len(payload):
            raise ResearchJobConflict("artifact store returned a different byte identity")
        if control(ResearchProgress("publishing")).stop:
            return finish("abandoned", "worker_shutdown")
        publication = ResearchPublication(
            request.job_id,
            request.run_id,
            claim.attempt_id,
            report.status,
            report.source.semantic_sha256,
            report.semantic_sha256,
            artifact.semantic_sha256,
            reference,
        )
        return workflow.publish(claim, publication=publication)
    except ResearchClaimLost:
        return finish("failed", "research_execution_failed")
    except Exception:
        # Exception classes/text/payloads are deliberately excluded from durable public reasons.
        return finish("failed", "research_execution_failed")
