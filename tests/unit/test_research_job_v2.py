from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from functools import lru_cache

import pytest

from packages.application.personal_codec import encode_record
from packages.application.personal_inputs import synthetic_engine_inputs
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.engine_contracts import EngineInputs
from packages.domain.personal_contracts import VersionPin
from packages.domain.report_contracts import ReportConventions
from packages.domain.research_job_contracts import (
    MAX_INPUT_BYTES,
    MAX_OBJECT_BYTES,
    ObjectRef,
    ResearchProgress,
    ResearchPublication,
    ResearchRunRequest,
)
from packages.domain.research_job_v2 import (
    ResearchClaimLost,
    ResearchJobConflict,
    ResearchJobState,
    cancel_research_job,
    claim_research_job,
    finish_research_attempt,
    publish_research_attempt,
    queue_research_job,
    recover_research_job,
    reduce_research_job,
    renew_research_claim,
)

NOW = datetime(2026, 9, 10, 12, tzinfo=UTC)


@lru_cache
def sample_inputs() -> EngineInputs:
    pins = tuple(
        VersionPin(name, "personal-report/2" if name == "report" else "test-fixture/1", "a" * 64)
        for name in sorted(
            (
                "engine",
                "source",
                "dependency_lock",
                "tzdata",
                "availability",
                "actions",
                "numeric",
                "benchmark",
                "report",
                "dirty_patch",
            )
        )
    )
    inputs = synthetic_engine_inputs(
        fixture="flat",
        pins=pins,
        configuration=ReferenceConfiguration(lookback=3),
        session_count=8,
        warmup_count=3,
    )
    return replace(
        inputs, spec=replace(inputs.spec, max_output_bytes=MAX_OBJECT_BYTES, max_cpu_cores=1)
    )


def sample_request(key: str = "request-0001") -> ResearchRunRequest:
    inputs = sample_inputs()
    payload = encode_record(inputs)
    return ResearchRunRequest(
        inputs.spec,
        ReportConventions(),
        ObjectRef(hashlib.sha256(payload).hexdigest(), len(payload)),
        "owner",
        key,
        "trial-001",
    )


def claimed() -> ResearchJobState:
    return claim_research_job(
        queue_research_job(sample_request(), NOW),
        worker_id="worker",
        worker_instance_id="process-one",
        now=NOW,
    )


def publication(state: ResearchJobState) -> ResearchPublication:
    assert state.claim is not None
    return ResearchPublication(
        state.request.job_id,
        state.request.run_id,
        state.claim.attempt_id,
        "completed",
        "a" * 64,
        "b" * 64,
        "c" * 64,
        ObjectRef("d" * 64, 10),
    )


def test_request_identity_binds_every_selection_but_not_accepted_time() -> None:
    request = sample_request()
    assert request.job_id == replace(request, trial_id="trial-other").job_id
    assert request.semantic_sha256 != replace(request, trial_id="trial-other").semantic_sha256
    assert request.run_id == sample_request("request-other").run_id
    assert request.job_id != sample_request("request-other").job_id
    assert queue_research_job(request, NOW).view.requested_at == NOW
    invalid_requests: tuple[Callable[[], ResearchRunRequest], ...] = (
        lambda: replace(request, owner_id="/private/path"),
        lambda: replace(request, idempotency_key="/private/path"),
        lambda: replace(request, trial_id="/private/path"),
    )
    for invalid in invalid_requests:
        with pytest.raises(ValueError):
            invalid()


def test_object_and_request_byte_codec_and_resource_admission() -> None:
    with pytest.raises(ValueError):
        ObjectRef("a" * 64, MAX_OBJECT_BYTES + 1)
    with pytest.raises(ValueError):
        replace(sample_request(), inputs=ObjectRef("a" * 64, MAX_INPUT_BYTES + 1))
    with pytest.raises(ValueError):
        replace(sample_request(), inputs=ObjectRef("a" * 64, 20, "personal-research-dataset-v1"))
    with pytest.raises(ValueError):
        replace(
            sample_request(),
            spec=replace(sample_inputs().spec, max_output_bytes=MAX_OBJECT_BYTES + 1),
        )
    assert publication(claimed()).run_id.startswith("run-")


def test_half_open_expiry_and_rotating_exact_claim_fence() -> None:
    state = claimed()
    assert state.claim is not None
    original = state.claim
    renewed, control = renew_research_claim(
        state, original, progress=ResearchProgress("running", 4, 2), now=NOW + timedelta(seconds=10)
    )
    assert control.claim.lease_revision == 1
    assert renewed.view.progress == ResearchProgress("running", 4, 2)
    with pytest.raises(ResearchClaimLost):
        publish_research_attempt(renewed, original, publication(state), NOW + timedelta(seconds=11))
    with pytest.raises(ResearchClaimLost):
        renew_research_claim(
            renewed, control.claim, progress=ResearchProgress(), now=control.claim.lease_expires_at
        )
    recovered = recover_research_job(renewed, control.claim.lease_expires_at)
    assert recovered.view.attempts[0].outcome == "abandoned"
    next_attempt = claim_research_job(
        recovered,
        worker_id="worker",
        worker_instance_id="process-two",
        now=control.claim.lease_expires_at,
    )
    assert next_attempt.claim is not None and next_attempt.claim.fence == 2
    with pytest.raises(ResearchClaimLost):
        publish_research_attempt(
            next_attempt, control.claim, publication(state), control.claim.lease_expires_at
        )


def test_three_abandoned_attempts_exhaust_recovery_without_fabricating_execution() -> None:
    state = claimed()
    for number in range(1, 4):
        assert state.claim is not None
        now = state.claim.lease_expires_at
        state = recover_research_job(state, now)
        if number < 3:
            state = claim_research_job(
                state, worker_id="worker", worker_instance_id=f"process-{number}", now=now
            )
    assert state.view.status == "failed" and state.view.reason_code == "attempts_exhausted"
    assert tuple(attempt.outcome for attempt in state.view.attempts) == ("abandoned",) * 3
    assert state.view.publication is None


def test_cancellation_retains_owner_intent_and_wins_before_publication() -> None:
    queued = queue_research_job(sample_request(), NOW)
    cancelled = cancel_research_job(
        queued, owner_id="owner", idempotency_key="cancel-0001", now=NOW
    )
    assert cancelled.view.status == "cancelled" and cancelled.view.attempts == ()
    state = claimed()
    assert state.claim is not None
    pending = cancel_research_job(state, owner_id="owner", idempotency_key="cancel-0002", now=NOW)
    assert pending.view.status == "running" and pending.view.cancel_requested
    renewed, control = renew_research_claim(
        pending, state.claim, progress=ResearchProgress("stopping"), now=NOW + timedelta(seconds=1)
    )
    assert control.cancel_requested
    with pytest.raises(ResearchClaimLost):
        publish_research_attempt(
            renewed, control.claim, publication(renewed), NOW + timedelta(seconds=2)
        )
    recovered = recover_research_job(renewed, control.claim.lease_expires_at)
    assert recovered.view.status == "cancelled" and len(recovered.view.attempts) == 1


def test_publication_lost_ack_is_idempotent_and_conflicting_terminal_rejects() -> None:
    state = claimed()
    assert state.claim is not None
    result = publication(state)
    completed = publish_research_attempt(state, state.claim, result, NOW)
    assert (
        publish_research_attempt(completed, state.claim, result, NOW + timedelta(days=1))
        == completed
    )
    assert (
        cancel_research_job(completed, owner_id="owner", idempotency_key="late-cancel", now=NOW)
        == completed
    )
    with pytest.raises(ResearchClaimLost):
        publish_research_attempt(
            completed, state.claim, replace(result, report_sha256="e" * 64), NOW
        )


def test_graceful_shutdown_preserves_recoverable_attempt_and_history_rejects_tampering() -> None:
    state = claimed()
    assert state.claim is not None
    stopped = finish_research_attempt(
        state, state.claim, outcome="abandoned", reason_code="worker_shutdown", now=NOW
    )
    assert stopped.view.status == "queued" and stopped.view.attempts[0].outcome == "abandoned"
    with pytest.raises(ResearchJobConflict):
        reduce_research_job(
            state.request,
            (state.events[0], replace(state.events[1], previous_event_sha256="f" * 64)),
        )
    with pytest.raises(ResearchJobConflict):
        reduce_research_job(
            state.request,
            (state.events[0], replace(state.events[1], occurred_at=NOW - timedelta(seconds=1))),
        )
    with pytest.raises(ResearchJobConflict):
        cancel_research_job(state, owner_id="another-owner", idempotency_key="cancel-0003", now=NOW)
