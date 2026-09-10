"""Pure fenced research-job transitions, independent of clocks and storage."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Literal

from packages.domain.personal_contracts import content_digest, require_utc
from packages.domain.research_job_contracts import (
    LEASE_SECONDS,
    MAX_ATTEMPTS,
    MAX_JOB_EVENTS,
    ClaimControl,
    EventKind,
    JobStatus,
    ResearchAttempt,
    ResearchClaim,
    ResearchJobEvent,
    ResearchJobView,
    ResearchProgress,
    ResearchPublication,
    ResearchRunRequest,
    require_identifier,
)


class ResearchJobConflict(ValueError):
    """Immutable identity or lifecycle evidence disagrees."""


class ResearchClaimLost(ResearchJobConflict):
    """The exact claim has expired or been superseded."""


@dataclass(frozen=True, slots=True)
class ResearchJobState:
    request: ResearchRunRequest
    events: tuple[ResearchJobEvent, ...]
    view: ResearchJobView
    claim: ResearchClaim | None


def require_claim(state: ResearchJobState, claim: ResearchClaim, now: datetime) -> None:
    require_utc(now, "database authority time")
    if state.claim != claim or state.view.status != "running" or now >= claim.lease_expires_at:
        raise ResearchClaimLost("current unexpired exact research claim required")
    if now < state.view.updated_at:
        raise ResearchClaimLost("database authority time regressed")


def reduce_research_job(
    request: ResearchRunRequest, events: tuple[ResearchJobEvent, ...]
) -> ResearchJobState:
    if (
        type(request) is not ResearchRunRequest
        or type(events) is not tuple
        or not 0 < len(events) <= MAX_JOB_EVENTS
    ):
        raise ResearchJobConflict("bounded immutable request/event chain required")
    first = events[0]
    if (
        first.kind != "queued"
        or first.actor_id != request.owner_id
        or any(
            value is not None
            for value in (
                first.claim,
                first.publication,
                first.reason_code,
                first.command_id,
                first.progress,
            )
        )
    ):
        raise ResearchJobConflict("job must start with its owner queued event")
    state = ResearchJobState(
        request,
        (),
        ResearchJobView(
            request.job_id,
            request.run_id,
            request.owner_id,
            request.trial_id,
            "queued",
            first.occurred_at,
            first.occurred_at,
            False,
            (),
            first.semantic_sha256,
        ),
        None,
    )
    for index, event in enumerate(events):
        if (
            type(event) is not ResearchJobEvent
            or event.job_id != request.job_id
            or event.sequence != index
            or event.previous_event_sha256
            != (None if index == 0 else events[index - 1].semantic_sha256)
        ):
            raise ResearchJobConflict("research event chain identity or predecessor differs")
        if event.occurred_at < state.view.updated_at:
            raise ResearchJobConflict("research event time regressed")
        if index:
            state = _apply(state, event)
        state = replace(
            state,
            events=events[: index + 1],
            view=replace(
                state.view, updated_at=event.occurred_at, last_event_sha256=event.semantic_sha256
            ),
        )
    return state


def _apply(state: ResearchJobState, event: ResearchJobEvent) -> ResearchJobState:
    view, claim = state.view, state.claim
    if view.status not in ("queued", "running"):
        raise ResearchJobConflict("terminal research job cannot transition")
    if event.kind != "renewed" and event.progress is not None:
        raise ResearchJobConflict("progress must be a claim observation")
    if event.kind not in ("completed", "incomplete") and event.publication is not None:
        raise ResearchJobConflict("only published terminals carry report evidence")
    if event.kind not in ("cancel_requested", "cancelled") and event.command_id is not None:
        raise ResearchJobConflict("command identity only belongs to owner cancellation")
    if (
        event.kind in ("claimed", "renewed", "cancel_requested", "completed", "incomplete")
        and event.reason_code is not None
    ):
        raise ResearchJobConflict("unexpected terminal reason")
    if event.kind == "claimed":
        new = event.claim
        number = len(view.attempts) + 1
        if (
            view.status != "queued"
            or view.cancel_requested
            or claim is not None
            or new is None
            or number > MAX_ATTEMPTS
        ):
            raise ResearchJobConflict("research job cannot be claimed")
        if (
            new.fence != number
            or new.lease_revision != 0
            or new.started_at != event.occurred_at
            or new.lease_expires_at != event.occurred_at + timedelta(seconds=LEASE_SECONDS)
            or event.actor_id != new.worker_id
        ):
            raise ResearchJobConflict("claim differs from its bounded attempt")
        attempt = ResearchAttempt(new.attempt_id, number, event.occurred_at, None, "running")
        return replace(
            state,
            claim=new,
            view=replace(
                view,
                status="running",
                attempts=(*view.attempts, attempt),
                reason_code=None,
                progress=None,
            ),
        )
    if event.kind == "renewed":
        if claim is None or event.claim is None:
            raise ResearchClaimLost("renewal lacks a claim")
        require_claim(state, claim, event.occurred_at)
        expected = replace(
            claim,
            lease_revision=claim.lease_revision + 1,
            lease_expires_at=event.occurred_at + timedelta(seconds=LEASE_SECONDS),
        )
        if event.claim != expected or event.actor_id != claim.worker_id or event.progress is None:
            raise ResearchJobConflict("renewal differs from current authority")
        return replace(state, claim=expected, view=replace(view, progress=event.progress))
    if event.kind == "cancel_requested":
        if (
            view.status != "running"
            or event.actor_id != state.request.owner_id
            or event.command_id is None
            or event.claim is not None
        ):
            raise ResearchJobConflict("running owner cancellation requires command evidence")
        return replace(state, view=replace(view, cancel_requested=True))
    if event.kind == "queued":
        raise ResearchJobConflict("queued is only the initial event")
    if event.kind == "cancelled" and view.status == "queued":
        if (
            event.actor_id != state.request.owner_id
            or event.command_id is None
            or event.claim is not None
            or event.reason_code != "owner_cancelled"
        ):
            raise ResearchJobConflict("queued cancellation requires its owner command")
        return replace(
            state,
            view=replace(
                view, status="cancelled", cancel_requested=True, reason_code=event.reason_code
            ),
        )
    if event.kind == "failed" and view.status == "queued":
        if (
            len(view.attempts) != MAX_ATTEMPTS
            or view.attempts[-1].outcome != "abandoned"
            or event.claim is not None
            or event.reason_code != "attempts_exhausted"
            or event.actor_id != "recovery"
        ):
            raise ResearchJobConflict("queued failure requires exhausted abandoned attempts")
        return replace(state, view=replace(view, status="failed", reason_code=event.reason_code))
    if claim is None or event.claim != claim:
        raise ResearchClaimLost("attempt closure requires its exact claim")
    recovery = event.actor_id == "recovery" and event.occurred_at >= claim.lease_expires_at
    if not recovery:
        require_claim(state, claim, event.occurred_at)
        if event.actor_id != claim.worker_id:
            raise ResearchClaimLost("only current worker may close its attempt")
    status: JobStatus
    if event.kind in ("completed", "incomplete"):
        if recovery or view.cancel_requested or event.publication is None:
            raise ResearchClaimLost("cancelled or expired attempt cannot publish")
        publication = event.publication
        if (
            publication.run_id != state.request.run_id
            or publication.attempt_id != claim.attempt_id
            or publication.outcome != event.kind
        ):
            raise ResearchJobConflict("publication differs from accepted execution identity")
        status = event.kind
    elif event.kind == "abandoned":
        if (
            view.cancel_requested
            or event.reason_code not in ("lease_expired", "worker_shutdown")
            or (recovery != (event.reason_code == "lease_expired"))
        ):
            raise ResearchJobConflict("abandonment must describe loss or graceful shutdown")
        status = "queued"
    elif event.kind == "cancelled":
        if (
            not view.cancel_requested
            or event.reason_code not in ("owner_cancelled", "lease_expired_cancelled")
            or recovery != (event.reason_code == "lease_expired_cancelled")
            or event.command_id is not None
        ):
            raise ResearchJobConflict("cancel closure requires prior durable owner intent")
        status = "cancelled"
    elif event.kind == "failed":
        if recovery or view.cancel_requested or event.reason_code is None:
            raise ResearchJobConflict("failure requires current uncancelled attempt")
        status = "failed"
    else:
        raise ResearchJobConflict("unsupported attempt closure")
    attempt = replace(
        view.attempts[-1],
        outcome=event.kind,
        ended_at=event.occurred_at,
        reason_code=event.reason_code,
    )
    return replace(
        state,
        claim=None,
        view=replace(
            view,
            status=status,
            attempts=(*view.attempts[:-1], attempt),
            reason_code=event.reason_code,
            publication=event.publication,
        ),
    )


def _append(
    state: ResearchJobState,
    *,
    kind: EventKind,
    now: datetime,
    actor: str,
    claim: ResearchClaim | None = None,
    publication: ResearchPublication | None = None,
    reason: str | None = None,
    command_id: str | None = None,
    progress: ResearchProgress | None = None,
) -> ResearchJobState:
    event = ResearchJobEvent(
        state.request.job_id,
        len(state.events),
        state.events[-1].semantic_sha256,
        kind,
        now,
        actor,
        claim,
        publication,
        reason,
        command_id,
        progress,
    )
    return reduce_research_job(state.request, (*state.events, event))


def queue_research_job(request: ResearchRunRequest, now: datetime) -> ResearchJobState:
    return reduce_research_job(
        request, (ResearchJobEvent(request.job_id, 0, None, "queued", now, request.owner_id),)
    )


def claim_research_job(
    state: ResearchJobState, *, worker_id: str, worker_instance_id: str, now: datetime
) -> ResearchJobState:
    number = len(state.view.attempts) + 1
    claim = ResearchClaim(
        state.request.job_id,
        content_digest(
            ("personal-research-job/2", "attempt", state.request.job_id, number, worker_instance_id)
        ),
        number,
        0,
        worker_id,
        worker_instance_id,
        now,
        now + timedelta(seconds=LEASE_SECONDS),
    )
    return _append(state, kind="claimed", now=now, actor=worker_id, claim=claim)


def renew_research_claim(
    state: ResearchJobState, claim: ResearchClaim, *, progress: ResearchProgress, now: datetime
) -> tuple[ResearchJobState, ClaimControl]:
    require_claim(state, claim, now)
    new = replace(
        claim,
        lease_revision=claim.lease_revision + 1,
        lease_expires_at=now + timedelta(seconds=LEASE_SECONDS),
    )
    updated = _append(
        state, kind="renewed", now=now, actor=claim.worker_id, claim=new, progress=progress
    )
    return updated, ClaimControl(new, now, updated.view.cancel_requested)


def cancel_research_job(
    state: ResearchJobState, *, owner_id: str, idempotency_key: str, now: datetime
) -> ResearchJobState:
    require_identifier(idempotency_key, "cancel idempotency key")
    if len(idempotency_key) < 8 or owner_id != state.request.owner_id:
        raise ResearchJobConflict("cancellation requires the owning principal and command key")
    command = content_digest(
        ("personal-research-job/2", "cancel", state.request.job_id, owner_id, idempotency_key)
    )
    if any(event.command_id == command for event in state.events) or state.view.status not in (
        "queued",
        "running",
    ):
        return state
    queued = state.view.status == "queued"
    return _append(
        state,
        kind="cancelled" if queued else "cancel_requested",
        now=now,
        actor=owner_id,
        command_id=command,
        reason="owner_cancelled" if queued else None,
    )


def finish_research_attempt(
    state: ResearchJobState,
    claim: ResearchClaim,
    *,
    outcome: Literal["failed", "cancelled", "abandoned"],
    reason_code: str,
    now: datetime,
) -> ResearchJobState:
    require_claim(state, claim, now)
    if state.view.cancel_requested:
        outcome, reason_code = "cancelled", "owner_cancelled"
    return _append(
        state, kind=outcome, now=now, actor=claim.worker_id, claim=claim, reason=reason_code
    )


def publish_research_attempt(
    state: ResearchJobState, claim: ResearchClaim, publication: ResearchPublication, now: datetime
) -> ResearchJobState:
    if state.view.publication == publication:
        if state.events[-1].claim != claim:
            raise ResearchClaimLost("publication retry differs from committed terminal claim")
        return state
    require_claim(state, claim, now)
    return _append(
        state,
        kind=publication.outcome,
        now=now,
        actor=claim.worker_id,
        claim=claim,
        publication=publication,
    )


def recover_research_job(state: ResearchJobState, now: datetime) -> ResearchJobState:
    if state.claim is not None:
        if now < state.claim.lease_expires_at:
            raise ResearchClaimLost("unexpired attempt cannot be recovered")
        state = _append(
            state,
            kind="cancelled" if state.view.cancel_requested else "abandoned",
            now=now,
            actor="recovery",
            claim=state.claim,
            reason="lease_expired_cancelled" if state.view.cancel_requested else "lease_expired",
        )
    if state.view.status == "queued" and len(state.view.attempts) == MAX_ATTEMPTS:
        state = _append(
            state, kind="failed", now=now, actor="recovery", reason="attempts_exhausted"
        )
    return state
