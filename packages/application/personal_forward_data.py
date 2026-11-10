"""Pure capture admission and immutable closure; no network or execution permit."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta

from packages.domain.forward_contracts import (
    CaptureReceipt,
    ForwardDataState,
    ForwardDataTransition,
    ForwardFrontier,
    ForwardObservation,
    ForwardQuote,
    ForwardRequirement,
    ForwardSource,
    ModeledAvailability,
    QuoteAdmission,
    SourceEnvironment,
)
from packages.domain.personal_contracts import content_digest, require_text, require_utc


def _slot(observation: ForwardObservation) -> ForwardRequirement:
    p = observation.payload
    return ForwardRequirement(
        observation.source_id, p.instrument_id, p.symbol, p.session, observation.kind
    )


def _source(state: ForwardDataState, source_id: str) -> ForwardSource | None:
    return next((s for s in state.sources if s.source_id == source_id), None)


def _source_reasons(source: ForwardSource) -> tuple[str, ...]:
    if source.provider == "fixture":
        return ()
    reasons = []
    if source.identity_reference is None:
        reasons.append("SOURCE_IDENTITY_UNKNOWN")
    if source.rights_status != "allowed" or source.rights_reference is None:
        reasons.append("SOURCE_RIGHTS_UNAVAILABLE")
    return tuple(reasons)


def _edge_valid(parent: ForwardObservation, child: ForwardObservation) -> bool:
    return (
        parent.source_id == child.source_id
        and parent.revision_key == child.revision_key
        and parent.revision + 1 == child.revision
        and _slot(parent) == _slot(child)
        and (
            child.source_sequence is None
            or parent.source_sequence is None
            or parent.source_sequence < child.source_sequence
        )
    )


def _gaps(state: ForwardDataState, observation: ForwardObservation) -> tuple[str, ...]:
    source = _source(state, observation.source_id)
    if source is None:
        return ("SOURCE_NOT_PINNED",)
    reasons = list(_source_reasons(source))
    by_id = {o.observation_id: o for o in state.observations}
    current = observation
    while current.predecessor_id is not None:
        parent = by_id.get(current.predecessor_id)
        if parent is None:
            reasons.append("REVISION_GAP")
            break
        if not _edge_valid(parent, current):
            reasons.append("REVISION_CHAIN_CONFLICT")
            break
        current = parent
    if source.sequence_start is not None:
        if observation.source_sequence is None:
            reasons.append("SOURCE_SEQUENCE_UNAVAILABLE")
        else:
            sequences = sorted(
                {
                    o.source_sequence
                    for o in state.observations
                    if o.source_id == source.source_id
                    and o.source_sequence is not None
                    and o.source_sequence <= observation.source_sequence
                }
            )
            if any(value != source.sequence_start + i for i, value in enumerate(sequences)):
                reasons.append("SOURCE_SEQUENCE_GAP")
    return tuple(sorted(set(reasons)))


def admit_observation(
    state: ForwardDataState, observation: ForwardObservation, *, admitted_at: datetime
) -> ForwardDataTransition:
    """Retain valid evidence even when its lineage/qualification remains pending."""
    require_utc(admitted_at, "admission time")
    state.__post_init__()
    observation.__post_init__()
    old = next(
        (o for o in state.observations if o.observation_id == observation.observation_id), None
    )
    if old is not None:
        return ForwardDataTransition(
            state,
            "duplicate" if old == observation else "rejected",
            () if old == observation else ("OBSERVATION_ID_CONFLICT",),
        )
    reasons = []
    source = _source(state, observation.source_id)
    if source is None:
        reasons.append("SOURCE_NOT_PINNED")
    if observation.known_at > admitted_at:
        reasons.append("OBSERVATION_NOT_YET_AVAILABLE")
    availability = observation.availability
    if state.mode == "recorded":
        if not isinstance(availability, CaptureReceipt):
            reasons.append("MODELED_RECEIPT_IN_RECORDED_SOURCE")
        elif source is not None and availability.source_sha256 != source.semantic_sha256:
            reasons.append("CAPTURE_SOURCE_BINDING_MISMATCH")
    elif not isinstance(availability, ModeledAvailability):
        reasons.append("RECORDED_RECEIPT_IN_MODELED_SOURCE")
    if source is not None:
        if source.sequence_scope is None and observation.source_sequence is not None:
            reasons.append("SOURCE_SEQUENCE_SCOPE_UNQUALIFIED")
        if (
            source.sequence_start is not None
            and observation.source_sequence is not None
            and observation.source_sequence < source.sequence_start
        ):
            reasons.append("SOURCE_SEQUENCE_PRECEDES_START")
    for prior in state.observations:
        if prior.source_id == observation.source_id:
            if (
                prior.revision_key == observation.revision_key
                and prior.revision == observation.revision
            ):
                reasons.append("REVISION_FORK")
            if (
                observation.source_sequence is not None
                and prior.source_sequence == observation.source_sequence
            ):
                reasons.append("SOURCE_SEQUENCE_CONFLICT")
        if observation.predecessor_id == prior.observation_id and not _edge_valid(
            prior, observation
        ):
            reasons.append("REVISION_CHAIN_CONFLICT")
        if prior.predecessor_id == observation.observation_id and not _edge_valid(
            observation, prior
        ):
            reasons.append("REVISION_CHAIN_CONFLICT")
        if (
            isinstance(availability, CaptureReceipt)
            and isinstance(prior.availability, CaptureReceipt)
            and availability.capture_id == prior.availability.capture_id
            and availability != prior.availability
        ):
            reasons.append("CAPTURE_ID_CONFLICT")
    if len(state.observations) >= 100000:
        reasons.append("OBSERVATION_BOUND_EXCEEDED")
    if reasons:
        return ForwardDataTransition(state, "rejected", tuple(sorted(set(reasons))))
    updated = replace(
        state,
        observations=tuple(
            sorted((*state.observations, observation), key=lambda o: o.observation_id)
        ),
    )
    gaps = _gaps(updated, observation)
    return ForwardDataTransition(updated, "pending" if gaps else "accepted", gaps)


def quote_admission(
    observation: ForwardObservation,
    source: ForwardSource,
    *,
    expected: ForwardRequirement,
    environment: SourceEnvironment,
    account_scope: str,
    evaluated_at: datetime,
    boot_id: str,
    evaluated_monotonic_ns: int,
) -> QuoteAdmission:
    """Quote field/freshness checks only; verified source and coverage ports remain required."""
    require_utc(evaluated_at, "quote check time")
    require_text(account_scope, "expected account scope")
    require_text(boot_id, "current boot")
    if type(evaluated_monotonic_ns) is not int or not 0 <= evaluated_monotonic_ns < 2**63:
        raise ValueError("quote check monotonic time is invalid")
    reasons = list(_source_reasons(source))
    if (
        source.environment != environment
        or source.account_scope != account_scope
        or source.source_id != observation.source_id
        or _slot(observation) != expected
    ):
        reasons.append("QUOTE_SCOPE_MISMATCH")
    if source.provider == "fixture" or source.environment != "production":
        reasons.append("QUOTE_NOT_PRODUCTION_OBSERVATION")
    if source.entitlement_status != "realtime" or source.entitlement_reference is None:
        reasons.append("QUOTE_ENTITLEMENT_UNAVAILABLE")
    quote = observation.payload
    if not isinstance(quote, ForwardQuote):
        reasons.append("QUOTE_PAYLOAD_REQUIRED")
    else:
        if quote.bid is None or quote.ask is None:
            reasons.append("QUOTE_PRICE_UNAVAILABLE")
        if quote.currency != "USD":
            reasons.append("QUOTE_CURRENCY_UNQUALIFIED")
        if quote.delay_status != "realtime":
            reasons.append("QUOTE_DELAY_UNQUALIFIED")
        if quote.source_at is not None and quote.source_at > evaluated_at:
            reasons.append("QUOTE_SOURCE_TIME_FUTURE")
        if quote.time_basis != "documented_side_times":
            reasons.append("QUOTE_SIDE_TIME_BASIS_UNQUALIFIED")
        for name, at in (("BID", quote.bid_at), ("ASK", quote.ask_at)):
            if at is None:
                reasons.append(f"QUOTE_{name}_TIME_UNAVAILABLE")
            elif not timedelta(0) <= evaluated_at - at < timedelta(seconds=5):
                reasons.append(f"QUOTE_{name}_TIME_STALE_OR_FUTURE")
    receipt = observation.availability
    if not isinstance(receipt, CaptureReceipt):
        reasons.append("ACTUAL_CAPTURE_REQUIRED")
    else:
        if receipt.source_sha256 != source.semantic_sha256:
            reasons.append("CAPTURE_SOURCE_BINDING_MISMATCH")
        if receipt.validated_at > evaluated_at:
            reasons.append("OBSERVATION_NOT_YET_AVAILABLE")
        if (
            isinstance(quote, ForwardQuote)
            and quote.source_at is not None
            and quote.source_at > receipt.received_at
        ):
            reasons.append("QUOTE_SOURCE_TIME_AFTER_RECEIPT")
        if isinstance(quote, ForwardQuote):
            for name, at in (("BID", quote.bid_at), ("ASK", quote.ask_at)):
                if at is not None and at > receipt.received_at:
                    reasons.append(f"QUOTE_{name}_TIME_AFTER_RECEIPT")
        if not timedelta(0) <= evaluated_at - receipt.received_at < timedelta(seconds=1):
            reasons.append("QUOTE_RECEIPT_STALE_OR_FUTURE")
        if receipt.boot_id != boot_id:
            reasons.append("QUOTE_MONOTONIC_BOOT_MISMATCH")
        elif (
            not receipt.validated_monotonic_ns
            <= evaluated_monotonic_ns
            < receipt.received_monotonic_ns + 1000000000
        ):
            reasons.append("QUOTE_MONOTONIC_RECEIPT_STALE_OR_FUTURE")
    return QuoteAdmission(
        observation.semantic_sha256,
        source.semantic_sha256,
        evaluated_at,
        not reasons,
        tuple(sorted(set(reasons))),
    )


def close_frontier(
    state: ForwardDataState,
    *,
    frontier_id: str,
    requirements: tuple[ForwardRequirement, ...],
    cutoff: datetime,
    closed_at: datetime,
) -> ForwardDataTransition:
    """Close one data watermark once; quote execution eligibility is a separate check."""
    require_utc(cutoff, "decision cutoff")
    require_utc(closed_at, "frontier closure")
    require_text(frontier_id, "frontier ID")
    if type(requirements) is not tuple or not 1 <= len(requirements) <= 16:
        raise ValueError("frontier requirements must be a bounded immutable tuple")
    requirements = tuple(sorted(requirements, key=lambda r: r.semantic_sha256))
    if len({r.semantic_sha256 for r in requirements}) != len(requirements):
        raise ValueError("frontier requirements must be unique")
    previous = next((f for f in state.frontiers if f.frontier_id == frontier_id), None)
    if previous is not None:
        if previous.requirements != requirements or previous.cutoff != cutoff:
            return ForwardDataTransition(state, "rejected", ("FRONTIER_ID_CONFLICT",))
        return ForwardDataTransition(state, "duplicate", frontier=previous)
    if state.frontiers and closed_at < state.frontiers[-1].closed_at:
        return ForwardDataTransition(state, "rejected", ("FRONTIER_TIME_REGRESSION",))
    visible = replace(
        state, observations=tuple(o for o in state.observations if o.known_at <= closed_at)
    )
    selected = []
    missing = []
    for requirement in requirements:
        candidates = [
            o for o in visible.observations if _slot(o) == requirement and o.known_at < cutoff
        ]
        reasons = []
        if not candidates:
            reasons.append("REQUIRED_OBSERVATION_MISSING")
        elif requirement.kind == "daily" and len({o.revision_key for o in candidates}) != 1:
            reasons.append("AMBIGUOUS_DAILY_REVISION_ROOT")
        else:
            # A later revision cannot be hidden by an older revision fetched later.
            by_revision_key: dict[str, ForwardObservation] = {}
            for candidate in candidates:
                current = by_revision_key.get(candidate.revision_key)
                if current is None or candidate.revision > current.revision:
                    by_revision_key[candidate.revision_key] = candidate
            heads = tuple(by_revision_key.values())
            latest = max(o.known_at for o in heads)
            tied = [o for o in heads if o.known_at == latest]
            if len(tied) > 1 and any(o.source_sequence is None for o in tied):
                reasons.append("AMBIGUOUS_QUOTE_ORDER")
            else:
                head = max(
                    tied, key=lambda o: o.source_sequence if o.source_sequence is not None else -1
                )
                reasons.extend(_gaps(visible, head))
                if not reasons:
                    selected.append((requirement.semantic_sha256, head.observation_id))
        if reasons:
            missing.append((requirement.semantic_sha256, tuple(sorted(set(reasons)))))
    if closed_at < cutoff and missing:
        return ForwardDataTransition(
            state, "pending", tuple(sorted({r for _, reasons in missing for r in reasons}))
        )
    if len(state.frontiers) >= 10000:
        return ForwardDataTransition(state, "rejected", ("FRONTIER_BOUND_EXCEEDED",))
    frontier = ForwardFrontier(
        frontier_id,
        requirements,
        cutoff,
        closed_at,
        content_digest((state.sources, visible.observations)),
        tuple(selected),
        tuple(missing),
        "skipped" if closed_at >= cutoff else "complete",
        ("DECISION_CUTOFF_REACHED",) if closed_at >= cutoff else (),
    )
    updated = replace(state, frontiers=(*state.frontiers, frontier))
    return ForwardDataTransition(updated, "closed", frontier=frontier)
