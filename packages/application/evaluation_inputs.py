"""Pure evaluation-to-W2 input preparation; execution belongs to the one runner."""

from __future__ import annotations

from dataclasses import replace

from packages.application.personal_inputs import canonical_events
from packages.domain.accounting_contracts import AccountingState, ExecutionObservation
from packages.domain.engine_contracts import (
    BenchmarkPrice,
    DailyPrice,
    EngineInputs,
    EvaluationSpec,
)
from packages.domain.personal_contracts import VersionPin, content_digest
from packages.domain.personal_evaluation import (
    EVALUATION_VERSION,
    EvaluationError,
    EvaluationProtocol,
    EvaluationTrial,
    ReferenceFitArtifact,
    training_slice,
    validate_protocol,
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EvaluationError(message)


def prepare_trial_inputs(
    *,
    protocol: EvaluationProtocol,
    trial: EvaluationTrial,
    fit: ReferenceFitArtifact,
    source: EngineInputs,
) -> EngineInputs:
    """Bind one preregistered trial without running, fitting or publishing it.

    Input row identities are unchanged. Calendar and settlement horizons remain
    intact; only source events inside this independent window are admitted.
    Action/accounting/explicit schedule tapes require a separate scoped contract.
    """
    _require(
        type(protocol) is EvaluationProtocol
        and type(trial) is EvaluationTrial
        and type(fit) is ReferenceFitArtifact
        and type(source) is EngineInputs,
        "trial preparation requires exact immutable records",
    )
    validate_protocol(protocol, calendar=source.spec.calendar)
    spec = source.spec
    _require(
        spec.semantic_sha256 == protocol.source_spec_sha256
        and spec.dataset_id == protocol.dataset_id
        and spec.dataset_sha256 == protocol.dataset_sha256
        and spec.data_class == protocol.data_class
        and spec.availability_mode == protocol.availability_mode
        and spec.instruments == protocol.instruments
        and spec.pins == protocol.implementation_pins,
        "source specification differs from preregistration",
    )
    _require(
        source.initial_state == AccountingState(spec.account_id)
        and spec.initial_state_sha256 == source.initial_state.semantic_sha256,
        "independent evaluation requires an empty initial account",
    )
    canonical = canonical_events(source.events)
    _require(content_digest(canonical) == spec.events_sha256, "source event manifest mismatch")
    _require(
        all(
            type(e.payload) in (DailyPrice, BenchmarkPrice, ExecutionObservation) for e in canonical
        ),
        "evaluation does not support action, accounting or explicit schedule boundaries",
    )
    _require(
        spec.execution_policy.model_id == "next-regular-open-proxy-v1"
        and spec.strategy.version == "personal-daily-reference/1",
        "evaluation requires the fixed W2 daily reference model",
    )
    _require(trial.protocol_sha256 == protocol.semantic_sha256, "trial belongs to another protocol")
    ordered = tuple(
        (f, c, w, cost)
        for f in protocol.folds
        for c in protocol.candidates
        for w in f.windows
        for cost in protocol.costs
    )
    _require(trial.ordinal < len(ordered), "trial ordinal exceeds declared inventory")
    fold, candidate, window, cost = ordered[trial.ordinal]
    _require(
        (trial.fold_id, trial.candidate_id, trial.segment, trial.cost)
        == (fold.fold_id, candidate.candidate_id, window.kind, cost),
        "trial order or scope differs from preregistration",
    )
    _require(
        fit.configuration == candidate.configuration
        and content_digest(candidate.configuration) == trial.configuration_sha256
        and fit.semantic_sha256 == trial.fit_sha256,
        "trial configuration or no-fit artifact differs",
    )
    _require(
        fit.training == training_slice(protocol, fold.fold_id, daily_events=canonical),
        "fit artifact does not bind the exact available training slice",
    )
    sessions = set((*window.warmup_sessions, *window.scored_sessions))
    close_sessions = {s.closes_at: s.session_label for s in spec.calendar.sessions}
    selected = []
    for event in canonical:
        payload = event.payload
        if isinstance(payload, (DailyPrice, ExecutionObservation)):
            keep = payload.session in sessions
        else:
            _require(event.economic_at in close_sessions, "benchmark lacks an exact session close")
            keep = close_sessions[event.economic_at] in sessions
        if keep:
            selected.append(event)
    event_ids = {event.event_id for event in selected}
    _require(
        all(set(e.predecessor_ids).issubset(event_ids) for e in selected),
        "trial slicing would drop a required causal predecessor",
    )
    scoped = tuple(selected)  # canonical input order; no timestamp/identity rewriting.
    extra = {
        "evaluation_protocol": protocol.semantic_sha256,
        "evaluation_trial": trial.semantic_sha256,
        "evaluation_fold": fold.semantic_sha256,
        "evaluation_fit": fit.semantic_sha256,
        "evaluation_cost": cost.semantic_sha256,
        "evaluation_access": protocol.prior_access.semantic_sha256,
    }
    _require(
        not set(extra).intersection(pin.name for pin in spec.pins),
        "source already contains evaluation pins",
    )
    pins = tuple(
        sorted(
            (
                *spec.pins,
                *(VersionPin(name, EVALUATION_VERSION, digest) for name, digest in extra.items()),
            ),
            key=lambda pin: pin.name,
        )
    )
    configuration = candidate.configuration
    return EngineInputs(
        replace(
            spec,
            strategy_configuration=configuration,
            strategy=VersionPin(
                "strategy",
                "personal-daily-reference/1",
                content_digest((configuration, "reference-callback-adapter/1")),
            ),
            evaluation=EvaluationSpec(
                f"{fold.fold_id}:{window.kind}",
                window.warmup_sessions,
                window.scored_sessions,
                f"retrospective-{protocol.prior_access.status}",
            ),
            events_sha256=content_digest(scoped),
            pins=pins,
            initial_cash=protocol.initial_cash,
            execution_policy=replace(
                spec.execution_policy,
                slippage_bps=cost.slippage_bps,
                fee_per_share=cost.fee_per_share,
            ),
            risk_policy=replace(spec.risk_policy, fee_per_share=cost.fee_per_share),
            limitations=tuple(
                sorted(
                    set(
                        (
                            *spec.limitations,
                            "descriptive-only-no-candidate-qualification",
                            "identity-no-fit-fixed-reference",
                            "historical-holdout-not-claimed-untouched",
                            f"prior-access:{protocol.prior_access.status}",
                            "four-preregistered-execution-cost-models",
                        )
                    )
                )
            ),
        ),
        scoped,
        AccountingState(spec.account_id),
    )
