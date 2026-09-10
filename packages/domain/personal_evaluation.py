"""Immutable descriptive evaluation plans for the fixed W2 reference strategies.

These records do not own workers, attempts, data access or trading permission.
Identity/no-fit is explicit: no learned parameter is manufactured or consumed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import ClassVar, Literal

from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.engine_contracts import DailyPrice, EngineEvent
from packages.domain.personal_contracts import (
    ContractRecord,
    VersionPin,
    content_digest,
    require_amount,
    require_digest,
    require_text,
)
from packages.domain.report_contracts import MetricValue, RunReport
from packages.domain.research_dataset import ResearchCalendar, ResearchDataClass

EVALUATION_VERSION = "personal-evaluation/1"
type Segment = Literal["train", "validation", "test"]
type AttemptStatus = Literal[
    "queued", "running", "completed", "incomplete", "failed", "cancelled", "abandoned"
]


class EvaluationError(ValueError):
    """An evaluation declaration or retained result contradicts its scope."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EvaluationError(message)


def _sessions(values: tuple[date, ...], name: str, *, empty: bool = False) -> None:
    _require(
        (empty or bool(values)) and values == tuple(sorted(set(values))),
        f"{name} must be sorted unique eligible sessions",
    )


class EvaluationRecord(ContractRecord):
    __slots__ = ()
    contract_version: ClassVar[str] = EVALUATION_VERSION


@dataclass(frozen=True, slots=True)
class CostScenario(EvaluationRecord):
    scenario_id: Literal["base_1x", "base_2x", "base_3x", "adverse"]
    slippage_bps: Decimal
    fee_per_share: Decimal

    def __post_init__(self) -> None:
        super(CostScenario, self).__post_init__()
        expected = {
            "base_1x": ("5", ".01"),
            "base_2x": ("10", ".02"),
            "base_3x": ("15", ".03"),
            "adverse": ("20", ".02"),
        }
        _require(
            (self.slippage_bps, self.fee_per_share)
            == tuple(map(Decimal, expected[self.scenario_id])),
            "cost scenario differs from its frozen model",
        )


COST_SCENARIOS: tuple[CostScenario, ...] = (
    CostScenario("base_1x", Decimal(5), Decimal(".01")),
    CostScenario("base_2x", Decimal(10), Decimal(".02")),
    CostScenario("base_3x", Decimal(15), Decimal(".03")),
    CostScenario("adverse", Decimal(20), Decimal(".02")),
)


@dataclass(frozen=True, slots=True)
class EvaluationWindow(EvaluationRecord):
    kind: Segment
    warmup_sessions: tuple[date, ...]
    scored_sessions: tuple[date, ...]

    def __post_init__(self) -> None:
        super(EvaluationWindow, self).__post_init__()
        _sessions(self.warmup_sessions, "warmup", empty=True)
        _sessions(self.scored_sessions, "scoring")
        _require(
            not self.warmup_sessions or self.warmup_sessions[-1] < self.scored_sessions[0],
            "warmup must precede scoring",
        )


@dataclass(frozen=True, slots=True)
class EvaluationFold(EvaluationRecord):
    fold_id: str
    windows: tuple[EvaluationWindow, ...]
    fit_knowledge_cutoff: datetime
    reset_mode: Literal["independent"] = "independent"
    purge_sessions: int = 0
    embargo_sessions: int = 0

    def __post_init__(self) -> None:
        super(EvaluationFold, self).__post_init__()
        require_text(self.fold_id, "fold ID")
        _require(
            tuple(w.kind for w in self.windows) == ("train", "validation", "test"),
            "fold requires ordered train, validation and test windows",
        )
        _require(
            all(
                a.scored_sessions[-1] < b.scored_sessions[0]
                for a, b in zip(self.windows, self.windows[1:], strict=False)
            ),
            "fold scored windows overlap or reverse",
        )
        _require(
            self.purge_sessions == self.embargo_sessions == 0,
            "nonzero purge or embargo is not implemented for fixed references",
        )

    def window(self, segment: Segment) -> EvaluationWindow:
        return next(w for w in self.windows if w.kind == segment)


@dataclass(frozen=True, slots=True)
class EvaluationCandidate(EvaluationRecord):
    candidate_id: str
    configuration: ReferenceConfiguration

    def __post_init__(self) -> None:
        super(EvaluationCandidate, self).__post_init__()
        require_text(self.candidate_id, "candidate ID")


@dataclass(frozen=True, slots=True)
class PriorAccessDeclaration(EvaluationRecord):
    status: Literal["known_accessed", "unknown"]
    recorded_at: datetime
    recorded_by: str
    description: str

    def __post_init__(self) -> None:
        super(PriorAccessDeclaration, self).__post_init__()
        require_text(self.recorded_by, "access recorder")
        require_text(self.description, "prior access description")


@dataclass(frozen=True, slots=True)
class EvaluationProtocol(EvaluationRecord):
    name: str
    hypothesis: str
    registered_at: datetime
    registered_by: str
    dataset_id: str
    dataset_sha256: str
    source_spec_sha256: str
    data_class: ResearchDataClass
    availability_mode: Literal["modeled", "recorded"]
    calendar_sha256: str
    instruments: tuple[tuple[str, str], ...]
    candidates: tuple[EvaluationCandidate, ...]
    folds: tuple[EvaluationFold, ...]
    prior_access: PriorAccessDeclaration
    implementation_pins: tuple[VersionPin, ...]
    initial_cash: Decimal = Decimal("10000")
    maximum_trials: int = 256
    warmup_sessions: int = 252
    mode: Literal["descriptive_only"] = "descriptive_only"
    costs: tuple[CostScenario, ...] = COST_SCENARIOS

    def __post_init__(self) -> None:
        super(EvaluationProtocol, self).__post_init__()
        for name in ("name", "hypothesis", "registered_by", "dataset_id"):
            require_text(getattr(self, name), name)
        require_digest(self.dataset_sha256, "dataset")
        require_digest(self.source_spec_sha256, "source specification")
        require_digest(self.calendar_sha256, "calendar")
        require_amount(self.initial_cash, "initial cash", positive=True)
        _require(
            self.prior_access.recorded_at <= self.registered_at,
            "access declaration must precede registration",
        )
        _require(self.costs == COST_SCENARIOS, "protocol requires all four cost scenarios")
        _require(
            0 <= self.warmup_sessions <= 10000 and 1 <= self.maximum_trials <= 4096,
            "evaluation resource declaration is outside its bound",
        )
        _require(bool(self.candidates) and bool(self.folds), "protocol needs candidates and folds")
        for items, values, name in (
            (self.candidates, tuple(c.candidate_id for c in self.candidates), "candidates"),
            (self.folds, tuple(f.fold_id for f in self.folds), "folds"),
        ):
            _require(
                len(items) <= 32 and values == tuple(sorted(set(values))),
                f"{name} must have bounded sorted unique IDs",
            )
        ids = tuple(i for i, _ in self.instruments)
        _require(
            bool(ids) and ids == tuple(sorted(set(ids))) and len(ids) <= 4,
            "instruments must be a bounded sorted unique scope",
        )
        _require(
            all(s in ("DIA", "IWM", "QQQ", "SPY") for _, s in self.instruments),
            "unsupported evaluation symbol",
        )
        pin_names = tuple(pin.name for pin in self.implementation_pins)
        _require(
            bool(pin_names) and pin_names == tuple(sorted(set(pin_names))),
            "implementation pins must be unique and sorted",
        )
        _require(
            self.planned_trial_count <= self.maximum_trials,
            "declared trial inventory exceeds its budget",
        )
        scored: set[date] = set()
        for fold in self.folds:
            for window in fold.windows:
                _require(
                    len(window.warmup_sessions) == self.warmup_sessions,
                    "window differs from declared warmup length",
                )
                if window.kind != "train":
                    _require(
                        not scored.intersection(window.scored_sessions),
                        "out-of-training scored windows overlap across folds",
                    )
                    scored.update(window.scored_sessions)
        _require(
            all(
                c.configuration.kind != "trend_sma"
                or c.configuration.lookback <= self.warmup_sessions + 1
                for c in self.candidates
            ),
            "warmup cannot supply the required trend lookback",
        )

    @property
    def planned_trial_count(self) -> int:
        return len(self.candidates) * len(self.folds) * 3 * len(self.costs)

    @property
    def protocol_id(self) -> str:
        return "evaluation-" + self.semantic_sha256


def validate_protocol(protocol: EvaluationProtocol, *, calendar: ResearchCalendar) -> None:
    _require(
        type(protocol) is EvaluationProtocol and type(calendar) is ResearchCalendar,
        "protocol validation requires exact immutable records",
    )
    _require(content_digest(calendar) == protocol.calendar_sha256, "calendar identity mismatch")
    labels = tuple(session.session_label for session in calendar.sessions)
    by_day = {session.session_label: session for session in calendar.sessions}
    for fold in protocol.folds:
        for window in fold.windows:
            _require(
                all(day in by_day for day in (*window.warmup_sessions, *window.scored_sessions)),
                "declared session outside supplied calendar",
            )
            first, last = (
                labels.index(window.scored_sessions[0]),
                labels.index(window.scored_sessions[-1]),
            )
            _require(
                labels[first : last + 1] == window.scored_sessions,
                "scored window omits an expected calendar session",
            )
            _require(
                first >= protocol.warmup_sessions
                and labels[first - protocol.warmup_sessions : first] == window.warmup_sessions,
                "warmup must contain the exact eligible preceding sessions",
            )
            _require(last + 1 < len(labels), "next execution session horizon is required")
        _require(
            by_day[fold.windows[0].scored_sessions[-1]].closes_at
            <= fold.fit_knowledge_cutoff
            < by_day[fold.windows[1].scored_sessions[0]].opens_at,
            "fit cutoff must follow training and precede validation",
        )


@dataclass(frozen=True, slots=True)
class TrainingSlice(EvaluationRecord):
    fold_id: str
    sessions: tuple[date, ...]
    knowledge_cutoff: datetime
    instruments: tuple[tuple[str, str], ...]
    events: tuple[EngineEvent, ...]

    def __post_init__(self) -> None:
        super(TrainingSlice, self).__post_init__()
        require_text(self.fold_id, "fit fold")
        _sessions(self.sessions, "training sessions")
        ids = tuple(i for i, _ in self.instruments)
        _require(
            bool(ids)
            and ids == tuple(sorted(set(ids)))
            and all(s in ("DIA", "IWM", "QQQ", "SPY") for _, s in self.instruments),
            "training instruments must be unique supported identities",
        )
        _require(
            bool(self.events)
            and tuple(e.event_id for e in self.events)
            == tuple(sorted({e.event_id for e in self.events})),
            "training events must be unique and sorted",
        )
        expected = {(i, day) for i, _ in self.instruments for day in self.sessions}
        observed = set()
        for event in self.events:
            payload = event.payload
            _require(type(payload) is DailyPrice, "training slice accepts daily observations only")
            assert isinstance(payload, DailyPrice)
            _require(
                (payload.instrument_id, payload.session) in expected
                and dict(self.instruments).get(payload.instrument_id) == payload.symbol,
                "training event exceeds declared session/instrument scope",
            )
            _require(
                event.knowledge_at <= self.knowledge_cutoff, "training event exceeds fit cutoff"
            )
            observed.add((payload.instrument_id, payload.session))
        _require(observed == expected, "training observations are incomplete at fit cutoff")


def training_slice(
    protocol: EvaluationProtocol, fold_id: str, *, daily_events: tuple[EngineEvent, ...]
) -> TrainingSlice:
    fold = next((f for f in protocol.folds if f.fold_id == fold_id), None)
    _require(fold is not None, "unknown training fold")
    assert fold is not None
    selected: dict[str, EngineEvent] = {}
    for event in daily_events:
        if (
            isinstance(event.payload, DailyPrice)
            and event.payload.session in fold.windows[0].scored_sessions
            and event.knowledge_at <= fold.fit_knowledge_cutoff
        ):
            _require(
                event.event_id not in selected or selected[event.event_id] == event,
                "conflicting training event identity",
            )
            _require(
                event.provenance.data_class == protocol.data_class, "training data class mismatch"
            )
            available = (
                event.provenance.simulated_available_at
                if protocol.availability_mode == "modeled"
                else event.provenance.observed_at
            )
            _require(
                available is not None and event.knowledge_at >= available,
                "training event precedes its declared availability",
            )
            selected[event.event_id] = event
    return TrainingSlice(
        fold_id,
        fold.windows[0].scored_sessions,
        fold.fit_knowledge_cutoff,
        protocol.instruments,
        tuple(selected[k] for k in sorted(selected)),
    )


@dataclass(frozen=True, slots=True)
class ReferenceFitArtifact(EvaluationRecord):
    training: TrainingSlice
    configuration: ReferenceConfiguration
    transform_version: Literal["identity-no-fit/1"] = "identity-no-fit/1"
    fitted_parameters: tuple[tuple[str, Decimal], ...] = ()
    learned_transform_supported: Literal[False] = False

    def __post_init__(self) -> None:
        super(ReferenceFitArtifact, self).__post_init__()
        _require(not self.fitted_parameters, "fixed reference cannot contain learned parameters")

    @property
    def parameters_sha256(self) -> str:
        return content_digest((self.transform_version, self.configuration, self.fitted_parameters))


def freeze_reference_fit(
    training: TrainingSlice, configuration: ReferenceConfiguration
) -> ReferenceFitArtifact:
    return ReferenceFitArtifact(training, configuration)


@dataclass(frozen=True, slots=True)
class EvaluationTrial(EvaluationRecord):
    protocol_sha256: str
    ordinal: int
    fold_id: str
    segment: Segment
    candidate_id: str
    configuration_sha256: str
    fit_sha256: str
    cost: CostScenario

    def __post_init__(self) -> None:
        super(EvaluationTrial, self).__post_init__()
        for name in ("protocol_sha256", "configuration_sha256", "fit_sha256"):
            require_digest(getattr(self, name), name)
        require_text(self.fold_id, "trial fold")
        require_text(self.candidate_id, "trial candidate")
        _require(self.ordinal >= 0, "trial ordinal must be nonnegative")

    @property
    def trial_id(self) -> str:
        return "trial-" + self.semantic_sha256


def expand_trials(
    protocol: EvaluationProtocol, *, fits: tuple[ReferenceFitArtifact, ...]
) -> tuple[EvaluationTrial, ...]:
    by_key = {(fit.training.fold_id, content_digest(fit.configuration)): fit for fit in fits}
    _require(len(by_key) == len(fits), "duplicate fold/configuration fit")
    required = {
        (fold.fold_id, content_digest(c.configuration))
        for fold in protocol.folds
        for c in protocol.candidates
    }
    _require(set(by_key) == required, "fit inventory differs from declared candidates/folds")
    result: list[EvaluationTrial] = []
    for fold in protocol.folds:
        for candidate in protocol.candidates:
            fit = by_key[(fold.fold_id, content_digest(candidate.configuration))]
            _require(
                fit.training.sessions == fold.windows[0].scored_sessions
                and fit.training.knowledge_cutoff == fold.fit_knowledge_cutoff
                and fit.training.instruments == protocol.instruments,
                "fit scope differs from protocol",
            )
            for window in fold.windows:
                for cost in protocol.costs:
                    result.append(
                        EvaluationTrial(
                            protocol.semantic_sha256,
                            len(result),
                            fold.fold_id,
                            window.kind,
                            candidate.candidate_id,
                            content_digest(candidate.configuration),
                            fit.semantic_sha256,
                            cost,
                        )
                    )
    return tuple(result)


@dataclass(frozen=True, slots=True)
class TrialOutcome(EvaluationRecord):
    trial_id: str
    attempt_id: str
    status: AttemptStatus
    report: RunReport | None = None
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super(TrialOutcome, self).__post_init__()
        require_text(self.trial_id, "outcome trial")
        require_text(self.attempt_id, "attempt")
        _require(
            self.status != "completed"
            or (
                self.report is not None
                and self.report.status == "completed"
                and self.report.source.status == "completed"
            ),
            "completion requires a completed economic report",
        )
        _require(
            self.status not in ("queued", "running") or self.report is None,
            "nonterminal attempt cannot publish a report",
        )
        _require(
            self.status not in ("incomplete", "failed", "cancelled", "abandoned")
            or bool(self.reasons),
            "unsuccessful attempt requires an explicit reason",
        )


@dataclass(frozen=True, slots=True)
class TrialComparisonRow(EvaluationRecord):
    trial: EvaluationTrial
    outcomes: tuple[TrialOutcome, ...]
    metrics: tuple[MetricValue, ...]
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EvaluationComparison(EvaluationRecord):
    protocol_sha256: str
    rows: tuple[TrialComparisonRow, ...]
    eligibility: Literal["not_assessed"] = "not_assessed"
    selected_candidate_id: None = None
    reasons: tuple[str, ...] = ("descriptive_only_no_owner_suitability_criteria",)


def compare_trials(
    protocol: EvaluationProtocol,
    *,
    trials: tuple[EvaluationTrial, ...],
    outcomes: tuple[TrialOutcome, ...],
) -> EvaluationComparison:
    _require(
        len(trials) == protocol.planned_trial_count
        and tuple(t.ordinal for t in trials) == tuple(range(len(trials))),
        "comparison requires the full declared trial inventory",
    )
    expected = tuple(
        (f.fold_id, c.candidate_id, content_digest(c.configuration), w.kind, cost)
        for f in protocol.folds
        for c in protocol.candidates
        for w in f.windows
        for cost in protocol.costs
    )
    _require(
        tuple(
            (t.fold_id, t.candidate_id, t.configuration_sha256, t.segment, t.cost) for t in trials
        )
        == expected
        and all(t.protocol_sha256 == protocol.semantic_sha256 for t in trials),
        "comparison trial scope differs from registration",
    )
    by_id = {t.trial_id: t for t in trials}
    _require(
        len({o.attempt_id for o in outcomes}) == len(outcomes), "attempt outcomes must be unique"
    )
    _require(all(o.trial_id in by_id for o in outcomes), "outcome references an unknown trial")
    rows = []
    for trial in trials:
        fold = next(f for f in protocol.folds if f.fold_id == trial.fold_id)
        window = fold.window(trial.segment)
        history = tuple(o for o in outcomes if o.trial_id == trial.trial_id)
        completed = tuple(o for o in history if o.status == "completed")
        _require(
            len(completed) <= 1, "one logical trial cannot have duplicate completed publications"
        )
        for outcome in history:
            if outcome.report is None:
                continue
            spec = outcome.report.source.spec
            pins = {pin.name: pin.sha256 for pin in spec.pins}
            _require(
                pins.get("evaluation_trial") == trial.semantic_sha256
                and pins.get("evaluation_protocol") == protocol.semantic_sha256
                and pins.get("evaluation_fit") == trial.fit_sha256
                and pins.get("evaluation_fold") == fold.semantic_sha256
                and pins.get("evaluation_cost") == trial.cost.semantic_sha256
                and pins.get("evaluation_access") == protocol.prior_access.semantic_sha256,
                "outcome report lacks exact evaluation identity",
            )
            _require(
                content_digest(spec.strategy_configuration) == trial.configuration_sha256
                and spec.execution_policy.slippage_bps == trial.cost.slippage_bps
                and spec.execution_policy.fee_per_share == trial.cost.fee_per_share,
                "outcome configuration or costs differ from trial",
            )
            _require(
                spec.dataset_id == protocol.dataset_id
                and spec.dataset_sha256 == protocol.dataset_sha256
                and spec.data_class == protocol.data_class
                and spec.availability_mode == protocol.availability_mode
                and spec.instruments == protocol.instruments
                and content_digest(spec.calendar) == protocol.calendar_sha256
                and spec.initial_cash == protocol.initial_cash
                and spec.evaluation.warmup_sessions == window.warmup_sessions
                and spec.evaluation.scored_sessions == window.scored_sessions
                and spec.evaluation.prior_access_label
                == f"retrospective-{protocol.prior_access.status}"
                and all(pin in spec.pins for pin in protocol.implementation_pins),
                "outcome data, window or implementation differs from registration",
            )
            _require(
                outcome.report.run_id == spec.run_id
                and outcome.report.result_sha256 == outcome.report.source.semantic_sha256
                and outcome.report.interval == outcome.report.source.interval,
                "outcome report differs from retained engine result",
            )
        report = completed[0].report if completed else None
        rows.append(
            TrialComparisonRow(
                trial,
                history,
                () if report is None else report.metrics,
                ()
                if report is not None
                else ("not_attempted" if not history else "no_completed_report",),
            )
        )
    return EvaluationComparison(protocol.semantic_sha256, tuple(rows))
