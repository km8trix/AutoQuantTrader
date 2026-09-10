"""Bounded retained-input resolution and pure ordinary-run preparation.

No path, provider, worker queue or database is selected here. Real observations
must reproduce from the exact retained W1 archive; historical availability
assumptions and prior access declarations remain explicit.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace
from decimal import Decimal

from packages.application.personal_codec import decode_record, encode_record
from packages.application.personal_inputs import canonical_events, research_engine_inputs
from packages.application.research_dataset import research_dataset_from_json_bytes
from packages.domain.accounting_contracts import (
    AccountingState,
    ExecutionObservation,
    ExecutionPolicy,
    SettlementCalendar,
)
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.engine_contracts import (
    BenchmarkPrice,
    DailyPrice,
    DailyRiskPolicy,
    EngineEvent,
    EngineInputs,
    EvaluationSpec,
)
from packages.domain.personal_contracts import VersionPin, content_digest, require_amount
from packages.domain.personal_evaluation import CostScenario, PriorAccessDeclaration
from packages.domain.research_catalog import ResearchCatalogEntry
from packages.domain.research_dataset import ResearchDataClass
from packages.domain.research_job_contracts import (
    MAX_INPUT_BYTES,
    MAX_OBJECT_BYTES,
    ObjectRef,
    ResearchArtifactStore,
    ResearchRunRequest,
)


class ResearchCatalogError(ValueError):
    """Retained catalog inputs contradict their immutable identity or scope."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ResearchCatalogError(message)


def _bytes_match(payload: bytes, reference: ObjectRef) -> None:
    _require(
        type(payload) is bytes
        and len(payload) == reference.byte_count
        and len(payload) <= MAX_INPUT_BYTES
        and hashlib.sha256(payload).hexdigest() == reference.object_sha256,
        "retained bytes differ from bounded object identity",
    )


def _read(artifacts: ResearchArtifactStore, reference: ObjectRef) -> bytes:
    payload = artifacts.read(reference, max_bytes=MAX_INPUT_BYTES)
    _bytes_match(payload, reference)
    return payload


def _source(inputs: EngineInputs) -> tuple[EngineEvent, ...]:
    _require(type(inputs) is EngineInputs, "exact immutable engine inputs required")
    spec = inputs.spec
    _require(
        inputs.initial_state == AccountingState(spec.account_id)
        and spec.initial_state_sha256 == inputs.initial_state.semantic_sha256,
        "catalog source requires exact empty initial state",
    )
    events = canonical_events(inputs.events)
    _require(content_digest(events) == spec.events_sha256, "source event manifest mismatch")
    _require(
        bool(events)
        and all(
            type(e.payload) in (DailyPrice, BenchmarkPrice, ExecutionObservation) for e in events
        ),
        "catalog source cannot contain actions, accounting or scheduling commands",
    )
    _require(
        spec.execution_policy.model_id == "next-regular-open-proxy-v1"
        and spec.strategy.version == "personal-daily-reference/1"
        and spec.strategy.sha256
        == content_digest((spec.strategy_configuration, "reference-callback-adapter/1")),
        "catalog requires the fixed W2 reference model",
    )
    instruments = dict(spec.instruments)
    labels = {s.session_label for s in spec.calendar.sessions}
    closes = {s.closes_at for s in spec.calendar.sessions}
    for event in events:
        payload = event.payload
        _require(event.provenance.data_class == spec.data_class, "source event data class mismatch")
        if isinstance(payload, (DailyPrice, ExecutionObservation)):
            _require(
                instruments.get(payload.instrument_id) == payload.symbol
                and payload.session in labels,
                "source observation exceeds declared instrument/session scope",
            )
        else:
            _require(event.economic_at in closes, "benchmark must identify an exact calendar close")
    return events


def _scope(inputs: EngineInputs, evaluation: EvaluationSpec) -> tuple[EngineEvent, ...]:
    labels = tuple(s.session_label for s in inputs.spec.calendar.sessions)
    requested = (*evaluation.warmup_sessions, *evaluation.scored_sessions)
    _require(all(day in labels for day in requested), "requested session outside retained calendar")
    first, last = labels.index(requested[0]), labels.index(requested[-1])
    _require(
        labels[first : last + 1] == requested,
        "run warmup/scoring must be contiguous eligible sessions",
    )
    _require(last + 1 < len(labels), "next execution session horizon is required")
    sessions = set(requested)
    closes = {s.closes_at: s.session_label for s in inputs.spec.calendar.sessions}
    selected = tuple(
        e
        for e in canonical_events(inputs.events)
        if (
            e.payload.session
            if isinstance(e.payload, (DailyPrice, ExecutionObservation))
            else closes[e.economic_at]
        )
        in sessions
    )
    identities = {e.event_id for e in selected}
    _require(
        all(set(e.predecessor_ids).issubset(identities) for e in selected),
        "run scope drops a required causal predecessor",
    )
    return selected


def _entry_source(entry: ResearchCatalogEntry, source: EngineInputs) -> None:
    _source(source)
    spec = source.spec
    _require(
        (
            entry.dataset_id,
            entry.dataset_sha256,
            entry.source_spec_sha256,
            entry.data_class,
            entry.availability_mode,
            entry.instruments,
            entry.calendar_sha256,
            entry.settlement_calendar_sha256,
        )
        == (
            spec.dataset_id,
            spec.dataset_sha256,
            spec.semantic_sha256,
            spec.data_class,
            spec.availability_mode,
            spec.instruments,
            content_digest(spec.calendar),
            content_digest(spec.execution_policy.settlement_calendar),
        ),
        "catalog source specification differs from registration",
    )
    _bytes_match(encode_record(source), entry.source_inputs)
    _bytes_match(
        encode_record(spec.execution_policy.settlement_calendar), entry.settlement_calendar
    )


def create_catalog_entry(
    *,
    display_name: str,
    prior_access: PriorAccessDeclaration,
    source: EngineInputs,
    source_inputs: ObjectRef,
    archive: ObjectRef | None,
    settlement_calendar: ObjectRef,
) -> ResearchCatalogEntry:
    """Freeze admitted source metadata; resolver verifies retained archive contents."""
    _source(source)
    spec = source.spec
    entry = ResearchCatalogEntry(
        display_name,
        prior_access,
        source_inputs,
        archive,
        settlement_calendar,
        spec.dataset_id,
        spec.dataset_sha256,
        spec.semantic_sha256,
        spec.data_class,
        spec.availability_mode,
        spec.instruments,
        content_digest(spec.calendar),
        content_digest(spec.execution_policy.settlement_calendar),
    )
    _entry_source(entry, source)
    return entry


def _retained_provenance(
    *,
    source: EngineInputs,
    artifacts: ResearchArtifactStore,
    archive: ObjectRef | None,
    settlement_calendar: ObjectRef | None,
    scoped: bool,
) -> None:
    spec = source.spec
    _require(settlement_calendar is not None, "retained settlement calendar is required")
    assert settlement_calendar is not None
    _require(
        settlement_calendar.codec_version == "personal-record/1",
        "settlement calendar codec mismatch",
    )
    settlement = decode_record(_read(artifacts, settlement_calendar), SettlementCalendar)
    _require(
        settlement == spec.execution_policy.settlement_calendar,
        "settlement calendar differs from source",
    )
    _require(
        archive is not None or spec.data_class is ResearchDataClass.SYNTHETIC_FIXTURE,
        "current-vintage source requires its retained W1 archive",
    )
    if archive is None:
        return
    _require(
        archive.codec_version == "personal-research-dataset-v1", "retained archive codec mismatch"
    )
    dataset = research_dataset_from_json_bytes(_read(artifacts, archive))
    expected = research_engine_inputs(
        dataset,
        configuration=spec.strategy_configuration,
        evaluation=spec.evaluation,
        settlement_calendar=settlement,
        pins=spec.pins,
        initial_cash=spec.initial_cash,
        slippage_bps=spec.execution_policy.slippage_bps,
        fee_per_share=spec.execution_policy.fee_per_share,
    )
    _require(
        (
            spec.dataset_id,
            spec.dataset_sha256,
            spec.data_class,
            spec.availability_mode,
            spec.instruments,
            spec.calendar,
        )
        == (
            expected.spec.dataset_id,
            expected.spec.dataset_sha256,
            expected.spec.data_class,
            expected.spec.availability_mode,
            expected.spec.instruments,
            expected.spec.calendar,
        ),
        "source dataset identity/calendar differs from retained archive",
    )
    _require(
        canonical_events(source.events)
        == (_scope(expected, spec.evaluation) if scoped else expected.events),
        "source events differ from exact retained archive scope",
    )
    _require(
        set(expected.spec.limitations).issubset(spec.limitations),
        "source omits archive limitations",
    )


def resolve_catalog_inputs(
    entry: ResearchCatalogEntry, *, artifacts: ResearchArtifactStore
) -> EngineInputs:
    _require(type(entry) is ResearchCatalogEntry, "exact catalog entry required")
    source = decode_record(_read(artifacts, entry.source_inputs), EngineInputs)
    _entry_source(entry, source)
    _retained_provenance(
        source=source,
        artifacts=artifacts,
        archive=entry.archive,
        settlement_calendar=entry.settlement_calendar,
        scoped=False,
    )
    return source


def prepare_catalog_run_inputs(
    *,
    entry: ResearchCatalogEntry,
    source: EngineInputs,
    configuration: ReferenceConfiguration,
    evaluation: EvaluationSpec,
    initial_cash: Decimal,
    cost: CostScenario,
    current_build_pins: tuple[VersionPin, ...],
) -> EngineInputs:
    """Prepare one fresh product-policy run, preserving factual input identities."""
    _require(
        type(entry) is ResearchCatalogEntry
        and type(configuration) is ReferenceConfiguration
        and type(evaluation) is EvaluationSpec
        and type(cost) is CostScenario,
        "run preparation requires exact immutable declarations",
    )
    _entry_source(entry, source)
    require_amount(initial_cash, "run initial cash", positive=True)
    _require(
        configuration.kind != "trend_sma"
        or configuration.lookback <= len(evaluation.warmup_sessions) + 1,
        "run warmup cannot supply reference lookback",
    )
    _require(
        evaluation.prior_access_label == f"retrospective-{entry.prior_access.status}",
        "run must preserve catalog prior access declaration",
    )
    events = _scope(source, evaluation)
    spec = replace(
        source.spec,
        strategy_configuration=configuration,
        strategy=VersionPin(
            "strategy",
            "personal-daily-reference/1",
            content_digest((configuration, "reference-callback-adapter/1")),
        ),
        evaluation=evaluation,
        initial_cash=initial_cash,
        pins=current_build_pins,
        initial_state_sha256=AccountingState(source.spec.account_id).semantic_sha256,
        events_sha256=content_digest(events),
        execution_policy=ExecutionPolicy(
            source.spec.execution_policy.settlement_calendar,
            slippage_bps=cost.slippage_bps,
            fee_per_share=cost.fee_per_share,
        ),
        risk_policy=DailyRiskPolicy(fee_per_share=cost.fee_per_share),
        max_cpu_cores=1,
        max_output_bytes=MAX_OBJECT_BYTES,
        max_memory_bytes=4 * 1024**3,
        max_wall_seconds=1800,
        limitations=tuple(
            sorted(
                set(
                    (
                        *source.spec.limitations,
                        "catalog-run-descriptive-only",
                        f"prior-access:{entry.prior_access.status}",
                        "historical-holdout-not-claimed-untouched",
                    )
                )
            )
        ),
    )
    return EngineInputs(spec, events, AccountingState(spec.account_id))


class StoredResearchInputResolver:
    def __init__(self, artifacts: ResearchArtifactStore) -> None:
        self._artifacts = artifacts

    def resolve(self, request: ResearchRunRequest) -> EngineInputs:
        _require(type(request) is ResearchRunRequest, "exact retained run request required")
        source = decode_record(_read(self._artifacts, request.inputs), EngineInputs)
        _require(
            source.spec == request.spec, "retained inputs differ from accepted run specification"
        )
        events = _source(source)
        _require(
            events == _scope(source, source.spec.evaluation),
            "run events exceed the requested window",
        )
        _retained_provenance(
            source=source,
            artifacts=self._artifacts,
            archive=request.dataset_archive,
            settlement_calendar=request.settlement_calendar,
            scoped=True,
        )
        return source
