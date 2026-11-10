"""Owner-scoped API composition over retained catalog and durable research jobs."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import cast

from sqlalchemy.exc import IntegrityError

from apps.api.personal_research_contracts import (
    PersonalCapability,
    PersonalComparison,
    PersonalComparisonRequest,
    PersonalConfiguration,
    PersonalCostScenario,
    PersonalDatasetView,
    PersonalExperimentList,
    PersonalExperimentRequest,
    PersonalExperimentTrial,
    PersonalExperimentView,
    PersonalNamedValue,
    PersonalResearchCatalog,
    PersonalRowsKind,
    PersonalRunList,
    PersonalRunReport,
    PersonalRunRequest,
    PersonalRunRows,
    PersonalRunStatus,
    PersonalRunView,
    PersonalStrategyView,
)
from apps.api.personal_research_projection import (
    PersonalProjectionError,
    comparison_view,
    configuration_view,
    report_rows,
    report_view,
    run_view,
)
from apps.api.personal_research_views import ResearchConflictError, ResearchNotFoundError
from packages.adapters.personal_build import current_build_pins
from packages.application.evaluation_inputs import prepare_trial_inputs
from packages.application.personal_codec import decode_record, encode_record
from packages.application.research_catalog import prepare_catalog_run_inputs, resolve_catalog_inputs
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.engine_contracts import DailyPrice, EngineInputs, EvaluationSpec
from packages.domain.personal_contracts import content_digest
from packages.domain.personal_evaluation import (
    COST_SCENARIOS,
    CostScenario,
    EvaluationCandidate,
    EvaluationFold,
    EvaluationProtocol,
    EvaluationWindow,
    PriorAccessDeclaration,
    Segment,
    expand_trials,
    freeze_reference_fit,
    training_slice,
)
from packages.domain.report_contracts import ReportArtifact, ReportConventions
from packages.domain.research_job_contracts import (
    MAX_INPUT_BYTES,
    MAX_OBJECT_BYTES,
    ResearchArtifactStore,
    ResearchJobView,
    ResearchRunRequest,
    require_identifier,
)
from packages.domain.research_job_v2 import ResearchJobConflict
from packages.domain.research_registration import ResearchExperimentRegistration
from packages.persistence.immutable import ImmutableFactConflict
from packages.persistence.research_catalog import (
    ResearchCatalogConflict,
    ResearchCatalogMissing,
    SqlResearchCatalog,
)
from packages.persistence.research_workflow_v2 import SqlResearchWorkflow

STRATEGY_VERSION = "personal-daily-reference/1"


@contextmanager
def _conflicts() -> Iterator[None]:
    try:
        yield
    except ResearchCatalogMissing as error:
        raise ResearchNotFoundError("owner catalog identity absent") from error
    except ResearchJobConflict as error:
        if str(error) == "research job does not exist":
            raise ResearchNotFoundError("owner research job absent") from error
        raise ResearchConflictError("retained research job conflict") from error
    except (
        ResearchCatalogConflict,
        ImmutableFactConflict,
        PersonalProjectionError,
        IntegrityError,
    ) as error:
        raise ResearchConflictError("retained research identity conflict") from error


def _wire(value: PersonalRunRequest | PersonalExperimentRequest) -> str:
    return json.dumps(value.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def _configuration(value: PersonalConfiguration) -> ReferenceConfiguration:
    return ReferenceConfiguration(
        value.kind, value.lookback, Decimal(value.allocation), value.rebalance_sessions
    )


def _cost(identity: str) -> CostScenario:
    value = next((c for c in COST_SCENARIOS if c.scenario_id == identity), None)
    if value is None:
        raise ValueError("unsupported execution cost scenario")
    return value


def _request_cost(request: ResearchRunRequest) -> str:
    policy = request.spec.execution_policy
    value = next(
        (
            c
            for c in COST_SCENARIOS
            if (c.slippage_bps, c.fee_per_share) == (policy.slippage_bps, policy.fee_per_share)
        ),
        None,
    )
    if value is None:
        raise ResearchConflictError("retained run has no supported cost scenario")
    return value.scenario_id


def _cost_views() -> list[PersonalCostScenario]:
    return [
        PersonalCostScenario(
            scenario_id=c.scenario_id,
            display_name=c.scenario_id.replace("_", " "),
            slippage_bps=c.slippage_bps,
            fee_per_share=c.fee_per_share,
            assumptions=[
                "deterministic execution-cost model; no broker-fee or empirical-liquidity claim"
            ],
        )
        for c in COST_SCENARIOS
    ]


def _window(
    source: EngineInputs, start: date, end: date, warmup: int
) -> tuple[tuple[date, ...], tuple[date, ...]]:
    labels = tuple(s.session_label for s in source.spec.calendar.sessions)
    if (
        type(warmup) is not int
        or warmup < 0
        or start not in labels
        or end not in labels
        or start > end
    ):
        raise ValueError("window requires ordered retained calendar dates")
    first, last = labels.index(start), labels.index(end)
    if first < warmup or last + 1 >= len(labels):
        raise ValueError("window requires preceding warmup and next execution horizon")
    return labels[first - warmup : first], labels[first : last + 1]


class PersonalResearchService:
    def __init__(
        self,
        workflow: SqlResearchWorkflow,
        catalog: SqlResearchCatalog,
        artifacts: ResearchArtifactStore,
        *,
        owner_id: str,
        mutations_enabled: bool = True,
    ) -> None:
        require_identifier(owner_id, "service owner")
        if type(mutations_enabled) is not bool:
            raise ValueError("mutation capability must be exact boolean")
        self._workflow, self._catalog, self._artifacts = workflow, catalog, artifacts
        self._owner, self._mutations = owner_id, mutations_enabled

    def _mutate(self, owner_id: str, key: str) -> None:
        if owner_id != self._owner:
            raise ResearchNotFoundError("owner research scope absent")
        require_identifier(key, "idempotency key")
        if len(key) < 8:
            raise ValueError("idempotency key is too short")
        if not self._mutations:
            raise ResearchConflictError("research mutations disabled")

    def _owned(self, job_id: str) -> tuple[ResearchRunRequest, ResearchJobView]:
        job = self._workflow.get(job_id)
        if job.owner_id != self._owner:
            raise ResearchNotFoundError("owner research scope absent")
        request = self._workflow.get_request(job_id)
        if request.owner_id != self._owner:
            raise ResearchNotFoundError("owner research scope absent")
        return request, job

    def _artifact(self, job: ResearchJobView) -> ReportArtifact:
        if job.publication is None:
            raise ResearchConflictError("report is not published")
        ref = job.publication.object
        payload = self._artifacts.read(ref, max_bytes=MAX_OBJECT_BYTES)
        if (
            len(payload) != ref.byte_count
            or hashlib.sha256(payload).hexdigest() != ref.object_sha256
        ):
            raise ResearchConflictError("published object bytes differ")
        return decode_record(payload, ReportArtifact)

    def catalog(self) -> PersonalResearchCatalog:
        with _conflicts():
            datasets = []
            for entry in self._catalog.datasets(owner_id=self._owner, limit=200):
                source = resolve_catalog_inputs(entry, artifacts=self._artifacts)
                days = sorted(
                    {e.payload.session for e in source.events if isinstance(e.payload, DailyPrice)}
                )
                if not days:
                    raise ResearchConflictError("catalog contains no daily observations")
                datasets.append(
                    PersonalDatasetView(
                        dataset_id=entry.catalog_id,
                        manifest_sha256=entry.dataset_sha256,
                        display_name=entry.display_name,
                        data_class=entry.data_class.value,
                        symbols=[s for _, s in entry.instruments],
                        start_session=days[0],
                        end_session=days[-1],
                        session_count=len(days),
                        availability_policy=source.spec.availability_mode,
                        prior_access=entry.prior_access.status,
                        limitations=list(source.spec.limitations),
                    )
                )
            enabled = self._mutations and bool(datasets)
            capability = PersonalCapability(
                enabled=enabled,
                reasons=[]
                if enabled
                else [
                    "research_mutations_disabled"
                    if not self._mutations
                    else "no_registered_dataset"
                ],
            )
            return PersonalResearchCatalog(
                as_of=datetime.now(UTC),
                datasets=datasets,
                strategies=[
                    PersonalStrategyView(
                        strategy_id=kind,
                        version=STRATEGY_VERSION,
                        display_name="Buy and hold reference"
                        if kind == "buy_hold"
                        else "SMA trend reference",
                        description=(
                            "Fixed deterministic W2 engineering reference; "
                            "no learned parameters or qualification."
                        ),
                        default_configuration=configuration_view(ReferenceConfiguration(kind)),
                        minimum_lookback=1,
                        maximum_lookback=10000,
                        default_warmup_sessions=252,
                        limitations=["descriptive-only", "cash-funded-long-only"],
                    )
                    for kind in ("buy_hold", "trend_sma")
                ],
                cost_scenarios=_cost_views(),
                launch=capability,
                cancel=PersonalCapability(
                    enabled=self._mutations,
                    reasons=[] if self._mutations else ["research_mutations_disabled"],
                ),
                experiments=capability,
                limitations=["no_untouched_holdout_claim", "no_trading_or_strategy_qualification"],
            )

    def runs(self) -> PersonalRunList:
        with _conflicts():
            jobs = self._workflow.jobs(owner_id=self._owner, limit=100)
            views = []
            for job in jobs:
                request = self._workflow.get_request(job.job_id)
                views.append(run_view(request, job, cost_scenario_id=_request_cost(request)))
            return PersonalRunList(as_of=datetime.now(UTC), jobs=views, truncated=len(jobs) == 100)

    def run(self, job_id: str) -> PersonalRunView:
        with _conflicts():
            request, job = self._owned(job_id)
            return run_view(request, job, cost_scenario_id=_request_cost(request))

    def launch(self, request: PersonalRunRequest, *, owner_id: str, key: str) -> PersonalRunView:
        with _conflicts():
            self._mutate(owner_id, key)
            wire = _wire(request)
            existing = self._catalog.existing_launch(owner_id=owner_id, key=key, request_json=wire)
            if existing is not None:
                return self.run(existing)
            entry = self._catalog.get(request.dataset_id, owner_id=owner_id)
            if request.dataset_manifest_sha256 != entry.dataset_sha256:
                raise ResearchConflictError("selected dataset manifest changed")
            if (
                request.strategy_id != request.configuration.kind
                or request.strategy_version != STRATEGY_VERSION
            ):
                raise ValueError("strategy identity differs from its fixed configuration")
            source = resolve_catalog_inputs(entry, artifacts=self._artifacts)
            days = sorted(
                {e.payload.session for e in source.events if isinstance(e.payload, DailyPrice)}
            )
            if len(days) <= request.warmup_sessions:
                raise ValueError("warmup leaves no scored observations")
            start = request.scored_start or days[request.warmup_sessions]
            end = request.scored_end
            if end is None:
                horizon_supported = {
                    session.session_label for session in source.spec.calendar.sessions[:-1]
                }
                admitted = [day for day in days if day in horizon_supported]
                if not admitted or start > admitted[-1]:
                    raise ValueError("warmup leaves no scored observations before the horizon")
                end = admitted[-1]
            warm, scored = _window(source, start, end, request.warmup_sessions)
            evaluation = EvaluationSpec(
                "ordinary", warm, scored, f"retrospective-{entry.prior_access.status}"
            )
            prepared = prepare_catalog_run_inputs(
                entry=entry,
                source=source,
                configuration=_configuration(request.configuration),
                evaluation=evaluation,
                initial_cash=Decimal(request.initial_cash),
                cost=_cost(request.cost_scenario_id),
                current_build_pins=current_build_pins(),
            )
            retained = ResearchRunRequest(
                prepared.spec,
                ReportConventions(),
                self._artifacts.put(encode_record(prepared), max_bytes=MAX_INPUT_BYTES),
                owner_id,
                key,
                "adhoc-" + content_digest((owner_id, key, wire)),
                entry.archive,
                entry.settlement_calendar,
            )
            try:
                job_id = self._catalog.launch(
                    retained,
                    catalog_id=entry.catalog_id,
                    cost_scenario_id=request.cost_scenario_id,
                    request_json=wire,
                )
            except ResearchCatalogConflict:
                # Another first request may have committed after our early lookup.
                # Recover only its exact public intent; SQL still rejects differing records.
                existing = self._catalog.existing_launch(
                    owner_id=owner_id, key=key, request_json=wire
                )
                if existing is None:
                    raise
                job_id = existing
            return self.run(job_id)

    def cancel(self, job_id: str, *, owner_id: str, key: str) -> PersonalRunView:
        with _conflicts():
            self._mutate(owner_id, key)
            request, _ = self._owned(job_id)
            job = self._workflow.request_cancel(job_id, owner_id=owner_id, idempotency_key=key)
            return run_view(request, job, cost_scenario_id=_request_cost(request))

    def report(self, job_id: str) -> PersonalRunReport:
        with _conflicts():
            request, job = self._owned(job_id)
            view = report_view(request, job, self._artifact(job))
            return view.model_copy(
                update={"export_url": f"/api/v1/research/personal/runs/{job_id}/export"}
            )

    def rows(
        self, job_id: str, *, kind: PersonalRowsKind, report_sha256: str, offset: int, limit: int
    ) -> PersonalRunRows:
        with _conflicts():
            _, job = self._owned(job_id)
            return report_rows(
                job,
                self._artifact(job),
                kind=kind,
                report_sha256=report_sha256,
                offset=offset,
                limit=limit,
            )

    def comparison(self, request: PersonalComparisonRequest) -> PersonalComparison:
        with _conflicts():
            items = []
            for job_id in request.job_ids:
                retained, job = self._owned(job_id)
                items.append((retained, job, self._artifact(job), _request_cost(retained)))
            return comparison_view(tuple(items))

    def export(self, job_id: str) -> bytes:
        with _conflicts():
            request, job = self._owned(job_id)
            artifact = self._artifact(job)
            report_view(request, job, artifact)
            return encode_record(artifact)

    def create_experiment(
        self, request: PersonalExperimentRequest, *, owner_id: str, key: str
    ) -> PersonalExperimentView:
        with _conflicts():
            self._mutate(owner_id, key)
            wire = _wire(request)
            existing = self._catalog.existing_experiment(
                owner_id=owner_id, key=key, request_json=wire
            )
            if existing is not None:
                return self._experiment_view(existing)
            entry = self._catalog.get(request.dataset_id, owner_id=owner_id)
            if (
                entry.prior_access.status == "known_accessed"
                and request.prior_access.status != "known_accessed"
            ):
                raise ValueError("known prior access cannot be downgraded")
            source = resolve_catalog_inputs(entry, artifacts=self._artifacts)
            refreshed = prepare_catalog_run_inputs(
                entry=entry,
                source=source,
                configuration=source.spec.strategy_configuration,
                evaluation=replace(
                    source.spec.evaluation,
                    prior_access_label=f"retrospective-{entry.prior_access.status}",
                ),
                initial_cash=Decimal(10000),
                cost=COST_SCENARIOS[0],
                current_build_pins=current_build_pins(),
            )
            # Refresh only execution/build declarations: retain the full original tape,
            # including observations outside the producer's old scoring window.
            source = replace(
                refreshed,
                events=source.events,
                spec=replace(refreshed.spec, events_sha256=source.spec.events_sha256),
            )
            folds = []
            for requested in sorted(request.folds, key=lambda f: f.fold_id):
                windows = []
                for kind, start, end in (
                    ("train", requested.train_start, requested.train_end),
                    ("validation", requested.validation_start, requested.validation_end),
                    ("test", requested.test_start, requested.test_end),
                ):
                    warm, scored = _window(source, start, end, request.warmup_sessions)
                    windows.append(EvaluationWindow(cast(Segment, kind), warm, scored))
                times = [
                    e.knowledge_at
                    for e in source.events
                    if isinstance(e.payload, DailyPrice)
                    and e.payload.session in windows[0].scored_sessions
                ]
                if not times:
                    raise ValueError("training window has no available observations")
                folds.append(EvaluationFold(requested.fold_id, tuple(windows), max(times)))
            now = datetime.now(UTC)
            protocol = EvaluationProtocol(
                name=request.name,
                hypothesis=request.hypothesis,
                registered_at=now,
                registered_by=owner_id,
                dataset_id=source.spec.dataset_id,
                dataset_sha256=source.spec.dataset_sha256,
                source_spec_sha256=source.spec.semantic_sha256,
                data_class=source.spec.data_class,
                availability_mode=source.spec.availability_mode,
                calendar_sha256=content_digest(source.spec.calendar),
                instruments=source.spec.instruments,
                candidates=tuple(
                    EvaluationCandidate(c.candidate_id, _configuration(c.configuration))
                    for c in sorted(request.candidates, key=lambda c: c.candidate_id)
                ),
                folds=tuple(folds),
                prior_access=PriorAccessDeclaration(
                    request.prior_access.status, now, owner_id, request.prior_access.description
                ),
                implementation_pins=source.spec.pins,
                maximum_trials=256,
                warmup_sessions=request.warmup_sessions,
            )
            fits = tuple(
                {
                    (f.fold_id, content_digest(c.configuration)): freeze_reference_fit(
                        training_slice(protocol, f.fold_id, daily_events=source.events),
                        c.configuration,
                    )
                    for f in protocol.folds
                    for c in protocol.candidates
                }.values()
            )
            trials = expand_trials(protocol, fits=fits)
            experiment_id = content_digest(
                (ResearchExperimentRegistration.contract_version, owner_id, key)
            )
            jobs = []
            for trial in trials:
                fit = next(f for f in fits if f.semantic_sha256 == trial.fit_sha256)
                prepared = prepare_trial_inputs(
                    protocol=protocol, trial=trial, fit=fit, source=source
                )
                jobs.append(
                    ResearchRunRequest(
                        prepared.spec,
                        ReportConventions(),
                        self._artifacts.put(encode_record(prepared), max_bytes=MAX_INPUT_BYTES),
                        owner_id,
                        f"exp.{experiment_id}.{trial.ordinal}",
                        trial.trial_id,
                        entry.archive,
                        entry.settlement_calendar,
                    )
                )
            record = ResearchExperimentRegistration(
                owner_id,
                key,
                wire,
                entry.catalog_id,
                protocol,
                trials,
                tuple(j.job_id for j in jobs),
                self._artifacts.put(encode_record(source), max_bytes=MAX_INPUT_BYTES),
                tuple(
                    self._artifacts.put(encode_record(fit), max_bytes=MAX_INPUT_BYTES)
                    for fit in fits
                ),
            )
            try:
                retained = self._catalog.register_experiment(record, tuple(jobs))
            except ResearchCatalogConflict:
                existing = self._catalog.existing_experiment(
                    owner_id=owner_id, key=key, request_json=wire
                )
                if existing is None:
                    raise
                retained = existing
            return self._experiment_view(retained)

    def _experiment_view(
        self, record: ResearchExperimentRegistration, *, metrics: bool = True
    ) -> PersonalExperimentView:
        request = PersonalExperimentRequest.model_validate_json(record.request_json)
        trials = []
        jobs = []
        for trial, job_id in zip(record.trials, record.job_ids, strict=True):
            retained, job = self._owned(job_id)
            jobs.append(job)
            report = None
            if metrics and job.publication is not None:
                report = report_view(retained, job, self._artifact(job))
            trials.append(
                PersonalExperimentTrial(
                    trial_id=trial.trial_id,
                    candidate_id=trial.candidate_id,
                    fold_id=trial.fold_id,
                    window=trial.segment,
                    cost_scenario_id=trial.cost.scenario_id,
                    status=job.status,
                    job_id=job_id,
                    report_sha256=None
                    if job.publication is None
                    else job.publication.report_sha256,
                    reasons=[] if job.reason_code is None else [job.reason_code],
                    metrics=[] if report is None else report.metrics,
                    benchmark_metrics=[] if report is None else report.benchmark_metrics,
                )
            )
        statuses = {j.status for j in jobs}
        status = next(
            (
                s
                for s in ("running", "queued", "failed", "cancelled", "incomplete")
                if s in statuses
            ),
            "completed",
        )
        protocol = record.protocol
        provenance = {
            "data_class": protocol.data_class.value,
            "dataset_sha256": protocol.dataset_sha256,
            "availability_mode": protocol.availability_mode,
            "reset_mode": "independent",
            "warmup_sessions": str(protocol.warmup_sessions),
            "prior_access": protocol.prior_access.status,
            "source_inputs_sha256": record.source_inputs.object_sha256,
            "source_spec_sha256": protocol.source_spec_sha256,
            "fit_inventory_sha256": content_digest(record.fit_objects),
            "fit_count": str(len(record.fit_objects)),
            "transform": "identity-no-fit/1",
        }
        provenance.update(
            {"pin:" + p.name: p.version + ":" + p.sha256 for p in protocol.implementation_pins}
        )
        return PersonalExperimentView(
            experiment_id=record.experiment_id,
            protocol_sha256=protocol.semantic_sha256,
            requested_at=min(j.requested_at for j in jobs),
            updated_at=max(j.updated_at for j in jobs),
            request=request,
            status=cast(PersonalRunStatus, status),
            evaluation_mode="descriptive_only",
            suitability="not_assessed",
            planned_trial_count=protocol.planned_trial_count,
            cost_scenarios=_cost_views(),
            trials=trials,
            provenance=[PersonalNamedValue(name=k, value=v) for k, v in sorted(provenance.items())],
            limitations=[
                "no_untouched_holdout_claim",
                "no_strategy_suitability_qualification",
                "independent_account_and_strategy_reset",
                "fixed_reference_identity_no_fit",
            ],
            reasons=[] if metrics else ["trial_metrics_available_in_experiment_detail"],
            export_url=None,
        )

    def experiments(self) -> PersonalExperimentList:
        with _conflicts():
            records = self._catalog.experiments(owner_id=self._owner, limit=6)
            return PersonalExperimentList(
                as_of=datetime.now(UTC),
                experiments=[self._experiment_view(r, metrics=False) for r in records],
                truncated=len(records) == 6,
            )

    def experiment(self, experiment_id: str) -> PersonalExperimentView:
        with _conflicts():
            return self._experiment_view(
                self._catalog.experiment(experiment_id, owner_id=self._owner)
            )
