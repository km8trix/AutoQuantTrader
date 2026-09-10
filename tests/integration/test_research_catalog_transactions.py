from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Event
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy import Engine

from packages.application import personal_codec
from packages.domain.engine_contracts import EvaluationSpec
from packages.domain.personal_contracts import VersionPin, content_digest
from packages.domain.personal_evaluation import (
    COST_SCENARIOS,
    EvaluationCandidate,
    EvaluationFold,
    EvaluationProtocol,
    EvaluationTrial,
    EvaluationWindow,
    PriorAccessDeclaration,
)
from packages.domain.research_catalog import ResearchCatalogEntry
from packages.domain.research_job_contracts import ObjectRef, ResearchProgress, ResearchRunRequest
from packages.domain.research_job_v2 import ResearchJobConflict
from packages.domain.research_registration import ResearchExperimentRegistration
from packages.persistence import research_catalog
from packages.persistence.database import (
    DatabaseSchemaNotReady,
    _capture_personal_research_validation,
    _repeatable_read_transaction,
)
from packages.persistence.research_catalog import (
    ResearchCatalogConflict,
    ResearchCatalogMissing,
    SqlResearchCatalog,
)
from packages.persistence.research_catalog_schema import (
    RESEARCH_CATALOG_TABLES,
)
from packages.persistence.research_catalog_schema import (
    research_catalog_entries as entries,
)
from packages.persistence.research_catalog_schema import (
    research_experiments as experiments,
)
from packages.persistence.research_catalog_schema import (
    research_trial_jobs as links,
)
from packages.persistence.research_schema_v2 import RESEARCH_TABLES_V2
from packages.persistence.research_schema_v2 import research_jobs_v2 as jobs
from packages.persistence.research_workflow_v2 import SqlResearchWorkflow
from packages.persistence.schema import metadata
from tests.integration.test_phase2_postgres_exit import postgres_engine as postgres_engine
from tests.integration.test_research_workflow_v2 import make_workflow
from tests.unit.test_research_job_v2 import NOW, sample_inputs, sample_request


def object_ref(value: object) -> ObjectRef:
    payload = personal_codec.encode_record(value)
    return ObjectRef(hashlib.sha256(payload).hexdigest(), len(payload))


def catalog_sample(label: str = "SQL transaction fixture") -> ResearchCatalogEntry:
    inputs = sample_inputs()
    spec = inputs.spec
    calendar = spec.execution_policy.settlement_calendar
    return ResearchCatalogEntry(
        label,
        PriorAccessDeclaration("known_accessed", NOW, "owner", "synthetic fixture"),
        object_ref(inputs),
        None,
        object_ref(calendar),
        spec.dataset_id,
        spec.dataset_sha256,
        spec.semantic_sha256,
        spec.data_class,
        spec.availability_mode,
        spec.instruments,
        content_digest(spec.calendar),
        content_digest(calendar),
    )


def launch_sample(
    entry: ResearchCatalogEntry, key: str = "catalog-launch-0001"
) -> ResearchRunRequest:
    return replace(sample_request(key), settlement_calendar=entry.settlement_calendar)


def experiment_sample(
    entry: ResearchCatalogEntry, *, key: str = "experiment-0001", owner: str = "owner"
) -> tuple[ResearchExperimentRegistration, tuple[ResearchRunRequest, ...]]:
    source = sample_inputs()
    spec = source.spec
    dates = tuple(s.session_label for s in spec.calendar.sessions)
    fold = EvaluationFold(
        "fold-one",
        (
            EvaluationWindow("train", dates[:1], dates[1:2]),
            EvaluationWindow("validation", dates[2:3], dates[3:4]),
            EvaluationWindow("test", dates[4:5], dates[5:6]),
        ),
        NOW,
    )
    candidate = EvaluationCandidate("buy-hold", spec.strategy_configuration)
    protocol = EvaluationProtocol(
        "SQL fixture",
        "Persistence has no economic computation",
        NOW,
        owner,
        entry.dataset_id,
        entry.dataset_sha256,
        entry.source_spec_sha256,
        entry.data_class,
        entry.availability_mode,
        entry.calendar_sha256,
        entry.instruments,
        (candidate,),
        (fold,),
        entry.prior_access,
        spec.pins,
        warmup_sessions=1,
    )
    # Labelled SQL binding fixture: this object is never offered as a fitted strategy.
    fit = object_ref(("SQL-only fit placeholder", key))
    fit_digest = content_digest(("SQL-only fit identity", key))
    trials: list[EvaluationTrial] = []
    requests = []
    for window in fold.windows:
        for cost in COST_SCENARIOS:
            trial = EvaluationTrial(
                protocol.semantic_sha256,
                len(trials),
                fold.fold_id,
                window.kind,
                candidate.candidate_id,
                content_digest(candidate.configuration),
                fit_digest,
                cost,
            )
            pin_values = {
                "evaluation_trial": trial.semantic_sha256,
                "evaluation_protocol": protocol.semantic_sha256,
                "evaluation_fit": trial.fit_sha256,
                "evaluation_fold": fold.semantic_sha256,
                "evaluation_cost": cost.semantic_sha256,
                "evaluation_access": entry.prior_access.semantic_sha256,
            }
            trial_spec = replace(
                spec,
                execution_policy=replace(
                    spec.execution_policy,
                    slippage_bps=cost.slippage_bps,
                    fee_per_share=cost.fee_per_share,
                ),
                evaluation=EvaluationSpec(
                    fold.fold_id,
                    window.warmup_sessions,
                    window.scored_sessions,
                    "retrospective-known_accessed",
                ),
                pins=tuple(
                    sorted(
                        (
                            *spec.pins,
                            *(
                                VersionPin(name, "test-evaluation/1", digest)
                                for name, digest in pin_values.items()
                            ),
                        ),
                        key=lambda p: p.name,
                    )
                ),
            )
            inputs = replace(source, spec=trial_spec)
            request = replace(
                launch_sample(entry, f"{key}-trial-{trial.ordinal:03}"),
                spec=trial_spec,
                inputs=object_ref(inputs),
                owner_id=owner,
                trial_id=trial.trial_id,
            )
            trials.append(trial)
            requests.append(request)
    return ResearchExperimentRegistration(
        owner,
        key,
        '{"experiment":"SQL fixture"}',
        entry.catalog_id,
        protocol,
        tuple(trials),
        tuple(r.job_id for r in requests),
        entry.source_inputs,
        (fit,),
    ), tuple(requests)


def make_catalog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Engine, SqlResearchCatalog]:
    engine, workflow, clock = make_workflow(tmp_path, monkeypatch)
    metadata.create_all(engine, tables=RESEARCH_CATALOG_TABLES)
    monkeypatch.setattr(research_catalog, "database_time", lambda _connection: clock[0])
    return engine, SqlResearchCatalog(engine, codec=personal_codec, workflow=workflow)


def count(engine: Engine, table: sa.Table) -> int:
    with engine.connect() as connection:
        return int(connection.scalar(sa.select(sa.func.count()).select_from(table)))


def verify_integrity(engine: Engine) -> None:
    with _repeatable_read_transaction(engine) as connection:
        validate = _capture_personal_research_validation(connection, codec=personal_codec)
    assert validate is not None
    validate()


def test_catalog_launch_strict_retry_and_owner_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, catalog = make_catalog(tmp_path, monkeypatch)
    entry = catalog.register(catalog_sample(), owner_id="owner")
    request = launch_sample(entry)
    args = {
        "catalog_id": entry.catalog_id,
        "cost_scenario_id": "base_1x",
        "request_json": '{"launch":1}',
    }
    assert catalog.launch(request, **args) == request.job_id
    assert catalog.launch(request, **args) == request.job_id
    assert (
        catalog.existing_launch(
            owner_id="owner", key=request.idempotency_key, request_json=args["request_json"]
        )
        == request.job_id
    )
    for changed in (
        replace(request, trial_id="changed-trial"),
        replace(request, inputs=ObjectRef("b" * 64, 10)),
    ):
        with pytest.raises(ResearchCatalogConflict):
            catalog.launch(changed, **args)
    for field, value in (
        ("catalog_id", "catalog-" + "a" * 64),
        ("cost_scenario_id", "adverse"),
        ("request_json", "{}"),
    ):
        with pytest.raises(ResearchCatalogConflict):
            catalog.launch(request, **(args | {field: value}))
    assert catalog.datasets(owner_id="other") == ()
    assert (
        catalog.existing_launch(owner_id="other", key=request.idempotency_key, request_json="{}")
        is None
    )
    with pytest.raises(ResearchCatalogMissing):
        catalog.get(entry.catalog_id, owner_id="other")
    with pytest.raises(ResearchCatalogMissing):
        catalog.launch(replace(request, owner_id="other"), **args)


def test_experiment_atomic_late_conflict_rolls_back_all_new_jobs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, catalog = make_catalog(tmp_path, monkeypatch)
    entry = catalog.register(catalog_sample(), owner_id="owner")
    record, requests = experiment_sample(entry)
    catalog.workflow.launch(replace(requests[-1], trial_id="conflicting-last-trial"))
    with pytest.raises(ResearchJobConflict):
        catalog.register_experiment(record, requests)
    assert count(engine, jobs) == 1
    assert count(engine, experiments) == count(engine, links) == 0
    assert catalog.workflow.get_request(requests[-1].job_id).trial_id == "conflicting-last-trial"


def test_experiment_concurrent_identical_retry_and_exact_immutable_comparison(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, catalog = make_catalog(tmp_path, monkeypatch)
    entry = catalog.register(catalog_sample(), owner_id="owner")
    record, requests = experiment_sample(entry)
    with ThreadPoolExecutor(max_workers=2) as pool:
        returned = tuple(
            pool.map(lambda _: catalog.register_experiment(record, requests), range(2))
        )
    assert returned == (record, record)
    assert count(engine, experiments) == 1 and count(engine, links) == count(engine, jobs) == 12
    assert catalog.experiment(record.experiment_id, owner_id="owner") == record
    with pytest.raises(ResearchCatalogConflict):
        catalog.register_experiment(replace(record, request_json="{}"), requests)
    with pytest.raises(ResearchCatalogConflict):
        catalog.register_experiment(
            record, (replace(requests[0], inputs=ObjectRef("b" * 64, 10)), *requests[1:])
        )
    assert (
        catalog.existing_experiment(
            owner_id="owner", key=record.idempotency_key, request_json=record.request_json
        )
        == record
    )
    with pytest.raises(ResearchCatalogMissing):
        catalog.experiment(record.experiment_id, owner_id="other")
    verify_integrity(engine)
    with (
        engine.connect() as connection,
        pytest.raises(DatabaseSchemaNotReady, match="requires a record codec"),
    ):
        _capture_personal_research_validation(connection, codec=None)


@pytest.mark.parametrize("mutation", ["owner", "byte_digest", "semantic_digest", "payload"])
def test_catalog_retained_binding_tamper_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    engine, catalog = make_catalog(tmp_path, monkeypatch)
    entry = catalog.register(catalog_sample(), owner_id="owner")
    mutations: dict[str, dict[str, object]] = {
        "owner": {"owner_id": "other"},
        "byte_digest": {"payload_sha256": "0" * 64},
        "semantic_digest": {"entry_sha256": "0" * 64},
        "payload": {"payload": b"{}", "payload_sha256": hashlib.sha256(b"{}").hexdigest()},
    }
    changes = mutations[mutation]
    with engine.begin() as connection:
        connection.execute(entries.update().values(**changes))
    with pytest.raises(ValueError):
        catalog.get(entry.catalog_id, owner_id="other" if mutation == "owner" else "owner")
    with pytest.raises(DatabaseSchemaNotReady):
        verify_integrity(engine)


@pytest.mark.parametrize(
    "mutation", ["trial_link", "request_owner", "trial_pin", "catalog_link", "orphan"]
)
def test_experiment_rechecks_actual_job_and_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    engine, catalog = make_catalog(tmp_path, monkeypatch)
    entry = catalog.register(catalog_sample(), owner_id="owner")
    record, requests = experiment_sample(entry)
    catalog.register_experiment(record, requests)
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        if mutation == "trial_link":
            connection.execute(
                links.update().where(links.c.ordinal == 0).values(trial_id="trial-" + "0" * 64)
            )
        elif mutation in ("request_owner", "trial_pin"):
            request = requests[0]
            changed = (
                replace(request, owner_id="other")
                if mutation == "request_owner"
                else replace(
                    request,
                    spec=replace(
                        request.spec,
                        pins=tuple(
                            replace(pin, sha256="0" * 64) if pin.name == "evaluation_trial" else pin
                            for pin in request.spec.pins
                        ),
                    ),
                )
            )
            connection.execute(
                jobs.update()
                .where(jobs.c.job_id == request.job_id)
                .values(
                    request_payload=personal_codec.encode_record(changed),
                    request_sha256=changed.semantic_sha256,
                )
            )
        elif mutation == "catalog_link":
            connection.execute(experiments.update().values(catalog_id="catalog-" + "0" * 64))
        else:
            connection.execute(experiments.delete())
        connection.commit()
    if mutation != "orphan":
        with pytest.raises((ValueError, RuntimeError)):
            catalog.experiment(record.experiment_id, owner_id="owner")
    with pytest.raises(DatabaseSchemaNotReady):
        verify_integrity(engine)


def test_experiment_rejects_wrong_protocol_pin_before_any_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, catalog = make_catalog(tmp_path, monkeypatch)
    entry = catalog.register(catalog_sample(), owner_id="owner")
    record, requests = experiment_sample(entry)
    changed = replace(
        requests[-1],
        spec=replace(
            requests[-1].spec,
            pins=tuple(
                replace(pin, sha256="0" * 64) if pin.name == "evaluation_protocol" else pin
                for pin in requests[-1].spec.pins
            ),
        ),
    )
    with pytest.raises(ValueError, match="exact evaluation trial"):
        catalog.register_experiment(record, (*requests[:-1], changed))
    assert count(engine, experiments) == count(engine, jobs) == 0


@pytest.mark.parametrize(
    "reader_kind", ["get", "datasets", "launch", "experiment", "experiments", "existing"]
)
def test_catalog_expensive_validation_releases_snapshot_before_writer_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reader_kind: str
) -> None:
    """An intentionally stalled validator cannot retain a SQLite SHARED lock."""
    _, catalog = make_catalog(tmp_path, monkeypatch)
    entry = catalog.register(catalog_sample(), owner_id="owner")
    record, requests = experiment_sample(entry)
    catalog.register_experiment(record, requests)
    ordinary = launch_sample(entry)
    catalog.launch(
        ordinary, catalog_id=entry.catalog_id, cost_scenario_id="base_1x", request_json="{}"
    )
    entered, release = Event(), Event()
    original = catalog._entry

    def stalled(row):  # type: ignore[no-untyped-def]
        entered.set()
        assert release.wait(15), "test did not release catalog validation"
        return original(row)

    monkeypatch.setattr(catalog, "_entry", stalled)

    def read():  # type: ignore[no-untyped-def]
        if reader_kind == "get":
            return catalog.get(entry.catalog_id, owner_id="owner")
        if reader_kind == "datasets":
            return catalog.datasets(owner_id="owner")
        if reader_kind == "launch":
            return catalog.existing_launch(
                owner_id="owner", key=ordinary.idempotency_key, request_json="{}"
            )
        if reader_kind == "experiment":
            return catalog.experiment(record.experiment_id, owner_id="owner")
        if reader_kind == "experiments":
            return catalog.experiments(owner_id="owner")
        return catalog.existing_experiment(
            owner_id="owner", key=record.idempotency_key, request_json=record.request_json
        )

    def write() -> str:
        claimed = catalog.workflow.claim_next(worker_id="worker", worker_instance_id="process")
        assert claimed is not None
        catalog.workflow.heartbeat(claimed.claim, progress=ResearchProgress("running", 1, 1))
        return claimed.claim.job_id

    with ThreadPoolExecutor(max_workers=2) as pool:
        reader = pool.submit(read)
        try:
            assert entered.wait(10)
            # Both write transactions must COMMIT while the reader is still stalled.
            job_id = pool.submit(write).result(timeout=4)
            assert not reader.done()
            assert catalog.workflow.get(job_id).progress == ResearchProgress("running", 1, 1)
        finally:
            release.set()
        assert reader.result(timeout=10) is not None


@pytest.mark.parametrize("mutation", ["entry", "link", "page"])
def test_catalog_final_snapshot_rechecks_discovered_graph(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    engine, catalog = make_catalog(tmp_path, monkeypatch)
    entry = catalog.register(catalog_sample(), owner_id="owner")
    record, requests = experiment_sample(entry)
    catalog.register_experiment(record, requests)
    original = catalog.workflow.decode_request_row
    changed = False

    def interleave(row):  # type: ignore[no-untyped-def]
        nonlocal changed
        decoded = original(row)
        if not changed:
            changed = True
            if mutation == "page":
                extra, extra_requests = experiment_sample(entry, key="second-experiment")
                catalog.register_experiment(extra, extra_requests)
            else:
                with engine.begin() as connection:
                    if mutation == "entry":
                        connection.execute(entries.update().values(owner_id="other"))
                    else:
                        connection.execute(
                            links.update()
                            .where(links.c.ordinal == 0)
                            .values(trial_id="trial-" + "0" * 64)
                        )
        return decoded

    monkeypatch.setattr(catalog.workflow, "decode_request_row", interleave)
    with pytest.raises(ResearchCatalogConflict, match="selection changed during read"):
        catalog.experiments(owner_id="owner")


def test_catalog_capture_is_immutable_and_defers_typed_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, catalog = make_catalog(tmp_path, monkeypatch)
    entry = catalog.register(catalog_sample(), owner_id="owner")
    record, requests = experiment_sample(entry)
    catalog.register_experiment(record, requests)
    with engine.begin() as connection:
        connection.execute(entries.update().values(payload_sha256="0" * 64))
    with _repeatable_read_transaction(engine) as connection:
        snapshot = catalog.read_catalog_rows(connection)
    with pytest.raises(TypeError):
        snapshot.entries[0]["owner_id"] = "other"  # type: ignore[index]
    with pytest.raises(ValueError, match="registration bytes differ"):
        catalog.replay_catalog_rows(snapshot, {request.job_id: request for request in requests})


@pytest.mark.parametrize("registrations", [1, 3])
def test_catalog_snapshot_queries_are_batched_across_registered_jobs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, registrations: int
) -> None:
    engine, catalog = make_catalog(tmp_path, monkeypatch)
    entry = catalog.register(catalog_sample(), owner_id="owner")
    expected = []
    for index in range(registrations):
        record, requests = experiment_sample(entry, key=f"batch-experiment-{index}")
        catalog.register_experiment(record, requests)
        expected.append(record)
    selects = 0

    def counted(_connection, _cursor, statement, _parameters, _context, _many):  # type: ignore[no-untyped-def]
        nonlocal selects
        if statement.lstrip().upper().startswith("SELECT"):
            selects += 1

    sa.event.listen(engine, "before_cursor_execute", counted)
    try:
        actual = catalog.experiments(owner_id="owner")
    finally:
        sa.event.remove(engine, "before_cursor_execute", counted)
    assert actual == tuple(sorted(expected, key=lambda record: record.experiment_id))
    # One page of 12 or 36 jobs must not issue a SELECT chain per linked job.
    assert selects <= 20


def test_postgres_catalog_registration_concurrent_and_atomic(postgres_engine: Engine) -> None:
    owner = "test-research-" + uuid4().hex
    catalog = SqlResearchCatalog(
        postgres_engine,
        codec=personal_codec,
        workflow=SqlResearchWorkflow(postgres_engine, codec=personal_codec),
    )
    entry = catalog.register(catalog_sample(owner), owner_id=owner)
    record, requests = experiment_sample(entry, key=owner, owner=owner)
    conflict, conflicting_requests = experiment_sample(entry, key=owner + "-conflict", owner=owner)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = tuple(
                pool.map(lambda _: catalog.register_experiment(record, requests), range(2))
            )
        assert results == (record, record)
        assert catalog.experiment(record.experiment_id, owner_id=owner) == record
        catalog.workflow.launch(replace(conflicting_requests[-1], trial_id="preexisting-conflict"))
        with pytest.raises(ResearchJobConflict):
            catalog.register_experiment(conflict, conflicting_requests)
        with postgres_engine.connect() as connection:
            assert (
                connection.scalar(
                    sa.select(sa.func.count()).select_from(jobs).where(jobs.c.owner_id == owner)
                )
                == 13
            )
            assert (
                connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(experiments)
                    .where(experiments.c.owner_id == owner)
                )
                == 1
            )
    finally:
        with postgres_engine.begin() as connection:
            connection.execute(links.delete().where(links.c.experiment_id == record.experiment_id))
            connection.execute(experiments.delete().where(experiments.c.owner_id == owner))
            for table in reversed(RESEARCH_TABLES_V2[1:]):
                connection.execute(
                    table.delete().where(table.c.job_id.in_((*record.job_ids, *conflict.job_ids)))
                )
            connection.execute(
                RESEARCH_TABLES_V2[0]
                .delete()
                .where(
                    RESEARCH_TABLES_V2[0].c.object_sha256.in_(
                        tuple(r.inputs.object_sha256 for r in (*requests, *conflicting_requests))
                    )
                )
            )
            connection.execute(entries.delete().where(entries.c.owner_id == owner))


def test_catalog_read_uses_one_snapshot_during_concurrent_job_transition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, catalog = make_catalog(tmp_path, monkeypatch)
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA journal_mode=WAL")
    entry = catalog.register(catalog_sample(), owner_id="owner")
    request = launch_sample(entry)
    catalog.launch(
        request, catalog_id=entry.catalog_id, cost_scenario_id="base_1x", request_json="{}"
    )
    advanced = False

    def advance_after_head(_connection, _cursor, statement, _parameters, _context, _executemany):  # type: ignore[no-untyped-def]
        nonlocal advanced
        if not advanced and "FROM research_jobs_v2" in statement:
            advanced = True
            with ThreadPoolExecutor(max_workers=1) as pool:
                assert (
                    pool.submit(
                        catalog.workflow.claim_next,
                        worker_id="worker",
                        worker_instance_id="reader-race",
                    ).result(timeout=5)
                    is not None
                )

    sa.event.listen(engine, "before_cursor_execute", advance_after_head)
    try:
        assert (
            catalog.existing_launch(
                owner_id="owner", key=request.idempotency_key, request_json="{}"
            )
            == request.job_id
        )
    finally:
        sa.event.remove(engine, "before_cursor_execute", advance_after_head)
    assert advanced and catalog.workflow.get(request.job_id).status == "running"


def test_experiment_sql_accepts_refreshed_source_declaration_but_not_access_downgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, catalog = make_catalog(tmp_path, monkeypatch)
    entry = catalog.register(catalog_sample(), owner_id="owner")
    # SQL only checks declared links; byte-level current-build/source validation
    # belongs to the application resolver and is deliberately not claimed here.
    refreshed = replace(
        entry,
        source_inputs=ObjectRef("b" * 64, 20),
        source_spec_sha256="c" * 64,
        prior_access=replace(entry.prior_access, description="refreshed known-access declaration"),
    )
    record, requests = experiment_sample(refreshed)
    record = replace(record, catalog_id=entry.catalog_id)
    assert catalog.register_experiment(record, requests) == record
    assert catalog.experiment(record.experiment_id, owner_id="owner") == record
    downgraded = replace(entry, prior_access=replace(entry.prior_access, status="unknown"))
    record, requests = experiment_sample(downgraded, key="downgrade-0001")
    with pytest.raises(ValueError, match="catalog source"):
        catalog.register_experiment(replace(record, catalog_id=entry.catalog_id), requests)
