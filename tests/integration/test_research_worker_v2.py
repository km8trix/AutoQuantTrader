from __future__ import annotations

import hashlib
import json
import select
import subprocess
import sys
from collections.abc import Callable
from dataclasses import replace
from datetime import timedelta
from decimal import Decimal
from pathlib import Path

import pytest
import sqlalchemy as sa

from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec
from packages.application.causal_engine import run_causal_engine
from packages.application.reference_strategy import ReferenceStrategy
from packages.application.research_worker_v2 import process_one_research_job
from packages.application.run_report import build_report_artifact, build_run_report
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.engine_contracts import EngineInputs
from packages.domain.research_job_contracts import (
    MAX_INPUT_BYTES,
    ResearchExecutionOutcome,
    ResearchExecutionRequest,
    ResearchProgress,
    ResearchRunRequest,
    RunControl,
)
from packages.persistence.research_schema_v2 import research_publications_v2
from tests.helpers.personal_report_oracle import verify_personal_report
from tests.integration.test_research_workflow_v2 import make_workflow
from tests.unit.test_research_job_v2 import NOW, sample_inputs, sample_request


def test_engine_resource_diagnostic_has_explicit_incomplete_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = sample_inputs()
    inputs = replace(source, spec=replace(source.spec, max_events=1))
    store = LocalResearchArtifactStore(tmp_path / "objects")
    reference = store.put(personal_codec.encode_record(inputs), max_bytes=MAX_INPUT_BYTES)
    request = replace(sample_request(), spec=inputs.spec, inputs=reference)
    _, workflow, _ = make_workflow(tmp_path, monkeypatch)
    workflow.launch(request)
    final = process_one_research_job(
        workflow,
        worker_id="worker",
        worker_instance_id="incomplete",
        resolver=Resolver(inputs),
        runner=InlineRunner(),
        artifacts=store,
        codec=personal_codec,
    )
    assert final is not None and final.status == "incomplete"
    assert final.publication is not None and final.publication.outcome == "incomplete"


class Resolver:
    def __init__(self, inputs: EngineInputs | None = None) -> None:
        self.inputs = inputs or sample_inputs()

    def resolve(self, request: ResearchRunRequest) -> EngineInputs:
        return self.inputs


class InlineRunner:
    def __init__(
        self, on_control: Callable[[], None] | None = None, wrong_attempt: bool = False
    ) -> None:
        self.on_control, self.wrong_attempt = on_control, wrong_attempt

    def run(
        self,
        execution: ResearchExecutionRequest,
        *,
        control: Callable[[ResearchProgress], RunControl],
    ) -> ResearchExecutionOutcome:
        if self.on_control is not None:
            self.on_control()
        stopped = control(ResearchProgress("running"))
        if stopped.stop:
            return ResearchExecutionOutcome("abandoned", reason_code="shutdown")
        result = run_causal_engine(
            execution.inputs, accounting=PersonalAccounting(), strategy=ReferenceStrategy()
        )
        report = build_run_report(result, execution.request.conventions)
        artifact = build_report_artifact(
            report,
            attempt_id="wrong-attempt" if self.wrong_attempt else execution.claim.attempt_id,
            generated_at=NOW,
        )
        return ResearchExecutionOutcome(report.status, artifact)


def store_inputs(tmp_path: Path) -> LocalResearchArtifactStore:
    store = LocalResearchArtifactStore(tmp_path / "objects")
    assert (
        store.put(personal_codec.encode_record(sample_inputs()), max_bytes=MAX_INPUT_BYTES)
        == sample_request().inputs
    )
    return store


def test_actual_small_w2_economics_publish_and_reopen_durably(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, workflow, _ = make_workflow(tmp_path, monkeypatch)
    store = store_inputs(tmp_path)
    request = sample_request()
    workflow.launch(request)
    final = process_one_research_job(
        workflow,
        worker_id="worker",
        worker_instance_id="one",
        resolver=Resolver(),
        runner=InlineRunner(),
        artifacts=store,
        codec=personal_codec,
    )
    assert final is not None and final.status == "completed" and final.publication is not None
    from packages.domain.report_contracts import ReportArtifact

    artifact = personal_codec.decode_record(store.read(final.publication.object), ReportArtifact)
    assert artifact.report.source.final_snapshot.nav == Decimal("9998.56")
    verify_personal_report(artifact.report.source, artifact.report)
    assert workflow.get(request.job_id) == final
    assert (
        process_one_research_job(
            workflow,
            worker_id="worker",
            worker_instance_id="two",
            resolver=Resolver(),
            runner=InlineRunner(),
            artifacts=store,
            codec=personal_codec,
        )
        is None
    )


@pytest.mark.parametrize("fault", ["wrong-attempt", "wrong-input", "corrupt-object"])
def test_mismatched_worker_result_and_input_never_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    engine, workflow, _ = make_workflow(tmp_path, monkeypatch)
    store = store_inputs(tmp_path)
    request = sample_request()
    workflow.launch(request)
    inputs = sample_inputs()
    if fault == "corrupt-object":
        (tmp_path / "objects" / (request.inputs.object_sha256 + ".json")).write_bytes(b"corrupt")
    if fault == "wrong-input":
        inputs = replace(inputs, spec=replace(inputs.spec, initial_cash=Decimal("9999")))
    final = process_one_research_job(
        workflow,
        worker_id="worker",
        worker_instance_id="one",
        resolver=Resolver(inputs),
        runner=InlineRunner(wrong_attempt=fault == "wrong-attempt"),
        artifacts=store,
        codec=personal_codec,
    )
    assert (
        final is not None
        and final.status == "failed"
        and final.reason_code == "research_execution_failed"
    )
    with engine.connect() as connection:
        assert (
            connection.execute(
                sa.select(sa.func.count()).select_from(research_publications_v2)
            ).scalar_one()
            == 0
        )


@pytest.mark.parametrize("kind", ["owner", "shutdown", "lease-loss"])
def test_independent_control_stops_cancel_shutdown_and_lost_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    _, workflow, clock = make_workflow(tmp_path, monkeypatch)
    store = store_inputs(tmp_path)
    request = sample_request()
    workflow.launch(request)
    shutdown = [False]

    def action() -> None:
        if kind == "owner":
            workflow.request_cancel(request.job_id, owner_id="owner", idempotency_key="cancel-0001")
        elif kind == "shutdown":
            shutdown[0] = True
        else:
            clock[0] += timedelta(seconds=60)

    final = process_one_research_job(
        workflow,
        worker_id="worker",
        worker_instance_id="one",
        resolver=Resolver(),
        runner=InlineRunner(on_control=action),
        artifacts=store,
        codec=personal_codec,
        stop_requested=lambda: shutdown[0],
    )
    assert final is not None and final.publication is None
    assert (
        final.status == {"owner": "cancelled", "shutdown": "queued", "lease-loss": "running"}[kind]
    )
    if kind == "shutdown":
        assert final.attempts[-1].outcome == "abandoned"
    if kind == "lease-loss":
        recovered = workflow.claim_next(worker_id="worker", worker_instance_id="two")
        assert recovered is not None and recovered.claim.fence == 2


def test_lost_ack_after_terminal_commit_returns_one_durable_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, workflow, _ = make_workflow(tmp_path, monkeypatch)
    store = store_inputs(tmp_path)
    workflow.launch(sample_request())
    publish = workflow.publish

    def lost_ack(claim, *, publication):  # type: ignore[no-untyped-def]
        publish(claim, publication=publication)
        raise ConnectionError("injected lost terminal acknowledgement")

    monkeypatch.setattr(workflow, "publish", lost_ack)
    final = process_one_research_job(
        workflow,
        worker_id="worker",
        worker_instance_id="one",
        resolver=Resolver(),
        runner=InlineRunner(),
        artifacts=store,
        codec=personal_codec,
    )
    assert final is not None and final.status == "completed"
    with engine.connect() as connection:
        assert (
            connection.execute(
                sa.select(sa.func.count()).select_from(research_publications_v2)
            ).scalar_one()
            == 1
        )


def test_actual_bounded_process_uses_durable_attempt_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apps.worker.research_runner import ResearchProcessRunner
    from packages.adapters.personal_build import current_build_pins
    from packages.domain.report_contracts import ReportArtifact

    _, workflow, _ = make_workflow(tmp_path, monkeypatch)
    source = sample_inputs()
    inputs = replace(source, spec=replace(source.spec, pins=current_build_pins(), max_cpu_cores=1))
    store = LocalResearchArtifactStore(tmp_path / "objects")
    reference = store.put(personal_codec.encode_record(inputs), max_bytes=MAX_INPUT_BYTES)
    request = replace(sample_request(), spec=inputs.spec, inputs=reference)
    workflow.launch(request)
    final = process_one_research_job(
        workflow,
        worker_id="worker",
        worker_instance_id="actual-process",
        resolver=Resolver(inputs),
        runner=ResearchProcessRunner(),
        artifacts=store,
        codec=personal_codec,
    )
    assert final is not None and final.status == "completed", final
    assert final.publication is not None
    artifact = personal_codec.decode_record(store.read(final.publication.object), ReportArtifact)
    assert artifact.attempt_id == final.attempts[0].attempt_id
    assert artifact.report.run_id == request.run_id
    verify_personal_report(artifact.report.source, artifact.report)


def test_fast_supervisor_polling_is_bounded_to_ten_second_heartbeats(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, workflow, clock = make_workflow(tmp_path, monkeypatch)
    store = store_inputs(tmp_path)
    request = sample_request()
    workflow.launch(request)
    monotonic = [0.0]
    monkeypatch.setattr(
        "packages.application.research_worker_v2.time.monotonic", lambda: monotonic[0]
    )

    class PollingRunner(InlineRunner):
        def run(
            self,
            execution: ResearchExecutionRequest,
            *,
            control: Callable[[ResearchProgress], RunControl],
        ) -> ResearchExecutionOutcome:
            for _ in range(5000):
                assert not control(ResearchProgress("running")).stop
            monotonic[0] = 9.999
            assert not control(ResearchProgress("running")).stop
            monotonic[0] = 10.0
            clock[0] += timedelta(seconds=10)
            assert not control(ResearchProgress("running")).stop
            return super().run(execution, control=control)

    final = process_one_research_job(
        workflow,
        worker_id="worker",
        worker_instance_id="one",
        resolver=Resolver(),
        runner=PollingRunner(),
        artifacts=store,
        codec=personal_codec,
    )
    assert final is not None and final.status == "completed"
    with workflow._engine.connect() as connection:
        state = workflow._load(connection, request.job_id)
    assert sum(event.kind == "renewed" for event in state.events) == 5


def test_imported_archive_bytes_link_to_generic_worker_without_fixture_catalog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from packages.application.personal_inputs import research_engine_inputs
    from packages.application.research_dataset import research_dataset_to_json_bytes
    from packages.domain.accounting_contracts import SettlementCalendar
    from packages.domain.engine_contracts import EvaluationSpec
    from packages.domain.report_contracts import ReportArtifact
    from tests.unit.test_personal_research_dataset import _inputs, _load

    source_dir = tmp_path / "source"
    source_dir.mkdir()
    paths, declaration, exchange_calendar = _inputs(source_dir)
    # These are labelled generated Tiingo-format rows, not invented provider captures.
    for symbol, path in paths.items():
        rows = json.loads(path.read_bytes())
        for row in rows:
            row["divCash"] = 0
        path.write_text(json.dumps(rows))
        item = next(item for item in declaration["instruments"] if item["symbol"] == symbol)
        item["source_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    dataset = _load(paths, declaration, exchange_calendar)
    sessions = tuple(item.session_label for item in dataset.manifest.calendar.sessions)
    settlement = SettlementCalendar("synthetic-settlement", "test-v1", sessions)
    inputs = research_engine_inputs(
        dataset,
        configuration=sample_inputs().spec.strategy_configuration,
        evaluation=EvaluationSpec(
            "archive-fold", sessions[:1], sessions[1:-1], "synthetic-import-test"
        ),
        settlement_calendar=settlement,
        pins=sample_inputs().spec.pins,
    )
    inputs = replace(
        inputs, spec=replace(inputs.spec, max_output_bytes=64 * 1024 * 1024, max_cpu_cores=1)
    )
    store = LocalResearchArtifactStore(tmp_path / "objects")
    request = replace(
        sample_request(),
        spec=inputs.spec,
        inputs=store.put(personal_codec.encode_record(inputs), max_bytes=MAX_INPUT_BYTES),
        dataset_archive=store.put(
            research_dataset_to_json_bytes(dataset),
            codec_version="personal-research-dataset-v1",
            max_bytes=MAX_INPUT_BYTES,
        ),
        settlement_calendar=store.put(
            personal_codec.encode_record(settlement), max_bytes=MAX_INPUT_BYTES
        ),
    )
    _, workflow, _ = make_workflow(tmp_path, monkeypatch)
    workflow.launch(request)
    final = process_one_research_job(
        workflow,
        worker_id="worker",
        worker_instance_id="archive-process",
        resolver=Resolver(inputs),
        runner=InlineRunner(),
        artifacts=store,
        codec=personal_codec,
    )
    assert final is not None and final.publication is not None and final.status == "completed"
    artifact = personal_codec.decode_record(store.read(final.publication.object), ReportArtifact)
    assert artifact.report.source.spec.dataset_id == dataset.dataset_id
    assert artifact.report.source.spec.data_class == dataset.manifest.data_class
    assert all(
        exclusion in artifact.report.limitations for exclusion in dataset.manifest.exclusions
    )
    verify_personal_report(artifact.report.source, artifact.report)


def test_killed_claimant_restarts_with_fenced_single_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apps.worker.research_runner import ResearchProcessRunner
    from packages.adapters.personal_build import current_build_pins

    engine, workflow, clock = make_workflow(tmp_path, monkeypatch)
    inputs = replace(
        sample_inputs(),
        spec=replace(sample_inputs().spec, pins=current_build_pins(), max_cpu_cores=1),
    )
    store = LocalResearchArtifactStore(tmp_path / "objects")
    request = replace(
        sample_request(),
        spec=inputs.spec,
        inputs=store.put(personal_codec.encode_record(inputs), max_bytes=MAX_INPUT_BYTES),
    )
    workflow.launch(request)
    # Stop an owned worker after its durable claim and before execution. Recovery
    # then uses the actual bounded W2 process, not a synthetic terminal result.
    script = """from datetime import datetime
import sys, time
import sqlalchemy as sa
from packages.application import personal_codec
from packages.persistence import research_workflow_v2
research_workflow_v2.database_time = lambda connection: datetime.fromisoformat(sys.argv[2])
engine = sa.create_engine(sys.argv[1])
workflow = research_workflow_v2.SqlResearchWorkflow(engine, codec=personal_codec)
claimed = workflow.claim_next(worker_id='worker', worker_instance_id='killed-instance')
assert claimed is not None
print('claimed', flush=True)
while True:
    time.sleep(1)
"""
    environment = {
        "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin",
        "PYTHONPATH": str(Path(__file__).resolve().parents[2]),
        "PYTHONDONTWRITEBYTECODE": "1",
        "TZ": "UTC",
    }
    with subprocess.Popen(
        [sys.executable, "-B", "-c", script, str(engine.url), NOW.isoformat()],
        cwd=tmp_path,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ) as child:
        try:
            assert child.stdout is not None
            assert select.select([child.stdout], [], [], 10)[0], (
                "claiming process did not acknowledge"
            )
            assert child.stdout.readline() == b"claimed\n"
            child.kill()
            child.wait(timeout=5)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
    assert workflow.get(request.job_id).status == "running"
    clock[0] += timedelta(seconds=60)
    final = process_one_research_job(
        workflow,
        worker_id="worker",
        worker_instance_id="restarted-instance",
        resolver=Resolver(inputs),
        runner=ResearchProcessRunner(),
        artifacts=store,
        codec=personal_codec,
    )
    assert final is not None and final.status == "completed"
    assert tuple(item.outcome for item in final.attempts) == ("abandoned", "completed")
    assert (
        final.publication is not None
        and final.publication.attempt_id == final.attempts[1].attempt_id
    )
    assert workflow.claim_next(worker_id="worker", worker_instance_id="later-instance") is None
    with engine.connect() as connection:
        assert (
            connection.execute(
                sa.select(sa.func.count()).select_from(research_publications_v2)
            ).scalar_one()
            == 1
        )
