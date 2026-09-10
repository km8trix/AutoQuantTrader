"""Actual supervised retained-input processes, without activating a database."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from itertools import pairwise
from pathlib import Path
from types import SimpleNamespace

import pytest

from apps.worker.research_runner import ResearchProcessRunner
from packages.adapters.personal_build import current_build_pins
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application.personal_codec import decode_record, encode_record
from packages.application.personal_inputs import synthetic_engine_inputs
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.engine_contracts import EngineInputs
from packages.domain.personal_contracts import VersionPin
from packages.domain.report_contracts import ReportArtifact, ReportConventions
from packages.domain.research_job_contracts import (
    MAX_INPUT_BYTES,
    ResearchProgress,
    ResearchRunRequest,
    RetainedResearchExecutionRequest,
    RunControl,
)
from packages.domain.research_job_v2 import claim_research_job, queue_research_job


def _execution(
    root: Path, *, memory_mib: int = 512, seconds: int = 20, key: str = "request-0001"
) -> RetainedResearchExecutionRequest:
    inputs = synthetic_engine_inputs(
        fixture="flat",
        pins=current_build_pins(),
        session_count=8,
        warmup_count=3,
        configuration=ReferenceConfiguration(lookback=3),
    )
    inputs = replace(
        inputs,
        spec=replace(
            inputs.spec,
            max_cpu_cores=1,
            max_memory_bytes=memory_mib * 1024**2,
            max_wall_seconds=seconds,
            max_output_bytes=8 * 1024**2,
        ),
    )
    store = LocalResearchArtifactStore(root)
    request = ResearchRunRequest(
        inputs.spec,
        ReportConventions(),
        store.put(encode_record(inputs), max_bytes=MAX_INPUT_BYTES),
        "owner",
        key,
        "trial-001",
        settlement_calendar=store.put(
            encode_record(inputs.spec.execution_policy.settlement_calendar)
        ),
    )
    now = datetime.now(UTC)
    state = claim_research_job(
        queue_research_job(request, now),
        worker_id="worker",
        worker_instance_id="unit-process",
        now=now,
    )
    assert state.claim is not None
    return RetainedResearchExecutionRequest(request, state.claim)


def test_actual_retained_child_resolves_and_validates_without_parent_financial_graph(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from apps.worker import research_runner
    from packages.application import research_catalog

    root = tmp_path / "objects"
    execution = _execution(root)
    original_decode = research_runner.decode_record

    def small_only(payload, expected_type):
        assert expected_type not in (ReportArtifact, EngineInputs)
        assert len(payload) <= 16 * 1024
        return original_decode(payload, expected_type)

    def no_parent_resolution(*args, **kwargs):
        raise AssertionError("financial input resolution reached the parent")

    monkeypatch.setattr(research_runner, "decode_record", small_only)
    monkeypatch.setattr(
        research_catalog.StoredResearchInputResolver, "resolve", no_parent_resolution
    )
    observations = []

    def control(progress: ResearchProgress) -> RunControl:
        observations.append(progress.stage)
        return RunControl()

    outcome = ResearchProcessRunner(artifact_root=root).run_retained(execution, control=control)
    assert outcome.outcome == "completed" and outcome.artifact is None
    publication = outcome.publication
    assert publication is not None
    assert publication.job_id == execution.request.job_id
    assert publication.run_id == execution.request.run_id
    assert publication.attempt_id == execution.claim.attempt_id
    artifact = decode_record(
        LocalResearchArtifactStore(root).read(publication.object), ReportArtifact
    )
    assert artifact.report.source.final_snapshot.nav == Decimal("9998.56")
    assert artifact.semantic_sha256 == publication.artifact_sha256
    assert artifact.report.semantic_sha256 == publication.report_sha256
    assert artifact.report.source.semantic_sha256 == publication.result_sha256
    assert "loading" in observations and "publishing" in observations


def test_two_actual_jobs_with_descending_budgets_ignore_parent_lifetime_peak(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from apps.worker import personal_research

    # Simulate an earlier parent allocation larger than either child's budget.
    # Fresh subprocesses still use their own real rusage and active RSS checks.
    monkeypatch.setattr(
        personal_research.resource, "getrusage", lambda _: SimpleNamespace(ru_maxrss=5 * 1024**3)
    )
    root = tmp_path / "objects"
    runner = ResearchProcessRunner(artifact_root=root)
    for number, memory in enumerate((512, 256)):
        execution = _execution(root, memory_mib=memory, key=f"request-{number:04}")
        outcome = runner.run_retained(execution, control=lambda _: RunControl())
        assert outcome.outcome == "completed" and outcome.publication is not None


@pytest.mark.parametrize("fault", ["deadline", "cancel_requested", "lease_lost", "shutdown"])
def test_stalled_actual_child_validation_keeps_control_and_never_returns_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    from apps.worker import personal_research

    root = tmp_path / "objects"
    execution = _execution(root, seconds=3 if fault == "deadline" else 20)
    marker = tmp_path / "validation-entered"
    original_popen = subprocess.Popen
    children = []
    # Test-only process fault injection after the sole real W2 engine/report ran.
    # No test hooks or delay flags are added to the production command surface.
    code = """import sys,time
from pathlib import Path
from apps.worker import personal_research as cli
def stalled(artifact, limit):
    Path(MARKER).write_text('validation')
    while True:
        time.sleep(0.05)
cli._validated_artifact_payload = stalled
raise SystemExit(cli.main(sys.argv[1:]))
""".replace("MARKER", repr(str(marker)))

    def fault_process(command, **kwargs):
        if command[2:4] != ["-m", "apps.worker.personal_research"]:
            return original_popen(command, **kwargs)
        assert command[2:4] == ["-m", "apps.worker.personal_research"]
        child = original_popen([*command[:2], "-c", code, *command[4:]], **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(personal_research.subprocess, "Popen", fault_process)
    observed = []
    shutdown = []

    def control(progress: ResearchProgress) -> RunControl:
        if marker.exists():
            observed.append((time.monotonic(), progress.stage))
            # Allow several supervised polls while validation is demonstrably stuck.
            if len(observed) >= 3:
                if fault == "cancel_requested":
                    return RunControl(True, "cancel_requested")
                if fault == "lease_lost":
                    raise RuntimeError("injected loss of heartbeat authority")
                if fault == "shutdown":
                    os.kill(os.getpid(), signal.SIGTERM)
        return RunControl()

    began = time.monotonic()
    outcome = ResearchProcessRunner(
        artifact_root=root, on_shutdown=lambda: shutdown.append(True)
    ).run_retained(execution, control=control)
    elapsed = time.monotonic() - began
    assert marker.exists() and len(observed) >= 3
    assert all(stage == "validating" for _, stage in observed)
    assert max(b[0] - a[0] for a, b in pairwise(observed)) < 2
    assert outcome.publication is None and outcome.artifact is None
    assert (
        outcome.outcome
        == {
            "deadline": "failed",
            "cancel_requested": "cancelled",
            "lease_lost": "abandoned",
            "shutdown": "abandoned",
        }[fault]
    )
    assert outcome.reason_code == ("resource_limit" if fault == "deadline" else fault)
    assert elapsed < 12 and all(child.poll() is not None for child in children)
    assert bool(shutdown) == (fault == "shutdown")
    # Only the admitted inputs/calendar exist; a late child cannot install a report.
    assert len(tuple(root.iterdir())) == 2


@pytest.mark.parametrize("fault", ["input", "calendar", "build"])
def test_retained_provenance_and_build_mismatches_never_publish(
    tmp_path: Path,
    fault: str,
) -> None:
    root = tmp_path / "objects"
    execution = _execution(root)
    if fault in ("input", "calendar"):
        reference = (
            execution.request.inputs if fault == "input" else execution.request.settlement_calendar
        )
        assert reference is not None
        (root / (reference.object_sha256 + ".json")).write_bytes(b"invalid retained record")
    else:
        pins = tuple(
            replace(pin, sha256="f" * 64) if pin.name == "source" else pin
            for pin in execution.request.spec.pins
        )
        execution = replace(
            execution,
            request=replace(execution.request, spec=replace(execution.request.spec, pins=pins)),
        )
    outcome = ResearchProcessRunner(artifact_root=root).run_retained(
        execution, control=lambda _: RunControl()
    )
    assert outcome.outcome == "failed" and outcome.publication is None


def test_retained_manifest_must_bind_the_current_attempt_before_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from apps.worker import research_runner

    root = tmp_path / "objects"
    execution = _execution(root)
    original = research_runner._supervise

    def wrong_manifest(args, **kwargs):
        status = original(args, **kwargs)
        value = json.loads(args._publication.read_bytes())
        value["value"]["fields"]["attempt_id"] = "f" * 64
        args._publication.write_bytes(
            (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )
        return status

    monkeypatch.setattr(research_runner, "_supervise", wrong_manifest)
    outcome = ResearchProcessRunner(artifact_root=root).run_retained(
        execution, control=lambda _: RunControl()
    )
    assert outcome.outcome == "failed" and outcome.reason_code == "report-binding-mismatch"
    assert outcome.publication is None and len(tuple(root.iterdir())) == 2


def test_exact_current_build_allows_additional_evaluation_pins(tmp_path: Path) -> None:
    from apps.worker.personal_research import _matches_spec_build

    execution = _execution(tmp_path / "objects")
    spec = execution.request.spec
    pins = tuple(
        sorted(
            (*spec.pins, VersionPin("evaluation_trial", "trial/1", "e" * 64)),
            key=lambda pin: pin.name,
        )
    )
    assert _matches_spec_build(replace(spec, pins=pins))
