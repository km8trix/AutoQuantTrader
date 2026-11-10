"""Durable-job composition over the existing bounded W2 process supervisor."""

from __future__ import annotations

import tempfile
import time
from collections.abc import Callable
from contextlib import nullcontext
from pathlib import Path

from apps.worker.personal_research import (
    _bounded_read,
    _matches_build,
    _matches_spec_build,
    _parser,
    _research_guard,
    _supervise,
    _write_record,
)
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application.personal_codec import decode_record
from packages.application.run_report import build_run_report
from packages.domain.report_contracts import ReportArtifact
from packages.domain.research_job_contracts import (
    MAX_EXECUTION_METADATA_BYTES,
    MAX_INPUT_BYTES,
    MAX_OBJECT_BYTES,
    MAX_PUBLICATION_BYTES,
    ResearchExecutionOutcome,
    ResearchExecutionRequest,
    ResearchProgress,
    ResearchPublication,
    RetainedResearchExecutionRequest,
    RunControl,
    TerminalOutcome,
)


class _ExecutionStopped(Exception):
    """Internal control signal; never stored or exposed as exception text."""


class ResearchProcessRunner:
    """Run reviewed reference code with independent lease/cancel supervision.

    The worker holds one process lock before claiming work. Direct callers can
    omit the descriptor and acquire the same lock for this invocation. The child
    inherits it and detects parent death, retaining W2's orphan recovery rules.
    """

    def __init__(
        self,
        *,
        lock_descriptor: int | None = None,
        on_shutdown: Callable[[], None] | None = None,
        artifact_root: Path | None = None,
    ) -> None:
        self._lock_descriptor = lock_descriptor
        self._on_shutdown = on_shutdown
        self._artifact_root = artifact_root

    def run_retained(
        self,
        execution: RetainedResearchExecutionRequest,
        *,
        control: Callable[[ResearchProgress], RunControl],
    ) -> ResearchExecutionOutcome:
        """Keep all financial object construction inside one supervised child.

        The small manifest is a readout of that reviewed child, not an independent
        proof. Parent transfer uses bounded chunks and shares the whole-run wall
        deadline. Local filesystem syscalls and database calls must themselves
        return; this is not a hostile-code or kernel-I/O sandbox.
        """
        if self._artifact_root is None:
            raise ValueError("retained execution requires an explicit private artifact root")
        spec = execution.request.spec
        deadline = time.monotonic() + spec.max_wall_seconds
        stopped = RunControl()
        stage = ResearchProgress("loading")
        progress_path: Path | None = None

        def poll() -> bool:
            nonlocal stopped, stage
            if stopped.stop:
                return True
            if progress_path is not None and progress_path.exists():
                observed = _bounded_read(progress_path, 64).decode("ascii")
                if observed not in ("loading", "running", "validating", "publishing"):
                    raise ValueError("invalid child progress observation")
                if observed == "loading":
                    stage = ResearchProgress("loading")
                elif observed == "running":
                    stage = ResearchProgress("running")
                elif observed == "validating":
                    stage = ResearchProgress("validating")
                else:
                    stage = ResearchProgress("publishing")
            try:
                observed_control = control(stage)
                if not stopped.stop:  # A signal may have latched shutdown during the callback.
                    stopped = observed_control
            except Exception:
                stopped = RunControl(True, "lease_lost")
            if not stopped.stop and time.monotonic() >= deadline:
                stopped = RunControl(True, "resource_limit")
            return stopped.stop

        def checkpoint() -> None:
            if poll():
                raise _ExecutionStopped

        def shutdown() -> None:
            nonlocal stopped
            stopped = RunControl(True, "shutdown")
            if self._on_shutdown is not None:
                self._on_shutdown()

        def stopped_result() -> ResearchExecutionOutcome:
            outcome: TerminalOutcome = "abandoned"
            if stopped.reason_code == "cancel_requested":
                outcome = "cancelled"
            elif stopped.reason_code == "resource_limit":
                outcome = "failed"
            return ResearchExecutionOutcome(outcome, reason_code=stopped.reason_code)

        try:
            checkpoint()
            if not _matches_spec_build(spec):
                return ResearchExecutionOutcome("failed", reason_code="input-or-build-mismatch")
            guard = _research_guard() if self._lock_descriptor is None else None
            with guard if guard is not None else nullcontext():
                descriptor = guard.fileno() if guard is not None else self._lock_descriptor
                with tempfile.TemporaryDirectory(prefix="autoquant-durable-run-") as directory:
                    root = Path(directory)
                    request_path, output, manifest = (
                        root / "request.json",
                        root / "report.json",
                        root / "publication.json",
                    )
                    progress_path = root / "progress"
                    _write_record(request_path, execution, MAX_EXECUTION_METADATA_BYTES)
                    checkpoint()
                    args = _parser().parse_args(
                        [
                            "--_request",
                            str(request_path),
                            "--_artifact-root",
                            str(self._artifact_root),
                            "--_publication",
                            str(manifest),
                            "--_progress",
                            str(progress_path),
                            "--_attempt-id",
                            execution.claim.attempt_id,
                            "--output",
                            str(output),
                            "--max-events",
                            str(spec.max_events),
                            "--max-seconds",
                            str(spec.max_wall_seconds),
                            "--max-memory-mib",
                            str(spec.max_memory_bytes // (1024 * 1024)),
                            "--max-output-mib",
                            str(spec.max_output_bytes // (1024 * 1024)),
                        ]
                    )
                    _supervise(
                        args,
                        lock_descriptor=descriptor,
                        control=poll,
                        on_signal=shutdown,
                        emit_status=False,
                    )
                    checkpoint()
                    if not output.is_file():
                        return ResearchExecutionOutcome(
                            "failed", reason_code="bounded-process-failed"
                        )
                    publication = decode_record(
                        _bounded_read(manifest, MAX_PUBLICATION_BYTES), ResearchPublication
                    )
                    if (
                        publication.job_id != execution.request.job_id
                        or publication.run_id != execution.request.run_id
                        or publication.attempt_id != execution.claim.attempt_id
                        or publication.object.byte_count > spec.max_output_bytes
                        or not _matches_spec_build(spec)
                    ):
                        return ResearchExecutionOutcome(
                            "failed", reason_code="report-binding-mismatch"
                        )
                    checkpoint()
                    store = LocalResearchArtifactStore(self._artifact_root)
                    store.install_file(
                        output,
                        publication.object,
                        max_bytes=spec.max_output_bytes,
                        checkpoint=checkpoint,
                    )
                    checkpoint()
                    return ResearchExecutionOutcome(publication.outcome, publication=publication)
        except _ExecutionStopped:
            return stopped_result()

    def run(
        self,
        execution: ResearchExecutionRequest,
        *,
        control: Callable[[ResearchProgress], RunControl],
    ) -> ResearchExecutionOutcome:
        """Compatibility path for explicit resolved-input test ports, not the durable CLI."""
        request, inputs = execution.request, execution.inputs
        if inputs.spec != request.spec or not _matches_build(inputs):
            return ResearchExecutionOutcome("failed", reason_code="input-or-build-mismatch")
        stopped = RunControl()

        def poll() -> bool:
            nonlocal stopped
            if stopped.stop:
                return True
            try:
                observed_control = control(ResearchProgress("running"))
                if not stopped.stop:
                    stopped = observed_control
            except Exception:
                stopped = RunControl(True, "lease_lost")
            return stopped.stop

        def shutdown() -> None:
            nonlocal stopped
            stopped = RunControl(True, "shutdown")
            if self._on_shutdown is not None:
                self._on_shutdown()

        guard = _research_guard() if self._lock_descriptor is None else None
        with guard if guard is not None else nullcontext():
            descriptor = guard.fileno() if guard is not None else self._lock_descriptor
            with tempfile.TemporaryDirectory(prefix="autoquant-durable-run-") as directory:
                root = Path(directory)
                inputs_path, conventions_path, output = (
                    root / "inputs.json",
                    root / "conventions.json",
                    root / "report.json",
                )
                _write_record(inputs_path, inputs, MAX_INPUT_BYTES)
                _write_record(conventions_path, request.conventions, 1024 * 1024)
                spec = inputs.spec
                args = _parser().parse_args(
                    [
                        "--_inputs",
                        str(inputs_path),
                        "--_conventions",
                        str(conventions_path),
                        "--_attempt-id",
                        execution.claim.attempt_id,
                        "--output",
                        str(output),
                        "--max-events",
                        str(spec.max_events),
                        "--max-seconds",
                        str(spec.max_wall_seconds),
                        "--max-memory-mib",
                        str(spec.max_memory_bytes // (1024 * 1024)),
                        "--max-output-mib",
                        str(spec.max_output_bytes // (1024 * 1024)),
                    ]
                )
                if not poll():
                    _supervise(
                        args,
                        lock_descriptor=descriptor,
                        control=poll,
                        on_signal=shutdown,
                        emit_status=False,
                    )
                if stopped.stop:
                    outcome: TerminalOutcome = (
                        "cancelled" if stopped.reason_code == "cancel_requested" else "abandoned"
                    )
                    return ResearchExecutionOutcome(outcome, reason_code=stopped.reason_code)
                if not output.is_file():
                    return ResearchExecutionOutcome("failed", reason_code="bounded-process-failed")
                artifact = decode_record(_bounded_read(output, MAX_OBJECT_BYTES), ReportArtifact)
                if (
                    artifact.attempt_id != execution.claim.attempt_id
                    or artifact.report.source.spec != spec
                    or build_run_report(artifact.report.source, request.conventions)
                    != artifact.report
                    or not _matches_build(inputs)
                ):
                    return ResearchExecutionOutcome("failed", reason_code="report-binding-mismatch")
                if poll():
                    outcome = (
                        "cancelled" if stopped.reason_code == "cancel_requested" else "abandoned"
                    )
                    return ResearchExecutionOutcome(outcome, reason_code=stopped.reason_code)
                return ResearchExecutionOutcome(artifact.report.status, artifact)
