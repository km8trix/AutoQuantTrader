"""Exercise an installed durable research wheel using a disposable offline fixture.

Only the explicitly selected interpreter imports application code. Every child
runs outside the source checkout with an empty, allowlisted environment and
isolated Python imports. Output contains counts, hashes and SQLite policy metadata.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from contextlib import ExitStack, suppress
from pathlib import Path
from types import FrameType

_MAX_STDOUT = 16 * 1024
_OWNER = "installed-wheel-acceptance"
_LOCK = Path(f"/tmp/autoquant-personal-research-{os.getuid()}/instance.lock")

# This program is passed to the selected installed interpreter, never imported
# by the source-side harness. Application imports are restricted to wheel files.
_INSTALLED = r"""
import hashlib
import importlib.metadata
import json
import sys
import sysconfig
from pathlib import Path


class CheckFailure(Exception):
    pass


def check(condition, code):
    if not condition:
        raise CheckFailure(code)


distribution = importlib.metadata.distribution("autoquant-trader")
root = Path(distribution.locate_file("")).resolve()
site = {Path(sysconfig.get_path(name)).resolve() for name in ("purelib", "platlib")}
check(root in site, "distribution-not-installed")
direct = json.loads(distribution.read_text("direct_url.json") or "{}")
check(not direct.get("dir_info", {}).get("editable", False), "editable-install-rejected")
files = {str(path): path for path in distribution.files or ()}
check(bool(files), "wheel-file-inventory-missing")
record = distribution.read_text("RECORD")
check(record is not None, "wheel-record-missing")
record_sha256 = hashlib.sha256(record.encode()).hexdigest()


def check_origins():
    for name, module in tuple(sys.modules.items()):
        if name.split(".")[0] not in {"apps", "packages", "migrations"}:
            continue
        filename = getattr(module, "__file__", None)
        check(filename is not None, "unowned-package-origin")
        path = Path(filename)
        check(not path.is_symlink(), "symlinked-package-origin")
        path = path.resolve()
        check(path.is_relative_to(root), "source-import-rejected")
        relative = path.relative_to(root).as_posix()
        check(relative in files, "module-not-in-wheel-record")
        expected = files[relative].hash
        check(expected is not None and expected.mode == "sha256", "module-hash-missing")
        import base64

        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(path.read_bytes()).digest())
            .rstrip(b"=")
            .decode()
        )
        check(digest == expected.value, "installed-module-bytes-changed")


entries = [
    entry
    for entry in distribution.entry_points
    if entry.group == "console_scripts" and entry.name == "autoquant-research-jobs"
]
check(
    len(entries) == 1 and entries[0].value == "apps.worker.research_jobs:main",
    "jobs-entrypoint-missing",
)
"""

_CLI = r"""
main = entries[0].load()
check_origins()
code = main(sys.argv[1:])
check(code == 0, "jobs-command-failed")
check_origins()
"""

_SQLITE_SETUP = r"""
from packages.persistence.database import create_database_engine

check_origins()
# Verify init retained WAL before the opt-in connection can apply its policy.
engine = create_database_engine(sys.argv[1])
with engine.connect() as connection:
    check(connection.exec_driver_sql("PRAGMA journal_mode").scalar_one() == "wal", "init-not-wal")
engine.dispose()
engine = create_database_engine(sys.argv[1], research_sqlite_wal=True)
with engine.connect() as connection:
    runtime = connection.exec_driver_sql("SELECT sqlite_version()").scalar_one()
    version = tuple(int(part) for part in runtime.split("."))
    admitted = len(version) == 3 and (
        version >= (3, 51, 3)
        or version[:2] == (3, 50) and version[2] >= 7
        or version[:2] == (3, 44) and version[2] >= 6
    )
    journal = connection.exec_driver_sql("PRAGMA journal_mode").scalar_one()
    synchronous = connection.exec_driver_sql("PRAGMA synchronous").scalar_one()
    timeout = connection.exec_driver_sql("PRAGMA busy_timeout").scalar_one()
    checkpoint = connection.exec_driver_sql("PRAGMA wal_autocheckpoint").scalar_one()
check(admitted, "sqlite-runtime-not-admitted")
check(journal == "wal" and synchronous == 2, "sqlite-durability-policy-differs")
check(timeout == 5000 and checkpoint == 1000, "sqlite-defaults-differ")
sqlite_checks = {
    "sqlite_runtime": runtime,
    "sqlite_runtime_admitted": admitted,
    "sqlite_journal_mode": journal,
    "sqlite_synchronous": synchronous,
    "sqlite_busy_timeout_ms": timeout,
    "sqlite_wal_autocheckpoint_pages": checkpoint,
}
"""

_SQLITE_PROBE = (
    _SQLITE_SETUP
    + r"""
engine.dispose()
check_origins()
print(json.dumps(sqlite_checks, sort_keys=True))
"""
)

_SERVICE = (
    _SQLITE_SETUP
    + r"""
import sqlalchemy as sa
from decimal import Context, Decimal, ROUND_FLOOR, localcontext
from apps.api.personal_research_contracts import PersonalConfiguration, PersonalRunRequest
from apps.api.personal_research_service import PersonalResearchService
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec
from packages.domain.report_contracts import ReportArtifact
from packages.domain.research_job_contracts import MAX_INPUT_BYTES, MAX_OBJECT_BYTES
from packages.persistence.database import verify_operational_schema
from packages.persistence.research_catalog import SqlResearchCatalog
from packages.persistence.research_schema_v2 import research_jobs_v2, research_publications_v2
from packages.persistence.research_workflow_v2 import SqlResearchWorkflow

check_origins()
artifacts = LocalResearchArtifactStore(Path(sys.argv[2]))
owner = sys.argv[3]
workflow = SqlResearchWorkflow(engine, codec=personal_codec)
catalog = SqlResearchCatalog(engine, codec=personal_codec, workflow=workflow)
service = PersonalResearchService(workflow, catalog, artifacts, owner_id=owner)
verify_operational_schema(engine, require_phase_zero_facts=False, research_codec=personal_codec)
datasets = catalog.datasets(owner_id=owner)
check(len(datasets) == 1, "catalog-count-differs")
entry = datasets[0]
request = PersonalRunRequest(
    dataset_id=entry.catalog_id,
    dataset_manifest_sha256=entry.dataset_sha256,
    strategy_id="buy_hold",
    strategy_version="personal-daily-reference/1",
    configuration=PersonalConfiguration(
        kind="buy_hold", lookback=3, allocation="0.25", rebalance_sessions=None
    ),
    initial_cash="10000",
    warmup_sessions=3,
    scored_start=None,
    scored_end=None,
    cost_scenario_id="base_1x",
)
view = service.launch(request, owner_id=owner, key="installed-wheel-one-job")
job = workflow.get(view.job_id)
retained = workflow.get_request(view.job_id)
check(retained.spec.data_class.value == "synthetic_fixture", "fixture-label-differs")
for reference in (entry.source_inputs, entry.settlement_calendar, retained.inputs):
    artifacts.read(reference, max_bytes=MAX_INPUT_BYTES)
check(retained.spec.run_id == view.run_id and retained.run_id == job.run_id, "run-binding-differs")
check(
    len(retained.spec.evaluation.warmup_sessions) == 3
    and len(retained.spec.evaluation.scored_sessions) == 9,
    "scored-scope-differs",
)
check(len(retained.spec.calendar.sessions) == 13, "calendar-horizon-differs")
with engine.connect() as connection:
    job_count = connection.scalar(sa.select(sa.func.count()).select_from(research_jobs_v2))
    publication_count = connection.scalar(
        sa.select(sa.func.count()).select_from(research_publications_v2)
    )
check(job_count == 1, "duplicate-job")
result = {
    "job_id": job.job_id,
    "request_sha256": retained.semantic_sha256,
    "run_spec_sha256": retained.spec.semantic_sha256,
    "job_count": job_count,
    "publication_count": publication_count,
    "attempt_count": len(job.attempts),
    "wheel_record_sha256": record_sha256,
} | sqlite_checks
"""
)

_PREPARE = (
    _SERVICE
    + r"""
check(
    job.status == "queued" and not job.attempts and job.publication is None,
    "initial-job-not-queued",
)
check(publication_count == 0, "premature-publication")
result["status"] = "queued"
engine.dispose()
check_origins()
print(json.dumps(result, sort_keys=True))
"""
)

_VERIFY = (
    _SERVICE
    + r"""
check(
    job.status == "completed" and len(job.attempts) == publication_count == 1,
    "terminal-history-differs",
)
check(
    job.attempts[0].outcome == "completed" and job.publication is not None, "attempt-not-completed"
)
publication = job.publication
payload = artifacts.read(publication.object, max_bytes=MAX_OBJECT_BYTES)
artifact = personal_codec.decode_record(payload, ReportArtifact)
report = artifact.report
source = report.source
check(
    artifact.attempt_id == publication.attempt_id == job.attempts[0].attempt_id,
    "attempt-binding-differs",
)
check(report.status == source.status == "completed", "report-incomplete")
check(source.spec == retained.spec and report.run_id == retained.run_id, "report-spec-differs")
check(
    source.semantic_sha256 == report.result_sha256 == publication.result_sha256,
    "result-digest-differs",
)
check(report.semantic_sha256 == publication.report_sha256, "report-digest-differs")
check(artifact.semantic_sha256 == publication.artifact_sha256, "artifact-digest-differs")
check(personal_codec.encode_record(artifact) == payload, "artifact-roundtrip-differs")
check(service.export(job.job_id) == payload, "service-export-differs")
check(len(source.executions) == 1, "execution-count-differs")
fill = source.executions[0]
# Independent literal arithmetic. No production metric, wealth, strategy or
# accounting helper participates in these expected values.
with localcontext(Context(prec=80)):
    starting, raw, allocation = Decimal("10000"), Decimal("100"), Decimal("0.25")
    quantity = (
        starting * allocation / (raw * Decimal("1.01") + Decimal("0.01"))
    ).to_integral_value(rounding=ROUND_FLOOR)
    fill_price = raw * (Decimal(1) + Decimal(5) / Decimal(10000))
    fee = quantity * Decimal("0.01")
    cash = starting - quantity * fill_price - fee
    nav = cash + quantity * raw
    check(
        quantity == 24 and nav == Decimal("9998.56") and cash == Decimal("7598.56"),
        "literal-oracle-differs",
    )
    check(
        fill.side.value == "buy"
        and (fill.quantity, fill.price, fill.fee) == (quantity, fill_price, fee),
        "fill-economics-differ",
    )
    snapshot = source.final_snapshot
    check(
        (snapshot.nav, snapshot.trade_date_cash, snapshot.fees, snapshot.market_value)
        == (nav, cash, fee, quantity * raw),
        "final-economics-differ",
    )
    check(
        len(snapshot.positions) == 1 and snapshot.positions[0].quantity == quantity,
        "position-differs",
    )
    metrics = {metric.name: metric for metric in report.metrics}
    check(metrics["ending_equity"].value == nav, "ending-equity-differs")
    check(metrics["total_return"].value == nav / starting - 1, "total-return-differs")
    annual = ("annualized_return", "annualized_volatility", "sharpe_ratio", "sortino_ratio")
    check(
        all(
            metrics[name].value is None
            and metrics[name].status == "undefined"
            and metrics[name].reasons
            for name in annual
        ),
        "short-history-annualization-defined",
    )
verify_operational_schema(engine, require_phase_zero_facts=False, research_codec=personal_codec)
result.update(
    status="completed",
    execution_count=1,
    annualized_null_count=len(annual),
    artifact_sha256=publication.object.object_sha256,
    report_sha256=publication.report_sha256,
    result_sha256=publication.result_sha256,
    event_head_sha256=job.last_event_sha256,
)
engine.dispose()
check_origins()
print(json.dumps(result, sort_keys=True))
"""
)


def _program(body: str) -> str:
    # Fixed error codes only: neither tracebacks nor exception messages escape.
    return (
        "try:\n"
        + "\n".join("    " + line for line in (_INSTALLED + body).splitlines())
        + '\nexcept BaseException:\n    print("{\\"status\\":\\"harness-rejected\\"}")\n'
        + "    raise SystemExit(2)\n"
    )


class VerificationFailure(Exception):
    """Static diagnostic without child output, paths, or environment values."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise VerificationFailure(code)


def _lock_available() -> bool:
    try:
        descriptor = os.open(_LOCK, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return True
    try:
        info = os.fstat(descriptor)
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid(), "invalid-worker-lock")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return True
    finally:
        os.close(descriptor)


def _terminate(child: subprocess.Popen[bytes]) -> None:
    with suppress(ProcessLookupError):
        os.killpg(child.pid, signal.SIGTERM)
    with suppress(subprocess.TimeoutExpired):
        child.wait(timeout=2)
    # A descendant may outlive its direct parent. Kill the process group even
    # when the parent already exited, then reap the direct child explicitly.
    with suppress(ProcessLookupError):
        os.killpg(child.pid, signal.SIGKILL)
    child.wait(timeout=2)


class Verifier:
    def __init__(self, python: Path, directory: Path) -> None:
        self.python, self.directory = python, directory
        self.environment = {
            "PATH": "/usr/bin:/bin",
            "TMPDIR": str(directory),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        self.deadline = time.monotonic() + 180

    def run(self, phase: str, code: str, arguments: list[str]) -> list[dict[str, object]]:
        deadline = min(self.deadline, time.monotonic() + 60)
        with subprocess.Popen(
            [str(self.python), "-I", "-B", "-c", _program(code), *arguments],
            cwd=self.directory,
            env=self.environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        ) as child:
            _require(child.stdout is not None, "child-pipe-unavailable")
            assert child.stdout is not None
            output = bytearray()
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    while selector.get_map():
                        _require(time.monotonic() < deadline, phase + "-timeout")
                        for key, _ in selector.select(timeout=0.1):
                            chunk = os.read(key.fd, 4096)
                            if not chunk:
                                selector.unregister(key.fd)
                                continue
                            output.extend(chunk)
                            _require(len(output) <= _MAX_STDOUT, phase + "-output-bound")
                    child.wait(timeout=max(0.01, deadline - time.monotonic()))
                _require(child.returncode == 0, phase + "-failed")
                rows = [json.loads(line) for line in output.splitlines() if line.strip()]
                _require(bool(rows) and all(type(row) is dict for row in rows), phase + "-status")
                return rows
            except BaseException:
                _terminate(child)
                raise


def verify(python: Path, output_dir: Path | None = None) -> dict[str, object]:
    _require(
        python.is_absolute() and python.is_file() and os.access(python, os.X_OK), "invalid-python"
    )
    _require(_lock_available(), "worker-lock-busy")
    previous_umask = os.umask(0o077)
    try:
        with ExitStack() as resources:
            if output_dir is None:
                temporary = resources.enter_context(
                    tempfile.TemporaryDirectory(prefix="aqt-installed-jobs-", dir="/tmp")
                )
                directory = Path(temporary)
            else:
                _require(output_dir.is_absolute(), "output-directory-must-be-absolute")
                _require(
                    not output_dir.resolve().is_relative_to(Path(__file__).resolve().parents[1]),
                    "output-directory-inside-source",
                )
                output_dir.mkdir(mode=0o700)
                directory = output_dir
            artifacts = directory / "objects"
            url = "sqlite+pysqlite:///" + str(directory / "research.sqlite")
            verifier = Verifier(python, directory)
            common = ["--database-url", url, "--artifacts", str(artifacts), "--owner-id", _OWNER]
            initialized = verifier.run("initialize", _CLI, [*common, "init"])
            _require(initialized[-1].get("status") == "initialized", "initialize-status")
            sqlite_checks = verifier.run("sqlite-policy", _SQLITE_PROBE, [url])[-1]
            registered = verifier.run(
                "register",
                _CLI,
                [
                    *common,
                    "register",
                    "--fixture",
                    "flat",
                    "--fixture-sessions",
                    "12",
                    "--display-name",
                    "Installed wheel flat fixture",
                    "--access-description",
                    "Reusable synthetic acceptance fixture",
                ],
            )
            _require(registered[-1].get("status") == "registered", "register-status")
            prepared = verifier.run("prepare", _PREPARE, [url, str(artifacts), _OWNER])[-1]
            worked = verifier.run("worker", _CLI, [*common, "work", "--once"])
            _require(
                len(worked) == 2
                and worked[0].get("status") == "completed"
                and worked[-1].get("processed_jobs") == 1,
                "worker-status",
            )
            first = verifier.run("verify", _VERIFY, [url, str(artifacts), _OWNER])[-1]
            restarted = verifier.run("restart", _CLI, [*common, "work", "--once"])
            _require(
                len(restarted) == 1 and restarted[-1].get("processed_jobs") == 0,
                "restart-claimed-another-job",
            )
            final = verifier.run("recheck", _VERIFY, [url, str(artifacts), _OWNER])[-1]
            _require(first == final, "restart-changed-terminal-history")
            for key in ("job_id", "request_sha256", "run_spec_sha256", "wheel_record_sha256"):
                _require(prepared[key] == final[key], "immutable-request-changed")
            for key, value in sqlite_checks.items():
                _require(prepared[key] == final[key] == value, "sqlite-policy-changed")
            _require(_lock_available(), "worker-lock-not-released")
            _require(stat.S_IMODE(artifacts.stat().st_mode) == 0o700, "artifact-root-mode")
            objects = tuple(artifacts.iterdir())
            for path in objects:
                info = path.lstat()
                _require(
                    stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600,
                    "artifact-file-mode",
                )
            # Identifiers and private paths remain local. Only bounded counts,
            # immutable hashes and SQLite policy metadata escape the harness.
            return {
                key: final[key]
                for key in (
                    "job_count",
                    "publication_count",
                    "attempt_count",
                    "execution_count",
                    "annualized_null_count",
                    "request_sha256",
                    "run_spec_sha256",
                    "wheel_record_sha256",
                    "artifact_sha256",
                    "report_sha256",
                    "result_sha256",
                    "event_head_sha256",
                    "sqlite_runtime",
                    "sqlite_runtime_admitted",
                    "sqlite_journal_mode",
                    "sqlite_synchronous",
                    "sqlite_busy_timeout_ms",
                    "sqlite_wal_autocheckpoint_pages",
                )
            } | {
                "status": "verified",
                "object_count": len(objects),
                "fixture_sessions": 12,
                "calendar_sessions": 13,
                "scored_sessions": 9,
            }
    finally:
        os.umask(previous_umask)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--python", type=Path, required=True, help="absolute installed-wheel interpreter"
    )
    parser.add_argument(
        "--output-dir", type=Path, help="new private directory for retained probe files"
    )
    args = parser.parse_args()

    def interrupted(_signum: int, _frame: FrameType | None) -> None:
        raise VerificationFailure("interrupted")

    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        result = verify(args.python, args.output_dir)
        if args.output_dir is not None:
            descriptor = os.open(
                args.output_dir / "evidence.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(descriptor, "w") as stream:
                stream.write(json.dumps(result, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
    except VerificationFailure as error:
        print(json.dumps({"status": "rejected", "reason": str(error)}, sort_keys=True))
        return 2
    except Exception:
        print(
            json.dumps({"status": "rejected", "reason": "verification-unavailable"}, sort_keys=True)
        )
        return 2
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
