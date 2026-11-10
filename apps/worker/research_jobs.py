"""Explicit local database setup, archive registration and durable research worker."""

from __future__ import annotations

import argparse
import json
import signal
import threading
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from types import FrameType
from uuid import uuid4

import sqlalchemy as sa
from alembic import command
from alembic.config import Config

from apps.worker.personal_research import _bounded_read, _calendar, _research_guard
from apps.worker.research_runner import ResearchProcessRunner
from packages.adapters.personal_build import current_build_pins
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec
from packages.application.personal_inputs import research_engine_inputs, synthetic_engine_inputs
from packages.application.research_catalog import (
    create_catalog_entry,
    resolve_catalog_inputs,
)
from packages.application.research_dataset import research_dataset_from_json_bytes
from packages.application.research_worker_v2 import process_one_research_job
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.engine_contracts import EvaluationSpec
from packages.domain.personal_evaluation import PriorAccessDeclaration
from packages.domain.research_job_contracts import MAX_INPUT_BYTES, MAX_OBJECT_BYTES
from packages.persistence.database import create_database_engine, verify_operational_schema
from packages.persistence.research_catalog import SqlResearchCatalog
from packages.persistence.research_workflow_v2 import SqlResearchWorkflow


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database-url", required=True, help="explicit SQLite/PostgreSQL research database"
    )
    parser.add_argument(
        "--artifacts", type=Path, required=True, help="private local object directory"
    )
    parser.add_argument("--owner-id", default="local-operator")
    subcommands = parser.add_subparsers(dest="operation", required=True)
    subcommands.add_parser("init", help="migrate an explicitly selected empty database")
    register = subcommands.add_parser(
        "register", help="admit an existing archive or labelled fixture"
    )
    source = register.add_mutually_exclusive_group(required=True)
    source.add_argument("--dataset", type=Path)
    source.add_argument("--fixture", choices=("flat", "regime"))
    register.add_argument("--settlement-calendar", type=Path)
    register.add_argument("--fixture-sessions", type=int, default=520)
    register.add_argument("--display-name", required=True)
    register.add_argument(
        "--prior-access", choices=("known_accessed", "unknown"), default="known_accessed"
    )
    register.add_argument("--access-description", required=True)
    work = subcommands.add_parser(
        "work", help="process queued actual-engine jobs; stop cleanly on SIGTERM"
    )
    work.add_argument("--once", action="store_true")
    work.add_argument("--max-jobs", type=int, default=0, help="zero continues until stopped")
    work.add_argument("--worker-id", default="local-research-worker")
    return parser


def _initialize(args: argparse.Namespace) -> None:
    inspection_engine = create_database_engine(args.database_url)
    try:
        if sa.inspect(inspection_engine).get_table_names():
            raise ValueError("init requires an explicitly selected empty database")
    finally:
        inspection_engine.dispose()
    engine = create_database_engine(args.database_url, research_sqlite_wal=True)
    try:
        config = Config()
        config.set_main_option(
            "script_location", str(Path(__file__).resolve().parents[2] / "migrations")
        )
        config.set_main_option("sqlalchemy.url", args.database_url.replace("%", "%%"))
        config.attributes["aqt_explicit_database_url"] = args.database_url
        command.upgrade(config, "head")
        verify_operational_schema(
            engine, require_phase_zero_facts=False, research_codec=personal_codec
        )
        LocalResearchArtifactStore(args.artifacts)
    finally:
        engine.dispose()


def _register(
    args: argparse.Namespace, catalog: SqlResearchCatalog, artifacts: LocalResearchArtifactStore
) -> str:
    archive = None
    pins = current_build_pins()
    if args.fixture is not None:
        if not 2 <= args.fixture_sessions <= 5200:
            raise ValueError("fixture session count exceeds its registration bound")
        inputs = synthetic_engine_inputs(
            fixture=args.fixture, pins=pins, session_count=args.fixture_sessions, warmup_count=0
        )
    else:
        if args.settlement_calendar is None:
            raise ValueError("archive registration requires its settlement calendar")
        payload = _bounded_read(args.dataset, MAX_INPUT_BYTES)
        dataset = research_dataset_from_json_bytes(payload)
        sessions = tuple(s.session_label for s in dataset.manifest.calendar.sessions)
        if len(sessions) < 2:
            raise ValueError("archive must leave scoring and a final calendar horizon")
        configuration = ReferenceConfiguration(
            allocation=Decimal("0.2375")
            if len(dataset.manifest.instruments) == 4
            else Decimal("0.25")
        )
        inputs = research_engine_inputs(
            dataset,
            configuration=configuration,
            evaluation=EvaluationSpec(
                "catalog-source", (), sessions[:-1], f"retrospective-{args.prior_access}"
            ),
            settlement_calendar=_calendar(args.settlement_calendar),
            pins=pins,
        )
        archive = artifacts.put(
            payload, codec_version="personal-research-dataset-v1", max_bytes=MAX_INPUT_BYTES
        )
    inputs = replace(
        inputs, spec=replace(inputs.spec, max_cpu_cores=1, max_output_bytes=MAX_OBJECT_BYTES)
    )
    source_ref = artifacts.put(personal_codec.encode_record(inputs), max_bytes=MAX_INPUT_BYTES)
    calendar_ref = artifacts.put(
        personal_codec.encode_record(inputs.spec.execution_policy.settlement_calendar),
        max_bytes=MAX_INPUT_BYTES,
    )
    entry = create_catalog_entry(
        display_name=args.display_name,
        prior_access=PriorAccessDeclaration(
            args.prior_access, datetime.now(UTC), args.owner_id, args.access_description
        ),
        source=inputs,
        source_inputs=source_ref,
        archive=archive,
        settlement_calendar=calendar_ref,
    )
    resolve_catalog_inputs(entry, artifacts=artifacts)
    return catalog.register(entry, owner_id=args.owner_id).catalog_id


def _work(
    args: argparse.Namespace, workflow: SqlResearchWorkflow, artifacts: LocalResearchArtifactStore
) -> int:
    if not 0 <= args.max_jobs <= 256:
        raise ValueError("worker invocation job count exceeds its bound")
    stop = threading.Event()

    def shutdown(_signum: int, _frame: FrameType | None) -> None:
        stop.set()

    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    for sig in previous:
        signal.signal(sig, shutdown)
    count = 0
    try:
        # No job may be claimed before the inherited W2 process guard is held.
        with _research_guard() as guard:
            runner = ResearchProcessRunner(
                lock_descriptor=guard.fileno(), on_shutdown=stop.set, artifact_root=args.artifacts
            )
            instance = "process-" + uuid4().hex
            while not stop.is_set():
                result = process_one_research_job(
                    workflow,
                    worker_id=args.worker_id,
                    worker_instance_id=instance,
                    retained_runner=runner,
                    artifacts=artifacts,
                    codec=personal_codec,
                    stop_requested=stop.is_set,
                )
                if result is not None:
                    count += 1
                    print(
                        json.dumps(
                            {
                                "job_id": result.job_id,
                                "status": result.status,
                                "trading_authorized": False,
                            },
                            sort_keys=True,
                        ),
                        flush=True,
                    )
                if args.once or (args.max_jobs and count >= args.max_jobs):
                    break
                if result is None:
                    stop.wait(1)
        return count
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    engine = None
    try:
        if args.operation == "init":
            _initialize(args)
            print(json.dumps({"status": "initialized", "trading_authorized": False}))
            return 0
        engine = create_database_engine(args.database_url, research_sqlite_wal=True)
        verify_operational_schema(
            engine, require_phase_zero_facts=False, research_codec=personal_codec
        )
        workflow = SqlResearchWorkflow(engine, codec=personal_codec)
        artifacts = LocalResearchArtifactStore(args.artifacts)
        catalog = SqlResearchCatalog(engine, codec=personal_codec, workflow=workflow)
        if args.operation == "register":
            identity = _register(args, catalog, artifacts)
            print(
                json.dumps(
                    {"status": "registered", "catalog_id": identity, "trading_authorized": False}
                )
            )
        else:
            count = _work(args, workflow, artifacts)
            print(
                json.dumps(
                    {"status": "stopped", "processed_jobs": count, "trading_authorized": False}
                )
            )
        return 0
    except (ValueError, TypeError, OSError, RuntimeError, sa.exc.SQLAlchemyError):
        # Inputs, source paths, DB URLs and provider bytes are never error text.
        print(
            json.dumps(
                {
                    "status": "rejected",
                    "reason": "research-setup-or-runtime-unavailable",
                    "trading_authorized": False,
                }
            )
        )
        return 2
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
