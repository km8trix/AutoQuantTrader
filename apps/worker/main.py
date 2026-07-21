"""Local historical-ingestion and fixture-research worker entrypoint."""

from __future__ import annotations

import argparse
import json
import time
from uuid import uuid4

from apps.api.config import Environment, Settings
from packages.application.backtest_worker import (
    ensure_golden_research_catalog,
    process_one_golden_backtest,
)
from packages.application.market_data_ingestion import ingest_recorded_fixture
from packages.observability.logging import configure_logging
from packages.persistence.backtest_workflow import BacktestJobSnapshot, SqlBacktestWorkflow
from packages.persistence.database import create_database_engine, verify_operational_schema


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--once",
        action="store_true",
        help="ingest the configured fixture and process at most one research job",
    )
    arguments = parser.parse_args()
    settings = Settings.from_env()
    if settings.environment is not Environment.LOCAL:
        print(
            json.dumps(
                {
                    "service": "worker",
                    "status": "not_ready",
                    "reason": "recorded fixture ingestion is local-only",
                },
                sort_keys=True,
            ),
            flush=True,
        )
        raise SystemExit(2)
    configure_logging(settings.log_level)
    engine = create_database_engine(settings.database_url)
    verify_operational_schema(engine, require_phase_zero_facts=False)
    outcome = ingest_recorded_fixture(
        engine=engine,
        data_lake_path=settings.data_lake_path,
        source_path=settings.market_data_fixture_path,
    )
    workflow = SqlBacktestWorkflow(engine)
    catalog_input = ensure_golden_research_catalog(workflow)
    worker_id = f"local-fixture-worker-{uuid4().hex}"

    def process_backtest() -> BacktestJobSnapshot | None:
        return process_one_golden_backtest(
            workflow,
            worker_id=worker_id,
            catalog_input=catalog_input,
        )

    if arguments.once:
        backtest = process_backtest()
        print(
            json.dumps(
                {
                    "job_id": outcome.job_id,
                    "manifest_id": outcome.manifest_id,
                    "mode": "synthetic_fixture",
                    "admission_run_id": outcome.admission_run_id,
                    "qualification": outcome.admission_status,
                    "backtest_job_id": None if backtest is None else backtest.job_id,
                    "backtest_status": ("idle" if backtest is None else backtest.status.value),
                    "service": "worker",
                    "status": "published" if outcome.first_publication else "idempotent",
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return

    print(
        json.dumps(
            {
                "job_id": outcome.job_id,
                "manifest_id": outcome.manifest_id,
                "mode": "synthetic_fixture",
                "admission_run_id": outcome.admission_run_id,
                "qualification": outcome.admission_status,
                "backtest_status": "watching",
                "service": "worker",
                "status": "published" if outcome.first_publication else "idempotent",
            },
            sort_keys=True,
        ),
        flush=True,
    )
    while True:
        backtest = process_backtest()
        if backtest is None:
            time.sleep(1)
            continue
        print(
            json.dumps(
                {
                    "backtest_job_id": backtest.job_id,
                    "backtest_status": backtest.status.value,
                    "mode": "fixture_backtest",
                    "service": "worker",
                },
                sort_keys=True,
            ),
            flush=True,
        )


if __name__ == "__main__":
    main()
