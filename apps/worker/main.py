"""Phase 1B local historical-ingestion and admission worker entrypoint."""

from __future__ import annotations

import argparse
import json

from apps.api.config import Environment, Settings
from packages.application.market_data_ingestion import ingest_recorded_fixture
from packages.observability.logging import configure_logging
from packages.persistence.database import create_database_engine, verify_operational_schema


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="ingest the configured fixture once")
    parser.parse_args()
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
    print(
        json.dumps(
            {
                "job_id": outcome.job_id,
                "manifest_id": outcome.manifest_id,
                "mode": "synthetic_fixture",
                "admission_run_id": outcome.admission_run_id,
                "qualification": outcome.admission_status,
                "service": "worker",
                "status": "published" if outcome.first_publication else "idempotent",
            },
            sort_keys=True,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
