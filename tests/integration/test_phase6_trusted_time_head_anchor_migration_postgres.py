"""Isolated PostgreSQL proof for the exact additive Phase 6D migration."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, make_url

from packages.persistence.database import create_database_engine, verify_operational_schema
from packages.persistence.postgres_tls import is_supabase_session_pooler_url
from packages.persistence.schema import (
    phase6_trusted_time_epoch_registrations,
    phase6_trusted_time_head_anchor_intents,
    phase6_trusted_time_head_anchor_receipts,
    phase6_trusted_time_host_heads,
    phase6_trusted_time_probe_evaluations,
)
from packages.persistence.trusted_time import SqlTrustedTimeRepository
from scripts.migrate_phase6_trusted_time_head_anchors import (
    PRIOR_REVISION,
    TARGET_REVISION,
    check_static_bindings,
    collect_catalog_snapshot,
    run_exact_migration,
    verify_postflight_catalog,
    verify_preflight_catalog,
)

ROOT = Path(__file__).resolve().parents[2]
TEST_DATABASE_ENV = "AQT_TEST_POSTGRES_URL"


def _revision(engine: Engine) -> str | None:
    with engine.connect() as connection:
        value = connection.scalar(sa.text("SELECT version_num FROM public.alembic_version"))
    return value if isinstance(value, str) else None


def _anchor_history_count(engine: Engine) -> int:
    with engine.connect() as connection:
        return sum(
            int(connection.scalar(sa.select(sa.func.count()).select_from(table)) or 0)
            for table in (
                phase6_trusted_time_head_anchor_intents,
                phase6_trusted_time_head_anchor_receipts,
            )
        )


def _alembic_config(database_url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


def _migrate(config: Config, database_url: str, *, revision: str) -> None:
    # migrations/env.py intentionally gives AQT_DATABASE_URL precedence.  Pin
    # it to the designated test target so ambient runtime configuration cannot
    # redirect this isolated proof.
    with patch.dict(os.environ, {"AQT_DATABASE_URL": database_url}):
        if revision == TARGET_REVISION:
            command.upgrade(config, revision)
        else:
            command.downgrade(config, revision)


def _cleanup_local_host(engine: Engine, host_id: str) -> None:
    with engine.begin() as connection:
        connection.execute(
            sa.delete(phase6_trusted_time_host_heads).where(
                phase6_trusted_time_host_heads.c.host_id == host_id
            )
        )
        connection.execute(
            sa.delete(phase6_trusted_time_probe_evaluations).where(
                phase6_trusted_time_probe_evaluations.c.host_id == host_id
            )
        )
        connection.execute(
            sa.delete(phase6_trusted_time_epoch_registrations).where(
                phase6_trusted_time_epoch_registrations.c.host_id == host_id
            )
        )


def test_exact_phase6d_migration_preserves_nonempty_local_history_without_backfill() -> None:
    database_url = os.getenv(TEST_DATABASE_ENV)
    if database_url is None:
        pytest.skip(f"set {TEST_DATABASE_ENV} to run PostgreSQL Phase 6D migration proof")
    if make_url(database_url).get_backend_name() != "postgresql":
        pytest.fail(f"{TEST_DATABASE_ENV} must select a PostgreSQL test database")
    require_client_tls = is_supabase_session_pooler_url(make_url(database_url))
    config = _alembic_config(database_url)
    engine = create_database_engine(database_url)
    original_revision = _revision(engine)
    host_id = f"pytest-phase6d-migration-{uuid4().hex}"
    local_history_created = False
    try:
        if original_revision == TARGET_REVISION:
            if _anchor_history_count(engine) != 0:
                pytest.fail("designated test database has nonempty trusted-time anchor history")
            engine.dispose()
            _migrate(config, database_url, revision=PRIOR_REVISION)
            engine = create_database_engine(database_url)
        elif original_revision != PRIOR_REVISION:
            pytest.fail("designated test database is not at exact revision 0035 or 0036")

        SqlTrustedTimeRepository(engine).register_new_epoch(
            source_id="phase6d-migration-proof-source",
            source_authority_sha256="a" * 64,
            host_id=host_id,
            recorded_at=datetime(2026, 8, 1, 12, 0, tzinfo=UTC),
        )
        local_history_created = True
        with engine.connect() as connection:
            connection.exec_driver_sql("SET LOCAL search_path TO public")
            preflight = collect_catalog_snapshot(connection)
        verify_preflight_catalog(preflight, require_client_tls=require_client_tls)
        assert (
            dict(preflight.local_history_counts)[phase6_trusted_time_epoch_registrations.name] >= 1
        )

        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL search_path TO public")
            run_exact_migration(connection, check_static_bindings())

        with engine.connect() as connection:
            connection.exec_driver_sql("SET LOCAL search_path TO public")
            postflight = collect_catalog_snapshot(connection)
            preserved = connection.scalar(
                sa.select(sa.func.count())
                .select_from(phase6_trusted_time_epoch_registrations)
                .where(phase6_trusted_time_epoch_registrations.c.host_id == host_id)
            )
        verify_postflight_catalog(postflight, require_client_tls=require_client_tls)
        assert preserved == 1
        assert postflight.anchor_table_counts == (
            (phase6_trusted_time_head_anchor_intents.name, 0),
            (phase6_trusted_time_head_anchor_receipts.name, 0),
        )
        verify_operational_schema(
            engine,
            require_phase_zero_facts=False,
            expected_revision=TARGET_REVISION,
        )
    finally:
        try:
            if local_history_created and _revision(engine) in {
                PRIOR_REVISION,
                TARGET_REVISION,
            }:
                _cleanup_local_host(engine, host_id)
        finally:
            current_revision = _revision(engine)
            engine.dispose()
            if original_revision == PRIOR_REVISION and current_revision == TARGET_REVISION:
                _migrate(config, database_url, revision=PRIOR_REVISION)
            elif original_revision == TARGET_REVISION and current_revision == PRIOR_REVISION:
                _migrate(config, database_url, revision=TARGET_REVISION)
