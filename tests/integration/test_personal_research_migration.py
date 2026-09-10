from __future__ import annotations

import ast
import builtins
import importlib
from concurrent.futures import ThreadPoolExecutor
from io import StringIO
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine

from packages.application import personal_codec
from packages.domain.research_catalog import ResearchCatalogEntry
from packages.domain.research_job_contracts import ResearchJobEvent, ResearchRunRequest
from packages.domain.walking_thread import WalkingThread
from packages.persistence import database as database_module
from packages.persistence.database import (
    EXPECTED_SCHEMA_REVISION,
    DatabaseSchemaNotReady,
    create_database_engine,
    verify_operational_schema,
)
from packages.persistence.research_catalog import SqlResearchCatalog
from packages.persistence.research_catalog_schema import RESEARCH_CATALOG_TABLES
from packages.persistence.research_schema_v2 import RESEARCH_TABLES_V2
from packages.persistence.research_workflow_v2 import SqlResearchWorkflow
from packages.persistence.risk import SqlRiskDecisionRepository
from packages.persistence.walking_thread import WalkingThreadUnitOfWork
from tests.integration.test_research_catalog_transactions import catalog_sample
from tests.unit.test_research_job_v2 import NOW, sample_request

ROOT = Path(__file__).resolve().parents[2]
REVISION = "0039_personal_research"
PRIOR = "0038_phase4_etrade_oauth"
TABLES = (*RESEARCH_TABLES_V2, *RESEARCH_CATALOG_TABLES)
SUPPORTED_REVISIONS = (
    "0035_phase6_time_uncertainty",
    "0036_phase6_time_anchors",
    "0037_phase3_fixture_worker",
    PRIOR,
    REVISION,
)


def migration_config(path: Path) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{path}")
    return config


def database_url(config: Config) -> str:
    value = config.get_main_option("sqlalchemy.url")
    assert value is not None
    return value


def shapes(engine: Engine) -> dict[str, object]:
    inspector = sa.inspect(engine)
    return {
        name: tuple((c["name"], str(c["type"]), c["nullable"]) for c in inspector.get_columns(name))
        for name in inspector.get_table_names()
    }


def test_0039_additive_static_ddl_and_empty_downgrade(tmp_path: Path) -> None:
    config = migration_config(tmp_path / "migration.sqlite")
    command.upgrade(config, PRIOR)
    engine = create_database_engine(database_url(config))
    before = shapes(engine)
    verify_operational_schema(engine, expected_revision=PRIOR, require_phase_zero_facts=False)
    command.upgrade(config, REVISION)
    after = shapes(engine)
    assert set(after) == set(before) | {t.name for t in TABLES}
    assert {name: after[name] for name in before} == before
    inspector = sa.inspect(engine)
    for table in TABLES:
        assert tuple(c["name"] for c in inspector.get_columns(table.name)) == tuple(table.c.keys())
        assert inspector.get_pk_constraint(table.name)["constrained_columns"] == [
            c.name for c in table.primary_key
        ]
        assert {i["name"] for i in inspector.get_indexes(table.name)} == {
            i.name for i in table.indexes
        }
        assert {
            (tuple(f["constrained_columns"]), f["referred_table"], tuple(f["referred_columns"]))
            for f in inspector.get_foreign_keys(table.name)
        } == {
            (
                tuple(e.parent.name for e in constraint.elements),
                constraint.referred_table.name,
                tuple(e.column.name for e in constraint.elements),
            )
            for constraint in table.foreign_key_constraints
        }
        assert {c["name"] for c in inspector.get_check_constraints(table.name)} == {
            c.name for c in table.constraints if isinstance(c, sa.CheckConstraint)
        }
        assert {tuple(c["column_names"]) for c in inspector.get_unique_constraints(table.name)} == {
            tuple(c.name for c in constraint.columns)
            for constraint in table.constraints
            if isinstance(constraint, sa.UniqueConstraint)
        }
    assert EXPECTED_SCHEMA_REVISION == REVISION
    verify_operational_schema(engine, require_phase_zero_facts=False)
    command.downgrade(config, PRIOR)
    assert shapes(engine) == before
    verify_operational_schema(engine, expected_revision=PRIOR, require_phase_zero_facts=False)
    engine.dispose()


@pytest.mark.parametrize("table", TABLES, ids=lambda t: t.name)
def test_0039_downgrade_refuses_each_nonempty_history_table(
    tmp_path: Path, table: sa.Table
) -> None:
    config = migration_config(tmp_path / "retained.sqlite")
    command.upgrade(config, REVISION)
    # An isolated malformed SQL row proves the downgrade guard checks every table,
    # including orphan history. No typed application operation admits this row.
    engine = sa.create_engine(database_url(config))
    values: dict[str, object] = {}
    for column in table.columns:
        if column.nullable:
            continue
        if isinstance(column.type, sa.DateTime):
            values[column.name] = NOW
        elif isinstance(column.type, sa.Boolean):
            values[column.name] = False
        elif isinstance(column.type, sa.Integer):
            values[column.name] = 2 if column.name == "byte_count" else 0
        elif isinstance(column.type, sa.LargeBinary):
            values[column.name] = b"{}"
        else:
            values[column.name] = {
                "codec_version": "personal-record/1",
                "status": "queued",
                "outcome": "completed",
                "request_json": "{}",
            }.get(column.name, "a" * min(getattr(column.type, "length", None) or 64, 64))
    with engine.begin() as connection:
        connection.execute(table.insert().values(**values))
    with pytest.raises(
        RuntimeError, match="refusing to downgrade nonempty personal research history"
    ):
        command.downgrade(config, PRIOR)
    with engine.connect() as connection:
        assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == REVISION
        assert connection.scalar(sa.select(sa.func.count()).select_from(table)) == 1
    assert {t.name for t in TABLES}.issubset(sa.inspect(engine).get_table_names())
    engine.dispose()


def test_0039_nonempty_schema_probe_requires_injected_codec_and_rechecks_rows(
    tmp_path: Path,
) -> None:
    config = migration_config(tmp_path / "integrity.sqlite")
    command.upgrade(config, REVISION)
    engine = create_database_engine(database_url(config))
    request = sample_request()
    SqlResearchWorkflow(engine, codec=personal_codec).launch(request)
    with pytest.raises(DatabaseSchemaNotReady, match="requires a record codec"):
        verify_operational_schema(engine, require_phase_zero_facts=False)
    verify_operational_schema(engine, require_phase_zero_facts=False, research_codec=personal_codec)
    with engine.begin() as connection:
        connection.execute(RESEARCH_TABLES_V2[1].update().values(owner_id="other"))
    with pytest.raises(DatabaseSchemaNotReady, match="research SQL integrity"):
        verify_operational_schema(
            engine, require_phase_zero_facts=False, research_codec=personal_codec
        )
    engine.dispose()


class PausingResearchCodec:
    """Pause one actual typed validation after its coherent raw snapshot is read."""

    def __init__(self, record_type: type[object]) -> None:
        self.record_type = record_type
        self.entered = Event()
        self.release = Event()

    def encode_record(self, value: object) -> bytes:
        return personal_codec.encode_record(value)

    def decode_record[T](self, payload: bytes, expected: type[T]) -> T:
        if expected is self.record_type and not self.entered.is_set():
            self.entered.set()
            assert self.release.wait(10), "readiness validation was not released"
        return personal_codec.decode_record(payload, expected)


@pytest.mark.parametrize("require_phase_zero_facts", [False, True])
@pytest.mark.parametrize(
    "record_type", [ResearchRunRequest, ResearchJobEvent, ResearchCatalogEntry]
)
def test_0039_readiness_releases_snapshot_before_slow_validation_and_rechecks_corruption(
    tmp_path: Path, require_phase_zero_facts: bool, record_type: type[object]
) -> None:
    config = migration_config(tmp_path / "readiness-writer.sqlite")
    command.upgrade(config, REVISION)
    engine = create_database_engine(database_url(config))
    try:
        # Exercise both real public verification paths, including the retained
        # financial integrity checks when phase-zero facts are required.
        result = WalkingThread.run(
            SqlRiskDecisionRepository(engine, WalkingThread.risk_authority())
        )
        WalkingThreadUnitOfWork(engine).persist(result)
        workflow = SqlResearchWorkflow(engine, codec=personal_codec)
        request = sample_request()
        workflow.launch(request)
        SqlResearchCatalog(engine, codec=personal_codec, workflow=workflow).register(
            catalog_sample(), owner_id="owner"
        )
        with engine.connect() as connection:
            assert connection.scalar(sa.text("PRAGMA journal_mode")) == "delete"

        codec = PausingResearchCodec(record_type)
        with ThreadPoolExecutor(max_workers=2) as pool:
            reading = pool.submit(
                verify_operational_schema,
                engine,
                require_phase_zero_facts=require_phase_zero_facts,
                research_codec=codec,
            )
            try:
                assert codec.entered.wait(10), "readiness did not reach typed W3 validation"
                claimed = pool.submit(
                    workflow.claim_next,
                    worker_id="worker",
                    worker_instance_id="readiness-concurrent-claim",
                ).result(timeout=3)
                # claim_next returns only after its actual SQL COMMIT. A live
                # readiness read transaction would block that commit in DELETE mode.
                assert claimed is not None and claimed.request == request
            finally:
                codec.release.set()
            reading.result(timeout=10)

        # The paused verification accepts its coherent queued snapshot even
        # though a claim committed later; a new call validates the current state.
        assert workflow.get(request.job_id).status == "running"
        verify_operational_schema(
            engine,
            require_phase_zero_facts=require_phase_zero_facts,
            research_codec=personal_codec,
        )
        with engine.begin() as connection:
            connection.execute(RESEARCH_TABLES_V2[1].update().values(owner_id="other"))
        with pytest.raises(DatabaseSchemaNotReady, match="research SQL integrity"):
            verify_operational_schema(
                engine,
                require_phase_zero_facts=require_phase_zero_facts,
                research_codec=personal_codec,
            )
    finally:
        engine.dispose()


@pytest.mark.parametrize("revision", SUPPORTED_REVISIONS)
def test_supported_revision_readability_probes_are_batched_without_new_historical_tables(
    tmp_path: Path, revision: str
) -> None:
    config = migration_config(tmp_path / "historical.sqlite")
    command.upgrade(config, revision)
    engine = create_database_engine(database_url(config))
    statements: list[str] = []

    def observe(_connection, _cursor, statement, _parameters, _context, _executemany):  # type: ignore[no-untyped-def]
        statements.append(statement)

    sa.event.listen(engine, "before_cursor_execute", observe)
    try:
        verify_operational_schema(
            engine, expected_revision=revision, require_phase_zero_facts=False
        )
        probes = [statement for statement in statements if " AS required_table_" in statement]
        counts = [statement.count(" AS required_table_") for statement in probes]
        assert all(1 <= count <= 64 for count in counts)
        # The real readiness call resolves over one hundred required tables in
        # three or fewer probes, rather than a transaction-spanning probe per table.
        assert sum(counts) > 100 and 1 <= len(probes) <= 3
        assert all("WHERE 0 = 1" in statement for statement in probes)
        if revision != REVISION:
            assert not {t.name for t in TABLES} & set(sa.inspect(engine).get_table_names())
    finally:
        sa.event.remove(engine, "before_cursor_execute", observe)
        engine.dispose()


@pytest.mark.parametrize("revision", SUPPORTED_REVISIONS)
@pytest.mark.parametrize("missing", ["table", "column"])
def test_batched_readiness_rejects_missing_required_table_or_column_when_empty(
    tmp_path: Path, revision: str, missing: str
) -> None:
    config = migration_config(tmp_path / "missing-readable-schema.sqlite")
    command.upgrade(config, revision)
    engine = create_database_engine(database_url(config))
    try:
        verify_operational_schema(
            engine, expected_revision=revision, require_phase_zero_facts=False
        )
        with engine.begin() as connection:
            assert connection.scalar(sa.text("SELECT COUNT(*) FROM market_data_sources")) == 0
            if missing == "table":
                connection.exec_driver_sql("DROP TABLE market_data_sources")
            else:
                connection.exec_driver_sql("ALTER TABLE market_data_sources DROP COLUMN detail")
        with pytest.raises(DatabaseSchemaNotReady, match="schema is unavailable") as failure:
            verify_operational_schema(
                engine, expected_revision=revision, require_phase_zero_facts=False
            )
        # The batched probe itself must resolve the empty table's full column
        # inventory; a later row-dependent financial validator is not sufficient.
        cause = failure.value.__cause__
        assert isinstance(cause, sa.exc.DBAPIError) and cause.statement is not None
        assert " AS required_table_" in cause.statement
    finally:
        engine.dispose()


@pytest.mark.parametrize("revision", SUPPORTED_REVISIONS)
@pytest.mark.parametrize("require_phase_zero_facts", [False, True])
def test_integrity_dependencies_finish_loading_before_read_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    revision: str,
    require_phase_zero_facts: bool,
) -> None:
    config = migration_config(tmp_path / "dependency-loading.sqlite")
    command.upgrade(config, revision)
    engine = create_database_engine(database_url(config))
    try:
        if require_phase_zero_facts:
            result = WalkingThread.run(
                SqlRiskDecisionRepository(engine, WalkingThread.risk_authority())
            )
            WalkingThreadUnitOfWork(engine).persist(result)

        expected = {
            "packages.persistence.advanced_batch_risk",
            "packages.persistence.alpaca_paper_account_binding",
            "packages.persistence.account_coordinator",
            "packages.persistence.batch_risk",
            "packages.persistence.phase2_ledger",
            "packages.persistence.reservation_lifecycle",
            "packages.persistence.simulation_horizon",
            "packages.persistence.submission_attempt",
            "packages.persistence.backtest_workflow",
            "packages.persistence.replay",
        }
        if revision in ("0037_phase3_fixture_worker", PRIOR, REVISION):
            expected.add("packages.persistence.fixture_segment_worker")
        if revision in (PRIOR, REVISION):
            expected.add("packages.persistence.etrade_oauth_coordinator")
        if revision == REVISION:
            expected.update(
                (
                    "packages.persistence.research_catalog",
                    "packages.persistence.research_workflow_v2",
                )
            )
        if require_phase_zero_facts:
            expected.add("packages.persistence.risk")

        imported: set[str] = set()
        began = False
        nested_loading_finished = False
        real_import = builtins.__import__
        real_load = database_module._load_nested_integrity_dependencies

        def observe_import(name, globals=None, locals=None, fromlist=(), level=0):  # type: ignore[no-untyped-def]
            if name in expected and name not in imported:
                assert not began, f"first dependency import occurred inside transaction: {name}"
                imported.add(name)
            return real_import(name, globals, locals, fromlist, level)

        def load_nested() -> None:
            nonlocal nested_loading_finished
            assert not began
            real_load()
            nested_loading_finished = True

        def before_begin(_connection: sa.Connection) -> None:
            nonlocal began
            assert nested_loading_finished and expected <= imported
            began = True

        sa.event.listen(engine, "begin", before_begin)
        try:
            with monkeypatch.context() as patch:
                patch.setattr(builtins, "__import__", observe_import)
                patch.setattr(database_module, "_load_nested_integrity_dependencies", load_nested)
                verify_operational_schema(
                    engine,
                    expected_revision=revision,
                    require_phase_zero_facts=require_phase_zero_facts,
                )
            assert began and expected <= imported
        finally:
            sa.event.remove(engine, "begin", before_begin)
    finally:
        engine.dispose()


def test_0038_still_requires_oauth_tables_and_0039_requires_all_new_tables(tmp_path: Path) -> None:
    config = migration_config(tmp_path / "missing.sqlite")
    command.upgrade(config, PRIOR)
    engine = create_database_engine(database_url(config))
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE phase4_etrade_oauth_session_heads")
    with pytest.raises(DatabaseSchemaNotReady):
        verify_operational_schema(engine, expected_revision=PRIOR, require_phase_zero_facts=False)
    engine.dispose()
    config = migration_config(tmp_path / "missing-new.sqlite")
    command.upgrade(config, REVISION)
    engine = create_database_engine(database_url(config))
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE research_trial_jobs")
    with pytest.raises(DatabaseSchemaNotReady):
        verify_operational_schema(engine, require_phase_zero_facts=False)
    engine.dispose()


def test_frozen_migration_has_no_runtime_schema_import_and_emits_offline_ddl(
    tmp_path: Path,
) -> None:
    module = importlib.import_module("migrations.versions.0039_personal_research_workflow")
    assert module.__file__ is not None
    source = Path(module.__file__).read_text()
    assert not any(
        isinstance(node, ast.ImportFrom) and (node.module or "").startswith("packages")
        for node in ast.walk(ast.parse(source))
    )
    config = migration_config(tmp_path / "never-created.sqlite")
    output = StringIO()
    config.output_buffer = output
    command.upgrade(config, f"{PRIOR}:{REVISION}", sql=True)
    sql = output.getvalue()
    assert all(f"CREATE TABLE {table.name}" in sql for table in TABLES)
    assert "owner_binding_sha256" in sql
    assert not (tmp_path / "never-created.sqlite").exists()
    with pytest.raises(RuntimeError, match="requires online locked history"):
        command.downgrade(config, f"{REVISION}:{PRIOR}", sql=True)


def test_postgres_downgrade_locks_all_tables_before_any_history_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = importlib.import_module("migrations.versions.0039_personal_research_workflow")
    connection = MagicMock()
    connection.dialect = SimpleNamespace(name="postgresql")
    connection.execute.return_value.first.return_value = (1,)
    monkeypatch.setattr(module.op, "get_bind", lambda: connection)
    monkeypatch.setattr(module.op, "get_context", lambda: SimpleNamespace(as_sql=False))
    with pytest.raises(RuntimeError, match="refusing to downgrade nonempty"):
        module.downgrade()
    assert connection.method_calls[0].args == (
        "LOCK TABLE " + ", ".join(table.name for table in TABLES) + " IN ACCESS EXCLUSIVE MODE",
    )
    assert connection.method_calls[0][0] == "exec_driver_sql"


def test_explicit_migration_url_takes_precedence_over_ambient_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = tmp_path / "explicit.sqlite"
    ambient = tmp_path / "must-not-open.sqlite"
    config = migration_config(selected)
    config.attributes["aqt_explicit_database_url"] = database_url(config)
    monkeypatch.setenv("AQT_DATABASE_URL", f"sqlite+pysqlite:///{ambient}")
    command.upgrade(config, REVISION)
    assert selected.exists() and not ambient.exists()
