"""Disposable migration/readiness probes; no account or provider activation."""

from __future__ import annotations

import ast
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
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from packages.application import personal_codec
from packages.persistence import database as database_module
from packages.persistence.applied_reconciliation_schema import APPLIED_RECONCILIATION_TABLES
from packages.persistence.continuous_account_schema import CONTINUOUS_ACCOUNT_TABLES
from packages.persistence.daily_runtime_risk_schema import DAILY_RUNTIME_TABLES
from packages.persistence.database import (
    EXPECTED_SCHEMA_REVISION,
    ContinuousIntegritySnapshot,
    DatabaseSchemaNotReady,
    create_database_engine,
    verify_operational_schema,
)
from packages.persistence.durable_journal_schema import (
    JOURNAL_TABLES,
    journal_entries,
    journal_streams,
)
from packages.persistence.research_schema_v2 import research_jobs_v2
from packages.persistence.research_workflow_v2 import SqlResearchWorkflow
from tests.integration.test_personal_research_migration import (
    database_url,
    migration_config,
    shapes,
)
from tests.unit.test_durable_journal import journal, key, record, request
from tests.unit.test_research_job_v2 import NOW, sample_request

REVISION = "0040_personal_continuous"
PRIOR = "0039_personal_research"
TABLES = (
    *JOURNAL_TABLES,
    *APPLIED_RECONCILIATION_TABLES,
    *DAILY_RUNTIME_TABLES,
    *CONTINUOUS_ACCOUNT_TABLES,
)


def migrated(tmp_path):
    config = migration_config(tmp_path / "continuous.sqlite")
    command.upgrade(config, REVISION)
    return config, create_database_engine(database_url(config))


class SnapshotReader:
    """Test-only row observer; production must supply actual store restoration."""

    def __init__(self):
        self.snapshots = []

    def validate_snapshot(self, snapshot: ContinuousIntegritySnapshot) -> None:
        self.snapshots.append(snapshot)
        assert snapshot.revision == REVISION
        assert tuple(snapshot.tables) == tuple(t.name for t in TABLES)
        with pytest.raises(TypeError):
            snapshot.tables["invented"] = ()
        for table in TABLES:
            rows = snapshot.tables[table.name]
            keys = [tuple(row[c.name] for c in table.primary_key) for row in rows]
            assert keys == sorted(keys)
            for row in rows:
                with pytest.raises(TypeError):
                    row["invented"] = "value"


def malformed_values(table):
    values = {}
    for column in table.c:
        if column.nullable:
            continue
        if isinstance(column.type, sa.DateTime):
            values[column.name] = NOW
        elif isinstance(column.type, sa.Date):
            values[column.name] = NOW.date()
        elif isinstance(column.type, sa.Boolean):
            values[column.name] = False
        elif isinstance(column.type, sa.Integer):
            values[column.name] = 1
        elif isinstance(column.type, sa.LargeBinary):
            values[column.name] = b"{}"
        else:
            values[column.name] = "a" * min(column.type.length, 64)
    return values


def test_0040_additive_roundtrip_preserves_all_prior_tables_and_exact_declared_ddl(tmp_path):
    config = migration_config(tmp_path / "roundtrip.sqlite")
    command.upgrade(config, PRIOR)
    engine = create_database_engine(database_url(config))
    try:
        before = shapes(engine)
        verify_operational_schema(engine, expected_revision=PRIOR, require_phase_zero_facts=False)
        command.upgrade(config, REVISION)
        after = shapes(engine)
        assert set(after) == set(before) | {t.name for t in TABLES}
        assert len(TABLES) == 16
        assert {name: after[name] for name in before} == before
        inspector = sa.inspect(engine)
        for table in TABLES:
            assert tuple(c["name"] for c in inspector.get_columns(table.name)) == tuple(
                table.c.keys()
            )
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
                    tuple(e.parent.name for e in c.elements),
                    c.referred_table.name,
                    tuple(e.column.name for e in c.elements),
                )
                for c in table.foreign_key_constraints
            }
            assert {c["name"] for c in inspector.get_check_constraints(table.name)} == {
                c.name for c in table.constraints if isinstance(c, sa.CheckConstraint)
            }
            assert {
                tuple(c["column_names"]) for c in inspector.get_unique_constraints(table.name)
            } == {
                tuple(c.name for c in con.columns)
                for con in table.constraints
                if isinstance(con, sa.UniqueConstraint)
            }
        assert EXPECTED_SCHEMA_REVISION == REVISION
        verify_operational_schema(engine, require_phase_zero_facts=False)
        command.downgrade(config, PRIOR)
        assert shapes(engine) == before
        verify_operational_schema(engine, expected_revision=PRIOR, require_phase_zero_facts=False)
    finally:
        engine.dispose()


@pytest.mark.parametrize("table", TABLES, ids=lambda t: t.name)
def test_downgrade_refuses_every_nonempty_w4_table_without_touching_history(tmp_path, table):
    config, checked_engine = migrated(tmp_path)
    checked_engine.dispose()
    # Corrupt orphan rows are deliberate fixtures: downgrade may not erase them.
    engine = sa.create_engine(database_url(config))
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("PRAGMA ignore_check_constraints=ON")
            connection.execute(table.insert().values(**malformed_values(table)))
        with pytest.raises(
            RuntimeError, match="refusing to downgrade nonempty personal continuous"
        ):
            command.downgrade(config, PRIOR)
        with engine.connect() as connection:
            assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == REVISION
            assert connection.scalar(sa.select(sa.func.count()).select_from(table)) == 1
        assert {t.name for t in TABLES} <= set(sa.inspect(engine).get_table_names())
    finally:
        engine.dispose()


@pytest.mark.parametrize("table", TABLES, ids=lambda t: t.name)
def test_readiness_requires_every_new_table_even_when_empty(tmp_path, table):
    _, engine = migrated(tmp_path)
    try:
        with engine.begin() as connection:
            table.drop(connection)
        with pytest.raises(DatabaseSchemaNotReady, match="schema is unavailable"):
            verify_operational_schema(engine, require_phase_zero_facts=False)
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "table",
    [JOURNAL_TABLES[0], DAILY_RUNTIME_TABLES[0], CONTINUOUS_ACCOUNT_TABLES[0]],
    ids=lambda t: t.name,
)
def test_readiness_requires_new_columns_even_without_history(tmp_path, table):
    _, engine = migrated(tmp_path)
    try:
        column = next(
            c
            for c in reversed(tuple(table.c))
            if c.name in {"last_entry_sha256", "recorded_at", "receipt_sha256"}
        )
        with engine.begin() as connection:
            connection.exec_driver_sql(f"ALTER TABLE {table.name} DROP COLUMN {column.name}")
        with pytest.raises(DatabaseSchemaNotReady, match="schema is unavailable"):
            verify_operational_schema(engine, require_phase_zero_facts=False)
    finally:
        engine.dispose()


def test_nonempty_w4_requires_reader_and_always_keeps_w3_codec_and_replay_checks(tmp_path):
    _, engine = migrated(tmp_path)
    try:
        journal(engine).append(key(), request())
        with pytest.raises(DatabaseSchemaNotReady, match="requires an integrity reader"):
            verify_operational_schema(engine, require_phase_zero_facts=False)
        reader = SnapshotReader()
        verify_operational_schema(
            engine, require_phase_zero_facts=False, continuous_integrity=reader
        )
        assert len(reader.snapshots) == 1
        assert len(reader.snapshots[0].tables[journal_entries.name]) == 1
        SqlResearchWorkflow(engine, codec=personal_codec).launch(sample_request())
        with pytest.raises(DatabaseSchemaNotReady, match="requires a record codec"):
            verify_operational_schema(
                engine, require_phase_zero_facts=False, continuous_integrity=reader
            )
        verify_operational_schema(
            engine,
            require_phase_zero_facts=False,
            research_codec=personal_codec,
            continuous_integrity=reader,
        )
        with engine.begin() as connection:
            connection.execute(research_jobs_v2.update().values(owner_id="corrupt-owner"))
        with pytest.raises(DatabaseSchemaNotReady, match="research SQL integrity"):
            verify_operational_schema(
                engine,
                require_phase_zero_facts=False,
                research_codec=personal_codec,
                continuous_integrity=reader,
            )
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "table", [t for t in TABLES if t.foreign_key_constraints], ids=lambda t: t.name
)
def test_readiness_checks_every_w4_foreign_key_parent_before_reader(tmp_path, table):
    config, checked_engine = migrated(tmp_path)
    checked_engine.dispose()
    unchecked = sa.create_engine(database_url(config))
    with unchecked.begin() as connection:
        connection.exec_driver_sql("PRAGMA ignore_check_constraints=ON")
        connection.execute(table.insert().values(**malformed_values(table)))
    unchecked.dispose()
    engine = create_database_engine(database_url(config))
    reader = SnapshotReader()
    try:
        with pytest.raises(DatabaseSchemaNotReady, match="orphan reference"):
            verify_operational_schema(
                engine, require_phase_zero_facts=False, continuous_integrity=reader
            )
        assert not reader.snapshots
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "change", ["payload", "key_payload", "text", "integer", "row_budget", "byte_budget"]
)
def test_sql_preflight_rejects_bad_or_oversized_fields_before_payload_transfer(
    tmp_path, monkeypatch, change
):
    _, engine = migrated(tmp_path)
    try:
        journal(engine).append(key(), request())
        with engine.begin() as connection:
            if change == "payload":
                connection.execute(journal_entries.update().values(payload=b"x" * (256 * 1024 + 1)))
            elif change == "key_payload":
                connection.execute(
                    journal_streams.update().values(key_payload=b"x" * (16 * 1024 + 1))
                )
            elif change == "text":
                connection.execute(journal_streams.update().values(last_entry_sha256="x" * 65))
            elif change == "integer":
                connection.exec_driver_sql("PRAGMA ignore_check_constraints=ON")
                connection.execute(journal_streams.update().values(last_sequence="x" * 1_000_000))
        if change == "row_budget":
            monkeypatch.setattr(database_module, "MAX_CONTINUOUS_INTEGRITY_ROWS", 1)
        if change == "byte_budget":
            monkeypatch.setattr(database_module, "MAX_CONTINUOUS_INTEGRITY_BYTES", 16)
        reader = SnapshotReader()
        statements = []

        def observe(_connection, _cursor, statement, _parameters, _context, _executemany):
            statements.append(statement)

        sa.event.listen(engine, "before_cursor_execute", observe)
        with pytest.raises(DatabaseSchemaNotReady, match="type or size bounds"):
            verify_operational_schema(
                engine, require_phase_zero_facts=False, continuous_integrity=reader
            )
        assert not reader.snapshots
        selected = (
            journal_entries.name
            if change == "payload"
            else JOURNAL_TABLES[1].name
            if change == "row_budget"
            else journal_streams.name
        )
        assert not any(s.startswith(f"SELECT {selected}.") for s in statements)
    finally:
        engine.dispose()


def test_paused_integrity_reader_runs_after_snapshot_release_and_next_read_rechecks_corruption(
    tmp_path,
):
    _, engine = migrated(tmp_path)
    store = journal(engine)
    first = store.append(key(), request())
    entered, release = Event(), Event()

    class PausingReader(SnapshotReader):
        def validate_snapshot(self, snapshot):
            entered.set()
            assert release.wait(10)
            super().validate_snapshot(snapshot)

    reader = PausingReader()
    try:
        with engine.connect() as connection:
            assert connection.scalar(sa.text("PRAGMA journal_mode")) == "delete"
        with ThreadPoolExecutor(max_workers=2) as pool:
            reading = pool.submit(
                verify_operational_schema,
                engine,
                require_phase_zero_facts=False,
                continuous_integrity=reader,
            )
            try:
                assert entered.wait(10)
                second = pool.submit(
                    store.append,
                    key(),
                    request(command="second", head=first.committed_head, records=(record("two"),)),
                ).result(timeout=3)
                assert second.committed_head.sequence == 2
            finally:
                release.set()
            reading.result(timeout=10)
        assert len(reader.snapshots[0].tables[journal_entries.name]) == 1
        fresh = SnapshotReader()
        verify_operational_schema(
            engine, require_phase_zero_facts=False, continuous_integrity=fresh
        )
        assert len(fresh.snapshots[0].tables[journal_entries.name]) == 2
        with engine.begin() as connection:
            connection.execute(journal_streams.update().values(last_entry_sha256="x" * 65))
        with pytest.raises(DatabaseSchemaNotReady, match="type or size bounds"):
            verify_operational_schema(
                engine, require_phase_zero_facts=False, continuous_integrity=fresh
            )
    finally:
        engine.dispose()


def test_reader_failure_is_static_and_does_not_expose_payload(tmp_path):
    _, engine = migrated(tmp_path)

    class FailingReader:
        def validate_snapshot(self, _snapshot):
            raise ValueError("PRIVATE_FIXTURE_PAYLOAD_SENTINEL")

    try:
        journal(engine).append(key(), request())
        with pytest.raises(DatabaseSchemaNotReady, match="continuous retained integrity") as error:
            verify_operational_schema(
                engine, require_phase_zero_facts=False, continuous_integrity=FailingReader()
            )
        assert "PRIVATE_FIXTURE" not in str(error.value)
        assert error.value.__cause__ is None
    finally:
        engine.dispose()


def test_frozen_migration_offline_ddl_and_postgres_lock_order(tmp_path, monkeypatch):
    module = importlib.import_module("migrations.versions.0040_personal_continuous")
    source = Path(module.__file__).read_text()
    assert not any(
        isinstance(n, ast.ImportFrom) and (n.module or "").startswith("packages")
        for n in ast.walk(ast.parse(source))
    )
    assert tuple(t.name for t in module._TABLES) == tuple(t.name for t in TABLES)
    for frozen, current in zip(module._TABLES, TABLES, strict=True):
        assert str(CreateTable(frozen).compile(dialect=postgresql.dialect())) == str(
            CreateTable(current).compile(dialect=postgresql.dialect())
        )
    config = migration_config(tmp_path / "never-opened.sqlite")
    output = StringIO()
    config.output_buffer = output
    command.upgrade(config, f"{PRIOR}:{REVISION}", sql=True)
    assert all(f"CREATE TABLE {t.name}" in output.getvalue() for t in TABLES)
    assert output.getvalue().index(
        "CREATE TABLE personal_continuous_account_commits"
    ) < output.getvalue().index("CREATE TABLE daily_runtime_attempt_events")
    attempt_parent = next(
        c
        for c in next(
            t for t in DAILY_RUNTIME_TABLES if t.name == "daily_runtime_attempt_events"
        ).foreign_key_constraints
        if c.name == "fk_daily_attempt_parent_command"
    )
    assert attempt_parent.deferrable and attempt_parent.initially == "DEFERRED"
    assert tuple(e.parent.name for e in attempt_parent.elements) == (
        "account_id",
        "coordinator_command_id",
        "coordinator_sequence",
    )
    observed_table = next(
        t for t in DAILY_RUNTIME_TABLES if t.name == "daily_runtime_observed_hold_groups"
    )
    observed_parent = next(
        c
        for c in observed_table.foreign_key_constraints
        if c.name == "fk_daily_observed_parent_command"
    )
    assert observed_parent.deferrable and observed_parent.initially == "DEFERRED"
    assert tuple(e.parent.name for e in observed_parent.elements) == (
        "account_id",
        "coordinator_command_id",
        "coordinator_sequence",
    )
    assert output.getvalue().index(
        "CREATE TABLE personal_continuous_account_commits"
    ) < output.getvalue().index("CREATE TABLE daily_runtime_observed_hold_groups")
    assert not (tmp_path / "never-opened.sqlite").exists()
    with pytest.raises(RuntimeError, match="requires online locked history"):
        command.downgrade(config, f"{REVISION}:{PRIOR}", sql=True)
    connection = MagicMock()
    connection.dialect = SimpleNamespace(name="postgresql")
    connection.execute.return_value.first.return_value = (1,)
    monkeypatch.setattr(module.op, "get_bind", lambda: connection)
    monkeypatch.setattr(module.op, "get_context", lambda: SimpleNamespace(as_sql=False))
    with pytest.raises(RuntimeError, match="refusing to downgrade nonempty"):
        module.downgrade()
    assert connection.method_calls[0].args == (
        "LOCK TABLE " + ", ".join(t.name for t in TABLES) + " IN ACCESS EXCLUSIVE MODE",
    )
