"""Local SQLite operating-mode checks using disposable data, without providers."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import sqlalchemy as sa
from sqlalchemy import Engine

from packages.persistence import sqlite_config
from packages.persistence.database import create_database_engine
from packages.persistence.sqlite_config import ResearchSQLiteConfigurationError

ROOT = Path(__file__).resolve().parents[2]


def _url(path: Path) -> str:
    return f"sqlite+pysqlite:///{path}"


def _settings(engine: Engine) -> tuple[object, ...]:
    with engine.connect() as connection:
        return tuple(
            connection.exec_driver_sql(f"PRAGMA {name}").scalar_one()
            for name in (
                "journal_mode",
                "synchronous",
                "foreign_keys",
                "busy_timeout",
                "wal_autocheckpoint",
            )
        )


def test_opt_in_sets_wal_full_on_each_physical_connection_and_retains_defaults(
    tmp_path: Path,
) -> None:
    engine = create_database_engine(_url(tmp_path / "research.sqlite"), research_sqlite_wal=True)
    try:
        with engine.connect() as first, engine.connect() as second:
            assert first.connection.driver_connection is not second.connection.driver_connection
            for connection in (first, second):
                assert connection.exec_driver_sql("PRAGMA journal_mode").scalar_one() == "wal"
                assert connection.exec_driver_sql("PRAGMA synchronous").scalar_one() == 2
                assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
                assert connection.exec_driver_sql("PRAGMA busy_timeout").scalar_one() == 5000
                assert connection.exec_driver_sql("PRAGMA wal_autocheckpoint").scalar_one() == 1000
        with engine.begin() as connection:
            connection.exec_driver_sql("CREATE TABLE parent (id INTEGER PRIMARY KEY)")
            connection.exec_driver_sql(
                "CREATE TABLE child (parent_id INTEGER REFERENCES parent(id))"
            )
        with pytest.raises(sa.exc.IntegrityError), engine.begin() as connection:
            connection.exec_driver_sql("INSERT INTO child VALUES (1)")
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "url",
    (
        "sqlite+pysqlite://",
        "sqlite+pysqlite:///:memory:",
        "sqlite+pysqlite:///file::memory:?cache=shared&uri=true",
        "sqlite+pysqlite:///file:research-memory?mode=memory&cache=shared&uri=true",
    ),
)
def test_opt_in_leaves_memory_databases_unchanged(
    url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden_version_check(_version: str) -> bool:
        raise AssertionError("memory databases must not enter the WAL admission gate")

    monkeypatch.setattr(sqlite_config, "_supports_research_wal", forbidden_version_check)
    engine = create_database_engine(url, research_sqlite_wal=True)
    try:
        assert _settings(engine) == ("memory", 2, 1, 5000, 1000)
    finally:
        engine.dispose()


def test_default_file_mode_preserves_delete_and_does_not_apply_version_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sqlite_config, "_supports_research_wal", lambda _version: False)
    engine = create_database_engine(_url(tmp_path / "legacy.sqlite"))
    try:
        assert _settings(engine) == ("delete", 2, 1, 5000, 1000)
    finally:
        engine.dispose()


def test_non_sqlite_configuration_has_no_connection_listener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = MagicMock(spec=Engine)
    engine.dialect = MagicMock(name="postgresql")
    engine.dialect.name = "postgresql"
    listen = MagicMock()
    monkeypatch.setattr(sqlite_config.event, "listen", listen)
    assert sqlite_config.configure_research_sqlite(engine) is engine
    listen.assert_not_called()


@pytest.mark.parametrize(
    ("version", "supported"),
    (
        ("3.44.5", False),
        ("3.44.6", True),
        ("3.44.7", True),
        ("3.45.9", False),
        ("3.49.9", False),
        ("3.50.6", False),
        ("3.50.7", True),
        ("3.50.8", True),
        ("3.51.0", False),
        ("3.51.2", False),
        ("3.51.3", True),
        ("3.52.0", True),
        ("3.53.1", True),
        ("3.51", False),
        ("3.51.3 patched", False),
        ("unknown", False),
    ),
)
def test_runtime_admission_is_limited_to_fixed_releases(version: str, supported: bool) -> None:
    assert sqlite_config._supports_research_wal(version) is supported


def test_unsupported_runtime_rejects_before_changing_journal_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "unsupported.sqlite"
    monkeypatch.setattr(sqlite_config, "_supports_research_wal", lambda _version: False)
    engine = create_database_engine(_url(path), research_sqlite_wal=True)
    try:
        with pytest.raises(ResearchSQLiteConfigurationError, match="runtime"):
            engine.connect()
        with sqlite3.connect(path) as connection:
            assert connection.execute("PRAGMA journal_mode").fetchone() == ("delete",)
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    ("responses", "message", "last_statement"),
    (
        ([("3.53.1",), ("delete",)], "WAL mode", "PRAGMA journal_mode=WAL"),
        ([("3.53.1",), None], "WAL mode", "PRAGMA journal_mode=WAL"),
        ([("3.53.1",), ("wal",), (1,)], "FULL", "PRAGMA synchronous"),
        ([("3.53.1",), ("wal",), (2,), (0,)], "foreign keys", "PRAGMA foreign_keys"),
    ),
)
def test_unavailable_connection_policy_fails_without_fallback(
    responses: list[tuple[object, ...] | None], message: str, last_statement: str
) -> None:
    connection = MagicMock()
    cursor = connection.cursor.return_value
    cursor.fetchall.return_value = [(0, "main", "/test-only/database.sqlite")]
    cursor.fetchone.side_effect = responses
    with pytest.raises(ResearchSQLiteConfigurationError, match=message):
        sqlite_config._enable_research_wal(connection, MagicMock())
    assert cursor.execute.call_args.args == (last_statement,)
    cursor.close.assert_called_once()


def test_writer_commits_while_reader_snapshot_is_open_and_backup_retains_committed_wal(
    tmp_path: Path,
) -> None:
    path = tmp_path / "concurrent.sqlite"
    backup_path = tmp_path / "backup.sqlite"
    engine = create_database_engine(_url(path), research_sqlite_wal=True)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("CREATE TABLE facts (id INTEGER PRIMARY KEY)")
            connection.exec_driver_sql("INSERT INTO facts VALUES (1)")
        with engine.connect() as reader:
            reader.exec_driver_sql("BEGIN")
            assert reader.exec_driver_sql("SELECT count(*) FROM facts").scalar_one() == 1
            with engine.begin() as writer:
                writer.exec_driver_sql("INSERT INTO facts VALUES (2)")
            # COMMIT above completes while the reader still retains the old snapshot.
            assert reader.exec_driver_sql("SELECT count(*) FROM facts").scalar_one() == 1
            assert Path(f"{path}-wal").stat().st_size > 0
            with sqlite3.connect(path) as source, sqlite3.connect(backup_path) as destination:
                source.backup(destination)
                assert destination.execute("SELECT count(*) FROM facts").fetchone() == (2,)
            reader.rollback()
            assert reader.exec_driver_sql("SELECT count(*) FROM facts").scalar_one() == 2
    finally:
        engine.dispose()
    with sqlite3.connect(backup_path) as restored:
        assert restored.execute("SELECT id FROM facts ORDER BY id").fetchall() == [(1,), (2,)]


def test_new_process_retains_data_and_reestablishes_per_connection_full(tmp_path: Path) -> None:
    path = tmp_path / "restart.sqlite"
    script = """
import json
import sys
from packages.persistence.database import create_database_engine
engine = create_database_engine(sys.argv[1], research_sqlite_wal=True)
with engine.begin() as connection:
    if sys.argv[2] == 'write':
        connection.exec_driver_sql('CREATE TABLE facts (value INTEGER)')
        connection.exec_driver_sql('INSERT INTO facts VALUES (37)')
    result = {name: connection.exec_driver_sql('PRAGMA ' + name).scalar_one()
              for name in ('journal_mode', 'synchronous', 'foreign_keys')}
    result['value'] = connection.exec_driver_sql('SELECT value FROM facts').scalar_one()
print(json.dumps(result, sort_keys=True))
engine.dispose()
"""
    for operation in ("write", "read"):
        process = subprocess.run(
            [sys.executable, "-B", "-c", script, _url(path), operation],
            cwd=tmp_path,
            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1"},
            text=True,
            capture_output=True,
            check=True,
            timeout=30,
        )
        assert json.loads(process.stdout) == {
            "journal_mode": "wal",
            "synchronous": 2,
            "foreign_keys": 1,
            "value": 37,
        }


@pytest.mark.parametrize("enabled", (False, True))
def test_api_only_opts_in_for_its_own_research_engine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, enabled: bool
) -> None:
    from apps.api import main
    from apps.api.config import Settings

    created: list[Engine] = []
    options: list[bool] = []

    def create(url: str, *, research_sqlite_wal: bool = False) -> Engine:
        options.append(research_sqlite_wal)
        engine = create_database_engine(url, research_sqlite_wal=research_sqlite_wal)
        created.append(engine)
        return engine

    monkeypatch.setattr(main, "create_database_engine", create)
    try:
        main.create_app(
            Settings(
                database_url=_url(tmp_path / "api.sqlite"),
                research_artifacts_path=tmp_path / "objects" if enabled else None,
            )
        )
        assert options == [enabled]
        assert _settings(created[0])[0] == ("wal" if enabled else "delete")
    finally:
        for engine in created:
            engine.dispose()


def test_api_injected_engine_retains_caller_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apps.api import main
    from apps.api.config import Settings

    factory = MagicMock(side_effect=AssertionError("injected engine must not be replaced"))
    monkeypatch.setattr(main, "create_database_engine", factory)
    engine = create_database_engine(_url(tmp_path / "injected.sqlite"))
    try:
        main.create_app(Settings(research_artifacts_path=tmp_path / "objects"), engine=engine)
        factory.assert_not_called()
        assert _settings(engine)[0] == "delete"
    finally:
        engine.dispose()


def test_api_fails_closed_when_research_wal_runtime_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apps.api import main
    from apps.api.config import Settings

    monkeypatch.setattr(sqlite_config, "_supports_research_wal", lambda _version: False)
    app = main.create_app(
        Settings(
            database_url=_url(tmp_path / "unavailable-api.sqlite"),
            research_artifacts_path=tmp_path / "objects",
        )
    )
    assert app.state.persistence_ready is False
    assert app.state.persistence_error == "operational persistence unavailable"
    assert not (tmp_path / "objects").exists()


@pytest.mark.parametrize("operation", ("init", "work"))
def test_durable_cli_opts_in_and_rejects_unavailable_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    operation: str,
) -> None:
    from apps.worker import research_jobs

    options: list[bool] = []

    def unavailable(_url: str, *, research_sqlite_wal: bool = False) -> Engine:
        options.append(research_sqlite_wal)
        if not research_sqlite_wal:
            return create_database_engine(_url)
        raise ResearchSQLiteConfigurationError("test-only unavailable mode")

    monkeypatch.setattr(research_jobs, "create_database_engine", unavailable)
    assert (
        research_jobs.main(
            [
                "--database-url",
                _url(tmp_path / "cli.sqlite"),
                "--artifacts",
                str(tmp_path / "objects"),
                operation,
            ]
        )
        == 2
    )
    assert options == ([False, True] if operation == "init" else [True])
    assert json.loads(capsys.readouterr().out) == {
        "status": "rejected",
        "reason": "research-setup-or-runtime-unavailable",
        "trading_authorized": False,
    }


def test_rejected_init_does_not_convert_an_existing_database(tmp_path: Path) -> None:
    from apps.worker import research_jobs

    path = tmp_path / "existing.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE retained_fact (value INTEGER)")
        connection.execute("INSERT INTO retained_fact VALUES (41)")
    assert (
        research_jobs.main(
            ["--database-url", _url(path), "--artifacts", str(tmp_path / "objects"), "init"]
        )
        == 2
    )
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone() == ("delete",)
        assert connection.execute("SELECT value FROM retained_fact").fetchone() == (41,)
    assert not (tmp_path / "objects").exists()


def test_cli_initialization_and_empty_worker_use_persisted_wal(tmp_path: Path) -> None:
    from apps.worker import research_jobs

    path = tmp_path / "cli.sqlite"
    common = ["--database-url", _url(path), "--artifacts", str(tmp_path / "objects")]
    assert research_jobs.main([*common, "init"]) == 0
    assert research_jobs.main([*common, "work", "--once"]) == 0
    engine = create_database_engine(_url(path), research_sqlite_wal=True)
    try:
        assert _settings(engine) == ("wal", 2, 1, 5000, 1000)
        with engine.connect() as connection:
            assert connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version"
            ).scalar_one() == ("0039_personal_research")
    finally:
        engine.dispose()
