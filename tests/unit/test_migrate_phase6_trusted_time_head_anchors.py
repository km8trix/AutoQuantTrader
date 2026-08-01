from __future__ import annotations

import json
import stat
import subprocess
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any, cast
from unittest.mock import MagicMock

import pytest
from sqlalchemy import Engine
from sqlalchemy.engine import Connection

import scripts.migrate_phase6_trusted_time_head_anchors as migration_operator
from packages.persistence.postgres_tls import SUPABASE_DATABASE_CA_SHA256
from scripts.migrate_phase6_trusted_time_head_anchors import (
    CatalogSnapshot,
    MigrationOperatorError,
    apply_runtime,
    check_static_bindings,
    load_environment_bindings,
    preflight_runtime,
    read_and_validate_preflight_artifact,
    verify_postflight_catalog,
    verify_preflight_catalog,
    write_owner_only_artifact,
)
from scripts.migrate_phase6_trusted_time_head_anchors import (
    test_postgres as run_test_postgres,
)

RUNTIME_URL = (
    "postgresql+psycopg://postgres.abcdefghijklmnopqrst:runtime-password@"
    "aws-0-us-east-1.pooler.supabase.com:5432/postgres?sslmode=verify-full"
)
TEST_URL = (
    "postgresql+psycopg://postgres.bcdefghijklmnopqrstu:test-password@"
    "aws-0-us-east-2.pooler.supabase.com:5432/postgres?sslmode=verify-full"
)


def _write_environment(
    path: Path,
    *,
    runtime_url: str = RUNTIME_URL,
    test_url: str = TEST_URL,
) -> Path:
    path.write_text(
        "IGNORED_SECRET=must-not-be-loaded\n"
        f"AQT_DATABASE_URL={runtime_url}\n"
        f"AQT_TEST_POSTGRES_URL={test_url}\n"
        "PGPASSWORD=must-not-be-loaded\n",
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def _snapshot(
    *,
    postflight: bool,
    database_time_unix_seconds: int = 1_000,
    server_major_version: int = 16,
    local_history_counts: tuple[int, int, int] = (3, 5, 2),
) -> CatalogSnapshot:
    return CatalogSnapshot(
        revision=(
            migration_operator.TARGET_REVISION if postflight else migration_operator.PRIOR_REVISION
        ),
        database_time_unix_seconds=database_time_unix_seconds,
        server_major_version=server_major_version,
        tls_active=True,
        public_schema_active=True,
        public_search_path_only=True,
        local_history_counts=tuple(
            zip(migration_operator._BASE_TABLES, local_history_counts, strict=True)
        ),
        base_catalog_sha256=migration_operator._EXPECTED_BASE_CATALOG_SHA256,
        anchor_relations=(migration_operator._EXPECTED_RELATIONS if postflight else ()),
        anchor_table_counts=(
            tuple((table, 0) for table in migration_operator._ANCHOR_TABLES) if postflight else ()
        ),
        columns=(
            tuple(
                (table, migration_operator._EXPECTED_COLUMNS[table])
                for table in migration_operator._ANCHOR_TABLES
            )
            if postflight
            else ()
        ),
        constraints=(
            tuple(
                (table, migration_operator._EXPECTED_CONSTRAINTS[table])
                for table in migration_operator._ANCHOR_TABLES
            )
            if postflight
            else ()
        ),
        indexes=(
            tuple(
                (table, migration_operator._INDEX_CONTRACTS[table])
                for table in migration_operator._ANCHOR_TABLES
            )
            if postflight
            else ()
        ),
    )


def _mock_engine() -> tuple[Engine, Connection, MagicMock]:
    raw_engine = MagicMock(spec=Engine)
    raw_connection = MagicMock(spec=Connection)
    raw_engine.connect.return_value.__enter__.return_value = raw_connection
    raw_engine.begin.return_value.__enter__.return_value = raw_connection
    return cast(Engine, raw_engine), cast(Connection, raw_connection), raw_engine


def _write_preflight(path: Path, env_file: Path, *, now_seconds: int) -> str:
    static = check_static_bindings()
    environment = load_environment_bindings(env_file)
    body = migration_operator._artifact_body(
        artifact_type=migration_operator._PREFLIGHT_ARTIFACT_TYPE,
        static=static,
        environment=environment,
        database=_snapshot(postflight=False, database_time_unix_seconds=now_seconds),
        now_seconds=now_seconds,
    )
    return write_owner_only_artifact(path, migration_operator._seal_artifact(body))


def test_static_bindings_pin_exact_migration_ca_graph_and_schema_catalog() -> None:
    bindings = check_static_bindings()

    assert bindings.migration_sha256 == migration_operator.EXPECTED_MIGRATION_SHA256
    assert bindings.database_ca_sha256 == SUPABASE_DATABASE_CA_SHA256
    assert len(bindings.source_state_sha256) == 64
    assert migration_operator._TEST_POSTGRES_PATH in migration_operator._SOURCE_BINDING_PATHS
    assert Path("migrations/versions/0035_phase6_trusted_time_uncertainty.py") in (
        migration_operator._SOURCE_BINDING_PATHS
    )
    assert set(migration_operator._EXPECTED_COLUMNS) == set(migration_operator._ANCHOR_TABLES)
    assert "fk_phase6_anchor_intent_evaluation" in {
        name
        for name, _kind, _definition, _validated, _enforced in (
            migration_operator._EXPECTED_CONSTRAINTS["phase6_trusted_time_head_anchor_intents"]
        )
    }
    assert "fk_phase6_anchor_receipt_intent" in {
        name
        for name, _kind, _definition, _validated, _enforced in (
            migration_operator._EXPECTED_CONSTRAINTS["phase6_trusted_time_head_anchor_receipts"]
        )
    }


@pytest.mark.parametrize("mode", [0o400, 0o600])
def test_environment_loader_reads_only_distinct_verify_full_session_poolers(
    tmp_path: Path,
    mode: int,
) -> None:
    env_file = _write_environment(tmp_path / ".env")
    env_file.chmod(mode)

    bindings = load_environment_bindings(env_file)

    assert bindings.runtime_database_url == RUNTIME_URL
    assert bindings.test_database_url == TEST_URL
    assert "runtime-password" not in repr(bindings)
    assert "test-password" not in repr(bindings)
    assert set(bindings.public_payload) == {
        "database_targets_sha256",
        "owner_environment_version_sha256",
    }


@pytest.mark.parametrize(
    ("runtime_url", "test_url", "reason"),
    [
        (RUNTIME_URL, RUNTIME_URL, "runtime_test_database_reuse_rejected"),
        (
            RUNTIME_URL.replace("verify-full", "require"),
            TEST_URL,
            "database_url_not_supabase_session_tls",
        ),
    ],
)
def test_environment_loader_rejects_shared_or_unpinned_targets(
    tmp_path: Path,
    runtime_url: str,
    test_url: str,
    reason: str,
) -> None:
    env_file = _write_environment(
        tmp_path / ".env",
        runtime_url=runtime_url,
        test_url=test_url,
    )

    with pytest.raises(MigrationOperatorError, match=reason):
        load_environment_bindings(env_file)


@pytest.mark.parametrize("server_major_version", [16, 17])
def test_catalog_contract_allows_nonempty_local_history_and_exact_anchor_addition(
    server_major_version: int,
) -> None:
    preflight = _snapshot(postflight=False, server_major_version=server_major_version)
    postflight = _snapshot(postflight=True, server_major_version=server_major_version)

    verify_preflight_catalog(preflight)
    verify_postflight_catalog(postflight)
    assert dict(preflight.local_history_counts) == {
        "phase6_trusted_time_epoch_registrations": 3,
        "phase6_trusted_time_probe_evaluations": 5,
        "phase6_trusted_time_host_heads": 2,
    }


def test_catalog_contract_rejects_preexisting_anchor_relation_and_postflight_drift() -> None:
    preflight = _snapshot(postflight=False)
    with pytest.raises(MigrationOperatorError, match="runtime_preflight_rejected"):
        verify_preflight_catalog(
            replace(
                preflight,
                anchor_relations=(migration_operator._EXPECTED_RELATIONS[0],),
            )
        )

    postflight = _snapshot(postflight=True)
    table, entries = postflight.constraints[0]
    changed = list(entries[0])
    changed[2] = "0" * 64
    with pytest.raises(MigrationOperatorError, match="runtime_postflight_rejected"):
        verify_postflight_catalog(
            replace(
                postflight,
                constraints=(
                    (
                        table,
                        (cast(migration_operator.ConstraintContract, tuple(changed)), *entries[1:]),
                    ),
                    *postflight.constraints[1:],
                ),
            )
        )


@pytest.mark.parametrize("server_major_version", [15, 18, True])
def test_catalog_contract_rejects_unsupported_postgres_major(
    server_major_version: object,
) -> None:
    with pytest.raises(MigrationOperatorError, match="postgres_server_major_unsupported"):
        verify_preflight_catalog(
            replace(
                _snapshot(postflight=False),
                server_major_version=cast(int, server_major_version),
            )
        )


def test_catalog_structural_proof_uses_stable_nonpretty_postgres_definitions() -> None:
    source = (
        migration_operator.ROOT / "scripts/migrate_phase6_trusted_time_head_anchors.py"
    ).read_text(encoding="utf-8")

    assert "pg_get_expr(default_row.adbin, default_row.adrelid, false)" in source
    assert "pg_get_constraintdef(constraint_row.oid, false)" in source
    assert "pg_get_indexdef(index_row.oid, 0, false)" in source
    assert frozenset({16, 17}) == migration_operator.SUPPORTED_POSTGRES_MAJOR_VERSIONS


def test_preflight_writes_owner_only_secret_free_artifact_and_verifies_0035(
    tmp_path: Path,
) -> None:
    env_file = _write_environment(tmp_path / ".env")
    artifact_path = tmp_path / "preflight.json"
    engine, connection, raw_engine = _mock_engine()
    cast(Any, connection).scalar.return_value = 1_000
    schema_calls: list[tuple[Engine, bool, str]] = []

    def schema_verifier(
        candidate_engine: Engine,
        *,
        require_phase_zero_facts: bool,
        expected_revision: str,
    ) -> None:
        schema_calls.append((candidate_engine, require_phase_zero_facts, expected_revision))

    result = preflight_runtime(
        env_file=env_file,
        artifact_path=artifact_path,
        engine_factory=lambda _url: engine,
        catalog_reader=lambda _connection: _snapshot(postflight=False),
        schema_verifier=schema_verifier,
    )

    payload = artifact_path.read_bytes()
    decoded = json.loads(payload)
    assert result["status"] == "ready"
    assert schema_calls == [(engine, False, migration_operator.PRIOR_REVISION)]
    assert stat.S_IMODE(artifact_path.stat().st_mode) == 0o600
    assert payload == migration_operator._canonical_json_bytes(decoded)
    assert decoded["restore_capable"] is False
    assert decoded["database"]["local_history_counts"]
    assert RUNTIME_URL.encode() not in payload
    assert TEST_URL.encode() not in payload
    assert b"pooler.supabase.com" not in payload
    raw_engine.dispose.assert_called_once_with()


def test_preflight_artifact_rejects_modification_and_expiration(tmp_path: Path) -> None:
    env_file = _write_environment(tmp_path / ".env")
    artifact_path = tmp_path / "preflight.json"
    _write_preflight(artifact_path, env_file, now_seconds=1_000)
    static = check_static_bindings()
    environment = load_environment_bindings(env_file)
    decoded = json.loads(artifact_path.read_bytes())
    decoded["database"]["tls_active"] = False
    artifact_path.write_bytes(migration_operator._canonical_json_bytes(decoded))
    artifact_path.chmod(0o600)

    with pytest.raises(MigrationOperatorError, match="preflight_artifact_modified"):
        read_and_validate_preflight_artifact(
            artifact_path,
            static=static,
            environment=environment,
            now_seconds=1_001,
        )

    artifact_path.unlink()
    _write_preflight(artifact_path, env_file, now_seconds=1_000)
    with pytest.raises(MigrationOperatorError, match="preflight_artifact_stale"):
        read_and_validate_preflight_artifact(
            artifact_path,
            static=static,
            environment=environment,
            now_seconds=1_900,
        )


def test_apply_runs_exact_additive_boundary_and_accepts_new_local_history(
    tmp_path: Path,
) -> None:
    env_file = _write_environment(tmp_path / ".env")
    preflight_path = tmp_path / "preflight.json"
    postflight_path = tmp_path / "postflight.json"
    _write_preflight(preflight_path, env_file, now_seconds=5_000)
    engine, connection, raw_engine = _mock_engine()
    cast(Any, connection).scalar.side_effect = [True, 5_001, 5_001]
    snapshots: Iterator[CatalogSnapshot] = iter(
        (
            _snapshot(postflight=False, local_history_counts=(4, 7, 3)),
            _snapshot(postflight=True, database_time_unix_seconds=5_002),
            _snapshot(postflight=True, database_time_unix_seconds=5_003),
        )
    )
    migration_calls: list[tuple[Connection, str]] = []
    schema_calls: list[tuple[Engine, bool, str]] = []

    def migration_runner(
        candidate_connection: Connection,
        bindings: migration_operator.StaticBindings,
    ) -> None:
        migration_calls.append((candidate_connection, bindings.migration_sha256))

    def schema_verifier(
        candidate_engine: Engine,
        *,
        require_phase_zero_facts: bool,
        expected_revision: str,
    ) -> None:
        schema_calls.append((candidate_engine, require_phase_zero_facts, expected_revision))

    result = apply_runtime(
        env_file=env_file,
        preflight_artifact_path=preflight_path,
        postflight_artifact_path=postflight_path,
        engine_factory=lambda _url: engine,
        catalog_reader=lambda _connection: next(snapshots),
        migration_runner=cast(migration_operator.MigrationRunner, migration_runner),
        schema_verifier=schema_verifier,
    )

    assert result["migration_committed"] is True
    assert migration_calls == [(connection, migration_operator.EXPECTED_MIGRATION_SHA256)]
    assert schema_calls == [
        (engine, False, migration_operator.PRIOR_REVISION),
        (engine, False, migration_operator.TARGET_REVISION),
    ]
    postflight = json.loads(postflight_path.read_bytes())
    assert postflight["database"]["revision"] == migration_operator.TARGET_REVISION
    assert postflight["restore_capable"] is False
    assert RUNTIME_URL not in postflight_path.read_text(encoding="utf-8")
    sql_calls = [str(call.args[0]) for call in cast(Any, connection).exec_driver_sql.call_args_list]
    assert any("SHARE ROW EXCLUSIVE" in statement for statement in sql_calls)
    raw_engine.dispose.assert_called_once_with()


def test_apply_rolls_back_catalog_drift_before_commit(tmp_path: Path) -> None:
    env_file = _write_environment(tmp_path / ".env")
    preflight_path = tmp_path / "preflight.json"
    _write_preflight(preflight_path, env_file, now_seconds=5_000)
    engine, connection, _raw_engine = _mock_engine()
    cast(Any, connection).scalar.side_effect = [True, 5_001, 5_001]
    invalid_postflight = replace(
        _snapshot(postflight=True),
        anchor_table_counts=(
            ("phase6_trusted_time_head_anchor_intents", 1),
            ("phase6_trusted_time_head_anchor_receipts", 0),
        ),
    )
    snapshots: Iterator[CatalogSnapshot] = iter((_snapshot(postflight=False), invalid_postflight))

    with pytest.raises(MigrationOperatorError, match="runtime_postflight_rejected") as captured:
        apply_runtime(
            env_file=env_file,
            preflight_artifact_path=preflight_path,
            postflight_artifact_path=tmp_path / "postflight.json",
            engine_factory=lambda _url: engine,
            catalog_reader=lambda _connection: next(snapshots),
            migration_runner=lambda _connection, _bindings: None,
            schema_verifier=lambda _engine, **_kwargs: None,
        )

    assert captured.value.migration_committed is False
    assert not (tmp_path / "postflight.json").exists()


def test_apply_reprobes_lost_commit_ack_and_writes_postflight(tmp_path: Path) -> None:
    env_file = _write_environment(tmp_path / ".env")
    preflight_path = tmp_path / "preflight.json"
    postflight_path = tmp_path / "postflight.json"
    _write_preflight(preflight_path, env_file, now_seconds=5_000)
    original, original_connection, raw_original = _mock_engine()
    probe, _probe_connection, _raw_probe = _mock_engine()
    verifier, _verifier_connection, _raw_verifier = _mock_engine()
    cast(Any, original_connection).scalar.side_effect = [True, 5_001, 5_001]
    raw_original.begin.return_value.__exit__.side_effect = RuntimeError("lost commit ack")
    engines: Iterator[Engine] = iter((original, probe, verifier))
    snapshots: Iterator[CatalogSnapshot] = iter(
        (
            _snapshot(postflight=False),
            _snapshot(postflight=True, database_time_unix_seconds=5_001),
            _snapshot(postflight=True, database_time_unix_seconds=5_002),
            _snapshot(postflight=True, database_time_unix_seconds=5_003),
        )
    )

    result = apply_runtime(
        env_file=env_file,
        preflight_artifact_path=preflight_path,
        postflight_artifact_path=postflight_path,
        engine_factory=lambda _url: next(engines),
        catalog_reader=lambda _connection: next(snapshots),
        migration_runner=lambda _connection, _bindings: None,
        schema_verifier=lambda _engine, **_kwargs: None,
    )

    assert result["migration_committed"] is True
    assert json.loads(postflight_path.read_bytes())["database"]["revision"] == (
        migration_operator.TARGET_REVISION
    )


def test_apply_reports_unknown_when_ambiguous_commit_cannot_be_reprobed(
    tmp_path: Path,
) -> None:
    env_file = _write_environment(tmp_path / ".env")
    preflight_path = tmp_path / "preflight.json"
    _write_preflight(preflight_path, env_file, now_seconds=5_000)
    original, original_connection, raw_original = _mock_engine()
    probe, _probe_connection, raw_probe = _mock_engine()
    cast(Any, original_connection).scalar.side_effect = [True, 5_001, 5_001]
    raw_original.begin.return_value.__exit__.side_effect = RuntimeError("lost commit ack")
    raw_probe.begin.return_value.__enter__.side_effect = RuntimeError("probe unavailable")
    engines: Iterator[Engine] = iter((original, probe))
    snapshots: Iterator[CatalogSnapshot] = iter(
        (_snapshot(postflight=False), _snapshot(postflight=True))
    )

    with pytest.raises(
        MigrationOperatorError,
        match="migration_commit_outcome_unknown",
    ) as captured:
        apply_runtime(
            env_file=env_file,
            preflight_artifact_path=preflight_path,
            postflight_artifact_path=tmp_path / "postflight.json",
            engine_factory=lambda _url: next(engines),
            catalog_reader=lambda _connection: next(snapshots),
            migration_runner=lambda _connection, _bindings: None,
            schema_verifier=lambda _engine, **_kwargs: None,
        )

    assert captured.value.migration_committed is None
    assert not (tmp_path / "postflight.json").exists()


def test_apply_reports_rollback_only_after_exact_0035_reprobe(tmp_path: Path) -> None:
    env_file = _write_environment(tmp_path / ".env")
    preflight_path = tmp_path / "preflight.json"
    _write_preflight(preflight_path, env_file, now_seconds=5_000)
    original, original_connection, raw_original = _mock_engine()
    probe, _probe_connection, _raw_probe = _mock_engine()
    cast(Any, original_connection).scalar.side_effect = [True, 5_001, 5_001]
    raw_original.begin.return_value.__exit__.side_effect = RuntimeError("lost commit ack")
    engines: Iterator[Engine] = iter((original, probe))
    snapshots: Iterator[CatalogSnapshot] = iter(
        (
            _snapshot(postflight=False),
            _snapshot(postflight=True),
            _snapshot(postflight=False, database_time_unix_seconds=5_002),
        )
    )

    with pytest.raises(MigrationOperatorError, match="migration_operation_failed") as captured:
        apply_runtime(
            env_file=env_file,
            preflight_artifact_path=preflight_path,
            postflight_artifact_path=tmp_path / "postflight.json",
            engine_factory=lambda _url: next(engines),
            catalog_reader=lambda _connection: next(snapshots),
            migration_runner=lambda _connection, _bindings: None,
            schema_verifier=lambda _engine, **_kwargs: None,
        )

    assert captured.value.migration_committed is False


@pytest.mark.parametrize(
    "interruption",
    [KeyboardInterrupt("secret-interrupt"), SystemExit("secret-exit")],
)
def test_apply_reprobes_interrupted_commit_before_reporting(
    tmp_path: Path,
    interruption: BaseException,
) -> None:
    env_file = _write_environment(tmp_path / ".env")
    preflight_path = tmp_path / "preflight.json"
    postflight_path = tmp_path / "postflight.json"
    _write_preflight(preflight_path, env_file, now_seconds=5_000)
    original, original_connection, raw_original = _mock_engine()
    probe, _probe_connection, _raw_probe = _mock_engine()
    verifier, _verifier_connection, _raw_verifier = _mock_engine()
    cast(Any, original_connection).scalar.side_effect = [True, 5_001, 5_001]
    raw_original.begin.return_value.__exit__.side_effect = interruption
    engines: Iterator[Engine] = iter((original, probe, verifier))
    snapshots: Iterator[CatalogSnapshot] = iter(
        (
            _snapshot(postflight=False),
            _snapshot(postflight=True),
            _snapshot(postflight=True, database_time_unix_seconds=5_002),
            _snapshot(postflight=True, database_time_unix_seconds=5_003),
        )
    )

    with pytest.raises(MigrationOperatorError, match="migration_interrupted") as captured:
        apply_runtime(
            env_file=env_file,
            preflight_artifact_path=preflight_path,
            postflight_artifact_path=postflight_path,
            engine_factory=lambda _url: next(engines),
            catalog_reader=lambda _connection: next(snapshots),
            migration_runner=lambda _connection, _bindings: None,
            schema_verifier=lambda _engine, **_kwargs: None,
        )

    assert captured.value.interrupted is True
    assert captured.value.migration_committed is True
    assert postflight_path.exists()
    assert "secret" not in json.dumps(migration_operator._safe_failure(captured.value))


def test_test_postgres_child_environment_strips_ambient_database_secrets() -> None:
    child = migration_operator._test_postgres_child_environment(
        TEST_URL,
        {
            "AQT_DATABASE_URL": RUNTIME_URL,
            "AQT_OTHER_SECRET": "secret",
            "LANG": "en_US.UTF-8",
            "PATH": "/usr/bin",
            "PGPASSWORD": "secret",
            "PYTHONPATH": "/untrusted",
        },
    )

    assert child["AQT_DATABASE_URL"] == TEST_URL
    assert child["AQT_TEST_POSTGRES_URL"] == TEST_URL
    assert child["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert all(not key.startswith("PG") for key in child)
    assert "AQT_OTHER_SECRET" not in child


def test_test_postgres_spawns_only_designated_phase6d_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_file = _write_environment(tmp_path / ".env")
    observed: dict[str, Any] = {}

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed["argv"] = argv
        observed.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, stdout="1 passed in 1.00s\n", stderr="")

    monkeypatch.setattr(
        "scripts.migrate_phase6_trusted_time_head_anchors.subprocess.run",
        fake_run,
    )

    result, exit_code = run_test_postgres(env_file=env_file)

    assert exit_code == 0
    assert result["status"] == "passed"
    assert observed["argv"][-1] == str(migration_operator._TEST_POSTGRES_PATH)
    child_environment = cast(dict[str, str], observed["env"])
    assert child_environment["AQT_DATABASE_URL"] == TEST_URL
    assert RUNTIME_URL not in child_environment.values()


def test_test_postgres_discards_child_failure_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_file = _write_environment(tmp_path / ".env")
    leaked = f"connection failed for {TEST_URL}"

    def fake_run(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            argv,
            1,
            stdout="1 failed in 1.00s\n",
            stderr=leaked,
        )

    monkeypatch.setattr(
        "scripts.migrate_phase6_trusted_time_head_anchors.subprocess.run",
        fake_run,
    )

    result, exit_code = run_test_postgres(env_file=env_file)

    assert exit_code == 2
    assert result["status"] == "failed"
    assert leaked not in json.dumps(result)
    assert TEST_URL not in json.dumps(result)


def test_cli_never_echoes_unexpected_exception_text(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = "postgresql+psycopg://user:do-not-print@example.invalid/db"

    def fail() -> migration_operator.StaticBindings:
        raise RuntimeError(secret)

    monkeypatch.setattr(migration_operator, "check_static_bindings", fail)

    assert migration_operator.main(["check-bindings"]) == 2
    output = capsys.readouterr().out
    assert secret not in output
    assert json.loads(output)["reason"] == "internal_operator_failure"


@pytest.mark.parametrize(
    "interruption",
    [KeyboardInterrupt("secret-interrupt"), SystemExit("secret-exit")],
)
def test_cli_sanitizes_fatal_interruption(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    interruption: BaseException,
) -> None:
    def fail() -> migration_operator.StaticBindings:
        raise interruption

    monkeypatch.setattr(migration_operator, "check_static_bindings", fail)

    assert migration_operator.main(["check-bindings"]) == 130
    output = capsys.readouterr().out
    assert "secret" not in output
    assert json.loads(output)["reason"] == "operator_interrupted"
