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

import scripts.migrate_phase6_trusted_time_uncertainty as migration_operator
from packages.persistence.postgres_tls import SUPABASE_DATABASE_CA_SHA256
from scripts.migrate_phase6_trusted_time_uncertainty import (
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
from scripts.migrate_phase6_trusted_time_uncertainty import (
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
    path: Path, *, runtime_url: str = RUNTIME_URL, test_url: str = TEST_URL
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
) -> CatalogSnapshot:
    column: tuple[tuple[str, object], ...] | None = None
    if postflight:
        column = tuple(
            sorted(
                {
                    "data_type": "numeric",
                    "nullable": True,
                    "numeric_precision": 28,
                    "numeric_scale": 10,
                    "ordinal_position": 34,
                }.items()
            )
        )
    return CatalogSnapshot(
        revision=(
            migration_operator.TARGET_REVISION if postflight else migration_operator.PRIOR_REVISION
        ),
        database_time_unix_seconds=database_time_unix_seconds,
        server_major_version=server_major_version,
        tls_active=True,
        public_schema_active=True,
        public_search_path_only=True,
        table_counts=tuple((table, 0) for table in migration_operator._TABLES),
        uncertainty_column=column,
        old_policy_constraint_count=0 if postflight else 2,
        new_policy_constraint_count=2 if postflight else 0,
        columns=tuple(
            (
                table,
                (
                    migration_operator._EXPECTED_POST_COLUMNS
                    if postflight
                    else migration_operator._EXPECTED_PRE_COLUMNS
                )[table],
            )
            for table in migration_operator._TABLES
        ),
        constraints=tuple(
            (
                table,
                (
                    migration_operator._EXPECTED_POST_CONSTRAINTS
                    if postflight
                    else migration_operator._EXPECTED_PRE_CONSTRAINTS
                )[table],
            )
            for table in migration_operator._TABLES
        ),
        indexes=tuple(
            (table, migration_operator._EXPECTED_INDEXES[table])
            for table in migration_operator._TABLES
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
        database=_snapshot(postflight=False),
        now_seconds=now_seconds,
    )
    artifact = migration_operator._seal_artifact(body)
    return write_owner_only_artifact(path, artifact)


def test_static_bindings_pin_exact_migration_ca_graph_and_physical_catalog_names() -> None:
    bindings = check_static_bindings()

    assert bindings.migration_sha256 == migration_operator.EXPECTED_MIGRATION_SHA256
    assert bindings.database_ca_sha256 == SUPABASE_DATABASE_CA_SHA256
    assert len(bindings.source_state_sha256) == 64
    assert Path("migrations/versions/0034_phase6_trusted_time.py") in (
        migration_operator._SOURCE_BINDING_PATHS
    )
    assert Path("tests/integration/test_phase6_trusted_time_postgres.py") in (
        migration_operator._SOURCE_BINDING_PATHS
    )
    epoch_checks = {
        name
        for name, kind, _definition, _validated, _enforced in (
            migration_operator._EXPECTED_POST_CONSTRAINTS["phase6_trusted_time_epoch_registrations"]
        )
        if kind == "c"
    }
    evaluation_checks = {
        name
        for name, kind, _definition, _validated, _enforced in (
            migration_operator._EXPECTED_POST_CONSTRAINTS["phase6_trusted_time_probe_evaluations"]
        )
        if kind == "c"
    }
    assert "ck_phase6_trusted_time_epoch_registrations_phase6_trust_95fd" in epoch_checks
    assert "ck_phase6_trusted_time_probe_evaluations_phase6_trusted_4604" in (evaluation_checks)
    assert "ck_phase6_trusted_time_probe_evaluations_phase6_trusted_9308" in (evaluation_checks)
    assert "ck_phase6_trusted_time_probe_evaluations_phase6_trusted_fc75" in (evaluation_checks)


@pytest.mark.parametrize("mode", [0o400, 0o600])
def test_environment_loader_reads_only_distinct_exact_tls_bindings(
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
def test_environment_loader_rejects_shared_or_non_verify_full_targets(
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


def test_catalog_contract_requires_exact_preflight_and_postflight_shapes() -> None:
    verify_preflight_catalog(_snapshot(postflight=False))
    verify_postflight_catalog(_snapshot(postflight=True))

    invalid = _snapshot(postflight=False)
    invalid = CatalogSnapshot(
        revision=invalid.revision,
        database_time_unix_seconds=invalid.database_time_unix_seconds,
        server_major_version=invalid.server_major_version,
        tls_active=False,
        public_schema_active=invalid.public_schema_active,
        public_search_path_only=invalid.public_search_path_only,
        table_counts=invalid.table_counts,
        uncertainty_column=invalid.uncertainty_column,
        old_policy_constraint_count=invalid.old_policy_constraint_count,
        new_policy_constraint_count=invalid.new_policy_constraint_count,
        columns=invalid.columns,
        constraints=invalid.constraints,
        indexes=invalid.indexes,
    )
    with pytest.raises(MigrationOperatorError, match="trusted_time_catalog_invalid"):
        verify_preflight_catalog(invalid)


@pytest.mark.parametrize("server_major_version", [16, 17])
def test_catalog_contract_attests_supported_postgres_majors(
    server_major_version: int,
) -> None:
    verify_preflight_catalog(_snapshot(postflight=False, server_major_version=server_major_version))
    verify_postflight_catalog(_snapshot(postflight=True, server_major_version=server_major_version))


@pytest.mark.parametrize("server_major_version", [15, 18, True])
def test_catalog_contract_rejects_unsupported_or_non_integer_postgres_major(
    server_major_version: object,
) -> None:
    snapshot = replace(
        _snapshot(postflight=False),
        server_major_version=cast(int, server_major_version),
    )

    with pytest.raises(MigrationOperatorError, match="postgres_server_major_unsupported"):
        verify_preflight_catalog(snapshot)


def test_catalog_structural_proof_can_admit_plaintext_ci_but_tls_remains_default() -> None:
    plaintext = replace(_snapshot(postflight=False), tls_active=False)

    verify_preflight_catalog(plaintext, require_client_tls=False)
    with pytest.raises(MigrationOperatorError, match="trusted_time_catalog_invalid"):
        verify_preflight_catalog(plaintext)


def test_catalog_collection_uses_non_pretty_stable_postgres_definitions() -> None:
    source = (
        migration_operator.ROOT / "scripts/migrate_phase6_trusted_time_uncertainty.py"
    ).read_text(encoding="utf-8")

    assert "pg_get_expr(default_row.adbin, default_row.adrelid, false)" in source
    assert "pg_get_constraintdef(constraint_row.oid, false)" in source
    assert "pg_get_indexdef(index_row.oid, 0, false)" in source
    assert frozenset({16, 17}) == migration_operator.SUPPORTED_POSTGRES_MAJOR_VERSIONS


@pytest.mark.parametrize(
    ("field_index", "replacement_value"),
    [
        (2, "0" * 64),
        (3, False),
        (4, False),
    ],
)
def test_catalog_rejects_changed_constraint_definition_or_flags(
    field_index: int,
    replacement_value: object,
) -> None:
    snapshot = _snapshot(postflight=False)
    table, entries = snapshot.constraints[0]
    changed = list(entries[0])
    changed[field_index] = replacement_value
    constraints = ((table, (tuple(changed), *entries[1:])), *snapshot.constraints[1:])

    with pytest.raises(MigrationOperatorError, match="runtime_preflight_rejected"):
        verify_preflight_catalog(
            replace(
                snapshot,
                constraints=cast(
                    tuple[
                        tuple[
                            str,
                            tuple[migration_operator.ConstraintContract, ...],
                        ],
                        ...,
                    ],
                    constraints,
                ),
            )
        )


@pytest.mark.parametrize(
    ("field_index", "replacement_value"),
    [
        (1, "0" * 64),
        (2, False),
        (3, False),
        (4, True),
    ],
)
def test_catalog_rejects_changed_index_definition_or_flags(
    field_index: int,
    replacement_value: object,
) -> None:
    snapshot = _snapshot(postflight=False)
    table, entries = snapshot.indexes[0]
    changed = list(entries[0])
    changed[field_index] = replacement_value
    indexes = ((table, (tuple(changed), *entries[1:])), *snapshot.indexes[1:])

    with pytest.raises(MigrationOperatorError, match="trusted_time_catalog_invalid"):
        verify_preflight_catalog(
            replace(
                snapshot,
                indexes=cast(
                    tuple[
                        tuple[str, tuple[migration_operator.IndexContract, ...]],
                        ...,
                    ],
                    indexes,
                ),
            )
        )


def test_catalog_rejects_changed_existing_column_contract() -> None:
    snapshot = _snapshot(postflight=False)
    table, entries = snapshot.columns[0]
    changed = list(entries[0])
    changed[2] = "text"
    columns = ((table, (tuple(changed), *entries[1:])), *snapshot.columns[1:])

    with pytest.raises(MigrationOperatorError, match="runtime_preflight_rejected"):
        verify_preflight_catalog(
            replace(
                snapshot,
                columns=cast(
                    tuple[
                        tuple[str, tuple[migration_operator.ColumnContract, ...]],
                        ...,
                    ],
                    columns,
                ),
            )
        )


def test_preflight_writes_owner_only_canonical_artifact_without_secret_metadata(
    tmp_path: Path,
) -> None:
    env_file = _write_environment(tmp_path / ".env")
    artifact_path = tmp_path / "preflight.json"
    engine, connection, raw_engine = _mock_engine()
    cast(Any, connection).scalar.return_value = 1_000

    result = preflight_runtime(
        env_file=env_file,
        artifact_path=artifact_path,
        engine_factory=lambda _url: engine,
        catalog_reader=lambda _connection: _snapshot(postflight=False),
    )

    payload = artifact_path.read_bytes()
    decoded = json.loads(payload)
    assert result["status"] == "ready"
    assert stat.S_IMODE(artifact_path.stat().st_mode) == 0o600
    assert payload == migration_operator._canonical_json_bytes(decoded)
    assert decoded["restore_capable"] is False
    assert decoded["created_at_unix_seconds"] == 1_000
    assert decoded["expires_at_unix_seconds"] == 1_900
    assert decoded["database"]["server_major_version"] == 16
    assert RUNTIME_URL.encode() not in payload
    assert TEST_URL.encode() not in payload
    assert b"pooler.supabase.com" not in payload
    assert b"postgres." not in payload
    raw_engine.dispose.assert_called_once_with()


def test_preflight_artifact_rejects_modification_and_expiration(tmp_path: Path) -> None:
    env_file = _write_environment(tmp_path / ".env")
    artifact_path = tmp_path / "preflight.json"
    _write_preflight(artifact_path, env_file, now_seconds=1_000)
    static = check_static_bindings()
    environment = load_environment_bindings(env_file)
    decoded = json.loads(artifact_path.read_bytes())
    decoded["database"]["tls_active"] = False
    artifact_path.chmod(0o600)
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


def test_apply_uses_exact_runner_then_verifies_and_writes_nonrestore_postflight(
    tmp_path: Path,
) -> None:
    now_seconds = 5_000
    env_file = _write_environment(tmp_path / ".env")
    preflight_path = tmp_path / "preflight.json"
    postflight_path = tmp_path / "postflight.json"
    _write_preflight(preflight_path, env_file, now_seconds=now_seconds)
    engine, connection, raw_engine = _mock_engine()
    cast(Any, connection).scalar.side_effect = [True, now_seconds + 1, now_seconds + 1]
    snapshots: Iterator[CatalogSnapshot] = iter(
        (_snapshot(postflight=False), _snapshot(postflight=True))
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
        require_phase_zero_facts: bool = True,
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

    postflight = json.loads(postflight_path.read_bytes())
    assert result["status"] == "complete"
    assert result["migration_committed"] is True
    assert migration_calls == [(connection, migration_operator.EXPECTED_MIGRATION_SHA256)]
    assert schema_calls == [(engine, False, migration_operator.TARGET_REVISION)]
    assert postflight["restore_capable"] is False
    assert postflight["database"]["uncertainty_column"] == {
        "data_type": "numeric",
        "nullable": True,
        "numeric_precision": 28,
        "numeric_scale": 10,
        "ordinal_position": 34,
    }
    assert stat.S_IMODE(postflight_path.stat().st_mode) == 0o600
    assert RUNTIME_URL not in postflight_path.read_text(encoding="utf-8")
    raw_engine.dispose.assert_called_once_with()


def test_apply_reprobes_lost_commit_ack_and_insulates_dispose_failure(
    tmp_path: Path,
) -> None:
    env_file = _write_environment(tmp_path / ".env")
    preflight_path = tmp_path / "preflight.json"
    postflight_path = tmp_path / "postflight.json"
    _write_preflight(preflight_path, env_file, now_seconds=5_000)
    original_engine, original_connection, raw_original = _mock_engine()
    probe_engine, _probe_connection, raw_probe = _mock_engine()
    verifier_engine, _verifier_connection, raw_verifier = _mock_engine()
    cast(Any, original_connection).scalar.side_effect = [True, 5_001, 5_001]
    raw_original.begin.return_value.__exit__.side_effect = RuntimeError("lost commit ack")
    raw_original.dispose.side_effect = RuntimeError("dispose failed")
    engines: Iterator[Engine] = iter((original_engine, probe_engine, verifier_engine))
    snapshots: Iterator[CatalogSnapshot] = iter(
        (
            _snapshot(postflight=False, database_time_unix_seconds=5_001),
            _snapshot(postflight=True, database_time_unix_seconds=5_002),
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
    assert json.loads(postflight_path.read_bytes())["created_at_unix_seconds"] == 5_002
    probe_sql_calls = (
        raw_probe.begin.return_value.__enter__.return_value.exec_driver_sql.call_args_list
    )
    assert len(probe_sql_calls) == 2
    assert str(probe_sql_calls[1].args[0]).startswith("LOCK TABLE public.")
    raw_probe.dispose.assert_called_once_with()
    raw_verifier.dispose.assert_called_once_with()


@pytest.mark.parametrize(
    "interruption",
    [KeyboardInterrupt("secret-interrupt"), SystemExit("secret-exit")],
)
def test_apply_reprobes_interrupted_commit_and_writes_evidence_before_exit(
    tmp_path: Path,
    interruption: BaseException,
) -> None:
    env_file = _write_environment(tmp_path / ".env")
    preflight_path = tmp_path / "preflight.json"
    postflight_path = tmp_path / "postflight.json"
    _write_preflight(preflight_path, env_file, now_seconds=5_000)
    original_engine, original_connection, raw_original = _mock_engine()
    probe_engine, _probe_connection, _raw_probe = _mock_engine()
    verifier_engine, _verifier_connection, _raw_verifier = _mock_engine()
    cast(Any, original_connection).scalar.side_effect = [True, 5_001, 5_001]
    raw_original.begin.return_value.__exit__.side_effect = interruption
    engines: Iterator[Engine] = iter((original_engine, probe_engine, verifier_engine))
    snapshots: Iterator[CatalogSnapshot] = iter(
        (
            _snapshot(postflight=False, database_time_unix_seconds=5_001),
            _snapshot(postflight=True, database_time_unix_seconds=5_002),
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
    assert json.loads(postflight_path.read_bytes())["database"]["revision"] == (
        migration_operator.TARGET_REVISION
    )
    assert "secret" not in json.dumps(migration_operator._safe_failure(captured.value))


def test_apply_reports_unknown_not_false_when_commit_reprobe_cannot_classify(
    tmp_path: Path,
) -> None:
    env_file = _write_environment(tmp_path / ".env")
    preflight_path = tmp_path / "preflight.json"
    _write_preflight(preflight_path, env_file, now_seconds=5_000)
    original_engine, original_connection, raw_original = _mock_engine()
    probe_engine, _probe_connection, raw_probe = _mock_engine()
    cast(Any, original_connection).scalar.side_effect = [True, 5_001, 5_001]
    raw_original.begin.return_value.__exit__.side_effect = RuntimeError("lost commit ack")
    raw_probe.begin.return_value.__enter__.side_effect = RuntimeError("probe unavailable")
    engines: Iterator[Engine] = iter((original_engine, probe_engine))

    with pytest.raises(
        MigrationOperatorError,
        match="migration_commit_outcome_unknown",
    ) as captured:
        apply_runtime(
            env_file=env_file,
            preflight_artifact_path=preflight_path,
            postflight_artifact_path=tmp_path / "postflight.json",
            engine_factory=lambda _url: next(engines),
            catalog_reader=lambda _connection: _snapshot(
                postflight=False,
                database_time_unix_seconds=5_001,
            ),
            migration_runner=lambda _connection, _bindings: None,
        )

    assert captured.value.migration_committed is None
    assert migration_operator._safe_failure(captured.value)["migration_committed"] is None
    assert not (tmp_path / "postflight.json").exists()


def test_apply_reports_false_only_after_exact_preflight_proves_rollback(
    tmp_path: Path,
) -> None:
    env_file = _write_environment(tmp_path / ".env")
    preflight_path = tmp_path / "preflight.json"
    _write_preflight(preflight_path, env_file, now_seconds=5_000)
    original_engine, original_connection, raw_original = _mock_engine()
    probe_engine, _probe_connection, _raw_probe = _mock_engine()
    cast(Any, original_connection).scalar.side_effect = [True, 5_001, 5_001]
    raw_original.begin.return_value.__exit__.side_effect = RuntimeError("lost commit ack")
    engines: Iterator[Engine] = iter((original_engine, probe_engine))
    snapshots: Iterator[CatalogSnapshot] = iter(
        (
            _snapshot(postflight=False, database_time_unix_seconds=5_001),
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
        )

    assert captured.value.migration_committed is False


def test_apply_rechecks_authenticated_database_clock_and_rejects_expiry_before_migration(
    tmp_path: Path,
) -> None:
    env_file = _write_environment(tmp_path / ".env")
    preflight_path = tmp_path / "preflight.json"
    _write_preflight(preflight_path, env_file, now_seconds=1_000)
    engine, connection, raw_engine = _mock_engine()
    cast(Any, connection).scalar.side_effect = [True, 1_899, 1_900]
    migration_called = False

    def migration_runner(
        _connection: Connection,
        _bindings: migration_operator.StaticBindings,
    ) -> None:
        nonlocal migration_called
        migration_called = True

    with pytest.raises(MigrationOperatorError, match="preflight_artifact_stale"):
        apply_runtime(
            env_file=env_file,
            preflight_artifact_path=preflight_path,
            postflight_artifact_path=tmp_path / "postflight.json",
            engine_factory=lambda _url: engine,
            catalog_reader=lambda _connection: _snapshot(
                postflight=False,
                database_time_unix_seconds=1_001,
            ),
            migration_runner=cast(migration_operator.MigrationRunner, migration_runner),
        )
    assert migration_called is False
    raw_engine.dispose.assert_called_once_with()


def test_test_postgres_child_environment_strips_ambient_database_and_aqt_values() -> None:
    child = migration_operator._test_postgres_child_environment(
        TEST_URL,
        {
            "AQT_DATABASE_URL": RUNTIME_URL,
            "AQT_OTHER_SECRET": "secret",
            "LANG": "en_US.UTF-8",
            "PATH": "/usr/bin",
            "PGPASSWORD": "secret",
            "PGSERVICE": "runtime",
            "PYTHONPATH": "/untrusted",
        },
    )

    assert child == {
        "AQT_DATABASE_URL": TEST_URL,
        "AQT_TEST_POSTGRES_URL": TEST_URL,
        "LANG": "en_US.UTF-8",
        "PATH": "/usr/bin",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
    }
    assert all(not key.startswith("PG") for key in child)
    assert not any(key.startswith("AQT_") and child[key] != TEST_URL for key in child)


def test_test_postgres_spawns_only_designated_test_with_test_dsn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_file = _write_environment(tmp_path / ".env")
    observed: dict[str, Any] = {}

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed["argv"] = argv
        observed.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, stdout="3 passed in 1.00s\n", stderr="")

    monkeypatch.setattr(
        "scripts.migrate_phase6_trusted_time_uncertainty.subprocess.run",
        fake_run,
    )

    result, exit_code = run_test_postgres(env_file=env_file)

    assert exit_code == 0
    assert result["status"] == "passed"
    assert result["passed_count"] == 3
    assert observed["argv"][-1] == "tests/integration/test_phase6_trusted_time_postgres.py"
    assert observed["cwd"] == migration_operator.ROOT
    child_environment = cast(dict[str, str], observed["env"])
    assert child_environment["AQT_DATABASE_URL"] == TEST_URL
    assert child_environment["AQT_TEST_POSTGRES_URL"] == TEST_URL
    assert RUNTIME_URL not in child_environment.values()


def test_test_postgres_discards_child_failure_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_file = _write_environment(tmp_path / ".env")
    leaked_text = f"connection failed for {TEST_URL}"

    def fake_run(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            argv,
            1,
            stdout="1 failed in 1.00s\n",
            stderr=leaked_text,
        )

    monkeypatch.setattr(
        "scripts.migrate_phase6_trusted_time_uncertainty.subprocess.run",
        fake_run,
    )

    result, exit_code = run_test_postgres(env_file=env_file)

    assert exit_code == 2
    assert result["status"] == "failed"
    assert result["failed_count"] == 1
    assert leaked_text not in json.dumps(result)
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
def test_cli_sanitizes_fatal_interruption_and_preserves_interrupt_exit_status(
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
    decoded = json.loads(output)
    assert decoded["reason"] == "operator_interrupted"
    assert decoded["migration_committed"] is False
