"""Fresh retained-row metadata, with no replay, clock or financial authority."""

from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from types import SimpleNamespace

import pytest
import sqlalchemy as sa

from apps.trader.synthetic_session_genesis import initialize_synthetic_session
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec as codec
from packages.domain.continuous_persistence_contracts import MAX_CONTINUOUS_COMMIT_BYTES
from packages.domain.continuous_selection_contracts import (
    ContinuousSelectionCheckpoint,
    ContinuousSelectionSnapshot,
    RetainedContinuousSelection,
)
from packages.domain.daily_runtime_contracts import RuntimeRiskAssignment
from packages.domain.personal_contracts import content_digest
from packages.persistence.account_coordinator import SqlAccountCoordinator
from packages.persistence.continuous_account_schema import (
    continuous_account_commits as commits,
)
from packages.persistence.continuous_account_schema import (
    continuous_account_heads as heads,
)
from packages.persistence.continuous_selection_read_model import (
    ContinuousSelectionReadError,
    SqlContinuousSelectionReadModel,
)
from packages.persistence.daily_runtime_risk_schema import (
    daily_runtime_assignment_heads as assignment_heads,
)
from packages.persistence.daily_runtime_risk_schema import (
    daily_runtime_assignments as assignments,
)
from packages.persistence.database import EXPECTED_SCHEMA_REVISION, create_database_engine
from packages.persistence.immutable import as_aware_utc
from packages.persistence.runtime_owner_associations import SqlRuntimeOwnerAssociations
from packages.persistence.schema import metadata, phase2_account_lease_heads
from tests.integration.test_continuous_synthetic_initial_selection import (
    _facts,
    _publish,
    _request,
)
from tests.integration.test_continuous_synthetic_initial_selection import selection as selection
from tests.integration.test_continuous_synthetic_offline_configuration import (
    _facts as migrated_facts,
)
from tests.integration.test_continuous_synthetic_offline_configuration import _study
from tests.integration.test_continuous_synthetic_session_genesis import captured as captured

TABLES = (heads, commits, assignment_heads, assignments)
ERROR = "continuous selection metadata is unavailable or malformed"


def _stamp_test_revision(engine):
    """Supply revision metadata for fresh create_all/corruptible SQL fixtures.

    These fixtures are intentionally not migration proofs; the separate actual
    migrated selected-account test remains the maintained migration positive.
    """
    revisions = sa.Table("alembic_version", sa.MetaData(), sa.Column("version_num", sa.String(32)))
    revisions.create(engine)
    with engine.begin() as connection:
        connection.execute(revisions.insert().values(version_num=EXPECTED_SCHEMA_REVISION))


@pytest.fixture
def selected(selection):
    _stamp_test_revision(selection.ports["account_engine"])
    request = _request(selection)
    installed = _publish(selection, request)
    return SimpleNamespace(study=selection, installed=installed, request=request)


def _rows(engine, tables):
    with engine.connect() as connection:
        return tuple(
            tuple(tuple(row) for row in connection.execute(sa.select(table))) for table in tables
        )


def _all_facts(study):
    return _facts(study), _rows(study.ports["account_engine"], (phase2_account_lease_heads,))


def test_empty_database_and_unknown_account_are_absent_without_initialization():
    engine = create_database_engine("sqlite+pysqlite:///:memory:")
    try:
        metadata.create_all(engine)
        _stamp_test_revision(engine)
        before = _rows(engine, TABLES)
        snapshot = SqlContinuousSelectionReadModel(engine).read("unknown-synthetic-account")
        assert snapshot == ContinuousSelectionSnapshot(
            "unknown-synthetic-account", "absent", None, None
        )
        assert snapshot.verification == "row_integrity_only"
        assert _rows(engine, TABLES) == before
    finally:
        engine.dispose()


def test_real_genesis_is_unselected_without_replaying_or_reacquiring(captured):
    bootstrap, ports = captured
    _stamp_test_revision(ports["account_engine"])
    genesis = initialize_synthetic_session(bootstrap, **ports)
    before = _rows(ports["account_engine"], (*TABLES, phase2_account_lease_heads))
    snapshot = SqlContinuousSelectionReadModel(ports["account_engine"]).read(
        genesis.scope.account_id
    )
    receipt = genesis.restored.receipt
    assert snapshot == ContinuousSelectionSnapshot(
        genesis.scope.account_id,
        "unselected",
        ContinuousSelectionCheckpoint(genesis.scope.stream_id, 1, receipt.recorded_at),
        None,
    )
    assert _rows(ports["account_engine"], (*TABLES, phase2_account_lease_heads)) == before
    assert genesis.account.coordinator.current() is None


def test_real_signed_selection_returns_only_exact_retained_metadata(selected):
    study, assignment = selected.study, selected.installed
    engine = study.ports["account_engine"]
    before = _all_facts(study)
    with engine.connect() as connection:
        recorded = as_aware_utc(
            connection.execute(sa.select(assignments.c.recorded_at)).scalar_one()
        )
    snapshot = SqlContinuousSelectionReadModel(engine).read(study.genesis.scope.account_id)
    assert snapshot == ContinuousSelectionSnapshot(
        study.genesis.scope.account_id,
        "selected",
        ContinuousSelectionCheckpoint(
            study.genesis.scope.stream_id, 1, study.genesis.restored.receipt.recorded_at
        ),
        RetainedContinuousSelection(
            1,
            assignment.strategy.name,
            assignment.strategy.version,
            assignment.configuration_sha256,
            assignment.instrument_symbols,
            assignment.policy.policy_id,
            False,
            False,
            recorded,
            assignment.effective_at,
        ),
    )
    assert snapshot.verification == "row_integrity_only"
    assert snapshot.selection is not None
    assert snapshot.selection.recorded_at == recorded
    assert snapshot.selection.effective_at == assignment.effective_at
    assert not hasattr(snapshot, "ready") and not hasattr(snapshot, "equity")
    assert SqlContinuousSelectionReadModel(engine).read("unrelated-account").state == "absent"
    assert SqlContinuousSelectionReadModel(engine).read(study.genesis.scope.account_id) == snapshot
    assert _all_facts(study) == before


def test_genuinely_migrated_selected_account_is_read_without_mutation(tmp_path):
    with _study(tmp_path) as study:
        before = migrated_facts(study)
        head = _rows(study.ports["account_engine"], (phase2_account_lease_heads,))
        snapshot = SqlContinuousSelectionReadModel(study.ports["account_engine"]).read(
            study.genesis.scope.account_id
        )
        assert snapshot.state == "selected"
        assert snapshot.checkpoint.sequence == 1
        assert snapshot.checkpoint.recorded_at == study.genesis.restored.receipt.recorded_at
        assert snapshot.selection.generation == study.assignment.generation
        assert snapshot.selection.configuration_sha256 == study.assignment.configuration_sha256
        assert snapshot.selection.live_authorized is False
        assert snapshot.verification == "row_integrity_only"
        assert migrated_facts(study) == before
        assert _rows(study.ports["account_engine"], (phase2_account_lease_heads,)) == head


def test_selection_reader_never_calls_owners_private_objects_clocks_or_writers(
    selected, monkeypatch
):
    study = selected.study
    engine = study.ports["account_engine"]
    before = _all_facts(study)
    statements = []

    def forbidden(*args, **kwargs):
        raise AssertionError("metadata display attempted an owner, private object, clock or write")

    def record_statement(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    sa.event.listen(engine, "before_cursor_execute", record_statement)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(type(study.genesis.account), "restore", forbidden)
            patch.setattr(SqlRuntimeOwnerAssociations, "read", forbidden)
            patch.setattr(LocalResearchArtifactStore, "read", forbidden)
            patch.setattr(type(study.ports["clock"]), "now", forbidden)
            for name in (
                "acquire",
                "renew",
                "revalidate",
                "revalidate_in_transaction",
                "revalidate_for_commit_in_transaction",
                "release",
            ):
                patch.setattr(SqlAccountCoordinator, name, forbidden)
            snapshot = SqlContinuousSelectionReadModel(engine).read(study.genesis.scope.account_id)
            assert snapshot.state == "selected"
    finally:
        sa.event.remove(engine, "before_cursor_execute", record_statement)
    assert _all_facts(study) == before
    allowed = {table.name for table in TABLES} | {"alembic_version"}
    selects = tuple(
        statement for statement in statements if statement.lstrip().upper().startswith("SELECT")
    )
    assert selects
    for statement in selects:
        assert "LIMIT" in statement.upper() or (
            statement.startswith("SELECT EXISTS") and "WHERE 0 = 1" in statement
        )
        assert any(f"FROM {name}" in statement for name in allowed)
        assert "command_payload" not in statement
    assert all(
        statement.lstrip().upper().startswith(("SELECT", "BEGIN")) for statement in statements
    )


@pytest.fixture
def malformed_copy(selected, tmp_path):
    """A separate deliberately corruptible SQL database, not relaxed production constraints.

    Actual retained rows originate in the fresh signed fixture. These four table
    copies omit constraints so adverse bytes/native types impossible through the
    maintained writer can exercise the reader's fail-closed transfer boundary.
    """
    engine = create_database_engine(
        f"sqlite+pysqlite:///{tmp_path / 'malformed-metadata.sqlite'}", research_sqlite_wal=True
    )
    copied_metadata = sa.MetaData()
    copies = {
        table.name: sa.Table(
            table.name,
            copied_metadata,
            *(sa.Column(column.name, column.type, nullable=True) for column in table.c),
        )
        for table in TABLES
    }
    copied_metadata.create_all(engine)
    _stamp_test_revision(engine)
    with selected.study.ports["account_engine"].connect() as source, engine.begin() as target:
        for table in TABLES:
            rows = [dict(row) for row in source.execute(sa.select(table)).mappings()]
            if rows:
                target.execute(copies[table.name].insert(), rows)
    try:
        yield SimpleNamespace(engine=engine, selected=selected)
    finally:
        engine.dispose()


def _reject(engine, account):
    before = _rows(engine, TABLES)
    with pytest.raises(ContinuousSelectionReadError, match=f"^{ERROR}$"):
        SqlContinuousSelectionReadModel(engine).read(account)
    assert _rows(engine, TABLES) == before


@pytest.mark.parametrize(
    "damage",
    (
        "c_head_missing",
        "c_row_missing",
        "c_head_digest",
        "c_scalar",
        "c_payload",
        "c_noncanonical",
        "c_receipt",
        "b_head_missing",
        "b_row_missing",
        "b_head_digest",
        "b_payload_digest",
        "b_semantic",
        "b_noncanonical",
        "b_binding",
        "c_hidden_tail",
        "b_hidden_tail",
        "duplicate_head",
    ),
)
def test_corrupt_or_ambiguous_retained_metadata_is_static_error(malformed_copy, damage):
    engine = malformed_copy.engine
    account = malformed_copy.selected.study.genesis.scope.account_id
    with engine.begin() as connection:
        if damage == "c_head_missing":
            connection.execute(heads.delete())
        elif damage == "c_row_missing":
            connection.execute(commits.delete())
        elif damage == "c_head_digest":
            connection.execute(heads.update().values(commit_sha256="0" * 64))
        elif damage == "c_scalar":
            connection.execute(commits.update().values(checkpoint_sha256="0" * 64))
        elif damage == "c_payload":
            connection.execute(commits.update().values(canonical_payload=b"{}"))
        elif damage == "c_noncanonical":
            payload = connection.scalar(sa.select(commits.c.canonical_payload))
            connection.execute(commits.update().values(canonical_payload=b" " + payload))
        elif damage == "c_receipt":
            connection.execute(commits.update().values(receipt_sha256="0" * 64))
        elif damage == "b_head_missing":
            connection.execute(assignment_heads.delete())
        elif damage == "b_row_missing":
            connection.execute(assignments.delete())
        elif damage == "b_head_digest":
            connection.execute(assignment_heads.update().values(semantic_sha256="0" * 64))
        elif damage == "b_payload_digest":
            connection.execute(assignments.update().values(payload_sha256="0" * 64))
        elif damage == "b_semantic":
            connection.execute(assignments.update().values(semantic_sha256="0" * 64))
        elif damage == "b_noncanonical":
            payload = b" " + connection.scalar(sa.select(assignments.c.payload))
            connection.execute(
                assignments.update().values(
                    payload=payload, payload_sha256=sha256(payload).hexdigest()
                )
            )
        elif damage == "b_binding":
            payload = connection.scalar(sa.select(assignments.c.payload))
            assignment = replace(
                codec.decode_record(payload, RuntimeRiskAssignment),
                account_binding_sha256=content_digest("foreign-account"),
            )
            payload = codec.encode_record(assignment)
            connection.execute(
                assignments.update().values(
                    payload=payload,
                    payload_sha256=sha256(payload).hexdigest(),
                    semantic_sha256=assignment.semantic_sha256,
                )
            )
            connection.execute(
                assignment_heads.update().values(semantic_sha256=assignment.semantic_sha256)
            )
        elif damage == "c_hidden_tail":
            row = dict(connection.execute(sa.select(commits)).mappings().one())
            connection.execute(
                commits.insert().values(**{**row, "command_id": "hidden-c-tail", "sequence": 2})
            )
        elif damage == "b_hidden_tail":
            row = dict(connection.execute(sa.select(assignments)).mappings().one())
            connection.execute(assignments.insert().values(**{**row, "generation": 2}))
        elif damage == "duplicate_head":
            row = dict(connection.execute(sa.select(heads)).mappings().one())
            connection.execute(heads.insert().values(**row))
        else:
            raise AssertionError("unknown adverse fixture")
    _reject(engine, account)


@pytest.mark.parametrize(
    "table,column,value,blocked_table",
    (
        (commits, "canonical_payload", b"x" * (MAX_CONTINUOUS_COMMIT_BYTES + 1), commits),
        (assignments, "payload", b"x" * (1024 * 1024 + 1), assignments),
        (commits, "command_id", "private-poison" * 20000, commits),
        (commits, "owner_id", "private-poison" * 20000, commits),
        (heads, "command_id", "private-poison" * 20000, heads),
        (commits, "receipt_sha256", "x" * 65536, commits),
        (assignments, "semantic_sha256", "x" * 65536, assignments),
        (heads, "sequence", 1.5, heads),
        (assignment_heads, "generation", "not-a-native-integer", assignment_heads),
    ),
)
def test_native_or_oversized_fields_are_rejected_before_row_transfer(
    malformed_copy, table, column, value, blocked_table
):
    engine = malformed_copy.engine
    account = malformed_copy.selected.study.genesis.scope.account_id
    with engine.begin() as connection:
        connection.execute(table.update().values({column: value}))
    statements = []

    def record_statement(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    sa.event.listen(engine, "before_cursor_execute", record_statement)
    try:
        with pytest.raises(ContinuousSelectionReadError, match=f"^{ERROR}$"):
            SqlContinuousSelectionReadModel(engine).read(account)
    finally:
        sa.event.remove(engine, "before_cursor_execute", record_statement)
    # Guard SELECTs transfer CASE scalars only. No actual selected row from the
    # poisoned table may be fetched, even when its payload would otherwise fit.
    assert any(
        "CASE WHEN" in statement and f"FROM {blocked_table.name}" in statement
        for statement in statements
    )
    assert not any(
        statement.startswith(f"SELECT {blocked_table.name}.") for statement in statements
    )


@pytest.mark.parametrize("account", ("", " spaced ", "x" * 129, True, 1))
def test_invalid_account_identity_fails_before_sql(selected, account):
    engine = selected.study.ports["account_engine"]
    statements = []

    def record_statement(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    sa.event.listen(engine, "before_cursor_execute", record_statement)
    try:
        with pytest.raises(ContinuousSelectionReadError, match=f"^{ERROR}$"):
            SqlContinuousSelectionReadModel(engine).read(account)
    finally:
        sa.event.remove(engine, "before_cursor_execute", record_statement)
    assert statements == []


def test_public_metadata_native_counters_and_scope_are_exact():
    at = datetime(2026, 1, 1, tzinfo=UTC)
    checkpoint = ContinuousSelectionCheckpoint("synthetic-stream", 2**63 - 1, at)
    assert checkpoint.sequence == 2**63 - 1
    for invalid in (True, 0, 2**63, 1.5):
        with pytest.raises(ValueError):
            replace(checkpoint, sequence=invalid)
    with pytest.raises(ValueError):
        ContinuousSelectionSnapshot("account", "selected", checkpoint, None)
    with pytest.raises(ValueError):
        replace(
            ContinuousSelectionSnapshot("account", "unselected", checkpoint, None),
            verification="ready",
        )
    with pytest.raises(ValueError):
        replace(checkpoint, recorded_at=at.replace(tzinfo=None))


@pytest.mark.parametrize("prefix", ["", "2026-01-01 00:00:00"])
def test_timestamp_nul_tail_is_rejected_before_any_assignment_row_transfer(malformed_copy, prefix):
    engine = malformed_copy.engine
    account = malformed_copy.selected.study.genesis.scope.account_id
    poisoned = prefix + "\x00" + "x" * (1024 * 1024)
    with engine.begin() as connection:
        connection.exec_driver_sql(f"UPDATE {assignments.name} SET recorded_at = ?", (poisoned,))
    statements = []

    def record_statement(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    sa.event.listen(engine, "before_cursor_execute", record_statement)
    try:
        with pytest.raises(ContinuousSelectionReadError, match=f"^{ERROR}$"):
            SqlContinuousSelectionReadModel(engine).read(account)
    finally:
        sa.event.remove(engine, "before_cursor_execute", record_statement)
    assert any(
        "CASE WHEN" in statement and f"FROM {assignments.name}" in statement
        for statement in statements
    )
    assert not any(statement.startswith(f"SELECT {assignments.name}.") for statement in statements)


@pytest.mark.parametrize(
    "damage",
    (
        "missing_table",
        "empty",
        "wrong",
        "duplicate",
        "oversized",
        "binary",
        "null",
        "integer",
    ),
)
def test_incompatible_revision_is_rejected_before_any_retained_row_transfer(
    malformed_copy, damage, monkeypatch
):
    engine = malformed_copy.engine
    account = malformed_copy.selected.study.genesis.scope.account_id
    revision = sa.table("alembic_version", sa.column("version_num", sa.String(32)))
    with engine.begin() as connection:
        if damage == "missing_table":
            connection.exec_driver_sql("DROP TABLE alembic_version")
        elif damage == "empty":
            connection.execute(revision.delete())
        elif damage == "duplicate":
            connection.execute(revision.insert().values(version_num=EXPECTED_SCHEMA_REVISION))
        else:
            value = {
                "wrong": "0039_personal_research",
                "oversized": EXPECTED_SCHEMA_REVISION + "\x00" + "x" * (1024 * 1024),
                "binary": EXPECTED_SCHEMA_REVISION.encode("ascii"),
                "null": None,
                "integer": 40,
            }[damage]
            connection.execute(revision.update().values(version_num=value))
    before = _rows(engine, TABLES)
    statements = []

    def record_statement(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    def forbidden(*args, **kwargs):
        raise AssertionError("incompatible revision reached a retained record decoder")

    sa.event.listen(engine, "before_cursor_execute", record_statement)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(codec, "decode_record", forbidden)
            with pytest.raises(ContinuousSelectionReadError, match=f"^{ERROR}$"):
                SqlContinuousSelectionReadModel(engine).read(account)
    finally:
        sa.event.remove(engine, "before_cursor_execute", record_statement)
    assert _rows(engine, TABLES) == before
    selects = [statement for statement in statements if statement.startswith("SELECT")]
    assert len(selects) == 1
    assert selects[0].startswith("SELECT CASE WHEN")
    assert "FROM alembic_version" in selects[0] and "LIMIT" in selects[0]
    assert not any(f"FROM {table.name}" in selects[0] for table in TABLES)


def test_case_insensitive_revision_column_cannot_substitute_different_revision_bytes(
    malformed_copy,
):
    engine = malformed_copy.engine
    account = malformed_copy.selected.study.genesis.scope.account_id
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE alembic_version")
        connection.exec_driver_sql("CREATE TABLE alembic_version (version_num TEXT COLLATE NOCASE)")
        connection.execute(
            sa.text("INSERT INTO alembic_version (version_num) VALUES (:revision)"),
            {"revision": EXPECTED_SCHEMA_REVISION.upper()},
        )
    before = _rows(engine, TABLES)
    statements = []

    def record_statement(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    sa.event.listen(engine, "before_cursor_execute", record_statement)
    try:
        with pytest.raises(ContinuousSelectionReadError, match=f"^{ERROR}$"):
            SqlContinuousSelectionReadModel(engine).read(account)
    finally:
        sa.event.remove(engine, "before_cursor_execute", record_statement)
    assert _rows(engine, TABLES) == before
    selects = [statement for statement in statements if statement.startswith("SELECT")]
    assert len(selects) == 1
    assert selects[0].startswith("SELECT CASE WHEN") and "FROM alembic_version" in selects[0]


@pytest.mark.parametrize(
    "table,column",
    (
        (heads, None),
        (commits, None),
        (assignment_heads, None),
        (assignments, None),
        (commits, "canonical_payload"),
        (assignments, "payload"),
        (assignment_heads, "semantic_sha256"),
    ),
)
def test_missing_required_metadata_schema_fails_before_any_head_or_payload_transfer(
    malformed_copy, table, column, monkeypatch
):
    engine = malformed_copy.engine
    account = malformed_copy.selected.study.genesis.scope.account_id
    with engine.begin() as connection:
        if column is None:
            connection.exec_driver_sql(f"DROP TABLE {table.name}")
        else:
            connection.exec_driver_sql(
                f"ALTER TABLE {table.name} RENAME COLUMN {column} TO missing_required_column"
            )
    statements = []

    def record_statement(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    def forbidden(*args, **kwargs):
        raise AssertionError("incompatible columns reached a retained record decoder")

    sa.event.listen(engine, "before_cursor_execute", record_statement)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(codec, "decode_record", forbidden)
            with pytest.raises(ContinuousSelectionReadError, match=f"^{ERROR}$"):
                SqlContinuousSelectionReadModel(engine).read(account)
    finally:
        sa.event.remove(engine, "before_cursor_execute", record_statement)
    selects = [statement for statement in statements if statement.startswith("SELECT")]
    assert len(selects) == 2
    assert selects[0].startswith("SELECT CASE WHEN") and "FROM alembic_version" in selects[0]
    assert selects[1].startswith("SELECT EXISTS") and "WHERE 0 = 1" in selects[1]
    assert not any("command_payload" in statement for statement in selects)
    assert not any(
        statement.startswith(f"SELECT {item.name}.") for statement in selects for item in TABLES
    )


def test_revision_and_metadata_are_read_from_one_original_sql_snapshot(malformed_copy):
    engine = malformed_copy.engine
    account = malformed_copy.selected.study.genesis.scope.account_id
    before = _rows(engine, TABLES)
    original_connection = None
    retained_connections = []
    changed = False

    def replace_revision_after_capture(
        connection, cursor, statement, parameters, context, executemany
    ):
        nonlocal original_connection, changed
        if statement.startswith("SELECT") and "FROM alembic_version" in statement and not changed:
            original_connection = connection
            changed = True
            # The fresh WAL test database permits a genuine concurrent commit.
            # The original reader must keep its captured revision and C/B view.
            with engine.begin() as writer:
                assert writer is not connection
                writer.execute(
                    sa.text("UPDATE alembic_version SET version_num = :revision"),
                    {"revision": "concurrent-other-revision"},
                )
        elif statement.startswith("SELECT") and any(
            f"FROM {table.name}" in statement for table in TABLES
        ):
            retained_connections.append(connection)

    sa.event.listen(engine, "after_cursor_execute", replace_revision_after_capture)
    try:
        snapshot = SqlContinuousSelectionReadModel(engine).read(account)
    finally:
        sa.event.remove(engine, "after_cursor_execute", replace_revision_after_capture)
    assert changed and snapshot.state == "selected"
    assert retained_connections and all(
        connection is original_connection for connection in retained_connections
    )
    assert _rows(engine, TABLES) == before
    with engine.connect() as connection:
        assert (
            connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
            == "concurrent-other-revision"
        )
    # A separate request takes a new snapshot and fails closed on that revision.
    with pytest.raises(ContinuousSelectionReadError, match=f"^{ERROR}$"):
        SqlContinuousSelectionReadModel(engine).read(account)
    assert _rows(engine, TABLES) == before
