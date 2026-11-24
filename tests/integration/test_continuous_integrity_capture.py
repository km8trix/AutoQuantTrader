"""Coherent existing lease/control dependencies share the unchanged W4 capture cap."""

import pytest
import sqlalchemy as sa

from packages.persistence import database
from packages.persistence.schema import phase2_account_leases
from tests.integration.test_personal_continuous_migration import TABLES
from tests.integration.test_sql_daily_runtime_risk import harness

__all__ = ["harness"]


def capture(harness):
    with database._repeatable_read_transaction(harness.engine) as connection:
        return database._capture_continuous_integrity_snapshot(connection, tables=TABLES)


def test_six_existing_dependencies_are_separate_immutable_and_coherent(harness):
    snapshot = capture(harness)
    assert len(snapshot.tables) == 16
    assert tuple(snapshot.dependencies) == tuple(
        table.name for table in database.CONTINUOUS_INTEGRITY_DEPENDENCY_TABLES
    )
    assert len(snapshot.dependencies[phase2_account_leases.name]) == 1
    with pytest.raises(TypeError):
        snapshot.dependencies[phase2_account_leases.name] = ()
    with pytest.raises(TypeError):
        snapshot.dependencies[phase2_account_leases.name][0]["invented"] = 1
    with harness.engine.connect() as connection:
        for table in database.CONTINUOUS_INTEGRITY_DEPENDENCY_TABLES:
            assert snapshot.dependencies[table.name] == tuple(
                dict(row)
                for row in connection.execute(
                    sa.select(table).order_by(*table.primary_key.columns)
                ).mappings()
            )


@pytest.mark.parametrize("budget", ["rows", "bytes"])
def test_dependencies_consume_same_combined_budget(harness, monkeypatch, budget):
    snapshot = capture(harness)
    if budget == "rows":
        financial = sum(map(len, snapshot.tables.values()))
        monkeypatch.setattr(database, "MAX_CONTINUOUS_INTEGRITY_ROWS", financial)
    else:
        with harness.engine.connect() as connection:
            financial = sum(
                connection.scalar(
                    sa.select(
                        sa.func.coalesce(
                            sa.func.sum(
                                sum(
                                    (
                                        database._continuous_field_check(connection, column)[1]
                                        for column in table.c
                                    ),
                                    sa.literal(0),
                                )
                            ),
                            0,
                        )
                    ).select_from(table)
                )
                for table in TABLES
            )
        monkeypatch.setattr(database, "MAX_CONTINUOUS_INTEGRITY_BYTES", financial)
    with pytest.raises(database.DatabaseSchemaNotReady, match="bounds"):
        capture(harness)
