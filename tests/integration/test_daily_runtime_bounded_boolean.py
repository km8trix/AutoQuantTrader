"""Bounded Boolean SQL projection regression; fixtures grant no runtime authority."""

from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql, sqlite

from packages.persistence.daily_runtime_risk import (
    MAX_METADATA_BYTES,
    MAX_TOTAL_ROWS,
    DailyRuntimeRiskConflict,
    RuntimeReadBudget,
    _expressions,
    _typed_rows,
    capture_runtime_table,
)


def columns(*, nullable=True):
    return sa.Table(
        "bounded_boolean",
        sa.MetaData(),
        sa.Column("account_id", sa.String(32), primary_key=True),
        sa.Column("row_id", sa.Integer, primary_key=True),
        sa.Column("flag", sa.Boolean, nullable=nullable),
        sa.Column("counter", sa.BigInteger, nullable=False),
    )


@pytest.mark.parametrize(
    "dialect", [postgresql.dialect(), sqlite.dialect()], ids=["postgresql", "sqlite"]
)
def test_boolean_projection_uses_supported_integer_width_without_narrowing_integer_fields(dialect):
    table = columns()
    connection = SimpleNamespace(dialect=dialect)
    bool_projection = _expressions(table.c.flag, connection)[1]
    integer_projection = _expressions(table.c.counter, connection)[1]
    statement = sa.select(bool_projection, integer_projection).compile(
        dialect=dialect, compile_kwargs={"literal_binds": True}
    )
    sql = str(statement)
    assert "CAST(bounded_boolean.flag AS INTEGER)" in sql
    assert "CAST(bounded_boolean.flag AS BIGINT)" not in sql
    assert "CAST(bounded_boolean.counter AS BIGINT)" in sql


def test_sqlite_boolean_capture_retains_raw_int_typed_bool_null_and_wide_integer():
    table = columns()
    engine = sa.create_engine("sqlite+pysqlite:///:memory:")
    try:
        table.metadata.create_all(engine)
        with engine.begin() as connection:
            connection.execute(
                table.insert(),
                [
                    {
                        "account_id": "boolean-fixture",
                        "row_id": index,
                        "flag": flag,
                        "counter": 2**40,
                    }
                    for index, flag in enumerate((False, True, None))
                ],
            )
            budget = RuntimeReadBudget()
            raw = capture_runtime_table(
                connection, table, account_id="boolean-fixture", budget=budget
            )
        assert [row["flag"] for row in raw.rows] == [0, 1, None]
        assert all(type(row["flag"]) is int for row in raw.rows[:2])
        assert [row["flag"] for row in _typed_rows(raw)] == [False, True, None]
        assert all(type(row["flag"]) is bool for row in _typed_rows(raw)[:2])
        assert all(row["counter"] == 2**40 and type(row["counter"]) is int for row in raw.rows)
        assert budget.rows == 3 and budget.metadata_bytes > 0
        assert budget.captured == [raw]
    finally:
        engine.dispose()


@pytest.mark.parametrize("value", [2, -1, 1.5, "true", b"\x01", None])
def test_malformed_sqlite_storage_is_rejected_before_row_transfer(value):
    # Deliberately malformed physical fixture permits NULL despite the declared
    # non-null Boolean metadata. Production schema guards are not substituted.
    table = columns(nullable=False)
    engine = sa.create_engine("sqlite+pysqlite:///:memory:")
    statements = []
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE TABLE bounded_boolean (account_id TEXT, row_id INTEGER, "
                "flag BOOLEAN, counter BIGINT, PRIMARY KEY(account_id,row_id))"
            )
            connection.exec_driver_sql(
                "INSERT INTO bounded_boolean VALUES ('boolean-fixture', 1, ?, 1)", (value,)
            )
            sa.event.listen(
                connection,
                "before_cursor_execute",
                lambda _c, _cur, statement, _p, _ctx, _many: statements.append(statement),
            )
            budget = RuntimeReadBudget()
            with pytest.raises(
                DailyRuntimeRiskConflict, match="invalid or oversized retained SQL field"
            ):
                capture_runtime_table(
                    connection, table, account_id="boolean-fixture", budget=budget
                )
            assert len(statements) == 1  # Aggregate validation rejects before bounded row transfer.
            assert budget.captured == []
    finally:
        engine.dispose()


@pytest.mark.parametrize("kind", ["rows", "metadata"])
def test_boolean_capture_still_shares_original_row_and_metadata_budget(kind):
    table = columns()
    engine = sa.create_engine("sqlite+pysqlite:///:memory:")
    try:
        table.metadata.create_all(engine)
        with engine.begin() as connection:
            connection.execute(
                table.insert().values(account_id="boolean-fixture", row_id=1, flag=True, counter=1)
            )
            budget = RuntimeReadBudget(
                rows=MAX_TOTAL_ROWS if kind == "rows" else 0,
                metadata_bytes=MAX_METADATA_BYTES if kind == "metadata" else 0,
            )
            with pytest.raises(DailyRuntimeRiskConflict, match="aggregate capture bound"):
                capture_runtime_table(
                    connection, table, account_id="boolean-fixture", budget=budget
                )
            assert budget.captured == []
    finally:
        engine.dispose()
