"""One rollback-contained missing-head negative, never a valid C2 or writer."""

import pytest
import sqlalchemy as sa

from packages.persistence.continuous_account import ContinuousAccountConflict
from packages.persistence.continuous_account_schema import continuous_account_heads
from packages.persistence.schema import phase2_account_lease_heads
from tests.integration.test_operational_control_operator_account_context import (
    _account_interval,
    _assert_unchanged,
    _rows,
)
from tests.integration.test_operational_control_operator_account_context import (
    account_context as account_context,
)
from tests.integration.test_operational_control_operator_account_context import (
    captured as captured,
)


def test_missing_c1_head_denies_and_original_transaction_rolls_back(account_context):
    value = account_context
    engine = value.ports["account_engine"]
    heads_before = _rows(engine, (continuous_account_heads, phase2_account_lease_heads))
    assert len(heads_before[continuous_account_heads.name]) == 1
    value.current.account.require_resolved(value.c)
    with (
        pytest.raises(
            ContinuousAccountConflict, match=r"^CONTINUOUS_EMPTY_HEAD_HAS_RETAINED_HISTORY$"
        ),
        _account_interval(value),
        value.current.account.write_transaction() as connection,
    ):
        value.final_connection = connection
        assert connection.engine is engine
        assert connection.connection.driver_connection.in_transaction is True
        deleted = connection.execute(
            sa.delete(continuous_account_heads).where(
                continuous_account_heads.c.account_id == value.scope.account_id
            )
        )
        assert deleted.rowcount == 1
        value.current.account.recheck_in_transaction(connection, value.c, require_current=True)
        # This exception also escapes the owner context: unexpected success must
        # roll back, never commit the deliberate corruption.
        raise AssertionError("missing-head currentness unexpectedly succeeded")
    assert _rows(engine, (continuous_account_heads, phase2_account_lease_heads)) == heads_before
    _assert_unchanged(value)
    # Confirm actual restored currentness, without B/coordinator metadata writes.
    with _account_interval(value), value.current.account.write_transaction() as connection:
        value.final_connection = connection
        assert (
            value.current.account.recheck_in_transaction(connection, value.c, require_current=True)
            is None
        )
    assert _rows(engine, (continuous_account_heads, phase2_account_lease_heads)) == heads_before
    _assert_unchanged(value)
