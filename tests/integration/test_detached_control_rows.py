"""The existing control reducer is shared by SQL and detached runtime reads."""

from types import MappingProxyType

import pytest
import sqlalchemy as sa

from packages.domain.operational_control import OperationalControlConflict
from packages.persistence.operational_control import resolve_operational_control_rows
from packages.persistence.schema import (
    phase5_operational_control_completions as completions,
)
from packages.persistence.schema import (
    phase5_operational_control_heads as heads,
)
from packages.persistence.schema import (
    phase5_operational_control_transitions as transitions,
)
from tests.integration.test_phase5_operational_control_persistence import (
    ACCOUNT_ID,
    _engine,
    _initialize,
    _repository,
    _running_repository,
)


def rows(engine):
    with engine.begin() as connection:
        connection.exec_driver_sql("BEGIN")
        return {
            "account_id": ACCOUNT_ID,
            "transition_rows": tuple(
                MappingProxyType(dict(r))
                for r in connection.execute(
                    sa.select(transitions).order_by(transitions.c.sequence_number)
                ).mappings()
            ),
            "completion_rows": tuple(
                MappingProxyType(dict(r))
                for r in connection.execute(sa.select(completions)).mappings()
            ),
            "head_row": next(
                (
                    MappingProxyType(dict(r))
                    for r in connection.execute(sa.select(heads)).mappings()
                ),
                None,
            ),
        }


def test_absent_and_halted_control_rows_share_original_reducer_after_connection_closes(tmp_path):
    engine = _engine(tmp_path / "detached.sqlite")
    assert resolve_operational_control_rows(**rows(engine)) is None
    repository, _ = _repository(engine)
    _, expected = _initialize(repository)
    detached = rows(engine)
    engine.dispose()
    assert resolve_operational_control_rows(**detached) == expected


def test_detached_rearm_history_matches_actual_repository_and_checks_full_history(tmp_path):
    engine = _engine(tmp_path / "rearm.sqlite")
    repository, _, expected = _running_repository(engine)
    detached = rows(engine)
    assert resolve_operational_control_rows(**detached) == repository.load(ACCOUNT_ID) == expected
    with pytest.raises(OperationalControlConflict):
        resolve_operational_control_rows(
            **{**detached, "transition_rows": detached["transition_rows"][1:]}
        )
    with pytest.raises(OperationalControlConflict):
        resolve_operational_control_rows(**{**detached, "account_id": "other-account"})
    altered = dict(detached["head_row"])
    altered["effective_state"] = "halted"
    with pytest.raises(ValueError):
        resolve_operational_control_rows(**{**detached, "head_row": MappingProxyType(altered)})
    engine.dispose()
