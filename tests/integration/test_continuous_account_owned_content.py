"""Original owned prefix content is authenticated before external source preparation."""

from datetime import timedelta

import pytest

from packages.persistence.continuous_account import ContinuousAccountConflict
from packages.persistence.database import _repeatable_read_transaction
from tests.integration.test_continuous_account_store import Harness


@pytest.mark.parametrize("target", ["checkpoint", "request"])
def test_public_resolved_guard_detects_nested_original_engine_content_mutation(tmp_path, target):
    h = Harness(tmp_path)
    try:
        h.publish(h.prepare())
        resolved = h.store.restore(scope=h.scope)
        assert resolved is not None
        h.store.require_resolved(resolved)
        if target == "checkpoint":
            object.__setattr__(
                resolved.checkpoint, "now", resolved.checkpoint.now + timedelta(seconds=1)
            )
        else:
            object.__setattr__(resolved.request.spec, "deployment_id", "changed-original-stream")
        with pytest.raises(
            ContinuousAccountConflict, match="OWNED_RESTORED_ENGINE_CONTENT_CHANGED"
        ):
            h.store.require_resolved(resolved)
    finally:
        h.engine.dispose()


def test_history_capture_planning_gets_the_actual_previous_prefix_and_no_metadata_substitute(
    tmp_path,
):
    h = Harness(tmp_path)
    try:
        h.publish(h.prepare())
        previous = h.store.restore(h.scope)
        assert previous is not None
        receipt = h.publish(h.next(previous))
        with _repeatable_read_transaction(h.engine) as connection:
            raw = h.store.capture_current_in_transaction(connection, scope=h.scope)
        assert raw is not None
        through = h.store.resolve_index(raw)
        assert through.composition_plan is None
        with (
            _repeatable_read_transaction(h.engine) as connection,
            pytest.raises(ContinuousAccountConflict, match="PREVIOUS_PREFIX_PLAN"),
        ):
            h.store.capture_snapshot_in_transaction(connection, index=through)
        observed = []
        original = h.composer.prepare_capture

        def prepare(commit, *, previous):
            observed.append(previous)
            return original(commit, previous=previous)

        h.composer.prepare_capture = prepare
        index = h.store.resolve_index(raw, previous=previous)
        with _repeatable_read_transaction(h.engine) as connection:
            snapshot = h.store.capture_snapshot_in_transaction(connection, index=index)
        restored = h.store.resolve_snapshot(snapshot, previous=previous)
        assert restored.receipt == receipt
        assert observed and all(value is previous for value in observed)
    finally:
        h.engine.dispose()
