"""Original PENDING publication/restore with an additional exact handoff profile assertion.

This copy retains the original financial, ownership and inert-retry assertions.
Its actual fixture is separately released by the root; pure profile runs exclude it.
"""

import pytest

from packages.persistence.continuous_attempt_publication import (
    CommittedSimulationAttemptBatch,
    SqlContinuousAttemptPublication,
)
from tests.integration import test_continuous_attempt_publication as original

attempt_case = original.attempt_case
preparation = original.preparation


def test_original_pending_publication_has_case_in_exact_returned_handoff_graph(attempt_case):
    case, _service, _reader, previous, _current, _admission = attempt_case
    source, mutation, prepared = preparation(attempt_case)
    publication = SqlContinuousAttemptPublication(account=case.store)
    with pytest.raises(ValueError, match="FIRST_SEND"):
        publication.publish_dispatch(prepared, fence=case.h.lease.fence)
    receipt = publication.publish(prepared, fence=case.h.lease.fence)
    with pytest.raises(ValueError, match="SUCCESSFUL_DISPATCH_COMMIT"):
        publication.require_completed(CommittedSimulationAttemptBatch(receipt, prepared, mutation))
    current = case.h.resolved()
    restored = case.store.restore(case.scope)
    assert restored.receipt == receipt
    assert restored.checkpoint.state == previous.checkpoint.state
    assert restored.checkpoint.current == previous.checkpoint.current
    assert restored.checkpoint.now == source.source.checked_at > previous.checkpoint.now
    assert restored.checkpoint.runtime_decisions == previous.checkpoint.runtime_decisions
    assert current.attempts == mutation.result.attempts
    assert all(item.state.value == "pending" for item in current.attempts)
    assert current.obligations == mutation.result.obligations == mutation.snapshot.obligations
    assert (
        restored.receipt.commit.transition.resulting_heads.attempt_sha256
        != previous.receipt.commit.transition.resulting_heads.attempt_sha256
    )
    with case.store.write_transaction() as connection:
        retried = case.store.retry_in_transaction(
            connection,
            original=restored,
            command_sha256=prepared.commit.transition.command_sha256,
            fence=case.h.lease.fence,
        )
    assert retried is restored.receipt
    assert case.h.resolved().attempts == current.attempts

    from sqlalchemy.sql.elements import Case

    from packages.persistence import continuous_integrity as integrity

    records = integrity._factory_structure(
        (restored, current), account=case.store, daily=case.h.store
    )
    assert any(kind == "fields" and type(item) is Case for kind, item, *_ in records)
    integrity._require_factory_structure(records)
