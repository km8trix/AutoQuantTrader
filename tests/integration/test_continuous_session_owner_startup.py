"""Genuine retained owner selection over captured fixture genesis; controls stay HALTED.

This qualifies existing owners using temporary databases. It does not invoke or
implement the separately reviewed, unapplied offline initialization operation.
"""

from dataclasses import replace
from datetime import timedelta

from packages.domain.operational_control import OperationalControlState
from packages.persistence.daily_runtime_risk import RuntimeAssignmentCommand
from packages.persistence.runtime_assignment_publication import SqlRuntimeAssignmentPublication
from packages.persistence.runtime_owner_associations import SqlRuntimeOwnerAssociations
from packages.persistence.runtime_owner_commands import journal_key
from tests.integration.test_continuous_runtime_sources import Case
from tests.integration.test_runtime_owner_associations import genuine_empty_b_bootstrap
from tests.integration.test_runtime_owner_dependencies import converge


def publish_signed_assignment(fixture, assignment, name):
    pair, reader, _producer, auth, cookie, csrf = fixture
    h = pair.base.h
    previous = pair.account.restore(pair.base.scope)
    dep = reader.prepare_dependencies(previous=previous, proposed=assignment, fence=h.lease.fence)
    command = RuntimeAssignmentCommand(
        name,
        "simulation-owner",
        h.account,
        dep.record.previous_assignment_sha256,
        dep.record.proposed.semantic_sha256,
        dep.record.heads,
        dep.record.semantic_sha256,
        h.clock.instant,
        min(h.clock.instant + timedelta(seconds=60), dep.record.valid_until),
    )
    authenticated = auth.authenticate(
        command, session_cookie=cookie, csrf_token=csrf, now=command.requested_at
    )
    request = reader.commands.prepare(
        dep.record.scope,
        command=command,
        authenticated=authenticated,
        dependencies=dep.reference,
        expected_head=reader.commands.journal.read_head(journal_key(dep.record.scope)),
    )
    with pair.account.write_transaction() as connection:
        receipt = reader.commands.append_in_transaction(connection, request)
    plan = reader.prepare_owner_command_read(
        previous=dep.previous, original_receipt=receipt, fence=h.lease.fence
    )
    reader.require_plan(plan)
    current = h.store.resolve_snapshot(
        h.store.read_snapshot(account_id=h.account, fence=h.lease.fence, owner_command_ref=receipt)
    )
    prepared = h.store.prepare_assignment(
        current,
        assignment=assignment,
        expected_previous_sha256=dep.record.previous_assignment_sha256,
        owner_command_ref=receipt,
    )
    installed = SqlRuntimeAssignmentPublication(account=pair.account, daily=h.store).publish(
        prepared, fence=h.lease.fence
    )
    return installed, receipt


def genuine_captured_selection(tmp_path, monkeypatch):
    import tests.integration.test_continuous_reconciliation_publication as publication_fixture

    monkeypatch.setattr(
        publication_fixture, "Case", lambda path, **kwargs: Case(path, captured=True)
    )
    fixture = genuine_empty_b_bootstrap(tmp_path, monkeypatch)
    pair = fixture[0]
    h = pair.base.h
    initial = replace(
        h.assignment,
        generation=1,
        previous_assignment_sha256=None,
        enabled_for_new_exposure=False,
    )
    installed, initial_receipt = publish_signed_assignment(fixture, initial, "initial-selection")
    prior = converge(fixture)
    enabled = replace(
        installed,
        generation=2,
        previous_assignment_sha256=installed.semantic_sha256,
        enabled_for_new_exposure=True,
        effective_at=h.clock.instant,
    )
    enabled, enable_receipt = publish_signed_assignment(fixture, enabled, "enable-selection")
    return fixture, prior, enabled, initial_receipt, enable_receipt


def test_captured_genesis_signed_selection_and_enable_preserve_independent_halt(
    tmp_path, monkeypatch
):
    fixture, prior, enabled, initial_receipt, enable_receipt = genuine_captured_selection(
        tmp_path, monkeypatch
    )
    pair, dependencies, *_ = fixture
    try:
        h = pair.base.h
        current = h.store.resolve_snapshot(
            h.store.read_snapshot(account_id=h.account, fence=h.lease.fence)
        )
        assert current.assignment == enabled and len(current.assignment_rows) == 2
        assert enabled.enabled_for_new_exposure and not enabled.live_authorized
        assert current.control.effective_state is OperationalControlState.HALTED
        assert not current.attempts and not current.obligations.bindings
        assert prior.reconciliation.resolved.result.status == "converged"
        associations = SqlRuntimeOwnerAssociations(owner_dependencies=dependencies)
        for generation, receipt in ((1, initial_receipt), (2, enable_receipt)):
            original = associations.read(
                pair.base.scope, current=current, assignment_generation=generation
            )
            associations.require_association(original)
            assert original.request.read.receipt == receipt
        restored = pair.account.restore(pair.base.scope)
        assert restored.checkpoint.state == prior.continuous.checkpoint.state
        assert restored.checkpoint.current == prior.continuous.checkpoint.current
    finally:
        pair.close()
