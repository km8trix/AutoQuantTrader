"""Modeled-time local auth is test-only; the app consumes a retained request.

No HTTP transport or real-operator/model-time bridge is qualified here. The
separate API command owner uses actual session/CSRF authentication and writes
only its journal. The worker keeps its original disabled authenticator.
"""

from dataclasses import replace
from datetime import timedelta
from http.cookies import SimpleCookie
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from fastapi import Response

from apps.api.backtest_views import LOCAL_SESSION_COOKIE, LocalOperatorSecurity
from apps.api.runtime_owner_authentication import LocalRuntimeOwnerAuthenticator
from apps.trader.synthetic_initial_selection import (
    prepare_synthetic_initial_selection,
    publish_synthetic_initial_selection,
)
from apps.trader.synthetic_session_genesis import (
    initialize_synthetic_session,
    reconstruct_synthetic_session_owners,
)
from packages.application import personal_codec as codec
from packages.domain.account_coordinator import AccountCoordinatorError
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlCommand,
    OperationalControlCommandKind,
    OperationalControlState,
)
from packages.domain.personal_contracts import content_digest
from packages.persistence.continuous_account_schema import CONTINUOUS_ACCOUNT_TABLES
from packages.persistence.daily_runtime_risk import RuntimeAssignmentCommand, RuntimeReadBudget
from packages.persistence.daily_runtime_risk_schema import (
    DAILY_RUNTIME_TABLES,
    daily_runtime_assignment_heads,
    daily_runtime_assignments,
)
from packages.persistence.durable_journal_schema import JOURNAL_TABLES, journal_entries
from packages.persistence.operational_control import SqlOperationalControlRepository
from packages.persistence.runtime_owner_commands import (
    RuntimeOwnerCommandError,
    SqlRuntimeOwnerCommands,
    journal_key,
)
from packages.persistence.runtime_owner_dependencies import RuntimeOwnerDependencyError
from packages.persistence.schema import (
    phase2_account_lease_releases,
    phase2_account_leases,
    phase5_operational_control_completions,
    phase5_operational_control_heads,
    phase5_operational_control_transitions,
)
from tests.integration.test_continuous_synthetic_session_genesis import captured as captured


@pytest.fixture
def selection(captured):
    bootstrap, ports = captured
    genesis = initialize_synthetic_session(bootstrap, **ports)
    lease = genesis.account.coordinator.acquire("synthetic-selection-test")
    try:
        owners = reconstruct_synthetic_session_owners(genesis, lease=lease)
        dependencies = prepare_synthetic_initial_selection(genesis, owners=owners, lease=lease)
        yield SimpleNamespace(
            genesis=genesis, ports=ports, lease=lease, owners=owners, dependencies=dependencies
        )
    finally:
        # The app never takes this obligation, on success or failure. The outer
        # captured fixture subsequently disposes both independent engines.
        genesis.account.coordinator.release(lease.fence)
        assert genesis.account.coordinator.current() is None


def _rows(engine, tables):
    with engine.connect() as connection:
        return tuple(
            tuple(
                tuple(row)
                for row in connection.execute(sa.select(table).order_by(*table.primary_key.columns))
            )
            for table in tables
        )


def _facts(study, *, include_assignments=True):
    daily = tuple(
        table
        for table in DAILY_RUNTIME_TABLES
        if include_assignments
        or (table is not daily_runtime_assignments and table is not daily_runtime_assignment_heads)
    )
    return (
        _rows(
            study.ports["account_engine"],
            (
                *CONTINUOUS_ACCOUNT_TABLES,
                *daily,
                *JOURNAL_TABLES,
                phase5_operational_control_transitions,
                phase5_operational_control_heads,
                phase5_operational_control_completions,
                phase2_account_leases,
                phase2_account_lease_releases,
            ),
        ),
        _rows(study.ports["venue_engine"], JOURNAL_TABLES),
        tuple(
            tuple(sorted((path.name, path.read_bytes()) for path in store._root.iterdir()))
            for store in (study.ports["account_artifacts"], study.ports["venue_artifacts"])
        ),
    )


def _inventory(study):
    return study.owners.daily.resolve_snapshot(
        study.owners.daily.read_snapshot(
            account_id=study.genesis.scope.account_id, fence=study.lease.fence
        )
    )


def _request(study, *, scope=None, lifetime=30, changes=None, copy_auth=False):
    # This models a local API at the fixture's time. No application component
    # enables security or asserts a real loopback transport for this test.
    at = study.ports["clock"].now()
    security = LocalOperatorSecurity(
        enabled=True,
        transport_is_loopback_scoped=True,
        operator_id="modeled-test-operator",
        configured_secret="test-only-not-an-application-credential",
    )
    response = Response()
    capability = security.bootstrap_capability(
        response, persistence_ready=True, issued_at=at, session_cookie=None
    )
    cookies = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    assert type(capability.csrf_token) is str
    authenticator = LocalRuntimeOwnerAuthenticator(security)
    api = SqlRuntimeOwnerCommands(
        study.ports["account_engine"], codec=codec, authenticator=authenticator
    )
    dep = study.dependencies
    command = RuntimeAssignmentCommand(
        "synthetic-initial-selection-request",
        "modeled-test-operator",
        study.genesis.scope.account_id,
        None,
        dep.record.proposed.semantic_sha256,
        dep.record.heads,
        dep.record.semantic_sha256,
        at,
        min(at + timedelta(seconds=lifetime), dep.record.valid_until),
    )
    if changes:
        command = replace(command, **changes)
    authenticated = authenticator.authenticate(
        command,
        session_cookie=cookies[LOCAL_SESSION_COOKIE].value,
        csrf_token=capability.csrf_token,
        now=at,
    )
    selected_scope = scope or study.genesis.scope
    prepared = api.prepare(
        selected_scope,
        command=command,
        authenticated=replace(authenticated) if copy_auth else authenticated,
        dependencies=dep.reference,
        expected_head=api.journal.read_head(journal_key(selected_scope)),
    )
    api.require_prepared(prepared)
    with study.ports["account_engine"].begin() as connection:
        # SQLAlchemy's transaction object alone does not start a real SQLite
        # transaction. Preserve the journal's explicit caller-transaction guard.
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        receipt = api.append_in_transaction(connection, prepared)
    return SimpleNamespace(
        api=api, authenticated=authenticated, prepared=prepared, command=command, receipt=receipt
    )


def _publish(study, retained, **changes):
    arguments = dict(
        owners=study.owners,
        lease=study.lease,
        dependencies=study.dependencies,
        request=retained.receipt,
    )
    arguments.update(changes)
    return publish_synthetic_initial_selection(study.genesis, **arguments)


def _retained(study, request):
    retained = study.owners.owners.commands.read(
        study.genesis.scope,
        command_id=request.command.command_id,
        budget=RuntimeReadBudget(),
    )
    assert retained is not None
    study.owners.owners.commands.require_resolved(retained)
    assert retained.read.receipt == request.receipt
    assert retained.record.command == request.command
    return retained


def test_separate_authenticated_request_installs_only_disabled_initial_selection(selection):
    study = selection
    request = _request(study)
    worker = study.owners.owners.commands
    assert request.api is not worker and request.api.authenticator is not worker.authenticator
    assert worker.authenticator.security._enabled is False
    assert _inventory(study).assignment is None
    _retained(study, request)
    before = _facts(study, include_assignments=False)
    installed = _publish(study, request)
    assert installed is study.dependencies.record.proposed
    current = _inventory(study)
    assert current.assignment == installed and current.assignment_rows == (installed,)
    assert installed.generation == 1 and installed.previous_assignment_sha256 is None
    assert installed.enabled_for_new_exposure is False and installed.live_authorized is False
    spec = study.genesis.restored.checkpoint.inputs.spec
    assert installed.policy == spec.risk_policy
    assert installed.strategy == spec.strategy
    assert installed.configuration_sha256 == content_digest(spec.strategy_configuration)
    assert installed.instrument_symbols == spec.instruments
    assert installed.producer_map_sha256 == study.owners.runtime.producer_map.semantic_sha256
    assert current.control == study.genesis.control
    assert current.control.effective_state is OperationalControlState.HALTED
    assert not current.attempts and not current.obligations.bindings and not current.admissions
    restored = study.owners.account.restore(study.genesis.scope)
    assert restored.receipt == study.genesis.restored.receipt
    assert restored.checkpoint == study.genesis.restored.checkpoint
    venue = study.genesis.venue.read()
    assert not venue.state.commands and not venue.state.accounting.submissions
    assert _facts(study, include_assignments=False) == before
    assert study.genesis.account.coordinator.current() == study.lease
    assert worker.authenticator.security._enabled is False


def test_retained_request_is_not_an_installed_assignment(selection):
    request = _request(selection)
    retained = _retained(selection, request)
    assert retained.record.dependencies == selection.dependencies.reference
    assert _inventory(selection).assignment is None
    assert _rows(selection.ports["account_engine"], (daily_runtime_assignments,)) == ((),)


def test_copied_prepared_dependencies_are_not_owner_authority(selection):
    request = _request(selection)
    before = _facts(selection)
    with pytest.raises(
        RuntimeOwnerDependencyError, match=r"^OWNED_ORIGINAL_OWNER_DEPENDENCIES_REQUIRED$"
    ):
        _publish(selection, request, dependencies=replace(selection.dependencies))
    assert _facts(selection) == before


def test_copied_authentication_cannot_retain_a_request(selection):
    before = _facts(selection)
    with pytest.raises(RuntimeOwnerCommandError, match=r"^OWNER_REQUEST_PREPARATION_FAILED$"):
        _request(selection, copy_auth=True)
    assert _facts(selection) == before


def test_genuine_foreign_stream_request_cannot_select_this_account(selection):
    foreign_scope = replace(selection.genesis.scope, stream_id="foreign-synthetic-stream")
    request = _request(selection, scope=foreign_scope)
    assert (
        request.api.read(
            foreign_scope, command_id=request.command.command_id, budget=RuntimeReadBudget()
        )
        is not None
    )
    before = _facts(selection)
    with pytest.raises(
        RuntimeOwnerDependencyError, match=r"^ACTUAL_RETAINED_OWNER_REQUEST_REQUIRED$"
    ):
        _publish(selection, request)
    assert _facts(selection) == before


@pytest.mark.parametrize("field", ["command_sha256", "append_sha256"])
def test_altered_request_receipt_cannot_replace_retained_request(selection, field):
    request = _request(selection)
    changed = replace(request.receipt, **{field: content_digest(("changed", field))})
    before = _facts(selection)
    with pytest.raises(
        RuntimeOwnerDependencyError, match=r"^ACTUAL_RETAINED_OWNER_REQUEST_REQUIRED$"
    ):
        _publish(selection, request, request=changed)
    assert _facts(selection) == before


def test_authenticated_conflicting_assignment_is_not_adopted(selection):
    request = _request(selection, changes={"after_assignment_sha256": content_digest("different")})
    before = _facts(selection)
    with pytest.raises(
        RuntimeOwnerDependencyError,
        match=r"^OWNER_REQUEST_ORIGINAL_DEPENDENCIES_DIFFER_OR_EXPIRED$",
    ):
        _publish(selection, request)
    assert _facts(selection) == before
    _retained(selection, request)


def test_expired_request_stays_retained_without_refresh_or_lease_change(selection):
    request = _request(selection, lifetime=1)
    selection.ports["clock"].advance_to(request.command.expires_at)
    before = _facts(selection)
    with pytest.raises(
        RuntimeOwnerDependencyError,
        match=r"^OWNER_REQUEST_ORIGINAL_DEPENDENCIES_DIFFER_OR_EXPIRED$",
    ):
        _publish(selection, request)
    assert _facts(selection) == before
    _retained(selection, request)
    assert selection.genesis.account.coordinator.current() == selection.lease


def test_changed_control_head_is_not_adopted(selection):
    request = _request(selection)
    controls = SqlOperationalControlRepository(
        engine=selection.ports["account_engine"], clock=selection.ports["clock"]
    )
    changed = controls.apply(
        OperationalControlCommand(
            selection.genesis.scope.account_id,
            "later-selection-halt",
            OperationalControlCommandKind.HALT,
            OperationalControlState.HALTED,
            OperationalControlActor(
                "system", OperationalControlActorKind.SYSTEM, content_digest("halt"), None
            ),
            "TEST_LATER_HALT",
            content_digest("later-selection-halt"),
            selection.ports["clock"].now(),
        )
    )
    before = _facts(selection)
    with pytest.raises(ValueError):
        _publish(selection, request)
    assert controls.load(selection.genesis.scope.account_id) == changed
    assert _facts(selection) == before
    assert _inventory(selection).assignment is None


def test_released_startup_fence_cannot_publish_current_selection(selection):
    request = _request(selection)
    before = _facts(selection)
    with pytest.raises(AccountCoordinatorError, match="account fence is no longer current"):
        _publish(selection, request, lease=selection.genesis.lease)
    assert _facts(selection) == before


def test_renewal_does_not_refresh_original_dependency_revision(selection):
    request = _request(selection)
    coordinator = selection.genesis.account.coordinator
    selection.ports["clock"].advance_to(selection.lease.acquired_at + timedelta(seconds=1))
    renewed = coordinator.renew(selection.lease.fence)
    before = _facts(selection)
    with pytest.raises(ValueError, match=r"^CURRENT_SYNTHETIC_LEASE_REVISION_REQUIRED$"):
        _publish(selection, request)
    with pytest.raises(
        RuntimeOwnerDependencyError, match=r"^OWNER_ORIGINAL_FENCE_OR_TIME_DIFFERS$"
    ):
        _publish(selection, request, lease=renewed)
    assert _facts(selection) == before
    assert coordinator.current() == renewed


def test_duplicate_installation_denies_without_mutation(selection):
    request = _request(selection)
    _publish(selection, request)
    before = _facts(selection)
    with pytest.raises(ValueError, match=r"^SYNTHETIC_SELECTION_REQUIRES_HALTED_EMPTY_B$"):
        _publish(selection, request)
    assert _facts(selection) == before
    _retained(selection, request)


def test_changed_retained_request_bytes_fail_original_journal_validation(selection):
    request = _request(selection)
    engine = selection.ports["account_engine"]
    key = journal_key(selection.genesis.scope).semantic_sha256
    with engine.begin() as connection:
        changed = connection.execute(
            sa.update(journal_entries)
            .where(journal_entries.c.key_sha256 == key)
            .values(payload=b"{}")
        )
        assert changed.rowcount == 1
    before = _facts(selection)
    with pytest.raises(RuntimeOwnerCommandError, match=r"^OWNER_REQUEST_RESOLUTION_FAILED$"):
        _publish(selection, request)
    assert _facts(selection) == before
    assert _inventory(selection).assignment is None


def test_physical_assignment_failure_retains_request_and_rolls_back(selection):
    request = _request(selection)
    engine = selection.ports["account_engine"]
    failure = RuntimeError("injected physical initial assignment failure")
    calls = []

    def fail_assignment(connection, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("INSERT INTO DAILY_RUNTIME_ASSIGNMENTS"):
            calls.append(statement)
            raise failure

    before = _facts(selection)
    sa.event.listen(engine, "before_cursor_execute", fail_assignment)
    try:
        with pytest.raises(RuntimeError) as caught:
            _publish(selection, request)
        assert caught.value is failure
    finally:
        sa.event.remove(engine, "before_cursor_execute", fail_assignment)
    assert len(calls) == 1
    assert _facts(selection) == before
    assert _inventory(selection).assignment is None
    _retained(selection, request)
    assert selection.genesis.account.coordinator.current() == selection.lease
