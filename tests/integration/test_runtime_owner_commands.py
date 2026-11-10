"""Real signed local sessions retain bounded requests, never applied assignments."""

from dataclasses import replace
from datetime import timedelta

import pytest
import sqlalchemy as sa
from fastapi import HTTPException

from apps.api.runtime_owner_authentication import LocalRuntimeOwnerAuthenticator
from packages.application import personal_codec as codec
from packages.application.runtime_owner_authentication import AuthenticatedRuntimeOwnerCommand
from packages.domain.continuous_persistence_contracts import (
    ContinuousAccountScope,
    ContinuousEvidenceRef,
)
from packages.domain.durable_journal_contracts import JournalAppend, JournalRecord, empty_head
from packages.domain.research_job_contracts import ObjectRef
from packages.persistence.daily_runtime_risk import MAX_TOTAL_BYTES, RuntimeReadBudget
from packages.persistence.database import _repeatable_read_transaction, create_database_engine
from packages.persistence.durable_journal_schema import JOURNAL_TABLES, journal_entries
from packages.persistence.runtime_owner_commands import (
    OWNER_COMMAND_SCHEMA,
    OWNER_DEPENDENCIES_SCHEMA,
    RuntimeOwnerCommandError,
    SqlRuntimeOwnerCommands,
    journal_key,
)
from packages.persistence.schema import metadata
from tests.unit.test_runtime_owner_authentication import NOW, _command, _session


@pytest.fixture
def case(tmp_path):
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path}/owner.sqlite")
    metadata.create_all(engine, tables=JOURNAL_TABLES)
    security, cookie, csrf = _session()
    authority = LocalRuntimeOwnerAuthenticator(security)
    store = SqlRuntimeOwnerCommands(engine, codec=codec, authenticator=authority)
    scope = ContinuousAccountScope(_command().account_id, "b" * 64, "local-simulation")
    yield store, scope, authority, cookie, csrf
    engine.dispose()


def preparation(case, *, command=None, expected=None):
    store, scope, authority, cookie, csrf = case
    command = command or _command()
    authenticated = authority.authenticate(
        command, session_cookie=cookie, csrf_token=csrf, now=command.requested_at
    )
    dependencies = ContinuousEvidenceRef(
        OWNER_DEPENDENCIES_SCHEMA, ObjectRef("1" * 64, 100), command.quiescence_sha256
    )
    return store.prepare(
        scope,
        command=command,
        authenticated=authenticated,
        dependencies=dependencies,
        expected_head=expected or empty_head(journal_key(scope)),
    )


def append(store, prepared):
    store.require_prepared(prepared)
    with store.engine.begin() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        return store.append_in_transaction(connection, prepared)


def read(store, scope, command_id=None):
    return store.read(
        scope, command_id=command_id or _command().command_id, budget=RuntimeReadBudget()
    )


def count(store):
    with store.engine.connect() as connection:
        return connection.scalar(sa.select(sa.func.count()).select_from(journal_entries))


def test_actual_signed_session_retains_exact_request_and_restart_reads_no_credentials(case):
    store, scope, _, cookie, csrf = case
    prepared = preparation(case)
    receipt = append(store, prepared)
    other_authority = LocalRuntimeOwnerAuthenticator(_session()[0])
    restarted = SqlRuntimeOwnerCommands(store.engine, codec=codec, authenticator=other_authority)
    original = read(restarted, scope)
    assert original.record == prepared.record and original.read.receipt == receipt
    restarted.require_resolved(original)
    assert original.record.authentication.command_sha256 == original.record.command.semantic_sha256
    assert original.record.dependencies.semantic_sha256 == original.record.command.quiescence_sha256
    assert receipt.command_sha256 == original.record.command.semantic_sha256
    key = journal_key(scope)
    assert (key.namespace, key.source_provider, key.source_environment) == (
        "coordinator",
        "local-owner-session",
        "synthetic",
    )
    assert key.source_scope_sha256 == scope.semantic_sha256
    payload = codec.encode_record(original.record)
    assert cookie.encode() not in payload and csrf.encode() not in payload
    assert not hasattr(original.record, "verified") and count(store) == 1
    with _repeatable_read_transaction(store.engine) as connection:
        assert restarted.recheck_in_transaction(connection, original) == receipt


def test_expired_current_auth_rejects_but_original_request_and_retry_keep_old_times(
    case, monkeypatch
):
    store, scope, authority, cookie, csrf = case
    first = preparation(case)
    original_receipt = append(store, first)
    original = read(store, scope)
    later_command = replace(_command(at=NOW + timedelta(seconds=1)), command_id="later-request")
    second = preparation(case, command=later_command, expected=original_receipt.committed_head)
    append(store, second)
    late = NOW + timedelta(hours=8)
    with pytest.raises(HTTPException):
        authority.authenticate(_command(at=late), session_cookie=cookie, csrf_token=csrf, now=late)

    def forbidden(*args, **kwargs):
        raise AssertionError("historical requests must not reauthenticate")

    monkeypatch.setattr(authority, "require_authenticated", forbidden)
    restarted = SqlRuntimeOwnerCommands(store.engine, codec=codec, authenticator=authority)
    restored = read(restarted, scope)
    assert restored.record == original.record
    assert restored.record.authentication.command_expires_at == NOW + timedelta(seconds=60)
    assert restored.record.authentication.session_expires_at == late
    with _repeatable_read_transaction(store.engine) as connection:
        assert restarted.recheck_in_transaction(connection, restored) == original_receipt
        assert store.recheck_in_transaction(connection, original) == original_receipt
    # Even an in-process original append remains an immutable retry; no new issuance.
    with store.engine.begin() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        assert store.append_in_transaction(connection, first) == original_receipt
    assert count(store) == 2


@pytest.mark.parametrize(
    "change",
    [
        "command",
        "owner",
        "account",
        "time",
        "expiry",
        "dependency",
        "schema",
        "size",
        "token",
        "issuer",
    ],
)
def test_changed_command_dependencies_scope_or_authentication_never_append(case, change):
    store, scope, authority, _, _ = case
    prepared = preparation(case)
    command, authenticated, dependencies = (
        prepared.record.command,
        prepared.authenticated,
        prepared.record.dependencies,
    )
    if change == "command":
        command = replace(command, after_assignment_sha256="2" * 64)
    elif change == "owner":
        command = replace(command, owner_id="other-owner")
    elif change == "account":
        scope = replace(scope, account_id="other-account")
    elif change == "time":
        command = replace(command, requested_at=NOW + timedelta(microseconds=1))
    elif change == "expiry":
        command = replace(command, expires_at=command.expires_at + timedelta(microseconds=1))
    elif change == "dependency":
        dependencies = replace(dependencies, semantic_sha256="2" * 64)
    elif change == "schema":
        dependencies = replace(dependencies, schema_id="unreviewed/1")
    elif change == "size":
        dependencies = replace(
            dependencies, object_ref=replace(dependencies.object_ref, byte_count=256 * 1024 + 1)
        )
    elif change == "token":
        authenticated = AuthenticatedRuntimeOwnerCommand(
            authenticated.authentication, authenticated.seal
        )
    else:
        authority = LocalRuntimeOwnerAuthenticator(_session()[0])
        store = SqlRuntimeOwnerCommands(store.engine, codec=codec, authenticator=authority)
    with pytest.raises(RuntimeOwnerCommandError):
        store.prepare(
            scope,
            command=command,
            authenticated=authenticated,
            dependencies=dependencies,
            expected_head=empty_head(journal_key(scope)),
        )
    assert count(store) == 0


@pytest.mark.parametrize("cookie_change,csrf_change", [(True, False), (False, True)])
def test_invalid_actual_session_or_csrf_cannot_start_durable_request(
    case, cookie_change, csrf_change
):
    store, _, authority, cookie, csrf = case
    with pytest.raises(HTTPException):
        authority.authenticate(
            _command(),
            session_cookie=cookie + "x" if cookie_change else cookie,
            csrf_token="wrong" if csrf_change else csrf,
            now=NOW,
        )
    assert count(store) == 0


def test_empty_wrong_scope_and_changed_head_are_not_another_original_request(case):
    store, scope, _, _, _ = case
    assert read(store, scope) is None
    first = preparation(case)
    receipt = append(store, first)
    assert read(store, replace(scope, account_binding_sha256="3" * 64)) is None
    second = preparation(case, command=replace(_command(), command_id="stale-second"))
    with pytest.raises(RuntimeOwnerCommandError):
        append(store, second)
    assert append(store, first) == receipt and count(store) == 1


@pytest.mark.parametrize("kind", ["prepared", "resolved", "snapshot"])
def test_owned_original_graph_mutation_or_clone_is_rejected(case, kind):
    store, scope, _, _, _ = case
    prepared = preparation(case)
    append(store, prepared)
    if kind == "prepared":
        with pytest.raises(RuntimeOwnerCommandError):
            store.require_prepared(replace(prepared))
        object.__setattr__(prepared.record.authentication, "owner_id", "altered")
        with pytest.raises(RuntimeOwnerCommandError):
            store.require_prepared(prepared)
    elif kind == "resolved":
        value = read(store, scope)
        with pytest.raises(RuntimeOwnerCommandError):
            store.require_resolved(replace(value))
        object.__setattr__(value.record.dependencies.object_ref, "byte_count", 101)
        with pytest.raises(RuntimeOwnerCommandError):
            store.require_resolved(value)
    else:
        with _repeatable_read_transaction(store.engine) as connection:
            snapshot = store.capture_in_transaction(
                connection, scope, command_id=_command().command_id, budget=RuntimeReadBudget()
            )
        object.__setattr__(snapshot, "scope", replace(scope))
        with pytest.raises(RuntimeOwnerCommandError):
            store.resolve_snapshot(snapshot)


def test_all_auxiliary_rows_are_interned_and_shared_budget_charged_before_decode(case, monkeypatch):
    store, scope, _, _, _ = case
    append(store, preparation(case))
    budget = RuntimeReadBudget()
    with _repeatable_read_transaction(store.engine) as connection:
        snapshot = store.capture_in_transaction(
            connection, scope, command_id=_command().command_id, budget=budget
        )
    raw = snapshot.journal
    assert raw.head_receipt.entries[0] is raw.requested_receipt.entries[0] is raw.head_anchor
    assert raw.head_receipt.append is raw.requested_receipt.append
    assert budget.rows == 3
    assert budget.payload_bytes == len(raw.stream["key_payload"]) + len(raw.head_anchor["payload"])

    def forbidden(*args, **kwargs):
        raise AssertionError("decoder before aggregate bound")

    monkeypatch.setattr(codec, "decode_record", forbidden)
    with (
        _repeatable_read_transaction(store.engine) as connection,
        pytest.raises(RuntimeOwnerCommandError),
    ):
        store.capture_in_transaction(
            connection,
            scope,
            command_id=_command().command_id,
            budget=RuntimeReadBudget(payload_bytes=MAX_TOTAL_BYTES),
        )


def test_corrupt_auxiliary_large_sql_is_bounded_before_decode(case, monkeypatch):
    store, scope, _, _, _ = case
    prepared = preparation(case)
    first = append(store, prepared)
    raw = codec.encode_record(prepared.record)
    auxiliary = store.journal.prepare_append(
        journal_key(scope),
        JournalAppend(
            "auxiliary-request",
            "f" * 64,
            first.committed_head,
            tuple(JournalRecord(f"aux-{i}", OWNER_COMMAND_SCHEMA, raw) for i in range(64)),
        ),
    )
    with store.engine.begin() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        store.journal.append_in_transaction(connection, auxiliary)
    with store.engine.begin() as connection:
        connection.execute(
            sa.update(journal_entries)
            .where(journal_entries.c.command_id == "auxiliary-request")
            .values(payload=b"x" * (256 * 1024))
        )
    monkeypatch.setattr(codec, "decode_record", lambda *args: pytest.fail("decode before byte cap"))
    with (
        _repeatable_read_transaction(store.engine) as connection,
        pytest.raises(RuntimeOwnerCommandError),
    ):
        store.capture_in_transaction(
            connection, scope, command_id=_command().command_id, budget=RuntimeReadBudget()
        )


@pytest.mark.parametrize(
    "column,value", [("payload", b"{}"), ("payload_sha256", "9" * 64), ("record_id", "altered")]
)
def test_sql_original_tamper_rejects_detached_restore_and_final_recheck(case, column, value):
    store, scope, _, _, _ = case
    append(store, preparation(case))
    original = read(store, scope)
    with store.engine.begin() as connection:
        connection.execute(sa.update(journal_entries).values({column: value}))
    with pytest.raises(RuntimeOwnerCommandError):
        read(store, scope)
    with (
        _repeatable_read_transaction(store.engine) as connection,
        pytest.raises(RuntimeOwnerCommandError),
    ):
        store.recheck_in_transaction(connection, original)


def test_append_outer_rollback_and_inactive_transaction_do_not_publish(case):
    store, scope, _, _, _ = case
    prepared = preparation(case)
    with store.engine.begin() as connection, pytest.raises(RuntimeOwnerCommandError):
        store.append_in_transaction(connection, prepared)
    with pytest.raises(RuntimeError), store.engine.begin() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        store.append_in_transaction(connection, prepared)
        raise RuntimeError("outer rollback")
    assert read(store, scope) is None and count(store) == 0


def test_capture_append_and_final_recheck_do_no_codec_auth_or_graph_work(case, monkeypatch):
    store, scope, authority, _, _ = case
    prepared = preparation(case)
    store.require_prepared(prepared)

    def forbidden(*args, **kwargs):
        raise AssertionError("detached owner work under SQL")

    with monkeypatch.context() as context:
        context.setattr(codec, "encode_record", forbidden)
        context.setattr(codec, "decode_record", forbidden)
        context.setattr(authority, "require_authenticated", forbidden)
        context.setattr(store, "_fingerprint", forbidden)
        with store.engine.begin() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            receipt = store.append_in_transaction(connection, prepared)
            snapshot = store.capture_in_transaction(
                connection, scope, command_id=_command().command_id, budget=RuntimeReadBudget()
            )
    resolved = store.resolve_snapshot(snapshot)
    store.require_resolved(resolved)
    with monkeypatch.context() as context:
        context.setattr(codec, "encode_record", forbidden)
        context.setattr(codec, "decode_record", forbidden)
        context.setattr(authority, "require_authenticated", forbidden)
        context.setattr(store, "_fingerprint", forbidden)
        with _repeatable_read_transaction(store.engine) as connection:
            assert store.recheck_in_transaction(connection, resolved) == receipt


def test_changed_dependency_object_cannot_replace_original_retained_request(case):
    store, scope, _, _, _ = case
    first = preparation(case)
    receipt = append(store, first)
    # The issuer does not resolve the opaque object. An alternative ref can be
    # prepared, but it cannot replace the original request's immutable record.
    changed = replace(
        first.record.dependencies,
        object_ref=replace(first.record.dependencies.object_ref, object_sha256="2" * 64),
    )
    another = store.prepare(
        scope,
        command=first.record.command,
        authenticated=first.authenticated,
        dependencies=changed,
        expected_head=receipt.previous_head,
    )
    with pytest.raises(RuntimeOwnerCommandError):
        append(store, another)
    assert read(store, scope).record == first.record and count(store) == 1


def test_owned_prepared_and_read_tracking_does_not_retain_dead_values(case):
    import gc
    import weakref

    store, scope, _, _, _ = case
    prepared = preparation(case)
    append(store, prepared)
    resolved = read(store, scope)
    ids = (id(prepared), id(resolved))
    refs = (weakref.ref(prepared), weakref.ref(resolved))
    del prepared, resolved
    gc.collect()
    assert all(ref() is None for ref in refs)
    assert all(key not in store._original and key not in store._fingerprints for key in ids)


def test_owned_content_changed_after_detached_check_fails_cheaply_inside_sql(case, monkeypatch):
    store, _, authority, _, _ = case
    prepared = preparation(case)
    store.require_prepared(prepared)
    object.__setattr__(prepared.record.command, "owner_id", "mutated-after-preparation")
    monkeypatch.setattr(store, "_fingerprint", lambda *args: pytest.fail("SQL graph hash"))
    monkeypatch.setattr(authority, "require_authenticated", lambda *args: pytest.fail("SQL auth"))
    with (
        store.engine.begin() as connection,
        pytest.raises(RuntimeOwnerCommandError, match="FIELDS_CHANGED"),
    ):
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        store.append_in_transaction(connection, prepared)
    assert count(store) == 0
