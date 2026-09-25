"""Literal old-byte oracle around original C metadata fixture operations.

These tests delegate the existing genesis, predecessor/restart and shared-row
assertions. The fixture has actual C/journal/lease SQL owners and a zero-admission
RetainedMetadataComposer; it does not qualify the production session or providers.
"""

from collections import Counter

import pytest
import sqlalchemy as sa

from packages.domain import personal_contracts
from packages.domain.canonical import canonical_json_bytes
from packages.persistence import continuous_account as account
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.detached_journal_capture import detached_journal_value
from tests.integration import test_continuous_publication_reference as original

h = original.h


@pytest.mark.parametrize("scenario", ["genesis", "parent-restart", "shared-rows"])
def test_original_creation_require_and_final_sql_keep_legacy_bytes(h, monkeypatch, scenario):
    helper = account._reference_fingerprint
    resolve = account.SqlContinuousAccount.resolve_reference
    require = account.SqlContinuousAccount.require_reference
    recheck = account.SqlContinuousAccount.recheck_reference_in_transaction
    active = set()
    phases = []
    counts = Counter()
    retained = []

    def begin(connection):
        active.add(connection)

    def end(connection):
        active.discard(connection)

    def observed_helper(snapshot, journal, prior):
        assert not active, "full reference fingerprint ran inside SQL"
        assert phases and phases[-1] in {"creation", "require"}
        counts[phases[-1]] += 1
        encoded = []

        def encode(value):
            result = canonical_json_bytes(value)
            encoded.append(result)
            return result

        # Complete old expression is independently evaluated on original views.
        with monkeypatch.context() as oracle:
            oracle.setattr(personal_contracts, "canonical_json_bytes", encode)
            oracle.setattr(account, "canonical_json_bytes", encode)
            old = personal_contracts.content_digest(
                detached_journal_value((snapshot, journal, prior))
            )
            new = helper(snapshot, journal, prior)
        assert len(encoded) == 2 and encoded[0] == encoded[1]
        assert old == new
        return new

    def observed_resolve(owner, snapshot):
        phases.append("creation")
        try:
            result = resolve(owner, snapshot)
        finally:
            assert phases.pop() == "creation"
        assert len(retained) < 32
        retained.append((owner, result))
        return result

    def observed_require(owner, value):
        phases.append("require")
        try:
            return require(owner, value)
        finally:
            assert phases.pop() == "require"

    def observed_recheck(owner, connection, value):
        assert connection in active
        result = recheck(owner, connection, value)
        counts["final-sql"] += 1
        return result

    for event, listener in (("begin", begin), ("commit", end), ("rollback", end)):
        sa.event.listen(h.engine, event, listener)
    try:
        monkeypatch.setattr(account, "_reference_fingerprint", observed_helper)
        monkeypatch.setattr(account.SqlContinuousAccount, "resolve_reference", observed_resolve)
        monkeypatch.setattr(account.SqlContinuousAccount, "require_reference", observed_require)
        monkeypatch.setattr(
            account.SqlContinuousAccount, "recheck_reference_in_transaction", observed_recheck
        )
        with monkeypatch.context() as original_patches:
            if scenario == "genesis":
                original.test_original_reference_validates_genesis_without_composer_or_checkpoint_read(
                    h, original_patches
                )
            elif scenario == "parent-restart":
                original.test_parent_reference_retains_original_source_lease_across_heartbeat_and_later_commit(
                    h
                )
            else:
                original.test_shared_journal_pool_interns_original_reference_rows_before_ownership(
                    h
                )
        assert retained and counts["creation"] > 0
        owner, value = retained[-1]
        # The original parent case did not call require; the shared-row case did
        # not recheck SQL. Exercise both actual APIs on that same issued value.
        owner.require_reference(value)
        with _repeatable_read_transaction(h.engine) as connection:
            owner.recheck_reference_in_transaction(connection, value)
        assert counts["require"] > 0 and counts["final-sql"] > 0
        assert not active and not phases
    finally:
        for event, listener in (("begin", begin), ("commit", end), ("rollback", end)):
            sa.event.remove(h.engine, event, listener)


@pytest.mark.parametrize("error_type", [ValueError, TypeError, KeyError, UnicodeError])
def test_actual_creation_wraps_but_require_preserves_original_fingerprint_error(
    h, monkeypatch, error_type
):
    raw = original.capture(h)
    value = h.store.resolve_reference(raw)
    error = error_type("original-fingerprint-failure")
    calls = []

    def fail(snapshot, journal, prior):
        calls.append(snapshot)
        raise error

    monkeypatch.setattr(account, "_reference_fingerprint", fail)
    with pytest.raises(
        account.ContinuousAccountConflict, match=r"^CONTINUOUS_RETAINED_REFERENCE_INVALID$"
    ) as created:
        h.store.resolve_reference(raw)
    assert created.value.__cause__ is None and created.value.__suppress_context__
    assert created.value.__context__ is error
    assert calls == [raw]
    with pytest.raises(error_type) as required:
        h.store.require_reference(value)
    assert required.value is error and calls == [raw, raw]


def test_nested_journal_change_reaches_actual_content_fingerprint_guard(h, monkeypatch):
    from dataclasses import replace

    value = h.store.resolve_reference(original.capture(h))
    helper = account._reference_fingerprint
    calls = []

    def observed(snapshot, journal, prior):
        calls.append(snapshot)
        return helper(snapshot, journal, prior)

    monkeypatch.setattr(account, "_reference_fingerprint", observed)
    object.__setattr__(value.journal, "head", replace(value.journal.head, sequence=0))
    with pytest.raises(
        account.ContinuousAccountConflict, match=r"^CONTINUOUS_REFERENCE_CONTENT_CHANGED$"
    ):
        h.store.require_reference(value)
    assert calls == [value.snapshot]
