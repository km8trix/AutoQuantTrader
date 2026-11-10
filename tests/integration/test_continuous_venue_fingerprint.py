"""Actual retained modeled-venue ownership; no provider or C12 qualification."""

from dataclasses import replace
from datetime import timedelta

import pytest

from packages.application import personal_codec
from packages.persistence import continuous_venue_sources as source_module
from packages.persistence.continuous_venue_sources import (
    ContinuousVenueSourceError,
    SqlContinuousVenueSources,
)
from packages.persistence.database import _repeatable_read_transaction
from tests.integration.test_continuous_venue_sources import case  # noqa: F401
from tests.integration.test_stateful_venue_journal import retained  # noqa: F401
from tests.integration.test_venue_reconciliation_capture import capture_store  # noqa: F401
from tests.unit.test_venue_resolved_fingerprint import assert_legacy_equivalent


def test_original_retained_venue_fingerprint_and_sql_boundary(case, monkeypatch):  # noqa: F811
    captures, venue, capture, sources = case
    value = sources.resolve(capture)
    sources.require_resolved(value)
    original = assert_legacy_equivalent(value, monkeypatch)[0]
    other = SqlContinuousVenueSources(
        captures.engine,
        artifacts=captures.artifacts,
        codec=personal_codec,
        resolver=sources.resolver,
        scope=sources.scope,
        model=sources.model,
    )
    for owner, supplied in ((sources, replace(value)), (other, value)):
        with pytest.raises(ContinuousVenueSourceError, match="OWNED"):
            owner.require_resolved(supplied)
    for record, field, replacement in (
        (capture, "source_order", tuple(reversed(capture.source_order))),
        (value.pages[0], "received_at", value.pages[0].received_at + timedelta(microseconds=1)),
    ):
        retained_value = getattr(record, field)
        assert retained_value != replacement
        object.__setattr__(record, field, replacement)
        try:
            assert assert_legacy_equivalent(value, monkeypatch)[0] != original
            with pytest.raises(ContinuousVenueSourceError, match="FINGERPRINT"):
                sources.require_resolved(value)
        finally:
            object.__setattr__(record, field, retained_value)
        sources.require_resolved(value)
    original_read = value.reads[0]
    snapshot = original_read.snapshot
    assert snapshot.requested_receipt is not None
    original_entries = snapshot.requested_receipt.entries
    assert original_entries
    changed_entry = dict(original_entries[0])
    assert type(changed_entry["payload"]) is bytes
    changed_entry["payload"] += b"changed-original-journal"
    object.__setattr__(
        snapshot.requested_receipt, "entries", (changed_entry, *original_entries[1:])
    )
    try:
        assert assert_legacy_equivalent(value, monkeypatch)[0] != original
        with pytest.raises(ContinuousVenueSourceError, match="FINGERPRINT"):
            sources.require_resolved(value)
    finally:
        object.__setattr__(snapshot.requested_receipt, "entries", original_entries)
    sources.require_resolved(value)
    assert assert_legacy_equivalent(value, monkeypatch)[0] == original

    def forbidden(*args, **kwargs):
        pytest.fail("heavy work or independent venue query during final SQL readback")

    monkeypatch.setattr(personal_codec, "encode_record", forbidden)
    monkeypatch.setattr(personal_codec, "decode_record", forbidden)
    monkeypatch.setattr(captures.artifacts, "read", forbidden)
    monkeypatch.setattr(source_module, "_fingerprint", forbidden)
    monkeypatch.setattr(sources.resolver, "resolve_observation", forbidden)
    monkeypatch.setattr(venue, "read", forbidden)
    monkeypatch.setattr(venue, "facts", forbidden)
    with _repeatable_read_transaction(captures.engine) as connection:
        sources.recheck_in_transaction(connection, value)
