"""Actual retained PENDING and observed venue-source inputs, with modeled fixtures.

These comparisons neither qualify active delivery nor replace full original
source/financial/final SQL checks. Observed coverage uses the actual cash/source
publication and complete venue captures, not a claim of partial-fill authority.
"""

from dataclasses import replace
from types import MappingProxyType

import pytest

from packages.application import personal_codec as codec
from packages.persistence.continuous_capture_comparison import ContinuousCaptureComparison
from packages.persistence.continuous_observed_hold_sources import ContinuousObservedHoldSourceError
from packages.persistence.continuous_runtime_attempt_sources import (
    ContinuousRuntimeAttemptSourceError,
)
from tests.integration.test_continuous_observed_hold_sources import (
    capture,
    publish,
    resolver,
    retain,
)
from tests.integration.test_continuous_observed_hold_sources import (
    case as case,
)
from tests.integration.test_continuous_runtime_attempt_sources import (
    attempt_case as attempt_case,
)
from tests.integration.test_continuous_runtime_attempt_sources import (
    publish_original_pending,
)


def _changed_anchor(raw):
    journal = raw.state.references[0].journal
    original = journal.head_anchor
    assert original is not None and "entry_sha256" in original
    changed = dict(original)
    changed["entry_sha256"] = "9" * 64
    assert changed != dict(original)
    return journal, original, MappingProxyType(changed)


def test_actual_pending_complete_capture_compares_private_source_rows_without_replay(
    attempt_case, monkeypatch
):
    base, _service, reader, *_ = attempt_case
    published, _prepared, receipt = publish_original_pending(attempt_case)
    original = base.h.resolved()
    fresh = base.h.store.read_snapshot(account_id=base.scope.account_id, fence=base.h.lease.fence)
    assert original.attempt_sources is not None and fresh.attempt_sources is not None
    assert original.attempts and original.attempt_envelopes
    assert original.attempt_sources.sources == (published.source,)
    assert fresh.attempt_sources.state.historical == (True,)
    assert receipt.commit.sequence == published.source.coordinator_sequence
    base.h.store.require_same_complete_capture(original, fresh)

    def forbidden(*args, **kwargs):
        pytest.fail("capture equality must not replay, fingerprint, decode or read artifacts")

    with monkeypatch.context() as guard:
        guard.setattr(base.h.store, "resolve_snapshot", forbidden)
        guard.setattr(reader, "resolve_attempt_sources", forbidden)
        guard.setattr(reader, "_fingerprint", forbidden)
        guard.setattr(base.store, "resolve_reference", forbidden)
        guard.setattr(base.artifacts, "read", forbidden)
        guard.setattr(codec, "encode_record", forbidden)
        guard.setattr(codec, "decode_record", forbidden)
        assert base.h.store.require_same_complete_capture(original, fresh) is None

    captured = fresh.attempt_sources
    with pytest.raises(ContinuousRuntimeAttemptSourceError, match="OWNED_ORIGINAL"):
        reader.require_same_capture(
            original.attempt_sources, replace(captured), comparison=ContinuousCaptureComparison()
        )
    journal, old, changed = _changed_anchor(captured)
    public_tables = captured.tables
    object.__setattr__(journal, "head_anchor", changed)
    try:
        assert captured.tables is public_tables
        with pytest.raises(ValueError, match=r"CAPTURE|capture|CHANGED"):
            base.h.store.require_same_complete_capture(original, fresh)
    finally:
        object.__setattr__(journal, "head_anchor", old)
    original_mode = captured.state.historical
    object.__setattr__(captured.state, "historical", (False,))
    try:
        with pytest.raises(ContinuousRuntimeAttemptSourceError, match="OWNED_ORIGINAL"):
            base.h.store.require_same_complete_capture(original, fresh)
    finally:
        object.__setattr__(captured.state, "historical", original_mode)
    base.h.store.require_same_complete_capture(original, fresh)
    base.h.store.require_resolved_snapshot(original)
    reader.require_resolved(original.attempt_sources)


def test_actual_observed_capture_compares_complete_opaque_venue_history(case, monkeypatch):
    reader = resolver(case)
    token = retain(case, reader)
    receipt = publish(case, token)
    old_plan = reader.prepare_observed_hold_source_read((token.reference,))
    old_raw = capture(case, reader, old_plan)
    original = reader.resolve_observed_hold_sources(old_raw, admissions=())
    new_plan = reader.prepare_observed_hold_source_read((token.reference,))
    fresh = capture(case, reader, new_plan)
    assert original.inputs and original.inputs == (token.inputs,)
    assert fresh.state.historical == (True,)
    assert receipt.commit.sequence == token.inputs.source.coordinator_sequence
    assert fresh.state.venue_journals and fresh.state.venue_journals[0]
    reader.require_same_capture(original, fresh, comparison=ContinuousCaptureComparison())

    def forbidden(*args, **kwargs):
        pytest.fail("observed capture equality must not replay, fingerprint or load objects")

    with monkeypatch.context() as guard:
        guard.setattr(reader, "resolve_observed_hold_sources", forbidden)
        guard.setattr(reader, "_fingerprint", forbidden)
        guard.setattr(case.account, "resolve_reference", forbidden)
        guard.setattr(case.sources, "require_resolved", forbidden)
        guard.setattr(case.base.artifacts, "read", forbidden)
        guard.setattr(codec, "encode_record", forbidden)
        guard.setattr(codec, "decode_record", forbidden)
        reader.require_same_capture(original, fresh, comparison=ContinuousCaptureComparison())

    with pytest.raises(ContinuousObservedHoldSourceError, match="OWNED_ORIGINAL"):
        reader.require_same_capture(
            original, replace(fresh), comparison=ContinuousCaptureComparison()
        )
    journal, old, changed = _changed_anchor(fresh)
    public_tables = fresh.tables
    object.__setattr__(journal, "head_anchor", changed)
    try:
        assert fresh.tables is public_tables
        with pytest.raises(ValueError, match=r"CAPTURE|capture|CHANGED"):
            reader.require_same_capture(original, fresh, comparison=ContinuousCaptureComparison())
    finally:
        object.__setattr__(journal, "head_anchor", old)
    original_mode = fresh.state.historical
    object.__setattr__(fresh.state, "historical", (False,))
    try:
        with pytest.raises(ContinuousObservedHoldSourceError, match="OWNED_ORIGINAL"):
            reader.require_same_capture(original, fresh, comparison=ContinuousCaptureComparison())
    finally:
        object.__setattr__(fresh.state, "historical", original_mode)
    reader.require_same_capture(original, fresh, comparison=ContinuousCaptureComparison())
    reader.require_resolved(original)
