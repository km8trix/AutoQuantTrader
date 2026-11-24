"""Actual PENDING source ownership over explicit modeled controls/source/time.

The reused fixture has synthetic assignment/control setup. This qualifies the
original pending source graph, not signed startup, activation, delivery, outcome
history, whole-account restoration or an active worker.
"""

from dataclasses import replace
from datetime import timedelta

import pytest

from packages.application import personal_codec as codec
from packages.persistence import continuous_runtime_attempt_sources as attempt_sources
from packages.persistence.continuous_runtime_attempt_sources import (
    ContinuousRuntimeAttemptSourceError,
)
from packages.persistence.daily_runtime_risk import RuntimeReadBudget
from tests.integration.test_continuous_runtime_attempt_sources import (
    attempt_case as attempt_case,
)
from tests.integration.test_continuous_runtime_attempt_sources import pending
from tests.unit.test_attempt_resolved_fingerprint import assert_legacy_equivalent


def test_actual_pending_fingerprint_bytes_and_original_guards(attempt_case, monkeypatch):
    case, _service, reader, _previous, _current, view = attempt_case
    prepared = pending(attempt_case)
    reader.require_prepared(prepared)
    plan = reader.prepare_attempt_source_read((prepared.reference,))
    with case.store.write_transaction() as connection:
        raw = reader.capture_attempt_sources_in_transaction(
            connection, plan, account_id=case.scope.account_id, budget=RuntimeReadBudget()
        )
    resolved = reader.resolve_attempt_sources(raw, admissions=(view,))
    reader.require_resolved(resolved)
    result = assert_legacy_equivalent(resolved, monkeypatch)
    assert result[0] == ("return", reader._fingerprints[id(resolved)])
    assert resolved.sources == (prepared.source,)

    with pytest.raises(ContinuousRuntimeAttemptSourceError, match="OWNED_ORIGINAL"):
        reader.require_resolved(replace(resolved))

    # Equal row copies still violate the original nested snapshot identity.
    snapshot = next(value for value, _ in resolved.state.selected if value.rows)
    original_rows = snapshot.rows
    object.__setattr__(snapshot, "rows", tuple(dict(row) for row in original_rows))
    try:
        with pytest.raises(ContinuousRuntimeAttemptSourceError, match="OWNED_ORIGINAL"):
            reader.require_resolved(resolved)
    finally:
        object.__setattr__(snapshot, "rows", original_rows)

    item = plan.state.sources[0]
    original_payloads = item.admission_payloads
    assert original_payloads
    object.__setattr__(item, "admission_payloads", (b"changed-original-payload",))
    try:
        with pytest.raises(ContinuousRuntimeAttemptSourceError, match="OWNED_ORIGINAL"):
            reader.require_resolved(resolved)
    finally:
        object.__setattr__(item, "admission_payloads", original_payloads)

    source = item.source
    original_expiry = source.valid_until
    object.__setattr__(source, "valid_until", original_expiry + timedelta(microseconds=1))
    try:
        with pytest.raises(ContinuousRuntimeAttemptSourceError, match="OWNED_ORIGINAL"):
            reader.require_resolved(resolved)
        with (
            case.store.write_transaction() as connection,
            pytest.raises(ContinuousRuntimeAttemptSourceError, match="OWNED_ORIGINAL"),
        ):
            reader.recheck_attempt_sources_in_transaction(connection, resolved)
    finally:
        object.__setattr__(source, "valid_until", original_expiry)

    assert assert_legacy_equivalent(resolved, monkeypatch)[0] == result[0]
    reader.require_resolved(resolved)
    with monkeypatch.context() as guard:

        def fail(*args, **kwargs):
            pytest.fail("full fingerprint, codec, artifact or restore call inside final SQL")

        guard.setattr(codec, "encode_record", fail)
        guard.setattr(codec, "decode_record", fail)
        guard.setattr(case.artifacts, "read", fail)
        guard.setattr(case.artifacts, "put", fail)
        guard.setattr(case.store, "restore", fail)
        guard.setattr(attempt_sources, "canonical_json_bytes", fail)
        guard.setattr(reader, "_fingerprint", fail)
        with case.store.write_transaction() as connection:
            reader.recheck_attempt_sources_in_transaction(connection, resolved)
