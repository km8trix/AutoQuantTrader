"""Inspect original admission records after ordinary restoration, without effects."""

from dataclasses import replace

import pytest

from tests.integration.test_continuous_runtime_attempt_sources import attempt_case  # noqa: F401


def test_restored_snapshot_inspection_returns_exact_owned_admission(attempt_case):  # noqa: F811
    case, _service, _reader, previous, current, original = attempt_case
    store = case.h.store
    views = store.inspect_snapshot_admissions(current)
    assert views == (original,)
    for view in views:
        store.require_admission_view(view)
    assert case.h.resolved().obligations == current.obligations
    assert case.store.restore(case.scope).receipt == previous.receipt
    restored = store.resolve_snapshot(
        store.read_snapshot(account_id=case.scope.account_id, fence=case.h.lease.fence)
    )
    assert store.inspect_snapshot_admissions(restored) == views
    assert views[0].admission.expires_at == original.admission.expires_at
    with pytest.raises(ValueError, match="original"):
        store.inspect_snapshot_admissions(replace(restored))
    before = restored.admissions
    try:
        object.__setattr__(restored, "admissions", ())
        with pytest.raises(ValueError, match=r"changed|differs"):
            store.inspect_snapshot_admissions(restored)
    finally:
        object.__setattr__(restored, "admissions", before)
