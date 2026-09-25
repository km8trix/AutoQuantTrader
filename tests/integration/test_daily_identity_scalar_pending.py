"""Compare identity results on the original PENDING publication and C/B restore."""

from packages.persistence.daily_runtime_risk import (
    ResolvedDailyRuntimeSnapshot,
    RetainedDailyAttemptGroup,
    SqlDailyRuntimeRisk,
)
from tests.integration import test_continuous_attempt_publication as publication_fixture
from tests.unit.test_daily_identity_scalar_compatibility import legacy_fields

attempt_case = publication_fixture.attempt_case


def test_pending_original_identity_sequences_remain_exact(attempt_case, monkeypatch):
    original = SqlDailyRuntimeRisk._assignment_identity_fields
    observed = set()

    def compare(value):
        expected = legacy_fields(value)
        actual = original(value)
        assert len(actual) == len(expected)
        assert all(a is b for a, b in zip(expected, actual, strict=True))
        observed.add(type(value))
        return actual

    monkeypatch.setattr(SqlDailyRuntimeRisk, "_assignment_identity_fields", staticmethod(compare))
    publication_fixture.test_pending_atomic_publication_restores_original_hold_capacity_and_inert_retry(
        attempt_case
    )
    assert ResolvedDailyRuntimeSnapshot in observed
    assert RetainedDailyAttemptGroup in observed
