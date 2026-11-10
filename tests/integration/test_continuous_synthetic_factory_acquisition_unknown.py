"""A committed lease not returned to its constructor remains unknown.

Each fixture is new, private and disposable. The acquisition fault forwards the
original coordinator once, then raises before the constructor receives its lease.
The test's retained observation is never supplied back as cleanup authority.
"""

from types import SimpleNamespace

import pytest
from sqlalchemy import Engine

from apps.trader import continuous_simulation_factory as factory_module
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    account_lease_from_row,
    account_lease_release_from_row,
)
from tests.integration import test_continuous_synthetic_offline_configuration as study_module
from tests.integration.test_continuous_synthetic_factory_partial_cleanup import _snapshot


def _observe(monkeypatch, *, mode, primary, cleanup_error):
    original_check = factory_module.ContinuousSimulationFactory._check_stop
    original_acquire = SqlAccountCoordinator.acquire
    original_release = SqlAccountCoordinator.release
    original_dispose = Engine.dispose
    case = SimpleNamespace(
        factory=None,
        checks=0,
        acquire_calls=[],
        returned_lease=None,
        received_lease=None,
        engine=None,
        release_calls=[],
        release_results=[],
        disposal_attempts=0,
        disposal_completed=0,
        events=[],
        outcome=None,
    )

    def check(factory):
        if case.factory is None:
            case.factory = factory
        assert case.factory is factory
        if factory.lease is not None:
            case.received_lease = factory.lease
        return original_check(factory)

    def stop_requested():
        case.checks += 1
        if (mode == "before" and case.checks == 1) or (mode == "returned" and case.checks == 2):
            raise primary
        return False

    def acquire(coordinator, owner_id):
        assert coordinator is case.factory.coordinator
        assert case.acquire_calls == [], "this constructor must not retry acquisition"
        case.acquire_calls.append(owner_id)
        case.engine = case.factory.engine
        assert case.engine is coordinator._authority._engine
        # Original real SQL acquisition, including COMMIT, completes exactly once.
        # Only the fault observer receives this object on the unknown path.
        actual = original_acquire(coordinator, owner_id)
        case.returned_lease = actual
        case.events.append("acquire-returned-to-observer")
        if mode == "unknown":
            assert case.factory.lease is None
            raise primary
        return actual

    def release(coordinator, fence):
        assert coordinator is case.factory.coordinator
        case.release_calls.append(fence)
        case.events.append("release")
        result = original_release(coordinator, fence)
        case.release_results.append(result)
        return result

    def dispose(engine, *args, **kwargs):
        if engine is not case.engine:
            return original_dispose(engine, *args, **kwargs)
        case.disposal_attempts += 1
        case.events.append("dispose-account")
        result = original_dispose(engine, *args, **kwargs)
        case.disposal_completed += 1
        if cleanup_error is not None:
            # This exception reports failure after actual disposal; it does not
            # suppress original cleanup or fabricate a returned lease/release.
            raise cleanup_error
        return result

    monkeypatch.setattr(factory_module.ContinuousSimulationFactory, "_check_stop", check)
    monkeypatch.setattr(SqlAccountCoordinator, "acquire", acquire)
    monkeypatch.setattr(SqlAccountCoordinator, "release", release)
    monkeypatch.setattr(Engine, "dispose", dispose)
    case.stop_requested = stop_requested
    return case


def _require_original_lifecycle(case, before, after, configuration, *, mode):
    assert after.financial == before.financial
    assert len(before.heads) == len(after.heads) == 1
    assert before.heads[0]["current_lease_sha256"] is None
    assert before.heads[0]["current_fencing_generation"] is None
    assert case.factory.venue_engine is None
    if mode == "before":
        assert case.checks == 1 and case.acquire_calls == []
        assert case.returned_lease is None and case.received_lease is None
        assert case.release_calls == [] and case.release_results == []
        assert case.disposal_attempts == case.disposal_completed == 0
        assert case.events == []
        assert after.leases == before.leases
        assert after.releases == before.releases and after.heads == before.heads
        return
    assert len(case.acquire_calls) == 1
    assert case.disposal_attempts == case.disposal_completed == 1
    assert len(after.leases) == len(before.leases) + 1
    assert all(row in after.leases for row in before.leases)
    added = [row for row in after.leases if row not in before.leases]
    assert len(added) == 1
    actual = account_lease_from_row(added[0])
    assert actual == case.returned_lease
    assert actual.owner_id == case.acquire_calls[0]
    assert actual.owner_id.startswith("offline-owner-")
    assert actual.revision_number == 1 and actual.previous_lease_sha256 is None
    assert actual.fencing_generation == before.heads[0]["last_fencing_generation"] + 1
    assert actual.policy_sha256 == configuration.lease_policy().semantic_sha256
    assert actual.expires_at - actual.acquired_at == configuration.lease_policy().lease_ttl
    if mode == "unknown":
        assert case.checks == 1 and case.received_lease is None
        assert case.factory.lease is None
        assert case.release_calls == [] and case.release_results == []
        assert after.releases == before.releases
        assert after.heads[0] == {
            "account_id": actual.account_id,
            "last_fencing_generation": actual.fencing_generation,
            "current_fencing_generation": actual.fencing_generation,
            "current_lease_sha256": actual.semantic_sha256,
            "updated_at": added[0]["acquired_at"],
        }
        assert case.events == ["acquire-returned-to-observer", "dispose-account"]
        return
    assert mode == "returned" and case.checks == 2
    assert case.received_lease is case.returned_lease
    assert case.release_calls == [actual.fence] and len(case.release_results) == 1
    assert len(after.releases) == len(before.releases) + 1
    assert all(row in after.releases for row in before.releases)
    added_releases = [row for row in after.releases if row not in before.releases]
    assert len(added_releases) == 1
    released = account_lease_release_from_row(added_releases[0])
    assert released == case.release_results[0]
    assert released.lease_sha256 == actual.semantic_sha256 and released.fence == actual.fence
    assert actual.acquired_at <= released.released_at < actual.expires_at
    assert after.heads[0] == {
        "account_id": actual.account_id,
        "last_fencing_generation": actual.fencing_generation,
        "current_fencing_generation": None,
        "current_lease_sha256": None,
        "updated_at": added_releases[0]["released_at"],
    }
    assert case.events == ["acquire-returned-to-observer", "release", "dispose-account"]


def _exercise(tmp_path, monkeypatch, request, *, mode, primary_type, fail_cleanup=False):
    with study_module._study(tmp_path) as study:
        configuration = study_module._export(study)
        assert (
            configuration.lease_ttl_microseconds,
            configuration.maximum_in_flight_microseconds,
            configuration.takeover_safety_microseconds,
        ) == (60_000_000, 5_000_000, 10_000_000)
        study_module._release_setup(study)
        assert study.lease is None  # The fixture cannot later release the unknown new head.
        before = _snapshot(study)
        study.ports["account_engine"].dispose()
        study.ports["venue_engine"].dispose()
        primary = primary_type("private acquisition interruption")
        cleanup_error = RuntimeError("private post-disposal failure") if fail_cleanup else None
        case = _observe(monkeypatch, mode=mode, primary=primary, cleanup_error=cleanup_error)
        try:
            factory_module.ContinuousSimulationFactory(
                configuration,
                account_id=study.genesis.scope.account_id,
                stop_requested=case.stop_requested,
            )
        except BaseException as error:
            case.outcome = error
        try:
            after = _snapshot(study)
            # Inspect retained facts independently before asserting diagnostic
            # classification. Nothing reconciles, releases or retries this head.
            _require_original_lifecycle(case, before, after, configuration, mode=mode)
            assert case.outcome is not None
            if mode == "unknown":
                request.node.user_properties.append(("unknown_acquisition_retained", "true"))
                assert isinstance(case.outcome, BaseExceptionGroup)
                assert case.outcome.message == (
                    "offline factory lease acquisition completion unknown"
                )
                expected = (primary,) if cleanup_error is None else (primary, cleanup_error)
                assert case.outcome.exceptions == expected
            else:
                assert type(case.outcome) is factory_module.ContinuousSimulationFactoryError
                assert case.outcome.args == ("OFFLINE_FACTORY_INITIALIZATION_FAILED",)
        except BaseException as oracle:
            if case.outcome is not None:
                raise BaseExceptionGroup(
                    "observed acquisition outcome and independent oracle failed",
                    [case.outcome, oracle],
                ) from None
            raise
        # Deliberately no rescue: the fixture's namespace can end with the real
        # retained head. The observed lease is not returned to any production port.


@pytest.mark.parametrize("primary_type", [ValueError, KeyboardInterrupt], ids=["ordinary", "base"])
@pytest.mark.parametrize("fail_cleanup", [False, True], ids=["disposed", "dispose-error"])
def test_committed_acquisition_without_return_remains_explicitly_unknown(
    tmp_path, monkeypatch, request, primary_type, fail_cleanup
):
    _exercise(
        tmp_path,
        monkeypatch,
        request,
        mode="unknown",
        primary_type=primary_type,
        fail_cleanup=fail_cleanup,
    )


@pytest.mark.parametrize("mode", ["before", "returned"], ids=["pre-acquire", "returned-lease"])
def test_known_constructor_boundaries_keep_original_failure_and_cleanup_semantics(
    tmp_path, monkeypatch, request, mode
):
    _exercise(tmp_path, monkeypatch, request, mode=mode, primary_type=ValueError)
