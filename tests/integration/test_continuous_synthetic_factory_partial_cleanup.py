"""Fresh constructor interruption cleanup, without replaying retained histories.

The public stop callback raises at original constructor checkpoints. Observers
forward original methods; only the cleanup-failure cases raise once after the
original venue disposal has returned. No financial validator is replaced.
"""

from contextlib import contextmanager
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.pool import NullPool

from apps.trader import continuous_simulation_factory as factory_module
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    account_lease_from_row,
    account_lease_release_from_row,
)
from packages.persistence.schema import (
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
)
from tests.integration import test_continuous_synthetic_offline_configuration as study_module
from tests.integration.test_continuous_synthetic_full_readiness import _all_rows


def _snapshot(study):
    engines = []
    try:
        for key in ("database_path", "venue_database_path"):
            engines.append(
                sa.create_engine(
                    sa.URL.create(
                        "sqlite+pysqlite",
                        database=study.paths[key].as_uri(),
                        query={"mode": "ro", "uri": "true"},
                    ),
                    poolclass=NullPool,
                )
            )
        account, venue = engines
        lifecycle = {
            phase2_account_leases.name,
            phase2_account_lease_releases.name,
            phase2_account_lease_heads.name,
        }
        financial = (
            tuple((name, rows) for name, rows in _all_rows(account) if name not in lifecycle),
            _all_rows(venue),
            study_module._objects(study),
        )
        with account.connect() as connection:
            leases, releases, heads = (
                tuple(
                    dict(row)
                    for row in connection.execute(
                        sa.select(table).order_by(*table.primary_key.columns)
                    ).mappings()
                )
                for table in (
                    phase2_account_leases,
                    phase2_account_lease_releases,
                    phase2_account_lease_heads,
                )
            )
        return SimpleNamespace(financial=financial, leases=leases, releases=releases, heads=heads)
    finally:
        # These observation engines are independent of the constructor's pair.
        try:
            if len(engines) > 1:
                engines[1].dispose()
        finally:
            if engines:
                engines[0].dispose()


@contextmanager
def _observe(study, monkeypatch, request, *, checkpoint, primary, cleanup_error):
    original_check = factory_module.ContinuousSimulationFactory._check_stop
    original_release = SqlAccountCoordinator.release
    original_dispose = Engine.dispose
    case = SimpleNamespace(
        factory=None,
        checks=0,
        engines=[],
        lease=None,
        releases=[],
        release_results=[],
        disposal_attempts=[],
        disposal_completed=[],
        events=[],
        rescue=[],
        outcome=None,
        after=None,
    )

    def check(factory):
        if case.factory is None:
            case.factory = factory
        assert case.factory is factory
        for label in ("engine", "venue_engine"):
            engine = getattr(factory, label)
            if engine is not None and not any(engine is item[1] for item in case.engines):
                case.engines.append((label, engine))
        if factory.lease is not None:
            case.lease = factory.lease
        return original_check(factory)

    def stop_requested():
        case.checks += 1
        if case.checks == checkpoint:
            raise primary
        return False

    def release(coordinator, fence):
        if case.factory is not None and coordinator is getattr(case.factory, "coordinator", None):
            case.releases.append(fence)
            case.events.append("release")
            result = original_release(coordinator, fence)
            case.release_results.append(result)
            return result
        return original_release(coordinator, fence)

    def dispose(engine, *args, **kwargs):
        label = next((label for label, owned in case.engines if owned is engine), None)
        if label is None:
            return original_dispose(engine, *args, **kwargs)
        case.disposal_attempts.append(label)
        case.events.append(label)
        result = original_dispose(engine, *args, **kwargs)
        case.disposal_completed.append(label)
        if label == "venue_engine" and cleanup_error is not None:
            raise cleanup_error
        return result

    monkeypatch.setattr(factory_module.ContinuousSimulationFactory, "_check_stop", check)
    monkeypatch.setattr(SqlAccountCoordinator, "release", release)
    monkeypatch.setattr(Engine, "dispose", dispose)
    case.stop_requested = stop_requested
    failure = None
    try:
        yield case
    except BaseException as error:
        failure = error
        raise
    finally:
        # The first RED must not leak its NEW fixture's known-returned lease.
        # Rescue only an operation never attempted by the constructor, once.
        # Never adopt an unknown acquire result or retry failed cleanup.
        errors = []
        if case.factory is not None:
            if case.lease is None:
                case.lease = case.factory.lease
            for label in ("engine", "venue_engine"):
                engine = getattr(case.factory, label)
                if engine is not None and not any(engine is item[1] for item in case.engines):
                    case.engines.append((label, engine))
        if case.lease is not None and not case.releases:
            case.rescue.append("known_returned_lease")
            try:
                original_release(case.factory.coordinator, case.lease.fence)
            except BaseException as error:
                errors.append(error)
        for label, engine in reversed(case.engines):
            if label not in case.disposal_attempts:
                case.rescue.append(label)
                try:
                    original_dispose(engine)
                except BaseException as error:
                    errors.append(error)
        if case.rescue:
            record = ",".join(case.rescue)
            request.node.user_properties.append(("test_owned_unattempted_cleanup", record))
            if failure is not None:
                failure.add_note("Test-owned cleanup AFTER captured constructor failure: " + record)
            else:
                errors.insert(
                    0, AssertionError("passing case required test-owned cleanup: " + record)
                )
        if errors:
            if failure is not None:
                errors.insert(0, failure)
            raise BaseExceptionGroup(
                "constructor test and separately recorded cleanup failed", errors
            )


def _require_facts(case, before, configuration, *, checkpoint):
    after = case.after
    assert after.financial == before.financial
    assert len(before.heads) == len(after.heads) == 1
    assert before.heads[0]["current_lease_sha256"] is None
    assert after.heads[0]["current_lease_sha256"] is None
    assert after.heads[0]["current_fencing_generation"] is None
    assert case.checks == checkpoint
    if checkpoint == 1:
        assert after.leases == before.leases and after.releases == before.releases
        assert after.heads == before.heads
        assert case.lease is None and case.engines == [] and case.events == []
        return
    assert case.lease is not None
    assert len(after.leases) == len(before.leases) + 1
    assert len(after.releases) == len(before.releases) + 1
    assert all(row in after.leases for row in before.leases)
    assert all(row in after.releases for row in before.releases)
    added = [row for row in after.leases if row not in before.leases]
    actual = account_lease_from_row(added[0])
    assert actual == case.lease
    assert actual.revision_number == 1 and actual.previous_lease_sha256 is None
    assert actual.fencing_generation == before.heads[0]["last_fencing_generation"] + 1
    assert actual.policy_sha256 == configuration.lease_policy().semantic_sha256
    assert actual.owner_id.startswith("offline-owner-")
    assert case.releases == [actual.fence]
    assert len(case.release_results) == 1
    released = case.release_results[0]
    assert released.fence == actual.fence and released.lease_sha256 == actual.semantic_sha256
    added_releases = [row for row in after.releases if row not in before.releases]
    assert added_releases[0]["lease_sha256"] == actual.semantic_sha256
    assert account_lease_release_from_row(added_releases[0]) == released
    assert actual.acquired_at <= released.released_at < actual.expires_at
    assert after.heads[0] == {
        "account_id": actual.account_id,
        "last_fencing_generation": actual.fencing_generation,
        "current_fencing_generation": None,
        "current_lease_sha256": None,
        "updated_at": added_releases[0]["released_at"],
    }
    expected = ["engine"] if checkpoint == 2 else ["venue_engine", "engine"]
    assert case.disposal_attempts == expected
    assert case.disposal_completed == expected
    assert case.events == ["release", *expected]


def _exercise(tmp_path, monkeypatch, request, *, checkpoint, primary_type, fail_cleanup=False):
    with study_module._study(tmp_path) as study:
        configuration = study_module._export(study)
        study_module._release_setup(study)
        before = _snapshot(study)
        study.ports["account_engine"].dispose()
        study.ports["venue_engine"].dispose()
        primary = primary_type("private constructor interruption")
        cleanup_error = RuntimeError("private post-disposal failure") if fail_cleanup else None
        with _observe(
            study,
            monkeypatch,
            request,
            checkpoint=checkpoint,
            primary=primary,
            cleanup_error=cleanup_error,
        ) as case:
            try:
                factory_module.ContinuousSimulationFactory(
                    configuration,
                    account_id=study.genesis.scope.account_id,
                    stop_requested=case.stop_requested,
                )
            except BaseException as error:
                case.outcome = error
            # Capture the actual constructor outcome BEFORE any rescue. Raw SQL
            # avoids using the old modeled coordinator after actual-time loading.
            try:
                case.after = _snapshot(study)
                assert case.outcome is not None, "the public callback failure was not propagated"
                if fail_cleanup:
                    assert isinstance(case.outcome, BaseExceptionGroup)
                    assert case.outcome.message == (
                        "offline factory initialization and cleanup failed"
                    )
                    assert case.outcome.exceptions == (primary, cleanup_error)
                elif primary_type is ValueError:
                    assert type(case.outcome) is factory_module.ContinuousSimulationFactoryError
                    assert case.outcome.args == ("OFFLINE_FACTORY_INITIALIZATION_FAILED",)
                else:
                    assert case.outcome is primary
                _require_facts(case, before, configuration, checkpoint=checkpoint)
            except BaseException as oracle:
                if case.outcome is not None:
                    raise BaseExceptionGroup(
                        "observed constructor outcome and independent oracle failed",
                        [case.outcome, oracle],
                    ) from None
                raise


@pytest.mark.parametrize(
    "checkpoint", [1, 2, 3], ids=["pre-acquire", "lease-returned", "both-engines"]
)
@pytest.mark.parametrize("primary_type", [ValueError, KeyboardInterrupt], ids=["ordinary", "base"])
def test_fresh_constructor_failure_attempts_only_owned_cleanup_once(
    tmp_path, monkeypatch, request, checkpoint, primary_type
):
    _exercise(tmp_path, monkeypatch, request, checkpoint=checkpoint, primary_type=primary_type)


@pytest.mark.parametrize("primary_type", [ValueError, KeyboardInterrupt], ids=["ordinary", "base"])
def test_fresh_constructor_preserves_primary_with_one_post_disposal_cleanup_failure(
    tmp_path, monkeypatch, request, primary_type
):
    _exercise(
        tmp_path,
        monkeypatch,
        request,
        checkpoint=3,
        primary_type=primary_type,
        fail_cleanup=True,
    )


def test_interrupted_constructor_never_inspects_exception_owned_class(
    tmp_path, monkeypatch, request
):
    class UninspectableFailure(BaseException):
        @property
        def __class__(self):
            raise AssertionError("exception-owned class must not be inspected")

    _exercise(
        tmp_path,
        monkeypatch,
        request,
        checkpoint=3,
        primary_type=UninspectableFailure,
    )
