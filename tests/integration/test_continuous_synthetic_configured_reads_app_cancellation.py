"""Actual ASGI cancellation and cleanup cutoffs over fresh original L/K/G.

Only test-owned barriers hold original SQL or an already completed original
proof. The app owns one entry/exit; the inherited fixture independently checks
all financial rows, objects, R1/release/head, engines, guard and dead owner Thread.
No socket, replacement proof, owner injection or retained store is used.
"""

import threading
from types import SimpleNamespace

import anyio
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event

from apps.api.readiness_read_store import ReadinessReadStoreStatus
from tests.integration.test_continuous_synthetic_configured_reads_app import (
    BOOTSTRAP,
    SELECTION,
    UNAVAILABLE,
    _app_case,
    _authorize,
    _closed,
    _disabled,
    _request,
    _selection,
    _uncached,
)
from tests.integration.test_continuous_synthetic_readiness_http import _paused_original_proof
from tests.integration.test_continuous_synthetic_readiness_read_store import _held_query


def _fixed(error, suffix):
    assert type(error) is RuntimeError
    assert str(error) == "CONFIGURED_READINESS_READS_" + suffix


def _unavailable(response):
    _uncached(response, 503)
    assert response.json() == UNAVAILABLE


def _owner_closed(case):
    status = case.owner.status()
    assert status.phase == "stopped" and status.busy is False
    assert status.cleanup_complete is True and status.cleanup_failure is None
    assert not case.owner._thread.is_alive()
    assert (
        len(case.acquires)
        == len(case.release_attempts)
        == len(case.releases)
        == case.close_calls
        == case.guard_exits
        == 1
    )


def _read_closed(case):
    # An engine_disposed event alone is not proof that Engine.dispose returned.
    assert case.read_stores[0].status() == ReadinessReadStoreStatus("closed", False, True, None)
    assert case.read_disposals == case.read_engines
    assert all(connection.closed for connection in case.query_connections)


def test_operational_http_busy_slot_keeps_one_actual_proof_and_query(tmp_path, monkeypatch):
    with _app_case(tmp_path, monkeypatch) as case:
        with TestClient(case.app) as client:
            headers = _authorize(case, client)
            with _held_query(case) as pause:
                pause.responses = []
                caller = _request(client, headers, pause)
                assert pause.reached.wait(5), "original SQL did not reach its test barrier"
                assert case.proofs == case.query_count == len(case.read_ids) == 1
                assert case.proof_errors == [] and pause.responses == pause.errors == []
                assert case.read_stores[0].status().busy is True
                assert case.read_disposals == [] and case.exits == []
                second = client.get(SELECTION, headers=headers)
                _unavailable(second)
                assert case.proofs == case.query_count == len(case.read_ids) == 1
                assert pause.responses == pause.errors == []
                pause.release.set()
                caller.join(8)
                assert not caller.is_alive() and pause.errors == []
                assert len(pause.responses) == 1
                _selection(case, pause.responses[0])
                assert case.read_stores[0].status() == ReadinessReadStoreStatus(
                    "open", False, False, None
                )
                assert all(connection.closed for connection in case.query_connections)
            assert case.proofs == case.query_count == 1
        _closed(case)
        assert case.exits[0][1:] == (None, None)


def test_cancellation_around_actual_entry_delivery_closes_once_without_opening_permission(
    tmp_path, monkeypatch
):
    with _app_case(tmp_path, monkeypatch) as case:
        barrier = SimpleNamespace(
            reached=threading.Event(), release=threading.Event(), released_in_time=None
        )
        case.entry_barrier = barrier
        observed, propagated, entered_body = [], [], []

        async def cancel_after_entry(cancellation):
            try:
                reached = await anyio.to_thread.run_sync(barrier.reached.wait, 12)
                assert reached, "actual original entry did not reach its delivery barrier"
                observed.append(
                    (
                        len(case.entry_returns),
                        len(case.exits),
                        case.app_security[0].is_open(),
                        case.owner.status().phase,
                        case.read_stores[0].status(),
                    )
                )
                cancellation.cancel()
            finally:
                # Deliver the SAME successful original entry; the app must
                # retain completion and dispatch its original exit exactly once.
                barrier.release.set()

        async def exercise():
            with anyio.CancelScope() as cancellation:
                async with anyio.create_task_group() as tasks:
                    tasks.start_soon(cancel_after_entry, cancellation)
                    try:
                        async with case.app.router.lifespan_context(case.app):
                            entered_body.append(True)
                    except BaseException as error:
                        if isinstance(error, anyio.get_cancelled_exc_class()):
                            propagated.append(error)
                        raise
            assert cancellation.cancel_called is True
            assert cancellation.cancelled_caught is True

        try:
            anyio.run(exercise)
            assert observed == [
                (1, 0, False, "idle", ReadinessReadStoreStatus("open", False, False, None))
            ]
            assert entered_body == [] and len(propagated) == 1
            assert barrier.released_in_time is True
            assert case.exits[0][1] is type(propagated[0])
            assert case.exits[0][2] is propagated[0]
            assert case.proofs == case.query_count == 0 and case.read_ids == []
            _closed(case)
            client = TestClient(case.app)
            try:
                _disabled(client.get(BOOTSTRAP))
                assert len(case.entries) == len(case.exits) == 1
            finally:
                client.close()
        finally:
            barrier.release.set()


def test_actual_body_cancellation_keeps_identity_through_shielded_original_exit(
    tmp_path, monkeypatch
):
    with _app_case(tmp_path, monkeypatch) as case:
        client = TestClient(case.app)  # Manual lifespan below, never a second entry.
        body_cancellations, propagated, progress = [], [], []

        async def exercise():
            with anyio.CancelScope() as cancellation:
                try:
                    async with case.app.router.lifespan_context(case.app):
                        headers = await anyio.to_thread.run_sync(_authorize, case, client)
                        response = await anyio.to_thread.run_sync(
                            lambda: client.get(SELECTION, headers=headers)
                        )
                        _selection(case, response)
                        assert case.proofs == case.query_count == 1
                        assert case.proof_errors == [] and case.exits == []
                        assert case.owner.status().cleanup_complete is False
                        cancellation.cancel()
                        try:
                            await anyio.lowlevel.checkpoint()
                        except BaseException as error:
                            if isinstance(error, anyio.get_cancelled_exc_class()):
                                body_cancellations.append(error)
                            raise
                        progress.append("body incorrectly resumed")
                except BaseException as error:
                    if body_cancellations:
                        propagated.append(error)
                    raise
                progress.append("lifespan incorrectly suppressed cancellation")
            assert cancellation.cancel_called is True
            assert cancellation.cancelled_caught is True
            progress.append("only the original cancel scope suppressed cancellation")

        try:
            anyio.run(exercise)
            assert len(body_cancellations) == len(propagated) == 1
            assert propagated[0] is body_cancellations[0]
            assert progress == ["only the original cancel scope suppressed cancellation"]
            assert case.exits[0][1] is type(body_cancellations[0])
            assert case.exits[0][2] is body_cancellations[0]
            _closed(case)
            _disabled(client.get(BOOTSTRAP))
            assert case.proofs == case.query_count == 1
        finally:
            client.close()


def test_held_actual_sql_shutdown_preserves_cutoff_and_denies_late_http_result(
    tmp_path, monkeypatch
):
    with _app_case(tmp_path, monkeypatch) as case:
        client = TestClient(case.app)
        try:
            with _held_query(case) as pause:
                pause.responses = []

                async def exercise():
                    async with case.app.router.lifespan_context(case.app):
                        headers = await anyio.to_thread.run_sync(_authorize, case, client)
                        _request(client, headers, pause)
                        reached = await anyio.to_thread.run_sync(pause.reached.wait, 5)
                        assert reached, "original SQL did not reach its test barrier"
                        assert case.proofs == case.query_count == 1
                        assert case.proof_errors == [] and case.exits == []
                        # Leave while the original query still owns K's slot.

                with pytest.raises(RuntimeError) as raised:
                    anyio.run(exercise)
                cutoff = raised.value
                _fixed(cutoff, "READ_CLEANUP_INCOMPLETE")
                assert case.exit_errors == [cutoff] and case.exit_returns == []
                assert len(case.entries) == len(case.entry_returns) == len(case.exits) == 1
                assert case.exits[0][1:] == (None, None)
                assert case.read_stores[0].status() == ReadinessReadStoreStatus(
                    "closing", True, False, None
                )
                assert case.read_disposals == [] and pause.responses == pause.errors == []
                assert not case.app_security[0].is_open()
                _owner_closed(case)
                _disabled(client.get(BOOTSTRAP))
                pause.release.set()
                for caller in pause.callers:
                    caller.join(8)
                    assert not caller.is_alive()
                assert pause.errors == [] and len(pause.responses) == 1
                _unavailable(pause.responses[0])
                _read_closed(case)
                # Later cleanup cannot rewrite what L actually observed.
                assert case.exit_errors == [cutoff] and case.exit_returns == []
                _fixed(cutoff, "READ_CLEANUP_INCOMPLETE")
                assert case.proofs == case.query_count == len(case.read_ids) == 1
        finally:
            client.close()


def test_lifespan_primary_and_actual_k_disposal_failure_preserve_original_l_group(
    tmp_path, monkeypatch
):
    primary = BaseException("private operational-read body primary")
    cleanup = OSError("private actual read-engine disposal failure")
    with _app_case(tmp_path, monkeypatch) as case:
        client = TestClient(case.app)
        disposal_calls = []
        case.allow_read_cleanup_failure = True

        def failed_disposal(engine):
            disposal_calls.append(engine)
            raise cleanup

        async def exercise():
            async with case.app.router.lifespan_context(case.app):
                headers = await anyio.to_thread.run_sync(_authorize, case, client)
                response = await anyio.to_thread.run_sync(
                    lambda: client.get(SELECTION, headers=headers)
                )
                _selection(case, response)
                assert case.proofs == case.query_count == 1
                assert all(connection.closed for connection in case.query_connections)
                event.listen(case.read_engines[0], "engine_disposed", failed_disposal)
                raise primary

        try:
            with pytest.raises(BaseExceptionGroup) as raised:
                anyio.run(exercise)
            group = raised.value
            assert group.message == "CONFIGURED_READINESS_READS_OPERATION_AND_CLEANUP_FAILED"
            assert len(group.exceptions) == 2 and group.exceptions[0] is primary
            _fixed(group.exceptions[1], "READ_CLEANUP_INCOMPLETE")
            assert all(member is not cleanup for member in group.exceptions)
            assert case.exit_errors == [group] and case.exit_errors[0] is group
            assert case.exit_returns == [] and case.entry_errors == []
            assert len(case.entries) == len(case.entry_returns) == len(case.exits) == 1
            assert case.exits[0][1] is type(primary) and case.exits[0][2] is primary
            assert disposal_calls == case.read_disposals == case.read_engines
            assert case.read_stores[0]._cleanup_error is cleanup
            assert case.read_stores[0].status() == ReadinessReadStoreStatus(
                "closed", False, False, "cleanup_failed"
            )
            _owner_closed(case)
            assert not case.app_security[0].is_open()
            _disabled(client.get(BOOTSTRAP))
            assert len(case.exits) == 1 and case.proofs == case.query_count == 1
        finally:
            client.close()
            if case.read_engines and event.contains(
                case.read_engines[0], "engine_disposed", failed_disposal
            ):
                event.remove(case.read_engines[0], "engine_disposed", failed_disposal)


def test_held_original_proof_keeps_ordered_k_and_owner_cutoffs_without_retry(tmp_path, monkeypatch):
    with _app_case(tmp_path, monkeypatch) as case:
        client = TestClient(case.app)
        try:
            with _paused_original_proof(case, monkeypatch) as pause:

                async def exercise():
                    async with case.app.router.lifespan_context(case.app):
                        headers = await anyio.to_thread.run_sync(_authorize, case, client)
                        _request(client, headers, pause)
                        reached = await anyio.to_thread.run_sync(pause.reached.wait, 5)
                        assert reached, "original full proof did not reach its test barrier"
                        assert case.proofs == 1 and case.proof_errors == []
                        assert case.query_count == 0 and case.exits == []
                        # Original K.close observes its still-owned slot before
                        # original owner.stop observes the still-held proof.

                with pytest.raises(BaseExceptionGroup) as raised:
                    anyio.run(exercise)
                cutoff = raised.value
                assert cutoff.message == "CONFIGURED_READINESS_READS_OPERATION_AND_CLEANUP_FAILED"
                assert len(cutoff.exceptions) == 2
                _fixed(cutoff.exceptions[0], "READ_CLEANUP_INCOMPLETE")
                _fixed(cutoff.exceptions[1], "OWNER_CLEANUP_INCOMPLETE")
                assert case.exit_errors == [cutoff] and case.exit_errors[0] is cutoff
                assert case.exit_returns == [] and case.entry_errors == []
                assert len(case.entries) == len(case.entry_returns) == len(case.exits) == 1
                assert case.exits[0][1:] == (None, None)
                status = case.owner.status()
                assert status.phase == "stopping" and status.busy is True
                assert status.cleanup_complete is False and case.owner._thread.is_alive()
                assert case.guard._descriptor is not None
                assert case.release_attempts == case.releases == case.disposals == []
                assert case.close_calls == case.guard_exits == 0
                assert not case.app_security[0].is_open()
                # The original check waiter observes stop before proof return.
                # K may now complete deferred cleanup, but neither observed
                # cutoff may be replaced by that later successful completion.
                for caller in pause.callers:
                    caller.join(5)
                    assert not caller.is_alive()
                assert pause.errors == [] and len(pause.responses) == 1
                _unavailable(pause.responses[0])
                _read_closed(case)
                _disabled(client.get(BOOTSTRAP))
                assert case.proofs == len(case.read_ids) == 1 and case.query_count == 0
                assert case.exit_errors == [cutoff] and len(case.exits) == 1
                # Only this fixture's finally releases the proof barrier.
            case.owner._thread.join(8)
            _owner_closed(case)
            _read_closed(case)
            assert case.exit_errors == [cutoff] and case.exit_errors[0] is cutoff
            _fixed(cutoff.exceptions[0], "READ_CLEANUP_INCOMPLETE")
            _fixed(cutoff.exceptions[1], "OWNER_CLEANUP_INCOMPLETE")
            assert case.proofs == 1 and case.query_count == 0 and len(case.exits) == 1
        finally:
            client.close()
