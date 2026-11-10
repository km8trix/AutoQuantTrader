"""Real lifespan cancellation and ordered failures on new disposable stores.

The actual ASGI lifespan owns startup and its single stop dispatch. TestClient
is deliberately not entered as another lifespan. The original configured owner,
full financial proof, lease and all cleanup remain real; no server is started.
"""

import anyio
import pytest
from fastapi.testclient import TestClient

from tests.integration.test_continuous_synthetic_readiness_http import (
    _http_case,
    _lifespan_closed,
    _paused_original_proof,
    _reply,
    _request_in_thread,
)


def test_actual_lifespan_cancellation_preserves_identity_after_shielded_original_stop(
    tmp_path, monkeypatch
):
    with _http_case(tmp_path, monkeypatch) as case:
        client = TestClient(case.app)
        body_cancellations, propagated_cancellations = [], []
        progress = []

        async def exercise():
            with anyio.CancelScope() as cancellation:
                try:
                    async with case.app.router.lifespan_context(case.app):
                        response = await anyio.to_thread.run_sync(client.get, "/health/ready")
                        _reply(response, 200, "ready")
                        assert case.proofs == 1 and case.proof_errors == []
                        assert len(case.http_starts) == 1 and case.http_stops == []
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
                        propagated_cancellations.append(error)
                    raise
                progress.append("lifespan incorrectly suppressed cancellation")
            assert cancellation.cancel_called is True
            assert cancellation.cancelled_caught is True
            progress.append("only the original cancel scope suppressed cancellation")

        try:
            anyio.run(exercise)
            assert len(body_cancellations) == len(propagated_cancellations) == 1
            assert propagated_cancellations[0] is body_cancellations[0]
            assert progress == ["only the original cancel scope suppressed cancellation"]
            _lifespan_closed(case)
            assert case.proofs == 1 and len(case.acquires) == len(case.releases) == 1
            assert case.close_calls == 1 and case.guard_exits == 1
            assert case.http_stops[0][1].primary_failure is None
        finally:
            client.close()
        # The enclosing G fixture independently checks exact all-table/object
        # preservation, R1/release/head, both engines, guard and actual dead thread.


def test_lifespan_primary_is_not_masked_by_actual_incomplete_owner_cleanup(tmp_path, monkeypatch):
    primary = BaseException("private synthetic lifespan primary")
    with _http_case(tmp_path, monkeypatch) as case:
        with _paused_original_proof(case, monkeypatch) as pause:
            client = TestClient(case.app)

            async def exercise():
                async with case.app.router.lifespan_context(case.app):
                    caller = _request_in_thread(client, pause)
                    reached = await anyio.to_thread.run_sync(pause.reached.wait, 5)
                    assert reached, "original complete proof did not reach its test barrier"
                    await anyio.to_thread.run_sync(caller.join, 6)
                    assert not caller.is_alive() and pause.errors == []
                    assert len(pause.responses) == 1
                    _reply(pause.responses[0], 503, "not_ready")
                    assert case.proofs == 1 and case.proof_errors == []
                    assert case.owner.status().busy is True
                    assert case.release_attempts == [] and case.disposals == []
                    raise primary

            try:
                with pytest.raises(BaseExceptionGroup) as raised:
                    anyio.run(exercise)
                group = raised.value
                assert group.message == "CONTINUOUS_READINESS_LIFESPAN_AND_CLEANUP_FAILED"
                assert len(group.exceptions) == 2 and group.exceptions[0] is primary
                cleanup = group.exceptions[1]
                assert type(cleanup) is RuntimeError
                assert str(cleanup) == "CONTINUOUS_READINESS_CLEANUP_INCOMPLETE"
                assert len(case.http_starts) == len(case.http_stops) == 1
                stopped = case.http_stops[0][1]
                assert stopped.phase == "stopping" and stopped.cleanup_complete is False
                assert case.owner._thread.is_alive() and case.owner.status().busy is True
                assert case.guard._descriptor is not None
                assert case.release_attempts == [] and case.disposals == []
                assert case.close_calls == case.guard_exits == 0
                assert case.proofs == 1 and len(case.acquires) == 1
            finally:
                client.close()
        # Only the test barrier was released. The original owner performs all
        # financial cleanup; G's finally waits for it and verifies the facts.
        assert len(case.http_stops) == 1


def test_lifespan_primary_propagates_unchanged_after_successful_original_cleanup(
    tmp_path, monkeypatch
):
    primary = BaseException("private synthetic sole lifespan primary")
    with _http_case(tmp_path, monkeypatch) as case:
        client = TestClient(case.app)

        async def exercise():
            async with case.app.router.lifespan_context(case.app):
                response = await anyio.to_thread.run_sync(client.get, "/health/ready")
                _reply(response, 200, "ready")
                assert case.proofs == 1 and case.proof_errors == []
                assert case.http_stops == [] and case.release_attempts == []
                raise primary

        try:
            with pytest.raises(BaseException) as raised:
                anyio.run(exercise)
            assert raised.value is primary
            _lifespan_closed(case)
            assert case.proofs == 1 and len(case.acquires) == len(case.releases) == 1
            assert case.close_calls == 1 and case.guard_exits == 1
            assert case.http_stops[0][1].primary_failure is None
        finally:
            client.close()
