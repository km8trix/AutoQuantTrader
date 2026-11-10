"""One real HTTP-task cancellation at a controlled, socket-free ASGI boundary.

The installed framework shields its synchronous route worker. Cancellation of
the request task must therefore remain pending while genuine SQL is held, then
reach the controlled send checkpoint only after the original K body completes.
This is not a claim about network disconnects or immediate worker abandonment.
"""

import threading

import anyio
import pytest
from fastapi.testclient import TestClient

from apps.api.continuous_read_access import (
    CONTINUOUS_READ_CSRF_HEADER,
    CONTINUOUS_READ_SESSION_COOKIE,
)
from apps.api.readiness_read_store import ReadinessReadStoreStatus
from tests.integration.test_continuous_synthetic_configured_reads_app import (
    SELECTION,
    _app_case,
    _authorize,
)
from tests.integration.test_continuous_synthetic_readiness_read_store import _held_query


def test_actual_asgi_request_cancellation_keeps_sql_owned_until_original_body_exit(
    tmp_path, monkeypatch
):
    with _app_case(tmp_path, monkeypatch) as case:
        client = TestClient(case.app)  # Bootstrap only; no second lifespan.
        attempted, delivered, cancellations, scope_results, cutoffs = [], [], [], [], []
        received = []
        try:
            with _held_query(case) as pause:

                async def exercise():
                    finished = anyio.Event()
                    request_scope = None

                    async def receive():
                        # This fixed GET has no body or invented disconnect.
                        received.append("http.request")
                        assert received == ["http.request"]
                        return {"type": "http.request", "body": b"", "more_body": False}

                    async def send(message):
                        # Attempt is distinct from delivery. This explicit ASGI
                        # transport checkpoint admits actual cancellation, without
                        # pretending to model socket backpressure or disconnects.
                        attempted.append(dict(message))
                        await anyio.lowlevel.checkpoint()
                        delivered.append(dict(message))

                    async def request(scope, *, task_status=anyio.TASK_STATUS_IGNORED):
                        try:
                            with anyio.CancelScope() as cancellation:
                                task_status.started(cancellation)
                                try:
                                    await case.app(scope, receive, send)
                                except BaseException as error:
                                    if isinstance(error, anyio.get_cancelled_exc_class()):
                                        cancellations.append(error)
                                    raise
                            scope_results.append(
                                (cancellation.cancel_called, cancellation.cancelled_caught)
                            )
                        finally:
                            finished.set()

                    async with anyio.create_task_group() as tasks:
                        try:
                            with pytest.raises(RuntimeError) as raised:
                                async with case.app.router.lifespan_context(case.app):
                                    headers = await anyio.to_thread.run_sync(
                                        _authorize, case, client
                                    )
                                    token = client.cookies.get(CONTINUOUS_READ_SESSION_COOKIE)
                                    assert type(token) is str
                                    scope = {
                                        "type": "http",
                                        "asgi": {"version": "3.0", "spec_version": "2.3"},
                                        "http_version": "1.1",
                                        "scheme": "http",
                                        "method": "GET",
                                        "path": SELECTION,
                                        "raw_path": SELECTION.encode("ascii"),
                                        "query_string": b"",
                                        "root_path": "",
                                        "headers": [
                                            (b"host", b"testserver"),
                                            (
                                                b"cookie",
                                                (
                                                    CONTINUOUS_READ_SESSION_COOKIE + "=" + token
                                                ).encode("ascii"),
                                            ),
                                            (
                                                CONTINUOUS_READ_CSRF_HEADER.lower().encode("ascii"),
                                                headers[CONTINUOUS_READ_CSRF_HEADER].encode(
                                                    "ascii"
                                                ),
                                            ),
                                        ],
                                        "client": ("127.0.0.1", 12345),
                                        "server": ("testserver", 80),
                                    }
                                    request_scope = await tasks.start(request, scope)
                                    reached = await anyio.to_thread.run_sync(pause.reached.wait, 5)
                                    assert reached, "original SQL did not reach its test barrier"
                                    assert (
                                        case.proofs == case.query_count == len(case.read_ids) == 1
                                    )
                                    assert case.proof_errors == []
                                    assert len(case.query_threads) == 1
                                    worker = case.query_threads[0]
                                    assert worker is not threading.current_thread()
                                    assert worker is not case.owner._thread and worker.is_alive()
                                    pause.callers.append(worker)
                                    request_scope.cancel()
                                    await anyio.lowlevel.checkpoint()
                                    assert request_scope.cancel_called is True
                                    assert not finished.is_set() and cancellations == []
                                    assert attempted == delivered == []
                                    assert case.read_stores[0].status() == ReadinessReadStoreStatus(
                                        "open", True, False, None
                                    )
                                    assert len(case.query_connections) == 1
                                    assert not case.query_connections[0].closed
                                    assert case.read_disposals == [] and case.exits == []
                                    # The main task now leaves the composition;
                                    # only the separate request task is cancelled.

                            cutoff = raised.value
                            cutoffs.append(cutoff)
                            assert (
                                str(cutoff) == "CONFIGURED_READINESS_READS_READ_CLEANUP_INCOMPLETE"
                            )
                            assert type(cutoff) is RuntimeError
                            assert case.exit_errors == [cutoff] and case.exit_errors[0] is cutoff
                            assert case.exit_returns == [] and case.entry_errors == []
                            assert (
                                len(case.entries) == len(case.entry_returns) == len(case.exits) == 1
                            )
                            assert case.exits[0][1:] == (None, None)
                            assert not case.app_security[0].is_open()
                            owner_status = case.owner.status()
                            assert owner_status.phase == "stopped"
                            assert owner_status.cleanup_complete is True
                            assert not case.owner._thread.is_alive()
                            assert case.read_stores[0].status() == ReadinessReadStoreStatus(
                                "closing", True, False, None
                            )
                            assert not finished.is_set() and cancellations == []
                            assert attempted == delivered == [] and case.read_disposals == []
                            assert not case.query_connections[0].closed
                        finally:
                            # Release only the test barrier, even if an oracle
                            # fails. Wait for the actual ASGI task, never replace
                            # cleanup or release/adopt its owner's lease here.
                            pause.release.set()
                            if request_scope is not None:
                                request_scope.cancel()
                                with anyio.CancelScope(shield=True):
                                    with anyio.fail_after(8):
                                        await finished.wait()
                    assert finished.is_set()

                try:
                    anyio.run(exercise)
                finally:
                    pause.release.set()
                    # The runner has now ended its actual worker pool lifetime.
                    # The inherited barrier finally joins every observed worker,
                    # including a worker reached before an earlier assertion failed.
                    for worker in case.query_threads:
                        if worker not in pause.callers:
                            pause.callers.append(worker)

                assert len(cancellations) == 1 and scope_results == [(True, True)]
                assert len(attempted) == 1 and delivered == []
                start = attempted[0]
                assert set(start) == {"type", "status", "headers"}
                assert start["type"] == "http.response.start" and start["status"] == 503
                header_pairs = start["headers"]
                assert len(header_pairs) == len(dict(header_pairs)) == 4
                # Check names first so an unexpected cookie/header cannot be
                # included as a raw token in a value-comparison failure.
                assert {name for name, _value in header_pairs} == {
                    b"cache-control",
                    b"pragma",
                    b"content-length",
                    b"content-type",
                }
                # No body was attempted or delivered; this is the fixed 503
                # start and its declared body length, not a delivered-body claim.
                static_body = b'{"detail":"continuous operational read is unavailable"}'
                assert dict(header_pairs) == {
                    b"cache-control": b"no-store",
                    b"pragma": b"no-cache",
                    b"content-length": str(len(static_body)).encode("ascii"),
                    b"content-type": b"application/json",
                }
                assert case.read_stores[0].status() == ReadinessReadStoreStatus(
                    "closed", False, True, None
                )
                assert case.read_disposals == case.read_engines
                assert all(connection.closed for connection in case.query_connections)
                assert case.proofs == case.query_count == len(case.read_ids) == 1
                assert len(cutoffs) == 1 and case.exit_errors[0] is cutoffs[0]
                assert str(cutoffs[0]) == "CONFIGURED_READINESS_READS_READ_CLEANUP_INCOMPLETE"
                assert len(case.exits) == 1 and case.exit_returns == []
                assert (
                    len(case.acquires)
                    == len(case.release_attempts)
                    == len(case.releases)
                    == case.close_calls
                    == case.guard_exits
                    == 1
                )
            assert pause.callers and all(not worker.is_alive() for worker in pause.callers)
        finally:
            client.close()
        # Original G/K finalizers retain all row/object/fence/null-head and
        # successful original cleanup oracles; this is no network guarantee.
