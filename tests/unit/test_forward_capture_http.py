"""Mechanical socket/credential doubles only; no provider or entitlement evidence."""

import io
import json
import pickle
import threading
import time
from dataclasses import replace

import pytest

from packages.adapters import forward_capture_http as capture
from packages.adapters.broker import etrade_readonly as etrade
from packages.application import etrade_session as session_module
from tests.unit.test_etrade_session import NOW, Journal, values
from tests.unit.test_personal_forward_capture import request as fixture_request


@pytest.fixture
def network(monkeypatch):
    """Exercise the concrete algorithm without DNS, TLS, sockets or a service."""
    state = {
        "events": [],
        "body": b"{}",
        "status": 200,
        "content_type": "application/json",
        "encoding": "identity",
        "shutdown": threading.Event(),
    }

    def callback(name):
        if name in state:
            state[name]()

    class Socket:
        def settimeout(self, seconds):
            assert seconds > 0
            state["events"].append(("timeout", seconds))

        def connect(self, address):
            state["events"].append(("connect", address))
            callback("on_connect")

        def shutdown(self, _how):
            state["shutdown"].set()

        def close(self):
            state["events"].append("socket_closed")

    class Context:
        def wrap_socket(self, raw, *, server_hostname):
            state["events"].append(("tls", server_hostname))
            callback("on_tls")
            return raw

    class Response:
        def __init__(self):
            self.status = state["status"]
            self.body = state["body"]

        def getheader(self, name, default):
            if name == "Content-Encoding":
                return state.get("encoding", default)
            return {
                "Content-Type": state["content_type"],
            }.get(name, default)

        def read1(self, count):
            state["events"].append(("read_bound", count))
            callback("on_body")
            value, self.body = self.body[:count], self.body[count:]
            return value

        def close(self):
            state["events"].append("response_closed")
            callback("on_response_close")

    class Connection:
        def __init__(self, hostname, *, timeout, context):
            state["events"].append(("hostname", hostname))
            self.sock = None

        def request(self, method, path, *, headers):
            state["events"].append(("request", method, path, tuple(sorted(headers))))
            assert "fixture" in headers["Authorization"] or headers["Authorization"].startswith(
                "OAuth "
            )

        def getresponse(self):
            callback("on_headers")
            self.sock = None  # model Connection: close without dropping response ownership
            return Response()

        def close(self):
            state["events"].append("connection_closed")

    def addresses(hostname, port, **kwargs):
        state["events"].append(("dns", hostname, port))
        callback("on_dns")
        return [(2, 1, 6, "", ("192.0.2.1", 443))]

    monkeypatch.setattr(capture.socket, "getaddrinfo", addresses)
    monkeypatch.setattr(capture.socket, "socket", lambda *args: Socket())
    monkeypatch.setattr(capture.ssl, "create_default_context", Context)
    monkeypatch.setattr(capture.http.client, "HTTPSConnection", Connection)
    return state


def tiingo(request=None, *, loader=lambda: "fixture-token-only", seconds=1):
    request = request or fixture_request("daily", evidence_class="provider_https_read")
    return request, capture.TiingoForwardHTTPSGetTransport(
        request=request,
        token_loader=loader,
        deadline_monotonic=time.monotonic() + seconds,
    )


def actual_session(*, loader=None, transport=None):
    reference = etrade.EtradeSecretReference(
        etrade.EtradeEnvironment.PRODUCTION, "envfile:///fixture-only?version=1"
    )
    loaded = []

    class Store:
        def resolve(self, requested):
            assert requested is reference
            if loader is not None:
                loader()
            value = etrade.EtradeReadCredentials(reference, values())
            loaded.append(value)
            return value

    class Clock:
        def now(self):
            return NOW

    result = session_module.EtradeReadOnlySession(
        reference=reference,
        store=Store(),
        transport=transport or etrade.EtradeHTTPSGetTransport(),
        journal=Journal(),
        clock=Clock(),
    )
    return result, loaded


def _binding_transport(provider, loads):
    if provider == "tiingo":
        return tiingo(loader=lambda: loads.append(1) or "fixture-token-only")
    session, _ = actual_session(loader=lambda: loads.append(1))
    request = fixture_request(evidence_class="provider_https_read")
    return request, capture.EtradeForwardCaptureTransport(
        request=request, session=session, deadline_monotonic=time.monotonic() + 1
    )


@pytest.mark.parametrize("provider", ["tiingo", "etrade"])
def test_original_binding_check_before_and_after_use_has_no_io_or_attempt_effect(network, provider):
    loads = []
    request, transport = _binding_transport(provider, loads)
    original_deadline = transport._deadline
    for _ in range(2):
        transport.require_original_capture_binding(request)
    with pytest.raises(capture.ForwardCaptureHTTPError):
        transport.recheck_original_capture(request)
    assert not transport._used and not loads and not network["events"]
    assert transport._deadline == original_deadline

    response = transport.get(request, deadline_ms=1000)
    assert response.body == b"{}" and response.request_sha256 == request.http_request_sha256
    original_events, original_loads = tuple(network["events"]), tuple(loads)
    transport.require_original_capture_binding(request)
    transport.recheck_original_capture(request)
    with pytest.raises(capture.ForwardCaptureHTTPError):
        transport.get(request, deadline_ms=1000)
    assert transport._used and transport._deadline == original_deadline
    assert tuple(network["events"]) == original_events and tuple(loads) == original_loads


@pytest.mark.parametrize("provider", ["tiingo", "etrade"])
@pytest.mark.parametrize("fault", ["copy", "source", "deadline", "expired"])
def test_original_binding_check_rejects_request_or_deadline_change_without_io(
    network, monkeypatch, provider, fault
):
    loads = []
    request, transport = _binding_transport(provider, loads)
    supplied = request
    if fault == "copy":
        supplied = replace(request)
    elif fault == "source":
        object.__setattr__(request.source, "rights_reference", "changed-original")
    elif fault == "deadline":
        transport._deadline += 1
    else:
        monkeypatch.setattr(capture.time, "monotonic", lambda: transport._original_deadline)
    with pytest.raises(capture.ForwardCaptureHTTPError, match=r"ORIGINAL|DEADLINE"):
        transport.require_original_capture_binding(supplied)
    assert not transport._used and not loads and not network["events"]


def test_original_binding_check_rejects_tiingo_loader_substitution_without_loading(network):
    loads = []
    request, transport = _binding_transport("tiingo", loads)
    transport._token_loader = lambda: loads.append(2) or "different-fixture-token"
    with pytest.raises(capture.ForwardCaptureHTTPError, match="ORIGINAL_CAPTURE"):
        transport.require_original_capture_binding(request)
    assert not transport._used and not loads and not network["events"]


@pytest.mark.parametrize(
    "fault", ["session", "reference", "reference_fields", "store", "transport", "class", "closed"]
)
def test_original_binding_check_rejects_etrade_session_substitution_without_io(network, fault):
    loads = []
    request, transport = _binding_transport("etrade", loads)
    session = transport._session
    if fault == "session":
        replacement, _ = actual_session()
        replacement.reference, replacement.store, replacement.transport = transport._original
        transport._session = replacement
    elif fault == "reference":
        session.reference = replace(session.reference)
    elif fault == "reference_fields":
        object.__setattr__(session.reference, "environment", etrade.EtradeEnvironment.SANDBOX)
    elif fault == "store":
        session.store = object()
    elif fault == "transport":
        session.transport = etrade.EtradeHTTPSGetTransport()
    elif fault == "class":
        session.transport.evidence_class = "synthetic_fixture"
    else:
        session.close()
    with pytest.raises(capture.ForwardCaptureHTTPError, match="ORIGINAL_ETRADE"):
        transport.require_original_capture_binding(request)
    assert not transport._used and not loads and not network["events"]


def test_tiingo_original_request_fixed_headers_body_limit_and_one_attempt(network):
    request, transport = tiingo()
    result = transport.get(request, deadline_ms=1000)
    assert result.request_sha256 == request.http_request_sha256
    assert result.body == b"{}" and result.evidence_class == "provider_https_read"
    # That class tests concrete-path wiring only: all network operations above
    # are mechanical doubles, so this does not qualify a provider capture.
    assert ("dns", "api.tiingo.com", 443) in network["events"]
    assert ("tls", "api.tiingo.com") in network["events"]
    calls = [e for e in network["events"] if isinstance(e, tuple) and e[0] == "request"]
    assert calls == [
        (
            "request",
            "GET",
            request.path + "?startDate=2026-09-09&endDate=2026-09-09&format=json",
            ("Accept", "Accept-Encoding", "Authorization"),
        )
    ]
    assert "response_closed" in network["events"] and "socket_closed" in network["events"]
    with pytest.raises(capture.ForwardCaptureHTTPError, match="ALREADY_USED"):
        transport.get(request, deadline_ms=1000)
    with pytest.raises(TypeError):
        pickle.dumps(transport)
    assert "fixture-token" not in repr(transport)


@pytest.mark.parametrize("provider", ["tiingo", "etrade"])
def test_post_get_original_recheck_keeps_deadline_and_performs_no_io(
    network, monkeypatch, provider
):
    loads = []
    if provider == "tiingo":
        request, transport = tiingo(loader=lambda: loads.append(1) or "fixture-token-only")
    else:
        session, _ = actual_session(loader=lambda: loads.append(1))
        request = fixture_request(evidence_class="provider_https_read")
        transport = capture.EtradeForwardCaptureTransport(
            request=request, session=session, deadline_monotonic=time.monotonic() + 1
        )
    with pytest.raises(capture.ForwardCaptureHTTPError):
        transport.recheck_original_capture(request)
    assert not loads and not network["events"]
    transport.get(request, deadline_ms=1000)
    original_events, original_loads = tuple(network["events"]), tuple(loads)
    transport.recheck_original_capture(request)
    assert tuple(network["events"]) == original_events and tuple(loads) == original_loads
    assert transport._used
    with pytest.raises(capture.ForwardCaptureHTTPError):
        transport.recheck_original_capture(replace(request))
    monkeypatch.setattr(capture.time, "monotonic", lambda: transport._original_deadline)
    with pytest.raises(capture.ForwardCaptureHTTPError, match="DEADLINE"):
        transport.recheck_original_capture(request)
    assert tuple(network["events"]) == original_events and tuple(loads) == original_loads


@pytest.mark.parametrize("fault", ["loader", "source", "deadline", "closed", "reference"])
def test_post_get_original_recheck_rejects_late_binding_change(network, fault):
    if fault in ("closed", "reference"):
        session, _ = actual_session()
        request = fixture_request(evidence_class="provider_https_read")
        transport = capture.EtradeForwardCaptureTransport(
            request=request, session=session, deadline_monotonic=time.monotonic() + 1
        )
    else:
        request, transport = tiingo()
    transport.get(request, deadline_ms=1000)
    original_events = tuple(network["events"])
    if fault == "loader":
        transport._token_loader = lambda: "different-fixture-token"
    elif fault == "source":
        object.__setattr__(request.source, "rights_reference", "changed-original")
    elif fault == "deadline":
        transport._deadline += 1
    elif fault == "closed":
        session.close()
    else:
        session.reference = replace(session.reference)
    with pytest.raises(capture.ForwardCaptureHTTPError, match="ORIGINAL"):
        transport.recheck_original_capture(request)
    assert tuple(network["events"]) == original_events


@pytest.mark.parametrize("fault", ["copy", "source", "deadline", "loader"])
def test_original_request_and_deadline_are_bound_before_credentials(network, fault):
    loads = []
    request, transport = tiingo(loader=lambda: loads.append(1) or "fixture-token-only")
    supplied = request
    if fault == "copy":
        supplied = replace(request)
    elif fault == "source":
        object.__setattr__(request.source, "source_id", "changed-original-source")
    elif fault == "deadline":
        transport._deadline += 3
    else:
        transport._token_loader = lambda: "different-fixture-token"
    with pytest.raises(capture.ForwardCaptureHTTPError):
        transport.get(supplied, deadline_ms=1000)
    assert not loads and not network["events"]


@pytest.mark.parametrize("deadline", [0, float("nan"), float("inf"), True, 4])
def test_deadline_rejects_invalid_or_inflated_original_budget(deadline):
    with pytest.raises(capture.ForwardCaptureHTTPError):
        capture.TiingoForwardHTTPSGetTransport(
            request=fixture_request("daily", evidence_class="provider_https_read"),
            token_loader=lambda: "fixture-token-only",
            deadline_monotonic=deadline if type(deadline) is bool else time.monotonic() + deadline,
        )


def test_synthetic_class_and_injected_session_transport_cannot_claim_provider(network):
    with pytest.raises(capture.ForwardCaptureHTTPError, match="FIXTURE"):
        tiingo(fixture_request("daily"))

    class FixtureTransport:
        evidence_class = "provider_https_read"  # a string cannot confer this class

    session, _ = actual_session(transport=FixtureTransport())
    with pytest.raises(capture.ForwardCaptureHTTPError, match="EXACT_ETRADE"):
        capture.EtradeForwardCaptureTransport(
            request=fixture_request(evidence_class="provider_https_read"),
            session=session,
            deadline_monotonic=time.monotonic() + 1,
        )
    assert not network["events"]


@pytest.mark.parametrize("provider", ["tiingo", "etrade"])
def test_credential_delay_cannot_restart_deadline_or_dispatch_late(network, provider):
    entered, unblock = threading.Event(), threading.Event()

    def loader():
        entered.set()
        unblock.wait(1)
        return "fixture-token-only"

    started = time.monotonic()
    if provider == "tiingo":
        request, transport = tiingo(loader=loader, seconds=0.06)

        def call():
            return transport.get(request, deadline_ms=1000)

        loaded = []
    else:
        session, loaded = actual_session(loader=loader)

        def call():
            return session.read_quote_response(("SPY",), deadline_monotonic=started + 0.06)

    try:
        with pytest.raises((capture.ForwardCaptureHTTPError, etrade.EtradeReadError)):
            call()
        assert entered.is_set() and time.monotonic() - started < 0.4
        assert not network["events"]
    finally:
        unblock.set()
    until = time.monotonic() + 0.3
    while (
        provider == "etrade"
        and (not loaded or any(value._values for value in loaded))
        and time.monotonic() < until
    ):
        time.sleep(0.005)
    assert all(not value._values for value in loaded)
    assert not network["events"]


@pytest.mark.parametrize("stage", ["dns", "headers", "body"])
def test_tiingo_total_deadline_bounds_blocked_or_dripping_stage(network, stage):
    release = threading.Event()

    def block():
        (release if stage == "dns" else network["shutdown"]).wait(1)
        raise OSError("fixture-private-header-token")

    network["on_" + stage] = block
    request, transport = tiingo(seconds=0.07)
    started = time.monotonic()
    try:
        with pytest.raises(capture.ForwardCaptureHTTPError) as error:
            transport.get(request, deadline_ms=1000)
        assert "fixture-private" not in str(error.value)
        assert time.monotonic() - started < 0.4
    finally:
        release.set()
    assert "connection_closed" in network["events"]


@pytest.mark.parametrize("status", [204, 301, 401, 403, 429, 500])
def test_tiingo_http_status_is_observed_without_redirect_or_retry(network, status):
    network["status"] = status
    request, transport = tiingo()
    assert transport.get(request, deadline_ms=1000).status == status
    assert sum(e[0] == "request" for e in network["events"] if isinstance(e, tuple)) == 1


@pytest.mark.parametrize("fault", ["body", "encoding", "content_type"])
def test_tiingo_response_constraints_reject_before_capture_publication(network, fault):
    if fault == "body":
        network["body"] = b"12345"
    elif fault == "encoding":
        network["encoding"] = "gzip"
    else:
        network["content_type"] = "x" * 257
    request, transport = tiingo(
        fixture_request("daily", evidence_class="provider_https_read", max_response_bytes=4)
    )
    with pytest.raises(capture.ForwardCaptureHTTPError):
        transport.get(request, deadline_ms=1000)
    assert "connection_closed" in network["events"]


def test_tiingo_real_http_header_parser_has_aggregate_limit():
    class Socket:
        def makefile(self, mode):
            return io.BytesIO(b"HTTP/1.1 200 OK\r\nX: " + b"x" * 65510 + b"\r\nY: overflow\r\n\r\n")

    response = capture._TiingoHTTPResponse(Socket())
    with pytest.raises(capture.ForwardCaptureHTTPError, match="HEADERS_TOO_LARGE"):
        response.begin()
    response.close()


@pytest.mark.parametrize("fault", ["trailer", "chunk_extension", "none"])
def test_tiingo_real_chunked_parser_metadata_budget_does_not_charge_body(fault):
    prefix = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    body = b"x" * 65537
    if fault == "chunk_extension":
        chunks = b"".join(b"1;" + b"y" * 40000 + b"\r\nx\r\n" for _ in range(2))
    else:
        chunks = hex(len(body))[2:].encode() + b"\r\n" + body + b"\r\n"
    trailer = b"X: " + b"y" * 40000 + b"\r\n" if fault == "trailer" else b""

    class Socket:
        def makefile(self, mode):
            return io.BytesIO(prefix + chunks + b"0\r\n" + trailer * 2 + b"\r\n")

    response = capture._TiingoHTTPResponse(Socket())
    response.begin()
    read = []

    def consume():
        while data := response.read1(4096):
            read.append(data)

    try:
        if fault == "none":
            consume()
            assert b"".join(read) == body
        else:
            with pytest.raises(
                (capture.ForwardCaptureHTTPError, capture.http.client.IncompleteRead)
            ) as error:
                consume()
            # The stdlib chunk-size parser wraps ValueError as IncompleteRead;
            # its original metadata-limit cause must remain the same rejection.
            rejection = error.value
            if isinstance(rejection, capture.http.client.IncompleteRead):
                rejection = rejection.__context__
            assert type(rejection) is capture.ForwardCaptureHTTPError
            assert str(rejection) == "CAPTURE_HTTP_HEADERS_TOO_LARGE"
    finally:
        response.close()


def test_etrade_shared_deadline_and_smaller_body_cap_reach_actual_transport(network, monkeypatch):
    session, loaded = actual_session(loader=lambda: time.sleep(0.03))
    original = session_module.sign_account_get

    def sign(*args, **kwargs):
        time.sleep(0.03)
        return original(*args, **kwargs)

    monkeypatch.setattr(session_module, "sign_account_get", sign)
    request = fixture_request(evidence_class="provider_https_read", max_response_bytes=4)
    deadline = time.monotonic() + 0.7
    transport = capture.EtradeForwardCaptureTransport(
        request=request, session=session, deadline_monotonic=deadline
    )
    result = transport.get(request, deadline_ms=1000)
    assert json.loads(result.body) == {} and result.request_sha256 == request.http_request_sha256
    assert transport._deadline == deadline
    timeouts = [e[1] for e in network["events"] if isinstance(e, tuple) and e[0] == "timeout"]
    assert max(timeouts) < 0.65
    assert all(not value._values for value in loaded)
    assert ("read_bound", 5) in network["events"]


def test_etrade_small_body_limit_and_original_session_mutation_reject(network):
    session, loaded = actual_session()
    network["body"] = b"12345"
    with pytest.raises(etrade.EtradeReadError, match="RESPONSE_TOO_LARGE"):
        session.read_quote_response(
            ("SPY",), deadline_monotonic=time.monotonic() + 1, max_response_bytes=4
        )
    assert all(not value._values for value in loaded)
    request = fixture_request(evidence_class="provider_https_read")
    wrapper = capture.EtradeForwardCaptureTransport(
        request=request, session=session, deadline_monotonic=time.monotonic() + 1
    )
    session.reference = replace(session.reference)
    with pytest.raises(capture.ForwardCaptureHTTPError, match="ORIGINAL_ETRADE"):
        wrapper.get(request, deadline_ms=1000)


@pytest.mark.parametrize("stage", ["loader", "tls", "body"])
def test_tiingo_request_mutated_during_dependency_is_never_reclassified(network, stage):
    request = fixture_request("daily", evidence_class="provider_https_read")

    def mutate():
        object.__setattr__(request.instruments[0], "symbol", "QQQ")
        return "fixture-token-only"

    request, transport = tiingo(
        request, loader=mutate if stage == "loader" else lambda: "fixture-token-only"
    )
    if stage != "loader":
        network["on_" + stage] = mutate
    with pytest.raises(capture.ForwardCaptureHTTPError, match="ORIGINAL_CAPTURE"):
        transport.get(request, deadline_ms=1000)
    calls = [e for e in network["events"] if isinstance(e, tuple) and e[0] == "request"]
    assert not calls if stage != "body" else len(calls) == 1 and "/SPY/" in calls[0][2]


@pytest.mark.parametrize("deadline_ms", [True, 0, -1, 3001])
def test_relative_request_budget_cannot_expand_or_change_type(network, deadline_ms):
    loads = []
    request, transport = tiingo(loader=lambda: loads.append(1) or "fixture-token-only")
    with pytest.raises(capture.ForwardCaptureHTTPError):
        transport.get(request, deadline_ms=deadline_ms)
    assert not loads and not network["events"]


@pytest.mark.parametrize("fault", ["session", "reference_fields", "transport_class"])
def test_etrade_original_session_nested_identity_and_class_are_bound(network, fault):
    session, _ = actual_session()
    request = fixture_request(evidence_class="provider_https_read")
    wrapper = capture.EtradeForwardCaptureTransport(
        request=request, session=session, deadline_monotonic=time.monotonic() + 1
    )
    if fault == "session":
        replacement, _ = actual_session()
        replacement.reference, replacement.store, replacement.transport = wrapper._original
        wrapper._session = replacement
    elif fault == "reference_fields":
        object.__setattr__(session.reference, "environment", etrade.EtradeEnvironment.SANDBOX)
    else:
        session.transport.evidence_class = "synthetic_fixture"
    with pytest.raises(capture.ForwardCaptureHTTPError, match="ORIGINAL_ETRADE"):
        wrapper.get(request, deadline_ms=1000)
    assert not network["events"]


def test_etrade_signing_delay_spends_original_budget_before_http(network, monkeypatch):
    session, loaded = actual_session()
    original = session_module.sign_account_get

    def delayed_sign(*args, **kwargs):
        time.sleep(0.06)
        return original(*args, **kwargs)

    monkeypatch.setattr(session_module, "sign_account_get", delayed_sign)
    with pytest.raises(etrade.EtradeReadError, match="DEADLINE"):
        session.read_quote_response(("SPY",), deadline_monotonic=time.monotonic() + 0.04)
    assert not network["events"]
    assert loaded and all(not value._values for value in loaded)


def test_etrade_bounded_deadline_never_uses_legacy_injected_monotonic(network):
    unblock = threading.Event()
    session, loaded = actual_session(loader=lambda: unblock.wait(1))
    # Legacy fixture clocks remain injectable, but cannot extend actual HTTP or
    # strict credential waiting. This is no claim of UTC clock health.
    session.monotonic = lambda: 0.0
    started = time.monotonic()
    try:
        with pytest.raises(etrade.EtradeReadError, match="DEADLINE"):
            session.read_quote_response(("SPY",), deadline_monotonic=started + 0.05)
        assert time.monotonic() - started < 0.4
        assert not network["events"]
    finally:
        unblock.set()
    until = time.monotonic() + 0.3
    while (not loaded or any(value._values for value in loaded)) and time.monotonic() < until:
        time.sleep(0.005)
    assert loaded and all(not value._values for value in loaded)


def test_tiingo_connection_failures_try_at_most_four_addresses_and_never_http(network, monkeypatch):
    def addresses(*args, **kwargs):
        return [(2, 1, 6, "", ("192.0.2.1", 443))] * 6

    def failure():
        raise OSError("fixture-private-connect-message")

    monkeypatch.setattr(capture.socket, "getaddrinfo", addresses)
    network["on_connect"] = failure
    request, transport = tiingo()
    with pytest.raises(capture.ForwardCaptureHTTPError, match="TRANSPORT_FAILED"):
        transport.get(request, deadline_ms=1000)
    assert sum(e[0] == "connect" for e in network["events"] if isinstance(e, tuple)) == 4
    assert network["events"].count("socket_closed") == 4
    assert not any(e[0] == "request" for e in network["events"] if isinstance(e, tuple))


@pytest.mark.parametrize("provider", ["tiingo", "etrade"])
@pytest.mark.parametrize("fault", ["oversize", "deadline", "response_close"])
def test_connection_close_ownership_cleans_response_socket_connection(network, provider, fault):
    if fault == "oversize":
        network["body"] = b"12345"
    elif fault == "deadline":

        def deadline():
            network["shutdown"].wait(1)
            raise OSError("fixture-private-socket-exception")

        network["on_body"] = deadline
    else:

        def failed_close():
            raise OSError("fixture-private-cleanup-exception")

        network["on_response_close"] = failed_close

    started = time.monotonic()
    if provider == "tiingo":
        request, transport = tiingo(
            fixture_request("daily", evidence_class="provider_https_read", max_response_bytes=4),
            seconds=0.06,
        )
        with pytest.raises(capture.ForwardCaptureHTTPError) as error:
            transport.get(request, deadline_ms=1000)
    else:
        session, loaded = actual_session()
        with pytest.raises(etrade.EtradeReadError) as error:
            session.read_quote_response(
                ("SPY",), deadline_monotonic=started + 0.06, max_response_bytes=4
            )
        assert loaded and all(not value._values for value in loaded)
    assert "fixture-private" not in str(error.value)
    assert time.monotonic() - started < 0.4
    assert all(
        name in network["events"]
        for name in ("response_closed", "socket_closed", "connection_closed")
    )


@pytest.mark.parametrize("encoding", ["gzip", "deflate", "br", "gzip, identity"])
def test_etrade_nonidentity_encoding_is_rejected_before_body_read(network, encoding):
    session, loaded = actual_session()
    network["encoding"] = encoding
    with pytest.raises(etrade.EtradeReadError, match="RESPONSE_ENCODING_UNSUPPORTED"):
        session.read_quote_response(("SPY",), deadline_monotonic=time.monotonic() + 1)
    assert loaded and all(not value._values for value in loaded)
    assert not any(e[0] == "read_bound" for e in network["events"] if isinstance(e, tuple))
    assert all(
        name in network["events"]
        for name in ("response_closed", "socket_closed", "connection_closed")
    )


@pytest.mark.parametrize("encoding", [None, "IDENTITY"])
def test_etrade_plain_response_encoding_defaults_remain_compatible(network, encoding):
    session, _loaded = actual_session()
    if encoding is None:
        network.pop("encoding")
    else:
        network["encoding"] = encoding
    assert (
        session.read_quote_response(("SPY",), deadline_monotonic=time.monotonic() + 1).body == b"{}"
    )
