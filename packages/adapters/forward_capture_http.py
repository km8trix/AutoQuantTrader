"""Fixed provider GET components; no grants, clock qualification or scheduling.

The caller supplies an original transport deadline and a private token loader,
not evidence of provider rights. Only the concrete HTTPS path classifies its
response. Tests of patched sockets remain mechanical fixture evidence.
"""

from __future__ import annotations

import http.client
import math
import queue
import re
import socket
import ssl
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from typing import Any, BinaryIO, cast
from urllib.parse import urlencode

from packages.adapters.broker.etrade_readonly import EtradeHTTPSGetTransport
from packages.application.etrade_session import EtradeReadOnlySession
from packages.domain.forward_capture_contracts import CaptureResponse, ForwardCaptureRequest

_MAX_HEADER_BYTES = 64 * 1024
_MAX_DEADLINE_SECONDS = 3.0


class ForwardCaptureHTTPError(ValueError):
    """Static diagnostics; never include provider headers, bodies or secret text."""


def _remaining(deadline: float) -> float:
    value = deadline - time.monotonic()
    if value <= 0:
        raise ForwardCaptureHTTPError("CAPTURE_HTTP_DEADLINE_EXCEEDED")
    return value


class _HeaderStream:
    """Charge header/chunk/trailer lines; body reads keep their separate cap."""

    def __init__(self, original: BinaryIO) -> None:
        self.original, self.used = original, 0

    def readline(self, limit: int = -1) -> bytes:
        remaining = _MAX_HEADER_BYTES + 1 - self.used
        value = self.original.readline(remaining if limit < 0 else min(limit, remaining))
        self.used += len(value)
        if self.used > _MAX_HEADER_BYTES:
            raise ForwardCaptureHTTPError("CAPTURE_HTTP_HEADERS_TOO_LARGE")
        return value

    def close(self) -> None:
        self.original.close()

    def flush(self) -> None:
        self.original.flush()

    def read(self, count: int = -1) -> bytes:
        return self.original.read(count)

    def read1(self, count: int = -1) -> bytes:
        return cast(bytes, cast(Any, self.original).read1(count))


class _TiingoHTTPResponse(http.client.HTTPResponse):
    def begin(self) -> None:
        original = self.fp
        if original is None:
            raise ForwardCaptureHTTPError("CAPTURE_HTTP_RESPONSE_INVALID")
        if type(cast(object, original)) is not _HeaderStream:
            cast(Any, self).fp = _HeaderStream(original)
        super().begin()


def _resolve(output: queue.Queue[list[Any] | None]) -> None:
    try:
        output.put(socket.getaddrinfo("api.tiingo.com", 443, type=socket.SOCK_STREAM))
    except OSError:
        output.put(None)


def _expire(stream: socket.socket) -> None:
    with suppress(OSError):
        stream.shutdown(socket.SHUT_RDWR)


class _BoundRequest:
    def __init__(self, request: ForwardCaptureRequest, deadline_monotonic: float) -> None:
        if type(request) is not ForwardCaptureRequest:
            raise ForwardCaptureHTTPError("ORIGINAL_CAPTURE_HTTP_REQUEST_REQUIRED")
        request.__post_init__()
        if request.evidence_class != "provider_https_read":
            raise ForwardCaptureHTTPError("FIXTURE_CANNOT_CLAIM_PROVIDER_HTTP")
        if (
            type(deadline_monotonic) not in (float, int)
            or not math.isfinite(deadline_monotonic)
            or not 0 < deadline_monotonic - time.monotonic() <= _MAX_DEADLINE_SECONDS
        ):
            raise ForwardCaptureHTTPError("ORIGINAL_CAPTURE_HTTP_DEADLINE_REQUIRED")
        self._request = request
        self._request_sha256 = request.semantic_sha256
        self._deadline = deadline_monotonic
        self._original_deadline = deadline_monotonic
        self._path = request.path + "?" + urlencode(request.query)
        self._max_response_bytes = request.max_response_bytes
        self._http_request_sha256 = request.http_request_sha256

    def _require_original(self, request: ForwardCaptureRequest) -> None:
        if (
            request is not self._request
            or request.semantic_sha256 != self._request_sha256
            or self._deadline != self._original_deadline
            or request.path + "?" + urlencode(request.query) != self._path
            or request.max_response_bytes != self._max_response_bytes
            or request.http_request_sha256 != self._http_request_sha256
        ):
            raise ForwardCaptureHTTPError("ORIGINAL_CAPTURE_HTTP_REQUEST_REQUIRED")
        request.__post_init__()

    def _check(self, request: ForwardCaptureRequest, deadline_ms: int) -> float:
        self._require_original(request)
        if type(deadline_ms) is not int or not 0 < deadline_ms <= request.deadline_ms:
            raise ForwardCaptureHTTPError("ORIGINAL_CAPTURE_HTTP_REQUEST_REQUIRED")
        _remaining(self._deadline)
        return min(self._deadline, time.monotonic() + deadline_ms / 1000)

    def __reduce__(self) -> Any:
        raise TypeError("capture transport is process-local")


class TiingoForwardHTTPSGetTransport(_BoundRequest):
    """One original Tiingo request with bounded credential/DNS/TLS/header/body time."""

    def __init__(
        self,
        *,
        request: ForwardCaptureRequest,
        token_loader: Callable[[], str],
        deadline_monotonic: float,
    ) -> None:
        super().__init__(request, deadline_monotonic)
        if (
            request.kind != "daily"
            or request.source.provider != "tiingo"
            or not callable(token_loader)
        ):
            raise ForwardCaptureHTTPError("FIXED_TIINGO_DAILY_REQUEST_REQUIRED")
        self._token_loader = token_loader
        self._original_token_loader = token_loader
        self._used = False
        self._attempt_lock = threading.Lock()

    def __repr__(self) -> str:
        return "TiingoForwardHTTPSGetTransport(<private>)"

    def require_original_capture_binding(self, request: ForwardCaptureRequest) -> None:
        """Local binding check before or after use; no source authority or I/O."""
        self._require_original(request)
        if self._token_loader is not self._original_token_loader:
            raise ForwardCaptureHTTPError("ORIGINAL_CAPTURE_HTTP_REQUEST_REQUIRED")
        _remaining(self._deadline)

    def recheck_original_capture(self, request: ForwardCaptureRequest) -> None:
        """Extra local denial only; no token load, HTTP, or one-use reset."""
        self._require_original(request)
        if self._token_loader is not self._original_token_loader or not self._used:
            raise ForwardCaptureHTTPError("ORIGINAL_CAPTURE_HTTP_REQUEST_REQUIRED")
        _remaining(self._deadline)

    def _load_token(self, deadline: float) -> str:
        # A late credential read cannot dispatch HTTP. The daemon receives no
        # network transport and its result is discarded after cancellation.
        values: queue.Queue[str | None] = queue.Queue(maxsize=1)
        cancelled = threading.Event()
        loader = self._token_loader

        def load() -> None:
            try:
                value = loader()
                if not cancelled.is_set():
                    values.put(value if type(value) is str else None)
            except Exception:
                if not cancelled.is_set():
                    values.put(None)

        threading.Thread(target=load, daemon=True).start()
        try:
            token = values.get(timeout=_remaining(deadline))
        except queue.Empty:
            raise ForwardCaptureHTTPError("CAPTURE_HTTP_DEADLINE_EXCEEDED") from None
        finally:
            cancelled.set()
        if type(token) is not str or re.fullmatch(r"[A-Za-z0-9_-]{16,512}", token) is None:
            raise ForwardCaptureHTTPError("TIINGO_TOKEN_UNAVAILABLE")
        return token

    def get(self, request: ForwardCaptureRequest, *, deadline_ms: int) -> CaptureResponse:
        connection: http.client.HTTPSConnection | None = None
        response: http.client.HTTPResponse | None = None
        stream: socket.socket | None = None
        timer: threading.Timer | None = None
        try:
            deadline = self._check(request, deadline_ms)
            with self._attempt_lock:
                if self._used or self._token_loader is not self._original_token_loader:
                    raise ForwardCaptureHTTPError("CAPTURE_HTTP_ATTEMPT_ALREADY_USED")
                self._used = True
            token = self._load_token(deadline)
            self._require_original(request)
            _remaining(deadline)
            context = ssl.create_default_context()
            connection = http.client.HTTPSConnection(
                "api.tiingo.com", timeout=_remaining(deadline), context=context
            )
            connection.response_class = _TiingoHTTPResponse
            resolved: queue.Queue[list[Any] | None] = queue.Queue(maxsize=1)
            threading.Thread(target=_resolve, args=(resolved,), daemon=True).start()
            try:
                addresses = resolved.get(timeout=_remaining(deadline))
            except queue.Empty:
                raise ForwardCaptureHTTPError("CAPTURE_HTTP_DEADLINE_EXCEEDED") from None
            if not addresses:
                raise ForwardCaptureHTTPError("CAPTURE_HTTP_TRANSPORT_FAILED")
            for family, kind, protocol, _, address in addresses[:4]:
                raw = socket.socket(family, kind, protocol)
                try:
                    raw.settimeout(_remaining(deadline))
                    raw.connect(address)
                    raw.settimeout(_remaining(deadline))
                    stream = context.wrap_socket(raw, server_hostname="api.tiingo.com")
                    connection.sock = stream
                    break
                except OSError:
                    raw.close()
                except Exception:
                    raw.close()
                    raise
            if stream is None:
                raise ForwardCaptureHTTPError("CAPTURE_HTTP_TRANSPORT_FAILED")
            stream.settimeout(_remaining(deadline))
            timer = threading.Timer(_remaining(deadline), _expire, args=(stream,))
            timer.daemon = True
            timer.start()
            self._require_original(request)
            connection.request(
                "GET",
                self._path,
                headers={
                    "Authorization": "Token " + token,
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
            )
            del token
            response = connection.getresponse()
            if response.getheader("Content-Encoding", "identity").lower() != "identity":
                raise ForwardCaptureHTTPError("CAPTURE_HTTP_ENCODING_UNSUPPORTED")
            content_type = response.getheader("Content-Type", "")
            if len(content_type) > 256:
                raise ForwardCaptureHTTPError("CAPTURE_HTTP_MEDIA_TYPE_INVALID")
            chunks: list[bytes] = []
            length = 0
            while True:
                stream.settimeout(_remaining(deadline))
                chunk = response.read1(min(65536, self._max_response_bytes + 1 - length))
                if not chunk:
                    break
                length += len(chunk)
                if length > self._max_response_bytes:
                    raise ForwardCaptureHTTPError("CAPTURE_HTTP_RESPONSE_TOO_LARGE")
                chunks.append(chunk)
            _remaining(deadline)
            self._require_original(request)
            return CaptureResponse(
                self._http_request_sha256,
                response.status,
                content_type,
                b"".join(chunks),
                "provider_https_read",
            )
        except ForwardCaptureHTTPError:
            raise
        except Exception:
            raise ForwardCaptureHTTPError("CAPTURE_HTTP_TRANSPORT_FAILED") from None
        finally:
            if timer is not None:
                timer.cancel()
            cleanup_failed = False
            for item in (response, connection, stream):
                if item is not None:
                    try:
                        item.close()
                    except Exception:
                        cleanup_failed = True
            if cleanup_failed:
                raise ForwardCaptureHTTPError("CAPTURE_HTTP_CLEANUP_FAILED") from None


class EtradeForwardCaptureTransport(_BoundRequest):
    """Adapt one exact concrete session; no injected class label can promote data."""

    def __init__(
        self,
        *,
        request: ForwardCaptureRequest,
        session: EtradeReadOnlySession,
        deadline_monotonic: float,
    ) -> None:
        super().__init__(request, deadline_monotonic)
        if (
            request.kind != "quote"
            or request.source.provider != "etrade"
            or type(session) is not EtradeReadOnlySession
            or type(session.transport) is not EtradeHTTPSGetTransport
            or session.transport.evidence_class != "provider_https_read"
            or session.reference.environment.value != request.source.environment
        ):
            raise ForwardCaptureHTTPError("EXACT_ETRADE_CAPTURE_SESSION_REQUIRED")
        self._session = session
        self._original_session = session
        self._original = session.reference, session.store, session.transport
        self._reference_fields = (
            session.reference.environment,
            session.reference.uri,
            session.reference.version,
        )
        self._used = False
        self._attempt_lock = threading.Lock()

    def _require_session(self) -> None:
        reference = self._session.reference
        if (
            self._session is not self._original_session
            or self._session.transport.evidence_class != "provider_https_read"
            or (reference.environment, reference.uri, reference.version) != self._reference_fields
            or any(
                actual is not original
                for actual, original in zip(
                    (reference, self._session.store, self._session.transport),
                    self._original,
                    strict=True,
                )
            )
        ):
            raise ForwardCaptureHTTPError("ORIGINAL_ETRADE_CAPTURE_SESSION_REQUIRED")

    def recheck_original_capture(self, request: ForwardCaptureRequest) -> None:
        """Extra local denial only; no secret resolution, HTTP, or one-use reset."""
        self._require_original(request)
        self._require_session()
        if not self._used or self._session._closed:
            raise ForwardCaptureHTTPError("ORIGINAL_ETRADE_CAPTURE_SESSION_REQUIRED")
        _remaining(self._deadline)

    def require_original_capture_binding(self, request: ForwardCaptureRequest) -> None:
        """Local binding check before or after use; no source authority or I/O."""
        self._require_original(request)
        self._require_session()
        if self._session._closed:
            raise ForwardCaptureHTTPError("ORIGINAL_ETRADE_CAPTURE_SESSION_REQUIRED")
        _remaining(self._deadline)

    def get(self, request: ForwardCaptureRequest, *, deadline_ms: int) -> CaptureResponse:
        try:
            deadline = self._check(request, deadline_ms)
            with self._attempt_lock:
                self._require_session()
                if self._used:
                    raise ForwardCaptureHTTPError("ORIGINAL_ETRADE_CAPTURE_SESSION_REQUIRED")
                self._used = True
            result = self._session.read_quote_response(
                tuple(i.symbol for i in request.instruments),
                deadline_monotonic=deadline,
                max_response_bytes=self._max_response_bytes,
            )
            _remaining(deadline)
            self._require_original(request)
            self._require_session()
            if result.request_digest != self._http_request_sha256:
                raise ForwardCaptureHTTPError("CAPTURE_HTTP_REQUEST_BINDING_DIFFERS")
            return CaptureResponse(
                result.request_digest,
                result.status,
                result.content_type,
                result.body,
                "provider_https_read",
            )
        except ForwardCaptureHTTPError:
            raise
        except Exception:
            raise ForwardCaptureHTTPError("CAPTURE_HTTP_TRANSPORT_FAILED") from None
