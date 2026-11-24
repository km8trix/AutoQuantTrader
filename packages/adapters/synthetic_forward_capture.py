"""Finite modeled capture ports, without network or provider/clock authority.

Provider-shaped JSON remains synthetic evidence. The caller declares all samples,
bytes and provenance; the original collector retains its own real wall deadline.
These ports neither discover nor authenticate actual rights, currency or time.
"""

from datetime import datetime, timedelta

from packages.domain.forward_capture_contracts import (
    CaptureClockSample,
    CaptureResponse,
    CaptureVerification,
    ForwardCaptureRequest,
)
from packages.domain.personal_contracts import VersionPin, require_utc


class SyntheticForwardCaptureError(ValueError):
    """An explicit synthetic input, binding or finite script is invalid."""


class _SyntheticRequest:
    def __init__(self, request: ForwardCaptureRequest) -> None:
        if type(request) is not ForwardCaptureRequest:
            raise SyntheticForwardCaptureError("exact synthetic capture request required")
        request.__post_init__()
        if request.evidence_class != "synthetic_fixture":
            raise SyntheticForwardCaptureError("synthetic ports cannot supply provider evidence")
        self._request = request
        self._request_sha256 = request.semantic_sha256

    def _require_request(self, request: ForwardCaptureRequest) -> None:
        if type(request) is not ForwardCaptureRequest or request is not self._request:
            raise SyntheticForwardCaptureError("original synthetic request required")
        request.__post_init__()
        if (
            request.evidence_class != "synthetic_fixture"
            or request.semantic_sha256 != self._request_sha256
        ):
            raise SyntheticForwardCaptureError("original synthetic request changed")


def _require_sample(
    request: ForwardCaptureRequest,
    sample: CaptureClockSample,
    *,
    first: CaptureClockSample | None,
    previous: CaptureClockSample | None,
) -> None:
    if type(sample) is not CaptureClockSample:
        raise SyntheticForwardCaptureError("exact modeled clock sample required")
    sample.__post_init__()
    if not request.window_start <= sample.at < request.window_end:
        raise SyntheticForwardCaptureError("modeled sample is outside the capture window")
    if previous is not None and (
        sample.boot_id != previous.boot_id
        or sample.at < previous.at
        or sample.monotonic_ns < previous.monotonic_ns
    ):
        raise SyntheticForwardCaptureError("modeled clock moved backward or changed epoch")
    if first is not None and (
        not timedelta(0) <= sample.at - first.at < timedelta(milliseconds=request.deadline_ms)
        or not 0 <= sample.monotonic_ns - first.monotonic_ns < request.deadline_ms * 1_000_000
    ):
        raise SyntheticForwardCaptureError("modeled sample exhausted the capture deadline")


class SyntheticForwardCaptureClock(_SyntheticRequest):
    """Three declared capture samples; current_sample repeats the latest scalar view.

    The three stages are requested, received and validated, as required by the
    existing capture record. Current reads consume no sample and never advance
    time or extend a deadline. This is not a measurement of the host clock.
    """

    def __init__(
        self, request: ForwardCaptureRequest, *, samples: tuple[CaptureClockSample, ...]
    ) -> None:
        super().__init__(request)
        if type(samples) is not tuple or len(samples) != 3:
            raise SyntheticForwardCaptureError("exactly three modeled capture samples required")
        previous = None
        for sample in samples:
            _require_sample(request, sample, first=samples[0], previous=previous)
            previous = sample
        self._samples = samples
        self._next = 0

    def sample(self) -> CaptureClockSample:
        self._require_request(self._request)
        if self._next >= len(self._samples):
            raise SyntheticForwardCaptureError("modeled capture samples exhausted")
        sample = self._samples[self._next]
        _require_sample(
            self._request,
            sample,
            first=self._samples[0],
            previous=None if self._next == 0 else self._samples[self._next - 1],
        )
        self._next += 1
        return sample

    def current_sample(self) -> CaptureClockSample:
        self._require_request(self._request)
        if self._next == 0:
            raise SyntheticForwardCaptureError("no modeled capture sample has been issued")
        sample = self._samples[self._next - 1]
        _require_sample(self._request, sample, first=self._samples[0], previous=sample)
        return sample


class SyntheticForwardCaptureTransport(_SyntheticRequest):
    """Return one declared JSON byte response without waiting or performing I/O.

    The supplied remaining deadline must be positive and within the request's
    original limit. The collector separately enforces actual elapsed wall time.
    """

    def __init__(self, request: ForwardCaptureRequest, *, body: bytes) -> None:
        super().__init__(request)
        if type(body) is not bytes or not 0 < len(body) <= request.max_response_bytes:
            raise SyntheticForwardCaptureError("synthetic response bytes exceed request bounds")
        self._response = CaptureResponse(
            request.http_request_sha256, 200, "application/json", body, "synthetic_fixture"
        )
        self._used = False

    def get(self, request: ForwardCaptureRequest, *, deadline_ms: int) -> CaptureResponse:
        self._require_request(request)
        if type(deadline_ms) is not int or not 0 < deadline_ms <= request.deadline_ms:
            raise SyntheticForwardCaptureError("invalid remaining synthetic capture deadline")
        if self._used:
            raise SyntheticForwardCaptureError("synthetic response already consumed")
        if type(self._response) is not CaptureResponse:
            raise SyntheticForwardCaptureError("exact synthetic response required")
        self._response.__post_init__()
        if (
            self._response.request_sha256 != request.http_request_sha256
            or self._response.evidence_class != "synthetic_fixture"
            or not 0 < len(self._response.body) <= request.max_response_bytes
        ):
            raise SyntheticForwardCaptureError("synthetic response binding changed")
        self._used = True
        return self._response


class SyntheticForwardCaptureVerifier(_SyntheticRequest):
    """Check declared synthetic scope, never actual provider rights or clock health."""

    def __init__(
        self,
        request: ForwardCaptureRequest,
        *,
        producer: VersionPin,
        valid_until: datetime,
    ) -> None:
        super().__init__(request)
        if type(producer) is not VersionPin:
            raise SyntheticForwardCaptureError("exact synthetic verifier pin required")
        producer.__post_init__()
        require_utc(valid_until, "synthetic verification expiry")
        if not request.window_start < valid_until <= request.window_end:
            raise SyntheticForwardCaptureError("synthetic verification expiry exceeds window")
        self._producer = producer
        self._valid_until = valid_until
        self._first: CaptureClockSample | None = None
        self._latest: CaptureClockSample | None = None
        self._calls = 0

    def verify(
        self, request: ForwardCaptureRequest, sample: CaptureClockSample
    ) -> CaptureVerification:
        self._require_request(request)
        if self._calls >= 3:
            raise SyntheticForwardCaptureError("synthetic verification stages exhausted")
        _require_sample(request, sample, first=self._first, previous=self._latest)
        if sample.at >= self._valid_until:
            raise SyntheticForwardCaptureError("synthetic verification expired")
        source = request.source
        if (
            source.identity_reference is None
            or source.rights_reference is None
            or source.entitlement_reference is None
        ):
            raise SyntheticForwardCaptureError("synthetic source declarations are incomplete")
        proof = CaptureVerification(
            request.semantic_sha256,
            sample,
            self._valid_until,
            source.identity_reference,
            source.rights_reference,
            source.entitlement_reference,
            "synthetic-currency-USD/1",
            "synthetic-modeled-clock/1:" + sample.boot_id,
            self._producer,
            "synthetic_fixture",
        )
        proof.check(request, sample)
        if self._first is None:
            self._first = sample
        self._latest = sample
        self._calls += 1
        return proof
