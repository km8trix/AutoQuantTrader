"""Finite synthetic ports preserve the original collector's admission boundaries."""

from dataclasses import replace
from datetime import timedelta

import pytest

from packages.adapters.synthetic_forward_capture import (
    SyntheticForwardCaptureClock,
    SyntheticForwardCaptureError,
    SyntheticForwardCaptureTransport,
    SyntheticForwardCaptureVerifier,
)
from packages.application import personal_codec
from packages.application.personal_forward_capture import (
    ForwardCaptureError,
    capture_forward,
    replay_capture,
)
from packages.domain.forward_capture_contracts import (
    MAX_CAPTURE_BYTES,
    CaptureClockSample,
    CaptureResponse,
    CaptureVerification,
)
from packages.domain.forward_contracts import ForwardDataState
from packages.persistence.forward_capture_publication import SqlForwardCapturePublication
from tests.unit.test_personal_forward_capture import (
    AT,
    PIN,
    Journal,
    Objects,
    daily_body,
    quote_body,
    request,
)


def _samples(at=AT, milliseconds=(0, 100, 200)):
    return tuple(
        CaptureClockSample(
            at + timedelta(milliseconds=value), 1_000_000_000 + value * 1_000_000, "modeled-boot"
        )
        for value in milliseconds
    )


def _port(name, req):
    if name == "clock":
        return SyntheticForwardCaptureClock(req, samples=_samples())
    if name == "transport":
        return SyntheticForwardCaptureTransport(req, body=b"{}")
    return SyntheticForwardCaptureVerifier(req, producer=PIN, valid_until=AT + timedelta(seconds=1))


@pytest.mark.parametrize("port", ["clock", "transport", "verifier"])
@pytest.mark.parametrize("invalid", ["provider", "object", "none"])
def test_ports_require_exact_synthetic_requests(port, invalid):
    req = {
        "provider": request(evidence_class="provider_https_read"),
        "object": object(),
        "none": None,
    }[invalid]
    with pytest.raises(SyntheticForwardCaptureError):
        _port(port, req)


def test_clock_has_three_stages_and_current_reads_do_not_advance():
    req, samples = request(), _samples()
    clock = SyntheticForwardCaptureClock(req, samples=samples)
    with pytest.raises(SyntheticForwardCaptureError, match="no modeled"):
        clock.current_sample()
    for expected in samples:
        assert clock.sample() is expected
        assert clock.current_sample() is expected
        assert clock.current_sample() is expected
    with pytest.raises(SyntheticForwardCaptureError, match="exhausted"):
        clock.sample()
    assert clock.current_sample() is samples[-1]


@pytest.mark.parametrize("samples", [(), _samples()[:2], _samples() * 2, list(_samples())])
def test_clock_requires_the_fixed_three_sample_tuple(samples):
    with pytest.raises(SyntheticForwardCaptureError, match="exactly three"):
        SyntheticForwardCaptureClock(request(), samples=samples)


@pytest.mark.parametrize(
    "change",
    ["utc_back", "monotonic_back", "epoch", "utc_deadline", "monotonic_deadline", "window"],
)
def test_clock_rejects_backward_epoch_window_and_deadline_scripts(change):
    req = request()
    first, middle, last = _samples()
    if change == "utc_back":
        last = replace(last, at=first.at)
    elif change == "monotonic_back":
        last = replace(last, monotonic_ns=first.monotonic_ns)
    elif change == "epoch":
        last = replace(last, boot_id="different-model")
    elif change == "utc_deadline":
        last = replace(last, at=first.at + timedelta(milliseconds=req.deadline_ms))
    elif change == "monotonic_deadline":
        last = replace(last, monotonic_ns=first.monotonic_ns + req.deadline_ms * 1_000_000)
    else:
        last = replace(last, at=req.window_end)
    with pytest.raises(SyntheticForwardCaptureError):
        SyntheticForwardCaptureClock(req, samples=(first, middle, last))


@pytest.mark.parametrize("value", [True, -1, 2**63, 1.0])
def test_clock_revalidates_native_monotonic_bounds(value):
    samples = _samples()
    object.__setattr__(samples[1], "monotonic_ns", value)
    with pytest.raises(ValueError):
        SyntheticForwardCaptureClock(request(), samples=samples)


def test_clock_rejects_wrong_sample_type_and_mutated_issued_sample():
    req, samples = request(), _samples()
    with pytest.raises(SyntheticForwardCaptureError, match="exact modeled"):
        SyntheticForwardCaptureClock(req, samples=(samples[0], object(), samples[2]))
    clock = SyntheticForwardCaptureClock(req, samples=samples)
    assert clock.sample() is samples[0]
    object.__setattr__(samples[0], "at", req.window_end)
    with pytest.raises(SyntheticForwardCaptureError, match="window"):
        clock.current_sample()


@pytest.mark.parametrize(
    "body", [b"", bytearray(b"{}"), "{}", None, b"x" * (MAX_CAPTURE_BYTES + 1)]
)
def test_transport_rejects_nonbytes_empty_and_oversize_bodies(body):
    with pytest.raises(SyntheticForwardCaptureError, match="bytes"):
        SyntheticForwardCaptureTransport(request(), body=body)


def test_transport_respects_the_request_byte_bound_and_has_one_response():
    req = request(max_response_bytes=2)
    with pytest.raises(SyntheticForwardCaptureError, match="bounds"):
        SyntheticForwardCaptureTransport(req, body=b"xxx")
    transport = SyntheticForwardCaptureTransport(req, body=b"{}")
    response = transport.get(req, deadline_ms=1)
    assert type(response) is CaptureResponse
    assert response.body == b"{}" and response.status == 200
    assert response.request_sha256 == req.http_request_sha256
    assert response.evidence_class == "synthetic_fixture"
    assert response.content_type == "application/json"
    with pytest.raises(SyntheticForwardCaptureError, match="consumed"):
        transport.get(req, deadline_ms=1)


@pytest.mark.parametrize("deadline", [True, False, 0, -1, 3001, 1.0, None])
def test_invalid_remaining_deadline_does_not_consume_response(deadline):
    req = request()
    transport = SyntheticForwardCaptureTransport(req, body=b"{}")
    with pytest.raises(SyntheticForwardCaptureError, match="deadline"):
        transport.get(req, deadline_ms=deadline)
    assert transport.get(req, deadline_ms=req.deadline_ms).body == b"{}"


@pytest.mark.parametrize("changed", [False, True])
def test_transport_and_verifier_reject_another_request_even_with_same_http_scope(changed):
    req = request()
    other = replace(req, capture_id="another-capture") if changed else replace(req)
    assert other.http_request_sha256 == req.http_request_sha256
    transport = SyntheticForwardCaptureTransport(req, body=b"{}")
    verifier = SyntheticForwardCaptureVerifier(
        req, producer=PIN, valid_until=AT + timedelta(seconds=1)
    )
    with pytest.raises(SyntheticForwardCaptureError, match="original"):
        transport.get(other, deadline_ms=1)
    with pytest.raises(SyntheticForwardCaptureError, match="original"):
        verifier.verify(other, _samples()[0])
    assert transport.get(req, deadline_ms=1).body == b"{}"
    assert verifier.verify(req, _samples()[0]).evidence_class == "synthetic_fixture"


@pytest.mark.parametrize("port", ["clock", "transport", "verifier"])
@pytest.mark.parametrize("field,value", [("deadline_ms", True), ("max_response_bytes", True)])
def test_ports_revalidate_request_native_integer_fields(port, field, value):
    req = request()
    object.__setattr__(req, field, value)
    with pytest.raises(ValueError):
        _port(port, req)


def test_verifier_has_fixed_synthetic_expiry_and_never_extends_it():
    req, samples = request(), _samples()
    until = AT + timedelta(seconds=1)
    verifier = SyntheticForwardCaptureVerifier(req, producer=PIN, valid_until=until)
    for sample in samples:
        proof = verifier.verify(req, sample)
        assert type(proof) is CaptureVerification
        assert proof.sample is sample and proof.producer is PIN
        assert proof.valid_until == until
        assert proof.evidence_class == "synthetic_fixture"
        assert proof.request_sha256 == req.semantic_sha256
        assert proof.currency_reference.startswith("synthetic-")
        assert proof.clock_reference.startswith("synthetic-")
        proof.check(req, sample)
    with pytest.raises(SyntheticForwardCaptureError, match="exhausted"):
        verifier.verify(req, samples[-1])


@pytest.mark.parametrize("invalid", ["pin", "naive", "before", "after", "expired"])
def test_verifier_rejects_invalid_pin_or_expiry(invalid):
    req = request()
    pin = object() if invalid == "pin" else PIN
    until = {
        "pin": AT + timedelta(seconds=1),
        "naive": AT.replace(tzinfo=None),
        "before": req.window_start,
        "after": req.window_end + timedelta(microseconds=1),
        "expired": AT,
    }[invalid]
    with pytest.raises(ValueError):
        verifier = SyntheticForwardCaptureVerifier(req, producer=pin, valid_until=until)
        verifier.verify(req, _samples()[0])


@pytest.mark.parametrize("change", ["rights", "entitlement", "identity"])
def test_verifier_does_not_upgrade_unavailable_source_declarations(change):
    req = request()
    source = replace(
        req.source,
        **{
            "rights": {"rights_status": "denied"},
            "entitlement": {"entitlement_status": "delayed"},
            "identity": {"identity_reference": None},
        }[change],
    )
    req = replace(
        req,
        source=source,
        journal_key=replace(req.journal_key, source_scope_sha256=source.semantic_sha256),
    )
    verifier = SyntheticForwardCaptureVerifier(
        req, producer=PIN, valid_until=AT + timedelta(seconds=1)
    )
    with pytest.raises(ValueError):
        verifier.verify(req, _samples()[0])


def test_verifier_checks_sequence_deadline_and_exact_sample_type_without_consuming_on_error():
    req, samples = request(), _samples()
    verifier = SyntheticForwardCaptureVerifier(req, producer=PIN, valid_until=req.window_end)
    assert verifier.verify(req, samples[1]).sample is samples[1]
    for invalid in (
        samples[0],
        object(),
        replace(samples[2], boot_id="different"),
        replace(samples[2], at=samples[1].at + timedelta(milliseconds=req.deadline_ms)),
        replace(samples[2], monotonic_ns=samples[1].monotonic_ns + req.deadline_ms * 1_000_000),
    ):
        with pytest.raises(ValueError):
            verifier.verify(req, invalid)
    assert verifier.verify(req, samples[2]).sample is samples[2]


@pytest.mark.parametrize("kind", ["daily", "quote"])
def test_original_capture_collects_and_replays_the_synthetic_ports(kind):
    req = request(kind)
    at = AT if kind == "quote" else AT.replace(hour=20, minute=1)
    samples = _samples(at)
    clock = SyntheticForwardCaptureClock(req, samples=samples)
    body = quote_body() if kind == "quote" else daily_body()
    transport = SyntheticForwardCaptureTransport(req, body=body)
    verifier = SyntheticForwardCaptureVerifier(req, producer=PIN, valid_until=req.window_end)
    journal, objects = Journal(req.journal_key), Objects()
    try:
        state = ForwardDataState((req.source,), "recorded")
        publication = capture_forward(
            req,
            state,
            expected_head=journal.head,
            clock=clock,
            verifier=verifier,
            transport=transport,
            journal=journal.real,
            publisher=SqlForwardCapturePublication(journal.engine, journal=journal.real),
            artifacts=objects,
            codec=personal_codec,
        )
        assert publication.record.live_authorized is False
        assert publication.record.request.evidence_class == "synthetic_fixture"
        assert publication.record.receipt.requested_at == samples[0].at
        assert publication.record.receipt.received_at == samples[1].at
        assert publication.record.receipt.validated_at == samples[2].at
        assert objects.read(publication.record.raw_object) == body
        assert len(journal.entries) == 1
        assert "SYNTHETIC_TRANSPORT_NOT_PROVIDER_EVIDENCE" in publication.record.limitations
        replayed = replay_capture(publication.record, state, artifacts=objects)
        assert replayed.observations == publication.record.observations
    finally:
        journal.engine.dispose()


def test_original_collector_still_rejects_genuine_source_bridge():
    req = request(evidence_class="provider_https_read")
    journal, objects = Journal(req.journal_key), Objects()
    try:
        with pytest.raises(ForwardCaptureError, match="CAPTURE_GENUINE_SOURCE_BRIDGE_REQUIRED"):
            capture_forward(
                req,
                ForwardDataState((req.source,), "recorded"),
                expected_head=journal.head,
                clock=object(),
                verifier=object(),
                transport=object(),
                journal=journal.real,
                artifacts=objects,
                codec=personal_codec,
            )
        assert not journal.entries and objects.writes == 0
    finally:
        journal.engine.dispose()
