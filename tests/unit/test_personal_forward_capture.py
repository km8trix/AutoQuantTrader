"""Provider-shaped synthetic contracts only: no network or authentication claim."""

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from weakref import finalize

import pytest

from packages.adapters.broker.etrade import EtradeEnvironment
from packages.adapters.broker.etrade_quotes import EtradeQuoteError, parse_etrade_quotes
from packages.adapters.broker.etrade_readonly import (
    EtradeReadError,
    EtradeReadOperation,
    EtradeReadRequest,
)
from packages.application import personal_codec
from packages.application.personal_forward_capture import (
    ForwardCaptureError,
    capture_forward,
    read_capture,
    replay_capture,
)
from packages.domain.durable_journal_contracts import (
    JournalKey,
)
from packages.domain.forward_capture_contracts import (
    CAPTURE_SCHEMA,
    MAX_CAPTURE_BYTES,
    CaptureClockSample,
    CaptureInstrument,
    CaptureResponse,
    CaptureVerification,
    ForwardCaptureRecord,
    ForwardCaptureRequest,
)
from packages.domain.forward_contracts import ForwardDataState, ForwardSource
from packages.domain.personal_contracts import VersionPin
from packages.domain.research_job_contracts import ObjectRef
from packages.persistence.database import create_database_engine
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.durable_journal_schema import JOURNAL_TABLES
from packages.persistence.forward_capture_publication import SqlForwardCapturePublication
from packages.persistence.schema import metadata

AT = datetime(2026, 9, 9, 13, 35, tzinfo=UTC)
PIN = VersionPin("fixture-only-capture", "1", "a" * 64)


def request(kind="quote", capture_id="capture-1", **changes):
    source = ForwardSource(
        "fixture-shaped-" + kind,
        "etrade" if kind == "quote" else "tiingo",
        "production",
        "synthetic-contract-account",
        "identity-ref",
        "allowed",
        "rights-ref",
        "realtime" if kind == "quote" else "not_required",
        "entitlement-ref",
    )
    value = ForwardCaptureRequest(
        capture_id,
        source,
        kind,
        (CaptureInstrument("spy", "SPY", "USD", "instrument-ref"),),
        AT.date(),
        AT.replace(hour=13, minute=30),
        AT.replace(hour=20, minute=0),
        AT.replace(hour=13, minute=0),
        AT.replace(hour=23, minute=0),
        PIN,
        PIN,
        JournalKey(
            "capture",
            "fixture-stream-" + kind,
            source.account_scope,
            source.provider,
            source.environment,
            source.semantic_sha256,
        ),
        "synthetic_fixture",
    )
    return replace(value, **changes)


def quote_body(**changes):
    quote = {
        "Product": {"symbol": "SPY", "securityType": "EQ"},
        "dateTimeUTC": int(AT.timestamp()),
        "quoteStatus": "REALTIME",
        "All": {
            "bid": 99,
            "ask": 100,
            "bidTime": "09:35:00 EDT 09-09-2026",
            "askTime": "09:35:00 EDT 09-09-2026",
        },
    }
    quote.update(changes)
    return json.dumps({"QuoteResponse": {"QuoteData": [quote]}}).encode()


def daily_body(**changes):
    row = {
        "date": "2026-09-09T00:00:00.000Z",
        "open": 99,
        "high": 101,
        "low": 98,
        "close": 100,
        "volume": 10000,
        "adjOpen": 49.5,
        "adjHigh": 50.5,
        "adjLow": 49,
        "adjClose": 50,
        "adjVolume": 20000,
        "divCash": 0,
        "splitFactor": 1,
    }
    row.update(changes)
    return json.dumps([row]).encode()


class Clock:
    def __init__(self, at=AT, samples=None):
        self.samples = iter(
            samples
            or [
                CaptureClockSample(
                    at + timedelta(milliseconds=n), 1000000000 + n * 1000000, "fixture-boot"
                )
                for n in (0, 100, 200)
            ]
        )
        self.calls = 0

    def sample(self):
        self.calls += 1
        self.latest = next(self.samples)
        return self.latest

    def current_sample(self):
        return self.latest

    def advance(self, *, milliseconds):
        self.latest = replace(
            self.latest,
            at=self.latest.at + timedelta(milliseconds=milliseconds),
            monotonic_ns=self.latest.monotonic_ns + milliseconds * 1_000_000,
        )


class Verifier:
    def __init__(self):
        self.calls = []
        self.fail_at = None
        self.change = {}

    def verify(self, req, sample):
        self.calls.append(sample)
        if len(self.calls) == self.fail_at:
            raise ValueError("review-only-private-verifier-sentinel")
        return replace(
            CaptureVerification(
                req.semantic_sha256,
                sample,
                sample.at + timedelta(seconds=30),
                "identity-ref",
                "rights-ref",
                "entitlement-ref",
                "verified-instrument-currency-ref",
                "verified-clock-measurement-ref",
                PIN,
                "synthetic_fixture",
            ),
            **self.change,
        )


class Transport:
    def __init__(self, body=None):
        self.body = quote_body() if body is None else body
        self.calls = 0
        self.change = {}

    def get(self, req, *, deadline_ms):
        self.calls += 1
        assert deadline_ms <= 3000
        return replace(
            CaptureResponse(
                req.http_request_sha256, 200, "application/json", self.body, "synthetic_fixture"
            ),
            **self.change,
        )


class Objects:
    def __init__(self):
        self.objects = {}
        self.writes = 0

    def put(self, payload, *, codec_version="personal-record/1", max_bytes=MAX_CAPTURE_BYTES):
        self.writes += 1
        assert len(payload) <= max_bytes
        ref = ObjectRef(hashlib.sha256(payload).hexdigest(), len(payload), codec_version)
        self.objects[ref.object_sha256] = payload
        return ref

    def read(self, reference, *, max_bytes=MAX_CAPTURE_BYTES):
        assert reference.byte_count <= max_bytes
        return self.objects[reference.object_sha256]


class Journal:
    def __init__(self, key):
        self.key = key
        self.engine = create_database_engine("sqlite+pysqlite:///:memory:")
        finalize(self, self.engine.dispose)
        metadata.create_all(self.engine, tables=JOURNAL_TABLES)
        self.real = SqlDurableJournal(
            self.engine, codec=personal_codec, record_types={CAPTURE_SCHEMA: ForwardCaptureRecord}
        )

    @property
    def head(self):
        return self.real.read_head(self.key)

    @property
    def entries(self):
        return self.real.read_page(self.key, through_head=self.head).entries

    def read_receipt(self, key, command_id):
        return self.real.read_receipt(key, command_id)

    def read_page(self, key, *, through_head, after_head=None, limit=256):
        return self.real.read_page(
            key, through_head=through_head, after_head=after_head, limit=limit
        )


class Harness:
    def __init__(self, req=None):
        self.request = request() if req is None else req
        self.state = ForwardDataState((self.request.source,), "recorded")
        at = AT if self.request.kind == "quote" else AT.replace(hour=20, minute=1)
        self.clock, self.verifier = Clock(at), Verifier()
        self.transport = Transport(quote_body() if self.request.kind == "quote" else daily_body())
        self.objects, self.journal = Objects(), Journal(self.request.journal_key)
        self.publisher = SqlForwardCapturePublication(
            self.journal.engine, journal=self.journal.real
        )

    def capture(self, req=None):
        return capture_forward(
            self.request if req is None else req,
            self.state,
            expected_head=self.journal.head,
            clock=self.clock,
            verifier=self.verifier,
            transport=self.transport,
            journal=self.journal.real,
            publisher=self.publisher,
            artifacts=self.objects,
            codec=personal_codec,
        )


def test_actual_receipt_boundaries_raw_bytes_and_fixture_label_survive_replay():
    h = Harness()
    pub = h.capture()
    record = pub.record
    assert record.raw_object.codec_version == "personal-provider-json/1"
    assert h.objects.read(record.raw_object) == quote_body()
    assert record.receipt.requested_at == AT
    assert record.receipt.received_at == AT + timedelta(milliseconds=100)
    assert record.receipt.validated_at == AT + timedelta(milliseconds=200)
    assert record.receipt.validated_monotonic_ns == 1200000000
    assert record.request.evidence_class == "synthetic_fixture" and not record.live_authorized
    assert "SYNTHETIC_TRANSPORT_NOT_PROVIDER_EVIDENCE" in record.limitations
    assert all(o.source_sequence is None for o in record.observations)
    replayed = replay_capture(record, h.state, artifacts=h.objects)
    assert replayed.observations == record.observations
    assert h.transport.calls == 1 and len(h.verifier.calls) == 3
    assert (
        read_capture(h.request, journal=h.journal, artifacts=h.objects, codec=personal_codec) == pub
    )


def test_tiingo_exact_raw_and_adjusted_close_remain_distinct_and_receipt_is_actual():
    h = Harness(request("daily"))
    record = h.capture().record
    daily = record.observations[0].payload
    assert (daily.open_price, daily.close_price, daily.adjusted_close) == (99, 100, 50)
    assert record.observations[0].known_at.hour == 20
    assert "VENDOR_PUBLICATION_TIME_UNAVAILABLE" in record.limitations
    assert replay_capture(record, h.state, artifacts=h.objects).observations == record.observations


@pytest.mark.parametrize("stage", [1, 2, 3])
def test_verification_failure_never_retains_raw_bytes_or_private_diagnostics(stage):
    h = Harness()
    h.verifier.fail_at = stage
    with pytest.raises(ForwardCaptureError) as error:
        h.capture()
    assert "private" not in str(error.value)
    assert h.transport.calls == (0 if stage == 1 else 1)
    assert h.objects.writes == 0 and not h.journal.entries


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_sha256", "c" * 64),
        ("identity_reference", "wrong"),
        ("rights_reference", "wrong"),
        ("entitlement_reference", "wrong"),
        ("evidence_class", "provider_https_read"),
    ],
)
def test_unverified_or_mismatched_source_cannot_fetch(field, value):
    h = Harness()
    h.verifier.change[field] = value
    with pytest.raises(ForwardCaptureError):
        h.capture()
    assert h.transport.calls == 0 and h.objects.writes == 0


@pytest.mark.parametrize(
    "change",
    [
        {"rights_status": "unknown"},
        {"identity_reference": None},
        {"entitlement_status": "delayed"},
        {"rights_reference": None},
    ],
)
def test_unknown_source_gates_are_not_defaults(change):
    req = request()
    source = replace(req.source, **change)
    req = replace(
        req,
        source=source,
        journal_key=replace(req.journal_key, source_scope_sha256=source.semantic_sha256),
    )
    h = Harness(req)
    with pytest.raises(ForwardCaptureError):
        h.capture()
    assert not h.transport.calls and not h.objects.writes


@pytest.mark.parametrize(
    "field,value",
    [
        ("status", 204),
        ("status", 429),
        ("content_type", "text/html"),
        ("request_sha256", "0" * 64),
        ("evidence_class", "provider_https_read"),
        ("body", b""),
    ],
)
def test_failed_or_wrong_response_has_no_success_receipt(field, value):
    h = Harness()
    h.transport.change[field] = value
    with pytest.raises(ForwardCaptureError):
        h.capture()
    assert h.objects.writes == 0 and not h.journal.entries


@pytest.mark.parametrize(
    "which", ["utc-regression", "mono-regression", "boot-change", "deadline", "window"]
)
def test_actual_clock_boundaries_fail_closed(which):
    samples = [
        CaptureClockSample(AT + timedelta(milliseconds=n), 1000000000 + n * 1000000, "boot")
        for n in (0, 100, 200)
    ]
    if which == "utc-regression":
        samples[1] = replace(samples[1], at=AT - timedelta(seconds=1))
    if which == "mono-regression":
        samples[1] = replace(samples[1], monotonic_ns=0)
    if which == "boot-change":
        samples[2] = replace(samples[2], boot_id="different-boot")
    if which == "deadline":
        samples[2] = replace(samples[2], at=AT + timedelta(seconds=3), monotonic_ns=4000000000)
    if which == "window":
        samples[0] = replace(samples[0], at=request().window_end)
    h = Harness()
    h.clock = Clock(samples=samples)
    with pytest.raises(ForwardCaptureError):
        h.capture()
    assert h.objects.writes == 0 and not h.journal.entries


def test_wrapper_timestamp_cannot_refresh_an_old_or_unknown_quote_side():
    body = quote_body(
        All={"bid": 99, "ask": 100, "bidTime": "09:34:00 EDT 09-09-2026", "askTime": "n/a"}
    )
    quote = parse_etrade_quotes(body, request())[0]
    assert quote.source_at == AT and quote.bid_at == AT - timedelta(minutes=1)
    assert quote.ask_at is None and quote.time_basis == "unknown"


@pytest.mark.parametrize("status", ["EH_REALTIME", "CLOSING", "INVALID", None])
def test_unreviewed_quote_status_never_becomes_realtime(status):
    assert (
        parse_etrade_quotes(quote_body(quoteStatus=status), request())[0].delay_status == "unknown"
    )


@pytest.mark.parametrize(
    "value",
    ["09:35:00 EST 09-09-2026", "2026-09-09T13:35:00Z", "09:35:00 UNKNOWN 09-09-2026", None],
)
def test_side_time_parser_does_not_infer_timezone_or_format(value):
    quote = parse_etrade_quotes(
        quote_body(All={"bid": 99, "ask": 100, "bidTime": value, "askTime": value}), request()
    )[0]
    assert quote.bid_at is None and quote.ask_at is None


@pytest.mark.parametrize(
    "body",
    [
        b'{"QuoteResponse":{},"QuoteResponse":{}}',
        b'{"token":"fixture-secret"}',
        b'{"QuoteResponse":{"QuoteData":[],"Messages":{}}}',
        quote_body(Product={"symbol": "SPY", "securityType": "OPTN"}),
        quote_body(All={"bid": 101, "ask": 100}),
        b"{}",
        b"{",
        b"[]",
    ],
)
def test_quote_parse_rejects_ambiguous_products_and_secret_fields(body):
    with pytest.raises(EtradeQuoteError):
        parse_etrade_quotes(body, request())


@pytest.mark.parametrize("change", [{"divCash": 1}, {"splitFactor": 2}])
def test_daily_actions_require_separate_mapping_and_are_not_silently_dropped(change):
    h = Harness(request("daily"))
    h.transport.body = daily_body(**change)
    with pytest.raises(ForwardCaptureError, match="DAILY_ACTION_MAPPING_REQUIRED"):
        h.capture()
    assert h.objects.writes == 0


def test_exact_retry_after_later_capture_never_fetches_again():
    h = Harness()
    original = h.capture()
    h.state = replay_capture(original.record, h.state, artifacts=h.objects)
    h.clock = Clock(AT + timedelta(seconds=1))
    h.capture(replace(h.request, capture_id="capture-2"))
    h.verifier.fail_at = len(h.verifier.calls) + 1
    assert h.capture() == original
    assert h.transport.calls == 2
    with pytest.raises(ForwardCaptureError, match="CAPTURE_ID_CONFLICT"):
        h.capture(replace(h.request, deadline_ms=2999))


def test_daily_revisions_bind_actual_prior_capture_and_replay():
    h = Harness(request("daily"))
    first = h.capture()
    h.state = replay_capture(first.record, h.state, artifacts=h.objects)
    h.clock = Clock(AT.replace(hour=20, minute=2))
    h.transport.body = daily_body(close=101, adjClose=50)
    second = h.capture(replace(h.request, capture_id="daily-2"))
    observation = second.record.observations[0]
    assert (
        observation.revision == 2
        and observation.predecessor_id == first.record.observations[0].observation_id
    )
    assert observation.payload.predecessor_revision_id == observation.predecessor_id
    assert len(replay_capture(second.record, h.state, artifacts=h.objects).observations) == 2


def test_quote_request_is_exact_bounded_and_account_requests_are_unchanged():
    req = EtradeReadRequest(
        EtradeEnvironment.PRODUCTION,
        EtradeReadOperation.QUOTES,
        query=(("detailFlag", "ALL"),),
        symbols=("SPY",),
    )
    assert req.path == "/v1/market/quote/SPY" and req.digest == request().http_request_sha256
    assert (
        EtradeReadRequest(EtradeEnvironment.PRODUCTION, EtradeReadOperation.ACCOUNTS).path
        == "/v1/accounts/list"
    )
    for symbols in ((), ("SPY", "SPY"), ("SPY", "DIA"), ("SPY/../orders",), ("AAPL",)):
        with pytest.raises(EtradeReadError):
            replace(req, symbols=symbols)
    with pytest.raises(EtradeReadError):
        replace(req, query=(("detailFlag", "INTRADAY"),))
    with pytest.raises(EtradeReadError):
        EtradeReadRequest(
            EtradeEnvironment.PRODUCTION, EtradeReadOperation.ACCOUNTS, symbols=("SPY",)
        )


def test_existing_session_quote_path_retains_bytes_and_shared_budget():
    from tests.unit.test_etrade_session import setup

    session, _, store, transport, journal = setup()
    transport.payloads["quotes"] = json.loads(quote_body())
    response = session.read_quote_response(("SPY",))
    assert response.body == quote_body()
    assert journal.pages[-1][1] == response.body
    assert transport.requests[-1].path == "/v1/market/quote/SPY"
    with pytest.raises(EtradeReadError, match="CREDENTIALS_CLOSED"):
        store.resolved[-1]._value("access_token")
    for _ in range(9):
        session.discover_accounts()
    with pytest.raises(EtradeReadError, match="LOCAL_READ_BUDGET_EXHAUSTED"):
        session.read_quote_response(("SPY",))
    assert len(transport.requests) == 10


def test_provider_response_order_normalizes_to_exact_four_instrument_coverage():
    req = request(
        instruments=tuple(
            CaptureInstrument(s.lower(), s, "USD", f"identity-{s}")
            for s in ("DIA", "IWM", "QQQ", "SPY")
        )
    )
    rows = [
        json.loads(quote_body(Product={"symbol": i.symbol, "securityType": "EQ"}))["QuoteResponse"][
            "QuoteData"
        ][0]
        for i in reversed(req.instruments)
    ]
    h = Harness(req)
    h.transport.body = json.dumps({"QuoteResponse": {"QuoteData": rows}}).encode()
    record = h.capture().record
    assert tuple(o.payload.symbol for o in record.observations) == ("DIA", "IWM", "QQQ", "SPY")
    assert record.request.path == "/v1/market/quote/DIA,IWM,QQQ,SPY"


def test_request_size_limit_and_missing_currency_are_fail_closed():
    h = Harness(request(max_response_bytes=20))
    with pytest.raises(ForwardCaptureError):
        h.capture()
    assert h.objects.writes == 0
    with pytest.raises(ValueError):
        CaptureInstrument("spy", "SPY", None, "id")
    with pytest.raises(ValueError):
        request(deadline_ms=3001)
    with pytest.raises(ValueError):
        request(max_response_bytes=MAX_CAPTURE_BYTES + 1)


def test_later_captured_daily_revision_never_reopens_a_closed_frontier():
    from packages.application.personal_forward_data import close_frontier
    from packages.domain.forward_contracts import ForwardRequirement

    h = Harness(request("daily"))
    first = h.capture()
    h.state = replay_capture(first.record, h.state, artifacts=h.objects)
    required = ForwardRequirement(h.request.source.source_id, "spy", "SPY", AT.date(), "daily")
    h.state = close_frontier(
        h.state,
        frontier_id="decision",
        requirements=(required,),
        cutoff=AT.replace(hour=20, minute=2),
        closed_at=AT.replace(hour=20, minute=1, second=1),
    ).state
    closed = h.state.frontiers
    h.clock = Clock(AT.replace(hour=20, minute=3))
    h.transport.body = daily_body(close=101)
    later = h.capture(replace(h.request, capture_id="late-after-closure"))
    replayed = replay_capture(later.record, h.state, artifacts=h.objects)
    assert replayed.frontiers == closed
    assert closed[0].selected[0][1] == first.record.observations[0].observation_id
    assert len(replayed.observations) == 2


@pytest.mark.parametrize(
    "status,code",
    [
        (204, "UNDOCUMENTED_EMPTY_RESPONSE"),
        (401, "AUTHENTICATION_REJECTED"),
        (429, "PROVIDER_THROTTLED"),
    ],
)
def test_quote_session_preserves_failure_and_secret_journal_behavior(status, code):
    from tests.unit.test_etrade_session import setup

    session, _, _, transport, journal = setup()
    transport.payloads["quotes"] = json.loads(quote_body())
    transport.status = status
    with pytest.raises(EtradeReadError, match=code):
        session.read_quote_response(("SPY",))
    assert journal.pages[-1][1] is None and journal.pages[-1][0].body_digest is None


def test_quote_admission_failure_does_not_resolve_credentials():
    from tests.unit.test_etrade_session import setup

    session, _, store, transport, _ = setup()
    with pytest.raises(EtradeReadError):
        session.read_quote_response(("AAPL",))
    assert not store.count and not transport.requests


def test_new_raw_codec_is_rejected_by_existing_report_publication():
    from packages.domain.research_job_contracts import ResearchPublication

    raw = ObjectRef("c" * 64, 10, "personal-provider-json/1")
    with pytest.raises(ValueError, match="typed record codec"):
        ResearchPublication(
            "a" * 64, "run-" + "b" * 64, "c" * 64, "completed", "d" * 64, "e" * 64, "f" * 64, raw
        )


def test_forged_journal_committed_head_is_not_accepted_as_publication():
    h = Harness()
    real = h.journal.real.append_in_transaction

    def wrong_head(*args):
        receipt = real(*args)
        return replace(
            receipt, committed_head=replace(receipt.committed_head, entry_sha256="e" * 64)
        )

    h.journal.real.append_in_transaction = wrong_head
    h.publisher = SqlForwardCapturePublication(h.journal.engine, journal=h.journal.real)
    with pytest.raises(ForwardCaptureError, match="JOURNAL_BINDING_DIFFERS"):
        h.capture()
