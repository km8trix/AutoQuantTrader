"""Bounded capture ports and receipts; declarations never confer provider authority."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import ClassVar, Literal, Protocol

from packages.domain.durable_journal_contracts import (
    JournalAppend,
    JournalHead,
    JournalKey,
    JournalPage,
    JournalReceipt,
)
from packages.domain.forward_contracts import CaptureReceipt, ForwardObservation, ForwardSource
from packages.domain.personal_contracts import (
    ContractRecord,
    VersionPin,
    require_digest,
    require_text,
)
from packages.domain.research_job_contracts import ObjectRef

MAX_CAPTURE_BYTES = 2 * 1024 * 1024
CAPTURE_SCHEMA = "personal-forward-capture/1"
type CaptureEvidenceClass = Literal["provider_https_read", "synthetic_fixture"]


class CaptureRecord(ContractRecord):
    __slots__ = ()
    contract_version: ClassVar[str] = CAPTURE_SCHEMA


@dataclass(frozen=True, slots=True)
class CaptureInstrument(CaptureRecord):
    instrument_id: str
    symbol: Literal["DIA", "IWM", "QQQ", "SPY"]
    currency: Literal["USD"]
    identity_reference: str

    def __post_init__(self) -> None:
        super(CaptureInstrument, self).__post_init__()
        require_text(self.instrument_id, "instrument identity")
        require_text(self.identity_reference, "instrument identity reference")


@dataclass(frozen=True, slots=True)
class CaptureClockSample(CaptureRecord):
    at: datetime
    monotonic_ns: int
    boot_id: str

    def __post_init__(self) -> None:
        super(CaptureClockSample, self).__post_init__()
        require_text(self.boot_id, "actual boot identity")
        if not 0 <= self.monotonic_ns < 2**63:
            raise ValueError("capture monotonic clock is outside bounds")


@dataclass(frozen=True, slots=True)
class ForwardCaptureRequest(CaptureRecord):
    capture_id: str
    source: ForwardSource
    kind: Literal["daily", "quote"]
    instruments: tuple[CaptureInstrument, ...]
    session: date
    session_open: datetime
    session_close: datetime
    window_start: datetime
    window_end: datetime
    calendar: VersionPin
    producer: VersionPin
    journal_key: JournalKey
    evidence_class: CaptureEvidenceClass
    max_response_bytes: int = MAX_CAPTURE_BYTES
    deadline_ms: int = 3000

    def __post_init__(self) -> None:
        super(ForwardCaptureRequest, self).__post_init__()
        require_text(self.capture_id, "capture identity")
        if len(self.capture_id) > 128 or not 1 <= len(self.instruments) <= 4:
            raise ValueError("capture identity or symbol count is outside bounds")
        symbols = tuple(i.symbol for i in self.instruments)
        if symbols != tuple(sorted(set(symbols))) or len(
            {i.instrument_id for i in self.instruments}
        ) != len(symbols):
            raise ValueError("capture instruments must have unique sorted symbols and identities")
        if (self.kind == "daily" and (self.source.provider != "tiingo" or len(symbols) != 1)) or (
            self.kind == "quote" and self.source.provider != "etrade"
        ):
            raise ValueError("capture provider or single-symbol daily scope differs")
        if not self.session_open < self.session_close or not self.window_start < self.window_end:
            raise ValueError("capture calendar/window is invalid")
        if not 0 < self.max_response_bytes <= MAX_CAPTURE_BYTES or not 0 < self.deadline_ms <= 3000:
            raise ValueError("capture request exceeds resource bounds")
        key = self.journal_key
        if (
            key.namespace,
            key.source_provider,
            key.source_environment,
            key.source_scope_sha256,
        ) != (
            "capture",
            self.source.provider,
            self.source.environment,
            self.source.semantic_sha256,
        ):
            raise ValueError("capture journal does not bind the exact source")
        if self.source.account_scope is not None and key.account_scope != self.source.account_scope:
            raise ValueError("capture journal account differs")

    @property
    def path(self) -> str:
        if self.kind == "quote":
            return "/v1/market/quote/" + ",".join(i.symbol for i in self.instruments)
        return f"/tiingo/daily/{self.instruments[0].symbol}/prices"

    @property
    def query(self) -> tuple[tuple[str, str], ...]:
        if self.kind == "quote":
            return (("detailFlag", "ALL"),)
        return (
            ("startDate", self.session.isoformat()),
            ("endDate", self.session.isoformat()),
            ("format", "json"),
        )

    @property
    def http_request_sha256(self) -> str:
        # Matches the existing E*TRADE GET digest without tokens or arbitrary URLs.
        return hashlib.sha256(
            json.dumps(
                (self.source.environment, self.path, self.query), separators=(",", ":")
            ).encode()
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class CaptureVerification(CaptureRecord):
    """Output of a required trusted resolver, not a self-authenticating certificate.

    The resolver authenticates every retained reference and exact request scope,
    including instrument currency/calendar, actual clock health and plan rights.
    Synthetic test resolvers must return synthetic_fixture evidence.
    """

    request_sha256: str
    sample: CaptureClockSample
    valid_until: datetime
    identity_reference: str
    rights_reference: str
    entitlement_reference: str
    currency_reference: str
    clock_reference: str
    producer: VersionPin
    evidence_class: CaptureEvidenceClass

    def __post_init__(self) -> None:
        super(CaptureVerification, self).__post_init__()
        require_digest(self.request_sha256, "verified request")
        for name in (
            "identity_reference",
            "rights_reference",
            "entitlement_reference",
            "currency_reference",
            "clock_reference",
        ):
            require_text(getattr(self, name), name)
        if self.valid_until <= self.sample.at:
            raise ValueError("capture verification has expired")

    def check(self, request: ForwardCaptureRequest, sample: CaptureClockSample) -> None:
        if (
            self.request_sha256 != request.semantic_sha256
            or self.sample != sample
            or self.evidence_class != request.evidence_class
        ):
            raise ValueError("capture verification scope differs")
        source = request.source
        if (
            source.rights_status != "allowed"
            or self.identity_reference != source.identity_reference
            or self.rights_reference != source.rights_reference
            or self.entitlement_reference != source.entitlement_reference
            or source.entitlement_status
            != ("realtime" if request.kind == "quote" else "not_required")
        ):
            raise ValueError("verified capture source is unavailable")


@dataclass(frozen=True, slots=True)
class CaptureResponse(CaptureRecord):
    request_sha256: str
    status: int
    content_type: str
    body: bytes = field(repr=False)
    evidence_class: CaptureEvidenceClass

    def __post_init__(self) -> None:
        super(CaptureResponse, self).__post_init__()
        require_digest(self.request_sha256, "response request")
        if not 0 <= self.status <= 599 or len(self.body) > MAX_CAPTURE_BYTES:
            raise ValueError("capture response exceeds bounds")
        if len(self.content_type) > 256:
            raise ValueError("capture media type exceeds bounds")


@dataclass(frozen=True, slots=True)
class ForwardCaptureRecord(CaptureRecord):
    request: ForwardCaptureRequest
    before_state_sha256: str
    receipt: CaptureReceipt
    raw_object: ObjectRef
    verifications: tuple[CaptureVerification, ...]
    observations: tuple[ForwardObservation, ...]
    limitations: tuple[str, ...]
    live_authorized: Literal[False] = False

    def __post_init__(self) -> None:
        super(ForwardCaptureRecord, self).__post_init__()
        require_digest(self.before_state_sha256, "capture input state")
        r, q = self.receipt, self.request
        if (
            self.raw_object.codec_version != "personal-provider-json/1"
            or self.raw_object.object_sha256 != r.raw_sha256
            or self.raw_object.byte_count != r.byte_count
            or r.byte_count > q.max_response_bytes
            or (r.capture_id, r.source_sha256, r.request_sha256)
            != (q.capture_id, q.source.semantic_sha256, q.http_request_sha256)
        ):
            raise ValueError("capture raw object or request binding differs")
        samples = (
            CaptureClockSample(r.requested_at, r.requested_monotonic_ns, r.boot_id),
            CaptureClockSample(r.received_at, r.received_monotonic_ns, r.boot_id),
            CaptureClockSample(r.validated_at, r.validated_monotonic_ns, r.boot_id),
        )
        if len(self.verifications) != 3 or not 1 <= len(self.observations) <= 4:
            raise ValueError("capture verification/observation inventory differs")
        for proof, sample in zip(self.verifications, samples, strict=True):
            proof.check(q, sample)
        if (
            not q.window_start <= r.requested_at <= r.validated_at < q.window_end
            or r.validated_monotonic_ns - r.requested_monotonic_ns >= q.deadline_ms * 1_000_000
            or (r.validated_at - r.requested_at).total_seconds() * 1000 >= q.deadline_ms
        ):
            raise ValueError("capture receipt exceeds its window/deadline")
        if any(
            o.availability != r
            or o.source_id != q.source.source_id
            or o.source_sequence is not None
            for o in self.observations
        ):
            raise ValueError("capture observations have wrong receipt/source sequence")
        if tuple(o.payload.symbol for o in self.observations) != tuple(
            i.symbol for i in q.instruments
        ):
            raise ValueError("capture observation coverage differs")


@dataclass(frozen=True, slots=True)
class CapturePublication(CaptureRecord):
    record: ForwardCaptureRecord
    journal_receipt: JournalReceipt


class ForwardCaptureClock(Protocol):
    def sample(self) -> CaptureClockSample: ...
    def current_sample(self) -> CaptureClockSample:
        """Read local UTC/monotonic/epoch scalars only; never renew source evidence."""
        ...


class ForwardCaptureVerifier(Protocol):
    def verify(
        self, request: ForwardCaptureRequest, sample: CaptureClockSample
    ) -> CaptureVerification: ...


class ForwardCaptureTransport(Protocol):
    """Must enforce the supplied total deadline and byte bound before returning.

    No transport is supplied here; a blocked injected dependency is not forcibly
    interrupted by the collector. Production wiring remains separately reviewed.
    """

    def get(self, request: ForwardCaptureRequest, *, deadline_ms: int) -> CaptureResponse: ...


class ForwardCaptureJournal(Protocol):
    def append(self, key: JournalKey, request: JournalAppend) -> JournalReceipt: ...
    def read_receipt(self, key: JournalKey, command_id: str) -> JournalReceipt | None: ...
    def read_page(
        self,
        key: JournalKey,
        *,
        through_head: JournalHead,
        after_head: JournalHead | None = None,
        limit: int = 256,
    ) -> JournalPage: ...


class ForwardCapturePublisher(Protocol):
    """Mechanical publication port, not clock/rights/provider authority.

    The concrete SQL owner consumes an original collector-issued episode.
    A caller-built record or opaque object cannot substitute for that episode.
    """

    journal: ForwardCaptureJournal

    def require_original(self) -> None: ...
    def publish(self, episode: object) -> CapturePublication: ...
