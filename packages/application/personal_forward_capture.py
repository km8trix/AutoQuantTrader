"""One bounded retained capture over explicit ports; no scheduling or engine loop."""

from __future__ import annotations

import hashlib
import time
from dataclasses import asdict, dataclass, fields, is_dataclass, replace
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from threading import Thread, current_thread
from typing import Any
from weakref import WeakValueDictionary, finalize

from packages.adapters.broker.etrade_quotes import parse_etrade_quotes
from packages.adapters.market_data.tiingo_eod import TiingoEodScope, _contract_rows
from packages.application.personal_forward_data import admit_observation
from packages.domain.durable_journal_contracts import (
    JournalAppend,
    JournalEntry,
    JournalHead,
    JournalKey,
    JournalReceipt,
    JournalRecord,
)
from packages.domain.engine_contracts import DailyPrice
from packages.domain.forward_capture_contracts import (
    CAPTURE_SCHEMA,
    CaptureClockSample,
    CapturePublication,
    CaptureResponse,
    CaptureVerification,
    ForwardCaptureClock,
    ForwardCaptureJournal,
    ForwardCapturePublisher,
    ForwardCaptureRecord,
    ForwardCaptureRequest,
    ForwardCaptureTransport,
    ForwardCaptureVerifier,
)
from packages.domain.forward_contracts import (
    CaptureReceipt,
    ForwardDataState,
    ForwardObservation,
    ForwardQuote,
)
from packages.domain.personal_contracts import content_digest
from packages.domain.research_dataset import ResearchCalendar, ResearchSession, research_digest
from packages.domain.research_job_contracts import ResearchArtifactStore, ResearchRecordCodec
from packages.market_data import ExchangeCalendar, ExchangeSession, SessionKind


class ForwardCaptureError(ValueError):
    """Static capture failure codes; dependencies' diagnostics are never persisted."""


def require_capture_research_calendar_binding(
    request: ForwardCaptureRequest, calendar: ExchangeCalendar
) -> None:
    """Check the Tiingo-import research-calendar pin convention only.

    The caller must choose this producer convention; other capture pins need not
    use it. Hash the ResearchCalendar projection with string SessionKind values.
    Equal copied content is not original-object or authenticated source authority.
    This check does not grant capture admission. A source owner must separately
    retain and recheck its original request graph and calendar provenance.
    """

    try:
        if type(request) is not ForwardCaptureRequest or type(calendar) is not ExchangeCalendar:
            raise ForwardCaptureError("CAPTURE_CALENDAR_INVALID")
        request.__post_init__()
        request.calendar.__post_init__()
        if type(calendar.sessions) is not tuple or any(
            type(session) is not ExchangeSession or type(session.kind) is not SessionKind
            for session in calendar.sessions
        ):
            raise ForwardCaptureError("CAPTURE_CALENDAR_INVALID")
        for session in calendar.sessions:
            session.__post_init__()
        calendar.__post_init__()
        projected = ResearchCalendar(
            calendar_id=calendar.calendar_id,
            version=calendar.version,
            venue=calendar.venue,
            timezone=calendar.timezone,
            sessions=tuple(
                ResearchSession(
                    venue=session.venue,
                    session_label=session.session_label,
                    opens_at=session.opens_at,
                    closes_at=session.closes_at,
                    kind=session.kind.value,
                )
                for session in calendar.sessions
            ),
        )
        if (request.calendar.name, request.calendar.version, request.calendar.sha256) != (
            projected.calendar_id,
            projected.version,
            research_digest(asdict(projected)),
        ):
            raise ForwardCaptureError("CAPTURE_CALENDAR_BINDING_DIFFERS")
        selected = calendar.session_for_label(request.session)
        if selected is None or (selected.opens_at, selected.closes_at) != (
            request.session_open,
            request.session_close,
        ):
            raise ForwardCaptureError("CAPTURE_CALENDAR_SESSION_DIFFERS")
    except ForwardCaptureError:
        raise
    except Exception:
        raise ForwardCaptureError("CAPTURE_CALENDAR_INVALID") from None


_MAX_EPISODE_OBJECTS = 4096
_MAX_EPISODE_BYTES = 32 * 1024 * 1024
_MONOTONIC_NS = time.monotonic_ns


@dataclass(frozen=True, slots=True, weakref_slot=True)
class _CaptureEpisode:
    """Original in-process denial scope; never a provider authorization."""

    seal: object

    def __reduce__(self) -> Any:
        raise TypeError("capture episode is process-local")


@dataclass(frozen=True, slots=True)
class _OriginalFields:
    value: object
    kind: type
    version: object
    values: tuple[tuple[str, object], ...]


@dataclass(slots=True)
class _EpisodeState:
    seal: object
    request: ForwardCaptureRequest
    state: ForwardDataState
    expected_head: JournalHead
    clock: ForwardCaptureClock
    publisher: ForwardCapturePublisher
    ports: tuple[tuple[object, type, tuple[tuple[str, object], ...]], ...]
    thread: Thread
    requested: CaptureClockSample | None
    latest: CaptureClockSample | None
    started_ns: int
    deadline_ns: int
    valid_until: datetime
    fields: list[_OriginalFields]
    seen: set[int]
    byte_count: int = 0
    publication: CapturePublication | None = None
    append: JournalAppend | None = None
    claimed: bool = False


_EPISODES: WeakValueDictionary[int, _CaptureEpisode] = WeakValueDictionary()
_EPISODE_STATES: dict[int, _EpisodeState] = {}


def _method_identity(value: object) -> object:
    return (id(getattr(value, "__self__", value)), id(getattr(value, "__func__", value)))


def _remember_capture_fields(state: _EpisodeState, *roots: object) -> None:
    """Bound and snapshot immutable input fields outside every SQL transaction."""
    pending = list(roots)
    while pending:
        value = pending.pop()
        if id(value) in state.seen:
            continue
        state.seen.add(id(value))
        if len(state.seen) > _MAX_EPISODE_OBJECTS:
            raise ForwardCaptureError("CAPTURE_EPISODE_GRAPH_LIMIT")
        if type(value) is str:
            state.byte_count += len(value.encode("utf-8"))
        elif type(value) is bytes:
            state.byte_count += len(value)
        if state.byte_count > _MAX_EPISODE_BYTES:
            raise ForwardCaptureError("CAPTURE_EPISODE_GRAPH_LIMIT")
        values: tuple[tuple[str, object], ...]
        if isinstance(value, Enum):
            values = (("value", value.value),)
        elif is_dataclass(value) and not isinstance(value, type):
            values = tuple((f.name, getattr(value, f.name)) for f in fields(value))
        elif type(value) is tuple:
            pending.extend(value)
            continue
        elif value is None or type(value) in (str, bytes, bool, int, Decimal, date, datetime):
            continue
        else:
            raise ForwardCaptureError("CAPTURE_EPISODE_VALUE_UNSUPPORTED")
        state.fields.append(
            _OriginalFields(
                value, type(value), getattr(type(value), "contract_version", None), values
            )
        )
        pending.extend(item for _, item in values)


def _capture_episode_state(episode: object, publisher: object | None = None) -> _EpisodeState:
    if type(episode) is not _CaptureEpisode or _EPISODES.get(id(episode)) is not episode:
        raise ForwardCaptureError("CAPTURE_ORIGINAL_EPISODE_REQUIRED")
    state = _EPISODE_STATES[id(episode)]
    if episode.seal is not state.seal or state.thread is not current_thread():
        raise ForwardCaptureError("CAPTURE_ORIGINAL_EPISODE_REQUIRED")
    if publisher is not None and state.publisher is not publisher:
        raise ForwardCaptureError("CAPTURE_ORIGINAL_PUBLISHER_REQUIRED")
    for port, kind, methods in state.ports:
        if type(port) is not kind or any(
            _method_identity(getattr(port, name)) != original for name, original in methods
        ):
            raise ForwardCaptureError("CAPTURE_ORIGINAL_PORT_CHANGED")
    if any(
        type(item.value) is not item.kind
        or getattr(item.kind, "contract_version", None) is not item.version
        or any(getattr(item.value, name) is not original for name, original in item.values)
        for item in state.fields
    ):
        raise ForwardCaptureError("CAPTURE_ORIGINAL_INPUT_CHANGED")
    state.publisher.require_original()
    return state


def _capture_elapsed_ns(start: datetime, end: datetime) -> int:
    elapsed = end - start
    return (elapsed.days * 86400 + elapsed.seconds) * 1_000_000_000 + elapsed.microseconds * 1000


def _narrow_capture_deadline(state: _EpisodeState, valid_until: datetime) -> None:
    """Original UTC expiries only tighten the already earlier process origin."""
    if state.requested is None:
        raise ForwardCaptureError("CAPTURE_ORIGINAL_SAMPLE_REQUIRED")
    state.valid_until = min(state.valid_until, valid_until)
    state.deadline_ns = min(
        state.deadline_ns,
        state.started_ns + _capture_elapsed_ns(state.requested.at, state.valid_until),
    )


def _check_capture_time(state: _EpisodeState, sample: CaptureClockSample) -> None:
    if type(sample) is not CaptureClockSample:
        raise ForwardCaptureError("CAPTURE_CLOCK_SAMPLE_INVALID")
    sample.__post_init__()
    requested, latest = state.requested, state.latest
    if requested is None or latest is None:
        raise ForwardCaptureError("CAPTURE_ORIGINAL_SAMPLE_REQUIRED")
    utc_ns = _capture_elapsed_ns(requested.at, sample.at)
    if (
        sample.boot_id != requested.boot_id
        or sample.at < latest.at
        or sample.monotonic_ns < latest.monotonic_ns
        or not 0 <= utc_ns < state.request.deadline_ms * 1_000_000
        or not 0
        <= sample.monotonic_ns - requested.monotonic_ns
        < state.request.deadline_ms * 1_000_000
        or not state.request.window_start <= sample.at < state.valid_until
        or not state.started_ns <= _MONOTONIC_NS() < state.deadline_ns
    ):
        raise ForwardCaptureError("CAPTURE_ORIGINAL_DEADLINE_OR_CLOCK_CHANGED")
    state.latest = sample


def _recheck_capture_episode(episode: object, *, publisher: object | None = None) -> None:
    """Original bounded field identity plus current local scalar denial only."""
    state = _capture_episode_state(episode, publisher)
    _check_capture_time(state, state.clock.current_sample())
    # Sampling is an external port boundary. It cannot mutate original inputs.
    _capture_episode_state(episode, publisher)
    if _MONOTONIC_NS() >= state.deadline_ns:
        raise ForwardCaptureError("CAPTURE_ORIGINAL_DEADLINE_OR_CLOCK_CHANGED")


def _capture_publication_inputs(
    episode: object, *, publisher: object, claim: bool = False
) -> tuple[JournalKey, JournalAppend, CapturePublication]:
    state = _capture_episode_state(episode, publisher)
    if state.append is None or state.publication is None or (claim and state.claimed):
        raise ForwardCaptureError("CAPTURE_ORIGINAL_PREPARATION_REQUIRED")
    if claim:
        state.claimed = True
    return state.request.journal_key, state.append, state.publication


def _limitations(request: ForwardCaptureRequest) -> tuple[str, ...]:
    reasons = ["PROVIDER_SEQUENCE_AND_REVISION_UNAVAILABLE", "NO_EXECUTION_AUTHORITY"]
    if request.kind == "daily":
        reasons.append("VENDOR_PUBLICATION_TIME_UNAVAILABLE")
    if request.evidence_class == "synthetic_fixture":
        reasons.append("SYNTHETIC_TRANSPORT_NOT_PROVIDER_EVIDENCE")
    return tuple(reasons)


def _observations(
    request: ForwardCaptureRequest, body: bytes, receipt: CaptureReceipt, state: ForwardDataState
) -> tuple[ForwardObservation, ...]:
    payloads: tuple[DailyPrice | ForwardQuote, ...]
    if request.kind == "quote":
        payloads = parse_etrade_quotes(body, request)
    else:
        rows = _contract_rows(
            body,
            scope=TiingoEodScope(
                (request.instruments[0].symbol,), request.session, request.session
            ),
        )
        if len(rows) != 1 or receipt.received_at < request.session_close:
            raise ForwardCaptureError("DAILY_COMPLETE_SESSION_UNAVAILABLE")
        row = rows[0]
        if row.div_cash != 0 or row.split_factor != 1:
            raise ForwardCaptureError("DAILY_ACTION_MAPPING_REQUIRED")
        instrument = request.instruments[0]
        payloads = (
            DailyPrice(
                instrument.instrument_id,
                instrument.symbol,
                request.session,
                row.open_price,
                row.close_price,
                row.adjusted_close_price,
            ),
        )
    result = []
    for payload in payloads:
        slot = content_digest(
            (
                "forward-capture-slot/1",
                request.source.semantic_sha256,
                request.kind,
                payload.instrument_id,
                payload.session,
                request.capture_id if request.kind == "quote" else None,
            )
        )
        prior = max(
            (
                o
                for o in state.observations
                if o.source_id == request.source.source_id and o.revision_key == slot
            ),
            key=lambda o: o.revision,
            default=None,
        )
        if prior is not None and prior.known_at > receipt.requested_at:
            raise ForwardCaptureError("CAPTURE_PARENT_NOT_YET_KNOWN")
        revision, predecessor = (
            (1, None) if prior is None else (prior.revision + 1, prior.observation_id)
        )
        if isinstance(payload, DailyPrice):
            payload = replace(payload, revision=revision, predecessor_revision_id=predecessor)
        identifier = content_digest(
            (
                "forward-capture-observation/1",
                request.semantic_sha256,
                receipt.semantic_sha256,
                payload,
                revision,
                predecessor,
            )
        )
        result.append(
            ForwardObservation(
                identifier,
                request.source.source_id,
                payload,
                receipt,
                slot,
                revision,
                predecessor,
                None,
            )
        )
    return tuple(result)


def _admit(state: ForwardDataState, record: ForwardCaptureRecord) -> ForwardDataState:
    for observation in record.observations:
        transition = admit_observation(state, observation, admitted_at=record.receipt.validated_at)
        if transition.disposition not in ("accepted", "duplicate"):
            raise ForwardCaptureError("CAPTURE_OBSERVATION_ADMISSION_FAILED")
        state = transition.state
    return state


def _raw(record: ForwardCaptureRecord, artifacts: ResearchArtifactStore) -> bytes:
    record.__post_init__()
    if record.raw_object.codec_version != "personal-provider-json/1":
        raise ForwardCaptureError("CAPTURE_RAW_CODEC_REQUIRED")
    body = artifacts.read(record.raw_object, max_bytes=record.request.max_response_bytes)
    if (
        type(body) is not bytes
        or len(body) != record.receipt.byte_count
        or hashlib.sha256(body).hexdigest() != record.receipt.raw_sha256
    ):
        raise ForwardCaptureError("CAPTURE_RAW_OBJECT_DIFFERS")
    return body


def replay_capture(
    record: ForwardCaptureRecord, state: ForwardDataState, *, artifacts: ResearchArtifactStore
) -> ForwardDataState:
    """Validate retained bytes and advance only forward observation admission.

    This neither treats past quotes as currently fresh nor runs an economic engine.
    The caller supplies records from its fixed-through journal inventory.
    """
    try:
        state.__post_init__()
        body = _raw(record, artifacts)
        if record.before_state_sha256 != state.semantic_sha256:
            raise ForwardCaptureError("CAPTURE_REPLAY_STATE_DIFFERS")
        if record.observations != _observations(
            record.request, body, record.receipt, state
        ) or record.limitations != _limitations(record.request):
            raise ForwardCaptureError("CAPTURE_NORMALIZATION_BINDING_DIFFERS")
        return _admit(state, record)
    except ForwardCaptureError:
        raise
    except Exception:
        raise ForwardCaptureError("CAPTURE_REPLAY_VALIDATION_FAILED") from None


def _publication(
    request: ForwardCaptureRequest,
    record: ForwardCaptureRecord,
    receipt: object,
    codec: ResearchRecordCodec,
) -> CapturePublication:
    from packages.domain.durable_journal_contracts import JournalReceipt

    if type(receipt) is not JournalReceipt:
        raise ForwardCaptureError("CAPTURE_JOURNAL_RECEIPT_INVALID")
    receipt.__post_init__()
    payload = codec.encode_record(record)
    expected = JournalAppend(
        request.capture_id,
        request.semantic_sha256,
        receipt.previous_head,
        (JournalRecord(request.capture_id, CAPTURE_SCHEMA, payload),),
    )
    expected_entry = JournalEntry(
        receipt.previous_head.key_sha256,
        receipt.previous_head.sequence + 1,
        request.capture_id,
        expected.records[0],
        receipt.previous_head.entry_sha256,
    )
    if (
        receipt.committed_head != expected_entry.head
        or receipt.command_id != request.capture_id
        or receipt.command_sha256 != request.semantic_sha256
        or receipt.append_sha256 != expected.semantic_sha256
        or receipt.record_ids != (request.capture_id,)
        or receipt.record_hashes != (hashlib.sha256(payload).hexdigest(),)
        or receipt.previous_head.key_sha256 != request.journal_key.semantic_sha256
    ):
        raise ForwardCaptureError("CAPTURE_JOURNAL_BINDING_DIFFERS")
    return CapturePublication(record, receipt)


def read_capture(
    request: ForwardCaptureRequest,
    *,
    journal: ForwardCaptureJournal,
    artifacts: ResearchArtifactStore,
    codec: ResearchRecordCodec,
) -> CapturePublication | None:
    """Exact original retry, including after later appends; no network or fresh grant."""
    try:
        receipt = journal.read_receipt(request.journal_key, request.capture_id)
        if receipt is None:
            return None
        if receipt.command_sha256 != request.semantic_sha256:
            raise ForwardCaptureError("CAPTURE_ID_CONFLICT")
        page = journal.read_page(
            request.journal_key,
            through_head=receipt.committed_head,
            after_head=receipt.previous_head,
            limit=1,
        )
        page.__post_init__()
        if (
            len(page.entries) != 1
            or not page.complete
            or page.through_head != receipt.committed_head
            or page.previous_head != receipt.previous_head
        ):
            raise ForwardCaptureError("CAPTURE_ORIGINAL_PAGE_DIFFERS")
        entry = page.entries[0]
        if entry.record.schema_id != CAPTURE_SCHEMA or entry.record.record_id != request.capture_id:
            raise ForwardCaptureError("CAPTURE_RECORD_TYPE_DIFFERS")
        record = codec.decode_record(entry.record.payload, ForwardCaptureRecord)
        if (
            type(record) is not ForwardCaptureRecord
            or record.request != request
            or codec.encode_record(record) != entry.record.payload
        ):
            raise ForwardCaptureError("CAPTURE_ORIGINAL_RECORD_DIFFERS")
        _raw(record, artifacts)
        return _publication(request, record, receipt, codec)
    except ForwardCaptureError:
        raise
    except Exception:
        raise ForwardCaptureError("CAPTURE_READ_FAILED") from None


def _verify(
    request: ForwardCaptureRequest, sample: CaptureClockSample, verifier: ForwardCaptureVerifier
) -> CaptureVerification:
    if type(sample) is not CaptureClockSample:
        raise ForwardCaptureError("CAPTURE_CLOCK_SAMPLE_INVALID")
    sample.__post_init__()
    if not request.window_start <= sample.at < request.window_end:
        raise ForwardCaptureError("CAPTURE_WINDOW_CLOSED")
    proof = verifier.verify(request, sample)
    if type(proof) is not CaptureVerification:
        raise ForwardCaptureError("CAPTURE_VERIFIER_RECORD_INVALID")
    proof.__post_init__()
    proof.check(request, sample)
    return proof


def capture_forward(
    request: ForwardCaptureRequest,
    state: ForwardDataState,
    *,
    expected_head: JournalHead,
    clock: ForwardCaptureClock,
    verifier: ForwardCaptureVerifier,
    transport: ForwardCaptureTransport,
    journal: ForwardCaptureJournal,
    artifacts: ResearchArtifactStore,
    codec: ResearchRecordCodec,
    publisher: ForwardCapturePublisher | None = None,
) -> CapturePublication:
    """One capture, no retry/scheduler. All production ports require explicit wiring.

    Transport enforces its wall deadline; the collector also checks elapsed time.
    Ordinary filesystem/port calls are not a hostile-process resource sandbox.
    """
    episode: _CaptureEpisode | None = None
    try:
        request.__post_init__()
        state.__post_init__()
        original = read_capture(request, journal=journal, artifacts=artifacts, codec=codec)
        if original is not None:
            return original
        if request.evidence_class != "synthetic_fixture":
            raise ForwardCaptureError("CAPTURE_GENUINE_SOURCE_BRIDGE_REQUIRED")
        if publisher is None or publisher.journal is not journal:
            raise ForwardCaptureError("CAPTURE_ORIGINAL_PUBLISHER_REQUIRED")
        publisher.require_original()
        if (
            state.mode != "recorded"
            or request.source not in state.sources
            or expected_head.key_sha256 != request.journal_key.semantic_sha256
        ):
            raise ForwardCaptureError("CAPTURE_STATE_OR_HEAD_SCOPE_DIFFERS")
        started_ns = _MONOTONIC_NS()
        ports = (
            (clock, ("sample", "current_sample")),
            (verifier, ("verify",)),
            (transport, ("get",)),
            (journal, ("read_receipt", "read_page")),
            (publisher, ("require_original", "publish")),
            (artifacts, ("put", "read")),
            (codec, ("encode_record", "decode_record")),
        )
        seal = object()
        episode = _CaptureEpisode(seal)
        episode_state = _EpisodeState(
            seal,
            request,
            state,
            expected_head,
            clock,
            publisher,
            tuple(
                (
                    port,
                    type(port),
                    tuple((name, _method_identity(getattr(port, name))) for name in names),
                )
                for port, names in ports
            ),
            current_thread(),
            None,
            None,
            started_ns,
            started_ns + request.deadline_ms * 1_000_000,
            request.window_end,
            [],
            set(),
        )
        _EPISODES[id(episode)] = episode
        _EPISODE_STATES[id(episode)] = episode_state
        finalize(episode, _EPISODE_STATES.pop, id(episode), None)
        _remember_capture_fields(episode_state, request, state, expected_head)
        requested = clock.sample()
        _capture_episode_state(episode)
        if type(requested) is not CaptureClockSample:
            raise ForwardCaptureError("CAPTURE_CLOCK_SAMPLE_INVALID")
        requested.__post_init__()
        episode_state.requested = episode_state.latest = requested
        _remember_capture_fields(episode_state, requested)
        _narrow_capture_deadline(episode_state, request.window_end)

        def remember(proof: CaptureVerification) -> None:
            _capture_episode_state(episode)
            _remember_capture_fields(episode_state, proof)
            _narrow_capture_deadline(episode_state, proof.valid_until)
            _recheck_capture_episode(episode)

        first = _verify(request, requested, verifier)
        remember(first)
        remaining_ms = min(
            request.deadline_ms, (episode_state.deadline_ns - _MONOTONIC_NS()) // 1_000_000
        )
        if remaining_ms <= 0:
            raise ForwardCaptureError("CAPTURE_ORIGINAL_DEADLINE_OR_CLOCK_CHANGED")
        response = transport.get(request, deadline_ms=remaining_ms)
        _capture_episode_state(episode)
        received = clock.sample()
        _check_capture_time(episode_state, received)
        second = _verify(request, received, verifier)
        remember(second)
        if type(response) is not CaptureResponse:
            raise ForwardCaptureError("CAPTURE_RESPONSE_TYPE_INVALID")
        response.__post_init__()
        if (
            response.request_sha256 != request.http_request_sha256
            or response.evidence_class != request.evidence_class
            or response.status != 200
            or not 0 < len(response.body) <= request.max_response_bytes
            or response.content_type.split(";", 1)[0].strip().lower() != "application/json"
        ):
            raise ForwardCaptureError("CAPTURE_RESPONSE_NOT_ELIGIBLE")
        _remember_capture_fields(episode_state, response)
        # Normalize before creating a retained success. No guessed publication time.
        provisional = CaptureReceipt(
            request.capture_id,
            request.source.semantic_sha256,
            request.http_request_sha256,
            hashlib.sha256(response.body).hexdigest(),
            len(response.body),
            requested.at,
            received.at,
            received.at,
            requested.boot_id,
            requested.monotonic_ns,
            received.monotonic_ns,
            received.monotonic_ns,
        )
        _observations(request, response.body, provisional, state)
        validated = clock.sample()
        _check_capture_time(episode_state, validated)
        third = _verify(request, validated, verifier)
        remember(third)
        if requested.boot_id != received.boot_id or requested.boot_id != validated.boot_id:
            raise ForwardCaptureError("CAPTURE_BOOT_CHANGED")
        receipt = replace(
            provisional, validated_at=validated.at, validated_monotonic_ns=validated.monotonic_ns
        )
        observations = _observations(request, response.body, receipt, state)
        from packages.domain.research_job_contracts import ObjectRef

        raw_ref = ObjectRef(receipt.raw_sha256, receipt.byte_count, "personal-provider-json/1")
        record = ForwardCaptureRecord(
            request,
            state.semantic_sha256,
            receipt,
            raw_ref,
            (first, second, third),
            observations,
            _limitations(request),
        )
        _remember_capture_fields(episode_state, record)
        _recheck_capture_episode(episode)
        _admit(state, record)
        _recheck_capture_episode(episode)
        reference = artifacts.put(
            response.body,
            codec_version="personal-provider-json/1",
            max_bytes=request.max_response_bytes,
        )
        if reference != raw_ref:
            raise ForwardCaptureError("CAPTURE_RAW_PUBLICATION_DIFFERS")
        _recheck_capture_episode(episode)
        _raw(record, artifacts)
        _recheck_capture_episode(episode)
        encoded = codec.encode_record(record)
        if codec.decode_record(encoded, ForwardCaptureRecord) != record:
            raise ForwardCaptureError("CAPTURE_CODEC_ROUNDTRIP_DIFFERS")
        _recheck_capture_episode(episode)
        append = JournalAppend(
            request.capture_id,
            request.semantic_sha256,
            expected_head,
            (JournalRecord(request.capture_id, CAPTURE_SCHEMA, encoded),),
        )
        entry = JournalEntry(
            expected_head.key_sha256,
            expected_head.sequence + 1,
            request.capture_id,
            append.records[0],
            expected_head.entry_sha256,
        )
        prospective = JournalReceipt(
            request.capture_id,
            request.semantic_sha256,
            append.semantic_sha256,
            expected_head,
            entry.head,
            (request.capture_id,),
            (append.records[0].payload_sha256,),
        )
        publication = _publication(request, record, prospective, codec)
        _recheck_capture_episode(episode)
        _remember_capture_fields(episode_state, publication, append)
        episode_state.publication, episode_state.append = publication, append
        _recheck_capture_episode(episode)
        retained = publisher.publish(episode)
        if retained is not publication:
            raise ForwardCaptureError("CAPTURE_ORIGINAL_PUBLICATION_REQUIRED")
        return retained
    except ForwardCaptureError:
        raise
    except Exception:
        raise ForwardCaptureError("CAPTURE_DEPENDENCY_OR_VALIDATION_FAILED") from None
    finally:
        if episode is not None:
            _EPISODES.pop(id(episode), None)
            _EPISODE_STATES.pop(id(episode), None)
