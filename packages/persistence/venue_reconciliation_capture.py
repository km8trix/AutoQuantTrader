"""Retain independent venue observations before entering the account transaction.

The two databases are not one transaction. Venue reads, interpretation, codecs
and private object IO finish before the scoped coordinator capture journal is
published atomically. Unreferenced objects may remain after SQL rollback.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import datetime

from sqlalchemy.engine import Engine

from packages.application.venue_reconciliation import (
    VenueCaptureError,
    build_venue_financial_pages,
    reconciliation_page,
    resolve_venue_capture,
)
from packages.domain.durable_journal_contracts import (
    MAX_RECORD_BYTES,
    JournalAppend,
    JournalKey,
    JournalRecord,
    empty_head,
)
from packages.domain.identifiers import canonical_id
from packages.domain.personal_contracts import require_utc
from packages.domain.reconciliation_persistence_contracts import (
    MAX_EVIDENCE_BYTES,
    ReconciliationEvidenceRef,
    ReconciliationSourceManifest,
    ReconciliationSourceRef,
)
from packages.domain.research_job_contracts import (
    ObjectRef,
    ResearchArtifactStore,
    ResearchRecordCodec,
)
from packages.domain.venue_reconciliation_contracts import (
    VENUE_CAPTURE_SCHEMA,
    RetainedVenueCapture,
    VenueCapturePage,
    VenueCaptureRequest,
)
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.stateful_venue import SqlStatefulVenue


def venue_capture_key(request: VenueCaptureRequest) -> JournalKey:
    scope = request.binding.scope
    return JournalKey(
        "capture",
        request.capture_id,
        scope.account_id,
        scope.provider_id,
        "synthetic",
        scope.semantic_sha256,
    )


class SqlVenueReconciliationCapture:
    def __init__(
        self,
        engine: Engine,
        *,
        artifacts: ResearchArtifactStore,
        codec: ResearchRecordCodec,
        clock: Callable[[], datetime],
    ) -> None:
        self.engine, self.artifacts, self.codec, self.clock = engine, artifacts, codec, clock
        self._last_now: datetime | None = None
        self.journal = SqlDurableJournal(
            engine, codec=codec, record_types={VENUE_CAPTURE_SCHEMA: VenueCapturePage}
        )

    def _now(self) -> datetime:
        now = self.clock()
        require_utc(now, "venue query clock")
        if self._last_now is not None and now < self._last_now:
            raise VenueCaptureError("VENUE_CAPTURE_CLOCK_REGRESSED")
        self._last_now = now
        return now

    def read(self, request: VenueCaptureRequest) -> RetainedVenueCapture | None:
        """Return original receipt times and bytes; never refresh an old capture."""
        try:
            return self._read(request)
        except VenueCaptureError:
            raise
        except Exception:
            raise VenueCaptureError("VENUE_CAPTURE_RETAINED_READ_FAILED") from None

    def _read(self, request: VenueCaptureRequest) -> RetainedVenueCapture | None:
        request.__post_init__()
        key = venue_capture_key(request)
        head = self.journal.read_head(key)
        if head == empty_head(key):
            return None
        if not 1 <= head.sequence <= 256:
            raise VenueCaptureError("VENUE_CAPTURE_RETAINED_PAGE_LIMIT")
        raw_page = self.journal.read_page(key, through_head=head, limit=256)
        if not raw_page.complete or len(raw_page.entries) != head.sequence:
            raise VenueCaptureError("VENUE_CAPTURE_RETAINED_PAGE_GAP")
        pages: list[VenueCapturePage] = []
        sources: list[ReconciliationSourceRef] = []
        total = 0
        for entry in raw_page.entries:
            raw = entry.record.payload
            total += len(raw)
            if total > MAX_EVIDENCE_BYTES or entry.record.schema_id != VENUE_CAPTURE_SCHEMA:
                raise VenueCaptureError("VENUE_CAPTURE_RETAINED_BYTES_INVALID")
            value = self.codec.decode_record(raw, VenueCapturePage)
            if value.request != request or self.codec.encode_record(value) != raw:
                raise VenueCaptureError("VENUE_CAPTURE_REQUEST_OR_ENCODING_DIFFERS")
            reference = ObjectRef(hashlib.sha256(raw).hexdigest(), len(raw))
            if self.artifacts.read(reference, max_bytes=MAX_RECORD_BYTES) != raw:
                raise VenueCaptureError("VENUE_CAPTURE_OBJECT_DIFFERS")
            receipt = self.journal.read_receipt(key, entry.command_id)
            if receipt is None or receipt.command_sha256 != value.semantic_sha256:
                raise VenueCaptureError("VENUE_CAPTURE_RECEIPT_DIFFERS")
            sources.append(
                ReconciliationSourceRef(
                    reconciliation_page(value).receipt_id,
                    key,
                    receipt,
                    entry.record.record_id,
                    ReconciliationEvidenceRef(
                        VENUE_CAPTURE_SCHEMA, reference, value.semantic_sha256
                    ),
                )
            )
            pages.append(value)
        observed, facts = resolve_venue_capture(tuple(pages))
        manifest = ReconciliationSourceManifest(
            request.binding.scope, tuple(sorted(sources, key=lambda s: s.page_receipt_id))
        )
        return RetainedVenueCapture(
            manifest,
            observed,
            facts,
            tuple(
                f.fact_id
                for page in sorted(pages, key=lambda p: p.index)
                if page.body.fact_page is not None
                for f in page.body.fact_page.facts
            ),
        )

    def capture(
        self, request: VenueCaptureRequest, *, venue: SqlStatefulVenue
    ) -> RetainedVenueCapture:
        """Capture current independent state once, then retain its fixed prefix."""
        try:
            return self._capture(request, venue=venue)
        except VenueCaptureError:
            raise
        except Exception:
            raise VenueCaptureError("VENUE_CAPTURE_FAILED") from None

    def _capture(
        self, request: VenueCaptureRequest, *, venue: SqlStatefulVenue
    ) -> RetainedVenueCapture:
        existing = self.read(request)
        if existing is not None:
            return existing
        if venue.model != request.binding.model:
            raise VenueCaptureError("VENUE_CAPTURE_SOURCE_MODEL_OR_STORE_DIFFERS")
        requested_at = self._now()
        if request.requested_through > requested_at:
            raise VenueCaptureError("VENUE_CAPTURE_FUTURE_QUERY")
        source = venue.read()
        received_at = self._now()
        if request.through_head is not None and request.through_head != source.head:
            raise VenueCaptureError("VENUE_CAPTURE_HISTORICAL_HEAD_NOT_CURRENT")
        fact_pages = []
        fact_times = []
        offset = 0
        for _ in range(256):
            start = self._now()
            page = venue.facts(through_head=source.head, offset=offset, limit=200)
            end = self._now()
            fact_pages.append(page)
            fact_times.append((start, end))
            if page.complete:
                break
            if page.next_offset <= offset or page.next_offset > 4096:
                raise VenueCaptureError("VENUE_CAPTURE_FACT_PAGE_LIMIT")
            offset = page.next_offset
        else:
            raise VenueCaptureError("VENUE_CAPTURE_FACT_PAGE_LIMIT")
        bodies = build_venue_financial_pages(request, source, tuple(fact_pages))
        # The initial independent read is the financial freshness bound. A quiet
        # old venue state can still be current; a requested historical head cannot
        # become a current observation by re-querying it with a new capture ID.
        blockers = ("VENUE_ACCOUNT_HALTED",) if source.state.accounting.halted else ()
        pages = tuple(
            VenueCapturePage(
                request,
                source.head,
                source.state.semantic_sha256,
                source.state.as_of,
                *(
                    fact_times[body.ordinal]
                    if body.operation == "activity"
                    else (requested_at, received_at)
                ),
                body,
                index,
                len(bodies),
                blockers,
            )
            for index, body in enumerate(bodies)
        )
        resolve_venue_capture(pages)
        key, head = venue_capture_key(request), empty_head(venue_capture_key(request))
        prepared = []
        total = 0
        for value in pages:
            raw = self.codec.encode_record(value)
            total += len(raw)
            if not 0 < len(raw) <= MAX_RECORD_BYTES or total > MAX_EVIDENCE_BYTES:
                raise VenueCaptureError("VENUE_CAPTURE_ENCODED_BYTE_LIMIT")
            if self.codec.decode_record(raw, VenueCapturePage) != value:
                raise VenueCaptureError("VENUE_CAPTURE_CODEC_DIFFERS")
            reference = self.artifacts.put(raw, max_bytes=MAX_RECORD_BYTES)
            if (
                reference != ObjectRef(hashlib.sha256(raw).hexdigest(), len(raw))
                or self.artifacts.read(reference, max_bytes=MAX_RECORD_BYTES) != raw
            ):
                raise VenueCaptureError("VENUE_CAPTURE_OBJECT_WRITE_DIFFERS")
            identity = canonical_id("venue-capture-record/1", request.capture_id, value.index)
            append = JournalAppend(
                identity,
                value.semantic_sha256,
                head,
                (JournalRecord(identity, VENUE_CAPTURE_SCHEMA, raw),),
            )
            item = self.journal.prepare_append(key, append)
            prepared.append(item)
            head = item.receipt.committed_head
        # All heavy work above is detached. This transaction publishes only
        # bounded preencoded capture records, never an account/ledger mutation.
        with self.engine.connect() as connection:
            if connection.dialect.name == "sqlite":
                connection.exec_driver_sql("BEGIN IMMEDIATE")
            else:
                connection.begin()
            try:
                for item in prepared:
                    self.journal.append_in_transaction(connection, item)
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        retained = self.read(request)
        if retained is None:
            raise VenueCaptureError("VENUE_CAPTURE_PUBLICATION_MISSING")
        return retained
