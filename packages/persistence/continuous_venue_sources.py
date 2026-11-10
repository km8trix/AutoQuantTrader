"""Authenticate retained modeled-venue pages without querying the independent venue.

One coherent coordinator SQL snapshot is followed by detached typed decoding and
private-object comparison. Final account publication rechecks original journal
bytes only; later captures cannot refresh the original observation times.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field, fields, is_dataclass, replace
from hashlib import sha256
from typing import Any, overload
from weakref import WeakValueDictionary, finalize

from sqlalchemy import Connection, Engine

from packages.application.venue_reconciliation import (
    VenueReconciliationResolver,
    reconciliation_page,
)
from packages.domain.canonical import canonical_json_bytes
from packages.domain.durable_journal_contracts import MAX_APPEND_BYTES, MAX_RECORD_BYTES
from packages.domain.identifiers import canonical_id
from packages.domain.reconciliation_contracts import ReconciliationScope
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
from packages.domain.stateful_venue_contracts import VenueModel
from packages.domain.venue_reconciliation_contracts import (
    VENUE_CAPTURE_SCHEMA,
    RetainedVenueCapture,
    VenueCapturePage,
)
from packages.persistence.continuous_capture_comparison import ContinuousCaptureComparison
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.durable_journal import (
    JournalReadSnapshot,
    ResolvedJournalRead,
    SqlDurableJournal,
)
from packages.persistence.venue_reconciliation_capture import venue_capture_key

# Source bytes retain their existing 32 MiB cap. A later current append and its
# two neighboring anchors are auxiliary journal proof, not new source evidence.
MAX_VENUE_SNAPSHOT_BYTES = MAX_EVIDENCE_BYTES + MAX_APPEND_BYTES + 2 * MAX_RECORD_BYTES + 16 * 1024
MAX_VENUE_SNAPSHOT_METADATA_BYTES = 2 * 1024 * 1024


class ContinuousVenueSourceError(ValueError):
    pass


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResolvedContinuousVenueSources:
    capture: RetainedVenueCapture
    pages: tuple[VenueCapturePage, ...]
    reads: tuple[ResolvedJournalRead, ...]
    seal: object = field(repr=False, compare=False)


class _SnapshotRows:
    """Intern repeated head/neighbor rows and bound the complete detached graph."""

    def __init__(self) -> None:
        self.rows: dict[tuple[object, ...], Mapping[str, Any]] = {}
        self.byte_count = 0
        self.metadata_bytes = 0

    @overload
    def row(self, kind: str, row: None) -> None: ...

    @overload
    def row(self, kind: str, row: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def row(self, kind: str, row: Mapping[str, Any] | None) -> Mapping[str, Any] | None:
        if row is None:
            return None
        identity = (
            kind,
            row["key_sha256"],
            row.get("command_id") if kind == "append" else row.get("sequence"),
        )
        old = self.rows.get(identity)
        if old is not None:
            if old != row:
                raise ContinuousVenueSourceError("VENUE_SOURCE_SNAPSHOT_CHANGED")
            return old
        for value in row.values():
            if type(value) is bytes:
                self.byte_count += len(value)
            elif type(value) is str:
                self.metadata_bytes += len(value.encode("utf-8"))
            elif type(value) is int:
                self.metadata_bytes += 8
            else:
                raise ContinuousVenueSourceError("VENUE_SOURCE_SQL_METADATA_INVALID")
        if (
            self.byte_count > MAX_VENUE_SNAPSHOT_BYTES
            or self.metadata_bytes > MAX_VENUE_SNAPSHOT_METADATA_BYTES
        ):
            raise ContinuousVenueSourceError("VENUE_SOURCE_SQL_SNAPSHOT_LIMIT")
        self.rows[identity] = row
        return row

    def capture(self, snapshot: JournalReadSnapshot) -> JournalReadSnapshot:
        receipts = []
        for value in (snapshot.head_receipt, snapshot.requested_receipt):
            receipts.append(
                None
                if value is None
                else replace(
                    value,
                    append=self.row("append", value.append),
                    entries=tuple(self.row("entry", row) for row in value.entries),
                    previous=self.row("entry", value.previous),
                )
            )
        return replace(
            snapshot,
            stream=self.row("stream", snapshot.stream),
            head_anchor=self.row("entry", snapshot.head_anchor),
            head_receipt=receipts[0],
            requested_receipt=receipts[1],
        )


def _fingerprint_value(value: object) -> object:
    if type(value) is bytes:
        return ("bytes", len(value), sha256(value).hexdigest())
    if isinstance(value, Mapping):
        return tuple((str(key), _fingerprint_value(item)) for key, item in sorted(value.items()))
    if is_dataclass(value) and not isinstance(value, type):
        return (
            type(value).__qualname__,
            tuple(
                (f.name, _fingerprint_value(getattr(value, f.name)))
                for f in fields(value)
                if f.name not in {"_owner", "_validated_values"}
            ),
        )
    if type(value) is tuple:
        return tuple(_fingerprint_value(item) for item in value)
    return value


def _fingerprint(value: ResolvedContinuousVenueSources) -> str:
    return sha256(
        canonical_json_bytes(
            (
                value.capture.semantic_sha256,
                tuple(page.semantic_sha256 for page in value.pages),
                _fingerprint_value(value.reads),
            )
        )
    ).hexdigest()


class SqlContinuousVenueSources:
    def __init__(
        self,
        engine: Engine,
        *,
        artifacts: ResearchArtifactStore,
        codec: ResearchRecordCodec,
        resolver: VenueReconciliationResolver,
        scope: ReconciliationScope,
        model: VenueModel,
    ) -> None:
        if type(scope) is not ReconciliationScope or type(model) is not VenueModel:
            raise ContinuousVenueSourceError("EXACT_VENUE_SOURCE_PINS_REQUIRED")
        scope.__post_init__()
        model.__post_init__()
        if scope.source_class != "stateful_simulation" or scope.provider_id != model.venue_id:
            raise ContinuousVenueSourceError("MODELED_VENUE_SOURCE_SCOPE_REQUIRED")
        self.engine, self.artifacts, self.codec, self.resolver = engine, artifacts, codec, resolver
        self.scope, self.model = scope, model
        self.journal = SqlDurableJournal(
            engine, codec=codec, record_types={VENUE_CAPTURE_SCHEMA: VenueCapturePage}
        )
        self._seal = object()
        self._owned: WeakValueDictionary[int, ResolvedContinuousVenueSources] = (
            WeakValueDictionary()
        )
        self._fingerprints: dict[int, str] = {}
        self._identities: dict[int, tuple[int, int, int]] = {}

    def resolve(self, capture: RetainedVenueCapture) -> ResolvedContinuousVenueSources:
        try:
            if type(capture) is not RetainedVenueCapture:
                raise ContinuousVenueSourceError("EXACT_RETAINED_VENUE_CAPTURE_REQUIRED")
            capture.__post_init__()
            manifest = capture.manifest
            manifest.__post_init__()
            if manifest.scope != self.scope or not manifest.sources:
                raise ContinuousVenueSourceError("VENUE_SOURCE_SCOPE_OR_INVENTORY_DIFFERS")
            if sum(s.evidence.object_ref.byte_count for s in manifest.sources) > MAX_EVIDENCE_BYTES:
                raise ContinuousVenueSourceError("VENUE_SOURCE_OBJECT_BYTE_LIMIT")
            for source in manifest.sources:
                source.__post_init__()
                if (
                    source.evidence.schema_id != VENUE_CAPTURE_SCHEMA
                    or source.key.stream_id != capture.observed.round_id
                    or source.receipt.record_ids != (source.record_id,)
                    or source.receipt.command_id != source.record_id
                    or source.receipt.command_sha256 != source.evidence.semantic_sha256
                ):
                    raise ContinuousVenueSourceError("VENUE_SOURCE_APPEND_BINDING_DIFFERS")
            pool = _SnapshotRows()
            with _repeatable_read_transaction(self.engine) as connection:
                snapshots = tuple(
                    pool.capture(
                        self.journal.capture_in_transaction(
                            connection, source.key, command_id=source.receipt.command_id
                        )
                    )
                    for source in manifest.sources
                )
            reads = tuple(self.journal.resolve_snapshot(snapshot) for snapshot in snapshots)
            pages = []
            rebuilt_sources = []
            for source, read in zip(manifest.sources, reads, strict=True):
                rows = read.snapshot.requested_receipt
                if read.receipt != source.receipt or rows is None or len(rows.entries) != 1:
                    raise ContinuousVenueSourceError("VENUE_SOURCE_ORIGINAL_RECEIPT_DIFFERS")
                row = rows.entries[0]
                raw = row["payload"]
                reference = ObjectRef(sha256(raw).hexdigest(), len(raw))
                if (
                    source.evidence.object_ref != reference
                    or row["record_id"] != source.record_id
                    or row["schema_id"] != VENUE_CAPTURE_SCHEMA
                    or self.artifacts.read(reference, max_bytes=MAX_RECORD_BYTES) != raw
                ):
                    raise ContinuousVenueSourceError("VENUE_SOURCE_ORIGINAL_OBJECT_DIFFERS")
                page = self.codec.decode_record(raw, VenueCapturePage)
                if (
                    type(page) is not VenueCapturePage
                    or self.codec.encode_record(page) != raw
                    or page.request.binding.scope != self.scope
                    or page.request.binding.model != self.model
                    or venue_capture_key(page.request) != source.key
                    or canonical_id("venue-capture-record/1", page.request.capture_id, page.index)
                    != source.record_id
                    or page.index + 1 != source.receipt.committed_head.sequence
                ):
                    raise ContinuousVenueSourceError("VENUE_SOURCE_PAGE_BINDING_DIFFERS")
                rebuilt_sources.append(
                    ReconciliationSourceRef(
                        reconciliation_page(page).receipt_id,
                        venue_capture_key(page.request),
                        read.receipt,
                        source.record_id,
                        ReconciliationEvidenceRef(
                            VENUE_CAPTURE_SCHEMA, reference, page.semantic_sha256
                        ),
                    )
                )
                pages.append(page)
            exact_pages = tuple(pages)
            rebuilt_manifest = ReconciliationSourceManifest(self.scope, tuple(rebuilt_sources))
            contents = tuple(
                self.resolver.resolve_source(source, page)
                for source, page in zip(rebuilt_manifest.sources, exact_pages, strict=True)
            )
            rebuilt = RetainedVenueCapture(
                rebuilt_manifest,
                self.resolver.resolve_observation(rebuilt_manifest, exact_pages),
                tuple(
                    sorted(
                        (fact for content in contents for fact in content.facts),
                        key=lambda fact: fact.observation.fact_id,
                    )
                ),
                self.resolver.resolve_source_order(rebuilt_manifest, exact_pages),
            )
            if rebuilt != capture:
                raise ContinuousVenueSourceError("VENUE_SOURCE_RECONSTRUCTED_CAPTURE_DIFFERS")
            value = ResolvedContinuousVenueSources(capture, exact_pages, reads, self._seal)
            self._owned[id(value)] = value
            self._fingerprints[id(value)] = _fingerprint(value)
            self._identities[id(value)] = (id(value.capture), id(value.pages), id(value.reads))
            finalize(value, self._fingerprints.pop, id(value), None)
            finalize(value, self._identities.pop, id(value), None)
            return value
        except ContinuousVenueSourceError:
            raise
        except Exception:
            raise ContinuousVenueSourceError("VENUE_SOURCE_RESOLUTION_FAILED") from None

    def _require_owned(self, value: ResolvedContinuousVenueSources) -> None:
        if type(value) is not ResolvedContinuousVenueSources or (
            value.seal is not self._seal
            or self._owned.get(id(value)) is not value
            or self._identities.get(id(value))
            != (id(value.capture), id(value.pages), id(value.reads))
        ):
            raise ContinuousVenueSourceError("OWNED_VENUE_SOURCE_RESOLUTION_REQUIRED")

    def require_same_resolved_capture(
        self,
        original: ResolvedContinuousVenueSources,
        fresh: ResolvedContinuousVenueSources,
        *,
        comparison: ContinuousCaptureComparison,
    ) -> None:
        """Compare original capture/pages/read inputs; terminal fingerprint stays separate."""
        if type(comparison) is not ContinuousCaptureComparison:
            raise ContinuousVenueSourceError("EXACT_CAPTURE_COMPARISON_REQUIRED")
        for value in (original, fresh):
            self._require_owned(value)
        comparison.data((original.capture, original.pages), (fresh.capture, fresh.pages))
        for left, right in comparison.pairs(original.reads, fresh.reads):
            self.journal.require_same_resolved_read(left, right, comparison=comparison)
        for value in (original, fresh):
            self._require_owned(value)

    def require_resolved(self, value: ResolvedContinuousVenueSources) -> None:
        """Call before entering SQL; original fingerprint traverses retained bytes."""
        try:
            self._require_owned(value)
            if self._fingerprints.get(id(value)) != _fingerprint(value):
                raise ContinuousVenueSourceError("OWNED_VENUE_SOURCE_FINGERPRINT_DIFFERS")
        except ContinuousVenueSourceError:
            raise
        except Exception:
            raise ContinuousVenueSourceError("OWNED_VENUE_SOURCE_FINGERPRINT_DIFFERS") from None

    def recheck_in_transaction(
        self, connection: Connection, value: ResolvedContinuousVenueSources
    ) -> None:
        """Recheck original journal rows only, after detached require_resolved."""
        self._require_owned(value)
        try:
            for read, source in zip(value.reads, value.capture.manifest.sources, strict=True):
                _, receipt = self.journal.recheck_in_transaction(
                    connection, read, require_current_head=False
                )
                if receipt != source.receipt:
                    raise ContinuousVenueSourceError("VENUE_SOURCE_ORIGINAL_RECEIPT_DIFFERS")
        except ContinuousVenueSourceError:
            raise
        except Exception:
            raise ContinuousVenueSourceError("VENUE_SOURCE_RECHECK_FAILED") from None
