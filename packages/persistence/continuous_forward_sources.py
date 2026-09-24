"""Concrete capture-journal authentication for distinct daily and quote closures.

All payload decoding, private-object reads and normalization occur after the read
transaction closes. Final publication rechecks only exact original journal rows.
A later capture cannot refresh the original selected observations or receipt times.
"""

from dataclasses import dataclass, field
from weakref import WeakValueDictionary, finalize

from sqlalchemy import Connection, Engine

from packages.application.continuous_forward_replay import replay_continuous_forward_closure
from packages.application.personal_forward_capture import read_capture
from packages.domain.continuous_forward_contracts import (
    MAX_CLOSURE_RECORD_BYTES,
    ContinuousForwardClosure,
)
from packages.domain.continuous_quote_contracts import ContinuousQuoteClosure
from packages.domain.durable_journal_contracts import MAX_APPEND_BYTES, MAX_RECORD_BYTES
from packages.domain.forward_capture_contracts import (
    CAPTURE_SCHEMA,
    CaptureEvidenceClass,
    ForwardCaptureRecord,
)
from packages.domain.forward_contracts import ForwardDataState
from packages.domain.personal_contracts import content_digest
from packages.domain.research_job_contracts import ResearchArtifactStore, ResearchRecordCodec
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.detached_journal_capture import (
    DetachedJournalCapture,
    DetachedJournalCaptureError,
    detached_journal_value,
)
from packages.persistence.durable_journal import ResolvedJournalRead, SqlDurableJournal

MAX_FORWARD_SNAPSHOT_BYTES = (
    MAX_CLOSURE_RECORD_BYTES + MAX_APPEND_BYTES + 2 * MAX_RECORD_BYTES + 16 * 1024
)
MAX_FORWARD_SNAPSHOT_METADATA_BYTES = 2 * 1024 * 1024


class ContinuousForwardSourceError(ValueError):
    pass


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResolvedContinuousForwardSources:
    closure: ContinuousForwardClosure | ContinuousQuoteClosure
    state: ForwardDataState
    reads: tuple[ResolvedJournalRead, ...]
    seal: object = field(repr=False, compare=False)


class SqlContinuousForwardSources:
    def __init__(
        self,
        engine: Engine,
        *,
        artifacts: ResearchArtifactStore,
        codec: ResearchRecordCodec,
        evidence_class: CaptureEvidenceClass,
    ) -> None:
        if evidence_class not in ("provider_https_read", "synthetic_fixture"):
            raise ContinuousForwardSourceError("EXPLICIT_CAPTURE_CLASS_REQUIRED")
        self.engine, self.artifacts, self.codec, self.evidence_class = (
            engine,
            artifacts,
            codec,
            evidence_class,
        )
        self._original_evidence_class = evidence_class
        self.journal = SqlDurableJournal(
            engine, codec=codec, record_types={CAPTURE_SCHEMA: ForwardCaptureRecord}
        )
        self._seal = object()
        self._owned: WeakValueDictionary[int, ResolvedContinuousForwardSources] = (
            WeakValueDictionary()
        )
        self._identities: dict[int, tuple[object, object, object]] = {}
        self._fingerprints: dict[int, str] = {}

    def resolve(
        self, closure: ContinuousForwardClosure | ContinuousQuoteClosure
    ) -> ResolvedContinuousForwardSources:
        try:
            if self.evidence_class != self._original_evidence_class:
                raise ContinuousForwardSourceError("CAPTURE_CLASS_CANNOT_BE_PROMOTED")
            if type(closure) not in (ContinuousForwardClosure, ContinuousQuoteClosure):
                raise ContinuousForwardSourceError("EXACT_CAPTURE_CLOSURE_REQUIRED")
            closure.__post_init__()
            if closure.evidence_class != self.evidence_class:
                raise ContinuousForwardSourceError("CAPTURE_CLASS_CANNOT_BE_PROMOTED")
            pool = DetachedJournalCapture(
                max_bytes=MAX_FORWARD_SNAPSHOT_BYTES,
                max_metadata_bytes=MAX_FORWARD_SNAPSHOT_METADATA_BYTES,
            )
            with _repeatable_read_transaction(self.engine) as connection:
                captured = tuple(
                    pool.capture(
                        self.journal.capture_in_transaction(
                            connection,
                            publication.record.request.journal_key,
                            command_id=publication.record.request.capture_id,
                        )
                    )
                    for publication in closure.publications
                )
            # The original, fixed-through receipt remains exact even when another
            # capture appends after this detached SQL read.
            reads = tuple(self.journal.resolve_snapshot(value) for value in captured)
            for publication, read in zip(closure.publications, reads, strict=True):
                if (
                    read.receipt != publication.journal_receipt
                    or read_capture(
                        publication.record.request,
                        journal=self.journal,
                        artifacts=self.artifacts,
                        codec=self.codec,
                    )
                    != publication
                ):
                    raise ContinuousForwardSourceError("CAPTURE_JOURNAL_PUBLICATION_DIFFERS")
            state = replay_continuous_forward_closure(
                closure, artifacts=self.artifacts, codec=self.codec
            )
            result = ResolvedContinuousForwardSources(closure, state, reads, self._seal)
            self._owned[id(result)] = result
            self._identities[id(result)] = (result.closure, result.state, result.reads)
            self._fingerprints[id(result)] = self._fingerprint(result)
            finalize(result, self._identities.pop, id(result), None)
            finalize(result, self._fingerprints.pop, id(result), None)
            return result
        except ContinuousForwardSourceError:
            raise
        except DetachedJournalCaptureError:
            raise ContinuousForwardSourceError("CAPTURE_SQL_SNAPSHOT_LIMIT_OR_CONFLICT") from None
        except Exception:
            raise ContinuousForwardSourceError("CAPTURE_SOURCE_RESOLUTION_FAILED") from None

    def _require_owned(self, value: ResolvedContinuousForwardSources) -> None:
        if self.evidence_class != self._original_evidence_class:
            raise ContinuousForwardSourceError("CAPTURE_CLASS_CANNOT_BE_PROMOTED")
        if (
            type(value) is not ResolvedContinuousForwardSources
            or value.seal is not self._seal
            or self._owned.get(id(value)) is not value
        ):
            raise ContinuousForwardSourceError("OWNED_CAPTURE_SOURCE_RESOLUTION_REQUIRED")

        if value.closure.evidence_class != self._original_evidence_class:
            raise ContinuousForwardSourceError("CAPTURE_CLASS_CANNOT_BE_PROMOTED")

        if any(
            actual is not original
            for actual, original in zip(
                (value.closure, value.state, value.reads), self._identities[id(value)], strict=True
            )
        ):
            raise ContinuousForwardSourceError("ORIGINAL_CAPTURE_SOURCE_FIELDS_CHANGED")

    @staticmethod
    def _fingerprint(value: ResolvedContinuousForwardSources) -> str:
        return content_digest(
            (
                value.closure.semantic_sha256,
                value.state.semantic_sha256,
                detached_journal_value(value.reads),
            )
        )

    def require_resolved(self, value: ResolvedContinuousForwardSources) -> None:
        """Original full closure/state/read fingerprint, exclusively before SQL."""
        self._require_owned(value)
        if self._fingerprints.get(id(value)) != self._fingerprint(value):
            raise ContinuousForwardSourceError("ORIGINAL_CAPTURE_SOURCE_CONTENT_CHANGED")

    def recheck_in_transaction(
        self, connection: Connection, value: ResolvedContinuousForwardSources
    ) -> None:
        self._require_owned(value)
        try:
            for read, publication in zip(value.reads, value.closure.publications, strict=True):
                _, receipt = self.journal.recheck_in_transaction(
                    connection, read, require_current_head=False
                )
                if receipt != publication.journal_receipt:
                    raise ContinuousForwardSourceError("CAPTURE_ORIGINAL_RECEIPT_DIFFERS")
        except ContinuousForwardSourceError:
            raise
        except Exception:
            raise ContinuousForwardSourceError("CAPTURE_SOURCE_RECHECK_FAILED") from None
