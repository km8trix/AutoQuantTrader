"""Publish applied evidence after the actual account commit in one owned transaction.

Canonical hold changes are bound to the exact owned daily observed-hold result.
Source observations originate in the independent venue and are already retained in the
coordinator database. All decoding, source reconstruction, canonical comparison
and original-time validation precede SQL. No provider permission is inferred.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field, fields, is_dataclass
from hashlib import sha256
from typing import Literal
from weakref import WeakValueDictionary

from sqlalchemy import Connection, Engine

from packages.application.continuous_reconciliation import (
    ContinuousReconciliationTransitionResolver,
)
from packages.application.continuous_reconciliation_publication import (
    validate_continuous_application_times,
)
from packages.application.reconciliation_evidence import (
    ReconciliationEvidencePreparer,
    retain_reconciliation_evidence,
)
from packages.application.venue_reconciliation import VenueReconciliationResolver
from packages.domain.account_coordinator import AccountFence, AccountFenceReceipt
from packages.domain.accounting_contracts import ExecutionAccountingPort
from packages.domain.applied_reconciliation import compare_reconciled_account
from packages.domain.causal_checkpoint import CausalEngineCheckpoint
from packages.domain.continuous_account_contracts import CanonicalAccountTransitionRef
from packages.domain.continuous_composition_contracts import VENUE_CAPTURE_CLOSURE_SCHEMA
from packages.domain.continuous_persistence_contracts import (
    ContinuousAccountReceipt,
    ContinuousAccountScope,
)
from packages.domain.durable_journal_contracts import JournalKey
from packages.domain.personal_contracts import ContractRecord, content_digest
from packages.domain.reconciliation_contracts import (
    ReconciliationObligation,
    ReconciliationOrderBinding,
    ReconciliationScope,
)
from packages.domain.reconciliation_persistence_contracts import (
    APPLICATIONS_SCHEMA,
    COMMIT_SCHEMA,
    MAX_EVIDENCE_BYTES,
    RESULT_SCHEMA,
    ROUND_SCHEMA,
    SOURCES_SCHEMA,
    ReconciliationApplicationManifest,
    ReconciliationCaptureBinding,
    ReconciliationCommit,
    ReconciliationCommitReceipt,
    ReconciliationEvidenceRef,
    ReconciliationRetentionRead,
    ReconciliationSourceManifest,
)
from packages.domain.research_job_contracts import (
    ObjectRef,
    ResearchArtifactStore,
    ResearchRecordCodec,
)
from packages.domain.venue_reconciliation_contracts import VENUE_CAPTURE_SCHEMA, VenueCapturePage
from packages.persistence.account_coordinator import SqlAccountCoordinator
from packages.persistence.applied_reconciliation import (
    PreparedReconciliationCommit,
    ReconciliationCommitSnapshot,
    ResolvedReconciliationSnapshot,
    SqlAppliedReconciliation,
    reconciliation_journal_key,
)
from packages.persistence.continuous_account import (
    PreparedContinuousCommit,
    ResolvedContinuousAccount,
    SqlContinuousAccount,
)
from packages.persistence.continuous_composition import (
    PreparedContinuousCompositionView,
    SqlContinuousCommitComposer,
)
from packages.persistence.continuous_venue_sources import (
    ResolvedContinuousVenueSources,
    SqlContinuousVenueSources,
)
from packages.persistence.durable_journal import ResolvedJournalRead, SqlDurableJournal


class ContinuousReconciliationPublicationError(ValueError):
    """Static provenance or original ownership mismatch."""


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PreparedContinuousReconciliationPublication:
    continuous: PreparedContinuousCommit
    reconciliation: PreparedReconciliationCommit
    view: PreparedContinuousCompositionView
    journal: ResolvedJournalRead
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResolvedContinuousReconciliationPublication:
    continuous: ResolvedContinuousAccount
    reconciliation: ResolvedReconciliationSnapshot
    sources: ResolvedContinuousVenueSources
    journal: ResolvedJournalRead
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class ContinuousReconciliationPublicationReceipt:
    continuous: ContinuousAccountReceipt
    reconciliation: ReconciliationCommitReceipt


@dataclass(frozen=True, slots=True)
class _Active:
    prepared: PreparedContinuousReconciliationPublication | None
    original: ResolvedContinuousReconciliationPublication | None
    receipt: ContinuousAccountReceipt


@contextmanager
def _read_transaction(engine: Engine) -> Iterator[Connection]:
    with engine.connect() as connection:
        if engine.dialect.name == "sqlite":
            connection.exec_driver_sql("BEGIN")
        else:
            connection = connection.execution_options(isolation_level="REPEATABLE READ")
            connection.begin()
        try:
            yield connection
        finally:
            connection.rollback()


def _fingerprint_value(value: object) -> object:
    if type(value) is bytes:
        return ("bytes", len(value), sha256(value).hexdigest())
    if isinstance(value, Mapping):
        return tuple((str(key), _fingerprint_value(item)) for key, item in sorted(value.items()))
    if is_dataclass(value) and not isinstance(value, type):
        return (
            type(value).__qualname__,
            tuple(
                (item.name, _fingerprint_value(getattr(value, item.name)))
                for item in fields(value)
                if item.name not in {"seal", "_owner", "_validated_values"}
            ),
        )
    if type(value) is tuple:
        return tuple(_fingerprint_value(item) for item in value)
    return value


class SqlContinuousReconciliationPublication:
    """Concrete required A reader and coupled C→A publication owner.

    This object cannot authorize a caller-created passing receipt. Fresh reads
    require the exact account-store-issued publication in its still-open owned
    transaction; retries require the original store-restored checkpoint and its
    exact retained source closure. The account owner repeats its final deadline
    guard after A writes and immediately before outer COMMIT.
    """

    engine: Engine
    account: SqlContinuousAccount
    coordinator: SqlAccountCoordinator
    sources: SqlContinuousVenueSources
    journal: SqlDurableJournal
    applied: SqlAppliedReconciliation

    def __init__(
        self,
        engine: Engine,
        *,
        account: SqlContinuousAccount,
        composer: SqlContinuousCommitComposer,
        coordinator: SqlAccountCoordinator,
        sources: SqlContinuousVenueSources,
        artifacts: ResearchArtifactStore,
        codec: ResearchRecordCodec,
        accounting: ExecutionAccountingPort,
    ) -> None:
        if (
            type(account) is not SqlContinuousAccount
            or type(composer) is not SqlContinuousCommitComposer
            or type(sources) is not SqlContinuousVenueSources
            or account.engine is not engine
            or composer.engine is not engine
            or sources.engine is not engine
            or account.composer is not composer
            or composer.venue_sources is not sources
            or account.coordinator is not coordinator
            or composer.coordinator is not coordinator
            or composer.accounting is not accounting
        ):
            raise ContinuousReconciliationPublicationError(
                "EXACT_PUBLICATION_DEPENDENCIES_REQUIRED"
            )
        self.engine, self.account, self.composer = engine, account, composer
        self.coordinator, self.sources = coordinator, sources
        self.artifacts, self.codec, self.accounting = artifacts, codec, accounting
        self.transition = ContinuousReconciliationTransitionResolver(accounting=accounting)
        self.resolver = VenueReconciliationResolver(transition_resolver=self.transition)
        self.journal = SqlDurableJournal(
            engine, codec=codec, record_types={COMMIT_SCHEMA: ReconciliationCommit}
        )
        self.evidence = ReconciliationEvidencePreparer(
            codec=codec,
            artifacts=artifacts,
            checkpoint_type=CausalEngineCheckpoint,
            source_types={VENUE_CAPTURE_SCHEMA: VenueCapturePage},
            resolver=self.resolver,
            accounting=accounting,
        )
        self.applied = SqlAppliedReconciliation(
            engine,
            coordinator=coordinator,
            journal=self.journal,
            codec=codec,
            evidence=self.evidence,
            reader=self,
        )
        self._seal = object()
        self._owned: WeakValueDictionary[
            int,
            PreparedContinuousReconciliationPublication
            | ResolvedContinuousReconciliationPublication,
        ] = WeakValueDictionary()
        self._originals: dict[int, tuple[object, ...]] = {}
        self._fingerprints: dict[int, str] = {}
        self._active: _Active | None = None

    def _own(
        self,
        value: PreparedContinuousReconciliationPublication
        | ResolvedContinuousReconciliationPublication,
    ) -> None:
        from weakref import finalize

        self._owned[id(value)] = value
        self._originals[id(value)] = (
            value.continuous,
            value.reconciliation,
            value.view
            if isinstance(value, PreparedContinuousReconciliationPublication)
            else value.sources,
            value.journal,
        )
        self._fingerprints[id(value)] = self._fingerprint(value)
        finalize(value, self._originals.pop, id(value), None)
        finalize(value, self._fingerprints.pop, id(value), None)

    @staticmethod
    def _fingerprint(
        value: PreparedContinuousReconciliationPublication
        | ResolvedContinuousReconciliationPublication,
    ) -> str:
        return content_digest(
            (
                value.reconciliation.resolved.semantic_sha256,
                _fingerprint_value(value.reconciliation.receipt),
                _fingerprint_value(value.reconciliation.row_values),
                _fingerprint_value(value.journal),
            )
        )

    def _require_fingerprint(
        self,
        value: PreparedContinuousReconciliationPublication
        | ResolvedContinuousReconciliationPublication,
    ) -> None:
        if self._fingerprints.get(id(value)) != self._fingerprint(value):
            raise ContinuousReconciliationPublicationError("ORIGINAL_PUBLICATION_CONTENT_CHANGED")

    def _require(
        self,
        value: PreparedContinuousReconciliationPublication
        | ResolvedContinuousReconciliationPublication,
    ) -> None:
        if (
            type(value)
            not in (
                PreparedContinuousReconciliationPublication,
                ResolvedContinuousReconciliationPublication,
            )
            or value.seal is not self._seal
            or self._owned.get(id(value)) is not value
        ):
            raise ContinuousReconciliationPublicationError("OWNED_PUBLICATION_REQUIRED")
        actual = (
            value.continuous,
            value.reconciliation,
            value.view
            if isinstance(value, PreparedContinuousReconciliationPublication)
            else value.sources,
            value.journal,
        )
        if any(
            item is not original
            for item, original in zip(actual, self._originals[id(value)], strict=True)
        ):
            raise ContinuousReconciliationPublicationError("PUBLICATION_TOKEN_CHANGED")

    def _checkpoint(self, prepared: PreparedContinuousCommit) -> CausalEngineCheckpoint:
        reference = prepared.commit.transition
        raw = self.artifacts.read(reference.checkpoint, max_bytes=MAX_EVIDENCE_BYTES)
        if (
            len(raw) != reference.checkpoint.byte_count
            or sha256(raw).hexdigest() != reference.checkpoint.object_sha256
        ):
            raise ContinuousReconciliationPublicationError("ACTUAL_CHECKPOINT_BYTES_DIFFER")
        value = self.codec.decode_record(raw, CausalEngineCheckpoint)
        if (
            type(value) is not CausalEngineCheckpoint
            or self.codec.encode_record(value) != raw
            or value.semantic_sha256 != reference.checkpoint_sha256
        ):
            raise ContinuousReconciliationPublicationError("ACTUAL_CHECKPOINT_IDENTITY_DIFFERS")
        return value

    def _put(self, value: ContractRecord, schema: str) -> ReconciliationEvidenceRef:
        return retain_reconciliation_evidence(
            value, schema_id=schema, codec=self.codec, artifacts=self.artifacts
        )

    def prepare(
        self,
        continuous: PreparedContinuousCommit,
        *,
        previous: ResolvedContinuousReconciliationPublication | None,
    ) -> PreparedContinuousReconciliationPublication:
        """Prepare the complete comparison from actual C/B/source values, outside SQL."""
        view = self.composer.inspect_prepared(continuous.composition)
        capture = view.venue.capture
        transition = continuous.commit.transition
        if (
            continuous.commit.source_evidence != view.composition.source_evidence
            or continuous.commit.source_evidence.schema_id != VENUE_CAPTURE_CLOSURE_SCHEMA
            or continuous.commit.source_evidence.semantic_sha256 != capture.semantic_sha256
            or transition.expected_heads != view.evidence.expected_heads
            or transition.resulting_heads != view.evidence.resulting_heads
            or (
                view.evidence.before_obligations != view.evidence.after_obligations
                and view.evidence.observed_holds is None
            )
            or (
                view.evidence.observed_holds is not None
                and (
                    view.evidence.observed_holds.account_id != continuous.commit.scope.account_id
                    or view.evidence.observed_holds.coordinator_command_id != transition.command_id
                    or view.evidence.observed_holds.coordinator_sequence
                    != continuous.commit.sequence
                )
            )
        ):
            raise ContinuousReconciliationPublicationError(
                "ACTUAL_CANONICAL_HOLD_COMPOSITION_REQUIRED"
            )
        if previous is not None:
            self.require_resolved(previous)
            if previous.reconciliation.receipt.commit.scope != capture.manifest.scope:
                raise ContinuousReconciliationPublicationError(
                    "PREVIOUS_RECONCILIATION_SCOPE_DIFFERS"
                )
        checkpoint = self._checkpoint(continuous)
        validate_continuous_application_times(
            checkpoint,
            capture=capture,
            applications=view.evidence.applications,
            accounting=self.accounting,
        )
        current = self.transition.resolve_transition(transition, checkpoint)
        mappings: dict[str, ReconciliationOrderBinding] = {}
        for item in capture.facts:
            if item.mapping is not None:
                old = mappings.setdefault(item.mapping.order_id, item.mapping)
                if old != item.mapping:
                    raise ContinuousReconciliationPublicationError("ACTUAL_ORDER_MAPPING_CONFLICT")
        for binding in view.venue.pages[0].request.binding.orders:
            mapping = ReconciliationOrderBinding(
                binding.submission.order_id, binding.provider_order_id, binding.semantic_sha256
            )
            # Financial facts already carry the canonical mapping semantics.
            mappings.setdefault(mapping.order_id, mapping)
        obligations = []
        for retained_hold in view.evidence.after_obligations.bindings:
            commitment = retained_hold.commitment
            state: Literal[
                "approved_unsent",
                "working",
                "partial",
                "unknown",
                "pending_cancel",
                "terminal_unreleased",
            ]
            if commitment.state == "active":
                state = "working"
            elif commitment.state == "terminal":
                state = "terminal_unreleased"
            else:
                state = commitment.state
            mapped = mappings.get(commitment.order_id)
            obligations.append(
                ReconciliationObligation(
                    commitment.order_id,
                    None if mapped is None else mapped.provider_order_id,
                    state,
                    retained_hold.source_sha256,
                )
            )
        all_applied = {a.fact_id for a in view.evidence.applications} == {
            f.observation.fact_id for f in capture.facts
        }
        manifest = ReconciliationApplicationManifest(
            applications=view.evidence.applications,
            obligations=tuple(sorted(obligations, key=lambda item: item.order_id)),
            order_bindings=tuple(mappings[key] for key in sorted(mappings)),
            instrument_symbols=current.context.instruments,
            required_from=capture.observed.requested_from,
            required_through=capture.observed.requested_through,
            applied_through=capture.observed.requested_through if all_applied else None,
            completed_at=transition.applied_at,
            previous_result=None if previous is None else previous.reconciliation.resolved.result,
        )
        result = compare_reconciled_account(
            expected=current.current.snapshot,
            observed=capture.observed,
            heads=transition.resulting_heads,
            obligations=manifest.obligations,
            applications=manifest.applications,
            instrument_symbols=manifest.instrument_symbols,
            required_from=manifest.required_from,
            required_through=manifest.required_through,
            applied_through=manifest.applied_through,
            now=manifest.completed_at,
            previous=manifest.previous_result,
            order_bindings=manifest.order_bindings,
        )
        source = continuous.commit.source_evidence
        commit = ReconciliationCommit(
            command_id=transition.command_id,
            scope=capture.manifest.scope,
            previous_commit_sha256=None
            if previous is None
            else previous.reconciliation.receipt.commit.semantic_sha256,
            expected_heads=transition.expected_heads,
            resulting_heads=transition.resulting_heads,
            canonical_transition_ref=transition,
            sources=self._put(capture.manifest, SOURCES_SCHEMA),
            observed=self._put(capture.observed, ROUND_SCHEMA),
            applications=self._put(manifest, APPLICATIONS_SCHEMA),
            result=self._put(result, RESULT_SCHEMA),
            capture_binding=ReconciliationCaptureBinding(
                transition.source_closure_sha256,
                ReconciliationEvidenceRef(
                    source.schema_id, source.object_ref, source.semantic_sha256
                ),
                capture.manifest.semantic_sha256,
            ),
        )
        key = reconciliation_journal_key(commit.scope)
        with _read_transaction(self.engine) as connection:
            raw = self.journal.capture_in_transaction(connection, key, command_id=commit.command_id)
            current_row = self.applied.capture_current_in_transaction(
                connection, scope=commit.scope
            )
        journal = self.journal.resolve_snapshot(raw)
        if (
            current_row != (None if previous is None else previous.reconciliation.snapshot)
            or journal.receipt is not None
        ):
            raise ContinuousReconciliationPublicationError("ACTUAL_RECONCILIATION_PREFIX_DIFFERS")
        prepared = self.applied.prepare(
            commit,
            expected_head=journal.head,
            previous=None if previous is None else previous.reconciliation,
        )
        value = PreparedContinuousReconciliationPublication(
            continuous, prepared, view, journal, self._seal
        )
        self._own(value)
        return value

    def require_prepared(self, value: PreparedContinuousReconciliationPublication) -> None:
        self._require(value)
        self._require_fingerprint(value)
        self.composer.require_prepared_view(value.view)
        commit = value.reconciliation.resolved.commit
        source = value.continuous.commit.source_evidence
        binding = commit.capture_binding
        if binding is None or (
            commit.canonical_transition_ref != value.continuous.commit.transition
            or binding.capture
            != ReconciliationEvidenceRef(
                source.schema_id, source.object_ref, source.semantic_sha256
            )
            or binding.manifest_sha256 != value.view.venue.capture.manifest.semantic_sha256
            or value.reconciliation.resolved.sources != value.view.venue.capture.manifest
            or value.reconciliation.resolved.applications.applications
            != value.view.evidence.applications
        ):
            raise ContinuousReconciliationPublicationError("ORIGINAL_PUBLICATION_BINDING_CHANGED")

    def publish(
        self, prepared: PreparedContinuousReconciliationPublication, *, fence: AccountFence
    ) -> ContinuousReconciliationPublicationReceipt:
        self.require_prepared(prepared)
        if self._active is not None:
            raise ContinuousReconciliationPublicationError("REENTRANT_PUBLICATION_FORBIDDEN")
        with self.account.write_transaction() as connection:
            receipt = self.account.commit_in_transaction(
                connection, prepared=prepared.continuous, fence=fence
            )
            self._active = _Active(prepared, None, receipt)
            try:
                applied = self.applied.commit_in_transaction(
                    connection, prepared=prepared.reconciliation, fence=fence
                )
                if applied is not prepared.reconciliation.receipt:
                    raise ContinuousReconciliationPublicationError(
                        "ORIGINAL_APPLIED_RECEIPT_REQUIRED"
                    )
                self._recheck_published(connection, prepared, receipt, fence=fence)
            finally:
                self._active = None
        return ContinuousReconciliationPublicationReceipt(receipt, applied)

    def _recheck_published(
        self,
        connection: Connection,
        prepared: PreparedContinuousReconciliationPublication,
        receipt: ContinuousAccountReceipt,
        *,
        fence: AccountFence,
    ) -> None:
        """Last coupled readbacks after A writes, before C's outer fence guard."""
        self._require(prepared)
        self.account.require_committed_in_transaction(
            connection, prepared=prepared.continuous, receipt=receipt
        )
        self.composer.recheck_prepared_view_in_transaction(
            connection,
            prepared.view,
            fence=fence,
            prepared_account=prepared.continuous,
            account_receipt=receipt,
        )
        original = prepared.reconciliation
        current = self.applied.capture_current_in_transaction(
            connection, scope=original.receipt.commit.scope
        )
        if current is None or current.row != original.row_values:
            raise ContinuousReconciliationPublicationError("PUBLISHED_APPLIED_INDEX_CHANGED")
        if original.previous is not None:
            prior = self.applied.capture_commit_in_transaction(
                connection,
                scope=original.previous.snapshot.scope,
                command_id=original.previous.receipt.commit.command_id,
            )
            if prior != original.previous.snapshot:
                raise ContinuousReconciliationPublicationError("PUBLISHED_APPLIED_PREVIOUS_CHANGED")
        if (
            self.journal.recheck_prepared_append_in_transaction(
                connection, original.journal, require_current_head=True
            )
            is not original.receipt.journal
        ):
            raise ContinuousReconciliationPublicationError("PUBLISHED_APPLIED_JOURNAL_CHANGED")

    def restore(
        self,
        scope: ReconciliationScope,
        *,
        account_scope: ContinuousAccountScope,
        command_id: str | None = None,
    ) -> ResolvedContinuousReconciliationPublication | None:
        with _read_transaction(self.engine) as connection:
            raw = (
                self.applied.capture_current_in_transaction(connection, scope=scope)
                if command_id is None
                else self.applied.capture_commit_in_transaction(
                    connection, scope=scope, command_id=command_id
                )
            )
        if raw is None:
            return None
        applied = self.applied.resolve_snapshot(raw)
        commit = applied.receipt.commit
        continuous = self.account.restore(account_scope, command_id=commit.command_id)
        if continuous is None:
            raise ContinuousReconciliationPublicationError("ORIGINAL_CANONICAL_TRANSITION_MISSING")
        return self._resolve_pair(raw, applied, continuous)

    def resolve_for_account(
        self,
        continuous: ResolvedContinuousAccount,
        *,
        scope: ReconciliationScope,
    ) -> ResolvedContinuousReconciliationPublication | None:
        """Resolve only this authenticated account command's paired result.

        No account restore recursion or latest-result substitution occurs. The
        producer must reject a missing role, or explicitly resolve a reviewed
        immutable ancestor through the account owner, before calling this seam.
        """
        self.account.require_resolved(continuous)
        with _read_transaction(self.engine) as connection:
            raw = self.applied.capture_commit_in_transaction(
                connection,
                scope=scope,
                command_id=continuous.receipt.commit.transition.command_id,
            )
        if raw is None:
            return None
        return self._resolve_pair(raw, self.applied.resolve_snapshot(raw), continuous)

    def _resolve_pair(
        self,
        raw: ReconciliationCommitSnapshot,
        applied: ResolvedReconciliationSnapshot,
        continuous: ResolvedContinuousAccount,
    ) -> ResolvedContinuousReconciliationPublication:
        commit = applied.receipt.commit
        if continuous.receipt.commit.transition != commit.canonical_transition_ref:
            raise ContinuousReconciliationPublicationError("ORIGINAL_CANONICAL_TRANSITION_MISSING")
        binding = commit.capture_binding
        source = continuous.receipt.commit.source_evidence
        if binding is None or binding.capture != ReconciliationEvidenceRef(
            source.schema_id, source.object_ref, source.semantic_sha256
        ):
            raise ContinuousReconciliationPublicationError(
                "ORIGINAL_CAPTURE_TRANSITION_BINDING_DIFFERS"
            )
        raw_capture = self.artifacts.read(binding.capture.object_ref, max_bytes=MAX_EVIDENCE_BYTES)
        from packages.domain.venue_reconciliation_contracts import RetainedVenueCapture

        capture = self.codec.decode_record(raw_capture, RetainedVenueCapture)
        if (
            type(capture) is not RetainedVenueCapture
            or self.codec.encode_record(capture) != raw_capture
            or capture.semantic_sha256 != binding.capture.semantic_sha256
            or sha256(raw_capture).hexdigest() != binding.capture.object_ref.object_sha256
            or len(raw_capture) != binding.capture.object_ref.byte_count
            or capture.manifest != applied.resolved.sources
        ):
            raise ContinuousReconciliationPublicationError("ORIGINAL_CAPTURE_OBJECT_DIFFERS")
        sources = self.sources.resolve(capture)
        validate_continuous_application_times(
            continuous.checkpoint,
            capture=capture,
            applications=applied.resolved.applications.applications,
            accounting=self.accounting,
        )
        with _read_transaction(self.engine) as connection:
            journal_raw = self.journal.capture_in_transaction(
                connection, applied.receipt.journal_key, command_id=commit.command_id
            )
            if (
                self.applied.capture_commit_in_transaction(
                    connection, scope=commit.scope, command_id=commit.command_id
                )
                != raw
            ):
                raise ContinuousReconciliationPublicationError(
                    "ORIGINAL_RECONCILIATION_ROW_CHANGED"
                )
        journal = self.journal.resolve_snapshot(journal_raw)
        if journal.receipt != applied.receipt.journal:
            raise ContinuousReconciliationPublicationError(
                "ORIGINAL_RECONCILIATION_RECEIPT_DIFFERS"
            )
        value = ResolvedContinuousReconciliationPublication(
            continuous, applied, sources, journal, self._seal
        )
        self._own(value)
        return value

    def require_resolved(self, value: ResolvedContinuousReconciliationPublication) -> None:
        self._require(value)
        self._require_fingerprint(value)
        self.account.require_resolved(value.continuous)
        self.sources.require_resolved(value.sources)
        commit = value.reconciliation.receipt.commit
        if (
            commit.canonical_transition_ref != value.continuous.receipt.commit.transition
            or value.reconciliation.resolved.sources != value.sources.capture.manifest
        ):
            raise ContinuousReconciliationPublicationError("ORIGINAL_RESOLVED_PUBLICATION_CHANGED")
        validate_continuous_application_times(
            value.continuous.checkpoint,
            capture=value.sources.capture,
            applications=value.reconciliation.resolved.applications.applications,
            accounting=self.accounting,
        )

    def retry(
        self, original: ResolvedContinuousReconciliationPublication, *, fence: AccountFence
    ) -> ContinuousReconciliationPublicationReceipt:
        self.require_resolved(original)
        if self._active is not None:
            raise ContinuousReconciliationPublicationError("REENTRANT_PUBLICATION_FORBIDDEN")
        with self.account.write_transaction() as connection:
            receipt = self.account.retry_in_transaction(
                connection,
                original=original.continuous,
                command_sha256=original.continuous.receipt.commit.transition.command_sha256,
                fence=fence,
            )
            self._active = _Active(None, original, receipt)
            try:
                self.applied.recheck_snapshot_in_transaction(
                    connection, resolved=original.reconciliation, fence=fence
                )
            finally:
                self._active = None
        return ContinuousReconciliationPublicationReceipt(receipt, original.reconciliation.receipt)

    def recheck_in_transaction(
        self,
        connection: Connection,
        value: ResolvedContinuousReconciliationPublication,
        *,
        fence: AccountFence,
        require_current: bool,
    ) -> ReconciliationRetentionRead:
        """Recheck an already detached owned role; no decoding or object access."""
        self._require(value)
        if self._active is not None:
            raise ContinuousReconciliationPublicationError("REENTRANT_PUBLICATION_FORBIDDEN")
        self.account.recheck_in_transaction(
            connection, value.continuous, require_current=require_current
        )
        self._active = _Active(None, value, value.continuous.receipt)
        try:
            return self.applied.recheck_snapshot_in_transaction(
                connection, resolved=value.reconciliation, fence=fence
            )
        finally:
            self._active = None

    def read_in_transaction(
        self,
        connection: Connection,
        *,
        transition: CanonicalAccountTransitionRef,
        sources: ReconciliationSourceManifest,
        objects: tuple[ObjectRef, ...],
        reconciliation_key: JournalKey,
        reconciliation_receipt: ReconciliationCommitReceipt,
        fence_receipt: AccountFenceReceipt,
    ) -> ReconciliationRetentionRead:
        """Required concrete reader; only actual paired/retained publication context."""
        active = self._active
        if active is None:
            raise ContinuousReconciliationPublicationError(
                "OWNED_ACTIVE_ACCOUNT_PUBLICATION_REQUIRED"
            )
        if active.prepared is not None:
            value = active.prepared
            self._require(value)
            self.account.require_committed_in_transaction(
                connection, prepared=value.continuous, receipt=active.receipt
            )
            heads = self.composer.recheck_prepared_view_in_transaction(
                connection,
                value.view,
                fence=fence_receipt.fence,
                prepared_account=value.continuous,
                account_receipt=active.receipt,
            )
            resolved, original_journal, source_ref = (
                value.reconciliation.resolved,
                value.journal,
                value.continuous.commit.source_evidence,
            )
            original_receipt = value.reconciliation.receipt
            current = True
        else:
            original = active.original
            assert original is not None
            self._require(original)
            self.account.recheck_in_transaction(
                connection, original.continuous, require_current=False
            )
            self.sources.recheck_in_transaction(connection, original.sources)
            heads = original.continuous.receipt.commit.transition.resulting_heads
            resolved, original_journal, source_ref = (
                original.reconciliation.resolved,
                original.journal,
                original.continuous.receipt.commit.source_evidence,
            )
            original_receipt = original.reconciliation.receipt
            current = False
        binding = resolved.commit.capture_binding
        if (
            transition != resolved.commit.canonical_transition_ref
            or sources != resolved.sources
            or objects != resolved.retained_objects
            or reconciliation_key != original_receipt.journal_key
            or reconciliation_receipt != original_receipt
            or binding is None
            or binding.capture.schema_id != source_ref.schema_id
            or binding.capture.object_ref != source_ref.object_ref
            or binding.capture.semantic_sha256 != source_ref.semantic_sha256
            or binding.source_closure_sha256
            != active.receipt.commit.transition.source_closure_sha256
        ):
            raise ContinuousReconciliationPublicationError(
                "ACTUAL_RETAINED_PUBLICATION_METADATA_DIFFERS"
            )
        head, receipt = self.journal.recheck_in_transaction(
            connection, original_journal, require_current_head=current
        )
        return ReconciliationRetentionRead(
            transition, sources, objects, heads, head, receipt, binding
        )
