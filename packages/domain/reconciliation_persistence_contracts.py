"""Bounded provenance references; canonical account state stays separately owned."""

from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar

from packages.domain.accounting_contracts import (
    AccountingContext,
    AccountingTransition,
    ExecutionPolicy,
)
from packages.domain.continuous_account_contracts import CanonicalAccountTransitionRef
from packages.domain.durable_journal_contracts import (
    MAX_RECORD_BYTES,
    JournalHead,
    JournalKey,
    JournalReceipt,
    journal_identifier,
)
from packages.domain.personal_contracts import ContractRecord, require_digest
from packages.domain.reconciliation_application_contracts import ReconciliationFactCommand
from packages.domain.reconciliation_contracts import (
    MAX_RECONCILIATION_ITEMS,
    MAX_RECONCILIATION_PAGES,
    FactApplication,
    ObservationRound,
    ReconciliationHeads,
    ReconciliationObligation,
    ReconciliationOrderBinding,
    ReconciliationPage,
    ReconciliationResult,
    ReconciliationScope,
    require_reconciliation_id,
)
from packages.domain.research_job_contracts import ObjectRef

MAX_EVIDENCE_BYTES = 32 * 1024 * 1024
MAX_COMMIT_BYTES = 16 * 1024
COMMIT_SCHEMA = "reconciliation-commit/1"
SOURCES_SCHEMA = "reconciliation-sources/1"
APPLICATIONS_SCHEMA = "reconciliation-applications/1"
ROUND_SCHEMA = "reconciliation-round/1"
RESULT_SCHEMA = "reconciliation-result/1"


class ReconciliationPersistenceRecord(ContractRecord):
    __slots__ = ()
    contract_version: ClassVar[str] = "personal-reconciliation-persistence/1"


@dataclass(frozen=True, slots=True)
class ReconciliationEvidenceRef(ReconciliationPersistenceRecord):
    schema_id: str
    object_ref: ObjectRef
    semantic_sha256: str

    def __post_init__(self) -> None:
        super(ReconciliationEvidenceRef, self).__post_init__()
        journal_identifier(self.schema_id)
        require_digest(self.semantic_sha256, "evidence semantic identity")
        if (
            self.object_ref.codec_version != "personal-record/1"
            or self.object_ref.byte_count > MAX_EVIDENCE_BYTES
        ):
            raise ValueError("reconciliation evidence requires a bounded typed object")


@dataclass(frozen=True, slots=True)
class ReconciliationCaptureBinding(ReconciliationPersistenceRecord):
    """Distinct normalized frontier and retained capture/manifest identities.

    Structural agreement is not source authentication. The concrete reader must
    bind this exact capture object to the committed account source-evidence row.
    """

    source_closure_sha256: str
    capture: ReconciliationEvidenceRef
    manifest_sha256: str

    def __post_init__(self) -> None:
        super(ReconciliationCaptureBinding, self).__post_init__()
        require_digest(self.source_closure_sha256, "normalized source closure")
        require_digest(self.manifest_sha256, "retained source manifest")
        if self.capture.schema_id != "continuous-venue-capture/1":
            raise ValueError("capture binding requires exact retained venue capture schema")


@dataclass(frozen=True, slots=True)
class ReconciliationSourceRef(ReconciliationPersistenceRecord):
    page_receipt_id: str
    key: JournalKey
    receipt: JournalReceipt
    record_id: str
    evidence: ReconciliationEvidenceRef

    def __post_init__(self) -> None:
        super(ReconciliationSourceRef, self).__post_init__()
        require_reconciliation_id(self.page_receipt_id, "source page receipt")
        journal_identifier(self.record_id)
        if self.key.namespace != "capture" or (
            self.receipt.previous_head.key_sha256 != self.key.semantic_sha256
        ):
            raise ValueError("sources require coordinator-retained scoped capture records")
        if self.evidence.object_ref.byte_count > MAX_RECORD_BYTES:
            raise ValueError("source object exceeds the retained journal record bound")
        if self.record_id not in self.receipt.record_ids:
            raise ValueError("source record is absent from its retained append")
        index = self.receipt.record_ids.index(self.record_id)
        if self.receipt.record_hashes[index] != self.evidence.object_ref.object_sha256:
            raise ValueError("source object bytes differ from journal record bytes")


@dataclass(frozen=True, slots=True)
class ReconciliationSourceManifest(ReconciliationPersistenceRecord):
    scope: ReconciliationScope
    sources: tuple[ReconciliationSourceRef, ...]

    def __post_init__(self) -> None:
        super(ReconciliationSourceManifest, self).__post_init__()
        ids = tuple(value.page_receipt_id for value in self.sources)
        if len(ids) > MAX_RECONCILIATION_PAGES or ids != tuple(sorted(set(ids))):
            raise ValueError("source manifest requires bounded unique ordered page receipts")
        environment = (
            "synthetic"
            if self.scope.source_class == "stateful_simulation"
            else self.scope.environment
        )
        if any(
            source.key.account_scope != self.scope.account_id
            or source.key.source_provider != self.scope.provider_id
            or source.key.source_environment != environment
            or source.key.source_scope_sha256 != self.scope.semantic_sha256
            for source in self.sources
        ):
            raise ValueError("source manifest account/provider/environment/scope differs")


@dataclass(frozen=True, slots=True)
class ReconciliationSourceContent(ReconciliationPersistenceRecord):
    """Resolver output, after interpreting its explicitly allowlisted source record."""

    reference: ReconciliationSourceRef
    page: ReconciliationPage
    facts: tuple[ReconciliationFactCommand, ...]

    def __post_init__(self) -> None:
        super(ReconciliationSourceContent, self).__post_init__()
        ids = tuple(value.observation.fact_id for value in self.facts)
        if len(ids) > MAX_RECONCILIATION_ITEMS or ids != tuple(sorted(set(ids))):
            raise ValueError("source facts require bounded sorted unique identities")
        if self.reference.page_receipt_id != self.page.receipt_id or (
            self.reference.key.source_scope_sha256 != self.page.scope_sha256
        ):
            raise ValueError("resolved source page differs from its retained scope/receipt")
        if any(
            value.observation.source_receipt_id != self.page.receipt_id
            or value.source_sha256 != self.page.semantic_sha256
            or value.scope.semantic_sha256 != self.page.scope_sha256
            for value in self.facts
        ):
            raise ValueError("resolved source fact differs from its exact page")


@dataclass(frozen=True, slots=True)
class ReconciliationApplicationManifest(ReconciliationPersistenceRecord):
    applications: tuple[FactApplication, ...]
    obligations: tuple[ReconciliationObligation, ...]
    order_bindings: tuple[ReconciliationOrderBinding, ...]
    instrument_symbols: tuple[tuple[str, str], ...]
    required_from: datetime
    required_through: datetime
    applied_through: datetime | None
    completed_at: datetime
    previous_result: ReconciliationResult | None = None

    def __post_init__(self) -> None:
        super(ReconciliationApplicationManifest, self).__post_init__()
        for values, ids in (
            (self.applications, tuple(v.fact_id for v in self.applications)),
            (self.obligations, tuple(v.order_id for v in self.obligations)),
            (self.order_bindings, tuple(v.order_id for v in self.order_bindings)),
            (self.instrument_symbols, tuple(v[0] for v in self.instrument_symbols)),
        ):
            if len(values) > MAX_RECONCILIATION_ITEMS or ids != tuple(sorted(set(ids))):
                raise ValueError("application manifest requires bounded unique sorted inventories")
        if not self.required_from <= self.required_through <= self.completed_at or (
            self.applied_through is not None and self.applied_through > self.completed_at
        ):
            raise ValueError("application comparison boundaries are invalid")


@dataclass(frozen=True, slots=True)
class ReconciliationCommit(ReconciliationPersistenceRecord):
    command_id: str
    scope: ReconciliationScope
    previous_commit_sha256: str | None
    expected_heads: ReconciliationHeads
    resulting_heads: ReconciliationHeads
    canonical_transition_ref: CanonicalAccountTransitionRef
    sources: ReconciliationEvidenceRef
    observed: ReconciliationEvidenceRef
    applications: ReconciliationEvidenceRef
    result: ReconciliationEvidenceRef
    capture_binding: ReconciliationCaptureBinding | None = None

    def __post_init__(self) -> None:
        super(ReconciliationCommit, self).__post_init__()
        require_reconciliation_id(self.command_id, "reconciliation commit command")
        if self.previous_commit_sha256 is not None:
            require_digest(self.previous_commit_sha256, "previous reconciliation commit")
        for reference, schema in (
            (self.sources, SOURCES_SCHEMA),
            (self.observed, ROUND_SCHEMA),
            (self.applications, APPLICATIONS_SCHEMA),
            (self.result, RESULT_SCHEMA),
        ):
            if reference.schema_id != schema:
                raise ValueError("commit evidence schema differs from its declared role")
        transition = self.canonical_transition_ref
        if (
            transition.account_id != self.scope.account_id
            or transition.account_binding_sha256 != self.scope.binding_sha256
            or transition.expected_heads != self.expected_heads
            or transition.resulting_heads != self.resulting_heads
            or not _source_binding(transition, self.sources.semantic_sha256, self.capture_binding)
        ):
            raise ValueError("canonical transition and reconciliation commit bindings differ")


@dataclass(frozen=True, slots=True)
class ResolvedReconciliationTransition(ReconciliationPersistenceRecord):
    reference: CanonicalAccountTransitionRef
    current: AccountingTransition
    context: AccountingContext
    policy: ExecutionPolicy

    def __post_init__(self) -> None:
        super(ResolvedReconciliationTransition, self).__post_init__()
        snapshot = self.current.snapshot
        if (
            self.current.state.account_id != self.reference.account_id
            or snapshot.state_sha256 != self.current.state.semantic_sha256
            or snapshot.journal_sha256 != self.reference.resulting_heads.ledger_sha256
            or snapshot.order_sha256 != self.reference.resulting_heads.order_sha256
            or self.context.point.knowledge_at != self.reference.applied_at
            or self.context.point.stage != 1
            or snapshot.point != self.context.point
        ):
            raise ValueError("resolved canonical projection differs from transition reference")


@dataclass(frozen=True, slots=True)
class ResolvedReconciliationCommit(ReconciliationPersistenceRecord):
    commit: ReconciliationCommit
    sources: ReconciliationSourceManifest
    observed: ObservationRound
    applications: ReconciliationApplicationManifest
    result: ReconciliationResult
    transition: ResolvedReconciliationTransition
    retained_objects: tuple[ObjectRef, ...]

    def __post_init__(self) -> None:
        super(ResolvedReconciliationCommit, self).__post_init__()
        for value, reference in (
            (self.sources, self.commit.sources),
            (self.observed, self.commit.observed),
            (self.applications, self.commit.applications),
            (self.result, self.commit.result),
        ):
            if value.semantic_sha256 != reference.semantic_sha256:
                raise ValueError("resolved evidence differs from commit reference")
        if (
            self.transition.reference != self.commit.canonical_transition_ref
            or self.result.scope != self.commit.scope
            or self.result.heads != self.commit.resulting_heads
        ):
            raise ValueError("resolved transition/result binding differs")
        _objects(self.retained_objects, capture_binding=self.commit.capture_binding)


def _source_binding(
    transition: CanonicalAccountTransitionRef,
    manifest_sha256: str,
    binding: ReconciliationCaptureBinding | None,
) -> bool:
    if binding is None:
        return transition.source_closure_sha256 == manifest_sha256
    return (
        type(binding) is ReconciliationCaptureBinding
        and binding.source_closure_sha256 == transition.source_closure_sha256
        and binding.manifest_sha256 == manifest_sha256
    )


def _objects(
    values: tuple[ObjectRef, ...], *, capture_binding: ReconciliationCaptureBinding | None = None
) -> None:
    identities = tuple(value.object_sha256 for value in values)
    if (
        len(values) > MAX_RECONCILIATION_PAGES + (5 if capture_binding is None else 6)
        or identities != tuple(sorted(set(identities)))
        or sum(value.byte_count for value in values) > MAX_EVIDENCE_BYTES
        or any(value.codec_version != "personal-record/1" for value in values)
        or (capture_binding is not None and capture_binding.capture.object_ref not in values)
    ):
        raise ValueError("retained object metadata exceeds exact bounded inventory")


@dataclass(frozen=True, slots=True)
class ReconciliationCommitReceipt(ReconciliationPersistenceRecord):
    commit: ReconciliationCommit
    sequence: int
    journal_key: JournalKey
    journal: JournalReceipt

    def __post_init__(self) -> None:
        super(ReconciliationCommitReceipt, self).__post_init__()
        if not 1 <= self.sequence <= 2**63 - 1:
            raise ValueError("commit index sequence is outside its bound")
        if (
            self.journal_key.namespace != "coordinator"
            or self.journal_key.account_scope != self.commit.scope.account_id
            or self.journal_key.source_scope_sha256 != self.commit.scope.semantic_sha256
            or self.journal.previous_head.key_sha256 != self.journal_key.semantic_sha256
            or self.journal.command_id != self.commit.command_id
            or self.journal.command_sha256 != self.commit.semantic_sha256
            or len(self.journal.record_ids) != 1
            or self.journal.record_ids != (self.commit.semantic_sha256,)
        ):
            raise ValueError("commit receipt and exact scoped journal append differ")


@dataclass(frozen=True, slots=True)
class ReconciliationRetentionRead(ReconciliationPersistenceRecord):
    """Required durable reader's actual metadata, not an authority constructor."""

    transition: CanonicalAccountTransitionRef
    sources: ReconciliationSourceManifest
    objects: tuple[ObjectRef, ...]
    current_heads: ReconciliationHeads
    journal_head: JournalHead
    journal_receipt: JournalReceipt | None
    capture_binding: ReconciliationCaptureBinding | None = None

    def __post_init__(self) -> None:
        super(ReconciliationRetentionRead, self).__post_init__()
        _objects(self.objects, capture_binding=self.capture_binding)
        if (
            self.transition.account_id != self.sources.scope.account_id
            or self.transition.account_binding_sha256 != self.sources.scope.binding_sha256
            or not _source_binding(
                self.transition, self.sources.semantic_sha256, self.capture_binding
            )
            or (
                self.journal_receipt is not None
                and self.journal_receipt.committed_head.key_sha256 != self.journal_head.key_sha256
            )
        ):
            raise ValueError("retention metadata scope differs")
