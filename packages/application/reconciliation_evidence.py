"""Resolve and compare immutable retained evidence before any account SQL lock."""

from collections.abc import Mapping
from hashlib import sha256
from types import MappingProxyType
from typing import Protocol, TypeVar

from packages.application.account_reconciliation import apply_reconciliation_facts
from packages.domain.accounting_contracts import ExecutionAccountingPort
from packages.domain.applied_reconciliation import compare_reconciled_account
from packages.domain.continuous_account_contracts import CanonicalAccountTransitionRef
from packages.domain.personal_contracts import ContractRecord
from packages.domain.reconciliation_contracts import (
    MAX_RECONCILIATION_ITEMS,
    ObservationRound,
    ReconciliationResult,
)
from packages.domain.reconciliation_persistence_contracts import (
    MAX_COMMIT_BYTES,
    MAX_EVIDENCE_BYTES,
    ReconciliationApplicationManifest,
    ReconciliationCommit,
    ReconciliationEvidenceRef,
    ReconciliationSourceContent,
    ReconciliationSourceManifest,
    ReconciliationSourceRef,
    ResolvedReconciliationCommit,
    ResolvedReconciliationTransition,
)
from packages.domain.research_job_contracts import (
    ObjectRef,
    ResearchArtifactStore,
    ResearchRecordCodec,
)
from packages.domain.venue_reconciliation_contracts import RetainedVenueCapture


class ReconciliationEvidenceError(ValueError):
    """Static bounded failure; no source bytes or private paths in diagnostics."""


class ReconciliationEvidenceResolver(Protocol):
    def resolve_source(
        self,
        reference: ReconciliationSourceRef,
        value: ContractRecord,
    ) -> ReconciliationSourceContent: ...

    def resolve_observation(
        self,
        manifest: ReconciliationSourceManifest,
        values: tuple[ContractRecord, ...],
    ) -> ObservationRound:
        """Reconstruct all observations from retained sources, not caller balances."""
        ...

    def resolve_transition(
        self,
        reference: CanonicalAccountTransitionRef,
        value: ContractRecord,
    ) -> ResolvedReconciliationTransition:
        """Authenticate the actual checkpoint's canonical before/after closure."""
        ...


T = TypeVar("T", bound=ContractRecord)


def retain_reconciliation_evidence(
    value: ContractRecord,
    *,
    schema_id: str,
    codec: ResearchRecordCodec,
    artifacts: ResearchArtifactStore,
) -> ReconciliationEvidenceRef:
    """Retain typed bytes; full aggregate admission is performed by preparation."""
    try:
        payload = codec.encode_record(value)
        if type(payload) is not bytes or not 0 < len(payload) <= MAX_EVIDENCE_BYTES:
            raise ReconciliationEvidenceError("EVIDENCE_OBJECT_SIZE_INVALID")
        if codec.decode_record(payload, type(value)) != value:
            raise ReconciliationEvidenceError("EVIDENCE_CODEC_MISMATCH")
        reference = artifacts.put(payload, max_bytes=MAX_EVIDENCE_BYTES)
        if reference != ObjectRef(sha256(payload).hexdigest(), len(payload)):
            raise ReconciliationEvidenceError("EVIDENCE_STORAGE_IDENTITY_MISMATCH")
        return ReconciliationEvidenceRef(schema_id, reference, value.semantic_sha256)
    except ReconciliationEvidenceError:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError, OSError):
        raise ReconciliationEvidenceError("EVIDENCE_RETENTION_FAILED") from None


class ReconciliationEvidencePreparer:
    def __init__(
        self,
        *,
        codec: ResearchRecordCodec,
        artifacts: ResearchArtifactStore,
        checkpoint_type: type[ContractRecord],
        source_types: Mapping[str, type[ContractRecord]],
        resolver: ReconciliationEvidenceResolver,
        accounting: ExecutionAccountingPort,
    ) -> None:
        if (
            not issubclass(checkpoint_type, ContractRecord)
            or not source_types
            or any(not issubclass(value, ContractRecord) for value in source_types.values())
        ):
            raise ReconciliationEvidenceError("EXPLICIT_EVIDENCE_TYPES_REQUIRED")
        self.codec, self.artifacts = codec, artifacts
        self.checkpoint_type, self.source_types = (
            checkpoint_type,
            MappingProxyType(dict(source_types)),
        )
        self.resolver, self.accounting = resolver, accounting

    def _read(self, reference: ObjectRef, expected: type[T]) -> T:
        payload = self.artifacts.read(reference, max_bytes=MAX_EVIDENCE_BYTES)
        if (
            type(payload) is not bytes
            or len(payload) != reference.byte_count
            or sha256(payload).hexdigest() != reference.object_sha256
        ):
            raise ReconciliationEvidenceError("EVIDENCE_BYTES_MISMATCH")
        value = self.codec.decode_record(payload, expected)
        if type(value) is not expected or self.codec.encode_record(value) != payload:
            raise ReconciliationEvidenceError("EVIDENCE_CANONICAL_TYPE_MISMATCH")
        return value

    def _value(self, reference: ReconciliationEvidenceRef, expected: type[T]) -> T:
        value = self._read(reference.object_ref, expected)
        if value.semantic_sha256 != reference.semantic_sha256:
            raise ReconciliationEvidenceError("EVIDENCE_SEMANTIC_MISMATCH")
        return value

    @staticmethod
    def _budget(references: tuple[ObjectRef, ...]) -> tuple[ObjectRef, ...]:
        retained: dict[str, ObjectRef] = {}
        for value in references:
            if value.codec_version != "personal-record/1":
                raise ReconciliationEvidenceError("EVIDENCE_CODEC_NOT_ALLOWED")
            old = retained.setdefault(value.object_sha256, value)
            if old != value:
                raise ReconciliationEvidenceError("EVIDENCE_OBJECT_REFERENCE_CONFLICT")
        if sum(value.byte_count for value in retained.values()) > MAX_EVIDENCE_BYTES:
            raise ReconciliationEvidenceError("EVIDENCE_AGGREGATE_LIMIT")
        return tuple(retained[key] for key in sorted(retained))

    def resolve(self, commit: ReconciliationCommit) -> ResolvedReconciliationCommit:
        """Read only private immutable objects; never enter a database transaction."""
        try:
            return self._resolve(commit)
        except ReconciliationEvidenceError:
            raise
        except (ValueError, TypeError, KeyError, UnicodeError, OSError):
            raise ReconciliationEvidenceError("RECONCILIATION_EVIDENCE_INVALID") from None

    def _resolve(self, commit: ReconciliationCommit) -> ResolvedReconciliationCommit:
        if type(commit) is not ReconciliationCommit:
            raise ReconciliationEvidenceError("EXACT_COMMIT_REQUIRED")
        commit.__post_init__()
        compact = self.codec.encode_record(commit)
        if type(compact) is not bytes or not 0 < len(compact) <= MAX_COMMIT_BYTES:
            raise ReconciliationEvidenceError("COMPACT_COMMIT_LIMIT")
        top = self._budget(
            (
                commit.sources.object_ref,
                commit.observed.object_ref,
                commit.applications.object_ref,
                commit.result.object_ref,
                commit.canonical_transition_ref.checkpoint,
                *((commit.capture_binding.capture.object_ref,) if commit.capture_binding else ()),
            )
        )
        sources = self._value(commit.sources, ReconciliationSourceManifest)
        retained = self._budget((*top, *(source.evidence.object_ref for source in sources.sources)))
        observed = self._value(commit.observed, ObservationRound)
        applications = self._value(commit.applications, ReconciliationApplicationManifest)
        result = self._value(commit.result, ReconciliationResult)
        if sources.scope != commit.scope or observed.scope != commit.scope:
            raise ReconciliationEvidenceError("EVIDENCE_SCOPE_MISMATCH")
        values: list[ContractRecord] = []
        contents = []
        for source in sources.sources:
            expected = self.source_types.get(source.evidence.schema_id)
            if expected is None:
                raise ReconciliationEvidenceError("SOURCE_TYPE_NOT_ALLOWED")
            value = self._value(source.evidence, expected)
            content = self.resolver.resolve_source(source, value)
            if type(content) is not ReconciliationSourceContent or content.reference != source:
                raise ReconciliationEvidenceError("SOURCE_RESOLUTION_MISMATCH")
            content.__post_init__()
            values.append(value)
            contents.append(content)
        actual_round = self.resolver.resolve_observation(sources, tuple(values))
        if type(actual_round) is not ObservationRound or actual_round != observed:
            raise ReconciliationEvidenceError("RETAINED_OBSERVATION_MISMATCH")
        if sorted(value.page.semantic_sha256 for value in contents) != sorted(
            page.semantic_sha256 for page in observed.pages
        ):
            raise ReconciliationEvidenceError("SOURCE_PAGE_CLOSURE_MISMATCH")
        facts = tuple(fact for value in contents for fact in value.facts)
        if len(facts) > MAX_RECONCILIATION_ITEMS or sorted(
            fact.observation.semantic_sha256 for fact in facts
        ) != sorted(fact.semantic_sha256 for fact in observed.facts):
            raise ReconciliationEvidenceError("SOURCE_FACT_CLOSURE_MISMATCH")
        if commit.capture_binding is not None:
            capture = self._value(commit.capture_binding.capture, RetainedVenueCapture)
            if (
                capture.manifest != sources
                or capture.observed != observed
                or capture.manifest.scope != commit.scope
                or sorted(capture.facts, key=lambda item: item.observation.fact_id)
                != sorted(facts, key=lambda item: item.observation.fact_id)
            ):
                raise ReconciliationEvidenceError("ACTUAL_CAPTURE_MANIFEST_BINDING_MISMATCH")
        checkpoint = self._read(commit.canonical_transition_ref.checkpoint, self.checkpoint_type)
        if checkpoint.semantic_sha256 != commit.canonical_transition_ref.checkpoint_sha256:
            raise ReconciliationEvidenceError("CHECKPOINT_SEMANTIC_MISMATCH")
        transition = self.resolver.resolve_transition(commit.canonical_transition_ref, checkpoint)
        if type(transition) is not ResolvedReconciliationTransition or (
            transition.reference != commit.canonical_transition_ref
        ):
            raise ReconciliationEvidenceError("TRANSITION_RESOLUTION_MISMATCH")
        transition.__post_init__()
        if transition.reference.applied_at > applications.completed_at or (
            applications.instrument_symbols != transition.context.instruments
        ):
            raise ReconciliationEvidenceError("TRANSITION_COMPARISON_BOUNDARY_MISMATCH")
        applied_ids = {item.fact_id for item in applications.applications}
        if not applied_ids <= {fact.observation.fact_id for fact in facts}:
            raise ReconciliationEvidenceError("APPLICATION_SOURCE_MISSING")
        # Validate existing actual links through the canonical applicator. Only
        # already-applied facts enter this retry check: no new economic apply is
        # permitted, and unresolved independent source facts remain observable.
        checked = apply_reconciliation_facts(
            scope=commit.scope,
            state=transition.current.state,
            facts=tuple(fact for fact in facts if fact.observation.fact_id in applied_ids),
            source_receipts=tuple(value.page for value in contents),
            prior_applications=applications.applications,
            context=transition.context,
            accounting=self.accounting,
            policy=transition.policy,
        )
        if (
            checked.state != transition.current.state
            or checked.applications != applications.applications
            or checked.current.snapshot != transition.current.snapshot
        ):
            raise ReconciliationEvidenceError("ACTUAL_APPLICATION_LINK_MISMATCH")
        computed = compare_reconciled_account(
            expected=transition.current.snapshot,
            observed=observed,
            heads=commit.resulting_heads,
            obligations=applications.obligations,
            applications=applications.applications,
            instrument_symbols=applications.instrument_symbols,
            required_from=applications.required_from,
            required_through=applications.required_through,
            applied_through=applications.applied_through,
            now=applications.completed_at,
            previous=applications.previous_result,
            order_bindings=applications.order_bindings,
        )
        if computed != result:
            raise ReconciliationEvidenceError("RECOMPUTED_COMPARISON_MISMATCH")
        if (commit.previous_commit_sha256 is None) != (applications.previous_result is None):
            raise ReconciliationEvidenceError("PREVIOUS_COMPARISON_BINDING_MISMATCH")
        return ResolvedReconciliationCommit(
            commit,
            sources,
            observed,
            applications,
            result,
            transition,
            retained,
        )
