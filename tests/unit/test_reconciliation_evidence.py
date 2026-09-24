"""Synthetic retained-record evidence, with real canonical accounting links."""

from dataclasses import dataclass, replace
from datetime import timedelta
from decimal import Decimal
from hashlib import sha256

import pytest

from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec as codec
from packages.application.reconciliation_evidence import (
    ReconciliationEvidenceError,
    ReconciliationEvidencePreparer,
    retain_reconciliation_evidence,
)
from packages.domain.accounting_contracts import (
    AccountingContext,
    AccountingTransition,
    ExecutionPolicy,
)
from packages.domain.applied_reconciliation import compare_reconciled_account
from packages.domain.continuous_account_contracts import CanonicalAccountTransitionRef
from packages.domain.durable_journal_contracts import (
    JournalAppend,
    JournalEntry,
    JournalKey,
    JournalReceipt,
    JournalRecord,
    empty_head,
)
from packages.domain.personal_contracts import ContractRecord, content_digest
from packages.domain.reconciliation_application_contracts import ReconciliationFactCommand
from packages.domain.reconciliation_contracts import (
    REQUIRED_CASH_FIELDS,
    CashObservation,
    ObservationRound,
    PositionObservation,
    ReconciliationHeads,
)
from packages.domain.reconciliation_persistence_contracts import (
    APPLICATIONS_SCHEMA,
    MAX_EVIDENCE_BYTES,
    RESULT_SCHEMA,
    ROUND_SCHEMA,
    SOURCES_SCHEMA,
    ReconciliationApplicationManifest,
    ReconciliationCommit,
    ReconciliationSourceContent,
    ReconciliationSourceManifest,
    ReconciliationSourceRef,
    ResolvedReconciliationTransition,
)
from packages.domain.research_job_contracts import ObjectRef
from tests.unit.test_account_reconciliation import apply, fill, scope, wrap
from tests.unit.test_observed_accounting import OBSERVED, observed_order

SHA = "a" * 64


@dataclass(frozen=True, slots=True)
class SyntheticCapture(ContractRecord):
    observed: ObservationRound
    facts: tuple[ReconciliationFactCommand, ...]


@dataclass(frozen=True, slots=True)
class SyntheticCheckpoint(ContractRecord):
    current: AccountingTransition
    context: AccountingContext
    policy: ExecutionPolicy


class FixtureResolver:
    """Literal source/checkpoint projections; no production authentication claim."""

    def resolve_source(self, reference, value):
        assert type(value) is SyntheticCapture
        page = next(
            page for page in value.observed.pages if page.receipt_id == reference.page_receipt_id
        )
        return ReconciliationSourceContent(reference, page, value.facts)

    def resolve_observation(self, manifest, values):
        assert len(values) == 1 and type(values[0]) is SyntheticCapture
        return values[0].observed

    def resolve_transition(self, reference, value):
        assert type(value) is SyntheticCheckpoint
        return ResolvedReconciliationTransition(
            reference, value.current, value.context, value.policy
        )


def evidence_case(tmp_path, *, index=0, previous=None, effect=0):
    """A fill is canonical; incomplete coverage is intentionally retained as blocked."""
    artifacts = LocalResearchArtifactStore(tmp_path / f"objects-{index}")
    h, commitment = observed_order()
    pair = wrap(h, fill(h, commitment), receipt_id=f"activity-{index}")
    batch = apply(h, (pair,))
    at = pair[1].received_at + timedelta(seconds=index * 10)
    context = replace(
        h.context(at=at), point=replace(batch.current.snapshot.point, knowledge_at=at, stage=1)
    )
    current = h.port.project(state=batch.state, context=context, policy=OBSERVED)
    snapshot = current.snapshot
    page = replace(pair[1], requested_at=at, received_at=at)
    command = replace(
        pair[0],
        observation=replace(pair[0].observation, received_at=at),
        source_sha256=page.semantic_sha256,
    )
    observed = ObservationRound(
        scope=scope(h),
        round_id=f"round-{index}",
        started_at=at,
        completed_at=at,
        requested_from=at - timedelta(days=7),
        requested_through=at,
        pages=(page,),
        cash=tuple(
            CashObservation(field, getattr(snapshot, field, Decimal(0)), "USD", SHA)
            for field in REQUIRED_CASH_FIELDS
        ),
        positions=tuple(
            PositionObservation(p.instrument_id, p.symbol, p.quantity) for p in snapshot.positions
        ),
        orders=(),
        facts=(command.observation,),
        currency="USD",
        account_modes=(("balance", "CASH"),),
    )
    capture = SyntheticCapture(observed, (command,))

    def retain(value, schema):
        return retain_reconciliation_evidence(
            value, schema_id=schema, codec=codec, artifacts=artifacts
        )

    capture_ref = retain(capture, "fixture-source/1")
    key = JournalKey(
        "capture",
        f"source-{index}",
        h.state.account_id,
        observed.scope.provider_id,
        "synthetic",
        observed.scope.semantic_sha256,
    )
    record = JournalRecord(f"capture-{index}", "fixture-source/1", codec.encode_record(capture))
    request = JournalAppend(
        f"capture-command-{index}", content_digest(capture), empty_head(key), (record,)
    )
    entry = JournalEntry(
        key.semantic_sha256, 1, request.command_id, record, empty_head(key).entry_sha256
    )
    receipt = JournalReceipt(
        request.command_id,
        request.command_sha256,
        request.semantic_sha256,
        empty_head(key),
        entry.head,
        (record.record_id,),
        (record.payload_sha256,),
    )
    source = ReconciliationSourceRef(page.receipt_id, key, receipt, record.record_id, capture_ref)
    sources = ReconciliationSourceManifest(observed.scope, (source,))
    applications = ReconciliationApplicationManifest(
        batch.applications,
        (),
        (),
        context.instruments,
        observed.requested_from,
        observed.requested_through,
        at,
        at,
        None if previous is None else previous["result"],
    )
    heads = ReconciliationHeads(
        snapshot.journal_sha256, snapshot.order_sha256, "b" * 64, effect, "c" * 64, 0, 1
    )
    result = compare_reconciled_account(
        expected=snapshot,
        observed=observed,
        heads=heads,
        obligations=(),
        applications=batch.applications,
        instrument_symbols=context.instruments,
        required_from=observed.requested_from,
        required_through=observed.requested_through,
        applied_through=at,
        now=at,
        previous=applications.previous_result,
    )
    checkpoint = SyntheticCheckpoint(current, context, OBSERVED)
    checkpoint_ref = retain(checkpoint, "fixture-checkpoint/1")
    transition = CanonicalAccountTransitionRef(
        account_id=h.state.account_id,
        account_binding_sha256=observed.scope.binding_sha256,
        command_id=f"canonical-{index}",
        command_sha256=content_digest(("canonical", index)),
        previous_checkpoint_sha256=None
        if previous is None
        else previous["transition"].checkpoint_sha256,
        checkpoint=checkpoint_ref.object_ref,
        checkpoint_sha256=checkpoint.semantic_sha256,
        expected_heads=heads if previous is None else previous["heads"],
        resulting_heads=heads,
        source_closure_sha256=sources.semantic_sha256,
        applied_at=at,
    )
    commit = ReconciliationCommit(
        f"compare-{index}",
        observed.scope,
        None if previous is None else previous["commit"].semantic_sha256,
        transition.expected_heads,
        heads,
        transition,
        retain(sources, SOURCES_SCHEMA),
        retain(observed, ROUND_SCHEMA),
        retain(applications, APPLICATIONS_SCHEMA),
        retain(result, RESULT_SCHEMA),
    )
    preparer = ReconciliationEvidencePreparer(
        codec=codec,
        artifacts=artifacts,
        checkpoint_type=SyntheticCheckpoint,
        source_types={"fixture-source/1": SyntheticCapture},
        resolver=FixtureResolver(),
        accounting=h.port,
    )
    return dict(
        artifacts=artifacts,
        h=h,
        batch=batch,
        at=at,
        heads=heads,
        source=source,
        sources=sources,
        capture=capture,
        capture_request=request,
        observed=observed,
        applications=applications,
        result=result,
        transition=transition,
        commit=commit,
        preparer=preparer,
        retain=retain,
    )


def test_actual_fill_links_and_blocked_result_resolve_without_new_accounting(tmp_path):
    case = evidence_case(tmp_path)
    value = case["preparer"].resolve(case["commit"])
    assert value.transition.current.state == case["batch"].state
    assert value.transition.current.snapshot.trade_date_cash == 599
    assert value.transition.current.snapshot.trade_payable == 401
    assert len(value.applications.applications[0].journal_entry_ids) == 2
    assert value.result.status == "blocked" and value.result.blocking_reasons
    assert sum(ref.byte_count for ref in value.retained_objects) < MAX_EVIDENCE_BYTES
    assert value.retained_objects == tuple(
        sorted(value.retained_objects, key=lambda ref: ref.object_sha256)
    )


def test_same_object_reused_is_counted_once_and_conflicting_metadata_rejects():
    reference = ObjectRef(SHA, MAX_EVIDENCE_BYTES)
    assert ReconciliationEvidencePreparer._budget((reference, reference)) == (reference,)
    with pytest.raises(ReconciliationEvidenceError, match="REFERENCE_CONFLICT"):
        ReconciliationEvidencePreparer._budget((reference, replace(reference, byte_count=1)))
    with pytest.raises(ReconciliationEvidenceError, match="AGGREGATE_LIMIT"):
        ReconciliationEvidencePreparer._budget((reference, ObjectRef("b" * 64, 1)))


@pytest.mark.parametrize("change", ["cash", "result", "application", "checkpoint", "schema"])
def test_typed_but_unbound_or_false_evidence_rejects(tmp_path, change):
    case = evidence_case(tmp_path)
    commit, retain = case["commit"], case["retain"]
    if change == "cash":
        observed = replace(case["observed"], cash=())
        commit = replace(commit, observed=retain(observed, ROUND_SCHEMA))
    elif change == "result":
        result = replace(case["result"], completed_at=case["at"] + timedelta(seconds=1))
        commit = replace(commit, result=retain(result, RESULT_SCHEMA))
    elif change == "application":
        apps = case["applications"]
        item = replace(
            apps.applications[0], journal_entry_ids=apps.applications[0].journal_entry_ids[:1]
        )
        commit = replace(
            commit, applications=retain(replace(apps, applications=(item,)), APPLICATIONS_SCHEMA)
        )
    elif change == "checkpoint":
        commit = replace(
            commit, canonical_transition_ref=replace(case["transition"], checkpoint_sha256="d" * 64)
        )
    else:
        case["preparer"].source_types = {}
    with pytest.raises(ReconciliationEvidenceError):
        case["preparer"].resolve(commit)


@pytest.mark.parametrize("change", ["account", "provider", "environment", "scope", "record"])
def test_foreign_or_absent_source_reference_rejects(tmp_path, change):
    case = evidence_case(tmp_path)
    source = case["source"]
    if change == "record":
        with pytest.raises(ValueError):
            replace(source, record_id="absent")
        return
    field = {
        "account": "account_scope",
        "provider": "source_provider",
        "environment": "source_environment",
        "scope": "source_scope_sha256",
    }[change]
    value = (
        "production" if change == "environment" else "f" * 64 if change == "scope" else "foreign"
    )
    key = replace(source.key, **{field: value})
    # Rebind the synthetic receipt to demonstrate manifest's independent scope check.
    receipt = replace(
        source.receipt,
        previous_head=replace(source.receipt.previous_head, key_sha256=key.semantic_sha256),
        committed_head=replace(source.receipt.committed_head, key_sha256=key.semantic_sha256),
    )
    with pytest.raises(ValueError):
        ReconciliationSourceManifest(
            case["commit"].scope, (replace(source, key=key, receipt=receipt),)
        )


def test_missing_or_corrupted_private_object_rejects_with_static_error(tmp_path):
    case = evidence_case(tmp_path)
    reference = case["commit"].observed.object_ref
    path = tmp_path / "objects-0" / (reference.object_sha256 + ".json")
    path.write_bytes(b"x" * reference.byte_count)
    with pytest.raises(ReconciliationEvidenceError) as error:
        case["preparer"].resolve(case["commit"])
    assert str(tmp_path) not in str(error.value)
    path.unlink()
    with pytest.raises(ReconciliationEvidenceError):
        case["preparer"].resolve(case["commit"])


def test_budget_is_rejected_before_loading_oversized_references(tmp_path):
    case = evidence_case(tmp_path)
    ref = replace(case["commit"].observed, object_ref=ObjectRef("e" * 64, MAX_EVIDENCE_BYTES))
    with pytest.raises(ReconciliationEvidenceError, match="AGGREGATE_LIMIT"):
        case["preparer"].resolve(replace(case["commit"], observed=ref))


def test_same_source_bytes_and_semantic_identity_are_separate_checks(tmp_path):
    case = evidence_case(tmp_path)
    assert (
        sha256(codec.encode_record(case["observed"])).hexdigest()
        == case["commit"].observed.object_ref.object_sha256
    )
    with pytest.raises(ReconciliationEvidenceError, match="SEMANTIC_MISMATCH"):
        case["preparer"].resolve(
            replace(
                case["commit"], observed=replace(case["commit"].observed, semantic_sha256="e" * 64)
            )
        )


def test_retention_os_failure_does_not_disclose_private_path(tmp_path):
    case = evidence_case(tmp_path)

    class BrokenStorage:
        def put(self, *args, **kwargs):
            raise OSError(13, "fixture private path", str(tmp_path / "private-object"))

    with pytest.raises(ReconciliationEvidenceError, match="EVIDENCE_RETENTION_FAILED") as error:
        retain_reconciliation_evidence(
            case["observed"], schema_id=ROUND_SCHEMA, codec=codec, artifacts=BrokenStorage()
        )
    assert str(tmp_path) not in str(error.value)
