"""Independent pure DTO fixtures; no retained source or provider qualification."""

from dataclasses import fields, replace
from datetime import timedelta

import pytest

from packages.application import personal_codec as codec
from packages.application.continuous_runtime_evidence import (
    ContinuousRuntimeEvidencePort,
    RuntimeSourceCondition,
)
from packages.domain.account_coordinator import AccountFence
from packages.domain.continuous_account_contracts import CanonicalAccountTransitionRef
from packages.domain.continuous_persistence_contracts import (
    ContinuousAccountCommit,
    ContinuousAccountReceipt,
    ContinuousAccountScope,
    ContinuousEvidenceRef,
    ContinuousFenceReference,
)
from packages.domain.continuous_runtime_source_contracts import (
    ContinuousRuntimeRoleReferences,
    ContinuousRuntimeSourceDescriptor,
)
from packages.domain.daily_attempt_contracts import DailyFenceReference
from packages.domain.daily_runtime_risk import runtime_source_value_sha256
from packages.domain.durable_journal_contracts import JournalHead, JournalReceipt
from packages.domain.personal_contracts import content_digest
from packages.domain.research_job_contracts import ObjectRef
from tests.unit.test_daily_risk_snapshot import runtime_case

SHA = "a" * 64


def descriptor_fixture():
    assignment, snapshot, batch, refs, producers, now = runtime_case()
    scope = ContinuousAccountScope(
        assignment.account_id, assignment.account_binding_sha256, "stream"
    )
    ref = ContinuousEvidenceRef("continuous-account-request/1", ObjectRef(SHA, 1), SHA)
    transition = CanonicalAccountTransitionRef(
        account_id=scope.account_id,
        account_binding_sha256=scope.account_binding_sha256,
        command_id="fixture-initialize",
        command_sha256=SHA,
        previous_checkpoint_sha256=None,
        checkpoint=ObjectRef(SHA, 1),
        checkpoint_sha256=SHA,
        expected_heads=refs.heads,
        resulting_heads=refs.heads,
        source_closure_sha256=SHA,
        applied_at=now - timedelta(seconds=1),
    )
    commit = ContinuousAccountCommit(scope, 1, None, transition, ref, ref, ref)
    journal = JournalReceipt(
        transition.command_id,
        SHA,
        SHA,
        JournalHead(SHA, 0, SHA),
        JournalHead(SHA, 1, SHA),
        (commit.semantic_sha256,),
        (SHA,),
    )
    previous = ContinuousAccountReceipt(
        commit,
        journal,
        now - timedelta(seconds=1),
        ContinuousFenceReference("owner", "lease", 1, SHA, SHA, now + timedelta(seconds=60)),
    )
    reference = DailyFenceReference(
        fence=AccountFence(scope.account_id, "owner", "lease", 1),
        validated_at=now,
        valid_until=now + timedelta(seconds=60),
        policy_sha256=SHA,
        lease_sha256=SHA,
        original_receipt_sha256=SHA,
    )
    descriptor = ContinuousRuntimeSourceDescriptor(
        descriptor_id="fixture-source-before-decision",
        scope=scope,
        request_kind="frontier",
        request=ref,
        market_source=ref,
        market_evidence_class="synthetic_fixture",
        previous=previous,
        original_checked_at=now,
        captured_fence=reference,
        producer_map=producers,
        assignment_sha256=assignment.semantic_sha256,
        control_sha256=SHA,
        obligations_sha256=refs.obligations.semantic_sha256,
        attempts_sha256=content_digest(()),
        role_references=(),
    )
    return descriptor, (assignment, snapshot, batch, refs, producers, now)


class Conditions:
    def __init__(self, values=()):
        self.values = values
        self.observed = None

    def evaluate(self, **kwargs):
        self.observed = kwargs
        return self.values


def evidence_fixture(conditions=()):
    descriptor, case = descriptor_fixture()
    assignment, snapshot, batch, refs, _, now = case
    evaluator = Conditions(conditions)
    port = ContinuousRuntimeEvidencePort(
        descriptor=descriptor,
        assignment=assignment,
        obligations=refs.obligations,
        original_heads=refs.heads,
        cash_restrictions=None,
        reconciliation=None,
        evaluator=evaluator,
    )
    arguments = dict(
        snapshot=snapshot,
        batch=batch,
        phase="decision",
        evaluated_at=now,
        accepted_intent_ids=refs.accepted_intent_ids,
        daily_return=None,
        drawdown=None,
        request_rows=((now - timedelta(seconds=1), True),),
    )
    return port, evaluator, arguments


def test_precompute_descriptor_has_no_future_result_and_roundtrips_exactly():
    descriptor, _ = descriptor_fixture()
    names = {field.name for field in fields(descriptor)}
    assert not names & {"decision", "admission", "action", "result", "checkpoint"}
    encoded = codec.encode_record(descriptor)
    assert codec.decode_record(encoded, ContinuousRuntimeSourceDescriptor) == descriptor
    assert len(encoded) < 256 * 1024


@pytest.mark.parametrize(
    "changes",
    [
        {"previous": None},
        {"request_kind": "initialize"},
        {"request_kind": "runtime_action"},
        {"market_evidence_class": "qualified_provider"},
        {"obligations_sha256": "missing"},
    ],
)
def test_descriptor_rejects_missing_prefix_and_promoted_source_class(changes):
    descriptor, _ = descriptor_fixture()
    with pytest.raises(ValueError):
        replace(descriptor, **changes)


def test_action_schema_cannot_become_precompute_request():
    descriptor, _ = descriptor_fixture()
    with pytest.raises(ValueError, match="precede"):
        replace(
            descriptor, request=replace(descriptor.request, schema_id="continuous-runtime-action/1")
        )
    genesis = replace(descriptor, previous=None, request_kind="initialize", assignment_sha256=None)
    assert genesis.previous is None
    with pytest.raises(ValueError, match="BINDING"):
        port, _, _ = evidence_fixture()
        ContinuousRuntimeEvidencePort(
            descriptor=genesis,
            assignment=port.assignment,
            obligations=port.obligations,
            original_heads=port.original_heads,
            cash_restrictions=None,
            reconciliation=None,
            evaluator=Conditions(),
        )


def test_missing_roles_have_no_fabricated_observation_timestamps_or_success():
    port, evaluator, arguments = evidence_fixture()
    evidence = port.build(**arguments)
    assert evidence.inputs.sources == ()
    assert any(check.status == "unavailable" for check in evidence.checks)
    assert evidence.reasons
    assert evaluator.observed["request_rows"] is arguments["request_rows"]
    assert evidence.inputs.daily_return is None and evidence.inputs.drawdown is None
    assert evidence.inputs.reconciliation is None and evidence.inputs.cash_restrictions is None


def test_normalized_values_come_from_actual_callback_and_source_times_are_original():
    descriptor, (_, _, _, _, _, now) = descriptor_fixture()
    condition = RuntimeSourceCondition(
        "clock",
        now - timedelta(seconds=2),
        now - timedelta(seconds=1),
        now + timedelta(seconds=1),
        7,
        "unavailable",
        ("CLOCK_OFFSET_UNAVAILABLE",),
    )
    port, _, arguments = evidence_fixture((condition,))
    evidence = port.build(**arguments)
    (source,) = evidence.inputs.sources
    assert (source.source_at, source.received_at, source.valid_until) == (
        condition.source_at,
        condition.received_at,
        condition.valid_until,
    )
    assert source.value_sha256 == runtime_source_value_sha256(
        "clock",
        arguments["snapshot"],
        arguments["batch"],
        evidence.inputs,
    )
    assert source.source_sha256 == descriptor.semantic_sha256 and source.status == "unavailable"
    assert source.revision == 7


@pytest.mark.parametrize("change", ["time", "phase", "duplicate_role"])
def test_callback_cannot_refresh_original_boundary_or_duplicate_authenticator_roles(change):
    port, evaluator, arguments = evidence_fixture()
    now = arguments["evaluated_at"]
    if change == "time":
        arguments["evaluated_at"] += timedelta(microseconds=1)
    elif change == "phase":
        arguments["phase"] = "activation"
    else:
        value = RuntimeSourceCondition("clock", now, now, now, 0, "blocked", ("BLOCKED",))
        evaluator.values = (value, value)
    with pytest.raises(ValueError):
        port.build(**arguments)


def test_activation_records_later_check_but_preserves_original_snapshot_and_source_expiry():
    port, evaluator, arguments = evidence_fixture()
    original = arguments["snapshot"]
    checked = arguments["evaluated_at"] + timedelta(milliseconds=100)
    descriptor = replace(
        port.descriptor,
        request_kind="activation_dependencies",
        original_checked_at=checked,
        captured_fence=replace(port.descriptor.captured_fence, validated_at=checked),
    )
    port = ContinuousRuntimeEvidencePort(
        descriptor=descriptor,
        assignment=port.assignment,
        obligations=port.obligations,
        original_heads=port.original_heads,
        cash_restrictions=None,
        reconciliation=None,
        evaluator=evaluator,
    )
    condition = RuntimeSourceCondition(
        "clock",
        original.point.knowledge_at,
        original.point.knowledge_at,
        checked - timedelta(microseconds=1),
        1,
        "unavailable",
        ("CLOCK_EXPIRED",),
    )
    evaluator.values = (condition,)
    arguments.update(phase="activation", evaluated_at=checked)
    result = port.build(**arguments)
    assert evaluator.observed["snapshot"] is original
    assert result.produced_at == checked
    assert result.inputs.snapshot_sha256 == original.semantic_sha256
    assert result.inputs.sources[0].valid_until == condition.valid_until
    assert result.reasons
    port.descriptor = replace(descriptor, request_kind="frontier")
    with pytest.raises(ValueError, match="ORIGINAL_BOUNDARY"):
        port.build(**{**arguments, "phase": "decision"})


@pytest.mark.parametrize("reason", ["/private/example", "provider said secret", "", "A" * 97])
def test_authenticator_diagnostics_must_be_static_bounded_codes(reason):
    _, (_, _, _, _, _, now) = descriptor_fixture()
    with pytest.raises(ValueError, match="CONDITION"):
        RuntimeSourceCondition("clock", now, now, now, 0, "unavailable", (reason,))


def test_role_reference_inventory_is_bounded_unique_and_semantic():
    descriptor, _ = descriptor_fixture()
    original = ContinuousRuntimeRoleReferences("clock", (descriptor.request,))
    retained = replace(descriptor, role_references=(original,))
    assert retained.semantic_sha256 != descriptor.semantic_sha256
    for values in ((original, original), (original,) * 65):
        with pytest.raises(ValueError):
            replace(descriptor, role_references=values)
    with pytest.raises(ValueError):
        ContinuousRuntimeRoleReferences("clock", (descriptor.request,) * 2)
