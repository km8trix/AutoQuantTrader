"""The real engine prepares state; synthetic evidence does not qualify a provider."""

from dataclasses import replace

import pytest

from packages.application.continuous_account_transition import ContinuousAccountTransitionPreparer
from packages.application.reference_strategy import ReferenceStrategy
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.personal_contracts import content_digest
from tests.unit.test_continuous_engine import FixtureEvidence
from tests.unit.test_continuous_source_events import project, setup


def preparer(inputs):
    return ContinuousAccountTransitionPreparer(
        accounting=PersonalAccounting(),
        strategy=ReferenceStrategy(),
        runtime_evidence=FixtureEvidence(inputs.spec),
    )


def test_actual_engine_initialization_and_frontier_preserve_preinstall_decisions():
    existing, sources = setup()
    owner = preparer(existing.inputs)
    first = owner.prepare_initialize(
        command_id="initialize",
        inputs=existing.inputs,
        source_closure_sha256=content_digest(existing.inputs.bootstrap_events),
    )
    assert not first.new_decisions and first.disposition == "initialized"
    owner.require_prepared(first)
    assert first.checkpoint.state == existing.state
    frontier = project(first.checkpoint, sources)
    second = owner.prepare_frontier(
        command_id="first-session", checkpoint=first.checkpoint, frontier=frontier
    )
    owner.require_prepared(second)
    assert second.previous_checkpoint_sha256 == first.checkpoint.semantic_sha256
    assert second.source_closure_sha256 == frontier.source_frontier_sha256
    assert second.new_decisions == second.checkpoint.runtime_decisions
    assert second.new_decisions and any(d.installed_commitments for d in second.new_decisions)
    retry = owner.prepare_frontier(
        command_id="first-session", checkpoint=second.checkpoint, frontier=frontier
    )
    assert retry.disposition == "idempotent" and not retry.new_decisions
    assert retry.checkpoint is second.checkpoint


@pytest.mark.parametrize("change", ["copy", "command", "checkpoint", "other_owner", "mutate"])
def test_caller_cannot_turn_copied_or_modified_values_into_owned_preparation(change):
    checkpoint, _ = setup()
    owner = preparer(checkpoint.inputs)
    result = owner.prepare_initialize(
        command_id="initialize",
        inputs=checkpoint.inputs,
        source_closure_sha256=content_digest(checkpoint.inputs.bootstrap_events),
    )
    if change == "copy":
        result = replace(result)
    elif change == "command":
        result = replace(result, command_id="replacement")
    elif change == "checkpoint":
        result = replace(result, checkpoint=checkpoint)
    elif change == "other_owner":
        owner = preparer(checkpoint.inputs)
    else:
        object.__setattr__(result, "source_closure_sha256", "f" * 64)
    with pytest.raises(ValueError, match="OWNED"):
        owner.require_prepared(result)


def test_evidence_is_required_and_engine_rejects_wrong_source_parent():
    checkpoint, sources = setup()
    with pytest.raises(ValueError, match="EVIDENCE_REQUIRED"):
        ContinuousAccountTransitionPreparer(
            accounting=PersonalAccounting(), strategy=ReferenceStrategy(), runtime_evidence=None
        )
    frontier = replace(project(checkpoint, sources), previous_checkpoint_sha256="f" * 64)
    with pytest.raises(ValueError):
        preparer(checkpoint.inputs).prepare_frontier(
            command_id="bad-parent", checkpoint=checkpoint, frontier=frontier
        )
