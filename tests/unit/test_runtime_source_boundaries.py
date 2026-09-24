"""A source tape cannot grant canonical runtime activation or unsent release."""

from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

import pytest

from packages.application.causal_engine import _Stop, advance_continuous_engine, run_causal_engine
from packages.application.personal_inputs import synthetic_engine_inputs
from packages.application.reference_strategy import ReferenceStrategy
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.accounting_contracts import (
    AccountingCommand,
    ActivateRuntimeCommitments,
    RuntimeActivationTerms,
)
from packages.domain.continuous_engine_contracts import ClosedEngineFrontier
from packages.domain.engine_contracts import EngineEvent, ObservationProvenance
from packages.domain.personal_contracts import content_digest
from packages.domain.research_dataset import ResearchDataClass
from tests.unit.test_causal_checkpoint import PINS
from tests.unit.test_continuous_engine import inputs_and_prices, start


def event(account, at):
    sha = "a" * 64
    term = RuntimeActivationTerms(
        commitment_id="example-hold",
        expected_commitment_sha256=sha,
        reserved_cash=Decimal("101"),
        reserved_sell_quantity=Decimal(0),
        approved_price=Decimal("100"),
        remaining_fee_budget=Decimal(1),
        activation_sha256=sha,
        dispatch_sha256=sha,
    )
    payload = ActivateRuntimeCommitments(
        account_id=account,
        source_state_sha256=sha,
        source_snapshot_sha256=sha,
        original_policy_sha256=sha,
        decision_sha256=sha,
        evidence_sha256=sha,
        checked_at=at,
        expires_at=at + timedelta(seconds=1),
        terms=(term,),
    )
    command = AccountingCommand("untrusted-activation-command", payload)
    return EngineEvent(
        "untrusted-source",
        at,
        at,
        command,
        ObservationProvenance(
            ResearchDataClass.SYNTHETIC_FIXTURE,
            "synthetic-negative-case",
            content_digest(command),
            simulated_available_at=at,
            assumption_id="explicit-negative-fixture",
        ),
    )


def test_continuous_source_cannot_activate_runtime_reserves():
    inputs, _ = inputs_and_prices()
    checkpoint = start(inputs)
    at = checkpoint.now + timedelta(seconds=1)
    frontier = ClosedEngineFrontier(
        frontier_id="untrusted-activation",
        stream_id=inputs.spec.run_id,
        previous_checkpoint_sha256=checkpoint.semantic_sha256,
        source_frontier_sha256="b" * 64,
        knowledge_at=at,
        events=(event(inputs.spec.account_id, at),),
    )
    with pytest.raises(_Stop) as rejected:
        advance_continuous_engine(
            checkpoint,
            frontier,
            expected_sha256=checkpoint.semantic_sha256,
            accounting=PersonalAccounting(),
            strategy=ReferenceStrategy(),
        )
    assert rejected.value.reason == "ENGINE_OR_VENUE_OWNED_COMMAND_IN_SOURCE"


def test_finite_source_cannot_activate_runtime_reserves():
    inputs = synthetic_engine_inputs(fixture="flat", pins=PINS, session_count=8, warmup_count=2)
    at = inputs.events[0].knowledge_at
    events = tuple(
        sorted(
            (*inputs.events, event(inputs.spec.account_id, at)), key=lambda value: value.event_id
        )
    )
    inputs = replace(
        inputs, events=events, spec=replace(inputs.spec, events_sha256=content_digest(events))
    )
    result = run_causal_engine(
        inputs, accounting=PersonalAccounting(), strategy=ReferenceStrategy()
    )
    assert result.status == "rejected"
    assert "ENGINE_OWNED_COMMAND_IN_SOURCE_TAPE" in result.reasons
