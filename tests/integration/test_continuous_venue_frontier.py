"""Actual independent venue/capture stores feed the sole continuous engine offline."""

from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

import pytest

from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec
from packages.application.causal_engine import advance_continuous_engine_with_applications
from packages.application.continuous_venue_frontier import (
    continuous_initial_cash_application,
    project_continuous_venue_frontier,
)
from packages.application.reference_strategy import ReferenceStrategy
from packages.application.stateful_venue import project_stateful_venue
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.ledger_reducer import CashFlowKind, create_cash_flow
from packages.domain.personal_contracts import content_digest
from packages.domain.reconciliation_contracts import ReconciliationScope
from packages.domain.stateful_venue_contracts import VenueCommand
from packages.domain.venue_reconciliation_contracts import VenueAccountBinding, VenueCaptureRequest
from packages.persistence.database import create_database_engine
from packages.persistence.durable_journal_schema import JOURNAL_TABLES
from packages.persistence.schema import metadata
from packages.persistence.stateful_venue import SqlStatefulVenue
from packages.persistence.venue_reconciliation_capture import SqlVenueReconciliationCapture
from tests.integration.test_venue_reconciliation_capture import Clock
from tests.unit.test_continuous_engine import (
    FixtureEvidence,
    economic_values,
    inputs_and_prices,
    start,
)
from tests.unit.test_stateful_venue import FixtureVerifier, model


def test_independent_captured_cash_flow_session_replays_without_duplicate_genesis(tmp_path):
    inputs, _ = inputs_and_prices()
    checkpoint = start(inputs)
    initial = continuous_initial_cash_application(checkpoint, accounting=PersonalAccounting())
    assert initial.applied_at == checkpoint.inputs.spec.initialized_at
    databases = [
        create_database_engine(f"sqlite+pysqlite:///{tmp_path}/{name}.sqlite")
        for name in ("independent-venue", "coordinator-capture")
    ]
    try:
        for database in databases:
            metadata.create_all(database, tables=JOURNAL_TABLES)
        venue_model = model(
            initial_cash_flow=checkpoint.state.cash_flows[0],
            instruments=inputs.spec.instruments,
            execution_policy=replace(
                inputs.spec.execution_policy, model_id="stateful-venue-facts-v1"
            ),
        )
        venue = SqlStatefulVenue(
            databases[0],
            model=venue_model,
            artifacts=LocalResearchArtifactStore(tmp_path / "venue-objects"),
            codec=personal_codec,
            verified_sources=FixtureVerifier(),
            accounting=PersonalAccounting(),
        )
        venue.initialize()
        for i, (amount, name) in enumerate(((500, "deposit"), (-10400, "withdraw")), 1):
            at = checkpoint.now + timedelta(seconds=i)
            cash = create_cash_flow(
                kind=(CashFlowKind.CONTRIBUTION if amount > 0 else CashFlowKind.WITHDRAWAL),
                currency="USD",
                amount=Decimal(abs(amount)),
                effective_at=at,
                recorded_at=at,
                external_reference=name,
            )
            venue.execute(VenueCommand(name, at, cash))
        independent = venue.read()
        scope = ReconciliationScope(
            inputs.spec.account_id,
            venue_model.venue_id,
            "stateful_simulation",
            inputs.spec.account_binding_sha256,
            "stateful_simulation",
        )
        request = VenueCaptureRequest(
            "independent-cash-session",
            VenueAccountBinding(scope, venue_model, content_digest(venue_model), ()),
            checkpoint.now,
            independent.state.as_of,
        )
        clock = Clock(independent.state.as_of + timedelta(seconds=1))
        artifacts = LocalResearchArtifactStore(tmp_path / "capture-objects")
        captures = SqlVenueReconciliationCapture(
            databases[1], artifacts=artifacts, codec=personal_codec, clock=clock
        )
        captured = captures.capture(request, venue=venue)
        boundary = project_continuous_venue_frontier(
            checkpoint=checkpoint,
            capture=captured,
            prior_applications=(initial,),
            frontier_id="cash-closure",
            admitted_at=captured.observed.completed_at + timedelta(seconds=1),
        )
        current, (applied,) = advance_continuous_engine_with_applications(
            checkpoint,
            boundary,
            expected_sha256=checkpoint.semantic_sha256,
            accounting=PersonalAccounting(),
            strategy=ReferenceStrategy(),
            runtime_evidence=FixtureEvidence(inputs.spec),
        )
        assert current.current.snapshot.trade_date_cash == Decimal(100)
        assert applied.duplicate_fact_ids == (initial.fact_id,)
        assert not applied.unresolved_fact_ids and not applied.quarantined_fact_ids
        assert applied.reasons == ("EXTERNAL_ACTIVITY_REQUIRES_OWNER_DISPOSITION",)
        assert current.state.halted
        assert len(current.state.cash_flows) == 3 and len(current.flows) == 3
        assert (
            project_stateful_venue(venue_model, independent.state).snapshot.trade_date_cash == 100
        )
        assert current.current.snapshot.settled_cash == 100
        assert venue.read() == independent
        restarted = SqlVenueReconciliationCapture(
            databases[1],
            artifacts=artifacts,
            codec=personal_codec,
            clock=lambda: pytest.fail("replay refreshed capture time"),
        )
        retained = restarted.read(request)
        assert retained == captured
        replay_boundary = project_continuous_venue_frontier(
            checkpoint=checkpoint,
            capture=retained,
            prior_applications=(initial,),
            frontier_id="cash-closure",
            admitted_at=boundary.knowledge_at,
        )
        replay, replay_batches = advance_continuous_engine_with_applications(
            checkpoint,
            replay_boundary,
            expected_sha256=checkpoint.semantic_sha256,
            accounting=PersonalAccounting(),
            strategy=ReferenceStrategy(),
            runtime_evidence=FixtureEvidence(inputs.spec),
        )
        assert economic_values(replay) == economic_values(current)
        assert replay_batches == (applied,)
        # Re-reading the same fixed-through capture cannot create a new application
        # or replace its original closure/receipt times.
        duplicate = project_continuous_venue_frontier(
            checkpoint=current,
            capture=retained,
            prior_applications=applied.applications,
            frontier_id="duplicate-capture",
            admitted_at=current.now + timedelta(seconds=1),
        )
        assert duplicate.events == boundary.events
        repeated, new_batches = advance_continuous_engine_with_applications(
            current,
            duplicate,
            expected_sha256=current.semantic_sha256,
            accounting=PersonalAccounting(),
            strategy=ReferenceStrategy(),
            runtime_evidence=FixtureEvidence(inputs.spec),
        )
        assert repeated.state == current.state and new_batches == ()
    finally:
        for database in databases:
            database.dispose()
