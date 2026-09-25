"""A real modeled order-rejection journal is the source of retained observations."""

from datetime import timedelta

from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec
from packages.application.stateful_venue import venue_order_id
from packages.domain.reconciliation_contracts import ReconciliationScope
from packages.domain.stateful_venue_contracts import VenueCommand, VenueReject
from packages.domain.venue_reconciliation_contracts import (
    VenueAccountBinding,
    VenueCaptureRequest,
    VenueSubmissionBinding,
)
from packages.persistence.database import create_database_engine
from packages.persistence.durable_journal_schema import JOURNAL_TABLES
from packages.persistence.schema import metadata
from packages.persistence.venue_reconciliation_capture import SqlVenueReconciliationCapture
from tests.integration.test_stateful_venue_journal import retained, store  # noqa: F401
from tests.integration.test_venue_reconciliation_capture import Clock
from tests.unit.test_stateful_venue import packet


def test_actual_rejection_survives_venue_restart_and_capture_retry(tmp_path, retained):  # noqa: F811
    venue = store(retained)
    venue.initialize()
    outgoing = packet(venue.model)
    submit = VenueCommand("submitted", outgoing.registration.submission.submitted_at, outgoing)
    assert venue.execute(submit).acknowledgment.disposition == "registered"
    rejection = VenueCommand(
        "independent-rejection",
        submit.received_at + timedelta(seconds=1),
        VenueReject(outgoing.registration.submission.order_id, "modeled-venue-declined"),
    )
    original = venue.execute(rejection)
    assert original.acknowledgment.disposition == "applied"
    restarted = store(retained)
    assert restarted.read_command_receipt(rejection) == original
    independent = restarted.read()
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path}/coordinator-capture.sqlite")
    metadata.create_all(engine, tables=JOURNAL_TABLES)
    capture = SqlVenueReconciliationCapture(
        engine,
        artifacts=LocalResearchArtifactStore(tmp_path / "captured-objects"),
        codec=personal_codec,
        clock=Clock(rejection.received_at),
    )
    request = VenueCaptureRequest(
        "rejected-order-observation",
        VenueAccountBinding(
            ReconciliationScope(
                "coordinator-account",
                venue.model.venue_id,
                "stateful_simulation",
                "a" * 64,
                "stateful_simulation",
            ),
            venue.model,
            venue.model.semantic_sha256,
            (
                VenueSubmissionBinding(
                    outgoing.registration.submission,
                    outgoing.registration.semantic_sha256,
                    venue_order_id(venue.model, outgoing.registration.submission.order_id),
                ),
            ),
        ),
        venue.model.initial_cash_flow.effective_at,
        independent.state.as_of,
        independent.head,
    )
    try:
        result = capture.capture(request, venue=restarted)
        assert len(result.observed.orders) == 1
        order = result.observed.orders[0]
        assert order.order_id == outgoing.registration.submission.order_id
        assert order.status == "rejected" and order.filled_quantity == 0
        assert result.source_order == tuple(fact.fact_id for fact in independent.state.facts)
        assert capture.read(request) == result
        assert restarted.execute(rejection) == original
        assert restarted.read() == independent
    finally:
        engine.dispose()
