"""Actual halted factory graph and physical independent SQLite/storage bindings."""

from pathlib import Path

import pytest
import sqlalchemy as sa

from apps.trader.continuous_simulation_factory import ContinuousSimulationFactory
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.persistence.continuous_attempt_publication import SqlContinuousAttemptPublication
from packages.persistence.continuous_simulation_delivery import SqlContinuousSimulationDelivery
from packages.persistence.database import create_database_engine
from packages.persistence.stateful_venue import SqlStatefulVenue
from tests.integration import test_continuous_simulation_factory as factory_fixture
from tests.integration.test_runtime_owner_associations import install_initial_signed_assignment

configured = factory_fixture.configured


@pytest.fixture
def factory(configured):
    fixture, configuration = configured
    install_initial_signed_assignment(fixture)
    factory_fixture.release(fixture)
    value = ContinuousSimulationFactory(
        configuration,
        account_id=fixture[0].base.scope.account_id,
        stop_requested=lambda: False,
    )
    try:
        assert value.account.engine.url.database.startswith("file:")
        yield value, configuration
    finally:
        value.close()


def delivery_for(factory):
    publisher = SqlContinuousAttemptPublication(account=factory.account)
    return SqlContinuousSimulationDelivery(
        publisher=publisher, sources=factory.runtime_sources.attempt_sources
    )


def venue_for(delivery, engine, root):
    return SqlStatefulVenue(
        engine,
        model=delivery.model,
        artifacts=LocalResearchArtifactStore(Path(root)),
        codec=delivery.runtime.codec,
        accounting=delivery.runtime.accounting,
        verified_sources=delivery,
    )


def uri_engine(path):
    url = sa.URL.create(
        "sqlite+pysqlite", database=Path(path).as_uri(), query={"mode": "rw", "uri": "true"}
    )
    return create_database_engine(url.render_as_string(hide_password=True))


def test_actual_factory_accepts_distinct_uri_backed_venue(factory):
    owner, configuration = factory
    delivery = delivery_for(owner)
    engine = uri_engine(configuration.venue_database_path)
    try:
        venue = venue_for(delivery, engine, configuration.venue_artifact_root)
        original = venue.read()
        delivery.bind_venue(venue)
        assert delivery._require_owners() is venue
        assert venue.read() == original
    finally:
        engine.dispose()


@pytest.mark.parametrize("url_kind", ["uri", "ordinary"])
def test_actual_factory_rejects_same_physical_coordinator_database(factory, url_kind):
    owner, configuration = factory
    delivery = delivery_for(owner)
    engine = (
        uri_engine(configuration.database_path)
        if url_kind == "uri"
        else create_database_engine(f"sqlite+pysqlite:///{configuration.database_path}")
    )
    try:
        venue = venue_for(delivery, engine, configuration.venue_artifact_root)
        with pytest.raises(ValueError, match="DISTINCT"):
            delivery.bind_venue(venue)
        assert delivery.venue is None
    finally:
        engine.dispose()


def test_actual_factory_rejects_same_physical_object_root_through_second_store(factory):
    owner, configuration = factory
    delivery = delivery_for(owner)
    engine = uri_engine(configuration.venue_database_path)
    try:
        venue = venue_for(delivery, engine, configuration.artifact_root)
        assert venue.artifacts is not owner.runtime_sources.artifacts
        with pytest.raises(ValueError, match="DISTINCT"):
            delivery.bind_venue(venue)
        assert delivery.venue is None
    finally:
        engine.dispose()


@pytest.mark.parametrize("changed", ["coordinator", "venue"])
def test_bound_original_store_root_cannot_be_replaced(factory, monkeypatch, changed):
    owner, configuration = factory
    delivery = delivery_for(owner)
    engine = uri_engine(configuration.venue_database_path)
    try:
        venue = venue_for(delivery, engine, configuration.venue_artifact_root)
        delivery.bind_venue(venue)
        selected, other = (
            (owner.artifacts, venue.artifacts)
            if changed == "coordinator"
            else (venue.artifacts, owner.artifacts)
        )
        original = venue.read()
        with monkeypatch.context() as patch:
            patch.setattr(selected, "_root", other._root)
            with pytest.raises(ValueError, match="ORIGINAL_SIMULATION_VENUE_CHANGED"):
                delivery._require_owners()
        assert venue.read() == original
    finally:
        engine.dispose()
