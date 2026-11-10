"""Fresh HALTED initialization only; controlled clocks are not host qualification.

The actual-clock node selects one explicit per-run weekday fixture. Its genuine
16:00..20:00 New York prerequisite HOLD is not acceptance. All other nodes use
private modeled clock seams, real temporary SQL and private artifact stores.
"""

import os
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config

from apps.trader import prospective_session_capture as retention_app
from apps.trader import prospective_session_genesis as genesis_app
from apps.trader import synthetic_session_genesis as modeled_app
from apps.trader.synthetic_session_capture import capture_synthetic_bootstrap
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.adapters.synthetic_forward_capture import (
    SyntheticForwardCaptureTransport,
    SyntheticForwardCaptureVerifier,
)
from packages.application import personal_codec as codec
from packages.application.continuous_source_events import compile_continuous_bootstrap
from packages.application.personal_forward_capture import capture_forward, replay_capture
from packages.application.prospective_synthetic_inputs import prospective_synthetic_inputs
from packages.application.synthetic_continuous_inputs import synthetic_continuous_inputs
from packages.domain.account_coordinator import AccountLeasePolicy
from packages.domain.clock import SimulatedClock
from packages.domain.continuous_forward_contracts import ContinuousForwardClosure
from packages.domain.durable_journal_contracts import empty_head
from packages.domain.engine_contracts import BenchmarkPrice, DailyPrice
from packages.domain.forward_capture_contracts import CAPTURE_SCHEMA, ForwardCaptureRecord
from packages.domain.forward_contracts import ForwardDataState
from packages.domain.identifiers import canonical_id
from packages.domain.operational_control import OperationalControlState
from packages.domain.personal_contracts import VersionPin, content_digest
from packages.persistence.account_coordinator import SqlAccountCoordinator
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.continuous_forward_sources import SqlContinuousForwardSources
from packages.persistence.daily_runtime_risk_schema import DAILY_RUNTIME_TABLES
from packages.persistence.database import EXPECTED_SCHEMA_REVISION, create_database_engine
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.durable_journal_schema import JOURNAL_TABLES, journal_entries
from packages.persistence.forward_capture_publication import SqlForwardCapturePublication
from packages.persistence.schema import (
    metadata,
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
    phase5_operational_control_transitions,
)

ROOT = Path(__file__).resolve().parents[2]
NEW_YORK = ZoneInfo("America/New_York")
PINS = tuple(
    VersionPin(name, "prospective-genesis-test-only/1", content_digest((name, "synthetic")))
    for name in sorted(
        (
            "engine",
            "source",
            "dependency_lock",
            "tzdata",
            "availability",
            "actions",
            "numeric",
            "benchmark",
            "report",
            "dirty_patch",
        )
    )
)
VENUE = VersionPin("synthetic-venue", "prospective-test-model/1", content_digest("venue"))
PRODUCER = VersionPin("synthetic-capture", "prospective-test-model/1", content_digest("capture"))
DEFAULT_START = date(2026, 3, 5)
DEFAULT_AT = datetime(2026, 3, 9, 13, tzinfo=UTC)


def _plan(*, start=DEFAULT_START, candidate=DEFAULT_AT):
    return prospective_synthetic_inputs(
        fixture="regime", pins=PINS, start=start, initialized_at=candidate
    )


def _exclusive_file(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(descriptor)


@contextmanager
def _stores(parent, *, migrated=False):
    root = parent / "fresh-prospective-genesis"
    root.mkdir(mode=0o700)
    account_path, venue_path = root / "account.sqlite", root / "venue.sqlite"
    for path in (account_path, venue_path):
        _exclusive_file(path)
        if migrated:
            url = f"sqlite+pysqlite:///{path}"
            configuration = Config()
            configuration.set_main_option("script_location", str(ROOT / "migrations"))
            configuration.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
            configuration.attributes["aqt_explicit_database_url"] = url
            command.upgrade(configuration, EXPECTED_SCHEMA_REVISION)
    with ExitStack() as cleanup:
        account = create_database_engine(f"sqlite+pysqlite:///{account_path}")
        cleanup.callback(account.dispose)
        venue = create_database_engine(f"sqlite+pysqlite:///{venue_path}")
        cleanup.callback(venue.dispose)
        if not migrated:
            metadata.create_all(account)
            metadata.create_all(venue)
        artifacts = LocalResearchArtifactStore(root / "account-objects")
        venue_artifacts = LocalResearchArtifactStore(root / "venue-objects")
        journal = SqlDurableJournal(
            account, codec=codec, record_types={CAPTURE_SCHEMA: ForwardCaptureRecord}
        )
        yield SimpleNamespace(
            root=root,
            account_engine=account,
            venue_engine=venue,
            account_artifacts=artifacts,
            venue_artifacts=venue_artifacts,
            journal=journal,
            publisher=SqlForwardCapturePublication(account, journal=journal),
        )


class _AdvancingClock:
    def __init__(self, instant):
        self.origin = self.instant = instant

    def now(self):
        result = self.instant
        self.instant += timedelta(microseconds=100)
        return result

    def monotonic_ns(self):
        delta = self.instant - self.origin
        return (
            1_000_000_000
            + ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000
        )


@contextmanager
def _study(parent, monkeypatch, *, start=DEFAULT_START, at=DEFAULT_AT, retain=True):
    with _stores(parent) as ports:
        clock = _AdvancingClock(at)
        with monkeypatch.context() as patch:
            patch.setattr(retention_app, "SystemClock", lambda: clock)
            patch.setattr(retention_app, "time", SimpleNamespace(monotonic_ns=clock.monotonic_ns))
            patch.setattr(genesis_app, "SystemClock", lambda: clock)
            patch.setattr(genesis_app, "time", SimpleNamespace(monotonic_ns=clock.monotonic_ns))
            plan = _plan(start=start, candidate=at)
            retention = _retain(ports, plan) if retain else None
            yield SimpleNamespace(ports=ports, clock=clock, plan=plan, retention=retention)


@pytest.fixture
def study(tmp_path, monkeypatch):
    with _study(tmp_path, monkeypatch) as value:
        yield value


def _retain(ports, plan):
    return retention_app.retain_prospective_synthetic_warmup(
        plan,
        calendar_pin=VersionPin(
            "synthetic-calendar",
            "prospective-test-model/1",
            content_digest(plan.inputs.spec.calendar),
        ),
        producer_pin=PRODUCER,
        journal=ports.journal,
        publisher=ports.publisher,
        artifacts=ports.account_artifacts,
        codec=codec,
    )


def _arguments(ports):
    return {
        "account_engine": ports.account_engine,
        "venue_engine": ports.venue_engine,
        "account_artifacts": ports.account_artifacts,
        "venue_artifacts": ports.venue_artifacts,
        "owner_id": "prospective-startup-test",
        "venue_pin": VENUE,
        "quote_producer": PRODUCER,
    }


def _call(study, **changed):
    return genesis_app.initialize_prospective_synthetic_session(
        study.retention, **(_arguments(study.ports) | changed)
    )


def _rows(engine, tables):
    with engine.connect() as connection:
        return tuple(
            (
                table.name,
                tuple(
                    tuple(row)
                    for row in connection.execute(
                        sa.select(table).order_by(*table.primary_key.columns)
                    )
                ),
            )
            for table in tables
        )


def _objects(store):
    return tuple((path.name, path.read_bytes()) for path in sorted(store._root.iterdir()))


def _facts(ports):
    return (
        _rows(ports.account_engine, metadata.sorted_tables),
        _rows(ports.venue_engine, metadata.sorted_tables),
        _objects(ports.account_artifacts),
        _objects(ports.venue_artifacts),
    )


def _counts(engine, tables):
    with engine.connect() as connection:
        return tuple(
            connection.scalar(sa.select(sa.func.count()).select_from(table)) for table in tables
        )


def _released(ports):
    assert _counts(
        ports.account_engine, (phase2_account_leases, phase2_account_lease_releases)
    ) == (1, 1)
    with ports.account_engine.connect() as connection:
        head = connection.execute(sa.select(phase2_account_lease_heads)).mappings().one()
    assert head["last_fencing_generation"] == 1
    assert head["current_fencing_generation"] is None and head["current_lease_sha256"] is None


def _positive(result, retention, ports, *, before, after):
    inputs, state = result.restored.checkpoint.inputs, result.restored.checkpoint.state
    spec = inputs.spec
    assert result.restored.receipt.commit.sequence == 1 and result.restored.request == inputs
    assert before <= result.lease.acquired_at <= spec.initialized_at <= after
    assert spec.initialized_at >= max(p.record.receipt.validated_at for p in retention.publications)
    first = next(
        s for s in spec.calendar.sessions if s.session_label == spec.window.scored_sessions[0]
    )
    assert spec.initialized_at < first.closes_at
    assert spec.initialized_at != retention.plan.inputs.spec.initialized_at
    assert spec.live_authorized is False and spec.initial_cash == Decimal("10000")
    assert spec.risk_policy == retention.plan.inputs.spec.risk_policy
    assert spec.execution_policy == retention.plan.inputs.spec.execution_policy
    assert len(inputs.bootstrap_events) == 4
    assert sum(type(e.payload) is DailyPrice for e in inputs.bootstrap_events) == 2
    assert sum(type(e.payload) is BenchmarkPrice for e in inputs.bootstrap_events) == 2
    daily = sorted(
        (e.payload for e in inputs.bootstrap_events if type(e.payload) is DailyPrice),
        key=lambda p: p.session,
    )
    benchmarks = sorted(
        (e for e in inputs.bootstrap_events if type(e.payload) is BenchmarkPrice),
        key=lambda e: e.economic_at,
    )
    assert tuple(p.close_price for p in daily) == (Decimal("100"), Decimal("100.1"))
    assert tuple(e.payload.unit_price for e in benchmarks) == (Decimal("100"), Decimal("100.1"))
    assert all(e.payload.representation == "synthetic_total_return_units" for e in benchmarks)
    assert all(e.knowledge_at == spec.initialized_at for e in inputs.bootstrap_events)
    assert spec.bootstrap_events_sha256 == content_digest(inputs.bootstrap_events)
    assert spec.run_id != retention.plan.inputs.spec.run_id
    assert len(state.cash_flows) == 1 and state.cash_flows[0].amount == Decimal("10000")
    assert state.cash_flows[0].currency == "USD"
    assert (
        state.cash_flows[0].effective_at == state.cash_flows[0].recorded_at == spec.initialized_at
    )
    assert not state.submissions and not state.broker_events and not state.commitments
    assert not result.restored.checkpoint.runtime_decisions
    assert result.inventory.assignment is None and not result.inventory.assignment_rows
    assert not result.inventory.admissions and not result.inventory.obligations.bindings
    assert not result.inventory.attempts and not result.inventory.attempt_envelopes
    assert not result.inventory.observed_groups
    assert result.inventory.control == result.control
    assert result.control.effective_state is OperationalControlState.HALTED
    assert result.control.sequence_number == 1 and result.control.active_operation is None
    assert _counts(ports.account_engine, DAILY_RUNTIME_TABLES) == (0,) * len(DAILY_RUNTIME_TABLES)
    venue = result.venue.read()
    assert venue.head.sequence == 1 and venue.state.sequence == 0
    assert len(venue.state.accounting.cash_flows) == 1
    assert venue.state.accounting.cash_flows[0].amount == Decimal("10000")
    assert venue.state.accounting.cash_flows == state.cash_flows
    assert not venue.state.commands and not venue.state.acknowledgments
    assert not venue.state.accounting.submissions and not venue.state.accounting.commitments
    assert (
        result.venue.model.live_authorized is False
        and result.venue.model.source_mode == "synthetic_fixture"
    )
    assert result.venue.verified_sources is None
    assert _counts(ports.venue_engine, JOURNAL_TABLES) == (1, 1, 1)
    assert _counts(
        ports.venue_engine,
        (continuous_account_commits, phase5_operational_control_transitions, phase2_account_leases),
    ) == (0, 0, 0)
    assert _counts(ports.venue_engine, DAILY_RUNTIME_TABLES) == (0,) * len(DAILY_RUNTIME_TABLES)
    assert result.lease.revision_number == result.lease.fencing_generation == 1
    assert result.lease.expires_at - result.lease.acquired_at == timedelta(seconds=60)
    assert (
        result.lease.policy_sha256
        == AccountLeasePolicy(
            "synthetic-session-account-lease/1",
            "1",
            timedelta(seconds=60),
            timedelta(seconds=5),
            timedelta(seconds=10),
        ).semantic_sha256
    )
    assert (
        result.release.fence == result.lease.fence
        and result.release.lease_sha256 == result.lease.semantic_sha256
    )
    assert result.account.coordinator.current() is None
    assert result.runtime_sources.benchmark_instrument_id == "US-ETF-SPY"
    assert (
        result.runtime_sources.operating.clock_sampler.profile == "explicit_simulation_time_model"
    )
    result.account.require_resolved(result.restored)
    result.daily.require_resolved_snapshot(result.inventory)
    _released(ports)
    reference = result.restored.receipt.commit.source_evidence
    body = ports.account_artifacts.read(reference.object_ref)
    assert sha256(body).hexdigest() == reference.object_ref.object_sha256
    closure = codec.decode_record(body, ContinuousForwardClosure)
    assert (
        closure.admitted_at == spec.initialized_at
        and closure.publications == retention.publications
    )
    assert closure.initial_state == retention.initial_state
    assert retention.publications[0].journal_receipt.previous_head == empty_head(
        retention.publications[0].record.request.journal_key
    )
    assert (
        tuple(sorted(o.observation_id for o in retention.state.observations))
        == closure.observation_ids
    )
    assert (
        tuple(p.record.request.session for p in closure.publications)
        == retention.plan.inputs.spec.window.warmup_sessions
    )
    assert closure.closure_id == canonical_id(
        "prospective-synthetic-initialization/1",
        retention.plan_sha256,
        spec.initialized_at,
        tuple(p.semantic_sha256 for p in retention.publications),
        closure.observation_ids,
    )
    source = SqlContinuousForwardSources(
        ports.account_engine,
        artifacts=ports.account_artifacts,
        codec=codec,
        evidence_class="synthetic_fixture",
    )
    resolved = source.resolve(closure)
    source.require_resolved(resolved)
    assert resolved.state == retention.state
    assert (
        compile_continuous_bootstrap(
            spec,
            resolved.state,
            closure.observation_ids,
            spec.initialized_at,
            benchmark_instrument_id="US-ETF-SPY",
            capture_evidence_class="synthetic_fixture",
        )
        == inputs
    )


def _actual_plan(now):
    local = now.astimezone(NEW_YORK)
    if local.weekday() < 5 and time(16) <= local.time() < time(20):
        pytest.skip(
            "S4_2B_ACTUAL_WINDOW_HOLD: no weekday plan between NY16:00 and NY20:00; "
            "skip is not acceptance"
        )
    first = local.date()
    if first.weekday() >= 5 or local.time() >= time(20):
        first += timedelta(days=1)
        while first.weekday() >= 5:
            first += timedelta(days=1)
    start = first
    for _ in range(2):
        start -= timedelta(days=1)
        while start.weekday() >= 5:
            start -= timedelta(days=1)
    plan = _plan(start=start, candidate=now)
    assert max(e.knowledge_at for e in plan.inputs.bootstrap_events) <= now
    assert now < next(
        s.closes_at for s in plan.inputs.spec.calendar.sessions if s.session_label == first
    )
    return plan


def test_actual_migrated_private_initialization_uses_real_new_time_and_original_financial_owners(
    tmp_path, record_property
):
    before = datetime.now(UTC)
    plan = _actual_plan(before)
    record_property("declared_start", plan.inputs.spec.window.warmup_sessions[0].isoformat())
    record_property("declared_candidate", before.isoformat())
    with _stores(tmp_path, migrated=True) as ports:
        for engine in (ports.account_engine, ports.venue_engine):
            with engine.connect() as connection:
                assert tuple(
                    connection.scalars(sa.text("SELECT version_num FROM alembic_version"))
                ) == (EXPECTED_SCHEMA_REVISION,)
        retention = _retain(ports, plan)
        original = codec.encode_record((retention.plan.inputs, retention.plan.daily_events))
        result = genesis_app.initialize_prospective_synthetic_session(
            retention, **_arguments(ports)
        )
        _positive(result, retention, ports, before=before, after=datetime.now(UTC))
        assert codec.encode_record((retention.plan.inputs, retention.plan.daily_events)) == original


@pytest.mark.parametrize(
    "start,at",
    [
        (date(2026, 3, 5), datetime(2026, 3, 9, 13, tzinfo=UTC)),
        (date(2026, 10, 29), datetime(2026, 11, 2, 14, tzinfo=UTC)),
    ],
)
def test_controlled_advancing_utc_builds_new_compiled_identity_without_retiming_the_plan(
    tmp_path, monkeypatch, start, at
):
    with _study(tmp_path, monkeypatch, start=start, at=at) as study:
        original = codec.encode_record((study.plan.inputs, study.plan.daily_events))
        result = _call(study)
        _positive(result, study.retention, study.ports, before=at, after=study.clock.instant)
        assert codec.encode_record((study.plan.inputs, study.plan.daily_events)) == original


def _captured_profile(study, fault):
    """Produce real collector records that violate only the new entry profile."""
    calendar = VersionPin(
        "synthetic-calendar",
        "prospective-test-model/1",
        content_digest(study.plan.inputs.spec.calendar),
    )
    scenarios = retention_app._prepare_scenarios(study.plan, calendar, PRODUCER)
    source = scenarios[0].request.source
    initial = state = ForwardDataState((source,), "recorded")
    publications = []
    samples = retention_app._ActualSamples()
    for index, scenario in enumerate(scenarios):
        start = samples.sample().at
        request = replace(
            scenario.request,
            capture_id=f"genuine-adverse-{fault}-{index}",
            window_start=start,
            window_end=start + timedelta(seconds=4 if fault == "wide_window" else 3),
        )
        if fault == "second_producer" and index == 1:
            request = replace(
                request, producer=replace(PRODUCER, sha256=content_digest("different producer"))
            )
        body = (
            scenario.body.replace(b'"volume":0', b'"volume":1').replace(
                b'"adjVolume":0', b'"adjVolume":1'
            )
            if fault == "changed_body" and index == 1
            else scenario.body
        )
        publication = capture_forward(
            request,
            state,
            expected_head=study.ports.journal.read_head(request.journal_key),
            clock=retention_app._ActualCaptureClock(samples),
            verifier=SyntheticForwardCaptureVerifier(
                request, producer=request.producer, valid_until=request.window_end
            ),
            transport=SyntheticForwardCaptureTransport(request, body=body),
            journal=study.ports.journal,
            publisher=study.ports.publisher,
            artifacts=study.ports.account_artifacts,
            codec=codec,
        )
        publications.append(publication)
        state = replay_capture(publication.record, state, artifacts=study.ports.account_artifacts)
    return retention_app.ProspectiveSyntheticWarmupRetention(
        study.plan,
        content_digest((study.plan.inputs, study.plan.daily_events)),
        initial,
        tuple(publications),
        state,
    )


@pytest.mark.parametrize("fault", ["wide_window", "second_producer", "changed_body"])
def test_genuinely_captured_wrong_request_pin_or_body_profile_fails_new_entry_prelease(
    tmp_path, monkeypatch, fault
):
    with _study(tmp_path, monkeypatch, retain=False) as study:
        study.retention = _captured_profile(study, fault)
        for publication in study.retention.publications:
            publication.record.__post_init__()  # Valid native fixtures reached the NEW entry.
        assert _counts(study.ports.account_engine, (journal_entries,)) == (2,)
        before = _facts(study.ports)
        with pytest.raises(
            ValueError, match="prospective capture request, body or acquisition profile differs"
        ):
            _call(study)
        assert _facts(study.ports) == before


@pytest.mark.parametrize("fault", ["digest", "state", "order"])
def test_changed_retention_data_cannot_claim_original_source_ownership(study, fault):
    if fault == "digest":
        study.retention = replace(study.retention, plan_sha256="a" * 64)
    elif fault == "state":
        study.retention = replace(study.retention, state=study.retention.initial_state)
    else:
        study.retention = replace(
            study.retention, publications=tuple(reversed(study.retention.publications))
        )
    before = _facts(study.ports)
    with pytest.raises(ValueError):
        _call(study)
    assert _facts(study.ports) == before


@pytest.mark.parametrize("fault", ["missing", "corrupt"])
def test_original_source_owner_rejects_missing_or_corrupt_raw_bytes_before_lease(study, fault):
    reference = study.retention.publications[0].record.raw_object
    path = study.ports.account_artifacts._root / (reference.object_sha256 + ".json")
    if fault == "missing":
        path.unlink()
    else:
        payload = path.read_bytes()
        path.write_bytes(bytes([payload[0] ^ 1]) + payload[1:])
    before = _facts(study.ports)
    with pytest.raises(ValueError):
        _call(study)
    assert _facts(study.ports) == before
    assert _counts(study.ports.account_engine, (phase2_account_leases,)) == (0,)


def test_missing_actual_capture_journal_record_is_not_reconstructed_from_receipt_data(study):
    with study.ports.account_engine.begin() as connection:
        connection.execute(journal_entries.delete().where(journal_entries.c.sequence == 1))
    before = _facts(study.ports)
    with pytest.raises(ValueError):
        _call(study)
    assert _facts(study.ports) == before


@pytest.mark.parametrize("fault", ["database_alias", "extra_object"])
def test_original_fresh_store_guard_rejects_alias_or_extra_object_before_acquisition(study, fault):
    changed = {}
    if fault == "database_alias":
        changed["venue_engine"] = study.ports.account_engine
    else:
        study.ports.account_artifacts.put(b"unrelated existing bytes")
    before = _facts(study.ports)
    with pytest.raises(ValueError):
        _call(study, **changed)
    assert _facts(study.ports) == before
    assert _counts(study.ports.account_engine, (phase2_account_leases,)) == (0,)


@pytest.mark.parametrize("late", [timedelta(0), timedelta(microseconds=1)])
def test_new_actual_initialization_rejects_equal_or_elapsed_close_and_releases(
    study, monkeypatch, late
):
    first = study.plan.inputs.spec.window.scored_sessions[0]
    close = next(
        s.closes_at for s in study.plan.inputs.spec.calendar.sessions if s.session_label == first
    )
    original = SqlAccountCoordinator.acquire

    def acquire(self, owner):
        # Acquire at the ordinary modeled operation time, then simulate the actual
        # initialization sample crossing close WITHOUT consuming the lease TTL.
        study.clock.instant = close - timedelta(seconds=1)
        lease = original(self, owner)
        study.clock.instant = close + late
        return lease

    before_venue = _rows(study.ports.venue_engine, JOURNAL_TABLES)
    with monkeypatch.context() as patch:
        patch.setattr(SqlAccountCoordinator, "acquire", acquire)
        with pytest.raises(
            ValueError, match="continuous startup must precede the first operating close"
        ):
            _call(study)
    assert _counts(
        study.ports.account_engine,
        (continuous_account_commits, phase5_operational_control_transitions),
    ) == (0, 0)
    assert _rows(study.ports.venue_engine, JOURNAL_TABLES) == before_venue
    _released(study.ports)


@pytest.mark.parametrize("fault", ["future_receipts", "regressed_initialization"])
def test_actual_time_guards_do_not_backdate_source_or_initialization(study, monkeypatch, fault):
    if fault == "future_receipts":
        study.clock.instant = study.retention.publications[
            0
        ].record.receipt.requested_at - timedelta(seconds=1)
        before = _facts(study.ports)
        with pytest.raises(ValueError):
            _call(study)
        assert _facts(study.ports) == before
    else:
        original = SqlAccountCoordinator.acquire

        def acquire(self, owner):
            lease = original(self, owner)
            study.clock.instant = lease.acquired_at - timedelta(seconds=1)
            return lease

        with monkeypatch.context() as patch:
            patch.setattr(SqlAccountCoordinator, "acquire", acquire)
            with pytest.raises(BaseExceptionGroup) as caught:
                _call(study)
        assert "prospective initialization clock regressed" in str(caught.value.exceptions[0])
        assert len(caught.value.exceptions) == 2  # Original release also rejects regressed time.
        assert _counts(
            study.ports.account_engine,
            (phase2_account_leases, phase2_account_lease_releases, continuous_account_commits),
        ) == (1, 0, 0)
        assert _counts(study.ports.account_engine, (phase5_operational_control_transitions,)) == (
            0,
        )
        assert _counts(study.ports.venue_engine, JOURNAL_TABLES) == (0, 0, 0)


def test_original_lease_expiry_preserves_failed_cleanup_instead_of_faking_release(
    study, monkeypatch
):
    original = SqlAccountCoordinator.acquire
    acquired = []

    def acquire(self, owner):
        lease = original(self, owner)
        acquired.append(lease)
        study.clock.instant = lease.expires_at + timedelta(microseconds=1)
        return lease

    with monkeypatch.context() as patch:
        patch.setattr(SqlAccountCoordinator, "acquire", acquire)
        with pytest.raises(BaseExceptionGroup) as caught:
            _call(study)
    assert len(caught.value.exceptions) == 2 and len(acquired) == 1
    assert acquired[0].expires_at - acquired[0].acquired_at == timedelta(seconds=60)
    assert _counts(
        study.ports.account_engine,
        (phase2_account_leases, phase2_account_lease_releases, continuous_account_commits),
    ) == (1, 0, 0)
    with study.ports.account_engine.connect() as connection:
        head = connection.execute(sa.select(phase2_account_lease_heads)).mappings().one()
    assert head["current_lease_sha256"] == acquired[0].semantic_sha256
    assert head["current_fencing_generation"] == 1
    assert _counts(study.ports.account_engine, DAILY_RUNTIME_TABLES) == (0,) * len(
        DAILY_RUNTIME_TABLES
    )
    # The unchanged tail retains HALTED control and independent venue genesis
    # before account.prepare performs its first expired-fence read. C remains
    # unpublished; failed release must not erase those original partial facts.
    assert _counts(study.ports.account_engine, (phase5_operational_control_transitions,)) == (1,)
    assert _counts(study.ports.venue_engine, JOURNAL_TABLES) == (1, 1, 1)
    assert len(_objects(study.ports.account_artifacts)) > 2


@pytest.mark.parametrize("phase", ["control_commit", "c_insert", "c_commit"])
def test_partial_actual_commits_are_preserved_and_original_startup_fence_released(
    study, monkeypatch, phase
):
    failure = RuntimeError("injected fresh genesis phase failure")
    original = sa.Connection.commit
    fired = []

    def fail_commit(connection):
        target = False
        if connection.engine is study.ports.account_engine and not fired:
            controls = connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_operational_control_transitions)
            )
            commits = connection.scalar(
                sa.select(sa.func.count()).select_from(continuous_account_commits)
            )
            target = (phase == "control_commit" and controls == 1 and commits == 0) or (
                phase == "c_commit" and commits == 1
            )
        result = original(connection)
        if target:
            fired.append(phase)
            raise failure  # Raise AFTER the original physical commit actually succeeded.
        return result

    def fail_insert(connection, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("INSERT INTO PERSONAL_CONTINUOUS_ACCOUNT_COMMITS"):
            fired.append(phase)
            raise failure

    if phase == "c_insert":
        sa.event.listen(study.ports.account_engine, "before_cursor_execute", fail_insert)
    try:
        with monkeypatch.context() as patch:
            if phase != "c_insert":
                patch.setattr(sa.Connection, "commit", fail_commit)
            with pytest.raises(RuntimeError) as caught:
                _call(study)
        assert caught.value is failure and fired == [phase]
    finally:
        if phase == "c_insert":
            sa.event.remove(study.ports.account_engine, "before_cursor_execute", fail_insert)
    assert _counts(study.ports.account_engine, (continuous_account_commits,)) == (
        1 if phase == "c_commit" else 0,
    )
    assert _counts(study.ports.account_engine, (phase5_operational_control_transitions,)) == (1,)
    assert _counts(study.ports.account_engine, DAILY_RUNTIME_TABLES) == (0,) * len(
        DAILY_RUNTIME_TABLES
    )
    assert _counts(study.ports.venue_engine, JOURNAL_TABLES) == (
        (0, 0, 0) if phase == "control_commit" else (1, 1, 1)
    )
    if phase == "control_commit":
        assert len(_objects(study.ports.account_artifacts)) == 2
    else:
        assert len(_objects(study.ports.account_artifacts)) > 2
    _released(study.ports)
    before = _facts(study.ports)
    with pytest.raises(ValueError):
        _call(study)
    assert _facts(study.ports) == before


def test_primary_and_original_release_failures_remain_separate_without_repair(study, monkeypatch):
    primary, cleanup = RuntimeError("injected C insert"), RuntimeError("injected release")
    released = []

    def fail_insert(connection, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("INSERT INTO PERSONAL_CONTINUOUS_ACCOUNT_COMMITS"):
            raise primary

    def fail_release(self, fence):
        released.append(fence)
        raise cleanup

    sa.event.listen(study.ports.account_engine, "before_cursor_execute", fail_insert)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(SqlAccountCoordinator, "release", fail_release)
            with pytest.raises(BaseExceptionGroup) as caught:
                _call(study)
        assert caught.value.exceptions == (primary, cleanup)
    finally:
        sa.event.remove(study.ports.account_engine, "before_cursor_execute", fail_insert)
    assert len(released) == 1
    assert _counts(
        study.ports.account_engine,
        (phase2_account_leases, phase2_account_lease_releases, continuous_account_commits),
    ) == (1, 0, 0)
    assert _counts(study.ports.venue_engine, JOURNAL_TABLES) == (1, 1, 1)


def test_successful_initialization_cannot_be_repeated_or_adopted(study):
    _call(study)
    before = _facts(study.ports)
    with pytest.raises(ValueError):
        _call(study)
    assert _facts(study.ports) == before


def test_original_modeled_wrapper_keeps_equality_guard_and_publication_order(tmp_path, monkeypatch):
    with _stores(tmp_path) as ports:
        plan = synthetic_continuous_inputs(fixture="regime", pins=PINS)
        bootstrap = capture_synthetic_bootstrap(
            plan,
            calendar_pin=VersionPin(
                "synthetic-calendar",
                "prospective-test-model/1",
                content_digest(plan.inputs.spec.calendar),
            ),
            producer_pin=PRODUCER,
            journal=ports.journal,
            publisher=ports.publisher,
            artifacts=ports.account_artifacts,
            codec=codec,
        )
        args = _arguments(ports) | {
            "clock": SimulatedClock(plan.inputs.spec.initialized_at + timedelta(microseconds=1)),
            "monotonic_now_ns": lambda: 1_000_000_000,
            "epoch_id": "old-modeled-profile-test",
        }
        before = _facts(ports)
        calls = []
        original_fresh, original_values, original_tail = (
            modeled_app._require_fresh_stores,
            modeled_app._synthetic_genesis_values,
            modeled_app._publish_synthetic_genesis_under_lease,
        )
        original_acquire, original_release = (
            SqlAccountCoordinator.acquire,
            SqlAccountCoordinator.release,
        )
        original_compile = modeled_app.compile_continuous_bootstrap
        original_resolve = modeled_app.SqlContinuousForwardSources.resolve

        def fresh(*a, **kw):
            calls.append("fresh")
            return original_fresh(*a, **kw)

        def values(*a, **kw):
            calls.append("seed")
            return original_values(*a, **kw)

        def resolve(self, *a, **kw):
            if "acquire" not in calls:
                calls.append("source")
            return original_resolve(self, *a, **kw)

        def compile_original(*a, **kw):
            calls.append("compile")
            return original_compile(*a, **kw)

        def acquire(self, owner):
            calls.append("acquire")
            return original_acquire(self, owner)

        def tail(*a, **kw):
            calls.append("tail")
            return original_tail(*a, **kw)

        def release(self, fence):
            calls.append("release")
            return original_release(self, fence)

        with monkeypatch.context() as patch:
            patch.setattr(modeled_app, "_require_fresh_stores", fresh)
            patch.setattr(modeled_app, "_synthetic_genesis_values", values)
            patch.setattr(modeled_app.SqlContinuousForwardSources, "resolve", resolve)
            patch.setattr(modeled_app, "compile_continuous_bootstrap", compile_original)
            patch.setattr(modeled_app, "_publish_synthetic_genesis_under_lease", tail)
            patch.setattr(SqlAccountCoordinator, "acquire", acquire)
            patch.setattr(SqlAccountCoordinator, "release", release)
            with pytest.raises(
                ValueError, match="explicit modeled clock must begin at initialization"
            ):
                modeled_app.initialize_synthetic_session(bootstrap, **args)
            assert not calls and _facts(ports) == before
            args["clock"] = SimulatedClock(plan.inputs.spec.initialized_at)
            result = modeled_app.initialize_synthetic_session(bootstrap, **args)
        assert calls == ["fresh", "source", "compile", "seed", "acquire", "tail", "release"]
        assert result.restored.checkpoint.inputs == bootstrap.inputs
        _released(ports)
