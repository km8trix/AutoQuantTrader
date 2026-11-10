"""Fresh source retention only; modeled fault clocks never qualify host time.

The positive uses actual local stages and an exclusively migrated temporary DB.
Other fixtures use real SQL and private byte stores without creating any account,
lease, control, venue owner, bootstrap closure or initialization authority.
"""

import os
from contextlib import ExitStack, contextmanager
from dataclasses import fields, replace
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config

from apps.trader import prospective_session_capture as capture
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec as codec
from packages.application import personal_forward_capture as collector
from packages.application.personal_forward_capture import read_capture, replay_capture
from packages.application.prospective_synthetic_inputs import prospective_synthetic_inputs
from packages.domain.durable_journal_contracts import empty_head
from packages.domain.forward_capture_contracts import CAPTURE_SCHEMA, ForwardCaptureRecord
from packages.domain.personal_contracts import VersionPin, content_digest
from packages.domain.research_dataset import modeled_daily_availability
from packages.persistence.database import EXPECTED_SCHEMA_REVISION, create_database_engine
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.durable_journal_schema import JOURNAL_TABLES, journal_entries
from packages.persistence.forward_capture_publication import SqlForwardCapturePublication
from packages.persistence.schema import metadata

ROOT = Path(__file__).resolve().parents[2]
PINS = tuple(
    VersionPin(name, "prospective-retention-test-only/1", content_digest((name, "synthetic")))
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
WARMUP = (date(2023, 1, 2), date(2023, 1, 3))
MODELED_AT = datetime(2023, 1, 4, 1, tzinfo=UTC)


def _plan(fixture="flat"):
    # A past plan is explicit data. Retaining its bytes does not initialize it or
    # prove its scored window is still prospective at the actual acquisition.
    return prospective_synthetic_inputs(
        fixture=fixture,
        pins=PINS,
        start=date(2023, 1, 2),
        initialized_at=datetime(2023, 1, 4, 14, tzinfo=UTC),
    )


def _exclusive_file(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(descriptor)


@contextmanager
def _stores(parent, *, migrated=False):
    root = parent / "fresh-source-retention"
    root.mkdir(mode=0o700)
    account_path, venue_path = root / "source.sqlite", root / "independent-venue.sqlite"
    _exclusive_file(account_path)
    _exclusive_file(venue_path)
    url = f"sqlite+pysqlite:///{account_path}"
    if migrated:
        configuration = Config()
        configuration.set_main_option("script_location", str(ROOT / "migrations"))
        configuration.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
        configuration.attributes["aqt_explicit_database_url"] = url
        command.upgrade(configuration, EXPECTED_SCHEMA_REVISION)
    with ExitStack() as cleanup:
        engine = create_database_engine(url)
        cleanup.callback(engine.dispose)
        venue = create_database_engine(f"sqlite+pysqlite:///{venue_path}")
        cleanup.callback(venue.dispose)
        if not migrated:
            # These adverses qualify SQL behavior, not migrations. The separate
            # positive below uses the real migration chain without a fake marker.
            metadata.create_all(engine)
        sentinels = sa.MetaData()
        sentinel = sa.Table(
            "retention_independent_sentinel",
            sentinels,
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("value", sa.String(64), nullable=False),
        )
        sentinel.create(engine)
        sentinel.create(venue)
        for database, value in ((engine, "unrelated-account-data"), (venue, "independent-venue")):
            with database.begin() as connection:
                connection.execute(sentinel.insert().values(id=1, value=value))
        artifacts = LocalResearchArtifactStore(root / "source-objects")
        journal = SqlDurableJournal(
            engine, codec=codec, record_types={CAPTURE_SCHEMA: ForwardCaptureRecord}
        )
        yield SimpleNamespace(
            root=root,
            engine=engine,
            venue=venue,
            sentinel=sentinel,
            artifacts=artifacts,
            journal=journal,
            publisher=SqlForwardCapturePublication(engine, journal=journal),
        )


@pytest.fixture
def ports(tmp_path):
    with _stores(tmp_path) as value:
        yield value


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


def _untouched(ports):
    # Includes actual C/B/control/account-lease tables, with their independently
    # empty rows. The unrelated source DB and independent venue sentinels are not
    # empty: freshness must never be mistaken for whole-database emptiness.
    financial = tuple(
        table
        for table in metadata.sorted_tables
        if table.name not in {t.name for t in JOURNAL_TABLES}
    )
    return (
        _rows(ports.engine, (*financial, ports.sentinel)),
        _rows(ports.venue, (ports.sentinel,)),
    )


def _objects(ports):
    return tuple((path.name, path.read_bytes()) for path in sorted(ports.artifacts._root.iterdir()))


def _source_facts(ports):
    return _rows(ports.engine, JOURNAL_TABLES), _objects(ports)


def _arguments(ports, plan):
    return {
        "calendar_pin": VersionPin(
            "synthetic-calendar",
            "retention-test-model/1",
            content_digest(plan.inputs.spec.calendar),
        ),
        "producer_pin": VersionPin(
            "synthetic-producer",
            "retention-test-model/1",
            content_digest("declared synthetic producer"),
        ),
        "journal": ports.journal,
        "publisher": ports.publisher,
        "artifacts": ports.artifacts,
        "codec": codec,
    }


def _call(ports, plan=None, **changed):
    plan = _plan() if plan is None else plan
    return capture.retain_prospective_synthetic_warmup(plan, **(_arguments(ports, plan) | changed))


def _stored_records(ports):
    with ports.engine.connect() as connection:
        payloads = tuple(
            connection.scalars(
                sa.select(journal_entries.c.payload).order_by(journal_entries.c.sequence)
            )
        )
    return tuple(codec.decode_record(payload, ForwardCaptureRecord) for payload in payloads)


def _literal_body(session, *, rises):
    # Literal provider-shaped expectation, independent of the scenario formatter.
    prefix = ('[{"date":"' + session.isoformat() + 'T00:00:00.000Z",').encode("ascii")
    if rises:
        prices = (
            b'"open":1e2,"high":1001e-1,"low":1e2,"close":1001e-1,'
            b'"adjOpen":1e2,"adjHigh":1001e-1,"adjLow":1e2,"adjClose":1001e-1,'
        )
    else:
        prices = (
            b'"open":1e2,"high":1e2,"low":1e2,"close":1e2,'
            b'"adjOpen":1e2,"adjHigh":1e2,"adjLow":1e2,"adjClose":1e2,'
        )
    return prefix + prices + b'"volume":0,"adjVolume":0,"divCash":0,"splitFactor":1}]'


@pytest.mark.parametrize("fixture", ["flat", "regime"])
def test_actual_local_stages_retain_exact_bytes_and_original_publications_without_initialization(
    tmp_path, monkeypatch, fixture
):
    with _stores(tmp_path, migrated=True) as ports:
        with ports.engine.connect() as connection:
            assert tuple(
                connection.scalars(sa.text("SELECT version_num FROM alembic_version"))
            ) == (EXPECTED_SCHEMA_REVISION,)
        before = _untouched(ports)
        plan = _plan(fixture)
        arguments = _arguments(ports, plan)
        produced = []
        original = capture.capture_forward

        def observe(*args, **kwargs):
            publication = original(*args, **kwargs)
            produced.append(publication)
            return publication

        began = datetime.now(UTC)
        with monkeypatch.context() as patch:
            patch.setattr(capture, "capture_forward", observe)
            result = capture.retain_prospective_synthetic_warmup(plan, **arguments)
        ended = datetime.now(UTC)
        assert result.plan is plan
        assert result.plan_sha256 == content_digest((plan.inputs, plan.daily_events))
        assert tuple(field.name for field in fields(result)) == (
            "plan",
            "plan_sha256",
            "initial_state",
            "publications",
            "state",
        )
        assert len(result.publications) == len(produced) == 2
        assert all(
            actual is observed
            for actual, observed in zip(result.publications, produced, strict=True)
        )
        assert not result.initial_state.observations and not result.initial_state.frontiers
        assert result.initial_state.mode == result.state.mode == "recorded"
        assert tuple(p.record.request.session for p in result.publications) == WARMUP
        assert not set(WARMUP) & set(plan.inputs.spec.window.scored_sessions)
        assert len(result.state.observations) == 2 and not result.state.frontiers
        expected_prices = (
            Decimal("100"),
            Decimal("100.1") if fixture == "regime" else Decimal("100"),
        )
        state = result.initial_state
        boot_ids = set()
        for index, publication in enumerate(result.publications):
            record, receipt = publication.record, publication.record.receipt
            request = record.request
            assert request.evidence_class == "synthetic_fixture" and record.live_authorized is False
            assert request.calendar is arguments["calendar_pin"]
            assert request.producer is arguments["producer_pin"]
            assert (
                request.source.provider == "tiingo" and request.source.environment == "production"
            )
            assert request.source.identity_reference.startswith("synthetic-identity-model/1:")
            assert (
                request.source.rights_reference
                == "synthetic-rights-model/1:not-provider-permission"
            )
            assert (
                request.source.entitlement_reference
                == "synthetic-entitlement-model/1:not-provider-entitlement"
            )
            assert request.instruments[0].currency == "USD"
            assert request.deadline_ms == 3000 and request.max_response_bytes == 2 * 1024 * 1024
            assert request.window_end - request.window_start == timedelta(seconds=3)
            assert (
                began
                <= request.window_start
                <= receipt.requested_at
                <= receipt.received_at
                <= receipt.validated_at
                <= ended
            )
            assert receipt.validated_at < request.window_end
            assert (
                0 <= receipt.validated_monotonic_ns - receipt.requested_monotonic_ns < 3_000_000_000
            )
            assert (
                receipt.requested_monotonic_ns
                <= receipt.received_monotonic_ns
                <= receipt.validated_monotonic_ns
            )
            boot_ids.add(receipt.boot_id)
            assert receipt.boot_id.startswith("prospective-synthetic-acquisition/1:")
            for verification in record.verifications:
                assert verification.producer is arguments["producer_pin"]
                assert verification.evidence_class == "synthetic_fixture"
                assert (
                    verification.clock_reference == "synthetic-modeled-clock/1:" + receipt.boot_id
                )
            expected_body = _literal_body(WARMUP[index], rises=fixture == "regime" and index == 1)
            assert ports.artifacts.read(record.raw_object) == expected_body
            assert record.observations[0].payload.close_price == expected_prices[index]
            assert record.observations[0].known_at == receipt.validated_at
            assert receipt.requested_at > modeled_daily_availability(WARMUP[index])
            assert (
                read_capture(request, journal=ports.journal, artifacts=ports.artifacts, codec=codec)
                == publication
            )
            state = replay_capture(record, state, artifacts=ports.artifacts)
        assert len(boot_ids) == 1
        assert state == result.state
        assert result.publications[0].journal_receipt.previous_head == empty_head(
            result.publications[0].record.request.journal_key
        )
        assert (
            ports.journal.read_head(result.publications[-1].record.request.journal_key).sequence
            == 2
        )
        assert len({p.record.request.capture_id for p in result.publications}) == 2
        assert sum(p.record.raw_object.byte_count for p in result.publications) < 32 * 1024 * 1024
        assert _untouched(ports) == before
        # The caller's old candidate/model provenance was not retimed to the host.
        assert plan.inputs.spec.initialized_at == datetime(2023, 1, 4, 14, tzinfo=UTC)
        assert plan.inputs.bootstrap_events[-1].knowledge_at == MODELED_AT


def test_each_serial_capture_gets_a_fresh_window_and_warmup_equality_is_inclusive(
    ports, monkeypatch
):
    clock = SimpleNamespace(instant=MODELED_AT)
    produced = []
    original = capture.capture_forward

    class ModelClock:
        def now(self):
            return clock.instant

    def observe(*args, **kwargs):
        publication = original(*args, **kwargs)
        produced.append(publication)
        clock.instant += timedelta(seconds=4)
        return publication

    before = _untouched(ports)
    with monkeypatch.context() as patch:
        patch.setattr(capture, "SystemClock", ModelClock)
        patch.setattr(capture, "capture_forward", observe)
        result = _call(ports)
    first, second = result.publications
    assert first is produced[0] and second is produced[1]
    assert first.record.request.window_start == MODELED_AT
    assert second.record.request.window_start == MODELED_AT + timedelta(seconds=4)
    assert second.record.request.window_start > first.record.request.window_end
    assert all(
        p.record.receipt.validated_at < p.record.request.window_end for p in result.publications
    )
    assert _untouched(ports) == before


def test_future_second_warmup_prevents_the_first_capture_or_write(ports, monkeypatch):
    class ModelClock:
        def now(self):
            return datetime(2023, 1, 3, 2, tzinfo=UTC)

    plan = _plan()
    assert plan.inputs.bootstrap_events[0].knowledge_at < ModelClock().now()
    assert plan.inputs.bootstrap_events[1].knowledge_at > ModelClock().now()
    before, source = _untouched(ports), _source_facts(ports)

    def forbidden(*_args, **_kwargs):
        pytest.fail("future second warmup must reject before the first collector call")

    with monkeypatch.context() as patch:
        patch.setattr(capture, "SystemClock", ModelClock)
        patch.setattr(capture, "capture_forward", forbidden)
        with pytest.raises(ValueError, match="model availability remains future"):
            _call(ports, plan)
    assert _source_facts(ports) == source
    assert _untouched(ports) == before


def test_unsupported_second_scenario_is_preflighted_before_the_first_capture(ports, monkeypatch):
    plan = _plan()
    events = plan.inputs.bootstrap_events
    unsupported = replace(events[-1].payload, adjusted_close=Decimal("99"))
    last = replace(
        events[-1],
        payload=unsupported,
        provenance=replace(events[-1].provenance, normalized_sha256=content_digest(unsupported)),
    )
    changed = (*events[:-1], last)
    plan = replace(
        plan,
        inputs=replace(
            plan.inputs,
            spec=replace(plan.inputs.spec, bootstrap_events_sha256=content_digest(changed)),
            bootstrap_events=changed,
        ),
    )
    before, source = _untouched(ports), _source_facts(ports)

    def forbidden(*_args, **_kwargs):
        pytest.fail("all scenario bodies must be checked before capture")

    with monkeypatch.context() as patch:
        patch.setattr(capture, "capture_forward", forbidden)
        with pytest.raises(
            ValueError, match=r"^synthetic daily scenario has no action or revision model$"
        ):
            _call(ports, plan)
    assert _source_facts(ports) == source
    assert _untouched(ports) == before


@pytest.mark.parametrize("fault", ["cash", "live", "scored_order"])
def test_changed_fixed_profile_rejects_before_mutation(ports, fault):
    plan = _plan()
    if fault == "cash":
        plan = replace(
            plan,
            inputs=replace(
                plan.inputs, spec=replace(plan.inputs.spec, initial_cash=Decimal("9999"))
            ),
        )
    elif fault == "live":
        object.__setattr__(plan.inputs.spec, "live_authorized", True)
    else:
        plan = replace(plan, daily_events=tuple(reversed(plan.daily_events)))
    before, source = _untouched(ports), _source_facts(ports)
    with pytest.raises(ValueError):
        _call(ports, plan)
    assert _source_facts(ports) == source
    assert _untouched(ports) == before


@pytest.mark.parametrize("fault", ["journal", "codec", "artifacts"])
def test_original_port_graph_and_local_artifact_owner_are_required(ports, fault):
    class ForbiddenPort:
        def encode_record(self, *_args):
            pytest.fail("foreign codec must not run")

        def decode_record(self, *_args):
            pytest.fail("foreign codec must not run")

    changed = {
        "journal": SqlDurableJournal(
            ports.engine, codec=codec, record_types={CAPTURE_SCHEMA: ForwardCaptureRecord}
        ),
        "codec": ForbiddenPort(),
        "artifacts": object(),
    }
    before, source = _untouched(ports), _source_facts(ports)
    with pytest.raises(ValueError):
        _call(ports, **{fault: changed[fault]})
    assert _source_facts(ports) == source
    assert _untouched(ports) == before


@pytest.mark.parametrize("fault", ["public_root", "symlink_root"])
def test_private_local_object_directory_guards_prevent_any_write(ports, monkeypatch, fault):
    root = ports.artifacts._root
    before, source = _untouched(ports), _source_facts(ports)
    try:
        with monkeypatch.context() as patch:
            if fault == "public_root":
                root.chmod(0o755)
            else:
                link = ports.root / "object-root-alias"
                link.symlink_to(root, target_is_directory=True)
                patch.setattr(ports.artifacts, "_root", link)
            with pytest.raises(ValueError):
                _call(ports)
    finally:
        root.chmod(0o700)
    assert _source_facts(ports) == source
    assert _untouched(ports) == before


def test_existing_selected_stream_is_not_adopted_or_retried(ports, monkeypatch):
    _call(ports)
    before, source = _untouched(ports), _source_facts(ports)

    def forbidden(*_args, **_kwargs):
        pytest.fail("nonempty selected stream must reject before collector/idempotent readback")

    with monkeypatch.context() as patch:
        patch.setattr(capture, "capture_forward", forbidden)
        with pytest.raises(ValueError, match="fresh selected capture streams"):
            _call(ports)
    assert _source_facts(ports) == source
    assert _untouched(ports) == before


def test_second_transport_failure_preserves_first_actual_publication_without_retry(
    ports, monkeypatch
):
    original = capture.SyntheticForwardCaptureTransport.get
    calls = []

    def fail_second(self, request, *, deadline_ms):
        calls.append(request)
        if len(calls) == 2:
            raise ValueError("injected second transport failure")
        return original(self, request, deadline_ms=deadline_ms)

    before = _untouched(ports)
    with monkeypatch.context() as patch:
        patch.setattr(capture.SyntheticForwardCaptureTransport, "get", fail_second)
        with pytest.raises(ValueError):
            _call(ports)
    assert len(calls) == 2
    records = _stored_records(ports)
    assert len(records) == len(_objects(ports)) == 1
    assert records[0].request == calls[0] and records[0].request.session == WARMUP[0]
    assert ports.journal.read_head(calls[0].journal_key).sequence == 1
    assert (
        read_capture(calls[0], journal=ports.journal, artifacts=ports.artifacts, codec=codec).record
        == records[0]
    )
    assert _untouched(ports) == before
    retained = _source_facts(ports)
    with pytest.raises(ValueError, match="fresh selected capture streams"):
        _call(ports)
    assert _source_facts(ports) == retained


def test_actual_publication_commit_failure_rolls_back_rows_but_keeps_raw_object(ports, monkeypatch):
    original = sa.Connection.commit
    pending = []

    def fail_commit(connection):
        if connection.engine is ports.engine:
            pending.append(
                connection.scalar(sa.select(sa.func.count()).select_from(journal_entries))
            )
            raise ValueError("injected physical capture commit failure")
        return original(connection)

    before = _untouched(ports)
    with monkeypatch.context() as patch:
        patch.setattr(sa.Connection, "commit", fail_commit)
        with pytest.raises(ValueError):
            _call(ports)
    assert pending == [1]  # Real append rows existed inside the rejected transaction.
    assert not _stored_records(ports)
    assert all(not rows for _name, rows in _rows(ports.engine, JOURNAL_TABLES))
    assert tuple(payload for _name, payload in _objects(ports)) == (
        _literal_body(WARMUP[0], rises=False),
    )
    assert _untouched(ports) == before


@pytest.mark.parametrize("fault", ["utc", "monotonic"])
def test_shared_actual_sampler_rejects_scalar_regression_before_capture(ports, monkeypatch, fault):
    calls = []

    class ModelClock:
        def now(self):
            calls.append("utc")
            return MODELED_AT - (
                timedelta(microseconds=1) if fault == "utc" and len(calls) > 1 else timedelta(0)
            )

    values = iter((1_000_000, 999_999))
    before, source = _untouched(ports), _source_facts(ports)
    with monkeypatch.context() as patch:
        patch.setattr(capture, "SystemClock", ModelClock)
        if fault == "monotonic":
            patch.setattr(capture, "time", SimpleNamespace(monotonic_ns=lambda: next(values)))
        with pytest.raises(ValueError, match="acquisition clocks regressed"):
            _call(ports)
    assert len(calls) == 2
    assert _source_facts(ports) == source
    assert _untouched(ports) == before


@pytest.mark.parametrize("fault", ["epoch", "utc", "elapsed"])
def test_original_collector_rejects_changed_receipt_stage_before_publication(
    ports, monkeypatch, fault
):
    original = capture._ActualCaptureClock.sample
    injected = []

    def changed(self):
        sample = original(self)
        if self._issued == 2:
            injected.append(fault)
            if fault == "epoch":
                return replace(sample, boot_id=sample.boot_id + ":changed")
            if fault == "utc":
                return replace(sample, at=sample.at - timedelta(seconds=1))
            return replace(sample, monotonic_ns=sample.monotonic_ns + 3_000_000_000)
        return sample

    before, source = _untouched(ports), _source_facts(ports)
    with monkeypatch.context() as patch:
        patch.setattr(capture._ActualCaptureClock, "sample", changed)
        with pytest.raises(ValueError):
            _call(ports)
    assert injected == [fault]
    assert _source_facts(ports) == source
    assert _untouched(ports) == before


def test_original_collector_process_deadline_is_not_replaced_by_app_stage_clocks(
    ports, monkeypatch
):
    original = collector._MONOTONIC_NS
    started = original()
    calls = []

    def elapsed():
        calls.append(None)
        return started if len(calls) == 1 else started + 3_000_000_000

    before, source = _untouched(ports), _source_facts(ports)
    with monkeypatch.context() as patch:
        patch.setattr(collector, "_MONOTONIC_NS", elapsed)
        with pytest.raises(ValueError):
            _call(ports)
    assert len(calls) >= 2
    assert _source_facts(ports) == source
    assert _untouched(ports) == before


def test_plan_mutation_after_publication_returns_no_success_and_preserves_both_captures(
    ports, monkeypatch
):
    plan = _plan()
    original = capture.capture_forward
    returned = []

    def observe(*args, **kwargs):
        publication = original(*args, **kwargs)
        returned.append(publication)
        if len(returned) == 2:
            object.__setattr__(plan, "daily_events", tuple(reversed(plan.daily_events)))
        return publication

    before = _untouched(ports)
    with monkeypatch.context() as patch:
        patch.setattr(capture, "capture_forward", observe)
        with pytest.raises(ValueError, match="plan changed during retention"):
            _call(ports, plan)
    assert len(returned) == len(_stored_records(ports)) == len(_objects(ports)) == 2
    assert _stored_records(ports) == tuple(p.record for p in returned)
    assert ports.journal.read_head(returned[-1].record.request.journal_key).sequence == 2
    assert _untouched(ports) == before
