"""Original independent venue admission around fresh thread-owned readiness.

All SQL, objects, controls and leases belong to disposable synthetic fixtures.
Forwarding observers call the original venue reader and full schema verifier;
these tests do not replace financial reducers or claim connected readiness.
"""

import copy
import os
import threading
from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy import Engine

from apps.trader import continuous_readiness_owner as owner_module
from apps.trader.synthetic_session_graph import build_synthetic_session_graph
from packages.adapters.research_artifacts_v2 import (
    LocalResearchArtifactStore,
    ResearchArtifactError,
)
from packages.application import personal_codec
from packages.application.personal_runtime import LocalInstanceGuard
from packages.domain.durable_journal_contracts import empty_head
from packages.domain.identifiers import canonical_id
from packages.domain.stateful_venue_contracts import VenueCommand, VenueCommit, VenueRunDue
from packages.persistence.database import create_database_engine
from packages.persistence.durable_journal import JournalConflict
from packages.persistence.durable_journal_schema import JOURNAL_TABLES, journal_entries
from packages.persistence.schema import metadata
from packages.persistence.stateful_venue import SqlStatefulVenue, VenueStorageError
from tests.integration import test_continuous_synthetic_offline_configuration as study_module
from tests.integration.test_continuous_synthetic_full_readiness import (
    _all_rows,
    _assert_held,
    _assert_initial_state,
    _assert_released,
    _assert_scopes_closed,
    _facts,
    _reader,
    _seed_phase_zero,
)
from tests.integration.test_continuous_synthetic_readiness_owner import (
    _except_lease_lifecycle,
    _lease_rows,
)


def _contains(error, original):
    return error is original or (
        isinstance(error, BaseExceptionGroup)
        and any(_contains(item, original) for item in error.exceptions)
    )


def _objects(store):
    # Only this fixture's explicit root is inspected, never its parent.
    return tuple(sorted((path.name, path.read_bytes()) for path in store._root.iterdir()))


def _snapshot(study, extra):
    return _facts(study), tuple((_all_rows(engine), _objects(store)) for engine, store in extra)


def _damage_venue(venue, kind):
    head = venue.journal.read_head(venue.key)
    assert head.sequence == 1
    with venue.journal._engine.connect() as connection:
        row = (
            connection.execute(
                sa.select(journal_entries).where(
                    journal_entries.c.key_sha256 == venue.key.semantic_sha256,
                    journal_entries.c.sequence == 1,
                )
            )
            .mappings()
            .one()
        )
    original = row["payload"]
    assert type(original) is bytes
    assert sha256(original).hexdigest() == row["payload_sha256"]
    if kind == "journal":
        damaged = original[:-1] + bytes((original[-1] ^ 1,))
        with venue.journal._engine.begin() as connection:
            changed = connection.execute(
                journal_entries.update()
                .where(
                    journal_entries.c.key_sha256 == venue.key.semantic_sha256,
                    journal_entries.c.sequence == 1,
                )
                .values(payload=damaged)
            )
            assert changed.rowcount == 1
    else:
        assert kind == "object"
        commit = personal_codec.decode_record(original, VenueCommit)
        reference = commit.state_object
        payload = venue.artifacts.read(reference)
        assert sha256(payload).hexdigest() == reference.object_sha256
        assert len(payload) == reference.byte_count
        path = venue.artifacts._root / (reference.object_sha256 + ".json")
        assert path.read_bytes() == payload
        damaged = payload[:-1] + bytes((payload[-1] ^ 1,))
        assert path.write_bytes(damaged) == reference.byte_count
    assert damaged != (original if kind == "journal" else payload)


def _advance_venue(venue):
    before = venue.read()
    command = VenueCommand("readiness-test-due", before.state.as_of, VenueRunDue())
    receipt = venue.execute(command, expected_head=before.head)
    after = venue.read()
    assert receipt.journal_receipt.previous_head == before.head
    assert receipt.journal_receipt.committed_head == after.head
    assert after.head.sequence == 2 and after.state.sequence == 1
    assert after.state.commands == (command,)
    assert len(after.state.acknowledgments) == 1
    assert after.state.accounting.cash_flows == before.state.accounting.cash_flows
    assert not after.state.accounting.submissions and not after.state.accounting.commitments
    return before, after


@pytest.fixture
def venue_owner(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    caller = threading.current_thread()
    model = SimpleNamespace(
        installed=False,
        bound=False,
        admission=None,
        before_check=None,
        during_proof=None,
        identity_loop=False,
        owner=None,
        thread=None,
        engine_ids=(),
        events=[],
        proof_count=0,
        read_count=0,
        proof_equal=[],
        release_attempts=0,
        observation_error=None,
        restore=None,
        extra=[],
        construction_denial=None,
        advance_during_read=False,
        advance_on_next_read=False,
    )
    active = [None]
    lock_path = tmp_path / "readiness-venue.lock"
    model.owner_lock_path = lock_path
    original_verify = owner_module.verify_operational_schema
    original_read = SqlStatefulVenue.read
    original_dispose = Engine.dispose
    original_release = study_module._release_setup

    def read(venue, *args, **kwargs):
        if getattr(model, "venue", None) is venue:
            assert threading.current_thread() is model.thread
            # A cached historical head must not become current readiness.
            assert not args and not kwargs
            model.read_count += 1
        result = original_read(venue, *args, **kwargs)
        if getattr(model, "venue", None) is venue and model.advance_on_next_read:
            model.advance_on_next_read = False
            model.advancement = _advance_venue(venue)
            model.fault_facts = _snapshot(active[0], model.extra)
        return result

    def dispose(engine, *args, **kwargs):
        result = original_dispose(engine, *args, **kwargs)
        if id(engine) in model.engine_ids:
            model.events.append(("dispose", threading.current_thread(), id(engine)))
        return result

    def release(study):
        assert threading.current_thread() is model.thread
        model.release_attempts += 1
        model.events.append(("release", threading.current_thread(), None))
        lease = study.lease
        result = original_release(study)
        try:
            _assert_released(study, lease)
            model.release_rows = _lease_rows(study)
            model.released_facts = _facts(study)
        except BaseException as error:
            model.observation_error = error
            raise
        return result

    def verify(engine, **kwargs):
        study = active[0]
        assert study is not None and threading.current_thread() is model.thread
        assert engine is study.ports["account_engine"]
        assert set(kwargs) == {"research_codec", "continuous_integrity"}
        assert kwargs["research_codec"] is personal_codec
        assert kwargs["continuous_integrity"] is model.reader
        model.proof_count += 1
        model.events.append(("proof", threading.current_thread(), id(engine)))
        before = _snapshot(study, model.extra)
        try:
            result = original_verify(engine, **kwargs)
        finally:
            _assert_scopes_closed(model.reader)
            model.proof_equal.append(_snapshot(study, model.extra) == before)
        assert result is None
        if model.during_proof in ("object", "journal"):
            _damage_venue(model.venue, model.during_proof)
        elif model.during_proof == "advance":
            model.advancement = _advance_venue(model.venue)
        elif model.during_proof == "binding":
            original = model.venue.artifacts
            model.venue.artifacts = model.alternate_store
            model.restore = lambda: setattr(model.venue, "artifacts", original)
        if model.during_proof is not None:
            model.fault_facts = _snapshot(study, model.extra)
        return result

    @contextmanager
    def held_guard():
        guard = LocalInstanceGuard(lock_path)
        guard.__enter__()
        info = os.fstat(guard.fileno())
        model.guard_identity = info.st_dev, info.st_ino
        primary = None
        try:
            yield guard
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                if primary is None:
                    guard.__exit__(None, None, None)
                else:
                    guard.__exit__(type(primary), primary, primary.__traceback__)
            except BaseException as error:
                if primary is not None:
                    raise BaseExceptionGroup(
                        "readiness venue and guard cleanup failed", [primary, error]
                    ) from None
                raise
            model.events.append(("guard-exit", threading.current_thread(), None))

    @contextmanager
    def open_runtime(stop_event):
        model.thread = threading.current_thread()
        assert model.thread is not caller
        model.events.append(("construct", model.thread, None))
        primary = None
        try:
            with held_guard() as guard:
                try:
                    with study_module._study(tmp_path, install=model.installed) as study:
                        active[0] = study
                        model.engine_ids = tuple(
                            id(study.ports[name]) for name in ("account_engine", "venue_engine")
                        )
                        model.retained_engine_ids = model.engine_ids
                        try:
                            _seed_phase_zero(study)
                            _assert_initial_state(study, installed=model.installed)
                            _assert_held(study, study.lease)
                            venue = study.genesis.venue
                            if model.bound:
                                owners = study.owners
                                session = build_synthetic_session_graph(
                                    account=owners.account,
                                    runtime=owners.runtime,
                                    daily=owners.daily,
                                    venue_sources=owners.venue_sources,
                                    venue_engine=study.ports["venue_engine"],
                                    venue_artifacts=study.ports["venue_artifacts"],
                                    codec=personal_codec,
                                    capture_clock=study.ports["clock"].now,
                                    stop_event=stop_event,
                                )
                                venue = session.delivery.venue
                                assert venue.verified_sources is session.delivery
                                assert session.delivery._require_owners() is venue
                            else:
                                assert venue.verified_sources is None
                            if model.admission in ("empty", "foreign"):
                                database = study.root / "rejected-venue.sqlite"
                                study_module._exclusive_file(database)
                                rejected = create_database_engine(f"sqlite+pysqlite:///{database}")
                                model.extra_engine = rejected
                                model.engine_ids += (id(rejected),)
                                metadata.create_all(rejected, tables=JOURNAL_TABLES)
                                objects = LocalResearchArtifactStore(
                                    study.root / "rejected-objects"
                                )
                                model.extra.append((rejected, objects))
                                original_model = study.owners.runtime.venue_model
                                if model.admission == "foreign":
                                    foreign_model = replace(
                                        original_model,
                                        producer=replace(
                                            original_model.producer, version="foreign/1"
                                        ),
                                    )
                                    foreign = SqlStatefulVenue(
                                        rejected,
                                        model=foreign_model,
                                        artifacts=objects,
                                        codec=personal_codec,
                                        accounting=study.owners.runtime.accounting,
                                    )
                                    retained = foreign.initialize()
                                    assert retained.head.sequence == 1
                                    assert (
                                        retained.state.model_sha256
                                        != original_model.semantic_sha256
                                    )
                                venue = SqlStatefulVenue(
                                    rejected,
                                    model=original_model,
                                    artifacts=objects,
                                    codec=personal_codec,
                                    accounting=study.owners.runtime.accounting,
                                )
                            model.venue = venue
                            model.reader = _reader(study)
                            model.alternate_store = LocalResearchArtifactStore(
                                study.root / "unused-venue-objects"
                            )
                            if model.admission not in ("empty", "foreign"):
                                retained = original_read(venue)
                                assert retained.head.sequence == 1
                                assert retained.state.sequence == 0
                                assert not retained.state.commands
                                assert not retained.state.acknowledgments
                                assert not retained.state.accounting.submissions
                                assert not retained.state.accounting.commitments
                                assert retained.state.accounting.cash_flows == (
                                    study.genesis.restored.checkpoint.state.cash_flows
                                )
                                initial_receipt = venue.journal.read_receipt(
                                    venue.key,
                                    canonical_id("venue-genesis/1", venue.model.semantic_sha256),
                                )
                                assert initial_receipt is not None
                                assert initial_receipt.previous_head == empty_head(venue.key)
                                assert initial_receipt.committed_head == retained.head
                                assert initial_receipt.command_sha256 == venue.model.semantic_sha256
                            if model.admission in ("object", "journal"):
                                _damage_venue(venue, model.admission)
                            model.initial_facts = _snapshot(study, model.extra)
                            try:
                                runtime = owner_module._ReadinessRuntime(
                                    reader=model.reader,
                                    lease=study.lease,
                                    guard=guard,
                                    venue=venue,
                                    venue_engine=venue.journal._engine,
                                    stop_event=stop_event,
                                )
                            except BaseException as error:
                                model.construction_denial = error
                                assert _snapshot(study, model.extra) == model.initial_facts
                                raise
                            model.runtime = runtime
                            if model.identity_loop:
                                _binding_denials(model, study)
                            if model.before_check in ("object", "journal"):
                                _damage_venue(venue, model.before_check)
                                model.fault_facts = _snapshot(study, model.extra)
                            elif model.before_check == "advance":
                                model.advancement = _advance_venue(venue)
                                model.fault_facts = _snapshot(study, model.extra)
                            model.advance_on_next_read = model.advance_during_read
                            try:
                                yield runtime
                            finally:
                                if model.restore is not None:
                                    model.restore()
                                    model.restore = None
                        except BaseException as error:
                            primary = error
                            raise
                        finally:
                            model.before_release_facts = _snapshot(study, model.extra)
                            if hasattr(model, "reader"):
                                _assert_scopes_closed(model.reader)
                            if hasattr(model, "extra_engine"):
                                # This unadmitted replacement fixture is separate
                                # from the two retained graph engines. Its failed
                                # admission is already quiescent; both retained
                                # engines still unwind after original release.
                                try:
                                    model.extra_engine.dispose()
                                except BaseException as error:
                                    if primary is not None:
                                        raise BaseExceptionGroup(
                                            "readiness venue and extra cleanup failed",
                                            [primary, error],
                                        ) from None
                                    raise
                except BaseException as error:
                    if primary is not None and not _contains(error, primary):
                        raise BaseExceptionGroup(
                            "readiness venue and study cleanup failed", [primary, error]
                        ) from None
                    raise
        finally:
            active[0] = None
            model.builder_exited = True

    monkeypatch.setattr(SqlStatefulVenue, "read", read)
    monkeypatch.setattr(Engine, "dispose", dispose)
    monkeypatch.setattr(study_module, "_release_setup", release)
    monkeypatch.setattr(owner_module, "verify_operational_schema", verify)
    model.owner = owner_module.ContinuousReadinessOwner(_open_runtime=open_runtime)
    try:
        yield model
    finally:
        model.owner.stop()
        if model.thread is not None:
            model.thread.join(8)
            assert not model.thread.is_alive()
        if model.observation_error is not None:
            raise model.observation_error


def _binding_denials(model, study):
    runtime, venue = model.runtime, model.venue
    before = _snapshot(study, model.extra)
    callbacks = []

    def forbidden(*args, **kwargs):
        callbacks.append((args, kwargs))
        raise AssertionError("substituted venue dependency was invoked")

    replacements = (
        (runtime, "venue", copy.copy(venue)),
        (venue, "model", replace(venue.model)),
        (venue, "key", replace(venue.key)),
        (venue, "journal", copy.copy(venue.journal)),
        (venue.journal, "_engine", runtime.reader.engine),
        (venue, "artifacts", model.alternate_store),
        (venue, "accounting", copy.copy(venue.accounting)),
        (venue, "codec", SimpleNamespace(encode_record=forbidden, decode_record=forbidden)),
        (venue, "verified_sources", SimpleNamespace(_require_owners=forbidden)),
    )
    for owner, field, replacement in replacements:
        original = getattr(owner, field)
        setattr(owner, field, replacement)
        try:
            with pytest.raises(ValueError, match=r"^READINESS_ORIGINAL_RUNTIME_CHANGED$"):
                _ = runtime.lease_deadline_ns
        finally:
            setattr(owner, field, original)
    assert not callbacks
    assert type(runtime.lease_deadline_ns) is int
    assert model.proof_count == 0
    assert _snapshot(study, model.extra) == before
    model.binding_cases = len(replacements)


def _finish(model):
    model.owner.stop()
    model.thread.join(8)
    assert not model.thread.is_alive() and model.builder_exited
    status = model.owner.status()
    assert status.phase == "stopped" and status.cleanup_complete
    assert status.cleanup_failure is None
    assert model.release_attempts == 1
    assert model.observation_error is None
    assert all(thread is model.thread for _name, thread, _identity in model.events)
    assert all(model.proof_equal)
    for identity in model.engine_ids:
        assert (
            sum(
                name == "dispose" and selected == identity
                for name, _thread, selected in model.events
            )
            == 1
        )
    names = [name for name, _thread, _identity in model.events]
    retained_disposals = [
        index
        for index, (name, _thread, identity) in enumerate(model.events)
        if name == "dispose" and identity in model.retained_engine_ids
    ]
    all_disposals = [index for index, name in enumerate(names) if name == "dispose"]
    assert len(retained_disposals) == 2
    assert names.index("release") < min(retained_disposals)
    assert max(all_disposals) < names.index("guard-exit")
    assert _except_lease_lifecycle(model.released_facts) == _except_lease_lifecycle(
        model.before_release_facts[0]
    )
    with LocalInstanceGuard(model.owner_lock_path) as guard:
        observed = os.fstat(guard.fileno())
        assert (observed.st_dev, observed.st_ino) == model.guard_identity
    return status


@pytest.mark.parametrize(
    "installed,bound",
    [(False, False), (True, False), (True, True)],
    ids=["empty_b", "disabled_generation1", "bound_delivery"],
)
def test_original_venue_bookends_full_readiness_without_writes(venue_owner, installed, bound):
    model = venue_owner
    model.installed, model.bound = installed, bound
    assert model.owner.start().phase == "idle"
    assert model.owner.status().cleanup_complete is False
    assert model.venue.model is model.reader.daily.producers.venue_model
    result = model.owner.check("original-venue-readiness")
    assert (result.status, result.reason) == ("ready", "verified")
    assert model.proof_count == 1 and model.read_count >= 3
    status = _finish(model)
    assert status.primary_failure is None
    assert model.before_release_facts == model.initial_facts


@pytest.mark.parametrize(
    "fault,expected_type,expected",
    [
        ("empty", VenueStorageError, "VENUE_HEAD_UNINITIALIZED_OR_OUTSIDE_BOUND"),
        ("foreign", VenueStorageError, "VENUE_COMMIT_MODEL_DIFFERS"),
        ("object", ResearchArtifactError, "object bytes differ from the retained identity"),
        ("journal", JournalConflict, "JOURNAL_RECEIPT_INVALID"),
    ],
)
def test_constructor_rejects_actual_independent_retained_damage(
    venue_owner, fault, expected_type, expected
):
    model = venue_owner
    model.admission = fault
    assert model.owner.start().phase in ("stopping", "stopped")
    status = _finish(model)
    assert status.primary_failure == "startup_failed"
    assert model.proof_count == 0
    assert model.construction_denial is not None
    assert type(model.construction_denial) is expected_type
    assert model.construction_denial.args == (expected,)
    assert model.before_release_facts == model.initial_facts
    assert model.owner.check("never-admitted").status == "unavailable"


@pytest.mark.parametrize("fault", ["object", "journal", "advance"])
@pytest.mark.parametrize("stage", ["before", "during"])
def test_changed_original_venue_cannot_deliver_ready(venue_owner, fault, stage):
    model = venue_owner
    if stage == "before":
        model.before_check = fault
    else:
        model.during_proof = fault
    assert model.owner.start().phase == "idle"
    result = model.owner.check("changed-independent-venue")
    assert result.status == "unavailable" and result.reason == "runtime_failed"
    status = _finish(model)
    assert status.primary_failure == "runtime_failed"
    assert model.proof_count == (0 if stage == "before" else 1)
    assert model.before_release_facts == model.fault_facts
    assert model.fault_facts != model.initial_facts
    if fault == "advance":
        before, after = model.advancement
        assert before.head.sequence == 1 and after.head.sequence == 2
        assert before.state.accounting.cash_flows == after.state.accounting.cash_flows


def test_individual_original_venue_bindings_deny_without_invoking_substitutes(venue_owner):
    model = venue_owner
    model.identity_loop = True
    assert model.owner.start().phase == "idle"
    assert model.binding_cases == 9
    assert model.owner.check("originals-restored").status == "ready"
    _finish(model)
    assert model.proof_count == 1
    assert model.before_release_facts == model.initial_facts


def test_callback_time_venue_binding_change_withholds_completed_account_proof(venue_owner):
    model = venue_owner
    model.during_proof = "binding"
    assert model.owner.start().phase == "idle"
    assert model.owner.check("changed-owner").status == "unavailable"
    status = _finish(model)
    assert status.primary_failure == "runtime_failed" and model.proof_count == 1
    assert model.before_release_facts == model.initial_facts


def test_current_head_move_during_original_read_denies_historical_result(venue_owner):
    model = venue_owner
    model.advance_during_read = True
    assert model.owner.start().phase == "idle"
    result = model.owner.check("head-moved-during-read")
    assert result.status == "unavailable" and result.reason == "runtime_failed"
    status = _finish(model)
    assert status.primary_failure == "runtime_failed" and model.proof_count == 0
    assert model.advancement[0].head.sequence == 1
    assert model.advancement[1].head.sequence == 2
    assert model.before_release_facts == model.fault_facts
    assert model.fault_facts != model.initial_facts
