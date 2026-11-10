"""One private preparation on a new, genuinely configured empty-B account.

The original G generator owns the native thread's graph and cleanup. These tests
retain no REQUEST and install no assignment. Forwarders observe real operations;
they never replace a financial proof. No old retained fixture is loaded.
"""

import os
import sys
import threading
import time
from contextlib import contextmanager
from datetime import timedelta
from decimal import Decimal
from hashlib import sha256
from types import SimpleNamespace

import pytest
from sqlalchemy import Engine

from apps.trader import configured_readiness_owner as configured_module
from apps.trader import continuous_readiness_owner as owner_module
from apps.trader.continuous_simulation_factory import (
    PRODUCER_MAP_SCHEMA,
    ContinuousSimulationConfiguration,
)
from apps.trader.initial_selection_descriptor import (
    InitialSelectionDescriptor,
    initial_selection_request_data,
)
from apps.trader.initial_selection_preparation import _InitialSelectionPreparation
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec
from packages.application.personal_runtime import LocalInstanceGuard
from packages.domain.account_coordinator import ACCOUNT_COORDINATOR_CONTRACT_VERSION
from packages.domain.canonical import canonical_json_bytes
from packages.domain.continuous_persistence_contracts import (
    MAX_CONTINUOUS_OBJECT_BYTES,
    ContinuousEvidenceRef,
)
from packages.domain.daily_observed_hold_contracts import daily_runtime_effect_watermark
from packages.domain.daily_runtime_contracts import RuntimeRiskAssignment
from packages.domain.engine_contracts import DailyRiskPolicy
from packages.domain.personal_contracts import content_digest
from packages.domain.reconciliation_contracts import ReconciliationHeads
from packages.domain.runtime_owner_dependency_contracts import (
    MAX_OWNER_DEPENDENCIES_BYTES,
    OWNER_DEPENDENCIES_SCHEMA,
    RuntimeOwnerDependencies,
)
from packages.persistence.account_coordinator import (
    account_lease_from_row,
    account_lease_release_from_row,
)
from packages.persistence.daily_runtime_risk import daily_attempt_inventory_sha256
from tests.integration import test_continuous_synthetic_offline_configuration as study_module
from tests.integration.test_continuous_synthetic_configured_readiness import _observe
from tests.integration.test_continuous_synthetic_factory_partial_cleanup import _snapshot
from tests.integration.test_continuous_synthetic_full_readiness import (
    _assert_initial_state,
    _seed_phase_zero,
)


def _configuration(study):
    """Test-owned configuration data; the selected-only exporter stays unchanged."""
    runtime = study.owners.runtime
    policy = study.owners.account.coordinator._authority.policy
    assert policy.lease_ttl == timedelta(seconds=60)
    assert policy.maximum_in_flight_duration == timedelta(seconds=5)
    assert policy.takeover_safety_interval == timedelta(seconds=10)
    payload = personal_codec.encode_record(runtime.producer_map)
    reference = runtime.artifacts.put(payload, max_bytes=MAX_CONTINUOUS_OBJECT_BYTES)
    assert (reference.object_sha256, reference.byte_count) == (
        sha256(payload).hexdigest(),
        len(payload),
    )
    result = ContinuousSimulationConfiguration(
        schema_id="continuous-offline-configuration/1",
        operation="restore",
        owner_id="synthetic-private-preparation",
        database_path=str(study.paths["database_path"]),
        artifact_root=str(study.paths["artifact_root"]),
        venue_database_path=str(study.paths["venue_database_path"]),
        venue_artifact_root=str(study.paths["venue_artifact_root"]),
        inputs=study.genesis.restored.receipt.commit.request,
        venue_model=ContinuousEvidenceRef(
            "venue-model/1",
            runtime.venue_reference.object_ref,
            runtime.venue_model.semantic_sha256,
        ),
        producer_map=ContinuousEvidenceRef(
            PRODUCER_MAP_SCHEMA, reference, runtime.producer_map.semantic_sha256
        ),
        benchmark_instrument_id=runtime.benchmark_instrument_id,
        capture_evidence_class=runtime.forward_sources.evidence_class,
        clock_profile=runtime.operating.clock_sampler.profile,
        lease_policy_id=policy.policy_id,
        lease_policy_version=policy.policy_version,
        lease_ttl_microseconds=60_000_000,
        maximum_in_flight_microseconds=5_000_000,
        takeover_safety_microseconds=10_000_000,
    )
    assert result.capture_evidence_class == "synthetic_fixture"
    assert result.clock_profile == "explicit_simulation_time_model"
    assert len(personal_codec.encode_record(result)) <= 64 * 1024
    return result


def _observe_put(case, monkeypatch):
    original = LocalResearchArtifactStore.put

    def put(store, payload, **kwargs):
        reference = original(store, payload, **kwargs)
        if case.runtime is None or store is not case.runtime.reader.account.artifacts:
            return reference
        assert threading.current_thread() is case.thread
        assert kwargs["max_bytes"] == MAX_OWNER_DEPENDENCIES_BYTES
        assert len(case.puts) == 0
        # The original durable put has returned before any fault or barrier.
        assert (store._root / (reference.object_sha256 + ".json")).read_bytes() == payload
        case.puts.append((reference, payload))
        case.put_seen.set()
        if case.mode == "put-failure":
            raise case.sentinel
        if case.mode == "post-put-stop":
            case.stop_event.set()
        if case.mode == "late-put":
            assert case.allow_put.wait(10), "test did not release its real put barrier"
        if case.mode == "reentry":
            counts = case.proofs, len(case.puts)
            with pytest.raises(
                ValueError, match=r"^INITIAL_SELECTION_PREPARATION_ALREADY_ATTEMPTED$"
            ) as caught:
                case.adapter.prepare(deadline_ns=case.deadline_ns)
            case.reentry_error = caught.value
            assert (case.proofs, len(case.puts)) == counts
            assert case.adapter.descriptor() is None
        return reference

    monkeypatch.setattr(LocalResearchArtifactStore, "put", put)


def _same_application_facts(before, after):
    # Financial includes all reflected account tables except the three explicit
    # lease lifecycle tables, every venue table, and both object inventories.
    assert after.financial[:2] == before.financial[:2]
    assert after.financial[2][1] == before.financial[2][1]
    old_objects = dict(before.financial[2][0])
    new_objects = dict(after.financial[2][0])
    assert all(new_objects.get(name) == payload for name, payload in old_objects.items())
    return {name: payload for name, payload in new_objects.items() if name not in old_objects}


def _require_closed(case):
    assert case.thread is not None and not case.thread.is_alive()
    assert case.executions == case.factory_reads == 0
    assert all(thread is case.thread for _, thread in case.trace)
    assert case.guard_entered and case.guard_exits == 1
    assert case.guard._descriptor is None
    assert case.constructor_error is None
    assert case.close_calls == 1
    assert case.disposals == ["dispose-venue", "dispose-account"]
    labels = [label for label, _ in case.trace]
    assert labels[-1] == "guard-exit"
    assert labels.index("close") < labels.index("release")
    assert labels.index("release") < labels.index("dispose-venue")
    assert labels.index("dispose-account") < labels.index("guard-exit")
    before, after = case.before, _snapshot(case.study)
    case.after = after
    additions = _same_application_facts(before, after)
    assert case.admitted is not None
    assert _same_application_facts(before, case.admitted) == {}
    assert _same_application_facts(case.admitted, after) == additions
    expected = {reference.object_sha256 + ".json": payload for reference, payload in case.puts}
    assert additions == expected
    assert len(additions) == (0 if case.mode == "selected" else 1)
    assert case.configuration_path.read_bytes() == case.configuration_bytes
    assert len(case.acquires) == len(case.releases) == 1
    assert len(after.leases) == len(before.leases) + 1
    assert all(row in after.leases for row in before.leases)
    added = next(row for row in after.leases if row not in before.leases)
    actual = account_lease_from_row(added)
    assert actual == case.acquires[0]
    assert actual.fencing_generation == before.heads[0]["last_fencing_generation"] + 1
    assert actual.revision_number == 1 and actual.previous_lease_sha256 is None
    assert actual.policy_sha256 == case.configuration.lease_policy().semantic_sha256
    assert actual.expires_at - actual.acquired_at == timedelta(seconds=60)
    assert before.heads[0]["current_fencing_generation"] is None
    assert before.heads[0]["current_lease_sha256"] is None
    assert case.admitted.leases == after.leases
    assert case.admitted.releases == before.releases
    assert len(case.admitted.heads) == 1
    admitted_head = case.admitted.heads[0]
    assert admitted_head["account_id"] == actual.account_id
    assert admitted_head["last_fencing_generation"] == actual.fencing_generation
    assert admitted_head["current_fencing_generation"] == actual.fencing_generation
    assert admitted_head["current_lease_sha256"] == actual.semantic_sha256
    assert admitted_head["updated_at"] >= added["acquired_at"]
    assert case.release_attempts == [actual.fence]
    assert len(after.releases) == len(before.releases) + 1
    assert all(row in after.releases for row in before.releases)
    released_row = next(row for row in after.releases if row not in before.releases)
    released = account_lease_release_from_row(released_row)
    assert released == case.releases[0]
    assert released.fence == actual.fence and released.lease_sha256 == actual.semantic_sha256
    assert actual.acquired_at <= released.released_at < actual.expires_at
    assert after.heads == (
        {
            "account_id": actual.account_id,
            "last_fencing_generation": actual.fencing_generation,
            "current_fencing_generation": None,
            "current_lease_sha256": None,
            "updated_at": released_row["released_at"],
        },
    )
    # Reacquisition proves the original guard really exited, without another
    # account lease, graph construction, preparation, or financial operation.
    with LocalInstanceGuard(case.lock_path) as guard:
        info = os.fstat(guard.fileno())
        assert (info.st_dev, info.st_ino) == case.lock_identity


@contextmanager
def _preparation_case(tmp_path, monkeypatch, *, mode="success"):
    with study_module._study(tmp_path, install=mode == "selected") as study:
        _assert_initial_state(study, installed=mode == "selected")
        daily = study.owners.daily.resolve_snapshot(
            study.owners.daily.read_snapshot(
                account_id=study.genesis.scope.account_id, fence=study.lease.fence
            )
        )
        configuration = _configuration(study)
        _seed_phase_zero(study)
        path = study.root / "private-preparation.json"
        payload = personal_codec.encode_record(configuration)
        study_module._exclusive_file(path, payload)
        study_module._release_setup(study)
        assert study.lease is None
        before = _snapshot(study)
        study.ports["account_engine"].dispose()
        study.ports["venue_engine"].dispose()
        case = SimpleNamespace(
            study=study,
            configuration=configuration,
            configuration_path=path,
            configuration_bytes=payload,
            lock_path=study.root / "private-preparation.lock",
            before=before,
            admitted=None,
            after=None,
            mode=mode,
            caller_thread=threading.current_thread(),
            thread=None,
            trace=[],
            factory=None,
            constructor_error=None,
            checkpoints=0,
            close_calls=0,
            executions=0,
            factory_reads=0,
            acquires=[],
            release_attempts=[],
            releases=[],
            disposals=[],
            account_engine=None,
            venue_engine=None,
            runtime=None,
            stop_event=None,
            proofs=0,
            proof_errors=[],
            guard=None,
            guard_entered=False,
            guard_exits=0,
            lock_identity=None,
            startup_entered=threading.Event(),
            allow_startup=threading.Event(),
            unknown_primary=None,
            adapter=None,
            puts=[],
            put_seen=threading.Event(),
            allow_put=threading.Event(),
            finished=threading.Event(),
            failures=[],
            result=None,
            historical=None,
            operation_error=None,
            sentinel=RuntimeError("test original put returned then failed"),
            reentry_error=None,
            deadline_ns=None,
            started_ns=None,
            elapsed_ns=None,
            setup_daily=daily,
        )
        _observe(case, monkeypatch)
        _observe_put(case, monkeypatch)
        primary = None
        try:
            yield case
        except BaseException as error:
            primary = error
            raise
        finally:
            case.allow_put.set()
            case.allow_startup.set()
            errors = []
            if case.thread is not None:
                case.thread.join(20)
                if case.thread.is_alive():
                    errors.append(AssertionError("original preparation thread has not exited"))
                else:
                    try:
                        _require_closed(case)
                    except BaseException as error:
                        errors.append(error)
            if errors:
                if primary is not None:
                    errors.insert(0, primary)
                errors.extend(error for error in case.failures if error is not primary)
                raise BaseExceptionGroup("preparation test and original cleanup failed", errors)


def _historical_export(case, adapter):
    """Observe zero original runtime/I/O calls after actual G context closure."""
    assert case.guard_exits == 1 and case.close_calls == 1
    forbidden = {
        owner_module._ReadinessRuntime._require.__code__,
        owner_module._ReadinessRuntime._now.__code__,
        owner_module._ReadinessRuntime.verify.__code__,
        Engine.connect.__code__,
        LocalResearchArtifactStore.read.__code__,
        LocalResearchArtifactStore.put.__code__,
    }
    calls = []

    def profile(frame, event, argument):
        if event == "call" and frame.f_code in forbidden:
            calls.append(frame.f_code.co_name)
        elif event == "c_call" and argument is time.monotonic_ns:
            calls.append("monotonic_ns")

    previous = sys.getprofile()
    sys.setprofile(profile)
    try:
        first, second = adapter.descriptor(), adapter.descriptor()
    finally:
        sys.setprofile(previous)
    assert calls == [] and sys.getprofile() is previous
    if case.result is None:
        assert first is second is None
    else:
        assert first == second == case.result
        assert first is not second and first is not case.result
    case.historical = first


def _launch(case, operation):
    def worker():
        adapter = None
        try:
            context = contextmanager(configured_module._CONFIGURED_RUNTIME_GENERATOR)
            with context(
                configuration_file=case.configuration_path,
                lock_path=case.lock_path,
                account_id=case.study.genesis.scope.account_id,
                stop_event=threading.Event(),
            ) as runtime:
                assert runtime is case.runtime
                case.admitted = _snapshot(case.study)
                adapter = _InitialSelectionPreparation(runtime)
                case.adapter = adapter
                assert adapter.descriptor() is None
                case.started_ns = time.monotonic_ns()
                case.deadline_ns = case.started_ns + 5_000_000_000
                operation(case, adapter)
            _historical_export(case, adapter)
        except BaseException as error:
            case.failures.append(error)
        finally:
            case.finished.set()

    assert case.thread is None and case.trace == []
    case.thread = threading.Thread(target=worker, name="fresh-private-preparation")
    case.thread.start()


def _join(case):
    case.thread.join(20)
    assert not case.thread.is_alive(), "original preparation thread has not exited"
    assert case.finished.is_set()
    if case.failures:
        raise case.failures[0]


def _no_retry(case, adapter):
    counts = case.proofs, len(case.puts)
    expected = (
        "READINESS_OWNER_STOPPED"
        if case.stop_event.is_set()
        else "INITIAL_SELECTION_PREPARATION_ALREADY_ATTEMPTED"
    )
    # Original current stop admission precedes the repeated-attempt check.
    with pytest.raises(ValueError, match=r"^" + expected + "$"):
        adapter.prepare(deadline_ns=case.deadline_ns)
    assert (case.proofs, len(case.puts)) == counts
    assert adapter.descriptor() is None


def _success(case, adapter):
    before = dict(vars(adapter))
    counts = case.proofs, len(case.puts)
    with pytest.raises(ValueError, match=r"^INITIAL_SELECTION_PREPARATION_INVALID$"):
        adapter.__init__(case.runtime)
    assert vars(adapter) == before
    assert (case.proofs, len(case.puts)) == counts == (0, 0)
    assert adapter.descriptor() is None
    result = adapter.prepare(deadline_ns=case.deadline_ns)
    returned_ns = time.monotonic_ns()
    case.elapsed_ns = returned_ns - case.started_ns
    assert type(result) is InitialSelectionDescriptor
    assert returned_ns < case.deadline_ns
    case.result = adapter.descriptor()
    assert result == case.result and result is not case.result
    object.__setattr__(result, "dependency_semantic_sha256", "0" * 64)
    fresh = adapter.descriptor()
    assert fresh == case.result and fresh is not case.result
    assert fresh.dependency_semantic_sha256 != result.dependency_semantic_sha256
    before = dict(vars(adapter))
    counts = case.proofs, len(case.puts)
    with pytest.raises(ValueError, match=r"^INITIAL_SELECTION_PREPARATION_INVALID$"):
        adapter.__init__(case.runtime)
    assert vars(adapter) == before
    assert adapter.descriptor() == case.result
    assert (case.proofs, len(case.puts)) == counts == (2, 1)
    with pytest.raises(ValueError, match=r"^INITIAL_SELECTION_PREPARATION_ALREADY_ATTEMPTED$"):
        adapter.prepare(deadline_ns=case.deadline_ns)
    assert (case.proofs, len(case.puts)) == counts == (2, 1)


def _retained_record(case):
    """Read actual bytes independently of the adapter's private prepared value."""
    reference, observed_payload = case.puts[0]
    path = case.study.paths["artifact_root"] / (reference.object_sha256 + ".json")
    payload = path.read_bytes()
    assert payload == observed_payload
    assert 0 < len(payload) == reference.byte_count <= MAX_OWNER_DEPENDENCIES_BYTES
    assert sha256(payload).hexdigest() == reference.object_sha256
    record = personal_codec.decode_record(payload, RuntimeOwnerDependencies)
    assert type(record) is RuntimeOwnerDependencies
    assert personal_codec.encode_record(record) == payload
    genesis = case.study.genesis
    spec = genesis.restored.checkpoint.inputs.spec
    assert spec.initial_cash == Decimal("10000")
    assert spec.risk_policy.policy_id == "personal-daily-stateful-simulation/1"
    assert spec.risk_policy == DailyRiskPolicy(policy_id="personal-daily-stateful-simulation/1")
    assert spec.execution_policy.model_id == "observed-facts-v1"
    assert record.scope == genesis.scope
    assert record.previous == genesis.restored.receipt
    assert record.previous.commit.sequence == 1
    assert record.previous_assignment_sha256 is None and record.reconciliation is None
    assert record.control_sha256 == genesis.control.semantic_sha256
    assert record.proposed == RuntimeRiskAssignment(
        account_id=genesis.scope.account_id,
        account_binding_sha256=genesis.scope.account_binding_sha256,
        generation=1,
        policy=spec.risk_policy,
        strategy=spec.strategy,
        configuration_sha256=content_digest(spec.strategy_configuration),
        instrument_symbols=spec.instruments,
        producer_map_sha256=case.configuration.producer_map.semantic_sha256,
        effective_at=record.proposed.effective_at,
        previous_assignment_sha256=None,
        enabled_for_new_exposure=False,
        live_authorized=False,
    )
    assert record.proposed.environment == "stateful_simulation"
    assert record.proposed.financing_policy == "cash-funded-long-only/1"
    daily = case.setup_daily
    checkpoint = genesis.restored.checkpoint
    lease = case.acquires[0]
    expected_heads = ReconciliationHeads(
        checkpoint.current.snapshot.journal_sha256,
        checkpoint.current.snapshot.order_sha256,
        daily.obligations.semantic_sha256,
        daily_runtime_effect_watermark(
            attempt_envelopes=daily.attempt_envelopes, observed_groups=daily.observed_groups
        ),
        daily_attempt_inventory_sha256(daily.attempts),
        genesis.control.sequence_number,
        lease.fencing_generation,
    )
    assert record.heads == expected_heads
    assert record.obligations_sha256 == daily.obligations.semantic_sha256
    assert record.attempts_sha256 == daily_attempt_inventory_sha256(())
    assert record.fence.fence == lease.fence
    assert record.fence.lease_sha256 == lease.semantic_sha256
    assert record.fence.policy_sha256 == lease.policy_sha256
    assert record.fence.valid_until == lease.expires_at
    assert (
        record.fence.original_receipt_sha256
        == sha256(
            canonical_json_bytes(
                (
                    ACCOUNT_COORDINATOR_CONTRACT_VERSION,
                    "fence_receipt",
                    lease.fence.semantic_sha256,
                    record.fence.validated_at,
                    lease.expires_at,
                    lease.policy_sha256,
                    lease.semantic_sha256,
                )
            )
        ).hexdigest()
    )
    assert record.checked_at == record.fence.validated_at
    assert lease.acquired_at <= record.proposed.effective_at <= record.checked_at
    assert record.checked_at < record.valid_until == lease.expires_at
    assert record.valid_until - record.checked_at <= timedelta(seconds=60)
    return reference, record


def _assert_descriptor(case):
    reference, record = _retained_record(case)
    descriptor = case.result
    scope, heads, evidence = initial_selection_request_data(descriptor)
    assert scope == record.scope and heads == record.heads
    assert evidence == ContinuousEvidenceRef(
        OWNER_DEPENDENCIES_SCHEMA, reference, record.semantic_sha256
    )
    assert descriptor.after_assignment_sha256 == record.proposed.semantic_sha256
    assert descriptor.checked_at == record.checked_at
    assert descriptor.valid_until == record.valid_until
    assert descriptor.c1_receipt_sha256 == record.previous.semantic_sha256
    assert descriptor.control_sha256 == record.control_sha256
    assert descriptor.original_lease_sha256 == record.fence.lease_sha256
    assert case.historical == descriptor and case.historical is not descriptor
    assert case.proofs == 2 and case.proof_errors == []
    assert 0 <= case.elapsed_ns < 5_000_000_000


def test_actual_configured_empty_b_preparation_retains_one_original_dependency_object(
    tmp_path, monkeypatch
):
    with _preparation_case(tmp_path, monkeypatch) as case:
        _launch(case, _success)
        _join(case)
        _assert_descriptor(case)


def test_actual_dependency_put_then_error_retains_bytes_and_original_primary(tmp_path, monkeypatch):
    def operation(case, adapter):
        with pytest.raises(RuntimeError) as caught:
            adapter.prepare(deadline_ns=case.deadline_ns)
        assert caught.value is case.sentinel
        case.operation_error = caught.value
        assert case.proofs == 1 and len(case.puts) == 1
        _no_retry(case, adapter)

    with _preparation_case(tmp_path, monkeypatch, mode="put-failure") as case:
        _launch(case, operation)
        _join(case)
        assert case.operation_error is case.sentinel
        _retained_record(case)


def test_actual_post_put_stop_retains_object_without_descriptor_or_retry(tmp_path, monkeypatch):
    def operation(case, adapter):
        with pytest.raises(ValueError, match=r"^READINESS_OWNER_STOPPED$") as caught:
            adapter.prepare(deadline_ns=case.deadline_ns)
        case.operation_error = caught.value
        assert case.stop_event.is_set() and len(case.puts) == 1 and case.proofs == 1
        _no_retry(case, adapter)

    with _preparation_case(tmp_path, monkeypatch, mode="post-put-stop") as case:
        _launch(case, operation)
        _join(case)
        _retained_record(case)


def test_actual_post_put_deadline_barrier_never_exports_a_late_descriptor(tmp_path, monkeypatch):
    def operation(case, adapter):
        with pytest.raises(
            owner_module._DeadlineExpired, match=r"^READINESS_DEADLINE_EXPIRED$"
        ) as caught:
            adapter.prepare(deadline_ns=case.deadline_ns)
        case.operation_error = caught.value
        assert time.monotonic_ns() >= case.deadline_ns
        assert len(case.puts) == 1 and case.proofs == 1
        _no_retry(case, adapter)

    with _preparation_case(tmp_path, monkeypatch, mode="late-put") as case:
        try:
            _launch(case, operation)
            assert case.put_seen.wait(15), "original put did not reach the controlled barrier"
            assert case.thread.is_alive() and not case.finished.is_set()
            assert case.close_calls == 0 and case.release_attempts == []
            assert len(_same_application_facts(case.admitted, _snapshot(case.study))) == 1
            # Real monotonic passage through the admitted deadline, not a fake
            # clock, sleep-based quiescence claim, or enlarged operation limit.
            remaining = max(0, case.deadline_ns - time.monotonic_ns()) / 1_000_000_000
            assert not case.finished.wait(remaining)
            assert time.monotonic_ns() >= case.deadline_ns
        finally:
            case.allow_put.set()
            if case.thread is not None:
                _join(case)
        _retained_record(case)


def test_actual_selected_b_denies_private_preparation_before_put(tmp_path, monkeypatch):
    def operation(case, adapter):
        with pytest.raises(ValueError, match=r"^INITIAL_SELECTION_PREPARATION_REQUIRES_EMPTY_B$"):
            adapter.prepare(deadline_ns=case.deadline_ns)
        assert case.proofs == 1 and case.puts == []
        _no_retry(case, adapter)

    with _preparation_case(tmp_path, monkeypatch, mode="selected") as case:
        _launch(case, operation)
        _join(case)
        assert case.historical is None


def test_actual_put_reentry_consumes_no_second_attempt_and_preserves_outer_result(
    tmp_path, monkeypatch
):
    with _preparation_case(tmp_path, monkeypatch, mode="reentry") as case:
        _launch(case, _success)
        _join(case)
        assert type(case.reentry_error) is ValueError
        _assert_descriptor(case)
