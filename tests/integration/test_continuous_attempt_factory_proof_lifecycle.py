"""Genuine proof lifecycle cases sharing only original signed history.

Every case still creates a fresh factory, real UTC clock and original bounded
lease through the existing retained runner. No owner registration is fabricated.
"""

import json
import sys
from contextlib import ExitStack, contextmanager
from threading import Thread

import pytest

from apps.trader.continuous_simulation_factory import ContinuousSimulationFactoryError
from packages.persistence import continuous_integrity as integrity
from packages.persistence import continuous_runtime_attempt_sources as attempt_sources
from packages.persistence._factory_attempt_fingerprint import (
    _AttemptDataChanged,
    _AttemptDataSeal,
)
from packages.persistence.continuous_runtime_attempt_sources import (
    SqlContinuousRuntimeAttemptSources,
)
from tests.integration.test_continuous_attempt_factory_proof import (
    _copy_preserving_class_inventory,
    _mutate_provenance_scalar,
)
from tests.integration.test_continuous_simulation_factory_outcome import (
    _configuration_for_history,
    _execute_retained_factory,
    _signed_outcome_history,
)


@pytest.fixture(scope="module")
def signed_history(tmp_path_factory):
    patch = pytest.MonkeyPatch()
    history = None
    try:
        history = _signed_outcome_history(tmp_path_factory.mktemp("proof-history"), patch)
        pair, runtime, *_ = history
        yield history, _configuration_for_history(pair, runtime)
    finally:
        try:
            if history is not None:
                history[0].close()
        finally:
            patch.undo()


def _assert_retired(captured):
    source = captured["source"]
    context = captured["context"]
    use = captured["use"]
    assert id(captured["proof"]) not in attempt_sources._FACTORY_ATTEMPT_PROOFS
    assert context not in integrity._FACTORY_FINGERPRINTS
    assert context not in integrity._FACTORY_FINGERPRINT_READERS.values()
    assert use not in integrity._FACTORY_FINGERPRINT_USES
    assert not any(owner.source is source for owner in integrity._FACTORY_FINGERPRINTS.values())


@contextmanager
def _first_local_event(code, event, observe, *, select=None):
    """Watch one original code location, with no process-wide call profiling."""
    monitoring = sys.monitoring
    tool = next((index for index in range(6) if monitoring.get_tool(index) is None), None)
    assert tool is not None, "no free interpreter monitoring slot for proof validation"
    monitoring.use_tool_id(tool, "aqt-original-proof-test")
    active = True

    def close():
        nonlocal active
        if not active:
            return
        active = False
        try:
            monitoring.set_local_events(tool, code, 0)
        finally:
            try:
                monitoring.register_callback(tool, event, None)
            finally:
                monitoring.free_tool_id(tool)

    def received(actual, offset, *result):
        frame = sys._getframe(1)
        try:
            assert actual is code and frame.f_code is code
            if select is not None and not select(frame):
                return
            close()
            observe(frame)
        finally:
            del frame

    try:
        monitoring.register_callback(tool, event, received)
        monitoring.set_local_events(tool, code, event)
        yield
    finally:
        close()


@pytest.mark.parametrize(
    "case",
    [
        "original",
        "copied_proof",
        "foreign_thread",
        "reentrant",
        "nested_data",
        "retired",
        "reader_shadow",
    ],
)
@pytest.mark.skipif(
    sys.implementation.name != "cpython" or sys.version_info[:3] != (3, 12, 13),
    reason="genuine positive factory proof is qualified only on CPython 3.12.13",
)
def test_genuine_factory_proof_lifecycle_preserves_original_history(
    signed_history, monkeypatch, case
):
    history, config = signed_history
    method_code = SqlContinuousRuntimeAttemptSources._require_resolved_for_factory.__code__
    begin_code = integrity._begin_factory_fingerprint_use.__code__
    captured = {}
    denied = []
    cleanup_callbacks = []
    completed_permits = []

    def call_again(proof):
        try:
            captured["source"]._require_resolved_for_factory(
                captured["value"], proof=proof, use=captured["use"]
            )
        except ValueError as error:
            denied.append(type(error))

    def observe(frame):
        assert not captured
        # Reentrancy is injected only after the original permit has entered its
        # checking phase. Other cases use its first original method entry.
        at_checking = case == "reentrant"
        local = frame.f_locals
        source = local["source"] if at_checking else local["self"]
        value, proof, use = local["value"], local["proof"], local["use"]
        permit = integrity._FACTORY_FINGERPRINT_USES[use]
        captured.update(source=source, value=value, proof=proof, use=use, context=permit[0])
        if case == "copied_proof":
            copied = _copy_preserving_class_inventory(proof)
            assert copied is not proof
            call_again(copied)
            assert len(denied) == 1
            original_owner = integrity._FACTORY_FINGERPRINTS[permit[0]]
            assert original_owner.factory.failed and original_owner.daily.failed

            def forbidden_cleanup(*args, **kwargs):
                cleanup_callbacks.append("replacement invoked")
                raise AssertionError("replacement cleanup callback invoked")

            names = (
                "_fail_factory_fingerprint_use",
                "_retire_factory_fingerprint_context",
            )
            captured["cleanup_bindings"] = tuple((name, getattr(integrity, name)) for name in names)
            for name in names:
                setattr(integrity, name, forbidden_cleanup)
        elif case == "foreign_thread":
            worker = Thread(target=call_again, args=(proof,))
            worker.start()
            worker.join(timeout=2)
            assert not worker.is_alive()
        elif case == "reentrant":
            call_again(proof)
        elif case == "nested_data":
            registered = attempt_sources._FACTORY_ATTEMPT_PROOFS[id(proof)]
            assert registered[0]() is proof
            original_state = registered[1]
            data = original_state.data
            assert type(data) is _AttemptDataSeal

            def from_original_source(data_frame):
                caller = data_frame.f_back
                return caller is not None and caller.f_code is method_code

            def mutate_after_original_guards(data_frame):
                caller = data_frame.f_back
                assert caller is not None and caller.f_code is method_code
                assert data_frame.f_locals["self"] is data
                assert caller.f_locals["state"] is original_state
                assert caller.f_locals["self"] is source
                assert caller.f_locals["value"] is value
                assert caller.f_locals["proof"] is proof
                assert caller.f_locals["use"] is use
                assert integrity._FACTORY_FINGERPRINT_USES[use][2] == "checking"
                captured["mutation_owner"] = integrity._FACTORY_FINGERPRINTS[permit[0]]
                captured["mutated"] = _mutate_provenance_scalar(value)
                captured["mutation_applied"] = True

            observers.enter_context(
                _first_local_event(
                    data.require.__func__.__code__,
                    sys.monitoring.events.PY_START,
                    mutate_after_original_guards,
                    select=from_original_source,
                )
            )
            observers.enter_context(
                _first_local_event(
                    integrity._end_factory_fingerprint_use.__code__,
                    sys.monitoring.events.PY_START,
                    lambda _frame: completed_permits.append("completion entered"),
                    select=lambda end_frame: end_frame.f_locals["use"] is use,
                )
            )
        elif case == "reader_shadow":
            reader = integrity._FACTORY_FINGERPRINTS[permit[0]].reader
            assert "_require_daily_episode_identity" not in vars(reader)
            reader._require_daily_episode_identity = lambda *_args: None
            captured["shadowed_reader"] = reader

    execution_returned = False
    try:
        with ExitStack() as observers:
            code = begin_code if case == "reentrant" else method_code
            event = (
                sys.monitoring.events.PY_RETURN
                if case == "reentrant"
                else sys.monitoring.events.PY_START
            )
            with _first_local_event(code, event, observe):
                if case in {"original", "retired"}:
                    _execute_retained_factory(history, config, monkeypatch)
                else:
                    with pytest.raises(
                        ContinuousSimulationFactoryError,
                        match="OFFLINE_OPERATION_FAILED",
                    ) as failure:
                        _execute_retained_factory(history, config, monkeypatch)
        execution_returned = True
    finally:
        if "mutated" in captured:
            backing, key, original = captured.pop("mutated")
            dict.__setitem__(backing, key, original)
        if "shadowed_reader" in captured:
            del captured["shadowed_reader"].__dict__["_require_daily_episode_identity"]
        for name, original in captured.pop("cleanup_bindings", ()):
            setattr(integrity, name, original)
        if not execution_returned and case in {"original", "retired"}:
            print(
                "AQT_FACTORY_PROOF_DIAGNOSTIC "
                + json.dumps({"case": case, "private_entry_seen": bool(captured)}, sort_keys=True)
            )
    assert captured, "genuine nonempty factory path never issued/used the bounded proof"
    _assert_retired(captured)
    assert cleanup_callbacks == []
    if case in {"copied_proof", "foreign_thread", "reentrant"}:
        assert len(denied) == 1, "caught inner proof misuse must still poison the outer operation"
    else:
        assert denied == []
    if case == "nested_data":
        assert captured.get("mutation_applied") is True
        assert completed_permits == []
        owner = captured["mutation_owner"]
        assert owner.factory.failed and owner.daily.failed
        error = failure.value
        for _ in range(8):
            if type(error) is _AttemptDataChanged:
                break
            error = error.__context__
            if error is None:
                break
        assert type(error) is _AttemptDataChanged
        assert str(error) == "FACTORY_ATTEMPT_DATA_BINDING_CHANGED"
    if case == "reader_shadow":
        assert "shadowed_reader" in captured
    if case == "retired":
        call_again(captured["proof"])
        assert len(denied) == 1
        _assert_retired(captured)
