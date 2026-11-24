"""Same-interpreter Stop wiring admission and inert ports; no financial imports.

The original module is parsed as a golden value, never imported or executed.
Only its admitted target function runs with explicit fake ports and owned paths.
These controls qualify failure reporting, not leases, Stop priority or SQL.
"""

import ast
import copy
import gc
import hashlib
import json
import sys
import weakref
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.fixtures import lifecycle_outcome_diagnostic as diagnostic

ORIGINAL_SHA256 = "278f884b89f496b328be346e938724960c038d96255ee6b252159ea87305d0bb"
ORIGINAL_SOURCE = (
    '"""Actual private SQLite rows and fixed worker lifecycle; synthe'
    'tic financial inputs."""\n\nimport json\nimport os\nimport threading'
    "\nimport time\nfrom dataclasses import replace\nfrom hashlib import"
    " sha256\nfrom uuid import uuid4\n\nimport pytest\nimport sqlalchemy "
    "as sa\n\nfrom apps.trader.continuous_process_lifecycle import (\n  "
    "  ContinuousLifecycleError,\n    SqlContinuousParentProbe,\n    _b"
    "ytes,\n    _lease_fields,\n)\nfrom apps.trader.continuous_simulatio"
    "n_factory import _ActualClock\nfrom packages.application import c"
    "ontinuous_process as process_module\nfrom packages.application.co"
    "ntinuous_process import (\n    ContinuousProcessLimits,\n    Conti"
    "nuousProcessStartup,\n    ContinuousProcessSupervisor,\n    _encod"
    "e,\n    _private_read,\n    _private_write,\n)\nfrom packages.applic"
    "ation.personal_runtime import LocalInstanceGuard\nfrom packages.d"
    "omain.personal_contracts import content_digest\nfrom packages.per"
    "sistence.account_coordinator import (\n    SqlAccountCoordinator,"
    "\n    SqlAccountCoordinatorAuthority,\n    account_lease_from_row,"
    "\n)\nfrom packages.persistence.schema import phase5_operational_co"
    "ntrol_heads\nfrom tests.integration.test_continuous_simulation_fa"
    "ctory import (\n    configured,  # noqa: F401\n    release,\n    re"
    "quest_for,\n)\nfrom tests.integration.test_runtime_owner_associati"
    "ons import install_initial_signed_assignment\n\n\n@pytest.fixture\nd"
    "ef ready_case(configured, tmp_path):  # noqa: F811\n    fixture, "
    "config = configured\n    install_initial_signed_assignment(fixtur"
    "e)\n    release(fixture)\n    request = request_for(fixture, confi"
    'g)\n    directory = tmp_path / "private-lifecycle"\n    directory.'
    'mkdir(mode=0o700)\n    with LocalInstanceGuard(tmp_path / "parent'
    '.lock") as lock:\n        info = os.fstat(lock.fileno())\n        '
    "started = time.monotonic()\n        startup = ContinuousProcessSt"
    "artup(\n            request,\n            directory,\n            u"
    "uid4().hex,\n            os.getpid(),\n            sha256(_encode("
    "request)).hexdigest(),\n            sha256(_private_read(request."
    "configuration_path, 65536)).hexdigest(),\n            info.st_dev"
    ",\n            info.st_ino,\n            started,\n            star"
    "ted + 10,\n            started + 20,\n        )\n        probe = Sq"
    "lContinuousParentProbe(request)\n        probe.prepare(startup)\n "
    "       assert probe.observe(child_pid=None, child_exited=False) "
    '== "starting"\n        owner = SqlAccountCoordinator(\n           '
    " account_id=request.account_id,\n            authority=SqlAccount"
    "CoordinatorAuthority(\n                engine=fixture[0].base.eng"
    "ine, policy=config.lease_policy(), clock=_ActualClock()\n        "
    "    ),\n        )\n        # Transport fixture: actual new canonic"
    "al lease and current process ID.\n        # The separate fixed-wo"
    "rker tests supply the genuine Popen PID binding.\n        nonce ="
    ' uuid4().hex\n        lease = owner.acquire(\n            "offline'
    '-owner-" + content_digest((config.owner_id, os.getpid(), nonce))'
    "\n        )\n        rows = probe._database.capture()\n        read"
    'y = {\n            "schema": "continuous-lease-ready/1",\n        '
    '    "envelope_sha256": sha256(_bytes(probe._envelope)).hexdigest'
    '(),\n            "child_pid": os.getpid(),\n            "instance_'
    'nonce": nonce,\n            "scope_sha256": fixture[0].base.scope'
    '.semantic_sha256,\n            "lease": _lease_fields(lease),\n   '
    '         "control_sha256": rows.control["semantic_sha256"],\n    '
    '    }\n        _private_write(directory / "lease-ready.json", _by'
    "tes(ready))\n        yield probe, owner, lease, startup, ready, f"
    "ixture, config\n        probe._database.engine.dispose()\n\n\ndef ob"
    "serve(probe, *, exited=False):\n    return probe.observe(child_pi"
    "d=os.getpid(), child_exited=exited)\n\n\ndef result_for(probe):\n   "
    ' return json.dumps(\n        {\n            "schema": "continuous-'
    'offline-result/1",\n            "account_id": probe.request.accou'
    'nt_id,\n            "operation_id": probe.request.operation_id,\n '
    '           "operation": "restore",\n            "status": "restor'
    'ed",\n        },\n        sort_keys=True,\n        separators=(",",'
    ' ":"),\n    ).encode()\n\n\ndef begin_close(probe, startup, ready):\n'
    '    payload = result_for(probe)\n    frame = {\n        "schema": '
    '"continuous-result-ready/1",\n        "ready_sha256": sha256(_byt'
    'es(ready)).hexdigest(),\n        "result_sha256": sha256(payload)'
    '.hexdigest(),\n        "result_bytes": len(payload),\n    }\n    _p'
    'rivate_write(startup.directory / "result-ready.json", _bytes(fra'
    "me))\n    return payload, frame\n\n\ndef complete_close(startup, rea"
    'dy, released, payload):\n    frame = {\n        "schema": "continu'
    'ous-lease-released/1",\n        "ready_sha256": sha256(_bytes(rea'
    'dy)).hexdigest(),\n        "release_id": released.release_id,\n   '
    '     "release_sha256": released.semantic_sha256,\n        "releas'
    'ed_at": released.released_at.isoformat(),\n        "result_sha256'
    '": sha256(payload).hexdigest(),\n        "result_bytes": len(payl'
    'oad),\n    }\n    _private_write(startup.directory / "lease-releas'
    'ed.json", _bytes(frame))\n\n\ndef test_parent_probe_reads_exact_liv'
    "e_and_released_rows_without_any_sql_write(ready_case):\n    probe"
    ", owner, lease, startup, ready, *_ = ready_case\n    statements ="
    " []\n    sa.event.listen(\n        probe._database.engine,\n       "
    ' "before_cursor_execute",\n        lambda _c, _cu, text, *_a: sta'
    "tements.append(text),\n    )\n    before = probe._database.capture"
    '()\n    assert observe(probe) == "leased"\n    assert observe(prob'
    'e) == "leased"\n    assert probe._database.capture() == before\n  '
    "  payload, _frame = begin_close(probe, startup, ready)\n    asser"
    't observe(probe) == "closing"\n    released = owner.release(lease'
    '.fence)\n    assert observe(probe) == "closing"  # deliberate rel'
    "ease → terminal-file gap\n    complete_close(startup, ready, rele"
    'ased, payload)\n    assert observe(probe) == "released"\n    with '
    "pytest.raises(ContinuousLifecycleError):\n        probe.require_r"
    "esult(payload)  # zero child exit was not yet observed\n    asser"
    't observe(probe, exited=True) == "released"\n    probe.require_re'
    "sult(payload)\n    assert all(\n        text.lstrip().upper().star"
    'tswith(("SELECT", "BEGIN", "PRAGMA QUERY_ONLY"))\n        for tex'
    't in statements\n    )\n    assert not any("UPDATE " in text.upper'
    '() or "INSERT " in text.upper() for text in statements)\n\n\n@pytes'
    't.mark.parametrize(\n    "fault", ["pid", "nonce", "generation", '
    '"control", "early_release", "takeover"]\n)\ndef test_original_proc'
    "ess_lease_and_all_halted_control_fields_fail_closed(ready_case, "
    "fault):\n    probe, owner, lease, startup, ready, fixture, _confi"
    'g = ready_case\n    if fault in ("pid", "nonce", "generation"):\n '
    '       changed = dict(ready)\n        if fault == "pid":\n        '
    '    changed["child_pid"] += 1\n        elif fault == "nonce":\n   '
    '         changed["instance_nonce"] = "0" * 32\n        else:\n    '
    '        changed["lease"] = ready["lease"] | {"generation": lease'
    '.fencing_generation + 1}\n        path = startup.directory / "lea'
    'se-ready.json"\n        path.unlink()\n        _private_write(path'
    ', _bytes(changed))\n    else:\n        assert observe(probe) == "l'
    'eased"\n        if fault == "control":\n            with fixture[0'
    "].base.engine.begin() as connection:\n                connection."
    "execute(\n                    sa.update(phase5_operational_contro"
    'l_heads).values(canonical_payload="{}")\n                )\n      '
    "  else:\n            owner.release(lease.fence)\n            if fa"
    'ult == "takeover":\n                owner.acquire("different-actu'
    'al-process-owner")\n    with pytest.raises(ContinuousLifecycleErr'
    'or):\n        observe(probe)\n\n\n@pytest.mark.parametrize("fault", '
    '["result_hash", "missing_release", "closing_timeout"])\ndef test_'
    "terminal_claim_cannot_replace_actual_release_and_bound_result(\n "
    "   ready_case, monkeypatch, fault\n):\n    probe, owner, lease, st"
    'artup, ready, *_ = ready_case\n    assert observe(probe) == "leas'
    'ed"\n    payload, _frame = begin_close(probe, startup, ready)\n   '
    ' assert observe(probe) == "closing"\n    if fault == "closing_tim'
    'eout":\n        monkeypatch.setattr(\n            "apps.trader.con'
    'tinuous_process_lifecycle.time.monotonic",\n            lambda: p'
    'robe._closing_deadline,\n        )\n    elif fault == "missing_rel'
    'ease":\n        # No actual release: even a terminal-looking tran'
    "sport record cannot qualify.\n        _private_write(startup.dire"
    'ctory / "lease-released.json", b"{}")\n    else:\n        released'
    " = owner.release(lease.fence)\n        complete_close(startup, re"
    'ady, released, payload + b" ")\n    with pytest.raises(Continuous'
    "LifecycleError):\n        observe(probe)\n\n\n@pytest.mark.parametri"
    'ze("publish_before_sql", [False, True])\ndef test_complete_result'
    "_frames_cannot_be_paired_with_older_sql_snapshot(\n    ready_case"
    ", monkeypatch, publish_before_sql\n):\n    probe, owner, lease, st"
    'artup, ready, *_ = ready_case\n    assert observe(probe) == "leas'
    'ed"\n    original = probe._database.capture\n    changed = False\n '
    "   payload = result_for(probe)\n\n    def capture():\n        nonlo"
    "cal changed\n        if changed:\n            return original()\n  "
    "      changed = True\n        prior = None if publish_before_sql "
    "else original()\n        begin_close(probe, startup, ready)\n     "
    "   released = owner.release(lease.fence)\n        complete_close("
    "startup, ready, released, payload)\n        return original() if "
    "publish_before_sql else prior\n\n    monkeypatch.setattr(probe._da"
    'tabase, "capture", capture)\n    assert observe(probe) in ("lease'
    'd", "released")\n    assert observe(probe, exited=True) == "relea'
    'sed"\n    probe.require_result(payload)\n\n\n@pytest.mark.parametriz'
    'e("fault", ["stop", "ready_pid", "result", "early_release", "tak'
    'eover"])\ndef test_fixed_actual_child_parent_faults_never_accept_'
    "a_receipt(\n    configured,  # noqa: F811\n    tmp_path,\n    monke"
    "ypatch,\n    fault,\n):\n    fixture, config = configured\n    insta"
    "ll_initial_signed_assignment(fixture)\n    release(fixture)\n    r"
    "equest = replace(request_for(fixture, config), limits=Continuous"
    "ProcessLimits(wall_seconds=30))\n    probe = SqlContinuousParentP"
    "robe(request)\n    original = probe.observe\n    stopped = False\n "
    "   acted = False\n    observed = []\n\n    def checked(**kwargs):\n "
    '       nonlocal stopped, acted\n        if fault == "ready_pid" a'
    "nd probe._startup is not None:\n            path = probe._startup"
    '.directory / "lease-ready.json"\n            if path.exists() and'
    " probe._ready is None:\n                value = json.loads(path.r"
    'ead_bytes())\n                value["child_pid"] += 1\n           '
    "     path.unlink()\n                _private_write(path, _bytes(v"
    "alue))\n        phase = original(**kwargs)\n        observed.appen"
    'd(phase)\n        if phase == "leased" and fault == "stop":\n     '
    '       stopped = True\n        if phase == "leased" and not acted'
    ' and fault in ("early_release", "takeover"):\n            # Separ'
    "ate test fault actor mutates the real DB; the production\n       "
    "     # parent probe remains SQL read-only throughout this operat"
    "ion.\n            acted = True\n            actor = SqlAccountCoor"
    "dinator(\n                account_id=request.account_id,\n        "
    "        authority=SqlAccountCoordinatorAuthority(\n              "
    "      engine=fixture[0].base.engine,\n                    policy="
    "config.lease_policy(),\n                    clock=_ActualClock(),"
    "\n                ),\n            )\n            actual = account_l"
    "ease_from_row(probe._original_lease)\n            actor.release(a"
    'ctual.fence)\n            if fault == "takeover":\n               '
    ' actor.acquire("different-test-child-owner")\n        if phase =='
    ' "released" and kwargs["child_exited"] and fault == "result":\n  '
    '          path = probe._startup.directory / "receipt.json"\n     '
    '       path.write_bytes(path.read_bytes() + b" ")\n        return'
    ' phase\n\n    monkeypatch.setattr(probe, "observe", checked)\n    t'
    "mp_path.chmod(0o700)\n    supervisor = ContinuousProcessSuperviso"
    "r(artifact_directory=tmp_path)\n    with LocalInstanceGuard(tmp_p"
    'ath / "actual-parent.lock") as lock:\n        result = supervisor'
    ".run(\n            request, lock_descriptor=lock.fileno(), stop_r"
    "equested=lambda: stopped, lifecycle=probe\n        )\n    assert r"
    'esult.receipt is None and result.status != "completed"\n    if fa'
    'ult == "stop":\n        assert "leased" in observed and result.st'
    'atus == "stopped"\n    if fault in ("early_release", "takeover"):'
    "\n        assert acted\n    assert supervisor._probe_thread is not"
    " None and not supervisor._probe_thread.is_alive()\n    assert not"
    ' tuple(tmp_path.glob(".continuous-operation-*"))\n\n\ndef test_fixe'
    "d_child_requires_probe_sampled_after_exit_before_accepting_resul"
    "t(\n    configured,  # noqa: F811\n    tmp_path,\n    monkeypatch,\n"
    "):\n    _exercise_post_exit_probe(configured, tmp_path, monkeypat"
    "ch, observation_failure=False)\n\n\ndef test_post_exit_probe_hook_p"
    "reserves_observation_failure_and_cleanup(\n    configured,  # noq"
    "a: F811\n    tmp_path,\n    monkeypatch,\n):\n    _exercise_post_exi"
    "t_probe(configured, tmp_path, monkeypatch, observation_failure=T"
    "rue)\n\n\ndef _exercise_post_exit_probe(configured_case, tmp_path, "
    "monkeypatch, *, observation_failure):\n    fixture, config = conf"
    "igured_case\n    install_initial_signed_assignment(fixture)\n    r"
    "elease(fixture)\n    request = request_for(fixture, config)\n    p"
    "robe = SqlContinuousParentProbe(request)\n    original_launch = p"
    "rocess_module.subprocess.Popen\n    original_child_observe = proc"
    "ess_module._observe_child\n    original_terminate = process_modul"
    "e._terminate_owned_child\n    original_observe = probe.observe\n  "
    "  original_require_result = probe.require_result\n    zombie_seen"
    " = threading.Event()\n    pre_exit_sample_started = threading.Eve"
    "nt()\n    owned_children = []\n    waits = []\n    delayed_observat"
    "ion = False\n    post_exit_sample = False\n    cleaning_up = False"
    "\n    cleanup_observations = 0\n    failure_injected = False\n    r"
    "esult_checks = 0\n\n    def terminate(*args, **kwargs):\n        no"
    "nlocal cleaning_up\n        cleaning_up = True\n        try:\n     "
    "       return original_terminate(*args, **kwargs)\n        finall"
    "y:\n            cleaning_up = False\n\n    def launch(*args, **kwar"
    "gs):\n        child = original_launch(*args, **kwargs)\n        if"
    ' "apps.trader.continuous_simulation" in args[0]:\n            own'
    "ed_children.append(child)\n            original_wait = child.wait"
    "\n\n            def forbidden_poll():\n                raise Assert"
    'ionError("neither supervisor thread may reap through poll")\n\n   '
    "         def wait(*, timeout):\n                waits.append(time"
    "out)\n                return original_wait(timeout=timeout)\n\n    "
    '        monkeypatch.setattr(child, "poll", forbidden_poll)\n     '
    '       monkeypatch.setattr(child, "wait", wait)\n        return c'
    "hild\n\n    def observe_child(pid, **kwargs):\n        nonlocal cle"
    "anup_observations, failure_injected\n        assert threading.cur"
    "rent_thread() is threading.main_thread()\n        assert owned_ch"
    "ildren and owned_children[0].returncode is None\n        observat"
    "ion = original_child_observe(pid, **kwargs)\n        if cleaning_"
    "up:\n            # Cleanup can run after the SQL probe has stoppe"
    "d. Keep its real\n            # observation, but never wait for t"
    "he success-path handshake there.\n            cleanup_observation"
    "s += 1\n            return observation\n        if observation.exi"
    "ted and observation_failure:\n            assert not failure_inje"
    "cted\n            failure_injected = True\n            raise proce"
    'ss_module.subprocess.TimeoutExpired("test observation", kwargs["'
    'timeout"])\n        if observation.exited and not zombie_seen.is_'
    "set():\n            # Hold the main thread's real, non-reaping ob"
    "servation just long\n            # enough for the SQL thread to s"
    "ample the still-false exit latch.\n            zombie_seen.set()\n"
    "            assert pre_exit_sample_started.wait(0.2)\n        ret"
    "urn observation\n\n    def observe_after_delay(**kwargs):\n        "
    "nonlocal delayed_observation, post_exit_sample\n        if zombie"
    '_seen.is_set() and not kwargs["child_exited"]:\n            pre_e'
    "xit_sample_started.set()\n            time.sleep(0.1)  # this fal"
    "se sample finishes after main freezes exit\n            delayed_o"
    'bservation = True\n        if kwargs["child_exited"]:\n           '
    " post_exit_sample = True\n        return original_observe(**kwarg"
    "s)\n\n    def require_result(payload):\n        nonlocal result_che"
    "cks\n        result_checks += 1\n        assert not observation_fa"
    "ilure\n        assert delayed_observation and post_exit_sample\n  "
    "      assert supervisor._cleanup is not None and supervisor._cle"
    "anup.complete\n        assert owned_children[0].returncode == 0 a"
    "nd len(waits) == 1\n        return original_require_result(payloa"
    'd)\n\n    monkeypatch.setattr(process_module.subprocess, "Popen", '
    'launch)\n    monkeypatch.setattr(process_module, "_observe_child"'
    ', observe_child)\n    monkeypatch.setattr(process_module, "_termi'
    'nate_owned_child", terminate)\n    monkeypatch.setattr(probe, "ob'
    'serve", observe_after_delay)\n    monkeypatch.setattr(probe, "req'
    'uire_result", require_result)\n    tmp_path.chmod(0o700)\n    supe'
    "rvisor = ContinuousProcessSupervisor(artifact_directory=tmp_path"
    ')\n    with LocalInstanceGuard(tmp_path / "actual-exit-parent.loc'
    'k") as lock:\n        result = supervisor.run(\n            reques'
    "t, lock_descriptor=lock.fileno(), stop_requested=lambda: False, "
    "lifecycle=probe\n        )\n    if observation_failure:\n        as"
    'sert result.status == "failed" and result.reason == "child_obser'
    'vation_failed", result\n        assert result.receipt is None and'
    " failure_injected and cleanup_observations > 0\n        assert no"
    "t zombie_seen.is_set() and not pre_exit_sample_started.is_set()\n"
    "        assert not delayed_observation and not post_exit_sample "
    "and result_checks == 0\n    else:\n        assert result.status =="
    ' "completed", result.reason\n        assert pre_exit_sample_start'
    "ed.is_set() and delayed_observation and post_exit_sample\n       "
    " assert probe._observed_exit and result_checks == 1\n    assert s"
    "upervisor._cleanup is not None and supervisor._cleanup.complete\n"
    "    assert owned_children[0].returncode == 0 and len(waits) == 1"
    "\n    assert supervisor._probe_thread is not None and not supervi"
    "sor._probe_thread.is_alive()\n    assert not tuple(tmp_path.glob("
    '".continuous-operation-*"))\n'
)
_FUNCTION = "test_fixed_actual_child_parent_faults_never_accept_a_receipt"
_IMPORT = "tests.fixtures.lifecycle_outcome_diagnostic"
_NAME = "emit_lifecycle_outcome_failure"
_HANDLER = """
try:
    emit_lifecycle_outcome_failure(
        fault=fault,
        status=(result.status if type(result) is process_module.ContinuousProcessOutcome else None),
        reason=(result.reason if type(result) is process_module.ContinuousProcessOutcome else None),
        stopped=stopped,
        acted=acted,
    )
except BaseException:
    pass
"""


def dump(node):
    return ast.dump(node, include_attributes=False)


def current_source():
    return (
        Path(__file__).resolve().parents[1] / "integration" / "test_continuous_process_lifecycle.py"
    ).read_bytes()


def selected(module):
    functions = [
        node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == _FUNCTION
    ]
    assert len(functions) == 1
    return functions[0]


def admitted_function(source):
    assert type(source) is bytes and len(source) <= 24576
    assert len(ORIGINAL_SOURCE.encode("utf-8")) == 17822
    assert hashlib.sha256(ORIGINAL_SOURCE.encode("utf-8")).hexdigest() == ORIGINAL_SHA256
    golden = ast.parse(ORIGINAL_SOURCE)
    current = ast.parse(source)
    imports = [
        node for node in current.body if isinstance(node, ast.ImportFrom) and node.module == _IMPORT
    ]
    assert len(imports) == 1
    added = imports[0]
    assert added.level == 0
    assert [(item.name, item.asname) for item in added.names] == [(_NAME, None)]
    current.body.remove(added)
    original = selected(golden)
    function = selected(current)
    executable = copy.deepcopy(function)
    assert dump(function.body[-2]) == dump(original.body[-5])
    guard = function.body[-1]
    assert isinstance(guard, ast.Try)
    assert len(guard.handlers) == 1 and not guard.orelse and not guard.finalbody
    assert [dump(node) for node in guard.body] == [dump(node) for node in original.body[-4:]]
    handler = guard.handlers[0]
    assert dump(handler.type) == dump(ast.Name(id="AssertionError", ctx=ast.Load()))
    assert handler.name is None and len(handler.body) == 2
    assert dump(handler.body[0]) == dump(ast.parse(_HANDLER).body[0])
    assert dump(handler.body[1]) == dump(ast.Raise(exc=None, cause=None))
    function.body[-1:] = guard.body
    assert dump(current) == dump(golden)
    # Drop only the original pytest decorator after complete module admission.
    executable.decorator_list = []
    return executable


def original_function():
    function = copy.deepcopy(selected(ast.parse(ORIGINAL_SOURCE)))
    function.decorator_list = []
    return function


@dataclass(frozen=True, slots=True)
class Outcome:
    status: object
    reason: object
    receipt: object = None


@dataclass(frozen=True, slots=True)
class Limits:
    wall_seconds: int


@dataclass(frozen=True, slots=True)
class Request:
    account_id: str
    limits: object = None


class Writer:
    def __init__(self, error=None):
        self.lines = []
        self.error = error

    def write(self, text):
        self.lines.append(text)
        if self.error is not None:
            raise self.error
        return len(text)


class Harness:
    def __init__(
        self,
        *,
        outcome=None,
        phases=(),
        alive=False,
        run_error=None,
        enter_error=None,
        observe_error=None,
    ):
        self.outcome = outcome if outcome is not None else Outcome("failed", "probe_stalled")
        self.phases = tuple(phases)
        self.alive = alive
        self.run_error = run_error
        self.enter_error = enter_error
        self.observe_error = observe_error
        self.events = []
        self.run_arguments = None
        self.request = Request("inert-account")
        self.fixture = (SimpleNamespace(base=SimpleNamespace(engine=object())),)
        self.config = SimpleNamespace(lease_policy=lambda: "inert-policy")

    def globals(self, emitter):
        owner = self

        class Probe:
            def __init__(self, request):
                owner.events.append(("probe", request))
                self._startup = None
                self._ready = None
                self._original_lease = object()

            def observe(self, **kwargs):
                owner.events.append(("observe", dict(kwargs)))
                if owner.observe_error is not None:
                    raise owner.observe_error
                return owner.phases[kwargs["position"]]

        class Thread:
            def is_alive(self):
                owner.events.append("thread-check")
                return owner.alive

        class Supervisor:
            def __init__(self, *, artifact_directory):
                owner.events.append(("supervisor", artifact_directory))
                self._probe_thread = Thread()

            def run(self, request, **kwargs):
                owner.events.append("run")
                owner.run_arguments = (request, kwargs)
                if owner.run_error is not None:
                    raise owner.run_error
                lifecycle = kwargs["lifecycle"]
                for position, phase in enumerate(owner.phases):
                    assert (
                        lifecycle.observe(position=position, child_exited=phase == "released")
                        == phase
                    )
                owner.events.append(("stop", kwargs["stop_requested"]()))
                return owner.outcome

        class Guard:
            def __init__(self, path):
                owner.events.append(("guard", path))

            def __enter__(self):
                owner.events.append("enter")
                if owner.enter_error is not None:
                    raise owner.enter_error
                return self

            def fileno(self):
                owner.events.append("fileno")
                return 41

            def __exit__(self, *error):
                owner.events.append(("exit", error[0]))

        class Actor:
            def __init__(self, **kwargs):
                owner.events.append(("actor", kwargs))

            def release(self, fence):
                owner.events.append(("release-fence", fence))

            def acquire(self, identity):
                owner.events.append(("acquire", identity))

        def install(value):
            assert value is owner.fixture
            owner.events.append("install")

        def release(value):
            assert value is owner.fixture
            owner.events.append("release")

        def request_for(value, config):
            assert value is owner.fixture and config is owner.config
            owner.events.append("request")
            return owner.request

        # Only these reviewed globals are available to the extracted function.
        return {
            "__builtins__": {
                "AssertionError": AssertionError,
                "BaseException": BaseException,
                "tuple": tuple,
                "type": type,
            },
            "install_initial_signed_assignment": install,
            "release": release,
            "request_for": request_for,
            "replace": replace,
            "ContinuousProcessLimits": Limits,
            "SqlContinuousParentProbe": Probe,
            "ContinuousProcessSupervisor": Supervisor,
            "LocalInstanceGuard": Guard,
            "process_module": SimpleNamespace(ContinuousProcessOutcome=Outcome),
            "SqlAccountCoordinator": Actor,
            "SqlAccountCoordinatorAuthority": lambda **kwargs: kwargs,
            "account_lease_from_row": lambda value: SimpleNamespace(fence=value),
            "_ActualClock": lambda: "inert-clock",
            "json": json,
            "_bytes": lambda value: json.dumps(value).encode("ascii"),
            "_private_write": lambda path, value: path.write_bytes(value),
            _NAME: emitter,
        }

    def invoke(self, function, tmp_path, monkeypatch, *, fault="stop", emitter=None):
        namespace = self.globals(emitter or diagnostic.emit_lifecycle_outcome_failure)
        module = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
        exec(compile(module, "<admitted-inert-stop-wiring>", "exec"), namespace)
        namespace[_FUNCTION]((self.fixture, self.config), tmp_path, monkeypatch, fault)


def caught(harness, function, tmp_path, monkeypatch, *, fault="stop", emitter=None):
    try:
        harness.invoke(function, tmp_path, monkeypatch, fault=fault, emitter=emitter)
    except AssertionError as error:
        return error
    pytest.fail("original assertion must fail")


def wire():
    return admitted_function(current_source())


def install_writer(monkeypatch, writer):
    monkeypatch.setitem(diagnostic.sys.__dict__, "stdout", writer)


@pytest.mark.parametrize("fault", ["stop", "ready_pid", "result", "early_release", "takeover"])
def test_quiet_pass_preserves_original_arguments_actions_and_cleanup(tmp_path, monkeypatch, fault):
    phases = ("leased",) if fault in ("stop", "early_release", "takeover") else ()
    harness = Harness(
        phases=phases, outcome=Outcome("stopped" if fault == "stop" else "failed", "stopped")
    )
    calls = []
    harness.invoke(
        wire(), tmp_path, monkeypatch, fault=fault, emitter=lambda **kw: calls.append(kw)
    )
    assert calls == []
    request, args = harness.run_arguments
    assert request.account_id == harness.request.account_id
    assert request.limits == Limits(30)
    assert args["lock_descriptor"] == 41
    assert set(args) == {"lock_descriptor", "stop_requested", "lifecycle"}
    assert harness.events.index("install") < harness.events.index("release")
    assert harness.events.index("release") < harness.events.index("request")
    assert harness.events.index("fileno") < harness.events.index("run")
    assert harness.events.index(("exit", None)) < harness.events.index("thread-check")
    assert ("stop", fault == "stop") in harness.events
    assert len([item for item in harness.events if type(item) is tuple and item[0] == "probe"]) == 1
    if fault in ("early_release", "takeover"):
        assert (
            len([item for item in harness.events if type(item) is tuple and item[0] == "actor"])
            == 1
        )
        assert (
            len(
                [
                    item
                    for item in harness.events
                    if type(item) is tuple and item[0] == "release-fence"
                ]
            )
            == 1
        )
    assert (
        ("acquire", "different-test-child-owner") in harness.events
        if fault == "takeover"
        else not any(type(item) is tuple and item[0] == "acquire" for item in harness.events)
    )


@pytest.mark.parametrize("failed", ["stop", "acted", "thread", "directory"])
def test_each_later_assertion_reports_once_after_guard_exit(tmp_path, monkeypatch, failed):
    fault = "early_release" if failed == "acted" else "ready_pid"
    if failed == "stop":
        fault = "stop"
    harness = Harness(alive=failed == "thread")
    if failed == "directory":
        (tmp_path / ".continuous-operation-inert").mkdir()
    active = []
    calls = []

    def emit(**kwargs):
        active.append(sys.exception())
        calls.append(kwargs)
        assert ("exit", None) in harness.events

    error = caught(harness, wire(), tmp_path, monkeypatch, fault=fault, emitter=emit)
    assert active == [error] and active[0] is error
    assert calls == [
        {
            "fault": fault,
            "status": "failed",
            "reason": "probe_stalled",
            "stopped": False,
            "acted": False,
        }
    ]
    assert harness.events.count("run") == 1


def test_initial_receipt_assertion_is_outside_reporting(tmp_path, monkeypatch):
    calls = []
    harness = Harness(outcome=Outcome("completed", "completed", object()))
    error = caught(harness, wire(), tmp_path, monkeypatch, emitter=lambda **kw: calls.append(kw))
    assert type(error) is AssertionError and calls == []
    assert ("exit", None) in harness.events


@pytest.mark.parametrize("stage", ["run", "enter", "constructor", "observe"])
def test_original_failures_do_not_enter_diagnostic(tmp_path, monkeypatch, stage):
    primary = KeyboardInterrupt("inert-original")
    harness = Harness(
        run_error=primary if stage == "run" else None,
        enter_error=primary if stage == "enter" else None,
        observe_error=primary if stage == "observe" else None,
        phases=("leased",) if stage == "observe" else (),
    )
    calls = []
    if stage == "constructor":
        original_globals = harness.globals

        def globals_with_fault(emitter):
            namespace = original_globals(emitter)

            def fail(request):
                raise primary

            namespace["SqlContinuousParentProbe"] = fail
            return namespace

        monkeypatch.setattr(harness, "globals", globals_with_fault)
    with pytest.raises(KeyboardInterrupt) as caught_error:
        harness.invoke(wire(), tmp_path, monkeypatch, emitter=lambda **kw: calls.append(kw))
    assert caught_error.value is primary and calls == []
    if stage in ("run", "observe"):
        assert ("exit", KeyboardInterrupt) in harness.events


@pytest.mark.parametrize("kind", ["foreign", "subclass"])
def test_unknown_outcomes_get_no_new_slot_reads(tmp_path, monkeypatch, kind):
    reads = []

    class Foreign:
        def __getattribute__(self, name):
            reads.append(name)
            if name == "receipt":
                return None
            if name == "status":
                return "failed"
            raise RuntimeError("private-unknown-slot")

    class Subclass(Outcome):
        def __getattribute__(self, name):
            reads.append(name)
            return object.__getattribute__(self, name)

    value = Foreign() if kind == "foreign" else Subclass("failed", "private-reason")
    original = Harness(outcome=value)
    caught(original, original_function(), tmp_path, monkeypatch)
    baseline = list(reads)
    reads.clear()
    writer = Writer()
    install_writer(monkeypatch, writer)
    error = caught(Harness(outcome=value), wire(), tmp_path, monkeypatch)
    assert type(error) is AssertionError and reads == baseline
    payload = json.loads(writer.lines[0][len(diagnostic.PREFIX) :])
    assert payload["status"] is None and payload["reason"] is None
    assert payload["available"] is False and len(writer.lines) == 1


@pytest.mark.parametrize("failure_type", [RuntimeError, KeyboardInterrupt])
def test_exact_outcome_hostile_slot_lookup_preserves_pending_assertion(
    tmp_path, monkeypatch, failure_type
):
    reads = []
    original_get = Outcome.__getattribute__
    metadata = failure_type("inert-slot-fault")

    def getter(self, name):
        reads.append(name)
        if name == "reason":
            raise metadata
        return original_get(self, name)

    monkeypatch.setattr(Outcome, "__getattribute__", getter)
    calls = []
    error = caught(Harness(), wire(), tmp_path, monkeypatch, emitter=lambda **kw: calls.append(kw))
    assert type(error) is AssertionError and calls == []
    assert reads == ["receipt", "status", "status", "reason"]
    assert metadata.__context__ is error


@pytest.mark.parametrize("failure_type", [RuntimeError, KeyboardInterrupt])
def test_metadata_class_binding_fault_keeps_original_assertion(tmp_path, monkeypatch, failure_type):
    failure = failure_type("inert-binding-fault")
    harness = Harness()
    original_globals = harness.globals
    calls = []
    lookups = []

    class MissingBinding:
        def __getattribute__(self, name):
            lookups.append(name)
            raise failure

    def globals_with_fault(emitter):
        namespace = original_globals(emitter)
        namespace["process_module"] = MissingBinding()
        return namespace

    monkeypatch.setattr(harness, "globals", globals_with_fault)
    error = caught(harness, wire(), tmp_path, monkeypatch, emitter=lambda **kw: calls.append(kw))
    assert type(error) is AssertionError and calls == []
    assert lookups == ["ContinuousProcessOutcome"]
    assert failure.__context__ is error


_HOOKS = []


class PrivateMarker:
    def __repr__(self):
        _HOOKS.append("repr")
        raise KeyboardInterrupt("private")

    def __str__(self):
        _HOOKS.append("str")
        raise KeyboardInterrupt("private")

    def __eq__(self, other):
        _HOOKS.append("eq")
        raise KeyboardInterrupt("private")

    def __ne__(self, other):
        _HOOKS.append("ne")
        return True

    def __bool__(self):
        _HOOKS.append("bool")
        raise KeyboardInterrupt("private")


@pytest.mark.parametrize("field", ["status", "reason"])
def test_private_exact_outcome_fields_are_not_coerced_or_printed(tmp_path, monkeypatch, field):
    private = PrivateMarker()
    value = Outcome(private, "probe_stalled") if field == "status" else Outcome("failed", private)
    _HOOKS.clear()
    caught(Harness(outcome=value), original_function(), tmp_path, monkeypatch)
    baseline = list(_HOOKS)
    _HOOKS.clear()
    writer = Writer()
    install_writer(monkeypatch, writer)
    caught(Harness(outcome=value), wire(), tmp_path, monkeypatch)
    assert baseline == _HOOKS
    assert len(writer.lines) == 1
    payload = json.loads(writer.lines[0][len(diagnostic.PREFIX) :])
    assert payload[field] is None and payload["available"] is False
    assert "private" not in writer.lines[0]


@pytest.mark.parametrize("failure_type", [RuntimeError, KeyboardInterrupt, AssertionError])
def test_emitter_fault_preserves_original_identity_cause_context_and_no_retry(
    tmp_path, monkeypatch, failure_type
):
    calls = []
    original = []

    def emit(**kwargs):
        primary = sys.exception()
        original.append((primary, primary.__cause__, primary.__context__))
        calls.append(kwargs)
        raise failure_type("metadata-only")

    context = ValueError("original-context")
    try:
        raise context
    except ValueError:
        error = caught(Harness(), wire(), tmp_path, monkeypatch, emitter=emit)
    assert error is original[0][0]
    assert error.__cause__ is original[0][1]
    assert error.__context__ is original[0][2] is context
    assert len(calls) == 1


@pytest.mark.parametrize("failure_type", [RuntimeError, KeyboardInterrupt])
def test_real_emitter_output_fault_keeps_original_assertion_and_single_attempt(
    tmp_path, monkeypatch, failure_type
):
    metadata = failure_type("inert-write-fault")
    writer = Writer(metadata)
    install_writer(monkeypatch, writer)
    error = caught(Harness(), wire(), tmp_path, monkeypatch)
    assert type(error) is AssertionError
    assert metadata.__context__ is error and len(writer.lines) == 1
    assert len(writer.lines[0].encode("ascii")) <= 4096
    assert writer.lines[0].endswith("\n")


def lifetime(use_candidate, field, tmp_path, monkeypatch):
    private = PrivateMarker()
    reference = weakref.ref(private)
    value = Outcome(private, "probe_stalled") if field == "status" else Outcome("failed", private)
    harness = Harness(outcome=value)
    metadata = RuntimeError("retained-metadata-traceback")
    writer = Writer(metadata)
    with monkeypatch.context() as patch:
        install_writer(patch, writer)
        error = caught(harness, wire() if use_candidate else original_function(), tmp_path, patch)
    # The original caller legitimately retains result in its assertion frame.
    private = value = harness = None
    gc.collect()
    retained_by_original_frame = reference() is not None
    error.__traceback__ = None
    metadata.__context__ = None
    gc.collect()
    after_original_frame_release = reference() is not None
    # Keep the error object alive; the emitter must discard its auxiliary traceback.
    assert metadata.__traceback__ is None
    return retained_by_original_frame, after_original_frame_release


@pytest.mark.parametrize("field", ["status", "reason"])
def test_private_field_lifetime_matches_literal_original_baseline(tmp_path, monkeypatch, field):
    original = lifetime(False, field, tmp_path, monkeypatch)
    candidate = lifetime(True, field, tmp_path, monkeypatch)
    assert original == candidate == (True, False)


@pytest.mark.parametrize(
    "mutation",
    [
        "import-alias",
        "initial-assert",
        "tail-assert",
        "catch-widened",
        "bare-raise",
        "private-holder",
        "result-input",
        "status-unguarded",
        "wrong-class",
        "stop-callback",
        "wall-limit",
        "extra-observe",
    ],
)
def test_forbidden_mutations_are_rejected_before_extraction(mutation):
    tree = ast.parse(current_source())
    function = selected(tree)
    guard = function.body[-1]
    handler = guard.handlers[0]
    call = handler.body[0].body[0].value
    if mutation == "import-alias":
        added = next(
            node
            for node in tree.body
            if isinstance(node, ast.ImportFrom) and node.module == _IMPORT
        )
        added.names[0].asname = "hidden"
    elif mutation == "initial-assert":
        function.body[-2].test = ast.Constant(True)
    elif mutation == "tail-assert":
        guard.body[0].body[0].test = ast.Constant(True)
    elif mutation == "catch-widened":
        handler.type = ast.Name(id="BaseException", ctx=ast.Load())
    elif mutation == "bare-raise":
        handler.body[-1].exc = ast.Name(id="AssertionError", ctx=ast.Load())
    elif mutation == "private-holder":
        handler.body.insert(0, ast.parse("private_holder = result.reason").body[0])
    elif mutation == "result-input":
        call.keywords.append(ast.keyword(arg="result", value=ast.Name(id="result", ctx=ast.Load())))
    elif mutation == "status-unguarded":
        call.keywords[1].value = ast.parse("result.status", mode="eval").body
    elif mutation == "wrong-class":
        call.keywords[2].value.test.comparators[0].attr = "DifferentOutcome"
    elif mutation == "stop-callback":
        run = next(
            node
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "run"
        )
        next(kw for kw in run.keywords if kw.arg == "stop_requested").value.body = ast.Constant(
            True
        )
    elif mutation == "wall-limit":
        limits = next(
            node
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "ContinuousProcessLimits"
        )
        limits.keywords[0].value = ast.Constant(31)
    else:
        function.body.insert(-2, ast.parse("probe.observe(child_exited=False)").body[0])
    altered = ast.unparse(ast.fix_missing_locations(tree)).encode("utf-8")
    with pytest.raises(AssertionError):
        admitted_function(altered)
