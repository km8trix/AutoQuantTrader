"""Admitted worker-test wiring with inert ports, never real worker/SQL imports.

The embedded published baseline and candidate are compared in this interpreter.
Only the admitted FunctionDef executes, with an explicit fake-global allowlist
and newly owned temporary JSON files. Receipt contents here are synthetic; these
tests qualify wiring and unchanged assertions, not signed or financial history.
"""

import ast
import copy
import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.fixtures import lifecycle_failure_output as output
from tests.fixtures.lifecycle_forwarding_diagnostic import ObservedLifecycle

ORIGINAL_SHA256 = "895eb683e1d5f7311478d68f7f9b5545e9d4537c36e1e06d0bc95da67a2e8164"
ORIGINAL_SOURCE = (
    '"""Fixed supervised child restores real halted signed history from SQLite.\n'
    "\n"
    "The parent observes the actual child lease/control lifecycle through read-only\n"
    "SQLite probes. Canonical history and integrity remain the child's responsibility.\n"
    '"""\n'
    "\n"
    "import json\n"
    "from pathlib import Path\n"
    "\n"
    "from apps.trader.continuous_process_lifecycle import SqlContinuousParentProbe\n"
    "from packages.application import continuous_process as process_module\n"
    "from packages.application.continuous_process import ContinuousProcessSupervisor\n"
    "from packages.application.personal_runtime import LocalInstanceGuard\n"
    "from tests.fixtures.continuous_process_observation import ChildObservationDiagnostic\n"
    "from tests.integration import test_continuous_simulation_factory as factory_fixture\n"
    "\n"
    "configured = factory_fixture.configured\n"
    "\n"
    "\n"
    "def test_fixed_worker_runs_real_halted_restore_and_restarts_"
    "with_identical_financial_history(\n"
    "    configured,\n"
    "    monkeypatch,\n"
    "):\n"
    "    fixture, config = configured\n"
    "    pair = fixture[0]\n"
    "    factory_fixture.install_initial_signed_assignment(fixture)\n"
    "    original = pair.account.restore(pair.base.scope)\n"
    "    counts = pair.counts()\n"
    "    factory_fixture.release(fixture)\n"
    "    request = factory_fixture.request_for(fixture, config)\n"
    '    private = Path(config.database_path).parent / "supervised"\n'
    "    private.mkdir(mode=0o700)\n"
    "    supervisor = ContinuousProcessSupervisor(artifact_directory=private)\n"
    '    with LocalInstanceGuard(private / "instance.lock") as lock:\n'
    "        results = []\n"
    "        for iteration in range(1, 3):\n"
    "            diagnostic = ChildObservationDiagnostic(\n"
    "                process_module._observe_child,\n"
    "                deadline_code=process_module._observe_linux_child.__code__,\n"
    "            )\n"
    "            with monkeypatch.context() as observation_patch:\n"
    "                observation_patch.setattr(process_module, "
    '"_observe_child", diagnostic.observe)\n'
    "                outcome = supervisor.run(\n"
    "                    request,\n"
    "                    lock_descriptor=lock.fileno(),\n"
    "                    stop_requested=lambda: False,\n"
    "                    lifecycle=SqlContinuousParentProbe(request),\n"
    "                )\n"
    "            try:\n"
    '                assert outcome.status == "completed", outcome.reason\n'
    "            except AssertionError:\n"
    "                # The original supervisor and its finally cleanup have returned;\n"
    "                # only bounded static metadata is added to a failed assertion.\n"
    "                print(\n"
    '                    "AQT_CHILD_OBSERVATION_DIAGNOSTIC "\n'
    "                    + json.dumps(diagnostic.summary(iteration=iteration), sort_keys=True)\n"
    "                )\n"
    "                raise\n"
    "            assert outcome.receipt is not None\n"
    "            payload = outcome.receipt.path.read_bytes()\n"
    "            assert len(payload) == outcome.receipt.byte_count\n"
    "            results.append(json.loads(payload))\n"
    "    assert results[0] == results[1]\n"
    '    assert results[0]["checkpoint_sha256"] == original.checkpoint.semantic_sha256\n'
    '    assert results[0]["commit_sha256"] == original.receipt.commit.semantic_sha256\n'
    '    assert results[0]["status"] == "restored"\n'
    "    assert pair.counts() == counts\n"
)
_FUNCTION = (
    "test_fixed_worker_runs_real_halted_restore_and_restarts_with_identical_financial_history"
)
_IMPORT = "tests.fixtures.lifecycle_failure_output"
_NEW_NAMES = ("create_parent_diagnostics", "emit_parent_failure_line", "wrap_already_constructed")


def dump(value):
    return ast.dump(value, include_attributes=False)


def expression(text):
    return ast.parse(text, mode="eval").body


def current_source():
    return (
        Path(__file__).resolve().parents[1] / "integration" / "test_continuous_simulation_worker.py"
    ).read_bytes()


def admitted_function(source):
    assert type(source) is bytes and len(source) <= 8192
    assert len(ORIGINAL_SOURCE.encode("utf-8")) == 3088
    assert hashlib.sha256(ORIGINAL_SOURCE.encode("utf-8")).hexdigest() == ORIGINAL_SHA256
    original = ast.parse(ORIGINAL_SOURCE)
    candidate = ast.parse(source)
    imports = [
        node
        for node in candidate.body
        if isinstance(node, ast.ImportFrom) and node.module == _IMPORT
    ]
    assert len(imports) == 1
    selected_import = imports[0]
    assert selected_import.level == 0
    assert tuple((name.name, name.asname) for name in selected_import.names) == tuple(
        (name, None) for name in _NEW_NAMES
    )
    candidate.body.remove(selected_import)
    clocks = [
        node
        for node in candidate.body
        if isinstance(node, ast.ImportFrom) and node.module == "time"
    ]
    assert len(clocks) == 1
    clock_import = clocks[0]
    assert clock_import.level == 0
    assert tuple((name.name, name.asname) for name in clock_import.names) == (
        ("thread_time_ns", None),
    )
    candidate.body.remove(clock_import)
    functions = [
        node
        for node in candidate.body
        if isinstance(node, ast.FunctionDef) and node.name == _FUNCTION
    ]
    assert len(functions) == 1
    function = functions[0]
    executable = copy.deepcopy(function)
    diagnostics = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "ChildObservationDiagnostic"
    ]
    assert len(diagnostics) == 1
    cpu_keywords = [
        keyword for keyword in diagnostics[0].keywords if keyword.arg == "thread_clock_ns"
    ]
    assert len(cpu_keywords) == 1
    assert dump(cpu_keywords[0].value) == dump(expression("thread_time_ns"))
    diagnostics[0].keywords.remove(cpu_keywords[0])
    guards = [node for node in function.body if isinstance(node, ast.With)]
    assert len(guards) == 1
    guard = guards[0]
    assert len(guard.body) == 3
    assert dump(guard.body[0]) == dump(ast.parse("results = []").body[0])
    assert dump(guard.body[1]) == dump(
        ast.parse("parent_diagnostics = create_parent_diagnostics()").body[0]
    )
    del guard.body[1]
    lifecycles = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.keyword) and node.arg == "lifecycle"
    ]
    assert len(lifecycles) == 1
    keyword = lifecycles[0]
    expected = expression(
        "wrap_already_constructed(SqlContinuousParentProbe(request), "
        "diagnostics=parent_diagnostics, iteration=iteration)"
    )
    assert dump(keyword.value) == dump(expected)
    keyword.value = keyword.value.args[0]
    handlers = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.ExceptHandler)
        and dump(node.type) == dump(expression("AssertionError"))
    ]
    assert len(handlers) == 1 and len(handlers[0].body) == 3
    handler = handlers[0]
    expected_guard = ast.parse(
        "try:\n"
        "    emit_parent_failure_line(parent_diagnostics, iteration=iteration)\n"
        "except BaseException:\n"
        "    pass\n"
    ).body[0]
    assert dump(handler.body[1]) == dump(expected_guard)
    del handler.body[1]
    # The whole module must now equal the baseline, including all imports, every
    # assertion, constructor order, loop, patch context and cleanup.
    assert dump(candidate) == dump(original)
    assert sum(isinstance(node, ast.Assert) for node in ast.walk(function)) == 8
    return executable


def nodes(tree, kind):
    return [node for node in ast.walk(tree) if isinstance(node, kind)]


@pytest.mark.parametrize(
    "change",
    [
        "extra_import",
        "duplicate_import",
        "missing_import_name",
        "aliased_import",
        "missing_clock_import",
        "duplicate_clock_import",
        "aliased_clock_import",
        "missing_clock_keyword",
        "duplicate_clock_keyword",
        "foreign_clock",
        "called_clock",
        "manager_arguments",
        "manager_outside_guard",
        "wrapper_arguments",
        "constructor_hoisted",
        "emitter_before_child",
        "unguarded_emitter",
        "wrong_emitter_handler",
        "replacement_raise",
        "financial_assertion",
        "extra_iteration",
        "lock_path",
    ],
)
def test_admission_rejects_changed_behavior_before_any_function_execution(change):
    tree = ast.parse(current_source())
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef))
    guard = next(node for node in function.body if isinstance(node, ast.With))
    lifecycle = next(node for node in nodes(function, ast.keyword) if node.arg == "lifecycle")
    handler = next(
        node
        for node in nodes(function, ast.ExceptHandler)
        if isinstance(node.type, ast.Name) and node.type.id == "AssertionError"
    )
    import_node = next(
        node for node in tree.body if isinstance(node, ast.ImportFrom) and node.module == _IMPORT
    )
    clock_import = next(
        node for node in tree.body if isinstance(node, ast.ImportFrom) and node.module == "time"
    )
    diagnostic = next(
        node
        for node in nodes(function, ast.Call)
        if isinstance(node.func, ast.Name) and node.func.id == "ChildObservationDiagnostic"
    )
    clock_keyword = next(
        keyword for keyword in diagnostic.keywords if keyword.arg == "thread_clock_ns"
    )
    if change == "extra_import":
        tree.body.insert(1, ast.parse("import os").body[0])
    elif change == "duplicate_import":
        tree.body.append(copy.deepcopy(import_node))
    elif change == "missing_import_name":
        import_node.names.pop()
    elif change == "aliased_import":
        import_node.names[0].asname = "other_factory"
    elif change == "missing_clock_import":
        tree.body.remove(clock_import)
    elif change == "duplicate_clock_import":
        tree.body.append(copy.deepcopy(clock_import))
    elif change == "aliased_clock_import":
        clock_import.names[0].asname = "other_clock"
    elif change == "missing_clock_keyword":
        diagnostic.keywords.remove(clock_keyword)
    elif change == "duplicate_clock_keyword":
        diagnostic.keywords.append(copy.deepcopy(clock_keyword))
    elif change == "foreign_clock":
        clock_keyword.value = ast.Name(id="foreign_clock", ctx=ast.Load())
    elif change == "called_clock":
        clock_keyword.value = expression("thread_time_ns()")
    elif change == "manager_arguments":
        guard.body[1].value.args.append(ast.Constant(value=None))
    elif change == "manager_outside_guard":
        function.body.insert(function.body.index(guard), guard.body.pop(1))
    elif change == "wrapper_arguments":
        lifecycle.value.keywords.append(ast.keyword(arg="extra", value=ast.Constant(value=True)))
    elif change == "constructor_hoisted":
        function.body.insert(0, ast.parse("delegate = SqlContinuousParentProbe(request)").body[0])
        lifecycle.value.args[0] = ast.Name(id="delegate", ctx=ast.Load())
    elif change == "emitter_before_child":
        handler.body[0], handler.body[1] = handler.body[1], handler.body[0]
    elif change == "unguarded_emitter":
        handler.body[1] = handler.body[1].body[0]
    elif change == "wrong_emitter_handler":
        handler.body[1].handlers[0].type = ast.Name(id="Exception", ctx=ast.Load())
    elif change == "replacement_raise":
        handler.body[-1] = ast.parse("raise AssertionError('replacement')").body[0]
    elif change == "financial_assertion":
        nodes(function, ast.Assert)[-1].test = ast.Constant(value=True)
    elif change == "extra_iteration":
        nodes(function, ast.For)[0].iter.args[-1] = ast.Constant(value=4)
    else:
        context = guard.items[0].context_expr.args[0]
        context.right = ast.Constant(value="other.lock")
    with pytest.raises(AssertionError):
        admitted_function(ast.unparse(ast.fix_missing_locations(tree)).encode("utf-8"))


class Harness:
    def __init__(
        self,
        tmp_path,
        *,
        statuses=("completed", "completed"),
        fault=None,
        kind=RuntimeError,
        iteration=1,
    ):
        self.tmp_path = tmp_path
        self.statuses, self.fault, self.kind, self.iteration = statuses, fault, kind, iteration
        self.events, self.lines, self.probes, self.wraps, self.runs, self.diagnostics = (
            [],
            [],
            [],
            [],
            [],
            [],
        )
        self.scope, self.request, self.startup = object(), object(), object()
        self.thread_clock = object()
        self.counts = ("synthetic", 2)
        self.pending = self.manager = None
        self.error = kind("inert selected failure")
        self.cause, self.context = LookupError("original cause"), IndexError("original context")
        self.error.__cause__, self.error.__context__ = self.cause, self.context
        self.error.__suppress_context__ = False
        self.payload = {
            "checkpoint_sha256": "c" * 64,
            "commit_sha256": "d" * 64,
            "status": "restored",
        }
        self.receipts = []
        for number in (1, 2):
            value = dict(self.payload)
            if fault == "receipt_difference" and number == 2:
                value["status"] = "different"
            if fault in ("checkpoint", "commit", "restored_status"):
                key = {
                    "checkpoint": "checkpoint_sha256",
                    "commit": "commit_sha256",
                    "restored_status": "status",
                }[fault]
                value[key] = "wrong"
            raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
            if fault == "json_type":
                raw = b"null"
            elif fault == "json_syntax":
                raw = b"{"
            path = tmp_path / f"receipt-{number}.json"
            path.write_bytes(raw)
            self.receipts.append(SimpleNamespace(path=path, byte_count=len(raw)))
        if fault == "byte_count":
            self.receipts[0].byte_count += 1
        self.original = SimpleNamespace(
            checkpoint=SimpleNamespace(semantic_sha256=self.payload["checkpoint_sha256"]),
            receipt=SimpleNamespace(
                commit=SimpleNamespace(semantic_sha256=self.payload["commit_sha256"])
            ),
        )
        self.pair = SimpleNamespace(
            account=SimpleNamespace(restore=self.restore),
            base=SimpleNamespace(scope=self.scope),
            counts=self.read_counts,
        )
        self.fixture = (self.pair,)
        self.config = SimpleNamespace(database_path=str(tmp_path / "unused.sqlite"))

        def raw_observe(*args, **kwargs):
            self.events.append("child-observed")
            return "inert-child-state"

        def linux_reader():
            return None

        self.raw_observe, self.linux_reader = raw_observe, linux_reader
        self.process = SimpleNamespace(
            _observe_child=raw_observe, _observe_linux_child=linux_reader
        )
        self.lock_active = False

    def restore(self, scope):
        assert scope is self.scope
        self.events.append("restore")
        return self.original

    def read_counts(self):
        self.events.append("counts")
        return (
            ("changed", 2)
            if self.fault == "counts" and self.events.count("counts") == 2
            else self.counts
        )

    def assignment(self, fixture):
        assert fixture is self.fixture
        self.events.append("assignment")

    def release(self, fixture):
        assert fixture is self.fixture
        self.events.append("release")

    def request_for(self, fixture, config):
        assert fixture is self.fixture and config is self.config
        self.events.append("request")
        return self.request

    def guard(self, path):
        harness = self
        assert path == self.tmp_path / "supervised" / "instance.lock"

        class Guard:
            def __enter__(self):
                harness.events.append("lock-enter")
                harness.lock_active = True
                return self

            def fileno(self):
                assert harness.lock_active
                harness.events.append("fileno")
                return 91

            def __exit__(self, kind, value, tb):
                harness.events.append(("lock-exit", kind, value))
                harness.lock_active = False
                return False

        return Guard()

    def supervisor(self, *, artifact_directory):
        assert artifact_directory == self.tmp_path / "supervised"
        assert artifact_directory.is_dir()
        self.events.append("supervisor")
        return SimpleNamespace(run=self.run)

    def child_diagnostic(self, original, *, deadline_code, thread_clock_ns):
        assert original is self.raw_observe
        assert deadline_code is self.linux_reader.__code__
        assert thread_clock_ns is self.thread_clock
        self.events.append("child-diagnostic")
        diagnostic = SimpleNamespace(observe=lambda *args, **kwargs: original(*args, **kwargs))
        diagnostic.summary = lambda *, iteration: {"iteration": iteration, "inert": True}
        self.diagnostics.append(diagnostic)
        return diagnostic

    def probe(self, request):
        assert request is self.request and self.lock_active
        number = len(self.probes) + 1
        self.events.append(("probe", number))
        if self.fault == "constructor" and number == self.iteration:
            raise self.error
        probe = SimpleNamespace(
            prepare=lambda startup: self.events.append(("prepare", number, startup)),
            observe=lambda **kwargs: self.events.append(("observe", number, kwargs)),
            require_result=lambda payload: self.events.append(("require_result", number, payload)),
        )
        self.probes.append(probe)
        return probe

    def create(self):
        self.events.append("manager")
        self.manager = output.create_parent_diagnostics()
        return self.manager

    def wrap(self, delegate, *, diagnostics, iteration):
        assert delegate is self.probes[-1]
        assert diagnostics is self.manager
        self.events.append(("wrap", iteration))
        self.wraps.append((delegate, diagnostics, iteration))
        return output.wrap_already_constructed(
            delegate, diagnostics=diagnostics, iteration=iteration
        )

    def run(self, request, *, lock_descriptor, stop_requested, lifecycle):
        assert request is self.request and lock_descriptor == 91 and stop_requested() is False
        assert self.lock_active
        number = len(self.runs) + 1
        assert self.process._observe_child == self.diagnostics[-1].observe
        self.events.append(("run", number))
        self.runs.append((request, lock_descriptor, stop_requested, lifecycle))
        if self.fault == "supervisor" and number == self.iteration:
            raise self.error
        lifecycle.prepare(self.startup)
        lifecycle.observe(child_pid=None, child_exited=False)
        assert self.process._observe_child(None, child_exited=False) == "inert-child-state"
        if self.statuses[number - 1] == "completed":
            lifecycle.require_result(self.receipts[number - 1].path.read_bytes())
        receipt = (
            None if self.fault == "missing_receipt" and number == 1 else self.receipts[number - 1]
        )
        return SimpleNamespace(
            status=self.statuses[number - 1], reason="probe_stalled", receipt=receipt
        )

    def print_line(self, line):
        assert self.process._observe_child is self.raw_observe
        self.pending = sys.exception()
        assert type(self.pending) is AssertionError
        self.pending.__cause__, self.pending.__context__ = self.cause, self.context
        self.pending.__suppress_context__ = False
        self.events.append("child-print")
        if self.fault == "child_print":
            raise self.error
        self.lines.append(line + "\n")

    def emit(self, diagnostics, *, iteration):
        assert self.process._observe_child is self.raw_observe
        assert diagnostics is self.manager
        self.events.append(("parent-emit", iteration))
        if self.fault == "emitter":
            raise self.error
        output.emit_parent_failure_line(diagnostics, iteration=iteration)

    def execute(self, monkeypatch):
        function = admitted_function(current_source())
        namespace = {
            "__builtins__": {
                "AssertionError": AssertionError,
                "BaseException": BaseException,
                "range": range,
                "len": len,
                "print": self.print_line,
            },
            "json": json,
            "Path": Path,
            "factory_fixture": SimpleNamespace(
                install_initial_signed_assignment=self.assignment,
                release=self.release,
                request_for=self.request_for,
            ),
            "ContinuousProcessSupervisor": self.supervisor,
            "LocalInstanceGuard": self.guard,
            "ChildObservationDiagnostic": self.child_diagnostic,
            "thread_time_ns": self.thread_clock,
            "SqlContinuousParentProbe": self.probe,
            "process_module": self.process,
            "create_parent_diagnostics": self.create,
            "wrap_already_constructed": self.wrap,
            "emit_parent_failure_line": self.emit,
        }
        # No original module imports or top-level configured binding execute.
        compiled = compile(
            ast.Module(body=[function], type_ignores=[]), "<admitted-inert-worker-test>", "exec"
        )
        exec(compiled, namespace)
        with monkeypatch.context() as patch:
            patch.setattr(output.sys, "stdout", SimpleNamespace(write=self.lines.append))
            namespace[_FUNCTION]((self.fixture, self.config), monkeypatch)


def assert_cleanup(harness, expected_error=None):
    assert harness.process._observe_child is harness.raw_observe
    assert harness.lock_active is False
    assert harness.events[-1][0] == "lock-exit" or harness.events[-1] == "counts"
    exit_event = next(
        event
        for event in reversed(harness.events)
        if type(event) is tuple and event[0] == "lock-exit"
    )
    assert exit_event[2] is expected_error


def test_whole_module_admission_keeps_all_eight_original_assertions():
    function = admitted_function(current_source())
    assert sum(isinstance(node, ast.Assert) for node in ast.walk(function)) == 8


def test_normal_two_iterations_preserve_request_lock_stop_patch_binding_receipts_and_cleanup(
    tmp_path, monkeypatch
):
    harness = Harness(tmp_path)
    harness.execute(monkeypatch)
    assert harness.events[:6] == [
        "assignment",
        "restore",
        "counts",
        "release",
        "request",
        "supervisor",
    ]
    assert harness.events[6:8] == ["lock-enter", "manager"]
    assert (
        len(harness.probes)
        == len(harness.runs)
        == len(harness.wraps)
        == len(harness.diagnostics)
        == 2
    )
    assert all(type(run[3]) is ObservedLifecycle for run in harness.runs)
    assert [entry[2] for entry in harness.wraps] == [1, 2]
    assert harness.lines == [] and not any(
        type(event) is tuple and event[0] == "parent-emit" for event in harness.events
    )
    assert json.loads(harness.receipts[0].path.read_bytes()) == json.loads(
        harness.receipts[1].path.read_bytes()
    )
    for snapshot in (recorder.snapshot() for recorder in harness.manager._slots):
        assert snapshot["available"] is True
        assert all(
            row["returned"] == 1 and row["active"] == 0 for row in snapshot["stages"].values()
        )
    assert_cleanup(harness)


def test_failed_second_iteration_keeps_first_receipt_and_prints_child_before_parent(
    tmp_path, monkeypatch
):
    harness = Harness(tmp_path, statuses=("completed", "failed"))
    original_first = harness.receipts[0].path.read_bytes()
    with pytest.raises(AssertionError) as caught:
        harness.execute(monkeypatch)
    assert caught.value is harness.pending and caught.value.args == ("probe_stalled",)
    assert caught.value.__cause__ is harness.cause and caught.value.__context__ is harness.context
    assert caught.value.__suppress_context__ is False
    assert harness.receipts[0].path.read_bytes() == original_first
    assert len(harness.runs) == 2 and len(harness.lines) == 2
    assert harness.lines[0].startswith("AQT_CHILD_OBSERVATION_DIAGNOSTIC ")
    assert harness.lines[1].startswith(output.PREFIX)
    payload = json.loads(harness.lines[1][len(output.PREFIX) :])
    assert payload["current_iteration"] == 2
    assert payload["iterations"][0]["stages"]["require_result"]["returned"] == 1
    assert payload["iterations"][1]["stages"]["require_result"]["entered"] == 0
    assert harness.events.index("child-print") < harness.events.index(("parent-emit", 2))
    assert_cleanup(harness, caught.value)


@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt])
def test_unexpected_parent_emitter_error_is_guarded_and_original_assertion_reraised(
    tmp_path, monkeypatch, kind
):
    harness = Harness(tmp_path, statuses=("completed", "failed"), fault="emitter", kind=kind)
    with pytest.raises(AssertionError) as caught:
        harness.execute(monkeypatch)
    assert caught.value is harness.pending
    assert caught.value.__cause__ is harness.cause and caught.value.__context__ is harness.context
    assert caught.value.__suppress_context__ is False
    assert len(harness.lines) == 1 and harness.lines[0].startswith(
        "AQT_CHILD_OBSERVATION_DIAGNOSTIC "
    )
    assert harness.events.count(("parent-emit", 2)) == 1
    assert_cleanup(harness, caught.value)


@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt])
def test_original_child_print_failure_still_prevents_parent_emission(tmp_path, monkeypatch, kind):
    harness = Harness(tmp_path, statuses=("completed", "failed"), fault="child_print", kind=kind)
    with pytest.raises(kind) as caught:
        harness.execute(monkeypatch)
    assert caught.value is harness.error
    assert caught.value.__cause__ is harness.cause
    # Python's original print failure occurs while handling the status assertion.
    assert caught.value.__context__ is harness.pending
    assert harness.lines == []
    assert ("parent-emit", 2) not in harness.events
    assert_cleanup(harness, caught.value)


@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt])
@pytest.mark.parametrize("iteration", [1, 2])
def test_original_constructor_failure_is_not_wrapped_or_emitted_and_patch_lock_cleanup_remains(
    tmp_path, monkeypatch, kind, iteration
):
    harness = Harness(tmp_path, fault="constructor", kind=kind, iteration=iteration)
    with pytest.raises(kind) as caught:
        harness.execute(monkeypatch)
    assert caught.value is harness.error
    assert caught.value.__cause__ is harness.cause and caught.value.__context__ is harness.context
    assert caught.value.__suppress_context__ is False
    assert len(harness.wraps) == len(harness.runs) == iteration - 1
    assert harness.lines == [] and not any(
        type(event) is tuple and event[0] == "parent-emit" for event in harness.events
    )
    assert_cleanup(harness, caught.value)


@pytest.mark.parametrize("kind", [RuntimeError, KeyboardInterrupt])
def test_original_supervisor_error_preserves_identity_and_restores_patch_and_lock(
    tmp_path, monkeypatch, kind
):
    harness = Harness(tmp_path, fault="supervisor", kind=kind, iteration=2)
    with pytest.raises(kind) as caught:
        harness.execute(monkeypatch)
    assert caught.value is harness.error
    assert caught.value.__cause__ is harness.cause and caught.value.__context__ is harness.context
    assert caught.value.__suppress_context__ is False
    assert len(harness.runs) == 2 and harness.lines == []
    assert_cleanup(harness, caught.value)


@pytest.mark.parametrize(
    "fault",
    [
        "missing_receipt",
        "byte_count",
        "receipt_difference",
        "checkpoint",
        "commit",
        "restored_status",
        "counts",
    ],
)
def test_original_receipt_history_and_count_assertions_still_reject_after_completed_status(
    tmp_path, monkeypatch, fault
):
    harness = Harness(tmp_path, fault=fault)
    with pytest.raises(AssertionError) as caught:
        harness.execute(monkeypatch)
    assert harness.pending is None and harness.lines == []
    assert not any(type(event) is tuple and event[0] == "parent-emit" for event in harness.events)
    # Final outside-lock assertions fail after successful context exit; earlier
    # receipt assertions fail inside it. Neither gains new failure output.
    assert_cleanup(harness, caught.value if fault in ("missing_receipt", "byte_count") else None)


@pytest.mark.parametrize(
    "fault,kind", [("json_type", TypeError), ("json_syntax", json.JSONDecodeError)]
)
def test_original_payload_type_and_decode_errors_remain_visible_without_parent_output(
    tmp_path, monkeypatch, fault, kind
):
    harness = Harness(tmp_path, fault=fault)
    with pytest.raises(kind) as caught:
        harness.execute(monkeypatch)
    assert harness.lines == [] and harness.pending is None
    assert_cleanup(harness, caught.value if fault == "json_syntax" else None)


def test_safe_manager_creation_failure_still_uses_original_delegates_and_unknown_parent_output(
    tmp_path, monkeypatch
):
    harness = Harness(tmp_path, statuses=("completed", "failed"))

    def failed_manager():
        raise KeyboardInterrupt("new metadata constructor failure")

    with monkeypatch.context() as patch:
        patch.setattr(output, "ParentLifecycleDiagnostics", failed_manager)
        with pytest.raises(AssertionError) as caught:
            harness.execute(monkeypatch)
    assert harness.manager is None
    assert all(run[3] is harness.probes[index] for index, run in enumerate(harness.runs))
    payload = json.loads(harness.lines[1][len(output.PREFIX) :])
    assert payload["misused"] is None
    assert all(
        snapshot["available"] is False and snapshot["stages"] is None
        for snapshot in payload["iterations"]
    )
    assert caught.value is harness.pending
    assert_cleanup(harness, caught.value)
