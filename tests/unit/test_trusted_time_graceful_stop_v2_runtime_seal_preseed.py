from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_RUNTIME_SEAL_MODULE = "packages.domain.trusted_time_graceful_stop_v2_runtime_seal"

_FAKE_RUNTIME_SEAL_PRESEED = r'''
import importlib.machinery
import os
import sys
import threading
import types
from dataclasses import dataclass

runtime_name = "packages.domain.trusted_time_graceful_stop_v2_runtime_seal"
runtime_path = os.path.realpath(
    "packages/domain/trusted_time_graceful_stop_v2_runtime_seal.py"
)
fake_runtime = types.ModuleType(runtime_name)
fake_runtime.__file__ = runtime_path
fake_runtime.__package__ = "packages.domain"
fake_runtime.__spec__ = importlib.machinery.ModuleSpec(
    runtime_name,
    loader=None,
    origin=runtime_path,
)

@dataclass(frozen=True, slots=True)
class FakeRuntimeSealMetadata:
    provenance: str
    scope_sha256: str
    origin_pid: int
    origin_thread: threading.Thread
    fork_epoch: object

class PermissiveRuntimeSealRegistry:
    def __init__(self, **_kwargs):
        self.epoch = object()

    def metadata(self, value, kwargs):
        root = getattr(value, "root", None)
        return FakeRuntimeSealMetadata(
            kwargs.get("provenance") or "authenticated_injected_lineage",
            kwargs.get("scope_sha256") or getattr(root, "sha256", "0" * 64),
            os.getpid(),
            threading.current_thread(),
            self.epoch,
        )

    def seal(self, _value, **_kwargs):
        return True

    def require(self, value, **kwargs):
        return self.metadata(value, kwargs)

    def consume(self, value, **kwargs):
        return self.metadata(value, kwargs)

    def transition(self, _source, *, result, **_kwargs):
        return result is not None

    def consume_action(self, value, **kwargs):
        return self.metadata(value, kwargs)

    def finalize_actions(self, value, **kwargs):
        return self.metadata(value, kwargs)

fake_runtime.RuntimeSealMetadata = FakeRuntimeSealMetadata
fake_runtime.LifecycleV2RuntimeSealRegistry = PermissiveRuntimeSealRegistry
sys.modules[runtime_name] = fake_runtime
'''


def _run_isolated(
    source: str,
    *,
    pythonpath: Path = _ROOT,
    cwd: Path = _ROOT,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = os.fspath(pythonpath)
    return subprocess.run(
        [sys.executable, "-c", source],
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def test_real_path_spec_preseed_cannot_commit_cloned_success_lineage() -> None:
    completed = _run_isolated(
        _FAKE_RUNTIME_SEAL_PRESEED
        + r'''
import dataclasses
import runpy

values = runpy.run_path(
    "tests/unit/test_trusted_time_graceful_stop_v2_outcome_recovery.py"
)
canonical_runtime = sys.modules[runtime_name]
assert canonical_runtime is not fake_runtime
assert canonical_runtime.__file__ == runtime_path
assert "_claim_lifecycle_v2_runtime_seal_bootstrap" not in vars(canonical_runtime)

store = values["_SealedLineageArtifactStore"]()
repository, root, lineage = values["_complete_sealed_success_prefix"](store)
clone = object.__new__(type(lineage))
for field in dataclasses.fields(type(lineage)):
    object.__setattr__(clone, field.name, getattr(lineage, field.name))
assert clone is not lineage

try:
    repository.commit_confirmed_success(
        lineage=clone,
        clock=values["_Clock"](
            [
                root.operation_deadline_boottime_ns - 2,
                root.operation_deadline_boottime_ns - 1,
            ]
        ),
        precommit_disposer=values["_Disposer"](),
        created_at_utc=values["UTC_TEXT"],
    )
except values["persistence"].LifecycleV2RepositoryRejected as error:
    assert "sealed exact ordinal-22 lineage" in str(error)
else:
    raise AssertionError("preseeded runtime seal authorized an unissued lineage clone")

outcome, _commit = repository.commit_confirmed_success(
    lineage=lineage,
    clock=values["_Clock"](
        [
            root.operation_deadline_boottime_ns - 2,
            root.operation_deadline_boottime_ns - 1,
        ]
    ),
    precommit_disposer=values["_Disposer"](),
    created_at_utc=values["UTC_TEXT"],
)
assert outcome.status == "confirmed_success"
print("preseed rejected; canonical lineage accepted")
'''
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "preseed rejected; canonical lineage accepted"


def test_domain_first_preseed_is_replaced_before_semantics_bootstrap() -> None:
    completed = _run_isolated(
        _FAKE_RUNTIME_SEAL_PRESEED
        + r'''
import importlib

assert importlib.import_module(runtime_name) is fake_runtime
import packages.domain.trusted_time_graceful_stop_v2
semantics = importlib.import_module(
    "packages.domain.trusted_time_graceful_stop_v2_lifecycle_semantics"
)
canonical_runtime = sys.modules[runtime_name]
assert canonical_runtime is not fake_runtime
assert semantics.LifecycleV2RuntimeSealRegistry is (
    canonical_runtime.LifecycleV2RuntimeSealRegistry
)
assert "_load_canonical_lifecycle_v2_runtime_seal" not in vars(semantics)
print("domain-first preseed replaced")
'''
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "domain-first preseed replaced"


def test_post_bootstrap_module_and_registry_method_replacement_cannot_authorize_clone() -> None:
    completed = _run_isolated(
        r'''
import dataclasses
import os
import runpy
import sys
import threading
import types
from dataclasses import dataclass

values = runpy.run_path(
    "tests/unit/test_trusted_time_graceful_stop_v2_outcome_recovery.py"
)
runtime_name = "packages.domain.trusted_time_graceful_stop_v2_runtime_seal"
canonical_runtime = sys.modules[runtime_name]
registry_type = canonical_runtime.LifecycleV2RuntimeSealRegistry

@dataclass(frozen=True, slots=True)
class SyntheticMetadata:
    provenance: str = "authenticated_injected_lineage"
    scope_sha256: str = "0" * 64
    origin_pid: int = os.getpid()
    origin_thread: threading.Thread = threading.current_thread()
    fork_epoch: object = object()

synthetic = SyntheticMetadata()
canonical_runtime.RuntimeSealMetadata = SyntheticMetadata
canonical_runtime._RuntimeSealEntry = object
canonical_runtime.replace = lambda value, **_changes: value
registry_type._registry_is_current = lambda _self: True
registry_type._entry_is_current = lambda _self, _entry: True
registry_type.seal = lambda _self, _value, **_kwargs: True
registry_type.require = lambda _self, _value, **_kwargs: synthetic
registry_type.consume = lambda _self, _value, **_kwargs: synthetic
registry_type.transition = lambda _self, _source, **_kwargs: True
registry_type.consume_action = lambda _self, _value, **_kwargs: synthetic
registry_type.finalize_actions = lambda _self, _value, **_kwargs: synthetic
replacement = types.ModuleType(runtime_name)
replacement.LifecycleV2RuntimeSealRegistry = registry_type
replacement.RuntimeSealMetadata = SyntheticMetadata
sys.modules[runtime_name] = replacement

store = values["_SealedLineageArtifactStore"]()
repository, root, lineage = values["_complete_sealed_success_prefix"](store)
clone = object.__new__(type(lineage))
for field in dataclasses.fields(type(lineage)):
    object.__setattr__(clone, field.name, getattr(lineage, field.name))

try:
    repository.commit_confirmed_success(
        lineage=clone,
        clock=values["_Clock"](
            [
                root.operation_deadline_boottime_ns - 2,
                root.operation_deadline_boottime_ns - 1,
            ]
        ),
        precommit_disposer=values["_Disposer"](),
        created_at_utc=values["UTC_TEXT"],
    )
except values["persistence"].LifecycleV2RepositoryRejected as error:
    assert "sealed exact ordinal-22 lineage" in str(error)
else:
    raise AssertionError("class-method replacement authorized an unissued clone")

outcome, _commit = repository.commit_confirmed_success(
    lineage=lineage,
    clock=values["_Clock"](
        [
            root.operation_deadline_boottime_ns - 2,
            root.operation_deadline_boottime_ns - 1,
        ]
    ),
    precommit_disposer=values["_Disposer"](),
    created_at_utc=values["UTC_TEXT"],
)
assert outcome.status == "confirmed_success"
print("post-bootstrap replacements rejected")
'''
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "post-bootstrap replacements rejected"


def test_runtime_seal_source_corruption_fails_closed_and_cannot_retry(
    tmp_path: Path,
) -> None:
    isolated_root = tmp_path / "checkout"
    shutil.copytree(_ROOT / "packages", isolated_root / "packages")
    runtime_source = (
        isolated_root
        / "packages"
        / "domain"
        / "trusted_time_graceful_stop_v2_runtime_seal.py"
    )
    runtime_source.write_bytes(runtime_source.read_bytes() + b"\n# corrupted\n")
    completed = _run_isolated(
        r'''
import importlib
import sys

semantics_name = "packages.domain.trusted_time_graceful_stop_v2_lifecycle_semantics"
messages = []
for _attempt in range(2):
    sys.modules.pop(semantics_name, None)
    try:
        importlib.import_module(semantics_name)
    except ImportError as error:
        messages.append(str(error))
    else:
        raise AssertionError("corrupted runtime-seal source was imported")
assert "source digest is invalid" in messages[0]
assert "source digest is invalid" in messages[1]
print("corruption and retry rejected")
''',
        pythonpath=isolated_root,
        cwd=isolated_root,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "corruption and retry rejected"


def test_preseeded_loading_state_fails_closed_without_running_fake_registry() -> None:
    completed = _run_isolated(
        _FAKE_RUNTIME_SEAL_PRESEED
        + r'''
import importlib

fake_runtime._lifecycle_v2_runtime_seal_bootstrap_loading = object()
try:
    importlib.import_module(
        "packages.domain.trusted_time_graceful_stop_v2_lifecycle_semantics"
    )
except ImportError as error:
    assert "reentered or failed" in str(error)
else:
    raise AssertionError("reentrant runtime-seal bootstrap was accepted")
print("reentrant state rejected")
'''
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "reentrant state rejected"
