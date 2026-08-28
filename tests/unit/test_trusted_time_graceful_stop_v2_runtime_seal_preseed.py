from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_RUNTIME_SEAL_MODULE = "packages.domain.trusted_time_graceful_stop_v2_runtime_seal"

_FAKE_RUNTIME_SEAL_PRESEED = r"""
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
"""


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
        + r"""
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
"""
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "preseed rejected; canonical lineage accepted"


def test_domain_first_preseed_is_replaced_before_semantics_bootstrap() -> None:
    completed = _run_isolated(
        _FAKE_RUNTIME_SEAL_PRESEED
        + r"""
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
"""
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "domain-first preseed replaced"


def test_post_bootstrap_module_and_registry_method_replacement_cannot_authorize_clone() -> None:
    completed = _run_isolated(
        r"""
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
"""
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "post-bootstrap replacements rejected"


def test_recursive_authority_extraction_cannot_seal_or_commit_ordinal_22_clone() -> None:
    completed = _run_isolated(
        r"""
import dataclasses
import gc
import runpy
from types import FunctionType, MappingProxyType, MethodType

import packages.domain.trusted_time_graceful_stop_v2 as domain
import packages.domain.trusted_time_graceful_stop_v2_docker as docker
import packages.domain.trusted_time_graceful_stop_v2_lifecycle_semantics as semantics
import packages.domain.trusted_time_graceful_stop_v2_runtime_seal as runtime_seal
import packages.domain.trusted_time_graceful_stop_v2_terminal as terminal

values = runpy.run_path(
    "tests/unit/test_trusted_time_graceful_stop_v2_outcome_recovery.py"
)
store = values["_SealedLineageArtifactStore"]()
repository, root, lineage = values["_complete_sealed_success_prefix"](store)
clone = object.__new__(type(lineage))
for field in dataclasses.fields(type(lineage)):
    object.__setattr__(clone, field.name, getattr(lineage, field.name))

lifecycle_endpoint_names = (
    "_install_lifecycle_v2_reauthentication_semantic_binding_issuance_consumer",
    "_capture_lifecycle_v2_authenticated_reauthentication_binding_from_realm",
    "_build_injected_fake_lifecycle_v2_cleanup_observer",
    "_require_exact_cleanup_observer_runtime",
    "_require_canonical_evidence",
    "_require_exact_compound_value",
    "_consume_terminal_cleanup_unmount_authorization",
    "_consume_terminal_cleanup_native_owner_authorization",
    "_consume_terminal_cleanup_final_recovery_absence_authorization",
    "_consume_terminal_cleanup_final_socket_absence_authorization",
    "_consume_terminal_cleanup_final_credential_absence_authorization",
    "_finalize_exact_terminal_cleanup_authorization_runtime",
    "_require_exact_normal_progress_lineage_runtime",
    "require_exact_lifecycle_v2_normal_lineage_through_ordinal_5",
    "require_exact_lifecycle_v2_normal_lineage_through_ordinal_19",
    "consume_exact_lifecycle_v2_confirmed_success_lineage",
    "consume_exact_lifecycle_v2_confirmed_success_snapshot_for_repository",
)
roots = [(name, getattr(semantics, name)) for name in lifecycle_endpoint_names]
for value_type, method_name in (
    (semantics.LifecycleV2HostTransportCleanupIdentity, "capture"),
    (semantics.LifecycleV2TransportCleanupPlan, "from_retained_result"),
    (semantics.LifecycleV2SupervisorQuiescenceObservation, "capture"),
    (semantics.LifecycleV2HostTransportCleanupReceipt, "capture"),
    (semantics.LifecycleV2TransportQuiescence, "confirm"),
    (semantics.LifecycleV2ReauthenticationIntent, "_capture_fixed"),
    (semantics.LifecycleV2AuthenticatedReauthenticationBinding, "_capture_fake_for_tests"),
    (semantics.LifecycleV2EmptySecretMountIdentity, "capture"),
    (semantics.LifecycleV2EmptySecretMountProjection, "from_mounts"),
    (semantics.LifecycleV2PathAbsence, "_fixed"),
    (semantics.LifecycleV2NativeOwnerSet, "capture"),
    (semantics.LifecycleV2SecretMountUnmountReceipt, "completed"),
    (semantics.LifecycleV2NativeOwnerCleanupReceipt, "completed"),
    (terminal.LifecycleV2WirePublicationReceipt, "capture"),
    (terminal.LifecycleV2TerminalWireEvidence, "capture"),
    (docker.DockerMutationResultSemantic, "capture"),
    (docker.DockerVolumePreservationResult, "capture"),
):
    roots.append((f"{value_type.__name__}.{method_name}", getattr(value_type, method_name)))
for method_name in (
    "from_retained_result",
    "retain_transport_cleanup_commitment",
    "confirm_transport_channel_quiesced",
    "retain_pre_effect_reauthentication_intent",
    "retain_pre_effect_reauthentication_binding",
    "retain_supervisor_container_stop_intent",
    "retain_supervisor_container_stop_result",
    "retain_source_container_stop_intent",
    "retain_source_container_stop_result",
    "retain_supervisor_container_remove_intent",
    "retain_supervisor_container_remove_result",
    "retain_source_container_remove_intent",
    "retain_source_container_remove_result",
    "retain_project_network_remove_intent",
    "retain_project_network_remove_result",
    "retain_named_volume_preservation_intent",
    "retain_named_volumes_preserved",
    "retain_post_teardown_reauthentication_intent",
    "retain_post_teardown_reauthentication_binding",
    "retain_terminal_cleanup_intent",
    "retain_terminal_cleanup_confirmed",
):
    roots.append(
        (
            f"LifecycleV2NormalProgressLineage.{method_name}",
            getattr(semantics.LifecycleV2NormalProgressLineage, method_name),
        )
    )
roots.extend(
    (
        ("fake_transport_issue", domain._authenticate_lifecycle_v2_transport_envelope_for_tests),
        (
            "fake_transport_require",
            domain._require_fake_authenticated_lifecycle_v2_transport_envelope,
        ),
    )
)

target_modules = {
    domain.__name__,
    docker.__name__,
    semantics.__name__,
    terminal.__name__,
}
registry_type = runtime_seal.LifecycleV2RuntimeSealRegistry
seen = set()
mutable_state = []
registries = {}
functions_by_name = {}

def walk(path, value):
    identity = id(value)
    if identity in seen:
        return
    seen.add(identity)
    if type(value) is registry_type:
        registries[identity] = value
        return
    if type(value) is MethodType:
        if type(value.__self__) is registry_type:
            registries[id(value.__self__)] = value.__self__
            return
        walk(path + ".__func__", value.__func__)
        return
    if type(value) is FunctionType:
        if value.__module__ not in target_modules:
            return
        functions_by_name.setdefault(value.__name__, []).append(value)
        for index, item in enumerate(value.__defaults__ or ()):
            walk(f"{path}.__defaults__[{index}]", item)
        for name, item in (value.__kwdefaults__ or {}).items():
            walk(f"{path}.__kwdefaults__[{name!r}]", item)
        for name, cell in zip(
            value.__code__.co_freevars,
            value.__closure__ or (),
            strict=True,
        ):
            if name.startswith("original_"):
                continue
            try:
                item = cell.cell_contents
            except ValueError:
                continue
            walk(f"{path}.{name}", item)
        return
    if type(value) in {dict, list, set}:
        mutable_state.append((path, type(value).__name__))
        return
    if type(value) in {tuple, frozenset}:
        for index, item in enumerate(value):
            walk(f"{path}[{index}]", item)
        return
    if type(value) is MappingProxyType:
        for key, item in value.items():
            walk(f"{path}[{key!r}]", item)

for path, endpoint in roots:
    walk(path, endpoint)

assert not mutable_state, mutable_state
assert registries

def registry_entry(registry, value):
    return next(
        entry
        for entry_key, entry in registry._entries
        if entry_key == id(value)
    )

for registry in registries.values():
    assert type(registry._entries) is tuple
    assert all(
        type(referent) is not dict
        for referent in gc.get_referents(registry._entries)
    )
    for policy_name in (
        "_seal_callers",
        "_transition_callers",
        "_consume_action_callers",
        "_finalize_actions_callers",
        "_consume_callers",
        "_transfer_callers",
    ):
        assert type(getattr(registry, policy_name)) is frozenset
    try:
        registry._seal_callers = frozenset()
    except AttributeError:
        pass
    else:
        raise AssertionError("registry caller policy accepted ordinary replacement")
    try:
        del registry._configuration_locked
    except AttributeError:
        pass
    else:
        raise AssertionError("registry configuration lock accepted ordinary deletion")
    try:
        registry.__init__(_register_at_fork=None)
    except RuntimeError:
        pass
    else:
        raise AssertionError("registry accepted ordinary reinitialization")

lifecycle_registry = next(
    registry
    for registry in registries.values()
    if any(entry_key == id(lineage) for entry_key, _entry in registry._entries)
)
lineage_entry = registry_entry(lifecycle_registry, lineage)
lineage_metadata = lineage_entry.metadata
lineage_digest = semantics._lineage_snapshot(lineage)
try:
    lifecycle_registry._entries += ((id(clone), lineage_entry),)
except AttributeError:
    pass
else:
    raise AssertionError("registry entry snapshot accepted ordinary mutation")
try:
    lineage_metadata.__init__(
        "forged",
        root.sha256,
        lineage_metadata.origin_pid,
        lineage_metadata.origin_thread,
        lineage_metadata.fork_epoch,
    )
except TypeError:
    pass
assert lineage_metadata is lineage_entry.metadata
assert lineage_metadata.provenance == "authenticated_injected_lineage"
try:
    lineage_entry.__init__(
        clone,
        lineage_digest,
        "normal_progress_lineage",
        lineage_metadata,
        False,
        frozenset(),
    )
except TypeError:
    pass
assert lineage_entry.value is lineage
assert lineage_entry.snapshot_sha256 == lineage_digest

assert lifecycle_registry.seal(
    clone,
    snapshot_sha256=lineage_digest,
    kind="normal_progress_lineage",
    provenance=lineage_metadata.provenance,
    scope_sha256=lineage_metadata.scope_sha256,
) is False
assert lifecycle_registry.transition(
    lineage,
    source_snapshot_sha256=lineage_digest,
    result=clone,
    result_snapshot_sha256=lineage_digest,
    kind="normal_progress_lineage",
    provenance=lineage_metadata.provenance,
    scope_sha256=lineage_metadata.scope_sha256,
) is False
assert lifecycle_registry.consume_action(
    lineage,
    snapshot_sha256=lineage_digest,
    kind="normal_progress_lineage",
    action="repository_confirmed_success",
) is None
assert lifecycle_registry.consume_action_and_transfer(
    lineage,
    source_snapshot_sha256=lineage_digest,
    source_kind="normal_progress_lineage",
    action="repository_confirmed_success",
    result=clone,
    result_snapshot_sha256=lineage_digest,
    result_kind="confirmed_success_snapshot",
) is None
assert lifecycle_registry.finalize_actions(
    lineage,
    snapshot_sha256=lineage_digest,
    kind="normal_progress_lineage",
    required_actions=lineage_entry.actions,
) is None
assert lifecycle_registry.consume(
    lineage,
    snapshot_sha256=lineage_digest,
    kind="normal_progress_lineage",
) is None

cleanup_result = lineage.semantics[-1]
cleanup_clone = object.__new__(type(cleanup_result))
for field in dataclasses.fields(type(cleanup_result)):
    object.__setattr__(cleanup_clone, field.name, getattr(cleanup_result, field.name))
register_compound = functions_by_name["register_compound"][0]
try:
    register_compound(
        cleanup_clone,
        provenance=lineage_metadata.provenance,
        scope_sha256=lineage_metadata.scope_sha256,
    )
except semantics.TrustedTimeLifecycleV2SemanticsRejected as error:
    assert "escaped its exact construction topology" in str(error)
else:
    raise AssertionError("extracted generic registration helper sealed a clone")

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
    raise AssertionError("extracted runtime authority committed a cloned lineage")

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
print("recursive authority extraction rejected; authentic lineage accepted")
"""
    )

    assert completed.returncode == 0, completed.stderr
    assert (
        completed.stdout.strip()
        == "recursive authority extraction rejected; authentic lineage accepted"
    )


def test_direct_action_helpers_cannot_finalize_without_semantic_call_chain() -> None:
    completed = _run_isolated(
        r"""
from types import MethodType

import packages.domain.trusted_time_graceful_stop_v2_lifecycle_semantics as semantics
import packages.domain.trusted_time_graceful_stop_v2_runtime_seal as runtime_seal
from tests.unit import test_trusted_time_graceful_stop_v2_lifecycle_semantics as fixtures

def registry_entry(registry, value):
    return next(
        entry
        for entry_key, entry in registry._entries
        if entry_key == id(value)
    )

scenario = fixtures._scenario()
lineage, mounts, owners = fixtures._through_twenty_one(scenario)
authorization = lineage.terminal_cleanup_authorization
assert authorization is not None
snapshot = authorization._snapshot()

finalize_endpoint = semantics._finalize_exact_terminal_cleanup_authorization_runtime
registry = next(
    cell.cell_contents.__self__
    for cell in finalize_endpoint.__closure__ or ()
    if type(cell.cell_contents) is MethodType
    and type(cell.cell_contents.__self__)
    is runtime_seal.LifecycleV2RuntimeSealRegistry
)
entry_before = registry_entry(registry, authorization)
assert entry_before.actions == frozenset()
assert entry_before.consumed is False

published_action_endpoints = (
    semantics._consume_terminal_cleanup_unmount_authorization,
    semantics._consume_terminal_cleanup_native_owner_authorization,
    semantics._consume_terminal_cleanup_final_recovery_absence_authorization,
    semantics._consume_terminal_cleanup_final_socket_absence_authorization,
    semantics._consume_terminal_cleanup_final_credential_absence_authorization,
)
for endpoint in published_action_endpoints:
    try:
        endpoint(authorization, snapshot)
    except semantics.TrustedTimeLifecycleV2SemanticsRejected as error:
        assert "escaped its exact semantic call chain" in str(error)
    else:
        raise AssertionError("published action endpoint accepted a direct call")
    assert registry_entry(registry, authorization) is entry_before

try:
    finalize_endpoint(authorization, snapshot)
except semantics.TrustedTimeLifecycleV2SemanticsRejected as error:
    assert "escaped its exact semantic call chain" in str(error)
else:
    raise AssertionError("published finalizer accepted a direct call")
assert registry_entry(registry, authorization) is entry_before

def closure_value(endpoint, name):
    return next(
        cell.cell_contents
        for freevar, cell in zip(
            endpoint.__code__.co_freevars,
            endpoint.__closure__ or (),
            strict=True,
        )
        if freevar == name
    )

capture_unmount = semantics.LifecycleV2SecretMountUnmountReceipt.completed.__func__
capture_owner = semantics.LifecycleV2NativeOwnerCleanupReceipt.completed.__func__
capture_path = semantics.LifecycleV2PathAbsence._fixed.__func__
original_unmount = closure_value(capture_unmount, "original_unmount_receipt")
original_owner = closure_value(capture_owner, "original_owner_receipt")
original_path = closure_value(capture_path, "original_path_absence")
empty = semantics.LifecycleV2EmptySecretMountProjection.from_mounts(
    root=scenario.root,
    mounts=mounts,
)

for operation in (
    lambda: original_unmount(
        root=scenario.root,
        projection=empty,
        authorization=authorization,
        completed_boottime_ns=(1_100_300, 1_100_400, 1_100_500),
    ),
    lambda: original_owner(
        root=scenario.root,
        owners=owners,
        authorization=authorization,
        completed_boottime_ns=1_100_600,
    ),
    lambda: original_path(
        root=scenario.root,
        observer=scenario.cleanup_observer,
        kind="recovery_secret_mount",
        authorization=authorization,
        observed_boottime_ns=1_100_700,
    ),
    lambda: original_path(
        root=scenario.root,
        observer=scenario.cleanup_observer,
        kind="transport_socket",
        authorization=authorization,
        observed_boottime_ns=1_100_701,
    ),
    lambda: original_path(
        root=scenario.root,
        observer=scenario.cleanup_observer,
        kind="credential_paths",
        authorization=authorization,
        observed_boottime_ns=1_100_702,
    ),
    lambda: semantics._finalize_terminal_cleanup_authorization(authorization),
):
    try:
        operation()
    except semantics.TrustedTimeLifecycleV2SemanticsRejected as error:
        assert "escaped its exact semantic call chain" in str(error)
    else:
        raise AssertionError("extracted original helper escaped its semantic wrapper")
    assert registry_entry(registry, authorization) is entry_before

unmount = semantics.LifecycleV2SecretMountUnmountReceipt.completed(
    root=scenario.root,
    projection=empty,
    authorization=authorization,
    completed_boottime_ns=(1_100_300, 1_100_400, 1_100_500),
)
owner_receipt = semantics.LifecycleV2NativeOwnerCleanupReceipt.completed(
    root=scenario.root,
    owners=owners,
    authorization=authorization,
    completed_boottime_ns=1_100_600,
)
final_recovery = semantics.LifecycleV2PathAbsence.recovery_secret_mount(
    root=scenario.root,
    observer=scenario.cleanup_observer,
    authorization=authorization,
    observed_boottime_ns=1_100_700,
)
final_socket = semantics.LifecycleV2PathAbsence.transport_socket(
    root=scenario.root,
    observer=scenario.cleanup_observer,
    authorization=authorization,
    observed_boottime_ns=1_100_701,
)
final_credentials = semantics.LifecycleV2PathAbsence.credential_paths(
    root=scenario.root,
    observer=scenario.cleanup_observer,
    authorization=authorization,
    observed_boottime_ns=1_100_702,
)
completed_lineage = lineage.retain_terminal_cleanup_confirmed(
    empty_mount_projection=empty,
    unmount_receipt=unmount,
    native_owner_cleanup_receipt=owner_receipt,
    recovery_secret_mount_absence=final_recovery,
    socket_absence=final_socket,
    credential_path_absence=final_credentials,
    recorded_at_utc=fixtures.UTC_TEXT,
)
assert completed_lineage.last_record.ordinal == 22
final_entry = registry_entry(registry, authorization)
assert final_entry.actions == semantics._TERMINAL_CLEANUP_AUTHORIZATION_ACTIONS
assert final_entry.consumed is True
print("direct action/finalizer calls rejected; authentic semantic chain accepted")
"""
    )

    assert completed.returncode == 0, completed.stderr
    assert (
        completed.stdout.strip()
        == "direct action/finalizer calls rejected; authentic semantic chain accepted"
    )


def test_runtime_seal_source_corruption_fails_closed_and_cannot_retry(
    tmp_path: Path,
) -> None:
    isolated_root = tmp_path / "checkout"
    shutil.copytree(_ROOT / "packages", isolated_root / "packages")
    runtime_source = (
        isolated_root / "packages" / "domain" / "trusted_time_graceful_stop_v2_runtime_seal.py"
    )
    runtime_source.write_bytes(runtime_source.read_bytes() + b"\n# corrupted\n")
    completed = _run_isolated(
        r"""
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
""",
        pythonpath=isolated_root,
        cwd=isolated_root,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "corruption and retry rejected"


def test_preseeded_loading_state_fails_closed_without_running_fake_registry() -> None:
    completed = _run_isolated(
        _FAKE_RUNTIME_SEAL_PRESEED
        + r"""
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
"""
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "reentrant state rejected"
