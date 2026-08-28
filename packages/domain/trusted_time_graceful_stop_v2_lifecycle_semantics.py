"""Exact normal-path lifecycle-v2 progress semantics for ADR 0121.

The values in this module are evidence-only.  They cannot open a transport,
call Docker, authenticate an ADR-0109 observation, publish an artifact, or
grant stop authority.  A sealed lineage exposes one named method per normal
ordinal so no caller can select a stage, ordinal, predecessor, or effect kind.
"""

from __future__ import annotations

import builtins
import hashlib
import importlib
import os
import re
import stat
import sys
from collections.abc import Callable
from dataclasses import dataclass
from types import CodeType, MappingProxyType, ModuleType
from typing import TYPE_CHECKING, Any, Never, Self, cast

if TYPE_CHECKING:
    from packages.domain.trusted_time_graceful_stop_v2_runtime_seal import (
        LifecycleV2RuntimeSealRegistry,
        RuntimeSealMetadata,
    )

_RUNTIME_SEAL_MODULE_NAME = "packages.domain.trusted_time_graceful_stop_v2_runtime_seal"
_RUNTIME_SEAL_SOURCE_NAME = "trusted_time_graceful_stop_v2_runtime_seal.py"
_RUNTIME_SEAL_SOURCE_SHA256 = "7d2e3b821ef596df44aa35c962e5c9819c0f4806dc21d2e44c53e2b23cd5d78c"
_RUNTIME_SEAL_BOOTSTRAP_CLAIM = "_claim_lifecycle_v2_runtime_seal_bootstrap"
_RUNTIME_SEAL_LOADING = "_lifecycle_v2_runtime_seal_bootstrap_loading"
_RUNTIME_SEAL_FAILED = "_lifecycle_v2_runtime_seal_bootstrap_failed"


def _load_canonical_lifecycle_v2_runtime_seal() -> tuple[type[object], type[object]]:
    """Load the exact seal source without trusting a preseeded module object."""

    module_name = _RUNTIME_SEAL_MODULE_NAME
    source_name = _RUNTIME_SEAL_SOURCE_NAME
    source_sha256 = _RUNTIME_SEAL_SOURCE_SHA256
    bootstrap_claim_name = _RUNTIME_SEAL_BOOTSTRAP_CLAIM
    loading_name = _RUNTIME_SEAL_LOADING
    failed_name = _RUNTIME_SEAL_FAILED
    modules = sys.modules
    current = modules.get(module_name)
    if type(current) is ModuleType and (
        current.__dict__.get(loading_name) is not None or current.__dict__.get(failed_name) is True
    ):
        raise ImportError("lifecycle-v2 runtime-seal bootstrap was reentered or failed")

    semantics_path = os.path.realpath(__file__)
    domain_directory = os.path.dirname(semantics_path)
    if (
        os.path.basename(semantics_path) != "trusted_time_graceful_stop_v2_lifecycle_semantics.py"
        or os.path.basename(domain_directory) != "domain"
        or os.path.basename(os.path.dirname(domain_directory)) != "packages"
    ):
        raise ImportError("lifecycle-v2 runtime-seal source topology is invalid")
    source_path = os.path.join(domain_directory, source_name)
    if os.path.realpath(source_path) != source_path:
        raise ImportError("lifecycle-v2 runtime-seal source path is not canonical")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source_path, flags)
    try:
        source_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(source_stat.st_mode)
            or source_stat.st_size <= 0
            or source_stat.st_size > 65_536
        ):
            raise ImportError("lifecycle-v2 runtime-seal source file is invalid")
        chunks: list[bytes] = []
        remaining = source_stat.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 16_384))
            if not chunk:
                raise ImportError("lifecycle-v2 runtime-seal source read was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ImportError("lifecycle-v2 runtime-seal source changed during read")
        source = b"".join(chunks)
    finally:
        os.close(descriptor)
    if hashlib.sha256(source).hexdigest() != source_sha256:
        raise ImportError("lifecycle-v2 runtime-seal source digest is invalid")

    code = builtins.compile(source, source_path, "exec", dont_inherit=True, optimize=0)
    if code.co_filename != source_path:
        raise ImportError("lifecycle-v2 runtime-seal code provenance is invalid")
    module = ModuleType(module_name)
    namespace = module.__dict__
    permit = object()
    receipt = object()
    claim_state = "available"
    claimed: tuple[type[object], type[object]] | None = None
    namespace.update(
        {
            "__builtins__": builtins.__dict__,
            "__file__": source_path,
            "__loader__": None,
            "__name__": module_name,
            "__package__": "packages.domain",
            "__spec__": importlib.machinery.ModuleSpec(
                module_name,
                loader=None,
                origin=source_path,
            ),
            loading_name: permit,
        }
    )
    modules[module_name] = module

    def claim_runtime_seal_exports(
        received_permit: object,
        metadata_type: type[object],
        registry_type: type[object],
    ) -> object:
        nonlocal claim_state, claimed
        if claim_state != "available":
            claim_state = "failed"
            claimed = None
            raise ImportError("lifecycle-v2 runtime-seal bootstrap claim was replayed")
        claim_state = "consumed"
        if (
            received_permit is not permit
            or type(metadata_type) is not type
            or metadata_type.__module__ != module_name
            or metadata_type.__qualname__ != "RuntimeSealMetadata"
            or vars(metadata_type).get("__slots__") != ()
            or vars(metadata_type).get("_fields")
            != (
                "provenance",
                "scope_sha256",
                "origin_pid",
                "origin_thread",
                "fork_epoch",
            )
            or type(registry_type) is not type
            or registry_type.__module__ != module_name
            or registry_type.__qualname__ != "LifecycleV2RuntimeSealRegistry"
            or vars(registry_type).get("__slots__")
            != (
                "_configuration_locked",
                "_consume_action_callers",
                "_consume_callers",
                "_current_thread",
                "_entries",
                "_finalize_actions_callers",
                "_fork_epoch",
                "_fork_invalidated",
                "_get_call_frame",
                "_getpid",
                "_lock",
                "_origin_fork_epoch",
                "_origin_pid",
                "_seal_callers",
                "_transfer_callers",
                "_transition_callers",
            )
        ):
            claim_state = "failed"
            raise ImportError("lifecycle-v2 runtime-seal bootstrap exports are invalid")
        forbidden_globals = frozenset(
            {
                "RuntimeSealMetadata",
                "MappingProxyType",
                "NamedTuple",
                "_RuntimeSealEntry",
                "_REGISTER_AT_FORK",
                "id",
                "os",
                "replace",
                "sys",
                "threading",
            }
        )
        for method_name in (
            "__delattr__",
            "__setattr__",
            "__init__",
            "_registry_is_current",
            "_entry_is_current",
            "seal",
            "require",
            "consume",
            "transition",
            "consume_action",
            "consume_action_and_transfer",
            "finalize_actions",
        ):
            method = vars(registry_type).get(method_name)
            if (
                type(method) is not type(claim_runtime_seal_exports)
                or method.__globals__ is not namespace
                or method.__code__.co_filename != source_path
                or forbidden_globals.intersection(method.__code__.co_names)
            ):
                claim_state = "failed"
                raise ImportError("lifecycle-v2 runtime-seal endpoint topology is invalid")
        claimed = (registry_type, metadata_type)
        return receipt

    parent = modules.get("packages.domain")
    try:
        builtins.exec(code, namespace, namespace)
        endpoint = namespace.pop(bootstrap_claim_name, None)
        exact_endpoint = cast(
            Callable[
                [
                    object,
                    Callable[[object, type[object], type[object]], object],
                ],
                object,
            ],
            endpoint,
        )
        if (
            type(endpoint) is not type(claim_runtime_seal_exports)
            or endpoint.__globals__ is not namespace
            or endpoint.__code__.co_filename != source_path
            or exact_endpoint(permit, claim_runtime_seal_exports) is not receipt
            or claim_state != "consumed"
            or claimed is None
            or namespace.get("__all__") != ["LifecycleV2RuntimeSealRegistry", "RuntimeSealMetadata"]
        ):
            raise ImportError("lifecycle-v2 runtime-seal bootstrap claim is invalid")
        namespace.pop(loading_name, None)
        if parent is not None:
            setattr(parent, source_name.removesuffix(".py"), module)
        return claimed
    except BaseException as error:
        claim_state = "failed"
        claimed = None
        namespace.pop(bootstrap_claim_name, None)
        namespace.pop(loading_name, None)
        namespace[failed_name] = True
        if parent is not None:
            setattr(parent, source_name.removesuffix(".py"), module)
        if isinstance(error, ImportError):
            raise
        raise ImportError("lifecycle-v2 runtime-seal bootstrap failed") from error


if not TYPE_CHECKING:
    (
        LifecycleV2RuntimeSealRegistry,
        RuntimeSealMetadata,
    ) = _load_canonical_lifecycle_v2_runtime_seal()
del _load_canonical_lifecycle_v2_runtime_seal

from packages.domain.trusted_time_graceful_stop_v2 import (  # noqa: E402
    LIFECYCLE_V2_OPERATION_BUDGET_NS,
    LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION,
    LIFECYCLE_V2_ROOT_CONTRACT_VERSION,
    MAXIMUM_SIGNED_INTEGER,
    NORMAL_STAGE_BY_ORDINAL,
    FrozenJsonObject,
    LifecycleV2ProgressRecord,
    LifecycleV2Root,
    LifecycleV2Stage,
    LifecycleV2Transcript,
    TrustedTimeGracefulStopV2Rejected,
    _capture_lifecycle_v2_reauthentication_binding_evidence,
    canonical_v2_json_bytes,
    decode_canonical_v2_json_object,
    decode_lifecycle_v2_progress_record,
    decode_lifecycle_v2_root,
    decode_lifecycle_v2_transcript,
)
from packages.domain.trusted_time_graceful_stop_v2_docker import (  # noqa: E402
    COMMAND_SOCKET_VOLUME,
    STATE_VOLUME,
    DockerAdmissionCapture,
    DockerAdmissionRootedTracePrefix,
    DockerMutationResultSemantic,
    DockerOrdinalEvidence,
    DockerPlanIdentity,
    DockerRequestSemantic,
    DockerVolumePreservationResult,
    docker_call_spec,
)
from packages.domain.trusted_time_graceful_stop_v2_terminal import (  # noqa: E402
    LISTENER_PATH,
    SUPERVISOR_RAW_KEY_PATH,
    LifecycleV2CleanStopResult,
    LifecycleV2SupervisorCleanupCommitment,
    LifecycleV2TerminalWireEvidence,
    decode_lifecycle_v2_clean_stop_result,
)

LIFECYCLE_V2_CLEANUP_SERVICE = "trusted-time-graceful-stop-lifecycle-v2"
HOST_RAW_KEY_PATH = "/run/autoquant/trusted-time/graceful-stop-v2/host-secrets/host-ed25519.raw"
HOST_SECRET_MOUNT_PATH = "/run/autoquant/trusted-time/graceful-stop-v2/host-secrets"
SUPERVISOR_SECRET_MOUNT_PATH = "/run/autoquant/trusted-time/graceful-stop-v2/supervisor-secrets"
RECOVERY_SECRET_MOUNT_PATH = "/run/autoquant/trusted-time/graceful-stop-v2/recovery-secrets"
TRANSPORT_MOUNT_PATH = "/run/autoquant/trusted-time/graceful-stop-v2/transport"

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")
_MAJOR_MINOR = re.compile(r"(?:0|[1-9][0-9]*):(?:0|[1-9][0-9]*)\Z")
_REAUTHENTICATION_REALM_MODULE = "packages.domain.trusted_time_graceful_stop_v2_reauthentication"


class TrustedTimeLifecycleV2SemanticsRejected(TrustedTimeGracefulStopV2Rejected):
    """A typed lifecycle transition is mixed, late, incomplete, or out of order."""


def _reject(message: str) -> Never:
    raise TrustedTimeLifecycleV2SemanticsRejected(message)


def _require_fields(value: dict[str, object], expected: frozenset[str], label: str) -> None:
    if frozenset(value) != expected:
        _reject(f"{label} field set is not exact")


def _require_text(value: object, name: str, *, maximum_bytes: int = 4_096) -> str:
    if (
        type(value) is not str
        or not value
        or not value.isascii()
        or len(value.encode("ascii")) > maximum_bytes
        or "\0" in value
    ):
        _reject(f"{name} is not bounded ASCII text")
    return value


def _require_path(value: object, name: str) -> str:
    path = _require_text(value, name)
    if not path.startswith("/") or "//" in path or "/./" in path or "/../" in path:
        _reject(f"{name} is not an exact absolute path")
    return path


def _require_sha256(value: object, name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _reject(f"{name} is not lowercase SHA-256")
    return value


def _require_int(
    value: object,
    name: str,
    *,
    minimum: int = 0,
    maximum: int = MAXIMUM_SIGNED_INTEGER,
) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        _reject(f"{name} is outside its integer bounds")
    return value


def _require_true(value: object, name: str) -> None:
    if value is not True:
        _reject(f"{name} must be true")


def _require_utc(value: object, name: str) -> str:
    if type(value) is not str or _UTC.fullmatch(value) is None:
        _reject(f"{name} is not canonical UTC")
    return value


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _domain_sha256(domain: str, value: object) -> str:
    encoded = canonical_v2_json_bytes(value, maximum_bytes=256 * 1_024)
    return _sha256(domain.encode("ascii") + b"\0" + encoded)


def _runtime_scope(fields: FrozenJsonObject) -> str:
    value = fields.to_dict()
    for name in ("lifecycle_root_sha256", "root_sha256"):
        item = value.get(name)
        if type(item) is str and _SHA256.fullmatch(item) is not None:
            return item
    return "0" * 64


def _canonical_evidence_snapshot(value: Any) -> str:
    fields = value.fields
    if type(fields) is not FrozenJsonObject:
        _reject("typed lifecycle semantic fields are not frozen")
    sidecars: dict[str, object] = {}
    for name in (
        "boundary",
        "absence_kind",
        "root_sha256",
        "observed_boottime_ns",
        "authorization_intent_sha256",
        "_domain",
    ):
        if hasattr(value, name):
            sidecars[name] = getattr(value, name)
    if hasattr(value, "binding_evidence"):
        binding_evidence = value.binding_evidence
        if type(binding_evidence) is not FrozenJsonObject:
            _reject("reauthentication binding evidence sidecar is not frozen")
        sidecars["binding_evidence"] = binding_evidence.to_dict()
    if hasattr(value, "mounts"):
        mounts = value.mounts
        if type(mounts) is not tuple:
            _reject("typed lifecycle mount sidecar is not immutable")
        sidecars["mount_object_id_list"] = [id(item) for item in mounts]
    return _domain_sha256(
        "AutoQuantTrader/trusted-time/graceful-stop/runtime-canonical-evidence-seal/v2",
        {
            "type": f"{type(value).__module__}.{type(value).__qualname__}",
            "fields": fields.to_dict(),
            "sidecars": sidecars,
        },
    )


def _compound_value_snapshot(value: Any) -> str:
    body: dict[str, object] = {
        "type": f"{type(value).__module__}.{type(value).__qualname__}",
    }
    for name in (
        "evidence",
        "cleanup_intent_sha256",
        "authorized_boottime_ns",
        "observer_nonce_sha256",
        "root_sha256",
    ):
        if hasattr(value, name):
            item = getattr(value, name)
            body[name] = item.to_dict() if type(item) is FrozenJsonObject else item
    for name in (
        "clean_stop_result",
        "supervisor_commitment",
        "host_identity",
        "observation",
        "host_receipt",
        "empty_mounts",
        "unmount_receipt",
        "native_owner_receipt",
        "recovery_absence",
        "socket_absence",
        "credential_absence",
        "owners",
        "authorization",
    ):
        if hasattr(value, name):
            body[f"{name}_object_id"] = id(getattr(value, name))
    if hasattr(value, "mounts"):
        mounts = value.mounts
        if type(mounts) is not tuple:
            _reject("compound lifecycle mount sidecar is not immutable")
        body["mount_object_id_list"] = [id(item) for item in mounts]
    return _domain_sha256(
        "AutoQuantTrader/trusted-time/graceful-stop/runtime-compound-value-seal/v2",
        body,
    )


def _exact_root(value: object) -> LifecycleV2Root:
    if type(value) is not LifecycleV2Root:
        _reject("normal lifecycle semantics require one exact v2 root")
    root = value
    if decode_lifecycle_v2_root(root.encoded) != root:
        _reject("lifecycle root changed under canonical revalidation")
    if root.operation_deadline_boottime_ns != (
        root.admission_started_boottime_ns + LIFECYCLE_V2_OPERATION_BUDGET_NS
    ):
        _reject("lifecycle root operation deadline is not the checked sum")
    return root


def _exact_record(value: object) -> LifecycleV2ProgressRecord:
    if type(value) is not LifecycleV2ProgressRecord:
        _reject("normal lifecycle semantics require one exact progress record")
    record = value
    if decode_lifecycle_v2_progress_record(record.encoded) != record:
        _reject("progress record changed under canonical revalidation")
    return record


class _CanonicalEvidence:
    fields: FrozenJsonObject

    def _require_canonical_seal(self) -> None:
        _require_canonical_evidence(self)

    def to_dict(self) -> dict[str, object]:
        self._require_canonical_seal()
        return self.fields.to_dict()

    @property
    def encoded(self) -> bytes:
        return canonical_v2_json_bytes(self.to_dict(), maximum_bytes=256 * 1_024)

    @property
    def sha256(self) -> str:
        return _domain_sha256(self.digest_domain, self.to_dict())

    @property
    def digest_domain(self) -> str:
        raise NotImplementedError


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2InjectedCleanupObserver:
    """Injected observer identity; Wave 6 exposes only a test-root fake."""

    root: LifecycleV2Root
    observer_nonce_sha256: str
    provenance: str

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("cleanup observers require an injected provenance seam")

    def _snapshot(self) -> str:
        return _domain_sha256(
            "AutoQuantTrader/trusted-time/graceful-stop/runtime-cleanup-observer-seal/v2",
            {
                "root_sha256": self.root.sha256,
                "observer_nonce_sha256": self.observer_nonce_sha256,
                "provenance": self.provenance,
            },
        )

    def _require_sealed(self, *, root: LifecycleV2Root) -> RuntimeSealMetadata:
        exact_root = _exact_root(root)
        try:
            snapshot = self._snapshot()
        except (AttributeError, TypeError, TrustedTimeGracefulStopV2Rejected):
            _reject("cleanup observer is not sealed")
        metadata = _require_exact_cleanup_observer_runtime(
            self,
            snapshot,
            exact_root.sha256,
        )
        if (
            metadata is None
            or self.root != exact_root
            or self.provenance != metadata.provenance
            or (
                self.provenance == "fake_injected_cleanup_observer"
                and exact_root.environment != "test"
            )
        ):
            _reject("cleanup observer crossed its injected root or provenance")
        return cast(RuntimeSealMetadata, metadata)


def _build_injected_fake_lifecycle_v2_cleanup_observer(
    *,
    root: LifecycleV2Root,
    observer_nonce_sha256: str,
) -> LifecycleV2InjectedCleanupObserver:
    """Build the explicit no-effect fake accepted only for injected test roots."""

    exact_root = _exact_root(root)
    nonce = _require_sha256(observer_nonce_sha256, "observer_nonce_sha256")
    if exact_root.environment != "test":
        _reject("fake cleanup observers are confined to injected test roots")
    result = object.__new__(LifecycleV2InjectedCleanupObserver)
    object.__setattr__(result, "root", exact_root)
    object.__setattr__(result, "observer_nonce_sha256", nonce)
    object.__setattr__(result, "provenance", "fake_injected_cleanup_observer")
    return result


def _require_cleanup_observer(
    observer: object,
    *,
    root: LifecycleV2Root,
) -> RuntimeSealMetadata:
    if type(observer) is not LifecycleV2InjectedCleanupObserver:
        _reject("cleanup evidence requires one exact injected observer")
    return observer._require_sealed(root=root)


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2HostTransportCleanupIdentity(_CanonicalEvidence):
    """Stable-loaded host custody and handshake identity used by ordinal three."""

    fields: FrozenJsonObject

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("host cleanup identities require stable typed capture")

    @classmethod
    def capture(
        cls,
        *,
        root: LifecycleV2Root,
        observer: LifecycleV2InjectedCleanupObserver,
        host_socket_identity_sha256: str,
        host_peer_credential_sha256: str,
        host_raw_key_device: int,
        host_raw_key_inode: int,
        host_challenge_sha256: str,
        host_process_nonce_sha256: str,
    ) -> Self:
        exact_root = _exact_root(root)
        _require_cleanup_observer(observer, root=exact_root)
        for name, item in (
            ("host_socket_identity_sha256", host_socket_identity_sha256),
            ("host_peer_credential_sha256", host_peer_credential_sha256),
            ("host_challenge_sha256", host_challenge_sha256),
            ("host_process_nonce_sha256", host_process_nonce_sha256),
        ):
            _require_sha256(item, name)
        _require_int(host_raw_key_device, "host_raw_key_device", minimum=1)
        _require_int(host_raw_key_inode, "host_raw_key_inode", minimum=1)
        fields = FrozenJsonObject.capture(
            {
                "environment": exact_root.environment,
                "graceful_stop_operation_id": exact_root.graceful_stop_operation_id,
                "lifecycle_root_sha256": exact_root.sha256,
                "channel_id": exact_root.channel_id,
                "host_process_epoch_sha256": exact_root.host_process_epoch_sha256,
                "host_socket_identity_sha256": host_socket_identity_sha256,
                "host_peer_credential_sha256": host_peer_credential_sha256,
                "host_raw_key_path": HOST_RAW_KEY_PATH,
                "host_raw_key_device": host_raw_key_device,
                "host_raw_key_inode": host_raw_key_inode,
                "host_challenge_sha256": host_challenge_sha256,
                "host_process_nonce_sha256": host_process_nonce_sha256,
            }
        )
        result = object.__new__(cls)
        object.__setattr__(result, "fields", fields)
        return result

    @property
    def digest_domain(self) -> str:
        return "AutoQuantTrader/trusted-time/graceful-stop/host-transport-cleanup-identity/v2"


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2TransportCleanupPlan:
    """Complete typed source for ordinal-three evidence."""

    evidence: FrozenJsonObject
    clean_stop_result: LifecycleV2CleanStopResult
    supervisor_commitment: LifecycleV2SupervisorCleanupCommitment
    host_identity: LifecycleV2HostTransportCleanupIdentity

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("transport cleanup plans require result-bound construction")

    @classmethod
    def from_retained_result(
        cls,
        *,
        root: LifecycleV2Root,
        result_record: LifecycleV2ProgressRecord,
        terminal_wire_evidence: LifecycleV2TerminalWireEvidence,
        clean_stop_result: LifecycleV2CleanStopResult,
        host_identity: LifecycleV2HostTransportCleanupIdentity,
    ) -> Self:
        exact_root = _exact_root(root)
        exact_record = _exact_record(result_record)
        if type(terminal_wire_evidence) is not LifecycleV2TerminalWireEvidence:
            _reject("ordinal three requires exact authenticated terminal-wire evidence")
        if type(clean_stop_result) is not LifecycleV2CleanStopResult:
            _reject("ordinal three requires one exact clean-stop result")
        exact_result = decode_lifecycle_v2_clean_stop_result(clean_stop_result.encoded)
        if type(host_identity) is not LifecycleV2HostTransportCleanupIdentity:
            _reject("ordinal three requires one exact host cleanup identity")
        host_metadata = _require_canonical_evidence(host_identity)
        if (
            host_metadata.provenance == "fake_injected_cleanup_observer"
            and exact_root.environment != "test"
        ):
            _reject("fake cleanup identity cannot enter a non-test lifecycle")
        if (
            exact_record.ordinal != 2
            or exact_record.stage is not LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED
            or exact_record.effect_kind != "clean_stop_result"
            or exact_record.deadline_boottime_ns != exact_root.operation_deadline_boottime_ns
            or exact_record.root_sha256 != exact_root.sha256
            or exact_record.graceful_stop_operation_id != exact_root.graceful_stop_operation_id
            or exact_record.evidence != FrozenJsonObject.capture(terminal_wire_evidence.to_dict())
        ):
            _reject("ordinal-three predecessor is not the exact retained result")
        retained = terminal_wire_evidence.to_dict()
        result_fields = exact_result.to_dict()
        commitment = exact_result.cleanup_commitment
        commitment_fields = commitment.to_dict()
        result_deadline = exact_root.clean_stop_result_deadline_boottime_ns
        if result_deadline > MAXIMUM_SIGNED_INTEGER - 5_000_000_000:
            _reject("transport cleanup deadline addition overflows")
        expected_cleanup_deadline = min(
            result_deadline + 5_000_000_000,
            exact_root.operation_deadline_boottime_ns,
        )
        if not (
            retained["frame_type"] == "clean_stop_result"
            and retained["clean_stop_result_payload_sha256"] == _sha256(exact_result.encoded)
            and retained["terminal_projection_sha256"] == exact_result.terminal_projection.sha256
            and exact_record.predecessor_sha256 == retained["intent_sha256"]
            and result_fields["environment"] == exact_root.environment
            and result_fields["graceful_stop_operation_id"] == exact_root.graceful_stop_operation_id
            and result_fields["lifecycle_root_sha256"] == exact_root.sha256
            and result_fields["admission_sha256"] == exact_root.admission_sha256
            and result_fields["channel_id"] == exact_root.channel_id
            and result_fields["boot_epoch_sha256"] == exact_root.boot_epoch_sha256
            and result_fields["host_process_epoch_sha256"] == exact_root.host_process_epoch_sha256
            and result_fields["supervisor_process_epoch_sha256"]
            == exact_root.supervisor_process_epoch_sha256
            and result_fields["supervisor_container_id"] == exact_root.supervisor_container_id
            and result_fields["transport_cleanup_deadline_boottime_ns"] == expected_cleanup_deadline
            and commitment_fields["environment"] == exact_root.environment
            and commitment_fields["graceful_stop_operation_id"]
            == exact_root.graceful_stop_operation_id
            and commitment_fields["lifecycle_root_sha256"] == exact_root.sha256
            and commitment_fields["admission_sha256"] == exact_root.admission_sha256
            and commitment_fields["channel_id"] == exact_root.channel_id
            and commitment_fields["boot_epoch_sha256"] == exact_root.boot_epoch_sha256
            and commitment_fields["supervisor_process_epoch_sha256"]
            == exact_root.supervisor_process_epoch_sha256
            and commitment_fields["supervisor_container_id"] == exact_root.supervisor_container_id
            and commitment_fields["transport_authority_manifest_sha256"]
            == exact_root.transport_authority_manifest_sha256
            and commitment_fields["key_generation"] == exact_root.transport_key_generation
            and commitment_fields["supervisor_key_id"] == exact_root.supervisor_transport_key_id
            and commitment_fields["cleanup_deadline_boottime_ns"] == expected_cleanup_deadline
            and expected_cleanup_deadline > result_deadline
        ):
            _reject("clean-stop result or cleanup commitment crossed its root")
        host = host_identity.to_dict()
        if (
            host["environment"] != exact_root.environment
            or host["graceful_stop_operation_id"] != exact_root.graceful_stop_operation_id
            or host["lifecycle_root_sha256"] != exact_root.sha256
            or host["channel_id"] != exact_root.channel_id
            or host["host_process_epoch_sha256"] != exact_root.host_process_epoch_sha256
        ):
            _reject("host cleanup identity crossed its lifecycle root")
        evidence = FrozenJsonObject.capture(
            {
                "clean_stop_result_sha256": retained["clean_stop_result_sha256"],
                "supervisor_cleanup_commitment_sha256": commitment.sha256,
                "channel_id": exact_root.channel_id,
                "host_process_epoch_sha256": exact_root.host_process_epoch_sha256,
                "host_socket_identity_sha256": host["host_socket_identity_sha256"],
                "host_peer_credential_sha256": host["host_peer_credential_sha256"],
                "host_raw_key_path": HOST_RAW_KEY_PATH,
                "host_raw_key_device": host["host_raw_key_device"],
                "host_raw_key_inode": host["host_raw_key_inode"],
                "host_challenge_sha256": host["host_challenge_sha256"],
                "host_process_nonce_sha256": host["host_process_nonce_sha256"],
                "cleanup_deadline_boottime_ns": expected_cleanup_deadline,
            }
        )
        result = object.__new__(cls)
        object.__setattr__(result, "evidence", evidence)
        object.__setattr__(result, "clean_stop_result", exact_result)
        object.__setattr__(result, "supervisor_commitment", commitment)
        object.__setattr__(result, "host_identity", host_identity)
        return result

    def _require_sealed(self) -> RuntimeSealMetadata:
        return cast(RuntimeSealMetadata, _require_exact_compound_value(self))


_SUPERVISOR_QUIESCENCE_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "environment",
        "graceful_stop_operation_id",
        "lifecycle_root_sha256",
        "channel_id",
        "supervisor_process_epoch_sha256",
        "supervisor_cleanup_commitment_sha256",
        "supervisor_peer_credential_sha256",
        "listener_path",
        "listener_path_device",
        "listener_path_inode",
        "listener_fd_socket_inode",
        "accepted_fd_socket_inode",
        "supervisor_fd_table_sha256",
        "channel_eof_observed",
        "listener_fd_absent",
        "accepted_fd_absent",
        "socket_path_absent",
        "credential_path_absent",
        "observed_boottime_ns",
    }
)


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2SupervisorQuiescenceObservation(_CanonicalEvidence):
    fields: FrozenJsonObject

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("supervisor quiescence observations require canonical capture")

    @classmethod
    def capture(
        cls,
        value: object,
        *,
        root: LifecycleV2Root,
        plan: LifecycleV2TransportCleanupPlan,
        observer: LifecycleV2InjectedCleanupObserver,
    ) -> Self:
        exact_root = _exact_root(root)
        if type(plan) is not LifecycleV2TransportCleanupPlan:
            _reject("supervisor quiescence requires one exact cleanup plan")
        plan_metadata = plan._require_sealed()
        observer_metadata = _require_cleanup_observer(observer, root=exact_root)
        if (
            plan_metadata.provenance != observer_metadata.provenance
            or plan_metadata.scope_sha256 != observer.observer_nonce_sha256
        ):
            _reject("supervisor quiescence observer crossed its cleanup plan")
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _SUPERVISOR_QUIESCENCE_FIELDS, "supervisor quiescence")
        commitment = plan.supervisor_commitment.to_dict()
        if (
            fields["contract_version"]
            != "phase6d-trusted-time-graceful-stop-supervisor-transport-quiescence-observation-v2"
            or fields["service"] != LIFECYCLE_V2_CLEANUP_SERVICE
            or fields["status"] != "supervisor_transport_quiescence_observed"
        ):
            _reject("supervisor quiescence discriminator is invalid")
        for name, expected in (
            ("environment", exact_root.environment),
            ("graceful_stop_operation_id", exact_root.graceful_stop_operation_id),
            ("lifecycle_root_sha256", exact_root.sha256),
            ("channel_id", exact_root.channel_id),
            ("supervisor_process_epoch_sha256", exact_root.supervisor_process_epoch_sha256),
            ("supervisor_cleanup_commitment_sha256", plan.supervisor_commitment.sha256),
            ("supervisor_peer_credential_sha256", commitment["supervisor_peer_credential_sha256"]),
            ("listener_path", LISTENER_PATH),
            ("listener_path_device", commitment["listener_path_device"]),
            ("listener_path_inode", commitment["listener_path_inode"]),
            ("listener_fd_socket_inode", commitment["listener_fd_socket_inode"]),
            ("accepted_fd_socket_inode", commitment["accepted_fd_socket_inode"]),
        ):
            if fields[name] != expected:
                _reject(f"supervisor quiescence {name} crossed its commitment")
        _require_sha256(fields["supervisor_fd_table_sha256"], "supervisor_fd_table_sha256")
        for name in (
            "channel_eof_observed",
            "listener_fd_absent",
            "accepted_fd_absent",
            "socket_path_absent",
            "credential_path_absent",
        ):
            _require_true(fields[name], name)
        observed = _require_int(fields["observed_boottime_ns"], "observed_boottime_ns")
        if observed >= cast(int, commitment["cleanup_deadline_boottime_ns"]):
            _reject("supervisor quiescence observation is equality-expired or late")
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        return result

    @property
    def digest_domain(self) -> str:
        return (
            "AutoQuantTrader/trusted-time/graceful-stop/"
            "supervisor-transport-quiescence-observation/v2"
        )


_HOST_CLEANUP_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "environment",
        "graceful_stop_operation_id",
        "lifecycle_root_sha256",
        "channel_id",
        "host_process_epoch_sha256",
        "host_socket_identity_sha256",
        "host_peer_credential_sha256",
        "host_raw_key_path",
        "host_raw_key_device",
        "host_raw_key_inode",
        "accepted_channel_closed",
        "host_signer_zeroized",
        "host_challenge_zeroized",
        "host_process_nonce_zeroized",
        "credential_path_absent",
        "cleanup_started_boottime_ns",
        "cleanup_completed_boottime_ns",
    }
)


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2HostTransportCleanupReceipt(_CanonicalEvidence):
    fields: FrozenJsonObject

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("host cleanup receipts require canonical capture")

    @classmethod
    def capture(
        cls,
        value: object,
        *,
        root: LifecycleV2Root,
        plan: LifecycleV2TransportCleanupPlan,
        observer: LifecycleV2InjectedCleanupObserver,
    ) -> Self:
        exact_root = _exact_root(root)
        if type(plan) is not LifecycleV2TransportCleanupPlan:
            _reject("host cleanup requires one exact cleanup plan")
        plan_metadata = plan._require_sealed()
        observer_metadata = _require_cleanup_observer(observer, root=exact_root)
        if (
            plan_metadata.provenance != observer_metadata.provenance
            or plan_metadata.scope_sha256 != observer.observer_nonce_sha256
        ):
            _reject("host cleanup observer crossed its cleanup plan")
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _HOST_CLEANUP_FIELDS, "host cleanup receipt")
        plan_fields = plan.evidence.to_dict()
        if (
            fields["contract_version"]
            != "phase6d-trusted-time-graceful-stop-host-transport-cleanup-receipt-v2"
            or fields["service"] != LIFECYCLE_V2_CLEANUP_SERVICE
            or fields["status"] != "host_transport_cleanup_completed"
        ):
            _reject("host cleanup receipt discriminator is invalid")
        for name, expected in (
            ("environment", exact_root.environment),
            ("graceful_stop_operation_id", exact_root.graceful_stop_operation_id),
            ("lifecycle_root_sha256", exact_root.sha256),
            ("channel_id", exact_root.channel_id),
            ("host_process_epoch_sha256", exact_root.host_process_epoch_sha256),
            ("host_socket_identity_sha256", plan_fields["host_socket_identity_sha256"]),
            ("host_peer_credential_sha256", plan_fields["host_peer_credential_sha256"]),
            ("host_raw_key_path", HOST_RAW_KEY_PATH),
            ("host_raw_key_device", plan_fields["host_raw_key_device"]),
            ("host_raw_key_inode", plan_fields["host_raw_key_inode"]),
        ):
            if fields[name] != expected:
                _reject(f"host cleanup {name} crossed its plan")
        for name in (
            "accepted_channel_closed",
            "host_signer_zeroized",
            "host_challenge_zeroized",
            "host_process_nonce_zeroized",
            "credential_path_absent",
        ):
            _require_true(fields[name], name)
        started = _require_int(fields["cleanup_started_boottime_ns"], "cleanup_started_boottime_ns")
        completed = _require_int(
            fields["cleanup_completed_boottime_ns"], "cleanup_completed_boottime_ns"
        )
        deadline = cast(int, plan_fields["cleanup_deadline_boottime_ns"])
        if not started <= completed < deadline:
            _reject("host cleanup timestamps are reversed or equality-expired")
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        return result

    @property
    def digest_domain(self) -> str:
        return "AutoQuantTrader/trusted-time/graceful-stop/host-transport-cleanup-receipt/v2"


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2TransportQuiescence:
    evidence: FrozenJsonObject
    observation: LifecycleV2SupervisorQuiescenceObservation
    host_receipt: LifecycleV2HostTransportCleanupReceipt

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("transport quiescence requires both exact cleanup receipts")

    @classmethod
    def confirm(
        cls,
        *,
        root: LifecycleV2Root,
        cleanup_record: LifecycleV2ProgressRecord,
        plan: LifecycleV2TransportCleanupPlan,
        observation: LifecycleV2SupervisorQuiescenceObservation,
        host_receipt: LifecycleV2HostTransportCleanupReceipt,
    ) -> Self:
        exact_root = _exact_root(root)
        exact_record = _exact_record(cleanup_record)
        if (
            type(plan) is not LifecycleV2TransportCleanupPlan
            or type(observation) is not LifecycleV2SupervisorQuiescenceObservation
            or type(host_receipt) is not LifecycleV2HostTransportCleanupReceipt
            or exact_record.ordinal != 3
            or exact_record.stage is not LifecycleV2Stage.TRANSPORT_CLEANUP_COMMITMENT_RETAINED
            or exact_record.root_sha256 != exact_root.sha256
            or exact_record.evidence != plan.evidence
        ):
            _reject("transport quiescence crossed its exact ordinal-three plan")
        plan_metadata = plan._require_sealed()
        observation_metadata = _require_canonical_evidence(observation)
        receipt_metadata = _require_canonical_evidence(host_receipt)
        if (
            observation_metadata.provenance != plan_metadata.provenance
            or receipt_metadata.provenance != plan_metadata.provenance
            or observation_metadata.scope_sha256 != plan_metadata.scope_sha256
            or receipt_metadata.scope_sha256 != plan_metadata.scope_sha256
        ):
            _reject("transport cleanup evidence crossed its injected observer")
        observation_fields = observation.to_dict()
        receipt_fields = host_receipt.to_dict()
        terminal_completed = cast(
            int, plan.clean_stop_result.to_dict()["result_completed_boottime_ns"]
        )
        started = cast(int, receipt_fields["cleanup_started_boottime_ns"])
        completed = cast(int, receipt_fields["cleanup_completed_boottime_ns"])
        observed = cast(int, observation_fields["observed_boottime_ns"])
        if not terminal_completed <= observed <= started <= completed:
            _reject("transport cleanup did not follow terminal completion in order")
        evidence = FrozenJsonObject.capture(
            {
                "cleanup_commitment_record_sha256": exact_record.sha256,
                "supervisor_cleanup_commitment_sha256": plan.supervisor_commitment.sha256,
                "host_native_cleanup_receipt_sha256": host_receipt.sha256,
                "supervisor_quiescence_observation_sha256": observation.sha256,
                "channel_eof_observed": True,
                "listener_fd_absent": True,
                "accepted_fd_absent": True,
                "socket_path_absent": True,
                "host_signer_zeroized": True,
                "host_challenge_zeroized": True,
                "host_process_nonce_zeroized": True,
                "credential_paths_absent": True,
                "cleanup_started_boottime_ns": started,
                "cleanup_completed_boottime_ns": completed,
            }
        )
        result = object.__new__(cls)
        object.__setattr__(result, "evidence", evidence)
        object.__setattr__(result, "observation", observation)
        object.__setattr__(result, "host_receipt", host_receipt)
        return result

    def _require_sealed(self) -> RuntimeSealMetadata:
        return cast(RuntimeSealMetadata, _require_exact_compound_value(self))


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2ReauthenticationIntent(_CanonicalEvidence):
    fields: FrozenJsonObject
    boundary: str

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("reauthentication intents require a fixed lifecycle boundary")

    @classmethod
    def _capture_fixed(cls, value: dict[str, object], *, boundary: str) -> Self:
        if boundary not in {"pre_effect", "post_teardown"}:
            _reject("reauthentication intent boundary is outside the closed set")
        result = object.__new__(cls)
        object.__setattr__(result, "fields", FrozenJsonObject.capture(value))
        object.__setattr__(result, "boundary", boundary)
        return result

    @property
    def digest_domain(self) -> str:
        return (
            "AutoQuantTrader/trusted-time/graceful-stop/"
            f"{self.boundary.replace('_', '-')}-reauthentication-intent/v2"
        )


_REAUTHENTICATION_BINDING_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "environment",
        "graceful_stop_operation_id",
        "lifecycle_root_sha256",
        "channel_id",
        "boundary",
        "intent_semantic_sha256",
        "binding_evidence_sha256",
        "issuer_identity_sha256",
        "challenge_sha256",
        "observation_semantic_sha256",
        "observed_head_sha256",
        "provider_identity_sha256",
        "observation_started_boottime_ns",
        "observation_completed_boottime_ns",
    }
)


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2AuthenticatedReauthenticationBinding(_CanonicalEvidence):
    """Sealed primitive evidence returned by a distinct ADR-0109 v2 seam."""

    fields: FrozenJsonObject
    binding_evidence: FrozenJsonObject
    boundary: str

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("reauthentication bindings require an authentication seam")

    @classmethod
    def _capture_fake_for_tests(
        cls,
        value: object,
        *,
        binding_evidence: object,
        root: LifecycleV2Root,
        intent: LifecycleV2ReauthenticationIntent,
    ) -> Self:
        exact_root = _exact_root(root)
        if exact_root.environment != "test":
            _reject("fake reauthentication binding is confined to injected test roots")
        return cast(
            Self,
            _build_unregistered_authenticated_reauthentication_binding(
                value,
                binding_evidence=binding_evidence,
                root=exact_root,
                intent=intent,
            ),
        )

    def _require_sealed(self) -> None:
        metadata = _require_canonical_evidence(self)
        if metadata.provenance not in {
            "fake_reauthentication_binding",
            "production_reauthentication_binding",
        }:
            _reject("reauthentication binding is not sealed")

    @property
    def digest_domain(self) -> str:
        self._require_sealed()
        return (
            "AutoQuantTrader/trusted-time/graceful-stop/"
            f"{self.boundary.replace('_', '-')}-reauthentication-binding/v2"
        )


def _build_unregistered_authenticated_reauthentication_binding(
    value: object,
    *,
    binding_evidence: object,
    root: LifecycleV2Root,
    intent: LifecycleV2ReauthenticationIntent,
) -> LifecycleV2AuthenticatedReauthenticationBinding:
    """Build inert primitive evidence; only registry closures can seal the result."""

    exact_root = _exact_root(root)
    if type(intent) is not LifecycleV2ReauthenticationIntent:
        _reject("reauthentication binding requires one exact typed intent")
    frozen = FrozenJsonObject.capture(value)
    fields = frozen.to_dict()
    _require_fields(fields, _REAUTHENTICATION_BINDING_FIELDS, "reauthentication binding")
    boundary = intent.boundary
    frozen_binding_evidence, binding_evidence_sha256 = (
        _capture_lifecycle_v2_reauthentication_binding_evidence(
            binding_evidence,
            boundary=boundary,
        )
    )
    evidence_fields = frozen_binding_evidence.to_dict()
    expected_contract = (
        "phase6d-trusted-time-graceful-stop-"
        f"{boundary.replace('_', '-')}-reauthentication-binding-v2"
    )
    if (
        fields["contract_version"] != expected_contract
        or fields["service"] != LIFECYCLE_V2_CLEANUP_SERVICE
        or fields["status"] != f"{boundary}_reauthentication_bound"
        or fields["boundary"] != boundary
        or fields["environment"] != exact_root.environment
        or fields["graceful_stop_operation_id"] != exact_root.graceful_stop_operation_id
        or fields["lifecycle_root_sha256"] != exact_root.sha256
        or fields["channel_id"] != exact_root.channel_id
        or fields["intent_semantic_sha256"] != intent.sha256
        or fields["binding_evidence_sha256"] != binding_evidence_sha256
        or evidence_fields["environment"] != exact_root.environment
        or evidence_fields["graceful_stop_operation_id"] != exact_root.graceful_stop_operation_id
        or evidence_fields["lifecycle_root_sha256"] != exact_root.sha256
        or fields["observed_head_sha256"] != intent.to_dict()["expected_head_sha256"]
        or fields["provider_identity_sha256"] != intent.to_dict()["provider_identity_sha256"]
        or fields["issuer_identity_sha256"] != evidence_fields["adr0109_issuer_binding_sha256"]
        or fields["challenge_sha256"] != evidence_fields["issuer_challenge_sha256"]
        or fields["observation_semantic_sha256"] != evidence_fields["observation_semantic_sha256"]
        or fields["observed_head_sha256"] != evidence_fields["expected_clean_stop_head_sha256"]
        or fields["provider_identity_sha256"] != evidence_fields["provider_identity_sha256"]
        or fields["observation_started_boottime_ns"]
        != evidence_fields["observation_started_monotonic_ns"]
        or fields["observation_completed_boottime_ns"]
        != evidence_fields["observation_completed_monotonic_ns"]
    ):
        _reject("reauthentication binding crossed its exact intent")
    for name in (
        "issuer_identity_sha256",
        "challenge_sha256",
        "observation_semantic_sha256",
        "observed_head_sha256",
        "provider_identity_sha256",
    ):
        _require_sha256(fields[name], name)
    started = _require_int(
        fields["observation_started_boottime_ns"],
        "observation_started_boottime_ns",
    )
    completed = _require_int(
        fields["observation_completed_boottime_ns"],
        "observation_completed_boottime_ns",
    )
    intent_fields = intent.to_dict()
    if not (
        cast(int, intent_fields["observation_not_before_boottime_ns"])
        <= started
        <= completed
        < cast(int, intent_fields["call_deadline_boottime_ns"])
    ):
        _reject("reauthentication observation is reversed or equality-expired")
    result = object.__new__(LifecycleV2AuthenticatedReauthenticationBinding)
    object.__setattr__(result, "fields", frozen)
    object.__setattr__(result, "binding_evidence", frozen_binding_evidence)
    object.__setattr__(result, "boundary", boundary)
    return result


def _mint_fake_lifecycle_v2_reauthentication_binding(
    value: object,
    *,
    binding_evidence: object,
    root: LifecycleV2Root,
    intent: LifecycleV2ReauthenticationIntent,
) -> LifecycleV2AuthenticatedReauthenticationBinding:
    """Test-only seam; the distinct production seams use a separate capability."""

    return LifecycleV2AuthenticatedReauthenticationBinding._capture_fake_for_tests(
        value,
        binding_evidence=binding_evidence,
        root=root,
        intent=intent,
    )


_MOUNT_RULES = MappingProxyType(
    {
        HOST_SECRET_MOUNT_PATH: (0, 0, 0o700),
        SUPERVISOR_SECRET_MOUNT_PATH: (0, 10_001, 0o730),
        TRANSPORT_MOUNT_PATH: (0, 10_001, 0o770),
    }
)
_MOUNT_FIELDS = frozenset(
    {
        "path",
        "mount_id",
        "mount_parent_id",
        "mount_major_minor",
        "mount_root",
        "mount_options",
        "directory_device",
        "directory_inode",
        "directory_uid",
        "directory_gid",
        "directory_mode",
        "entry_count",
    }
)


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2EmptySecretMountIdentity(_CanonicalEvidence):
    fields: FrozenJsonObject
    observed_boottime_ns: int

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("secret mount identities require canonical capture")

    @classmethod
    def capture(
        cls,
        value: object,
        *,
        observer: LifecycleV2InjectedCleanupObserver,
        observed_boottime_ns: int,
    ) -> Self:
        _require_cleanup_observer(observer, root=observer.root)
        observed = _require_int(observed_boottime_ns, "observed_boottime_ns")
        if not (
            observer.root.admission_started_boottime_ns
            <= observed
            < observer.root.operation_deadline_boottime_ns
        ):
            _reject("secret mount observation is outside the operation interval")
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _MOUNT_FIELDS, "secret mount identity")
        path = _require_path(fields["path"], "path")
        rule = _MOUNT_RULES.get(path)
        if rule is None:
            _reject("secret mount path is outside the exact normal-path set")
        _require_int(fields["mount_id"], "mount_id", minimum=1)
        _require_int(fields["mount_parent_id"], "mount_parent_id", minimum=1)
        major_minor = _require_text(fields["mount_major_minor"], "mount_major_minor")
        if _MAJOR_MINOR.fullmatch(major_minor) is None:
            _reject("mount_major_minor is not canonical")
        if fields["mount_root"] != "/":
            _reject("normal-path secret mount root must be slash")
        if fields["mount_options"] != [
            "nodev",
            "noexec",
            "nosuid",
            "rw",
            "size=64K",
        ]:
            _reject("normal-path tmpfs mount options are not exact")
        for name in ("directory_device", "directory_inode"):
            _require_int(fields[name], name, minimum=1)
        for name in ("directory_uid", "directory_gid", "directory_mode"):
            _require_int(fields[name], name)
        entry_count = _require_int(fields["entry_count"], "entry_count")
        if (
            fields["directory_uid"] != rule[0]
            or fields["directory_gid"] != rule[1]
            or fields["directory_mode"] != rule[2]
            or entry_count != 0
        ):
            _reject("secret mount ownership, mode, or emptiness drifted")
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        object.__setattr__(result, "observed_boottime_ns", observed)
        return result

    @property
    def digest_domain(self) -> str:
        return "AutoQuantTrader/trusted-time/graceful-stop/secret-mount-identity/v2"


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2EmptySecretMountProjection(_CanonicalEvidence):
    fields: FrozenJsonObject
    mounts: tuple[LifecycleV2EmptySecretMountIdentity, ...]

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("empty mount projections require the exact three mounts")

    @classmethod
    def from_mounts(
        cls,
        *,
        root: LifecycleV2Root,
        mounts: object,
    ) -> Self:
        exact_root = _exact_root(root)
        if type(mounts) not in {tuple, list}:
            _reject("empty mount projection requires a concrete mount sequence")
        sequence = tuple(cast(tuple[object, ...] | list[object], mounts))
        if any(type(item) is not LifecycleV2EmptySecretMountIdentity for item in sequence):
            _reject("empty mount projection contains an inexact mount identity")
        typed = cast(tuple[LifecycleV2EmptySecretMountIdentity, ...], sequence)
        metadata = tuple(_require_canonical_evidence(item) for item in typed)
        if (
            not metadata
            or len({item.provenance for item in metadata}) != 1
            or len({item.scope_sha256 for item in metadata}) != 1
            or (
                metadata[0].provenance == "fake_injected_cleanup_observer"
                and exact_root.environment != "test"
            )
        ):
            _reject("empty mount projection crossed its injected observer")
        expected_paths = tuple(sorted(_MOUNT_RULES))
        if tuple(item.to_dict()["path"] for item in typed) != expected_paths:
            _reject("empty mount projection is not the path-sorted three-mount set")
        ids = [item.to_dict()["mount_id"] for item in typed]
        if len(set(ids)) != 3:
            _reject("empty mount projection reuses a mount ID")
        fields = FrozenJsonObject.capture(
            {
                "environment": exact_root.environment,
                "graceful_stop_operation_id": exact_root.graceful_stop_operation_id,
                "lifecycle_root_sha256": exact_root.sha256,
                "mounts": [item.to_dict() for item in typed],
            }
        )
        result = object.__new__(cls)
        object.__setattr__(result, "fields", fields)
        object.__setattr__(result, "mounts", typed)
        return result

    @property
    def digest_domain(self) -> str:
        return "AutoQuantTrader/trusted-time/graceful-stop/empty-secret-mount-projection/v2"


_ABSENCE_PATHS = MappingProxyType(
    {
        "recovery_secret_mount": (RECOVERY_SECRET_MOUNT_PATH,),
        "transport_socket": (LISTENER_PATH,),
        "credential_paths": (HOST_RAW_KEY_PATH, SUPERVISOR_RAW_KEY_PATH),
    }
)


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2PathAbsence(_CanonicalEvidence):
    fields: FrozenJsonObject
    absence_kind: str
    authorization_intent_sha256: str | None

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("path absence requires a fixed closed absence kind")

    @classmethod
    def _fixed(
        cls,
        *,
        root: LifecycleV2Root,
        observer: LifecycleV2InjectedCleanupObserver,
        kind: str,
        observed_boottime_ns: int,
        authorization: LifecycleV2TerminalCleanupAuthorization | None = None,
    ) -> Self:
        exact_root = _exact_root(root)
        observer_metadata = _require_cleanup_observer(observer, root=exact_root)
        paths = _ABSENCE_PATHS[kind]
        observed = _require_int(observed_boottime_ns, "observed_boottime_ns")
        if not (
            exact_root.admission_started_boottime_ns
            <= observed
            < exact_root.operation_deadline_boottime_ns
        ):
            _reject("path-absence observation is equality-expired or late")
        authorization_intent_sha256: str | None = None
        if authorization is not None:
            authorization_snapshot = authorization._snapshot()
            if kind == "recovery_secret_mount":
                authorization_metadata = (
                    _consume_terminal_cleanup_final_recovery_absence_authorization(
                        authorization,
                        authorization_snapshot,
                    )
                )
            elif kind == "transport_socket":
                authorization_metadata = (
                    _consume_terminal_cleanup_final_socket_absence_authorization(
                        authorization,
                        authorization_snapshot,
                    )
                )
            elif kind == "credential_paths":
                authorization_metadata = (
                    _consume_terminal_cleanup_final_credential_absence_authorization(
                        authorization,
                        authorization_snapshot,
                    )
                )
            else:
                _reject("terminal cleanup absence action is outside the closed set")
            if authorization_metadata is None:
                _reject("terminal cleanup authorization action is reused or out of order")
            if (
                authorization_metadata.provenance != observer_metadata.provenance
                or authorization_metadata.scope_sha256 != observer.observer_nonce_sha256
                or observed <= authorization.authorized_boottime_ns
            ):
                _reject("final path absence crossed or preceded cleanup authorization")
            authorization_intent_sha256 = authorization.cleanup_intent_sha256
        fields = FrozenJsonObject.capture(
            {
                "environment": exact_root.environment,
                "graceful_stop_operation_id": exact_root.graceful_stop_operation_id,
                "lifecycle_root_sha256": exact_root.sha256,
                "absence_kind": kind,
                "paths": list(paths),
                "all_absent": True,
                "observed_boottime_ns": observed,
            }
        )
        result = object.__new__(cls)
        object.__setattr__(result, "fields", fields)
        object.__setattr__(result, "absence_kind", kind)
        object.__setattr__(result, "authorization_intent_sha256", authorization_intent_sha256)
        return result

    @classmethod
    def recovery_secret_mount(
        cls,
        *,
        root: LifecycleV2Root,
        observer: LifecycleV2InjectedCleanupObserver,
        observed_boottime_ns: int,
        authorization: LifecycleV2TerminalCleanupAuthorization | None = None,
    ) -> Self:
        return cls._fixed(
            root=root,
            observer=observer,
            kind="recovery_secret_mount",
            observed_boottime_ns=observed_boottime_ns,
            authorization=authorization,
        )

    @classmethod
    def transport_socket(
        cls,
        *,
        root: LifecycleV2Root,
        observer: LifecycleV2InjectedCleanupObserver,
        observed_boottime_ns: int,
        authorization: LifecycleV2TerminalCleanupAuthorization | None = None,
    ) -> Self:
        return cls._fixed(
            root=root,
            observer=observer,
            kind="transport_socket",
            observed_boottime_ns=observed_boottime_ns,
            authorization=authorization,
        )

    @classmethod
    def credential_paths(
        cls,
        *,
        root: LifecycleV2Root,
        observer: LifecycleV2InjectedCleanupObserver,
        observed_boottime_ns: int,
        authorization: LifecycleV2TerminalCleanupAuthorization | None = None,
    ) -> Self:
        return cls._fixed(
            root=root,
            observer=observer,
            kind="credential_paths",
            observed_boottime_ns=observed_boottime_ns,
            authorization=authorization,
        )

    @property
    def digest_domain(self) -> str:
        return (
            "AutoQuantTrader/trusted-time/graceful-stop/"
            f"{self.absence_kind.replace('_', '-')}-absence/v2"
        )


_OWNER_KINDS = (
    "docker_effect_client",
    "endpoint_signer",
    "post_teardown_issuer",
    "pre_effect_issuer",
    "transport_channel",
)
_OWNER_ENTRY_FIELDS = frozenset({"owner_kind", "owner_process_epoch_sha256", "owner_nonce_sha256"})


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2NativeOwnerSet(_CanonicalEvidence):
    fields: FrozenJsonObject
    root_sha256: str
    observed_boottime_ns: int

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("native owner sets require closed kind-sorted capture")

    @classmethod
    def capture(
        cls,
        *,
        root: LifecycleV2Root,
        observer: LifecycleV2InjectedCleanupObserver,
        owners: object,
        observed_boottime_ns: int,
    ) -> Self:
        exact_root = _exact_root(root)
        _require_cleanup_observer(observer, root=exact_root)
        observed = _require_int(observed_boottime_ns, "observed_boottime_ns")
        if not (
            exact_root.admission_started_boottime_ns
            <= observed
            < exact_root.operation_deadline_boottime_ns
        ):
            _reject("native owner observation is outside the operation interval")
        if type(owners) not in {list, tuple}:
            _reject("native owner set requires a concrete owner sequence")
        raw = tuple(cast(list[object] | tuple[object, ...], owners))
        if not raw:
            _reject("native owner set cannot omit every remaining owner")
        normalized: list[dict[str, object]] = []
        for item in raw:
            if type(item) is not dict:
                _reject("native owner entry must be one exact object")
            entry = cast(dict[str, object], item)
            _require_fields(entry, _OWNER_ENTRY_FIELDS, "native owner entry")
            kind = _require_text(entry["owner_kind"], "owner_kind")
            if kind not in _OWNER_KINDS:
                _reject("native owner kind is outside the closed set")
            expected_epoch = (
                exact_root.supervisor_process_epoch_sha256
                if kind == "endpoint_signer"
                else exact_root.host_process_epoch_sha256
            )
            if entry["owner_process_epoch_sha256"] != expected_epoch:
                _reject("native owner process epoch drifted")
            _require_sha256(entry["owner_nonce_sha256"], "owner_nonce_sha256")
            normalized.append(dict(entry))
        kinds = [cast(str, entry["owner_kind"]) for entry in normalized]
        nonces = [cast(str, entry["owner_nonce_sha256"]) for entry in normalized]
        if kinds != sorted(kinds) or len(set(kinds)) != len(kinds):
            _reject("native owner entries are not kind-sorted and unique")
        if len(set(nonces)) != len(nonces):
            _reject("native owners reuse an owner nonce")
        fields = FrozenJsonObject.capture({"owners": normalized})
        result = object.__new__(cls)
        object.__setattr__(result, "fields", fields)
        object.__setattr__(result, "root_sha256", exact_root.sha256)
        object.__setattr__(result, "observed_boottime_ns", observed)
        return result

    @property
    def owner_count(self) -> int:
        return len(cast(list[object], self.to_dict()["owners"]))

    @property
    def digest_domain(self) -> str:
        return "AutoQuantTrader/trusted-time/graceful-stop/native-owner-set/v2"

    @property
    def sha256(self) -> str:
        """Hash the exact kind-sorted owner list, not a digest-only wrapper."""

        return _domain_sha256(self.digest_domain, self.to_dict()["owners"])


_TERMINAL_CLEANUP_AUTHORIZATION_ACTIONS = frozenset(
    {
        "unmount",
        "native_owner_cleanup",
        "final_recovery_secret_mount_absence",
        "final_transport_socket_absence",
        "final_credential_paths_absence",
    }
)


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2TerminalCleanupAuthorization:
    """One-shot action set issued only after ordinal twenty-one exists."""

    root_sha256: str
    cleanup_intent_sha256: str
    observer_nonce_sha256: str
    authorized_boottime_ns: int

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("terminal cleanup authorization requires retained ordinal twenty-one")

    def _snapshot(self) -> str:
        return _compound_value_snapshot(self)


def _require_terminal_cleanup_authorization(
    authorization: object,
) -> RuntimeSealMetadata:
    if type(authorization) is not LifecycleV2TerminalCleanupAuthorization:
        _reject("terminal cleanup authorization is not exact")
    return cast(RuntimeSealMetadata, _require_exact_compound_value(authorization))


def _finalize_terminal_cleanup_authorization(
    authorization: LifecycleV2TerminalCleanupAuthorization,
) -> RuntimeSealMetadata:
    _require_terminal_cleanup_authorization(authorization)
    metadata = _finalize_exact_terminal_cleanup_authorization_runtime(
        authorization,
        authorization._snapshot(),
    )
    if metadata is None:
        _reject("terminal cleanup authorization is incomplete or already consumed")
    return cast(RuntimeSealMetadata, metadata)


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2SecretMountUnmountReceipt(_CanonicalEvidence):
    fields: FrozenJsonObject
    authorization_intent_sha256: str

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("unmount receipts require the exact three-mount order")

    @classmethod
    def completed(
        cls,
        *,
        root: LifecycleV2Root,
        projection: LifecycleV2EmptySecretMountProjection,
        authorization: LifecycleV2TerminalCleanupAuthorization,
        completed_boottime_ns: object,
    ) -> Self:
        exact_root = _exact_root(root)
        if type(projection) is not LifecycleV2EmptySecretMountProjection:
            _reject("unmount receipt requires the complete empty-mount projection")
        projection_metadata = _require_canonical_evidence(projection)
        authorization_metadata = _require_terminal_cleanup_authorization(authorization)
        if (
            authorization.root_sha256 != exact_root.sha256
            or projection_metadata.provenance != authorization_metadata.provenance
            or projection_metadata.scope_sha256 != authorization_metadata.scope_sha256
        ):
            _reject("unmount receipt crossed its cleanup authorization")
        projection_fields = projection.to_dict()
        if (
            projection_fields["environment"] != exact_root.environment
            or projection_fields["graceful_stop_operation_id"]
            != exact_root.graceful_stop_operation_id
            or projection_fields["lifecycle_root_sha256"] != exact_root.sha256
        ):
            _reject("unmount receipt crossed its empty-mount projection root")
        if type(completed_boottime_ns) not in {tuple, list}:
            _reject("unmount receipt requires three ordered completion samples")
        times = tuple(cast(tuple[object, ...] | list[object], completed_boottime_ns))
        if len(times) != 3:
            _reject("unmount receipt requires exactly three completion samples")
        parsed = tuple(_require_int(value, "completed_boottime_ns") for value in times)
        if not (
            authorization.authorized_boottime_ns
            < parsed[0]
            <= parsed[1]
            <= parsed[2]
            < exact_root.operation_deadline_boottime_ns
        ):
            _reject("unmount completion order is reversed or equality-expired")
        by_path = {mount.to_dict()["path"]: mount for mount in projection.mounts}
        ordered_paths = (
            SUPERVISOR_SECRET_MOUNT_PATH,
            HOST_SECRET_MOUNT_PATH,
            TRANSPORT_MOUNT_PATH,
        )
        results = [
            {
                "mount_id": by_path[path].to_dict()["mount_id"],
                "unmounted": True,
                "mount_absent": True,
                "completed_boottime_ns": parsed[index],
            }
            for index, path in enumerate(ordered_paths)
        ]
        fields = FrozenJsonObject.capture(
            {
                "environment": exact_root.environment,
                "graceful_stop_operation_id": exact_root.graceful_stop_operation_id,
                "lifecycle_root_sha256": exact_root.sha256,
                "mounts": results,
            }
        )
        result = object.__new__(cls)
        object.__setattr__(result, "fields", fields)
        object.__setattr__(
            result,
            "authorization_intent_sha256",
            authorization.cleanup_intent_sha256,
        )
        consumed_metadata = _consume_terminal_cleanup_unmount_authorization(
            authorization,
            authorization._snapshot(),
        )
        if consumed_metadata != authorization_metadata:
            _reject("unmount receipt changed cleanup authorization")
        return result

    @property
    def completed_boottime_ns(self) -> int:
        mounts = cast(list[dict[str, object]], self.to_dict()["mounts"])
        return cast(int, mounts[-1]["completed_boottime_ns"])

    @property
    def digest_domain(self) -> str:
        return "AutoQuantTrader/trusted-time/graceful-stop/secret-mount-unmount-receipt/v2"


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2NativeOwnerCleanupReceipt(_CanonicalEvidence):
    fields: FrozenJsonObject
    authorization_intent_sha256: str

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("native owner cleanup receipts require an exact owner set")

    @classmethod
    def completed(
        cls,
        *,
        root: LifecycleV2Root,
        owners: LifecycleV2NativeOwnerSet,
        authorization: LifecycleV2TerminalCleanupAuthorization,
        completed_boottime_ns: int,
    ) -> Self:
        exact_root = _exact_root(root)
        if type(owners) is not LifecycleV2NativeOwnerSet:
            _reject("native cleanup receipt requires one exact native owner set")
        if owners.root_sha256 != exact_root.sha256:
            _reject("native cleanup receipt crossed its owner-set root")
        owner_metadata = _require_canonical_evidence(owners)
        authorization_metadata = _require_terminal_cleanup_authorization(authorization)
        if (
            authorization.root_sha256 != exact_root.sha256
            or owner_metadata.provenance != authorization_metadata.provenance
            or owner_metadata.scope_sha256 != authorization_metadata.scope_sha256
        ):
            _reject("native cleanup receipt crossed its cleanup authorization")
        completed = _require_int(completed_boottime_ns, "completed_boottime_ns")
        if not (
            authorization.authorized_boottime_ns
            < completed
            < exact_root.operation_deadline_boottime_ns
        ):
            _reject("native owner cleanup is equality-expired or late")
        fields = FrozenJsonObject.capture(
            {
                "environment": exact_root.environment,
                "graceful_stop_operation_id": exact_root.graceful_stop_operation_id,
                "lifecycle_root_sha256": exact_root.sha256,
                "channel_id": exact_root.channel_id,
                "host_process_epoch_sha256": exact_root.host_process_epoch_sha256,
                "supervisor_process_epoch_sha256": exact_root.supervisor_process_epoch_sha256,
                "native_owner_set_sha256": owners.sha256,
                "owner_count_before": owners.owner_count,
                "owner_count_after": 0,
                "every_owner_invalidated": True,
                "every_private_buffer_zeroized_or_process_destroyed": True,
                "completed_boottime_ns": completed,
            }
        )
        result = object.__new__(cls)
        object.__setattr__(result, "fields", fields)
        object.__setattr__(
            result,
            "authorization_intent_sha256",
            authorization.cleanup_intent_sha256,
        )
        consumed_metadata = _consume_terminal_cleanup_native_owner_authorization(
            authorization,
            authorization._snapshot(),
        )
        if consumed_metadata != authorization_metadata:
            _reject("native cleanup receipt changed cleanup authorization")
        return result

    @property
    def completed_boottime_ns(self) -> int:
        return cast(int, self.to_dict()["completed_boottime_ns"])

    @property
    def digest_domain(self) -> str:
        return "AutoQuantTrader/trusted-time/graceful-stop/native-owner-cleanup-receipt/v2"


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2TerminalCleanupPlan:
    evidence: FrozenJsonObject
    mounts: tuple[LifecycleV2EmptySecretMountIdentity, ...]
    recovery_absence: LifecycleV2PathAbsence
    socket_absence: LifecycleV2PathAbsence
    credential_absence: LifecycleV2PathAbsence
    owners: LifecycleV2NativeOwnerSet
    authorization: LifecycleV2TerminalCleanupAuthorization

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("terminal cleanup plans require exact prior lifecycle evidence")

    def _require_sealed(self) -> RuntimeSealMetadata:
        return cast(RuntimeSealMetadata, _require_exact_compound_value(self))


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2TerminalCleanupResult:
    evidence: FrozenJsonObject
    empty_mounts: LifecycleV2EmptySecretMountProjection
    unmount_receipt: LifecycleV2SecretMountUnmountReceipt
    native_owner_receipt: LifecycleV2NativeOwnerCleanupReceipt
    recovery_absence: LifecycleV2PathAbsence
    socket_absence: LifecycleV2PathAbsence
    credential_absence: LifecycleV2PathAbsence
    authorization: LifecycleV2TerminalCleanupAuthorization

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("terminal cleanup results require exact typed cleanup evidence")

    def _require_sealed(self) -> RuntimeSealMetadata:
        return cast(RuntimeSealMetadata, _require_exact_compound_value(self))


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2ConfirmedSuccessLineageSnapshot:
    """Repository-facing, one-shot snapshot of the exact sealed ordinal-22 lineage."""

    root: LifecycleV2Root
    records: tuple[LifecycleV2ProgressRecord, ...]
    root_encoded: bytes
    record_encoded: tuple[bytes, ...]
    lineage_provenance: str
    lineage_snapshot_sha256: str
    terminal_cleanup_result: LifecycleV2TerminalCleanupResult
    terminal_cleanup_result_snapshot_sha256: str

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("confirmed-success snapshots require one-shot lineage consumption")


def _confirmed_success_snapshot(value: Any) -> str:
    root = value.root
    records = value.records
    root_encoded = value.root_encoded
    record_encoded = value.record_encoded
    lineage_provenance = value.lineage_provenance
    lineage_digest = value.lineage_snapshot_sha256
    cleanup_result = value.terminal_cleanup_result
    cleanup_result_digest = value.terminal_cleanup_result_snapshot_sha256
    if (
        type(root) is not LifecycleV2Root
        or type(records) is not tuple
        or type(root_encoded) is not bytes
        or type(record_encoded) is not tuple
        or any(type(item) is not bytes for item in record_encoded)
        or type(lineage_provenance) is not str
        or type(lineage_digest) is not str
        or type(cleanup_result) is not LifecycleV2TerminalCleanupResult
        or type(cleanup_result_digest) is not str
        or root_encoded != root.encoded
        or record_encoded != tuple(record.encoded for record in records)
        or cleanup_result_digest != _semantic_runtime_snapshot(cleanup_result)
    ):
        _reject("confirmed-success lineage snapshot is malformed")
    return _domain_sha256(
        "AutoQuantTrader/trusted-time/graceful-stop/confirmed-success-lineage-snapshot/v2",
        {
            "root_encoded_sha256": _sha256(root_encoded),
            "record_encoded_sha256_list": [_sha256(item) for item in record_encoded],
            "lineage_provenance": lineage_provenance,
            "lineage_snapshot_sha256": lineage_digest,
            "terminal_cleanup_result_snapshot_sha256": cleanup_result_digest,
        },
    )


@dataclass(frozen=True, slots=True)
class _StageSpec:
    ordinal: int
    stage: LifecycleV2Stage
    effect_kind: str


_SPECS = MappingProxyType(
    {
        3: _StageSpec(
            3,
            LifecycleV2Stage.TRANSPORT_CLEANUP_COMMITMENT_RETAINED,
            "transport_cleanup_commitment",
        ),
        4: _StageSpec(4, LifecycleV2Stage.TRANSPORT_CHANNEL_QUIESCED, "transport_cleanup"),
        5: _StageSpec(
            5,
            LifecycleV2Stage.PRE_EFFECT_REAUTHENTICATION_INTENT_RETAINED,
            "pre_effect_reauthentication",
        ),
        6: _StageSpec(
            6, LifecycleV2Stage.PRE_EFFECT_REAUTHENTICATION_BOUND, "pre_effect_reauthentication"
        ),
        7: _StageSpec(
            7,
            LifecycleV2Stage.SUPERVISOR_CONTAINER_STOP_INTENT_RETAINED,
            "supervisor_container_stop",
        ),
        8: _StageSpec(
            8,
            LifecycleV2Stage.SUPERVISOR_CONTAINER_STOP_RESULT_RETAINED,
            "supervisor_container_stop",
        ),
        9: _StageSpec(
            9, LifecycleV2Stage.SOURCE_CONTAINER_STOP_INTENT_RETAINED, "source_container_stop"
        ),
        10: _StageSpec(
            10, LifecycleV2Stage.SOURCE_CONTAINER_STOP_RESULT_RETAINED, "source_container_stop"
        ),
        11: _StageSpec(
            11,
            LifecycleV2Stage.SUPERVISOR_CONTAINER_REMOVE_INTENT_RETAINED,
            "supervisor_container_remove",
        ),
        12: _StageSpec(
            12,
            LifecycleV2Stage.SUPERVISOR_CONTAINER_REMOVE_RESULT_RETAINED,
            "supervisor_container_remove",
        ),
        13: _StageSpec(
            13, LifecycleV2Stage.SOURCE_CONTAINER_REMOVE_INTENT_RETAINED, "source_container_remove"
        ),
        14: _StageSpec(
            14, LifecycleV2Stage.SOURCE_CONTAINER_REMOVE_RESULT_RETAINED, "source_container_remove"
        ),
        15: _StageSpec(
            15, LifecycleV2Stage.PROJECT_NETWORK_REMOVE_INTENT_RETAINED, "project_network_remove"
        ),
        16: _StageSpec(
            16, LifecycleV2Stage.PROJECT_NETWORK_REMOVE_RESULT_RETAINED, "project_network_remove"
        ),
        17: _StageSpec(
            17,
            LifecycleV2Stage.NAMED_VOLUME_PRESERVATION_INTENT_RETAINED,
            "named_volume_preservation",
        ),
        18: _StageSpec(18, LifecycleV2Stage.NAMED_VOLUMES_PRESERVED, "named_volume_preservation"),
        19: _StageSpec(
            19,
            LifecycleV2Stage.POST_TEARDOWN_REAUTHENTICATION_INTENT_RETAINED,
            "post_teardown_reauthentication",
        ),
        20: _StageSpec(
            20,
            LifecycleV2Stage.POST_TEARDOWN_TERMINAL_REAUTHENTICATION_BOUND,
            "post_teardown_reauthentication",
        ),
        21: _StageSpec(21, LifecycleV2Stage.TERMINAL_CLEANUP_INTENT_RETAINED, "terminal_cleanup"),
        22: _StageSpec(22, LifecycleV2Stage.TERMINAL_CLEANUP_CONFIRMED, "terminal_cleanup"),
    }
)


@dataclass(frozen=True, slots=True)
class _DockerRule:
    intent_ordinal: int
    result_ordinal: int
    primary_connection_ordinal: int
    result_kind: str
    target_kind: str
    target_id_attribute: str


_DOCKER_RULES = MappingProxyType(
    {
        "supervisor_stop": _DockerRule(
            7, 8, 6, "container_stop", "container", "supervisor_container_id"
        ),
        "source_stop": _DockerRule(9, 10, 8, "container_stop", "container", "source_container_id"),
        "supervisor_remove": _DockerRule(
            11, 12, 10, "container_remove", "container", "supervisor_container_id"
        ),
        "source_remove": _DockerRule(
            13, 14, 12, "container_remove", "container", "source_container_id"
        ),
        "network_remove": _DockerRule(
            15, 16, 14, "network_remove", "network", "project_network_id"
        ),
    }
)


def _docker_trace_runtime_snapshot(value: object) -> str:
    if type(value) is not DockerAdmissionRootedTracePrefix:
        _reject("normal lifecycle Docker trace type is not exact")
    value._require_sealed()
    admission = object.__getattribute__(value, "_admission")
    entries = object.__getattribute__(value, "_entries")
    if type(admission) is not DockerAdmissionCapture or type(entries) is not tuple:
        _reject("normal lifecycle Docker trace sidecars are malformed")
    for entry in entries:
        if type(entry) is not DockerOrdinalEvidence:
            _reject("normal lifecycle Docker trace entry type is not exact")
        entry._validate()
    return _domain_sha256(
        "AutoQuantTrader/trusted-time/graceful-stop/runtime-docker-trace-seal/v2",
        {
            "admission": admission.to_dict(),
            "entry_list": [
                {
                    "request": entry.request.to_dict(),
                    "connection": entry.connection.to_dict(),
                    "exchange": entry.exchange.to_dict(),
                    "trace": entry.trace.to_dict(),
                }
                for entry in entries
            ],
        },
    )


def _semantic_runtime_snapshot(value: Any) -> str:
    if type(value) is LifecycleV2CleanStopResult:
        exact = decode_lifecycle_v2_clean_stop_result(value.encoded)
        if exact != value:
            _reject("retained clean-stop result changed under revalidation")
        body: object = exact.to_dict()
    elif type(value) in {DockerMutationResultSemantic, DockerVolumePreservationResult}:
        body = value.to_dict()
    elif isinstance(value, _CanonicalEvidence):
        _require_canonical_evidence(value)
        body = value.to_dict()
    elif type(value) is LifecycleV2TransportCleanupPlan:
        _require_exact_compound_value(value)
        value.host_identity.to_dict()
        decode_lifecycle_v2_clean_stop_result(value.clean_stop_result.encoded)
        body = {
            "compound": _compound_value_snapshot(value),
            "host_identity": value.host_identity.to_dict(),
            "supervisor_commitment": value.supervisor_commitment.to_dict(),
        }
    elif type(value) is LifecycleV2TransportQuiescence:
        _require_exact_compound_value(value)
        body = {
            "compound": _compound_value_snapshot(value),
            "observation": value.observation.to_dict(),
            "host_receipt": value.host_receipt.to_dict(),
        }
    elif type(value) is LifecycleV2TerminalCleanupPlan:
        _require_exact_compound_value(value)
        _require_terminal_cleanup_authorization(value.authorization)
        body = {
            "compound": _compound_value_snapshot(value),
            "mount_list": [item.to_dict() for item in value.mounts],
            "recovery_absence": value.recovery_absence.to_dict(),
            "socket_absence": value.socket_absence.to_dict(),
            "credential_absence": value.credential_absence.to_dict(),
            "owners": value.owners.to_dict(),
            "authorization": value.authorization._snapshot(),
        }
    elif type(value) is LifecycleV2TerminalCleanupResult:
        _require_exact_compound_value(value)
        _require_terminal_cleanup_authorization(value.authorization)
        body = {
            "compound": _compound_value_snapshot(value),
            "empty_mounts": value.empty_mounts.to_dict(),
            "unmount_receipt": value.unmount_receipt.to_dict(),
            "native_owner_receipt": value.native_owner_receipt.to_dict(),
            "recovery_absence": value.recovery_absence.to_dict(),
            "socket_absence": value.socket_absence.to_dict(),
            "credential_absence": value.credential_absence.to_dict(),
            "authorization": value.authorization._snapshot(),
        }
    else:
        _reject("normal lifecycle retained an unsupported semantic type")
    return _domain_sha256(
        "AutoQuantTrader/trusted-time/graceful-stop/runtime-retained-semantic-seal/v2",
        {
            "type": f"{type(value).__module__}.{type(value).__qualname__}",
            "body": body,
        },
    )


def _lineage_snapshot(value: Any) -> str:
    root = value.root
    records = value.records
    semantics = value.semantics
    if (
        type(root) is not LifecycleV2Root
        or type(records) is not tuple
        or type(semantics) is not tuple
        or len(records) != len(semantics)
    ):
        _reject("normal lifecycle lineage snapshot is malformed")
    return _domain_sha256(
        "AutoQuantTrader/trusted-time/graceful-stop/runtime-normal-lineage-seal/v2",
        {
            "root": root.to_dict(),
            "record_list": [record.to_dict() for record in records],
            "semantic_snapshot_sha256_list": [
                _semantic_runtime_snapshot(item) for item in semantics
            ],
            "terminal_wire": value.terminal_wire.to_dict(),
            "clean_stop_result": value.clean_stop_result.to_dict(),
            "docker_admission": (
                None if value.docker_admission is None else value.docker_admission.to_dict()
            ),
            "docker_trace_snapshot_sha256": (
                None
                if value.docker_trace is None
                else _docker_trace_runtime_snapshot(value.docker_trace)
            ),
            "pre_effect_binding_snapshot_sha256": (
                None
                if value.pre_effect_binding is None
                else _semantic_runtime_snapshot(value.pre_effect_binding)
            ),
            "prefix_through_eighteen": (
                None
                if value.prefix_through_eighteen is None
                else decode_lifecycle_v2_transcript(value.prefix_through_eighteen.encoded).to_dict()
            ),
            "terminal_cleanup_plan_snapshot_sha256": (
                None
                if value.terminal_cleanup_plan is None
                else _semantic_runtime_snapshot(value.terminal_cleanup_plan)
            ),
            "terminal_cleanup_authorization_snapshot_sha256": (
                None
                if value.terminal_cleanup_authorization is None
                else value.terminal_cleanup_authorization._snapshot()
            ),
        },
    )


def _populate_lineage_result(
    result: LifecycleV2NormalProgressLineage,
    source: LifecycleV2NormalProgressLineage,
    *,
    record: LifecycleV2ProgressRecord,
    semantic: object,
    docker_admission: DockerAdmissionCapture | None = None,
    docker_trace: DockerAdmissionRootedTracePrefix | None = None,
    pre_effect_binding: LifecycleV2AuthenticatedReauthenticationBinding | None = None,
    prefix_through_eighteen: LifecycleV2Transcript | None = None,
    terminal_cleanup_plan: LifecycleV2TerminalCleanupPlan | None = None,
    terminal_cleanup_authorization: LifecycleV2TerminalCleanupAuthorization | None = None,
) -> None:
    """Populate state only; this helper never registers or authorizes a lineage."""

    object.__setattr__(result, "root", source.root)
    object.__setattr__(result, "records", (*source.records, record))
    object.__setattr__(result, "semantics", (*source.semantics, semantic))
    object.__setattr__(result, "terminal_wire", source.terminal_wire)
    object.__setattr__(result, "clean_stop_result", source.clean_stop_result)
    object.__setattr__(
        result,
        "docker_admission",
        source.docker_admission if docker_admission is None else docker_admission,
    )
    object.__setattr__(
        result,
        "docker_trace",
        source.docker_trace if docker_trace is None else docker_trace,
    )
    object.__setattr__(
        result,
        "pre_effect_binding",
        source.pre_effect_binding if pre_effect_binding is None else pre_effect_binding,
    )
    object.__setattr__(
        result,
        "prefix_through_eighteen",
        source.prefix_through_eighteen
        if prefix_through_eighteen is None
        else prefix_through_eighteen,
    )
    object.__setattr__(
        result,
        "terminal_cleanup_plan",
        source.terminal_cleanup_plan if terminal_cleanup_plan is None else terminal_cleanup_plan,
    )
    object.__setattr__(
        result,
        "terminal_cleanup_authorization",
        source.terminal_cleanup_authorization
        if terminal_cleanup_authorization is None
        else terminal_cleanup_authorization,
    )


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2NormalProgressLineage:
    """Sealed, immutable normal lineage beginning at authenticated ordinal two."""

    root: LifecycleV2Root
    records: tuple[LifecycleV2ProgressRecord, ...]
    semantics: tuple[object, ...]
    terminal_wire: LifecycleV2TerminalWireEvidence
    clean_stop_result: LifecycleV2CleanStopResult
    docker_admission: DockerAdmissionCapture | None
    docker_trace: DockerAdmissionRootedTracePrefix | None
    pre_effect_binding: LifecycleV2AuthenticatedReauthenticationBinding | None
    prefix_through_eighteen: LifecycleV2Transcript | None
    terminal_cleanup_plan: LifecycleV2TerminalCleanupPlan | None
    terminal_cleanup_authorization: LifecycleV2TerminalCleanupAuthorization | None

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("normal progress lineages require authenticated ordinal-two evidence")

    @classmethod
    def from_retained_result(
        cls,
        *,
        root: LifecycleV2Root,
        result_record: LifecycleV2ProgressRecord,
        terminal_wire_evidence: LifecycleV2TerminalWireEvidence,
        clean_stop_result: LifecycleV2CleanStopResult,
    ) -> Self:
        exact_root = _exact_root(root)
        exact_record = _exact_record(result_record)
        if type(clean_stop_result) is not LifecycleV2CleanStopResult:
            _reject("normal lineage requires one exact clean-stop result")
        exact_result = decode_lifecycle_v2_clean_stop_result(clean_stop_result.encoded)
        if (
            type(terminal_wire_evidence) is not LifecycleV2TerminalWireEvidence
            or exact_record.ordinal != 2
            or exact_record.stage is not LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED
            or exact_record.effect_kind != "clean_stop_result"
            or exact_record.deadline_boottime_ns != exact_root.operation_deadline_boottime_ns
            or exact_record.root_sha256 != exact_root.sha256
            or exact_record.graceful_stop_operation_id != exact_root.graceful_stop_operation_id
            or exact_record.evidence != FrozenJsonObject.capture(terminal_wire_evidence.to_dict())
            or exact_record.predecessor_sha256 != terminal_wire_evidence.to_dict()["intent_sha256"]
            or terminal_wire_evidence.to_dict()["clean_stop_result_payload_sha256"]
            != _sha256(exact_result.encoded)
            or exact_result.to_dict()["lifecycle_root_sha256"] != exact_root.sha256
        ):
            _reject("normal lineage does not begin at one exact authenticated result")
        result = object.__new__(cls)
        object.__setattr__(result, "root", exact_root)
        object.__setattr__(result, "records", (exact_record,))
        object.__setattr__(result, "semantics", (exact_result,))
        object.__setattr__(result, "terminal_wire", terminal_wire_evidence)
        object.__setattr__(result, "clean_stop_result", exact_result)
        object.__setattr__(result, "docker_admission", None)
        object.__setattr__(result, "docker_trace", None)
        object.__setattr__(result, "pre_effect_binding", None)
        object.__setattr__(result, "prefix_through_eighteen", None)
        object.__setattr__(result, "terminal_cleanup_plan", None)
        object.__setattr__(result, "terminal_cleanup_authorization", None)
        return result

    def _require_sealed(self, *, allow_consumed: bool = True) -> RuntimeSealMetadata:
        try:
            snapshot = _lineage_snapshot(self)
        except (AttributeError, TypeError, TrustedTimeGracefulStopV2Rejected):
            _reject("normal lifecycle lineage is not sealed")
        metadata = _require_exact_normal_progress_lineage_runtime(
            self,
            snapshot,
            self.root.sha256,
            allow_consumed,
        )
        if metadata is None:
            _reject("normal lifecycle lineage is not sealed or was already advanced")
        return cast(RuntimeSealMetadata, metadata)

    @property
    def last_record(self) -> LifecycleV2ProgressRecord:
        self._require_sealed()
        return self.records[-1]

    def record_at(self, ordinal: int) -> LifecycleV2ProgressRecord:
        self._require_sealed()
        _require_int(ordinal, "ordinal", minimum=2, maximum=22)
        for record in self.records:
            if record.ordinal == ordinal:
                return record
        _reject("requested ordinal is not retained in this lineage")

    def semantic_at(self, ordinal: int) -> object:
        self._require_sealed()
        _require_int(ordinal, "ordinal", minimum=2, maximum=22)
        for record, semantic in zip(self.records, self.semantics, strict=True):
            if record.ordinal == ordinal:
                return semantic
        _reject("requested ordinal semantic is not retained in this lineage")

    def _build_unregistered_stage_state(
        self,
        *,
        evidence: FrozenJsonObject,
        semantic: object,
        recorded_at_utc: str,
        docker_admission: DockerAdmissionCapture | None = None,
        docker_trace: DockerAdmissionRootedTracePrefix | None = None,
        pre_effect_binding: LifecycleV2AuthenticatedReauthenticationBinding | None = None,
        prefix_through_eighteen: LifecycleV2Transcript | None = None,
        terminal_cleanup_plan: LifecycleV2TerminalCleanupPlan | None = None,
        terminal_cleanup_authorization: LifecycleV2TerminalCleanupAuthorization | None = None,
    ) -> Self:
        """Build inert state; only named transition wrappers can register it."""

        self._require_sealed()
        previous = self.last_record
        spec = _SPECS.get(previous.ordinal + 1)
        if spec is None:
            _reject("normal lifecycle has no further progress stage")
        _require_utc(recorded_at_utc, "recorded_at_utc")
        record = LifecycleV2ProgressRecord(
            graceful_stop_operation_id=self.root.graceful_stop_operation_id,
            root_sha256=self.root.sha256,
            ordinal=spec.ordinal,
            stage=spec.stage,
            predecessor_sha256=previous.sha256,
            effect_kind=spec.effect_kind,
            deadline_boottime_ns=self.root.operation_deadline_boottime_ns,
            evidence=evidence,
            recorded_at_utc=recorded_at_utc,
        )
        result = object.__new__(type(self))
        _populate_lineage_result(
            result,
            self,
            record=record,
            semantic=semantic,
            docker_admission=docker_admission,
            docker_trace=docker_trace,
            pre_effect_binding=pre_effect_binding,
            prefix_through_eighteen=prefix_through_eighteen,
            terminal_cleanup_plan=terminal_cleanup_plan,
            terminal_cleanup_authorization=terminal_cleanup_authorization,
        )
        return result

    def retain_transport_cleanup_commitment(
        self,
        *,
        plan: LifecycleV2TransportCleanupPlan,
        recorded_at_utc: str,
    ) -> Self:
        if (
            self.last_record.ordinal != 2
            or type(plan) is not LifecycleV2TransportCleanupPlan
            or plan.clean_stop_result != self.clean_stop_result
        ):
            _reject("transport cleanup commitment is not the fixed ordinal-three input")
        plan._require_sealed()
        return self._build_unregistered_stage_state(
            evidence=plan.evidence,
            semantic=plan,
            recorded_at_utc=recorded_at_utc,
        )

    def confirm_transport_channel_quiesced(
        self,
        *,
        quiescence: LifecycleV2TransportQuiescence,
        recorded_at_utc: str,
    ) -> Self:
        if self.last_record.ordinal != 3 or type(quiescence) is not LifecycleV2TransportQuiescence:
            _reject("transport quiescence is not the fixed ordinal-four input")
        quiescence._require_sealed()
        plan = self.semantic_at(3)
        if type(plan) is not LifecycleV2TransportCleanupPlan:
            _reject("ordinal-three cleanup plan sidecar is absent")
        expected = LifecycleV2TransportQuiescence.confirm(
            root=self.root,
            cleanup_record=self.last_record,
            plan=plan,
            observation=quiescence.observation,
            host_receipt=quiescence.host_receipt,
        )
        if expected.evidence != quiescence.evidence:
            _reject("transport quiescence evidence changed after typed confirmation")
        return self._build_unregistered_stage_state(
            evidence=quiescence.evidence,
            semantic=quiescence,
            recorded_at_utc=recorded_at_utc,
        )

    def retain_pre_effect_reauthentication_intent(
        self,
        *,
        provider_identity_sha256: str,
        call_deadline_boottime_ns: int,
        recorded_at_utc: str,
    ) -> Self:
        if self.last_record.ordinal != 4:
            _reject("pre-effect reauthentication intent is not ordinal five")
        quiescence = self.semantic_at(4)
        if type(quiescence) is not LifecycleV2TransportQuiescence:
            _reject("pre-effect intent lacks typed transport quiescence")
        provider = _require_sha256(provider_identity_sha256, "provider_identity_sha256")
        deadline = _require_int(call_deadline_boottime_ns, "call_deadline_boottime_ns")
        not_before = cast(int, quiescence.evidence.to_dict()["cleanup_completed_boottime_ns"])
        if not_before > MAXIMUM_SIGNED_INTEGER - 120_000_000_000:
            _reject("pre-effect reauthentication deadline addition overflows")
        expected_deadline = min(
            not_before + 120_000_000_000,
            self.root.operation_deadline_boottime_ns,
        )
        if deadline != expected_deadline or deadline <= not_before:
            _reject("pre-effect reauthentication deadline is not the exact 120-second bound")
        terminal = self.clean_stop_result.to_dict()
        projection = self.clean_stop_result.terminal_projection.to_dict()
        intent = LifecycleV2ReauthenticationIntent._capture_fixed(
            {
                "contract_version": (
                    "phase6d-trusted-time-graceful-stop-pre-effect-reauthentication-intent-v2"
                ),
                "service": LIFECYCLE_V2_CLEANUP_SERVICE,
                "status": "pre_effect_reauthentication_requested",
                "environment": self.root.environment,
                "graceful_stop_operation_id": self.root.graceful_stop_operation_id,
                "lifecycle_root_sha256": self.root.sha256,
                "boundary": "pre_effect",
                "request_sha256": terminal["request_sha256"],
                "clean_stop_result_sha256": self.terminal_wire.to_dict()[
                    "clean_stop_result_sha256"
                ],
                "clean_stop_terminal_semantic_sha256": projection[
                    "clean_stop_terminal_result_semantic_sha256"
                ],
                "transport_quiescence_record_sha256": self.last_record.sha256,
                "channel_id": self.root.channel_id,
                "topology_sha256": self.root.topology_sha256,
                "expected_head_sha256": projection["current_anchor_sha256"],
                "provider_identity_sha256": provider,
                "observation_not_before_boottime_ns": not_before,
                "call_deadline_boottime_ns": deadline,
            },
            boundary="pre_effect",
        )
        evidence = FrozenJsonObject.capture(
            {
                "target_identity_sha256": projection["current_anchor_sha256"],
                "arguments_sha256": intent.sha256,
                "admission_sha256": self.root.admission_sha256,
                "channel_id": self.root.channel_id,
                "call_deadline_boottime_ns": deadline,
            }
        )
        return self._build_unregistered_stage_state(
            evidence=evidence,
            semantic=intent,
            recorded_at_utc=recorded_at_utc,
        )

    def retain_pre_effect_reauthentication_binding(
        self,
        *,
        binding: LifecycleV2AuthenticatedReauthenticationBinding,
        recorded_at_utc: str,
    ) -> Self:
        if (
            self.last_record.ordinal != 5
            or type(binding) is not LifecycleV2AuthenticatedReauthenticationBinding
        ):
            _reject("pre-effect binding is not the fixed ordinal-six input")
        binding._require_sealed()
        intent = self.semantic_at(5)
        if (
            type(intent) is not LifecycleV2ReauthenticationIntent
            or binding.boundary != "pre_effect"
            or binding.to_dict()["intent_semantic_sha256"] != intent.sha256
        ):
            _reject("pre-effect binding crossed its exact ordinal-five intent")
        fields = binding.to_dict()
        intent_fields = intent.to_dict()
        binding_evidence = binding.binding_evidence.to_dict()
        terminal_projection = self.clean_stop_result.terminal_projection.to_dict()
        if (
            binding_evidence["clean_stop_request_sha256"] != self.clean_stop_result.request.sha256
            or binding_evidence["clean_stop_result_sha256"] != self.clean_stop_result.sha256
            or binding_evidence["channel_id"] != self.root.channel_id
            or binding_evidence["expected_clean_stop_head_sha256"]
            != intent_fields["expected_head_sha256"]
            or binding_evidence["expected_clean_stop_terminal_result_semantic_sha256"]
            != terminal_projection["clean_stop_terminal_result_semantic_sha256"]
            or binding_evidence["topology_sha256"] != self.root.topology_sha256
            or binding_evidence["topology_lease_sha256"] != self.root.topology_lease_sha256
            or binding_evidence["transport_quiescence_record_sha256"] != self.record_at(4).sha256
            or binding_evidence["pre_effect_intent_sha256"] != self.last_record.sha256
        ):
            _reject("pre-effect binding evidence crossed its exact lifecycle prefix")
        evidence = FrozenJsonObject.capture(
            {
                "intent_sha256": self.last_record.sha256,
                "responder_identity_sha256": fields["issuer_identity_sha256"],
                "disposition": "pre_effect_reauthentication_bound",
                "result_semantic_sha256": binding.sha256,
                "call_started_boottime_ns": fields["observation_started_boottime_ns"],
                "call_completed_boottime_ns": fields["observation_completed_boottime_ns"],
                "observation_semantic_sha256": fields["observation_semantic_sha256"],
                "binding_semantic_sha256": binding.sha256,
                "observed_head_sha256": fields["observed_head_sha256"],
                "provider_identity_sha256": fields["provider_identity_sha256"],
                "channel_id": fields["channel_id"],
                "intent_semantic_sha256": fields["intent_semantic_sha256"],
                "binding_evidence": binding_evidence,
            }
        )
        return self._build_unregistered_stage_state(
            evidence=evidence,
            semantic=binding,
            recorded_at_utc=recorded_at_utc,
            pre_effect_binding=binding,
        )

    def _require_docker_admission(
        self,
        admission: DockerAdmissionCapture,
        trace: DockerAdmissionRootedTracePrefix,
        *,
        expected_last_ordinal: int,
    ) -> None:
        if (
            type(admission) is not DockerAdmissionCapture
            or type(trace) is not DockerAdmissionRootedTracePrefix
        ):
            _reject("Docker lifecycle stage requires exact admission-rooted trace evidence")
        fields = admission.to_dict()
        exchanges = cast(list[dict[str, object]], fields["ordered_http_exchange_list"])
        if (
            fields["environment"] != self.root.environment
            or fields["graceful_stop_operation_id"] != self.root.graceful_stop_operation_id
            or fields["channel_id"] != self.root.channel_id
            or exchanges[1]["target_identity"] != self.root.supervisor_container_id
            or exchanges[2]["target_identity"] != self.root.source_container_id
            or exchanges[3]["target_identity"] != self.root.project_network_id
            or fields["command_socket_volume_projection_sha256"]
            != self.root.chrony_command_socket_volume_identity_sha256
            or fields["state_volume_projection_sha256"]
            != self.root.chrony_state_volume_identity_sha256
            or trace.last_ordinal != expected_last_ordinal
            or trace.admission_sha256 != admission.sha256
        ):
            _reject("Docker admission or trace crossed the lifecycle root")
        if self.docker_admission is not None and self.docker_admission.sha256 != admission.sha256:
            _reject("Docker admission changed during the lifecycle")

    def _retain_docker_intent(
        self,
        *,
        rule: _DockerRule,
        admission: DockerAdmissionCapture,
        trace_prefix: DockerAdmissionRootedTracePrefix,
        call_deadline_boottime_ns: int,
        recorded_at_utc: str,
    ) -> Self:
        if (
            not any(rule is fixed_rule for fixed_rule in _DOCKER_RULES.values())
            or self.last_record.ordinal + 1 != rule.intent_ordinal
        ):
            _reject("Docker intent is not the one fixed next lifecycle stage")
        expected_prior_trace = rule.primary_connection_ordinal - 1
        self._require_docker_admission(
            admission, trace_prefix, expected_last_ordinal=expected_prior_trace
        )
        if self.docker_trace is not None and trace_prefix is not self.docker_trace:
            _reject("Docker intent substituted the exact prior trace object")
        if self.docker_admission is not None and admission is not self.docker_admission:
            _reject("Docker intent substituted the exact admitted capture object")
        deadline = _require_int(call_deadline_boottime_ns, "call_deadline_boottime_ns")
        prior_completed = cast(
            int,
            self.last_record.evidence.to_dict().get(
                "call_completed_boottime_ns",
                self.last_record.evidence.to_dict().get("cleanup_completed_boottime_ns", 0),
            ),
        )
        if not prior_completed < deadline <= self.root.operation_deadline_boottime_ns:
            _reject("Docker call deadline is not future-bounded")
        target_id = cast(str, getattr(self.root, rule.target_id_attribute))
        plan = DockerPlanIdentity(
            self.root.supervisor_container_id,
            self.root.source_container_id,
            self.root.project_network_id,
        )
        primary = DockerRequestSemantic.from_spec(
            docker_call_spec(rule.primary_connection_ordinal, plan)
        )
        post = DockerRequestSemantic.from_spec(
            docker_call_spec(rule.primary_connection_ordinal + 1, plan)
        )
        intent_value = {
            "contract_version": "phase6d-trusted-time-graceful-stop-docker-effect-intent-v2",
            "service": LIFECYCLE_V2_CLEANUP_SERVICE,
            "status": f"{rule.result_kind}_requested",
            "environment": self.root.environment,
            "graceful_stop_operation_id": self.root.graceful_stop_operation_id,
            "lifecycle_root_sha256": self.root.sha256,
            "admission_sha256": self.root.admission_sha256,
            "docker_admission_capture_sha256": admission.sha256,
            "result_kind": rule.result_kind,
            "target_kind": rule.target_kind,
            "target_id": target_id,
            "previous_trace_entry_sha256": trace_prefix.trace_head_sha256,
            "primary_connection_ordinal": rule.primary_connection_ordinal,
            "post_inspect_connection_ordinal": rule.primary_connection_ordinal + 1,
            "docker_request_semantic_sha256": primary.sha256,
            "docker_post_inspect_request_semantic_sha256": post.sha256,
            "call_deadline_boottime_ns": deadline,
        }
        intent = _FixedSemantic.capture(
            intent_value,
            "AutoQuantTrader/trusted-time/graceful-stop/docker-effect-intent/v2",
        )
        evidence = FrozenJsonObject.capture(
            {
                "target_identity_sha256": target_id,
                "arguments_sha256": intent.sha256,
                "admission_sha256": self.root.admission_sha256,
                "channel_id": self.root.channel_id,
                "call_deadline_boottime_ns": deadline,
                "docker_request_semantic_sha256": primary.sha256,
                "docker_post_inspect_request_semantic_sha256": post.sha256,
            }
        )
        return self._build_unregistered_stage_state(
            evidence=evidence,
            semantic=intent,
            recorded_at_utc=recorded_at_utc,
            docker_admission=admission,
            docker_trace=trace_prefix,
        )

    def _retain_docker_result(
        self,
        *,
        rule: _DockerRule,
        result_semantic: DockerMutationResultSemantic,
        trace_prefix: DockerAdmissionRootedTracePrefix,
        recorded_at_utc: str,
    ) -> Self:
        if (
            not any(rule is fixed_rule for fixed_rule in _DOCKER_RULES.values())
            or self.last_record.ordinal != rule.intent_ordinal
            or type(result_semantic) is not DockerMutationResultSemantic
            or self.docker_admission is None
            or self.docker_trace is None
        ):
            _reject("Docker result is not the fixed result for a retained intent")
        self._require_docker_admission(
            self.docker_admission,
            trace_prefix,
            expected_last_ordinal=rule.primary_connection_ordinal + 1,
        )
        fields = result_semantic.to_dict()
        intent = self.semantic_at(rule.intent_ordinal)
        if type(intent) is not _FixedSemantic:
            _reject("Docker result lacks its complete typed intent")
        intent_fields = intent.to_dict()
        traces = cast(list[str], fields["ordered_trace_entry_sha256_list"])
        trace_objects = cast(list[dict[str, object]], fields["ordered_trace_entry_list"])
        primary_connection = cast(dict[str, object], fields["primary_connection_identity"])
        post_connection = cast(dict[str, object], fields["post_inspect_connection_identity"])
        deadline = cast(int, self.last_record.evidence.to_dict()["call_deadline_boottime_ns"])
        prior_evidence = self.record_at(rule.intent_ordinal - 1).evidence.to_dict()
        prior_completed = cast(
            int,
            prior_evidence.get(
                "call_completed_boottime_ns",
                prior_evidence.get("cleanup_completed_boottime_ns", 0),
            ),
        )
        if not (
            fields["environment"] == self.root.environment
            and fields["graceful_stop_operation_id"] == self.root.graceful_stop_operation_id
            and fields["root_sha256"] == self.root.sha256
            and fields["docker_admission_capture_sha256"] == self.docker_admission.sha256
            and fields["result_kind"] == rule.result_kind
            and fields["target_kind"] == rule.target_kind
            and fields["target_id"] == getattr(self.root, rule.target_id_attribute)
            and fields["primary_request_semantic_sha256"]
            == intent_fields["docker_request_semantic_sha256"]
            and fields["post_inspect_request_semantic_sha256"]
            == intent_fields["docker_post_inspect_request_semantic_sha256"]
            and trace_objects[0]["previous_trace_entry_sha256"]
            == intent_fields["previous_trace_entry_sha256"]
            and traces[-1] == trace_prefix.trace_head_sha256
            and prior_completed
            <= cast(int, fields["call_started_boottime_ns"])
            <= cast(int, fields["call_completed_boottime_ns"])
            < deadline
            and cast(int, fields["call_completed_boottime_ns"])
            < self.root.operation_deadline_boottime_ns
            and cast(int, primary_connection["call_deadline_boottime_ns"]) <= deadline
            and cast(int, post_connection["call_deadline_boottime_ns"]) <= deadline
        ):
            _reject("Docker result crossed target, request, trace, or deadline")
        evidence = FrozenJsonObject.capture(
            {
                "intent_sha256": self.last_record.sha256,
                "responder_identity_sha256": fields["admitted_daemon_info_projection_sha256"],
                "disposition": fields["outcome"],
                "result_semantic_sha256": result_semantic.sha256,
                "call_started_boottime_ns": fields["call_started_boottime_ns"],
                "call_completed_boottime_ns": fields["call_completed_boottime_ns"],
                "docker_request_semantic_sha256": fields["primary_request_semantic_sha256"],
                "docker_post_inspect_request_semantic_sha256": fields[
                    "post_inspect_request_semantic_sha256"
                ],
                "result_semantic": fields,
                "docker_method_trace_entry_sha256_list": traces,
            }
        )
        return self._build_unregistered_stage_state(
            evidence=evidence,
            semantic=result_semantic,
            recorded_at_utc=recorded_at_utc,
            docker_trace=trace_prefix,
        )

    def retain_supervisor_container_stop_intent(
        self,
        *,
        admission: DockerAdmissionCapture,
        trace_prefix: DockerAdmissionRootedTracePrefix,
        call_deadline_boottime_ns: int,
        recorded_at_utc: str,
    ) -> Self:
        return self._retain_docker_intent(
            rule=_DOCKER_RULES["supervisor_stop"],
            admission=admission,
            trace_prefix=trace_prefix,
            call_deadline_boottime_ns=call_deadline_boottime_ns,
            recorded_at_utc=recorded_at_utc,
        )

    def retain_supervisor_container_stop_result(
        self,
        *,
        result_semantic: DockerMutationResultSemantic,
        trace_prefix: DockerAdmissionRootedTracePrefix,
        recorded_at_utc: str,
    ) -> Self:
        return self._retain_docker_result(
            rule=_DOCKER_RULES["supervisor_stop"],
            result_semantic=result_semantic,
            trace_prefix=trace_prefix,
            recorded_at_utc=recorded_at_utc,
        )

    def retain_source_container_stop_intent(
        self,
        *,
        admission: DockerAdmissionCapture,
        trace_prefix: DockerAdmissionRootedTracePrefix,
        call_deadline_boottime_ns: int,
        recorded_at_utc: str,
    ) -> Self:
        return self._retain_docker_intent(
            rule=_DOCKER_RULES["source_stop"],
            admission=admission,
            trace_prefix=trace_prefix,
            call_deadline_boottime_ns=call_deadline_boottime_ns,
            recorded_at_utc=recorded_at_utc,
        )

    def retain_source_container_stop_result(
        self,
        *,
        result_semantic: DockerMutationResultSemantic,
        trace_prefix: DockerAdmissionRootedTracePrefix,
        recorded_at_utc: str,
    ) -> Self:
        return self._retain_docker_result(
            rule=_DOCKER_RULES["source_stop"],
            result_semantic=result_semantic,
            trace_prefix=trace_prefix,
            recorded_at_utc=recorded_at_utc,
        )

    def retain_supervisor_container_remove_intent(
        self,
        *,
        admission: DockerAdmissionCapture,
        trace_prefix: DockerAdmissionRootedTracePrefix,
        call_deadline_boottime_ns: int,
        recorded_at_utc: str,
    ) -> Self:
        return self._retain_docker_intent(
            rule=_DOCKER_RULES["supervisor_remove"],
            admission=admission,
            trace_prefix=trace_prefix,
            call_deadline_boottime_ns=call_deadline_boottime_ns,
            recorded_at_utc=recorded_at_utc,
        )

    def retain_supervisor_container_remove_result(
        self,
        *,
        result_semantic: DockerMutationResultSemantic,
        trace_prefix: DockerAdmissionRootedTracePrefix,
        recorded_at_utc: str,
    ) -> Self:
        return self._retain_docker_result(
            rule=_DOCKER_RULES["supervisor_remove"],
            result_semantic=result_semantic,
            trace_prefix=trace_prefix,
            recorded_at_utc=recorded_at_utc,
        )

    def retain_source_container_remove_intent(
        self,
        *,
        admission: DockerAdmissionCapture,
        trace_prefix: DockerAdmissionRootedTracePrefix,
        call_deadline_boottime_ns: int,
        recorded_at_utc: str,
    ) -> Self:
        return self._retain_docker_intent(
            rule=_DOCKER_RULES["source_remove"],
            admission=admission,
            trace_prefix=trace_prefix,
            call_deadline_boottime_ns=call_deadline_boottime_ns,
            recorded_at_utc=recorded_at_utc,
        )

    def retain_source_container_remove_result(
        self,
        *,
        result_semantic: DockerMutationResultSemantic,
        trace_prefix: DockerAdmissionRootedTracePrefix,
        recorded_at_utc: str,
    ) -> Self:
        return self._retain_docker_result(
            rule=_DOCKER_RULES["source_remove"],
            result_semantic=result_semantic,
            trace_prefix=trace_prefix,
            recorded_at_utc=recorded_at_utc,
        )

    def retain_project_network_remove_intent(
        self,
        *,
        admission: DockerAdmissionCapture,
        trace_prefix: DockerAdmissionRootedTracePrefix,
        call_deadline_boottime_ns: int,
        recorded_at_utc: str,
    ) -> Self:
        return self._retain_docker_intent(
            rule=_DOCKER_RULES["network_remove"],
            admission=admission,
            trace_prefix=trace_prefix,
            call_deadline_boottime_ns=call_deadline_boottime_ns,
            recorded_at_utc=recorded_at_utc,
        )

    def retain_project_network_remove_result(
        self,
        *,
        result_semantic: DockerMutationResultSemantic,
        trace_prefix: DockerAdmissionRootedTracePrefix,
        recorded_at_utc: str,
    ) -> Self:
        return self._retain_docker_result(
            rule=_DOCKER_RULES["network_remove"],
            result_semantic=result_semantic,
            trace_prefix=trace_prefix,
            recorded_at_utc=recorded_at_utc,
        )

    def retain_named_volume_preservation_intent(
        self,
        *,
        call_deadline_boottime_ns: int,
        recorded_at_utc: str,
    ) -> Self:
        if (
            self.last_record.ordinal != 16
            or self.docker_admission is None
            or self.docker_trace is None
        ):
            _reject("volume preservation intent is not the fixed ordinal-seventeen input")
        if self.docker_trace.last_ordinal != 15:
            _reject("volume preservation intent did not follow network absence")
        deadline = _require_int(call_deadline_boottime_ns, "call_deadline_boottime_ns")
        prior_completed = cast(
            int, self.last_record.evidence.to_dict()["call_completed_boottime_ns"]
        )
        if not prior_completed < deadline <= self.root.operation_deadline_boottime_ns:
            _reject("volume proof deadline is not future-bounded")
        plan = DockerPlanIdentity(
            self.root.supervisor_container_id,
            self.root.source_container_id,
            self.root.project_network_id,
        )
        requests = [
            DockerRequestSemantic.from_spec(docker_call_spec(ordinal, plan)).sha256
            for ordinal in (16, 17)
        ]
        target = _domain_sha256(
            "AutoQuantTrader/trusted-time/graceful-stop/named-volume-set/v2",
            [
                self.root.chrony_command_socket_volume_identity_sha256,
                self.root.chrony_state_volume_identity_sha256,
            ],
        )
        intent = _FixedSemantic.capture(
            {
                "contract_version": (
                    "phase6d-trusted-time-graceful-stop-volume-preservation-intent-v2"
                ),
                "service": LIFECYCLE_V2_CLEANUP_SERVICE,
                "status": "named_volume_preservation_requested",
                "environment": self.root.environment,
                "graceful_stop_operation_id": self.root.graceful_stop_operation_id,
                "lifecycle_root_sha256": self.root.sha256,
                "admission_sha256": self.root.admission_sha256,
                "docker_admission_capture_sha256": self.docker_admission.sha256,
                "target_names": [COMMAND_SOCKET_VOLUME, STATE_VOLUME],
                "target_identity_sha256": target,
                "admission_volume_projection_sha256_list": [
                    self.root.chrony_command_socket_volume_identity_sha256,
                    self.root.chrony_state_volume_identity_sha256,
                ],
                "previous_trace_entry_sha256": self.docker_trace.trace_head_sha256,
                "connection_ordinals": [16, 17],
                "docker_request_semantic_sha256_list": requests,
                "call_deadline_boottime_ns": deadline,
            },
            "AutoQuantTrader/trusted-time/graceful-stop/volume-preservation-intent/v2",
        )
        evidence = FrozenJsonObject.capture(
            {
                "target_identity_sha256": target,
                "arguments_sha256": intent.sha256,
                "admission_sha256": self.root.admission_sha256,
                "channel_id": self.root.channel_id,
                "call_deadline_boottime_ns": deadline,
                "docker_request_semantic_sha256_list": requests,
            }
        )
        return self._build_unregistered_stage_state(
            evidence=evidence,
            semantic=intent,
            recorded_at_utc=recorded_at_utc,
        )

    def retain_named_volumes_preserved(
        self,
        *,
        result_semantic: DockerVolumePreservationResult,
        trace_prefix: DockerAdmissionRootedTracePrefix,
        recorded_at_utc: str,
    ) -> Self:
        if (
            self.last_record.ordinal != 17
            or type(result_semantic) is not DockerVolumePreservationResult
            or type(trace_prefix) is not DockerAdmissionRootedTracePrefix
            or self.docker_admission is None
            or self.docker_trace is None
        ):
            _reject("volume proof is not the fixed ordinal-eighteen input")
        self._require_docker_admission(
            self.docker_admission, trace_prefix, expected_last_ordinal=17
        )
        fields = result_semantic.to_dict()
        intent = self.semantic_at(17)
        if type(intent) is not _FixedSemantic:
            _reject("volume proof lacks its complete typed intent")
        intent_fields = intent.to_dict()
        trace_objects = cast(list[dict[str, object]], fields["ordered_trace_entry_list"])
        traces = cast(list[str], fields["ordered_trace_entry_sha256_list"])
        connections = cast(list[dict[str, object]], fields["ordered_connection_identity_list"])
        deadline = cast(int, self.last_record.evidence.to_dict()["call_deadline_boottime_ns"])
        prior_completed = cast(
            int, self.record_at(16).evidence.to_dict()["call_completed_boottime_ns"]
        )
        if not (
            fields["environment"] == self.root.environment
            and fields["graceful_stop_operation_id"] == self.root.graceful_stop_operation_id
            and fields["root_sha256"] == self.root.sha256
            and fields["docker_admission_capture_sha256"] == self.docker_admission.sha256
            and fields["admission_volume_projection_sha256_list"]
            == intent_fields["admission_volume_projection_sha256_list"]
            and fields["ordered_request_semantic_sha256_list"]
            == intent_fields["docker_request_semantic_sha256_list"]
            and trace_objects[0]["previous_trace_entry_sha256"]
            == intent_fields["previous_trace_entry_sha256"]
            and traces[-1] == trace_prefix.trace_head_sha256
            and type(fields["volume_delete_call_count"]) is int
            and fields["volume_delete_call_count"] == 0
            and prior_completed
            <= cast(int, fields["proof_started_boottime_ns"])
            <= cast(int, fields["proof_completed_boottime_ns"])
            < deadline
            and cast(int, fields["proof_completed_boottime_ns"])
            < self.root.operation_deadline_boottime_ns
            and all(
                cast(int, connection["call_deadline_boottime_ns"]) <= deadline
                for connection in connections
            )
        ):
            _reject("volume proof crossed identities, request order, trace, or deadline")
        evidence = FrozenJsonObject.capture(
            {
                "intent_sha256": self.last_record.sha256,
                "responder_identity_sha256": fields["admitted_daemon_info_projection_sha256"],
                "disposition": "volumes_preserved",
                "result_semantic_sha256": result_semantic.sha256,
                "call_started_boottime_ns": fields["proof_started_boottime_ns"],
                "call_completed_boottime_ns": fields["proof_completed_boottime_ns"],
                "command_socket_volume_identity_sha256": (
                    self.root.chrony_command_socket_volume_identity_sha256
                ),
                "state_volume_identity_sha256": self.root.chrony_state_volume_identity_sha256,
                "docker_api_trace_sha256": trace_prefix.trace_head_sha256,
                "volume_delete_call_count": 0,
                "docker_request_semantic_sha256_list": fields[
                    "ordered_request_semantic_sha256_list"
                ],
                "result_semantic": fields,
                "docker_method_trace_entry_sha256_list": traces,
            }
        )
        return self._build_unregistered_stage_state(
            evidence=evidence,
            semantic=result_semantic,
            recorded_at_utc=recorded_at_utc,
            docker_trace=trace_prefix,
        )

    def retain_post_teardown_reauthentication_intent(
        self,
        *,
        prefix_transcript: LifecycleV2Transcript,
        provider_identity_sha256: str,
        call_deadline_boottime_ns: int,
        recorded_at_utc: str,
    ) -> Self:
        if self.last_record.ordinal != 18 or self.pre_effect_binding is None:
            _reject("post-teardown intent is not the fixed ordinal-nineteen input")
        if type(prefix_transcript) is not LifecycleV2Transcript:
            _reject("post-teardown intent requires the complete prefix transcript")
        exact_transcript = decode_lifecycle_v2_transcript(prefix_transcript.encoded)
        if (
            exact_transcript != prefix_transcript
            or prefix_transcript.environment != self.root.environment
            or prefix_transcript.graceful_stop_operation_id != self.root.graceful_stop_operation_id
            or prefix_transcript.root_sha256 != self.root.sha256
            or len(prefix_transcript.entries) != 19
            or prefix_transcript.entries[-1].ordinal != 18
        ):
            _reject("post-teardown transcript is not the exact ordinal-eighteen prefix")
        by_ordinal = {record.ordinal: record for record in self.records}
        if frozenset(by_ordinal) != frozenset(range(2, 19)):
            _reject("post-teardown lineage is not the exact ordinal-two-through-eighteen set")
        root_entry = prefix_transcript.entries[0]
        intent_entry = prefix_transcript.entries[1]
        if (
            root_entry.stage is not LifecycleV2Stage.ROOT_RESERVED
            or root_entry.record_artifact_kind != "root"
            or root_entry.record_contract_version != LIFECYCLE_V2_ROOT_CONTRACT_VERSION
            or root_entry.record_artifact_sha256 != self.root.sha256
            or root_entry.predecessor_sha256 is not None
            or any(
                item is not None
                for item in (
                    root_entry.wire_artifact_kind,
                    root_entry.wire_artifact_path,
                    root_entry.wire_artifact_file_name,
                    root_entry.wire_artifact_sha256,
                )
            )
            or intent_entry.stage is not LifecycleV2Stage.CLEAN_STOP_REQUEST_INTENT_RETAINED
            or intent_entry.record_artifact_kind != "progress"
            or intent_entry.record_contract_version != LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION
            or intent_entry.record_artifact_sha256 != self.record_at(2).predecessor_sha256
            or intent_entry.predecessor_sha256 != self.root.sha256
            or any(
                item is not None
                for item in (
                    intent_entry.wire_artifact_kind,
                    intent_entry.wire_artifact_path,
                    intent_entry.wire_artifact_file_name,
                    intent_entry.wire_artifact_sha256,
                )
            )
        ):
            _reject("post-teardown transcript substituted its root or request intent")
        for entry in prefix_transcript.entries[2:]:
            expected = by_ordinal.get(entry.ordinal)
            if (
                expected is None
                or entry.stage is not NORMAL_STAGE_BY_ORDINAL[entry.ordinal]
                or entry.stage is not expected.stage
                or entry.record_artifact_kind != "progress"
                or entry.record_contract_version != LIFECYCLE_V2_PROGRESS_CONTRACT_VERSION
                or entry.record_artifact_sha256 != expected.sha256
                or entry.predecessor_sha256 != expected.predecessor_sha256
                or (
                    entry.ordinal != 2
                    and any(
                        item is not None
                        for item in (
                            entry.wire_artifact_kind,
                            entry.wire_artifact_path,
                            entry.wire_artifact_file_name,
                            entry.wire_artifact_sha256,
                        )
                    )
                )
            ):
                _reject("post-teardown transcript substituted a lifecycle record")
        terminal_wire = self.terminal_wire.to_dict()
        wire_entry = prefix_transcript.entries[2]
        if (
            wire_entry.stage is not LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED
            or wire_entry.wire_artifact_kind != "signed_result_envelope"
            or wire_entry.wire_artifact_path != terminal_wire["clean_stop_result_artifact_path"]
            or wire_entry.wire_artifact_file_name
            != terminal_wire["clean_stop_result_artifact_name"]
            or wire_entry.wire_artifact_sha256 != terminal_wire["clean_stop_result_sha256"]
        ):
            _reject("post-teardown transcript substituted the retained terminal wire")
        provider = _require_sha256(provider_identity_sha256, "provider_identity_sha256")
        deadline = _require_int(call_deadline_boottime_ns, "call_deadline_boottime_ns")
        volume = self.semantic_at(18)
        if type(volume) is not DockerVolumePreservationResult:
            _reject("post-teardown intent lacks the complete volume proof")
        not_before = cast(int, volume.to_dict()["proof_completed_boottime_ns"]) + 1
        if not_before > MAXIMUM_SIGNED_INTEGER - 120_000_000_000:
            _reject("post-teardown reauthentication deadline addition overflows")
        expected_deadline = min(
            not_before + 120_000_000_000,
            self.root.operation_deadline_boottime_ns,
        )
        if deadline != expected_deadline or deadline <= not_before:
            _reject("post-teardown reauthentication deadline is not the exact 120-second bound")
        expected_head = self.clean_stop_result.terminal_projection.to_dict()[
            "current_anchor_sha256"
        ]
        teardown = [self.record_at(ordinal).sha256 for ordinal in (8, 10, 12, 14, 16, 18)]
        intent = LifecycleV2ReauthenticationIntent._capture_fixed(
            {
                "contract_version": (
                    "phase6d-trusted-time-graceful-stop-post-teardown-reauthentication-intent-v2"
                ),
                "service": LIFECYCLE_V2_CLEANUP_SERVICE,
                "status": "post_teardown_reauthentication_requested",
                "environment": self.root.environment,
                "graceful_stop_operation_id": self.root.graceful_stop_operation_id,
                "lifecycle_root_sha256": self.root.sha256,
                "boundary": "post_teardown",
                "prefix_transcript_sha256": prefix_transcript.sha256,
                "expected_head_sha256": expected_head,
                "pre_effect_binding_sha256": self.pre_effect_binding.sha256,
                "teardown_result_record_sha256_list": teardown,
                "volume_proof_sha256": volume.sha256,
                "provider_identity_sha256": provider,
                "channel_id": self.root.channel_id,
                "observation_not_before_boottime_ns": not_before,
                "call_deadline_boottime_ns": deadline,
            },
            boundary="post_teardown",
        )
        evidence = FrozenJsonObject.capture(
            {
                "target_identity_sha256": expected_head,
                "arguments_sha256": intent.sha256,
                "admission_sha256": self.root.admission_sha256,
                "channel_id": self.root.channel_id,
                "call_deadline_boottime_ns": deadline,
            }
        )
        return self._build_unregistered_stage_state(
            evidence=evidence,
            semantic=intent,
            recorded_at_utc=recorded_at_utc,
            prefix_through_eighteen=prefix_transcript,
        )

    def retain_post_teardown_reauthentication_binding(
        self,
        *,
        binding: LifecycleV2AuthenticatedReauthenticationBinding,
        recorded_at_utc: str,
    ) -> Self:
        if (
            self.last_record.ordinal != 19
            or type(binding) is not LifecycleV2AuthenticatedReauthenticationBinding
            or self.pre_effect_binding is None
        ):
            _reject("post-teardown binding is not the fixed ordinal-twenty input")
        binding._require_sealed()
        intent = self.semantic_at(19)
        if type(intent) is not LifecycleV2ReauthenticationIntent:
            _reject("post-teardown binding lacks its typed intent")
        fields = binding.to_dict()
        pre_fields = self.pre_effect_binding.to_dict()
        binding_evidence = binding.binding_evidence.to_dict()
        pre_evidence, pre_evidence_sha256 = _capture_lifecycle_v2_reauthentication_binding_evidence(
            self.pre_effect_binding.binding_evidence,
            boundary="pre_effect",
        )
        terminal_projection = self.clean_stop_result.terminal_projection.to_dict()
        if not (
            binding.boundary == "post_teardown"
            and fields["intent_semantic_sha256"] == intent.sha256
            and fields["issuer_identity_sha256"] != pre_fields["issuer_identity_sha256"]
            and fields["challenge_sha256"] != pre_fields["challenge_sha256"]
            and fields["observation_semantic_sha256"] != pre_fields["observation_semantic_sha256"]
            and binding.sha256 != self.pre_effect_binding.sha256
            and cast(int, fields["observation_started_boottime_ns"])
            > cast(int, self.record_at(18).evidence.to_dict()["call_completed_boottime_ns"])
        ):
            _reject("post-teardown binding reused or preceded pre-effect/teardown evidence")
        if (
            binding_evidence["published_prefix_through_ordinal_18_sha256"]
            != intent.to_dict()["prefix_transcript_sha256"]
            or binding_evidence["expected_clean_stop_head_sha256"]
            != intent.to_dict()["expected_head_sha256"]
            or binding_evidence["expected_clean_stop_terminal_result_semantic_sha256"]
            != terminal_projection["clean_stop_terminal_result_semantic_sha256"]
            or binding_evidence["pre_effect_binding_sha256"] != pre_evidence_sha256
            or binding_evidence["supervisor_stop_result_sha256"] != self.record_at(8).sha256
            or binding_evidence["source_stop_result_sha256"] != self.record_at(10).sha256
            or binding_evidence["supervisor_remove_result_sha256"] != self.record_at(12).sha256
            or binding_evidence["source_remove_result_sha256"] != self.record_at(14).sha256
            or binding_evidence["project_network_remove_result_sha256"] != self.record_at(16).sha256
            or binding_evidence["volume_proof_sha256"] != self.record_at(18).sha256
            or binding_evidence["post_teardown_intent_sha256"] != self.last_record.sha256
            or binding_evidence["provider_identity_sha256"]
            != pre_evidence.to_dict()["provider_identity_sha256"]
        ):
            _reject("post-teardown binding evidence crossed its exact lifecycle prefix")
        evidence = FrozenJsonObject.capture(
            {
                "intent_sha256": self.last_record.sha256,
                "responder_identity_sha256": fields["issuer_identity_sha256"],
                "disposition": "post_teardown_reauthentication_bound",
                "result_semantic_sha256": binding.sha256,
                "call_started_boottime_ns": fields["observation_started_boottime_ns"],
                "call_completed_boottime_ns": fields["observation_completed_boottime_ns"],
                "observation_semantic_sha256": fields["observation_semantic_sha256"],
                "binding_semantic_sha256": binding.sha256,
                "observed_head_sha256": fields["observed_head_sha256"],
                "provider_identity_sha256": fields["provider_identity_sha256"],
                "channel_id": fields["channel_id"],
                "intent_semantic_sha256": fields["intent_semantic_sha256"],
                "binding_evidence": binding_evidence,
            }
        )
        return self._build_unregistered_stage_state(
            evidence=evidence,
            semantic=binding,
            recorded_at_utc=recorded_at_utc,
        )

    def retain_terminal_cleanup_intent(
        self,
        *,
        observer: LifecycleV2InjectedCleanupObserver,
        mounts: object,
        recovery_secret_mount_absence: LifecycleV2PathAbsence,
        socket_path_absence: LifecycleV2PathAbsence,
        credential_path_absence: LifecycleV2PathAbsence,
        native_owner_set: LifecycleV2NativeOwnerSet,
        cleanup_authorized_boottime_ns: int,
        recorded_at_utc: str,
    ) -> Self:
        if self.last_record.ordinal != 20:
            _reject("terminal cleanup intent is not the fixed ordinal-twenty-one input")
        observer_metadata = _require_cleanup_observer(observer, root=self.root)
        projection = LifecycleV2EmptySecretMountProjection.from_mounts(
            root=self.root, mounts=mounts
        )
        if (
            type(recovery_secret_mount_absence) is not LifecycleV2PathAbsence
            or recovery_secret_mount_absence.absence_kind != "recovery_secret_mount"
            or type(socket_path_absence) is not LifecycleV2PathAbsence
            or socket_path_absence.absence_kind != "transport_socket"
            or type(credential_path_absence) is not LifecycleV2PathAbsence
            or credential_path_absence.absence_kind != "credential_paths"
            or type(native_owner_set) is not LifecycleV2NativeOwnerSet
        ):
            _reject("terminal cleanup plan contains an inexact mount, path, or owner value")
        evidence_values: tuple[_CanonicalEvidence, ...] = (
            projection,
            recovery_secret_mount_absence,
            socket_path_absence,
            credential_path_absence,
            native_owner_set,
        )
        evidence_metadata = tuple(_require_canonical_evidence(value) for value in evidence_values)
        if any(
            metadata.provenance != observer_metadata.provenance
            or metadata.scope_sha256 != observer.observer_nonce_sha256
            for metadata in evidence_metadata
        ):
            _reject("terminal cleanup plan crossed its injected observer")
        for absence in (
            recovery_secret_mount_absence,
            socket_path_absence,
            credential_path_absence,
        ):
            absence_fields = absence.to_dict()
            if (
                absence_fields["environment"] != self.root.environment
                or absence_fields["graceful_stop_operation_id"]
                != self.root.graceful_stop_operation_id
                or absence_fields["lifecycle_root_sha256"] != self.root.sha256
            ):
                _reject("terminal cleanup path absence crossed its lifecycle root")
        if native_owner_set.root_sha256 != self.root.sha256:
            _reject("terminal cleanup native-owner set crossed its lifecycle root")
        last_completed = cast(
            int, self.last_record.evidence.to_dict()["call_completed_boottime_ns"]
        )
        for absence in (
            recovery_secret_mount_absence,
            socket_path_absence,
            credential_path_absence,
        ):
            if cast(int, absence.to_dict()["observed_boottime_ns"]) <= last_completed:
                _reject("terminal cleanup plan reused a pre-binding absence observation")
        observation_times = [
            *(mount.observed_boottime_ns for mount in projection.mounts),
            recovery_secret_mount_absence.to_dict()["observed_boottime_ns"],
            socket_path_absence.to_dict()["observed_boottime_ns"],
            credential_path_absence.to_dict()["observed_boottime_ns"],
            native_owner_set.observed_boottime_ns,
        ]
        if any(type(value) is not int or value <= last_completed for value in observation_times):
            _reject("terminal cleanup plan reused evidence from before post-teardown binding")
        by_path = {mount.to_dict()["path"]: mount for mount in projection.mounts}
        plan = object.__new__(LifecycleV2TerminalCleanupPlan)
        evidence = FrozenJsonObject.capture(
            {
                "transport_quiescence_record_sha256": self.record_at(4).sha256,
                "supervisor_remove_result_sha256": self.record_at(12).sha256,
                "transport_mount_identity_sha256": by_path[TRANSPORT_MOUNT_PATH].sha256,
                "host_secret_mount_identity_sha256": by_path[HOST_SECRET_MOUNT_PATH].sha256,
                "supervisor_secret_mount_identity_sha256": by_path[
                    SUPERVISOR_SECRET_MOUNT_PATH
                ].sha256,
                "recovery_secret_mount_absence_sha256": recovery_secret_mount_absence.sha256,
                "socket_path_absence_sha256": socket_path_absence.sha256,
                "credential_path_absence_sha256": credential_path_absence.sha256,
                "native_owner_set_sha256": native_owner_set.sha256,
                "cleanup_deadline_boottime_ns": self.root.operation_deadline_boottime_ns,
            }
        )
        object.__setattr__(plan, "evidence", evidence)
        object.__setattr__(plan, "mounts", projection.mounts)
        object.__setattr__(plan, "recovery_absence", recovery_secret_mount_absence)
        object.__setattr__(plan, "socket_absence", socket_path_absence)
        object.__setattr__(plan, "credential_absence", credential_path_absence)
        object.__setattr__(plan, "owners", native_owner_set)
        result = self._build_unregistered_stage_state(
            evidence=evidence,
            semantic=plan,
            recorded_at_utc=recorded_at_utc,
            terminal_cleanup_plan=plan,
        )
        return result

    def retain_terminal_cleanup_confirmed(
        self,
        *,
        empty_mount_projection: LifecycleV2EmptySecretMountProjection,
        unmount_receipt: LifecycleV2SecretMountUnmountReceipt,
        native_owner_cleanup_receipt: LifecycleV2NativeOwnerCleanupReceipt,
        recovery_secret_mount_absence: LifecycleV2PathAbsence,
        socket_absence: LifecycleV2PathAbsence,
        credential_path_absence: LifecycleV2PathAbsence,
        recorded_at_utc: str,
    ) -> Self:
        plan = self.terminal_cleanup_plan
        if (
            self.last_record.ordinal != 21
            or type(plan) is not LifecycleV2TerminalCleanupPlan
            or type(empty_mount_projection) is not LifecycleV2EmptySecretMountProjection
            or type(unmount_receipt) is not LifecycleV2SecretMountUnmountReceipt
            or type(native_owner_cleanup_receipt) is not LifecycleV2NativeOwnerCleanupReceipt
            or type(recovery_secret_mount_absence) is not LifecycleV2PathAbsence
            or recovery_secret_mount_absence.absence_kind != "recovery_secret_mount"
            or type(socket_absence) is not LifecycleV2PathAbsence
            or socket_absence.absence_kind != "transport_socket"
            or type(credential_path_absence) is not LifecycleV2PathAbsence
            or credential_path_absence.absence_kind != "credential_paths"
        ):
            _reject("terminal cleanup result is not the fixed ordinal-twenty-two input")
        plan_metadata = plan._require_sealed()
        authorization = plan.authorization
        authorization_metadata = _require_terminal_cleanup_authorization(authorization)
        if (
            self.terminal_cleanup_authorization is not authorization
            or authorization.cleanup_intent_sha256 != self.last_record.sha256
            or authorization_metadata.provenance != plan_metadata.provenance
            or authorization_metadata.scope_sha256 != plan_metadata.scope_sha256
        ):
            _reject("terminal cleanup result crossed its retained authorization")
        if tuple(mount.sha256 for mount in empty_mount_projection.mounts) != tuple(
            mount.sha256 for mount in plan.mounts
        ):
            _reject("terminal cleanup mount identity drifted from its durable plan")
        projection_fields = empty_mount_projection.to_dict()
        for value in (
            projection_fields,
            unmount_receipt.to_dict(),
            native_owner_cleanup_receipt.to_dict(),
            recovery_secret_mount_absence.to_dict(),
            socket_absence.to_dict(),
            credential_path_absence.to_dict(),
        ):
            if (
                value["environment"] != self.root.environment
                or value["graceful_stop_operation_id"] != self.root.graceful_stop_operation_id
                or value["lifecycle_root_sha256"] != self.root.sha256
            ):
                _reject("terminal cleanup evidence crossed its lifecycle root")
        result_values: tuple[_CanonicalEvidence, ...] = (
            empty_mount_projection,
            unmount_receipt,
            native_owner_cleanup_receipt,
            recovery_secret_mount_absence,
            socket_absence,
            credential_path_absence,
        )
        result_metadata = tuple(_require_canonical_evidence(value) for value in result_values)
        if any(
            metadata.provenance != authorization_metadata.provenance
            or metadata.scope_sha256 != authorization_metadata.scope_sha256
            for metadata in result_metadata
        ):
            _reject("terminal cleanup result crossed its injected observer")
        by_path = {
            mount.to_dict()["path"]: mount.to_dict()["mount_id"]
            for mount in empty_mount_projection.mounts
        }
        receipt_mounts = cast(list[dict[str, object]], unmount_receipt.to_dict()["mounts"])
        if [entry["mount_id"] for entry in receipt_mounts] != [
            by_path[SUPERVISOR_SECRET_MOUNT_PATH],
            by_path[HOST_SECRET_MOUNT_PATH],
            by_path[TRANSPORT_MOUNT_PATH],
        ]:
            _reject("terminal cleanup unmount receipt changed mount identity or order")
        if native_owner_cleanup_receipt.to_dict()["native_owner_set_sha256"] != plan.owners.sha256:
            _reject("terminal cleanup receipt crossed its native-owner plan")
        planned_recovery_time = cast(int, plan.recovery_absence.to_dict()["observed_boottime_ns"])
        planned_socket_time = cast(int, plan.socket_absence.to_dict()["observed_boottime_ns"])
        planned_credential_time = cast(
            int, plan.credential_absence.to_dict()["observed_boottime_ns"]
        )
        recovery_time = cast(int, recovery_secret_mount_absence.to_dict()["observed_boottime_ns"])
        socket_time = cast(int, socket_absence.to_dict()["observed_boottime_ns"])
        credential_time = cast(int, credential_path_absence.to_dict()["observed_boottime_ns"])
        destructive_completed = max(
            unmount_receipt.completed_boottime_ns,
            native_owner_cleanup_receipt.completed_boottime_ns,
        )
        completed = max(
            destructive_completed,
            recovery_time,
            socket_time,
            credential_time,
        )
        if not (
            recovery_time >= planned_recovery_time
            and socket_time >= planned_socket_time
            and credential_time >= planned_credential_time
            and destructive_completed < min(recovery_time, socket_time, credential_time)
            and unmount_receipt.authorization_intent_sha256 == authorization.cleanup_intent_sha256
            and native_owner_cleanup_receipt.authorization_intent_sha256
            == authorization.cleanup_intent_sha256
            and recovery_secret_mount_absence.authorization_intent_sha256
            == authorization.cleanup_intent_sha256
            and socket_absence.authorization_intent_sha256 == authorization.cleanup_intent_sha256
            and credential_path_absence.authorization_intent_sha256
            == authorization.cleanup_intent_sha256
            and completed < self.root.operation_deadline_boottime_ns
        ):
            _reject("terminal cleanup absence or completion evidence is stale or late")
        _finalize_terminal_cleanup_authorization(authorization)
        result = object.__new__(LifecycleV2TerminalCleanupResult)
        evidence = FrozenJsonObject.capture(
            {
                "cleanup_intent_sha256": self.last_record.sha256,
                "transport_quiescence_record_sha256": self.record_at(4).sha256,
                "supervisor_remove_result_sha256": self.record_at(12).sha256,
                "socket_absence_sha256": socket_absence.sha256,
                "credential_path_absence_sha256": credential_path_absence.sha256,
                "empty_mount_projection_sha256": empty_mount_projection.sha256,
                "unmount_receipt_sha256": unmount_receipt.sha256,
                "native_owner_cleanup_receipt_sha256": native_owner_cleanup_receipt.sha256,
                "socket_absence": socket_absence.to_dict(),
                "credential_path_absence": credential_path_absence.to_dict(),
                "empty_mount_projection": empty_mount_projection.to_dict(),
                "unmount_receipt": unmount_receipt.to_dict(),
                "native_owner_cleanup_receipt": native_owner_cleanup_receipt.to_dict(),
                "all_private_material_unreachable": True,
                "cleanup_completed_boottime_ns": completed,
            }
        )
        object.__setattr__(result, "evidence", evidence)
        object.__setattr__(result, "empty_mounts", empty_mount_projection)
        object.__setattr__(result, "unmount_receipt", unmount_receipt)
        object.__setattr__(result, "native_owner_receipt", native_owner_cleanup_receipt)
        object.__setattr__(result, "recovery_absence", recovery_secret_mount_absence)
        object.__setattr__(result, "socket_absence", socket_absence)
        object.__setattr__(result, "credential_absence", credential_path_absence)
        object.__setattr__(result, "authorization", authorization)
        return self._build_unregistered_stage_state(
            evidence=evidence,
            semantic=result,
            recorded_at_utc=recorded_at_utc,
        )


@dataclass(frozen=True, slots=True, init=False)
class _FixedSemantic(_CanonicalEvidence):
    fields: FrozenJsonObject
    _domain: str

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("fixed lifecycle semantics require named construction")

    @classmethod
    def capture(cls, value: object, domain: str) -> Self:
        result = object.__new__(cls)
        object.__setattr__(result, "fields", FrozenJsonObject.capture(value))
        object.__setattr__(result, "_domain", domain)
        return result

    @property
    def digest_domain(self) -> str:
        return self._domain


def _install_lifecycle_v2_runtime_seals() -> tuple[Any, ...]:
    """Install exact construction/transition closures around a closure-owned registry."""

    global _finalize_terminal_cleanup_authorization

    registry_seal: Callable[..., bool]
    registry_require: Callable[..., RuntimeSealMetadata | None]
    registry_consume: Callable[..., RuntimeSealMetadata | None]
    registry_transition: Callable[..., bool]
    registry_consume_action: Callable[..., RuntimeSealMetadata | None]
    registry_consume_action_and_transfer: Callable[..., RuntimeSealMetadata | None]
    registry_finalize_actions: Callable[..., RuntimeSealMetadata | None]
    canonical_registration_callers: frozenset[CodeType]
    compound_registration_callers: frozenset[CodeType]
    authorization_action_callers: frozenset[CodeType]
    authorization_mint_callers: frozenset[CodeType]
    final_credential_action_call_chain: tuple[CodeType, CodeType]
    final_recovery_action_call_chain: tuple[CodeType, CodeType]
    final_socket_action_call_chain: tuple[CodeType, CodeType]
    finalization_call_chain: tuple[CodeType, CodeType, CodeType]
    native_owner_action_call_chain: tuple[CodeType, CodeType]
    transition_validation_callers: frozenset[CodeType]
    unmount_action_call_chain: tuple[CodeType, CodeType]
    reauthentication_issuance_consumer: Callable[..., object] | None = None
    reauthentication_issuance_snapshot_type: type[object] | None = None
    import_reauthentication_module = importlib.import_module
    get_call_frame = sys._getframe
    exact_len = len
    exact_getattr = getattr
    exact_realpath = os.path.realpath
    reauthentication_module_name = _REAUTHENTICATION_REALM_MODULE
    reauthentication_module_source = os.path.realpath(
        os.path.join(
            os.path.dirname(__file__),
            "trusted_time_graceful_stop_v2_reauthentication.py",
        )
    )
    with open(reauthentication_module_source, "rb") as realm_source_file:
        expected_reauthentication_module_code = compile(
            realm_source_file.read(),
            reauthentication_module_source,
            "exec",
        )
    expected_reauthentication_names = frozenset(
        {
            "_install_lifecycle_v2_reauthentication_binding_realms",
            "_consume_exact_lifecycle_v2_reauthentication_semantic_binding_issuance_once",
            "_install_lifecycle_v2_reauthentication_semantic_binding_issuance_consumer",
            "_LifecycleV2ReauthenticationSemanticBindingIssuanceSnapshot",
        }
    )
    expected_consumer_freevars = (
        "current_thread",
        "fake_semantic_binding_provenance",
        "getpid",
        "origin_pid",
        "registry_lock",
        "semantic_issuance_snapshot_type",
        "semantic_issuance_type",
        "semantic_issuances",
    )
    decode_reauthentication_snapshot = decode_canonical_v2_json_object

    canonical_types = (
        LifecycleV2HostTransportCleanupIdentity,
        LifecycleV2SupervisorQuiescenceObservation,
        LifecycleV2HostTransportCleanupReceipt,
        LifecycleV2ReauthenticationIntent,
        LifecycleV2AuthenticatedReauthenticationBinding,
        LifecycleV2EmptySecretMountIdentity,
        LifecycleV2EmptySecretMountProjection,
        LifecycleV2PathAbsence,
        LifecycleV2NativeOwnerSet,
        LifecycleV2SecretMountUnmountReceipt,
        LifecycleV2NativeOwnerCleanupReceipt,
        _FixedSemantic,
    )
    compound_kind_by_type = MappingProxyType(
        {
            LifecycleV2TransportCleanupPlan: "transport_cleanup_plan",
            LifecycleV2TransportQuiescence: "transport_quiescence",
            LifecycleV2TerminalCleanupAuthorization: "terminal_cleanup_authorization",
            LifecycleV2TerminalCleanupPlan: "terminal_cleanup_plan",
            LifecycleV2TerminalCleanupResult: "terminal_cleanup_result",
        }
    )

    def require_authority_caller(
        allowed_callers: frozenset[CodeType],
        operation: str,
    ) -> None:
        caller = get_call_frame(2)
        try:
            if caller.f_code not in allowed_callers:
                _reject(f"{operation} escaped its exact construction topology")
        finally:
            del caller

    def require_authority_call_chain(
        expected_callers: tuple[CodeType, ...],
        operation: str,
    ) -> None:
        expected_length = exact_len(expected_callers)
        first: Any = None
        second: Any = None
        third: Any = None
        try:
            first = get_call_frame(2)
            second = get_call_frame(3)
            third = get_call_frame(4) if expected_length == 3 else None
            actual_callers = (
                first.f_code,
                second.f_code,
                *((third.f_code,) if third is not None else ()),
            )
            if actual_callers != expected_callers:
                _reject(f"{operation} escaped its exact semantic call chain")
        except ValueError:
            _reject(f"{operation} escaped its exact semantic call chain")
        finally:
            del first, second, third

    def register_canonical(value: object, *, provenance: str, scope_sha256: str) -> None:
        require_authority_caller(
            canonical_registration_callers,
            "canonical runtime-seal registration",
        )
        if type(value) not in canonical_types or not registry_seal(
            value,
            snapshot_sha256=_canonical_evidence_snapshot(value),
            kind="canonical_evidence",
            provenance=provenance,
            scope_sha256=scope_sha256,
        ):
            _reject("typed lifecycle semantic runtime seal could not be created")

    def require_canonical(value: object) -> RuntimeSealMetadata:
        if type(value) not in canonical_types:
            _reject("typed lifecycle semantic is not canonically sealed")
        try:
            snapshot = _canonical_evidence_snapshot(value)
        except (AttributeError, TypeError, TrustedTimeGracefulStopV2Rejected):
            _reject("typed lifecycle semantic is not canonically sealed")
        metadata = registry_require(
            value,
            snapshot_sha256=snapshot,
            kind="canonical_evidence",
        )
        if metadata is None:
            _reject("typed lifecycle semantic is not canonically sealed")
        return metadata

    def register_compound(value: object, *, provenance: str, scope_sha256: str) -> None:
        require_authority_caller(
            compound_registration_callers,
            "compound runtime-seal registration",
        )
        kind = compound_kind_by_type.get(type(value))
        if kind is None or not registry_seal(
            value,
            snapshot_sha256=_compound_value_snapshot(value),
            kind=kind,
            provenance=provenance,
            scope_sha256=scope_sha256,
        ):
            _reject("typed lifecycle compound runtime seal could not be created")

    def require_compound(value: object) -> RuntimeSealMetadata:
        kind = compound_kind_by_type.get(type(value))
        if kind is None:
            _reject("typed lifecycle compound value is not sealed")
        try:
            snapshot = _compound_value_snapshot(value)
        except (AttributeError, TypeError, TrustedTimeGracefulStopV2Rejected):
            _reject(f"{kind} is not sealed")
        metadata = registry_require(value, snapshot_sha256=snapshot, kind=kind)
        if metadata is None:
            _reject(f"{kind} is not sealed")
        return metadata

    def install_reauthentication_issuance_consumer(endpoint: object) -> None:
        """Capture the exact reauthentication-registry consumer once."""

        nonlocal reauthentication_issuance_consumer
        nonlocal reauthentication_issuance_snapshot_type
        if (
            reauthentication_issuance_consumer is not None
            or reauthentication_issuance_snapshot_type is not None
            or not callable(endpoint)
        ):
            _reject("reauthentication semantic issuance consumer installation is invalid")
        caller = get_call_frame(1)
        try:
            caller_code = caller.f_code
            caller_globals = caller.f_globals
            caller_codes: set[CodeType] = set()
            pending_codes = [caller_code]
            while pending_codes:
                nested_code = pending_codes.pop()
                caller_codes.add(nested_code)
                pending_codes.extend(
                    item for item in nested_code.co_consts if type(item) is CodeType
                )
            if (
                caller_code.co_name != "<module>"
                or caller_code != expected_reauthentication_module_code
                or not expected_reauthentication_names.issubset(caller_code.co_names)
                or exact_realpath(caller_code.co_filename) != reauthentication_module_source
            ):
                _reject("reauthentication semantic issuance consumer installation is invalid")
            realm_module = import_reauthentication_module(reauthentication_module_name)
            realm_globals = exact_getattr(realm_module, "__dict__", None)
            realm_spec = exact_getattr(realm_module, "__spec__", None)
            exact_endpoint = cast(
                Any, realm_module
            )._consume_exact_lifecycle_v2_reauthentication_semantic_binding_issuance_once
            exact_snapshot_type = cast(
                Any, realm_module
            )._LifecycleV2ReauthenticationSemanticBindingIssuanceSnapshot
            endpoint_code = exact_getattr(endpoint, "__code__", None)
            if (
                realm_globals is not caller_globals
                or exact_getattr(realm_module, "__name__", None) != reauthentication_module_name
                or exact_realpath(exact_getattr(realm_module, "__file__", ""))
                != reauthentication_module_source
                or exact_getattr(realm_spec, "name", None) != reauthentication_module_name
                or exact_realpath(exact_getattr(realm_spec, "origin", ""))
                != reauthentication_module_source
                or exact_getattr(realm_spec, "_initializing", False) is not True
                or endpoint is not exact_endpoint
                or exact_getattr(endpoint, "__globals__", None) is not caller_globals
                or exact_getattr(endpoint, "__module__", None) != reauthentication_module_name
                or type(endpoint_code) is not CodeType
                or endpoint_code not in caller_codes
                or endpoint_code.co_name != "consume_semantic_binding_issuance_once"
                or endpoint_code.co_qualname
                != "_build_binding_registries.<locals>.consume_semantic_binding_issuance_once"
                or endpoint_code.co_freevars != expected_consumer_freevars
                or type(exact_snapshot_type) is not type
                or exact_getattr(exact_snapshot_type, "__module__", None)
                != reauthentication_module_name
                or exact_getattr(exact_snapshot_type, "__qualname__", None)
                != "_LifecycleV2ReauthenticationSemanticBindingIssuanceSnapshot"
            ):
                _reject("reauthentication semantic issuance consumer installation is invalid")
        except (AttributeError, ImportError, TypeError, ValueError) as error:
            raise TrustedTimeLifecycleV2SemanticsRejected(
                "reauthentication semantic issuance consumer installation is invalid"
            ) from error
        finally:
            del caller
        reauthentication_issuance_consumer = cast(Callable[..., object], endpoint)
        reauthentication_issuance_snapshot_type = cast(type[object], exact_snapshot_type)

    original_observer_builder = cast(
        Callable[..., LifecycleV2InjectedCleanupObserver],
        _build_injected_fake_lifecycle_v2_cleanup_observer,
    )

    def build_fake_observer(
        *args: object,
        **kwargs: object,
    ) -> LifecycleV2InjectedCleanupObserver:
        result = original_observer_builder(*args, **kwargs)
        if type(result) is not LifecycleV2InjectedCleanupObserver or not registry_seal(
            result,
            snapshot_sha256=result._snapshot(),
            kind="cleanup_observer",
            provenance="fake_injected_cleanup_observer",
            scope_sha256=result.root.sha256,
        ):
            _reject("fake cleanup observer runtime seal could not be created")
        return result

    def require_observer_runtime(
        value: object,
        snapshot_sha256: str,
        root_sha256: str,
    ) -> RuntimeSealMetadata | None:
        if type(value) is not LifecycleV2InjectedCleanupObserver:
            return None
        return registry_require(
            value,
            snapshot_sha256=snapshot_sha256,
            kind="cleanup_observer",
            scope_sha256=root_sha256,
        )

    original_host_identity = cast(
        Callable[..., LifecycleV2HostTransportCleanupIdentity],
        LifecycleV2HostTransportCleanupIdentity.capture,
    )
    original_transport_plan = cast(
        Callable[..., LifecycleV2TransportCleanupPlan],
        LifecycleV2TransportCleanupPlan.from_retained_result,
    )
    original_supervisor_observation = cast(
        Callable[..., LifecycleV2SupervisorQuiescenceObservation],
        LifecycleV2SupervisorQuiescenceObservation.capture,
    )
    original_host_receipt = cast(
        Callable[..., LifecycleV2HostTransportCleanupReceipt],
        LifecycleV2HostTransportCleanupReceipt.capture,
    )
    original_quiescence = cast(
        Callable[..., LifecycleV2TransportQuiescence],
        LifecycleV2TransportQuiescence.confirm,
    )
    original_reauth_intent = cast(
        Callable[..., LifecycleV2ReauthenticationIntent],
        LifecycleV2ReauthenticationIntent._capture_fixed,
    )
    original_reauth_binding = cast(
        Callable[..., LifecycleV2AuthenticatedReauthenticationBinding],
        LifecycleV2AuthenticatedReauthenticationBinding._capture_fake_for_tests,
    )
    original_reauth_binding_builder = cast(
        Callable[..., LifecycleV2AuthenticatedReauthenticationBinding],
        _build_unregistered_authenticated_reauthentication_binding,
    )
    original_empty_mount = cast(
        Callable[..., LifecycleV2EmptySecretMountIdentity],
        LifecycleV2EmptySecretMountIdentity.capture,
    )
    original_mount_projection = cast(
        Callable[..., LifecycleV2EmptySecretMountProjection],
        LifecycleV2EmptySecretMountProjection.from_mounts,
    )
    original_path_absence = cast(
        Callable[..., LifecycleV2PathAbsence],
        LifecycleV2PathAbsence._fixed,
    )
    original_owner_set = cast(
        Callable[..., LifecycleV2NativeOwnerSet],
        LifecycleV2NativeOwnerSet.capture,
    )
    original_unmount_receipt = cast(
        Callable[..., LifecycleV2SecretMountUnmountReceipt],
        LifecycleV2SecretMountUnmountReceipt.completed,
    )
    original_owner_receipt = cast(
        Callable[..., LifecycleV2NativeOwnerCleanupReceipt],
        LifecycleV2NativeOwnerCleanupReceipt.completed,
    )
    original_fixed_semantic = cast(
        Callable[..., _FixedSemantic],
        _FixedSemantic.capture,
    )

    def original_authorization_mint(
        *,
        root: LifecycleV2Root,
        cleanup_intent: LifecycleV2ProgressRecord,
        observer: LifecycleV2InjectedCleanupObserver,
        authorized_boottime_ns: int,
        not_before_boottime_ns: int,
    ) -> LifecycleV2TerminalCleanupAuthorization:
        exact_root = _exact_root(root)
        _require_cleanup_observer(observer, root=exact_root)
        exact_intent = _exact_record(cleanup_intent)
        authorized = _require_int(authorized_boottime_ns, "authorized_boottime_ns")
        if (
            exact_intent.ordinal != 21
            or exact_intent.stage is not LifecycleV2Stage.TERMINAL_CLEANUP_INTENT_RETAINED
            or exact_intent.effect_kind != "terminal_cleanup"
            or exact_intent.root_sha256 != exact_root.sha256
            or exact_intent.deadline_boottime_ns != exact_root.operation_deadline_boottime_ns
            or not not_before_boottime_ns < authorized < exact_root.operation_deadline_boottime_ns
        ):
            _reject("terminal cleanup authorization crossed or preceded ordinal twenty-one")
        result = object.__new__(LifecycleV2TerminalCleanupAuthorization)
        object.__setattr__(result, "root_sha256", exact_root.sha256)
        object.__setattr__(result, "cleanup_intent_sha256", exact_intent.sha256)
        object.__setattr__(
            result,
            "observer_nonce_sha256",
            observer.observer_nonce_sha256,
        )
        object.__setattr__(result, "authorized_boottime_ns", authorized)
        return result

    def capture_host_identity(
        cls: type[LifecycleV2HostTransportCleanupIdentity],
        /,
        *args: object,
        **kwargs: object,
    ) -> LifecycleV2HostTransportCleanupIdentity:
        if cls is not LifecycleV2HostTransportCleanupIdentity:
            _reject("host cleanup identity capture class is not exact")
        result = original_host_identity(*args, **kwargs)
        observer = kwargs.get("observer")
        root = kwargs.get("root")
        if (
            type(observer) is not LifecycleV2InjectedCleanupObserver
            or type(root) is not LifecycleV2Root
        ):
            _reject("host cleanup identity omitted its injected observer")
        metadata = observer._require_sealed(root=root)
        register_canonical(
            result,
            provenance=metadata.provenance,
            scope_sha256=observer.observer_nonce_sha256,
        )
        return result

    def capture_transport_plan(
        cls: type[LifecycleV2TransportCleanupPlan],
        /,
        *args: object,
        **kwargs: object,
    ) -> LifecycleV2TransportCleanupPlan:
        if cls is not LifecycleV2TransportCleanupPlan:
            _reject("transport cleanup plan capture class is not exact")
        result = original_transport_plan(*args, **kwargs)
        if type(result) is not LifecycleV2TransportCleanupPlan:
            _reject("transport cleanup plan capture returned an inexact type")
        metadata = require_canonical(result.host_identity)
        register_compound(
            result,
            provenance=metadata.provenance,
            scope_sha256=metadata.scope_sha256,
        )
        return result

    def capture_supervisor_observation(
        cls: type[LifecycleV2SupervisorQuiescenceObservation],
        /,
        *args: object,
        **kwargs: object,
    ) -> LifecycleV2SupervisorQuiescenceObservation:
        if cls is not LifecycleV2SupervisorQuiescenceObservation:
            _reject("supervisor observation capture class is not exact")
        result = original_supervisor_observation(*args, **kwargs)
        observer = kwargs.get("observer")
        root = kwargs.get("root")
        if (
            type(observer) is not LifecycleV2InjectedCleanupObserver
            or type(root) is not LifecycleV2Root
        ):
            _reject("supervisor quiescence omitted its injected observer")
        metadata = observer._require_sealed(root=root)
        register_canonical(
            result,
            provenance=metadata.provenance,
            scope_sha256=observer.observer_nonce_sha256,
        )
        return result

    def capture_host_receipt(
        cls: type[LifecycleV2HostTransportCleanupReceipt],
        /,
        *args: object,
        **kwargs: object,
    ) -> LifecycleV2HostTransportCleanupReceipt:
        if cls is not LifecycleV2HostTransportCleanupReceipt:
            _reject("host cleanup receipt capture class is not exact")
        result = original_host_receipt(*args, **kwargs)
        observer = kwargs.get("observer")
        root = kwargs.get("root")
        if (
            type(observer) is not LifecycleV2InjectedCleanupObserver
            or type(root) is not LifecycleV2Root
        ):
            _reject("host cleanup receipt omitted its injected observer")
        metadata = observer._require_sealed(root=root)
        register_canonical(
            result,
            provenance=metadata.provenance,
            scope_sha256=observer.observer_nonce_sha256,
        )
        return result

    def capture_quiescence(
        cls: type[LifecycleV2TransportQuiescence],
        /,
        *args: object,
        **kwargs: object,
    ) -> LifecycleV2TransportQuiescence:
        if cls is not LifecycleV2TransportQuiescence:
            _reject("transport quiescence capture class is not exact")
        result = original_quiescence(*args, **kwargs)
        if type(result) is not LifecycleV2TransportQuiescence:
            _reject("transport quiescence capture returned an inexact type")
        metadata = require_compound(kwargs.get("plan"))
        register_compound(
            result,
            provenance=metadata.provenance,
            scope_sha256=metadata.scope_sha256,
        )
        return result

    def capture_reauth_intent(
        cls: type[LifecycleV2ReauthenticationIntent],
        /,
        *args: object,
        **kwargs: object,
    ) -> LifecycleV2ReauthenticationIntent:
        if cls is not LifecycleV2ReauthenticationIntent:
            _reject("reauthentication intent capture class is not exact")
        result = original_reauth_intent(*args, **kwargs)
        register_canonical(
            result,
            provenance="derived_lifecycle_semantic",
            scope_sha256=_runtime_scope(result.fields),
        )
        return result

    def capture_reauth_binding(
        cls: type[LifecycleV2AuthenticatedReauthenticationBinding],
        /,
        *args: object,
        **kwargs: object,
    ) -> LifecycleV2AuthenticatedReauthenticationBinding:
        if cls is not LifecycleV2AuthenticatedReauthenticationBinding:
            _reject("reauthentication binding capture class is not exact")
        result = original_reauth_binding(*args, **kwargs)
        root = kwargs.get("root")
        if type(root) is not LifecycleV2Root:
            _reject("fake reauthentication binding omitted its exact root")
        register_canonical(
            result,
            provenance="fake_reauthentication_binding",
            scope_sha256=root.sha256,
        )
        return result

    def capture_reauth_binding_from_realm(
        binding_issuance: object,
        *,
        root: LifecycleV2Root,
        intent: LifecycleV2ReauthenticationIntent,
    ) -> LifecycleV2AuthenticatedReauthenticationBinding:
        """Consume one live realm issuance, then seal its exact primitive binding."""

        exact_root = _exact_root(root)
        if type(intent) is not LifecycleV2ReauthenticationIntent:
            _reject("reauthentication realm issuance omitted its exact intent")
        require_canonical(intent)
        consumer = reauthentication_issuance_consumer
        snapshot_type = reauthentication_issuance_snapshot_type
        if consumer is None or snapshot_type is None:
            try:
                import_reauthentication_module(_REAUTHENTICATION_REALM_MODULE)
            except ImportError as error:
                raise TrustedTimeLifecycleV2SemanticsRejected(
                    "reauthentication semantic issuance consumer is not installed"
                ) from error
            consumer = reauthentication_issuance_consumer
            snapshot_type = reauthentication_issuance_snapshot_type
        if consumer is None or snapshot_type is None:
            _reject("reauthentication semantic issuance consumer is not installed")
        snapshot = consumer(binding_issuance, root=exact_root, intent=intent)
        if type(snapshot) is not snapshot_type:
            _reject("reauthentication semantic issuance snapshot type is not exact")
        exact_snapshot = cast(Any, snapshot)
        encoded = exact_snapshot.semantic_binding_encoded
        binding_evidence_encoded = exact_snapshot.binding_evidence_encoded
        binding_evidence_sha256 = exact_snapshot.binding_evidence_sha256
        provenance = exact_snapshot.provenance
        if (
            type(encoded) is not bytes
            or type(binding_evidence_encoded) is not bytes
            or type(binding_evidence_sha256) is not str
            or _SHA256.fullmatch(binding_evidence_sha256) is None
            or provenance
            not in {
                "fake_reauthentication_binding",
                "production_reauthentication_binding",
            }
            or type(exact_snapshot.root_sha256) is not str
            or exact_snapshot.root_sha256 != exact_root.sha256
            or type(exact_snapshot.intent_semantic_sha256) is not str
            or exact_snapshot.intent_semantic_sha256 != intent.sha256
            or type(exact_snapshot.boundary) is not str
            or exact_snapshot.boundary != intent.boundary
            or (provenance == "fake_reauthentication_binding" and exact_root.environment != "test")
        ):
            _reject("reauthentication semantic issuance snapshot crossed its exact realm")
        fields = decode_reauthentication_snapshot(
            encoded,
            maximum_bytes=256 * 1_024,
        )
        binding_evidence_fields = decode_reauthentication_snapshot(
            binding_evidence_encoded,
            maximum_bytes=256 * 1_024,
        )
        _captured_evidence, exact_binding_evidence_sha256 = (
            _capture_lifecycle_v2_reauthentication_binding_evidence(
                binding_evidence_fields,
                boundary=intent.boundary,
            )
        )
        if exact_binding_evidence_sha256 != binding_evidence_sha256:
            _reject("reauthentication semantic issuance evidence digest changed")
        result = original_reauth_binding_builder(
            fields,
            binding_evidence=binding_evidence_fields,
            root=exact_root,
            intent=intent,
        )
        register_canonical(
            result,
            provenance=provenance,
            scope_sha256=exact_root.sha256,
        )
        return result

    def capture_empty_mount(
        cls: type[LifecycleV2EmptySecretMountIdentity],
        /,
        *args: object,
        **kwargs: object,
    ) -> LifecycleV2EmptySecretMountIdentity:
        if cls is not LifecycleV2EmptySecretMountIdentity:
            _reject("empty mount capture class is not exact")
        result = original_empty_mount(*args, **kwargs)
        observer = kwargs.get("observer")
        if type(observer) is not LifecycleV2InjectedCleanupObserver:
            _reject("empty mount capture omitted its injected observer")
        metadata = observer._require_sealed(root=observer.root)
        register_canonical(
            result,
            provenance=metadata.provenance,
            scope_sha256=observer.observer_nonce_sha256,
        )
        return result

    def capture_mount_projection(
        cls: type[LifecycleV2EmptySecretMountProjection],
        /,
        *args: object,
        **kwargs: object,
    ) -> LifecycleV2EmptySecretMountProjection:
        if cls is not LifecycleV2EmptySecretMountProjection:
            _reject("empty mount projection capture class is not exact")
        result = original_mount_projection(*args, **kwargs)
        if type(result) is not LifecycleV2EmptySecretMountProjection or not result.mounts:
            _reject("empty mount projection capture returned an inexact value")
        metadata = require_canonical(result.mounts[0])
        register_canonical(
            result,
            provenance=metadata.provenance,
            scope_sha256=metadata.scope_sha256,
        )
        return result

    def capture_path_absence(
        cls: type[LifecycleV2PathAbsence],
        /,
        *args: object,
        **kwargs: object,
    ) -> LifecycleV2PathAbsence:
        if cls is not LifecycleV2PathAbsence:
            _reject("path absence capture class is not exact")
        result = original_path_absence(*args, **kwargs)
        observer = kwargs.get("observer")
        root = kwargs.get("root")
        if (
            type(observer) is not LifecycleV2InjectedCleanupObserver
            or type(root) is not LifecycleV2Root
        ):
            _reject("path absence omitted its injected observer")
        metadata = observer._require_sealed(root=root)
        register_canonical(
            result,
            provenance=metadata.provenance,
            scope_sha256=observer.observer_nonce_sha256,
        )
        return result

    def capture_owner_set(
        cls: type[LifecycleV2NativeOwnerSet],
        /,
        *args: object,
        **kwargs: object,
    ) -> LifecycleV2NativeOwnerSet:
        if cls is not LifecycleV2NativeOwnerSet:
            _reject("native owner capture class is not exact")
        result = original_owner_set(*args, **kwargs)
        observer = kwargs.get("observer")
        root = kwargs.get("root")
        if (
            type(observer) is not LifecycleV2InjectedCleanupObserver
            or type(root) is not LifecycleV2Root
        ):
            _reject("native owner capture omitted its injected observer")
        metadata = observer._require_sealed(root=root)
        register_canonical(
            result,
            provenance=metadata.provenance,
            scope_sha256=observer.observer_nonce_sha256,
        )
        return result

    def mint_authorization(
        *,
        root: LifecycleV2Root,
        cleanup_intent: LifecycleV2ProgressRecord,
        observer: LifecycleV2InjectedCleanupObserver,
        authorized_boottime_ns: int,
        not_before_boottime_ns: int,
    ) -> LifecycleV2TerminalCleanupAuthorization:
        require_authority_caller(
            authorization_mint_callers,
            "terminal cleanup authorization mint",
        )
        result = original_authorization_mint(
            root=root,
            cleanup_intent=cleanup_intent,
            observer=observer,
            authorized_boottime_ns=authorized_boottime_ns,
            not_before_boottime_ns=not_before_boottime_ns,
        )
        metadata = observer._require_sealed(root=root)
        register_compound(
            result,
            provenance=metadata.provenance,
            scope_sha256=observer.observer_nonce_sha256,
        )
        return result

    def consume_authorization_action(
        value: object,
        snapshot_sha256: str,
        *,
        action: str,
        prerequisites: frozenset[str] = frozenset(),
    ) -> RuntimeSealMetadata | None:
        require_authority_caller(
            authorization_action_callers,
            "terminal cleanup authorization action",
        )
        if type(value) is not LifecycleV2TerminalCleanupAuthorization:
            return None
        return registry_consume_action(
            value,
            snapshot_sha256=snapshot_sha256,
            kind="terminal_cleanup_authorization",
            action=action,
            prerequisites=prerequisites,
        )

    def consume_unmount(
        value: object,
        snapshot_sha256: str,
    ) -> RuntimeSealMetadata | None:
        require_authority_call_chain(
            unmount_action_call_chain,
            "terminal cleanup unmount authorization",
        )
        return consume_authorization_action(
            value,
            snapshot_sha256,
            action="unmount",
        )

    def consume_native_owner(
        value: object,
        snapshot_sha256: str,
    ) -> RuntimeSealMetadata | None:
        require_authority_call_chain(
            native_owner_action_call_chain,
            "terminal native-owner cleanup authorization",
        )
        return consume_authorization_action(
            value,
            snapshot_sha256,
            action="native_owner_cleanup",
        )

    def consume_final_recovery(
        value: object,
        snapshot_sha256: str,
    ) -> RuntimeSealMetadata | None:
        require_authority_call_chain(
            final_recovery_action_call_chain,
            "terminal recovery-absence authorization",
        )
        return consume_authorization_action(
            value,
            snapshot_sha256,
            action="final_recovery_secret_mount_absence",
            prerequisites=frozenset({"native_owner_cleanup", "unmount"}),
        )

    def consume_final_socket(
        value: object,
        snapshot_sha256: str,
    ) -> RuntimeSealMetadata | None:
        require_authority_call_chain(
            final_socket_action_call_chain,
            "terminal socket-absence authorization",
        )
        return consume_authorization_action(
            value,
            snapshot_sha256,
            action="final_transport_socket_absence",
            prerequisites=frozenset({"native_owner_cleanup", "unmount"}),
        )

    def consume_final_credential(
        value: object,
        snapshot_sha256: str,
    ) -> RuntimeSealMetadata | None:
        require_authority_call_chain(
            final_credential_action_call_chain,
            "terminal credential-absence authorization",
        )
        return consume_authorization_action(
            value,
            snapshot_sha256,
            action="final_credential_paths_absence",
            prerequisites=frozenset({"native_owner_cleanup", "unmount"}),
        )

    def finalize_authorization(
        value: object,
        snapshot_sha256: str,
    ) -> RuntimeSealMetadata | None:
        require_authority_call_chain(
            finalization_call_chain,
            "terminal cleanup authorization finalization",
        )
        if type(value) is not LifecycleV2TerminalCleanupAuthorization:
            return None
        metadata = registry_finalize_actions(
            value,
            snapshot_sha256=snapshot_sha256,
            kind="terminal_cleanup_authorization",
            required_actions=_TERMINAL_CLEANUP_AUTHORIZATION_ACTIONS,
        )
        return metadata

    def guarded_finalize_terminal_cleanup_authorization(
        authorization: LifecycleV2TerminalCleanupAuthorization,
    ) -> RuntimeSealMetadata:
        require_authority_call_chain(
            finalization_call_chain[1:],
            "terminal cleanup semantic finalization",
        )
        _require_terminal_cleanup_authorization(authorization)
        metadata = finalize_authorization(
            authorization,
            authorization._snapshot(),
        )
        if metadata is None:
            _reject("terminal cleanup authorization is incomplete or already consumed")
        return metadata

    def require_finalized_authorization(
        value: object,
    ) -> RuntimeSealMetadata:
        if type(value) is not LifecycleV2TerminalCleanupAuthorization:
            _reject("terminal cleanup authorization finalization identity is not exact")
        try:
            snapshot = _compound_value_snapshot(value)
        except (AttributeError, TypeError, TrustedTimeGracefulStopV2Rejected):
            _reject("terminal cleanup authorization is not exactly finalized")
        metadata = registry_require(
            value,
            snapshot_sha256=snapshot,
            kind="terminal_cleanup_authorization",
            consumed=True,
        )
        if metadata is None:
            _reject("terminal cleanup authorization is not exactly finalized")
        return metadata

    def capture_unmount_receipt(
        cls: type[LifecycleV2SecretMountUnmountReceipt],
        /,
        *args: object,
        **kwargs: object,
    ) -> LifecycleV2SecretMountUnmountReceipt:
        if cls is not LifecycleV2SecretMountUnmountReceipt:
            _reject("unmount receipt capture class is not exact")
        result = original_unmount_receipt(*args, **kwargs)
        authorization = kwargs.get("authorization")
        metadata = require_compound(authorization)
        register_canonical(
            result,
            provenance=metadata.provenance,
            scope_sha256=metadata.scope_sha256,
        )
        return result

    def capture_owner_receipt(
        cls: type[LifecycleV2NativeOwnerCleanupReceipt],
        /,
        *args: object,
        **kwargs: object,
    ) -> LifecycleV2NativeOwnerCleanupReceipt:
        if cls is not LifecycleV2NativeOwnerCleanupReceipt:
            _reject("native owner receipt capture class is not exact")
        result = original_owner_receipt(*args, **kwargs)
        authorization = kwargs.get("authorization")
        metadata = require_compound(authorization)
        register_canonical(
            result,
            provenance=metadata.provenance,
            scope_sha256=metadata.scope_sha256,
        )
        return result

    def capture_fixed_semantic(
        cls: type[_FixedSemantic],
        /,
        *args: object,
        **kwargs: object,
    ) -> _FixedSemantic:
        if cls is not _FixedSemantic:
            _reject("fixed lifecycle semantic capture class is not exact")
        result = original_fixed_semantic(*args, **kwargs)
        register_canonical(
            result,
            provenance="derived_lifecycle_semantic",
            scope_sha256=_runtime_scope(result.fields),
        )
        return result

    cast(Any, LifecycleV2HostTransportCleanupIdentity).capture = classmethod(capture_host_identity)
    cast(Any, LifecycleV2TransportCleanupPlan).from_retained_result = classmethod(
        capture_transport_plan
    )
    cast(Any, LifecycleV2SupervisorQuiescenceObservation).capture = classmethod(
        capture_supervisor_observation
    )
    cast(Any, LifecycleV2HostTransportCleanupReceipt).capture = classmethod(capture_host_receipt)
    cast(Any, LifecycleV2TransportQuiescence).confirm = classmethod(capture_quiescence)
    cast(Any, LifecycleV2ReauthenticationIntent)._capture_fixed = classmethod(capture_reauth_intent)
    cast(
        Any, LifecycleV2AuthenticatedReauthenticationBinding
    )._capture_fake_for_tests = classmethod(capture_reauth_binding)
    cast(Any, LifecycleV2EmptySecretMountIdentity).capture = classmethod(capture_empty_mount)
    cast(Any, LifecycleV2EmptySecretMountProjection).from_mounts = classmethod(
        capture_mount_projection
    )
    cast(Any, LifecycleV2PathAbsence)._fixed = classmethod(capture_path_absence)
    cast(Any, LifecycleV2NativeOwnerSet).capture = classmethod(capture_owner_set)
    cast(Any, LifecycleV2SecretMountUnmountReceipt).completed = classmethod(capture_unmount_receipt)
    cast(Any, LifecycleV2NativeOwnerCleanupReceipt).completed = classmethod(capture_owner_receipt)
    cast(Any, _FixedSemantic).capture = classmethod(capture_fixed_semantic)

    original_initial_lineage = cast(
        Callable[..., LifecycleV2NormalProgressLineage],
        LifecycleV2NormalProgressLineage.from_retained_result,
    )

    def validate_lineage_records(
        value: LifecycleV2NormalProgressLineage,
        *,
        exact_last_ordinal: int,
    ) -> None:
        if (
            type(value) is not LifecycleV2NormalProgressLineage
            or type(value.root) is not LifecycleV2Root
            or type(value.records) is not tuple
            or type(value.semantics) is not tuple
            or len(value.records) != exact_last_ordinal - 1
            or len(value.semantics) != len(value.records)
            or tuple(record.ordinal for record in value.records)
            != tuple(range(2, exact_last_ordinal + 1))
        ):
            _reject("normal lifecycle lineage is not the exact retained ordinal prefix")
        previous_sha256 = value.records[0].predecessor_sha256
        for record in value.records:
            exact = _exact_record(record)
            expected_stage = NORMAL_STAGE_BY_ORDINAL[exact.ordinal]
            expected_effect = (
                "clean_stop_result" if exact.ordinal == 2 else _SPECS[exact.ordinal].effect_kind
            )
            if (
                exact.root_sha256 != value.root.sha256
                or exact.graceful_stop_operation_id != value.root.graceful_stop_operation_id
                or exact.stage is not expected_stage
                or exact.effect_kind != expected_effect
                or exact.deadline_boottime_ns != value.root.operation_deadline_boottime_ns
                or exact.predecessor_sha256 != previous_sha256
            ):
                _reject("normal lifecycle lineage record chain is not exact")
            previous_sha256 = exact.sha256

    def capture_initial_lineage(
        cls: type[LifecycleV2NormalProgressLineage],
        /,
        *args: object,
        **kwargs: object,
    ) -> LifecycleV2NormalProgressLineage:
        if cls is not LifecycleV2NormalProgressLineage:
            _reject("normal lifecycle lineage capture class is not exact")
        result = original_initial_lineage(*args, **kwargs)
        validate_lineage_records(result, exact_last_ordinal=2)
        if not registry_seal(
            result,
            snapshot_sha256=_lineage_snapshot(result),
            kind="normal_progress_lineage",
            provenance="authenticated_injected_lineage",
            scope_sha256=result.root.sha256,
        ):
            _reject("normal lifecycle lineage runtime seal could not be created")
        return result

    cast(Any, LifecycleV2NormalProgressLineage).from_retained_result = classmethod(
        capture_initial_lineage
    )

    semantic_type_by_ordinal = MappingProxyType(
        {
            3: LifecycleV2TransportCleanupPlan,
            4: LifecycleV2TransportQuiescence,
            5: LifecycleV2ReauthenticationIntent,
            6: LifecycleV2AuthenticatedReauthenticationBinding,
            7: _FixedSemantic,
            8: DockerMutationResultSemantic,
            9: _FixedSemantic,
            10: DockerMutationResultSemantic,
            11: _FixedSemantic,
            12: DockerMutationResultSemantic,
            13: _FixedSemantic,
            14: DockerMutationResultSemantic,
            15: _FixedSemantic,
            16: DockerMutationResultSemantic,
            17: _FixedSemantic,
            18: DockerVolumePreservationResult,
            19: LifecycleV2ReauthenticationIntent,
            20: LifecycleV2AuthenticatedReauthenticationBinding,
            21: LifecycleV2TerminalCleanupPlan,
            22: LifecycleV2TerminalCleanupResult,
        }
    )

    def validate_transition(
        source: LifecycleV2NormalProgressLineage,
        result: object,
        expected_ordinal: int,
        transition_arguments: dict[str, object],
    ) -> LifecycleV2NormalProgressLineage:
        require_authority_caller(
            transition_validation_callers,
            "normal lifecycle transition validation",
        )
        if type(result) is not LifecycleV2NormalProgressLineage:
            _reject("named lifecycle transition returned an inexact lineage")
        exact_result = result
        if (
            exact_result.root is not source.root
            or exact_result.terminal_wire is not source.terminal_wire
            or exact_result.clean_stop_result is not source.clean_stop_result
            or len(exact_result.records) != len(source.records) + 1
            or len(exact_result.semantics) != len(source.semantics) + 1
            or any(
                candidate is not retained
                for candidate, retained in zip(
                    exact_result.records[:-1], source.records, strict=True
                )
            )
            or any(
                candidate is not retained
                for candidate, retained in zip(
                    exact_result.semantics[:-1], source.semantics, strict=True
                )
            )
            or type(exact_result.semantics[-1]) is not semantic_type_by_ordinal[expected_ordinal]
        ):
            _reject("named lifecycle transition substituted retained identity")
        record = _exact_record(exact_result.records[-1])
        spec = _SPECS[expected_ordinal]
        if (
            record.ordinal != expected_ordinal
            or record.stage is not spec.stage
            or record.effect_kind != spec.effect_kind
            or record.predecessor_sha256 != source.records[-1].sha256
            or record.root_sha256 != source.root.sha256
            or record.graceful_stop_operation_id != source.root.graceful_stop_operation_id
            or record.deadline_boottime_ns != source.root.operation_deadline_boottime_ns
        ):
            _reject("named lifecycle transition changed ordinal, stage, effect, or deadline")
        trace_changes = frozenset({7, 8, 10, 12, 14, 16, 18})
        if expected_ordinal == 7:
            if (
                type(exact_result.docker_admission) is not DockerAdmissionCapture
                or type(exact_result.docker_trace) is not DockerAdmissionRootedTracePrefix
            ):
                _reject("ordinal seven omitted exact Docker admission identity")
        elif exact_result.docker_admission is not source.docker_admission:
            _reject("lifecycle transition substituted Docker admission identity")
        if (
            expected_ordinal not in trace_changes
            and exact_result.docker_trace is not source.docker_trace
        ):
            _reject("lifecycle transition substituted Docker trace identity")
        if expected_ordinal == 6:
            if (
                type(exact_result.pre_effect_binding)
                is not LifecycleV2AuthenticatedReauthenticationBinding
            ):
                _reject("ordinal six omitted its exact reauthentication binding")
        elif exact_result.pre_effect_binding is not source.pre_effect_binding:
            _reject("lifecycle transition substituted pre-effect binding identity")
        if expected_ordinal == 19:
            if type(exact_result.prefix_through_eighteen) is not LifecycleV2Transcript:
                _reject("ordinal nineteen omitted its exact prefix transcript")
        elif exact_result.prefix_through_eighteen is not source.prefix_through_eighteen:
            _reject("lifecycle transition substituted prefix transcript identity")
        if expected_ordinal == 21:
            plan = exact_result.terminal_cleanup_plan
            observer = transition_arguments.get("observer")
            authorized_boottime_ns = transition_arguments.get("cleanup_authorized_boottime_ns")
            if (
                type(plan) is not LifecycleV2TerminalCleanupPlan
                or plan is not exact_result.semantics[-1]
                or type(observer) is not LifecycleV2InjectedCleanupObserver
            ):
                _reject("ordinal twenty-one omitted its exact injected cleanup plan")
            not_before_boottime_ns = max(
                *(mount.observed_boottime_ns for mount in plan.mounts),
                cast(int, plan.recovery_absence.to_dict()["observed_boottime_ns"]),
                cast(int, plan.socket_absence.to_dict()["observed_boottime_ns"]),
                cast(int, plan.credential_absence.to_dict()["observed_boottime_ns"]),
                plan.owners.observed_boottime_ns,
            )
            exact_authorized_boottime_ns = _require_int(
                authorized_boottime_ns,
                "cleanup_authorized_boottime_ns",
            )
            authorization = mint_authorization(
                root=exact_result.root,
                cleanup_intent=exact_result.records[-1],
                observer=observer,
                authorized_boottime_ns=exact_authorized_boottime_ns,
                not_before_boottime_ns=not_before_boottime_ns,
            )
            object.__setattr__(plan, "authorization", authorization)
            object.__setattr__(
                exact_result,
                "terminal_cleanup_authorization",
                authorization,
            )
            authorization_metadata = require_compound(authorization)
            register_compound(
                plan,
                provenance=authorization_metadata.provenance,
                scope_sha256=authorization_metadata.scope_sha256,
            )
        else:
            if exact_result.terminal_cleanup_plan is not source.terminal_cleanup_plan:
                _reject("lifecycle transition substituted terminal cleanup plan")
            if (
                exact_result.terminal_cleanup_authorization
                is not source.terminal_cleanup_authorization
            ):
                _reject("lifecycle transition substituted terminal cleanup authorization")
        if expected_ordinal == 22:
            cleanup_result = exact_result.semantics[-1]
            terminal_authorization = exact_result.terminal_cleanup_authorization
            if (
                type(cleanup_result) is not LifecycleV2TerminalCleanupResult
                or type(terminal_authorization) is not LifecycleV2TerminalCleanupAuthorization
                or cleanup_result.authorization is not terminal_authorization
            ):
                _reject("ordinal twenty-two lacks finalized exact cleanup evidence")
            authorization_metadata = require_finalized_authorization(terminal_authorization)
            register_compound(
                cleanup_result,
                provenance=authorization_metadata.provenance,
                scope_sha256=authorization_metadata.scope_sha256,
            )
        validate_lineage_records(exact_result, exact_last_ordinal=expected_ordinal)
        return exact_result

    def wrap_transition(
        original: Callable[..., LifecycleV2NormalProgressLineage],
        expected_ordinal: int,
    ) -> Callable[..., LifecycleV2NormalProgressLineage]:
        def transition(
            self: LifecycleV2NormalProgressLineage,
            *args: object,
            **kwargs: object,
        ) -> LifecycleV2NormalProgressLineage:
            if type(self) is not LifecycleV2NormalProgressLineage:
                _reject("normal lifecycle transition requires an exact lineage")
            source_snapshot = _lineage_snapshot(self)
            source_metadata = registry_require(
                self,
                snapshot_sha256=source_snapshot,
                kind="normal_progress_lineage",
                provenance="authenticated_injected_lineage",
                scope_sha256=self.root.sha256,
                allow_consumed=False,
            )
            if source_metadata is None or self.records[-1].ordinal + 1 != expected_ordinal:
                _reject("normal lifecycle source is unavailable or already advanced")
            result = original(self, *args, **kwargs)
            exact_result = validate_transition(
                self,
                result,
                expected_ordinal,
                kwargs,
            )
            if not registry_transition(
                self,
                source_snapshot_sha256=source_snapshot,
                result=exact_result,
                result_snapshot_sha256=_lineage_snapshot(exact_result),
                kind="normal_progress_lineage",
                provenance=source_metadata.provenance,
                scope_sha256=source_metadata.scope_sha256,
            ):
                _reject("normal lifecycle transition was replayed or crossed runtime scope")
            return exact_result

        return transition

    transition_methods = (
        ("retain_transport_cleanup_commitment", 3),
        ("confirm_transport_channel_quiesced", 4),
        ("retain_pre_effect_reauthentication_intent", 5),
        ("retain_pre_effect_reauthentication_binding", 6),
        ("retain_supervisor_container_stop_intent", 7),
        ("retain_supervisor_container_stop_result", 8),
        ("retain_source_container_stop_intent", 9),
        ("retain_source_container_stop_result", 10),
        ("retain_supervisor_container_remove_intent", 11),
        ("retain_supervisor_container_remove_result", 12),
        ("retain_source_container_remove_intent", 13),
        ("retain_source_container_remove_result", 14),
        ("retain_project_network_remove_intent", 15),
        ("retain_project_network_remove_result", 16),
        ("retain_named_volume_preservation_intent", 17),
        ("retain_named_volumes_preserved", 18),
        ("retain_post_teardown_reauthentication_intent", 19),
        ("retain_post_teardown_reauthentication_binding", 20),
        ("retain_terminal_cleanup_intent", 21),
        ("retain_terminal_cleanup_confirmed", 22),
    )
    wrapped_transition_codes: set[CodeType] = set()
    terminal_confirmation_code: CodeType | None = None
    terminal_transition_code: CodeType | None = None
    for method_name, ordinal in transition_methods:
        original = cast(
            Callable[..., LifecycleV2NormalProgressLineage],
            getattr(LifecycleV2NormalProgressLineage, method_name),
        )
        if ordinal == 22:
            terminal_confirmation_code = original.__code__
        wrapped_transition = wrap_transition(original, ordinal)
        if ordinal == 22:
            terminal_transition_code = wrapped_transition.__code__
        wrapped_transition_codes.add(wrapped_transition.__code__)
        setattr(LifecycleV2NormalProgressLineage, method_name, wrapped_transition)

    def require_lineage_runtime(
        value: object,
        snapshot_sha256: str,
        root_sha256: str,
        allow_consumed: bool,
    ) -> RuntimeSealMetadata | None:
        if type(value) is not LifecycleV2NormalProgressLineage:
            return None
        return registry_require(
            value,
            snapshot_sha256=snapshot_sha256,
            kind="normal_progress_lineage",
            provenance="authenticated_injected_lineage",
            scope_sha256=root_sha256,
            allow_consumed=allow_consumed,
        )

    def require_lineage_prefix(value: object, ordinal: int) -> LifecycleV2NormalProgressLineage:
        if type(value) is not LifecycleV2NormalProgressLineage:
            _reject("normal lifecycle lineage prefix type is not exact")
        snapshot = _lineage_snapshot(value)
        if (
            registry_require(
                value,
                snapshot_sha256=snapshot,
                kind="normal_progress_lineage",
                provenance="authenticated_injected_lineage",
                scope_sha256=value.root.sha256,
                allow_consumed=False,
            )
            is None
        ):
            _reject("normal lifecycle lineage prefix is unavailable or already advanced")
        validate_lineage_records(value, exact_last_ordinal=ordinal)
        return value

    def require_through_five(value: object) -> LifecycleV2NormalProgressLineage:
        return require_lineage_prefix(value, 5)

    def require_through_nineteen(value: object) -> LifecycleV2NormalProgressLineage:
        result = require_lineage_prefix(value, 19)
        if (
            type(result.pre_effect_binding) is not LifecycleV2AuthenticatedReauthenticationBinding
            or type(result.prefix_through_eighteen) is not LifecycleV2Transcript
        ):
            _reject("ordinal-nineteen lineage omitted exact pre-binding or transcript")
        return result

    def consume_confirmed_success(value: object) -> LifecycleV2ConfirmedSuccessLineageSnapshot:
        if type(value) is not LifecycleV2NormalProgressLineage:
            _reject("confirmed success requires one exact normal lineage")
        lineage_digest = _lineage_snapshot(value)
        validate_lineage_records(value, exact_last_ordinal=22)
        metadata = registry_require(
            value,
            snapshot_sha256=lineage_digest,
            kind="normal_progress_lineage",
            provenance="authenticated_injected_lineage",
            scope_sha256=value.root.sha256,
            allow_consumed=False,
        )
        if metadata is None:
            _reject("confirmed-success lineage is unavailable or already advanced")
        cleanup_result = value.semantics[-1]
        authorization = value.terminal_cleanup_authorization
        if (
            type(cleanup_result) is not LifecycleV2TerminalCleanupResult
            or type(authorization) is not LifecycleV2TerminalCleanupAuthorization
            or cleanup_result.authorization is not authorization
        ):
            _reject("confirmed success lacks exact finalized ordinal-twenty-two evidence")
        require_finalized_authorization(authorization)
        cleanup_result._require_sealed()
        result = object.__new__(LifecycleV2ConfirmedSuccessLineageSnapshot)
        object.__setattr__(result, "root", value.root)
        object.__setattr__(result, "records", value.records)
        object.__setattr__(result, "root_encoded", value.root.encoded)
        object.__setattr__(
            result,
            "record_encoded",
            tuple(record.encoded for record in value.records),
        )
        object.__setattr__(result, "lineage_provenance", metadata.provenance)
        object.__setattr__(result, "lineage_snapshot_sha256", lineage_digest)
        object.__setattr__(result, "terminal_cleanup_result", cleanup_result)
        object.__setattr__(
            result,
            "terminal_cleanup_result_snapshot_sha256",
            _semantic_runtime_snapshot(cleanup_result),
        )
        transferred_metadata = registry_consume_action_and_transfer(
            value,
            source_snapshot_sha256=lineage_digest,
            source_kind="normal_progress_lineage",
            action="repository_confirmed_success",
            result=result,
            result_snapshot_sha256=_confirmed_success_snapshot(result),
            result_kind="confirmed_success_snapshot",
        )
        if transferred_metadata is not metadata:
            _reject("confirmed-success repository snapshot could not be atomically sealed")
        return result

    def consume_confirmed_success_snapshot_for_repository(
        value: object,
    ) -> LifecycleV2ConfirmedSuccessLineageSnapshot:
        if type(value) is not LifecycleV2ConfirmedSuccessLineageSnapshot:
            _reject("confirmed-success repository snapshot type is not exact")
        try:
            snapshot = _confirmed_success_snapshot(value)
        except (AttributeError, TypeError, TrustedTimeGracefulStopV2Rejected):
            _reject("confirmed-success repository snapshot is not sealed")
        value.terminal_cleanup_result._require_sealed()
        if (
            registry_consume(
                value,
                snapshot_sha256=snapshot,
                kind="confirmed_success_snapshot",
                scope_sha256=value.root.sha256,
            )
            is None
        ):
            _reject("confirmed-success repository snapshot is not sealed or was replayed")
        return value

    canonical_registration_callers = frozenset(
        {
            capture_host_identity.__code__,
            capture_supervisor_observation.__code__,
            capture_host_receipt.__code__,
            capture_reauth_intent.__code__,
            capture_reauth_binding.__code__,
            capture_reauth_binding_from_realm.__code__,
            capture_empty_mount.__code__,
            capture_mount_projection.__code__,
            capture_path_absence.__code__,
            capture_owner_set.__code__,
            capture_unmount_receipt.__code__,
            capture_owner_receipt.__code__,
            capture_fixed_semantic.__code__,
        }
    )
    compound_registration_callers = frozenset(
        {
            capture_transport_plan.__code__,
            capture_quiescence.__code__,
            mint_authorization.__code__,
            validate_transition.__code__,
        }
    )
    authorization_action_callers = frozenset(
        {
            consume_unmount.__code__,
            consume_native_owner.__code__,
            consume_final_recovery.__code__,
            consume_final_socket.__code__,
            consume_final_credential.__code__,
        }
    )
    authorization_mint_callers = frozenset({validate_transition.__code__})
    transition_validation_callers = frozenset(wrapped_transition_codes)
    if (
        terminal_confirmation_code is None
        or terminal_transition_code is None
        or exact_len(transition_validation_callers) != 1
    ):
        _reject("normal lifecycle transition caller topology is invalid")
    path_absence_code = cast(Any, original_path_absence).__func__.__code__
    unmount_receipt_code = cast(Any, original_unmount_receipt).__func__.__code__
    native_owner_receipt_code = cast(Any, original_owner_receipt).__func__.__code__
    unmount_action_call_chain = (
        unmount_receipt_code,
        capture_unmount_receipt.__code__,
    )
    native_owner_action_call_chain = (
        native_owner_receipt_code,
        capture_owner_receipt.__code__,
    )
    final_recovery_action_call_chain = (
        path_absence_code,
        capture_path_absence.__code__,
    )
    final_socket_action_call_chain = final_recovery_action_call_chain
    final_credential_action_call_chain = final_recovery_action_call_chain
    finalization_call_chain = (
        guarded_finalize_terminal_cleanup_authorization.__code__,
        terminal_confirmation_code,
        terminal_transition_code,
    )
    registry = LifecycleV2RuntimeSealRegistry(
        _seal_callers=frozenset(
            {
                register_canonical.__code__,
                register_compound.__code__,
                build_fake_observer.__code__,
                capture_initial_lineage.__code__,
            }
        ),
        _transition_callers=transition_validation_callers,
        _consume_action_callers=frozenset({consume_authorization_action.__code__}),
        _finalize_actions_callers=frozenset({finalize_authorization.__code__}),
        _consume_callers=frozenset({consume_confirmed_success_snapshot_for_repository.__code__}),
        _transfer_callers=frozenset({consume_confirmed_success.__code__}),
    )
    registry_seal = registry.seal
    registry_require = registry.require
    registry_consume = registry.consume
    registry_transition = registry.transition
    registry_consume_action = registry.consume_action
    registry_consume_action_and_transfer = registry.consume_action_and_transfer
    registry_finalize_actions = registry.finalize_actions
    _finalize_terminal_cleanup_authorization = guarded_finalize_terminal_cleanup_authorization

    return (
        install_reauthentication_issuance_consumer,
        capture_reauth_binding_from_realm,
        build_fake_observer,
        require_observer_runtime,
        require_canonical,
        require_compound,
        consume_unmount,
        consume_native_owner,
        consume_final_recovery,
        consume_final_socket,
        consume_final_credential,
        finalize_authorization,
        require_lineage_runtime,
        require_through_five,
        require_through_nineteen,
        consume_confirmed_success,
        consume_confirmed_success_snapshot_for_repository,
    )


(
    _install_lifecycle_v2_reauthentication_semantic_binding_issuance_consumer,
    _capture_lifecycle_v2_authenticated_reauthentication_binding_from_realm,
    _build_injected_fake_lifecycle_v2_cleanup_observer,
    _require_exact_cleanup_observer_runtime,
    _require_canonical_evidence,
    _require_exact_compound_value,
    _consume_terminal_cleanup_unmount_authorization,
    _consume_terminal_cleanup_native_owner_authorization,
    _consume_terminal_cleanup_final_recovery_absence_authorization,
    _consume_terminal_cleanup_final_socket_absence_authorization,
    _consume_terminal_cleanup_final_credential_absence_authorization,
    _finalize_exact_terminal_cleanup_authorization_runtime,
    _require_exact_normal_progress_lineage_runtime,
    require_exact_lifecycle_v2_normal_lineage_through_ordinal_5,
    require_exact_lifecycle_v2_normal_lineage_through_ordinal_19,
    consume_exact_lifecycle_v2_confirmed_success_lineage,
    consume_exact_lifecycle_v2_confirmed_success_snapshot_for_repository,
) = _install_lifecycle_v2_runtime_seals()
del _install_lifecycle_v2_runtime_seals


def lifecycle_v2_semantics_non_authority_facts() -> dict[str, bool]:
    return {
        "transport_opened": False,
        "docker_called": False,
        "signature_authenticated": False,
        "reauthentication_issuer_consumed": False,
        "artifact_published": False,
        "stop_authority_granted": False,
        "production_cleanup_observer_present": False,
        "raw_cleanup_assertion_authority_present": False,
        "production_caller_present": False,
    }


__all__ = [
    "HOST_RAW_KEY_PATH",
    "HOST_SECRET_MOUNT_PATH",
    "LIFECYCLE_V2_CLEANUP_SERVICE",
    "RECOVERY_SECRET_MOUNT_PATH",
    "SUPERVISOR_SECRET_MOUNT_PATH",
    "TRANSPORT_MOUNT_PATH",
    "LifecycleV2AuthenticatedReauthenticationBinding",
    "LifecycleV2ConfirmedSuccessLineageSnapshot",
    "LifecycleV2EmptySecretMountIdentity",
    "LifecycleV2EmptySecretMountProjection",
    "LifecycleV2HostTransportCleanupIdentity",
    "LifecycleV2HostTransportCleanupReceipt",
    "LifecycleV2InjectedCleanupObserver",
    "LifecycleV2NativeOwnerCleanupReceipt",
    "LifecycleV2NativeOwnerSet",
    "LifecycleV2NormalProgressLineage",
    "LifecycleV2PathAbsence",
    "LifecycleV2ReauthenticationIntent",
    "LifecycleV2SecretMountUnmountReceipt",
    "LifecycleV2SupervisorQuiescenceObservation",
    "LifecycleV2TerminalCleanupAuthorization",
    "LifecycleV2TerminalCleanupPlan",
    "LifecycleV2TerminalCleanupResult",
    "LifecycleV2TransportCleanupPlan",
    "LifecycleV2TransportQuiescence",
    "TrustedTimeLifecycleV2SemanticsRejected",
    "consume_exact_lifecycle_v2_confirmed_success_lineage",
    "consume_exact_lifecycle_v2_confirmed_success_snapshot_for_repository",
    "lifecycle_v2_semantics_non_authority_facts",
    "require_exact_lifecycle_v2_normal_lineage_through_ordinal_5",
    "require_exact_lifecycle_v2_normal_lineage_through_ordinal_19",
]
