"""Exact normal-path lifecycle-v2 progress semantics for ADR 0121.

The values in this module are evidence-only.  They cannot open a transport,
call Docker, authenticate an ADR-0109 observation, publish an artifact, or
grant stop authority.  A sealed lineage exposes one named method per normal
ordinal so no caller can select a stage, ordinal, predecessor, or effect kind.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Never, Self, cast

from packages.domain.trusted_time_graceful_stop_v2 import (
    LIFECYCLE_V2_OPERATION_BUDGET_NS,
    MAXIMUM_SIGNED_INTEGER,
    FrozenJsonObject,
    LifecycleV2ProgressRecord,
    LifecycleV2Root,
    LifecycleV2Stage,
    LifecycleV2Transcript,
    TrustedTimeGracefulStopV2Rejected,
    canonical_v2_json_bytes,
    decode_lifecycle_v2_progress_record,
    decode_lifecycle_v2_root,
    decode_lifecycle_v2_transcript,
)
from packages.domain.trusted_time_graceful_stop_v2_docker import (
    COMMAND_SOCKET_VOLUME,
    STATE_VOLUME,
    DockerAdmissionCapture,
    DockerAdmissionRootedTracePrefix,
    DockerMutationResultSemantic,
    DockerPlanIdentity,
    DockerRequestSemantic,
    DockerVolumePreservationResult,
    docker_call_spec,
)
from packages.domain.trusted_time_graceful_stop_v2_terminal import (
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
_LINEAGE_CAPABILITY = object()
_CANONICAL_EVIDENCE_CAPABILITY = object()
_TRANSPORT_PLAN_CAPABILITY = object()
_TRANSPORT_QUIESCENCE_CAPABILITY = object()
_FAKE_REAUTHENTICATION_BINDING_CAPABILITY = object()
_PRODUCTION_REAUTHENTICATION_BINDING_CAPABILITY = object()
_TYPED_STAGE_CAPABILITY = object()


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
    _evidence_capability: object

    def _require_canonical_seal(self) -> None:
        if getattr(self, "_evidence_capability", None) is not _CANONICAL_EVIDENCE_CAPABILITY:
            _reject("typed lifecycle semantic is not canonically sealed")

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
        host_socket_identity_sha256: str,
        host_peer_credential_sha256: str,
        host_raw_key_device: int,
        host_raw_key_inode: int,
        host_challenge_sha256: str,
        host_process_nonce_sha256: str,
    ) -> Self:
        exact_root = _exact_root(root)
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
        object.__setattr__(result, "_evidence_capability", _CANONICAL_EVIDENCE_CAPABILITY)
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
    _capability: object

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
        if (
            exact_record.ordinal != 2
            or exact_record.stage is not LifecycleV2Stage.CLEAN_STOP_RESULT_RETAINED
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
        object.__setattr__(result, "_capability", _TRANSPORT_PLAN_CAPABILITY)
        return result

    def _require_sealed(self) -> None:
        if getattr(self, "_capability", None) is not _TRANSPORT_PLAN_CAPABILITY:
            _reject("transport cleanup plan is not sealed")


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
    ) -> Self:
        exact_root = _exact_root(root)
        if type(plan) is not LifecycleV2TransportCleanupPlan:
            _reject("supervisor quiescence requires one exact cleanup plan")
        plan._require_sealed()
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
        object.__setattr__(result, "_evidence_capability", _CANONICAL_EVIDENCE_CAPABILITY)
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
    ) -> Self:
        exact_root = _exact_root(root)
        if type(plan) is not LifecycleV2TransportCleanupPlan:
            _reject("host cleanup requires one exact cleanup plan")
        plan._require_sealed()
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
        object.__setattr__(result, "_evidence_capability", _CANONICAL_EVIDENCE_CAPABILITY)
        return result

    @property
    def digest_domain(self) -> str:
        return "AutoQuantTrader/trusted-time/graceful-stop/host-transport-cleanup-receipt/v2"


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2TransportQuiescence:
    evidence: FrozenJsonObject
    observation: LifecycleV2SupervisorQuiescenceObservation
    host_receipt: LifecycleV2HostTransportCleanupReceipt
    _capability: object

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
        plan._require_sealed()
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
        object.__setattr__(result, "_capability", _TRANSPORT_QUIESCENCE_CAPABILITY)
        return result

    def _require_sealed(self) -> None:
        if getattr(self, "_capability", None) is not _TRANSPORT_QUIESCENCE_CAPABILITY:
            _reject("transport quiescence is not sealed")


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
        object.__setattr__(result, "_evidence_capability", _CANONICAL_EVIDENCE_CAPABILITY)
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
    boundary: str
    _capability: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("reauthentication bindings require an authentication seam")

    @classmethod
    def _capture(
        cls,
        value: object,
        *,
        root: LifecycleV2Root,
        intent: LifecycleV2ReauthenticationIntent,
        capability: object,
    ) -> Self:
        if capability not in {
            _FAKE_REAUTHENTICATION_BINDING_CAPABILITY,
            _PRODUCTION_REAUTHENTICATION_BINDING_CAPABILITY,
        }:
            _reject("reauthentication binding capability is invalid")
        exact_root = _exact_root(root)
        if type(intent) is not LifecycleV2ReauthenticationIntent:
            _reject("reauthentication binding requires one exact typed intent")
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _REAUTHENTICATION_BINDING_FIELDS, "reauthentication binding")
        boundary = intent.boundary
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
            or fields["observed_head_sha256"] != intent.to_dict()["expected_head_sha256"]
            or fields["provider_identity_sha256"] != intent.to_dict()["provider_identity_sha256"]
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
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        object.__setattr__(result, "_evidence_capability", _CANONICAL_EVIDENCE_CAPABILITY)
        object.__setattr__(result, "boundary", boundary)
        object.__setattr__(result, "_capability", capability)
        return result

    def _require_sealed(self) -> None:
        if getattr(self, "_capability", None) not in {
            _FAKE_REAUTHENTICATION_BINDING_CAPABILITY,
            _PRODUCTION_REAUTHENTICATION_BINDING_CAPABILITY,
        }:
            _reject("reauthentication binding is not sealed")

    @property
    def digest_domain(self) -> str:
        self._require_sealed()
        return (
            "AutoQuantTrader/trusted-time/graceful-stop/"
            f"{self.boundary.replace('_', '-')}-reauthentication-binding/v2"
        )


def _mint_fake_lifecycle_v2_reauthentication_binding(
    value: object,
    *,
    root: LifecycleV2Root,
    intent: LifecycleV2ReauthenticationIntent,
    capability: object,
) -> LifecycleV2AuthenticatedReauthenticationBinding:
    """Test-only seam; the distinct production seams use a separate capability."""

    if capability is not _FAKE_REAUTHENTICATION_BINDING_CAPABILITY:
        _reject("fake reauthentication binding capability is invalid")
    return LifecycleV2AuthenticatedReauthenticationBinding._capture(
        value,
        root=root,
        intent=intent,
        capability=capability,
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

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("secret mount identities require canonical capture")

    @classmethod
    def capture(cls, value: object) -> Self:
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
        object.__setattr__(result, "_evidence_capability", _CANONICAL_EVIDENCE_CAPABILITY)
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
        object.__setattr__(result, "_evidence_capability", _CANONICAL_EVIDENCE_CAPABILITY)
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

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("path absence requires a fixed closed absence kind")

    @classmethod
    def _fixed(
        cls,
        *,
        root: LifecycleV2Root,
        kind: str,
        observed_boottime_ns: int,
    ) -> Self:
        exact_root = _exact_root(root)
        paths = _ABSENCE_PATHS[kind]
        observed = _require_int(observed_boottime_ns, "observed_boottime_ns")
        if observed >= exact_root.operation_deadline_boottime_ns:
            _reject("path-absence observation is equality-expired or late")
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
        object.__setattr__(result, "_evidence_capability", _CANONICAL_EVIDENCE_CAPABILITY)
        object.__setattr__(result, "absence_kind", kind)
        return result

    @classmethod
    def recovery_secret_mount(cls, *, root: LifecycleV2Root, observed_boottime_ns: int) -> Self:
        return cls._fixed(
            root=root,
            kind="recovery_secret_mount",
            observed_boottime_ns=observed_boottime_ns,
        )

    @classmethod
    def transport_socket(cls, *, root: LifecycleV2Root, observed_boottime_ns: int) -> Self:
        return cls._fixed(
            root=root,
            kind="transport_socket",
            observed_boottime_ns=observed_boottime_ns,
        )

    @classmethod
    def credential_paths(cls, *, root: LifecycleV2Root, observed_boottime_ns: int) -> Self:
        return cls._fixed(
            root=root,
            kind="credential_paths",
            observed_boottime_ns=observed_boottime_ns,
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

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("native owner sets require closed kind-sorted capture")

    @classmethod
    def capture(cls, *, root: LifecycleV2Root, owners: object) -> Self:
        exact_root = _exact_root(root)
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
        object.__setattr__(result, "_evidence_capability", _CANONICAL_EVIDENCE_CAPABILITY)
        object.__setattr__(result, "root_sha256", exact_root.sha256)
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


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2SecretMountUnmountReceipt(_CanonicalEvidence):
    fields: FrozenJsonObject

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("unmount receipts require the exact three-mount order")

    @classmethod
    def completed(
        cls,
        *,
        root: LifecycleV2Root,
        projection: LifecycleV2EmptySecretMountProjection,
        completed_boottime_ns: object,
    ) -> Self:
        exact_root = _exact_root(root)
        if type(projection) is not LifecycleV2EmptySecretMountProjection:
            _reject("unmount receipt requires the complete empty-mount projection")
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
        if not parsed[0] <= parsed[1] <= parsed[2] < exact_root.operation_deadline_boottime_ns:
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
        object.__setattr__(result, "_evidence_capability", _CANONICAL_EVIDENCE_CAPABILITY)
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

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("native owner cleanup receipts require an exact owner set")

    @classmethod
    def completed(
        cls,
        *,
        root: LifecycleV2Root,
        owners: LifecycleV2NativeOwnerSet,
        completed_boottime_ns: int,
    ) -> Self:
        exact_root = _exact_root(root)
        if type(owners) is not LifecycleV2NativeOwnerSet:
            _reject("native cleanup receipt requires one exact native owner set")
        if owners.root_sha256 != exact_root.sha256:
            _reject("native cleanup receipt crossed its owner-set root")
        completed = _require_int(completed_boottime_ns, "completed_boottime_ns")
        if completed >= exact_root.operation_deadline_boottime_ns:
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
        object.__setattr__(result, "_evidence_capability", _CANONICAL_EVIDENCE_CAPABILITY)
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

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("terminal cleanup plans require exact prior lifecycle evidence")


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2TerminalCleanupResult:
    evidence: FrozenJsonObject
    empty_mounts: LifecycleV2EmptySecretMountProjection
    unmount_receipt: LifecycleV2SecretMountUnmountReceipt
    native_owner_receipt: LifecycleV2NativeOwnerCleanupReceipt

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("terminal cleanup results require exact typed cleanup evidence")


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
    _capability: object

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
        object.__setattr__(result, "_capability", _LINEAGE_CAPABILITY)
        return result

    def _require_sealed(self) -> None:
        if getattr(self, "_capability", None) is not _LINEAGE_CAPABILITY:
            _reject("normal lifecycle lineage is not sealed")

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

    def _materialize_validated_stage(
        self,
        *,
        _capability: object,
        evidence: FrozenJsonObject,
        semantic: object,
        recorded_at_utc: str,
        docker_admission: DockerAdmissionCapture | None = None,
        docker_trace: DockerAdmissionRootedTracePrefix | None = None,
        pre_effect_binding: LifecycleV2AuthenticatedReauthenticationBinding | None = None,
        prefix_through_eighteen: LifecycleV2Transcript | None = None,
        terminal_cleanup_plan: LifecycleV2TerminalCleanupPlan | None = None,
    ) -> Self:
        self._require_sealed()
        if _capability is not _TYPED_STAGE_CAPABILITY:
            _reject("lifecycle stage was not produced by its named typed builder")
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
        object.__setattr__(result, "root", self.root)
        object.__setattr__(result, "records", (*self.records, record))
        object.__setattr__(result, "semantics", (*self.semantics, semantic))
        object.__setattr__(result, "terminal_wire", self.terminal_wire)
        object.__setattr__(result, "clean_stop_result", self.clean_stop_result)
        object.__setattr__(
            result,
            "docker_admission",
            self.docker_admission if docker_admission is None else docker_admission,
        )
        object.__setattr__(
            result,
            "docker_trace",
            self.docker_trace if docker_trace is None else docker_trace,
        )
        object.__setattr__(
            result,
            "pre_effect_binding",
            self.pre_effect_binding if pre_effect_binding is None else pre_effect_binding,
        )
        object.__setattr__(
            result,
            "prefix_through_eighteen",
            self.prefix_through_eighteen
            if prefix_through_eighteen is None
            else prefix_through_eighteen,
        )
        object.__setattr__(
            result,
            "terminal_cleanup_plan",
            self.terminal_cleanup_plan if terminal_cleanup_plan is None else terminal_cleanup_plan,
        )
        object.__setattr__(result, "_capability", _LINEAGE_CAPABILITY)
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
        return self._materialize_validated_stage(
            _capability=_TYPED_STAGE_CAPABILITY,
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
        return self._materialize_validated_stage(
            _capability=_TYPED_STAGE_CAPABILITY,
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
        return self._materialize_validated_stage(
            _capability=_TYPED_STAGE_CAPABILITY,
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
            }
        )
        return self._materialize_validated_stage(
            _capability=_TYPED_STAGE_CAPABILITY,
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
        _capability: object,
        rule: _DockerRule,
        admission: DockerAdmissionCapture,
        trace_prefix: DockerAdmissionRootedTracePrefix,
        call_deadline_boottime_ns: int,
        recorded_at_utc: str,
    ) -> Self:
        if (
            _capability is not _TYPED_STAGE_CAPABILITY
            or not any(rule is fixed_rule for fixed_rule in _DOCKER_RULES.values())
            or self.last_record.ordinal + 1 != rule.intent_ordinal
        ):
            _reject("Docker intent is not the one fixed next lifecycle stage")
        expected_prior_trace = rule.primary_connection_ordinal - 1
        self._require_docker_admission(
            admission, trace_prefix, expected_last_ordinal=expected_prior_trace
        )
        if (
            self.docker_trace is not None
            and trace_prefix.trace_head_sha256 != self.docker_trace.trace_head_sha256
        ):
            _reject("Docker intent did not consume the exact prior trace head")
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
        return self._materialize_validated_stage(
            _capability=_TYPED_STAGE_CAPABILITY,
            evidence=evidence,
            semantic=intent,
            recorded_at_utc=recorded_at_utc,
            docker_admission=admission,
            docker_trace=trace_prefix,
        )

    def _retain_docker_result(
        self,
        *,
        _capability: object,
        rule: _DockerRule,
        result_semantic: DockerMutationResultSemantic,
        trace_prefix: DockerAdmissionRootedTracePrefix,
        recorded_at_utc: str,
    ) -> Self:
        if (
            _capability is not _TYPED_STAGE_CAPABILITY
            or not any(rule is fixed_rule for fixed_rule in _DOCKER_RULES.values())
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
        return self._materialize_validated_stage(
            _capability=_TYPED_STAGE_CAPABILITY,
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
            _capability=_TYPED_STAGE_CAPABILITY,
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
            _capability=_TYPED_STAGE_CAPABILITY,
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
            _capability=_TYPED_STAGE_CAPABILITY,
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
            _capability=_TYPED_STAGE_CAPABILITY,
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
            _capability=_TYPED_STAGE_CAPABILITY,
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
            _capability=_TYPED_STAGE_CAPABILITY,
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
            _capability=_TYPED_STAGE_CAPABILITY,
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
            _capability=_TYPED_STAGE_CAPABILITY,
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
            _capability=_TYPED_STAGE_CAPABILITY,
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
            _capability=_TYPED_STAGE_CAPABILITY,
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
        return self._materialize_validated_stage(
            _capability=_TYPED_STAGE_CAPABILITY,
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
        return self._materialize_validated_stage(
            _capability=_TYPED_STAGE_CAPABILITY,
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
            or prefix_transcript.entries[-1].ordinal != 18
        ):
            _reject("post-teardown transcript is not the exact ordinal-eighteen prefix")
        by_ordinal = {record.ordinal: record for record in self.records}
        for entry in prefix_transcript.entries[2:]:
            expected = by_ordinal.get(entry.ordinal)
            if expected is None or entry.record_artifact_sha256 != expected.sha256:
                _reject("post-teardown transcript substituted a lifecycle record")
        terminal_wire = self.terminal_wire.to_dict()
        wire_entry = prefix_transcript.entries[2]
        if (
            wire_entry.wire_artifact_kind != "signed_result_envelope"
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
        return self._materialize_validated_stage(
            _capability=_TYPED_STAGE_CAPABILITY,
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
            }
        )
        return self._materialize_validated_stage(
            _capability=_TYPED_STAGE_CAPABILITY,
            evidence=evidence,
            semantic=binding,
            recorded_at_utc=recorded_at_utc,
        )

    def retain_terminal_cleanup_intent(
        self,
        *,
        mounts: object,
        recovery_secret_mount_absence: LifecycleV2PathAbsence,
        socket_path_absence: LifecycleV2PathAbsence,
        credential_path_absence: LifecycleV2PathAbsence,
        native_owner_set: LifecycleV2NativeOwnerSet,
        recorded_at_utc: str,
    ) -> Self:
        if self.last_record.ordinal != 20:
            _reject("terminal cleanup intent is not the fixed ordinal-twenty-one input")
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
            if cast(int, absence.to_dict()["observed_boottime_ns"]) < last_completed:
                _reject("terminal cleanup plan reused a pre-binding absence observation")
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
        return self._materialize_validated_stage(
            _capability=_TYPED_STAGE_CAPABILITY,
            evidence=evidence,
            semantic=plan,
            recorded_at_utc=recorded_at_utc,
            terminal_cleanup_plan=plan,
        )

    def retain_terminal_cleanup_confirmed(
        self,
        *,
        empty_mount_projection: LifecycleV2EmptySecretMountProjection,
        unmount_receipt: LifecycleV2SecretMountUnmountReceipt,
        native_owner_cleanup_receipt: LifecycleV2NativeOwnerCleanupReceipt,
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
            or type(socket_absence) is not LifecycleV2PathAbsence
            or socket_absence.absence_kind != "transport_socket"
            or type(credential_path_absence) is not LifecycleV2PathAbsence
            or credential_path_absence.absence_kind != "credential_paths"
        ):
            _reject("terminal cleanup result is not the fixed ordinal-twenty-two input")
        if tuple(mount.sha256 for mount in empty_mount_projection.mounts) != tuple(
            mount.sha256 for mount in plan.mounts
        ):
            _reject("terminal cleanup mount identity drifted from its durable plan")
        projection_fields = empty_mount_projection.to_dict()
        for value in (
            projection_fields,
            unmount_receipt.to_dict(),
            native_owner_cleanup_receipt.to_dict(),
            socket_absence.to_dict(),
            credential_path_absence.to_dict(),
        ):
            if (
                value["environment"] != self.root.environment
                or value["graceful_stop_operation_id"] != self.root.graceful_stop_operation_id
                or value["lifecycle_root_sha256"] != self.root.sha256
            ):
                _reject("terminal cleanup evidence crossed its lifecycle root")
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
        planned_socket_time = cast(int, plan.socket_absence.to_dict()["observed_boottime_ns"])
        planned_credential_time = cast(
            int, plan.credential_absence.to_dict()["observed_boottime_ns"]
        )
        socket_time = cast(int, socket_absence.to_dict()["observed_boottime_ns"])
        credential_time = cast(int, credential_path_absence.to_dict()["observed_boottime_ns"])
        completed = max(
            unmount_receipt.completed_boottime_ns,
            native_owner_cleanup_receipt.completed_boottime_ns,
            socket_time,
            credential_time,
        )
        if not (
            socket_time >= planned_socket_time
            and credential_time >= planned_credential_time
            and completed < self.root.operation_deadline_boottime_ns
        ):
            _reject("terminal cleanup absence or completion evidence is stale or late")
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
                "all_private_material_unreachable": True,
                "cleanup_completed_boottime_ns": completed,
            }
        )
        object.__setattr__(result, "evidence", evidence)
        object.__setattr__(result, "empty_mounts", empty_mount_projection)
        object.__setattr__(result, "unmount_receipt", unmount_receipt)
        object.__setattr__(result, "native_owner_receipt", native_owner_cleanup_receipt)
        return self._materialize_validated_stage(
            _capability=_TYPED_STAGE_CAPABILITY,
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
        object.__setattr__(result, "_evidence_capability", _CANONICAL_EVIDENCE_CAPABILITY)
        object.__setattr__(result, "_domain", domain)
        return result

    @property
    def digest_domain(self) -> str:
        return self._domain


def lifecycle_v2_semantics_non_authority_facts() -> dict[str, bool]:
    return {
        "transport_opened": False,
        "docker_called": False,
        "signature_authenticated": False,
        "reauthentication_issuer_consumed": False,
        "artifact_published": False,
        "stop_authority_granted": False,
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
    "LifecycleV2EmptySecretMountIdentity",
    "LifecycleV2EmptySecretMountProjection",
    "LifecycleV2HostTransportCleanupIdentity",
    "LifecycleV2HostTransportCleanupReceipt",
    "LifecycleV2NativeOwnerCleanupReceipt",
    "LifecycleV2NativeOwnerSet",
    "LifecycleV2NormalProgressLineage",
    "LifecycleV2PathAbsence",
    "LifecycleV2ReauthenticationIntent",
    "LifecycleV2SecretMountUnmountReceipt",
    "LifecycleV2SupervisorQuiescenceObservation",
    "LifecycleV2TerminalCleanupPlan",
    "LifecycleV2TerminalCleanupResult",
    "LifecycleV2TransportCleanupPlan",
    "LifecycleV2TransportQuiescence",
    "TrustedTimeLifecycleV2SemanticsRejected",
    "lifecycle_v2_semantics_non_authority_facts",
]
