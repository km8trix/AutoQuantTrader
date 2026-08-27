"""Effect-free fault fakes for the partial ADR-0121 milestone-one core.

These adapters contain no socket, HTTP, Docker SDK, subprocess, or filesystem
call.  Their only purpose is deterministic state-machine and ambiguity tests.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Never

from packages.domain.trusted_time_graceful_stop_v2 import (
    _FAKE_TRANSPORT_AUTHENTICATION_CAPABILITY,
    LifecycleV2CleanStopRequest,
    UnverifiedLifecycleV2TransportEnvelope,
    _authenticate_lifecycle_v2_transport_envelope_for_fake,
    _FakeAuthenticatedLifecycleV2TransportEnvelope,
    canonical_v2_json_bytes,
)
from packages.persistence.trusted_time_graceful_stop_v2 import (
    LifecycleV2ArtifactAlreadyExists,
    LifecycleV2ArtifactPublicationUncertain,
)


class FakeLifecycleV2Fault(RuntimeError):
    """A deterministic fake boundary fault."""


@dataclass(frozen=True, slots=True)
class FakePublicationFault:
    operation: str
    phase: str

    def __post_init__(self) -> None:
        if type(self.operation) is not str or not self.operation:
            raise ValueError("fake publication operation is required")
        if self.phase not in {
            "before",
            "staging_created",
            "file_fsynced",
            "renamed",
            "directory_fsynced",
            "readback",
        }:
            raise ValueError("fake publication phase is invalid")


class FakeLifecycleV2ArtifactStore:
    """An immutable-name store with injectable publication ambiguity."""

    __slots__ = ("_artifacts", "_fault", "_fault_consumed", "events")

    def __init__(
        self,
        *,
        initial: dict[str, bytes] | None = None,
        fault: FakePublicationFault | None = None,
    ) -> None:
        self._artifacts = dict(initial or {})
        self._fault = fault
        self._fault_consumed = False
        self.events: list[str] = []

    def _maybe_fault(self, operation: str, phase: str) -> None:
        self.events.append(f"{operation}:{phase}")
        if (
            self._fault is not None
            and not self._fault_consumed
            and self._fault.operation == operation
            and self._fault.phase == phase
        ):
            self._fault_consumed = True
            raise LifecycleV2ArtifactPublicationUncertain(f"{operation}:{phase}")

    def inventory(self) -> tuple[str, ...]:
        return tuple(sorted(self._artifacts))

    def read_stable(self, file_name: str) -> bytes:
        self.events.append(f"read:{file_name}")
        try:
            return self._artifacts[file_name]
        except KeyError as error:
            raise LifecycleV2ArtifactPublicationUncertain("artifact is absent") from error

    def create_root_exclusive(self, file_name: str, encoded: bytes) -> None:
        operation = "root"
        self._maybe_fault(operation, "before")
        if file_name in self._artifacts:
            raise LifecycleV2ArtifactAlreadyExists(file_name)
        self._artifacts[file_name] = encoded
        self._maybe_fault(operation, "renamed")
        self._maybe_fault(operation, "directory_fsynced")
        self._maybe_fault(operation, "readback")

    def publish_immutable(
        self,
        *,
        staging_name: str,
        final_name: str,
        encoded: bytes,
    ) -> None:
        operation = _publication_operation(final_name)
        self._maybe_fault(operation, "before")
        if staging_name in self._artifacts:
            raise LifecycleV2ArtifactAlreadyExists(staging_name)
        if final_name in self._artifacts:
            if self._artifacts[final_name] == encoded:
                self.events.append(f"{operation}:revalidated")
                return
            raise LifecycleV2ArtifactAlreadyExists(final_name)
        self._artifacts[staging_name] = encoded
        self._maybe_fault(operation, "staging_created")
        self._maybe_fault(operation, "file_fsynced")
        self._artifacts[final_name] = self._artifacts.pop(staging_name)
        self._maybe_fault(operation, "renamed")
        self._maybe_fault(operation, "directory_fsynced")
        if self._artifacts[final_name] != encoded:
            raise LifecycleV2ArtifactPublicationUncertain("fake readback drift")
        self._maybe_fault(operation, "readback")

    def inject(self, file_name: str, encoded: bytes) -> None:
        """Test-only incident-state injection, never repository cleanup."""

        self._artifacts[file_name] = encoded


def _publication_operation(file_name: str) -> str:
    if "wire-result" in file_name:
        return "wire_result"
    if "wire-error" in file_name:
        return "wire_error"
    if "record-" in file_name:
        return "record"
    if "transcript-" in file_name:
        return "transcript"
    if "outcome-" in file_name and not file_name.startswith("."):
        return "outcome"
    if file_name.startswith(".post-enrollment-graceful-stop-outcome-committed"):
        return "commit"
    return "unknown"


class FakeLifecycleV2Transport:
    """One-request/one-terminal-frame transport with no real I/O or signing."""

    __slots__ = ("_response", "_used", "events", "fail_at")

    def __init__(
        self,
        response: UnverifiedLifecycleV2TransportEnvelope,
        *,
        fail_at: str | None = None,
    ) -> None:
        if type(
            response
        ) is not UnverifiedLifecycleV2TransportEnvelope or response.frame_type not in {
            "clean_stop_result",
            "clean_stop_error",
        }:
            raise ValueError("fake transport requires one exact terminal envelope")
        if fail_at not in {None, "before_send", "after_send", "before_receive", "after_receive"}:
            raise ValueError("fake transport fault boundary is invalid")
        self._response = response
        self._used = False
        self.events: list[str] = []
        self.fail_at = fail_at

    def exchange(
        self,
        request: LifecycleV2CleanStopRequest,
        request_envelope: UnverifiedLifecycleV2TransportEnvelope,
    ) -> _FakeAuthenticatedLifecycleV2TransportEnvelope:
        if self._used:
            raise FakeLifecycleV2Fault("transport replay is forbidden")
        self._used = True
        if (
            type(request) is not LifecycleV2CleanStopRequest
            or type(request_envelope) is not UnverifiedLifecycleV2TransportEnvelope
            or request_envelope.frame_type != "clean_stop_request"
            or request_envelope.payload != request.encoded
        ):
            raise FakeLifecycleV2Fault("transport request does not bind its envelope")
        request_fields = request_envelope.to_dict()
        response_fields = self._response.to_dict()
        for name in (
            "environment",
            "key_generation",
            "boot_epoch_sha256",
            "host_process_epoch_sha256",
            "supervisor_process_epoch_sha256",
            "channel_id",
            "lifecycle_dispatch_prefix_sha256",
            "deadline_boottime_ns",
        ):
            if request_fields[name] != response_fields[name]:
                raise FakeLifecycleV2Fault("terminal frame is cross-channel or cross-deadline")
        for boundary in ("before_send", "after_send", "before_receive", "after_receive"):
            self.events.append(boundary)
            if self.fail_at == boundary:
                raise FakeLifecycleV2Fault(boundary)
        return _authenticate_lifecycle_v2_transport_envelope_for_fake(
            self._response,
            capability=_FAKE_TRANSPORT_AUTHENTICATION_CAPABILITY,
        )


@dataclass(frozen=True, slots=True)
class FakeDockerEffectResult:
    operation: str
    target_id: str
    request_semantic_sha256: str
    result_semantic_sha256: str


class FakeLifecycleV2DockerEffects:
    """Exact-method fake; notably has no generic request or volume delete method."""

    __slots__ = ("_burned", "_failed_operation", "_used", "events")

    def __init__(self, *, failed_operation: str | None = None) -> None:
        allowed = {
            "stop_supervisor",
            "stop_source",
            "remove_supervisor",
            "remove_source",
            "remove_network",
            "prove_volumes",
        }
        if failed_operation is not None and failed_operation not in allowed:
            raise ValueError("fake Docker failure operation is invalid")
        self._burned = False
        self._failed_operation = failed_operation
        self._used: set[str] = set()
        self.events: list[str] = []

    def _perform(
        self,
        operation: str,
        target_id: str,
        request: dict[str, object],
    ) -> FakeDockerEffectResult:
        if self._burned:
            raise FakeLifecycleV2Fault("effect adapter is burned")
        if operation in self._used:
            self._reject("effect replay is forbidden")
        self._used.add(operation)
        self.events.append(operation)
        try:
            if self._failed_operation == operation:
                raise FakeLifecycleV2Fault(operation)
            request_encoded = canonical_v2_json_bytes(request, maximum_bytes=16 * 1_024)
            request_digest = hashlib.sha256(request_encoded).hexdigest()
            result = {
                "operation": operation,
                "outcome": "fake_confirmed",
                "request_semantic_sha256": request_digest,
                "target_id": target_id,
            }
            result_digest = hashlib.sha256(
                canonical_v2_json_bytes(result, maximum_bytes=16 * 1_024)
            ).hexdigest()
            return FakeDockerEffectResult(operation, target_id, request_digest, result_digest)
        except BaseException:
            self._burned = True
            raise

    def _reject(self, message: str) -> Never:
        self._burned = True
        raise FakeLifecycleV2Fault(message)

    def stop_supervisor(self, container_id: str) -> FakeDockerEffectResult:
        return self._perform(
            "stop_supervisor",
            container_id,
            {"method": "POST", "path": f"/v1.45/containers/{container_id}/stop?t=30"},
        )

    def stop_source(self, container_id: str) -> FakeDockerEffectResult:
        if "stop_supervisor" not in self._used:
            self._reject("source cannot stop before supervisor")
        return self._perform(
            "stop_source",
            container_id,
            {"method": "POST", "path": f"/v1.45/containers/{container_id}/stop?t=30"},
        )

    def remove_supervisor(self, container_id: str) -> FakeDockerEffectResult:
        if "stop_source" not in self._used:
            self._reject("containers must stop before removal")
        return self._perform(
            "remove_supervisor",
            container_id,
            {
                "method": "DELETE",
                "path": f"/v1.45/containers/{container_id}?v=false&force=false&link=false",
            },
        )

    def remove_source(self, container_id: str) -> FakeDockerEffectResult:
        if "remove_supervisor" not in self._used:
            self._reject("supervisor must be removed before source")
        return self._perform(
            "remove_source",
            container_id,
            {
                "method": "DELETE",
                "path": f"/v1.45/containers/{container_id}?v=false&force=false&link=false",
            },
        )

    def remove_network(self, network_id: str) -> FakeDockerEffectResult:
        if "remove_source" not in self._used:
            self._reject("both containers must be removed before the network")
        return self._perform(
            "remove_network",
            network_id,
            {"method": "DELETE", "path": f"/v1.45/networks/{network_id}"},
        )

    def prove_volumes_preserved(
        self,
        command_socket_volume: str,
        state_volume: str,
    ) -> FakeDockerEffectResult:
        if "remove_network" not in self._used:
            self._reject("volume proof must follow teardown")
        target = f"{command_socket_volume},{state_volume}"
        return self._perform(
            "prove_volumes",
            target,
            {
                "delete_call_count": 0,
                "method": "GET",
                "volume_names": [command_socket_volume, state_volume],
            },
        )


def fake_adapters_non_authority_facts() -> dict[str, bool]:
    return {
        "socket_imported": False,
        "http_client_imported": False,
        "docker_sdk_imported": False,
        "subprocess_imported": False,
        "filesystem_mutation_present": False,
        "volume_delete_method_present": False,
    }


__all__ = [
    "FakeDockerEffectResult",
    "FakeLifecycleV2ArtifactStore",
    "FakeLifecycleV2DockerEffects",
    "FakeLifecycleV2Fault",
    "FakeLifecycleV2Transport",
    "FakePublicationFault",
    "fake_adapters_non_authority_facts",
]
