"""Byte-level, effect-free Docker daemon fakes for ADR 0121 milestone one."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Never

from packages.domain.trusted_time_graceful_stop_v2_docker import (
    COMMAND_SOCKET_VOLUME,
    DOCKER_SERVICE,
    DOCKER_SOCKET_PATH,
    STATE_VOLUME,
    DockerCallSpec,
    DockerConnectionIdentity,
    DockerOrdinalEvidence,
    DockerPlanIdentity,
    DockerRequestSemantic,
    docker_call_spec,
    parse_docker_response,
    validate_docker_request_bytes,
)


class FakeDockerDaemonFault(RuntimeError):
    """The fake boundary failed or was used outside its one fixed plan."""


@dataclass(frozen=True, slots=True)
class FakeDockerFault:
    ordinal: int
    kind: str

    def __post_init__(self) -> None:
        if type(self.ordinal) is not int or not 0 <= self.ordinal <= 17:
            raise ValueError("fake Docker fault ordinal is outside 0..17")
        if self.kind not in {
            "disconnect",
            "truncated_body",
            "surplus_body",
            "chunked",
            "duplicate_header",
            "wrong_status",
            "oversized_header",
            "volume_identity_drift",
            "post_image_id_drift",
            "post_config_image_drift",
            "post_stop_signal_drift",
            "post_container_name_drift",
        }:
            raise ValueError("fake Docker fault kind is unknown")


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def _json_response(status: int, reason: str, value: object) -> bytes:
    body = _json_bytes(value)
    return (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Content-Type: application/json\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + body


def _empty_response() -> bytes:
    return b"HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"


def _info() -> dict[str, object]:
    return {
        "ID": "fake-daemon",
        "DockerRootDir": "/var/lib/docker",
        "Name": "fake-host",
        "ServerVersion": "27.5.1",
        "OperatingSystem": "Fake Linux",
        "OSType": "linux",
        "Architecture": "x86_64",
        "Driver": "overlay2",
        "SecurityOptions": ["name=seccomp,profile=builtin", "name=cgroupns"],
        "IgnoredFutureField": {"remains": "raw-body-bound"},
    }


def _container(container_id: str, *, running: bool) -> dict[str, object]:
    return {
        "Id": container_id,
        "Image": f"sha256:{'a' * 64}",
        "Name": f"/{container_id[:12]}",
        "State": {
            "Status": "running" if running else "exited",
            "Running": running,
            "Paused": False,
            "Restarting": False,
            "OOMKilled": False,
            "Dead": False,
            "Pid": 1234 if running else 0,
            "ExitCode": 0,
            "StartedAt": "2026-08-27T12:00:00.000000000Z",
            "FinishedAt": "0001-01-01T00:00:00Z" if running else "2026-08-27T12:01:00Z",
            "Ignored": "raw-body-bound",
        },
        "Config": {
            "Image": "autoquant/trusted-time@sha256:" + "b" * 64,
            "StopSignal": None,
            "User": "10001:10001",
            "Labels": {"com.docker.compose.project": "autoquanttrader-trusted-time"},
        },
        "HostConfig": {
            "NetworkMode": "autoquanttrader-trusted-time_default",
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapAdd": None,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "PidsLimit": 128,
            "NanoCpus": 500_000_000,
            "Memory": 268_435_456,
        },
        "Mounts": [
            {
                "Type": "volume",
                "Name": COMMAND_SOCKET_VOLUME,
                "Source": f"/var/lib/docker/volumes/{COMMAND_SOCKET_VOLUME}/_data",
                "Destination": "/run/chrony",
                "Driver": "local",
                "Mode": "rw",
                "RW": True,
                "Propagation": "",
            }
        ],
        "NetworkSettings": {
            "Networks": {
                "autoquanttrader-trusted-time_default": {
                    "NetworkID": "c" * 64,
                    "EndpointID": "d" * 64,
                    "Gateway": "172.28.0.1",
                    "IPAddress": "172.28.0.2",
                    "GlobalIPv6Address": "",
                    "MacAddress": "02:42:ac:1c:00:02",
                }
            }
        },
    }


def _network(network_id: str) -> dict[str, object]:
    return {
        "Id": network_id,
        "Name": "autoquanttrader-trusted-time_default",
        "Created": "2026-08-27T12:00:00.000000000Z",
        "Scope": "local",
        "Driver": "bridge",
        "EnableIPv6": False,
        "Internal": True,
        "Attachable": False,
        "Ingress": False,
        "IPAM": {
            "Driver": "default",
            "Options": None,
            "Config": [
                {
                    "Subnet": "172.28.0.0/16",
                    "IPRange": None,
                    "Gateway": "172.28.0.1",
                    "AuxiliaryAddresses": None,
                }
            ],
        },
        "Options": {"com.docker.network.bridge.enable_icc": "false"},
        "Labels": {"com.docker.compose.project": "autoquanttrader-trusted-time"},
        "Containers": {},
        "IgnoredFutureField": True,
    }


def _volume(name: str, *, drifted: bool = False) -> dict[str, object]:
    return {
        "Name": name,
        "Driver": "local",
        "Mountpoint": f"/var/lib/docker/volumes/{name}/{'changed' if drifted else '_data'}",
        "CreatedAt": "2026-08-27T12:00:00Z",
        "Status": None,
        "Labels": {"com.docker.compose.project": "autoquanttrader-trusted-time"},
        "Scope": "local",
        "Options": None,
    }


class FakeDockerDaemon:
    """One byte-exact daemon plan; any fault or replay permanently burns it."""

    __slots__ = (
        "_burned",
        "_expected_ordinal",
        "_fault",
        "_identity",
        "_network_present",
        "_present",
        "_running",
        "events",
        "request_bytes",
        "volume_delete_call_count",
    )

    def __init__(
        self,
        identity: DockerPlanIdentity,
        *,
        fault: FakeDockerFault | None = None,
    ) -> None:
        if type(identity) is not DockerPlanIdentity:
            raise ValueError("fake daemon requires one exact admitted identity")
        self._identity = identity
        self._fault = fault
        self._expected_ordinal = 0
        self._burned = False
        self._running = {
            identity.supervisor_container_id: True,
            identity.source_container_id: True,
        }
        self._present = set(self._running)
        self._network_present = True
        self.volume_delete_call_count = 0
        self.events: list[str] = []
        self.request_bytes: list[bytes] = []

    @property
    def burned(self) -> bool:
        return self._burned

    def invalidate_after_ambiguous_response(self) -> None:
        """Burn after adapter-side parsing or evidence validation fails."""

        self._burned = True

    def exchange(self, ordinal: int, encoded_request: bytes) -> bytes:
        if self._burned:
            raise FakeDockerDaemonFault("fake Docker daemon is burned")
        if type(ordinal) is not int:
            self._fail("Docker call ordinal is not an exact integer")
        if self._expected_ordinal >= 18:
            self._fail("Docker call occurs after the closed plan")
        if ordinal != self._expected_ordinal:
            self._fail("Docker call is replayed, skipped, or reordered")
        try:
            spec = docker_call_spec(ordinal, self._identity)
            validate_docker_request_bytes(encoded_request, spec=spec)
            self.events.append(f"{ordinal}:{spec.method}:{spec.request_target}")
            self.request_bytes.append(encoded_request)
            if self._fault is not None and self._fault.ordinal == ordinal:
                if self._fault.kind == "disconnect":
                    self._fail("fake Docker connection disconnected")
                response = self._response(
                    spec, volume_drift=self._fault.kind == "volume_identity_drift"
                )
                response = self._tamper(response, self._fault.kind)
            else:
                response = self._response(spec, volume_drift=False)
            self._expected_ordinal += 1
            return response
        except BaseException:
            self._burned = True
            raise

    def _response(self, spec: DockerCallSpec, *, volume_drift: bool) -> bytes:
        ordinal = spec.ordinal
        if ordinal == 0:
            return _json_response(200, "OK", _info())
        if ordinal in {1, 2, 7, 9}:
            return _json_response(
                200,
                "OK",
                _container(spec.target_identity, running=self._running[spec.target_identity]),
            )
        if ordinal == 3:
            return _json_response(200, "OK", _network(self._identity.project_network_id))
        if ordinal in {4, 5, 16, 17}:
            return _json_response(
                200,
                "OK",
                _volume(spec.target_identity, drifted=volume_drift),
            )
        if ordinal in {6, 8}:
            if spec.target_identity not in self._present:
                self._fail("fake Docker stop target is absent")
            self._running[spec.target_identity] = False
            return _empty_response()
        if ordinal in {10, 12}:
            if spec.target_identity not in self._present:
                self._fail("fake Docker remove target is absent")
            self._present.remove(spec.target_identity)
            return _empty_response()
        if ordinal in {11, 13}:
            if spec.target_identity in self._present:
                self._fail("fake removed container remains present")
            return _json_response(
                404,
                "Not Found",
                {"message": f"No such container: {spec.target_identity}"},
            )
        if ordinal == 14:
            if not self._network_present:
                self._fail("fake Docker network is already absent")
            self._network_present = False
            return _empty_response()
        if ordinal == 15:
            if self._network_present:
                self._fail("fake removed network remains present")
            return _json_response(
                404,
                "Not Found",
                {"message": f"network {spec.target_identity} not found"},
            )
        self._fail("fake Docker ordinal has no closed response")

    def _tamper(self, response: bytes, kind: str) -> bytes:
        if kind == "volume_identity_drift":
            return response
        if kind in {
            "post_image_id_drift",
            "post_config_image_drift",
            "post_stop_signal_drift",
            "post_container_name_drift",
        }:
            _headers, body = response.split(b"\r\n\r\n", 1)
            value = json.loads(body)
            if type(value) is not dict:
                self._fail("fake Docker container response is not an object")
            if kind == "post_image_id_drift":
                value["Image"] = "sha256:" + "f" * 64
            elif kind == "post_config_image_drift":
                value["Config"]["Image"] = "drifted:latest"
            elif kind == "post_stop_signal_drift":
                value["Config"]["StopSignal"] = "SIGKILL"
            else:
                value["Name"] = "/drifted-container"
            return _json_response(200, "OK", value)
        if kind == "truncated_body":
            return response[:-1]
        if kind == "surplus_body":
            return response + b"x"
        if kind == "chunked":
            return response.replace(b"Connection: close\r\n", b"Transfer-Encoding: chunked\r\n")
        if kind == "duplicate_header":
            return response.replace(
                b"Connection: close\r\n",
                b"Connection: close\r\nconnection: close\r\n",
            )
        if kind == "wrong_status":
            return response.replace(b"HTTP/1.1 200", b"HTTP/1.1 201", 1).replace(
                b"HTTP/1.1 204", b"HTTP/1.1 202", 1
            )
        if kind == "oversized_header":
            return response.replace(b"\r\n\r\n", b"\r\nX-Fill: " + b"a" * 16_384 + b"\r\n\r\n", 1)
        self._fail("fake Docker tamper kind is unknown")

    def _fail(self, message: str) -> Never:
        self._burned = True
        raise FakeDockerDaemonFault(message)


class FakeDockerHttpAdapter:
    """Test-only ordinal adapter with no generic or volume-delete method."""

    __slots__ = (
        "_burned",
        "_channel_id",
        "_daemon",
        "_daemon_projection",
        "_environment",
        "_evidence",
        "_identity",
        "_operation_id",
        "_previous_trace",
    )

    def __init__(
        self,
        daemon: FakeDockerDaemon,
        identity: DockerPlanIdentity,
        *,
        environment: str,
        graceful_stop_operation_id: str,
        channel_id: str,
    ) -> None:
        if type(daemon) is not FakeDockerDaemon or type(identity) is not DockerPlanIdentity:
            raise ValueError("fake Docker adapter inputs are not exact")
        self._daemon = daemon
        self._identity = identity
        self._environment = environment
        self._operation_id = graceful_stop_operation_id
        self._channel_id = channel_id
        self._daemon_projection: str | None = None
        self._previous_trace: str | None = None
        self._evidence: list[DockerOrdinalEvidence] = []
        self._burned = False

    @property
    def burned(self) -> bool:
        return self._burned

    @property
    def evidence(self) -> tuple[DockerOrdinalEvidence, ...]:
        return tuple(self._evidence)

    def execute_ordinal(self, ordinal: int) -> DockerOrdinalEvidence:
        if self._burned:
            raise FakeDockerDaemonFault("fake Docker adapter is burned")
        if type(ordinal) is not int:
            self._burn("fake Docker adapter ordinal is not an exact integer")
        if len(self._evidence) >= 18:
            self._burn("fake Docker adapter call occurs after the closed plan")
        if ordinal != len(self._evidence):
            self._burn("fake Docker adapter call is replayed, skipped, or reordered")
        try:
            spec = docker_call_spec(ordinal, self._identity)
            request = DockerRequestSemantic.from_spec(spec)
            encoded_response = self._daemon.exchange(ordinal, request.request_bytes(spec))
            response = parse_docker_response(
                encoded_response,
                spec=spec,
                volume_host_identity=_volume_host_identity(spec),
            )
            connection = DockerConnectionIdentity.capture(
                _fake_connection_identity(
                    spec,
                    environment=self._environment,
                    graceful_stop_operation_id=self._operation_id,
                    channel_id=self._channel_id,
                    admitted_daemon_info_projection_sha256=self._daemon_projection,
                )
            )
            evidence = DockerOrdinalEvidence.construct(
                spec=spec,
                request=request,
                connection=connection,
                response=response,
                previous_trace_entry_sha256=self._previous_trace,
            )
            if ordinal == 0:
                self._daemon_projection = response.response_projection_sha256
            self._previous_trace = evidence.trace.sha256
            self._evidence.append(evidence)
            return evidence
        except BaseException:
            self._burned = True
            self._daemon.invalidate_after_ambiguous_response()
            raise

    def run_complete_plan(self) -> tuple[DockerOrdinalEvidence, ...]:
        if self._burned:
            raise FakeDockerDaemonFault("fake Docker adapter is burned")
        if len(self._evidence) >= 18:
            self._burn("fake Docker complete plan is one shot")
        while len(self._evidence) < 18:
            self.execute_ordinal(len(self._evidence))
        return tuple(self._evidence)

    def _burn(self, message: str) -> Never:
        self._burned = True
        self._daemon.invalidate_after_ambiguous_response()
        raise FakeDockerDaemonFault(message)


def _volume_host_identity(spec: DockerCallSpec) -> tuple[int, int] | None:
    if spec.target_identity == COMMAND_SOCKET_VOLUME:
        return (500, 600)
    if spec.target_identity == STATE_VOLUME:
        return (501, 601)
    return None


def _fake_connection_identity(
    spec: DockerCallSpec,
    *,
    environment: str,
    graceful_stop_operation_id: str,
    channel_id: str,
    admitted_daemon_info_projection_sha256: str | None,
) -> dict[str, object]:
    start = 1_000_000 + spec.ordinal * 100
    return {
        "contract_version": ("phase6d-trusted-time-graceful-stop-docker-connection-identity-v2"),
        "service": DOCKER_SERVICE,
        "status": "docker_connection_bound",
        "environment": environment,
        "graceful_stop_operation_id": graceful_stop_operation_id,
        "channel_id": channel_id,
        "api_version": "v1.45",
        "connection_ordinal": spec.ordinal,
        "docker_socket_path": DOCKER_SOCKET_PATH,
        "socket_mount_id": 10,
        "socket_mount_parent_id": 1,
        "socket_mount_major_minor": "0:42",
        "socket_mount_root": "/",
        "socket_mount_point": "/var/run/docker.sock",
        "socket_mount_filesystem_type": "tmpfs",
        "socket_mount_source": "tmpfs",
        "socket_mount_options": ["rw"],
        "socket_mount_super_options": ["rw"],
        "socket_path_device": 100,
        "socket_path_inode": 200,
        "socket_path_uid": 0,
        "socket_path_gid": 0,
        "socket_path_mode": 49_584,
        "peer_uid": 0,
        "peer_gid": 0,
        "peer_pid": 999,
        "daemon_start_time_ticks": 123_456,
        "daemon_proc_device": 101,
        "daemon_proc_inode": 201,
        "daemon_pid_namespace_inode": 202,
        "daemon_executable_device": 102,
        "daemon_executable_inode": 203,
        "daemon_executable_size": 1_024,
        "daemon_executable_uid": 0,
        "daemon_executable_gid": 0,
        "daemon_executable_mode": 33_261,
        "daemon_executable_nlink": 1,
        "daemon_executable_sha256": "d" * 64,
        "daemon_cgroup_sha256": "e" * 64,
        "local_socket_device": 103,
        "local_socket_inode": 300 + spec.ordinal,
        "local_socket_cookie": 400 + spec.ordinal,
        "admitted_daemon_info_projection_sha256": (
            None if spec.ordinal == 0 else admitted_daemon_info_projection_sha256
        ),
        "path_preconnect_validated_boottime_ns": start,
        "opened_boottime_ns": start + 1,
        "pre_request_revalidated_boottime_ns": start + 2,
        "response_headers_revalidated_boottime_ns": start + 3,
        "response_complete_revalidated_boottime_ns": start + 4,
        "call_deadline_boottime_ns": start + 1_000,
    }


def fake_docker_non_authority_facts() -> dict[str, bool]:
    return {
        "real_socket_present": False,
        "generic_request_present": False,
        "volume_delete_present": False,
        "retry_present": False,
        "production_importer_present": False,
    }


__all__ = [
    "FakeDockerDaemon",
    "FakeDockerDaemonFault",
    "FakeDockerFault",
    "FakeDockerHttpAdapter",
    "fake_docker_non_authority_facts",
]
