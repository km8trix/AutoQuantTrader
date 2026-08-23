from __future__ import annotations

import hashlib
import json
import os
import pickle
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from copy import copy, deepcopy
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from typing import Any, Literal, Never, cast

import pytest

import scripts.trusted_time_post_enrollment_topology_reader as reader
from apps.trusted_time_supervisor.main import DATABASE_SECRET_CONSUMED_BYTES
from packages.adapters.trusted_time._owned_file_descriptor import (
    _acquire_trusted_time_launch_lock,
    _TrustedTimeLaunchLockLease,
    _validate_trusted_time_launch_lock,
)
from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    TrustedTimeConfirmedFirstEnrollment,
    TrustedTimeFirstEnrollmentIdentities,
    TrustedTimeImmutableLaunchEvidence,
    TrustedTimeSequenceOneEvidence,
    build_post_enrollment_start_review,
)
from packages.domain.trusted_time_post_enrollment_start import (
    TrustedTimePostEnrollmentStartApproval,
)
from scripts.bounded_subprocess import BoundedSubprocessResult
from scripts.start_trusted_time_supervisor import (
    COMPOSE_NETWORK_NAME,
    DATABASE_SECRET_CONSUMED_PATH,
    DATABASE_SECRET_CONSUMED_SHA256,
    LocalDockerDaemonIdentity,
    TrustedTimeApprovedLaunch,
)
from scripts.trusted_time_post_enrollment_staged_topology import (
    TrustedTimePostEnrollmentStagedContainerSnapshot,
    TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot,
)
from scripts.trusted_time_post_enrollment_topology import (
    TrustedTimePostEnrollmentCreatedContainerSnapshot,
    TrustedTimePostEnrollmentCreatedTopologySnapshot,
    post_enrollment_created_topology_network_name,
)

SOURCE_CONTAINER_ID = "a" * 64
SUPERVISOR_CONTAINER_ID = "b" * 64
NETWORK_ID = "c" * 64
SOURCE_ENDPOINT_ID = "d" * 64
SUPERVISOR_ENDPOINT_ID = "e" * 64
SOURCE_IMAGE_ID = "sha256:" + "1" * 64
SUPERVISOR_IMAGE_ID = "sha256:" + "2" * 64
OPERATION_ID = "223e4567-e89b-42d3-a456-426614174001"


def _json_line(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


def _identities() -> TrustedTimeFirstEnrollmentIdentities:
    return TrustedTimeFirstEnrollmentIdentities(
        anchor_authority_sha256="1" * 64,
        anchor_project_identity_sha256="2" * 64,
        bucket_identity_sha256="3" * 64,
        deployment_identity_sha256="4" * 64,
        host_identity_sha256="5" * 64,
        principal_identity_sha256="6" * 64,
        runtime_database_identity_sha256="7" * 64,
        signing_public_key_sha256="8" * 64,
        source_authority_sha256="9" * 64,
    )


def _sequence_one() -> TrustedTimeSequenceOneEvidence:
    return TrustedTimeSequenceOneEvidence(
        completion_disposition="new_intent_completed",
        uploaded_anchor_count=1,
        idempotent_duplicate_count=0,
        anchor_intent_semantic_sha256="a" * 64,
        candidate_remote_readback_sha256="b" * 64,
        current_anchor_semantic_sha256="c" * 64,
        current_anchor_sha256="b" * 64,
        current_host_head_sha256="d" * 64,
        receipt_semantic_sha256="e" * 64,
        remote_namespace_sha256="f" * 64,
    )


def _approval() -> TrustedTimePostEnrollmentStartApproval:
    enrollment = TrustedTimeConfirmedFirstEnrollment(
        operation_id="123e4567-e89b-42d3-a456-426614174000",
        approval_sha256="0" * 64,
        claim_sha256="1" * 64,
        outcome_sha256="2" * 64,
        unenrolled_admission_sha256="3" * 64,
        enrollment_launch=TrustedTimeImmutableLaunchEvidence(
            git_revision="a" * 40,
            image_admission_sha256="4" * 64,
            source_image_id="sha256:" + "5" * 64,
            supervisor_image_id="sha256:" + "6" * 64,
        ),
        identities=_identities(),
        sequence_one=_sequence_one(),
    )
    return TrustedTimePostEnrollmentStartApproval(
        operation_id=OPERATION_ID,
        review=build_post_enrollment_start_review(
            confirmed_enrollment=enrollment,
            proposed_launch=TrustedTimeImmutableLaunchEvidence(
                git_revision="f" * 40,
                image_admission_sha256="7" * 64,
                source_image_id=SOURCE_IMAGE_ID,
                supervisor_image_id=SUPERVISOR_IMAGE_ID,
            ),
        ),
    )


def _approved_launch() -> TrustedTimeApprovedLaunch:
    proposed = _approval().proposed_launch
    return TrustedTimeApprovedLaunch(
        git_revision=proposed.git_revision,
        image_admission_sha256=proposed.image_admission_sha256,
        source_image_id=proposed.source_image_id,
        supervisor_image_id=proposed.supervisor_image_id,
    )


def _created_snapshot(endpoint: str) -> TrustedTimePostEnrollmentCreatedTopologySnapshot:
    approval = _approval()
    source = TrustedTimePostEnrollmentCreatedContainerSnapshot(
        service="chrony-nts",
        container_id=SOURCE_CONTAINER_ID,
        image_id=SOURCE_IMAGE_ID,
        inspection_projection_sha256="1" * 64,
        image_configuration_projection_sha256="2" * 64,
    )
    supervisor = TrustedTimePostEnrollmentCreatedContainerSnapshot(
        service="trusted-time-supervisor",
        container_id=SUPERVISOR_CONTAINER_ID,
        image_id=SUPERVISOR_IMAGE_ID,
        inspection_projection_sha256="3" * 64,
        image_configuration_projection_sha256="4" * 64,
    )
    return TrustedTimePostEnrollmentCreatedTopologySnapshot(
        operation_id=approval.operation_id,
        approval_sha256=approval.approval_sha256,
        review_projection_sha256=approval.review.projection_sha256,
        confirmed_enrollment_evidence_sha256=approval.confirmed_enrollment.evidence_sha256,
        approved_launch=approval.proposed_launch,
        daemon_context_name="<DOCKER_HOST>",
        daemon_endpoint=endpoint,
        daemon_id="LOCAL:DAEMON:1",
        socket_volume_sha256="5" * 64,
        state_volume_sha256="6" * 64,
        source=source,
        supervisor=supervisor,
        source_start_argv=("docker", "container", "start", SOURCE_CONTAINER_ID),
        supervisor_start_argv=("docker", "container", "start", SUPERVISOR_CONTAINER_ID),
    )


def _staged_snapshot(
    endpoint: str,
    created: TrustedTimePostEnrollmentCreatedTopologySnapshot,
) -> TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot:
    approval = _approval()
    source = TrustedTimePostEnrollmentStagedContainerSnapshot(
        service="chrony-nts",
        container_id=SOURCE_CONTAINER_ID,
        image_id=SOURCE_IMAGE_ID,
        stable_inspection_projection_sha256="1" * 64,
        running_state_projection_sha256="2" * 64,
        image_configuration_projection_sha256="3" * 64,
    )
    supervisor = TrustedTimePostEnrollmentStagedContainerSnapshot(
        service="trusted-time-supervisor",
        container_id=SUPERVISOR_CONTAINER_ID,
        image_id=SUPERVISOR_IMAGE_ID,
        stable_inspection_projection_sha256="4" * 64,
        running_state_projection_sha256="5" * 64,
        image_configuration_projection_sha256="6" * 64,
    )
    return TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot(
        operation_id=approval.operation_id,
        approval_sha256=approval.approval_sha256,
        review_projection_sha256=approval.review.projection_sha256,
        confirmed_enrollment_evidence_sha256=approval.confirmed_enrollment.evidence_sha256,
        approved_launch=approval.proposed_launch,
        created_topology_snapshot_sha256=created.snapshot_sha256,
        daemon_context_name="<DOCKER_HOST>",
        daemon_endpoint=endpoint,
        daemon_id="LOCAL:DAEMON:1",
        socket_volume_sha256="5" * 64,
        state_volume_sha256="6" * 64,
        source=source,
        supervisor=supervisor,
        database_secret_consumed_candidate_sha256="7" * 64,
        release_paths_absence_candidate_sha256="8" * 64,
        staged_input_retirement_candidate_sha256="9" * 64,
    )


def _staged_paths(root: Path) -> tuple[Path, Path, Path, Path]:
    root.mkdir(mode=0o700)
    return (
        root / (".database-secret-" + "1" * 32) / "database-url",
        root / (".head-anchor-authority-" + "2" * 32) / "head-anchor-authority.json",
        root / (".head-anchor-auth-" + "3" * 32) / "head-anchor-auth",
        root / (".head-anchor-signing-key-" + "4" * 32) / "head-anchor-signing-key",
    )


@contextmanager
def _unix_socket(path: Path) -> Iterator[None]:
    assert path.is_socket()
    yield


def _short_socket_path(seed: Path) -> Path:
    del seed
    return Path("/var/run/docker.sock").resolve(strict=True)


def _make_executable(path: Path) -> None:
    path.write_bytes(b"test docker executable\n")
    path.chmod(0o700)


class _QueuedRunner:
    def __init__(self, outputs: list[bytes | BaseException]) -> None:
        self.outputs = list(outputs)
        self.calls: list[dict[str, object]] = []

    def __call__(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: float,
        maximum_stdout_bytes: int,
        maximum_stderr_bytes: int,
        stdin_bytes: bytes | None = None,
        maximum_stdin_bytes: int = 0,
    ) -> BoundedSubprocessResult:
        self.calls.append(
            {
                "argv": argv,
                "cwd": cwd,
                "environment": dict(environment),
                "timeout_seconds": timeout_seconds,
                "maximum_stdout_bytes": maximum_stdout_bytes,
                "maximum_stderr_bytes": maximum_stderr_bytes,
                "stdin_bytes": stdin_bytes,
                "maximum_stdin_bytes": maximum_stdin_bytes,
            }
        )
        if not self.outputs:
            raise AssertionError("unexpected subprocess read")
        output = self.outputs.pop(0)
        if isinstance(output, BaseException):
            raise output
        return (argv, 0, output, b"")


class _TupleSubclass(tuple[object, ...]):
    pass


class _LegacyDescriptorTrap:
    @property
    def args(self) -> Never:
        raise AssertionError("legacy result descriptor was read")

    @property
    def returncode(self) -> Never:
        raise AssertionError("legacy result descriptor was read")

    @property
    def stdout(self) -> Never:
        raise AssertionError("legacy result descriptor was read")

    @property
    def stderr(self) -> Never:
        raise AssertionError("legacy result descriptor was read")


def test_bounded_runner_result_requires_exact_immutable_tuple_authority() -> None:
    argv = ("/usr/bin/docker", "info")
    exact: object = (argv, 0, b"stdout", b"")

    assert (
        reader._require_exact_bounded_runner_result(
            exact,
            expected_argv=argv,
            maximum_stdout_bytes=6,
            maximum_stderr_bytes=0,
            require_argv_identity=True,
        )
        is exact
    )

    equal_argv = tuple(list(argv))
    assert equal_argv == argv and equal_argv is not argv
    equal_result: object = (equal_argv, 0, b"stdout", b"")
    assert (
        reader._require_exact_bounded_runner_result(
            equal_result,
            expected_argv=argv,
            maximum_stdout_bytes=6,
            maximum_stderr_bytes=0,
        )
        is equal_result
    )
    with pytest.raises(ValueError):
        reader._require_exact_bounded_runner_result(
            equal_result,
            expected_argv=argv,
            maximum_stdout_bytes=6,
            maximum_stderr_bytes=0,
            require_argv_identity=True,
        )


@pytest.mark.parametrize(
    "malformed",
    [
        _LegacyDescriptorTrap(),
        _TupleSubclass((("/usr/bin/docker", "info"), 0, b"stdout", b"")),
        (("/usr/bin/docker", "info"), 0, b"stdout"),
        (("/usr/bin/docker", "version"), 0, b"stdout", b""),
        (("/usr/bin/docker", "info"), False, b"stdout", b""),
        (("/usr/bin/docker", "info"), 0, bytearray(b"stdout"), b""),
        (("/usr/bin/docker", "info"), 0, b"stdout", ""),
        (("/usr/bin/docker", "info"), 0, b"oversize", b""),
        (("/usr/bin/docker", "info"), 0, b"stdout", b"oversize"),
    ],
)
def test_bounded_runner_result_rejects_legacy_or_inexact_authority(malformed: object) -> None:
    with pytest.raises(ValueError):
        reader._require_exact_bounded_runner_result(
            malformed,
            expected_argv=("/usr/bin/docker", "info"),
            maximum_stdout_bytes=6,
            maximum_stderr_bytes=0,
        )


def test_daemon_descriptor_is_captured_once_before_a_b_relabel() -> None:
    selected = LocalDockerDaemonIdentity(
        context_name="<DOCKER_HOST>",
        endpoint="unix:///run/docker-a.sock",
        daemon_id="LOCAL:DAEMON:A",
    )
    captured_by_validator: list[tuple[str, str, str, str]] = []

    def validate_after_relabel(candidate: object) -> tuple[str, str, str, str]:
        exact = reader._require_daemon_identity_registration(candidate)
        captured_by_validator.append(exact)
        object.__setattr__(selected, "endpoint", "unix:///run/docker-b.sock")
        object.__setattr__(selected, "daemon_id", "LOCAL:DAEMON:B")
        return exact

    registration = reader._capture_daemon_identity_registration(
        selected,
        _require_registration=validate_after_relabel,
    )

    assert registration == (
        "trusted-time-daemon-identity-registration-v1",
        "<DOCKER_HOST>",
        "unix:///run/docker-a.sock",
        "LOCAL:DAEMON:A",
    )
    assert captured_by_validator == [registration]
    assert selected.endpoint == "unix:///run/docker-b.sock"
    assert selected.daemon_id == "LOCAL:DAEMON:B"
    diagnostic = reader._daemon_identity_view(registration)
    object.__setattr__(diagnostic, "endpoint", "unix:///run/docker-c.sock")
    assert registration[2] == "unix:///run/docker-a.sock"


def test_environment_capture_is_exact_and_survives_source_mapping_mutation() -> None:
    submitted = {
        "TERM": "xterm-256color",
        "LANG": "C.UTF-8",
        "PATH": "/attacker/bin",
    }
    captured = reader._minimal_docker_environment(
        submitted,
        endpoint="unix:///run/docker.sock",
    )
    expected = (
        ("DOCKER_HOST", "unix:///run/docker.sock"),
        ("LANG", "C.UTF-8"),
        ("PATH", "/usr/bin:/bin"),
        ("TERM", "xterm-256color"),
    )
    assert captured == expected

    submitted.clear()
    submitted.update({"LANG": "attacker", "PATH": "/attacker/two"})
    assert captured == expected
    assert (
        reader._environment_identity_sha256(captured)
        == hashlib.sha256(reader._EXACT_IMMUTABLE_JSON_SERIALIZER((0, captured))).hexdigest()
    )
    with pytest.raises(ValueError):
        reader._environment_identity_sha256(tuple(reversed(captured)))


def test_trusted_docker_resolver_returns_exact_string_and_stat9_identity() -> None:
    executable, identity = reader._resolve_trusted_docker_executable()

    assert type(executable) is str
    assert executable.startswith("/")
    assert os.path.normpath(executable) == executable
    assert type(identity) is tuple and len(identity) == 9
    assert all(type(value) is int for value in identity)
    assert reader._docker_executable_identity(executable) == identity


def _network_settings(
    state: Literal["created", "staged_unreleased"],
    service: Literal["chrony-nts", "trusted-time-supervisor"],
) -> dict[str, object]:
    source = service == "chrony-nts"
    name = "aqt-source" if source else "aqt-supervisor"
    endpoint = SOURCE_ENDPOINT_ID if source else SUPERVISOR_ENDPOINT_ID
    address = "172.19.0.2" if source else "172.19.0.3"
    mac = "02:42:ac:13:00:02" if source else "02:42:ac:13:00:03"
    sandbox = "1" * 64 if source else "2" * 64
    attachment: dict[str, object] = {
        "Aliases": [name, service],
        "DNSNames": None,
        "DriverOpts": None,
        "EndpointID": "",
        "Gateway": "",
        "GlobalIPv6Address": "",
        "GlobalIPv6PrefixLen": 0,
        "GwPriority": 0,
        "IPAddress": "",
        "IPAMConfig": None,
        "IPPrefixLen": 0,
        "IPv6Gateway": "",
        "Links": None,
        "MacAddress": "",
        "NetworkID": NETWORK_ID,
    }
    sandbox_id = ""
    sandbox_key = ""
    if state == "staged_unreleased":
        attachment.update(
            {
                "DNSNames": [name, service],
                "EndpointID": endpoint,
                "Gateway": "172.19.0.1",
                "IPAddress": address,
                "IPPrefixLen": 16,
                "MacAddress": mac,
            }
        )
        sandbox_id = sandbox
        sandbox_key = "/var/run/docker/netns/" + sandbox[:12]
    return {
        "Bridge": "",
        "EndpointID": "",
        "Gateway": "",
        "GlobalIPv6Address": "",
        "GlobalIPv6PrefixLen": 0,
        "HairpinMode": False,
        "IPAddress": "",
        "IPPrefixLen": 0,
        "IPv6Gateway": "",
        "LinkLocalIPv6Address": "",
        "LinkLocalIPv6PrefixLen": 0,
        "MacAddress": "",
        "Networks": {COMPOSE_NETWORK_NAME: attachment},
        "Ports": {},
        "SandboxID": sandbox_id,
        "SandboxKey": sandbox_key,
        "SecondaryIPAddresses": None,
        "SecondaryIPv6Addresses": None,
    }


def _container(
    state: Literal["created", "staged_unreleased"],
    service: Literal["chrony-nts", "trusted-time-supervisor"],
) -> dict[str, object]:
    source = service == "chrony-nts"
    return {
        "AppArmorProfile": "docker-default",
        "Config": {
            "Labels": {
                "com.docker.compose.project": "autoquanttrader-trusted-time",
                "com.docker.compose.service": service,
            },
            "StopTimeout": 10 if source else 40,
        },
        "ExecIDs": [],
        "HostConfig": {"Runtime": "runc"},
        "Id": SOURCE_CONTAINER_ID if source else SUPERVISOR_CONTAINER_ID,
        "NetworkSettings": _network_settings(state, service),
        "Platform": "linux",
    }


def _network(state: Literal["created", "staged_unreleased"]) -> dict[str, object]:
    containers: dict[str, object] = {}
    if state == "staged_unreleased":
        containers = {
            SOURCE_CONTAINER_ID: {
                "EndpointID": SOURCE_ENDPOINT_ID,
                "IPv4Address": "172.19.0.2/16",
                "IPv6Address": "",
                "MacAddress": "02:42:ac:13:00:02",
                "Name": "aqt-source",
            },
            SUPERVISOR_CONTAINER_ID: {
                "EndpointID": SUPERVISOR_ENDPOINT_ID,
                "IPv4Address": "172.19.0.3/16",
                "IPv6Address": "",
                "MacAddress": "02:42:ac:13:00:03",
                "Name": "aqt-supervisor",
            },
        }
    return {
        "Attachable": False,
        "ConfigOnly": False,
        "ConfigFrom": {"Network": ""},
        "Containers": containers,
        "Created": "2026-08-09T12:00:00.000000000Z",
        "Driver": "bridge",
        "EnableIPv6": False,
        "IPAM": {
            "Config": [{"Gateway": "172.19.0.1", "Subnet": "172.19.0.0/16"}],
            "Driver": "default",
            "Options": None,
        },
        "Id": NETWORK_ID,
        "Ingress": False,
        "Internal": False,
        "Labels": {
            "com.docker.compose.network": "default",
            "com.docker.compose.project": "autoquanttrader-trusted-time",
        },
        "Name": COMPOSE_NETWORK_NAME,
        "Options": {},
        "Scope": "local",
    }


def _inventory_bytes() -> bytes:
    return (
        SOURCE_CONTAINER_ID.encode("ascii")
        + b" chrony-nts\n"
        + SUPERVISOR_CONTAINER_ID.encode("ascii")
        + b" trusted-time-supervisor\n"
    )


def _barrier() -> dict[str, object]:
    return {
        "contract_version": "phase6d-post-enrollment-barrier-read-probe-v1",
        "marker": {
            "byte_sha256": DATABASE_SECRET_CONSUMED_SHA256,
            "changed_time_ns": 7,
            "device": 4,
            "inode": 5,
            "link_count": 1,
            "mode": 0o400,
            "modified_time_ns": 6,
            "owner_gid": 10_001,
            "owner_uid": 10_001,
            "path": DATABASE_SECRET_CONSUMED_PATH,
            "regular": True,
            "size": len(DATABASE_SECRET_CONSUMED_BYTES),
        },
        "release_absences": [{"path": path, "status": "absent"} for path in reader._RELEASE_PATHS],
    }


def _state_outputs(state: Literal["created", "staged_unreleased"]) -> list[bytes]:
    daemon = _json_line("LOCAL:DAEMON:1")
    volumes = [_json_line({"volume": "socket"}), _json_line({"volume": "state"})]
    images = [
        _json_line({"Config": {}, "Id": SOURCE_IMAGE_ID}),
        _json_line({"Config": {}, "Id": SUPERVISOR_IMAGE_ID}),
    ]
    containers = [
        _json_line(_container(state, "chrony-nts")),
        _json_line(_container(state, "trusted-time-supervisor")),
    ]
    if state == "created":
        return [
            daemon,
            *volumes,
            _inventory_bytes(),
            _json_line(_network(state)),
            *images,
            *containers,
            _inventory_bytes(),
            _json_line(_network(state)),
            *volumes,
            daemon,
        ]
    barrier = _json_line(_barrier())
    return [
        daemon,
        *volumes,
        _inventory_bytes(),
        _json_line(_network(state)),
        barrier,
        *images,
        barrier,
        *containers,
        _inventory_bytes(),
        _json_line(_network(state)),
        *volumes,
        daemon,
    ]


def _install_pure_validator_stubs(
    monkeypatch: pytest.MonkeyPatch,
    *,
    endpoint: str,
) -> tuple[
    TrustedTimePostEnrollmentCreatedTopologySnapshot,
    TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot,
    list[dict[str, object]],
]:
    created = _created_snapshot(endpoint)
    staged = _staged_snapshot(endpoint, created)
    exact_calls: list[dict[str, object]] = []

    monkeypatch.setattr(reader, "validate_socket_volume_inspection", lambda *_args, **_kw: None)
    monkeypatch.setattr(
        reader,
        "validate_chrony_state_volume_inspection",
        lambda *_args, **_kw: None,
    )
    monkeypatch.setattr(
        reader,
        "_stable_volume_identity_sha256",
        lambda *_args, expected_name, **_kw: "5" * 64 if "socket" in expected_name else "6" * 64,
    )

    def exact_stub(*_args: object, **kwargs: object) -> None:
        exact_calls.append(dict(kwargs))

    monkeypatch.setattr(reader, "validate_exact_never_started_created_container", exact_stub)
    monkeypatch.setattr(reader, "validate_exact_staged_running_container", exact_stub)
    monkeypatch.setattr(
        reader,
        "validate_post_enrollment_start_created_topology",
        lambda **_kwargs: created,
    )
    monkeypatch.setattr(
        reader,
        "validate_post_enrollment_start_staged_unreleased_topology",
        lambda **_kwargs: staged,
    )
    return created, staged, exact_calls


def _test_only_authenticated_activation_closure() -> tuple[
    Callable[..., object],
    Callable[..., object],
    Callable[..., object],
    Callable[..., object],
    Callable[..., object],
]:
    guarded_activate = cast(
        Any,
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer.activate,
    )
    closure = guarded_activate.__closure__
    assert type(closure) is tuple
    captured = {
        name: cell.cell_contents
        for name, cell in zip(guarded_activate.__code__.co_freevars, closure, strict=True)
    }
    assert set(captured) == {
        "BaseException",
        "Exception",
        "_getpid",
        "_run_under_lock",
        "abort_activation",
        "begin_activation",
        "commit_activation",
        "getattr",
        "isinstance",
        "method",
        "process_pid",
        "register",
        "sealed_reader_error",
    }
    assert captured["BaseException"] is BaseException
    assert captured["Exception"] is Exception
    assert captured["getattr"] is getattr
    assert captured["isinstance"] is isinstance
    sealed_reader_error = captured["sealed_reader_error"]
    assert callable(sealed_reader_error)
    sealed_reader_error_code = getattr(sealed_reader_error, "__code__", None)
    assert getattr(sealed_reader_error_code, "co_name", None) == "sealed_reader_error"
    assert getattr(sealed_reader_error_code, "co_qualname", None) == (
        "_build_observation_sealer.<locals>.sealed_reader_error"
    )
    values = (
        captured["method"],
        captured["begin_activation"],
        captured["register"],
        captured["commit_activation"],
        captured["abort_activation"],
    )
    assert all(callable(value) for value in values)
    return cast(tuple[Callable[..., object], ...], values)


def _test_only_authenticated_capability_registrar() -> Callable[..., object]:
    return _test_only_authenticated_activation_closure()[2]


def _public_open(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    runner: _QueuedRunner,
    socket_path: Path,
    legacy_executable: Path | None = None,
) -> reader.TrustedTimePostEnrollmentTopologyObservationIssuer:
    del legacy_executable
    del monkeypatch
    ignored_root = tmp_path / "artifacts"
    docker_executable, docker_executable_identity = reader._resolve_trusted_docker_executable()
    daemon_identity_registration = reader._capture_daemon_identity_registration(
        LocalDockerDaemonIdentity(
            context_name="<DOCKER_HOST>",
            endpoint=f"unix://{socket_path}",
            daemon_id="LOCAL:DAEMON:1",
        )
    )
    environment_identity = reader._minimal_docker_environment(
        {"PATH": os.fspath(tmp_path / "attacker-bin"), "LANG": "C"},
        endpoint=f"unix://{socket_path}",
    )
    issuer = reader.TrustedTimePostEnrollmentTopologyObservationIssuer.allocate_inert()
    (
        _,
        begin_activation,
        registrar,
        commit_activation,
        abort_activation,
    ) = _test_only_authenticated_activation_closure()
    begin_activation(issuer, issuer._lifecycle_lock)
    try:
        result = issuer._activate_with_dependencies(
            daemon_identity_registration=daemon_identity_registration,
            environment_identity=environment_identity,
            docker_executable=docker_executable,
            docker_executable_identity=docker_executable_identity,
            ignored_root=os.fspath(ignored_root),
            artifact_directory=os.fspath(ignored_root / "trusted-time"),
            runner=runner,
            session_token_factory=lambda: b"n" * 32,
            _capability_registrar=registrar,
            _activation_committer=commit_activation,
        )
        assert result is None
    except BaseException:
        with suppress(BaseException):
            abort_activation(issuer)
        raise
    network_name = post_enrollment_created_topology_network_name(issuer._session_sha256)
    for index, output in enumerate(runner.outputs):
        if type(output) is not bytes or not output.endswith(b"\n"):
            continue
        try:
            value = json.loads(output)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if type(value) is not dict:
            continue
        labels = value.get("Labels")
        if (
            value.get("Name") == COMPOSE_NETWORK_NAME
            and type(labels) is dict
            and labels.get("com.docker.compose.network") == "default"
        ):
            value["Name"] = network_name
        network_settings = value.get("NetworkSettings")
        networks = network_settings.get("Networks") if type(network_settings) is dict else None
        if type(networks) is dict and COMPOSE_NETWORK_NAME in networks:
            networks[network_name] = networks.pop(COMPOSE_NETWORK_NAME)
        host = value.get("HostConfig")
        if type(host) is dict and host.get("NetworkMode") == COMPOSE_NETWORK_NAME:
            host["NetworkMode"] = network_name
        runner.outputs[index] = _json_line(value)
    return issuer


def _issue_arguments(paths: tuple[Path, Path, Path, Path]) -> dict[str, object]:
    return {
        "approval": _approval(),
        "approved_launch": _approved_launch(),
        "expected_database_secret_file": paths[0],
        "expected_head_anchor_authority_file": paths[1],
        "expected_head_anchor_auth_secret_file": paths[2],
        "expected_head_anchor_signing_key_secret_file": paths[3],
    }


def _open_created_test_issuer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[
    reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
    _QueuedRunner,
    tuple[Path, Path, Path, Path],
    reader.TrustedTimePostEnrollmentCreatedTopologyObservation,
]:
    socket_path = _short_socket_path(tmp_path)
    _install_pure_validator_stubs(monkeypatch, endpoint=f"unix://{socket_path}")
    paths = _staged_paths(tmp_path / "retired")
    queued = _QueuedRunner([_json_line("LOCAL:DAEMON:1"), *_state_outputs("created")])
    issuer = _public_open(monkeypatch, tmp_path, queued, socket_path)
    created = issuer.issue_created_snapshot(**_issue_arguments(paths))  # type: ignore[arg-type]
    assert queued.outputs == []
    return issuer, queued, paths, created


def test_public_open_uses_definition_captured_runner_and_entropy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_activate = _test_only_authenticated_activation_closure()[0]
    activation_defaults = cast(dict[str, object], original_activate.__kwdefaults__)
    captured_runner = activation_defaults["_runner"]
    captured_token_factory = cast(
        Callable[[], bytes],
        activation_defaults["_session_token_factory"],
    )
    token_defaults = cast(dict[str, object], captured_token_factory.__kwdefaults__)
    captured_entropy = token_defaults["_entropy"]
    decoy_calls: list[object] = []

    def decoy_runner(*args: object, **kwargs: object) -> Never:
        decoy_calls.append((args, kwargs))
        raise AssertionError("module runner relabel was selected")

    def decoy_entropy(size: int) -> bytes:
        decoy_calls.append(size)
        return b"x" * size

    monkeypatch.setattr(reader, "run_bounded_subprocess", decoy_runner)
    monkeypatch.setattr(reader.secrets, "token_bytes", decoy_entropy)

    assert activation_defaults["_runner"] is captured_runner
    assert activation_defaults["_runner"] is not decoy_runner
    assert token_defaults["_entropy"] is captured_entropy
    assert token_defaults["_entropy"] is not decoy_entropy
    token = captured_token_factory()
    assert type(token) is bytes and len(token) == 32
    assert decoy_calls == []


def test_open_captures_daemon_and_environment_before_resolver_a_b_a_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = _short_socket_path(tmp_path)
    endpoint_a = f"unix://{socket_path}"
    endpoint_b = "unix:///run/attacker-docker.sock"
    selected_daemon = LocalDockerDaemonIdentity(
        context_name="<DOCKER_HOST>",
        endpoint=endpoint_a,
        daemon_id="LOCAL:DAEMON:A",
    )
    submitted_environment = {"LANG": "C", "PATH": "/attacker/a"}
    expected_daemon_registration = reader._capture_daemon_identity_registration(selected_daemon)
    expected_environment_identity = reader._minimal_docker_environment(
        submitted_environment,
        endpoint=endpoint_a,
    )
    docker_executable, docker_executable_identity = reader._resolve_trusted_docker_executable()
    queued = _QueuedRunner([_json_line("LOCAL:DAEMON:A")])
    ignored_root = tmp_path / "artifacts"
    monkeypatch.setattr(reader, "IGNORED_ARTIFACT_ROOT", ignored_root)
    resolver_calls = 0

    def mutating_resolver() -> tuple[str, tuple[int, ...]]:
        nonlocal resolver_calls
        resolver_calls += 1
        object.__setattr__(selected_daemon, "endpoint", endpoint_b)
        object.__setattr__(selected_daemon, "daemon_id", "LOCAL:DAEMON:B")
        submitted_environment.clear()
        submitted_environment.update({"LANG": "attacker", "PATH": "/attacker/b"})
        return docker_executable, docker_executable_identity

    (
        original_activate,
        begin_activation,
        registrar,
        commit_activation,
        abort_activation,
    ) = _test_only_authenticated_activation_closure()
    issuer = reader.TrustedTimePostEnrollmentTopologyObservationIssuer.allocate_inert()
    begin_activation(issuer, issuer._lifecycle_lock)
    try:
        activation_result = original_activate(
            issuer,
            expected_daemon_identity=selected_daemon,
            docker_environment=submitted_environment,
            _capability_registrar=registrar,
            _activation_committer=commit_activation,
            _resolve_docker=mutating_resolver,
            _runner=queued,
            _session_token_factory=lambda: b"n" * 32,
            _ignored_root_value=os.fspath(ignored_root),
            _artifact_directory_value=os.fspath(ignored_root / "trusted-time"),
        )
        assert activation_result is None
    except BaseException:
        with suppress(BaseException):
            abort_activation(issuer)
        raise
    assert resolver_calls == 1
    assert selected_daemon.endpoint == endpoint_b
    assert selected_daemon.daemon_id == "LOCAL:DAEMON:B"
    assert submitted_environment == {"LANG": "attacker", "PATH": "/attacker/b"}

    capability = issuer._authentication_capability
    runtime_registration = reader._authenticated_issuer_runtime_provenance(
        issuer,
        capability,
    )
    assert runtime_registration[1] == expected_environment_identity
    assert runtime_registration[7] == expected_daemon_registration
    assert issuer._environment_identity_value == expected_environment_identity
    assert issuer._daemon_identity_registration_value == expected_daemon_registration

    object.__setattr__(selected_daemon, "endpoint", endpoint_a)
    object.__setattr__(selected_daemon, "daemon_id", "LOCAL:DAEMON:A")
    submitted_environment.clear()
    submitted_environment.update({"LANG": "C", "PATH": "/attacker/a"})
    assert (
        reader._authenticated_issuer_runtime_provenance(
            issuer,
            capability,
        )[7]
        == expected_daemon_registration
    )
    issuer.close()


def test_public_issuer_reads_exact_bounded_schedule_and_seals_two_staged_observations(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = _short_socket_path(tmp_path)
    endpoint = f"unix://{socket_path}"
    created_snapshot, staged_snapshot, exact_calls = _install_pure_validator_stubs(
        monkeypatch,
        endpoint=endpoint,
    )
    paths = _staged_paths(tmp_path / "retired")
    queued = _QueuedRunner(
        [
            _json_line("LOCAL:DAEMON:1"),
            *_state_outputs("created"),
            *_state_outputs("staged_unreleased"),
            *_state_outputs("staged_unreleased"),
        ]
    )

    with _unix_socket(socket_path):
        issuer = _public_open(monkeypatch, tmp_path, queued, socket_path)
        created = issuer.issue_created_snapshot(**_issue_arguments(paths))  # type: ignore[arg-type]
        staged_one = issuer.issue_staged_unreleased_snapshot(
            created_observation=created,
            **_issue_arguments(paths),  # type: ignore[arg-type]
        )
        staged_two = issuer.issue_staged_unreleased_snapshot(
            created_observation=created,
            **_issue_arguments(paths),  # type: ignore[arg-type]
        )

        assert created.snapshot is created_snapshot
        assert staged_one.snapshot is staged_snapshot
        assert staged_two.snapshot is staged_snapshot
        assert created.observation_count == 14
        assert staged_one.observation_count == staged_two.observation_count == 16
        assert staged_one.staged_observation_ordinal == 1
        assert staged_two.staged_observation_ordinal == 2
        assert staged_one.predecessor_observation_sha256 == created.observation_sha256
        assert staged_two.predecessor_observation_sha256 == staged_one.observation_sha256
        assert staged_one.created_observation_sha256 == created.observation_sha256
        assert staged_two.created_observation_sha256 == created.observation_sha256
        assert created.observation_provenance_authenticated is True
        assert created.lock_session_authenticated is True
        assert created.daemon_session_authenticated is True
        assert staged_two.observation_provenance_authenticated is True

        for observation in (created, staged_one, staged_two):
            payload = observation.payload()
            false_fields = set(FIRST_ENROLLMENT_AUTHORITY_FIELDS) | {
                "authority_granted",
                "claim_retention_authorized",
                "database_secret_disclosed",
                "persistent_start_authorized",
                "release_authorized",
                "sequence_2_authorized",
                "shutdown_authorized",
                "source_start_authorized",
                "start_order_authenticated",
                "supervisor_start_authorized",
                "topology_authenticated",
                "topology_mutation_authorized",
            }
            assert all(payload[field] is False for field in false_fields)
            encoded = json.dumps(payload, sort_keys=True)
            assert os.fspath(paths[0]) not in encoded
            assert DATABASE_SECRET_CONSUMED_PATH not in encoded
            assert "container_inspections" not in encoded
            assert "NetworkSettings" not in encoded

        assert len(queued.calls) == 47
        assert queued.outputs == []
        expected_executable = issuer._docker_executable_path_value
        assert all(call["argv"][0] == expected_executable for call in queued.calls)  # type: ignore[index]
        assert all(call["cwd"] == Path("/") for call in queued.calls)
        assert all(call["timeout_seconds"] == 2.0 for call in queued.calls)
        assert all(call["maximum_stderr_bytes"] == 4 * 1_024 for call in queued.calls)
        assert all(call["stdin_bytes"] is None for call in queued.calls)
        assert all(call["maximum_stdin_bytes"] == 0 for call in queued.calls)
        for call in queued.calls:
            environment = cast(dict[str, str], call["environment"])
            assert environment == {
                "DOCKER_HOST": endpoint,
                "LANG": "C",
                "PATH": "/usr/bin:/bin",
            }
        assert len(exact_calls) == 6
        assert all(call["require_live_observation_fields"] is True for call in exact_calls)

        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            replace(created, transcript_sha256="f" * 64)
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            replace(staged_one, staged_observation_ordinal=2)
        with pytest.raises(FrozenInstanceError):
            created.session_sha256 = "0" * 64  # type: ignore[misc]
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer.issue_staged_unreleased_snapshot(
                created_observation=created,
                **_issue_arguments(paths),  # type: ignore[arg-type]
            )
            issuer.close()
            with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
                issuer.close()


def test_claim_admitted_final_action_observation_reuses_full_staged_read_recipe(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = _short_socket_path(tmp_path)
    endpoint = f"unix://{socket_path}"
    created_snapshot, staged_snapshot, exact_calls = _install_pure_validator_stubs(
        monkeypatch,
        endpoint=endpoint,
    )
    paths = _staged_paths(tmp_path / "retired")
    queued = _QueuedRunner(
        [
            _json_line("LOCAL:DAEMON:1"),
            *_state_outputs("created"),
            *_state_outputs("staged_unreleased"),
            _json_line("LOCAL:DAEMON:1"),
            _json_line("LOCAL:DAEMON:1"),
            *_state_outputs("staged_unreleased"),
            _json_line("LOCAL:DAEMON:1"),
            *_state_outputs("staged_unreleased"),
        ]
    )
    authorization = object()
    claimed_fence_sha256 = "c" * 64
    authorization_calls: list[tuple[object, dict[str, object]]] = []

    import scripts.trusted_time_post_enrollment_claimed_fence as claimed_module

    class ExactClaimedFence:
        def __init__(
            self,
            *,
            created_observation: object,
            pre_release_observation: object,
            final_cursor: object,
            approval: object,
        ) -> None:
            self._created_observation = created_observation
            self._pre_release_staged_observation = pre_release_observation
            self._final_cursor = final_cursor
            self._approval = approval

        def __post_init__(self) -> None:
            return None

        @property
        def fence_sha256(self) -> str:
            return claimed_fence_sha256

    monkeypatch.setattr(
        claimed_module,
        "TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence",
        ExactClaimedFence,
    )

    def consume(candidate: object, **kwargs: object) -> bool:
        authorization_calls.append((candidate, dict(kwargs)))
        return candidate is authorization

    monkeypatch.setattr(
        reader,
        "_consume_claimed_action_topology_observation_authorization",
        consume,
    )

    issuer = _public_open(monkeypatch, tmp_path, queued, socket_path)

    def observe(
        lease: object,
    ) -> tuple[
        reader.TrustedTimePostEnrollmentStagedTopologyObservation,
        reader.TrustedTimePostEnrollmentFinalActionTopologyObservation,
        object,
    ]:
        created = issuer.issue_created_snapshot(
            **_issue_arguments(paths),  # type: ignore[arg-type]
            _choreography_lease=lease,
        )
        issuer.issue_staged_unreleased_snapshot(
            created_observation=created,
            **_issue_arguments(paths),  # type: ignore[arg-type]
            _choreography_lease=lease,
        )
        issuer.issue_observation_cursor(_choreography_lease=lease)
        issuer.issue_observation_cursor(_choreography_lease=lease)
        staged_two = issuer.issue_staged_unreleased_snapshot(
            created_observation=created,
            **_issue_arguments(paths),  # type: ignore[arg-type]
            _choreography_lease=lease,
        )
        final_cursor = issuer.issue_observation_cursor(_choreography_lease=lease)
        action_arguments = _issue_arguments(paths)
        approval = cast(
            TrustedTimePostEnrollmentStartApproval,
            action_arguments["approval"],
        )
        claimed_fence = ExactClaimedFence(
            created_observation=created,
            pre_release_observation=staged_two,
            final_cursor=final_cursor,
            approval=approval,
        )
        final = issuer._issue_claimed_final_action_topology_snapshot(
            claimed_action_authorization=authorization,
            claimed_fence=claimed_fence,
            claimed_fence_sha256=claimed_fence_sha256,
            created_observation=created,
            approval=approval,
            approved_launch=cast(TrustedTimeApprovedLaunch, action_arguments["approved_launch"]),
            expected_database_secret_file=paths[0],
            expected_head_anchor_authority_file=paths[1],
            expected_head_anchor_auth_secret_file=paths[2],
            expected_head_anchor_signing_key_secret_file=paths[3],
            _choreography_lease=lease,
        )
        return staged_two, final, claimed_fence

    staged_two, final, claimed_fence = issuer._run_exclusive_choreography(observe)

    assert final.snapshot is staged_snapshot
    assert final.snapshot is staged_two.snapshot
    assert final.observation_count == 16
    assert final.claimed_fence_sha256 == claimed_fence_sha256
    assert final.session_sha256 == staged_two.session_sha256
    assert final.created_observation_sha256 == staged_two.created_observation_sha256
    assert final.predecessor_observation_sha256 == staged_two.observation_sha256
    assert final.transcript_sha256 != staged_two.transcript_sha256
    assert final.status == reader.POST_ENROLLMENT_FINAL_ACTION_TOPOLOGY_OBSERVATION_STATUS
    assert final.claimed_fence_authorization_authenticated is True
    assert final.final_action_topology_reobservation_authenticated is True
    assert final.same_session_observation_chain_authenticated is True
    assert final.stable_topology_match_authenticated is True
    assert final.freshness_authenticated is False
    assert final.current_daemon_session_authenticated is False
    assert final.current_lock_session_authenticated is False
    payload = final.payload()
    assert payload["contract_version"] == (
        reader.POST_ENROLLMENT_FINAL_ACTION_TOPOLOGY_OBSERVATION_CONTRACT_VERSION
    )
    assert payload["kind"] == "final_action_staged_unreleased"
    assert payload["release_authorized"] is False
    assert payload["sequence_2_authorized"] is False
    assert payload["topology_mutation_authorized"] is False
    assert payload["persistent_start_authorized"] is False
    assert issuer._staged_observation_count == 2
    assert issuer._cursor_count == 3
    assert issuer._last_observation_sha256 == staged_two.observation_sha256
    assert issuer._final_action_observation_sha256 == final.observation_sha256
    assert len(authorization_calls) == 1
    candidate, authorization_arguments = authorization_calls[0]
    assert candidate is authorization
    assert authorization_arguments["topology_issuer"] is issuer
    assert authorization_arguments["claimed_fence"] is claimed_fence
    assert authorization_arguments["claimed_fence_sha256"] == claimed_fence_sha256
    assert authorization_arguments["staged_paths"] == paths
    assert len(queued.calls) == 66
    assert queued.outputs == []
    assert len(exact_calls) == 8
    assert created_snapshot.snapshot_sha256 == final.snapshot.created_topology_snapshot_sha256

    for operation in (
        lambda: copy(final),
        lambda: deepcopy(final),
        lambda: pickle.dumps(final),
    ):
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            operation()
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        replace(final, claimed_fence_sha256="d" * 64)
    issuer.close()


def test_real_claimed_action_module_consumes_reader_authorization_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import scripts.trusted_time_post_enrollment_action_topology_fence as action_fence
    import scripts.trusted_time_post_enrollment_claimed_fence as claimed_fence
    from scripts.trusted_time_post_enrollment_topology_fence import (
        bind_post_enrollment_start_pre_claim_topology_fence,
    )
    from tests.unit import test_trusted_time_post_enrollment_claimed_fence as claimed_fixtures
    from tests.unit import (
        test_trusted_time_post_enrollment_topology_choreography_lease as lease_fixtures,
    )

    with monkeypatch.context() as context_patch:
        context_patch.setattr(
            reader,
            "_valid_observation_seal",
            lambda candidate, payload: (
                type(candidate) is bytes
                and candidate
                == claimed_fixtures._authenticated_seal(cast(dict[str, object], payload))
            ),
        )
        context_patch.setattr(
            reader,
            "_valid_cursor_seal",
            lambda candidate, payload, _result: (
                type(candidate) is bytes
                and candidate
                == claimed_fixtures._authenticated_seal(cast(dict[str, object], payload))
            ),
        )
        context = claimed_fixtures._context(tmp_path)

    socket_path = _short_socket_path(tmp_path)
    endpoint = f"unix://{socket_path}"
    _install_pure_validator_stubs(monkeypatch, endpoint=endpoint)
    created_validation_snapshot = replace(
        context.created.snapshot,
        daemon_endpoint=endpoint,
    )
    staged_validation_snapshot = replace(
        context.staged_two.snapshot,
        created_topology_snapshot_sha256=created_validation_snapshot.snapshot_sha256,
        daemon_endpoint=endpoint,
    )
    monkeypatch.setattr(
        reader,
        "validate_post_enrollment_start_created_topology",
        lambda **_kwargs: created_validation_snapshot,
    )
    monkeypatch.setattr(
        reader,
        "validate_post_enrollment_start_staged_unreleased_topology",
        lambda **_kwargs: staged_validation_snapshot,
    )
    paths = claimed_fixtures._staged_paths(context.artifact_directory)
    queued = _QueuedRunner(
        [
            _json_line("LOCAL:DAEMON:1"),
            *_state_outputs("created"),
            *_state_outputs("staged_unreleased"),
            _json_line("LOCAL:DAEMON:1"),
            _json_line("LOCAL:DAEMON:1"),
            *_state_outputs("staged_unreleased"),
            _json_line("LOCAL:DAEMON:1"),
            *_state_outputs("staged_unreleased"),
        ]
    )
    issuer = _public_open(monkeypatch, tmp_path, queued, socket_path)

    def prepare_action(
        lease: object,
        capability: object,
    ) -> action_fence.TrustedTimePostEnrollmentStartClaimedActionTopologyFence:
        created = issuer.issue_created_snapshot(
            **_issue_arguments(paths),  # type: ignore[arg-type]
            _choreography_lease=lease,
        )
        staged_one = issuer.issue_staged_unreleased_snapshot(
            created_observation=created,
            **_issue_arguments(paths),  # type: ignore[arg-type]
            _choreography_lease=lease,
        )
        cursor_one = issuer.issue_observation_cursor(_choreography_lease=lease)
        cursor_two = issuer.issue_observation_cursor(_choreography_lease=lease)
        staged_two = issuer.issue_staged_unreleased_snapshot(
            created_observation=created,
            **_issue_arguments(paths),  # type: ignore[arg-type]
            _choreography_lease=lease,
        )
        cursor_three = issuer.issue_observation_cursor(_choreography_lease=lease)
        context.created = created
        context.staged_one = staged_one
        context.staged_two = staged_two
        context.pre_claim = bind_post_enrollment_start_pre_claim_topology_fence(
            created,
            staged_one,
        )
        context.cursors = [cursor_one, cursor_two, cursor_three]
        context.topology_issuer = issuer
        with monkeypatch.context() as claimed_patch:
            claimed_fixtures._install_success(
                claimed_patch,
                context,
                expected_choreography_lease=lease,
                expected_recovery_retention_capability=capability,
            )
            claimed = claimed_fence.prepare_post_enrollment_start_leased_claimed_pre_release_fence(
                **context.kwargs(),  # type: ignore[arg-type]
                choreography_lease=lease,
                recovery_retention_capability=capability,
            )
        retained = cast(
            Any,
            context.bound_recovery_claims[-1],
        )
        lease_fixtures._bind_registered_recovery_claim(
            issuer,
            lease,
            capability,
            retained,
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )
        return action_fence.prepare_post_enrollment_start_leased_claimed_action_topology_fence(
            claimed_fence=claimed,
            topology_issuer=issuer,
            choreography_lease=lease,
            recovery_retention_capability=capability,
            approved_launch=context.approved_launch,
            expected_database_secret_file=paths[0],
            expected_head_anchor_authority_file=paths[1],
            expected_head_anchor_auth_secret_file=paths[2],
            expected_head_anchor_signing_key_secret_file=paths[3],
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )

    action = issuer._run_exclusive_choreography_with_recovery_retention(prepare_action)

    assert action.final_action_topology_reobservation_authenticated is True
    assert action.claim_chronology_authenticated is True
    assert action.claim_retention_authenticated is True
    assert action.final_action_snapshot_sha256 == context.staged_two.snapshot.snapshot_sha256
    assert action.predecessor_observation_sha256 == context.staged_two.observation_sha256
    assert issuer._final_action_observation_sha256 == action.final_action_observation_sha256
    assert issuer._staged_observation_count == 2
    assert issuer._cursor_count == 3
    assert len(queued.calls) == 66
    assert queued.outputs == []
    lease_fixtures._close_and_assert_launch_lock_is_reacquirable(issuer)


def test_final_action_observation_rejects_unconsumed_authorization_before_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = _short_socket_path(tmp_path)
    queued = _QueuedRunner([_json_line("LOCAL:DAEMON:1")])
    issuer = _public_open(monkeypatch, tmp_path, queued, socket_path)
    paths = _staged_paths(tmp_path / "retired")
    monkeypatch.setattr(
        reader,
        "_consume_claimed_action_topology_observation_authorization",
        lambda *_args, **_kwargs: False,
    )

    with pytest.raises(
        reader.TrustedTimePostEnrollmentTopologyReaderError,
        match="authorization is unavailable",
    ):
        issuer._issue_claimed_final_action_topology_snapshot(
            claimed_action_authorization=object(),
            claimed_fence=object(),
            claimed_fence_sha256="c" * 64,
            created_observation=cast(
                reader.TrustedTimePostEnrollmentCreatedTopologyObservation,
                object(),
            ),
            **_issue_arguments(paths),  # type: ignore[arg-type]
            _choreography_lease=object(),
        )

    assert len(queued.calls) == 1
    assert issuer._final_action_observation_sha256 is None
    assert "poisoned" in repr(issuer)
    issuer.close()


def test_armed_recovery_guard_accepts_only_the_live_registered_tuple(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from tests.unit import (
        test_trusted_time_post_enrollment_topology_choreography_lease as lease_fixtures,
    )

    issuer, queued = lease_fixtures._open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = lease_fixtures._retain_claim_for_issuer(issuer)
    observed: list[reader._ChoreographyCheckpoint] = []

    def require_armed(lease: object, capability: object) -> None:
        lease_fixtures._bind_registered_recovery_claim(
            issuer,
            lease,
            capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        observed.append(
            issuer._require_armed_recovery_outcome_retention(
                lease,
                capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        )

    issuer._run_exclusive_choreography_with_recovery_retention(require_armed)

    assert len(observed) == 1
    assert observed[0].started_monotonic_ns < observed[0].observed_monotonic_ns
    assert observed[0].observed_monotonic_ns < observed[0].deadline_monotonic_ns
    assert issuer._poisoned is False
    assert issuer._busy is False
    assert len(queued.calls) == 1
    assert queued.outputs == []
    lease_fixtures._close_and_assert_launch_lock_is_reacquirable(issuer)


def test_armed_recovery_guard_rejects_unbound_capability(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from tests.unit import (
        test_trusted_time_post_enrollment_topology_choreography_lease as lease_fixtures,
    )

    issuer, queued = lease_fixtures._open_issuer(monkeypatch, tmp_path)
    artifact_directory = issuer._ignored_root / "trusted-time"
    ignored_root = issuer._ignored_root

    def reject_unbound(lease: object, capability: object) -> None:
        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="armed recovery retention is unavailable",
        ):
            issuer._require_armed_recovery_outcome_retention(
                lease,
                capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        assert issuer._poisoned is True

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_unbound)

    assert issuer._busy is False
    assert issuer._poisoned is True
    assert len(queued.calls) == 1
    assert queued.outputs == []
    lease_fixtures._close_and_assert_launch_lock_is_reacquirable(issuer)


@pytest.mark.parametrize("mismatch", ["capability", "lease", "lock", "roots"])
def test_armed_recovery_guard_failure_preserves_exact_recovery_escape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mismatch: str,
) -> None:
    from tests.unit import (
        test_trusted_time_post_enrollment_topology_choreography_lease as lease_fixtures,
    )

    class RecoveryTerminal(BaseException):
        pass

    issuer, queued = lease_fixtures._open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = lease_fixtures._retain_claim_for_issuer(issuer)
    recovery_checkpoints: list[reader._TrustedTimePostEnrollmentRecoveryRetentionCheckpoint] = []

    def reject_wrong_capability(lease: object, capability: object) -> None:
        lease_fixtures._bind_registered_recovery_claim(
            issuer,
            lease,
            capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

        def require_mismatched_tuple() -> None:
            candidate_lease = object() if mismatch == "lease" else lease
            candidate_capability = object() if mismatch == "capability" else capability
            candidate_ignored_root = (
                ignored_root.parent / "wrong-artifacts" if mismatch == "roots" else ignored_root
            )
            issuer._require_armed_recovery_outcome_retention(
                candidate_lease,
                candidate_capability,
                artifact_directory=(candidate_ignored_root / "trusted-time"),
                ignored_root=candidate_ignored_root,
            )

        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="armed recovery retention is unavailable",
        ):
            if mismatch == "lock":

                def reject_lock(_candidate: object) -> None:
                    raise OSError("lock replaced")

                with monkeypatch.context() as scoped:
                    scoped.setattr(
                        type(issuer),
                        "_validate_lock",
                        reject_lock,
                    )
                    require_mismatched_tuple()
            else:
                require_mismatched_tuple()
        assert issuer._poisoned is True
        assert issuer._busy is False
        recovery_checkpoint = issuer._begin_recovery_outcome_retention(
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        recovery_checkpoints.append(recovery_checkpoint)
        issuer._abandon_recovery_outcome_retention(capability, recovery_checkpoint)
        raise RecoveryTerminal

    with pytest.raises(RecoveryTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_wrong_capability)

    assert len(recovery_checkpoints) == 1
    assert recovery_checkpoints[0].retained_claim is retained
    assert issuer._poisoned is True
    assert issuer._busy is False
    assert len(queued.calls) == 1
    assert queued.outputs == []
    lease_fixtures._close_and_assert_launch_lock_is_reacquirable(issuer)


def test_armed_recovery_guard_rejects_action_deadline_equality(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from tests.unit import (
        test_trusted_time_post_enrollment_topology_choreography_lease as lease_fixtures,
    )

    class RecoveryTerminal(BaseException):
        pass

    started = 7_000_000_000
    action_deadline = started + reader._POST_ENROLLMENT_START_CHOREOGRAPHY_DEADLINE_NANOSECONDS
    clock_values = [
        started,
        started + 1,
        started + 2,
        started + 3,
        started + 4,
        action_deadline,
        action_deadline + 1,
    ]
    clock = lease_fixtures._MonotonicClock(clock_values)
    issuer, queued = lease_fixtures._open_issuer(
        monkeypatch,
        tmp_path,
        monotonic_clock=clock,
    )
    retained, artifact_directory, ignored_root = lease_fixtures._retain_claim_for_issuer(issuer)

    def reject_expired_action(lease: object, capability: object) -> None:
        lease_fixtures._bind_registered_recovery_claim(
            issuer,
            lease,
            capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="armed recovery retention is unavailable",
        ):
            issuer._require_armed_recovery_outcome_retention(
                lease,
                capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        assert issuer._poisoned is True
        recovery_checkpoint = issuer._begin_recovery_outcome_retention(
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        issuer._abandon_recovery_outcome_retention(capability, recovery_checkpoint)
        raise RecoveryTerminal

    with pytest.raises(RecoveryTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_expired_action)

    assert clock.calls == clock_values
    assert issuer._busy is False
    assert issuer._poisoned is True
    assert len(queued.calls) == 1
    assert queued.outputs == []
    lease_fixtures._close_and_assert_launch_lock_is_reacquirable(issuer)


def test_final_action_cleanup_interruption_clears_busy_and_preserves_recovery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from tests.unit import (
        test_trusted_time_post_enrollment_topology_choreography_lease as lease_fixtures,
    )

    class CleanupInterruption(BaseException):
        pass

    class RecoveryTerminal(BaseException):
        pass

    socket_path = _short_socket_path(tmp_path)
    endpoint = f"unix://{socket_path}"
    _install_pure_validator_stubs(monkeypatch, endpoint=endpoint)
    paths = _staged_paths(tmp_path / "retired")
    queued = _QueuedRunner(
        [
            _json_line("LOCAL:DAEMON:1"),
            *_state_outputs("created"),
            *_state_outputs("staged_unreleased"),
            _json_line("LOCAL:DAEMON:1"),
            _json_line("LOCAL:DAEMON:1"),
            *_state_outputs("staged_unreleased"),
            _json_line("LOCAL:DAEMON:1"),
            *_state_outputs("staged_unreleased"),
        ]
    )
    authorization = object()
    claimed_fence_sha256 = "c" * 64

    import scripts.trusted_time_post_enrollment_claimed_fence as claimed_module

    class ExactClaimedFence:
        def __init__(
            self,
            *,
            created_observation: object,
            pre_release_observation: object,
            final_cursor: object,
            approval: object,
        ) -> None:
            self._created_observation = created_observation
            self._pre_release_staged_observation = pre_release_observation
            self._final_cursor = final_cursor
            self._approval = approval

        def __post_init__(self) -> None:
            return None

        @property
        def fence_sha256(self) -> str:
            return claimed_fence_sha256

    monkeypatch.setattr(
        claimed_module,
        "TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence",
        ExactClaimedFence,
    )
    monkeypatch.setattr(
        reader,
        "_consume_claimed_action_topology_observation_authorization",
        lambda candidate, **_kwargs: candidate is authorization,
    )

    issuer = _public_open(monkeypatch, tmp_path, queued, socket_path)
    retained, artifact_directory, ignored_root = lease_fixtures._retain_claim_for_issuer(issuer)
    original_finish = reader.TrustedTimePostEnrollmentTopologyObservationIssuer._finish_observation
    finish_interrupted = False
    recovery_checkpoints: list[reader._TrustedTimePostEnrollmentRecoveryRetentionCheckpoint] = []

    def observe_then_recover(lease: object, capability: object) -> None:
        nonlocal finish_interrupted
        created = issuer.issue_created_snapshot(
            **_issue_arguments(paths),  # type: ignore[arg-type]
            _choreography_lease=lease,
        )
        issuer.issue_staged_unreleased_snapshot(
            created_observation=created,
            **_issue_arguments(paths),  # type: ignore[arg-type]
            _choreography_lease=lease,
        )
        issuer.issue_observation_cursor(_choreography_lease=lease)
        issuer.issue_observation_cursor(_choreography_lease=lease)
        staged_two = issuer.issue_staged_unreleased_snapshot(
            created_observation=created,
            **_issue_arguments(paths),  # type: ignore[arg-type]
            _choreography_lease=lease,
        )
        final_cursor = issuer.issue_observation_cursor(_choreography_lease=lease)
        action_arguments = _issue_arguments(paths)
        approval = cast(
            TrustedTimePostEnrollmentStartApproval,
            action_arguments["approval"],
        )
        claimed_fence = ExactClaimedFence(
            created_observation=created,
            pre_release_observation=staged_two,
            final_cursor=final_cursor,
            approval=approval,
        )
        lease_fixtures._bind_registered_recovery_claim(
            issuer,
            lease,
            capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

        def interrupt_finish_once(
            candidate: reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        ) -> None:
            nonlocal finish_interrupted
            if candidate is issuer and not finish_interrupted:
                finish_interrupted = True
                raise CleanupInterruption
            original_finish(candidate)

        monkeypatch.setattr(
            reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
            "_finish_observation",
            interrupt_finish_once,
        )
        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="cleanup is unavailable",
        ):
            issuer._issue_claimed_final_action_topology_snapshot(
                claimed_action_authorization=authorization,
                claimed_fence=claimed_fence,
                claimed_fence_sha256=claimed_fence_sha256,
                created_observation=created,
                approval=approval,
                approved_launch=cast(
                    TrustedTimeApprovedLaunch,
                    action_arguments["approved_launch"],
                ),
                expected_database_secret_file=paths[0],
                expected_head_anchor_authority_file=paths[1],
                expected_head_anchor_auth_secret_file=paths[2],
                expected_head_anchor_signing_key_secret_file=paths[3],
                _choreography_lease=lease,
            )
        assert issuer._busy is False
        assert issuer._poisoned is True
        assert issuer._final_action_observation_sha256 is not None
        lease_fixtures._assert_launch_lock_is_held(issuer)
        recovery_checkpoint = issuer._begin_recovery_outcome_retention(
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        recovery_checkpoints.append(recovery_checkpoint)
        issuer._abandon_recovery_outcome_retention(capability, recovery_checkpoint)
        raise RecoveryTerminal

    with pytest.raises(RecoveryTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(observe_then_recover)

    assert finish_interrupted is True
    assert len(recovery_checkpoints) == 1
    assert recovery_checkpoints[0].retained_claim is retained
    assert issuer._busy is False
    assert issuer._poisoned is True
    assert len(queued.calls) == 66
    assert queued.outputs == []
    lease_fixtures._close_and_assert_launch_lock_is_reacquirable(issuer)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"key":1,"key":2}\n',
        b'{"outer":{"key":1,"key":2}}\n',
        b'{"a":1,"\\u0061":2}\n',
        b'{"key":1} {"other":2}\n',
        b' {"key":1}\n',
        b'{"key":1} \n',
        b'{"key": 1}\n',
        b'{"key":1}\r\n',
        b'{"key":1}\n\n',
        b'\xef\xbb\xbf{"key":1}\n',
        b'{"key":"bad\x00value"}\n',
        b'{"key":"\xff"}\n',
        b'{"key":"\\ud800"}\n',
        b'{"key":NaN}\n',
        b'{"key":Infinity}\n',
        b'{"key":1.0}\n',
        b'{"key":1e400}\n',
        ('{"key":' + str(1 << 300) + "}\n").encode(),
        ("[" * 66 + "0" + "]" * 66 + "\n").encode(),
    ],
)
def test_strict_json_decoder_rejects_ambiguous_or_unbounded_bytes(raw: bytes) -> None:
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        reader._decode_strict_json(
            raw,
            expected_type=dict,
            maximum_bytes=max(1_024, len(raw)),
        )


def test_strict_json_decoder_accepts_only_exact_root_and_bounded_nodes() -> None:
    assert reader._decode_strict_json(
        b'{"key":[true,false,null,"value",7]}\n',
        expected_type=dict,
        maximum_bytes=1_024,
    ) == {"key": [True, False, None, "value", 7]}
    assert (
        reader._decode_strict_json(
            b'"inventory-id"',
            expected_type=str,
            maximum_bytes=128,
        )
        == "inventory-id"
    )
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        reader._decode_strict_json(
            b"[]\n",
            expected_type=dict,
            maximum_bytes=128,
        )
    oversized_tree = ("[" + ",".join("0" for _ in range(131_073)) + "]\n").encode()
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        reader._decode_strict_json(
            oversized_tree,
            expected_type=list,
            maximum_bytes=len(oversized_tree),
        )


@pytest.mark.parametrize(
    ("state", "mutation"),
    [
        ("created", lambda value: value.pop("ExecIDs")),
        ("created", lambda value: value.__setitem__("ExecIDs", ["exec"])),
        ("created", lambda value: value.__setitem__("AppArmorProfile", "")),
        ("created", lambda value: value.__setitem__("Platform", "darwin")),
        ("created", lambda value: value["HostConfig"].__setitem__("Runtime", "kata")),
        (
            "created",
            lambda value: value["NetworkSettings"].__setitem__("SandboxID", "1" * 64),
        ),
        (
            "created",
            lambda value: value["NetworkSettings"]["Networks"][COMPOSE_NETWORK_NAME].pop(
                "EndpointID"
            ),
        ),
        (
            "created",
            lambda value: value["NetworkSettings"]["Networks"][COMPOSE_NETWORK_NAME].__setitem__(
                "EndpointID", SOURCE_ENDPOINT_ID
            ),
        ),
        (
            "staged_unreleased",
            lambda value: value["NetworkSettings"]["Networks"][COMPOSE_NETWORK_NAME].__setitem__(
                "IPAddress", ""
            ),
        ),
        (
            "staged_unreleased",
            lambda value: value["NetworkSettings"]["Networks"][COMPOSE_NETWORK_NAME].__setitem__(
                "MacAddress", ""
            ),
        ),
        (
            "staged_unreleased",
            lambda value: value["NetworkSettings"].pop("SandboxKey"),
        ),
    ],
)
def test_container_raw_boundary_rejects_live_field_drift(
    state: Literal["created", "staged_unreleased"],
    mutation: Callable[[dict[str, Any]], object],
) -> None:
    value = _container(state, "chrony-nts")
    mutation(cast(dict[str, Any], value))
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        reader._validate_container_reader_boundary(
            value,
            expected_container_id=SOURCE_CONTAINER_ID,
            expected_service="chrony-nts",
            expected_state=state,
            expected_network_name=COMPOSE_NETWORK_NAME,
        )


def test_container_raw_boundary_accepts_exact_created_and_staged_shapes() -> None:
    created = _container("created", "chrony-nts")
    created["ExecIDs"] = None
    created_attachment = reader._validate_container_reader_boundary(
        created,
        expected_container_id=SOURCE_CONTAINER_ID,
        expected_service="chrony-nts",
        expected_state="created",
        expected_network_name=COMPOSE_NETWORK_NAME,
    )
    staged_attachment = reader._validate_container_reader_boundary(
        _container("staged_unreleased", "trusted-time-supervisor"),
        expected_container_id=SUPERVISOR_CONTAINER_ID,
        expected_service="trusted-time-supervisor",
        expected_state="staged_unreleased",
        expected_network_name=COMPOSE_NETWORK_NAME,
    )
    assert created_attachment.network_id == staged_attachment.network_id == NETWORK_ID
    assert created_attachment.endpoint_id == ""
    assert staged_attachment.endpoint_id == SUPERVISOR_ENDPOINT_ID


def test_ipv4_input_is_capped_before_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    def unexpected_parser(_: object) -> object:
        nonlocal called
        called = True
        raise AssertionError

    monkeypatch.setattr(reader.ipaddress, "ip_address", unexpected_parser)
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        reader._ipv4_address("1" * 10_000)
    assert called is False


@pytest.mark.parametrize(
    ("state", "mutate"),
    [
        ("created", lambda value: value["Containers"].update({SOURCE_CONTAINER_ID: {}})),
        ("created", lambda value: value.__setitem__("EnableIPv6", True)),
        ("created", lambda value: value.__setitem__("Driver", "overlay")),
        ("created", lambda value: value.__setitem__("unexpected", False)),
        (
            "staged_unreleased",
            lambda value: value["Containers"][SOURCE_CONTAINER_ID].__setitem__(
                "IPv4Address", "172.19.0.2/999"
            ),
        ),
        (
            "staged_unreleased",
            lambda value: value["Containers"][SOURCE_CONTAINER_ID].__setitem__(
                "EndpointID", "short"
            ),
        ),
        (
            "staged_unreleased",
            lambda value: value["Containers"].pop(SOURCE_CONTAINER_ID),
        ),
    ],
)
def test_separate_network_inspection_rejects_boundary_drift(
    state: Literal["created", "staged_unreleased"],
    mutate: Callable[[dict[str, Any]], object],
) -> None:
    value = _network(state)
    mutate(cast(dict[str, Any], value))
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        reader._network_identity(
            value,
            expected_inventory=frozenset({SOURCE_CONTAINER_ID, SUPERVISOR_CONTAINER_ID}),
            expected_state=state,
            expected_network_name=COMPOSE_NETWORK_NAME,
            expected_create_invocation_sha256=None,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["release_absences"].append({"path": "/junk", "status": "absent"}),
        lambda value: value["release_absences"].append("junk"),
        lambda value: value["release_absences"][0].__setitem__("extra", False),
        lambda value: value["release_absences"][0].pop("status"),
        lambda value: value["marker"].__setitem__("extra", False),
    ],
)
def test_barrier_parser_rejects_extra_or_inexact_candidates(
    mutation: Callable[[dict[str, Any]], object],
) -> None:
    assert reader._STAGED_BARRIER_COMMAND == (
        "/opt/autoquant/trusted-time/bin/autoquant-trusted-time-python",
        "post-enrollment-staged-barrier-read",
    )
    payload = _barrier()
    mutation(cast(dict[str, Any], payload))
    with pytest.raises(ValueError):
        reader._parse_staged_barrier_probe(_json_line(payload))


def test_host_retirement_is_root_and_parent_descriptor_anchored(tmp_path: Path) -> None:
    paths = _staged_paths(tmp_path / "retired")
    observed = reader._require_anchored_retirement_observation(
        reader._observe_host_retirements(paths)
    )
    assert tuple(projection[1] for projection in observed[2]) == tuple(
        os.fspath(path) for path in paths
    )

    target = tmp_path / "attacker-parent"
    target.mkdir(mode=0o700)
    paths[0].parent.symlink_to(target, target_is_directory=True)
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        reader._observe_host_retirements(paths)


def test_host_retirement_rejects_existing_leaf_or_insecure_root(tmp_path: Path) -> None:
    paths = _staged_paths(tmp_path / "retired")
    paths[0].parent.mkdir(mode=0o700)
    paths[0].write_text("retained", encoding="utf-8")
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        reader._observe_host_retirements(paths)
    paths[0].unlink()
    paths[0].parent.rmdir()
    paths[0].parent.parent.chmod(0o755)
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        reader._observe_host_retirements(paths)


def test_direct_envelope_construction_has_no_authentication_surface(tmp_path: Path) -> None:
    endpoint = "unix:///trusted/docker.sock"
    created = _created_snapshot(endpoint)
    staged = _staged_snapshot(endpoint, created)
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        reader.TrustedTimePostEnrollmentCreatedTopologyObservation(
            session_sha256="1" * 64,
            transcript_sha256="2" * 64,
            observation_count=14,
            snapshot=created,
            _seal=b"0" * 32,
        )
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        reader.TrustedTimePostEnrollmentStagedTopologyObservation(
            session_sha256="1" * 64,
            transcript_sha256="2" * 64,
            observation_count=16,
            created_observation_sha256="3" * 64,
            staged_observation_ordinal=1,
            predecessor_observation_sha256="3" * 64,
            snapshot=staged,
            _seal=b"0" * 32,
        )
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        reader.TrustedTimePostEnrollmentFinalActionTopologyObservation(
            session_sha256="1" * 64,
            transcript_sha256="2" * 64,
            observation_count=16,
            claimed_fence_sha256="3" * 64,
            created_observation_sha256="4" * 64,
            predecessor_observation_sha256="5" * 64,
            snapshot=staged,
            _seal=b"0" * 32,
        )


def test_dependency_injected_session_cannot_mint_authenticated_envelope(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = _short_socket_path(tmp_path)
    endpoint = f"unix://{socket_path}"
    _install_pure_validator_stubs(monkeypatch, endpoint=endpoint)
    queued = _QueuedRunner([_json_line("LOCAL:DAEMON:1"), *_state_outputs("created")])
    ignored_root = tmp_path / "artifacts"
    executable_path, executable_identity = reader._resolve_trusted_docker_executable()
    issuer = reader.TrustedTimePostEnrollmentTopologyObservationIssuer.allocate_inert()
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._activate_with_dependencies(
            daemon_identity_registration=reader._capture_daemon_identity_registration(
                LocalDockerDaemonIdentity(
                    context_name="<DOCKER_HOST>",
                    endpoint=endpoint,
                    daemon_id="LOCAL:DAEMON:1",
                )
            ),
            environment_identity=reader._minimal_docker_environment({}, endpoint=endpoint),
            docker_executable=executable_path,
            docker_executable_identity=executable_identity,
            ignored_root=os.fspath(ignored_root),
            artifact_directory=os.fspath(ignored_root / "trusted-time"),
            runner=queued,
            session_token_factory=lambda: b"n" * 32,
        )
    assert len(queued.calls) <= 1


@pytest.mark.parametrize("capability_slot", ["registered", "none", "decoy"])
@pytest.mark.parametrize(
    ("failure_type", "exit_code"),
    [(KeyboardInterrupt, None), (SystemExit, 23)],
)
def test_poison_invalidates_heap_before_retry_and_permanently_burns_closure_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capability_slot: str,
    failure_type: type[BaseException],
    exit_code: int | None,
) -> None:
    socket_path = _short_socket_path(tmp_path)
    queued = _QueuedRunner([_json_line("LOCAL:DAEMON:1")])
    issuer = _public_open(monkeypatch, tmp_path, queued, socket_path)
    saved_capability = issuer._authentication_capability
    assert type(saved_capability) is reader._AuthenticatedIssuerCapability
    if capability_slot == "none":
        issuer._authentication_capability = None
    elif capability_slot == "decoy":
        issuer._authentication_capability = cast(Any, object())

    burn_calls = 0

    def interrupt_then_burn_owner(owner: object) -> bool:
        nonlocal burn_calls
        burn_calls += 1
        assert owner is issuer
        assert issuer._poisoned is True
        assert issuer._authentication_capability is None
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            reader._authenticated_issuer_runtime_provenance(
                issuer,
                saved_capability,
            )
        if burn_calls == 1:
            if failure_type is SystemExit:
                raise SystemExit(exit_code)
            raise KeyboardInterrupt
        assert reader._revoke_authenticated_issuer_owner_registrations(issuer) is True
        return True

    with pytest.raises(failure_type) as raised:
        issuer._poison_locked(_burn_owner_registrations=interrupt_then_burn_owner)
    if failure_type is SystemExit:
        assert cast(SystemExit, raised.value).code == exit_code
    assert burn_calls >= 2
    assert issuer._poisoned is True
    assert issuer._authentication_capability is None

    issuer._authentication_capability = saved_capability
    issuer._poisoned = False
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        reader._authenticated_issuer_runtime_provenance(
            issuer,
            saved_capability,
        )
    issuer.close()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires POSIX fork")
def test_real_fork_rejects_inherited_closure_provenance_after_getpid_relabel(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = _short_socket_path(tmp_path)
    queued = _QueuedRunner([_json_line("LOCAL:DAEMON:1")])
    issuer = _public_open(monkeypatch, tmp_path, queued, socket_path)
    saved_capability = issuer._authentication_capability
    assert type(saved_capability) is reader._AuthenticatedIssuerCapability
    real_getpid = os.getpid
    parent_pid = real_getpid()
    read_descriptor, write_descriptor = os.pipe()
    monkeypatch.setattr(reader.os, "getpid", lambda: parent_pid)

    child_pid = os.fork()
    if child_pid == 0:
        os.close(read_descriptor)
        try:
            try:
                reader._authenticated_issuer_runtime_provenance(
                    issuer,
                    saved_capability,
                )
            except reader.TrustedTimePostEnrollmentTopologyReaderError:
                outcome = b"rejected"
            except BaseException:
                outcome = b"unexpected-error"
            else:
                outcome = b"accepted"
            os.write(write_descriptor, outcome)
        finally:
            os.close(write_descriptor)
            os._exit(0)

    os.close(write_descriptor)
    try:
        outcome = os.read(read_descriptor, 64)
    finally:
        os.close(read_descriptor)
    waited_pid, status = os.waitpid(child_pid, 0)
    assert waited_pid == child_pid
    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 0
    assert outcome == b"rejected"
    issuer.close()


def test_staged_barrier_rejects_heap_relabels_before_runner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, queued, _, created = _open_created_test_issuer(monkeypatch, tmp_path)
    registration = reader._require_reviewed_created_registration(
        issuer._reviewed_mutation_created_registration
    )
    assert registration[1] is created
    original_call_count = len(queued.calls)

    def assert_rejected_before_runner() -> None:
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._observe_barrier(())
        assert len(queued.calls) == original_call_count

    issuer._reviewed_mutation_created_registration = (
        registration[0],
        registration[1],
        registration[2],
        registration[3],
        ("c" * 64, "d" * 64),
        registration[5],
    )
    assert_rejected_before_runner()
    issuer._reviewed_mutation_created_registration = registration

    issuer._reviewed_mutation_created_registration = (
        registration[0],
        registration[1],
        registration[2],
        registration[3],
        registration[4],
        "/tmp/attacker-docker",
    )
    assert_rejected_before_runner()
    issuer._reviewed_mutation_created_registration = registration

    trusted_docker = issuer._docker_executable_path_value
    issuer._docker_executable_path_value = "/tmp/attacker-docker"
    assert_rejected_before_runner()
    issuer._docker_executable_path_value = trusted_docker

    trusted_session = issuer._session_sha256
    issuer._session_sha256 = "0" * 64 if trusted_session != "0" * 64 else "1" * 64
    assert_rejected_before_runner()
    issuer._session_sha256 = trusted_session

    assert issuer._reviewed_mutation_created_registration is registration
    issuer.close()


def test_inventory_and_staged_commands_ignore_relabelled_globals(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, queued, _, _ = _open_created_test_issuer(monkeypatch, tmp_path)
    monkeypatch.setattr(
        reader,
        "POST_ENROLLMENT_CREATED_TOPOLOGY_COMPOSE_PROJECT",
        "--attacker-project",
    )
    monkeypatch.setattr(reader, "_FULL_ID_PATTERN", reader.re.compile(r".*"))
    monkeypatch.setattr(
        reader,
        "_STAGED_BARRIER_COMMAND",
        ("/tmp/attacker-python", "attacker-probe"),
    )
    queued.outputs.extend([_inventory_bytes(), _json_line(_barrier())])

    inventory, inventory_receipts = issuer._observe_inventory(())
    assert inventory == (SOURCE_CONTAINER_ID, SUPERVISOR_CONTAINER_ID)
    assert len(inventory_receipts) == 1
    assert queued.calls[-1]["argv"] == (
        issuer._docker_executable_path_value,
        "container",
        "ls",
        "--all",
        "--no-trunc",
        "--filter",
        "label=com.docker.compose.project=autoquanttrader-trusted-time",
        "--format",
        '{{.ID}} {{.Label "com.docker.compose.service"}}',
    )

    projection, barrier_receipts = issuer._observe_barrier(())
    assert projection[0] == "trusted-time-staged-barrier-probe-v1"
    assert len(barrier_receipts) == 1
    assert queued.calls[-1]["argv"] == (
        issuer._docker_executable_path_value,
        "container",
        "exec",
        "--user",
        "10001:10001",
        SUPERVISOR_CONTAINER_ID,
        "/opt/autoquant/trusted-time/bin/autoquant-trusted-time-python",
        "post-enrollment-staged-barrier-read",
    )
    assert queued.outputs == []
    issuer.close()


def test_inventory_rejects_option_like_id_even_if_pattern_global_is_permissive(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = _short_socket_path(tmp_path)
    malformed_inventory = (
        b"--"
        + b"a" * 62
        + b" chrony-nts\n"
        + SUPERVISOR_CONTAINER_ID.encode("ascii")
        + b" trusted-time-supervisor\n"
    )
    queued = _QueuedRunner([_json_line("LOCAL:DAEMON:1"), malformed_inventory])
    issuer = _public_open(monkeypatch, tmp_path, queued, socket_path)
    monkeypatch.setattr(reader, "_FULL_ID_PATTERN", reader.re.compile(r".*"))

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._observe_inventory(())
    assert queued.calls[-1]["argv"] == (
        issuer._docker_executable_path_value,
        "container",
        "ls",
        "--all",
        "--no-trunc",
        "--filter",
        "label=com.docker.compose.project=autoquanttrader-trusted-time",
        "--format",
        '{{.ID}} {{.Label "com.docker.compose.service"}}',
    )
    assert queued.outputs == []
    issuer.close()


@pytest.mark.parametrize("failure", [KeyboardInterrupt(), SystemExit(2)])
def test_observation_baseexception_poisons_and_lock_remains_closeable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure: BaseException,
) -> None:
    socket_path = _short_socket_path(tmp_path)
    queued = _QueuedRunner([_json_line("LOCAL:DAEMON:1"), failure])
    paths = _staged_paths(tmp_path / "retired")
    issuer = _public_open(monkeypatch, tmp_path, queued, socket_path)
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer.issue_created_snapshot(**_issue_arguments(paths))  # type: ignore[arg-type]
    assert len(queued.calls) == 2
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer.issue_created_snapshot(**_issue_arguments(paths))  # type: ignore[arg-type]
    assert len(queued.calls) == 2
    issuer.close()

    reopened_runner = _QueuedRunner([_json_line("LOCAL:DAEMON:1")])
    reopened = _public_open(monkeypatch, tmp_path, reopened_runner, socket_path)
    reopened.close()


def test_open_rejects_missing_line_feed_and_releases_lock(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = _short_socket_path(tmp_path)
    malformed = _QueuedRunner([b'"LOCAL:DAEMON:1"'])
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        _public_open(monkeypatch, tmp_path, malformed, socket_path)

    valid = _QueuedRunner([_json_line("LOCAL:DAEMON:1")])
    issuer = _public_open(monkeypatch, tmp_path, valid, socket_path)
    issuer.close()


def test_close_scrubs_and_releases_after_arbitrary_validation_baseexception(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = _short_socket_path(tmp_path)
    queued = _QueuedRunner([_json_line("LOCAL:DAEMON:1")])
    issuer = _public_open(monkeypatch, tmp_path, queued, socket_path)
    failure = KeyboardInterrupt()

    def interrupted_validation(
        _issuer: reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
    ) -> Never:
        raise failure

    with pytest.raises(KeyboardInterrupt) as raised:
        issuer.close(_teardown_binding=interrupted_validation)
    assert raised.value is failure
    assert repr(issuer).endswith("state='closed')")
    assert issuer._launch_lock_lease is None
    assert issuer._authentication_capability is None
    assert issuer._environment == {}

    reopened_runner = _QueuedRunner([_json_line("LOCAL:DAEMON:1")])
    reopened = _public_open(monkeypatch, tmp_path, reopened_runner, socket_path)
    reopened.close()


def test_close_never_closes_a_foreign_heap_decoy_lease(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root_a = tmp_path / "issuer-a"
    root_b = tmp_path / "issuer-b"
    root_a.mkdir()
    root_b.mkdir()
    socket_path = _short_socket_path(tmp_path)
    issuer_a = _public_open(
        monkeypatch,
        root_a,
        _QueuedRunner([_json_line("LOCAL:DAEMON:1")]),
        socket_path,
    )
    issuer_b = _public_open(
        monkeypatch,
        root_b,
        _QueuedRunner([_json_line("LOCAL:DAEMON:1")]),
        socket_path,
    )
    lease_a = issuer_a._launch_lock_lease
    lease_b = issuer_b._launch_lock_lease
    assert type(lease_a) is _TrustedTimeLaunchLockLease
    assert type(lease_b) is _TrustedTimeLaunchLockLease
    issuer_a._launch_lock_lease = lease_b

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer_a.close()

    assert lease_a.closed is True
    assert lease_b.closed is False
    _validate_trusted_time_launch_lock(lease_b)
    assert issuer_a._launch_lock_lease is None
    issuer_b.close()
    assert lease_b.closed is True


def test_close_classifies_diagnostic_path_crossbinding_but_closes_true_lease(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = _short_socket_path(tmp_path)
    issuer = _public_open(
        monkeypatch,
        tmp_path,
        _QueuedRunner([_json_line("LOCAL:DAEMON:1")]),
        socket_path,
    )
    ignored_root = os.fspath(issuer._ignored_root)
    lease = issuer._launch_lock_lease
    assert type(lease) is _TrustedTimeLaunchLockLease
    issuer._ignored_root = tmp_path / "foreign-diagnostic-root"

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer.close()

    assert lease.closed is True
    assert issuer._launch_lock_lease is None
    replacement = _acquire_trusted_time_launch_lock(ignored_root)
    _validate_trusted_time_launch_lock(replacement)
    replacement.close()


def test_close_reports_premature_native_lease_close_and_finishes_burn(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = _short_socket_path(tmp_path)
    issuer = _public_open(
        monkeypatch,
        tmp_path,
        _QueuedRunner([_json_line("LOCAL:DAEMON:1")]),
        socket_path,
    )
    ignored_root = os.fspath(issuer._ignored_root)
    lease = issuer._launch_lock_lease
    assert type(lease) is _TrustedTimeLaunchLockLease
    lease.close()

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer.close()

    assert lease.closed is True
    assert issuer._closed is True
    assert issuer._poisoned is True
    assert issuer._authentication_capability is None
    assert issuer._launch_lock_lease is None
    replacement = _acquire_trusted_time_launch_lock(ignored_root)
    _validate_trusted_time_launch_lock(replacement)
    replacement.close()


def test_pid_drift_fails_before_inherited_mutex_or_docker_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = _short_socket_path(tmp_path)
    queued = _QueuedRunner([_json_line("LOCAL:DAEMON:1")])
    issuer = _public_open(monkeypatch, tmp_path, queued, socket_path)
    owner_pid = os.getpid()
    ignored_root = os.fspath(issuer._ignored_root)
    lease = issuer._launch_lock_lease
    assert type(lease) is _TrustedTimeLaunchLockLease
    issuer._lifecycle_lock.acquire()
    monkeypatch.setattr(reader.os, "getpid", lambda: owner_pid + 1)
    try:
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._begin_observation()
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer.close(_getpid=lambda: owner_pid + 1)
        assert len(queued.calls) == 1
    finally:
        monkeypatch.setattr(reader.os, "getpid", lambda: owner_pid)
        issuer._lifecycle_lock.release()
    assert issuer._closed is True
    assert issuer._launch_lock_lease is None
    assert lease.closed is True
    replacement = _acquire_trusted_time_launch_lock(ignored_root)
    _validate_trusted_time_launch_lock(replacement)
    replacement.close()


def test_issuer_rejects_copy_deepcopy_pickle_and_reentrant_begin(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = _short_socket_path(tmp_path)
    queued = _QueuedRunner([_json_line("LOCAL:DAEMON:1")])
    issuer = _public_open(monkeypatch, tmp_path, queued, socket_path)
    for operation in (
        lambda: copy(issuer),
        lambda: deepcopy(issuer),
        lambda: pickle.dumps(issuer),
    ):
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            operation()
    issuer._begin_observation()
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._begin_observation()
    issuer._finish_observation()
    assert "poisoned" in repr(issuer)
    issuer.close()


def test_docker_executable_or_socket_identity_drift_fails_before_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = _short_socket_path(tmp_path)
    queued = _QueuedRunner([_json_line("LOCAL:DAEMON:1")])
    issuer = _public_open(monkeypatch, tmp_path, queued, socket_path)
    trusted_path = issuer._docker_executable_path_value
    issuer._docker_executable_path_value = "/tmp/attacker-docker"
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._validate_session()
    assert len(queued.calls) == 1
    issuer._docker_executable_path_value = trusted_path
    issuer.close()


def test_operational_probe_currentness_boundaries_are_pinned_in_all_operator_docs() -> None:
    documents = (
        reader.ROOT / "docs" / "ARCHITECTURE.md",
        reader.ROOT / "docs" / "IMPLEMENTATION_PLAN.md",
        reader.ROOT
        / "docs"
        / "adr"
        / "0099-approval-bound-post-enrollment-start-and-graceful-stop.md",
        reader.ROOT / "docs" / "runbooks" / "trusted-time-supervisor.md",
    )
    required_phrases = (
        "process-entry stream selection",
        "legacy Python runner/Popen boundary",
        "does not establish an immutable aggregate spawn transaction",
        "write-once/no-hostile-writer boundary",
    )

    for path in documents:
        documented = path.read_text(encoding="utf-8")
        assert all(phrase in documented for phrase in required_phrases), path


def test_reader_surface_is_dormant_and_has_no_authority_methods() -> None:
    public = set(reader.__all__)
    assert public == {
        "POST_ENROLLMENT_CREATED_TOPOLOGY_OBSERVATION_STATUS",
        "POST_ENROLLMENT_FINAL_ACTION_TOPOLOGY_OBSERVATION_CONTRACT_VERSION",
        "POST_ENROLLMENT_FINAL_ACTION_TOPOLOGY_OBSERVATION_STATUS",
        "POST_ENROLLMENT_STAGED_TOPOLOGY_OBSERVATION_STATUS",
        "POST_ENROLLMENT_TOPOLOGY_OBSERVATION_CURSOR_CONTRACT_VERSION",
        "POST_ENROLLMENT_TOPOLOGY_OBSERVATION_CURSOR_STATUS",
        "POST_ENROLLMENT_TOPOLOGY_READER_CONTRACT_VERSION",
        "TrustedTimePostEnrollmentCreatedTopologyObservation",
        "TrustedTimePostEnrollmentFinalActionTopologyObservation",
        "TrustedTimePostEnrollmentStagedTopologyObservation",
        "TrustedTimePostEnrollmentTopologyObservationCursor",
        "TrustedTimePostEnrollmentTopologyObservationIssuer",
        "TrustedTimePostEnrollmentTopologyReaderError",
    }
    assert not hasattr(reader, "main")
    assert not hasattr(reader, "run")
    assert not hasattr(reader.TrustedTimePostEnrollmentTopologyObservationIssuer, "start")
    assert not hasattr(reader.TrustedTimePostEnrollmentTopologyObservationIssuer, "release")
    assert not hasattr(reader.TrustedTimePostEnrollmentTopologyObservationIssuer, "claim")
