from __future__ import annotations

import hashlib
import json
import os
import pickle
import subprocess
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from copy import copy, deepcopy
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from typing import Any, Literal, cast

import pytest

import scripts.trusted_time_post_enrollment_topology_reader as reader
from apps.trusted_time_supervisor.main import DATABASE_SECRET_CONSUMED_BYTES
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
    del path
    yield


def _short_socket_path(seed: Path) -> Path:
    digest = hashlib.sha256(os.fspath(seed).encode()).hexdigest()[:16]
    return reader.ROOT / f".aqt-reader-{digest}.sock"


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
    ) -> subprocess.CompletedProcess[bytes]:
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
        return subprocess.CompletedProcess(argv, 0, output, b"")


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
    return _json_line(SOURCE_CONTAINER_ID) + _json_line(SUPERVISOR_CONTAINER_ID)


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


def _public_open(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    runner: _QueuedRunner,
    socket_path: Path,
    executable: Path,
) -> reader.TrustedTimePostEnrollmentTopologyObservationIssuer:
    ignored_root = tmp_path / "artifacts"
    lock_path = ignored_root / "trusted-time" / "trusted-time-launch.lock"
    monkeypatch.setattr(reader, "IGNORED_ARTIFACT_ROOT", ignored_root)
    monkeypatch.setattr(reader, "TRUSTED_TIME_LAUNCH_LOCK_PATH", lock_path)
    monkeypatch.setattr(reader, "_TRUSTED_DOCKER_EXECUTABLE_CANDIDATES", (executable,))
    monkeypatch.setattr(reader, "run_bounded_subprocess", runner)
    monkeypatch.setattr(
        reader,
        "_socket_identity",
        lambda _path: (1, 2, 0o140700, os.geteuid(), os.getegid()),
    )
    return reader.TrustedTimePostEnrollmentTopologyObservationIssuer.open(
        expected_daemon_identity=LocalDockerDaemonIdentity(
            context_name="<DOCKER_HOST>",
            endpoint=f"unix://{socket_path}",
            daemon_id="LOCAL:DAEMON:1",
        ),
        docker_environment={"PATH": os.fspath(tmp_path / "attacker-bin"), "LANG": "C"},
    )


def _issue_arguments(paths: tuple[Path, Path, Path, Path]) -> dict[str, object]:
    return {
        "approval": _approval(),
        "approved_launch": _approved_launch(),
        "expected_database_secret_file": paths[0],
        "expected_head_anchor_authority_file": paths[1],
        "expected_head_anchor_auth_secret_file": paths[2],
        "expected_head_anchor_signing_key_secret_file": paths[3],
    }


def test_public_issuer_reads_exact_bounded_schedule_and_seals_two_staged_observations(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = _short_socket_path(tmp_path)
    executable = tmp_path / "trusted-docker"
    _make_executable(executable)
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
        issuer = _public_open(monkeypatch, tmp_path, queued, socket_path, executable)
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
        expected_executable = os.fspath(executable.resolve())
        assert all(call["argv"][0] == expected_executable for call in queued.calls)  # type: ignore[index]
        assert all(call["cwd"] == reader.ROOT for call in queued.calls)
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
    executable = tmp_path / "trusted-docker"
    _make_executable(executable)
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

    issuer = _public_open(monkeypatch, tmp_path, queued, socket_path, executable)

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
    executable = tmp_path / "trusted-docker"
    _make_executable(executable)
    endpoint = f"unix://{socket_path}"
    _install_pure_validator_stubs(monkeypatch, endpoint=endpoint)
    monkeypatch.setattr(
        reader,
        "validate_post_enrollment_start_created_topology",
        lambda **_kwargs: context.created.snapshot,
    )
    monkeypatch.setattr(
        reader,
        "validate_post_enrollment_start_staged_unreleased_topology",
        lambda **_kwargs: context.staged_two.snapshot,
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
    issuer = _public_open(monkeypatch, tmp_path, queued, socket_path, executable)

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
    executable = tmp_path / "trusted-docker"
    _make_executable(executable)
    queued = _QueuedRunner([_json_line("LOCAL:DAEMON:1")])
    issuer = _public_open(monkeypatch, tmp_path, queued, socket_path, executable)
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
    executable = tmp_path / "trusted-docker"
    _make_executable(executable)
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

    issuer = _public_open(monkeypatch, tmp_path, queued, socket_path, executable)
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
        )


def test_container_raw_boundary_accepts_exact_created_and_staged_shapes() -> None:
    created = _container("created", "chrony-nts")
    created["ExecIDs"] = None
    created_attachment = reader._validate_container_reader_boundary(
        created,
        expected_container_id=SOURCE_CONTAINER_ID,
        expected_service="chrony-nts",
        expected_state="created",
    )
    staged_attachment = reader._validate_container_reader_boundary(
        _container("staged_unreleased", "trusted-time-supervisor"),
        expected_container_id=SUPERVISOR_CONTAINER_ID,
        expected_service="trusted-time-supervisor",
        expected_state="staged_unreleased",
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
    monkeypatch: pytest.MonkeyPatch,
    mutation: Callable[[dict[str, Any]], object],
) -> None:
    payload = _barrier()
    mutation(cast(dict[str, Any], payload))
    issuer = object.__new__(reader.TrustedTimePostEnrollmentTopologyObservationIssuer)
    issuer._docker_executable_path = Path("/trusted/docker")
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_run_json",
        lambda *_args, **_kwargs: payload,
    )
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._observe_barrier([], supervisor_container_id=SUPERVISOR_CONTAINER_ID)


def test_host_retirement_is_root_and_parent_descriptor_anchored(tmp_path: Path) -> None:
    paths = _staged_paths(tmp_path / "retired")
    observed = reader._observe_host_retirements(paths)
    assert tuple(candidate.path for candidate in observed.candidates) == tuple(
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
    executable = tmp_path / "trusted-docker"
    _make_executable(executable)
    _install_pure_validator_stubs(monkeypatch, endpoint=endpoint)
    queued = _QueuedRunner([_json_line("LOCAL:DAEMON:1"), *_state_outputs("created")])
    monkeypatch.setattr(
        reader,
        "_socket_identity",
        lambda _path: (1, 2, 0o140700, os.geteuid(), os.getegid()),
    )
    ignored_root = tmp_path / "artifacts"
    issuer = reader.TrustedTimePostEnrollmentTopologyObservationIssuer._open_with_dependencies(
        expected_daemon_identity=LocalDockerDaemonIdentity(
            context_name="<DOCKER_HOST>",
            endpoint=endpoint,
            daemon_id="LOCAL:DAEMON:1",
        ),
        docker_environment={},
        docker_executable=executable,
        lock_path=ignored_root / "trusted-time" / "trusted-time-launch.lock",
        ignored_root=ignored_root,
        runner=queued,
        session_token_factory=lambda: b"n" * 32,
    )
    paths = _staged_paths(tmp_path / "retired")
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer.issue_created_snapshot(**_issue_arguments(paths))  # type: ignore[arg-type]
    assert len(queued.calls) == 1
    assert "open" in repr(issuer)
    issuer.close()


@pytest.mark.parametrize("failure", [KeyboardInterrupt(), SystemExit(2)])
def test_observation_baseexception_poisons_and_lock_remains_closeable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure: BaseException,
) -> None:
    socket_path = _short_socket_path(tmp_path)
    executable = tmp_path / "trusted-docker"
    _make_executable(executable)
    queued = _QueuedRunner([_json_line("LOCAL:DAEMON:1"), failure])
    paths = _staged_paths(tmp_path / "retired")
    issuer = _public_open(monkeypatch, tmp_path, queued, socket_path, executable)
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer.issue_created_snapshot(**_issue_arguments(paths))  # type: ignore[arg-type]
    assert len(queued.calls) == 2
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer.issue_created_snapshot(**_issue_arguments(paths))  # type: ignore[arg-type]
    assert len(queued.calls) == 2
    issuer.close()

    reopened_runner = _QueuedRunner([_json_line("LOCAL:DAEMON:1")])
    reopened = _public_open(monkeypatch, tmp_path, reopened_runner, socket_path, executable)
    reopened.close()


def test_open_rejects_missing_line_feed_and_releases_lock(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = _short_socket_path(tmp_path)
    executable = tmp_path / "trusted-docker"
    _make_executable(executable)
    malformed = _QueuedRunner([b'"LOCAL:DAEMON:1"'])
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        _public_open(monkeypatch, tmp_path, malformed, socket_path, executable)

    valid = _QueuedRunner([_json_line("LOCAL:DAEMON:1")])
    issuer = _public_open(monkeypatch, tmp_path, valid, socket_path, executable)
    issuer.close()


def test_close_scrubs_and_releases_after_arbitrary_validation_baseexception(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = _short_socket_path(tmp_path)
    executable = tmp_path / "trusted-docker"
    _make_executable(executable)
    queued = _QueuedRunner([_json_line("LOCAL:DAEMON:1")])
    issuer = _public_open(monkeypatch, tmp_path, queued, socket_path, executable)
    original_validate_lock = (
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer._validate_lock
    )

    def interrupted_validation(
        _issuer: reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
    ) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_validate_lock",
        interrupted_validation,
    )
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer.close()
    assert repr(issuer).endswith("state='closed')")
    assert issuer._lock_descriptor == -1
    assert issuer._authentication_capability is None
    assert issuer._environment == {}

    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_validate_lock",
        original_validate_lock,
    )
    reopened_runner = _QueuedRunner([_json_line("LOCAL:DAEMON:1")])
    reopened = _public_open(monkeypatch, tmp_path, reopened_runner, socket_path, executable)
    reopened.close()


def test_pid_drift_fails_before_inherited_mutex_or_docker_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = _short_socket_path(tmp_path)
    executable = tmp_path / "trusted-docker"
    _make_executable(executable)
    queued = _QueuedRunner([_json_line("LOCAL:DAEMON:1")])
    issuer = _public_open(monkeypatch, tmp_path, queued, socket_path, executable)
    owner_pid = os.getpid()
    issuer._lifecycle_lock.acquire()
    monkeypatch.setattr(reader.os, "getpid", lambda: owner_pid + 1)
    try:
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._begin_observation()
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer.close()
        assert len(queued.calls) == 1
    finally:
        monkeypatch.setattr(reader.os, "getpid", lambda: owner_pid)
        issuer._lifecycle_lock.release()
    issuer.close()


def test_issuer_rejects_copy_deepcopy_pickle_and_reentrant_begin(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = _short_socket_path(tmp_path)
    executable = tmp_path / "trusted-docker"
    _make_executable(executable)
    queued = _QueuedRunner([_json_line("LOCAL:DAEMON:1")])
    issuer = _public_open(monkeypatch, tmp_path, queued, socket_path, executable)
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
    executable = tmp_path / "trusted-docker"
    _make_executable(executable)
    queued = _QueuedRunner([_json_line("LOCAL:DAEMON:1")])
    issuer = _public_open(monkeypatch, tmp_path, queued, socket_path, executable)
    executable.chmod(0o755)
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._validate_session()
    assert len(queued.calls) == 1
    issuer.close()


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
