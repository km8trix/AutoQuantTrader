from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from collections.abc import Callable
from copy import deepcopy
from dataclasses import fields, replace
from pathlib import Path
from typing import Any, Never, cast

import pytest

import apps.trusted_time_supervisor.post_enrollment_release as release
import scripts.trusted_time_post_enrollment_active_controller_admission as admission_module
import scripts.trusted_time_post_enrollment_claimed_fence as claimed_module
import scripts.trusted_time_post_enrollment_persistent_topology as persistent
import scripts.trusted_time_post_enrollment_topology_reader as reader_module
from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_start import (
    TrustedTimePostEnrollmentStartSuccessor,
)
from scripts.start_trusted_time_supervisor import (
    LocalDockerDaemonIdentity,
    TrustedTimeVolumeIdentities,
)
from scripts.trusted_time_post_enrollment_action_topology_fence import (
    prepare_post_enrollment_start_leased_claimed_action_topology_fence as prepare_action_fence,
)
from scripts.trusted_time_post_enrollment_staged_topology import (
    TrustedTimePostEnrollmentAbsentPathCandidate,
    validate_post_enrollment_start_staged_unreleased_topology,
)
from scripts.trusted_time_post_enrollment_topology import (
    validate_post_enrollment_start_created_topology,
)
from scripts.trusted_time_post_enrollment_topology_fence import (
    bind_post_enrollment_start_pre_claim_topology_fence,
)
from tests.unit import test_trusted_time_post_enrollment_action_topology_fence as action_fixtures
from tests.unit import (
    test_trusted_time_post_enrollment_active_controller_admission as admission_fixtures,
)
from tests.unit import test_trusted_time_post_enrollment_claimed_fence as claimed_fixtures
from tests.unit import test_trusted_time_post_enrollment_staged_topology as staged_fixtures
from tests.unit import test_trusted_time_post_enrollment_start as start_fixtures
from tests.unit import test_trusted_time_post_enrollment_topology_reader as reader_fixtures


@pytest.fixture(autouse=True)
def _install_test_observation_validators(monkeypatch: pytest.MonkeyPatch) -> None:
    def valid(candidate: object, payload: object) -> bool:
        return type(candidate) is bytes and candidate == claimed_fixtures._authenticated_seal(
            cast(dict[str, object], payload)
        )

    monkeypatch.setattr(
        reader_module,
        "_valid_observation_seal",
        valid,
    )
    monkeypatch.setattr(
        reader_module,
        "_valid_cursor_seal",
        lambda candidate, payload, _result: valid(candidate, payload),
    )


def _release_marker(
    **changes: object,
) -> persistent.TrustedTimePostEnrollmentReleaseMarkerCandidate:
    values: dict[str, object] = {
        "path": release.POST_ENROLLMENT_START_RELEASE_PATH,
        "byte_sha256": release.POST_ENROLLMENT_START_RELEASE_SHA256,
        "size": len(release.POST_ENROLLMENT_START_RELEASE_BYTES),
        "owner_uid": 10_001,
        "owner_gid": 10_001,
        "mode": 0o400,
        "link_count": 1,
        "regular": True,
        "device": 4,
        "inode": 8,
        "modified_time_ns": 9,
        "changed_time_ns": 10,
    }
    values.update(changes)
    return persistent.TrustedTimePostEnrollmentReleaseMarkerCandidate(**values)  # type: ignore[arg-type]


def _network() -> dict[str, object]:
    return reader_fixtures._network("staged_unreleased")


def _exact_staged_inputs(
    context: claimed_fixtures._Context,
) -> dict[str, object]:
    paths_tuple = claimed_fixtures._staged_paths(context.artifact_directory)
    paths = dict(zip(("database", "authority", "auth", "signing"), paths_tuple, strict=True))
    approval = staged_fixtures._approval()
    approved_launch = staged_fixtures._approved_launch()
    source_created = staged_fixtures._container_inspection(
        role="source",
        container_id=staged_fixtures.SOURCE_CONTAINER_ID,
        image_id=staged_fixtures.SOURCE_IMAGE_ID,
        staged_paths=paths,
        running=False,
    )
    supervisor_created = staged_fixtures._container_inspection(
        role="supervisor",
        container_id=staged_fixtures.SUPERVISOR_CONTAINER_ID,
        image_id=staged_fixtures.SUPERVISOR_IMAGE_ID,
        staged_paths=paths,
        running=False,
    )
    created = validate_post_enrollment_start_created_topology(
        approval=approval,
        approved_launch=approved_launch,
        daemon_identity_before=staged_fixtures._daemon_identity(),
        daemon_identity_after=staged_fixtures._daemon_identity(),
        volume_identities_before=staged_fixtures._volume_identities(),
        volume_identities_after=staged_fixtures._volume_identities(),
        project_container_ids_before=(
            staged_fixtures.SOURCE_CONTAINER_ID,
            staged_fixtures.SUPERVISOR_CONTAINER_ID,
        ),
        project_container_ids_after=(
            staged_fixtures.SUPERVISOR_CONTAINER_ID,
            staged_fixtures.SOURCE_CONTAINER_ID,
        ),
        container_inspections={
            staged_fixtures.SOURCE_CONTAINER_ID: source_created,
            staged_fixtures.SUPERVISOR_CONTAINER_ID: supervisor_created,
        },
        source_image_configuration=staged_fixtures._image_configuration("source"),
        supervisor_image_configuration=staged_fixtures._image_configuration("supervisor"),
        expected_database_secret_file=paths["database"],
        expected_head_anchor_authority_file=paths["authority"],
        expected_head_anchor_auth_secret_file=paths["auth"],
        expected_head_anchor_signing_key_secret_file=paths["signing"],
    )
    release_paths = [
        release.POST_ENROLLMENT_START_RELEASE_PATH,
        release.POST_ENROLLMENT_START_RELEASE_STAGING_PATH,
    ]
    staged_paths = [os.fspath(path) for path in paths.values()]
    return {
        "approval": approval,
        "approved_launch": approved_launch,
        "created_topology": created,
        "daemon_identity_before": staged_fixtures._daemon_identity(),
        "daemon_identity_after": staged_fixtures._daemon_identity(),
        "volume_identities_before": staged_fixtures._volume_identities(),
        "volume_identities_after": staged_fixtures._volume_identities(),
        "project_container_ids_before": (
            staged_fixtures.SOURCE_CONTAINER_ID,
            staged_fixtures.SUPERVISOR_CONTAINER_ID,
        ),
        "project_container_ids_after": (
            staged_fixtures.SUPERVISOR_CONTAINER_ID,
            staged_fixtures.SOURCE_CONTAINER_ID,
        ),
        "container_inspections": {
            staged_fixtures.SUPERVISOR_CONTAINER_ID: (
                staged_fixtures._container_inspection(
                    role="supervisor",
                    container_id=staged_fixtures.SUPERVISOR_CONTAINER_ID,
                    image_id=staged_fixtures.SUPERVISOR_IMAGE_ID,
                    staged_paths=paths,
                    running=True,
                )
            ),
            staged_fixtures.SOURCE_CONTAINER_ID: staged_fixtures._container_inspection(
                role="source",
                container_id=staged_fixtures.SOURCE_CONTAINER_ID,
                image_id=staged_fixtures.SOURCE_IMAGE_ID,
                staged_paths=paths,
                running=True,
            ),
        },
        "source_image_configuration": staged_fixtures._image_configuration("source"),
        "supervisor_image_configuration": staged_fixtures._image_configuration("supervisor"),
        "expected_database_secret_file": paths["database"],
        "expected_head_anchor_authority_file": paths["authority"],
        "expected_head_anchor_auth_secret_file": paths["auth"],
        "expected_head_anchor_signing_key_secret_file": paths["signing"],
        "database_secret_consumed_before": staged_fixtures._marker_candidate(),
        "database_secret_consumed_after": staged_fixtures._marker_candidate(),
        "release_path_absences_before": staged_fixtures._absence_candidates(release_paths),
        "release_path_absences_after": staged_fixtures._absence_candidates(
            list(reversed(release_paths))
        ),
        "staged_input_retirements_before": staged_fixtures._absence_candidates(staged_paths),
        "staged_input_retirements_after": staged_fixtures._absence_candidates(
            list(reversed(staged_paths))
        ),
    }


def _rebind_context_to_staged_inputs(
    context: claimed_fixtures._Context,
    staged_inputs: dict[str, object],
) -> object:
    staged = validate_post_enrollment_start_staged_unreleased_topology(
        **staged_inputs  # type: ignore[arg-type]
    )
    created = claimed_fixtures._created_observation(staged_inputs["created_topology"])
    staged_one = claimed_fixtures._staged_observation(
        staged,
        created,
        ordinal=1,
        predecessor_sha256=created.observation_sha256,
        transcript_sha256="2" * 64,
    )
    staged_two = claimed_fixtures._staged_observation(
        staged,
        created,
        ordinal=2,
        predecessor_sha256=staged_one.observation_sha256,
        transcript_sha256="3" * 64,
    )
    context.approval = staged_inputs["approval"]
    context.approved_launch = staged_inputs["approved_launch"]
    context.created = created
    context.staged_one = staged_one
    context.staged_two = staged_two
    context.pre_claim = bind_post_enrollment_start_pre_claim_topology_fence(
        created,
        staged_one,
    )
    context.cursors = [
        claimed_fixtures._cursor(
            ordinal=1,
            staged_count=1,
            created_observation_sha256=created.observation_sha256,
            last_observation_sha256=staged_one.observation_sha256,
            staged_snapshot_sha256=staged.snapshot_sha256,
        ),
        claimed_fixtures._cursor(
            ordinal=2,
            staged_count=1,
            created_observation_sha256=created.observation_sha256,
            last_observation_sha256=staged_one.observation_sha256,
            staged_snapshot_sha256=staged.snapshot_sha256,
        ),
        claimed_fixtures._cursor(
            ordinal=3,
            staged_count=2,
            created_observation_sha256=created.observation_sha256,
            last_observation_sha256=staged_two.observation_sha256,
            staged_snapshot_sha256=staged.snapshot_sha256,
        ),
    ]
    return staged


def _valid_inputs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[dict[str, object], claimed_fixtures._Context]:
    context = claimed_fixtures._context(tmp_path)
    staged_inputs = _exact_staged_inputs(context)
    final_snapshot = _rebind_context_to_staged_inputs(context, staged_inputs)
    lease = object()
    recovery = object()
    cast(Any, context).action_recovery_retention_capability = recovery
    claimed_fixtures._install_success(
        monkeypatch,
        context,
        expected_choreography_lease=lease,
        expected_recovery_retention_capability=recovery,
    )
    claimed = claimed_module.prepare_post_enrollment_start_leased_claimed_pre_release_fence(
        **context.kwargs(),  # type: ignore[arg-type]
        choreography_lease=lease,
        recovery_retention_capability=recovery,
    )
    context.events.clear()
    final = action_fixtures._final_observation(context, claimed, snapshot=final_snapshot)
    action_fixtures._install_final_issuer(
        monkeypatch,
        context,
        lease,
        claimed,
        final,
    )
    action_fence = prepare_action_fence(**action_fixtures._action_kwargs(context, lease, claimed))
    admission = admission_module.prepare_post_enrollment_start_active_controller_admission(
        **admission_fixtures._admission_kwargs(context, lease, recovery, action_fence)
    )
    staged_paths = [
        os.fspath(cast(Path, staged_inputs[key]))
        for key in (
            "expected_database_secret_file",
            "expected_head_anchor_authority_file",
            "expected_head_anchor_auth_secret_file",
            "expected_head_anchor_signing_key_secret_file",
        )
    ]
    inputs = {
        "admission": admission,
        "final_action_staged_topology": final_snapshot,
        "successor": start_fixtures._successor(),
        "approved_launch": staged_inputs["approved_launch"],
        "daemon_identity_before": staged_inputs["daemon_identity_before"],
        "daemon_identity_after": staged_inputs["daemon_identity_after"],
        "volume_identities_before": staged_inputs["volume_identities_before"],
        "volume_identities_after": staged_inputs["volume_identities_after"],
        "project_container_ids_before": staged_inputs["project_container_ids_before"],
        "project_container_ids_after": staged_inputs["project_container_ids_after"],
        "project_network_before": _network(),
        "project_network_after": _network(),
        "container_inspections": staged_inputs["container_inspections"],
        "source_image_configuration": staged_inputs["source_image_configuration"],
        "supervisor_image_configuration": staged_inputs["supervisor_image_configuration"],
        "expected_database_secret_file": staged_inputs["expected_database_secret_file"],
        "expected_head_anchor_authority_file": staged_inputs["expected_head_anchor_authority_file"],
        "expected_head_anchor_auth_secret_file": staged_inputs[
            "expected_head_anchor_auth_secret_file"
        ],
        "expected_head_anchor_signing_key_secret_file": staged_inputs[
            "expected_head_anchor_signing_key_secret_file"
        ],
        "database_secret_consumed_before": staged_inputs["database_secret_consumed_before"],
        "database_secret_consumed_after": staged_inputs["database_secret_consumed_after"],
        "release_marker_before": _release_marker(),
        "release_marker_after": _release_marker(),
        "release_staging_absences_before": (
            TrustedTimePostEnrollmentAbsentPathCandidate(
                path=release.POST_ENROLLMENT_START_RELEASE_STAGING_PATH
            ),
        ),
        "release_staging_absences_after": (
            TrustedTimePostEnrollmentAbsentPathCandidate(
                path=release.POST_ENROLLMENT_START_RELEASE_STAGING_PATH
            ),
        ),
        "staged_input_retirements_before": staged_fixtures._absence_candidates(staged_paths),
        "staged_input_retirements_after": staged_fixtures._absence_candidates(
            list(reversed(staged_paths))
        ),
    }
    return inputs, context


def _validate(
    inputs: dict[str, object],
) -> persistent.TrustedTimePostEnrollmentPersistentTopologySnapshot:
    validator = cast(
        Callable[..., persistent.TrustedTimePostEnrollmentPersistentTopologySnapshot],
        persistent.validate_post_enrollment_start_persistent_topology,
    )
    return validator(**inputs)


def _mutate(
    candidate: object,
    path: tuple[str | int, ...],
    value: object,
) -> object:
    result = deepcopy(candidate)
    cursor = result
    for part in path[:-1]:
        cursor = cast(dict[object, object] | list[object], cursor)[part]  # type: ignore[index]
    cast(dict[object, object] | list[object], cursor)[path[-1]] = value  # type: ignore[index]
    return result


def test_persistent_topology_binds_exact_post_release_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, _ = _valid_inputs(monkeypatch, tmp_path)

    snapshot = _validate(inputs)

    admission = cast(
        admission_module.TrustedTimePostEnrollmentStartActiveControllerAdmission,
        inputs["admission"],
    )
    successor = cast(TrustedTimePostEnrollmentStartSuccessor, inputs["successor"])
    assert snapshot.status == persistent.POST_ENROLLMENT_PERSISTENT_TOPOLOGY_STATUS
    assert snapshot.operation_id == admission.operation_id
    assert snapshot.active_controller_admission_sha256 == admission.admission_sha256
    assert snapshot.successor is successor
    assert snapshot.successor.anchor_sequence == 2
    assert snapshot.successor.checkpoint_reason == "epoch_rotation"
    assert snapshot.network_id == reader_fixtures.NETWORK_ID
    assert type(snapshot.source) is persistent.TrustedTimePostEnrollmentPersistentContainerSnapshot
    assert type(snapshot.supervisor) is (
        persistent.TrustedTimePostEnrollmentPersistentContainerSnapshot
    )
    assert type(snapshot.source) is not type(
        cast(Any, inputs["final_action_staged_topology"]).source
    )
    assert snapshot.source.container_id == staged_fixtures.SOURCE_CONTAINER_ID
    assert snapshot.supervisor.container_id == staged_fixtures.SUPERVISOR_CONTAINER_ID
    assert snapshot.release_marker_candidate_sha256 == _release_marker().candidate_sha256


def test_persistent_payload_is_digest_only_secret_free_and_grants_no_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, context = _valid_inputs(monkeypatch, tmp_path)

    snapshot = _validate(inputs)
    payload = snapshot.payload()
    encoded = json.dumps(payload, sort_keys=True)
    closed = set(FIRST_ENROLLMENT_AUTHORITY_FIELDS) | set(persistent._CLOSED_FIELDS)

    assert payload["contract_version"] == (
        "phase6d-post-enrollment-start-persistent-topology-snapshot-v1"
    )
    assert payload["status"] == "persistent_topology_snapshot_unqualified"
    assert all(payload[field_name] is False for field_name in closed)
    assert all(getattr(snapshot, field_name) is False for field_name in closed)
    assert "container_inspections" not in encoded
    assert "release_marker_before" not in encoded
    assert "choreography_lease" not in encoded
    assert os.fspath(context.artifact_directory / "runtime-secrets") not in encoded
    assert len(snapshot.snapshot_sha256) == 64


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        (
            "daemon_identity_after",
            LocalDockerDaemonIdentity(
                context_name="desktop-linux",
                endpoint="unix:///local/docker.sock",
                daemon_id="LOCAL:DAEMON:2",
            ),
        ),
        (
            "volume_identities_after",
            TrustedTimeVolumeIdentities(
                socket_sha256="c" * 64,
                state_sha256="b" * 64,
            ),
        ),
        ("project_container_ids_after", (staged_fixtures.SOURCE_CONTAINER_ID, "c" * 64)),
    ],
)
def test_persistent_topology_rejects_daemon_volume_or_inventory_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    field_name: str,
    replacement: object,
) -> None:
    inputs, _ = _valid_inputs(monkeypatch, tmp_path)
    inputs[field_name] = replacement

    with pytest.raises(persistent.TrustedTimePostEnrollmentPersistentTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("Id",), "d" * 64),
        (("Internal",), True),
        (("Containers", staged_fixtures.SOURCE_CONTAINER_ID, "EndpointID"), "e" * 64),
        (("Labels", "com.docker.compose.project"), "wrong-project"),
    ],
)
def test_persistent_topology_rejects_network_drift_or_unsafe_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    path: tuple[str | int, ...],
    value: object,
) -> None:
    inputs, _ = _valid_inputs(monkeypatch, tmp_path)
    inputs["project_network_after"] = _mutate(inputs["project_network_after"], path, value)

    with pytest.raises(persistent.TrustedTimePostEnrollmentPersistentTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    ("role", "path", "value"),
    [
        ("source", (0, "State", "Health", "Status"), "unhealthy"),
        ("source", (0, "State", "Running"), False),
        ("source", (0, "RestartCount"), 1),
        ("source", (0, "Image"), f"sha256:{'f' * 64}"),
        ("supervisor", (0, "State", "Running"), False),
        ("supervisor", (0, "HostConfig", "ReadonlyRootfs"), False),
        ("supervisor", (0, "Mounts", 1, "RW"), True),
    ],
)
def test_persistent_topology_rejects_runtime_health_restart_or_hardening_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    role: str,
    path: tuple[str | int, ...],
    value: object,
) -> None:
    inputs, _ = _valid_inputs(monkeypatch, tmp_path)
    container_id = (
        staged_fixtures.SOURCE_CONTAINER_ID
        if role == "source"
        else staged_fixtures.SUPERVISOR_CONTAINER_ID
    )
    inspections = cast(dict[str, object], inputs["container_inspections"])
    inspections[container_id] = _mutate(inspections[container_id], path, value)

    with pytest.raises(persistent.TrustedTimePostEnrollmentPersistentTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    ("field_name", "changes"),
    [
        ("release_marker_after", {"byte_sha256": "0" * 64}),
        ("release_marker_after", {"mode": 0o600}),
        ("release_marker_after", {"link_count": 2}),
        ("release_marker_after", {"inode": 9}),
    ],
)
def test_persistent_topology_rejects_release_marker_tamper_or_two_pass_race(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    field_name: str,
    changes: dict[str, object],
) -> None:
    inputs, _ = _valid_inputs(monkeypatch, tmp_path)
    if changes.keys() <= {"byte_sha256", "mode", "link_count"}:
        with pytest.raises(persistent.TrustedTimePostEnrollmentPersistentTopologyRejected):
            _release_marker(**changes)
        return
    inputs[field_name] = _release_marker(**changes)

    with pytest.raises(persistent.TrustedTimePostEnrollmentPersistentTopologyRejected):
        _validate(inputs)


def test_persistent_topology_rejects_release_staging_or_retirement_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, _ = _valid_inputs(monkeypatch, tmp_path)
    inputs["release_staging_absences_after"] = (
        TrustedTimePostEnrollmentAbsentPathCandidate(path="/tmp/other"),
    )

    with pytest.raises(persistent.TrustedTimePostEnrollmentPersistentTopologyRejected):
        _validate(inputs)

    second = tmp_path / "second"
    second.mkdir()
    inputs, _ = _valid_inputs(monkeypatch, second)
    retired = list(
        cast(
            tuple[TrustedTimePostEnrollmentAbsentPathCandidate, ...],
            inputs["staged_input_retirements_after"],
        )
    )
    retired[-1] = TrustedTimePostEnrollmentAbsentPathCandidate(path="/tmp/other-staged-input")
    inputs["staged_input_retirements_after"] = tuple(retired)
    with pytest.raises(persistent.TrustedTimePostEnrollmentPersistentTopologyRejected):
        _validate(inputs)


@pytest.mark.parametrize(
    ("before_changes", "after_changes"),
    [
        ({}, {"inode": 9}),
        ({"inode": 9}, {"inode": 9}),
    ],
)
def test_persistent_topology_requires_stable_original_consumed_marker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    before_changes: dict[str, object],
    after_changes: dict[str, object],
) -> None:
    inputs, _ = _valid_inputs(monkeypatch, tmp_path)
    inputs["database_secret_consumed_before"] = staged_fixtures._marker_candidate(**before_changes)
    inputs["database_secret_consumed_after"] = staged_fixtures._marker_candidate(**after_changes)

    with pytest.raises(persistent.TrustedTimePostEnrollmentPersistentTopologyRejected):
        _validate(inputs)


def test_persistent_topology_rejects_wrong_successor_predecessor(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, _ = _valid_inputs(monkeypatch, tmp_path)
    inputs["successor"] = replace(
        cast(TrustedTimePostEnrollmentStartSuccessor, inputs["successor"]),
        predecessor_anchor_sha256="a" * 64,
    )

    with pytest.raises(persistent.TrustedTimePostEnrollmentPersistentTopologyRejected):
        _validate(inputs)


def test_persistent_snapshot_constructor_rejects_nested_final_snapshot_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, _ = _valid_inputs(monkeypatch, tmp_path)
    snapshot = _validate(inputs)
    drifted_final = replace(
        cast(Any, inputs["final_action_staged_topology"]),
        database_secret_consumed_candidate_sha256="0" * 64,
    )

    with pytest.raises(persistent.TrustedTimePostEnrollmentPersistentTopologyRejected):
        replace(snapshot, _final_action_staged_topology=drifted_final)


def test_persistent_topology_rejects_forged_admission_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, _ = _valid_inputs(monkeypatch, tmp_path)
    admission = cast(
        admission_module.TrustedTimePostEnrollmentStartActiveControllerAdmission,
        inputs["admission"],
    )
    forged = object.__new__(type(admission))
    for descriptor in fields(admission):
        object.__setattr__(forged, descriptor.name, getattr(admission, descriptor.name))
    inputs["admission"] = forged

    with pytest.raises(persistent.TrustedTimePostEnrollmentPersistentTopologyRejected):
        _validate(inputs)


def test_persistent_topology_rejects_copied_final_staged_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, _ = _valid_inputs(monkeypatch, tmp_path)
    inputs["final_action_staged_topology"] = replace(
        cast(Any, inputs["final_action_staged_topology"])
    )

    with pytest.raises(persistent.TrustedTimePostEnrollmentPersistentTopologyRejected):
        _validate(inputs)


def test_persistent_validation_performs_no_host_or_release_effects(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, _ = _valid_inputs(monkeypatch, tmp_path)
    effects: list[str] = []

    def forbidden(name: str) -> Any:
        def fail(*_args: object, **_kwargs: object) -> Never:
            effects.append(name)
            raise AssertionError(f"forbidden effect: {name}")

        return fail

    monkeypatch.setattr(os, "open", forbidden("open"))
    monkeypatch.setattr(os, "read", forbidden("read"))
    monkeypatch.setattr(os, "write", forbidden("write"))
    monkeypatch.setattr(os, "stat", forbidden("stat"))
    monkeypatch.setattr(os, "lstat", forbidden("lstat"))
    monkeypatch.setattr(time, "monotonic", forbidden("monotonic"))
    monkeypatch.setattr(time, "time", forbidden("wall-clock"))
    monkeypatch.setattr(subprocess, "run", forbidden("subprocess"))
    monkeypatch.setattr(release, "write_post_enrollment_start_release", forbidden("release"))

    snapshot = _validate(inputs)

    assert snapshot.status == persistent.POST_ENROLLMENT_PERSISTENT_TOPOLOGY_STATUS
    assert effects == []


def test_persistent_network_projection_rejects_non_json_cycles(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, _ = _valid_inputs(monkeypatch, tmp_path)
    cyclic = _network()
    cyclic["cycle"] = cyclic
    inputs["project_network_before"] = cyclic

    with pytest.raises(persistent.TrustedTimePostEnrollmentPersistentTopologyRejected):
        _validate(inputs)


def test_release_marker_candidate_digest_is_canonical_and_frozen() -> None:
    marker = _release_marker()
    expected = hashlib.sha256(canonical_first_enrollment_json_bytes(marker.payload())).hexdigest()

    assert marker.candidate_sha256 == expected
    assert marker.payload()["status"] == "present"


@pytest.mark.parametrize(
    ("changes"),
    [
        {"device": 5},
        {"inode": 9},
        {"modified_time_ns": 11},
        {"changed_time_ns": 12},
    ],
)
def test_persistent_topology_requires_exact_stable_release_marker_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    changes: dict[str, object],
) -> None:
    inputs, _ = _valid_inputs(monkeypatch, tmp_path)
    marker_before = cast(
        persistent.TrustedTimePostEnrollmentReleaseMarkerCandidate,
        inputs["release_marker_before"],
    )
    marker_after = cast(
        persistent.TrustedTimePostEnrollmentReleaseMarkerCandidate,
        inputs["release_marker_after"],
    )

    assert marker_before is not marker_after
    assert marker_before == marker_after
    assert marker_before.candidate_sha256 == marker_after.candidate_sha256

    inputs["release_marker_after"] = _release_marker(**changes)
    with pytest.raises(persistent.TrustedTimePostEnrollmentPersistentTopologyRejected):
        _validate(inputs)
