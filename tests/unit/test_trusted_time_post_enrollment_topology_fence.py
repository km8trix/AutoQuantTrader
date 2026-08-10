from __future__ import annotations

import ast
import hashlib
import hmac
import inspect
import json
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path

import pytest

import scripts.trusted_time_post_enrollment_topology_fence as fence
import scripts.trusted_time_post_enrollment_topology_reader as reader
from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    TrustedTimeImmutableLaunchEvidence,
    canonical_first_enrollment_json_bytes,
)
from scripts.trusted_time_post_enrollment_staged_topology import (
    POST_ENROLLMENT_STAGED_TOPOLOGY_CONTRACT_VERSION,
    TrustedTimePostEnrollmentStagedContainerSnapshot,
    TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot,
)
from scripts.trusted_time_post_enrollment_topology import (
    POST_ENROLLMENT_CREATED_TOPOLOGY_CONTRACT_VERSION,
    TrustedTimePostEnrollmentCreatedContainerSnapshot,
    TrustedTimePostEnrollmentCreatedTopologySnapshot,
)

SESSION_SHA256 = "a" * 64
OTHER_SESSION_SHA256 = "b" * 64
SOURCE_CONTAINER_ID = "1" * 64
SUPERVISOR_CONTAINER_ID = "2" * 64
SOURCE_IMAGE_ID = "sha256:" + "3" * 64
SUPERVISOR_IMAGE_ID = "sha256:" + "4" * 64
OPERATION_ID = "223e4567-e89b-42d3-a456-426614174001"


def _test_observation_seal(payload: object) -> bytes:
    return hashlib.sha256(canonical_first_enrollment_json_bytes(payload)).digest()


@pytest.fixture(autouse=True)
def _install_test_observation_validator(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        reader,
        "_valid_observation_seal",
        lambda candidate, payload: (
            type(candidate) is bytes
            and hmac.compare_digest(candidate, _test_observation_seal(payload))
        ),
    )


def _launch() -> TrustedTimeImmutableLaunchEvidence:
    return TrustedTimeImmutableLaunchEvidence(
        git_revision="c" * 40,
        image_admission_sha256="d" * 64,
        source_image_id=SOURCE_IMAGE_ID,
        supervisor_image_id=SUPERVISOR_IMAGE_ID,
    )


def _created_snapshot() -> TrustedTimePostEnrollmentCreatedTopologySnapshot:
    return TrustedTimePostEnrollmentCreatedTopologySnapshot(
        operation_id=OPERATION_ID,
        approval_sha256="5" * 64,
        review_projection_sha256="6" * 64,
        confirmed_enrollment_evidence_sha256="7" * 64,
        approved_launch=_launch(),
        daemon_context_name="<DOCKER_HOST>",
        daemon_endpoint="unix:///trusted/docker.sock",
        daemon_id="LOCAL:DAEMON:1",
        socket_volume_sha256="8" * 64,
        state_volume_sha256="9" * 64,
        source=TrustedTimePostEnrollmentCreatedContainerSnapshot(
            service="chrony-nts",
            container_id=SOURCE_CONTAINER_ID,
            image_id=SOURCE_IMAGE_ID,
            inspection_projection_sha256="a" * 64,
            image_configuration_projection_sha256="b" * 64,
        ),
        supervisor=TrustedTimePostEnrollmentCreatedContainerSnapshot(
            service="trusted-time-supervisor",
            container_id=SUPERVISOR_CONTAINER_ID,
            image_id=SUPERVISOR_IMAGE_ID,
            inspection_projection_sha256="c" * 64,
            image_configuration_projection_sha256="d" * 64,
        ),
        source_start_argv=("docker", "container", "start", SOURCE_CONTAINER_ID),
        supervisor_start_argv=("docker", "container", "start", SUPERVISOR_CONTAINER_ID),
    )


def _staged_snapshot(
    created: TrustedTimePostEnrollmentCreatedTopologySnapshot,
    *,
    operation_id: str = OPERATION_ID,
    consumed_sha256: str = "e" * 64,
) -> TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot:
    return TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot(
        operation_id=operation_id,
        approval_sha256=created.approval_sha256,
        review_projection_sha256=created.review_projection_sha256,
        confirmed_enrollment_evidence_sha256=(created.confirmed_enrollment_evidence_sha256),
        approved_launch=created.approved_launch,
        created_topology_snapshot_sha256=created.snapshot_sha256,
        daemon_context_name=created.daemon_context_name,
        daemon_endpoint=created.daemon_endpoint,
        daemon_id=created.daemon_id,
        socket_volume_sha256=created.socket_volume_sha256,
        state_volume_sha256=created.state_volume_sha256,
        source=TrustedTimePostEnrollmentStagedContainerSnapshot(
            service=created.source.service,
            container_id=created.source.container_id,
            image_id=created.source.image_id,
            stable_inspection_projection_sha256="f" * 64,
            running_state_projection_sha256="0" * 64,
            image_configuration_projection_sha256=(
                created.source.image_configuration_projection_sha256
            ),
        ),
        supervisor=TrustedTimePostEnrollmentStagedContainerSnapshot(
            service=created.supervisor.service,
            container_id=created.supervisor.container_id,
            image_id=created.supervisor.image_id,
            stable_inspection_projection_sha256="1" * 64,
            running_state_projection_sha256="2" * 64,
            image_configuration_projection_sha256=(
                created.supervisor.image_configuration_projection_sha256
            ),
        ),
        database_secret_consumed_candidate_sha256=consumed_sha256,
        release_paths_absence_candidate_sha256="3" * 64,
        staged_input_retirement_candidate_sha256="4" * 64,
    )


def _created_observation(
    snapshot: TrustedTimePostEnrollmentCreatedTopologySnapshot,
    *,
    session_sha256: str = SESSION_SHA256,
    transcript_sha256: str = "5" * 64,
) -> reader.TrustedTimePostEnrollmentCreatedTopologyObservation:
    payload = reader._observation_payload(
        kind="created",
        status=reader.POST_ENROLLMENT_CREATED_TOPOLOGY_OBSERVATION_STATUS,
        session_sha256=session_sha256,
        transcript_sha256=transcript_sha256,
        observation_count=14,
        snapshot_contract_version=POST_ENROLLMENT_CREATED_TOPOLOGY_CONTRACT_VERSION,
        snapshot_sha256=snapshot.snapshot_sha256,
    )
    return reader.TrustedTimePostEnrollmentCreatedTopologyObservation(
        session_sha256=session_sha256,
        transcript_sha256=transcript_sha256,
        observation_count=14,
        snapshot=snapshot,
        _seal=_test_observation_seal(payload),
    )


def _staged_observation(
    snapshot: TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot,
    created: reader.TrustedTimePostEnrollmentCreatedTopologyObservation,
    *,
    ordinal: int,
    predecessor_sha256: str,
    session_sha256: str = SESSION_SHA256,
    transcript_sha256: str | None = None,
) -> reader.TrustedTimePostEnrollmentStagedTopologyObservation:
    transcript = transcript_sha256 or ("6" if ordinal == 1 else "7") * 64
    payload = reader._observation_payload(
        kind="staged_unreleased",
        status=reader.POST_ENROLLMENT_STAGED_TOPOLOGY_OBSERVATION_STATUS,
        session_sha256=session_sha256,
        transcript_sha256=transcript,
        observation_count=16,
        snapshot_contract_version=POST_ENROLLMENT_STAGED_TOPOLOGY_CONTRACT_VERSION,
        snapshot_sha256=snapshot.snapshot_sha256,
        created_observation_sha256=created.observation_sha256,
        staged_observation_ordinal=ordinal,
        predecessor_observation_sha256=predecessor_sha256,
    )
    return reader.TrustedTimePostEnrollmentStagedTopologyObservation(
        session_sha256=session_sha256,
        transcript_sha256=transcript,
        observation_count=16,
        created_observation_sha256=created.observation_sha256,
        staged_observation_ordinal=ordinal,
        predecessor_observation_sha256=predecessor_sha256,
        snapshot=snapshot,
        _seal=_test_observation_seal(payload),
    )


def _chain() -> tuple[
    reader.TrustedTimePostEnrollmentCreatedTopologyObservation,
    reader.TrustedTimePostEnrollmentStagedTopologyObservation,
    reader.TrustedTimePostEnrollmentStagedTopologyObservation,
]:
    created_snapshot = _created_snapshot()
    staged_snapshot = _staged_snapshot(created_snapshot)
    created = _created_observation(created_snapshot)
    staged_one = _staged_observation(
        staged_snapshot,
        created,
        ordinal=1,
        predecessor_sha256=created.observation_sha256,
    )
    staged_two = _staged_observation(
        staged_snapshot,
        created,
        ordinal=2,
        predecessor_sha256=staged_one.observation_sha256,
    )
    return created, staged_one, staged_two


def _pre_claim(
    created: reader.TrustedTimePostEnrollmentCreatedTopologyObservation,
    staged_one: reader.TrustedTimePostEnrollmentStagedTopologyObservation,
) -> fence.TrustedTimePostEnrollmentStartPreClaimTopologyFence:
    return fence.bind_post_enrollment_start_pre_claim_topology_fence(
        created,
        staged_one,
    )


def test_binds_exact_two_stage_same_session_chain() -> None:
    created, staged_one, staged_two = _chain()

    pre_claim = _pre_claim(created, staged_one)
    pre_release = fence.bind_post_enrollment_start_pre_release_topology_fence(
        pre_claim,
        staged_two,
    )

    assert pre_claim.status == fence.POST_ENROLLMENT_START_PRE_CLAIM_TOPOLOGY_FENCE_STATUS
    assert pre_claim.session_sha256 == created.session_sha256
    assert pre_claim.created_observation_sha256 == created.observation_sha256
    assert pre_claim.created_snapshot_sha256 == created.snapshot.snapshot_sha256
    assert pre_claim.staged_observation_ordinal == 1
    assert pre_claim.predecessor_observation_sha256 == created.observation_sha256
    assert pre_claim.staged_observation_sha256 == staged_one.observation_sha256
    assert pre_claim.staged_snapshot_sha256 == staged_one.snapshot.snapshot_sha256
    assert pre_claim.staged_stable_topology_sha256 == staged_one.snapshot.stable_topology_sha256
    assert pre_release.status == fence.POST_ENROLLMENT_START_PRE_RELEASE_TOPOLOGY_FENCE_STATUS
    assert pre_release.pre_claim_fence_sha256 == pre_claim.fence_sha256
    assert pre_release.pre_claim_staged_observation_ordinal == 1
    assert pre_release.pre_release_staged_observation_ordinal == 2
    assert pre_release.pre_release_predecessor_observation_sha256 == staged_one.observation_sha256
    assert pre_release.pre_release_staged_observation_sha256 == staged_two.observation_sha256
    assert pre_release.staged_snapshot_sha256 == staged_two.snapshot.snapshot_sha256
    assert pre_claim.observation_provenance_authenticated is True
    assert pre_claim.same_session_observation_chain_authenticated is True
    assert pre_claim.stable_topology_match_authenticated is False
    assert pre_release.observation_provenance_authenticated is True
    assert pre_release.same_session_observation_chain_authenticated is True
    assert pre_release.stable_topology_match_authenticated is True


def test_rejects_tampered_or_forged_observation_hmac_seals() -> None:
    created, staged_one, staged_two = _chain()
    object.__setattr__(created, "_seal", b"forged")
    with pytest.raises(fence.TrustedTimePostEnrollmentStartTopologyFenceRejected):
        _pre_claim(created, staged_one)

    created, staged_one, staged_two = _chain()
    pre_claim = _pre_claim(created, staged_one)
    object.__setattr__(staged_two, "transcript_sha256", "8" * 64)
    with pytest.raises(fence.TrustedTimePostEnrollmentStartTopologyFenceRejected):
        fence.bind_post_enrollment_start_pre_release_topology_fence(
            pre_claim,
            staged_two,
        )


def test_revalidates_privately_retained_envelopes_after_fence_creation() -> None:
    created, staged_one, staged_two = _chain()
    pre_claim = _pre_claim(created, staged_one)
    pre_release = fence.bind_post_enrollment_start_pre_release_topology_fence(
        pre_claim,
        staged_two,
    )

    object.__setattr__(staged_one, "transcript_sha256", "8" * 64)

    with pytest.raises(fence.TrustedTimePostEnrollmentStartTopologyFenceRejected):
        pre_claim.__post_init__()
    with pytest.raises(fence.TrustedTimePostEnrollmentStartTopologyFenceRejected):
        pre_release.__post_init__()
    with pytest.raises(fence.TrustedTimePostEnrollmentStartTopologyFenceRejected):
        replace(pre_release, _pre_claim_fence=object())


def test_rejects_nonexact_types_and_forged_preclaim_projection() -> None:
    created, staged_one, staged_two = _chain()
    with pytest.raises(fence.TrustedTimePostEnrollmentStartTopologyFenceRejected):
        fence.bind_post_enrollment_start_pre_claim_topology_fence(
            object(),  # type: ignore[arg-type]
            staged_one,
        )
    with pytest.raises(fence.TrustedTimePostEnrollmentStartTopologyFenceRejected):
        fence.TrustedTimePostEnrollmentStartPreClaimTopologyFence(
            session_sha256=created.session_sha256,
            created_observation_sha256=created.observation_sha256,
            created_snapshot_sha256=created.snapshot.snapshot_sha256,
            staged_observation_ordinal=1,
            predecessor_observation_sha256=created.observation_sha256,
            staged_observation_sha256=staged_one.observation_sha256,
            staged_snapshot_sha256=staged_one.snapshot.snapshot_sha256,
            staged_stable_topology_sha256=(staged_one.snapshot.stable_topology_sha256),
            _created_observation=object(),
            _staged_observation=staged_one,
        )
    pre_claim = _pre_claim(created, staged_one)
    object.__setattr__(pre_claim, "staged_observation_sha256", "f" * 64)
    with pytest.raises(fence.TrustedTimePostEnrollmentStartTopologyFenceRejected):
        fence.bind_post_enrollment_start_pre_release_topology_fence(
            pre_claim,
            staged_two,
        )
    with pytest.raises(fence.TrustedTimePostEnrollmentStartTopologyFenceRejected):
        fence.bind_post_enrollment_start_pre_release_topology_fence(
            object(),  # type: ignore[arg-type]
            staged_two,
        )


def test_rejects_cross_session_chain_and_wrong_ordinal() -> None:
    created, staged_one, staged_two = _chain()
    cross_session = _staged_observation(
        staged_one.snapshot,
        created,
        ordinal=1,
        predecessor_sha256=created.observation_sha256,
        session_sha256=OTHER_SESSION_SHA256,
    )
    with pytest.raises(fence.TrustedTimePostEnrollmentStartTopologyFenceRejected):
        _pre_claim(created, cross_session)
    with pytest.raises(fence.TrustedTimePostEnrollmentStartTopologyFenceRejected):
        _pre_claim(created, staged_two)

    pre_claim = _pre_claim(created, staged_one)
    with pytest.raises(fence.TrustedTimePostEnrollmentStartTopologyFenceRejected):
        fence.bind_post_enrollment_start_pre_release_topology_fence(
            pre_claim,
            staged_one,
        )
    cross_session_two = _staged_observation(
        staged_two.snapshot,
        created,
        ordinal=2,
        predecessor_sha256=staged_one.observation_sha256,
        session_sha256=OTHER_SESSION_SHA256,
    )
    with pytest.raises(fence.TrustedTimePostEnrollmentStartTopologyFenceRejected):
        fence.bind_post_enrollment_start_pre_release_topology_fence(
            pre_claim,
            cross_session_two,
        )


def test_rejects_predecessor_and_created_observation_chain_substitution() -> None:
    created, staged_one, _ = _chain()
    wrong_predecessor = _staged_observation(
        staged_one.snapshot,
        created,
        ordinal=1,
        predecessor_sha256="f" * 64,
    )
    with pytest.raises(fence.TrustedTimePostEnrollmentStartTopologyFenceRejected):
        _pre_claim(created, wrong_predecessor)

    pre_claim = _pre_claim(created, staged_one)
    wrong_second_predecessor = _staged_observation(
        staged_one.snapshot,
        created,
        ordinal=2,
        predecessor_sha256=created.observation_sha256,
    )
    with pytest.raises(fence.TrustedTimePostEnrollmentStartTopologyFenceRejected):
        fence.bind_post_enrollment_start_pre_release_topology_fence(
            pre_claim,
            wrong_second_predecessor,
        )

    other_created = _created_observation(
        _created_snapshot(),
        session_sha256=SESSION_SHA256,
        transcript_sha256="8" * 64,
    )
    substituted = _staged_observation(
        staged_one.snapshot,
        other_created,
        ordinal=2,
        predecessor_sha256=staged_one.observation_sha256,
    )
    with pytest.raises(fence.TrustedTimePostEnrollmentStartTopologyFenceRejected):
        fence.bind_post_enrollment_start_pre_release_topology_fence(
            pre_claim,
            substituted,
        )


@pytest.mark.parametrize(
    ("operation_id", "consumed_sha256"),
    [
        ("323e4567-e89b-42d3-a456-426614174001", "e" * 64),
        (OPERATION_ID, "f" * 64),
    ],
)
def test_rejects_cross_snapshot_identity_or_stable_topology_drift(
    operation_id: str,
    consumed_sha256: str,
) -> None:
    created_snapshot = _created_snapshot()
    created = _created_observation(created_snapshot)
    baseline_snapshot = _staged_snapshot(created_snapshot)
    staged_one = _staged_observation(
        baseline_snapshot,
        created,
        ordinal=1,
        predecessor_sha256=created.observation_sha256,
    )
    drifted_snapshot = _staged_snapshot(
        created_snapshot,
        operation_id=operation_id,
        consumed_sha256=consumed_sha256,
    )

    if operation_id != OPERATION_ID:
        drifted_one = _staged_observation(
            drifted_snapshot,
            created,
            ordinal=1,
            predecessor_sha256=created.observation_sha256,
        )
        with pytest.raises(fence.TrustedTimePostEnrollmentStartTopologyFenceRejected):
            _pre_claim(created, drifted_one)
        return

    pre_claim = _pre_claim(created, staged_one)
    drifted_two = _staged_observation(
        drifted_snapshot,
        created,
        ordinal=2,
        predecessor_sha256=staged_one.observation_sha256,
    )
    with pytest.raises(fence.TrustedTimePostEnrollmentStartTopologyFenceRejected):
        fence.bind_post_enrollment_start_pre_release_topology_fence(
            pre_claim,
            drifted_two,
        )


def test_outputs_are_frozen_digest_projections_without_raw_topology_in_payload_or_repr() -> None:
    created, staged_one, staged_two = _chain()
    pre_claim = _pre_claim(created, staged_one)
    pre_release = fence.bind_post_enrollment_start_pre_release_topology_fence(
        pre_claim,
        staged_two,
    )

    with pytest.raises(FrozenInstanceError):
        pre_claim.session_sha256 = "0" * 64  # type: ignore[misc]
    with pytest.raises(fence.TrustedTimePostEnrollmentStartTopologyFenceRejected):
        replace(pre_release, staged_snapshot_sha256="0" * 64)

    for result in (pre_claim, pre_release):
        payload = result.payload()
        encoded = json.dumps(payload, sort_keys=True)
        assert "unix:///trusted/docker.sock" not in encoded
        assert SOURCE_IMAGE_ID not in encoded
        assert SUPERVISOR_IMAGE_ID not in encoded
        assert "_created_observation" not in payload
        assert "_staged_observation" not in payload
        assert "_pre_claim_fence" not in payload
        assert "_created_observation=" not in repr(result)
        assert "_staged_observation=" not in repr(result)
        assert "_pre_claim_fence=" not in repr(result)
        assert not hasattr(result, "snapshot")
        assert not hasattr(result, "operation_id")
        public_field_names = {item.name for item in fields(result) if not item.name.startswith("_")}
        assert all(
            name.endswith("_sha256") or name.endswith("_ordinal") for name in public_field_names
        )


def test_replay_is_deterministic_but_never_authenticates_chronology_or_freshness() -> None:
    created, staged_one, staged_two = _chain()
    pre_claim_one = _pre_claim(created, staged_one)
    pre_claim_two = _pre_claim(created, staged_one)
    pre_release_one = fence.bind_post_enrollment_start_pre_release_topology_fence(
        pre_claim_one,
        staged_two,
    )
    pre_release_two = fence.bind_post_enrollment_start_pre_release_topology_fence(
        pre_claim_two,
        staged_two,
    )

    assert pre_claim_one == pre_claim_two
    assert pre_claim_one.fence_sha256 == pre_claim_two.fence_sha256
    assert pre_release_one == pre_release_two
    assert pre_release_one.fence_sha256 == pre_release_two.fence_sha256
    for result in (pre_claim_one, pre_release_one):
        assert result.claim_chronology_authenticated is False
        assert result.freshness_authenticated is False
        assert result.current_lock_session_authenticated is False
        assert result.current_daemon_session_authenticated is False
        assert result.claim_retention_authorized is False
        assert result.release_authorized is False


def test_every_action_and_operational_authority_remains_false() -> None:
    created, staged_one, staged_two = _chain()
    results = (
        _pre_claim(created, staged_one),
        fence.bind_post_enrollment_start_pre_release_topology_fence(
            _pre_claim(created, staged_one),
            staged_two,
        ),
    )
    false_fields = set(FIRST_ENROLLMENT_AUTHORITY_FIELDS) | {
        "authority_granted",
        "claim_chronology_authenticated",
        "claim_retention_authorized",
        "container_identity_authenticated",
        "created_topology_authenticated",
        "current_daemon_session_authenticated",
        "current_lock_session_authenticated",
        "daemon_identity_authenticated",
        "database_secret_consumption_authenticated",
        "database_secret_disclosed",
        "freshness_authenticated",
        "inventory_authenticated",
        "persistent_start_authorized",
        "release_absence_authenticated",
        "release_authorized",
        "sequence_2_authorized",
        "shutdown_authorized",
        "source_start_authenticated",
        "source_start_authorized",
        "staged_input_retirement_authenticated",
        "start_order_authenticated",
        "supervisor_start_authenticated",
        "supervisor_start_authorized",
        "topology_authenticated",
        "topology_mutation_authorized",
        "volume_identity_authenticated",
    }
    for result in results:
        payload = result.payload()
        assert all(payload[field_name] is False for field_name in false_fields)
        assert all(getattr(result, field_name) is False for field_name in false_fields)


def test_module_is_pure_and_has_no_action_or_runtime_surface() -> None:
    source = inspect.getsource(fence)
    tree = ast.parse(source)
    imported_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    direct_imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    called_names = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not imported_modules.intersection(
        {
            "apps.trusted_time_supervisor.post_enrollment_release",
            "scripts.start_trusted_time_supervisor",
            "scripts.trusted_time_post_enrollment_staging",
            "scripts.trusted_time_post_enrollment_start",
        }
    )
    assert not direct_imports.intersection(
        {"asyncio", "datetime", "os", "socket", "sqlite3", "subprocess", "time"}
    )
    assert not called_names.intersection({"open", "run", "sleep"})
    assert not hasattr(fence, "main")
    assert not hasattr(fence, "run")
    assert not hasattr(fence, "start")
    assert not hasattr(fence, "release")
    assert not hasattr(fence, "claim")
    assert not hasattr(fence, "handoff")
    assert Path(fence.__file__).name == "trusted_time_post_enrollment_topology_fence.py"


def test_public_surface_is_exact() -> None:
    assert set(fence.__all__) == {
        "POST_ENROLLMENT_START_PRE_CLAIM_TOPOLOGY_FENCE_CONTRACT_VERSION",
        "POST_ENROLLMENT_START_PRE_CLAIM_TOPOLOGY_FENCE_STATUS",
        "POST_ENROLLMENT_START_PRE_RELEASE_TOPOLOGY_FENCE_CONTRACT_VERSION",
        "POST_ENROLLMENT_START_PRE_RELEASE_TOPOLOGY_FENCE_STATUS",
        "TrustedTimePostEnrollmentStartPreClaimTopologyFence",
        "TrustedTimePostEnrollmentStartPreReleaseTopologyFence",
        "TrustedTimePostEnrollmentStartTopologyFenceRejected",
        "bind_post_enrollment_start_pre_claim_topology_fence",
        "bind_post_enrollment_start_pre_release_topology_fence",
    }
