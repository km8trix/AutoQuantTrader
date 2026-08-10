from __future__ import annotations

import hashlib
import hmac
import os
import pickle
from collections.abc import Mapping
from copy import copy, deepcopy
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest

import scripts.trusted_time_post_enrollment_claimed_fence as claimed
import scripts.trusted_time_post_enrollment_staging as staging
import scripts.trusted_time_post_enrollment_topology_reader as reader
from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_start import (
    TrustedTimePostEnrollmentStartClaim,
)
from scripts.trusted_time_post_enrollment_staged_topology import (
    POST_ENROLLMENT_STAGED_TOPOLOGY_CONTRACT_VERSION,
)
from scripts.trusted_time_post_enrollment_staging import (
    TrustedTimePostEnrollmentStartStagingHandoff,
)
from scripts.trusted_time_post_enrollment_start import (
    POST_ENROLLMENT_START_CLAIM_FILE_NAME,
    retain_post_enrollment_start_claim,
)
from scripts.trusted_time_post_enrollment_topology import (
    POST_ENROLLMENT_CREATED_TOPOLOGY_CONTRACT_VERSION,
)
from scripts.trusted_time_post_enrollment_topology_fence import (
    bind_post_enrollment_start_pre_claim_topology_fence,
    bind_post_enrollment_start_pre_release_topology_fence,
)
from tests.unit import test_trusted_time_post_enrollment_staging as staging_fixtures
from tests.unit import test_trusted_time_post_enrollment_topology_reader as reader_fixtures


def _authenticated_seal(payload: Mapping[str, object]) -> bytes:
    return hashlib.sha256(canonical_first_enrollment_json_bytes(payload)).digest()


@pytest.fixture(autouse=True)
def _install_test_observation_validators(monkeypatch: pytest.MonkeyPatch) -> None:
    def valid(candidate: object, payload: Mapping[str, object]) -> bool:
        return type(candidate) is bytes and hmac.compare_digest(
            candidate,
            _authenticated_seal(payload),
        )

    monkeypatch.setattr(reader, "_valid_observation_seal", valid)
    monkeypatch.setattr(
        reader,
        "_valid_cursor_seal",
        lambda candidate, payload, _result: valid(candidate, payload),
    )


def _created_observation(
    snapshot: Any,
    *,
    session_sha256: str = "a" * 64,
    transcript_sha256: str = "1" * 64,
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
        _seal=_authenticated_seal(payload),
    )


def _staged_observation(
    snapshot: Any,
    created_observation: reader.TrustedTimePostEnrollmentCreatedTopologyObservation,
    *,
    ordinal: int,
    predecessor_sha256: str,
    transcript_sha256: str,
) -> reader.TrustedTimePostEnrollmentStagedTopologyObservation:
    payload = reader._observation_payload(
        kind="staged_unreleased",
        status=reader.POST_ENROLLMENT_STAGED_TOPOLOGY_OBSERVATION_STATUS,
        session_sha256=created_observation.session_sha256,
        transcript_sha256=transcript_sha256,
        observation_count=16,
        snapshot_contract_version=POST_ENROLLMENT_STAGED_TOPOLOGY_CONTRACT_VERSION,
        snapshot_sha256=snapshot.snapshot_sha256,
        created_observation_sha256=created_observation.observation_sha256,
        staged_observation_ordinal=ordinal,
        predecessor_observation_sha256=predecessor_sha256,
    )
    return reader.TrustedTimePostEnrollmentStagedTopologyObservation(
        session_sha256=created_observation.session_sha256,
        transcript_sha256=transcript_sha256,
        observation_count=16,
        created_observation_sha256=created_observation.observation_sha256,
        staged_observation_ordinal=ordinal,
        predecessor_observation_sha256=predecessor_sha256,
        snapshot=snapshot,
        _seal=_authenticated_seal(payload),
    )


def _cursor(
    *,
    ordinal: int,
    staged_count: int,
    created_observation_sha256: str,
    last_observation_sha256: str,
    staged_snapshot_sha256: str,
    session_sha256: str = "a" * 64,
) -> reader.TrustedTimePostEnrollmentTopologyObservationCursor:
    transcript_sha256 = str(ordinal + 4) * 64
    payload = reader._cursor_payload(
        session_sha256=session_sha256,
        transcript_sha256=transcript_sha256,
        cursor_ordinal=ordinal,
        staged_observation_count=staged_count,
        created_observation_sha256=created_observation_sha256,
        last_observation_sha256=last_observation_sha256,
        first_staged_snapshot_sha256=staged_snapshot_sha256,
    )
    return reader.TrustedTimePostEnrollmentTopologyObservationCursor(
        session_sha256=session_sha256,
        transcript_sha256=transcript_sha256,
        cursor_ordinal=ordinal,
        staged_observation_count=staged_count,
        created_observation_sha256=created_observation_sha256,
        last_observation_sha256=last_observation_sha256,
        first_staged_snapshot_sha256=staged_snapshot_sha256,
        _seal=_authenticated_seal(payload),
    )


def _staged_paths(artifact_directory: Path) -> tuple[Path, Path, Path, Path]:
    root = artifact_directory / "runtime-secrets"
    return (
        root / f".database-secret-{'0' * 32}" / "database-url",
        root / f".head-anchor-authority-{'1' * 32}" / "head-anchor-authority.json",
        root / f".head-anchor-auth-{'2' * 32}" / "head-anchor-auth",
        root / f".head-anchor-signing-key-{'3' * 32}" / "head-anchor-signing-key",
    )


def _staged_retirement_sha256(paths: tuple[Path, Path, Path, Path]) -> str:
    payload = [{"path": str(path), "status": "absent"} for path in sorted(paths, key=str)]
    return hashlib.sha256(canonical_first_enrollment_json_bytes(payload)).hexdigest()


@dataclass
class _Context:
    approval: Any
    approved_launch: Any
    created: reader.TrustedTimePostEnrollmentCreatedTopologyObservation
    staged_one: reader.TrustedTimePostEnrollmentStagedTopologyObservation
    staged_two: reader.TrustedTimePostEnrollmentStagedTopologyObservation
    pre_claim: Any
    cursors: list[reader.TrustedTimePostEnrollmentTopologyObservationCursor]
    topology_issuer: reader.TrustedTimePostEnrollmentTopologyObservationIssuer
    ignored_root: Path
    artifact_directory: Path
    events: list[str]

    def handoff(self) -> TrustedTimePostEnrollmentStartStagingHandoff:
        claim = TrustedTimePostEnrollmentStartClaim(
            approval=self.approval,
            reauthentication=staging_fixtures._reauthentication(self.approval),
        )
        retained = retain_post_enrollment_start_claim(
            claim,
            artifact_directory=self.artifact_directory,
            ignored_root=self.ignored_root,
        )
        return TrustedTimePostEnrollmentStartStagingHandoff(
            approval=self.approval,
            approval_sha256=self.approval.approval_sha256,
            confirmed_enrollment=self.approval.confirmed_enrollment,
            reauthentication=claim.reauthentication,
            retained_claim=retained,
            artifact_directory=self.artifact_directory,
            ignored_root=self.ignored_root,
            supervisor_container_id=reader_fixtures.SUPERVISOR_CONTAINER_ID,
            release_argv=staging.post_enrollment_start_release_argv(
                reader_fixtures.SUPERVISOR_CONTAINER_ID
            ),
        )

    def kwargs(self) -> dict[str, object]:
        staged_paths = _staged_paths(self.artifact_directory)
        return {
            "approval": self.approval,
            "expected_approval_sha256": self.approval.approval_sha256,
            "approved_launch": self.approved_launch,
            "created_observation": self.created,
            "pre_claim_fence": self.pre_claim,
            "topology_issuer": self.topology_issuer,
            "supervisor_container_id": reader_fixtures.SUPERVISOR_CONTAINER_ID,
            "reauthentication_issuer": staging_fixtures._Issuer(
                staging_fixtures._observed_postcondition()
            ),
            "expected_database_secret_file": staged_paths[0],
            "expected_head_anchor_authority_file": staged_paths[1],
            "expected_head_anchor_auth_secret_file": staged_paths[2],
            "expected_head_anchor_signing_key_secret_file": staged_paths[3],
            "artifact_directory": self.artifact_directory,
            "ignored_root": self.ignored_root,
        }


def _context(tmp_path: Path) -> _Context:
    ignored_root = tmp_path / "artifacts"
    ignored_root.mkdir(mode=0o700)
    artifact_directory = ignored_root / "trusted-time"
    artifact_directory.mkdir(mode=0o700)
    (artifact_directory / "runtime-secrets").mkdir(mode=0o700)
    approval = reader_fixtures._approval()
    approved_launch = reader_fixtures._approved_launch()
    created_snapshot = reader_fixtures._created_snapshot("unix:///trusted/docker.sock")
    staged_snapshot = reader_fixtures._staged_snapshot(
        "unix:///trusted/docker.sock",
        created_snapshot,
    )
    staged_snapshot = replace(
        staged_snapshot,
        staged_input_retirement_candidate_sha256=_staged_retirement_sha256(
            _staged_paths(artifact_directory)
        ),
        source=replace(
            staged_snapshot.source,
            image_configuration_projection_sha256=(
                created_snapshot.source.image_configuration_projection_sha256
            ),
        ),
        supervisor=replace(
            staged_snapshot.supervisor,
            image_configuration_projection_sha256=(
                created_snapshot.supervisor.image_configuration_projection_sha256
            ),
        ),
    )
    created = _created_observation(created_snapshot)
    staged_one = _staged_observation(
        staged_snapshot,
        created,
        ordinal=1,
        predecessor_sha256=created.observation_sha256,
        transcript_sha256="2" * 64,
    )
    staged_two = _staged_observation(
        staged_snapshot,
        created,
        ordinal=2,
        predecessor_sha256=staged_one.observation_sha256,
        transcript_sha256="3" * 64,
    )
    pre_claim = bind_post_enrollment_start_pre_claim_topology_fence(
        created,
        staged_one,
    )
    cursors = [
        _cursor(
            ordinal=1,
            staged_count=1,
            created_observation_sha256=created.observation_sha256,
            last_observation_sha256=staged_one.observation_sha256,
            staged_snapshot_sha256=staged_snapshot.snapshot_sha256,
        ),
        _cursor(
            ordinal=2,
            staged_count=1,
            created_observation_sha256=created.observation_sha256,
            last_observation_sha256=staged_one.observation_sha256,
            staged_snapshot_sha256=staged_snapshot.snapshot_sha256,
        ),
        _cursor(
            ordinal=3,
            staged_count=2,
            created_observation_sha256=created.observation_sha256,
            last_observation_sha256=staged_two.observation_sha256,
            staged_snapshot_sha256=staged_snapshot.snapshot_sha256,
        ),
    ]
    return _Context(
        approval=approval,
        approved_launch=approved_launch,
        created=created,
        staged_one=staged_one,
        staged_two=staged_two,
        pre_claim=pre_claim,
        cursors=cursors,
        topology_issuer=object.__new__(reader.TrustedTimePostEnrollmentTopologyObservationIssuer),
        ignored_root=ignored_root,
        artifact_directory=artifact_directory,
        events=[],
    )


def _install_success(
    monkeypatch: pytest.MonkeyPatch,
    context: _Context,
    *,
    cursor_values: list[reader.TrustedTimePostEnrollmentTopologyObservationCursor] | None = None,
    staged_error: BaseException | None = None,
    bind_error: BaseException | None = None,
    revalidations: list[bool] | None = None,
) -> None:
    cursors = iter(cursor_values or context.cursors)
    validations = iter(revalidations or [True, True])

    def issue_cursor(_: object) -> reader.TrustedTimePostEnrollmentTopologyObservationCursor:
        value = next(cursors)
        context.events.append(f"cursor:{value.cursor_ordinal}:{value.staged_observation_count}")
        return value

    def prepare(**_: object) -> TrustedTimePostEnrollmentStartStagingHandoff:
        context.events.append("prepare_claim")
        return context.handoff()

    def revalidate(*_: object, **__: object) -> bool:
        context.events.append("revalidate_claim")
        return next(validations)

    def issue_staged(
        _: object, **__: object
    ) -> reader.TrustedTimePostEnrollmentStagedTopologyObservation:
        context.events.append("issue_ordinal_2")
        if staged_error is not None:
            raise staged_error
        return context.staged_two

    original_bind = bind_post_enrollment_start_pre_release_topology_fence

    def bind(*args: object) -> Any:
        context.events.append("bind_pre_release")
        if bind_error is not None:
            raise bind_error
        return original_bind(*args)  # type: ignore[arg-type]

    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "issue_observation_cursor",
        issue_cursor,
    )
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "issue_staged_unreleased_snapshot",
        issue_staged,
    )
    monkeypatch.setattr(
        claimed,
        "prepare_post_enrollment_start_release_under_lock",
        prepare,
    )
    monkeypatch.setattr(
        claimed,
        "revalidate_retained_post_enrollment_start_claim",
        revalidate,
    )
    monkeypatch.setattr(
        claimed,
        "bind_post_enrollment_start_pre_release_topology_fence",
        bind,
    )


def test_success_binds_exact_three_cursor_claim_chronology(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    _install_success(monkeypatch, context)

    result = claimed.prepare_post_enrollment_start_claimed_pre_release_fence(
        **context.kwargs()  # type: ignore[arg-type]
    )

    assert result.status == claimed.POST_ENROLLMENT_START_CLAIMED_PRE_RELEASE_TOPOLOGY_FENCE_STATUS
    assert result.pre_claim_cursor_sha256 == context.cursors[0].cursor_sha256
    assert result.post_claim_cursor_sha256 == context.cursors[1].cursor_sha256
    assert result.final_cursor_sha256 == context.cursors[2].cursor_sha256
    assert result.pre_release_staged_observation_sha256 == context.staged_two.observation_sha256
    assert context.events == [
        "cursor:1:1",
        "prepare_claim",
        "revalidate_claim",
        "cursor:2:1",
        "issue_ordinal_2",
        "bind_pre_release",
        "cursor:3:2",
        "revalidate_claim",
    ]
    true_fields = {
        "claim_chronology_authenticated",
        "claim_retention_authenticated",
        "final_cursor_session_authenticated",
        "observation_provenance_authenticated",
        "ordinal_2_after_claim_authenticated",
        "same_session_observation_chain_authenticated",
        "stable_topology_match_authenticated",
    }
    assert all(result.payload()[name] is True for name in true_fields)
    false_fields = set(FIRST_ENROLLMENT_AUTHORITY_FIELDS) | {
        "authority_granted",
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
    assert all(result.payload()[name] is False for name in false_fields)
    assert {path.name for path in context.artifact_directory.iterdir()} == {
        POST_ENROLLMENT_START_CLAIM_FILE_NAME,
        "runtime-secrets",
    }
    assert list((context.artifact_directory / "runtime-secrets").iterdir()) == []


def test_cached_ordinal_two_is_rejected_before_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    cached = _cursor(
        ordinal=1,
        staged_count=2,
        created_observation_sha256=context.created.observation_sha256,
        last_observation_sha256=context.staged_two.observation_sha256,
        staged_snapshot_sha256=context.staged_two.snapshot.snapshot_sha256,
    )
    _install_success(monkeypatch, context, cursor_values=[cached])

    with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRejected):
        claimed.prepare_post_enrollment_start_claimed_pre_release_fence(
            **context.kwargs()  # type: ignore[arg-type]
        )

    assert context.events == ["cursor:1:2"]
    assert not (context.artifact_directory / POST_ENROLLMENT_START_CLAIM_FILE_NAME).exists()


@pytest.mark.parametrize("foreign_input", ["created_observation", "pre_claim_fence"])
def test_wrong_preclaim_or_session_is_rejected_before_cursor_or_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    foreign_input: str,
) -> None:
    context = _context(tmp_path)
    foreign_created = _created_observation(
        context.created.snapshot,
        session_sha256="b" * 64,
        transcript_sha256="9" * 64,
    )
    _install_success(monkeypatch, context)
    arguments = context.kwargs()
    if foreign_input == "created_observation":
        arguments[foreign_input] = foreign_created
    else:
        foreign_staged = _staged_observation(
            context.staged_one.snapshot,
            foreign_created,
            ordinal=1,
            predecessor_sha256=foreign_created.observation_sha256,
            transcript_sha256="8" * 64,
        )
        arguments[foreign_input] = bind_post_enrollment_start_pre_claim_topology_fence(
            foreign_created,
            foreign_staged,
        )

    with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRejected):
        claimed.prepare_post_enrollment_start_claimed_pre_release_fence(
            **arguments  # type: ignore[arg-type]
        )

    assert context.events == []


def test_cross_approval_preclaim_is_rejected_before_cursor_or_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    _install_success(monkeypatch, context)
    foreign_approval = type(context.approval)(
        operation_id="323e4567-e89b-42d3-a456-426614174002",
        review=context.approval.review,
    )
    arguments = context.kwargs()
    arguments["approval"] = foreign_approval
    arguments["expected_approval_sha256"] = foreign_approval.approval_sha256

    with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRejected):
        claimed.prepare_post_enrollment_start_claimed_pre_release_fence(
            **arguments  # type: ignore[arg-type]
        )

    assert context.events == []
    assert not (context.artifact_directory / POST_ENROLLMENT_START_CLAIM_FILE_NAME).exists()


def test_malformed_staged_path_is_rejected_before_cursor_or_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    _install_success(monkeypatch, context)
    arguments = context.kwargs()
    arguments["expected_database_secret_file"] = context.artifact_directory / "wrong"

    with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRejected):
        claimed.prepare_post_enrollment_start_claimed_pre_release_fence(
            **arguments  # type: ignore[arg-type]
        )

    assert context.events == []
    assert not (context.artifact_directory / POST_ENROLLMENT_START_CLAIM_FILE_NAME).exists()


def test_structurally_valid_wrong_staged_root_is_rejected_before_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    _install_success(monkeypatch, context)
    alternate = _staged_paths(context.artifact_directory / "alternate")
    arguments = context.kwargs()
    arguments.update(
        {
            "expected_database_secret_file": alternate[0],
            "expected_head_anchor_authority_file": alternate[1],
            "expected_head_anchor_auth_secret_file": alternate[2],
            "expected_head_anchor_signing_key_secret_file": alternate[3],
        }
    )

    with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRejected):
        claimed.prepare_post_enrollment_start_claimed_pre_release_fence(
            **arguments  # type: ignore[arg-type]
        )

    assert context.events == []
    assert not (context.artifact_directory / POST_ENROLLMENT_START_CLAIM_FILE_NAME).exists()


@pytest.mark.parametrize("drift", ["mode", "symlink"])
def test_insecure_staged_root_is_rejected_before_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    context = _context(tmp_path)
    _install_success(monkeypatch, context)
    staged_root = context.artifact_directory / "runtime-secrets"
    if drift == "mode":
        staged_root.chmod(0o755)
    else:
        staged_root.rmdir()
        replacement = context.artifact_directory / "replacement-runtime-secrets"
        replacement.mkdir(mode=0o700)
        staged_root.symlink_to(replacement, target_is_directory=True)

    with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRejected):
        claimed.prepare_post_enrollment_start_claimed_pre_release_fence(
            **context.kwargs()  # type: ignore[arg-type]
        )

    assert context.events == []
    assert not (context.artifact_directory / POST_ENROLLMENT_START_CLAIM_FILE_NAME).exists()


@pytest.mark.parametrize("drift", ["regular_leaf", "symlink_leaf", "symlink_parent"])
def test_recreated_staged_input_is_rejected_before_cursor_or_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    context = _context(tmp_path)
    _install_success(monkeypatch, context)
    staged_path = _staged_paths(context.artifact_directory)[0]
    replacement = context.artifact_directory / "replacement"
    if drift == "symlink_parent":
        replacement.mkdir(mode=0o700)
        staged_path.parent.symlink_to(replacement, target_is_directory=True)
    else:
        staged_path.parent.mkdir(mode=0o700)
        if drift == "regular_leaf":
            staged_path.write_text("recreated", encoding="utf-8")
        else:
            replacement.write_text("recreated", encoding="utf-8")
            staged_path.symlink_to(replacement)

    with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRejected):
        claimed.prepare_post_enrollment_start_claimed_pre_release_fence(
            **context.kwargs()  # type: ignore[arg-type]
        )

    assert context.events == []
    assert not (context.artifact_directory / POST_ENROLLMENT_START_CLAIM_FILE_NAME).exists()


@pytest.mark.parametrize("failure", [KeyboardInterrupt(), SystemExit(7)])
def test_process_control_failure_before_claim_boundary_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
) -> None:
    context = _context(tmp_path)
    _install_success(monkeypatch, context)

    def fail_preclaim(**_: object) -> None:
        raise failure

    monkeypatch.setattr(claimed, "_require_pre_claim_structural_inputs", fail_preclaim)
    with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRejected):
        claimed.prepare_post_enrollment_start_claimed_pre_release_fence(
            **context.kwargs()  # type: ignore[arg-type]
        )

    assert context.events == []
    assert not (context.artifact_directory / POST_ENROLLMENT_START_CLAIM_FILE_NAME).exists()


def test_failure_after_claim_preparation_begins_requires_recovery_and_keeps_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    _install_success(monkeypatch, context)

    def prepare(**_: object) -> TrustedTimePostEnrollmentStartStagingHandoff:
        context.events.append("prepare_claim")
        context.handoff()
        raise RuntimeError("uncertain")

    monkeypatch.setattr(
        claimed,
        "prepare_post_enrollment_start_release_under_lock",
        prepare,
    )
    with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRecoveryRequired):
        claimed.prepare_post_enrollment_start_claimed_pre_release_fence(
            **context.kwargs()  # type: ignore[arg-type]
        )
    assert (context.artifact_directory / POST_ENROLLMENT_START_CLAIM_FILE_NAME).exists()


@pytest.mark.parametrize("failure", [KeyboardInterrupt(), SystemExit(7)])
def test_process_control_failure_after_claim_boundary_requires_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
) -> None:
    context = _context(tmp_path)
    _install_success(monkeypatch, context)

    def prepare(**_: object) -> TrustedTimePostEnrollmentStartStagingHandoff:
        context.events.append("prepare_claim")
        context.handoff()
        raise failure

    monkeypatch.setattr(
        claimed,
        "prepare_post_enrollment_start_release_under_lock",
        prepare,
    )
    with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRecoveryRequired):
        claimed.prepare_post_enrollment_start_claimed_pre_release_fence(
            **context.kwargs()  # type: ignore[arg-type]
        )
    assert (context.artifact_directory / POST_ENROLLMENT_START_CLAIM_FILE_NAME).exists()


def test_failure_after_materials_return_is_recovery_required(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    _install_success(monkeypatch, context)

    def fail_payload(**_: object) -> dict[str, object]:
        raise KeyboardInterrupt

    monkeypatch.setattr(claimed, "_claimed_fence_payload", fail_payload)
    with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRecoveryRequired):
        claimed.prepare_post_enrollment_start_claimed_pre_release_fence(
            **context.kwargs()  # type: ignore[arg-type]
        )
    assert (context.artifact_directory / POST_ENROLLMENT_START_CLAIM_FILE_NAME).exists()


def test_post_claim_cursor_drift_requires_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    drift = _cursor(
        ordinal=2,
        staged_count=2,
        created_observation_sha256=context.created.observation_sha256,
        last_observation_sha256=context.staged_two.observation_sha256,
        staged_snapshot_sha256=context.staged_two.snapshot.snapshot_sha256,
    )
    _install_success(
        monkeypatch,
        context,
        cursor_values=[context.cursors[0], drift],
    )
    with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRecoveryRequired):
        claimed.prepare_post_enrollment_start_claimed_pre_release_fence(
            **context.kwargs()  # type: ignore[arg-type]
        )
    assert (context.artifact_directory / POST_ENROLLMENT_START_CLAIM_FILE_NAME).exists()
    assert "issue_ordinal_2" not in context.events


def test_first_post_claim_revalidation_failure_stops_before_second_cursor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    _install_success(monkeypatch, context, revalidations=[False])

    with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRecoveryRequired):
        claimed.prepare_post_enrollment_start_claimed_pre_release_fence(
            **context.kwargs()  # type: ignore[arg-type]
        )

    assert context.events == ["cursor:1:1", "prepare_claim", "revalidate_claim"]
    assert (context.artifact_directory / POST_ENROLLMENT_START_CLAIM_FILE_NAME).exists()


def test_preadvanced_first_cursor_is_rejected_before_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    preadvanced = _cursor(
        ordinal=2,
        staged_count=1,
        created_observation_sha256=context.created.observation_sha256,
        last_observation_sha256=context.staged_one.observation_sha256,
        staged_snapshot_sha256=context.staged_one.snapshot.snapshot_sha256,
    )
    _install_success(monkeypatch, context, cursor_values=[preadvanced])

    with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRejected):
        claimed.prepare_post_enrollment_start_claimed_pre_release_fence(
            **context.kwargs()  # type: ignore[arg-type]
        )

    assert context.events == ["cursor:2:1"]
    assert not (context.artifact_directory / POST_ENROLLMENT_START_CLAIM_FILE_NAME).exists()


@pytest.mark.parametrize("failure", ["issue", "bind"])
def test_ordinal_two_or_bind_failure_requires_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    context = _context(tmp_path)
    _install_success(
        monkeypatch,
        context,
        staged_error=RuntimeError("issue") if failure == "issue" else None,
        bind_error=RuntimeError("bind") if failure == "bind" else None,
    )
    with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRecoveryRequired):
        claimed.prepare_post_enrollment_start_claimed_pre_release_fence(
            **context.kwargs()  # type: ignore[arg-type]
        )
    assert (context.artifact_directory / POST_ENROLLMENT_START_CLAIM_FILE_NAME).exists()
    assert "cursor:3:2" not in context.events


@pytest.mark.parametrize("failure", ["final_cursor", "claim_revalidation"])
def test_final_cursor_or_claim_revalidation_failure_requires_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    context = _context(tmp_path)
    cursors = list(context.cursors)
    if failure == "final_cursor":
        cursors[2] = _cursor(
            ordinal=3,
            staged_count=1,
            created_observation_sha256=context.created.observation_sha256,
            last_observation_sha256=context.staged_one.observation_sha256,
            staged_snapshot_sha256=context.staged_one.snapshot.snapshot_sha256,
        )
    _install_success(
        monkeypatch,
        context,
        cursor_values=cursors,
        revalidations=[True, failure != "claim_revalidation"],
    )
    with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRecoveryRequired):
        claimed.prepare_post_enrollment_start_claimed_pre_release_fence(
            **context.kwargs()  # type: ignore[arg-type]
        )
    assert (context.artifact_directory / POST_ENROLLMENT_START_CLAIM_FILE_NAME).exists()


def test_direct_result_forgery_or_tampering_fails_process_seal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    _install_success(monkeypatch, context)
    result = claimed.prepare_post_enrollment_start_claimed_pre_release_fence(
        **context.kwargs()  # type: ignore[arg-type]
    )

    capability_type = claimed._ClaimedFenceCapability
    forged_capability = object.__new__(capability_type)
    with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRejected):
        replace(result, _capability=forged_capability)
    with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRejected):
        replace(result, final_cursor_sha256="0" * 64)
    with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRejected):
        replace(result)
    for clone in (
        lambda: copy(result),
        lambda: deepcopy(result),
        lambda: pickle.dumps(result),
    ):
        with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRejected):
            clone()


def test_uninitialized_result_cannot_assert_authenticated_facts() -> None:
    forged = object.__new__(claimed.TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence)

    for name in (
        "claim_chronology_authenticated",
        "claim_retention_authenticated",
        "final_cursor_session_authenticated",
        "observation_provenance_authenticated",
        "ordinal_2_after_claim_authenticated",
        "same_session_observation_chain_authenticated",
        "stable_topology_match_authenticated",
    ):
        with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRejected):
            getattr(forged, name)
    with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRejected):
        forged.payload()


def test_fully_populated_raw_result_cannot_project_authenticated_payload() -> None:
    forged = object.__new__(claimed.TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence)
    values: dict[str, object] = {
        "operation_id": "123e4567-e89b-42d3-a456-426614174000",
        "approval_sha256": "1" * 64,
        "session_sha256": "2" * 64,
        "pre_claim_fence_sha256": "3" * 64,
        "claim_sha256": "4" * 64,
        "retained_claim_artifact_sha256": "5" * 64,
        "pre_claim_cursor_sha256": "6" * 64,
        "post_claim_cursor_sha256": "7" * 64,
        "pre_release_staged_observation_sha256": "8" * 64,
        "pre_release_fence_sha256": "9" * 64,
        "final_cursor_sha256": "a" * 64,
        "_approval": None,
        "_created_observation": None,
        "_pre_claim_fence": None,
        "_handoff": None,
        "_pre_claim_cursor": None,
        "_post_claim_cursor": None,
        "_pre_release_staged_observation": None,
        "_pre_release_fence": None,
        "_final_cursor": None,
        "_capability": None,
    }
    for name, value in values.items():
        object.__setattr__(forged, name, value)

    with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRejected):
        forged.payload()


def test_claimed_fence_subclass_cannot_override_authentication_or_digest_validation() -> None:
    class ForgedClaimedFence(claimed.TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence):
        def __post_init__(self) -> None:
            return

    forged = ForgedClaimedFence(
        operation_id="123e4567-e89b-42d3-a456-426614174000",
        approval_sha256="1" * 64,
        session_sha256="2" * 64,
        pre_claim_fence_sha256="3" * 64,
        claim_sha256="4" * 64,
        retained_claim_artifact_sha256="5" * 64,
        pre_claim_cursor_sha256="6" * 64,
        post_claim_cursor_sha256="7" * 64,
        pre_release_staged_observation_sha256="8" * 64,
        pre_release_fence_sha256="9" * 64,
        final_cursor_sha256="a" * 64,
        _approval=None,
        _created_observation=None,
        _pre_claim_fence=None,
        _handoff=None,
        _pre_claim_cursor=None,
        _post_claim_cursor=None,
        _pre_release_staged_observation=None,
        _pre_release_fence=None,
        _final_cursor=None,
        _capability=None,
    )

    with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRejected):
        _ = forged.claim_chronology_authenticated
    with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRejected):
        _ = forged.fence_sha256
    with pytest.raises(claimed.TrustedTimePostEnrollmentStartClaimedFenceRejected):
        forged.payload()


def test_result_is_invalid_in_forked_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not hasattr(os, "fork"):
        pytest.skip("fork is unavailable")
    context = _context(tmp_path)
    _install_success(monkeypatch, context)
    result = claimed.prepare_post_enrollment_start_claimed_pre_release_fence(
        **context.kwargs()  # type: ignore[arg-type]
    )
    read_descriptor, write_descriptor = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:  # pragma: no cover - asserted through the pipe
        os.close(read_descriptor)
        rejected = 0
        for operation in (result.__post_init__, result.payload):
            try:
                operation()
            except claimed.TrustedTimePostEnrollmentStartClaimedFenceRejected:
                rejected += 1
        try:
            os.write(write_descriptor, b"rejected" if rejected == 2 else b"accepted")
        finally:
            os.close(write_descriptor)
        os._exit(0)

    os.close(write_descriptor)
    try:
        assert os.read(read_descriptor, 16) == b"rejected"
    finally:
        os.close(read_descriptor)
        os.waitpid(child_pid, 0)


def test_module_has_no_cli_release_subprocess_or_outcome_surface() -> None:
    assert set(claimed.__all__) == {
        "POST_ENROLLMENT_START_CLAIMED_PRE_RELEASE_TOPOLOGY_FENCE_CONTRACT_VERSION",
        "POST_ENROLLMENT_START_CLAIMED_PRE_RELEASE_TOPOLOGY_FENCE_STATUS",
        "TrustedTimePostEnrollmentStartClaimedFenceRecoveryRequired",
        "TrustedTimePostEnrollmentStartClaimedFenceRejected",
        "TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence",
        "prepare_post_enrollment_start_claimed_pre_release_fence",
    }
    for name in ("main", "run", "release", "execute", "retain_outcome"):
        assert not hasattr(claimed, name)
    assert not hasattr(
        claimed,
        "_prepare_post_enrollment_start_claimed_pre_release_materials",
    )
    assert not hasattr(claimed, "_build_claimed_fence_preparer")
    assert not hasattr(claimed, "subprocess")
