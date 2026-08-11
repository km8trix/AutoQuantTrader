from __future__ import annotations

import inspect
import json
import pickle
import sys
import threading
from copy import copy, deepcopy
from dataclasses import fields, replace
from pathlib import Path
from typing import Any, cast

import pytest

import scripts.trusted_time_post_enrollment_action_topology_fence as action_fence
import scripts.trusted_time_post_enrollment_claimed_fence as claimed_fence
import scripts.trusted_time_post_enrollment_topology_reader as reader
from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
)
from scripts.start_trusted_time_supervisor import DATABASE_SECRET_CONSUMED_PATH
from scripts.trusted_time_post_enrollment_start import (
    RetainedTrustedTimePostEnrollmentStartClaim,
    revalidate_retained_post_enrollment_start_claim,
)
from tests.unit import test_trusted_time_post_enrollment_claimed_fence as claimed_fixtures


class _AsyncInterruption(BaseException):
    pass


@pytest.fixture(autouse=True)
def _install_test_observation_validators(monkeypatch: pytest.MonkeyPatch) -> None:
    def valid(candidate: object, payload: object) -> bool:
        return type(candidate) is bytes and candidate == claimed_fixtures._authenticated_seal(
            cast(dict[str, object], payload)
        )

    monkeypatch.setattr(reader, "_valid_observation_seal", valid)
    monkeypatch.setattr(
        reader,
        "_valid_cursor_seal",
        lambda candidate, payload, _result: valid(candidate, payload),
    )


def _claimed_context(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[
    claimed_fixtures._Context,
    object,
    claimed_fence.TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence,
]:
    context = claimed_fixtures._context(tmp_path)
    lease = object()
    recovery_retention_capability = object()
    cast(Any, context).action_recovery_retention_capability = recovery_retention_capability
    claimed_fixtures._install_success(
        monkeypatch,
        context,
        expected_choreography_lease=lease,
        expected_recovery_retention_capability=recovery_retention_capability,
    )
    claimed = claimed_fence.prepare_post_enrollment_start_leased_claimed_pre_release_fence(
        **context.kwargs(),  # type: ignore[arg-type]
        choreography_lease=lease,
        recovery_retention_capability=recovery_retention_capability,
    )
    context.events.clear()
    return context, lease, claimed


def _final_observation(
    context: claimed_fixtures._Context,
    claimed: claimed_fence.TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence,
    *,
    snapshot: Any | None = None,
) -> reader.TrustedTimePostEnrollmentFinalActionTopologyObservation:
    final_snapshot = snapshot or context.staged_two.snapshot
    payload = reader._final_action_observation_payload(
        session_sha256=claimed.session_sha256,
        transcript_sha256="9" * 64,
        observation_count=16,
        claimed_fence_sha256=claimed.fence_sha256,
        created_observation_sha256=context.created.observation_sha256,
        predecessor_observation_sha256=context.staged_two.observation_sha256,
        snapshot_sha256=final_snapshot.snapshot_sha256,
    )
    return reader.TrustedTimePostEnrollmentFinalActionTopologyObservation(
        session_sha256=claimed.session_sha256,
        transcript_sha256="9" * 64,
        observation_count=16,
        claimed_fence_sha256=claimed.fence_sha256,
        created_observation_sha256=context.created.observation_sha256,
        predecessor_observation_sha256=context.staged_two.observation_sha256,
        snapshot=final_snapshot,
        _seal=claimed_fixtures._authenticated_seal(payload),
    )


def _action_kwargs(
    context: claimed_fixtures._Context,
    lease: object,
    claimed: claimed_fence.TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence,
) -> dict[str, object]:
    claimed_kwargs = context.kwargs()
    return {
        "claimed_fence": claimed,
        "topology_issuer": context.topology_issuer,
        "choreography_lease": lease,
        "recovery_retention_capability": cast(
            Any,
            context,
        ).action_recovery_retention_capability,
        "approved_launch": context.approved_launch,
        "expected_database_secret_file": claimed_kwargs["expected_database_secret_file"],
        "expected_head_anchor_authority_file": claimed_kwargs[
            "expected_head_anchor_authority_file"
        ],
        "expected_head_anchor_auth_secret_file": claimed_kwargs[
            "expected_head_anchor_auth_secret_file"
        ],
        "expected_head_anchor_signing_key_secret_file": claimed_kwargs[
            "expected_head_anchor_signing_key_secret_file"
        ],
        "artifact_directory": context.artifact_directory,
        "ignored_root": context.ignored_root,
    }


def _install_final_issuer(
    monkeypatch: pytest.MonkeyPatch,
    context: claimed_fixtures._Context,
    lease: object,
    claimed: claimed_fence.TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence,
    final: reader.TrustedTimePostEnrollmentFinalActionTopologyObservation,
    *,
    authorization_claimed_fence: object | None = None,
    consume_in_thread: bool = False,
    fail_before_consume: BaseException | None = None,
    replay: bool = False,
) -> list[object]:
    accepted: list[object] = []

    def issue(
        candidate: reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        *,
        claimed_action_authorization: object,
        claimed_fence: object,
        claimed_fence_sha256: str,
        created_observation: object,
        approval: object,
        approved_launch: object,
        expected_database_secret_file: Path,
        expected_head_anchor_authority_file: Path,
        expected_head_anchor_auth_secret_file: Path,
        expected_head_anchor_signing_key_secret_file: Path,
        _choreography_lease: object,
    ) -> reader.TrustedTimePostEnrollmentFinalActionTopologyObservation:
        context.events.append("issue_final_action_observation")
        accepted.append(claimed_action_authorization)
        if fail_before_consume is not None:
            raise fail_before_consume
        staged_paths = (
            expected_database_secret_file,
            expected_head_anchor_authority_file,
            expected_head_anchor_auth_secret_file,
            expected_head_anchor_signing_key_secret_file,
        )

        def consume() -> bool:
            return bool(
                action_fence._consume_claimed_action_topology_observation_authorization(
                    claimed_action_authorization,
                    topology_issuer=candidate,
                    choreography_lease=_choreography_lease,
                    claimed_fence=(
                        claimed_fence
                        if authorization_claimed_fence is None
                        else authorization_claimed_fence
                    ),
                    claimed_fence_sha256=claimed_fence_sha256,
                    created_observation=created_observation,
                    approval=approval,
                    approved_launch=approved_launch,
                    staged_paths=staged_paths,
                )
            )

        if consume_in_thread:
            values: list[bool] = []
            worker = threading.Thread(target=lambda: values.append(consume()))
            worker.start()
            worker.join(timeout=5)
            assert not worker.is_alive()
            consumed = values == [True]
        else:
            consumed = consume()
        if replay:
            assert consume() is False
        if not consumed:
            raise reader.TrustedTimePostEnrollmentTopologyReaderError(
                "trusted-time final-action topology authorization is unavailable"
            )
        assert candidate is context.topology_issuer
        assert _choreography_lease is lease
        assert claimed_fence is claimed
        return final

    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_issue_claimed_final_action_topology_snapshot",
        issue,
        raising=False,
    )

    def require_armed(
        candidate: reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        candidate_lease: object,
        candidate_capability: object,
        *,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> None:
        assert candidate is context.topology_issuer
        assert candidate_lease is lease
        assert candidate_capability is cast(Any, context).action_recovery_retention_capability
        assert artifact_directory == context.artifact_directory
        assert ignored_root == context.ignored_root
        context.events.append("require_armed_recovery")

    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_require_armed_recovery_outcome_retention",
        require_armed,
        raising=False,
    )
    return accepted


def test_binds_exact_claimed_fence_to_one_full_action_time_reobservation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, claimed = _claimed_context(monkeypatch, tmp_path)
    final = _final_observation(context, claimed)
    _install_final_issuer(monkeypatch, context, lease, claimed, final, replay=True)

    def revalidate(
        candidate: RetainedTrustedTimePostEnrollmentStartClaim,
        *,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> bool:
        context.events.append("revalidate_claim")
        return revalidate_retained_post_enrollment_start_claim(
            candidate,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    monkeypatch.setattr(
        action_fence,
        "revalidate_retained_post_enrollment_start_claim",
        revalidate,
    )

    result = action_fence.prepare_post_enrollment_start_leased_claimed_action_topology_fence(
        **_action_kwargs(context, lease, claimed)
    )

    assert result.status == action_fence.POST_ENROLLMENT_START_CLAIMED_ACTION_TOPOLOGY_FENCE_STATUS
    assert result.claimed_fence_sha256 == claimed.fence_sha256
    assert result.predecessor_observation_sha256 == context.staged_two.observation_sha256
    assert result.final_action_observation_sha256 == final.observation_sha256
    assert result.final_action_snapshot_sha256 == context.staged_two.snapshot.snapshot_sha256
    assert (
        result.final_action_stable_topology_sha256
        == context.staged_two.snapshot.stable_topology_sha256
    )
    assert context.events == [
        "require_armed_recovery",
        "checkpoint_lease",
        "revalidate_claim",
        "require_armed_recovery",
        "checkpoint_lease",
        "issue_final_action_observation",
        "revalidate_claim",
        "require_armed_recovery",
        "checkpoint_lease",
        "require_armed_recovery",
        "checkpoint_lease",
    ]
    payload = result.payload()
    assert payload["final_action_topology_reobservation_authenticated"] is True
    assert payload["retained_claim_revalidated"] is True
    assert payload["claim_chronology_authenticated"] is True
    assert payload["claim_retention_authenticated"] is True
    assert payload["observation_provenance_authenticated"] is True
    assert payload["same_session_observation_chain_authenticated"] is True
    assert payload["stable_topology_match_authenticated"] is True
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
    assert all(payload[field] is False for field in false_fields)
    assert all(getattr(result, field) is False for field in false_fields)


def test_authorization_rejects_stolen_claimed_fence_identity_and_is_consumed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, claimed = _claimed_context(monkeypatch, tmp_path)
    final = _final_observation(context, claimed)
    stolen = object()
    _install_final_issuer(
        monkeypatch,
        context,
        lease,
        claimed,
        final,
        authorization_claimed_fence=stolen,
    )
    poisons: list[object] = []
    monkeypatch.setattr(action_fence, "_poison_action", poisons.append)

    with pytest.raises(
        action_fence.TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRecoveryRequired
    ):
        action_fence.prepare_post_enrollment_start_leased_claimed_action_topology_fence(
            **_action_kwargs(context, lease, claimed)
        )

    assert poisons == [context.topology_issuer]


def test_forged_exact_claimed_result_consumes_origin_and_poisons_before_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, claimed = _claimed_context(monkeypatch, tmp_path)
    forged = object.__new__(
        claimed_fence.TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence
    )
    for candidate_field in fields(claimed):
        object.__setattr__(
            forged,
            candidate_field.name,
            getattr(claimed, candidate_field.name),
        )
    context.topology_issuer._lifecycle_lock = threading.RLock()
    poisons: list[object] = []
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_poison_locked",
        lambda candidate: poisons.append(candidate),
    )
    kwargs = _action_kwargs(context, lease, claimed)
    kwargs["claimed_fence"] = forged

    with pytest.raises(
        action_fence.TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRecoveryRequired
    ):
        action_fence.prepare_post_enrollment_start_leased_claimed_action_topology_fence(**kwargs)

    assert poisons
    assert all(candidate is context.topology_issuer for candidate in poisons)
    assert context.events == []


@pytest.mark.parametrize("wrong_binding", ["issuer", "lease", "recovery"])
def test_claimed_action_origin_binding_is_one_shot_and_poisons_both_sides(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    wrong_binding: str,
) -> None:
    context, lease, claimed = _claimed_context(monkeypatch, tmp_path)
    final = _final_observation(context, claimed)
    _install_final_issuer(monkeypatch, context, lease, claimed, final)
    other_issuer = object.__new__(reader.TrustedTimePostEnrollmentTopologyObservationIssuer)
    context.topology_issuer._lifecycle_lock = threading.RLock()
    other_issuer._lifecycle_lock = threading.RLock()
    context.topology_issuer._owner_pid = action_fence.os.getpid()
    other_issuer._owner_pid = action_fence.os.getpid()
    poisons: list[object] = []
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_poison_locked",
        lambda candidate: poisons.append(candidate),
    )
    kwargs = _action_kwargs(context, lease, claimed)
    if wrong_binding == "issuer":
        kwargs["topology_issuer"] = other_issuer
    elif wrong_binding == "lease":
        kwargs["choreography_lease"] = object()
    else:
        assert wrong_binding == "recovery"
        kwargs["recovery_retention_capability"] = object()

    with pytest.raises(
        action_fence.TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRecoveryRequired
    ):
        action_fence.prepare_post_enrollment_start_leased_claimed_action_topology_fence(**kwargs)

    assert context.topology_issuer in poisons
    if wrong_binding == "issuer":
        assert other_issuer in poisons
    assert context.events == []
    with pytest.raises(
        action_fence.TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRecoveryRequired
    ):
        action_fence.prepare_post_enrollment_start_leased_claimed_action_topology_fence(
            **_action_kwargs(context, lease, claimed)
        )
    assert context.events == []


def test_claimed_action_origin_interruption_after_pop_cannot_replay(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, claimed = _claimed_context(monkeypatch, tmp_path)
    context.topology_issuer._lifecycle_lock = threading.RLock()
    poisons: list[object] = []
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_poison_locked",
        lambda candidate: poisons.append(candidate),
    )
    consume = claimed_fence._consume_claimed_fence_action_choreography
    source, first_line = inspect.getsourcelines(consume)
    after_pop_line = first_line + next(
        offset for offset, line in enumerate(source) if "if origin is None:" in line
    )
    interrupted = False
    kwargs = _action_kwargs(context, lease, claimed)
    consume_arguments = {
        "topology_issuer": context.topology_issuer,
        "choreography_lease": lease,
        "recovery_retention_capability": kwargs["recovery_retention_capability"],
        "artifact_directory": context.artifact_directory,
        "ignored_root": context.ignored_root,
    }

    def interrupt_after_pop(frame: object, event: str, _arg: object) -> object:
        nonlocal interrupted
        if (
            not interrupted
            and event == "line"
            and getattr(frame, "f_code", None) is consume.__code__
            and getattr(frame, "f_lineno", None) == after_pop_line
        ):
            interrupted = True
            sys.settrace(None)
            raise _AsyncInterruption
        return interrupt_after_pop

    sys.settrace(interrupt_after_pop)
    try:
        with pytest.raises(_AsyncInterruption):
            consume(claimed, **consume_arguments)
    finally:
        sys.settrace(None)

    origin_map = cast(
        dict[object, object],
        inspect.getclosurevars(consume).nonlocals["claimed_action_choreographies"],
    )
    assert interrupted is True
    assert poisons == [context.topology_issuer]
    assert claimed._capability not in origin_map
    assert consume(claimed, **consume_arguments) is False


def test_successful_claimed_origin_replay_poisons_original_not_wrong_issuer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, claimed = _claimed_context(monkeypatch, tmp_path)
    original_issuer = context.topology_issuer
    wrong_issuer = object.__new__(reader.TrustedTimePostEnrollmentTopologyObservationIssuer)
    original_issuer._lifecycle_lock = threading.RLock()
    wrong_issuer._lifecycle_lock = threading.RLock()
    poisons: list[object] = []
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_poison_locked",
        lambda candidate: poisons.append(candidate),
    )
    consume = claimed_fence._consume_claimed_fence_action_choreography
    kwargs = _action_kwargs(context, lease, claimed)
    consume_arguments = {
        "topology_issuer": original_issuer,
        "choreography_lease": lease,
        "recovery_retention_capability": kwargs["recovery_retention_capability"],
        "artifact_directory": context.artifact_directory,
        "ignored_root": context.ignored_root,
    }

    assert consume(claimed, **consume_arguments) is True
    consume_arguments["topology_issuer"] = wrong_issuer
    assert consume(claimed, **consume_arguments) is False
    assert poisons == [original_issuer]


def test_claimed_capability_unregister_interruption_retries_all_map_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context = claimed_fixtures._context(tmp_path)
    claimed_fixtures._install_success(monkeypatch, context)
    prepare = claimed_fence.prepare_post_enrollment_start_claimed_pre_release_fence
    unregister = cast(
        Any,
        inspect.getclosurevars(prepare).nonlocals["unregister"],
    )
    unregister_state = inspect.getclosurevars(unregister).nonlocals
    registrations = cast(dict[object, object], unregister_state["registrations"])
    origins = cast(
        dict[object, object],
        unregister_state["claimed_action_choreographies"],
    )
    tombstones = cast(
        dict[object, object],
        unregister_state["consumed_claimed_action_origins"],
    )
    baseline_registration_keys = set(registrations)
    baseline_origin_keys = set(origins)
    baseline_tombstone_keys = set(tombstones)
    source, first_line = inspect.getsourcelines(unregister)
    after_origin_pop_line = first_line + next(
        offset
        for offset, line in enumerate(source)
        if "consumed_claimed_action_origins.pop" in line
    )
    interrupted = False

    def reject_result(**_kwargs: object) -> object:
        raise RuntimeError("result construction failed")

    def interrupt_after_origin_pop(frame: object, event: str, _arg: object) -> object:
        nonlocal interrupted
        if (
            not interrupted
            and event == "line"
            and getattr(frame, "f_code", None) is unregister.__code__
            and getattr(frame, "f_lineno", None) == after_origin_pop_line
        ):
            interrupted = True
            sys.settrace(None)
            raise _AsyncInterruption
        return interrupt_after_origin_pop

    monkeypatch.setattr(
        claimed_fence,
        "TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence",
        reject_result,
    )
    sys.settrace(interrupt_after_origin_pop)
    try:
        with pytest.raises(_AsyncInterruption):
            prepare(**context.kwargs())  # type: ignore[arg-type]
    finally:
        sys.settrace(None)

    assert interrupted is True
    assert set(registrations) == baseline_registration_keys
    assert set(origins) == baseline_origin_keys
    assert set(tombstones) == baseline_tombstone_keys


def test_claimed_action_requires_claim_bound_recovery_retention(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context = claimed_fixtures._context(tmp_path)
    lease = object()
    recovery_retention_capability = object()
    cast(Any, context).action_recovery_retention_capability = recovery_retention_capability
    claimed_fixtures._install_success(
        monkeypatch,
        context,
        expected_choreography_lease=lease,
    )
    claimed = claimed_fence.prepare_post_enrollment_start_leased_claimed_pre_release_fence(
        **context.kwargs(),  # type: ignore[arg-type]
        choreography_lease=lease,
    )
    context.events.clear()
    context.topology_issuer._lifecycle_lock = threading.RLock()
    poisons: list[object] = []
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_poison_locked",
        lambda candidate: poisons.append(candidate),
    )

    with pytest.raises(
        action_fence.TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRecoveryRequired
    ):
        action_fence.prepare_post_enrollment_start_leased_claimed_action_topology_fence(
            **_action_kwargs(context, lease, claimed)
        )

    assert poisons
    assert all(candidate is context.topology_issuer for candidate in poisons)
    assert context.events == []


def test_authorization_is_finally_revoked_when_reader_fails_before_consumption(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, claimed = _claimed_context(monkeypatch, tmp_path)
    final = _final_observation(context, claimed)
    captured = _install_final_issuer(
        monkeypatch,
        context,
        lease,
        claimed,
        final,
        fail_before_consume=_AsyncInterruption(),
    )
    monkeypatch.setattr(action_fence, "_poison_action", lambda _issuer: None)

    with pytest.raises(
        action_fence.TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRecoveryRequired
    ):
        action_fence.prepare_post_enrollment_start_leased_claimed_action_topology_fence(
            **_action_kwargs(context, lease, claimed)
        )

    assert len(captured) == 1
    claimed_kwargs = context.kwargs()
    assert (
        action_fence._consume_claimed_action_topology_observation_authorization(
            captured[0],
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            claimed_fence=claimed,
            claimed_fence_sha256=claimed.fence_sha256,
            created_observation=context.created,
            approval=context.approval,
            approved_launch=context.approved_launch,
            staged_paths=(
                claimed_kwargs["expected_database_secret_file"],
                claimed_kwargs["expected_head_anchor_authority_file"],
                claimed_kwargs["expected_head_anchor_auth_secret_file"],
                claimed_kwargs["expected_head_anchor_signing_key_secret_file"],
            ),
        )
        is False
    )


def test_poison_interruption_is_not_normalized_inside_action_preparer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, claimed = _claimed_context(monkeypatch, tmp_path)
    final = _final_observation(context, claimed)
    _install_final_issuer(
        monkeypatch,
        context,
        lease,
        claimed,
        final,
        fail_before_consume=RuntimeError("reader failed"),
    )

    def interrupted_poison(_: object) -> None:
        raise _AsyncInterruption

    monkeypatch.setattr(action_fence, "_poison_action", interrupted_poison)
    with pytest.raises(_AsyncInterruption):
        action_fence.prepare_post_enrollment_start_leased_claimed_action_topology_fence(
            **_action_kwargs(context, lease, claimed)
        )


def test_cross_thread_authorization_use_fails_closed_and_cannot_be_retried(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, claimed = _claimed_context(monkeypatch, tmp_path)
    final = _final_observation(context, claimed)
    captured = _install_final_issuer(
        monkeypatch,
        context,
        lease,
        claimed,
        final,
        consume_in_thread=True,
    )
    monkeypatch.setattr(action_fence, "_poison_action", lambda _issuer: None)

    with pytest.raises(
        action_fence.TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRecoveryRequired
    ):
        action_fence.prepare_post_enrollment_start_leased_claimed_action_topology_fence(
            **_action_kwargs(context, lease, claimed)
        )

    assert len(captured) == 1
    claimed_kwargs = context.kwargs()
    assert (
        action_fence._consume_claimed_action_topology_observation_authorization(
            captured[0],
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            claimed_fence=claimed,
            claimed_fence_sha256=claimed.fence_sha256,
            created_observation=context.created,
            approval=context.approval,
            approved_launch=context.approved_launch,
            staged_paths=(
                claimed_kwargs["expected_database_secret_file"],
                claimed_kwargs["expected_head_anchor_authority_file"],
                claimed_kwargs["expected_head_anchor_auth_secret_file"],
                claimed_kwargs["expected_head_anchor_signing_key_secret_file"],
            ),
        )
        is False
    )


def test_revalidates_exact_retained_claim_before_and_after_final_observation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, claimed = _claimed_context(monkeypatch, tmp_path)
    final = _final_observation(context, claimed)
    _install_final_issuer(monkeypatch, context, lease, claimed, final)
    validations = iter([True, False])
    monkeypatch.setattr(
        action_fence,
        "revalidate_retained_post_enrollment_start_claim",
        lambda *_args, **_kwargs: next(validations),
    )
    poisons: list[object] = []
    monkeypatch.setattr(action_fence, "_poison_action", poisons.append)

    with pytest.raises(
        action_fence.TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRecoveryRequired
    ):
        action_fence.prepare_post_enrollment_start_leased_claimed_action_topology_fence(
            **_action_kwargs(context, lease, claimed)
        )

    assert context.events.count("issue_final_action_observation") == 1
    assert poisons == [context.topology_issuer]


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("database_secret_consumed_candidate_sha256", "a" * 64),
        ("release_paths_absence_candidate_sha256", "b" * 64),
        ("staged_input_retirement_candidate_sha256", "c" * 64),
        ("socket_volume_sha256", "d" * 64),
        ("state_volume_sha256", "e" * 64),
    ],
)
def test_rejects_final_action_stable_topology_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    field_name: str,
    value: str,
) -> None:
    context, lease, claimed = _claimed_context(monkeypatch, tmp_path)
    baseline = context.staged_two.snapshot
    if getattr(baseline, field_name) == value:
        value = "f" * 64
    if field_name == "database_secret_consumed_candidate_sha256":
        drifted = replace(baseline, database_secret_consumed_candidate_sha256=value)
    elif field_name == "release_paths_absence_candidate_sha256":
        drifted = replace(baseline, release_paths_absence_candidate_sha256=value)
    elif field_name == "staged_input_retirement_candidate_sha256":
        drifted = replace(baseline, staged_input_retirement_candidate_sha256=value)
    elif field_name == "socket_volume_sha256":
        drifted = replace(baseline, socket_volume_sha256=value)
    else:
        assert field_name == "state_volume_sha256"
        drifted = replace(baseline, state_volume_sha256=value)
    final = _final_observation(context, claimed, snapshot=drifted)
    _install_final_issuer(monkeypatch, context, lease, claimed, final)
    monkeypatch.setattr(action_fence, "_poison_action", lambda _issuer: None)

    with pytest.raises(
        action_fence.TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRecoveryRequired
    ):
        action_fence.prepare_post_enrollment_start_leased_claimed_action_topology_fence(
            **_action_kwargs(context, lease, claimed)
        )


def test_invalid_claimed_input_is_rejected_before_action_or_poison(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, claimed = _claimed_context(monkeypatch, tmp_path)
    poisons: list[object] = []
    monkeypatch.setattr(action_fence, "_poison_action", poisons.append)

    kwargs = _action_kwargs(context, lease, claimed)
    kwargs["claimed_fence"] = object()
    with pytest.raises(
        action_fence.TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected
    ):
        action_fence.prepare_post_enrollment_start_leased_claimed_action_topology_fence(**kwargs)

    assert poisons == []
    assert context.events == []


def test_result_is_exact_process_sealed_noncopyable_and_secret_free(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, claimed = _claimed_context(monkeypatch, tmp_path)
    final = _final_observation(context, claimed)
    _install_final_issuer(monkeypatch, context, lease, claimed, final)
    result = action_fence.prepare_post_enrollment_start_leased_claimed_action_topology_fence(
        **_action_kwargs(context, lease, claimed)
    )
    encoded = json.dumps(result.payload(), sort_keys=True)

    for operation in (
        lambda: copy(result),
        lambda: deepcopy(result),
        lambda: pickle.dumps(result),
    ):
        with pytest.raises(
            action_fence.TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected
        ):
            operation()
    with pytest.raises(
        action_fence.TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected
    ):
        replace(result)
    owner_pid = action_fence.os.getpid()
    with monkeypatch.context() as forked:
        forked.setattr(action_fence.os, "getpid", lambda: owner_pid + 1)
        with pytest.raises(
            action_fence.TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected
        ):
            result.__post_init__()
    object.__setattr__(final, "transcript_sha256", "8" * 64)
    with pytest.raises(
        action_fence.TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected
    ):
        result.__post_init__()

    assert str(context.artifact_directory) not in encoded
    assert DATABASE_SECRET_CONSUMED_PATH not in encoded


def test_public_surface_is_exact_and_has_no_runtime_action_entrypoint() -> None:
    assert set(action_fence.__all__) == {
        "POST_ENROLLMENT_START_CLAIMED_ACTION_TOPOLOGY_FENCE_CONTRACT_VERSION",
        "POST_ENROLLMENT_START_CLAIMED_ACTION_TOPOLOGY_FENCE_STATUS",
        "TrustedTimePostEnrollmentStartClaimedActionTopologyFence",
        "TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRecoveryRequired",
        "TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected",
        "prepare_post_enrollment_start_leased_claimed_action_topology_fence",
    }
    for name in ("main", "run", "start", "release", "claim", "handoff"):
        assert not hasattr(action_fence, name)
