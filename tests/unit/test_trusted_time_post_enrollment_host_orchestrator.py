from __future__ import annotations

import dis
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from scripts import trusted_time_post_enrollment_host_orchestrator as orchestrator
from scripts.trusted_time_post_enrollment_controller_outcome import (
    TrustedTimePostEnrollmentStartControllerOutcomeStatus,
)

_CLOSED_AUTHORITY_FIELDS = {
    "active_controller_authorized",
    "alert_delivery_authorized",
    "arming_authorized",
    "authority_granted",
    "automatic_rearm_authorized",
    "automatic_resume_authorized",
    "broker_action_authorized",
    "claim_retention_authorized",
    "controller_execution_authorized",
    "database_secret_disclosed",
    "exposure_authorized",
    "live_trading_authorized",
    "new_exposure_authorized",
    "operational_control_authorized",
    "outcome_retention_authorized",
    "paper_trading_authorized",
    "persistent_start_authorized",
    "readiness_authorized",
    "rearm_authorized",
    "release_authorized",
    "retry_authorized",
    "runtime_start_authorized",
    "sequence_2_authorized",
    "shutdown_authorized",
    "source_start_authorized",
    "success_outcome_retention_authorized",
    "supervisor_start_authorized",
    "topology_mutation_authorized",
}


class _InjectedFailure(BaseException):
    pass


class _RetainedOutcome:
    def __init__(
        self,
        *,
        operation_id: str = "123e4567-e89b-42d3-a456-426614174000",
        approval_sha256: str = "a" * 64,
        status: object = "confirmed",
    ) -> None:
        self.operation_id = operation_id
        self.approval_sha256 = approval_sha256
        self.outcome_sha256 = "b" * 64
        self.reason = "post_enrollment_start_confirmed"
        self.status = status

    def __post_init__(self) -> None:
        return None


class _RetainedLegacyOutcome(_RetainedOutcome):
    pass


class _TerminalOutcomeSignal(RuntimeError):
    def __init__(self, retained_outcome: object) -> None:
        self.retained_outcome = retained_outcome
        super().__init__("terminal outcome")


class _Approval:
    def __init__(
        self,
        *,
        operation_id: str = "123e4567-e89b-42d3-a456-426614174000",
        approval_sha256: str = "a" * 64,
    ) -> None:
        self.operation_id = operation_id
        self.approval_sha256 = approval_sha256

    def __post_init__(self) -> None:
        return None


class _SequenceOneIssuer:
    def __init__(self, events: list[str]) -> None:
        self._events = events
        self.closed = False

    def close(self) -> None:
        if self.closed:
            return
        self._events.append("sequence_one_close")
        self.closed = True


class _SequenceTwoVerifier:
    def __init__(self, events: list[str]) -> None:
        self._events = events
        self.aborted = False

    def abort(self) -> None:
        if self.aborted:
            return
        self._events.append("sequence_two_abort")
        self.aborted = True


class _Owner:
    def __init__(self) -> None:
        self.empty = False

    def _retire_all(self) -> None:
        self.empty = True

    def _retire_all_confirmed(self) -> None:
        self.empty = True

    def _is_empty(self) -> bool:
        return self.empty


class _Issuer:
    def __init__(
        self,
        events: list[str],
        *,
        fail_at: str | None = None,
        armed_recovery: bool = True,
        adopted_terminal: object | None = None,
    ) -> None:
        self.events = events
        self.fail_at = fail_at
        self.armed_recovery = armed_recovery
        self.adopted_terminal = adopted_terminal
        self.lease = object()
        self.recovery = object()
        self.created = SimpleNamespace(
            snapshot=SimpleNamespace(
                supervisor=SimpleNamespace(container_id="supervisor-container")
            )
        )

    def _event(self, name: str) -> None:
        self.events.append(name)
        if self.fail_at == name:
            raise _InjectedFailure(name)

    def _run_exclusive_choreography_with_recovery_retention(self, callback: Any) -> object:
        self.events.append("choreography_enter")
        try:
            return callback(self.lease, self.recovery)
        finally:
            self.events.append("choreography_exit")

    def _require_active_choreography_lease(self, lease: object) -> object:
        assert lease is self.lease
        self._event("checkpoint")
        return SimpleNamespace(deadline_monotonic_ns=900_000_000_000)

    def _create_reviewed_topology(self, **kwargs: object) -> object:
        assert kwargs["_choreography_lease"] is self.lease
        self._event("create")
        return self.created

    def _start_reviewed_source(self, **kwargs: object) -> None:
        assert kwargs["created_observation"] is self.created
        assert kwargs["_choreography_lease"] is self.lease
        self._event("source_start")

    def _start_reviewed_supervisor(self, **kwargs: object) -> None:
        assert kwargs["created_observation"] is self.created
        assert kwargs["_choreography_lease"] is self.lease
        self._event("supervisor_start")

    def issue_staged_unreleased_snapshot(self, **kwargs: object) -> object:
        assert kwargs["created_observation"] is self.created
        assert kwargs["_choreography_lease"] is self.lease
        self._event("ordinal_one")
        return object()

    def _mark_reviewed_topology_claim_boundary(self, **kwargs: object) -> None:
        assert kwargs["created_observation"] is self.created
        assert kwargs["_choreography_lease"] is self.lease
        self._event("claim_boundary")

    def _teardown_reviewed_topology_before_claim(self, **kwargs: object) -> None:
        assert kwargs["_choreography_lease"] is self.lease
        self.events.append(
            "teardown_none" if kwargs["created_observation"] is None else "teardown_created"
        )

    def _require_armed_recovery_outcome_retention(
        self,
        lease: object,
        recovery: object,
        **_: object,
    ) -> object:
        assert lease is self.lease
        assert recovery is self.recovery
        self.events.append("require_armed_recovery")
        if not self.armed_recovery:
            raise _InjectedFailure("recovery is not armed")
        return object()

    def _recovery_outcome_retention_is_armed(
        self,
        lease: object,
        recovery: object,
        **_: object,
    ) -> bool:
        assert lease is self.lease
        assert recovery is self.recovery
        self.events.append("classify_recovery")
        return self.armed_recovery

    def _adopt_registered_confirmed_terminal_outcome(
        self,
        lease: object,
        recovery: object,
        **_: object,
    ) -> object:
        assert lease is self.lease
        assert recovery is self.recovery
        if self.adopted_terminal is None:
            raise orchestrator.TrustedTimePostEnrollmentTopologyReaderError(
                "no current-scope terminal"
            )
        self.events.append("adopt_terminal")
        return self.adopted_terminal


def _inputs(tmp_path: Path) -> tuple[object, Path, object, object, _Owner]:
    approval = SimpleNamespace(
        operation_id="123e4567-e89b-42d3-a456-426614174000",
        approval_sha256="a" * 64,
    )
    admission = SimpleNamespace(approval=approval)
    paths = tuple(tmp_path / name for name in ("database", "authority", "auth", "signing"))
    materials = orchestrator._RuntimeMaterials(
        database_url="postgresql://redacted.invalid/database",
        database_secret=cast(Any, SimpleNamespace(path=paths[0])),
        head_anchor_inputs=cast(
            Any,
            SimpleNamespace(
                authority=SimpleNamespace(path=paths[1]),
                auth_secret=SimpleNamespace(path=paths[2]),
                signing_key=SimpleNamespace(path=paths[3]),
            ),
        ),
        sequence_two_configuration=cast(
            Any,
            SimpleNamespace(authority=object(), credentials=object(), verifier=object()),
        ),
    )
    approved_launch = SimpleNamespace(
        git_revision="f" * 40,
        image_admission_sha256="1" * 64,
        source_image_id="sha256:" + "2" * 64,
        supervisor_image_id="sha256:" + "3" * 64,
    )
    return admission, tmp_path / "approval.json", materials, approved_launch, _Owner()


def _install_choreography_fakes(
    monkeypatch: pytest.MonkeyPatch,
    events: list[str],
    *,
    controller_failure: BaseException | None = None,
    claimed_failure: BaseException | None = None,
    consume_result: bool = True,
) -> tuple[_SequenceOneIssuer, _RetainedOutcome]:
    sequence_one = _SequenceOneIssuer(events)
    retained = _RetainedOutcome()

    def prepare_sequence_one(**_: object) -> _SequenceOneIssuer:
        events.append("sequence_one_prepare")
        return sequence_one

    def consume(*_: object, **__: object) -> bool:
        events.append("consume")
        return consume_result

    def retire(*_: object, **__: object) -> None:
        events.append("retire_inputs")

    def bind(*_: object, **__: object) -> object:
        events.append("bind_preclaim")
        return object()

    def claim(**_: object) -> object:
        events.append("claimed_fence")
        if claimed_failure is not None:
            raise claimed_failure
        sequence_one.close()
        return object()

    def action(**_: object) -> object:
        events.append("action_fence")
        return object()

    def controller_admission(**_: object) -> object:
        events.append("controller_admission")
        return object()

    def sequence_two(**_: object) -> _SequenceTwoVerifier:
        events.append("sequence_two_prepare")
        return _SequenceTwoVerifier(events)

    def controller(**_: object) -> _RetainedOutcome:
        events.append("controller")
        if controller_failure is not None:
            raise controller_failure
        return retained

    monkeypatch.setattr(
        orchestrator,
        "prepare_trusted_time_post_enrollment_sequence_one_reauthentication_issuer",
        prepare_sequence_one,
    )
    monkeypatch.setattr(
        orchestrator,
        "_consume_post_enrollment_execution_admission",
        consume,
    )
    monkeypatch.setattr(orchestrator, "_retire_inputs", retire)
    monkeypatch.setattr(orchestrator, "bind_post_enrollment_start_pre_claim_topology_fence", bind)
    monkeypatch.setattr(
        orchestrator,
        "prepare_post_enrollment_start_leased_claimed_pre_release_fence",
        claim,
    )
    monkeypatch.setattr(
        orchestrator,
        "prepare_post_enrollment_start_leased_claimed_action_topology_fence",
        action,
    )
    monkeypatch.setattr(
        orchestrator,
        "prepare_post_enrollment_start_active_controller_admission",
        controller_admission,
    )
    monkeypatch.setattr(
        orchestrator,
        "prepare_trusted_time_post_enrollment_start_sequence_two_verifier",
        sequence_two,
    )
    monkeypatch.setattr(orchestrator, "run_post_enrollment_start_active_controller", controller)
    monkeypatch.setattr(
        orchestrator, "RetainedTrustedTimePostEnrollmentStartControllerOutcome", _RetainedOutcome
    )
    return sequence_one, retained


def test_cli_accepts_only_the_two_exact_required_file_flags(tmp_path: Path) -> None:
    approval = tmp_path / "approval.json"
    runtime = tmp_path / "runtime.env"

    parsed = orchestrator._parse_cli(
        ["--approval-artifact", str(approval), "--runtime-env-file", str(runtime)]
    )

    assert parsed.approval_artifact == approval
    assert parsed.runtime_env_file == runtime
    with pytest.raises(SystemExit):
        orchestrator._parse_cli(["--approval-artifact", str(approval)])
    with pytest.raises(SystemExit):
        orchestrator._parse_cli(
            [
                "--approval-artifact",
                str(approval),
                "--runtime-env-file",
                str(runtime),
                "--shutdown-authorized",
            ]
        )


def test_ordinary_import_cannot_invoke_the_effecting_composition(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    admitted = False

    def unexpected_admission(**_: object) -> object:
        nonlocal admitted
        admitted = True
        return object()

    monkeypatch.setattr(orchestrator, "_CLI_REPOSITORY_ROOT", None)
    monkeypatch.setattr(
        orchestrator,
        "admit_post_enrollment_execution_attempt",
        unexpected_admission,
    )

    with pytest.raises(
        orchestrator.TrustedTimePostEnrollmentHostOrchestratorRejected,
        match="only through the isolated CLI",
    ):
        orchestrator.run_approved_post_enrollment_start_once(
            approval_artifact=tmp_path / "approval.json",
            runtime_env_file=tmp_path / "runtime.env",
        )

    assert admitted is False


def test_terminal_projection_is_nonsecret_and_grants_no_trading_or_shutdown_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    retained = _RetainedOutcome()
    monkeypatch.setattr(
        orchestrator,
        "RetainedTrustedTimePostEnrollmentStartControllerOutcome",
        _RetainedOutcome,
    )

    payload = orchestrator._safe_terminal_payload(cast(Any, retained))

    assert payload == {
        **dict.fromkeys(_CLOSED_AUTHORITY_FIELDS, False),
        "approval_sha256": "a" * 64,
        "contract_version": orchestrator.POST_ENROLLMENT_HOST_ORCHESTRATOR_CONTRACT_VERSION,
        "operation_id": "123e4567-e89b-42d3-a456-426614174000",
        "orchestrator_status": "terminal_outcome_retained",
        "outcome_sha256": "b" * 64,
        "reason": "post_enrollment_start_confirmed",
        "service": orchestrator.POST_ENROLLMENT_HOST_ORCHESTRATOR_SERVICE,
        "status": "confirmed",
    }
    assert set(vars(orchestrator)["_CLOSED_AUTHORITY_FIELDS"]) == _CLOSED_AUTHORITY_FIELDS
    encoded = json.dumps(payload)
    assert "postgresql://" not in encoded
    assert "runtime-secrets" not in encoded
    assert "private_key" not in encoded


def test_fatal_projection_closes_the_same_authority_surface_without_tuple_history() -> None:
    payload = orchestrator._fatal_payload()

    assert payload == {
        **dict.fromkeys(_CLOSED_AUTHORITY_FIELDS, False),
        "contract_version": orchestrator.POST_ENROLLMENT_HOST_ORCHESTRATOR_CONTRACT_VERSION,
        "orchestrator_status": "retention_unconfirmed",
        "reason": "retention_unconfirmed_manual_recovery_required",
        "service": orchestrator.POST_ENROLLMENT_HOST_ORCHESTRATOR_SERVICE,
        "status": "fatal",
    }
    assert "operation_id" not in payload
    assert "approval_sha256" not in payload
    assert "outcome_sha256" not in payload


def test_cli_never_substitutes_prior_terminal_for_current_invocation_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    approval_artifact = tmp_path / "approval.json"
    runtime_env_file = tmp_path / "runtime.env"
    monkeypatch.setattr(
        orchestrator,
        "load_post_enrollment_execution_approval",
        lambda **_: SimpleNamespace(approval=_Approval()),
    )
    monkeypatch.setattr(
        orchestrator,
        "run_approved_post_enrollment_start_once",
        lambda **_: (_ for _ in ()).throw(
            orchestrator.TrustedTimePostEnrollmentHostOrchestratorRejected(
                "topology issuer close is unconfirmed"
            )
        ),
    )

    with pytest.raises(SystemExit) as terminal:
        orchestrator.main(
            [
                "--approval-artifact",
                str(approval_artifact),
                "--runtime-env-file",
                str(runtime_env_file),
            ]
        )

    assert terminal.value.code == 2
    assert json.loads(capsys.readouterr().out) == orchestrator._fatal_payload()
    source = Path(orchestrator.__file__).read_text(encoding="utf-8")
    assert "load_retained_post_enrollment_start_controller_outcome" not in source
    assert "load_retained_post_enrollment_start_outcome" not in source


def _install_terminal_types(
    monkeypatch: pytest.MonkeyPatch,
    *,
    controller_valid: bool = True,
    legacy_valid: bool = True,
) -> None:
    from packages.domain import trusted_time_post_enrollment_start as domain

    monkeypatch.setattr(domain, "TrustedTimePostEnrollmentStartApproval", _Approval)
    monkeypatch.setattr(orchestrator, "TrustedTimePostEnrollmentStartApproval", _Approval)
    monkeypatch.setattr(
        orchestrator,
        "RetainedTrustedTimePostEnrollmentStartControllerOutcome",
        _RetainedOutcome,
    )
    monkeypatch.setattr(
        orchestrator,
        "RetainedTrustedTimePostEnrollmentStartOutcome",
        _RetainedLegacyOutcome,
    )
    monkeypatch.setattr(
        orchestrator,
        "revalidate_retained_post_enrollment_start_controller_outcome",
        lambda *_args, **_kwargs: controller_valid,
    )
    monkeypatch.setattr(
        orchestrator,
        "revalidate_retained_post_enrollment_start_outcome",
        lambda *_args, **_kwargs: legacy_valid,
    )


@pytest.mark.parametrize(
    ("outcome_type", "exit_code"),
    [(_RetainedOutcome, 0), (_RetainedLegacyOutcome, 2)],
)
def test_cli_accepts_only_a_typed_terminal_from_the_current_call(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    outcome_type: type[_RetainedOutcome],
    exit_code: int,
) -> None:
    class CurrentControllerTerminal(Exception):
        def __init__(self, retained_outcome: object) -> None:
            self.retained_outcome = retained_outcome

    class CurrentLegacyTerminal(Exception):
        def __init__(self, retained_outcome: object) -> None:
            self.retained_outcome = retained_outcome

    _install_terminal_types(monkeypatch)
    approval = _Approval()
    status: object = (
        TrustedTimePostEnrollmentStartControllerOutcomeStatus.CONFIRMED
        if outcome_type is _RetainedOutcome
        else "recovery_required"
    )
    outcome = outcome_type(status=status)
    terminal_type = (
        CurrentControllerTerminal if outcome_type is _RetainedOutcome else CurrentLegacyTerminal
    )
    monkeypatch.setattr(
        orchestrator,
        "TrustedTimePostEnrollmentStartActiveControllerRecoveryRequired",
        CurrentControllerTerminal,
    )
    monkeypatch.setattr(
        orchestrator,
        "TrustedTimePostEnrollmentStartRecoveryOutcomeRetained",
        CurrentLegacyTerminal,
    )
    monkeypatch.setattr(
        orchestrator,
        "load_post_enrollment_execution_approval",
        lambda **_: SimpleNamespace(approval=approval),
    )
    monkeypatch.setattr(
        orchestrator,
        "run_approved_post_enrollment_start_once",
        lambda **_: (_ for _ in ()).throw(terminal_type(outcome)),
    )

    with pytest.raises(SystemExit) as terminal:
        orchestrator.main(
            [
                "--approval-artifact",
                str(tmp_path / "approval.json"),
                "--runtime-env-file",
                str(tmp_path / "runtime.env"),
            ]
        )

    assert terminal.value.code == exit_code
    assert json.loads(capsys.readouterr().out) == orchestrator._safe_terminal_payload(outcome)


@pytest.mark.parametrize(
    ("outcome_type", "controller_valid", "legacy_valid"),
    [(_RetainedOutcome, True, False), (_RetainedLegacyOutcome, False, True)],
)
def test_typed_terminal_requires_durable_revalidation_and_exact_approval_binding(
    monkeypatch: pytest.MonkeyPatch,
    outcome_type: type[_RetainedOutcome],
    controller_valid: bool,
    legacy_valid: bool,
) -> None:
    _install_terminal_types(
        monkeypatch,
        controller_valid=controller_valid,
        legacy_valid=legacy_valid,
    )
    approval = _Approval()
    outcome = outcome_type()
    require_exact = cast(Any, orchestrator._require_exact_terminal_outcome)

    assert require_exact(approval, outcome) is outcome

    crossed = outcome_type(operation_id="223e4567-e89b-42d3-a456-426614174001")
    with pytest.raises(
        orchestrator.TrustedTimePostEnrollmentHostOrchestratorRejected,
        match="crosses the requested approval",
    ):
        require_exact(approval, crossed)


def test_typed_terminal_rejects_matching_fields_when_durable_revalidation_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_terminal_types(monkeypatch, controller_valid=False)
    require_exact = cast(Any, orchestrator._require_exact_terminal_outcome)

    with pytest.raises(
        orchestrator.TrustedTimePostEnrollmentHostOrchestratorRejected,
        match="crosses the requested approval",
    ):
        require_exact(_Approval(), _RetainedOutcome())


def test_only_confirmed_controller_terminal_receives_success_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_terminal_types(monkeypatch)
    exit_code = cast(Any, orchestrator._terminal_exit_code)
    confirmed = TrustedTimePostEnrollmentStartControllerOutcomeStatus.CONFIRMED
    recovery = TrustedTimePostEnrollmentStartControllerOutcomeStatus.RECOVERY_REQUIRED

    assert exit_code(_RetainedOutcome(status=confirmed)) == 0
    assert exit_code(_RetainedOutcome(status=recovery)) == 2
    assert exit_code(_RetainedLegacyOutcome(status=confirmed)) == 2


def _run_choreography(
    *,
    issuer: _Issuer,
    admission: object,
    approval_artifact: Path,
    materials: object,
    approved_launch: object,
    owner: _Owner,
) -> object:
    run = cast(Any, orchestrator._run_post_enrollment_choreography)
    return run(
        admission=admission,
        approval_artifact=approval_artifact,
        materials=materials,
        owner=owner,
        approved_launch=approved_launch,
        compose_payload=b"reviewed-compose",
        issuer=issuer,
    )


def test_exact_choreography_prepares_sequence_one_then_consumes_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    issuer = _Issuer(events)
    admission, approval_artifact, materials, approved_launch, owner = _inputs(tmp_path)
    _, retained = _install_choreography_fakes(monkeypatch, events)

    result = _run_choreography(
        issuer=issuer,
        admission=admission,
        approval_artifact=approval_artifact,
        materials=materials,
        approved_launch=approved_launch,
        owner=owner,
    )

    assert result is retained
    assert events == [
        "choreography_enter",
        "checkpoint",
        "sequence_one_prepare",
        "consume",
        "create",
        "source_start",
        "supervisor_start",
        "retire_inputs",
        "ordinal_one",
        "bind_preclaim",
        "claim_boundary",
        "claimed_fence",
        "sequence_one_close",
        "action_fence",
        "controller_admission",
        "sequence_two_prepare",
        "controller",
        "sequence_two_abort",
        "choreography_exit",
    ]
    assert events.index("sequence_one_prepare") < events.index("consume")
    assert events[events.index("consume") + 1] == "create"


@pytest.mark.parametrize(
    ("failure_stage", "expected_teardown"),
    [("create", "teardown_none"), ("source_start", "teardown_created")],
)
def test_preclaim_mutation_failure_closes_sequence_one_and_tears_down_inside_the_same_lease(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure_stage: str,
    expected_teardown: str,
) -> None:
    events: list[str] = []
    issuer = _Issuer(events, fail_at=failure_stage)
    admission, approval_artifact, materials, approved_launch, owner = _inputs(tmp_path)
    sequence_one, _ = _install_choreography_fakes(monkeypatch, events)

    with pytest.raises(_InjectedFailure):
        _run_choreography(
            issuer=issuer,
            admission=admission,
            approval_artifact=approval_artifact,
            materials=materials,
            approved_launch=approved_launch,
            owner=owner,
        )

    assert sequence_one.closed is True
    assert expected_teardown in events
    assert (
        events.index(expected_teardown)
        < events.index("sequence_one_close")
        < events.index("choreography_exit")
    )
    assert "claim_boundary" not in events
    assert "require_armed_recovery" not in events


def test_failed_consume_closes_prepared_sequence_one_without_entering_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    issuer = _Issuer(events)
    admission, approval_artifact, materials, approved_launch, owner = _inputs(tmp_path)
    sequence_one, _ = _install_choreography_fakes(
        monkeypatch,
        events,
        consume_result=False,
    )

    with pytest.raises(orchestrator.TrustedTimePostEnrollmentHostOrchestratorRejected):
        _run_choreography(
            issuer=issuer,
            admission=admission,
            approval_artifact=approval_artifact,
            materials=materials,
            approved_launch=approved_launch,
            owner=owner,
        )

    assert events == [
        "choreography_enter",
        "checkpoint",
        "sequence_one_prepare",
        "consume",
        "sequence_one_close",
        "choreography_exit",
    ]
    assert sequence_one.closed is True
    assert all(not event.startswith("teardown") for event in events)


def test_post_claim_failure_uses_only_armed_recovery_and_never_tears_down(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    issuer = _Issuer(events, armed_recovery=True)
    admission, approval_artifact, materials, approved_launch, owner = _inputs(tmp_path)
    _install_choreography_fakes(
        monkeypatch,
        events,
        claimed_failure=_InjectedFailure("after authoritative boundary"),
    )

    def retain(
        *,
        topology_issuer: _Issuer,
        recovery_retention_capability: object,
        **_: object,
    ) -> None:
        topology_issuer._require_armed_recovery_outcome_retention(
            topology_issuer.lease,
            recovery_retention_capability,
        )
        events.append("retain_recovery")
        raise _InjectedFailure("terminal recovery retained")

    monkeypatch.setattr(
        orchestrator,
        "retain_post_enrollment_start_recovery_required_outcome",
        retain,
    )

    with pytest.raises(_InjectedFailure, match="terminal recovery retained"):
        _run_choreography(
            issuer=issuer,
            admission=admission,
            approval_artifact=approval_artifact,
            materials=materials,
            approved_launch=approved_launch,
            owner=owner,
        )

    assert "claim_boundary" in events
    assert events[-5:] == [
        "classify_recovery",
        "require_armed_recovery",
        "retain_recovery",
        "sequence_one_close",
        "choreography_exit",
    ]
    assert all(not event.startswith("teardown") for event in events)


def test_post_claim_unarmed_failure_neither_tears_down_nor_claims_recovery_retention(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    issuer = _Issuer(events, armed_recovery=False)
    admission, approval_artifact, materials, approved_launch, owner = _inputs(tmp_path)
    _install_choreography_fakes(
        monkeypatch,
        events,
        claimed_failure=_InjectedFailure("after authoritative boundary"),
    )

    def retain(
        *,
        topology_issuer: _Issuer,
        recovery_retention_capability: object,
        **_: object,
    ) -> None:
        topology_issuer._require_armed_recovery_outcome_retention(
            topology_issuer.lease,
            recovery_retention_capability,
        )
        events.append("retain_recovery")

    monkeypatch.setattr(
        orchestrator,
        "retain_post_enrollment_start_recovery_required_outcome",
        retain,
    )

    with pytest.raises(_InjectedFailure, match="after authoritative boundary"):
        _run_choreography(
            issuer=issuer,
            admission=admission,
            approval_artifact=approval_artifact,
            materials=materials,
            approved_launch=approved_launch,
            owner=owner,
        )

    assert "claim_boundary" in events
    assert "classify_recovery" in events
    assert "require_armed_recovery" not in events
    assert "retain_recovery" not in events
    assert all(not event.startswith("teardown") for event in events)


def test_controller_entry_interruption_uses_armed_legacy_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    issuer = _Issuer(events)
    admission, approval_artifact, materials, approved_launch, owner = _inputs(tmp_path)
    _install_choreography_fakes(
        monkeypatch,
        events,
        controller_failure=KeyboardInterrupt(),
    )

    def retain(**_: object) -> None:
        events.append("retain_recovery")
        raise _InjectedFailure("terminal recovery retained")

    monkeypatch.setattr(
        orchestrator,
        "retain_post_enrollment_start_recovery_required_outcome",
        retain,
    )

    with pytest.raises(_InjectedFailure, match="terminal recovery retained"):
        _run_choreography(
            issuer=issuer,
            admission=admission,
            approval_artifact=approval_artifact,
            materials=materials,
            approved_launch=approved_launch,
            owner=owner,
        )

    assert events[-5:] == [
        "controller",
        "classify_recovery",
        "retain_recovery",
        "sequence_two_abort",
        "choreography_exit",
    ]
    assert "require_armed_recovery" not in events
    assert all(not event.startswith("teardown") for event in events)


@pytest.mark.parametrize("terminal_kind", ["success", "failure", "legacy"])
def test_host_callback_adopts_only_current_scope_receipt_after_controller_return_interruption(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    terminal_kind: str,
) -> None:
    events: list[str] = []
    admission, approval_artifact, materials, approved_launch, owner = _inputs(tmp_path)
    issuer = _Issuer(events)
    _install_choreography_fakes(monkeypatch, events)
    if terminal_kind == "success":
        retained: object = _RetainedOutcome(
            status=TrustedTimePostEnrollmentStartControllerOutcomeStatus.CONFIRMED
        )
    elif terminal_kind == "failure":
        retained = _RetainedOutcome(
            status=TrustedTimePostEnrollmentStartControllerOutcomeStatus.RECOVERY_REQUIRED
        )
        monkeypatch.setattr(
            orchestrator,
            "TrustedTimePostEnrollmentStartActiveControllerRecoveryRequired",
            _TerminalOutcomeSignal,
        )
    else:
        retained = _RetainedLegacyOutcome(status="recovery_required")
        monkeypatch.setattr(
            orchestrator,
            "RetainedTrustedTimePostEnrollmentStartOutcome",
            _RetainedLegacyOutcome,
        )
        monkeypatch.setattr(
            orchestrator,
            "TrustedTimePostEnrollmentStartRecoveryOutcomeRetained",
            _TerminalOutcomeSignal,
        )
    issuer.adopted_terminal = retained
    interrupted = False

    def completed_controller(**_: object) -> object:
        events.append("controller")
        events.append("controller_receipt_committed")
        return retained

    monkeypatch.setattr(
        orchestrator,
        "run_post_enrollment_start_active_controller",
        completed_controller,
    )
    run_scope = issuer._run_exclusive_choreography_with_recovery_retention

    def interrupt_host_call_return(callback: Any) -> object:
        nonlocal interrupted
        target_code = callback.__code__
        instructions = list(dis.get_instructions(target_code))
        load_index = next(
            index
            for index, instruction in enumerate(instructions)
            if instruction.opname == "LOAD_GLOBAL"
            and instruction.argval == "run_post_enrollment_start_active_controller"
        )
        call_index = next(
            index
            for index in range(load_index + 1, len(instructions))
            if instructions[index].opname == "CALL"
        )
        target_offset = instructions[call_index + 1].offset
        tool_id = next(
            candidate
            for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
            if sys.monitoring.get_tool(candidate) is None
        )
        sys.monitoring.use_tool_id(tool_id, "trusted-time-host-controller-return-test")

        def interrupt(code: object, instruction_offset: int) -> None:
            nonlocal interrupted
            if not interrupted and code is target_code and instruction_offset == target_offset:
                interrupted = True
                raise KeyboardInterrupt

        try:
            sys.monitoring.register_callback(
                tool_id,
                sys.monitoring.events.INSTRUCTION,
                interrupt,
            )
            sys.monitoring.set_local_events(
                tool_id,
                target_code,
                sys.monitoring.events.INSTRUCTION,
            )
            return run_scope(callback)
        finally:
            sys.monitoring.set_local_events(tool_id, target_code, 0)
            sys.monitoring.register_callback(tool_id, sys.monitoring.events.INSTRUCTION, None)
            sys.monitoring.free_tool_id(tool_id)

    monkeypatch.setattr(
        issuer,
        "_run_exclusive_choreography_with_recovery_retention",
        interrupt_host_call_return,
    )
    if terminal_kind == "success":
        returned = _run_choreography(
            issuer=issuer,
            admission=admission,
            approval_artifact=approval_artifact,
            materials=materials,
            approved_launch=approved_launch,
            owner=owner,
        )
        assert returned is retained
    else:
        with pytest.raises(_TerminalOutcomeSignal) as terminal:
            _run_choreography(
                issuer=issuer,
                admission=admission,
                approval_artifact=approval_artifact,
                materials=materials,
                approved_launch=approved_launch,
                owner=owner,
            )
        assert terminal.value.retained_outcome is retained

    assert interrupted is True
    assert events.count("adopt_terminal") == 1
    assert "classify_recovery" not in events


def test_host_callback_never_reclassifies_an_interrupted_current_scope_query(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    issuer = _Issuer(events)
    admission, approval_artifact, materials, approved_launch, owner = _inputs(tmp_path)
    _install_choreography_fakes(
        monkeypatch,
        events,
        controller_failure=RuntimeError("controller return is unavailable"),
    )

    def interrupt_query(*_: object, **__: object) -> object:
        events.append("adopt_terminal_interrupted")
        raise KeyboardInterrupt

    monkeypatch.setattr(
        issuer,
        "_adopt_registered_confirmed_terminal_outcome",
        interrupt_query,
    )

    with pytest.raises(KeyboardInterrupt):
        _run_choreography(
            issuer=issuer,
            admission=admission,
            approval_artifact=approval_artifact,
            materials=materials,
            approved_launch=approved_launch,
            owner=owner,
        )

    assert events.count("adopt_terminal_interrupted") == 1
    assert "classify_recovery" not in events


def test_host_async_adopter_interruption_is_retried_only_by_outer_exact_scope(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    retained = _RetainedOutcome(
        status=TrustedTimePostEnrollmentStartControllerOutcomeStatus.CONFIRMED
    )
    issuer = _Issuer(events, adopted_terminal=retained)
    admission, approval_artifact, materials, approved_launch, owner = _inputs(tmp_path)
    _install_choreography_fakes(
        monkeypatch,
        events,
        controller_failure=RuntimeError("controller return is unavailable"),
    )
    real_adopt = issuer._adopt_registered_confirmed_terminal_outcome
    adoption_attempts = 0

    def interrupt_once(*args: object, **kwargs: object) -> object:
        nonlocal adoption_attempts
        adoption_attempts += 1
        events.append("adopt_terminal_attempt")
        if adoption_attempts == 1:
            raise KeyboardInterrupt
        return real_adopt(*args, **kwargs)

    issuer._adopt_registered_confirmed_terminal_outcome = interrupt_once  # type: ignore[method-assign]

    def run_scope(callback: Any) -> object:
        try:
            return callback(issuer.lease, issuer.recovery)
        except BaseException:
            try:
                return issuer._adopt_registered_confirmed_terminal_outcome(
                    issuer.lease,
                    issuer.recovery,
                )
            finally:
                events.append("choreography_exit")

    issuer._run_exclusive_choreography_with_recovery_retention = run_scope  # type: ignore[method-assign]

    returned = _run_choreography(
        issuer=issuer,
        admission=admission,
        approval_artifact=approval_artifact,
        materials=materials,
        approved_launch=approved_launch,
        owner=owner,
    )

    assert returned is retained
    assert adoption_attempts == 2
    assert events.count("adopt_terminal") == 1
    assert "classify_recovery" not in events


def test_claim_boundary_call_store_interruption_never_reenables_preclaim_teardown(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    issuer = _Issuer(events, fail_at="claim_boundary", armed_recovery=False)
    admission, approval_artifact, materials, approved_launch, owner = _inputs(tmp_path)
    _install_choreography_fakes(monkeypatch, events)

    with pytest.raises(_InjectedFailure, match="claim_boundary"):
        _run_choreography(
            issuer=issuer,
            admission=admission,
            approval_artifact=approval_artifact,
            materials=materials,
            approved_launch=approved_launch,
            owner=owner,
        )

    assert "claim_boundary" in events
    assert "classify_recovery" in events
    assert "require_armed_recovery" not in events
    assert "retain_recovery" not in events
    assert all(not event.startswith("teardown") for event in events)
