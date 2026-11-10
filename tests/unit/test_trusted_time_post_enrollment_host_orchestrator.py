from __future__ import annotations

import dis
import hashlib
import inspect
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Never, cast

import pytest

from apps.trusted_time_supervisor.config import TrustedTimeSupervisorConfigurationError
from packages.adapters.trusted_time._owned_file_descriptor import (
    _acquire_trusted_time_launch_lock,
    _validate_trusted_time_launch_lock,
)
from scripts import trusted_time_post_enrollment_host_orchestrator as orchestrator
from scripts import trusted_time_post_enrollment_topology_reader as topology_reader
from scripts.start_trusted_time_supervisor import (
    LocalDockerDaemonIdentity,
    MaterializedDatabaseSecret,
    MaterializedHeadAnchorFile,
    MaterializedHeadAnchorInputs,
)
from scripts.trusted_time_post_enrollment_controller_outcome import (
    TrustedTimePostEnrollmentStartControllerOutcomeStatus,
)
from scripts.trusted_time_post_enrollment_execution_admission import (
    DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
)
from scripts.trusted_time_post_enrollment_topology_reader import (
    TrustedTimePostEnrollmentTopologyReaderError,
)
from scripts.verify_trusted_time_images import (
    DEFAULT_IMAGE_ADMISSION_ARTIFACT,
    IGNORED_ARTIFACT_ROOT,
)
from tests.unit import test_trusted_time_post_enrollment_topology_reader as topology_fixtures

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
        self.prepared_creation = object()
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

    def _prepare_reviewed_topology_creation(self, **kwargs: object) -> object:
        assert kwargs["_choreography_lease"] is self.lease
        database_secret = cast(Any, kwargs["database_secret_receipt"])
        head_anchor_inputs = cast(Any, kwargs["head_anchor_inputs_receipt"])
        assert database_secret.path == kwargs["expected_database_secret_file"]
        assert head_anchor_inputs.authority.path == kwargs["expected_head_anchor_authority_file"]
        self._event("prepare_create")
        return self.prepared_creation

    def _execute_prepared_reviewed_topology_creation(
        self,
        prepared_creation: object,
        **kwargs: object,
    ) -> object:
        assert prepared_creation is self.prepared_creation
        assert kwargs["_choreography_lease"] is self.lease
        self._event("execute_create")
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
            raise TrustedTimePostEnrollmentTopologyReaderError("no current-scope terminal")
        self.events.append("adopt_terminal")
        return self.adopted_terminal


def _inputs(tmp_path: Path) -> tuple[Any, Any, Any, Any, _Owner]:
    approval = SimpleNamespace(
        operation_id="123e4567-e89b-42d3-a456-426614174000",
        approval_sha256="a" * 64,
    )
    loaded_approval = SimpleNamespace(
        approval=approval,
        artifact_path=tmp_path / "approval.json",
        image_provenance=object(),
    )
    image_witness = SimpleNamespace(admission_sha256="4" * 64)
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
    return loaded_approval, image_witness, materials, approved_launch, _Owner()


def _real_runtime_materials(
    tmp_path: Path,
) -> tuple[orchestrator._RuntimeMaterials, tuple[Path, Path, Path, Path]]:
    root = tmp_path / "staged"
    root.mkdir(mode=0o700)
    paths = (
        root / (".database-secret-" + "1" * 32) / "database-url",
        root / (".head-anchor-authority-" + "2" * 32) / "head-anchor-authority.json",
        root / (".head-anchor-auth-" + "3" * 32) / "head-anchor-auth",
        root / (".head-anchor-signing-key-" + "4" * 32) / "head-anchor-signing-key",
    )
    payloads = (b"database", b"authority", b"auth-secret", b"s" * 32)
    metadata: list[tuple[Any, Any, bytes]] = []
    for path, payload in zip(paths, payloads, strict=True):
        path.parent.mkdir(mode=0o700)
        path.write_bytes(payload)
        path.chmod(0o400)
        metadata.append((path.parent.stat(), path.stat(), payload))

    directory, file, payload = metadata[0]
    database = MaterializedDatabaseSecret(
        root=root,
        ignored_root=tmp_path,
        directory=paths[0].parent,
        path=paths[0],
        directory_device=directory.st_dev,
        directory_inode=directory.st_ino,
        file_device=file.st_dev,
        file_inode=file.st_ino,
        size=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
    )
    head_files: list[MaterializedHeadAnchorFile] = []
    for path, kind, (directory, file, payload) in zip(
        paths[1:],
        ("authority", "auth", "signing-key"),
        metadata[1:],
        strict=True,
    ):
        head_files.append(
            MaterializedHeadAnchorFile(
                root=root,
                ignored_root=tmp_path,
                directory=path.parent,
                path=path,
                directory_device=directory.st_dev,
                directory_inode=directory.st_ino,
                file_device=file.st_dev,
                file_inode=file.st_ino,
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
                kind=kind,
            )
        )
    materials = orchestrator._RuntimeMaterials(
        database_url="postgresql://redacted.invalid/database",
        database_secret=database,
        head_anchor_inputs=MaterializedHeadAnchorInputs(
            authority=head_files[0],
            auth_secret=head_files[1],
            signing_key=head_files[2],
        ),
        sequence_two_configuration=cast(
            Any,
            SimpleNamespace(authority=object(), credentials=object(), verifier=object()),
        ),
    )
    return materials, paths


def _install_choreography_fakes(
    monkeypatch: pytest.MonkeyPatch,
    events: list[str],
    *,
    controller_failure: BaseException | None = None,
    claimed_failure: BaseException | None = None,
    consume_result: bool = True,
    reserve_failure: BaseException | None = None,
    expected_loaded_approval: Any | None = None,
    expected_image_witness: object | None = None,
) -> tuple[_SequenceOneIssuer, _RetainedOutcome]:
    sequence_one = _SequenceOneIssuer(events)
    retained = _RetainedOutcome()
    execution_admission = object()

    def prepare_sequence_one(**_: object) -> _SequenceOneIssuer:
        events.append("sequence_one_prepare")
        return sequence_one

    def reserve(**kwargs: object) -> object:
        if expected_loaded_approval is not None:
            assert kwargs["loaded_attested_approval"] is expected_loaded_approval
        if expected_image_witness is not None:
            assert kwargs["image_admission"] is expected_image_witness
        events.append("reserve")
        if reserve_failure is not None:
            raise reserve_failure
        return execution_admission

    def consume(admission: object, **kwargs: object) -> bool:
        assert admission is execution_admission
        if expected_loaded_approval is not None:
            assert (
                kwargs["operator_attested_approval_artifact"]
                == expected_loaded_approval.artifact_path
            )
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
        "reserve_post_enrollment_execution_attempt",
        reserve,
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
    approval = tmp_path / "operator-attested-approval.json"
    runtime = tmp_path / "runtime.env"

    parsed = orchestrator._parse_cli(
        [
            "--operator-attested-approval-artifact",
            str(approval),
            "--runtime-env-file",
            str(runtime),
        ]
    )

    assert parsed.operator_attested_approval_artifact == approval
    assert parsed.runtime_env_file == runtime
    with pytest.raises(SystemExit):
        orchestrator._parse_cli(["--operator-attested-approval-artifact", str(approval)])
    with pytest.raises(SystemExit):
        orchestrator._parse_cli(
            [
                "--operator-attested-approval-artifact",
                str(approval),
                "--runtime-env-file",
                str(runtime),
                "--shutdown-authorized",
            ]
        )
    with pytest.raises(SystemExit):
        orchestrator._parse_cli(
            ["--approval-artifact", str(approval), "--runtime-env-file", str(runtime)]
        )
    with pytest.raises(SystemExit):
        orchestrator._parse_cli(
            [
                "--operator-attested-approval-artif",
                str(approval),
                "--runtime-env-file",
                str(runtime),
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
        "reserve_post_enrollment_execution_attempt",
        unexpected_admission,
    )

    with pytest.raises(
        orchestrator.TrustedTimePostEnrollmentHostOrchestratorRejected,
        match="only through the isolated CLI",
    ):
        orchestrator.run_operator_attested_post_enrollment_start_once(
            operator_attested_approval_artifact=tmp_path / "operator-attested-approval.json",
            runtime_env_file=tmp_path / "runtime.env",
        )

    assert admitted is False


def test_operator_attested_entry_authenticates_before_every_effecting_preflight(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    operator_attested_approval_artifact = tmp_path / (
        "trusted-time-post-enrollment-start-execution-approval-v3-" + "1" * 64 + ".json"
    )
    runtime_env_file = tmp_path / "runtime.env"
    approval = object()
    loaded_attested_approval = SimpleNamespace(
        approval=approval,
        artifact_path=operator_attested_approval_artifact,
    )
    approved_revision = "f" * 40
    approved_launch = SimpleNamespace(git_revision=approved_revision)
    docker_environment = {"DOCKER_HOST": "unix:///validated-docker.sock"}
    daemon_identity = object()
    retained = object()

    class Issuer:
        pass

    issuer = Issuer()

    def require_sources(repository_root: Path) -> None:
        assert repository_root == tmp_path
        events.append("source_attestation")

    def load_attested(**kwargs: object) -> object:
        assert kwargs == {
            "operator_attested_approval_artifact": operator_attested_approval_artifact,
            "artifact_directory": DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
            "ignored_root": IGNORED_ARTIFACT_ROOT,
        }
        events.append("attested_v3_load")
        return loaded_attested_approval

    def approved(candidate: object) -> object:
        assert candidate is approval
        events.append("embedded_v2_semantics")
        return approved_launch

    def current_revision() -> str:
        events.append("current_head")
        return approved_revision

    def minimal_environment() -> dict[str, str]:
        events.append("docker_environment")
        return docker_environment

    def qualify(*, environment: dict[str, str]) -> object:
        assert environment is docker_environment
        events.append("docker_daemon")
        return daemon_identity

    def allocate_issuer() -> Issuer:
        events.append("issuer_allocate")
        return issuer

    def activate_issuer(candidate: object, **kwargs: object) -> None:
        assert candidate is issuer
        assert kwargs == {
            "expected_daemon_identity": daemon_identity,
            "docker_environment": docker_environment,
        }
        events.append("issuer_activate")

    def abort_issuer(candidate: object) -> None:
        assert candidate is issuer
        events.append("issuer_abort")

    def close_issuer(candidate: object) -> None:
        assert candidate is issuer
        events.append("issuer_close")

    def require_same(candidate: object, *, environment: dict[str, str]) -> None:
        assert candidate is daemon_identity
        assert environment is docker_environment
        events.append("same_daemon")

    def execute(**kwargs: object) -> object:
        assert kwargs == {
            "loaded_attested_approval": loaded_attested_approval,
            "runtime_env_file": runtime_env_file,
            "issuer": issuer,
            "daemon_identity": daemon_identity,
            "docker_environment": docker_environment,
        }
        events.append("runtime_preflight_and_choreography")
        return retained

    monkeypatch.setattr(orchestrator, "_CLI_REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(orchestrator, "_require_repository_first_party_sources", require_sources)
    monkeypatch.setattr(
        orchestrator,
        "load_post_enrollment_operator_attested_execution_approval",
        load_attested,
    )
    monkeypatch.setattr(orchestrator, "_approved_launch", approved)
    monkeypatch.setattr(orchestrator, "_current_git_revision", current_revision)
    monkeypatch.setattr(orchestrator, "_minimal_docker_environment", minimal_environment)
    monkeypatch.setattr(orchestrator, "qualify_local_docker_daemon", qualify)
    monkeypatch.setattr(orchestrator, "_require_same_local_daemon", require_same)
    monkeypatch.setattr(orchestrator, "_execute_under_issuer", execute)

    result = orchestrator._run_operator_attested_post_enrollment_start_once_with_dependencies(
        operator_attested_approval_artifact=operator_attested_approval_artifact,
        runtime_env_file=runtime_env_file,
        issuer_type=cast(Any, Issuer),
        allocate_inert_issuer=cast(Any, allocate_issuer),
        activate_issuer=activate_issuer,
        close_issuer=close_issuer,
        abort_issuer_activation=abort_issuer,
    )

    assert result is retained
    assert events == [
        "source_attestation",
        "attested_v3_load",
        "embedded_v2_semantics",
        "current_head",
        "docker_environment",
        "docker_daemon",
        "issuer_allocate",
        "issuer_activate",
        "same_daemon",
        "runtime_preflight_and_choreography",
        "issuer_close",
        "issuer_abort",
        "issuer_close",
        "issuer_abort",
        "issuer_close",
        "issuer_abort",
        "issuer_close",
        "issuer_abort",
        "issuer_close",
        "issuer_abort",
    ]


@pytest.mark.parametrize("interruption_point", ["activation_return", "host_call_store"])
@pytest.mark.parametrize("failure_type", [KeyboardInterrupt, SystemExit])
def test_host_activation_publication_interruption_burns_caller_owned_issuer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    interruption_point: str,
    failure_type: type[BaseException],
) -> None:
    operator_attested_approval_artifact = tmp_path / (
        "trusted-time-post-enrollment-start-execution-approval-v3-" + "1" * 64 + ".json"
    )
    runtime_env_file = tmp_path / "runtime.env"
    approval = object()
    loaded_attested_approval = SimpleNamespace(
        approval=approval,
        artifact_path=operator_attested_approval_artifact,
    )
    approved_revision = "f" * 40
    approved_launch = SimpleNamespace(git_revision=approved_revision)
    socket_path = topology_fixtures._short_socket_path(tmp_path)
    endpoint = f"unix://{socket_path}"
    docker_environment: dict[str, str] = {}
    daemon_identity = LocalDockerDaemonIdentity(
        context_name="<DOCKER_HOST>",
        endpoint=endpoint,
        daemon_id="LOCAL:DAEMON:1",
    )
    queued = topology_fixtures._QueuedRunner([topology_fixtures._json_line("LOCAL:DAEMON:1")])
    docker_executable, docker_executable_identity = (
        topology_reader._resolve_trusted_docker_executable()
    )
    ignored_root = tmp_path / "artifacts"
    issuer_type = topology_reader.TrustedTimePostEnrollmentTopologyObservationIssuer
    issuer = issuer_type.allocate_inert()
    exact_activate_method = topology_fixtures._test_only_authenticated_activation_closure()[0]
    activation_defaults = cast(dict[str, object], exact_activate_method.__kwdefaults__)
    monkeypatch.setitem(
        activation_defaults,
        "_resolve_docker",
        lambda: (docker_executable, docker_executable_identity),
    )
    monkeypatch.setitem(activation_defaults, "_runner", queued)
    monkeypatch.setitem(activation_defaults, "_session_token_factory", lambda: b"h" * 32)
    monkeypatch.setitem(activation_defaults, "_ignored_root_value", str(ignored_root))
    monkeypatch.setitem(
        activation_defaults,
        "_artifact_directory_value",
        str(ignored_root / "trusted-time"),
    )

    monkeypatch.setattr(orchestrator, "_CLI_REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(
        orchestrator,
        "_require_repository_first_party_sources",
        lambda _root: None,
    )
    monkeypatch.setattr(
        orchestrator,
        "load_post_enrollment_operator_attested_execution_approval",
        lambda **_kwargs: loaded_attested_approval,
    )
    monkeypatch.setattr(orchestrator, "_approved_launch", lambda _approval: approved_launch)
    monkeypatch.setattr(orchestrator, "_current_git_revision", lambda: approved_revision)
    monkeypatch.setattr(orchestrator, "_minimal_docker_environment", lambda: docker_environment)
    monkeypatch.setattr(
        orchestrator,
        "qualify_local_docker_daemon",
        lambda *, environment: daemon_identity,
    )
    monkeypatch.setattr(
        orchestrator,
        "_require_same_local_daemon",
        lambda *_args, **_kwargs: pytest.fail("post-activation work was reached"),
    )
    monkeypatch.setattr(
        orchestrator,
        "_execute_under_issuer",
        lambda **_kwargs: pytest.fail("effecting orchestration was reached"),
    )

    abort_calls = 0

    def allocate_issuer() -> topology_reader.TrustedTimePostEnrollmentTopologyObservationIssuer:
        return issuer

    def checked_abort(candidate: object) -> None:
        nonlocal abort_calls
        abort_calls += 1
        assert candidate is issuer
        topology_reader._abort_authenticated_issuer_activation(candidate)

    failure: BaseException = (
        SystemExit(53 if interruption_point == "host_call_store" else 59)
        if failure_type is SystemExit
        else KeyboardInterrupt()
    )
    host = orchestrator._run_operator_attested_post_enrollment_start_once_with_dependencies
    if interruption_point == "host_call_store":
        target_code = host.__code__
        target_offset = next(
            instruction.offset
            for instruction in dis.get_instructions(host)
            if instruction.opname == "STORE_FAST" and instruction.argval == "activation_result"
        )
        monitoring_event = sys.monitoring.events.INSTRUCTION

        def interrupt(*event_arguments: object) -> None:
            instruction_offset = cast(int, event_arguments[1])
            if instruction_offset != target_offset:
                return
            raise failure

    else:
        assert interruption_point == "activation_return"
        target_code = issuer_type.activate.__code__
        monitoring_event = sys.monitoring.events.PY_RETURN

        def interrupt(*_event_arguments: object) -> None:
            raise failure

    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )
    sys.monitoring.use_tool_id(tool_id, "trusted-time-host-activation-publication-test")
    try:
        sys.monitoring.register_callback(tool_id, monitoring_event, interrupt)
        sys.monitoring.set_local_events(tool_id, target_code, monitoring_event)
        with pytest.raises(failure_type) as retained_interruption:
            host(
                operator_attested_approval_artifact=operator_attested_approval_artifact,
                runtime_env_file=runtime_env_file,
                issuer_type=issuer_type,
                allocate_inert_issuer=allocate_issuer,
                activate_issuer=issuer_type.activate,
                close_issuer=issuer_type.close,
                abort_issuer_activation=checked_abort,
            )
    finally:
        sys.monitoring.set_local_events(tool_id, target_code, 0)
        sys.monitoring.register_callback(tool_id, monitoring_event, None)
        sys.monitoring.free_tool_id(tool_id)

    assert retained_interruption.value.__traceback__ is not None
    assert retained_interruption.value is failure
    assert abort_calls == 5
    assert queued.outputs == []
    assert issuer._launch_lock_lease is None
    saved_capability = issuer._authentication_capability
    with pytest.raises(topology_reader.TrustedTimePostEnrollmentTopologyReaderError):
        topology_reader._authenticated_issuer_runtime_provenance(
            issuer,
            saved_capability,
        )
    replacement = _acquire_trusted_time_launch_lock(str(ignored_root))
    _validate_trusted_time_launch_lock(replacement)
    replacement.close()
    with pytest.raises(topology_reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer.activate(
            expected_daemon_identity=daemon_identity,
            docker_environment=docker_environment,
        )


def test_operator_attested_entry_rejects_head_mismatch_before_preflight(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    artifact = tmp_path / (
        "trusted-time-post-enrollment-start-execution-approval-v3-" + "1" * 64 + ".json"
    )
    loaded = SimpleNamespace(approval=object(), artifact_path=artifact)

    def load_attested(**_: object) -> object:
        events.append("attested_v3_load")
        return loaded

    def approved(_: object) -> object:
        events.append("embedded_v2_semantics")
        return SimpleNamespace(git_revision="f" * 40)

    def current_revision() -> str:
        events.append("current_head")
        return "e" * 40

    monkeypatch.setattr(orchestrator, "_CLI_REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(
        orchestrator,
        "_require_repository_first_party_sources",
        lambda _: events.append("source_attestation"),
    )
    monkeypatch.setattr(
        orchestrator,
        "load_post_enrollment_operator_attested_execution_approval",
        load_attested,
    )
    monkeypatch.setattr(
        orchestrator,
        "_approved_launch",
        approved,
    )
    monkeypatch.setattr(
        orchestrator,
        "_current_git_revision",
        current_revision,
    )

    def unexpected_preflight(*_: object, **__: object) -> Never:
        events.append("unexpected_preflight")
        raise AssertionError("preflight ran after a HEAD mismatch")

    monkeypatch.setattr(orchestrator, "_minimal_docker_environment", unexpected_preflight)
    monkeypatch.setattr(orchestrator, "qualify_local_docker_daemon", unexpected_preflight)
    monkeypatch.setattr(orchestrator, "_execute_under_issuer", unexpected_preflight)

    with pytest.raises(
        orchestrator.TrustedTimePostEnrollmentHostOrchestratorRejected,
        match="approved revision is unavailable",
    ):
        orchestrator.run_operator_attested_post_enrollment_start_once(
            operator_attested_approval_artifact=artifact,
            runtime_env_file=tmp_path / "runtime.env",
        )

    assert events == [
        "source_attestation",
        "attested_v3_load",
        "embedded_v2_semantics",
        "current_head",
    ]


def test_legacy_v2_artifact_has_no_host_loader_or_api_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    legacy_v2_artifact = tmp_path / (
        "trusted-time-post-enrollment-start-execution-approval-" + "1" * 64 + ".json"
    )

    monkeypatch.setattr(orchestrator, "_CLI_REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(
        orchestrator,
        "_require_repository_first_party_sources",
        lambda _: events.append("source_attestation"),
    )

    def reject_legacy(**kwargs: object) -> Never:
        assert kwargs["operator_attested_approval_artifact"] == legacy_v2_artifact
        events.append("attested_v3_load")
        raise _InjectedFailure("legacy v2 artifact rejected")

    monkeypatch.setattr(
        orchestrator,
        "load_post_enrollment_operator_attested_execution_approval",
        reject_legacy,
    )

    def unexpected_preflight(*_: object, **__: object) -> Never:
        events.append("unexpected_preflight")
        raise AssertionError("legacy v2 fallback reached a preflight")

    monkeypatch.setattr(orchestrator, "_approved_launch", unexpected_preflight)
    monkeypatch.setattr(orchestrator, "_minimal_docker_environment", unexpected_preflight)
    monkeypatch.setattr(orchestrator, "qualify_local_docker_daemon", unexpected_preflight)
    monkeypatch.setattr(orchestrator, "_execute_under_issuer", unexpected_preflight)

    with pytest.raises(_InjectedFailure, match="legacy v2 artifact rejected"):
        orchestrator.run_operator_attested_post_enrollment_start_once(
            operator_attested_approval_artifact=legacy_v2_artifact,
            runtime_env_file=tmp_path / "runtime.env",
        )

    assert events == ["source_attestation", "attested_v3_load"]
    assert not hasattr(orchestrator, "load_post_enrollment_execution_approval")
    assert not hasattr(orchestrator, "run_approved_post_enrollment_start_once")
    assert "run_approved_post_enrollment_start_once" not in orchestrator.__all__
    assert tuple(
        inspect.signature(orchestrator.run_operator_attested_post_enrollment_start_once).parameters
    ) == ("operator_attested_approval_artifact", "runtime_env_file")


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

    assert (
        orchestrator.POST_ENROLLMENT_HOST_ORCHESTRATOR_CONTRACT_VERSION
        == "phase6d-post-enrollment-start-host-orchestrator-v3"
    )
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
    approval_artifact = tmp_path / "operator-attested-approval.json"
    runtime_env_file = tmp_path / "runtime.env"
    monkeypatch.setattr(
        orchestrator,
        "load_post_enrollment_operator_attested_execution_approval",
        lambda **_: SimpleNamespace(approval=_Approval()),
    )
    monkeypatch.setattr(
        orchestrator,
        "run_operator_attested_post_enrollment_start_once",
        lambda **_: (_ for _ in ()).throw(
            orchestrator.TrustedTimePostEnrollmentHostOrchestratorRejected(
                "topology issuer close is unconfirmed"
            )
        ),
    )

    with pytest.raises(SystemExit) as terminal:
        orchestrator.main(
            [
                "--operator-attested-approval-artifact",
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
        "load_post_enrollment_operator_attested_execution_approval",
        lambda **_: SimpleNamespace(approval=approval),
    )
    monkeypatch.setattr(
        orchestrator,
        "run_operator_attested_post_enrollment_start_once",
        lambda **_: (_ for _ in ()).throw(terminal_type(outcome)),
    )

    with pytest.raises(SystemExit) as terminal:
        orchestrator.main(
            [
                "--operator-attested-approval-artifact",
                str(tmp_path / "approval.json"),
                "--runtime-env-file",
                str(tmp_path / "runtime.env"),
            ]
        )

    assert terminal.value.code == exit_code
    assert json.loads(capsys.readouterr().out) == orchestrator._safe_terminal_payload(
        cast(Any, outcome)
    )


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


def test_compose_validation_issues_the_exact_jit_witness_after_reversible_checks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    _, _, materials, _, _ = _inputs(tmp_path)
    identities = object()
    approved_launch = SimpleNamespace(
        git_revision="f" * 40,
        source_image_id="sha256:" + "2" * 64,
        supervisor_image_id="sha256:" + "3" * 64,
        identities=identities,
    )
    daemon_identity = object()
    docker_environment = {"DOCKER_HOST": "unix:///validated-docker.sock"}
    rendered = object()
    image_witness = SimpleNamespace(identities=identities)

    monkeypatch.setattr(
        orchestrator,
        "_current_git_revision",
        lambda: approved_launch.git_revision,
    )

    def require_same(candidate: object, *, environment: dict[str, str]) -> None:
        assert candidate is daemon_identity
        assert environment is docker_environment
        events.append("same_daemon")

    def reviewed(revision: str, path: str) -> bytes:
        assert revision == approved_launch.git_revision
        assert path == "infra/compose/trusted-time.compose.yaml"
        events.append("reviewed_compose")
        return b"reviewed-compose"

    def render(**kwargs: object) -> object:
        assert kwargs == {
            "source_image": approved_launch.source_image_id,
            "supervisor_image": approved_launch.supervisor_image_id,
            "database_secret_file": materials.database_secret.path,
            "head_anchor_authority_file": materials.head_anchor_inputs.authority.path,
            "head_anchor_auth_secret_file": materials.head_anchor_inputs.auth_secret.path,
            "head_anchor_signing_key_secret_file": materials.head_anchor_inputs.signing_key.path,
            "compose_payload": b"validated-compose",
            "docker_environment": docker_environment,
        }
        events.append("render")
        return rendered

    def validate_model(candidate: object, **kwargs: object) -> None:
        assert candidate is rendered
        assert kwargs["expected_source_image"] == approved_launch.source_image_id
        assert kwargs["expected_supervisor_image"] == approved_launch.supervisor_image_id
        events.append("validate_model")

    def witness(
        artifact_path: Path,
        source_image_id: str,
        supervisor_image_id: str,
        **kwargs: object,
    ) -> object:
        assert artifact_path == DEFAULT_IMAGE_ADMISSION_ARTIFACT
        assert source_image_id == approved_launch.source_image_id
        assert supervisor_image_id == approved_launch.supervisor_image_id
        assert kwargs == {
            "ignored_root": IGNORED_ARTIFACT_ROOT,
            "docker_environment": docker_environment,
        }
        events.append("jit_witness")
        return image_witness

    monkeypatch.setattr(orchestrator, "_require_same_local_daemon", require_same)
    monkeypatch.setattr(orchestrator, "_head_reviewed_input_payload", reviewed)
    monkeypatch.setattr(
        orchestrator,
        "_validate_runtime_compose_payload",
        lambda payload: b"validated-compose" if payload == b"reviewed-compose" else None,
    )
    monkeypatch.setattr(orchestrator, "render_compose_model", render)
    monkeypatch.setattr(orchestrator, "validate_compose_model", validate_model)
    monkeypatch.setattr(
        orchestrator,
        "validate_materialized_database_secret",
        lambda candidate: events.append("validate_database_secret"),
    )
    monkeypatch.setattr(
        orchestrator,
        "validate_materialized_trusted_time_head_anchor_inputs",
        lambda candidate: events.append("validate_head_inputs"),
    )
    monkeypatch.setattr(
        orchestrator,
        "verify_and_write_existing_image_admission",
        witness,
    )

    compose_payload, returned_witness = orchestrator._validate_compose(
        approved_launch=cast(Any, approved_launch),
        daemon_identity=cast(Any, daemon_identity),
        docker_environment=docker_environment,
        materials=cast(Any, materials),
    )

    assert compose_payload == b"validated-compose"
    assert cast(Any, returned_witness) is image_witness
    assert events == [
        "same_daemon",
        "reviewed_compose",
        "render",
        "validate_model",
        "validate_database_secret",
        "validate_head_inputs",
        "jit_witness",
        "same_daemon",
        "validate_database_secret",
        "validate_head_inputs",
    ]


@pytest.mark.parametrize("path_index", [0, 1])
def test_post_witness_same_bytes_inode_replacement_fails_before_choreography(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    path_index: int,
) -> None:
    materials, paths = _real_runtime_materials(tmp_path)
    identities = object()
    approved_launch = SimpleNamespace(
        git_revision="f" * 40,
        source_image_id="sha256:" + "2" * 64,
        supervisor_image_id="sha256:" + "3" * 64,
        identities=identities,
    )
    image_witness = SimpleNamespace(identities=identities)
    events: list[str] = []

    monkeypatch.setattr(
        orchestrator,
        "_current_git_revision",
        lambda: approved_launch.git_revision,
    )
    monkeypatch.setattr(orchestrator, "_require_same_local_daemon", lambda *_a, **_k: None)
    monkeypatch.setattr(orchestrator, "_head_reviewed_input_payload", lambda *_a: b"compose")
    monkeypatch.setattr(orchestrator, "_validate_runtime_compose_payload", lambda value: value)
    monkeypatch.setattr(orchestrator, "render_compose_model", lambda **_: object())
    monkeypatch.setattr(orchestrator, "validate_compose_model", lambda *_a, **_k: None)

    def replace_after_jit(*_: object, **__: object) -> object:
        path = paths[path_index]
        replacement = path.with_name(path.name + ".replacement")
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(0o400)
        original_inode = path.stat().st_ino
        path.unlink()
        replacement.rename(path)
        assert path.stat().st_ino != original_inode
        events.append("jit_witness_returned")
        return image_witness

    monkeypatch.setattr(
        orchestrator,
        "verify_and_write_existing_image_admission",
        replace_after_jit,
    )
    monkeypatch.setattr(
        orchestrator,
        "reserve_post_enrollment_execution_attempt",
        lambda **_: (_ for _ in ()).throw(AssertionError("attempt slot reserved")),
    )

    with pytest.raises(TrustedTimeSupervisorConfigurationError):
        orchestrator._validate_compose(
            approved_launch=cast(Any, approved_launch),
            daemon_identity=cast(Any, object()),
            docker_environment={"DOCKER_HOST": "unix:///validated-docker.sock"},
            materials=materials,
        )

    assert events == ["jit_witness_returned"]


@pytest.mark.parametrize("failure_stage", ["runtime_preflight", "jit_witness"])
def test_outer_reversible_failure_never_enters_choreography_or_reserves_attempt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure_stage: str,
) -> None:
    events: list[str] = []
    loaded_approval, _, materials, approved_launch, _ = _inputs(tmp_path)

    class RecordingOwner:
        def _retire_all_confirmed(self) -> None:
            events.append("retire_inputs")

    def materialize(**_: object) -> object:
        events.append("runtime_preflight")
        if failure_stage == "runtime_preflight":
            raise _InjectedFailure(failure_stage)
        return materials

    def validate(**_: object) -> object:
        events.append("jit_witness")
        raise _InjectedFailure(failure_stage)

    def unexpected(**_: object) -> object:
        events.append("unexpected_effecting_path")
        raise AssertionError("effecting path entered")

    monkeypatch.setattr(orchestrator, "_MaterializedRuntimeInputOwner", RecordingOwner)
    monkeypatch.setattr(orchestrator, "_materialize_runtime_inputs", materialize)
    monkeypatch.setattr(orchestrator, "_approved_launch", lambda _: approved_launch)
    monkeypatch.setattr(orchestrator, "_validate_compose", validate)
    monkeypatch.setattr(orchestrator, "_run_post_enrollment_choreography", unexpected)
    monkeypatch.setattr(
        orchestrator,
        "reserve_post_enrollment_execution_attempt",
        unexpected,
    )

    execute = cast(Any, orchestrator._execute_under_issuer)
    with pytest.raises(_InjectedFailure, match=failure_stage):
        execute(
            loaded_attested_approval=loaded_approval,
            runtime_env_file=tmp_path / "runtime.env",
            issuer=object(),
            daemon_identity=object(),
            docker_environment={"DOCKER_HOST": "unix:///validated-docker.sock"},
        )

    assert events[-1] == "retire_inputs"
    assert "unexpected_effecting_path" not in events


def _run_choreography(
    *,
    issuer: _Issuer,
    loaded_approval: object,
    image_witness: object,
    materials: object,
    approved_launch: object,
    owner: _Owner,
) -> object:
    run = cast(Any, orchestrator._run_post_enrollment_choreography)
    return run(
        loaded_attested_approval=loaded_approval,
        image_witness=image_witness,
        materials=materials,
        owner=owner,
        approved_launch=approved_launch,
        compose_payload=b"reviewed-compose",
        issuer=issuer,
    )


def _interrupt_after_callback_call(
    issuer: _Issuer,
    callable_name: str,
) -> tuple[Any, SimpleNamespace]:
    run_scope = issuer._run_exclusive_choreography_with_recovery_retention
    state = SimpleNamespace(interrupted=False)

    def interrupt_call_store(callback: Any) -> object:
        target_code = callback.__code__
        instructions = list(dis.get_instructions(target_code))
        load_index = next(
            index
            for index, instruction in enumerate(instructions)
            if instruction.argval == callable_name
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
        sys.monitoring.use_tool_id(tool_id, f"trusted-time-{callable_name}-return-test")

        def interrupt(code: object, instruction_offset: int) -> None:
            if (
                not state.interrupted
                and code is target_code
                and instruction_offset == target_offset
            ):
                state.interrupted = True
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

    return interrupt_call_store, state


def test_exact_choreography_prepares_sequence_one_then_consumes_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    issuer = _Issuer(events)
    loaded_approval, image_witness, materials, approved_launch, owner = _inputs(tmp_path)
    _, retained = _install_choreography_fakes(
        monkeypatch,
        events,
        expected_loaded_approval=loaded_approval,
        expected_image_witness=image_witness,
    )

    result = _run_choreography(
        issuer=issuer,
        loaded_approval=loaded_approval,
        image_witness=image_witness,
        materials=materials,
        approved_launch=approved_launch,
        owner=owner,
    )

    assert result is retained
    assert events == [
        "choreography_enter",
        "checkpoint",
        "sequence_one_prepare",
        "prepare_create",
        "reserve",
        "consume",
        "execute_create",
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
    assert events.index("sequence_one_prepare") < events.index("prepare_create")
    assert events[events.index("prepare_create") + 1 : events.index("execute_create") + 1] == [
        "reserve",
        "consume",
        "execute_create",
    ]


@pytest.mark.parametrize("failure_stage", ["prepare_create", "reserve"])
def test_reversible_fence_and_reservation_failures_close_sequence_one_without_create(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure_stage: str,
) -> None:
    events: list[str] = []
    issuer = _Issuer(
        events,
        fail_at="prepare_create" if failure_stage == "prepare_create" else None,
    )
    loaded_approval, image_witness, materials, approved_launch, owner = _inputs(tmp_path)
    sequence_one, _ = _install_choreography_fakes(
        monkeypatch,
        events,
        reserve_failure=(_InjectedFailure("reserve") if failure_stage == "reserve" else None),
    )

    with pytest.raises(_InjectedFailure, match=failure_stage):
        _run_choreography(
            issuer=issuer,
            loaded_approval=loaded_approval,
            image_witness=image_witness,
            materials=materials,
            approved_launch=approved_launch,
            owner=owner,
        )

    assert sequence_one.closed is True
    assert "execute_create" not in events
    assert all(not event.startswith("teardown") for event in events)
    if failure_stage == "prepare_create":
        assert "reserve" not in events
    else:
        assert "reserve" in events


def test_reservation_call_store_interruption_preserves_slot_but_never_creates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    issuer = _Issuer(events)
    loaded_approval, image_witness, materials, approved_launch, owner = _inputs(tmp_path)
    sequence_one, _ = _install_choreography_fakes(monkeypatch, events)
    permanent_slot_receipt = object()

    def reserve(**kwargs: object) -> object:
        assert kwargs["loaded_attested_approval"] is loaded_approval
        assert kwargs["image_admission"] is image_witness
        events.append("reserve_slot_committed")
        return permanent_slot_receipt

    monkeypatch.setattr(
        orchestrator,
        "reserve_post_enrollment_execution_attempt",
        reserve,
    )
    interrupting_scope, state = _interrupt_after_callback_call(
        issuer,
        "reserve_post_enrollment_execution_attempt",
    )
    monkeypatch.setattr(
        issuer,
        "_run_exclusive_choreography_with_recovery_retention",
        interrupting_scope,
    )

    with pytest.raises(KeyboardInterrupt):
        _run_choreography(
            issuer=issuer,
            loaded_approval=loaded_approval,
            image_witness=image_witness,
            materials=materials,
            approved_launch=approved_launch,
            owner=owner,
        )

    assert state.interrupted is True
    assert sequence_one.closed is True
    assert "reserve_slot_committed" in events
    assert "consume" not in events
    assert "execute_create" not in events
    assert all(not event.startswith("teardown") for event in events)


def test_consume_call_store_interruption_preserves_consumption_but_never_creates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    issuer = _Issuer(events)
    loaded_approval, image_witness, materials, approved_launch, owner = _inputs(tmp_path)
    sequence_one, _ = _install_choreography_fakes(monkeypatch, events)

    def consume(admission: object, **kwargs: object) -> bool:
        assert admission is not None
        assert kwargs["operator_attested_approval_artifact"] == loaded_approval.artifact_path
        events.append("consume_committed")
        return True

    monkeypatch.setattr(
        orchestrator,
        "_consume_post_enrollment_execution_admission",
        consume,
    )
    interrupting_scope, state = _interrupt_after_callback_call(
        issuer,
        "_consume_post_enrollment_execution_admission",
    )
    monkeypatch.setattr(
        issuer,
        "_run_exclusive_choreography_with_recovery_retention",
        interrupting_scope,
    )

    with pytest.raises(KeyboardInterrupt):
        _run_choreography(
            issuer=issuer,
            loaded_approval=loaded_approval,
            image_witness=image_witness,
            materials=materials,
            approved_launch=approved_launch,
            owner=owner,
        )

    assert state.interrupted is True
    assert sequence_one.closed is True
    assert "consume_committed" in events
    assert "execute_create" not in events
    assert all(not event.startswith("teardown") for event in events)


def test_execute_call_store_interruption_tears_down_with_created_none_under_same_lease(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    issuer = _Issuer(events)
    loaded_approval, image_witness, materials, approved_launch, owner = _inputs(tmp_path)
    sequence_one, _ = _install_choreography_fakes(monkeypatch, events)
    interrupting_scope, state = _interrupt_after_callback_call(
        issuer,
        "_execute_prepared_reviewed_topology_creation",
    )
    monkeypatch.setattr(
        issuer,
        "_run_exclusive_choreography_with_recovery_retention",
        interrupting_scope,
    )

    with pytest.raises(KeyboardInterrupt):
        _run_choreography(
            issuer=issuer,
            loaded_approval=loaded_approval,
            image_witness=image_witness,
            materials=materials,
            approved_launch=approved_launch,
            owner=owner,
        )

    assert state.interrupted is True
    assert sequence_one.closed is True
    assert events[events.index("execute_create") + 1 : events.index("sequence_one_close")] == [
        "teardown_none"
    ]
    assert events.count("teardown_none") == 1
    assert "source_start" not in events


@pytest.mark.parametrize(
    ("failure_stage", "expected_teardown"),
    [("execute_create", "teardown_none"), ("source_start", "teardown_created")],
)
def test_preclaim_mutation_failure_closes_sequence_one_and_tears_down_inside_the_same_lease(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure_stage: str,
    expected_teardown: str,
) -> None:
    events: list[str] = []
    issuer = _Issuer(events, fail_at=failure_stage)
    loaded_approval, image_witness, materials, approved_launch, owner = _inputs(tmp_path)
    sequence_one, _ = _install_choreography_fakes(monkeypatch, events)

    with pytest.raises(_InjectedFailure):
        _run_choreography(
            issuer=issuer,
            loaded_approval=loaded_approval,
            image_witness=image_witness,
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
    loaded_approval, image_witness, materials, approved_launch, owner = _inputs(tmp_path)
    sequence_one, _ = _install_choreography_fakes(
        monkeypatch,
        events,
        consume_result=False,
    )

    with pytest.raises(orchestrator.TrustedTimePostEnrollmentHostOrchestratorRejected):
        _run_choreography(
            issuer=issuer,
            loaded_approval=loaded_approval,
            image_witness=image_witness,
            materials=materials,
            approved_launch=approved_launch,
            owner=owner,
        )

    assert events == [
        "choreography_enter",
        "checkpoint",
        "sequence_one_prepare",
        "prepare_create",
        "reserve",
        "consume",
        "sequence_one_close",
        "choreography_exit",
    ]
    assert sequence_one.closed is True
    assert "execute_create" not in events
    assert all(not event.startswith("teardown") for event in events)


def test_post_claim_failure_uses_only_armed_recovery_and_never_tears_down(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    issuer = _Issuer(events, armed_recovery=True)
    loaded_approval, image_witness, materials, approved_launch, owner = _inputs(tmp_path)
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
            loaded_approval=loaded_approval,
            image_witness=image_witness,
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
    loaded_approval, image_witness, materials, approved_launch, owner = _inputs(tmp_path)
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
            loaded_approval=loaded_approval,
            image_witness=image_witness,
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
    loaded_approval, image_witness, materials, approved_launch, owner = _inputs(tmp_path)
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
            loaded_approval=loaded_approval,
            image_witness=image_witness,
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
    loaded_approval, image_witness, materials, approved_launch, owner = _inputs(tmp_path)
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
            loaded_approval=loaded_approval,
            image_witness=image_witness,
            materials=materials,
            approved_launch=approved_launch,
            owner=owner,
        )
        assert returned is retained
    else:
        with pytest.raises(_TerminalOutcomeSignal) as terminal:
            _run_choreography(
                issuer=issuer,
                loaded_approval=loaded_approval,
                image_witness=image_witness,
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
    loaded_approval, image_witness, materials, approved_launch, owner = _inputs(tmp_path)
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
            loaded_approval=loaded_approval,
            image_witness=image_witness,
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
    loaded_approval, image_witness, materials, approved_launch, owner = _inputs(tmp_path)
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
        loaded_approval=loaded_approval,
        image_witness=image_witness,
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
    loaded_approval, image_witness, materials, approved_launch, owner = _inputs(tmp_path)
    _install_choreography_fakes(monkeypatch, events)

    with pytest.raises(_InjectedFailure, match="claim_boundary"):
        _run_choreography(
            issuer=issuer,
            loaded_approval=loaded_approval,
            image_witness=image_witness,
            materials=materials,
            approved_launch=approved_launch,
            owner=owner,
        )

    assert "claim_boundary" in events
    assert "classify_recovery" in events
    assert "require_armed_recovery" not in events
    assert "retain_recovery" not in events
    assert all(not event.startswith("teardown") for event in events)
