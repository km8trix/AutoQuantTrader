from __future__ import annotations

import copy
import gc
import inspect
import os
import pickle
import sys
import threading
import weakref
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import scripts.trusted_time_post_enrollment_sequence_one_reauthentication as issuer_module
from apps.trusted_time_supervisor.head_anchor_attempt import (
    TrustedTimeHeadAnchorFirstEnrollmentPostcondition,
)
from apps.trusted_time_supervisor.head_anchor_config import TrustedTimeHeadAnchorAuthority
from packages.adapters.trusted_time.ed25519_anchor import (
    Ed25519TrustedTimeAnchorVerifier,
    ed25519_public_key_sha256,
)
from packages.adapters.trusted_time.supabase_storage_anchor import (
    SupabaseStorageAnchorCredentials,
)
from packages.application.trusted_time_head_anchor import (
    TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
    TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
    TrustedTimeHeadAnchorCheckpointReason,
)
from packages.persistence.trusted_time_head_anchor import (
    TrustedTimeHeadAnchorPersistenceSnapshot,
)
from scripts.trusted_time_post_enrollment_sequence_one_reauthentication import (
    POST_ENROLLMENT_SEQUENCE_ONE_REAUTHENTICATION_CONTRACT_VERSION,
    POST_ENROLLMENT_SEQUENCE_ONE_REAUTHENTICATION_RESERVE_NANOSECONDS,
    TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer,
    TrustedTimePostEnrollmentSequenceOneReauthenticationRejected,
    _build_trusted_time_post_enrollment_sequence_one_reauthentication_preparer,
    _build_trusted_time_post_enrollment_sequence_one_reauthentication_preparer_with_registry,
    _PreparationBinding,
    _ReadOnlyConfiguration,
)

_RUNTIME_PROJECT_REF = "a" * 20
_ANCHOR_PROJECT_REF = "b" * 20
_DATABASE_URL = (
    "postgresql+psycopg://postgres."
    f"{_RUNTIME_PROJECT_REF}:test-password@aws-0-test.pooler.supabase.com:5432/"
    "postgres?sslmode=verify-full"
)
_ARTIFACT_ROOT = Path("/tmp/sequence-one-reauthentication-test-artifacts")
_ARTIFACT_DIRECTORY = _ARTIFACT_ROOT / "trusted-time"


class _FakeIssuer:
    def __init__(self) -> None:
        self.monotonic_clock: _Clock | None = None
        self.clock_requests = 0

    def _bound_choreography_monotonic_clock(self) -> _Clock:
        self.clock_requests += 1
        if self.monotonic_clock is None:
            raise AssertionError("issuer clock was not installed")
        return self.monotonic_clock


class _TupleMember:
    pass


@dataclass
class _Clock:
    value: int

    def __call__(self) -> int:
        return self.value


class _FakeResources:
    def __init__(self, closed: list[str], close_error: BaseException | None = None) -> None:
        self.closed = closed
        self.close_error = close_error

    def close(self) -> None:
        self.closed.append("closed")
        if self.close_error is not None:
            raise self.close_error


def _configuration() -> _ReadOnlyConfiguration:
    public_key = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    public_key_sha256 = ed25519_public_key_sha256(public_key)
    authority = TrustedTimeHeadAnchorAuthority(
        anchor_authority_sha256="1" * 64,
        deployment_identity_sha256="2" * 64,
        host_id="trusted-time-host",
        source_authority_sha256="3" * 64,
        runtime_database_project_ref=_RUNTIME_PROJECT_REF,
        runtime_database_identity_sha256="4" * 64,
        anchor_project_ref=_ANCHOR_PROJECT_REF,
        anchor_project_url=f"https://{_ANCHOR_PROJECT_REF}.supabase.co",
        anchor_project_identity_sha256="5" * 64,
        bucket_name=TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
        principal_id="11111111-1111-4111-8111-111111111111",
        signing_key_id="anchor.key.v1",
        signing_public_key_sha256=public_key_sha256,
        signing_public_key_bytes=public_key,
    )
    credentials = SupabaseStorageAnchorCredentials(
        project_url=authority.anchor_project_url,
        publishable_key="sb_publishable_" + "P" * 32,
        principal_id=authority.principal_id,
        anchor_project_identity_sha256=authority.anchor_project_identity_sha256,
        email="sequence-one@example.invalid",
        password="S" * 32,
    )
    verifier = Ed25519TrustedTimeAnchorVerifier.from_public_key_bytes(
        signing_key_id=authority.signing_key_id,
        expected_signing_public_key_sha256=authority.signing_public_key_sha256,
        public_key_bytes=public_key,
    )
    return _ReadOnlyConfiguration(
        authority=authority,
        credentials=credentials,
        verifier=verifier,
    )


def _postcondition() -> TrustedTimeHeadAnchorFirstEnrollmentPostcondition:
    configuration = _configuration()
    authority = configuration.authority
    return TrustedTimeHeadAnchorFirstEnrollmentPostcondition(
        anchor_sequence=1,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT,
        confirmed_anchor_count=1,
        local_transition_count=1,
        confirmed_anchor_local_transition_ordinal=1,
        remote_object_count=1,
        current_host_head_sha256="6" * 64,
        current_anchor_sha256="7" * 64,
        current_anchor_semantic_sha256="8" * 64,
        anchor_intent_semantic_sha256="9" * 64,
        candidate_remote_readback_sha256="7" * 64,
        receipt_semantic_sha256="a" * 64,
        remote_namespace_sha256="b" * 64,
        anchor_authority_sha256=authority.anchor_authority_sha256,
        deployment_identity_sha256=authority.deployment_identity_sha256,
        runtime_database_identity_sha256=authority.runtime_database_identity_sha256,
        anchor_project_identity_sha256=authority.anchor_project_identity_sha256,
        source_authority_sha256=authority.source_authority_sha256,
        signing_public_key_sha256=authority.signing_public_key_sha256,
        host_identity_sha256="c" * 64,
        principal_identity_sha256="d" * 64,
        bucket_identity_sha256="e" * 64,
        full_audit_completed=True,
        pending_intent_present=False,
    )


def _harness(
    *,
    runner_error: BaseException | None = None,
    factory_error: BaseException | None = None,
    close_error: BaseException | None = None,
    clock: _Clock | None = None,
    use_issuer_clock: bool = False,
    process_id: object | None = None,
    current_thread: object | None = None,
) -> tuple[
    TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer,
    dict[str, object],
]:
    topology_issuer = _FakeIssuer()
    lease = _TupleMember()
    recovery = _TupleMember()
    exact_clock = _Clock(1_000_000_000) if clock is None else clock
    topology_issuer.monotonic_clock = exact_clock
    closed: list[str] = []
    constructed: list[str] = []
    deadlines: list[int] = []
    validations: list[int] = []
    configuration = _configuration()

    def preparation_validator(**_: object) -> _PreparationBinding:
        return _PreparationBinding(
            origin_sha256="f" * 64,
            payload={"session_sha256": "0" * 64},
        )

    def call_validator(**_: object) -> None:
        validations.append(1)

    def resource_factory(*, owner: object, **_: object) -> _FakeResources:
        constructed.append("constructed")
        resources = _FakeResources(closed, close_error)
        cast(Any, owner).register(resources.close)
        if factory_error is not None:
            raise factory_error
        return resources

    def reauthentication_runner(
        resources: object,
        guard: object,
    ) -> TrustedTimeHeadAnchorFirstEnrollmentPostcondition:
        assert type(resources) is _FakeResources
        exact_guard = cast(Any, guard)
        deadlines.append(exact_guard.deadline_monotonic_ns)
        exact_guard.require_remaining()
        if runner_error is not None:
            raise runner_error
        return _postcondition()

    dependencies: dict[str, object] = {
        "preparation_validator": preparation_validator,
        "call_validator": call_validator,
        "resource_factory": resource_factory,
        "reauthentication_runner": reauthentication_runner,
    }
    if not use_issuer_clock:
        dependencies["monotonic_ns"] = exact_clock
    if process_id is not None:
        dependencies["process_id"] = process_id
    if current_thread is not None:
        dependencies["current_thread"] = current_thread
    prepare = _build_trusted_time_post_enrollment_sequence_one_reauthentication_preparer(
        **dependencies
    )
    deadline = 300_000_000_000
    issuer = prepare(
        database_url=_DATABASE_URL,
        authority=configuration.authority,
        credentials=configuration.credentials,
        verifier=configuration.verifier,
        topology_issuer=topology_issuer,
        choreography_lease=lease,
        recovery_retention_capability=recovery,
        action_deadline_monotonic_ns=deadline,
        artifact_directory=_ARTIFACT_DIRECTORY,
        ignored_root=_ARTIFACT_ROOT,
    )
    observations: dict[str, object] = {
        "closed": closed,
        "constructed": constructed,
        "deadline": deadline,
        "deadlines": deadlines,
        "prepare": prepare,
        "configuration": configuration,
        "topology_issuer": topology_issuer,
        "tuple_references": (
            weakref.ref(topology_issuer),
            weakref.ref(lease),
            weakref.ref(recovery),
        ),
        "validations": validations,
    }
    return issuer, observations


def test_configuration_is_exact_digest_only_and_redacts_credentials() -> None:
    configuration = _configuration()

    rendered = repr(configuration)
    assert "sequence-one@example.invalid" not in rendered
    assert "sb_publishable_" not in rendered
    assert "S" * 32 not in rendered
    assert len(configuration.configuration_sha256) == 64
    assert configuration.configuration_sha256 == configuration.configuration_sha256
    assert POST_ENROLLMENT_SEQUENCE_ONE_REAUTHENTICATION_CONTRACT_VERSION.endswith(
        "read-only-reauthentication-v1"
    )


def test_public_preparer_seals_only_production_dependencies_and_issuer_clock() -> None:
    dependencies = inspect.getclosurevars(
        issuer_module.prepare_trusted_time_post_enrollment_sequence_one_reauthentication_issuer
    ).nonlocals

    assert dependencies["preparation_validator"] is issuer_module._prepare_exact_binding
    assert dependencies["call_validator"] is issuer_module._revalidate_exact_call
    assert dependencies["resource_factory"] is issuer_module._create_production_resources
    assert dependencies["reauthentication_runner"] is issuer_module._production_reauthenticate_once
    assert dependencies["monotonic_ns"] is None
    assert not hasattr(
        issuer_module._DeadlineBoundReadOnlyProvider,
        "upload_object_no_overwrite",
    )
    assert "Ed25519PrivateKey" not in issuer_module.__dict__


def test_production_dispatch_performs_exact_sql_remote_sql_reauthentication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration = _configuration()
    authority = configuration.authority
    record = SimpleNamespace(
        anchor_sequence=1,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.ENROLLMENT,
        previous_anchor_sha256=None,
        previous_anchored_host_head_sha256=None,
        anchor_authority_sha256=authority.anchor_authority_sha256,
        deployment_identity_sha256=authority.deployment_identity_sha256,
        runtime_database_identity_sha256=authority.runtime_database_identity_sha256,
        anchor_project_identity_sha256=authority.anchor_project_identity_sha256,
        anchor_project_ref=authority.anchor_project_ref,
        source_authority_sha256=authority.source_authority_sha256,
        signing_key_id=authority.signing_key_id,
        signing_public_key_sha256=authority.signing_public_key_sha256,
        host_id=authority.host_id,
        principal_id=authority.principal_id,
        bucket_name=authority.bucket_name,
        checkpoint_interval_seconds=TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
        current_host_head_sha256="6" * 64,
        byte_sha256="7" * 64,
        semantic_sha256="8" * 64,
        __post_init__=lambda: None,
    )
    receipt = SimpleNamespace(
        intent=SimpleNamespace(record=record, semantic_sha256="9" * 64),
        readback_bytes_sha256="7" * 64,
        semantic_sha256="a" * 64,
        __post_init__=lambda: None,
    )

    def snapshot() -> TrustedTimeHeadAnchorPersistenceSnapshot:
        value = object.__new__(TrustedTimeHeadAnchorPersistenceSnapshot)
        tip = SimpleNamespace(
            confirmed_anchor_count=1,
            confirmed_anchor_tip=record,
            confirmed_anchor_local_transition_ordinal=1,
            local_transition_count=1,
            current_local_host_head_sha256="6" * 64,
        )
        object.__setattr__(value, "confirmed_anchor_receipt", receipt)
        object.__setattr__(value, "authenticated_journal_tip", tip)
        object.__setattr__(value, "complete_replay", True)
        object.__setattr__(value, "confirmed_anchor_count", 1)
        object.__setattr__(value, "pending_intent", None)
        object.__setattr__(value, "local_transition_count", 1)
        object.__setattr__(value, "current_host_head_sha256", "6" * 64)
        return value

    snapshots = [snapshot(), snapshot()]

    class Repository:
        def __init__(self) -> None:
            self.loads: list[dict[str, object]] = []
            self.discarded: list[object] = []

        def load_head_anchor_startup_snapshot(self, **kwargs: object) -> object:
            self.loads.append(kwargs)
            return snapshots[len(self.loads) - 1]

        def discard_head_anchor_snapshot(self, observed: object) -> None:
            self.discarded.append(observed)

    class Boundary:
        def __init__(self) -> None:
            self.events: list[tuple[str, object]] = []

        def activate(self, guard: object) -> None:
            self.events.append(("activate", guard))

        def deactivate(self, guard: object) -> None:
            self.events.append(("deactivate", guard))

    repository = Repository()
    provider = Boundary()
    router = Boundary()
    resources = issuer_module._ProductionResources(
        authority=authority,
        repository=repository,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]
        verifier=configuration.verifier,
        router=router,  # type: ignore[arg-type]
    )
    guard = issuer_module._ReauthenticationPhaseGuard(
        deadline_monotonic_ns=10_000_000_000,
        clock=_Clock(1),
        owner_pid=os.getpid(),
        owner_thread=threading.current_thread(),
    )
    remote_calls: list[tuple[object, dict[str, object]]] = []

    def verify_remote(tip: object, **kwargs: object) -> str:
        remote_calls.append((tip, kwargs))
        return "b" * 64

    monkeypatch.setattr(
        issuer_module,
        "verify_bounded_first_enrollment_remote_postcondition",
        verify_remote,
    )

    observed = issuer_module._production_reauthenticate_once(resources, guard)
    resources.discard_snapshot()

    assert observed.current_anchor_sha256 == "7" * 64
    assert observed.remote_namespace_sha256 == "b" * 64
    assert observed.anchor_authority_sha256 == authority.anchor_authority_sha256
    assert observed.deployment_identity_sha256 == authority.deployment_identity_sha256
    assert observed.runtime_database_identity_sha256 == authority.runtime_database_identity_sha256
    assert observed.anchor_project_identity_sha256 == authority.anchor_project_identity_sha256
    assert observed.source_authority_sha256 == authority.source_authority_sha256
    assert observed.signing_public_key_sha256 == authority.signing_public_key_sha256
    assert len(repository.loads) == 2
    assert repository.discarded == snapshots
    assert provider.events == [("activate", guard), ("deactivate", guard)]
    assert router.events == [("activate", guard), ("deactivate", guard)]
    assert remote_calls == [
        (
            snapshots[0].authenticated_journal_tip,
            {
                "provider": provider,
                "verifier": configuration.verifier,
                "signing_key_id": authority.signing_key_id,
                "signing_public_key_sha256": authority.signing_public_key_sha256,
                "checkpoint_interval_seconds": (
                    TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
                ),
                "anchor_authority_sha256": authority.anchor_authority_sha256,
            },
        )
    ]


def test_one_exact_call_is_lazy_deadline_bounded_and_closes_once() -> None:
    issuer, observations = _harness()

    assert type(issuer) is TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer
    assert observations["constructed"] == []
    binding_digest = issuer.issuer_binding_sha256
    configuration_digest = issuer.read_only_configuration_sha256

    observed = issuer.reauthenticate_first_enrollment_postcondition()

    assert type(observed) is TrustedTimeHeadAnchorFirstEnrollmentPostcondition
    assert observations["constructed"] == ["constructed"]
    assert observations["closed"] == ["closed"]
    assert observations["validations"] == [1, 1]
    assert observations["deadlines"] == [
        cast(int, observations["deadline"])
        - POST_ENROLLMENT_SEQUENCE_ONE_REAUTHENTICATION_RESERVE_NANOSECONDS
    ]
    assert issuer.issuer_binding_sha256 == binding_digest
    assert issuer.read_only_configuration_sha256 == configuration_digest
    issuer.close()
    issuer.close()
    assert observations["closed"] == ["closed"]

    with pytest.raises(TrustedTimePostEnrollmentSequenceOneReauthenticationRejected):
        issuer.reauthenticate_first_enrollment_postcondition()


def test_default_clock_is_the_exact_issuer_owned_suspend_aware_clock() -> None:
    issuer, observations = _harness(use_issuer_clock=True)
    topology_issuer = observations["topology_issuer"]

    issuer.reauthenticate_first_enrollment_postcondition()

    assert type(topology_issuer) is _FakeIssuer
    assert topology_issuer.clock_requests == 1


def test_duplicate_preparation_consumes_exact_origin_once() -> None:
    issuer, observations = _harness()
    configuration = observations["configuration"]
    topology_issuer = observations["topology_issuer"]
    prepare = cast(Any, observations["prepare"])
    assert type(configuration) is _ReadOnlyConfiguration

    with pytest.raises(TrustedTimePostEnrollmentSequenceOneReauthenticationRejected):
        prepare(
            database_url=_DATABASE_URL,
            authority=configuration.authority,
            credentials=configuration.credentials,
            verifier=configuration.verifier,
            topology_issuer=topology_issuer,
            choreography_lease=_TupleMember(),
            recovery_retention_capability=_TupleMember(),
            action_deadline_monotonic_ns=observations["deadline"],
            artifact_directory=_ARTIFACT_DIRECTORY,
            ignored_root=_ARTIFACT_ROOT,
        )

    issuer.close()


def test_close_before_call_prevents_lazy_resource_construction() -> None:
    issuer, observations = _harness()

    issuer.close()
    issuer.close()

    assert observations["constructed"] == []
    with pytest.raises(TrustedTimePostEnrollmentSequenceOneReauthenticationRejected):
        issuer.reauthenticate_first_enrollment_postcondition()


def test_terminal_state_releases_exact_tuple_and_secret_configuration_references() -> None:
    issuer, observations = _harness()
    references = cast(tuple[weakref.ReferenceType[Any], ...], observations["tuple_references"])
    configuration = observations.pop("configuration")
    observations.pop("topology_issuer")

    issuer.reauthenticate_first_enrollment_postcondition()
    del configuration
    gc.collect()

    assert all(reference() is None for reference in references)
    assert len(issuer.issuer_binding_sha256) == 64
    assert len(issuer.read_only_configuration_sha256) == 64


def test_base_exception_and_factory_store_interruption_close_registered_resource() -> None:
    issuer, observations = _harness(runner_error=KeyboardInterrupt())

    with pytest.raises(KeyboardInterrupt):
        issuer.reauthenticate_first_enrollment_postcondition()
    assert observations["closed"] == ["closed"]

    issuer, observations = _harness(factory_error=KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        issuer.reauthenticate_first_enrollment_postcondition()
    assert observations["closed"] == ["closed"]


def test_unconfirmed_terminal_cleanup_fails_closed_and_cannot_be_replayed() -> None:
    issuer, observations = _harness(close_error=OSError("unconfirmed"))

    with pytest.raises(TrustedTimePostEnrollmentSequenceOneReauthenticationRejected):
        issuer.reauthenticate_first_enrollment_postcondition()

    assert observations["closed"] == ["closed"]
    with pytest.raises(TrustedTimePostEnrollmentSequenceOneReauthenticationRejected):
        issuer.reauthenticate_first_enrollment_postcondition()


def test_resource_factory_return_store_interruption_closes_registered_resource() -> None:
    issuer, observations = _harness()
    source, first_line = inspect.getsourcelines(
        _build_trusted_time_post_enrollment_sequence_one_reauthentication_preparer_with_registry
    )
    store_line = first_line + next(
        offset for offset, line in enumerate(source) if 'state["resources"] = resources' in line
    )
    interrupted = False

    def interrupt_before_store(frame: object, event: str, _arg: object) -> object:
        nonlocal interrupted
        if (
            not interrupted
            and event == "line"
            and getattr(frame, "f_lineno", None) == store_line
            and getattr(getattr(frame, "f_code", None), "co_name", None) == "reauthenticate"
        ):
            interrupted = True
            sys.settrace(None)
            raise KeyboardInterrupt
        return interrupt_before_store

    sys.settrace(interrupt_before_store)  # type: ignore[arg-type]
    try:
        with pytest.raises(KeyboardInterrupt):
            issuer.reauthenticate_first_enrollment_postcondition()
    finally:
        sys.settrace(None)

    assert interrupted is True
    assert observations["constructed"] == ["constructed"]
    assert observations["closed"] == ["closed"]


def test_lost_unused_issuer_revokes_without_constructing_resources() -> None:
    issuer, observations = _harness()
    issuer_reference = weakref.ref(issuer)

    del issuer
    gc.collect()

    assert issuer_reference() is None
    assert observations["constructed"] == []


def test_phase_expiry_process_change_and_thread_change_fail_before_construction() -> None:
    clock = _Clock(1_000_000_000)
    issuer, observations = _harness(clock=clock)
    clock.value = 40_000_000_000
    with pytest.raises(TrustedTimePostEnrollmentSequenceOneReauthenticationRejected):
        issuer.reauthenticate_first_enrollment_postcondition()
    assert observations["constructed"] == []

    process = {"pid": 101}
    issuer, observations = _harness(process_id=lambda: process["pid"])
    process["pid"] = 102
    with pytest.raises(TrustedTimePostEnrollmentSequenceOneReauthenticationRejected):
        issuer.reauthenticate_first_enrollment_postcondition()
    assert observations["constructed"] == []

    thread = {"value": threading.current_thread()}
    issuer, observations = _harness(current_thread=lambda: thread["value"])
    thread["value"] = threading.Thread()
    with pytest.raises(TrustedTimePostEnrollmentSequenceOneReauthenticationRejected):
        issuer.reauthenticate_first_enrollment_postcondition()
    assert observations["constructed"] == []


def test_issuer_cannot_be_constructed_copied_serialized_or_capability_swapped() -> None:
    first, _ = _harness()
    second, _ = _harness()

    with pytest.raises(TrustedTimePostEnrollmentSequenceOneReauthenticationRejected):
        TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer()
    with pytest.raises(TrustedTimePostEnrollmentSequenceOneReauthenticationRejected):
        copy.copy(first)
    with pytest.raises(TrustedTimePostEnrollmentSequenceOneReauthenticationRejected):
        copy.deepcopy(first)
    with pytest.raises(TrustedTimePostEnrollmentSequenceOneReauthenticationRejected):
        pickle.dumps(first)
    with pytest.raises(TrustedTimePostEnrollmentSequenceOneReauthenticationRejected):
        first._capability = second._capability

    first.close()
    second.close()


def test_production_resources_pin_tls_and_never_expose_provider_write_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration = _configuration()
    observed: dict[str, object] = {}

    class Engine:
        def dispose(self) -> None:
            observed["disposed"] = True

    class Provider:
        def close(self) -> None:
            observed["provider_closed"] = True

    monkeypatch.setattr(
        issuer_module,
        "pinned_verify_full_connect_args",
        lambda database_url, *, required: (
            observed.update({"tls_url": database_url, "tls_required": required})
            or {"sslrootcert": "/private/pinned-ca.crt"}
        ),
    )
    monkeypatch.setattr(
        issuer_module,
        "create_engine",
        lambda database_url, **kwargs: (
            observed.update({"engine_url": database_url, "engine_kwargs": kwargs}) or Engine()
        ),
    )
    monkeypatch.setattr(cast(Any, issuer_module).event, "listen", lambda *a, **k: None)
    monkeypatch.setattr(
        issuer_module,
        "SqlTrustedTimeHeadAnchorRepository",
        lambda *a, **k: cast(Any, object()),
    )
    monkeypatch.setattr(
        issuer_module,
        "SupabaseStorageTrustedTimeAnchorProvider",
        lambda **kwargs: observed.update({"provider_kwargs": kwargs}) or Provider(),
    )
    owner = issuer_module._ResourceOwner()
    guard = issuer_module._ReauthenticationPhaseGuard(
        deadline_monotonic_ns=10_000_000_000,
        clock=_Clock(1),
        owner_pid=os.getpid(),
        owner_thread=threading.current_thread(),
    )

    resources = issuer_module._create_production_resources(
        database_url=_DATABASE_URL,
        configuration=configuration,
        owner=owner,
        owner_pid=os.getpid(),
        owner_thread=threading.current_thread(),
        initial_guard=guard,
    )
    owner.close(require_success=True)

    assert observed["tls_url"] == _DATABASE_URL
    assert observed["tls_required"] is True
    assert observed["engine_url"] == _DATABASE_URL
    assert cast(dict[str, object], observed["engine_kwargs"])["connect_args"] == {
        "connect_timeout": 1,
        "sslrootcert": "/private/pinned-ca.crt",
        "options": (
            "-c statement_timeout=1000 -c lock_timeout=500 -c default_transaction_read_only=on"
        ),
    }
    assert observed["disposed"] is True
    assert observed["provider_closed"] is True
    assert not hasattr(resources._provider, "upload_object_no_overwrite")


def test_configuration_rejects_crossed_authority_without_rendering_secrets() -> None:
    configuration = _configuration()
    other = _configuration()

    with pytest.raises(
        TrustedTimePostEnrollmentSequenceOneReauthenticationRejected,
        match="crosses authority",
    ):
        _ReadOnlyConfiguration(
            authority=configuration.authority,
            credentials=configuration.credentials,
            verifier=other.verifier,
        )
