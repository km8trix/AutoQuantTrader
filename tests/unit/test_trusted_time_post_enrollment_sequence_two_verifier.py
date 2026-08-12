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
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import scripts.trusted_time_post_enrollment_sequence_two_verifier as verifier_module
from apps.trusted_time_supervisor.head_anchor_attempt import (
    TrustedTimeHeadAnchorPostEnrollmentStartPostcondition,
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
    TrustedTimeHeadAnchorCheckpointReason,
)
from scripts.trusted_time_post_enrollment_sequence_two_verifier import (
    POST_ENROLLMENT_START_SEQUENCE_TWO_FIRST_VERIFICATION_RESERVE_NANOSECONDS,
    POST_ENROLLMENT_START_SEQUENCE_TWO_SECOND_VERIFICATION_RESERVE_NANOSECONDS,
    POST_ENROLLMENT_START_SEQUENCE_TWO_VERIFIER_CONTRACT_VERSION,
    TrustedTimePostEnrollmentStartSequenceTwoReadOnlyConfiguration,
    TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected,
    TrustedTimePostEnrollmentStartSequenceTwoVerifier,
    _build_trusted_time_post_enrollment_start_sequence_two_verifier_preparer,
    _build_trusted_time_post_enrollment_start_sequence_two_verifier_preparer_with_registry,
    _PreparationBinding,
)
from tests.unit import test_trusted_time_head_anchor_attempt as anchor_attempt_fx

_RUNTIME_PROJECT_REF = "a" * 20
_ANCHOR_PROJECT_REF = "b" * 20
_DATABASE_URL = (
    "postgresql+psycopg://postgres."
    f"{_RUNTIME_PROJECT_REF}:test-password@aws-0-test.pooler.supabase.com:5432/"
    "postgres?sslmode=verify-full"
)
_ARTIFACT_ROOT = Path("/tmp/sequence-two-test-artifacts")
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
    def __init__(self, closed: list[str]) -> None:
        self.closed = closed

    def close(self) -> None:
        self.closed.append("closed")


def _configuration() -> TrustedTimePostEnrollmentStartSequenceTwoReadOnlyConfiguration:
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
        email="sequence-two@example.invalid",
        password="S" * 32,
    )
    verifier = Ed25519TrustedTimeAnchorVerifier.from_public_key_bytes(
        signing_key_id=authority.signing_key_id,
        expected_signing_public_key_sha256=authority.signing_public_key_sha256,
        public_key_bytes=public_key,
    )
    return TrustedTimePostEnrollmentStartSequenceTwoReadOnlyConfiguration(
        authority=authority,
        credentials=credentials,
        verifier=verifier,
    )


def _postcondition(
    *, namespace: str = "f" * 64
) -> TrustedTimeHeadAnchorPostEnrollmentStartPostcondition:
    return TrustedTimeHeadAnchorPostEnrollmentStartPostcondition(
        anchor_sequence=2,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.EPOCH_ROTATION,
        confirmed_anchor_count=2,
        local_transition_count=2,
        confirmed_anchor_local_transition_ordinal=2,
        remote_object_count=2,
        predecessor_anchor_sha256="6" * 64,
        current_host_head_sha256="7" * 64,
        current_anchor_sha256="8" * 64,
        current_anchor_semantic_sha256="9" * 64,
        anchor_intent_semantic_sha256="a" * 64,
        candidate_remote_readback_sha256="8" * 64,
        receipt_semantic_sha256="b" * 64,
        remote_namespace_sha256=namespace,
        anchor_authority_sha256="1" * 64,
        deployment_identity_sha256="2" * 64,
        runtime_database_identity_sha256="4" * 64,
        anchor_project_identity_sha256="5" * 64,
        source_authority_sha256="3" * 64,
        signing_public_key_sha256="c" * 64,
        host_identity_sha256="d" * 64,
        principal_identity_sha256="e" * 64,
        bucket_identity_sha256="0" * 64,
        full_audit_completed=True,
        pending_intent_present=False,
    )


def _harness(
    *,
    results: list[TrustedTimeHeadAnchorPostEnrollmentStartPostcondition] | None = None,
    runner_error: BaseException | None = None,
    factory_error: BaseException | None = None,
    clock: _Clock | None = None,
    use_issuer_clock: bool = False,
    process_id: object | None = None,
    current_thread: object | None = None,
) -> tuple[
    TrustedTimePostEnrollmentStartSequenceTwoVerifier,
    dict[str, object],
    dict[str, object],
]:
    admission = _TupleMember()
    issuer = _FakeIssuer()
    lease = _TupleMember()
    recovery = _TupleMember()
    retained_claim = _TupleMember()
    retained_claim_holder = [retained_claim]
    origin = object()
    closed: list[str] = []
    constructed: list[str] = []
    deadlines: list[int] = []
    validation_calls: list[int] = []
    exact_clock = _Clock(1_000_000_000) if clock is None else clock
    issuer.monotonic_clock = exact_clock
    exact_results = [_postcondition(), _postcondition()] if results is None else results

    def preparation_validator(**_: object) -> _PreparationBinding:
        return _PreparationBinding(
            origin_token=origin,
            retained_claim=retained_claim_holder.pop(),
            payload={"claim_sha256": "1" * 64, "operation_id": "test-operation"},
        )

    def call_validator(**_: object) -> None:
        validation_calls.append(1)

    def resource_factory(*, owner: object, **_: object) -> _FakeResources:
        constructed.append("constructed")
        resources = _FakeResources(closed)
        owner.register(resources.close)
        if factory_error is not None:
            raise factory_error
        return resources

    def verification_runner(
        resources: object,
        guard: object,
    ) -> TrustedTimeHeadAnchorPostEnrollmentStartPostcondition:
        assert type(resources) is _FakeResources
        deadlines.append(guard.deadline_monotonic_ns)
        guard.require_remaining()
        if runner_error is not None:
            raise runner_error
        return exact_results[len(deadlines) - 1]

    dependencies: dict[str, object] = {
        "preparation_validator": preparation_validator,
        "call_validator": call_validator,
        "resource_factory": resource_factory,
        "verification_runner": verification_runner,
    }
    if not use_issuer_clock:
        dependencies["monotonic_ns"] = exact_clock
    if process_id is not None:
        dependencies["process_id"] = process_id
    if current_thread is not None:
        dependencies["current_thread"] = current_thread
    prepare = _build_trusted_time_post_enrollment_start_sequence_two_verifier_preparer(
        **dependencies
    )
    deadline = 121_000_000_000
    configuration = _configuration()
    arguments = {
        "admission": admission,
        "topology_issuer": issuer,
        "choreography_lease": lease,
        "recovery_retention_capability": recovery,
        "action_deadline_monotonic_ns": deadline,
        "artifact_directory": _ARTIFACT_DIRECTORY,
        "ignored_root": _ARTIFACT_ROOT,
    }
    verifier = prepare(
        **arguments,
        database_url=_DATABASE_URL,
        configuration=configuration,
    )
    observations: dict[str, object] = {
        "closed": closed,
        "constructed": constructed,
        "deadlines": deadlines,
        "origin": origin,
        "prepare": prepare,
        "configuration": configuration,
        "tuple_references": {
            "admission": weakref.ref(admission),
            "issuer": weakref.ref(issuer),
            "lease": weakref.ref(lease),
            "recovery": weakref.ref(recovery),
            "retained_claim": weakref.ref(retained_claim),
        },
        "validation_calls": validation_calls,
    }
    return verifier, arguments, observations


def test_read_only_configuration_redacts_all_credentials_and_has_stable_digest() -> None:
    configuration = _configuration()

    rendered = repr(configuration)
    assert "sequence-two@example.invalid" not in rendered
    assert "sb_publishable_" not in rendered
    assert "S" * 32 not in rendered
    assert configuration.configuration_sha256 == configuration.configuration_sha256
    assert len(configuration.configuration_sha256) == 64
    assert POST_ENROLLMENT_START_SEQUENCE_TWO_VERIFIER_CONTRACT_VERSION in (
        "phase6d-post-enrollment-start-sequence-two-verifier-v1",
    )


def test_public_preparer_seals_production_dispatch_and_issuer_clock_route() -> None:
    dependencies = inspect.getclosurevars(
        verifier_module.prepare_trusted_time_post_enrollment_start_sequence_two_verifier
    ).nonlocals

    assert dependencies["preparation_validator"] is verifier_module._prepare_exact_binding
    assert dependencies["call_validator"] is verifier_module._revalidate_exact_call
    assert dependencies["resource_factory"] is verifier_module._create_production_resources
    assert dependencies["verification_runner"] is verifier_module._production_verify_once
    assert dependencies["monotonic_ns"] is None


def test_production_dispatch_uses_two_local_snapshots_and_one_read_only_remote_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = anchor_attempt_fx._authority()
    record = anchor_attempt_fx._post_enrollment_record()
    receipt = anchor_attempt_fx._post_enrollment_receipt(record)
    snapshots = [
        anchor_attempt_fx._post_enrollment_snapshot(receipt),
        anchor_attempt_fx._post_enrollment_snapshot(receipt),
    ]

    class Repository:
        def __init__(self) -> None:
            self.loads: list[dict[str, object]] = []
            self.discarded: list[object] = []

        def load_head_anchor_startup_snapshot(self, **kwargs: object) -> object:
            self.loads.append(kwargs)
            return snapshots[len(self.loads) - 1]

        def discard_head_anchor_snapshot(self, snapshot: object) -> None:
            self.discarded.append(snapshot)

    class DeadlineBoundary:
        def __init__(self) -> None:
            self.events: list[tuple[str, object]] = []

        def activate(self, guard: object) -> None:
            self.events.append(("activate", guard))

        def deactivate(self, guard: object) -> None:
            self.events.append(("deactivate", guard))

    repository = Repository()
    provider = DeadlineBoundary()
    router = DeadlineBoundary()
    configuration = _configuration()
    resources = verifier_module._ProductionResources(
        authority=authority,
        repository=repository,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]
        verifier=configuration.verifier,
        router=router,  # type: ignore[arg-type]
    )
    guard = verifier_module._VerificationPhaseGuard(
        deadline_monotonic_ns=10_000_000_000,
        clock=_Clock(1),
        owner_pid=os.getpid(),
        owner_thread=threading.current_thread(),
    )
    remote_calls: list[tuple[object, dict[str, object]]] = []

    def verify_remote(tip: object, **kwargs: object) -> str:
        remote_calls.append((tip, kwargs))
        return "0" * 64

    monkeypatch.setattr(
        verifier_module,
        "verify_bounded_post_enrollment_start_remote_postcondition",
        verify_remote,
    )

    observed = verifier_module._production_verify_once(resources, guard)
    resources.discard_snapshot()

    assert observed == anchor_attempt_fx._post_enrollment_postcondition()
    assert len(repository.loads) == 2
    assert repository.discarded == snapshots
    assert provider.events == [("activate", guard), ("deactivate", guard)]
    assert router.events == [("activate", guard), ("deactivate", guard)]
    assert len(remote_calls) == 1
    assert remote_calls[0][0] is snapshots[0].authenticated_journal_tip
    assert remote_calls[0][1]["provider"] is provider


@pytest.mark.parametrize("interrupted_registration", [1, 2])
def test_production_resource_construction_closes_interrupted_unregistered_resource(
    monkeypatch: pytest.MonkeyPatch,
    interrupted_registration: int,
) -> None:
    class Engine:
        def __init__(self) -> None:
            self.dispose_calls = 0

        def dispose(self) -> None:
            self.dispose_calls += 1

    class Provider:
        def __init__(self) -> None:
            self.close_calls = 0

        def close(self) -> None:
            self.close_calls += 1

    engine = Engine()
    providers: list[Provider] = []
    monkeypatch.setattr(
        verifier_module,
        "pinned_verify_full_connect_args",
        lambda *a, **k: {},
    )
    monkeypatch.setattr(verifier_module, "create_engine", lambda *a, **k: engine)
    monkeypatch.setattr(verifier_module.event, "listen", lambda *a, **k: None)
    monkeypatch.setattr(
        verifier_module,
        "SqlTrustedTimeHeadAnchorRepository",
        lambda *a, **k: object(),
    )

    def create_provider(**_: object) -> Provider:
        provider = Provider()
        providers.append(provider)
        return provider

    monkeypatch.setattr(
        verifier_module,
        "SupabaseStorageTrustedTimeAnchorProvider",
        create_provider,
    )
    source, first_line = inspect.getsourcelines(verifier_module._construct_owned_resource)
    registration_line = first_line + next(
        offset for offset, line in enumerate(source) if "owner.register_owned" in line
    )
    registration_visits = 0
    interrupted = False

    def interrupt_before_registration(frame: object, event: str, _arg: object) -> object:
        nonlocal interrupted, registration_visits
        if (
            event == "line"
            and getattr(frame, "f_code", None) is verifier_module._construct_owned_resource.__code__
            and getattr(frame, "f_lineno", None) == registration_line
        ):
            registration_visits += 1
            if registration_visits == interrupted_registration:
                interrupted = True
                sys.settrace(None)
                raise KeyboardInterrupt
        return interrupt_before_registration

    owner = verifier_module._ResourceOwner()
    guard = verifier_module._VerificationPhaseGuard(
        deadline_monotonic_ns=10_000_000_000,
        clock=_Clock(1),
        owner_pid=os.getpid(),
        owner_thread=threading.current_thread(),
    )
    sys.settrace(interrupt_before_registration)
    try:
        with pytest.raises(KeyboardInterrupt):
            verifier_module._create_production_resources(
                database_url=_DATABASE_URL,
                configuration=_configuration(),
                owner=owner,
                owner_pid=os.getpid(),
                owner_thread=threading.current_thread(),
                initial_guard=guard,
            )
    finally:
        sys.settrace(None)
        owner.close(require_success=False)

    assert interrupted is True
    assert engine.dispose_calls == 1
    if interrupted_registration == 1:
        assert providers == []
    else:
        assert len(providers) == 1
        assert providers[0].close_calls == 1


def test_snapshot_loaded_at_deadline_is_discarded_before_ownership_can_escape() -> None:
    replacement = anchor_attempt_fx._post_enrollment_snapshot(
        anchor_attempt_fx._post_enrollment_receipt(anchor_attempt_fx._post_enrollment_record())
    )

    class Repository:
        def __init__(self) -> None:
            self.discarded: list[object] = []

        def load_head_anchor_startup_snapshot(self, **_: object) -> object:
            return replacement

        def discard_head_anchor_snapshot(self, snapshot: object) -> None:
            self.discarded.append(snapshot)

    repository = Repository()
    configuration = _configuration()
    resources = verifier_module._ProductionResources(
        authority=anchor_attempt_fx._authority(),
        repository=repository,  # type: ignore[arg-type]
        provider=cast(Any, object()),
        verifier=configuration.verifier,
        router=cast(Any, object()),
    )
    observed = iter((0, 0, 2_000_000_000))
    guard = verifier_module._VerificationPhaseGuard(
        deadline_monotonic_ns=2_000_000_000,
        clock=lambda: next(observed),
        owner_pid=os.getpid(),
        owner_thread=threading.current_thread(),
    )

    with pytest.raises(TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected):
        resources._replace_snapshot(guard)
    resources.discard_snapshot()

    assert repository.discarded == [replacement]


def test_snapshot_publication_interruption_retains_new_and_discards_both_snapshots() -> None:
    receipt = anchor_attempt_fx._post_enrollment_receipt(
        anchor_attempt_fx._post_enrollment_record()
    )
    previous = anchor_attempt_fx._post_enrollment_snapshot(receipt)
    replacement = anchor_attempt_fx._post_enrollment_snapshot(receipt)

    class Repository:
        def __init__(self) -> None:
            self.discarded: list[object] = []

        def load_head_anchor_startup_snapshot(self, **_: object) -> object:
            return replacement

        def discard_head_anchor_snapshot(self, snapshot: object) -> None:
            self.discarded.append(snapshot)

    repository = Repository()
    configuration = _configuration()
    resources = verifier_module._ProductionResources(
        authority=anchor_attempt_fx._authority(),
        repository=repository,  # type: ignore[arg-type]
        provider=cast(Any, object()),
        verifier=configuration.verifier,
        router=cast(Any, object()),
    )
    resources._snapshot = previous
    guard = verifier_module._VerificationPhaseGuard(
        deadline_monotonic_ns=10_000_000_000,
        clock=_Clock(1),
        owner_pid=os.getpid(),
        owner_thread=threading.current_thread(),
    )
    source, first_line = inspect.getsourcelines(
        verifier_module._ProductionResources._replace_snapshot
    )
    discard_line = first_line + next(
        offset
        for offset, line in enumerate(source)
        if "self._repository.discard_head_anchor_snapshot(previous)" in line
    )
    interrupted = False

    def interrupt_before_previous_discard(frame: object, event: str, _arg: object) -> object:
        nonlocal interrupted
        if (
            not interrupted
            and event == "line"
            and getattr(frame, "f_code", None)
            is verifier_module._ProductionResources._replace_snapshot.__code__
            and getattr(frame, "f_lineno", None) == discard_line
        ):
            interrupted = True
            sys.settrace(None)
            raise KeyboardInterrupt
        return interrupt_before_previous_discard

    sys.settrace(interrupt_before_previous_discard)
    try:
        with pytest.raises(KeyboardInterrupt):
            resources._replace_snapshot(guard)
    finally:
        sys.settrace(None)
    resources.discard_snapshot()

    assert interrupted is True
    assert repository.discarded == [previous, replacement]


def test_two_exact_calls_are_lazy_deadline_partitioned_and_emit_transcript() -> None:
    verifier, arguments, observations = _harness()
    deadline = arguments["action_deadline_monotonic_ns"]

    assert type(verifier) is TrustedTimePostEnrollmentStartSequenceTwoVerifier
    assert observations["constructed"] == []
    assert verifier.verification_transcript_sha256 is None
    binding_digest = verifier.verifier_binding_sha256
    configuration_digest = verifier.read_only_configuration_sha256

    first = verifier.reauthenticate_post_enrollment_start_successor(**arguments)
    assert observations["constructed"] == ["constructed"]
    assert observations["closed"] == []
    assert verifier.verification_transcript_sha256 is None
    second = verifier.reauthenticate_post_enrollment_start_successor(**arguments)

    assert second == first
    assert observations["deadlines"] == [
        deadline - POST_ENROLLMENT_START_SEQUENCE_TWO_FIRST_VERIFICATION_RESERVE_NANOSECONDS,
        deadline - POST_ENROLLMENT_START_SEQUENCE_TWO_SECOND_VERIFICATION_RESERVE_NANOSECONDS,
    ]
    assert observations["constructed"] == ["constructed"]
    assert observations["closed"] == ["closed"]
    assert verifier.verifier_binding_sha256 == binding_digest
    assert verifier.read_only_configuration_sha256 == configuration_digest
    assert verifier.verification_transcript_sha256 is not None
    assert len(verifier.verification_transcript_sha256 or "") == 64

    with pytest.raises(TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected):
        verifier.reauthenticate_post_enrollment_start_successor(**arguments)


def test_mismatched_second_result_fails_closed_without_transcript() -> None:
    verifier, arguments, observations = _harness(
        results=[_postcondition(), _postcondition(namespace="1" * 64)]
    )
    verifier.reauthenticate_post_enrollment_start_successor(**arguments)

    with pytest.raises(TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected):
        verifier.reauthenticate_post_enrollment_start_successor(**arguments)

    assert observations["closed"] == ["closed"]
    assert verifier.verification_transcript_sha256 is None


@pytest.mark.parametrize(
    "field_name,replacement",
    [
        ("admission", object()),
        ("topology_issuer", object()),
        ("choreography_lease", object()),
        ("recovery_retention_capability", object()),
        ("action_deadline_monotonic_ns", 121_000_000_001),
        ("artifact_directory", Path("/tmp/wrong-sequence-two-artifacts/trusted-time")),
        ("ignored_root", Path("/tmp/wrong-sequence-two-artifacts")),
    ],
)
def test_wrong_tuple_closes_before_resource_construction(
    field_name: str,
    replacement: object,
) -> None:
    verifier, arguments, observations = _harness()
    wrong = dict(arguments)
    wrong[field_name] = replacement

    with pytest.raises(TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected):
        verifier.reauthenticate_post_enrollment_start_successor(**wrong)

    assert observations["constructed"] == []
    assert verifier.verification_transcript_sha256 is None


def test_default_verifier_clock_is_the_exact_issuer_owned_clock() -> None:
    verifier, arguments, observations = _harness(use_issuer_clock=True)
    references = observations["tuple_references"]
    assert type(references) is dict
    issuer = references["issuer"]()

    verifier.reauthenticate_post_enrollment_start_successor(**arguments)
    verifier.reauthenticate_post_enrollment_start_successor(**arguments)

    assert type(issuer) is _FakeIssuer
    assert issuer.clock_requests == 1
    assert observations["deadlines"] == [
        arguments["action_deadline_monotonic_ns"]
        - POST_ENROLLMENT_START_SEQUENCE_TWO_FIRST_VERIFICATION_RESERVE_NANOSECONDS,
        arguments["action_deadline_monotonic_ns"]
        - POST_ENROLLMENT_START_SEQUENCE_TWO_SECOND_VERIFICATION_RESERVE_NANOSECONDS,
    ]


def test_duplicate_preparation_consumes_the_exact_origin_once() -> None:
    verifier, arguments, observations = _harness()
    prepare = observations["prepare"]

    with pytest.raises(TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected):
        prepare(
            **arguments,
            database_url=_DATABASE_URL,
            configuration=observations["configuration"],
        )

    verifier.abort()


def test_abort_is_idempotent_and_prevents_any_lazy_construction() -> None:
    verifier, arguments, observations = _harness()

    verifier.abort()
    verifier.abort()

    assert observations["constructed"] == []
    with pytest.raises(TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected):
        verifier.reauthenticate_post_enrollment_start_successor(**arguments)


@pytest.mark.parametrize("completed_calls", [0, 1, 2])
def test_terminal_state_retains_only_digest_evidence_and_releases_tuple_refs(
    completed_calls: int,
) -> None:
    verifier, arguments, observations = _harness()
    binding_digest = verifier.verifier_binding_sha256
    configuration_digest = verifier.read_only_configuration_sha256
    if completed_calls >= 1:
        verifier.reauthenticate_post_enrollment_start_successor(**arguments)
    if completed_calls == 2:
        verifier.reauthenticate_post_enrollment_start_successor(**arguments)
        transcript_digest = verifier.verification_transcript_sha256
        assert transcript_digest is not None
    else:
        verifier.abort()
        transcript_digest = None

    arguments.clear()
    gc.collect()

    references = observations["tuple_references"]
    assert all(reference() is None for reference in references.values())
    assert verifier.verifier_binding_sha256 == binding_digest
    assert verifier.read_only_configuration_sha256 == configuration_digest
    assert verifier.verification_transcript_sha256 == transcript_digest
    verifier.abort()
    assert verifier.verifier_binding_sha256 == binding_digest


def test_base_exception_closes_registered_resource_and_abort_remains_idempotent() -> None:
    verifier, arguments, observations = _harness(runner_error=KeyboardInterrupt())

    with pytest.raises(KeyboardInterrupt):
        verifier.reauthenticate_post_enrollment_start_successor(**arguments)

    assert observations["constructed"] == ["constructed"]
    assert observations["closed"] == ["closed"]
    assert verifier.verification_transcript_sha256 is None
    verifier.abort()
    assert observations["closed"] == ["closed"]


def test_factory_call_store_interruption_closes_registered_resource() -> None:
    verifier, arguments, observations = _harness(factory_error=KeyboardInterrupt())

    with pytest.raises(KeyboardInterrupt):
        verifier.reauthenticate_post_enrollment_start_successor(**arguments)

    assert observations["constructed"] == ["constructed"]
    assert observations["closed"] == ["closed"]


def test_resource_factory_return_store_interruption_closes_registered_resource() -> None:
    verifier, arguments, observations = _harness()
    builder_source, builder_first_line = inspect.getsourcelines(
        _build_trusted_time_post_enrollment_start_sequence_two_verifier_preparer_with_registry
    )
    store_line = builder_first_line + next(
        offset
        for offset, line in enumerate(builder_source)
        if 'state["resources"] = resources' in line
    )
    interrupted = False

    def interrupt_before_store(frame: object, event: str, _arg: object) -> object:
        nonlocal interrupted
        if (
            not interrupted
            and event == "line"
            and getattr(frame, "f_lineno", None) == store_line
            and getattr(getattr(frame, "f_code", None), "co_name", None) == "verify"
        ):
            interrupted = True
            sys.settrace(None)
            raise KeyboardInterrupt
        return interrupt_before_store

    sys.settrace(interrupt_before_store)
    try:
        with pytest.raises(KeyboardInterrupt):
            verifier.reauthenticate_post_enrollment_start_successor(**arguments)
    finally:
        sys.settrace(None)

    assert interrupted is True
    assert observations["constructed"] == ["constructed"]
    assert observations["closed"] == ["closed"]
    assert verifier.verification_transcript_sha256 is None
    assert verifier.verification_transcript_sha256 is None
    verifier.abort()
    assert observations["closed"] == ["closed"]


def test_lost_verifier_after_first_call_revokes_and_closes_resources() -> None:
    verifier, arguments, observations = _harness()
    verifier.reauthenticate_post_enrollment_start_successor(**arguments)
    verifier_reference = weakref.ref(verifier)

    del verifier
    gc.collect()

    assert verifier_reference() is None
    assert observations["closed"] == ["closed"]


def test_phase_deadline_expiry_rejects_before_lazy_construction() -> None:
    clock = _Clock(1_000_000_000)
    verifier, arguments, observations = _harness(clock=clock)
    clock.value = 40_000_000_000

    with pytest.raises(TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected):
        verifier.reauthenticate_post_enrollment_start_successor(**arguments)

    assert observations["constructed"] == []


def test_process_identity_change_rejects_and_thread_change_rejects() -> None:
    process = {"pid": 101}
    verifier, arguments, observations = _harness(process_id=lambda: process["pid"])
    process["pid"] = 102

    with pytest.raises(TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected):
        verifier.reauthenticate_post_enrollment_start_successor(**arguments)
    assert observations["constructed"] == []

    thread = {"value": threading.current_thread()}
    verifier, arguments, observations = _harness(current_thread=lambda: thread["value"])
    thread["value"] = threading.Thread()
    with pytest.raises(TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected):
        verifier.reauthenticate_post_enrollment_start_successor(**arguments)
    assert observations["constructed"] == []


def test_verifier_cannot_be_constructed_copied_serialized_or_capability_swapped() -> None:
    first, _, _ = _harness()
    second, _, _ = _harness()

    with pytest.raises(TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected):
        TrustedTimePostEnrollmentStartSequenceTwoVerifier()
    with pytest.raises(TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected):
        copy.copy(first)
    with pytest.raises(TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected):
        copy.deepcopy(first)
    with pytest.raises(TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected):
        pickle.dumps(first)

    with pytest.raises(TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected):
        first._capability = second._capability
    assert len(first.verifier_binding_sha256) == 64
