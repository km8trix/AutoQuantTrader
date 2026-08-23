from __future__ import annotations

import copy
import gc
import inspect
import os
import pickle
import select
import signal
import threading
import weakref
from collections.abc import Callable
from dataclasses import FrozenInstanceError, dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import event as sqlalchemy_event

import scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication as reauth_module
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
from scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication import (
    POST_ENROLLMENT_CLEAN_STOP_TERMINAL_REAUTHENTICATION_CONTRACT_VERSION,
    TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration,
    TrustedTimePostEnrollmentCleanStopTerminalPostcondition,
    TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer,
    TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected,
    _build_trusted_time_post_enrollment_clean_stop_terminal_reauthentication_preparer,
    prepare_trusted_time_post_enrollment_clean_stop_terminal_reauthentication_issuer,
)

_build_preparer = _build_trusted_time_post_enrollment_clean_stop_terminal_reauthentication_preparer

_RUNTIME_PROJECT_REF = "a" * 20
_ANCHOR_PROJECT_REF = "b" * 20
_DATABASE_URL = (
    "postgresql+psycopg://postgres."
    f"{_RUNTIME_PROJECT_REF}:test-password@aws-0-test.pooler.supabase.com:5432/"
    "postgres?sslmode=verify-full"
)
_OBSERVED_AT = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
_FALSE_AUTHORITY_PROPERTIES = frozenset(
    {
        "active_controller_authorized",
        "admission_authorized",
        "alert_delivery_authorized",
        "arming_authorized",
        "authority_granted",
        "automatic_rearm_authorized",
        "automatic_resume_authorized",
        "broker_action_authorized",
        "claim_retention_authorized",
        "clean_stop_authorized",
        "clean_stop_outcome_retention_authorized",
        "confirmed_start_outcome_authenticated",
        "container_removal_authorized",
        "controller_execution_authorized",
        "current_topology_authenticated",
        "currentness_qualified",
        "database_secret_disclosed",
        "decision_authenticated",
        "durability_authenticated",
        "durable",
        "durable_stop_outcome_authenticated",
        "effect_authorized",
        "execution_admission_authorized",
        "execution_attempt_reservation_authorized",
        "exposure_authorized",
        "freshness_authenticated",
        "freshness_qualified",
        "graceful_stop_authorized",
        "live_trading_authorized",
        "network_removal_authorized",
        "new_exposure_authorized",
        "no_new_record_authenticated",
        "no_new_record_success",
        "operational_control_authorized",
        "operator_attestation_authenticated",
        "outcome_retention_authorized",
        "paper_trading_authorized",
        "persistent_start_authorized",
        "persistent_topology_authenticated",
        "provider_terminal_currentness_authenticated",
        "qualified",
        "readiness_authorized",
        "rearm_authorized",
        "release_authorized",
        "retry_authorized",
        "runtime_start_authorized",
        "sequence_2_authorized",
        "shutdown_authorized",
        "shutdown_locator_authenticated",
        "shutdown_outcome_retention_authorized",
        "signal_authorized",
        "single_use_authenticated",
        "slot_authorized",
        "source_start_authorized",
        "source_stop_authorized",
        "start_execution_attempt_authenticated",
        "stop_admission_qualified",
        "stop_attempt_reservation_authorized",
        "stop_attempt_slot_reserved",
        "stop_decision_authenticated",
        "stop_execution_authorized",
        "stop_outcome_retained",
        "success_outcome_retention_authorized",
        "supervisor_signal_authorized",
        "supervisor_start_authorized",
        "supervisor_stop_authorized",
        "target_authenticated",
        "teardown_authorized",
        "topology_mutation_authorized",
        "volume_removal_authorized",
        "watchdog_authorized",
    }
)


@dataclass
class _Clock:
    value: int = 1_000_000_000
    calls: int = 0

    def __call__(self) -> int:
        self.calls += 1
        return self.value


@dataclass(frozen=True, slots=True)
class _RecordView:
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason = (
        TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP
    )


class _FakeRecord:
    def __init__(self, authority: TrustedTimeHeadAnchorAuthority) -> None:
        self.anchor_sequence = 3
        self.checkpoint_reason = TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP
        self.previous_anchor_sha256: str | None = "6" * 64
        self.current_host_head_sha256 = "7" * 64
        self.byte_sha256 = "8" * 64
        self.semantic_sha256 = "9" * 64
        self.anchor_authority_sha256 = authority.anchor_authority_sha256
        self.deployment_identity_sha256 = authority.deployment_identity_sha256
        self.runtime_database_identity_sha256 = authority.runtime_database_identity_sha256
        self.anchor_project_identity_sha256 = authority.anchor_project_identity_sha256
        self.anchor_project_ref = authority.anchor_project_ref
        self.bucket_name = authority.bucket_name
        self.principal_id = authority.principal_id
        self.host_id = authority.host_id
        self.source_authority_sha256 = authority.source_authority_sha256
        self.signing_key_id = authority.signing_key_id
        self.signing_public_key_sha256 = authority.signing_public_key_sha256
        self.checkpoint_interval_seconds = authority.checkpoint_interval_seconds
        self.post_init_error: BaseException | None = None

    def __post_init__(self) -> None:
        if self.post_init_error is not None:
            raise self.post_init_error


class _FakeIntent:
    def __init__(self, record: _FakeRecord) -> None:
        self.record = record
        self.semantic_sha256 = "a" * 64
        self.post_init_error: BaseException | None = None

    def __post_init__(self) -> None:
        if self.post_init_error is not None:
            raise self.post_init_error


class _FakeReceipt:
    def __init__(self, intent: _FakeIntent) -> None:
        self.intent = intent
        self.readback_bytes_sha256 = intent.record.byte_sha256
        self.observed_at_utc = _OBSERVED_AT
        self.semantic_sha256 = "b" * 64
        self.post_init_error: BaseException | None = None

    def __post_init__(self) -> None:
        if self.post_init_error is not None:
            raise self.post_init_error


class _FakeTip:
    def __init__(self, record: _FakeRecord) -> None:
        self.confirmed_anchor_count = 3
        self.confirmed_anchor_tip: object = record
        self.confirmed_anchor_local_transition_ordinal: int | None = 3
        self.local_transition_count = 3
        self.current_local_host_head_sha256 = record.current_host_head_sha256
        self.post_init_error: BaseException | None = None

    def __post_init__(self) -> None:
        if self.post_init_error is not None:
            raise self.post_init_error


class _FakeSnapshot:
    def __init__(self, authority: TrustedTimeHeadAnchorAuthority) -> None:
        record = _FakeRecord(authority)
        intent = _FakeIntent(record)
        self.confirmed_anchor_receipt: object = _FakeReceipt(intent)
        self.authenticated_journal_tip: object = _FakeTip(record)
        self.complete_replay = True
        self.pending_intent: object | None = None
        self.confirmed_anchor_count = 3
        self.local_transition_count = 3
        self.current_host_head_sha256 = record.current_host_head_sha256


def _patch_sql_projection_types(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        reauth_module,
        "TrustedTimeHeadAnchorPersistenceSnapshot",
        _FakeSnapshot,
    )
    monkeypatch.setattr(
        reauth_module,
        "PersistedTrustedTimeHeadAnchorReceipt",
        _FakeReceipt,
    )
    monkeypatch.setattr(
        reauth_module,
        "PersistedTrustedTimeHeadAnchorIntent",
        _FakeIntent,
    )
    monkeypatch.setattr(reauth_module, "TrustedTimeHeadAnchorRecord", _FakeRecord)
    monkeypatch.setattr(
        reauth_module,
        "AuthenticatedTrustedTimeHeadJournalTip",
        _FakeTip,
    )


def _mutate_fake_sql_snapshot(snapshot: _FakeSnapshot, mutation: str) -> None:
    receipt = cast(_FakeReceipt, snapshot.confirmed_anchor_receipt)
    intent = receipt.intent
    record = intent.record
    tip = cast(_FakeTip, snapshot.authenticated_journal_tip)
    targets: dict[str, tuple[object, str, object]] = {
        "complete_replay": (snapshot, "complete_replay", False),
        "pending": (snapshot, "pending_intent", object()),
        "snapshot_count": (snapshot, "confirmed_anchor_count", 4),
        "snapshot_local_count": (snapshot, "local_transition_count", 4),
        "snapshot_head": (snapshot, "current_host_head_sha256", "0" * 64),
        "receipt_readback": (receipt, "readback_bytes_sha256", "0" * 64),
        "reason": (
            record,
            "checkpoint_reason",
            TrustedTimeHeadAnchorCheckpointReason.PERIODIC,
        ),
        "sequence": (record, "anchor_sequence", 2),
        "predecessor": (record, "previous_anchor_sha256", None),
        "record_head": (record, "current_host_head_sha256", "0" * 64),
        "tip_count": (tip, "confirmed_anchor_count", 4),
        "tip_record": (tip, "confirmed_anchor_tip", object()),
        "tip_ordinal": (tip, "confirmed_anchor_local_transition_ordinal", 2),
        "tip_local_count": (tip, "local_transition_count", 4),
        "tip_head": (tip, "current_local_host_head_sha256", "0" * 64),
        "anchor_authority": (record, "anchor_authority_sha256", "0" * 64),
        "deployment": (record, "deployment_identity_sha256", "0" * 64),
        "runtime_database": (record, "runtime_database_identity_sha256", "0" * 64),
        "anchor_project_identity": (record, "anchor_project_identity_sha256", "0" * 64),
        "anchor_project_ref": (record, "anchor_project_ref", "c" * 20),
        "bucket": (record, "bucket_name", "wrong-bucket"),
        "principal": (record, "principal_id", "22222222-2222-4222-8222-222222222222"),
        "host": (record, "host_id", "different-host"),
        "source_authority": (record, "source_authority_sha256", "0" * 64),
        "signing_key_id": (record, "signing_key_id", "anchor.key.v2"),
        "signing_public_key": (record, "signing_public_key_sha256", "0" * 64),
        "checkpoint_interval": (record, "checkpoint_interval_seconds", 31),
    }
    target, name, value = targets[mutation]
    setattr(target, name, value)


def _configuration(
    *, password: str = "S" * 32
) -> TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration:
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
        email="clean-stop@example.invalid",
        password=password,
    )
    verifier = Ed25519TrustedTimeAnchorVerifier.from_public_key_bytes(
        signing_key_id=authority.signing_key_id,
        expected_signing_public_key_sha256=authority.signing_public_key_sha256,
        public_key_bytes=public_key,
    )
    return TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration(
        authority=authority,
        credentials=credentials,
        verifier=verifier,
    )


def _projection(**changes: object) -> reauth_module._SqlProjection:
    values: dict[str, object] = {
        "receipt": object(),
        "intent": object(),
        "record": _RecordView(),
        "journal_tip": object(),
        "anchor_sequence": 3,
        "confirmed_anchor_count": 3,
        "local_transition_count": 3,
        "confirmed_anchor_local_transition_ordinal": 3,
        "predecessor_anchor_sha256": "6" * 64,
        "current_host_head_sha256": "7" * 64,
        "current_anchor_sha256": "8" * 64,
        "current_anchor_semantic_sha256": "9" * 64,
        "anchor_intent_semantic_sha256": "a" * 64,
        "candidate_remote_readback_sha256": "8" * 64,
        "receipt_semantic_sha256": "b" * 64,
        "receipt_observed_at_utc": _OBSERVED_AT,
    }
    values.update(changes)
    return reauth_module._SqlProjection(**cast(Any, values))


def _harness(
    *,
    configuration: TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration | None = None,
    clock: _Clock | None = None,
    factory_error: BaseException | None = None,
    runner_error: BaseException | None = None,
    runner_observation: reauth_module._VerifiedObservation | None = None,
    mutate_during_runner: Any = None,
    close_error: BaseException | None = None,
) -> tuple[
    TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer,
    TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration,
    dict[str, object],
]:
    exact_configuration = _configuration() if configuration is None else configuration
    exact_clock = _Clock() if clock is None else clock
    observations: dict[str, object] = {
        "closed": [],
        "constructed": [],
        "factory_configurations": [],
    }

    def resource_factory(*, owner: reauth_module._ResourceOwner, **kwargs: object) -> object:
        cast(list[str], observations["constructed"]).append("constructed")
        cast(list[object], observations["factory_configurations"]).append(kwargs["configuration"])

        def close() -> None:
            cast(list[str], observations["closed"]).append("closed")
            if close_error is not None:
                raise close_error

        owner.register(close)
        if factory_error is not None:
            raise factory_error
        return object()

    def verification_runner(
        _: object,
        guard: reauth_module._VerificationPhaseGuard,
    ) -> reauth_module._VerifiedObservation:
        if mutate_during_runner is not None:
            mutate_during_runner()
        if runner_error is not None:
            raise runner_error
        if runner_observation is not None:
            return runner_observation
        completed = guard.observe()
        return reauth_module._VerifiedObservation(
            projection=_projection(),
            remote_observation_sha256="c" * 64,
            observation_started_monotonic_ns=guard.started_monotonic_ns,
            observation_completed_monotonic_ns=completed,
            deadline_monotonic_ns=guard.deadline_monotonic_ns,
        )

    prepare = _build_preparer(
        resource_factory=resource_factory,
        verification_runner=verification_runner,
        monotonic_ns=exact_clock,
    )
    issuer = prepare(database_url=_DATABASE_URL, configuration=exact_configuration)
    observations["clock"] = exact_clock
    return issuer, exact_configuration, observations


def _direct_private_issue(
    *,
    issuer: TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer,
    configuration: TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration,
    observation: reauth_module._VerifiedObservation,
    capability: object | None = None,
) -> TrustedTimePostEnrollmentCleanStopTerminalPostcondition:
    return reauth_module._issue_postcondition(
        issuer=issuer,
        issuer_capability=issuer._capability if capability is None else capability,
        observation=observation,
        authority=configuration.authority,
        issuer_binding_sha256=issuer.issuer_binding_sha256,
        configuration_sha256=issuer.read_only_configuration_sha256,
        owner_pid=os.getpid(),
        owner_thread=threading.current_thread(),
    )


def test_public_contract_surface_and_read_only_configuration_redaction() -> None:
    configuration = _configuration()
    signature = inspect.signature(
        prepare_trusted_time_post_enrollment_clean_stop_terminal_reauthentication_issuer
    )

    assert POST_ENROLLMENT_CLEAN_STOP_TERMINAL_REAUTHENTICATION_CONTRACT_VERSION == (
        "phase6d-post-enrollment-clean-stop-terminal-reauthentication-v1"
    )
    assert tuple(signature.parameters) == ("database_url", "configuration")
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in signature.parameters.values()
    )
    rendered = repr(configuration)
    assert "sb_publishable_" not in rendered
    assert "clean-stop@example.invalid" not in rendered
    assert "S" * 32 not in rendered
    assert len(configuration.configuration_sha256) == 64


def test_public_preparer_pins_only_production_dependencies() -> None:
    dependencies = inspect.getclosurevars(
        prepare_trusted_time_post_enrollment_clean_stop_terminal_reauthentication_issuer
    ).nonlocals

    assert dependencies["resource_factory"] is reauth_module._create_production_resources
    assert dependencies["verification_runner"] is reauth_module._production_verify_once
    assert dependencies["monotonic_ns"] is reauth_module._suspend_aware_monotonic_ns
    assert dependencies["process_id"] is os.getpid
    assert dependencies["current_thread"] is threading.current_thread


def test_private_binding_clones_secrets_without_rendering_or_publicly_hashing_them() -> None:
    first = _configuration(password="S" * 32)
    second = TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration(
        authority=first.authority,
        credentials=replace(first.credentials, password="T" * 32),
        verifier=first.verifier,
    )
    first_binding = reauth_module._capture_configuration_binding(first)
    second_binding = reauth_module._capture_configuration_binding(second)

    assert first.configuration_sha256 == second.configuration_sha256
    assert first_binding.public_configuration_sha256 == (second_binding.public_configuration_sha256)
    assert first_binding.credential_values != second_binding.credential_values
    assert first_binding.private_configuration is not first
    assert first_binding.private_configuration.authority is not first.authority
    assert first_binding.private_configuration.credentials is not first.credentials
    assert first_binding.private_configuration.verifier is not first.verifier
    rendered = repr(first_binding)
    assert first.credentials.publishable_key not in rendered
    assert first.credentials.email not in rendered
    assert first.credentials.password not in rendered
    assert "secret_configuration_sha256" not in inspect.getsource(reauth_module)


def test_one_shot_issuer_emits_only_bounded_historical_truth_and_cleans_resources() -> None:
    issuer, configuration, observations = _harness()
    binding = issuer.issuer_binding_sha256
    configuration_digest = issuer.read_only_configuration_sha256

    result = issuer.reauthenticate_clean_stop_terminal_once()

    assert type(result) is TrustedTimePostEnrollmentCleanStopTerminalPostcondition
    assert result.contract_version == (
        POST_ENROLLMENT_CLEAN_STOP_TERMINAL_REAUTHENTICATION_CONTRACT_VERSION
    )
    assert result.status == "provider_terminal_observed_under_stable_sql_authenticated"
    assert result.provider_terminal_observed_under_stable_sql_authenticated is True
    assert (
        result.anchor_sequence == result.confirmed_anchor_count == result.remote_object_count == 3
    )
    assert result.checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP
    assert result.issuer_binding_sha256 == binding
    assert result.read_only_configuration_sha256 == configuration_digest
    assert result.anchor_authority_sha256 == configuration.authority.anchor_authority_sha256
    assert all(getattr(result, field_name) is False for field_name in _FALSE_AUTHORITY_PROPERTIES)
    assert observations["constructed"] == ["constructed"]
    assert observations["closed"] == ["closed"]
    private_configuration = cast(list[object], observations["factory_configurations"])[0]
    assert private_configuration is not configuration

    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        issuer.reauthenticate_clean_stop_terminal_once()


def test_issuer_and_result_have_the_exact_same_false_authority_descriptor_set() -> None:
    for subject_type in (
        TrustedTimePostEnrollmentCleanStopTerminalPostcondition,
        TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer,
    ):
        descriptors = {
            name: descriptor
            for name, descriptor in vars(subject_type).items()
            if type(descriptor) is property and descriptor.fget is reauth_module._never_authorized
        }
        assert frozenset(descriptors) == _FALSE_AUTHORITY_PROPERTIES
        assert all(
            type(descriptor) is property and descriptor.fget is reauth_module._never_authorized
            for descriptor in descriptors.values()
        )
        assert not hasattr(subject_type, "provider_terminal_authenticated")


def test_issuer_and_result_are_sealed_immutable_noncopyable_and_nonserializable() -> None:
    issuer, _, _ = _harness()
    result = issuer.reauthenticate_clean_stop_terminal_once()

    for value in (issuer, result):
        with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
            copy.copy(value)
        with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
            copy.deepcopy(value)
        with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
            pickle.dumps(value)
    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer()
    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        TrustedTimePostEnrollmentCleanStopTerminalPostcondition()
    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        issuer._capability = object()  # type: ignore[assignment]
    with pytest.raises(
        (
            FrozenInstanceError,
            TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected,
        )
    ):
        result.anchor_sequence = 4  # type: ignore[misc]
    with pytest.raises(
        (
            TypeError,
            TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected,
        )
    ):
        replace(result, anchor_sequence=4)


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    (
        ("anchor_sequence", 4),
        ("receipt_observed_at_utc", _OBSERVED_AT + timedelta(microseconds=1)),
        ("remote_observation_sha256", "d" * 64),
    ),
)
def test_valid_shaped_result_tamper_invalidates_every_property_accessor(
    field_name: str,
    replacement: object,
) -> None:
    issuer, _, _ = _harness()
    result = issuer.reauthenticate_clean_stop_terminal_once()
    object.__setattr__(result, field_name, replacement)
    false_property_names = tuple(
        name
        for name, descriptor in vars(type(result)).items()
        if type(descriptor) is property and descriptor.fget is reauth_module._never_authorized
    )
    accessors: tuple[Callable[[], object], ...] = (
        lambda: result.contract_version,
        lambda: result.status,
        lambda: result.semantic_sha256,
        lambda: result.provider_terminal_observed_under_stable_sql_authenticated,
        *(lambda name=name: getattr(result, name) for name in false_property_names),
    )

    for access in accessors:
        with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
            access()


def test_object_level_issuer_capability_swap_invalidates_every_accessor() -> None:
    first, _, _ = _harness()
    second, _, _ = _harness()
    object.__setattr__(first, "_capability", second._capability)
    false_property_names = tuple(
        name
        for name, descriptor in vars(type(first)).items()
        if type(descriptor) is property and descriptor.fget is reauth_module._never_authorized
    )
    accessors: tuple[Callable[[], object], ...] = (
        lambda: first.issuer_binding_sha256,
        lambda: first.read_only_configuration_sha256,
        lambda: first.reauthenticate_clean_stop_terminal_once(),
        *(lambda name=name: getattr(first, name) for name in false_property_names),
    )

    for access in accessors:
        with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
            access()


@pytest.mark.parametrize("component", ["authority", "credentials", "verifier"])
def test_post_prepare_configuration_drift_burns_issuer_before_resource_construction(
    component: str,
) -> None:
    issuer, configuration, observations = _harness()
    if component == "authority":
        object.__setattr__(configuration.authority, "host_id", "trusted-time-host-two")
    elif component == "credentials":
        object.__setattr__(configuration.credentials, "password", "T" * 32)
    else:
        object.__setattr__(configuration.verifier, "signing_key_id", "anchor.key.v2")
        object.__setattr__(configuration.authority, "signing_key_id", "anchor.key.v2")

    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        issuer.reauthenticate_clean_stop_terminal_once()

    assert observations["constructed"] == []
    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        issuer.reauthenticate_clean_stop_terminal_once()


def test_mid_provider_and_final_clock_configuration_drift_burn_without_result() -> None:
    configuration = _configuration()

    def mutate_in_runner() -> None:
        object.__setattr__(configuration.credentials, "password", "T" * 32)

    issuer, _, observations = _harness(
        configuration=configuration,
        mutate_during_runner=mutate_in_runner,
    )
    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        issuer.reauthenticate_clean_stop_terminal_once()
    assert observations["closed"] == ["closed"]

    configuration = _configuration()

    class MutatingClock(_Clock):
        def __call__(self) -> int:
            value = super().__call__()
            if self.calls == 4:
                object.__setattr__(configuration.credentials, "password", "T" * 32)
            return value

    issuer, _, observations = _harness(
        configuration=configuration,
        clock=MutatingClock(),
    )
    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        issuer.reauthenticate_clean_stop_terminal_once()
    assert observations["closed"] == ["closed"]


def test_private_snapshot_mutation_during_runner_is_detected_before_issuance() -> None:
    observations: dict[str, object]

    def mutate_private_snapshot() -> None:
        private_configuration = cast(
            list[TrustedTimePostEnrollmentCleanStopReadOnlyConfiguration],
            observations["factory_configurations"],
        )[0]
        object.__setattr__(private_configuration.credentials, "password", "T" * 32)

    issuer, _, observations = _harness(mutate_during_runner=mutate_private_snapshot)

    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        issuer.reauthenticate_clean_stop_terminal_once()

    assert observations["closed"] == ["closed"]


@pytest.mark.parametrize(
    "mutation",
    (
        "complete_replay",
        "pending",
        "snapshot_count",
        "snapshot_local_count",
        "snapshot_head",
        "receipt_readback",
        "reason",
        "sequence",
        "predecessor",
        "record_head",
        "tip_count",
        "tip_record",
        "tip_ordinal",
        "tip_local_count",
        "tip_head",
        "anchor_authority",
        "deployment",
        "runtime_database",
        "anchor_project_identity",
        "anchor_project_ref",
        "bucket",
        "principal",
        "host",
        "source_authority",
        "signing_key_id",
        "signing_public_key",
        "checkpoint_interval",
    ),
)
def test_exact_sql_projection_rejects_every_terminal_shape_or_authority_drift(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    configuration = _configuration()
    snapshot = _FakeSnapshot(configuration.authority)
    _patch_sql_projection_types(monkeypatch)
    _mutate_fake_sql_snapshot(snapshot, mutation)

    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        reauth_module._capture_sql_projection(
            snapshot,
            authority=configuration.authority,
        )


def test_exact_sql_projection_accepts_only_the_current_clean_stop_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration = _configuration()
    snapshot = _FakeSnapshot(configuration.authority)
    _patch_sql_projection_types(monkeypatch)

    projection = reauth_module._capture_sql_projection(
        snapshot,
        authority=configuration.authority,
    )

    assert projection.anchor_sequence == 3
    assert projection.confirmed_anchor_count == 3
    assert projection.confirmed_anchor_local_transition_ordinal == 3
    assert projection.current_anchor_sha256 == "8" * 64


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(29)])
def test_sql_projection_async_validation_error_escapes_exact(
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
) -> None:
    configuration = _configuration()
    snapshot = _FakeSnapshot(configuration.authority)
    receipt = cast(_FakeReceipt, snapshot.confirmed_anchor_receipt)
    receipt.post_init_error = error
    _patch_sql_projection_types(monkeypatch)

    with pytest.raises(type(error)) as caught:
        reauth_module._capture_sql_projection(
            snapshot,
            authority=configuration.authority,
        )

    assert caught.value is error


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(17)])
@pytest.mark.parametrize("boundary", ["factory", "runner", "close"])
def test_async_base_exceptions_escape_exact_and_burn_issuer(
    error: BaseException,
    boundary: str,
) -> None:
    kwargs: dict[str, object] = {f"{boundary}_error": error}
    issuer, _, observations = _harness(**cast(Any, kwargs))

    with pytest.raises(type(error)) as caught:
        issuer.reauthenticate_clean_stop_terminal_once()

    assert caught.value is error
    if boundary != "factory":
        assert observations["closed"] == ["closed"]
    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        issuer.reauthenticate_clean_stop_terminal_once()


@pytest.mark.parametrize(
    "field_name", ["observation_started_monotonic_ns", "deadline_monotonic_ns"]
)
def test_runner_cannot_widen_or_replace_issuer_clock_binding(field_name: str) -> None:
    clock = _Clock()
    baseline = reauth_module._VerifiedObservation(
        projection=_projection(),
        remote_observation_sha256="c" * 64,
        observation_started_monotonic_ns=clock.value,
        observation_completed_monotonic_ns=clock.value,
        deadline_monotonic_ns=clock.value + reauth_module._PHASE_TIMEOUT_NANOSECONDS,
    )
    replacement = (
        clock.value - 1
        if field_name == "observation_started_monotonic_ns"
        else baseline.deadline_monotonic_ns + 1
    )
    if field_name == "observation_started_monotonic_ns":
        changed = replace(baseline, observation_started_monotonic_ns=replacement)
    else:
        changed = replace(baseline, deadline_monotonic_ns=replacement)
    issuer, _, observations = _harness(clock=clock, runner_observation=changed)

    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        issuer.reauthenticate_clean_stop_terminal_once()
    assert observations["closed"] == ["closed"]


def test_deadline_equality_and_clock_regression_fail_before_or_during_resources() -> None:
    clock = _Clock()
    issuer, _, observations = _harness(clock=clock)
    clock.value += reauth_module._PHASE_TIMEOUT_NANOSECONDS
    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        issuer.reauthenticate_clean_stop_terminal_once()
    assert observations["constructed"] == []

    values = iter((10, 9))
    prepare = _build_preparer(
        resource_factory=lambda **_: object(),
        verification_runner=lambda *_: cast(Any, None),
        monotonic_ns=lambda: next(values),
    )
    issuer = prepare(database_url=_DATABASE_URL, configuration=_configuration())
    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        issuer.reauthenticate_clean_stop_terminal_once()


def test_cross_thread_access_rejected_before_and_after_terminal_state() -> None:
    issuer, _, observations = _harness()
    errors: list[BaseException] = []

    def access() -> None:
        try:
            _ = issuer.issuer_binding_sha256
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=access)
    thread.start()
    thread.join()
    assert len(errors) == 1
    assert type(errors[0]) is TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected
    assert observations["constructed"] == []

    issuer.reauthenticate_clean_stop_terminal_once()
    errors.clear()
    thread = threading.Thread(target=access)
    thread.start()
    thread.join()
    assert len(errors) == 1
    assert type(errors[0]) is TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected

    failed, _, _ = _harness(runner_error=ValueError("failed"))
    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        failed.reauthenticate_clean_stop_terminal_once()
    errors.clear()

    def access_failed() -> None:
        try:
            _ = failed.read_only_configuration_sha256
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=access_failed)
    thread.start()
    thread.join()
    assert len(errors) == 1
    assert type(errors[0]) is TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires fork process semantics")
def test_post_fork_issuer_and_result_access_fail_closed_after_success_and_failure() -> None:
    confirmed, _, _ = _harness()
    result = confirmed.reauthenticate_clean_stop_terminal_once()
    failed, _, _ = _harness(runner_error=ValueError("failed"))
    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        failed.reauthenticate_clean_stop_terminal_once()
    read_fd, write_fd = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:
        os.close(read_fd)
        rejected = bytearray()
        reads: tuple[Callable[[], object], ...] = (
            lambda: confirmed.issuer_binding_sha256,
            lambda: result.status,
            lambda: failed.read_only_configuration_sha256,
        )
        for read in reads:
            try:
                read()
            except TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected:
                rejected.extend(b"1")
            else:
                rejected.extend(b"0")
        os.write(write_fd, bytes(rejected))
        os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    observed = os.read(read_fd, 3)
    os.close(read_fd)
    _, status = os.waitpid(child_pid, 0)

    assert status == 0
    assert observed == b"111"


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires fork process semantics")
def test_postcondition_registry_held_across_fork_rejects_without_child_deadlock() -> None:
    issuer, _, _ = _harness()
    result = issuer.reauthenticate_clean_stop_terminal_once()
    read_fd, write_fd = os.pipe()
    reauth_module._POSTCONDITION_REGISTRY_LOCK.acquire()
    reauth_module._ISSUER_DISPATCH_REGISTRY_LOCK.acquire()
    child_pid = os.fork()
    if child_pid == 0:  # pragma: no cover - asserted through the pipe
        os.close(read_fd)
        rejected = bytearray()

        def consume() -> None:
            reauth_module._consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once(
                result,
                issuer=issuer,
                bridge_identity=object(),
            )

        for operation in (
            lambda: issuer.issuer_binding_sha256,
            lambda: result.status,
            consume,
        ):
            try:
                operation()
            except TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected:
                rejected.extend(b"1")
            else:
                rejected.extend(b"0")
        os.write(write_fd, bytes(rejected))
        os.close(write_fd)
        os._exit(0)

    os.close(write_fd)
    try:
        readable, _, _ = select.select([read_fd], [], [], 2.0)
    finally:
        reauth_module._ISSUER_DISPATCH_REGISTRY_LOCK.release()
        reauth_module._POSTCONDITION_REGISTRY_LOCK.release()
    if readable:
        observed = os.read(read_fd, 3)
    else:
        observed = b""
        os.kill(child_pid, signal.SIGKILL)
    os.close(read_fd)
    _, status = os.waitpid(child_pid, 0)

    assert readable == [read_fd]
    assert status == 0
    assert observed == b"111"
    assert result.status == "provider_terminal_observed_under_stable_sql_authenticated"
    reauth_module._consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once(
        result,
        issuer=issuer,
        bridge_identity=object(),
    )


def test_lost_prepared_issuer_revokes_without_constructing_resources() -> None:
    issuer, _, observations = _harness()
    reference = weakref.ref(issuer)

    del issuer
    gc.collect()

    assert reference() is None
    assert observations["constructed"] == []


def test_production_choreography_is_sql_one_remote_sql_two_and_discards_both(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration = _configuration()
    projection = _projection()
    snapshots = (object(), object())
    events: list[str] = []

    class Repository:
        def __init__(self) -> None:
            self.loads = 0
            self.discarded: list[object] = []

        def load_head_anchor_startup_snapshot(self, **_: object) -> object:
            self.loads += 1
            events.append(f"sql-{self.loads}")
            return snapshots[self.loads - 1]

        def discard_head_anchor_snapshot(self, snapshot: object) -> None:
            self.discarded.append(snapshot)

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
    owner = reauth_module._ResourceOwner()
    resources = reauth_module._ProductionResources(
        authority=configuration.authority,
        repository=cast(Any, repository),
        provider=cast(Any, provider),
        verifier=configuration.verifier,
        router=cast(Any, router),
        owner=owner,
    )
    guard = reauth_module._VerificationPhaseGuard(
        started_monotonic_ns=1,
        deadline_monotonic_ns=10_000_000_000,
        clock=lambda: 1,
        owner_pid=os.getpid(),
        owner_thread=threading.current_thread(),
    )
    captured: list[tuple[object, dict[str, object]]] = []

    def capture(_: object, **__: object) -> reauth_module._SqlProjection:
        return projection

    def remote(tip: object, **kwargs: object) -> str:
        events.append("provider")
        captured.append((tip, kwargs))
        return "d" * 64

    monkeypatch.setattr(reauth_module, "_capture_sql_projection", capture)
    monkeypatch.setattr(
        reauth_module,
        "verify_bounded_clean_stop_terminal_remote_postcondition",
        remote,
    )

    observed = resources.verify(guard)
    owner.close(require_success=True)

    assert events == ["sql-1", "provider", "sql-2"]
    assert observed.projection is projection
    assert observed.remote_observation_sha256 == "d" * 64
    assert repository.discarded == [snapshots[1], snapshots[0]]
    assert captured[0][0] is projection.journal_tip
    assert captured[0][1]["provider"] is provider
    assert provider.events == [("activate", guard), ("deactivate", guard)]
    assert router.events == [("activate", guard), ("deactivate", guard)]


def test_invalid_sql_one_never_calls_provider_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration = _configuration()
    snapshot = _FakeSnapshot(configuration.authority)
    snapshot.complete_replay = False
    _patch_sql_projection_types(monkeypatch)
    remote_calls: list[int] = []

    class Repository:
        def load_head_anchor_startup_snapshot(self, **_: object) -> object:
            return snapshot

        def discard_head_anchor_snapshot(self, _: object) -> None:
            return None

    class Boundary:
        def activate(self, _: object) -> None:
            return None

        def deactivate(self, _: object) -> None:
            return None

    def remote(*_: object, **__: object) -> str:
        remote_calls.append(1)
        return "d" * 64

    monkeypatch.setattr(
        reauth_module,
        "verify_bounded_clean_stop_terminal_remote_postcondition",
        remote,
    )
    owner = reauth_module._ResourceOwner()
    resources = reauth_module._ProductionResources(
        authority=configuration.authority,
        repository=cast(Any, Repository()),
        provider=cast(Any, Boundary()),
        verifier=configuration.verifier,
        router=cast(Any, Boundary()),
        owner=owner,
    )
    guard = reauth_module._VerificationPhaseGuard(
        started_monotonic_ns=1,
        deadline_monotonic_ns=10_000_000_000,
        clock=lambda: 1,
        owner_pid=os.getpid(),
        owner_thread=threading.current_thread(),
    )

    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        resources.verify(guard)

    owner.close(require_success=False)
    assert remote_calls == []


@pytest.mark.parametrize(
    "field_name",
    tuple(reauth_module._SqlProjection.__dataclass_fields__),
)
def test_every_sql_two_projection_drift_rejects(
    monkeypatch: pytest.MonkeyPatch,
    field_name: str,
) -> None:
    configuration = _configuration()
    initial = _projection()
    current = getattr(initial, field_name)
    if field_name == "record":
        replacement: object = _RecordView(TrustedTimeHeadAnchorCheckpointReason.PERIODIC)
    elif type(current) is int:
        replacement = current + 1
    elif type(current) is str:
        replacement = "0" * 64
    elif type(current) is datetime:
        replacement = current + timedelta(microseconds=1)
    else:
        replacement = object()
    replace_any = cast(Any, replace)
    final = cast(reauth_module._SqlProjection, replace_any(initial, **{field_name: replacement}))
    projections = iter((initial, final))

    class Repository:
        def load_head_anchor_startup_snapshot(self, **_: object) -> object:
            return object()

        def discard_head_anchor_snapshot(self, _: object) -> None:
            return None

    class Boundary:
        def activate(self, _: object) -> None:
            return None

        def deactivate(self, _: object) -> None:
            return None

    monkeypatch.setattr(
        reauth_module,
        "_capture_sql_projection",
        lambda *_a, **_k: next(projections),
    )
    monkeypatch.setattr(
        reauth_module,
        "verify_bounded_clean_stop_terminal_remote_postcondition",
        lambda *_a, **_k: "d" * 64,
    )
    owner = reauth_module._ResourceOwner()
    resources = reauth_module._ProductionResources(
        authority=configuration.authority,
        repository=cast(Any, Repository()),
        provider=cast(Any, Boundary()),
        verifier=configuration.verifier,
        router=cast(Any, Boundary()),
        owner=owner,
    )
    guard = reauth_module._VerificationPhaseGuard(
        started_monotonic_ns=1,
        deadline_monotonic_ns=10_000_000_000,
        clock=lambda: 1,
        owner_pid=os.getpid(),
        owner_thread=threading.current_thread(),
    )

    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        resources.verify(guard)

    owner.close(require_success=False)


def test_production_sql_drift_rejects_and_deactivates_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration = _configuration()
    projections = iter((_projection(), _projection(receipt_semantic_sha256="e" * 64)))

    class Repository:
        def load_head_anchor_startup_snapshot(self, **_: object) -> object:
            return object()

        def discard_head_anchor_snapshot(self, _: object) -> None:
            return None

    class Boundary:
        def __init__(self) -> None:
            self.events: list[str] = []

        def activate(self, _: object) -> None:
            self.events.append("activate")

        def deactivate(self, _: object) -> None:
            self.events.append("deactivate")

    provider = Boundary()
    router = Boundary()
    owner = reauth_module._ResourceOwner()
    resources = reauth_module._ProductionResources(
        authority=configuration.authority,
        repository=cast(Any, Repository()),
        provider=cast(Any, provider),
        verifier=configuration.verifier,
        router=cast(Any, router),
        owner=owner,
    )
    guard = reauth_module._VerificationPhaseGuard(
        started_monotonic_ns=1,
        deadline_monotonic_ns=10_000_000_000,
        clock=lambda: 1,
        owner_pid=os.getpid(),
        owner_thread=threading.current_thread(),
    )
    monkeypatch.setattr(
        reauth_module, "_capture_sql_projection", lambda *_a, **_k: next(projections)
    )
    monkeypatch.setattr(
        reauth_module,
        "verify_bounded_clean_stop_terminal_remote_postcondition",
        lambda *_a, **_k: "d" * 64,
    )

    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        resources.verify(guard)

    owner.close(require_success=False)
    assert provider.events == ["activate", "deactivate"]
    assert router.events == ["activate", "deactivate"]


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(23)])
def test_provider_async_error_is_not_masked_when_clock_expires(error: BaseException) -> None:
    clock = _Clock(value=0)
    deadline = 1_000_000_000

    class Provider:
        _timeout_seconds = 1.0

        def download_object(self, **_: object) -> bytes:
            clock.value = deadline
            raise error

    wrapper = reauth_module._DeadlineBoundReadOnlyProvider(cast(Any, Provider()))
    guard = reauth_module._VerificationPhaseGuard(
        started_monotonic_ns=0,
        deadline_monotonic_ns=deadline,
        clock=clock,
        owner_pid=os.getpid(),
        owner_thread=threading.current_thread(),
    )
    wrapper.activate(guard)

    with pytest.raises(type(error)) as caught:
        wrapper.download_object(bucket_name="bucket", object_name="object")

    assert caught.value is error
    assert not hasattr(wrapper, "upload_object_no_overwrite")


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(31)])
def test_post_registration_validation_async_rolls_back_exact_registry_entry(
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
) -> None:
    issuer, _, observations = _harness()
    registry_before = set(reauth_module._POSTCONDITION_REGISTRY)

    def interrupt(_: object) -> None:
        raise error

    monkeypatch.setattr(
        TrustedTimePostEnrollmentCleanStopTerminalPostcondition,
        "__post_init__",
        interrupt,
    )

    with pytest.raises(type(error)) as caught:
        issuer.reauthenticate_clean_stop_terminal_once()

    gc.collect()
    assert caught.value is error
    assert set(reauth_module._POSTCONDITION_REGISTRY) == registry_before
    assert observations["closed"] == ["closed"]


def test_unretained_issued_result_is_removed_from_weak_registry() -> None:
    issuer, _, _ = _harness()
    registry_before = set(reauth_module._POSTCONDITION_REGISTRY)
    result = issuer.reauthenticate_clean_stop_terminal_once()
    result_id = id(result)
    assert result_id in reauth_module._POSTCONDITION_REGISTRY

    del result
    gc.collect()

    assert set(reauth_module._POSTCONDITION_REGISTRY) == registry_before


def test_arbitrary_capability_wrong_issuer_and_forged_observation_cannot_issue() -> None:
    configuration = _configuration()
    first, _, _ = _harness(configuration=configuration)
    second, _, _ = _harness()
    forged = reauth_module._VerifiedObservation(
        projection=_projection(),
        remote_observation_sha256="c" * 64,
        observation_started_monotonic_ns=1,
        observation_completed_monotonic_ns=2,
        deadline_monotonic_ns=3,
    )
    arbitrary_capability = object.__new__(cast(type[Any], reauth_module._PostconditionCapability))

    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        _direct_private_issue(
            issuer=first,
            configuration=configuration,
            observation=forged,
            capability=arbitrary_capability,
        )
    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        _direct_private_issue(
            issuer=first,
            configuration=configuration,
            observation=forged,
            capability=second._capability,
        )
    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        _direct_private_issue(
            issuer=first,
            configuration=configuration,
            observation=forged,
        )


def test_live_capability_cannot_issue_forged_observation_while_in_flight() -> None:
    configuration = _configuration()
    rejected: list[str] = []
    issuer: TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer

    def attempt_forgery() -> None:
        forged = reauth_module._VerifiedObservation(
            projection=_projection(),
            remote_observation_sha256="c" * 64,
            observation_started_monotonic_ns=1,
            observation_completed_monotonic_ns=2,
            deadline_monotonic_ns=3,
        )
        with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
            _direct_private_issue(
                issuer=issuer,
                configuration=configuration,
                observation=forged,
            )
        rejected.append("rejected")

    issuer, _, _ = _harness(
        configuration=configuration,
        mutate_during_runner=attempt_forgery,
    )

    result = issuer.reauthenticate_clean_stop_terminal_once()

    assert result.provider_terminal_observed_under_stable_sql_authenticated is True
    assert rejected == ["rejected"]


def test_exact_issuance_observation_is_consumed_once_and_cannot_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_issue = reauth_module._issue_postcondition
    captured: list[dict[str, object]] = []

    def capture_issue(**kwargs: object) -> TrustedTimePostEnrollmentCleanStopTerminalPostcondition:
        captured.append(dict(kwargs))
        return original_issue(**cast(Any, kwargs))

    monkeypatch.setattr(reauth_module, "_issue_postcondition", capture_issue)
    issuer, _, _ = _harness()
    result = issuer.reauthenticate_clean_stop_terminal_once()

    assert result.provider_terminal_observed_under_stable_sql_authenticated is True
    assert len(captured) == 1
    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        original_issue(**cast(Any, captured[0]))


def test_private_bridge_consumer_binds_exact_issuer_and_identity_once() -> None:
    issuer, _, _ = _harness()
    result = issuer.reauthenticate_clean_stop_terminal_once()
    bridge_identity = object()

    consumed = (
        reauth_module._consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once(
            result,
            issuer=issuer,
            bridge_identity=bridge_identity,
        )
    )

    registration = reauth_module._POSTCONDITION_REGISTRY[id(result)]
    assert type(consumed) is reauth_module._ConsumedPostconditionRegistrySnapshot
    assert consumed.values == registration[4]
    assert consumed.semantic_sha256 == registration[5]
    assert consumed.issuer_identity is issuer
    assert consumed.bridge_identity is bridge_identity
    assert registration[6]() is issuer
    assert registration[7] is bridge_identity
    assert registration[8] is True
    assert result.provider_terminal_observed_under_stable_sql_authenticated is True
    validated = reauth_module._validate_trusted_time_post_enrollment_clean_stop_terminal_postcondition_consumed_by(  # noqa: E501
        result,
        issuer=issuer,
        bridge_identity=bridge_identity,
    )
    assert validated == consumed
    assert validated.issuer_identity is issuer
    assert validated.bridge_identity is bridge_identity

    wrong_issuer, _, _ = _harness()
    for invalid_issuer, invalid_bridge in (
        (wrong_issuer, bridge_identity),
        (issuer, object()),
    ):
        with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
            reauth_module._validate_trusted_time_post_enrollment_clean_stop_terminal_postcondition_consumed_by(
                result,
                issuer=invalid_issuer,
                bridge_identity=invalid_bridge,
            )
    reauth_module._validate_trusted_time_post_enrollment_clean_stop_terminal_postcondition_consumed_by(
        result,
        issuer=issuer,
        bridge_identity=bridge_identity,
    )

    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        reauth_module._consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once(
            result,
            issuer=issuer,
            bridge_identity=bridge_identity,
        )
    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        result.__post_init__()


@pytest.mark.parametrize("invalid_bridge_identity", [None])
def test_private_bridge_consumer_invalid_identity_burns_before_retry(
    invalid_bridge_identity: object,
) -> None:
    issuer, _, _ = _harness()
    result = issuer.reauthenticate_clean_stop_terminal_once()

    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        reauth_module._consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once(
            result,
            issuer=issuer,
            bridge_identity=invalid_bridge_identity,
        )

    assert id(result) not in reauth_module._POSTCONDITION_REGISTRY
    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        reauth_module._consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once(
            result,
            issuer=issuer,
            bridge_identity=object(),
        )


def test_private_bridge_consumer_wrong_issuer_burns_before_correct_retry() -> None:
    issuer, _, _ = _harness()
    wrong_issuer, _, _ = _harness()
    result = issuer.reauthenticate_clean_stop_terminal_once()

    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        reauth_module._consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once(
            result,
            issuer=wrong_issuer,
            bridge_identity=object(),
        )

    assert id(result) not in reauth_module._POSTCONDITION_REGISTRY
    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        reauth_module._consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once(
            result,
            issuer=issuer,
            bridge_identity=object(),
        )


def test_private_bridge_consumer_wrong_thread_burns_before_correct_retry() -> None:
    issuer, _, _ = _harness()
    result = issuer.reauthenticate_clean_stop_terminal_once()
    failures: list[BaseException] = []

    def consume_on_wrong_thread() -> None:
        try:
            reauth_module._consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once(
                result,
                issuer=issuer,
                bridge_identity=object(),
            )
        except BaseException as error:
            failures.append(error)

    thread = threading.Thread(target=consume_on_wrong_thread)
    thread.start()
    thread.join()

    assert len(failures) == 1
    assert type(failures[0]) is TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected
    assert id(result) not in reauth_module._POSTCONDITION_REGISTRY
    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        reauth_module._consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once(
            result,
            issuer=issuer,
            bridge_identity=object(),
        )


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(43)])
def test_private_bridge_consumer_async_error_escapes_after_burn(
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
) -> None:
    issuer, _, _ = _harness()
    result = issuer.reauthenticate_clean_stop_terminal_once()
    original_values = reauth_module._postcondition_values

    def interrupting_values(value: object) -> tuple[object, ...]:
        if value is result:
            raise error
        return original_values(cast(Any, value))

    monkeypatch.setattr(reauth_module, "_postcondition_values", interrupting_values)
    with pytest.raises(type(error)) as caught:
        reauth_module._consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once(
            result,
            issuer=issuer,
            bridge_identity=object(),
        )
    assert caught.value is error
    assert id(result) not in reauth_module._POSTCONDITION_REGISTRY

    monkeypatch.setattr(reauth_module, "_postcondition_values", original_values)
    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        reauth_module._consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once(
            result,
            issuer=issuer,
            bridge_identity=object(),
        )


def test_failed_issuance_clears_exact_observation_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_issue = reauth_module._issue_postcondition
    captured: dict[str, object] = {}
    registry_before = set(reauth_module._POSTCONDITION_REGISTRY)

    def fail_issue(**kwargs: object) -> TrustedTimePostEnrollmentCleanStopTerminalPostcondition:
        captured.update(kwargs)
        raise ValueError("injected issuance failure")

    monkeypatch.setattr(reauth_module, "_issue_postcondition", fail_issue)
    issuer, _, observations = _harness()
    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        issuer.reauthenticate_clean_stop_terminal_once()

    assert observations["closed"] == ["closed"]
    assert set(reauth_module._POSTCONDITION_REGISTRY) == registry_before
    with pytest.raises(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected):
        original_issue(**cast(Any, captured))


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(37)])
def test_configuration_and_clock_async_errors_escape_without_issuer(
    error: BaseException,
) -> None:
    configuration = _configuration()

    class PublicKey:
        def public_bytes(self, **_: object) -> bytes:
            raise error

    object.__setattr__(configuration.verifier, "_public_key", PublicKey())
    with pytest.raises(type(error)) as caught:
        prepare_trusted_time_post_enrollment_clean_stop_terminal_reauthentication_issuer(
            database_url=_DATABASE_URL,
            configuration=configuration,
        )
    assert caught.value is error

    def interrupting_clock() -> int:
        raise error

    prepare = _build_preparer(monotonic_ns=interrupting_clock)
    with pytest.raises(type(error)) as caught:
        prepare(database_url=_DATABASE_URL, configuration=_configuration())
    assert caught.value is error


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(41)])
def test_closed_owner_preserves_async_cleanup_error(error: BaseException) -> None:
    owner = reauth_module._ResourceOwner()
    owner.close(require_success=False)

    def interrupt() -> None:
        raise error

    with pytest.raises(type(error)) as caught:
        owner.register(interrupt)

    assert caught.value is error


def test_production_resources_enforce_database_read_only_and_hide_provider_upload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration = _configuration()
    captured: dict[str, object] = {}

    class Engine:
        def dispose(self) -> None:
            return None

    class Provider:
        def close(self) -> None:
            return None

    def create_engine(*_: object, **kwargs: object) -> Engine:
        captured.update(kwargs)
        return Engine()

    monkeypatch.setattr(reauth_module, "pinned_verify_full_connect_args", lambda *_a, **_k: {})
    monkeypatch.setattr(reauth_module, "create_engine", create_engine)
    monkeypatch.setattr(sqlalchemy_event, "listen", lambda *_a, **_k: None)
    monkeypatch.setattr(
        reauth_module,
        "SqlTrustedTimeHeadAnchorRepository",
        lambda *_a, **_k: object(),
    )
    monkeypatch.setattr(
        reauth_module,
        "SupabaseStorageTrustedTimeAnchorProvider",
        lambda **_k: Provider(),
    )
    owner = reauth_module._ResourceOwner()
    guard = reauth_module._VerificationPhaseGuard(
        started_monotonic_ns=1,
        deadline_monotonic_ns=10_000_000_000,
        clock=lambda: 1,
        owner_pid=os.getpid(),
        owner_thread=threading.current_thread(),
    )

    resources = reauth_module._create_production_resources(
        database_url=_DATABASE_URL,
        configuration=configuration,
        owner=owner,
        owner_pid=os.getpid(),
        owner_thread=threading.current_thread(),
        initial_guard=guard,
    )
    owner.close(require_success=True)

    connect_args = cast(dict[str, object], captured["connect_args"])
    assert "-c default_transaction_read_only=on" in cast(str, connect_args["options"])
    assert not hasattr(resources._provider, "upload_object_no_overwrite")
    source = inspect.getsource(reauth_module)
    assert ".commit_prepared_intent(" not in source
    assert ".confirm_remote_readback_from_snapshot(" not in source
    assert ".upload_object_no_overwrite(" not in source
