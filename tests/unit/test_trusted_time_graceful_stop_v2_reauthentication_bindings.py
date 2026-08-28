from __future__ import annotations

import ast
import copy
import gc
import hashlib
import inspect
import os
import pickle
import secrets
import subprocess
import sys
import threading
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from types import FunctionType, MappingProxyType, MethodType, SimpleNamespace
from typing import Any, cast

import pytest

import scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication as adr0109
from packages.adapters.trusted_time import graceful_stop_v2_reauthentication as adapter
from packages.domain import (
    trusted_time_graceful_stop_v2_lifecycle_semantics as lifecycle_semantics,
)
from packages.domain import trusted_time_graceful_stop_v2_reauthentication as reauthentication
from packages.domain.trusted_time_graceful_stop_v2 import (
    TrustedTimeGracefulStopV2Rejected,
    canonical_v2_json_bytes,
)
from packages.domain.trusted_time_graceful_stop_v2_docker import (
    DockerMutationResultSemantic,
    DockerVolumePreservationResult,
)
from packages.domain.trusted_time_graceful_stop_v2_lifecycle_semantics import (
    LifecycleV2AuthenticatedReauthenticationBinding,
    LifecycleV2NormalProgressLineage,
)
from packages.domain.trusted_time_graceful_stop_v2_reauthentication import (
    ADR0109_OBSERVATION_BUDGET_NS,
    ADR0109_REAUTHENTICATION_CONTRACT_VERSION,
    ADR0109_REAUTHENTICATION_STATUS,
    LifecycleV2ADR0109ObservationPrimitives,
    LifecycleV2PostTeardownBinding,
    LifecycleV2PostTeardownBindingEvidence,
    LifecycleV2PreEffectBinding,
    LifecycleV2PreEffectBindingEvidence,
    _build_fake_lifecycle_v2_reauthentication_binding_realm,
    _LifecycleV2ADR0109ObservationCandidate,
    _LifecycleV2PostTeardownBindingIssuer,
    _LifecycleV2PreEffectBindingIssuer,
)
from tests.unit import (
    test_trusted_time_graceful_stop_v2_lifecycle_semantics as semantics_fixtures,
)
from tests.unit import (
    test_trusted_time_post_enrollment_clean_stop_terminal_reauthentication as adr0109_fixtures,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _observation_primitives(
    result: Any,
    *,
    label: str,
    started: int,
    provider_suffix: str = "",
) -> LifecycleV2ADR0109ObservationPrimitives:
    terminal = result.terminal_projection.to_dict()
    payload: dict[str, object] = {
        "contract_version": ADR0109_REAUTHENTICATION_CONTRACT_VERSION,
        "status": ADR0109_REAUTHENTICATION_STATUS,
        "anchor_sequence": terminal["anchor_sequence"],
        "checkpoint_reason": terminal["checkpoint_reason"],
        "confirmed_anchor_count": terminal["confirmed_anchor_count"],
        "local_transition_count": terminal["local_transition_count"],
        "confirmed_anchor_local_transition_ordinal": terminal[
            "confirmed_anchor_local_transition_ordinal"
        ],
        "remote_object_count": terminal["anchor_sequence"],
        "predecessor_anchor_sha256": terminal["predecessor_anchor_sha256"],
        "current_host_head_sha256": terminal["current_host_head_sha256"],
        "current_anchor_sha256": terminal["current_anchor_sha256"],
        "current_anchor_semantic_sha256": terminal["current_anchor_semantic_sha256"],
        "anchor_intent_semantic_sha256": terminal["current_anchor_intent_semantic_sha256"],
        "candidate_remote_readback_sha256": terminal["current_candidate_remote_readback_sha256"],
        "receipt_semantic_sha256": terminal["current_receipt_semantic_sha256"],
        "receipt_observed_at_utc": terminal["receipt_observed_at_utc"],
        "remote_observation_sha256": _digest(f"remote-{label}"),
        "anchor_authority_sha256": _digest(f"anchor-authority{provider_suffix}"),
        "deployment_identity_sha256": _digest(f"deployment{provider_suffix}"),
        "runtime_database_identity_sha256": _digest(f"database{provider_suffix}"),
        "anchor_project_identity_sha256": _digest(f"project{provider_suffix}"),
        "source_authority_sha256": _digest(f"source-authority{provider_suffix}"),
        "signing_public_key_sha256": _digest(f"signing-key{provider_suffix}"),
        "host_identity_sha256": _digest(f"host{provider_suffix}"),
        "principal_identity_sha256": _digest(f"principal{provider_suffix}"),
        "bucket_identity_sha256": _digest(f"bucket{provider_suffix}"),
        "observation_started_monotonic_ns": started,
        "observation_completed_monotonic_ns": started + 100,
        "deadline_monotonic_ns": started + ADR0109_OBSERVATION_BUDGET_NS,
        "issuer_binding_sha256": _digest(f"issuer-{label}"),
        "read_only_configuration_sha256": _digest(f"configuration{provider_suffix}"),
    }
    payload["semantic_sha256"] = hashlib.sha256(
        canonical_v2_json_bytes(payload, maximum_bytes=256 * 1_024)
    ).hexdigest()
    return LifecycleV2ADR0109ObservationPrimitives.capture(payload)


@dataclass(frozen=True, slots=True)
class _ObservationInput:
    primitives: LifecycleV2ADR0109ObservationPrimitives
    issuer_identity: object
    observation_identity: object
    fail: bool = False


def _test_realm(challenges: list[bytes]) -> tuple[Any, list[object]]:
    remaining = iter(challenges)
    authenticator_calls: list[object] = []

    def challenge_source(size: int) -> bytes:
        assert size == 32
        return next(remaining)

    def authenticate(
        binding_issuer: object,
        value: object,
    ) -> _LifecycleV2ADR0109ObservationCandidate:
        authenticator_calls.append(binding_issuer)
        if type(value) is not _ObservationInput or value.fail:
            raise TrustedTimeGracefulStopV2Rejected("injected observation failure")
        return _LifecycleV2ADR0109ObservationCandidate(
            primitives=value.primitives,
            issuer_identity=value.issuer_identity,
            observation_identity=value.observation_identity,
        )

    return (
        _build_fake_lifecycle_v2_reauthentication_binding_realm(
            authenticate_observation=authenticate,
            challenge_source=challenge_source,
        ),
        authenticator_calls,
    )


def _exact_adr0109_observation(
    scenario: Any,
    *,
    started: int,
    label: str,
    configuration: object | None = None,
) -> tuple[object, object, object, LifecycleV2ADR0109ObservationPrimitives]:
    terminal = scenario.clean_stop_result.terminal_projection.to_dict()
    observed_at = datetime.strptime(
        cast(str, terminal["receipt_observed_at_utc"]),
        "%Y-%m-%dT%H:%M:%S.%fZ",
    ).replace(tzinfo=UTC)
    projection = adr0109_fixtures._projection(
        anchor_sequence=terminal["anchor_sequence"],
        confirmed_anchor_count=terminal["confirmed_anchor_count"],
        local_transition_count=terminal["local_transition_count"],
        confirmed_anchor_local_transition_ordinal=terminal[
            "confirmed_anchor_local_transition_ordinal"
        ],
        predecessor_anchor_sha256=terminal["predecessor_anchor_sha256"],
        current_host_head_sha256=terminal["current_host_head_sha256"],
        current_anchor_sha256=terminal["current_anchor_sha256"],
        current_anchor_semantic_sha256=terminal["current_anchor_semantic_sha256"],
        anchor_intent_semantic_sha256=terminal["current_anchor_intent_semantic_sha256"],
        candidate_remote_readback_sha256=terminal["current_candidate_remote_readback_sha256"],
        receipt_semantic_sha256=terminal["current_receipt_semantic_sha256"],
        receipt_observed_at_utc=observed_at,
    )
    verified = adr0109._VerifiedObservation(
        projection=projection,
        remote_observation_sha256=_digest(f"production-remote-{label}"),
        observation_started_monotonic_ns=started,
        observation_completed_monotonic_ns=started,
        deadline_monotonic_ns=started + ADR0109_OBSERVATION_BUDGET_NS,
    )
    issuer, exact_configuration, _ = adr0109_fixtures._harness(
        configuration=cast(Any, configuration),
        clock=adr0109_fixtures._Clock(value=started),
        runner_observation=verified,
    )
    postcondition = issuer.reauthenticate_clean_stop_terminal_once()
    values = adr0109._postcondition_values(postcondition)
    payload = adr0109._postcondition_payload(values)
    payload["semantic_sha256"] = postcondition.semantic_sha256
    primitives = LifecycleV2ADR0109ObservationPrimitives.capture(payload)
    return issuer, postcondition, exact_configuration, primitives


def _through_five(
    scenario: Any,
    *,
    provider_identity_sha256: str,
) -> LifecycleV2NormalProgressLineage:
    plan = semantics_fixtures._transport_plan(scenario)
    lineage = scenario.lineage.retain_transport_cleanup_commitment(
        plan=plan,
        recorded_at_utc=semantics_fixtures.UTC_TEXT,
    )
    quiescence = semantics_fixtures._transport_quiescence(
        scenario,
        plan,
        lineage.last_record,
    )
    lineage = lineage.confirm_transport_channel_quiesced(
        quiescence=quiescence,
        recorded_at_utc=semantics_fixtures.UTC_TEXT,
    )
    return cast(
        LifecycleV2NormalProgressLineage,
        lineage.retain_pre_effect_reauthentication_intent(
            provider_identity_sha256=provider_identity_sha256,
            call_deadline_boottime_ns=(semantics_fixtures.PRE_EFFECT_REAUTHENTICATION_DEADLINE_NS),
            recorded_at_utc=semantics_fixtures.UTC_TEXT,
        ),
    )


def _through_eighteen_from_six(
    scenario: Any,
    lineage: LifecycleV2NormalProgressLineage,
) -> LifecycleV2NormalProgressLineage:
    mutations = (
        (
            "retain_supervisor_container_stop_intent",
            "retain_supervisor_container_stop_result",
            "container_stop",
            6,
            1,
        ),
        (
            "retain_source_container_stop_intent",
            "retain_source_container_stop_result",
            "container_stop",
            8,
            2,
        ),
        (
            "retain_supervisor_container_remove_intent",
            "retain_supervisor_container_remove_result",
            "container_remove",
            10,
            1,
        ),
        (
            "retain_source_container_remove_intent",
            "retain_source_container_remove_result",
            "container_remove",
            12,
            2,
        ),
        (
            "retain_project_network_remove_intent",
            "retain_project_network_remove_result",
            "network_remove",
            14,
            3,
        ),
    )
    for intent_name, result_name, kind, ordinal, admitted_ordinal in mutations:
        prior = lineage.docker_trace
        if prior is None:
            prior = semantics_fixtures._trace_prefix(
                scenario.admission,
                scenario.entries,
                ordinal - 1,
            )
        assert prior.last_ordinal == ordinal - 1
        lineage = getattr(lineage, intent_name)(
            admission=scenario.admission,
            trace_prefix=prior,
            call_deadline_boottime_ns=2_000_000,
            recorded_at_utc=semantics_fixtures.UTC_TEXT,
        )
        result_prefix = semantics_fixtures._trace_prefix(
            scenario.admission,
            scenario.entries,
            ordinal + 1,
        )
        semantic = DockerMutationResultSemantic.from_pair(
            result_kind=kind,
            environment=semantics_fixtures.ENVIRONMENT,
            graceful_stop_operation_id=semantics_fixtures.OPERATION_ID,
            root_sha256=scenario.root.sha256,
            admission=scenario.admission,
            trace_prefix=result_prefix,
            admitted_target=scenario.entries[admitted_ordinal],
            previous=scenario.entries[ordinal - 1],
            primary=scenario.entries[ordinal],
            post_inspect=scenario.entries[ordinal + 1],
        )
        lineage = getattr(lineage, result_name)(
            result_semantic=semantic,
            trace_prefix=result_prefix,
            recorded_at_utc=semantics_fixtures.UTC_TEXT,
        )
    lineage = lineage.retain_named_volume_preservation_intent(
        call_deadline_boottime_ns=2_000_000,
        recorded_at_utc=semantics_fixtures.UTC_TEXT,
    )
    prefix = semantics_fixtures._trace_prefix(
        scenario.admission,
        scenario.entries,
        17,
    )
    volume = DockerVolumePreservationResult.from_pair(
        environment=semantics_fixtures.ENVIRONMENT,
        graceful_stop_operation_id=semantics_fixtures.OPERATION_ID,
        root_sha256=scenario.root.sha256,
        admission=scenario.admission,
        trace_prefix=prefix,
        previous=scenario.entries[15],
        command_socket=scenario.entries[16],
        state=scenario.entries[17],
        volume_delete_call_count=scenario.daemon.volume_delete_call_count,
    )
    return lineage.retain_named_volumes_preserved(
        result_semantic=volume,
        trace_prefix=prefix,
        recorded_at_utc=semantics_fixtures.UTC_TEXT,
    )


def _through_nineteen(
    scenario: Any,
    lineage_six: LifecycleV2NormalProgressLineage,
    *,
    provider_identity_sha256: str,
) -> LifecycleV2NormalProgressLineage:
    lineage = _through_eighteen_from_six(scenario, lineage_six)
    transcript = semantics_fixtures._prefix_transcript(scenario, lineage)
    return lineage.retain_post_teardown_reauthentication_intent(
        prefix_transcript=transcript,
        provider_identity_sha256=provider_identity_sha256,
        call_deadline_boottime_ns=(semantics_fixtures.POST_TEARDOWN_REAUTHENTICATION_DEADLINE_NS),
        recorded_at_utc=semantics_fixtures.UTC_TEXT,
    )


@dataclass(frozen=True, slots=True)
class _PreSetup:
    scenario: Any
    realm: Any
    authenticator_calls: list[object]
    lineage_five: LifecycleV2NormalProgressLineage
    lineage_six: LifecycleV2NormalProgressLineage
    observation_issuer: object
    observation: _ObservationInput
    binding_issuer: _LifecycleV2PreEffectBindingIssuer
    binding: LifecycleV2PreEffectBinding


def _pre_setup(*, challenges: list[bytes] | None = None) -> _PreSetup:
    scenario = semantics_fixtures._scenario()
    primitives = _observation_primitives(
        scenario.clean_stop_result,
        label="pre",
        started=100,
    )
    lineage_five = _through_five(
        scenario,
        provider_identity_sha256=primitives.provider_identity_sha256,
    )
    realm, calls = _test_realm(challenges or [b"p" * 32, b"q" * 32, b"r" * 32])
    observation_issuer = object()
    binding_issuer = realm.prepare_pre_effect(
        lineage_through_ordinal_5=lineage_five,
        observation_issuer_identity=observation_issuer,
    )
    observation = _ObservationInput(primitives, observation_issuer, object())
    binding = realm.bind_pre_effect(binding_issuer, observation=observation)
    lineage_six = lineage_five.retain_pre_effect_reauthentication_binding(
        binding=binding.lifecycle_semantic_binding,
        recorded_at_utc=semantics_fixtures.UTC_TEXT,
    )
    return _PreSetup(
        scenario,
        realm,
        calls,
        lineage_five,
        lineage_six,
        observation_issuer,
        observation,
        binding_issuer,
        binding,
    )


@dataclass(frozen=True, slots=True)
class _PostSetup:
    pre: _PreSetup
    lineage_nineteen: LifecycleV2NormalProgressLineage
    observation_issuer: object
    observation: _ObservationInput
    binding_issuer: _LifecycleV2PostTeardownBindingIssuer
    binding: LifecycleV2PostTeardownBinding | None


def _post_setup(*, bind: bool = True) -> _PostSetup:
    pre = _pre_setup()
    primitives = _observation_primitives(
        pre.scenario.clean_stop_result,
        label="post",
        started=1_100_000,
    )
    lineage_nineteen = _through_nineteen(
        pre.scenario,
        pre.lineage_six,
        provider_identity_sha256=primitives.provider_identity_sha256,
    )
    observation_issuer = object()
    binding_issuer = pre.realm.prepare_post_teardown(
        lineage_through_ordinal_19=lineage_nineteen,
        pre_effect_binding=pre.binding,
        observation_issuer_identity=observation_issuer,
    )
    observation = _ObservationInput(primitives, observation_issuer, object())
    binding = (
        pre.realm.bind_post_teardown(binding_issuer, observation=observation) if bind else None
    )
    return _PostSetup(
        pre,
        lineage_nineteen,
        observation_issuer,
        observation,
        binding_issuer,
        binding,
    )


def _clone_slots(value: Any) -> Any:
    clone = object.__new__(type(value))
    for owner in reversed(type(value).__mro__):
        raw_slots = owner.__dict__.get("__slots__", ())
        slots = (raw_slots,) if type(raw_slots) is str else raw_slots
        for slot in slots:
            if slot != "__weakref__" and hasattr(value, slot):
                object.__setattr__(clone, slot, getattr(value, slot))
    return clone


def test_pre_effect_binding_retains_full_observation_and_exact_semantics() -> None:
    setup = _pre_setup()
    evidence = setup.binding.durable_evidence
    fields = evidence.to_dict()
    semantic = setup.binding.lifecycle_semantic_binding

    assert type(setup.binding) is LifecycleV2PreEffectBinding
    assert fields["lifecycle_root_sha256"] == setup.scenario.root.sha256
    assert fields["channel_id"] == setup.scenario.root.channel_id
    assert fields["topology_sha256"] == setup.scenario.root.topology_sha256
    assert fields["topology_lease_sha256"] == setup.scenario.root.topology_lease_sha256
    assert fields["adr0109_observation"] == setup.observation.primitives.to_dict()
    assert fields["adr0109_observation_sha256"] == setup.observation.primitives.sha256
    assert fields["provider_identity_sha256"] == (
        setup.observation.primitives.provider_identity_sha256
    )
    assert (
        evidence.binding_sha256
        == LifecycleV2PreEffectBindingEvidence._capture(fields).binding_sha256
    )
    assert semantic.boundary == "pre_effect"
    assert semantic.to_dict()["intent_semantic_sha256"] == (
        cast(Any, setup.lineage_five.semantic_at(5)).sha256
    )
    assert semantic.to_dict()["binding_evidence_sha256"] == evidence.binding_sha256
    assert semantic.binding_evidence.to_dict() == fields
    assert setup.lineage_six.pre_effect_binding is not None
    assert setup.lineage_six.pre_effect_binding.encoded == semantic.encoded
    retained = setup.lineage_six.record_at(6).evidence.to_dict()
    assert retained["binding_evidence"] == fields
    assert retained["binding_semantic_sha256"] == semantic.sha256
    assert not any(name in fields for name in ("owner_pid", "owner_thread", "seal"))
    assert setup.binding_issuer._status == "consumed"
    assert setup.binding_issuer._challenge == bytearray()

    replay = _ObservationInput(
        _observation_primitives(
            setup.scenario.clean_stop_result,
            label="pre-replay",
            started=200,
        ),
        setup.observation_issuer,
        object(),
    )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="replayed"):
        setup.realm.bind_pre_effect(setup.binding_issuer, observation=replay)


def test_observation_replay_burns_the_second_issuer_before_rejection() -> None:
    scenario = semantics_fixtures._scenario()
    primitives = _observation_primitives(
        scenario.clean_stop_result,
        label="one-observation",
        started=100,
    )
    lineage = _through_five(
        scenario,
        provider_identity_sha256=primitives.provider_identity_sha256,
    )
    realm, calls = _test_realm([b"a" * 32, b"b" * 32])
    observation_issuer = object()
    first = realm.prepare_pre_effect(
        lineage_through_ordinal_5=lineage,
        observation_issuer_identity=observation_issuer,
    )
    second = realm.prepare_pre_effect(
        lineage_through_ordinal_5=lineage,
        observation_issuer_identity=observation_issuer,
    )
    observation = _ObservationInput(primitives, observation_issuer, object())

    realm.bind_pre_effect(first, observation=observation)
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="replayed"):
        realm.bind_pre_effect(second, observation=observation)
    assert len(calls) == 2
    assert second._status == "consumed"
    assert second._challenge == bytearray()
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="replayed"):
        realm.bind_pre_effect(
            second,
            observation=_ObservationInput(primitives, observation_issuer, object()),
        )
    assert len(calls) == 2


def test_failed_authenticator_burns_issuer_before_untrusted_callback() -> None:
    scenario = semantics_fixtures._scenario()
    primitives = _observation_primitives(
        scenario.clean_stop_result,
        label="burn",
        started=100,
    )
    lineage = _through_five(
        scenario,
        provider_identity_sha256=primitives.provider_identity_sha256,
    )
    realm, calls = _test_realm([b"c" * 32])
    observation_issuer = object()
    issuer = realm.prepare_pre_effect(
        lineage_through_ordinal_5=lineage,
        observation_issuer_identity=observation_issuer,
    )
    failed = _ObservationInput(primitives, observation_issuer, object(), fail=True)

    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="injected"):
        realm.bind_pre_effect(issuer, observation=failed)
    assert issuer._status == "consumed"
    assert issuer._challenge == bytearray()
    assert calls == [issuer]

    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="replayed"):
        realm.bind_pre_effect(
            issuer,
            observation=_ObservationInput(primitives, observation_issuer, object()),
        )
    assert calls == [issuer]


def test_registry_snapshots_revoke_mutated_issuers_and_bindings() -> None:
    scenario = semantics_fixtures._scenario()
    primitives = _observation_primitives(
        scenario.clean_stop_result,
        label="issuer-tamper",
        started=100,
    )
    lineage = _through_five(
        scenario,
        provider_identity_sha256=primitives.provider_identity_sha256,
    )
    realm, _ = _test_realm([b"d" * 32])
    observation_issuer = object()
    issuer = realm.prepare_pre_effect(
        lineage_through_ordinal_5=lineage,
        observation_issuer_identity=observation_issuer,
    )
    original_context = issuer._context
    object.__setattr__(issuer, "_context", object())
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="seal changed"):
        realm.bind_pre_effect(
            issuer,
            observation=_ObservationInput(primitives, observation_issuer, object()),
        )
    object.__setattr__(issuer, "_context", original_context)
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="replayed"):
        realm.bind_pre_effect(
            issuer,
            observation=_ObservationInput(primitives, observation_issuer, object()),
        )

    nested_realm, _ = _test_realm([b"e" * 32])
    nested_issuer = nested_realm.prepare_pre_effect(
        lineage_through_ordinal_5=lineage,
        observation_issuer_identity=observation_issuer,
    )
    nested_context = nested_issuer._context
    original_root = nested_context.root
    with pytest.raises(AttributeError):
        object.__setattr__(nested_context, "root", object())
    original_environment = original_root.environment
    object.__setattr__(original_root, "environment", "tampered")
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="seal changed"):
        nested_realm.bind_pre_effect(
            nested_issuer,
            observation=_ObservationInput(primitives, observation_issuer, object()),
        )
    object.__setattr__(original_root, "environment", original_environment)
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="replayed"):
        nested_realm.bind_pre_effect(
            nested_issuer,
            observation=_ObservationInput(primitives, observation_issuer, object()),
        )

    valid = _pre_setup()
    original_identity = valid.binding._issuer_identity
    object.__setattr__(valid.binding, "_issuer_identity", object())
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="seal changed"):
        _ = valid.binding.durable_evidence
    object.__setattr__(valid.binding, "_issuer_identity", original_identity)
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="registered"):
        _ = valid.binding.durable_evidence

    nested_evidence = _pre_setup().binding
    exposed_evidence = nested_evidence._evidence
    original_fields = exposed_evidence.fields
    object.__setattr__(exposed_evidence, "fields", object())
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="seal changed"):
        _ = nested_evidence.durable_evidence
    object.__setattr__(exposed_evidence, "fields", original_fields)
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="registered"):
        _ = nested_evidence.durable_evidence

    nested_semantic = _pre_setup().binding
    exposed_semantic = nested_semantic._semantic_binding
    original_boundary = exposed_semantic.boundary
    object.__setattr__(exposed_semantic, "boundary", "post_teardown")
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="seal changed"):
        _ = nested_semantic.lifecycle_semantic_binding
    object.__setattr__(exposed_semantic, "boundary", original_boundary)
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="registered"):
        _ = nested_semantic.lifecycle_semantic_binding


def test_post_teardown_binding_covers_typed_lineage_and_distinct_observation() -> None:
    setup = _post_setup()
    assert setup.binding is not None
    binding = setup.binding
    fields = binding.durable_evidence.to_dict()
    pre_fields = setup.pre.binding.durable_evidence.to_dict()

    assert type(binding) is LifecycleV2PostTeardownBinding
    assert setup.lineage_nineteen.prefix_through_eighteen is not None
    assert fields["published_prefix_through_ordinal_18_sha256"] == (
        setup.lineage_nineteen.prefix_through_eighteen.sha256
    )
    assert fields["pre_effect_binding_sha256"] == (
        setup.pre.binding.durable_evidence.binding_sha256
    )
    for field, ordinal in (
        ("supervisor_stop_result_sha256", 8),
        ("source_stop_result_sha256", 10),
        ("supervisor_remove_result_sha256", 12),
        ("source_remove_result_sha256", 14),
        ("project_network_remove_result_sha256", 16),
        ("volume_proof_sha256", 18),
    ):
        assert fields[field] == setup.lineage_nineteen.record_at(ordinal).sha256
    assert fields["post_teardown_intent_sha256"] == (setup.lineage_nineteen.record_at(19).sha256)
    assert fields["adr0109_observation"] == setup.observation.primitives.to_dict()
    assert fields["provider_identity_sha256"] == pre_fields["provider_identity_sha256"]
    assert fields["observation_semantic_sha256"] != pre_fields["observation_semantic_sha256"]
    assert cast(int, fields["observation_started_monotonic_ns"]) > cast(
        int,
        setup.lineage_nineteen.record_at(18).evidence.to_dict()["call_completed_boottime_ns"],
    )
    semantic = binding.lifecycle_semantic_binding
    assert semantic.boundary == "post_teardown"
    assert semantic.to_dict()["binding_evidence_sha256"] == (
        binding.durable_evidence.binding_sha256
    )
    assert semantic.binding_evidence.to_dict() == fields
    assert binding.durable_evidence.binding_sha256 == (
        LifecycleV2PostTeardownBindingEvidence._capture(fields).binding_sha256
    )
    lineage_twenty = setup.lineage_nineteen.retain_post_teardown_reauthentication_binding(
        binding=semantic,
        recorded_at_utc=semantics_fixtures.UTC_TEXT,
    )
    retained = lineage_twenty.record_at(20).evidence.to_dict()
    assert retained["binding_evidence"] == fields
    assert retained["binding_semantic_sha256"] == semantic.sha256


def test_pre_binding_can_reserve_only_one_post_issuer() -> None:
    pre = _pre_setup(challenges=[b"p" * 32, b"q" * 32, b"r" * 32])
    primitives = _observation_primitives(
        pre.scenario.clean_stop_result,
        label="post-reservation",
        started=1_100_000,
    )
    lineage = _through_nineteen(
        pre.scenario,
        pre.lineage_six,
        provider_identity_sha256=primitives.provider_identity_sha256,
    )
    first = pre.realm.prepare_post_teardown(
        lineage_through_ordinal_19=lineage,
        pre_effect_binding=pre.binding,
        observation_issuer_identity=object(),
    )
    assert type(first) is _LifecycleV2PostTeardownBindingIssuer

    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="already reserved"):
        pre.realm.prepare_post_teardown(
            lineage_through_ordinal_19=lineage,
            pre_effect_binding=pre.binding,
            observation_issuer_identity=object(),
        )


def test_failed_post_preparation_consumes_pre_binding_reservation() -> None:
    pre = _pre_setup(challenges=[b"p" * 32, b"p" * 32, b"r" * 32])
    primitives = _observation_primitives(
        pre.scenario.clean_stop_result,
        label="post-challenge-reuse",
        started=1_100_000,
    )
    lineage = _through_nineteen(
        pre.scenario,
        pre.lineage_six,
        provider_identity_sha256=primitives.provider_identity_sha256,
    )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="challenge reused"):
        pre.realm.prepare_post_teardown(
            lineage_through_ordinal_19=lineage,
            pre_effect_binding=pre.binding,
            observation_issuer_identity=object(),
        )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="already reserved"):
        pre.realm.prepare_post_teardown(
            lineage_through_ordinal_19=lineage,
            pre_effect_binding=pre.binding,
            observation_issuer_identity=object(),
        )


@pytest.mark.parametrize(
    ("started", "provider_suffix"),
    ((150, ""), (1_100_000, "-drift")),
)
def test_invalid_post_observation_burns_issuer(
    started: int,
    provider_suffix: str,
) -> None:
    setup = _post_setup(bind=False)
    invalid = _ObservationInput(
        _observation_primitives(
            setup.pre.scenario.clean_stop_result,
            label=f"invalid-post-{started}",
            started=started,
            provider_suffix=provider_suffix,
        ),
        setup.observation_issuer,
        object(),
    )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected):
        setup.pre.realm.bind_post_teardown(setup.binding_issuer, observation=invalid)
    assert setup.binding_issuer._status == "consumed"
    assert setup.binding_issuer._challenge == bytearray()
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="replayed"):
        setup.pre.realm.bind_post_teardown(
            setup.binding_issuer,
            observation=setup.observation,
        )


def test_cross_realm_and_pre_observation_reuse_reject() -> None:
    pre = _pre_setup()
    post_primitives = _observation_primitives(
        pre.scenario.clean_stop_result,
        label="post-cross-realm",
        started=1_100_000,
    )
    lineage = _through_nineteen(
        pre.scenario,
        pre.lineage_six,
        provider_identity_sha256=post_primitives.provider_identity_sha256,
    )
    foreign_realm, _ = _test_realm([b"x" * 32])
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="crossed"):
        foreign_realm.prepare_post_teardown(
            lineage_through_ordinal_19=lineage,
            pre_effect_binding=pre.binding,
            observation_issuer_identity=object(),
        )

    post_issuer_identity = object()
    issuer = pre.realm.prepare_post_teardown(
        lineage_through_ordinal_19=lineage,
        pre_effect_binding=pre.binding,
        observation_issuer_identity=post_issuer_identity,
    )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="replayed"):
        pre.realm.bind_post_teardown(
            issuer,
            observation=_ObservationInput(
                post_primitives,
                post_issuer_identity,
                pre.observation.observation_identity,
            ),
        )


def test_wrong_thread_checks_precede_locks_and_do_not_burn_issuer() -> None:
    scenario = semantics_fixtures._scenario()
    primitives = _observation_primitives(
        scenario.clean_stop_result,
        label="thread",
        started=100,
    )
    lineage = _through_five(
        scenario,
        provider_identity_sha256=primitives.provider_identity_sha256,
    )
    realm, calls = _test_realm([b"t" * 32])
    observation_issuer = object()
    issuer = realm.prepare_pre_effect(
        lineage_through_ordinal_5=lineage,
        observation_issuer_identity=observation_issuer,
    )
    observation = _ObservationInput(primitives, observation_issuer, object())
    errors: list[BaseException] = []
    owner_thread = threading.current_thread()
    original_threading = reauthentication.threading

    def consume() -> None:
        reauthentication.threading = SimpleNamespace(  # type: ignore[assignment]
            current_thread=lambda: owner_thread,
        )
        try:
            realm.bind_pre_effect(issuer, observation=observation)
        except BaseException as error:
            errors.append(error)
        finally:
            reauthentication.threading = original_threading

    thread = threading.Thread(target=consume)
    thread.start()
    thread.join()
    assert len(errors) == 1
    assert isinstance(errors[0], TrustedTimeGracefulStopV2Rejected)
    assert issuer._status == "prepared"
    assert calls == []
    assert type(realm.bind_pre_effect(issuer, observation=observation)) is (
        LifecycleV2PreEffectBinding
    )


def test_live_objects_reject_copy_pickle_wrong_thread_and_fork() -> None:
    setup = _pre_setup()
    for value in (setup.binding_issuer, setup.binding):
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(TrustedTimeGracefulStopV2Rejected):
                operation(value)

    errors: list[BaseException] = []
    owner_thread = threading.current_thread()
    original_threading = reauthentication.threading

    def read_binding() -> None:
        reauthentication.threading = SimpleNamespace(  # type: ignore[assignment]
            current_thread=lambda: owner_thread,
        )
        try:
            _ = setup.binding.durable_evidence
        except BaseException as error:
            errors.append(error)
        finally:
            reauthentication.threading = original_threading

    thread = threading.Thread(target=read_binding)
    thread.start()
    thread.join()
    assert len(errors) == 1
    assert isinstance(errors[0], TrustedTimeGracefulStopV2Rejected)
    assert setup.binding.durable_evidence.binding_sha256

    if not hasattr(os, "fork"):
        return
    read_fd, write_fd = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:
        os.close(read_fd)
        try:
            _ = setup.binding.durable_evidence
        except TrustedTimeGracefulStopV2Rejected:
            os.write(write_fd, b"rejected")
        else:
            os.write(write_fd, b"accepted")
        finally:
            os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    message = os.read(read_fd, 32)
    os.close(read_fd)
    waited, status = os.waitpid(child_pid, 0)
    assert waited == child_pid
    assert os.WIFEXITED(status)
    assert message == b"rejected"


def test_challenge_source_is_exact_and_fail_closed() -> None:
    scenario = semantics_fixtures._scenario()
    primitives = _observation_primitives(
        scenario.clean_stop_result,
        label="challenge",
        started=100,
    )
    lineage = _through_five(
        scenario,
        provider_identity_sha256=primitives.provider_identity_sha256,
    )

    def authenticate(
        _binding_issuer: object,
        value: object,
    ) -> _LifecycleV2ADR0109ObservationCandidate:
        assert type(value) is _ObservationInput
        return _LifecycleV2ADR0109ObservationCandidate(
            value.primitives,
            value.issuer_identity,
            value.observation_identity,
        )

    for source in (
        lambda _size: b"short",
        lambda _size: bytearray(b"x" * 32),
    ):
        realm = _build_fake_lifecycle_v2_reauthentication_binding_realm(
            authenticate_observation=authenticate,
            challenge_source=cast(Callable[[int], bytes], source),
        )
        with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="exactly 32 bytes"):
            realm.prepare_pre_effect(
                lineage_through_ordinal_5=lineage,
                observation_issuer_identity=object(),
            )


def test_raw_boundary_apis_and_generic_observation_mints_are_absent() -> None:
    for name in (
        "_PRODUCTION_OBSERVATION_CAPABILITY",
        "_FAKE_OBSERVATION_CAPABILITY",
        "LifecycleV2AuthenticatedADR0109Observation",
        "_mint_production_authenticated_adr0109_observation",
        "_mint_fake_authenticated_adr0109_observation",
        "_register_binding_issuer",
        "_begin_binding_issuer_once",
        "_register_live_binding",
        "_reserve_pre_binding_for_post",
        "_build_binding_registries",
        "_initialize_issuer",
        "_issue_binding",
        "_semantic_binding",
        "_prepare_lifecycle_v2_pre_effect_binding_issuer",
        "_prepare_lifecycle_v2_post_teardown_binding_issuer",
        "_bind_lifecycle_v2_pre_effect_observation_once",
        "_bind_lifecycle_v2_post_teardown_observation_once",
        "_capture_lifecycle_v2_authenticated_reauthentication_binding_from_realm",
        "_install_lifecycle_v2_reauthentication_semantic_binding_issuance_consumer",
        "_FAKE_REAUTHENTICATION_BINDING_CAPABILITY",
        "_PRODUCTION_REAUTHENTICATION_BINDING_CAPABILITY",
        "_FAKE_REAUTHENTICATION_BINDING_PROVENANCE",
        "_PRODUCTION_REAUTHENTICATION_BINDING_PROVENANCE",
        "_REAUTHENTICATION_BINDING_PROVENANCES",
        "_PRODUCTION_ADAPTER_MODULE",
        "_PRODUCTION_ADAPTER_AUTHENTICATOR",
    ):
        assert not hasattr(reauthentication, name)

    realm, _ = _test_realm([b"i" * 32])
    pre_parameters = inspect.signature(realm.prepare_pre_effect).parameters
    post_parameters = inspect.signature(realm.prepare_post_teardown).parameters
    assert "lineage_through_ordinal_5" in pre_parameters
    assert "lineage_through_ordinal_19" in post_parameters
    assert not set(pre_parameters).intersection(
        {"root", "request", "result", "transport_quiescence", "pre_effect_intent"}
    )
    assert not set(post_parameters).intersection(
        {
            "root",
            "published_prefix_through_ordinal_18",
            "teardown_result_records",
            "post_teardown_intent",
        }
    )

    setup = _pre_setup()
    semantic = setup.binding.lifecycle_semantic_binding
    assert type(semantic) is LifecycleV2AuthenticatedReauthenticationBinding
    semantic._require_sealed()
    assert (
        lifecycle_semantics._require_canonical_evidence(semantic).provenance
        == "fake_reauthentication_binding"
    )
    assert not hasattr(semantic, "_capability")
    assert not hasattr(reauthentication, "register_semantic_binding_issuance")


def test_registry_backed_lineage_rejects_object_new_clone_and_mutation() -> None:
    scenario = semantics_fixtures._scenario()
    primitives = _observation_primitives(
        scenario.clean_stop_result,
        label="lineage-forgery",
        started=100,
    )
    lineage = _through_five(
        scenario,
        provider_identity_sha256=primitives.provider_identity_sha256,
    )
    realm, _ = _test_realm([b"l" * 32])
    forged = _clone_slots(lineage)

    with pytest.raises(TrustedTimeGracefulStopV2Rejected):
        realm.prepare_pre_effect(
            lineage_through_ordinal_5=forged,
            observation_issuer_identity=object(),
        )

    mutated = _through_five(
        semantics_fixtures._scenario(),
        provider_identity_sha256=primitives.provider_identity_sha256,
    )
    object.__setattr__(mutated, "records", tuple(reversed(mutated.records)))
    with pytest.raises(TrustedTimeGracefulStopV2Rejected):
        realm.prepare_pre_effect(
            lineage_through_ordinal_5=mutated,
            observation_issuer_identity=object(),
        )


def test_semantic_issuance_rejects_direct_object_new_and_snapshot_substitution() -> None:
    scenario = semantics_fixtures._scenario()
    primitives = _observation_primitives(
        scenario.clean_stop_result,
        label="semantic-issuance-forgery",
        started=100,
    )
    lineage = _through_five(
        scenario,
        provider_identity_sha256=primitives.provider_identity_sha256,
    )
    intent = cast(Any, lineage.semantic_at(5))
    issuance_type = reauthentication._LifecycleV2ReauthenticationSemanticBindingIssuance
    snapshot_type = reauthentication._LifecycleV2ReauthenticationSemanticBindingIssuanceSnapshot
    forged_issuance = object.__new__(issuance_type)
    evidence = _pre_setup().binding.durable_evidence
    forged_snapshot = snapshot_type(
        semantic_binding_encoded=canonical_v2_json_bytes(
            {
                "binding_evidence_sha256": evidence.binding_sha256,
                "caller": "forged",
            },
            maximum_bytes=256 * 1_024,
        ),
        binding_evidence_encoded=evidence.encoded,
        binding_evidence_sha256=evidence.binding_sha256,
        provenance="production_reauthentication_binding",
        root_sha256=scenario.root.sha256,
        intent_semantic_sha256=intent.sha256,
        boundary="pre_effect",
    )

    for forged in (forged_issuance, forged_snapshot):
        with pytest.raises(TrustedTimeGracefulStopV2Rejected):
            reauthentication._consume_exact_lifecycle_v2_reauthentication_semantic_binding_issuance_once(
                forged,
                root=scenario.root,
                intent=intent,
            )


def test_lifecycle_capture_keeps_exact_installed_consumer_and_snapshot_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def forged_consumer(*_args: object, **_kwargs: object) -> object:
        calls.append("consumer")
        raise AssertionError("module-global consumer replacement was invoked")

    class ForgedSnapshot:
        pass

    class ForgedIssuance:
        pass

    def forged_capture(*_args: object, **_kwargs: object) -> object:
        calls.append("capture")
        raise AssertionError("module-global capture replacement was invoked")

    monkeypatch.setattr(
        reauthentication,
        "_consume_exact_lifecycle_v2_reauthentication_semantic_binding_issuance_once",
        forged_consumer,
    )
    monkeypatch.setattr(
        reauthentication,
        "_LifecycleV2ReauthenticationSemanticBindingIssuanceSnapshot",
        ForgedSnapshot,
    )
    monkeypatch.setattr(
        reauthentication,
        "_LifecycleV2ReauthenticationSemanticBindingIssuance",
        ForgedIssuance,
    )
    monkeypatch.setattr(
        lifecycle_semantics,
        "_capture_lifecycle_v2_authenticated_reauthentication_binding_from_realm",
        forged_capture,
    )

    setup = _pre_setup()
    setup.binding.lifecycle_semantic_binding._require_sealed()
    assert calls == []


def test_fake_semantic_binding_mint_rejects_a_production_root() -> None:
    setup = _pre_setup()
    production_root = replace(setup.scenario.root, environment="production")
    with pytest.raises(TrustedTimeGracefulStopV2Rejected):
        LifecycleV2AuthenticatedReauthenticationBinding._capture_fake_for_tests(
            setup.binding.lifecycle_semantic_binding.to_dict(),
            binding_evidence=(setup.binding.lifecycle_semantic_binding.binding_evidence),
            root=production_root,
            intent=cast(Any, setup.lineage_five.semantic_at(5)),
        )


def test_production_realm_claim_is_one_shot_and_not_a_generic_mint() -> None:
    assert not hasattr(adapter, "_consume_exact_adr0109_observation")

    def lookalike(
        _binding_issuer: object,
        _observation: object,
    ) -> _LifecycleV2ADR0109ObservationCandidate:
        raise AssertionError

    lookalike.__module__ = "packages.adapters.trusted_time.graceful_stop_v2_reauthentication"
    lookalike.__qualname__ = "_consume_exact_adr0109_observation"
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="claim is invalid"):
        reauthentication._claim_lifecycle_v2_production_reauthentication_binding_realm(
            authenticate_observation=lookalike,
            challenge_source=secrets.token_bytes,
        )


def test_fake_realm_closure_cannot_mint_or_register_production_realm() -> None:
    fake_builder = reauthentication._build_fake_lifecycle_v2_reauthentication_binding_realm
    fake_closure = dict(
        zip(
            fake_builder.__code__.co_freevars,
            fake_builder.__closure__ or (),
            strict=True,
        )
    )
    create_realm = fake_closure["create_realm"].cell_contents

    def authenticate(
        _binding_issuer: object,
        _observation: object,
    ) -> _LifecycleV2ADR0109ObservationCandidate:
        raise AssertionError("forged production authenticator was reached")

    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="realm caller"):
        create_realm(
            authenticate_observation=authenticate,
            challenge_source=lambda size: b"x" * size,
            semantic_binding_provenance="production_reauthentication_binding",
        )

    create_closure = dict(
        zip(
            create_realm.__code__.co_freevars,
            create_realm.__closure__ or (),
            strict=True,
        )
    )
    register_realm = create_closure["register_realm"].cell_contents
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="realm caller"):
        register_realm(
            object(),
            realm_identity=object(),
            semantic_binding_provenance="production_reauthentication_binding",
        )

    claim = reauthentication._claim_lifecycle_v2_production_reauthentication_binding_realm
    claim_closure = dict(zip(claim.__code__.co_freevars, claim.__closure__ or (), strict=True))
    with pytest.raises(ValueError):
        _ = claim_closure["production_bootstrap_permit"].cell_contents

    setup = _pre_setup(challenges=[b"z" * 32])
    assert callable(setup.realm.prepare_pre_effect)

    pending: list[object] = [
        fake_builder,
        claim,
        reauthentication._require_live_binding,
        reauthentication._consume_exact_lifecycle_v2_reauthentication_semantic_binding_issuance_once,
        setup.realm.prepare_pre_effect,
        setup.realm.bind_pre_effect,
        setup.realm.prepare_post_teardown,
        setup.realm.bind_post_teardown,
    ]
    seen: set[int] = set()
    authority_records: list[object] = []
    while pending:
        value = pending.pop()
        if id(value) in seen:
            continue
        seen.add(id(value))
        assert not isinstance(value, (dict, list, set, bytearray))
        if type(value).__name__ in {
            "_IssuerRegistration",
            "_BindingRegistration",
            "_SemanticBindingIssuanceRegistration",
        }:
            authority_records.append(value)
        if isinstance(value, FunctionType) and value.__module__ == reauthentication.__name__:
            for cell in value.__closure__ or ():
                with suppress(ValueError):
                    pending.append(cell.cell_contents)
            pending.extend(value.__defaults__ or ())
            pending.extend((value.__kwdefaults__ or {}).values())
        elif isinstance(value, MethodType):
            pending.extend((value.__func__, value.__self__))
        elif isinstance(value, (tuple, frozenset, MappingProxyType)):
            if isinstance(value, MappingProxyType):
                pending.extend(value.keys())
                pending.extend(value.values())
            else:
                pending.extend(value)

    issuer_registration = next(
        value
        for value in authority_records
        if type(value).__name__ == "_IssuerRegistration"
        and cast(Any, value).reference() is setup.binding_issuer
    )
    binding_registration = next(
        value
        for value in authority_records
        if type(value).__name__ == "_BindingRegistration"
        and cast(Any, value).reference() is setup.binding
    )
    assert cast(Any, issuer_registration).status == "consumed"
    cast(Any, issuer_registration).__init__(
        *cast(Any, issuer_registration)._replace(status="prepared")
    )
    assert cast(Any, issuer_registration).status == "consumed"
    with pytest.raises(AttributeError):
        object.__setattr__(issuer_registration, "status", "prepared")
    cast(Any, binding_registration).__init__(
        *cast(Any, binding_registration)._replace(
            semantic_binding_provenance="production_reauthentication_binding"
        )
    )
    assert (
        cast(Any, binding_registration).semantic_binding_provenance
        == "fake_reauthentication_binding"
    )
    with pytest.raises(AttributeError):
        object.__setattr__(
            binding_registration,
            "semantic_binding_provenance",
            "production_reauthentication_binding",
        )

    object.__setattr__(setup.binding_issuer, "_status", "prepared")
    object.__setattr__(
        setup.binding_issuer,
        "_challenge",
        bytearray(cast(Any, issuer_registration).challenge_encoded),
    )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="replayed"):
        setup.realm.bind_pre_effect(
            setup.binding_issuer,
            observation=setup.observation,
        )


def test_gc_referents_cannot_mutate_fake_realm_provenance_into_production() -> None:
    realm, _ = _test_realm([b"g" * 32])
    prepare_closure = dict(
        zip(
            realm.prepare_pre_effect.__code__.co_freevars,
            realm.prepare_pre_effect.__closure__ or (),
            strict=True,
        )
    )
    register_closure = dict(
        zip(
            prepare_closure["register_issuer"].cell_contents.__code__.co_freevars,
            prepare_closure["register_issuer"].cell_contents.__closure__ or (),
            strict=True,
        )
    )
    require_realm = register_closure["require_realm_permit"].cell_contents
    realm_state = dict(
        zip(
            require_realm.__code__.co_freevars,
            require_realm.__closure__ or (),
            strict=True,
        )
    )["realm_permit_state"].cell_contents
    assert type(realm_state) is tuple
    realm_permit = prepare_closure["realm_permit"].cell_contents
    registration = next(item for _, item in realm_state if item[0] is realm_permit)
    assert registration[2] == "fake_reauthentication_binding"
    pending = [realm_state]
    seen: set[int] = set()
    while pending:
        value = pending.pop()
        if id(value) in seen:
            continue
        seen.add(id(value))
        referents = gc.get_referents(value)
        assert not any(type(item) is dict for item in referents)
        pending.extend(item for item in referents if type(item) is tuple)

    scenario = semantics_fixtures._scenario()
    primitives = _observation_primitives(
        scenario.clean_stop_result,
        label="gc-provenance",
        started=100,
    )
    lineage_five = _through_five(
        scenario,
        provider_identity_sha256=primitives.provider_identity_sha256,
    )
    observation_issuer = object()
    issuer = realm.prepare_pre_effect(
        lineage_through_ordinal_5=lineage_five,
        observation_issuer_identity=observation_issuer,
    )
    binding = realm.bind_pre_effect(
        issuer,
        observation=_ObservationInput(primitives, observation_issuer, object()),
    )
    metadata = lifecycle_semantics._require_canonical_evidence(binding.lifecycle_semantic_binding)
    assert metadata.provenance == "fake_reauthentication_binding"


def test_production_realm_helpers_require_one_exact_wrapper_operation_chain() -> None:
    adapter_bind_closure = dict(
        zip(
            adapter._bind_lifecycle_v2_pre_effect_adr0109_observation_once.__code__.co_freevars,
            adapter._bind_lifecycle_v2_pre_effect_adr0109_observation_once.__closure__ or (),
            strict=True,
        )
    )
    production_realm = adapter_bind_closure["production_binding_realm"].cell_contents
    prepare_closure = dict(
        zip(
            production_realm.prepare_pre_effect.__code__.co_freevars,
            production_realm.prepare_pre_effect.__closure__ or (),
            strict=True,
        )
    )
    bind_closure = dict(
        zip(
            production_realm.bind_pre_effect.__code__.co_freevars,
            production_realm.bind_pre_effect.__closure__ or (),
            strict=True,
        )
    )

    scenario = semantics_fixtures._scenario()
    observation_issuer, postcondition, _, primitives = _exact_adr0109_observation(
        scenario,
        started=100,
        label="operation-chain",
    )
    lineage_five = _through_five(
        scenario,
        provider_identity_sha256=primitives.provider_identity_sha256,
    )
    attacker_challenge_calls: list[int] = []

    def attacker_challenge_source(size: int) -> bytes:
        attacker_challenge_calls.append(size)
        return b"x" * size

    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match=r"call chain|operation token"):
        prepare_closure["prepare_pre_effect_issuer"].cell_contents(
            operation_token=object(),
            lineage_through_ordinal_5=lineage_five,
            observation_issuer_identity=object(),
            challenge_source=attacker_challenge_source,
            realm_identity=prepare_closure["realm_identity"].cell_contents,
            realm_permit=prepare_closure["realm_permit"].cell_contents,
            authorize_issuer_initialization=prepare_closure[
                "authorize_issuer_initialization"
            ].cell_contents,
            register_issuer=prepare_closure["register_issuer"].cell_contents,
            initialize_issuer=prepare_closure["initialize_issuer"].cell_contents,
            require_lineage_boundary=prepare_closure["require_lineage_boundary"].cell_contents,
            normal_stage_for_ordinal=prepare_closure["exact_normal_stage_lookup"].cell_contents,
            getpid=prepare_closure["getpid"].cell_contents,
            current_thread=prepare_closure["current_thread"].cell_contents,
        )
    assert attacker_challenge_calls == []

    binding_issuer = adapter._prepare_lifecycle_v2_pre_effect_adr0109_binding_issuer(
        lineage_through_ordinal_5=lineage_five,
        adr0109_issuer=observation_issuer,
    )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="operation caller"):
        bind_closure["begin_realm_operation"].cell_contents(
            realm_permit=bind_closure["realm_permit"].cell_contents,
            realm_identity=bind_closure["realm_identity"].cell_contents,
            operation="bind",
            boundary="pre_effect",
            subject=binding_issuer,
        )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="operation closer"):
        bind_closure["close_realm_operation"].cell_contents(
            object(),
            realm_permit=bind_closure["realm_permit"].cell_contents,
            realm_identity=bind_closure["realm_identity"].cell_contents,
            operation="bind",
            boundary="pre_effect",
            subject=binding_issuer,
            succeeded=False,
        )
    assert binding_issuer._status == "prepared"
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match=r"call chain|operation token"):
        bind_closure["bind_pre_effect_observation"].cell_contents(
            binding_issuer,
            operation_token=object(),
            observation=object(),
            realm_identity=bind_closure["realm_identity"].cell_contents,
            realm_permit=bind_closure["realm_permit"].cell_contents,
            authenticate_observation=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("injected authenticator was reached")
            ),
            require_observation_candidate=bind_closure[
                "require_observation_candidate"
            ].cell_contents,
            begin_issuer=bind_closure["begin_issuer"].cell_contents,
            register_binding=bind_closure["register_binding"].cell_contents,
            semantic_binding_builder=bind_closure["build_semantic_binding"].cell_contents,
            issue_binding=bind_closure["issue_binding"].cell_contents,
            getpid=bind_closure["getpid"].cell_contents,
            current_thread=bind_closure["current_thread"].cell_contents,
        )
    assert binding_issuer._status == "prepared"

    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match=r"call chain|operation token"):
        bind_closure["authenticate_once"].cell_contents(
            binding_issuer,
            object(),
            operation_token=object(),
            boundary="pre_effect",
        )
    assert binding_issuer._status == "prepared"

    binding = adapter._bind_lifecycle_v2_pre_effect_adr0109_observation_once(
        binding_issuer,
        postcondition=postcondition,
        adr0109_issuer=observation_issuer,
    )
    binding.lifecycle_semantic_binding._require_sealed()
    live = reauthentication._require_live_binding(
        binding,
        expected_type=LifecycleV2PreEffectBinding,
    )
    attempt = reauthentication._IssuerAttempt(
        issuer=binding_issuer,
        context=live.context,
        expected_observation_issuer=live.observation_issuer_identity,
        challenge_sha256=cast(
            str,
            binding.durable_evidence.to_dict()["issuer_challenge_sha256"],
        ),
        realm_identity=live.realm_identity,
        semantic_binding_provenance="production_reauthentication_binding",
    )
    candidate = _LifecycleV2ADR0109ObservationCandidate(
        primitives=primitives,
        issuer_identity=live.observation_issuer_identity,
        observation_identity=live.observation_identity,
    )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match=r"call chain|operation token"):
        bind_closure["build_semantic_binding"].cell_contents(
            operation_token=object(),
            boundary="pre_effect",
            context=live.context,
            attempt=attempt,
            authenticated=candidate,
            binding_evidence=binding.durable_evidence,
        )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match=r"call chain|operation token"):
        bind_closure["issue_binding"].cell_contents(
            LifecycleV2PreEffectBinding,
            operation_token=object(),
            evidence=binding.durable_evidence,
            semantic_binding=binding.lifecycle_semantic_binding,
            attempt=attempt,
            observation=candidate,
            realm_permit=bind_closure["realm_permit"].cell_contents,
            register_binding=bind_closure["register_binding"].cell_contents,
            getpid=bind_closure["getpid"].cell_contents,
            current_thread=bind_closure["current_thread"].cell_contents,
        )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="binding caller"):
        bind_closure["register_binding"].cell_contents(
            binding,
            operation_token=object(),
            realm_permit=bind_closure["realm_permit"].cell_contents,
            binding_type=LifecycleV2PreEffectBinding,
            evidence=binding.durable_evidence,
            semantic_binding=binding.lifecycle_semantic_binding,
            context=live.context,
            issuer_identity=binding_issuer,
            observation_identity=live.observation_identity,
            observation_issuer_identity=live.observation_issuer_identity,
            realm_identity=live.realm_identity,
        )
    binding.lifecycle_semantic_binding._require_sealed()


def test_live_weakref_callback_and_initializer_cannot_reissue_consumed_issuer() -> None:
    setup = _pre_setup(challenges=[b"a" * 32, b"b" * 32])
    prepare_closure = dict(
        zip(
            setup.realm.prepare_pre_effect.__code__.co_freevars,
            setup.realm.prepare_pre_effect.__closure__ or (),
            strict=True,
        )
    )
    register_issuer = prepare_closure["register_issuer"].cell_contents
    register_closure = dict(
        zip(
            register_issuer.__code__.co_freevars,
            register_issuer.__closure__ or (),
            strict=True,
        )
    )
    issuer_state = dict(register_closure["issuer_state"].cell_contents)
    registration = issuer_state[id(setup.binding_issuer)]
    callback = registration.reference.__callback__
    assert callback is not None
    callback(registration.reference)
    assert dict(register_closure["issuer_state"].cell_contents)[id(setup.binding_issuer)] is (
        registration
    )

    attacker_challenge_calls: list[int] = []

    def attacker_challenge_source(size: int) -> bytes:
        attacker_challenge_calls.append(size)
        return b"z" * size

    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match=r"call chain|operation token"):
        prepare_closure["initialize_issuer"].cell_contents(
            setup.binding_issuer,
            operation_token=object(),
            issuer_type=_LifecycleV2PreEffectBindingIssuer,
            context=registration.exposed_context,
            observation_issuer_identity=registration.expected_observation_issuer,
            challenge_source=attacker_challenge_source,
            realm_identity=prepare_closure["realm_identity"].cell_contents,
            realm_permit=prepare_closure["realm_permit"].cell_contents,
            authorize_issuer_initialization=prepare_closure[
                "authorize_issuer_initialization"
            ].cell_contents,
            register_issuer=register_issuer,
            getpid=prepare_closure["getpid"].cell_contents,
            current_thread=prepare_closure["current_thread"].cell_contents,
        )
    assert attacker_challenge_calls == []
    assert setup.binding_issuer._status == "consumed"
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="replayed"):
        setup.realm.bind_pre_effect(
            setup.binding_issuer,
            observation=setup.observation,
        )

    fresh_scenario = semantics_fixtures._scenario()
    fresh_primitives = _observation_primitives(
        fresh_scenario.clean_stop_result,
        label="callback-continuation",
        started=100,
    )
    fresh_lineage_five = _through_five(
        fresh_scenario,
        provider_identity_sha256=fresh_primitives.provider_identity_sha256,
    )
    fresh_observation_issuer = object()
    fresh_issuer = setup.realm.prepare_pre_effect(
        lineage_through_ordinal_5=fresh_lineage_five,
        observation_issuer_identity=fresh_observation_issuer,
    )
    fresh_binding = setup.realm.bind_pre_effect(
        fresh_issuer,
        observation=_ObservationInput(
            fresh_primitives,
            fresh_observation_issuer,
            object(),
        ),
    )
    fresh_binding.lifecycle_semantic_binding._require_sealed()


def test_traced_live_operation_token_cannot_reenter_production_prepare() -> None:
    adapter_closure = dict(
        zip(
            adapter._bind_lifecycle_v2_pre_effect_adr0109_observation_once.__code__.co_freevars,
            adapter._bind_lifecycle_v2_pre_effect_adr0109_observation_once.__closure__ or (),
            strict=True,
        )
    )
    realm = adapter_closure["production_binding_realm"].cell_contents
    prepare = dict(
        zip(
            realm.prepare_pre_effect.__code__.co_freevars,
            realm.prepare_pre_effect.__closure__ or (),
            strict=True,
        )
    )
    operation_state_cell = dict(
        zip(
            prepare["begin_realm_operation"].cell_contents.__code__.co_freevars,
            prepare["begin_realm_operation"].cell_contents.__closure__ or (),
            strict=True,
        )
    )["operation_state"]
    scenario = semantics_fixtures._scenario()
    observation_issuer, postcondition, _, primitives = _exact_adr0109_observation(
        scenario,
        started=100,
        label="trace-prepare",
    )
    lineage_five = _through_five(
        scenario,
        provider_identity_sha256=primitives.provider_identity_sha256,
    )
    captured: dict[str, object] = {}
    inside = False

    def tracer(frame: Any, _event: str, _arg: object) -> Callable[..., object]:
        nonlocal inside
        if inside or captured or frame.f_code is not realm.prepare_pre_effect.__code__:
            return tracer
        registrations = [
            registration
            for _, registration in operation_state_cell.cell_contents
            if registration.operation == "prepare"
            and registration.boundary == "pre_effect"
            and not registration.issuer_registered
        ]
        if not registrations:
            return tracer
        operation = registrations[0]
        inside = True
        try:
            try:
                captured["hidden"] = prepare["prepare_pre_effect_issuer"].cell_contents(
                    operation_token=operation.token,
                    lineage_through_ordinal_5=lineage_five,
                    observation_issuer_identity=observation_issuer,
                    challenge_source=prepare["challenge_source"].cell_contents,
                    realm_identity=prepare["realm_identity"].cell_contents,
                    realm_permit=prepare["realm_permit"].cell_contents,
                    authorize_issuer_initialization=prepare[
                        "authorize_issuer_initialization"
                    ].cell_contents,
                    register_issuer=prepare["register_issuer"].cell_contents,
                    initialize_issuer=prepare["initialize_issuer"].cell_contents,
                    require_lineage_boundary=prepare["require_lineage_boundary"].cell_contents,
                    normal_stage_for_ordinal=prepare["exact_normal_stage_lookup"].cell_contents,
                    getpid=prepare["getpid"].cell_contents,
                    current_thread=prepare["current_thread"].cell_contents,
                )
            except TrustedTimeGracefulStopV2Rejected as error:
                captured["direct_error"] = str(error)
        finally:
            inside = False
        return tracer

    sys.settrace(tracer)
    try:
        issuer = adapter._prepare_lifecycle_v2_pre_effect_adr0109_binding_issuer(
            lineage_through_ordinal_5=lineage_five,
            adr0109_issuer=observation_issuer,
        )
    finally:
        sys.settrace(None)
    assert captured == {"direct_error": "lifecycle-v2 reauthentication call chain is invalid"}
    assert issuer._status == "prepared"
    binding = adapter._bind_lifecycle_v2_pre_effect_adr0109_observation_once(
        issuer,
        postcondition=postcondition,
        adr0109_issuer=observation_issuer,
    )
    binding.lifecycle_semantic_binding._require_sealed()


def test_traced_live_bind_token_cannot_burn_issuer_or_adr0109_observation() -> None:
    adapter_closure = dict(
        zip(
            adapter._bind_lifecycle_v2_pre_effect_adr0109_observation_once.__code__.co_freevars,
            adapter._bind_lifecycle_v2_pre_effect_adr0109_observation_once.__closure__ or (),
            strict=True,
        )
    )
    realm = adapter_closure["production_binding_realm"].cell_contents
    bind = dict(
        zip(
            realm.bind_pre_effect.__code__.co_freevars,
            realm.bind_pre_effect.__closure__ or (),
            strict=True,
        )
    )
    operation_state_cell = dict(
        zip(
            bind["begin_realm_operation"].cell_contents.__code__.co_freevars,
            bind["begin_realm_operation"].cell_contents.__closure__ or (),
            strict=True,
        )
    )["operation_state"]
    scenario = semantics_fixtures._scenario()
    observation_issuer, postcondition, _, primitives = _exact_adr0109_observation(
        scenario,
        started=100,
        label="trace-bind",
    )
    lineage_five = _through_five(
        scenario,
        provider_identity_sha256=primitives.provider_identity_sha256,
    )
    victim = adapter._prepare_lifecycle_v2_pre_effect_adr0109_binding_issuer(
        lineage_through_ordinal_5=lineage_five,
        adr0109_issuer=observation_issuer,
    )
    continuation = adapter._prepare_lifecycle_v2_pre_effect_adr0109_binding_issuer(
        lineage_through_ordinal_5=lineage_five,
        adr0109_issuer=observation_issuer,
    )
    captured: dict[str, str] = {}
    inside = False

    def tracer(frame: Any, _event: str, _arg: object) -> Callable[..., object]:
        nonlocal inside
        if inside or captured or frame.f_code is not realm.bind_pre_effect.__code__:
            return tracer
        registrations = [
            registration
            for _, registration in operation_state_cell.cell_contents
            if registration.operation == "bind"
            and registration.boundary == "pre_effect"
            and registration.subject is victim
            and registration.candidate_status == "absent"
        ]
        if not registrations:
            return tracer
        operation = registrations[0]
        inside = True
        try:
            try:
                bind["bind_pre_effect_observation"].cell_contents(
                    victim,
                    operation_token=operation.token,
                    observation=frame.f_locals["observation"],
                    realm_identity=bind["realm_identity"].cell_contents,
                    realm_permit=bind["realm_permit"].cell_contents,
                    authenticate_observation=bind["authenticate_once"].cell_contents,
                    require_observation_candidate=bind[
                        "require_observation_candidate"
                    ].cell_contents,
                    begin_issuer=bind["begin_issuer"].cell_contents,
                    register_binding=bind["register_binding"].cell_contents,
                    semantic_binding_builder=lambda **_kwargs: (_ for _ in ()).throw(
                        AssertionError("semantic builder was reached")
                    ),
                    issue_binding=bind["issue_binding"].cell_contents,
                    getpid=bind["getpid"].cell_contents,
                    current_thread=bind["current_thread"].cell_contents,
                )
            except TrustedTimeGracefulStopV2Rejected as error:
                captured["direct_error"] = str(error)
                raise
        finally:
            inside = False
        return tracer

    sys.settrace(tracer)
    try:
        with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="call chain"):
            adapter._bind_lifecycle_v2_pre_effect_adr0109_observation_once(
                victim,
                postcondition=postcondition,
                adr0109_issuer=observation_issuer,
            )
    finally:
        sys.settrace(None)
    assert captured == {"direct_error": "lifecycle-v2 reauthentication call chain is invalid"}
    assert victim._status == "prepared"
    binding = adapter._bind_lifecycle_v2_pre_effect_adr0109_observation_once(
        victim,
        postcondition=postcondition,
        adr0109_issuer=observation_issuer,
    )
    binding.lifecycle_semantic_binding._require_sealed()
    assert continuation._status == "prepared"


def test_domain_first_metadata_spoof_cannot_preempt_production_adapter_claim() -> None:
    repository = Path(__file__).resolve().parents[2]
    script = """
import secrets
from packages.domain import trusted_time_graceful_stop_v2_reauthentication as domain

def forged(_binding_issuer, _observation):
    raise AssertionError

forged.__module__ = "packages.adapters.trusted_time.graceful_stop_v2_reauthentication"
forged.__name__ = "_consume_exact_adr0109_observation"
forged.__qualname__ = "_consume_exact_adr0109_observation"
try:
    domain._claim_lifecycle_v2_production_reauthentication_binding_realm(
        authenticate_observation=forged,
        challenge_source=secrets.token_bytes,
    )
except domain.TrustedTimeGracefulStopV2Rejected:
    pass
else:
    raise SystemExit("forged production realm claim was accepted")

from packages.adapters.trusted_time import graceful_stop_v2_reauthentication as adapter
if hasattr(adapter, "_consume_exact_adr0109_observation"):
    raise SystemExit("raw production observation consumer remained exposed")
try:
    domain._claim_lifecycle_v2_production_reauthentication_binding_realm(
        authenticate_observation=forged,
        challenge_source=secrets.token_bytes,
    )
except domain.TrustedTimeGracefulStopV2Rejected:
    pass
else:
    raise SystemExit("production realm claim was replayed")
"""
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(repository)
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr


def test_sys_modules_adapter_spoof_cannot_claim_the_production_realm() -> None:
    repository = Path(__file__).resolve().parents[2]
    script = """
import importlib.util
import secrets
import sys
import types
from pathlib import Path

repository = Path.cwd()
module_name = "packages.adapters.trusted_time.graceful_stop_v2_reauthentication"
adapter_path = repository / "packages/adapters/trusted_time/graceful_stop_v2_reauthentication.py"
forged_module = types.ModuleType(module_name)
forged_module.__file__ = str(adapter_path)
forged_module.__spec__ = importlib.util.spec_from_file_location(
    module_name,
    adapter_path,
)
forged_module.__spec__._initializing = True
sys.modules[module_name] = forged_module

from packages.domain import trusted_time_graceful_stop_v2_reauthentication as domain

forged_module.__dict__["domain"] = domain
forged_source = '''
import secrets

def _consume_exact_adr0109_observation(_binding_issuer, _observation):
    raise AssertionError

try:
    domain._claim_lifecycle_v2_production_reauthentication_binding_realm(
        authenticate_observation=_consume_exact_adr0109_observation,
        challenge_source=secrets.token_bytes,
    )
except domain.TrustedTimeGracefulStopV2Rejected:
    pass
else:
    raise SystemExit("forged sys.modules adapter claimed production realm")
'''
exec(compile(forged_source, str(adapter_path), "exec"), forged_module.__dict__)
"""
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(repository)
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr


def test_sys_modules_adr0109_spoof_cannot_mint_a_production_binding() -> None:
    repository = Path(__file__).resolve().parents[2]
    script = """
import importlib.util
import sys
import types
from pathlib import Path

repository = Path.cwd()
module_name = "scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication"
source = repository / "scripts/trusted_time_post_enrollment_clean_stop_terminal_reauthentication.py"
forged_module = types.ModuleType(module_name)
forged_module.__file__ = str(source)
forged_module.__spec__ = importlib.util.spec_from_file_location(module_name, source)
forged_module.__spec__._initializing = True
forged_module._attacker_sentinel = object()
forged_calls = []

def forged_consume(*_args, **_kwargs):
    forged_calls.append(True)
    return object()

forged_module._consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once = (
    forged_consume
)
forged_module._postcondition_payload = lambda _value: {}
setattr(
    forged_module,
    "_validate_trusted_time_post_enrollment_clean_stop_terminal_postcondition_consumed_by",
    forged_consume,
)
forged_module._ConsumedPostconditionRegistrySnapshot = type(
    "_ConsumedPostconditionRegistrySnapshot",
    (),
    {},
)
forged_module.TrustedTimePostEnrollmentCleanStopTerminalPostcondition = type(
    "TrustedTimePostEnrollmentCleanStopTerminalPostcondition",
    (),
    {},
)
forged_module.TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer = type(
    "TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer",
    (),
    {},
)
sys.modules[module_name] = forged_module

from packages.domain import trusted_time_graceful_stop_v2_reauthentication as domain
trusted_adr0109 = sys.modules[module_name]
if hasattr(trusted_adr0109, "_attacker_sentinel"):
    raise SystemExit("forged ADR-0109 namespace survived canonical bootstrap")
if (
    trusted_adr0109._consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once
    is forged_consume
):
    raise SystemExit("forged ADR-0109 consumer survived canonical bootstrap")

from packages.adapters.trusted_time import graceful_stop_v2_reauthentication as adapter
from tests.unit import test_trusted_time_graceful_stop_v2_lifecycle_semantics as semantics
from tests.unit import test_trusted_time_graceful_stop_v2_reauthentication_bindings as binding_fx

scenario = semantics._scenario()
issuer, postcondition, _, primitives = binding_fx._exact_adr0109_observation(
    scenario,
    started=100,
    label="preseed",
)
lineage_five = binding_fx._through_five(
    scenario,
    provider_identity_sha256=primitives.provider_identity_sha256,
)
binding_issuer = adapter._prepare_lifecycle_v2_pre_effect_adr0109_binding_issuer(
    lineage_through_ordinal_5=lineage_five,
    adr0109_issuer=issuer,
)
binding = adapter._bind_lifecycle_v2_pre_effect_adr0109_observation_once(
    binding_issuer,
    postcondition=postcondition,
    adr0109_issuer=issuer,
)
lineage_six = lineage_five.retain_pre_effect_reauthentication_binding(
    binding=binding.lifecycle_semantic_binding,
    recorded_at_utc=semantics.UTC_TEXT,
)
if (
    lineage_six.record_at(6).evidence.to_dict()["binding_semantic_sha256"]
    != binding.lifecycle_semantic_binding.sha256
):
    raise SystemExit("canonical production ordinal-six binding was not retained")
if forged_calls:
    raise SystemExit("forged ADR-0109 consumer was invoked")
try:
    domain._claim_lifecycle_v2_production_reauthentication_binding_realm(
        authenticate_observation=lambda *_args: None,
        challenge_source=lambda size: b"x" * size,
    )
except domain.TrustedTimeGracefulStopV2Rejected:
    pass
else:
    raise SystemExit("production realm bootstrap claim was replayed")
"""
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(repository)
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr


def test_preseeded_modules_cannot_claim_terminal_recovery_or_lifecycle_installers() -> None:
    repository = Path(__file__).resolve().parents[2]
    script = """
import importlib.util
import sys
import types
from pathlib import Path

repository = Path.cwd()
adapter_name = "packages.adapters.trusted_time.graceful_stop_v2_ed25519"
adapter_path = repository / "packages/adapters/trusted_time/graceful_stop_v2_ed25519.py"
fake_adapter = types.ModuleType(adapter_name)
fake_adapter.__file__ = str(adapter_path)
fake_adapter.__spec__ = importlib.util.spec_from_file_location(adapter_name, adapter_path)
fake_adapter.__spec__._initializing = True
sys.modules[adapter_name] = fake_adapter

from packages.domain import trusted_time_graceful_stop_v2_terminal as terminal
from packages.domain import trusted_time_graceful_stop_v2_recovery as recovery
fake_adapter.__dict__.update(terminal=terminal, recovery=recovery)
forged_adapter_source = '''
def forged_terminal(value):
    return value
def forged_recovery(value):
    return value
_unwrap_authenticated_lifecycle_v2_transport_envelope = forged_terminal
_consume_authenticated_lifecycle_v2_recovery_envelope_value = forged_recovery
try:
    terminal._install_authenticated_terminal_envelope_adapter_endpoint(forged_terminal)
except terminal.TrustedTimeGracefulStopV2Rejected:
    pass
else:
    raise SystemExit("preseeded adapter claimed terminal proof installation")
try:
    recovery._install_authenticated_lifecycle_v2_recovery_adapter_endpoint(forged_recovery)
except recovery.TrustedTimeGracefulStopV2Rejected:
    pass
else:
    raise SystemExit("preseeded adapter claimed recovery installation")
'''
exec(compile(forged_adapter_source, str(adapter_path), "exec"), fake_adapter.__dict__)

realm_name = "packages.domain.trusted_time_graceful_stop_v2_reauthentication"
realm_path = repository / "packages/domain/trusted_time_graceful_stop_v2_reauthentication.py"
fake_realm = types.ModuleType(realm_name)
fake_realm.__file__ = str(realm_path)
fake_realm.__spec__ = importlib.util.spec_from_file_location(realm_name, realm_path)
fake_realm.__spec__._initializing = True
sys.modules[realm_name] = fake_realm
from packages.domain import trusted_time_graceful_stop_v2_lifecycle_semantics as lifecycle
fake_realm.__dict__["lifecycle"] = lifecycle
forged_realm_source = '''
def forged_consumer(value):
    return value
_consume_exact_lifecycle_v2_reauthentication_semantic_binding_issuance_once = forged_consumer
_LifecycleV2ReauthenticationSemanticBindingIssuanceSnapshot = type(
    "_LifecycleV2ReauthenticationSemanticBindingIssuanceSnapshot",
    (),
    {},
)
try:
    lifecycle._install_lifecycle_v2_reauthentication_semantic_binding_issuance_consumer(
        forged_consumer,
    )
except lifecycle.TrustedTimeLifecycleV2SemanticsRejected:
    pass
else:
    raise SystemExit("preseeded realm claimed lifecycle semantic installation")
'''
exec(compile(forged_realm_source, str(realm_path), "exec"), fake_realm.__dict__)
"""
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(repository)
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize("first_import", ["domain", "adapter"])
def test_production_adapter_bootstrap_supports_both_import_orders(
    first_import: str,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    script = f"""
import sys
if {first_import!r} == "domain":
    from packages.domain import trusted_time_graceful_stop_v2_reauthentication
    from packages.adapters.trusted_time import graceful_stop_v2_reauthentication as adapter
else:
    from packages.adapters.trusted_time import graceful_stop_v2_reauthentication as adapter
    from packages.domain import trusted_time_graceful_stop_v2_reauthentication
name = "packages.adapters.trusted_time.graceful_stop_v2_reauthentication"
if adapter is not sys.modules[name]:
    raise SystemExit("production adapter import identity is not canonical")
if hasattr(adapter, "_LIFECYCLE_V2_PRODUCTION_REALM_BOOTSTRAP_PERMIT"):
    raise SystemExit("production bootstrap permit remained exposed")
for endpoint in (
    "_prepare_lifecycle_v2_pre_effect_adr0109_binding_issuer",
    "_bind_lifecycle_v2_pre_effect_adr0109_observation_once",
    "_prepare_lifecycle_v2_post_teardown_adr0109_binding_issuer",
    "_bind_lifecycle_v2_post_teardown_adr0109_observation_once",
):
    if not callable(getattr(adapter, endpoint, None)):
        raise SystemExit("production adapter endpoint is missing")
"""
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(repository)
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr


def test_production_realm_ignores_challenge_source_monkeypatch_after_bootstrap() -> None:
    repository = Path(__file__).resolve().parents[2]
    script = """
import secrets
import sys
from packages.domain import trusted_time_graceful_stop_v2_reauthentication as domain

module_name = "packages.adapters.trusted_time.graceful_stop_v2_reauthentication"
trusted_adapter = sys.modules[module_name]
trusted_prepare = trusted_adapter._prepare_lifecycle_v2_pre_effect_adr0109_binding_issuer
secrets.token_bytes = lambda size: b"x" * size
from packages.adapters.trusted_time import graceful_stop_v2_reauthentication as adapter
if adapter is not trusted_adapter:
    raise SystemExit("canonical production adapter identity changed")
if adapter._prepare_lifecycle_v2_pre_effect_adr0109_binding_issuer is not trusted_prepare:
    raise SystemExit("production realm endpoint changed after global replacement")
try:
    domain._claim_lifecycle_v2_production_reauthentication_binding_realm(
        authenticate_observation=lambda *_args: None,
        challenge_source=secrets.token_bytes,
    )
except domain.TrustedTimeGracefulStopV2Rejected:
    pass
else:
    raise SystemExit("consumed production realm claim was replayed")
"""
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(repository)
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr


def test_production_adapter_consumes_exact_adr0109_registry_for_both_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forged_dependency(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("module-global adapter dependency replacement was invoked")

    monkeypatch.setattr(adapter, "_PRODUCTION_BINDING_REALM", object(), raising=False)
    for name in (
        "_consume_exact_adr0109_observation",
        "_consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once",
        "_observation_from_consumed_snapshot",
        "_postcondition_payload",
        "_validate_trusted_time_post_enrollment_clean_stop_terminal_postcondition_consumed_by",
    ):
        monkeypatch.setattr(adapter, name, forged_dependency, raising=False)
    monkeypatch.setattr(adapter, "_ADR0109ObservationInput", object(), raising=False)
    monkeypatch.setattr(
        adapter,
        "_LifecycleV2ADR0109ObservationCandidate",
        object(),
        raising=False,
    )
    monkeypatch.setattr(
        adapter,
        "LifecycleV2ADR0109ObservationPrimitives",
        object(),
        raising=False,
    )
    scenario = semantics_fixtures._scenario()
    (
        pre_observation_issuer,
        pre_postcondition,
        configuration,
        pre_primitives,
    ) = _exact_adr0109_observation(
        scenario,
        started=100,
        label="pre",
    )
    lineage_five = _through_five(
        scenario,
        provider_identity_sha256=pre_primitives.provider_identity_sha256,
    )
    burned_issuer = adapter._prepare_lifecycle_v2_pre_effect_adr0109_binding_issuer(
        lineage_through_ordinal_5=lineage_five,
        adr0109_issuer=pre_observation_issuer,
    )
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="exact ADR-0109"):
        adapter._bind_lifecycle_v2_pre_effect_adr0109_observation_once(
            burned_issuer,
            postcondition=pre_postcondition,
            adr0109_issuer=object(),
        )
    assert burned_issuer._status == "consumed"
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="replayed"):
        adapter._bind_lifecycle_v2_pre_effect_adr0109_observation_once(
            burned_issuer,
            postcondition=pre_postcondition,
            adr0109_issuer=pre_observation_issuer,
        )

    pre_binding_issuer = adapter._prepare_lifecycle_v2_pre_effect_adr0109_binding_issuer(
        lineage_through_ordinal_5=lineage_five,
        adr0109_issuer=pre_observation_issuer,
    )
    pre_binding = adapter._bind_lifecycle_v2_pre_effect_adr0109_observation_once(
        pre_binding_issuer,
        postcondition=pre_postcondition,
        adr0109_issuer=pre_observation_issuer,
    )
    assert type(pre_binding.lifecycle_semantic_binding) is (
        LifecycleV2AuthenticatedReauthenticationBinding
    )
    pre_binding.lifecycle_semantic_binding._require_sealed()
    assert pre_binding.durable_evidence.to_dict()["adr0109_observation"] == (
        pre_primitives.to_dict()
    )
    lineage_six = lineage_five.retain_pre_effect_reauthentication_binding(
        binding=pre_binding.lifecycle_semantic_binding,
        recorded_at_utc=semantics_fixtures.UTC_TEXT,
    )

    (
        post_observation_issuer,
        post_postcondition,
        _,
        post_primitives,
    ) = _exact_adr0109_observation(
        scenario,
        started=1_100_000,
        label="post",
        configuration=configuration,
    )
    lineage_nineteen = _through_nineteen(
        scenario,
        lineage_six,
        provider_identity_sha256=post_primitives.provider_identity_sha256,
    )
    post_binding_issuer = adapter._prepare_lifecycle_v2_post_teardown_adr0109_binding_issuer(
        lineage_through_ordinal_19=lineage_nineteen,
        pre_effect_binding=pre_binding,
        adr0109_issuer=post_observation_issuer,
    )
    post_binding = adapter._bind_lifecycle_v2_post_teardown_adr0109_observation_once(
        post_binding_issuer,
        postcondition=post_postcondition,
        adr0109_issuer=post_observation_issuer,
    )
    assert type(post_binding.lifecycle_semantic_binding) is (
        LifecycleV2AuthenticatedReauthenticationBinding
    )
    post_binding.lifecycle_semantic_binding._require_sealed()
    assert post_binding.durable_evidence.to_dict()["adr0109_observation"] == (
        post_primitives.to_dict()
    )
    assert (
        post_binding.durable_evidence.to_dict()["provider_identity_sha256"]
        == (pre_binding.durable_evidence.to_dict()["provider_identity_sha256"])
    )


def test_adapter_uses_exact_adr0109_registry_after_domain_begin() -> None:
    lookalike = type(
        "TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer",
        (),
        {},
    )()
    type(
        lookalike
    ).__module__ = "scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication"
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="exact ADR-0109"):
        adapter._require_exact_adr0109_issuer(lookalike)

    path = Path("packages/adapters/trusted_time/graceful_stop_v2_reauthentication.py")
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert "trusted_time_post_enrollment_clean_stop_terminal_reauthentication" in source
    assert "graceful_stop_supervisor_bridge" not in source
    assert "trusted_time_graceful_stop_v2_adr0111" not in source
    assert not imports.intersection({"socket", "subprocess", "docker", "requests"})
    assert "reauthenticate_clean_stop_terminal_once" not in source
    assert "publish_immutable" not in source

    bind_function = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "bind_pre_effect"
    )
    calls = [
        ast.unparse(node.func) for node in ast.walk(bind_function) if isinstance(node, ast.Call)
    ]
    assert "_consume_exact_adr0109_observation" not in calls
    assert "production_binding_realm.bind_pre_effect" in calls
    assert not hasattr(adapter, "_PRODUCTION_BINDING_REALM")
    assert not hasattr(
        adapter,
        "_claim_lifecycle_v2_production_reauthentication_binding_realm",
    )


def test_observation_schema_rejects_bool_deadline_and_head_substitution() -> None:
    scenario = semantics_fixtures._scenario()
    base = _observation_primitives(
        scenario.clean_stop_result,
        label="schema",
        started=100,
    ).to_dict()
    for name, replacement in (
        ("anchor_sequence", True),
        (
            "deadline_monotonic_ns",
            cast(int, base["deadline_monotonic_ns"]) - 1,
        ),
        ("candidate_remote_readback_sha256", _digest("other-anchor")),
        ("semantic_sha256", _digest("caller-selected-semantic")),
    ):
        with pytest.raises(TrustedTimeGracefulStopV2Rejected):
            LifecycleV2ADR0109ObservationPrimitives.capture({**base, name: replacement})
