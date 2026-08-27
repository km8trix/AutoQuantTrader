from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import os
import pickle
import secrets
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

import scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication as adr0109
from packages.adapters.trusted_time import graceful_stop_v2_reauthentication as adapter
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
    _FAKE_REAUTHENTICATION_BINDING_CAPABILITY,
    _PRODUCTION_REAUTHENTICATION_BINDING_CAPABILITY,
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
        prior = semantics_fixtures._trace_prefix(
            scenario.admission,
            scenario.entries,
            ordinal - 1,
        )
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
    assert setup.lineage_six.pre_effect_binding is not None
    assert setup.lineage_six.pre_effect_binding.encoded == semantic.encoded
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
    object.__setattr__(nested_context, "root", object())
    with pytest.raises(TrustedTimeGracefulStopV2Rejected, match="seal changed"):
        nested_realm.bind_pre_effect(
            nested_issuer,
            observation=_ObservationInput(primitives, observation_issuer, object()),
        )
    object.__setattr__(nested_context, "root", original_root)
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
    assert binding.lifecycle_semantic_binding.boundary == "post_teardown"
    assert binding.durable_evidence.binding_sha256 == (
        LifecycleV2PostTeardownBindingEvidence._capture(fields).binding_sha256
    )


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

    def consume() -> None:
        try:
            realm.bind_pre_effect(issuer, observation=observation)
        except BaseException as error:
            errors.append(error)

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

    def read_binding() -> None:
        try:
            _ = setup.binding.durable_evidence
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=read_binding)
    thread.start()
    thread.join()
    assert len(errors) == 1
    assert isinstance(errors[0], TrustedTimeGracefulStopV2Rejected)

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
    assert setup.binding.lifecycle_semantic_binding._capability is (
        _FAKE_REAUTHENTICATION_BINDING_CAPABILITY
    )
    assert setup.binding.lifecycle_semantic_binding._capability is not (
        _PRODUCTION_REAUTHENTICATION_BINDING_CAPABILITY
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


def test_production_realm_rejects_challenge_source_monkeypatch_after_domain_load() -> None:
    repository = Path(__file__).resolve().parents[2]
    script = """
import secrets
from packages.domain import trusted_time_graceful_stop_v2_reauthentication as domain

secrets.token_bytes = lambda size: b"x" * size
try:
    from packages.adapters.trusted_time import graceful_stop_v2_reauthentication
except domain.TrustedTimeGracefulStopV2Rejected:
    pass
else:
    raise SystemExit("monkeypatched production challenge source was accepted")
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


def test_production_adapter_consumes_exact_adr0109_registry_for_both_boundaries() -> None:
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
    assert pre_binding.lifecycle_semantic_binding._capability is (
        _PRODUCTION_REAUTHENTICATION_BINDING_CAPABILITY
    )
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
    assert post_binding.lifecycle_semantic_binding._capability is (
        _PRODUCTION_REAUTHENTICATION_BINDING_CAPABILITY
    )
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
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "_bind_lifecycle_v2_pre_effect_adr0109_observation_once"
    )
    calls = [
        ast.unparse(node.func) for node in ast.walk(bind_function) if isinstance(node, ast.Call)
    ]
    assert "_consume_exact_adr0109_observation" not in calls
    assert "_PRODUCTION_BINDING_REALM.bind_pre_effect" in calls


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
