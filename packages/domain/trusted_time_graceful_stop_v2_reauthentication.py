"""Effect-free ADR-0109 binding seams for lifecycle-v2 milestone one.

The durable values in this module contain only canonical primitive evidence.
The issuer, observation, and binding seals are deliberately process-local,
thread-bound, one shot, and non-serializable.  This module performs no
provider observation, persistence, transport, Docker call, or stop effect.
"""

from __future__ import annotations

import hashlib
import importlib
import os
import re
import secrets
import sys
import threading
import weakref
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from importlib.machinery import ModuleSpec
from types import CodeType, FrameType, ModuleType
from typing import NamedTuple, Never, Self, TypeVar, cast

from packages.domain.trusted_time_graceful_stop_v2 import (
    LIFECYCLE_V2_SERVICE,
    MAXIMUM_SIGNED_INTEGER,
    FrozenJsonObject,
    LifecycleV2CleanStopRequest,
    LifecycleV2ProgressRecord,
    LifecycleV2Root,
    LifecycleV2Stage,
    LifecycleV2Transcript,
    TrustedTimeGracefulStopV2Rejected,
    canonical_v2_json_bytes,
    decode_lifecycle_v2_clean_stop_request,
    decode_lifecycle_v2_progress_record,
    decode_lifecycle_v2_root,
    decode_lifecycle_v2_transcript,
    normal_lifecycle_v2_stage_for_ordinal,
)
from packages.domain.trusted_time_graceful_stop_v2_lifecycle_semantics import (
    LIFECYCLE_V2_CLEANUP_SERVICE,
    LifecycleV2AuthenticatedReauthenticationBinding,
    LifecycleV2NormalProgressLineage,
    LifecycleV2ReauthenticationIntent,
    _capture_lifecycle_v2_authenticated_reauthentication_binding_from_realm,
    _install_lifecycle_v2_reauthentication_semantic_binding_issuance_consumer,
    require_exact_lifecycle_v2_normal_lineage_through_ordinal_5,
    require_exact_lifecycle_v2_normal_lineage_through_ordinal_19,
)
from packages.domain.trusted_time_graceful_stop_v2_terminal import (
    LifecycleV2CleanStopResult,
)

ADR0109_REAUTHENTICATION_CONTRACT_VERSION = (
    "phase6d-post-enrollment-clean-stop-terminal-reauthentication-v1"
)
ADR0109_REAUTHENTICATION_STATUS = "provider_terminal_observed_under_stable_sql_authenticated"
LIFECYCLE_V2_PRE_EFFECT_BINDING_CONTRACT_VERSION = (
    "phase6d-trusted-time-graceful-stop-pre-effect-reauthentication-binding-v2"
)
LIFECYCLE_V2_POST_TEARDOWN_BINDING_CONTRACT_VERSION = (
    "phase6d-trusted-time-graceful-stop-post-teardown-reauthentication-binding-v2"
)
ADR0109_OBSERVATION_BUDGET_NS = 120_000_000_000
_FAKE_REAUTHENTICATION_BINDING_PROVENANCE = "fake_reauthentication_binding"
_PRODUCTION_REAUTHENTICATION_BINDING_PROVENANCE = "production_reauthentication_binding"
_REAUTHENTICATION_BINDING_PROVENANCES = frozenset(
    {
        _FAKE_REAUTHENTICATION_BINDING_PROVENANCE,
        _PRODUCTION_REAUTHENTICATION_BINDING_PROVENANCE,
    }
)
_StateValue = TypeVar("_StateValue")

_MAXIMUM_BYTES = 256 * 1_024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")


def _reject(message: str) -> Never:
    raise TrustedTimeGracefulStopV2Rejected(message)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _domain_sha256(domain: str, value: object) -> str:
    encoded = canonical_v2_json_bytes(value, maximum_bytes=_MAXIMUM_BYTES)
    return _sha256(domain.encode("ascii") + b"\0" + encoded)


def _require_sha256(value: object, name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _reject(f"{name} is not lowercase SHA-256")
    return value


def _require_int(
    value: object,
    name: str,
    *,
    minimum: int = 0,
    maximum: int = MAXIMUM_SIGNED_INTEGER,
) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        _reject(f"{name} is outside its integer bounds")
    return value


def _require_fields(value: dict[str, object], fields: frozenset[str], label: str) -> None:
    if frozenset(value) != fields:
        _reject(f"{label} field set is not exact")


def _require_exact_root(value: object) -> LifecycleV2Root:
    if type(value) is not LifecycleV2Root:
        _reject("reauthentication binding requires an exact lifecycle root")
    canonical = decode_lifecycle_v2_root(value.encoded)
    if canonical != value:
        _reject("reauthentication lifecycle root changed under validation")
    return canonical


def _require_exact_request(value: object) -> LifecycleV2CleanStopRequest:
    if type(value) is not LifecycleV2CleanStopRequest:
        _reject("reauthentication binding requires an exact clean-stop request")
    canonical = decode_lifecycle_v2_clean_stop_request(value.encoded)
    if canonical != value:
        _reject("reauthentication clean-stop request changed under validation")
    return canonical


def _require_exact_result(value: object) -> LifecycleV2CleanStopResult:
    if type(value) is not LifecycleV2CleanStopResult:
        _reject("reauthentication binding requires an exact clean-stop result")
    canonical = LifecycleV2CleanStopResult.capture(value.to_dict())
    if canonical != value:
        _reject("reauthentication clean-stop result changed under validation")
    return canonical


def _require_exact_record(
    value: object,
    *,
    root: LifecycleV2Root,
    ordinal: int,
    stage: LifecycleV2Stage,
    predecessor_sha256: str | None = None,
) -> LifecycleV2ProgressRecord:
    if type(value) is not LifecycleV2ProgressRecord:
        _reject("reauthentication binding requires an exact progress record")
    canonical = decode_lifecycle_v2_progress_record(value.encoded)
    if (
        canonical != value
        or canonical.graceful_stop_operation_id != root.graceful_stop_operation_id
        or canonical.root_sha256 != root.sha256
        or canonical.ordinal != ordinal
        or canonical.stage is not stage
        or (predecessor_sha256 is not None and canonical.predecessor_sha256 != predecessor_sha256)
    ):
        _reject("reauthentication progress record crossed its lifecycle prefix")
    return canonical


def _require_exact_transcript(
    value: object,
    *,
    root: LifecycleV2Root,
    last_ordinal: int,
    last_stage: LifecycleV2Stage,
) -> LifecycleV2Transcript:
    if type(value) is not LifecycleV2Transcript:
        _reject("post-teardown binding requires an exact lifecycle transcript")
    canonical = decode_lifecycle_v2_transcript(value.encoded)
    if (
        canonical != value
        or canonical.environment != root.environment
        or canonical.graceful_stop_operation_id != root.graceful_stop_operation_id
        or canonical.root_sha256 != root.sha256
        or canonical.entries[-1].ordinal != last_ordinal
        or canonical.entries[-1].stage is not last_stage
    ):
        _reject("post-teardown transcript is not the exact ordinal-18 prefix")
    return canonical


_OBSERVATION_FIELDS = frozenset(
    {
        "contract_version",
        "status",
        "anchor_sequence",
        "checkpoint_reason",
        "confirmed_anchor_count",
        "local_transition_count",
        "confirmed_anchor_local_transition_ordinal",
        "remote_object_count",
        "predecessor_anchor_sha256",
        "current_host_head_sha256",
        "current_anchor_sha256",
        "current_anchor_semantic_sha256",
        "anchor_intent_semantic_sha256",
        "candidate_remote_readback_sha256",
        "receipt_semantic_sha256",
        "receipt_observed_at_utc",
        "remote_observation_sha256",
        "anchor_authority_sha256",
        "deployment_identity_sha256",
        "runtime_database_identity_sha256",
        "anchor_project_identity_sha256",
        "source_authority_sha256",
        "signing_public_key_sha256",
        "host_identity_sha256",
        "principal_identity_sha256",
        "bucket_identity_sha256",
        "observation_started_monotonic_ns",
        "observation_completed_monotonic_ns",
        "deadline_monotonic_ns",
        "issuer_binding_sha256",
        "read_only_configuration_sha256",
        "semantic_sha256",
    }
)
_PROVIDER_IDENTITY_FIELDS = (
    "anchor_authority_sha256",
    "deployment_identity_sha256",
    "runtime_database_identity_sha256",
    "anchor_project_identity_sha256",
    "source_authority_sha256",
    "signing_public_key_sha256",
    "host_identity_sha256",
    "principal_identity_sha256",
    "bucket_identity_sha256",
    "read_only_configuration_sha256",
)
_OBSERVATION_TERMINAL_FIELDS = (
    "anchor_sequence",
    "checkpoint_reason",
    "confirmed_anchor_count",
    "local_transition_count",
    "confirmed_anchor_local_transition_ordinal",
    "predecessor_anchor_sha256",
    "current_host_head_sha256",
    "current_anchor_sha256",
    "current_anchor_semantic_sha256",
    "anchor_intent_semantic_sha256",
    "candidate_remote_readback_sha256",
    "receipt_semantic_sha256",
    "receipt_observed_at_utc",
)


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2ADR0109ObservationPrimitives:
    """Canonical durable projection of one consumed ADR-0109 observation."""

    fields: FrozenJsonObject

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("ADR-0109 observation primitives require canonical capture")

    @classmethod
    def capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _OBSERVATION_FIELDS, "ADR-0109 observation")
        if (
            fields["contract_version"] != ADR0109_REAUTHENTICATION_CONTRACT_VERSION
            or fields["status"] != ADR0109_REAUTHENTICATION_STATUS
            or fields["checkpoint_reason"] != "clean_stop"
        ):
            _reject("ADR-0109 observation discriminator is invalid")
        anchor_sequence = _require_int(fields["anchor_sequence"], "anchor_sequence", minimum=3)
        confirmed = _require_int(
            fields["confirmed_anchor_count"], "confirmed_anchor_count", minimum=3
        )
        remote_count = _require_int(fields["remote_object_count"], "remote_object_count", minimum=3)
        local_count = _require_int(
            fields["local_transition_count"], "local_transition_count", minimum=3
        )
        terminal_ordinal = _require_int(
            fields["confirmed_anchor_local_transition_ordinal"],
            "confirmed_anchor_local_transition_ordinal",
            minimum=3,
        )
        if (
            confirmed != anchor_sequence
            or remote_count != anchor_sequence
            or terminal_ordinal != local_count
            or local_count < anchor_sequence
        ):
            _reject("ADR-0109 observation counts are inconsistent")
        for name in fields:
            if name.endswith("_sha256"):
                _require_sha256(fields[name], name)
        semantic_payload = dict(fields)
        semantic_sha256 = cast(str, semantic_payload.pop("semantic_sha256"))
        if (
            _sha256(canonical_v2_json_bytes(semantic_payload, maximum_bytes=_MAXIMUM_BYTES))
            != semantic_sha256
        ):
            _reject("ADR-0109 observation semantic digest is not canonical")
        if fields["candidate_remote_readback_sha256"] != fields["current_anchor_sha256"]:
            _reject("ADR-0109 observation readback is not its current anchor")
        receipt_utc = fields["receipt_observed_at_utc"]
        if type(receipt_utc) is not str or _UTC.fullmatch(receipt_utc) is None:
            _reject("ADR-0109 observation receipt time is not canonical UTC")
        started = _require_int(
            fields["observation_started_monotonic_ns"],
            "observation_started_monotonic_ns",
        )
        completed = _require_int(
            fields["observation_completed_monotonic_ns"],
            "observation_completed_monotonic_ns",
        )
        deadline = _require_int(fields["deadline_monotonic_ns"], "deadline_monotonic_ns")
        if (
            started > MAXIMUM_SIGNED_INTEGER - ADR0109_OBSERVATION_BUDGET_NS
            or deadline != started + ADR0109_OBSERVATION_BUDGET_NS
            or not started <= completed < deadline
        ):
            _reject("ADR-0109 observation interval is not the exact live 120-second interval")
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        return result

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def encoded(self) -> bytes:
        return canonical_v2_json_bytes(self.to_dict(), maximum_bytes=_MAXIMUM_BYTES)

    @property
    def sha256(self) -> str:
        return _sha256(self.encoded)

    @property
    def provider_identity_sha256(self) -> str:
        fields = self.to_dict()
        projection = {name: fields[name] for name in _PROVIDER_IDENTITY_FIELDS}
        return _domain_sha256(
            "AutoQuantTrader/trusted-time/graceful-stop/adr0109-provider-identity/v2",
            projection,
        )


@dataclass(frozen=True, slots=True, eq=False)
class _LifecycleV2ADR0109ObservationCandidate:
    """Non-authoritative callback data consumed inside one isolated realm.

    The production realm fixes its callback to the direct ADR-0109 registry
    consumer in the adapter.  Constructing this data grants no authority: a
    caller cannot supply it to that fixed callback or choose the realm seal.
    """

    primitives: LifecycleV2ADR0109ObservationPrimitives
    issuer_identity: object
    observation_identity: object


def _build_observation_candidate_validator() -> Callable[
    [object],
    _LifecycleV2ADR0109ObservationCandidate,
]:
    candidate_type = _LifecycleV2ADR0109ObservationCandidate
    primitives_type = LifecycleV2ADR0109ObservationPrimitives
    capture_primitives = primitives_type.capture
    raw_new = object.__new__
    raw_setattr = object.__setattr__

    def require_observation_candidate(
        value: object,
    ) -> _LifecycleV2ADR0109ObservationCandidate:
        if type(value) is not candidate_type:
            _reject("ADR-0109 authenticator returned an invalid result")
        exact = value
        if type(exact.primitives) is not primitives_type:
            _reject("authenticated ADR-0109 observation primitives are not exact")
        canonical = capture_primitives(exact.primitives.to_dict())
        if (
            canonical != exact.primitives
            or exact.issuer_identity is None
            or exact.observation_identity is None
        ):
            _reject("authenticated ADR-0109 observation changed after callback")
        result = raw_new(candidate_type)
        raw_setattr(result, "primitives", canonical)
        raw_setattr(result, "issuer_identity", exact.issuer_identity)
        raw_setattr(result, "observation_identity", exact.observation_identity)
        return result

    return require_observation_candidate


_require_observation_candidate = _build_observation_candidate_validator()
del _build_observation_candidate_validator


def _terminal_projection_from_result(result: LifecycleV2CleanStopResult) -> dict[str, object]:
    value = result.terminal_projection.to_dict()
    return {
        "anchor_sequence": value["anchor_sequence"],
        "checkpoint_reason": value["checkpoint_reason"],
        "confirmed_anchor_count": value["confirmed_anchor_count"],
        "local_transition_count": value["local_transition_count"],
        "confirmed_anchor_local_transition_ordinal": value[
            "confirmed_anchor_local_transition_ordinal"
        ],
        "predecessor_anchor_sha256": value["predecessor_anchor_sha256"],
        "current_host_head_sha256": value["current_host_head_sha256"],
        "current_anchor_sha256": value["current_anchor_sha256"],
        "current_anchor_semantic_sha256": value["current_anchor_semantic_sha256"],
        "anchor_intent_semantic_sha256": value["current_anchor_intent_semantic_sha256"],
        "candidate_remote_readback_sha256": value["current_candidate_remote_readback_sha256"],
        "receipt_semantic_sha256": value["current_receipt_semantic_sha256"],
        "receipt_observed_at_utc": value["receipt_observed_at_utc"],
    }


def _require_observation_matches_result(
    observation: _LifecycleV2ADR0109ObservationCandidate,
    result: LifecycleV2CleanStopResult,
) -> dict[str, object]:
    fields = observation.primitives.to_dict()
    expected = _terminal_projection_from_result(result)
    if any(fields[name] != expected[name] for name in _OBSERVATION_TERMINAL_FIELDS):
        _reject("ADR-0109 observation crossed its exact CLEAN_STOP result")
    return fields


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2PreEffectBindingEvidence:
    """Primitive-only durable evidence for the ordinal-six binding."""

    fields: FrozenJsonObject

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("pre-effect binding evidence requires the private seam")

    @classmethod
    def _capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _PRE_EFFECT_EVIDENCE_FIELDS, "pre-effect binding")
        if (
            fields["contract_version"] != LIFECYCLE_V2_PRE_EFFECT_BINDING_CONTRACT_VERSION
            or fields["service"] != LIFECYCLE_V2_SERVICE
            or fields["status"] != "fresh_pre_effect_adr0109_observation_bound"
            or fields["expected_checkpoint_reason"] != "clean_stop"
        ):
            _reject("pre-effect binding discriminator is invalid")
        for name in fields:
            if name.endswith("_sha256"):
                _require_sha256(fields[name], name)
        started = _require_int(
            fields["observation_started_monotonic_ns"],
            "observation_started_monotonic_ns",
        )
        completed = _require_int(
            fields["observation_completed_monotonic_ns"],
            "observation_completed_monotonic_ns",
        )
        deadline = _require_int(fields["observation_deadline_monotonic_ns"], "deadline")
        if not started <= completed < deadline:
            _reject("pre-effect binding observation interval is invalid")
        observation = LifecycleV2ADR0109ObservationPrimitives.capture(fields["adr0109_observation"])
        observation_fields = observation.to_dict()
        if (
            fields["adr0109_observation_sha256"] != observation.sha256
            or fields["provider_identity_sha256"] != observation.provider_identity_sha256
            or fields["observation_semantic_sha256"] != observation_fields["semantic_sha256"]
            or fields["adr0109_issuer_binding_sha256"]
            != observation_fields["issuer_binding_sha256"]
            or fields["adr0109_read_only_configuration_sha256"]
            != observation_fields["read_only_configuration_sha256"]
            or started != observation_fields["observation_started_monotonic_ns"]
            or completed != observation_fields["observation_completed_monotonic_ns"]
            or deadline != observation_fields["deadline_monotonic_ns"]
        ):
            _reject("pre-effect binding does not retain its exact ADR-0109 primitives")
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        return result

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def encoded(self) -> bytes:
        return canonical_v2_json_bytes(self.to_dict(), maximum_bytes=_MAXIMUM_BYTES)

    @property
    def binding_sha256(self) -> str:
        return _domain_sha256(
            "AutoQuantTrader/trusted-time/graceful-stop/pre-effect-reauthentication-binding/v2",
            self.to_dict(),
        )


_PRE_EFFECT_EVIDENCE_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "environment",
        "graceful_stop_operation_id",
        "lifecycle_root_sha256",
        "clean_stop_request_sha256",
        "clean_stop_result_sha256",
        "channel_id",
        "expected_checkpoint_reason",
        "expected_clean_stop_head_sha256",
        "expected_clean_stop_terminal_result_semantic_sha256",
        "topology_sha256",
        "topology_lease_sha256",
        "transport_quiescence_record_sha256",
        "pre_effect_intent_sha256",
        "adr0109_observation",
        "adr0109_observation_sha256",
        "provider_identity_sha256",
        "observation_semantic_sha256",
        "adr0109_issuer_binding_sha256",
        "adr0109_read_only_configuration_sha256",
        "issuer_challenge_sha256",
        "observation_started_monotonic_ns",
        "observation_completed_monotonic_ns",
        "observation_deadline_monotonic_ns",
    }
)


@dataclass(frozen=True, slots=True, init=False)
class LifecycleV2PostTeardownBindingEvidence:
    """Primitive-only durable evidence for the ordinal-twenty binding."""

    fields: FrozenJsonObject

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("post-teardown binding evidence requires the private seam")

    @classmethod
    def _capture(cls, value: object) -> Self:
        frozen = FrozenJsonObject.capture(value)
        fields = frozen.to_dict()
        _require_fields(fields, _POST_TEARDOWN_EVIDENCE_FIELDS, "post-teardown binding")
        if (
            fields["contract_version"] != LIFECYCLE_V2_POST_TEARDOWN_BINDING_CONTRACT_VERSION
            or fields["service"] != LIFECYCLE_V2_SERVICE
            or fields["status"] != "distinct_post_teardown_adr0109_observation_bound"
            or fields["expected_checkpoint_reason"] != "clean_stop"
        ):
            _reject("post-teardown binding discriminator is invalid")
        for name in fields:
            if name.endswith("_sha256"):
                _require_sha256(fields[name], name)
        started = _require_int(
            fields["observation_started_monotonic_ns"],
            "observation_started_monotonic_ns",
        )
        completed = _require_int(
            fields["observation_completed_monotonic_ns"],
            "observation_completed_monotonic_ns",
        )
        deadline = _require_int(fields["observation_deadline_monotonic_ns"], "deadline")
        if not started <= completed < deadline:
            _reject("post-teardown binding observation interval is invalid")
        observation = LifecycleV2ADR0109ObservationPrimitives.capture(fields["adr0109_observation"])
        observation_fields = observation.to_dict()
        if (
            fields["adr0109_observation_sha256"] != observation.sha256
            or fields["provider_identity_sha256"] != observation.provider_identity_sha256
            or fields["observation_semantic_sha256"] != observation_fields["semantic_sha256"]
            or fields["adr0109_issuer_binding_sha256"]
            != observation_fields["issuer_binding_sha256"]
            or fields["adr0109_read_only_configuration_sha256"]
            != observation_fields["read_only_configuration_sha256"]
            or started != observation_fields["observation_started_monotonic_ns"]
            or completed != observation_fields["observation_completed_monotonic_ns"]
            or deadline != observation_fields["deadline_monotonic_ns"]
        ):
            _reject("post-teardown binding does not retain its exact ADR-0109 primitives")
        result = object.__new__(cls)
        object.__setattr__(result, "fields", frozen)
        return result

    def to_dict(self) -> dict[str, object]:
        return self.fields.to_dict()

    @property
    def encoded(self) -> bytes:
        return canonical_v2_json_bytes(self.to_dict(), maximum_bytes=_MAXIMUM_BYTES)

    @property
    def binding_sha256(self) -> str:
        return _domain_sha256(
            "AutoQuantTrader/trusted-time/graceful-stop/post-teardown-reauthentication-binding/v2",
            self.to_dict(),
        )


_POST_TEARDOWN_EVIDENCE_FIELDS = frozenset(
    {
        "contract_version",
        "service",
        "status",
        "environment",
        "graceful_stop_operation_id",
        "lifecycle_root_sha256",
        "published_prefix_through_ordinal_18_sha256",
        "expected_checkpoint_reason",
        "expected_clean_stop_head_sha256",
        "expected_clean_stop_terminal_result_semantic_sha256",
        "pre_effect_binding_sha256",
        "supervisor_stop_result_sha256",
        "source_stop_result_sha256",
        "supervisor_remove_result_sha256",
        "source_remove_result_sha256",
        "project_network_remove_result_sha256",
        "volume_proof_sha256",
        "post_teardown_intent_sha256",
        "adr0109_observation",
        "adr0109_observation_sha256",
        "provider_identity_sha256",
        "observation_semantic_sha256",
        "adr0109_issuer_binding_sha256",
        "adr0109_read_only_configuration_sha256",
        "issuer_challenge_sha256",
        "observation_started_monotonic_ns",
        "observation_completed_monotonic_ns",
        "observation_deadline_monotonic_ns",
    }
)


class _PreEffectContext(NamedTuple):
    root: LifecycleV2Root
    request: LifecycleV2CleanStopRequest
    result: LifecycleV2CleanStopResult
    transport_quiescence: LifecycleV2ProgressRecord
    intent: LifecycleV2ProgressRecord
    intent_semantic: LifecycleV2ReauthenticationIntent


class _PostTeardownContext(NamedTuple):
    root: LifecycleV2Root
    transcript: LifecycleV2Transcript
    pre_binding: LifecycleV2PreEffectBinding
    result: LifecycleV2CleanStopResult
    result_records: tuple[LifecycleV2ProgressRecord, ...]
    intent: LifecycleV2ProgressRecord
    intent_semantic: LifecycleV2ReauthenticationIntent


class _BindingIssuerBase:
    __slots__ = (
        "__weakref__",
        "_challenge",
        "_challenge_sha256",
        "_expected_observation_issuer",
        "_owner_pid",
        "_owner_thread",
        "_realm_identity",
        "_status",
    )

    _challenge: bytearray
    _challenge_sha256: str
    _context: _PreEffectContext | _PostTeardownContext
    _expected_observation_issuer: object
    _owner_pid: int
    _owner_thread: threading.Thread
    _realm_identity: object
    _status: str

    def __new__(cls) -> Self:
        _reject("lifecycle-v2 reauthentication binding issuers require preparation")

    def __setattr__(self, _name: str, _value: object) -> Never:
        _reject("lifecycle-v2 reauthentication binding issuers are immutable")

    def __delattr__(self, _name: str) -> Never:
        _reject("lifecycle-v2 reauthentication binding issuers are immutable")

    def __copy__(self) -> Never:
        _reject("lifecycle-v2 reauthentication binding issuers cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        _reject("lifecycle-v2 reauthentication binding issuers cannot be copied")

    def __reduce__(self) -> Never:
        _reject("lifecycle-v2 reauthentication binding issuers cannot be serialized")

    def __reduce_ex__(self, _protocol: object) -> Never:
        _reject("lifecycle-v2 reauthentication binding issuers cannot be serialized")


class _LifecycleV2PreEffectBindingIssuer(_BindingIssuerBase):
    __slots__ = ("_context",)

    _context: _PreEffectContext


class _LifecycleV2PostTeardownBindingIssuer(_BindingIssuerBase):
    __slots__ = ("_context",)

    _context: _PostTeardownContext


class _BindingBase:
    __slots__ = (
        "__weakref__",
        "_evidence",
        "_issuer_identity",
        "_observation_identity",
        "_observation_issuer_identity",
        "_owner_pid",
        "_owner_thread",
        "_realm_identity",
        "_semantic_binding",
    )

    _evidence: LifecycleV2PreEffectBindingEvidence | LifecycleV2PostTeardownBindingEvidence
    _issuer_identity: object
    _observation_identity: object
    _observation_issuer_identity: object
    _owner_pid: int
    _owner_thread: threading.Thread
    _realm_identity: object
    _semantic_binding: LifecycleV2AuthenticatedReauthenticationBinding

    def __new__(cls) -> Self:
        _reject("lifecycle-v2 reauthentication bindings require a private one-shot seam")

    def __setattr__(self, _name: str, _value: object) -> Never:
        _reject("lifecycle-v2 reauthentication bindings are immutable")

    def __delattr__(self, _name: str) -> Never:
        _reject("lifecycle-v2 reauthentication bindings are immutable")

    def __copy__(self) -> Never:
        _reject("lifecycle-v2 reauthentication bindings cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        _reject("lifecycle-v2 reauthentication bindings cannot be copied")

    def __reduce__(self) -> Never:
        _reject("lifecycle-v2 reauthentication bindings cannot be serialized")

    def __reduce_ex__(self, _protocol: object) -> Never:
        _reject("lifecycle-v2 reauthentication bindings cannot be serialized")

    @property
    def lifecycle_semantic_binding(
        self,
    ) -> LifecycleV2AuthenticatedReauthenticationBinding:
        expected_type: type[LifecycleV2PreEffectBinding] | type[LifecycleV2PostTeardownBinding] = (
            LifecycleV2PreEffectBinding
            if type(self) is LifecycleV2PreEffectBinding
            else LifecycleV2PostTeardownBinding
        )
        return _require_live_binding(self, expected_type=expected_type).semantic_binding


class LifecycleV2PreEffectBinding(_BindingBase):
    """Live pre-effect seal; its durable projection grants no effect authority."""

    __slots__ = ()

    @property
    def durable_evidence(self) -> LifecycleV2PreEffectBindingEvidence:
        registration = _require_live_binding(
            self,
            expected_type=LifecycleV2PreEffectBinding,
        )
        return cast(LifecycleV2PreEffectBindingEvidence, registration.evidence)


class LifecycleV2PostTeardownBinding(_BindingBase):
    """Live post-teardown seal; it authorizes no additional effect."""

    __slots__ = ()

    @property
    def durable_evidence(self) -> LifecycleV2PostTeardownBindingEvidence:
        registration = _require_live_binding(
            self,
            expected_type=LifecycleV2PostTeardownBinding,
        )
        return cast(LifecycleV2PostTeardownBindingEvidence, registration.evidence)


_BindingEvidence = LifecycleV2PreEffectBindingEvidence | LifecycleV2PostTeardownBindingEvidence
_BindingContext = _PreEffectContext | _PostTeardownContext


class _PreEffectContextSnapshot(NamedTuple):
    root_encoded: bytes
    request_encoded: bytes
    result_encoded: bytes
    transport_quiescence_encoded: bytes
    intent_encoded: bytes
    intent_semantic_encoded: bytes


class _PostTeardownContextSnapshot(NamedTuple):
    root_encoded: bytes
    transcript_encoded: bytes
    pre_binding: LifecycleV2PreEffectBinding
    result_encoded: bytes
    result_records_encoded: tuple[bytes, ...]
    intent_encoded: bytes
    intent_semantic_encoded: bytes


_BindingContextSnapshot = _PreEffectContextSnapshot | _PostTeardownContextSnapshot


@dataclass(frozen=True, slots=True)
class _LifecycleV2ReauthenticationSemanticBindingIssuanceSnapshot:
    """Exact burned realm issuance consumed only by lifecycle semantics."""

    semantic_binding_encoded: bytes
    binding_evidence_encoded: bytes
    binding_evidence_sha256: str
    provenance: str
    root_sha256: str
    intent_semantic_sha256: str
    boundary: str

    def __post_init__(self) -> None:
        if (
            type(self.semantic_binding_encoded) is not bytes
            or not self.semantic_binding_encoded
            or len(self.semantic_binding_encoded) > _MAXIMUM_BYTES
            or type(self.binding_evidence_encoded) is not bytes
            or not self.binding_evidence_encoded
            or len(self.binding_evidence_encoded) > _MAXIMUM_BYTES
            or _SHA256.fullmatch(self.binding_evidence_sha256) is None
            or self.provenance
            not in {
                "fake_reauthentication_binding",
                "production_reauthentication_binding",
            }
            or _SHA256.fullmatch(self.root_sha256) is None
            or _SHA256.fullmatch(self.intent_semantic_sha256) is None
            or self.boundary not in {"pre_effect", "post_teardown"}
        ):
            _reject("reauthentication semantic issuance snapshot is invalid")
        semantic_fields = _canonical_object_from_encoded(self.semantic_binding_encoded)
        evidence_type: (
            type[LifecycleV2PreEffectBindingEvidence] | type[LifecycleV2PostTeardownBindingEvidence]
        ) = (
            LifecycleV2PreEffectBindingEvidence
            if self.boundary == "pre_effect"
            else LifecycleV2PostTeardownBindingEvidence
        )
        evidence = _evidence_from_encoded(
            self.binding_evidence_encoded,
            evidence_type=evidence_type,
        )
        if (
            evidence.encoded != self.binding_evidence_encoded
            or evidence.binding_sha256 != self.binding_evidence_sha256
            or semantic_fields.get("binding_evidence_sha256") != self.binding_evidence_sha256
        ):
            _reject("reauthentication semantic issuance evidence changed")


class _LifecycleV2ReauthenticationSemanticBindingIssuance:
    __slots__ = (
        "__weakref__",
        "_binding_evidence_sha256",
        "_boundary",
        "_intent_semantic_sha256",
        "_owner_pid",
        "_owner_thread",
        "_provenance",
        "_realm_identity",
        "_root_sha256",
        "_status",
    )

    _binding_evidence_sha256: str
    _boundary: str
    _intent_semantic_sha256: str
    _owner_pid: int
    _owner_thread: threading.Thread
    _provenance: str
    _realm_identity: object
    _root_sha256: str
    _status: str

    def __new__(cls) -> Self:
        _reject("reauthentication semantic binding issuances require a live realm")

    def __setattr__(self, _name: str, _value: object) -> Never:
        _reject("reauthentication semantic binding issuances are immutable")

    def __delattr__(self, _name: str) -> Never:
        _reject("reauthentication semantic binding issuances are immutable")

    def __copy__(self) -> Never:
        _reject("reauthentication semantic binding issuances cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        _reject("reauthentication semantic binding issuances cannot be copied")

    def __reduce__(self) -> Never:
        _reject("reauthentication semantic binding issuances cannot be serialized")

    def __reduce_ex__(self, _protocol: object) -> Never:
        _reject("reauthentication semantic binding issuances cannot be serialized")


@dataclass(frozen=True, slots=True)
class _IssuerAttempt:
    issuer: _BindingIssuerBase
    context: _BindingContext
    expected_observation_issuer: object
    challenge_sha256: str
    realm_identity: object
    semantic_binding_provenance: str


@dataclass(frozen=True, slots=True)
class _BindingRegistrySnapshot:
    evidence: _BindingEvidence
    semantic_binding: LifecycleV2AuthenticatedReauthenticationBinding
    context: _BindingContext
    issuer_identity: object
    observation_identity: object
    observation_issuer_identity: object
    realm_identity: object
    post_reservation_status: str


class _IssuerRegistration(NamedTuple):
    reference: weakref.ReferenceType[_BindingIssuerBase]
    issuer_type: type[_BindingIssuerBase]
    exposed_context: _BindingContext
    exposed_context_sha256: str
    context: _BindingContextSnapshot
    expected_observation_issuer: object
    challenge_encoded: bytes
    challenge_sha256: str
    owner_pid: int
    owner_thread: threading.Thread
    realm_identity: object
    semantic_binding_provenance: str
    status: str


class _BindingRegistration(NamedTuple):
    reference: weakref.ReferenceType[_BindingBase]
    binding_type: type[_BindingBase]
    exposed_evidence: _BindingEvidence
    evidence_encoded: bytes
    exposed_semantic_binding: LifecycleV2AuthenticatedReauthenticationBinding
    semantic_binding_encoded: bytes
    context: _BindingContextSnapshot
    issuer_identity: object
    observation_identity: object
    observation_issuer_identity: object
    owner_pid: int
    owner_thread: threading.Thread
    realm_identity: object
    semantic_binding_provenance: str
    status: str
    post_reservation_status: str


@dataclass(frozen=True, slots=True)
class _ExposedBindingSeal:
    evidence: _BindingEvidence
    evidence_encoded: bytes
    semantic_binding: LifecycleV2AuthenticatedReauthenticationBinding
    semantic_binding_encoded: bytes
    semantic_boundary: str
    issuer_identity: object
    observation_identity: object
    observation_issuer_identity: object
    realm_identity: object


@dataclass(frozen=True, slots=True)
class _BindingRegistryMaterial:
    binding_type: type[_BindingBase]
    evidence_encoded: bytes
    semantic_binding: LifecycleV2AuthenticatedReauthenticationBinding
    semantic_binding_encoded: bytes
    context: _BindingContext
    issuer_identity: object
    observation_identity: object
    observation_issuer_identity: object
    realm_identity: object
    semantic_binding_provenance: str
    post_reservation_status: str


class _SemanticBindingIssuanceRegistration(NamedTuple):
    reference: weakref.ReferenceType[_LifecycleV2ReauthenticationSemanticBindingIssuance]
    semantic_binding_encoded: bytes
    binding_evidence_encoded: bytes
    binding_evidence_sha256: str
    provenance: str
    root_sha256: str
    intent_semantic_sha256: str
    boundary: str
    owner_pid: int
    owner_thread: threading.Thread
    realm_identity: object
    status: str


class _RealmOperationRegistration(NamedTuple):
    token: object
    realm_permit: object
    realm_identity: object
    operation: str
    boundary: str
    subject: object
    owner_pid: int
    owner_thread: threading.Thread
    issuer_registered: bool
    candidate: _LifecycleV2ADR0109ObservationCandidate | None
    candidate_primitives_encoded: bytes | None
    candidate_issuer_identity: object | None
    candidate_observation_identity: object | None
    candidate_status: str
    semantic_registered: bool
    binding_registered: bool


def _capture_context_snapshot(value: _BindingContext) -> _BindingContextSnapshot:
    if type(value) is _PreEffectContext:
        return _PreEffectContextSnapshot(
            root_encoded=bytes(value.root.encoded),
            request_encoded=bytes(value.request.encoded),
            result_encoded=bytes(value.result.encoded),
            transport_quiescence_encoded=bytes(value.transport_quiescence.encoded),
            intent_encoded=bytes(value.intent.encoded),
            intent_semantic_encoded=bytes(value.intent_semantic.encoded),
        )
    if type(value) is _PostTeardownContext:
        return _PostTeardownContextSnapshot(
            root_encoded=bytes(value.root.encoded),
            transcript_encoded=bytes(value.transcript.encoded),
            pre_binding=value.pre_binding,
            result_encoded=bytes(value.result.encoded),
            result_records_encoded=tuple(bytes(record.encoded) for record in value.result_records),
            intent_encoded=bytes(value.intent.encoded),
            intent_semantic_encoded=bytes(value.intent_semantic.encoded),
        )
    _reject("reauthentication binding context type is invalid")


def _context_from_snapshot(value: _BindingContextSnapshot) -> _BindingContext:
    if type(value) is _PreEffectContextSnapshot:
        return _PreEffectContext(
            decode_lifecycle_v2_root(value.root_encoded),
            decode_lifecycle_v2_clean_stop_request(value.request_encoded),
            LifecycleV2CleanStopResult.capture(
                _canonical_object_from_encoded(value.result_encoded)
            ),
            decode_lifecycle_v2_progress_record(value.transport_quiescence_encoded),
            decode_lifecycle_v2_progress_record(value.intent_encoded),
            LifecycleV2ReauthenticationIntent._capture_fixed(
                _canonical_object_from_encoded(value.intent_semantic_encoded),
                boundary="pre_effect",
            ),
        )
    if type(value) is _PostTeardownContextSnapshot:
        return _PostTeardownContext(
            decode_lifecycle_v2_root(value.root_encoded),
            decode_lifecycle_v2_transcript(value.transcript_encoded),
            value.pre_binding,
            LifecycleV2CleanStopResult.capture(
                _canonical_object_from_encoded(value.result_encoded)
            ),
            tuple(
                decode_lifecycle_v2_progress_record(encoded)
                for encoded in value.result_records_encoded
            ),
            decode_lifecycle_v2_progress_record(value.intent_encoded),
            LifecycleV2ReauthenticationIntent._capture_fixed(
                _canonical_object_from_encoded(value.intent_semantic_encoded),
                boundary="post_teardown",
            ),
        )
    _reject("reauthentication binding context snapshot type is invalid")


def _clone_context(value: _BindingContext) -> _BindingContext:
    return _context_from_snapshot(_capture_context_snapshot(value))


def _context_snapshot_sha256(value: _BindingContext) -> str:
    if type(value) is _PreEffectContext:
        payload: dict[str, object] = {
            "kind": "pre_effect",
            "root_sha256": value.root.sha256,
            "request_sha256": value.request.sha256,
            "result_sha256": value.result.sha256,
            "transport_quiescence_sha256": value.transport_quiescence.sha256,
            "intent_sha256": value.intent.sha256,
            "intent_semantic_sha256": value.intent_semantic.sha256,
        }
    elif type(value) is _PostTeardownContext:
        payload = {
            "kind": "post_teardown",
            "root_sha256": value.root.sha256,
            "transcript_sha256": value.transcript.sha256,
            "pre_binding_object_identity": id(value.pre_binding),
            "result_sha256": value.result.sha256,
            "result_record_sha256_list": [record.sha256 for record in value.result_records],
            "intent_sha256": value.intent.sha256,
            "intent_semantic_sha256": value.intent_semantic.sha256,
        }
    else:
        _reject("reauthentication binding context type is invalid")
    return _domain_sha256(
        "AutoQuantTrader/trusted-time/graceful-stop/reauthentication-context-seal/v2",
        payload,
    )


def _evidence_from_encoded(
    encoded: bytes,
    *,
    evidence_type: type[LifecycleV2PreEffectBindingEvidence]
    | type[LifecycleV2PostTeardownBindingEvidence],
) -> _BindingEvidence:
    value = _canonical_object_from_encoded(encoded)
    if evidence_type is LifecycleV2PreEffectBindingEvidence:
        return LifecycleV2PreEffectBindingEvidence._capture(value)
    return LifecycleV2PostTeardownBindingEvidence._capture(value)


def _canonical_object_from_encoded(encoded: bytes) -> dict[str, object]:
    from packages.domain.trusted_time_graceful_stop_v2 import (
        decode_canonical_v2_json_object,
    )

    return decode_canonical_v2_json_object(encoded, maximum_bytes=_MAXIMUM_BYTES)


def _build_binding_registries() -> tuple[
    Callable[..., None],
    Callable[..., None],
    Callable[..., object],
    Callable[..., None],
    Callable[..., None],
    Callable[..., None],
    Callable[..., _LifecycleV2ADR0109ObservationCandidate],
    Callable[..., None],
    Callable[..., _IssuerAttempt],
    Callable[..., None],
    Callable[..., _BindingRegistrySnapshot],
    Callable[..., _BindingRegistrySnapshot],
    Callable[..., _LifecycleV2ReauthenticationSemanticBindingIssuance],
    Callable[..., _LifecycleV2ReauthenticationSemanticBindingIssuanceSnapshot],
]:
    """Keep all live issuance state outside caller-mutable Python objects."""

    getpid = os.getpid
    current_thread = threading.current_thread
    origin_pid = getpid()
    registry_lock = threading.Lock()
    require_observation_candidate = _require_observation_candidate  # noqa: F821 - install-time capture
    realm_permit_state: tuple[tuple[int, tuple[object, object, str]], ...] = ()
    issuer_state: tuple[tuple[int, _IssuerRegistration], ...] = ()
    binding_state: tuple[tuple[int, _BindingRegistration], ...] = ()
    semantic_issuance_state: tuple[tuple[int, _SemanticBindingIssuanceRegistration], ...] = ()
    operation_state: tuple[tuple[int, _RealmOperationRegistration], ...] = ()

    def state_get(
        state: tuple[tuple[int, _StateValue], ...],
        key: int,
    ) -> _StateValue | None:
        return next((value for candidate, value in state if candidate == key), None)

    def state_store(
        state: tuple[tuple[int, _StateValue], ...],
        key: int,
        value: _StateValue,
    ) -> tuple[tuple[int, _StateValue], ...]:
        return (*((candidate, item) for candidate, item in state if candidate != key), (key, value))

    def state_remove(
        state: tuple[tuple[int, _StateValue], ...],
        key: int,
    ) -> tuple[tuple[int, _StateValue], ...]:
        return tuple((candidate, item) for candidate, item in state if candidate != key)

    # Capture the exact issuance and snapshot classes inside the registry realm.
    # Later module-global replacement must not redirect either construction or
    # the lifecycle installer's already captured consumer/type pair.
    semantic_issuance_type = _LifecycleV2ReauthenticationSemanticBindingIssuance
    semantic_issuance_snapshot_type = _LifecycleV2ReauthenticationSemanticBindingIssuanceSnapshot
    fake_semantic_binding_provenance = _FAKE_REAUTHENTICATION_BINDING_PROVENANCE  # noqa: F821 - install-time capture
    production_semantic_binding_provenance = _PRODUCTION_REAUTHENTICATION_BINDING_PROVENANCE  # noqa: F821 - install-time capture
    semantic_binding_provenances = frozenset(
        {
            fake_semantic_binding_provenance,
            production_semantic_binding_provenance,
        }
    )
    get_call_frame = sys._getframe
    realm_constructor_code: CodeType | None = None
    issuer_initializer_code: CodeType | None = None
    begin_issuer_codes: frozenset[CodeType] = frozenset()
    binding_issuer_code: CodeType | None = None
    pre_binding_reservation_code: CodeType | None = None
    semantic_registration_code: CodeType | None = None
    semantic_consumer_code: CodeType | None = None
    prepare_pre_wrapper_code: CodeType | None = None
    prepare_post_wrapper_code: CodeType | None = None
    bind_pre_wrapper_code: CodeType | None = None
    bind_post_wrapper_code: CodeType | None = None
    observation_authenticator_code: CodeType | None = None
    prepare_pre_helper_code: CodeType | None = None
    prepare_post_helper_code: CodeType | None = None
    bind_pre_helper_code: CodeType | None = None
    bind_post_helper_code: CodeType | None = None
    semantic_wrapper_code: CodeType | None = None

    def configure_registry_callers(
        *,
        realm_constructor: CodeType,
        issuer_initializer: CodeType,
        issuer_beginners: tuple[CodeType, ...],
        binding_issuer: CodeType,
        pre_binding_reservation: CodeType,
        semantic_registration: CodeType,
        semantic_consumer: CodeType,
        prepare_pre_wrapper: CodeType,
        prepare_post_wrapper: CodeType,
        bind_pre_wrapper: CodeType,
        bind_post_wrapper: CodeType,
        observation_authenticator: CodeType,
        prepare_pre_helper: CodeType,
        prepare_post_helper: CodeType,
        bind_pre_helper: CodeType,
        bind_post_helper: CodeType,
        semantic_wrapper: CodeType,
    ) -> None:
        nonlocal realm_constructor_code
        nonlocal issuer_initializer_code
        nonlocal begin_issuer_codes
        nonlocal binding_issuer_code
        nonlocal pre_binding_reservation_code
        nonlocal semantic_registration_code
        nonlocal semantic_consumer_code
        nonlocal prepare_pre_wrapper_code
        nonlocal prepare_post_wrapper_code
        nonlocal bind_pre_wrapper_code
        nonlocal bind_post_wrapper_code
        nonlocal observation_authenticator_code
        nonlocal prepare_pre_helper_code
        nonlocal prepare_post_helper_code
        nonlocal bind_pre_helper_code
        nonlocal bind_post_helper_code
        nonlocal semantic_wrapper_code
        code_values = (
            realm_constructor,
            issuer_initializer,
            *issuer_beginners,
            binding_issuer,
            pre_binding_reservation,
            semantic_registration,
            semantic_consumer,
            prepare_pre_wrapper,
            prepare_post_wrapper,
            bind_pre_wrapper,
            bind_post_wrapper,
            observation_authenticator,
            prepare_pre_helper,
            prepare_post_helper,
            bind_pre_helper,
            bind_post_helper,
            semantic_wrapper,
        )
        if (
            realm_constructor_code is not None
            or not issuer_beginners
            or any(type(value) is not CodeType for value in code_values)
        ):
            _reject("lifecycle-v2 reauthentication realm constructor is invalid")
        realm_constructor_code = realm_constructor
        issuer_initializer_code = issuer_initializer
        begin_issuer_codes = frozenset(issuer_beginners)
        binding_issuer_code = binding_issuer
        pre_binding_reservation_code = pre_binding_reservation
        semantic_registration_code = semantic_registration
        semantic_consumer_code = semantic_consumer
        prepare_pre_wrapper_code = prepare_pre_wrapper
        prepare_post_wrapper_code = prepare_post_wrapper
        bind_pre_wrapper_code = bind_pre_wrapper
        bind_post_wrapper_code = bind_post_wrapper
        observation_authenticator_code = observation_authenticator
        prepare_pre_helper_code = prepare_pre_helper
        prepare_post_helper_code = prepare_post_helper
        bind_pre_helper_code = bind_pre_helper
        bind_post_helper_code = bind_post_helper
        semantic_wrapper_code = semantic_wrapper

    def register_realm(
        realm_permit: object,
        *,
        realm_identity: object,
        semantic_binding_provenance: str,
    ) -> None:
        nonlocal realm_permit_state
        caller = get_call_frame(1)
        try:
            if caller.f_code is not realm_constructor_code:
                _reject("lifecycle-v2 reauthentication realm caller is invalid")
        finally:
            del caller
        if (
            getpid() != origin_pid
            or realm_permit is None
            or realm_identity is None
            or semantic_binding_provenance not in semantic_binding_provenances
        ):
            _reject("lifecycle-v2 reauthentication realm registration is invalid")
        with registry_lock:
            if state_get(realm_permit_state, id(realm_permit)) is not None:
                _reject("lifecycle-v2 reauthentication realm registration replayed")
            realm_permit_state = state_store(
                realm_permit_state,
                id(realm_permit),
                (
                    realm_permit,
                    realm_identity,
                    semantic_binding_provenance,
                ),
            )

    def require_realm_permit(
        realm_permit: object,
        *,
        realm_identity: object,
    ) -> str:
        if getpid() != origin_pid:
            _reject("lifecycle-v2 reauthentication realm crossed its process")
        registration = state_get(realm_permit_state, id(realm_permit))
        if (
            registration is None
            or registration[0] is not realm_permit
            or registration[1] is not realm_identity
        ):
            _reject("lifecycle-v2 reauthentication realm permit is invalid")
        return registration[2]

    def expected_operation_wrapper(
        *,
        operation: str,
        boundary: str,
    ) -> CodeType | None:
        if operation == "prepare" and boundary == "pre_effect":
            return prepare_pre_wrapper_code
        if operation == "prepare" and boundary == "post_teardown":
            return prepare_post_wrapper_code
        if operation == "bind" and boundary == "pre_effect":
            return bind_pre_wrapper_code
        if operation == "bind" and boundary == "post_teardown":
            return bind_post_wrapper_code
        return None

    def expected_prepare_helper(boundary: str) -> CodeType | None:
        if boundary == "pre_effect":
            return prepare_pre_helper_code
        if boundary == "post_teardown":
            return prepare_post_helper_code
        return None

    def expected_bind_helper(boundary: str) -> CodeType | None:
        if boundary == "pre_effect":
            return bind_pre_helper_code
        if boundary == "post_teardown":
            return bind_post_helper_code
        return None

    def require_exact_call_chain(*expected_codes: CodeType | None) -> None:
        if any(code is None for code in expected_codes):
            _reject("lifecycle-v2 reauthentication call chain is invalid")
        frames: list[FrameType] = []
        try:
            for depth, expected_code in enumerate(expected_codes, start=2):
                frame = get_call_frame(depth)
                frames.append(frame)
                if frame.f_code is not expected_code:
                    _reject("lifecycle-v2 reauthentication call chain is invalid")
        finally:
            frames.clear()

    def begin_realm_operation(
        *,
        realm_permit: object,
        realm_identity: object,
        operation: str,
        boundary: str,
        subject: object,
    ) -> object:
        nonlocal operation_state
        caller = get_call_frame(1)
        try:
            expected_caller = expected_operation_wrapper(
                operation=operation,
                boundary=boundary,
            )
            if expected_caller is None or caller.f_code is not expected_caller:
                _reject("lifecycle-v2 reauthentication operation caller is invalid")
        finally:
            del caller
        require_realm_permit(
            realm_permit,
            realm_identity=realm_identity,
        )
        if getpid() != origin_pid or subject is None:
            _reject("lifecycle-v2 reauthentication operation is invalid")
        token = object()
        registration = _RealmOperationRegistration(
            token=token,
            realm_permit=realm_permit,
            realm_identity=realm_identity,
            operation=operation,
            boundary=boundary,
            subject=subject,
            owner_pid=getpid(),
            owner_thread=current_thread(),
            issuer_registered=False,
            candidate=None,
            candidate_primitives_encoded=None,
            candidate_issuer_identity=None,
            candidate_observation_identity=None,
            candidate_status="absent",
            semantic_registered=False,
            binding_registered=False,
        )
        with registry_lock:
            if state_get(operation_state, id(token)) is not None:
                _reject("lifecycle-v2 reauthentication operation token replayed")
            operation_state = state_store(operation_state, id(token), registration)
        return token

    def require_operation_locked(
        token: object,
        *,
        realm_permit: object,
        realm_identity: object,
        operation: str,
        boundary: str,
        subject: object | None = None,
    ) -> _RealmOperationRegistration:
        registration = state_get(operation_state, id(token))
        if (
            getpid() != origin_pid
            or registration is None
            or registration.token is not token
            or registration.realm_permit is not realm_permit
            or registration.realm_identity is not realm_identity
            or registration.operation != operation
            or registration.boundary != boundary
            or registration.owner_pid != getpid()
            or registration.owner_thread is not current_thread()
            or (subject is not None and registration.subject is not subject)
        ):
            _reject("lifecycle-v2 reauthentication operation token is invalid")
        return registration

    def close_realm_operation(
        token: object,
        *,
        realm_permit: object,
        realm_identity: object,
        operation: str,
        boundary: str,
        subject: object,
        succeeded: bool,
    ) -> None:
        nonlocal operation_state
        caller = get_call_frame(1)
        try:
            expected_caller = expected_operation_wrapper(
                operation=operation,
                boundary=boundary,
            )
            if expected_caller is None or caller.f_code is not expected_caller:
                _reject("lifecycle-v2 reauthentication operation closer is invalid")
        finally:
            del caller
        with registry_lock:
            registration = require_operation_locked(
                token,
                realm_permit=realm_permit,
                realm_identity=realm_identity,
                operation=operation,
                boundary=boundary,
                subject=subject,
            )
            complete = (
                registration.issuer_registered
                if operation == "prepare"
                else (
                    registration.candidate_status == "consumed"
                    and registration.semantic_registered
                    and registration.binding_registered
                )
            )
            operation_state = state_remove(operation_state, id(token))
        if succeeded and not complete:
            _reject("lifecycle-v2 reauthentication operation was incomplete")

    def authorize_observation_authentication(
        token: object,
        *,
        realm_permit: object,
        realm_identity: object,
        boundary: str,
        issuer: object,
    ) -> None:
        caller = get_call_frame(1)
        try:
            if caller.f_code is not observation_authenticator_code:
                _reject("ADR-0109 observation authentication caller is invalid")
        finally:
            del caller
        require_exact_call_chain(
            observation_authenticator_code,
            expected_bind_helper(boundary),
            expected_operation_wrapper(operation="bind", boundary=boundary),
        )
        with registry_lock:
            registration = require_operation_locked(
                token,
                realm_permit=realm_permit,
                realm_identity=realm_identity,
                operation="bind",
                boundary=boundary,
                subject=issuer,
            )
            if registration.candidate_status != "absent":
                _reject("authenticated ADR-0109 observation was replayed")

    def authorize_issuer_initialization(
        token: object,
        *,
        realm_permit: object,
        realm_identity: object,
        boundary: str,
    ) -> None:
        caller = get_call_frame(1)
        try:
            if caller.f_code is not issuer_initializer_code:
                _reject("lifecycle-v2 reauthentication issuer initializer is invalid")
        finally:
            del caller
        require_exact_call_chain(
            issuer_initializer_code,
            expected_prepare_helper(boundary),
            expected_operation_wrapper(operation="prepare", boundary=boundary),
        )
        with registry_lock:
            registration = require_operation_locked(
                token,
                realm_permit=realm_permit,
                realm_identity=realm_identity,
                operation="prepare",
                boundary=boundary,
            )
            if registration.issuer_registered:
                _reject("lifecycle-v2 reauthentication issuer initialization replayed")

    def register_authenticated_observation(
        token: object,
        *,
        realm_permit: object,
        realm_identity: object,
        boundary: str,
        issuer: object,
        authenticated: _LifecycleV2ADR0109ObservationCandidate,
    ) -> _LifecycleV2ADR0109ObservationCandidate:
        nonlocal operation_state
        caller = get_call_frame(1)
        try:
            if caller.f_code is not observation_authenticator_code:
                _reject("ADR-0109 observation registration caller is invalid")
        finally:
            del caller
        require_exact_call_chain(
            observation_authenticator_code,
            expected_bind_helper(boundary),
            expected_operation_wrapper(operation="bind", boundary=boundary),
        )
        canonical = require_observation_candidate(authenticated)
        primitives_encoded = canonical.primitives.encoded
        with registry_lock:
            operation_registration = require_operation_locked(
                token,
                realm_permit=realm_permit,
                realm_identity=realm_identity,
                operation="bind",
                boundary=boundary,
                subject=issuer,
            )
            issuer_registration = state_get(issuer_state, id(issuer))
            if (
                operation_registration.candidate_status != "absent"
                or issuer_registration is None
                or issuer_registration.reference() is not issuer
                or issuer_registration.realm_identity is not realm_identity
                or issuer_registration.status != "consumed"
                or canonical.issuer_identity is not issuer_registration.expected_observation_issuer
            ):
                _reject("authenticated ADR-0109 observation is not bound to the issuer")
            operation_state = state_store(
                operation_state,
                id(token),
                operation_registration._replace(
                    candidate=canonical,
                    candidate_primitives_encoded=primitives_encoded,
                    candidate_issuer_identity=canonical.issuer_identity,
                    candidate_observation_identity=canonical.observation_identity,
                    candidate_status="registered",
                ),
            )
        return canonical

    def _precheck_issuer(
        value: object,
        *,
        expected_type: type[_BindingIssuerBase],
        realm_identity: object,
    ) -> _BindingIssuerBase:
        if getpid() != origin_pid or type(value) is not expected_type:
            _reject("lifecycle-v2 reauthentication issuer crossed its process")
        issuer = value
        try:
            if (
                issuer._owner_pid != getpid()
                or issuer._owner_thread is not current_thread()
                or issuer._realm_identity is not realm_identity
            ):
                raise ValueError
        except Exception:
            _reject("lifecycle-v2 reauthentication issuer crossed its process or thread")
        return issuer

    def _precheck_binding(
        value: object,
        *,
        expected_type: type[_BindingBase],
        realm_identity: object | None,
    ) -> _BindingBase:
        if getpid() != origin_pid or type(value) is not expected_type:
            _reject("lifecycle-v2 reauthentication binding crossed its process")
        binding = value
        try:
            if (
                binding._owner_pid != getpid()
                or binding._owner_thread is not current_thread()
                or (realm_identity is not None and binding._realm_identity is not realm_identity)
            ):
                raise ValueError
        except Exception:
            _reject("lifecycle-v2 reauthentication binding crossed its process or thread")
        return binding

    def capture_exposed_binding_seal(
        binding: _BindingBase,
        *,
        expected_type: type[_BindingBase],
    ) -> _ExposedBindingSeal | None:
        evidence_type: (
            type[LifecycleV2PreEffectBindingEvidence] | type[LifecycleV2PostTeardownBindingEvidence]
        ) = (
            LifecycleV2PreEffectBindingEvidence
            if expected_type is LifecycleV2PreEffectBinding
            else LifecycleV2PostTeardownBindingEvidence
        )
        try:
            evidence = binding._evidence
            semantic_binding = binding._semantic_binding
            if (
                type(evidence) is not evidence_type
                or type(semantic_binding) is not LifecycleV2AuthenticatedReauthenticationBinding
            ):
                raise ValueError
            return _ExposedBindingSeal(
                evidence=evidence,
                evidence_encoded=bytes(evidence.encoded),
                semantic_binding=semantic_binding,
                semantic_binding_encoded=bytes(semantic_binding.encoded),
                semantic_boundary=semantic_binding.boundary,
                issuer_identity=binding._issuer_identity,
                observation_identity=binding._observation_identity,
                observation_issuer_identity=binding._observation_issuer_identity,
                realm_identity=binding._realm_identity,
            )
        except Exception:
            return None

    def register_issuer(
        issuer: _BindingIssuerBase,
        *,
        operation_token: object,
        realm_permit: object,
        issuer_type: type[_BindingIssuerBase],
        context: _BindingContext,
        expected_observation_issuer: object,
        challenge: bytearray,
        challenge_sha256: str,
        realm_identity: object,
    ) -> None:
        nonlocal operation_state
        nonlocal issuer_state
        caller = get_call_frame(1)
        try:
            if caller.f_code is not issuer_initializer_code:
                _reject("lifecycle-v2 reauthentication issuer caller is invalid")
        finally:
            del caller
        semantic_binding_provenance = require_realm_permit(
            realm_permit,
            realm_identity=realm_identity,
        )
        if (
            getpid() != origin_pid
            or type(issuer) is not issuer_type
            or type(challenge) is not bytearray
            or len(challenge) != 32
            or _sha256(bytes(challenge)) != challenge_sha256
        ):
            _reject("lifecycle-v2 reauthentication issuer registration is invalid")
        issuer_id = id(issuer)
        boundary = (
            "pre_effect"
            if issuer_type is _LifecycleV2PreEffectBindingIssuer
            else "post_teardown"
            if issuer_type is _LifecycleV2PostTeardownBindingIssuer
            else ""
        )
        require_exact_call_chain(
            issuer_initializer_code,
            expected_prepare_helper(boundary),
            expected_operation_wrapper(operation="prepare", boundary=boundary),
        )

        def issuer_lost(reference: weakref.ReferenceType[_BindingIssuerBase]) -> None:
            nonlocal issuer_state
            if getpid() != origin_pid or reference() is not None:
                return
            with registry_lock:
                current = state_get(issuer_state, issuer_id)
                if current is not None and current.reference is reference:
                    issuer_state = state_remove(issuer_state, issuer_id)

        registration = _IssuerRegistration(
            reference=weakref.ref(issuer, issuer_lost),
            issuer_type=issuer_type,
            exposed_context=context,
            exposed_context_sha256=_context_snapshot_sha256(context),
            context=_capture_context_snapshot(context),
            expected_observation_issuer=expected_observation_issuer,
            challenge_encoded=bytes(challenge),
            challenge_sha256=challenge_sha256,
            owner_pid=getpid(),
            owner_thread=current_thread(),
            realm_identity=realm_identity,
            semantic_binding_provenance=semantic_binding_provenance,
            status="prepared",
        )
        with registry_lock:
            operation_registration = require_operation_locked(
                operation_token,
                realm_permit=realm_permit,
                realm_identity=realm_identity,
                operation="prepare",
                boundary=boundary,
            )
            if (
                operation_registration.issuer_registered
                or state_get(issuer_state, issuer_id) is not None
            ):
                _reject("lifecycle-v2 reauthentication issuer registration replayed")
            issuer_state = state_store(issuer_state, issuer_id, registration)
            operation_state = state_store(
                operation_state,
                id(operation_token),
                operation_registration._replace(issuer_registered=True),
            )

    def begin_issuer_once(
        value: object,
        *,
        operation_token: object,
        operation: str,
        boundary: str,
        realm_permit: object,
        expected_type: type[_BindingIssuerBase],
        realm_identity: object,
    ) -> _IssuerAttempt:
        nonlocal issuer_state
        caller = get_call_frame(1)
        try:
            if caller.f_code not in begin_issuer_codes:
                _reject("lifecycle-v2 reauthentication issuer begin caller is invalid")
        finally:
            del caller
        operation_helper_code = (
            expected_bind_helper(boundary)
            if operation == "bind"
            else expected_prepare_helper(boundary)
        )
        require_exact_call_chain(
            operation_helper_code,
            expected_operation_wrapper(operation=operation, boundary=boundary),
        )
        semantic_binding_provenance = require_realm_permit(
            realm_permit,
            realm_identity=realm_identity,
        )
        issuer = _precheck_issuer(
            value,
            expected_type=expected_type,
            realm_identity=realm_identity,
        )
        try:
            exposed_context_sha256 = _context_snapshot_sha256(issuer._context)
        except Exception:
            exposed_context_sha256 = None
        invalid = False
        with registry_lock:
            require_operation_locked(
                operation_token,
                realm_permit=realm_permit,
                realm_identity=realm_identity,
                operation=operation,
                boundary=boundary,
                subject=issuer if operation == "bind" else None,
            )
            registration = state_get(issuer_state, id(issuer))
            if (
                registration is None
                or registration.reference() is not issuer
                or registration.issuer_type is not expected_type
                or registration.owner_pid != getpid()
                or registration.owner_thread is not current_thread()
                or registration.realm_identity is not realm_identity
                or registration.semantic_binding_provenance != semantic_binding_provenance
                or registration.status != "prepared"
            ):
                _reject("lifecycle-v2 reauthentication binding issuer was replayed")
            try:
                invalid = (
                    type(issuer._challenge) is not bytearray
                    or bytes(issuer._challenge) != registration.challenge_encoded
                    or issuer._challenge_sha256 != registration.challenge_sha256
                    or issuer._expected_observation_issuer
                    is not registration.expected_observation_issuer
                    or issuer._status != "prepared"
                    or issuer._context is not registration.exposed_context
                    or exposed_context_sha256 != registration.exposed_context_sha256
                    or len(registration.challenge_encoded) != 32
                    or _sha256(registration.challenge_encoded) != registration.challenge_sha256
                )
            except Exception:
                invalid = True
            issuer_state = state_store(
                issuer_state,
                id(issuer),
                registration._replace(status="consumed"),
            )
            object.__setattr__(issuer, "_status", "consumed")
            raw_challenge = getattr(issuer, "_challenge", None)
            if type(raw_challenge) is bytearray:
                for index in range(len(raw_challenge)):
                    raw_challenge[index] = 0
                raw_challenge.clear()
            registered_context = registration.context
            expected_observation_issuer = registration.expected_observation_issuer
            challenge_sha256 = registration.challenge_sha256
        if invalid:
            _reject("lifecycle-v2 reauthentication issuer seal changed")
        return _IssuerAttempt(
            issuer=issuer,
            context=_context_from_snapshot(registered_context),
            expected_observation_issuer=expected_observation_issuer,
            challenge_sha256=challenge_sha256,
            realm_identity=realm_identity,
            semantic_binding_provenance=semantic_binding_provenance,
        )

    def register_binding(
        binding: _BindingBase,
        *,
        operation_token: object,
        realm_permit: object,
        binding_type: type[_BindingBase],
        evidence: _BindingEvidence,
        semantic_binding: LifecycleV2AuthenticatedReauthenticationBinding,
        context: _BindingContext,
        issuer_identity: object,
        observation_identity: object,
        observation_issuer_identity: object,
        realm_identity: object,
    ) -> None:
        nonlocal operation_state
        nonlocal binding_state
        caller = get_call_frame(1)
        try:
            if caller.f_code is not binding_issuer_code:
                _reject("lifecycle-v2 reauthentication binding caller is invalid")
        finally:
            del caller
        semantic_binding_provenance = require_realm_permit(
            realm_permit,
            realm_identity=realm_identity,
        )
        if (
            getpid() != origin_pid
            or type(binding) is not binding_type
            or type(semantic_binding) is not LifecycleV2AuthenticatedReauthenticationBinding
        ):
            _reject("lifecycle-v2 reauthentication binding registration is invalid")
        semantic_binding._require_sealed()
        binding_id = id(binding)
        boundary = (
            "pre_effect"
            if binding_type is LifecycleV2PreEffectBinding
            else "post_teardown"
            if binding_type is LifecycleV2PostTeardownBinding
            else ""
        )
        require_exact_call_chain(
            binding_issuer_code,
            expected_bind_helper(boundary),
            expected_operation_wrapper(operation="bind", boundary=boundary),
        )

        def binding_lost(reference: weakref.ReferenceType[_BindingBase]) -> None:
            nonlocal binding_state
            if getpid() != origin_pid or reference() is not None:
                return
            with registry_lock:
                current = state_get(binding_state, binding_id)
                if current is not None and current.reference is reference:
                    binding_state = state_remove(binding_state, binding_id)

        registration = _BindingRegistration(
            reference=weakref.ref(binding, binding_lost),
            binding_type=binding_type,
            exposed_evidence=evidence,
            evidence_encoded=bytes(evidence.encoded),
            exposed_semantic_binding=semantic_binding,
            semantic_binding_encoded=bytes(semantic_binding.encoded),
            context=_capture_context_snapshot(context),
            issuer_identity=issuer_identity,
            observation_identity=observation_identity,
            observation_issuer_identity=observation_issuer_identity,
            owner_pid=getpid(),
            owner_thread=current_thread(),
            realm_identity=realm_identity,
            semantic_binding_provenance=semantic_binding_provenance,
            status="live",
            post_reservation_status=(
                "available" if binding_type is LifecycleV2PreEffectBinding else "not_applicable"
            ),
        )
        with registry_lock:
            operation_registration = require_operation_locked(
                operation_token,
                realm_permit=realm_permit,
                realm_identity=realm_identity,
                operation="bind",
                boundary=boundary,
                subject=issuer_identity,
            )
            if (
                state_get(binding_state, binding_id) is not None
                or operation_registration.candidate_status != "consumed"
                or not operation_registration.semantic_registered
                or operation_registration.binding_registered
                or operation_registration.candidate_issuer_identity
                is not observation_issuer_identity
                or operation_registration.candidate_observation_identity is not observation_identity
            ):
                _reject("lifecycle-v2 reauthentication binding registration replayed")
            binding_state = state_store(binding_state, binding_id, registration)
            operation_state = state_store(
                operation_state,
                id(operation_token),
                operation_registration._replace(binding_registered=True),
            )

    def _binding_snapshot_locked(
        registration: _BindingRegistration,
        exposed: _ExposedBindingSeal | None,
    ) -> _BindingRegistryMaterial:
        nonlocal binding_state
        valid = (
            exposed is not None
            and exposed.evidence is registration.exposed_evidence
            and exposed.evidence_encoded == registration.evidence_encoded
            and exposed.semantic_binding is registration.exposed_semantic_binding
            and exposed.semantic_binding_encoded == registration.semantic_binding_encoded
            and exposed.semantic_boundary
            == (
                "pre_effect"
                if registration.binding_type is LifecycleV2PreEffectBinding
                else "post_teardown"
            )
            and exposed.issuer_identity is registration.issuer_identity
            and exposed.observation_identity is registration.observation_identity
            and exposed.observation_issuer_identity is registration.observation_issuer_identity
            and exposed.realm_identity is registration.realm_identity
        )
        if not valid:
            binding = registration.reference()
            if binding is not None and state_get(binding_state, id(binding)) is registration:
                binding_state = state_store(
                    binding_state,
                    id(binding),
                    registration._replace(status="revoked"),
                )
            _reject("lifecycle-v2 reauthentication binding seal changed")
        return _BindingRegistryMaterial(
            binding_type=registration.binding_type,
            evidence_encoded=registration.evidence_encoded,
            semantic_binding=registration.exposed_semantic_binding,
            semantic_binding_encoded=registration.semantic_binding_encoded,
            context=_context_from_snapshot(registration.context),
            issuer_identity=registration.issuer_identity,
            observation_identity=registration.observation_identity,
            observation_issuer_identity=registration.observation_issuer_identity,
            realm_identity=registration.realm_identity,
            semantic_binding_provenance=registration.semantic_binding_provenance,
            post_reservation_status=registration.post_reservation_status,
        )

    def materialize_binding_snapshot(
        material: _BindingRegistryMaterial,
    ) -> _BindingRegistrySnapshot:
        evidence_type: (
            type[LifecycleV2PreEffectBindingEvidence] | type[LifecycleV2PostTeardownBindingEvidence]
        ) = (
            LifecycleV2PreEffectBindingEvidence
            if material.binding_type is LifecycleV2PreEffectBinding
            else LifecycleV2PostTeardownBindingEvidence
        )
        evidence = _evidence_from_encoded(
            material.evidence_encoded,
            evidence_type=evidence_type,
        )
        context = _clone_context(material.context)
        semantic_binding = material.semantic_binding
        semantic_binding._require_sealed()
        if bytes(semantic_binding.encoded) != material.semantic_binding_encoded:
            _reject("lifecycle-v2 reauthentication semantic binding changed")
        return _BindingRegistrySnapshot(
            evidence=evidence,
            semantic_binding=semantic_binding,
            context=context,
            issuer_identity=material.issuer_identity,
            observation_identity=material.observation_identity,
            observation_issuer_identity=material.observation_issuer_identity,
            realm_identity=material.realm_identity,
            post_reservation_status=material.post_reservation_status,
        )

    def require_binding(
        value: object,
        *,
        expected_type: type[_BindingBase],
        realm_identity: object | None = None,
    ) -> _BindingRegistrySnapshot:
        binding = _precheck_binding(
            value,
            expected_type=expected_type,
            realm_identity=realm_identity,
        )
        exposed = capture_exposed_binding_seal(
            binding,
            expected_type=expected_type,
        )
        with registry_lock:
            registration = state_get(binding_state, id(binding))
            if (
                registration is None
                or registration.reference() is not binding
                or registration.binding_type is not expected_type
                or registration.owner_pid != getpid()
                or registration.owner_thread is not current_thread()
                or registration.status != "live"
                or (
                    realm_identity is not None and registration.realm_identity is not realm_identity
                )
            ):
                _reject("lifecycle-v2 reauthentication binding is not registered")
            material = _binding_snapshot_locked(registration, exposed)
        return materialize_binding_snapshot(material)

    def reserve_pre_binding_for_post(
        value: object,
        *,
        operation_token: object,
        realm_permit: object,
        realm_identity: object,
    ) -> _BindingRegistrySnapshot:
        nonlocal binding_state
        caller = get_call_frame(1)
        try:
            if caller.f_code is not pre_binding_reservation_code:
                _reject("pre-effect binding reservation caller is invalid")
        finally:
            del caller
        require_exact_call_chain(
            prepare_post_helper_code,
            prepare_post_wrapper_code,
        )
        semantic_binding_provenance = require_realm_permit(
            realm_permit,
            realm_identity=realm_identity,
        )
        binding = _precheck_binding(
            value,
            expected_type=LifecycleV2PreEffectBinding,
            realm_identity=realm_identity,
        )
        exposed = capture_exposed_binding_seal(
            binding,
            expected_type=LifecycleV2PreEffectBinding,
        )
        with registry_lock:
            require_operation_locked(
                operation_token,
                realm_permit=realm_permit,
                realm_identity=realm_identity,
                operation="prepare",
                boundary="post_teardown",
            )
            registration = state_get(binding_state, id(binding))
            if (
                registration is None
                or registration.reference() is not binding
                or registration.binding_type is not LifecycleV2PreEffectBinding
                or registration.realm_identity is not realm_identity
                or registration.semantic_binding_provenance != semantic_binding_provenance
                or registration.status != "live"
                or registration.post_reservation_status != "available"
            ):
                _reject("pre-effect binding was already reserved for post-teardown")
            registration = registration._replace(post_reservation_status="post_reserved")
            binding_state = state_store(binding_state, id(binding), registration)
            material = _binding_snapshot_locked(registration, exposed)
        return materialize_binding_snapshot(material)

    def register_semantic_binding_issuance(
        *,
        operation_token: object,
        realm_permit: object,
        realm_identity: object,
        issuer: object,
        authenticated: _LifecycleV2ADR0109ObservationCandidate,
        semantic_binding_encoded: bytes,
        binding_evidence_encoded: bytes,
        binding_evidence_sha256: str,
        root: LifecycleV2Root,
        intent: LifecycleV2ReauthenticationIntent,
    ) -> _LifecycleV2ReauthenticationSemanticBindingIssuance:
        nonlocal operation_state
        nonlocal semantic_issuance_state
        caller = get_call_frame(1)
        try:
            if caller.f_code is not semantic_registration_code:
                _reject("reauthentication semantic issuance caller is invalid")
        finally:
            del caller
        provenance = require_realm_permit(
            realm_permit,
            realm_identity=realm_identity,
        )
        exact_root = _require_exact_root(root)
        if type(intent) is not LifecycleV2ReauthenticationIntent:
            _reject("reauthentication semantic issuance intent type is not exact")
        intent._require_canonical_seal()
        if (
            type(semantic_binding_encoded) is not bytes
            or not semantic_binding_encoded
            or len(semantic_binding_encoded) > _MAXIMUM_BYTES
            or type(binding_evidence_encoded) is not bytes
            or not binding_evidence_encoded
            or len(binding_evidence_encoded) > _MAXIMUM_BYTES
            or type(binding_evidence_sha256) is not str
            or _SHA256.fullmatch(binding_evidence_sha256) is None
            or (provenance == fake_semantic_binding_provenance and exact_root.environment != "test")
        ):
            _reject("reauthentication semantic issuance registration is invalid")
        semantic_fields = _canonical_object_from_encoded(semantic_binding_encoded)
        evidence_type: (
            type[LifecycleV2PreEffectBindingEvidence] | type[LifecycleV2PostTeardownBindingEvidence]
        ) = (
            LifecycleV2PreEffectBindingEvidence
            if intent.boundary == "pre_effect"
            else LifecycleV2PostTeardownBindingEvidence
        )
        binding_evidence = _evidence_from_encoded(
            binding_evidence_encoded,
            evidence_type=evidence_type,
        )
        if (
            binding_evidence.encoded != binding_evidence_encoded
            or binding_evidence.binding_sha256 != binding_evidence_sha256
            or semantic_fields.get("binding_evidence_sha256") != binding_evidence_sha256
        ):
            _reject("reauthentication semantic issuance evidence changed")
        root_sha256 = exact_root.sha256
        intent_semantic_sha256 = intent.sha256
        boundary = intent.boundary
        require_exact_call_chain(
            semantic_registration_code,
            semantic_wrapper_code,
            expected_bind_helper(boundary),
            expected_operation_wrapper(operation="bind", boundary=boundary),
        )
        canonical_authenticated = require_observation_candidate(authenticated)
        issuance = object.__new__(semantic_issuance_type)
        object.__setattr__(
            issuance,
            "_binding_evidence_sha256",
            binding_evidence_sha256,
        )
        object.__setattr__(issuance, "_boundary", boundary)
        object.__setattr__(
            issuance,
            "_intent_semantic_sha256",
            intent_semantic_sha256,
        )
        object.__setattr__(issuance, "_owner_pid", getpid())
        object.__setattr__(
            issuance,
            "_owner_thread",
            current_thread(),
        )
        object.__setattr__(issuance, "_provenance", provenance)
        object.__setattr__(issuance, "_realm_identity", realm_identity)
        object.__setattr__(issuance, "_root_sha256", root_sha256)
        object.__setattr__(issuance, "_status", "prepared")
        issuance_id = id(issuance)

        def issuance_lost(
            reference: weakref.ReferenceType[_LifecycleV2ReauthenticationSemanticBindingIssuance],
        ) -> None:
            nonlocal semantic_issuance_state
            if getpid() != origin_pid or reference() is not None:
                return
            with registry_lock:
                current = state_get(semantic_issuance_state, issuance_id)
                if current is not None and current.reference is reference:
                    semantic_issuance_state = state_remove(
                        semantic_issuance_state,
                        issuance_id,
                    )

        registration = _SemanticBindingIssuanceRegistration(
            reference=weakref.ref(issuance, issuance_lost),
            semantic_binding_encoded=bytes(semantic_binding_encoded),
            binding_evidence_encoded=bytes(binding_evidence_encoded),
            binding_evidence_sha256=binding_evidence_sha256,
            provenance=provenance,
            root_sha256=root_sha256,
            intent_semantic_sha256=intent_semantic_sha256,
            boundary=boundary,
            owner_pid=getpid(),
            owner_thread=current_thread(),
            realm_identity=realm_identity,
            status="prepared",
        )
        with registry_lock:
            operation_registration = require_operation_locked(
                operation_token,
                realm_permit=realm_permit,
                realm_identity=realm_identity,
                operation="bind",
                boundary=boundary,
                subject=issuer,
            )
            if (
                state_get(semantic_issuance_state, issuance_id) is not None
                or operation_registration.candidate_status != "registered"
                or operation_registration.semantic_registered
                or operation_registration.candidate is not authenticated
                or operation_registration.candidate_primitives_encoded
                != canonical_authenticated.primitives.encoded
                or operation_registration.candidate_issuer_identity
                is not canonical_authenticated.issuer_identity
                or operation_registration.candidate_observation_identity
                is not canonical_authenticated.observation_identity
            ):
                _reject("reauthentication semantic issuance registration replayed")
            semantic_issuance_state = state_store(
                semantic_issuance_state,
                issuance_id,
                registration,
            )
            operation_state = state_store(
                operation_state,
                id(operation_token),
                operation_registration._replace(
                    candidate_status="consumed",
                    semantic_registered=True,
                ),
            )
        return issuance

    def consume_semantic_binding_issuance_once(
        value: object,
        *,
        root: LifecycleV2Root,
        intent: LifecycleV2ReauthenticationIntent,
    ) -> _LifecycleV2ReauthenticationSemanticBindingIssuanceSnapshot:
        nonlocal semantic_issuance_state
        caller = get_call_frame(1)
        try:
            if caller.f_code is not semantic_consumer_code:
                _reject("reauthentication semantic consumption caller is invalid")
        finally:
            del caller
        if getpid() != origin_pid or type(value) is not semantic_issuance_type:
            _reject("reauthentication semantic issuance crossed its process")
        issuance = value
        try:
            if issuance._owner_pid != getpid() or issuance._owner_thread is not current_thread():
                raise ValueError
        except Exception:
            _reject("reauthentication semantic issuance crossed its process or thread")
        exact_root = _require_exact_root(root)
        if type(intent) is not LifecycleV2ReauthenticationIntent:
            _reject("reauthentication semantic issuance intent type is not exact")
        intent._require_canonical_seal()
        root_sha256 = exact_root.sha256
        intent_semantic_sha256 = intent.sha256
        boundary = intent.boundary
        require_exact_call_chain(
            semantic_consumer_code,
            semantic_registration_code,
            semantic_wrapper_code,
            expected_bind_helper(boundary),
            expected_operation_wrapper(operation="bind", boundary=boundary),
        )
        invalid = False
        with registry_lock:
            registration = state_get(semantic_issuance_state, id(issuance))
            if (
                registration is None
                or registration.reference() is not issuance
                or registration.owner_pid != getpid()
                or registration.owner_thread is not current_thread()
                or registration.status != "prepared"
            ):
                _reject("reauthentication semantic issuance was replayed")
            try:
                invalid = (
                    issuance._binding_evidence_sha256 != registration.binding_evidence_sha256
                    or issuance._boundary != registration.boundary
                    or issuance._intent_semantic_sha256 != registration.intent_semantic_sha256
                    or issuance._owner_pid != registration.owner_pid
                    or issuance._owner_thread is not registration.owner_thread
                    or issuance._provenance != registration.provenance
                    or issuance._realm_identity is not registration.realm_identity
                    or issuance._root_sha256 != registration.root_sha256
                    or issuance._status != "prepared"
                    or root_sha256 != registration.root_sha256
                    or intent_semantic_sha256 != registration.intent_semantic_sha256
                    or boundary != registration.boundary
                    or (
                        registration.provenance == fake_semantic_binding_provenance
                        and exact_root.environment != "test"
                    )
                )
            except Exception:
                invalid = True
            semantic_issuance_state = state_store(
                semantic_issuance_state,
                id(issuance),
                registration._replace(status="consumed"),
            )
            object.__setattr__(issuance, "_status", "consumed")
            semantic_binding_encoded = registration.semantic_binding_encoded
            binding_evidence_encoded = registration.binding_evidence_encoded
            binding_evidence_sha256 = registration.binding_evidence_sha256
            provenance = registration.provenance
            registered_root_sha256 = registration.root_sha256
            registered_intent_semantic_sha256 = registration.intent_semantic_sha256
            registered_boundary = registration.boundary
        if invalid:
            _reject("reauthentication semantic issuance seal changed")
        return semantic_issuance_snapshot_type(
            semantic_binding_encoded=semantic_binding_encoded,
            binding_evidence_encoded=binding_evidence_encoded,
            binding_evidence_sha256=binding_evidence_sha256,
            provenance=provenance,
            root_sha256=registered_root_sha256,
            intent_semantic_sha256=registered_intent_semantic_sha256,
            boundary=registered_boundary,
        )

    return (
        configure_registry_callers,
        register_realm,
        begin_realm_operation,
        close_realm_operation,
        authorize_issuer_initialization,
        authorize_observation_authentication,
        register_authenticated_observation,
        register_issuer,
        begin_issuer_once,
        register_binding,
        require_binding,
        reserve_pre_binding_for_post,
        register_semantic_binding_issuance,
        consume_semantic_binding_issuance_once,
    )


_require_live_binding: Callable[..., _BindingRegistrySnapshot]


def _capture_challenge(challenge_source: Callable[[int], bytes]) -> bytearray:
    if not callable(challenge_source):
        _reject("reauthentication issuer challenge source is invalid")
    try:
        challenge = challenge_source(32)
    except Exception as error:
        raise TrustedTimeGracefulStopV2Rejected(
            "reauthentication issuer challenge generation failed"
        ) from error
    if type(challenge) is not bytes or len(challenge) != 32:
        _reject("reauthentication issuer challenge must be exactly 32 bytes")
    return bytearray(challenge)


@dataclass(frozen=True, slots=True)
class _ValidatedLineageBoundary:
    root: LifecycleV2Root
    request: LifecycleV2CleanStopRequest
    result: LifecycleV2CleanStopResult
    records: tuple[LifecycleV2ProgressRecord, ...]
    intent: LifecycleV2ProgressRecord
    intent_semantic: LifecycleV2ReauthenticationIntent
    transcript: LifecycleV2Transcript | None


def _require_exact_normal_lineage_boundary(
    value: object,
    *,
    last_ordinal: int,
    boundary: str,
    normal_stage_for_ordinal: Callable[[int], LifecycleV2Stage | None],
) -> _ValidatedLineageBoundary:
    if (
        type(value) is not LifecycleV2NormalProgressLineage
        or last_ordinal not in {5, 19}
        or boundary not in {"pre_effect", "post_teardown"}
    ):
        _reject("reauthentication requires one exact typed normal lineage")
    lineage = (
        require_exact_lifecycle_v2_normal_lineage_through_ordinal_5(value)
        if last_ordinal == 5
        else require_exact_lifecycle_v2_normal_lineage_through_ordinal_19(value)
    )
    if lineage is not value:
        _reject("reauthentication lineage validator substituted its live identity")
    root = _require_exact_root(lineage.root)
    result = _require_exact_result(lineage.clean_stop_result)
    request = _require_exact_request(result.request)
    if (
        result.to_dict()["lifecycle_root_sha256"] != root.sha256
        or request.to_dict()["lifecycle_root_sha256"] != root.sha256
        or result.request.encoded != request.encoded
        or type(lineage.records) is not tuple
        or type(lineage.semantics) is not tuple
        or len(lineage.records) != last_ordinal - 1
        or len(lineage.semantics) != len(lineage.records)
    ):
        _reject("typed normal lineage changed at its root or result")
    exact_records: list[LifecycleV2ProgressRecord] = []
    previous_sha256 = cast(str, request.to_dict()["request_intent_sha256"])
    for expected_ordinal, raw_record in enumerate(lineage.records, start=2):
        expected_stage = normal_stage_for_ordinal(expected_ordinal)
        if expected_stage is None:
            _reject("typed normal lineage stage lookup is incomplete")
        record = _require_exact_record(
            raw_record,
            root=root,
            ordinal=expected_ordinal,
            stage=expected_stage,
            predecessor_sha256=previous_sha256,
        )
        if lineage.record_at(expected_ordinal) != record:
            _reject("typed normal lineage record lookup changed")
        exact_records.append(record)
        previous_sha256 = record.sha256
    if exact_records[-1].ordinal != last_ordinal:
        _reject("typed normal lineage ended at the wrong boundary")
    raw_intent = lineage.semantic_at(last_ordinal)
    if type(raw_intent) is not LifecycleV2ReauthenticationIntent or raw_intent.boundary != boundary:
        _reject("typed normal lineage lacks its exact reauthentication intent")
    raw_intent._require_canonical_seal()
    intent = LifecycleV2ReauthenticationIntent._capture_fixed(
        raw_intent.to_dict(),
        boundary=boundary,
    )
    intent_fields = intent.to_dict()
    terminal = result.terminal_projection.to_dict()
    if (
        intent_fields["lifecycle_root_sha256"] != root.sha256
        or intent_fields["graceful_stop_operation_id"] != root.graceful_stop_operation_id
        or intent_fields["channel_id"] != root.channel_id
        or intent_fields["expected_head_sha256"] != terminal["current_anchor_sha256"]
        or exact_records[-1].evidence.to_dict()["arguments_sha256"] != intent.sha256
        or exact_records[-1].evidence.to_dict()["channel_id"] != root.channel_id
        or exact_records[-1].evidence.to_dict()["admission_sha256"] != root.admission_sha256
    ):
        _reject("typed reauthentication intent crossed its exact lineage")
    transcript: LifecycleV2Transcript | None = None
    if last_ordinal == 19:
        raw_transcript = lineage.prefix_through_eighteen
        if type(raw_transcript) is not LifecycleV2Transcript:
            _reject("post-teardown lineage lacks its exact published prefix")
        transcript = _require_exact_transcript(
            raw_transcript,
            root=root,
            last_ordinal=18,
            last_stage=LifecycleV2Stage.NAMED_VOLUMES_PRESERVED,
        )
        if len(transcript.entries) != 19:
            _reject("post-teardown prefix is not complete through ordinal eighteen")
        by_ordinal = {record.ordinal: record for record in exact_records}
        for entry in transcript.entries:
            if entry.stage is not normal_stage_for_ordinal(entry.ordinal):
                _reject("post-teardown prefix stage order is not exact")
            if entry.ordinal == 0:
                expected_digest = root.sha256
            elif entry.ordinal == 1:
                expected_digest = cast(str, request.to_dict()["request_intent_sha256"])
            else:
                expected_digest = by_ordinal[entry.ordinal].sha256
            if entry.record_artifact_sha256 != expected_digest:
                _reject("post-teardown prefix substituted a typed lifecycle record")
        pre_semantic = lineage.pre_effect_binding
        if type(pre_semantic) is not LifecycleV2AuthenticatedReauthenticationBinding:
            _reject("post-teardown lineage lacks its exact pre-effect binding")
        pre_semantic._require_sealed()
        if intent_fields["pre_effect_binding_sha256"] != pre_semantic.sha256:
            _reject("post-teardown intent crossed its pre-effect binding")
    return _ValidatedLineageBoundary(
        root=root,
        request=request,
        result=result,
        records=tuple(exact_records),
        intent=exact_records[-1],
        intent_semantic=intent,
        transcript=transcript,
    )


def _initialize_issuer(
    issuer: _BindingIssuerBase,
    *,
    operation_token: object,
    issuer_type: type[_BindingIssuerBase],
    context: _BindingContext,
    observation_issuer_identity: object,
    challenge_source: Callable[[int], bytes],
    realm_identity: object,
    realm_permit: object,
    authorize_issuer_initialization: Callable[..., None],
    register_issuer: Callable[..., None],
    getpid: Callable[[], int],
    current_thread: Callable[[], threading.Thread],
) -> None:
    boundary = (
        "pre_effect"
        if issuer_type is _LifecycleV2PreEffectBindingIssuer
        else "post_teardown"
        if issuer_type is _LifecycleV2PostTeardownBindingIssuer
        else ""
    )
    authorize_issuer_initialization(
        operation_token,
        realm_permit=realm_permit,
        realm_identity=realm_identity,
        boundary=boundary,
    )
    if observation_issuer_identity is None:
        _reject("ADR-0109 observation issuer identity is required")
    challenge = _capture_challenge(challenge_source)
    challenge_sha256 = _sha256(bytes(challenge))
    try:
        object.__setattr__(issuer, "_challenge", challenge)
        object.__setattr__(issuer, "_challenge_sha256", challenge_sha256)
        object.__setattr__(
            issuer,
            "_expected_observation_issuer",
            observation_issuer_identity,
        )
        object.__setattr__(issuer, "_owner_pid", getpid())
        object.__setattr__(issuer, "_owner_thread", current_thread())
        object.__setattr__(issuer, "_realm_identity", realm_identity)
        object.__setattr__(issuer, "_status", "prepared")
        object.__setattr__(issuer, "_context", context)
        register_issuer(
            issuer,
            operation_token=operation_token,
            realm_permit=realm_permit,
            issuer_type=issuer_type,
            context=context,
            expected_observation_issuer=observation_issuer_identity,
            challenge=challenge,
            challenge_sha256=challenge_sha256,
            realm_identity=realm_identity,
        )
    except BaseException:
        for index in range(len(challenge)):
            challenge[index] = 0
        challenge.clear()
        object.__setattr__(issuer, "_status", "consumed")
        raise


def _prepare_lifecycle_v2_pre_effect_binding_issuer(
    *,
    operation_token: object,
    lineage_through_ordinal_5: object,
    observation_issuer_identity: object,
    challenge_source: Callable[[int], bytes],
    realm_identity: object,
    realm_permit: object,
    authorize_issuer_initialization: Callable[..., None],
    register_issuer: Callable[..., None],
    initialize_issuer: Callable[..., None],
    require_lineage_boundary: Callable[..., _ValidatedLineageBoundary],
    normal_stage_for_ordinal: Callable[[int], LifecycleV2Stage | None],
    getpid: Callable[[], int],
    current_thread: Callable[[], threading.Thread],
) -> _LifecycleV2PreEffectBindingIssuer:
    boundary = require_lineage_boundary(
        lineage_through_ordinal_5,
        last_ordinal=5,
        boundary="pre_effect",
        normal_stage_for_ordinal=normal_stage_for_ordinal,
    )
    quiescence = boundary.records[2]
    issuer: _LifecycleV2PreEffectBindingIssuer = object.__new__(_LifecycleV2PreEffectBindingIssuer)
    initialize_issuer(
        issuer,
        operation_token=operation_token,
        issuer_type=_LifecycleV2PreEffectBindingIssuer,
        context=_PreEffectContext(
            boundary.root,
            boundary.request,
            boundary.result,
            quiescence,
            boundary.intent,
            boundary.intent_semantic,
        ),
        observation_issuer_identity=observation_issuer_identity,
        challenge_source=challenge_source,
        realm_identity=realm_identity,
        realm_permit=realm_permit,
        authorize_issuer_initialization=authorize_issuer_initialization,
        register_issuer=register_issuer,
        getpid=getpid,
        current_thread=current_thread,
    )
    return issuer


_POST_TEARDOWN_RESULT_RULES = (
    (8, LifecycleV2Stage.SUPERVISOR_CONTAINER_STOP_RESULT_RETAINED),
    (10, LifecycleV2Stage.SOURCE_CONTAINER_STOP_RESULT_RETAINED),
    (12, LifecycleV2Stage.SUPERVISOR_CONTAINER_REMOVE_RESULT_RETAINED),
    (14, LifecycleV2Stage.SOURCE_CONTAINER_REMOVE_RESULT_RETAINED),
    (16, LifecycleV2Stage.PROJECT_NETWORK_REMOVE_RESULT_RETAINED),
    (18, LifecycleV2Stage.NAMED_VOLUMES_PRESERVED),
)


def _prepare_lifecycle_v2_post_teardown_binding_issuer(
    *,
    operation_token: object,
    lineage_through_ordinal_19: object,
    pre_effect_binding: object,
    observation_issuer_identity: object,
    challenge_source: Callable[[int], bytes],
    realm_identity: object,
    realm_permit: object,
    authorize_issuer_initialization: Callable[..., None],
    register_issuer: Callable[..., None],
    begin_issuer: Callable[..., _IssuerAttempt],
    require_binding: Callable[..., _BindingRegistrySnapshot],
    reserve_pre_binding: Callable[..., _BindingRegistrySnapshot],
    initialize_issuer: Callable[..., None],
    require_lineage_boundary: Callable[..., _ValidatedLineageBoundary],
    normal_stage_for_ordinal: Callable[[int], LifecycleV2Stage | None],
    getpid: Callable[[], int],
    current_thread: Callable[[], threading.Thread],
) -> _LifecycleV2PostTeardownBindingIssuer:
    exact_lineage = cast(
        LifecycleV2NormalProgressLineage,
        lineage_through_ordinal_19,
    )
    boundary = require_lineage_boundary(
        exact_lineage,
        last_ordinal=19,
        boundary="post_teardown",
        normal_stage_for_ordinal=normal_stage_for_ordinal,
    )
    assert boundary.transcript is not None
    pre_registration = require_binding(
        pre_effect_binding,
        expected_type=LifecycleV2PreEffectBinding,
        realm_identity=realm_identity,
    )
    if type(pre_registration.context) is not _PreEffectContext:
        _reject("post-teardown binding lacks its exact pre-effect context")
    raw_pre_issuer = pre_registration.issuer_identity
    if type(raw_pre_issuer) is not _LifecycleV2PreEffectBindingIssuer:
        _reject("post-teardown binding lacks its exact pre-effect issuer")
    pre_result = pre_registration.context.result
    if type(pre_registration.evidence) is not LifecycleV2PreEffectBindingEvidence:
        _reject("post-teardown binding lacks exact pre-effect evidence")
    pre_fields = pre_registration.evidence.to_dict()
    if (
        pre_fields["environment"] != boundary.root.environment
        or pre_fields["graceful_stop_operation_id"] != boundary.root.graceful_stop_operation_id
        or pre_fields["lifecycle_root_sha256"] != boundary.root.sha256
        or pre_fields["clean_stop_request_sha256"] != boundary.request.sha256
        or pre_fields["clean_stop_result_sha256"] != boundary.result.sha256
        or pre_result.encoded != boundary.result.encoded
        or observation_issuer_identity is pre_registration.observation_issuer_identity
        or type(exact_lineage.pre_effect_binding)
        is not LifecycleV2AuthenticatedReauthenticationBinding
        or exact_lineage.pre_effect_binding is not pre_registration.semantic_binding
        or exact_lineage.pre_effect_binding.encoded != pre_registration.semantic_binding.encoded
    ):
        _reject("post-teardown binding reused or crossed the pre-effect boundary")
    exact_results = tuple(
        boundary.records[ordinal - 2] for ordinal, _ in _POST_TEARDOWN_RESULT_RULES
    )
    reserved = reserve_pre_binding(
        pre_effect_binding,
        operation_token=operation_token,
        realm_permit=realm_permit,
        realm_identity=realm_identity,
    )
    if (
        reserved.evidence != pre_registration.evidence
        or reserved.issuer_identity is not pre_registration.issuer_identity
        or reserved.observation_identity is not pre_registration.observation_identity
        or reserved.observation_issuer_identity is not pre_registration.observation_issuer_identity
    ):
        _reject("pre-effect binding changed during post-teardown reservation")
    issuer: _LifecycleV2PostTeardownBindingIssuer = object.__new__(
        _LifecycleV2PostTeardownBindingIssuer
    )
    initialize_issuer(
        issuer,
        operation_token=operation_token,
        issuer_type=_LifecycleV2PostTeardownBindingIssuer,
        context=_PostTeardownContext(
            boundary.root,
            boundary.transcript,
            cast(LifecycleV2PreEffectBinding, pre_effect_binding),
            pre_result,
            exact_results,
            boundary.intent,
            boundary.intent_semantic,
        ),
        observation_issuer_identity=observation_issuer_identity,
        challenge_source=challenge_source,
        realm_identity=realm_identity,
        realm_permit=realm_permit,
        authorize_issuer_initialization=authorize_issuer_initialization,
        register_issuer=register_issuer,
        getpid=getpid,
        current_thread=current_thread,
    )
    if issuer._challenge_sha256 == pre_fields["issuer_challenge_sha256"]:
        begin_issuer(
            issuer,
            operation_token=operation_token,
            operation="prepare",
            boundary="post_teardown",
            realm_permit=realm_permit,
            expected_type=_LifecycleV2PostTeardownBindingIssuer,
            realm_identity=realm_identity,
        )
        _reject("post-teardown issuer challenge reused the pre-effect challenge")
    return issuer


def _issue_binding(
    binding_type: type[LifecycleV2PreEffectBinding] | type[LifecycleV2PostTeardownBinding],
    *,
    operation_token: object,
    evidence: LifecycleV2PreEffectBindingEvidence | LifecycleV2PostTeardownBindingEvidence,
    semantic_binding: LifecycleV2AuthenticatedReauthenticationBinding,
    attempt: _IssuerAttempt,
    observation: _LifecycleV2ADR0109ObservationCandidate,
    realm_permit: object,
    register_binding: Callable[..., None],
    getpid: Callable[[], int],
    current_thread: Callable[[], threading.Thread],
) -> LifecycleV2PreEffectBinding | LifecycleV2PostTeardownBinding:
    result = object.__new__(binding_type)
    object.__setattr__(result, "_evidence", evidence)
    object.__setattr__(result, "_issuer_identity", attempt.issuer)
    object.__setattr__(result, "_observation_identity", observation.observation_identity)
    object.__setattr__(result, "_observation_issuer_identity", observation.issuer_identity)
    object.__setattr__(result, "_owner_pid", getpid())
    object.__setattr__(result, "_owner_thread", current_thread())
    object.__setattr__(result, "_realm_identity", attempt.realm_identity)
    object.__setattr__(result, "_semantic_binding", semantic_binding)
    register_binding(
        result,
        operation_token=operation_token,
        realm_permit=realm_permit,
        binding_type=binding_type,
        evidence=evidence,
        semantic_binding=semantic_binding,
        context=attempt.context,
        issuer_identity=attempt.issuer,
        observation_identity=observation.observation_identity,
        observation_issuer_identity=observation.issuer_identity,
        realm_identity=attempt.realm_identity,
    )
    return result


def _semantic_binding(
    *,
    operation_token: object,
    boundary: str,
    context: _BindingContext,
    attempt: _IssuerAttempt,
    authenticated: _LifecycleV2ADR0109ObservationCandidate,
    binding_evidence: _BindingEvidence,
    realm_permit: object,
    register_semantic_binding_issuance: Callable[
        ...,
        _LifecycleV2ReauthenticationSemanticBindingIssuance,
    ],
    capture_semantic_binding: Callable[
        ...,
        LifecycleV2AuthenticatedReauthenticationBinding,
    ],
) -> LifecycleV2AuthenticatedReauthenticationBinding:
    expected_evidence_type: (
        type[LifecycleV2PreEffectBindingEvidence] | type[LifecycleV2PostTeardownBindingEvidence]
    ) = (
        LifecycleV2PreEffectBindingEvidence
        if boundary == "pre_effect"
        else LifecycleV2PostTeardownBindingEvidence
    )
    if type(binding_evidence) is not expected_evidence_type:
        _reject("reauthentication semantic binding evidence type is not exact")
    observation_fields = authenticated.primitives.to_dict()
    intent = context.intent_semantic
    payload = {
        "contract_version": (
            "phase6d-trusted-time-graceful-stop-"
            f"{boundary.replace('_', '-')}-reauthentication-binding-v2"
        ),
        "service": LIFECYCLE_V2_CLEANUP_SERVICE,
        "status": f"{boundary}_reauthentication_bound",
        "environment": context.root.environment,
        "graceful_stop_operation_id": context.root.graceful_stop_operation_id,
        "lifecycle_root_sha256": context.root.sha256,
        "channel_id": context.root.channel_id,
        "boundary": boundary,
        "intent_semantic_sha256": intent.sha256,
        "binding_evidence_sha256": binding_evidence.binding_sha256,
        "issuer_identity_sha256": observation_fields["issuer_binding_sha256"],
        "challenge_sha256": attempt.challenge_sha256,
        "observation_semantic_sha256": observation_fields["semantic_sha256"],
        "observed_head_sha256": observation_fields["current_anchor_sha256"],
        "provider_identity_sha256": authenticated.primitives.provider_identity_sha256,
        "observation_started_boottime_ns": observation_fields["observation_started_monotonic_ns"],
        "observation_completed_boottime_ns": observation_fields[
            "observation_completed_monotonic_ns"
        ],
    }
    issuance = register_semantic_binding_issuance(
        operation_token=operation_token,
        realm_permit=realm_permit,
        realm_identity=attempt.realm_identity,
        issuer=attempt.issuer,
        authenticated=authenticated,
        semantic_binding_encoded=canonical_v2_json_bytes(
            payload,
            maximum_bytes=_MAXIMUM_BYTES,
        ),
        binding_evidence_encoded=binding_evidence.encoded,
        binding_evidence_sha256=binding_evidence.binding_sha256,
        root=context.root,
        intent=intent,
    )
    return capture_semantic_binding(
        issuance,
        root=context.root,
        intent=intent,
    )


_ObservationAuthenticator = Callable[..., _LifecycleV2ADR0109ObservationCandidate]


def _bind_lifecycle_v2_pre_effect_observation_once(
    issuer: object,
    *,
    operation_token: object,
    observation: object,
    realm_identity: object,
    realm_permit: object,
    authenticate_observation: _ObservationAuthenticator,
    require_observation_candidate: Callable[
        [object],
        _LifecycleV2ADR0109ObservationCandidate,
    ],
    begin_issuer: Callable[..., _IssuerAttempt],
    register_binding: Callable[..., None],
    semantic_binding_builder: Callable[
        ...,
        LifecycleV2AuthenticatedReauthenticationBinding,
    ],
    issue_binding: Callable[
        ...,
        LifecycleV2PreEffectBinding | LifecycleV2PostTeardownBinding,
    ],
    getpid: Callable[[], int],
    current_thread: Callable[[], threading.Thread],
) -> LifecycleV2PreEffectBinding:
    attempt = begin_issuer(
        issuer,
        operation_token=operation_token,
        operation="bind",
        boundary="pre_effect",
        realm_permit=realm_permit,
        expected_type=_LifecycleV2PreEffectBindingIssuer,
        realm_identity=realm_identity,
    )
    authenticated = authenticate_observation(
        attempt.issuer,
        observation,
        operation_token=operation_token,
        boundary="pre_effect",
    )
    if authenticated.issuer_identity is not attempt.expected_observation_issuer:
        _reject("ADR-0109 observation crossed its exact issuer object")
    if type(attempt.context) is not _PreEffectContext:
        _reject("pre-effect binding context is invalid")
    context = attempt.context
    observation_fields = _require_observation_matches_result(
        authenticated,
        context.result,
    )
    quiescence_fields = context.transport_quiescence.evidence.to_dict()
    started = cast(int, observation_fields["observation_started_monotonic_ns"])
    completed = cast(int, observation_fields["observation_completed_monotonic_ns"])
    if (
        started <= cast(int, quiescence_fields["cleanup_completed_boottime_ns"])
        or completed >= context.root.operation_deadline_boottime_ns
    ):
        _reject("pre-effect observation did not follow quiescence within the operation deadline")
    terminal = context.result.terminal_projection.to_dict()
    evidence = LifecycleV2PreEffectBindingEvidence._capture(
        {
            "contract_version": LIFECYCLE_V2_PRE_EFFECT_BINDING_CONTRACT_VERSION,
            "service": LIFECYCLE_V2_SERVICE,
            "status": "fresh_pre_effect_adr0109_observation_bound",
            "environment": context.root.environment,
            "graceful_stop_operation_id": context.root.graceful_stop_operation_id,
            "lifecycle_root_sha256": context.root.sha256,
            "clean_stop_request_sha256": context.request.sha256,
            "clean_stop_result_sha256": context.result.sha256,
            "channel_id": context.root.channel_id,
            "expected_checkpoint_reason": "clean_stop",
            "expected_clean_stop_head_sha256": terminal["current_anchor_sha256"],
            "expected_clean_stop_terminal_result_semantic_sha256": terminal[
                "clean_stop_terminal_result_semantic_sha256"
            ],
            "topology_sha256": context.root.topology_sha256,
            "topology_lease_sha256": context.root.topology_lease_sha256,
            "transport_quiescence_record_sha256": context.transport_quiescence.sha256,
            "pre_effect_intent_sha256": context.intent.sha256,
            "adr0109_observation": observation_fields,
            "adr0109_observation_sha256": authenticated.primitives.sha256,
            "provider_identity_sha256": authenticated.primitives.provider_identity_sha256,
            "observation_semantic_sha256": observation_fields["semantic_sha256"],
            "adr0109_issuer_binding_sha256": observation_fields["issuer_binding_sha256"],
            "adr0109_read_only_configuration_sha256": observation_fields[
                "read_only_configuration_sha256"
            ],
            "issuer_challenge_sha256": attempt.challenge_sha256,
            "observation_started_monotonic_ns": started,
            "observation_completed_monotonic_ns": completed,
            "observation_deadline_monotonic_ns": observation_fields["deadline_monotonic_ns"],
        }
    )
    semantic_binding = semantic_binding_builder(
        operation_token=operation_token,
        boundary="pre_effect",
        context=context,
        attempt=attempt,
        authenticated=authenticated,
        binding_evidence=evidence,
    )
    binding = issue_binding(
        LifecycleV2PreEffectBinding,
        operation_token=operation_token,
        evidence=evidence,
        semantic_binding=semantic_binding,
        attempt=attempt,
        observation=authenticated,
        realm_permit=realm_permit,
        register_binding=register_binding,
        getpid=getpid,
        current_thread=current_thread,
    )
    assert type(binding) is LifecycleV2PreEffectBinding
    return binding


def _bind_lifecycle_v2_post_teardown_observation_once(
    issuer: object,
    *,
    operation_token: object,
    observation: object,
    realm_identity: object,
    realm_permit: object,
    authenticate_observation: _ObservationAuthenticator,
    require_observation_candidate: Callable[
        [object],
        _LifecycleV2ADR0109ObservationCandidate,
    ],
    begin_issuer: Callable[..., _IssuerAttempt],
    register_binding: Callable[..., None],
    require_binding: Callable[..., _BindingRegistrySnapshot],
    semantic_binding_builder: Callable[
        ...,
        LifecycleV2AuthenticatedReauthenticationBinding,
    ],
    issue_binding: Callable[
        ...,
        LifecycleV2PreEffectBinding | LifecycleV2PostTeardownBinding,
    ],
    getpid: Callable[[], int],
    current_thread: Callable[[], threading.Thread],
) -> LifecycleV2PostTeardownBinding:
    attempt = begin_issuer(
        issuer,
        operation_token=operation_token,
        operation="bind",
        boundary="post_teardown",
        realm_permit=realm_permit,
        expected_type=_LifecycleV2PostTeardownBindingIssuer,
        realm_identity=realm_identity,
    )
    authenticated = authenticate_observation(
        attempt.issuer,
        observation,
        operation_token=operation_token,
        boundary="post_teardown",
    )
    if authenticated.issuer_identity is not attempt.expected_observation_issuer:
        _reject("ADR-0109 observation crossed its exact issuer object")
    if type(attempt.context) is not _PostTeardownContext:
        _reject("post-teardown binding context is invalid")
    context = attempt.context
    pre_registration = require_binding(
        context.pre_binding,
        expected_type=LifecycleV2PreEffectBinding,
        realm_identity=realm_identity,
    )
    if (
        authenticated.issuer_identity is pre_registration.observation_issuer_identity
        or authenticated.observation_identity is pre_registration.observation_identity
    ):
        _reject("post-teardown seam reused the pre-effect issuer or observation object")
    observation_fields = _require_observation_matches_result(
        authenticated,
        context.result,
    )
    if type(pre_registration.evidence) is not LifecycleV2PreEffectBindingEvidence:
        _reject("post-teardown seam lost its pre-effect evidence")
    pre_evidence = pre_registration.evidence
    pre_fields = pre_evidence.to_dict()
    latest_teardown_completion = max(
        cast(int, record.evidence.to_dict()["call_completed_boottime_ns"])
        for record in context.result_records
    )
    started = cast(int, observation_fields["observation_started_monotonic_ns"])
    completed = cast(int, observation_fields["observation_completed_monotonic_ns"])
    if (
        started <= cast(int, pre_fields["observation_completed_monotonic_ns"])
        or started <= latest_teardown_completion
        or completed >= context.root.operation_deadline_boottime_ns
        or observation_fields["issuer_binding_sha256"]
        == pre_fields["adr0109_issuer_binding_sha256"]
        or observation_fields["semantic_sha256"] == pre_fields["observation_semantic_sha256"]
        or authenticated.primitives.provider_identity_sha256
        != pre_fields["provider_identity_sha256"]
        or observation_fields["current_anchor_sha256"]
        != pre_fields["expected_clean_stop_head_sha256"]
    ):
        _reject("post-teardown observation is not fresh, distinct, and cross-bound")
    result_by_ordinal = {record.ordinal: record for record in context.result_records}
    evidence = LifecycleV2PostTeardownBindingEvidence._capture(
        {
            "contract_version": LIFECYCLE_V2_POST_TEARDOWN_BINDING_CONTRACT_VERSION,
            "service": LIFECYCLE_V2_SERVICE,
            "status": "distinct_post_teardown_adr0109_observation_bound",
            "environment": context.root.environment,
            "graceful_stop_operation_id": context.root.graceful_stop_operation_id,
            "lifecycle_root_sha256": context.root.sha256,
            "published_prefix_through_ordinal_18_sha256": context.transcript.sha256,
            "expected_checkpoint_reason": "clean_stop",
            "expected_clean_stop_head_sha256": pre_fields["expected_clean_stop_head_sha256"],
            "expected_clean_stop_terminal_result_semantic_sha256": pre_fields[
                "expected_clean_stop_terminal_result_semantic_sha256"
            ],
            "pre_effect_binding_sha256": pre_evidence.binding_sha256,
            "supervisor_stop_result_sha256": result_by_ordinal[8].sha256,
            "source_stop_result_sha256": result_by_ordinal[10].sha256,
            "supervisor_remove_result_sha256": result_by_ordinal[12].sha256,
            "source_remove_result_sha256": result_by_ordinal[14].sha256,
            "project_network_remove_result_sha256": result_by_ordinal[16].sha256,
            "volume_proof_sha256": result_by_ordinal[18].sha256,
            "post_teardown_intent_sha256": context.intent.sha256,
            "adr0109_observation": observation_fields,
            "adr0109_observation_sha256": authenticated.primitives.sha256,
            "provider_identity_sha256": authenticated.primitives.provider_identity_sha256,
            "observation_semantic_sha256": observation_fields["semantic_sha256"],
            "adr0109_issuer_binding_sha256": observation_fields["issuer_binding_sha256"],
            "adr0109_read_only_configuration_sha256": observation_fields[
                "read_only_configuration_sha256"
            ],
            "issuer_challenge_sha256": attempt.challenge_sha256,
            "observation_started_monotonic_ns": started,
            "observation_completed_monotonic_ns": completed,
            "observation_deadline_monotonic_ns": observation_fields["deadline_monotonic_ns"],
        }
    )
    if evidence.binding_sha256 == pre_evidence.binding_sha256:
        _reject("pre-effect and post-teardown binding digests must be distinct")
    semantic_binding = semantic_binding_builder(
        operation_token=operation_token,
        boundary="post_teardown",
        context=context,
        attempt=attempt,
        authenticated=authenticated,
        binding_evidence=evidence,
    )
    binding = issue_binding(
        LifecycleV2PostTeardownBinding,
        operation_token=operation_token,
        evidence=evidence,
        semantic_binding=semantic_binding,
        attempt=attempt,
        observation=authenticated,
        realm_permit=realm_permit,
        register_binding=register_binding,
        getpid=getpid,
        current_thread=current_thread,
    )
    assert type(binding) is LifecycleV2PostTeardownBinding
    return binding


@dataclass(frozen=True, slots=True)
class _LifecycleV2ReauthenticationBindingRealm:
    prepare_pre_effect: Callable[..., _LifecycleV2PreEffectBindingIssuer]
    bind_pre_effect: Callable[..., LifecycleV2PreEffectBinding]
    prepare_post_teardown: Callable[..., _LifecycleV2PostTeardownBindingIssuer]
    bind_post_teardown: Callable[..., LifecycleV2PostTeardownBinding]


_PRODUCTION_ADAPTER_MODULE = "packages.adapters.trusted_time.graceful_stop_v2_reauthentication"
_PRODUCTION_ADAPTER_AUTHENTICATOR = "_consume_exact_adr0109_observation"


def _install_lifecycle_v2_reauthentication_binding_realms() -> tuple[
    Callable[..., _LifecycleV2ReauthenticationBindingRealm],
    Callable[..., _LifecycleV2ReauthenticationBindingRealm],
    Callable[..., _BindingRegistrySnapshot],
    Callable[..., _LifecycleV2ReauthenticationSemanticBindingIssuanceSnapshot],
    Callable[[], ModuleType],
]:
    """Hide every registry mutation and production permit in one closure."""

    (
        configure_registry_callers,
        register_realm,
        begin_realm_operation,
        close_realm_operation,
        authorize_issuer_initialization,
        authorize_observation_authentication,
        register_authenticated_observation,
        register_issuer,
        begin_issuer,
        register_binding,
        require_binding,
        reserve_pre_binding,
        register_semantic_binding_issuance,
        consume_semantic_binding_issuance_once,
    ) = _build_binding_registries()  # noqa: F821 - captured before module deletion
    initialize_issuer = _initialize_issuer  # noqa: F821 - installation-only binding
    require_lineage_boundary = _require_exact_normal_lineage_boundary
    exact_normal_stage_lookup = normal_lifecycle_v2_stage_for_ordinal
    prepare_pre_effect_issuer = _prepare_lifecycle_v2_pre_effect_binding_issuer  # noqa: F821
    prepare_post_teardown_issuer = _prepare_lifecycle_v2_post_teardown_binding_issuer  # noqa: F821
    bind_pre_effect_observation = _bind_lifecycle_v2_pre_effect_observation_once  # noqa: F821
    bind_post_teardown_observation = _bind_lifecycle_v2_post_teardown_observation_once  # noqa: F821
    semantic_binding_builder = _semantic_binding  # noqa: F821 - installation-only
    issue_binding = _issue_binding  # noqa: F821 - installation-only binding
    require_observation_candidate = _require_observation_candidate  # noqa: F821 - install-time capture
    capture_semantic_binding = (
        _capture_lifecycle_v2_authenticated_reauthentication_binding_from_realm  # noqa: F821
    )
    import_production_adapter = importlib.import_module
    source_open = open
    compile_source = compile
    sha256 = _sha256
    production_adapter_module = _PRODUCTION_ADAPTER_MODULE  # noqa: F821
    production_adapter_authenticator = _PRODUCTION_ADAPTER_AUTHENTICATOR  # noqa: F821
    production_adapter_source = os.path.realpath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "adapters",
            "trusted_time",
            "graceful_stop_v2_reauthentication.py",
        )
    )
    with source_open(production_adapter_source, "rb") as adapter_source_file:
        production_adapter_source_bytes = adapter_source_file.read()
        expected_production_adapter_code = compile_source(
            production_adapter_source_bytes,
            production_adapter_source,
            "exec",
        )
    production_adapter_source_sha256 = sha256(production_adapter_source_bytes)
    adr0109_module_name = (
        "scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication"
    )
    adr0109_module_source = os.path.realpath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "scripts",
            "trusted_time_post_enrollment_clean_stop_terminal_reauthentication.py",
        )
    )
    with source_open(adr0109_module_source, "rb") as adr0109_source_file:
        adr0109_source_bytes = adr0109_source_file.read()
        expected_adr0109_module_code = compile_source(
            adr0109_source_bytes,
            adr0109_module_source,
            "exec",
        )
    adr0109_source_sha256 = sha256(adr0109_source_bytes)
    expected_adr0109_names = frozenset(
        {
            "TrustedTimePostEnrollmentCleanStopTerminalPostcondition",
            "TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer",
            "_consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once",
            "_ConsumedPostconditionRegistrySnapshot",
            "_postcondition_payload",
            "_validate_trusted_time_post_enrollment_clean_stop_terminal_postcondition_consumed_by",
        }
    )
    expected_adapter_names = frozenset(
        {
            "_build_exact_adr0109_observation_consumer",
            "_claim_lifecycle_v2_production_reauthentication_binding_realm",
            "_consume_exact_adr0109_observation",
            "_install_lifecycle_v2_production_reauthentication_endpoints",
            "_PRODUCTION_BINDING_REALM",
        }
    )
    expected_authenticator_freevars = (
        "adr0109_issuer_type",
        "adr0109_postcondition_type",
        "consume_postcondition_once",
        "observation_from_consumed_snapshot",
        "observation_input_type",
        "post_teardown_issuer_type",
        "pre_effect_issuer_type",
        "rejected_type",
    )
    get_call_frame = sys._getframe
    exact_getattr = getattr
    exact_realpath = os.path.realpath
    fake_semantic_binding_provenance = _FAKE_REAUTHENTICATION_BINDING_PROVENANCE  # noqa: F821
    production_semantic_binding_provenance = _PRODUCTION_REAUTHENTICATION_BINDING_PROVENANCE  # noqa: F821
    production_challenge_source = secrets.token_bytes
    production_bootstrap_permit = object()
    production_bootstrap_consumed = False
    production_claimed = False
    exact_modules = sys.modules
    module_type = ModuleType
    module_spec_type = ModuleSpec
    execute_code = exec
    exact_setattr = setattr
    exact_delattr = delattr
    reject = _reject
    getpid = os.getpid
    current_thread = threading.current_thread
    new_lock = threading.Lock
    adapter_parent_name, _, adapter_leaf_name = production_adapter_module.rpartition(".")
    adr0109_parent_name, _, adr0109_leaf_name = adr0109_module_name.rpartition(".")
    fake_realm_builder_code: CodeType | None = None
    production_realm_claim_code: CodeType | None = None

    def create_realm(
        *,
        authenticate_observation: _ObservationAuthenticator,
        challenge_source: Callable[[int], bytes],
        semantic_binding_provenance: object | None = None,
    ) -> _LifecycleV2ReauthenticationBindingRealm:
        caller = get_call_frame(1)
        try:
            caller_code = caller.f_code
        finally:
            del caller
        caller_provenance = (
            fake_semantic_binding_provenance
            if caller_code is fake_realm_builder_code
            else production_semantic_binding_provenance
            if caller_code is production_realm_claim_code
            else None
        )
        if semantic_binding_provenance is not None or caller_provenance is None:
            reject("reauthentication binding realm caller is invalid")
        if not callable(authenticate_observation) or not callable(challenge_source):
            reject("reauthentication binding realm dependencies are invalid")
        realm_identity = object()
        realm_permit = object()
        register_realm(
            realm_permit,
            realm_identity=realm_identity,
            semantic_binding_provenance=caller_provenance,
        )
        origin_pid = getpid()
        consumed_observation_lock = new_lock()
        consumed_observation_state: tuple[tuple[int, object], ...] = ()

        def build_semantic_binding(
            *,
            operation_token: object,
            boundary: str,
            context: _BindingContext,
            attempt: _IssuerAttempt,
            authenticated: _LifecycleV2ADR0109ObservationCandidate,
            binding_evidence: _BindingEvidence,
        ) -> LifecycleV2AuthenticatedReauthenticationBinding:
            return semantic_binding_builder(
                operation_token=operation_token,
                boundary=boundary,
                context=context,
                attempt=attempt,
                authenticated=authenticated,
                binding_evidence=binding_evidence,
                realm_permit=realm_permit,
                register_semantic_binding_issuance=(register_semantic_binding_issuance),
                capture_semantic_binding=capture_semantic_binding,
            )

        def authenticate_once(
            binding_issuer: object,
            observation: object,
            *,
            operation_token: object,
            boundary: str,
        ) -> _LifecycleV2ADR0109ObservationCandidate:
            nonlocal consumed_observation_state
            if getpid() != origin_pid:
                reject("reauthentication observation realm crossed its process")
            authorize_observation_authentication(
                operation_token,
                realm_permit=realm_permit,
                realm_identity=realm_identity,
                boundary=boundary,
                issuer=binding_issuer,
            )
            authenticated = require_observation_candidate(
                authenticate_observation(binding_issuer, observation)
            )
            observation_identity = authenticated.observation_identity
            with consumed_observation_lock:
                existing = next(
                    (
                        item
                        for identity, item in consumed_observation_state
                        if identity == id(observation_identity)
                    ),
                    None,
                )
                if existing is not None:
                    reject("authenticated ADR-0109 observation was replayed")
                consumed_observation_state = (
                    *consumed_observation_state,
                    (id(observation_identity), observation_identity),
                )
            return register_authenticated_observation(
                operation_token,
                realm_permit=realm_permit,
                realm_identity=realm_identity,
                boundary=boundary,
                issuer=binding_issuer,
                authenticated=authenticated,
            )

        def prepare_pre_effect(
            *,
            lineage_through_ordinal_5: object,
            observation_issuer_identity: object,
        ) -> _LifecycleV2PreEffectBindingIssuer:
            operation_token = begin_realm_operation(
                realm_permit=realm_permit,
                realm_identity=realm_identity,
                operation="prepare",
                boundary="pre_effect",
                subject=lineage_through_ordinal_5,
            )
            succeeded = False
            try:
                result = prepare_pre_effect_issuer(
                    operation_token=operation_token,
                    lineage_through_ordinal_5=lineage_through_ordinal_5,
                    observation_issuer_identity=observation_issuer_identity,
                    challenge_source=challenge_source,
                    realm_identity=realm_identity,
                    realm_permit=realm_permit,
                    authorize_issuer_initialization=(authorize_issuer_initialization),
                    register_issuer=register_issuer,
                    initialize_issuer=initialize_issuer,
                    require_lineage_boundary=require_lineage_boundary,
                    normal_stage_for_ordinal=exact_normal_stage_lookup,
                    getpid=getpid,
                    current_thread=current_thread,
                )
                succeeded = True
                return result
            finally:
                close_realm_operation(
                    operation_token,
                    realm_permit=realm_permit,
                    realm_identity=realm_identity,
                    operation="prepare",
                    boundary="pre_effect",
                    subject=lineage_through_ordinal_5,
                    succeeded=succeeded,
                )

        def bind_pre_effect(
            issuer: object,
            *,
            observation: object,
        ) -> LifecycleV2PreEffectBinding:
            operation_token = begin_realm_operation(
                realm_permit=realm_permit,
                realm_identity=realm_identity,
                operation="bind",
                boundary="pre_effect",
                subject=issuer,
            )
            succeeded = False
            try:
                result = bind_pre_effect_observation(
                    issuer,
                    operation_token=operation_token,
                    observation=observation,
                    realm_identity=realm_identity,
                    realm_permit=realm_permit,
                    authenticate_observation=authenticate_once,
                    require_observation_candidate=require_observation_candidate,
                    begin_issuer=begin_issuer,
                    register_binding=register_binding,
                    semantic_binding_builder=build_semantic_binding,
                    issue_binding=issue_binding,
                    getpid=getpid,
                    current_thread=current_thread,
                )
                succeeded = True
                return result
            finally:
                close_realm_operation(
                    operation_token,
                    realm_permit=realm_permit,
                    realm_identity=realm_identity,
                    operation="bind",
                    boundary="pre_effect",
                    subject=issuer,
                    succeeded=succeeded,
                )

        def prepare_post_teardown(
            *,
            lineage_through_ordinal_19: object,
            pre_effect_binding: object,
            observation_issuer_identity: object,
        ) -> _LifecycleV2PostTeardownBindingIssuer:
            operation_token = begin_realm_operation(
                realm_permit=realm_permit,
                realm_identity=realm_identity,
                operation="prepare",
                boundary="post_teardown",
                subject=lineage_through_ordinal_19,
            )
            succeeded = False
            try:
                result = prepare_post_teardown_issuer(
                    operation_token=operation_token,
                    lineage_through_ordinal_19=lineage_through_ordinal_19,
                    pre_effect_binding=pre_effect_binding,
                    observation_issuer_identity=observation_issuer_identity,
                    challenge_source=challenge_source,
                    realm_identity=realm_identity,
                    realm_permit=realm_permit,
                    authorize_issuer_initialization=(authorize_issuer_initialization),
                    register_issuer=register_issuer,
                    begin_issuer=begin_issuer,
                    require_binding=require_binding,
                    reserve_pre_binding=reserve_pre_binding,
                    initialize_issuer=initialize_issuer,
                    require_lineage_boundary=require_lineage_boundary,
                    normal_stage_for_ordinal=exact_normal_stage_lookup,
                    getpid=getpid,
                    current_thread=current_thread,
                )
                succeeded = True
                return result
            finally:
                close_realm_operation(
                    operation_token,
                    realm_permit=realm_permit,
                    realm_identity=realm_identity,
                    operation="prepare",
                    boundary="post_teardown",
                    subject=lineage_through_ordinal_19,
                    succeeded=succeeded,
                )

        def bind_post_teardown(
            issuer: object,
            *,
            observation: object,
        ) -> LifecycleV2PostTeardownBinding:
            operation_token = begin_realm_operation(
                realm_permit=realm_permit,
                realm_identity=realm_identity,
                operation="bind",
                boundary="post_teardown",
                subject=issuer,
            )
            succeeded = False
            try:
                result = bind_post_teardown_observation(
                    issuer,
                    operation_token=operation_token,
                    observation=observation,
                    realm_identity=realm_identity,
                    realm_permit=realm_permit,
                    authenticate_observation=authenticate_once,
                    require_observation_candidate=require_observation_candidate,
                    begin_issuer=begin_issuer,
                    register_binding=register_binding,
                    require_binding=require_binding,
                    semantic_binding_builder=build_semantic_binding,
                    issue_binding=issue_binding,
                    getpid=getpid,
                    current_thread=current_thread,
                )
                succeeded = True
                return result
            finally:
                close_realm_operation(
                    operation_token,
                    realm_permit=realm_permit,
                    realm_identity=realm_identity,
                    operation="bind",
                    boundary="post_teardown",
                    subject=issuer,
                    succeeded=succeeded,
                )

        return _LifecycleV2ReauthenticationBindingRealm(
            prepare_pre_effect=prepare_pre_effect,
            bind_pre_effect=bind_pre_effect,
            prepare_post_teardown=prepare_post_teardown,
            bind_post_teardown=bind_post_teardown,
        )

    realm_nested_codes = {
        value.co_name: value for value in create_realm.__code__.co_consts if type(value) is CodeType
    }
    configure_registry_callers(
        realm_constructor=create_realm.__code__,
        issuer_initializer=initialize_issuer.__code__,
        issuer_beginners=(
            prepare_post_teardown_issuer.__code__,
            bind_pre_effect_observation.__code__,
            bind_post_teardown_observation.__code__,
        ),
        binding_issuer=issue_binding.__code__,
        pre_binding_reservation=prepare_post_teardown_issuer.__code__,
        semantic_registration=semantic_binding_builder.__code__,
        semantic_consumer=capture_semantic_binding.__code__,
        prepare_pre_wrapper=realm_nested_codes["prepare_pre_effect"],
        prepare_post_wrapper=realm_nested_codes["prepare_post_teardown"],
        bind_pre_wrapper=realm_nested_codes["bind_pre_effect"],
        bind_post_wrapper=realm_nested_codes["bind_post_teardown"],
        observation_authenticator=realm_nested_codes["authenticate_once"],
        prepare_pre_helper=prepare_pre_effect_issuer.__code__,
        prepare_post_helper=prepare_post_teardown_issuer.__code__,
        bind_pre_helper=bind_pre_effect_observation.__code__,
        bind_post_helper=bind_post_teardown_observation.__code__,
        semantic_wrapper=realm_nested_codes["build_semantic_binding"],
    )
    del realm_nested_codes

    def build_fake_realm(
        *,
        authenticate_observation: _ObservationAuthenticator,
        challenge_source: Callable[[int], bytes],
    ) -> _LifecycleV2ReauthenticationBindingRealm:
        """Build an explicitly fake realm with no production binding seal."""

        return create_realm(
            authenticate_observation=authenticate_observation,
            challenge_source=challenge_source,
        )

    def claim_production_realm(
        *,
        authenticate_observation: _ObservationAuthenticator,
        challenge_source: Callable[[int], bytes],
        _bootstrap_permit: object | None = None,
    ) -> _LifecycleV2ReauthenticationBindingRealm:
        """One-shot claim by the exact direct ADR-0109 adapter function."""

        nonlocal production_bootstrap_consumed
        nonlocal production_bootstrap_permit
        nonlocal production_claimed
        if (
            production_claimed
            or production_bootstrap_consumed
            or _bootstrap_permit is not production_bootstrap_permit
            or not callable(authenticate_observation)
        ):
            reject("production ADR-0109 binding realm claim is invalid")
        production_bootstrap_consumed = True
        caller = get_call_frame(1)
        try:
            caller_code = caller.f_code
            caller_globals = caller.f_globals
            caller_codes: set[CodeType] = set()
            pending_caller_codes = [caller_code]
            while pending_caller_codes:
                nested_code = pending_caller_codes.pop()
                caller_codes.add(nested_code)
                pending_caller_codes.extend(
                    value for value in nested_code.co_consts if type(value) is CodeType
                )
            if (
                caller_code.co_name != "<module>"
                or caller_code != expected_production_adapter_code
                or not expected_adapter_names.issubset(caller_code.co_names)
                or exact_realpath(caller_code.co_filename) != production_adapter_source
            ):
                reject("production ADR-0109 binding realm claim is invalid")
            adapter = import_production_adapter(production_adapter_module)
            adapter_globals = exact_getattr(adapter, "__dict__", None)
            adapter_spec = exact_getattr(adapter, "__spec__", None)
            exact_authenticator = exact_getattr(
                adapter,
                production_adapter_authenticator,
            )
            authenticator_code = exact_getattr(
                authenticate_observation,
                "__code__",
                None,
            )
            if (
                adapter_globals is not caller_globals
                or exact_getattr(adapter, "__name__", None) != production_adapter_module
                or exact_realpath(exact_getattr(adapter, "__file__", ""))
                != production_adapter_source
                or exact_getattr(adapter_spec, "name", None) != production_adapter_module
                or exact_realpath(exact_getattr(adapter_spec, "origin", ""))
                != production_adapter_source
                or exact_getattr(adapter_spec, "_initializing", False) is not True
                or authenticate_observation is not exact_authenticator
                or exact_getattr(authenticate_observation, "__globals__", None)
                is not caller_globals
                or type(authenticator_code) is not CodeType
                or authenticator_code not in caller_codes
                or authenticator_code.co_name != "consume_exact_adr0109_observation"
                or authenticator_code.co_qualname
                != (
                    "_build_exact_adr0109_observation_consumer.<locals>."
                    "consume_exact_adr0109_observation"
                )
                or authenticator_code.co_freevars != expected_authenticator_freevars
                or challenge_source is not production_challenge_source
            ):
                reject("production ADR-0109 binding realm claim is invalid")
        except (AttributeError, ImportError, TypeError, ValueError) as error:
            raise TrustedTimeGracefulStopV2Rejected(
                "production ADR-0109 binding realm claim is invalid"
            ) from error
        finally:
            del caller
        production_claimed = True
        del production_bootstrap_permit
        return create_realm(
            authenticate_observation=authenticate_observation,
            challenge_source=challenge_source,
        )

    fake_realm_builder_code = build_fake_realm.__code__
    production_realm_claim_code = claim_production_realm.__code__

    def bootstrap_production_adapter() -> ModuleType:
        """Execute the pinned adapter source with one closure-owned permit."""

        if production_claimed or production_bootstrap_consumed:
            reject("production ADR-0109 adapter bootstrap is already consumed")
        if (
            sha256(production_adapter_source_bytes) != production_adapter_source_sha256
            or expected_production_adapter_code.co_filename != production_adapter_source
            or sha256(adr0109_source_bytes) != adr0109_source_sha256
            or expected_adr0109_module_code.co_filename != adr0109_module_source
        ):
            reject("production ADR-0109 adapter source snapshot changed")
        previous_adr0109_module = exact_modules.get(adr0109_module_name)
        adr0109_parent_module = exact_modules.get(adr0109_parent_name)
        previous_adr0109_parent_child = (
            None
            if adr0109_parent_module is None
            else exact_getattr(adr0109_parent_module, adr0109_leaf_name, None)
        )
        reuse_adr0109_module = type(previous_adr0109_module) is module_type
        previous_adr0109_namespace = (
            dict(previous_adr0109_module.__dict__) if reuse_adr0109_module else None
        )
        trusted_adr0109_module = (
            previous_adr0109_module if reuse_adr0109_module else module_type(adr0109_module_name)
        )
        if type(trusted_adr0109_module) is not module_type:
            reject("canonical ADR-0109 module bootstrap target is invalid")
        if reuse_adr0109_module:
            trusted_adr0109_module.__dict__.clear()
        trusted_adr0109_spec = module_spec_type(
            adr0109_module_name,
            loader=None,
            origin=adr0109_module_source,
        )
        exact_setattr(trusted_adr0109_spec, "_initializing", True)
        trusted_adr0109_module.__name__ = adr0109_module_name
        trusted_adr0109_module.__file__ = adr0109_module_source
        trusted_adr0109_module.__package__ = adr0109_parent_name
        trusted_adr0109_module.__spec__ = trusted_adr0109_spec
        exact_modules[adr0109_module_name] = trusted_adr0109_module
        if adr0109_parent_module is not None:
            exact_setattr(
                adr0109_parent_module,
                adr0109_leaf_name,
                trusted_adr0109_module,
            )
        try:
            execute_code(expected_adr0109_module_code, trusted_adr0109_module.__dict__)
            if any(name not in trusted_adr0109_module.__dict__ for name in expected_adr0109_names):
                reject("canonical ADR-0109 module bootstrap is incomplete")
        except BaseException:
            if reuse_adr0109_module:
                if previous_adr0109_namespace is None:
                    reject("canonical ADR-0109 rollback snapshot is invalid")
                trusted_adr0109_module.__dict__.clear()
                trusted_adr0109_module.__dict__.update(previous_adr0109_namespace)
            elif previous_adr0109_module is None:
                exact_modules.pop(adr0109_module_name, None)
            else:
                exact_modules[adr0109_module_name] = previous_adr0109_module
            if adr0109_parent_module is not None:
                if previous_adr0109_parent_child is None:
                    with suppress(AttributeError):
                        exact_delattr(adr0109_parent_module, adr0109_leaf_name)
                else:
                    exact_setattr(
                        adr0109_parent_module,
                        adr0109_leaf_name,
                        previous_adr0109_parent_child,
                    )
            raise
        finally:
            exact_setattr(trusted_adr0109_spec, "_initializing", False)
        previous_module = exact_modules.get(production_adapter_module)
        parent_module = exact_modules.get(adapter_parent_name)
        previous_parent_child = (
            None if parent_module is None else exact_getattr(parent_module, adapter_leaf_name, None)
        )
        trusted_module = module_type(production_adapter_module)
        trusted_spec = module_spec_type(
            production_adapter_module,
            loader=None,
            origin=production_adapter_source,
        )
        exact_setattr(trusted_spec, "_initializing", True)
        trusted_module.__file__ = production_adapter_source
        trusted_module.__package__ = adapter_parent_name
        trusted_module.__spec__ = trusted_spec
        trusted_module.__dict__["_LIFECYCLE_V2_PRODUCTION_REALM_BOOTSTRAP_PERMIT"] = (
            production_bootstrap_permit
        )
        exact_modules[production_adapter_module] = trusted_module
        if parent_module is not None:
            exact_setattr(parent_module, adapter_leaf_name, trusted_module)
        try:
            execute_code(expected_production_adapter_code, trusted_module.__dict__)
            if trusted_module.__dict__.get(
                "_LIFECYCLE_V2_PRODUCTION_REALM_BOOTSTRAP_PERMIT"
            ) is not None or any(
                not callable(trusted_module.__dict__.get(name))
                for name in (
                    "_prepare_lifecycle_v2_pre_effect_adr0109_binding_issuer",
                    "_bind_lifecycle_v2_pre_effect_adr0109_observation_once",
                    "_prepare_lifecycle_v2_post_teardown_adr0109_binding_issuer",
                    "_bind_lifecycle_v2_post_teardown_adr0109_observation_once",
                )
            ):
                reject("production ADR-0109 adapter bootstrap did not consume its permit")
        except BaseException:
            if previous_module is None:
                exact_modules.pop(production_adapter_module, None)
            else:
                exact_modules[production_adapter_module] = previous_module
            if parent_module is not None:
                if previous_parent_child is None:
                    with suppress(AttributeError):
                        exact_delattr(parent_module, adapter_leaf_name)
                else:
                    exact_setattr(parent_module, adapter_leaf_name, previous_parent_child)
            raise
        finally:
            trusted_module.__dict__.pop(
                "_LIFECYCLE_V2_PRODUCTION_REALM_BOOTSTRAP_PERMIT",
                None,
            )
            exact_setattr(trusted_spec, "_initializing", False)
        return trusted_module

    return (
        build_fake_realm,
        claim_production_realm,
        require_binding,
        consume_semantic_binding_issuance_once,
        bootstrap_production_adapter,
    )


(
    _build_fake_lifecycle_v2_reauthentication_binding_realm,
    _claim_lifecycle_v2_production_reauthentication_binding_realm,
    _require_live_binding,
    _consume_exact_lifecycle_v2_reauthentication_semantic_binding_issuance_once,
    _bootstrap_lifecycle_v2_production_reauthentication_adapter,
) = _install_lifecycle_v2_reauthentication_binding_realms()

_bootstrap_lifecycle_v2_production_reauthentication_adapter()
del _bootstrap_lifecycle_v2_production_reauthentication_adapter

_install_lifecycle_v2_reauthentication_semantic_binding_issuance_consumer(
    _consume_exact_lifecycle_v2_reauthentication_semantic_binding_issuance_once
)

# Registry writers and object mints are installation-only implementation
# details.  Removing their module bindings prevents consumers from combining
# object.__new__ forgeries with a callable register/issue seam.
del _bind_lifecycle_v2_post_teardown_observation_once
del _bind_lifecycle_v2_pre_effect_observation_once
del _build_binding_registries
del _capture_lifecycle_v2_authenticated_reauthentication_binding_from_realm
del _FAKE_REAUTHENTICATION_BINDING_PROVENANCE
del _initialize_issuer
del _install_lifecycle_v2_reauthentication_semantic_binding_issuance_consumer
del _install_lifecycle_v2_reauthentication_binding_realms
del _issue_binding
del _prepare_lifecycle_v2_post_teardown_binding_issuer
del _prepare_lifecycle_v2_pre_effect_binding_issuer
del _require_observation_candidate
del _PRODUCTION_ADAPTER_AUTHENTICATOR
del _PRODUCTION_ADAPTER_MODULE
del _PRODUCTION_REAUTHENTICATION_BINDING_PROVENANCE
del _REAUTHENTICATION_BINDING_PROVENANCES
del _semantic_binding
