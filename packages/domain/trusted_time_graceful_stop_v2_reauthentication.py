"""Effect-free ADR-0109 binding seams for lifecycle-v2 milestone one.

The durable values in this module contain only canonical primitive evidence.
The issuer, observation, and binding seals are deliberately process-local,
thread-bound, one shot, and non-serializable.  This module performs no
provider observation, persistence, transport, Docker call, or stop effect.
"""

from __future__ import annotations

import hashlib
import os
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Never, Self, cast

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
)
from packages.domain.trusted_time_graceful_stop_v2_terminal import (
    LifecycleV2CleanStopResult,
)

ADR0109_REAUTHENTICATION_CONTRACT_VERSION = (
    "phase6d-post-enrollment-clean-stop-terminal-reauthentication-v1"
)
ADR0109_REAUTHENTICATION_STATUS = (
    "provider_terminal_observed_under_stable_sql_authenticated"
)
LIFECYCLE_V2_PRE_EFFECT_BINDING_CONTRACT_VERSION = (
    "phase6d-trusted-time-graceful-stop-pre-effect-reauthentication-binding-v2"
)
LIFECYCLE_V2_POST_TEARDOWN_BINDING_CONTRACT_VERSION = (
    "phase6d-trusted-time-graceful-stop-post-teardown-reauthentication-binding-v2"
)
ADR0109_OBSERVATION_BUDGET_NS = 120_000_000_000

_MAXIMUM_BYTES = 256 * 1_024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")
_PRODUCTION_OBSERVATION_CAPABILITY = object()
_FAKE_OBSERVATION_CAPABILITY = object()
_BINDING_SEAL = object()
_ADR0109_ISSUER_TYPE = (
    "scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication",
    "TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer",
)
_ADR0109_POSTCONDITION_TYPE = (
    "scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication",
    "TrustedTimePostEnrollmentCleanStopTerminalPostcondition",
)


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
        or (
            predecessor_sha256 is not None
            and canonical.predecessor_sha256 != predecessor_sha256
        )
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
        anchor_sequence = _require_int(
            fields["anchor_sequence"], "anchor_sequence", minimum=3
        )
        confirmed = _require_int(
            fields["confirmed_anchor_count"], "confirmed_anchor_count", minimum=3
        )
        remote_count = _require_int(
            fields["remote_object_count"], "remote_object_count", minimum=3
        )
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


@dataclass(frozen=True, slots=True, init=False, eq=False)
class LifecycleV2AuthenticatedADR0109Observation:
    """Process-local seal over one exact consumed ADR-0109 observation object."""

    primitives: LifecycleV2ADR0109ObservationPrimitives
    issuer_identity: object
    observation_identity: object
    owner_pid: int
    owner_thread: threading.Thread
    _consumed_by: object | None
    _lock: threading.Lock
    _capability: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("authenticated ADR-0109 observations require a private seam")

    def __copy__(self) -> Never:
        _reject("authenticated ADR-0109 observations cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        _reject("authenticated ADR-0109 observations cannot be copied")

    def __reduce__(self) -> Never:
        _reject("authenticated ADR-0109 observations cannot be serialized")

    def __reduce_ex__(self, _protocol: object) -> Never:
        _reject("authenticated ADR-0109 observations cannot be serialized")


def _seal_authenticated_observation(
    primitives: object,
    *,
    issuer_identity: object,
    observation_identity: object,
    capability: object,
) -> LifecycleV2AuthenticatedADR0109Observation:
    if type(primitives) is not LifecycleV2ADR0109ObservationPrimitives:
        _reject("authenticated ADR-0109 observation primitives are invalid")
    exact = LifecycleV2ADR0109ObservationPrimitives.capture(primitives.to_dict())
    if exact != primitives or issuer_identity is None or observation_identity is None:
        _reject("authenticated ADR-0109 observation identity is invalid")
    result = object.__new__(LifecycleV2AuthenticatedADR0109Observation)
    object.__setattr__(result, "primitives", exact)
    object.__setattr__(result, "issuer_identity", issuer_identity)
    object.__setattr__(result, "observation_identity", observation_identity)
    object.__setattr__(result, "owner_pid", os.getpid())
    object.__setattr__(result, "owner_thread", threading.current_thread())
    object.__setattr__(result, "_consumed_by", None)
    object.__setattr__(result, "_lock", threading.Lock())
    object.__setattr__(result, "_capability", capability)
    return result


def _mint_production_authenticated_adr0109_observation(
    primitives: object,
    *,
    issuer_identity: object,
    observation_identity: object,
    capability: object,
) -> LifecycleV2AuthenticatedADR0109Observation:
    """Private mint used only after the adapter consumes the ADR-0109 registry."""

    if capability is not _PRODUCTION_OBSERVATION_CAPABILITY:
        _reject("production ADR-0109 observation capability is invalid")
    issuer_type = type(issuer_identity)
    observation_type = type(observation_identity)
    if (
        (issuer_type.__module__, issuer_type.__qualname__) != _ADR0109_ISSUER_TYPE
        or (observation_type.__module__, observation_type.__qualname__)
        != _ADR0109_POSTCONDITION_TYPE
    ):
        _reject("production ADR-0109 observation requires exact ADR-0109 objects")
    return _seal_authenticated_observation(
        primitives,
        issuer_identity=issuer_identity,
        observation_identity=observation_identity,
        capability=capability,
    )


def _mint_fake_authenticated_adr0109_observation(
    primitives: object,
    *,
    issuer_identity: object,
    observation_identity: object,
    capability: object,
) -> LifecycleV2AuthenticatedADR0109Observation:
    """Private deterministic fake mint; it grants no provider authority."""

    if capability is not _FAKE_OBSERVATION_CAPABILITY:
        _reject("fake ADR-0109 observation capability is invalid")
    return _seal_authenticated_observation(
        primitives,
        issuer_identity=issuer_identity,
        observation_identity=observation_identity,
        capability=capability,
    )


def _require_authenticated_observation(
    value: object,
) -> LifecycleV2AuthenticatedADR0109Observation:
    if (
        type(value) is not LifecycleV2AuthenticatedADR0109Observation
        or (
            value._capability is not _PRODUCTION_OBSERVATION_CAPABILITY
            and value._capability is not _FAKE_OBSERVATION_CAPABILITY
        )
        or value.owner_pid != os.getpid()
        or value.owner_thread is not threading.current_thread()
        or value.issuer_identity is None
        or value.observation_identity is None
    ):
        _reject("authenticated ADR-0109 observation crossed its process or thread")
    canonical = LifecycleV2ADR0109ObservationPrimitives.capture(value.primitives.to_dict())
    if canonical != value.primitives:
        _reject("authenticated ADR-0109 observation primitives changed")
    return value


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
        "anchor_intent_semantic_sha256": value[
            "current_anchor_intent_semantic_sha256"
        ],
        "candidate_remote_readback_sha256": value[
            "current_candidate_remote_readback_sha256"
        ],
        "receipt_semantic_sha256": value["current_receipt_semantic_sha256"],
        "receipt_observed_at_utc": value["receipt_observed_at_utc"],
    }


def _require_observation_matches_result(
    observation: LifecycleV2AuthenticatedADR0109Observation,
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
            fields["contract_version"]
            != LIFECYCLE_V2_POST_TEARDOWN_BINDING_CONTRACT_VERSION
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


@dataclass(frozen=True, slots=True)
class _PreEffectContext:
    root: LifecycleV2Root
    request: LifecycleV2CleanStopRequest
    result: LifecycleV2CleanStopResult
    transport_quiescence: LifecycleV2ProgressRecord
    intent: LifecycleV2ProgressRecord


@dataclass(frozen=True, slots=True)
class _PostTeardownContext:
    root: LifecycleV2Root
    transcript: LifecycleV2Transcript
    pre_binding: LifecycleV2PreEffectBinding
    result: LifecycleV2CleanStopResult
    result_records: tuple[LifecycleV2ProgressRecord, ...]
    intent: LifecycleV2ProgressRecord


class _BindingIssuerBase:
    __slots__ = (
        "_challenge",
        "_challenge_sha256",
        "_expected_observation_issuer",
        "_lock",
        "_owner_pid",
        "_owner_thread",
        "_status",
    )

    _challenge: bytearray
    _challenge_sha256: str
    _expected_observation_issuer: object
    _lock: threading.Lock
    _owner_pid: int
    _owner_thread: threading.Thread
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
        "_evidence",
        "_issuer_identity",
        "_observation_identity",
        "_observation_issuer_identity",
        "_owner_pid",
        "_owner_thread",
        "_seal",
    )

    _evidence: LifecycleV2PreEffectBindingEvidence | LifecycleV2PostTeardownBindingEvidence
    _issuer_identity: object
    _observation_identity: object
    _observation_issuer_identity: object
    _owner_pid: int
    _owner_thread: threading.Thread
    _seal: object

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


class LifecycleV2PreEffectBinding(_BindingBase):
    """Live pre-effect seal; its durable projection grants no effect authority."""

    __slots__ = ()

    @property
    def durable_evidence(self) -> LifecycleV2PreEffectBindingEvidence:
        _require_live_binding(self, expected_type=LifecycleV2PreEffectBinding)
        return cast(LifecycleV2PreEffectBindingEvidence, self._evidence)


class LifecycleV2PostTeardownBinding(_BindingBase):
    """Live post-teardown seal; it authorizes no additional effect."""

    __slots__ = ()

    @property
    def durable_evidence(self) -> LifecycleV2PostTeardownBindingEvidence:
        _require_live_binding(self, expected_type=LifecycleV2PostTeardownBinding)
        return cast(LifecycleV2PostTeardownBindingEvidence, self._evidence)


def _require_live_binding(
    value: object,
    *,
    expected_type: type[LifecycleV2PreEffectBinding] | type[LifecycleV2PostTeardownBinding],
) -> LifecycleV2PreEffectBinding | LifecycleV2PostTeardownBinding:
    if (
        type(value) is not expected_type
        or value._seal is not _BINDING_SEAL
        or value._owner_pid != os.getpid()
        or value._owner_thread is not threading.current_thread()
        or value._issuer_identity is None
        or value._observation_identity is None
        or value._observation_issuer_identity is None
    ):
        _reject("lifecycle-v2 reauthentication binding crossed its process or thread")
    evidence = value._evidence
    if type(value) is LifecycleV2PreEffectBinding:
        if type(evidence) is not LifecycleV2PreEffectBindingEvidence:
            _reject("pre-effect binding evidence type is invalid")
        pre_canonical = LifecycleV2PreEffectBindingEvidence._capture(evidence.to_dict())
        if pre_canonical != evidence:
            _reject("lifecycle-v2 reauthentication binding evidence changed")
    else:
        if type(evidence) is not LifecycleV2PostTeardownBindingEvidence:
            _reject("post-teardown binding evidence type is invalid")
        post_canonical = LifecycleV2PostTeardownBindingEvidence._capture(evidence.to_dict())
        if post_canonical != evidence:
            _reject("lifecycle-v2 reauthentication binding evidence changed")
    return value


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


def _initialize_issuer(
    issuer: _BindingIssuerBase,
    *,
    observation_issuer_identity: object,
    challenge_source: Callable[[int], bytes],
) -> None:
    if observation_issuer_identity is None:
        _reject("ADR-0109 observation issuer identity is required")
    challenge = _capture_challenge(challenge_source)
    object.__setattr__(issuer, "_challenge", challenge)
    object.__setattr__(issuer, "_challenge_sha256", _sha256(bytes(challenge)))
    object.__setattr__(issuer, "_expected_observation_issuer", observation_issuer_identity)
    object.__setattr__(issuer, "_lock", threading.Lock())
    object.__setattr__(issuer, "_owner_pid", os.getpid())
    object.__setattr__(issuer, "_owner_thread", threading.current_thread())
    object.__setattr__(issuer, "_status", "prepared")


def _prepare_lifecycle_v2_pre_effect_binding_issuer(
    *,
    root: object,
    request: object,
    result: object,
    transport_quiescence: object,
    pre_effect_intent: object,
    observation_issuer_identity: object,
    challenge_source: Callable[[int], bytes],
) -> _LifecycleV2PreEffectBindingIssuer:
    exact_root = _require_exact_root(root)
    exact_request = _require_exact_request(request)
    exact_result = _require_exact_result(result)
    result_fields = exact_result.to_dict()
    request_fields = exact_request.to_dict()
    if (
        exact_result.request != exact_request
        or exact_result.request.encoded != exact_request.encoded
        or request_fields["lifecycle_root_sha256"] != exact_root.sha256
        or result_fields["lifecycle_root_sha256"] != exact_root.sha256
        or request_fields["graceful_stop_operation_id"]
        != exact_root.graceful_stop_operation_id
        or result_fields["graceful_stop_operation_id"]
        != exact_root.graceful_stop_operation_id
        or request_fields["channel_id"] != exact_root.channel_id
        or result_fields["channel_id"] != exact_root.channel_id
        or request_fields["topology_sha256"] != exact_root.topology_sha256
        or request_fields["topology_lease_sha256"] != exact_root.topology_lease_sha256
    ):
        _reject("pre-effect binding crossed its root, request, result, channel, or topology")
    quiescence = _require_exact_record(
        transport_quiescence,
        root=exact_root,
        ordinal=4,
        stage=LifecycleV2Stage.TRANSPORT_CHANNEL_QUIESCED,
    )
    intent = _require_exact_record(
        pre_effect_intent,
        root=exact_root,
        ordinal=5,
        stage=LifecycleV2Stage.PRE_EFFECT_REAUTHENTICATION_INTENT_RETAINED,
        predecessor_sha256=quiescence.sha256,
    )
    issuer: _LifecycleV2PreEffectBindingIssuer = object.__new__(
        _LifecycleV2PreEffectBindingIssuer
    )
    _initialize_issuer(
        issuer,
        observation_issuer_identity=observation_issuer_identity,
        challenge_source=challenge_source,
    )
    object.__setattr__(
        issuer,
        "_context",
        _PreEffectContext(exact_root, exact_request, exact_result, quiescence, intent),
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
    root: object,
    published_prefix_through_ordinal_18: object,
    pre_effect_binding: object,
    teardown_result_records: object,
    post_teardown_intent: object,
    observation_issuer_identity: object,
    challenge_source: Callable[[int], bytes],
) -> _LifecycleV2PostTeardownBindingIssuer:
    exact_root = _require_exact_root(root)
    transcript = _require_exact_transcript(
        published_prefix_through_ordinal_18,
        root=exact_root,
        last_ordinal=18,
        last_stage=LifecycleV2Stage.NAMED_VOLUMES_PRESERVED,
    )
    pre_binding = _require_live_binding(
        pre_effect_binding,
        expected_type=LifecycleV2PreEffectBinding,
    )
    assert type(pre_binding) is LifecycleV2PreEffectBinding
    raw_pre_issuer = pre_binding._issuer_identity
    if type(raw_pre_issuer) is not _LifecycleV2PreEffectBindingIssuer:
        _reject("post-teardown binding lacks its exact pre-effect issuer")
    pre_issuer = raw_pre_issuer
    pre_result = pre_issuer._context.result
    pre_fields = pre_binding.durable_evidence.to_dict()
    if (
        pre_fields["environment"] != exact_root.environment
        or pre_fields["graceful_stop_operation_id"]
        != exact_root.graceful_stop_operation_id
        or pre_fields["lifecycle_root_sha256"] != exact_root.sha256
        or observation_issuer_identity is pre_binding._observation_issuer_identity
    ):
        _reject("post-teardown binding reused or crossed the pre-effect boundary")
    if type(teardown_result_records) is not tuple or len(teardown_result_records) != 6:
        _reject("post-teardown binding requires the six exact teardown results")
    exact_results: list[LifecycleV2ProgressRecord] = []
    for raw_record, (ordinal, stage) in zip(
        teardown_result_records,
        _POST_TEARDOWN_RESULT_RULES,
        strict=True,
    ):
        record = _require_exact_record(
            raw_record,
            root=exact_root,
            ordinal=ordinal,
            stage=stage,
            predecessor_sha256=transcript.entries[ordinal - 1].record_artifact_sha256,
        )
        if transcript.entries[ordinal].record_artifact_sha256 != record.sha256:
            _reject("post-teardown result is not in the published ordinal-18 prefix")
        exact_results.append(record)
    intent = _require_exact_record(
        post_teardown_intent,
        root=exact_root,
        ordinal=19,
        stage=LifecycleV2Stage.POST_TEARDOWN_REAUTHENTICATION_INTENT_RETAINED,
        predecessor_sha256=transcript.entries[-1].record_artifact_sha256,
    )
    issuer: _LifecycleV2PostTeardownBindingIssuer = object.__new__(
        _LifecycleV2PostTeardownBindingIssuer
    )
    _initialize_issuer(
        issuer,
        observation_issuer_identity=observation_issuer_identity,
        challenge_source=challenge_source,
    )
    if issuer._challenge_sha256 == pre_fields["issuer_challenge_sha256"]:
        with issuer._lock:
            _burn_issuer_locked(issuer)
        _reject("post-teardown issuer challenge reused the pre-effect challenge")
    object.__setattr__(
        issuer,
        "_context",
        _PostTeardownContext(
            exact_root,
            transcript,
            pre_binding,
            pre_result,
            tuple(exact_results),
            intent,
        ),
    )
    return issuer


def _require_issuer_origin(issuer: _BindingIssuerBase) -> None:
    if issuer._owner_pid != os.getpid() or issuer._owner_thread is not threading.current_thread():
        _reject("lifecycle-v2 reauthentication issuer crossed its process or thread")


def _burn_issuer_locked(issuer: _BindingIssuerBase) -> None:
    object.__setattr__(issuer, "_status", "consumed")
    for index in range(len(issuer._challenge)):
        issuer._challenge[index] = 0
    issuer._challenge.clear()


def _consume_issuer_once(
    issuer: _BindingIssuerBase,
    *,
    observation: object,
) -> LifecycleV2AuthenticatedADR0109Observation:
    _require_issuer_origin(issuer)
    authenticated = _require_authenticated_observation(observation)
    with issuer._lock:
        if issuer._status != "prepared":
            _reject("lifecycle-v2 reauthentication binding issuer was replayed")
        _burn_issuer_locked(issuer)
    with authenticated._lock:
        if authenticated._consumed_by is not None:
            _reject("authenticated ADR-0109 observation was replayed")
        object.__setattr__(authenticated, "_consumed_by", issuer)
    if authenticated.issuer_identity is not issuer._expected_observation_issuer:
        _reject("ADR-0109 observation crossed its exact issuer object")
    return authenticated


def _issue_binding(
    binding_type: type[LifecycleV2PreEffectBinding] | type[LifecycleV2PostTeardownBinding],
    *,
    evidence: LifecycleV2PreEffectBindingEvidence | LifecycleV2PostTeardownBindingEvidence,
    issuer: _BindingIssuerBase,
    observation: LifecycleV2AuthenticatedADR0109Observation,
) -> LifecycleV2PreEffectBinding | LifecycleV2PostTeardownBinding:
    result = object.__new__(binding_type)
    object.__setattr__(result, "_evidence", evidence)
    object.__setattr__(result, "_issuer_identity", issuer)
    object.__setattr__(result, "_observation_identity", observation.observation_identity)
    object.__setattr__(
        result, "_observation_issuer_identity", observation.issuer_identity
    )
    object.__setattr__(result, "_owner_pid", os.getpid())
    object.__setattr__(result, "_owner_thread", threading.current_thread())
    object.__setattr__(result, "_seal", _BINDING_SEAL)
    return result


def _bind_lifecycle_v2_pre_effect_observation_once(
    issuer: object,
    *,
    observation: object,
) -> LifecycleV2PreEffectBinding:
    if type(issuer) is not _LifecycleV2PreEffectBindingIssuer:
        _reject("pre-effect seam requires its exact private issuer")
    exact_issuer = issuer
    authenticated = _consume_issuer_once(exact_issuer, observation=observation)
    context = exact_issuer._context
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
            "provider_identity_sha256": authenticated.primitives.provider_identity_sha256,
            "observation_semantic_sha256": observation_fields["semantic_sha256"],
            "adr0109_issuer_binding_sha256": observation_fields["issuer_binding_sha256"],
            "adr0109_read_only_configuration_sha256": observation_fields[
                "read_only_configuration_sha256"
            ],
            "issuer_challenge_sha256": exact_issuer._challenge_sha256,
            "observation_started_monotonic_ns": started,
            "observation_completed_monotonic_ns": completed,
            "observation_deadline_monotonic_ns": observation_fields[
                "deadline_monotonic_ns"
            ],
        }
    )
    binding = _issue_binding(
        LifecycleV2PreEffectBinding,
        evidence=evidence,
        issuer=exact_issuer,
        observation=authenticated,
    )
    assert type(binding) is LifecycleV2PreEffectBinding
    return binding


def _bind_lifecycle_v2_post_teardown_observation_once(
    issuer: object,
    *,
    observation: object,
) -> LifecycleV2PostTeardownBinding:
    if type(issuer) is not _LifecycleV2PostTeardownBindingIssuer:
        _reject("post-teardown seam requires its exact private issuer")
    exact_issuer = issuer
    authenticated = _consume_issuer_once(exact_issuer, observation=observation)
    context = exact_issuer._context
    pre_binding = _require_live_binding(
        context.pre_binding,
        expected_type=LifecycleV2PreEffectBinding,
    )
    assert type(pre_binding) is LifecycleV2PreEffectBinding
    if (
        authenticated.issuer_identity is pre_binding._observation_issuer_identity
        or authenticated.observation_identity is pre_binding._observation_identity
    ):
        _reject("post-teardown seam reused the pre-effect issuer or observation object")
    observation_fields = _require_observation_matches_result(
        authenticated,
        context.result,
    )
    pre_evidence = pre_binding.durable_evidence
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
        or observation_fields["semantic_sha256"]
        == pre_fields["observation_semantic_sha256"]
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
            "expected_clean_stop_head_sha256": pre_fields[
                "expected_clean_stop_head_sha256"
            ],
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
            "provider_identity_sha256": authenticated.primitives.provider_identity_sha256,
            "observation_semantic_sha256": observation_fields["semantic_sha256"],
            "adr0109_issuer_binding_sha256": observation_fields["issuer_binding_sha256"],
            "adr0109_read_only_configuration_sha256": observation_fields[
                "read_only_configuration_sha256"
            ],
            "issuer_challenge_sha256": exact_issuer._challenge_sha256,
            "observation_started_monotonic_ns": started,
            "observation_completed_monotonic_ns": completed,
            "observation_deadline_monotonic_ns": observation_fields[
                "deadline_monotonic_ns"
            ],
        }
    )
    if evidence.binding_sha256 == pre_evidence.binding_sha256:
        _reject("pre-effect and post-teardown binding digests must be distinct")
    binding = _issue_binding(
        LifecycleV2PostTeardownBinding,
        evidence=evidence,
        issuer=exact_issuer,
        observation=authenticated,
    )
    assert type(binding) is LifecycleV2PostTeardownBinding
    return binding
