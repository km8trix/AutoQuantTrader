"""Direct ADR-0109 registry-consumption adapter for lifecycle-v2 bindings.

This module deliberately imports ADR-0109 itself rather than the dormant
ADR-0111 bridge.  It creates no provider observation and has no production
caller; it only consumes an already-issued exact ADR-0109 postcondition into
the process-local v2 seams.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import cast

from packages.domain.trusted_time_graceful_stop_v2 import TrustedTimeGracefulStopV2Rejected
from packages.domain.trusted_time_graceful_stop_v2_lifecycle_semantics import (
    LifecycleV2NormalProgressLineage,
)
from packages.domain.trusted_time_graceful_stop_v2_reauthentication import (
    LifecycleV2ADR0109ObservationPrimitives,
    LifecycleV2PostTeardownBinding,
    LifecycleV2PreEffectBinding,
    _claim_lifecycle_v2_production_reauthentication_binding_realm,
    _LifecycleV2ADR0109ObservationCandidate,
    _LifecycleV2PostTeardownBindingIssuer,
    _LifecycleV2PreEffectBindingIssuer,
)
from scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication import (
    TrustedTimePostEnrollmentCleanStopTerminalPostcondition,
    TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer,
    _consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once,
    _ConsumedPostconditionRegistrySnapshot,
    _postcondition_payload,
    _validate_trusted_time_post_enrollment_clean_stop_terminal_postcondition_consumed_by,
)


@dataclass(frozen=True, slots=True)
class _ADR0109ObservationInput:
    """Exact adapter input; this is not an authenticated observation seal."""

    postcondition: object
    issuer: object


def _require_exact_adr0109_issuer(
    value: object,
) -> TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer:
    if type(value) is not TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer:
        raise TrustedTimeGracefulStopV2Rejected(
            "lifecycle-v2 binding requires an exact ADR-0109 issuer"
        )
    return cast(TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer, value)


def _observation_from_consumed_snapshot(
    snapshot: object,
    *,
    postcondition: object,
    issuer: object,
    bridge_identity: object,
) -> _LifecycleV2ADR0109ObservationCandidate:
    if (
        type(snapshot) is not _ConsumedPostconditionRegistrySnapshot
        or type(postcondition) is not TrustedTimePostEnrollmentCleanStopTerminalPostcondition
        or type(issuer) is not TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer
        or snapshot.issuer_identity is not issuer
        or snapshot.bridge_identity is not bridge_identity
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "ADR-0109 consumed observation snapshot is not exact"
        )
    revalidated = (
        _validate_trusted_time_post_enrollment_clean_stop_terminal_postcondition_consumed_by(
            postcondition,
            issuer=issuer,
            bridge_identity=bridge_identity,
        )
    )
    if (
        type(revalidated) is not _ConsumedPostconditionRegistrySnapshot
        or revalidated.values != snapshot.values
        or revalidated.semantic_sha256 != snapshot.semantic_sha256
        or revalidated.issuer_identity is not issuer
        or revalidated.bridge_identity is not bridge_identity
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "ADR-0109 consumed observation changed during v2 binding"
        )
    payload = _postcondition_payload(snapshot.values)
    payload["semantic_sha256"] = snapshot.semantic_sha256
    primitives = LifecycleV2ADR0109ObservationPrimitives.capture(payload)
    return _LifecycleV2ADR0109ObservationCandidate(
        primitives=primitives,
        issuer_identity=issuer,
        observation_identity=postcondition,
    )


def _consume_exact_adr0109_observation(
    binding_issuer: object,
    observation: object,
) -> _LifecycleV2ADR0109ObservationCandidate:
    if (
        type(binding_issuer)
        not in {
            _LifecycleV2PreEffectBindingIssuer,
            _LifecycleV2PostTeardownBindingIssuer,
        }
        or type(observation) is not _ADR0109ObservationInput
    ):
        raise TrustedTimeGracefulStopV2Rejected(
            "ADR-0109 observation authentication requires an exact begun binding issuer"
        )
    exact_input = observation
    exact_issuer = _require_exact_adr0109_issuer(exact_input.issuer)
    postcondition = exact_input.postcondition
    if type(postcondition) is not TrustedTimePostEnrollmentCleanStopTerminalPostcondition:
        raise TrustedTimeGracefulStopV2Rejected(
            "lifecycle-v2 binding requires an exact ADR-0109 postcondition"
        )
    try:
        snapshot = _consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once(
            postcondition,
            issuer=exact_issuer,
            bridge_identity=binding_issuer,
        )
        return _observation_from_consumed_snapshot(
            snapshot,
            postcondition=postcondition,
            issuer=exact_issuer,
            bridge_identity=binding_issuer,
        )
    except TrustedTimeGracefulStopV2Rejected:
        raise
    except Exception as error:
        raise TrustedTimeGracefulStopV2Rejected(
            "ADR-0109 observation could not be consumed by lifecycle v2"
        ) from error


_PRODUCTION_BINDING_REALM = _claim_lifecycle_v2_production_reauthentication_binding_realm(
    authenticate_observation=_consume_exact_adr0109_observation,
    challenge_source=secrets.token_bytes,
)
del _consume_exact_adr0109_observation


def _prepare_lifecycle_v2_pre_effect_adr0109_binding_issuer(
    *,
    lineage_through_ordinal_5: LifecycleV2NormalProgressLineage,
    adr0109_issuer: object,
) -> _LifecycleV2PreEffectBindingIssuer:
    exact_issuer = _require_exact_adr0109_issuer(adr0109_issuer)
    return _PRODUCTION_BINDING_REALM.prepare_pre_effect(
        lineage_through_ordinal_5=lineage_through_ordinal_5,
        observation_issuer_identity=exact_issuer,
    )


def _bind_lifecycle_v2_pre_effect_adr0109_observation_once(
    binding_issuer: object,
    *,
    postcondition: object,
    adr0109_issuer: object,
) -> LifecycleV2PreEffectBinding:
    if type(binding_issuer) is not _LifecycleV2PreEffectBindingIssuer:
        raise TrustedTimeGracefulStopV2Rejected("pre-effect ADR-0109 binding issuer is invalid")
    return _PRODUCTION_BINDING_REALM.bind_pre_effect(
        binding_issuer,
        observation=_ADR0109ObservationInput(postcondition, adr0109_issuer),
    )


def _prepare_lifecycle_v2_post_teardown_adr0109_binding_issuer(
    *,
    lineage_through_ordinal_19: LifecycleV2NormalProgressLineage,
    pre_effect_binding: LifecycleV2PreEffectBinding,
    adr0109_issuer: object,
) -> _LifecycleV2PostTeardownBindingIssuer:
    exact_issuer = _require_exact_adr0109_issuer(adr0109_issuer)
    return _PRODUCTION_BINDING_REALM.prepare_post_teardown(
        lineage_through_ordinal_19=lineage_through_ordinal_19,
        pre_effect_binding=pre_effect_binding,
        observation_issuer_identity=exact_issuer,
    )


def _bind_lifecycle_v2_post_teardown_adr0109_observation_once(
    binding_issuer: object,
    *,
    postcondition: object,
    adr0109_issuer: object,
) -> LifecycleV2PostTeardownBinding:
    if type(binding_issuer) is not _LifecycleV2PostTeardownBindingIssuer:
        raise TrustedTimeGracefulStopV2Rejected("post-teardown ADR-0109 binding issuer is invalid")
    return _PRODUCTION_BINDING_REALM.bind_post_teardown(
        binding_issuer,
        observation=_ADR0109ObservationInput(postcondition, adr0109_issuer),
    )
