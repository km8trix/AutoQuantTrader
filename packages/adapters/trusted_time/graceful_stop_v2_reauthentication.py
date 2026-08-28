"""Direct ADR-0109 registry-consumption adapter for lifecycle-v2 bindings.

This module deliberately imports ADR-0109 itself rather than the dormant
ADR-0111 bridge.  It creates no provider observation and has no production
caller; it only consumes an already-issued exact ADR-0109 postcondition into
the process-local v2 seams.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
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
    _LifecycleV2ReauthenticationBindingRealm,
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


def _build_exact_adr0109_observation_consumer() -> Callable[
    [object, object],
    _LifecycleV2ADR0109ObservationCandidate,
]:
    """Capture the exact ADR-0109 registry and schema dependencies once."""

    observation_input_type = _ADR0109ObservationInput
    observation_candidate_type = _LifecycleV2ADR0109ObservationCandidate
    observation_primitives_type = LifecycleV2ADR0109ObservationPrimitives
    pre_effect_issuer_type = _LifecycleV2PreEffectBindingIssuer
    post_teardown_issuer_type = _LifecycleV2PostTeardownBindingIssuer
    adr0109_postcondition_type = (
        TrustedTimePostEnrollmentCleanStopTerminalPostcondition
    )
    adr0109_issuer_type = (
        TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer
    )
    consumed_snapshot_type = (
        _ConsumedPostconditionRegistrySnapshot  # noqa: F821 - install-time capture
    )
    consume_postcondition_once = (
        _consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once  # noqa: F821
    )
    validate_consumed_postcondition = (
        _validate_trusted_time_post_enrollment_clean_stop_terminal_postcondition_consumed_by  # noqa: F821
    )
    postcondition_payload = _postcondition_payload  # noqa: F821 - install-time capture
    rejected_type = TrustedTimeGracefulStopV2Rejected

    def observation_from_consumed_snapshot(
        snapshot: object,
        *,
        postcondition: object,
        issuer: object,
        bridge_identity: object,
    ) -> _LifecycleV2ADR0109ObservationCandidate:
        if (
            type(snapshot) is not consumed_snapshot_type
            or type(postcondition) is not adr0109_postcondition_type
            or type(issuer) is not adr0109_issuer_type
            or snapshot.issuer_identity is not issuer
            or snapshot.bridge_identity is not bridge_identity
        ):
            raise rejected_type(
                "ADR-0109 consumed observation snapshot is not exact"
            )
        revalidated = validate_consumed_postcondition(
            postcondition,
            issuer=issuer,
            bridge_identity=bridge_identity,
        )
        if (
            type(revalidated) is not consumed_snapshot_type
            or revalidated.values != snapshot.values
            or revalidated.semantic_sha256 != snapshot.semantic_sha256
            or revalidated.issuer_identity is not issuer
            or revalidated.bridge_identity is not bridge_identity
        ):
            raise rejected_type(
                "ADR-0109 consumed observation changed during v2 binding"
            )
        payload = postcondition_payload(snapshot.values)
        payload["semantic_sha256"] = snapshot.semantic_sha256
        primitives = observation_primitives_type.capture(payload)
        return observation_candidate_type(
            primitives=primitives,
            issuer_identity=issuer,
            observation_identity=postcondition,
        )

    def consume_exact_adr0109_observation(
        binding_issuer: object,
        observation: object,
    ) -> _LifecycleV2ADR0109ObservationCandidate:
        if (
            type(binding_issuer)
            not in {
                pre_effect_issuer_type,
                post_teardown_issuer_type,
            }
            or type(observation) is not observation_input_type
        ):
            raise rejected_type(
                "ADR-0109 observation authentication requires an exact begun binding issuer"
            )
        exact_input = observation
        exact_issuer = exact_input.issuer
        if type(exact_issuer) is not adr0109_issuer_type:
            raise rejected_type(
                "lifecycle-v2 binding requires an exact ADR-0109 issuer"
            )
        postcondition = exact_input.postcondition
        if type(postcondition) is not adr0109_postcondition_type:
            raise rejected_type(
                "lifecycle-v2 binding requires an exact ADR-0109 postcondition"
            )
        try:
            snapshot = consume_postcondition_once(
                postcondition,
                issuer=exact_issuer,
                bridge_identity=binding_issuer,
            )
            return observation_from_consumed_snapshot(
                snapshot,
                postcondition=postcondition,
                issuer=exact_issuer,
                bridge_identity=binding_issuer,
            )
        except rejected_type:
            raise
        except Exception as error:
            raise rejected_type(
                "ADR-0109 observation could not be consumed by lifecycle v2"
            ) from error

    return consume_exact_adr0109_observation


_consume_exact_adr0109_observation = _build_exact_adr0109_observation_consumer()
del _build_exact_adr0109_observation_consumer


_PRODUCTION_BINDING_REALM = _claim_lifecycle_v2_production_reauthentication_binding_realm(
    authenticate_observation=_consume_exact_adr0109_observation,
    challenge_source=secrets.token_bytes,
)
del _consume_exact_adr0109_observation
del _claim_lifecycle_v2_production_reauthentication_binding_realm
del _consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once
del _ConsumedPostconditionRegistrySnapshot
del _postcondition_payload
del _validate_trusted_time_post_enrollment_clean_stop_terminal_postcondition_consumed_by


def _install_lifecycle_v2_production_reauthentication_endpoints(
    production_binding_realm: _LifecycleV2ReauthenticationBindingRealm,
) -> tuple[
    Callable[..., _LifecycleV2PreEffectBindingIssuer],
    Callable[..., LifecycleV2PreEffectBinding],
    Callable[..., _LifecycleV2PostTeardownBindingIssuer],
    Callable[..., LifecycleV2PostTeardownBinding],
]:
    """Capture the production realm away from the adapter module namespace."""

    require_exact_issuer = _require_exact_adr0109_issuer
    observation_input_type = _ADR0109ObservationInput
    pre_effect_issuer_type = _LifecycleV2PreEffectBindingIssuer
    post_teardown_issuer_type = _LifecycleV2PostTeardownBindingIssuer
    rejected_type = TrustedTimeGracefulStopV2Rejected

    def prepare_pre_effect(
        *,
        lineage_through_ordinal_5: LifecycleV2NormalProgressLineage,
        adr0109_issuer: object,
    ) -> _LifecycleV2PreEffectBindingIssuer:
        exact_issuer = require_exact_issuer(adr0109_issuer)
        return production_binding_realm.prepare_pre_effect(
            lineage_through_ordinal_5=lineage_through_ordinal_5,
            observation_issuer_identity=exact_issuer,
        )

    def bind_pre_effect(
        binding_issuer: object,
        *,
        postcondition: object,
        adr0109_issuer: object,
    ) -> LifecycleV2PreEffectBinding:
        if type(binding_issuer) is not pre_effect_issuer_type:
            raise rejected_type(
                "pre-effect ADR-0109 binding issuer is invalid"
            )
        return production_binding_realm.bind_pre_effect(
            binding_issuer,
            observation=observation_input_type(postcondition, adr0109_issuer),
        )

    def prepare_post_teardown(
        *,
        lineage_through_ordinal_19: LifecycleV2NormalProgressLineage,
        pre_effect_binding: LifecycleV2PreEffectBinding,
        adr0109_issuer: object,
    ) -> _LifecycleV2PostTeardownBindingIssuer:
        exact_issuer = require_exact_issuer(adr0109_issuer)
        return production_binding_realm.prepare_post_teardown(
            lineage_through_ordinal_19=lineage_through_ordinal_19,
            pre_effect_binding=pre_effect_binding,
            observation_issuer_identity=exact_issuer,
        )

    def bind_post_teardown(
        binding_issuer: object,
        *,
        postcondition: object,
        adr0109_issuer: object,
    ) -> LifecycleV2PostTeardownBinding:
        if type(binding_issuer) is not post_teardown_issuer_type:
            raise rejected_type(
                "post-teardown ADR-0109 binding issuer is invalid"
            )
        return production_binding_realm.bind_post_teardown(
            binding_issuer,
            observation=observation_input_type(postcondition, adr0109_issuer),
        )

    return (
        prepare_pre_effect,
        bind_pre_effect,
        prepare_post_teardown,
        bind_post_teardown,
    )


(
    _prepare_lifecycle_v2_pre_effect_adr0109_binding_issuer,
    _bind_lifecycle_v2_pre_effect_adr0109_observation_once,
    _prepare_lifecycle_v2_post_teardown_adr0109_binding_issuer,
    _bind_lifecycle_v2_post_teardown_adr0109_observation_once,
) = _install_lifecycle_v2_production_reauthentication_endpoints(
    _PRODUCTION_BINDING_REALM
)
del _install_lifecycle_v2_production_reauthentication_endpoints
del _PRODUCTION_BINDING_REALM
