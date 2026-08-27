"""Direct ADR-0109 registry-consumption adapter for lifecycle-v2 bindings.

This module deliberately imports ADR-0109 itself rather than the dormant
ADR-0111 bridge.  It creates no provider observation and has no production
caller; it only consumes an already-issued exact ADR-0109 postcondition into
the process-local v2 seams.
"""

from __future__ import annotations

import secrets
from typing import cast

from packages.domain.trusted_time_graceful_stop_v2 import (
    LifecycleV2CleanStopRequest,
    LifecycleV2ProgressRecord,
    LifecycleV2Root,
    LifecycleV2Transcript,
    TrustedTimeGracefulStopV2Rejected,
)
from packages.domain.trusted_time_graceful_stop_v2_reauthentication import (
    _PRODUCTION_OBSERVATION_CAPABILITY,
    LifecycleV2ADR0109ObservationPrimitives,
    LifecycleV2AuthenticatedADR0109Observation,
    LifecycleV2PostTeardownBinding,
    LifecycleV2PreEffectBinding,
    _bind_lifecycle_v2_post_teardown_observation_once,
    _bind_lifecycle_v2_pre_effect_observation_once,
    _LifecycleV2PostTeardownBindingIssuer,
    _LifecycleV2PreEffectBindingIssuer,
    _mint_production_authenticated_adr0109_observation,
    _prepare_lifecycle_v2_post_teardown_binding_issuer,
    _prepare_lifecycle_v2_pre_effect_binding_issuer,
)
from packages.domain.trusted_time_graceful_stop_v2_terminal import (
    LifecycleV2CleanStopResult,
)
from scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication import (
    TrustedTimePostEnrollmentCleanStopTerminalPostcondition,
    TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer,
    _consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once,
    _ConsumedPostconditionRegistrySnapshot,
    _postcondition_payload,
    _validate_trusted_time_post_enrollment_clean_stop_terminal_postcondition_consumed_by,
)


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
) -> LifecycleV2AuthenticatedADR0109Observation:
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
    return _mint_production_authenticated_adr0109_observation(
        primitives,
        issuer_identity=issuer,
        observation_identity=postcondition,
        capability=_PRODUCTION_OBSERVATION_CAPABILITY,
    )


def _consume_exact_adr0109_observation(
    postcondition: object,
    *,
    issuer: object,
    bridge_identity: object,
) -> LifecycleV2AuthenticatedADR0109Observation:
    exact_issuer = _require_exact_adr0109_issuer(issuer)
    if type(postcondition) is not TrustedTimePostEnrollmentCleanStopTerminalPostcondition:
        raise TrustedTimeGracefulStopV2Rejected(
            "lifecycle-v2 binding requires an exact ADR-0109 postcondition"
        )
    try:
        snapshot = (
            _consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once(
                postcondition,
                issuer=exact_issuer,
                bridge_identity=bridge_identity,
            )
        )
        return _observation_from_consumed_snapshot(
            snapshot,
            postcondition=postcondition,
            issuer=exact_issuer,
            bridge_identity=bridge_identity,
        )
    except TrustedTimeGracefulStopV2Rejected:
        raise
    except Exception as error:
        raise TrustedTimeGracefulStopV2Rejected(
            "ADR-0109 observation could not be consumed by lifecycle v2"
        ) from error


def _prepare_lifecycle_v2_pre_effect_adr0109_binding_issuer(
    *,
    root: LifecycleV2Root,
    request: LifecycleV2CleanStopRequest,
    result: LifecycleV2CleanStopResult,
    transport_quiescence: LifecycleV2ProgressRecord,
    pre_effect_intent: LifecycleV2ProgressRecord,
    adr0109_issuer: object,
) -> _LifecycleV2PreEffectBindingIssuer:
    exact_issuer = _require_exact_adr0109_issuer(adr0109_issuer)
    return _prepare_lifecycle_v2_pre_effect_binding_issuer(
        root=root,
        request=request,
        result=result,
        transport_quiescence=transport_quiescence,
        pre_effect_intent=pre_effect_intent,
        observation_issuer_identity=exact_issuer,
        challenge_source=secrets.token_bytes,
    )


def _bind_lifecycle_v2_pre_effect_adr0109_observation_once(
    binding_issuer: object,
    *,
    postcondition: object,
    adr0109_issuer: object,
) -> LifecycleV2PreEffectBinding:
    if type(binding_issuer) is not _LifecycleV2PreEffectBindingIssuer:
        raise TrustedTimeGracefulStopV2Rejected(
            "pre-effect ADR-0109 binding issuer is invalid"
        )
    observation = _consume_exact_adr0109_observation(
        postcondition,
        issuer=adr0109_issuer,
        bridge_identity=binding_issuer,
    )
    return _bind_lifecycle_v2_pre_effect_observation_once(
        binding_issuer,
        observation=observation,
    )


def _prepare_lifecycle_v2_post_teardown_adr0109_binding_issuer(
    *,
    root: LifecycleV2Root,
    published_prefix_through_ordinal_18: LifecycleV2Transcript,
    pre_effect_binding: LifecycleV2PreEffectBinding,
    teardown_result_records: tuple[LifecycleV2ProgressRecord, ...],
    post_teardown_intent: LifecycleV2ProgressRecord,
    adr0109_issuer: object,
) -> _LifecycleV2PostTeardownBindingIssuer:
    exact_issuer = _require_exact_adr0109_issuer(adr0109_issuer)
    return _prepare_lifecycle_v2_post_teardown_binding_issuer(
        root=root,
        published_prefix_through_ordinal_18=published_prefix_through_ordinal_18,
        pre_effect_binding=pre_effect_binding,
        teardown_result_records=teardown_result_records,
        post_teardown_intent=post_teardown_intent,
        observation_issuer_identity=exact_issuer,
        challenge_source=secrets.token_bytes,
    )


def _bind_lifecycle_v2_post_teardown_adr0109_observation_once(
    binding_issuer: object,
    *,
    postcondition: object,
    adr0109_issuer: object,
) -> LifecycleV2PostTeardownBinding:
    if type(binding_issuer) is not _LifecycleV2PostTeardownBindingIssuer:
        raise TrustedTimeGracefulStopV2Rejected(
            "post-teardown ADR-0109 binding issuer is invalid"
        )
    observation = _consume_exact_adr0109_observation(
        postcondition,
        issuer=adr0109_issuer,
        bridge_identity=binding_issuer,
    )
    return _bind_lifecycle_v2_post_teardown_observation_once(
        binding_issuer,
        observation=observation,
    )
