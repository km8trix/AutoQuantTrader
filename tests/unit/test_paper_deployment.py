from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from packages.application.no_exposure_smoke_strategy import (
    NO_EXPOSURE_SMOKE_ARTIFACT_SHA256,
    NO_EXPOSURE_SMOKE_MANIFEST_SHA256,
    NO_EXPOSURE_SMOKE_STRATEGY_ID,
)
from packages.application.paper_deployment import (
    AlertProviderIndependenceEvidence,
    AuthoritativeRiskEvidence,
    AuthoritativeSourcePin,
    CorrectionSafeFillEvidence,
    DeployedPaperDrillEvidence,
    ExternalHeartbeatWatchdogEvidence,
    FixedPausedControlAlertEvidence,
    OpaqueSecretReference,
    PaperAlertProvider,
    PaperBrokerMode,
    PaperDatabasePlan,
    PaperDatabaseProvider,
    PaperDeploymentAuthoritativeSources,
    PaperDeploymentBlocker,
    PaperDeploymentConflict,
    PaperDeploymentEnvironment,
    PaperDeploymentError,
    PaperDeploymentEvidence,
    PaperDeploymentNetworkMode,
    PaperSecretPurpose,
    PaperSourceKind,
    PaperTelemetryProvider,
    PaperWorkerProvider,
    PinnedNoExposureStrategy,
    QualifiedReconciliationEvidence,
    RecommendedPaperDeployment,
    TrustedTimeManualRearmEvidence,
    assess_paper_deployment_readiness,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _decision() -> RecommendedPaperDeployment:
    return RecommendedPaperDeployment.create(
        deployment_id="aqt-paper-smoke",
        revision_id="release-2026-07-29.1",
    )


def _secret(purpose: PaperSecretPurpose) -> OpaqueSecretReference:
    return OpaqueSecretReference(
        purpose=purpose,
        reference_id=f"secret://paper/local-owner-env/aqt/{purpose.value}",
        version_id=f"{purpose.value}-v1",
    )


def _source(
    kind: PaperSourceKind,
    *,
    content_sha256: str | None = None,
) -> AuthoritativeSourcePin:
    if content_sha256 is None:
        content_sha256 = _digest(kind.value)
    return AuthoritativeSourcePin(
        kind=kind,
        source_id=f"aqt-paper-{kind.value}",
        revision_id="release-2026-07-29.1",
        content_sha256=content_sha256,
    )


def _sources() -> PaperDeploymentAuthoritativeSources:
    return PaperDeploymentAuthoritativeSources(
        database_credentials=_secret(PaperSecretPurpose.DATABASE),
        broker_credentials=_secret(PaperSecretPurpose.BROKER),
        telemetry_credentials=_secret(PaperSecretPurpose.TELEMETRY),
        primary_alert_credentials=_secret(PaperSecretPurpose.PRIMARY_ALERT),
        fallback_alert_credentials=_secret(PaperSecretPurpose.FALLBACK_ALERT),
        deployment_spec=_source(PaperSourceKind.DEPLOYMENT_SPEC),
        runtime_image=_source(PaperSourceKind.RUNTIME_IMAGE),
        alert_route_plan=_source(PaperSourceKind.ALERT_ROUTE_PLAN),
        strategy_artifact=_source(
            PaperSourceKind.STRATEGY_ARTIFACT,
            content_sha256=NO_EXPOSURE_SMOKE_ARTIFACT_SHA256,
        ),
        strategy_manifest=_source(
            PaperSourceKind.STRATEGY_MANIFEST,
            content_sha256=NO_EXPOSURE_SMOKE_MANIFEST_SHA256,
        ),
        risk_policy=_source(PaperSourceKind.RISK_POLICY),
        fill_correction_policy=_source(PaperSourceKind.FILL_CORRECTION_POLICY),
        reconciliation_policy=_source(PaperSourceKind.RECONCILIATION_POLICY),
        trusted_time_policy=_source(PaperSourceKind.TRUSTED_TIME_POLICY),
        manual_rearm_policy=_source(PaperSourceKind.MANUAL_REARM_POLICY),
        control_alert_policy=_source(PaperSourceKind.CONTROL_ALERT_POLICY),
        heartbeat_watchdog_spec=_source(PaperSourceKind.HEARTBEAT_WATCHDOG_SPEC),
        deployed_drill_plan=_source(PaperSourceKind.DEPLOYED_DRILL_PLAN),
    )


def _independence(
    sources: PaperDeploymentAuthoritativeSources,
) -> AlertProviderIndependenceEvidence:
    assert sources.alert_route_plan is not None
    assert sources.primary_alert_credentials is not None
    assert sources.fallback_alert_credentials is not None
    return AlertProviderIndependenceEvidence(
        primary_provider=PaperAlertProvider.PAGERDUTY,
        fallback_provider=PaperAlertProvider.TWILIO_SMS,
        alert_route_plan_sha256=sources.alert_route_plan.content_sha256,
        primary_secret_reference_sha256=sources.primary_alert_credentials.semantic_sha256,
        fallback_secret_reference_sha256=sources.fallback_alert_credentials.semantic_sha256,
        provider_accounts_distinct=True,
        credential_sources_distinct=True,
        delivery_transports_distinct=True,
        failure_domains_distinct=True,
        verified_in_deployed_environment=True,
        evidence_sha256=_digest("provider-independence"),
    )


def _risk(sources: PaperDeploymentAuthoritativeSources) -> AuthoritativeRiskEvidence:
    assert sources.risk_policy is not None
    return AuthoritativeRiskEvidence(
        risk_policy_sha256=sources.risk_policy.content_sha256,
        moderate_risk_profile_activated=True,
        durable_authoritative_head_verified=True,
        caller_override_rejected=True,
        evidence_sha256=_digest("authoritative-risk"),
    )


def _fills(sources: PaperDeploymentAuthoritativeSources) -> CorrectionSafeFillEvidence:
    assert sources.fill_correction_policy is not None
    return CorrectionSafeFillEvidence(
        fill_correction_policy_sha256=sources.fill_correction_policy.content_sha256,
        durable_fill_ledger_verified=True,
        bust_replace_chain_verified=True,
        unresolved_correction_blocks_readiness=True,
        evidence_sha256=_digest("correction-safe-fills"),
    )


def _reconciliation(
    sources: PaperDeploymentAuthoritativeSources,
) -> QualifiedReconciliationEvidence:
    assert sources.reconciliation_policy is not None
    return QualifiedReconciliationEvidence(
        reconciliation_policy_sha256=sources.reconciliation_policy.content_sha256,
        orders_positions_activity_qualified=True,
        correction_safe_fills_consumed=True,
        zero_unresolved_differences=True,
        evidence_sha256=_digest("qualified-reconciliation"),
    )


def _time_rearm(
    sources: PaperDeploymentAuthoritativeSources,
) -> TrustedTimeManualRearmEvidence:
    assert sources.trusted_time_policy is not None
    assert sources.manual_rearm_policy is not None
    return TrustedTimeManualRearmEvidence(
        trusted_time_policy_sha256=sources.trusted_time_policy.content_sha256,
        manual_rearm_policy_sha256=sources.manual_rearm_policy.content_sha256,
        durable_trusted_time_healthy=True,
        rollback_staleness_trip_verified=True,
        automatic_rearm_disabled=True,
        manual_rearm_evidence_durable=True,
        evidence_sha256=_digest("trusted-time-manual-rearm"),
    )


def _fixed_paused(
    sources: PaperDeploymentAuthoritativeSources,
) -> FixedPausedControlAlertEvidence:
    assert sources.control_alert_policy is not None
    assert sources.alert_route_plan is not None
    return FixedPausedControlAlertEvidence(
        control_alert_policy_sha256=sources.control_alert_policy.content_sha256,
        alert_route_plan_sha256=sources.alert_route_plan.content_sha256,
        fixed_paused_state_observed=True,
        automatic_running_transition_disabled=True,
        control_trip_alert_policy_activated=True,
        primary_and_fallback_routes_verified=True,
        evidence_sha256=_digest("fixed-paused-control-alert"),
    )


def _heartbeat(
    sources: PaperDeploymentAuthoritativeSources,
) -> ExternalHeartbeatWatchdogEvidence:
    assert sources.heartbeat_watchdog_spec is not None
    return ExternalHeartbeatWatchdogEvidence(
        heartbeat_watchdog_spec_sha256=sources.heartbeat_watchdog_spec.content_sha256,
        external_failure_domain_verified=True,
        missed_heartbeat_trip_verified=True,
        critical_alert_delivery_verified=True,
        evidence_sha256=_digest("external-heartbeat"),
    )


def _drill(
    decision: RecommendedPaperDeployment,
    sources: PaperDeploymentAuthoritativeSources,
) -> DeployedPaperDrillEvidence:
    assert sources.deployment_spec is not None
    assert sources.runtime_image is not None
    assert sources.deployed_drill_plan is not None
    assert sources.strategy_artifact is not None
    assert sources.strategy_manifest is not None
    return DeployedPaperDrillEvidence(
        deployment_id=decision.deployment_id,
        decision_sha256=decision.semantic_sha256,
        deployment_spec_sha256=sources.deployment_spec.content_sha256,
        runtime_image_sha256=sources.runtime_image.content_sha256,
        deployed_drill_plan_sha256=sources.deployed_drill_plan.content_sha256,
        strategy_artifact_sha256=sources.strategy_artifact.content_sha256,
        strategy_manifest_sha256=sources.strategy_manifest.content_sha256,
        campaign_id="phase5-paper-drill-001",
        deployed_environment_observed=True,
        all_required_scenarios_passed=True,
        timing_deadlines_met=True,
        no_new_exposure_observed=True,
        live_trading_disabled_observed=True,
        public_inbound_absent_observed=True,
        manual_rearm_only_observed=True,
        evidence_sha256=_digest("deployed-drill"),
    )


def _complete_evidence(
    decision: RecommendedPaperDeployment,
    *,
    sources: PaperDeploymentAuthoritativeSources | None = None,
) -> PaperDeploymentEvidence:
    if sources is None:
        sources = _sources()
    return PaperDeploymentEvidence(
        sources=sources,
        provider_independence=_independence(sources),
        authoritative_risk=_risk(sources),
        correction_safe_fills=_fills(sources),
        qualified_reconciliation=_reconciliation(sources),
        trusted_time_manual_rearm=_time_rearm(sources),
        fixed_paused_control_alert=_fixed_paused(sources),
        external_heartbeat_watchdog=_heartbeat(sources),
        deployed_drill=_drill(decision, sources),
    )


def test_recommendation_freezes_the_selected_provider_stack_and_artifact() -> None:
    decision = _decision()

    assert decision.environment is PaperDeploymentEnvironment.PAPER
    assert decision.network_mode is PaperDeploymentNetworkMode.PRIVATE_OUTBOUND_ONLY
    assert decision.database_provider is PaperDatabaseProvider.SUPABASE_MANAGED_POSTGRESQL
    assert decision.database_plan is PaperDatabasePlan.SUPABASE_FREE
    assert decision.worker_provider is PaperWorkerProvider.LOCAL_OWNER_SUPERVISED
    assert decision.broker_mode is PaperBrokerMode.ALPACA_PAPER
    assert decision.telemetry_provider is PaperTelemetryProvider.SENTRY
    assert decision.primary_alert_provider is PaperAlertProvider.DEFERRED
    assert decision.fallback_alert_provider is PaperAlertProvider.DEFERRED
    assert decision.strategy.strategy_id == NO_EXPOSURE_SMOKE_STRATEGY_ID
    assert decision.strategy.artifact_sha256 == NO_EXPOSURE_SMOKE_ARTIFACT_SHA256
    assert decision.strategy.manifest_sha256 == NO_EXPOSURE_SMOKE_MANIFEST_SHA256
    assert decision.strategy.matches_recommendation
    assert not decision.broker_action_authorized
    assert not decision.new_exposure_authorized
    assert not decision.live_trading_authorized
    assert not decision.public_inbound_authorized


def test_missing_authoritative_sources_and_deployed_proof_fail_closed_in_fixed_order() -> None:
    report = assess_paper_deployment_readiness(
        decision=_decision(),
        evidence=PaperDeploymentEvidence(
            sources=PaperDeploymentAuthoritativeSources(),
        ),
    )

    assert report.blockers == (
        PaperDeploymentBlocker.DATABASE_SECRET_SOURCE_MISSING,
        PaperDeploymentBlocker.BROKER_SECRET_SOURCE_MISSING,
        PaperDeploymentBlocker.TELEMETRY_SECRET_SOURCE_MISSING,
        PaperDeploymentBlocker.PRIMARY_ALERT_SECRET_SOURCE_MISSING,
        PaperDeploymentBlocker.FALLBACK_ALERT_SECRET_SOURCE_MISSING,
        PaperDeploymentBlocker.DEPLOYMENT_SPEC_SOURCE_MISSING,
        PaperDeploymentBlocker.RUNTIME_IMAGE_SOURCE_MISSING,
        PaperDeploymentBlocker.ALERT_ROUTE_SOURCE_MISSING,
        PaperDeploymentBlocker.STRATEGY_ARTIFACT_SOURCE_MISSING,
        PaperDeploymentBlocker.STRATEGY_MANIFEST_SOURCE_MISSING,
        PaperDeploymentBlocker.PROVIDER_INDEPENDENCE_EVIDENCE_MISSING,
        PaperDeploymentBlocker.RISK_POLICY_SOURCE_MISSING,
        PaperDeploymentBlocker.AUTHORITATIVE_RISK_EVIDENCE_MISSING,
        PaperDeploymentBlocker.FILL_CORRECTION_SOURCE_MISSING,
        PaperDeploymentBlocker.CORRECTION_SAFE_FILL_EVIDENCE_MISSING,
        PaperDeploymentBlocker.RECONCILIATION_SOURCE_MISSING,
        PaperDeploymentBlocker.QUALIFIED_RECONCILIATION_EVIDENCE_MISSING,
        PaperDeploymentBlocker.TRUSTED_TIME_SOURCE_MISSING,
        PaperDeploymentBlocker.MANUAL_REARM_SOURCE_MISSING,
        PaperDeploymentBlocker.TRUSTED_TIME_REARM_EVIDENCE_MISSING,
        PaperDeploymentBlocker.CONTROL_ALERT_POLICY_SOURCE_MISSING,
        PaperDeploymentBlocker.FIXED_PAUSED_CONTROL_ALERT_EVIDENCE_MISSING,
        PaperDeploymentBlocker.HEARTBEAT_WATCHDOG_SOURCE_MISSING,
        PaperDeploymentBlocker.EXTERNAL_HEARTBEAT_EVIDENCE_MISSING,
        PaperDeploymentBlocker.DEPLOYED_DRILL_PLAN_SOURCE_MISSING,
        PaperDeploymentBlocker.DEPLOYED_DRILL_EVIDENCE_MISSING,
        PaperDeploymentBlocker.LOCAL_OWNER_SUPERVISION_ONLY,
        PaperDeploymentBlocker.EXTERNAL_ALERTS_DEFERRED,
    )
    assert not report.ready
    assert not report.smoke_deployable
    assert not report.phase5_activation_ready


def test_complete_synthetic_evidence_cannot_close_deferred_activation_gates() -> None:
    decision = _decision()
    evidence = _complete_evidence(decision)

    first = assess_paper_deployment_readiness(decision=decision, evidence=evidence)
    second = assess_paper_deployment_readiness(decision=decision, evidence=evidence)

    assert not first.ready
    assert first.smoke_deployable
    assert not first.phase5_activation_ready
    assert first.blockers == (
        PaperDeploymentBlocker.LOCAL_OWNER_SUPERVISION_ONLY,
        PaperDeploymentBlocker.EXTERNAL_ALERTS_DEFERRED,
    )
    assert first == second
    assert first.semantic_sha256 == second.semantic_sha256
    assert len(first.report_id) <= 128
    assert not first.broker_action_authorized
    assert not first.new_exposure_authorized
    assert not first.live_trading_authorized
    assert not first.public_inbound_authorized
    assert not first.automatic_rearm_authorized


def test_live_broker_live_environment_and_public_inbound_are_all_blocked() -> None:
    unsafe = replace(
        _decision(),
        environment=PaperDeploymentEnvironment.LIVE,
        broker_mode=PaperBrokerMode.ALPACA_LIVE,
        network_mode=PaperDeploymentNetworkMode.PUBLIC_INBOUND,
    )
    report = assess_paper_deployment_readiness(
        decision=unsafe,
        evidence=_complete_evidence(unsafe),
    )

    assert report.blockers == (
        PaperDeploymentBlocker.ENVIRONMENT_NOT_PAPER,
        PaperDeploymentBlocker.LIVE_BROKER_SELECTED,
        PaperDeploymentBlocker.PUBLIC_INBOUND_ENABLED,
        PaperDeploymentBlocker.LOCAL_OWNER_SUPERVISION_ONLY,
        PaperDeploymentBlocker.EXTERNAL_ALERTS_DEFERRED,
    )
    assert not report.ready


def test_substituted_database_worker_telemetry_and_alert_providers_are_blocked() -> None:
    substituted = replace(
        _decision(),
        database_provider=PaperDatabaseProvider.OTHER,
        database_plan=PaperDatabasePlan.OTHER,
        worker_provider=PaperWorkerProvider.OTHER,
        telemetry_provider=PaperTelemetryProvider.OTHER,
        primary_alert_provider=PaperAlertProvider.OTHER,
        fallback_alert_provider=PaperAlertProvider.OTHER,
    )
    report = assess_paper_deployment_readiness(
        decision=substituted,
        evidence=_complete_evidence(substituted),
    )

    assert report.blockers == (
        PaperDeploymentBlocker.DATABASE_PROVIDER_NOT_RECOMMENDED,
        PaperDeploymentBlocker.DATABASE_PLAN_NOT_SUPABASE_FREE,
        PaperDeploymentBlocker.WORKER_PROVIDER_NOT_LOCAL_OWNER_SUPERVISED,
        PaperDeploymentBlocker.TELEMETRY_PROVIDER_NOT_RECOMMENDED,
        PaperDeploymentBlocker.ALERT_PROVIDER_NOT_DEFERRED,
    )


def test_smoke_packaging_is_distinct_from_phase5_activation_readiness() -> None:
    decision = _decision()
    report = assess_paper_deployment_readiness(
        decision=decision,
        evidence=PaperDeploymentEvidence(sources=_sources()),
    )

    assert report.smoke_deployable
    assert not report.phase5_activation_ready
    assert not report.ready
    assert report.smoke_blockers == ()
    assert report.activation_blockers == (
        PaperDeploymentBlocker.PROVIDER_INDEPENDENCE_EVIDENCE_MISSING,
        PaperDeploymentBlocker.AUTHORITATIVE_RISK_EVIDENCE_MISSING,
        PaperDeploymentBlocker.CORRECTION_SAFE_FILL_EVIDENCE_MISSING,
        PaperDeploymentBlocker.QUALIFIED_RECONCILIATION_EVIDENCE_MISSING,
        PaperDeploymentBlocker.TRUSTED_TIME_REARM_EVIDENCE_MISSING,
        PaperDeploymentBlocker.FIXED_PAUSED_CONTROL_ALERT_EVIDENCE_MISSING,
        PaperDeploymentBlocker.EXTERNAL_HEARTBEAT_EVIDENCE_MISSING,
        PaperDeploymentBlocker.DEPLOYED_DRILL_EVIDENCE_MISSING,
        PaperDeploymentBlocker.LOCAL_OWNER_SUPERVISION_ONLY,
        PaperDeploymentBlocker.EXTERNAL_ALERTS_DEFERRED,
    )


@pytest.mark.parametrize(
    ("field_name", "expected"),
    (
        (
            "authoritative_risk",
            PaperDeploymentBlocker.AUTHORITATIVE_RISK_EVIDENCE_MISSING,
        ),
        (
            "correction_safe_fills",
            PaperDeploymentBlocker.CORRECTION_SAFE_FILL_EVIDENCE_MISSING,
        ),
        (
            "qualified_reconciliation",
            PaperDeploymentBlocker.QUALIFIED_RECONCILIATION_EVIDENCE_MISSING,
        ),
        (
            "trusted_time_manual_rearm",
            PaperDeploymentBlocker.TRUSTED_TIME_REARM_EVIDENCE_MISSING,
        ),
        (
            "fixed_paused_control_alert",
            PaperDeploymentBlocker.FIXED_PAUSED_CONTROL_ALERT_EVIDENCE_MISSING,
        ),
        (
            "external_heartbeat_watchdog",
            PaperDeploymentBlocker.EXTERNAL_HEARTBEAT_EVIDENCE_MISSING,
        ),
    ),
)
def test_each_activation_authority_has_a_distinct_missing_evidence_blocker(
    field_name: str,
    expected: PaperDeploymentBlocker,
) -> None:
    decision = _decision()
    evidence = replace(
        _complete_evidence(decision),
        **{field_name: None},  # type: ignore[arg-type]
    )

    report = assess_paper_deployment_readiness(decision=decision, evidence=evidence)

    assert report.blockers == (
        expected,
        PaperDeploymentBlocker.LOCAL_OWNER_SUPERVISION_ONLY,
        PaperDeploymentBlocker.EXTERNAL_ALERTS_DEFERRED,
    )
    assert report.smoke_deployable
    assert not report.phase5_activation_ready


def test_each_activation_authority_must_be_operationally_verified() -> None:
    decision = _decision()
    complete = _complete_evidence(decision)
    assert complete.authoritative_risk is not None
    assert complete.correction_safe_fills is not None
    assert complete.qualified_reconciliation is not None
    assert complete.trusted_time_manual_rearm is not None
    assert complete.fixed_paused_control_alert is not None
    assert complete.external_heartbeat_watchdog is not None
    unverified = replace(
        complete,
        authoritative_risk=replace(
            complete.authoritative_risk,
            durable_authoritative_head_verified=False,
        ),
        correction_safe_fills=replace(
            complete.correction_safe_fills,
            bust_replace_chain_verified=False,
        ),
        qualified_reconciliation=replace(
            complete.qualified_reconciliation,
            zero_unresolved_differences=False,
        ),
        trusted_time_manual_rearm=replace(
            complete.trusted_time_manual_rearm,
            automatic_rearm_disabled=False,
        ),
        fixed_paused_control_alert=replace(
            complete.fixed_paused_control_alert,
            fixed_paused_state_observed=False,
        ),
        external_heartbeat_watchdog=replace(
            complete.external_heartbeat_watchdog,
            external_failure_domain_verified=False,
        ),
    )

    report = assess_paper_deployment_readiness(decision=decision, evidence=unverified)

    assert report.blockers == (
        PaperDeploymentBlocker.AUTHORITATIVE_RISK_UNVERIFIED,
        PaperDeploymentBlocker.CORRECTION_SAFE_FILL_UNVERIFIED,
        PaperDeploymentBlocker.QUALIFIED_RECONCILIATION_UNVERIFIED,
        PaperDeploymentBlocker.TRUSTED_TIME_REARM_UNVERIFIED,
        PaperDeploymentBlocker.FIXED_PAUSED_CONTROL_ALERT_UNVERIFIED,
        PaperDeploymentBlocker.EXTERNAL_HEARTBEAT_UNVERIFIED,
        PaperDeploymentBlocker.LOCAL_OWNER_SUPERVISION_ONLY,
        PaperDeploymentBlocker.EXTERNAL_ALERTS_DEFERRED,
    )


def test_changed_strategy_pin_and_changed_authoritative_artifacts_are_blocked() -> None:
    changed_pin = replace(
        PinnedNoExposureStrategy.recommended(),
        artifact_sha256=_digest("unreviewed-artifact"),
    )
    changed_decision = replace(_decision(), strategy=changed_pin)
    changed_sources = replace(
        _sources(),
        strategy_artifact=_source(
            PaperSourceKind.STRATEGY_ARTIFACT,
            content_sha256=_digest("unreviewed-artifact"),
        ),
        strategy_manifest=_source(
            PaperSourceKind.STRATEGY_MANIFEST,
            content_sha256=_digest("unreviewed-manifest"),
        ),
    )
    report = assess_paper_deployment_readiness(
        decision=changed_decision,
        evidence=_complete_evidence(changed_decision, sources=changed_sources),
    )

    assert report.blockers == (
        PaperDeploymentBlocker.STRATEGY_PIN_MISMATCH,
        PaperDeploymentBlocker.STRATEGY_ARTIFACT_SOURCE_MISMATCH,
        PaperDeploymentBlocker.STRATEGY_MANIFEST_SOURCE_MISMATCH,
        PaperDeploymentBlocker.LOCAL_OWNER_SUPERVISION_ONLY,
        PaperDeploymentBlocker.EXTERNAL_ALERTS_DEFERRED,
    )


def test_provider_independence_must_bind_sources_and_be_operationally_verified() -> None:
    decision = _decision()
    sources = _sources()
    unverified = replace(
        _independence(sources),
        failure_domains_distinct=False,
        verified_in_deployed_environment=False,
    )
    report = assess_paper_deployment_readiness(
        decision=decision,
        evidence=replace(
            _complete_evidence(decision, sources=sources),
            provider_independence=unverified,
        ),
    )
    assert report.blockers == (
        PaperDeploymentBlocker.PROVIDER_INDEPENDENCE_UNVERIFIED,
        PaperDeploymentBlocker.LOCAL_OWNER_SUPERVISION_ONLY,
        PaperDeploymentBlocker.EXTERNAL_ALERTS_DEFERRED,
    )

    misbound = replace(
        _independence(sources),
        alert_route_plan_sha256=_digest("different-route-plan"),
    )
    report = assess_paper_deployment_readiness(
        decision=decision,
        evidence=replace(
            _complete_evidence(decision, sources=sources),
            provider_independence=misbound,
        ),
    )
    assert report.blockers == (
        PaperDeploymentBlocker.PROVIDER_INDEPENDENCE_BINDING_MISMATCH,
        PaperDeploymentBlocker.LOCAL_OWNER_SUPERVISION_ONLY,
        PaperDeploymentBlocker.EXTERNAL_ALERTS_DEFERRED,
    )


def test_only_deployed_bound_passing_drill_evidence_satisfies_readiness() -> None:
    decision = _decision()
    sources = _sources()
    local_only = replace(
        _drill(decision, sources),
        deployed_environment_observed=False,
    )
    report = assess_paper_deployment_readiness(
        decision=decision,
        evidence=replace(
            _complete_evidence(decision, sources=sources),
            deployed_drill=local_only,
        ),
    )
    assert report.blockers == (
        PaperDeploymentBlocker.DEPLOYED_DRILL_FAILED,
        PaperDeploymentBlocker.LOCAL_OWNER_SUPERVISION_ONLY,
        PaperDeploymentBlocker.EXTERNAL_ALERTS_DEFERRED,
    )

    misbound = replace(
        _drill(decision, sources),
        runtime_image_sha256=_digest("different-image"),
    )
    report = assess_paper_deployment_readiness(
        decision=decision,
        evidence=replace(
            _complete_evidence(decision, sources=sources),
            deployed_drill=misbound,
        ),
    )
    assert report.blockers == (
        PaperDeploymentBlocker.DEPLOYED_DRILL_BINDING_MISMATCH,
        PaperDeploymentBlocker.LOCAL_OWNER_SUPERVISION_ONLY,
        PaperDeploymentBlocker.EXTERNAL_ALERTS_DEFERRED,
    )


def test_secret_reference_rejects_values_and_never_exposes_reference_in_repr() -> None:
    reference_id = "secret://paper/render/aqt/broker"
    version_id = "broker-v1"
    reference = OpaqueSecretReference(
        purpose=PaperSecretPurpose.BROKER,
        reference_id=reference_id,
        version_id=version_id,
    )

    assert reference_id not in repr(reference)
    assert version_id not in repr(reference)
    assert reference_id not in reference.canonical_json
    assert version_id not in reference.canonical_json
    assert len(reference.semantic_sha256) == 64

    for raw_value in (
        "postgresql://user:password@example.invalid/db",
        "https://example.invalid/sentry-dsn",
        "secret://live/render/aqt/broker",
        "secret://bad ref",
    ):
        with pytest.raises(PaperDeploymentError, match="secret://paper/ reference"):
            OpaqueSecretReference(
                purpose=PaperSecretPurpose.DATABASE,
                reference_id=raw_value,
                version_id="v1",
            )


def test_source_and_secret_slots_reject_cross_purpose_bindings() -> None:
    with pytest.raises(PaperDeploymentConflict, match="wrong secret purpose"):
        PaperDeploymentAuthoritativeSources(
            database_credentials=_secret(PaperSecretPurpose.BROKER),
        )
    with pytest.raises(PaperDeploymentConflict, match="wrong source kind"):
        PaperDeploymentAuthoritativeSources(
            strategy_manifest=_source(PaperSourceKind.STRATEGY_ARTIFACT),
        )


def test_exact_types_bounded_text_digests_and_bools_are_enforced() -> None:
    decision = _decision()
    with pytest.raises(PaperDeploymentError, match="exact PaperDeploymentEnvironment"):
        replace(decision, environment="paper")  # type: ignore[arg-type]
    with pytest.raises(PaperDeploymentError, match="1-128"):
        replace(decision, deployment_id="x" * 129)
    with pytest.raises(PaperDeploymentError, match="lowercase SHA-256"):
        replace(
            decision.strategy,
            artifact_sha256="A" * 64,
        )
    with pytest.raises(PaperDeploymentError, match="exact bool"):
        replace(
            _independence(_sources()),
            provider_accounts_distinct=1,  # type: ignore[arg-type]
        )
    with pytest.raises(PaperDeploymentError, match="exact bool"):
        replace(
            _drill(decision, _sources()),
            all_required_scenarios_passed=1,  # type: ignore[arg-type]
        )


def test_semantic_identity_is_stable_and_changes_with_nonsecret_source_revision() -> None:
    left = _sources()
    right = _sources()
    assert left == right
    assert left.semantic_sha256 == right.semantic_sha256

    assert left.deployment_spec is not None
    changed = replace(
        left,
        deployment_spec=replace(
            left.deployment_spec,
            revision_id="release-2026-07-29.2",
        ),
    )
    assert left.semantic_sha256 != changed.semantic_sha256
