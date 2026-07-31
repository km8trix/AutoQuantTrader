"""Fail-closed composition root for the selected paper smoke deployment."""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass

from packages.application.no_exposure_smoke_strategy import (
    NoExposureSmokeArtifact,
    NoExposureSmokeArtifactError,
    load_no_exposure_smoke_artifact,
)
from packages.application.paper_deployment import (
    PAPER_DEPLOYMENT_CONTRACT_VERSION,
    AuthoritativeSourcePin,
    PaperDeploymentAuthoritativeSources,
    PaperDeploymentError,
    PaperDeploymentEvidence,
    PaperDeploymentReadinessReport,
    PaperSourceKind,
    RecommendedPaperDeployment,
    assess_paper_deployment_readiness,
)

DEFAULT_PAPER_DEPLOYMENT_ID = "aqt-paper-smoke"
DEFAULT_PAPER_DEPLOYMENT_REVISION = "unbound-preflight"


@dataclass(frozen=True, slots=True)
class PaperSmokePreflight:
    """Public, secret-free projection of one repository artifact preflight."""

    decision: RecommendedPaperDeployment
    artifact: NoExposureSmokeArtifact
    readiness: PaperDeploymentReadinessReport

    def __post_init__(self) -> None:
        if type(self.decision) is not RecommendedPaperDeployment:
            raise PaperDeploymentError("paper smoke preflight requires an exact decision")
        if type(self.artifact) is not NoExposureSmokeArtifact:
            raise PaperDeploymentError("paper smoke preflight requires an exact artifact")
        if type(self.readiness) is not PaperDeploymentReadinessReport:
            raise PaperDeploymentError("paper smoke preflight requires an exact readiness report")
        self.decision.__post_init__()
        self.artifact.__post_init__()
        self.readiness.__post_init__()
        if self.readiness.decision_sha256 != self.decision.semantic_sha256:
            raise PaperDeploymentError("paper smoke preflight decision binding is invalid")

    @property
    def public_payload(self) -> dict[str, object]:
        return {
            "activation_blockers": tuple(
                blocker.value for blocker in self.readiness.activation_blockers
            ),
            "automatic_rearm_authorized": False,
            "broker_action_authorized": False,
            "decision_sha256": self.decision.semantic_sha256,
            "deployment_id": self.decision.deployment_id,
            "deployment_revision": self.decision.revision_id,
            "live_trading_authorized": False,
            "mode": "paper_smoke_preflight",
            "new_exposure_authorized": False,
            "phase5_activation_ready": self.readiness.phase5_activation_ready,
            "profile_contract_version": PAPER_DEPLOYMENT_CONTRACT_VERSION,
            "profile": {
                "broker_mode": self.decision.broker_mode.value,
                "database_plan": self.decision.database_plan.value,
                "database_provider": self.decision.database_provider.value,
                "fallback_alert_provider": self.decision.fallback_alert_provider.value,
                "primary_alert_provider": self.decision.primary_alert_provider.value,
                "telemetry_provider": self.decision.telemetry_provider.value,
                "worker_provider": self.decision.worker_provider.value,
            },
            "public_inbound_authorized": False,
            "readiness_report_sha256": self.readiness.semantic_sha256,
            "service": "trader",
            "smoke_blockers": tuple(blocker.value for blocker in self.readiness.smoke_blockers),
            "smoke_deployable": self.readiness.smoke_deployable,
            "status": (
                "phase5_activation_ready"
                if self.readiness.phase5_activation_ready
                else ("smoke_preflight_ready" if self.readiness.smoke_deployable else "not_ready")
            ),
            "strategy": {
                "artifact_sha256": self.artifact.subprocess_spec.artifact_sha256,
                "configuration_sha256": self.artifact.strategy_configuration_sha256,
                "exposure_authorized": False,
                "manifest_sha256": self.artifact.manifest_sha256,
                "strategy_id": self.artifact.strategy_id,
                "strategy_version": self.artifact.strategy_version,
                "verified": True,
            },
        }


def build_repository_paper_smoke_preflight(
    *,
    deployment_id: str = DEFAULT_PAPER_DEPLOYMENT_ID,
    revision_id: str = DEFAULT_PAPER_DEPLOYMENT_REVISION,
) -> PaperSmokePreflight:
    """Verify checked-in artifact bytes and assess only evidence present here."""

    decision = RecommendedPaperDeployment.create(
        deployment_id=deployment_id,
        revision_id=revision_id,
    )
    artifact = load_no_exposure_smoke_artifact()
    sources = PaperDeploymentAuthoritativeSources(
        strategy_artifact=AuthoritativeSourcePin(
            kind=PaperSourceKind.STRATEGY_ARTIFACT,
            source_id="repository-no-exposure-smoke-artifact",
            revision_id=artifact.strategy_version,
            content_sha256=artifact.subprocess_spec.artifact_sha256,
        ),
        strategy_manifest=AuthoritativeSourcePin(
            kind=PaperSourceKind.STRATEGY_MANIFEST,
            source_id="repository-no-exposure-smoke-manifest",
            revision_id=artifact.strategy_version,
            content_sha256=artifact.manifest_sha256,
        ),
    )
    readiness = assess_paper_deployment_readiness(
        decision=decision,
        evidence=PaperDeploymentEvidence(sources=sources),
    )
    return PaperSmokePreflight(
        decision=decision,
        artifact=artifact,
        readiness=readiness,
    )


def _safe_failure_payload(reason: str) -> dict[str, object]:
    return {
        "broker_action_authorized": False,
        "live_trading_authorized": False,
        "mode": "paper_smoke_preflight",
        "new_exposure_authorized": False,
        "public_inbound_authorized": False,
        "reason": reason,
        "service": "trader",
        "status": "not_ready",
    }


def _deployment_revision_from_environment() -> str:
    return os.getenv(
        "AQT_PAPER_DEPLOYMENT_REVISION",
        DEFAULT_PAPER_DEPLOYMENT_REVISION,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--once",
        action="store_true",
        help="run the selected paper deployment preflight once and exit",
    )
    arguments = parser.parse_args()
    requested_environment = os.getenv("AQT_ENVIRONMENT", "local")
    if requested_environment not in {"local", "paper", "live"}:
        print(
            json.dumps(_safe_failure_payload("environment_invalid"), sort_keys=True),
            flush=True,
        )
        raise SystemExit(2)
    if requested_environment == "live":
        print(
            json.dumps(_safe_failure_payload("live_environment_rejected"), sort_keys=True),
            flush=True,
        )
        raise SystemExit(2)

    try:
        preflight = build_repository_paper_smoke_preflight(
            deployment_id=os.getenv(
                "AQT_PAPER_DEPLOYMENT_ID",
                DEFAULT_PAPER_DEPLOYMENT_ID,
            ),
            revision_id=_deployment_revision_from_environment(),
        )
    except (NoExposureSmokeArtifactError, PaperDeploymentError):
        print(
            json.dumps(
                _safe_failure_payload("deployment_profile_or_artifact_invalid"),
                sort_keys=True,
            ),
            flush=True,
        )
        raise SystemExit(2) from None

    payload = preflight.public_payload
    payload["requested_environment"] = requested_environment
    print(json.dumps(payload, sort_keys=True), flush=True)

    # No environment may turn a not-ready result into process success. This
    # keeps local diagnostics from becoming an accidental supervisor bypass.
    if not arguments.once or not preflight.readiness.smoke_deployable:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
