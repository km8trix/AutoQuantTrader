from __future__ import annotations

import json
import sys

import pytest

from apps.trader.main import (
    DEFAULT_PAPER_DEPLOYMENT_ID,
    DEFAULT_PAPER_DEPLOYMENT_REVISION,
    build_repository_paper_smoke_preflight,
    main,
)
from packages.application.no_exposure_smoke_strategy import (
    NO_EXPOSURE_SMOKE_ARTIFACT_SHA256,
    NO_EXPOSURE_SMOKE_MANIFEST_SHA256,
)
from packages.application.paper_deployment import PaperDeploymentBlocker


def test_repository_preflight_verifies_artifact_and_preserves_external_blockers() -> None:
    preflight = build_repository_paper_smoke_preflight()

    assert preflight.decision.deployment_id == DEFAULT_PAPER_DEPLOYMENT_ID
    assert preflight.decision.revision_id == DEFAULT_PAPER_DEPLOYMENT_REVISION
    assert preflight.artifact.subprocess_spec.artifact_sha256 == (NO_EXPOSURE_SMOKE_ARTIFACT_SHA256)
    assert preflight.artifact.manifest_sha256 == NO_EXPOSURE_SMOKE_MANIFEST_SHA256
    assert (
        PaperDeploymentBlocker.STRATEGY_ARTIFACT_SOURCE_MISSING not in preflight.readiness.blockers
    )
    assert (
        PaperDeploymentBlocker.STRATEGY_MANIFEST_SOURCE_MISSING not in preflight.readiness.blockers
    )
    assert PaperDeploymentBlocker.DATABASE_SECRET_SOURCE_MISSING in (
        preflight.readiness.smoke_blockers
    )
    assert PaperDeploymentBlocker.AUTHORITATIVE_RISK_EVIDENCE_MISSING in (
        preflight.readiness.activation_blockers
    )
    assert PaperDeploymentBlocker.BROKER_SECRET_SOURCE_MISSING in (
        preflight.readiness.activation_blockers
    )
    assert PaperDeploymentBlocker.PRIMARY_ALERT_SECRET_SOURCE_MISSING in (
        preflight.readiness.activation_blockers
    )
    assert PaperDeploymentBlocker.FALLBACK_ALERT_SECRET_SOURCE_MISSING in (
        preflight.readiness.activation_blockers
    )
    assert PaperDeploymentBlocker.ALERT_ROUTE_SOURCE_MISSING in (
        preflight.readiness.activation_blockers
    )
    assert PaperDeploymentBlocker.EXTERNAL_ALERTS_DEFERRED in (
        preflight.readiness.activation_blockers
    )
    assert not preflight.readiness.smoke_deployable
    assert not preflight.readiness.phase5_activation_ready
    assert not preflight.readiness.broker_action_authorized
    assert not preflight.readiness.new_exposure_authorized


def test_public_preflight_payload_is_secret_free_and_non_authorizing() -> None:
    preflight = build_repository_paper_smoke_preflight(
        deployment_id="paper-smoke-public-projection",
        revision_id="release-test-1",
    )

    payload = preflight.public_payload
    serialized = json.dumps(payload, sort_keys=True)

    assert payload["status"] == "not_ready"
    assert payload["smoke_deployable"] is False
    assert payload["phase5_activation_ready"] is False
    assert payload["broker_action_authorized"] is False
    assert payload["new_exposure_authorized"] is False
    assert payload["live_trading_authorized"] is False
    assert payload["automatic_rearm_authorized"] is False
    assert payload["public_inbound_authorized"] is False
    assert payload["profile"] == {
        "broker_mode": "alpaca_paper",
        "database_plan": "supabase_free",
        "database_provider": "supabase_managed_postgresql",
        "fallback_alert_provider": "deferred",
        "primary_alert_provider": "deferred",
        "telemetry_provider": "sentry",
        "worker_provider": "local_owner_supervised",
    }
    assert payload["strategy"] == {
        "artifact_sha256": NO_EXPOSURE_SMOKE_ARTIFACT_SHA256,
        "configuration_sha256": preflight.artifact.strategy_configuration_sha256,
        "exposure_authorized": False,
        "manifest_sha256": NO_EXPOSURE_SMOKE_MANIFEST_SHA256,
        "strategy_id": preflight.artifact.strategy_id,
        "strategy_version": preflight.artifact.strategy_version,
        "verified": True,
    }
    for forbidden in (
        "postgresql://",
        "secret://",
        "api_key",
        "routing_key",
        "phone",
        "recipient",
    ):
        assert forbidden not in serialized.lower()


def test_local_once_inspects_profile_without_claiming_readiness(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("AQT_ENVIRONMENT", "local")
    monkeypatch.setattr(sys, "argv", ["autoquant-trader", "--once"])

    with pytest.raises(SystemExit) as stopped:
        main()

    assert stopped.value.code == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["requested_environment"] == "local"
    assert payload["status"] == "not_ready"
    assert payload["smoke_deployable"] is False


def test_paper_once_exits_not_ready_while_external_smoke_sources_are_unbound(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("AQT_ENVIRONMENT", "paper")
    monkeypatch.setenv("AQT_PAPER_DEPLOYMENT_ID", "paper-smoke-cli")
    monkeypatch.setenv("AQT_PAPER_DEPLOYMENT_REVISION", "release-cli-1")
    monkeypatch.setattr(sys, "argv", ["autoquant-trader", "--once"])

    with pytest.raises(SystemExit) as stopped:
        main()

    assert stopped.value.code == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["requested_environment"] == "paper"
    assert payload["deployment_id"] == "paper-smoke-cli"
    assert payload["deployment_revision"] == "release-cli-1"
    assert payload["status"] == "not_ready"
    assert "database_secret_source_missing" in payload["smoke_blockers"]


def test_render_environment_cannot_substitute_the_local_deployment_revision(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("AQT_ENVIRONMENT", "paper")
    monkeypatch.delenv("AQT_PAPER_DEPLOYMENT_REVISION", raising=False)
    monkeypatch.setenv("RENDER_GIT_COMMIT", "a" * 40)
    monkeypatch.setattr(sys, "argv", ["autoquant-trader", "--once"])

    with pytest.raises(SystemExit) as stopped:
        main()

    assert stopped.value.code == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["deployment_revision"] == DEFAULT_PAPER_DEPLOYMENT_REVISION
    assert payload["smoke_deployable"] is False


@pytest.mark.parametrize(
    ("environment", "reason"),
    [
        ("live", "live_environment_rejected"),
        ("unexpected", "environment_invalid"),
    ],
)
def test_cli_rejects_live_or_unknown_environment_before_profile_loading(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    environment: str,
    reason: str,
) -> None:
    monkeypatch.setenv("AQT_ENVIRONMENT", environment)
    monkeypatch.setattr(sys, "argv", ["autoquant-trader", "--once"])

    with pytest.raises(SystemExit) as stopped:
        main()

    assert stopped.value.code == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "broker_action_authorized": False,
        "live_trading_authorized": False,
        "mode": "paper_smoke_preflight",
        "new_exposure_authorized": False,
        "public_inbound_authorized": False,
        "reason": reason,
        "service": "trader",
        "status": "not_ready",
    }
