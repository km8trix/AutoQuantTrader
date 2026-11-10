from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest

from packages.adapters.alerts.approved_routes import (
    ApprovedCriticalAlertRouteError,
    ApprovedCriticalAlertRouteResolver,
)
from packages.application.critical_alert_delivery import (
    CriticalAlertProviderReceipt,
    CriticalAlertProviderRequest,
)
from packages.application.critical_alert_supervisor import CriticalAlertRouteBinding
from packages.domain.critical_alert import CriticalAlertIncident, CriticalAlertRoute

BASE = datetime(2026, 7, 29, 14, 0, tzinfo=UTC)


@dataclass(slots=True)
class _Port:
    provider_id: str

    def deliver(
        self,
        request: CriticalAlertProviderRequest,
        *,
        timeout_seconds: float,
    ) -> CriticalAlertProviderReceipt:
        del request, timeout_seconds
        return CriticalAlertProviderReceipt(provider_receipt_sha256="f" * 64)


def _binding(route: CriticalAlertRoute, provider_id: str, seed: str) -> CriticalAlertRouteBinding:
    return CriticalAlertRouteBinding(
        route=route,
        provider_id=provider_id,
        destination_sha256=seed * 64,
        recipient_set_sha256=seed.upper().lower() * 64,
    )


def _incident(scope_id: str = "paper-account-1") -> CriticalAlertIncident:
    return CriticalAlertIncident(
        scope_id=scope_id,
        source_id="strategy-supervisor",
        idempotency_key="critical-incident-0001",
        alert_code="strategy_deadline_exceeded",
        evidence_sha256="a" * 64,
        detected_at=BASE - timedelta(milliseconds=100),
        recorded_at=BASE,
        correlation_sha256="b" * 64,
    )


def _resolver() -> tuple[
    ApprovedCriticalAlertRouteResolver,
    CriticalAlertRouteBinding,
    _Port,
    CriticalAlertRouteBinding,
    _Port,
]:
    primary_binding = _binding(CriticalAlertRoute.PRIMARY, "pagerduty-primary", "c")
    escalation_binding = _binding(CriticalAlertRoute.ESCALATION, "twilio-fallback", "d")
    primary = _Port(primary_binding.provider_id)
    escalation = _Port(escalation_binding.provider_id)
    return (
        ApprovedCriticalAlertRouteResolver(
            expected_scope_id="paper-account-1",
            primary_binding=primary_binding,
            primary_adapter=primary,
            escalation_binding=escalation_binding,
            escalation_adapter=escalation,
        ),
        primary_binding,
        primary,
        escalation_binding,
        escalation,
    )


def test_resolver_returns_only_exact_account_bound_routes() -> None:
    resolver, primary_binding, primary, escalation_binding, escalation = _resolver()

    assert resolver.resolve(_incident(), primary_binding) is primary
    assert resolver.resolve(_incident(), escalation_binding) is escalation
    assert resolver.resolve(_incident("another-paper-account"), primary_binding) is None
    assert (
        resolver.resolve(
            _incident(),
            _binding(CriticalAlertRoute.PRIMARY, "pagerduty-primary", "e"),
        )
        is None
    )


def test_resolver_projection_contains_only_digests_and_redaction() -> None:
    resolver, primary_binding, _primary, escalation_binding, _escalation = _resolver()

    rendered = repr(resolver)
    assert "paper-account-1" not in rendered
    assert primary_binding.destination_sha256 not in rendered
    assert escalation_binding.destination_sha256 not in rendered
    assert "[REDACTED]" in rendered
    assert len(resolver.scope_sha256) == 64
    assert resolver.primary_binding_sha256 == primary_binding.semantic_sha256
    assert resolver.escalation_binding_sha256 == escalation_binding.semantic_sha256


def test_resolver_rejects_crossed_or_shared_provider_adapters() -> None:
    primary_binding = _binding(CriticalAlertRoute.PRIMARY, "pagerduty-primary", "c")
    escalation_binding = _binding(CriticalAlertRoute.ESCALATION, "twilio-fallback", "d")

    with pytest.raises(ApprovedCriticalAlertRouteError, match="conflicts"):
        ApprovedCriticalAlertRouteResolver(
            expected_scope_id="paper-account-1",
            primary_binding=primary_binding,
            primary_adapter=_Port("another-primary"),
            escalation_binding=escalation_binding,
            escalation_adapter=_Port(escalation_binding.provider_id),
        )

    shared = _Port("shared-provider")
    with pytest.raises(ApprovedCriticalAlertRouteError, match=r"conflicts|distinct"):
        ApprovedCriticalAlertRouteResolver(
            expected_scope_id="paper-account-1",
            primary_binding=_binding(
                CriticalAlertRoute.PRIMARY,
                "shared-provider",
                "c",
            ),
            primary_adapter=shared,
            escalation_binding=_binding(
                CriticalAlertRoute.ESCALATION,
                "shared-provider",
                "d",
            ),
            escalation_adapter=shared,
        )


@pytest.mark.parametrize("scope_id", ("", " untrimmed ", "x" * 65))
def test_resolver_rejects_invalid_scope_without_disclosing_it(scope_id: str) -> None:
    primary_binding = _binding(CriticalAlertRoute.PRIMARY, "pagerduty-primary", "c")
    escalation_binding = _binding(CriticalAlertRoute.ESCALATION, "twilio-fallback", "d")

    with pytest.raises(ApprovedCriticalAlertRouteError) as failure:
        ApprovedCriticalAlertRouteResolver(
            expected_scope_id=scope_id,
            primary_binding=primary_binding,
            primary_adapter=_Port(primary_binding.provider_id),
            escalation_binding=escalation_binding,
            escalation_adapter=_Port(escalation_binding.provider_id),
        )
    assert not scope_id or scope_id not in str(failure.value)
