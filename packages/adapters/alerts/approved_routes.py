"""Account-bound resolver for the approved PagerDuty/Twilio route pair."""

from __future__ import annotations

import hashlib

from packages.application.critical_alert_delivery import CriticalAlertDeliveryPort
from packages.application.critical_alert_supervisor import CriticalAlertRouteBinding
from packages.domain.critical_alert import CriticalAlertIncident, CriticalAlertRoute


class ApprovedCriticalAlertRouteError(ValueError):
    """An approved route binding or adapter is malformed or inconsistent."""


def _scope_sha256(scope_id: str) -> str:
    if (
        type(scope_id) is not str
        or not scope_id
        or scope_id != scope_id.strip()
        or len(scope_id) > 64
        or any(ord(character) < 32 or ord(character) == 127 for character in scope_id)
    ):
        raise ApprovedCriticalAlertRouteError(
            "approved critical-alert scope must be bounded trimmed text"
        )
    return hashlib.sha256(scope_id.encode("utf-8")).hexdigest()


def _validate_adapter(
    adapter: CriticalAlertDeliveryPort,
    binding: CriticalAlertRouteBinding,
    *,
    route: CriticalAlertRoute,
) -> None:
    if type(binding) is not CriticalAlertRouteBinding:
        raise ApprovedCriticalAlertRouteError(
            "approved critical-alert route requires an exact binding"
        )
    try:
        binding.__post_init__()
        provider_id = adapter.provider_id
        deliver = adapter.deliver
    except Exception:
        raise ApprovedCriticalAlertRouteError(
            "approved critical-alert route adapter is invalid"
        ) from None
    if binding.route is not route or provider_id != binding.provider_id or not callable(deliver):
        raise ApprovedCriticalAlertRouteError(
            "approved critical-alert route adapter conflicts with its binding"
        )


class ApprovedCriticalAlertRouteResolver:
    """Resolve only the exact account and two reviewed opaque route bindings."""

    __slots__ = (
        "_escalation_adapter",
        "_escalation_binding",
        "_primary_adapter",
        "_primary_binding",
        "_scope_sha256",
    )

    def __init__(
        self,
        *,
        expected_scope_id: str,
        primary_binding: CriticalAlertRouteBinding,
        primary_adapter: CriticalAlertDeliveryPort,
        escalation_binding: CriticalAlertRouteBinding,
        escalation_adapter: CriticalAlertDeliveryPort,
    ) -> None:
        scope_sha256 = _scope_sha256(expected_scope_id)
        _validate_adapter(
            primary_adapter,
            primary_binding,
            route=CriticalAlertRoute.PRIMARY,
        )
        _validate_adapter(
            escalation_adapter,
            escalation_binding,
            route=CriticalAlertRoute.ESCALATION,
        )
        if (
            primary_binding.provider_id == escalation_binding.provider_id
            or primary_adapter is escalation_adapter
        ):
            raise ApprovedCriticalAlertRouteError(
                "approved critical-alert routes require distinct provider adapters"
            )
        self._scope_sha256 = scope_sha256
        self._primary_binding = primary_binding
        self._primary_adapter = primary_adapter
        self._escalation_binding = escalation_binding
        self._escalation_adapter = escalation_adapter

    def __repr__(self) -> str:
        return (
            "ApprovedCriticalAlertRouteResolver("
            f"scope_sha256={self._scope_sha256!r}, "
            f"primary_binding_sha256={self._primary_binding.semantic_sha256!r}, "
            f"escalation_binding_sha256={self._escalation_binding.semantic_sha256!r}, "
            "adapters='[REDACTED]')"
        )

    @property
    def scope_sha256(self) -> str:
        return self._scope_sha256

    @property
    def primary_binding_sha256(self) -> str:
        return self._primary_binding.semantic_sha256

    @property
    def escalation_binding_sha256(self) -> str:
        return self._escalation_binding.semantic_sha256

    def resolve(
        self,
        incident: CriticalAlertIncident,
        binding: CriticalAlertRouteBinding,
    ) -> CriticalAlertDeliveryPort | None:
        if (
            type(incident) is not CriticalAlertIncident
            or type(binding) is not CriticalAlertRouteBinding
        ):
            return None
        try:
            incident.__post_init__()
            binding.__post_init__()
            incident_scope_sha256 = _scope_sha256(incident.scope_id)
        except Exception:
            return None
        if incident_scope_sha256 != self._scope_sha256:
            return None
        if binding == self._primary_binding:
            return self._primary_adapter
        if binding == self._escalation_binding:
            return self._escalation_adapter
        return None


__all__ = [
    "ApprovedCriticalAlertRouteError",
    "ApprovedCriticalAlertRouteResolver",
]
