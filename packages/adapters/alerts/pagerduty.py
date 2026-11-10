"""PagerDuty Events API v2 primary critical-alert delivery."""

from __future__ import annotations

import re

import httpx

from packages.adapters.alerts._http import (
    AlertAdapterConfigurationError,
    AlertProviderResponseError,
    ClientTransport,
    _bounded_post,
    _json_bytes,
    _json_object,
    _receipt_sha256,
    _redacted_repr,
    _validate_provider_request,
    _validate_secret,
)
from packages.application.critical_alert_delivery import (
    CriticalAlertProviderReceipt,
    CriticalAlertProviderRequest,
)
from packages.domain.critical_alert import CriticalAlertRoute

PAGERDUTY_EVENTS_V2_PROVIDER_ID = "pagerduty-events-v2-primary"
PAGERDUTY_EVENTS_V2_URL = "https://events.pagerduty.com/v2/enqueue"
PAGERDUTY_SERVICE_IDENTITY = "autoquant-trader-paper-safety"

_PAGERDUTY_ROUTING_KEY = re.compile(r"^[A-Za-z0-9]{32}$")


class PagerDutyEventsV2CriticalAlertDelivery:
    """Send one sanitized primary incident to one fixed PagerDuty service."""

    __slots__ = ("_routing_key", "_transport")

    def __init__(
        self,
        *,
        routing_key: str,
        transport: ClientTransport = None,
    ) -> None:
        _validate_secret(
            routing_key,
            pattern=_PAGERDUTY_ROUTING_KEY,
            minimum=32,
            maximum=32,
        )
        if transport is not None and not isinstance(transport, httpx.BaseTransport):
            raise AlertAdapterConfigurationError(
                "critical-alert provider transport configuration is invalid"
            )
        self._routing_key = routing_key
        self._transport = transport

    @property
    def provider_id(self) -> str:
        return PAGERDUTY_EVENTS_V2_PROVIDER_ID

    def __repr__(self) -> str:
        return _redacted_repr(type(self).__name__, self.provider_id)

    def deliver(
        self,
        request: CriticalAlertProviderRequest,
        *,
        timeout_seconds: float,
    ) -> CriticalAlertProviderReceipt:
        request_binding = _validate_provider_request(
            request,
            provider_id=self.provider_id,
            route=CriticalAlertRoute.PRIMARY,
        )
        body = _json_bytes(
            {
                "dedup_key": request_binding,
                "event_action": "trigger",
                "payload": {
                    "class": "critical-alert",
                    "component": "safety-control",
                    "custom_details": {
                        "alert_code": request.alert_code,
                        "correlation_sha256": request.correlation_sha256,
                        "evidence_sha256": request.evidence_sha256,
                        "incident_sha256": request.incident_sha256,
                        "provider_request_sha256": request_binding,
                        "route": CriticalAlertRoute.PRIMARY.value,
                    },
                    "group": "paper-deployment",
                    "severity": "critical",
                    "source": PAGERDUTY_SERVICE_IDENTITY,
                    "summary": (
                        "AutoQuantTrader critical safety alert requires operator attention"
                    ),
                },
                "routing_key": self._routing_key,
            }
        )
        response = _bounded_post(
            url=PAGERDUTY_EVENTS_V2_URL,
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Content-Type": "application/json",
                "User-Agent": "autoquant-trader/0.1 critical-alert-pagerduty",
            },
            body=body,
            timeout_seconds=timeout_seconds,
            auth=None,
            transport=self._transport,
        )
        if response.status_code != 202:
            raise AlertProviderResponseError("PagerDuty did not acknowledge the critical alert")
        payload = _json_object(response)
        if (
            len(payload) > 8
            or payload.get("status") != "success"
            or payload.get("dedup_key") != request_binding
        ):
            raise AlertProviderResponseError(
                "PagerDuty returned an invalid critical-alert acknowledgement"
            )
        message = payload.get("message")
        if message is not None and (
            type(message) is not str
            or not message
            or len(message) > 256
            or any(ord(character) < 32 or ord(character) == 127 for character in message)
        ):
            raise AlertProviderResponseError(
                "PagerDuty returned an invalid critical-alert acknowledgement"
            )
        return CriticalAlertProviderReceipt(
            provider_receipt_sha256=_receipt_sha256(
                provider_id=self.provider_id,
                request_binding_sha256=request_binding,
                provider_receipt_id=request_binding,
            )
        )
