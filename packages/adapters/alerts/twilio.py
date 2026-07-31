"""Twilio Messaging Service SMS escalation for critical alerts."""

from __future__ import annotations

import re
from urllib.parse import urlencode

import httpx

from packages.adapters.alerts._http import (
    AlertAdapterConfigurationError,
    AlertProviderResponseError,
    ClientTransport,
    _bounded_post,
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

TWILIO_MESSAGING_SERVICE_SMS_PROVIDER_ID = "twilio-messaging-service-sms-escalation"
TWILIO_API_HOST = "api.twilio.com"

_TWILIO_ACCOUNT_SID = re.compile(r"^AC[0-9a-fA-F]{32}$")
_TWILIO_API_KEY_SID = re.compile(r"^SK[0-9a-fA-F]{32}$")
_TWILIO_MESSAGING_SERVICE_SID = re.compile(r"^MG[0-9a-fA-F]{32}$")
_TWILIO_MESSAGE_SID = re.compile(r"^SM[0-9a-fA-F]{32}$")
_E164_RECIPIENT = re.compile(r"^\+[1-9][0-9]{7,14}$")
_ACKNOWLEDGED_MESSAGE_STATES = frozenset({"accepted", "queued", "sending", "sent"})
_MAX_SMS_BODY_CHARACTERS = 320


class TwilioMessagingServiceSmsCriticalAlertDelivery:
    """Send one sanitized escalation SMS through one fixed Messaging Service."""

    __slots__ = (
        "_account_sid",
        "_api_key_secret",
        "_api_key_sid",
        "_messaging_service_sid",
        "_recipient",
        "_transport",
    )

    def __init__(
        self,
        *,
        account_sid: str,
        api_key_sid: str,
        api_key_secret: str,
        messaging_service_sid: str,
        recipient: str,
        transport: ClientTransport = None,
    ) -> None:
        _validate_secret(
            account_sid,
            pattern=_TWILIO_ACCOUNT_SID,
            minimum=34,
            maximum=34,
        )
        _validate_secret(
            api_key_sid,
            pattern=_TWILIO_API_KEY_SID,
            minimum=34,
            maximum=34,
        )
        _validate_secret(api_key_secret, minimum=16, maximum=128)
        _validate_secret(
            messaging_service_sid,
            pattern=_TWILIO_MESSAGING_SERVICE_SID,
            minimum=34,
            maximum=34,
        )
        _validate_secret(
            recipient,
            pattern=_E164_RECIPIENT,
            minimum=9,
            maximum=16,
        )
        if transport is not None and not isinstance(transport, httpx.BaseTransport):
            raise AlertAdapterConfigurationError(
                "critical-alert provider transport configuration is invalid"
            )
        self._account_sid = account_sid
        self._api_key_sid = api_key_sid
        self._api_key_secret = api_key_secret
        self._messaging_service_sid = messaging_service_sid
        self._recipient = recipient
        self._transport = transport

    @property
    def provider_id(self) -> str:
        return TWILIO_MESSAGING_SERVICE_SMS_PROVIDER_ID

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
            route=CriticalAlertRoute.ESCALATION,
        )
        message = (
            "AutoQuantTrader CRITICAL safety alert. "
            f"code={request.alert_code}; "
            f"incident={request.incident_sha256[:16]}; "
            f"evidence={request.evidence_sha256[:16]}; "
            f"ref={request_binding[:20]}. Operator review required."
        )
        if len(message) > _MAX_SMS_BODY_CHARACTERS:
            raise AlertProviderResponseError("Twilio critical-alert message exceeded its bound")
        body = urlencode(
            {
                "Body": message,
                "MessagingServiceSid": self._messaging_service_sid,
                "To": self._recipient,
            }
        ).encode("ascii")
        url = f"https://{TWILIO_API_HOST}/2010-04-01/Accounts/{self._account_sid}/Messages.json"
        response = _bounded_post(
            url=url,
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Content-Type": "application/x-www-form-urlencoded",
                "Idempotency-Key": request_binding,
                "User-Agent": "autoquant-trader/0.1 critical-alert-twilio",
            },
            body=body,
            timeout_seconds=timeout_seconds,
            auth=httpx.BasicAuth(self._api_key_sid, self._api_key_secret),
            transport=self._transport,
        )
        if response.status_code != 201:
            raise AlertProviderResponseError("Twilio did not acknowledge the critical alert")
        payload = _json_object(response)
        provider_message_sid = payload.get("sid")
        if (
            len(payload) > 64
            or type(provider_message_sid) is not str
            or _TWILIO_MESSAGE_SID.fullmatch(provider_message_sid) is None
            or payload.get("messaging_service_sid") != self._messaging_service_sid
            or payload.get("to") != self._recipient
            or payload.get("status") not in _ACKNOWLEDGED_MESSAGE_STATES
        ):
            raise AlertProviderResponseError(
                "Twilio returned an invalid critical-alert acknowledgement"
            )
        return CriticalAlertProviderReceipt(
            provider_receipt_sha256=_receipt_sha256(
                provider_id=self.provider_id,
                request_binding_sha256=request_binding,
                provider_receipt_id=provider_message_sid,
            )
        )
