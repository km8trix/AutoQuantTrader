from __future__ import annotations

import base64
import json
import re
from dataclasses import fields
from urllib.parse import parse_qs

import httpx
import pytest

from packages.adapters.alerts._http import (
    MAX_ALERT_HTTP_RESPONSE_BYTES,
    AlertAdapterConfigurationError,
    AlertProviderResponseError,
    AlertProviderTransportError,
)
from packages.adapters.alerts.pagerduty import (
    PAGERDUTY_EVENTS_V2_PROVIDER_ID,
    PAGERDUTY_EVENTS_V2_URL,
    PAGERDUTY_SERVICE_IDENTITY,
    PagerDutyEventsV2CriticalAlertDelivery,
)
from packages.adapters.alerts.twilio import (
    TWILIO_MESSAGING_SERVICE_SMS_PROVIDER_ID,
    TwilioMessagingServiceSmsCriticalAlertDelivery,
)
from packages.application.critical_alert_delivery import (
    CriticalAlertProviderReceipt,
    CriticalAlertProviderRequest,
)
from packages.domain.critical_alert import CriticalAlertRoute

ROUTING_KEY = "p" * 32
ACCOUNT_SID = "AC" + "1" * 32
API_KEY_SID = "SK" + "2" * 32
API_KEY_SECRET = "restricted-api-key-secret-value"
MESSAGING_SERVICE_SID = "MG" + "3" * 32
RECIPIENT = "+15551234567"
MESSAGE_SID = "SM" + "4" * 32
RAW_ACCOUNT_SCOPE = "account-id-must-never-cross-provider-boundary"
RAW_SOURCE = "SPY-position-price-419.25"
RAW_IDEMPOTENCY_KEY = "critical-alert-attempt-account-00000001"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _request(
    *,
    provider_id: str,
    route: CriticalAlertRoute,
) -> CriticalAlertProviderRequest:
    return CriticalAlertProviderRequest(
        incident_id="incident-internal-account-reference",
        incident_sha256="a" * 64,
        scope_id=RAW_ACCOUNT_SCOPE,
        source_id=RAW_SOURCE,
        alert_code="strategy_deadline_exceeded",
        evidence_sha256="b" * 64,
        correlation_sha256="c" * 64,
        route=route,
        provider_id=provider_id,
        idempotency_key=RAW_IDEMPOTENCY_KEY,
    )


def _json_response(
    status_code: int,
    payload: object,
    *,
    request: httpx.Request,
) -> httpx.Response:
    return httpx.Response(
        status_code,
        headers={"content-type": "application/json"},
        content=json.dumps(payload, separators=(",", ":")).encode(),
        request=request,
    )


def test_pagerduty_delivers_bounded_sanitized_primary_event() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["body"] = request.content
        captured["timeouts"] = request.extensions["timeout"]
        event = json.loads(request.content)
        return _json_response(
            202,
            {
                "status": "success",
                "message": "Event processed",
                "dedup_key": event["dedup_key"],
            },
            request=request,
        )

    adapter = PagerDutyEventsV2CriticalAlertDelivery(
        routing_key=ROUTING_KEY,
        transport=httpx.MockTransport(handler),
    )
    receipt = adapter.deliver(
        _request(
            provider_id=PAGERDUTY_EVENTS_V2_PROVIDER_ID,
            route=CriticalAlertRoute.PRIMARY,
        ),
        timeout_seconds=27.0,
    )

    assert adapter.provider_id == PAGERDUTY_EVENTS_V2_PROVIDER_ID
    assert captured["method"] == "POST"
    assert captured["url"] == PAGERDUTY_EVENTS_V2_URL
    assert captured["timeouts"] == {
        "connect": 10.0,
        "read": 10.0,
        "write": 10.0,
        "pool": 10.0,
    }
    body = captured["body"]
    assert type(body) is bytes
    event = json.loads(body)
    assert event["routing_key"] == ROUTING_KEY
    assert event["event_action"] == "trigger"
    assert _SHA256.fullmatch(event["dedup_key"]) is not None
    assert event["payload"] == {
        "class": "critical-alert",
        "component": "safety-control",
        "custom_details": {
            "alert_code": "strategy_deadline_exceeded",
            "correlation_sha256": "c" * 64,
            "evidence_sha256": "b" * 64,
            "incident_sha256": "a" * 64,
            "provider_request_sha256": event["dedup_key"],
            "route": "primary",
        },
        "group": "paper-deployment",
        "severity": "critical",
        "source": PAGERDUTY_SERVICE_IDENTITY,
        "summary": "AutoQuantTrader critical safety alert requires operator attention",
    }
    serialized = body.decode()
    assert RAW_ACCOUNT_SCOPE not in serialized
    assert RAW_SOURCE not in serialized
    assert RAW_IDEMPOTENCY_KEY not in serialized
    assert type(receipt) is CriticalAlertProviderReceipt
    assert _SHA256.fullmatch(receipt.provider_receipt_sha256) is not None
    assert tuple(field.name for field in fields(receipt)) == ("provider_receipt_sha256",)


@pytest.mark.parametrize(
    ("provider_id", "route"),
    [
        (TWILIO_MESSAGING_SERVICE_SMS_PROVIDER_ID, CriticalAlertRoute.PRIMARY),
        (PAGERDUTY_EVENTS_V2_PROVIDER_ID, CriticalAlertRoute.ESCALATION),
    ],
)
def test_pagerduty_rejects_nonexact_request_binding_before_http(
    provider_id: str,
    route: CriticalAlertRoute,
) -> None:
    def forbidden(_: httpx.Request) -> httpx.Response:
        raise AssertionError("provider must not be called")

    adapter = PagerDutyEventsV2CriticalAlertDelivery(
        routing_key=ROUTING_KEY,
        transport=httpx.MockTransport(forbidden),
    )

    with pytest.raises(AlertProviderResponseError, match="binding"):
        adapter.deliver(
            _request(provider_id=provider_id, route=route),
            timeout_seconds=1.0,
        )


def test_pagerduty_rejects_duplicate_or_oversized_json_without_leaking_response() -> None:
    raw_response = b'{"status":"success","status":"secret","dedup_key":"not-the-binding"}'

    def duplicate_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            202,
            headers={"content-type": "application/json"},
            content=raw_response,
            request=request,
        )

    adapter = PagerDutyEventsV2CriticalAlertDelivery(
        routing_key=ROUTING_KEY,
        transport=httpx.MockTransport(duplicate_handler),
    )
    with pytest.raises(AlertProviderResponseError) as duplicate_failure:
        adapter.deliver(
            _request(
                provider_id=PAGERDUTY_EVENTS_V2_PROVIDER_ID,
                route=CriticalAlertRoute.PRIMARY,
            ),
            timeout_seconds=1.0,
        )
    assert raw_response.decode() not in str(duplicate_failure.value)
    assert ROUTING_KEY not in repr(duplicate_failure.value)

    def oversized_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            202,
            headers={"content-type": "application/json"},
            content=b"x" * (MAX_ALERT_HTTP_RESPONSE_BYTES + 1),
            request=request,
        )

    oversized = PagerDutyEventsV2CriticalAlertDelivery(
        routing_key=ROUTING_KEY,
        transport=httpx.MockTransport(oversized_handler),
    )
    with pytest.raises(AlertProviderResponseError, match="exceeded its bound"):
        oversized.deliver(
            _request(
                provider_id=PAGERDUTY_EVENTS_V2_PROVIDER_ID,
                route=CriticalAlertRoute.PRIMARY,
            ),
            timeout_seconds=1.0,
        )


def test_pagerduty_sanitizes_transport_and_timeout_failures() -> None:
    transport_secret = "raw-provider-error-with-routing-key-" + ROUTING_KEY

    def failing(_: httpx.Request) -> httpx.Response:
        raise RuntimeError(transport_secret)

    adapter = PagerDutyEventsV2CriticalAlertDelivery(
        routing_key=ROUTING_KEY,
        transport=httpx.MockTransport(failing),
    )
    request = _request(
        provider_id=PAGERDUTY_EVENTS_V2_PROVIDER_ID,
        route=CriticalAlertRoute.PRIMARY,
    )
    with pytest.raises(AlertProviderTransportError) as failure:
        adapter.deliver(request, timeout_seconds=1.0)
    assert transport_secret not in str(failure.value)
    assert ROUTING_KEY not in repr(failure.value)

    def timing_out(http_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout(transport_secret, request=http_request)

    timeout_adapter = PagerDutyEventsV2CriticalAlertDelivery(
        routing_key=ROUTING_KEY,
        transport=httpx.MockTransport(timing_out),
    )
    with pytest.raises(TimeoutError) as timeout:
        timeout_adapter.deliver(request, timeout_seconds=1.0)
    assert transport_secret not in str(timeout.value)
    assert ROUTING_KEY not in repr(timeout.value)


def test_twilio_delivers_bounded_sanitized_escalation_message() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["body"] = request.content
        captured["timeouts"] = request.extensions["timeout"]
        return _json_response(
            201,
            {
                "sid": MESSAGE_SID,
                "messaging_service_sid": MESSAGING_SERVICE_SID,
                "to": RECIPIENT,
                "status": "queued",
                "body": "provider echo is intentionally ignored",
            },
            request=request,
        )

    adapter = TwilioMessagingServiceSmsCriticalAlertDelivery(
        account_sid=ACCOUNT_SID,
        api_key_sid=API_KEY_SID,
        api_key_secret=API_KEY_SECRET,
        messaging_service_sid=MESSAGING_SERVICE_SID,
        recipient=RECIPIENT,
        transport=httpx.MockTransport(handler),
    )
    receipt = adapter.deliver(
        _request(
            provider_id=TWILIO_MESSAGING_SERVICE_SMS_PROVIDER_ID,
            route=CriticalAlertRoute.ESCALATION,
        ),
        timeout_seconds=0.75,
    )

    assert adapter.provider_id == TWILIO_MESSAGING_SERVICE_SMS_PROVIDER_ID
    assert captured["method"] == "POST"
    assert captured["url"] == (
        f"https://api.twilio.com/2010-04-01/Accounts/{ACCOUNT_SID}/Messages.json"
    )
    assert captured["timeouts"] == {
        "connect": 0.75,
        "read": 0.75,
        "write": 0.75,
        "pool": 0.75,
    }
    headers = captured["headers"]
    assert type(headers) is dict
    assert headers["content-type"] == "application/x-www-form-urlencoded"
    assert _SHA256.fullmatch(headers["idempotency-key"]) is not None
    authorization = headers["authorization"]
    assert authorization.startswith("Basic ")
    assert base64.b64decode(authorization.removeprefix("Basic ")).decode() == (
        f"{API_KEY_SID}:{API_KEY_SECRET}"
    )
    body = captured["body"]
    assert type(body) is bytes
    form = parse_qs(body.decode(), strict_parsing=True)
    assert form["To"] == [RECIPIENT]
    assert form["MessagingServiceSid"] == [MESSAGING_SERVICE_SID]
    assert form["Body"] == [
        "AutoQuantTrader CRITICAL safety alert. "
        "code=strategy_deadline_exceeded; "
        f"incident={'a' * 16}; evidence={'b' * 16}; "
        f"ref={headers['idempotency-key'][:20]}. Operator review required."
    ]
    serialized = body.decode()
    assert RAW_ACCOUNT_SCOPE not in serialized
    assert RAW_SOURCE not in serialized
    assert RAW_IDEMPOTENCY_KEY not in serialized
    assert type(receipt) is CriticalAlertProviderReceipt
    assert _SHA256.fullmatch(receipt.provider_receipt_sha256) is not None
    assert MESSAGE_SID not in repr(receipt)
    assert RECIPIENT not in repr(receipt)


def test_twilio_rejects_nonexact_request_binding_before_http() -> None:
    def forbidden(_: httpx.Request) -> httpx.Response:
        raise AssertionError("provider must not be called")

    adapter = TwilioMessagingServiceSmsCriticalAlertDelivery(
        account_sid=ACCOUNT_SID,
        api_key_sid=API_KEY_SID,
        api_key_secret=API_KEY_SECRET,
        messaging_service_sid=MESSAGING_SERVICE_SID,
        recipient=RECIPIENT,
        transport=httpx.MockTransport(forbidden),
    )

    with pytest.raises(AlertProviderResponseError, match="binding"):
        adapter.deliver(
            _request(
                provider_id=TWILIO_MESSAGING_SERVICE_SMS_PROVIDER_ID,
                route=CriticalAlertRoute.PRIMARY,
            ),
            timeout_seconds=1.0,
        )


def test_twilio_requires_strict_acknowledgement_and_sanitizes_raw_response() -> None:
    raw_provider_body = {
        "sid": "not-a-message-sid",
        "messaging_service_sid": MESSAGING_SERVICE_SID,
        "to": RECIPIENT,
        "status": "failed",
        "error_message": "raw response secret " + API_KEY_SECRET,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return _json_response(201, raw_provider_body, request=request)

    adapter = TwilioMessagingServiceSmsCriticalAlertDelivery(
        account_sid=ACCOUNT_SID,
        api_key_sid=API_KEY_SID,
        api_key_secret=API_KEY_SECRET,
        messaging_service_sid=MESSAGING_SERVICE_SID,
        recipient=RECIPIENT,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(AlertProviderResponseError) as failure:
        adapter.deliver(
            _request(
                provider_id=TWILIO_MESSAGING_SERVICE_SMS_PROVIDER_ID,
                route=CriticalAlertRoute.ESCALATION,
            ),
            timeout_seconds=1.0,
        )
    rendered = f"{failure.value!s} {failure.value!r}"
    assert API_KEY_SECRET not in rendered
    assert RECIPIENT not in rendered
    assert MESSAGE_SID not in rendered
    assert json.dumps(raw_provider_body) not in rendered


def test_adapter_representations_and_configuration_failures_are_secret_safe() -> None:
    pagerduty = PagerDutyEventsV2CriticalAlertDelivery(routing_key=ROUTING_KEY)
    twilio = TwilioMessagingServiceSmsCriticalAlertDelivery(
        account_sid=ACCOUNT_SID,
        api_key_sid=API_KEY_SID,
        api_key_secret=API_KEY_SECRET,
        messaging_service_sid=MESSAGING_SERVICE_SID,
        recipient=RECIPIENT,
    )

    for rendered in (repr(pagerduty), str(pagerduty), repr(twilio), str(twilio)):
        assert "REDACTED" in rendered
        assert ROUTING_KEY not in rendered
        assert ACCOUNT_SID not in rendered
        assert API_KEY_SID not in rendered
        assert API_KEY_SECRET not in rendered
        assert MESSAGING_SERVICE_SID not in rendered
        assert RECIPIENT not in rendered

    invalid_secret = "invalid-secret-value-that-must-not-leak"
    with pytest.raises(AlertAdapterConfigurationError) as pagerduty_failure:
        PagerDutyEventsV2CriticalAlertDelivery(routing_key=invalid_secret)
    assert invalid_secret not in repr(pagerduty_failure.value)

    with pytest.raises(AlertAdapterConfigurationError) as twilio_failure:
        TwilioMessagingServiceSmsCriticalAlertDelivery(
            account_sid=ACCOUNT_SID,
            api_key_sid=API_KEY_SID,
            api_key_secret=API_KEY_SECRET,
            messaging_service_sid=MESSAGING_SERVICE_SID,
            recipient=invalid_secret,
        )
    assert invalid_secret not in repr(twilio_failure.value)


@pytest.mark.parametrize("timeout_seconds", [0.0, -1.0, float("inf"), float("nan"), True])
def test_alert_adapters_reject_invalid_timeout_without_http(
    timeout_seconds: float,
) -> None:
    def forbidden(_: httpx.Request) -> httpx.Response:
        raise AssertionError("provider must not be called")

    adapter = PagerDutyEventsV2CriticalAlertDelivery(
        routing_key=ROUTING_KEY,
        transport=httpx.MockTransport(forbidden),
    )
    with pytest.raises(AlertProviderTransportError, match="timeout"):
        adapter.deliver(
            _request(
                provider_id=PAGERDUTY_EVENTS_V2_PROVIDER_ID,
                route=CriticalAlertRoute.PRIMARY,
            ),
            timeout_seconds=timeout_seconds,
        )
