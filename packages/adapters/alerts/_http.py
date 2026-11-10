"""Bounded HTTPS and request-binding primitives shared by alert adapters."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx

from packages.application.critical_alert_delivery import CriticalAlertProviderRequest
from packages.domain.canonical import canonical_json_bytes
from packages.domain.critical_alert import CriticalAlertRoute

MAX_ALERT_HTTP_REQUEST_BYTES = 4_096
MAX_ALERT_HTTP_RESPONSE_BYTES = 32_768
MAX_ALERT_HTTP_TIMEOUT_SECONDS = 10.0

_ALERT_CODE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

type JsonObject = dict[str, Any]


class AlertAdapterConfigurationError(ValueError):
    """An adapter was given invalid secret or routing configuration."""


class AlertProviderTransportError(RuntimeError):
    """A sanitized provider transport failure."""


class AlertProviderResponseError(RuntimeError):
    """A sanitized provider response-contract failure."""


@dataclass(frozen=True, slots=True)
class _BoundedHttpResponse:
    status_code: int
    media_type: str | None
    body: bytes = field(repr=False)

    def __repr__(self) -> str:
        return (
            "_BoundedHttpResponse("
            f"status_code={self.status_code!r}, media_type={self.media_type!r}, "
            f"body_bytes={len(self.body)!r})"
        )


def _validate_secret(
    value: str,
    *,
    pattern: re.Pattern[str] | None = None,
    minimum: int = 1,
    maximum: int = 256,
) -> None:
    if (
        type(value) is not str
        or not minimum <= len(value) <= maximum
        or value != value.strip()
        or any(not 33 <= ord(character) <= 126 for character in value)
        or (pattern is not None and pattern.fullmatch(value) is None)
    ):
        raise AlertAdapterConfigurationError("critical-alert provider configuration is invalid")


def _validate_provider_request(
    request: CriticalAlertProviderRequest,
    *,
    provider_id: str,
    route: CriticalAlertRoute,
) -> str:
    if type(request) is not CriticalAlertProviderRequest:
        raise AlertProviderResponseError("critical-alert provider request is invalid")
    if request.provider_id != provider_id or request.route is not route:
        raise AlertProviderResponseError("critical-alert provider request binding is invalid")
    if (
        type(request.alert_code) is not str
        or _ALERT_CODE.fullmatch(request.alert_code) is None
        or type(request.idempotency_key) is not str
        or _IDEMPOTENCY_KEY.fullmatch(request.idempotency_key) is None
    ):
        raise AlertProviderResponseError("critical-alert provider request content is invalid")
    for digest in (
        request.incident_sha256,
        request.evidence_sha256,
        request.correlation_sha256,
    ):
        if type(digest) is not str or _SHA256.fullmatch(digest) is None:
            raise AlertProviderResponseError("critical-alert provider request digest is invalid")

    # Raw application identifiers never cross the provider boundary. The
    # provider correlation value is bound to the durable idempotency key and
    # immutable incident evidence, but reveals only a SHA-256 digest.
    idempotency_sha256 = hashlib.sha256(request.idempotency_key.encode("utf-8")).hexdigest()
    return hashlib.sha256(
        canonical_json_bytes(
            (
                "phase5-critical-alert-provider-binding-v1",
                provider_id,
                route.value,
                request.incident_sha256,
                request.evidence_sha256,
                request.correlation_sha256,
                idempotency_sha256,
            )
        )
    ).hexdigest()


def _receipt_sha256(
    *,
    provider_id: str,
    request_binding_sha256: str,
    provider_receipt_id: str,
) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            (
                "phase5-critical-alert-provider-receipt-v1",
                provider_id,
                request_binding_sha256,
                provider_receipt_id,
            )
        )
    ).hexdigest()


def _effective_timeout(timeout_seconds: float) -> float:
    if (
        type(timeout_seconds) not in {int, float}
        or isinstance(timeout_seconds, bool)
        or not math.isfinite(float(timeout_seconds))
        or float(timeout_seconds) <= 0
    ):
        raise AlertProviderTransportError("critical-alert provider timeout is invalid")
    return min(float(timeout_seconds), MAX_ALERT_HTTP_TIMEOUT_SECONDS)


def _bounded_post(
    *,
    url: str,
    headers: Mapping[str, str],
    body: bytes,
    timeout_seconds: float,
    auth: httpx.Auth | None,
    transport: httpx.BaseTransport | None,
) -> _BoundedHttpResponse:
    if type(body) is not bytes or not body or len(body) > MAX_ALERT_HTTP_REQUEST_BYTES:
        raise AlertProviderTransportError("critical-alert provider request exceeded its bound")
    timeout = _effective_timeout(timeout_seconds)
    try:
        with (
            httpx.Client(
                verify=True,
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(
                    connect=timeout,
                    read=timeout,
                    write=timeout,
                    pool=timeout,
                ),
                transport=transport,
            ) as client,
            client.stream(
                "POST",
                url,
                headers=dict(headers),
                content=body,
                auth=auth,
            ) as response,
        ):
            if response.request.method != "POST" or str(response.request.url) != url:
                raise AlertProviderTransportError(
                    "critical-alert provider changed the fixed request target"
                )
            response_body = bytearray()
            chunks = (response.content,) if response.is_stream_consumed else response.iter_raw()
            for chunk in chunks:
                if len(response_body) + len(chunk) > MAX_ALERT_HTTP_RESPONSE_BYTES:
                    raise AlertProviderResponseError(
                        "critical-alert provider response exceeded its bound"
                    )
                response_body.extend(chunk)
            encoding = response.headers.get("content-encoding")
            if encoding is not None and encoding.strip().lower() != "identity":
                raise AlertProviderResponseError(
                    "critical-alert provider response encoding is unsupported"
                )
            content_type = response.headers.get("content-type")
            media_type: str | None = None
            if content_type is not None and len(content_type) <= 128:
                media_type = content_type.partition(";")[0].strip().lower()
            return _BoundedHttpResponse(
                status_code=response.status_code,
                media_type=media_type,
                body=bytes(response_body),
            )
    except (AlertProviderTransportError, AlertProviderResponseError):
        raise
    except httpx.TimeoutException:
        raise TimeoutError("critical-alert provider request timed out") from None
    except Exception:
        # Never let an HTTP library, injected transport, URL, credential, or
        # provider response become part of an application-visible exception.
        raise AlertProviderTransportError("critical-alert provider request failed") from None


class _DuplicateJsonKey(ValueError):
    pass


def _json_object(response: _BoundedHttpResponse) -> JsonObject:
    if response.media_type != "application/json" or not response.body:
        raise AlertProviderResponseError("critical-alert provider returned an invalid response")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> JsonObject:
        result: JsonObject = {}
        for key, value in pairs:
            if key in result:
                raise _DuplicateJsonKey
            result[key] = value
        return result

    try:
        parsed = json.loads(
            response.body.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateJsonKey, ValueError, TypeError):
        raise AlertProviderResponseError(
            "critical-alert provider returned an invalid response"
        ) from None
    if type(parsed) is not dict:
        raise AlertProviderResponseError("critical-alert provider returned an invalid response")
    return parsed


def _json_bytes(payload: Mapping[str, object]) -> bytes:
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError):
        raise AlertProviderTransportError(
            "critical-alert provider request serialization failed"
        ) from None
    if not encoded or len(encoded) > MAX_ALERT_HTTP_REQUEST_BYTES:
        raise AlertProviderTransportError("critical-alert provider request exceeded its bound")
    return encoded


def _redacted_repr(class_name: str, provider_id: str) -> str:
    return f"{class_name}(provider_id={provider_id!r}, credentials='[REDACTED]')"


type ClientTransport = httpx.BaseTransport | None
type MonotonicClock = Callable[[], float]
