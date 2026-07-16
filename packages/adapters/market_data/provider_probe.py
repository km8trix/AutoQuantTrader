"""Secret-safe, read-only connectivity probes for candidate market-data products."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum
from http.client import HTTPException, HTTPSConnection
from typing import Any, Protocol
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

MAX_RESPONSE_BYTES = 1_048_576
PROBE_NOTE = (
    "Connectivity evidence only; it does not establish licensing, point-in-time "
    "suitability, admission, or trading authority."
)
_SYMBOL = re.compile(r"^[A-Z][A-Z0-9.-]{0,14}$")


class ProbeProvider(StrEnum):
    MASSIVE_TRADES = "massive-trades"
    MASSIVE_QUOTES = "massive-quotes"
    SHARADAR_SFP = "sharadar-sfp"
    TIINGO = "tiingo"


class ProbeAccess(StrEnum):
    NOT_CONFIGURED = "not_configured"
    ACCESSIBLE = "accessible"
    ACCESSIBLE_NO_DATA = "accessible_no_data"
    UNAUTHORIZED = "unauthorized"
    NOT_ENTITLED = "not_entitled"
    RATE_LIMITED = "rate_limited"
    REMOTE_ERROR = "remote_error"
    INVALID_RESPONSE = "invalid_response"
    NETWORK_ERROR = "network_error"


@dataclass(frozen=True, slots=True)
class ProbeRequest:
    """An outbound request whose URL or headers may contain a credential."""

    provider: ProbeProvider
    url: str = field(repr=False)
    headers: Mapping[str, str] = field(repr=False)

    def __repr__(self) -> str:
        return f"ProbeRequest(provider={self.provider.value!r}, redacted=True)"


@dataclass(frozen=True, slots=True)
class ProbeResponse:
    status: int
    payload: bytes


class ProbeTransport(Protocol):
    def __call__(
        self,
        request: ProbeRequest,
        *,
        timeout_seconds: float,
    ) -> ProbeResponse: ...


@dataclass(frozen=True, slots=True)
class ProviderProbeResult:
    provider: ProbeProvider
    configured: bool
    access: ProbeAccess
    http_status: int | None
    record_count: int | None
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {
            "access": self.access.value,
            "admission_effect": "none",
            "configured": self.configured,
            "detail": self.detail,
            "http_status": self.http_status,
            "provider": self.provider.value,
            "record_count": self.record_count,
        }


class ProbeNetworkError(RuntimeError):
    """A sanitized transport failure with no URL, header, or response content."""


class ProbeProtocolError(ValueError):
    """A sanitized response-contract failure."""


def _https_get(request: ProbeRequest, *, timeout_seconds: float) -> ProbeResponse:
    target = urlsplit(request.url)
    if target.scheme != "https" or not target.hostname or target.username or target.password:
        raise ProbeProtocolError("probe target must be a credential-free HTTPS authority")
    path = urlunsplit(("", "", target.path or "/", target.query, ""))
    connection = HTTPSConnection(target.hostname, target.port, timeout=timeout_seconds)
    try:
        connection.request("GET", path, headers=dict(request.headers))
        response = connection.getresponse()
        payload = response.read(MAX_RESPONSE_BYTES + 1)
    except (HTTPException, OSError, TimeoutError, ValueError) as error:
        raise ProbeNetworkError("candidate provider request failed") from error
    finally:
        connection.close()
    if len(payload) > MAX_RESPONSE_BYTES:
        raise ProbeProtocolError("candidate provider response exceeded the probe limit")
    return ProbeResponse(status=response.status, payload=payload)


def _request_for(
    provider: ProbeProvider,
    *,
    credential: str,
    symbol: str,
    session_date: date,
) -> ProbeRequest:
    encoded_symbol = quote(symbol, safe="")
    date_value = session_date.isoformat()
    common_headers = {"Accept": "application/json", "User-Agent": "AutoQuantTrader/0.1"}
    if provider in {ProbeProvider.MASSIVE_TRADES, ProbeProvider.MASSIVE_QUOTES}:
        query = urlencode(
            {
                "limit": "1",
                "order": "asc",
                "sort": "timestamp",
                "timestamp": date_value,
            }
        )
        resource = "trades" if provider is ProbeProvider.MASSIVE_TRADES else "quotes"
        return ProbeRequest(
            provider,
            f"https://api.massive.com/v3/{resource}/{encoded_symbol}?{query}",
            {**common_headers, "Authorization": f"Bearer {credential}"},
        )
    if provider is ProbeProvider.SHARADAR_SFP:
        # Nasdaq documents api_key query authentication for the Tables API.
        # The request URL is redacted from repr, results, errors, and CLI output.
        query = urlencode(
            {
                "api_key": credential,
                "date": date_value,
                "qopts.per_page": "1",
                "ticker": symbol,
            }
        )
        return ProbeRequest(
            provider,
            f"https://data.nasdaq.com/api/v3/datatables/SHARADAR/SFP.json?{query}",
            common_headers,
        )
    if provider is ProbeProvider.TIINGO:
        query = urlencode(
            {
                "endDate": date_value,
                "format": "json",
                "startDate": date_value,
            }
        )
        return ProbeRequest(
            provider,
            f"https://api.tiingo.com/tiingo/daily/{encoded_symbol}/prices?{query}",
            {**common_headers, "Authorization": f"Token {credential}"},
        )
    raise AssertionError(f"unsupported provider: {provider}")


def _record_count(provider: ProbeProvider, payload: bytes) -> int:
    try:
        decoded: Any = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProbeProtocolError("candidate provider returned invalid JSON") from error
    rows: object
    if provider in {ProbeProvider.MASSIVE_TRADES, ProbeProvider.MASSIVE_QUOTES}:
        rows = decoded.get("results") if isinstance(decoded, dict) else None
    elif provider is ProbeProvider.SHARADAR_SFP:
        datatable = decoded.get("datatable") if isinstance(decoded, dict) else None
        rows = datatable.get("data") if isinstance(datatable, dict) else None
    elif provider is ProbeProvider.TIINGO:
        rows = decoded
    else:
        raise AssertionError(f"unsupported provider: {provider}")
    if not isinstance(rows, list):
        raise ProbeProtocolError("candidate provider response has an unexpected schema")
    return len(rows)


def _http_failure(provider: ProbeProvider, status: int) -> ProviderProbeResult:
    access, detail = {
        401: (ProbeAccess.UNAUTHORIZED, "Credential was rejected."),
        403: (ProbeAccess.NOT_ENTITLED, "Credential lacks access to the requested product."),
        429: (ProbeAccess.RATE_LIMITED, "Provider rate limit blocked the probe."),
    }.get(
        status,
        (ProbeAccess.REMOTE_ERROR, "Provider returned a non-success status."),
    )
    return ProviderProbeResult(
        provider=provider,
        configured=True,
        access=access,
        http_status=status,
        record_count=None,
        detail=detail,
    )


def probe_provider(
    provider: ProbeProvider,
    *,
    environ: Mapping[str, str],
    symbol: str,
    session_date: date,
    timeout_seconds: float = 8.0,
    transport: ProbeTransport = _https_get,
) -> ProviderProbeResult:
    """Make one bounded read and return only secret-free connectivity facts."""

    if _SYMBOL.fullmatch(symbol) is None:
        raise ValueError("symbol must be a canonical uppercase market symbol")
    if timeout_seconds <= 0 or timeout_seconds > 30:
        raise ValueError("timeout_seconds must be greater than zero and at most 30")
    variable = {
        ProbeProvider.MASSIVE_TRADES: "MASSIVE_API_KEY",
        ProbeProvider.MASSIVE_QUOTES: "MASSIVE_API_KEY",
        ProbeProvider.SHARADAR_SFP: "NASDAQ_DATA_LINK_API_KEY",
        ProbeProvider.TIINGO: "TIINGO_TOKEN",
    }[provider]
    credential = environ.get(variable, "")
    if not credential:
        return ProviderProbeResult(
            provider=provider,
            configured=False,
            access=ProbeAccess.NOT_CONFIGURED,
            http_status=None,
            record_count=None,
            detail=f"Required environment variable {variable} is not set.",
        )
    request = _request_for(
        provider,
        credential=credential,
        symbol=symbol,
        session_date=session_date,
    )
    try:
        response = transport(request, timeout_seconds=timeout_seconds)
    except ProbeNetworkError:
        return ProviderProbeResult(
            provider=provider,
            configured=True,
            access=ProbeAccess.NETWORK_ERROR,
            http_status=None,
            record_count=None,
            detail="Provider could not be reached within the bounded probe.",
        )
    except ProbeProtocolError:
        return ProviderProbeResult(
            provider=provider,
            configured=True,
            access=ProbeAccess.INVALID_RESPONSE,
            http_status=None,
            record_count=None,
            detail="Provider response violated the bounded probe contract.",
        )
    if not 200 <= response.status < 300:
        return _http_failure(provider, response.status)
    try:
        count = _record_count(provider, response.payload)
    except ProbeProtocolError:
        return ProviderProbeResult(
            provider=provider,
            configured=True,
            access=ProbeAccess.INVALID_RESPONSE,
            http_status=response.status,
            record_count=None,
            detail="Provider returned a success status with an unexpected response.",
        )
    return ProviderProbeResult(
        provider=provider,
        configured=True,
        access=ProbeAccess.ACCESSIBLE if count else ProbeAccess.ACCESSIBLE_NO_DATA,
        http_status=response.status,
        record_count=count,
        detail=(
            "Authenticated product read returned sample data."
            if count
            else "Authenticated product read succeeded but returned no row for the sample."
        ),
    )
