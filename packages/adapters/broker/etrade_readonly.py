"""Personal-v1 E*TRADE read transport and explicitly referenced secret stores.

Separate from historical recorded-offline authority proofs. Nothing in this
module starts a connection or resolves a secret on import. Only five account
GET surfaces exist. The supported session starts with an existing access token;
OAuth acquisition/renewal requires the separate supervised OAuth workflow.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import queue
import re
import socket
import ssl
import subprocess
import threading
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qs, quote, urlencode, urlsplit

from packages.adapters.broker.etrade import (
    EtradeAccountIdKey,
    EtradeEnvironment,
    EtradeSecretScope,
)
from packages.adapters.broker.etrade_oauth import (
    EtradeOAuthConsumerSecretReference,
    EtradeOAuthNonce,
    EtradeOAuthTokenKind,
    EtradeOAuthTokenSecretReference,
    etrade_oauth_percent_encode,
)

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_SECRET_FILE_BYTES = 64 * 1024
REQUEST_DEADLINE_SECONDS = 3.0


class EtradeReadError(ValueError):
    """Sanitized failure code; never interpolate provider/secret-store text."""


class EtradeReadOperation(StrEnum):
    ACCOUNTS = "accounts"
    BALANCES = "balances"
    PORTFOLIO = "portfolio"
    ORDERS = "orders"
    ACTIVITY = "activity"


def require_utc(value: datetime) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise EtradeReadError("UTC_TIMESTAMP_REQUIRED")
    return value


def _instant(value: object) -> datetime:
    try:
        if type(value) is not str:
            raise ValueError
        return require_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except (ValueError, TypeError):
        raise EtradeReadError("TOKEN_TIME_METADATA_UNAVAILABLE") from None


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EtradeReadError("DUPLICATE_JSON_FIELD")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class EtradeSecretReference:
    """Explicit reference; environment and revision are part of its identity.

    envfile:///absolute/path?version=1 loads only that environment's allowlist.
    keychain://service/item?version=1 addresses one exact macOS generic item.
    References are configuration, never proof of owner authorization.
    """

    environment: EtradeEnvironment
    uri: str = field(repr=False)
    version: int = 1

    def __post_init__(self) -> None:
        if type(self.environment) is not EtradeEnvironment:
            raise EtradeReadError("ENVIRONMENT_REQUIRED")
        if type(self.version) is not int or self.version < 1:
            raise EtradeReadError("SECRET_REFERENCE_VERSION_REQUIRED")
        parts = urlsplit(self.uri)
        if parts.fragment or parse_qs(parts.query) != {"version": [str(self.version)]}:
            raise EtradeReadError("SECRET_REFERENCE_FORMAT_INVALID")
        if parts.scheme == "envfile":
            if parts.netloc or not parts.path.startswith("/") or "%" in parts.path:
                raise EtradeReadError("SECRET_REFERENCE_FORMAT_INVALID")
        elif parts.scheme == "keychain":
            expected = f"autoquanttrader.etrade.{self.environment.value}.oauth.v1"
            if parts.netloc != expected or not re.fullmatch(r"/[A-Za-z0-9_-]{1,80}", parts.path):
                raise EtradeReadError("SECRET_REFERENCE_ENVIRONMENT_MISMATCH")
        else:
            raise EtradeReadError("SECRET_REFERENCE_SCHEME_UNSUPPORTED")

    @property
    def consumer_reference(self) -> EtradeOAuthConsumerSecretReference:
        scope = (
            EtradeSecretScope.SANDBOX_CONSUMER
            if self.environment is EtradeEnvironment.SANDBOX
            else EtradeSecretScope.PRODUCTION_CONSUMER
        )
        return EtradeOAuthConsumerSecretReference(self.environment, scope, self.version)

    @property
    def token_reference(self) -> EtradeOAuthTokenSecretReference:
        scope = (
            EtradeSecretScope.SANDBOX_TOKEN
            if self.environment is EtradeEnvironment.SANDBOX
            else EtradeSecretScope.PRODUCTION_TOKEN
        )
        return EtradeOAuthTokenSecretReference(
            self.environment,
            scope,
            EtradeOAuthTokenKind.ACCESS_TOKEN,
            self.version,
        )


class EtradeReadCredentials:
    """Short-lived material, redacted and nonserializable; buffers clear on close.

    Python/SSL may make transient immutable copies. This is secret minimization,
    not a claim that all copies can be securely erased from process memory.
    """

    __slots__ = ("_values", "expires_at", "issued_at", "last_activity_at", "reference")

    def __init__(self, reference: EtradeSecretReference, values: Mapping[str, str]) -> None:
        self.reference = reference
        self._values: dict[str, bytearray] = {}
        try:
            for key in ("consumer_key", "consumer_secret", "access_token", "access_secret"):
                value = values.get(key, "")
                if (
                    not value
                    or len(value) > 4096
                    or any(ord(char) < 33 or ord(char) > 126 for char in value)
                ):
                    raise EtradeReadError("SCOPED_ACCESS_TOKEN_OR_CONSUMER_UNAVAILABLE")
                self._values[key] = bytearray(value, "ascii")
            self.issued_at = _instant(values.get("issued_at"))
            self.last_activity_at = _instant(values.get("last_activity_at"))
            self.expires_at = _instant(values.get("expires_at"))
            if not self.issued_at <= self.last_activity_at < self.expires_at:
                raise EtradeReadError("TOKEN_TIME_METADATA_INVALID")
        except Exception:
            self.close()
            raise

    def _value(self, name: str) -> str:
        if not self._values:
            raise EtradeReadError("CREDENTIALS_CLOSED")
        return self._values[name].decode("ascii")

    def close(self) -> None:
        for value in self._values.values():
            value[:] = b"\x00" * len(value)
        self._values.clear()

    def __repr__(self) -> str:
        return "EtradeReadCredentials(<redacted>)"

    def __reduce__(self) -> Any:
        raise TypeError("E*TRADE credentials cannot be serialized")


class EtradeCredentialStore(Protocol):
    def resolve(self, reference: EtradeSecretReference) -> EtradeReadCredentials: ...


@dataclass(frozen=True, slots=True)
class EtradeSecretPresence:
    environment: EtradeEnvironment
    consumer_pair_present: bool
    scoped_access_pair_present: bool
    scoped_token_times_present: bool
    unscoped_access_pair_present: bool

    @property
    def blocker(self) -> str | None:
        if not self.consumer_pair_present:
            return "ENVIRONMENT_CONSUMER_PAIR_MISSING"
        if not self.scoped_access_pair_present:
            return "OWNER_OAUTH_CONSENT_AND_ENVIRONMENT_BOUND_ACCESS_TOKEN_REQUIRED"
        if not self.scoped_token_times_present:
            return "TOKEN_LIFECYCLE_METADATA_REQUIRED"
        return None


class EnvFileEtradeCredentialStore:
    """Reads only one explicit file, no shell/eval/interpolation or fallback.

    ETRADE_SANDBOX_* and ETRADE_PROD_* are independent namespaces. Legacy
    unscoped access tokens are reported as present only and never consumed.
    Presence inspection returns booleans; it never returns any secret values.
    """

    @staticmethod
    def _read(reference: EtradeSecretReference) -> dict[str, str]:
        reference.__post_init__()
        parts = urlsplit(reference.uri)
        if parts.scheme != "envfile":
            raise EtradeReadError("ENVFILE_REFERENCE_REQUIRED")
        prefix = (
            "ETRADE_SANDBOX_"
            if reference.environment is EtradeEnvironment.SANDBOX
            else "ETRADE_PROD_"
        )
        names = {
            prefix + suffix
            for suffix in (
                "CONSUMER_KEY",
                "CONSUMER_SECRET",
                "ACCESS_TOKEN",
                "ACCESS_SECRET",
                "TOKEN_ISSUED_AT",
                "TOKEN_LAST_ACTIVITY_AT",
                "TOKEN_EXPIRES_AT",
            )
        } | {"ETRADE_ACCESS_TOKEN", "ETRADE_ACCESS_SECRET"}
        try:
            with Path(parts.path).open("rb") as source:
                raw = source.read(MAX_SECRET_FILE_BYTES + 1)
            if len(raw) > MAX_SECRET_FILE_BYTES:
                raise EtradeReadError("SECRET_FILE_TOO_LARGE")
            lines = raw.decode("utf-8").splitlines()
        except (OSError, UnicodeError):
            raise EtradeReadError("SECRET_STORE_UNAVAILABLE") from None
        result: dict[str, str] = {}
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("export "):
                stripped = stripped[7:]
            name, separator, value = stripped.partition("=")
            name = name.strip()
            if not separator or name not in names:
                continue
            if name in result:
                raise EtradeReadError("DUPLICATE_SCOPED_SECRET_VARIABLE")
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            elif " #" in value:
                value = value.split(" #", 1)[0].rstrip()
            if "$" in value or "`" in value or "\\" in value:
                raise EtradeReadError("SECRET_FILE_INTERPOLATION_UNSUPPORTED")
            result[name] = value
        return result

    def inspect(self, reference: EtradeSecretReference) -> EtradeSecretPresence:
        values = self._read(reference)
        prefix = (
            "ETRADE_SANDBOX_"
            if reference.environment is EtradeEnvironment.SANDBOX
            else "ETRADE_PROD_"
        )
        return EtradeSecretPresence(
            reference.environment,
            all(
                bool(values.get(prefix + suffix)) for suffix in ("CONSUMER_KEY", "CONSUMER_SECRET")
            ),
            all(bool(values.get(prefix + suffix)) for suffix in ("ACCESS_TOKEN", "ACCESS_SECRET")),
            all(
                bool(values.get(prefix + suffix))
                for suffix in ("TOKEN_ISSUED_AT", "TOKEN_LAST_ACTIVITY_AT", "TOKEN_EXPIRES_AT")
            ),
            all(bool(values.get(name)) for name in ("ETRADE_ACCESS_TOKEN", "ETRADE_ACCESS_SECRET")),
        )

    def resolve(self, reference: EtradeSecretReference) -> EtradeReadCredentials:
        values = self._read(reference)
        prefix = (
            "ETRADE_SANDBOX_"
            if reference.environment is EtradeEnvironment.SANDBOX
            else "ETRADE_PROD_"
        )
        return EtradeReadCredentials(
            reference,
            {
                target: values.get(prefix + suffix, "")
                for target, suffix in (
                    ("consumer_key", "CONSUMER_KEY"),
                    ("consumer_secret", "CONSUMER_SECRET"),
                    ("access_token", "ACCESS_TOKEN"),
                    ("access_secret", "ACCESS_SECRET"),
                    ("issued_at", "TOKEN_ISSUED_AT"),
                    ("last_activity_at", "TOKEN_LAST_ACTIVITY_AT"),
                    ("expires_at", "TOKEN_EXPIRES_AT"),
                )
            },
        )


class MacOSKeychainEtradeCredentialStore:
    """Exact generic-password lookup; does not enumerate, create, or migrate items.

    JSON item schema: environment, version, consumer_key, consumer_secret,
    access_token, access_secret, issued_at, last_activity_at, expires_at.
    """

    def resolve(self, reference: EtradeSecretReference) -> EtradeReadCredentials:
        reference.__post_init__()
        parts = urlsplit(reference.uri)
        if parts.scheme != "keychain":
            raise EtradeReadError("KEYCHAIN_REFERENCE_REQUIRED")
        try:
            result = subprocess.run(
                [
                    "/usr/bin/security",
                    "find-generic-password",
                    "-s",
                    parts.netloc,
                    "-a",
                    parts.path[1:],
                    "-w",
                ],
                capture_output=True,
                check=False,
                timeout=3,
                env={"PATH": "/usr/bin:/bin"},
            )
            if result.returncode or len(result.stdout) > MAX_SECRET_FILE_BYTES:
                raise EtradeReadError("SECRET_STORE_UNAVAILABLE")
            values = json.loads(result.stdout, object_pairs_hook=_unique_object)
            if (
                type(values) is not dict
                or values.pop("environment", None) != reference.environment.value
            ):
                raise EtradeReadError("SECRET_REFERENCE_ENVIRONMENT_MISMATCH")
            if values.pop("version", None) != reference.version:
                raise EtradeReadError("SECRET_REFERENCE_VERSION_MISMATCH")
            if set(values) != {
                "consumer_key",
                "consumer_secret",
                "access_token",
                "access_secret",
                "issued_at",
                "last_activity_at",
                "expires_at",
            }:
                raise EtradeReadError("SECRET_ITEM_SCHEMA_INVALID")
            if any(type(value) is not str for value in values.values()):
                raise EtradeReadError("SECRET_ITEM_SCHEMA_INVALID")
            return EtradeReadCredentials(reference, values)
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError, UnicodeError):
            raise EtradeReadError("SECRET_STORE_UNAVAILABLE") from None


@dataclass(frozen=True, slots=True)
class EtradeReadRequest:
    environment: EtradeEnvironment
    operation: EtradeReadOperation
    account_key: EtradeAccountIdKey | None = field(default=None, repr=False)
    query: tuple[tuple[str, str], ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.environment) is not EtradeEnvironment
            or type(self.operation) is not EtradeReadOperation
        ):
            raise EtradeReadError("READ_OPERATION_OR_ENVIRONMENT_INVALID")
        if self.operation is EtradeReadOperation.ACCOUNTS:
            if self.account_key is not None or self.query:
                raise EtradeReadError("DISCOVERY_SCOPE_INVALID")
            return
        if type(self.account_key) is not EtradeAccountIdKey:
            raise EtradeReadError("EXPLICIT_ACCOUNT_REQUIRED")
        self.account_key.__post_init__()
        allowed = {
            EtradeReadOperation.BALANCES: {"instType", "realTimeNAV"},
            EtradeReadOperation.PORTFOLIO: {"count", "pageNumber", "view", "marketSession"},
            EtradeReadOperation.ORDERS: {"count", "marker", "fromDate", "toDate"},
            EtradeReadOperation.ACTIVITY: {"count", "marker", "startDate", "endDate", "sortOrder"},
        }[self.operation]
        if type(self.query) is not tuple or len(dict(self.query)) != len(self.query):
            raise EtradeReadError("READ_QUERY_INVALID")
        for name, value in self.query:
            if (
                name not in allowed
                or type(value) is not str
                or len(value) > 1024
                or any(ord(c) < 32 for c in value)
            ):
                raise EtradeReadError("READ_QUERY_INVALID")

    @property
    def origin(self) -> str:
        return (
            "https://apisb.etrade.com"
            if self.environment is EtradeEnvironment.SANDBOX
            else "https://api.etrade.com"
        )

    @property
    def path(self) -> str:
        if self.operation is EtradeReadOperation.ACCOUNTS:
            return "/v1/accounts/list"
        assert self.account_key is not None
        suffix = {
            EtradeReadOperation.BALANCES: "balance",
            EtradeReadOperation.PORTFOLIO: "portfolio",
            EtradeReadOperation.ORDERS: "orders",
            EtradeReadOperation.ACTIVITY: "transactions",
        }[self.operation]
        return f"/v1/accounts/{self.account_key.value}/{suffix}"

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            json.dumps(
                (self.environment.value, self.path, self.query),
                separators=(",", ":"),
            ).encode()
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class EtradeReadResponse:
    request_digest: str
    status: int
    body: bytes = field(repr=False)
    content_type: str = "application/json"


class EtradeGetTransport(Protocol):
    evidence_class: str

    def get(
        self, request: EtradeReadRequest, *, authorization: str, deadline_seconds: float
    ) -> EtradeReadResponse: ...


def sign_account_get(
    request: EtradeReadRequest,
    credentials: EtradeReadCredentials,
    *,
    at: datetime,
    nonce: str,
) -> str:
    """OAuth 1.0a HMAC-SHA1 for this bounded GET request, including query params."""
    request.__post_init__()
    require_utc(at)
    EtradeOAuthNonce(nonce)
    if credentials.reference.environment is not request.environment:
        raise EtradeReadError("SECRET_REFERENCE_ENVIRONMENT_MISMATCH")
    encode = etrade_oauth_percent_encode
    params = [
        ("oauth_consumer_key", credentials._value("consumer_key")),
        ("oauth_token", credentials._value("access_token")),
        ("oauth_nonce", nonce),
        ("oauth_timestamp", str(int(at.timestamp()))),
        ("oauth_signature_method", "HMAC-SHA1"),
    ]
    normalized = "&".join(
        f"{name}={value}"
        for name, value in sorted(
            (encode(name), encode(value)) for name, value in [*params, *request.query]
        )
    )
    base = "&".join(("GET", encode(request.origin + request.path), encode(normalized)))
    key = (
        encode(credentials._value("consumer_secret"))
        + "&"
        + encode(credentials._value("access_secret"))
    )
    signature = base64.b64encode(
        hmac.new(key.encode(), base.encode(), hashlib.sha1).digest()
    ).decode()
    return "OAuth " + ", ".join(
        f'{encode(name)}="{encode(value)}"'
        for name, value in sorted([*params, ("oauth_signature", signature)])
    )


class EtradeHTTPSGetTransport:
    """Pinned TLS GETs, no redirects/proxies/retry/order endpoints; total deadline."""

    evidence_class = "provider_https_read"

    def get(
        self, request: EtradeReadRequest, *, authorization: str, deadline_seconds: float
    ) -> EtradeReadResponse:
        request.__post_init__()
        if not 0 < deadline_seconds <= REQUEST_DEADLINE_SECONDS:
            raise EtradeReadError("REQUEST_DEADLINE_INVALID")
        started = time.monotonic()
        hostname = (
            "apisb.etrade.com"
            if request.environment is EtradeEnvironment.SANDBOX
            else "api.etrade.com"
        )
        context = ssl.create_default_context()
        connection = http.client.HTTPSConnection(
            hostname, timeout=deadline_seconds, context=context
        )
        deadline_timer: threading.Timer | None = None
        try:
            # DNS gets a separate daemon that never sees credentials. A timed-out
            # resolver may finish later, but cannot send an HTTP request.
            resolved: queue.Queue[list[Any] | None] = queue.Queue(maxsize=1)
            resolver = threading.Thread(
                target=_resolve_hostname, args=(hostname, resolved), daemon=True
            )
            resolver.start()
            remaining = deadline_seconds - (time.monotonic() - started)
            if remaining <= 0:
                raise EtradeReadError("READ_DEADLINE_EXCEEDED")
            try:
                addresses = resolved.get(timeout=remaining)
            except queue.Empty:
                raise EtradeReadError("READ_DEADLINE_EXCEEDED") from None
            if not addresses:
                raise EtradeReadError("READ_TRANSPORT_FAILED")
            for family, kind, protocol, _, address in addresses[:4]:
                remaining = deadline_seconds - (time.monotonic() - started)
                if remaining <= 0:
                    raise EtradeReadError("READ_DEADLINE_EXCEEDED")
                raw_socket = socket.socket(family, kind, protocol)
                try:
                    raw_socket.settimeout(remaining)
                    raw_socket.connect(address)
                    remaining = deadline_seconds - (time.monotonic() - started)
                    if remaining <= 0:
                        raise EtradeReadError("READ_DEADLINE_EXCEEDED")
                    raw_socket.settimeout(remaining)
                    connection.sock = context.wrap_socket(raw_socket, server_hostname=hostname)
                    break
                except OSError:
                    raw_socket.close()
                except Exception:
                    raw_socket.close()
                    raise
            # Keep the socket even when getresponse handles Connection: close by
            # clearing connection.sock while the response still owns its stream.
            transport_socket = connection.sock
            remaining = deadline_seconds - (time.monotonic() - started)
            if remaining <= 0 or transport_socket is None:
                raise EtradeReadError("READ_DEADLINE_EXCEEDED")
            transport_socket.settimeout(remaining)
            # An absolute timer also bounds slow/dripping response headers, for
            # which a per-receive socket timeout alone is insufficient.
            deadline_timer = threading.Timer(remaining, _expire_socket, args=(transport_socket,))
            deadline_timer.daemon = True
            deadline_timer.start()
            path = request.path + (
                "?" + urlencode(request.query, quote_via=quote) if request.query else ""
            )
            connection.request(
                "GET", path, headers={"Authorization": authorization, "Accept": "application/json"}
            )
            response = connection.getresponse()
            chunks: list[bytes] = []
            length = 0
            while True:
                remaining = deadline_seconds - (time.monotonic() - started)
                if remaining <= 0:
                    raise EtradeReadError("READ_DEADLINE_EXCEEDED")
                transport_socket.settimeout(remaining)
                chunk = response.read1(min(65536, MAX_RESPONSE_BYTES + 1 - length))
                if not chunk:
                    break
                chunks.append(chunk)
                length += len(chunk)
                if length > MAX_RESPONSE_BYTES:
                    raise EtradeReadError("RESPONSE_TOO_LARGE")
            return EtradeReadResponse(
                request.digest,
                response.status,
                b"".join(chunks),
                response.getheader("Content-Type", ""),
            )
        except (OSError, http.client.HTTPException):
            raise EtradeReadError("READ_TRANSPORT_FAILED") from None
        finally:
            if deadline_timer is not None:
                deadline_timer.cancel()
            connection.close()


def _resolve_hostname(hostname: str, output: queue.Queue[list[Any] | None]) -> None:
    try:
        output.put(socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM))
    except OSError:
        output.put(None)


def _expire_socket(transport_socket: socket.socket) -> None:
    with suppress(OSError):
        transport_socket.shutdown(socket.SHUT_RDWR)
