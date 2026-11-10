"""Interactive owner OAuth acquisition, isolated from read/order composition.

Official request/access/authorize pages reviewed 2026-09-09. Both environments
use the shared api.etrade.com token host, with distinct consumer credentials.
No import-time effects, retries, revocation, account or order requests. Renewal
uses the separate explicitly authorized renewal workflow.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import os
import queue
import re
import secrets
import socket
import ssl
import subprocess
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from datetime import time as wall_time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit
from zoneinfo import ZoneInfo

from packages.adapters.broker.etrade import (
    ETRADE_SHARED_ACCESS_TOKEN_URL,
    ETRADE_SHARED_AUTHORIZATION_PAGE,
    ETRADE_SHARED_RENEW_ACCESS_TOKEN_URL,
    ETRADE_SHARED_REQUEST_TOKEN_URL,
    EtradeEnvironment,
)
from packages.adapters.broker.etrade_oauth import (
    EtradeOAuthConsumerKey,
    EtradeOAuthConsumerSecret,
    EtradeOAuthNonce,
    EtradeOAuthOperation,
    etrade_oauth_percent_encode,
)
from packages.adapters.broker.etrade_readonly import (
    EnvFileEtradeCredentialStore,
    EtradeReadError,
    EtradeSecretReference,
    _resolve_hostname,
    require_utc,
)

_ENDPOINTS = {
    EtradeOAuthOperation.REQUEST_TOKEN: ETRADE_SHARED_REQUEST_TOKEN_URL,
    EtradeOAuthOperation.ACCESS_TOKEN: ETRADE_SHARED_ACCESS_TOKEN_URL,
    EtradeOAuthOperation.RENEW_ACCESS_TOKEN: ETRADE_SHARED_RENEW_ACCESS_TOKEN_URL,
}


def _literal(value: str) -> str:
    if (
        not value
        or len(value) > 4096
        or any(ord(char) < 33 or ord(char) > 126 for char in value)
        or any(char in value for char in "'\"$`\\")
    ):
        raise EtradeReadError("OAUTH_SECRET_LITERAL_UNSUPPORTED")
    return value


def _signature(
    url: str, parameters: list[tuple[str, str]], consumer_secret: str, token_secret: str
) -> str:
    encode = etrade_oauth_percent_encode
    normalized = "&".join(
        f"{key}={value}"
        for key, value in sorted((encode(key), encode(value)) for key, value in parameters)
    )
    base = "&".join(("GET", encode(url), encode(normalized)))
    key = encode(consumer_secret) + "&" + encode(token_secret)
    return base64.b64encode(hmac.new(key.encode(), base.encode(), hashlib.sha1).digest()).decode()


def _header(
    operation: EtradeOAuthOperation,
    consumer_key: str,
    consumer_secret: str,
    at: datetime,
    nonce: str,
    token: str = "",
    token_secret: str = "",
    verifier: str = "",
) -> str:
    if operation not in _ENDPOINTS:
        raise EtradeReadError("OAUTH_OPERATION_UNSUPPORTED")
    require_utc(at)
    EtradeOAuthNonce(nonce)
    params = [
        ("oauth_consumer_key", consumer_key),
        ("oauth_nonce", nonce),
        ("oauth_timestamp", str(int(at.timestamp()))),
        ("oauth_signature_method", "HMAC-SHA1"),
        ("oauth_version", "1.0"),
    ]
    if operation is EtradeOAuthOperation.REQUEST_TOKEN:
        if token or token_secret or verifier:
            raise EtradeReadError("REQUEST_TOKEN_SCOPE_INVALID")
        params.append(("oauth_callback", "oob"))
    elif operation is EtradeOAuthOperation.ACCESS_TOKEN:
        for value in (token, token_secret, verifier):
            _literal(value)
        params += [("oauth_token", token), ("oauth_verifier", verifier)]
    else:
        for value in (token, token_secret):
            _literal(value)
        if verifier:
            raise EtradeReadError("RENEWAL_VERIFIER_UNSUPPORTED")
        params.append(("oauth_token", token))
    params.append(
        (
            "oauth_signature",
            _signature(_ENDPOINTS[operation], params, consumer_secret, token_secret),
        )
    )
    encode = etrade_oauth_percent_encode
    return "OAuth " + ", ".join(f'{encode(key)}="{encode(value)}"' for key, value in sorted(params))


def _parse_form(body: bytes, *, request_token: bool) -> tuple[str, str]:
    try:
        if type(body) is not bytes or not body or len(body) > 16384:
            raise ValueError
        text = body.decode("ascii")
        if re.search(r"%(?![0-9a-fA-F]{2})", text):
            raise ValueError
        pairs = parse_qsl(
            text, keep_blank_values=True, strict_parsing=True, encoding="ascii", errors="strict"
        )
        fields = dict(pairs)
        required = {"oauth_token", "oauth_token_secret"}
        if request_token:
            required.add("oauth_callback_confirmed")
        if len(pairs) != len(fields) or set(fields) != required:
            raise ValueError
        # E*TRADE documents false when no callback URL is configured; manual OOB
        # authorization remains valid. Do not inherit the old fixture-only true rule.
        if request_token and fields["oauth_callback_confirmed"] not in ("true", "false"):
            raise ValueError
        return _literal(fields["oauth_token"]), _literal(fields["oauth_token_secret"])
    except (ValueError, UnicodeError):
        raise EtradeReadError("OAUTH_TOKEN_RESPONSE_REJECTED") from None


def exchange_token(operation: EtradeOAuthOperation, authorization: str) -> bytes:
    """One fixed HTTPS token GET; no redirects, retries or response logging."""
    if operation not in _ENDPOINTS:
        raise EtradeReadError("OAUTH_OPERATION_UNSUPPORTED")
    context = ssl.create_default_context()
    connection = http.client.HTTPSConnection("api.etrade.com", timeout=3, context=context)
    timer: threading.Timer | None = None
    started = time.monotonic()
    try:
        resolved: queue.Queue[list[Any] | None] = queue.Queue(maxsize=1)
        resolver = threading.Thread(
            target=_resolve_hostname, args=("api.etrade.com", resolved), daemon=True
        )
        resolver.start()
        remaining = 3 - (time.monotonic() - started)
        if remaining <= 0:
            raise EtradeReadError("OAUTH_EXCHANGE_UNCERTAIN_NO_RETRY")
        try:
            addresses = resolved.get(timeout=remaining)
        except queue.Empty:
            raise EtradeReadError("OAUTH_DNS_DEADLINE_NO_REQUEST_SENT") from None
        if not addresses:
            raise EtradeReadError("OAUTH_DNS_UNAVAILABLE_NO_REQUEST_SENT")
        for family, kind, protocol, _, address in addresses[:4]:
            raw_socket = socket.socket(family, kind, protocol)
            try:
                remaining = 3 - (time.monotonic() - started)
                if remaining <= 0:
                    raise EtradeReadError("OAUTH_EXCHANGE_UNCERTAIN_NO_RETRY")
                raw_socket.settimeout(remaining)
                raw_socket.connect(address)
                remaining = 3 - (time.monotonic() - started)
                if remaining <= 0:
                    raise EtradeReadError("OAUTH_EXCHANGE_UNCERTAIN_NO_RETRY")
                raw_socket.settimeout(remaining)
                connection.sock = context.wrap_socket(raw_socket, server_hostname="api.etrade.com")
                break
            except OSError:
                raw_socket.close()
            except Exception:
                raw_socket.close()
                raise
        transport_socket = connection.sock
        remaining = 3 - (time.monotonic() - started)
        if transport_socket is None or remaining <= 0:
            raise EtradeReadError("OAUTH_EXCHANGE_UNCERTAIN_NO_RETRY")
        transport_socket.settimeout(remaining)
        timer = threading.Timer(remaining, _shutdown, args=(transport_socket,))
        timer.daemon = True
        timer.start()
        renewing = operation is EtradeOAuthOperation.RENEW_ACCESS_TOKEN
        connection.request(
            "GET",
            urlsplit(_ENDPOINTS[operation]).path,
            headers={
                "Authorization": authorization,
                "Accept": "text/plain" if renewing else "application/x-www-form-urlencoded",
            },
        )
        response = connection.getresponse()
        if response.status != 200:
            raise EtradeReadError("OAUTH_REJECTED_OR_UNCERTAIN_NO_RETRY")
        content_type = response.getheader("Content-Type", "").split(";", 1)[0].lower().strip()
        if not renewing and content_type not in ("application/x-www-form-urlencoded", "text/plain"):
            raise EtradeReadError("OAUTH_TOKEN_RESPONSE_MEDIA_TYPE_UNSUPPORTED")
        limit = 256 if renewing else 16384
        body = response.read(limit + 1)
        if len(body) > limit or time.monotonic() - started >= 3:
            raise EtradeReadError("OAUTH_EXCHANGE_UNCERTAIN_NO_RETRY")
        if renewing and body.strip(b" \t\r\n") != b"Access Token has been renewed":
            raise EtradeReadError("OAUTH_RENEWAL_RESPONSE_REJECTED")
        return body
    except (OSError, http.client.HTTPException):
        raise EtradeReadError("OAUTH_EXCHANGE_UNCERTAIN_NO_RETRY") from None
    finally:
        if timer is not None:
            timer.cancel()
        connection.close()


def _shutdown(transport_socket: socket.socket) -> None:
    with suppress(OSError):
        transport_socket.shutdown(2)


def open_authorization(url: str) -> bool:
    """macOS system opener with no BROWSER/shell override or inherited output."""
    try:
        result = subprocess.run(
            ["/usr/bin/open", url],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin"},
            timeout=5,
            check=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        raise EtradeReadError("OAUTH_BROWSER_OPEN_FAILED") from None


def acquire_owner_session(
    *,
    reference: EtradeSecretReference,
    output: Path,
    verifier_input: Callable[[], str],
    exchange: Callable[[EtradeOAuthOperation, str], bytes] = exchange_token,
    browser: Callable[[str], bool] = open_authorization,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    monotonic: Callable[[], float] = time.monotonic,
    nonce: Callable[[], str] = lambda: secrets.token_hex(24),
) -> dict[str, object]:
    """Caller must establish a real interactive terminal before invoking this seam.

    Reserves a new private file before resolving credentials. Failures retain only
    phase/outcome comments; a used attempt is never silently retried or replaced.
    """
    reference.__post_init__()
    if urlsplit(reference.uri).scheme != "envfile":
        raise EtradeReadError("EXPLICIT_ENVFILE_CONSUMER_REFERENCE_REQUIRED")
    root = Path(__file__).resolve().parents[3]
    if not output.is_absolute() or root == output.resolve() or root in output.resolve().parents:
        raise EtradeReadError("SESSION_OUTPUT_MUST_BE_PRIVATE_AND_OUTSIDE_CHECKOUT")
    # Validate exact resulting reader reference before any effects.
    result_reference = EtradeSecretReference(reference.environment, f"envfile://{output}?version=1")
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        last_phase = "RESERVED"

        def phase(value: str) -> None:
            nonlocal last_phase
            message = f"# oauth_attempt_phase={value}\n".encode()
            if os.write(descriptor, message) != len(message):
                raise OSError("short attempt write")
            os.fsync(descriptor)
            last_phase = value

        phase("RESERVED")
        try:
            values = EnvFileEtradeCredentialStore._read(reference)
            prefix = (
                "ETRADE_SANDBOX_"
                if reference.environment is EtradeEnvironment.SANDBOX
                else "ETRADE_PROD_"
            )
            key = _literal(values.get(prefix + "CONSUMER_KEY", ""))
            secret = _literal(values.get(prefix + "CONSUMER_SECRET", ""))
            EtradeOAuthConsumerKey(key)
            EtradeOAuthConsumerSecret(secret)
            del values
            request_start = require_utc(now())
            mono_start = monotonic()
            first_nonce = nonce()
            request_header = _header(
                EtradeOAuthOperation.REQUEST_TOKEN, key, secret, request_start, first_nonce
            )
            phase("REQUEST_TOKEN_DISPATCHING")
            token, token_secret = _parse_form(
                exchange(EtradeOAuthOperation.REQUEST_TOKEN, request_header), request_token=True
            )
            del request_header
            request_received = require_utc(now())
            request_elapsed = monotonic() - mono_start
            if (
                request_elapsed < 0
                or request_elapsed >= 300
                or abs((request_received - request_start).total_seconds() - request_elapsed) >= 1
            ):
                raise EtradeReadError("OAUTH_REQUEST_TOKEN_EXPIRED_OR_CLOCK_CHANGED")
            phase("OWNER_CONSENT_PENDING")
            if not browser(
                ETRADE_SHARED_AUTHORIZATION_PAGE + "?" + urlencode({"key": key, "token": token})
            ):
                raise EtradeReadError("OAUTH_BROWSER_OPEN_FAILED")
            verifier = _literal(verifier_input())
            access_start = require_utc(now())
            access_mono = monotonic()
            elapsed = access_mono - mono_start
            if (
                elapsed < 0
                or elapsed >= 300
                or abs((access_start - request_start).total_seconds() - elapsed) >= 1
            ):
                raise EtradeReadError("OAUTH_REQUEST_TOKEN_EXPIRED_OR_CLOCK_CHANGED")
            second_nonce = nonce()
            if second_nonce == first_nonce:
                raise EtradeReadError("OAUTH_NONCE_REUSED")
            access_header = _header(
                EtradeOAuthOperation.ACCESS_TOKEN,
                key,
                secret,
                access_start,
                second_nonce,
                token,
                token_secret,
                verifier,
            )
            del token, token_secret, verifier
            phase("ACCESS_TOKEN_DISPATCHING")
            access_token, access_secret = _parse_form(
                exchange(EtradeOAuthOperation.ACCESS_TOKEN, access_header), request_token=False
            )
            del access_header
            received = require_utc(now())
            access_elapsed = monotonic() - access_mono
            if (
                access_elapsed < 0
                or access_elapsed >= 3
                or abs((received - access_start).total_seconds() - access_elapsed) >= 1
            ):
                raise EtradeReadError("OAUTH_ACCESS_DEADLINE_OR_CLOCK_CHANGED")
            eastern = access_start.astimezone(ZoneInfo("America/New_York"))
            expires = datetime.combine(
                eastern.date() + timedelta(days=1), wall_time(), ZoneInfo("America/New_York")
            ).astimezone(UTC)
            if received < access_start or received >= expires:
                raise EtradeReadError("OAUTH_MIDNIGHT_OR_CLOCK_BOUNDARY_REAUTHORIZE")
            fields = {
                "CONSUMER_KEY": key,
                "CONSUMER_SECRET": secret,
                "ACCESS_TOKEN": access_token,
                "ACCESS_SECRET": access_secret,
                "TOKEN_ISSUED_AT": access_start.isoformat(),
                "TOKEN_LAST_ACTIVITY_AT": access_start.isoformat(),
                "TOKEN_EXPIRES_AT": expires.isoformat(),
            }
            payload = (
                "# lifecycle_basis=local_access_request_start_conservative\n"
                "# expiry_basis=documented_default_next_eastern_midnight\n"
            )
            payload += "".join(
                f"{prefix}{name}='{_literal(value)}'\n" for name, value in fields.items()
            )
            encoded = payload.encode()
            if os.write(descriptor, encoded) != len(encoded):
                raise OSError("short session write")
            phase("ACCESS_TOKEN_SAVED")
            parent_descriptor = os.open(output.parent, os.O_RDONLY)
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
            return {
                "environment": reference.environment.value,
                "session_reference": result_reference.uri,
                "access_request_started_at": access_start.isoformat(),
                "access_response_received_at": received.isoformat(),
                "expires_at": expires.isoformat(),
                "lifecycle_basis": "local_access_request_start_conservative",
                "expiry_basis": "documented_default_next_eastern_midnight",
                "provider_token_requests": 2,
                "account_requests": 0,
                "trading_authorized": False,
            }
        except BaseException:
            # Unbuffered writes permit truncating catchable publication failures.
            # A process kill cannot run cleanup: review that attempt before retry.
            with suppress(OSError):
                os.ftruncate(descriptor, 0)
                os.lseek(descriptor, 0, os.SEEK_SET)
                os.write(
                    descriptor,
                    (
                        f"# STOPPED_REVIEW_BEFORE_NEW_ATTEMPT\n# stopped_after_phase={last_phase}\n"
                    ).encode(),
                )
                os.fsync(descriptor)
            raise

    finally:
        # Successful fsync is the durability boundary; close performs no buffered write.
        with suppress(OSError):
            os.close(descriptor)
