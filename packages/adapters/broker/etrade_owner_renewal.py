"""One supervised OAuth renewal; no browser, retry, account or order requests.

The existing access token and issuance remain unchanged. Local renewal request
start becomes a conservative activity observation only after documented success.
The original expiry is never extended. See the official renew_access_token page.
"""

from __future__ import annotations

import os
import secrets
import time
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from datetime import time as wall_time
from pathlib import Path
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from packages.adapters.broker.etrade import EtradeEnvironment
from packages.adapters.broker.etrade_oauth import EtradeOAuthOperation
from packages.adapters.broker.etrade_owner_oauth import _header, _literal, exchange_token
from packages.adapters.broker.etrade_readonly import (
    EnvFileEtradeCredentialStore,
    EtradeReadError,
    EtradeSecretReference,
    require_utc,
)


def renew_owner_session(
    *,
    reference: EtradeSecretReference,
    output: Path,
    authorize_renew: bool,
    exchange: Callable[[EtradeOAuthOperation, str], bytes] = exchange_token,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    monotonic: Callable[[], float] = time.monotonic,
    nonce: Callable[[], str] = lambda: secrets.token_hex(24),
) -> dict[str, object]:
    """Reserve a new private attempt before credentials or one renewal dispatch.

    Catchable failures truncate this new file to phase comments. Process kills
    cannot run cleanup; review every failed/interrupted attempt before retrying.
    """
    if authorize_renew is not True:
        raise EtradeReadError("EXPLICIT_RENEWAL_AUTHORIZATION_REQUIRED")
    reference.__post_init__()
    if urlsplit(reference.uri).scheme != "envfile" or reference.version != 1:
        raise EtradeReadError("EXPLICIT_V1_ENVFILE_SESSION_REFERENCE_REQUIRED")
    root = Path(__file__).resolve().parents[3]
    if not output.is_absolute() or root == output.resolve() or root in output.resolve().parents:
        raise EtradeReadError("SESSION_OUTPUT_MUST_BE_PRIVATE_AND_OUTSIDE_CHECKOUT")
    result_reference = EtradeSecretReference(reference.environment, f"envfile://{output}?version=1")
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    last_phase = "RESERVED"

    def phase(value: str) -> None:
        nonlocal last_phase
        encoded = f"# oauth_renewal_phase={value}\n".encode()
        if os.write(descriptor, encoded) != len(encoded):
            raise OSError("short attempt write")
        os.fsync(descriptor)
        last_phase = value

    try:
        phase("RESERVED")
        credentials = EnvFileEtradeCredentialStore().resolve(reference)
        try:
            started, mono_start = require_utc(now()), monotonic()
            eastern = credentials.issued_at.astimezone(ZoneInfo("America/New_York"))
            midnight = datetime.combine(
                eastern.date() + timedelta(days=1), wall_time(), ZoneInfo("America/New_York")
            ).astimezone(UTC)
            expires = min(credentials.expires_at, midnight)
            if started < credentials.last_activity_at or started < credentials.issued_at:
                raise EtradeReadError("TOKEN_TIME_METADATA_FUTURE")
            if started >= expires:
                raise EtradeReadError("DAILY_REAUTHORIZATION_REQUIRED")
            fields = {
                name: _literal(credentials._value(key))
                for name, key in (
                    ("CONSUMER_KEY", "consumer_key"),
                    ("CONSUMER_SECRET", "consumer_secret"),
                    ("ACCESS_TOKEN", "access_token"),
                    ("ACCESS_SECRET", "access_secret"),
                )
            }
            authorization = _header(
                EtradeOAuthOperation.RENEW_ACCESS_TOKEN,
                fields["CONSUMER_KEY"],
                fields["CONSUMER_SECRET"],
                started,
                nonce(),
                fields["ACCESS_TOKEN"],
                fields["ACCESS_SECRET"],
            )
            phase("RENEWAL_DISPATCHING")
            body = exchange(EtradeOAuthOperation.RENEW_ACCESS_TOKEN, authorization)
            del authorization
            received, elapsed = require_utc(now()), monotonic() - mono_start
            if (
                elapsed < 0
                or elapsed >= 3
                or received < started
                or received >= expires
                or abs((received - started).total_seconds() - elapsed) >= 1
            ):
                raise EtradeReadError("RENEWAL_DEADLINE_EXPIRY_OR_CLOCK_CHANGED")
            if (
                type(body) is not bytes
                or len(body) > 256
                or body.strip(b" \t\r\n") != b"Access Token has been renewed"
            ):
                raise EtradeReadError("OAUTH_RENEWAL_RESPONSE_REJECTED")
            del body
            fields.update(
                {
                    "TOKEN_ISSUED_AT": credentials.issued_at.isoformat(),
                    "TOKEN_LAST_ACTIVITY_AT": started.isoformat(),
                    "TOKEN_EXPIRES_AT": expires.isoformat(),
                }
            )
            prefix = (
                "ETRADE_SANDBOX_"
                if reference.environment is EtradeEnvironment.SANDBOX
                else "ETRADE_PROD_"
            )
            payload = (
                "# lifecycle_basis=original_issuance_and_local_renewal_request_start\n"
                "# expiry_basis=min_original_and_original_issue_next_eastern_midnight\n"
                f"# renewal_response_received_at={received.isoformat()}\n"
                + "".join(f"{prefix}{name}='{_literal(value)}'\n" for name, value in fields.items())
            ).encode()
            if os.write(descriptor, payload) != len(payload):
                raise OSError("short session write")
            phase("RENEWED_SESSION_SAVED")
            parent_descriptor = os.open(output.parent, os.O_RDONLY)
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
            return {
                "environment": reference.environment.value,
                "session_reference": result_reference.uri,
                "renewal_request_started_at": started.isoformat(),
                "renewal_response_received_at": received.isoformat(),
                "expires_at": expires.isoformat(),
                "lifecycle_basis": "original_issuance_and_local_renewal_request_start",
                "expiry_basis": "min_original_and_original_issue_next_eastern_midnight",
                "token_rotated": False,
                "provider_token_requests": 1,
                "account_requests": 0,
                "trading_authorized": False,
            }
        finally:
            credentials.close()
    except BaseException:
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
        with suppress(OSError):
            os.close(descriptor)
