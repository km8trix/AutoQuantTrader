"""One-composition permission to request original integrity and fixed metadata.

This purpose never authenticates a command. The private signing nonce and public
composition identity are independent; the supported transport is explicitly local.
Actual proof availability remains the original L/K port's responsibility.
"""

import base64
import binascii
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Final

from fastapi import HTTPException, Response

from apps.api.contracts import ContinuousOperationalReadCapabilityView
from packages.domain.durable_journal_contracts import journal_identifier

CONTINUOUS_READ_SESSION_COOKIE: Final = "aqt_continuous_read_session"
CONTINUOUS_READ_CSRF_HEADER: Final = "X-Continuous-Read-CSRF-Token"
CONTINUOUS_READ_SESSION_PURPOSE: Final = "continuous-operational-read/1"
_SESSION_SECONDS = 8 * 60 * 60
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_SAFE_TOKEN_CHARACTERS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
_CACHE_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}


@dataclass(frozen=True, slots=True)
class ContinuousReadAccessConfiguration:
    enabled: bool
    transport_is_loopback_scoped: bool
    operator_id: str
    configured_secret: str = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool or type(self.transport_is_loopback_scoped) is not bool:
            raise ValueError("continuous read security flags must be exact booleans")
        if self.enabled and not self.transport_is_loopback_scoped:
            raise ValueError("continuous read access requires a loopback-scoped transport")
        if (
            type(self.operator_id) is not str
            or not self.operator_id
            or self.operator_id != self.operator_id.strip()
            or len(self.operator_id) > 128
            or any(ord(character) < 32 for character in self.operator_id)
        ):
            raise ValueError("continuous read operator ID must be bounded trimmed text")
        if type(self.configured_secret) is not str:
            raise ValueError("continuous read session secret must be text")
        try:
            self.operator_id.encode("utf-8")
            self.configured_secret.encode("utf-8")
        except UnicodeError:
            raise ValueError("continuous read configuration is not valid UTF-8") from None


@dataclass(frozen=True, slots=True)
class _AuthenticatedContinuousReader:
    operator_id: str
    csrf_token: str
    expires_at: datetime


def _utc_epoch(value: datetime) -> int:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise HTTPException(503, "continuous read UTC is unavailable", headers=dict(_CACHE_HEADERS))
    return (value - _EPOCH) // timedelta(seconds=1)


class ContinuousReadAccessSecurity:
    """Accept only this account and permanently single-use composition scope."""

    __slots__ = ("_account_id", "_enabled", "_key", "_lock", "_operator_id", "_phase", "_scope")

    def __init__(
        self, *, configuration: ContinuousReadAccessConfiguration, account_id: str
    ) -> None:
        if type(configuration) is not ContinuousReadAccessConfiguration:
            raise ValueError("exact continuous read configuration required")
        configuration.__post_init__()
        journal_identifier(account_id)
        try:
            account_id.encode("utf-8")
        except UnicodeError:
            raise ValueError("continuous read account is not valid UTF-8") from None
        self._key = hashlib.sha256(
            CONTINUOUS_READ_SESSION_PURPOSE.encode("ascii")
            + b"\0"
            + configuration.configured_secret.encode("utf-8")
            + b"\0"
            + secrets.token_bytes(32)
        ).digest()
        # Public identity is not signing entropy. 32hex also keeps every original
        # valid account/operator combination inside the original2048 token cap.
        self._scope = secrets.token_hex(16)
        self._enabled = configuration.enabled
        self._operator_id = configuration.operator_id
        self._account_id = account_id
        self._lock = Lock()
        self._phase = "new"

    def open(self) -> None:
        """Called only after this composition's original L entry returned."""
        with self._lock:
            if self._phase != "new":
                raise RuntimeError("CONTINUOUS_READ_SCOPE_ALREADY_USED")
            self._phase = "open"

    def close(self) -> None:
        with self._lock:
            self._phase = "closed"

    def is_open(self) -> bool:
        with self._lock:
            return self._phase == "open"

    def bootstrap_capability(
        self, response: Response, *, issued_at: datetime, session_cookie: str | None
    ) -> ContinuousOperationalReadCapabilityView:
        response.headers.update(_CACHE_HEADERS)
        # Holding the short local lock prevents close from interleaving issuance.
        # No filesystem, SQL, owner, clock supplier or caller callback is used.
        with self._lock:
            if not self._enabled or self._phase != "open":
                response.delete_cookie(CONTINUOUS_READ_SESSION_COOKIE, path="/api/v1")
                return ContinuousOperationalReadCapabilityView(
                    enabled=False,
                    operator_id=None,
                    account_id=None,
                    csrf_token=None,
                    csrf_header=CONTINUOUS_READ_CSRF_HEADER,
                    expires_at=None,
                    disabled_reason="continuous read permission is unavailable",
                )
            issued_epoch = _utc_epoch(issued_at)
            try:
                expires_at = _EPOCH + timedelta(seconds=issued_epoch + _SESSION_SECONDS)
            except OverflowError:
                raise HTTPException(
                    503, "continuous read UTC is unavailable", headers=dict(_CACHE_HEADERS)
                ) from None
            try:
                current = self._decode(session_cookie, now_epoch=issued_epoch)
            except HTTPException:
                current = None
            if current is not None:
                return self._capability(current.csrf_token, current.expires_at)
            cookie, csrf = self._issue(issued_epoch)
            response.set_cookie(
                key=CONTINUOUS_READ_SESSION_COOKIE,
                value=cookie,
                max_age=_SESSION_SECONDS,
                httponly=True,
                secure=False,
                samesite="strict",
                path="/api/v1",
            )
            return self._capability(csrf, expires_at)

    def _capability(
        self, csrf: str, expires_at: datetime
    ) -> ContinuousOperationalReadCapabilityView:
        return ContinuousOperationalReadCapabilityView(
            enabled=True,
            operator_id=self._operator_id,
            account_id=self._account_id,
            csrf_token=csrf,
            csrf_header=CONTINUOUS_READ_CSRF_HEADER,
            expires_at=expires_at,
            disabled_reason=None,
        )

    def authenticate(self, session_cookie: str | None, csrf_token: str, *, now: datetime) -> str:
        with self._lock:
            if not self._enabled:
                raise HTTPException(
                    403, "continuous read permission is disabled", headers=dict(_CACHE_HEADERS)
                )
            if self._phase != "open":
                raise HTTPException(
                    503, "continuous read permission is unavailable", headers=dict(_CACHE_HEADERS)
                )
            session = self._decode(session_cookie, now_epoch=_utc_epoch(now))
            if (
                type(csrf_token) is not str
                or not 32 <= len(csrf_token) <= 128
                or any(character not in _SAFE_TOKEN_CHARACTERS for character in csrf_token)
                or not hmac.compare_digest(session.csrf_token, csrf_token)
            ):
                raise HTTPException(
                    403, "continuous read CSRF validation failed", headers=dict(_CACHE_HEADERS)
                )
            return session.operator_id

    def _issue(self, issued_epoch: int) -> tuple[str, str]:
        csrf = secrets.token_urlsafe(32)
        payload = {
            "account": self._account_id,
            "csrf": csrf,
            "exp": issued_epoch + _SESSION_SECONDS,
            "iat": issued_epoch,
            "purpose": CONTINUOUS_READ_SESSION_PURPOSE,
            "scope": self._scope,
            "sub": self._operator_id,
            "v": 1,
        }
        encoded = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode(
                "utf-8"
            )
        ).rstrip(b"=")
        signature = hmac.new(self._key, encoded, hashlib.sha256).hexdigest()
        return f"{encoded.decode('ascii')}.{signature}", csrf

    def _decode(
        self, session_cookie: str | None, *, now_epoch: int
    ) -> _AuthenticatedContinuousReader:
        unauthorized = HTTPException(
            401,
            "a current continuous read session is required",
            headers={**_CACHE_HEADERS, "WWW-Authenticate": "ContinuousReadSession"},
        )
        if type(session_cookie) is not str or not 1 <= len(session_cookie) <= 2048:
            raise unauthorized
        try:
            encoded_text, signature = session_cookie.split(".", maxsplit=1)
            if (
                not encoded_text
                or any(character not in _SAFE_TOKEN_CHARACTERS for character in encoded_text)
                or len(signature) != 64
                or any(character not in "0123456789abcdef" for character in signature)
            ):
                raise ValueError("invalid continuous read encoding")
            encoded = encoded_text.encode("ascii")
            expected = hmac.new(self._key, encoded, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, signature):
                raise ValueError("invalid continuous read signature")
            raw = base64.b64decode(
                encoded + b"=" * (-len(encoded) % 4), altchars=b"-_", validate=True
            )
            if base64.urlsafe_b64encode(raw).rstrip(b"=") != encoded:
                raise ValueError("noncanonical continuous read encoding")
            payload = json.loads(raw)
            if type(payload) is not dict or set(payload) != {
                "account",
                "csrf",
                "exp",
                "iat",
                "purpose",
                "scope",
                "sub",
                "v",
            }:
                raise ValueError("invalid continuous read fields")
            if (
                json.dumps(
                    payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False
                ).encode("utf-8")
                != raw
            ):
                raise ValueError("noncanonical continuous read payload")
            csrf, expires, issued, scope = (
                payload["csrf"],
                payload["exp"],
                payload["iat"],
                payload["scope"],
            )
            if (
                type(csrf) is not str
                or not 32 <= len(csrf) <= 128
                or any(character not in _SAFE_TOKEN_CHARACTERS for character in csrf)
                or type(expires) is not int
                or type(issued) is not int
                or type(payload["v"]) is not int
                or payload["v"] != 1
                or type(payload["purpose"]) is not str
                or payload["purpose"] != CONTINUOUS_READ_SESSION_PURPOSE
                or type(payload["sub"]) is not str
                or payload["sub"] != self._operator_id
                or type(payload["account"]) is not str
                or payload["account"] != self._account_id
                or type(scope) is not str
                or len(scope) != 32
                or any(character not in "0123456789abcdef" for character in scope)
                or scope != self._scope
                or issued > now_epoch
                or expires <= now_epoch
                or expires - issued != _SESSION_SECONDS
            ):
                raise ValueError("invalid continuous read claims")
            return _AuthenticatedContinuousReader(
                self._operator_id, csrf, _EPOCH + timedelta(seconds=expires)
            )
        except (UnicodeError, ValueError, TypeError, KeyError, OverflowError, binascii.Error):
            raise unauthorized from None
