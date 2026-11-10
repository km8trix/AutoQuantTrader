"""Purpose-separated local sessions for retained metadata reads only.

The caller supplies actual authentication UTC and the established local transport
configuration. Issuance says nothing about database compatibility or operational
readiness. No instance of the original mutation security is created or adapted.
"""

import base64
import binascii
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, Response

METADATA_SESSION_COOKIE = "aqt_metadata_session"
METADATA_CSRF_HEADER = "X-Metadata-CSRF-Token"
METADATA_SESSION_PURPOSE = "continuous-selection-read/1"
_SESSION_VERSION = 1
_SESSION_SECONDS = 8 * 60 * 60
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_SAFE_TOKEN_CHARACTERS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
_CACHE_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}


@dataclass(frozen=True, slots=True)
class MetadataReadCapability:
    enabled: bool
    operator_id: str | None
    csrf_token: str | None
    csrf_header: str
    expires_at: datetime | None
    disabled_reason: str | None


@dataclass(frozen=True, slots=True)
class _AuthenticatedMetadataReader:
    operator_id: str
    csrf_token: str
    expires_at: datetime


def _utc_epoch(value: datetime) -> int:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise HTTPException(
            503, "metadata authentication UTC is unavailable", headers=dict(_CACHE_HEADERS)
        )
    return (value - _EPOCH) // timedelta(seconds=1)


class MetadataAccessSecurity:
    """Accept only this process's fixed-purpose metadata cookie and CSRF value."""

    __slots__ = ("_enabled", "_key", "_operator_id")

    def __init__(
        self,
        *,
        enabled: bool,
        transport_is_loopback_scoped: bool,
        operator_id: str,
        configured_secret: str,
    ) -> None:
        if type(enabled) is not bool or type(transport_is_loopback_scoped) is not bool:
            raise ValueError("metadata security flags must be exact booleans")
        if enabled and not transport_is_loopback_scoped:
            raise ValueError("metadata access requires a loopback-scoped transport")
        if (
            type(operator_id) is not str
            or not operator_id
            or operator_id != operator_id.strip()
            or len(operator_id) > 128
            or any(ord(character) < 32 for character in operator_id)
        ):
            raise ValueError("metadata operator ID must be bounded trimmed text")
        if type(configured_secret) is not str:
            raise ValueError("metadata session secret must be text")
        try:
            operator_id.encode("utf-8")
            secret = configured_secret.encode("utf-8")
        except UnicodeError:
            raise ValueError("metadata authentication configuration is not valid UTF-8") from None
        # Keep both the key domain and token purpose distinct from mutation auth,
        # including when configuration is shared. A nonce expires sessions on restart.
        self._key = hashlib.sha256(
            METADATA_SESSION_PURPOSE.encode("ascii")
            + b"\0"
            + secret
            + b"\0"
            + secrets.token_bytes(32)
        ).digest()
        self._enabled = enabled
        self._operator_id = operator_id

    def bootstrap_capability(
        self,
        response: Response,
        *,
        issued_at: datetime,
        session_cookie: str | None,
    ) -> MetadataReadCapability:
        response.headers.update(_CACHE_HEADERS)
        if not self._enabled:
            response.delete_cookie(METADATA_SESSION_COOKIE, path="/api/v1")
            return MetadataReadCapability(
                False,
                None,
                None,
                METADATA_CSRF_HEADER,
                None,
                "metadata read authentication is disabled",
            )
        issued_epoch = _utc_epoch(issued_at)
        try:
            expires_at = _EPOCH + timedelta(seconds=issued_epoch + _SESSION_SECONDS)
        except OverflowError:
            raise HTTPException(
                503, "metadata authentication UTC is unavailable", headers=dict(_CACHE_HEADERS)
            ) from None
        try:
            current = self._decode(session_cookie, now_epoch=issued_epoch)
        except HTTPException:
            current = None
        if current is not None:
            return MetadataReadCapability(
                True,
                current.operator_id,
                current.csrf_token,
                METADATA_CSRF_HEADER,
                current.expires_at,
                None,
            )
        cookie, csrf = self._issue(issued_epoch)
        response.set_cookie(
            key=METADATA_SESSION_COOKIE,
            value=cookie,
            max_age=_SESSION_SECONDS,
            httponly=True,
            secure=False,
            samesite="strict",
            path="/api/v1",
        )
        return MetadataReadCapability(
            True, self._operator_id, csrf, METADATA_CSRF_HEADER, expires_at, None
        )

    def authenticate(
        self,
        session_cookie: str | None,
        csrf_token: str,
        *,
        now: datetime,
    ) -> str:
        if not self._enabled:
            raise HTTPException(
                403, "metadata read authentication is disabled", headers=dict(_CACHE_HEADERS)
            )
        session = self._decode(session_cookie, now_epoch=_utc_epoch(now))
        if (
            type(csrf_token) is not str
            or not 32 <= len(csrf_token) <= 128
            or any(character not in _SAFE_TOKEN_CHARACTERS for character in csrf_token)
            or not hmac.compare_digest(session.csrf_token, csrf_token)
        ):
            raise HTTPException(
                403, "metadata read CSRF validation failed", headers=dict(_CACHE_HEADERS)
            )
        return session.operator_id

    def _issue(self, issued_epoch: int) -> tuple[str, str]:
        csrf = secrets.token_urlsafe(32)
        payload = {
            "csrf": csrf,
            "exp": issued_epoch + _SESSION_SECONDS,
            "iat": issued_epoch,
            "purpose": METADATA_SESSION_PURPOSE,
            "sub": self._operator_id,
            "v": _SESSION_VERSION,
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
    ) -> _AuthenticatedMetadataReader:
        unauthorized = HTTPException(
            401,
            "a current metadata read session is required",
            headers={**_CACHE_HEADERS, "WWW-Authenticate": "MetadataReadSession"},
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
                raise ValueError("invalid metadata session encoding")
            encoded = encoded_text.encode("ascii")
            expected = hmac.new(self._key, encoded, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, signature):
                raise ValueError("invalid metadata signature")
            raw = base64.b64decode(
                encoded + b"=" * (-len(encoded) % 4), altchars=b"-_", validate=True
            )
            if base64.urlsafe_b64encode(raw).rstrip(b"=") != encoded:
                raise ValueError("noncanonical metadata token encoding")
            payload = json.loads(raw)
            if type(payload) is not dict or set(payload) != {
                "csrf",
                "exp",
                "iat",
                "purpose",
                "sub",
                "v",
            }:
                raise ValueError("invalid metadata session fields")
            if (
                json.dumps(
                    payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False
                ).encode("utf-8")
                != raw
            ):
                raise ValueError("noncanonical metadata session payload")
            csrf, expires, issued = payload["csrf"], payload["exp"], payload["iat"]
            if (
                type(csrf) is not str
                or not 32 <= len(csrf) <= 128
                or any(character not in _SAFE_TOKEN_CHARACTERS for character in csrf)
                or type(expires) is not int
                or type(issued) is not int
                or type(payload["v"]) is not int
                or payload["v"] != _SESSION_VERSION
                or type(payload["purpose"]) is not str
                or payload["purpose"] != METADATA_SESSION_PURPOSE
                or type(payload["sub"]) is not str
                or payload["sub"] != self._operator_id
                or issued > now_epoch
                or expires <= now_epoch
                or expires - issued != _SESSION_SECONDS
            ):
                raise ValueError("invalid metadata session claims")
            return _AuthenticatedMetadataReader(
                self._operator_id, csrf, _EPOCH + timedelta(seconds=expires)
            )
        except (UnicodeError, ValueError, TypeError, KeyError, OverflowError, binascii.Error):
            raise unauthorized from None
