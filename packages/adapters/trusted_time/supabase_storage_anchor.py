"""Bounded Supabase Auth and Storage adapter for signed trusted-head objects."""

from __future__ import annotations

import asyncio
import json
import math
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlsplit
from uuid import UUID

import httpx

from packages.application.trusted_time_head_anchor import (
    MAX_TRUSTED_TIME_HEAD_ANCHOR_BYTES,
    MAX_TRUSTED_TIME_HEAD_ANCHOR_SEQUENCE,
    TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
    TRUSTED_TIME_HEAD_ANCHOR_CONTENT_TYPE,
    TrustedTimeHeadAnchorProviderIdentity,
    TrustedTimeHeadAnchorProviderUnavailable,
)

SUPABASE_STORAGE_ANCHOR_ADAPTER_CONTRACT_VERSION = (
    "phase6d-separate-supabase-storage-anchor-adapter-v1"
)
SUPABASE_STORAGE_ANCHOR_LIST_PAGE_SIZE = 1_000
SUPABASE_STORAGE_ANCHOR_MAX_OBJECTS = 250_000
SUPABASE_STORAGE_ANCHOR_MAX_RESPONSE_BYTES = 2_097_152
SUPABASE_STORAGE_ANCHOR_MAX_AUTH_RESPONSE_BYTES = 32_768
SUPABASE_STORAGE_ANCHOR_TIMEOUT_SECONDS = 5.0

_PROJECT_HOST = re.compile(r"([a-z0-9]{20})[.]supabase[.]co\Z")
_PUBLISHABLE_KEY = re.compile(r"sb_publishable_[A-Za-z0-9_-]{20,128}\Z")
_EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]{1,190}\Z")
_OBJECT_PREFIX = re.compile(r"v1/[0-9a-f]{64}/[0-9a-f]{64}/\Z")
_OBJECT_BASENAME = re.compile(r"[0-9]{20}-[0-9a-f]{64}[.]json\Z")
_OBJECT_NAME = re.compile(r"v1/[0-9a-f]{64}/[0-9a-f]{64}/[0-9]{20}-[0-9a-f]{64}[.]json\Z")


class SupabaseStorageAnchorError(RuntimeError):
    """A sanitized anchor-provider configuration or operation failure."""


class SupabaseStorageAnchorConflict(SupabaseStorageAnchorError):
    """A no-overwrite upload collided with an existing object."""


class SupabaseStorageAnchorUnavailable(
    SupabaseStorageAnchorError,
    TrustedTimeHeadAnchorProviderUnavailable,
):
    """A positively classified bounded provider outage may be retried."""


class _DuplicateJsonKey(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SupabaseStorageAnchorCredentials:
    """Least-privilege Auth-user credentials; secret fields never render."""

    project_url: str
    publishable_key: str = field(repr=False)
    principal_id: str
    anchor_project_identity_sha256: str
    email: str = field(repr=False)
    password: str = field(repr=False)

    def __post_init__(self) -> None:
        _validate_project_url(self.project_url)
        if (
            type(self.publishable_key) is not str
            or _PUBLISHABLE_KEY.fullmatch(self.publishable_key) is None
        ):
            raise SupabaseStorageAnchorError(
                "trusted-time anchor requires an exact Supabase publishable key"
            )
        _validate_uuid(self.principal_id)
        if (
            type(self.anchor_project_identity_sha256) is not str
            or len(self.anchor_project_identity_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.anchor_project_identity_sha256
            )
        ):
            raise SupabaseStorageAnchorError("trusted-time anchor project identity is invalid")
        if (
            type(self.email) is not str
            or not 3 <= len(self.email) <= 254
            or _EMAIL.fullmatch(self.email) is None
        ):
            raise SupabaseStorageAnchorError("trusted-time anchor Auth identity is invalid")
        if (
            type(self.password) is not str
            or not 32 <= len(self.password) <= 256
            or self.password != self.password.strip()
            or any(not 33 <= ord(character) <= 126 for character in self.password)
        ):
            raise SupabaseStorageAnchorError("trusted-time anchor Auth credential is invalid")

    @property
    def project_ref(self) -> str:
        host = urlsplit(self.project_url).hostname
        assert host is not None
        matched = _PROJECT_HOST.fullmatch(host)
        assert matched is not None
        return matched.group(1)

    def __repr__(self) -> str:
        return (
            "SupabaseStorageAnchorCredentials("
            f"project_url={self.project_url!r}, publishable_key=<redacted>, "
            f"principal_id={self.principal_id!r}, "
            f"anchor_project_identity_sha256={self.anchor_project_identity_sha256!r}, "
            "email=<redacted>, password=<redacted>)"
        )


@dataclass(frozen=True, slots=True)
class _Session:
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    refresh_at_monotonic: float


@dataclass(frozen=True, slots=True)
class _Response:
    status_code: int
    media_type: str | None
    body: bytes = field(repr=False)


def _validate_project_url(value: object) -> str:
    if type(value) is not str:
        raise SupabaseStorageAnchorError("trusted-time anchor project URL is invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.hostname is None
        or _PROJECT_HOST.fullmatch(parsed.hostname) is None
        or value != f"https://{parsed.hostname}"
    ):
        raise SupabaseStorageAnchorError("trusted-time anchor project URL is invalid")
    return value


def _validate_uuid(value: object) -> str:
    if type(value) is not str:
        raise SupabaseStorageAnchorError("trusted-time anchor principal identity is invalid")
    try:
        parsed = UUID(value)
    except (AttributeError, ValueError):
        raise SupabaseStorageAnchorError(
            "trusted-time anchor principal identity is invalid"
        ) from None
    if parsed.int == 0 or str(parsed) != value:
        raise SupabaseStorageAnchorError("trusted-time anchor principal identity is invalid")
    return value


def _json_object(payload: bytes) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise _DuplicateJsonKey
            value[key] = item
        return value

    try:
        decoded = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        RecursionError,
        TypeError,
        ValueError,
    ):
        raise SupabaseStorageAnchorError(
            "trusted-time anchor provider returned invalid JSON"
        ) from None
    if type(decoded) is not dict:
        raise SupabaseStorageAnchorError("trusted-time anchor provider returned invalid JSON")
    return decoded


def _json_bytes(value: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError):
        raise SupabaseStorageAnchorError(
            "trusted-time anchor provider request serialization failed"
        ) from None


class SupabaseStorageTrustedTimeAnchorProvider:
    """One authenticated, RLS-constrained Supabase Storage session."""

    __slots__ = (
        "_closed",
        "_credentials",
        "_monotonic",
        "_session",
        "_timeout_seconds",
        "_transport",
    )

    def __init__(
        self,
        *,
        credentials: SupabaseStorageAnchorCredentials,
        monotonic_clock: Callable[[], float] = time.monotonic,
        timeout_seconds: float = SUPABASE_STORAGE_ANCHOR_TIMEOUT_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if type(credentials) is not SupabaseStorageAnchorCredentials:
            raise SupabaseStorageAnchorError("trusted-time anchor credentials are invalid")
        credentials.__post_init__()
        if (
            type(timeout_seconds) not in {int, float}
            or isinstance(timeout_seconds, bool)
            or not math.isfinite(float(timeout_seconds))
            or not 0 < float(timeout_seconds) <= SUPABASE_STORAGE_ANCHOR_TIMEOUT_SECONDS
            or not callable(monotonic_clock)
        ):
            raise SupabaseStorageAnchorError("trusted-time anchor HTTP bounds are invalid")
        timeout = float(timeout_seconds)
        self._credentials = credentials
        self._monotonic = monotonic_clock
        self._session: _Session | None = None
        self._closed = False
        self._timeout_seconds = timeout
        self._transport = transport

    def __enter__(self) -> SupabaseStorageTrustedTimeAnchorProvider:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            "SupabaseStorageTrustedTimeAnchorProvider("
            f"project_url={self._credentials.project_url!r}, "
            f"principal_id={self._credentials.principal_id!r}, credentials=<redacted>)"
        )

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._session = None

    def attest_identity(self) -> TrustedTimeHeadAnchorProviderIdentity:
        """Return the exact physical project, principal, and bucket binding."""

        if self._closed:
            raise SupabaseStorageAnchorError("trusted-time anchor provider is closed")
        return TrustedTimeHeadAnchorProviderIdentity(
            anchor_project_identity_sha256=(self._credentials.anchor_project_identity_sha256),
            anchor_project_ref=self._credentials.project_ref,
            principal_id=self._credentials.principal_id,
            bucket_name=TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
        )

    def _now(self) -> float:
        try:
            value = self._monotonic()
        except Exception:
            raise SupabaseStorageAnchorError("trusted-time anchor monotonic clock failed") from None
        if type(value) not in {int, float} or isinstance(value, bool) or not math.isfinite(value):
            raise SupabaseStorageAnchorError("trusted-time anchor monotonic clock is invalid")
        return float(value)

    async def _request_async(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        maximum_response_bytes: int,
    ) -> _Response:
        url = f"{self._credentials.project_url}{path}"
        timeout = httpx.Timeout(
            connect=self._timeout_seconds,
            read=self._timeout_seconds,
            write=self._timeout_seconds,
            pool=self._timeout_seconds,
        )
        async with asyncio.timeout(self._timeout_seconds):
            async with httpx.AsyncClient(
                verify=True,
                trust_env=False,
                follow_redirects=False,
                timeout=timeout,
                transport=self._transport,
            ) as client:
                async with client.stream(
                    method,
                    url,
                    headers=dict(headers),
                    content=body,
                ) as response:
                    if response.request.method != method or str(response.request.url) != url:
                        raise SupabaseStorageAnchorError(
                            "trusted-time anchor provider changed the fixed request target"
                        )
                    if response.is_redirect:
                        raise SupabaseStorageAnchorError(
                            "trusted-time anchor provider returned a redirect"
                        )
                    encoding = response.headers.get("content-encoding")
                    if encoding is not None and encoding.strip().lower() != "identity":
                        raise SupabaseStorageAnchorError(
                            "trusted-time anchor provider response encoding is unsupported"
                        )
                    payload = bytearray()
                    if response.is_stream_consumed:
                        chunks = (response.content,)
                        for chunk in chunks:
                            if len(payload) + len(chunk) > maximum_response_bytes:
                                raise SupabaseStorageAnchorError(
                                    "trusted-time anchor provider response exceeded its bound"
                                )
                            payload.extend(chunk)
                    else:
                        async for chunk in response.aiter_raw():
                            if len(payload) + len(chunk) > maximum_response_bytes:
                                raise SupabaseStorageAnchorError(
                                    "trusted-time anchor provider response exceeded its bound"
                                )
                            payload.extend(chunk)
                    content_type = response.headers.get("content-type")
                    media_type = None
                    if content_type is not None and len(content_type) <= 128:
                        media_type = content_type.partition(";")[0].strip().lower()
                    return _Response(response.status_code, media_type, bytes(payload))

    def _request(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        maximum_response_bytes: int,
    ) -> _Response:
        if self._closed:
            raise SupabaseStorageAnchorError("trusted-time anchor provider is closed")
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise SupabaseStorageAnchorError(
                "trusted-time anchor synchronous provider cannot run on an event loop"
            )
        try:
            response = asyncio.run(
                self._request_async(
                    method,
                    path,
                    headers=headers,
                    body=body,
                    maximum_response_bytes=maximum_response_bytes,
                )
            )
        except SupabaseStorageAnchorError:
            raise
        except (TimeoutError, httpx.TimeoutException):
            raise SupabaseStorageAnchorUnavailable(
                "trusted-time anchor provider request timed out"
            ) from None
        except httpx.TransportError:
            raise SupabaseStorageAnchorUnavailable(
                "trusted-time anchor provider transport is unavailable"
            ) from None
        except Exception:
            raise SupabaseStorageAnchorError(
                "trusted-time anchor provider request failed"
            ) from None
        if response.status_code in {408, 425, 429} or 500 <= response.status_code <= 599:
            raise SupabaseStorageAnchorUnavailable(
                "trusted-time anchor provider service is unavailable"
            )
        return response

    def _auth_headers(self, access_token: str | None = None) -> dict[str, str]:
        headers = {
            "accept": "application/json",
            "accept-encoding": "identity",
            "apikey": self._credentials.publishable_key,
            "user-agent": "AutoQuantTrader-trusted-time-anchor/1",
        }
        if access_token is not None:
            headers["authorization"] = f"Bearer {access_token}"
        return headers

    def _decode_session(self, response: _Response, *, observed_monotonic: float) -> _Session:
        if response.status_code != 200 or response.media_type != "application/json":
            raise SupabaseStorageAnchorError("trusted-time anchor authentication failed")
        payload = _json_object(response.body)
        access_token = payload.get("access_token")
        refresh_token = payload.get("refresh_token")
        expires_in = payload.get("expires_in")
        token_type = payload.get("token_type")
        user = payload.get("user")
        if (
            type(access_token) is not str
            or not 64 <= len(access_token) <= 8_192
            or type(refresh_token) is not str
            or not 16 <= len(refresh_token) <= 2_048
            or type(expires_in) is not int
            or not 60 <= expires_in <= 86_400
            or token_type != "bearer"
            or type(user) is not dict
            or user.get("id") != self._credentials.principal_id
        ):
            raise SupabaseStorageAnchorError(
                "trusted-time anchor authentication response is invalid"
            )
        refresh_margin = min(60, max(1, expires_in // 10))
        return _Session(
            access_token=access_token,
            refresh_token=refresh_token,
            refresh_at_monotonic=observed_monotonic + expires_in - refresh_margin,
        )

    def _verify_user(self, session: _Session) -> None:
        response = self._request(
            "GET",
            "/auth/v1/user",
            headers=self._auth_headers(session.access_token),
            body=None,
            maximum_response_bytes=SUPABASE_STORAGE_ANCHOR_MAX_AUTH_RESPONSE_BYTES,
        )
        if response.status_code != 200 or response.media_type != "application/json":
            raise SupabaseStorageAnchorError("trusted-time anchor Auth user verification failed")
        if _json_object(response.body).get("id") != self._credentials.principal_id:
            raise SupabaseStorageAnchorError("trusted-time anchor Auth user identity conflicts")

    def _sign_in(self) -> _Session:
        observed = self._now()
        response = self._request(
            "POST",
            "/auth/v1/token?grant_type=password",
            headers={**self._auth_headers(), "content-type": "application/json"},
            body=_json_bytes(
                {"email": self._credentials.email, "password": self._credentials.password}
            ),
            maximum_response_bytes=SUPABASE_STORAGE_ANCHOR_MAX_AUTH_RESPONSE_BYTES,
        )
        session = self._decode_session(response, observed_monotonic=observed)
        self._verify_user(session)
        self._session = session
        return session

    def _refresh(self, previous: _Session) -> _Session:
        observed = self._now()
        response = self._request(
            "POST",
            "/auth/v1/token?grant_type=refresh_token",
            headers={**self._auth_headers(), "content-type": "application/json"},
            body=_json_bytes({"refresh_token": previous.refresh_token}),
            maximum_response_bytes=SUPABASE_STORAGE_ANCHOR_MAX_AUTH_RESPONSE_BYTES,
        )
        try:
            session = self._decode_session(response, observed_monotonic=observed)
            self._verify_user(session)
        except Exception:
            self._session = None
            raise
        self._session = session
        return session

    def _access_token(self) -> str:
        session = self._session
        if session is None:
            session = self._sign_in()
        elif self._now() >= session.refresh_at_monotonic:
            session = self._refresh(session)
        return session.access_token

    def _storage_headers(self) -> dict[str, str]:
        return self._auth_headers(self._access_token())

    def _list_object_names(
        self,
        *,
        bucket_name: str,
        prefix: str,
        sequence: int | None,
    ) -> tuple[str, ...]:
        if bucket_name != TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME:
            raise SupabaseStorageAnchorError("trusted-time anchor bucket identity changed")
        if type(prefix) is not str or _OBJECT_PREFIX.fullmatch(prefix) is None:
            raise SupabaseStorageAnchorError("trusted-time anchor object prefix is invalid")
        if sequence is not None and (
            type(sequence) is not int
            or isinstance(sequence, bool)
            or not 1 <= sequence <= MAX_TRUSTED_TIME_HEAD_ANCHOR_SEQUENCE
        ):
            raise SupabaseStorageAnchorError("trusted-time anchor sequence search is invalid")
        basename_prefix = None if sequence is None else f"{sequence:020d}-"
        page_limit = 2 if sequence is not None else SUPABASE_STORAGE_ANCHOR_LIST_PAGE_SIZE
        names: list[str] = []
        seen: set[str] = set()
        offset = 0
        while True:
            request_value: dict[str, object] = {
                "limit": page_limit,
                "offset": offset,
                "prefix": prefix,
                "sortBy": {"column": "name", "order": "asc"},
            }
            if basename_prefix is not None:
                request_value["search"] = basename_prefix
            request = _json_bytes(request_value)
            response = self._request(
                "POST",
                f"/storage/v1/object/list/{quote(bucket_name, safe='')}",
                headers={**self._storage_headers(), "content-type": "application/json"},
                body=request,
                maximum_response_bytes=SUPABASE_STORAGE_ANCHOR_MAX_RESPONSE_BYTES,
            )
            if response.status_code != 200 or response.media_type != "application/json":
                raise SupabaseStorageAnchorError("trusted-time anchor object listing failed")
            try:
                page = json.loads(
                    response.body.decode("utf-8", errors="strict"),
                    object_pairs_hook=lambda pairs: _unique_mapping(pairs),
                    parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
                )
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
                _DuplicateJsonKey,
                RecursionError,
                ValueError,
            ):
                raise SupabaseStorageAnchorError(
                    "trusted-time anchor object listing is invalid"
                ) from None
            if type(page) is not list or len(page) > page_limit:
                raise SupabaseStorageAnchorError("trusted-time anchor object listing is invalid")
            for item in page:
                basename = item.get("name") if type(item) is dict else None
                if type(basename) is not str or _OBJECT_BASENAME.fullmatch(basename) is None:
                    raise SupabaseStorageAnchorError(
                        "trusted-time anchor object listing contains contamination"
                    )
                if basename_prefix is not None and not basename.startswith(basename_prefix):
                    raise SupabaseStorageAnchorError(
                        "trusted-time anchor sequence listing contains contamination"
                    )
                object_name = f"{prefix}{basename}"
                if object_name in seen:
                    raise SupabaseStorageAnchorError(
                        "trusted-time anchor object listing contains duplicates"
                    )
                seen.add(object_name)
                names.append(object_name)
            if len(names) > SUPABASE_STORAGE_ANCHOR_MAX_OBJECTS:
                raise SupabaseStorageAnchorError(
                    "trusted-time anchor object listing exceeded its bound"
                )
            # Two objects for one sequence already prove a fork. Returning the
            # bounded pair lets the application classify it without traversing
            # an attacker-inflated namespace.
            if sequence is not None:
                break
            if len(page) < page_limit:
                break
            offset += len(page)
        return tuple(names)

    def list_object_names(self, *, bucket_name: str, prefix: str) -> tuple[str, ...]:
        """List the complete exact namespace for an explicit full audit."""

        return self._list_object_names(
            bucket_name=bucket_name,
            prefix=prefix,
            sequence=None,
        )

    def list_object_names_page(
        self,
        *,
        bucket_name: str,
        prefix: str,
        offset: int,
        limit: int,
    ) -> tuple[str, ...]:
        """Return one exact bounded, name-sorted namespace page."""

        if bucket_name != TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME:
            raise SupabaseStorageAnchorError("trusted-time anchor bucket identity changed")
        if type(prefix) is not str or _OBJECT_PREFIX.fullmatch(prefix) is None:
            raise SupabaseStorageAnchorError("trusted-time anchor object prefix is invalid")
        if (
            type(offset) is not int
            or isinstance(offset, bool)
            or not 0 <= offset <= SUPABASE_STORAGE_ANCHOR_MAX_OBJECTS
            or type(limit) is not int
            or isinstance(limit, bool)
            or not 1 <= limit <= SUPABASE_STORAGE_ANCHOR_LIST_PAGE_SIZE
        ):
            raise SupabaseStorageAnchorError(
                "trusted-time anchor bounded listing cursor is invalid"
            )
        response = self._request(
            "POST",
            f"/storage/v1/object/list/{quote(bucket_name, safe='')}",
            headers={**self._storage_headers(), "content-type": "application/json"},
            body=_json_bytes(
                {
                    "limit": limit,
                    "offset": offset,
                    "prefix": prefix,
                    "sortBy": {"column": "name", "order": "asc"},
                }
            ),
            maximum_response_bytes=SUPABASE_STORAGE_ANCHOR_MAX_RESPONSE_BYTES,
        )
        if response.status_code != 200 or response.media_type != "application/json":
            raise SupabaseStorageAnchorError("trusted-time anchor bounded object listing failed")
        try:
            raw_page = json.loads(
                response.body.decode("utf-8", errors="strict"),
                object_pairs_hook=lambda pairs: _unique_mapping(pairs),
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            _DuplicateJsonKey,
            RecursionError,
            ValueError,
        ):
            raise SupabaseStorageAnchorError(
                "trusted-time anchor bounded object listing is invalid"
            ) from None
        if type(raw_page) is not list or len(raw_page) > limit:
            raise SupabaseStorageAnchorError(
                "trusted-time anchor bounded object listing is invalid"
            )
        names: list[str] = []
        for item in raw_page:
            basename = item.get("name") if type(item) is dict else None
            if type(basename) is not str or _OBJECT_BASENAME.fullmatch(basename) is None:
                raise SupabaseStorageAnchorError(
                    "trusted-time anchor bounded object listing contains contamination"
                )
            names.append(f"{prefix}{basename}")
        if len(set(names)) != len(names) or tuple(sorted(names)) != tuple(names):
            raise SupabaseStorageAnchorError(
                "trusted-time anchor bounded object listing is duplicated or unordered"
            )
        return tuple(names)

    def list_sequence_object_names(
        self,
        *,
        bucket_name: str,
        prefix: str,
        anchor_sequence: int,
    ) -> tuple[str, ...]:
        """Search one exact sequence without traversing historical objects."""

        return self._list_object_names(
            bucket_name=bucket_name,
            prefix=prefix,
            sequence=anchor_sequence,
        )

    def download_object(self, *, bucket_name: str, object_name: str) -> bytes:
        _validate_storage_target(bucket_name, object_name)
        response = self._request(
            "GET",
            (
                f"/storage/v1/object/authenticated/{quote(bucket_name, safe='')}/"
                f"{quote(object_name, safe='/')}"
            ),
            headers=self._storage_headers(),
            body=None,
            maximum_response_bytes=MAX_TRUSTED_TIME_HEAD_ANCHOR_BYTES,
        )
        if (
            response.status_code != 200
            or response.media_type != TRUSTED_TIME_HEAD_ANCHOR_CONTENT_TYPE
            or not response.body
        ):
            raise SupabaseStorageAnchorError("trusted-time anchor object download failed")
        return response.body

    def upload_object_no_overwrite(
        self,
        *,
        bucket_name: str,
        object_name: str,
        payload: bytes,
        content_type: str,
    ) -> None:
        _validate_storage_target(bucket_name, object_name)
        if (
            type(payload) is not bytes
            or not payload
            or len(payload) > MAX_TRUSTED_TIME_HEAD_ANCHOR_BYTES
            or content_type != TRUSTED_TIME_HEAD_ANCHOR_CONTENT_TYPE
        ):
            raise SupabaseStorageAnchorError("trusted-time anchor upload is invalid")
        response = self._request(
            "POST",
            (f"/storage/v1/object/{quote(bucket_name, safe='')}/{quote(object_name, safe='/')}"),
            headers={
                **self._storage_headers(),
                "cache-control": "no-store",
                "content-type": TRUSTED_TIME_HEAD_ANCHOR_CONTENT_TYPE,
                "x-upsert": "false",
            },
            body=payload,
            maximum_response_bytes=SUPABASE_STORAGE_ANCHOR_MAX_AUTH_RESPONSE_BYTES,
        )
        if response.status_code in {200, 201}:
            return None
        if response.status_code in {400, 409} and _is_exact_collision(response):
            raise SupabaseStorageAnchorConflict("trusted-time anchor object already exists")
        if response.status_code in {401, 403}:
            self._session = None
            raise SupabaseStorageAnchorError("trusted-time anchor Storage authorization failed")
        raise SupabaseStorageAnchorError("trusted-time anchor object upload failed")


def _unique_mapping(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _validate_storage_target(bucket_name: object, object_name: object) -> None:
    if bucket_name != TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME:
        raise SupabaseStorageAnchorError("trusted-time anchor bucket identity changed")
    if type(object_name) is not str or _OBJECT_NAME.fullmatch(object_name) is None:
        raise SupabaseStorageAnchorError("trusted-time anchor object name is invalid")


def _is_exact_collision(response: _Response) -> bool:
    if response.media_type != "application/json" or not response.body:
        return False
    try:
        payload = _json_object(response.body)
    except SupabaseStorageAnchorError:
        return False
    code = payload.get("error") or payload.get("code")
    message = payload.get("message")
    return code in {"KeyAlreadyExists", "ResourceAlreadyExists"} or (
        response.status_code == 400 and message == "The resource already exists"
    )


__all__ = [
    "SUPABASE_STORAGE_ANCHOR_ADAPTER_CONTRACT_VERSION",
    "SUPABASE_STORAGE_ANCHOR_LIST_PAGE_SIZE",
    "SUPABASE_STORAGE_ANCHOR_MAX_OBJECTS",
    "SUPABASE_STORAGE_ANCHOR_TIMEOUT_SECONDS",
    "SupabaseStorageAnchorConflict",
    "SupabaseStorageAnchorCredentials",
    "SupabaseStorageAnchorError",
    "SupabaseStorageAnchorUnavailable",
    "SupabaseStorageTrustedTimeAnchorProvider",
]
