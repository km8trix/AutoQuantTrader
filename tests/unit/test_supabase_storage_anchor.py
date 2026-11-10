from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Callable

import httpx
import pytest

import packages.adapters.trusted_time.supabase_storage_anchor as adapter
from packages.adapters.trusted_time.supabase_storage_anchor import (
    SUPABASE_STORAGE_ANCHOR_MAX_SESSION_EXPIRY_SECONDS,
    SupabaseStorageAnchorAuthenticationError,
    SupabaseStorageAnchorAuthenticationResponseError,
    SupabaseStorageAnchorAuthPasswordTokenRequestTargetError,
    SupabaseStorageAnchorAuthPasswordTokenResponseBoundError,
    SupabaseStorageAnchorAuthPasswordTokenResponseEncodingError,
    SupabaseStorageAnchorAuthPasswordTokenResponseEnvelopeError,
    SupabaseStorageAnchorAuthPasswordTokenResponseError,
    SupabaseStorageAnchorAuthPasswordTokenSessionSchemaError,
    SupabaseStorageAnchorAuthUserVerificationResponseError,
    SupabaseStorageAnchorBoundedListResponseError,
    SupabaseStorageAnchorConflict,
    SupabaseStorageAnchorCredentials,
    SupabaseStorageAnchorError,
    SupabaseStorageAnchorResponseError,
    SupabaseStorageAnchorStorageAccessError,
    SupabaseStorageAnchorUnavailable,
    SupabaseStorageTrustedTimeAnchorProvider,
)

PROJECT_URL = "https://abcdefghijklmnopqrst.supabase.co"
PUBLISHABLE_KEY = "sb_publishable_abcdefghijklmnopqrstuvwxyz12345"
PRINCIPAL_ID = "12345678-1234-4234-9234-123456789abc"
ANCHOR_PROJECT_IDENTITY_SHA256 = "6" * 64
EMAIL = "aqt-trusted-time-anchor-v1@example.invalid"
PASSWORD = "correct-horse-battery-staple-anchor-1!"
ACCESS_TOKEN = "a" * 128
REFRESH_TOKEN = "r" * 64
PREFIX = f"v1/{'1' * 64}/{'2' * 64}/"
FIRST_NAME = f"{PREFIX}{1:020d}-{'3' * 64}.json"
SECOND_NAME = f"{PREFIX}{2:020d}-{'4' * 64}.json"
THIRD_NAME = f"{PREFIX}{3:020d}-{'5' * 64}.json"
PAYLOAD = b'{"signed":"anchor"}'
SECRET_PROVIDER_RESPONSE = "secret-provider-response-sentinel"


class _SlowTrickleStream(httpx.AsyncByteStream):
    async def __aiter__(self):  # type: ignore[no-untyped-def]
        yield b"{"
        await asyncio.sleep(0.05)
        yield b"}"


class _SingleChunkStream(httpx.AsyncByteStream):
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    async def __aiter__(self):  # type: ignore[no-untyped-def]
        yield self._payload


class _NeverReadStream(httpx.AsyncByteStream):
    def __aiter__(self) -> AsyncIterator[bytes]:
        return self

    async def __anext__(self) -> bytes:
        raise AssertionError("non-collision error body must not be read")


def _credentials(**changes: str) -> SupabaseStorageAnchorCredentials:
    values = {
        "project_url": PROJECT_URL,
        "publishable_key": PUBLISHABLE_KEY,
        "principal_id": PRINCIPAL_ID,
        "anchor_project_identity_sha256": ANCHOR_PROJECT_IDENTITY_SHA256,
        "email": EMAIL,
        "password": PASSWORD,
        **changes,
    }
    return SupabaseStorageAnchorCredentials(**values)


def _session_response(
    *,
    access_token: object = ACCESS_TOKEN,
    expires_in: int = 3_600,
    include_user_id: bool = True,
    refresh_token: object = REFRESH_TOKEN,
    user_id: object = PRINCIPAL_ID,
) -> httpx.Response:
    user = {"id": user_id} if include_user_id else {}
    return httpx.Response(
        200,
        headers={"content-type": "application/json"},
        json={
            "access_token": access_token,
            "expires_in": expires_in,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "user": user,
        },
    )


def _auth_or(
    operation: Callable[[httpx.Request], httpx.Response],
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/v1/token":
            assert request.method == "POST"
            assert request.headers["apikey"] == PUBLISHABLE_KEY
            return _session_response()
        if request.url.path == "/auth/v1/user":
            assert request.headers["authorization"] == f"Bearer {ACCESS_TOKEN}"
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json={"id": PRINCIPAL_ID},
            )
        return operation(request)

    return httpx.MockTransport(handler)


def test_credentials_reject_elevated_keys_and_unsafe_project_targets() -> None:
    assert _credentials().project_ref == "abcdefghijklmnopqrst"

    for key in ("sb_secret_abcdefghijklmnopqrstuvwxyz12345", "eyJ" + "x" * 100):
        with pytest.raises(SupabaseStorageAnchorError, match="publishable"):
            _credentials(publishable_key=key)
    for url in (
        "http://abcdefghijklmnopqrst.supabase.co",
        "https://abcdefghijklmnopqrst.supabase.co/path",
        "https://abcdefghijklmnopqrst.supabase.co.evil.invalid",
    ):
        with pytest.raises(SupabaseStorageAnchorError, match="project URL"):
            _credentials(project_url=url)
    with pytest.raises(SupabaseStorageAnchorError, match="project identity"):
        _credentials(anchor_project_identity_sha256="not-a-digest")


@pytest.mark.parametrize(
    "leaf_type",
    [
        SupabaseStorageAnchorAuthPasswordTokenRequestTargetError,
        SupabaseStorageAnchorAuthPasswordTokenResponseEncodingError,
        SupabaseStorageAnchorAuthPasswordTokenResponseBoundError,
        SupabaseStorageAnchorAuthPasswordTokenResponseEnvelopeError,
        SupabaseStorageAnchorAuthPasswordTokenSessionSchemaError,
    ],
)
def test_password_token_response_taxonomy_uses_direct_backward_compatible_leaves(
    leaf_type: type[SupabaseStorageAnchorAuthPasswordTokenResponseError],
) -> None:
    assert leaf_type.__bases__ == (SupabaseStorageAnchorAuthPasswordTokenResponseError,)


def test_provider_attests_exact_physical_project_principal_and_bucket() -> None:
    with SupabaseStorageTrustedTimeAnchorProvider(
        credentials=_credentials(),
        transport=httpx.MockTransport(lambda _: httpx.Response(500)),
    ) as provider:
        identity = provider.attest_identity()

    assert identity.anchor_project_identity_sha256 == ANCHOR_PROJECT_IDENTITY_SHA256
    assert identity.anchor_project_ref == "abcdefghijklmnopqrst"
    assert identity.principal_id == PRINCIPAL_ID
    assert identity.bucket_name == "aqt-trusted-time-anchors-v1"


def test_credentials_and_provider_reprs_redact_every_runtime_secret() -> None:
    credentials = _credentials()
    provider = SupabaseStorageTrustedTimeAnchorProvider(
        credentials=credentials,
        transport=httpx.MockTransport(lambda _: httpx.Response(500)),
    )
    try:
        rendered = f"{credentials!r} {provider!r}"
    finally:
        provider.close()

    assert PUBLISHABLE_KEY not in rendered
    assert EMAIL not in rendered
    assert PASSWORD not in rendered
    assert "<redacted>" in rendered


def test_list_authenticates_and_consumes_every_exact_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(adapter, "SUPABASE_STORAGE_ANCHOR_LIST_PAGE_SIZE", 2)
    offsets: list[int] = []

    def operation(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/storage/v1/object/list/aqt-trusted-time-anchors-v1"
        assert request.headers["authorization"] == f"Bearer {ACCESS_TOKEN}"
        body = json.loads(request.content)
        assert body["prefix"] == PREFIX
        offsets.append(body["offset"])
        names = (
            [FIRST_NAME.removeprefix(PREFIX), SECOND_NAME.removeprefix(PREFIX)]
            if body["offset"] == 0
            else [THIRD_NAME.removeprefix(PREFIX)]
        )
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[{"name": name} for name in names],
        )

    with SupabaseStorageTrustedTimeAnchorProvider(
        credentials=_credentials(),
        monotonic_clock=lambda: 10.0,
        transport=_auth_or(operation),
    ) as provider:
        assert provider.list_object_names(
            bucket_name="aqt-trusted-time-anchors-v1",
            prefix=PREFIX,
        ) == (FIRST_NAME, SECOND_NAME, THIRD_NAME)

    assert offsets == [0, 2]


def test_bounded_list_returns_exactly_one_sorted_page() -> None:
    calls = 0

    def operation(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        body = json.loads(request.content)
        assert body == {
            "limit": 2,
            "offset": 7,
            "prefix": PREFIX,
            "sortBy": {"column": "name", "order": "asc"},
        }
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[
                {"name": SECOND_NAME.removeprefix(PREFIX)},
                {"name": THIRD_NAME.removeprefix(PREFIX)},
            ],
        )

    with SupabaseStorageTrustedTimeAnchorProvider(
        credentials=_credentials(),
        transport=_auth_or(operation),
    ) as provider:
        assert provider.list_object_names_page(
            bucket_name="aqt-trusted-time-anchors-v1",
            prefix=PREFIX,
            offset=7,
            limit=2,
        ) == (SECOND_NAME, THIRD_NAME)

    assert calls == 1


def test_bounded_list_retypes_auth_denial_without_disclosing_response() -> None:
    def denied(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            headers={
                "content-encoding": "gzip",
                "content-type": "application/json",
            },
            stream=_SingleChunkStream(SECRET_PROVIDER_RESPONSE.encode("ascii")),
        )

    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=httpx.MockTransport(denied),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorAuthenticationError) as raised,
    ):
        provider.list_object_names_page(
            bucket_name="aqt-trusted-time-anchors-v1",
            prefix=PREFIX,
            offset=0,
            limit=1,
        )

    assert type(raised.value) is SupabaseStorageAnchorAuthenticationError
    assert isinstance(raised.value, SupabaseStorageAnchorError)
    assert SECRET_PROVIDER_RESPONSE not in str(raised.value)
    assert SECRET_PROVIDER_RESPONSE not in repr(raised.value)


@pytest.mark.parametrize("status_code", [200, 204])
def test_bounded_list_retypes_malformed_auth_success_as_response_error(
    status_code: int,
) -> None:
    def malformed_auth(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code,
            headers={"content-type": "text/plain"},
            content=SECRET_PROVIDER_RESPONSE.encode("ascii"),
        )

    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=httpx.MockTransport(malformed_auth),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorAuthPasswordTokenResponseEnvelopeError) as raised,
    ):
        provider.list_object_names_page(
            bucket_name="aqt-trusted-time-anchors-v1",
            prefix=PREFIX,
            offset=0,
            limit=1,
        )

    assert isinstance(raised.value, SupabaseStorageAnchorError)
    assert SECRET_PROVIDER_RESPONSE not in str(raised.value)
    assert SECRET_PROVIDER_RESPONSE not in repr(raised.value)


@pytest.mark.parametrize(
    "body",
    [
        SECRET_PROVIDER_RESPONSE.encode("ascii"),
        json.dumps([SECRET_PROVIDER_RESPONSE]).encode("ascii"),
    ],
)
def test_password_token_invalid_json_or_root_is_envelope_typed(body: bytes) -> None:
    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=httpx.MockTransport(
                lambda _: httpx.Response(
                    200,
                    headers={"content-type": "application/json"},
                    content=body,
                )
            ),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorAuthPasswordTokenResponseEnvelopeError) as raised,
    ):
        provider.list_object_names_page(
            bucket_name="aqt-trusted-time-anchors-v1",
            prefix=PREFIX,
            offset=0,
            limit=1,
        )

    assert SECRET_PROVIDER_RESPONSE not in str(raised.value)
    assert SECRET_PROVIDER_RESPONSE not in repr(raised.value)


@pytest.mark.parametrize(
    ("protocol_error", "expected_type"),
    [
        ("redirect", SupabaseStorageAnchorAuthPasswordTokenRequestTargetError),
        ("encoding", SupabaseStorageAnchorAuthPasswordTokenResponseEncodingError),
        ("oversize", SupabaseStorageAnchorAuthPasswordTokenResponseBoundError),
    ],
)
def test_auth_protocol_error_is_stage_typed_without_disclosing_response(
    monkeypatch: pytest.MonkeyPatch,
    protocol_error: str,
    expected_type: type[SupabaseStorageAnchorAuthPasswordTokenResponseError],
) -> None:
    monkeypatch.setattr(adapter, "SUPABASE_STORAGE_ANCHOR_MAX_AUTH_RESPONSE_BYTES", 8)

    def malformed(_: httpx.Request) -> httpx.Response:
        if protocol_error == "redirect":
            return httpx.Response(
                302,
                headers={"location": f"{PROJECT_URL}/redirected"},
                content=SECRET_PROVIDER_RESPONSE.encode("ascii"),
            )
        if protocol_error == "encoding":
            return httpx.Response(
                200,
                headers={
                    "content-encoding": "gzip",
                    "content-type": "application/json",
                },
                content=SECRET_PROVIDER_RESPONSE.encode("ascii"),
            )
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=SECRET_PROVIDER_RESPONSE.encode("ascii"),
        )

    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=httpx.MockTransport(malformed),
        ) as provider,
        pytest.raises(expected_type) as raised,
    ):
        provider.list_object_names_page(
            bucket_name="aqt-trusted-time-anchors-v1",
            prefix=PREFIX,
            offset=0,
            limit=1,
        )

    assert type(raised.value) is expected_type
    assert isinstance(raised.value, SupabaseStorageAnchorResponseError)
    assert SECRET_PROVIDER_RESPONSE not in str(raised.value)
    assert SECRET_PROVIDER_RESPONSE not in repr(raised.value)


@pytest.mark.parametrize(
    "expires_in",
    [1, SUPABASE_STORAGE_ANCHOR_MAX_SESSION_EXPIRY_SECONDS],
)
def test_auth_session_expiry_accepts_official_bounds(expires_in: int) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/v1/token":
            return _session_response(expires_in=expires_in)
        if request.url.path == "/auth/v1/user":
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json={"id": PRINCIPAL_ID},
            )
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[],
        )

    with SupabaseStorageTrustedTimeAnchorProvider(
        credentials=_credentials(),
        transport=httpx.MockTransport(handler),
    ) as provider:
        assert (
            provider.list_object_names_page(
                bucket_name="aqt-trusted-time-anchors-v1",
                prefix=PREFIX,
                offset=0,
                limit=1,
            )
            == ()
        )


@pytest.mark.parametrize(
    "expires_in",
    [0, SUPABASE_STORAGE_ANCHOR_MAX_SESSION_EXPIRY_SECONDS + 1],
)
def test_auth_session_expiry_rejects_outside_official_bounds(expires_in: int) -> None:
    def excessive(_: httpx.Request) -> httpx.Response:
        return _session_response(expires_in=expires_in)

    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=httpx.MockTransport(excessive),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorAuthPasswordTokenSessionSchemaError),
    ):
        provider.list_object_names_page(
            bucket_name="aqt-trusted-time-anchors-v1",
            prefix=PREFIX,
            offset=0,
            limit=1,
        )


def test_long_access_and_refresh_tokens_are_accepted_within_response_bound() -> None:
    access_token = "a" * 10_000
    refresh_token = "r" * 10_000

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/v1/token":
            return _session_response(
                access_token=access_token,
                refresh_token=refresh_token,
            )
        if request.url.path == "/auth/v1/user":
            assert request.headers["authorization"] == f"Bearer {access_token}"
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json={"id": PRINCIPAL_ID},
            )
        assert request.headers["authorization"] == f"Bearer {access_token}"
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[],
        )

    with SupabaseStorageTrustedTimeAnchorProvider(
        credentials=_credentials(),
        transport=httpx.MockTransport(handler),
    ) as provider:
        assert (
            provider.list_object_names_page(
                bucket_name="aqt-trusted-time-anchors-v1",
                prefix=PREFIX,
                offset=0,
                limit=1,
            )
            == ()
        )


@pytest.mark.parametrize(
    ("access_token", "refresh_token"),
    [
        ("", REFRESH_TOKEN),
        ("visible-prefix\ncontrol", REFRESH_TOKEN),
        (ACCESS_TOKEN, ""),
    ],
)
def test_empty_or_control_session_tokens_are_schema_failures(
    access_token: str,
    refresh_token: str,
) -> None:
    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=httpx.MockTransport(
                lambda _: _session_response(
                    access_token=access_token,
                    refresh_token=refresh_token,
                )
            ),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorAuthPasswordTokenSessionSchemaError),
    ):
        provider.list_object_names_page(
            bucket_name="aqt-trusted-time-anchors-v1",
            prefix=PREFIX,
            offset=0,
            limit=1,
        )


@pytest.mark.parametrize(
    ("include_user_id", "user_id"),
    [(False, None), (True, 7), (True, SECRET_PROVIDER_RESPONSE)],
)
def test_password_token_user_id_shape_failure_is_endpoint_typed(
    include_user_id: bool,
    user_id: object,
) -> None:
    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=httpx.MockTransport(
                lambda _: _session_response(
                    include_user_id=include_user_id,
                    user_id=user_id,
                )
            ),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorAuthPasswordTokenSessionSchemaError) as raised,
    ):
        provider.list_object_names_page(
            bucket_name="aqt-trusted-time-anchors-v1",
            prefix=PREFIX,
            offset=0,
            limit=1,
        )

    assert type(raised.value) is SupabaseStorageAnchorAuthPasswordTokenSessionSchemaError
    assert SECRET_PROVIDER_RESPONSE not in str(raised.value)
    assert SECRET_PROVIDER_RESPONSE not in repr(raised.value)


def test_bounded_list_retypes_auth_user_principal_mismatch_without_disclosure() -> None:
    def mismatched_user(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/v1/token":
            return _session_response()
        if request.url.path == "/auth/v1/user":
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json={
                    "id": "87654321-4321-4321-8321-cba987654321",
                    "unexpected_secret": SECRET_PROVIDER_RESPONSE,
                },
            )
        raise AssertionError(request.url)

    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=httpx.MockTransport(mismatched_user),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorAuthenticationError) as raised,
    ):
        provider.list_object_names_page(
            bucket_name="aqt-trusted-time-anchors-v1",
            prefix=PREFIX,
            offset=0,
            limit=1,
        )

    assert SECRET_PROVIDER_RESPONSE not in str(raised.value)
    assert SECRET_PROVIDER_RESPONSE not in repr(raised.value)


@pytest.mark.parametrize(
    "user_payload",
    [
        {"unexpected_secret": SECRET_PROVIDER_RESPONSE},
        {"id": 7, "unexpected_secret": SECRET_PROVIDER_RESPONSE},
        {"id": SECRET_PROVIDER_RESPONSE},
    ],
)
def test_auth_user_verification_id_shape_failure_is_endpoint_typed(
    user_payload: dict[str, object],
) -> None:
    def malformed_user(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/v1/token":
            return _session_response()
        if request.url.path == "/auth/v1/user":
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json=user_payload,
            )
        raise AssertionError(request.url)

    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=httpx.MockTransport(malformed_user),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorAuthUserVerificationResponseError) as raised,
    ):
        provider.list_object_names_page(
            bucket_name="aqt-trusted-time-anchors-v1",
            prefix=PREFIX,
            offset=0,
            limit=1,
        )

    assert type(raised.value) is SupabaseStorageAnchorAuthUserVerificationResponseError
    assert SECRET_PROVIDER_RESPONSE not in str(raised.value)
    assert SECRET_PROVIDER_RESPONSE not in repr(raised.value)


@pytest.mark.parametrize("protocol_error", ["redirect", "encoding", "oversize"])
def test_auth_user_verification_protocol_error_is_endpoint_typed(
    protocol_error: str,
) -> None:
    def malformed_user(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/v1/token":
            return _session_response()
        if request.url.path != "/auth/v1/user":
            raise AssertionError(request.url)
        if protocol_error == "redirect":
            return httpx.Response(
                302,
                headers={"location": f"{PROJECT_URL}/redirected"},
                content=SECRET_PROVIDER_RESPONSE.encode("ascii"),
            )
        if protocol_error == "encoding":
            return httpx.Response(
                200,
                headers={
                    "content-encoding": "gzip",
                    "content-type": "application/json",
                },
                content=SECRET_PROVIDER_RESPONSE.encode("ascii"),
            )
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=SECRET_PROVIDER_RESPONSE.encode("ascii") * 2_000,
        )

    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=httpx.MockTransport(malformed_user),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorAuthUserVerificationResponseError) as raised,
    ):
        provider.list_object_names_page(
            bucket_name="aqt-trusted-time-anchors-v1",
            prefix=PREFIX,
            offset=0,
            limit=1,
        )

    assert type(raised.value) is SupabaseStorageAnchorAuthUserVerificationResponseError
    assert SECRET_PROVIDER_RESPONSE not in str(raised.value)
    assert SECRET_PROVIDER_RESPONSE not in repr(raised.value)


def test_bounded_list_retypes_storage_denial_without_disclosing_response() -> None:
    auth_attempts = 0

    def denied(request: httpx.Request) -> httpx.Response:
        nonlocal auth_attempts
        if request.url.path == "/auth/v1/token":
            auth_attempts += 1
            return _session_response()
        if request.url.path == "/auth/v1/user":
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json={"id": PRINCIPAL_ID},
            )
        return httpx.Response(
            403,
            headers={
                "content-encoding": "gzip",
                "content-type": "application/json",
            },
            stream=_SingleChunkStream(SECRET_PROVIDER_RESPONSE.encode("ascii")),
        )

    with SupabaseStorageTrustedTimeAnchorProvider(
        credentials=_credentials(),
        transport=httpx.MockTransport(denied),
    ) as provider:
        for _ in range(2):
            with pytest.raises(SupabaseStorageAnchorStorageAccessError) as raised:
                provider.list_object_names_page(
                    bucket_name="aqt-trusted-time-anchors-v1",
                    prefix=PREFIX,
                    offset=0,
                    limit=1,
                )

    assert auth_attempts == 2
    assert type(raised.value) is SupabaseStorageAnchorStorageAccessError
    assert isinstance(raised.value, SupabaseStorageAnchorError)
    assert SECRET_PROVIDER_RESPONSE not in str(raised.value)
    assert SECRET_PROVIDER_RESPONSE not in repr(raised.value)


def test_bounded_list_retypes_malformed_storage_success_as_response_error() -> None:
    def malformed(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"unexpected_secret": SECRET_PROVIDER_RESPONSE},
        )

    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=_auth_or(malformed),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorBoundedListResponseError) as raised,
    ):
        provider.list_object_names_page(
            bucket_name="aqt-trusted-time-anchors-v1",
            prefix=PREFIX,
            offset=0,
            limit=1,
        )

    assert SECRET_PROVIDER_RESPONSE not in str(raised.value)
    assert SECRET_PROVIDER_RESPONSE not in repr(raised.value)


def test_bounded_list_retypes_no_content_as_response_error() -> None:
    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=_auth_or(lambda _: httpx.Response(204)),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorBoundedListResponseError),
    ):
        provider.list_object_names_page(
            bucket_name="aqt-trusted-time-anchors-v1",
            prefix=PREFIX,
            offset=0,
            limit=1,
        )


@pytest.mark.parametrize("protocol_error", ["redirect", "encoding", "oversize"])
def test_bounded_list_protocol_error_is_stage_typed_without_disclosure(
    monkeypatch: pytest.MonkeyPatch,
    protocol_error: str,
) -> None:
    monkeypatch.setattr(adapter, "SUPABASE_STORAGE_ANCHOR_MAX_RESPONSE_BYTES", 8)

    def malformed(_: httpx.Request) -> httpx.Response:
        if protocol_error == "redirect":
            return httpx.Response(
                302,
                headers={"location": f"{PROJECT_URL}/redirected"},
                content=SECRET_PROVIDER_RESPONSE.encode("ascii"),
            )
        if protocol_error == "encoding":
            return httpx.Response(
                200,
                headers={
                    "content-encoding": "gzip",
                    "content-type": "application/json",
                },
                content=SECRET_PROVIDER_RESPONSE.encode("ascii"),
            )
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=SECRET_PROVIDER_RESPONSE.encode("ascii"),
        )

    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=_auth_or(malformed),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorBoundedListResponseError) as raised,
    ):
        provider.list_object_names_page(
            bucket_name="aqt-trusted-time-anchors-v1",
            prefix=PREFIX,
            offset=0,
            limit=1,
        )

    assert type(raised.value) is SupabaseStorageAnchorBoundedListResponseError
    assert isinstance(raised.value, SupabaseStorageAnchorResponseError)
    assert SECRET_PROVIDER_RESPONSE not in str(raised.value)
    assert SECRET_PROVIDER_RESPONSE not in repr(raised.value)


def test_bounded_list_preserves_explicit_provider_unavailable_semantics() -> None:
    def unavailable(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            503,
            headers={
                "content-encoding": "gzip",
                "content-type": "application/json",
            },
            stream=_SingleChunkStream(SECRET_PROVIDER_RESPONSE.encode("ascii")),
        )

    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=_auth_or(unavailable),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorUnavailable) as raised,
    ):
        provider.list_object_names_page(
            bucket_name="aqt-trusted-time-anchors-v1",
            prefix=PREFIX,
            offset=0,
            limit=1,
        )

    assert type(raised.value) is SupabaseStorageAnchorUnavailable
    assert SECRET_PROVIDER_RESPONSE not in str(raised.value)
    assert SECRET_PROVIDER_RESPONSE not in repr(raised.value)


def test_sequence_list_uses_exact_storage_search_without_history_traversal() -> None:
    def operation(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        body = json.loads(request.content)
        assert body["prefix"] == PREFIX
        assert body["search"] == f"{2:020d}-"
        assert body["limit"] == 2
        assert body["offset"] == 0
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[{"name": SECOND_NAME.removeprefix(PREFIX)}],
        )

    with SupabaseStorageTrustedTimeAnchorProvider(
        credentials=_credentials(),
        transport=_auth_or(operation),
    ) as provider:
        assert provider.list_sequence_object_names(
            bucket_name="aqt-trusted-time-anchors-v1",
            prefix=PREFIX,
            anchor_sequence=2,
        ) == (SECOND_NAME,)


def test_sequence_list_rejects_provider_search_contamination() -> None:
    def operation(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[{"name": FIRST_NAME.removeprefix(PREFIX)}],
        )

    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=_auth_or(operation),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorError, match="sequence listing"),
    ):
        provider.list_sequence_object_names(
            bucket_name="aqt-trusted-time-anchors-v1",
            prefix=PREFIX,
            anchor_sequence=2,
        )


def test_sequence_list_returns_a_bounded_fork_without_paging_history() -> None:
    calls = 0

    def operation(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[
                {"name": SECOND_NAME.removeprefix(PREFIX)},
                {"name": f"{2:020d}-{'9' * 64}.json"},
            ],
        )

    with SupabaseStorageTrustedTimeAnchorProvider(
        credentials=_credentials(),
        transport=_auth_or(operation),
    ) as provider:
        names = provider.list_sequence_object_names(
            bucket_name="aqt-trusted-time-anchors-v1",
            prefix=PREFIX,
            anchor_sequence=2,
        )

    assert len(names) == 2
    assert calls == 1


def test_list_rejects_duplicate_pages_and_namespace_contamination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(adapter, "SUPABASE_STORAGE_ANCHOR_LIST_PAGE_SIZE", 1)

    def duplicate(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[{"name": FIRST_NAME.removeprefix(PREFIX)}],
        )

    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=_auth_or(duplicate),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorError, match="duplicates"),
    ):
        provider.list_object_names(
            bucket_name="aqt-trusted-time-anchors-v1",
            prefix=PREFIX,
        )

    def contaminated(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=[{"name": "../escape.json"}],
        )

    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=_auth_or(contaminated),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorError, match="contamination"),
    ):
        provider.list_object_names(
            bucket_name="aqt-trusted-time-anchors-v1",
            prefix=PREFIX,
        )


def test_deeply_nested_provider_json_is_sanitized() -> None:
    nested = b"[" * 2_000 + b"]" * 2_000

    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=_auth_or(
                lambda _: httpx.Response(
                    200,
                    headers={"content-type": "application/json"},
                    content=nested,
                )
            ),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorError, match="object listing"),
    ):
        provider.list_object_names(
            bucket_name="aqt-trusted-time-anchors-v1",
            prefix=PREFIX,
        )


def test_upload_is_no_overwrite_and_download_is_authenticated_exact_bytes() -> None:
    calls: list[str] = []

    def operation(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        assert request.headers["authorization"] == f"Bearer {ACCESS_TOKEN}"
        if request.method == "POST":
            assert request.url.path.endswith(FIRST_NAME)
            assert request.headers["x-upsert"] == "false"
            assert request.headers["content-type"] == "application/json"
            assert request.content == PAYLOAD
            return httpx.Response(
                201,
                headers={"content-type": "application/json"},
                json={"Key": FIRST_NAME},
            )
        assert request.method == "GET"
        assert request.url.path.endswith(FIRST_NAME)
        assert "/object/authenticated/" in request.url.path
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=PAYLOAD,
        )

    with SupabaseStorageTrustedTimeAnchorProvider(
        credentials=_credentials(),
        transport=_auth_or(operation),
    ) as provider:
        provider.upload_object_no_overwrite(
            bucket_name="aqt-trusted-time-anchors-v1",
            object_name=FIRST_NAME,
            payload=PAYLOAD,
            content_type="application/json",
        )
        assert (
            provider.download_object(
                bucket_name="aqt-trusted-time-anchors-v1",
                object_name=FIRST_NAME,
            )
            == PAYLOAD
        )

    assert calls == ["POST", "GET"]


def test_upload_recognizes_only_structured_no_overwrite_collision() -> None:
    def collision(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            409,
            headers={"content-type": "application/json"},
            json={"code": "KeyAlreadyExists", "message": "exists"},
        )

    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=_auth_or(collision),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorConflict, match="already exists"),
    ):
        provider.upload_object_no_overwrite(
            bucket_name="aqt-trusted-time-anchors-v1",
            object_name=FIRST_NAME,
            payload=PAYLOAD,
            content_type="application/json",
        )

    def generic(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            409,
            headers={"content-type": "application/json"},
            json={"message": "another failure"},
        )

    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=_auth_or(generic),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorError, match="upload failed"),
    ):
        provider.upload_object_no_overwrite(
            bucket_name="aqt-trusted-time-anchors-v1",
            object_name=FIRST_NAME,
            payload=PAYLOAD,
            content_type="application/json",
        )


@pytest.mark.parametrize(
    ("status_code", "expected_error"),
    [
        (401, SupabaseStorageAnchorStorageAccessError),
        (403, SupabaseStorageAnchorStorageAccessError),
        (503, SupabaseStorageAnchorUnavailable),
    ],
)
def test_upload_does_not_read_non_collision_error_bodies(
    status_code: int,
    expected_error: type[Exception],
) -> None:
    def rejected(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code,
            headers={
                "content-encoding": "gzip",
                "content-type": "application/json",
            },
            stream=_NeverReadStream(),
        )

    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=_auth_or(rejected),
        ) as provider,
        pytest.raises(expected_error) as raised,
    ):
        provider.upload_object_no_overwrite(
            bucket_name="aqt-trusted-time-anchors-v1",
            object_name=FIRST_NAME,
            payload=PAYLOAD,
            content_type="application/json",
        )

    assert type(raised.value) is expected_error


def test_redirects_oversized_responses_and_unsafe_names_fail_closed() -> None:
    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=_auth_or(
                lambda _: httpx.Response(302, headers={"location": "https://evil.invalid"})
            ),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorError, match="redirect"),
    ):
        provider.download_object(
            bucket_name="aqt-trusted-time-anchors-v1",
            object_name=FIRST_NAME,
        )

    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=_auth_or(
                lambda _: httpx.Response(
                    200,
                    headers={"content-type": "application/json"},
                    content=b"x" * 4_097,
                )
            ),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorError, match="exceeded"),
    ):
        provider.download_object(
            bucket_name="aqt-trusted-time-anchors-v1",
            object_name=FIRST_NAME,
        )

    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=httpx.MockTransport(lambda _: httpx.Response(500)),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorError, match="object name"),
    ):
        provider.download_object(
            bucket_name="aqt-trusted-time-anchors-v1",
            object_name="../../secret",
        )


def test_absolute_request_deadline_stops_a_slow_trickle_response() -> None:
    def operation(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            stream=_SlowTrickleStream(),
        )

    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            timeout_seconds=0.01,
            transport=_auth_or(operation),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorUnavailable, match="timed out"),
    ):
        provider.download_object(
            bucket_name="aqt-trusted-time-anchors-v1",
            object_name=FIRST_NAME,
        )


def test_expiring_session_refreshes_once_without_password_resubmission() -> None:
    clock = iter((0.0, 3_600.0, 3_600.0))
    grants: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/v1/token":
            grants.append(request.url.params["grant_type"])
            return _session_response()
        if request.url.path == "/auth/v1/user":
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json={"id": PRINCIPAL_ID},
            )
        if request.url.path.startswith("/storage/v1/object/list/"):
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json=[],
            )
        raise AssertionError(request.url)

    with SupabaseStorageTrustedTimeAnchorProvider(
        credentials=_credentials(),
        monotonic_clock=lambda: next(clock),
        transport=httpx.MockTransport(handler),
    ) as provider:
        for _ in range(2):
            assert (
                provider.list_object_names(
                    bucket_name="aqt-trusted-time-anchors-v1",
                    prefix=PREFIX,
                )
                == ()
            )

    assert grants == ["password", "refresh_token"]


def test_refresh_response_failure_retains_generic_auth_response_type() -> None:
    clock = iter((0.0, 3_600.0, 3_600.0))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/v1/token":
            if request.url.params["grant_type"] == "password":
                return _session_response()
            return httpx.Response(
                200,
                headers={"content-type": "text/plain"},
                content=SECRET_PROVIDER_RESPONSE.encode("ascii"),
            )
        if request.url.path == "/auth/v1/user":
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json={"id": PRINCIPAL_ID},
            )
        if request.url.path.startswith("/storage/v1/object/list/"):
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json=[],
            )
        raise AssertionError(request.url)

    with SupabaseStorageTrustedTimeAnchorProvider(
        credentials=_credentials(),
        monotonic_clock=lambda: next(clock),
        transport=httpx.MockTransport(handler),
    ) as provider:
        assert (
            provider.list_object_names_page(
                bucket_name="aqt-trusted-time-anchors-v1",
                prefix=PREFIX,
                offset=0,
                limit=1,
            )
            == ()
        )
        with pytest.raises(SupabaseStorageAnchorAuthenticationResponseError) as raised:
            provider.list_object_names_page(
                bucket_name="aqt-trusted-time-anchors-v1",
                prefix=PREFIX,
                offset=0,
                limit=1,
            )

    assert type(raised.value) is SupabaseStorageAnchorAuthenticationResponseError
    assert SECRET_PROVIDER_RESPONSE not in str(raised.value)
    assert SECRET_PROVIDER_RESPONSE not in repr(raised.value)


@pytest.mark.parametrize("status_code", [408, 425, 429, 500, 503, 599])
def test_retryable_http_status_is_explicit_provider_unavailable(
    status_code: int,
) -> None:
    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=_auth_or(lambda _: httpx.Response(status_code)),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorUnavailable, match="service is unavailable"),
    ):
        provider.download_object(
            bucket_name="aqt-trusted-time-anchors-v1",
            object_name=FIRST_NAME,
        )


def test_transport_outage_is_explicit_provider_unavailable() -> None:
    def unavailable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("unavailable", request=request)

    with (
        SupabaseStorageTrustedTimeAnchorProvider(
            credentials=_credentials(),
            transport=_auth_or(unavailable),
        ) as provider,
        pytest.raises(SupabaseStorageAnchorUnavailable, match="transport is unavailable"),
    ):
        provider.download_object(
            bucket_name="aqt-trusted-time-anchors-v1",
            object_name=FIRST_NAME,
        )
