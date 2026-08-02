from __future__ import annotations

import asyncio
import json
from collections.abc import Callable

import httpx
import pytest

import packages.adapters.trusted_time.supabase_storage_anchor as adapter
from packages.adapters.trusted_time.supabase_storage_anchor import (
    SupabaseStorageAnchorConflict,
    SupabaseStorageAnchorCredentials,
    SupabaseStorageAnchorError,
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


class _SlowTrickleStream(httpx.AsyncByteStream):
    async def __aiter__(self):  # type: ignore[no-untyped-def]
        yield b"{"
        await asyncio.sleep(0.05)
        yield b"}"


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


def _session_response() -> httpx.Response:
    return httpx.Response(
        200,
        headers={"content-type": "application/json"},
        json={
            "access_token": ACCESS_TOKEN,
            "expires_in": 3600,
            "refresh_token": REFRESH_TOKEN,
            "token_type": "bearer",
            "user": {"id": PRINCIPAL_ID},
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
