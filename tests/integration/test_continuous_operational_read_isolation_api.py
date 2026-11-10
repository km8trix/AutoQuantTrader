"""New permission is rejected by every original HTTP authentication consumer.

These use real decoders and fresh migrated fixtures, without a new owner or any
server. A readiness503 or request422 would not establish credential isolation.
"""

from datetime import UTC, datetime
from http.cookies import SimpleCookie

from fastapi import Response

from apps.api.backtest_views import LOCAL_SESSION_COOKIE
from apps.api.continuous_read_access import (
    CONTINUOUS_READ_SESSION_COOKIE,
    ContinuousReadAccessConfiguration,
    ContinuousReadAccessSecurity,
)
from apps.api.metadata_access import METADATA_CSRF_HEADER, METADATA_SESSION_COOKIE
from tests.integration.test_continuous_metadata_access_api import (
    _cookie,
    _database_facts,
    _empty_api,
    _facts,
    _path,
    _read_capability,
    _selected_api,
    _writer_requests,
)


def _permission(account_id):
    # Test-owned standalone issuer exercises real signing; only actual M app
    # acceptance establishes the separate L-entry/admission relationship.
    security = ContinuousReadAccessSecurity(
        configuration=ContinuousReadAccessConfiguration(
            enabled=True,
            transport_is_loopback_scoped=True,
            operator_id="local-operator",
            configured_secret="local-development-only",
        ),
        account_id=account_id,
    )
    security.open()
    response = Response()
    capability = security.bootstrap_capability(
        response, issued_at=datetime.now(UTC), session_cookie=None
    )
    cookies = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    return security, cookies[CONTINUOUS_READ_SESSION_COOKIE].value, capability.csrf_token


def test_operational_read_credential_cannot_use_any_original_authenticated_http_consumer(tmp_path):
    with _selected_api(tmp_path, writer_probes=True) as selected:
        account_id = selected.study.genesis.scope.account_id
        security, token, csrf = _permission(account_id)
        original_headers = _read_capability(selected.client)
        metadata_cookie = selected.client.cookies.get(METADATA_SESSION_COOKIE)
        _cookie(selected.client, CONTINUOUS_READ_SESSION_COOKIE, token)
        _cookie(selected.client, LOCAL_SESSION_COOKIE, token)
        headers = {"X-CSRF-Token": csrf, "Idempotency-Key": "operational-read-denial"}
        before = _facts(selected.study)
        for method, path, body in _writer_requests(account_id):
            response = selected.client.request(method, path, headers=headers, json=body)
            assert response.status_code == 401, (method, path, response.text)
            assert _facts(selected.study) == before
        _cookie(selected.client, METADATA_SESSION_COOKIE, token)
        denied = selected.client.get(_path(account_id), headers={METADATA_CSRF_HEADER: csrf})
        assert denied.status_code == 401
        assert denied.headers["cache-control"] == "no-store"
        assert denied.headers["pragma"] == "no-cache"
        assert _facts(selected.study) == before
        _cookie(selected.client, METADATA_SESSION_COOKIE, metadata_cookie)
        assert selected.client.get(_path(account_id), headers=original_headers).status_code == 200
        assert selected.client.get("/health/ready").status_code == 503
        assert selected.study.genesis.account.coordinator.current() is None
        assert _facts(selected.study) == before
        security.close()


def test_new_cookie_coexists_with_both_original_actual_bootstraps_without_changing_them(tmp_path):
    with _empty_api(tmp_path) as api:
        before = _database_facts(api.engine)
        security, token, csrf = _permission("absent-account")
        _cookie(api.client, CONTINUOUS_READ_SESSION_COOKIE, token)
        metadata_headers = _read_capability(api.client)
        metadata_cookie = api.client.cookies.get(METADATA_SESSION_COOKIE)
        original = api.client.get("/api/v1/ui/bootstrap")
        assert original.status_code == 200
        capability = original.json()["backtest_launch"]
        assert capability["enabled"] is True
        original_cookie = api.client.cookies.get(LOCAL_SESSION_COOKIE)
        assert original_cookie
        assert api.client.cookies.get(CONTINUOUS_READ_SESSION_COOKIE) == token
        assert api.client.cookies.get(METADATA_SESSION_COOKIE) == metadata_cookie
        assert api.client.get(_path("absent-account"), headers=metadata_headers).status_code == 200
        assert (
            api.client.get(
                "/api/v1/operations/accounts/absent-account",
                headers={"X-CSRF-Token": capability["csrf_token"]},
            ).status_code
            == 200
        )
        assert security.authenticate(token, csrf, now=datetime.now(UTC)) == "local-operator"
        assert _database_facts(api.engine) == before
        security.close()
