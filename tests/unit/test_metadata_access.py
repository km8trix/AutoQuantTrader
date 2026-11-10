"""Actual read-only session signatures and denial by original mutation decoders."""

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta, timezone
from http.cookies import SimpleCookie

import pytest
from fastapi import HTTPException, Response

from apps.api.backtest_views import LOCAL_SESSION_COOKIE, LocalOperatorSecurity
from apps.api.metadata_access import (
    METADATA_CSRF_HEADER,
    METADATA_SESSION_COOKIE,
    METADATA_SESSION_PURPOSE,
    MetadataAccessSecurity,
)
from apps.api.runtime_owner_authentication import LocalRuntimeOwnerAuthenticator
from packages.domain.reconciliation_contracts import ReconciliationHeads
from packages.persistence.daily_runtime_risk import RuntimeAssignmentCommand

NOW = datetime(2026, 10, 22, 14, 35, 12, 123456, tzinfo=UTC)
OWNER = "metadata-test-operator"
SECRET = "unit-test-only-shared-configuration"


def _security(**changes):
    values = {
        "enabled": True,
        "transport_is_loopback_scoped": True,
        "operator_id": OWNER,
        "configured_secret": SECRET,
    }
    values.update(changes)
    return MetadataAccessSecurity(**values)


def _bootstrap(security, *, at=NOW, cookie=None):
    response = Response()
    capability = security.bootstrap_capability(response, issued_at=at, session_cookie=cookie)
    cookies = SimpleCookie()
    if "set-cookie" in response.headers:
        cookies.load(response.headers["set-cookie"])
    token = cookies[METADATA_SESSION_COOKIE].value if METADATA_SESSION_COOKIE in cookies else cookie
    return capability, token, response


def _original():
    security = LocalOperatorSecurity(
        enabled=True, transport_is_loopback_scoped=True, operator_id=OWNER, configured_secret=SECRET
    )
    response = Response()
    capability = security.bootstrap_capability(
        response, persistence_ready=True, issued_at=NOW, session_cookie=None
    )
    cookies = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    return security, cookies[LOCAL_SESSION_COOKIE].value, capability.csrf_token


def _payload(cookie):
    encoded = cookie.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))


def _signed_negative(security, payload=None, *, raw=None):
    # Deliberately malformed, validly signed input reaches the actual claim decoder.
    if raw is None:
        raw = json.dumps(
            payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False
        ).encode()
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=")
    signature = hmac.new(security._key, encoded, hashlib.sha256).hexdigest()
    return encoded.decode() + "." + signature


def test_real_metadata_cookie_scope_expiry_and_nonrenewing_bootstrap():
    security = _security()
    capability, cookie, response = _bootstrap(security)
    assert capability.enabled is True and capability.operator_id == OWNER
    assert capability.csrf_header == METADATA_CSRF_HEADER
    assert capability.disabled_reason is None
    assert capability.expires_at == NOW.replace(microsecond=0) + timedelta(hours=8)
    assert security.authenticate(cookie, capability.csrf_token, now=NOW) == OWNER
    assert _payload(cookie)["purpose"] == METADATA_SESSION_PURPOSE
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    cookies = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    assert set(cookies) == {METADATA_SESSION_COOKIE}
    attributes = cookies[METADATA_SESSION_COOKIE]
    assert attributes["httponly"] and attributes["samesite"] == "strict"
    assert attributes["path"] == "/api/v1" and attributes["max-age"] == "28800"
    assert not attributes["secure"]  # Actual supported transport is local HTTP.
    repeated, same_cookie, repeated_response = _bootstrap(
        security, at=NOW + timedelta(hours=1), cookie=cookie
    )
    assert repeated == capability and same_cookie == cookie
    assert "set-cookie" not in repeated_response.headers
    assert not hasattr(capability, "idempotency_header")


def test_original_and_metadata_actual_decoders_reject_each_others_tokens():
    original, original_cookie, original_csrf = _original()
    metadata = _security()
    capability, metadata_cookie, _ = _bootstrap(metadata)
    assert original.authenticate(original_cookie, original_csrf, now=NOW) == OWNER
    assert metadata.authenticate(metadata_cookie, capability.csrf_token, now=NOW) == OWNER
    with pytest.raises(HTTPException) as old_denial:
        original.authenticate(metadata_cookie, capability.csrf_token, now=NOW)
    assert old_denial.value.status_code == 401
    with pytest.raises(HTTPException) as metadata_denial:
        metadata.authenticate(original_cookie, original_csrf, now=NOW)
    assert metadata_denial.value.status_code == 401


def test_key_domain_is_distinct_even_with_the_same_configured_secret_and_nonce(monkeypatch):
    monkeypatch.setattr("secrets.token_bytes", lambda count: b"x" * count)
    original, original_cookie, original_csrf = _original()
    metadata = _security()
    capability, cookie, _ = _bootstrap(metadata)
    assert metadata._key != original._key
    assert metadata.authenticate(cookie, capability.csrf_token, now=NOW) == OWNER
    with pytest.raises(HTTPException) as denial:
        metadata.authenticate(original_cookie, original_csrf, now=NOW)
    assert denial.value.status_code == 401


def test_metadata_cannot_create_original_runtime_owner_authentication():
    original, original_cookie, original_csrf = _original()
    metadata = _security()
    capability, cookie, _ = _bootstrap(metadata)
    command = RuntimeAssignmentCommand(
        command_id="metadata-denied-owner-request",
        owner_id=OWNER,
        account_id="test-account",
        before_assignment_sha256=None,
        after_assignment_sha256="a" * 64,
        expected_heads=ReconciliationHeads("b" * 64, "c" * 64, "d" * 64, 0, "e" * 64, 0, 1),
        quiescence_sha256="f" * 64,
        requested_at=NOW,
        expires_at=NOW + timedelta(seconds=60),
    )
    authority = LocalRuntimeOwnerAuthenticator(original)
    with pytest.raises(HTTPException) as denial:
        authority.authenticate(
            command, session_cookie=cookie, csrf_token=capability.csrf_token, now=NOW
        )
    assert denial.value.status_code == 401
    assert not authority._original and not authority._owned
    with pytest.raises(ValueError, match="actual local operator security instance"):
        LocalRuntimeOwnerAuthenticator(metadata)
    legitimate = authority.authenticate(
        command, session_cookie=original_cookie, csrf_token=original_csrf, now=NOW
    )
    authority.require_authenticated(legitimate)


@pytest.mark.parametrize(
    "changes",
    [
        {"enabled": 1},
        {"transport_is_loopback_scoped": 1},
        {"transport_is_loopback_scoped": False},
        {"operator_id": ""},
        {"operator_id": " owner"},
        {"operator_id": "a" * 129},
        {"operator_id": "owner\nname"},
        {"operator_id": "\ud800"},
        {"configured_secret": b"not-text"},
        {"configured_secret": "\ud800"},
    ],
)
def test_invalid_configuration_is_rejected(changes):
    with pytest.raises(ValueError):
        _security(**changes)


def test_maximum_unicode_operator_still_receives_a_bounded_usable_token():
    security = _security(operator_id="\U0001f600" * 128)
    capability, cookie, _ = _bootstrap(security)
    assert len(cookie) <= 2048
    assert security.authenticate(cookie, capability.csrf_token, now=NOW) == capability.operator_id


def test_disabled_metadata_deletes_only_its_cookie_and_does_not_authorize():
    original, original_cookie, original_csrf = _original()
    capability, _, response = _bootstrap(
        _security(enabled=False, transport_is_loopback_scoped=False)
    )
    assert not capability.enabled
    assert capability.operator_id is capability.csrf_token is capability.expires_at is None
    cookies = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    assert (
        set(cookies) == {METADATA_SESSION_COOKIE}
        and cookies[METADATA_SESSION_COOKIE]["max-age"] == "0"
    )
    assert original.authenticate(original_cookie, original_csrf, now=NOW) == OWNER
    with pytest.raises(HTTPException) as denial:
        _security(enabled=False).authenticate(None, "x" * 32, now=NOW)
    assert denial.value.status_code == 403


def test_original_bootstrap_does_not_delete_or_reissue_metadata_cookie():
    original, _, _ = _original()
    metadata = _security()
    capability, cookie, _ = _bootstrap(metadata)
    response = Response()
    original.bootstrap_capability(
        response, persistence_ready=False, issued_at=NOW, session_cookie=None
    )
    cookies = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    assert set(cookies) == {LOCAL_SESSION_COOKIE}
    assert metadata.authenticate(cookie, capability.csrf_token, now=NOW) == OWNER


@pytest.mark.parametrize(
    "kind", ["missing", "empty", "bytes", "oversize", "tampered", "bad64", "signature", "restart"]
)
def test_invalid_cookie_is_static_unauthorized(kind):
    security = _security()
    capability, cookie, _ = _bootstrap(security)
    if kind == "restart":
        security = _security()
    else:
        cookie = {
            "missing": None,
            "empty": "",
            "bytes": cookie.encode(),
            "oversize": "a" * 2049,
            "tampered": cookie + "x",
            "bad64": "!" + cookie,
            "signature": cookie.rsplit(".", 1)[0] + "." + "g" * 64,
        }[kind]
    with pytest.raises(HTTPException) as denial:
        security.authenticate(cookie, capability.csrf_token, now=NOW)
    assert denial.value.status_code == 401
    assert denial.value.detail == "a current metadata read session is required"
    assert denial.value.headers["WWW-Authenticate"] == "MetadataReadSession"
    assert denial.value.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize(
    "csrf", [None, True, b"a" * 43, "", "a" * 31, "a" * 129, "é" * 43, "a" * 43]
)
def test_csrf_requires_exact_bounded_matching_text(csrf):
    security = _security()
    _, cookie, _ = _bootstrap(security)
    with pytest.raises(HTTPException) as denial:
        security.authenticate(cookie, csrf, now=NOW)
    assert denial.value.status_code == 403
    assert denial.value.detail == "metadata read CSRF validation failed"


@pytest.mark.parametrize(
    "change",
    [
        {"purpose": "backtest-launch"},
        {"purpose": True},
        {"sub": "foreign"},
        {"v": True},
        {"v": 2},
        {"iat": True},
        {"exp": True},
        {"csrf": "x"},
        {"csrf": "é" * 43},
        {"extra": "unaccepted"},
        {"iat": 10**100, "exp": 10**100 + 28800},
    ],
)
def test_valid_signature_cannot_admit_invalid_claims(change):
    security = _security()
    capability, cookie, _ = _bootstrap(security)
    payload = _payload(cookie)
    payload.update(change)
    with pytest.raises(HTTPException) as denial:
        security.authenticate(_signed_negative(security, payload), capability.csrf_token, now=NOW)
    assert denial.value.status_code == 401


@pytest.mark.parametrize(
    "kind",
    [
        "missing-purpose",
        "short-life",
        "long-life",
        "future",
        "duplicate",
        "noncanonical",
        "bad-json",
        "array",
    ],
)
def test_signed_structural_and_lifetime_corruption_is_rejected(kind):
    security = _security()
    capability, cookie, _ = _bootstrap(security)
    payload = _payload(cookie)
    raw = None
    if kind == "missing-purpose":
        del payload["purpose"]
    elif kind in {"short-life", "long-life"}:
        payload["exp"] += -1 if kind == "short-life" else 1
    elif kind == "future":
        payload["iat"] += 1
        payload["exp"] += 1
    elif kind == "duplicate":
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        raw = raw[:-1] + b',"v":1}'
    elif kind == "noncanonical":
        raw = json.dumps(payload, indent=2).encode()
    elif kind == "bad-json":
        raw = b'{"unterminated"'
    elif kind == "array":
        raw = b"[]"
    with pytest.raises(HTTPException) as denial:
        security.authenticate(
            _signed_negative(security, payload, raw=raw), capability.csrf_token, now=NOW
        )
    assert denial.value.status_code == 401


def test_original_expiry_boundary_and_rebootstrap_do_not_extend_old_token():
    security = _security()
    capability, cookie, _ = _bootstrap(security)
    expiry = capability.expires_at
    assert (
        security.authenticate(cookie, capability.csrf_token, now=expiry - timedelta(microseconds=1))
        == OWNER
    )
    with pytest.raises(HTTPException) as denial:
        security.authenticate(cookie, capability.csrf_token, now=expiry)
    assert denial.value.status_code == 401
    renewed, new_cookie, _ = _bootstrap(security, at=expiry, cookie=cookie)
    assert new_cookie != cookie and renewed.csrf_token != capability.csrf_token
    assert renewed.expires_at == expiry + timedelta(hours=8)
    with pytest.raises(HTTPException):
        security.authenticate(cookie, capability.csrf_token, now=expiry)


@pytest.mark.parametrize(
    "now", [None, True, NOW.replace(tzinfo=None), NOW.astimezone(timezone(timedelta(hours=1)))]
)
def test_invalid_actual_authentication_utc_rejects_before_cookie_issue(now):
    security = _security()
    capability, cookie, _ = _bootstrap(security)
    response = Response()
    with pytest.raises(HTTPException) as issue_denial:
        security.bootstrap_capability(response, issued_at=now, session_cookie=None)
    assert issue_denial.value.status_code == 503 and "set-cookie" not in response.headers
    with pytest.raises(HTTPException) as read_denial:
        security.authenticate(cookie, capability.csrf_token, now=now)
    assert read_denial.value.status_code == 503


def test_unrepresentable_expiry_never_sets_a_cookie():
    response = Response()
    with pytest.raises(HTTPException) as denial:
        _security().bootstrap_capability(
            response, issued_at=datetime.max.replace(tzinfo=UTC), session_cookie=None
        )
    assert denial.value.status_code == 503 and "set-cookie" not in response.headers
