"""Real signatures and purpose boundaries, without an owner or private store.

Every credential here is generated from synthetic test-only configuration.
Successful authentication grants only the new fixed proof/read permission; the
separate ASGI tests must qualify actual L/K ownership and financial no-effects.
"""

import base64
import hashlib
import hmac
import json
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta, timezone
from http.cookies import SimpleCookie

import pytest
from fastapi import HTTPException, Response
from pydantic import ValidationError

from apps.api.backtest_views import LOCAL_SESSION_COOKIE, LocalOperatorSecurity
from apps.api.continuous_read_access import (
    CONTINUOUS_READ_CSRF_HEADER,
    CONTINUOUS_READ_SESSION_COOKIE,
    CONTINUOUS_READ_SESSION_PURPOSE,
    ContinuousReadAccessConfiguration,
    ContinuousReadAccessSecurity,
)
from apps.api.contracts import ContinuousOperationalReadCapabilityView
from apps.api.metadata_access import (
    METADATA_SESSION_COOKIE,
    METADATA_SESSION_PURPOSE,
    MetadataAccessSecurity,
)
from apps.api.runtime_owner_authentication import LocalRuntimeOwnerAuthenticator
from packages.domain.reconciliation_contracts import ReconciliationHeads
from packages.persistence.daily_runtime_risk import RuntimeAssignmentCommand

NOW = datetime(2026, 10, 28, 14, 35, 12, 123456, tzinfo=UTC)
OWNER = "continuous-read-test-operator"
ACCOUNT = "continuous-read-test-account"
SECRET = "synthetic-unit-only-configuration-secret"
_CACHE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _configuration(**changes):
    values = {
        "enabled": True,
        "transport_is_loopback_scoped": True,
        "operator_id": OWNER,
        "configured_secret": SECRET,
    }
    values.update(changes)
    return ContinuousReadAccessConfiguration(**values)


def _security(*, account=ACCOUNT, opened=True, configuration=None, **changes):
    security = ContinuousReadAccessSecurity(
        configuration=_configuration(**changes) if configuration is None else configuration,
        account_id=account,
    )
    if opened:
        security.open()
    return security


def _cookies(response):
    cookies = SimpleCookie()
    for header in response.headers.getlist("set-cookie"):
        cookies.load(header)
    return cookies


def _bootstrap(security, *, at=NOW, cookie=None, response=None):
    response = Response() if response is None else response
    capability = security.bootstrap_capability(response, issued_at=at, session_cookie=cookie)
    cookies = _cookies(response)
    token = (
        cookies[CONTINUOUS_READ_SESSION_COOKIE].value
        if CONTINUOUS_READ_SESSION_COOKIE in cookies
        else cookie
    )
    return capability, token, response


def _legacy(*, metadata=False):
    cls = MetadataAccessSecurity if metadata else LocalOperatorSecurity
    security = cls(
        enabled=True,
        transport_is_loopback_scoped=True,
        operator_id=OWNER,
        configured_secret=SECRET,
    )
    response = Response()
    arguments = {"issued_at": NOW, "session_cookie": None}
    if not metadata:
        arguments["persistence_ready"] = True
    capability = security.bootstrap_capability(response, **arguments)
    name = METADATA_SESSION_COOKIE if metadata else LOCAL_SESSION_COOKIE
    return security, _cookies(response)[name].value, capability.csrf_token


def _payload(cookie):
    encoded = cookie.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))


def _signed_encoded(security, encoded):
    signature = hmac.new(security._key, encoded, hashlib.sha256).hexdigest()
    return encoded.decode("ascii") + "." + signature


def _signed(security, payload=None, *, raw=None):
    # Deliberately invalid claims with a real signature reach the actual claim
    # decoder. No replacement authenticator or financial proof is used.
    if raw is None:
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode(
            "utf-8"
        )
    return _signed_encoded(security, base64.urlsafe_b64encode(raw).rstrip(b"="))


def _denied(security, cookie, csrf, *, status=401, at=NOW):
    with pytest.raises(HTTPException) as raised:
        security.authenticate(cookie, csrf, now=at)
    assert raised.value.status_code == status
    assert all(raised.value.headers[key] == value for key, value in _CACHE.items())
    assert SECRET not in str(raised.value.detail)
    return raised.value


def test_exact_permission_cookie_claims_and_nonrenewing_bootstrap():
    security = _security()
    capability, cookie, response = _bootstrap(security)
    assert type(capability) is ContinuousOperationalReadCapabilityView
    assert capability.enabled is True
    assert capability.operator_id == OWNER and capability.account_id == ACCOUNT
    assert capability.scope == CONTINUOUS_READ_SESSION_PURPOSE == "continuous-operational-read/1"
    assert capability.csrf_header == CONTINUOUS_READ_CSRF_HEADER
    assert capability.disabled_reason is None
    assert capability.expires_at == NOW.replace(microsecond=0) + timedelta(hours=8)
    assert len(capability.csrf_token) == 43 and len(cookie) <= 2048
    assert security.authenticate(cookie, capability.csrf_token, now=NOW) == OWNER
    claims = _payload(cookie)
    assert set(claims) == {"account", "csrf", "exp", "iat", "purpose", "scope", "sub", "v"}
    assert claims["account"] == ACCOUNT and claims["sub"] == OWNER
    assert claims["purpose"] == CONTINUOUS_READ_SESSION_PURPOSE and claims["v"] == 1
    assert len(claims["scope"]) == 32
    assert all(character in "0123456789abcdef" for character in claims["scope"])
    assert claims["exp"] - claims["iat"] == 28800
    attributes = _cookies(response)[CONTINUOUS_READ_SESSION_COOKIE]
    assert attributes["httponly"] and attributes["samesite"] == "strict"
    assert attributes["path"] == "/api/v1" and attributes["max-age"] == "28800"
    assert not attributes["secure"]  # Explicitly local HTTP, not a socket qualification.
    assert all(response.headers[key] == value for key, value in _CACHE.items())
    repeated, repeated_cookie, reused_response = _bootstrap(
        security, at=NOW + timedelta(hours=1), cookie=cookie
    )
    assert repeated == capability and repeated_cookie == cookie
    assert "set-cookie" not in reused_response.headers
    assert set(capability.model_dump()) == {
        "enabled",
        "operator_id",
        "account_id",
        "csrf_token",
        "csrf_header",
        "expires_at",
        "disabled_reason",
        "scope",
    }
    assert not hasattr(capability, "verification") and not hasattr(capability, "idempotency_header")


def test_configuration_and_returned_dto_cannot_rewrite_copied_security_state():
    configuration = _configuration()
    assert not hasattr(configuration, "__dict__") and SECRET not in repr(configuration)
    with pytest.raises(FrozenInstanceError):
        configuration.enabled = False
    security = _security(configuration=configuration)
    object.__setattr__(configuration, "enabled", False)
    object.__setattr__(configuration, "operator_id", "another-operator")
    object.__setattr__(configuration, "configured_secret", "another-synthetic-secret")
    capability, cookie, _ = _bootstrap(security)
    assert capability.enabled is True and capability.operator_id == OWNER
    with pytest.raises(ValidationError):
        capability.enabled = False
    with pytest.raises(ValidationError):
        ContinuousOperationalReadCapabilityView(**{**capability.model_dump(), "readiness": "ready"})
    object.__setattr__(capability, "operator_id", "another-operator")
    assert security.authenticate(cookie, capability.csrf_token, now=NOW) == OWNER
    unchanged, same_cookie, _ = _bootstrap(security, cookie=cookie)
    assert unchanged.operator_id == OWNER and same_cookie == cookie


def test_scope_opens_once_closes_permanently_and_is_not_proof_availability():
    security = _security(opened=False)
    assert security.is_open() is False
    unavailable, _, response = _bootstrap(security)
    assert unavailable.enabled is False and unavailable.account_id is None
    assert set(_cookies(response)) == {CONTINUOUS_READ_SESSION_COOKIE}
    _denied(security, None, "a" * 43, status=503)
    security.open()
    assert security.is_open() is True
    capability, cookie, _ = _bootstrap(security)
    with pytest.raises(RuntimeError, match=r"^CONTINUOUS_READ_SCOPE_ALREADY_USED$"):
        security.open()
    assert security.authenticate(cookie, capability.csrf_token, now=NOW) == OWNER
    security.close()
    security.close()
    assert security.is_open() is False
    _denied(security, cookie, capability.csrf_token, status=503)
    closed, _, _ = _bootstrap(security, cookie=cookie)
    assert closed.enabled is False and closed.csrf_token is None and closed.expires_at is None
    with pytest.raises(RuntimeError, match=r"^CONTINUOUS_READ_SCOPE_ALREADY_USED$"):
        security.open()
    never_opened = _security(opened=False)
    never_opened.close()
    with pytest.raises(RuntimeError, match=r"^CONTINUOUS_READ_SCOPE_ALREADY_USED$"):
        never_opened.open()


@pytest.mark.parametrize("opened", [False, True])
def test_disabled_permission_never_issues_or_authenticates(opened):
    security = _security(opened=opened, enabled=False, transport_is_loopback_scoped=False)
    capability, _, response = _bootstrap(security)
    assert capability.enabled is False
    assert capability.operator_id is capability.account_id is capability.csrf_token is None
    assert capability.expires_at is None
    assert _cookies(response)[CONTINUOUS_READ_SESSION_COOKIE]["max-age"] == "0"
    _denied(security, None, "a" * 43, status=403)


@pytest.mark.parametrize(
    "source,target",
    [
        ("new", "metadata"),
        ("new", "shared"),
        ("metadata", "new"),
        ("shared", "new"),
        ("shared", "metadata"),
        ("metadata", "shared"),
    ],
)
def test_all_three_actual_decoders_reject_other_purposes(source, target):
    new = _security()
    capability, cookie, _ = _bootstrap(new)
    issued = {
        "new": (new, cookie, capability.csrf_token),
        "metadata": _legacy(metadata=True),
        "shared": _legacy(),
    }
    for security, legitimate_cookie, csrf in issued.values():
        assert security.authenticate(legitimate_cookie, csrf, now=NOW) == OWNER
    target_security = issued[target][0]
    _, foreign_cookie, foreign_csrf = issued[source]
    with pytest.raises(HTTPException) as raised:
        target_security.authenticate(foreign_cookie, foreign_csrf, now=NOW)
    assert raised.value.status_code == 401  # The actual decoder, not a readiness denial.


def test_domains_stay_distinct_with_same_controlled_private_nonce_and_secret(monkeypatch):
    with monkeypatch.context() as local:
        local.setattr("secrets.token_bytes", lambda count: b"x" * count)
        shared, shared_cookie, shared_csrf = _legacy()
        metadata, metadata_cookie, metadata_csrf = _legacy(metadata=True)
        new = _security()
        capability, cookie, _ = _bootstrap(new)
    assert len({shared._key, metadata._key, new._key}) == 3
    for security, own_cookie, csrf in (
        (shared, shared_cookie, shared_csrf),
        (metadata, metadata_cookie, metadata_csrf),
        (new, cookie, capability.csrf_token),
    ):
        assert security.authenticate(own_cookie, csrf, now=NOW) == OWNER
    _denied(new, shared_cookie, shared_csrf)
    _denied(new, metadata_cookie, metadata_csrf)


def test_public_scope_is_not_private_signing_entropy(monkeypatch):
    draws = iter((b"a" * 32, b"s" * 16, b"b" * 32, b"s" * 16))
    observed = []

    def controlled(count):
        value = next(draws)
        assert len(value) == count
        observed.append(count)
        return value

    with monkeypatch.context() as local:
        local.setattr("secrets.token_bytes", controlled)
        first, second = _security(), _security()
    assert observed == [32, 16, 32, 16]
    assert first._scope == second._scope == (b"s" * 16).hex()
    prefix = CONTINUOUS_READ_SESSION_PURPOSE.encode("ascii") + b"\0" + SECRET.encode() + b"\0"
    assert first._key == hashlib.sha256(prefix + b"a" * 32).digest()
    assert second._key == hashlib.sha256(prefix + b"b" * 32).digest()
    assert first._key != second._key
    assert first._key != hashlib.sha256(prefix + bytes.fromhex(first._scope)).digest()
    capability, cookie, _ = _bootstrap(first)
    _denied(second, cookie, capability.csrf_token)
    encoded = cookie.split(".")[0].encode("ascii")
    exposed_material_key = hashlib.sha256(prefix + bytes.fromhex(first._scope)).digest()
    forged = (
        encoded.decode("ascii")
        + "."
        + hmac.new(exposed_material_key, encoded, hashlib.sha256).hexdigest()
    )
    _denied(first, forged, capability.csrf_token)


def test_new_permission_cannot_issue_runtime_owner_authentication_or_command_seal():
    shared, shared_cookie, shared_csrf = _legacy()
    new = _security()
    capability, cookie, _ = _bootstrap(new)
    command = RuntimeAssignmentCommand(
        command_id="continuous-read-denied-owner-request",
        owner_id=OWNER,
        account_id=ACCOUNT,
        before_assignment_sha256=None,
        after_assignment_sha256="a" * 64,
        expected_heads=ReconciliationHeads("b" * 64, "c" * 64, "d" * 64, 0, "e" * 64, 0, 1),
        quiescence_sha256="f" * 64,
        requested_at=NOW,
        expires_at=NOW + timedelta(seconds=60),
    )
    authority = LocalRuntimeOwnerAuthenticator(shared)
    with pytest.raises(HTTPException) as denied:
        authority.authenticate(
            command, session_cookie=cookie, csrf_token=capability.csrf_token, now=NOW
        )
    assert denied.value.status_code == 401
    assert not authority._original and not authority._owned
    with pytest.raises(ValueError, match="actual local operator security instance"):
        LocalRuntimeOwnerAuthenticator(new)
    legitimate = authority.authenticate(
        command, session_cookie=shared_cookie, csrf_token=shared_csrf, now=NOW
    )
    authority.require_authenticated(legitimate)


@pytest.mark.parametrize("different_account", [False, True])
def test_another_scope_or_account_cannot_adopt_existing_credential(different_account):
    first = _security()
    capability, cookie, _ = _bootstrap(first)
    other = _security(account="another-test-account" if different_account else ACCOUNT)
    _denied(other, cookie, capability.csrf_token)
    claims = _payload(cookie)
    # Re-sign with the recipient's own actual key: rejection must also enforce
    # exact account/scope, not rely solely on different process signatures.
    _denied(other, _signed(other, claims), capability.csrf_token)
    valid, _, _ = _bootstrap(other)
    assert valid.account_id == ("another-test-account" if different_account else ACCOUNT)


def test_exact_expiry_equality_and_rebootstrap_cannot_extend_old_token():
    security = _security()
    capability, cookie, _ = _bootstrap(security)
    expiry = capability.expires_at
    assert (
        security.authenticate(cookie, capability.csrf_token, now=expiry - timedelta(microseconds=1))
        == OWNER
    )
    _denied(security, cookie, capability.csrf_token, at=expiry)
    fresh, new_cookie, response = _bootstrap(security, at=expiry, cookie=cookie)
    assert new_cookie != cookie and fresh.expires_at == expiry + timedelta(hours=8)
    assert "set-cookie" in response.headers
    _denied(security, cookie, capability.csrf_token, at=expiry)
    assert security.authenticate(new_cookie, fresh.csrf_token, now=expiry) == OWNER


class _ForeignText(str):
    def __len__(self):
        raise AssertionError("foreign text length must not run")

    def split(self, *args, **kwargs):
        raise AssertionError("foreign text split must not run")


@pytest.mark.parametrize(
    "cookie",
    [
        None,
        True,
        b"not-text",
        _ForeignText("opaque"),
        "",
        "x" * 2049,
        ".",
        "x.y.z",
        "a." + "f" * 64,
    ],
)
def test_invalid_native_or_bounded_cookie_is_static_unauthorized(cookie):
    security = _security()
    _denied(security, cookie, "a" * 43)


@pytest.mark.parametrize("part", ["signature", "payload", "signature-alphabet", "padding"])
def test_external_cookie_tampering_cannot_reuse_an_original_signature(part):
    security = _security()
    capability, cookie, _ = _bootstrap(security)
    encoded, signature = cookie.split(".")
    if part == "signature":
        signature = ("0" if signature[0] != "0" else "1") + signature[1:]
    elif part == "payload":
        encoded = ("A" if encoded[0] != "A" else "B") + encoded[1:]
    elif part == "signature-alphabet":
        signature = "G" + signature[1:]
    else:
        encoded += "="
    _denied(security, encoded + "." + signature, capability.csrf_token)


@pytest.mark.parametrize(
    "csrf", [None, True, b"not-text", _ForeignText("a" * 43), "a" * 31, "a" * 129, "+" * 43]
)
def test_csrf_requires_native_bounded_safe_matching_text(csrf):
    security = _security()
    _, cookie, _ = _bootstrap(security)
    _denied(security, cookie, csrf, status=403)


def test_matching_cookie_with_another_native_csrf_is_forbidden():
    security = _security()
    capability, cookie, _ = _bootstrap(security)
    other = ("a" if capability.csrf_token[0] != "a" else "b") + capability.csrf_token[1:]
    _denied(security, cookie, other, status=403)


@pytest.mark.parametrize(
    "changes",
    [
        {"account": "other-account"},
        {"account": None},
        {"account": True},
        {"purpose": METADATA_SESSION_PURPOSE},
        {"purpose": True},
        {"sub": "another-operator"},
        {"sub": None},
        {"scope": True},
        {"scope": "g" * 32},
        {"scope": "a" * 31},
        {"v": True},
        {"v": 2},
        {"iat": True},
        {"exp": True},
        {"csrf": None},
        {"csrf": "x" * 31},
        {"csrf": "x" * 129},
        {"csrf": "+" * 43},
    ],
)
def test_valid_signature_does_not_admit_wrong_native_or_scope_claims(changes):
    security = _security()
    capability, cookie, _ = _bootstrap(security)
    claims = {**_payload(cookie), **changes}
    _denied(security, _signed(security, claims), capability.csrf_token)


@pytest.mark.parametrize(
    "kind", ["scope", "future", "expiry-equality", "short-session", "long-session", "huge-time"]
)
def test_actual_signed_claims_reject_foreign_scope_and_time_windows(kind):
    security = _security()
    capability, cookie, _ = _bootstrap(security)
    claims = _payload(cookie)
    if kind == "scope":
        current = claims["scope"]
        claims["scope"] = ("0" if current[0] != "0" else "1") + current[1:]
    elif kind == "future":
        claims["iat"] += 1
        claims["exp"] += 1
    elif kind == "expiry-equality":
        claims["exp"] = claims["iat"]
        claims["iat"] -= 28800
    elif kind == "short-session":
        claims["exp"] -= 1
    elif kind == "long-session":
        claims["exp"] += 1
    else:
        claims["iat"] = 2**62
        claims["exp"] = 2**62 + 28800
    _denied(security, _signed(security, claims), capability.csrf_token)


@pytest.mark.parametrize(
    "kind", ["missing", "extra", "array", "whitespace", "duplicate", "utf8", "empty"]
)
def test_signed_structure_and_noncanonical_json_do_not_reach_authentication(kind):
    security = _security()
    capability, cookie, _ = _bootstrap(security)
    claims = _payload(cookie)
    canonical = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode()
    if kind == "missing":
        del claims["account"]
        raw = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode()
    elif kind == "extra":
        raw = canonical[:-1] + b',"authority":true}'
    elif kind == "array":
        raw = b"[]"
    elif kind == "whitespace":
        raw = b" " + canonical
    elif kind == "duplicate":
        raw = b'{"v":1,' + canonical[1:]
    elif kind == "utf8":
        raw = b"\xff"
    else:
        raw = b""
    _denied(security, _signed(security, raw=raw), capability.csrf_token)


def test_noncanonical_base64_is_rejected_even_when_it_decodes_to_valid_claims():
    security = _security()
    _, cookie, _ = _bootstrap(security)
    claims = _payload(cookie)
    raw = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode()
    if len(raw) % 3 == 0:
        claims["csrf"] += "a"
        raw = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode()
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=")
    canonical = _signed_encoded(security, encoded)
    assert security.authenticate(canonical, claims["csrf"], now=NOW) == OWNER
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = alphabet.index(encoded[-1])
    changed = encoded[:-1] + bytes((alphabet[last + 1],))
    assert base64.urlsafe_b64decode(changed + b"=" * (-len(changed) % 4)) == raw
    _denied(security, _signed_encoded(security, changed), claims["csrf"])


@pytest.mark.parametrize(
    "changes",
    [
        {"enabled": 1},
        {"transport_is_loopback_scoped": 1},
        {"transport_is_loopback_scoped": False},
        {"operator_id": ""},
        {"operator_id": " owner"},
        {"operator_id": "owner\nname"},
        {"operator_id": "a" * 129},
        {"operator_id": "\ud800"},
        {"configured_secret": b"not-text"},
        {"configured_secret": "\ud800"},
    ],
)
def test_invalid_configuration_rejects_native_bounds_and_utf8(changes):
    with pytest.raises(ValueError):
        _configuration(**changes)


@pytest.mark.parametrize(
    "account", [None, True, 1, "", " padded ", "a" * 129, "\ud800", _ForeignText("account")]
)
def test_invalid_account_is_rejected_before_a_scope_is_opened(account):
    with pytest.raises(ValueError):
        _security(account=account)


def test_mutated_configuration_is_revalidated_before_security_copies_it():
    configuration = _configuration()
    object.__setattr__(configuration, "enabled", 1)
    with pytest.raises(ValueError, match="exact booleans"):
        _security(configuration=configuration)
    with pytest.raises(ValueError, match="exact continuous read configuration"):
        ContinuousReadAccessSecurity(configuration=object(), account_id=ACCOUNT)


@pytest.mark.parametrize(
    "at",
    [
        None,
        True,
        "2026-10-28",
        datetime(2026, 10, 28),
        datetime(2026, 10, 28, tzinfo=timezone(timedelta(hours=1))),
    ],
)
def test_invalid_authentication_utc_cannot_issue_or_authenticate(at):
    security = _security()
    capability, cookie, _ = _bootstrap(security)
    response = Response()
    with pytest.raises(HTTPException) as raised:
        _bootstrap(security, at=at, response=response)
    assert raised.value.status_code == 503 and "set-cookie" not in response.headers
    _denied(security, cookie, capability.csrf_token, status=503, at=at)


def test_unrepresentable_expiry_sets_no_cookie():
    security = _security()
    response = Response()
    with pytest.raises(HTTPException) as raised:
        _bootstrap(security, at=datetime.max.replace(tzinfo=UTC), response=response)
    assert raised.value.status_code == 503 and "set-cookie" not in response.headers
    assert all(response.headers[key] == value for key, value in _CACHE.items())


def test_maximum_original_account_and_unicode_operator_issue_exact_2045_byte_cookie():
    # journal_identifier permits these128 non-whitespace control characters;
    # JSON must escape each as six bytes. Each operator scalar takes four UTF-8
    # bytes, and both epoch claims use twelve digits at this representable date.
    security = _security(account="\x01" * 128, operator_id="\U0001f600" * 128)
    at = datetime(9999, 12, 30, tzinfo=UTC)
    capability, cookie, _ = _bootstrap(security, at=at)
    assert len(cookie) == len(cookie.encode("ascii")) == 2045
    assert len(cookie) <= 2048
    assert capability.account_id == "\x01" * 128
    assert capability.operator_id == "\U0001f600" * 128
    assert capability.expires_at == at + timedelta(hours=8)
    assert security.authenticate(cookie, capability.csrf_token, now=at) == "\U0001f600" * 128
    assert _payload(cookie)["account"] == capability.account_id


def test_bootstrap_and_close_delete_only_the_new_cookie_and_old_issuers_preserve_it():
    security = _security()
    response = Response()
    response.set_cookie(LOCAL_SESSION_COOKIE, "synthetic-shared-cookie", path="/api/v1")
    response.set_cookie(METADATA_SESSION_COOKIE, "synthetic-metadata-cookie", path="/api/v1")
    _, cookie, issued = _bootstrap(security, response=response)
    cookies = _cookies(issued)
    assert cookies[LOCAL_SESSION_COOKIE].value == "synthetic-shared-cookie"
    assert cookies[METADATA_SESSION_COOKIE].value == "synthetic-metadata-cookie"
    assert cookies[CONTINUOUS_READ_SESSION_COOKIE].value == cookie
    security.close()
    removed = Response()
    removed.set_cookie(LOCAL_SESSION_COOKIE, "synthetic-shared-cookie", path="/api/v1")
    removed.set_cookie(METADATA_SESSION_COOKIE, "synthetic-metadata-cookie", path="/api/v1")
    disabled, _, _ = _bootstrap(security, cookie=cookie, response=removed)
    assert disabled.enabled is False and removed is not issued
    cookies = _cookies(removed)
    assert cookies[LOCAL_SESSION_COOKIE].value == "synthetic-shared-cookie"
    assert cookies[METADATA_SESSION_COOKIE].value == "synthetic-metadata-cookie"
    assert cookies[CONTINUOUS_READ_SESSION_COOKIE]["max-age"] == "0"
    for metadata in (False, True):
        legacy, _, _ = _legacy(metadata=metadata)
        preserved = Response()
        preserved.set_cookie(CONTINUOUS_READ_SESSION_COOKIE, cookie, path="/api/v1")
        arguments = {"issued_at": NOW, "session_cookie": None}
        if not metadata:
            arguments["persistence_ready"] = False
        legacy.bootstrap_capability(preserved, **arguments)
        assert _cookies(preserved)[CONTINUOUS_READ_SESSION_COOKIE].value == cookie
    # Closing new scope is not allowed to invalidate either old independent key.
    shared, shared_cookie, shared_csrf = _legacy()
    metadata, metadata_cookie, metadata_csrf = _legacy(metadata=True)
    assert shared.authenticate(shared_cookie, shared_csrf, now=NOW) == OWNER
    assert metadata.authenticate(metadata_cookie, metadata_csrf, now=NOW) == OWNER
