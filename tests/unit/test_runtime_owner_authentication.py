"""Actual local session validation, without issuing a runtime assignment."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie

import pytest
from fastapi import HTTPException, Response

from apps.api.backtest_views import LOCAL_SESSION_COOKIE, LocalOperatorSecurity
from apps.api.runtime_owner_authentication import LocalRuntimeOwnerAuthenticator
from packages.application import personal_codec
from packages.application.runtime_owner_authentication import AuthenticatedRuntimeOwnerCommand
from packages.domain.reconciliation_contracts import ReconciliationHeads
from packages.domain.runtime_owner_contracts import RuntimeOwnerAuthentication
from packages.persistence.daily_runtime_risk import RuntimeAssignmentCommand

NOW = datetime(2023, 1, 5, 14, 35, tzinfo=UTC)


def _session(*, enabled=True, issued_at=NOW):
    security = LocalOperatorSecurity(
        enabled=enabled,
        transport_is_loopback_scoped=True,
        operator_id="simulation-owner",
        configured_secret="unit-test-only",
    )
    response = Response()
    capability = security.bootstrap_capability(
        response, persistence_ready=True, issued_at=issued_at, session_cookie=None
    )
    cookies = SimpleCookie()
    cookies.load(response.headers["set-cookie"])
    return security, cookies[LOCAL_SESSION_COOKIE].value, capability.csrf_token or "missing"


def _command(*, at=NOW, expires=None):
    return RuntimeAssignmentCommand(
        command_id="simulation-assignment-request",
        owner_id="simulation-owner",
        account_id="continuous-account",
        before_assignment_sha256=None,
        after_assignment_sha256="a" * 64,
        expected_heads=ReconciliationHeads("b" * 64, "c" * 64, "d" * 64, 0, "e" * 64, 0, 1),
        quiescence_sha256="f" * 64,
        requested_at=at,
        expires_at=expires or at + timedelta(seconds=60),
    )


def test_actual_session_binds_exact_command_and_retains_no_credentials():
    security, cookie, csrf = _session()
    authority = LocalRuntimeOwnerAuthenticator(security)
    command = _command()
    authenticated = authority.authenticate(command, session_cookie=cookie, csrf_token=csrf, now=NOW)
    authority.require_authenticated(authenticated)
    record = authenticated.authentication
    assert record.command_sha256 == command.semantic_sha256
    assert record.session_expires_at == NOW + timedelta(hours=8)
    assert record.command_expires_at == NOW + timedelta(seconds=60)
    payload = personal_codec.encode_record(record)
    assert personal_codec.decode_record(payload, RuntimeOwnerAuthentication) == record
    assert cookie.encode() not in payload and csrf.encode() not in payload
    assert security.authenticate(cookie, csrf, now=NOW) == command.owner_id


@pytest.mark.parametrize(
    "kind", ["missing", "changed_cookie", "csrf", "restart", "disabled", "expired"]
)
def test_actual_invalid_session_cannot_issue_owner_authentication(kind):
    security, cookie, csrf = _session(enabled=kind != "disabled")
    at = NOW
    if kind == "missing":
        cookie = None
    elif kind == "changed_cookie":
        cookie += "x"
    elif kind == "csrf":
        csrf = "different"
    elif kind == "restart":
        security = _session()[0]
    elif kind == "expired":
        at += timedelta(hours=8)
    authority = LocalRuntimeOwnerAuthenticator(security)
    with pytest.raises(HTTPException):
        authority.authenticate(_command(at=at), session_cookie=cookie, csrf_token=csrf, now=at)


@pytest.mark.parametrize("kind", ["owner", "time", "long", "session_expiry"])
def test_authenticated_session_does_not_authorize_changed_command_scope_or_time(kind):
    security, cookie, csrf = _session()
    authority = LocalRuntimeOwnerAuthenticator(security)
    command, at = _command(), NOW
    if kind == "owner":
        command = replace(command, owner_id="different-owner")
    elif kind == "time":
        at += timedelta(microseconds=1)
    elif kind == "long":
        command = replace(command, expires_at=NOW + timedelta(seconds=61))
    else:
        at = NOW + timedelta(hours=8, seconds=-30)
        command = _command(at=at)
    with pytest.raises(ValueError):
        authority.authenticate(command, session_cookie=cookie, csrf_token=csrf, now=at)


@pytest.mark.parametrize("kind", ["clone", "foreign", "replaced_record", "nested_mutation"])
def test_only_issued_original_authentication_content_is_accepted(kind):
    security, cookie, csrf = _session()
    authority = LocalRuntimeOwnerAuthenticator(security)
    value = authority.authenticate(_command(), session_cookie=cookie, csrf_token=csrf, now=NOW)
    if kind == "clone":
        value = AuthenticatedRuntimeOwnerCommand(value.authentication, value.seal)
    elif kind == "foreign":
        authority = LocalRuntimeOwnerAuthenticator(security)
    elif kind == "replaced_record":
        object.__setattr__(value, "authentication", replace(value.authentication))
    else:
        object.__setattr__(value.authentication, "command_sha256", "a" * 64)
    with pytest.raises(ValueError, match="original local authentication"):
        authority.require_authenticated(value)
