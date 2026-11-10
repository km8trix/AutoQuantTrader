from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from packages.adapters.broker.etrade import ETRADE_SANDBOX_ENDPOINT_PROFILE, EtradeEnvironment
from packages.adapters.broker.etrade_oauth import (
    EtradeOAuthConsumerCredentials,
    EtradeOAuthConsumerKey,
    EtradeOAuthConsumerSecret,
    EtradeOAuthNonce,
    EtradeOAuthOperation,
    EtradeOAuthReplayGuard,
    EtradeOAuthToken,
    EtradeOAuthTokenCredentials,
    EtradeOAuthTokenSecret,
    EtradeOAuthTrustedTimestamp,
    create_etrade_oauth_signing_intent,
    sign_etrade_oauth_intent,
)
from packages.adapters.broker.etrade_owner_oauth import _header
from packages.adapters.broker.etrade_owner_renewal import renew_owner_session
from packages.adapters.broker.etrade_readonly import (
    EnvFileEtradeCredentialStore,
    EtradeReadError,
    EtradeSecretReference,
)
from scripts.renew_etrade_session import main

ISSUED = datetime(2026, 9, 9, 11, 38, tzinfo=UTC)
NOW = datetime(2026, 9, 9, 21, 25, tzinfo=UTC)
MIDNIGHT = datetime(2026, 9, 10, 4, tzinfo=UTC)
SUCCESS = b"Access Token has been renewed"


def reference(
    tmp_path: Path,
    environment: EtradeEnvironment = EtradeEnvironment.SANDBOX,
    *,
    expires: datetime = MIDNIGHT,
) -> EtradeSecretReference:
    source = tmp_path / "fixture-original-session.env"
    source.write_text(
        "".join(
            f"{prefix}{name}='{value}'\n"
            for prefix, label in (("ETRADE_SANDBOX_", "sandbox"), ("ETRADE_PROD_", "production"))
            for name, value in {
                "CONSUMER_KEY": label + "-key",
                "CONSUMER_SECRET": label + "-secret",
                "ACCESS_TOKEN": label + "/token=",
                "ACCESS_SECRET": label + "+access-secret",
                "TOKEN_ISSUED_AT": ISSUED.isoformat(),
                "TOKEN_LAST_ACTIVITY_AT": ISSUED.isoformat(),
                "TOKEN_EXPIRES_AT": expires.isoformat(),
            }.items()
        )
    )
    source.chmod(0o600)
    return EtradeSecretReference(environment, f"envfile://{source}?version=1")


def flow(
    tmp_path: Path,
    *,
    environment: EtradeEnvironment = EtradeEnvironment.SANDBOX,
    expires: datetime = MIDNIGHT,
    body: Any = SUCCESS,
    times: list[datetime] | None = None,
    monos: list[float] | None = None,
    **overrides: Any,
) -> tuple[dict[str, object], list[Any], Path]:
    selected = reference(tmp_path, environment, expires=expires)
    output = tmp_path / "new-renewed-session.env"
    calls: list[Any] = []
    instants = iter(times or [NOW, NOW + timedelta(seconds=1)])
    elapsed = iter(monos or [0.0, 1.0])

    def exchange(operation: EtradeOAuthOperation, authorization: str) -> bytes:
        assert output.stat().st_mode & 0o777 == 0o600
        assert "RENEWAL_DISPATCHING" in output.read_text()
        calls.append((operation, authorization))
        return body

    result = renew_owner_session(
        **{
            "reference": selected,
            "output": output,
            "authorize_renew": True,
            "exchange": exchange,
            "now": lambda: next(instants),
            "monotonic": lambda: next(elapsed),
            "nonce": lambda: "fixture-renewal-nonce-0001",
            **overrides,
        }
    )
    return result, calls, output


@pytest.mark.parametrize("environment", list(EtradeEnvironment))
@pytest.mark.parametrize(
    "expires", [MIDNIGHT, MIDNIGHT - timedelta(hours=1), MIDNIGHT + timedelta(hours=1)]
)
def test_renewal_preserves_token_issuance_source_and_expiry_with_environment_isolation(
    tmp_path: Path, environment: EtradeEnvironment, expires: datetime
) -> None:
    original_ref = reference(tmp_path, environment, expires=expires)
    original = (tmp_path / "fixture-original-session.env").read_bytes()
    result, calls, output = flow(
        tmp_path, environment=environment, expires=expires, body=b" \r\n" + SUCCESS + b"\t\n"
    )
    assert [call[0] for call in calls] == [EtradeOAuthOperation.RENEW_ACCESS_TOKEN]
    assert "oauth_verifier" not in calls[0][1] and "oauth_callback" not in calls[0][1]
    assert (tmp_path / "fixture-original-session.env").read_bytes() == original
    before = EnvFileEtradeCredentialStore().resolve(original_ref)
    after = EnvFileEtradeCredentialStore().resolve(
        EtradeSecretReference(environment, str(result["session_reference"]))
    )
    try:
        assert before.issued_at == after.issued_at == ISSUED
        assert after.last_activity_at == NOW
        assert after.expires_at == min(expires, MIDNIGHT)
        for name in ("consumer_key", "consumer_secret", "access_token", "access_secret"):
            assert before._value(name) == after._value(name)
        public = json.dumps(result)
        assert all(
            before._value(name) not in public
            for name in ("consumer_key", "consumer_secret", "access_token", "access_secret")
        )
    finally:
        before.close()
        after.close()
    foreign = "ETRADE_PROD_" if environment is EtradeEnvironment.SANDBOX else "ETRADE_SANDBOX_"
    assert foreign not in output.read_text()
    assert "local_renewal_request_start" in output.read_text()
    assert result["renewal_response_received_at"] == (NOW + timedelta(seconds=1)).isoformat()
    assert result["token_rotated"] is False and result["provider_token_requests"] == 1
    assert result["account_requests"] == 0 and result["trading_authorized"] is False


def test_renewal_header_matches_existing_pure_signer_without_authority_changes(
    tmp_path: Path,
) -> None:
    selected = reference(tmp_path)
    nonce = EtradeOAuthNonce("fixture-renewal-nonce-0001")
    intent = create_etrade_oauth_signing_intent(
        environment=selected.environment,
        endpoint_profile=ETRADE_SANDBOX_ENDPOINT_PROFILE,
        operation=EtradeOAuthOperation.RENEW_ACCESS_TOKEN,
        generation=1,
        consumer_reference=selected.consumer_reference,
        token_reference=selected.token_reference,
        timestamp=EtradeOAuthTrustedTimestamp(int(NOW.timestamp()), "a" * 64),
        nonce=nonce,
    )
    signed = sign_etrade_oauth_intent(
        intent,
        replay_guard=EtradeOAuthReplayGuard(),
        consumer_credentials=EtradeOAuthConsumerCredentials(
            reference=selected.consumer_reference,
            consumer_key=EtradeOAuthConsumerKey("sandbox-key"),
            consumer_secret=EtradeOAuthConsumerSecret("sandbox-secret"),
        ),
        token_credentials=EtradeOAuthTokenCredentials(
            reference=selected.token_reference,
            token=EtradeOAuthToken("sandbox/token="),
            token_secret=EtradeOAuthTokenSecret("sandbox+access-secret"),
        ),
    )
    assert signed.authorization_header_matches(
        _header(
            EtradeOAuthOperation.RENEW_ACCESS_TOKEN,
            "sandbox-key",
            "sandbox-secret",
            NOW,
            nonce.value,
            "sandbox/token=",
            "sandbox+access-secret",
        )
    )
    assert all(value is False for value in signed.authority.values())
    with pytest.raises(EtradeReadError, match="VERIFIER_UNSUPPORTED"):
        _header(
            EtradeOAuthOperation.RENEW_ACCESS_TOKEN,
            "key",
            "secret",
            NOW,
            nonce.value,
            "token",
            "token-secret",
            "verifier",
        )


@pytest.mark.parametrize(
    "start", [MIDNIGHT, MIDNIGHT + timedelta(seconds=1), ISSUED - timedelta(seconds=1)]
)
def test_expired_or_future_session_has_no_provider_effects(tmp_path: Path, start: datetime) -> None:
    with pytest.raises(EtradeReadError, match=r"REAUTHORIZATION|METADATA_FUTURE"):
        flow(
            tmp_path, times=[start], exchange=lambda *args: pytest.fail("unexpected provider call")
        )
    assert "ETRADE_" not in (tmp_path / "new-renewed-session.env").read_text()


@pytest.mark.parametrize(
    "times,monos",
    [
        ([MIDNIGHT - timedelta(seconds=1), MIDNIGHT], [0.0, 1.0]),
        ([NOW, NOW + timedelta(seconds=3)], [0.0, 3.0]),
        ([NOW, NOW + timedelta(seconds=2)], [0.0, 1.0]),
        ([NOW, NOW - timedelta(milliseconds=1)], [0.0, 0.0]),
        ([NOW, NOW], [1.0, 0.0]),
    ],
)
def test_midnight_deadline_clock_jump_and_regression_never_publish(
    tmp_path: Path, times: list[datetime], monos: list[float]
) -> None:
    with pytest.raises(EtradeReadError, match="DEADLINE_EXPIRY_OR_CLOCK"):
        flow(tmp_path, times=times, monos=monos)
    assert "ETRADE_" not in (tmp_path / "new-renewed-session.env").read_text()


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"Access Token has been renewed!",
        b"<p>Access Token has been renewed</p>",
        SUCCESS + b" private-provider-detail",
        b" " * 257,
        "Access Token has been renewed",
    ],
)
def test_only_bounded_exact_success_body_can_publish(tmp_path: Path, body: Any) -> None:
    with pytest.raises(EtradeReadError, match="RESPONSE_REJECTED"):
        flow(tmp_path, body=body)
    saved = (tmp_path / "new-renewed-session.env").read_text()
    assert "ETRADE_" not in saved and "private-provider-detail" not in saved


@pytest.mark.parametrize(
    "failure_call,interrupt", [(1, False), (2, False), (3, False), (4, False), (3, True)]
)
def test_fsync_and_interrupt_failures_remove_any_written_credentials(
    tmp_path: Path, monkeypatch: Any, failure_call: int, interrupt: bool
) -> None:
    import packages.adapters.broker.etrade_owner_renewal as adapter

    original = adapter.os.fsync
    calls = 0

    def fail_once(fd: int) -> None:
        nonlocal calls
        calls += 1
        if calls == failure_call:
            raise KeyboardInterrupt if interrupt else OSError("fixture fsync failure")
        original(fd)

    monkeypatch.setattr(adapter.os, "fsync", fail_once)
    with pytest.raises(KeyboardInterrupt if interrupt else OSError):
        flow(tmp_path)
    saved = (tmp_path / "new-renewed-session.env").read_text()
    assert "STOPPED_REVIEW_BEFORE_NEW_ATTEMPT" in saved and "ETRADE_" not in saved


def test_partial_payload_write_is_truncated(tmp_path: Path, monkeypatch: Any) -> None:
    import packages.adapters.broker.etrade_owner_renewal as adapter

    original = adapter.os.write

    def partial(fd: int, body: bytes) -> int:
        if body.startswith(b"# lifecycle_basis="):
            return original(fd, body[: len(body) // 2])
        return original(fd, body)

    monkeypatch.setattr(adapter.os, "write", partial)
    with pytest.raises(OSError, match="short session write"):
        flow(tmp_path)
    assert "ETRADE_" not in (tmp_path / "new-renewed-session.env").read_text()


def test_existing_output_and_missing_authorization_stop_before_credentials(
    tmp_path: Path, monkeypatch: Any
) -> None:
    selected = reference(tmp_path)
    monkeypatch.setattr(
        EnvFileEtradeCredentialStore, "resolve", lambda *args: pytest.fail("unexpected secret read")
    )
    output = tmp_path / "preserve"
    output.write_text("unchanged")
    with pytest.raises(FileExistsError):
        renew_owner_session(reference=selected, output=output, authorize_renew=True)
    with pytest.raises(EtradeReadError, match="AUTHORIZATION_REQUIRED"):
        renew_owner_session(
            reference=selected, output=tmp_path / "not-created", authorize_renew=False
        )
    with pytest.raises(EtradeReadError, match="OUTSIDE_CHECKOUT"):
        renew_owner_session(reference=selected, output=Path("relative"), authorize_renew=True)
    assert output.read_text() == "unchanged" and not (tmp_path / "not-created").exists()


def test_cli_requires_explicit_flag_without_tty_and_redacts_failures(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    import scripts.renew_etrade_session as cli

    calls: list[object] = []

    def fail(**kwargs: Any) -> Any:
        calls.append(kwargs)
        raise RuntimeError("PRIVATE-TOKEN-RESPONSE-AND-URL")

    monkeypatch.setattr(cli, "renew_owner_session", fail)
    args = [
        "--environment",
        "sandbox",
        "--secret-reference",
        "envfile:///never-read?version=1",
        "--new-session-output",
        str(tmp_path / "never-created"),
    ]
    with pytest.raises(SystemExit):
        main(args)
    with pytest.raises(SystemExit) as result:
        main(["--help"])
    assert result.value.code == 0 and calls == []
    capsys.readouterr()
    assert main(["--authorize-renew", *args]) == 2
    assert len(calls) == 1
    output = capsys.readouterr()
    assert "PRIVATE-TOKEN-RESPONSE-AND-URL" not in output.out + output.err
    assert "RENEWAL_NOT_COMPLETED" in output.out
