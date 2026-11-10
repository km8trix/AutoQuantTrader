from __future__ import annotations

import io
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from packages.adapters.broker.etrade import ETRADE_SANDBOX_ENDPOINT_PROFILE, EtradeEnvironment
from packages.adapters.broker.etrade_oauth import (
    EtradeOAuthConsumerCredentials,
    EtradeOAuthConsumerKey,
    EtradeOAuthConsumerSecret,
    EtradeOAuthNonce,
    EtradeOAuthOperation,
    EtradeOAuthReplayGuard,
    EtradeOAuthTrustedTimestamp,
    create_etrade_oauth_signing_intent,
    sign_etrade_oauth_intent,
)
from packages.adapters.broker.etrade_owner_oauth import (
    _header,
    _parse_form,
    _signature,
    acquire_owner_session,
    open_authorization,
)
from packages.adapters.broker.etrade_readonly import (
    EnvFileEtradeCredentialStore,
    EtradeReadError,
    EtradeSecretReference,
)
from scripts.authorize_etrade_session import main

NOW = datetime(2026, 9, 9, 14, tzinfo=UTC)


def reference(
    tmp_path: Path, environment: EtradeEnvironment = EtradeEnvironment.SANDBOX
) -> EtradeSecretReference:
    source = tmp_path / "existing-consumers"
    source.write_text(
        "ETRADE_SANDBOX_CONSUMER_KEY=sandbox-key\nETRADE_SANDBOX_CONSUMER_SECRET=sandbox-secret\nETRADE_PROD_CONSUMER_KEY=production-key\nETRADE_PROD_CONSUMER_SECRET=production-secret\n"
    )
    return EtradeSecretReference(environment, f"envfile://{source}?version=1")


def flow(
    tmp_path: Path,
    *,
    environment: EtradeEnvironment = EtradeEnvironment.SANDBOX,
    times: list[datetime] | None = None,
    **overrides: Any,
) -> tuple[dict[str, object], list[Any], Path]:
    selected = reference(tmp_path, environment)
    output = tmp_path / "new-session.env"
    events: list[Any] = []
    instants = iter(
        times
        or [
            NOW,
            NOW + timedelta(seconds=1),
            NOW + timedelta(seconds=10),
            NOW + timedelta(seconds=11),
        ]
    )
    monos = iter([0.0, 1.0, 10.0, 11.0])
    nonces = iter(["fixture-first-nonce-0001", "fixture-second-nonce-0002"])

    def exchange(operation: EtradeOAuthOperation, authorization: str) -> bytes:
        events.append((operation, authorization))
        if operation is EtradeOAuthOperation.REQUEST_TOKEN:
            return (
                b"oauth_token=request%2Ftoken%3D&oauth_token_secret=request%2Bsecret"
                b"&oauth_callback_confirmed=false"
            )
        return b"oauth_token=access%2Ftoken%3D&oauth_token_secret=access%2Bsecret"

    def browser(url: str) -> bool:
        events.append(("browser", url))
        return True

    options = {
        "reference": selected,
        "output": output,
        "verifier_input": lambda: "fixture-verifier",
        "exchange": exchange,
        "browser": browser,
        "now": lambda: next(instants),
        "monotonic": lambda: next(monos),
        "nonce": lambda: next(nonces),
        **overrides,
    }
    result = acquire_owner_session(**options)
    return result, events, output


@pytest.mark.parametrize(
    "environment,prefix,foreign",
    [
        (EtradeEnvironment.SANDBOX, "ETRADE_SANDBOX_", "production"),
        (EtradeEnvironment.PRODUCTION, "ETRADE_PROD_", "sandbox"),
    ],
)
def test_owner_flow_is_environment_scoped_new_private_and_reader_compatible(
    tmp_path: Path, environment: EtradeEnvironment, prefix: str, foreign: str
) -> None:
    result, events, output = flow(tmp_path, environment=environment)
    assert [event[0] for event in events] == [
        EtradeOAuthOperation.REQUEST_TOKEN,
        "browser",
        EtradeOAuthOperation.ACCESS_TOKEN,
    ]
    assert output.stat().st_mode & 0o777 == 0o600
    content = output.read_text()
    assert prefix + "ACCESS_TOKEN='access/token='" in content
    assert foreign + "-secret" not in content
    assert "fixture-verifier" not in content
    assert "request/token" not in content
    assert "local_access_request_start_conservative" in content
    assert (
        "ETRADE_SANDBOX_CONSUMER_KEY=sandbox-key" in (tmp_path / "existing-consumers").read_text()
    )
    session_reference = EtradeSecretReference(environment, str(result["session_reference"]))
    credentials = EnvFileEtradeCredentialStore().resolve(session_reference)
    assert credentials.issued_at == NOW + timedelta(seconds=10)
    assert credentials.last_activity_at == NOW + timedelta(seconds=10)
    assert credentials.expires_at == datetime(2026, 9, 10, 4, tzinfo=UTC)
    credentials.close()
    public = json.dumps(result)
    for private in (
        "sandbox-key",
        "production-key",
        "access/token",
        "request/token",
        "fixture-verifier",
        "Authorization",
    ):
        assert private not in public
    assert result["provider_token_requests"] == 2
    assert result["account_requests"] == 0
    browser_query = parse_qs(urlsplit(events[1][1]).query)
    assert browser_query["key"] == [
        "sandbox-key" if environment is EtradeEnvironment.SANDBOX else "production-key"
    ]
    assert browser_query["token"] == ["request/token="]


def test_request_signing_matches_existing_pure_oauth_helper(tmp_path: Path) -> None:
    selected = reference(tmp_path)
    nonce = EtradeOAuthNonce("fixture-request-nonce-0001")
    timestamp = EtradeOAuthTrustedTimestamp(int(NOW.timestamp()), "a" * 64)
    intent = create_etrade_oauth_signing_intent(
        environment=selected.environment,
        endpoint_profile=ETRADE_SANDBOX_ENDPOINT_PROFILE,
        operation=EtradeOAuthOperation.REQUEST_TOKEN,
        generation=1,
        consumer_reference=selected.consumer_reference,
        token_reference=None,
        timestamp=timestamp,
        nonce=nonce,
    )
    credentials = EtradeOAuthConsumerCredentials(
        reference=selected.consumer_reference,
        consumer_key=EtradeOAuthConsumerKey("sandbox-key"),
        consumer_secret=EtradeOAuthConsumerSecret("sandbox-secret"),
    )
    signed = sign_etrade_oauth_intent(
        intent, replay_guard=EtradeOAuthReplayGuard(), consumer_credentials=credentials
    )
    assert signed.authorization_header_matches(
        _header(
            EtradeOAuthOperation.REQUEST_TOKEN, "sandbox-key", "sandbox-secret", NOW, nonce.value
        )
    )
    assert all(value is False for value in signed.authority.values())


def test_signature_matches_official_published_vector() -> None:
    # Nonsecret mathematically checked example in the E*TRADE developer guide.
    signature = _signature(
        "https://api.etrade.com/v1/accounts/list",
        [
            ("oauth_consumer_key", "c5bb4dcb7bd6826c7c4340df3f791188"),
            ("oauth_token", "VbiNYl63EejjlKdQM6FeENzcnrLACrZ2JYD6NQROfVI="),
            ("oauth_timestamp", "1344885636"),
            ("oauth_nonce", "0bba225a40d1bbac2430aa0c6163ce44"),
            ("oauth_signature_method", "HMAC-SHA1"),
        ],
        "7d30246211192cda43ede3abd9b393b9",
        "XCF9RzyQr4UEPloA+WlC06BnTfYC1P0Fwr3GUw/B0Es=",
    )
    assert signature == "UOnPVdzExTAgHkcGWLLfeTaaMSM="


@pytest.mark.parametrize(
    "body",
    [
        b"oauth_token=a&oauth_token=a&oauth_token_secret=b",
        b"oauth_token=%ZZ&oauth_token_secret=b",
        b"oauth_token=&oauth_token_secret=b",
        b"oauth_token=a&oauth_token_secret=b&unexpected=c",
        b"oauth_token=a&oauth_token_secret=%0Asecret",
        b"oauth_token=a&oauth_token_secret=%24shell",
        b"oauth_token=a&oauth_token_secret=b&oauth_callback_confirmed=true",
    ],
)
def test_access_token_parser_rejects_malformed_unknown_or_unroundtrippable_values(
    body: bytes,
) -> None:
    with pytest.raises(EtradeReadError, match="OAUTH_TOKEN_RESPONSE_REJECTED"):
        _parse_form(body, request_token=False)


@pytest.mark.parametrize("configured", [b"true", b"false"])
def test_request_token_callback_field_supports_documented_manual_oob(configured: bytes) -> None:
    assert _parse_form(
        b"oauth_token=a&oauth_token_secret=b&oauth_callback_confirmed=" + configured,
        request_token=True,
    ) == ("a", "b")


def test_existing_output_blocks_before_credentials_or_provider_effects(tmp_path: Path) -> None:
    selected = reference(tmp_path)
    output = tmp_path / "new-session.env"
    output.write_text("preserve")
    calls: list[str] = []
    with pytest.raises(FileExistsError):
        acquire_owner_session(
            reference=selected,
            output=output,
            verifier_input=lambda: calls.append("verifier") or "value",
        )
    assert calls == []
    assert output.read_text() == "preserve"


def test_symlink_output_cannot_overwrite_existing_file(tmp_path: Path) -> None:
    selected = reference(tmp_path)
    original = tmp_path / "keep"
    original.write_text("untouched")
    linked = tmp_path / "new-session.env"
    linked.symlink_to(original)
    with pytest.raises(FileExistsError):
        acquire_owner_session(reference=selected, output=linked, verifier_input=lambda: "unused")
    assert original.read_text() == "untouched"


def test_midnight_crossing_leaves_no_access_secret(tmp_path: Path) -> None:
    just_before = datetime(2026, 9, 10, 3, 59, 59, tzinfo=UTC)
    with pytest.raises(EtradeReadError, match="MIDNIGHT"):
        flow(
            tmp_path,
            times=[
                just_before - timedelta(seconds=10),
                just_before - timedelta(seconds=9),
                just_before,
                datetime(2026, 9, 10, 4, tzinfo=UTC),
            ],
        )
    content = (tmp_path / "new-session.env").read_text()
    assert "STOPPED_REVIEW_BEFORE_NEW_ATTEMPT" in content
    assert "ACCESS_TOKEN=" not in content
    assert "access+secret" not in content


def test_request_token_expiry_and_nonce_reuse_stop_before_access_exchange(tmp_path: Path) -> None:
    with pytest.raises(EtradeReadError, match="REQUEST_TOKEN_EXPIRED"):
        flow(tmp_path, monotonic=iter([0.0, 300.0]).__next__)
    assert "ACCESS_TOKEN_DISPATCHING" not in (tmp_path / "new-session.env").read_text()


def test_ambiguous_exchange_never_retries_or_saves_response(tmp_path: Path) -> None:
    calls: list[EtradeOAuthOperation] = []

    def exchange(operation: EtradeOAuthOperation, authorization: str) -> bytes:
        calls.append(operation)
        raise RuntimeError("secret-url-and-private-body")

    with pytest.raises(RuntimeError):
        flow(tmp_path, exchange=exchange)
    assert calls == [EtradeOAuthOperation.REQUEST_TOKEN]
    saved = (tmp_path / "new-session.env").read_text()
    assert "REQUEST_TOKEN_DISPATCHING" in saved
    assert "secret-url" not in saved


def test_cli_without_real_tty_has_zero_effects(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    import scripts.authorize_etrade_session as cli

    monkeypatch.setattr(cli.sys, "stdin", io.StringIO())
    monkeypatch.setattr(
        cli, "acquire_owner_session", lambda **kwargs: pytest.fail("unexpected effect")
    )
    output = tmp_path / "never-created"
    assert (
        main(
            [
                "--interactive",
                "--environment",
                "sandbox",
                "--consumer-reference",
                "envfile:///never-read?version=1",
                "--new-session-output",
                str(output),
            ]
        )
        == 2
    )
    assert "REAL_INTERACTIVE_TERMINAL_REQUIRED" in capsys.readouterr().out
    assert not output.exists()


def test_cli_help_and_invalid_arguments_do_not_resolve_or_open(
    tmp_path: Path, monkeypatch: Any
) -> None:
    import scripts.authorize_etrade_session as cli

    monkeypatch.setattr(
        cli, "acquire_owner_session", lambda **kwargs: pytest.fail("unexpected effect")
    )
    with pytest.raises(SystemExit) as help_result:
        main(["--help"])
    assert help_result.value.code == 0
    with pytest.raises(SystemExit):
        main(["--environment", "production"])


def test_cli_redacts_arbitrary_dependency_exception(monkeypatch: Any, capsys: Any) -> None:
    import scripts.authorize_etrade_session as cli

    class TTY(io.StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(cli.sys, "stdin", TTY())
    monkeypatch.setattr(cli.sys, "stderr", TTY())

    def fail(**kwargs: Any) -> Any:
        raise RuntimeError("SENSITIVE-KEY-TOKEN-VERIFIER")

    monkeypatch.setattr(cli, "acquire_owner_session", fail)
    assert (
        main(
            [
                "--interactive",
                "--environment",
                "sandbox",
                "--consumer-reference",
                "envfile:///never-read?version=1",
                "--new-session-output",
                "/private/tmp/never-created-by-this-test",
            ]
        )
        == 2
    )
    output = capsys.readouterr().out
    assert "SENSITIVE" not in output
    assert "OAUTH_NOT_COMPLETED" in output


def test_system_browser_opener_ignores_browser_override_and_suppresses_output(
    monkeypatch: Any,
) -> None:
    import packages.adapters.broker.etrade_owner_oauth as adapter

    calls: list[Any] = []

    class Result:
        returncode = 0

    def run(args: Any, **kwargs: Any) -> Result:
        calls.append((args, kwargs))
        return Result()

    monkeypatch.setenv("BROWSER", "untrusted-helper")
    monkeypatch.setattr(adapter.subprocess, "run", run)
    assert open_authorization("https://us.etrade.com/e/t/etws/authorize?key=fixture&token=fixture")
    arguments, options = calls[0]
    assert arguments[0] == "/usr/bin/open"
    assert options["env"] == {"PATH": "/usr/bin:/bin"}
    assert options["stdout"] == options["stderr"] == adapter.subprocess.DEVNULL
    assert "shell" not in options


@pytest.mark.parametrize("failure_call,interrupt", [(5, False), (6, False), (5, True)])
def test_catchable_publication_failure_truncates_credentials(
    tmp_path: Path, monkeypatch: Any, failure_call: int, interrupt: bool
) -> None:
    import packages.adapters.broker.etrade_owner_oauth as adapter

    actual = adapter.os.fsync
    calls = 0

    def fail_once(fd: int) -> None:
        nonlocal calls
        calls += 1
        if calls == failure_call:
            if interrupt:
                raise KeyboardInterrupt
            raise OSError("fixture storage failure")
        actual(fd)

    monkeypatch.setattr(adapter.os, "fsync", fail_once)
    with pytest.raises(KeyboardInterrupt if interrupt else OSError):
        flow(tmp_path)
    content = (tmp_path / "new-session.env").read_text()
    assert "STOPPED_REVIEW_BEFORE_NEW_ATTEMPT" in content
    assert "ETRADE_" not in content
    assert "access/token" not in content


def test_partial_payload_write_failure_truncates_credentials(
    tmp_path: Path, monkeypatch: Any
) -> None:
    import packages.adapters.broker.etrade_owner_oauth as adapter

    actual = adapter.os.write

    def partial(fd: int, body: bytes) -> int:
        if body.startswith(b"# lifecycle_basis="):
            actual(fd, body[: len(body) // 2])
            raise OSError("fixture partial write")
        return actual(fd, body)

    monkeypatch.setattr(adapter.os, "write", partial)
    with pytest.raises(OSError):
        flow(tmp_path)
    content = (tmp_path / "new-session.env").read_text()
    assert "ETRADE_" not in content
    assert "STOPPED_REVIEW_BEFORE_NEW_ATTEMPT" in content


def test_clock_divergence_during_access_exchange_blocks_publication(tmp_path: Path) -> None:
    with pytest.raises(EtradeReadError, match="ACCESS_DEADLINE_OR_CLOCK_CHANGED"):
        flow(
            tmp_path,
            times=[
                NOW,
                NOW + timedelta(seconds=1),
                NOW + timedelta(seconds=10),
                NOW + timedelta(seconds=12),
            ],
        )
    assert "ETRADE_" not in (tmp_path / "new-session.env").read_text()


def test_request_token_expiry_blocks_browser_and_verifier(tmp_path: Path) -> None:
    callbacks: list[str] = []
    with pytest.raises(EtradeReadError, match="REQUEST_TOKEN_EXPIRED"):
        flow(
            tmp_path,
            monotonic=iter([0.0, 300.0]).__next__,
            browser=lambda url: callbacks.append("browser") or True,
            verifier_input=lambda: callbacks.append("verifier") or "value",
        )
    assert callbacks == []


@pytest.mark.parametrize(
    "operation,path",
    [
        (EtradeOAuthOperation.REQUEST_TOKEN, "/oauth/request_token"),
        (EtradeOAuthOperation.ACCESS_TOKEN, "/oauth/access_token"),
        (EtradeOAuthOperation.RENEW_ACCESS_TOKEN, "/oauth/renew_access_token"),
    ],
)
def test_concrete_token_transport_uses_only_shared_fixed_get_endpoints(
    monkeypatch: Any, operation: EtradeOAuthOperation, path: str
) -> None:
    import packages.adapters.broker.etrade_owner_oauth as adapter

    events: list[Any] = []

    class Socket:
        def settimeout(self, value: float) -> None:
            assert 0 < value <= 3

        def connect(self, address: object) -> None:
            events.append(("connect", address))

        def shutdown(self, how: int) -> None:
            pass

        def close(self) -> None:
            pass

    class Context:
        def wrap_socket(self, raw: Socket, *, server_hostname: str) -> Socket:
            events.append(("tls", server_hostname))
            return raw

    class Response:
        status = 200

        def getheader(self, name: str, default: str) -> str:
            if operation is EtradeOAuthOperation.RENEW_ACCESS_TOKEN:
                return "text/html"
            return "application/x-www-form-urlencoded"

        def read(self, size: int) -> bytes:
            if operation is EtradeOAuthOperation.RENEW_ACCESS_TOKEN:
                assert size == 257
                return b" Access Token has been renewed\r\n"
            assert size == 16385
            return b"oauth_token=fixture&oauth_token_secret=fixture"

    class Connection:
        def __init__(self, host: str, **kwargs: Any) -> None:
            events.append(("host", host))
            self.sock: Any = None

        def request(self, method: str, target: str, *, headers: dict[str, str]) -> None:
            events.append((method, target, sorted(headers)))

        def getresponse(self) -> Response:
            self.sock = None
            return Response()

        def close(self) -> None:
            events.append("close")

    def resolve(host: str, output: Any) -> None:
        assert host == "api.etrade.com"
        output.put([(2, 1, 6, "", ("192.0.2.1", 443))])

    monkeypatch.setattr(adapter, "_resolve_hostname", resolve)
    monkeypatch.setattr(adapter.socket, "socket", lambda *args: Socket())
    monkeypatch.setattr(adapter.ssl, "create_default_context", Context)
    monkeypatch.setattr(adapter.http.client, "HTTPSConnection", Connection)
    result = adapter.exchange_token(operation, "OAuth fixture")
    if operation is EtradeOAuthOperation.RENEW_ACCESS_TOKEN:
        assert result.strip() == b"Access Token has been renewed"
    else:
        assert result.startswith(b"oauth_token=")
    assert ("host", "api.etrade.com") in events
    assert ("tls", "api.etrade.com") in events
    assert ("GET", path, ["Accept", "Authorization"]) in events
    assert events[-1] == "close"


def test_dns_failure_never_connects_or_sends_token_request(monkeypatch: Any) -> None:
    import packages.adapters.broker.etrade_owner_oauth as adapter

    monkeypatch.setattr(adapter, "_resolve_hostname", lambda host, output: output.put(None))
    monkeypatch.setattr(adapter.socket, "socket", lambda *args: pytest.fail("unexpected socket"))
    with pytest.raises(EtradeReadError, match="DNS_UNAVAILABLE_NO_REQUEST_SENT"):
        adapter.exchange_token(EtradeOAuthOperation.REQUEST_TOKEN, "OAuth fixture")


def test_hidden_verifier_never_falls_back_to_echo(monkeypatch: Any) -> None:
    import warnings

    import scripts.authorize_etrade_session as cli

    def unavailable(prompt: str) -> str:
        warnings.warn("echo unavailable", cli.getpass.GetPassWarning, stacklevel=1)
        pytest.fail("echo fallback must not run")

    monkeypatch.setattr(cli.getpass, "getpass", unavailable)
    with pytest.raises(cli.getpass.GetPassWarning):
        cli._verifier()
