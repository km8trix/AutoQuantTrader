import pytest

from apps.api.backtest_views import LocalOperatorSecurity
from apps.api.config import (
    Environment,
    LiveCredentialRefs,
    LocalCredentials,
    PaperCredentialRefs,
    Settings,
)


def test_local_operator_identity_is_bounded_and_cors_cannot_be_wildcarded() -> None:
    with pytest.raises(ValueError, match="operator ID"):
        LocalCredentials(operator_id=" untrimmed ")
    with pytest.raises(ValueError, match="wildcard CORS"):
        Settings(cors_origins=("*",))


def test_local_capability_requires_a_loopback_transport_boundary() -> None:
    with pytest.raises(ValueError, match="loopback API bind"):
        Settings(api_host="192.0.2.10")
    with pytest.raises(ValueError, match="loopback HTTP CORS"):
        Settings(cors_origins=("https://research.example",))
    with pytest.raises(ValueError, match="wildcard container bind"):
        Settings(api_host="127.0.0.1", trusted_loopback_proxy=True)

    proxied = Settings(api_host="0.0.0.0", trusted_loopback_proxy=True)
    assert proxied.local_auth_transport_is_loopback_scoped is True
    with pytest.raises(ValueError, match="loopback-scoped transport"):
        LocalOperatorSecurity(
            enabled=True,
            transport_is_loopback_scoped=False,
            operator_id="local-operator",
            configured_secret="test-secret",
        )


def test_local_auth_is_rejected_outside_local() -> None:
    with pytest.raises(ValueError, match="local authentication"):
        Settings(
            environment=Environment.PAPER,
            local_auth_enabled=True,
            session_secret="a-real-paper-secret",
        )


def test_non_local_environment_requires_session_secret() -> None:
    with pytest.raises(ValueError, match="session secret"):
        Settings(environment=Environment.LIVE, local_auth_enabled=False)


def test_paper_credentials_cannot_be_reused_for_live() -> None:
    paper_credentials = PaperCredentialRefs(
        account_id="paper-account",
        expected_provider_account_id="11111111-1111-4111-8111-111111111111",
        broker_secret_ref="secret://paper/broker",
        broker_secret_version="version-1",
        market_data_secret_ref="secret://paper/data",
    )

    with pytest.raises(ValueError, match="LiveCredentialRefs"):
        Settings(
            environment=Environment.LIVE,
            local_auth_enabled=False,
            session_secret="non-placeholder-secret",
            credentials=paper_credentials,
        )


def test_paper_credentials_compose_an_exact_nonsecret_account_reference() -> None:
    credentials = PaperCredentialRefs(
        account_id="paper-account",
        expected_provider_account_id="11111111-1111-4111-8111-111111111111",
        broker_secret_ref="secret://paper/alpaca/account",
        broker_secret_version="version-7",
        market_data_secret_ref="secret://paper/data",
    )

    reference = credentials.alpaca_paper_account_reference

    assert reference.account_id == "paper-account"
    assert reference.expected_provider_account_id == "11111111-1111-4111-8111-111111111111"
    assert reference.secret_ref == "secret://paper/alpaca/account"
    assert reference.secret_version == "version-7"
    assert reference.credential_values_present is False
    assert reference.transport_authorized is False
    assert reference.trading_effect_authorized is False


@pytest.mark.parametrize(
    ("provider_account_id", "secret_ref", "secret_version", "message"),
    [
        ("not-a-uuid", "secret://paper/broker", "version-1", "canonical UUID"),
        (
            "11111111-1111-4111-8111-111111111111",
            "secret://live/broker",
            "version-1",
            "paper-scoped",
        ),
        (
            "11111111-1111-4111-8111-111111111111",
            "secret://paper/broker",
            "version with spaces",
            "safe-text",
        ),
    ],
)
def test_paper_account_reference_rejects_unpinned_or_unsafe_configuration(
    provider_account_id: str,
    secret_ref: str,
    secret_version: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        PaperCredentialRefs(
            account_id="paper-account",
            expected_provider_account_id=provider_account_id,
            broker_secret_ref=secret_ref,
            broker_secret_version=secret_version,
            market_data_secret_ref="secret://paper/data",
        )


def test_paper_account_reference_is_loaded_from_nonsecret_environment_pins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AQT_ENVIRONMENT", "paper")
    monkeypatch.setenv("AQT_LOCAL_AUTH_ENABLED", "false")
    monkeypatch.setenv("AQT_SESSION_SECRET", "non-placeholder-secret")
    monkeypatch.setenv("AQT_PAPER_ACCOUNT_ID", "paper-account")
    monkeypatch.setenv(
        "AQT_PAPER_PROVIDER_ACCOUNT_ID",
        "11111111-1111-4111-8111-111111111111",
    )
    monkeypatch.setenv("AQT_PAPER_BROKER_SECRET_REF", "secret://paper/alpaca/account")
    monkeypatch.setenv("AQT_PAPER_BROKER_SECRET_VERSION", "version-7")
    monkeypatch.setenv("AQT_PAPER_DATA_SECRET_REF", "secret://paper/data")

    settings = Settings.from_env()

    assert type(settings.credentials) is PaperCredentialRefs
    assert settings.credentials.alpaca_paper_account_reference.secret_version == "version-7"


def test_live_secret_references_must_be_live_scoped() -> None:
    with pytest.raises(ValueError, match="live-scoped"):
        LiveCredentialRefs(
            account_id="live-account",
            broker_secret_ref="secret://paper/broker",
            market_data_secret_ref="secret://live/data",
            promotion_record_id="promotion-001",
        )
