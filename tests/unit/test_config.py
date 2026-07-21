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
        broker_secret_ref="secret://paper/broker",
        market_data_secret_ref="secret://paper/data",
    )

    with pytest.raises(ValueError, match="LiveCredentialRefs"):
        Settings(
            environment=Environment.LIVE,
            local_auth_enabled=False,
            session_secret="non-placeholder-secret",
            credentials=paper_credentials,
        )


def test_live_secret_references_must_be_live_scoped() -> None:
    with pytest.raises(ValueError, match="live-scoped"):
        LiveCredentialRefs(
            account_id="live-account",
            broker_secret_ref="secret://paper/broker",
            market_data_secret_ref="secret://live/data",
            promotion_record_id="promotion-001",
        )
