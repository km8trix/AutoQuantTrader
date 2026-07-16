import pytest

from apps.api.config import (
    Environment,
    LiveCredentialRefs,
    PaperCredentialRefs,
    Settings,
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
