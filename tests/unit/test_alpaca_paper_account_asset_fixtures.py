from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from packages.adapters.broker.alpaca_paper_account_assets import (
    ALPACA_PAPER_ACCOUNT_ASSET_OBSERVATION_CONTRACT_VERSION,
    ALPACA_PAPER_ACCOUNT_ASSET_OBSERVATION_REVIEWED_ON,
    AlpacaAccountObservationOutcome,
    AlpacaAssetObservationOutcome,
    create_alpaca_account_observation_description,
    create_alpaca_asset_observation_description,
    decode_alpaca_account_observation_response,
    decode_alpaca_asset_observation_response,
)

FIXTURE_ROOT = Path(__file__).resolve().parents[2] / "tests/fixtures/broker/alpaca_paper"


def _fixture_bytes(name: str) -> bytes:
    return (FIXTURE_ROOT / name).read_bytes()


def _fixture_object(name: str) -> dict[str, Any]:
    value = json.loads(_fixture_bytes(name))
    assert type(value) is dict
    return value


def test_phase4e_manifest_truthfully_pins_synthetic_fixture_bytes() -> None:
    manifest = _fixture_object("account_asset_manifest.json")
    expected = {
        "account_active.json": {
            "provenance": "documentation_derived_synthetic",
            "sha256": "a2b852b7e80b8a0769e5947e5fbb8b9dc129bafac500854a9028150269b85a38",
        },
        "asset_not_found.json": {
            "provenance": "unqualified_synthetic_error_example",
            "sha256": "3f7286aaa0ba921dd6a6d5c4eac8185baedafd925aabe88a54934054dfc09dfe",
        },
        "asset_spy_active.json": {
            "provenance": "unqualified_synthetic_contract_example",
            "sha256": "0fffbd895857dd032928aee83f7bc3fda6b0b9e892e780c8340628153d38570f",
        },
    }

    assert manifest["contract_version"] == (ALPACA_PAPER_ACCOUNT_ASSET_OBSERVATION_CONTRACT_VERSION)
    assert manifest["reviewed_on"] == ALPACA_PAPER_ACCOUNT_ASSET_OBSERVATION_REVIEWED_ON
    assert manifest["fixtures"] == expected
    assert {name: hashlib.sha256(_fixture_bytes(name)).hexdigest() for name in expected} == {
        name: item["sha256"] for name, item in expected.items()
    }
    assert all("authenticated" not in item["provenance"] for item in expected.values())
    assert any("No fixture is an authenticated" in note for note in manifest["notes"])
    assert manifest["source_artifacts"] == {
        "alpaca_py_enums": {
            "commit": "bd1fa9ea2fc3194914be9d47f7f5822a18a05b5f",
            "sha256": "08a7d06d9ae6ce4ad6251c5628d74eaeef8d62a001784951dc24b90df0e5cc30",
        },
        "alpaca_py_models": {
            "commit": "bd1fa9ea2fc3194914be9d47f7f5822a18a05b5f",
            "sha256": "0a4296847ea46c434de3fe08ef6bb82519d9442705e59b4671127ffffad3855f",
        },
    }
    assert {
        "https://raw.githubusercontent.com/alpacahq/alpaca-py/"
        "bd1fa9ea2fc3194914be9d47f7f5822a18a05b5f/alpaca/trading/enums.py",
        "https://raw.githubusercontent.com/alpacahq/alpaca-py/"
        "bd1fa9ea2fc3194914be9d47f7f5822a18a05b5f/alpaca/trading/models.py",
    } <= set(manifest["sources"])


def test_phase4e_synthetic_fixtures_decode_but_never_become_runtime_evidence() -> None:
    account = decode_alpaca_account_observation_response(
        create_alpaca_account_observation_description(account_id="paper-account-fixture"),
        http_status=200,
        provider_request_id="synthetic-account-request",
        response_body=_fixture_bytes("account_active.json"),
        received_at=datetime(2026, 7, 27, 14, 30, tzinfo=UTC),
    )
    asset_description = create_alpaca_asset_observation_description(
        account_id="paper-account-fixture",
        instrument_id="US-ETF-SPY",
        symbol="SPY",
    )
    asset = decode_alpaca_asset_observation_response(
        asset_description,
        http_status=200,
        provider_request_id="synthetic-asset-request",
        response_body=_fixture_bytes("asset_spy_active.json"),
        received_at=account.received_at,
    )
    not_found = decode_alpaca_asset_observation_response(
        asset_description,
        http_status=404,
        provider_request_id="synthetic-asset-not-found-request",
        response_body=_fixture_bytes("asset_not_found.json"),
        received_at=account.received_at,
    )

    assert account.outcome is AlpacaAccountObservationOutcome.OBSERVED_USABLE_CANDIDATE
    assert asset.outcome is AlpacaAssetObservationOutcome.OBSERVED_USABLE_CANDIDATE
    assert not_found.outcome is AlpacaAssetObservationOutcome.NOT_VISIBLE_INCONCLUSIVE
    assert account.runtime_current is asset.runtime_current is not_found.runtime_current is False
    assert account.authenticated_provider_evidence is False
    assert asset.authenticated_provider_evidence is False
