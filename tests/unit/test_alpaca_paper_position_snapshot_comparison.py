from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest

from packages.adapters.broker.alpaca_paper_position_snapshot_comparison import (
    ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_CONTRACT_VERSION,
    ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_POLICY_ID,
    ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_POLICY_SHA256,
    ALPACA_PAPER_POSITION_SNAPSHOT_MINIMUM_UTC_SEPARATION,
    AlpacaPaperPositionSnapshotComparison,
    AlpacaPaperPositionSnapshotComparisonConflict,
    AlpacaPaperPositionSnapshotComparisonDisposition,
    AlpacaPaperPositionSnapshotComparisonError,
    compare_alpaca_paper_position_snapshots,
)
from packages.adapters.broker.alpaca_paper_positions import (
    AlpacaPaperPositionSnapshotError,
    PersistedAlpacaPaperPositionSnapshot,
    create_alpaca_paper_position_snapshot_description,
    persist_then_decode_alpaca_paper_position_snapshot_response,
)
from packages.domain.broker_ingress import (
    BrokerIngressDelivery,
    BrokerIngressReceipt,
)

ACCOUNT_ID = "paper-account-position-comparison"
BASE = datetime(2026, 7, 28, 19, 0, tzinfo=UTC)
SYMBOLS = ("SPY", "QQQ", "IWM", "DIA", "XLK", "XLF")


class _Recorder:
    def __init__(self) -> None:
        self.receipts: list[BrokerIngressReceipt] = []

    def record(self, delivery: BrokerIngressDelivery) -> BrokerIngressReceipt:
        receipt = BrokerIngressReceipt(
            delivery=delivery,
            ingress_sequence=len(self.receipts) + 1,
            previous_receipt_sha256=(
                None if not self.receipts else self.receipts[-1].semantic_sha256
            ),
        )
        self.receipts.append(receipt)
        return receipt


def _position(
    number: int,
    *,
    symbol: str | None = None,
    quantity_lexeme: str = "2.5000",
    entry_price_lexeme: str = "430.1200",
) -> dict[str, object]:
    selected_symbol = SYMBOLS[(number - 1) % len(SYMBOLS)] if symbol is None else symbol
    return {
        "asset_id": str(UUID(int=number)),
        "symbol": selected_symbol,
        "exchange": "ARCA",
        "asset_class": "us_equity",
        "asset_marginable": True,
        "avg_entry_price": entry_price_lexeme,
        "qty": quantity_lexeme,
        "side": "long",
        "market_value": "1077.80000",
        "cost_basis": "1075.3000",
        "unrealized_pl": "2.50000",
        "unrealized_plpc": "0.002325",
        "unrealized_intraday_pl": "1.2500",
        "unrealized_intraday_plpc": "0.001161",
        "current_price": "431.120000",
        "lastday_price": "430.6200",
        "change_today": "0.001161",
        "qty_available": "1.500",
    }


def _body(
    positions: tuple[dict[str, object], ...],
    *,
    pretty: bool = False,
) -> bytes:
    if pretty:
        return json.dumps(
            positions,
            allow_nan=False,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
    return json.dumps(
        positions,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _capture(
    recorder: _Recorder,
    *,
    capture_key: str,
    received_at: datetime,
    positions: tuple[dict[str, object], ...] = (),
    account_id: str = ACCOUNT_ID,
    pretty: bool = False,
) -> PersistedAlpacaPaperPositionSnapshot:
    description = create_alpaca_paper_position_snapshot_description(
        account_id=account_id,
        capture_idempotency_key=capture_key,
    )
    return persist_then_decode_alpaca_paper_position_snapshot_response(
        recorder,
        description,
        http_status=200,
        provider_request_id=f"position-comparison-request-{capture_key}",
        response_body=_body(positions, pretty=pretty),
        received_at=received_at,
        recorded_at=received_at + timedelta(milliseconds=1),
    )


def _pair(
    *,
    later_offset: timedelta = timedelta(seconds=2),
    earlier_positions: tuple[dict[str, object], ...] | None = None,
    later_positions: tuple[dict[str, object], ...] | None = None,
) -> tuple[
    PersistedAlpacaPaperPositionSnapshot,
    PersistedAlpacaPaperPositionSnapshot,
]:
    recorder = _Recorder()
    default = (_position(1), _position(2))
    earlier = _capture(
        recorder,
        capture_key="position-comparison-earlier",
        received_at=BASE,
        positions=default if earlier_positions is None else earlier_positions,
    )
    later = _capture(
        recorder,
        capture_key="position-comparison-later",
        received_at=BASE + later_offset,
        positions=default if later_positions is None else later_positions,
    )
    return earlier, later


def _assert_no_authority(value: object) -> None:
    for property_name in (
        "request_budget_enforced",
        "authenticated_provider_evidence",
        "runtime_current",
        "capture_authenticated",
        "durable_source_positions_authenticated",
        "snapshot_isolation_qualified",
        "provider_snapshot_complete",
        "snapshot_complete",
        "monotonic_timing_qualified",
        "provider_revision_identity_qualified",
        "provider_deduplication_authorized",
        "normalized_fact_authorized",
        "inbox_application_authorized",
        "lifecycle_application_authorized",
        "reconciliation_application_authorized",
        "reconciliation_completion_authorized",
        "reconciliation_complete",
        "unknown_resolution_authorized",
        "reservation_release_authorized",
        "resubmission_authorized",
        "canonical_position_fact_authorized",
        "canonical_execution_fact_authorized",
        "canonical_account_fact_authorized",
        "canonical_ledger_fact_authorized",
        "canonical_cash_fact_authorized",
        "readiness_transition_authorized",
        "reconciliation_ready",
        "dispatch_preflight_ready",
        "paper_startup_ready",
        "transport_authorized",
        "broker_call_authorized",
        "trading_effect_authorized",
        "converged",
    ):
        assert getattr(value, property_name) is False


def test_exact_two_second_equal_view_is_stable_and_explicitly_unqualified() -> None:
    earlier, later = _pair()

    comparison = compare_alpaca_paper_position_snapshots(earlier, later)
    repeated = compare_alpaca_paper_position_snapshots(earlier, later)

    assert ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_CONTRACT_VERSION == (
        "phase4s-exact-position-view-comparison-v1"
    )
    assert ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_POLICY_ID == (
        "phase4s-exact-position-view-comparison-policy-v1"
    )
    assert len(ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_POLICY_SHA256) == 64
    assert timedelta(seconds=2) == ALPACA_PAPER_POSITION_SNAPSHOT_MINIMUM_UTC_SEPARATION
    assert comparison.disposition is (
        AlpacaPaperPositionSnapshotComparisonDisposition.EXACT_POSITION_VIEW_MATCH_UNQUALIFIED
    )
    assert comparison.account_id == ACCOUNT_ID
    assert len(comparison.capture_profile_sha256) == 64
    assert comparison.earlier_received_at == BASE
    assert comparison.later_received_at == BASE + timedelta(seconds=2)
    assert comparison.observed_utc_separation == timedelta(seconds=2)
    assert comparison.observed_utc_separation_microseconds == 2_000_000
    assert comparison.receive_windows_non_overlapping is True
    assert comparison.minimum_utc_separation_observed is True
    assert comparison.position_views_equal is True
    assert comparison.exact_position_view_match_unqualified is True
    assert comparison.earlier_view == comparison.later_view
    assert comparison.earlier_view_sha256 == comparison.later_view_sha256
    assert tuple(asset_id for asset_id, _ in comparison.earlier_view) == (
        str(UUID(int=1)),
        str(UUID(int=2)),
    )
    assert comparison.added_asset_ids == ()
    assert comparison.removed_asset_ids == ()
    assert comparison.changed_asset_ids == ()
    assert comparison.additional_reconciliation_required is True
    assert comparison == repeated
    assert comparison.semantic_sha256 == repeated.semantic_sha256
    assert str(UUID(comparison.comparison_id)) == comparison.comparison_id
    _assert_no_authority(comparison)


@pytest.mark.parametrize(
    ("later_offset", "non_overlapping"),
    (
        (timedelta(seconds=2, microseconds=-1), True),
        (timedelta(microseconds=-1), False),
    ),
)
def test_too_close_view_waits_without_qualifying_monotonic_time(
    later_offset: timedelta,
    non_overlapping: bool,
) -> None:
    earlier, later = _pair(
        later_offset=later_offset,
        later_positions=(_position(1, entry_price_lexeme="431.0000"), _position(2)),
    )

    comparison = compare_alpaca_paper_position_snapshots(earlier, later)

    assert comparison.disposition is (
        AlpacaPaperPositionSnapshotComparisonDisposition.WAITING_MINIMUM_SEPARATION
    )
    assert comparison.receive_windows_non_overlapping is non_overlapping
    assert comparison.minimum_utc_separation_observed is False
    assert comparison.position_views_equal is False
    assert comparison.changed_asset_ids == (str(UUID(int=1)),)
    assert comparison.exact_position_view_match_unqualified is False
    assert comparison.monotonic_timing_qualified is False
    assert comparison.converged is False


def test_added_removed_and_exactly_changed_assets_are_sorted() -> None:
    earlier, later = _pair(
        later_offset=timedelta(seconds=3),
        earlier_positions=(_position(3), _position(1), _position(2)),
        later_positions=(
            _position(4),
            _position(2, entry_price_lexeme="430.120"),
            _position(3),
        ),
    )

    comparison = compare_alpaca_paper_position_snapshots(earlier, later)

    assert comparison.disposition is (
        AlpacaPaperPositionSnapshotComparisonDisposition.POSITION_VIEW_DIFFERENT
    )
    assert comparison.added_asset_ids == (str(UUID(int=4)),)
    assert comparison.removed_asset_ids == (str(UUID(int=1)),)
    assert comparison.changed_asset_ids == (str(UUID(int=2)),)
    assert comparison.position_views_equal is False
    assert comparison.earlier_view_sha256 != comparison.later_view_sha256
    assert comparison.canonical_position_fact_authorized is False
    assert comparison.reconciliation_completion_authorized is False


def test_decimal_lexeme_change_is_semantic_even_when_decimal_value_is_equal() -> None:
    earlier, later = _pair(
        earlier_positions=(_position(1, quantity_lexeme="2.5000"),),
        later_positions=(_position(1, quantity_lexeme="2.500"),),
    )
    assert earlier.observation.positions[0].quantity.value == (
        later.observation.positions[0].quantity.value
    )

    comparison = compare_alpaca_paper_position_snapshots(earlier, later)

    assert comparison.changed_asset_ids == (str(UUID(int=1)),)
    assert comparison.disposition is (
        AlpacaPaperPositionSnapshotComparisonDisposition.POSITION_VIEW_DIFFERENT
    )


def test_array_order_raw_format_and_capture_identity_do_not_change_the_view() -> None:
    recorder = _Recorder()
    earlier = _capture(
        recorder,
        capture_key="position-comparison-format-earlier",
        received_at=BASE,
        positions=(_position(2), _position(1)),
    )
    later = _capture(
        recorder,
        capture_key="position-comparison-format-later",
        received_at=BASE + timedelta(seconds=3),
        positions=(_position(1), _position(2)),
        pretty=True,
    )

    comparison = compare_alpaca_paper_position_snapshots(earlier, later)

    assert earlier.capture_id != later.capture_id
    assert earlier.receipt.delivery.body_sha256 != later.receipt.delivery.body_sha256
    assert earlier.semantic_sha256 != later.semantic_sha256
    assert comparison.earlier_view == comparison.later_view
    assert comparison.earlier_view_sha256 == comparison.later_view_sha256
    assert comparison.disposition is (
        AlpacaPaperPositionSnapshotComparisonDisposition.EXACT_POSITION_VIEW_MATCH_UNQUALIFIED
    )


def test_asset_identity_substitution_is_added_and_removed_not_changed() -> None:
    earlier, later = _pair(
        earlier_positions=(_position(5, symbol="XLK"),),
        later_positions=(_position(6, symbol="XLK"),),
    )

    comparison = compare_alpaca_paper_position_snapshots(earlier, later)

    assert comparison.added_asset_ids == (str(UUID(int=6)),)
    assert comparison.removed_asset_ids == (str(UUID(int=5)),)
    assert comparison.changed_asset_ids == ()


def test_duplicate_assets_or_provider_symbols_never_reach_comparison() -> None:
    duplicate_asset_recorder = _Recorder()
    with pytest.raises(AlpacaPaperPositionSnapshotError, match="provider asset ID"):
        _capture(
            duplicate_asset_recorder,
            capture_key="position-comparison-duplicate-asset",
            received_at=BASE,
            positions=(_position(1), _position(1, symbol="QQQ")),
        )
    assert len(duplicate_asset_recorder.receipts) == 1

    duplicate_symbol_recorder = _Recorder()
    with pytest.raises(AlpacaPaperPositionSnapshotError, match="provider identity"):
        _capture(
            duplicate_symbol_recorder,
            capture_key="position-comparison-duplicate-symbol",
            received_at=BASE,
            positions=(_position(1), _position(2, symbol="SPY")),
        )
    assert len(duplicate_symbol_recorder.receipts) == 1


def test_two_empty_views_match_but_cannot_complete_reconciliation() -> None:
    earlier, later = _pair(earlier_positions=(), later_positions=())

    comparison = compare_alpaca_paper_position_snapshots(earlier, later)

    assert comparison.earlier_view == ()
    assert comparison.later_view == ()
    assert comparison.position_views_equal is True
    assert comparison.disposition is (
        AlpacaPaperPositionSnapshotComparisonDisposition.EXACT_POSITION_VIEW_MATCH_UNQUALIFIED
    )
    assert comparison.provider_snapshot_complete is False
    assert comparison.reconciliation_complete is False
    assert comparison.paper_startup_ready is False


def test_pair_requires_same_account_distinct_capture_and_strict_source_order() -> None:
    recorder = _Recorder()
    earlier = _capture(
        recorder,
        capture_key="position-comparison-source-earlier",
        received_at=BASE,
    )
    other_account = _capture(
        recorder,
        capture_key="position-comparison-other-account",
        received_at=BASE + timedelta(seconds=2),
        account_id="different-paper-account",
    )
    with pytest.raises(
        AlpacaPaperPositionSnapshotComparisonConflict,
        match="different accounts",
    ):
        compare_alpaca_paper_position_snapshots(earlier, other_account)

    same_capture_again = _capture(
        recorder,
        capture_key="position-comparison-source-earlier",
        received_at=BASE + timedelta(seconds=3),
    )
    with pytest.raises(
        AlpacaPaperPositionSnapshotComparisonConflict,
        match="distinct capture",
    ):
        compare_alpaca_paper_position_snapshots(earlier, same_capture_again)

    valid_later = _capture(
        recorder,
        capture_key="position-comparison-source-later",
        received_at=BASE + timedelta(seconds=4),
    )
    with pytest.raises(
        AlpacaPaperPositionSnapshotComparisonConflict,
        match="does not follow",
    ):
        compare_alpaca_paper_position_snapshots(valid_later, earlier)

    independent_earlier = _capture(
        _Recorder(),
        capture_key="position-comparison-independent-earlier",
        received_at=BASE,
    )
    independent_later = _capture(
        _Recorder(),
        capture_key="position-comparison-independent-later",
        received_at=BASE + timedelta(seconds=2),
    )
    with pytest.raises(
        AlpacaPaperPositionSnapshotComparisonConflict,
        match="does not follow",
    ):
        compare_alpaca_paper_position_snapshots(
            independent_earlier,
            independent_later,
        )


def test_comparison_is_proof_constructed_immutable_and_rejects_wrong_sources() -> None:
    earlier, later = _pair()
    comparison = compare_alpaca_paper_position_snapshots(earlier, later)

    with pytest.raises(TypeError, match="proof-constructed"):
        AlpacaPaperPositionSnapshotComparison()
    mutable: Any = comparison
    with pytest.raises(FrozenInstanceError):
        mutable.disposition = (
            AlpacaPaperPositionSnapshotComparisonDisposition.POSITION_VIEW_DIFFERENT
        )
    with pytest.raises(AlpacaPaperPositionSnapshotComparisonError, match="earlier"):
        compare_alpaca_paper_position_snapshots(
            object(),  # type: ignore[arg-type]
            later,
        )
    with pytest.raises(AlpacaPaperPositionSnapshotComparisonError, match="later"):
        compare_alpaca_paper_position_snapshots(
            earlier,
            object(),  # type: ignore[arg-type]
        )
