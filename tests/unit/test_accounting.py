from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal

import pytest

from packages.domain.accounting import Ledger
from packages.domain.models import Posting
from packages.domain.risk import RiskAccountSnapshot
from packages.domain.walking_thread import WalkingThread


@pytest.mark.parametrize("amount", [Decimal("NaN"), Decimal("Infinity"), Decimal("0")])
def test_opening_balance_must_be_finite_and_positive(amount: Decimal) -> None:
    with pytest.raises(ValueError, match="finite and positive"):
        Ledger().open_account(amount, datetime(2026, 7, 15, tzinfo=UTC))


@pytest.mark.parametrize("non_finite", [Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity")])
def test_non_finite_values_are_rejected_at_accounting_and_risk_boundaries(
    non_finite: Decimal,
) -> None:
    result = WalkingThread.run()
    with pytest.raises(ValueError, match="fill fee"):
        replace(result.fill, fee=non_finite)
    with pytest.raises(ValueError, match="finite"):
        Posting(account="assets:cash:USD", currency="USD", debit=non_finite)
    with pytest.raises(ValueError, match="available cash"):
        RiskAccountSnapshot(
            account_id=WalkingThread.account_id,
            version=WalkingThread.risk_snapshot_version,
            available_cash=non_finite,
        )


@pytest.mark.parametrize("quantity", [Decimal("0.5"), Decimal("10.25")])
def test_fractional_share_facts_are_rejected(quantity: Decimal) -> None:
    result = WalkingThread.run()

    with pytest.raises(ValueError, match="whole number"):
        replace(result.target.targets[0], quantity=quantity)
    with pytest.raises(ValueError, match="whole number"):
        replace(result.intent, quantity=quantity)
    with pytest.raises(ValueError, match="whole number"):
        replace(result.order, quantity=quantity, filled_quantity=Decimal("0"))
    with pytest.raises(ValueError, match="whole number"):
        replace(result.fill, quantity=quantity)
