"""Transactional, immutable persistence for the Phase 0 walking thread."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection

from packages.domain.models import DecisionStatus, LedgerEntry
from packages.domain.risk import RiskAuthorizationError
from packages.domain.walking_thread import WalkingThreadResult
from packages.persistence.immutable import (
    ImmutableFactConflict,
    assert_immutable,
    insert_or_verify,
)
from packages.persistence.risk import (
    decision_from_row,
    immutable_decision_values,
    submission_attempt_id,
)
from packages.persistence.schema import (
    fills,
    ledger_entries,
    ledger_postings,
    metadata,
    orders,
    risk_account_guards,
    risk_decisions,
    risk_reservations,
    submission_attempts,
)


@dataclass(frozen=True, slots=True)
class PersistenceReceipt:
    run_id: str
    inserted_facts: int
    existing_facts: int


def initialize_phase_zero_schema(engine: Engine) -> None:
    """Create local/test tables; Alembic remains authoritative for deployed databases."""

    metadata.create_all(engine)


def _posting_values(entry: LedgerEntry) -> list[dict[str, Any]]:
    return [
        {
            "entry_id": entry.entry_id,
            "line_number": line_number,
            "account": posting.account,
            "currency": posting.currency,
            "debit": posting.debit,
            "credit": posting.credit,
            "units_delta": posting.units_delta,
            "instrument_id": posting.instrument_id,
        }
        for line_number, posting in enumerate(entry.postings, start=1)
    ]


def _persist_ledger_entry(connection: Connection, entry: LedgerEntry) -> tuple[int, int]:
    entry_values = {
        "entry_id": entry.entry_id,
        "event_type": entry.event_type,
        "reference_id": entry.reference_id,
        "posted_at": entry.posted_at,
    }
    inserted_entry = insert_or_verify(connection, ledger_entries, "entry_id", entry_values)
    expected_postings = _posting_values(entry)
    existing_postings = (
        connection.execute(
            sa.select(ledger_postings)
            .where(ledger_postings.c.entry_id == entry.entry_id)
            .order_by(ledger_postings.c.line_number)
        )
        .mappings()
        .all()
    )
    if inserted_entry:
        connection.execute(sa.insert(ledger_postings), expected_postings)
        persisted_postings = (
            connection.execute(
                sa.select(ledger_postings)
                .where(ledger_postings.c.entry_id == entry.entry_id)
                .order_by(ledger_postings.c.line_number)
            )
            .mappings()
            .all()
        )
        if len(persisted_postings) != len(expected_postings):
            raise ImmutableFactConflict(
                f"ledger entry {entry.entry_id!r} did not persist every posting"
            )
        for actual, expected in zip(persisted_postings, expected_postings, strict=True):
            assert_immutable(ledger_postings, entry.entry_id, actual, expected)
        return 1 + len(expected_postings), 0
    if len(existing_postings) != len(expected_postings):
        raise ImmutableFactConflict(
            f"ledger entry {entry.entry_id!r} has a different posting count"
        )
    for actual, expected in zip(existing_postings, expected_postings, strict=True):
        assert_immutable(ledger_postings, entry.entry_id, actual, expected)
    return 0, 1 + len(expected_postings)


class WalkingThreadUnitOfWork:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def execution_exists(self, order_id: str) -> bool:
        with self._engine.connect() as connection:
            return (
                connection.execute(
                    sa.select(orders.c.order_id).where(orders.c.order_id == order_id)
                ).scalar_one_or_none()
                is not None
            )

    def persist(self, result: WalkingThreadResult) -> PersistenceReceipt:
        inserted = 0
        existing = 0
        facts = (
            (
                orders,
                "order_id",
                {
                    "order_id": result.order.order_id,
                    "client_order_id": result.order.client_order_id,
                    "intent_id": result.order.intent_id,
                    "risk_decision_id": result.order.risk_decision_id,
                    "instrument_id": result.order.instrument_id,
                    "symbol": result.order.symbol,
                    "side": result.order.side.value,
                    "quantity": result.order.quantity,
                    "filled_quantity": result.order.filled_quantity,
                    "activation_after_event_time": result.order.activation_after_event_time,
                    "submitted_at": result.order.submitted_at,
                    "status": result.order.status.value,
                },
            ),
            (
                fills,
                "fill_id",
                {
                    "fill_id": result.fill.fill_id,
                    "order_id": result.fill.order_id,
                    "instrument_id": result.fill.instrument_id,
                    "symbol": result.fill.symbol,
                    "side": result.fill.side.value,
                    "quantity": result.fill.quantity,
                    "price": result.fill.price,
                    "fee": result.fill.fee,
                    "executed_at": result.fill.executed_at,
                },
            ),
        )
        with self._engine.begin() as connection:
            decision_row = (
                connection.execute(
                    sa.select(risk_decisions).where(
                        risk_decisions.c.decision_id == result.risk_decision.decision_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if decision_row is None:
                raise RiskAuthorizationError(
                    "walking-thread persistence requires a previously issued risk decision"
                )
            decoded_decision = decision_from_row(decision_row)
            if decoded_decision != result.risk_decision:
                raise ImmutableFactConflict(
                    f"risk decision {result.risk_decision.decision_id!r} conflicts with "
                    "the issued authorization"
                )
            assert_immutable(
                risk_decisions,
                result.risk_decision.decision_id,
                decision_row,
                {
                    **immutable_decision_values(result.risk_decision),
                    "consumed_at": result.order.submitted_at,
                },
            )
            if result.risk_decision.status is not DecisionStatus.APPROVED:
                raise RiskAuthorizationError(
                    "walking-thread execution requires an approved risk decision"
                )

            reservation_row = (
                connection.execute(
                    sa.select(risk_reservations).where(
                        risk_reservations.c.decision_id == result.risk_decision.decision_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if reservation_row is None:
                raise RiskAuthorizationError(
                    "walking-thread persistence requires a durable risk reservation"
                )
            assert_immutable(
                risk_reservations,
                result.risk_decision.decision_id,
                reservation_row,
                {
                    "decision_id": result.risk_decision.decision_id,
                    "account_id": result.risk_account_snapshot.account_id,
                    "snapshot_version": result.risk_account_snapshot.version,
                    "cash_amount": result.risk_decision.reserved_cash,
                    "state": "consumed",
                    "expires_at": result.risk_decision.expires_at,
                },
            )
            guard_row = (
                connection.execute(
                    sa.select(risk_account_guards).where(
                        risk_account_guards.c.account_id == result.risk_account_snapshot.account_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if guard_row is None:
                raise RiskAuthorizationError(
                    "walking-thread persistence requires its risk account guard"
                )
            if (
                guard_row["snapshot_version"] != result.risk_account_snapshot.version
                or Decimal(str(guard_row["available_cash"]))
                != result.risk_account_snapshot.available_cash
                or Decimal(str(guard_row["reserved_cash"])) < result.risk_decision.reserved_cash
            ):
                raise RiskAuthorizationError("risk account guard conflicts with its snapshot")

            expected_attempt_id = submission_attempt_id(
                result.risk_decision.decision_id,
                result.intent.intent_id,
            )
            attempt_row = (
                connection.execute(
                    sa.select(submission_attempts)
                    .where(submission_attempts.c.decision_id == result.risk_decision.decision_id)
                    .with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if attempt_row is None:
                raise RiskAuthorizationError(
                    "walking-thread persistence requires an authorized submission attempt"
                )
            assert_immutable(
                submission_attempts,
                expected_attempt_id,
                attempt_row,
                {
                    "attempt_id": expected_attempt_id,
                    "decision_id": result.risk_decision.decision_id,
                    "intent_id": result.intent.intent_id,
                    "submitted_at": result.order.submitted_at,
                },
            )
            attempt_state = attempt_row["state"]
            if attempt_state == "authorized" and attempt_row["order_id"] is None:
                record_attempt = True
            elif attempt_state == "recorded" and attempt_row["order_id"] == result.order.order_id:
                record_attempt = False
            else:
                raise ImmutableFactConflict(
                    f"submission attempt {expected_attempt_id!r} conflicts with order binding"
                )

            existing += 4
            for table, key_name, values in facts:
                if insert_or_verify(connection, table, key_name, values):
                    inserted += 1
                else:
                    existing += 1
            for entry in result.ledger_entries:
                new_count, existing_count = _persist_ledger_entry(connection, entry)
                inserted += new_count
                existing += existing_count
            if record_attempt:
                attempt_update = connection.execute(
                    sa.update(submission_attempts)
                    .where(
                        submission_attempts.c.attempt_id == expected_attempt_id,
                        submission_attempts.c.state == "authorized",
                        submission_attempts.c.order_id.is_(None),
                    )
                    .values(state="recorded", order_id=result.order.order_id)
                )
                if attempt_update.rowcount != 1:
                    raise RiskAuthorizationError("submission attempt was recorded concurrently")
        return PersistenceReceipt(
            run_id=result.run_id,
            inserted_facts=inserted,
            existing_facts=existing,
        )
