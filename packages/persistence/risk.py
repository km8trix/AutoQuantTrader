"""Durable issuance and single-use consumption of risk authorizations."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any, cast

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Connection, RowMapping

from packages.domain.identifiers import deterministic_id
from packages.domain.models import (
    DecisionStatus,
    OrderIntent,
    RiskDecision,
    RiskRuleResult,
    require_aware,
)
from packages.domain.risk import (
    RiskAccountSnapshot,
    RiskAuthority,
    RiskAuthorizationError,
    evaluate_risk_decision,
    intent_payload_hash,
    validate_consumption,
)
from packages.persistence.immutable import as_aware_utc
from packages.persistence.schema import (
    risk_account_guards,
    risk_decisions,
    risk_reservations,
    submission_attempts,
)

_RULE_KEYS = frozenset({"rule", "passed", "observed", "limit"})


def submission_attempt_id(decision_id: str, intent_id: str) -> str:
    """Return the stable identity of an authorization-to-submission handoff."""

    return deterministic_id("submission-attempt", decision_id, intent_id)


def _rule_payload(decision: RiskDecision) -> list[dict[str, Any]]:
    return [
        {
            "rule": rule.rule,
            "passed": rule.passed,
            "observed": rule.observed,
            "limit": rule.limit,
        }
        for rule in decision.rules
    ]


def immutable_decision_values(decision: RiskDecision) -> dict[str, Any]:
    """Return the complete immutable SQL representation of a decision."""

    return {
        "decision_id": decision.decision_id,
        "intent_id": decision.intent_id,
        "intent_payload_hash": decision.intent_payload_hash,
        "policy_version": decision.policy_version,
        "status": decision.status.value,
        "evaluated_at": decision.evaluated_at,
        "expires_at": decision.expires_at,
        "reserved_cash": decision.reserved_cash,
        "rules": _rule_payload(decision),
    }


def _strict_rules(raw: object) -> tuple[RiskRuleResult, ...]:
    if type(raw) is not list:
        raise RiskAuthorizationError("persisted risk rules must be a JSON array")
    parsed: list[RiskRuleResult] = []
    for index, item in enumerate(raw):
        if type(item) is not dict or frozenset(item) != _RULE_KEYS:
            raise RiskAuthorizationError(f"persisted risk rule {index} has an invalid object shape")
        if type(item["passed"]) is not bool:
            raise RiskAuthorizationError(
                f"persisted risk rule {index} passed flag must be a boolean"
            )
        if any(type(item[key]) is not str for key in ("rule", "observed", "limit")):
            raise RiskAuthorizationError(f"persisted risk rule {index} fields must be strings")
        try:
            parsed.append(
                RiskRuleResult(
                    rule=item["rule"],
                    passed=item["passed"],
                    observed=item["observed"],
                    limit=item["limit"],
                )
            )
        except ValueError as error:
            raise RiskAuthorizationError("persisted risk rule is invalid") from error
    return tuple(parsed)


def decision_from_row(row: RowMapping) -> RiskDecision:
    """Decode persisted authorization data without coercing malformed values."""

    try:
        status_value = row["status"]
        if type(status_value) is not str:
            raise RiskAuthorizationError("persisted risk status must be a string")
        return RiskDecision(
            decision_id=str(row["decision_id"]),
            intent_id=str(row["intent_id"]),
            intent_payload_hash=str(row["intent_payload_hash"]),
            policy_version=str(row["policy_version"]),
            status=DecisionStatus(status_value),
            evaluated_at=as_aware_utc(cast(datetime, row["evaluated_at"])),
            expires_at=as_aware_utc(cast(datetime, row["expires_at"])),
            reserved_cash=Decimal(str(row["reserved_cash"])),
            rules=_strict_rules(row["rules"]),
        )
    except RiskAuthorizationError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise RiskAuthorizationError("persisted risk decision is malformed") from error


def _insert_guard_if_absent(
    connection: Connection,
    snapshot: RiskAccountSnapshot,
    evaluated_at: datetime,
) -> None:
    values = {
        "account_id": snapshot.account_id,
        "snapshot_version": snapshot.version,
        "available_cash": snapshot.available_cash,
        "reserved_cash": Decimal("0"),
        "updated_at": evaluated_at,
    }
    dialect = connection.dialect.name
    if dialect == "postgresql":
        postgres_statement = postgresql_insert(risk_account_guards).values(**values)
        # The guard has both an account PK and an account/snapshot uniqueness
        # invariant. Concurrent first writers can be reported through either
        # constraint, so this bootstrap insert must tolerate any uniqueness
        # conflict before locking and validating the authoritative row.
        postgres_statement = postgres_statement.on_conflict_do_nothing()
        connection.execute(postgres_statement)
        return
    elif dialect == "sqlite":
        sqlite_statement = sqlite_insert(risk_account_guards).values(**values)
        sqlite_statement = sqlite_statement.on_conflict_do_nothing()
        connection.execute(sqlite_statement)
        return
    else:
        raise RiskAuthorizationError(
            f"atomic risk reservations do not support SQL dialect {dialect!r}"
        )


def _existing_for_intent(
    connection: Connection,
    intent: OrderIntent,
) -> RiskDecision | None:
    row = (
        connection.execute(
            sa.select(risk_decisions).where(risk_decisions.c.intent_id == intent.intent_id)
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    decision = decision_from_row(row)
    if decision.intent_payload_hash != intent_payload_hash(intent):
        raise RiskAuthorizationError("intent IDs are immutable")
    return decision


def _verify_reservation(
    connection: Connection,
    decision: RiskDecision,
    snapshot: RiskAccountSnapshot,
) -> None:
    row = (
        connection.execute(
            sa.select(risk_reservations).where(
                risk_reservations.c.decision_id == decision.decision_id
            )
        )
        .mappings()
        .one_or_none()
    )
    if decision.status is DecisionStatus.REJECTED:
        if row is not None:
            raise RiskAuthorizationError("rejected decision has an invalid reservation")
        return
    if row is None:
        raise RiskAuthorizationError("approved decision lacks its durable reservation")
    expected = {
        "account_id": snapshot.account_id,
        "snapshot_version": snapshot.version,
        "cash_amount": decision.reserved_cash,
        "expires_at": decision.expires_at,
    }
    for field, value in expected.items():
        actual = row[field]
        if isinstance(value, Decimal):
            matches = Decimal(str(actual)) == value
        elif isinstance(value, datetime):
            matches = isinstance(actual, datetime) and as_aware_utc(actual) == value
        else:
            matches = actual == value
        if not matches:
            raise RiskAuthorizationError(f"durable reservation conflicts in field {field!r}")
    if row["state"] not in {"approved", "consumed"}:
        raise RiskAuthorizationError("durable reservation is not executable")


class SqlRiskDecisionRepository:
    """Issue decisions under an account lock and consume them exactly once."""

    def __init__(self, engine: Engine, authority: RiskAuthority) -> None:
        self._engine = engine
        self._authority = authority

    def authorize(self, intent: OrderIntent) -> RiskDecision:
        snapshot = self._authority.account_snapshots.current()
        evaluated_at = self._authority.evaluation_clock.now()
        require_aware(evaluated_at, "evaluated_at")
        with self._engine.begin() as connection:
            _insert_guard_if_absent(connection, snapshot, evaluated_at)
            guard = (
                connection.execute(
                    sa.select(risk_account_guards)
                    .where(risk_account_guards.c.account_id == snapshot.account_id)
                    .with_for_update()
                )
                .mappings()
                .one()
            )
            if guard["snapshot_version"] != snapshot.version:
                raise RiskAuthorizationError("risk account snapshot version is stale")
            if Decimal(str(guard["available_cash"])) != snapshot.available_cash:
                raise RiskAuthorizationError("risk snapshot version changed its cash capacity")

            existing = _existing_for_intent(connection, intent)
            if existing is not None:
                _verify_reservation(connection, existing, snapshot)
                return existing

            guard_updated_at = as_aware_utc(cast(datetime, guard["updated_at"]))
            if evaluated_at < guard_updated_at:
                raise RiskAuthorizationError(
                    "risk evaluation clock moved backwards for the account snapshot"
                )
            reserved_cash = Decimal(str(guard["reserved_cash"]))
            decision = evaluate_risk_decision(
                intent,
                self._authority.limits,
                # Numeric columns restore their declared scale. Normalize only the
                # persisted aggregate before policy evaluation so evidence strings
                # remain identical to the original domain decimals.
                snapshot.available_cash - reserved_cash.normalize(),
                evaluated_at,
            )
            connection.execute(
                sa.insert(risk_decisions).values(
                    **immutable_decision_values(decision),
                    consumed_at=None,
                )
            )
            new_reserved_cash = reserved_cash
            if decision.status is DecisionStatus.APPROVED:
                connection.execute(
                    sa.insert(risk_reservations).values(
                        decision_id=decision.decision_id,
                        account_id=snapshot.account_id,
                        snapshot_version=snapshot.version,
                        cash_amount=decision.reserved_cash,
                        state="approved",
                        expires_at=decision.expires_at,
                    )
                )
                new_reserved_cash += decision.reserved_cash
            connection.execute(
                sa.update(risk_account_guards)
                .where(risk_account_guards.c.account_id == snapshot.account_id)
                .values(reserved_cash=new_reserved_cash, updated_at=evaluated_at)
            )
            return decision

    def get(self, decision_id: str) -> RiskDecision | None:
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    sa.select(risk_decisions).where(risk_decisions.c.decision_id == decision_id)
                )
                .mappings()
                .one_or_none()
            )
        return None if row is None else decision_from_row(row)

    def consume(self, decision_id: str, intent: OrderIntent) -> datetime:
        consumed_at = self._authority.consumption_clock.now()
        with self._engine.begin() as connection:
            row = (
                connection.execute(
                    sa.select(risk_decisions)
                    .where(risk_decisions.c.decision_id == decision_id)
                    .with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise RiskAuthorizationError("execution requires a durably persisted risk decision")
            decision = decision_from_row(row)
            validate_consumption(decision, intent, consumed_at)
            if cast(datetime | None, row["consumed_at"]) is not None:
                raise RiskAuthorizationError("risk approval has already been consumed")
            reservation = (
                connection.execute(
                    sa.select(risk_reservations)
                    .where(risk_reservations.c.decision_id == decision_id)
                    .with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if reservation is None:
                raise RiskAuthorizationError("risk approval lacks a durable reservation")
            if (
                reservation["state"] != "approved"
                or Decimal(str(reservation["cash_amount"])) != decision.reserved_cash
                or as_aware_utc(cast(datetime, reservation["expires_at"])) != decision.expires_at
            ):
                raise RiskAuthorizationError("risk reservation is not valid for consumption")
            existing_attempt = (
                connection.execute(
                    sa.select(submission_attempts)
                    .where(submission_attempts.c.decision_id == decision_id)
                    .with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if existing_attempt is not None:
                raise RiskAuthorizationError(
                    "risk approval already has a durable submission attempt"
                )
            decision_update = connection.execute(
                sa.update(risk_decisions)
                .where(
                    risk_decisions.c.decision_id == decision_id,
                    risk_decisions.c.consumed_at.is_(None),
                )
                .values(consumed_at=consumed_at)
            )
            reservation_update = connection.execute(
                sa.update(risk_reservations)
                .where(
                    risk_reservations.c.decision_id == decision_id,
                    risk_reservations.c.state == "approved",
                )
                .values(state="consumed")
            )
            if decision_update.rowcount != 1 or reservation_update.rowcount != 1:
                raise RiskAuthorizationError("risk approval was consumed concurrently")
            connection.execute(
                sa.insert(submission_attempts).values(
                    attempt_id=submission_attempt_id(decision_id, intent.intent_id),
                    decision_id=decision_id,
                    intent_id=intent.intent_id,
                    submitted_at=consumed_at,
                    state="authorized",
                    order_id=None,
                )
            )
        return consumed_at
