"""Immutable daily input conversion for the personal causal engine.

A retrospective open proxy is explicitly modeled. The archive's later factual
receipt is retained as provenance and never claimed to have occurred at the open.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from typing import Literal
from zoneinfo import ZoneInfo

from packages.domain.accounting_contracts import (
    AccountingState,
    ExecutionObservation,
    ExecutionPolicy,
    SettlementCalendar,
)
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.decimal_math import exact_decimal_add, exact_decimal_multiply
from packages.domain.engine_contracts import (
    BenchmarkPrice,
    DailyPrice,
    DailyRiskPolicy,
    EngineEvent,
    EngineInputs,
    EvaluationSpec,
    ObservationProvenance,
    RunSpec,
)
from packages.domain.personal_contracts import VersionPin, content_digest
from packages.domain.research_dataset import (
    DAILY_AVAILABILITY_POLICY,
    ResearchCalendar,
    ResearchDataClass,
    ResearchDataset,
    ResearchSession,
    modeled_daily_availability,
)

OPEN_PROXY_ASSUMPTION = "retrospective-raw-open-available-at-open-model/1"
SYNTHETIC_CALENDAR = "synthetic-weekdays-not-an-exchange-holiday-calendar/1"
_DEFAULT_CONFIGURATION = ReferenceConfiguration()


@dataclass(frozen=True, slots=True)
class _Row:
    price: DailyPrice
    opens_at: datetime
    closes_at: datetime
    available_at: datetime
    raw_sha256: str
    observed_at: datetime | None = None


def canonical_events(events: tuple[EngineEvent, ...]) -> tuple[EngineEvent, ...]:
    result: dict[str, EngineEvent] = {}
    for event in events:
        previous = result.get(event.event_id)
        if previous is not None and previous != event:
            raise ValueError("conflicting engine event identity")
        result[event.event_id] = event
    return tuple(result[key] for key in sorted(result))


def _events(
    rows: tuple[_Row, ...],
    *,
    data_class: ResearchDataClass,
    namespace: str,
    limitations: tuple[str, ...],
) -> tuple[EngineEvent, ...]:
    events: list[EngineEvent] = []
    for row in rows:
        p = row.price
        key = f"{namespace}:{p.instrument_id}:{p.session.isoformat()}"
        observation = ExecutionObservation(
            observation_id=key + ":raw-open",
            instrument_id=p.instrument_id,
            symbol=p.symbol,
            session=p.session,
            price=p.open_price,
            economic_at=row.opens_at,
            knowledge_at=row.opens_at,
            model_id="next-regular-open-proxy-v1",
            source_sha256=content_digest((p.instrument_id, p.session, p.open_price, row.opens_at)),
        )
        events.append(
            EngineEvent(
                observation.observation_id,
                row.opens_at,
                row.opens_at,
                observation,
                ObservationProvenance(
                    data_class,
                    namespace,
                    content_digest(observation),
                    observed_at=row.observed_at,
                    simulated_available_at=row.opens_at,
                    assumption_id=OPEN_PROXY_ASSUMPTION,
                    raw_sha256=row.raw_sha256,
                    limitations=(*limitations, OPEN_PROXY_ASSUMPTION),
                ),
            )
        )
        events.append(
            EngineEvent(
                key + ":daily:1",
                row.closes_at,
                row.available_at,
                p,
                ObservationProvenance(
                    data_class,
                    namespace,
                    content_digest(p),
                    observed_at=row.observed_at,
                    simulated_available_at=row.available_at,
                    assumption_id=DAILY_AVAILABILITY_POLICY,
                    raw_sha256=row.raw_sha256,
                    limitations=limitations,
                ),
            )
        )
        if p.symbol == "SPY":
            benchmark = BenchmarkPrice(
                "SPY-total-return-units/1",
                p.adjusted_close,
                "synthetic_total_return_units"
                if data_class is ResearchDataClass.SYNTHETIC_FIXTURE
                else "adjusted_total_return_units",
            )
            events.append(
                EngineEvent(
                    key + ":benchmark:1",
                    row.closes_at,
                    row.available_at,
                    benchmark,
                    ObservationProvenance(
                        data_class,
                        namespace,
                        content_digest(benchmark),
                        observed_at=row.observed_at,
                        simulated_available_at=row.available_at,
                        assumption_id=DAILY_AVAILABILITY_POLICY,
                        raw_sha256=row.raw_sha256,
                        limitations=limitations,
                    ),
                )
            )
    return canonical_events(tuple(events))


def _inputs(
    *,
    dataset_id: str,
    dataset_sha256: str,
    rows: tuple[_Row, ...],
    data_class: ResearchDataClass,
    namespace: str,
    calendar: ResearchCalendar,
    instruments: tuple[tuple[str, str], ...],
    configuration: ReferenceConfiguration,
    evaluation: EvaluationSpec,
    settlement_calendar: SettlementCalendar,
    pins: tuple[VersionPin, ...],
    limitations: tuple[str, ...],
    initial_cash: Decimal,
    slippage_bps: Decimal,
    fee_per_share: Decimal,
) -> EngineInputs:
    events = _events(rows, data_class=data_class, namespace=namespace, limitations=limitations)
    account = AccountingState("personal-historical-simulation")
    execution = ExecutionPolicy(
        settlement_calendar, slippage_bps=slippage_bps, fee_per_share=fee_per_share
    )
    risk = DailyRiskPolicy(fee_per_share=fee_per_share)
    strategy = VersionPin(
        "strategy",
        "personal-daily-reference/1",
        content_digest((configuration, "reference-callback-adapter/1")),
    )
    spec = RunSpec(
        account_id=account.account_id,
        dataset_id=dataset_id,
        dataset_sha256=dataset_sha256,
        events_sha256=content_digest(events),
        data_class=data_class,
        availability_mode="modeled",
        instruments=instruments,
        calendar=calendar,
        strategy=strategy,
        strategy_configuration=configuration,
        evaluation=evaluation,
        execution_policy=execution,
        risk_policy=risk,
        pins=pins,
        initial_state_sha256=account.semantic_sha256,
        initial_cash=initial_cash,
        limitations=tuple(
            sorted(
                set((*limitations, OPEN_PROXY_ASSUMPTION, "exploratory-not-trading-qualification"))
            )
        ),
    )
    return EngineInputs(spec, events, account)


def research_engine_inputs(
    dataset: ResearchDataset,
    *,
    configuration: ReferenceConfiguration,
    evaluation: EvaluationSpec,
    settlement_calendar: SettlementCalendar,
    pins: tuple[VersionPin, ...],
    initial_cash: Decimal = Decimal("10000"),
    slippage_bps: Decimal = Decimal("5"),
    fee_per_share: Decimal = Decimal("0.01"),
) -> EngineInputs:
    """Convert a previously validated W1 archive without fetching provider data."""
    if any(row.div_cash != 0 or row.split_factor != 1 for row in dataset.rows):
        raise ValueError(
            "dataset action candidates require explicit qualified action and payable facts"
        )
    rows = tuple(
        _Row(
            DailyPrice(
                row.instrument_id,
                row.symbol,
                row.session_label,
                row.open_price,
                row.close_price,
                row.adjusted_close_price,
            ),
            row.interval_start,
            row.interval_end,
            row.simulated_available_at,
            row.raw_object_sha256,
            row.observed_available_at,
        )
        for row in dataset.rows
    )
    return _inputs(
        dataset_id=dataset.dataset_id,
        dataset_sha256=content_digest((dataset.manifest, dataset.rows)),
        rows=rows,
        data_class=dataset.manifest.data_class,
        namespace=dataset.manifest.source_id,
        calendar=dataset.manifest.calendar,
        instruments=tuple(sorted((i, s) for s, i in dataset.manifest.instruments)),
        configuration=configuration,
        evaluation=evaluation,
        settlement_calendar=settlement_calendar,
        pins=pins,
        limitations=dataset.manifest.exclusions,
        initial_cash=initial_cash,
        slippage_bps=slippage_bps,
        fee_per_share=fee_per_share,
    )


def synthetic_engine_inputs(
    *,
    fixture: Literal["flat", "regime"],
    pins: tuple[VersionPin, ...],
    configuration: ReferenceConfiguration = _DEFAULT_CONFIGURATION,
    session_count: int = 520,
    warmup_count: int = 252,
    start: date = date(2023, 1, 2),
    initial_cash: Decimal = Decimal("10000"),
    slippage_bps: Decimal = Decimal("5"),
    fee_per_share: Decimal = Decimal("0.01"),
) -> EngineInputs:
    """Transparent engineering data, including synthetic holiday/settlement assumptions."""
    if (
        fixture not in ("flat", "regime")
        or type(session_count) is not int
        or not 2 <= session_count <= 5000
    ):
        raise ValueError("unsupported fixture or bounded session count")
    if type(warmup_count) is not int or not 0 <= warmup_count < session_count:
        raise ValueError("warmup must leave scored sessions")
    dates: list[date] = []
    current = start
    while len(dates) < session_count + 6:
        if current.weekday() < 5:
            dates.append(current)
        current += timedelta(days=1)
    zone = ZoneInfo("America/New_York")
    sessions = tuple(
        ResearchSession(
            "SYNTHETIC",
            label,
            datetime.combine(label, time(9, 30), zone).astimezone(UTC),
            datetime.combine(label, time(16), zone).astimezone(UTC),
            "regular",
        )
        for label in dates[: session_count + 1]
    )
    calendar = ResearchCalendar(SYNTHETIC_CALENDAR, "1", "SYNTHETIC", "America/New_York", sessions)
    settlement = SettlementCalendar(
        "synthetic-weekday-settlement-not-bank-holidays", "1", tuple(dates)
    )
    rows: list[_Row] = []
    previous = Decimal(100)
    for index, session in enumerate(sessions[:session_count]):
        # A known formula, not market data or a tuned investment strategy.
        change = (
            Decimal(0)
            if fixture == "flat"
            else exact_decimal_multiply(Decimal(min(index, session_count - index)), Decimal("0.1"))
        )
        close = exact_decimal_add(Decimal(100), change)
        price = DailyPrice("US-ETF-SPY", "SPY", session.session_label, previous, close, close)
        rows.append(
            _Row(
                price,
                session.opens_at,
                session.closes_at,
                modeled_daily_availability(session.session_label),
                content_digest((fixture, price)),
            )
        )
        previous = close
    dataset_sha = content_digest(("engineering-daily-fixture/1", fixture, tuple(rows), calendar))
    return _inputs(
        dataset_id="synthetic-" + dataset_sha,
        dataset_sha256=dataset_sha,
        rows=tuple(rows),
        data_class=ResearchDataClass.SYNTHETIC_FIXTURE,
        namespace="engineering-daily-fixture/1",
        calendar=calendar,
        instruments=(("US-ETF-SPY", "SPY"),),
        configuration=configuration,
        evaluation=EvaluationSpec(
            "synthetic-full-history",
            tuple(dates[:warmup_count]),
            tuple(dates[warmup_count:session_count]),
            "reusable-engineering-fixture-no-holdout",
        ),
        settlement_calendar=settlement,
        pins=pins,
        limitations=(
            SYNTHETIC_CALENDAR,
            "synthetic-prices-no-empirical-liquidity",
            "no-empirical-strategy-evidence",
        ),
        initial_cash=initial_cash,
        slippage_bps=slippage_bps,
        fee_per_share=fee_per_share,
    )
