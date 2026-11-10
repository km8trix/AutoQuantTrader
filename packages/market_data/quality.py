"""Deterministic market-data quality checks over canonical raw bars."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from itertools import pairwise

from packages.domain.identifiers import deterministic_id
from packages.market_data.calendar import ExchangeCalendar
from packages.market_data.models import (
    BarInterval,
    RawBar,
    RevisionPolicy,
    require_text,
    require_utc,
)
from packages.market_data.temporal import select_as_of_for_quality


class QualityCode(StrEnum):
    GAP = "gap"
    DUPLICATE = "duplicate"
    OHLC_INVALID = "ohlc_invalid"
    STALE = "stale"
    EXTREME_RETURN = "extreme_return"
    REVISION_CONFLICT = "revision_conflict"
    REVISION_SEQUENCE = "revision_sequence"
    TIMEZONE_INVALID = "timezone_invalid"
    SESSION_MISMATCH = "session_mismatch"
    UNKNOWN_SECURITY = "unknown_security"
    NON_TRADABLE = "non_tradable"
    TEMPORAL_INVALID = "temporal_invalid"


class QualitySeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class QualityIssue:
    issue_id: str
    code: QualityCode
    severity: QualitySeverity
    message: str
    source_id: str | None = None
    security_id: str | None = None
    observation_id: str | None = None
    event_revision_id: str | None = None
    session_label: date | None = None
    occurred_at: datetime | None = None
    details: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        require_text(self.issue_id, "issue_id")
        require_text(self.message, "message")
        if self.occurred_at is not None:
            require_utc(self.occurred_at, "occurred_at")
        if self.details != tuple(sorted(self.details)):
            raise ValueError("quality issue details must use stable key order")
        if len({key for key, _ in self.details}) != len(self.details):
            raise ValueError("quality issue detail keys must be unique")

    @property
    def blocking(self) -> bool:
        return self.severity in {QualitySeverity.ERROR, QualitySeverity.CRITICAL}


def quality_issue(
    code: QualityCode,
    severity: QualitySeverity,
    message: str,
    *,
    source_id: str | None = None,
    security_id: str | None = None,
    observation_id: str | None = None,
    event_revision_id: str | None = None,
    session_label: date | None = None,
    occurred_at: datetime | None = None,
    details: Iterable[tuple[str, str]] = (),
) -> QualityIssue:
    stable_details = tuple(sorted(details))
    issue_id = deterministic_id(
        "data-quality-issue",
        code.value,
        severity.value,
        source_id,
        security_id,
        observation_id,
        event_revision_id,
        session_label,
        occurred_at,
        stable_details,
        message,
    )
    return QualityIssue(
        issue_id=issue_id,
        code=code,
        severity=severity,
        message=message,
        source_id=source_id,
        security_id=security_id,
        observation_id=observation_id,
        event_revision_id=event_revision_id,
        session_label=session_label,
        occurred_at=occurred_at,
        details=stable_details,
    )


def _revision_issues(bars: tuple[RawBar, ...]) -> list[QualityIssue]:
    issues: list[QualityIssue] = []
    by_observation: dict[str, list[RawBar]] = defaultdict(list)
    for bar in bars:
        by_observation[bar.observation_id].append(bar)
    for observation_id, revisions in sorted(by_observation.items()):
        by_number: dict[int, list[RawBar]] = defaultdict(list)
        for bar in revisions:
            by_number[bar.revision].append(bar)
        for revision, same_revision in sorted(by_number.items()):
            payloads = {bar.payload_sha256 for bar in same_revision}
            event_ids = {bar.event_revision_id for bar in same_revision}
            if len(payloads) > 1 or len(event_ids) > 1:
                exemplar = min(same_revision, key=lambda bar: bar.event_revision_id)
                issues.append(
                    quality_issue(
                        QualityCode.REVISION_CONFLICT,
                        QualitySeverity.ERROR,
                        "one observation has conflicting facts at the same revision",
                        source_id=exemplar.source_id,
                        security_id=exemplar.security_id,
                        observation_id=observation_id,
                        occurred_at=exemplar.available_at,
                        details=(("revision", str(revision)),),
                    )
                )
        numbers = sorted(by_number)
        if numbers != list(range(1, max(numbers) + 1)):
            exemplar = min(revisions, key=lambda bar: bar.event_revision_id)
            issues.append(
                quality_issue(
                    QualityCode.REVISION_SEQUENCE,
                    QualitySeverity.ERROR,
                    "revision sequence must be contiguous and begin at one",
                    source_id=exemplar.source_id,
                    security_id=exemplar.security_id,
                    observation_id=observation_id,
                    occurred_at=exemplar.available_at,
                    details=(("revisions", ",".join(str(value) for value in numbers)),),
                )
            )
        previous: RawBar | None = None
        for revision in numbers:
            current = min(by_number[revision], key=lambda bar: bar.event_revision_id)
            if previous is not None and (
                current.available_at < previous.available_at
                or current.supersedes_event_revision_id != previous.event_revision_id
            ):
                issues.append(
                    quality_issue(
                        QualityCode.REVISION_SEQUENCE,
                        QualitySeverity.ERROR,
                        "correction lineage or availability order is inconsistent",
                        source_id=current.source_id,
                        security_id=current.security_id,
                        observation_id=observation_id,
                        event_revision_id=current.event_revision_id,
                        occurred_at=current.available_at,
                        details=(("revision", str(current.revision)),),
                    )
                )
            previous = current
    return issues


def _duplicate_issues(bars: tuple[RawBar, ...]) -> list[QualityIssue]:
    issues: list[QualityIssue] = []
    by_natural_key: dict[tuple[object, ...], list[RawBar]] = defaultdict(list)
    for bar in bars:
        key = (
            bar.source_id,
            bar.security_id,
            bar.interval,
            bar.interval_start,
            bar.revision,
        )
        by_natural_key[key].append(bar)
    for duplicates in by_natural_key.values():
        if len(duplicates) < 2:
            continue
        exemplar = min(duplicates, key=lambda bar: bar.event_revision_id)
        issues.append(
            quality_issue(
                QualityCode.DUPLICATE,
                QualitySeverity.ERROR,
                "multiple records occupy the same source/security/bar/revision key",
                source_id=exemplar.source_id,
                security_id=exemplar.security_id,
                observation_id=exemplar.observation_id,
                event_revision_id=exemplar.event_revision_id,
                session_label=exemplar.session_label,
                occurred_at=exemplar.available_at,
                details=(("count", str(len(duplicates))),),
            )
        )
    return issues


def _session_issues(
    bars: tuple[RawBar, ...],
    calendar: ExchangeCalendar,
) -> list[QualityIssue]:
    issues: list[QualityIssue] = []
    for bar in bars:
        session = calendar.session_for_label(bar.session_label)
        if (
            bar.venue != calendar.venue
            or session is None
            or not session.contains_bar(bar.interval_start, bar.interval_end, bar.interval)
        ):
            issues.append(
                quality_issue(
                    QualityCode.SESSION_MISMATCH,
                    QualitySeverity.ERROR,
                    "bar is outside its declared exchange session",
                    source_id=bar.source_id,
                    security_id=bar.security_id,
                    observation_id=bar.observation_id,
                    event_revision_id=bar.event_revision_id,
                    session_label=bar.session_label,
                    occurred_at=bar.available_at,
                )
            )
    return issues


def _gap_issues(
    selected: tuple[RawBar, ...],
    calendar: ExchangeCalendar,
    expected_session_labels: tuple[date, ...] | None,
) -> list[QualityIssue]:
    issues: list[QualityIssue] = []
    grouped: dict[tuple[str, str, BarInterval, date], set[datetime]] = defaultdict(set)
    observed_series = {(bar.source_id, bar.security_id, bar.interval) for bar in selected}
    for bar in selected:
        grouped[(bar.source_id, bar.security_id, bar.interval, bar.session_label)].add(
            bar.interval_start
        )
    if expected_session_labels is not None:
        for source_id, security_id, interval in observed_series:
            for session_label in expected_session_labels:
                grouped.setdefault((source_id, security_id, interval, session_label), set())
    else:
        labels_by_series: dict[tuple[str, str, BarInterval], set[date]] = defaultdict(set)
        for bar in selected:
            labels_by_series[(bar.source_id, bar.security_id, bar.interval)].add(bar.session_label)
        for (source_id, security_id, interval), labels in labels_by_series.items():
            if interval is not BarInterval.ONE_DAY:
                continue
            first_label = min(labels)
            last_label = max(labels)
            for calendar_session in calendar.sessions:
                if first_label <= calendar_session.session_label <= last_label:
                    grouped.setdefault(
                        (source_id, security_id, interval, calendar_session.session_label),
                        set(),
                    )

    for (source_id, security_id, interval, session_label), actual in sorted(
        grouped.items(),
        key=lambda item: (str(item[0][0]), str(item[0][1]), str(item[0][2]), item[0][3]),
    ):
        session = calendar.session_for_label(session_label)
        if session is None:
            issues.append(
                quality_issue(
                    QualityCode.SESSION_MISMATCH,
                    QualitySeverity.ERROR,
                    "bar references a session absent from the pinned calendar",
                    source_id=source_id,
                    security_id=security_id,
                    session_label=session_label,
                )
            )
            continue
        all_expected = session.expected_starts(interval)
        if expected_session_labels is None and actual:
            first_observed = min(actual)
            last_observed = max(actual)
            expected = {start for start in all_expected if first_observed <= start <= last_observed}
        else:
            expected = set(all_expected)
        missing = sorted(expected - actual)
        if missing:
            issues.append(
                quality_issue(
                    QualityCode.GAP,
                    QualitySeverity.ERROR,
                    "expected exchange-session bars are missing",
                    source_id=source_id,
                    security_id=security_id,
                    session_label=session_label,
                    occurred_at=missing[0],
                    details=(
                        ("count", str(len(missing))),
                        ("first_missing", missing[0].isoformat()),
                        ("last_missing", missing[-1].isoformat()),
                    ),
                )
            )
    return issues


def _stale_issues(
    selected: tuple[RawBar, ...],
    as_of: datetime,
    stale_after: timedelta,
    stale_after_by_interval: Mapping[BarInterval, timedelta],
) -> list[QualityIssue]:
    latest: dict[tuple[str, str, BarInterval], RawBar] = {}
    for bar in selected:
        key = (bar.source_id, bar.security_id, bar.interval)
        previous = latest.get(key)
        if previous is None or bar.available_at > previous.available_at:
            latest[key] = bar
    issues: list[QualityIssue] = []
    for bar in latest.values():
        age = as_of - bar.available_at
        budget = stale_after_by_interval.get(bar.interval, stale_after)
        if age <= budget:
            continue
        issues.append(
            quality_issue(
                QualityCode.STALE,
                QualitySeverity.WARNING,
                "latest market observation exceeds the configured age budget",
                source_id=bar.source_id,
                security_id=bar.security_id,
                observation_id=bar.observation_id,
                event_revision_id=bar.event_revision_id,
                session_label=bar.session_label,
                occurred_at=as_of,
                details=(
                    ("age_seconds", str(int(age.total_seconds()))),
                    ("budget_seconds", str(int(budget.total_seconds()))),
                    ("interval", bar.interval.value),
                ),
            )
        )
    return issues


def _extreme_return_issues(
    selected: tuple[RawBar, ...],
    threshold: Decimal,
) -> list[QualityIssue]:
    issues: list[QualityIssue] = []
    grouped: dict[tuple[str, str, BarInterval], list[RawBar]] = defaultdict(list)
    for bar in selected:
        grouped[(bar.source_id, bar.security_id, bar.interval)].append(bar)
    for series in grouped.values():
        ordered = sorted(series, key=lambda bar: (bar.interval_start, bar.event_revision_id))
        for previous, current in pairwise(ordered):
            change = abs(current.close_price / previous.close_price - Decimal("1"))
            if change >= threshold:
                issues.append(
                    quality_issue(
                        QualityCode.EXTREME_RETURN,
                        QualitySeverity.WARNING,
                        "absolute close-to-close return exceeds the configured threshold",
                        source_id=current.source_id,
                        security_id=current.security_id,
                        observation_id=current.observation_id,
                        event_revision_id=current.event_revision_id,
                        session_label=current.session_label,
                        occurred_at=current.available_at,
                        details=(
                            ("absolute_return", format(change, "f")),
                            ("threshold", format(threshold, "f")),
                        ),
                    )
                )
    return issues


def check_quality(
    bars: Iterable[RawBar],
    *,
    calendar: ExchangeCalendar,
    as_of: datetime,
    revision_policy: RevisionPolicy = RevisionPolicy.REVISED_AS_OF,
    stale_after: timedelta = timedelta(minutes=5),
    stale_after_by_interval: Mapping[BarInterval, timedelta] | None = None,
    extreme_return_threshold: Decimal = Decimal("0.25"),
    expected_session_labels: tuple[date, ...] | None = None,
) -> tuple[QualityIssue, ...]:
    """Run structural, causal, calendar, freshness, and price checks."""

    require_utc(as_of, "as_of")
    if stale_after <= timedelta(0):
        raise ValueError("stale_after must be positive")
    interval_budgets = {} if stale_after_by_interval is None else dict(stale_after_by_interval)
    if any(
        not isinstance(interval, BarInterval)
        or not isinstance(budget, timedelta)
        or budget <= timedelta(0)
        for interval, budget in interval_budgets.items()
    ):
        raise ValueError("interval freshness budgets require known intervals and positive values")
    if not extreme_return_threshold.is_finite() or extreme_return_threshold <= 0:
        raise ValueError("extreme_return_threshold must be finite and positive")
    facts = tuple(bars)
    selected = select_as_of_for_quality(
        facts,
        as_of=as_of,
        policy=revision_policy,
    )
    issues = [
        *_revision_issues(facts),
        *_duplicate_issues(facts),
        *_session_issues(selected, calendar),
        *_gap_issues(selected, calendar, expected_session_labels),
        *_stale_issues(selected, as_of, stale_after, interval_budgets),
        *_extreme_return_issues(selected, extreme_return_threshold),
    ]
    return tuple(
        sorted(
            issues,
            key=lambda issue: (
                issue.code.value,
                issue.source_id or "",
                issue.security_id or "",
                issue.occurred_at or as_of,
                issue.issue_id,
            ),
        )
    )
