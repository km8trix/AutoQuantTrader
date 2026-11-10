"""Receipt-time local lineage for complete, verified Tiingo EOD captures.

This module compares independently verified research snapshots. It records only
when AutoQuantTrader observed each retained delivery and never assigns a vendor
publication timestamp, vendor revision, canonical-bar authority, or admission.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import Decimal
from enum import StrEnum
from itertools import pairwise
from typing import NoReturn

from packages.adapters.market_data.tiingo_eod import (
    TiingoEodError,
    TiingoEodRow,
    TiingoEodScope,
)
from packages.adapters.market_data.tiingo_eod_snapshot import (
    TiingoEodVerifiedResearchSnapshot,
)
from packages.market_data.models import require_digest, require_utc

TIINGO_EOD_RECEIPT_LINEAGE_SCHEMA_VERSION = "tiingo-eod-receipt-lineage-v1"
TIINGO_EOD_RECEIPT_LINEAGE_POLICY = "first-observed-local-revisions-v1"
_ECONOMICS_SCHEMA_VERSION = "tiingo-eod-row-economics-v1"
_REVISION_SCHEMA_VERSION = "tiingo-eod-local-revision-v1"


def _digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _decimal_text(value: Decimal) -> str:
    """Return a compact canonical encoding without expanding the exponent."""

    if not value.is_finite():
        raise TiingoEodError("lineage economics require finite decimals")
    sign, raw_digits, raw_exponent = value.as_tuple()
    if not any(raw_digits):
        return "0"
    digits = list(raw_digits)
    exponent = int(raw_exponent)
    while digits[-1] == 0:
        digits.pop()
        exponent += 1
    coefficient = "".join(str(digit) for digit in digits)
    prefix = "-" if sign else ""
    return f"{prefix}{coefficient}e{exponent}"


def _economics_material(row: TiingoEodRow) -> dict[str, object]:
    return {
        "adjusted_close_price": _decimal_text(row.adjusted_close_price),
        "adjusted_high_price": _decimal_text(row.adjusted_high_price),
        "adjusted_low_price": _decimal_text(row.adjusted_low_price),
        "adjusted_open_price": _decimal_text(row.adjusted_open_price),
        "adjusted_price_basis": row.adjusted_price_basis.value,
        "adjusted_volume": row.adjusted_volume,
        "close_price": _decimal_text(row.close_price),
        "div_cash": _decimal_text(row.div_cash),
        "high_price": _decimal_text(row.high_price),
        "interval": row.interval.value,
        "low_price": _decimal_text(row.low_price),
        "open_price": _decimal_text(row.open_price),
        "raw_price_basis": row.raw_price_basis.value,
        "schema_version": _ECONOMICS_SCHEMA_VERSION,
        "split_factor": _decimal_text(row.split_factor),
        "volume": row.volume,
    }


def _economics_sha256(row: TiingoEodRow) -> str:
    return _digest(_economics_material(row))


def _local_observation_id(
    *,
    profile_contract_sha256: str,
    calendar_artifact_sha256: str,
    symbol: str,
    session_label: date,
) -> str:
    return _digest(
        {
            "calendar_artifact_sha256": calendar_artifact_sha256,
            "profile_contract_sha256": profile_contract_sha256,
            "schema_version": TIINGO_EOD_RECEIPT_LINEAGE_SCHEMA_VERSION,
            "session_label": session_label.isoformat(),
            "symbol": symbol,
        }
    )


class TiingoEodReceiptDisposition(StrEnum):
    """How one complete delivery relates to the latest local row version."""

    INITIAL = "initial"
    UNCHANGED = "unchanged"
    CHANGED = "changed"


@dataclass(frozen=True, slots=True, init=False)
class TiingoEodLocalRevision:
    """One locally observed economic version, never a vendor revision."""

    local_observation_id: str
    symbol: str
    session_label: date
    local_revision: int
    observed_at: datetime
    capture_sha256: str
    snapshot_semantic_sha256: str
    response_sha256: str
    economics_sha256: str
    revision_sha256: str
    supersedes_revision_sha256: str | None
    row: TiingoEodRow = field(repr=False)

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("Tiingo EOD local revisions can only be derived from verified proofs")

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.local_observation_id, "local_observation_id"),
            (self.capture_sha256, "capture_sha256"),
            (self.snapshot_semantic_sha256, "snapshot_semantic_sha256"),
            (self.response_sha256, "response_sha256"),
            (self.economics_sha256, "economics_sha256"),
            (self.revision_sha256, "revision_sha256"),
        ):
            require_digest(value, field_name)
        if self.supersedes_revision_sha256 is not None:
            require_digest(self.supersedes_revision_sha256, "supersedes_revision_sha256")
        if type(self.session_label) is not date:
            raise ValueError("session_label must be a date")
        if type(self.local_revision) is not int or self.local_revision < 1:
            raise ValueError("local_revision must be a positive integer")
        if self.local_revision == 1 and self.supersedes_revision_sha256 is not None:
            raise ValueError("an initial local revision cannot supersede another revision")
        if self.local_revision > 1 and self.supersedes_revision_sha256 is None:
            raise ValueError("a changed local revision must identify its predecessor")
        require_utc(self.observed_at, "observed_at")
        if type(self.row) is not TiingoEodRow:
            raise ValueError("a local revision requires an exact Tiingo EOD row")
        if (
            self.row.symbol != self.symbol
            or self.row.session_label != self.session_label
            or self.row.observed_at != self.observed_at
            or self.row.response_sha256 != self.response_sha256
        ):
            raise ValueError("local revision metadata does not match its exact row")
        if _economics_sha256(self.row) != self.economics_sha256:
            raise ValueError("local revision economics digest does not match its row")


@dataclass(frozen=True, slots=True, init=False)
class TiingoEodReceiptComparison:
    """One capture/key occurrence and its effective local revision."""

    local_observation_id: str
    symbol: str
    session_label: date
    capture_sha256: str
    snapshot_semantic_sha256: str
    response_sha256: str
    observed_at: datetime
    economics_sha256: str
    disposition: TiingoEodReceiptDisposition
    effective_local_revision: int
    effective_revision_sha256: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("Tiingo EOD receipt comparisons can only be derived from verified proofs")

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.local_observation_id, "local_observation_id"),
            (self.capture_sha256, "capture_sha256"),
            (self.snapshot_semantic_sha256, "snapshot_semantic_sha256"),
            (self.response_sha256, "response_sha256"),
            (self.economics_sha256, "economics_sha256"),
            (self.effective_revision_sha256, "effective_revision_sha256"),
        ):
            require_digest(value, field_name)
        if type(self.session_label) is not date:
            raise ValueError("session_label must be a date")
        require_utc(self.observed_at, "observed_at")
        if type(self.disposition) is not TiingoEodReceiptDisposition:
            raise ValueError("disposition must be an exact Tiingo receipt disposition")
        if type(self.effective_local_revision) is not int or self.effective_local_revision < 1:
            raise ValueError("effective_local_revision must be a positive integer")


def _revision_sha256(
    revision: TiingoEodLocalRevision,
    *,
    profile_contract_sha256: str,
    calendar_artifact_sha256: str,
) -> str:
    return _digest(
        {
            "calendar_artifact_sha256": calendar_artifact_sha256,
            "capture_sha256": revision.capture_sha256,
            "economics_sha256": revision.economics_sha256,
            "local_observation_id": revision.local_observation_id,
            "local_revision": revision.local_revision,
            "observed_at": revision.observed_at.isoformat(),
            "policy": TIINGO_EOD_RECEIPT_LINEAGE_POLICY,
            "profile_contract_sha256": profile_contract_sha256,
            "response_sha256": revision.response_sha256,
            "schema_version": _REVISION_SCHEMA_VERSION,
            "session_label": revision.session_label.isoformat(),
            "snapshot_semantic_sha256": revision.snapshot_semantic_sha256,
            "supersedes_revision_sha256": revision.supersedes_revision_sha256,
            "symbol": revision.symbol,
        }
    )


def _make_revision(
    *,
    row: TiingoEodRow,
    local_observation_id: str,
    local_revision: int,
    capture_sha256: str,
    snapshot_semantic_sha256: str,
    economics_sha256: str,
    supersedes_revision_sha256: str | None,
    profile_contract_sha256: str,
    calendar_artifact_sha256: str,
) -> TiingoEodLocalRevision:
    revision = object.__new__(TiingoEodLocalRevision)
    for field_name, value in (
        ("local_observation_id", local_observation_id),
        ("symbol", row.symbol),
        ("session_label", row.session_label),
        ("local_revision", local_revision),
        ("observed_at", row.observed_at),
        ("capture_sha256", capture_sha256),
        ("snapshot_semantic_sha256", snapshot_semantic_sha256),
        ("response_sha256", row.response_sha256),
        ("economics_sha256", economics_sha256),
        ("supersedes_revision_sha256", supersedes_revision_sha256),
        ("row", row),
    ):
        object.__setattr__(revision, field_name, value)
    digest = _revision_sha256(
        revision,
        profile_contract_sha256=profile_contract_sha256,
        calendar_artifact_sha256=calendar_artifact_sha256,
    )
    object.__setattr__(revision, "revision_sha256", digest)
    revision.__post_init__()
    return revision


def _make_comparison(
    *,
    row: TiingoEodRow,
    local_observation_id: str,
    capture_sha256: str,
    snapshot_semantic_sha256: str,
    economics_sha256: str,
    disposition: TiingoEodReceiptDisposition,
    effective: TiingoEodLocalRevision,
) -> TiingoEodReceiptComparison:
    comparison = object.__new__(TiingoEodReceiptComparison)
    for field_name, value in (
        ("local_observation_id", local_observation_id),
        ("symbol", row.symbol),
        ("session_label", row.session_label),
        ("capture_sha256", capture_sha256),
        ("snapshot_semantic_sha256", snapshot_semantic_sha256),
        ("response_sha256", row.response_sha256),
        ("observed_at", row.observed_at),
        ("economics_sha256", economics_sha256),
        ("disposition", disposition),
        ("effective_local_revision", effective.local_revision),
        ("effective_revision_sha256", effective.revision_sha256),
    ):
        object.__setattr__(comparison, field_name, value)
    comparison.__post_init__()
    return comparison


@dataclass(frozen=True, slots=True)
class _DerivedLineage:
    profile_contract_sha256: str
    calendar_artifact_sha256: str
    scope: TiingoEodScope
    revisions: tuple[TiingoEodLocalRevision, ...]
    comparisons: tuple[TiingoEodReceiptComparison, ...]
    lineage_sha256: str


def _validate_snapshots(
    snapshots: tuple[TiingoEodVerifiedResearchSnapshot, ...],
) -> None:
    if type(snapshots) is not tuple or len(snapshots) < 2:
        raise TiingoEodError(
            "receipt-time lineage requires at least two verified snapshots in an exact tuple"
        )
    if any(type(snapshot) is not TiingoEodVerifiedResearchSnapshot for snapshot in snapshots):
        raise TiingoEodError("receipt-time lineage requires exact verified snapshot proofs")
    for snapshot in snapshots:
        try:
            snapshot.__post_init__()
        except ValueError as error:
            raise TiingoEodError(f"verified snapshot proof is invalid: {error}") from error

    reference = snapshots[0]
    profile = reference.manifest.profile
    if profile.correction_policy != TIINGO_EOD_RECEIPT_LINEAGE_POLICY:
        raise TiingoEodError("acquisition profile uses an unsupported local lineage policy")
    capture_digests = tuple(snapshot.capture_sha256 for snapshot in snapshots)
    if len(capture_digests) != len(set(capture_digests)):
        raise TiingoEodError("receipt-time lineage contains a duplicate capture")
    semantic_digests = tuple(snapshot.semantic_sha256 for snapshot in snapshots)
    if len(semantic_digests) != len(set(semantic_digests)):
        raise TiingoEodError("receipt-time lineage contains a duplicate snapshot proof")

    reference_keys = tuple((row.symbol, row.session_label) for row in reference.rows)
    for snapshot in snapshots[1:]:
        if (
            snapshot.manifest.profile != profile
            or snapshot.manifest.profile_contract_sha256 != profile.contract_sha256
        ):
            raise TiingoEodError("receipt-time lineage snapshots do not share one exact profile")
        if (
            snapshot.calendar_artifact_sha256 != reference.calendar_artifact_sha256
            or snapshot.calendar_artifact != reference.calendar_artifact
            or snapshot.calendar_bindings != reference.calendar_bindings
        ):
            raise TiingoEodError(
                "receipt-time lineage snapshots do not share one exact calendar artifact"
            )
        keys = tuple((row.symbol, row.session_label) for row in snapshot.rows)
        if keys != reference_keys:
            raise TiingoEodError(
                "receipt-time lineage requires identical complete symbol/session coverage; "
                "missing or extra rows are not deletions"
            )
    for previous, current in pairwise(snapshots):
        if current.manifest.requested_at <= previous.manifest.received_at:
            raise TiingoEodError(
                "receipt-time lineage snapshots must be strictly chronological and non-overlapping"
            )


def _lineage_sha256(
    *,
    snapshots: tuple[TiingoEodVerifiedResearchSnapshot, ...],
    profile_contract_sha256: str,
    calendar_artifact_sha256: str,
    scope: TiingoEodScope,
    revisions: tuple[TiingoEodLocalRevision, ...],
    comparisons: tuple[TiingoEodReceiptComparison, ...],
) -> str:
    return _digest(
        {
            "calendar_artifact_sha256": calendar_artifact_sha256,
            "captures": [
                {
                    "capture_sha256": snapshot.capture_sha256,
                    "received_at": snapshot.manifest.received_at.isoformat(),
                    "requested_at": snapshot.manifest.requested_at.isoformat(),
                    "snapshot_semantic_sha256": snapshot.semantic_sha256,
                }
                for snapshot in snapshots
            ],
            "comparisons": [
                {
                    "capture_sha256": comparison.capture_sha256,
                    "disposition": comparison.disposition.value,
                    "economics_sha256": comparison.economics_sha256,
                    "effective_local_revision": comparison.effective_local_revision,
                    "effective_revision_sha256": comparison.effective_revision_sha256,
                    "local_observation_id": comparison.local_observation_id,
                    "observed_at": comparison.observed_at.isoformat(),
                    "response_sha256": comparison.response_sha256,
                    "session_label": comparison.session_label.isoformat(),
                    "snapshot_semantic_sha256": comparison.snapshot_semantic_sha256,
                    "symbol": comparison.symbol,
                }
                for comparison in comparisons
            ],
            "policy": TIINGO_EOD_RECEIPT_LINEAGE_POLICY,
            "profile_contract_sha256": profile_contract_sha256,
            "revisions": [revision.revision_sha256 for revision in revisions],
            "schema_version": TIINGO_EOD_RECEIPT_LINEAGE_SCHEMA_VERSION,
            "scope": scope.to_dict(),
        }
    )


def _derive_components(
    snapshots: tuple[TiingoEodVerifiedResearchSnapshot, ...],
) -> _DerivedLineage:
    _validate_snapshots(snapshots)
    reference = snapshots[0]
    profile_contract_sha256 = reference.manifest.profile_contract_sha256
    calendar_artifact_sha256 = reference.calendar_artifact_sha256
    scope = reference.manifest.profile.scope
    latest_by_key: dict[tuple[str, date], TiingoEodLocalRevision] = {}
    last_observed_by_key: dict[tuple[str, date], datetime] = {}
    revisions: list[TiingoEodLocalRevision] = []
    comparisons: list[TiingoEodReceiptComparison] = []

    for snapshot in snapshots:
        for row in snapshot.rows:
            key = (row.symbol, row.session_label)
            previous_observed_at = last_observed_by_key.get(key)
            if previous_observed_at is not None and row.observed_at <= previous_observed_at:
                raise TiingoEodError(
                    "receipt-time lineage row observations must be strictly chronological"
                )
            last_observed_by_key[key] = row.observed_at
            economics_sha256 = _economics_sha256(row)
            local_observation_id = _local_observation_id(
                profile_contract_sha256=profile_contract_sha256,
                calendar_artifact_sha256=calendar_artifact_sha256,
                symbol=row.symbol,
                session_label=row.session_label,
            )
            previous = latest_by_key.get(key)
            if previous is None:
                disposition = TiingoEodReceiptDisposition.INITIAL
                effective = _make_revision(
                    row=row,
                    local_observation_id=local_observation_id,
                    local_revision=1,
                    capture_sha256=snapshot.capture_sha256,
                    snapshot_semantic_sha256=snapshot.semantic_sha256,
                    economics_sha256=economics_sha256,
                    supersedes_revision_sha256=None,
                    profile_contract_sha256=profile_contract_sha256,
                    calendar_artifact_sha256=calendar_artifact_sha256,
                )
                revisions.append(effective)
                latest_by_key[key] = effective
            elif previous.economics_sha256 == economics_sha256:
                disposition = TiingoEodReceiptDisposition.UNCHANGED
                effective = previous
            else:
                disposition = TiingoEodReceiptDisposition.CHANGED
                effective = _make_revision(
                    row=row,
                    local_observation_id=local_observation_id,
                    local_revision=previous.local_revision + 1,
                    capture_sha256=snapshot.capture_sha256,
                    snapshot_semantic_sha256=snapshot.semantic_sha256,
                    economics_sha256=economics_sha256,
                    supersedes_revision_sha256=previous.revision_sha256,
                    profile_contract_sha256=profile_contract_sha256,
                    calendar_artifact_sha256=calendar_artifact_sha256,
                )
                revisions.append(effective)
                latest_by_key[key] = effective
            comparisons.append(
                _make_comparison(
                    row=row,
                    local_observation_id=local_observation_id,
                    capture_sha256=snapshot.capture_sha256,
                    snapshot_semantic_sha256=snapshot.semantic_sha256,
                    economics_sha256=economics_sha256,
                    disposition=disposition,
                    effective=effective,
                )
            )

    ordered_revisions = tuple(
        sorted(
            revisions,
            key=lambda revision: (
                revision.symbol,
                revision.session_label,
                revision.local_revision,
            ),
        )
    )
    ordered_comparisons = tuple(comparisons)
    lineage_sha256 = _lineage_sha256(
        snapshots=snapshots,
        profile_contract_sha256=profile_contract_sha256,
        calendar_artifact_sha256=calendar_artifact_sha256,
        scope=scope,
        revisions=ordered_revisions,
        comparisons=ordered_comparisons,
    )
    return _DerivedLineage(
        profile_contract_sha256=profile_contract_sha256,
        calendar_artifact_sha256=calendar_artifact_sha256,
        scope=scope,
        revisions=ordered_revisions,
        comparisons=ordered_comparisons,
        lineage_sha256=lineage_sha256,
    )


@dataclass(frozen=True, slots=True, init=False)
class TiingoEodReceiptTimeLineage:
    """Proof-derived local lineage with no admission or trading authority."""

    snapshots: tuple[TiingoEodVerifiedResearchSnapshot, ...] = field(repr=False)
    profile_contract_sha256: str
    calendar_artifact_sha256: str
    scope: TiingoEodScope
    revisions: tuple[TiingoEodLocalRevision, ...]
    comparisons: tuple[TiingoEodReceiptComparison, ...]
    lineage_sha256: str
    schema_version: str = TIINGO_EOD_RECEIPT_LINEAGE_SCHEMA_VERSION
    policy: str = TIINGO_EOD_RECEIPT_LINEAGE_POLICY

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("Tiingo EOD receipt-time lineage can only be created from verified proofs")

    @classmethod
    def _from_verified_snapshots(
        cls,
        snapshots: tuple[TiingoEodVerifiedResearchSnapshot, ...],
    ) -> TiingoEodReceiptTimeLineage:
        if cls is not TiingoEodReceiptTimeLineage:
            raise TypeError("Tiingo EOD receipt-time lineage subclasses are not supported")
        derived = _derive_components(snapshots)
        lineage = object.__new__(cls)
        for field_name, value in (
            ("snapshots", snapshots),
            ("profile_contract_sha256", derived.profile_contract_sha256),
            ("calendar_artifact_sha256", derived.calendar_artifact_sha256),
            ("scope", derived.scope),
            ("revisions", derived.revisions),
            ("comparisons", derived.comparisons),
            ("lineage_sha256", derived.lineage_sha256),
            ("schema_version", TIINGO_EOD_RECEIPT_LINEAGE_SCHEMA_VERSION),
            ("policy", TIINGO_EOD_RECEIPT_LINEAGE_POLICY),
        ):
            object.__setattr__(lineage, field_name, value)
        lineage.__post_init__()
        return lineage

    def __post_init__(self) -> None:
        require_digest(self.profile_contract_sha256, "profile_contract_sha256")
        require_digest(self.calendar_artifact_sha256, "calendar_artifact_sha256")
        require_digest(self.lineage_sha256, "lineage_sha256")
        if self.schema_version != TIINGO_EOD_RECEIPT_LINEAGE_SCHEMA_VERSION:
            raise ValueError("unsupported Tiingo EOD receipt-lineage schema")
        if self.policy != TIINGO_EOD_RECEIPT_LINEAGE_POLICY:
            raise ValueError("unsupported Tiingo EOD receipt-lineage policy")
        derived = _derive_components(self.snapshots)
        if (
            self.profile_contract_sha256 != derived.profile_contract_sha256
            or self.calendar_artifact_sha256 != derived.calendar_artifact_sha256
            or self.scope != derived.scope
            or self.revisions != derived.revisions
            or self.comparisons != derived.comparisons
            or self.lineage_sha256 != derived.lineage_sha256
        ):
            raise ValueError("receipt-time lineage does not match its verified snapshot proofs")

    def raw_bar_records(self) -> NoReturn:
        raise TiingoEodError(
            "receipt-time local lineage does not establish execution-safe raw bars"
        )

    def canonical_bar_records(self) -> NoReturn:
        raise TiingoEodError("receipt-time local lineage cannot become canonical bars")

    def admission_evidence(self) -> NoReturn:
        raise TiingoEodError(
            "receipt-time local lineage is research-only and permanently non-admitting"
        )

    def historical_bar_source(self) -> NoReturn:
        raise TiingoEodError("receipt-time local lineage cannot become a HistoricalBarSource")


def derive_tiingo_eod_receipt_lineage(
    snapshots: tuple[TiingoEodVerifiedResearchSnapshot, ...],
) -> TiingoEodReceiptTimeLineage:
    """Derive deterministic local versions from complete verified captures."""

    return TiingoEodReceiptTimeLineage._from_verified_snapshots(snapshots)


__all__ = [
    "TIINGO_EOD_RECEIPT_LINEAGE_POLICY",
    "TIINGO_EOD_RECEIPT_LINEAGE_SCHEMA_VERSION",
    "TiingoEodLocalRevision",
    "TiingoEodReceiptComparison",
    "TiingoEodReceiptDisposition",
    "TiingoEodReceiptTimeLineage",
    "derive_tiingo_eod_receipt_lineage",
]
