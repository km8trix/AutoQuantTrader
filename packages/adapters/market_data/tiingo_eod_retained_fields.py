"""Proof-derived qualification of exact retained Tiingo EOD field routing.

This boundary proves only that one verified capture matched the frozen field
contract and the application's documented field-role policy. Observed values do
not prove genuine unadjusted prices, adjustment methodology, corporate actions,
vendor publication history, admission, or trading authority.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import StrEnum
from typing import NoReturn

from packages.adapters.market_data.tiingo_eod import (
    TIINGO_EOD_FIELD_CONTRACT,
    TIINGO_EOD_FIELDS,
    TIINGO_EOD_SCHEMA_SHA256,
    TiingoEodError,
    TiingoEodScope,
    _decimal,
    _fields,
    _integer,
    _json,
    _object,
    _trading_date,
)
from packages.adapters.market_data.tiingo_eod_snapshot import (
    TiingoEodVerifiedResearchSnapshot,
)
from packages.market_data.models import require_digest, require_text, require_utc

TIINGO_EOD_RETAINED_FIELD_SCHEMA_VERSION = "tiingo-eod-retained-field-qualification-v1"
TIINGO_EOD_RETAINED_FIELD_CHECK_IDS = (
    "exact-thirteen-field-contract-v1",
    "duplicate-missing-unknown-field-rejection-v1",
    "finite-numeric-domain-v1",
    "documented-raw-candidate-lane-routing-v1",
    "adjusted-research-lane-routing-v1",
    "corporate-action-candidate-lane-routing-v1",
    "independent-raw-and-adjusted-ohlc-ordering-v1",
    "scope-calendar-session-coverage-v1",
    "receipt-response-row-binding-v1",
)


def _digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class TiingoEodRetainedFieldRole(StrEnum):
    """Application-policy role for one frozen Tiingo response field."""

    SESSION_IDENTITY = "session_identity"
    DOCUMENTED_RAW_CANDIDATE = "documented_raw_candidate"
    ADJUSTED_RESEARCH = "adjusted_research"
    CORPORATE_ACTION_CANDIDATE = "corporate_action_candidate"


class TiingoEodRetainedFieldQualificationKind(StrEnum):
    """Bounded conclusion supported by one exact verified capture."""

    EXACT_RETAINED_FIELD_CONTRACT_ONLY = "exact_retained_field_contract_only"


_RAW_CANDIDATE_FIELDS = {"open", "high", "low", "close", "volume"}
_ADJUSTED_RESEARCH_FIELDS = {"adjOpen", "adjHigh", "adjLow", "adjClose", "adjVolume"}
_CORPORATE_ACTION_CANDIDATE_FIELDS = {"divCash", "splitFactor"}


def _field_role(
    field_name: str,
    source_schema_constraint_id: str,
) -> TiingoEodRetainedFieldRole:
    if (field_name, source_schema_constraint_id) not in TIINGO_EOD_FIELD_CONTRACT:
        raise ValueError("field and source constraint are not in the frozen Tiingo contract")
    if field_name == "date":
        return TiingoEodRetainedFieldRole.SESSION_IDENTITY
    if field_name in _RAW_CANDIDATE_FIELDS:
        return TiingoEodRetainedFieldRole.DOCUMENTED_RAW_CANDIDATE
    if field_name in _ADJUSTED_RESEARCH_FIELDS:
        return TiingoEodRetainedFieldRole.ADJUSTED_RESEARCH
    if field_name in _CORPORATE_ACTION_CANDIDATE_FIELDS:
        return TiingoEodRetainedFieldRole.CORPORATE_ACTION_CANDIDATE
    raise ValueError("field does not have an explicit retained-field role")


def _row_attribute(field_name: str) -> str:
    if field_name == "date":
        return "session_label"
    if field_name in {"open", "high", "low", "close"}:
        return f"{field_name}_price"
    if field_name == "volume":
        return "volume"
    if field_name.startswith("adj"):
        stem = field_name.removeprefix("adj")
        normalized = stem[:1].lower() + stem[1:]
        return "adjusted_volume" if normalized == "volume" else f"adjusted_{normalized}_price"
    if field_name == "divCash":
        return "div_cash"
    if field_name == "splitFactor":
        return "split_factor"
    raise ValueError("field name is not part of the frozen Tiingo field contract")


@dataclass(frozen=True, slots=True)
class TiingoEodRetainedFieldBinding:
    """One value-free field-role and local-constraint binding."""

    field_name: str
    row_attribute: str
    source_schema_constraint_id: str
    role: TiingoEodRetainedFieldRole

    def __post_init__(self) -> None:
        require_text(self.field_name, "field_name")
        require_text(self.row_attribute, "row_attribute")
        require_text(self.source_schema_constraint_id, "source_schema_constraint_id")
        if type(self.role) is not TiingoEodRetainedFieldRole:
            raise ValueError("retained field role must use the exact role enum")
        if self.role is not _field_role(
            self.field_name,
            self.source_schema_constraint_id,
        ):
            raise ValueError("retained field role does not match the frozen field contract")
        if self.row_attribute != _row_attribute(self.field_name):
            raise ValueError("retained field target does not match the frozen row routing")


TIINGO_EOD_RETAINED_FIELD_BINDINGS = tuple(
    TiingoEodRetainedFieldBinding(
        field_name=field_name,
        row_attribute=_row_attribute(field_name),
        source_schema_constraint_id=source_schema_constraint_id,
        role=_field_role(field_name, source_schema_constraint_id),
    )
    for field_name, source_schema_constraint_id in TIINGO_EOD_FIELD_CONTRACT
)
TIINGO_EOD_RETAINED_FIELD_ROLE_CONTRACT_SHA256 = _digest(
    [
        {
            "field_name": binding.field_name,
            "row_attribute": binding.row_attribute,
            "role": binding.role.value,
            "source_schema_constraint_id": binding.source_schema_constraint_id,
        }
        for binding in TIINGO_EOD_RETAINED_FIELD_BINDINGS
    ]
)


def _source_value(
    payload: dict[str, object],
    binding: TiingoEodRetainedFieldBinding,
    *,
    row_label: str,
) -> object:
    value = payload[binding.field_name]
    field_label = f"{row_label}.{binding.field_name}"
    if binding.field_name == "date":
        return _trading_date(value, field_label)
    if binding.field_name in {"volume", "adjVolume"}:
        return _integer(value, field_label)
    return _decimal(
        value,
        field_label,
        allow_zero=binding.field_name == "divCash",
    )


def _replay_field_routing(snapshot: TiingoEodVerifiedResearchSnapshot) -> None:
    rows_by_key = {(row.symbol, row.session_label): row for row in snapshot.rows}
    replayed_keys: set[tuple[str, date]] = set()
    for observation in snapshot.observations:
        decoded = _json(observation.payload)
        if not isinstance(decoded, list) or not decoded:
            raise TiingoEodError("retained response must be a non-empty JSON array")
        for index, value in enumerate(decoded):
            row_label = f"rows[{index}]"
            payload = _object(value, row_label)
            _fields(payload, set(TIINGO_EOD_FIELDS), row_label)
            session_label = _trading_date(payload["date"], f"{row_label}.date")
            key = (observation.symbol, session_label)
            row = rows_by_key.get(key)
            if row is None or key in replayed_keys:
                raise TiingoEodError(
                    "retained field replay does not exactly match verified symbol/session rows"
                )
            replayed_keys.add(key)
            for binding in TIINGO_EOD_RETAINED_FIELD_BINDINGS:
                if _source_value(payload, binding, row_label=row_label) != getattr(
                    row, binding.row_attribute
                ):
                    raise TiingoEodError(
                        "retained response field was not routed to its frozen row attribute"
                    )
    if replayed_keys != set(rows_by_key):
        raise TiingoEodError("retained field replay does not cover every verified row")


@dataclass(frozen=True, slots=True)
class _DerivedRetainedFieldQualification:
    scope: TiingoEodScope
    profile_contract_sha256: str
    calendar_artifact_sha256: str
    manifest_sha256: str
    snapshot_semantic_sha256: str
    requested_at: datetime
    received_at: datetime
    observation_count: int
    row_count: int
    session_count: int
    field_occurrence_count: int
    qualification_sha256: str


def _qualification_sha256(
    *,
    snapshot: TiingoEodVerifiedResearchSnapshot,
    observation_count: int,
    row_count: int,
    session_count: int,
    field_occurrence_count: int,
) -> str:
    return _digest(
        {
            "calendar_artifact_sha256": snapshot.calendar_artifact_sha256,
            "check_ids": list(TIINGO_EOD_RETAINED_FIELD_CHECK_IDS),
            "corporate_action_effect": "none",
            "field_bindings": [
                {
                    "field_name": binding.field_name,
                    "row_attribute": binding.row_attribute,
                    "role": binding.role.value,
                    "source_schema_constraint_id": binding.source_schema_constraint_id,
                }
                for binding in TIINGO_EOD_RETAINED_FIELD_BINDINGS
            ],
            "field_contract_sha256": TIINGO_EOD_SCHEMA_SHA256,
            "field_occurrence_count": field_occurrence_count,
            "kind": (
                TiingoEodRetainedFieldQualificationKind.EXACT_RETAINED_FIELD_CONTRACT_ONLY.value
            ),
            "manifest_sha256": snapshot.manifest_sha256,
            "observation_count": observation_count,
            "profile_contract_sha256": snapshot.manifest.profile_contract_sha256,
            "raw_execution_effect": "none",
            "received_at": snapshot.manifest.received_at.isoformat(),
            "role_contract_sha256": TIINGO_EOD_RETAINED_FIELD_ROLE_CONTRACT_SHA256,
            "row_count": row_count,
            "schema_version": TIINGO_EOD_RETAINED_FIELD_SCHEMA_VERSION,
            "scope": snapshot.manifest.profile.scope.to_dict(),
            "requested_at": snapshot.manifest.requested_at.isoformat(),
            "session_count": session_count,
            "snapshot_semantic_sha256": snapshot.semantic_sha256,
            "trading_effect": "none",
            "admission_effect": "none",
            "field_occurrence_counts": [
                {"count": row_count, "field_name": binding.field_name}
                for binding in TIINGO_EOD_RETAINED_FIELD_BINDINGS
            ],
        }
    )


def _derive_qualification(
    snapshot: TiingoEodVerifiedResearchSnapshot,
) -> _DerivedRetainedFieldQualification:
    if type(snapshot) is not TiingoEodVerifiedResearchSnapshot:
        raise TiingoEodError(
            "retained field qualification requires one exact verified snapshot proof"
        )
    try:
        snapshot.__post_init__()
    except (AttributeError, TypeError, ValueError) as error:
        raise TiingoEodError(f"verified snapshot proof is invalid: {error}") from error

    field_names = tuple(binding.field_name for binding in TIINGO_EOD_RETAINED_FIELD_BINDINGS)
    if field_names != TIINGO_EOD_FIELDS:
        raise TiingoEodError("retained field roles do not exhaust the frozen field contract")
    if snapshot.manifest.profile.schema_sha256 != TIINGO_EOD_SCHEMA_SHA256:
        raise TiingoEodError("verified snapshot does not use the frozen Tiingo field contract")
    if len(set(field_names)) != len(field_names):
        raise TiingoEodError("retained field roles contain a duplicate field")
    if set(binding.role for binding in TIINGO_EOD_RETAINED_FIELD_BINDINGS) != set(
        TiingoEodRetainedFieldRole
    ):
        raise TiingoEodError("retained field roles do not cover every required lane")
    _replay_field_routing(snapshot)

    observation_count = len(snapshot.observations)
    row_count = len(snapshot.rows)
    session_count = len({row.session_label for row in snapshot.rows})
    field_occurrence_count = row_count * len(TIINGO_EOD_RETAINED_FIELD_BINDINGS)
    return _DerivedRetainedFieldQualification(
        scope=snapshot.manifest.profile.scope,
        profile_contract_sha256=snapshot.manifest.profile_contract_sha256,
        calendar_artifact_sha256=snapshot.calendar_artifact_sha256,
        manifest_sha256=snapshot.manifest_sha256,
        snapshot_semantic_sha256=snapshot.semantic_sha256,
        requested_at=snapshot.manifest.requested_at,
        received_at=snapshot.manifest.received_at,
        observation_count=observation_count,
        row_count=row_count,
        session_count=session_count,
        field_occurrence_count=field_occurrence_count,
        qualification_sha256=_qualification_sha256(
            snapshot=snapshot,
            observation_count=observation_count,
            row_count=row_count,
            session_count=session_count,
            field_occurrence_count=field_occurrence_count,
        ),
    )


@dataclass(frozen=True, slots=True, init=False)
class TiingoEodRetainedFieldQualification:
    """Value-free proof of exact retained field-contract conformance."""

    snapshot: TiingoEodVerifiedResearchSnapshot = field(repr=False)
    scope: TiingoEodScope
    profile_contract_sha256: str
    calendar_artifact_sha256: str
    manifest_sha256: str
    snapshot_semantic_sha256: str
    requested_at: datetime
    received_at: datetime
    field_contract_sha256: str
    role_contract_sha256: str
    field_bindings: tuple[TiingoEodRetainedFieldBinding, ...]
    check_ids: tuple[str, ...]
    observation_count: int
    row_count: int
    session_count: int
    field_occurrence_count: int
    qualification_sha256: str
    schema_version: str = TIINGO_EOD_RETAINED_FIELD_SCHEMA_VERSION
    qualification_kind: TiingoEodRetainedFieldQualificationKind = (
        TiingoEodRetainedFieldQualificationKind.EXACT_RETAINED_FIELD_CONTRACT_ONLY
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "Tiingo EOD retained field qualifications can only be derived from verified proofs"
        )

    @classmethod
    def _from_verified_snapshot(
        cls,
        snapshot: TiingoEodVerifiedResearchSnapshot,
    ) -> TiingoEodRetainedFieldQualification:
        if cls is not TiingoEodRetainedFieldQualification:
            raise TypeError("retained field qualification subclasses are not supported")
        derived = _derive_qualification(snapshot)
        qualification = object.__new__(cls)
        for field_name, value in (
            ("snapshot", snapshot),
            ("scope", derived.scope),
            ("profile_contract_sha256", derived.profile_contract_sha256),
            ("calendar_artifact_sha256", derived.calendar_artifact_sha256),
            ("manifest_sha256", derived.manifest_sha256),
            ("snapshot_semantic_sha256", derived.snapshot_semantic_sha256),
            ("requested_at", derived.requested_at),
            ("received_at", derived.received_at),
            ("field_contract_sha256", TIINGO_EOD_SCHEMA_SHA256),
            ("role_contract_sha256", TIINGO_EOD_RETAINED_FIELD_ROLE_CONTRACT_SHA256),
            ("field_bindings", TIINGO_EOD_RETAINED_FIELD_BINDINGS),
            ("check_ids", TIINGO_EOD_RETAINED_FIELD_CHECK_IDS),
            ("observation_count", derived.observation_count),
            ("row_count", derived.row_count),
            ("session_count", derived.session_count),
            ("field_occurrence_count", derived.field_occurrence_count),
            ("qualification_sha256", derived.qualification_sha256),
            ("schema_version", TIINGO_EOD_RETAINED_FIELD_SCHEMA_VERSION),
            (
                "qualification_kind",
                TiingoEodRetainedFieldQualificationKind.EXACT_RETAINED_FIELD_CONTRACT_ONLY,
            ),
        ):
            object.__setattr__(qualification, field_name, value)
        qualification.__post_init__()
        return qualification

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.profile_contract_sha256, "profile_contract_sha256"),
            (self.calendar_artifact_sha256, "calendar_artifact_sha256"),
            (self.manifest_sha256, "manifest_sha256"),
            (self.snapshot_semantic_sha256, "snapshot_semantic_sha256"),
            (self.field_contract_sha256, "field_contract_sha256"),
            (self.role_contract_sha256, "role_contract_sha256"),
            (self.qualification_sha256, "qualification_sha256"),
        ):
            require_digest(value, field_name)
        require_utc(self.requested_at, "requested_at")
        require_utc(self.received_at, "received_at")
        if self.schema_version != TIINGO_EOD_RETAINED_FIELD_SCHEMA_VERSION:
            raise ValueError("unsupported retained field qualification schema")
        if (
            self.qualification_kind
            is not TiingoEodRetainedFieldQualificationKind.EXACT_RETAINED_FIELD_CONTRACT_ONLY
        ):
            raise ValueError("unsupported retained field qualification kind")
        derived = _derive_qualification(self.snapshot)
        if (
            self.scope != derived.scope
            or self.profile_contract_sha256 != derived.profile_contract_sha256
            or self.calendar_artifact_sha256 != derived.calendar_artifact_sha256
            or self.manifest_sha256 != derived.manifest_sha256
            or self.snapshot_semantic_sha256 != derived.snapshot_semantic_sha256
            or self.requested_at != derived.requested_at
            or self.received_at != derived.received_at
            or self.field_contract_sha256 != TIINGO_EOD_SCHEMA_SHA256
            or self.role_contract_sha256 != TIINGO_EOD_RETAINED_FIELD_ROLE_CONTRACT_SHA256
            or self.field_bindings != TIINGO_EOD_RETAINED_FIELD_BINDINGS
            or self.check_ids != TIINGO_EOD_RETAINED_FIELD_CHECK_IDS
            or self.observation_count != derived.observation_count
            or self.row_count != derived.row_count
            or self.session_count != derived.session_count
            or self.field_occurrence_count != derived.field_occurrence_count
            or self.qualification_sha256 != derived.qualification_sha256
        ):
            raise ValueError(
                "retained field qualification does not match its verified snapshot proof"
            )

    def raw_bar_records(self) -> NoReturn:
        raise TiingoEodError(
            "exact retained fields remain documented raw candidates, not execution-safe raw bars"
        )

    def canonical_bar_records(self) -> NoReturn:
        raise TiingoEodError("retained field qualification cannot become canonical bars")

    def corporate_action_records(self) -> NoReturn:
        raise TiingoEodError(
            "retained dividend and split fields are candidates without action authority"
        )

    def admission_evidence(self) -> NoReturn:
        raise TiingoEodError(
            "retained field qualification is research-only and permanently non-admitting"
        )

    def historical_bar_source(self) -> NoReturn:
        raise TiingoEodError("retained field qualification cannot become a HistoricalBarSource")


def qualify_tiingo_eod_retained_fields(
    snapshot: TiingoEodVerifiedResearchSnapshot,
) -> TiingoEodRetainedFieldQualification:
    """Derive value-free field-contract proof from one verified capture."""

    return TiingoEodRetainedFieldQualification._from_verified_snapshot(snapshot)


__all__ = [
    "TIINGO_EOD_RETAINED_FIELD_BINDINGS",
    "TIINGO_EOD_RETAINED_FIELD_CHECK_IDS",
    "TIINGO_EOD_RETAINED_FIELD_ROLE_CONTRACT_SHA256",
    "TIINGO_EOD_RETAINED_FIELD_SCHEMA_VERSION",
    "TiingoEodRetainedFieldBinding",
    "TiingoEodRetainedFieldQualification",
    "TiingoEodRetainedFieldQualificationKind",
    "TiingoEodRetainedFieldRole",
    "qualify_tiingo_eod_retained_fields",
]
