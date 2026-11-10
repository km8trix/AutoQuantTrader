"""Offline Tiingo EOD market-semantics contract qualification.

This boundary binds one exact verified snapshot, retained-field proof,
identity/lifecycle proof, and canonical semantics artifact.  It validates only
contract shape and consistency.  It never grants raw-price, market-provenance,
corporate-action, source, admission, or trading authority.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import NoReturn, cast

from packages.adapters.market_data.tiingo_eod import (
    PHASE1_TIINGO_SYMBOLS,
    TIINGO_DATASET,
    TIINGO_EOD_FIELDS,
    TIINGO_PROVIDER,
    TiingoEodError,
    TiingoEodScope,
    _boolean,
    _datetime,
    _fields,
    _json,
    _object,
    _text,
    _timestamp,
)
from packages.adapters.market_data.tiingo_eod_identity_lifecycle import (
    TiingoEodIdentityLifecycleQualification,
)
from packages.adapters.market_data.tiingo_eod_retained_fields import (
    TiingoEodRetainedFieldQualification,
)
from packages.adapters.market_data.tiingo_eod_snapshot import (
    TiingoEodVerifiedResearchSnapshot,
)
from packages.market_data.models import require_digest, require_text, require_utc

TIINGO_EOD_MARKET_SEMANTICS_ARTIFACT_SCHEMA_VERSION = "tiingo-eod-market-semantics-artifact-v1"
TIINGO_EOD_MARKET_SEMANTICS_QUALIFICATION_SCHEMA_VERSION = (
    "tiingo-eod-market-semantics-qualification-v1"
)
MAX_TIINGO_EOD_MARKET_SEMANTICS_ARTIFACT_BYTES = 1_048_576
TIINGO_EOD_MARKET_SEMANTICS_CHECK_IDS = (
    "exact-phase1-market-semantics-scope-v1",
    "canonical-market-semantics-artifact-v1",
    "snapshot-retained-identity-proof-chain-v1",
    "profile-semantics-authority-binding-v1",
    "structured-market-provenance-contract-v1",
    "full-session-provenance-coverage-v1",
    "exact-thirteen-field-semantics-partition-v1",
    "cash-dividend-candidate-convention-v1",
    "split-factor-candidate-convention-v1",
    "neutral-values-do-not-prove-action-absence-v1",
    "five-isolated-synthetic-cases-v1",
    "stable-identity-candidate-resolution-v1",
    "contract-only-authority-separation-v1",
)

_SESSION_IDENTITY_FIELDS = ("date",)
_DOCUMENTED_RAW_CANDIDATE_FIELDS = ("open", "high", "low", "close", "volume")
_ADJUSTED_RESEARCH_FIELDS = (
    "adjOpen",
    "adjHigh",
    "adjLow",
    "adjClose",
    "adjVolume",
)
_CORPORATE_ACTION_CANDIDATE_FIELDS = ("divCash", "splitFactor")
_EXPECTED_CASE_TEXT = (
    ("neutral", "0", "1"),
    ("cash_dividend", "0.25", "1"),
    ("forward_split", "0", "2"),
    ("reverse_split", "0", "0.25"),
    ("simultaneous_dividend_forward_split", "0.25", "2"),
)
_ACTION_CANDIDATE_CONVENTION = {
    "absence_inference": "forbidden",
    "announcement_time": "not_provided",
    "div_cash_currency": "USD",
    "div_cash_neutral": "0",
    "div_cash_orientation": "positive_cash_per_share_candidate",
    "effective_date_basis": "row_date_candidate_only",
    "payable_time": "not_provided",
    "publication_time": "not_provided",
    "revision": "not_provided",
    "split_factor_neutral": "1",
    "split_factor_orientation": "new_shares_per_old_share_candidate",
}


def _digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _array(value: object, field_name: str) -> list[object]:
    if not isinstance(value, list):
        raise TiingoEodError(f"{field_name} must be a JSON array")
    return cast(list[object], value)


def _optional_text(value: object, field_name: str) -> str | None:
    return None if value is None else _text(value, field_name)


def _optional_datetime(value: object, field_name: str) -> datetime | None:
    return None if value is None else _datetime(value, field_name)


def _optional_timestamp(value: datetime | None) -> str | None:
    return None if value is None else _timestamp(value)


def _nonzero_digest(value: str, field_name: str) -> None:
    require_digest(value, field_name)
    if value == "0" * 64:
        raise ValueError(f"{field_name} must identify exact evidence")


def _decimal_text(value: object, field_name: str, *, allow_zero: bool) -> Decimal:
    if not isinstance(value, str):
        raise TiingoEodError(f"{field_name} must be a decimal string")
    try:
        result = Decimal(value)
    except InvalidOperation as error:
        raise TiingoEodError(f"{field_name} must be a finite decimal string") from error
    if not result.is_finite() or result < 0 or (not allow_zero and result == 0):
        qualifier = "non-negative" if allow_zero else "positive"
        raise TiingoEodError(f"{field_name} must be a finite {qualifier} decimal string")
    return result


def _string_array(value: object, field_name: str) -> tuple[str, ...]:
    values = _array(value, field_name)
    if not all(isinstance(item, str) for item in values):
        raise TiingoEodError(f"{field_name} must contain only strings")
    return tuple(cast(list[str], values))


class TiingoEodMarketSemanticsArtifactKind(StrEnum):
    """Evidence category asserted by the contract artifact."""

    SYNTHETIC_CONTRACT = "synthetic_contract"
    REVIEWED_REFERENCE = "reviewed_reference"


class TiingoEodMarketSemanticsQualificationKind(StrEnum):
    """The only conclusion supported by this boundary."""

    MARKET_SEMANTICS_CONTRACT_ONLY = "market_semantics_contract_only"


@dataclass(frozen=True, slots=True)
class TiingoEodMarketSemanticsFieldPartition:
    """The complete immutable role partition for all thirteen source fields."""

    session_identity_fields: tuple[str, ...]
    documented_raw_candidate_fields: tuple[str, ...]
    adjusted_research_fields: tuple[str, ...]
    corporate_action_candidate_fields: tuple[str, ...]

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.session_identity_fields, "session_identity_fields"),
            (self.documented_raw_candidate_fields, "documented_raw_candidate_fields"),
            (self.adjusted_research_fields, "adjusted_research_fields"),
            (self.corporate_action_candidate_fields, "corporate_action_candidate_fields"),
        ):
            if type(value) is not tuple or any(type(item) is not str for item in value):
                raise ValueError(f"{field_name} must be an immutable string tuple")
        if self.session_identity_fields != _SESSION_IDENTITY_FIELDS:
            raise ValueError("session-identity field contract was altered")
        if self.documented_raw_candidate_fields != _DOCUMENTED_RAW_CANDIDATE_FIELDS:
            raise ValueError("documented-raw-candidate field contract was altered")
        if self.adjusted_research_fields != _ADJUSTED_RESEARCH_FIELDS:
            raise ValueError("adjusted-research field contract was altered")
        if self.corporate_action_candidate_fields != _CORPORATE_ACTION_CANDIDATE_FIELDS:
            raise ValueError("corporate-action-candidate field contract was altered")
        if (
            self.session_identity_fields
            + self.documented_raw_candidate_fields
            + self.adjusted_research_fields
            + self.corporate_action_candidate_fields
            != TIINGO_EOD_FIELDS
        ):
            raise ValueError("field partition must exactly cover the Tiingo EOD contract")

    def to_dict(self) -> dict[str, object]:
        return {
            "adjusted_research_fields": list(self.adjusted_research_fields),
            "corporate_action_candidate_fields": list(self.corporate_action_candidate_fields),
            "documented_raw_candidate_fields": list(self.documented_raw_candidate_fields),
            "session_identity_fields": list(self.session_identity_fields),
        }


@dataclass(frozen=True, slots=True)
class TiingoEodMarketProvenanceContract:
    """Structured reference provenance, without production authority."""

    aggregation: str
    condition_scope: str
    currency: str
    effective_from: datetime
    effective_to: datetime | None
    endpoint: str
    feed: str
    product: str
    session_scope: str
    venue_scope: str

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.aggregation, "provenance.aggregation"),
            (self.condition_scope, "provenance.condition_scope"),
            (self.currency, "provenance.currency"),
            (self.endpoint, "provenance.endpoint"),
            (self.feed, "provenance.feed"),
            (self.product, "provenance.product"),
            (self.session_scope, "provenance.session_scope"),
            (self.venue_scope, "provenance.venue_scope"),
        ):
            require_text(value, field_name)
        if self.currency != "USD":
            raise ValueError("bounded Tiingo market provenance must use USD")
        require_utc(self.effective_from, "provenance.effective_from")
        if self.effective_to is not None:
            require_utc(self.effective_to, "provenance.effective_to")
            if self.effective_to <= self.effective_from:
                raise ValueError("provenance.effective_to must follow effective_from")

    def to_dict(self) -> dict[str, object]:
        return {
            "aggregation": self.aggregation,
            "condition_scope": self.condition_scope,
            "currency": self.currency,
            "effective_from": _timestamp(self.effective_from),
            "effective_to": _optional_timestamp(self.effective_to),
            "endpoint": self.endpoint,
            "feed": self.feed,
            "product": self.product,
            "session_scope": self.session_scope,
            "venue_scope": self.venue_scope,
        }


@dataclass(frozen=True, slots=True)
class TiingoEodActionCandidateConvention:
    """Frozen non-authorizing interpretation of candidate fields."""

    absence_inference: str
    announcement_time: str
    div_cash_currency: str
    div_cash_neutral: str
    div_cash_orientation: str
    effective_date_basis: str
    payable_time: str
    publication_time: str
    revision: str
    split_factor_neutral: str
    split_factor_orientation: str

    def __post_init__(self) -> None:
        for field_name, value in self.to_dict().items():
            require_text(cast(str, value), f"action_candidate_convention.{field_name}")
        if self.to_dict() != _ACTION_CANDIDATE_CONVENTION:
            raise ValueError("action-candidate convention was altered")

    def to_dict(self) -> dict[str, object]:
        return {
            "absence_inference": self.absence_inference,
            "announcement_time": self.announcement_time,
            "div_cash_currency": self.div_cash_currency,
            "div_cash_neutral": self.div_cash_neutral,
            "div_cash_orientation": self.div_cash_orientation,
            "effective_date_basis": self.effective_date_basis,
            "payable_time": self.payable_time,
            "publication_time": self.publication_time,
            "revision": self.revision,
            "split_factor_neutral": self.split_factor_neutral,
            "split_factor_orientation": self.split_factor_orientation,
        }


@dataclass(frozen=True, slots=True)
class TiingoEodMarketSemanticsSyntheticCase:
    """One isolated repository-owned candidate-orientation example."""

    case_id: str
    div_cash: Decimal
    split_factor: Decimal

    def __post_init__(self) -> None:
        require_text(self.case_id, "synthetic case_id")
        if type(self.div_cash) is not Decimal or not self.div_cash.is_finite():
            raise ValueError("synthetic div_cash must be an exact finite Decimal")
        if self.div_cash < 0:
            raise ValueError("synthetic div_cash must be non-negative")
        if (
            type(self.split_factor) is not Decimal
            or not self.split_factor.is_finite()
            or self.split_factor <= 0
        ):
            raise ValueError("synthetic split_factor must be a positive finite Decimal")

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "div_cash": str(self.div_cash),
            "split_factor": str(self.split_factor),
        }


def _field_partition_from_dict(value: object) -> TiingoEodMarketSemanticsFieldPartition:
    payload = _object(value, "field_partition")
    _fields(
        payload,
        {
            "adjusted_research_fields",
            "corporate_action_candidate_fields",
            "documented_raw_candidate_fields",
            "session_identity_fields",
        },
        "field_partition",
    )
    return TiingoEodMarketSemanticsFieldPartition(
        session_identity_fields=_string_array(
            payload["session_identity_fields"], "field_partition.session_identity_fields"
        ),
        documented_raw_candidate_fields=_string_array(
            payload["documented_raw_candidate_fields"],
            "field_partition.documented_raw_candidate_fields",
        ),
        adjusted_research_fields=_string_array(
            payload["adjusted_research_fields"],
            "field_partition.adjusted_research_fields",
        ),
        corporate_action_candidate_fields=_string_array(
            payload["corporate_action_candidate_fields"],
            "field_partition.corporate_action_candidate_fields",
        ),
    )


def _provenance_from_dict(value: object) -> TiingoEodMarketProvenanceContract:
    payload = _object(value, "provenance")
    _fields(
        payload,
        {
            "aggregation",
            "condition_scope",
            "currency",
            "effective_from",
            "effective_to",
            "endpoint",
            "feed",
            "product",
            "session_scope",
            "venue_scope",
        },
        "provenance",
    )
    return TiingoEodMarketProvenanceContract(
        aggregation=_text(payload["aggregation"], "provenance.aggregation"),
        condition_scope=_text(payload["condition_scope"], "provenance.condition_scope"),
        currency=_text(payload["currency"], "provenance.currency"),
        effective_from=_datetime(payload["effective_from"], "provenance.effective_from"),
        effective_to=_optional_datetime(payload["effective_to"], "provenance.effective_to"),
        endpoint=_text(payload["endpoint"], "provenance.endpoint"),
        feed=_text(payload["feed"], "provenance.feed"),
        product=_text(payload["product"], "provenance.product"),
        session_scope=_text(payload["session_scope"], "provenance.session_scope"),
        venue_scope=_text(payload["venue_scope"], "provenance.venue_scope"),
    )


def _convention_from_dict(value: object) -> TiingoEodActionCandidateConvention:
    payload = _object(value, "action_candidate_convention")
    _fields(payload, set(_ACTION_CANDIDATE_CONVENTION), "action_candidate_convention")
    return TiingoEodActionCandidateConvention(
        absence_inference=_text(
            payload["absence_inference"], "action_candidate_convention.absence_inference"
        ),
        announcement_time=_text(
            payload["announcement_time"], "action_candidate_convention.announcement_time"
        ),
        div_cash_currency=_text(
            payload["div_cash_currency"], "action_candidate_convention.div_cash_currency"
        ),
        div_cash_neutral=_text(
            payload["div_cash_neutral"], "action_candidate_convention.div_cash_neutral"
        ),
        div_cash_orientation=_text(
            payload["div_cash_orientation"],
            "action_candidate_convention.div_cash_orientation",
        ),
        effective_date_basis=_text(
            payload["effective_date_basis"],
            "action_candidate_convention.effective_date_basis",
        ),
        payable_time=_text(payload["payable_time"], "action_candidate_convention.payable_time"),
        publication_time=_text(
            payload["publication_time"], "action_candidate_convention.publication_time"
        ),
        revision=_text(payload["revision"], "action_candidate_convention.revision"),
        split_factor_neutral=_text(
            payload["split_factor_neutral"],
            "action_candidate_convention.split_factor_neutral",
        ),
        split_factor_orientation=_text(
            payload["split_factor_orientation"],
            "action_candidate_convention.split_factor_orientation",
        ),
    )


def _synthetic_case_from_dict(
    value: object,
    index: int,
) -> TiingoEodMarketSemanticsSyntheticCase:
    field_name = f"synthetic_cases[{index}]"
    payload = _object(value, field_name)
    _fields(payload, {"case_id", "div_cash", "split_factor"}, field_name)
    return TiingoEodMarketSemanticsSyntheticCase(
        case_id=_text(payload["case_id"], f"{field_name}.case_id"),
        div_cash=_decimal_text(payload["div_cash"], f"{field_name}.div_cash", allow_zero=True),
        split_factor=_decimal_text(
            payload["split_factor"], f"{field_name}.split_factor", allow_zero=False
        ),
    )


@dataclass(frozen=True, slots=True)
class TiingoEodMarketSemanticsArtifact:
    """Canonical bounded semantics reference; never production authority."""

    action_candidate_convention: TiingoEodActionCandidateConvention
    adjusted_methodology_evidence_sha256: str
    approved: bool
    artifact_id: str
    artifact_kind: TiingoEodMarketSemanticsArtifactKind
    corporate_action_authority: str
    corporate_action_candidate_evidence_sha256: str
    executor_id: str
    field_partition: TiingoEodMarketSemanticsFieldPartition
    identity_lifecycle_qualification_sha256: str
    market_provenance_evidence_sha256: str
    market_provenance_label: str
    market_semantics_source_id: str
    observed_at: datetime
    profile_contract_sha256: str
    provenance: TiingoEodMarketProvenanceContract
    raw_semantics_evidence_sha256: str
    reviewed_at: datetime | None
    reviewer_id: str | None
    synthetic_cases: tuple[TiingoEodMarketSemanticsSyntheticCase, ...]
    trade_symbols: tuple[str, ...]
    schema_version: str = TIINGO_EOD_MARKET_SEMANTICS_ARTIFACT_SCHEMA_VERSION
    provider: str = TIINGO_PROVIDER
    dataset: str = TIINGO_DATASET

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.artifact_id, "artifact_id"),
            (self.executor_id, "executor_id"),
            (self.corporate_action_authority, "corporate_action_authority"),
            (self.market_provenance_label, "market_provenance_label"),
            (self.market_semantics_source_id, "market_semantics_source_id"),
        ):
            require_text(value, field_name)
        if self.market_semantics_source_id in {
            self.market_provenance_label,
            self.corporate_action_authority,
        }:
            raise ValueError("market_semantics_source_id must differ from profile authority labels")
        if type(self.artifact_kind) is not TiingoEodMarketSemanticsArtifactKind:
            raise ValueError("artifact_kind must use the exact artifact-kind enum")
        if type(self.approved) is not bool:
            raise ValueError("approved must be boolean")
        require_utc(self.observed_at, "observed_at")
        for value, field_name in (
            (self.profile_contract_sha256, "profile_contract_sha256"),
            (
                self.identity_lifecycle_qualification_sha256,
                "identity_lifecycle_qualification_sha256",
            ),
            (self.raw_semantics_evidence_sha256, "raw_semantics_evidence_sha256"),
            (
                self.adjusted_methodology_evidence_sha256,
                "adjusted_methodology_evidence_sha256",
            ),
            (
                self.market_provenance_evidence_sha256,
                "market_provenance_evidence_sha256",
            ),
            (
                self.corporate_action_candidate_evidence_sha256,
                "corporate_action_candidate_evidence_sha256",
            ),
        ):
            _nonzero_digest(value, field_name)
        if self.schema_version != TIINGO_EOD_MARKET_SEMANTICS_ARTIFACT_SCHEMA_VERSION:
            raise ValueError("unsupported Tiingo EOD market-semantics artifact schema")
        if self.provider != TIINGO_PROVIDER or self.dataset != TIINGO_DATASET:
            raise ValueError("market-semantics artifact does not identify Tiingo EOD")
        if self.artifact_kind is TiingoEodMarketSemanticsArtifactKind.SYNTHETIC_CONTRACT:
            if self.approved or self.reviewer_id is not None or self.reviewed_at is not None:
                raise ValueError("synthetic contract artifacts must remain unapproved")
        else:
            if not self.approved or self.reviewer_id is None or self.reviewed_at is None:
                raise ValueError("reviewed reference artifacts require explicit approval")
            require_text(self.reviewer_id, "reviewer_id")
            require_utc(self.reviewed_at, "reviewed_at")
            if self.reviewer_id == self.executor_id:
                raise ValueError("reviewer_id must differ from executor_id")
            if self.reviewed_at < self.observed_at:
                raise ValueError("reviewed_at cannot precede observed_at")
        if type(self.field_partition) is not TiingoEodMarketSemanticsFieldPartition:
            raise ValueError("field_partition must use the exact partition type")
        if type(self.provenance) is not TiingoEodMarketProvenanceContract:
            raise ValueError("provenance must use the exact provenance-contract type")
        if type(self.action_candidate_convention) is not TiingoEodActionCandidateConvention:
            raise ValueError("action_candidate_convention must use the exact convention type")
        self.field_partition.__post_init__()
        self.provenance.__post_init__()
        self.action_candidate_convention.__post_init__()
        if type(self.trade_symbols) is not tuple or self.trade_symbols != PHASE1_TIINGO_SYMBOLS:
            raise ValueError("trade_symbols must exactly equal DIA, IWM, QQQ, and SPY")
        if type(self.synthetic_cases) is not tuple or any(
            type(value) is not TiingoEodMarketSemanticsSyntheticCase
            for value in self.synthetic_cases
        ):
            raise ValueError("synthetic_cases must use an immutable exact case tuple")
        for case in self.synthetic_cases:
            case.__post_init__()
        if (
            tuple(
                (case.case_id, str(case.div_cash), str(case.split_factor))
                for case in self.synthetic_cases
            )
            != _EXPECTED_CASE_TEXT
        ):
            raise ValueError("synthetic_cases must exactly match the five frozen cases")
        if len(self.to_json_bytes()) > MAX_TIINGO_EOD_MARKET_SEMANTICS_ARTIFACT_BYTES:
            raise ValueError("market-semantics artifact exceeds the size limit")

    @property
    def artifact_sha256(self) -> str:
        return hashlib.sha256(self.to_json_bytes()).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {
            "action_candidate_convention": self.action_candidate_convention.to_dict(),
            "adjusted_methodology_evidence_sha256": (self.adjusted_methodology_evidence_sha256),
            "approved": self.approved,
            "artifact_id": self.artifact_id,
            "artifact_kind": self.artifact_kind.value,
            "corporate_action_authority": self.corporate_action_authority,
            "corporate_action_candidate_evidence_sha256": (
                self.corporate_action_candidate_evidence_sha256
            ),
            "dataset": self.dataset,
            "executor_id": self.executor_id,
            "field_partition": self.field_partition.to_dict(),
            "identity_lifecycle_qualification_sha256": (
                self.identity_lifecycle_qualification_sha256
            ),
            "market_provenance_evidence_sha256": (self.market_provenance_evidence_sha256),
            "market_provenance_label": self.market_provenance_label,
            "market_semantics_source_id": self.market_semantics_source_id,
            "observed_at": _timestamp(self.observed_at),
            "profile_contract_sha256": self.profile_contract_sha256,
            "provenance": self.provenance.to_dict(),
            "provider": self.provider,
            "raw_semantics_evidence_sha256": self.raw_semantics_evidence_sha256,
            "reviewed_at": _optional_timestamp(self.reviewed_at),
            "reviewer_id": self.reviewer_id,
            "schema_version": self.schema_version,
            "synthetic_cases": [case.to_dict() for case in self.synthetic_cases],
            "trade_symbols": list(self.trade_symbols),
        }

    def to_json_bytes(self) -> bytes:
        return (
            json.dumps(self.to_dict(), ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, payload_bytes: bytes) -> TiingoEodMarketSemanticsArtifact:
        if type(payload_bytes) is not bytes or not payload_bytes:
            raise TiingoEodError("market-semantics artifact must be non-empty immutable bytes")
        if len(payload_bytes) > MAX_TIINGO_EOD_MARKET_SEMANTICS_ARTIFACT_BYTES:
            raise TiingoEodError("market-semantics artifact exceeds the size limit")
        payload = _object(_json(payload_bytes), "market-semantics artifact")
        _fields(
            payload,
            {
                "action_candidate_convention",
                "adjusted_methodology_evidence_sha256",
                "approved",
                "artifact_id",
                "artifact_kind",
                "corporate_action_authority",
                "corporate_action_candidate_evidence_sha256",
                "dataset",
                "executor_id",
                "field_partition",
                "identity_lifecycle_qualification_sha256",
                "market_provenance_evidence_sha256",
                "market_provenance_label",
                "market_semantics_source_id",
                "observed_at",
                "profile_contract_sha256",
                "provenance",
                "provider",
                "raw_semantics_evidence_sha256",
                "reviewed_at",
                "reviewer_id",
                "schema_version",
                "synthetic_cases",
                "trade_symbols",
            },
            "market-semantics artifact",
        )
        trade_symbols = _string_array(payload["trade_symbols"], "trade_symbols")
        case_values = _array(payload["synthetic_cases"], "synthetic_cases")
        try:
            artifact = cls(
                action_candidate_convention=_convention_from_dict(
                    payload["action_candidate_convention"]
                ),
                adjusted_methodology_evidence_sha256=_text(
                    payload["adjusted_methodology_evidence_sha256"],
                    "adjusted_methodology_evidence_sha256",
                ),
                approved=_boolean(payload["approved"], "approved"),
                artifact_id=_text(payload["artifact_id"], "artifact_id"),
                artifact_kind=TiingoEodMarketSemanticsArtifactKind(
                    _text(payload["artifact_kind"], "artifact_kind")
                ),
                corporate_action_authority=_text(
                    payload["corporate_action_authority"], "corporate_action_authority"
                ),
                corporate_action_candidate_evidence_sha256=_text(
                    payload["corporate_action_candidate_evidence_sha256"],
                    "corporate_action_candidate_evidence_sha256",
                ),
                executor_id=_text(payload["executor_id"], "executor_id"),
                field_partition=_field_partition_from_dict(payload["field_partition"]),
                identity_lifecycle_qualification_sha256=_text(
                    payload["identity_lifecycle_qualification_sha256"],
                    "identity_lifecycle_qualification_sha256",
                ),
                market_provenance_evidence_sha256=_text(
                    payload["market_provenance_evidence_sha256"],
                    "market_provenance_evidence_sha256",
                ),
                market_provenance_label=_text(
                    payload["market_provenance_label"], "market_provenance_label"
                ),
                market_semantics_source_id=_text(
                    payload["market_semantics_source_id"],
                    "market_semantics_source_id",
                ),
                observed_at=_datetime(payload["observed_at"], "observed_at"),
                profile_contract_sha256=_text(
                    payload["profile_contract_sha256"], "profile_contract_sha256"
                ),
                provenance=_provenance_from_dict(payload["provenance"]),
                raw_semantics_evidence_sha256=_text(
                    payload["raw_semantics_evidence_sha256"],
                    "raw_semantics_evidence_sha256",
                ),
                reviewed_at=_optional_datetime(payload["reviewed_at"], "reviewed_at"),
                reviewer_id=_optional_text(payload["reviewer_id"], "reviewer_id"),
                synthetic_cases=tuple(
                    _synthetic_case_from_dict(value, index)
                    for index, value in enumerate(case_values)
                ),
                trade_symbols=trade_symbols,
                schema_version=_text(payload["schema_version"], "schema_version"),
                provider=_text(payload["provider"], "provider"),
                dataset=_text(payload["dataset"], "dataset"),
            )
        except ValueError as error:
            if isinstance(error, TiingoEodError):
                raise
            raise TiingoEodError(f"market-semantics artifact is invalid: {error}") from error
        if artifact.to_json_bytes() != payload_bytes:
            raise TiingoEodError("market-semantics artifact must use exact canonical encoding")
        return artifact


@dataclass(frozen=True, slots=True)
class _DerivedMarketSemanticsQualification:
    artifact: TiingoEodMarketSemanticsArtifact
    scope: TiingoEodScope
    profile_contract_sha256: str
    calendar_artifact_sha256: str
    snapshot_semantic_sha256: str
    retained_field_qualification_sha256: str
    identity_lifecycle_qualification_sha256: str
    field_semantics_contract_sha256: str
    action_candidate_contract_sha256: str
    synthetic_case_contract_sha256: str
    row_count: int
    stable_id_count: int
    candidate_field_count: int
    candidate_occurrence_count: int
    resolved_rows: tuple[tuple[str, str, str], ...]
    qualification_sha256: str


def _qualification_material(
    *,
    artifact: TiingoEodMarketSemanticsArtifact,
    snapshot: TiingoEodVerifiedResearchSnapshot,
    retained_fields: TiingoEodRetainedFieldQualification,
    identity_lifecycle: TiingoEodIdentityLifecycleQualification,
    field_semantics_contract_sha256: str,
    action_candidate_contract_sha256: str,
    synthetic_case_contract_sha256: str,
    stable_id_count: int,
    resolved_rows: tuple[tuple[str, str, str], ...],
) -> dict[str, object]:
    row_count = len(snapshot.rows)
    return {
        "action_candidate_contract_sha256": action_candidate_contract_sha256,
        "adjustment_methodology_effect": "none",
        "admission_effect": "none",
        "artifact_kind": artifact.artifact_kind.value,
        "artifact_sha256": artifact.artifact_sha256,
        "calendar_artifact_sha256": snapshot.calendar_artifact_sha256,
        "candidate_field_count": len(_CORPORATE_ACTION_CANDIDATE_FIELDS),
        "candidate_occurrence_count": row_count * len(_CORPORATE_ACTION_CANDIDATE_FIELDS),
        "canonical_bar_effect": "none",
        "check_ids": list(TIINGO_EOD_MARKET_SEMANTICS_CHECK_IDS),
        "corporate_action_effect": "none",
        "correction_effect": "none",
        "field_semantics_contract_sha256": field_semantics_contract_sha256,
        "genuine_raw_effect": "none",
        "historical_source_effect": "none",
        "identity_lifecycle_qualification_sha256": (identity_lifecycle.qualification_sha256),
        "market_provenance_effect": "none",
        "profile_contract_sha256": snapshot.manifest.profile_contract_sha256,
        "qualification_kind": (
            TiingoEodMarketSemanticsQualificationKind.MARKET_SEMANTICS_CONTRACT_ONLY.value
        ),
        "retained_field_qualification_sha256": retained_fields.qualification_sha256,
        "resolved_row_mapping_sha256": _digest(resolved_rows),
        "row_count": row_count,
        "schema_version": TIINGO_EOD_MARKET_SEMANTICS_QUALIFICATION_SCHEMA_VERSION,
        "scope": snapshot.manifest.profile.scope.to_dict(),
        "snapshot_semantic_sha256": snapshot.semantic_sha256,
        "stable_id_count": stable_id_count,
        "synthetic_case_contract_sha256": synthetic_case_contract_sha256,
        "synthetic_case_count": len(artifact.synthetic_cases),
        "trading_effect": "none",
        "vendor_publication_effect": "none",
    }


def _derive_market_semantics_qualification(
    *,
    snapshot: TiingoEodVerifiedResearchSnapshot,
    retained_fields: TiingoEodRetainedFieldQualification,
    identity_lifecycle: TiingoEodIdentityLifecycleQualification,
    artifact_bytes: bytes,
) -> _DerivedMarketSemanticsQualification:
    if type(snapshot) is not TiingoEodVerifiedResearchSnapshot:
        raise TiingoEodError("market-semantics qualification requires an exact snapshot")
    if type(retained_fields) is not TiingoEodRetainedFieldQualification:
        raise TiingoEodError(
            "market-semantics qualification requires an exact retained-field proof"
        )
    if type(identity_lifecycle) is not TiingoEodIdentityLifecycleQualification:
        raise TiingoEodError(
            "market-semantics qualification requires an exact identity/lifecycle proof"
        )
    snapshot.__post_init__()
    retained_fields.__post_init__()
    identity_lifecycle.__post_init__()
    if retained_fields.snapshot is not snapshot:
        raise TiingoEodError("retained-field proof does not bind the verified snapshot")
    if (
        identity_lifecycle.snapshot is not snapshot
        or identity_lifecycle.retained_fields is not retained_fields
    ):
        raise TiingoEodError(
            "identity/lifecycle proof does not bind the snapshot and retained-field proof"
        )
    artifact = TiingoEodMarketSemanticsArtifact.from_json_bytes(artifact_bytes)
    profile = snapshot.manifest.profile
    if profile.scope.symbols != PHASE1_TIINGO_SYMBOLS:
        raise TiingoEodError(
            "market-semantics qualification requires the exact Phase 1 symbol scope"
        )
    if artifact.trade_symbols != profile.scope.symbols:
        raise TiingoEodError("market-semantics artifact does not match the capture scope")
    if artifact.profile_contract_sha256 != profile.contract_sha256:
        raise TiingoEodError("market-semantics artifact does not bind the capture profile")
    if artifact.identity_lifecycle_qualification_sha256 != identity_lifecycle.qualification_sha256:
        raise TiingoEodError("market-semantics artifact does not bind the identity/lifecycle proof")
    if artifact.market_provenance_label != profile.market_provenance:
        raise TiingoEodError("market-semantics provenance label does not match the capture profile")
    if artifact.corporate_action_authority != profile.corporate_action_authority:
        raise TiingoEodError("market-semantics action authority does not match the capture profile")
    if artifact.market_semantics_source_id == profile.source_id:
        raise TiingoEodError(
            "market-semantics evidence source must differ from the capture transport source"
        )
    for calendar_binding in snapshot.calendar_bindings:
        for session in calendar_binding.sessions:
            if artifact.provenance.effective_from > session.opens_at or (
                artifact.provenance.effective_to is not None
                and artifact.provenance.effective_to <= session.closes_at
            ):
                raise TiingoEodError(
                    "market-semantics provenance does not cover every full pinned session"
                )
    mappings = identity_lifecycle.mappings
    if (
        type(mappings) is not tuple
        or tuple(symbol for symbol, _, _ in mappings) != PHASE1_TIINGO_SYMBOLS
    ):
        raise TiingoEodError("identity/lifecycle proof has invalid stable mappings")
    stable_ids = {security_id for _, security_id, _ in mappings}
    if len(stable_ids) != len(PHASE1_TIINGO_SYMBOLS):
        raise TiingoEodError("each trade symbol must resolve to a distinct stable identity")
    mapping_by_symbol = {symbol: (security_id, venue) for symbol, security_id, venue in mappings}
    binding_by_symbol = {binding.symbol: binding for binding in snapshot.calendar_bindings}
    resolved_rows: list[tuple[str, str, str]] = []
    for row in snapshot.rows:
        mapping = mapping_by_symbol.get(row.symbol)
        row_binding = binding_by_symbol.get(row.symbol)
        if (
            row.symbol not in artifact.trade_symbols
            or mapping is None
            or row_binding is None
            or mapping[1] != row_binding.venue
        ):
            raise TiingoEodError(
                "snapshot row does not resolve through the exact stable identity and venue"
            )
        resolved_rows.append((row.symbol, mapping[0], mapping[1]))
    exact_resolved_rows = tuple(resolved_rows)
    field_semantics_contract_sha256 = _digest(
        {
            "adjusted_methodology_evidence_sha256": (artifact.adjusted_methodology_evidence_sha256),
            "field_partition": artifact.field_partition.to_dict(),
            "market_provenance_evidence_sha256": (artifact.market_provenance_evidence_sha256),
            "market_provenance_label": artifact.market_provenance_label,
            "market_semantics_source_id": artifact.market_semantics_source_id,
            "provenance": artifact.provenance.to_dict(),
            "raw_semantics_evidence_sha256": artifact.raw_semantics_evidence_sha256,
        }
    )
    action_candidate_contract_sha256 = _digest(
        {
            "action_candidate_convention": artifact.action_candidate_convention.to_dict(),
            "corporate_action_authority": artifact.corporate_action_authority,
            "corporate_action_candidate_evidence_sha256": (
                artifact.corporate_action_candidate_evidence_sha256
            ),
            "market_semantics_source_id": artifact.market_semantics_source_id,
        }
    )
    synthetic_case_contract_sha256 = _digest([case.to_dict() for case in artifact.synthetic_cases])
    material = _qualification_material(
        artifact=artifact,
        snapshot=snapshot,
        retained_fields=retained_fields,
        identity_lifecycle=identity_lifecycle,
        field_semantics_contract_sha256=field_semantics_contract_sha256,
        action_candidate_contract_sha256=action_candidate_contract_sha256,
        synthetic_case_contract_sha256=synthetic_case_contract_sha256,
        stable_id_count=len(stable_ids),
        resolved_rows=exact_resolved_rows,
    )
    return _DerivedMarketSemanticsQualification(
        artifact=artifact,
        scope=profile.scope,
        profile_contract_sha256=profile.contract_sha256,
        calendar_artifact_sha256=snapshot.calendar_artifact_sha256,
        snapshot_semantic_sha256=snapshot.semantic_sha256,
        retained_field_qualification_sha256=retained_fields.qualification_sha256,
        identity_lifecycle_qualification_sha256=identity_lifecycle.qualification_sha256,
        field_semantics_contract_sha256=field_semantics_contract_sha256,
        action_candidate_contract_sha256=action_candidate_contract_sha256,
        synthetic_case_contract_sha256=synthetic_case_contract_sha256,
        row_count=len(snapshot.rows),
        stable_id_count=len(stable_ids),
        candidate_field_count=len(_CORPORATE_ACTION_CANDIDATE_FIELDS),
        candidate_occurrence_count=len(snapshot.rows) * len(_CORPORATE_ACTION_CANDIDATE_FIELDS),
        resolved_rows=exact_resolved_rows,
        qualification_sha256=_digest(material),
    )


def _not_authorized(name: str) -> NoReturn:
    raise TiingoEodError(f"market-semantics contract-only qualification cannot produce {name}")


@dataclass(frozen=True, slots=True, init=False)
class TiingoEodMarketSemanticsQualification:
    """Proof-constructed value-free result with no downstream authority."""

    snapshot: TiingoEodVerifiedResearchSnapshot = field(repr=False)
    retained_fields: TiingoEodRetainedFieldQualification = field(repr=False)
    identity_lifecycle: TiingoEodIdentityLifecycleQualification = field(repr=False)
    artifact_bytes: bytes = field(repr=False)
    resolved_rows: tuple[tuple[str, str, str], ...] = field(repr=False)
    artifact_kind: TiingoEodMarketSemanticsArtifactKind
    artifact_sha256: str
    scope: TiingoEodScope
    profile_contract_sha256: str
    calendar_artifact_sha256: str
    snapshot_semantic_sha256: str
    retained_field_qualification_sha256: str
    identity_lifecycle_qualification_sha256: str
    field_semantics_contract_sha256: str
    action_candidate_contract_sha256: str
    synthetic_case_contract_sha256: str
    row_count: int
    stable_id_count: int
    candidate_field_count: int
    candidate_occurrence_count: int
    synthetic_case_count: int
    qualification_sha256: str
    adjustment_methodology_effect: str = "none"
    admission_effect: str = "none"
    canonical_bar_effect: str = "none"
    corporate_action_effect: str = "none"
    correction_effect: str = "none"
    genuine_raw_effect: str = "none"
    historical_source_effect: str = "none"
    market_provenance_effect: str = "none"
    trading_effect: str = "none"
    vendor_publication_effect: str = "none"
    check_ids: tuple[str, ...] = TIINGO_EOD_MARKET_SEMANTICS_CHECK_IDS
    qualification_kind: TiingoEodMarketSemanticsQualificationKind = (
        TiingoEodMarketSemanticsQualificationKind.MARKET_SEMANTICS_CONTRACT_ONLY
    )
    schema_version: str = TIINGO_EOD_MARKET_SEMANTICS_QUALIFICATION_SCHEMA_VERSION

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("market-semantics qualifications can only be created by the qualifier")

    @classmethod
    def _from_derived(
        cls,
        *,
        snapshot: TiingoEodVerifiedResearchSnapshot,
        retained_fields: TiingoEodRetainedFieldQualification,
        identity_lifecycle: TiingoEodIdentityLifecycleQualification,
        artifact_bytes: bytes,
        derived: _DerivedMarketSemanticsQualification,
    ) -> TiingoEodMarketSemanticsQualification:
        if cls is not TiingoEodMarketSemanticsQualification:
            raise TypeError("market-semantics qualification subclasses are not supported")
        result = object.__new__(cls)
        values: tuple[tuple[str, object], ...] = (
            ("snapshot", snapshot),
            ("retained_fields", retained_fields),
            ("identity_lifecycle", identity_lifecycle),
            ("artifact_bytes", artifact_bytes),
            ("resolved_rows", derived.resolved_rows),
            ("artifact_kind", derived.artifact.artifact_kind),
            ("artifact_sha256", derived.artifact.artifact_sha256),
            ("scope", derived.scope),
            ("profile_contract_sha256", derived.profile_contract_sha256),
            ("calendar_artifact_sha256", derived.calendar_artifact_sha256),
            ("snapshot_semantic_sha256", derived.snapshot_semantic_sha256),
            (
                "retained_field_qualification_sha256",
                derived.retained_field_qualification_sha256,
            ),
            (
                "identity_lifecycle_qualification_sha256",
                derived.identity_lifecycle_qualification_sha256,
            ),
            (
                "field_semantics_contract_sha256",
                derived.field_semantics_contract_sha256,
            ),
            (
                "action_candidate_contract_sha256",
                derived.action_candidate_contract_sha256,
            ),
            (
                "synthetic_case_contract_sha256",
                derived.synthetic_case_contract_sha256,
            ),
            ("row_count", derived.row_count),
            ("stable_id_count", derived.stable_id_count),
            ("candidate_field_count", derived.candidate_field_count),
            ("candidate_occurrence_count", derived.candidate_occurrence_count),
            ("synthetic_case_count", len(derived.artifact.synthetic_cases)),
            ("qualification_sha256", derived.qualification_sha256),
            ("adjustment_methodology_effect", "none"),
            ("admission_effect", "none"),
            ("canonical_bar_effect", "none"),
            ("corporate_action_effect", "none"),
            ("correction_effect", "none"),
            ("genuine_raw_effect", "none"),
            ("historical_source_effect", "none"),
            ("market_provenance_effect", "none"),
            ("trading_effect", "none"),
            ("vendor_publication_effect", "none"),
            ("check_ids", TIINGO_EOD_MARKET_SEMANTICS_CHECK_IDS),
            (
                "qualification_kind",
                TiingoEodMarketSemanticsQualificationKind.MARKET_SEMANTICS_CONTRACT_ONLY,
            ),
            ("schema_version", TIINGO_EOD_MARKET_SEMANTICS_QUALIFICATION_SCHEMA_VERSION),
        )
        for field_name, value in values:
            object.__setattr__(result, field_name, value)
        result.__post_init__()
        return result

    def __post_init__(self) -> None:
        try:
            derived = _derive_market_semantics_qualification(
                snapshot=self.snapshot,
                retained_fields=self.retained_fields,
                identity_lifecycle=self.identity_lifecycle,
                artifact_bytes=self.artifact_bytes,
            )
        except (AttributeError, TypeError, ValueError) as error:
            if isinstance(error, TiingoEodError):
                raise
            raise TiingoEodError(f"market-semantics proof is invalid: {error}") from error
        expected = {
            "artifact_kind": derived.artifact.artifact_kind,
            "artifact_sha256": derived.artifact.artifact_sha256,
            "scope": derived.scope,
            "profile_contract_sha256": derived.profile_contract_sha256,
            "calendar_artifact_sha256": derived.calendar_artifact_sha256,
            "snapshot_semantic_sha256": derived.snapshot_semantic_sha256,
            "retained_field_qualification_sha256": (derived.retained_field_qualification_sha256),
            "identity_lifecycle_qualification_sha256": (
                derived.identity_lifecycle_qualification_sha256
            ),
            "field_semantics_contract_sha256": derived.field_semantics_contract_sha256,
            "action_candidate_contract_sha256": derived.action_candidate_contract_sha256,
            "synthetic_case_contract_sha256": derived.synthetic_case_contract_sha256,
            "row_count": derived.row_count,
            "stable_id_count": derived.stable_id_count,
            "candidate_field_count": derived.candidate_field_count,
            "candidate_occurrence_count": derived.candidate_occurrence_count,
            "synthetic_case_count": len(derived.artifact.synthetic_cases),
            "resolved_rows": derived.resolved_rows,
            "qualification_sha256": derived.qualification_sha256,
        }
        if any(getattr(self, name) != value for name, value in expected.items()):
            raise TiingoEodError("market-semantics qualification was not exactly re-derived")
        for name in (
            "adjustment_methodology_effect",
            "admission_effect",
            "canonical_bar_effect",
            "corporate_action_effect",
            "correction_effect",
            "genuine_raw_effect",
            "historical_source_effect",
            "market_provenance_effect",
            "trading_effect",
            "vendor_publication_effect",
        ):
            if getattr(self, name) != "none":
                raise TiingoEodError("market-semantics qualification effects must remain none")
        if self.check_ids != TIINGO_EOD_MARKET_SEMANTICS_CHECK_IDS:
            raise TiingoEodError("market-semantics check contract was altered")
        if (
            self.qualification_kind
            is not TiingoEodMarketSemanticsQualificationKind.MARKET_SEMANTICS_CONTRACT_ONLY
        ):
            raise TiingoEodError("market-semantics qualification kind is unsupported")
        if self.schema_version != TIINGO_EOD_MARKET_SEMANTICS_QUALIFICATION_SCHEMA_VERSION:
            raise TiingoEodError("market-semantics qualification schema is unsupported")

    def raw_bar_records(self) -> NoReturn:
        _not_authorized("raw bar records")

    def vendor_bar_records(self) -> NoReturn:
        _not_authorized("vendor bar records")

    def canonical_bar_records(self) -> NoReturn:
        _not_authorized("canonical bar records")

    def corporate_action_records(self) -> NoReturn:
        _not_authorized("corporate-action records")

    def security_master(self) -> NoReturn:
        _not_authorized("a production SecurityMaster")

    def historical_source_bundle(self) -> NoReturn:
        _not_authorized("a HistoricalSourceBundle")

    def historical_bar_source(self) -> NoReturn:
        _not_authorized("a HistoricalBarSource")

    def admission_evidence(self) -> NoReturn:
        _not_authorized("admission evidence")


def qualify_tiingo_eod_market_semantics(
    *,
    snapshot: TiingoEodVerifiedResearchSnapshot,
    retained_fields: TiingoEodRetainedFieldQualification,
    identity_lifecycle: TiingoEodIdentityLifecycleQualification,
    artifact_bytes: bytes,
) -> TiingoEodMarketSemanticsQualification:
    """Derive one deterministic, permanently non-authorizing contract proof."""

    if type(artifact_bytes) is not bytes:
        raise TiingoEodError("market-semantics artifact must be exact immutable bytes")
    derived = _derive_market_semantics_qualification(
        snapshot=snapshot,
        retained_fields=retained_fields,
        identity_lifecycle=identity_lifecycle,
        artifact_bytes=artifact_bytes,
    )
    return TiingoEodMarketSemanticsQualification._from_derived(
        snapshot=snapshot,
        retained_fields=retained_fields,
        identity_lifecycle=identity_lifecycle,
        artifact_bytes=artifact_bytes,
        derived=derived,
    )


__all__ = [
    "MAX_TIINGO_EOD_MARKET_SEMANTICS_ARTIFACT_BYTES",
    "TIINGO_EOD_MARKET_SEMANTICS_ARTIFACT_SCHEMA_VERSION",
    "TIINGO_EOD_MARKET_SEMANTICS_CHECK_IDS",
    "TIINGO_EOD_MARKET_SEMANTICS_QUALIFICATION_SCHEMA_VERSION",
    "TiingoEodActionCandidateConvention",
    "TiingoEodMarketProvenanceContract",
    "TiingoEodMarketSemanticsArtifact",
    "TiingoEodMarketSemanticsArtifactKind",
    "TiingoEodMarketSemanticsFieldPartition",
    "TiingoEodMarketSemanticsQualification",
    "TiingoEodMarketSemanticsQualificationKind",
    "TiingoEodMarketSemanticsSyntheticCase",
    "qualify_tiingo_eod_market_semantics",
]
