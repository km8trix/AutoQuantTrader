"""Contract-only Tiingo EOD security-identity and lifecycle qualification.

This module validates a bounded reference artifact against one exact verified
capture and its retained-field proof.  It proves parser, causal-resolution, and
lifecycle-transition behavior only.  It does not establish that the reference
facts are correct in the real market and grants no canonical, source,
admission, or trading authority.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from itertools import pairwise
from typing import NoReturn, cast

from packages.adapters.market_data.tiingo_eod import (
    PHASE1_TIINGO_SYMBOLS,
    TIINGO_DATASET,
    TIINGO_PROVIDER,
    TiingoEodError,
    TiingoEodScope,
    _boolean,
    _datetime,
    _fields,
    _integer,
    _json,
    _object,
    _text,
    _timestamp,
)
from packages.adapters.market_data.tiingo_eod_retained_fields import (
    TiingoEodRetainedFieldQualification,
)
from packages.adapters.market_data.tiingo_eod_snapshot import (
    TiingoEodVerifiedResearchSnapshot,
)
from packages.market_data import (
    AssetClass,
    NonTradableSecurityError,
    RevisionPolicy,
    Security,
    SecurityIdentifier,
    SecurityMaster,
    SecurityResolutionError,
    UniverseMembership,
)
from packages.market_data.models import require_digest, require_text, require_utc
from packages.market_data.temporal import RevisionConflictError, select_as_of

TIINGO_EOD_IDENTITY_LIFECYCLE_ARTIFACT_SCHEMA_VERSION = "tiingo-eod-identity-lifecycle-artifact-v1"
TIINGO_EOD_IDENTITY_LIFECYCLE_QUALIFICATION_SCHEMA_VERSION = (
    "tiingo-eod-identity-lifecycle-qualification-v1"
)
MAX_TIINGO_EOD_IDENTITY_LIFECYCLE_ARTIFACT_BYTES = 1_048_576
TIINGO_EOD_IDENTITY_LIFECYCLE_CHECK_IDS = (
    "exact-phase1-trade-symbol-scope-v1",
    "bounded-etf-usd-security-contract-v1",
    "profile-and-identifier-authority-binding-v1",
    "canonical-reference-artifact-v1",
    "artifact-internal-contiguous-revision-chains-v1",
    "full-session-unique-identifier-resolution-v1",
    "full-session-exact-trade-universe-membership-v1",
    "isolated-stable-identity-symbol-change-v1",
    "isolated-tradable-to-nontradable-delisting-v1",
    "lifecycle-corpus-trade-exclusion-v1",
    "snapshot-retained-field-proof-binding-v1",
)


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


def _nonzero_digest(value: str, field_name: str) -> None:
    require_digest(value, field_name)
    if value == "0" * 64:
        raise ValueError(f"{field_name} must identify exact evidence")


def _optional_timestamp(value: datetime | None) -> str | None:
    return None if value is None else _timestamp(value)


class TiingoEodIdentityLifecycleArtifactKind(StrEnum):
    """Provenance category asserted by a reference artifact."""

    SYNTHETIC_CONTRACT = "synthetic_contract"
    REVIEWED_REFERENCE = "reviewed_reference"


class TiingoEodIdentityLifecycleQualificationKind(StrEnum):
    """The only conclusion this boundary can support."""

    IDENTITY_LIFECYCLE_CONTRACT_ONLY = "identity_lifecycle_contract_only"


@dataclass(frozen=True, slots=True)
class TiingoEodSourcedUniverseMembership:
    """A universe fact plus the source absent from the generic domain type."""

    source_id: str
    membership: UniverseMembership

    def __post_init__(self) -> None:
        require_text(self.source_id, "membership source_id")
        if type(self.membership) is not UniverseMembership:
            raise ValueError("membership must be an exact UniverseMembership")
        self.membership.__post_init__()


@dataclass(frozen=True, slots=True)
class TiingoEodSymbolChangeCase:
    """One synthetic or reviewed stable-identity ticker transition."""

    case_id: str
    security_id: str
    old_symbol: str
    old_venue: str
    new_symbol: str
    new_venue: str
    effective_at: datetime

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.case_id, "symbol-change case_id"),
            (self.security_id, "symbol-change security_id"),
            (self.old_symbol, "symbol-change old_symbol"),
            (self.old_venue, "symbol-change old_venue"),
            (self.new_symbol, "symbol-change new_symbol"),
            (self.new_venue, "symbol-change new_venue"),
        ):
            require_text(value, field_name)
        if (
            self.old_symbol != self.old_symbol.upper()
            or self.new_symbol != self.new_symbol.upper()
            or self.old_venue != self.old_venue.upper()
            or self.new_venue != self.new_venue.upper()
        ):
            raise ValueError("symbol-change symbols and venues must be canonical uppercase")
        if self.old_symbol == self.new_symbol:
            raise ValueError("symbol-change case requires distinct old and new symbols")
        require_utc(self.effective_at, "symbol-change effective_at")


@dataclass(frozen=True, slots=True)
class TiingoEodDelistingCase:
    """One synthetic or reviewed tradable-to-nontradable transition."""

    case_id: str
    security_id: str
    symbol: str
    venue: str
    effective_at: datetime

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.case_id, "delisting case_id"),
            (self.security_id, "delisting security_id"),
            (self.symbol, "delisting symbol"),
            (self.venue, "delisting venue"),
        ):
            require_text(value, field_name)
        if self.symbol != self.symbol.upper() or self.venue != self.venue.upper():
            raise ValueError("delisting symbol and venue must be canonical uppercase")
        require_utc(self.effective_at, "delisting effective_at")


def _security_dict(security: Security) -> dict[str, object]:
    return {
        "asset_class": security.asset_class.value,
        "currency": security.currency,
        "name": security.name,
        "security_id": security.security_id,
    }


def _identifier_dict(identifier: SecurityIdentifier) -> dict[str, object]:
    return {
        "available_at": _timestamp(identifier.available_at),
        "effective_from": _timestamp(identifier.effective_from),
        "effective_to": _optional_timestamp(identifier.effective_to),
        "event_revision_id": identifier.event_revision_id,
        "observation_id": identifier.observation_id,
        "revision": identifier.revision,
        "security_id": identifier.security_id,
        "source_id": identifier.source_id,
        "supersedes_event_revision_id": identifier.supersedes_event_revision_id,
        "symbol": identifier.symbol,
        "tradable": identifier.tradable,
        "venue": identifier.venue,
    }


def _membership_dict(value: TiingoEodSourcedUniverseMembership) -> dict[str, object]:
    membership = value.membership
    return {
        "available_at": _timestamp(membership.available_at),
        "effective_from": _timestamp(membership.effective_from),
        "effective_to": _optional_timestamp(membership.effective_to),
        "event_revision_id": membership.event_revision_id,
        "included": membership.included,
        "observation_id": membership.observation_id,
        "revision": membership.revision,
        "security_id": membership.security_id,
        "source_id": value.source_id,
        "supersedes_event_revision_id": membership.supersedes_event_revision_id,
        "universe_id": membership.universe_id,
    }


def _symbol_change_dict(value: TiingoEodSymbolChangeCase) -> dict[str, object]:
    return {
        "case_id": value.case_id,
        "effective_at": _timestamp(value.effective_at),
        "new_symbol": value.new_symbol,
        "new_venue": value.new_venue,
        "old_symbol": value.old_symbol,
        "old_venue": value.old_venue,
        "security_id": value.security_id,
    }


def _delisting_dict(value: TiingoEodDelistingCase) -> dict[str, object]:
    return {
        "case_id": value.case_id,
        "effective_at": _timestamp(value.effective_at),
        "security_id": value.security_id,
        "symbol": value.symbol,
        "venue": value.venue,
    }


def _security_from_dict(value: object, index: int) -> Security:
    field_name = f"securities[{index}]"
    payload = _object(value, field_name)
    _fields(payload, {"asset_class", "currency", "name", "security_id"}, field_name)
    try:
        return Security(
            security_id=_text(payload["security_id"], f"{field_name}.security_id"),
            asset_class=AssetClass(_text(payload["asset_class"], f"{field_name}.asset_class")),
            currency=_text(payload["currency"], f"{field_name}.currency"),
            name=_text(payload["name"], f"{field_name}.name"),
        )
    except ValueError as error:
        raise TiingoEodError(f"{field_name} is invalid: {error}") from error


def _identifier_from_dict(value: object, index: int) -> SecurityIdentifier:
    field_name = f"identifiers[{index}]"
    payload = _object(value, field_name)
    _fields(
        payload,
        {
            "available_at",
            "effective_from",
            "effective_to",
            "event_revision_id",
            "observation_id",
            "revision",
            "security_id",
            "source_id",
            "supersedes_event_revision_id",
            "symbol",
            "tradable",
            "venue",
        },
        field_name,
    )
    try:
        return SecurityIdentifier(
            observation_id=_text(payload["observation_id"], f"{field_name}.observation_id"),
            event_revision_id=_text(
                payload["event_revision_id"], f"{field_name}.event_revision_id"
            ),
            security_id=_text(payload["security_id"], f"{field_name}.security_id"),
            source_id=_text(payload["source_id"], f"{field_name}.source_id"),
            symbol=_text(payload["symbol"], f"{field_name}.symbol"),
            venue=_text(payload["venue"], f"{field_name}.venue"),
            effective_from=_datetime(payload["effective_from"], f"{field_name}.effective_from"),
            effective_to=_optional_datetime(payload["effective_to"], f"{field_name}.effective_to"),
            available_at=_datetime(payload["available_at"], f"{field_name}.available_at"),
            tradable=_boolean(payload["tradable"], f"{field_name}.tradable"),
            revision=_integer(payload["revision"], f"{field_name}.revision"),
            supersedes_event_revision_id=_optional_text(
                payload["supersedes_event_revision_id"],
                f"{field_name}.supersedes_event_revision_id",
            ),
        )
    except ValueError as error:
        if isinstance(error, TiingoEodError):
            raise
        raise TiingoEodError(f"{field_name} is invalid: {error}") from error


def _membership_from_dict(
    value: object,
    index: int,
) -> TiingoEodSourcedUniverseMembership:
    field_name = f"memberships[{index}]"
    payload = _object(value, field_name)
    _fields(
        payload,
        {
            "available_at",
            "effective_from",
            "effective_to",
            "event_revision_id",
            "included",
            "observation_id",
            "revision",
            "security_id",
            "source_id",
            "supersedes_event_revision_id",
            "universe_id",
        },
        field_name,
    )
    try:
        membership = UniverseMembership(
            observation_id=_text(payload["observation_id"], f"{field_name}.observation_id"),
            event_revision_id=_text(
                payload["event_revision_id"], f"{field_name}.event_revision_id"
            ),
            universe_id=_text(payload["universe_id"], f"{field_name}.universe_id"),
            security_id=_text(payload["security_id"], f"{field_name}.security_id"),
            effective_from=_datetime(payload["effective_from"], f"{field_name}.effective_from"),
            effective_to=_optional_datetime(payload["effective_to"], f"{field_name}.effective_to"),
            available_at=_datetime(payload["available_at"], f"{field_name}.available_at"),
            included=_boolean(payload["included"], f"{field_name}.included"),
            revision=_integer(payload["revision"], f"{field_name}.revision"),
            supersedes_event_revision_id=_optional_text(
                payload["supersedes_event_revision_id"],
                f"{field_name}.supersedes_event_revision_id",
            ),
        )
        return TiingoEodSourcedUniverseMembership(
            source_id=_text(payload["source_id"], f"{field_name}.source_id"),
            membership=membership,
        )
    except ValueError as error:
        if isinstance(error, TiingoEodError):
            raise
        raise TiingoEodError(f"{field_name} is invalid: {error}") from error


def _symbol_change_from_dict(value: object) -> TiingoEodSymbolChangeCase:
    payload = _object(value, "symbol_change_case")
    _fields(
        payload,
        {
            "case_id",
            "effective_at",
            "new_symbol",
            "new_venue",
            "old_symbol",
            "old_venue",
            "security_id",
        },
        "symbol_change_case",
    )
    try:
        return TiingoEodSymbolChangeCase(
            case_id=_text(payload["case_id"], "symbol_change_case.case_id"),
            security_id=_text(payload["security_id"], "symbol_change_case.security_id"),
            old_symbol=_text(payload["old_symbol"], "symbol_change_case.old_symbol"),
            old_venue=_text(payload["old_venue"], "symbol_change_case.old_venue"),
            new_symbol=_text(payload["new_symbol"], "symbol_change_case.new_symbol"),
            new_venue=_text(payload["new_venue"], "symbol_change_case.new_venue"),
            effective_at=_datetime(payload["effective_at"], "symbol_change_case.effective_at"),
        )
    except ValueError as error:
        if isinstance(error, TiingoEodError):
            raise
        raise TiingoEodError(f"symbol_change_case is invalid: {error}") from error


def _delisting_from_dict(value: object) -> TiingoEodDelistingCase:
    payload = _object(value, "delisting_case")
    _fields(
        payload,
        {"case_id", "effective_at", "security_id", "symbol", "venue"},
        "delisting_case",
    )
    try:
        return TiingoEodDelistingCase(
            case_id=_text(payload["case_id"], "delisting_case.case_id"),
            security_id=_text(payload["security_id"], "delisting_case.security_id"),
            symbol=_text(payload["symbol"], "delisting_case.symbol"),
            venue=_text(payload["venue"], "delisting_case.venue"),
            effective_at=_datetime(payload["effective_at"], "delisting_case.effective_at"),
        )
    except ValueError as error:
        if isinstance(error, TiingoEodError):
            raise
        raise TiingoEodError(f"delisting_case is invalid: {error}") from error


def _identifier_sort_key(
    value: SecurityIdentifier,
) -> tuple[str, str, str, datetime, str, int, str]:
    return (
        value.security_id,
        value.symbol,
        value.venue,
        value.effective_from,
        value.observation_id,
        value.revision,
        value.event_revision_id,
    )


def _membership_sort_key(
    value: TiingoEodSourcedUniverseMembership,
) -> tuple[str, str, datetime, str, int, str]:
    membership = value.membership
    return (
        membership.universe_id,
        membership.security_id,
        membership.effective_from,
        membership.observation_id,
        membership.revision,
        membership.event_revision_id,
    )


def _validate_identifier_chains(identifiers: tuple[SecurityIdentifier, ...]) -> None:
    by_observation: dict[str, list[SecurityIdentifier]] = defaultdict(list)
    event_ids: set[str] = set()
    for identifier in identifiers:
        if identifier.event_revision_id in event_ids:
            raise ValueError("identifier event_revision_id values must be globally unique")
        event_ids.add(identifier.event_revision_id)
        by_observation[identifier.observation_id].append(identifier)
    for observation_id, values in by_observation.items():
        chain = sorted(values, key=lambda value: value.revision)
        if [value.revision for value in chain] != list(range(1, len(chain) + 1)):
            raise ValueError(
                f"identifier observation {observation_id!r} has a non-contiguous revision chain"
            )
        if len({(value.security_id, value.source_id) for value in chain}) != 1:
            raise ValueError("identifier corrections cannot change security or authority source")
        for previous, current in pairwise(chain):
            if current.supersedes_event_revision_id != previous.event_revision_id:
                raise ValueError("identifier revision does not supersede its exact predecessor")
            if current.available_at <= previous.available_at:
                raise ValueError("identifier revision availability must increase strictly")


def _validate_membership_chains(
    memberships: tuple[TiingoEodSourcedUniverseMembership, ...],
) -> None:
    by_observation: dict[str, list[TiingoEodSourcedUniverseMembership]] = defaultdict(list)
    event_ids: set[str] = set()
    for sourced in memberships:
        membership = sourced.membership
        if membership.event_revision_id in event_ids:
            raise ValueError("membership event_revision_id values must be globally unique")
        event_ids.add(membership.event_revision_id)
        by_observation[membership.observation_id].append(sourced)
    for observation_id, values in by_observation.items():
        chain = sorted(values, key=lambda value: value.membership.revision)
        if [value.membership.revision for value in chain] != list(range(1, len(chain) + 1)):
            raise ValueError(
                f"membership observation {observation_id!r} has a non-contiguous revision chain"
            )
        if (
            len(
                {
                    (
                        value.membership.security_id,
                        value.membership.universe_id,
                        value.source_id,
                    )
                    for value in chain
                }
            )
            != 1
        ):
            raise ValueError("membership corrections cannot change security, universe, or source")
        for previous, current in pairwise(chain):
            if (
                current.membership.supersedes_event_revision_id
                != previous.membership.event_revision_id
            ):
                raise ValueError("membership revision does not supersede its exact predecessor")
            if current.membership.available_at <= previous.membership.available_at:
                raise ValueError("membership revision availability must increase strictly")


def _intervals_overlap(left: SecurityIdentifier, right: SecurityIdentifier) -> bool:
    return (left.effective_to is None or right.effective_from < left.effective_to) and (
        right.effective_to is None or left.effective_from < right.effective_to
    )


@dataclass(frozen=True, slots=True)
class TiingoEodIdentityLifecycleArtifact:
    """Canonical bounded reference facts; never a production SecurityMaster."""

    artifact_id: str
    artifact_kind: TiingoEodIdentityLifecycleArtifactKind
    approved: bool
    executor_id: str
    reviewer_id: str | None
    observed_at: datetime
    reviewed_at: datetime | None
    profile_contract_sha256: str
    identifier_authority: str
    identity_source_id: str
    identifier_evidence_sha256: str
    lifecycle_evidence_sha256: str
    trade_symbols: tuple[str, ...]
    universe_id: str
    universe_version: str
    securities: tuple[Security, ...]
    identifiers: tuple[SecurityIdentifier, ...]
    memberships: tuple[TiingoEodSourcedUniverseMembership, ...]
    symbol_change_case: TiingoEodSymbolChangeCase
    delisting_case: TiingoEodDelistingCase
    schema_version: str = TIINGO_EOD_IDENTITY_LIFECYCLE_ARTIFACT_SCHEMA_VERSION
    provider: str = TIINGO_PROVIDER
    dataset: str = TIINGO_DATASET

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.artifact_id, "artifact_id"),
            (self.executor_id, "executor_id"),
            (self.identifier_authority, "identifier_authority"),
            (self.identity_source_id, "identity_source_id"),
            (self.universe_id, "universe_id"),
            (self.universe_version, "universe_version"),
        ):
            require_text(value, field_name)
        if type(self.artifact_kind) is not TiingoEodIdentityLifecycleArtifactKind:
            raise ValueError("artifact_kind must use the exact artifact-kind enum")
        if type(self.approved) is not bool:
            raise ValueError("approved must be boolean")
        require_utc(self.observed_at, "observed_at")
        require_digest(self.profile_contract_sha256, "profile_contract_sha256")
        _nonzero_digest(self.profile_contract_sha256, "profile_contract_sha256")
        _nonzero_digest(self.identifier_evidence_sha256, "identifier_evidence_sha256")
        _nonzero_digest(self.lifecycle_evidence_sha256, "lifecycle_evidence_sha256")
        if self.schema_version != TIINGO_EOD_IDENTITY_LIFECYCLE_ARTIFACT_SCHEMA_VERSION:
            raise ValueError("unsupported Tiingo EOD identity/lifecycle artifact schema")
        if self.provider != TIINGO_PROVIDER or self.dataset != TIINGO_DATASET:
            raise ValueError("identity/lifecycle artifact does not identify Tiingo EOD")
        if self.artifact_kind is TiingoEodIdentityLifecycleArtifactKind.SYNTHETIC_CONTRACT:
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
        if type(self.trade_symbols) is not tuple:
            raise ValueError("trade_symbols must be an immutable tuple")
        if self.trade_symbols != PHASE1_TIINGO_SYMBOLS:
            raise ValueError("trade_symbols must exactly equal DIA, IWM, QQQ, and SPY")
        if (
            type(self.securities) is not tuple
            or not self.securities
            or any(type(value) is not Security for value in self.securities)
        ):
            raise ValueError("securities must be a non-empty tuple of exact Security values")
        if (
            type(self.identifiers) is not tuple
            or not self.identifiers
            or any(type(value) is not SecurityIdentifier for value in self.identifiers)
        ):
            raise ValueError(
                "identifiers must be a non-empty tuple of exact SecurityIdentifier values"
            )
        if (
            type(self.memberships) is not tuple
            or not self.memberships
            or any(
                type(value) is not TiingoEodSourcedUniverseMembership for value in self.memberships
            )
        ):
            raise ValueError("memberships must be exact sourced membership values")
        if type(self.symbol_change_case) is not TiingoEodSymbolChangeCase:
            raise ValueError("symbol_change_case must use the exact case type")
        if type(self.delisting_case) is not TiingoEodDelistingCase:
            raise ValueError("delisting_case must use the exact case type")
        for security in self.securities:
            security.__post_init__()
            if security.asset_class is not AssetClass.ETF or security.currency != "USD":
                raise ValueError("bounded identity/lifecycle securities must be USD ETFs")
        for identifier in self.identifiers:
            identifier.__post_init__()
        for sourced in self.memberships:
            sourced.__post_init__()
        self.symbol_change_case.__post_init__()
        self.delisting_case.__post_init__()
        if self.securities != tuple(sorted(self.securities, key=lambda value: value.security_id)):
            raise ValueError("securities must use canonical security_id order")
        if self.identifiers != tuple(sorted(self.identifiers, key=_identifier_sort_key)):
            raise ValueError("identifiers must use canonical causal order")
        if self.memberships != tuple(sorted(self.memberships, key=_membership_sort_key)):
            raise ValueError("memberships must use canonical causal order")
        security_ids = tuple(value.security_id for value in self.securities)
        if len(security_ids) != len(set(security_ids)):
            raise ValueError("security IDs must be unique")
        known_ids = set(security_ids)
        if any(identifier.security_id not in known_ids for identifier in self.identifiers):
            raise ValueError("every identifier must reference a known security")
        if any(sourced.membership.security_id not in known_ids for sourced in self.memberships):
            raise ValueError("every membership must reference a known security")
        if {identifier.security_id for identifier in self.identifiers} != known_ids:
            raise ValueError("every bounded security must have identifier facts")
        if any(identifier.source_id != self.identity_source_id for identifier in self.identifiers):
            raise ValueError("identifier source_id does not match the artifact identity source")
        if any(value.source_id != self.identity_source_id for value in self.memberships):
            raise ValueError("membership source_id does not match the artifact identity source")
        if any(value.membership.universe_id != self.universe_id for value in self.memberships):
            raise ValueError("membership universe_id does not match the frozen universe")
        if any(value.available_at > self.observed_at for value in self.identifiers) or any(
            value.membership.available_at > self.observed_at for value in self.memberships
        ):
            raise ValueError("artifact cannot use identity facts observed after observed_at")
        if (
            self.symbol_change_case.effective_at > self.observed_at
            or self.delisting_case.effective_at > self.observed_at
        ):
            raise ValueError("lifecycle cases must be effective by observed_at")
        lifecycle_symbols = {
            self.symbol_change_case.old_symbol,
            self.symbol_change_case.new_symbol,
            self.delisting_case.symbol,
        }
        if len(lifecycle_symbols) != 3:
            raise ValueError("lifecycle cases require three distinct symbols")
        if lifecycle_symbols & set(self.trade_symbols):
            raise ValueError("lifecycle symbols must be isolated from the trade allow-list")
        if self.symbol_change_case.security_id == self.delisting_case.security_id:
            raise ValueError("symbol-change and delisting cases require separate securities")
        lifecycle_security_ids = {
            self.symbol_change_case.security_id,
            self.delisting_case.security_id,
        }
        if (
            self.symbol_change_case.security_id not in known_ids
            or self.delisting_case.security_id not in known_ids
        ):
            raise ValueError("lifecycle cases must reference known securities")
        _validate_identifier_chains(self.identifiers)
        _validate_membership_chains(self.memberships)
        try:
            visible_identifiers = select_as_of(
                self.identifiers,
                as_of=self.observed_at,
                policy=RevisionPolicy.REVISED_AS_OF,
            )
            visible_memberships = select_as_of(
                tuple(value.membership for value in self.memberships),
                as_of=self.observed_at,
                policy=RevisionPolicy.REVISED_AS_OF,
            )
        except RevisionConflictError as error:
            raise ValueError(f"artifact has conflicting causal revisions: {error}") from error
        for index, left in enumerate(visible_identifiers):
            for right in visible_identifiers[index + 1 :]:
                if (
                    left.symbol == right.symbol
                    and left.venue == right.venue
                    and _intervals_overlap(left, right)
                ):
                    raise ValueError("visible identifier effective intervals cannot overlap")
        expected_symbols = set(self.trade_symbols) | lifecycle_symbols
        if {value.symbol for value in visible_identifiers} != expected_symbols:
            raise ValueError("visible identifier symbols do not exactly cover the bounded corpus")
        if len(visible_memberships) != len(self.trade_symbols) or any(
            not value.included for value in visible_memberships
        ):
            raise ValueError("visible universe facts must be four included memberships")
        trade_security_ids = {value.security_id for value in visible_memberships}
        if len(trade_security_ids) != len(self.trade_symbols):
            raise ValueError("visible universe facts must identify four distinct securities")
        if trade_security_ids & lifecycle_security_ids:
            raise ValueError("lifecycle securities cannot enter the trade universe")
        if known_ids != trade_security_ids | lifecycle_security_ids:
            raise ValueError("bounded corpus must contain exactly four trade and two lifecycle IDs")
        trade_identifiers = tuple(
            value for value in visible_identifiers if value.security_id in trade_security_ids
        )
        if (
            len(trade_identifiers) != len(self.trade_symbols)
            or {value.security_id for value in trade_identifiers} != trade_security_ids
            or {value.symbol for value in trade_identifiers} != set(self.trade_symbols)
            or any(not value.tradable for value in trade_identifiers)
        ):
            raise ValueError(
                "trade securities require exactly one tradable bounded symbol/venue mapping"
            )
        symbol_change_identifiers = tuple(
            value
            for value in visible_identifiers
            if value.security_id == self.symbol_change_case.security_id
        )
        if (
            len(symbol_change_identifiers) != 2
            or {(value.symbol, value.venue) for value in symbol_change_identifiers}
            != {
                (
                    self.symbol_change_case.old_symbol,
                    self.symbol_change_case.old_venue,
                ),
                (
                    self.symbol_change_case.new_symbol,
                    self.symbol_change_case.new_venue,
                ),
            }
            or any(not value.tradable for value in symbol_change_identifiers)
        ):
            raise ValueError("symbol-change security must own exactly its two lifecycle aliases")
        delisting_identifiers = tuple(
            value
            for value in visible_identifiers
            if value.security_id == self.delisting_case.security_id
        )
        if (
            len(delisting_identifiers) != 2
            or {(value.symbol, value.venue) for value in delisting_identifiers}
            != {(self.delisting_case.symbol, self.delisting_case.venue)}
            or {value.tradable for value in delisting_identifiers} != {False, True}
        ):
            raise ValueError(
                "delisting security must own exactly its tradable and nontradable lifecycle facts"
            )
        if len(self.to_json_bytes()) > MAX_TIINGO_EOD_IDENTITY_LIFECYCLE_ARTIFACT_BYTES:
            raise ValueError("identity/lifecycle artifact exceeds the size limit")

    @property
    def artifact_sha256(self) -> str:
        return hashlib.sha256(self.to_json_bytes()).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {
            "approved": self.approved,
            "artifact_id": self.artifact_id,
            "artifact_kind": self.artifact_kind.value,
            "dataset": self.dataset,
            "delisting_case": _delisting_dict(self.delisting_case),
            "executor_id": self.executor_id,
            "identifier_authority": self.identifier_authority,
            "identifier_evidence_sha256": self.identifier_evidence_sha256,
            "identifiers": [_identifier_dict(value) for value in self.identifiers],
            "identity_source_id": self.identity_source_id,
            "lifecycle_evidence_sha256": self.lifecycle_evidence_sha256,
            "memberships": [_membership_dict(value) for value in self.memberships],
            "observed_at": _timestamp(self.observed_at),
            "profile_contract_sha256": self.profile_contract_sha256,
            "provider": self.provider,
            "reviewed_at": _optional_timestamp(self.reviewed_at),
            "reviewer_id": self.reviewer_id,
            "schema_version": self.schema_version,
            "securities": [_security_dict(value) for value in self.securities],
            "symbol_change_case": _symbol_change_dict(self.symbol_change_case),
            "trade_symbols": list(self.trade_symbols),
            "universe_id": self.universe_id,
            "universe_version": self.universe_version,
        }

    def to_json_bytes(self) -> bytes:
        return (
            json.dumps(self.to_dict(), ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, payload_bytes: bytes) -> TiingoEodIdentityLifecycleArtifact:
        if type(payload_bytes) is not bytes or not payload_bytes:
            raise TiingoEodError("identity/lifecycle artifact must be non-empty immutable bytes")
        if len(payload_bytes) > MAX_TIINGO_EOD_IDENTITY_LIFECYCLE_ARTIFACT_BYTES:
            raise TiingoEodError("identity/lifecycle artifact exceeds the size limit")
        payload = _object(_json(payload_bytes), "identity/lifecycle artifact")
        _fields(
            payload,
            {
                "approved",
                "artifact_id",
                "artifact_kind",
                "dataset",
                "delisting_case",
                "executor_id",
                "identifier_authority",
                "identifier_evidence_sha256",
                "identifiers",
                "identity_source_id",
                "lifecycle_evidence_sha256",
                "memberships",
                "observed_at",
                "profile_contract_sha256",
                "provider",
                "reviewed_at",
                "reviewer_id",
                "schema_version",
                "securities",
                "symbol_change_case",
                "trade_symbols",
                "universe_id",
                "universe_version",
            },
            "identity/lifecycle artifact",
        )
        security_values = _array(payload["securities"], "securities")
        identifier_values = _array(payload["identifiers"], "identifiers")
        membership_values = _array(payload["memberships"], "memberships")
        trade_values = _array(payload["trade_symbols"], "trade_symbols")
        if not all(isinstance(value, str) for value in trade_values):
            raise TiingoEodError("trade_symbols must be an array of strings")
        try:
            artifact = cls(
                artifact_id=_text(payload["artifact_id"], "artifact_id"),
                artifact_kind=TiingoEodIdentityLifecycleArtifactKind(
                    _text(payload["artifact_kind"], "artifact_kind")
                ),
                approved=_boolean(payload["approved"], "approved"),
                executor_id=_text(payload["executor_id"], "executor_id"),
                reviewer_id=_optional_text(payload["reviewer_id"], "reviewer_id"),
                observed_at=_datetime(payload["observed_at"], "observed_at"),
                reviewed_at=_optional_datetime(payload["reviewed_at"], "reviewed_at"),
                profile_contract_sha256=_text(
                    payload["profile_contract_sha256"], "profile_contract_sha256"
                ),
                identifier_authority=_text(payload["identifier_authority"], "identifier_authority"),
                identity_source_id=_text(payload["identity_source_id"], "identity_source_id"),
                identifier_evidence_sha256=_text(
                    payload["identifier_evidence_sha256"],
                    "identifier_evidence_sha256",
                ),
                lifecycle_evidence_sha256=_text(
                    payload["lifecycle_evidence_sha256"],
                    "lifecycle_evidence_sha256",
                ),
                trade_symbols=tuple(cast(list[str], trade_values)),
                universe_id=_text(payload["universe_id"], "universe_id"),
                universe_version=_text(payload["universe_version"], "universe_version"),
                securities=tuple(
                    _security_from_dict(value, index) for index, value in enumerate(security_values)
                ),
                identifiers=tuple(
                    _identifier_from_dict(value, index)
                    for index, value in enumerate(identifier_values)
                ),
                memberships=tuple(
                    _membership_from_dict(value, index)
                    for index, value in enumerate(membership_values)
                ),
                symbol_change_case=_symbol_change_from_dict(payload["symbol_change_case"]),
                delisting_case=_delisting_from_dict(payload["delisting_case"]),
                schema_version=_text(payload["schema_version"], "schema_version"),
                provider=_text(payload["provider"], "provider"),
                dataset=_text(payload["dataset"], "dataset"),
            )
        except ValueError as error:
            if isinstance(error, TiingoEodError):
                raise
            raise TiingoEodError(f"identity/lifecycle artifact is invalid: {error}") from error
        if artifact.to_json_bytes() != payload_bytes:
            raise TiingoEodError("identity/lifecycle artifact must use exact canonical encoding")
        return artifact


@dataclass(frozen=True, slots=True)
class _DerivedIdentityLifecycleQualification:
    artifact: TiingoEodIdentityLifecycleArtifact
    scope: TiingoEodScope
    profile_contract_sha256: str
    calendar_artifact_sha256: str
    snapshot_semantic_sha256: str
    retained_field_qualification_sha256: str
    mappings: tuple[tuple[str, str, str], ...] = field(repr=False)
    session_mapping_count: int
    qualification_sha256: str


def _one_identifier(
    values: tuple[SecurityIdentifier, ...],
    *,
    security_id: str,
    symbol: str,
    venue: str,
    effective_from: datetime | None = None,
    effective_to: datetime | None = None,
    tradable: bool,
) -> SecurityIdentifier:
    matches = tuple(
        value
        for value in values
        if value.security_id == security_id
        and value.symbol == symbol
        and value.venue == venue
        and (effective_from is None or value.effective_from == effective_from)
        and (effective_to is None or value.effective_to == effective_to)
        and value.tradable is tradable
    )
    if len(matches) != 1:
        raise TiingoEodError("lifecycle case does not match exactly one visible identifier fact")
    return matches[0]


def _validate_lifecycle_cases(
    artifact: TiingoEodIdentityLifecycleArtifact,
    master: SecurityMaster,
    trade_security_ids: set[str],
) -> None:
    visible = select_as_of(
        artifact.identifiers,
        as_of=artifact.observed_at,
        policy=RevisionPolicy.REVISED_AS_OF,
    )
    change = artifact.symbol_change_case
    if change.security_id in trade_security_ids:
        raise TiingoEodError("symbol-change case cannot use a trade-enabled security")
    _one_identifier(
        visible,
        security_id=change.security_id,
        symbol=change.old_symbol,
        venue=change.old_venue,
        effective_to=change.effective_at,
        tradable=True,
    )
    _one_identifier(
        visible,
        security_id=change.security_id,
        symbol=change.new_symbol,
        venue=change.new_venue,
        effective_from=change.effective_at,
        tradable=True,
    )
    if any(
        value.security_id == change.security_id
        and value.symbol == change.old_symbol
        and value.venue == change.old_venue
        and (value.effective_to is None or value.effective_to > change.effective_at)
        for value in visible
    ):
        raise TiingoEodError("old symbol remains effective at or after the change boundary")
    if any(
        value.security_id == change.security_id
        and value.symbol == change.new_symbol
        and value.venue == change.new_venue
        and value.effective_from < change.effective_at
        for value in visible
    ):
        raise TiingoEodError("new symbol becomes effective before the change boundary")
    before_change = change.effective_at - timedelta(microseconds=1)
    old_mapping = master.resolve_identifier(
        symbol=change.old_symbol,
        venue=change.old_venue,
        effective_at=before_change,
        as_of=artifact.observed_at,
    )
    new_mapping = master.resolve_identifier(
        symbol=change.new_symbol,
        venue=change.new_venue,
        effective_at=change.effective_at,
        as_of=artifact.observed_at,
    )
    if old_mapping.security_id != new_mapping.security_id or (
        old_mapping.security_id != change.security_id
    ):
        raise TiingoEodError("symbol-change case does not preserve one stable security ID")

    delisting = artifact.delisting_case
    if delisting.security_id in trade_security_ids:
        raise TiingoEodError("delisting case cannot use a trade-enabled security")
    _one_identifier(
        visible,
        security_id=delisting.security_id,
        symbol=delisting.symbol,
        venue=delisting.venue,
        effective_to=delisting.effective_at,
        tradable=True,
    )
    _one_identifier(
        visible,
        security_id=delisting.security_id,
        symbol=delisting.symbol,
        venue=delisting.venue,
        effective_from=delisting.effective_at,
        tradable=False,
    )
    before_delisting = delisting.effective_at - timedelta(microseconds=1)
    before_mapping = master.resolve_identifier(
        symbol=delisting.symbol,
        venue=delisting.venue,
        effective_at=before_delisting,
        as_of=artifact.observed_at,
    )
    after_mapping = master.resolve_identifier(
        symbol=delisting.symbol,
        venue=delisting.venue,
        effective_at=delisting.effective_at,
        as_of=artifact.observed_at,
        require_tradable=False,
    )
    if (
        before_mapping.security_id != delisting.security_id
        or after_mapping.security_id != delisting.security_id
        or after_mapping.tradable
    ):
        raise TiingoEodError("delisting case does not preserve identity and stop tradability")
    try:
        master.resolve_identifier(
            symbol=delisting.symbol,
            venue=delisting.venue,
            effective_at=delisting.effective_at,
            as_of=artifact.observed_at,
        )
    except NonTradableSecurityError:
        pass
    else:
        raise TiingoEodError("delisted security unexpectedly resolves as tradable")
    if any(
        value.security_id == delisting.security_id
        and value.tradable
        and (value.effective_to is None or value.effective_to > delisting.effective_at)
        for value in visible
    ):
        raise TiingoEodError("delisting case contains post-delisting tradability")


def _qualification_material(
    *,
    artifact: TiingoEodIdentityLifecycleArtifact,
    snapshot: TiingoEodVerifiedResearchSnapshot,
    retained_fields: TiingoEodRetainedFieldQualification,
    mappings: tuple[tuple[str, str, str], ...],
    session_mapping_count: int,
) -> dict[str, object]:
    return {
        "admission_effect": "none",
        "artifact_kind": artifact.artifact_kind.value,
        "artifact_sha256": artifact.artifact_sha256,
        "calendar_artifact_sha256": snapshot.calendar_artifact_sha256,
        "canonical_bar_effect": "none",
        "check_ids": list(TIINGO_EOD_IDENTITY_LIFECYCLE_CHECK_IDS),
        "corporate_action_effect": "none",
        "delisting_case_count": 1,
        "historical_source_effect": "none",
        "identifier_count": len(artifact.identifiers),
        "lifecycle_calendar_effect": "none",
        "mapping_count": len(mappings),
        "mappings": [
            {"security_id": security_id, "symbol": symbol, "venue": venue}
            for symbol, security_id, venue in mappings
        ],
        "membership_count": len(artifact.memberships),
        "profile_contract_sha256": snapshot.manifest.profile_contract_sha256,
        "production_identity_effect": "none",
        "qualification_kind": (
            TiingoEodIdentityLifecycleQualificationKind.IDENTITY_LIFECYCLE_CONTRACT_ONLY.value
        ),
        "raw_execution_effect": "none",
        "retained_field_qualification_sha256": retained_fields.qualification_sha256,
        "schema_version": TIINGO_EOD_IDENTITY_LIFECYCLE_QUALIFICATION_SCHEMA_VERSION,
        "scope": snapshot.manifest.profile.scope.to_dict(),
        "security_count": len(artifact.securities),
        "session_mapping_count": session_mapping_count,
        "snapshot_semantic_sha256": snapshot.semantic_sha256,
        "symbol_change_case_count": 1,
        "trade_symbol_count": len(artifact.trade_symbols),
        "trading_effect": "none",
        "universe_id": artifact.universe_id,
        "universe_version": artifact.universe_version,
    }


def _derive_identity_lifecycle_qualification(
    *,
    snapshot: TiingoEodVerifiedResearchSnapshot,
    retained_fields: TiingoEodRetainedFieldQualification,
    artifact_bytes: bytes,
) -> _DerivedIdentityLifecycleQualification:
    if type(snapshot) is not TiingoEodVerifiedResearchSnapshot:
        raise TiingoEodError("identity qualification requires an exact verified snapshot")
    if type(retained_fields) is not TiingoEodRetainedFieldQualification:
        raise TiingoEodError("identity qualification requires an exact retained-field proof")
    snapshot.__post_init__()
    retained_fields.__post_init__()
    if retained_fields.snapshot != snapshot:
        raise TiingoEodError("retained-field proof does not bind the verified snapshot")
    artifact = TiingoEodIdentityLifecycleArtifact.from_json_bytes(artifact_bytes)
    if artifact.to_json_bytes() != artifact_bytes:
        raise TiingoEodError("identity/lifecycle artifact must use exact canonical encoding")
    profile = snapshot.manifest.profile
    if profile.scope.symbols != PHASE1_TIINGO_SYMBOLS:
        raise TiingoEodError("identity qualification requires the exact Phase 1 symbol scope")
    if artifact.trade_symbols != profile.scope.symbols:
        raise TiingoEodError("identity/lifecycle artifact does not match the capture scope")
    if artifact.profile_contract_sha256 != profile.contract_sha256:
        raise TiingoEodError("identity/lifecycle artifact does not bind the capture profile")
    if artifact.identifier_authority != profile.identifier_authority:
        raise TiingoEodError("identity/lifecycle artifact authority does not match the profile")

    master = SecurityMaster(
        securities=artifact.securities,
        identifiers=artifact.identifiers,
        memberships=tuple(value.membership for value in artifact.memberships),
    )
    bindings = {value.symbol: value for value in snapshot.calendar_bindings}
    resolved_rows: list[tuple[str, str, str]] = []
    by_symbol: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for row in snapshot.rows:
        binding = bindings[row.symbol]
        session = next(
            (value for value in binding.sessions if value.session_label == row.session_label),
            None,
        )
        if session is None:
            raise TiingoEodError("snapshot row does not have an exact pinned-calendar session")
        try:
            open_identifier = master.resolve_identifier(
                symbol=row.symbol,
                venue=binding.venue,
                effective_at=session.opens_at,
                as_of=artifact.observed_at,
            )
            close_identifier = master.resolve_identifier(
                symbol=row.symbol,
                venue=binding.venue,
                effective_at=session.closes_at,
                as_of=artifact.observed_at,
            )
        except SecurityResolutionError as error:
            raise TiingoEodError(
                "identity/lifecycle facts do not resolve every pinned session"
            ) from error
        if open_identifier != close_identifier:
            raise TiingoEodError("one identifier fact must continuously cover each pinned session")
        resolved_rows.append((row.symbol, close_identifier.security_id, binding.venue))
        by_symbol[row.symbol].add((close_identifier.security_id, binding.venue))
    if set(by_symbol) != set(PHASE1_TIINGO_SYMBOLS) or any(
        len(values) != 1 for values in by_symbol.values()
    ):
        raise TiingoEodError("each trade symbol must resolve to one stable security and venue")
    mappings = tuple((symbol, *next(iter(by_symbol[symbol]))) for symbol in PHASE1_TIINGO_SYMBOLS)
    trade_security_ids = {security_id for _, security_id, _ in mappings}
    if len(trade_security_ids) != len(PHASE1_TIINGO_SYMBOLS):
        raise TiingoEodError("trade symbols must map to four distinct internal securities")
    for row in snapshot.rows:
        binding = bindings[row.symbol]
        session = next(
            value for value in binding.sessions if value.session_label == row.session_label
        )
        try:
            boundary_members = tuple(
                master.universe_members(
                    universe_id=artifact.universe_id,
                    effective_at=instant,
                    as_of=artifact.observed_at,
                )
                for instant in (session.opens_at, session.closes_at)
            )
        except SecurityResolutionError as error:
            raise TiingoEodError(
                "identity/lifecycle universe facts do not resolve every pinned session"
            ) from error
        if any(
            {value.security_id for value in members} != trade_security_ids
            for members in boundary_members
        ):
            raise TiingoEodError("trade universe does not continuously cover every pinned session")
    try:
        _validate_lifecycle_cases(artifact, master, trade_security_ids)
    except SecurityResolutionError as error:
        raise TiingoEodError(
            "identity/lifecycle facts do not resolve the bounded lifecycle cases"
        ) from error
    material = _qualification_material(
        artifact=artifact,
        snapshot=snapshot,
        retained_fields=retained_fields,
        mappings=mappings,
        session_mapping_count=len(resolved_rows),
    )
    return _DerivedIdentityLifecycleQualification(
        artifact=artifact,
        scope=profile.scope,
        profile_contract_sha256=profile.contract_sha256,
        calendar_artifact_sha256=snapshot.calendar_artifact_sha256,
        snapshot_semantic_sha256=snapshot.semantic_sha256,
        retained_field_qualification_sha256=retained_fields.qualification_sha256,
        mappings=mappings,
        session_mapping_count=len(resolved_rows),
        qualification_sha256=_digest(material),
    )


def _not_authorized(name: str) -> NoReturn:
    raise TiingoEodError(f"identity/lifecycle contract-only qualification cannot produce {name}")


@dataclass(frozen=True, slots=True, init=False)
class TiingoEodIdentityLifecycleQualification:
    """Proof-constructed deterministic result with no downstream authority."""

    snapshot: TiingoEodVerifiedResearchSnapshot = field(repr=False)
    retained_fields: TiingoEodRetainedFieldQualification = field(repr=False)
    artifact_bytes: bytes = field(repr=False)
    artifact_kind: TiingoEodIdentityLifecycleArtifactKind
    artifact_sha256: str
    scope: TiingoEodScope
    profile_contract_sha256: str
    calendar_artifact_sha256: str
    snapshot_semantic_sha256: str
    retained_field_qualification_sha256: str
    mappings: tuple[tuple[str, str, str], ...] = field(repr=False)
    session_mapping_count: int
    security_count: int
    identifier_count: int
    membership_count: int
    mapping_count: int
    trade_symbol_count: int
    symbol_change_case_count: int
    delisting_case_count: int
    qualification_sha256: str
    production_identity_effect: str = "none"
    raw_execution_effect: str = "none"
    canonical_bar_effect: str = "none"
    corporate_action_effect: str = "none"
    lifecycle_calendar_effect: str = "none"
    historical_source_effect: str = "none"
    admission_effect: str = "none"
    trading_effect: str = "none"
    check_ids: tuple[str, ...] = TIINGO_EOD_IDENTITY_LIFECYCLE_CHECK_IDS
    qualification_kind: TiingoEodIdentityLifecycleQualificationKind = (
        TiingoEodIdentityLifecycleQualificationKind.IDENTITY_LIFECYCLE_CONTRACT_ONLY
    )
    schema_version: str = TIINGO_EOD_IDENTITY_LIFECYCLE_QUALIFICATION_SCHEMA_VERSION

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("identity/lifecycle qualifications can only be created by the qualifier")

    @classmethod
    def _from_derived(
        cls,
        *,
        snapshot: TiingoEodVerifiedResearchSnapshot,
        retained_fields: TiingoEodRetainedFieldQualification,
        artifact_bytes: bytes,
        derived: _DerivedIdentityLifecycleQualification,
    ) -> TiingoEodIdentityLifecycleQualification:
        if cls is not TiingoEodIdentityLifecycleQualification:
            raise TypeError("identity/lifecycle qualification subclasses are not supported")
        result = object.__new__(cls)
        values: tuple[tuple[str, object], ...] = (
            ("snapshot", snapshot),
            ("retained_fields", retained_fields),
            ("artifact_bytes", artifact_bytes),
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
            ("mappings", derived.mappings),
            ("session_mapping_count", derived.session_mapping_count),
            ("security_count", len(derived.artifact.securities)),
            ("identifier_count", len(derived.artifact.identifiers)),
            ("membership_count", len(derived.artifact.memberships)),
            ("mapping_count", len(derived.mappings)),
            ("trade_symbol_count", len(derived.artifact.trade_symbols)),
            ("symbol_change_case_count", 1),
            ("delisting_case_count", 1),
            ("qualification_sha256", derived.qualification_sha256),
            ("production_identity_effect", "none"),
            ("raw_execution_effect", "none"),
            ("canonical_bar_effect", "none"),
            ("corporate_action_effect", "none"),
            ("lifecycle_calendar_effect", "none"),
            ("historical_source_effect", "none"),
            ("admission_effect", "none"),
            ("trading_effect", "none"),
            ("check_ids", TIINGO_EOD_IDENTITY_LIFECYCLE_CHECK_IDS),
            (
                "qualification_kind",
                TiingoEodIdentityLifecycleQualificationKind.IDENTITY_LIFECYCLE_CONTRACT_ONLY,
            ),
            ("schema_version", TIINGO_EOD_IDENTITY_LIFECYCLE_QUALIFICATION_SCHEMA_VERSION),
        )
        for field_name, value in values:
            object.__setattr__(result, field_name, value)
        result.__post_init__()
        return result

    def __post_init__(self) -> None:
        try:
            derived = _derive_identity_lifecycle_qualification(
                snapshot=self.snapshot,
                retained_fields=self.retained_fields,
                artifact_bytes=self.artifact_bytes,
            )
        except (AttributeError, TypeError, ValueError) as error:
            if isinstance(error, TiingoEodError):
                raise
            raise TiingoEodError(f"identity/lifecycle proof is invalid: {error}") from error
        expected = {
            "artifact_kind": derived.artifact.artifact_kind,
            "artifact_sha256": derived.artifact.artifact_sha256,
            "scope": derived.scope,
            "profile_contract_sha256": derived.profile_contract_sha256,
            "calendar_artifact_sha256": derived.calendar_artifact_sha256,
            "snapshot_semantic_sha256": derived.snapshot_semantic_sha256,
            "retained_field_qualification_sha256": (derived.retained_field_qualification_sha256),
            "mappings": derived.mappings,
            "session_mapping_count": derived.session_mapping_count,
            "security_count": len(derived.artifact.securities),
            "identifier_count": len(derived.artifact.identifiers),
            "membership_count": len(derived.artifact.memberships),
            "mapping_count": len(derived.mappings),
            "trade_symbol_count": len(derived.artifact.trade_symbols),
            "symbol_change_case_count": 1,
            "delisting_case_count": 1,
            "qualification_sha256": derived.qualification_sha256,
        }
        if any(getattr(self, name) != value for name, value in expected.items()):
            raise TiingoEodError("identity/lifecycle qualification was not exactly re-derived")
        for name in (
            "production_identity_effect",
            "raw_execution_effect",
            "canonical_bar_effect",
            "corporate_action_effect",
            "lifecycle_calendar_effect",
            "historical_source_effect",
            "admission_effect",
            "trading_effect",
        ):
            if getattr(self, name) != "none":
                raise TiingoEodError("identity/lifecycle qualification effects must remain none")
        if self.check_ids != TIINGO_EOD_IDENTITY_LIFECYCLE_CHECK_IDS:
            raise TiingoEodError("identity/lifecycle check contract was altered")
        if (
            self.qualification_kind
            is not TiingoEodIdentityLifecycleQualificationKind.IDENTITY_LIFECYCLE_CONTRACT_ONLY
        ):
            raise TiingoEodError("identity/lifecycle qualification kind is unsupported")
        if self.schema_version != TIINGO_EOD_IDENTITY_LIFECYCLE_QUALIFICATION_SCHEMA_VERSION:
            raise TiingoEodError("identity/lifecycle qualification schema is unsupported")

    def security_master(self) -> NoReturn:
        _not_authorized("a production SecurityMaster")

    def raw_bar_records(self) -> NoReturn:
        _not_authorized("raw bar records")

    def canonical_bar_records(self) -> NoReturn:
        _not_authorized("canonical bar records")

    def corporate_action_records(self) -> NoReturn:
        _not_authorized("corporate-action records")

    def historical_source_bundle(self) -> NoReturn:
        _not_authorized("a HistoricalSourceBundle")

    def historical_bar_source(self) -> NoReturn:
        _not_authorized("a HistoricalBarSource")

    def admission_evidence(self) -> NoReturn:
        _not_authorized("admission evidence")


def qualify_tiingo_eod_identity_lifecycle(
    *,
    snapshot: TiingoEodVerifiedResearchSnapshot,
    retained_fields: TiingoEodRetainedFieldQualification,
    artifact_bytes: bytes,
) -> TiingoEodIdentityLifecycleQualification:
    """Derive one deterministic contract-only identity/lifecycle proof."""

    if type(artifact_bytes) is not bytes:
        raise TiingoEodError("identity/lifecycle artifact must be exact immutable bytes")
    derived = _derive_identity_lifecycle_qualification(
        snapshot=snapshot,
        retained_fields=retained_fields,
        artifact_bytes=artifact_bytes,
    )
    return TiingoEodIdentityLifecycleQualification._from_derived(
        snapshot=snapshot,
        retained_fields=retained_fields,
        artifact_bytes=artifact_bytes,
        derived=derived,
    )


__all__ = [
    "MAX_TIINGO_EOD_IDENTITY_LIFECYCLE_ARTIFACT_BYTES",
    "TIINGO_EOD_IDENTITY_LIFECYCLE_ARTIFACT_SCHEMA_VERSION",
    "TIINGO_EOD_IDENTITY_LIFECYCLE_CHECK_IDS",
    "TIINGO_EOD_IDENTITY_LIFECYCLE_QUALIFICATION_SCHEMA_VERSION",
    "TiingoEodDelistingCase",
    "TiingoEodIdentityLifecycleArtifact",
    "TiingoEodIdentityLifecycleArtifactKind",
    "TiingoEodIdentityLifecycleQualification",
    "TiingoEodIdentityLifecycleQualificationKind",
    "TiingoEodSourcedUniverseMembership",
    "TiingoEodSymbolChangeCase",
    "qualify_tiingo_eod_identity_lifecycle",
]
