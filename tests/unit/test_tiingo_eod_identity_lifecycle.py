from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from packages.adapters.market_data.tiingo_eod import (
    PHASE1_TIINGO_SYMBOLS,
    TiingoEodError,
    TiingoEodScope,
)
from packages.adapters.market_data.tiingo_eod_identity_lifecycle import (
    TIINGO_EOD_IDENTITY_LIFECYCLE_CHECK_IDS,
    TiingoEodDelistingCase,
    TiingoEodIdentityLifecycleArtifact,
    TiingoEodIdentityLifecycleArtifactKind,
    TiingoEodIdentityLifecycleQualification,
    TiingoEodIdentityLifecycleQualificationKind,
    TiingoEodSourcedUniverseMembership,
    TiingoEodSymbolChangeCase,
    qualify_tiingo_eod_identity_lifecycle,
)
from packages.adapters.market_data.tiingo_eod_retained_fields import (
    qualify_tiingo_eod_retained_fields,
)
from packages.market_data import (
    AssetClass,
    HistoricalBarSource,
    NonTradableSecurityError,
    Security,
    SecurityIdentifier,
    SecurityMaster,
    UniverseMembership,
    UnknownSecurityError,
)
from tests.unit.test_tiingo_eod_snapshot import (
    CAPTURE_REQUESTED_AT,
    SESSION_DATE,
    SYMBOLS,
    VENUE_BY_SYMBOL,
    profile,
    scope,
    verify,
    write_capture,
)

IDENTITY_SOURCE_ID = "test-reviewed-identity-source-v1"
UNIVERSE_ID = "test-phase1-trade-universe"
UNIVERSE_VERSION = "test-phase1-trade-universe-2026a"
OBSERVED_AT = datetime(2026, 7, 15, 22, 0, tzinfo=UTC)
REVIEWED_AT = datetime(2026, 7, 16, 10, 0, tzinfo=UTC)
TRADE_EFFECTIVE_FROM = datetime(2020, 1, 2, 14, 30, tzinfo=UTC)
SYMBOL_CHANGE_AT = datetime(2025, 1, 2, 14, 30, tzinfo=UTC)
DELISTING_AT = datetime(2025, 6, 30, 20, 0, tzinfo=UTC)
RENAME_SECURITY_ID = "security-lifecycle-renamed"
DELISTED_SECURITY_ID = "security-lifecycle-delisted"


def _evidence_digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _identifier(
    *,
    security_id: str,
    symbol: str,
    venue: str,
    effective_from: datetime,
    effective_to: datetime | None = None,
    tradable: bool = True,
    available_at: datetime | None = None,
    observation_id: str | None = None,
    event_revision_id: str | None = None,
    revision: int = 1,
    supersedes_event_revision_id: str | None = None,
    source_id: str = IDENTITY_SOURCE_ID,
) -> SecurityIdentifier:
    selected_observation_id = observation_id or f"identifier-{security_id}-{symbol}"
    return SecurityIdentifier(
        observation_id=selected_observation_id,
        event_revision_id=(event_revision_id or f"{selected_observation_id}-r{revision}"),
        security_id=security_id,
        source_id=source_id,
        symbol=symbol,
        venue=venue,
        effective_from=effective_from,
        effective_to=effective_to,
        available_at=available_at or effective_from - timedelta(days=1),
        tradable=tradable,
        revision=revision,
        supersedes_event_revision_id=supersedes_event_revision_id,
    )


def _membership(
    security_id: str,
    *,
    source_id: str = IDENTITY_SOURCE_ID,
) -> TiingoEodSourcedUniverseMembership:
    observation_id = f"membership-{security_id}"
    return TiingoEodSourcedUniverseMembership(
        source_id=source_id,
        membership=UniverseMembership(
            observation_id=observation_id,
            event_revision_id=f"{observation_id}-r1",
            universe_id=UNIVERSE_ID,
            security_id=security_id,
            effective_from=TRADE_EFFECTIVE_FROM,
            effective_to=None,
            available_at=TRADE_EFFECTIVE_FROM - timedelta(days=1),
            included=True,
            revision=1,
        ),
    )


def _artifact(
    profile_contract_sha256: str,
    *,
    kind: TiingoEodIdentityLifecycleArtifactKind = (
        TiingoEodIdentityLifecycleArtifactKind.SYNTHETIC_CONTRACT
    ),
) -> TiingoEodIdentityLifecycleArtifact:
    trade_securities = tuple(
        Security(
            security_id=f"security-{symbol.lower()}",
            asset_class=AssetClass.ETF,
            currency="USD",
            name=f"Bounded {symbol} identity fixture",
        )
        for symbol in SYMBOLS
    )
    lifecycle_securities = (
        Security(
            security_id=DELISTED_SECURITY_ID,
            asset_class=AssetClass.ETF,
            currency="USD",
            name="Bounded delisting identity fixture",
        ),
        Security(
            security_id=RENAME_SECURITY_ID,
            asset_class=AssetClass.ETF,
            currency="USD",
            name="Bounded ticker-change identity fixture",
        ),
    )
    identifiers = tuple(
        sorted(
            (
                *(
                    _identifier(
                        security_id=f"security-{symbol.lower()}",
                        symbol=symbol,
                        venue=VENUE_BY_SYMBOL[symbol],
                        effective_from=TRADE_EFFECTIVE_FROM,
                    )
                    for symbol in SYMBOLS
                ),
                _identifier(
                    security_id=RENAME_SECURITY_ID,
                    symbol="OLD",
                    venue="XNYS",
                    effective_from=datetime(2024, 1, 2, 14, 30, tzinfo=UTC),
                    effective_to=SYMBOL_CHANGE_AT,
                ),
                _identifier(
                    security_id=RENAME_SECURITY_ID,
                    symbol="NEW",
                    venue="XNYS",
                    effective_from=SYMBOL_CHANGE_AT,
                ),
                _identifier(
                    security_id=DELISTED_SECURITY_ID,
                    symbol="DEAD",
                    venue="XNYS",
                    effective_from=datetime(2020, 1, 2, 14, 30, tzinfo=UTC),
                    effective_to=DELISTING_AT,
                ),
                _identifier(
                    security_id=DELISTED_SECURITY_ID,
                    symbol="DEAD",
                    venue="XNYS",
                    effective_from=DELISTING_AT,
                    tradable=False,
                    available_at=datetime(2025, 6, 20, 12, 0, tzinfo=UTC),
                    observation_id="identifier-security-lifecycle-delisted-DEAD-nontradable",
                ),
            ),
            key=lambda value: (
                value.security_id,
                value.symbol,
                value.venue,
                value.effective_from,
                value.observation_id,
                value.revision,
                value.event_revision_id,
            ),
        )
    )
    securities = tuple(
        sorted((*trade_securities, *lifecycle_securities), key=lambda value: value.security_id)
    )
    memberships = tuple(
        sorted(
            (_membership(f"security-{symbol.lower()}") for symbol in SYMBOLS),
            key=lambda value: value.membership.security_id,
        )
    )
    reviewed = kind is TiingoEodIdentityLifecycleArtifactKind.REVIEWED_REFERENCE
    return TiingoEodIdentityLifecycleArtifact(
        artifact_id="test-tiingo-identity-lifecycle-contract",
        artifact_kind=kind,
        approved=reviewed,
        executor_id="test-identity-contract-executor",
        reviewer_id="test-independent-reference-reviewer" if reviewed else None,
        observed_at=OBSERVED_AT,
        reviewed_at=REVIEWED_AT if reviewed else None,
        profile_contract_sha256=profile_contract_sha256,
        identifier_authority="tiingo-ticker-mapping-v1",
        identity_source_id=IDENTITY_SOURCE_ID,
        identifier_evidence_sha256=_evidence_digest("identifier evidence"),
        lifecycle_evidence_sha256=_evidence_digest("lifecycle evidence"),
        trade_symbols=PHASE1_TIINGO_SYMBOLS,
        universe_id=UNIVERSE_ID,
        universe_version=UNIVERSE_VERSION,
        securities=securities,
        identifiers=identifiers,
        memberships=memberships,
        symbol_change_case=TiingoEodSymbolChangeCase(
            case_id="test-stable-identity-symbol-change",
            security_id=RENAME_SECURITY_ID,
            old_symbol="OLD",
            old_venue="XNYS",
            new_symbol="NEW",
            new_venue="XNYS",
            effective_at=SYMBOL_CHANGE_AT,
        ),
        delisting_case=TiingoEodDelistingCase(
            case_id="test-tradable-to-nontradable-delisting",
            security_id=DELISTED_SECURITY_ID,
            symbol="DEAD",
            venue="XNYS",
            effective_at=DELISTING_AT,
        ),
    )


def _canonical_json(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode()


def _payload(artifact: TiingoEodIdentityLifecycleArtifact) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(artifact.to_json_bytes()))


def _sort_identifiers(payload: dict[str, Any]) -> None:
    payload["identifiers"].sort(
        key=lambda value: (
            value["security_id"],
            value["symbol"],
            value["venue"],
            value["effective_from"],
            value["observation_id"],
            value["revision"],
            value["event_revision_id"],
        )
    )


def _sort_memberships(payload: dict[str, Any]) -> None:
    payload["memberships"].sort(
        key=lambda value: (
            value["universe_id"],
            value["security_id"],
            value["effective_from"],
            value["observation_id"],
            value["revision"],
            value["event_revision_id"],
        )
    )


def _proof_inputs(tmp_path: Path) -> tuple[Any, Any, TiingoEodIdentityLifecycleArtifact]:
    capture = write_capture(tmp_path)
    snapshot = verify(capture)
    retained = qualify_tiingo_eod_retained_fields(snapshot)
    return snapshot, retained, _artifact(capture.profile.contract_sha256)


def test_exact_trade_identity_universe_and_isolated_lifecycle_boundaries(
    tmp_path: Path,
) -> None:
    snapshot, retained, artifact = _proof_inputs(tmp_path)
    qualification = qualify_tiingo_eod_identity_lifecycle(
        snapshot=snapshot,
        retained_fields=retained,
        artifact_bytes=artifact.to_json_bytes(),
    )
    master = SecurityMaster(
        securities=artifact.securities,
        identifiers=artifact.identifiers,
        memberships=tuple(value.membership for value in artifact.memberships),
    )

    expected_mappings = tuple(
        (symbol, f"security-{symbol.lower()}", VENUE_BY_SYMBOL[symbol])
        for symbol in PHASE1_TIINGO_SYMBOLS
    )
    assert qualification.mappings == expected_mappings
    assert qualification.session_mapping_count == 4
    assert qualification.mapping_count == 4
    assert qualification.trade_symbol_count == 4
    assert qualification.security_count == 6
    assert qualification.identifier_count == 8
    assert qualification.membership_count == 4
    assert tuple(binding.venue for binding in snapshot.calendar_bindings) == tuple(
        VENUE_BY_SYMBOL[symbol] for symbol in PHASE1_TIINGO_SYMBOLS
    )
    for binding in snapshot.calendar_bindings:
        session = next(value for value in binding.sessions if value.session_label == SESSION_DATE)
        resolved = master.resolve_identifier(
            symbol=binding.symbol,
            venue=binding.venue,
            effective_at=session.opens_at,
            as_of=artifact.observed_at,
        )
        assert resolved.security_id == f"security-{binding.symbol.lower()}"
        assert {
            value.security_id
            for value in master.universe_members(
                universe_id=UNIVERSE_ID,
                effective_at=session.opens_at,
                as_of=artifact.observed_at,
            )
        } == {f"security-{symbol.lower()}" for symbol in PHASE1_TIINGO_SYMBOLS}

    just_before_change = SYMBOL_CHANGE_AT - timedelta(microseconds=1)
    assert (
        master.resolve_identifier(
            symbol="OLD",
            venue="XNYS",
            effective_at=just_before_change,
            as_of=artifact.observed_at,
        ).security_id
        == RENAME_SECURITY_ID
    )
    with pytest.raises(UnknownSecurityError):
        master.resolve_identifier(
            symbol="NEW",
            venue="XNYS",
            effective_at=just_before_change,
            as_of=artifact.observed_at,
        )
    assert (
        master.resolve_identifier(
            symbol="NEW",
            venue="XNYS",
            effective_at=SYMBOL_CHANGE_AT,
            as_of=artifact.observed_at,
        ).security_id
        == RENAME_SECURITY_ID
    )
    with pytest.raises(UnknownSecurityError):
        master.resolve_identifier(
            symbol="OLD",
            venue="XNYS",
            effective_at=SYMBOL_CHANGE_AT,
            as_of=artifact.observed_at,
        )

    just_before_delisting = DELISTING_AT - timedelta(microseconds=1)
    assert master.resolve_identifier(
        symbol="DEAD",
        venue="XNYS",
        effective_at=just_before_delisting,
        as_of=artifact.observed_at,
    ).tradable
    with pytest.raises(NonTradableSecurityError):
        master.resolve_identifier(
            symbol="DEAD",
            venue="XNYS",
            effective_at=DELISTING_AT,
            as_of=artifact.observed_at,
        )
    assert not master.resolve_identifier(
        symbol="DEAD",
        venue="XNYS",
        effective_at=DELISTING_AT,
        as_of=artifact.observed_at,
        require_tradable=False,
    ).tradable


@pytest.mark.parametrize(
    "kind",
    [
        TiingoEodIdentityLifecycleArtifactKind.SYNTHETIC_CONTRACT,
        TiingoEodIdentityLifecycleArtifactKind.REVIEWED_REFERENCE,
    ],
)
def test_contract_kinds_are_deterministic_and_grant_no_authority(
    tmp_path: Path,
    kind: TiingoEodIdentityLifecycleArtifactKind,
) -> None:
    capture = write_capture(tmp_path)
    snapshot = verify(capture)
    retained = qualify_tiingo_eod_retained_fields(snapshot)
    artifact = _artifact(capture.profile.contract_sha256, kind=kind)

    first = qualify_tiingo_eod_identity_lifecycle(
        snapshot=snapshot,
        retained_fields=retained,
        artifact_bytes=artifact.to_json_bytes(),
    )
    second = qualify_tiingo_eod_identity_lifecycle(
        snapshot=snapshot,
        retained_fields=retained,
        artifact_bytes=artifact.to_json_bytes(),
    )

    assert first == second
    assert first.artifact_kind is kind
    assert first.qualification_sha256 == second.qualification_sha256
    assert len(first.qualification_sha256) == 64
    assert first.check_ids == TIINGO_EOD_IDENTITY_LIFECYCLE_CHECK_IDS
    assert (
        first.qualification_kind
        is TiingoEodIdentityLifecycleQualificationKind.IDENTITY_LIFECYCLE_CONTRACT_ONLY
    )
    for effect in (
        first.production_identity_effect,
        first.raw_execution_effect,
        first.canonical_bar_effect,
        first.corporate_action_effect,
        first.lifecycle_calendar_effect,
        first.historical_source_effect,
        first.admission_effect,
        first.trading_effect,
    ):
        assert effect == "none"


def test_bounded_identity_corpus_requires_usd_etfs() -> None:
    artifact = _artifact("1" * 64)
    equity = replace(artifact.securities[0], asset_class=AssetClass.EQUITY)

    with pytest.raises(ValueError, match="USD ETFs"):
        replace(artifact, securities=(equity, *artifact.securities[1:]))


@pytest.mark.parametrize("case", ["noncanonical", "duplicate", "unknown", "missing"])
def test_artifact_json_is_exact_canonical_and_closed(case: str) -> None:
    artifact = _artifact("1" * 64)
    encoded = artifact.to_json_bytes()
    if case == "noncanonical":
        malformed = json.dumps(json.loads(encoded)).encode()
    elif case == "duplicate":
        malformed = encoded.replace(
            b'  "approved": false,\n',
            b'  "approved": false,\n  "approved": false,\n',
            1,
        )
    else:
        payload = _payload(artifact)
        if case == "unknown":
            payload["identifiers"][0]["unexpected"] = True
        else:
            payload["symbol_change_case"].pop("old_symbol")
        malformed = _canonical_json(payload)

    with pytest.raises(TiingoEodError):
        TiingoEodIdentityLifecycleArtifact.from_json_bytes(malformed)


@pytest.mark.parametrize(
    "case",
    ["profile", "authority", "scope", "source", "capture_scope"],
)
def test_qualification_rejects_profile_authority_scope_and_source_mismatch(
    tmp_path: Path,
    case: str,
) -> None:
    if case == "capture_scope":
        selected_profile = profile(capture_scope=scope(symbols=("SPY",)))
        capture = write_capture(tmp_path, selected_profile=selected_profile)
        snapshot = verify(capture)
        retained = qualify_tiingo_eod_retained_fields(snapshot)
        artifact_bytes = _artifact(selected_profile.contract_sha256).to_json_bytes()
    else:
        snapshot, retained, artifact = _proof_inputs(tmp_path)
        payload = _payload(artifact)
        if case == "profile":
            payload["profile_contract_sha256"] = "2" * 64
        elif case == "authority":
            payload["identifier_authority"] = "other-identifier-authority"
        elif case == "scope":
            payload["trade_symbols"].pop()
        else:
            payload["identifiers"][0]["source_id"] = "other-identity-source"
        artifact_bytes = _canonical_json(payload)

    with pytest.raises(TiingoEodError):
        qualify_tiingo_eod_identity_lifecycle(
            snapshot=snapshot,
            retained_fields=retained,
            artifact_bytes=artifact_bytes,
        )


@pytest.mark.parametrize("case", ["missing", "extra", "ambiguous", "overlap"])
def test_artifact_rejects_incomplete_extra_ambiguous_and_overlapping_mappings(
    case: str,
) -> None:
    artifact = _artifact("1" * 64)
    payload = _payload(artifact)
    dia = next(value for value in payload["identifiers"] if value["symbol"] == "DIA")
    if case == "missing":
        payload["identifiers"].remove(dia)
    elif case == "extra":
        extra = dict(dia)
        extra.update(
            {
                "event_revision_id": "identifier-extra-r1",
                "observation_id": "identifier-extra",
                "symbol": "EXTRA",
            }
        )
        payload["identifiers"].append(extra)
    elif case == "ambiguous":
        payload["securities"].append(
            {
                "asset_class": "etf",
                "currency": "USD",
                "name": "Ambiguous DIA fixture",
                "security_id": "security-dia-ambiguous",
            }
        )
        payload["securities"].sort(key=lambda value: value["security_id"])
        duplicate = dict(dia)
        duplicate.update(
            {
                "event_revision_id": "identifier-dia-ambiguous-r1",
                "observation_id": "identifier-dia-ambiguous",
                "security_id": "security-dia-ambiguous",
            }
        )
        payload["identifiers"].append(duplicate)
    else:
        overlapping = dict(dia)
        overlapping.update(
            {
                "effective_from": "2021-01-04T14:30:00Z",
                "event_revision_id": "identifier-dia-overlap-r1",
                "observation_id": "identifier-dia-overlap",
            }
        )
        payload["identifiers"].append(overlapping)
    _sort_identifiers(payload)

    with pytest.raises(TiingoEodError):
        TiingoEodIdentityLifecycleArtifact.from_json_bytes(_canonical_json(payload))


@pytest.mark.parametrize(
    "case",
    ["noncontiguous", "wrong_predecessor", "noncausal_availability", "future_fact"],
)
def test_artifact_rejects_broken_revision_chains_and_noncausal_facts(case: str) -> None:
    artifact = _artifact("1" * 64)
    payload = _payload(artifact)
    dia = next(value for value in payload["identifiers"] if value["symbol"] == "DIA")
    if case == "future_fact":
        dia["available_at"] = "2026-07-16T00:00:00Z"
    else:
        correction = dict(dia)
        correction["event_revision_id"] = "identifier-security-dia-DIA-r2"
        correction["revision"] = 3 if case == "noncontiguous" else 2
        correction["supersedes_event_revision_id"] = (
            "not-the-predecessor" if case == "wrong_predecessor" else dia["event_revision_id"]
        )
        correction["available_at"] = (
            dia["available_at"] if case == "noncausal_availability" else "2026-01-02T12:00:00Z"
        )
        payload["identifiers"].append(correction)
    _sort_identifiers(payload)

    with pytest.raises(TiingoEodError):
        TiingoEodIdentityLifecycleArtifact.from_json_bytes(_canonical_json(payload))


@pytest.mark.parametrize(
    "case",
    ["noncontiguous", "wrong_predecessor", "noncausal_availability", "future_fact"],
)
def test_artifact_rejects_broken_membership_revision_chains(case: str) -> None:
    artifact = _artifact("1" * 64)
    payload = _payload(artifact)
    membership = payload["memberships"][0]
    if case == "future_fact":
        membership["available_at"] = "2026-07-16T00:00:00Z"
    else:
        correction = dict(membership)
        correction["event_revision_id"] = "membership-security-dia-r2"
        correction["revision"] = 3 if case == "noncontiguous" else 2
        correction["supersedes_event_revision_id"] = (
            "not-the-predecessor"
            if case == "wrong_predecessor"
            else membership["event_revision_id"]
        )
        correction["available_at"] = (
            membership["available_at"]
            if case == "noncausal_availability"
            else "2026-01-02T12:00:00Z"
        )
        payload["memberships"].append(correction)
    _sort_memberships(payload)

    with pytest.raises(TiingoEodError):
        TiingoEodIdentityLifecycleArtifact.from_json_bytes(_canonical_json(payload))


@pytest.mark.parametrize(
    "case",
    [
        "symbol_boundary",
        "delisting_boundary",
        "resurrection",
        "cross_venue_overlap",
        "trade_lifecycle_alias",
        "old_symbol_resurrection",
        "new_symbol_premature",
        "collapsed_lifecycle_symbol",
        "universe_leakage",
    ],
)
def test_lifecycle_mismatch_resurrection_and_universe_leakage_fail_closed(
    tmp_path: Path,
    case: str,
) -> None:
    snapshot, retained, artifact = _proof_inputs(tmp_path)
    payload = _payload(artifact)
    if case == "symbol_boundary":
        payload["symbol_change_case"]["effective_at"] = "2025-01-03T14:30:00Z"
    elif case == "delisting_boundary":
        payload["delisting_case"]["effective_at"] = "2025-07-01T20:00:00Z"
    elif case == "resurrection":
        nontradable = next(
            value
            for value in payload["identifiers"]
            if value["security_id"] == DELISTED_SECURITY_ID and not value["tradable"]
        )
        nontradable["effective_to"] = "2026-01-02T14:30:00Z"
        resurrected = dict(nontradable)
        resurrected.update(
            {
                "available_at": "2025-12-20T12:00:00Z",
                "effective_from": "2026-01-02T14:30:00Z",
                "effective_to": None,
                "event_revision_id": "identifier-dead-resurrected-r1",
                "observation_id": "identifier-dead-resurrected",
                "tradable": True,
            }
        )
        payload["identifiers"].append(resurrected)
        _sort_identifiers(payload)
    elif case == "cross_venue_overlap":
        pre_delisting = next(
            value
            for value in payload["identifiers"]
            if value["security_id"] == DELISTED_SECURITY_ID and value["tradable"]
        )
        overlapping = dict(pre_delisting)
        overlapping.update(
            {
                "effective_to": None,
                "event_revision_id": "identifier-dead-xnas-overlap-r1",
                "observation_id": "identifier-dead-xnas-overlap",
                "venue": "XNAS",
            }
        )
        payload["identifiers"].append(overlapping)
        _sort_identifiers(payload)
    elif case == "trade_lifecycle_alias":
        trade_identifier = next(
            value for value in payload["identifiers"] if value["symbol"] == "DIA"
        )
        leaked_alias = dict(trade_identifier)
        leaked_alias.update(
            {
                "event_revision_id": "identifier-dia-old-alias-r1",
                "observation_id": "identifier-dia-old-alias",
                "symbol": "OLD",
                "venue": "XNAS",
            }
        )
        payload["identifiers"].append(leaked_alias)
        _sort_identifiers(payload)
    elif case == "old_symbol_resurrection":
        old_identifier = next(
            value
            for value in payload["identifiers"]
            if value["security_id"] == RENAME_SECURITY_ID and value["symbol"] == "OLD"
        )
        lingering_old = dict(old_identifier)
        lingering_old.update(
            {
                "effective_from": payload["symbol_change_case"]["effective_at"],
                "effective_to": None,
                "event_revision_id": "identifier-old-lingering-r1",
                "observation_id": "identifier-old-lingering",
            }
        )
        payload["identifiers"].append(lingering_old)
        _sort_identifiers(payload)
    elif case == "new_symbol_premature":
        new_identifier = next(
            value
            for value in payload["identifiers"]
            if value["security_id"] == RENAME_SECURITY_ID and value["symbol"] == "NEW"
        )
        premature_new = dict(new_identifier)
        premature_new.update(
            {
                "effective_from": "2024-01-02T14:30:00Z",
                "effective_to": payload["symbol_change_case"]["effective_at"],
                "event_revision_id": "identifier-new-premature-r1",
                "observation_id": "identifier-new-premature",
            }
        )
        payload["identifiers"].append(premature_new)
        _sort_identifiers(payload)
    elif case == "collapsed_lifecycle_symbol":
        payload["delisting_case"]["symbol"] = "OLD"
    else:
        leaked = payload["memberships"][0]
        leaked["security_id"] = RENAME_SECURITY_ID
        leaked["event_revision_id"] = "membership-lifecycle-renamed-r1"
        leaked["observation_id"] = "membership-lifecycle-renamed"
        _sort_memberships(payload)

    artifact_bytes = _canonical_json(payload)
    with pytest.raises(TiingoEodError):
        qualify_tiingo_eod_identity_lifecycle(
            snapshot=snapshot,
            retained_fields=retained,
            artifact_bytes=artifact_bytes,
        )


@pytest.mark.parametrize("fact_kind", ["identifier", "membership"])
def test_qualification_requires_continuous_full_session_identity_and_universe(
    tmp_path: Path,
    fact_kind: str,
) -> None:
    snapshot, retained, artifact = _proof_inputs(tmp_path)
    payload = _payload(artifact)
    dia_binding = next(value for value in snapshot.calendar_bindings if value.symbol == "DIA")
    session = next(value for value in dia_binding.sessions if value.session_label == SESSION_DATE)
    if fact_kind == "identifier":
        dia = next(value for value in payload["identifiers"] if value["symbol"] == "DIA")
        dia["effective_to"] = (
            (session.opens_at + timedelta(microseconds=1)).isoformat().replace("+00:00", "Z")
        )
    else:
        dia_membership = next(
            value for value in payload["memberships"] if value["security_id"] == "security-dia"
        )
        dia_membership["effective_to"] = (
            (session.opens_at + timedelta(microseconds=1)).isoformat().replace("+00:00", "Z")
        )

    with pytest.raises(TiingoEodError, match="pinned session"):
        qualify_tiingo_eod_identity_lifecycle(
            snapshot=snapshot,
            retained_fields=retained,
            artifact_bytes=_canonical_json(payload),
        )


def test_qualification_requires_exact_inputs_and_rejects_substitution_and_tamper(
    tmp_path: Path,
) -> None:
    snapshot, retained, artifact = _proof_inputs(tmp_path / "first")
    artifact_bytes = artifact.to_json_bytes()
    qualification = qualify_tiingo_eod_identity_lifecycle(
        snapshot=snapshot,
        retained_fields=retained,
        artifact_bytes=artifact_bytes,
    )

    with pytest.raises(TiingoEodError, match="exact verified snapshot"):
        qualify_tiingo_eod_identity_lifecycle(
            snapshot=cast(Any, object()),
            retained_fields=retained,
            artifact_bytes=artifact_bytes,
        )
    with pytest.raises(TiingoEodError, match="exact retained-field proof"):
        qualify_tiingo_eod_identity_lifecycle(
            snapshot=snapshot,
            retained_fields=cast(Any, object()),
            artifact_bytes=artifact_bytes,
        )
    with pytest.raises(TiingoEodError, match="exact immutable bytes"):
        qualify_tiingo_eod_identity_lifecycle(
            snapshot=snapshot,
            retained_fields=retained,
            artifact_bytes=cast(Any, bytearray(artifact_bytes)),
        )

    other_capture = write_capture(
        tmp_path / "second",
        capture_requested_at=CAPTURE_REQUESTED_AT + timedelta(minutes=1),
    )
    other_snapshot = verify(other_capture)
    other_retained = qualify_tiingo_eod_retained_fields(other_snapshot)
    with pytest.raises(TiingoEodError, match="does not bind"):
        qualify_tiingo_eod_identity_lifecycle(
            snapshot=snapshot,
            retained_fields=other_retained,
            artifact_bytes=artifact_bytes,
        )

    with pytest.raises(TypeError, match="only be created by the qualifier"):
        TiingoEodIdentityLifecycleQualification()
    with pytest.raises(TypeError, match="only be created by the qualifier"):
        replace(qualification, mapping_count=99)
    object.__setattr__(qualification, "mapping_count", 99)
    with pytest.raises(TiingoEodError, match="not exactly re-derived"):
        qualification.__post_init__()


def test_qualification_refuses_every_downstream_authority(tmp_path: Path) -> None:
    snapshot, retained, artifact = _proof_inputs(tmp_path)
    qualification = qualify_tiingo_eod_identity_lifecycle(
        snapshot=snapshot,
        retained_fields=retained,
        artifact_bytes=artifact.to_json_bytes(),
    )

    assert not isinstance(qualification, HistoricalBarSource)
    assert not hasattr(qualification, "load")
    rendered = repr(qualification)
    assert "mappings=" not in rendered
    for security in artifact.securities:
        assert security.security_id not in rendered
    with pytest.raises(AttributeError):
        cast(Any, qualification).load()
    for operation in (
        qualification.security_master,
        qualification.raw_bar_records,
        qualification.canonical_bar_records,
        qualification.corporate_action_records,
        qualification.historical_source_bundle,
        qualification.historical_bar_source,
        qualification.admission_evidence,
    ):
        with pytest.raises(TiingoEodError, match="contract-only"):
            operation()


def test_artifact_digest_binds_evidence_and_exact_canonical_bytes() -> None:
    artifact = _artifact("1" * 64)
    parsed = TiingoEodIdentityLifecycleArtifact.from_json_bytes(artifact.to_json_bytes())
    changed = replace(
        artifact,
        lifecycle_evidence_sha256=_evidence_digest("different lifecycle evidence"),
    )

    assert parsed == artifact
    assert parsed.to_json_bytes() == artifact.to_json_bytes()
    assert parsed.artifact_sha256 == hashlib.sha256(parsed.to_json_bytes()).hexdigest()
    assert changed.artifact_sha256 != artifact.artifact_sha256
    assert changed.to_json_bytes() != artifact.to_json_bytes()


def test_exact_trade_scope_is_dia_iwm_qqq_spy() -> None:
    assert SYMBOLS == PHASE1_TIINGO_SYMBOLS == ("DIA", "IWM", "QQQ", "SPY")
    assert (
        TiingoEodScope(
            symbols=PHASE1_TIINGO_SYMBOLS,
            start_date=SESSION_DATE,
            end_date=SESSION_DATE,
        ).symbols
        == PHASE1_TIINGO_SYMBOLS
    )
