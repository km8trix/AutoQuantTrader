from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

import packages.adapters.market_data.tiingo_eod_market_semantics as semantics_module
from packages.adapters.market_data.tiingo_eod import (
    PHASE1_TIINGO_SYMBOLS,
    TIINGO_EOD_FIELDS,
    TiingoEodError,
)
from packages.adapters.market_data.tiingo_eod_identity_lifecycle import (
    TiingoEodIdentityLifecycleQualification,
    qualify_tiingo_eod_identity_lifecycle,
)
from packages.adapters.market_data.tiingo_eod_market_semantics import (
    MAX_TIINGO_EOD_MARKET_SEMANTICS_ARTIFACT_BYTES,
    TIINGO_EOD_MARKET_SEMANTICS_CHECK_IDS,
    TiingoEodMarketSemanticsArtifact,
    TiingoEodMarketSemanticsQualification,
    qualify_tiingo_eod_market_semantics,
)
from packages.adapters.market_data.tiingo_eod_retained_fields import (
    qualify_tiingo_eod_retained_fields,
)
from packages.market_data import (
    CorporateActionRevision,
    HistoricalBarSource,
    HistoricalSourceBundle,
    RawBar,
    SecurityMaster,
    VendorBarRecord,
)
from tests.unit.test_tiingo_eod_identity_lifecycle import _artifact as identity_artifact
from tests.unit.test_tiingo_eod_snapshot import (
    SESSION_DATE,
    SYMBOLS,
    economic_row,
    response_bytes,
    verify,
    write_capture,
)

OBSERVED_AT = datetime(2026, 7, 16, 13, 0, tzinfo=UTC)
REVIEWED_AT = datetime(2026, 7, 16, 14, 0, tzinfo=UTC)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _canonical_json(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode()


def _semantics_payload(
    *,
    profile_contract_sha256: str,
    identity_lifecycle_qualification_sha256: str,
    kind: str = "synthetic_contract",
) -> dict[str, Any]:
    reviewed = kind == "reviewed_reference"
    return {
        "action_candidate_convention": {
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
        },
        "adjusted_methodology_evidence_sha256": _digest("adjusted methodology evidence"),
        "approved": reviewed,
        "artifact_id": "test-tiingo-eod-market-semantics-contract",
        "artifact_kind": kind,
        "corporate_action_authority": "tiingo-eod-actions-v1",
        "corporate_action_candidate_evidence_sha256": _digest(
            "corporate action candidate evidence"
        ),
        "dataset": "end-of-day",
        "executor_id": "test-market-semantics-executor",
        "field_partition": {
            "adjusted_research_fields": [
                "adjOpen",
                "adjHigh",
                "adjLow",
                "adjClose",
                "adjVolume",
            ],
            "corporate_action_candidate_fields": ["divCash", "splitFactor"],
            "documented_raw_candidate_fields": ["open", "high", "low", "close", "volume"],
            "session_identity_fields": ["date"],
        },
        "identity_lifecycle_qualification_sha256": (identity_lifecycle_qualification_sha256),
        "market_provenance_evidence_sha256": _digest("market provenance evidence"),
        "market_provenance_label": "tiingo-eod-us-consolidated-market-v1",
        "market_semantics_source_id": "test-market-semantics-evidence-source-v1",
        "observed_at": OBSERVED_AT.isoformat().replace("+00:00", "Z"),
        "profile_contract_sha256": profile_contract_sha256,
        "provenance": {
            "aggregation": "provider-eod-ohlcv-candidate",
            "condition_scope": "provider-documented-eligible-trades-candidate",
            "currency": "USD",
            "effective_from": "2020-01-01T00:00:00Z",
            "effective_to": None,
            "endpoint": "tiingo-daily-prices-endpoint-v1",
            "feed": "tiingo-eod-rest-feed-v1",
            "product": "tiingo-end-of-day-v1",
            "session_scope": "regular-session-daily-candidate",
            "venue_scope": "us-consolidated-market-candidate",
        },
        "provider": "tiingo",
        "raw_semantics_evidence_sha256": _digest("raw semantics evidence"),
        "reviewed_at": (REVIEWED_AT.isoformat().replace("+00:00", "Z") if reviewed else None),
        "reviewer_id": "test-independent-market-semantics-reviewer" if reviewed else None,
        "schema_version": "tiingo-eod-market-semantics-artifact-v1",
        "synthetic_cases": [
            {"case_id": "neutral", "div_cash": "0", "split_factor": "1"},
            {"case_id": "cash_dividend", "div_cash": "0.25", "split_factor": "1"},
            {"case_id": "forward_split", "div_cash": "0", "split_factor": "2"},
            {"case_id": "reverse_split", "div_cash": "0", "split_factor": "0.25"},
            {
                "case_id": "simultaneous_dividend_forward_split",
                "div_cash": "0.25",
                "split_factor": "2",
            },
        ],
        "trade_symbols": list(PHASE1_TIINGO_SYMBOLS),
    }


def _artifact_bytes(
    *,
    profile_contract_sha256: str,
    identity_lifecycle_qualification_sha256: str,
    kind: str = "synthetic_contract",
) -> bytes:
    return _canonical_json(
        _semantics_payload(
            profile_contract_sha256=profile_contract_sha256,
            identity_lifecycle_qualification_sha256=(identity_lifecycle_qualification_sha256),
            kind=kind,
        )
    )


def _proof_chain(
    tmp_path: Path,
    *,
    kind: str = "synthetic_contract",
    payloads: dict[str, bytes] | None = None,
) -> tuple[Any, Any, TiingoEodIdentityLifecycleQualification, bytes]:
    capture = write_capture(tmp_path, payloads=payloads)
    snapshot = verify(capture)
    retained = qualify_tiingo_eod_retained_fields(snapshot)
    identity_bytes = identity_artifact(capture.profile.contract_sha256).to_json_bytes()
    identity = qualify_tiingo_eod_identity_lifecycle(
        snapshot=snapshot,
        retained_fields=retained,
        artifact_bytes=identity_bytes,
    )
    artifact_bytes = _artifact_bytes(
        profile_contract_sha256=capture.profile.contract_sha256,
        identity_lifecycle_qualification_sha256=identity.qualification_sha256,
        kind=kind,
    )
    return snapshot, retained, identity, artifact_bytes


def _qualify(
    snapshot: Any,
    retained: Any,
    identity: TiingoEodIdentityLifecycleQualification,
    artifact_bytes: bytes,
) -> TiingoEodMarketSemanticsQualification:
    return qualify_tiingo_eod_market_semantics(
        snapshot=snapshot,
        retained_fields=retained,
        identity_lifecycle=identity,
        artifact_bytes=artifact_bytes,
    )


def test_exact_proof_chain_field_partition_cases_and_stable_identity_resolution(
    tmp_path: Path,
) -> None:
    snapshot, retained, identity, artifact_bytes = _proof_chain(tmp_path)

    qualification = _qualify(snapshot, retained, identity, artifact_bytes)
    artifact = TiingoEodMarketSemanticsArtifact.from_json_bytes(artifact_bytes)

    partition = artifact.field_partition
    assert (
        partition.session_identity_fields
        + partition.documented_raw_candidate_fields
        + partition.adjusted_research_fields
        + partition.corporate_action_candidate_fields
    ) == TIINGO_EOD_FIELDS
    assert tuple(
        (case.case_id, str(case.div_cash), str(case.split_factor))
        for case in artifact.synthetic_cases
    ) == (
        ("neutral", "0", "1"),
        ("cash_dividend", "0.25", "1"),
        ("forward_split", "0", "2"),
        ("reverse_split", "0", "0.25"),
        ("simultaneous_dividend_forward_split", "0.25", "2"),
    )
    assert qualification.scope.symbols == SYMBOLS
    assert qualification.profile_contract_sha256 == snapshot.manifest.profile_contract_sha256
    assert qualification.retained_field_qualification_sha256 == retained.qualification_sha256
    assert qualification.identity_lifecycle_qualification_sha256 == identity.qualification_sha256
    assert qualification.row_count == 4
    assert qualification.stable_id_count == 4
    assert len(qualification.resolved_rows) == 4
    assert set(qualification.resolved_rows).issubset(set(identity.mappings))
    assert qualification.candidate_field_count == 2
    assert qualification.candidate_occurrence_count == 8
    assert qualification.synthetic_case_count == 5
    assert qualification.check_ids == TIINGO_EOD_MARKET_SEMANTICS_CHECK_IDS


@pytest.mark.parametrize("kind", ["synthetic_contract", "reviewed_reference"])
def test_synthetic_and_reviewed_reference_artifacts_remain_contract_only(
    tmp_path: Path,
    kind: str,
) -> None:
    snapshot, retained, identity, artifact_bytes = _proof_chain(tmp_path, kind=kind)

    qualification = _qualify(snapshot, retained, identity, artifact_bytes)

    assert qualification.artifact_kind.value == kind
    assert qualification.qualification_kind.value == "market_semantics_contract_only"
    assert qualification.schema_version == "tiingo-eod-market-semantics-qualification-v1"
    for field_name in (
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
        assert getattr(qualification, field_name) == "none"


@pytest.mark.parametrize(
    "mutation",
    [
        "compact",
        "duplicate",
        "unknown",
        "missing",
        "oversized",
        "deeply_nested",
    ],
)
def test_artifact_requires_exact_bounded_canonical_closed_json(
    tmp_path: Path,
    mutation: str,
) -> None:
    snapshot, _, identity, artifact_bytes = _proof_chain(tmp_path)
    payload = cast(dict[str, Any], json.loads(artifact_bytes))
    if mutation == "compact":
        candidate = json.dumps(payload, separators=(",", ":")).encode()
    elif mutation == "duplicate":
        candidate = artifact_bytes.replace(
            b'  "approved": false,',
            b'  "approved": false,\n  "approved": false,',
            1,
        )
    elif mutation == "unknown":
        payload["private_unknown"] = True
        candidate = _canonical_json(payload)
    elif mutation == "missing":
        payload.pop("market_provenance_evidence_sha256")
        candidate = _canonical_json(payload)
    elif mutation == "oversized":
        candidate = b"{" + b" " * MAX_TIINGO_EOD_MARKET_SEMANTICS_ARTIFACT_BYTES + b"}"
    else:
        candidate = b"[" * 10_000 + b"]" * 10_000

    with pytest.raises(TiingoEodError):
        TiingoEodMarketSemanticsArtifact.from_json_bytes(candidate)

    assert snapshot.semantic_sha256
    assert identity.qualification_sha256


@pytest.mark.parametrize(
    "mutation",
    [
        "profile",
        "identity",
        "market_provenance_label",
        "market_semantics_source_id",
        "source_repeats_provenance_label",
        "source_repeats_action_authority",
        "source_repeats_profile_source",
        "corporate_action_authority",
        "scope",
        "zero_raw_evidence",
        "zero_adjusted_evidence",
        "zero_provenance_evidence",
        "zero_action_evidence",
    ],
)
def test_evidence_profile_authority_scope_and_identity_mismatches_fail_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    snapshot, retained, identity, artifact_bytes = _proof_chain(tmp_path)
    payload = cast(dict[str, Any], json.loads(artifact_bytes))
    replacements: dict[str, tuple[str, Any]] = {
        "profile": ("profile_contract_sha256", "1" * 64),
        "identity": ("identity_lifecycle_qualification_sha256", "2" * 64),
        "market_provenance_label": ("market_provenance_label", "different-provenance"),
        "market_semantics_source_id": ("market_semantics_source_id", ""),
        "source_repeats_provenance_label": (
            "market_semantics_source_id",
            snapshot.manifest.profile.market_provenance,
        ),
        "source_repeats_action_authority": (
            "market_semantics_source_id",
            snapshot.manifest.profile.corporate_action_authority,
        ),
        "source_repeats_profile_source": (
            "market_semantics_source_id",
            snapshot.manifest.profile.source_id,
        ),
        "corporate_action_authority": (
            "corporate_action_authority",
            "different-action-authority",
        ),
        "scope": ("trade_symbols", ["DIA", "IWM", "QQQ"]),
        "zero_raw_evidence": ("raw_semantics_evidence_sha256", "0" * 64),
        "zero_adjusted_evidence": ("adjusted_methodology_evidence_sha256", "0" * 64),
        "zero_provenance_evidence": ("market_provenance_evidence_sha256", "0" * 64),
        "zero_action_evidence": (
            "corporate_action_candidate_evidence_sha256",
            "0" * 64,
        ),
    }
    field_name, value = replacements[mutation]
    payload[field_name] = value

    with pytest.raises((TiingoEodError, ValueError)):
        _qualify(snapshot, retained, identity, _canonical_json(payload))


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("effective_from", "2026-07-14T13:30:00.000001Z"),
        ("effective_to", "2026-07-14T19:59:59.999999Z"),
        ("effective_to", "2026-07-14T20:00:00Z"),
    ],
)
def test_structured_provenance_must_cover_every_exact_full_session(
    tmp_path: Path,
    field_name: str,
    value: str,
) -> None:
    snapshot, retained, identity, artifact_bytes = _proof_chain(tmp_path)
    payload = cast(dict[str, Any], json.loads(artifact_bytes))
    payload["provenance"][field_name] = value

    with pytest.raises(TiingoEodError):
        _qualify(snapshot, retained, identity, _canonical_json(payload))


@pytest.mark.parametrize(
    "mutation",
    [
        "synthetic_approved",
        "reviewed_unapproved",
        "self_review",
        "review_before_observation",
        "nonutc_observed",
        "nonutc_reviewed",
        "nonutc_effective_from",
        "nonutc_effective_to",
    ],
)
def test_artifact_approval_review_and_utc_chronology_fail_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    kind = "synthetic_contract" if mutation == "synthetic_approved" else "reviewed_reference"
    _, _, _, artifact_bytes = _proof_chain(tmp_path, kind=kind)
    payload = cast(dict[str, Any], json.loads(artifact_bytes))
    if mutation == "synthetic_approved":
        payload["approved"] = True
    elif mutation == "reviewed_unapproved":
        payload["approved"] = False
    elif mutation == "self_review":
        payload["reviewer_id"] = payload["executor_id"]
    elif mutation == "review_before_observation":
        payload["reviewed_at"] = "2026-07-16T12:59:59Z"
    elif mutation == "nonutc_observed":
        payload["observed_at"] = "2026-07-16T09:00:00-04:00"
    elif mutation == "nonutc_reviewed":
        payload["reviewed_at"] = "2026-07-16T10:00:00-04:00"
    elif mutation == "nonutc_effective_from":
        payload["provenance"]["effective_from"] = "2019-12-31T19:00:00-05:00"
    else:
        payload["provenance"]["effective_to"] = "2026-07-14T17:00:00-05:00"

    with pytest.raises((TiingoEodError, ValueError)):
        TiingoEodMarketSemanticsArtifact.from_json_bytes(_canonical_json(payload))


def test_neutral_values_do_not_assert_action_absence_and_relationships_are_not_inferred(
    tmp_path: Path,
) -> None:
    equal_payloads: dict[str, bytes] = {}
    for symbol in SYMBOLS:
        row = economic_row(SESSION_DATE)
        row.update(
            {
                "adjOpen": row["open"],
                "adjHigh": row["high"],
                "adjLow": row["low"],
                "adjClose": row["close"],
                "adjVolume": row["volume"],
                "divCash": 0,
                "splitFactor": 1,
            }
        )
        equal_payloads[symbol] = json.dumps(
            [row], ensure_ascii=True, separators=(",", ":")
        ).encode()
    snapshot, retained, identity, artifact_bytes = _proof_chain(
        tmp_path / "equal",
        payloads=equal_payloads,
    )
    equal = _qualify(snapshot, retained, identity, artifact_bytes)

    different_snapshot, different_retained, different_identity, different_artifact = _proof_chain(
        tmp_path / "different",
        payloads={symbol: response_bytes() for symbol in SYMBOLS},
    )
    different = _qualify(
        different_snapshot,
        different_retained,
        different_identity,
        different_artifact,
    )

    assert equal.candidate_occurrence_count == different.candidate_occurrence_count == 8
    assert equal.corporate_action_effect == different.corporate_action_effect == "none"
    assert equal.genuine_raw_effect == different.genuine_raw_effect == "none"
    assert equal.adjustment_methodology_effect == different.adjustment_methodology_effect == "none"


def test_qualification_rejects_proof_substitution_construction_replace_and_tamper(
    tmp_path: Path,
) -> None:
    snapshot, retained, identity, artifact_bytes = _proof_chain(tmp_path / "first")
    qualification = _qualify(snapshot, retained, identity, artifact_bytes)
    other_snapshot, other_retained, other_identity, _ = _proof_chain(
        tmp_path / "other",
        payloads={
            symbol: response_bytes(volume=2_000_000 + index) for index, symbol in enumerate(SYMBOLS)
        },
    )

    with pytest.raises((TiingoEodError, ValueError)):
        _qualify(snapshot, other_retained, identity, artifact_bytes)
    with pytest.raises((TiingoEodError, ValueError)):
        _qualify(snapshot, retained, other_identity, artifact_bytes)
    with pytest.raises((TiingoEodError, ValueError)):
        _qualify(other_snapshot, retained, identity, artifact_bytes)
    with pytest.raises((TiingoEodError, ValueError)):
        _qualify(copy.copy(snapshot), retained, identity, artifact_bytes)
    with pytest.raises((TiingoEodError, ValueError)):
        _qualify(snapshot, copy.copy(retained), identity, artifact_bytes)
    with pytest.raises(TypeError):
        TiingoEodMarketSemanticsQualification()
    with pytest.raises(TypeError):
        replace(qualification, row_count=99)

    class UnsupportedQualification(TiingoEodMarketSemanticsQualification):
        pass

    with pytest.raises(TypeError):
        UnsupportedQualification()

    object.__setattr__(qualification, "row_count", 99)
    with pytest.raises((TiingoEodError, ValueError)):
        qualification.__post_init__()


def test_artifact_and_qualification_digests_are_deterministic_and_evidence_bound(
    tmp_path: Path,
) -> None:
    snapshot, retained, identity, artifact_bytes = _proof_chain(tmp_path)
    first = _qualify(snapshot, retained, identity, artifact_bytes)
    second = _qualify(snapshot, retained, identity, artifact_bytes)
    payload = cast(dict[str, Any], json.loads(artifact_bytes))
    payload["raw_semantics_evidence_sha256"] = _digest("different raw evidence")
    changed_bytes = _canonical_json(payload)
    changed = _qualify(snapshot, retained, identity, changed_bytes)

    assert first == second
    assert first.artifact_sha256 == hashlib.sha256(artifact_bytes).hexdigest()
    assert first.qualification_sha256 == second.qualification_sha256
    assert changed.artifact_sha256 == hashlib.sha256(changed_bytes).hexdigest()
    assert changed.artifact_sha256 != first.artifact_sha256
    assert changed.qualification_sha256 != first.qualification_sha256
    for digest_name in (
        "artifact_sha256",
        "qualification_sha256",
        "field_semantics_contract_sha256",
        "action_candidate_contract_sha256",
        "synthetic_case_contract_sha256",
    ):
        assert len(getattr(first, digest_name)) == 64


def test_qualification_repr_is_value_free_and_refuses_every_downstream_type(
    tmp_path: Path,
) -> None:
    snapshot, retained, identity, artifact_bytes = _proof_chain(tmp_path)
    qualification = _qualify(snapshot, retained, identity, artifact_bytes)
    rendered = repr(qualification)

    assert not isinstance(qualification, HistoricalBarSource)
    assert not hasattr(qualification, "load")
    for prohibited in (
        artifact_bytes.decode(),
        "102.375",
        "101.125",
        "51.1875",
        "0.25",
        "security-dia",
        "test-independent-market-semantics-reviewer",
        "test-market-semantics-evidence-source-v1",
        _digest("raw semantics evidence"),
        _digest("market provenance evidence"),
    ):
        assert prohibited not in rendered

    refused_types = (
        RawBar,
        VendorBarRecord,
        CorporateActionRevision,
        SecurityMaster,
        HistoricalSourceBundle,
        HistoricalBarSource,
    )
    assert not isinstance(qualification, refused_types)
    for operation_name in (
        "raw_bar_records",
        "vendor_bar_records",
        "canonical_bar_records",
        "corporate_action_records",
        "security_master",
        "historical_source_bundle",
        "historical_bar_source",
        "admission_evidence",
    ):
        operation = getattr(qualification, operation_name)
        with pytest.raises(TiingoEodError):
            operation()


def test_fixed_contract_objects_reject_partition_case_and_convention_drift(
    tmp_path: Path,
) -> None:
    _, _, identity, artifact_bytes = _proof_chain(tmp_path)
    base = cast(dict[str, Any], json.loads(artifact_bytes))
    mutations: list[dict[str, Any]] = []

    overlapping = cast(dict[str, Any], json.loads(artifact_bytes))
    overlapping["field_partition"]["adjusted_research_fields"][0] = "open"
    mutations.append(overlapping)
    reordered = cast(dict[str, Any], json.loads(artifact_bytes))
    reordered["synthetic_cases"] = list(reversed(reordered["synthetic_cases"]))
    mutations.append(reordered)
    missing_case = cast(dict[str, Any], json.loads(artifact_bytes))
    missing_case["synthetic_cases"].pop()
    mutations.append(missing_case)
    provider_bound = cast(dict[str, Any], json.loads(artifact_bytes))
    provider_bound["synthetic_cases"][0]["symbol"] = "SPY"
    mutations.append(provider_bound)
    neutral_drift = cast(dict[str, Any], json.loads(artifact_bytes))
    neutral_drift["action_candidate_convention"]["div_cash_neutral"] = "0.01"
    mutations.append(neutral_drift)
    direction_drift = cast(dict[str, Any], json.loads(artifact_bytes))
    direction_drift["action_candidate_convention"]["split_factor_orientation"] = (
        "old_shares_per_new_share"
    )
    mutations.append(direction_drift)
    negative_zero = cast(dict[str, Any], json.loads(artifact_bytes))
    negative_zero["synthetic_cases"][0]["div_cash"] = "-0"
    mutations.append(negative_zero)
    trailing_zero = cast(dict[str, Any], json.loads(artifact_bytes))
    trailing_zero["synthetic_cases"][1]["div_cash"] = "0.250"
    mutations.append(trailing_zero)
    noncanonical_one = cast(dict[str, Any], json.loads(artifact_bytes))
    noncanonical_one["synthetic_cases"][0]["split_factor"] = "1.0"
    mutations.append(noncanonical_one)

    for payload in mutations:
        with pytest.raises((TiingoEodError, ValueError)):
            TiingoEodMarketSemanticsArtifact.from_json_bytes(_canonical_json(payload))

    assert base["identity_lifecycle_qualification_sha256"] == identity.qualification_sha256
    assert semantics_module is not None
