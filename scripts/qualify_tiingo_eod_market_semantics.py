"""Qualify one Tiingo capture against the market-semantics contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import NoReturn

from packages.adapters.market_data.tiingo_eod import (
    MAX_TIINGO_AUTHORIZATION_BYTES,
    MAX_TIINGO_PROFILE_BYTES,
    TiingoEodAcquisitionProfile,
    TiingoEodError,
)
from packages.adapters.market_data.tiingo_eod_calendar import (
    MAX_TIINGO_CALENDAR_ARTIFACT_BYTES,
)
from packages.adapters.market_data.tiingo_eod_identity_lifecycle import (
    MAX_TIINGO_EOD_IDENTITY_LIFECYCLE_ARTIFACT_BYTES,
    TiingoEodIdentityLifecycleArtifact,
    qualify_tiingo_eod_identity_lifecycle,
)
from packages.adapters.market_data.tiingo_eod_market_semantics import (
    MAX_TIINGO_EOD_MARKET_SEMANTICS_ARTIFACT_BYTES,
    TiingoEodMarketSemanticsArtifact,
    qualify_tiingo_eod_market_semantics,
)
from packages.adapters.market_data.tiingo_eod_retained_fields import (
    qualify_tiingo_eod_retained_fields,
)
from packages.adapters.market_data.tiingo_eod_snapshot import verify_tiingo_eod_capture
from scripts.local_artifact import read_owner_only_artifact

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ONLY_NOTE = (
    "Market-semantics and split/dividend-candidate contract consistency only. "
    "Structured provenance and field conventions are reference inputs, neutral "
    "values do not prove action absence, and no genuine-raw, adjustment, "
    "corporate-action, source, admission, or trading authority is granted."
)
QUALIFICATION_FAILURE_MESSAGE = "market-semantics qualification failed"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-name", required=True)
    parser.add_argument("--profile-file", required=True, type=Path)
    parser.add_argument("--authorization-file", required=True, type=Path)
    parser.add_argument("--calendar-file", required=True, type=Path)
    parser.add_argument("--identity-lifecycle-file", required=True, type=Path)
    parser.add_argument("--market-semantics-file", required=True, type=Path)
    return parser.parse_args()


def _die(message: str) -> NoReturn:
    raise SystemExit(message)


def main() -> int:
    args = _parse_args()
    try:
        profile_bytes = read_owner_only_artifact(
            args.profile_file,
            limit=MAX_TIINGO_PROFILE_BYTES,
            label="acquisition profile",
        )
        authorization_bytes = read_owner_only_artifact(
            args.authorization_file,
            limit=MAX_TIINGO_AUTHORIZATION_BYTES,
            label="capture authorization",
        )
        calendar_artifact_bytes = read_owner_only_artifact(
            args.calendar_file,
            limit=MAX_TIINGO_CALENDAR_ARTIFACT_BYTES,
            label="pinned calendar artifact",
        )
        identity_lifecycle_bytes = read_owner_only_artifact(
            args.identity_lifecycle_file,
            limit=MAX_TIINGO_EOD_IDENTITY_LIFECYCLE_ARTIFACT_BYTES,
            label="identity/lifecycle artifact",
        )
        market_semantics_bytes = read_owner_only_artifact(
            args.market_semantics_file,
            limit=MAX_TIINGO_EOD_MARKET_SEMANTICS_ARTIFACT_BYTES,
            label="market-semantics artifact",
        )
    except ValueError as error:
        _die(str(error))

    try:
        profile = TiingoEodAcquisitionProfile.from_json_bytes(profile_bytes)
        TiingoEodIdentityLifecycleArtifact.from_json_bytes(identity_lifecycle_bytes)
        TiingoEodMarketSemanticsArtifact.from_json_bytes(market_semantics_bytes)
        snapshot = verify_tiingo_eod_capture(
            repository_root=REPOSITORY_ROOT,
            capture_name=args.capture_name,
            expected_profile=profile,
            authorization_bytes=authorization_bytes,
            calendar_artifact_bytes=calendar_artifact_bytes,
        )
        retained_fields = qualify_tiingo_eod_retained_fields(snapshot)
        identity_lifecycle = qualify_tiingo_eod_identity_lifecycle(
            snapshot=snapshot,
            retained_fields=retained_fields,
            artifact_bytes=identity_lifecycle_bytes,
        )
        qualification = qualify_tiingo_eod_market_semantics(
            snapshot=snapshot,
            retained_fields=retained_fields,
            identity_lifecycle=identity_lifecycle,
            artifact_bytes=market_semantics_bytes,
        )
    except (TiingoEodError, ValueError):
        _die(QUALIFICATION_FAILURE_MESSAGE)

    print(
        json.dumps(
            {
                "action_candidate_contract_sha256": (
                    qualification.action_candidate_contract_sha256
                ),
                "adjustment_methodology_effect": qualification.adjustment_methodology_effect,
                "admission_effect": qualification.admission_effect,
                "artifact_kind": qualification.artifact_kind.value,
                "artifact_sha256": qualification.artifact_sha256,
                "calendar_artifact_sha256": qualification.calendar_artifact_sha256,
                "candidate_field_count": qualification.candidate_field_count,
                "candidate_occurrence_count": qualification.candidate_occurrence_count,
                "canonical_bar_effect": qualification.canonical_bar_effect,
                "capture_name": args.capture_name,
                "check_ids": list(qualification.check_ids),
                "corporate_action_effect": qualification.corporate_action_effect,
                "correction_effect": qualification.correction_effect,
                "field_semantics_contract_sha256": (qualification.field_semantics_contract_sha256),
                "genuine_raw_effect": qualification.genuine_raw_effect,
                "historical_source_effect": qualification.historical_source_effect,
                "identity_lifecycle_qualification_sha256": (
                    qualification.identity_lifecycle_qualification_sha256
                ),
                "market_provenance_effect": qualification.market_provenance_effect,
                "note": CONTRACT_ONLY_NOTE,
                "profile_contract_sha256": qualification.profile_contract_sha256,
                "qualification_kind": qualification.qualification_kind.value,
                "qualification_sha256": qualification.qualification_sha256,
                "retained_field_qualification_sha256": (
                    qualification.retained_field_qualification_sha256
                ),
                "row_count": qualification.row_count,
                "schema_version": qualification.schema_version,
                "scope": qualification.scope.to_dict(),
                "stable_id_count": qualification.stable_id_count,
                "synthetic_case_contract_sha256": (qualification.synthetic_case_contract_sha256),
                "synthetic_case_count": qualification.synthetic_case_count,
                "trading_effect": qualification.trading_effect,
                "vendor_publication_effect": qualification.vendor_publication_effect,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
