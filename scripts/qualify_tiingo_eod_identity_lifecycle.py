"""Qualify one verified Tiingo capture against an identity/lifecycle contract."""

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
from packages.adapters.market_data.tiingo_eod_retained_fields import (
    qualify_tiingo_eod_retained_fields,
)
from packages.adapters.market_data.tiingo_eod_snapshot import verify_tiingo_eod_capture
from scripts.local_artifact import read_owner_only_artifact

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ONLY_NOTE = (
    "Identity/lifecycle contract consistency only. The profile authority name is a label, "
    "lifecycle instants are not calendar authority, and no production identity, raw price, "
    "corporate-action, source, admission, or trading authority is granted."
)
QUALIFICATION_FAILURE_MESSAGE = "identity/lifecycle qualification failed"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-name", required=True)
    parser.add_argument("--profile-file", required=True, type=Path)
    parser.add_argument("--authorization-file", required=True, type=Path)
    parser.add_argument("--calendar-file", required=True, type=Path)
    parser.add_argument("--identity-lifecycle-file", required=True, type=Path)
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
    except ValueError as error:
        _die(str(error))

    try:
        profile = TiingoEodAcquisitionProfile.from_json_bytes(profile_bytes)
        TiingoEodIdentityLifecycleArtifact.from_json_bytes(identity_lifecycle_bytes)
        snapshot = verify_tiingo_eod_capture(
            repository_root=REPOSITORY_ROOT,
            capture_name=args.capture_name,
            expected_profile=profile,
            authorization_bytes=authorization_bytes,
            calendar_artifact_bytes=calendar_artifact_bytes,
        )
        retained_fields = qualify_tiingo_eod_retained_fields(snapshot)
        qualification = qualify_tiingo_eod_identity_lifecycle(
            snapshot=snapshot,
            retained_fields=retained_fields,
            artifact_bytes=identity_lifecycle_bytes,
        )
    except (TiingoEodError, ValueError):
        _die(QUALIFICATION_FAILURE_MESSAGE)

    print(
        json.dumps(
            {
                "admission_effect": "none",
                "artifact_kind": qualification.artifact_kind.value,
                "artifact_sha256": qualification.artifact_sha256,
                "calendar_artifact_sha256": qualification.calendar_artifact_sha256,
                "canonical_bar_effect": "none",
                "capture_name": args.capture_name,
                "check_ids": list(qualification.check_ids),
                "corporate_action_effect": "none",
                "delisting_case_count": qualification.delisting_case_count,
                "historical_source_effect": "none",
                "identifier_count": qualification.identifier_count,
                "lifecycle_calendar_effect": "none",
                "mapping_count": qualification.mapping_count,
                "membership_count": qualification.membership_count,
                "note": CONTRACT_ONLY_NOTE,
                "profile_contract_sha256": qualification.profile_contract_sha256,
                "production_identity_effect": qualification.production_identity_effect,
                "qualification_kind": qualification.qualification_kind.value,
                "qualification_sha256": qualification.qualification_sha256,
                "raw_execution_effect": "none",
                "retained_field_qualification_sha256": (
                    qualification.retained_field_qualification_sha256
                ),
                "schema_version": qualification.schema_version,
                "scope": qualification.scope.to_dict(),
                "security_count": qualification.security_count,
                "session_mapping_count": qualification.session_mapping_count,
                "snapshot_semantic_sha256": qualification.snapshot_semantic_sha256,
                "symbol_change_case_count": qualification.symbol_change_case_count,
                "trade_symbol_count": qualification.trade_symbol_count,
                "trading_effect": "none",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
