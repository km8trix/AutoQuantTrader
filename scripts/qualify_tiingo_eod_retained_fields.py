"""Qualify one verified Tiingo capture against the retained field contract."""

from __future__ import annotations

import argparse
import json
from collections import Counter
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
from packages.adapters.market_data.tiingo_eod_retained_fields import (
    qualify_tiingo_eod_retained_fields,
)
from packages.adapters.market_data.tiingo_eod_snapshot import (
    verify_tiingo_eod_capture,
)
from scripts.local_artifact import read_owner_only_artifact

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RESEARCH_ONLY_NOTE = (
    "Exact retained field-contract conformance only. Field roles are application policy; "
    "observed values do not establish execution-safe raw prices, adjustment or action "
    "semantics, admission, or trading authority."
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-name", required=True)
    parser.add_argument("--profile-file", required=True, type=Path)
    parser.add_argument("--authorization-file", required=True, type=Path)
    parser.add_argument("--calendar-file", required=True, type=Path)
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
        profile = TiingoEodAcquisitionProfile.from_json_bytes(profile_bytes)
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
        snapshot = verify_tiingo_eod_capture(
            repository_root=REPOSITORY_ROOT,
            capture_name=args.capture_name,
            expected_profile=profile,
            authorization_bytes=authorization_bytes,
            calendar_artifact_bytes=calendar_artifact_bytes,
        )
        qualification = qualify_tiingo_eod_retained_fields(snapshot)
    except (TiingoEodError, ValueError) as error:
        _die(str(error))

    role_field_counts = Counter(binding.role.value for binding in qualification.field_bindings)
    print(
        json.dumps(
            {
                "admission_effect": "none",
                "calendar_artifact_sha256": qualification.calendar_artifact_sha256,
                "capture_name": args.capture_name,
                "check_ids": list(qualification.check_ids),
                "corporate_action_effect": "none",
                "field_bindings": [
                    {
                        "field_name": binding.field_name,
                        "role": binding.role.value,
                        "row_attribute": binding.row_attribute,
                        "source_schema_constraint_id": (binding.source_schema_constraint_id),
                    }
                    for binding in qualification.field_bindings
                ],
                "field_contract_sha256": qualification.field_contract_sha256,
                "field_count": len(qualification.field_bindings),
                "field_occurrence_count": qualification.field_occurrence_count,
                "field_occurrence_counts": [
                    {
                        "count": qualification.row_count,
                        "field_name": binding.field_name,
                    }
                    for binding in qualification.field_bindings
                ],
                "manifest_sha256": qualification.manifest_sha256,
                "note": RESEARCH_ONLY_NOTE,
                "observation_count": qualification.observation_count,
                "profile_contract_sha256": qualification.profile_contract_sha256,
                "qualification_kind": qualification.qualification_kind.value,
                "qualification_sha256": qualification.qualification_sha256,
                "raw_execution_effect": "none",
                "received_at": qualification.received_at.isoformat(),
                "requested_at": qualification.requested_at.isoformat(),
                "role_contract_sha256": qualification.role_contract_sha256,
                "role_field_counts": dict(sorted(role_field_counts.items())),
                "row_count": qualification.row_count,
                "schema_version": qualification.schema_version,
                "scope": qualification.scope.to_dict(),
                "session_count": qualification.session_count,
                "snapshot_semantic_sha256": qualification.snapshot_semantic_sha256,
                "trading_effect": "none",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
