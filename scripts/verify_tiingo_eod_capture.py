"""Verify one immutable Tiingo EOD capture with reviewed local artifacts."""

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
from packages.adapters.market_data.tiingo_eod_snapshot import (
    verify_tiingo_eod_capture,
)
from scripts.local_artifact import read_owner_only_artifact

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RESEARCH_ONLY_NOTE = (
    "Verified receipt-time research observations only. No vendor publication or revision "
    "timestamps were inferred, and admission/trading effects are none."
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
    except (TiingoEodError, ValueError) as error:
        _die(str(error))

    print(
        json.dumps(
            {
                "admission_effect": "none",
                "authorization_sha256": snapshot.manifest.authorization_sha256,
                "calendar_artifact_sha256": snapshot.calendar_artifact_sha256,
                "calendar_bindings": [
                    {
                        "authority": binding.authority,
                        "calendar_id": binding.calendar_id,
                        "calendar_sha256": binding.calendar_sha256,
                        "calendar_version": binding.calendar_version,
                        "session_count": len(binding.sessions),
                        "symbol": binding.symbol,
                        "timezone": binding.timezone,
                        "venue": binding.venue,
                    }
                    for binding in snapshot.calendar_bindings
                ],
                "capture_name": args.capture_name,
                "manifest_sha256": snapshot.manifest_sha256,
                "note": RESEARCH_ONLY_NOTE,
                "observation_count": len(snapshot.observations),
                "profile_contract_sha256": snapshot.manifest.profile_contract_sha256,
                "row_count": len(snapshot.rows),
                "schema_version": snapshot.schema_version,
                "semantic_sha256": snapshot.semantic_sha256,
                "trading_effect": "none",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
