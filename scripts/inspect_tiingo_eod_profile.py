"""Validate a Tiingo EOD acquisition profile and print its normalized contract digest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import NoReturn

from packages.adapters.market_data.tiingo_eod import (
    MAX_TIINGO_PROFILE_BYTES,
    TiingoEodAcquisitionProfile,
    TiingoEodError,
)
from scripts.local_artifact import read_owner_only_artifact


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile-file", required=True, type=Path)
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
    except (TiingoEodError, ValueError) as error:
        _die(str(error))
    print(
        json.dumps(
            {
                "approved": profile.approved,
                "profile_contract_sha256": profile.contract_sha256,
                "profile_id": profile.profile_id,
                "reviewed_at": profile.reviewed_at.isoformat().replace("+00:00", "Z"),
                "reviewer_id": profile.reviewer_id,
                "scope": profile.scope.to_dict(),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
