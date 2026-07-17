"""Capture a reviewed Tiingo EOD snapshot for offline research qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from datetime import UTC, date, datetime
from pathlib import Path
from typing import NoReturn

from packages.adapters.market_data.tiingo_eod import (
    MAX_TIINGO_AUTHORIZATION_BYTES,
    MAX_TIINGO_PROFILE_BYTES,
    PHASE1_TIINGO_SYMBOLS,
    TiingoEodAcquisitionProfile,
    TiingoEodCaptureAuthorization,
    TiingoEodScope,
)
from packages.adapters.market_data.tiingo_eod_calendar import (
    MAX_TIINGO_CALENDAR_ARTIFACT_BYTES,
    TiingoEodPinnedCalendarArtifact,
)
from packages.adapters.market_data.tiingo_eod_capture import (
    TiingoEodCaptureError,
    capture_tiingo_eod,
)
from scripts.credential_env import load_owner_only_environment
from scripts.local_artifact import read_owner_only_artifact

RESEARCH_ONLY_NOTE = (
    "Captured for offline qualification only. Tiingo EOD responses do not establish "
    "vendor publication or revision timestamps, and admission/trading effects are none."
)
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("date must use YYYY-MM-DD") from error


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start-date", required=True, type=_date)
    parser.add_argument("--end-date", type=_date)
    parser.add_argument(
        "--symbol",
        action="append",
        choices=PHASE1_TIINGO_SYMBOLS,
        help="Phase 1 symbol; repeat as needed. Defaults to all four.",
    )
    parser.add_argument("--profile-file", required=True, type=Path)
    parser.add_argument("--authorization-file", required=True, type=Path)
    parser.add_argument("--calendar-file", required=True, type=Path)
    parser.add_argument("--env-file", type=Path)
    parser.add_argument(
        "--per-request-timeout",
        type=float,
        default=15.0,
        help="Socket I/O timeout for each symbol request; not a whole-capture deadline.",
    )
    return parser.parse_args()


def _die(message: str) -> NoReturn:
    raise SystemExit(message)


def main() -> int:
    args = _parse_args()
    end_date = args.end_date or args.start_date
    symbols = tuple(sorted(set(args.symbol or PHASE1_TIINGO_SYMBOLS)))
    try:
        scope = TiingoEodScope(
            symbols=symbols,
            start_date=args.start_date,
            end_date=end_date,
        )
        profile_bytes = read_owner_only_artifact(
            args.profile_file,
            limit=MAX_TIINGO_PROFILE_BYTES,
            label="acquisition profile",
        )
        profile = TiingoEodAcquisitionProfile.from_json_bytes(profile_bytes)
        if profile.scope != scope:
            raise ValueError("requested scope must exactly match the reviewed acquisition profile")
        authorization_bytes = read_owner_only_artifact(
            args.authorization_file,
            limit=MAX_TIINGO_AUTHORIZATION_BYTES,
            label="capture authorization",
        )
        authorization = TiingoEodCaptureAuthorization.from_json_bytes(authorization_bytes)
        calendar_artifact_bytes = read_owner_only_artifact(
            args.calendar_file,
            limit=MAX_TIINGO_CALENDAR_ARTIFACT_BYTES,
            label="pinned calendar artifact",
        )
        calendar_artifact = TiingoEodPinnedCalendarArtifact.from_json_bytes(calendar_artifact_bytes)
        validation_instant = datetime.now(UTC)
        authorization.authorize(profile, requested_at=validation_instant)
        calendar_artifact.authorize(profile, requested_at=validation_instant)
        if not math.isfinite(args.per_request_timeout) or not 0 < args.per_request_timeout <= 30:
            raise ValueError("per-request timeout must be finite and between 0 and 30 seconds")

        # Credential access deliberately follows every scope, profile, and permission check.
        environment = load_owner_only_environment(args.env_file, variables=("TIINGO_TOKEN",))
        token = environment.get("TIINGO_TOKEN", "")
        manifest_path = capture_tiingo_eod(
            repository_root=REPOSITORY_ROOT,
            token=token,
            profile=profile,
            authorization_bytes=authorization_bytes,
            calendar_artifact_bytes=calendar_artifact_bytes,
            timeout_seconds=args.per_request_timeout,
        )
    except (ValueError, TiingoEodCaptureError) as error:
        _die(str(error))
    print(
        json.dumps(
            {
                "admission_effect": "none",
                "authorization_sha256": hashlib.sha256(authorization_bytes).hexdigest(),
                "calendar_artifact_sha256": calendar_artifact.artifact_sha256,
                "manifest": str(manifest_path.relative_to(REPOSITORY_ROOT)),
                "note": RESEARCH_ONLY_NOTE,
                "profile_contract_sha256": profile.contract_sha256,
                "scope": scope.to_dict(),
                "trading_effect": "none",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
