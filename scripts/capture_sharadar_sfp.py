"""Capture a bounded Sharadar SFP snapshot for offline research qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from datetime import date
from pathlib import Path
from typing import NoReturn

from packages.adapters.market_data.sharadar_sfp import (
    MAX_AUTHORIZATION_BYTES,
    PHASE1_SFP_SYMBOLS,
    SfpCaptureScope,
)
from packages.adapters.market_data.sharadar_sfp_capture import (
    SharadarSfpCaptureError,
    capture_sharadar_sfp,
)
from scripts.credential_env import load_owner_only_environment

RESEARCH_ONLY_NOTE = (
    "Captured for offline qualification only. SFP OHLCV is adjusted, the historical "
    "knowledge timeline before this capture is unknown, and admission/trading effects are none."
)
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CAPTURE_ROOT = REPOSITORY_ROOT / ".local/vendor-snapshots/sharadar-sfp"
_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)


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
        choices=PHASE1_SFP_SYMBOLS,
        help="Phase 1 symbol; repeat as needed. Defaults to all four.",
    )
    parser.add_argument("--authorization-file", required=True, type=Path)
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--timeout", type=float, default=15.0)
    return parser.parse_args()


def _die(message: str) -> NoReturn:
    raise SystemExit(message)


def _read_authorization(path: Path) -> bytes:
    absolute = Path(os.path.abspath(path))
    try:
        directory_descriptor = os.open(absolute.anchor, _DIRECTORY_FLAGS)
        for part in absolute.parts[1:-1]:
            next_descriptor = os.open(part, _DIRECTORY_FLAGS, dir_fd=directory_descriptor)
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        file_descriptor = os.open(
            absolute.name,
            _FILE_FLAGS,
            dir_fd=directory_descriptor,
        )
    except OSError as error:
        if "directory_descriptor" in locals():
            os.close(directory_descriptor)
        raise ValueError(
            "authorization path must contain only non-symlinked directories and a regular file"
        ) from error
    try:
        metadata = os.fstat(file_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("authorization file must be a regular file")
        with os.fdopen(file_descriptor, "rb", closefd=False) as stream:
            payload = stream.read(MAX_AUTHORIZATION_BYTES + 1)
    except OSError as error:
        raise ValueError("cannot read the capture authorization file") from error
    finally:
        os.close(file_descriptor)
        os.close(directory_descriptor)
    if len(payload) > MAX_AUTHORIZATION_BYTES:
        raise ValueError("authorization file exceeds the size limit")
    return payload


def main() -> int:
    args = _parse_args()
    end_date = args.end_date or args.start_date
    symbols = tuple(sorted(set(args.symbol or PHASE1_SFP_SYMBOLS)))
    try:
        environment = load_owner_only_environment(
            args.env_file,
            variables=("NASDAQ_DATA_LINK_API_KEY",),
        )
        api_key = environment.get("NASDAQ_DATA_LINK_API_KEY", "")
        scope = SfpCaptureScope(
            symbols=symbols,
            start_date=args.start_date,
            end_date=end_date,
        )
        authorization_bytes = _read_authorization(args.authorization_file)
        authorization_sha256 = hashlib.sha256(authorization_bytes).hexdigest()
        manifest_path = capture_sharadar_sfp(
            CAPTURE_ROOT,
            repository_root=REPOSITORY_ROOT,
            api_key=api_key,
            scope=scope,
            authorization_bytes=authorization_bytes,
            timeout_seconds=args.timeout,
        )
    except (ValueError, SharadarSfpCaptureError) as error:
        _die(str(error))
    print(
        json.dumps(
            {
                "admission_effect": "none",
                "authorization_sha256": authorization_sha256,
                "manifest": str(manifest_path.relative_to(REPOSITORY_ROOT)),
                "note": RESEARCH_ONLY_NOTE,
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
