"""Probe candidate market-data access without exposing credentials or granting admission."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from datetime import UTC, date, datetime
from pathlib import Path
from typing import NoReturn

from packages.adapters.market_data.provider_probe import (
    PROBE_NOTE,
    ProbeAccess,
    ProbeProvider,
    probe_provider,
)
from scripts.credential_env import load_owner_only_environment


def _date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("date must use YYYY-MM-DD") from error


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--provider",
        action="append",
        choices=tuple(provider.value for provider in ProbeProvider),
        help="Provider to probe; repeat to select multiple. Defaults to all.",
    )
    parser.add_argument("--symbol", default="SPY", help="Canonical uppercase sample symbol")
    parser.add_argument("--date", required=True, type=_date, help="Completed session YYYY-MM-DD")
    parser.add_argument(
        "--timeout", default=8.0, type=float, help="Per-provider timeout in seconds"
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        help="Owner-only dotenv file parsed literally; defaults to the process environment",
    )
    return parser.parse_args()


def _die(message: str) -> NoReturn:
    raise SystemExit(message)


def _load_environment(path: Path | None) -> Mapping[str, str]:
    return load_owner_only_environment(
        path,
        variables=("MASSIVE_API_KEY", "NASDAQ_DATA_LINK_API_KEY", "TIINGO_TOKEN"),
    )


def main() -> int:
    args = _parse_args()
    provider_values = args.provider or [provider.value for provider in ProbeProvider]
    try:
        providers = tuple(ProbeProvider(value) for value in provider_values)
        environment = _load_environment(args.env_file)
        results = [
            probe_provider(
                provider,
                environ=environment,
                symbol=args.symbol,
                session_date=args.date,
                timeout_seconds=args.timeout,
            )
            for provider in providers
        ]
    except ValueError as error:
        _die(str(error))
    print(
        json.dumps(
            {
                "note": PROBE_NOTE,
                "probed_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "probes": [result.to_dict() for result in results],
                "sample": {
                    "session_date": args.date.isoformat(),
                    "symbol": args.symbol,
                },
            },
            indent=2,
            sort_keys=True,
        )
    )
    successful = {ProbeAccess.ACCESSIBLE, ProbeAccess.ACCESSIBLE_NO_DATA}
    return 0 if all(result.access in successful for result in results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
