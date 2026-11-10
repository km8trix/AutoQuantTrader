"""Capture a small explicitly authorized Tiingo sample without exposing the token.

No retries, subscriptions, order endpoints, ambient credentials or dotenv
evaluation. Exact private response files and sanitized factual receipt metadata
are the only outputs. The importer separately checks source rights and calendar.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Callable
from datetime import UTC, date, datetime
from pathlib import Path
from urllib.parse import urlencode

from packages.adapters.market_data.tiingo_eod import (
    PHASE1_TIINGO_SYMBOLS,
    TiingoEodScope,
    tiingo_eod_response_contract,
)
from packages.adapters.market_data.tiingo_eod_capture import (
    TiingoEodApiRequest,
    TiingoEodApiTransport,
    TiingoEodCaptureError,
    _https_get,
)
from packages.market_data.models import require_utc


def _load_token(path: Path) -> str:
    """Extract only TIINGO_TOKEN; other dotenv assignments are not interpreted."""
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise ValueError("credential source must be an owner-owned regular file")
        payload = source.read(1_048_577)
    if len(payload) > 1_048_576:
        raise ValueError("credential source exceeds the size limit")
    matches: list[str] = []
    for raw in payload.decode("utf-8").splitlines():
        match = re.match(r"^\s*(?:export\s+)?TIINGO_TOKEN\s*=(.*)$", raw)
        if match is not None:
            value = match.group(1).strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            matches.append(value)
    if len(matches) != 1 or re.fullmatch(r"[A-Za-z0-9_-]{16,512}", matches[0]) is None:
        raise ValueError("credential source requires one literal TIINGO_TOKEN assignment")
    return matches[0]


def _write_private(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)


def capture_personal_tiingo(
    *,
    env_file: Path,
    output_dir: Path,
    scope: TiingoEodScope,
    transport: TiingoEodApiTransport = _https_get,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> dict[str, object]:
    if (
        not set(scope.symbols).issubset(PHASE1_TIINGO_SYMBOLS)
        or (scope.end_date - scope.start_date).days > 30
    ):
        raise ValueError("capture is limited to four personal-v1 symbols and 31 calendar days")
    if not output_dir.is_absolute():
        raise ValueError("capture output directory must be explicit and absolute")
    repository = Path(__file__).resolve().parents[1]
    resolved_output = output_dir.resolve()
    if resolved_output == repository or repository in resolved_output.parents:
        raise ValueError("private capture output must be outside the checkout")
    output_dir.mkdir(mode=0o700)
    token = _load_token(env_file)
    scope_bytes = json.dumps(scope.to_dict(), sort_keys=True).encode()
    scope_sha256 = hashlib.sha256(scope_bytes).hexdigest()
    receipts: list[dict[str, object]] = []
    for symbol in scope.symbols:
        requested_at = clock()
        require_utc(requested_at, "requested_at")
        query = urlencode(
            {
                "startDate": scope.start_date.isoformat(),
                "endDate": scope.end_date.isoformat(),
                "format": "json",
            }
        )
        request = TiingoEodApiRequest(
            symbol=symbol,
            profile_contract_sha256=scope_sha256,
            url=f"https://api.tiingo.com/tiingo/daily/{symbol}/prices?{query}",
            headers={
                "Accept": "application/json",
                "Authorization": f"Token {token}",
                "User-Agent": "AutoQuantTrader/personal-v1",
            },
        )
        try:
            response = transport(request, timeout_seconds=15.0)
        except Exception:
            raise TiingoEodCaptureError("Tiingo request failed; no retry was attempted") from None
        received_at = clock()
        require_utc(received_at, "received_at")
        if received_at < requested_at:
            raise ValueError("capture UTC regressed")
        if response.status != 200:
            raise TiingoEodCaptureError(f"Tiingo returned HTTP {response.status}; capture stopped")
        try:
            contract = tiingo_eod_response_contract(response.payload, scope=scope)
        except ValueError:
            raise TiingoEodCaptureError("Tiingo response failed the daily field contract") from None
        validated_at = clock()
        require_utc(validated_at, "validated_at")
        if validated_at < received_at:
            raise ValueError("capture UTC regressed")
        _write_private(output_dir / f"{symbol}.json", response.payload)
        receipt: dict[str, object] = {
            "symbol": symbol,
            "requested_at": requested_at.isoformat(),
            "received_at": received_at.isoformat(),
            "observed_available_at": validated_at.isoformat(),
            "sha256": contract.response_sha256,
            "byte_count": contract.byte_count,
            "row_count": len(contract.session_dates),
            "schema_sha256": contract.schema_sha256,
        }
        receipts.append(receipt)
        _write_private(
            output_dir / f"{symbol}.receipt.json",
            (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode(),
        )
    metadata: dict[str, object] = {
        "schema_version": "personal-tiingo-capture-v1",
        "provider": "tiingo",
        "endpoint_authority": "https://api.tiingo.com",
        "scope": scope.to_dict(),
        "receipts": receipts,
        "vendor_published_at": None,
        "admission_effect": "none",
        "trading_effect": "none",
    }
    _write_private(
        output_dir / "capture.json",
        (json.dumps(metadata, sort_keys=True, indent=2) + "\n").encode(),
    )
    return metadata


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--start-date", type=date.fromisoformat, required=True)
    parser.add_argument("--end-date", type=date.fromisoformat, required=True)
    parser.add_argument("--symbol", action="append", choices=PHASE1_TIINGO_SYMBOLS, required=True)
    args = parser.parse_args(argv)
    try:
        metadata = capture_personal_tiingo(
            env_file=args.env_file,
            output_dir=args.output_dir,
            scope=TiingoEodScope(tuple(sorted(args.symbol)), args.start_date, args.end_date),
        )
    except Exception as error:
        # Some filesystem and credential-library exceptions can contain input text.
        print(
            f"Tiingo capture failed ({type(error).__name__}); private partial output retained",
            file=sys.stderr,
        )
        return 2
    print(json.dumps(metadata, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
