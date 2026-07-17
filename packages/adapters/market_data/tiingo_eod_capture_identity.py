"""Shared identity rules for immutable Tiingo EOD capture directories."""

from __future__ import annotations

import hashlib
import re

from packages.adapters.market_data.tiingo_eod import (
    TiingoEodCaptureManifest,
    TiingoEodError,
)

TIINGO_EOD_FINAL_CAPTURE_NAME_PATTERN = re.compile(r"^[0-9]{8}T[0-9]{12}Z-[0-9a-f]{64}$")


def tiingo_eod_capture_name(manifest_bytes: bytes) -> str:
    """Return the timestamped full-manifest identity for canonical bytes."""

    if type(manifest_bytes) is not bytes or not manifest_bytes:
        raise TiingoEodError("capture manifest identity requires non-empty immutable bytes")
    manifest = TiingoEodCaptureManifest.from_json_bytes(manifest_bytes)
    if manifest.to_json_bytes() != manifest_bytes:
        raise TiingoEodError("capture manifest identity requires canonical frozen encoding")
    timestamp = manifest.requested_at.strftime("%Y%m%dT%H%M%S%fZ")
    return f"{timestamp}-{hashlib.sha256(manifest_bytes).hexdigest()}"
