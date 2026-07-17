"""Derive receipt-time local lineage from immutable verified Tiingo captures."""

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
from packages.adapters.market_data.tiingo_eod_lineage import (
    TiingoEodReceiptDisposition,
    derive_tiingo_eod_receipt_lineage,
)
from packages.adapters.market_data.tiingo_eod_snapshot import (
    verify_tiingo_eod_capture,
)
from scripts.local_artifact import read_owner_only_artifact

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RESEARCH_ONLY_NOTE = (
    "Local receipt-time versions from independently verified captures only. No vendor "
    "publication time or vendor correction was inferred; admission/trading effects are none."
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-name", action="append", required=True)
    parser.add_argument("--profile-file", required=True, type=Path)
    parser.add_argument("--authorization-file", required=True, type=Path)
    parser.add_argument("--calendar-file", required=True, type=Path)
    return parser.parse_args()


def _die(message: str) -> NoReturn:
    raise SystemExit(message)


def main() -> int:
    args = _parse_args()
    capture_names = tuple(args.capture_name)
    try:
        if len(capture_names) < 2:
            raise ValueError("at least two capture names are required for receipt-time lineage")
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
        snapshots = tuple(
            verify_tiingo_eod_capture(
                repository_root=REPOSITORY_ROOT,
                capture_name=capture_name,
                expected_profile=profile,
                authorization_bytes=authorization_bytes,
                calendar_artifact_bytes=calendar_artifact_bytes,
            )
            for capture_name in capture_names
        )
        lineage = derive_tiingo_eod_receipt_lineage(snapshots)
    except (TiingoEodError, ValueError) as error:
        _die(str(error))

    disposition_counts = {
        disposition.value: sum(
            comparison.disposition is disposition for comparison in lineage.comparisons
        )
        for disposition in TiingoEodReceiptDisposition
    }
    print(
        json.dumps(
            {
                "admission_effect": "none",
                "calendar_artifact_sha256": lineage.calendar_artifact_sha256,
                "capture_count": len(lineage.snapshots),
                "captures": [
                    {
                        "capture_name": capture_name,
                        "manifest_sha256": snapshot.manifest_sha256,
                        "received_at": snapshot.manifest.received_at.isoformat(),
                        "requested_at": snapshot.manifest.requested_at.isoformat(),
                        "snapshot_semantic_sha256": snapshot.semantic_sha256,
                    }
                    for capture_name, snapshot in zip(
                        capture_names,
                        lineage.snapshots,
                        strict=True,
                    )
                ],
                "comparison_count": len(lineage.comparisons),
                "disposition_counts": disposition_counts,
                "lineage_sha256": lineage.lineage_sha256,
                "local_observation_count": len(
                    {comparison.local_observation_id for comparison in lineage.comparisons}
                ),
                "local_revision_count": len(lineage.revisions),
                "note": RESEARCH_ONLY_NOTE,
                "policy": lineage.policy,
                "profile_contract_sha256": lineage.profile_contract_sha256,
                "schema_version": lineage.schema_version,
                "scope": lineage.scope.to_dict(),
                "trading_effect": "none",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
