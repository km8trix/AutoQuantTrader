"""Verify the checked-in no-exposure smoke strategy without executing it."""

from __future__ import annotations

import json

from packages.application.no_exposure_smoke_strategy import (
    load_no_exposure_smoke_artifact,
)
from packages.domain.strategy_supervision import STRATEGY_SUBPROCESS_PROTOCOL_VERSION


def main() -> int:
    artifact = load_no_exposure_smoke_artifact()
    result = {
        "artifact_sha256": artifact.subprocess_spec.artifact_sha256,
        "manifest_sha256": artifact.manifest_sha256,
        "protocol_version": STRATEGY_SUBPROCESS_PROTOCOL_VERSION,
        "result_contract_version": artifact.result_contract_version,
        "strategy_configuration_sha256": artifact.strategy_configuration_sha256,
        "strategy_id": artifact.strategy_id,
        "strategy_version": artifact.strategy_version,
        "verified": True,
    }
    print(
        json.dumps(
            result,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
