"""Evaluate a frozen market-data admission specification and evidence bundle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from packages.application.market_data_admission import (
    AdmissionInputError,
    admission_report_payload,
    load_admission_evidence,
    load_admission_specification,
)
from packages.market_data import AdmissionEvidenceError, AdmissionStatus, evaluate_admission


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--specification", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument(
        "--allow-not-admitted",
        action="store_true",
        help="return success after printing a blocked, pending, or rejected report",
    )
    args = parser.parse_args()
    try:
        specification = load_admission_specification(args.specification)
        evidence = load_admission_evidence(args.evidence)
        report = evaluate_admission(specification, evidence)
    except (AdmissionInputError, AdmissionEvidenceError, ValueError) as error:
        print(
            json.dumps(
                {"error": str(error), "status": "invalid"},
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(admission_report_payload(report), indent=2, sort_keys=True))
    if report.status is AdmissionStatus.ADMITTED or args.allow_not_admitted:
        return 0
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
