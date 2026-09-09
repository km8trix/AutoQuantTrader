"""Explicitly renew one existing E*TRADE session into a NEW private env file.

Uses only the selected environment and one fixed OAuth renewal request. No
browser, verifier, automatic retries, account calls, or original-file changes.
Renewal does not extend daily expiry. The output duplicates private credentials.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from packages.adapters.broker.etrade import EtradeEnvironment
from packages.adapters.broker.etrade_owner_renewal import renew_owner_session
from packages.adapters.broker.etrade_readonly import EtradeSecretReference


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorize-renew", action="store_true", required=True)
    parser.add_argument(
        "--environment", choices=[value.value for value in EtradeEnvironment], required=True
    )
    parser.add_argument("--secret-reference", required=True)
    parser.add_argument("--new-session-output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = renew_owner_session(
            reference=EtradeSecretReference(
                EtradeEnvironment(args.environment), args.secret_reference
            ),
            output=args.new_session_output,
            authorize_renew=args.authorize_renew,
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except KeyboardInterrupt:
        print(json.dumps({"blocker": "RENEWAL_INTERRUPTED_REVIEW_ATTEMPT_BEFORE_RETRY"}))
        return 2
    except Exception:
        # Do not print dependency exceptions, headers or arbitrary provider bodies.
        print(
            json.dumps(
                {
                    "blocker": "RENEWAL_NOT_COMPLETED_REVIEW_PRIVATE_ATTEMPT_FILE",
                    "trading_authorized": False,
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
