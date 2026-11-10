"""Owner-only interactive E*TRADE OAuth consent, with secret-free terminal output.

Run separately for sandbox/production. This opens the local browser and accepts
E*TRADE's verifier only through getpass in a real terminal. A new private scoped
session file is created; the existing consumer reference is never modified.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
import warnings
from collections.abc import Sequence
from pathlib import Path

from packages.adapters.broker.etrade import EtradeEnvironment
from packages.adapters.broker.etrade_owner_oauth import acquire_owner_session
from packages.adapters.broker.etrade_readonly import EtradeSecretReference


def _verifier() -> str:
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        return getpass.getpass("Enter the E*TRADE verifier here (hidden): ")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interactive", action="store_true", required=True)
    parser.add_argument(
        "--environment", choices=[value.value for value in EtradeEnvironment], required=True
    )
    parser.add_argument("--consumer-reference", required=True)
    parser.add_argument("--new-session-output", type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.interactive or not sys.stdin.isatty() or not sys.stderr.isatty():
        print(json.dumps({"blocker": "REAL_INTERACTIVE_TERMINAL_REQUIRED", "provider_requests": 0}))
        return 2
    try:
        reference = EtradeSecretReference(
            EtradeEnvironment(args.environment), args.consumer_reference
        )
        result = acquire_owner_session(
            reference=reference, output=args.new_session_output, verifier_input=_verifier
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except KeyboardInterrupt:
        print(json.dumps({"blocker": "OWNER_CANCELLED_REVIEW_ATTEMPT_BEFORE_RETRY"}))
        return 2
    except Exception:
        # Never print exception text: dependency errors can embed URLs/credentials.
        print(
            json.dumps(
                {
                    "blocker": "OAUTH_NOT_COMPLETED_REVIEW_PRIVATE_ATTEMPT_FILE",
                    "trading_authorized": False,
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
