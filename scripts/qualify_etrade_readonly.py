"""Explicitly invoked E*TRADE credential-presence/discovery/read qualification.

Examples (placeholders; never source or print the credential file):
  python -m scripts.qualify_etrade_readonly --environment sandbox \
    --secret-reference 'envfile:///absolute/path/.env?version=1' --inspect-reference

  python -m scripts.qualify_etrade_readonly --environment production \
    --secret-reference 'envfile:///absolute/path/.env?version=1' --authorize-read \
    --private-output-dir /absolute/private/new-capture-directory

Discovery prints only account fingerprints. Repeat with explicit
--account-fingerprint, --declare-exclusive, --start-date and --end-date for
bounded account capture. Each command creates a new private output directory.
Add --allow-margin-privileges only for the explicit cash-funded read profile;
this permits CASH/MARGIN privileges and grants no borrowing or trading authority.
The authorize-read flag records the caller's explicit action, not an OAuth
privilege or evidence certificate. This script never acquires/renews a token.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from dataclasses import asdict
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit

from packages.adapters.broker.etrade import EtradeEnvironment
from packages.adapters.broker.etrade_readonly import (
    EnvFileEtradeCredentialStore,
    EtradeHTTPSGetTransport,
    EtradeReadError,
    EtradeSecretReference,
    MacOSKeychainEtradeCredentialStore,
)
from packages.application.etrade_session import (
    EtradeCaptureBounds,
    EtradeReadOnlySession,
    PrivateDirectoryEtradeJournal,
)
from packages.domain.clock import SystemClock


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--environment",
        required=True,
        choices=[environment.value for environment in EtradeEnvironment],
    )
    parser.add_argument("--secret-reference", required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument(
        "--inspect-reference",
        action="store_true",
        help="Return environment-scoped presence booleans only; no provider request",
    )
    action.add_argument(
        "--authorize-read",
        action="store_true",
        help="Explicitly invoke bounded account GET requests using the selected reference",
    )
    parser.add_argument("--private-output-dir", type=Path)
    parser.add_argument("--account-fingerprint")
    parser.add_argument(
        "--declare-exclusive", action="store_true", help="Owner declaration; never broker-attested"
    )
    parser.add_argument(
        "--allow-margin-privileges",
        action="store_true",
        help="Explicit capture opt-in for CASH/MARGIN privileges; cash-funded restrictions remain",
    )
    parser.add_argument("--start-date", type=date.fromisoformat)
    parser.add_argument("--end-date", type=date.fromisoformat)
    args = parser.parse_args(argv)
    session = None
    try:
        environment = EtradeEnvironment(args.environment)
        reference = EtradeSecretReference(environment, args.secret_reference)
        if args.allow_margin_privileges and (
            args.inspect_reference or not args.account_fingerprint
        ):
            raise EtradeReadError("MARGIN_PRIVILEGES_OPT_IN_REQUIRES_ACCOUNT_CAPTURE")
        if args.inspect_reference:
            if urlsplit(reference.uri).scheme != "envfile":
                raise EtradeReadError("PRESENCE_INSPECTION_SUPPORTS_EXPLICIT_ENVFILE_ONLY")
            presence = EnvFileEtradeCredentialStore().inspect(reference)
            print(
                json.dumps(
                    {**asdict(presence), "blocker": presence.blocker, "provider_requests": 0},
                    sort_keys=True,
                )
            )
            return 0 if presence.blocker is None else 2
        if args.private_output_dir is None:
            raise EtradeReadError("EXPLICIT_PRIVATE_OUTPUT_DIRECTORY_REQUIRED")
        output = args.private_output_dir.resolve()
        repository = Path(__file__).resolve().parents[1]
        if (
            not args.private_output_dir.is_absolute()
            or output == repository
            or repository in output.parents
        ):
            raise EtradeReadError("PRIVATE_OUTPUT_MUST_BE_ABSOLUTE_AND_OUTSIDE_CHECKOUT")
        # Validate dependent CLI inputs before creating a journal or resolving secrets.
        if args.account_fingerprint:
            if not args.declare_exclusive or args.start_date is None or args.end_date is None:
                raise EtradeReadError("EXPLICIT_ACCOUNT_CAPTURE_ARGUMENTS_REQUIRED")
            EtradeCaptureBounds(args.start_date, args.end_date).validate(SystemClock().now())
        elif args.start_date is not None or args.end_date is not None or args.declare_exclusive:
            raise EtradeReadError("EXPLICIT_ACCOUNT_FINGERPRINT_REQUIRED")
        store = (
            EnvFileEtradeCredentialStore()
            if urlsplit(reference.uri).scheme == "envfile"
            else MacOSKeychainEtradeCredentialStore()
        )
        session = EtradeReadOnlySession(
            reference=reference,
            store=store,
            transport=EtradeHTTPSGetTransport(),
            journal=PrivateDirectoryEtradeJournal(output),
            clock=SystemClock(),
        )
        accounts = session.discover_accounts()
        if not args.account_fingerprint:
            print(
                json.dumps(
                    {
                        "environment": environment.value,
                        "accounts": [
                            {
                                "fingerprint": account.fingerprint,
                                "cash_candidate": account.eligible_cash_candidate,
                                "currency_proven_usd": account.currency == "USD",
                            }
                            for account in accounts
                        ],
                        "next_step": "EXPLICIT_ACCOUNT_SELECTION_REQUIRED",
                        "trading_authorized": False,
                    },
                    sort_keys=True,
                )
            )
            return 0
        session.select_account(
            args.account_fingerprint,
            owner_declared_exclusive=args.declare_exclusive,
            allow_margin_privileges=args.allow_margin_privileges,
        )
        assert args.start_date is not None and args.end_date is not None
        capture = session.capture_account(EtradeCaptureBounds(args.start_date, args.end_date))
        print(json.dumps(capture.portable(), sort_keys=True))
        return 0 if capture.traversal_complete else 2
    except (EtradeReadError, OSError) as error:
        blocker = str(error) if isinstance(error, EtradeReadError) else "PRIVATE_OUTPUT_UNAVAILABLE"
        print(json.dumps({"blocker": blocker, "trading_authorized": False}, sort_keys=True))
        return 2
    finally:
        if session is not None:
            session.close()


if __name__ == "__main__":
    raise SystemExit(main())
