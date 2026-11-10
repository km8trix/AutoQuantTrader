"""Run the conventional, always-halted local simulation foundation."""

from __future__ import annotations

import argparse
from pathlib import Path

from packages.adapters.standard_clock import StandardClock
from packages.application.personal_runtime import (
    DuplicateRuntimeError,
    PersonalRuntimeConfig,
    run_personal_runtime,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--instance-lock", required=True, type=Path, help="Private local lock path")
    parser.add_argument("--once", action="store_true", help="Sample and stop once")
    parser.add_argument("--poll-interval", type=float, default=1.0)
    args = parser.parse_args(argv)
    try:
        config = PersonalRuntimeConfig(
            instance_lock_path=args.instance_lock,
            poll_interval_seconds=args.poll_interval,
        )
        # This explicit model is usable only by the simulation configuration.
        # It makes no claim that an external source measured the host's drift.
        clock = StandardClock(simulated_health=True)
        return run_personal_runtime(config, clock=clock, once=args.once)
    except DuplicateRuntimeError:
        parser.exit(2, "Personal simulation is already running for this lock path.\n")
    except (ValueError, OSError):
        parser.exit(2, "Personal simulation configuration or lock path is invalid.\n")


if __name__ == "__main__":
    raise SystemExit(main())
