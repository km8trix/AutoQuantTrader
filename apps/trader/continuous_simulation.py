"""Execute one supervised continuous-simulation operation from retained sources."""

from __future__ import annotations

import argparse
from pathlib import Path

from packages.application.continuous_process import enter_continuous_worker


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true", required=True)
    parser.add_argument("--process-request", required=True, type=Path)
    parser.add_argument("--process-receipt", required=True, type=Path)
    parser.add_argument("--instance-lock-fd", required=True, type=int)
    parser.add_argument("--parent-pid", required=True, type=int)
    parser.add_argument("--parent-death-fd", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        with enter_continuous_worker(
            process_request=args.process_request,
            process_receipt=args.process_receipt,
            instance_lock_fd=args.instance_lock_fd,
            parent_pid=args.parent_pid,
            parent_death_fd=args.parent_death_fd,
        ) as worker:
            # Resource limits and parent-death supervision precede importing
            # the actual SQL/source graph or decoding its bounded configuration.
            from apps.trader.continuous_process_lifecycle import ContinuousWorkerLifecycle
            from apps.trader.continuous_simulation_factory import run_continuous_operation

            if worker.stop_requested():
                return 70
            payload = run_continuous_operation(
                worker.request,
                stop_requested=worker.stop_requested,
                lifecycle=ContinuousWorkerLifecycle(worker),
            )
            worker.write_receipt(payload)
        return 0
    except Exception:
        # Provider data, local paths and private artifact contents never enter
        # stderr or a traceback; the supervisor records a bounded failure.
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
