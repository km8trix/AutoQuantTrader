"""Real parent-death test driver for the explicit continuous fixture child."""

import sys
from pathlib import Path

from packages.application.continuous_process import (
    ContinuousProcessLimits,
    ContinuousProcessRequest,
    ContinuousProcessSupervisor,
)
from packages.application.personal_runtime import LocalInstanceGuard


def main():
    root = Path(sys.argv[1])
    request = ContinuousProcessRequest(
        "fixture-account",
        "orphan",
        root / "config.json",
        limits=ContinuousProcessLimits(wall_seconds=8, cpu_seconds=5),
    )
    with LocalInstanceGuard(root / "instance.lock") as guard:
        outcome = ContinuousProcessSupervisor(artifact_directory=root)._run_fixture_for_test(
            request,
            lock_descriptor=guard.fileno(),
            stop_requested=lambda: False,
            fence_is_current=lambda: True,
        )
    return 0 if outcome.status == "completed" else 3


if __name__ == "__main__":
    raise SystemExit(main())
