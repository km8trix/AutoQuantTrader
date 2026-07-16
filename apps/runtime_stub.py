"""Signal-aware Phase 0 process stub shared by worker and trader entrypoints."""

from __future__ import annotations

import argparse
import json
import os
import signal
import threading

from apps.api.config import Environment, Settings
from packages.observability.logging import configure_logging


def run_stub(service: str) -> None:
    parser = argparse.ArgumentParser(description=f"AutoQuantTrader {service} Phase 0 stub")
    parser.add_argument("--once", action="store_true", help="report readiness and exit")
    arguments = parser.parse_args()
    requested_environment = Environment(os.getenv("AQT_ENVIRONMENT", Environment.LOCAL.value))
    if requested_environment is not Environment.LOCAL:
        payload = {
            "service": service,
            "mode": "stub",
            "status": "not_ready",
            "reason": "Phase 0 stub cannot run in paper/live environments",
        }
        print(json.dumps(payload, sort_keys=True), flush=True)
        raise SystemExit(2)
    settings = Settings.from_env()
    configure_logging(settings.log_level)
    payload = {"service": service, "mode": "stub", "status": "not_ready"}
    print(json.dumps(payload, sort_keys=True), flush=True)
    if arguments.once:
        return

    stopped = threading.Event()

    def request_stop(signum: int, frame: object) -> None:
        del signum, frame
        stopped.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    while not stopped.wait(timeout=1.0):
        pass
