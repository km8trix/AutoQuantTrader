"""Explicit process-test child. Never selected by the production supervisor API."""

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from packages.application.continuous_process import enter_continuous_worker

_DESCENDANT_PROGRAM = """
import json
import os
import signal
import sys
import time

signal.signal(signal.SIGINT, signal.SIG_IGN)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
if sys.argv[2] == "close":
    os.close(1)
    os.close(2)
pending = sys.argv[1] + ".pending"
fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as stream:
    json.dump({"pid": os.getpid(), "pgid": os.getpgrp()}, stream)
os.replace(pending, sys.argv[1])
deadline = time.monotonic() + 3.0
while time.monotonic() < deadline:
    time.sleep(0.01)
os._exit(0)
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--process-request", type=Path, required=True)
    parser.add_argument("--process-receipt", type=Path, required=True)
    parser.add_argument("--instance-lock-fd", type=int, required=True)
    parser.add_argument("--parent-pid", type=int, required=True)
    parser.add_argument("--parent-death-fd", type=int, required=True)
    args = parser.parse_args()
    with enter_continuous_worker(
        process_request=args.process_request,
        process_receipt=args.process_receipt,
        instance_lock_fd=args.instance_lock_fd,
        parent_pid=args.parent_pid,
        parent_death_fd=args.parent_death_fd,
    ) as worker:
        config = json.loads(worker.request.configuration_path.read_text())
        Path(config["pid_file"]).write_text(str(os.getpid()))
        mode = worker.request.operation_id
        if mode in ("descendant_holds_output", "descendant_closes_output"):
            descendant_path = Path(config["pid_file"]).with_suffix(".descendant.json")
            # Same session/group, no inherited lock/death descriptors. This
            # process ignores TERM but self-expires even if supervision fails.
            descendant = subprocess.Popen(
                (
                    sys.executable,
                    "-B",
                    "-c",
                    _DESCENDANT_PROGRAM,
                    str(descendant_path),
                    "close" if mode == "descendant_closes_output" else "hold",
                ),
                stdin=subprocess.DEVNULL,
                close_fds=True,
            )
            ready_deadline = time.monotonic() + 0.5
            while not descendant_path.exists() and time.monotonic() < ready_deadline:
                time.sleep(0.01)
            assert descendant_path.exists() and descendant.returncode is None
            # Intentionally do not poll/wait: the leader now writes its normal
            # receipt and exits with its live descendant still in the group.
        if mode in ("early_eof_success", "early_eof_stall"):
            os.close(1)
            os.close(2)
            if mode == "early_eof_stall":
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                while True:
                    time.sleep(0.05)
            time.sleep(0.15)
        if mode.startswith("event_"):
            event = worker.stop_event
            assert type(event) is threading.Event and event is worker._cancelled
            assert worker.stop_event is event and not event.is_set()
            try:
                worker.stop_event = threading.Event()
            except AttributeError:
                pass
            else:
                raise AssertionError("the original Event property must be read-only")
            assert worker.stop_event is event
            if mode == "event_identity":
                assert not worker.stop_requested()
            elif mode in ("event_set", "event_signal"):
                if mode == "event_set":
                    event.set()
                else:
                    os.kill(os.getpid(), signal.SIGTERM)
                assert event.is_set() and worker.stop_requested()
            elif mode == "event_deadline":
                # Deterministic seam samples in this main thread only. The real
                # watcher, stored deadline and all resource limits are unchanged.
                main_thread = threading.current_thread()
                original_monotonic = time.monotonic
                deadline = worker.work_deadline_monotonic
                samples = [deadline - 1, deadline]
                sampled = []

                def modeled_monotonic():
                    if threading.current_thread() is main_thread:
                        value = samples.pop(0)
                        sampled.append(value)
                        return value
                    return original_monotonic()

                time.monotonic = modeled_monotonic
                try:
                    assert not worker.stop_requested() and not event.is_set()
                    assert worker.stop_requested() and event.is_set()
                    # Cancellation keeps its original clock-free short-circuit.
                    assert worker.stop_requested() and not samples
                    assert sampled == [deadline - 1, deadline]
                    assert worker.work_deadline_monotonic == deadline
                finally:
                    time.monotonic = original_monotonic
            else:
                raise AssertionError("unknown Event fixture mode")
            if mode != "event_identity":
                try:
                    worker.write_receipt(b'{"fixture":true,"trading_authorized":false}')
                except ValueError as exc:
                    assert str(exc) == "continuous worker receipt rejected"
                else:
                    raise AssertionError("a cancelled child must reject its receipt")
                assert worker.stop_event is event and not args.process_receipt.exists()
                Path(config["pid_file"]).with_suffix(".event-checked").write_text(mode)
                return 0
        if mode == "crash":
            os._exit(9)
        if mode == "no_receipt":
            return 0
        if mode == "symlink_receipt":
            os.symlink(worker.request.configuration_path, args.process_receipt)
            return 0
        if mode in ("stall", "orphan"):
            # Deliberately ignore cooperative cancellation and SIGTERM.
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            while True:
                time.sleep(0.05)
        if mode == "cpu":
            while True:
                pass
        if mode == "memory":
            allocation = bytearray(160 * 1024 * 1024)
            while allocation:
                time.sleep(0.05)
        if mode == "output":
            while True:
                os.write(1, b"x" * 4096)
        if mode == "oversized_receipt":
            worker.write_receipt(b"x" * (worker.request.limits.receipt_bytes + 1))
        if mode == "file_limit":
            # Sparse near-ceiling write exercises the OS cap without allocating
            # 256 MiB of fixture data. The supervisor must discard the artifact.
            fd = os.open(args.process_receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb", buffering=0) as stream:
                stream.seek(256 * 1024 * 1024 - 1)
                stream.write(b"x")
                stream.write(b"x")
        if mode == "environment":
            assert "CONTINUOUS_TEST_SECRET" not in os.environ
            assert "HOME" not in os.environ
            assert "ETRADE_PROD_CONSUMER_KEY" not in os.environ
        if mode == "pipe_eof":
            # Same parent PID stays alive, but EOF still forces child shutdown.
            while True:
                time.sleep(0.05)
        worker.write_receipt(b'{"fixture":true,"trading_authorized":false}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
