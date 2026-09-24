"""Run the explicit foundation suite with no ambient operational configuration."""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

_REGRESSIONS = [
    "config",
    "canonical",
    "accounting",
    "ledger_reducer",
    "account_projection",
    "corporate_action_ledger",
    "settlement_ledger",
    "order_reducer",
    "replay",
    "strategy_replay",
    "portfolio_intent_batches",
    "simulated_broker",
    "simulation_horizon",
    "backtest_report",
    "golden_runner",
    "causal_engine",
    "daily_risk",
    "daily_reference",
    "daily_target_conversion",
    "run_report",
    "feature_replay",
    "feature_target_replay",
    "batch_risk",
    "risk_and_execution",
    "submission_attempt",
    "attempt_resolved_fingerprint",
    "unknown_submission_recovery",
    "account_coordinator",
    "trusted_time",
    "trusted_time_monitor",
    "reservation_lifecycle",
    "operational_control",
    "etrade",
    "etrade_accounts",
    "etrade_oauth",
    "etrade_oauth_token_runtime",
    "etrade_owner_oauth",
    "etrade_owner_renewal",
    "tiingo_eod",
    "tiingo_eod_capture",
    "tiingo_eod_calendar",
    "account_reconciliation",
    "applied_reconciliation",
    "causal_checkpoint",
    "forward_capture_http",
    "journal_transaction_read",
    "observed_accounting",
    "reconciliation_evidence",
    "runtime_operating_evidence",
    "runtime_quote_marks",
    "runtime_source_boundaries",
    "runtime_unsent_release",
    "runtime_venue_registration",
]
_INTEGRATIONS = [
    "schema",
    "phase2_submission_attempt_persistence",
    "phase2_batch_risk_persistence",
    "phase2_backtest_workflow",
    "api",
    "postgres_risk_concurrency",
    "phase2_reservation_lifecycle_persistence",
    "phase5_operational_control_persistence",
    "account_observation_scope",
    "applied_reconciliation_store",
    "detached_control_rows",
    "runtime_assignment_publication",
    "runtime_attempt_source_binding",
    "runtime_historical_descriptor",
    "runtime_observed_source_binding",
    "runtime_original_clock",
    "sql_daily_runtime_risk",
    "sql_runtime_operating_evidence",
]
_POSTGRES_COORDINATOR_GATES = (
    "test_two_owners_racing_for_first_coordinator_lease_have_one_winner",
    "test_same_owner_conditional_generation_race_advances_only_once",
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres-url", help="Explicit disposable test database only")
    parser.add_argument("--shard-count", type=int, help="Explicit outer CI shard count (1-32)")
    parser.add_argument("--shard-index", type=int, help="Zero-based outer CI shard index")
    args = parser.parse_args()
    if (args.shard_count is None) != (args.shard_index is None):
        parser.error("--shard-count and --shard-index must be provided together")
    if args.shard_count is not None:
        if not 1 <= args.shard_count <= 32:
            parser.error("--shard-count must be between 1 and 32")
        if not 0 <= args.shard_index < args.shard_count:
            parser.error("--shard-index must be between 0 and --shard-count - 1")
    root = Path(__file__).resolve().parents[1]
    tests = {f"tests/unit/test_{name}.py" for name in _REGRESSIONS}
    tests.update(f"tests/integration/test_{name}.py" for name in _INTEGRATIONS)
    tests.update(
        f"tests/integration/test_phase2_postgres_exit.py::{name}"
        for name in _POSTGRES_COORDINATOR_GATES
    )
    for pattern in (
        "test_personal_*.py",
        "test_research_dataset*.py",
        "test_research_*.py",
        "test_retained_research_*.py",
        "test_etrade_readonly*.py",
        "test_etrade_session*.py",
        "test_standard_clock.py",
        "test_continuous_*.py",
        "test_daily_*.py",
        "test_durable_journal*.py",
        "test_runtime_owner_*.py",
        "test_stateful_venue*.py",
        "test_venue_*.py",
    ):
        tests.update(str(path.relative_to(root)) for path in (root / "tests").rglob(pattern))
    missing = [name for name in tests if not (root / name.split("::", 1)[0]).is_file()]
    if missing:
        parser.error(f"missing regression files: {missing}")
    with tempfile.TemporaryDirectory(prefix="aqt-personal-tests-") as directory:
        env = {
            "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin",
            "PYTHONPATH": str(root),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "TMPDIR": directory,
            "TZ": "UTC",
        }
        command = [
            sys.executable,
            "-B",
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "--basetemp",
            str(Path(directory) / "pytest"),
            *sorted(tests),
        ]
        if args.postgres_url:
            command.extend(["--aqt-test-postgres-url", args.postgres_url])
        if args.shard_count is not None:
            command.extend(
                [
                    "--aqt-shard-count",
                    str(args.shard_count),
                    "--aqt-shard-index",
                    str(args.shard_index),
                ]
            )
        return subprocess.run(command, cwd=root, env=env, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
