"""Add the Phase 2C durable fixture-research workflow.

Revision ID: 0008_phase2_research
Revises: 0007_phase2_durability
Create Date: 2026-07-20
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008_phase2_research"
down_revision: str | None = "0007_phase2_durability"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "phase2_strategy_versions",
        sa.Column("strategy_version_id", sa.String(length=64), nullable=False),
        sa.Column("strategy_id", sa.String(length=128), nullable=False),
        sa.Column("strategy_version", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=False),
        sa.Column("presentation_payload", sa.Text(), nullable=False),
        sa.Column("presentation_sha256", sa.String(length=64), nullable=False),
        sa.Column("implementation_sha256", sa.String(length=64), nullable=False),
        sa.Column("parameter_schema_sha256", sa.String(length=64), nullable=False),
        sa.Column("parameter_schema_payload", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "length(implementation_sha256) = 64 AND length(parameter_schema_sha256) = 64 AND length(presentation_sha256) = 64 AND length(semantic_sha256) = 64",
            name=op.f("ck_phase2_strategy_versions_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(parameter_schema_payload) BETWEEN 2 AND 65536 AND length(presentation_payload) BETWEEN 2 AND 65536 AND length(canonical_payload) BETWEEN 2 AND 131072",
            name=op.f("ck_phase2_strategy_versions_payload_sizes"),
        ),
        sa.PrimaryKeyConstraint("strategy_version_id", name=op.f("pk_phase2_strategy_versions")),
        sa.UniqueConstraint(
            "semantic_sha256", name=op.f("uq_phase2_strategy_versions_semantic_sha256")
        ),
        sa.UniqueConstraint(
            "presentation_sha256",
            name=op.f("uq_phase2_strategy_versions_presentation_sha256"),
        ),
        sa.UniqueConstraint(
            "strategy_version_id", "strategy_id", "strategy_version", name="strategy_identity"
        ),
        sa.UniqueConstraint("strategy_id", "strategy_version", name="strategy_version"),
    )
    op.create_table(
        "phase2_strategy_configurations",
        sa.Column("configuration_sha256", sa.String(length=64), nullable=False),
        sa.Column("strategy_version_id", sa.String(length=64), nullable=False),
        sa.Column("strategy_id", sa.String(length=128), nullable=False),
        sa.Column("strategy_version", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=False),
        sa.Column("parameters_payload", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "length(configuration_sha256) = 64 AND length(semantic_sha256) = 64",
            name=op.f("ck_phase2_strategy_configurations_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(parameters_payload) BETWEEN 2 AND 65536 AND length(canonical_payload) BETWEEN 2 AND 131072",
            name=op.f("ck_phase2_strategy_configurations_payload_sizes"),
        ),
        sa.ForeignKeyConstraint(
            ["strategy_version_id", "strategy_id", "strategy_version"],
            [
                "phase2_strategy_versions.strategy_version_id",
                "phase2_strategy_versions.strategy_id",
                "phase2_strategy_versions.strategy_version",
            ],
            name="strategy_version_identity",
        ),
        sa.PrimaryKeyConstraint(
            "configuration_sha256", name=op.f("pk_phase2_strategy_configurations")
        ),
        sa.UniqueConstraint(
            "configuration_sha256", "strategy_version_id", name="configuration_version"
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f("uq_phase2_strategy_configurations_semantic_sha256"),
        ),
    )
    op.create_table(
        "phase2_backtest_fixtures",
        sa.Column("fixture_sha256", sa.String(length=64), nullable=False),
        sa.Column("fixture_id", sa.String(length=128), nullable=False),
        sa.Column("fixture_version", sa.String(length=64), nullable=False),
        sa.Column("dataset_manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column("source_tape_sha256", sa.String(length=64), nullable=False),
        sa.Column("replay_run_id", sa.String(length=64), nullable=False),
        sa.Column("replay_manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column("replay_input_sha256", sa.String(length=64), nullable=False),
        sa.Column("replay_semantic_sha256", sa.String(length=64), nullable=False),
        sa.Column("strategy_version_id", sa.String(length=64), nullable=False),
        sa.Column("strategy_id", sa.String(length=128), nullable=False),
        sa.Column("strategy_version", sa.String(length=64), nullable=False),
        sa.Column("strategy_configuration_sha256", sa.String(length=64), nullable=False),
        sa.Column("benchmark_sha256", sa.String(length=64), nullable=False),
        sa.Column("cost_model_sha256", sa.String(length=64), nullable=False),
        sa.Column("fill_model_sha256", sa.String(length=64), nullable=False),
        sa.Column("metric_conventions_sha256", sa.String(length=64), nullable=False),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "replay_run_id = replay_manifest_sha256",
            name=op.f("ck_phase2_backtest_fixtures_content_addressed_replay"),
        ),
        sa.CheckConstraint(
            "length(fixture_sha256) = 64 AND length(dataset_manifest_sha256) = 64 AND length(source_tape_sha256) = 64 AND length(replay_run_id) = 64 AND length(replay_manifest_sha256) = 64 AND length(replay_input_sha256) = 64 AND length(replay_semantic_sha256) = 64 AND length(strategy_configuration_sha256) = 64 AND length(benchmark_sha256) = 64 AND length(cost_model_sha256) = 64 AND length(fill_model_sha256) = 64 AND length(metric_conventions_sha256) = 64 AND length(semantic_sha256) = 64",
            name=op.f("ck_phase2_backtest_fixtures_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 131072",
            name=op.f("ck_phase2_backtest_fixtures_payload_size"),
        ),
        sa.ForeignKeyConstraint(
            ["strategy_configuration_sha256", "strategy_version_id"],
            [
                "phase2_strategy_configurations.configuration_sha256",
                "phase2_strategy_configurations.strategy_version_id",
            ],
            name="strategy_configuration_identity",
        ),
        sa.ForeignKeyConstraint(
            ["strategy_version_id", "strategy_id", "strategy_version"],
            [
                "phase2_strategy_versions.strategy_version_id",
                "phase2_strategy_versions.strategy_id",
                "phase2_strategy_versions.strategy_version",
            ],
            name="strategy_version_identity",
        ),
        sa.PrimaryKeyConstraint("fixture_sha256", name=op.f("pk_phase2_backtest_fixtures")),
        sa.UniqueConstraint(
            "fixture_id",
            "fixture_version",
            "dataset_manifest_sha256",
            "replay_run_id",
            name="fixture_launch_identity",
        ),
        sa.UniqueConstraint("fixture_id", "fixture_version", name="fixture_version"),
        sa.UniqueConstraint(
            "semantic_sha256", name=op.f("uq_phase2_backtest_fixtures_semantic_sha256")
        ),
    )
    op.create_table(
        "phase2_backtest_jobs",
        sa.Column("job_id", sa.String(length=64), nullable=False),
        sa.Column("input_sha256", sa.String(length=64), nullable=False),
        sa.Column("fixture_id", sa.String(length=128), nullable=False),
        sa.Column("fixture_version", sa.String(length=64), nullable=False),
        sa.Column("dataset_manifest_id", sa.String(length=64), nullable=False),
        sa.Column("dataset_manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column("replay_run_id", sa.String(length=64), nullable=False),
        sa.Column("strategy_version_id", sa.String(length=64), nullable=False),
        sa.Column("strategy_id", sa.String(length=128), nullable=False),
        sa.Column("strategy_version", sa.String(length=64), nullable=False),
        sa.Column("strategy_configuration_sha256", sa.String(length=64), nullable=False),
        sa.Column("benchmark_sha256", sa.String(length=64), nullable=False),
        sa.Column("cost_model_sha256", sa.String(length=64), nullable=False),
        sa.Column("fill_model_sha256", sa.String(length=64), nullable=False),
        sa.Column("metric_conventions_sha256", sa.String(length=64), nullable=False),
        sa.Column("requested_by", sa.String(length=128), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "dataset_manifest_id = dataset_manifest_sha256",
            name=op.f("ck_phase2_backtest_jobs_content_addressed_dataset"),
        ),
        sa.CheckConstraint(
            "length(job_id) = 64 AND length(input_sha256) = 64 AND length(dataset_manifest_id) = 64 AND length(dataset_manifest_sha256) = 64 AND length(replay_run_id) = 64 AND length(strategy_configuration_sha256) = 64 AND length(benchmark_sha256) = 64 AND length(cost_model_sha256) = 64 AND length(fill_model_sha256) = 64 AND length(metric_conventions_sha256) = 64 AND length(semantic_sha256) = 64",
            name=op.f("ck_phase2_backtest_jobs_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 524288",
            name=op.f("ck_phase2_backtest_jobs_payload_size"),
        ),
        sa.ForeignKeyConstraint(
            [
                "fixture_id",
                "fixture_version",
                "dataset_manifest_sha256",
                "replay_run_id",
            ],
            [
                "phase2_backtest_fixtures.fixture_id",
                "phase2_backtest_fixtures.fixture_version",
                "phase2_backtest_fixtures.dataset_manifest_sha256",
                "phase2_backtest_fixtures.replay_run_id",
            ],
            name="fixture_launch_identity",
        ),
        sa.ForeignKeyConstraint(
            ["strategy_configuration_sha256", "strategy_version_id"],
            [
                "phase2_strategy_configurations.configuration_sha256",
                "phase2_strategy_configurations.strategy_version_id",
            ],
            name="strategy_configuration_identity",
        ),
        sa.ForeignKeyConstraint(
            ["strategy_version_id", "strategy_id", "strategy_version"],
            [
                "phase2_strategy_versions.strategy_version_id",
                "phase2_strategy_versions.strategy_id",
                "phase2_strategy_versions.strategy_version",
            ],
            name="strategy_version_identity",
        ),
        sa.PrimaryKeyConstraint("job_id", name=op.f("pk_phase2_backtest_jobs")),
        sa.UniqueConstraint("requested_by", "idempotency_key", name="operator_idempotency"),
        sa.UniqueConstraint(
            "semantic_sha256", name=op.f("uq_phase2_backtest_jobs_semantic_sha256")
        ),
    )
    op.create_index(
        "ix_phase2_backtest_jobs_requested_at",
        "phase2_backtest_jobs",
        ["requested_at"],
        unique=False,
    )
    op.create_table(
        "phase2_backtest_reports",
        sa.Column("report_artifact_sha256", sa.String(length=64), nullable=False),
        sa.Column("report_sha256", sa.String(length=64), nullable=False),
        sa.Column("account_id", sa.String(length=64), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("starting_equity", sa.Numeric(precision=28, scale=10), nullable=False),
        sa.Column("ending_equity", sa.Numeric(precision=28, scale=10), nullable=False),
        sa.Column("total_return", sa.Numeric(precision=28, scale=10), nullable=False),
        sa.Column("maximum_drawdown", sa.Numeric(precision=28, scale=10), nullable=False),
        sa.Column("turnover", sa.Numeric(precision=28, scale=10), nullable=False),
        sa.Column("trade_count", sa.Integer(), nullable=False),
        sa.Column("realized_pnl", sa.Numeric(precision=28, scale=10), nullable=False),
        sa.Column("unrealized_pnl", sa.Numeric(precision=28, scale=10), nullable=False),
        sa.Column("dividend_income", sa.Numeric(precision=28, scale=10), nullable=False),
        sa.Column("total_execution_costs", sa.Numeric(precision=28, scale=10), nullable=False),
        sa.Column("semantic_payload", sa.Text(), nullable=False),
        sa.Column("artifact_payload", sa.Text(), nullable=False),
        sa.Column("query_payload", sa.Text(), nullable=False),
        sa.Column("query_payload_sha256", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "length(currency) = 3 AND currency = upper(currency)",
            name=op.f("ck_phase2_backtest_reports_canonical_currency"),
        ),
        sa.CheckConstraint(
            "length(report_sha256) = 64 AND length(report_artifact_sha256) = 64 AND length(query_payload_sha256) = 64",
            name=op.f("ck_phase2_backtest_reports_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(semantic_payload) BETWEEN 2 AND 4194304 AND length(artifact_payload) BETWEEN 2 AND 131072 AND length(query_payload) BETWEEN 2 AND 4194304",
            name=op.f("ck_phase2_backtest_reports_payload_sizes"),
        ),
        sa.CheckConstraint(
            "period_end >= period_start AND generated_at >= period_end",
            name=op.f("ck_phase2_backtest_reports_valid_time_range"),
        ),
        sa.CheckConstraint(
            "starting_equity > 0 AND ending_equity > 0 AND maximum_drawdown >= 0 AND turnover >= 0 AND trade_count >= 0 AND total_execution_costs >= 0",
            name=op.f("ck_phase2_backtest_reports_valid_metrics"),
        ),
        sa.PrimaryKeyConstraint("report_artifact_sha256", name=op.f("pk_phase2_backtest_reports")),
        sa.UniqueConstraint(
            "report_sha256", "report_artifact_sha256", name="report_artifact_identity"
        ),
    )
    op.create_index(
        "ix_phase2_backtest_reports_generated_at",
        "phase2_backtest_reports",
        ["generated_at"],
        unique=False,
    )
    op.create_table(
        "phase2_backtest_run_manifests",
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column("job_id", sa.String(length=64), nullable=False),
        sa.Column("manifest_input_sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("report_sha256", sa.String(length=64), nullable=True),
        sa.Column("report_artifact_sha256", sa.String(length=64), nullable=True),
        sa.Column("terminal_reason_code", sa.String(length=64), nullable=True),
        sa.Column("terminal_reason_sha256", sa.String(length=64), nullable=True),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.CheckConstraint(
            "run_id = manifest_sha256",
            name=op.f("ck_phase2_backtest_run_manifests_content_addressed_run"),
        ),
        sa.CheckConstraint(
            "length(run_id) = 64 AND length(manifest_sha256) = 64 AND length(manifest_input_sha256) = 64 AND (report_sha256 IS NULL OR length(report_sha256) = 64) AND (report_artifact_sha256 IS NULL OR length(report_artifact_sha256) = 64) AND (terminal_reason_sha256 IS NULL OR length(terminal_reason_sha256) = 64)",
            name=op.f("ck_phase2_backtest_run_manifests_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 1048576",
            name=op.f("ck_phase2_backtest_run_manifests_payload_size"),
        ),
        sa.CheckConstraint(
            "(status = 'completed' AND report_sha256 IS NOT NULL AND report_artifact_sha256 IS NOT NULL AND terminal_reason_code IS NULL AND terminal_reason_sha256 IS NULL) OR (status IN ('failed', 'canceled') AND report_sha256 IS NULL AND report_artifact_sha256 IS NULL AND terminal_reason_code IS NOT NULL AND terminal_reason_sha256 IS NOT NULL)",
            name=op.f("ck_phase2_backtest_run_manifests_terminal_evidence_shape"),
        ),
        sa.CheckConstraint(
            "completed_at >= started_at",
            name=op.f("ck_phase2_backtest_run_manifests_valid_time_range"),
        ),
        sa.CheckConstraint(
            "status IN ('completed', 'failed', 'canceled')",
            name=op.f("ck_phase2_backtest_run_manifests_valid_status"),
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["phase2_backtest_jobs.job_id"],
            name=op.f("fk_phase2_backtest_run_manifests_job_id_phase2_backtest_jobs"),
        ),
        sa.ForeignKeyConstraint(
            ["report_sha256", "report_artifact_sha256"],
            [
                "phase2_backtest_reports.report_sha256",
                "phase2_backtest_reports.report_artifact_sha256",
            ],
            name="report_artifact",
        ),
        sa.PrimaryKeyConstraint("run_id", name=op.f("pk_phase2_backtest_run_manifests")),
        sa.UniqueConstraint("job_id", name=op.f("uq_phase2_backtest_run_manifests_job_id")),
        sa.UniqueConstraint(
            "manifest_sha256",
            name=op.f("uq_phase2_backtest_run_manifests_manifest_sha256"),
        ),
    )
    op.create_index(
        "ix_phase2_backtest_run_manifests_completed_at",
        "phase2_backtest_run_manifests",
        ["completed_at"],
        unique=False,
    )
    op.create_table(
        "phase2_backtest_job_events",
        sa.Column("event_sha256", sa.String(length=64), nullable=False),
        sa.Column("job_id", sa.String(length=64), nullable=False),
        sa.Column("sequence_number", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_id", sa.String(length=128), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("previous_event_sha256", sa.String(length=64), nullable=True),
        sa.Column("worker_id", sa.String(length=128), nullable=True),
        sa.Column("claim_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("run_manifest_sha256", sa.String(length=64), nullable=True),
        sa.Column("report_sha256", sa.String(length=64), nullable=True),
        sa.Column("report_artifact_sha256", sa.String(length=64), nullable=True),
        sa.Column("terminal_reason_code", sa.String(length=64), nullable=True),
        sa.Column("terminal_reason_sha256", sa.String(length=64), nullable=True),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.CheckConstraint(
            "length(event_sha256) = 64 AND (previous_event_sha256 IS NULL OR length(previous_event_sha256) = 64) AND (run_manifest_sha256 IS NULL OR length(run_manifest_sha256) = 64) AND (report_sha256 IS NULL OR length(report_sha256) = 64) AND (report_artifact_sha256 IS NULL OR length(report_artifact_sha256) = 64) AND (terminal_reason_sha256 IS NULL OR length(terminal_reason_sha256) = 64)",
            name=op.f("ck_phase2_backtest_job_events_hash_lengths"),
        ),
        sa.CheckConstraint(
            "(sequence_number = 0 AND status = 'queued' AND attempt_number = 0 AND previous_event_sha256 IS NULL) OR (sequence_number > 0 AND status <> 'queued' AND attempt_number > 0 AND previous_event_sha256 IS NOT NULL)",
            name=op.f("ck_phase2_backtest_job_events_initial_event_shape"),
        ),
        sa.CheckConstraint(
            "sequence_number >= 0",
            name=op.f("ck_phase2_backtest_job_events_non_negative_sequence"),
        ),
        sa.CheckConstraint(
            "attempt_number >= 0",
            name=op.f("ck_phase2_backtest_job_events_non_negative_attempt"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 262144",
            name=op.f("ck_phase2_backtest_job_events_payload_size"),
        ),
        sa.CheckConstraint(
            "(status = 'queued' AND worker_id IS NULL AND claim_expires_at IS NULL AND run_manifest_sha256 IS NULL AND report_sha256 IS NULL AND report_artifact_sha256 IS NULL AND terminal_reason_code IS NULL AND terminal_reason_sha256 IS NULL) OR (status = 'running' AND worker_id IS NOT NULL AND claim_expires_at > occurred_at AND run_manifest_sha256 IS NULL AND report_sha256 IS NULL AND report_artifact_sha256 IS NULL AND terminal_reason_code IS NULL AND terminal_reason_sha256 IS NULL) OR (status = 'completed' AND worker_id IS NULL AND claim_expires_at IS NULL AND run_manifest_sha256 IS NOT NULL AND report_sha256 IS NOT NULL AND report_artifact_sha256 IS NOT NULL AND terminal_reason_code IS NULL AND terminal_reason_sha256 IS NULL) OR (status IN ('failed', 'canceled') AND worker_id IS NULL AND claim_expires_at IS NULL AND run_manifest_sha256 IS NULL AND report_sha256 IS NULL AND report_artifact_sha256 IS NULL AND terminal_reason_code IS NOT NULL AND terminal_reason_sha256 IS NOT NULL)",
            name=op.f("ck_phase2_backtest_job_events_status_evidence_shape"),
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'canceled')",
            name=op.f("ck_phase2_backtest_job_events_valid_status"),
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["phase2_backtest_jobs.job_id"],
            name=op.f("fk_phase2_backtest_job_events_job_id_phase2_backtest_jobs"),
        ),
        sa.ForeignKeyConstraint(
            ["report_sha256", "report_artifact_sha256"],
            [
                "phase2_backtest_reports.report_sha256",
                "phase2_backtest_reports.report_artifact_sha256",
            ],
            name="report_artifact",
        ),
        sa.ForeignKeyConstraint(
            ["run_manifest_sha256"],
            ["phase2_backtest_run_manifests.manifest_sha256"],
            name="run_manifest",
        ),
        sa.PrimaryKeyConstraint("event_sha256", name=op.f("pk_phase2_backtest_job_events")),
        sa.UniqueConstraint("job_id", "sequence_number", "event_sha256", name="job_event_identity"),
        sa.UniqueConstraint("job_id", "sequence_number", name="job_sequence"),
    )
    op.create_index(
        "ix_phase2_backtest_job_events_status_occurred",
        "phase2_backtest_job_events",
        ["status", "occurred_at"],
        unique=False,
    )
    op.create_table(
        "phase2_backtest_job_heads",
        sa.Column("job_id", sa.String(length=64), nullable=False),
        sa.Column("last_sequence_number", sa.Integer(), nullable=False),
        sa.Column("last_event_sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("worker_id", sa.String(length=128), nullable=True),
        sa.Column("claim_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("run_manifest_sha256", sa.String(length=64), nullable=True),
        sa.Column("report_sha256", sa.String(length=64), nullable=True),
        sa.Column("report_artifact_sha256", sa.String(length=64), nullable=True),
        sa.Column("terminal_reason_code", sa.String(length=64), nullable=True),
        sa.Column("terminal_reason_sha256", sa.String(length=64), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(last_event_sha256) = 64",
            name=op.f("ck_phase2_backtest_job_heads_event_hash_length"),
        ),
        sa.CheckConstraint(
            "last_sequence_number >= 0 AND attempt_number >= 0",
            name=op.f("ck_phase2_backtest_job_heads_non_negative_versions"),
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'canceled')",
            name=op.f("ck_phase2_backtest_job_heads_valid_status"),
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["phase2_backtest_jobs.job_id"],
            name=op.f("fk_phase2_backtest_job_heads_job_id_phase2_backtest_jobs"),
        ),
        sa.ForeignKeyConstraint(
            ["job_id", "last_sequence_number", "last_event_sha256"],
            [
                "phase2_backtest_job_events.job_id",
                "phase2_backtest_job_events.sequence_number",
                "phase2_backtest_job_events.event_sha256",
            ],
            name="latest_event",
        ),
        sa.PrimaryKeyConstraint("job_id", name=op.f("pk_phase2_backtest_job_heads")),
    )
    op.create_index(
        "ix_phase2_backtest_job_heads_status_updated",
        "phase2_backtest_job_heads",
        ["status", "updated_at"],
        unique=False,
    )
    op.create_table(
        "phase2_backtest_audit_events",
        sa.Column("audit_sha256", sa.String(length=64), nullable=False),
        sa.Column("job_id", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("actor_id", sa.String(length=128), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("request_sha256", sa.String(length=64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "length(audit_sha256) = 64 AND length(request_sha256) = 64 AND length(semantic_sha256) = 64",
            name=op.f("ck_phase2_backtest_audit_events_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 131072",
            name=op.f("ck_phase2_backtest_audit_events_payload_size"),
        ),
        sa.CheckConstraint(
            "action = 'launch'", name=op.f("ck_phase2_backtest_audit_events_phase2_launch_only")
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["phase2_backtest_jobs.job_id"],
            name=op.f("fk_phase2_backtest_audit_events_job_id_phase2_backtest_jobs"),
        ),
        sa.PrimaryKeyConstraint("audit_sha256", name=op.f("pk_phase2_backtest_audit_events")),
        sa.UniqueConstraint("actor_id", "idempotency_key", name="actor_idempotency"),
        sa.UniqueConstraint(
            "semantic_sha256", name=op.f("uq_phase2_backtest_audit_events_semantic_sha256")
        ),
    )
    op.create_index(
        "ix_phase2_backtest_audit_events_occurred_at",
        "phase2_backtest_audit_events",
        ["occurred_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_phase2_backtest_audit_events_occurred_at",
        table_name="phase2_backtest_audit_events",
    )
    op.drop_table("phase2_backtest_audit_events")
    op.drop_index(
        "ix_phase2_backtest_job_heads_status_updated",
        table_name="phase2_backtest_job_heads",
    )
    op.drop_table("phase2_backtest_job_heads")
    op.drop_index(
        "ix_phase2_backtest_job_events_status_occurred",
        table_name="phase2_backtest_job_events",
    )
    op.drop_table("phase2_backtest_job_events")
    op.drop_index(
        "ix_phase2_backtest_run_manifests_completed_at",
        table_name="phase2_backtest_run_manifests",
    )
    op.drop_table("phase2_backtest_run_manifests")
    op.drop_index(
        "ix_phase2_backtest_reports_generated_at",
        table_name="phase2_backtest_reports",
    )
    op.drop_table("phase2_backtest_reports")
    op.drop_index(
        "ix_phase2_backtest_jobs_requested_at",
        table_name="phase2_backtest_jobs",
    )
    op.drop_table("phase2_backtest_jobs")
    op.drop_table("phase2_backtest_fixtures")
    op.drop_table("phase2_strategy_configurations")
    op.drop_table("phase2_strategy_versions")
