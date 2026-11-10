"""Bind trusted-time samples to conservative source uncertainty.

Revision ID: 0035_phase6_time_uncertainty
Revises: 0034_phase6_trusted_time
Create Date: 2026-07-31
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0035_phase6_time_uncertainty"
down_revision: str | None = "0034_phase6_trusted_time"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_EPOCH_TABLE = "phase6_trusted_time_epoch_registrations"
_EVALUATION_TABLE = "phase6_trusted_time_probe_evaluations"
_HEAD_TABLE = "phase6_trusted_time_host_heads"
_OLD_POLICY_SHA256 = "e2ed2efe97b6a13764fba36976916001eec074773f1f2fcf37f759c80e474944"
_NEW_POLICY_SHA256 = "64b826c9300e02a5f1543dfb5e1d7684e32317777fb12ab96b95da834f3f697c"
_EPOCH_IDENTITY = "phase6_trusted_time_epoch_identity"
_EVALUATION_IDENTITY = "phase6_trusted_time_eval_identity"
_SAMPLE_SHAPE = "phase6_trusted_time_eval_sample_shape"
_SAMPLE_ORDER = "phase6_trusted_time_eval_sample_order"


def _require_empty_history(action: str) -> None:
    connection = op.get_bind()
    guarded_tables = (_HEAD_TABLE, _EVALUATION_TABLE, _EPOCH_TABLE)
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            "LOCK TABLE " + ", ".join(guarded_tables) + " IN ACCESS EXCLUSIVE MODE"
        )
    counts = tuple(
        connection.scalar(sa.text(f"SELECT COUNT(*) FROM {table_name}"))
        for table_name in guarded_tables
    )
    if any(counts):
        raise RuntimeError(f"refusing to {action} nonempty trusted-time history")


def _epoch_identity(policy_sha256: str) -> str:
    return (
        "length(monitor_epoch_id) = 36 "
        "AND length(host_id) BETWEEN 1 AND 128 "
        "AND length(source_id) BETWEEN 1 AND 128 "
        "AND length(source_authority_sha256) = 64 "
        "AND length(policy_sha256) = 64 "
        f"AND policy_sha256 = '{policy_sha256}' "
        "AND length(semantic_sha256) = 64 "
        "AND (previous_monitor_epoch_id IS NULL "
        "OR length(previous_monitor_epoch_id) = 36) "
        "AND (previous_epoch_sha256 IS NULL "
        "OR length(previous_epoch_sha256) = 64) "
        "AND (previous_host_head_sha256 IS NULL "
        "OR length(previous_host_head_sha256) = 64)"
    )


def _evaluation_identity(policy_sha256: str) -> str:
    return (
        "length(evaluation_id) = 36 "
        "AND length(host_id) BETWEEN 1 AND 128 "
        "AND length(monitor_epoch_id) = 36 "
        "AND length(epoch_sha256) = 64 "
        "AND (previous_evaluation_id IS NULL "
        "OR length(previous_evaluation_id) = 36) "
        "AND (previous_evaluation_sha256 IS NULL "
        "OR length(previous_evaluation_sha256) = 64) "
        "AND (source_evidence_sha256 IS NULL "
        "OR length(source_evidence_sha256) = 64) "
        "AND (sample_sha256 IS NULL OR length(sample_sha256) = 64) "
        "AND (previous_state_sha256 IS NULL "
        "OR length(previous_state_sha256) = 64) "
        "AND length(policy_sha256) = 64 "
        f"AND policy_sha256 = '{policy_sha256}' "
        "AND (latest_sample_sha256 IS NULL "
        "OR length(latest_sample_sha256) = 64) "
        "AND length(state_sha256) = 64 "
        "AND length(evaluation_sha256) = 64 "
        "AND length(semantic_sha256) = 64"
    )


def _sample_shape(*, include_uncertainty: bool) -> str:
    recorded_uncertainty = (
        "AND source_uncertainty_milliseconds IS NOT NULL " if include_uncertainty else ""
    )
    absent_uncertainty = (
        "AND source_uncertainty_milliseconds IS NULL " if include_uncertainty else ""
    )
    return (
        "(probe_status = 'recorded' "
        "AND sample_sequence IS NOT NULL "
        "AND source_evidence_sha256 IS NOT NULL "
        "AND probe_started_at_utc IS NOT NULL "
        "AND probe_completed_at_utc IS NOT NULL "
        "AND trusted_at_utc IS NOT NULL "
        f"{recorded_uncertainty}"
        "AND probe_started_monotonic_ns IS NOT NULL "
        "AND probe_completed_monotonic_ns IS NOT NULL "
        "AND sample_canonical_payload IS NOT NULL "
        "AND sample_sha256 IS NOT NULL) "
        "OR (probe_status <> 'recorded' "
        "AND sample_sequence IS NULL "
        "AND source_evidence_sha256 IS NULL "
        "AND probe_started_at_utc IS NULL "
        "AND probe_completed_at_utc IS NULL "
        "AND trusted_at_utc IS NULL "
        f"{absent_uncertainty}"
        "AND probe_started_monotonic_ns IS NULL "
        "AND probe_completed_monotonic_ns IS NULL "
        "AND sample_canonical_payload IS NULL "
        "AND sample_sha256 IS NULL)"
    )


def _sample_order(*, include_uncertainty: bool) -> str:
    uncertainty_bound = (
        "AND (source_uncertainty_milliseconds IS NULL "
        "OR source_uncertainty_milliseconds BETWEEN 0 AND 100) "
        if include_uncertainty
        else ""
    )
    return (
        "(sample_sequence IS NULL OR sample_sequence > 0) "
        "AND (probe_started_monotonic_ns IS NULL "
        "OR probe_started_monotonic_ns >= 0) "
        "AND (probe_completed_monotonic_ns IS NULL "
        "OR probe_completed_monotonic_ns >= probe_started_monotonic_ns) "
        "AND (probe_started_at_utc IS NULL "
        "OR probe_started_at_utc <= probe_completed_at_utc) "
        f"{uncertainty_bound}"
        "AND (probe_completed_at_utc IS NULL "
        "OR probe_completed_at_utc <= evaluated_at_utc) "
        "AND (probe_completed_monotonic_ns IS NULL "
        "OR probe_completed_monotonic_ns <= evaluated_at_monotonic_ns)"
    )


def _replace_epoch_policy_constraint(policy_sha256: str) -> None:
    with op.batch_alter_table(_EPOCH_TABLE) as batch_op:
        batch_op.drop_constraint(_EPOCH_IDENTITY, type_="check")
        batch_op.create_check_constraint(
            _EPOCH_IDENTITY,
            _epoch_identity(policy_sha256),
        )


def _replace_evaluation_constraints(
    *,
    policy_sha256: str,
    add_uncertainty: bool,
) -> None:
    with op.batch_alter_table(_EVALUATION_TABLE) as batch_op:
        batch_op.drop_constraint(_SAMPLE_SHAPE, type_="check")
        batch_op.drop_constraint(_SAMPLE_ORDER, type_="check")
        batch_op.drop_constraint(_EVALUATION_IDENTITY, type_="check")
        if add_uncertainty:
            batch_op.add_column(
                sa.Column(
                    "source_uncertainty_milliseconds",
                    sa.Numeric(28, 10),
                    nullable=True,
                )
            )
        else:
            batch_op.drop_column("source_uncertainty_milliseconds")
        batch_op.create_check_constraint(
            _SAMPLE_SHAPE,
            _sample_shape(include_uncertainty=add_uncertainty),
        )
        batch_op.create_check_constraint(
            _SAMPLE_ORDER,
            _sample_order(include_uncertainty=add_uncertainty),
        )
        batch_op.create_check_constraint(
            _EVALUATION_IDENTITY,
            _evaluation_identity(policy_sha256),
        )


def upgrade() -> None:
    _require_empty_history("upgrade")
    _replace_epoch_policy_constraint(_NEW_POLICY_SHA256)
    _replace_evaluation_constraints(
        policy_sha256=_NEW_POLICY_SHA256,
        add_uncertainty=True,
    )


def downgrade() -> None:
    _require_empty_history("downgrade")
    _replace_evaluation_constraints(
        policy_sha256=_OLD_POLICY_SHA256,
        add_uncertainty=False,
    )
    _replace_epoch_policy_constraint(_OLD_POLICY_SHA256)
