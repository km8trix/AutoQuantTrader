"""Add durable E*TRADE OAuth replay/session-head coordination.

Revision ID: 0038_phase4_etrade_oauth
Revises: 0037_phase3_fixture_worker
Create Date: 2026-08-25
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0038_phase4_etrade_oauth"
down_revision: str | None = "0037_phase3_fixture_worker"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_EVENTS = "phase4_etrade_oauth_session_events"
_HEADS = "phase4_etrade_oauth_session_heads"


def upgrade() -> None:
    op.create_table(
        _EVENTS,
        sa.Column("event_sha256", sa.String(64), nullable=False),
        sa.Column("scope_sha256", sa.String(64), nullable=False),
        sa.Column("sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("environment", sa.String(16), nullable=False),
        sa.Column("consumer_scope", sa.String(64), nullable=False),
        sa.Column("consumer_reference_version", sa.BigInteger(), nullable=False),
        sa.Column("consumer_reference_sha256", sa.String(64), nullable=False),
        sa.Column("endpoint_profile_sha256", sa.String(64), nullable=False),
        sa.Column("previous_event_sha256", sa.String(64), nullable=True),
        sa.Column("prior_session_state_sha256", sa.String(64), nullable=True),
        sa.Column("session_state_sha256", sa.String(64), nullable=False),
        sa.Column("session_payload", sa.Text(), nullable=False),
        sa.Column("session_payload_sha256", sa.String(64), nullable=False),
        sa.Column("replay_guard_sha256", sa.String(64), nullable=False),
        sa.Column("replay_fingerprint_sha256", sa.String(64), nullable=True),
        sa.Column("signing_scope_sha256", sa.String(64), nullable=True),
        sa.Column("signing_generation", sa.BigInteger(), nullable=True),
        sa.Column("signing_unix_seconds", sa.BigInteger(), nullable=True),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("event_sha256", name=op.f(f"pk_{_EVENTS}")),
        sa.ForeignKeyConstraint(
            ["previous_event_sha256"],
            [f"{_EVENTS}.event_sha256"],
            name="fk_phase4_etrade_oauth_events_predecessor",
        ),
        sa.UniqueConstraint(
            "scope_sha256",
            "sequence_number",
            name="uq_phase4_etrade_oauth_events_scope_sequence",
        ),
        sa.CheckConstraint(
            "environment IN ('sandbox', 'production') "
            "AND sequence_number > 0 "
            "AND consumer_reference_version > 0",
            name="phase4_etrade_oauth_event_scalar_shape",
        ),
        sa.CheckConstraint(
            "(sequence_number = 1 AND previous_event_sha256 IS NULL "
            "AND prior_session_state_sha256 IS NULL "
            "AND replay_fingerprint_sha256 IS NULL "
            "AND signing_scope_sha256 IS NULL "
            "AND signing_generation IS NULL "
            "AND signing_unix_seconds IS NULL) "
            "OR (sequence_number > 1 AND previous_event_sha256 IS NOT NULL "
            "AND prior_session_state_sha256 IS NOT NULL "
            "AND ((replay_fingerprint_sha256 IS NULL "
            "AND signing_scope_sha256 IS NULL "
            "AND signing_generation IS NULL "
            "AND signing_unix_seconds IS NULL) "
            "OR (replay_fingerprint_sha256 IS NOT NULL "
            "AND ((signing_scope_sha256 IS NULL "
            "AND signing_generation IS NULL "
            "AND signing_unix_seconds IS NULL) "
            "OR (signing_scope_sha256 IS NOT NULL "
            "AND signing_generation IS NOT NULL "
            "AND signing_generation > 0 "
            "AND signing_unix_seconds IS NOT NULL "
            "AND signing_unix_seconds > 0)))))",
            name="phase4_etrade_oauth_event_delta_shape",
        ),
        sa.CheckConstraint(
            "length(event_sha256) = 64 "
            "AND length(scope_sha256) = 64 "
            "AND length(consumer_scope) BETWEEN 1 AND 64 "
            "AND length(consumer_reference_sha256) = 64 "
            "AND length(endpoint_profile_sha256) = 64 "
            "AND (previous_event_sha256 IS NULL OR length(previous_event_sha256) = 64) "
            "AND (prior_session_state_sha256 IS NULL "
            "OR length(prior_session_state_sha256) = 64) "
            "AND length(session_state_sha256) = 64 "
            "AND length(session_payload) BETWEEN 2 AND 16384 "
            "AND length(session_payload_sha256) = 64 "
            "AND length(replay_guard_sha256) = 64 "
            "AND (replay_fingerprint_sha256 IS NULL "
            "OR length(replay_fingerprint_sha256) = 64) "
            "AND (signing_scope_sha256 IS NULL OR length(signing_scope_sha256) = 64) "
            "AND length(canonical_payload) BETWEEN 2 AND 32768",
            name="phase4_etrade_oauth_event_identity_shape",
        ),
    )
    op.create_index(
        "ix_phase4_etrade_oauth_events_scope_sequence",
        _EVENTS,
        ["scope_sha256", "sequence_number"],
        unique=False,
    )
    op.create_index(
        "ix_phase4_etrade_oauth_events_replay_fingerprint",
        _EVENTS,
        ["replay_fingerprint_sha256"],
        unique=True,
        sqlite_where=sa.text("replay_fingerprint_sha256 IS NOT NULL"),
        postgresql_where=sa.text("replay_fingerprint_sha256 IS NOT NULL"),
    )

    op.create_table(
        _HEADS,
        sa.Column("scope_sha256", sa.String(64), nullable=False),
        sa.Column("environment", sa.String(16), nullable=False),
        sa.Column("consumer_scope", sa.String(64), nullable=False),
        sa.Column("consumer_reference_version", sa.BigInteger(), nullable=False),
        sa.Column("consumer_reference_sha256", sa.String(64), nullable=False),
        sa.Column("latest_sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("latest_event_sha256", sa.String(64), nullable=False),
        sa.Column("current_session_state_sha256", sa.String(64), nullable=False),
        sa.Column("current_replay_guard_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("scope_sha256", name=op.f(f"pk_{_HEADS}")),
        sa.ForeignKeyConstraint(
            ["latest_event_sha256"],
            [f"{_EVENTS}.event_sha256"],
            name="fk_phase4_etrade_oauth_heads_latest_event",
        ),
        sa.UniqueConstraint("latest_event_sha256", name=op.f(f"uq_{_HEADS}_latest_event_sha256")),
        sa.UniqueConstraint(
            "environment",
            "consumer_scope",
            name="uq_phase4_etrade_oauth_heads_environment_consumer_scope",
        ),
        sa.CheckConstraint(
            "environment IN ('sandbox', 'production') "
            "AND consumer_reference_version > 0 "
            "AND latest_sequence_number > 0",
            name="phase4_etrade_oauth_head_scalar_shape",
        ),
        sa.CheckConstraint(
            "length(scope_sha256) = 64 "
            "AND length(consumer_scope) BETWEEN 1 AND 64 "
            "AND length(consumer_reference_sha256) = 64 "
            "AND length(latest_event_sha256) = 64 "
            "AND length(current_session_state_sha256) = 64 "
            "AND length(current_replay_guard_sha256) = 64",
            name="phase4_etrade_oauth_head_identity_shape",
        ),
    )


def downgrade() -> None:
    connection = op.get_bind()
    guarded_tables = (_HEADS, _EVENTS)
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            "LOCK TABLE " + ", ".join(guarded_tables) + " IN ACCESS EXCLUSIVE MODE"
        )
    counts = tuple(
        connection.scalar(sa.text(f"SELECT COUNT(*) FROM {table_name}"))
        for table_name in guarded_tables
    )
    if any(counts):
        raise RuntimeError("refusing to downgrade nonempty E*TRADE OAuth durable history")
    op.drop_table(_HEADS)
    op.drop_index("ix_phase4_etrade_oauth_events_replay_fingerprint", table_name=_EVENTS)
    op.drop_index("ix_phase4_etrade_oauth_events_scope_sequence", table_name=_EVENTS)
    op.drop_table(_EVENTS)
