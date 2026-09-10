"""Add bounded personal research jobs, artifacts and immutable trial registration.

Revision ID: 0039_personal_research
Revises: 0038_phase4_etrade_oauth

These definitions are frozen migration DDL, independent of current application tables.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0039_personal_research"
down_revision: str | None = "0038_phase4_etrade_oauth"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

metadata = sa.MetaData(
    naming_convention={
        "ix": "ix_%(column_0_label)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s",
    }
)

research_objects_v2 = sa.Table(
    "research_objects_v2",
    metadata,
    sa.Column("object_sha256", sa.String(64), primary_key=True),
    sa.Column("byte_count", sa.BigInteger, nullable=False),
    sa.Column("codec_version", sa.String(32), nullable=False),
    sa.CheckConstraint("byte_count > 0 AND byte_count <= 67108864", name="research_object_size"),
    sa.CheckConstraint(
        "codec_version IN ('personal-record/1','personal-research-dataset-v1')",
        name="research_object_codec",
    ),
)

research_jobs_v2 = sa.Table(
    "research_jobs_v2",
    metadata,
    sa.Column("job_id", sa.String(64), primary_key=True),
    sa.Column("run_id", sa.String(68), nullable=False),
    sa.Column("owner_id", sa.String(128), nullable=False),
    sa.Column("idempotency_key", sa.String(128), nullable=False),
    sa.Column("trial_id", sa.String(128), nullable=False),
    sa.Column("request_sha256", sa.String(64), nullable=False),
    sa.Column("request_payload", sa.LargeBinary, nullable=False),
    sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
    sa.UniqueConstraint("owner_id", "idempotency_key"),
    sa.Index("ix_research_jobs_v2_owner_requested", "owner_id", "requested_at", "job_id"),
    sa.Index("ix_research_jobs_v2_run", "run_id"),
)

research_job_events_v2 = sa.Table(
    "research_job_events_v2",
    metadata,
    sa.Column("job_id", sa.String(64), sa.ForeignKey("research_jobs_v2.job_id"), primary_key=True),
    sa.Column("sequence", sa.Integer, primary_key=True),
    sa.Column("event_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("previous_event_sha256", sa.String(64)),
    sa.Column("kind", sa.String(24), nullable=False),
    sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("command_id", sa.String(64), unique=True),
    sa.Column("payload", sa.LargeBinary, nullable=False),
    sa.CheckConstraint("sequence >= 0 AND sequence < 4096", name="research_event_sequence"),
    sa.UniqueConstraint("job_id", "sequence", "event_sha256"),
)

research_job_heads_v2 = sa.Table(
    "research_job_heads_v2",
    metadata,
    sa.Column("job_id", sa.String(64), sa.ForeignKey("research_jobs_v2.job_id"), primary_key=True),
    sa.Column("last_sequence", sa.Integer, nullable=False),
    sa.Column("last_event_sha256", sa.String(64), nullable=False),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("attempt_count", sa.Integer, nullable=False),
    sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
    sa.Column("cancel_requested", sa.Boolean, nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(
        ["job_id", "last_sequence", "last_event_sha256"],
        [
            "research_job_events_v2.job_id",
            "research_job_events_v2.sequence",
            "research_job_events_v2.event_sha256",
        ],
    ),
    sa.CheckConstraint(
        "attempt_count >= 0 AND attempt_count <= 3", name="research_head_attempt_count"
    ),
    sa.CheckConstraint(
        "status IN ('queued','running','completed','incomplete','failed','cancelled')",
        name="research_head_status",
    ),
    sa.Index("ix_research_job_heads_v2_claimable", "status", "lease_expires_at", "job_id"),
)

research_publications_v2 = sa.Table(
    "research_publications_v2",
    metadata,
    sa.Column("job_id", sa.String(64), sa.ForeignKey("research_jobs_v2.job_id"), primary_key=True),
    sa.Column("run_id", sa.String(68), nullable=False),
    sa.Column("attempt_id", sa.String(64), nullable=False, unique=True),
    sa.Column("outcome", sa.String(16), nullable=False),
    sa.Column("result_sha256", sa.String(64), nullable=False),
    sa.Column("report_sha256", sa.String(64), nullable=False),
    sa.Column("artifact_sha256", sa.String(64), nullable=False),
    sa.Column(
        "object_sha256",
        sa.String(64),
        sa.ForeignKey("research_objects_v2.object_sha256"),
        nullable=False,
    ),
    sa.Column("publication_sha256", sa.String(64), nullable=False),
    sa.Column("payload", sa.LargeBinary, nullable=False),
    sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint(
        "outcome IN ('completed','incomplete')", name="research_publication_outcome"
    ),
)

RESEARCH_TABLES_V2 = (
    research_objects_v2,
    research_jobs_v2,
    research_job_events_v2,
    research_job_heads_v2,
    research_publications_v2,
)


research_catalog_entries = sa.Table(
    "research_catalog_entries",
    metadata,
    sa.Column("catalog_id", sa.String(72), primary_key=True),
    sa.Column("owner_id", sa.String(128), nullable=False),
    sa.Column("entry_sha256", sa.String(64), nullable=False),
    sa.Column("owner_binding_sha256", sa.String(64), nullable=False),
    sa.Column("payload_sha256", sa.String(64), nullable=False),
    sa.Column("payload", sa.LargeBinary, nullable=False),
    sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("length(payload) <= 4194304", name="research_catalog_payload_bound"),
    sa.Index("ix_research_catalog_owner", "owner_id", "catalog_id"),
)

research_launch_intents = sa.Table(
    "research_launch_intents",
    metadata,
    sa.Column("owner_id", sa.String(128), primary_key=True),
    sa.Column("idempotency_key", sa.String(128), primary_key=True),
    sa.Column(
        "job_id",
        sa.String(64),
        sa.ForeignKey("research_jobs_v2.job_id"),
        nullable=False,
        unique=True,
    ),
    sa.Column(
        "catalog_id",
        sa.String(72),
        sa.ForeignKey("research_catalog_entries.catalog_id"),
        nullable=False,
    ),
    sa.Column("cost_scenario_id", sa.String(32), nullable=False),
    sa.Column("request_json", sa.Text, nullable=False),
    sa.Column("request_sha256", sa.String(64), nullable=False),
    sa.CheckConstraint("length(request_json) <= 65536", name="research_launch_intent_bound"),
)

research_experiments = sa.Table(
    "research_experiments",
    metadata,
    sa.Column("experiment_id", sa.String(64), primary_key=True),
    sa.Column("owner_id", sa.String(128), nullable=False),
    sa.Column("idempotency_key", sa.String(128), nullable=False),
    sa.Column(
        "catalog_id",
        sa.String(72),
        sa.ForeignKey("research_catalog_entries.catalog_id"),
        nullable=False,
    ),
    sa.Column("registration_sha256", sa.String(64), nullable=False),
    sa.Column("payload_sha256", sa.String(64), nullable=False),
    sa.Column("payload", sa.LargeBinary, nullable=False),
    sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False),
    sa.UniqueConstraint("owner_id", "idempotency_key"),
    sa.CheckConstraint("length(payload) <= 4194304", name="research_experiment_payload_bound"),
    sa.Index("ix_research_experiments_owner", "owner_id", "registered_at"),
)

research_trial_jobs = sa.Table(
    "research_trial_jobs",
    metadata,
    sa.Column(
        "experiment_id",
        sa.String(64),
        sa.ForeignKey("research_experiments.experiment_id"),
        primary_key=True,
    ),
    sa.Column("ordinal", sa.Integer, primary_key=True),
    sa.Column("trial_id", sa.String(70), nullable=False, unique=True),
    sa.Column(
        "job_id",
        sa.String(64),
        sa.ForeignKey("research_jobs_v2.job_id"),
        nullable=False,
        unique=True,
    ),
    sa.CheckConstraint("ordinal >= 0 AND ordinal < 256", name="research_trial_ordinal"),
)

RESEARCH_CATALOG_TABLES = (
    research_catalog_entries,
    research_launch_intents,
    research_experiments,
    research_trial_jobs,
)


_TABLES = RESEARCH_TABLES_V2 + RESEARCH_CATALOG_TABLES


def upgrade() -> None:
    connection = op.get_bind()
    for table in _TABLES:
        table.create(connection, checkfirst=False)


def downgrade() -> None:
    if op.get_context().as_sql:
        raise RuntimeError("research downgrade requires online locked history verification")
    connection = op.get_bind()
    names = tuple(table.name for table in _TABLES)
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql("LOCK TABLE " + ", ".join(names) + " IN ACCESS EXCLUSIVE MODE")
    elif connection.dialect.name == "sqlite":
        # Even a zero-row write acquires SQLite's transaction write lock. It
        # protects the following emptiness check and DDL without changing facts.
        connection.exec_driver_sql(
            "UPDATE research_objects_v2 SET object_sha256 = object_sha256 WHERE 0"
        )
    else:
        raise RuntimeError("unsupported research downgrade database")
    if any(connection.execute(sa.select(table).limit(1)).first() is not None for table in _TABLES):
        raise RuntimeError("refusing to downgrade nonempty personal research history")
    for table in reversed(_TABLES):
        table.drop(connection, checkfirst=False)
