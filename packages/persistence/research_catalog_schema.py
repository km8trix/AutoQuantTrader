"""Additive immutable catalog, launch intent and experiment registry tables."""

import sqlalchemy as sa

from packages.persistence.schema import metadata

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
