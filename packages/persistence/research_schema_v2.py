"""Additive W3 research tables; migration ownership remains with composition."""

import sqlalchemy as sa

from packages.persistence.schema import metadata

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
