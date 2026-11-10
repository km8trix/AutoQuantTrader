"""Phase 0 operational schema for the risk-to-ledger walking thread."""

import sqlalchemy as sa

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata = sa.MetaData(naming_convention=NAMING_CONVENTION)

risk_account_guards = sa.Table(
    "risk_account_guards",
    metadata,
    sa.Column("account_id", sa.String(64), primary_key=True),
    sa.Column("snapshot_version", sa.String(64), nullable=False),
    sa.Column("available_cash", sa.Numeric(28, 10), nullable=False),
    sa.Column("reserved_cash", sa.Numeric(28, 10), nullable=False, server_default="0"),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.UniqueConstraint(
        "account_id",
        "snapshot_version",
        name="uq_risk_account_guards_account_snapshot",
    ),
    sa.CheckConstraint(
        "available_cash >= 0",
        name="risk_account_guards_available_cash_non_negative",
    ),
    sa.CheckConstraint(
        "reserved_cash >= 0",
        name="risk_account_guards_reserved_cash_non_negative",
    ),
    sa.CheckConstraint(
        "reserved_cash <= available_cash",
        name="risk_account_guards_reserved_cash_within_capacity",
    ),
)

risk_decisions = sa.Table(
    "risk_decisions",
    metadata,
    sa.Column("decision_id", sa.String(36), primary_key=True),
    sa.Column("intent_id", sa.String(36), nullable=False, unique=True),
    sa.Column("intent_payload_hash", sa.String(64), nullable=False),
    sa.Column("policy_version", sa.String(32), nullable=False),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("reserved_cash", sa.Numeric(28, 10), nullable=False),
    sa.Column("rules", sa.JSON(), nullable=False),
    sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("reserved_cash >= 0", name="risk_decisions_reserved_cash_non_negative"),
    sa.CheckConstraint("expires_at > evaluated_at", name="risk_decisions_positive_ttl"),
)

risk_reservations = sa.Table(
    "risk_reservations",
    metadata,
    sa.Column(
        "decision_id",
        sa.String(36),
        sa.ForeignKey("risk_decisions.decision_id"),
        primary_key=True,
    ),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("snapshot_version", sa.String(64), nullable=False),
    sa.Column("cash_amount", sa.Numeric(28, 10), nullable=False),
    sa.Column("state", sa.String(16), nullable=False),
    sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(
        ["account_id", "snapshot_version"],
        ["risk_account_guards.account_id", "risk_account_guards.snapshot_version"],
        name="fk_risk_reservations_account_snapshot_risk_account_guards",
    ),
    sa.CheckConstraint(
        "cash_amount > 0",
        name="risk_reservations_cash_amount_positive",
    ),
    sa.CheckConstraint(
        "state IN ('approved', 'consumed', 'released')",
        name="risk_reservations_valid_state",
    ),
)
sa.Index(
    "ix_risk_reservations_account_state",
    risk_reservations.c.account_id,
    risk_reservations.c.state,
)
sa.Index("ix_risk_reservations_expires_at", risk_reservations.c.expires_at)

orders = sa.Table(
    "orders",
    metadata,
    sa.Column("order_id", sa.String(36), primary_key=True),
    sa.Column("client_order_id", sa.String(64), nullable=False, unique=True),
    sa.Column("intent_id", sa.String(36), nullable=False, unique=True),
    sa.Column(
        "risk_decision_id",
        sa.String(36),
        sa.ForeignKey("risk_decisions.decision_id"),
        nullable=False,
        unique=True,
    ),
    sa.Column("instrument_id", sa.String(64), nullable=False),
    sa.Column("symbol", sa.String(32), nullable=False),
    sa.Column("side", sa.String(8), nullable=False),
    sa.Column("quantity", sa.Numeric(28, 10), nullable=False),
    sa.Column("filled_quantity", sa.Numeric(28, 10), nullable=False, server_default="0"),
    sa.Column("activation_after_event_time", sa.DateTime(timezone=True), nullable=False),
    sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("status", sa.String(32), nullable=False),
    sa.CheckConstraint("quantity > 0", name="orders_quantity_positive"),
    sa.CheckConstraint("quantity = CAST(quantity AS BIGINT)", name="orders_quantity_whole_shares"),
    sa.CheckConstraint(
        "filled_quantity = CAST(filled_quantity AS BIGINT)",
        name="orders_filled_quantity_whole_shares",
    ),
    sa.CheckConstraint(
        "filled_quantity >= 0 AND filled_quantity <= quantity",
        name="orders_filled_quantity_valid",
    ),
)

submission_attempts = sa.Table(
    "submission_attempts",
    metadata,
    sa.Column("attempt_id", sa.String(36), primary_key=True),
    sa.Column(
        "decision_id",
        sa.String(36),
        sa.ForeignKey("risk_decisions.decision_id"),
        nullable=False,
        unique=True,
    ),
    sa.Column("intent_id", sa.String(36), nullable=False, unique=True),
    sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("state", sa.String(16), nullable=False),
    sa.Column(
        "order_id",
        sa.String(36),
        sa.ForeignKey("orders.order_id"),
        nullable=True,
        unique=True,
    ),
    sa.CheckConstraint(
        "state IN ('authorized', 'recorded')",
        name="submission_attempts_valid_state",
    ),
    sa.CheckConstraint(
        "(state = 'authorized' AND order_id IS NULL) "
        "OR (state = 'recorded' AND order_id IS NOT NULL)",
        name="submission_attempts_state_matches_order",
    ),
)

fills = sa.Table(
    "fills",
    metadata,
    sa.Column("fill_id", sa.String(36), primary_key=True),
    sa.Column(
        "order_id", sa.String(36), sa.ForeignKey("orders.order_id"), nullable=False, index=True
    ),
    sa.Column("instrument_id", sa.String(64), nullable=False),
    sa.Column("symbol", sa.String(32), nullable=False),
    sa.Column("side", sa.String(8), nullable=False),
    sa.Column("quantity", sa.Numeric(28, 10), nullable=False),
    sa.Column("price", sa.Numeric(28, 10), nullable=False),
    sa.Column("fee", sa.Numeric(28, 10), nullable=False),
    sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("quantity > 0", name="fills_quantity_positive"),
    sa.CheckConstraint("quantity = CAST(quantity AS BIGINT)", name="fills_quantity_whole_shares"),
    sa.CheckConstraint("price > 0", name="fills_price_positive"),
    sa.CheckConstraint("fee >= 0", name="fills_fee_non_negative"),
)

ledger_entries = sa.Table(
    "ledger_entries",
    metadata,
    sa.Column("entry_id", sa.String(36), primary_key=True),
    sa.Column("event_type", sa.String(32), nullable=False),
    sa.Column("reference_id", sa.String(64), nullable=False, unique=True),
    sa.Column("posted_at", sa.DateTime(timezone=True), nullable=False),
)

ledger_postings = sa.Table(
    "ledger_postings",
    metadata,
    sa.Column(
        "posting_id",
        sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
        primary_key=True,
        autoincrement=True,
    ),
    sa.Column(
        "entry_id",
        sa.String(36),
        sa.ForeignKey("ledger_entries.entry_id"),
        nullable=False,
        index=True,
    ),
    sa.Column("line_number", sa.Integer(), nullable=False),
    sa.Column("account", sa.String(128), nullable=False),
    sa.Column("currency", sa.String(3), nullable=False),
    sa.Column("debit", sa.Numeric(28, 10), nullable=False, server_default="0"),
    sa.Column("credit", sa.Numeric(28, 10), nullable=False, server_default="0"),
    sa.Column("units_delta", sa.Numeric(28, 10), nullable=False, server_default="0"),
    sa.Column("instrument_id", sa.String(64), nullable=True),
    sa.UniqueConstraint("entry_id", "line_number", name="uq_ledger_postings_entry_line"),
    sa.CheckConstraint("debit >= 0 AND credit >= 0", name="ledger_postings_non_negative"),
    sa.CheckConstraint(
        "(debit > 0 AND credit = 0) OR (credit > 0 AND debit = 0)",
        name="ledger_postings_single_side",
    ),
)

# Phase 1A point-in-time market-data catalog. Historical payloads remain in the
# immutable object store; PostgreSQL publishes only identity, lineage, manifest,
# and quality metadata.
market_data_sources = sa.Table(
    "market_data_sources",
    metadata,
    sa.Column("source_id", sa.String(64), primary_key=True),
    sa.Column("name", sa.String(128), nullable=False),
    sa.Column("provider", sa.String(64), nullable=False),
    sa.Column("dataset", sa.String(64), nullable=False),
    sa.Column("feed", sa.String(64), nullable=False),
    sa.Column("kind", sa.String(32), nullable=False),
    sa.Column("licensed", sa.Boolean(), nullable=False),
    sa.Column("detail", sa.String(512), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint(
        "kind IN ('synthetic_fixture', 'recorded_fixture', 'vendor')",
        name="market_data_sources_valid_kind",
    ),
)

market_data_entitlements = sa.Table(
    "market_data_entitlements",
    metadata,
    sa.Column("entitlement_id", sa.String(64), primary_key=True),
    sa.Column(
        "source_id",
        sa.String(64),
        sa.ForeignKey("market_data_sources.source_id"),
        nullable=False,
        index=True,
    ),
    sa.Column("status", sa.String(24), nullable=False),
    sa.Column("scope", sa.String(256), nullable=False),
    sa.Column("effective_from", sa.DateTime(timezone=True), nullable=False),
    sa.Column("effective_to", sa.DateTime(timezone=True), nullable=True),
    sa.Column("terms_digest", sa.String(64), nullable=False),
    sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint(
        "status IN ('fixture_only', 'active', 'expired', 'revoked')",
        name="market_data_entitlements_valid_status",
    ),
    sa.CheckConstraint(
        "effective_to IS NULL OR effective_to > effective_from",
        name="market_data_entitlements_valid_range",
    ),
    sa.CheckConstraint(
        "length(terms_digest) = 64",
        name="market_data_entitlements_digest_length",
    ),
)

market_data_admission_profiles = sa.Table(
    "market_data_admission_profiles",
    metadata,
    sa.Column("profile_id", sa.String(64), primary_key=True),
    sa.Column(
        "source_id",
        sa.String(64),
        sa.ForeignKey("market_data_sources.source_id"),
        nullable=False,
        index=True,
    ),
    sa.Column("name", sa.String(128), nullable=False),
    sa.Column("adapter_type", sa.String(64), nullable=False),
    sa.Column("identifier_authority", sa.String(128), nullable=False),
    sa.Column(
        "universe_version",
        sa.String(64),
        sa.ForeignKey("universe_versions.universe_version"),
        nullable=False,
    ),
    sa.Column(
        "calendar_version",
        sa.String(64),
        sa.ForeignKey("calendar_versions.calendar_version"),
        nullable=False,
    ),
    sa.Column(
        "corporate_action_version",
        sa.String(64),
        sa.ForeignKey("corporate_action_sets.corporate_action_version"),
        nullable=False,
    ),
    sa.Column("coverage_start", sa.DateTime(timezone=True), nullable=False),
    sa.Column("coverage_end", sa.DateTime(timezone=True), nullable=False),
    sa.Column("required_symbols", sa.JSON(), nullable=False),
    sa.Column("required_checks", sa.JSON(), nullable=False),
    sa.Column("specification_digest", sa.String(64), nullable=False, unique=True),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint(
        "coverage_end >= coverage_start",
        name="market_data_admission_profiles_valid_coverage",
    ),
    sa.CheckConstraint(
        "length(profile_id) = 64 AND length(specification_digest) = 64",
        name="market_data_admission_profiles_hash_lengths",
    ),
)

market_data_admission_runs = sa.Table(
    "market_data_admission_runs",
    metadata,
    sa.Column("admission_run_id", sa.String(64), primary_key=True),
    sa.Column(
        "profile_id",
        sa.String(64),
        sa.ForeignKey("market_data_admission_profiles.profile_id"),
        nullable=False,
        index=True,
    ),
    sa.Column(
        "source_id",
        sa.String(64),
        sa.ForeignKey("market_data_sources.source_id"),
        nullable=False,
        index=True,
    ),
    sa.Column(
        "manifest_id",
        sa.String(64),
        sa.ForeignKey("dataset_manifests.manifest_id"),
        nullable=True,
    ),
    sa.Column("status", sa.String(24), nullable=False),
    sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("executed_by", sa.String(128), nullable=False),
    sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("reviewed_by", sa.String(128), nullable=True),
    sa.Column("review_decision", sa.String(16), nullable=True),
    sa.Column("evidence_digest", sa.String(64), nullable=False),
    sa.Column("report_digest", sa.String(64), nullable=False, unique=True),
    sa.Column("passed_check_count", sa.Integer(), nullable=False),
    sa.Column("failed_check_count", sa.Integer(), nullable=False),
    sa.Column("pending_check_count", sa.Integer(), nullable=False),
    sa.Column("detail", sa.String(512), nullable=False),
    sa.CheckConstraint(
        "status IN ('blocked', 'review_pending', 'admitted', 'rejected')",
        name="market_data_admission_runs_valid_status",
    ),
    sa.CheckConstraint(
        "review_decision IS NULL OR review_decision IN ('approved', 'rejected')",
        name="market_data_admission_runs_valid_review_decision",
    ),
    sa.CheckConstraint(
        "(reviewed_at IS NULL AND reviewed_by IS NULL AND review_decision IS NULL) OR "
        "(reviewed_at IS NOT NULL AND reviewed_by IS NOT NULL AND review_decision IS NOT NULL)",
        name="market_data_admission_runs_complete_review",
    ),
    sa.CheckConstraint(
        "status <> 'admitted' OR review_decision = 'approved'",
        name="market_data_admission_runs_reviewed_final_status",
    ),
    sa.CheckConstraint(
        "passed_check_count >= 0 AND failed_check_count >= 0 AND pending_check_count >= 0",
        name="market_data_admission_runs_non_negative_counts",
    ),
    sa.CheckConstraint(
        "length(evidence_digest) = 64 AND length(report_digest) = 64",
        name="market_data_admission_runs_hash_lengths",
    ),
)

market_data_admission_checks = sa.Table(
    "market_data_admission_checks",
    metadata,
    sa.Column(
        "admission_run_id",
        sa.String(64),
        sa.ForeignKey("market_data_admission_runs.admission_run_id"),
        primary_key=True,
    ),
    sa.Column("code", sa.String(64), primary_key=True),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("evidence_digest", sa.String(64), nullable=True),
    sa.Column("detail", sa.String(512), nullable=False),
    sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint(
        "status IN ('passed', 'failed', 'pending')",
        name="market_data_admission_checks_valid_status",
    ),
    sa.CheckConstraint(
        "status <> 'passed' OR evidence_digest IS NOT NULL",
        name="market_data_admission_checks_passed_evidence",
    ),
    sa.CheckConstraint(
        "evidence_digest IS NULL OR length(evidence_digest) = 64",
        name="market_data_admission_checks_digest_length",
    ),
)

instruments = sa.Table(
    "instruments",
    metadata,
    sa.Column("instrument_id", sa.String(64), primary_key=True),
    sa.Column("name", sa.String(160), nullable=False),
    sa.Column("asset_class", sa.String(24), nullable=False),
    sa.Column("currency", sa.String(3), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint(
        "asset_class IN ('etf', 'equity')",
        name="instruments_valid_asset_class",
    ),
)

instrument_identifiers = sa.Table(
    "instrument_identifiers",
    metadata,
    sa.Column("identifier_id", sa.String(64), primary_key=True),
    sa.Column(
        "instrument_id",
        sa.String(64),
        sa.ForeignKey("instruments.instrument_id"),
        nullable=False,
        index=True,
    ),
    sa.Column(
        "source_id",
        sa.String(64),
        sa.ForeignKey("market_data_sources.source_id"),
        nullable=False,
    ),
    sa.Column("symbol", sa.String(32), nullable=False),
    sa.Column("venue", sa.String(16), nullable=False),
    sa.Column("effective_from", sa.DateTime(timezone=True), nullable=False),
    sa.Column("effective_to", sa.DateTime(timezone=True), nullable=True),
    sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("tradable", sa.Boolean(), nullable=False),
    sa.Column("revision", sa.Integer(), nullable=False),
    sa.UniqueConstraint(
        "source_id",
        "symbol",
        "venue",
        "effective_from",
        "revision",
        name="uq_instrument_identifiers_source_symbol_effective_revision",
    ),
    sa.CheckConstraint(
        "effective_to IS NULL OR effective_to > effective_from",
        name="instrument_identifiers_valid_range",
    ),
    sa.CheckConstraint("revision >= 1", name="instrument_identifiers_positive_revision"),
)

universe_versions = sa.Table(
    "universe_versions",
    metadata,
    sa.Column("universe_version", sa.String(64), primary_key=True),
    sa.Column("name", sa.String(128), nullable=False),
    sa.Column("effective_as_of", sa.DateTime(timezone=True), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("content_hash", sa.String(64), nullable=False, unique=True),
    sa.Column("content_hash_version", sa.String(32), nullable=False),
    sa.CheckConstraint("length(content_hash) = 64", name="universe_versions_hash_length"),
)

universe_memberships = sa.Table(
    "universe_memberships",
    metadata,
    sa.Column(
        "universe_version",
        sa.String(64),
        sa.ForeignKey("universe_versions.universe_version"),
        primary_key=True,
    ),
    sa.Column(
        "instrument_id",
        sa.String(64),
        sa.ForeignKey("instruments.instrument_id"),
        primary_key=True,
    ),
    sa.Column("included_from", sa.DateTime(timezone=True), nullable=False),
    sa.Column("included_to", sa.DateTime(timezone=True), nullable=True),
    sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint(
        "included_to IS NULL OR included_to > included_from",
        name="universe_memberships_valid_range",
    ),
)

calendar_versions = sa.Table(
    "calendar_versions",
    metadata,
    sa.Column("calendar_version", sa.String(64), primary_key=True),
    sa.Column("name", sa.String(64), nullable=False),
    sa.Column("timezone", sa.String(64), nullable=False),
    sa.Column("tzdata_version", sa.String(32), nullable=False),
    sa.Column("content_hash", sa.String(64), nullable=False, unique=True),
    sa.Column("content_hash_version", sa.String(32), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("length(content_hash) = 64", name="calendar_versions_hash_length"),
)

calendar_sessions = sa.Table(
    "calendar_sessions",
    metadata,
    sa.Column(
        "calendar_version",
        sa.String(64),
        sa.ForeignKey("calendar_versions.calendar_version"),
        primary_key=True,
    ),
    sa.Column("session_label", sa.String(10), primary_key=True),
    sa.Column("opens_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("closes_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("half_day", sa.Boolean(), nullable=False),
    sa.CheckConstraint("closes_at > opens_at", name="calendar_sessions_positive_duration"),
)

corporate_action_revisions = sa.Table(
    "corporate_action_revisions",
    metadata,
    sa.Column("action_revision_id", sa.String(64), primary_key=True),
    sa.Column("action_id", sa.String(64), nullable=False),
    sa.Column(
        "instrument_id",
        sa.String(64),
        sa.ForeignKey("instruments.instrument_id"),
        nullable=False,
        index=True,
    ),
    sa.Column("action_type", sa.String(24), nullable=False),
    sa.Column("revision", sa.Integer(), nullable=False),
    sa.Column("announced_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("terms", sa.JSON(), nullable=False),
    sa.Column("payload_hash", sa.String(64), nullable=False),
    sa.UniqueConstraint(
        "action_id",
        "revision",
        name="uq_corporate_action_revisions_action_revision",
    ),
    sa.CheckConstraint(
        "action_type IN ('split', 'cash_dividend', 'merger', 'symbol_change', 'delisting')",
        name="corporate_action_revisions_valid_type",
    ),
    sa.CheckConstraint("revision >= 1", name="corporate_action_revisions_positive_revision"),
    sa.CheckConstraint(
        "length(payload_hash) = 64",
        name="corporate_action_revisions_hash_length",
    ),
)

ingestion_jobs = sa.Table(
    "ingestion_jobs",
    metadata,
    sa.Column("job_id", sa.String(64), primary_key=True),
    sa.Column("idempotency_key", sa.String(64), nullable=False, unique=True),
    sa.Column(
        "source_id",
        sa.String(64),
        sa.ForeignKey("market_data_sources.source_id"),
        nullable=False,
        index=True,
    ),
    sa.Column("source_checksum", sa.String(64), nullable=False),
    sa.Column("status", sa.String(32), nullable=False),
    sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("source_record_count", sa.Integer(), nullable=False),
    sa.Column("normalized_record_count", sa.Integer(), nullable=False),
    sa.Column("published_partition_count", sa.Integer(), nullable=False),
    sa.Column("quarantined_record_count", sa.Integer(), nullable=False),
    sa.Column("error_message", sa.String(512), nullable=True),
    sa.CheckConstraint(
        "status IN ('completed', 'completed_with_issues', 'failed')",
        name="ingestion_jobs_valid_status",
    ),
    sa.CheckConstraint(
        "source_record_count >= 0 AND normalized_record_count >= 0 "
        "AND published_partition_count >= 0 AND quarantined_record_count >= 0",
        name="ingestion_jobs_non_negative_counts",
    ),
    sa.CheckConstraint(
        "length(idempotency_key) = 64 AND length(source_checksum) = 64",
        name="ingestion_jobs_hash_lengths",
    ),
)

data_objects = sa.Table(
    "data_objects",
    metadata,
    sa.Column("object_id", sa.String(64), primary_key=True),
    sa.Column("object_key", sa.String(256), nullable=False, unique=True),
    sa.Column("byte_checksum", sa.String(64), nullable=False, unique=True),
    sa.Column("semantic_checksum", sa.String(64), nullable=False),
    sa.Column("semantic_checksum_version", sa.String(32), nullable=False),
    sa.Column("format", sa.String(16), nullable=False),
    sa.Column("size_bytes", sa.BigInteger(), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint(
        "length(object_id) = 64 AND length(byte_checksum) = 64 AND length(semantic_checksum) = 64",
        name="data_objects_hash_lengths",
    ),
    sa.CheckConstraint("size_bytes > 0", name="data_objects_positive_size"),
    sa.CheckConstraint("format = 'parquet'", name="data_objects_parquet_only"),
)

dataset_partitions = sa.Table(
    "dataset_partitions",
    metadata,
    sa.Column("partition_id", sa.String(64), primary_key=True),
    sa.Column(
        "object_id",
        sa.String(64),
        sa.ForeignKey("data_objects.object_id"),
        nullable=False,
    ),
    sa.Column(
        "job_id",
        sa.String(64),
        sa.ForeignKey("ingestion_jobs.job_id"),
        nullable=False,
        index=True,
    ),
    sa.Column(
        "source_id",
        sa.String(64),
        sa.ForeignKey("market_data_sources.source_id"),
        nullable=False,
    ),
    sa.Column("layer", sa.String(16), nullable=False),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("schema_version", sa.String(32), nullable=False),
    sa.Column("price_basis", sa.String(16), nullable=False),
    sa.Column("row_count", sa.Integer(), nullable=False),
    sa.Column("event_time_start", sa.DateTime(timezone=True), nullable=False),
    sa.Column("event_time_end", sa.DateTime(timezone=True), nullable=False),
    sa.Column("available_at_start", sa.DateTime(timezone=True), nullable=False),
    sa.Column("available_at_end", sa.DateTime(timezone=True), nullable=False),
    sa.Column("semantic_checksum", sa.String(64), nullable=False),
    sa.Column("semantic_checksum_version", sa.String(32), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.UniqueConstraint(
        "layer",
        "semantic_checksum",
        name="uq_dataset_partitions_layer_semantic_checksum",
    ),
    sa.CheckConstraint("layer IN ('raw', 'normalized')", name="dataset_partitions_valid_layer"),
    sa.CheckConstraint(
        "status IN ('published', 'quarantined')",
        name="dataset_partitions_valid_status",
    ),
    sa.CheckConstraint("price_basis = 'raw'", name="dataset_partitions_raw_price_only"),
    sa.CheckConstraint("row_count > 0", name="dataset_partitions_positive_rows"),
    sa.CheckConstraint(
        "event_time_end >= event_time_start AND available_at_end >= available_at_start",
        name="dataset_partitions_valid_ranges",
    ),
    sa.CheckConstraint(
        "length(partition_id) = 64 AND length(semantic_checksum) = 64",
        name="dataset_partitions_hash_lengths",
    ),
)

data_quality_runs = sa.Table(
    "data_quality_runs",
    metadata,
    sa.Column("quality_run_id", sa.String(64), primary_key=True),
    sa.Column(
        "job_id",
        sa.String(64),
        sa.ForeignKey("ingestion_jobs.job_id"),
        nullable=False,
        unique=True,
    ),
    sa.Column("ruleset_version", sa.String(32), nullable=False),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint(
        "status IN ('passed', 'warning', 'failed')",
        name="data_quality_runs_valid_status",
    ),
)

data_quality_issues = sa.Table(
    "data_quality_issues",
    metadata,
    sa.Column("issue_id", sa.String(64), primary_key=True),
    sa.Column(
        "quality_run_id",
        sa.String(64),
        sa.ForeignKey("data_quality_runs.quality_run_id"),
        nullable=False,
        index=True,
    ),
    sa.Column("partition_id", sa.String(64), nullable=True),
    sa.Column("instrument_id", sa.String(64), nullable=True),
    sa.Column("record_key", sa.String(160), nullable=True),
    sa.Column("session_label", sa.String(10), nullable=True),
    sa.Column("code", sa.String(32), nullable=False),
    sa.Column("severity", sa.String(16), nullable=False),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("summary", sa.String(160), nullable=False),
    sa.Column("detail", sa.String(1024), nullable=False),
    sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("quarantined", sa.Boolean(), nullable=False),
    sa.CheckConstraint(
        "severity IN ('info', 'warning', 'error')",
        name="data_quality_issues_valid_severity",
    ),
    sa.CheckConstraint("status = 'open'", name="data_quality_issues_open_only"),
)

partition_quarantines = sa.Table(
    "partition_quarantines",
    metadata,
    sa.Column(
        "partition_id",
        sa.String(64),
        sa.ForeignKey("dataset_partitions.partition_id"),
        primary_key=True,
    ),
    sa.Column("reason", sa.String(512), nullable=False),
    sa.Column("quarantined_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("row_count", sa.Integer(), nullable=False),
    sa.CheckConstraint("row_count > 0", name="partition_quarantines_positive_rows"),
)

corporate_action_sets = sa.Table(
    "corporate_action_sets",
    metadata,
    sa.Column("corporate_action_version", sa.String(64), primary_key=True),
    sa.Column("name", sa.String(128), nullable=False),
    sa.Column("content_hash", sa.String(64), nullable=False, unique=True),
    sa.Column("content_hash_version", sa.String(32), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("length(content_hash) = 64", name="corporate_action_sets_hash_length"),
)

corporate_action_set_members = sa.Table(
    "corporate_action_set_members",
    metadata,
    sa.Column(
        "corporate_action_version",
        sa.String(64),
        sa.ForeignKey("corporate_action_sets.corporate_action_version"),
        primary_key=True,
    ),
    sa.Column("ordinal", sa.Integer(), primary_key=True),
    sa.Column(
        "action_revision_id",
        sa.String(64),
        sa.ForeignKey("corporate_action_revisions.action_revision_id"),
        nullable=False,
    ),
    sa.UniqueConstraint(
        "corporate_action_version",
        "action_revision_id",
        name="uq_corporate_action_set_members_action",
    ),
    sa.CheckConstraint("ordinal >= 0", name="corporate_action_set_members_non_negative_ordinal"),
)

dataset_manifests = sa.Table(
    "dataset_manifests",
    metadata,
    sa.Column("manifest_id", sa.String(64), primary_key=True),
    sa.Column("name", sa.String(128), nullable=False),
    sa.Column("manifest_hash", sa.String(64), nullable=False, unique=True),
    sa.Column(
        "source_id",
        sa.String(64),
        sa.ForeignKey("market_data_sources.source_id"),
        nullable=False,
    ),
    sa.Column("schema_version", sa.String(32), nullable=False),
    sa.Column(
        "calendar_version",
        sa.String(64),
        sa.ForeignKey("calendar_versions.calendar_version"),
        nullable=False,
    ),
    sa.Column(
        "universe_version",
        sa.String(64),
        sa.ForeignKey("universe_versions.universe_version"),
        nullable=False,
    ),
    sa.Column(
        "corporate_action_version",
        sa.String(64),
        sa.ForeignKey("corporate_action_sets.corporate_action_version"),
        nullable=False,
    ),
    sa.Column("revision_policy", sa.String(24), nullable=False),
    sa.Column("price_basis", sa.String(16), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("row_count", sa.Integer(), nullable=False),
    sa.CheckConstraint(
        "revision_policy IN ('first_seen', 'revised_as_of')",
        name="dataset_manifests_valid_revision_policy",
    ),
    sa.CheckConstraint("price_basis = 'raw'", name="dataset_manifests_raw_price_only"),
    sa.CheckConstraint("row_count > 0", name="dataset_manifests_positive_rows"),
    sa.CheckConstraint(
        "length(manifest_id) = 64 AND length(manifest_hash) = 64",
        name="dataset_manifests_hash_lengths",
    ),
)

dataset_manifest_partitions = sa.Table(
    "dataset_manifest_partitions",
    metadata,
    sa.Column(
        "manifest_id",
        sa.String(64),
        sa.ForeignKey("dataset_manifests.manifest_id"),
        primary_key=True,
    ),
    sa.Column("ordinal", sa.Integer(), primary_key=True),
    sa.Column(
        "partition_id",
        sa.String(64),
        sa.ForeignKey("dataset_partitions.partition_id"),
        nullable=False,
    ),
    sa.UniqueConstraint(
        "manifest_id",
        "partition_id",
        name="uq_dataset_manifest_partitions_partition",
    ),
    sa.CheckConstraint("ordinal >= 0", name="dataset_manifest_partitions_non_negative_ordinal"),
)

replay_run_manifests = sa.Table(
    "replay_run_manifests",
    metadata,
    sa.Column("run_id", sa.String(64), primary_key=True),
    sa.Column("idempotency_key", sa.String(64), nullable=False, unique=True),
    sa.Column(
        "dataset_manifest_id",
        sa.String(64),
        sa.ForeignKey("dataset_manifests.manifest_id"),
        nullable=False,
        index=True,
    ),
    sa.Column("dataset_manifest_hash", sa.String(64), nullable=False),
    sa.Column("manifest_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("manifest_payload", sa.Text(), nullable=False),
    sa.Column("tape_sha256", sa.String(64), nullable=False),
    sa.Column("replay_semantic_sha256", sa.String(64), nullable=False),
    sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("processed_event_count", sa.Integer(), nullable=False),
    sa.Column("batch_count", sa.Integer(), nullable=False),
    sa.Column("complete_batch_count", sa.Integer(), nullable=False),
    sa.Column("skipped_batch_count", sa.Integer(), nullable=False),
    sa.CheckConstraint(
        "run_id = manifest_sha256",
        name="replay_run_manifests_content_addressed",
    ),
    sa.CheckConstraint(
        "length(run_id) = 64 "
        "AND length(idempotency_key) = 64 "
        "AND length(dataset_manifest_id) = 64 "
        "AND length(dataset_manifest_hash) = 64 "
        "AND length(manifest_sha256) = 64 "
        "AND length(tape_sha256) = 64 "
        "AND length(replay_semantic_sha256) = 64",
        name="replay_run_manifests_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(manifest_payload) <= 65536",
        name="replay_run_manifests_payload_size",
    ),
    sa.CheckConstraint(
        "completed_at >= started_at",
        name="replay_run_manifests_valid_time_range",
    ),
    sa.CheckConstraint(
        "processed_event_count >= 0 "
        "AND batch_count > 0 "
        "AND complete_batch_count >= 0 "
        "AND skipped_batch_count >= 0",
        name="replay_run_manifests_valid_counts",
    ),
    sa.CheckConstraint(
        "complete_batch_count + skipped_batch_count = batch_count",
        name="replay_run_manifests_reconciled_batch_counts",
    ),
)

# Phase 2 durable execution facts intentionally live beside, rather than mutate,
# the Phase 0 walking-thread tables above. The two contracts have different
# cardinality and lifecycle semantics: Phase 0 authorizes one intent, while
# Phase 2 authorizes one complete batch and records every side effect as an
# immutable fact plus an explicitly rebuildable projection.
phase2_account_leases = sa.Table(
    "phase2_account_leases",
    metadata,
    sa.Column("lease_sha256", sa.String(64), primary_key=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("owner_id", sa.String(128), nullable=False),
    sa.Column("lease_id", sa.String(64), nullable=False),
    sa.Column("fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("revision_number", sa.BigInteger(), nullable=False),
    sa.Column("previous_lease_sha256", sa.String(64), nullable=True),
    sa.Column("acquired_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("policy_sha256", sa.String(64), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.UniqueConstraint(
        "account_id",
        "fencing_generation",
        "lease_sha256",
        name="account_generation_digest",
    ),
    sa.UniqueConstraint(
        "account_id",
        "fencing_generation",
        "revision_number",
        name="account_generation_revision",
    ),
    sa.UniqueConstraint(
        "account_id",
        "lease_id",
        "heartbeat_at",
        name="account_lease_revision",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "fencing_generation", "previous_lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="previous_lease_revision",
    ),
    sa.CheckConstraint("fencing_generation > 0", name="positive_generation"),
    sa.CheckConstraint("revision_number > 0", name="positive_revision"),
    sa.CheckConstraint(
        "(revision_number = 1 AND previous_lease_sha256 IS NULL) "
        "OR (revision_number > 1 AND previous_lease_sha256 IS NOT NULL "
        "AND previous_lease_sha256 <> lease_sha256)",
        name="revision_predecessor_shape",
    ),
    sa.CheckConstraint(
        "heartbeat_at >= acquired_at AND expires_at > heartbeat_at",
        name="valid_time_range",
    ),
    sa.CheckConstraint(
        "length(lease_sha256) = 64 AND length(policy_sha256) = 64 "
        "AND (previous_lease_sha256 IS NULL OR length(previous_lease_sha256) = 64)",
        name="hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 65536",
        name="payload_size",
    ),
)
sa.Index(
    "ix_phase2_account_leases_account_generation",
    phase2_account_leases.c.account_id,
    phase2_account_leases.c.fencing_generation,
    phase2_account_leases.c.revision_number,
)

phase2_account_lease_heads = sa.Table(
    "phase2_account_lease_heads",
    metadata,
    sa.Column("account_id", sa.String(64), primary_key=True),
    sa.Column("last_fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("current_fencing_generation", sa.BigInteger(), nullable=True),
    sa.Column("current_lease_sha256", sa.String(64), nullable=True),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(
        ["account_id", "current_fencing_generation", "current_lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="current_lease",
    ),
    sa.CheckConstraint("last_fencing_generation >= 0", name="non_negative_generation"),
    sa.CheckConstraint(
        "(current_fencing_generation IS NULL AND current_lease_sha256 IS NULL) "
        "OR (current_fencing_generation IS NOT NULL "
        "AND current_lease_sha256 IS NOT NULL "
        "AND current_fencing_generation = last_fencing_generation)",
        name="current_lease_pair",
    ),
    sa.CheckConstraint(
        "current_lease_sha256 IS NULL OR length(current_lease_sha256) = 64",
        name="current_hash_length",
    ),
)

phase2_account_lease_releases = sa.Table(
    "phase2_account_lease_releases",
    metadata,
    sa.Column("release_id", sa.String(64), primary_key=True),
    sa.Column("release_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("owner_id", sa.String(128), nullable=False),
    sa.Column("lease_id", sa.String(64), nullable=False),
    sa.Column("fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("lease_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("released_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("policy_sha256", sa.String(64), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.ForeignKeyConstraint(
        ["account_id", "fencing_generation", "lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="released_lease",
    ),
    sa.CheckConstraint("fencing_generation > 0", name="positive_generation"),
    sa.CheckConstraint(
        "length(release_sha256) = 64 AND length(lease_sha256) = 64 AND length(policy_sha256) = 64",
        name="hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 65536",
        name="payload_size",
    ),
)
sa.Index(
    "ix_phase2_account_lease_releases_account_generation",
    phase2_account_lease_releases.c.account_id,
    phase2_account_lease_releases.c.fencing_generation,
)

phase2_batch_decisions = sa.Table(
    "phase2_batch_decisions",
    metadata,
    sa.Column("decision_id", sa.String(64), primary_key=True),
    sa.Column("intent_batch_id", sa.String(64), nullable=False, unique=True),
    sa.Column("intent_batch_sha256", sa.String(64), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("account_observation_sequence", sa.BigInteger(), nullable=False),
    sa.Column("capacity_observation_contract", sa.String(64), nullable=False),
    sa.Column("fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("lease_sha256", sa.String(64), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column("snapshot_version", sa.String(64), nullable=False),
    sa.Column("snapshot_sha256", sa.String(64), nullable=False),
    sa.Column("active_capacity_payload", sa.Text(), nullable=False),
    sa.Column("active_capacity_sha256", sa.String(64), nullable=False),
    sa.Column("policy_id", sa.String(64), nullable=False),
    sa.Column("policy_version", sa.String(64), nullable=False),
    sa.Column("policy_sha256", sa.String(64), nullable=False),
    sa.Column("currency", sa.String(3), nullable=False),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("intent_count", sa.Integer(), nullable=False),
    sa.Column("rules_payload", sa.Text(), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        ["account_id", "fencing_generation", "lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="authorizing_lease",
    ),
    sa.UniqueConstraint(
        "decision_id",
        "account_id",
        "fencing_generation",
        name="decision_account_generation",
    ),
    sa.UniqueConstraint(
        "decision_id",
        "account_id",
        "fencing_generation",
        "semantic_sha256",
        name="decision_account_generation_exact",
    ),
    sa.UniqueConstraint(
        "account_id",
        "account_observation_sequence",
        name="account_observation_sequence",
    ),
    sa.CheckConstraint(
        "account_observation_sequence > 0",
        name="positive_observation_sequence",
    ),
    sa.CheckConstraint(
        "capacity_observation_contract IN "
        "('phase2-capacity-observation-v3', 'phase2-capacity-observation-v4')",
        name="valid_capacity_observation_contract",
    ),
    sa.CheckConstraint("fencing_generation > 0", name="positive_generation"),
    sa.CheckConstraint("expires_at > evaluated_at", name="positive_ttl"),
    sa.CheckConstraint(
        "status IN ('approved', 'rejected', 'no_action')",
        name="valid_status",
    ),
    sa.CheckConstraint(
        "(status = 'no_action' AND intent_count = 0) "
        "OR (status IN ('approved', 'rejected') AND intent_count > 0)",
        name="status_matches_count",
    ),
    sa.CheckConstraint(
        "length(intent_batch_sha256) = 64 "
        "AND length(lease_sha256) = 64 "
        "AND length(fence_sha256) = 64 "
        "AND length(snapshot_sha256) = 64 "
        "AND length(active_capacity_sha256) = 64 "
        "AND length(policy_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="hash_lengths",
    ),
    sa.CheckConstraint(
        "length(currency) = 3 AND currency = upper(currency)",
        name="canonical_currency",
    ),
    sa.CheckConstraint(
        "length(rules_payload) BETWEEN 2 AND 262144 "
        "AND length(active_capacity_payload) BETWEEN 2 AND 1048576 "
        "AND length(canonical_payload) BETWEEN 2 AND 1048576",
        name="payload_sizes",
    ),
)
sa.Index(
    "ix_phase2_batch_decisions_account_evaluated",
    phase2_batch_decisions.c.account_id,
    phase2_batch_decisions.c.evaluated_at,
)

phase2_batch_members = sa.Table(
    "phase2_batch_members",
    metadata,
    sa.Column("membership_id", sa.String(64), primary_key=True),
    sa.Column(
        "decision_id",
        sa.String(64),
        sa.ForeignKey("phase2_batch_decisions.decision_id"),
        nullable=False,
    ),
    sa.Column("intent_batch_id", sa.String(64), nullable=False),
    sa.Column("intent_batch_sha256", sa.String(64), nullable=False),
    sa.Column("ordinal", sa.Integer(), nullable=False),
    sa.Column("intent_id", sa.String(64), nullable=False, unique=True),
    sa.Column("intent_payload_sha256", sa.String(64), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint("decision_id", "ordinal", name="decision_ordinal"),
    sa.UniqueConstraint(
        "decision_id",
        "intent_id",
        name="batch_member_decision_intent",
    ),
    sa.CheckConstraint("ordinal >= 0", name="non_negative_ordinal"),
    sa.CheckConstraint(
        "length(intent_batch_sha256) = 64 "
        "AND length(intent_payload_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 262144",
        name="payload_size",
    ),
)
sa.Index(
    "ix_phase2_batch_members_batch_ordinal",
    phase2_batch_members.c.intent_batch_id,
    phase2_batch_members.c.ordinal,
)

phase2_batch_reservations = sa.Table(
    "phase2_batch_reservations",
    metadata,
    sa.Column("reservation_id", sa.String(64), primary_key=True),
    sa.Column(
        "parent_decision_id",
        sa.String(64),
        sa.ForeignKey("phase2_batch_decisions.decision_id"),
        nullable=False,
        unique=True,
    ),
    sa.Column("intent_batch_id", sa.String(64), nullable=False, unique=True),
    sa.Column("intent_batch_sha256", sa.String(64), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("lease_sha256", sa.String(64), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column("snapshot_sha256", sa.String(64), nullable=False),
    sa.Column("policy_sha256", sa.String(64), nullable=False),
    sa.Column("currency", sa.String(3), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("state", sa.String(24), nullable=False),
    sa.Column("state_version", sa.BigInteger(), nullable=False, server_default="1"),
    sa.Column("authorization_count", sa.Integer(), nullable=False),
    sa.Column("remaining_authorization_count", sa.Integer(), nullable=False),
    sa.Column("initial_cash", sa.Numeric(28, 10), nullable=False),
    sa.Column("initial_buy_exposure", sa.Numeric(28, 10), nullable=False),
    sa.Column("remaining_cash", sa.Numeric(28, 10), nullable=False),
    sa.Column("remaining_buy_exposure", sa.Numeric(28, 10), nullable=False),
    sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        ["account_id", "fencing_generation", "lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="authorizing_lease",
    ),
    sa.UniqueConstraint(
        "reservation_id",
        "parent_decision_id",
        name="reservation_parent",
    ),
    sa.CheckConstraint("fencing_generation > 0", name="positive_generation"),
    sa.CheckConstraint("expires_at > created_at", name="positive_ttl"),
    sa.CheckConstraint("state_version > 0", name="positive_state_version"),
    sa.CheckConstraint(
        "state IN ('active', 'partially_released', 'frozen', 'released')",
        name="valid_state",
    ),
    sa.CheckConstraint(
        "authorization_count > 0 "
        "AND remaining_authorization_count >= 0 "
        "AND remaining_authorization_count <= authorization_count",
        name="valid_authorization_counts",
    ),
    sa.CheckConstraint(
        "initial_cash >= 0 "
        "AND initial_buy_exposure >= 0 "
        "AND remaining_cash >= 0 "
        "AND remaining_cash <= initial_cash "
        "AND remaining_buy_exposure >= 0 "
        "AND remaining_buy_exposure <= initial_buy_exposure",
        name="conserved_amounts",
    ),
    sa.CheckConstraint(
        "(state = 'released' "
        "AND released_at IS NOT NULL "
        "AND remaining_authorization_count = 0 "
        "AND remaining_cash = 0 "
        "AND remaining_buy_exposure = 0) "
        "OR (state <> 'released' AND released_at IS NULL)",
        name="released_state",
    ),
    sa.CheckConstraint(
        "length(intent_batch_sha256) = 64 "
        "AND length(lease_sha256) = 64 "
        "AND length(fence_sha256) = 64 "
        "AND length(snapshot_sha256) = 64 "
        "AND length(policy_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="hash_lengths",
    ),
    sa.CheckConstraint(
        "length(currency) = 3 AND currency = upper(currency)",
        name="canonical_currency",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 1048576",
        name="payload_size",
    ),
)
sa.Index(
    "ix_phase2_batch_reservations_account_state",
    phase2_batch_reservations.c.account_id,
    phase2_batch_reservations.c.state,
)
sa.Index(
    "ix_phase2_batch_reservations_expires_at",
    phase2_batch_reservations.c.expires_at,
)

phase2_batch_authorizations = sa.Table(
    "phase2_batch_authorizations",
    metadata,
    sa.Column("authorization_id", sa.String(64), primary_key=True),
    sa.Column("parent_decision_id", sa.String(64), nullable=False),
    sa.Column("reservation_id", sa.String(64), nullable=False),
    sa.Column("intent_batch_id", sa.String(64), nullable=False),
    sa.Column("intent_batch_sha256", sa.String(64), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("lease_sha256", sa.String(64), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column("snapshot_sha256", sa.String(64), nullable=False),
    sa.Column("policy_sha256", sa.String(64), nullable=False),
    sa.Column("session_sha256", sa.String(64), nullable=False),
    sa.Column("currency", sa.String(3), nullable=False),
    sa.Column("intent_id", sa.String(64), nullable=False, unique=True),
    sa.Column("intent_payload_sha256", sa.String(64), nullable=False),
    sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("instrument_id", sa.String(64), nullable=False),
    sa.Column("symbol", sa.String(32), nullable=False),
    sa.Column("side", sa.String(8), nullable=False),
    sa.Column("quantity", sa.Numeric(28, 10), nullable=False),
    sa.Column("reference_price", sa.Numeric(28, 10), nullable=False),
    sa.Column("snapshot_as_of", sa.DateTime(timezone=True), nullable=False),
    sa.Column("reference_event_time", sa.DateTime(timezone=True), nullable=False),
    sa.Column("maximum_execution_price", sa.Numeric(28, 10), nullable=False),
    sa.Column("maximum_fee", sa.Numeric(28, 10), nullable=False),
    sa.Column("maximum_cash_requirement", sa.Numeric(28, 10), nullable=False),
    sa.Column("reserved_cash", sa.Numeric(28, 10), nullable=False),
    sa.Column("reserved_sell_quantity", sa.Numeric(28, 10), nullable=False),
    sa.Column("reserved_buy_exposure", sa.Numeric(28, 10), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        ["reservation_id", "parent_decision_id"],
        [
            "phase2_batch_reservations.reservation_id",
            "phase2_batch_reservations.parent_decision_id",
        ],
        name="parent_reservation",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "fencing_generation", "lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="authorizing_lease",
    ),
    sa.UniqueConstraint(
        "parent_decision_id",
        "intent_id",
        name="authorization_decision_intent",
    ),
    sa.CheckConstraint("fencing_generation > 0", name="positive_generation"),
    sa.CheckConstraint("expires_at > evaluated_at", name="positive_ttl"),
    sa.CheckConstraint("side IN ('buy', 'sell')", name="valid_side"),
    sa.CheckConstraint(
        "quantity > 0 AND quantity = CAST(quantity AS BIGINT)",
        name="whole_quantity",
    ),
    sa.CheckConstraint(
        "reference_price > 0 "
        "AND maximum_execution_price >= reference_price "
        "AND maximum_fee >= 0 "
        "AND maximum_cash_requirement >= 0 "
        "AND reserved_cash >= 0 "
        "AND reserved_sell_quantity >= 0 "
        "AND reserved_buy_exposure >= 0",
        name="valid_amounts",
    ),
    sa.CheckConstraint(
        "maximum_cash_requirement = reserved_cash "
        "AND reserved_cash = reserved_buy_exposure + maximum_fee",
        name="cash_conservation",
    ),
    sa.CheckConstraint(
        "(side = 'buy' "
        "AND reserved_sell_quantity = 0 "
        "AND reserved_buy_exposure = quantity * maximum_execution_price) "
        "OR (side = 'sell' "
        "AND reserved_sell_quantity = quantity "
        "AND reserved_buy_exposure = 0)",
        name="side_holds",
    ),
    sa.CheckConstraint(
        "length(intent_batch_sha256) = 64 "
        "AND length(lease_sha256) = 64 "
        "AND length(fence_sha256) = 64 "
        "AND length(snapshot_sha256) = 64 "
        "AND length(policy_sha256) = 64 "
        "AND length(session_sha256) = 64 "
        "AND length(intent_payload_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="hash_lengths",
    ),
    sa.CheckConstraint(
        "length(currency) = 3 AND currency = upper(currency)",
        name="canonical_currency",
    ),
    sa.CheckConstraint("symbol = upper(symbol)", name="canonical_symbol"),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 262144",
        name="payload_size",
    ),
)
sa.Index(
    "ix_phase2_batch_authorizations_account_instrument",
    phase2_batch_authorizations.c.account_id,
    phase2_batch_authorizations.c.instrument_id,
)
sa.Index(
    "ix_phase2_batch_authorizations_expires_at",
    phase2_batch_authorizations.c.expires_at,
)

phase2_logical_orders = sa.Table(
    "phase2_logical_orders",
    metadata,
    sa.Column("order_id", sa.String(64), primary_key=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("lease_sha256", sa.String(64), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column("parent_decision_id", sa.String(64), nullable=False),
    sa.Column("reservation_id", sa.String(64), nullable=False),
    sa.Column(
        "authorization_id",
        sa.String(64),
        sa.ForeignKey("phase2_batch_authorizations.authorization_id"),
        nullable=False,
        unique=True,
    ),
    sa.Column("intent_batch_id", sa.String(64), nullable=False),
    sa.Column("intent_id", sa.String(64), nullable=False, unique=True),
    sa.Column("intent_payload_sha256", sa.String(64), nullable=False),
    sa.Column("intent_payload", sa.Text(), nullable=False),
    sa.Column("submission_attempt_id", sa.String(64), nullable=False, unique=True),
    sa.Column("client_order_id", sa.String(64), nullable=False, unique=True),
    sa.Column("instrument_id", sa.String(64), nullable=False),
    sa.Column("symbol", sa.String(32), nullable=False),
    sa.Column("side", sa.String(8), nullable=False),
    sa.Column("quantity", sa.Numeric(28, 10), nullable=False),
    sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        ["reservation_id", "parent_decision_id"],
        [
            "phase2_batch_reservations.reservation_id",
            "phase2_batch_reservations.parent_decision_id",
        ],
        name="parent_reservation",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "fencing_generation", "lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="authorizing_lease",
    ),
    sa.UniqueConstraint(
        "order_id",
        "account_id",
        "fencing_generation",
        name="order_account_generation",
    ),
    sa.CheckConstraint("fencing_generation > 0", name="positive_generation"),
    sa.CheckConstraint("side IN ('buy', 'sell')", name="valid_side"),
    sa.CheckConstraint(
        "quantity > 0 AND quantity = CAST(quantity AS BIGINT)",
        name="whole_quantity",
    ),
    sa.CheckConstraint("symbol = upper(symbol)", name="canonical_symbol"),
    sa.CheckConstraint(
        "length(lease_sha256) = 64 "
        "AND length(fence_sha256) = 64 "
        "AND length(intent_payload_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="hash_lengths",
    ),
    sa.CheckConstraint(
        "length(intent_payload) BETWEEN 2 AND 262144 "
        "AND length(canonical_payload) BETWEEN 2 AND 524288",
        name="payload_sizes",
    ),
)
sa.Index(
    "ix_phase2_logical_orders_account_submitted",
    phase2_logical_orders.c.account_id,
    phase2_logical_orders.c.submitted_at,
)

phase2_authorization_consumptions = sa.Table(
    "phase2_authorization_consumptions",
    metadata,
    sa.Column("consumption_id", sa.String(64), primary_key=True),
    sa.Column(
        "authorization_id",
        sa.String(64),
        sa.ForeignKey("phase2_batch_authorizations.authorization_id"),
        nullable=False,
        unique=True,
    ),
    sa.Column(
        "order_id",
        sa.String(64),
        sa.ForeignKey("phase2_logical_orders.order_id"),
        nullable=False,
        unique=True,
    ),
    sa.Column("reservation_id", sa.String(64), nullable=False),
    sa.Column("intent_id", sa.String(64), nullable=False, unique=True),
    sa.Column("intent_payload_sha256", sa.String(64), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("lease_sha256", sa.String(64), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        ["account_id", "fencing_generation", "lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="consuming_lease",
    ),
    sa.CheckConstraint("fencing_generation > 0", name="positive_generation"),
    sa.CheckConstraint(
        "length(intent_payload_sha256) = 64 "
        "AND length(lease_sha256) = 64 "
        "AND length(fence_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="hash_lengths",
    ),
)
sa.Index(
    "ix_phase2_authorization_consumptions_account_time",
    phase2_authorization_consumptions.c.account_id,
    phase2_authorization_consumptions.c.consumed_at,
)

phase2_submission_attempts = sa.Table(
    "phase2_submission_attempts",
    metadata,
    sa.Column("attempt_id", sa.String(64), primary_key=True),
    sa.Column(
        "order_id",
        sa.String(64),
        sa.ForeignKey("phase2_logical_orders.order_id"),
        nullable=False,
    ),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("lease_sha256", sa.String(64), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column(
        "parent_decision_id",
        sa.String(64),
        sa.ForeignKey("phase2_batch_decisions.decision_id"),
        nullable=False,
    ),
    sa.Column(
        "authorization_id",
        sa.String(64),
        sa.ForeignKey("phase2_batch_authorizations.authorization_id"),
        nullable=False,
    ),
    sa.Column("reservation_id", sa.String(64), nullable=False),
    sa.Column("intent_id", sa.String(64), nullable=False),
    sa.Column("intent_payload_sha256", sa.String(64), nullable=False),
    sa.Column("risk_decision_sha256", sa.String(64), nullable=False),
    sa.Column("authorization_sha256", sa.String(64), nullable=False),
    sa.Column("fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("fence_validated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("attempt_number", sa.Integer(), nullable=False),
    sa.Column("client_order_id", sa.String(64), nullable=False),
    sa.Column("adapter_id", sa.String(128), nullable=False),
    sa.Column("adapter_version", sa.String(64), nullable=False),
    sa.Column("operation", sa.String(64), nullable=False),
    sa.Column("request_sha256", sa.String(64), nullable=False),
    sa.Column("request_payload", sa.Text(), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        ["account_id", "fencing_generation", "lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="attempt_lease",
    ),
    sa.ForeignKeyConstraint(
        ["reservation_id", "parent_decision_id"],
        [
            "phase2_batch_reservations.reservation_id",
            "phase2_batch_reservations.parent_decision_id",
        ],
        name="attempt_parent_reservation",
    ),
    sa.UniqueConstraint("order_id", "attempt_number", name="order_attempt_number"),
    sa.CheckConstraint("fencing_generation > 0", name="positive_generation"),
    sa.CheckConstraint("attempt_number > 0", name="positive_attempt_number"),
    sa.CheckConstraint(
        "fence_validated_at <= created_at AND created_at < fence_valid_until",
        name="current_fence_receipt",
    ),
    sa.CheckConstraint(
        "length(lease_sha256) = 64 "
        "AND length(fence_sha256) = 64 "
        "AND length(intent_payload_sha256) = 64 "
        "AND length(risk_decision_sha256) = 64 "
        "AND length(authorization_sha256) = 64 "
        "AND length(fence_receipt_sha256) = 64 "
        "AND length(request_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="hash_lengths",
    ),
    sa.CheckConstraint(
        "length(request_payload) BETWEEN 2 AND 262144 "
        "AND length(canonical_payload) BETWEEN 2 AND 524288",
        name="payload_sizes",
    ),
)
sa.Index(
    "ix_phase2_submission_attempts_account_created",
    phase2_submission_attempts.c.account_id,
    phase2_submission_attempts.c.created_at,
)
sa.Index(
    "ix_phase2_submission_attempts_client_order",
    phase2_submission_attempts.c.client_order_id,
)

phase2_submission_attempt_events = sa.Table(
    "phase2_submission_attempt_events",
    metadata,
    sa.Column("event_id", sa.String(64), primary_key=True),
    sa.Column(
        "attempt_id",
        sa.String(64),
        sa.ForeignKey("phase2_submission_attempts.attempt_id"),
        nullable=False,
    ),
    sa.Column("sequence_number", sa.Integer(), nullable=False),
    sa.Column("state", sa.String(16), nullable=False),
    sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("visible_after_observation_sequence", sa.BigInteger(), nullable=False),
    sa.Column("capacity_visibility_sha256", sa.String(64), nullable=True),
    sa.Column("previous_event_sha256", sa.String(64), nullable=True),
    sa.Column("dispatch_account_id", sa.String(64), nullable=True),
    sa.Column("dispatch_fencing_generation", sa.BigInteger(), nullable=True),
    sa.Column("dispatch_lease_sha256", sa.String(64), nullable=True),
    sa.Column("dispatch_fence_sha256", sa.String(64), nullable=True),
    sa.Column("dispatch_fence_receipt_sha256", sa.String(64), nullable=True),
    sa.Column("dispatch_fence_validated_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("dispatch_fence_valid_until", sa.DateTime(timezone=True), nullable=True),
    sa.Column("response_sha256", sa.String(64), nullable=True),
    sa.Column("broker_order_id", sa.String(128), nullable=True),
    sa.Column("error_class", sa.String(128), nullable=True),
    sa.Column("resolution", sa.String(24), nullable=True),
    sa.Column("reconciliation_sha256", sa.String(64), nullable=True),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        [
            "dispatch_account_id",
            "dispatch_fencing_generation",
            "dispatch_lease_sha256",
        ],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="dispatch_lease",
    ),
    sa.UniqueConstraint("attempt_id", "sequence_number", name="attempt_sequence"),
    sa.CheckConstraint("sequence_number > 0", name="positive_sequence"),
    sa.CheckConstraint(
        "state IN ('pending', 'in_flight', 'abandoned', 'confirmed', 'unknown', 'resolved')",
        name="valid_state",
    ),
    sa.CheckConstraint(
        "(state = 'pending' AND sequence_number = 1 AND previous_event_sha256 IS NULL) "
        "OR (state <> 'pending' AND sequence_number > 1 "
        "AND previous_event_sha256 IS NOT NULL)",
        name="pending_is_first",
    ),
    sa.CheckConstraint(
        "(state = 'in_flight' "
        "AND dispatch_account_id IS NOT NULL "
        "AND dispatch_fencing_generation IS NOT NULL "
        "AND dispatch_lease_sha256 IS NOT NULL "
        "AND dispatch_fence_sha256 IS NOT NULL "
        "AND dispatch_fence_receipt_sha256 IS NOT NULL "
        "AND dispatch_fence_validated_at IS NOT NULL "
        "AND dispatch_fence_valid_until IS NOT NULL) "
        "OR (state <> 'in_flight' "
        "AND dispatch_account_id IS NULL "
        "AND dispatch_fencing_generation IS NULL "
        "AND dispatch_lease_sha256 IS NULL "
        "AND dispatch_fence_sha256 IS NULL "
        "AND dispatch_fence_receipt_sha256 IS NULL "
        "AND dispatch_fence_validated_at IS NULL "
        "AND dispatch_fence_valid_until IS NULL)",
        name="dispatch_receipt_shape",
    ),
    sa.CheckConstraint(
        "state <> 'in_flight' OR (dispatch_fencing_generation > 0 "
        "AND dispatch_fence_validated_at = occurred_at "
        "AND occurred_at < dispatch_fence_valid_until)",
        name="current_dispatch_receipt",
    ),
    sa.CheckConstraint(
        "(state IN ('pending', 'in_flight') "
        "AND response_sha256 IS NULL AND broker_order_id IS NULL "
        "AND error_class IS NULL AND resolution IS NULL "
        "AND reconciliation_sha256 IS NULL) "
        "OR (state = 'abandoned' AND response_sha256 IS NULL "
        "AND broker_order_id IS NULL AND error_class IS NOT NULL "
        "AND resolution IS NULL AND reconciliation_sha256 IS NULL) "
        "OR (state = 'confirmed' AND response_sha256 IS NOT NULL "
        "AND broker_order_id IS NOT NULL AND error_class IS NULL "
        "AND resolution IS NULL AND reconciliation_sha256 IS NULL) "
        "OR (state = 'unknown' AND response_sha256 IS NULL "
        "AND broker_order_id IS NULL AND error_class IS NOT NULL "
        "AND resolution IS NULL AND reconciliation_sha256 IS NULL) "
        "OR (state = 'resolved' AND error_class IS NULL "
        "AND resolution IS NOT NULL AND reconciliation_sha256 IS NOT NULL "
        "AND ((resolution = 'not_submitted' AND response_sha256 IS NULL "
        "AND broker_order_id IS NULL) "
        "OR (resolution = 'broker_accepted' AND response_sha256 IS NOT NULL "
        "AND broker_order_id IS NOT NULL) "
        "OR (resolution = 'broker_rejected' AND response_sha256 IS NOT NULL)))",
        name="state_evidence_shape",
    ),
    sa.CheckConstraint(
        "resolution IS NULL OR resolution IN "
        "('not_submitted', 'broker_accepted', 'broker_rejected')",
        name="valid_resolution",
    ),
    sa.CheckConstraint("recorded_at >= occurred_at", name="valid_time_order"),
    sa.CheckConstraint(
        "(visible_after_observation_sequence = 0 AND capacity_visibility_sha256 IS NULL) "
        "OR (visible_after_observation_sequence > 0 "
        "AND length(capacity_visibility_sha256) = 64)",
        name="valid_capacity_visibility_binding",
    ),
    sa.CheckConstraint(
        "(previous_event_sha256 IS NULL OR length(previous_event_sha256) = 64) "
        "AND (dispatch_lease_sha256 IS NULL OR length(dispatch_lease_sha256) = 64) "
        "AND (dispatch_fence_sha256 IS NULL OR length(dispatch_fence_sha256) = 64) "
        "AND (dispatch_fence_receipt_sha256 IS NULL "
        "OR length(dispatch_fence_receipt_sha256) = 64) "
        "AND (response_sha256 IS NULL OR length(response_sha256) = 64) "
        "AND (reconciliation_sha256 IS NULL OR length(reconciliation_sha256) = 64)",
        name="optional_hash_lengths",
    ),
    sa.CheckConstraint("length(semantic_sha256) = 64", name="semantic_hash_length"),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 262144",
        name="payload_size",
    ),
)
sa.Index(
    "ix_phase2_submission_attempt_events_state_recorded",
    phase2_submission_attempt_events.c.state,
    phase2_submission_attempt_events.c.recorded_at,
)
sa.Index(
    "ux_phase2_submission_attempt_event_exact",
    phase2_submission_attempt_events.c.attempt_id,
    phase2_submission_attempt_events.c.event_id,
    phase2_submission_attempt_events.c.semantic_sha256,
    unique=True,
)

phase2_order_events = sa.Table(
    "phase2_order_events",
    metadata,
    sa.Column("event_id", sa.String(128), primary_key=True),
    sa.Column(
        "order_id",
        sa.String(64),
        sa.ForeignKey("phase2_logical_orders.order_id"),
        nullable=False,
    ),
    sa.Column("broker_order_id", sa.String(128), nullable=False),
    sa.Column("broker_sequence", sa.Integer(), nullable=False),
    sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("visible_after_observation_sequence", sa.BigInteger(), nullable=False),
    sa.Column("capacity_visibility_sha256", sa.String(64), nullable=True),
    sa.Column("kind", sa.String(32), nullable=False),
    sa.Column("reason", sa.String(512), nullable=True),
    sa.Column("execution_id", sa.String(128), nullable=True),
    sa.Column("execution_revision", sa.Integer(), nullable=True),
    sa.Column("supersedes_event_id", sa.String(128), nullable=True),
    sa.Column("quantity", sa.Numeric(28, 10), nullable=True),
    sa.Column("price", sa.Numeric(28, 10), nullable=True),
    sa.Column("fee", sa.Numeric(28, 10), nullable=True),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        ["supersedes_event_id"],
        ["phase2_order_events.event_id"],
        name="superseded_event",
    ),
    sa.UniqueConstraint("order_id", "broker_sequence", name="order_broker_sequence"),
    sa.UniqueConstraint(
        "order_id",
        "execution_id",
        "execution_revision",
        name="execution_revision",
    ),
    sa.CheckConstraint("broker_sequence > 0", name="positive_broker_sequence"),
    sa.CheckConstraint("received_at >= occurred_at", name="valid_time_order"),
    sa.CheckConstraint(
        "(visible_after_observation_sequence = 0 AND capacity_visibility_sha256 IS NULL) "
        "OR (visible_after_observation_sequence > 0 "
        "AND length(capacity_visibility_sha256) = 64)",
        name="valid_capacity_visibility_binding",
    ),
    sa.CheckConstraint(
        "kind IN ('accepted', 'rejected', 'canceled', 'execution', 'execution_correction')",
        name="valid_kind",
    ),
    sa.CheckConstraint(
        "kind <> 'rejected' OR reason IS NOT NULL",
        name="rejection_reason",
    ),
    sa.CheckConstraint(
        "(kind NOT IN ('execution', 'execution_correction') "
        "AND execution_id IS NULL "
        "AND execution_revision IS NULL "
        "AND supersedes_event_id IS NULL "
        "AND quantity IS NULL AND price IS NULL AND fee IS NULL) "
        "OR (kind = 'execution' "
        "AND execution_id IS NOT NULL "
        "AND execution_revision = 1 "
        "AND supersedes_event_id IS NULL "
        "AND quantity > 0 AND quantity = CAST(quantity AS BIGINT) "
        "AND price > 0 AND fee >= 0) "
        "OR (kind = 'execution_correction' "
        "AND execution_id IS NOT NULL "
        "AND execution_revision > 1 "
        "AND supersedes_event_id IS NOT NULL "
        "AND quantity >= 0 AND quantity = CAST(quantity AS BIGINT) "
        "AND price > 0 AND fee >= 0)",
        name="execution_shape",
    ),
    sa.CheckConstraint("length(semantic_sha256) = 64", name="semantic_hash_length"),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 262144",
        name="payload_size",
    ),
)
sa.Index(
    "ix_phase2_order_events_broker_order",
    phase2_order_events.c.broker_order_id,
)
sa.Index(
    "ix_phase2_order_events_order_received",
    phase2_order_events.c.order_id,
    phase2_order_events.c.received_at,
)

phase2_simulation_horizon_facts = sa.Table(
    "phase2_simulation_horizon_facts",
    metadata,
    sa.Column("horizon_id", sa.String(64), primary_key=True),
    sa.Column("horizon_reference", sa.String(64), nullable=False, unique=True),
    sa.Column("horizon_source_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column(
        "reservation_id",
        sa.String(64),
        sa.ForeignKey("phase2_batch_reservations.reservation_id"),
        nullable=False,
    ),
    sa.Column(
        "parent_decision_id",
        sa.String(64),
        sa.ForeignKey("phase2_batch_decisions.decision_id"),
        nullable=False,
    ),
    sa.Column(
        "authorization_id",
        sa.String(64),
        sa.ForeignKey("phase2_batch_authorizations.authorization_id"),
        nullable=False,
    ),
    sa.Column(
        "attempt_id",
        sa.String(64),
        sa.ForeignKey("phase2_submission_attempts.attempt_id"),
        nullable=False,
    ),
    sa.Column(
        "order_id",
        sa.String(64),
        sa.ForeignKey("phase2_logical_orders.order_id"),
        nullable=False,
    ),
    sa.Column(
        "final_order_event_id",
        sa.String(128),
        sa.ForeignKey("phase2_order_events.event_id"),
        nullable=False,
    ),
    sa.Column(
        "replay_run_id",
        sa.String(64),
        sa.ForeignKey("replay_run_manifests.run_id"),
        nullable=False,
    ),
    sa.Column(
        "replay_manifest_sha256",
        sa.String(64),
        sa.ForeignKey("replay_run_manifests.manifest_sha256"),
        nullable=False,
    ),
    sa.Column("replay_event_count", sa.Integer(), nullable=False),
    sa.Column("replay_watermark_count", sa.Integer(), nullable=False),
    sa.Column("simulation_result_id", sa.String(64), nullable=False, unique=True),
    sa.Column("horizon_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.CheckConstraint(
        "replay_run_id = replay_manifest_sha256",
        name="content_addressed_replay",
    ),
    sa.CheckConstraint("recorded_at >= horizon_at", name="valid_time_order"),
    sa.CheckConstraint(
        "replay_event_count >= 0 AND replay_watermark_count > 0",
        name="valid_replay_counts",
    ),
    sa.CheckConstraint(
        "length(horizon_id) = 36 "
        "AND length(horizon_reference) = 36 "
        "AND length(simulation_result_id) = 36 "
        "AND length(horizon_source_sha256) = 64 "
        "AND length(replay_run_id) = 64 "
        "AND length(replay_manifest_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 524288",
        name="payload_size",
    ),
)
sa.Index(
    "ix_phase2_simulation_horizon_facts_reservation_recorded",
    phase2_simulation_horizon_facts.c.reservation_id,
    phase2_simulation_horizon_facts.c.recorded_at,
)

phase2_reservation_release_events = sa.Table(
    "phase2_reservation_release_events",
    metadata,
    sa.Column("release_event_id", sa.String(64), primary_key=True),
    sa.Column(
        "reservation_id",
        sa.String(64),
        sa.ForeignKey("phase2_batch_reservations.reservation_id"),
        nullable=False,
    ),
    sa.Column(
        "authorization_id",
        sa.String(64),
        sa.ForeignKey("phase2_batch_authorizations.authorization_id"),
        nullable=False,
    ),
    sa.Column("order_id", sa.String(64), sa.ForeignKey("phase2_logical_orders.order_id")),
    sa.Column(
        "attempt_id",
        sa.String(64),
        sa.ForeignKey("phase2_submission_attempts.attempt_id"),
        nullable=True,
    ),
    sa.Column(
        "order_event_id",
        sa.String(128),
        sa.ForeignKey("phase2_order_events.event_id"),
        nullable=True,
    ),
    sa.Column("reason", sa.String(32), nullable=False),
    sa.Column("finality_reference", sa.String(256), nullable=False),
    sa.Column("source_sha256", sa.String(64), nullable=False),
    sa.Column("released_cash", sa.Numeric(28, 10), nullable=False),
    sa.Column("released_buy_exposure", sa.Numeric(28, 10), nullable=False),
    sa.Column("released_sell_quantity", sa.Numeric(28, 10), nullable=False),
    sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("visible_after_observation_sequence", sa.BigInteger(), nullable=False),
    sa.Column("capacity_visibility_sha256", sa.String(64), nullable=True),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.CheckConstraint(
        "reason IN ('approval_expired_unsent', 'broker_rejected', "
        "'execution_accounted', 'reconciled_terminal', 'simulation_horizon_final')",
        name="valid_reason",
    ),
    sa.CheckConstraint(
        "released_cash >= 0 "
        "AND released_buy_exposure >= 0 "
        "AND released_sell_quantity >= 0 "
        "AND (released_cash > 0 "
        "OR released_buy_exposure > 0 "
        "OR released_sell_quantity > 0)",
        name="positive_release",
    ),
    sa.CheckConstraint(
        "released_sell_quantity = CAST(released_sell_quantity AS BIGINT)",
        name="whole_sell_quantity",
    ),
    sa.CheckConstraint("recorded_at >= occurred_at", name="valid_time_order"),
    sa.CheckConstraint(
        "(visible_after_observation_sequence = 0 AND capacity_visibility_sha256 IS NULL) "
        "OR (visible_after_observation_sequence > 0 "
        "AND length(capacity_visibility_sha256) = 64)",
        name="valid_capacity_visibility_binding",
    ),
    sa.CheckConstraint(
        "length(source_sha256) = 64 AND length(semantic_sha256) = 64",
        name="hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 262144",
        name="payload_size",
    ),
)
sa.Index(
    "ix_phase2_reservation_releases_reservation_recorded",
    phase2_reservation_release_events.c.reservation_id,
    phase2_reservation_release_events.c.recorded_at,
)

phase2_ledger_entries = sa.Table(
    "phase2_ledger_entries",
    metadata,
    sa.Column("entry_id", sa.String(64), primary_key=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("kind", sa.String(40), nullable=False),
    sa.Column("reference_id", sa.String(128), nullable=False),
    sa.Column("source_sha256", sa.String(64), nullable=False),
    sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint("account_id", "kind", "reference_id", name="account_fact"),
    sa.CheckConstraint(
        "kind IN ('cash_flow', 'execution', 'execution_correction', "
        "'settlement_reclassification', 'execution_settlement', 'stock_split', "
        "'cash_dividend_accrual', 'cash_dividend_payment')",
        name="valid_kind",
    ),
    sa.CheckConstraint("recorded_at >= effective_at", name="valid_time_order"),
    sa.CheckConstraint(
        "length(source_sha256) = 64 AND length(semantic_sha256) = 64",
        name="hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 524288",
        name="payload_size",
    ),
)
sa.Index(
    "ix_phase2_ledger_entries_account_effective",
    phase2_ledger_entries.c.account_id,
    phase2_ledger_entries.c.effective_at,
)

phase2_ledger_postings = sa.Table(
    "phase2_ledger_postings",
    metadata,
    sa.Column(
        "posting_id",
        sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
        primary_key=True,
        autoincrement=True,
    ),
    sa.Column(
        "entry_id",
        sa.String(64),
        sa.ForeignKey("phase2_ledger_entries.entry_id"),
        nullable=False,
    ),
    sa.Column("line_number", sa.Integer(), nullable=False),
    sa.Column("account", sa.String(128), nullable=False),
    sa.Column("currency", sa.String(3), nullable=False),
    sa.Column("debit", sa.Numeric(28, 10), nullable=False, server_default="0"),
    sa.Column("credit", sa.Numeric(28, 10), nullable=False, server_default="0"),
    sa.Column("units_delta", sa.Numeric(28, 10), nullable=False, server_default="0"),
    sa.Column("instrument_id", sa.String(64), nullable=True),
    sa.Column("semantic_sha256", sa.String(64), nullable=False),
    sa.UniqueConstraint("entry_id", "line_number", name="entry_line"),
    sa.UniqueConstraint("entry_id", "semantic_sha256", name="entry_posting_digest"),
    sa.CheckConstraint("line_number > 0", name="positive_line_number"),
    sa.CheckConstraint("debit >= 0 AND credit >= 0", name="non_negative_money"),
    sa.CheckConstraint("debit = 0 OR credit = 0", name="single_money_side"),
    sa.CheckConstraint(
        "NOT (debit = 0 AND credit = 0 AND units_delta = 0)",
        name="non_empty_posting",
    ),
    sa.CheckConstraint(
        "units_delta = 0 "
        "OR (instrument_id IS NOT NULL "
        "AND units_delta = CAST(units_delta AS BIGINT))",
        name="valid_units",
    ),
    sa.CheckConstraint(
        "length(currency) = 3 AND currency = upper(currency)",
        name="canonical_currency",
    ),
    sa.CheckConstraint("length(semantic_sha256) = 64", name="semantic_hash_length"),
)
sa.Index(
    "ix_phase2_ledger_postings_entry_id",
    phase2_ledger_postings.c.entry_id,
)

# Phase 2C fixture-only research workflow.  Launch inputs and result artifacts
# are immutable; ``phase2_backtest_job_heads`` is only a lockable projection of
# the append-only job event stream.
phase2_strategy_versions = sa.Table(
    "phase2_strategy_versions",
    metadata,
    sa.Column("strategy_version_id", sa.String(64), primary_key=True),
    sa.Column("strategy_id", sa.String(128), nullable=False),
    sa.Column("strategy_version", sa.String(64), nullable=False),
    sa.Column("display_name", sa.String(128), nullable=False),
    sa.Column("presentation_payload", sa.Text(), nullable=False),
    sa.Column("presentation_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("implementation_sha256", sa.String(64), nullable=False),
    sa.Column("parameter_schema_sha256", sa.String(64), nullable=False),
    sa.Column("parameter_schema_payload", sa.Text(), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint("strategy_id", "strategy_version", name="strategy_version"),
    sa.UniqueConstraint(
        "strategy_version_id", "strategy_id", "strategy_version", name="strategy_identity"
    ),
    sa.CheckConstraint(
        "length(implementation_sha256) = 64 "
        "AND length(parameter_schema_sha256) = 64 "
        "AND length(presentation_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="hash_lengths",
    ),
    sa.CheckConstraint(
        "length(parameter_schema_payload) BETWEEN 2 AND 65536 "
        "AND length(presentation_payload) BETWEEN 2 AND 65536 "
        "AND length(canonical_payload) BETWEEN 2 AND 131072",
        name="payload_sizes",
    ),
)

phase2_strategy_configurations = sa.Table(
    "phase2_strategy_configurations",
    metadata,
    sa.Column("configuration_sha256", sa.String(64), primary_key=True),
    sa.Column("strategy_version_id", sa.String(64), nullable=False),
    sa.Column("strategy_id", sa.String(128), nullable=False),
    sa.Column("strategy_version", sa.String(64), nullable=False),
    sa.Column("display_name", sa.String(128), nullable=False),
    sa.Column("parameters_payload", sa.Text(), nullable=False),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        ["strategy_version_id", "strategy_id", "strategy_version"],
        [
            "phase2_strategy_versions.strategy_version_id",
            "phase2_strategy_versions.strategy_id",
            "phase2_strategy_versions.strategy_version",
        ],
        name="strategy_version_identity",
    ),
    sa.UniqueConstraint(
        "configuration_sha256", "strategy_version_id", name="configuration_version"
    ),
    sa.CheckConstraint(
        "length(configuration_sha256) = 64 AND length(semantic_sha256) = 64",
        name="hash_lengths",
    ),
    sa.CheckConstraint(
        "length(parameters_payload) BETWEEN 2 AND 65536 "
        "AND length(canonical_payload) BETWEEN 2 AND 131072",
        name="payload_sizes",
    ),
)

phase2_backtest_fixtures = sa.Table(
    "phase2_backtest_fixtures",
    metadata,
    sa.Column("fixture_sha256", sa.String(64), primary_key=True),
    sa.Column("fixture_id", sa.String(128), nullable=False),
    sa.Column("fixture_version", sa.String(64), nullable=False),
    sa.Column("dataset_manifest_sha256", sa.String(64), nullable=False),
    sa.Column("source_tape_sha256", sa.String(64), nullable=False),
    sa.Column("replay_run_id", sa.String(64), nullable=False),
    sa.Column("replay_manifest_sha256", sa.String(64), nullable=False),
    sa.Column("replay_input_sha256", sa.String(64), nullable=False),
    sa.Column("replay_semantic_sha256", sa.String(64), nullable=False),
    sa.Column("strategy_version_id", sa.String(64), nullable=False),
    sa.Column("strategy_id", sa.String(128), nullable=False),
    sa.Column("strategy_version", sa.String(64), nullable=False),
    sa.Column("strategy_configuration_sha256", sa.String(64), nullable=False),
    sa.Column("benchmark_sha256", sa.String(64), nullable=False),
    sa.Column("cost_model_sha256", sa.String(64), nullable=False),
    sa.Column("fill_model_sha256", sa.String(64), nullable=False),
    sa.Column("metric_conventions_sha256", sa.String(64), nullable=False),
    sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint("fixture_id", "fixture_version", name="fixture_version"),
    sa.UniqueConstraint(
        "fixture_id",
        "fixture_version",
        "dataset_manifest_sha256",
        "replay_run_id",
        name="fixture_launch_identity",
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
    sa.ForeignKeyConstraint(
        ["strategy_configuration_sha256", "strategy_version_id"],
        [
            "phase2_strategy_configurations.configuration_sha256",
            "phase2_strategy_configurations.strategy_version_id",
        ],
        name="strategy_configuration_identity",
    ),
    sa.CheckConstraint("replay_run_id = replay_manifest_sha256", name="content_addressed_replay"),
    sa.CheckConstraint(
        "length(fixture_sha256) = 64 "
        "AND length(dataset_manifest_sha256) = 64 "
        "AND length(source_tape_sha256) = 64 "
        "AND length(replay_run_id) = 64 "
        "AND length(replay_manifest_sha256) = 64 "
        "AND length(replay_input_sha256) = 64 "
        "AND length(replay_semantic_sha256) = 64 "
        "AND length(strategy_configuration_sha256) = 64 "
        "AND length(benchmark_sha256) = 64 "
        "AND length(cost_model_sha256) = 64 "
        "AND length(fill_model_sha256) = 64 "
        "AND length(metric_conventions_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="hash_lengths",
    ),
    sa.CheckConstraint("length(canonical_payload) BETWEEN 2 AND 131072", name="payload_size"),
)

phase2_backtest_jobs = sa.Table(
    "phase2_backtest_jobs",
    metadata,
    sa.Column("job_id", sa.String(64), primary_key=True),
    sa.Column("input_sha256", sa.String(64), nullable=False),
    sa.Column("fixture_id", sa.String(128), nullable=False),
    sa.Column("fixture_version", sa.String(64), nullable=False),
    sa.Column("dataset_manifest_id", sa.String(64), nullable=False),
    sa.Column("dataset_manifest_sha256", sa.String(64), nullable=False),
    sa.Column("replay_run_id", sa.String(64), nullable=False),
    sa.Column("strategy_version_id", sa.String(64), nullable=False),
    sa.Column("strategy_id", sa.String(128), nullable=False),
    sa.Column("strategy_version", sa.String(64), nullable=False),
    sa.Column("strategy_configuration_sha256", sa.String(64), nullable=False),
    sa.Column("benchmark_sha256", sa.String(64), nullable=False),
    sa.Column("cost_model_sha256", sa.String(64), nullable=False),
    sa.Column("fill_model_sha256", sa.String(64), nullable=False),
    sa.Column("metric_conventions_sha256", sa.String(64), nullable=False),
    sa.Column("requested_by", sa.String(128), nullable=False),
    sa.Column("idempotency_key", sa.String(128), nullable=False),
    sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
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
        ["strategy_version_id", "strategy_id", "strategy_version"],
        [
            "phase2_strategy_versions.strategy_version_id",
            "phase2_strategy_versions.strategy_id",
            "phase2_strategy_versions.strategy_version",
        ],
        name="strategy_version_identity",
    ),
    sa.ForeignKeyConstraint(
        ["strategy_configuration_sha256", "strategy_version_id"],
        [
            "phase2_strategy_configurations.configuration_sha256",
            "phase2_strategy_configurations.strategy_version_id",
        ],
        name="strategy_configuration_identity",
    ),
    sa.UniqueConstraint("requested_by", "idempotency_key", name="operator_idempotency"),
    sa.CheckConstraint(
        "dataset_manifest_id = dataset_manifest_sha256", name="content_addressed_dataset"
    ),
    sa.CheckConstraint(
        "length(job_id) = 64 AND length(input_sha256) = 64 "
        "AND length(dataset_manifest_id) = 64 "
        "AND length(dataset_manifest_sha256) = 64 "
        "AND length(replay_run_id) = 64 "
        "AND length(strategy_configuration_sha256) = 64 "
        "AND length(benchmark_sha256) = 64 "
        "AND length(cost_model_sha256) = 64 "
        "AND length(fill_model_sha256) = 64 "
        "AND length(metric_conventions_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="hash_lengths",
    ),
    sa.CheckConstraint("length(canonical_payload) BETWEEN 2 AND 524288", name="payload_size"),
)
sa.Index(
    "ix_phase2_backtest_jobs_requested_at",
    phase2_backtest_jobs.c.requested_at,
)

phase2_backtest_reports = sa.Table(
    "phase2_backtest_reports",
    metadata,
    sa.Column("report_artifact_sha256", sa.String(64), primary_key=True),
    sa.Column("report_sha256", sa.String(64), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("currency", sa.String(3), nullable=False),
    sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
    sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
    sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("starting_equity", sa.Numeric(28, 10), nullable=False),
    sa.Column("ending_equity", sa.Numeric(28, 10), nullable=False),
    sa.Column("total_return", sa.Numeric(28, 10), nullable=False),
    sa.Column("maximum_drawdown", sa.Numeric(28, 10), nullable=False),
    sa.Column("turnover", sa.Numeric(28, 10), nullable=False),
    sa.Column("trade_count", sa.Integer(), nullable=False),
    sa.Column("realized_pnl", sa.Numeric(28, 10), nullable=False),
    sa.Column("unrealized_pnl", sa.Numeric(28, 10), nullable=False),
    sa.Column("dividend_income", sa.Numeric(28, 10), nullable=False),
    sa.Column("total_execution_costs", sa.Numeric(28, 10), nullable=False),
    sa.Column("semantic_payload", sa.Text(), nullable=False),
    sa.Column("artifact_payload", sa.Text(), nullable=False),
    sa.Column("query_payload", sa.Text(), nullable=False),
    sa.Column("query_payload_sha256", sa.String(64), nullable=False),
    sa.UniqueConstraint("report_sha256", "report_artifact_sha256", name="report_artifact_identity"),
    sa.CheckConstraint(
        "period_end >= period_start AND generated_at >= period_end", name="valid_time_range"
    ),
    sa.CheckConstraint(
        "starting_equity > 0 AND ending_equity > 0 "
        "AND maximum_drawdown >= 0 AND turnover >= 0 "
        "AND trade_count >= 0 AND total_execution_costs >= 0",
        name="valid_metrics",
    ),
    sa.CheckConstraint(
        "length(currency) = 3 AND currency = upper(currency)", name="canonical_currency"
    ),
    sa.CheckConstraint(
        "length(report_sha256) = 64 AND length(report_artifact_sha256) = 64 "
        "AND length(query_payload_sha256) = 64",
        name="hash_lengths",
    ),
    sa.CheckConstraint(
        "length(semantic_payload) BETWEEN 2 AND 4194304 "
        "AND length(artifact_payload) BETWEEN 2 AND 131072 "
        "AND length(query_payload) BETWEEN 2 AND 4194304",
        name="payload_sizes",
    ),
)
sa.Index(
    "ix_phase2_backtest_reports_generated_at",
    phase2_backtest_reports.c.generated_at,
)

phase2_backtest_run_manifests = sa.Table(
    "phase2_backtest_run_manifests",
    metadata,
    sa.Column("run_id", sa.String(64), primary_key=True),
    sa.Column("manifest_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column(
        "job_id",
        sa.String(64),
        sa.ForeignKey("phase2_backtest_jobs.job_id"),
        nullable=False,
        unique=True,
    ),
    sa.Column("manifest_input_sha256", sa.String(64), nullable=False),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("report_sha256", sa.String(64), nullable=True),
    sa.Column("report_artifact_sha256", sa.String(64), nullable=True),
    sa.Column("terminal_reason_code", sa.String(64), nullable=True),
    sa.Column("terminal_reason_sha256", sa.String(64), nullable=True),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.ForeignKeyConstraint(
        ["report_sha256", "report_artifact_sha256"],
        [
            "phase2_backtest_reports.report_sha256",
            "phase2_backtest_reports.report_artifact_sha256",
        ],
        name="report_artifact",
    ),
    sa.CheckConstraint("run_id = manifest_sha256", name="content_addressed_run"),
    sa.CheckConstraint("status IN ('completed', 'failed', 'canceled')", name="valid_status"),
    sa.CheckConstraint(
        "(status = 'completed' AND report_sha256 IS NOT NULL "
        "AND report_artifact_sha256 IS NOT NULL "
        "AND terminal_reason_code IS NULL AND terminal_reason_sha256 IS NULL) "
        "OR (status IN ('failed', 'canceled') AND report_sha256 IS NULL "
        "AND report_artifact_sha256 IS NULL "
        "AND terminal_reason_code IS NOT NULL AND terminal_reason_sha256 IS NOT NULL)",
        name="terminal_evidence_shape",
    ),
    sa.CheckConstraint("completed_at >= started_at", name="valid_time_range"),
    sa.CheckConstraint(
        "length(run_id) = 64 AND length(manifest_sha256) = 64 "
        "AND length(manifest_input_sha256) = 64 "
        "AND (report_sha256 IS NULL OR length(report_sha256) = 64) "
        "AND (report_artifact_sha256 IS NULL OR length(report_artifact_sha256) = 64) "
        "AND (terminal_reason_sha256 IS NULL OR length(terminal_reason_sha256) = 64)",
        name="hash_lengths",
    ),
    sa.CheckConstraint("length(canonical_payload) BETWEEN 2 AND 1048576", name="payload_size"),
)
sa.Index(
    "ix_phase2_backtest_run_manifests_completed_at",
    phase2_backtest_run_manifests.c.completed_at,
)

phase2_backtest_job_events = sa.Table(
    "phase2_backtest_job_events",
    metadata,
    sa.Column("event_sha256", sa.String(64), primary_key=True),
    sa.Column(
        "job_id",
        sa.String(64),
        sa.ForeignKey("phase2_backtest_jobs.job_id"),
        nullable=False,
    ),
    sa.Column("sequence_number", sa.Integer(), nullable=False),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("actor_id", sa.String(128), nullable=False),
    sa.Column("attempt_number", sa.Integer(), nullable=False),
    sa.Column("previous_event_sha256", sa.String(64), nullable=True),
    sa.Column("worker_id", sa.String(128), nullable=True),
    sa.Column("claim_expires_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("run_manifest_sha256", sa.String(64), nullable=True),
    sa.Column("report_sha256", sa.String(64), nullable=True),
    sa.Column("report_artifact_sha256", sa.String(64), nullable=True),
    sa.Column("terminal_reason_code", sa.String(64), nullable=True),
    sa.Column("terminal_reason_sha256", sa.String(64), nullable=True),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.ForeignKeyConstraint(
        ["run_manifest_sha256"],
        ["phase2_backtest_run_manifests.manifest_sha256"],
        name="run_manifest",
    ),
    sa.ForeignKeyConstraint(
        ["report_sha256", "report_artifact_sha256"],
        [
            "phase2_backtest_reports.report_sha256",
            "phase2_backtest_reports.report_artifact_sha256",
        ],
        name="report_artifact",
    ),
    sa.UniqueConstraint("job_id", "sequence_number", name="job_sequence"),
    sa.UniqueConstraint("job_id", "sequence_number", "event_sha256", name="job_event_identity"),
    sa.CheckConstraint("sequence_number >= 0", name="non_negative_sequence"),
    sa.CheckConstraint("attempt_number >= 0", name="non_negative_attempt"),
    sa.CheckConstraint(
        "status IN ('queued', 'running', 'completed', 'failed', 'canceled')",
        name="valid_status",
    ),
    sa.CheckConstraint(
        "(sequence_number = 0 AND status = 'queued' "
        "AND attempt_number = 0 AND previous_event_sha256 IS NULL) "
        "OR (sequence_number > 0 AND status <> 'queued' "
        "AND attempt_number > 0 AND previous_event_sha256 IS NOT NULL)",
        name="initial_event_shape",
    ),
    sa.CheckConstraint(
        "(status = 'queued' AND worker_id IS NULL AND claim_expires_at IS NULL "
        "AND run_manifest_sha256 IS NULL AND report_sha256 IS NULL "
        "AND report_artifact_sha256 IS NULL AND terminal_reason_code IS NULL "
        "AND terminal_reason_sha256 IS NULL) "
        "OR (status = 'running' AND worker_id IS NOT NULL "
        "AND claim_expires_at > occurred_at AND run_manifest_sha256 IS NULL "
        "AND report_sha256 IS NULL AND report_artifact_sha256 IS NULL "
        "AND terminal_reason_code IS NULL AND terminal_reason_sha256 IS NULL) "
        "OR (status = 'completed' AND worker_id IS NULL AND claim_expires_at IS NULL "
        "AND run_manifest_sha256 IS NOT NULL AND report_sha256 IS NOT NULL "
        "AND report_artifact_sha256 IS NOT NULL AND terminal_reason_code IS NULL "
        "AND terminal_reason_sha256 IS NULL) "
        "OR (status IN ('failed', 'canceled') AND worker_id IS NULL "
        "AND claim_expires_at IS NULL AND run_manifest_sha256 IS NULL "
        "AND report_sha256 IS NULL AND report_artifact_sha256 IS NULL "
        "AND terminal_reason_code IS NOT NULL AND terminal_reason_sha256 IS NOT NULL)",
        name="status_evidence_shape",
    ),
    sa.CheckConstraint(
        "length(event_sha256) = 64 "
        "AND (previous_event_sha256 IS NULL OR length(previous_event_sha256) = 64) "
        "AND (run_manifest_sha256 IS NULL OR length(run_manifest_sha256) = 64) "
        "AND (report_sha256 IS NULL OR length(report_sha256) = 64) "
        "AND (report_artifact_sha256 IS NULL OR length(report_artifact_sha256) = 64) "
        "AND (terminal_reason_sha256 IS NULL OR length(terminal_reason_sha256) = 64)",
        name="hash_lengths",
    ),
    sa.CheckConstraint("length(canonical_payload) BETWEEN 2 AND 262144", name="payload_size"),
)
sa.Index(
    "ix_phase2_backtest_job_events_status_occurred",
    phase2_backtest_job_events.c.status,
    phase2_backtest_job_events.c.occurred_at,
)

phase2_backtest_job_heads = sa.Table(
    "phase2_backtest_job_heads",
    metadata,
    sa.Column(
        "job_id",
        sa.String(64),
        sa.ForeignKey("phase2_backtest_jobs.job_id"),
        primary_key=True,
    ),
    sa.Column("last_sequence_number", sa.Integer(), nullable=False),
    sa.Column("last_event_sha256", sa.String(64), nullable=False),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("attempt_number", sa.Integer(), nullable=False),
    sa.Column("worker_id", sa.String(128), nullable=True),
    sa.Column("claim_expires_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("run_manifest_sha256", sa.String(64), nullable=True),
    sa.Column("report_sha256", sa.String(64), nullable=True),
    sa.Column("report_artifact_sha256", sa.String(64), nullable=True),
    sa.Column("terminal_reason_code", sa.String(64), nullable=True),
    sa.Column("terminal_reason_sha256", sa.String(64), nullable=True),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(
        ["job_id", "last_sequence_number", "last_event_sha256"],
        [
            "phase2_backtest_job_events.job_id",
            "phase2_backtest_job_events.sequence_number",
            "phase2_backtest_job_events.event_sha256",
        ],
        name="latest_event",
    ),
    sa.CheckConstraint(
        "status IN ('queued', 'running', 'completed', 'failed', 'canceled')",
        name="valid_status",
    ),
    sa.CheckConstraint(
        "last_sequence_number >= 0 AND attempt_number >= 0", name="non_negative_versions"
    ),
    sa.CheckConstraint("length(last_event_sha256) = 64", name="event_hash_length"),
)
sa.Index(
    "ix_phase2_backtest_job_heads_status_updated",
    phase2_backtest_job_heads.c.status,
    phase2_backtest_job_heads.c.updated_at,
)

phase2_backtest_audit_events = sa.Table(
    "phase2_backtest_audit_events",
    metadata,
    sa.Column("audit_sha256", sa.String(64), primary_key=True),
    sa.Column(
        "job_id",
        sa.String(64),
        sa.ForeignKey("phase2_backtest_jobs.job_id"),
        nullable=False,
    ),
    sa.Column("action", sa.String(32), nullable=False),
    sa.Column("actor_id", sa.String(128), nullable=False),
    sa.Column("idempotency_key", sa.String(128), nullable=False),
    sa.Column("request_sha256", sa.String(64), nullable=False),
    sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint("actor_id", "idempotency_key", name="actor_idempotency"),
    sa.CheckConstraint("action = 'launch'", name="phase2_launch_only"),
    sa.CheckConstraint(
        "length(audit_sha256) = 64 AND length(request_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="hash_lengths",
    ),
    sa.CheckConstraint("length(canonical_payload) BETWEEN 2 AND 131072", name="payload_size"),
)
sa.Index(
    "ix_phase2_backtest_audit_events_occurred_at",
    phase2_backtest_audit_events.c.occurred_at,
)

# Phase 3C fixture-only experiment governance. Global tape policies prevent
# exploratory evidence from crossing the one-family holdout boundary, while
# family claims authenticate all three segment roles. Families and attempts are
# immutable definitions, attempt state is an append-only event chain, and
# holdout reveal plus operator commands are immutable audited facts. The family
# row is also the deterministic transaction lock used to serialize attempt
# allocation and reveal.
phase3_experiment_families = sa.Table(
    "phase3_experiment_families",
    metadata,
    sa.Column("family_id", sa.String(64), primary_key=True),
    sa.Column("family_name", sa.String(128), nullable=False),
    sa.Column("owner_id", sa.String(128), nullable=False),
    sa.Column("strategy_version_id", sa.String(64), nullable=False),
    sa.Column("dataset_replay_sha256", sa.String(64), nullable=False),
    sa.Column("evaluation_plan_sha256", sa.String(64), nullable=False),
    sa.Column("promotion_criteria_sha256", sa.String(64), nullable=False),
    sa.Column("holdout_commitment_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column(
        "holdout_content_commitment_sha256",
        sa.String(64),
        nullable=False,
        unique=True,
    ),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("evidence_payload", sa.Text(), nullable=False),
    sa.Column("evidence_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        ["strategy_version_id"],
        ["phase2_strategy_versions.strategy_version_id"],
        name="fk_phase3_families_strategy_version",
    ),
    sa.CheckConstraint(
        "length(family_id) = 64 "
        "AND length(strategy_version_id) = 64 "
        "AND length(dataset_replay_sha256) = 64 "
        "AND length(evaluation_plan_sha256) = 64 "
        "AND length(promotion_criteria_sha256) = 64 "
        "AND length(holdout_commitment_sha256) = 64 "
        "AND length(holdout_content_commitment_sha256) = 64 "
        "AND length(evidence_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase3_family_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 524288 "
        "AND length(evidence_payload) BETWEEN 2 AND 1048576",
        name="phase3_family_payload_sizes",
    ),
)
sa.Index(
    "ix_phase3_experiment_families_created_at",
    phase3_experiment_families.c.created_at,
)

phase3_experiment_tape_policies = sa.Table(
    "phase3_experiment_tape_policies",
    metadata,
    sa.Column("tape_content_sha256", sa.String(64), primary_key=True),
    sa.Column("source_tape_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("usage_class", sa.String(16), nullable=False),
    sa.Column(
        "holdout_family_id",
        sa.String(64),
        sa.ForeignKey(
            "phase3_experiment_families.family_id",
            name="fk_phase3_tape_policies_holdout_family",
        ),
        nullable=True,
        unique=True,
    ),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "tape_content_sha256",
        "source_tape_sha256",
        "usage_class",
        name="uq_phase3_tape_policies_identity_usage",
    ),
    sa.CheckConstraint(
        "(usage_class = 'exploratory' AND holdout_family_id IS NULL) "
        "OR (usage_class = 'holdout' AND holdout_family_id IS NOT NULL)",
        name="phase3_tape_policy_usage_shape",
    ),
    sa.CheckConstraint(
        "length(tape_content_sha256) = 64 "
        "AND length(source_tape_sha256) = 64 "
        "AND (holdout_family_id IS NULL OR length(holdout_family_id) = 64) "
        "AND length(semantic_sha256) = 64",
        name="phase3_tape_policy_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 4096",
        name="phase3_tape_policy_payload_size",
    ),
)

phase3_experiment_tape_claims = sa.Table(
    "phase3_experiment_tape_claims",
    metadata,
    sa.Column("claim_sha256", sa.String(64), primary_key=True),
    sa.Column(
        "family_id",
        sa.String(64),
        sa.ForeignKey(
            "phase3_experiment_families.family_id",
            name="fk_phase3_tape_claims_family",
        ),
        nullable=False,
    ),
    sa.Column("segment_kind", sa.String(16), nullable=False),
    sa.Column("segment_sha256", sa.String(64), nullable=False),
    sa.Column("source_tape_sha256", sa.String(64), nullable=False),
    sa.Column("tape_content_sha256", sa.String(64), nullable=False),
    sa.Column("usage_class", sa.String(16), nullable=False),
    sa.ForeignKeyConstraint(
        ["tape_content_sha256", "source_tape_sha256", "usage_class"],
        [
            "phase3_experiment_tape_policies.tape_content_sha256",
            "phase3_experiment_tape_policies.source_tape_sha256",
            "phase3_experiment_tape_policies.usage_class",
        ],
        name="fk_phase3_tape_claims_policy",
    ),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "family_id",
        "segment_kind",
        name="uq_phase3_tape_claims_family_segment_kind",
    ),
    sa.UniqueConstraint(
        "family_id",
        "segment_sha256",
        name="uq_phase3_tape_claims_family_segment",
    ),
    sa.UniqueConstraint(
        "family_id",
        "source_tape_sha256",
        name="uq_phase3_tape_claims_family_source_tape",
    ),
    sa.CheckConstraint(
        "(segment_kind IN ('train', 'validation') AND usage_class = 'exploratory') "
        "OR (segment_kind = 'test' AND usage_class = 'holdout')",
        name="phase3_tape_claim_role_usage",
    ),
    sa.CheckConstraint(
        "length(claim_sha256) = 64 "
        "AND length(family_id) = 64 "
        "AND length(segment_sha256) = 64 "
        "AND length(source_tape_sha256) = 64 "
        "AND length(tape_content_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase3_tape_claim_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 4096",
        name="phase3_tape_claim_payload_size",
    ),
)
sa.Index(
    "ix_phase3_experiment_tape_claims_family",
    phase3_experiment_tape_claims.c.family_id,
)

phase3_experiment_attempts = sa.Table(
    "phase3_experiment_attempts",
    metadata,
    sa.Column("attempt_id", sa.String(64), primary_key=True),
    sa.Column(
        "family_id",
        sa.String(64),
        sa.ForeignKey(
            "phase3_experiment_families.family_id",
            name="fk_phase3_attempts_family",
        ),
        nullable=False,
    ),
    sa.Column("sequence_number", sa.Integer(), nullable=False),
    sa.Column("attempt_number", sa.Integer(), nullable=False),
    sa.Column("configuration_sha256", sa.String(64), nullable=False),
    sa.Column("configuration_validation_sha256", sa.String(64), nullable=False),
    sa.Column("segment_kind", sa.String(16), nullable=False),
    sa.Column("segment_sha256", sa.String(64), nullable=False),
    sa.Column("holdout_reveal_sha256", sa.String(64), nullable=True, unique=True),
    sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        ["configuration_sha256"],
        ["phase2_strategy_configurations.configuration_sha256"],
        name="fk_phase3_attempts_configuration",
    ),
    sa.UniqueConstraint(
        "family_id",
        "sequence_number",
        name="uq_phase3_attempts_family_sequence",
    ),
    sa.UniqueConstraint(
        "family_id",
        "attempt_number",
        name="uq_phase3_attempts_family_attempt_number",
    ),
    sa.UniqueConstraint(
        "attempt_id",
        "family_id",
        name="uq_phase3_attempts_identity_family",
    ),
    sa.CheckConstraint(
        "sequence_number >= 0 AND attempt_number = sequence_number + 1",
        name="phase3_attempt_contiguous_number",
    ),
    sa.CheckConstraint(
        "segment_kind IN ('train', 'validation', 'test')",
        name="phase3_attempt_valid_segment_kind",
    ),
    sa.CheckConstraint(
        "(segment_kind = 'test' AND holdout_reveal_sha256 IS NOT NULL) "
        "OR (segment_kind <> 'test' AND holdout_reveal_sha256 IS NULL)",
        name="phase3_attempt_holdout_binding",
    ),
    sa.CheckConstraint(
        "length(attempt_id) = 64 "
        "AND length(family_id) = 64 "
        "AND length(configuration_sha256) = 64 "
        "AND length(configuration_validation_sha256) = 64 "
        "AND length(segment_sha256) = 64 "
        "AND (holdout_reveal_sha256 IS NULL OR length(holdout_reveal_sha256) = 64) "
        "AND length(semantic_sha256) = 64",
        name="phase3_attempt_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 262144",
        name="phase3_attempt_payload_size",
    ),
)
sa.Index(
    "ix_phase3_experiment_attempts_family_requested",
    phase3_experiment_attempts.c.family_id,
    phase3_experiment_attempts.c.requested_at,
)

phase3_experiment_attempt_events = sa.Table(
    "phase3_experiment_attempt_events",
    metadata,
    sa.Column("event_sha256", sa.String(64), primary_key=True),
    sa.Column("attempt_id", sa.String(64), nullable=False),
    sa.Column("family_id", sa.String(64), nullable=False),
    sa.Column("global_sequence_number", sa.Integer(), nullable=False),
    sa.Column("attempt_sequence_number", sa.Integer(), nullable=False),
    sa.Column("previous_entry_sha256", sa.String(64), nullable=True),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("actor_id", sa.String(128), nullable=False),
    sa.Column("terminal_evidence_sha256", sa.String(64), nullable=True),
    sa.Column("terminal_evidence_payload", sa.Text(), nullable=True),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        ["attempt_id", "family_id"],
        [
            "phase3_experiment_attempts.attempt_id",
            "phase3_experiment_attempts.family_id",
        ],
        name="fk_phase3_attempt_events_attempt_family",
    ),
    sa.UniqueConstraint(
        "family_id",
        "global_sequence_number",
        name="uq_phase3_attempt_events_family_global_sequence",
    ),
    sa.UniqueConstraint(
        "attempt_id",
        "attempt_sequence_number",
        name="uq_phase3_attempt_events_attempt_sequence",
    ),
    sa.UniqueConstraint(
        "attempt_id",
        "event_sha256",
        name="uq_phase3_attempt_events_attempt_event",
    ),
    sa.CheckConstraint(
        "(global_sequence_number = 0 AND previous_entry_sha256 IS NULL) "
        "OR (global_sequence_number > 0 AND previous_entry_sha256 IS NOT NULL)",
        name="phase3_attempt_event_initial_shape",
    ),
    sa.CheckConstraint(
        "status IN ('queued', 'running', 'completed', 'failed', 'canceled', 'abandoned')",
        name="phase3_attempt_event_valid_status",
    ),
    sa.CheckConstraint(
        "(status IN ('queued', 'running') "
        "AND terminal_evidence_sha256 IS NULL AND terminal_evidence_payload IS NULL) "
        "OR (status IN ('completed', 'failed', 'canceled', 'abandoned') "
        "AND terminal_evidence_sha256 IS NOT NULL AND terminal_evidence_payload IS NOT NULL)",
        name="phase3_attempt_event_evidence_shape",
    ),
    sa.CheckConstraint(
        "length(event_sha256) = 64 "
        "AND length(attempt_id) = 64 "
        "AND length(family_id) = 64 "
        "AND (previous_entry_sha256 IS NULL OR length(previous_entry_sha256) = 64) "
        "AND (terminal_evidence_sha256 IS NULL OR length(terminal_evidence_sha256) = 64) "
        "AND length(semantic_sha256) = 64",
        name="phase3_attempt_event_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(actor_id) BETWEEN 1 AND 128",
        name="phase3_attempt_event_actor_size",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 262144 "
        "AND (terminal_evidence_payload IS NULL "
        "OR length(terminal_evidence_payload) BETWEEN 2 AND 262144)",
        name="phase3_attempt_event_payload_size",
    ),
)
sa.Index(
    "ix_phase3_attempt_events_family_occurred",
    phase3_experiment_attempt_events.c.family_id,
    phase3_experiment_attempt_events.c.occurred_at,
)

phase3_holdout_reveals = sa.Table(
    "phase3_holdout_reveals",
    metadata,
    sa.Column("reveal_id", sa.String(64), primary_key=True),
    sa.Column(
        "family_id",
        sa.String(64),
        sa.ForeignKey(
            "phase3_experiment_families.family_id",
            name="fk_phase3_holdout_reveals_family",
        ),
        nullable=False,
        unique=True,
    ),
    sa.Column("holdout_commitment_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column(
        "holdout_content_commitment_sha256",
        sa.String(64),
        nullable=False,
        unique=True,
    ),
    sa.Column("global_sequence_number", sa.Integer(), nullable=False),
    sa.Column("previous_entry_sha256", sa.String(64), nullable=False),
    sa.Column("promotion_criteria_sha256", sa.String(64), nullable=False),
    sa.Column("selected_configuration_sha256", sa.String(64), nullable=False),
    sa.Column("pre_reveal_attempt_count", sa.Integer(), nullable=False),
    sa.Column("pre_reveal_attempts_sha256", sa.String(64), nullable=False),
    sa.Column("pre_reveal_registry_sha256", sa.String(64), nullable=False),
    sa.Column("authorization_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("revealed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("revealed_by", sa.String(128), nullable=False),
    sa.Column("access_reason", sa.String(1024), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        ["selected_configuration_sha256"],
        ["phase2_strategy_configurations.configuration_sha256"],
        name="fk_phase3_holdout_reveals_configuration",
    ),
    sa.CheckConstraint(
        "global_sequence_number >= 1 AND pre_reveal_attempt_count >= 1",
        name="phase3_holdout_reveal_non_negative_attempt_count",
    ),
    sa.CheckConstraint(
        "length(reveal_id) = 64 "
        "AND length(holdout_commitment_sha256) = 64 "
        "AND length(holdout_content_commitment_sha256) = 64 "
        "AND length(previous_entry_sha256) = 64 "
        "AND length(promotion_criteria_sha256) = 64 "
        "AND length(selected_configuration_sha256) = 64 "
        "AND length(pre_reveal_attempts_sha256) = 64 "
        "AND length(pre_reveal_registry_sha256) = 64 "
        "AND length(authorization_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase3_holdout_reveal_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 262144",
        name="phase3_holdout_reveal_payload_size",
    ),
)
sa.Index(
    "ix_phase3_holdout_reveals_revealed_at",
    phase3_holdout_reveals.c.revealed_at,
)

phase3_experiment_audit_events = sa.Table(
    "phase3_experiment_audit_events",
    metadata,
    sa.Column("audit_sha256", sa.String(64), primary_key=True),
    sa.Column(
        "family_id",
        sa.String(64),
        sa.ForeignKey(
            "phase3_experiment_families.family_id",
            name="fk_phase3_experiment_audits_family",
        ),
        nullable=False,
    ),
    sa.Column("action", sa.String(32), nullable=False),
    sa.Column("actor_id", sa.String(128), nullable=False),
    sa.Column("idempotency_key", sa.String(128), nullable=False),
    sa.Column("request_sha256", sa.String(64), nullable=False),
    sa.Column("expected_registry_sha256", sa.String(64), nullable=False),
    sa.Column("result_registry_sha256", sa.String(64), nullable=False),
    sa.Column("resource_sha256", sa.String(64), nullable=False),
    sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "actor_id",
        "idempotency_key",
        name="uq_phase3_experiment_audits_actor_idempotency",
    ),
    sa.CheckConstraint(
        "action IN ('register_family', 'record_attempt', 'transition_attempt', 'reveal_holdout')",
        name="phase3_experiment_audit_valid_action",
    ),
    sa.CheckConstraint(
        "length(audit_sha256) = 64 "
        "AND length(request_sha256) = 64 "
        "AND length(expected_registry_sha256) = 64 "
        "AND length(result_registry_sha256) = 64 "
        "AND length(resource_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase3_experiment_audit_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 262144",
        name="phase3_experiment_audit_payload_size",
    ),
)
sa.Index(
    "ix_phase3_experiment_audits_family_occurred",
    phase3_experiment_audit_events.c.family_id,
    phase3_experiment_audit_events.c.occurred_at,
)

# Phase 3F durable repository-fixture segment work. Transcript artifacts and
# job/event history are immutable; the head is a checked lock projection. A
# stable governed actor remains distinct from rotating physical worker claims.
phase3_fixture_segment_transcript_artifacts = sa.Table(
    "phase3_fixture_segment_transcript_artifacts",
    metadata,
    sa.Column("artifact_sha256", sa.String(64), primary_key=True),
    sa.Column("artifact_kind", sa.String(16), nullable=False),
    sa.Column("family_id", sa.String(64), nullable=False),
    sa.Column("attempt_id", sa.String(64), nullable=False),
    sa.Column("segment_kind", sa.String(16), nullable=False),
    sa.Column("segment_sha256", sa.String(64), nullable=False),
    sa.Column("source_evidence_sha256", sa.String(64), nullable=False),
    sa.Column("configuration_sha256", sa.String(64), nullable=True),
    sa.Column("certification_sha256", sa.String(64), nullable=False),
    sa.Column("parity_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("transcript_sha256", sa.String(64), nullable=False),
    sa.Column("step_count", sa.Integer(), nullable=False),
    sa.Column("output_count", sa.Integer(), nullable=False),
    sa.Column("transcript_payload", sa.Text(), nullable=False),
    sa.Column("transcript_payload_sha256", sa.String(64), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        ["attempt_id", "family_id"],
        [
            "phase3_experiment_attempts.attempt_id",
            "phase3_experiment_attempts.family_id",
        ],
        name="fk_phase3_fixture_artifacts_attempt_family",
    ),
    sa.UniqueConstraint(
        "attempt_id",
        "artifact_kind",
        name="uq_phase3_fixture_artifacts_attempt_kind",
    ),
    sa.CheckConstraint(
        "artifact_kind IN ('feature', 'target') "
        "AND segment_kind IN ('train', 'validation', 'test') "
        "AND ((artifact_kind = 'feature' AND configuration_sha256 IS NULL) "
        "OR (artifact_kind = 'target' AND configuration_sha256 IS NOT NULL))",
        name="phase3_fixture_artifact_kind_shape",
    ),
    sa.CheckConstraint(
        "step_count BETWEEN 1 AND 100000 AND output_count BETWEEN 0 AND 5000000",
        name="phase3_fixture_artifact_count_bounds",
    ),
    sa.CheckConstraint(
        "length(artifact_sha256) = 64 "
        "AND length(family_id) = 64 "
        "AND length(attempt_id) = 64 "
        "AND length(segment_sha256) = 64 "
        "AND length(source_evidence_sha256) = 64 "
        "AND (configuration_sha256 IS NULL OR length(configuration_sha256) = 64) "
        "AND length(certification_sha256) = 64 "
        "AND length(parity_receipt_sha256) = 64 "
        "AND length(transcript_sha256) = 64 "
        "AND length(transcript_payload_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase3_fixture_artifact_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(transcript_payload) BETWEEN 2 AND 8388608",
        name="phase3_fixture_artifact_payload_bound",
    ),
)
sa.Index(
    "ix_phase3_fixture_artifacts_family_attempt",
    phase3_fixture_segment_transcript_artifacts.c.family_id,
    phase3_fixture_segment_transcript_artifacts.c.attempt_id,
)

phase3_fixture_segment_jobs = sa.Table(
    "phase3_fixture_segment_jobs",
    metadata,
    sa.Column("job_id", sa.String(64), primary_key=True),
    sa.Column("family_id", sa.String(64), nullable=False),
    sa.Column("attempt_id", sa.String(64), nullable=False, unique=True),
    sa.Column("configuration_sha256", sa.String(64), nullable=False),
    sa.Column("configuration_validation_sha256", sa.String(64), nullable=False),
    sa.Column("segment_kind", sa.String(16), nullable=False),
    sa.Column("segment_sha256", sa.String(64), nullable=False),
    sa.Column("source_evidence_sha256", sa.String(64), nullable=False),
    sa.Column("queued_governance_event_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("feature_certification_sha256", sa.String(64), nullable=False),
    sa.Column("feature_transcript_artifact_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("governed_actor_id", sa.String(96), nullable=False, unique=True),
    sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("requested_by", sa.String(128), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        ["attempt_id", "family_id"],
        [
            "phase3_experiment_attempts.attempt_id",
            "phase3_experiment_attempts.family_id",
        ],
        name="fk_phase3_fixture_jobs_attempt_family",
    ),
    sa.ForeignKeyConstraint(
        ["queued_governance_event_sha256"],
        ["phase3_experiment_attempt_events.event_sha256"],
        name="fk_phase3_fixture_jobs_queued_event",
    ),
    sa.ForeignKeyConstraint(
        ["feature_transcript_artifact_sha256"],
        ["phase3_fixture_segment_transcript_artifacts.artifact_sha256"],
        name="fk_phase3_fixture_jobs_feature_artifact",
    ),
    sa.CheckConstraint(
        "segment_kind IN ('train', 'validation', 'test') "
        "AND length(requested_by) BETWEEN 1 AND 128 "
        "AND length(governed_actor_id) BETWEEN 1 AND 96",
        name="phase3_fixture_job_text_shape",
    ),
    sa.CheckConstraint(
        "length(job_id) = 64 "
        "AND length(family_id) = 64 "
        "AND length(attempt_id) = 64 "
        "AND length(configuration_sha256) = 64 "
        "AND length(configuration_validation_sha256) = 64 "
        "AND length(segment_sha256) = 64 "
        "AND length(source_evidence_sha256) = 64 "
        "AND length(queued_governance_event_sha256) = 64 "
        "AND length(feature_certification_sha256) = 64 "
        "AND length(feature_transcript_artifact_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase3_fixture_job_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 262144",
        name="phase3_fixture_job_payload_bound",
    ),
)
sa.Index(
    "ix_phase3_fixture_jobs_requested",
    phase3_fixture_segment_jobs.c.requested_at,
    phase3_fixture_segment_jobs.c.job_id,
)

phase3_fixture_segment_job_events = sa.Table(
    "phase3_fixture_segment_job_events",
    metadata,
    sa.Column("event_sha256", sa.String(64), primary_key=True),
    sa.Column(
        "job_id",
        sa.String(64),
        sa.ForeignKey("phase3_fixture_segment_jobs.job_id", name="fk_phase3_fixture_events_job"),
        nullable=False,
    ),
    sa.Column("sequence_number", sa.Integer(), nullable=False),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("actor_id", sa.String(128), nullable=False),
    sa.Column("attempt_number", sa.Integer(), nullable=False),
    sa.Column("previous_event_sha256", sa.String(64), nullable=True),
    sa.Column("worker_id", sa.String(128), nullable=True),
    sa.Column("claim_expires_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("governance_event_sha256", sa.String(64), nullable=False),
    sa.Column("feature_artifact_sha256", sa.String(64), nullable=False),
    sa.Column("target_artifact_sha256", sa.String(64), nullable=True),
    sa.Column("completion_receipt_sha256", sa.String(64), nullable=True),
    sa.Column("terminal_reason_code", sa.String(64), nullable=True),
    sa.Column("terminal_reason_sha256", sa.String(64), nullable=True),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        ["previous_event_sha256"],
        ["phase3_fixture_segment_job_events.event_sha256"],
        name="fk_phase3_fixture_events_predecessor",
    ),
    sa.ForeignKeyConstraint(
        ["governance_event_sha256"],
        ["phase3_experiment_attempt_events.event_sha256"],
        name="fk_phase3_fixture_events_governance_event",
    ),
    sa.ForeignKeyConstraint(
        ["feature_artifact_sha256"],
        ["phase3_fixture_segment_transcript_artifacts.artifact_sha256"],
        name="fk_phase3_fixture_events_feature_artifact",
    ),
    sa.ForeignKeyConstraint(
        ["target_artifact_sha256"],
        ["phase3_fixture_segment_transcript_artifacts.artifact_sha256"],
        name="fk_phase3_fixture_events_target_artifact",
    ),
    sa.UniqueConstraint("job_id", "sequence_number", name="uq_phase3_fixture_events_job_sequence"),
    sa.CheckConstraint(
        "(sequence_number = 0 AND previous_event_sha256 IS NULL) "
        "OR (sequence_number > 0 AND previous_event_sha256 IS NOT NULL)",
        name="phase3_fixture_event_predecessor_shape",
    ),
    sa.CheckConstraint(
        "status IN ('queued', 'running', 'completed', 'failed') "
        "AND attempt_number >= 0 "
        "AND length(actor_id) BETWEEN 1 AND 128 "
        "AND (worker_id IS NULL OR length(worker_id) BETWEEN 1 AND 128)",
        name="phase3_fixture_event_status_shape",
    ),
    sa.CheckConstraint(
        "(status = 'queued' AND sequence_number = 0 AND attempt_number = 0 "
        "AND worker_id IS NULL AND claim_expires_at IS NULL "
        "AND target_artifact_sha256 IS NULL AND completion_receipt_sha256 IS NULL "
        "AND terminal_reason_code IS NULL AND terminal_reason_sha256 IS NULL) "
        "OR (status = 'running' AND attempt_number > 0 AND worker_id IS NOT NULL "
        "AND claim_expires_at IS NOT NULL AND target_artifact_sha256 IS NULL "
        "AND completion_receipt_sha256 IS NULL AND terminal_reason_code IS NULL "
        "AND terminal_reason_sha256 IS NULL) "
        "OR (status = 'completed' AND attempt_number > 0 AND worker_id IS NOT NULL "
        "AND claim_expires_at IS NULL AND target_artifact_sha256 IS NOT NULL "
        "AND completion_receipt_sha256 IS NOT NULL AND terminal_reason_code IS NULL "
        "AND terminal_reason_sha256 IS NULL) "
        "OR (status = 'failed' AND attempt_number > 0 AND worker_id IS NOT NULL "
        "AND claim_expires_at IS NULL AND target_artifact_sha256 IS NULL "
        "AND completion_receipt_sha256 IS NULL AND terminal_reason_code IS NOT NULL "
        "AND terminal_reason_sha256 IS NOT NULL)",
        name="phase3_fixture_event_evidence_shape",
    ),
    sa.CheckConstraint(
        "length(event_sha256) = 64 "
        "AND length(job_id) = 64 "
        "AND (previous_event_sha256 IS NULL OR length(previous_event_sha256) = 64) "
        "AND length(governance_event_sha256) = 64 "
        "AND length(feature_artifact_sha256) = 64 "
        "AND (target_artifact_sha256 IS NULL OR length(target_artifact_sha256) = 64) "
        "AND (completion_receipt_sha256 IS NULL OR length(completion_receipt_sha256) = 64) "
        "AND (terminal_reason_sha256 IS NULL OR length(terminal_reason_sha256) = 64) "
        "AND length(semantic_sha256) = 64",
        name="phase3_fixture_event_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 262144",
        name="phase3_fixture_event_payload_bound",
    ),
)
sa.Index(
    "ix_phase3_fixture_events_job_occurred",
    phase3_fixture_segment_job_events.c.job_id,
    phase3_fixture_segment_job_events.c.occurred_at,
)

phase3_fixture_segment_job_heads = sa.Table(
    "phase3_fixture_segment_job_heads",
    metadata,
    sa.Column(
        "job_id",
        sa.String(64),
        sa.ForeignKey("phase3_fixture_segment_jobs.job_id", name="fk_phase3_fixture_heads_job"),
        primary_key=True,
    ),
    sa.Column("status", sa.String(16), nullable=False),
    sa.Column("latest_sequence_number", sa.Integer(), nullable=False),
    sa.Column("latest_event_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("attempt_number", sa.Integer(), nullable=False),
    sa.Column("worker_id", sa.String(128), nullable=True),
    sa.Column("claim_expires_at", sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(
        ["latest_event_sha256"],
        ["phase3_fixture_segment_job_events.event_sha256"],
        name="fk_phase3_fixture_heads_latest_event",
    ),
    sa.CheckConstraint(
        "status IN ('queued', 'running', 'completed', 'failed') "
        "AND latest_sequence_number >= 0 AND attempt_number >= 0 "
        "AND ((status = 'running' AND worker_id IS NOT NULL AND claim_expires_at IS NOT NULL) "
        "OR (status <> 'running' AND worker_id IS NULL AND claim_expires_at IS NULL))",
        name="phase3_fixture_head_shape",
    ),
    sa.CheckConstraint(
        "length(job_id) = 64 AND length(latest_event_sha256) = 64 "
        "AND (worker_id IS NULL OR length(worker_id) BETWEEN 1 AND 128)",
        name="phase3_fixture_head_identity",
    ),
)
sa.Index(
    "ix_phase3_fixture_heads_claimable",
    phase3_fixture_segment_job_heads.c.status,
    phase3_fixture_segment_job_heads.c.claim_expires_at,
)

# Phase 4AM durable, secret-free E*TRADE OAuth replay/session coordination.
# Event rows retain only typed reference identities, sanitized state evidence,
# replay fingerprints, monotonic high-water metadata, and authenticated digests.
phase4_etrade_oauth_session_events = sa.Table(
    "phase4_etrade_oauth_session_events",
    metadata,
    sa.Column("event_sha256", sa.String(64), primary_key=True),
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
    sa.ForeignKeyConstraint(
        ["previous_event_sha256"],
        ["phase4_etrade_oauth_session_events.event_sha256"],
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
sa.Index(
    "ix_phase4_etrade_oauth_events_scope_sequence",
    phase4_etrade_oauth_session_events.c.scope_sha256,
    phase4_etrade_oauth_session_events.c.sequence_number,
)
sa.Index(
    "ix_phase4_etrade_oauth_events_replay_fingerprint",
    phase4_etrade_oauth_session_events.c.replay_fingerprint_sha256,
    unique=True,
    sqlite_where=phase4_etrade_oauth_session_events.c.replay_fingerprint_sha256.is_not(None),
    postgresql_where=phase4_etrade_oauth_session_events.c.replay_fingerprint_sha256.is_not(None),
)

phase4_etrade_oauth_session_heads = sa.Table(
    "phase4_etrade_oauth_session_heads",
    metadata,
    sa.Column("scope_sha256", sa.String(64), primary_key=True),
    sa.Column("environment", sa.String(16), nullable=False),
    sa.Column("consumer_scope", sa.String(64), nullable=False),
    sa.Column("consumer_reference_version", sa.BigInteger(), nullable=False),
    sa.Column("consumer_reference_sha256", sa.String(64), nullable=False),
    sa.Column("latest_sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("latest_event_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("current_session_state_sha256", sa.String(64), nullable=False),
    sa.Column("current_replay_guard_sha256", sa.String(64), nullable=False),
    sa.ForeignKeyConstraint(
        ["latest_event_sha256"],
        ["phase4_etrade_oauth_session_events.event_sha256"],
        name="fk_phase4_etrade_oauth_heads_latest_event",
    ),
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

phase4_broker_ingress_receipts = sa.Table(
    "phase4_broker_ingress_receipts",
    metadata,
    sa.Column("receipt_id", sa.String(64), primary_key=True),
    sa.Column(
        "account_id",
        sa.String(64),
        sa.ForeignKey(
            "phase2_account_lease_heads.account_id",
            name="fk_phase4_broker_ingress_account_head",
        ),
        nullable=False,
    ),
    sa.Column("ingress_sequence", sa.BigInteger(), nullable=False),
    sa.Column("previous_receipt_sha256", sa.String(64), nullable=True),
    sa.Column("delivery_idempotency_key", sa.String(128), nullable=False),
    sa.Column("provider_id", sa.String(128), nullable=False),
    sa.Column("adapter_version", sa.String(64), nullable=False),
    sa.Column("environment", sa.String(32), nullable=False),
    sa.Column("channel", sa.String(128), nullable=False),
    sa.Column("operation", sa.String(128), nullable=False),
    sa.Column("correlation_sha256", sa.String(64), nullable=True),
    sa.Column("transport_status", sa.Integer(), nullable=True),
    sa.Column("provider_request_id", sa.String(256), nullable=True),
    sa.Column("media_type", sa.String(128), nullable=True),
    sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("body", sa.LargeBinary(), nullable=False),
    sa.Column("body_size_bytes", sa.BigInteger(), nullable=False),
    sa.Column("body_sha256", sa.String(64), nullable=False),
    sa.Column("delivery_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "account_id",
        "ingress_sequence",
        name="uq_phase4_broker_ingress_account_sequence",
    ),
    sa.UniqueConstraint(
        "account_id",
        "delivery_idempotency_key",
        name="uq_phase4_broker_ingress_account_delivery_key",
    ),
    sa.UniqueConstraint(
        "account_id",
        "semantic_sha256",
        name="uq_phase4_broker_ingress_account_semantic",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "previous_receipt_sha256"],
        [
            "phase4_broker_ingress_receipts.account_id",
            "phase4_broker_ingress_receipts.semantic_sha256",
        ],
        name="fk_phase4_broker_ingress_predecessor",
    ),
    sa.CheckConstraint(
        "(ingress_sequence = 1 AND previous_receipt_sha256 IS NULL) "
        "OR (ingress_sequence > 1 AND previous_receipt_sha256 IS NOT NULL)",
        name="phase4_broker_ingress_predecessor_shape",
    ),
    sa.CheckConstraint(
        "transport_status IS NULL OR transport_status BETWEEN 100 AND 599",
        name="phase4_broker_ingress_transport_status",
    ),
    sa.CheckConstraint(
        "recorded_at >= received_at",
        name="phase4_broker_ingress_time_order",
    ),
    sa.CheckConstraint(
        "body_size_bytes BETWEEN 0 AND 1048576 AND length(body) = body_size_bytes",
        name="phase4_broker_ingress_body_size",
    ),
    sa.CheckConstraint(
        "length(receipt_id) = 64 "
        "AND (previous_receipt_sha256 IS NULL "
        "OR length(previous_receipt_sha256) = 64) "
        "AND (correlation_sha256 IS NULL OR length(correlation_sha256) = 64) "
        "AND length(body_sha256) = 64 "
        "AND length(delivery_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_broker_ingress_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 8192",
        name="phase4_broker_ingress_canonical_payload_size",
    ),
)
sa.Index(
    "ix_phase4_broker_ingress_account_received",
    phase4_broker_ingress_receipts.c.account_id,
    phase4_broker_ingress_receipts.c.received_at,
)
sa.Index(
    "ix_phase4_broker_ingress_provider_request",
    phase4_broker_ingress_receipts.c.provider_id,
    phase4_broker_ingress_receipts.c.provider_request_id,
)
sa.Index(
    "ux_phase4_broker_ingress_account_receipt_semantic",
    phase4_broker_ingress_receipts.c.account_id,
    phase4_broker_ingress_receipts.c.receipt_id,
    phase4_broker_ingress_receipts.c.semantic_sha256,
    unique=True,
)

phase4_broker_ingress_heads = sa.Table(
    "phase4_broker_ingress_heads",
    metadata,
    sa.Column(
        "account_id",
        sa.String(64),
        sa.ForeignKey(
            "phase2_account_lease_heads.account_id",
            name="fk_phase4_broker_ingress_head_account",
        ),
        primary_key=True,
    ),
    sa.Column("last_ingress_sequence", sa.BigInteger(), nullable=False),
    sa.Column("last_receipt_sha256", sa.String(64), nullable=True),
    sa.ForeignKeyConstraint(
        ["account_id", "last_receipt_sha256"],
        [
            "phase4_broker_ingress_receipts.account_id",
            "phase4_broker_ingress_receipts.semantic_sha256",
        ],
        name="fk_phase4_broker_ingress_head_terminal_receipt",
    ),
    sa.CheckConstraint(
        "(last_ingress_sequence = 0 AND last_receipt_sha256 IS NULL) "
        "OR (last_ingress_sequence > 0 AND last_receipt_sha256 IS NOT NULL "
        "AND length(last_receipt_sha256) = 64)",
        name="phase4_broker_ingress_head_terminal_shape",
    ),
)

# Broker request permits are immutable, consumed-at-issuance capacity facts.
# The account-local chain makes allocation order and policy transitions
# independently auditable; the mutable head is only the serialized chain tip.
phase4_broker_request_permits = sa.Table(
    "phase4_broker_request_permits",
    metadata,
    sa.Column("permit_id", sa.String(64), primary_key=True),
    sa.Column(
        "account_id",
        sa.String(64),
        sa.ForeignKey(
            "phase2_account_lease_heads.account_id",
            name="fk_phase4_broker_request_permits_account",
        ),
        nullable=False,
    ),
    sa.Column("sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("previous_sequence_number", sa.BigInteger(), nullable=True),
    sa.Column("previous_permit_sha256", sa.String(64), nullable=True),
    sa.Column("provider_id", sa.String(128), nullable=False),
    sa.Column("environment", sa.String(32), nullable=False),
    sa.Column("policy_id", sa.String(128), nullable=False),
    sa.Column("policy_version", sa.String(128), nullable=False),
    sa.Column("window_seconds", sa.BigInteger(), nullable=False),
    sa.Column("permit_ttl_seconds", sa.BigInteger(), nullable=False),
    sa.Column("submission_capacity", sa.BigInteger(), nullable=False),
    sa.Column("recovery_capacity", sa.BigInteger(), nullable=False),
    sa.Column("total_capacity", sa.BigInteger(), nullable=False),
    sa.Column("policy_payload", sa.Text(), nullable=False),
    sa.Column("policy_sha256", sa.String(64), nullable=False),
    sa.Column("demand_id", sa.String(64), nullable=False, unique=True),
    sa.Column("idempotency_key", sa.String(128), nullable=False),
    sa.Column("operation", sa.String(128), nullable=False),
    sa.Column("purpose", sa.String(32), nullable=False),
    sa.Column("correlation_sha256", sa.String(64), nullable=False),
    sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("demand_payload", sa.Text(), nullable=False),
    sa.Column("demand_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("window_permit_count", sa.BigInteger(), nullable=False),
    sa.Column("admission_ceiling", sa.BigInteger(), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "account_id",
        "sequence_number",
        name="uq_phase4_broker_request_permits_account_sequence",
    ),
    sa.UniqueConstraint(
        "account_id",
        "idempotency_key",
        name="uq_phase4_broker_request_permits_account_idempotency",
    ),
    sa.UniqueConstraint(
        "account_id",
        "semantic_sha256",
        name="uq_phase4_broker_request_permits_account_semantic",
    ),
    sa.UniqueConstraint(
        "account_id",
        "sequence_number",
        "semantic_sha256",
        name="uq_phase4_broker_request_permits_account_sequence_semantic",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "previous_sequence_number",
            "previous_permit_sha256",
        ],
        [
            "phase4_broker_request_permits.account_id",
            "phase4_broker_request_permits.sequence_number",
            "phase4_broker_request_permits.semantic_sha256",
        ],
        name="fk_phase4_broker_request_permits_predecessor",
    ),
    sa.CheckConstraint(
        "(sequence_number = 1 "
        "AND previous_sequence_number IS NULL "
        "AND previous_permit_sha256 IS NULL) "
        "OR (sequence_number > 1 "
        "AND previous_sequence_number = sequence_number - 1 "
        "AND previous_permit_sha256 IS NOT NULL)",
        name="phase4_broker_request_permit_predecessor_shape",
    ),
    sa.CheckConstraint(
        "window_seconds > 0 AND permit_ttl_seconds > 0 AND permit_ttl_seconds <= window_seconds",
        name="phase4_broker_request_permit_positive_durations",
    ),
    sa.CheckConstraint(
        "submission_capacity > 0 "
        "AND submission_capacity < recovery_capacity "
        "AND recovery_capacity < total_capacity",
        name="phase4_broker_request_permit_capacity_order",
    ),
    sa.CheckConstraint(
        "purpose IN ('submission', 'unknown_lookup', 'cancel', 'reconciliation')",
        name="phase4_broker_request_permit_valid_purpose",
    ),
    sa.CheckConstraint(
        "requested_at <= issued_at AND issued_at < expires_at",
        name="phase4_broker_request_permit_time_order",
    ),
    sa.CheckConstraint(
        "window_permit_count > 0 "
        "AND window_permit_count <= admission_ceiling "
        "AND admission_ceiling IN "
        "(submission_capacity, recovery_capacity, total_capacity)",
        name="phase4_broker_request_permit_valid_counts",
    ),
    sa.CheckConstraint(
        "length(permit_id) = 64 "
        "AND (previous_permit_sha256 IS NULL "
        "OR length(previous_permit_sha256) = 64) "
        "AND length(policy_sha256) = 64 "
        "AND length(demand_id) = 64 "
        "AND length(demand_sha256) = 64 "
        "AND length(correlation_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_broker_request_permit_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(policy_payload) BETWEEN 2 AND 8192 "
        "AND length(demand_payload) BETWEEN 2 AND 8192 "
        "AND length(canonical_payload) BETWEEN 2 AND 16384",
        name="phase4_broker_request_permit_payload_sizes",
    ),
)
sa.Index(
    "ix_phase4_broker_request_permits_account_issued",
    phase4_broker_request_permits.c.account_id,
    phase4_broker_request_permits.c.issued_at,
)
sa.Index(
    "ix_phase4_broker_request_permits_policy_issued",
    phase4_broker_request_permits.c.policy_sha256,
    phase4_broker_request_permits.c.issued_at,
)
sa.Index(
    "ux_phase4_broker_request_account_permit_semantic",
    phase4_broker_request_permits.c.account_id,
    phase4_broker_request_permits.c.permit_id,
    phase4_broker_request_permits.c.semantic_sha256,
    unique=True,
)

phase4_broker_request_heads = sa.Table(
    "phase4_broker_request_heads",
    metadata,
    sa.Column(
        "account_id",
        sa.String(64),
        sa.ForeignKey(
            "phase2_account_lease_heads.account_id",
            name="fk_phase4_broker_request_heads_account",
        ),
        primary_key=True,
    ),
    sa.Column("last_sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("last_permit_sha256", sa.String(64), nullable=False),
    sa.Column("last_issued_at", sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(
        ["account_id", "last_sequence_number", "last_permit_sha256"],
        [
            "phase4_broker_request_permits.account_id",
            "phase4_broker_request_permits.sequence_number",
            "phase4_broker_request_permits.semantic_sha256",
        ],
        name="fk_phase4_broker_request_heads_terminal_permit",
    ),
    sa.CheckConstraint(
        "last_sequence_number > 0 AND length(last_permit_sha256) = 64",
        name="phase4_broker_request_head_terminal_shape",
    ),
)

# Authenticated Alpaca paper account bindings are immutable, secret-free
# runtime facts.  Credential values never cross this boundary: only the
# operator-controlled secret reference and its nonsecret version are retained.
# The predecessor key includes the pinned provider UUID so that an account-local
# chain cannot silently transition to a different provider account.
phase4_alpaca_paper_account_bindings = sa.Table(
    "phase4_alpaca_paper_account_bindings",
    metadata,
    sa.Column("binding_id", sa.String(36), primary_key=True),
    sa.Column(
        "account_id",
        sa.String(64),
        sa.ForeignKey(
            "phase2_account_lease_heads.account_id",
            name="fk_phase4_alpaca_account_bindings_account",
        ),
        nullable=False,
    ),
    sa.Column("sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("previous_binding_sha256", sa.String(64), nullable=True),
    sa.Column("provider_id", sa.String(128), nullable=False),
    sa.Column("environment", sa.String(32), nullable=False),
    sa.Column("expected_provider_account_id", sa.String(36), nullable=False),
    sa.Column("observed_provider_account_id", sa.String(36), nullable=False),
    sa.Column("secret_ref", sa.String(256), nullable=False),
    sa.Column("secret_version", sa.String(128), nullable=False),
    sa.Column("credential_reference_sha256", sa.String(64), nullable=False),
    sa.Column("credential_resolution_sha256", sa.String(64), nullable=False),
    sa.Column("resolver_id", sa.String(128), nullable=False),
    sa.Column("resolver_version", sa.String(128), nullable=False),
    sa.Column("capability_sha256", sa.String(64), nullable=False),
    sa.Column("description_sha256", sa.String(64), nullable=False),
    sa.Column("policy_sha256", sa.String(64), nullable=False),
    sa.Column("demand_id", sa.String(64), nullable=False),
    sa.Column("demand_sha256", sa.String(64), nullable=False),
    sa.Column("permit_id", sa.String(64), nullable=False),
    sa.Column("permit_sha256", sa.String(64), nullable=False),
    sa.Column("permit_freshness_sha256", sa.String(64), nullable=False),
    sa.Column("pre_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("post_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("ingress_receipt_id", sa.String(64), nullable=False),
    sa.Column("ingress_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("observation_sha256", sa.String(64), nullable=False),
    sa.Column("transport_request_sha256", sa.String(64), nullable=False),
    sa.Column("transport_response_sha256", sa.String(64), nullable=False),
    sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("permit_checked_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("pre_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("request_started_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("raw_recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("qualified_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("post_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("evidence_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "account_id",
        "sequence_number",
        name="uq_phase4_alpaca_account_bindings_account_sequence",
    ),
    sa.UniqueConstraint(
        "account_id",
        "semantic_sha256",
        name="uq_phase4_alpaca_account_bindings_account_semantic",
    ),
    sa.UniqueConstraint(
        "account_id",
        "expected_provider_account_id",
        "semantic_sha256",
        name="uq_phase4_alpaca_account_bindings_provider_semantic",
    ),
    sa.UniqueConstraint(
        "account_id",
        "sequence_number",
        "semantic_sha256",
        "expected_provider_account_id",
        name="uq_phase4_alpaca_account_bindings_terminal",
    ),
    sa.UniqueConstraint(
        "permit_id",
        name="uq_phase4_alpaca_account_bindings_permit",
    ),
    sa.UniqueConstraint(
        "ingress_receipt_id",
        name="uq_phase4_alpaca_account_bindings_ingress_receipt",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "expected_provider_account_id",
            "previous_binding_sha256",
        ],
        [
            "phase4_alpaca_paper_account_bindings.account_id",
            "phase4_alpaca_paper_account_bindings.expected_provider_account_id",
            "phase4_alpaca_paper_account_bindings.semantic_sha256",
        ],
        name="fk_phase4_alpaca_account_bindings_predecessor",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "permit_id", "permit_sha256"],
        [
            "phase4_broker_request_permits.account_id",
            "phase4_broker_request_permits.permit_id",
            "phase4_broker_request_permits.semantic_sha256",
        ],
        name="fk_phase4_alpaca_account_bindings_permit",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "ingress_receipt_id", "ingress_receipt_sha256"],
        [
            "phase4_broker_ingress_receipts.account_id",
            "phase4_broker_ingress_receipts.receipt_id",
            "phase4_broker_ingress_receipts.semantic_sha256",
        ],
        name="fk_phase4_alpaca_account_bindings_ingress",
    ),
    sa.CheckConstraint(
        "(sequence_number = 1 AND previous_binding_sha256 IS NULL) "
        "OR (sequence_number > 1 AND previous_binding_sha256 IS NOT NULL)",
        name="phase4_alpaca_binding_predecessor_shape",
    ),
    sa.CheckConstraint(
        "provider_id = 'alpaca-paper' AND environment = 'paper'",
        name="phase4_alpaca_binding_provider_scope",
    ),
    sa.CheckConstraint(
        "expected_provider_account_id = observed_provider_account_id "
        "AND length(expected_provider_account_id) = 36 "
        "AND expected_provider_account_id = lower(expected_provider_account_id) "
        "AND substr(expected_provider_account_id, 9, 1) = '-' "
        "AND substr(expected_provider_account_id, 14, 1) = '-' "
        "AND substr(expected_provider_account_id, 19, 1) = '-' "
        "AND substr(expected_provider_account_id, 24, 1) = '-'",
        name="phase4_alpaca_binding_provider_uuid",
    ),
    sa.CheckConstraint(
        "length(secret_ref) BETWEEN 16 AND 256 "
        "AND secret_ref LIKE 'secret://paper/%' "
        "AND length(secret_version) BETWEEN 1 AND 128",
        name="phase4_alpaca_binding_secret_reference",
    ),
    sa.CheckConstraint(
        "length(resolver_id) BETWEEN 1 AND 128 AND length(resolver_version) BETWEEN 1 AND 128",
        name="phase4_alpaca_binding_resolver_identity",
    ),
    sa.CheckConstraint(
        "requested_at <= resolved_at "
        "AND resolved_at <= pre_fence_validated_at "
        "AND pre_fence_validated_at <= permit_checked_at "
        "AND permit_checked_at <= request_started_at "
        "AND request_started_at <= received_at "
        "AND received_at <= raw_recorded_at "
        "AND raw_recorded_at <= qualified_at "
        "AND qualified_at < valid_until "
        "AND valid_until <= post_fence_valid_until",
        name="phase4_alpaca_binding_time_order",
    ),
    sa.CheckConstraint(
        sa.extract("epoch", sa.column("valid_until"))
        - sa.extract("epoch", sa.column("qualified_at"))
        <= 5,
        name="phase4_alpaca_binding_max_ttl",
    ),
    sa.CheckConstraint(
        "length(binding_id) = 36 "
        "AND binding_id = lower(binding_id) "
        "AND substr(binding_id, 9, 1) = '-' "
        "AND substr(binding_id, 14, 1) = '-' "
        "AND substr(binding_id, 19, 1) = '-' "
        "AND substr(binding_id, 24, 1) = '-'",
        name="phase4_alpaca_binding_id_shape",
    ),
    sa.CheckConstraint(
        "(previous_binding_sha256 IS NULL "
        "OR length(previous_binding_sha256) = 64) "
        "AND length(credential_reference_sha256) = 64 "
        "AND length(credential_resolution_sha256) = 64 "
        "AND length(capability_sha256) = 64 "
        "AND length(description_sha256) = 64 "
        "AND length(policy_sha256) = 64 "
        "AND length(demand_id) = 64 "
        "AND length(demand_sha256) = 64 "
        "AND length(permit_id) = 64 "
        "AND length(permit_sha256) = 64 "
        "AND length(permit_freshness_sha256) = 64 "
        "AND length(pre_fence_receipt_sha256) = 64 "
        "AND length(post_fence_receipt_sha256) = 64 "
        "AND length(ingress_receipt_id) = 64 "
        "AND length(ingress_receipt_sha256) = 64 "
        "AND length(observation_sha256) = 64 "
        "AND length(transport_request_sha256) = 64 "
        "AND length(transport_response_sha256) = 64 "
        "AND length(evidence_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_alpaca_binding_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 32768",
        name="phase4_alpaca_binding_payload_size",
    ),
)
sa.Index(
    "ix_phase4_alpaca_account_bindings_account_qualified",
    phase4_alpaca_paper_account_bindings.c.account_id,
    phase4_alpaca_paper_account_bindings.c.qualified_at,
)
sa.Index(
    "ix_phase4_alpaca_account_bindings_provider_qualified",
    phase4_alpaca_paper_account_bindings.c.provider_id,
    phase4_alpaca_paper_account_bindings.c.environment,
    phase4_alpaca_paper_account_bindings.c.expected_provider_account_id,
    phase4_alpaca_paper_account_bindings.c.qualified_at,
)
sa.Index(
    "ix_phase4_alpaca_account_bindings_valid_until",
    phase4_alpaca_paper_account_bindings.c.valid_until,
)

phase4_alpaca_paper_account_binding_heads = sa.Table(
    "phase4_alpaca_paper_account_binding_heads",
    metadata,
    sa.Column(
        "account_id",
        sa.String(64),
        sa.ForeignKey(
            "phase2_account_lease_heads.account_id",
            name="fk_phase4_alpaca_account_binding_heads_account",
        ),
        primary_key=True,
    ),
    sa.Column("provider_id", sa.String(128), nullable=False),
    sa.Column("environment", sa.String(32), nullable=False),
    sa.Column("expected_provider_account_id", sa.String(36), nullable=False),
    sa.Column("last_sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("last_binding_sha256", sa.String(64), nullable=False),
    sa.Column("last_qualified_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("last_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.UniqueConstraint(
        "provider_id",
        "environment",
        "expected_provider_account_id",
        name="uq_phase4_alpaca_account_binding_heads_provider",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "last_sequence_number",
            "last_binding_sha256",
            "expected_provider_account_id",
        ],
        [
            "phase4_alpaca_paper_account_bindings.account_id",
            "phase4_alpaca_paper_account_bindings.sequence_number",
            "phase4_alpaca_paper_account_bindings.semantic_sha256",
            "phase4_alpaca_paper_account_bindings.expected_provider_account_id",
        ],
        name="fk_phase4_alpaca_account_binding_heads_terminal",
    ),
    sa.CheckConstraint(
        "provider_id = 'alpaca-paper' AND environment = 'paper'",
        name="phase4_alpaca_binding_head_provider_scope",
    ),
    sa.CheckConstraint(
        "last_sequence_number > 0 "
        "AND length(last_binding_sha256) = 64 "
        "AND length(expected_provider_account_id) = 36",
        name="phase4_alpaca_binding_head_terminal_shape",
    ),
    sa.CheckConstraint(
        "last_qualified_at < last_valid_until",
        name="phase4_alpaca_binding_head_time_order",
    ),
)
sa.Index(
    "ix_phase4_alpaca_account_binding_heads_valid_until",
    phase4_alpaca_paper_account_binding_heads.c.last_valid_until,
)

# Authenticated Alpaca paper asset bindings retain one short-lived,
# operator-pinned local-instrument/provider-asset proof.  Histories are
# instrument-local while writes still use the shared account serialization
# boundary.  The exact account-binding index lets the child row authenticate
# the parent row identity, semantic digest, account, and provider-account pin.
sa.Index(
    "ux_phase4_alpaca_account_binding_exact",
    phase4_alpaca_paper_account_bindings.c.account_id,
    phase4_alpaca_paper_account_bindings.c.binding_id,
    phase4_alpaca_paper_account_bindings.c.semantic_sha256,
    phase4_alpaca_paper_account_bindings.c.expected_provider_account_id,
    unique=True,
)

phase4_alpaca_paper_asset_bindings = sa.Table(
    "phase4_alpaca_paper_asset_bindings",
    metadata,
    sa.Column("binding_id", sa.String(36), primary_key=True),
    sa.Column(
        "account_id",
        sa.String(64),
        sa.ForeignKey(
            "phase2_account_lease_heads.account_id",
            name="fk_phase4_alpaca_asset_bindings_account",
        ),
        nullable=False,
    ),
    sa.Column(
        "instrument_id",
        sa.String(64),
        sa.ForeignKey(
            "instruments.instrument_id",
            name="fk_phase4_alpaca_asset_bindings_instrument",
        ),
        nullable=False,
    ),
    sa.Column("sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("previous_binding_sha256", sa.String(64), nullable=True),
    sa.Column("provider_id", sa.String(128), nullable=False),
    sa.Column("environment", sa.String(32), nullable=False),
    sa.Column("expected_provider_account_id", sa.String(36), nullable=False),
    sa.Column("symbol", sa.String(32), nullable=False),
    sa.Column("expected_provider_asset_id", sa.String(36), nullable=False),
    sa.Column("observed_provider_asset_id", sa.String(36), nullable=False),
    sa.Column("asset_class", sa.String(32), nullable=False),
    sa.Column("exchange", sa.String(16), nullable=False),
    sa.Column("asset_status", sa.String(16), nullable=False),
    sa.Column("tradable", sa.Boolean(), nullable=False),
    sa.Column("secret_ref", sa.String(256), nullable=False),
    sa.Column("secret_version", sa.String(128), nullable=False),
    sa.Column("credential_reference_sha256", sa.String(64), nullable=False),
    sa.Column("security_reference_sha256", sa.String(64), nullable=False),
    sa.Column("credential_resolution_sha256", sa.String(64), nullable=False),
    sa.Column("resolver_id", sa.String(128), nullable=False),
    sa.Column("resolver_version", sa.String(128), nullable=False),
    sa.Column("capability_sha256", sa.String(64), nullable=False),
    sa.Column("account_binding_id", sa.String(36), nullable=False),
    sa.Column("account_binding_sha256", sa.String(64), nullable=False),
    sa.Column("pre_account_binding_freshness_sha256", sa.String(64), nullable=False),
    sa.Column("post_account_binding_freshness_sha256", sa.String(64), nullable=False),
    sa.Column("description_sha256", sa.String(64), nullable=False),
    sa.Column("policy_sha256", sa.String(64), nullable=False),
    sa.Column("demand_id", sa.String(64), nullable=False),
    sa.Column("demand_sha256", sa.String(64), nullable=False),
    sa.Column("permit_id", sa.String(64), nullable=False),
    sa.Column("permit_sha256", sa.String(64), nullable=False),
    sa.Column("permit_freshness_sha256", sa.String(64), nullable=False),
    sa.Column("pre_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("post_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("ingress_receipt_id", sa.String(64), nullable=False),
    sa.Column("ingress_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("observation_sha256", sa.String(64), nullable=False),
    sa.Column("transport_request_sha256", sa.String(64), nullable=False),
    sa.Column("transport_response_sha256", sa.String(64), nullable=False),
    sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("pre_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("permit_checked_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("pre_account_binding_checked_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("request_started_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("raw_recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("post_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("post_account_binding_checked_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("account_binding_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("post_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("qualified_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("evidence_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "account_id",
        "instrument_id",
        "sequence_number",
        name="uq_phase4_alpaca_asset_bindings_instrument_sequence",
    ),
    sa.UniqueConstraint(
        "account_id",
        "instrument_id",
        "semantic_sha256",
        name="uq_phase4_alpaca_asset_bindings_instrument_semantic",
    ),
    sa.UniqueConstraint(
        "account_id",
        "instrument_id",
        "expected_provider_asset_id",
        "semantic_sha256",
        name="uq_phase4_alpaca_asset_bindings_predecessor_target",
    ),
    sa.UniqueConstraint(
        "account_id",
        "instrument_id",
        "sequence_number",
        "semantic_sha256",
        "expected_provider_asset_id",
        name="uq_phase4_alpaca_asset_bindings_terminal",
    ),
    sa.UniqueConstraint(
        "permit_id",
        name="uq_phase4_alpaca_asset_bindings_permit",
    ),
    sa.UniqueConstraint(
        "ingress_receipt_id",
        name="uq_phase4_alpaca_asset_bindings_ingress_receipt",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "instrument_id",
            "expected_provider_asset_id",
            "previous_binding_sha256",
        ],
        [
            "phase4_alpaca_paper_asset_bindings.account_id",
            "phase4_alpaca_paper_asset_bindings.instrument_id",
            "phase4_alpaca_paper_asset_bindings.expected_provider_asset_id",
            "phase4_alpaca_paper_asset_bindings.semantic_sha256",
        ],
        name="fk_phase4_alpaca_asset_bindings_predecessor",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "account_binding_id",
            "account_binding_sha256",
            "expected_provider_account_id",
        ],
        [
            "phase4_alpaca_paper_account_bindings.account_id",
            "phase4_alpaca_paper_account_bindings.binding_id",
            "phase4_alpaca_paper_account_bindings.semantic_sha256",
            "phase4_alpaca_paper_account_bindings.expected_provider_account_id",
        ],
        name="fk_phase4_alpaca_asset_bindings_account_binding",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "permit_id", "permit_sha256"],
        [
            "phase4_broker_request_permits.account_id",
            "phase4_broker_request_permits.permit_id",
            "phase4_broker_request_permits.semantic_sha256",
        ],
        name="fk_phase4_alpaca_asset_bindings_permit",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "ingress_receipt_id", "ingress_receipt_sha256"],
        [
            "phase4_broker_ingress_receipts.account_id",
            "phase4_broker_ingress_receipts.receipt_id",
            "phase4_broker_ingress_receipts.semantic_sha256",
        ],
        name="fk_phase4_alpaca_asset_bindings_ingress",
    ),
    sa.CheckConstraint(
        "(sequence_number = 1 AND previous_binding_sha256 IS NULL) "
        "OR (sequence_number > 1 AND previous_binding_sha256 IS NOT NULL)",
        name="phase4_alpaca_asset_binding_predecessor_shape",
    ),
    sa.CheckConstraint(
        "provider_id = 'alpaca-paper' AND environment = 'paper'",
        name="phase4_alpaca_asset_binding_provider_scope",
    ),
    sa.CheckConstraint(
        "expected_provider_asset_id = observed_provider_asset_id "
        "AND length(expected_provider_asset_id) = 36 "
        "AND expected_provider_asset_id = lower(expected_provider_asset_id) "
        "AND substr(expected_provider_asset_id, 9, 1) = '-' "
        "AND substr(expected_provider_asset_id, 14, 1) = '-' "
        "AND substr(expected_provider_asset_id, 19, 1) = '-' "
        "AND substr(expected_provider_asset_id, 24, 1) = '-'",
        name="phase4_alpaca_asset_binding_provider_asset_uuid",
    ),
    sa.CheckConstraint(
        "length(expected_provider_account_id) = 36 "
        "AND expected_provider_account_id = lower(expected_provider_account_id) "
        "AND substr(expected_provider_account_id, 9, 1) = '-' "
        "AND substr(expected_provider_account_id, 14, 1) = '-' "
        "AND substr(expected_provider_account_id, 19, 1) = '-' "
        "AND substr(expected_provider_account_id, 24, 1) = '-'",
        name="phase4_alpaca_asset_binding_provider_account_uuid",
    ),
    sa.CheckConstraint(
        "length(symbol) BETWEEN 1 AND 32 AND symbol = upper(symbol)",
        name="phase4_alpaca_asset_binding_symbol_shape",
    ),
    sa.CheckConstraint(
        "asset_class = 'us_equity' "
        "AND exchange IN ('AMEX', 'ARCA', 'BATS', 'NYSE', 'NASDAQ', 'NYSEARCA') "
        "AND asset_status = 'active' AND tradable",
        name="phase4_alpaca_asset_binding_qualified_state",
    ),
    sa.CheckConstraint(
        "length(secret_ref) BETWEEN 16 AND 256 "
        "AND secret_ref LIKE 'secret://paper/%' "
        "AND length(secret_version) BETWEEN 1 AND 128",
        name="phase4_alpaca_asset_binding_secret_reference",
    ),
    sa.CheckConstraint(
        "length(resolver_id) BETWEEN 1 AND 128 AND length(resolver_version) BETWEEN 1 AND 128",
        name="phase4_alpaca_asset_binding_resolver_identity",
    ),
    sa.CheckConstraint(
        "requested_at <= resolved_at "
        "AND resolved_at <= pre_fence_validated_at "
        "AND pre_fence_validated_at <= permit_checked_at "
        "AND permit_checked_at <= pre_account_binding_checked_at "
        "AND pre_account_binding_checked_at <= request_started_at "
        "AND request_started_at <= received_at "
        "AND received_at <= raw_recorded_at "
        "AND raw_recorded_at <= post_fence_validated_at "
        "AND post_fence_validated_at <= post_account_binding_checked_at "
        "AND post_account_binding_checked_at = qualified_at "
        "AND qualified_at < valid_until "
        "AND valid_until <= account_binding_valid_until "
        "AND valid_until <= post_fence_valid_until",
        name="phase4_alpaca_asset_binding_time_order",
    ),
    sa.CheckConstraint(
        sa.extract("epoch", sa.column("valid_until"))
        - sa.extract("epoch", sa.column("qualified_at"))
        <= 5,
        name="phase4_alpaca_asset_binding_max_ttl",
    ),
    sa.CheckConstraint(
        "length(binding_id) = 36 "
        "AND binding_id = lower(binding_id) "
        "AND substr(binding_id, 9, 1) = '-' "
        "AND substr(binding_id, 14, 1) = '-' "
        "AND substr(binding_id, 19, 1) = '-' "
        "AND substr(binding_id, 24, 1) = '-' "
        "AND length(account_binding_id) = 36",
        name="phase4_alpaca_asset_binding_id_shape",
    ),
    sa.CheckConstraint(
        "(previous_binding_sha256 IS NULL "
        "OR length(previous_binding_sha256) = 64) "
        "AND length(credential_reference_sha256) = 64 "
        "AND length(security_reference_sha256) = 64 "
        "AND length(credential_resolution_sha256) = 64 "
        "AND length(capability_sha256) = 64 "
        "AND length(account_binding_sha256) = 64 "
        "AND length(pre_account_binding_freshness_sha256) = 64 "
        "AND length(post_account_binding_freshness_sha256) = 64 "
        "AND length(description_sha256) = 64 "
        "AND length(policy_sha256) = 64 "
        "AND length(demand_id) = 64 "
        "AND length(demand_sha256) = 64 "
        "AND length(permit_id) = 64 "
        "AND length(permit_sha256) = 64 "
        "AND length(permit_freshness_sha256) = 64 "
        "AND length(pre_fence_receipt_sha256) = 64 "
        "AND length(post_fence_receipt_sha256) = 64 "
        "AND length(ingress_receipt_id) = 64 "
        "AND length(ingress_receipt_sha256) = 64 "
        "AND length(observation_sha256) = 64 "
        "AND length(transport_request_sha256) = 64 "
        "AND length(transport_response_sha256) = 64 "
        "AND length(evidence_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_alpaca_asset_binding_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 65536",
        name="phase4_alpaca_asset_binding_payload_size",
    ),
)
sa.Index(
    "ix_phase4_alpaca_asset_bindings_instrument_qualified",
    phase4_alpaca_paper_asset_bindings.c.account_id,
    phase4_alpaca_paper_asset_bindings.c.instrument_id,
    phase4_alpaca_paper_asset_bindings.c.qualified_at,
)
sa.Index(
    "ix_phase4_alpaca_asset_bindings_provider_asset",
    phase4_alpaca_paper_asset_bindings.c.provider_id,
    phase4_alpaca_paper_asset_bindings.c.environment,
    phase4_alpaca_paper_asset_bindings.c.expected_provider_asset_id,
)
sa.Index(
    "ix_phase4_alpaca_asset_bindings_valid_until",
    phase4_alpaca_paper_asset_bindings.c.valid_until,
)

phase4_alpaca_paper_asset_binding_heads = sa.Table(
    "phase4_alpaca_paper_asset_binding_heads",
    metadata,
    sa.Column(
        "account_id",
        sa.String(64),
        sa.ForeignKey(
            "phase2_account_lease_heads.account_id",
            name="fk_phase4_alpaca_asset_binding_heads_account",
        ),
        primary_key=True,
    ),
    sa.Column(
        "instrument_id",
        sa.String(64),
        sa.ForeignKey(
            "instruments.instrument_id",
            name="fk_phase4_alpaca_asset_binding_heads_instrument",
        ),
        primary_key=True,
    ),
    sa.Column("provider_id", sa.String(128), nullable=False),
    sa.Column("environment", sa.String(32), nullable=False),
    sa.Column("expected_provider_account_id", sa.String(36), nullable=False),
    sa.Column("symbol", sa.String(32), nullable=False),
    sa.Column("expected_provider_asset_id", sa.String(36), nullable=False),
    sa.Column("last_sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("last_binding_sha256", sa.String(64), nullable=False),
    sa.Column("last_qualified_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("last_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.UniqueConstraint(
        "account_id",
        "expected_provider_asset_id",
        name="uq_phase4_alpaca_asset_binding_heads_provider_asset",
    ),
    sa.UniqueConstraint(
        "account_id",
        "symbol",
        name="uq_phase4_alpaca_asset_binding_heads_symbol",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "instrument_id",
            "last_sequence_number",
            "last_binding_sha256",
            "expected_provider_asset_id",
        ],
        [
            "phase4_alpaca_paper_asset_bindings.account_id",
            "phase4_alpaca_paper_asset_bindings.instrument_id",
            "phase4_alpaca_paper_asset_bindings.sequence_number",
            "phase4_alpaca_paper_asset_bindings.semantic_sha256",
            "phase4_alpaca_paper_asset_bindings.expected_provider_asset_id",
        ],
        name="fk_phase4_alpaca_asset_binding_heads_terminal",
    ),
    sa.CheckConstraint(
        "provider_id = 'alpaca-paper' AND environment = 'paper'",
        name="phase4_alpaca_asset_binding_head_provider_scope",
    ),
    sa.CheckConstraint(
        "last_sequence_number > 0 "
        "AND length(last_binding_sha256) = 64 "
        "AND length(expected_provider_account_id) = 36 "
        "AND length(expected_provider_asset_id) = 36 "
        "AND length(symbol) BETWEEN 1 AND 32",
        name="phase4_alpaca_asset_binding_head_terminal_shape",
    ),
    sa.CheckConstraint(
        "last_qualified_at < last_valid_until",
        name="phase4_alpaca_asset_binding_head_time_order",
    ),
)
sa.Index(
    "ix_phase4_alpaca_asset_binding_heads_valid_until",
    phase4_alpaca_paper_asset_binding_heads.c.last_valid_until,
)

# Authenticated client-order lookups are historical recovery observations for
# one exact UNKNOWN event.  Each attempt owns an append-only receipt chain,
# while all writes share the account serialization boundary with request
# permits, raw ingress, account bindings, and submission lifecycle changes.
phase4_alpaca_paper_lookup_observations = sa.Table(
    "phase4_alpaca_paper_lookup_observations",
    metadata,
    sa.Column("receipt_id", sa.String(36), primary_key=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("provider_id", sa.String(128), nullable=False),
    sa.Column("environment", sa.String(32), nullable=False),
    sa.Column("attempt_id", sa.String(64), nullable=False),
    sa.Column("attempt_sha256", sa.String(64), nullable=False),
    sa.Column("terminal_event_id", sa.String(64), nullable=False),
    sa.Column("terminal_event_sha256", sa.String(64), nullable=False),
    sa.Column("terminal_event_sequence", sa.BigInteger(), nullable=False),
    sa.Column("parent_decision_id", sa.String(64), nullable=False),
    sa.Column("reservation_id", sa.String(64), nullable=False),
    sa.Column("order_id", sa.String(64), nullable=False),
    sa.Column("client_order_id", sa.String(64), nullable=False),
    sa.Column("instrument_id", sa.String(64), nullable=False),
    sa.Column("symbol", sa.String(32), nullable=False),
    sa.Column("expected_provider_account_id", sa.String(36), nullable=False),
    sa.Column("expected_provider_asset_id", sa.String(36), nullable=False),
    sa.Column("outcome", sa.String(64), nullable=False),
    sa.Column("provider_order_id", sa.String(128), nullable=True),
    sa.Column("provider_order_status", sa.String(64), nullable=True),
    sa.Column("observed_provider_asset_id", sa.String(36), nullable=True),
    sa.Column("mismatch_fields_payload", sa.Text(), nullable=False),
    sa.Column("secret_ref", sa.String(256), nullable=False),
    sa.Column("secret_version", sa.String(128), nullable=False),
    sa.Column("credential_reference_sha256", sa.String(64), nullable=False),
    sa.Column("security_reference_sha256", sa.String(64), nullable=False),
    sa.Column("credential_resolution_sha256", sa.String(64), nullable=False),
    sa.Column("resolver_id", sa.String(128), nullable=False),
    sa.Column("resolver_version", sa.String(128), nullable=False),
    sa.Column("capability_sha256", sa.String(64), nullable=False),
    sa.Column("account_binding_id", sa.String(36), nullable=False),
    sa.Column("account_binding_sha256", sa.String(64), nullable=False),
    sa.Column("pre_attempt_freshness_sha256", sa.String(64), nullable=False),
    sa.Column("post_attempt_freshness_sha256", sa.String(64), nullable=False),
    sa.Column("pre_account_identity_sha256", sa.String(64), nullable=False),
    sa.Column("post_account_identity_sha256", sa.String(64), nullable=False),
    sa.Column("description_sha256", sa.String(64), nullable=False),
    sa.Column("submission_sha256", sa.String(64), nullable=False),
    sa.Column("policy_sha256", sa.String(64), nullable=False),
    sa.Column("demand_id", sa.String(64), nullable=False),
    sa.Column("demand_sha256", sa.String(64), nullable=False),
    sa.Column("permit_id", sa.String(64), nullable=False),
    sa.Column("permit_sha256", sa.String(64), nullable=False),
    sa.Column("permit_freshness_sha256", sa.String(64), nullable=False),
    sa.Column("fence_owner_id", sa.String(128), nullable=False),
    sa.Column("fence_lease_id", sa.String(64), nullable=False),
    sa.Column("fence_fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column("fence_policy_sha256", sa.String(64), nullable=False),
    sa.Column("pre_fence_lease_sha256", sa.String(64), nullable=False),
    sa.Column("post_fence_lease_sha256", sa.String(64), nullable=False),
    sa.Column("pre_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("post_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("ingress_receipt_id", sa.String(64), nullable=False),
    sa.Column("ingress_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("observation_sha256", sa.String(64), nullable=False),
    sa.Column("transport_request_sha256", sa.String(64), nullable=False),
    sa.Column("transport_response_sha256", sa.String(64), nullable=False),
    sa.Column("http_status", sa.Integer(), nullable=False),
    sa.Column("provider_request_id", sa.String(256), nullable=False),
    sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column(
        "credential_resolution_started_at",
        sa.DateTime(timezone=True),
        nullable=False,
    ),
    sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column(
        "credential_resolution_valid_until",
        sa.DateTime(timezone=True),
        nullable=False,
    ),
    sa.Column("permit_checked_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("pre_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("pre_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("pre_attempt_checked_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column(
        "pre_account_identity_checked_at",
        sa.DateTime(timezone=True),
        nullable=False,
    ),
    sa.Column("request_started_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("raw_recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("post_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("post_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("post_attempt_checked_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column(
        "post_account_identity_checked_at",
        sa.DateTime(timezone=True),
        nullable=False,
    ),
    sa.Column("authenticated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("commit_checked_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("previous_receipt_sha256", sa.String(64), nullable=True),
    sa.Column("evidence_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "account_id",
        "attempt_id",
        "sequence_number",
        name="uq_phase4_alpaca_lookup_attempt_sequence",
    ),
    sa.UniqueConstraint(
        "account_id",
        "attempt_id",
        "semantic_sha256",
        name="uq_phase4_alpaca_lookup_attempt_semantic",
    ),
    sa.UniqueConstraint(
        "account_id",
        "attempt_id",
        "sequence_number",
        "semantic_sha256",
        "terminal_event_id",
        "terminal_event_sha256",
        name="uq_phase4_alpaca_lookup_terminal",
    ),
    sa.UniqueConstraint(
        "permit_id",
        name="uq_phase4_alpaca_lookup_permit",
    ),
    sa.UniqueConstraint(
        "ingress_receipt_id",
        name="uq_phase4_alpaca_lookup_ingress",
    ),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase4_alpaca_lookup_account",
    ),
    sa.ForeignKeyConstraint(
        ["attempt_id"],
        ["phase2_submission_attempts.attempt_id"],
        name="fk_phase4_alpaca_lookup_attempt",
    ),
    sa.ForeignKeyConstraint(
        ["attempt_id", "terminal_event_id", "terminal_event_sha256"],
        [
            "phase2_submission_attempt_events.attempt_id",
            "phase2_submission_attempt_events.event_id",
            "phase2_submission_attempt_events.semantic_sha256",
        ],
        name="fk_phase4_alpaca_lookup_unknown_event",
    ),
    sa.ForeignKeyConstraint(
        ["instrument_id"],
        ["instruments.instrument_id"],
        name="fk_phase4_alpaca_lookup_instrument",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "account_binding_id",
            "account_binding_sha256",
            "expected_provider_account_id",
        ],
        [
            "phase4_alpaca_paper_account_bindings.account_id",
            "phase4_alpaca_paper_account_bindings.binding_id",
            "phase4_alpaca_paper_account_bindings.semantic_sha256",
            "phase4_alpaca_paper_account_bindings.expected_provider_account_id",
        ],
        name="fk_phase4_alpaca_lookup_account_binding",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "permit_id", "permit_sha256"],
        [
            "phase4_broker_request_permits.account_id",
            "phase4_broker_request_permits.permit_id",
            "phase4_broker_request_permits.semantic_sha256",
        ],
        name="fk_phase4_alpaca_lookup_permit",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "ingress_receipt_id", "ingress_receipt_sha256"],
        [
            "phase4_broker_ingress_receipts.account_id",
            "phase4_broker_ingress_receipts.receipt_id",
            "phase4_broker_ingress_receipts.semantic_sha256",
        ],
        name="fk_phase4_alpaca_lookup_ingress",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "fence_fencing_generation",
            "pre_fence_lease_sha256",
        ],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase4_alpaca_lookup_pre_fence_lease",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "fence_fencing_generation",
            "post_fence_lease_sha256",
        ],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase4_alpaca_lookup_post_fence_lease",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "attempt_id",
            "previous_receipt_sha256",
        ],
        [
            "phase4_alpaca_paper_lookup_observations.account_id",
            "phase4_alpaca_paper_lookup_observations.attempt_id",
            "phase4_alpaca_paper_lookup_observations.semantic_sha256",
        ],
        name="fk_phase4_alpaca_lookup_predecessor",
    ),
    sa.CheckConstraint(
        "(sequence_number = 1 AND previous_receipt_sha256 IS NULL) "
        "OR (sequence_number > 1 AND previous_receipt_sha256 IS NOT NULL)",
        name="phase4_alpaca_lookup_predecessor_shape",
    ),
    sa.CheckConstraint(
        "provider_id = 'alpaca-paper' AND environment = 'paper'",
        name="phase4_alpaca_lookup_provider_scope",
    ),
    sa.CheckConstraint(
        "outcome IN ('found_matched', 'found_mismatch', "
        "'security_identity_mismatch', "
        "'not_visible_inconclusive')",
        name="phase4_alpaca_lookup_outcome",
    ),
    sa.CheckConstraint(
        "(http_status = 404 AND outcome = 'not_visible_inconclusive' "
        "AND provider_order_id IS NULL "
        "AND provider_order_status IS NULL "
        "AND observed_provider_asset_id IS NULL "
        'AND mismatch_fields_payload = \'{"type":"tuple","value":[]}\') '
        "OR (http_status = 200 AND outcome = 'found_matched' "
        "AND provider_order_id IS NOT NULL "
        "AND provider_order_status IS NOT NULL "
        "AND observed_provider_asset_id IS NOT NULL "
        "AND observed_provider_asset_id = expected_provider_asset_id "
        'AND mismatch_fields_payload = \'{"type":"tuple","value":[]}\') '
        "OR (http_status = 200 AND outcome = 'found_mismatch' "
        "AND provider_order_id IS NOT NULL "
        "AND provider_order_status IS NOT NULL "
        "AND observed_provider_asset_id IS NOT NULL "
        "AND observed_provider_asset_id = expected_provider_asset_id "
        'AND mismatch_fields_payload <> \'{"type":"tuple","value":[]}\') '
        "OR (http_status = 200 AND outcome = 'security_identity_mismatch' "
        "AND provider_order_id IS NOT NULL "
        "AND provider_order_status IS NOT NULL "
        "AND (observed_provider_asset_id IS NULL "
        "OR observed_provider_asset_id <> expected_provider_asset_id))",
        name="phase4_alpaca_lookup_http_shape",
    ),
    sa.CheckConstraint(
        "terminal_event_sequence > 0 AND fence_fencing_generation > 0 AND sequence_number > 0",
        name="phase4_alpaca_lookup_positive_sequences",
    ),
    sa.CheckConstraint(
        "length(symbol) BETWEEN 1 AND 32 AND symbol = upper(symbol)",
        name="phase4_alpaca_lookup_symbol",
    ),
    sa.CheckConstraint(
        "length(secret_ref) BETWEEN 16 AND 256 "
        "AND secret_ref LIKE 'secret://paper/%' "
        "AND length(secret_version) BETWEEN 1 AND 128 "
        "AND length(resolver_id) BETWEEN 1 AND 128 "
        "AND length(resolver_version) BETWEEN 1 AND 128",
        name="phase4_alpaca_lookup_reference_shape",
    ),
    sa.CheckConstraint(
        "length(receipt_id) = 36 "
        "AND receipt_id = lower(receipt_id) "
        "AND length(expected_provider_account_id) = 36 "
        "AND expected_provider_account_id = lower(expected_provider_account_id) "
        "AND length(expected_provider_asset_id) = 36 "
        "AND expected_provider_asset_id = lower(expected_provider_asset_id) "
        "AND (observed_provider_asset_id IS NULL "
        "OR (length(observed_provider_asset_id) = 36 "
        "AND observed_provider_asset_id = lower(observed_provider_asset_id))) "
        "AND length(account_binding_id) = 36",
        name="phase4_alpaca_lookup_uuid_shape",
    ),
    sa.CheckConstraint(
        "requested_at <= credential_resolution_started_at "
        "AND credential_resolution_started_at <= resolved_at "
        "AND resolved_at < credential_resolution_valid_until "
        "AND resolved_at <= pre_fence_validated_at "
        "AND pre_fence_validated_at < pre_fence_valid_until "
        "AND pre_fence_validated_at <= permit_checked_at "
        "AND permit_checked_at <= pre_attempt_checked_at "
        "AND pre_attempt_checked_at <= pre_account_identity_checked_at "
        "AND pre_account_identity_checked_at <= request_started_at "
        "AND request_started_at < credential_resolution_valid_until "
        "AND request_started_at <= received_at "
        "AND received_at < credential_resolution_valid_until "
        "AND received_at < pre_fence_valid_until "
        "AND received_at <= raw_recorded_at "
        "AND raw_recorded_at <= post_fence_validated_at "
        "AND post_fence_validated_at < post_fence_valid_until "
        "AND post_fence_validated_at <= post_attempt_checked_at "
        "AND post_attempt_checked_at <= post_account_identity_checked_at "
        "AND post_account_identity_checked_at <= authenticated_at "
        "AND authenticated_at <= commit_checked_at "
        "AND commit_checked_at < post_fence_valid_until",
        name="phase4_alpaca_lookup_time_order",
    ),
    sa.CheckConstraint(
        "(previous_receipt_sha256 IS NULL "
        "OR length(previous_receipt_sha256) = 64) "
        "AND length(attempt_sha256) = 64 "
        "AND length(terminal_event_sha256) = 64 "
        "AND length(credential_reference_sha256) = 64 "
        "AND length(security_reference_sha256) = 64 "
        "AND length(credential_resolution_sha256) = 64 "
        "AND length(capability_sha256) = 64 "
        "AND length(account_binding_sha256) = 64 "
        "AND length(pre_attempt_freshness_sha256) = 64 "
        "AND length(post_attempt_freshness_sha256) = 64 "
        "AND length(pre_account_identity_sha256) = 64 "
        "AND length(post_account_identity_sha256) = 64 "
        "AND length(description_sha256) = 64 "
        "AND length(submission_sha256) = 64 "
        "AND length(policy_sha256) = 64 "
        "AND length(demand_id) = 64 "
        "AND length(demand_sha256) = 64 "
        "AND length(permit_id) = 64 "
        "AND length(permit_sha256) = 64 "
        "AND length(permit_freshness_sha256) = 64 "
        "AND length(fence_sha256) = 64 "
        "AND length(fence_policy_sha256) = 64 "
        "AND length(pre_fence_lease_sha256) = 64 "
        "AND length(post_fence_lease_sha256) = 64 "
        "AND length(pre_fence_receipt_sha256) = 64 "
        "AND length(post_fence_receipt_sha256) = 64 "
        "AND length(ingress_receipt_id) = 64 "
        "AND length(ingress_receipt_sha256) = 64 "
        "AND length(observation_sha256) = 64 "
        "AND length(transport_request_sha256) = 64 "
        "AND length(transport_response_sha256) = 64 "
        "AND length(evidence_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_alpaca_lookup_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(mismatch_fields_payload) BETWEEN 2 AND 4096 "
        "AND length(canonical_payload) BETWEEN 2 AND 131072",
        name="phase4_alpaca_lookup_payload_sizes",
    ),
)
sa.Index(
    "ix_phase4_alpaca_lookup_attempt_authenticated",
    phase4_alpaca_paper_lookup_observations.c.account_id,
    phase4_alpaca_paper_lookup_observations.c.attempt_id,
    phase4_alpaca_paper_lookup_observations.c.authenticated_at,
)
sa.Index(
    "ix_phase4_alpaca_lookup_provider_order",
    phase4_alpaca_paper_lookup_observations.c.provider_id,
    phase4_alpaca_paper_lookup_observations.c.environment,
    phase4_alpaca_paper_lookup_observations.c.provider_order_id,
)

phase4_alpaca_paper_lookup_observation_heads = sa.Table(
    "phase4_alpaca_paper_lookup_observation_heads",
    metadata,
    sa.Column("account_id", sa.String(64), primary_key=True),
    sa.Column("attempt_id", sa.String(64), primary_key=True),
    sa.Column("terminal_event_id", sa.String(64), nullable=False),
    sa.Column("terminal_event_sha256", sa.String(64), nullable=False),
    sa.Column("last_sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("last_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("last_authenticated_at", sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase4_alpaca_lookup_heads_account",
    ),
    sa.ForeignKeyConstraint(
        ["attempt_id"],
        ["phase2_submission_attempts.attempt_id"],
        name="fk_phase4_alpaca_lookup_heads_attempt",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "attempt_id",
            "last_sequence_number",
            "last_receipt_sha256",
            "terminal_event_id",
            "terminal_event_sha256",
        ],
        [
            "phase4_alpaca_paper_lookup_observations.account_id",
            "phase4_alpaca_paper_lookup_observations.attempt_id",
            "phase4_alpaca_paper_lookup_observations.sequence_number",
            "phase4_alpaca_paper_lookup_observations.semantic_sha256",
            "phase4_alpaca_paper_lookup_observations.terminal_event_id",
            "phase4_alpaca_paper_lookup_observations.terminal_event_sha256",
        ],
        name="fk_phase4_alpaca_lookup_heads_terminal",
    ),
    sa.CheckConstraint(
        "last_sequence_number > 0 "
        "AND length(last_receipt_sha256) = 64 "
        "AND length(terminal_event_sha256) = 64",
        name="phase4_alpaca_lookup_head_shape",
    ),
)

# Phase 4J recovery plans freeze the bounded delayed-lookup schedule for one
# exact IN_FLIGHT -> UNKNOWN submission transition.  Schedule decisions form an
# immutable per-plan event chain.  The head is only a lockable projection; a
# plan may exist without a head until its first DISPATCH or EXHAUSTED decision.
sa.Index(
    "ux_phase2_submission_attempt_recovery_source",
    phase2_submission_attempts.c.account_id,
    phase2_submission_attempts.c.attempt_id,
    phase2_submission_attempts.c.client_order_id,
    unique=True,
)
sa.Index(
    "ux_phase4_lookup_observation_recovery_exact",
    phase4_alpaca_paper_lookup_observations.c.account_id,
    phase4_alpaca_paper_lookup_observations.c.attempt_id,
    phase4_alpaca_paper_lookup_observations.c.receipt_id,
    phase4_alpaca_paper_lookup_observations.c.semantic_sha256,
    unique=True,
)

phase4_unknown_lookup_recovery_plans = sa.Table(
    "phase4_unknown_lookup_recovery_plans",
    metadata,
    sa.Column("plan_id", sa.String(64), primary_key=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("attempt_id", sa.String(64), nullable=False),
    sa.Column("attempt_sha256", sa.String(64), nullable=False),
    sa.Column("client_order_id", sa.String(128), nullable=False),
    sa.Column("lookup_correlation_sha256", sa.String(64), nullable=False),
    sa.Column("in_flight_event_id", sa.String(64), nullable=False),
    sa.Column("in_flight_event_sha256", sa.String(64), nullable=False),
    sa.Column("in_flight_sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("in_flight_occurred_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("in_flight_recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("unknown_event_id", sa.String(64), nullable=False),
    sa.Column("unknown_event_sha256", sa.String(64), nullable=False),
    sa.Column("unknown_sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("unknown_occurred_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("unknown_recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("recovery_deadline_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("slot_count", sa.Integer(), nullable=False),
    sa.Column("slots_payload", sa.Text(), nullable=False),
    sa.Column("slots_sha256", sa.String(64), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "account_id",
        "attempt_id",
        "unknown_event_id",
        name="uq_phase4_unknown_recovery_attempt_event",
    ),
    sa.UniqueConstraint(
        "plan_id",
        "account_id",
        "attempt_id",
        "semantic_sha256",
        name="uq_phase4_unknown_recovery_plan_exact",
    ),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase4_unknown_recovery_account",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "attempt_id", "client_order_id"],
        [
            "phase2_submission_attempts.account_id",
            "phase2_submission_attempts.attempt_id",
            "phase2_submission_attempts.client_order_id",
        ],
        name="fk_phase4_unknown_recovery_attempt",
    ),
    sa.ForeignKeyConstraint(
        ["attempt_id", "in_flight_event_id", "in_flight_event_sha256"],
        [
            "phase2_submission_attempt_events.attempt_id",
            "phase2_submission_attempt_events.event_id",
            "phase2_submission_attempt_events.semantic_sha256",
        ],
        name="fk_phase4_unknown_recovery_in_flight",
    ),
    sa.ForeignKeyConstraint(
        ["attempt_id", "unknown_event_id", "unknown_event_sha256"],
        [
            "phase2_submission_attempt_events.attempt_id",
            "phase2_submission_attempt_events.event_id",
            "phase2_submission_attempt_events.semantic_sha256",
        ],
        name="fk_phase4_unknown_recovery_unknown",
    ),
    sa.CheckConstraint(
        "in_flight_sequence_number = 2 AND unknown_sequence_number = 3",
        name="phase4_unknown_recovery_source_sequence",
    ),
    sa.CheckConstraint(
        "in_flight_occurred_at <= in_flight_recorded_at "
        "AND in_flight_occurred_at <= unknown_occurred_at "
        "AND in_flight_recorded_at <= unknown_recorded_at "
        "AND unknown_occurred_at <= unknown_recorded_at",
        name="phase4_unknown_recovery_source_time",
    ),
    sa.CheckConstraint(
        "slot_count BETWEEN 0 AND 6",
        name="phase4_unknown_recovery_slot_count",
    ),
    sa.CheckConstraint(
        "length(plan_id) = 64 "
        "AND length(attempt_sha256) = 64 "
        "AND length(lookup_correlation_sha256) = 64 "
        "AND length(in_flight_event_sha256) = 64 "
        "AND length(unknown_event_sha256) = 64 "
        "AND length(slots_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_unknown_recovery_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(slots_payload) BETWEEN 2 AND 32768 "
        "AND length(canonical_payload) BETWEEN 2 AND 65536",
        name="phase4_unknown_recovery_payload_sizes",
    ),
)
sa.Index(
    "ix_phase4_unknown_recovery_account_deadline",
    phase4_unknown_lookup_recovery_plans.c.account_id,
    phase4_unknown_lookup_recovery_plans.c.recovery_deadline_at,
)

phase4_unknown_lookup_recovery_events = sa.Table(
    "phase4_unknown_lookup_recovery_events",
    metadata,
    sa.Column("event_id", sa.String(64), primary_key=True),
    sa.Column("plan_id", sa.String(64), nullable=False),
    sa.Column("plan_sha256", sa.String(64), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("attempt_id", sa.String(64), nullable=False),
    sa.Column("sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("kind", sa.String(16), nullable=False),
    sa.Column("previous_event_sha256", sa.String(64), nullable=True),
    sa.Column("committed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("evaluation_id", sa.String(64), nullable=True),
    sa.Column("evaluation_sha256", sa.String(64), nullable=True),
    sa.Column("evaluation_payload", sa.Text(), nullable=True),
    sa.Column("consumed_slot_ids_payload", sa.Text(), nullable=False),
    sa.Column("coalesced_slot_ids_payload", sa.Text(), nullable=False),
    sa.Column("selected_slot_ordinal", sa.Integer(), nullable=True),
    sa.Column("selected_slot_id", sa.String(64), nullable=True),
    sa.Column("selected_slot_sha256", sa.String(64), nullable=True),
    sa.Column("selected_scheduled_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("ticket_id", sa.String(64), nullable=True),
    sa.Column("ticket_sha256", sa.String(64), nullable=True),
    sa.Column("claim_issued_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("claim_valid_until", sa.DateTime(timezone=True), nullable=True),
    sa.Column("source_dispatch_event_id", sa.String(64), nullable=True),
    sa.Column("source_dispatch_event_sha256", sa.String(64), nullable=True),
    sa.Column("lookup_receipt_id", sa.String(36), nullable=True),
    sa.Column("lookup_receipt_sha256", sa.String(64), nullable=True),
    sa.Column("fence_owner_id", sa.String(128), nullable=False),
    sa.Column("fence_lease_id", sa.String(64), nullable=False),
    sa.Column("fence_fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column("fence_policy_sha256", sa.String(64), nullable=False),
    sa.Column("fence_lease_sha256", sa.String(64), nullable=False),
    sa.Column("fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "plan_id",
        "sequence_number",
        name="uq_phase4_unknown_recovery_event_sequence",
    ),
    sa.UniqueConstraint(
        "plan_id",
        "semantic_sha256",
        name="uq_phase4_unknown_recovery_event_semantic",
    ),
    sa.UniqueConstraint(
        "plan_id",
        "account_id",
        "attempt_id",
        "event_id",
        "semantic_sha256",
        name="uq_phase4_unknown_recovery_dispatch_exact",
    ),
    sa.UniqueConstraint(
        "plan_id",
        "account_id",
        "attempt_id",
        "sequence_number",
        "event_id",
        "semantic_sha256",
        name="uq_phase4_unknown_recovery_event_exact",
    ),
    sa.UniqueConstraint(
        "ticket_id",
        name="uq_phase4_unknown_recovery_ticket",
    ),
    sa.UniqueConstraint(
        "source_dispatch_event_id",
        name="uq_phase4_unknown_recovery_observed_dispatch",
    ),
    sa.UniqueConstraint(
        "lookup_receipt_id",
        name="uq_phase4_unknown_recovery_lookup_receipt",
    ),
    sa.ForeignKeyConstraint(
        ["plan_id", "account_id", "attempt_id", "plan_sha256"],
        [
            "phase4_unknown_lookup_recovery_plans.plan_id",
            "phase4_unknown_lookup_recovery_plans.account_id",
            "phase4_unknown_lookup_recovery_plans.attempt_id",
            "phase4_unknown_lookup_recovery_plans.semantic_sha256",
        ],
        name="fk_phase4_unknown_recovery_event_plan",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "fence_fencing_generation", "fence_lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase4_unknown_recovery_event_lease",
    ),
    sa.ForeignKeyConstraint(
        ["plan_id", "previous_event_sha256"],
        [
            "phase4_unknown_lookup_recovery_events.plan_id",
            "phase4_unknown_lookup_recovery_events.semantic_sha256",
        ],
        name="fk_phase4_unknown_recovery_predecessor",
    ),
    sa.ForeignKeyConstraint(
        [
            "plan_id",
            "account_id",
            "attempt_id",
            "source_dispatch_event_id",
            "source_dispatch_event_sha256",
        ],
        [
            "phase4_unknown_lookup_recovery_events.plan_id",
            "phase4_unknown_lookup_recovery_events.account_id",
            "phase4_unknown_lookup_recovery_events.attempt_id",
            "phase4_unknown_lookup_recovery_events.event_id",
            "phase4_unknown_lookup_recovery_events.semantic_sha256",
        ],
        name="fk_phase4_unknown_recovery_dispatch",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "attempt_id", "lookup_receipt_id", "lookup_receipt_sha256"],
        [
            "phase4_alpaca_paper_lookup_observations.account_id",
            "phase4_alpaca_paper_lookup_observations.attempt_id",
            "phase4_alpaca_paper_lookup_observations.receipt_id",
            "phase4_alpaca_paper_lookup_observations.semantic_sha256",
        ],
        name="fk_phase4_unknown_recovery_receipt",
    ),
    sa.CheckConstraint(
        "(sequence_number = 1 AND previous_event_sha256 IS NULL) "
        "OR (sequence_number > 1 AND previous_event_sha256 IS NOT NULL)",
        name="phase4_unknown_recovery_event_predecessor",
    ),
    sa.CheckConstraint(
        "kind IN ('dispatch', 'observation', 'exhausted')",
        name="phase4_unknown_recovery_event_kind",
    ),
    sa.CheckConstraint(
        "(kind = 'dispatch' "
        "AND evaluation_id IS NOT NULL AND evaluation_sha256 IS NOT NULL "
        "AND evaluation_payload IS NOT NULL "
        "AND selected_slot_ordinal IS NOT NULL "
        "AND selected_slot_id IS NOT NULL AND selected_slot_sha256 IS NOT NULL "
        "AND selected_scheduled_at IS NOT NULL "
        "AND ticket_id IS NOT NULL AND ticket_sha256 IS NOT NULL "
        "AND claim_issued_at IS NOT NULL AND claim_valid_until IS NOT NULL "
        "AND source_dispatch_event_id IS NULL "
        "AND source_dispatch_event_sha256 IS NULL "
        "AND lookup_receipt_id IS NULL AND lookup_receipt_sha256 IS NULL) "
        "OR (kind = 'observation' "
        "AND evaluation_id IS NULL AND evaluation_sha256 IS NULL "
        "AND evaluation_payload IS NULL "
        "AND selected_slot_ordinal IS NULL "
        "AND selected_slot_id IS NULL AND selected_slot_sha256 IS NULL "
        "AND selected_scheduled_at IS NULL "
        "AND ticket_id IS NULL AND ticket_sha256 IS NULL "
        "AND claim_issued_at IS NULL AND claim_valid_until IS NULL "
        "AND source_dispatch_event_id IS NOT NULL "
        "AND source_dispatch_event_sha256 IS NOT NULL "
        "AND lookup_receipt_id IS NOT NULL AND lookup_receipt_sha256 IS NOT NULL) "
        "OR (kind = 'exhausted' "
        "AND evaluation_id IS NOT NULL AND evaluation_sha256 IS NOT NULL "
        "AND evaluation_payload IS NOT NULL "
        "AND selected_slot_ordinal IS NULL "
        "AND selected_slot_id IS NULL AND selected_slot_sha256 IS NULL "
        "AND selected_scheduled_at IS NULL "
        "AND ticket_id IS NULL AND ticket_sha256 IS NULL "
        "AND claim_issued_at IS NULL AND claim_valid_until IS NULL "
        "AND source_dispatch_event_id IS NULL "
        "AND source_dispatch_event_sha256 IS NULL "
        "AND lookup_receipt_id IS NULL AND lookup_receipt_sha256 IS NULL)",
        name="phase4_unknown_recovery_event_shape",
    ),
    sa.CheckConstraint(
        "(kind <> 'dispatch') "
        "OR (selected_slot_ordinal BETWEEN 1 AND 6 "
        "AND selected_scheduled_at <= claim_issued_at "
        "AND claim_issued_at < claim_valid_until "
        "AND committed_at = claim_issued_at)",
        name="phase4_unknown_recovery_claim_time",
    ),
    sa.CheckConstraint(
        "committed_at < fence_valid_until AND fence_fencing_generation > 0 AND sequence_number > 0",
        name="phase4_unknown_recovery_event_time",
    ),
    sa.CheckConstraint(
        "length(event_id) = 64 "
        "AND length(plan_id) = 64 "
        "AND length(plan_sha256) = 64 "
        "AND (previous_event_sha256 IS NULL OR length(previous_event_sha256) = 64) "
        "AND (evaluation_id IS NULL OR length(evaluation_id) = 64) "
        "AND (evaluation_sha256 IS NULL OR length(evaluation_sha256) = 64) "
        "AND (selected_slot_id IS NULL OR length(selected_slot_id) = 64) "
        "AND (selected_slot_sha256 IS NULL OR length(selected_slot_sha256) = 64) "
        "AND (ticket_id IS NULL OR length(ticket_id) = 64) "
        "AND (ticket_sha256 IS NULL OR length(ticket_sha256) = 64) "
        "AND (source_dispatch_event_sha256 IS NULL "
        "OR length(source_dispatch_event_sha256) = 64) "
        "AND (lookup_receipt_sha256 IS NULL OR length(lookup_receipt_sha256) = 64) "
        "AND length(fence_sha256) = 64 "
        "AND length(fence_policy_sha256) = 64 "
        "AND length(fence_lease_sha256) = 64 "
        "AND length(fence_receipt_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_unknown_recovery_event_hashes",
    ),
    sa.CheckConstraint(
        "length(consumed_slot_ids_payload) BETWEEN 2 AND 4096 "
        "AND length(coalesced_slot_ids_payload) BETWEEN 2 AND 4096 "
        "AND (evaluation_payload IS NULL "
        "OR length(evaluation_payload) BETWEEN 2 AND 32768) "
        "AND length(canonical_payload) BETWEEN 2 AND 65536",
        name="phase4_unknown_recovery_event_payloads",
    ),
)
sa.Index(
    "ix_phase4_unknown_recovery_event_plan_time",
    phase4_unknown_lookup_recovery_events.c.plan_id,
    phase4_unknown_lookup_recovery_events.c.committed_at,
)

phase4_unknown_lookup_recovery_heads = sa.Table(
    "phase4_unknown_lookup_recovery_heads",
    metadata,
    sa.Column("plan_id", sa.String(64), primary_key=True),
    sa.Column("plan_sha256", sa.String(64), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("attempt_id", sa.String(64), nullable=False),
    sa.Column("last_sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("last_event_id", sa.String(64), nullable=False),
    sa.Column("last_event_sha256", sa.String(64), nullable=False),
    sa.Column("last_committed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("consumed_slot_ids_payload", sa.Text(), nullable=False),
    sa.Column("consumed_slot_count", sa.Integer(), nullable=False),
    sa.Column("issuance_status", sa.String(32), nullable=False),
    sa.ForeignKeyConstraint(
        ["plan_id", "account_id", "attempt_id", "plan_sha256"],
        [
            "phase4_unknown_lookup_recovery_plans.plan_id",
            "phase4_unknown_lookup_recovery_plans.account_id",
            "phase4_unknown_lookup_recovery_plans.attempt_id",
            "phase4_unknown_lookup_recovery_plans.semantic_sha256",
        ],
        name="fk_phase4_unknown_recovery_head_plan",
    ),
    sa.ForeignKeyConstraint(
        [
            "plan_id",
            "account_id",
            "attempt_id",
            "last_sequence_number",
            "last_event_id",
            "last_event_sha256",
        ],
        [
            "phase4_unknown_lookup_recovery_events.plan_id",
            "phase4_unknown_lookup_recovery_events.account_id",
            "phase4_unknown_lookup_recovery_events.attempt_id",
            "phase4_unknown_lookup_recovery_events.sequence_number",
            "phase4_unknown_lookup_recovery_events.event_id",
            "phase4_unknown_lookup_recovery_events.semantic_sha256",
        ],
        name="fk_phase4_unknown_recovery_head_event",
    ),
    sa.CheckConstraint(
        "last_sequence_number > 0 "
        "AND consumed_slot_count BETWEEN 0 AND 6 "
        "AND issuance_status IN "
        "('active', 'exhausted', 'reconciliation_required', 'blocked_mismatch')",
        name="phase4_unknown_recovery_head_state",
    ),
    sa.CheckConstraint(
        "length(plan_id) = 64 "
        "AND length(plan_sha256) = 64 "
        "AND length(last_event_id) = 64 "
        "AND length(last_event_sha256) = 64 "
        "AND length(consumed_slot_ids_payload) BETWEEN 2 AND 4096",
        name="phase4_unknown_recovery_head_shape",
    ),
)
sa.Index(
    "ix_phase4_unknown_recovery_head_account_status",
    phase4_unknown_lookup_recovery_heads.c.account_id,
    phase4_unknown_lookup_recovery_heads.c.issuance_status,
)

# Phase 4K normalization facts preserve one authenticated lookup observation
# without applying it to submission, order, execution, ledger, or risk state.
# The immutable account-local chain provides a single auditable ordering across
# lookup-derived evidence; the mutable head is only its serialized tip.
phase4_broker_reconciliation_facts = sa.Table(
    "phase4_broker_reconciliation_facts",
    metadata,
    sa.Column("fact_id", sa.String(36), primary_key=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("account_sequence", sa.BigInteger(), nullable=False),
    sa.Column("previous_fact_sha256", sa.String(64), nullable=True),
    sa.Column("provider_id", sa.String(128), nullable=False),
    sa.Column("environment", sa.String(32), nullable=False),
    sa.Column("attempt_id", sa.String(64), nullable=False),
    sa.Column("order_id", sa.String(64), nullable=False),
    sa.Column("client_order_id", sa.String(128), nullable=False),
    sa.Column("instrument_id", sa.String(64), nullable=False),
    sa.Column("symbol", sa.String(32), nullable=False),
    sa.Column("outcome", sa.String(32), nullable=False),
    sa.Column("expected_provider_asset_id", sa.String(36), nullable=False),
    sa.Column("provider_order_id", sa.String(128), nullable=True),
    sa.Column("provider_order_status", sa.String(64), nullable=True),
    sa.Column("provider_replaced_by", sa.String(128), nullable=True),
    sa.Column("provider_replaces", sa.String(128), nullable=True),
    sa.Column("observed_provider_asset_id", sa.String(36), nullable=True),
    sa.Column("mismatch_fields_payload", sa.Text(), nullable=False),
    sa.Column("provider_timestamps_payload", sa.Text(), nullable=False),
    sa.Column("requested_quantity", sa.String(64), nullable=True),
    sa.Column("requested_notional", sa.String(64), nullable=True),
    sa.Column("cumulative_filled_quantity", sa.String(64), nullable=True),
    sa.Column("cumulative_filled_average_price", sa.String(64), nullable=True),
    sa.Column("provider_source", sa.String(128), nullable=True),
    sa.Column("source_lookup_receipt_id", sa.String(36), nullable=False),
    sa.Column("source_lookup_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("source_ingress_receipt_id", sa.String(64), nullable=False),
    sa.Column("source_ingress_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("source_ingress_sequence", sa.BigInteger(), nullable=False),
    sa.Column("source_delivery_idempotency_key", sa.String(128), nullable=False),
    sa.Column("source_observation_sha256", sa.String(64), nullable=False),
    sa.Column("source_body_sha256", sa.String(64), nullable=False),
    sa.Column("http_status", sa.Integer(), nullable=False),
    sa.Column("provider_request_id", sa.String(256), nullable=False),
    sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("raw_recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("authenticated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("source_committed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("normalized_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "account_id",
        "account_sequence",
        name="uq_phase4_broker_reconciliation_account_sequence",
    ),
    sa.UniqueConstraint(
        "account_id",
        "semantic_sha256",
        name="uq_phase4_broker_reconciliation_account_semantic",
    ),
    sa.UniqueConstraint(
        "account_id",
        "account_sequence",
        "fact_id",
        "semantic_sha256",
        name="uq_phase4_broker_reconciliation_fact_exact",
    ),
    sa.UniqueConstraint(
        "source_lookup_receipt_id",
        name="uq_phase4_broker_reconciliation_lookup_source",
    ),
    sa.UniqueConstraint(
        "source_ingress_receipt_id",
        name="uq_phase4_broker_reconciliation_ingress_source",
    ),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase4_broker_reconciliation_account",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "previous_fact_sha256"],
        [
            "phase4_broker_reconciliation_facts.account_id",
            "phase4_broker_reconciliation_facts.semantic_sha256",
        ],
        name="fk_phase4_broker_reconciliation_predecessor",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "attempt_id",
            "source_lookup_receipt_id",
            "source_lookup_receipt_sha256",
        ],
        [
            "phase4_alpaca_paper_lookup_observations.account_id",
            "phase4_alpaca_paper_lookup_observations.attempt_id",
            "phase4_alpaca_paper_lookup_observations.receipt_id",
            "phase4_alpaca_paper_lookup_observations.semantic_sha256",
        ],
        name="fk_phase4_broker_reconciliation_lookup_source",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "source_ingress_receipt_id",
            "source_ingress_receipt_sha256",
        ],
        [
            "phase4_broker_ingress_receipts.account_id",
            "phase4_broker_ingress_receipts.receipt_id",
            "phase4_broker_ingress_receipts.semantic_sha256",
        ],
        name="fk_phase4_broker_reconciliation_ingress_source",
    ),
    sa.CheckConstraint(
        "(account_sequence = 1 AND previous_fact_sha256 IS NULL) "
        "OR (account_sequence > 1 AND previous_fact_sha256 IS NOT NULL)",
        name="phase4_broker_reconciliation_predecessor_shape",
    ),
    sa.CheckConstraint(
        "outcome IN "
        "('order_observed_candidate', 'quarantined_economic_mismatch', "
        "'quarantined_security_mismatch', 'inconclusive_not_visible')",
        name="phase4_broker_reconciliation_outcome",
    ),
    sa.CheckConstraint(
        "(http_status = 404 AND outcome = 'inconclusive_not_visible' "
        "AND provider_order_id IS NULL "
        "AND provider_order_status IS NULL "
        "AND provider_replaced_by IS NULL "
        "AND provider_replaces IS NULL "
        "AND observed_provider_asset_id IS NULL "
        "AND requested_quantity IS NULL "
        "AND requested_notional IS NULL "
        "AND cumulative_filled_quantity IS NULL "
        "AND cumulative_filled_average_price IS NULL "
        "AND provider_source IS NULL) "
        "OR (http_status = 200 "
        "AND outcome IN "
        "('order_observed_candidate', 'quarantined_economic_mismatch', "
        "'quarantined_security_mismatch') "
        "AND provider_order_id IS NOT NULL "
        "AND provider_order_status IS NOT NULL "
        "AND cumulative_filled_quantity IS NOT NULL)",
        name="phase4_broker_reconciliation_observation_shape",
    ),
    sa.CheckConstraint(
        "received_at <= raw_recorded_at "
        "AND raw_recorded_at <= authenticated_at "
        "AND authenticated_at <= source_committed_at "
        "AND source_committed_at <= normalized_at",
        name="phase4_broker_reconciliation_time_order",
    ),
    sa.CheckConstraint(
        "source_ingress_sequence > 0 AND account_sequence > 0",
        name="phase4_broker_reconciliation_positive_sequences",
    ),
    sa.CheckConstraint(
        "length(fact_id) = 36 "
        "AND (previous_fact_sha256 IS NULL "
        "OR length(previous_fact_sha256) = 64) "
        "AND length(source_lookup_receipt_sha256) = 64 "
        "AND length(source_ingress_receipt_id) = 64 "
        "AND length(source_ingress_receipt_sha256) = 64 "
        "AND length(source_observation_sha256) = 64 "
        "AND length(source_body_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_broker_reconciliation_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(mismatch_fields_payload) BETWEEN 2 AND 4096 "
        "AND length(provider_timestamps_payload) BETWEEN 2 AND 8192 "
        "AND (requested_quantity IS NULL OR length(requested_quantity) BETWEEN 1 AND 64) "
        "AND (requested_notional IS NULL OR length(requested_notional) BETWEEN 1 AND 64) "
        "AND (cumulative_filled_quantity IS NULL "
        "OR length(cumulative_filled_quantity) BETWEEN 1 AND 64) "
        "AND (cumulative_filled_average_price IS NULL "
        "OR length(cumulative_filled_average_price) BETWEEN 1 AND 64) "
        "AND length(canonical_payload) BETWEEN 2 AND 65536",
        name="phase4_broker_reconciliation_payload_sizes",
    ),
)
sa.Index(
    "ix_phase4_broker_reconciliation_account_normalized",
    phase4_broker_reconciliation_facts.c.account_id,
    phase4_broker_reconciliation_facts.c.normalized_at,
)
sa.Index(
    "ix_phase4_broker_reconciliation_attempt",
    phase4_broker_reconciliation_facts.c.account_id,
    phase4_broker_reconciliation_facts.c.attempt_id,
    phase4_broker_reconciliation_facts.c.account_sequence,
)

phase4_broker_reconciliation_heads = sa.Table(
    "phase4_broker_reconciliation_heads",
    metadata,
    sa.Column("account_id", sa.String(64), primary_key=True),
    sa.Column("last_account_sequence", sa.BigInteger(), nullable=False),
    sa.Column("last_fact_id", sa.String(36), nullable=False),
    sa.Column("last_fact_sha256", sa.String(64), nullable=False),
    sa.Column("last_normalized_at", sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase4_broker_reconciliation_head_account",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "last_account_sequence",
            "last_fact_id",
            "last_fact_sha256",
        ],
        [
            "phase4_broker_reconciliation_facts.account_id",
            "phase4_broker_reconciliation_facts.account_sequence",
            "phase4_broker_reconciliation_facts.fact_id",
            "phase4_broker_reconciliation_facts.semantic_sha256",
        ],
        name="fk_phase4_broker_reconciliation_head_fact",
    ),
    sa.CheckConstraint(
        "last_account_sequence > 0 AND length(last_fact_id) = 36 AND length(last_fact_sha256) = 64",
        name="phase4_broker_reconciliation_head_shape",
    ),
)

# Phase 4L retains source-scoped normalized inbox requests separately from
# their account-local source-link ordering and their explicit non-application
# receipts. No table in this slice is an order, execution, or lifecycle
# application target.
phase4_broker_normalized_facts = sa.Table(
    "phase4_broker_normalized_facts",
    metadata,
    sa.Column("request_id", sa.String(36), primary_key=True),
    sa.Column("observation_id", sa.String(36), nullable=False, unique=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("provider_id", sa.String(128), nullable=False),
    sa.Column("environment", sa.String(32), nullable=False),
    sa.Column("source_kind", sa.String(64), nullable=False),
    sa.Column("identity_profile_id", sa.String(128), nullable=False),
    sa.Column("identity_profile_sha256", sa.String(64), nullable=False),
    sa.Column("identity_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("source_reconciliation_fact_id", sa.String(36), nullable=False, unique=True),
    sa.Column("source_reconciliation_fact_sha256", sa.String(64), nullable=False),
    sa.Column("source_reconciliation_evidence_sha256", sa.String(64), nullable=False),
    sa.Column("source_reconciliation_account_sequence", sa.BigInteger(), nullable=False),
    sa.Column("source_fact_normalized_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("source_lookup_receipt_id", sa.String(36), nullable=False, unique=True),
    sa.Column("source_lookup_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("source_ingress_receipt_id", sa.String(64), nullable=False, unique=True),
    sa.Column("source_ingress_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("source_observation_sha256", sa.String(64), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "request_id",
        "account_id",
        "observation_id",
        "semantic_sha256",
        name="uq_phase4_broker_normalized_fact_exact",
    ),
    sa.UniqueConstraint(
        "request_id",
        "account_id",
        "observation_id",
        "source_reconciliation_fact_id",
        "source_reconciliation_fact_sha256",
        "source_ingress_receipt_id",
        "source_ingress_receipt_sha256",
        "semantic_sha256",
        name="uq_phase4_broker_normalized_source_exact",
    ),
    sa.CheckConstraint(
        "source_kind = 'authenticated_client_order_lookup'",
        name="phase4_broker_normalized_source_kind",
    ),
    sa.CheckConstraint(
        "source_reconciliation_account_sequence > 0",
        name="phase4_broker_normalized_positive_sequence",
    ),
    sa.CheckConstraint(
        "length(request_id) = 36 "
        "AND length(observation_id) = 36 "
        "AND length(identity_profile_sha256) = 64 "
        "AND length(identity_sha256) = 64 "
        "AND length(source_reconciliation_fact_id) = 36 "
        "AND length(source_reconciliation_fact_sha256) = 64 "
        "AND length(source_reconciliation_evidence_sha256) = 64 "
        "AND length(source_lookup_receipt_id) = 36 "
        "AND length(source_lookup_receipt_sha256) = 64 "
        "AND length(source_ingress_receipt_id) = 64 "
        "AND length(source_ingress_receipt_sha256) = 64 "
        "AND length(source_observation_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_broker_normalized_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 65536",
        name="phase4_broker_normalized_payload_size",
    ),
)
sa.Index(
    "ix_phase4_broker_normalized_account_source_time",
    phase4_broker_normalized_facts.c.account_id,
    phase4_broker_normalized_facts.c.source_fact_normalized_at,
)

phase4_broker_inbox_source_links = sa.Table(
    "phase4_broker_inbox_source_links",
    metadata,
    sa.Column("link_id", sa.String(36), primary_key=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("account_sequence", sa.BigInteger(), nullable=False),
    sa.Column("previous_link_sha256", sa.String(64), nullable=True),
    sa.Column("request_id", sa.String(36), nullable=False, unique=True),
    sa.Column("request_sha256", sa.String(64), nullable=False),
    sa.Column("observation_id", sa.String(36), nullable=False, unique=True),
    sa.Column("source_reconciliation_fact_id", sa.String(36), nullable=False, unique=True),
    sa.Column("source_reconciliation_fact_sha256", sa.String(64), nullable=False),
    sa.Column("source_reconciliation_evidence_sha256", sa.String(64), nullable=False),
    sa.Column("source_reconciliation_account_sequence", sa.BigInteger(), nullable=False),
    sa.Column("source_lookup_receipt_id", sa.String(36), nullable=False, unique=True),
    sa.Column("source_lookup_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("source_ingress_receipt_id", sa.String(64), nullable=False, unique=True),
    sa.Column("source_ingress_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("source_observation_sha256", sa.String(64), nullable=False),
    sa.Column("linked_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "account_id",
        "account_sequence",
        name="uq_phase4_broker_inbox_link_account_sequence",
    ),
    sa.UniqueConstraint(
        "account_id",
        "semantic_sha256",
        name="uq_phase4_broker_inbox_link_account_semantic",
    ),
    sa.UniqueConstraint(
        "account_id",
        "account_sequence",
        "link_id",
        "semantic_sha256",
        name="uq_phase4_broker_inbox_link_head_exact",
    ),
    sa.UniqueConstraint(
        "account_id",
        "account_sequence",
        "link_id",
        "request_id",
        "semantic_sha256",
        name="uq_phase4_broker_inbox_link_exact",
    ),
    sa.UniqueConstraint(
        "link_id",
        "account_id",
        "request_id",
        "semantic_sha256",
        name="uq_phase4_broker_inbox_link_receipt_exact",
    ),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase4_broker_inbox_link_account",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "previous_link_sha256"],
        [
            "phase4_broker_inbox_source_links.account_id",
            "phase4_broker_inbox_source_links.semantic_sha256",
        ],
        name="fk_phase4_broker_inbox_link_predecessor",
    ),
    sa.ForeignKeyConstraint(
        [
            "request_id",
            "account_id",
            "observation_id",
            "source_reconciliation_fact_id",
            "source_reconciliation_fact_sha256",
            "source_ingress_receipt_id",
            "source_ingress_receipt_sha256",
            "request_sha256",
        ],
        [
            "phase4_broker_normalized_facts.request_id",
            "phase4_broker_normalized_facts.account_id",
            "phase4_broker_normalized_facts.observation_id",
            "phase4_broker_normalized_facts.source_reconciliation_fact_id",
            "phase4_broker_normalized_facts.source_reconciliation_fact_sha256",
            "phase4_broker_normalized_facts.source_ingress_receipt_id",
            "phase4_broker_normalized_facts.source_ingress_receipt_sha256",
            "phase4_broker_normalized_facts.semantic_sha256",
        ],
        name="fk_phase4_broker_inbox_link_normalized_fact",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "source_reconciliation_account_sequence",
            "source_reconciliation_fact_id",
            "source_reconciliation_fact_sha256",
        ],
        [
            "phase4_broker_reconciliation_facts.account_id",
            "phase4_broker_reconciliation_facts.account_sequence",
            "phase4_broker_reconciliation_facts.fact_id",
            "phase4_broker_reconciliation_facts.semantic_sha256",
        ],
        name="fk_phase4_broker_inbox_link_reconciliation",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "source_ingress_receipt_id",
            "source_ingress_receipt_sha256",
        ],
        [
            "phase4_broker_ingress_receipts.account_id",
            "phase4_broker_ingress_receipts.receipt_id",
            "phase4_broker_ingress_receipts.semantic_sha256",
        ],
        name="fk_phase4_broker_inbox_link_ingress",
    ),
    sa.CheckConstraint(
        "(account_sequence = 1 AND previous_link_sha256 IS NULL) "
        "OR (account_sequence > 1 AND previous_link_sha256 IS NOT NULL)",
        name="phase4_broker_inbox_link_predecessor_shape",
    ),
    sa.CheckConstraint(
        "source_reconciliation_account_sequence > 0 AND account_sequence > 0",
        name="phase4_broker_inbox_link_positive_sequences",
    ),
    sa.CheckConstraint(
        "length(link_id) = 36 "
        "AND length(request_id) = 36 "
        "AND length(request_sha256) = 64 "
        "AND length(observation_id) = 36 "
        "AND (previous_link_sha256 IS NULL "
        "OR length(previous_link_sha256) = 64) "
        "AND length(source_reconciliation_fact_id) = 36 "
        "AND length(source_reconciliation_fact_sha256) = 64 "
        "AND length(source_reconciliation_evidence_sha256) = 64 "
        "AND length(source_lookup_receipt_id) = 36 "
        "AND length(source_lookup_receipt_sha256) = 64 "
        "AND length(source_ingress_receipt_id) = 64 "
        "AND length(source_ingress_receipt_sha256) = 64 "
        "AND length(source_observation_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_broker_inbox_link_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 65536",
        name="phase4_broker_inbox_link_payload_size",
    ),
)
sa.Index(
    "ix_phase4_broker_inbox_link_account_time",
    phase4_broker_inbox_source_links.c.account_id,
    phase4_broker_inbox_source_links.c.linked_at,
)

phase4_broker_inbox_heads = sa.Table(
    "phase4_broker_inbox_heads",
    metadata,
    sa.Column("account_id", sa.String(64), primary_key=True),
    sa.Column("last_account_sequence", sa.BigInteger(), nullable=False),
    sa.Column("last_link_id", sa.String(36), nullable=False),
    sa.Column("last_link_sha256", sa.String(64), nullable=False),
    sa.Column("last_linked_at", sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase4_broker_inbox_head_account",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "last_account_sequence",
            "last_link_id",
            "last_link_sha256",
        ],
        [
            "phase4_broker_inbox_source_links.account_id",
            "phase4_broker_inbox_source_links.account_sequence",
            "phase4_broker_inbox_source_links.link_id",
            "phase4_broker_inbox_source_links.semantic_sha256",
        ],
        name="fk_phase4_broker_inbox_head_link",
    ),
    sa.CheckConstraint(
        "last_account_sequence > 0 AND length(last_link_id) = 36 AND length(last_link_sha256) = 64",
        name="phase4_broker_inbox_head_shape",
    ),
)

phase4_broker_inbox_application_receipts = sa.Table(
    "phase4_broker_inbox_application_receipts",
    metadata,
    sa.Column("decision_id", sa.String(36), primary_key=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("request_id", sa.String(36), nullable=False, unique=True),
    sa.Column("request_sha256", sa.String(64), nullable=False),
    sa.Column("observation_id", sa.String(36), nullable=False, unique=True),
    sa.Column("source_link_id", sa.String(36), nullable=False, unique=True),
    sa.Column("source_link_sha256", sa.String(64), nullable=False),
    sa.Column("disposition", sa.String(64), nullable=False),
    sa.Column("policy_id", sa.String(128), nullable=False),
    sa.Column("policy_sha256", sa.String(64), nullable=False),
    sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "decision_id",
        "account_id",
        "request_id",
        "semantic_sha256",
        name="uq_phase4_broker_inbox_application_exact",
    ),
    sa.ForeignKeyConstraint(
        ["request_id", "account_id", "observation_id", "request_sha256"],
        [
            "phase4_broker_normalized_facts.request_id",
            "phase4_broker_normalized_facts.account_id",
            "phase4_broker_normalized_facts.observation_id",
            "phase4_broker_normalized_facts.semantic_sha256",
        ],
        name="fk_phase4_broker_inbox_application_request",
    ),
    sa.ForeignKeyConstraint(
        [
            "source_link_id",
            "account_id",
            "request_id",
            "source_link_sha256",
        ],
        [
            "phase4_broker_inbox_source_links.link_id",
            "phase4_broker_inbox_source_links.account_id",
            "phase4_broker_inbox_source_links.request_id",
            "phase4_broker_inbox_source_links.semantic_sha256",
        ],
        name="fk_phase4_broker_inbox_application_link",
    ),
    sa.CheckConstraint(
        "disposition IN "
        "('withheld_unqualified_revision_identity', "
        "'quarantined_economic_mismatch', "
        "'quarantined_security_mismatch', "
        "'inconclusive_not_visible')",
        name="phase4_broker_inbox_application_disposition",
    ),
    sa.CheckConstraint(
        "decided_at <= recorded_at",
        name="phase4_broker_inbox_application_time_order",
    ),
    sa.CheckConstraint(
        "length(decision_id) = 36 "
        "AND length(request_id) = 36 "
        "AND length(request_sha256) = 64 "
        "AND length(observation_id) = 36 "
        "AND length(source_link_id) = 36 "
        "AND length(source_link_sha256) = 64 "
        "AND length(policy_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_broker_inbox_application_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 65536",
        name="phase4_broker_inbox_application_payload_size",
    ),
)

# Phase 4O makes the bounded Phase 4M order traversal restart-safe without
# promoting the resulting cursor walk to an isolated provider snapshot.  A
# durable head carries at most one exact prepared-page claim; immutable pages
# separately chain runtime receipts and their raw-first Phase 4M page values.
sa.Index(
    "ux_phase4_order_snapshot_permit_exact",
    phase4_broker_request_permits.c.account_id,
    phase4_broker_request_permits.c.permit_id,
    phase4_broker_request_permits.c.semantic_sha256,
    phase4_broker_request_permits.c.demand_id,
    phase4_broker_request_permits.c.demand_sha256,
    phase4_broker_request_permits.c.policy_sha256,
    unique=True,
)

phase4_alpaca_paper_order_snapshot_plans = sa.Table(
    "phase4_alpaca_paper_order_snapshot_plans",
    metadata,
    sa.Column("snapshot_id", sa.String(36), primary_key=True),
    sa.Column(
        "account_id",
        sa.String(64),
        sa.ForeignKey(
            "phase2_account_lease_heads.account_id",
            name="fk_phase4_order_snapshot_plan_account",
        ),
        nullable=False,
    ),
    sa.Column("capture_idempotency_key", sa.String(128), nullable=False),
    sa.Column("capability_sha256", sa.String(64), nullable=False),
    sa.Column("traversal_profile_sha256", sa.String(64), nullable=False),
    sa.Column("page_limit", sa.BigInteger(), nullable=False),
    sa.Column("maximum_pages", sa.BigInteger(), nullable=False),
    sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "account_id",
        "capture_idempotency_key",
        name="uq_phase4_order_snapshot_plan_account_key",
    ),
    sa.UniqueConstraint(
        "snapshot_id",
        "account_id",
        "semantic_sha256",
        name="uq_phase4_order_snapshot_plan_exact",
    ),
    sa.CheckConstraint(
        "length(snapshot_id) = 36 "
        "AND snapshot_id = lower(snapshot_id) "
        "AND substr(snapshot_id, 9, 1) = '-' "
        "AND substr(snapshot_id, 14, 1) = '-' "
        "AND substr(snapshot_id, 19, 1) = '-' "
        "AND substr(snapshot_id, 24, 1) = '-'",
        name="phase4_order_snapshot_plan_id_shape",
    ),
    sa.CheckConstraint(
        "length(capture_idempotency_key) BETWEEN 8 AND 128",
        name="phase4_order_snapshot_plan_key_size",
    ),
    sa.CheckConstraint(
        "page_limit BETWEEN 1 AND 500 AND maximum_pages BETWEEN 1 AND 8",
        name="phase4_order_snapshot_plan_bounds",
    ),
    sa.CheckConstraint(
        "length(capability_sha256) = 64 "
        "AND length(traversal_profile_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_order_snapshot_plan_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 16384",
        name="phase4_order_snapshot_plan_payload_size",
    ),
)
sa.Index(
    "ix_phase4_order_snapshot_plan_account_prepared",
    phase4_alpaca_paper_order_snapshot_plans.c.account_id,
    phase4_alpaca_paper_order_snapshot_plans.c.prepared_at,
)

phase4_alpaca_paper_order_snapshot_pages = sa.Table(
    "phase4_alpaca_paper_order_snapshot_pages",
    metadata,
    sa.Column("receipt_id", sa.String(36), primary_key=True),
    sa.Column("snapshot_id", sa.String(36), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("page_number", sa.BigInteger(), nullable=False),
    sa.Column("plan_sha256", sa.String(64), nullable=False),
    sa.Column("previous_page_receipt_sha256", sa.String(64), nullable=True),
    sa.Column("previous_persisted_page_sha256", sa.String(64), nullable=True),
    sa.Column("description_sha256", sa.String(64), nullable=False),
    sa.Column("preparation_sha256", sa.String(64), nullable=False),
    sa.Column("prefix_capture_sha256", sa.String(64), nullable=False),
    sa.Column("prefix_page_count", sa.BigInteger(), nullable=False),
    sa.Column("preparation_previous_page_receipt_id", sa.String(36), nullable=True),
    sa.Column(
        "preparation_previous_page_receipt_sha256",
        sa.String(64),
        nullable=True,
    ),
    sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("provider_id", sa.String(128), nullable=False),
    sa.Column("environment", sa.String(32), nullable=False),
    sa.Column("capability_sha256", sa.String(64), nullable=False),
    sa.Column("expected_provider_account_id", sa.String(36), nullable=False),
    sa.Column("secret_ref", sa.String(256), nullable=False),
    sa.Column("secret_version", sa.String(128), nullable=False),
    sa.Column("credential_reference_sha256", sa.String(64), nullable=False),
    sa.Column("credential_resolution_sha256", sa.String(64), nullable=False),
    sa.Column("resolver_id", sa.String(128), nullable=False),
    sa.Column("resolver_version", sa.String(128), nullable=False),
    sa.Column(
        "credential_resolution_started_at",
        sa.DateTime(timezone=True),
        nullable=False,
    ),
    sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column(
        "credential_resolution_valid_until",
        sa.DateTime(timezone=True),
        nullable=False,
    ),
    sa.Column("account_binding_id", sa.String(36), nullable=False),
    sa.Column("account_binding_sha256", sa.String(64), nullable=False),
    sa.Column("pre_account_identity_sha256", sa.String(64), nullable=False),
    sa.Column("post_account_identity_sha256", sa.String(64), nullable=False),
    sa.Column(
        "pre_account_identity_checked_at",
        sa.DateTime(timezone=True),
        nullable=False,
    ),
    sa.Column(
        "post_account_identity_checked_at",
        sa.DateTime(timezone=True),
        nullable=False,
    ),
    sa.Column("policy_sha256", sa.String(64), nullable=False),
    sa.Column("demand_id", sa.String(64), nullable=False),
    sa.Column("demand_sha256", sa.String(64), nullable=False),
    sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("permit_id", sa.String(64), nullable=False),
    sa.Column("permit_sha256", sa.String(64), nullable=False),
    sa.Column("permit_freshness_sha256", sa.String(64), nullable=False),
    sa.Column("permit_checked_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("fence_owner_id", sa.String(128), nullable=False),
    sa.Column("fence_lease_id", sa.String(64), nullable=False),
    sa.Column("fence_fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column("fence_policy_sha256", sa.String(64), nullable=False),
    sa.Column("pre_fence_lease_sha256", sa.String(64), nullable=False),
    sa.Column("pre_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("pre_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("pre_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("transport_request_sha256", sa.String(64), nullable=False),
    sa.Column("transport_response_sha256", sa.String(64), nullable=False),
    sa.Column("request_started_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("http_status", sa.Integer(), nullable=False),
    sa.Column("provider_request_id", sa.String(256), nullable=False),
    sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("ingress_receipt_id", sa.String(64), nullable=False),
    sa.Column("ingress_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("ingress_sequence", sa.BigInteger(), nullable=False),
    sa.Column("raw_recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("observation_sha256", sa.String(64), nullable=False),
    sa.Column("persisted_page_sha256", sa.String(64), nullable=False),
    sa.Column("before_order_id", sa.String(36), nullable=True),
    sa.Column("next_before_order_id", sa.String(36), nullable=True),
    sa.Column("terminal_page", sa.Boolean(), nullable=False),
    sa.Column("bounded_truncation", sa.Boolean(), nullable=False),
    sa.Column("post_fence_lease_sha256", sa.String(64), nullable=False),
    sa.Column("post_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("post_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("post_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("authenticated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("evidence_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("commit_fence_lease_sha256", sa.String(64), nullable=False),
    sa.Column("commit_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("commit_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("commit_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "snapshot_id",
        "page_number",
        name="uq_phase4_order_snapshot_page_number",
    ),
    sa.UniqueConstraint(
        "permit_id",
        name="uq_phase4_alpaca_paper_order_snapshot_pages_permit_id",
    ),
    sa.UniqueConstraint(
        "ingress_receipt_id",
        name="uq_phase4_alpaca_paper_order_snapshot_pages_ingress_receipt_id",
    ),
    sa.UniqueConstraint(
        "snapshot_id",
        "semantic_sha256",
        name="uq_phase4_order_snapshot_page_predecessor",
    ),
    sa.UniqueConstraint(
        "snapshot_id",
        "page_number",
        "receipt_id",
        "semantic_sha256",
        "persisted_page_sha256",
        name="uq_phase4_order_snapshot_page_exact",
    ),
    sa.ForeignKeyConstraint(
        ["snapshot_id", "account_id", "plan_sha256"],
        [
            "phase4_alpaca_paper_order_snapshot_plans.snapshot_id",
            "phase4_alpaca_paper_order_snapshot_plans.account_id",
            "phase4_alpaca_paper_order_snapshot_plans.semantic_sha256",
        ],
        name="fk_phase4_order_snapshot_page_plan",
    ),
    sa.ForeignKeyConstraint(
        ["snapshot_id", "previous_page_receipt_sha256"],
        [
            "phase4_alpaca_paper_order_snapshot_pages.snapshot_id",
            "phase4_alpaca_paper_order_snapshot_pages.semantic_sha256",
        ],
        name="fk_phase4_order_snapshot_page_predecessor",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "account_binding_id",
            "account_binding_sha256",
            "expected_provider_account_id",
        ],
        [
            "phase4_alpaca_paper_account_bindings.account_id",
            "phase4_alpaca_paper_account_bindings.binding_id",
            "phase4_alpaca_paper_account_bindings.semantic_sha256",
            "phase4_alpaca_paper_account_bindings.expected_provider_account_id",
        ],
        name="fk_phase4_order_snapshot_page_account_binding",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "permit_id",
            "permit_sha256",
            "demand_id",
            "demand_sha256",
            "policy_sha256",
        ],
        [
            "phase4_broker_request_permits.account_id",
            "phase4_broker_request_permits.permit_id",
            "phase4_broker_request_permits.semantic_sha256",
            "phase4_broker_request_permits.demand_id",
            "phase4_broker_request_permits.demand_sha256",
            "phase4_broker_request_permits.policy_sha256",
        ],
        name="fk_phase4_order_snapshot_page_permit",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "ingress_receipt_id", "ingress_receipt_sha256"],
        [
            "phase4_broker_ingress_receipts.account_id",
            "phase4_broker_ingress_receipts.receipt_id",
            "phase4_broker_ingress_receipts.semantic_sha256",
        ],
        name="fk_phase4_order_snapshot_page_ingress",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "fence_fencing_generation", "pre_fence_lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase4_order_snapshot_page_pre_lease",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "fence_fencing_generation", "post_fence_lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase4_order_snapshot_page_post_lease",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "fence_fencing_generation", "commit_fence_lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase4_order_snapshot_page_commit_lease",
    ),
    sa.CheckConstraint(
        "(page_number = 1 "
        "AND previous_page_receipt_sha256 IS NULL "
        "AND previous_persisted_page_sha256 IS NULL "
        "AND before_order_id IS NULL "
        "AND prefix_page_count = 0 "
        "AND preparation_previous_page_receipt_id IS NULL "
        "AND preparation_previous_page_receipt_sha256 IS NULL) "
        "OR (page_number > 1 "
        "AND previous_page_receipt_sha256 IS NOT NULL "
        "AND previous_persisted_page_sha256 IS NOT NULL "
        "AND before_order_id IS NOT NULL "
        "AND prefix_page_count = page_number - 1 "
        "AND preparation_previous_page_receipt_id IS NOT NULL "
        "AND preparation_previous_page_receipt_sha256 = previous_page_receipt_sha256)",
        name="phase4_order_snapshot_page_predecessor_shape",
    ),
    sa.CheckConstraint(
        "provider_id = 'alpaca-paper' AND environment = 'paper'",
        name="phase4_order_snapshot_page_provider_scope",
    ),
    sa.CheckConstraint(
        "page_number BETWEEN 1 AND 8 "
        "AND prefix_page_count = page_number - 1 "
        "AND ingress_sequence > 0 "
        "AND fence_fencing_generation > 0",
        name="phase4_order_snapshot_page_positive_counts",
    ),
    sa.CheckConstraint(
        "http_status = 200",
        name="phase4_order_snapshot_page_http_status",
    ),
    sa.CheckConstraint(
        "(terminal_page AND next_before_order_id IS NULL AND NOT bounded_truncation) "
        "OR (NOT terminal_page AND next_before_order_id IS NOT NULL)",
        name="phase4_order_snapshot_page_cursor_shape",
    ),
    sa.CheckConstraint(
        "prepared_at <= requested_at "
        "AND requested_at <= credential_resolution_started_at "
        "AND credential_resolution_started_at <= resolved_at "
        "AND resolved_at <= pre_fence_validated_at "
        "AND pre_fence_validated_at <= permit_checked_at "
        "AND permit_checked_at <= pre_account_identity_checked_at "
        "AND pre_account_identity_checked_at <= request_started_at "
        "AND request_started_at <= received_at "
        "AND received_at <= raw_recorded_at "
        "AND raw_recorded_at <= post_fence_validated_at "
        "AND post_fence_validated_at <= post_account_identity_checked_at "
        "AND post_account_identity_checked_at <= authenticated_at "
        "AND authenticated_at <= commit_fence_validated_at",
        name="phase4_order_snapshot_page_time_order",
    ),
    sa.CheckConstraint(
        "resolved_at < credential_resolution_valid_until "
        "AND request_started_at < credential_resolution_valid_until "
        "AND received_at < credential_resolution_valid_until "
        "AND pre_fence_validated_at < pre_fence_valid_until "
        "AND received_at < pre_fence_valid_until "
        "AND post_fence_validated_at < post_fence_valid_until "
        "AND commit_fence_validated_at < commit_fence_valid_until",
        name="phase4_order_snapshot_page_validity_windows",
    ),
    sa.CheckConstraint(
        "length(receipt_id) = 36 "
        "AND length(snapshot_id) = 36 "
        "AND length(expected_provider_account_id) = 36 "
        "AND length(account_binding_id) = 36 "
        "AND (before_order_id IS NULL OR length(before_order_id) = 36) "
        "AND (next_before_order_id IS NULL OR length(next_before_order_id) = 36) "
        "AND (preparation_previous_page_receipt_id IS NULL "
        "OR length(preparation_previous_page_receipt_id) = 36)",
        name="phase4_order_snapshot_page_id_lengths",
    ),
    sa.CheckConstraint(
        "length(plan_sha256) = 64 "
        "AND (previous_page_receipt_sha256 IS NULL "
        "OR length(previous_page_receipt_sha256) = 64) "
        "AND (previous_persisted_page_sha256 IS NULL "
        "OR length(previous_persisted_page_sha256) = 64) "
        "AND length(description_sha256) = 64 "
        "AND length(preparation_sha256) = 64 "
        "AND length(prefix_capture_sha256) = 64 "
        "AND (preparation_previous_page_receipt_sha256 IS NULL "
        "OR length(preparation_previous_page_receipt_sha256) = 64) "
        "AND length(capability_sha256) = 64 "
        "AND length(credential_reference_sha256) = 64 "
        "AND length(credential_resolution_sha256) = 64 "
        "AND length(account_binding_sha256) = 64 "
        "AND length(pre_account_identity_sha256) = 64 "
        "AND length(post_account_identity_sha256) = 64 "
        "AND length(policy_sha256) = 64 "
        "AND length(demand_id) = 64 "
        "AND length(demand_sha256) = 64 "
        "AND length(permit_id) = 64 "
        "AND length(permit_sha256) = 64 "
        "AND length(permit_freshness_sha256) = 64 "
        "AND length(fence_sha256) = 64 "
        "AND length(fence_policy_sha256) = 64 "
        "AND length(pre_fence_lease_sha256) = 64 "
        "AND length(pre_fence_receipt_sha256) = 64 "
        "AND length(transport_request_sha256) = 64 "
        "AND length(transport_response_sha256) = 64 "
        "AND length(ingress_receipt_id) = 64 "
        "AND length(ingress_receipt_sha256) = 64 "
        "AND length(observation_sha256) = 64 "
        "AND length(persisted_page_sha256) = 64 "
        "AND length(post_fence_lease_sha256) = 64 "
        "AND length(post_fence_receipt_sha256) = 64 "
        "AND length(evidence_sha256) = 64 "
        "AND length(commit_fence_lease_sha256) = 64 "
        "AND length(commit_fence_receipt_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_order_snapshot_page_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 131072",
        name="phase4_order_snapshot_page_payload_size",
    ),
)
sa.Index(
    "ix_phase4_order_snapshot_page_account_authenticated",
    phase4_alpaca_paper_order_snapshot_pages.c.account_id,
    phase4_alpaca_paper_order_snapshot_pages.c.authenticated_at,
)
sa.Index(
    "ix_phase4_order_snapshot_page_ingress_sequence",
    phase4_alpaca_paper_order_snapshot_pages.c.account_id,
    phase4_alpaca_paper_order_snapshot_pages.c.ingress_sequence,
)
sa.Index(
    "uq_phase4_order_snapshot_page_preparation",
    phase4_alpaca_paper_order_snapshot_pages.c.preparation_sha256,
    unique=True,
)

# Phase 4AA normalizes every Phase 4O single-use page preparation into an
# immutable fact.  Existing committed pages and the sole stalled head retain
# every source field needed to backfill these rows without inventing evidence.
# The mutable head remains a cache/pointer; loaders authenticate it against the
# fact and completed pages retain the fact after the head advances.
phase4_alpaca_paper_order_snapshot_preparations = sa.Table(
    "phase4_alpaca_paper_order_snapshot_preparations",
    metadata,
    sa.Column("preparation_sha256", sa.String(64), primary_key=True),
    sa.Column("snapshot_id", sa.String(36), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("page_number", sa.BigInteger(), nullable=False),
    sa.Column("plan_sha256", sa.String(64), nullable=False),
    sa.Column("before_order_id", sa.String(36), nullable=True),
    sa.Column("description_sha256", sa.String(64), nullable=False),
    sa.Column("prefix_capture_sha256", sa.String(64), nullable=False),
    sa.Column("prefix_page_count", sa.BigInteger(), nullable=False),
    sa.Column("previous_page_receipt_id", sa.String(36), nullable=True),
    sa.Column("previous_page_receipt_sha256", sa.String(64), nullable=True),
    sa.Column("previous_persisted_page_sha256", sa.String(64), nullable=True),
    sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=False),
    sa.UniqueConstraint(
        "snapshot_id",
        "page_number",
        name="uq_phase4_order_snapshot_preparation_page",
    ),
    sa.UniqueConstraint(
        "preparation_sha256",
        "snapshot_id",
        "account_id",
        "page_number",
        "plan_sha256",
        "description_sha256",
        "prefix_capture_sha256",
        "prefix_page_count",
        "prepared_at",
        name="uq_phase4_order_snapshot_preparation_exact",
    ),
    sa.ForeignKeyConstraint(
        ["snapshot_id", "account_id", "plan_sha256"],
        [
            "phase4_alpaca_paper_order_snapshot_plans.snapshot_id",
            "phase4_alpaca_paper_order_snapshot_plans.account_id",
            "phase4_alpaca_paper_order_snapshot_plans.semantic_sha256",
        ],
        name="fk_phase4_order_snapshot_preparation_plan",
    ),
    sa.ForeignKeyConstraint(
        [
            "snapshot_id",
            "prefix_page_count",
            "previous_page_receipt_id",
            "previous_page_receipt_sha256",
            "previous_persisted_page_sha256",
        ],
        [
            "phase4_alpaca_paper_order_snapshot_pages.snapshot_id",
            "phase4_alpaca_paper_order_snapshot_pages.page_number",
            "phase4_alpaca_paper_order_snapshot_pages.receipt_id",
            "phase4_alpaca_paper_order_snapshot_pages.semantic_sha256",
            "phase4_alpaca_paper_order_snapshot_pages.persisted_page_sha256",
        ],
        name="fk_phase4_order_snapshot_preparation_predecessor",
    ),
    sa.CheckConstraint(
        "(page_number = 1 "
        "AND before_order_id IS NULL "
        "AND prefix_page_count = 0 "
        "AND previous_page_receipt_id IS NULL "
        "AND previous_page_receipt_sha256 IS NULL "
        "AND previous_persisted_page_sha256 IS NULL) "
        "OR (page_number > 1 "
        "AND before_order_id IS NOT NULL "
        "AND prefix_page_count = page_number - 1 "
        "AND previous_page_receipt_id IS NOT NULL "
        "AND previous_page_receipt_sha256 IS NOT NULL "
        "AND previous_persisted_page_sha256 IS NOT NULL)",
        name="phase4_order_snapshot_preparation_predecessor_shape",
    ),
    sa.CheckConstraint(
        "page_number BETWEEN 1 AND 8",
        name="phase4_order_snapshot_preparation_page_bounds",
    ),
    sa.CheckConstraint(
        "length(preparation_sha256) = 64 "
        "AND length(snapshot_id) = 36 "
        "AND (before_order_id IS NULL OR length(before_order_id) = 36) "
        "AND (previous_page_receipt_id IS NULL "
        "OR length(previous_page_receipt_id) = 36) "
        "AND length(plan_sha256) = 64 "
        "AND length(description_sha256) = 64 "
        "AND length(prefix_capture_sha256) = 64 "
        "AND (previous_page_receipt_sha256 IS NULL "
        "OR length(previous_page_receipt_sha256) = 64) "
        "AND (previous_persisted_page_sha256 IS NULL "
        "OR length(previous_persisted_page_sha256) = 64)",
        name="phase4_order_snapshot_preparation_identity_lengths",
    ),
)
sa.Index(
    "ix_phase4_order_snapshot_preparation_account_time",
    phase4_alpaca_paper_order_snapshot_preparations.c.account_id,
    phase4_alpaca_paper_order_snapshot_preparations.c.prepared_at,
)

phase4_alpaca_paper_order_snapshot_heads = sa.Table(
    "phase4_alpaca_paper_order_snapshot_heads",
    metadata,
    sa.Column("snapshot_id", sa.String(36), primary_key=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("plan_sha256", sa.String(64), nullable=False),
    sa.Column("committed_page_count", sa.BigInteger(), nullable=False),
    sa.Column("last_page_receipt_id", sa.String(36), nullable=True),
    sa.Column("last_page_receipt_sha256", sa.String(64), nullable=True),
    sa.Column("last_persisted_page_sha256", sa.String(64), nullable=True),
    sa.Column("next_page_number", sa.BigInteger(), nullable=True),
    sa.Column("next_before_order_id", sa.String(36), nullable=True),
    sa.Column("next_previous_page_sha256", sa.String(64), nullable=True),
    sa.Column("prepared_description_sha256", sa.String(64), nullable=True),
    sa.Column("prepared_prefix_capture_sha256", sa.String(64), nullable=True),
    sa.Column("prepared_prefix_page_count", sa.BigInteger(), nullable=True),
    sa.Column("prepared_previous_page_receipt_id", sa.String(36), nullable=True),
    sa.Column("prepared_previous_page_receipt_sha256", sa.String(64), nullable=True),
    sa.Column("preparation_sha256", sa.String(64), nullable=True),
    sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("state", sa.String(32), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False),
    sa.UniqueConstraint(
        "snapshot_id",
        "account_id",
        "semantic_sha256",
        name="uq_phase4_order_snapshot_head_exact",
    ),
    sa.ForeignKeyConstraint(
        ["snapshot_id", "account_id", "plan_sha256"],
        [
            "phase4_alpaca_paper_order_snapshot_plans.snapshot_id",
            "phase4_alpaca_paper_order_snapshot_plans.account_id",
            "phase4_alpaca_paper_order_snapshot_plans.semantic_sha256",
        ],
        name="fk_phase4_order_snapshot_head_plan",
    ),
    sa.ForeignKeyConstraint(
        [
            "snapshot_id",
            "committed_page_count",
            "last_page_receipt_id",
            "last_page_receipt_sha256",
            "last_persisted_page_sha256",
        ],
        [
            "phase4_alpaca_paper_order_snapshot_pages.snapshot_id",
            "phase4_alpaca_paper_order_snapshot_pages.page_number",
            "phase4_alpaca_paper_order_snapshot_pages.receipt_id",
            "phase4_alpaca_paper_order_snapshot_pages.semantic_sha256",
            "phase4_alpaca_paper_order_snapshot_pages.persisted_page_sha256",
        ],
        name="fk_phase4_order_snapshot_head_terminal_page",
    ),
    sa.CheckConstraint(
        "(committed_page_count = 0 "
        "AND last_page_receipt_id IS NULL "
        "AND last_page_receipt_sha256 IS NULL "
        "AND last_persisted_page_sha256 IS NULL) "
        "OR (committed_page_count > 0 "
        "AND last_page_receipt_id IS NOT NULL "
        "AND last_page_receipt_sha256 IS NOT NULL "
        "AND last_persisted_page_sha256 IS NOT NULL)",
        name="phase4_order_snapshot_head_tip_shape",
    ),
    sa.CheckConstraint(
        "state IN ('active', 'cursor_exhausted_unisolated', 'bounded_truncated', 'stalled')",
        name="phase4_order_snapshot_head_state",
    ),
    sa.CheckConstraint(
        "(state IN ('active', 'stalled') "
        "AND next_page_number = committed_page_count + 1 "
        "AND next_page_number BETWEEN 1 AND 8 "
        "AND ((next_page_number = 1 "
        "AND next_before_order_id IS NULL "
        "AND next_previous_page_sha256 IS NULL) "
        "OR (next_page_number > 1 "
        "AND next_before_order_id IS NOT NULL "
        "AND next_previous_page_sha256 = last_persisted_page_sha256))) "
        "OR (state IN ('cursor_exhausted_unisolated', 'bounded_truncated') "
        "AND next_page_number IS NULL "
        "AND next_before_order_id IS NULL "
        "AND next_previous_page_sha256 IS NULL)",
        name="phase4_order_snapshot_head_next_shape",
    ),
    sa.CheckConstraint(
        "(state <> 'stalled' "
        "AND prepared_description_sha256 IS NULL "
        "AND prepared_prefix_capture_sha256 IS NULL "
        "AND prepared_prefix_page_count IS NULL "
        "AND prepared_previous_page_receipt_id IS NULL "
        "AND prepared_previous_page_receipt_sha256 IS NULL "
        "AND preparation_sha256 IS NULL "
        "AND prepared_at IS NULL) "
        "OR (state = 'stalled' "
        "AND prepared_description_sha256 IS NOT NULL "
        "AND prepared_prefix_capture_sha256 IS NOT NULL "
        "AND prepared_prefix_page_count = committed_page_count "
        "AND preparation_sha256 IS NOT NULL "
        "AND prepared_at IS NOT NULL "
        "AND ((committed_page_count = 0 "
        "AND prepared_previous_page_receipt_id IS NULL "
        "AND prepared_previous_page_receipt_sha256 IS NULL) "
        "OR (committed_page_count > 0 "
        "AND prepared_previous_page_receipt_id = last_page_receipt_id "
        "AND prepared_previous_page_receipt_sha256 = last_page_receipt_sha256)))",
        name="phase4_order_snapshot_head_preparation_shape",
    ),
    sa.CheckConstraint(
        "committed_page_count BETWEEN 0 AND 8",
        name="phase4_order_snapshot_head_page_bound",
    ),
    sa.CheckConstraint(
        "length(plan_sha256) = 64 "
        "AND (last_page_receipt_sha256 IS NULL "
        "OR length(last_page_receipt_sha256) = 64) "
        "AND (last_persisted_page_sha256 IS NULL "
        "OR length(last_persisted_page_sha256) = 64) "
        "AND (next_previous_page_sha256 IS NULL "
        "OR length(next_previous_page_sha256) = 64) "
        "AND (prepared_description_sha256 IS NULL "
        "OR length(prepared_description_sha256) = 64) "
        "AND (prepared_prefix_capture_sha256 IS NULL "
        "OR length(prepared_prefix_capture_sha256) = 64) "
        "AND (prepared_previous_page_receipt_sha256 IS NULL "
        "OR length(prepared_previous_page_receipt_sha256) = 64) "
        "AND (preparation_sha256 IS NULL OR length(preparation_sha256) = 64) "
        "AND length(semantic_sha256) = 64",
        name="phase4_order_snapshot_head_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 16384",
        name="phase4_order_snapshot_head_payload_size",
    ),
)
sa.Index(
    "ix_phase4_order_snapshot_head_account_state",
    phase4_alpaca_paper_order_snapshot_heads.c.account_id,
    phase4_alpaca_paper_order_snapshot_heads.c.state,
    phase4_alpaca_paper_order_snapshot_heads.c.updated_at,
)
sa.Index(
    "uq_phase4_order_snapshot_head_preparation",
    phase4_alpaca_paper_order_snapshot_heads.c.preparation_sha256,
    unique=True,
)

# Phase 6A durably retains provider-neutral trusted-time epochs and probe
# evaluations, including conservative source uncertainty, without granting
# scheduler, control, broker, exposure, or re-arm authority. Every process
# epoch starts at evaluation sequence zero; only a process-local repository
# session may extend it.
phase6_trusted_time_epoch_registrations = sa.Table(
    "phase6_trusted_time_epoch_registrations",
    metadata,
    sa.Column("monitor_epoch_id", sa.String(36), primary_key=True),
    sa.Column("host_id", sa.String(128), nullable=False),
    sa.Column("epoch_sequence", sa.BigInteger(), nullable=False),
    sa.Column("previous_monitor_epoch_id", sa.String(36), nullable=True),
    sa.Column("previous_epoch_sha256", sa.String(64), nullable=True),
    sa.Column("previous_host_head_sha256", sa.String(64), nullable=True),
    sa.Column("source_id", sa.String(128), nullable=False),
    sa.Column("source_authority_sha256", sa.String(64), nullable=False),
    sa.Column("policy_sha256", sa.String(64), nullable=False),
    sa.Column("registered_at_utc", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "host_id",
        "epoch_sequence",
        name="uq_phase6_trusted_time_epoch_host_sequence",
    ),
    sa.UniqueConstraint(
        "host_id",
        "monitor_epoch_id",
        "semantic_sha256",
        name="uq_phase6_trusted_time_epoch_exact",
    ),
    sa.UniqueConstraint(
        "host_id",
        "epoch_sequence",
        "monitor_epoch_id",
        "semantic_sha256",
        name="uq_phase6_trusted_time_epoch_tip",
    ),
    sa.ForeignKeyConstraint(
        [
            "host_id",
            "previous_monitor_epoch_id",
            "previous_epoch_sha256",
        ],
        [
            "phase6_trusted_time_epoch_registrations.host_id",
            "phase6_trusted_time_epoch_registrations.monitor_epoch_id",
            "phase6_trusted_time_epoch_registrations.semantic_sha256",
        ],
        name="fk_phase6_trusted_time_epoch_predecessor",
    ),
    sa.CheckConstraint(
        "(epoch_sequence = 1 "
        "AND previous_monitor_epoch_id IS NULL "
        "AND previous_epoch_sha256 IS NULL "
        "AND previous_host_head_sha256 IS NULL) "
        "OR (epoch_sequence > 1 "
        "AND previous_monitor_epoch_id IS NOT NULL "
        "AND previous_epoch_sha256 IS NOT NULL "
        "AND previous_host_head_sha256 IS NOT NULL)",
        name="phase6_trusted_time_epoch_predecessor_shape",
    ),
    sa.CheckConstraint(
        "length(monitor_epoch_id) = 36 "
        "AND length(host_id) BETWEEN 1 AND 128 "
        "AND length(source_id) BETWEEN 1 AND 128 "
        "AND length(source_authority_sha256) = 64 "
        "AND length(policy_sha256) = 64 "
        "AND policy_sha256 = "
        "'64b826c9300e02a5f1543dfb5e1d7684e32317777fb12ab96b95da834f3f697c' "
        "AND length(semantic_sha256) = 64 "
        "AND (previous_monitor_epoch_id IS NULL "
        "OR length(previous_monitor_epoch_id) = 36) "
        "AND (previous_epoch_sha256 IS NULL "
        "OR length(previous_epoch_sha256) = 64) "
        "AND (previous_host_head_sha256 IS NULL "
        "OR length(previous_host_head_sha256) = 64)",
        name="phase6_trusted_time_epoch_identity",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 65536",
        name="phase6_trusted_time_epoch_payload",
    ),
)
sa.Index(
    "ix_phase6_trusted_time_epoch_host_registered",
    phase6_trusted_time_epoch_registrations.c.host_id,
    phase6_trusted_time_epoch_registrations.c.registered_at_utc,
)

phase6_trusted_time_probe_evaluations = sa.Table(
    "phase6_trusted_time_probe_evaluations",
    metadata,
    sa.Column("evaluation_id", sa.String(36), primary_key=True),
    sa.Column("host_id", sa.String(128), nullable=False),
    sa.Column("monitor_epoch_id", sa.String(36), nullable=False),
    sa.Column("epoch_sha256", sa.String(64), nullable=False),
    sa.Column("evaluation_sequence", sa.BigInteger(), nullable=False),
    sa.Column("previous_evaluation_id", sa.String(36), nullable=True),
    sa.Column("previous_evaluation_sha256", sa.String(64), nullable=True),
    sa.Column("probe_status", sa.String(32), nullable=False),
    sa.Column("sample_sequence", sa.BigInteger(), nullable=True),
    sa.Column("source_evidence_sha256", sa.String(64), nullable=True),
    sa.Column("probe_started_at_utc", sa.DateTime(timezone=True), nullable=True),
    sa.Column("probe_completed_at_utc", sa.DateTime(timezone=True), nullable=True),
    sa.Column("trusted_at_utc", sa.DateTime(timezone=True), nullable=True),
    sa.Column("probe_started_monotonic_ns", sa.BigInteger(), nullable=True),
    sa.Column("probe_completed_monotonic_ns", sa.BigInteger(), nullable=True),
    sa.Column("sample_canonical_payload", sa.Text(), nullable=True),
    sa.Column("sample_sha256", sa.String(64), nullable=True),
    sa.Column("previous_state_sha256", sa.String(64), nullable=True),
    sa.Column("policy_sha256", sa.String(64), nullable=False),
    sa.Column("latest_sample_sha256", sa.String(64), nullable=True),
    sa.Column("sample_health", sa.String(16), nullable=False),
    sa.Column("health", sa.String(16), nullable=False),
    sa.Column("reason", sa.String(32), nullable=False),
    sa.Column("hard_failure_latched", sa.Boolean(), nullable=False),
    sa.Column("healthy_since_monotonic_ns", sa.BigInteger(), nullable=True),
    sa.Column("clock_recovery_qualified", sa.Boolean(), nullable=False),
    sa.Column("evaluated_at_utc", sa.DateTime(timezone=True), nullable=False),
    sa.Column("evaluated_at_monotonic_ns", sa.BigInteger(), nullable=False),
    sa.Column("state_canonical_payload", sa.Text(), nullable=False),
    sa.Column("state_sha256", sa.String(64), nullable=False),
    sa.Column("evaluation_sha256", sa.String(64), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("source_uncertainty_milliseconds", sa.Numeric(28, 10), nullable=True),
    sa.UniqueConstraint(
        "host_id",
        "monitor_epoch_id",
        "evaluation_sequence",
        name="uq_phase6_trusted_time_eval_epoch_sequence",
    ),
    sa.UniqueConstraint(
        "host_id",
        "monitor_epoch_id",
        "evaluation_id",
        "semantic_sha256",
        "state_sha256",
        name="uq_phase6_trusted_time_eval_exact",
    ),
    sa.UniqueConstraint(
        "host_id",
        "monitor_epoch_id",
        "evaluation_sequence",
        "evaluation_id",
        "semantic_sha256",
        "state_sha256",
        "health",
        "reason",
        "hard_failure_latched",
        "clock_recovery_qualified",
        "evaluated_at_utc",
        "evaluated_at_monotonic_ns",
        name="uq_phase6_trusted_time_eval_tip",
    ),
    sa.ForeignKeyConstraint(
        ["host_id", "monitor_epoch_id", "epoch_sha256"],
        [
            "phase6_trusted_time_epoch_registrations.host_id",
            "phase6_trusted_time_epoch_registrations.monitor_epoch_id",
            "phase6_trusted_time_epoch_registrations.semantic_sha256",
        ],
        name="fk_phase6_trusted_time_eval_epoch",
    ),
    sa.ForeignKeyConstraint(
        [
            "host_id",
            "monitor_epoch_id",
            "previous_evaluation_id",
            "previous_evaluation_sha256",
            "previous_state_sha256",
        ],
        [
            "phase6_trusted_time_probe_evaluations.host_id",
            "phase6_trusted_time_probe_evaluations.monitor_epoch_id",
            "phase6_trusted_time_probe_evaluations.evaluation_id",
            "phase6_trusted_time_probe_evaluations.semantic_sha256",
            "phase6_trusted_time_probe_evaluations.state_sha256",
        ],
        name="fk_phase6_trusted_time_eval_predecessor",
    ),
    sa.CheckConstraint(
        "(evaluation_sequence = 1 "
        "AND previous_evaluation_id IS NULL "
        "AND previous_evaluation_sha256 IS NULL "
        "AND previous_state_sha256 IS NULL) "
        "OR (evaluation_sequence > 1 "
        "AND previous_evaluation_id IS NOT NULL "
        "AND previous_evaluation_sha256 IS NOT NULL "
        "AND previous_state_sha256 IS NOT NULL)",
        name="phase6_trusted_time_eval_predecessor_shape",
    ),
    sa.CheckConstraint(
        "probe_status IN ("
        "'recorded', "
        "'source_unavailable', "
        "'source_identity_mismatch', "
        "'invalid_reading')",
        name="phase6_trusted_time_eval_probe_status",
    ),
    sa.CheckConstraint(
        "(probe_status = 'recorded' "
        "AND sample_sequence IS NOT NULL "
        "AND source_evidence_sha256 IS NOT NULL "
        "AND probe_started_at_utc IS NOT NULL "
        "AND probe_completed_at_utc IS NOT NULL "
        "AND trusted_at_utc IS NOT NULL "
        "AND source_uncertainty_milliseconds IS NOT NULL "
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
        "AND source_uncertainty_milliseconds IS NULL "
        "AND probe_started_monotonic_ns IS NULL "
        "AND probe_completed_monotonic_ns IS NULL "
        "AND sample_canonical_payload IS NULL "
        "AND sample_sha256 IS NULL)",
        name="phase6_trusted_time_eval_sample_shape",
    ),
    sa.CheckConstraint(
        "(sample_sequence IS NULL OR sample_sequence > 0) "
        "AND (probe_started_monotonic_ns IS NULL "
        "OR probe_started_monotonic_ns >= 0) "
        "AND (probe_completed_monotonic_ns IS NULL "
        "OR probe_completed_monotonic_ns >= probe_started_monotonic_ns) "
        "AND (probe_started_at_utc IS NULL "
        "OR probe_started_at_utc <= probe_completed_at_utc) "
        "AND (source_uncertainty_milliseconds IS NULL "
        "OR source_uncertainty_milliseconds BETWEEN 0 AND 100) "
        "AND (probe_completed_at_utc IS NULL "
        "OR probe_completed_at_utc <= evaluated_at_utc) "
        "AND (probe_completed_monotonic_ns IS NULL "
        "OR probe_completed_monotonic_ns <= evaluated_at_monotonic_ns)",
        name="phase6_trusted_time_eval_sample_order",
    ),
    sa.CheckConstraint(
        "sample_health IN ('healthy', 'warning', 'blocked') "
        "AND health IN ('healthy', 'warning', 'blocked') "
        "AND reason IN ("
        "'within_limit', "
        "'startup_no_sample', "
        "'startup_qualifying', "
        "'source_unavailable', "
        "'warning_offset', "
        "'hard_offset', "
        "'hard_offset_latched', "
        "'sample_stale', "
        "'identity_changed', "
        "'sequence_discontinuity', "
        "'cadence_gap', "
        "'utc_regression', "
        "'monotonic_regression')",
        name="phase6_trusted_time_eval_outcome",
    ),
    sa.CheckConstraint(
        "evaluation_sequence > 0 "
        "AND evaluated_at_monotonic_ns >= 0 "
        "AND (healthy_since_monotonic_ns IS NULL "
        "OR (healthy_since_monotonic_ns >= 0 "
        "AND healthy_since_monotonic_ns <= evaluated_at_monotonic_ns)) "
        "AND (NOT clock_recovery_qualified "
        "OR healthy_since_monotonic_ns IS NOT NULL)",
        name="phase6_trusted_time_eval_state_bounds",
    ),
    sa.CheckConstraint(
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
        "AND policy_sha256 = "
        "'64b826c9300e02a5f1543dfb5e1d7684e32317777fb12ab96b95da834f3f697c' "
        "AND (latest_sample_sha256 IS NULL "
        "OR length(latest_sample_sha256) = 64) "
        "AND length(state_sha256) = 64 "
        "AND length(evaluation_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase6_trusted_time_eval_identity",
    ),
    sa.CheckConstraint(
        "(sample_canonical_payload IS NULL "
        "OR length(sample_canonical_payload) BETWEEN 2 AND 65536) "
        "AND length(state_canonical_payload) BETWEEN 2 AND 65536 "
        "AND length(canonical_payload) BETWEEN 2 AND 262144",
        name="phase6_trusted_time_eval_payload",
    ),
)
sa.Index(
    "ix_phase6_trusted_time_eval_host_time",
    phase6_trusted_time_probe_evaluations.c.host_id,
    phase6_trusted_time_probe_evaluations.c.evaluated_at_utc,
)

phase6_trusted_time_host_heads = sa.Table(
    "phase6_trusted_time_host_heads",
    metadata,
    sa.Column("host_id", sa.String(128), primary_key=True),
    sa.Column("epoch_sequence", sa.BigInteger(), nullable=False),
    sa.Column("monitor_epoch_id", sa.String(36), nullable=False),
    sa.Column("epoch_sha256", sa.String(64), nullable=False),
    sa.Column("evaluation_sequence", sa.BigInteger(), nullable=False),
    sa.Column("evaluation_id", sa.String(36), nullable=True),
    sa.Column("evaluation_record_sha256", sa.String(64), nullable=True),
    sa.Column("state_sha256", sa.String(64), nullable=True),
    sa.Column("health", sa.String(16), nullable=True),
    sa.Column("reason", sa.String(32), nullable=True),
    sa.Column("hard_failure_latched", sa.Boolean(), nullable=True),
    sa.Column("clock_recovery_qualified", sa.Boolean(), nullable=True),
    sa.Column("evaluated_at_utc", sa.DateTime(timezone=True), nullable=True),
    sa.Column("evaluated_at_monotonic_ns", sa.BigInteger(), nullable=True),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        [
            "host_id",
            "epoch_sequence",
            "monitor_epoch_id",
            "epoch_sha256",
        ],
        [
            "phase6_trusted_time_epoch_registrations.host_id",
            "phase6_trusted_time_epoch_registrations.epoch_sequence",
            "phase6_trusted_time_epoch_registrations.monitor_epoch_id",
            "phase6_trusted_time_epoch_registrations.semantic_sha256",
        ],
        name="fk_phase6_trusted_time_head_epoch",
    ),
    sa.ForeignKeyConstraint(
        [
            "host_id",
            "monitor_epoch_id",
            "evaluation_sequence",
            "evaluation_id",
            "evaluation_record_sha256",
            "state_sha256",
            "health",
            "reason",
            "hard_failure_latched",
            "clock_recovery_qualified",
            "evaluated_at_utc",
            "evaluated_at_monotonic_ns",
        ],
        [
            "phase6_trusted_time_probe_evaluations.host_id",
            "phase6_trusted_time_probe_evaluations.monitor_epoch_id",
            "phase6_trusted_time_probe_evaluations.evaluation_sequence",
            "phase6_trusted_time_probe_evaluations.evaluation_id",
            "phase6_trusted_time_probe_evaluations.semantic_sha256",
            "phase6_trusted_time_probe_evaluations.state_sha256",
            "phase6_trusted_time_probe_evaluations.health",
            "phase6_trusted_time_probe_evaluations.reason",
            "phase6_trusted_time_probe_evaluations.hard_failure_latched",
            "phase6_trusted_time_probe_evaluations.clock_recovery_qualified",
            "phase6_trusted_time_probe_evaluations.evaluated_at_utc",
            "phase6_trusted_time_probe_evaluations.evaluated_at_monotonic_ns",
        ],
        name="fk_phase6_trusted_time_head_tip",
    ),
    sa.CheckConstraint(
        "(evaluation_sequence = 0 "
        "AND evaluation_id IS NULL "
        "AND evaluation_record_sha256 IS NULL "
        "AND state_sha256 IS NULL "
        "AND health IS NULL "
        "AND reason IS NULL "
        "AND hard_failure_latched IS NULL "
        "AND clock_recovery_qualified IS NULL "
        "AND evaluated_at_utc IS NULL "
        "AND evaluated_at_monotonic_ns IS NULL) "
        "OR (evaluation_sequence > 0 "
        "AND evaluation_id IS NOT NULL "
        "AND evaluation_record_sha256 IS NOT NULL "
        "AND state_sha256 IS NOT NULL "
        "AND health IS NOT NULL "
        "AND reason IS NOT NULL "
        "AND hard_failure_latched IS NOT NULL "
        "AND clock_recovery_qualified IS NOT NULL "
        "AND evaluated_at_utc IS NOT NULL "
        "AND evaluated_at_monotonic_ns IS NOT NULL)",
        name="phase6_trusted_time_head_evaluation_shape",
    ),
    sa.CheckConstraint(
        "epoch_sequence > 0 "
        "AND evaluation_sequence >= 0 "
        "AND (evaluated_at_monotonic_ns IS NULL "
        "OR evaluated_at_monotonic_ns >= 0) "
        "AND (health IS NULL OR health IN ('healthy', 'warning', 'blocked')) "
        "AND (reason IS NULL OR reason IN ("
        "'within_limit', "
        "'startup_no_sample', "
        "'startup_qualifying', "
        "'source_unavailable', "
        "'warning_offset', "
        "'hard_offset', "
        "'hard_offset_latched', "
        "'sample_stale', "
        "'identity_changed', "
        "'sequence_discontinuity', "
        "'cadence_gap', "
        "'utc_regression', "
        "'monotonic_regression'))",
        name="phase6_trusted_time_head_state",
    ),
    sa.CheckConstraint(
        "length(host_id) BETWEEN 1 AND 128 "
        "AND length(monitor_epoch_id) = 36 "
        "AND length(epoch_sha256) = 64 "
        "AND (evaluation_id IS NULL OR length(evaluation_id) = 36) "
        "AND (evaluation_record_sha256 IS NULL "
        "OR length(evaluation_record_sha256) = 64) "
        "AND (state_sha256 IS NULL OR length(state_sha256) = 64) "
        "AND length(semantic_sha256) = 64",
        name="phase6_trusted_time_head_identity",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 65536",
        name="phase6_trusted_time_head_payload",
    ),
)

# Phase 6D records one immutable local intent before external object I/O and
# one immutable success receipt only after byte-exact remote readback. Anchors
# form a sparse chain independent from the gap-free local trusted-time journal;
# enrollment never fabricates anchors for existing history.
phase6_trusted_time_head_anchor_intents = sa.Table(
    "phase6_trusted_time_head_anchor_intents",
    metadata,
    sa.Column("anchor_intent_id", sa.String(36), primary_key=True),
    sa.Column("host_id", sa.String(128), nullable=False),
    sa.Column("anchor_sequence", sa.BigInteger(), nullable=False),
    sa.Column("previous_anchor_sha256", sa.String(64), nullable=True),
    sa.Column(
        "previous_anchored_host_head_sha256",
        sa.String(64),
        nullable=True,
    ),
    sa.Column("checkpoint_reason", sa.String(32), nullable=False),
    sa.Column("checkpoint_interval_seconds", sa.BigInteger(), nullable=False),
    sa.Column("anchor_authority_sha256", sa.String(64), nullable=False),
    sa.Column("deployment_identity_sha256", sa.String(64), nullable=False),
    sa.Column("runtime_database_identity_sha256", sa.String(64), nullable=False),
    sa.Column("anchor_project_identity_sha256", sa.String(64), nullable=False),
    sa.Column("anchor_project_ref", sa.String(20), nullable=False),
    sa.Column("bucket_name", sa.String(128), nullable=False),
    sa.Column("principal_id", sa.String(36), nullable=False),
    sa.Column("signing_key_id", sa.String(128), nullable=False),
    sa.Column("signing_public_key_sha256", sa.String(64), nullable=False),
    sa.Column("head_authenticated_at_utc", sa.DateTime(timezone=True), nullable=False),
    sa.Column("source_id", sa.String(128), nullable=False),
    sa.Column("source_authority_sha256", sa.String(64), nullable=False),
    sa.Column("policy_sha256", sa.String(64), nullable=False),
    sa.Column("persistence_contract_version", sa.String(64), nullable=False),
    sa.Column("epoch_sequence", sa.BigInteger(), nullable=False),
    sa.Column("monitor_epoch_id", sa.String(36), nullable=False),
    sa.Column("epoch_sha256", sa.String(64), nullable=False),
    sa.Column("evaluation_sequence", sa.BigInteger(), nullable=False),
    sa.Column("evaluation_id", sa.String(36), nullable=True),
    sa.Column("evaluation_record_sha256", sa.String(64), nullable=True),
    sa.Column("state_sha256", sa.String(64), nullable=True),
    sa.Column("probe_status", sa.String(32), nullable=True),
    sa.Column("health", sa.String(16), nullable=True),
    sa.Column("reason", sa.String(32), nullable=True),
    sa.Column("hard_failure_latched", sa.Boolean(), nullable=True),
    sa.Column("clock_recovery_qualified", sa.Boolean(), nullable=True),
    sa.Column("evaluated_at_utc", sa.DateTime(timezone=True), nullable=True),
    sa.Column("evaluated_at_monotonic_ns", sa.BigInteger(), nullable=True),
    sa.Column("local_previous_host_head_sha256", sa.String(64), nullable=True),
    sa.Column("current_host_head_sha256", sa.String(64), nullable=False),
    sa.Column("host_identity_sha256", sa.String(64), nullable=False),
    sa.Column("object_name", sa.String(512), nullable=False),
    sa.Column("signed_envelope_bytes", sa.LargeBinary(), nullable=False),
    sa.Column("signed_envelope_text", sa.Text(), nullable=False),
    sa.Column("signed_envelope_sha256", sa.String(64), nullable=False),
    sa.Column("created_at_utc", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False),
    sa.UniqueConstraint(
        "semantic_sha256",
        name="uq_phase6_anchor_intent_semantic",
    ),
    sa.UniqueConstraint(
        "signed_envelope_sha256",
        name="uq_phase6_anchor_intent_envelope",
    ),
    sa.UniqueConstraint(
        "host_id",
        "anchor_sequence",
        name="uq_phase6_anchor_intent_host_sequence",
    ),
    sa.UniqueConstraint(
        "host_id",
        "current_host_head_sha256",
        name="uq_phase6_anchor_intent_host_head",
    ),
    sa.UniqueConstraint(
        "host_id",
        "signed_envelope_sha256",
        "current_host_head_sha256",
        name="uq_phase6_anchor_intent_predecessor_target",
    ),
    sa.UniqueConstraint(
        "anchor_project_identity_sha256",
        "anchor_project_ref",
        "bucket_name",
        "object_name",
        name="uq_phase6_anchor_intent_object",
    ),
    sa.UniqueConstraint(
        "anchor_intent_id",
        "semantic_sha256",
        "signed_envelope_sha256",
        "deployment_identity_sha256",
        "runtime_database_identity_sha256",
        "anchor_project_identity_sha256",
        "anchor_project_ref",
        "bucket_name",
        "principal_id",
        "object_name",
        name="uq_phase6_anchor_intent_receipt_binding",
    ),
    sa.ForeignKeyConstraint(
        [
            "host_id",
            "previous_anchor_sha256",
            "previous_anchored_host_head_sha256",
        ],
        [
            "phase6_trusted_time_head_anchor_intents.host_id",
            "phase6_trusted_time_head_anchor_intents.signed_envelope_sha256",
            "phase6_trusted_time_head_anchor_intents.current_host_head_sha256",
        ],
        name="fk_phase6_anchor_intent_predecessor",
    ),
    sa.ForeignKeyConstraint(
        ["host_id", "epoch_sequence", "monitor_epoch_id", "epoch_sha256"],
        [
            "phase6_trusted_time_epoch_registrations.host_id",
            "phase6_trusted_time_epoch_registrations.epoch_sequence",
            "phase6_trusted_time_epoch_registrations.monitor_epoch_id",
            "phase6_trusted_time_epoch_registrations.semantic_sha256",
        ],
        name="fk_phase6_anchor_intent_epoch",
    ),
    sa.ForeignKeyConstraint(
        [
            "host_id",
            "monitor_epoch_id",
            "evaluation_sequence",
            "evaluation_id",
            "evaluation_record_sha256",
            "state_sha256",
            "health",
            "reason",
            "hard_failure_latched",
            "clock_recovery_qualified",
            "evaluated_at_utc",
            "evaluated_at_monotonic_ns",
        ],
        [
            "phase6_trusted_time_probe_evaluations.host_id",
            "phase6_trusted_time_probe_evaluations.monitor_epoch_id",
            "phase6_trusted_time_probe_evaluations.evaluation_sequence",
            "phase6_trusted_time_probe_evaluations.evaluation_id",
            "phase6_trusted_time_probe_evaluations.semantic_sha256",
            "phase6_trusted_time_probe_evaluations.state_sha256",
            "phase6_trusted_time_probe_evaluations.health",
            "phase6_trusted_time_probe_evaluations.reason",
            "phase6_trusted_time_probe_evaluations.hard_failure_latched",
            "phase6_trusted_time_probe_evaluations.clock_recovery_qualified",
            "phase6_trusted_time_probe_evaluations.evaluated_at_utc",
            "phase6_trusted_time_probe_evaluations.evaluated_at_monotonic_ns",
        ],
        name="fk_phase6_anchor_intent_evaluation",
    ),
    sa.CheckConstraint(
        "(anchor_sequence = 1 "
        "AND previous_anchor_sha256 IS NULL "
        "AND previous_anchored_host_head_sha256 IS NULL "
        "AND checkpoint_reason = 'enrollment') "
        "OR (anchor_sequence > 1 "
        "AND previous_anchor_sha256 IS NOT NULL "
        "AND previous_anchored_host_head_sha256 IS NOT NULL "
        "AND checkpoint_reason <> 'enrollment')",
        name="phase6_anchor_intent_predecessor_shape",
    ),
    sa.CheckConstraint(
        "checkpoint_reason IN ("
        "'enrollment', "
        "'epoch_rotation', "
        "'periodic', "
        "'hard_failure', "
        "'health_transition', "
        "'recovery_transition', "
        "'clean_stop', "
        "'on_demand') "
        "AND checkpoint_interval_seconds = 300",
        name="phase6_anchor_intent_checkpoint_policy",
    ),
    sa.CheckConstraint(
        "(evaluation_sequence = 0 "
        "AND evaluation_id IS NULL "
        "AND evaluation_record_sha256 IS NULL "
        "AND state_sha256 IS NULL "
        "AND probe_status IS NULL "
        "AND health IS NULL "
        "AND reason IS NULL "
        "AND hard_failure_latched IS NULL "
        "AND clock_recovery_qualified IS NULL "
        "AND evaluated_at_utc IS NULL "
        "AND evaluated_at_monotonic_ns IS NULL) "
        "OR (evaluation_sequence > 0 "
        "AND evaluation_id IS NOT NULL "
        "AND evaluation_record_sha256 IS NOT NULL "
        "AND state_sha256 IS NOT NULL "
        "AND probe_status IS NOT NULL "
        "AND health IS NOT NULL "
        "AND reason IS NOT NULL "
        "AND hard_failure_latched IS NOT NULL "
        "AND clock_recovery_qualified IS NOT NULL "
        "AND evaluated_at_utc IS NOT NULL "
        "AND evaluated_at_monotonic_ns IS NOT NULL)",
        name="phase6_anchor_intent_evaluation_shape",
    ),
    sa.CheckConstraint(
        "((epoch_sequence = 1 AND evaluation_sequence = 0) "
        "AND local_previous_host_head_sha256 IS NULL) "
        "OR ((epoch_sequence > 1 OR evaluation_sequence > 0) "
        "AND local_previous_host_head_sha256 IS NOT NULL)",
        name="phase6_anchor_intent_local_head_shape",
    ),
    sa.CheckConstraint(
        "anchor_sequence > 0 "
        "AND epoch_sequence > 0 "
        "AND evaluation_sequence >= 0 "
        "AND length(anchor_intent_id) = 36 "
        "AND length(host_id) BETWEEN 1 AND 128 "
        "AND (previous_anchor_sha256 IS NULL "
        "OR length(previous_anchor_sha256) = 64) "
        "AND (previous_anchored_host_head_sha256 IS NULL "
        "OR length(previous_anchored_host_head_sha256) = 64) "
        "AND length(anchor_authority_sha256) = 64 "
        "AND length(deployment_identity_sha256) = 64 "
        "AND length(runtime_database_identity_sha256) = 64 "
        "AND length(anchor_project_identity_sha256) = 64 "
        "AND length(anchor_project_ref) = 20 "
        "AND length(bucket_name) BETWEEN 1 AND 128 "
        "AND bucket_name = 'aqt-trusted-time-anchors-v1' "
        "AND length(principal_id) = 36 "
        "AND length(signing_key_id) BETWEEN 1 AND 128 "
        "AND length(signing_public_key_sha256) = 64 "
        "AND length(source_id) BETWEEN 1 AND 128 "
        "AND length(source_authority_sha256) = 64 "
        "AND length(policy_sha256) = 64 "
        "AND policy_sha256 = "
        "'64b826c9300e02a5f1543dfb5e1d7684e32317777fb12ab96b95da834f3f697c' "
        "AND persistence_contract_version = "
        "'phase6a-durable-trusted-time-persistence-v2' "
        "AND length(monitor_epoch_id) = 36 "
        "AND length(epoch_sha256) = 64 "
        "AND (evaluation_id IS NULL OR length(evaluation_id) = 36) "
        "AND (evaluation_record_sha256 IS NULL "
        "OR length(evaluation_record_sha256) = 64) "
        "AND (state_sha256 IS NULL OR length(state_sha256) = 64) "
        "AND (probe_status IS NULL OR probe_status IN ("
        "'recorded', "
        "'source_unavailable', "
        "'source_identity_mismatch', "
        "'invalid_reading')) "
        "AND (health IS NULL OR health IN ('healthy', 'warning', 'blocked')) "
        "AND (local_previous_host_head_sha256 IS NULL "
        "OR length(local_previous_host_head_sha256) = 64) "
        "AND length(current_host_head_sha256) = 64 "
        "AND (local_previous_host_head_sha256 IS NULL "
        "OR local_previous_host_head_sha256 <> current_host_head_sha256) "
        "AND (previous_anchored_host_head_sha256 IS NULL "
        "OR previous_anchored_host_head_sha256 <> current_host_head_sha256) "
        "AND length(host_identity_sha256) = 64 "
        "AND length(signed_envelope_sha256) = 64 "
        "AND length(semantic_sha256) = 64 "
        "AND (evaluated_at_utc IS NULL "
        "OR evaluated_at_utc = head_authenticated_at_utc) "
        "AND (evaluated_at_monotonic_ns IS NULL "
        "OR evaluated_at_monotonic_ns >= 0)",
        name="phase6_anchor_intent_identity",
    ),
    sa.CheckConstraint(
        "length(object_name) = 223 "
        "AND substr(object_name, 1, 133) = 'v1/' "
        "|| deployment_identity_sha256 || '/' "
        "|| host_identity_sha256 || '/' "
        "AND substr(object_name, 134, 1) BETWEEN '0' AND '9' "
        "AND substr(object_name, 135, 1) BETWEEN '0' AND '9' "
        "AND substr(object_name, 136, 1) BETWEEN '0' AND '9' "
        "AND substr(object_name, 137, 1) BETWEEN '0' AND '9' "
        "AND substr(object_name, 138, 1) BETWEEN '0' AND '9' "
        "AND substr(object_name, 139, 1) BETWEEN '0' AND '9' "
        "AND substr(object_name, 140, 1) BETWEEN '0' AND '9' "
        "AND substr(object_name, 141, 1) BETWEEN '0' AND '9' "
        "AND substr(object_name, 142, 1) BETWEEN '0' AND '9' "
        "AND substr(object_name, 143, 1) BETWEEN '0' AND '9' "
        "AND substr(object_name, 144, 1) BETWEEN '0' AND '9' "
        "AND substr(object_name, 145, 1) BETWEEN '0' AND '9' "
        "AND substr(object_name, 146, 1) BETWEEN '0' AND '9' "
        "AND substr(object_name, 147, 1) BETWEEN '0' AND '9' "
        "AND substr(object_name, 148, 1) BETWEEN '0' AND '9' "
        "AND substr(object_name, 149, 1) BETWEEN '0' AND '9' "
        "AND substr(object_name, 150, 1) BETWEEN '0' AND '9' "
        "AND substr(object_name, 151, 1) BETWEEN '0' AND '9' "
        "AND substr(object_name, 152, 1) BETWEEN '0' AND '9' "
        "AND substr(object_name, 153, 1) BETWEEN '0' AND '9' "
        "AND CAST(substr(object_name, 134, 20) AS BIGINT) = anchor_sequence "
        "AND substr(object_name, 154, 70) = '-' "
        "|| signed_envelope_sha256 || '.json'",
        name="phase6_anchor_intent_object_name",
    ),
    sa.CheckConstraint(
        "length(signed_envelope_bytes) BETWEEN 2 AND 4096 "
        "AND length(signed_envelope_text) BETWEEN 2 AND 4096 "
        "AND length(canonical_payload) BETWEEN 2 AND 65536",
        name="phase6_anchor_intent_payload",
    ),
)
sa.Index(
    "ix_phase6_anchor_intent_host_created",
    phase6_trusted_time_head_anchor_intents.c.host_id,
    phase6_trusted_time_head_anchor_intents.c.created_at_utc,
)

phase6_trusted_time_head_anchor_receipts = sa.Table(
    "phase6_trusted_time_head_anchor_receipts",
    metadata,
    sa.Column("anchor_receipt_id", sa.String(36), primary_key=True),
    sa.Column("anchor_intent_id", sa.String(36), nullable=False),
    sa.Column("anchor_intent_sha256", sa.String(64), nullable=False),
    sa.Column("signed_envelope_sha256", sa.String(64), nullable=False),
    sa.Column("deployment_identity_sha256", sa.String(64), nullable=False),
    sa.Column("runtime_database_identity_sha256", sa.String(64), nullable=False),
    sa.Column("anchor_project_identity_sha256", sa.String(64), nullable=False),
    sa.Column("anchor_project_ref", sa.String(20), nullable=False),
    sa.Column("bucket_name", sa.String(128), nullable=False),
    sa.Column("principal_id", sa.String(36), nullable=False),
    sa.Column("object_name", sa.String(512), nullable=False),
    sa.Column("readback_bytes_sha256", sa.String(64), nullable=False),
    sa.Column("observed_at_utc", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False),
    sa.UniqueConstraint(
        "anchor_intent_id",
        name="uq_phase6_anchor_receipt_intent",
    ),
    sa.UniqueConstraint(
        "semantic_sha256",
        name="uq_phase6_anchor_receipt_semantic",
    ),
    sa.ForeignKeyConstraint(
        [
            "anchor_intent_id",
            "anchor_intent_sha256",
            "signed_envelope_sha256",
            "deployment_identity_sha256",
            "runtime_database_identity_sha256",
            "anchor_project_identity_sha256",
            "anchor_project_ref",
            "bucket_name",
            "principal_id",
            "object_name",
        ],
        [
            "phase6_trusted_time_head_anchor_intents.anchor_intent_id",
            "phase6_trusted_time_head_anchor_intents.semantic_sha256",
            "phase6_trusted_time_head_anchor_intents.signed_envelope_sha256",
            "phase6_trusted_time_head_anchor_intents.deployment_identity_sha256",
            "phase6_trusted_time_head_anchor_intents.runtime_database_identity_sha256",
            "phase6_trusted_time_head_anchor_intents.anchor_project_identity_sha256",
            "phase6_trusted_time_head_anchor_intents.anchor_project_ref",
            "phase6_trusted_time_head_anchor_intents.bucket_name",
            "phase6_trusted_time_head_anchor_intents.principal_id",
            "phase6_trusted_time_head_anchor_intents.object_name",
        ],
        name="fk_phase6_anchor_receipt_intent",
    ),
    sa.CheckConstraint(
        "length(anchor_receipt_id) = 36 "
        "AND length(anchor_intent_id) = 36 "
        "AND length(anchor_intent_sha256) = 64 "
        "AND length(signed_envelope_sha256) = 64 "
        "AND length(deployment_identity_sha256) = 64 "
        "AND length(runtime_database_identity_sha256) = 64 "
        "AND length(anchor_project_identity_sha256) = 64 "
        "AND length(anchor_project_ref) = 20 "
        "AND length(bucket_name) BETWEEN 1 AND 128 "
        "AND bucket_name = 'aqt-trusted-time-anchors-v1' "
        "AND length(principal_id) = 36 "
        "AND length(object_name) BETWEEN 1 AND 512 "
        "AND length(readback_bytes_sha256) = 64 "
        "AND readback_bytes_sha256 = signed_envelope_sha256 "
        "AND length(semantic_sha256) = 64",
        name="phase6_anchor_receipt_identity",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 65536",
        name="phase6_anchor_receipt_payload",
    ),
)
sa.Index(
    "ix_phase6_anchor_receipt_observed",
    phase6_trusted_time_head_anchor_receipts.c.observed_at_utc,
)

# Phase 4AA reserves one exact ordered pair before either order traversal is
# prepared. Claims are page-granular immutable facts and consumptions bind
# those claims to the unchanged Phase 4O single-use preparation.
phase4_alpaca_paper_order_transition_members = sa.Table(
    "phase4_alpaca_paper_order_transition_members",
    metadata,
    sa.Column("member_id", sa.String(36), primary_key=True),
    sa.Column("round_id", sa.String(36), nullable=False),
    sa.Column("member_role", sa.String(16), nullable=False),
    sa.Column("transition_plan_sha256", sa.String(64), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("snapshot_id", sa.String(36), nullable=False, unique=True),
    sa.Column("capture_idempotency_key", sa.String(128), nullable=False),
    sa.Column("page_limit", sa.BigInteger(), nullable=False),
    sa.Column("maximum_pages", sa.BigInteger(), nullable=False),
    sa.Column("plan_canonical_payload", sa.Text(), nullable=False),
    sa.Column("plan_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "round_id",
        "member_role",
        name="uq_phase4_order_transition_member_role",
    ),
    sa.UniqueConstraint(
        "account_id",
        "capture_idempotency_key",
        name="uq_phase4_order_transition_member_account_key",
    ),
    sa.UniqueConstraint(
        "member_id",
        "round_id",
        "member_role",
        "transition_plan_sha256",
        "account_id",
        "snapshot_id",
        "plan_sha256",
        "semantic_sha256",
        name="uq_phase4_order_transition_member_exact",
    ),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase4_order_transition_member_account",
    ),
    sa.CheckConstraint(
        "member_role IN ('earlier', 'later') "
        "AND page_limit BETWEEN 1 AND 500 "
        "AND maximum_pages BETWEEN 1 AND 8",
        name="phase4_order_transition_member_scope",
    ),
    sa.CheckConstraint(
        "length(member_id) = 36 "
        "AND length(round_id) = 36 "
        "AND length(snapshot_id) = 36 "
        "AND length(transition_plan_sha256) = 64 "
        "AND length(plan_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_order_transition_member_identity",
    ),
    sa.CheckConstraint(
        "length(capture_idempotency_key) BETWEEN 8 AND 128 "
        "AND length(plan_canonical_payload) BETWEEN 2 AND 16384 "
        "AND length(canonical_payload) BETWEEN 2 AND 32768",
        name="phase4_order_transition_member_payload",
    ),
)
sa.Index(
    "ix_phase4_order_transition_member_account_round",
    phase4_alpaca_paper_order_transition_members.c.account_id,
    phase4_alpaca_paper_order_transition_members.c.round_id,
)

phase4_alpaca_paper_order_transition_claims = sa.Table(
    "phase4_alpaca_paper_order_transition_claims",
    metadata,
    sa.Column("claim_id", sa.String(36), primary_key=True),
    sa.Column("round_id", sa.String(36), nullable=False),
    sa.Column("transition_plan_sha256", sa.String(64), nullable=False),
    sa.Column("selected_role", sa.String(16), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("earlier_member_id", sa.String(36), nullable=False),
    sa.Column("earlier_member_role", sa.String(16), nullable=False),
    sa.Column("earlier_member_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_snapshot_id", sa.String(36), nullable=False),
    sa.Column("earlier_plan_sha256", sa.String(64), nullable=False),
    sa.Column("later_member_id", sa.String(36), nullable=False),
    sa.Column("later_member_role", sa.String(16), nullable=False),
    sa.Column("later_member_sha256", sa.String(64), nullable=False),
    sa.Column("later_snapshot_id", sa.String(36), nullable=False),
    sa.Column("later_plan_sha256", sa.String(64), nullable=False),
    sa.Column("selected_member_id", sa.String(36), nullable=False),
    sa.Column("selected_snapshot_id", sa.String(36), nullable=False),
    sa.Column("selected_plan_sha256", sa.String(64), nullable=False),
    sa.Column("page_number", sa.BigInteger(), nullable=False),
    sa.Column("description_sha256", sa.String(64), nullable=False),
    sa.Column("before_order_id", sa.String(36), nullable=True),
    sa.Column("prefix_id", sa.String(36), nullable=False),
    sa.Column("prefix_sha256", sa.String(64), nullable=False),
    sa.Column("prefix_capture_sha256", sa.String(64), nullable=False),
    sa.Column("prefix_page_count", sa.BigInteger(), nullable=False),
    sa.Column("previous_page_receipt_id", sa.String(36), nullable=True),
    sa.Column("previous_page_receipt_sha256", sa.String(64), nullable=True),
    sa.Column("previous_persisted_page_sha256", sa.String(64), nullable=True),
    sa.Column("previous_claim_id", sa.String(36), nullable=True),
    sa.Column("previous_claim_sha256", sa.String(64), nullable=True),
    sa.Column("prior_earlier_prefix_id", sa.String(36), nullable=True),
    sa.Column("prior_earlier_prefix_sha256", sa.String(64), nullable=True),
    sa.Column("prior_earlier_source_head_sha256", sa.String(64), nullable=True),
    sa.Column("prior_earlier_tip_receipt_id", sa.String(36), nullable=True),
    sa.Column("prior_earlier_tip_receipt_sha256", sa.String(64), nullable=True),
    sa.Column("prior_earlier_tip_received_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("eligible_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("fence_owner_id", sa.String(128), nullable=False),
    sa.Column("fence_lease_id", sa.String(64), nullable=False),
    sa.Column("fence_fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column("fence_policy_sha256", sa.String(64), nullable=False),
    sa.Column("commit_fence_lease_sha256", sa.String(64), nullable=False),
    sa.Column("commit_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("selected_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("commit_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("transition_policy_sha256", sa.String(64), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "round_id",
        "selected_role",
        "page_number",
        name="uq_phase4_order_transition_claim_page",
    ),
    sa.UniqueConstraint(
        "claim_id",
        "semantic_sha256",
        name="uq_phase4_order_transition_claim_identity",
    ),
    sa.UniqueConstraint(
        "claim_id",
        "semantic_sha256",
        "round_id",
        "selected_role",
        "selected_member_id",
        "selected_snapshot_id",
        "selected_plan_sha256",
        "page_number",
        "description_sha256",
        "fence_owner_id",
        "fence_lease_id",
        "fence_fencing_generation",
        "fence_sha256",
        "fence_policy_sha256",
        "commit_fence_lease_sha256",
        "commit_fence_receipt_sha256",
        "selected_at",
        "commit_fence_valid_until",
        name="uq_phase4_order_transition_claim_exact",
    ),
    sa.ForeignKeyConstraint(
        [
            "earlier_member_id",
            "round_id",
            "earlier_member_role",
            "transition_plan_sha256",
            "account_id",
            "earlier_snapshot_id",
            "earlier_plan_sha256",
            "earlier_member_sha256",
        ],
        [
            "phase4_alpaca_paper_order_transition_members.member_id",
            "phase4_alpaca_paper_order_transition_members.round_id",
            "phase4_alpaca_paper_order_transition_members.member_role",
            "phase4_alpaca_paper_order_transition_members.transition_plan_sha256",
            "phase4_alpaca_paper_order_transition_members.account_id",
            "phase4_alpaca_paper_order_transition_members.snapshot_id",
            "phase4_alpaca_paper_order_transition_members.plan_sha256",
            "phase4_alpaca_paper_order_transition_members.semantic_sha256",
        ],
        name="fk_phase4_order_transition_claim_earlier",
    ),
    sa.ForeignKeyConstraint(
        [
            "later_member_id",
            "round_id",
            "later_member_role",
            "transition_plan_sha256",
            "account_id",
            "later_snapshot_id",
            "later_plan_sha256",
            "later_member_sha256",
        ],
        [
            "phase4_alpaca_paper_order_transition_members.member_id",
            "phase4_alpaca_paper_order_transition_members.round_id",
            "phase4_alpaca_paper_order_transition_members.member_role",
            "phase4_alpaca_paper_order_transition_members.transition_plan_sha256",
            "phase4_alpaca_paper_order_transition_members.account_id",
            "phase4_alpaca_paper_order_transition_members.snapshot_id",
            "phase4_alpaca_paper_order_transition_members.plan_sha256",
            "phase4_alpaca_paper_order_transition_members.semantic_sha256",
        ],
        name="fk_phase4_order_transition_claim_later",
    ),
    sa.ForeignKeyConstraint(
        ["previous_claim_id", "previous_claim_sha256"],
        [
            "phase4_alpaca_paper_order_transition_claims.claim_id",
            "phase4_alpaca_paper_order_transition_claims.semantic_sha256",
        ],
        name="fk_phase4_order_transition_claim_predecessor",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "fence_fencing_generation", "commit_fence_lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase4_order_transition_claim_lease",
    ),
    sa.CheckConstraint(
        "selected_role IN ('earlier', 'later') "
        "AND earlier_member_role = 'earlier' "
        "AND later_member_role = 'later' "
        "AND earlier_member_id <> later_member_id "
        "AND earlier_snapshot_id <> later_snapshot_id",
        name="phase4_order_transition_claim_scope",
    ),
    sa.CheckConstraint(
        "(selected_role = 'earlier' "
        "AND selected_member_id = earlier_member_id "
        "AND selected_snapshot_id = earlier_snapshot_id "
        "AND selected_plan_sha256 = earlier_plan_sha256 "
        "AND prior_earlier_prefix_id IS NULL "
        "AND prior_earlier_prefix_sha256 IS NULL "
        "AND prior_earlier_source_head_sha256 IS NULL "
        "AND prior_earlier_tip_receipt_id IS NULL "
        "AND prior_earlier_tip_receipt_sha256 IS NULL "
        "AND prior_earlier_tip_received_at IS NULL "
        "AND eligible_at IS NULL) "
        "OR (selected_role = 'later' "
        "AND selected_member_id = later_member_id "
        "AND selected_snapshot_id = later_snapshot_id "
        "AND selected_plan_sha256 = later_plan_sha256 "
        "AND prior_earlier_prefix_id IS NOT NULL "
        "AND prior_earlier_prefix_sha256 IS NOT NULL "
        "AND prior_earlier_source_head_sha256 IS NOT NULL "
        "AND prior_earlier_tip_receipt_id IS NOT NULL "
        "AND prior_earlier_tip_receipt_sha256 IS NOT NULL "
        "AND prior_earlier_tip_received_at IS NOT NULL "
        "AND eligible_at IS NOT NULL "
        "AND selected_at >= eligible_at)",
        name="phase4_order_transition_claim_role_shape",
    ),
    sa.CheckConstraint(
        "(page_number = 1 "
        "AND prefix_page_count = 0 "
        "AND before_order_id IS NULL "
        "AND previous_page_receipt_id IS NULL "
        "AND previous_page_receipt_sha256 IS NULL "
        "AND previous_persisted_page_sha256 IS NULL "
        "AND previous_claim_id IS NULL "
        "AND previous_claim_sha256 IS NULL) "
        "OR (page_number > 1 "
        "AND prefix_page_count = page_number - 1 "
        "AND before_order_id IS NOT NULL "
        "AND previous_page_receipt_id IS NOT NULL "
        "AND previous_page_receipt_sha256 IS NOT NULL "
        "AND previous_persisted_page_sha256 IS NOT NULL "
        "AND previous_claim_id IS NOT NULL "
        "AND previous_claim_sha256 IS NOT NULL)",
        name="phase4_order_transition_claim_page_shape",
    ),
    sa.CheckConstraint(
        "page_number BETWEEN 1 AND 8 "
        "AND fence_fencing_generation > 0 "
        "AND selected_at < commit_fence_valid_until",
        name="phase4_order_transition_claim_bounds",
    ),
    sa.CheckConstraint(
        "length(claim_id) = 36 "
        "AND length(round_id) = 36 "
        "AND length(prefix_id) = 36 "
        "AND length(transition_plan_sha256) = 64 "
        "AND length(description_sha256) = 64 "
        "AND length(prefix_sha256) = 64 "
        "AND length(prefix_capture_sha256) = 64 "
        "AND length(fence_sha256) = 64 "
        "AND length(fence_policy_sha256) = 64 "
        "AND length(commit_fence_lease_sha256) = 64 "
        "AND length(commit_fence_receipt_sha256) = 64 "
        "AND length(transition_policy_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_order_transition_claim_identity",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 131072",
        name="phase4_order_transition_claim_payload",
    ),
)
sa.Index(
    "ix_phase4_order_transition_claim_account_selected",
    phase4_alpaca_paper_order_transition_claims.c.account_id,
    phase4_alpaca_paper_order_transition_claims.c.selected_at,
)

phase4_alpaca_paper_order_transition_consumptions = sa.Table(
    "phase4_alpaca_paper_order_transition_consumptions",
    metadata,
    sa.Column("consumption_id", sa.String(36), primary_key=True),
    sa.Column("claim_id", sa.String(36), nullable=False, unique=True),
    sa.Column("claim_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("round_id", sa.String(36), nullable=False),
    sa.Column("selected_role", sa.String(16), nullable=False),
    sa.Column("selected_member_id", sa.String(36), nullable=False),
    sa.Column("selected_snapshot_id", sa.String(36), nullable=False),
    sa.Column("selected_plan_sha256", sa.String(64), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("page_number", sa.BigInteger(), nullable=False),
    sa.Column("description_sha256", sa.String(64), nullable=False),
    sa.Column("preparation_id", sa.String(36), nullable=False, unique=True),
    sa.Column("preparation_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("prefix_capture_sha256", sa.String(64), nullable=False),
    sa.Column("prefix_page_count", sa.BigInteger(), nullable=False),
    sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("fence_owner_id", sa.String(128), nullable=False),
    sa.Column("fence_lease_id", sa.String(64), nullable=False),
    sa.Column("fence_fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column("fence_policy_sha256", sa.String(64), nullable=False),
    sa.Column("commit_fence_lease_sha256", sa.String(64), nullable=False),
    sa.Column("claim_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("claim_selected_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("commit_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("commit_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        [
            "claim_id",
            "claim_sha256",
            "round_id",
            "selected_role",
            "selected_member_id",
            "selected_snapshot_id",
            "selected_plan_sha256",
            "page_number",
            "description_sha256",
            "fence_owner_id",
            "fence_lease_id",
            "fence_fencing_generation",
            "fence_sha256",
            "fence_policy_sha256",
            "commit_fence_lease_sha256",
            "claim_fence_receipt_sha256",
            "claim_selected_at",
            "commit_fence_valid_until",
        ],
        [
            "phase4_alpaca_paper_order_transition_claims.claim_id",
            "phase4_alpaca_paper_order_transition_claims.semantic_sha256",
            "phase4_alpaca_paper_order_transition_claims.round_id",
            "phase4_alpaca_paper_order_transition_claims.selected_role",
            "phase4_alpaca_paper_order_transition_claims.selected_member_id",
            "phase4_alpaca_paper_order_transition_claims.selected_snapshot_id",
            "phase4_alpaca_paper_order_transition_claims.selected_plan_sha256",
            "phase4_alpaca_paper_order_transition_claims.page_number",
            "phase4_alpaca_paper_order_transition_claims.description_sha256",
            "phase4_alpaca_paper_order_transition_claims.fence_owner_id",
            "phase4_alpaca_paper_order_transition_claims.fence_lease_id",
            "phase4_alpaca_paper_order_transition_claims.fence_fencing_generation",
            "phase4_alpaca_paper_order_transition_claims.fence_sha256",
            "phase4_alpaca_paper_order_transition_claims.fence_policy_sha256",
            "phase4_alpaca_paper_order_transition_claims.commit_fence_lease_sha256",
            "phase4_alpaca_paper_order_transition_claims.commit_fence_receipt_sha256",
            "phase4_alpaca_paper_order_transition_claims.selected_at",
            "phase4_alpaca_paper_order_transition_claims.commit_fence_valid_until",
        ],
        name="fk_phase4_order_transition_consumption_claim",
    ),
    sa.ForeignKeyConstraint(
        [
            "preparation_sha256",
            "selected_snapshot_id",
            "account_id",
            "page_number",
            "selected_plan_sha256",
            "description_sha256",
            "prefix_capture_sha256",
            "prefix_page_count",
            "prepared_at",
        ],
        [
            "phase4_alpaca_paper_order_snapshot_preparations.preparation_sha256",
            "phase4_alpaca_paper_order_snapshot_preparations.snapshot_id",
            "phase4_alpaca_paper_order_snapshot_preparations.account_id",
            "phase4_alpaca_paper_order_snapshot_preparations.page_number",
            "phase4_alpaca_paper_order_snapshot_preparations.plan_sha256",
            "phase4_alpaca_paper_order_snapshot_preparations.description_sha256",
            "phase4_alpaca_paper_order_snapshot_preparations.prefix_capture_sha256",
            "phase4_alpaca_paper_order_snapshot_preparations.prefix_page_count",
            "phase4_alpaca_paper_order_snapshot_preparations.prepared_at",
        ],
        name="fk_phase4_order_transition_consumption_preparation",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "fence_fencing_generation", "commit_fence_lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase4_order_transition_consumption_lease",
    ),
    sa.CheckConstraint(
        "selected_role IN ('earlier', 'later') "
        "AND page_number BETWEEN 1 AND 8 "
        "AND prefix_page_count = page_number - 1 "
        "AND fence_fencing_generation > 0 "
        "AND claim_selected_at <= prepared_at "
        "AND prepared_at <= consumed_at "
        "AND consumed_at < commit_fence_valid_until",
        name="phase4_order_transition_consumption_time",
    ),
    sa.CheckConstraint(
        "length(consumption_id) = 36 "
        "AND length(claim_id) = 36 "
        "AND length(round_id) = 36 "
        "AND length(selected_member_id) = 36 "
        "AND length(selected_snapshot_id) = 36 "
        "AND length(preparation_id) = 36 "
        "AND length(claim_sha256) = 64 "
        "AND length(selected_plan_sha256) = 64 "
        "AND length(description_sha256) = 64 "
        "AND length(preparation_sha256) = 64 "
        "AND length(prefix_capture_sha256) = 64 "
        "AND length(fence_sha256) = 64 "
        "AND length(fence_policy_sha256) = 64 "
        "AND length(commit_fence_lease_sha256) = 64 "
        "AND length(claim_fence_receipt_sha256) = 64 "
        "AND length(commit_fence_receipt_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_order_transition_consumption_identity",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 131072",
        name="phase4_order_transition_consumption_payload",
    ),
)
sa.Index(
    "ix_phase4_order_transition_consumption_account_time",
    phase4_alpaca_paper_order_transition_consumptions.c.account_id,
    phase4_alpaca_paper_order_transition_consumptions.c.consumed_at,
)

phase4_alpaca_paper_order_view_comparisons = sa.Table(
    "phase4_alpaca_paper_order_view_comparisons",
    metadata,
    sa.Column("receipt_id", sa.String(36), primary_key=True),
    sa.Column("evidence_id", sa.String(36), nullable=False, unique=True),
    sa.Column("comparison_id", sa.String(36), nullable=False, unique=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("account_sequence", sa.BigInteger(), nullable=False),
    sa.Column("previous_receipt_sha256", sa.String(64), nullable=True),
    sa.Column("fence_owner_id", sa.String(128), nullable=False),
    sa.Column("fence_lease_id", sa.String(64), nullable=False),
    sa.Column("fence_fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column("fence_policy_sha256", sa.String(64), nullable=False),
    sa.Column("commit_fence_lease_sha256", sa.String(64), nullable=False),
    sa.Column("commit_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("commit_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("commit_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("authentication_policy_sha256", sa.String(64), nullable=False),
    sa.Column("comparison_policy_sha256", sa.String(64), nullable=False),
    sa.Column("traversal_profile_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_snapshot_id", sa.String(36), nullable=False),
    sa.Column("earlier_plan_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_head_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_prefix_id", sa.String(36), nullable=False),
    sa.Column("earlier_prefix_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_capture_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_page_count", sa.BigInteger(), nullable=False),
    sa.Column("earlier_tip_receipt_id", sa.String(36), nullable=False),
    sa.Column("earlier_tip_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_tip_persisted_page_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_source_committed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("earlier_window_started_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("earlier_window_ended_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("earlier_view_sha256", sa.String(64), nullable=False),
    sa.Column("later_snapshot_id", sa.String(36), nullable=False),
    sa.Column("later_plan_sha256", sa.String(64), nullable=False),
    sa.Column("later_head_sha256", sa.String(64), nullable=False),
    sa.Column("later_prefix_id", sa.String(36), nullable=False),
    sa.Column("later_prefix_sha256", sa.String(64), nullable=False),
    sa.Column("later_capture_sha256", sa.String(64), nullable=False),
    sa.Column("later_page_count", sa.BigInteger(), nullable=False),
    sa.Column("later_tip_receipt_id", sa.String(36), nullable=False),
    sa.Column("later_tip_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("later_tip_persisted_page_sha256", sa.String(64), nullable=False),
    sa.Column("later_source_committed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("later_window_started_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("later_window_ended_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("later_view_sha256", sa.String(64), nullable=False),
    sa.Column("observed_utc_separation_microseconds", sa.String(32), nullable=False),
    sa.Column("disposition", sa.String(64), nullable=False),
    sa.Column("added_provider_order_ids_payload", sa.Text(), nullable=False),
    sa.Column("removed_provider_order_ids_payload", sa.Text(), nullable=False),
    sa.Column("changed_provider_order_ids_payload", sa.Text(), nullable=False),
    sa.Column("added_count", sa.BigInteger(), nullable=False),
    sa.Column("removed_count", sa.BigInteger(), nullable=False),
    sa.Column("changed_count", sa.BigInteger(), nullable=False),
    sa.Column("comparison_sha256", sa.String(64), nullable=False),
    sa.Column("evidence_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "account_id",
        "account_sequence",
        name="uq_phase4_order_view_cmp_account_sequence",
    ),
    sa.UniqueConstraint(
        "account_id",
        "semantic_sha256",
        name="uq_phase4_order_view_cmp_account_semantic",
    ),
    sa.UniqueConstraint(
        "account_id",
        "account_sequence",
        "receipt_id",
        "semantic_sha256",
        "recorded_at",
        name="uq_phase4_order_view_cmp_exact",
    ),
    sa.UniqueConstraint(
        "earlier_snapshot_id",
        "later_snapshot_id",
        "authentication_policy_sha256",
        name="uq_phase4_order_view_cmp_source_pair",
    ),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase4_order_view_cmp_account",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "fence_fencing_generation",
            "commit_fence_lease_sha256",
        ],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase4_order_view_cmp_commit_lease",
    ),
    sa.ForeignKeyConstraint(
        ["earlier_snapshot_id", "account_id", "earlier_plan_sha256"],
        [
            "phase4_alpaca_paper_order_snapshot_plans.snapshot_id",
            "phase4_alpaca_paper_order_snapshot_plans.account_id",
            "phase4_alpaca_paper_order_snapshot_plans.semantic_sha256",
        ],
        name="fk_phase4_order_view_cmp_earlier_plan",
    ),
    sa.ForeignKeyConstraint(
        ["later_snapshot_id", "account_id", "later_plan_sha256"],
        [
            "phase4_alpaca_paper_order_snapshot_plans.snapshot_id",
            "phase4_alpaca_paper_order_snapshot_plans.account_id",
            "phase4_alpaca_paper_order_snapshot_plans.semantic_sha256",
        ],
        name="fk_phase4_order_view_cmp_later_plan",
    ),
    sa.ForeignKeyConstraint(
        ["earlier_snapshot_id", "account_id", "earlier_head_sha256"],
        [
            "phase4_alpaca_paper_order_snapshot_heads.snapshot_id",
            "phase4_alpaca_paper_order_snapshot_heads.account_id",
            "phase4_alpaca_paper_order_snapshot_heads.semantic_sha256",
        ],
        name="fk_phase4_order_view_cmp_earlier_head",
    ),
    sa.ForeignKeyConstraint(
        ["later_snapshot_id", "account_id", "later_head_sha256"],
        [
            "phase4_alpaca_paper_order_snapshot_heads.snapshot_id",
            "phase4_alpaca_paper_order_snapshot_heads.account_id",
            "phase4_alpaca_paper_order_snapshot_heads.semantic_sha256",
        ],
        name="fk_phase4_order_view_cmp_later_head",
    ),
    sa.ForeignKeyConstraint(
        [
            "earlier_snapshot_id",
            "earlier_page_count",
            "earlier_tip_receipt_id",
            "earlier_tip_receipt_sha256",
            "earlier_tip_persisted_page_sha256",
        ],
        [
            "phase4_alpaca_paper_order_snapshot_pages.snapshot_id",
            "phase4_alpaca_paper_order_snapshot_pages.page_number",
            "phase4_alpaca_paper_order_snapshot_pages.receipt_id",
            "phase4_alpaca_paper_order_snapshot_pages.semantic_sha256",
            "phase4_alpaca_paper_order_snapshot_pages.persisted_page_sha256",
        ],
        name="fk_phase4_order_view_cmp_earlier_tip",
    ),
    sa.ForeignKeyConstraint(
        [
            "later_snapshot_id",
            "later_page_count",
            "later_tip_receipt_id",
            "later_tip_receipt_sha256",
            "later_tip_persisted_page_sha256",
        ],
        [
            "phase4_alpaca_paper_order_snapshot_pages.snapshot_id",
            "phase4_alpaca_paper_order_snapshot_pages.page_number",
            "phase4_alpaca_paper_order_snapshot_pages.receipt_id",
            "phase4_alpaca_paper_order_snapshot_pages.semantic_sha256",
            "phase4_alpaca_paper_order_snapshot_pages.persisted_page_sha256",
        ],
        name="fk_phase4_order_view_cmp_later_tip",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "previous_receipt_sha256"],
        [
            "phase4_alpaca_paper_order_view_comparisons.account_id",
            "phase4_alpaca_paper_order_view_comparisons.semantic_sha256",
        ],
        name="fk_phase4_order_view_cmp_predecessor",
    ),
    sa.CheckConstraint(
        "(account_sequence = 1 AND previous_receipt_sha256 IS NULL) "
        "OR (account_sequence > 1 AND previous_receipt_sha256 IS NOT NULL)",
        name="phase4_order_view_cmp_predecessor_shape",
    ),
    sa.CheckConstraint(
        "fence_fencing_generation > 0 "
        "AND commit_fence_validated_at = recorded_at "
        "AND commit_fence_validated_at < commit_fence_valid_until",
        name="phase4_order_view_cmp_commit_fence",
    ),
    sa.CheckConstraint(
        "earlier_snapshot_id <> later_snapshot_id "
        "AND earlier_prefix_id <> later_prefix_id "
        "AND earlier_tip_receipt_id <> later_tip_receipt_id",
        name="phase4_order_view_cmp_distinct_sources",
    ),
    sa.CheckConstraint(
        "earlier_page_count BETWEEN 1 AND 8 "
        "AND later_page_count BETWEEN 1 AND 8 "
        "AND earlier_window_started_at <= earlier_window_ended_at "
        "AND later_window_started_at <= later_window_ended_at "
        "AND recorded_at >= earlier_source_committed_at "
        "AND recorded_at >= later_source_committed_at",
        name="phase4_order_view_cmp_time_bounds",
    ),
    sa.CheckConstraint(
        "disposition IN ("
        "'exact_order_view_match_unqualified', "
        "'order_view_different', "
        "'waiting_minimum_separation', "
        "'bounded_traversal_incomplete')",
        name="phase4_order_view_cmp_disposition",
    ),
    sa.CheckConstraint(
        "added_count >= 0 AND added_count <= 8000 "
        "AND removed_count >= 0 AND removed_count <= 8000 "
        "AND changed_count >= 0 AND changed_count <= 8000",
        name="phase4_order_view_cmp_difference_bounds",
    ),
    sa.CheckConstraint(
        "length(receipt_id) = 36 "
        "AND length(evidence_id) = 36 "
        "AND length(comparison_id) = 36 "
        "AND length(fence_owner_id) BETWEEN 1 AND 128 "
        "AND length(fence_lease_id) BETWEEN 1 AND 64 "
        "AND length(earlier_snapshot_id) = 36 "
        "AND length(earlier_prefix_id) = 36 "
        "AND length(earlier_tip_receipt_id) = 36 "
        "AND length(later_snapshot_id) = 36 "
        "AND length(later_prefix_id) = 36 "
        "AND length(later_tip_receipt_id) = 36",
        name="phase4_order_view_cmp_id_lengths",
    ),
    sa.CheckConstraint(
        "(previous_receipt_sha256 IS NULL OR length(previous_receipt_sha256) = 64) "
        "AND length(fence_sha256) = 64 "
        "AND length(fence_policy_sha256) = 64 "
        "AND length(commit_fence_lease_sha256) = 64 "
        "AND length(commit_fence_receipt_sha256) = 64 "
        "AND length(authentication_policy_sha256) = 64 "
        "AND length(comparison_policy_sha256) = 64 "
        "AND length(traversal_profile_sha256) = 64 "
        "AND length(earlier_plan_sha256) = 64 "
        "AND length(earlier_head_sha256) = 64 "
        "AND length(earlier_prefix_sha256) = 64 "
        "AND length(earlier_capture_sha256) = 64 "
        "AND length(earlier_tip_receipt_sha256) = 64 "
        "AND length(earlier_tip_persisted_page_sha256) = 64 "
        "AND length(earlier_view_sha256) = 64 "
        "AND length(later_plan_sha256) = 64 "
        "AND length(later_head_sha256) = 64 "
        "AND length(later_prefix_sha256) = 64 "
        "AND length(later_capture_sha256) = 64 "
        "AND length(later_tip_receipt_sha256) = 64 "
        "AND length(later_tip_persisted_page_sha256) = 64 "
        "AND length(later_view_sha256) = 64 "
        "AND length(comparison_sha256) = 64 "
        "AND length(evidence_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_order_view_cmp_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(observed_utc_separation_microseconds) BETWEEN 1 AND 32 "
        "AND length(added_provider_order_ids_payload) BETWEEN 2 AND 262144 "
        "AND length(removed_provider_order_ids_payload) BETWEEN 2 AND 262144 "
        "AND length(changed_provider_order_ids_payload) BETWEEN 2 AND 262144 "
        "AND length(canonical_payload) BETWEEN 2 AND 1048576",
        name="phase4_order_view_cmp_payload_sizes",
    ),
)
sa.Index(
    "ix_phase4_order_view_cmp_account_recorded",
    phase4_alpaca_paper_order_view_comparisons.c.account_id,
    phase4_alpaca_paper_order_view_comparisons.c.recorded_at,
)
sa.Index(
    "ix_phase4_order_view_cmp_sources",
    phase4_alpaca_paper_order_view_comparisons.c.earlier_snapshot_id,
    phase4_alpaca_paper_order_view_comparisons.c.later_snapshot_id,
)

phase4_alpaca_paper_order_view_comparison_heads = sa.Table(
    "phase4_alpaca_paper_order_view_comparison_heads",
    metadata,
    sa.Column("account_id", sa.String(64), primary_key=True),
    sa.Column("last_account_sequence", sa.BigInteger(), nullable=False),
    sa.Column("last_receipt_id", sa.String(36), nullable=False),
    sa.Column("last_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("last_recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False),
    sa.UniqueConstraint(
        "account_id",
        "semantic_sha256",
        name="uq_phase4_order_view_cmp_head_semantic",
    ),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase4_order_view_cmp_head_account",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "last_account_sequence",
            "last_receipt_id",
            "last_receipt_sha256",
            "last_recorded_at",
        ],
        [
            "phase4_alpaca_paper_order_view_comparisons.account_id",
            "phase4_alpaca_paper_order_view_comparisons.account_sequence",
            "phase4_alpaca_paper_order_view_comparisons.receipt_id",
            "phase4_alpaca_paper_order_view_comparisons.semantic_sha256",
            "phase4_alpaca_paper_order_view_comparisons.recorded_at",
        ],
        name="fk_phase4_order_view_cmp_head_tip",
    ),
    sa.CheckConstraint(
        "last_account_sequence > 0 "
        "AND length(last_receipt_id) = 36 "
        "AND length(last_receipt_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_order_view_cmp_head_shape",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 16384",
        name="phase4_order_view_cmp_head_payload",
    ),
)
sa.Index(
    "ix_phase4_order_view_cmp_head_recorded",
    phase4_alpaca_paper_order_view_comparison_heads.c.last_recorded_at,
)

phase4_alpaca_paper_position_snapshot_plans = sa.Table(
    "phase4_alpaca_paper_position_snapshot_plans",
    metadata,
    sa.Column("plan_id", sa.String(36), primary_key=True),
    sa.Column("capture_id", sa.String(36), nullable=False, unique=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("capture_idempotency_key", sa.String(128), nullable=False),
    sa.Column("description_sha256", sa.String(64), nullable=False),
    sa.Column("provider_id", sa.String(128), nullable=False),
    sa.Column("environment", sa.String(32), nullable=False),
    sa.Column("capability_sha256", sa.String(64), nullable=False),
    sa.Column("expected_provider_account_id", sa.String(36), nullable=False),
    sa.Column("secret_ref", sa.String(256), nullable=False),
    sa.Column("secret_version", sa.String(128), nullable=False),
    sa.Column("credential_reference_sha256", sa.String(64), nullable=False),
    sa.Column("account_binding_id", sa.String(36), nullable=False),
    sa.Column("account_binding_sha256", sa.String(64), nullable=False),
    sa.Column("account_binding_sequence", sa.BigInteger(), nullable=False),
    sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("preparation_id", sa.String(36), nullable=False, unique=True),
    sa.Column("preparation_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("plan_canonical_payload", sa.Text(), nullable=False),
    sa.Column("preparation_canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "account_id",
        "capture_idempotency_key",
        name="uq_phase4_position_snapshot_plan_account_key",
    ),
    sa.UniqueConstraint(
        "plan_id",
        "capture_id",
        "account_id",
        "semantic_sha256",
        "preparation_sha256",
        name="uq_phase4_position_snapshot_plan_exact",
    ),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase4_position_snapshot_plan_account",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "account_binding_id",
            "account_binding_sha256",
            "expected_provider_account_id",
        ],
        [
            "phase4_alpaca_paper_account_bindings.account_id",
            "phase4_alpaca_paper_account_bindings.binding_id",
            "phase4_alpaca_paper_account_bindings.semantic_sha256",
            "phase4_alpaca_paper_account_bindings.expected_provider_account_id",
        ],
        name="fk_phase4_position_snapshot_plan_account_binding",
    ),
    sa.CheckConstraint(
        "provider_id = 'alpaca-paper' AND environment = 'paper'",
        name="phase4_position_snapshot_plan_provider_scope",
    ),
    sa.CheckConstraint(
        "account_binding_sequence > 0 "
        "AND length(plan_id) = 36 "
        "AND length(capture_id) = 36 "
        "AND length(preparation_id) = 36 "
        "AND length(expected_provider_account_id) = 36 "
        "AND length(account_binding_id) = 36",
        name="phase4_position_snapshot_plan_id_shape",
    ),
    sa.CheckConstraint(
        "length(capture_idempotency_key) BETWEEN 8 AND 128 "
        "AND length(secret_ref) BETWEEN 1 AND 256 "
        "AND length(secret_version) BETWEEN 1 AND 128",
        name="phase4_position_snapshot_plan_text_bounds",
    ),
    sa.CheckConstraint(
        "length(description_sha256) = 64 "
        "AND length(capability_sha256) = 64 "
        "AND length(credential_reference_sha256) = 64 "
        "AND length(account_binding_sha256) = 64 "
        "AND length(preparation_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_position_snapshot_plan_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(plan_canonical_payload) BETWEEN 2 AND 16384 "
        "AND length(preparation_canonical_payload) BETWEEN 2 AND 16384",
        name="phase4_position_snapshot_plan_payload_sizes",
    ),
)
sa.Index(
    "ix_phase4_position_snapshot_plan_account_prepared",
    phase4_alpaca_paper_position_snapshot_plans.c.account_id,
    phase4_alpaca_paper_position_snapshot_plans.c.prepared_at,
)
sa.Index(
    "uq_phase4_position_snapshot_plan_transition_source",
    phase4_alpaca_paper_position_snapshot_plans.c.plan_id,
    phase4_alpaca_paper_position_snapshot_plans.c.capture_id,
    phase4_alpaca_paper_position_snapshot_plans.c.account_id,
    phase4_alpaca_paper_position_snapshot_plans.c.semantic_sha256,
    phase4_alpaca_paper_position_snapshot_plans.c.preparation_id,
    phase4_alpaca_paper_position_snapshot_plans.c.preparation_sha256,
    phase4_alpaca_paper_position_snapshot_plans.c.prepared_at,
    unique=True,
)

phase4_alpaca_paper_position_snapshots = sa.Table(
    "phase4_alpaca_paper_position_snapshots",
    metadata,
    sa.Column("receipt_id", sa.String(36), primary_key=True),
    sa.Column("evidence_id", sa.String(36), nullable=False, unique=True),
    sa.Column("plan_id", sa.String(36), nullable=False, unique=True),
    sa.Column("capture_id", sa.String(36), nullable=False, unique=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("plan_sha256", sa.String(64), nullable=False),
    sa.Column("preparation_sha256", sa.String(64), nullable=False),
    sa.Column("credential_resolution_sha256", sa.String(64), nullable=False),
    sa.Column("resolver_id", sa.String(128), nullable=False),
    sa.Column("resolver_version", sa.String(128), nullable=False),
    sa.Column(
        "credential_resolution_started_at",
        sa.DateTime(timezone=True),
        nullable=False,
    ),
    sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column(
        "credential_resolution_valid_until",
        sa.DateTime(timezone=True),
        nullable=False,
    ),
    sa.Column("pre_account_identity_sha256", sa.String(64), nullable=False),
    sa.Column("post_account_identity_sha256", sa.String(64), nullable=False),
    sa.Column(
        "pre_account_identity_checked_at",
        sa.DateTime(timezone=True),
        nullable=False,
    ),
    sa.Column(
        "post_account_identity_checked_at",
        sa.DateTime(timezone=True),
        nullable=False,
    ),
    sa.Column("policy_sha256", sa.String(64), nullable=False),
    sa.Column("demand_id", sa.String(64), nullable=False),
    sa.Column("demand_sha256", sa.String(64), nullable=False),
    sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("permit_id", sa.String(64), nullable=False, unique=True),
    sa.Column("permit_sha256", sa.String(64), nullable=False),
    sa.Column("permit_freshness_sha256", sa.String(64), nullable=False),
    sa.Column("permit_issued_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("permit_checked_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("permit_expires_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("fence_owner_id", sa.String(128), nullable=False),
    sa.Column("fence_lease_id", sa.String(64), nullable=False),
    sa.Column("fence_fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column("fence_policy_sha256", sa.String(64), nullable=False),
    sa.Column("pre_fence_lease_sha256", sa.String(64), nullable=False),
    sa.Column("pre_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("pre_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("pre_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("transport_request_sha256", sa.String(64), nullable=False),
    sa.Column("transport_response_sha256", sa.String(64), nullable=False),
    sa.Column("request_started_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("http_status", sa.Integer(), nullable=False),
    sa.Column("provider_request_id", sa.String(256), nullable=False),
    sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("ingress_receipt_id", sa.String(64), nullable=False, unique=True),
    sa.Column("ingress_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("ingress_sequence", sa.BigInteger(), nullable=False),
    sa.Column("raw_recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("response_size_bytes", sa.BigInteger(), nullable=False),
    sa.Column("response_body_sha256", sa.String(64), nullable=False),
    sa.Column("position_count", sa.BigInteger(), nullable=False),
    sa.Column("observation_sha256", sa.String(64), nullable=False),
    sa.Column("persisted_snapshot_sha256", sa.String(64), nullable=False),
    sa.Column("post_fence_lease_sha256", sa.String(64), nullable=False),
    sa.Column("post_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("post_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("post_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("final_fence_lease_sha256", sa.String(64), nullable=False),
    sa.Column("final_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("final_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("final_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("authenticated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("evidence_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("commit_fence_lease_sha256", sa.String(64), nullable=False),
    sa.Column("commit_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("commit_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("commit_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "plan_id",
        "capture_id",
        "account_id",
        "plan_sha256",
        "preparation_sha256",
        name="uq_phase4_position_snapshot_source_exact",
    ),
    sa.ForeignKeyConstraint(
        [
            "plan_id",
            "capture_id",
            "account_id",
            "plan_sha256",
            "preparation_sha256",
        ],
        [
            "phase4_alpaca_paper_position_snapshot_plans.plan_id",
            "phase4_alpaca_paper_position_snapshot_plans.capture_id",
            "phase4_alpaca_paper_position_snapshot_plans.account_id",
            "phase4_alpaca_paper_position_snapshot_plans.semantic_sha256",
            "phase4_alpaca_paper_position_snapshot_plans.preparation_sha256",
        ],
        name="fk_phase4_position_snapshot_plan",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "permit_id",
            "permit_sha256",
            "demand_id",
            "demand_sha256",
            "policy_sha256",
        ],
        [
            "phase4_broker_request_permits.account_id",
            "phase4_broker_request_permits.permit_id",
            "phase4_broker_request_permits.semantic_sha256",
            "phase4_broker_request_permits.demand_id",
            "phase4_broker_request_permits.demand_sha256",
            "phase4_broker_request_permits.policy_sha256",
        ],
        name="fk_phase4_position_snapshot_permit",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "ingress_receipt_id", "ingress_receipt_sha256"],
        [
            "phase4_broker_ingress_receipts.account_id",
            "phase4_broker_ingress_receipts.receipt_id",
            "phase4_broker_ingress_receipts.semantic_sha256",
        ],
        name="fk_phase4_position_snapshot_ingress",
    ),
    *(
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "fence_fencing_generation",
                f"{phase}_fence_lease_sha256",
            ],
            [
                "phase2_account_leases.account_id",
                "phase2_account_leases.fencing_generation",
                "phase2_account_leases.lease_sha256",
            ],
            name=f"fk_phase4_position_snapshot_{phase}_lease",
        )
        for phase in ("pre", "post", "final", "commit")
    ),
    sa.CheckConstraint(
        "http_status = 200 "
        "AND ingress_sequence > 0 "
        "AND fence_fencing_generation > 0 "
        "AND response_size_bytes BETWEEN 1 AND 1048576 "
        "AND position_count BETWEEN 0 AND 512",
        name="phase4_position_snapshot_bounds",
    ),
    sa.CheckConstraint(
        "pre_fence_lease_sha256 = post_fence_lease_sha256 "
        "AND post_fence_lease_sha256 = final_fence_lease_sha256 "
        "AND final_fence_lease_sha256 = commit_fence_lease_sha256 "
        "AND pre_fence_valid_until = post_fence_valid_until "
        "AND post_fence_valid_until = final_fence_valid_until "
        "AND final_fence_valid_until = commit_fence_valid_until",
        name="phase4_position_snapshot_same_lease",
    ),
    sa.CheckConstraint(
        "requested_at <= credential_resolution_started_at "
        "AND credential_resolution_started_at <= resolved_at "
        "AND resolved_at <= permit_issued_at "
        "AND permit_issued_at <= pre_fence_validated_at "
        "AND pre_fence_validated_at <= permit_checked_at "
        "AND permit_checked_at <= pre_account_identity_checked_at "
        "AND pre_account_identity_checked_at <= request_started_at "
        "AND request_started_at <= received_at "
        "AND received_at <= raw_recorded_at "
        "AND raw_recorded_at <= post_fence_validated_at "
        "AND post_fence_validated_at <= post_account_identity_checked_at "
        "AND post_account_identity_checked_at <= final_fence_validated_at "
        "AND final_fence_validated_at <= authenticated_at "
        "AND authenticated_at <= commit_fence_validated_at",
        name="phase4_position_snapshot_time_order",
    ),
    sa.CheckConstraint(
        "resolved_at < credential_resolution_valid_until "
        "AND request_started_at < credential_resolution_valid_until "
        "AND received_at < credential_resolution_valid_until "
        "AND permit_issued_at < permit_expires_at "
        "AND request_started_at < permit_expires_at "
        "AND received_at < permit_expires_at "
        "AND request_started_at < pre_fence_valid_until "
        "AND post_account_identity_checked_at < post_fence_valid_until "
        "AND authenticated_at < final_fence_valid_until "
        "AND commit_fence_validated_at < commit_fence_valid_until",
        name="phase4_position_snapshot_validity_windows",
    ),
    sa.CheckConstraint(
        "length(receipt_id) = 36 "
        "AND length(evidence_id) = 36 "
        "AND length(plan_id) = 36 "
        "AND length(capture_id) = 36",
        name="phase4_position_snapshot_id_lengths",
    ),
    sa.CheckConstraint(
        "length(plan_sha256) = 64 "
        "AND length(preparation_sha256) = 64 "
        "AND length(credential_resolution_sha256) = 64 "
        "AND length(pre_account_identity_sha256) = 64 "
        "AND length(post_account_identity_sha256) = 64 "
        "AND length(policy_sha256) = 64 "
        "AND length(demand_id) = 64 "
        "AND length(demand_sha256) = 64 "
        "AND length(permit_id) = 64 "
        "AND length(permit_sha256) = 64 "
        "AND length(permit_freshness_sha256) = 64 "
        "AND length(fence_sha256) = 64 "
        "AND length(fence_policy_sha256) = 64 "
        "AND length(pre_fence_lease_sha256) = 64 "
        "AND length(pre_fence_receipt_sha256) = 64 "
        "AND length(transport_request_sha256) = 64 "
        "AND length(transport_response_sha256) = 64 "
        "AND length(ingress_receipt_id) = 64 "
        "AND length(ingress_receipt_sha256) = 64 "
        "AND length(response_body_sha256) = 64 "
        "AND length(observation_sha256) = 64 "
        "AND length(persisted_snapshot_sha256) = 64 "
        "AND length(post_fence_lease_sha256) = 64 "
        "AND length(post_fence_receipt_sha256) = 64 "
        "AND length(final_fence_lease_sha256) = 64 "
        "AND length(final_fence_receipt_sha256) = 64 "
        "AND length(evidence_sha256) = 64 "
        "AND length(commit_fence_lease_sha256) = 64 "
        "AND length(commit_fence_receipt_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_position_snapshot_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 131072",
        name="phase4_position_snapshot_payload_size",
    ),
)
sa.Index(
    "ix_phase4_position_snapshot_account_authenticated",
    phase4_alpaca_paper_position_snapshots.c.account_id,
    phase4_alpaca_paper_position_snapshots.c.authenticated_at,
)
sa.Index(
    "ix_phase4_position_snapshot_ingress_sequence",
    phase4_alpaca_paper_position_snapshots.c.account_id,
    phase4_alpaca_paper_position_snapshots.c.ingress_sequence,
)
sa.Index(
    "uq_phase4_position_snapshot_comparison_source",
    phase4_alpaca_paper_position_snapshots.c.receipt_id,
    phase4_alpaca_paper_position_snapshots.c.plan_id,
    phase4_alpaca_paper_position_snapshots.c.capture_id,
    phase4_alpaca_paper_position_snapshots.c.account_id,
    phase4_alpaca_paper_position_snapshots.c.plan_sha256,
    phase4_alpaca_paper_position_snapshots.c.persisted_snapshot_sha256,
    phase4_alpaca_paper_position_snapshots.c.semantic_sha256,
    phase4_alpaca_paper_position_snapshots.c.ingress_receipt_id,
    phase4_alpaca_paper_position_snapshots.c.ingress_receipt_sha256,
    phase4_alpaca_paper_position_snapshots.c.ingress_sequence,
    phase4_alpaca_paper_position_snapshots.c.commit_fence_validated_at,
    unique=True,
)

phase4_alpaca_paper_position_transition_members = sa.Table(
    "phase4_alpaca_paper_position_transition_members",
    metadata,
    sa.Column("member_id", sa.String(36), primary_key=True),
    sa.Column("round_id", sa.String(36), nullable=False),
    sa.Column("member_role", sa.String(16), nullable=False),
    sa.Column("transition_plan_sha256", sa.String(64), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("expected_provider_account_id", sa.String(36), nullable=False),
    sa.Column("plan_id", sa.String(36), nullable=False, unique=True),
    sa.Column("capture_id", sa.String(36), nullable=False, unique=True),
    sa.Column("capture_idempotency_key", sa.String(128), nullable=False),
    sa.Column("description_sha256", sa.String(64), nullable=False),
    sa.Column("provider_id", sa.String(128), nullable=False),
    sa.Column("environment", sa.String(32), nullable=False),
    sa.Column("capability_sha256", sa.String(64), nullable=False),
    sa.Column("secret_ref", sa.String(256), nullable=False),
    sa.Column("secret_version", sa.String(128), nullable=False),
    sa.Column("credential_reference_sha256", sa.String(64), nullable=False),
    sa.Column("account_binding_id", sa.String(36), nullable=False),
    sa.Column("account_binding_sha256", sa.String(64), nullable=False),
    sa.Column("account_binding_sequence", sa.BigInteger(), nullable=False),
    sa.Column("plan_canonical_payload", sa.Text(), nullable=False),
    sa.Column("plan_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "round_id",
        "member_role",
        name="uq_phase4_position_transition_member_role",
    ),
    sa.UniqueConstraint(
        "account_id",
        "capture_idempotency_key",
        name="uq_phase4_position_transition_member_account_key",
    ),
    sa.UniqueConstraint(
        "member_id",
        "round_id",
        "member_role",
        "transition_plan_sha256",
        "account_id",
        "expected_provider_account_id",
        "plan_id",
        "capture_id",
        "plan_sha256",
        "semantic_sha256",
        name="uq_phase4_position_transition_member_exact",
    ),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase4_position_transition_member_account",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "account_binding_id",
            "account_binding_sha256",
            "expected_provider_account_id",
        ],
        [
            "phase4_alpaca_paper_account_bindings.account_id",
            "phase4_alpaca_paper_account_bindings.binding_id",
            "phase4_alpaca_paper_account_bindings.semantic_sha256",
            "phase4_alpaca_paper_account_bindings.expected_provider_account_id",
        ],
        name="fk_phase4_position_transition_member_binding",
    ),
    sa.CheckConstraint(
        "member_role IN ('earlier', 'later') "
        "AND provider_id = 'alpaca-paper' "
        "AND environment = 'paper' "
        "AND account_binding_sequence > 0",
        name="phase4_position_transition_member_scope",
    ),
    sa.CheckConstraint(
        "length(member_id) = 36 "
        "AND length(round_id) = 36 "
        "AND length(expected_provider_account_id) = 36 "
        "AND length(plan_id) = 36 "
        "AND length(capture_id) = 36 "
        "AND length(account_binding_id) = 36",
        name="phase4_position_transition_member_id_shape",
    ),
    sa.CheckConstraint(
        "length(transition_plan_sha256) = 64 "
        "AND length(description_sha256) = 64 "
        "AND length(capability_sha256) = 64 "
        "AND length(credential_reference_sha256) = 64 "
        "AND length(account_binding_sha256) = 64 "
        "AND length(plan_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_position_transition_member_hashes",
    ),
    sa.CheckConstraint(
        "length(capture_idempotency_key) BETWEEN 8 AND 128 "
        "AND length(secret_ref) BETWEEN 1 AND 256 "
        "AND length(secret_version) BETWEEN 1 AND 128 "
        "AND length(plan_canonical_payload) BETWEEN 2 AND 16384 "
        "AND length(canonical_payload) BETWEEN 2 AND 32768",
        name="phase4_position_transition_member_bounds",
    ),
)
sa.Index(
    "ix_phase4_position_transition_member_account_round",
    phase4_alpaca_paper_position_transition_members.c.account_id,
    phase4_alpaca_paper_position_transition_members.c.round_id,
)

phase4_alpaca_paper_position_transition_claims = sa.Table(
    "phase4_alpaca_paper_position_transition_claims",
    metadata,
    sa.Column("claim_id", sa.String(36), primary_key=True),
    sa.Column("round_id", sa.String(36), nullable=False),
    sa.Column("transition_plan_sha256", sa.String(64), nullable=False),
    sa.Column("selected_role", sa.String(16), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("expected_provider_account_id", sa.String(36), nullable=False),
    sa.Column("earlier_member_id", sa.String(36), nullable=False),
    sa.Column("earlier_member_role", sa.String(16), nullable=False),
    sa.Column("earlier_member_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_plan_id", sa.String(36), nullable=False),
    sa.Column("earlier_capture_id", sa.String(36), nullable=False),
    sa.Column("earlier_plan_sha256", sa.String(64), nullable=False),
    sa.Column("later_member_id", sa.String(36), nullable=False),
    sa.Column("later_member_role", sa.String(16), nullable=False),
    sa.Column("later_member_sha256", sa.String(64), nullable=False),
    sa.Column("later_plan_id", sa.String(36), nullable=False),
    sa.Column("later_capture_id", sa.String(36), nullable=False),
    sa.Column("later_plan_sha256", sa.String(64), nullable=False),
    sa.Column("selected_member_id", sa.String(36), nullable=False),
    sa.Column("selected_plan_id", sa.String(36), nullable=False),
    sa.Column("selected_capture_id", sa.String(36), nullable=False),
    sa.Column("selected_plan_sha256", sa.String(64), nullable=False),
    sa.Column("prior_snapshot_receipt_id", sa.String(36), nullable=True),
    sa.Column("prior_snapshot_receipt_sha256", sa.String(64), nullable=True),
    sa.Column("prior_plan_id", sa.String(36), nullable=True),
    sa.Column("prior_capture_id", sa.String(36), nullable=True),
    sa.Column("prior_plan_sha256", sa.String(64), nullable=True),
    sa.Column("prior_persisted_snapshot_sha256", sa.String(64), nullable=True),
    sa.Column("prior_ingress_receipt_id", sa.String(64), nullable=True),
    sa.Column("prior_ingress_receipt_sha256", sa.String(64), nullable=True),
    sa.Column("prior_ingress_sequence", sa.BigInteger(), nullable=True),
    sa.Column("prior_source_committed_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("eligible_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("fence_owner_id", sa.String(128), nullable=False),
    sa.Column("fence_lease_id", sa.String(64), nullable=False),
    sa.Column("fence_fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column("fence_policy_sha256", sa.String(64), nullable=False),
    sa.Column("commit_fence_lease_sha256", sa.String(64), nullable=False),
    sa.Column("commit_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("selected_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("commit_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("transition_policy_sha256", sa.String(64), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "round_id",
        "selected_role",
        name="uq_phase4_position_transition_claim_role",
    ),
    sa.UniqueConstraint(
        "selected_member_id",
        name="uq_phase4_position_transition_claim_member",
    ),
    sa.UniqueConstraint(
        "claim_id",
        "semantic_sha256",
        "round_id",
        "selected_role",
        "selected_member_id",
        "selected_plan_id",
        "selected_capture_id",
        "selected_plan_sha256",
        "account_id",
        "fence_owner_id",
        "fence_lease_id",
        "fence_fencing_generation",
        "fence_sha256",
        "fence_policy_sha256",
        "commit_fence_lease_sha256",
        "commit_fence_receipt_sha256",
        "selected_at",
        "commit_fence_valid_until",
        name="uq_phase4_position_transition_claim_exact",
    ),
    sa.ForeignKeyConstraint(
        [
            "earlier_member_id",
            "round_id",
            "earlier_member_role",
            "transition_plan_sha256",
            "account_id",
            "expected_provider_account_id",
            "earlier_plan_id",
            "earlier_capture_id",
            "earlier_plan_sha256",
            "earlier_member_sha256",
        ],
        [
            "phase4_alpaca_paper_position_transition_members.member_id",
            "phase4_alpaca_paper_position_transition_members.round_id",
            "phase4_alpaca_paper_position_transition_members.member_role",
            "phase4_alpaca_paper_position_transition_members.transition_plan_sha256",
            "phase4_alpaca_paper_position_transition_members.account_id",
            "phase4_alpaca_paper_position_transition_members.expected_provider_account_id",
            "phase4_alpaca_paper_position_transition_members.plan_id",
            "phase4_alpaca_paper_position_transition_members.capture_id",
            "phase4_alpaca_paper_position_transition_members.plan_sha256",
            "phase4_alpaca_paper_position_transition_members.semantic_sha256",
        ],
        name="fk_phase4_position_transition_claim_earlier",
    ),
    sa.ForeignKeyConstraint(
        [
            "later_member_id",
            "round_id",
            "later_member_role",
            "transition_plan_sha256",
            "account_id",
            "expected_provider_account_id",
            "later_plan_id",
            "later_capture_id",
            "later_plan_sha256",
            "later_member_sha256",
        ],
        [
            "phase4_alpaca_paper_position_transition_members.member_id",
            "phase4_alpaca_paper_position_transition_members.round_id",
            "phase4_alpaca_paper_position_transition_members.member_role",
            "phase4_alpaca_paper_position_transition_members.transition_plan_sha256",
            "phase4_alpaca_paper_position_transition_members.account_id",
            "phase4_alpaca_paper_position_transition_members.expected_provider_account_id",
            "phase4_alpaca_paper_position_transition_members.plan_id",
            "phase4_alpaca_paper_position_transition_members.capture_id",
            "phase4_alpaca_paper_position_transition_members.plan_sha256",
            "phase4_alpaca_paper_position_transition_members.semantic_sha256",
        ],
        name="fk_phase4_position_transition_claim_later",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "fence_fencing_generation",
            "commit_fence_lease_sha256",
        ],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase4_position_transition_claim_lease",
    ),
    sa.ForeignKeyConstraint(
        [
            "prior_snapshot_receipt_id",
            "prior_plan_id",
            "prior_capture_id",
            "account_id",
            "prior_plan_sha256",
            "prior_persisted_snapshot_sha256",
            "prior_snapshot_receipt_sha256",
            "prior_ingress_receipt_id",
            "prior_ingress_receipt_sha256",
            "prior_ingress_sequence",
            "prior_source_committed_at",
        ],
        [
            "phase4_alpaca_paper_position_snapshots.receipt_id",
            "phase4_alpaca_paper_position_snapshots.plan_id",
            "phase4_alpaca_paper_position_snapshots.capture_id",
            "phase4_alpaca_paper_position_snapshots.account_id",
            "phase4_alpaca_paper_position_snapshots.plan_sha256",
            "phase4_alpaca_paper_position_snapshots.persisted_snapshot_sha256",
            "phase4_alpaca_paper_position_snapshots.semantic_sha256",
            "phase4_alpaca_paper_position_snapshots.ingress_receipt_id",
            "phase4_alpaca_paper_position_snapshots.ingress_receipt_sha256",
            "phase4_alpaca_paper_position_snapshots.ingress_sequence",
            "phase4_alpaca_paper_position_snapshots.commit_fence_validated_at",
        ],
        name="fk_phase4_position_transition_claim_prior",
    ),
    sa.CheckConstraint(
        "selected_role IN ('earlier', 'later') "
        "AND earlier_member_role = 'earlier' "
        "AND later_member_role = 'later' "
        "AND earlier_member_id <> later_member_id "
        "AND earlier_plan_id <> later_plan_id "
        "AND earlier_capture_id <> later_capture_id",
        name="phase4_position_transition_claim_scope",
    ),
    sa.CheckConstraint(
        "(selected_role = 'earlier' "
        "AND selected_member_id = earlier_member_id "
        "AND selected_plan_id = earlier_plan_id "
        "AND selected_capture_id = earlier_capture_id "
        "AND selected_plan_sha256 = earlier_plan_sha256 "
        "AND prior_snapshot_receipt_id IS NULL "
        "AND prior_snapshot_receipt_sha256 IS NULL "
        "AND prior_plan_id IS NULL "
        "AND prior_capture_id IS NULL "
        "AND prior_plan_sha256 IS NULL "
        "AND prior_persisted_snapshot_sha256 IS NULL "
        "AND prior_ingress_receipt_id IS NULL "
        "AND prior_ingress_receipt_sha256 IS NULL "
        "AND prior_ingress_sequence IS NULL "
        "AND prior_source_committed_at IS NULL "
        "AND eligible_at IS NULL) "
        "OR (selected_role = 'later' "
        "AND selected_member_id = later_member_id "
        "AND selected_plan_id = later_plan_id "
        "AND selected_capture_id = later_capture_id "
        "AND selected_plan_sha256 = later_plan_sha256 "
        "AND prior_snapshot_receipt_id IS NOT NULL "
        "AND prior_snapshot_receipt_sha256 IS NOT NULL "
        "AND prior_plan_id = earlier_plan_id "
        "AND prior_capture_id = earlier_capture_id "
        "AND prior_plan_sha256 = earlier_plan_sha256 "
        "AND prior_persisted_snapshot_sha256 IS NOT NULL "
        "AND prior_ingress_receipt_id IS NOT NULL "
        "AND prior_ingress_receipt_sha256 IS NOT NULL "
        "AND prior_ingress_sequence > 0 "
        "AND prior_source_committed_at IS NOT NULL "
        "AND eligible_at IS NOT NULL "
        "AND selected_at >= eligible_at "
        "AND selected_at >= prior_source_committed_at)",
        name="phase4_position_transition_claim_role_shape",
    ),
    sa.CheckConstraint(
        "fence_fencing_generation > 0 AND selected_at < commit_fence_valid_until",
        name="phase4_position_transition_claim_fence",
    ),
    sa.CheckConstraint(
        "length(claim_id) = 36 "
        "AND length(round_id) = 36 "
        "AND length(expected_provider_account_id) = 36 "
        "AND length(earlier_member_id) = 36 "
        "AND length(later_member_id) = 36 "
        "AND length(selected_member_id) = 36 "
        "AND length(selected_plan_id) = 36 "
        "AND length(selected_capture_id) = 36",
        name="phase4_position_transition_claim_ids",
    ),
    sa.CheckConstraint(
        "length(transition_plan_sha256) = 64 "
        "AND length(earlier_member_sha256) = 64 "
        "AND length(earlier_plan_sha256) = 64 "
        "AND length(later_member_sha256) = 64 "
        "AND length(later_plan_sha256) = 64 "
        "AND length(selected_plan_sha256) = 64 "
        "AND length(fence_sha256) = 64 "
        "AND length(fence_policy_sha256) = 64 "
        "AND length(commit_fence_lease_sha256) = 64 "
        "AND length(commit_fence_receipt_sha256) = 64 "
        "AND length(transition_policy_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_position_transition_claim_hashes",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 131072",
        name="phase4_position_transition_claim_payload",
    ),
)
sa.Index(
    "ix_phase4_position_transition_claim_account_selected",
    phase4_alpaca_paper_position_transition_claims.c.account_id,
    phase4_alpaca_paper_position_transition_claims.c.selected_at,
)

phase4_alpaca_paper_position_transition_consumptions = sa.Table(
    "phase4_alpaca_paper_position_transition_consumptions",
    metadata,
    sa.Column("consumption_id", sa.String(36), primary_key=True),
    sa.Column("claim_id", sa.String(36), nullable=False, unique=True),
    sa.Column("claim_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("round_id", sa.String(36), nullable=False),
    sa.Column("selected_role", sa.String(16), nullable=False),
    sa.Column("selected_member_id", sa.String(36), nullable=False, unique=True),
    sa.Column("selected_plan_id", sa.String(36), nullable=False, unique=True),
    sa.Column("selected_capture_id", sa.String(36), nullable=False, unique=True),
    sa.Column("selected_plan_sha256", sa.String(64), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("preparation_id", sa.String(36), nullable=False, unique=True),
    sa.Column("preparation_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("fence_owner_id", sa.String(128), nullable=False),
    sa.Column("fence_lease_id", sa.String(64), nullable=False),
    sa.Column("fence_fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column("fence_policy_sha256", sa.String(64), nullable=False),
    sa.Column("commit_fence_lease_sha256", sa.String(64), nullable=False),
    sa.Column("claim_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("claim_selected_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("commit_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("commit_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        [
            "claim_id",
            "claim_sha256",
            "round_id",
            "selected_role",
            "selected_member_id",
            "selected_plan_id",
            "selected_capture_id",
            "selected_plan_sha256",
            "account_id",
            "fence_owner_id",
            "fence_lease_id",
            "fence_fencing_generation",
            "fence_sha256",
            "fence_policy_sha256",
            "commit_fence_lease_sha256",
            "claim_fence_receipt_sha256",
            "claim_selected_at",
            "commit_fence_valid_until",
        ],
        [
            "phase4_alpaca_paper_position_transition_claims.claim_id",
            "phase4_alpaca_paper_position_transition_claims.semantic_sha256",
            "phase4_alpaca_paper_position_transition_claims.round_id",
            "phase4_alpaca_paper_position_transition_claims.selected_role",
            "phase4_alpaca_paper_position_transition_claims.selected_member_id",
            "phase4_alpaca_paper_position_transition_claims.selected_plan_id",
            "phase4_alpaca_paper_position_transition_claims.selected_capture_id",
            "phase4_alpaca_paper_position_transition_claims.selected_plan_sha256",
            "phase4_alpaca_paper_position_transition_claims.account_id",
            "phase4_alpaca_paper_position_transition_claims.fence_owner_id",
            "phase4_alpaca_paper_position_transition_claims.fence_lease_id",
            "phase4_alpaca_paper_position_transition_claims.fence_fencing_generation",
            "phase4_alpaca_paper_position_transition_claims.fence_sha256",
            "phase4_alpaca_paper_position_transition_claims.fence_policy_sha256",
            "phase4_alpaca_paper_position_transition_claims.commit_fence_lease_sha256",
            "phase4_alpaca_paper_position_transition_claims.commit_fence_receipt_sha256",
            "phase4_alpaca_paper_position_transition_claims.selected_at",
            "phase4_alpaca_paper_position_transition_claims.commit_fence_valid_until",
        ],
        name="fk_phase4_position_transition_consumption_claim",
    ),
    sa.ForeignKeyConstraint(
        [
            "selected_plan_id",
            "selected_capture_id",
            "account_id",
            "selected_plan_sha256",
            "preparation_id",
            "preparation_sha256",
            "prepared_at",
        ],
        [
            "phase4_alpaca_paper_position_snapshot_plans.plan_id",
            "phase4_alpaca_paper_position_snapshot_plans.capture_id",
            "phase4_alpaca_paper_position_snapshot_plans.account_id",
            "phase4_alpaca_paper_position_snapshot_plans.semantic_sha256",
            "phase4_alpaca_paper_position_snapshot_plans.preparation_id",
            "phase4_alpaca_paper_position_snapshot_plans.preparation_sha256",
            "phase4_alpaca_paper_position_snapshot_plans.prepared_at",
        ],
        name="fk_phase4_position_transition_consumption_plan",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "fence_fencing_generation",
            "commit_fence_lease_sha256",
        ],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase4_position_transition_consumption_lease",
    ),
    sa.CheckConstraint(
        "selected_role IN ('earlier', 'later') "
        "AND fence_fencing_generation > 0 "
        "AND claim_selected_at <= prepared_at "
        "AND prepared_at <= consumed_at "
        "AND consumed_at < commit_fence_valid_until",
        name="phase4_position_transition_consumption_time",
    ),
    sa.CheckConstraint(
        "length(consumption_id) = 36 "
        "AND length(claim_id) = 36 "
        "AND length(round_id) = 36 "
        "AND length(selected_member_id) = 36 "
        "AND length(selected_plan_id) = 36 "
        "AND length(selected_capture_id) = 36 "
        "AND length(preparation_id) = 36",
        name="phase4_position_transition_consumption_ids",
    ),
    sa.CheckConstraint(
        "length(claim_sha256) = 64 "
        "AND length(selected_plan_sha256) = 64 "
        "AND length(preparation_sha256) = 64 "
        "AND length(fence_sha256) = 64 "
        "AND length(fence_policy_sha256) = 64 "
        "AND length(commit_fence_lease_sha256) = 64 "
        "AND length(claim_fence_receipt_sha256) = 64 "
        "AND length(commit_fence_receipt_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_position_transition_consumption_hashes",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 131072",
        name="phase4_position_transition_consumption_payload",
    ),
)
sa.Index(
    "ix_phase4_position_transition_consumption_account_time",
    phase4_alpaca_paper_position_transition_consumptions.c.account_id,
    phase4_alpaca_paper_position_transition_consumptions.c.consumed_at,
)

phase4_alpaca_paper_position_view_comparisons = sa.Table(
    "phase4_alpaca_paper_position_view_comparisons",
    metadata,
    sa.Column("receipt_id", sa.String(36), primary_key=True),
    sa.Column("evidence_id", sa.String(36), nullable=False, unique=True),
    sa.Column("comparison_id", sa.String(36), nullable=False, unique=True),
    sa.Column("comparison_plan_id", sa.String(36), nullable=False, unique=True),
    sa.Column("comparison_plan_sha256", sa.String(64), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("expected_provider_account_id", sa.String(36), nullable=False),
    sa.Column("account_sequence", sa.BigInteger(), nullable=False),
    sa.Column("previous_receipt_sha256", sa.String(64), nullable=True),
    sa.Column("fence_owner_id", sa.String(128), nullable=False),
    sa.Column("fence_lease_id", sa.String(64), nullable=False),
    sa.Column("fence_fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column("fence_policy_sha256", sa.String(64), nullable=False),
    sa.Column("commit_fence_lease_sha256", sa.String(64), nullable=False),
    sa.Column("commit_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("commit_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("commit_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("authentication_policy_sha256", sa.String(64), nullable=False),
    sa.Column("comparison_policy_sha256", sa.String(64), nullable=False),
    sa.Column("capture_profile_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_snapshot_receipt_id", sa.String(36), nullable=False),
    sa.Column("earlier_snapshot_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_plan_id", sa.String(36), nullable=False),
    sa.Column("earlier_plan_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_capture_id", sa.String(36), nullable=False),
    sa.Column("earlier_persisted_snapshot_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_ingress_receipt_id", sa.String(64), nullable=False),
    sa.Column("earlier_ingress_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_ingress_sequence", sa.BigInteger(), nullable=False),
    sa.Column("earlier_source_committed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("earlier_received_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("earlier_view_sha256", sa.String(64), nullable=False),
    sa.Column("later_snapshot_receipt_id", sa.String(36), nullable=False),
    sa.Column("later_snapshot_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("later_plan_id", sa.String(36), nullable=False),
    sa.Column("later_plan_sha256", sa.String(64), nullable=False),
    sa.Column("later_capture_id", sa.String(36), nullable=False),
    sa.Column("later_persisted_snapshot_sha256", sa.String(64), nullable=False),
    sa.Column("later_ingress_receipt_id", sa.String(64), nullable=False),
    sa.Column("later_ingress_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("later_ingress_sequence", sa.BigInteger(), nullable=False),
    sa.Column("later_source_committed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("later_received_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("later_view_sha256", sa.String(64), nullable=False),
    sa.Column("observed_utc_separation_microseconds", sa.String(32), nullable=False),
    sa.Column("disposition", sa.String(64), nullable=False),
    sa.Column("added_asset_ids_payload", sa.Text(), nullable=False),
    sa.Column("removed_asset_ids_payload", sa.Text(), nullable=False),
    sa.Column("changed_asset_ids_payload", sa.Text(), nullable=False),
    sa.Column("added_count", sa.BigInteger(), nullable=False),
    sa.Column("removed_count", sa.BigInteger(), nullable=False),
    sa.Column("changed_count", sa.BigInteger(), nullable=False),
    sa.Column("comparison_sha256", sa.String(64), nullable=False),
    sa.Column("evidence_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "account_id",
        "account_sequence",
        name="uq_phase4_position_view_cmp_account_sequence",
    ),
    sa.UniqueConstraint(
        "account_id",
        "semantic_sha256",
        name="uq_phase4_position_view_cmp_account_semantic",
    ),
    sa.UniqueConstraint(
        "account_id",
        "account_sequence",
        "receipt_id",
        "semantic_sha256",
        "recorded_at",
        name="uq_phase4_position_view_cmp_exact",
    ),
    sa.UniqueConstraint(
        "earlier_plan_id",
        "later_plan_id",
        "authentication_policy_sha256",
        name="uq_phase4_position_view_cmp_source_pair",
    ),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase4_position_view_cmp_account",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "fence_fencing_generation",
            "commit_fence_lease_sha256",
        ],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase4_position_view_cmp_commit_lease",
    ),
    sa.ForeignKeyConstraint(
        [
            "earlier_snapshot_receipt_id",
            "earlier_plan_id",
            "earlier_capture_id",
            "account_id",
            "earlier_plan_sha256",
            "earlier_persisted_snapshot_sha256",
            "earlier_snapshot_receipt_sha256",
            "earlier_ingress_receipt_id",
            "earlier_ingress_receipt_sha256",
            "earlier_ingress_sequence",
            "earlier_source_committed_at",
        ],
        [
            "phase4_alpaca_paper_position_snapshots.receipt_id",
            "phase4_alpaca_paper_position_snapshots.plan_id",
            "phase4_alpaca_paper_position_snapshots.capture_id",
            "phase4_alpaca_paper_position_snapshots.account_id",
            "phase4_alpaca_paper_position_snapshots.plan_sha256",
            "phase4_alpaca_paper_position_snapshots.persisted_snapshot_sha256",
            "phase4_alpaca_paper_position_snapshots.semantic_sha256",
            "phase4_alpaca_paper_position_snapshots.ingress_receipt_id",
            "phase4_alpaca_paper_position_snapshots.ingress_receipt_sha256",
            "phase4_alpaca_paper_position_snapshots.ingress_sequence",
            "phase4_alpaca_paper_position_snapshots.commit_fence_validated_at",
        ],
        name="fk_phase4_position_view_cmp_earlier_source",
    ),
    sa.ForeignKeyConstraint(
        [
            "later_snapshot_receipt_id",
            "later_plan_id",
            "later_capture_id",
            "account_id",
            "later_plan_sha256",
            "later_persisted_snapshot_sha256",
            "later_snapshot_receipt_sha256",
            "later_ingress_receipt_id",
            "later_ingress_receipt_sha256",
            "later_ingress_sequence",
            "later_source_committed_at",
        ],
        [
            "phase4_alpaca_paper_position_snapshots.receipt_id",
            "phase4_alpaca_paper_position_snapshots.plan_id",
            "phase4_alpaca_paper_position_snapshots.capture_id",
            "phase4_alpaca_paper_position_snapshots.account_id",
            "phase4_alpaca_paper_position_snapshots.plan_sha256",
            "phase4_alpaca_paper_position_snapshots.persisted_snapshot_sha256",
            "phase4_alpaca_paper_position_snapshots.semantic_sha256",
            "phase4_alpaca_paper_position_snapshots.ingress_receipt_id",
            "phase4_alpaca_paper_position_snapshots.ingress_receipt_sha256",
            "phase4_alpaca_paper_position_snapshots.ingress_sequence",
            "phase4_alpaca_paper_position_snapshots.commit_fence_validated_at",
        ],
        name="fk_phase4_position_view_cmp_later_source",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "previous_receipt_sha256"],
        [
            "phase4_alpaca_paper_position_view_comparisons.account_id",
            "phase4_alpaca_paper_position_view_comparisons.semantic_sha256",
        ],
        name="fk_phase4_position_view_cmp_predecessor",
    ),
    sa.CheckConstraint(
        "(account_sequence = 1 AND previous_receipt_sha256 IS NULL) "
        "OR (account_sequence > 1 AND previous_receipt_sha256 IS NOT NULL)",
        name="phase4_position_view_cmp_predecessor",
    ),
    sa.CheckConstraint(
        "fence_fencing_generation > 0 "
        "AND commit_fence_validated_at = recorded_at "
        "AND commit_fence_validated_at < commit_fence_valid_until",
        name="phase4_position_view_cmp_fence",
    ),
    sa.CheckConstraint(
        "earlier_snapshot_receipt_id <> later_snapshot_receipt_id "
        "AND earlier_plan_id <> later_plan_id "
        "AND earlier_capture_id <> later_capture_id "
        "AND earlier_ingress_receipt_id <> later_ingress_receipt_id",
        name="phase4_position_view_cmp_distinct",
    ),
    sa.CheckConstraint(
        "earlier_ingress_sequence > 0 "
        "AND later_ingress_sequence > earlier_ingress_sequence "
        "AND recorded_at >= earlier_source_committed_at "
        "AND recorded_at >= later_source_committed_at",
        name="phase4_position_view_cmp_order",
    ),
    sa.CheckConstraint(
        "disposition IN ("
        "'exact_position_view_match_unqualified', "
        "'position_view_different', "
        "'waiting_minimum_separation')",
        name="phase4_position_view_cmp_disposition",
    ),
    sa.CheckConstraint(
        "added_count BETWEEN 0 AND 512 "
        "AND removed_count BETWEEN 0 AND 512 "
        "AND changed_count BETWEEN 0 AND 512",
        name="phase4_position_view_cmp_differences",
    ),
    sa.CheckConstraint(
        "length(receipt_id) = 36 "
        "AND length(evidence_id) = 36 "
        "AND length(comparison_id) = 36 "
        "AND length(comparison_plan_id) = 36 "
        "AND length(expected_provider_account_id) = 36 "
        "AND length(fence_owner_id) BETWEEN 1 AND 128 "
        "AND length(fence_lease_id) BETWEEN 1 AND 64 "
        "AND length(earlier_snapshot_receipt_id) = 36 "
        "AND length(earlier_plan_id) = 36 "
        "AND length(earlier_capture_id) = 36 "
        "AND length(later_snapshot_receipt_id) = 36 "
        "AND length(later_plan_id) = 36 "
        "AND length(later_capture_id) = 36",
        name="phase4_position_view_cmp_ids",
    ),
    sa.CheckConstraint(
        "(previous_receipt_sha256 IS NULL "
        "OR length(previous_receipt_sha256) = 64) "
        "AND length(comparison_plan_sha256) = 64 "
        "AND length(fence_sha256) = 64 "
        "AND length(fence_policy_sha256) = 64 "
        "AND length(commit_fence_lease_sha256) = 64 "
        "AND length(commit_fence_receipt_sha256) = 64 "
        "AND length(authentication_policy_sha256) = 64 "
        "AND length(comparison_policy_sha256) = 64 "
        "AND length(capture_profile_sha256) = 64 "
        "AND length(earlier_snapshot_receipt_sha256) = 64 "
        "AND length(earlier_plan_sha256) = 64 "
        "AND length(earlier_persisted_snapshot_sha256) = 64 "
        "AND length(earlier_ingress_receipt_id) = 64 "
        "AND length(earlier_ingress_receipt_sha256) = 64 "
        "AND length(earlier_view_sha256) = 64 "
        "AND length(later_snapshot_receipt_sha256) = 64 "
        "AND length(later_plan_sha256) = 64 "
        "AND length(later_persisted_snapshot_sha256) = 64 "
        "AND length(later_ingress_receipt_id) = 64 "
        "AND length(later_ingress_receipt_sha256) = 64 "
        "AND length(later_view_sha256) = 64 "
        "AND length(comparison_sha256) = 64 "
        "AND length(evidence_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_position_view_cmp_hashes",
    ),
    sa.CheckConstraint(
        "length(observed_utc_separation_microseconds) BETWEEN 1 AND 32 "
        "AND length(added_asset_ids_payload) BETWEEN 2 AND 65536 "
        "AND length(removed_asset_ids_payload) BETWEEN 2 AND 65536 "
        "AND length(changed_asset_ids_payload) BETWEEN 2 AND 65536 "
        "AND length(canonical_payload) BETWEEN 2 AND 262144",
        name="phase4_position_view_cmp_payloads",
    ),
)
sa.Index(
    "ix_phase4_position_view_cmp_account_recorded",
    phase4_alpaca_paper_position_view_comparisons.c.account_id,
    phase4_alpaca_paper_position_view_comparisons.c.recorded_at,
)
sa.Index(
    "ix_phase4_position_view_cmp_sources",
    phase4_alpaca_paper_position_view_comparisons.c.earlier_plan_id,
    phase4_alpaca_paper_position_view_comparisons.c.later_plan_id,
)

phase4_alpaca_paper_position_view_comparison_heads = sa.Table(
    "phase4_alpaca_paper_position_view_comparison_heads",
    metadata,
    sa.Column("account_id", sa.String(64), primary_key=True),
    sa.Column("last_account_sequence", sa.BigInteger(), nullable=False),
    sa.Column("last_receipt_id", sa.String(36), nullable=False),
    sa.Column("last_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("last_recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False),
    sa.UniqueConstraint(
        "account_id",
        "semantic_sha256",
        name="uq_phase4_position_view_cmp_head_semantic",
    ),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase4_position_view_cmp_head_account",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "last_account_sequence",
            "last_receipt_id",
            "last_receipt_sha256",
            "last_recorded_at",
        ],
        [
            "phase4_alpaca_paper_position_view_comparisons.account_id",
            "phase4_alpaca_paper_position_view_comparisons.account_sequence",
            "phase4_alpaca_paper_position_view_comparisons.receipt_id",
            "phase4_alpaca_paper_position_view_comparisons.semantic_sha256",
            "phase4_alpaca_paper_position_view_comparisons.recorded_at",
        ],
        name="fk_phase4_position_view_cmp_head_tip",
    ),
    sa.CheckConstraint(
        "last_account_sequence > 0 "
        "AND length(last_receipt_id) = 36 "
        "AND length(last_receipt_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_position_view_cmp_head",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 16384",
        name="phase4_position_view_cmp_head_payload",
    ),
)
sa.Index(
    "ix_phase4_position_view_cmp_head_recorded",
    phase4_alpaca_paper_position_view_comparison_heads.c.last_recorded_at,
)

# Phase 5A durable operational-control spine.  Commands are retained as an
# immutable, account-local transition chain.  The head is only a transactional
# cache of the authenticated terminal transition; absence is intentionally
# distinct from RUNNING.
phase5_operational_control_transitions = sa.Table(
    "phase5_operational_control_transitions",
    metadata,
    sa.Column("transition_id", sa.String(36), primary_key=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("previous_transition_id", sa.String(36), nullable=True),
    sa.Column("previous_transition_sha256", sa.String(64), nullable=True),
    sa.Column("command_id", sa.String(36), nullable=False),
    sa.Column("actor_kind", sa.String(24), nullable=False),
    sa.Column("actor_id", sa.String(128), nullable=False),
    sa.Column("actor_authority_sha256", sa.String(64), nullable=False),
    sa.Column("actor_authenticated_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("idempotency_key", sa.String(128), nullable=False),
    sa.Column("command_kind", sa.String(32), nullable=False),
    sa.Column("target_state", sa.String(24), nullable=False),
    sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("reason_code", sa.String(128), nullable=False),
    sa.Column("reason_evidence_sha256", sa.String(64), nullable=False),
    sa.Column("rearm_evidence_sha256", sa.String(64), nullable=True),
    sa.Column("trip_rule_id", sa.String(128), nullable=True),
    sa.Column("trip_policy_sha256", sa.String(64), nullable=True),
    sa.Column("trip_observation_sha256", sa.String(64), nullable=True),
    sa.Column("command_canonical_payload", sa.Text(), nullable=False),
    sa.Column("command_sha256", sa.String(64), nullable=False),
    sa.Column("prior_state", sa.String(24), nullable=True),
    sa.Column("effective_state", sa.String(24), nullable=False),
    sa.Column("state_changed", sa.Boolean(), nullable=False),
    sa.Column("state_epoch_id", sa.String(36), nullable=False),
    sa.Column("blocking_event_count", sa.BigInteger(), nullable=False),
    sa.Column("blocking_event_ids_payload", sa.Text(), nullable=False),
    sa.Column("blocking_event_ids_sha256", sa.String(64), nullable=False),
    sa.Column("blocker_overflowed", sa.Boolean(), nullable=False),
    sa.Column("active_operation_attempt_id", sa.String(36), nullable=True),
    sa.Column("active_operation_kind", sa.String(24), nullable=True),
    sa.Column("active_operation_state_epoch_id", sa.String(36), nullable=True),
    sa.Column("active_operation_opened_by_command_id", sa.String(36), nullable=True),
    sa.Column("active_operation_opened_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("active_operation_sha256", sa.String(64), nullable=True),
    sa.Column("operation_started", sa.Boolean(), nullable=False),
    sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "account_id",
        "sequence_number",
        name="uq_phase5_control_transition_account_sequence",
    ),
    sa.UniqueConstraint(
        "account_id",
        "semantic_sha256",
        name="uq_phase5_control_transition_account_semantic",
    ),
    sa.UniqueConstraint(
        "account_id",
        "transition_id",
        "semantic_sha256",
        name="uq_phase5_control_transition_account_id_semantic",
    ),
    sa.UniqueConstraint(
        "account_id",
        "actor_kind",
        "actor_id",
        "idempotency_key",
        name="uq_phase5_control_transition_actor_key",
    ),
    sa.UniqueConstraint(
        "account_id",
        "transition_id",
        "sequence_number",
        "effective_state",
        "state_epoch_id",
        "blocking_event_count",
        "blocking_event_ids_sha256",
        "blocker_overflowed",
        "semantic_sha256",
        name="uq_phase5_control_transition_tip_exact",
    ),
    sa.UniqueConstraint(
        "account_id",
        "transition_id",
        "sequence_number",
        "state_epoch_id",
        "active_operation_attempt_id",
        "active_operation_kind",
        "active_operation_state_epoch_id",
        "active_operation_opened_by_command_id",
        "active_operation_opened_at",
        "active_operation_sha256",
        "semantic_sha256",
        name="uq_phase5_control_transition_operation_exact",
    ),
    sa.UniqueConstraint(
        "account_id",
        "transition_id",
        "sequence_number",
        "state_epoch_id",
        "active_operation_attempt_id",
        "active_operation_kind",
        "active_operation_state_epoch_id",
        "active_operation_opened_by_command_id",
        "active_operation_opened_at",
        "active_operation_sha256",
        "operation_started",
        "semantic_sha256",
        name="uq_phase5_control_transition_opener_exact",
    ),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase5_operational_control_transition_account",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "previous_transition_id",
            "previous_transition_sha256",
        ],
        [
            "phase5_operational_control_transitions.account_id",
            "phase5_operational_control_transitions.transition_id",
            "phase5_operational_control_transitions.semantic_sha256",
        ],
        name="fk_phase5_operational_control_transition_predecessor",
    ),
    sa.CheckConstraint(
        "(sequence_number = 1 AND previous_transition_id IS NULL "
        "AND previous_transition_sha256 IS NULL AND prior_state IS NULL "
        "AND command_kind = 'initialize_halted' "
        "AND effective_state = 'halted' AND target_state = 'halted' "
        "AND state_changed AND state_epoch_id = transition_id) "
        "OR (sequence_number > 1 AND previous_transition_id IS NOT NULL "
        "AND previous_transition_sha256 IS NOT NULL AND prior_state IS NOT NULL "
        "AND command_kind <> 'initialize_halted')",
        name="predecessor",
    ),
    sa.CheckConstraint(
        "effective_state IN ('running', 'paused', 'draining', 'flattening', 'halted') "
        "AND (prior_state IS NULL OR prior_state IN "
        "('running', 'paused', 'draining', 'flattening', 'halted')) "
        "AND target_state IN ('running', 'paused', 'draining', 'flattening', 'halted')",
        name="states",
    ),
    sa.CheckConstraint(
        "sequence_number > 0 AND length(state_epoch_id) = 36",
        name="sequence",
    ),
    sa.CheckConstraint(
        "(sequence_number = 1 AND state_changed) "
        "OR (sequence_number > 1 AND "
        "((state_changed AND prior_state <> effective_state "
        "AND state_epoch_id = transition_id) "
        "OR (NOT state_changed AND prior_state = effective_state)))",
        name="state_change",
    ),
    sa.CheckConstraint(
        "(effective_state IN ('draining', 'flattening') "
        "AND active_operation_attempt_id IS NOT NULL "
        "AND active_operation_sha256 IS NOT NULL "
        "AND active_operation_kind = "
        "CASE effective_state WHEN 'draining' THEN 'drain' ELSE 'flatten' END "
        "AND active_operation_state_epoch_id = state_epoch_id "
        "AND active_operation_opened_by_command_id IS NOT NULL "
        "AND active_operation_opened_at IS NOT NULL) "
        "OR (effective_state NOT IN ('draining', 'flattening') "
        "AND active_operation_attempt_id IS NULL "
        "AND active_operation_sha256 IS NULL "
        "AND active_operation_kind IS NULL "
        "AND active_operation_state_epoch_id IS NULL "
        "AND active_operation_opened_by_command_id IS NULL "
        "AND active_operation_opened_at IS NULL "
        "AND NOT operation_started)",
        name="operation",
    ),
    sa.CheckConstraint(
        "NOT operation_started OR "
        "(active_operation_opened_by_command_id = command_id "
        "AND active_operation_opened_at = decided_at)",
        name="operation_opener",
    ),
    sa.CheckConstraint(
        "actor_kind IN ('human', 'system', 'circuit_breaker') "
        "AND command_kind IN "
        "('initialize_halted', 'pause', 'drain', 'flatten', 'halt', 'trip', 'rearm') "
        "AND ("
        "(command_kind = 'trip' "
        "AND actor_kind IN ('system', 'circuit_breaker') "
        "AND target_state IN ('paused', 'halted') "
        "AND trip_rule_id IS NOT NULL "
        "AND trip_policy_sha256 IS NOT NULL "
        "AND trip_observation_sha256 IS NOT NULL) "
        "OR (command_kind <> 'trip' "
        "AND trip_rule_id IS NULL "
        "AND trip_policy_sha256 IS NULL "
        "AND trip_observation_sha256 IS NULL)) "
        "AND (command_kind <> 'initialize_halted' OR actor_kind = 'system') "
        "AND ((command_kind = 'rearm' AND actor_kind = 'human' "
        "AND target_state = 'running' AND rearm_evidence_sha256 IS NOT NULL) "
        "OR (command_kind <> 'rearm' AND rearm_evidence_sha256 IS NULL)) "
        "AND (command_kind <> 'pause' OR target_state = 'paused') "
        "AND (command_kind <> 'drain' OR target_state = 'draining') "
        "AND (command_kind <> 'flatten' OR target_state = 'flattening') "
        "AND (command_kind <> 'halt' OR target_state = 'halted')",
        name="command",
    ),
    sa.CheckConstraint(
        "(actor_kind = 'human' AND actor_authenticated_at IS NOT NULL) "
        "OR (actor_kind <> 'human' AND actor_authenticated_at IS NULL)",
        name="actor_authentication",
    ),
    sa.CheckConstraint(
        "length(transition_id) = 36 "
        "AND length(command_id) = 36 "
        "AND length(account_id) BETWEEN 1 AND 64 "
        "AND length(actor_kind) BETWEEN 1 AND 24 "
        "AND length(actor_id) BETWEEN 1 AND 128 "
        "AND length(idempotency_key) BETWEEN 8 AND 128 "
        "AND length(command_kind) BETWEEN 1 AND 32 "
        "AND length(reason_code) BETWEEN 1 AND 128",
        name="identity",
    ),
    sa.CheckConstraint(
        "length(command_sha256) = 64 "
        "AND length(actor_authority_sha256) = 64 "
        "AND length(reason_evidence_sha256) = 64 "
        "AND (rearm_evidence_sha256 IS NULL "
        "OR length(rearm_evidence_sha256) = 64) "
        "AND length(blocking_event_ids_sha256) = 64 "
        "AND length(semantic_sha256) = 64 "
        "AND (previous_transition_id IS NULL "
        "OR length(previous_transition_id) = 36) "
        "AND (previous_transition_sha256 IS NULL "
        "OR length(previous_transition_sha256) = 64) "
        "AND (trip_policy_sha256 IS NULL OR length(trip_policy_sha256) = 64) "
        "AND (trip_observation_sha256 IS NULL "
        "OR length(trip_observation_sha256) = 64) "
        "AND (active_operation_attempt_id IS NULL "
        "OR length(active_operation_attempt_id) = 36) "
        "AND (active_operation_sha256 IS NULL "
        "OR length(active_operation_sha256) = 64) "
        "AND (active_operation_state_epoch_id IS NULL "
        "OR length(active_operation_state_epoch_id) = 36) "
        "AND (active_operation_opened_by_command_id IS NULL "
        "OR length(active_operation_opened_by_command_id) = 36)",
        name="hashes",
    ),
    sa.CheckConstraint(
        "blocking_event_count BETWEEN 0 AND 2048 "
        "AND ((effective_state = 'running' AND blocking_event_count = 0 "
        "AND NOT blocker_overflowed) "
        "OR (effective_state <> 'running' AND blocking_event_count > 0)) "
        "AND (NOT blocker_overflowed OR blocking_event_count = 2048) "
        "AND length(command_canonical_payload) BETWEEN 2 AND 131072 "
        "AND length(blocking_event_ids_payload) BETWEEN 2 AND 262144 "
        "AND length(canonical_payload) BETWEEN 2 AND 2097152",
        name="payloads",
    ),
)
sa.Index(
    "ix_phase5_operational_control_transition_account_time",
    phase5_operational_control_transitions.c.account_id,
    phase5_operational_control_transitions.c.decided_at,
)

phase5_operational_control_heads = sa.Table(
    "phase5_operational_control_heads",
    metadata,
    sa.Column("account_id", sa.String(64), primary_key=True),
    sa.Column("sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("transition_id", sa.String(36), nullable=False),
    sa.Column("transition_sha256", sa.String(64), nullable=False),
    sa.Column("effective_state", sa.String(24), nullable=False),
    sa.Column("state_epoch_id", sa.String(36), nullable=False),
    sa.Column("blocking_event_count", sa.BigInteger(), nullable=False),
    sa.Column("blocking_event_ids_payload", sa.Text(), nullable=False),
    sa.Column("blocking_event_ids_sha256", sa.String(64), nullable=False),
    sa.Column("blocker_overflowed", sa.Boolean(), nullable=False),
    sa.Column("active_operation_attempt_id", sa.String(36), nullable=True),
    sa.Column("active_operation_kind", sa.String(24), nullable=True),
    sa.Column("active_operation_state_epoch_id", sa.String(36), nullable=True),
    sa.Column("active_operation_opened_by_command_id", sa.String(36), nullable=True),
    sa.Column("active_operation_opened_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("active_operation_sha256", sa.String(64), nullable=True),
    sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase5_operational_control_head_account",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "transition_id",
            "sequence_number",
            "effective_state",
            "state_epoch_id",
            "blocking_event_count",
            "blocking_event_ids_sha256",
            "blocker_overflowed",
            "transition_sha256",
        ],
        [
            "phase5_operational_control_transitions.account_id",
            "phase5_operational_control_transitions.transition_id",
            "phase5_operational_control_transitions.sequence_number",
            "phase5_operational_control_transitions.effective_state",
            "phase5_operational_control_transitions.state_epoch_id",
            "phase5_operational_control_transitions.blocking_event_count",
            "phase5_operational_control_transitions.blocking_event_ids_sha256",
            "phase5_operational_control_transitions.blocker_overflowed",
            "phase5_operational_control_transitions.semantic_sha256",
        ],
        name="fk_phase5_control_head_tip",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "transition_id",
            "sequence_number",
            "state_epoch_id",
            "active_operation_attempt_id",
            "active_operation_kind",
            "active_operation_state_epoch_id",
            "active_operation_opened_by_command_id",
            "active_operation_opened_at",
            "active_operation_sha256",
            "transition_sha256",
        ],
        [
            "phase5_operational_control_transitions.account_id",
            "phase5_operational_control_transitions.transition_id",
            "phase5_operational_control_transitions.sequence_number",
            "phase5_operational_control_transitions.state_epoch_id",
            "phase5_operational_control_transitions.active_operation_attempt_id",
            "phase5_operational_control_transitions.active_operation_kind",
            "phase5_operational_control_transitions.active_operation_state_epoch_id",
            "phase5_operational_control_transitions.active_operation_opened_by_command_id",
            "phase5_operational_control_transitions.active_operation_opened_at",
            "phase5_operational_control_transitions.active_operation_sha256",
            "phase5_operational_control_transitions.semantic_sha256",
        ],
        name="fk_phase5_control_head_operation_tip",
    ),
    sa.CheckConstraint(
        "sequence_number > 0 AND length(state_epoch_id) = 36 "
        "AND effective_state IN "
        "('running', 'paused', 'draining', 'flattening', 'halted')",
        name="state",
    ),
    sa.CheckConstraint(
        "(effective_state IN ('draining', 'flattening') "
        "AND active_operation_attempt_id IS NOT NULL "
        "AND active_operation_sha256 IS NOT NULL "
        "AND active_operation_kind = "
        "CASE effective_state WHEN 'draining' THEN 'drain' ELSE 'flatten' END "
        "AND active_operation_state_epoch_id = state_epoch_id "
        "AND active_operation_opened_by_command_id IS NOT NULL "
        "AND active_operation_opened_at IS NOT NULL) "
        "OR (effective_state NOT IN ('draining', 'flattening') "
        "AND active_operation_attempt_id IS NULL "
        "AND active_operation_sha256 IS NULL "
        "AND active_operation_kind IS NULL "
        "AND active_operation_state_epoch_id IS NULL "
        "AND active_operation_opened_by_command_id IS NULL "
        "AND active_operation_opened_at IS NULL)",
        name="operation",
    ),
    sa.CheckConstraint(
        "length(transition_id) = 36 "
        "AND length(transition_sha256) = 64 "
        "AND length(blocking_event_ids_sha256) = 64 "
        "AND length(semantic_sha256) = 64 "
        "AND blocking_event_count BETWEEN 0 AND 2048 "
        "AND ((effective_state = 'running' AND blocking_event_count = 0 "
        "AND NOT blocker_overflowed) "
        "OR (effective_state <> 'running' AND blocking_event_count > 0)) "
        "AND (NOT blocker_overflowed OR blocking_event_count = 2048) "
        "AND (active_operation_attempt_id IS NULL "
        "OR length(active_operation_attempt_id) = 36) "
        "AND (active_operation_sha256 IS NULL "
        "OR length(active_operation_sha256) = 64) "
        "AND (active_operation_state_epoch_id IS NULL "
        "OR length(active_operation_state_epoch_id) = 36) "
        "AND (active_operation_opened_by_command_id IS NULL "
        "OR length(active_operation_opened_by_command_id) = 36) "
        "AND length(blocking_event_ids_payload) BETWEEN 2 AND 262144 "
        "AND length(canonical_payload) BETWEEN 2 AND 262144",
        name="identity",
    ),
)
sa.Index(
    "ix_phase5_operational_control_head_time",
    phase5_operational_control_heads.c.decided_at,
)

phase5_operational_control_completions = sa.Table(
    "phase5_operational_control_completions",
    metadata,
    sa.Column("completion_id", sa.String(36), primary_key=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("idempotency_key", sa.String(128), nullable=False),
    sa.Column("operation_attempt_id", sa.String(36), nullable=False),
    sa.Column("operation_kind", sa.String(24), nullable=False),
    sa.Column("state_epoch_id", sa.String(36), nullable=False),
    sa.Column("operation_state_epoch_id", sa.String(36), nullable=False),
    sa.Column("operation_attempt_sha256", sa.String(64), nullable=False),
    sa.Column("operation_opened_by_command_id", sa.String(36), nullable=False),
    sa.Column("operation_opened_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("opener_transition_id", sa.String(36), nullable=False),
    sa.Column("opener_sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("opener_transition_sha256", sa.String(64), nullable=False),
    sa.Column("opener_operation_started", sa.Boolean(), nullable=False),
    sa.Column("head_transition_id", sa.String(36), nullable=False),
    sa.Column("head_sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("head_transition_sha256", sa.String(64), nullable=False),
    sa.Column("outcome", sa.String(32), nullable=False),
    sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("evidence_sha256", sa.String(64), nullable=False),
    sa.Column("terminal_order_count", sa.BigInteger(), nullable=False),
    sa.Column("working_order_count", sa.BigInteger(), nullable=False),
    sa.Column("working_order_ids_payload", sa.Text(), nullable=False),
    sa.Column("working_order_ids_sha256", sa.String(64), nullable=False),
    sa.Column("unknown_order_count", sa.BigInteger(), nullable=False),
    sa.Column("unknown_order_ids_payload", sa.Text(), nullable=False),
    sa.Column("unknown_order_ids_sha256", sa.String(64), nullable=False),
    sa.Column("pending_cancel_order_count", sa.BigInteger(), nullable=False),
    sa.Column("pending_cancel_order_ids_payload", sa.Text(), nullable=False),
    sa.Column("pending_cancel_order_ids_sha256", sa.String(64), nullable=False),
    sa.Column("reconciliation_clean", sa.Boolean(), nullable=False),
    sa.Column("source_evidence_sha256", sa.String(64), nullable=False),
    sa.Column("incomplete_reason", sa.String(256), nullable=True),
    sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("residual_position_count", sa.BigInteger(), nullable=False),
    sa.Column("residual_gross_exposure", sa.Numeric(32, 10), nullable=False),
    sa.Column("residual_positions_payload", sa.Text(), nullable=False),
    sa.Column("residual_positions_sha256", sa.String(64), nullable=False),
    sa.Column("residual_facts_sha256", sa.String(64), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "account_id",
        "operation_attempt_id",
        name="uq_phase5_control_completion_account_attempt",
    ),
    sa.UniqueConstraint(
        "account_id",
        "idempotency_key",
        name="uq_phase5_control_completion_account_key",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "opener_transition_id",
            "opener_sequence_number",
            "state_epoch_id",
            "operation_attempt_id",
            "operation_kind",
            "operation_state_epoch_id",
            "operation_opened_by_command_id",
            "operation_opened_at",
            "operation_attempt_sha256",
            "opener_operation_started",
            "opener_transition_sha256",
        ],
        [
            "phase5_operational_control_transitions.account_id",
            "phase5_operational_control_transitions.transition_id",
            "phase5_operational_control_transitions.sequence_number",
            "phase5_operational_control_transitions.state_epoch_id",
            "phase5_operational_control_transitions.active_operation_attempt_id",
            "phase5_operational_control_transitions.active_operation_kind",
            "phase5_operational_control_transitions.active_operation_state_epoch_id",
            "phase5_operational_control_transitions.active_operation_opened_by_command_id",
            "phase5_operational_control_transitions.active_operation_opened_at",
            "phase5_operational_control_transitions.active_operation_sha256",
            "phase5_operational_control_transitions.operation_started",
            "phase5_operational_control_transitions.semantic_sha256",
        ],
        name="fk_phase5_control_completion_opener",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "head_transition_id",
            "head_sequence_number",
            "state_epoch_id",
            "operation_attempt_id",
            "operation_kind",
            "operation_state_epoch_id",
            "operation_opened_by_command_id",
            "operation_opened_at",
            "operation_attempt_sha256",
            "head_transition_sha256",
        ],
        [
            "phase5_operational_control_transitions.account_id",
            "phase5_operational_control_transitions.transition_id",
            "phase5_operational_control_transitions.sequence_number",
            "phase5_operational_control_transitions.state_epoch_id",
            "phase5_operational_control_transitions.active_operation_attempt_id",
            "phase5_operational_control_transitions.active_operation_kind",
            "phase5_operational_control_transitions.active_operation_state_epoch_id",
            "phase5_operational_control_transitions.active_operation_opened_by_command_id",
            "phase5_operational_control_transitions.active_operation_opened_at",
            "phase5_operational_control_transitions.active_operation_sha256",
            "phase5_operational_control_transitions.semantic_sha256",
        ],
        name="fk_phase5_control_completion_head",
    ),
    sa.CheckConstraint(
        "operation_kind IN ('drain', 'flatten') "
        "AND length(state_epoch_id) = 36 "
        "AND operation_state_epoch_id = state_epoch_id "
        "AND opener_sequence_number > 0 "
        "AND head_sequence_number >= opener_sequence_number "
        "AND opener_operation_started "
        "AND terminal_order_count >= 0 "
        "AND working_order_count >= 0 "
        "AND unknown_order_count >= 0 "
        "AND pending_cancel_order_count >= 0 "
        "AND residual_position_count >= 0 "
        "AND residual_gross_exposure >= 0 "
        "AND observed_at >= operation_opened_at "
        "AND (deadline_at IS NULL OR deadline_at >= operation_opened_at)",
        name="scope",
    ),
    sa.CheckConstraint(
        "outcome IN ('completed', 'incomplete', 'deadline_exceeded') "
        "AND ("
        "(outcome = 'completed' "
        "AND incomplete_reason IS NULL "
        "AND working_order_count = 0 "
        "AND unknown_order_count = 0 "
        "AND pending_cancel_order_count = 0 "
        "AND reconciliation_clean "
        "AND (operation_kind <> 'flatten' "
        "OR (residual_position_count = 0 AND residual_gross_exposure = 0))) "
        "OR (outcome IN ('incomplete', 'deadline_exceeded') "
        "AND incomplete_reason IS NOT NULL "
        "AND (working_order_count > 0 "
        "OR unknown_order_count > 0 "
        "OR pending_cancel_order_count > 0 "
        "OR residual_position_count > 0 "
        "OR NOT reconciliation_clean))) "
        "AND (outcome <> 'deadline_exceeded' "
        "OR (deadline_at IS NOT NULL AND deadline_at <= observed_at))",
        name="outcome",
    ),
    sa.CheckConstraint(
        "length(completion_id) = 36 "
        "AND length(idempotency_key) BETWEEN 8 AND 128 "
        "AND length(operation_attempt_id) = 36 "
        "AND length(operation_attempt_sha256) = 64 "
        "AND length(operation_opened_by_command_id) = 36 "
        "AND length(opener_transition_id) = 36 "
        "AND length(opener_transition_sha256) = 64 "
        "AND length(head_transition_id) = 36 "
        "AND length(head_transition_sha256) = 64 "
        "AND length(evidence_sha256) = 64 "
        "AND length(source_evidence_sha256) = 64 "
        "AND length(working_order_ids_sha256) = 64 "
        "AND length(unknown_order_ids_sha256) = 64 "
        "AND length(pending_cancel_order_ids_sha256) = 64 "
        "AND length(residual_positions_sha256) = 64 "
        "AND length(residual_facts_sha256) = 64 "
        "AND length(outcome) BETWEEN 1 AND 32 "
        "AND (incomplete_reason IS NULL "
        "OR length(incomplete_reason) BETWEEN 1 AND 256) "
        "AND length(semantic_sha256) = 64",
        name="identity",
    ),
    sa.CheckConstraint(
        "length(working_order_ids_payload) BETWEEN 2 AND 4194304 "
        "AND length(unknown_order_ids_payload) BETWEEN 2 AND 4194304 "
        "AND length(pending_cancel_order_ids_payload) BETWEEN 2 AND 4194304 "
        "AND length(residual_positions_payload) BETWEEN 2 AND 2097152 "
        "AND length(canonical_payload) BETWEEN 2 AND 524288",
        name="payloads",
    ),
)
sa.Index(
    "ix_phase5_operational_control_completion_account_time",
    phase5_operational_control_completions.c.account_id,
    phase5_operational_control_completions.c.observed_at,
)

# Phase 5B advanced-risk persistence is strictly additive.  Policy assignment,
# evidence, assessment, and cutover identities live beside the Phase 2
# decision contract so retained Phase 2 semantic payloads remain unchanged.
# Mutable heads are authenticated caches only; every authority-bearing value
# points back to immutable, content-addressed facts.
phase5_advanced_risk_policies = sa.Table(
    "phase5_advanced_risk_policies",
    metadata,
    sa.Column("policy_sha256", sa.String(64), primary_key=True),
    sa.Column("policy_id", sa.String(128), nullable=False),
    sa.Column("policy_version", sa.String(64), nullable=False),
    sa.Column("environment", sa.String(32), nullable=False),
    sa.Column("scope_profile_id", sa.String(128), nullable=False),
    sa.Column("scope_profile_sha256", sa.String(64), nullable=False),
    sa.Column("rule_count", sa.Integer(), nullable=False),
    sa.Column("pretrade_new_exposure_rule_count", sa.Integer(), nullable=False),
    sa.Column("runtime_rule_count", sa.Integer(), nullable=False),
    sa.Column("none_disposition_count", sa.Integer(), nullable=False),
    sa.Column("reject_disposition_count", sa.Integer(), nullable=False),
    sa.Column("pause_disposition_count", sa.Integer(), nullable=False),
    sa.Column("halt_disposition_count", sa.Integer(), nullable=False),
    sa.Column("rules_payload", sa.Text(), nullable=False),
    # Owner-direction provenance is deliberately non-authenticating.  The
    # assignment command below is the sole actor-authority boundary.
    sa.Column("approval_evidence_sha256", sa.String(64), nullable=False),
    sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "policy_id",
        "policy_version",
        "environment",
        name="uq_phase5_adv_policy_version_scope",
    ),
    sa.UniqueConstraint(
        "policy_sha256",
        "policy_id",
        "environment",
        "semantic_sha256",
        name="uq_phase5_adv_policy_exact",
    ),
    sa.CheckConstraint(
        "rule_count BETWEEN 1 AND 64 "
        "AND pretrade_new_exposure_rule_count BETWEEN 1 AND rule_count "
        "AND runtime_rule_count BETWEEN 1 AND rule_count "
        "AND none_disposition_count BETWEEN 0 AND rule_count "
        "AND reject_disposition_count BETWEEN 0 AND rule_count "
        "AND pause_disposition_count BETWEEN 0 AND rule_count "
        "AND halt_disposition_count BETWEEN 0 AND rule_count",
        name="counts",
    ),
    sa.CheckConstraint(
        "length(policy_sha256) = 64 "
        "AND length(scope_profile_sha256) = 64 "
        "AND length(approval_evidence_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="hashes",
    ),
    sa.CheckConstraint(
        "length(policy_id) BETWEEN 1 AND 128 "
        "AND length(policy_version) BETWEEN 1 AND 64 "
        "AND length(environment) BETWEEN 1 AND 32 "
        "AND length(scope_profile_id) BETWEEN 1 AND 128 "
        "AND length(rules_payload) BETWEEN 2 AND 1048576 "
        "AND length(canonical_payload) BETWEEN 2 AND 2097152",
        name="payloads",
    ),
)
sa.Index(
    "ix_phase5_adv_policy_scope",
    phase5_advanced_risk_policies.c.environment,
    phase5_advanced_risk_policies.c.policy_id,
)

phase5_advanced_risk_assignments = sa.Table(
    "phase5_advanced_risk_assignments",
    metadata,
    sa.Column("assignment_id", sa.String(36), primary_key=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("previous_sequence_number", sa.BigInteger(), nullable=True),
    sa.Column("previous_assignment_id", sa.String(36), nullable=True),
    sa.Column("previous_assignment_sha256", sa.String(64), nullable=True),
    sa.Column("policy_sha256", sa.String(64), nullable=False),
    sa.Column("policy_id", sa.String(128), nullable=False),
    sa.Column("policy_semantic_sha256", sa.String(64), nullable=False),
    sa.Column("environment", sa.String(32), nullable=False),
    sa.Column("command_id", sa.String(36), nullable=False),
    sa.Column("command_sha256", sa.String(64), nullable=False),
    sa.Column("actor_id", sa.String(128), nullable=False),
    sa.Column("actor_authority_sha256", sa.String(64), nullable=False),
    sa.Column("actor_authenticated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("lease_sha256", sa.String(64), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column("operational_transition_id", sa.String(36), nullable=False),
    sa.Column("operational_transition_sha256", sa.String(64), nullable=False),
    sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "account_id",
        "sequence_number",
        name="uq_phase5_adv_assignment_account_sequence",
    ),
    sa.UniqueConstraint(
        "account_id",
        "command_id",
        name="uq_phase5_adv_assignment_command",
    ),
    sa.UniqueConstraint(
        "account_id",
        "assignment_id",
        "semantic_sha256",
        name="uq_phase5_adv_assignment_id_exact",
    ),
    sa.UniqueConstraint(
        "account_id",
        "sequence_number",
        "assignment_id",
        "semantic_sha256",
        name="uq_phase5_adv_assignment_chain_exact",
    ),
    sa.UniqueConstraint(
        "account_id",
        "assignment_id",
        "sequence_number",
        "policy_sha256",
        "semantic_sha256",
        name="uq_phase5_adv_assignment_policy_exact",
    ),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase5_adv_assignment_account",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "fencing_generation", "lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase5_adv_assignment_lease",
    ),
    sa.ForeignKeyConstraint(
        [
            "policy_sha256",
            "policy_id",
            "environment",
            "policy_semantic_sha256",
        ],
        [
            "phase5_advanced_risk_policies.policy_sha256",
            "phase5_advanced_risk_policies.policy_id",
            "phase5_advanced_risk_policies.environment",
            "phase5_advanced_risk_policies.semantic_sha256",
        ],
        name="fk_phase5_adv_assignment_policy",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "previous_sequence_number",
            "previous_assignment_id",
            "previous_assignment_sha256",
        ],
        [
            "phase5_advanced_risk_assignments.account_id",
            "phase5_advanced_risk_assignments.sequence_number",
            "phase5_advanced_risk_assignments.assignment_id",
            "phase5_advanced_risk_assignments.semantic_sha256",
        ],
        name="fk_phase5_adv_assignment_predecessor",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "operational_transition_id",
            "operational_transition_sha256",
        ],
        [
            "phase5_operational_control_transitions.account_id",
            "phase5_operational_control_transitions.transition_id",
            "phase5_operational_control_transitions.semantic_sha256",
        ],
        name="fk_phase5_adv_assignment_control",
    ),
    sa.CheckConstraint(
        "(sequence_number = 1 "
        "AND previous_sequence_number IS NULL "
        "AND previous_assignment_id IS NULL "
        "AND previous_assignment_sha256 IS NULL) "
        "OR (sequence_number > 1 "
        "AND previous_sequence_number = sequence_number - 1 "
        "AND previous_assignment_id IS NOT NULL "
        "AND previous_assignment_sha256 IS NOT NULL)",
        name="predecessor",
    ),
    sa.CheckConstraint(
        "fencing_generation > 0",
        name="scope",
    ),
    sa.CheckConstraint(
        "length(assignment_id) = 36 "
        "AND (previous_assignment_id IS NULL "
        "OR length(previous_assignment_id) = 36) "
        "AND (previous_assignment_sha256 IS NULL "
        "OR length(previous_assignment_sha256) = 64) "
        "AND length(policy_sha256) = 64 "
        "AND length(policy_semantic_sha256) = 64 "
        "AND length(command_id) = 36 "
        "AND length(command_sha256) = 64 "
        "AND length(actor_authority_sha256) = 64 "
        "AND length(lease_sha256) = 64 "
        "AND length(fence_sha256) = 64 "
        "AND length(operational_transition_id) = 36 "
        "AND length(operational_transition_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="hashes",
    ),
    sa.CheckConstraint(
        "length(account_id) BETWEEN 1 AND 64 "
        "AND length(environment) BETWEEN 1 AND 32 "
        "AND length(policy_id) BETWEEN 1 AND 128 "
        "AND length(actor_id) BETWEEN 1 AND 128 "
        "AND length(canonical_payload) BETWEEN 2 AND 524288",
        name="payloads",
    ),
)
sa.Index(
    "ix_phase5_adv_assignment_account_time",
    phase5_advanced_risk_assignments.c.account_id,
    phase5_advanced_risk_assignments.c.assigned_at,
)

phase5_advanced_risk_assignment_heads = sa.Table(
    "phase5_advanced_risk_assignment_heads",
    metadata,
    sa.Column("account_id", sa.String(64), primary_key=True),
    sa.Column("sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("assignment_id", sa.String(36), nullable=False),
    sa.Column("assignment_sha256", sa.String(64), nullable=False),
    sa.Column("policy_sha256", sa.String(64), nullable=False),
    sa.Column("environment", sa.String(32), nullable=False),
    sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase5_adv_assignment_head_account",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "assignment_id",
            "sequence_number",
            "policy_sha256",
            "assignment_sha256",
        ],
        [
            "phase5_advanced_risk_assignments.account_id",
            "phase5_advanced_risk_assignments.assignment_id",
            "phase5_advanced_risk_assignments.sequence_number",
            "phase5_advanced_risk_assignments.policy_sha256",
            "phase5_advanced_risk_assignments.semantic_sha256",
        ],
        name="fk_phase5_adv_assignment_head_tip",
    ),
    sa.CheckConstraint(
        "sequence_number > 0 AND assigned_at <= updated_at",
        name="scope",
    ),
    sa.CheckConstraint(
        "length(assignment_id) = 36 "
        "AND length(assignment_sha256) = 64 "
        "AND length(policy_sha256) = 64 "
        "AND length(environment) BETWEEN 1 AND 32 "
        "AND length(semantic_sha256) = 64 "
        "AND length(canonical_payload) BETWEEN 2 AND 524288",
        name="identity",
    ),
)

phase5_advanced_risk_evidence = sa.Table(
    "phase5_advanced_risk_evidence",
    metadata,
    sa.Column("evidence_id", sa.String(36), primary_key=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("observation_sequence", sa.BigInteger(), nullable=False),
    sa.Column("previous_observation_sequence", sa.BigInteger(), nullable=True),
    sa.Column("previous_evidence_id", sa.String(36), nullable=True),
    sa.Column("previous_evidence_sha256", sa.String(64), nullable=True),
    sa.Column("assignment_id", sa.String(36), nullable=False),
    sa.Column("assignment_sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("assignment_sha256", sa.String(64), nullable=False),
    sa.Column("policy_sha256", sa.String(64), nullable=False),
    sa.Column("environment", sa.String(32), nullable=False),
    sa.Column("idempotency_key", sa.String(128), nullable=False),
    sa.Column("rule_id", sa.String(128), nullable=False),
    sa.Column("rule_kind", sa.String(32), nullable=False),
    sa.Column("subject_id", sa.String(128), nullable=False),
    sa.Column("rule_sha256", sa.String(64), nullable=False),
    sa.Column("evaluation_mode", sa.String(32), nullable=False),
    sa.Column("breach_disposition", sa.String(16), nullable=False),
    sa.Column("producer_id", sa.String(128), nullable=False),
    sa.Column("producer_version", sa.String(64), nullable=False),
    sa.Column("producer_authority_sha256", sa.String(64), nullable=False),
    sa.Column("source_authority_sha256", sa.String(64), nullable=False),
    sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("window_ended_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("completeness", sa.String(16), nullable=False),
    sa.Column("value", sa.Numeric(28, 10), nullable=True),
    sa.Column("incomplete_reason", sa.String(512), nullable=True),
    sa.Column("sample_count", sa.BigInteger(), nullable=False),
    sa.Column("qualifying_count", sa.BigInteger(), nullable=False),
    sa.Column("source_count", sa.BigInteger(), nullable=False),
    sa.Column("retained_source_count", sa.Integer(), nullable=False),
    sa.Column("source_set_sha256", sa.String(64), nullable=False),
    sa.Column("evidence_sha256", sa.String(64), nullable=False),
    sa.Column("fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("lease_sha256", sa.String(64), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column("operational_transition_id", sa.String(36), nullable=False),
    sa.Column("operational_transition_sha256", sa.String(64), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "account_id",
        "observation_sequence",
        name="uq_phase5_adv_evidence_account_sequence",
    ),
    sa.UniqueConstraint(
        "account_id",
        "producer_id",
        "idempotency_key",
        name="uq_phase5_adv_evidence_producer_key",
    ),
    sa.UniqueConstraint(
        "account_id",
        "evidence_id",
        "semantic_sha256",
        name="uq_phase5_adv_evidence_id_exact",
    ),
    sa.UniqueConstraint(
        "account_id",
        "observation_sequence",
        "evidence_id",
        "semantic_sha256",
        name="uq_phase5_adv_evidence_chain_exact",
    ),
    sa.UniqueConstraint(
        "account_id",
        "evidence_id",
        "observation_sequence",
        "assignment_id",
        "policy_sha256",
        "semantic_sha256",
        name="uq_phase5_adv_evidence_watermark_exact",
    ),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase5_adv_evidence_account",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "fencing_generation", "lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase5_adv_evidence_lease",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "assignment_id",
            "assignment_sequence_number",
            "policy_sha256",
            "assignment_sha256",
        ],
        [
            "phase5_advanced_risk_assignments.account_id",
            "phase5_advanced_risk_assignments.assignment_id",
            "phase5_advanced_risk_assignments.sequence_number",
            "phase5_advanced_risk_assignments.policy_sha256",
            "phase5_advanced_risk_assignments.semantic_sha256",
        ],
        name="fk_phase5_adv_evidence_assignment",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "previous_observation_sequence",
            "previous_evidence_id",
            "previous_evidence_sha256",
        ],
        [
            "phase5_advanced_risk_evidence.account_id",
            "phase5_advanced_risk_evidence.observation_sequence",
            "phase5_advanced_risk_evidence.evidence_id",
            "phase5_advanced_risk_evidence.semantic_sha256",
        ],
        name="fk_phase5_adv_evidence_predecessor",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "operational_transition_id",
            "operational_transition_sha256",
        ],
        [
            "phase5_operational_control_transitions.account_id",
            "phase5_operational_control_transitions.transition_id",
            "phase5_operational_control_transitions.semantic_sha256",
        ],
        name="fk_phase5_adv_evidence_control",
    ),
    sa.CheckConstraint(
        "(observation_sequence = 1 "
        "AND previous_observation_sequence IS NULL "
        "AND previous_evidence_id IS NULL "
        "AND previous_evidence_sha256 IS NULL) "
        "OR (observation_sequence > 1 "
        "AND previous_observation_sequence = observation_sequence - 1 "
        "AND previous_evidence_id IS NOT NULL "
        "AND previous_evidence_sha256 IS NOT NULL)",
        name="predecessor",
    ),
    sa.CheckConstraint(
        "rule_kind IN "
        "('session_loss', 'session_drawdown', 'concentration', 'leverage', "
        "'volatility', 'spread', 'slippage', 'broker_reject_rate', "
        "'broker_rate_limit', 'clock_health', 'data_health', "
        "'unknown_duration', 'reconciliation_duration') "
        "AND evaluation_mode IN ('pretrade_new_exposure', 'runtime') "
        "AND breach_disposition IN ('none', 'reject', 'pause', 'halt')",
        name="rule",
    ),
    sa.CheckConstraint(
        "window_started_at < window_ended_at "
        "AND window_ended_at <= observed_at "
        "AND observed_at <= recorded_at",
        name="chronology",
    ),
    sa.CheckConstraint(
        "completeness IN "
        "('complete', 'insufficient', 'unavailable', 'overflowed') "
        "AND sample_count >= 0 "
        "AND qualifying_count BETWEEN 0 AND sample_count "
        "AND source_count >= 0 "
        "AND retained_source_count BETWEEN 0 AND 2048 "
        "AND ("
        "(completeness = 'complete' "
        "AND value IS NOT NULL "
        "AND incomplete_reason IS NULL "
        "AND source_count = retained_source_count "
        "AND retained_source_count > 0) "
        "OR (completeness = 'overflowed' "
        "AND value IS NULL "
        "AND incomplete_reason IS NOT NULL "
        "AND retained_source_count = 2048 "
        "AND source_count > retained_source_count) "
        "OR (completeness IN ('insufficient', 'unavailable') "
        "AND value IS NULL "
        "AND incomplete_reason IS NOT NULL "
        "AND source_count = retained_source_count))",
        name="completeness",
    ),
    sa.CheckConstraint(
        "fencing_generation > 0 "
        "AND assignment_sequence_number > 0 "
        "AND length(evidence_id) = 36 "
        "AND (previous_evidence_id IS NULL "
        "OR length(previous_evidence_id) = 36) "
        "AND (previous_evidence_sha256 IS NULL "
        "OR length(previous_evidence_sha256) = 64) "
        "AND length(assignment_id) = 36 "
        "AND length(assignment_sha256) = 64 "
        "AND length(policy_sha256) = 64 "
        "AND length(rule_sha256) = 64 "
        "AND length(producer_authority_sha256) = 64 "
        "AND length(source_authority_sha256) = 64 "
        "AND length(source_set_sha256) = 64 "
        "AND length(evidence_sha256) = 64 "
        "AND length(lease_sha256) = 64 "
        "AND length(fence_sha256) = 64 "
        "AND length(operational_transition_id) = 36 "
        "AND length(operational_transition_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="hashes",
    ),
    sa.CheckConstraint(
        "length(account_id) BETWEEN 1 AND 64 "
        "AND length(environment) BETWEEN 1 AND 32 "
        "AND length(idempotency_key) BETWEEN 8 AND 128 "
        "AND length(rule_id) BETWEEN 1 AND 128 "
        "AND length(subject_id) BETWEEN 1 AND 128 "
        "AND length(producer_id) BETWEEN 1 AND 128 "
        "AND length(producer_version) BETWEEN 1 AND 64 "
        "AND (incomplete_reason IS NULL "
        "OR length(incomplete_reason) BETWEEN 1 AND 512) "
        "AND length(canonical_payload) BETWEEN 2 AND 2097152",
        name="payloads",
    ),
)
sa.Index(
    "ix_phase5_adv_evidence_account_time",
    phase5_advanced_risk_evidence.c.account_id,
    phase5_advanced_risk_evidence.c.recorded_at,
)
sa.Index(
    "ix_phase5_adv_evidence_rule_time",
    phase5_advanced_risk_evidence.c.rule_kind,
    phase5_advanced_risk_evidence.c.recorded_at,
)

phase5_advanced_risk_evidence_sources = sa.Table(
    "phase5_advanced_risk_evidence_sources",
    metadata,
    sa.Column("evidence_id", sa.String(36), nullable=False),
    sa.Column("ordinal", sa.Integer(), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("evidence_sha256", sa.String(64), nullable=False),
    sa.Column("source_kind", sa.String(64), nullable=False),
    sa.Column("source_id", sa.String(128), nullable=False),
    sa.Column("source_sha256", sa.String(64), nullable=False),
    sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False),
    sa.PrimaryKeyConstraint("evidence_id", "ordinal"),
    sa.UniqueConstraint(
        "evidence_id",
        "source_kind",
        "source_id",
        name="uq_phase5_adv_evidence_source_identity",
    ),
    sa.UniqueConstraint(
        "evidence_id",
        "semantic_sha256",
        name="uq_phase5_adv_evidence_source_semantic",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "evidence_id", "evidence_sha256"],
        [
            "phase5_advanced_risk_evidence.account_id",
            "phase5_advanced_risk_evidence.evidence_id",
            "phase5_advanced_risk_evidence.semantic_sha256",
        ],
        name="fk_phase5_adv_evidence_source_parent",
    ),
    sa.CheckConstraint(
        "ordinal BETWEEN 0 AND 2047 AND effective_at <= available_at",
        name="scope",
    ),
    sa.CheckConstraint(
        "length(evidence_id) = 36 "
        "AND length(evidence_sha256) = 64 "
        "AND length(source_kind) BETWEEN 1 AND 64 "
        "AND length(source_id) BETWEEN 1 AND 128 "
        "AND length(source_sha256) = 64 "
        "AND length(semantic_sha256) = 64 "
        "AND length(canonical_payload) BETWEEN 2 AND 131072",
        name="identity",
    ),
)

phase5_advanced_risk_assessments = sa.Table(
    "phase5_advanced_risk_assessments",
    metadata,
    sa.Column("assessment_id", sa.String(36), primary_key=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("previous_sequence_number", sa.BigInteger(), nullable=True),
    sa.Column("previous_assessment_id", sa.String(36), nullable=True),
    sa.Column("previous_assessment_sha256", sa.String(64), nullable=True),
    sa.Column("idempotency_key", sa.String(128), nullable=False),
    sa.Column("assignment_id", sa.String(36), nullable=False),
    sa.Column("assignment_sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("assignment_sha256", sa.String(64), nullable=False),
    sa.Column("policy_sha256", sa.String(64), nullable=False),
    sa.Column("environment", sa.String(32), nullable=False),
    sa.Column("observation_watermark_sequence", sa.BigInteger(), nullable=False),
    sa.Column("watermark_evidence_id", sa.String(36), nullable=False),
    sa.Column("watermark_evidence_sha256", sa.String(64), nullable=False),
    sa.Column("evaluation_mode", sa.String(32), nullable=False),
    sa.Column("disposition", sa.String(16), nullable=False),
    sa.Column("result_count", sa.Integer(), nullable=False),
    sa.Column("complete_result_count", sa.Integer(), nullable=False),
    sa.Column("incomplete_result_count", sa.Integer(), nullable=False),
    sa.Column("breached_rule_count", sa.Integer(), nullable=False),
    sa.Column("results_payload", sa.Text(), nullable=False),
    sa.Column("results_sha256", sa.String(64), nullable=False),
    sa.Column("fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("lease_sha256", sa.String(64), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column("operational_transition_id", sa.String(36), nullable=False),
    sa.Column("operational_transition_sha256", sa.String(64), nullable=False),
    sa.Column("assessed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("valid_through", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "account_id",
        "sequence_number",
        name="uq_phase5_adv_assessment_account_sequence",
    ),
    sa.UniqueConstraint(
        "account_id",
        "idempotency_key",
        name="uq_phase5_adv_assessment_account_key",
    ),
    sa.UniqueConstraint(
        "account_id",
        "assessment_id",
        "semantic_sha256",
        name="uq_phase5_adv_assessment_id_exact",
    ),
    sa.UniqueConstraint(
        "account_id",
        "sequence_number",
        "assessment_id",
        "semantic_sha256",
        name="uq_phase5_adv_assessment_chain_exact",
    ),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase5_adv_assessment_account",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "fencing_generation", "lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase5_adv_assessment_lease",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "previous_sequence_number",
            "previous_assessment_id",
            "previous_assessment_sha256",
        ],
        [
            "phase5_advanced_risk_assessments.account_id",
            "phase5_advanced_risk_assessments.sequence_number",
            "phase5_advanced_risk_assessments.assessment_id",
            "phase5_advanced_risk_assessments.semantic_sha256",
        ],
        name="fk_phase5_adv_assessment_predecessor",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "assignment_id",
            "assignment_sequence_number",
            "policy_sha256",
            "assignment_sha256",
        ],
        [
            "phase5_advanced_risk_assignments.account_id",
            "phase5_advanced_risk_assignments.assignment_id",
            "phase5_advanced_risk_assignments.sequence_number",
            "phase5_advanced_risk_assignments.policy_sha256",
            "phase5_advanced_risk_assignments.semantic_sha256",
        ],
        name="fk_phase5_adv_assessment_assignment",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "watermark_evidence_id",
            "observation_watermark_sequence",
            "assignment_id",
            "policy_sha256",
            "watermark_evidence_sha256",
        ],
        [
            "phase5_advanced_risk_evidence.account_id",
            "phase5_advanced_risk_evidence.evidence_id",
            "phase5_advanced_risk_evidence.observation_sequence",
            "phase5_advanced_risk_evidence.assignment_id",
            "phase5_advanced_risk_evidence.policy_sha256",
            "phase5_advanced_risk_evidence.semantic_sha256",
        ],
        name="fk_phase5_adv_assessment_watermark",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "operational_transition_id",
            "operational_transition_sha256",
        ],
        [
            "phase5_operational_control_transitions.account_id",
            "phase5_operational_control_transitions.transition_id",
            "phase5_operational_control_transitions.semantic_sha256",
        ],
        name="fk_phase5_adv_assessment_control",
    ),
    sa.CheckConstraint(
        "(sequence_number = 1 "
        "AND previous_sequence_number IS NULL "
        "AND previous_assessment_id IS NULL "
        "AND previous_assessment_sha256 IS NULL) "
        "OR (sequence_number > 1 "
        "AND previous_sequence_number = sequence_number - 1 "
        "AND previous_assessment_id IS NOT NULL "
        "AND previous_assessment_sha256 IS NOT NULL)",
        name="predecessor",
    ),
    sa.CheckConstraint(
        "evaluation_mode IN ('pretrade_new_exposure', 'runtime') "
        "AND disposition IN ('none', 'reject', 'pause', 'halt')",
        name="outcome",
    ),
    sa.CheckConstraint(
        "result_count BETWEEN 1 AND 64 "
        "AND complete_result_count BETWEEN 0 AND result_count "
        "AND incomplete_result_count = result_count - complete_result_count "
        "AND breached_rule_count BETWEEN 0 AND complete_result_count",
        name="counts",
    ),
    sa.CheckConstraint(
        "fencing_generation > 0 "
        "AND assignment_sequence_number > 0 "
        "AND observation_watermark_sequence > 0 "
        "AND assessed_at < valid_through",
        name="scope",
    ),
    sa.CheckConstraint(
        "length(assessment_id) = 36 "
        "AND (previous_assessment_id IS NULL "
        "OR length(previous_assessment_id) = 36) "
        "AND (previous_assessment_sha256 IS NULL "
        "OR length(previous_assessment_sha256) = 64) "
        "AND length(assignment_id) = 36 "
        "AND length(assignment_sha256) = 64 "
        "AND length(policy_sha256) = 64 "
        "AND length(watermark_evidence_id) = 36 "
        "AND length(watermark_evidence_sha256) = 64 "
        "AND length(results_sha256) = 64 "
        "AND length(lease_sha256) = 64 "
        "AND length(fence_sha256) = 64 "
        "AND length(operational_transition_id) = 36 "
        "AND length(operational_transition_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="hashes",
    ),
    sa.CheckConstraint(
        "length(idempotency_key) BETWEEN 8 AND 128 "
        "AND length(environment) BETWEEN 1 AND 32 "
        "AND length(results_payload) BETWEEN 2 AND 2097152 "
        "AND length(canonical_payload) BETWEEN 2 AND 4194304",
        name="payloads",
    ),
)
sa.Index(
    "ix_phase5_adv_assessment_account_time",
    phase5_advanced_risk_assessments.c.account_id,
    phase5_advanced_risk_assessments.c.assessed_at,
)

phase5_advanced_risk_batch_admissions = sa.Table(
    "phase5_advanced_risk_batch_admissions",
    metadata,
    sa.Column("admission_id", sa.String(36), primary_key=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("phase2_decision_id", sa.String(64), nullable=False, unique=True),
    sa.Column("phase2_decision_sha256", sa.String(64), nullable=False),
    sa.Column("phase2_decision_status", sa.String(16), nullable=False),
    sa.Column("fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("lease_sha256", sa.String(64), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    # A canonical empty Phase 2 batch has no proposed instrument and therefore
    # cannot honestly produce a PRETRADE assessment.  Only NO_ACTION uses the
    # exact all-null assessment/assignment/watermark shape below.
    sa.Column("assessment_id", sa.String(36), nullable=True),
    sa.Column("assessment_sha256", sa.String(64), nullable=True),
    sa.Column("assignment_id", sa.String(36), nullable=True),
    sa.Column("assignment_sequence_number", sa.BigInteger(), nullable=True),
    sa.Column("assignment_sha256", sa.String(64), nullable=True),
    sa.Column("policy_sha256", sa.String(64), nullable=True),
    sa.Column("observation_watermark_sequence", sa.BigInteger(), nullable=True),
    sa.Column("watermark_evidence_id", sa.String(36), nullable=True),
    sa.Column("watermark_evidence_sha256", sa.String(64), nullable=True),
    sa.Column("operational_transition_id", sa.String(36), nullable=False),
    sa.Column("operational_transition_sha256", sa.String(64), nullable=False),
    sa.Column("assessment_mode", sa.String(32), nullable=True),
    sa.Column("assessment_disposition", sa.String(16), nullable=True),
    sa.Column("admitted", sa.Boolean(), nullable=False),
    sa.Column("bound_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "admission_id",
        "account_id",
        "phase2_decision_id",
        "semantic_sha256",
        name="uq_phase5_adv_admission_exact",
    ),
    sa.ForeignKeyConstraint(
        ["phase2_decision_id", "account_id", "fencing_generation"],
        [
            "phase2_batch_decisions.decision_id",
            "phase2_batch_decisions.account_id",
            "phase2_batch_decisions.fencing_generation",
        ],
        name="fk_phase5_adv_admission_phase2_decision",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "fencing_generation", "lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase5_adv_admission_lease",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "assessment_id", "assessment_sha256"],
        [
            "phase5_advanced_risk_assessments.account_id",
            "phase5_advanced_risk_assessments.assessment_id",
            "phase5_advanced_risk_assessments.semantic_sha256",
        ],
        name="fk_phase5_adv_admission_assessment",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "assignment_id",
            "assignment_sequence_number",
            "policy_sha256",
            "assignment_sha256",
        ],
        [
            "phase5_advanced_risk_assignments.account_id",
            "phase5_advanced_risk_assignments.assignment_id",
            "phase5_advanced_risk_assignments.sequence_number",
            "phase5_advanced_risk_assignments.policy_sha256",
            "phase5_advanced_risk_assignments.semantic_sha256",
        ],
        name="fk_phase5_adv_admission_assignment",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "watermark_evidence_id",
            "observation_watermark_sequence",
            "assignment_id",
            "policy_sha256",
            "watermark_evidence_sha256",
        ],
        [
            "phase5_advanced_risk_evidence.account_id",
            "phase5_advanced_risk_evidence.evidence_id",
            "phase5_advanced_risk_evidence.observation_sequence",
            "phase5_advanced_risk_evidence.assignment_id",
            "phase5_advanced_risk_evidence.policy_sha256",
            "phase5_advanced_risk_evidence.semantic_sha256",
        ],
        name="fk_phase5_adv_admission_watermark",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "operational_transition_id",
            "operational_transition_sha256",
        ],
        [
            "phase5_operational_control_transitions.account_id",
            "phase5_operational_control_transitions.transition_id",
            "phase5_operational_control_transitions.semantic_sha256",
        ],
        name="fk_phase5_adv_admission_control",
    ),
    sa.CheckConstraint(
        "(phase2_decision_status = 'no_action' "
        "AND NOT admitted "
        "AND assessment_id IS NULL "
        "AND assessment_sha256 IS NULL "
        "AND assignment_id IS NULL "
        "AND assignment_sequence_number IS NULL "
        "AND assignment_sha256 IS NULL "
        "AND policy_sha256 IS NULL "
        "AND observation_watermark_sequence IS NULL "
        "AND watermark_evidence_id IS NULL "
        "AND watermark_evidence_sha256 IS NULL "
        "AND assessment_mode IS NULL "
        "AND assessment_disposition IS NULL) "
        "OR (phase2_decision_status IN ('approved', 'rejected') "
        "AND assessment_id IS NOT NULL "
        "AND assessment_sha256 IS NOT NULL "
        "AND assignment_id IS NOT NULL "
        "AND assignment_sequence_number IS NOT NULL "
        "AND assignment_sha256 IS NOT NULL "
        "AND policy_sha256 IS NOT NULL "
        "AND observation_watermark_sequence IS NOT NULL "
        "AND watermark_evidence_id IS NOT NULL "
        "AND watermark_evidence_sha256 IS NOT NULL "
        "AND assessment_mode = 'pretrade_new_exposure' "
        "AND assessment_disposition IN ('none', 'reject', 'pause', 'halt') "
        "AND ((admitted "
        "AND phase2_decision_status = 'approved' "
        "AND assessment_disposition = 'none') "
        "OR (NOT admitted "
        "AND (phase2_decision_status = 'rejected' "
        "OR assessment_disposition <> 'none'))))",
        name="outcome",
    ),
    sa.CheckConstraint(
        "fencing_generation > 0 "
        "AND (assignment_sequence_number IS NULL "
        "OR assignment_sequence_number > 0) "
        "AND (observation_watermark_sequence IS NULL "
        "OR observation_watermark_sequence > 0) "
        "AND bound_at < expires_at",
        name="scope",
    ),
    sa.CheckConstraint(
        "length(admission_id) = 36 "
        "AND length(phase2_decision_sha256) = 64 "
        "AND length(lease_sha256) = 64 "
        "AND length(fence_sha256) = 64 "
        "AND (assessment_id IS NULL OR length(assessment_id) = 36) "
        "AND (assessment_sha256 IS NULL OR length(assessment_sha256) = 64) "
        "AND (assignment_id IS NULL OR length(assignment_id) = 36) "
        "AND (assignment_sha256 IS NULL OR length(assignment_sha256) = 64) "
        "AND (policy_sha256 IS NULL OR length(policy_sha256) = 64) "
        "AND (watermark_evidence_id IS NULL "
        "OR length(watermark_evidence_id) = 36) "
        "AND (watermark_evidence_sha256 IS NULL "
        "OR length(watermark_evidence_sha256) = 64) "
        "AND length(operational_transition_id) = 36 "
        "AND length(operational_transition_sha256) = 64 "
        "AND length(semantic_sha256) = 64 "
        "AND length(canonical_payload) BETWEEN 2 AND 2097152",
        name="identity",
    ),
)
sa.Index(
    "ix_phase5_adv_admission_account_time",
    phase5_advanced_risk_batch_admissions.c.account_id,
    phase5_advanced_risk_batch_admissions.c.bound_at,
)

phase5_advanced_risk_batch_outcomes = sa.Table(
    "phase5_advanced_risk_batch_outcomes",
    metadata,
    sa.Column("outcome_id", sa.String(36), primary_key=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("intent_batch_id", sa.String(64), nullable=False, unique=True),
    sa.Column("intent_batch_sha256", sa.String(64), nullable=False),
    sa.Column("watermark_id", sa.String(36), nullable=False, unique=True),
    sa.Column("watermark_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("target_id", sa.String(64), nullable=False),
    sa.Column("target_sha256", sa.String(64), nullable=False),
    sa.Column("snapshot_version", sa.String(128), nullable=False),
    sa.Column("snapshot_sha256", sa.String(64), nullable=False),
    sa.Column("active_capacity_sha256", sa.String(64), nullable=False),
    sa.Column("phase2_policy_sha256", sa.String(64), nullable=False),
    sa.Column("advanced_risk_policy_sha256", sa.String(64), nullable=False),
    sa.Column("fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("lease_sha256", sa.String(64), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column("runtime_instrument_ids_payload", sa.Text(), nullable=False),
    sa.Column("pretrade_instrument_ids_payload", sa.Text(), nullable=False),
    sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("assignment_id", sa.String(36), nullable=False),
    sa.Column("assignment_sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("assignment_sha256", sa.String(64), nullable=False),
    sa.Column("runtime_assessment_id", sa.String(36), nullable=False),
    sa.Column("runtime_assessment_sha256", sa.String(64), nullable=False),
    sa.Column("pretrade_assessment_id", sa.String(36), nullable=True),
    sa.Column("pretrade_assessment_sha256", sa.String(64), nullable=True),
    sa.Column("pre_control_transition_id", sa.String(36), nullable=False),
    sa.Column("pre_control_transition_sha256", sa.String(64), nullable=False),
    sa.Column("final_control_transition_id", sa.String(36), nullable=False),
    sa.Column("final_control_transition_sha256", sa.String(64), nullable=False),
    sa.Column("final_control_state", sa.String(16), nullable=False),
    sa.Column("phase2_decision_id", sa.String(64), nullable=True),
    sa.Column("phase2_decision_sha256", sa.String(64), nullable=True),
    sa.Column("admission_id", sa.String(36), nullable=True),
    sa.Column("admission_sha256", sa.String(64), nullable=True),
    sa.Column("outcome_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase5_adv_outcome_account",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "fencing_generation", "lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase5_adv_outcome_lease",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "assignment_id",
            "assignment_sequence_number",
            "advanced_risk_policy_sha256",
            "assignment_sha256",
        ],
        [
            "phase5_advanced_risk_assignments.account_id",
            "phase5_advanced_risk_assignments.assignment_id",
            "phase5_advanced_risk_assignments.sequence_number",
            "phase5_advanced_risk_assignments.policy_sha256",
            "phase5_advanced_risk_assignments.semantic_sha256",
        ],
        name="fk_phase5_adv_outcome_assignment",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "runtime_assessment_id", "runtime_assessment_sha256"],
        [
            "phase5_advanced_risk_assessments.account_id",
            "phase5_advanced_risk_assessments.assessment_id",
            "phase5_advanced_risk_assessments.semantic_sha256",
        ],
        name="fk_phase5_adv_outcome_runtime_assessment",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "pretrade_assessment_id", "pretrade_assessment_sha256"],
        [
            "phase5_advanced_risk_assessments.account_id",
            "phase5_advanced_risk_assessments.assessment_id",
            "phase5_advanced_risk_assessments.semantic_sha256",
        ],
        name="fk_phase5_adv_outcome_pretrade_assessment",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "pre_control_transition_id",
            "pre_control_transition_sha256",
        ],
        [
            "phase5_operational_control_transitions.account_id",
            "phase5_operational_control_transitions.transition_id",
            "phase5_operational_control_transitions.semantic_sha256",
        ],
        name="fk_phase5_adv_outcome_pre_control",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "final_control_transition_id",
            "final_control_transition_sha256",
        ],
        [
            "phase5_operational_control_transitions.account_id",
            "phase5_operational_control_transitions.transition_id",
            "phase5_operational_control_transitions.semantic_sha256",
        ],
        name="fk_phase5_adv_outcome_final_control",
    ),
    sa.ForeignKeyConstraint(
        [
            "phase2_decision_id",
            "account_id",
            "fencing_generation",
            "phase2_decision_sha256",
        ],
        [
            "phase2_batch_decisions.decision_id",
            "phase2_batch_decisions.account_id",
            "phase2_batch_decisions.fencing_generation",
            "phase2_batch_decisions.semantic_sha256",
        ],
        name="fk_phase5_adv_outcome_phase2_decision",
    ),
    sa.ForeignKeyConstraint(
        [
            "admission_id",
            "account_id",
            "phase2_decision_id",
            "admission_sha256",
        ],
        [
            "phase5_advanced_risk_batch_admissions.admission_id",
            "phase5_advanced_risk_batch_admissions.account_id",
            "phase5_advanced_risk_batch_admissions.phase2_decision_id",
            "phase5_advanced_risk_batch_admissions.semantic_sha256",
        ],
        name="fk_phase5_adv_outcome_admission",
    ),
    sa.CheckConstraint(
        "fencing_generation > 0 "
        "AND assignment_sequence_number > 0 "
        "AND final_control_state IN "
        "('running', 'paused', 'draining', 'flattening', 'halted')",
        name="scope",
    ),
    sa.CheckConstraint(
        "(pretrade_assessment_id IS NULL "
        "AND pretrade_assessment_sha256 IS NULL) "
        "OR (pretrade_assessment_id IS NOT NULL "
        "AND pretrade_assessment_sha256 IS NOT NULL)",
        name="pretrade_shape",
    ),
    sa.CheckConstraint(
        "(phase2_decision_id IS NULL "
        "AND phase2_decision_sha256 IS NULL "
        "AND admission_id IS NULL "
        "AND admission_sha256 IS NULL) "
        "OR (phase2_decision_id IS NOT NULL "
        "AND phase2_decision_sha256 IS NOT NULL "
        "AND admission_id IS NOT NULL "
        "AND admission_sha256 IS NOT NULL)",
        name="decision_shape",
    ),
    sa.CheckConstraint(
        "length(outcome_id) = 36 "
        "AND length(intent_batch_sha256) = 64 "
        "AND length(watermark_id) = 36 "
        "AND length(watermark_sha256) = 64 "
        "AND length(target_sha256) = 64 "
        "AND length(snapshot_sha256) = 64 "
        "AND length(active_capacity_sha256) = 64 "
        "AND length(phase2_policy_sha256) = 64 "
        "AND length(advanced_risk_policy_sha256) = 64 "
        "AND length(lease_sha256) = 64 "
        "AND length(fence_sha256) = 64 "
        "AND length(assignment_id) = 36 "
        "AND length(assignment_sha256) = 64 "
        "AND length(runtime_assessment_id) = 36 "
        "AND length(runtime_assessment_sha256) = 64 "
        "AND (pretrade_assessment_id IS NULL "
        "OR length(pretrade_assessment_id) = 36) "
        "AND (pretrade_assessment_sha256 IS NULL "
        "OR length(pretrade_assessment_sha256) = 64) "
        "AND length(pre_control_transition_id) = 36 "
        "AND length(pre_control_transition_sha256) = 64 "
        "AND length(final_control_transition_id) = 36 "
        "AND length(final_control_transition_sha256) = 64 "
        "AND (phase2_decision_sha256 IS NULL "
        "OR length(phase2_decision_sha256) = 64) "
        "AND (admission_id IS NULL OR length(admission_id) = 36) "
        "AND (admission_sha256 IS NULL OR length(admission_sha256) = 64) "
        "AND length(outcome_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="identity",
    ),
    sa.CheckConstraint(
        "length(account_id) BETWEEN 1 AND 64 "
        "AND length(intent_batch_id) BETWEEN 1 AND 64 "
        "AND length(target_id) BETWEEN 1 AND 64 "
        "AND length(snapshot_version) BETWEEN 1 AND 128 "
        "AND length(runtime_instrument_ids_payload) BETWEEN 2 AND 262144 "
        "AND length(pretrade_instrument_ids_payload) BETWEEN 2 AND 262144 "
        "AND length(canonical_payload) BETWEEN 2 AND 4194304",
        name="payloads",
    ),
)
sa.Index(
    "ix_phase5_adv_outcome_account_time",
    phase5_advanced_risk_batch_outcomes.c.account_id,
    phase5_advanced_risk_batch_outcomes.c.evaluated_at,
)

phase5_advanced_risk_enforcement_heads = sa.Table(
    "phase5_advanced_risk_enforcement_heads",
    metadata,
    sa.Column("account_id", sa.String(64), primary_key=True),
    sa.Column("cutover_sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("assignment_id", sa.String(36), nullable=False),
    sa.Column("assignment_sequence_number", sa.BigInteger(), nullable=False),
    sa.Column("assignment_sha256", sa.String(64), nullable=False),
    sa.Column("policy_sha256", sa.String(64), nullable=False),
    sa.Column("assessment_id", sa.String(36), nullable=False),
    sa.Column("assessment_sha256", sa.String(64), nullable=False),
    sa.Column("cutover_observation_sequence", sa.BigInteger(), nullable=False),
    sa.Column("cutover_evidence_id", sa.String(36), nullable=False),
    sa.Column("cutover_evidence_sha256", sa.String(64), nullable=False),
    sa.Column("operational_transition_id", sa.String(36), nullable=False),
    sa.Column("operational_transition_sha256", sa.String(64), nullable=False),
    sa.Column("fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("lease_sha256", sa.String(64), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column("enforcement_enabled", sa.Boolean(), nullable=False),
    sa.Column("assessment_disposition", sa.String(16), nullable=False),
    sa.Column("cutover_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("assessment_valid_through", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase5_adv_enforcement_head_account",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "fencing_generation", "lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase5_adv_enforcement_head_lease",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "assignment_id",
            "assignment_sequence_number",
            "policy_sha256",
            "assignment_sha256",
        ],
        [
            "phase5_advanced_risk_assignments.account_id",
            "phase5_advanced_risk_assignments.assignment_id",
            "phase5_advanced_risk_assignments.sequence_number",
            "phase5_advanced_risk_assignments.policy_sha256",
            "phase5_advanced_risk_assignments.semantic_sha256",
        ],
        name="fk_phase5_adv_enforcement_head_assignment",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "assessment_id", "assessment_sha256"],
        [
            "phase5_advanced_risk_assessments.account_id",
            "phase5_advanced_risk_assessments.assessment_id",
            "phase5_advanced_risk_assessments.semantic_sha256",
        ],
        name="fk_phase5_adv_enforcement_head_assessment",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "cutover_evidence_id",
            "cutover_observation_sequence",
            "assignment_id",
            "policy_sha256",
            "cutover_evidence_sha256",
        ],
        [
            "phase5_advanced_risk_evidence.account_id",
            "phase5_advanced_risk_evidence.evidence_id",
            "phase5_advanced_risk_evidence.observation_sequence",
            "phase5_advanced_risk_evidence.assignment_id",
            "phase5_advanced_risk_evidence.policy_sha256",
            "phase5_advanced_risk_evidence.semantic_sha256",
        ],
        name="fk_phase5_adv_enforcement_head_watermark",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "operational_transition_id",
            "operational_transition_sha256",
        ],
        [
            "phase5_operational_control_transitions.account_id",
            "phase5_operational_control_transitions.transition_id",
            "phase5_operational_control_transitions.semantic_sha256",
        ],
        name="fk_phase5_adv_enforcement_head_control",
    ),
    sa.CheckConstraint(
        "cutover_sequence_number > 0 "
        "AND assignment_sequence_number > 0 "
        "AND cutover_observation_sequence > 0 "
        "AND fencing_generation > 0 "
        "AND assessment_disposition IN ('none', 'reject', 'pause', 'halt') "
        "AND cutover_at < assessment_valid_through "
        "AND cutover_at <= updated_at",
        name="scope",
    ),
    sa.CheckConstraint(
        "length(assignment_id) = 36 "
        "AND length(assignment_sha256) = 64 "
        "AND length(policy_sha256) = 64 "
        "AND length(assessment_id) = 36 "
        "AND length(assessment_sha256) = 64 "
        "AND length(cutover_evidence_id) = 36 "
        "AND length(cutover_evidence_sha256) = 64 "
        "AND length(operational_transition_id) = 36 "
        "AND length(operational_transition_sha256) = 64 "
        "AND length(lease_sha256) = 64 "
        "AND length(fence_sha256) = 64 "
        "AND length(semantic_sha256) = 64 "
        "AND length(canonical_payload) BETWEEN 2 AND 2097152",
        name="identity",
    ),
)
sa.Index(
    "ix_phase5_adv_enforcement_head_time",
    phase5_advanced_risk_enforcement_heads.c.updated_at,
)

phase5_critical_alert_incidents = sa.Table(
    "phase5_critical_alert_incidents",
    metadata,
    sa.Column("incident_id", sa.String(36), primary_key=True),
    sa.Column("scope_id", sa.String(128), nullable=False),
    sa.Column("source_id", sa.String(128), nullable=False),
    sa.Column("idempotency_key", sa.String(128), nullable=False),
    sa.Column("alert_code", sa.String(128), nullable=False),
    sa.Column("evidence_sha256", sa.String(64), nullable=False),
    sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("correlation_sha256", sa.String(64), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False),
    sa.UniqueConstraint(
        "scope_id",
        "source_id",
        "idempotency_key",
        name="uq_phase5_critical_alert_source_key",
    ),
    sa.UniqueConstraint(
        "semantic_sha256",
        name="uq_phase5_critical_alert_incident_semantic",
    ),
    sa.UniqueConstraint(
        "incident_id",
        "semantic_sha256",
        name="uq_phase5_critical_alert_incident_exact",
    ),
    sa.CheckConstraint(
        "recorded_at >= detected_at",
        name="time",
    ),
    sa.CheckConstraint(
        "length(incident_id) = 36 "
        "AND length(scope_id) BETWEEN 1 AND 128 "
        "AND length(source_id) BETWEEN 1 AND 128 "
        "AND length(idempotency_key) BETWEEN 8 AND 128 "
        "AND length(alert_code) BETWEEN 1 AND 128 "
        "AND length(evidence_sha256) = 64 "
        "AND length(correlation_sha256) = 64 "
        "AND length(semantic_sha256) = 64 "
        "AND length(canonical_payload) BETWEEN 2 AND 65536",
        name="identity",
    ),
)
sa.Index(
    "ix_phase5_critical_alert_incident_recorded",
    phase5_critical_alert_incidents.c.recorded_at,
    phase5_critical_alert_incidents.c.incident_id,
)

phase5_critical_alert_delivery_attempts = sa.Table(
    "phase5_critical_alert_delivery_attempts",
    metadata,
    sa.Column("attempt_id", sa.String(36), primary_key=True),
    sa.Column("incident_id", sa.String(36), nullable=False),
    sa.Column("incident_sha256", sa.String(64), nullable=False),
    sa.Column("sequence_number", sa.Integer(), nullable=False),
    sa.Column("previous_attempt_id", sa.String(36), nullable=True),
    sa.Column("previous_attempt_sha256", sa.String(64), nullable=True),
    sa.Column("route", sa.String(24), nullable=False),
    sa.Column("provider_id", sa.String(128), nullable=False),
    sa.Column("idempotency_key", sa.String(128), nullable=False),
    sa.Column("request_sha256", sa.String(64), nullable=False),
    sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("command_sha256", sa.String(64), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False),
    sa.UniqueConstraint(
        "incident_id",
        "sequence_number",
        name="uq_phase5_critical_alert_attempt_sequence",
    ),
    sa.UniqueConstraint(
        "incident_id",
        "provider_id",
        "idempotency_key",
        name="uq_phase5_critical_alert_attempt_provider_key",
    ),
    sa.UniqueConstraint(
        "semantic_sha256",
        name="uq_phase5_critical_alert_attempt_semantic",
    ),
    sa.UniqueConstraint(
        "incident_id",
        "attempt_id",
        "semantic_sha256",
        name="uq_phase5_critical_alert_attempt_exact",
    ),
    sa.ForeignKeyConstraint(
        ["incident_id", "incident_sha256"],
        [
            "phase5_critical_alert_incidents.incident_id",
            "phase5_critical_alert_incidents.semantic_sha256",
        ],
        name="fk_phase5_critical_alert_attempt_incident",
    ),
    sa.ForeignKeyConstraint(
        [
            "incident_id",
            "previous_attempt_id",
            "previous_attempt_sha256",
        ],
        [
            "phase5_critical_alert_delivery_attempts.incident_id",
            "phase5_critical_alert_delivery_attempts.attempt_id",
            "phase5_critical_alert_delivery_attempts.semantic_sha256",
        ],
        name="fk_phase5_critical_alert_attempt_predecessor",
    ),
    sa.CheckConstraint(
        "(sequence_number = 1 AND previous_attempt_id IS NULL "
        "AND previous_attempt_sha256 IS NULL) "
        "OR (sequence_number > 1 AND previous_attempt_id IS NOT NULL "
        "AND previous_attempt_sha256 IS NOT NULL)",
        name="predecessor",
    ),
    sa.CheckConstraint(
        "sequence_number BETWEEN 1 AND 1024 "
        "AND claimed_at >= requested_at "
        "AND route IN ('primary', 'escalation')",
        name="scope",
    ),
    sa.CheckConstraint(
        "length(attempt_id) = 36 "
        "AND length(incident_id) = 36 "
        "AND length(incident_sha256) = 64 "
        "AND (previous_attempt_id IS NULL OR length(previous_attempt_id) = 36) "
        "AND (previous_attempt_sha256 IS NULL "
        "OR length(previous_attempt_sha256) = 64) "
        "AND length(provider_id) BETWEEN 1 AND 128 "
        "AND length(idempotency_key) BETWEEN 8 AND 128 "
        "AND length(request_sha256) = 64 "
        "AND length(command_sha256) = 64 "
        "AND length(semantic_sha256) = 64 "
        "AND length(canonical_payload) BETWEEN 2 AND 65536",
        name="identity",
    ),
)
sa.Index(
    "ix_phase5_critical_alert_attempt_incident",
    phase5_critical_alert_delivery_attempts.c.incident_id,
    phase5_critical_alert_delivery_attempts.c.sequence_number,
)

phase5_critical_alert_delivery_results = sa.Table(
    "phase5_critical_alert_delivery_results",
    metadata,
    sa.Column("result_id", sa.String(36), primary_key=True),
    sa.Column("incident_id", sa.String(36), nullable=False),
    sa.Column("incident_sha256", sa.String(64), nullable=False),
    sa.Column("attempt_id", sa.String(36), nullable=False),
    sa.Column("attempt_sha256", sa.String(64), nullable=False),
    sa.Column("outcome", sa.String(24), nullable=False),
    sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("elapsed_microseconds", sa.BigInteger(), nullable=False),
    sa.Column("provider_receipt_sha256", sa.String(64), nullable=True),
    sa.Column("failure_code", sa.String(128), nullable=True),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False),
    sa.UniqueConstraint(
        "attempt_id",
        name="uq_phase5_critical_alert_result_attempt",
    ),
    sa.UniqueConstraint(
        "semantic_sha256",
        name="uq_phase5_critical_alert_result_semantic",
    ),
    sa.UniqueConstraint(
        "incident_id",
        "attempt_id",
        "result_id",
        "semantic_sha256",
        name="uq_phase5_critical_alert_result_exact",
    ),
    sa.ForeignKeyConstraint(
        ["incident_id", "incident_sha256"],
        [
            "phase5_critical_alert_incidents.incident_id",
            "phase5_critical_alert_incidents.semantic_sha256",
        ],
        name="fk_phase5_critical_alert_result_incident",
    ),
    sa.ForeignKeyConstraint(
        ["incident_id", "attempt_id", "attempt_sha256"],
        [
            "phase5_critical_alert_delivery_attempts.incident_id",
            "phase5_critical_alert_delivery_attempts.attempt_id",
            "phase5_critical_alert_delivery_attempts.semantic_sha256",
        ],
        name="fk_phase5_critical_alert_result_attempt",
    ),
    sa.CheckConstraint(
        "elapsed_microseconds >= 0 "
        "AND outcome IN ('confirmed', 'timeout', 'error') "
        "AND ((outcome = 'confirmed' "
        "AND provider_receipt_sha256 IS NOT NULL AND failure_code IS NULL) "
        "OR (outcome <> 'confirmed' "
        "AND provider_receipt_sha256 IS NULL AND failure_code IS NOT NULL))",
        name="outcome",
    ),
    sa.CheckConstraint(
        "length(result_id) = 36 "
        "AND length(incident_id) = 36 "
        "AND length(incident_sha256) = 64 "
        "AND length(attempt_id) = 36 "
        "AND length(attempt_sha256) = 64 "
        "AND (provider_receipt_sha256 IS NULL "
        "OR length(provider_receipt_sha256) = 64) "
        "AND (failure_code IS NULL OR length(failure_code) BETWEEN 1 AND 128) "
        "AND length(semantic_sha256) = 64 "
        "AND length(canonical_payload) BETWEEN 2 AND 65536",
        name="identity",
    ),
)
sa.Index(
    "ix_phase5_critical_alert_result_completed",
    phase5_critical_alert_delivery_results.c.completed_at,
    phase5_critical_alert_delivery_results.c.result_id,
)

# Phase 5D binds replay-authenticated total delivery failure to the fixed local
# severity-preserving PAUSED control response and its source receipt in one
# transaction.
phase5_critical_alert_failure_control_receipts = sa.Table(
    "phase5_critical_alert_failure_control_receipts",
    metadata,
    sa.Column("receipt_id", sa.String(36), primary_key=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("incident_id", sa.String(36), nullable=False, unique=True),
    sa.Column("incident_sha256", sa.String(64), nullable=False),
    sa.Column("route_plan_id", sa.String(128), nullable=False),
    sa.Column("route_plan_version", sa.String(128), nullable=False),
    sa.Column("route_plan_sha256", sa.String(64), nullable=False),
    sa.Column("primary_provider_id", sa.String(128), nullable=False),
    sa.Column("primary_destination_sha256", sa.String(64), nullable=False),
    sa.Column("primary_recipient_set_sha256", sa.String(64), nullable=False),
    sa.Column("escalation_provider_id", sa.String(128), nullable=False),
    sa.Column("escalation_destination_sha256", sa.String(64), nullable=False),
    sa.Column("escalation_recipient_set_sha256", sa.String(64), nullable=False),
    sa.Column("supervisor_evidence_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("supervisor_disposition", sa.String(32), nullable=False),
    sa.Column("supervisor_reason", sa.String(64), nullable=False),
    sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("selected_route", sa.String(24), nullable=False),
    sa.Column("attempt_id", sa.String(36), nullable=False),
    sa.Column("attempt_sha256", sa.String(64), nullable=False),
    sa.Column("result_id", sa.String(36), nullable=True),
    sa.Column("result_sha256", sa.String(64), nullable=True),
    sa.Column("provider_called", sa.Boolean(), nullable=False),
    sa.Column("unresolved_claim", sa.Boolean(), nullable=False),
    sa.Column("actor_authority_sha256", sa.String(64), nullable=False),
    sa.Column("control_policy_sha256", sa.String(64), nullable=False),
    sa.Column("control_command_id", sa.String(36), nullable=False, unique=True),
    sa.Column("control_command_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("pre_control_transition_id", sa.String(36), nullable=False),
    sa.Column("pre_control_transition_sha256", sa.String(64), nullable=False),
    sa.Column("pre_control_state", sa.String(24), nullable=False),
    sa.Column("final_control_transition_id", sa.String(36), nullable=False),
    sa.Column("final_control_transition_sha256", sa.String(64), nullable=False),
    sa.Column("final_control_state", sa.String(24), nullable=False),
    sa.Column("bound_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase5_alert_failure_control_account",
    ),
    sa.ForeignKeyConstraint(
        ["incident_id", "incident_sha256"],
        [
            "phase5_critical_alert_incidents.incident_id",
            "phase5_critical_alert_incidents.semantic_sha256",
        ],
        name="fk_phase5_alert_failure_control_incident",
    ),
    sa.ForeignKeyConstraint(
        ["incident_id", "attempt_id", "attempt_sha256"],
        [
            "phase5_critical_alert_delivery_attempts.incident_id",
            "phase5_critical_alert_delivery_attempts.attempt_id",
            "phase5_critical_alert_delivery_attempts.semantic_sha256",
        ],
        name="fk_phase5_alert_failure_control_attempt",
    ),
    sa.ForeignKeyConstraint(
        ["incident_id", "attempt_id", "result_id", "result_sha256"],
        [
            "phase5_critical_alert_delivery_results.incident_id",
            "phase5_critical_alert_delivery_results.attempt_id",
            "phase5_critical_alert_delivery_results.result_id",
            "phase5_critical_alert_delivery_results.semantic_sha256",
        ],
        name="fk_phase5_alert_failure_control_result",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "pre_control_transition_id",
            "pre_control_transition_sha256",
        ],
        [
            "phase5_operational_control_transitions.account_id",
            "phase5_operational_control_transitions.transition_id",
            "phase5_operational_control_transitions.semantic_sha256",
        ],
        name="fk_phase5_alert_failure_control_pre_control",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "final_control_transition_id",
            "final_control_transition_sha256",
        ],
        [
            "phase5_operational_control_transitions.account_id",
            "phase5_operational_control_transitions.transition_id",
            "phase5_operational_control_transitions.semantic_sha256",
        ],
        name="fk_phase5_alert_failure_control_final_control",
    ),
    sa.CheckConstraint(
        "supervisor_disposition = 'total_delivery_failure' "
        "AND selected_route = 'escalation' "
        "AND bound_at >= observed_at",
        name="scope",
    ),
    sa.CheckConstraint(
        "(unresolved_claim "
        "AND supervisor_reason = 'escalation_deadline_unresolved' "
        "AND result_id IS NULL AND result_sha256 IS NULL) "
        "OR (NOT unresolved_claim "
        "AND supervisor_reason = 'escalation_attempt_failed' "
        "AND result_id IS NOT NULL AND result_sha256 IS NOT NULL)",
        name="failure_shape",
    ),
    sa.CheckConstraint(
        "(pre_control_state = 'running' AND final_control_state = 'paused') "
        "OR (pre_control_state = 'paused' AND final_control_state = 'paused') "
        "OR (pre_control_state = 'draining' AND final_control_state = 'draining') "
        "OR (pre_control_state = 'flattening' "
        "AND final_control_state = 'flattening') "
        "OR (pre_control_state = 'halted' AND final_control_state = 'halted')",
        name="severity",
    ),
    sa.CheckConstraint(
        "length(receipt_id) = 36 "
        "AND length(account_id) BETWEEN 1 AND 64 "
        "AND length(incident_id) = 36 "
        "AND length(incident_sha256) = 64 "
        "AND length(route_plan_id) BETWEEN 1 AND 128 "
        "AND length(route_plan_version) BETWEEN 1 AND 128 "
        "AND length(route_plan_sha256) = 64 "
        "AND length(primary_provider_id) BETWEEN 1 AND 128 "
        "AND length(primary_destination_sha256) = 64 "
        "AND length(primary_recipient_set_sha256) = 64 "
        "AND length(escalation_provider_id) BETWEEN 1 AND 128 "
        "AND length(escalation_destination_sha256) = 64 "
        "AND length(escalation_recipient_set_sha256) = 64 "
        "AND length(supervisor_evidence_sha256) = 64 "
        "AND length(attempt_id) = 36 "
        "AND length(attempt_sha256) = 64 "
        "AND (result_id IS NULL OR length(result_id) = 36) "
        "AND (result_sha256 IS NULL OR length(result_sha256) = 64) "
        "AND length(actor_authority_sha256) = 64 "
        "AND length(control_policy_sha256) = 64 "
        "AND length(control_command_id) = 36 "
        "AND length(control_command_sha256) = 64 "
        "AND length(pre_control_transition_id) = 36 "
        "AND length(pre_control_transition_sha256) = 64 "
        "AND length(final_control_transition_id) = 36 "
        "AND length(final_control_transition_sha256) = 64 "
        "AND length(semantic_sha256) = 64 "
        "AND length(canonical_payload) BETWEEN 2 AND 262144",
        name="identity",
    ),
)
sa.Index(
    "ix_phase5_alert_failure_control_account_time",
    phase5_critical_alert_failure_control_receipts.c.account_id,
    phase5_critical_alert_failure_control_receipts.c.bound_at,
)

# Phase 5C durable strategy-supervision observations. A failed child result and
# its PAUSED breaker transition are committed under the same fenced account
# transaction; a successful result binds the unchanged control head.
phase5_strategy_supervision_results = sa.Table(
    "phase5_strategy_supervision_results",
    metadata,
    sa.Column("invocation_id", sa.String(36), primary_key=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("invocation_sha256", sa.String(64), nullable=False),
    sa.Column("environment", sa.String(32), nullable=False),
    sa.Column("market_batch_id", sa.String(128), nullable=False),
    sa.Column("market_batch_sha256", sa.String(64), nullable=False),
    sa.Column("strategy_id", sa.String(128), nullable=False),
    sa.Column("strategy_version", sa.String(64), nullable=False),
    sa.Column("strategy_configuration_sha256", sa.String(64), nullable=False),
    sa.Column("runtime_sha256", sa.String(64), nullable=False),
    sa.Column("outcome", sa.String(24), nullable=False),
    sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("elapsed_microseconds", sa.BigInteger(), nullable=False),
    sa.Column("process_started", sa.Boolean(), nullable=False),
    sa.Column("exit_code", sa.Integer(), nullable=True),
    sa.Column("stdout_bytes", sa.BigInteger(), nullable=False),
    sa.Column("stdout_sha256", sa.String(64), nullable=False),
    sa.Column("stderr_bytes", sa.BigInteger(), nullable=False),
    sa.Column("stderr_sha256", sa.String(64), nullable=False),
    sa.Column("detail_code", sa.String(128), nullable=False),
    sa.Column("response_sha256", sa.String(64), nullable=True),
    sa.Column("response_result_sha256", sa.String(64), nullable=True),
    sa.Column("response_result_json", sa.Text(), nullable=True),
    sa.Column("fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("lease_sha256", sa.String(64), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column("pre_control_transition_id", sa.String(36), nullable=False),
    sa.Column("pre_control_transition_sha256", sa.String(64), nullable=False),
    sa.Column("final_control_transition_id", sa.String(36), nullable=False),
    sa.Column("final_control_transition_sha256", sa.String(64), nullable=False),
    sa.Column("critical_alert_incident_id", sa.String(36), nullable=True),
    sa.Column("critical_alert_incident_sha256", sa.String(64), nullable=True),
    sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("invocation_payload", sa.Text(), nullable=False),
    sa.Column("result_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "account_id",
        "invocation_id",
        "invocation_sha256",
        name="uq_phase5_strategy_supervision_exact_invocation",
    ),
    sa.UniqueConstraint(
        "account_id",
        "invocation_id",
        "invocation_sha256",
        "semantic_sha256",
        name="uq_phase5_strategy_supervision_lifecycle_result",
    ),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase5_strategy_supervision_account",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "fencing_generation", "lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase5_strategy_supervision_lease",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "pre_control_transition_id",
            "pre_control_transition_sha256",
        ],
        [
            "phase5_operational_control_transitions.account_id",
            "phase5_operational_control_transitions.transition_id",
            "phase5_operational_control_transitions.semantic_sha256",
        ],
        name="fk_phase5_strategy_supervision_pre_control",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "final_control_transition_id",
            "final_control_transition_sha256",
        ],
        [
            "phase5_operational_control_transitions.account_id",
            "phase5_operational_control_transitions.transition_id",
            "phase5_operational_control_transitions.semantic_sha256",
        ],
        name="fk_phase5_strategy_supervision_final_control",
    ),
    sa.ForeignKeyConstraint(
        ["critical_alert_incident_id"],
        ["phase5_critical_alert_incidents.incident_id"],
        name="fk_phase5_strategy_supervision_critical_alert",
    ),
    sa.CheckConstraint(
        "outcome IN "
        "('completed', 'timeout', 'crash', 'protocol_error', 'resource_exceeded') "
        "AND started_at <= completed_at "
        "AND completed_at <= recorded_at "
        "AND elapsed_microseconds >= 0 "
        "AND stdout_bytes BETWEEN 0 AND 262145 "
        "AND stderr_bytes BETWEEN 0 AND 65537 "
        "AND fencing_generation > 0",
        name="scope",
    ),
    sa.CheckConstraint(
        "process_started OR exit_code IS NULL",
        name="process_shape",
    ),
    sa.CheckConstraint(
        "(outcome = 'completed' "
        "AND process_started AND exit_code = 0 "
        "AND response_sha256 IS NOT NULL "
        "AND response_result_sha256 IS NOT NULL "
        "AND response_result_json IS NOT NULL "
        "AND pre_control_transition_id = final_control_transition_id "
        "AND pre_control_transition_sha256 = final_control_transition_sha256 "
        "AND critical_alert_incident_id IS NULL "
        "AND critical_alert_incident_sha256 IS NULL) "
        "OR (outcome <> 'completed' "
        "AND response_sha256 IS NULL "
        "AND response_result_sha256 IS NULL "
        "AND response_result_json IS NULL "
        "AND critical_alert_incident_id IS NOT NULL "
        "AND critical_alert_incident_sha256 IS NOT NULL)",
        name="outcome_shape",
    ),
    sa.CheckConstraint(
        "length(invocation_id) = 36 "
        "AND length(invocation_sha256) = 64 "
        "AND length(market_batch_sha256) = 64 "
        "AND length(strategy_configuration_sha256) = 64 "
        "AND length(runtime_sha256) = 64 "
        "AND length(stdout_sha256) = 64 "
        "AND length(stderr_sha256) = 64 "
        "AND (response_sha256 IS NULL OR length(response_sha256) = 64) "
        "AND (response_result_sha256 IS NULL "
        "OR length(response_result_sha256) = 64) "
        "AND length(lease_sha256) = 64 "
        "AND length(fence_sha256) = 64 "
        "AND length(pre_control_transition_id) = 36 "
        "AND length(pre_control_transition_sha256) = 64 "
        "AND length(final_control_transition_id) = 36 "
        "AND length(final_control_transition_sha256) = 64 "
        "AND (critical_alert_incident_id IS NULL "
        "OR length(critical_alert_incident_id) = 36) "
        "AND (critical_alert_incident_sha256 IS NULL "
        "OR length(critical_alert_incident_sha256) = 64) "
        "AND length(semantic_sha256) = 64",
        name="hashes",
    ),
    sa.CheckConstraint(
        "length(environment) BETWEEN 1 AND 32 "
        "AND length(market_batch_id) BETWEEN 1 AND 128 "
        "AND length(strategy_id) BETWEEN 1 AND 128 "
        "AND length(strategy_version) BETWEEN 1 AND 64 "
        "AND length(detail_code) BETWEEN 1 AND 128 "
        "AND (response_result_json IS NULL "
        "OR length(response_result_json) BETWEEN 1 AND 262144) "
        "AND length(invocation_payload) BETWEEN 2 AND 1048576 "
        "AND length(result_payload) BETWEEN 2 AND 1048576",
        name="payloads",
    ),
)
sa.Index(
    "ix_phase5_strategy_supervision_account_time",
    phase5_strategy_supervision_results.c.account_id,
    phase5_strategy_supervision_results.c.completed_at,
)

# Phase 5C pre-effect strategy claims. A newly inserted claim is the only
# lifecycle state that authorizes the injected runner to start one child.
# Retained claims are pending until exact result finalization or deterministic
# fail-closed interruption recovery.
phase5_strategy_invocation_claims = sa.Table(
    "phase5_strategy_invocation_claims",
    metadata,
    sa.Column("claim_id", sa.String(36), primary_key=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("invocation_id", sa.String(36), nullable=False, unique=True),
    sa.Column("invocation_sha256", sa.String(64), nullable=False),
    sa.Column("owner_id", sa.String(128), nullable=False),
    sa.Column("lease_id", sa.String(64), nullable=False),
    sa.Column("fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("lease_sha256", sa.String(64), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column("fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("policy_sha256", sa.String(64), nullable=False),
    sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("claim_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("recoverable_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("invocation_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "claim_id",
        "semantic_sha256",
        "account_id",
        "invocation_id",
        "invocation_sha256",
        name="uq_phase5_strategy_invocation_claim_exact",
    ),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase5_strategy_invocation_claim_account",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "fencing_generation", "lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase5_strategy_invocation_claim_lease",
    ),
    sa.CheckConstraint(
        "fencing_generation > 0 "
        "AND claimed_at < recoverable_at "
        "AND recoverable_at < claim_valid_until",
        name="window",
    ),
    sa.CheckConstraint(
        "length(claim_id) = 36 "
        "AND length(invocation_id) = 36 "
        "AND length(account_id) BETWEEN 1 AND 64 "
        "AND length(owner_id) BETWEEN 1 AND 128 "
        "AND length(lease_id) BETWEEN 1 AND 64",
        name="identities",
    ),
    sa.CheckConstraint(
        "length(invocation_sha256) = 64 "
        "AND length(lease_sha256) = 64 "
        "AND length(fence_sha256) = 64 "
        "AND length(fence_receipt_sha256) = 64 "
        "AND length(policy_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="hashes",
    ),
    sa.CheckConstraint(
        "length(invocation_payload) BETWEEN 2 AND 1048576",
        name="payload",
    ),
)
sa.Index(
    "ix_phase5_strategy_invocation_claim_account_time",
    phase5_strategy_invocation_claims.c.account_id,
    phase5_strategy_invocation_claims.c.claimed_at,
)
sa.Index(
    "ix_phase5_strategy_invocation_claim_recovery",
    phase5_strategy_invocation_claims.c.recoverable_at,
    phase5_strategy_invocation_claims.c.claim_id,
)

phase5_strategy_invocation_finalizations = sa.Table(
    "phase5_strategy_invocation_finalizations",
    metadata,
    sa.Column("claim_id", sa.String(36), primary_key=True),
    sa.Column("claim_sha256", sa.String(64), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("invocation_id", sa.String(36), nullable=False, unique=True),
    sa.Column("invocation_sha256", sa.String(64), nullable=False),
    sa.Column("result_record_sha256", sa.String(64), nullable=False),
    sa.Column("finalized_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.ForeignKeyConstraint(
        [
            "claim_id",
            "claim_sha256",
            "account_id",
            "invocation_id",
            "invocation_sha256",
        ],
        [
            "phase5_strategy_invocation_claims.claim_id",
            "phase5_strategy_invocation_claims.semantic_sha256",
            "phase5_strategy_invocation_claims.account_id",
            "phase5_strategy_invocation_claims.invocation_id",
            "phase5_strategy_invocation_claims.invocation_sha256",
        ],
        name="fk_phase5_strategy_invocation_finalization_claim",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "invocation_id",
            "invocation_sha256",
            "result_record_sha256",
        ],
        [
            "phase5_strategy_supervision_results.account_id",
            "phase5_strategy_supervision_results.invocation_id",
            "phase5_strategy_supervision_results.invocation_sha256",
            "phase5_strategy_supervision_results.semantic_sha256",
        ],
        name="fk_phase5_strategy_invocation_finalization_result",
    ),
    sa.CheckConstraint(
        "length(claim_id) = 36 "
        "AND length(invocation_id) = 36 "
        "AND length(account_id) BETWEEN 1 AND 64",
        name="identities",
    ),
    sa.CheckConstraint(
        "length(claim_sha256) = 64 "
        "AND length(invocation_sha256) = 64 "
        "AND length(result_record_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="hashes",
    ),
)
sa.Index(
    "ix_phase5_strategy_invocation_finalization_account_time",
    phase5_strategy_invocation_finalizations.c.account_id,
    phase5_strategy_invocation_finalizations.c.finalized_at,
)


# Phase 4AE persists authenticated one-page account-activity traversal state.
phase4_alpaca_paper_account_activity_plans = sa.Table(
    "phase4_alpaca_paper_account_activity_plans",
    metadata,
    sa.Column("capture_id", sa.String(36), primary_key=True),
    sa.Column(
        "account_id",
        sa.String(64),
        sa.ForeignKey(
            "phase2_account_lease_heads.account_id",
            name="fk_phase4_account_activity_plan_account",
        ),
        nullable=False,
    ),
    sa.Column("capture_idempotency_key", sa.String(128), nullable=False),
    sa.Column("capability_sha256", sa.String(64), nullable=False),
    sa.Column("traversal_profile_sha256", sa.String(64), nullable=False),
    sa.Column("page_size", sa.BigInteger(), nullable=False),
    sa.Column("maximum_pages", sa.BigInteger(), nullable=False),
    sa.Column("maximum_items", sa.BigInteger(), nullable=False),
    sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "account_id",
        "capture_idempotency_key",
        name="uq_phase4_account_activity_plan_account_key",
    ),
    sa.UniqueConstraint(
        "capture_id",
        "account_id",
        "semantic_sha256",
        name="uq_phase4_account_activity_plan_exact",
    ),
    sa.CheckConstraint(
        "length(capture_id) = 36 "
        "AND capture_id = lower(capture_id) "
        "AND substr(capture_id, 9, 1) = '-' "
        "AND substr(capture_id, 14, 1) = '-' "
        "AND substr(capture_id, 19, 1) = '-' "
        "AND substr(capture_id, 24, 1) = '-'",
        name="phase4_account_activity_plan_id_shape",
    ),
    sa.CheckConstraint(
        "length(capture_idempotency_key) BETWEEN 8 AND 128",
        name="phase4_account_activity_plan_key_size",
    ),
    sa.CheckConstraint(
        "page_size BETWEEN 1 AND 100 "
        "AND maximum_pages BETWEEN 1 AND 8 "
        "AND maximum_items BETWEEN 1 AND 800",
        name="phase4_account_activity_plan_bounds",
    ),
    sa.CheckConstraint(
        "length(capability_sha256) = 64 "
        "AND length(traversal_profile_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_account_activity_plan_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 16384",
        name="phase4_account_activity_plan_payload_size",
    ),
)
sa.Index(
    "ix_phase4_account_activity_plan_account_prepared",
    phase4_alpaca_paper_account_activity_plans.c.account_id,
    phase4_alpaca_paper_account_activity_plans.c.prepared_at,
)

phase4_alpaca_paper_account_activity_pages = sa.Table(
    "phase4_alpaca_paper_account_activity_pages",
    metadata,
    sa.Column("receipt_id", sa.String(36), primary_key=True),
    sa.Column("capture_id", sa.String(36), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("page_number", sa.BigInteger(), nullable=False),
    sa.Column("page_size", sa.BigInteger(), nullable=False),
    sa.Column("plan_sha256", sa.String(64), nullable=False),
    sa.Column("previous_page_receipt_sha256", sa.String(64), nullable=True),
    sa.Column("previous_persisted_page_sha256", sa.String(64), nullable=True),
    sa.Column("description_sha256", sa.String(64), nullable=False),
    sa.Column("preparation_sha256", sa.String(64), nullable=False),
    sa.Column("prefix_capture_sha256", sa.String(64), nullable=False),
    sa.Column("prefix_page_count", sa.BigInteger(), nullable=False),
    sa.Column("preparation_previous_page_receipt_id", sa.String(36), nullable=True),
    sa.Column(
        "preparation_previous_page_receipt_sha256",
        sa.String(64),
        nullable=True,
    ),
    sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("provider_id", sa.String(128), nullable=False),
    sa.Column("environment", sa.String(32), nullable=False),
    sa.Column("capability_sha256", sa.String(64), nullable=False),
    sa.Column("expected_provider_account_id", sa.String(36), nullable=False),
    sa.Column("secret_ref", sa.String(256), nullable=False),
    sa.Column("secret_version", sa.String(128), nullable=False),
    sa.Column("credential_reference_sha256", sa.String(64), nullable=False),
    sa.Column("credential_resolution_sha256", sa.String(64), nullable=False),
    sa.Column("resolver_id", sa.String(128), nullable=False),
    sa.Column("resolver_version", sa.String(128), nullable=False),
    sa.Column(
        "credential_resolution_started_at",
        sa.DateTime(timezone=True),
        nullable=False,
    ),
    sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column(
        "credential_resolution_valid_until",
        sa.DateTime(timezone=True),
        nullable=False,
    ),
    sa.Column("account_binding_id", sa.String(36), nullable=False),
    sa.Column("account_binding_sha256", sa.String(64), nullable=False),
    sa.Column("pre_account_identity_sha256", sa.String(64), nullable=False),
    sa.Column("post_account_identity_sha256", sa.String(64), nullable=False),
    sa.Column(
        "pre_account_identity_checked_at",
        sa.DateTime(timezone=True),
        nullable=False,
    ),
    sa.Column(
        "post_account_identity_checked_at",
        sa.DateTime(timezone=True),
        nullable=False,
    ),
    sa.Column("policy_sha256", sa.String(64), nullable=False),
    sa.Column("demand_id", sa.String(64), nullable=False),
    sa.Column("demand_sha256", sa.String(64), nullable=False),
    sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("permit_id", sa.String(64), nullable=False),
    sa.Column("permit_sha256", sa.String(64), nullable=False),
    sa.Column("permit_freshness_sha256", sa.String(64), nullable=False),
    sa.Column("permit_checked_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("fence_owner_id", sa.String(128), nullable=False),
    sa.Column("fence_lease_id", sa.String(64), nullable=False),
    sa.Column("fence_fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column("fence_policy_sha256", sa.String(64), nullable=False),
    sa.Column("pre_fence_lease_sha256", sa.String(64), nullable=False),
    sa.Column("pre_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("pre_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("pre_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("transport_request_sha256", sa.String(64), nullable=False),
    sa.Column("transport_response_sha256", sa.String(64), nullable=False),
    sa.Column("request_started_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("http_status", sa.Integer(), nullable=False),
    sa.Column("provider_request_id", sa.String(256), nullable=False),
    sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("ingress_receipt_id", sa.String(64), nullable=False),
    sa.Column("ingress_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("ingress_sequence", sa.BigInteger(), nullable=False),
    sa.Column("raw_recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("observation_sha256", sa.String(64), nullable=False),
    sa.Column("persisted_page_sha256", sa.String(64), nullable=False),
    sa.Column("page_token", sa.String(256), nullable=True),
    sa.Column("next_page_token", sa.String(256), nullable=True),
    sa.Column("activity_count", sa.BigInteger(), nullable=False),
    sa.Column("terminal_page", sa.Boolean(), nullable=False),
    sa.Column("bounded_truncation", sa.Boolean(), nullable=False),
    sa.Column("post_fence_lease_sha256", sa.String(64), nullable=False),
    sa.Column("post_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("post_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("post_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("authenticated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("evidence_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("commit_fence_lease_sha256", sa.String(64), nullable=False),
    sa.Column("commit_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("commit_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("commit_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "capture_id",
        "page_number",
        name="uq_phase4_account_activity_page_number",
    ),
    sa.UniqueConstraint(
        "permit_id",
        name="uq_phase4_alpaca_paper_account_activity_pages_permit_id",
    ),
    sa.UniqueConstraint(
        "ingress_receipt_id",
        name="uq_phase4_alpaca_paper_account_activity_pages_ingress_receipt",
    ),
    sa.UniqueConstraint(
        "capture_id",
        "semantic_sha256",
        name="uq_phase4_account_activity_page_predecessor",
    ),
    sa.UniqueConstraint(
        "capture_id",
        "page_number",
        "receipt_id",
        "semantic_sha256",
        "persisted_page_sha256",
        name="uq_phase4_account_activity_page_exact",
    ),
    sa.ForeignKeyConstraint(
        ["capture_id", "account_id", "plan_sha256"],
        [
            "phase4_alpaca_paper_account_activity_plans.capture_id",
            "phase4_alpaca_paper_account_activity_plans.account_id",
            "phase4_alpaca_paper_account_activity_plans.semantic_sha256",
        ],
        name="fk_phase4_account_activity_page_plan",
    ),
    sa.ForeignKeyConstraint(
        ["capture_id", "previous_page_receipt_sha256"],
        [
            "phase4_alpaca_paper_account_activity_pages.capture_id",
            "phase4_alpaca_paper_account_activity_pages.semantic_sha256",
        ],
        name="fk_phase4_account_activity_page_predecessor",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "account_binding_id",
            "account_binding_sha256",
            "expected_provider_account_id",
        ],
        [
            "phase4_alpaca_paper_account_bindings.account_id",
            "phase4_alpaca_paper_account_bindings.binding_id",
            "phase4_alpaca_paper_account_bindings.semantic_sha256",
            "phase4_alpaca_paper_account_bindings.expected_provider_account_id",
        ],
        name="fk_phase4_account_activity_page_account_binding",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "permit_id",
            "permit_sha256",
            "demand_id",
            "demand_sha256",
            "policy_sha256",
        ],
        [
            "phase4_broker_request_permits.account_id",
            "phase4_broker_request_permits.permit_id",
            "phase4_broker_request_permits.semantic_sha256",
            "phase4_broker_request_permits.demand_id",
            "phase4_broker_request_permits.demand_sha256",
            "phase4_broker_request_permits.policy_sha256",
        ],
        name="fk_phase4_account_activity_page_permit",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "ingress_receipt_id", "ingress_receipt_sha256"],
        [
            "phase4_broker_ingress_receipts.account_id",
            "phase4_broker_ingress_receipts.receipt_id",
            "phase4_broker_ingress_receipts.semantic_sha256",
        ],
        name="fk_phase4_account_activity_page_ingress",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "fence_fencing_generation", "pre_fence_lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase4_account_activity_page_pre_lease",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "fence_fencing_generation", "post_fence_lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase4_account_activity_page_post_lease",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "fence_fencing_generation", "commit_fence_lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase4_account_activity_page_commit_lease",
    ),
    sa.CheckConstraint(
        "(page_number = 1 "
        "AND previous_page_receipt_sha256 IS NULL "
        "AND previous_persisted_page_sha256 IS NULL "
        "AND page_token IS NULL "
        "AND prefix_page_count = 0 "
        "AND preparation_previous_page_receipt_id IS NULL "
        "AND preparation_previous_page_receipt_sha256 IS NULL) "
        "OR (page_number > 1 "
        "AND previous_page_receipt_sha256 IS NOT NULL "
        "AND previous_persisted_page_sha256 IS NOT NULL "
        "AND page_token IS NOT NULL "
        "AND prefix_page_count = page_number - 1 "
        "AND preparation_previous_page_receipt_id IS NOT NULL "
        "AND preparation_previous_page_receipt_sha256 = previous_page_receipt_sha256)",
        name="phase4_account_activity_page_predecessor_shape",
    ),
    sa.CheckConstraint(
        "provider_id = 'alpaca-paper' AND environment = 'paper'",
        name="phase4_account_activity_page_provider_scope",
    ),
    sa.CheckConstraint(
        "page_number BETWEEN 1 AND 8 "
        "AND page_size BETWEEN 1 AND 100 "
        "AND activity_count BETWEEN 0 AND page_size "
        "AND prefix_page_count = page_number - 1 "
        "AND ingress_sequence > 0 "
        "AND fence_fencing_generation > 0",
        name="phase4_account_activity_page_positive_counts",
    ),
    sa.CheckConstraint(
        "http_status = 200",
        name="phase4_account_activity_page_http_status",
    ),
    sa.CheckConstraint(
        "(terminal_page AND next_page_token IS NULL AND NOT bounded_truncation) "
        "OR (NOT terminal_page AND next_page_token IS NOT NULL)",
        name="phase4_account_activity_page_cursor_shape",
    ),
    sa.CheckConstraint(
        "prepared_at <= requested_at "
        "AND requested_at <= credential_resolution_started_at "
        "AND credential_resolution_started_at <= resolved_at "
        "AND resolved_at <= pre_fence_validated_at "
        "AND pre_fence_validated_at <= permit_checked_at "
        "AND permit_checked_at <= pre_account_identity_checked_at "
        "AND pre_account_identity_checked_at <= request_started_at "
        "AND request_started_at <= received_at "
        "AND received_at <= raw_recorded_at "
        "AND raw_recorded_at <= post_fence_validated_at "
        "AND post_fence_validated_at <= post_account_identity_checked_at "
        "AND post_account_identity_checked_at <= authenticated_at "
        "AND authenticated_at <= commit_fence_validated_at",
        name="phase4_account_activity_page_time_order",
    ),
    sa.CheckConstraint(
        "resolved_at < credential_resolution_valid_until "
        "AND request_started_at < credential_resolution_valid_until "
        "AND received_at < credential_resolution_valid_until "
        "AND pre_fence_validated_at < pre_fence_valid_until "
        "AND received_at < pre_fence_valid_until "
        "AND post_fence_validated_at < post_fence_valid_until "
        "AND commit_fence_validated_at < commit_fence_valid_until",
        name="phase4_account_activity_page_validity_windows",
    ),
    sa.CheckConstraint(
        "length(receipt_id) = 36 "
        "AND length(capture_id) = 36 "
        "AND length(expected_provider_account_id) = 36 "
        "AND length(account_binding_id) = 36 "
        "AND (page_token IS NULL OR length(page_token) BETWEEN 1 AND 256) "
        "AND (next_page_token IS NULL "
        "OR length(next_page_token) BETWEEN 1 AND 256) "
        "AND (preparation_previous_page_receipt_id IS NULL "
        "OR length(preparation_previous_page_receipt_id) = 36)",
        name="phase4_account_activity_page_id_lengths",
    ),
    sa.CheckConstraint(
        "length(plan_sha256) = 64 "
        "AND (previous_page_receipt_sha256 IS NULL "
        "OR length(previous_page_receipt_sha256) = 64) "
        "AND (previous_persisted_page_sha256 IS NULL "
        "OR length(previous_persisted_page_sha256) = 64) "
        "AND length(description_sha256) = 64 "
        "AND length(preparation_sha256) = 64 "
        "AND length(prefix_capture_sha256) = 64 "
        "AND (preparation_previous_page_receipt_sha256 IS NULL "
        "OR length(preparation_previous_page_receipt_sha256) = 64) "
        "AND length(capability_sha256) = 64 "
        "AND length(credential_reference_sha256) = 64 "
        "AND length(credential_resolution_sha256) = 64 "
        "AND length(account_binding_sha256) = 64 "
        "AND length(pre_account_identity_sha256) = 64 "
        "AND length(post_account_identity_sha256) = 64 "
        "AND length(policy_sha256) = 64 "
        "AND length(demand_id) = 64 "
        "AND length(demand_sha256) = 64 "
        "AND length(permit_id) = 64 "
        "AND length(permit_sha256) = 64 "
        "AND length(permit_freshness_sha256) = 64 "
        "AND length(fence_sha256) = 64 "
        "AND length(fence_policy_sha256) = 64 "
        "AND length(pre_fence_lease_sha256) = 64 "
        "AND length(pre_fence_receipt_sha256) = 64 "
        "AND length(transport_request_sha256) = 64 "
        "AND length(transport_response_sha256) = 64 "
        "AND length(ingress_receipt_id) = 64 "
        "AND length(ingress_receipt_sha256) = 64 "
        "AND length(observation_sha256) = 64 "
        "AND length(persisted_page_sha256) = 64 "
        "AND length(post_fence_lease_sha256) = 64 "
        "AND length(post_fence_receipt_sha256) = 64 "
        "AND length(evidence_sha256) = 64 "
        "AND length(commit_fence_lease_sha256) = 64 "
        "AND length(commit_fence_receipt_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_account_activity_page_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 131072",
        name="phase4_account_activity_page_payload_size",
    ),
)
sa.Index(
    "ix_phase4_account_activity_page_account_authenticated",
    phase4_alpaca_paper_account_activity_pages.c.account_id,
    phase4_alpaca_paper_account_activity_pages.c.authenticated_at,
)
sa.Index(
    "ix_phase4_account_activity_page_ingress_sequence",
    phase4_alpaca_paper_account_activity_pages.c.account_id,
    phase4_alpaca_paper_account_activity_pages.c.ingress_sequence,
)
sa.Index(
    "uq_phase4_account_activity_page_preparation",
    phase4_alpaca_paper_account_activity_pages.c.preparation_sha256,
    unique=True,
)

# Phase 4AA normalizes every Phase 4O single-use page preparation into an
# immutable fact.  Existing committed pages and the sole stalled head retain
# every source field needed to backfill these rows without inventing evidence.
# The mutable head remains a cache/pointer; loaders authenticate it against the
# fact and completed pages retain the fact after the head advances.
phase4_alpaca_paper_account_activity_preparations = sa.Table(
    "phase4_alpaca_paper_account_activity_preparations",
    metadata,
    sa.Column("preparation_sha256", sa.String(64), primary_key=True),
    sa.Column("capture_id", sa.String(36), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("page_number", sa.BigInteger(), nullable=False),
    sa.Column("page_size", sa.BigInteger(), nullable=False),
    sa.Column("plan_sha256", sa.String(64), nullable=False),
    sa.Column("page_token", sa.String(256), nullable=True),
    sa.Column("description_sha256", sa.String(64), nullable=False),
    sa.Column("prefix_capture_sha256", sa.String(64), nullable=False),
    sa.Column("prefix_page_count", sa.BigInteger(), nullable=False),
    sa.Column("previous_page_receipt_id", sa.String(36), nullable=True),
    sa.Column("previous_page_receipt_sha256", sa.String(64), nullable=True),
    sa.Column("previous_persisted_page_sha256", sa.String(64), nullable=True),
    sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=False),
    sa.UniqueConstraint(
        "capture_id",
        "page_number",
        name="uq_phase4_account_activity_preparation_page",
    ),
    sa.UniqueConstraint(
        "preparation_sha256",
        "capture_id",
        "account_id",
        "page_number",
        "plan_sha256",
        "description_sha256",
        "prefix_capture_sha256",
        "prefix_page_count",
        "prepared_at",
        name="uq_phase4_account_activity_preparation_exact",
    ),
    sa.ForeignKeyConstraint(
        ["capture_id", "account_id", "plan_sha256"],
        [
            "phase4_alpaca_paper_account_activity_plans.capture_id",
            "phase4_alpaca_paper_account_activity_plans.account_id",
            "phase4_alpaca_paper_account_activity_plans.semantic_sha256",
        ],
        name="fk_phase4_account_activity_preparation_plan",
    ),
    sa.ForeignKeyConstraint(
        [
            "capture_id",
            "prefix_page_count",
            "previous_page_receipt_id",
            "previous_page_receipt_sha256",
            "previous_persisted_page_sha256",
        ],
        [
            "phase4_alpaca_paper_account_activity_pages.capture_id",
            "phase4_alpaca_paper_account_activity_pages.page_number",
            "phase4_alpaca_paper_account_activity_pages.receipt_id",
            "phase4_alpaca_paper_account_activity_pages.semantic_sha256",
            "phase4_alpaca_paper_account_activity_pages.persisted_page_sha256",
        ],
        name="fk_phase4_account_activity_preparation_predecessor",
    ),
    sa.CheckConstraint(
        "(page_number = 1 "
        "AND page_token IS NULL "
        "AND prefix_page_count = 0 "
        "AND previous_page_receipt_id IS NULL "
        "AND previous_page_receipt_sha256 IS NULL "
        "AND previous_persisted_page_sha256 IS NULL) "
        "OR (page_number > 1 "
        "AND page_token IS NOT NULL "
        "AND prefix_page_count = page_number - 1 "
        "AND previous_page_receipt_id IS NOT NULL "
        "AND previous_page_receipt_sha256 IS NOT NULL "
        "AND previous_persisted_page_sha256 IS NOT NULL)",
        name="phase4_account_activity_preparation_predecessor_shape",
    ),
    sa.CheckConstraint(
        "page_number BETWEEN 1 AND 8 AND page_size BETWEEN 1 AND 100",
        name="phase4_account_activity_preparation_page_bounds",
    ),
    sa.CheckConstraint(
        "length(preparation_sha256) = 64 "
        "AND length(capture_id) = 36 "
        "AND (page_token IS NULL OR length(page_token) BETWEEN 1 AND 256) "
        "AND (previous_page_receipt_id IS NULL "
        "OR length(previous_page_receipt_id) = 36) "
        "AND length(plan_sha256) = 64 "
        "AND length(description_sha256) = 64 "
        "AND length(prefix_capture_sha256) = 64 "
        "AND (previous_page_receipt_sha256 IS NULL "
        "OR length(previous_page_receipt_sha256) = 64) "
        "AND (previous_persisted_page_sha256 IS NULL "
        "OR length(previous_persisted_page_sha256) = 64)",
        name="phase4_account_activity_preparation_identity_lengths",
    ),
)
sa.Index(
    "ix_phase4_account_activity_preparation_account_time",
    phase4_alpaca_paper_account_activity_preparations.c.account_id,
    phase4_alpaca_paper_account_activity_preparations.c.prepared_at,
)

phase4_alpaca_paper_account_activity_heads = sa.Table(
    "phase4_alpaca_paper_account_activity_heads",
    metadata,
    sa.Column("capture_id", sa.String(36), primary_key=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("plan_sha256", sa.String(64), nullable=False),
    sa.Column("committed_page_count", sa.BigInteger(), nullable=False),
    sa.Column("committed_activity_count", sa.BigInteger(), nullable=False),
    sa.Column("last_page_receipt_id", sa.String(36), nullable=True),
    sa.Column("last_page_receipt_sha256", sa.String(64), nullable=True),
    sa.Column("last_persisted_page_sha256", sa.String(64), nullable=True),
    sa.Column("next_page_number", sa.BigInteger(), nullable=True),
    sa.Column("next_page_size", sa.BigInteger(), nullable=True),
    sa.Column("next_page_token", sa.String(256), nullable=True),
    sa.Column("next_previous_page_sha256", sa.String(64), nullable=True),
    sa.Column("prepared_description_sha256", sa.String(64), nullable=True),
    sa.Column("prepared_prefix_capture_sha256", sa.String(64), nullable=True),
    sa.Column("prepared_prefix_page_count", sa.BigInteger(), nullable=True),
    sa.Column("prepared_previous_page_receipt_id", sa.String(36), nullable=True),
    sa.Column("prepared_previous_page_receipt_sha256", sa.String(64), nullable=True),
    sa.Column("preparation_sha256", sa.String(64), nullable=True),
    sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=True),
    sa.Column("state", sa.String(32), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False),
    sa.UniqueConstraint(
        "capture_id",
        "account_id",
        "semantic_sha256",
        name="uq_phase4_account_activity_head_exact",
    ),
    sa.ForeignKeyConstraint(
        ["capture_id", "account_id", "plan_sha256"],
        [
            "phase4_alpaca_paper_account_activity_plans.capture_id",
            "phase4_alpaca_paper_account_activity_plans.account_id",
            "phase4_alpaca_paper_account_activity_plans.semantic_sha256",
        ],
        name="fk_phase4_account_activity_head_plan",
    ),
    sa.ForeignKeyConstraint(
        [
            "capture_id",
            "committed_page_count",
            "last_page_receipt_id",
            "last_page_receipt_sha256",
            "last_persisted_page_sha256",
        ],
        [
            "phase4_alpaca_paper_account_activity_pages.capture_id",
            "phase4_alpaca_paper_account_activity_pages.page_number",
            "phase4_alpaca_paper_account_activity_pages.receipt_id",
            "phase4_alpaca_paper_account_activity_pages.semantic_sha256",
            "phase4_alpaca_paper_account_activity_pages.persisted_page_sha256",
        ],
        name="fk_phase4_account_activity_head_terminal_page",
    ),
    sa.CheckConstraint(
        "(committed_page_count = 0 "
        "AND last_page_receipt_id IS NULL "
        "AND last_page_receipt_sha256 IS NULL "
        "AND last_persisted_page_sha256 IS NULL) "
        "OR (committed_page_count > 0 "
        "AND last_page_receipt_id IS NOT NULL "
        "AND last_page_receipt_sha256 IS NOT NULL "
        "AND last_persisted_page_sha256 IS NOT NULL)",
        name="phase4_account_activity_head_tip_shape",
    ),
    sa.CheckConstraint(
        "state IN ('active', 'cursor_exhausted_unisolated', 'bounded_truncated', 'stalled')",
        name="phase4_account_activity_head_state",
    ),
    sa.CheckConstraint(
        "(state IN ('active', 'stalled') "
        "AND next_page_number = committed_page_count + 1 "
        "AND next_page_number BETWEEN 1 AND 8 "
        "AND next_page_size BETWEEN 1 AND 100 "
        "AND ((next_page_number = 1 "
        "AND next_page_token IS NULL "
        "AND next_previous_page_sha256 IS NULL) "
        "OR (next_page_number > 1 "
        "AND next_page_token IS NOT NULL "
        "AND next_previous_page_sha256 = last_persisted_page_sha256))) "
        "OR (state IN ('cursor_exhausted_unisolated', 'bounded_truncated') "
        "AND next_page_number IS NULL "
        "AND next_page_size IS NULL "
        "AND next_page_token IS NULL "
        "AND next_previous_page_sha256 IS NULL)",
        name="phase4_account_activity_head_next_shape",
    ),
    sa.CheckConstraint(
        "(state <> 'stalled' "
        "AND prepared_description_sha256 IS NULL "
        "AND prepared_prefix_capture_sha256 IS NULL "
        "AND prepared_prefix_page_count IS NULL "
        "AND prepared_previous_page_receipt_id IS NULL "
        "AND prepared_previous_page_receipt_sha256 IS NULL "
        "AND preparation_sha256 IS NULL "
        "AND prepared_at IS NULL) "
        "OR (state = 'stalled' "
        "AND prepared_description_sha256 IS NOT NULL "
        "AND prepared_prefix_capture_sha256 IS NOT NULL "
        "AND prepared_prefix_page_count = committed_page_count "
        "AND preparation_sha256 IS NOT NULL "
        "AND prepared_at IS NOT NULL "
        "AND ((committed_page_count = 0 "
        "AND prepared_previous_page_receipt_id IS NULL "
        "AND prepared_previous_page_receipt_sha256 IS NULL) "
        "OR (committed_page_count > 0 "
        "AND prepared_previous_page_receipt_id = last_page_receipt_id "
        "AND prepared_previous_page_receipt_sha256 = last_page_receipt_sha256)))",
        name="phase4_account_activity_head_preparation_shape",
    ),
    sa.CheckConstraint(
        "committed_page_count BETWEEN 0 AND 8 AND committed_activity_count BETWEEN 0 AND 800",
        name="phase4_account_activity_head_page_bound",
    ),
    sa.CheckConstraint(
        "length(plan_sha256) = 64 "
        "AND (last_page_receipt_sha256 IS NULL "
        "OR length(last_page_receipt_sha256) = 64) "
        "AND (last_persisted_page_sha256 IS NULL "
        "OR length(last_persisted_page_sha256) = 64) "
        "AND (next_previous_page_sha256 IS NULL "
        "OR length(next_previous_page_sha256) = 64) "
        "AND (prepared_description_sha256 IS NULL "
        "OR length(prepared_description_sha256) = 64) "
        "AND (prepared_prefix_capture_sha256 IS NULL "
        "OR length(prepared_prefix_capture_sha256) = 64) "
        "AND (prepared_previous_page_receipt_sha256 IS NULL "
        "OR length(prepared_previous_page_receipt_sha256) = 64) "
        "AND (preparation_sha256 IS NULL OR length(preparation_sha256) = 64) "
        "AND length(semantic_sha256) = 64",
        name="phase4_account_activity_head_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 16384",
        name="phase4_account_activity_head_payload_size",
    ),
)
sa.Index(
    "ix_phase4_account_activity_head_account_state",
    phase4_alpaca_paper_account_activity_heads.c.account_id,
    phase4_alpaca_paper_account_activity_heads.c.state,
    phase4_alpaca_paper_account_activity_heads.c.updated_at,
)
sa.Index(
    "uq_phase4_account_activity_head_preparation",
    phase4_alpaca_paper_account_activity_heads.c.preparation_sha256,
    unique=True,
)

# Phase 4AH persists one immutable Phase 4AG comparison for each exact ordered
# pair of complete Phase 4AE account-activity traversals.  Both source plans,
# terminal heads, first/tip page receipts, and raw ingress receipts remain
# reachable from SQL; loaders reconstruct every page and recompute Phase 4AF
# before accepting either a receipt or its account-local chain head.
phase4_alpaca_paper_account_activity_comparisons = sa.Table(
    "phase4_alpaca_paper_account_activity_comparisons",
    metadata,
    sa.Column("receipt_id", sa.String(36), primary_key=True),
    sa.Column("evidence_id", sa.String(36), nullable=False),
    sa.Column("comparison_id", sa.String(36), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("provider_account_id", sa.String(36), nullable=False),
    sa.Column("account_sequence", sa.BigInteger(), nullable=False),
    sa.Column("previous_receipt_sha256", sa.String(64), nullable=True),
    sa.Column("fence_owner_id", sa.String(128), nullable=False),
    sa.Column("fence_lease_id", sa.String(64), nullable=False),
    sa.Column("fence_fencing_generation", sa.BigInteger(), nullable=False),
    sa.Column("fence_sha256", sa.String(64), nullable=False),
    sa.Column("fence_policy_sha256", sa.String(64), nullable=False),
    sa.Column("commit_fence_lease_sha256", sa.String(64), nullable=False),
    sa.Column("commit_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("commit_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("commit_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("authentication_policy_sha256", sa.String(64), nullable=False),
    sa.Column("comparison_policy_sha256", sa.String(64), nullable=False),
    sa.Column("traversal_profile_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_capture_id", sa.String(36), nullable=False),
    sa.Column("earlier_plan_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_head_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_state_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_prefix_id", sa.String(36), nullable=False),
    sa.Column("earlier_prefix_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_capture_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_page_count", sa.BigInteger(), nullable=False),
    sa.Column("earlier_activity_count", sa.BigInteger(), nullable=False),
    sa.Column("earlier_first_page_number", sa.BigInteger(), nullable=False),
    sa.Column("earlier_first_receipt_id", sa.String(36), nullable=False),
    sa.Column("earlier_first_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_first_persisted_page_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_first_ingress_receipt_id", sa.String(64), nullable=False),
    sa.Column("earlier_first_ingress_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_first_ingress_sequence", sa.BigInteger(), nullable=False),
    sa.Column("earlier_tip_receipt_id", sa.String(36), nullable=False),
    sa.Column("earlier_tip_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_tip_persisted_page_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_tip_ingress_receipt_id", sa.String(64), nullable=False),
    sa.Column("earlier_tip_ingress_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("earlier_tip_ingress_sequence", sa.BigInteger(), nullable=False),
    sa.Column("earlier_source_committed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("earlier_window_started_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("earlier_window_ended_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("earlier_view_sha256", sa.String(64), nullable=False),
    sa.Column("later_capture_id", sa.String(36), nullable=False),
    sa.Column("later_plan_sha256", sa.String(64), nullable=False),
    sa.Column("later_head_sha256", sa.String(64), nullable=False),
    sa.Column("later_state_sha256", sa.String(64), nullable=False),
    sa.Column("later_prefix_id", sa.String(36), nullable=False),
    sa.Column("later_prefix_sha256", sa.String(64), nullable=False),
    sa.Column("later_capture_sha256", sa.String(64), nullable=False),
    sa.Column("later_page_count", sa.BigInteger(), nullable=False),
    sa.Column("later_activity_count", sa.BigInteger(), nullable=False),
    sa.Column("later_first_page_number", sa.BigInteger(), nullable=False),
    sa.Column("later_first_receipt_id", sa.String(36), nullable=False),
    sa.Column("later_first_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("later_first_persisted_page_sha256", sa.String(64), nullable=False),
    sa.Column("later_first_ingress_receipt_id", sa.String(64), nullable=False),
    sa.Column("later_first_ingress_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("later_first_ingress_sequence", sa.BigInteger(), nullable=False),
    sa.Column("later_tip_receipt_id", sa.String(36), nullable=False),
    sa.Column("later_tip_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("later_tip_persisted_page_sha256", sa.String(64), nullable=False),
    sa.Column("later_tip_ingress_receipt_id", sa.String(64), nullable=False),
    sa.Column("later_tip_ingress_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("later_tip_ingress_sequence", sa.BigInteger(), nullable=False),
    sa.Column("later_source_committed_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("later_window_started_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("later_window_ended_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("later_view_sha256", sa.String(64), nullable=False),
    sa.Column("observed_utc_separation_microseconds", sa.String(32), nullable=False),
    sa.Column("disposition", sa.String(64), nullable=False),
    sa.Column("added_provider_activity_ids_payload", sa.Text(), nullable=False),
    sa.Column("removed_provider_activity_ids_payload", sa.Text(), nullable=False),
    sa.Column("changed_provider_activity_ids_payload", sa.Text(), nullable=False),
    sa.Column("added_count", sa.BigInteger(), nullable=False),
    sa.Column("removed_count", sa.BigInteger(), nullable=False),
    sa.Column("changed_count", sa.BigInteger(), nullable=False),
    sa.Column("comparison_sha256", sa.String(64), nullable=False),
    sa.Column("evidence_sha256", sa.String(64), nullable=False),
    sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False),
    sa.UniqueConstraint(
        "evidence_id",
        name="uq_phase4_activity_cmp_evidence",
    ),
    sa.UniqueConstraint(
        "comparison_id",
        name="uq_phase4_activity_cmp_comparison",
    ),
    sa.UniqueConstraint(
        "evidence_sha256",
        name="uq_phase4_activity_cmp_evidence_sha",
    ),
    sa.UniqueConstraint(
        "semantic_sha256",
        name="uq_phase4_activity_cmp_semantic",
    ),
    sa.UniqueConstraint(
        "account_id",
        "account_sequence",
        name="uq_phase4_activity_cmp_account_sequence",
    ),
    sa.UniqueConstraint(
        "account_id",
        "semantic_sha256",
        name="uq_phase4_activity_cmp_account_semantic",
    ),
    sa.UniqueConstraint(
        "account_id",
        "account_sequence",
        "receipt_id",
        "semantic_sha256",
        "recorded_at",
        name="uq_phase4_activity_cmp_exact",
    ),
    sa.UniqueConstraint(
        "earlier_capture_id",
        "later_capture_id",
        "authentication_policy_sha256",
        name="uq_phase4_activity_cmp_source_pair",
    ),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase4_activity_cmp_account",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "fence_fencing_generation",
            "commit_fence_lease_sha256",
        ],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase4_activity_cmp_commit_lease",
    ),
    sa.ForeignKeyConstraint(
        ["earlier_capture_id", "account_id", "earlier_plan_sha256"],
        [
            "phase4_alpaca_paper_account_activity_plans.capture_id",
            "phase4_alpaca_paper_account_activity_plans.account_id",
            "phase4_alpaca_paper_account_activity_plans.semantic_sha256",
        ],
        name="fk_phase4_activity_cmp_earlier_plan",
    ),
    sa.ForeignKeyConstraint(
        ["later_capture_id", "account_id", "later_plan_sha256"],
        [
            "phase4_alpaca_paper_account_activity_plans.capture_id",
            "phase4_alpaca_paper_account_activity_plans.account_id",
            "phase4_alpaca_paper_account_activity_plans.semantic_sha256",
        ],
        name="fk_phase4_activity_cmp_later_plan",
    ),
    sa.ForeignKeyConstraint(
        ["earlier_capture_id", "account_id", "earlier_head_sha256"],
        [
            "phase4_alpaca_paper_account_activity_heads.capture_id",
            "phase4_alpaca_paper_account_activity_heads.account_id",
            "phase4_alpaca_paper_account_activity_heads.semantic_sha256",
        ],
        name="fk_phase4_activity_cmp_earlier_head",
    ),
    sa.ForeignKeyConstraint(
        ["later_capture_id", "account_id", "later_head_sha256"],
        [
            "phase4_alpaca_paper_account_activity_heads.capture_id",
            "phase4_alpaca_paper_account_activity_heads.account_id",
            "phase4_alpaca_paper_account_activity_heads.semantic_sha256",
        ],
        name="fk_phase4_activity_cmp_later_head",
    ),
    sa.ForeignKeyConstraint(
        [
            "earlier_capture_id",
            "earlier_first_page_number",
            "earlier_first_receipt_id",
            "earlier_first_receipt_sha256",
            "earlier_first_persisted_page_sha256",
        ],
        [
            "phase4_alpaca_paper_account_activity_pages.capture_id",
            "phase4_alpaca_paper_account_activity_pages.page_number",
            "phase4_alpaca_paper_account_activity_pages.receipt_id",
            "phase4_alpaca_paper_account_activity_pages.semantic_sha256",
            "phase4_alpaca_paper_account_activity_pages.persisted_page_sha256",
        ],
        name="fk_phase4_activity_cmp_earlier_first",
    ),
    sa.ForeignKeyConstraint(
        [
            "later_capture_id",
            "later_first_page_number",
            "later_first_receipt_id",
            "later_first_receipt_sha256",
            "later_first_persisted_page_sha256",
        ],
        [
            "phase4_alpaca_paper_account_activity_pages.capture_id",
            "phase4_alpaca_paper_account_activity_pages.page_number",
            "phase4_alpaca_paper_account_activity_pages.receipt_id",
            "phase4_alpaca_paper_account_activity_pages.semantic_sha256",
            "phase4_alpaca_paper_account_activity_pages.persisted_page_sha256",
        ],
        name="fk_phase4_activity_cmp_later_first",
    ),
    sa.ForeignKeyConstraint(
        [
            "earlier_capture_id",
            "earlier_page_count",
            "earlier_tip_receipt_id",
            "earlier_tip_receipt_sha256",
            "earlier_tip_persisted_page_sha256",
        ],
        [
            "phase4_alpaca_paper_account_activity_pages.capture_id",
            "phase4_alpaca_paper_account_activity_pages.page_number",
            "phase4_alpaca_paper_account_activity_pages.receipt_id",
            "phase4_alpaca_paper_account_activity_pages.semantic_sha256",
            "phase4_alpaca_paper_account_activity_pages.persisted_page_sha256",
        ],
        name="fk_phase4_activity_cmp_earlier_tip",
    ),
    sa.ForeignKeyConstraint(
        [
            "later_capture_id",
            "later_page_count",
            "later_tip_receipt_id",
            "later_tip_receipt_sha256",
            "later_tip_persisted_page_sha256",
        ],
        [
            "phase4_alpaca_paper_account_activity_pages.capture_id",
            "phase4_alpaca_paper_account_activity_pages.page_number",
            "phase4_alpaca_paper_account_activity_pages.receipt_id",
            "phase4_alpaca_paper_account_activity_pages.semantic_sha256",
            "phase4_alpaca_paper_account_activity_pages.persisted_page_sha256",
        ],
        name="fk_phase4_activity_cmp_later_tip",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "earlier_first_ingress_receipt_id",
            "earlier_first_ingress_receipt_sha256",
        ],
        [
            "phase4_broker_ingress_receipts.account_id",
            "phase4_broker_ingress_receipts.receipt_id",
            "phase4_broker_ingress_receipts.semantic_sha256",
        ],
        name="fk_phase4_activity_cmp_earlier_first_ingress",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "earlier_tip_ingress_receipt_id",
            "earlier_tip_ingress_receipt_sha256",
        ],
        [
            "phase4_broker_ingress_receipts.account_id",
            "phase4_broker_ingress_receipts.receipt_id",
            "phase4_broker_ingress_receipts.semantic_sha256",
        ],
        name="fk_phase4_activity_cmp_earlier_tip_ingress",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "later_first_ingress_receipt_id",
            "later_first_ingress_receipt_sha256",
        ],
        [
            "phase4_broker_ingress_receipts.account_id",
            "phase4_broker_ingress_receipts.receipt_id",
            "phase4_broker_ingress_receipts.semantic_sha256",
        ],
        name="fk_phase4_activity_cmp_later_first_ingress",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "later_tip_ingress_receipt_id",
            "later_tip_ingress_receipt_sha256",
        ],
        [
            "phase4_broker_ingress_receipts.account_id",
            "phase4_broker_ingress_receipts.receipt_id",
            "phase4_broker_ingress_receipts.semantic_sha256",
        ],
        name="fk_phase4_activity_cmp_later_tip_ingress",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "previous_receipt_sha256"],
        [
            "phase4_alpaca_paper_account_activity_comparisons.account_id",
            "phase4_alpaca_paper_account_activity_comparisons.semantic_sha256",
        ],
        name="fk_phase4_activity_cmp_predecessor",
    ),
    sa.CheckConstraint(
        "(account_sequence = 1 AND previous_receipt_sha256 IS NULL) "
        "OR (account_sequence > 1 AND previous_receipt_sha256 IS NOT NULL)",
        name="phase4_activity_cmp_predecessor_shape",
    ),
    sa.CheckConstraint(
        "fence_fencing_generation > 0 "
        "AND commit_fence_validated_at = recorded_at "
        "AND commit_fence_validated_at < commit_fence_valid_until",
        name="phase4_activity_cmp_commit_fence",
    ),
    sa.CheckConstraint(
        "earlier_capture_id <> later_capture_id "
        "AND earlier_prefix_id <> later_prefix_id "
        "AND earlier_first_receipt_id <> later_first_receipt_id "
        "AND earlier_tip_receipt_id <> later_tip_receipt_id",
        name="phase4_activity_cmp_distinct_sources",
    ),
    sa.CheckConstraint(
        "earlier_first_page_number = 1 "
        "AND later_first_page_number = 1 "
        "AND earlier_page_count BETWEEN 1 AND 8 "
        "AND later_page_count BETWEEN 1 AND 8 "
        "AND earlier_activity_count BETWEEN 0 AND 800 "
        "AND later_activity_count BETWEEN 0 AND 800 "
        "AND earlier_first_ingress_sequence > 0 "
        "AND earlier_first_ingress_sequence <= earlier_tip_ingress_sequence "
        "AND earlier_tip_ingress_sequence < later_first_ingress_sequence "
        "AND later_first_ingress_sequence <= later_tip_ingress_sequence",
        name="phase4_activity_cmp_source_bounds",
    ),
    sa.CheckConstraint(
        "earlier_window_started_at <= earlier_window_ended_at "
        "AND later_window_started_at <= later_window_ended_at "
        "AND recorded_at >= earlier_source_committed_at "
        "AND recorded_at >= later_source_committed_at",
        name="phase4_activity_cmp_time_bounds",
    ),
    sa.CheckConstraint(
        "disposition IN ("
        "'exact_activity_view_match_unqualified', "
        "'activity_view_different', "
        "'waiting_minimum_separation', "
        "'bounded_traversal_incomplete')",
        name="phase4_activity_cmp_disposition",
    ),
    sa.CheckConstraint(
        "added_count BETWEEN 0 AND 800 "
        "AND removed_count BETWEEN 0 AND 800 "
        "AND changed_count BETWEEN 0 AND 800",
        name="phase4_activity_cmp_difference_bounds",
    ),
    sa.CheckConstraint(
        "length(receipt_id) = 36 "
        "AND length(evidence_id) = 36 "
        "AND length(comparison_id) = 36 "
        "AND length(provider_account_id) = 36 "
        "AND provider_account_id = lower(provider_account_id) "
        "AND substr(provider_account_id, 9, 1) = '-' "
        "AND substr(provider_account_id, 14, 1) = '-' "
        "AND substr(provider_account_id, 19, 1) = '-' "
        "AND substr(provider_account_id, 24, 1) = '-' "
        "AND length(earlier_capture_id) = 36 "
        "AND length(earlier_prefix_id) = 36 "
        "AND length(earlier_first_receipt_id) = 36 "
        "AND length(earlier_first_ingress_receipt_id) = 64 "
        "AND length(earlier_tip_receipt_id) = 36 "
        "AND length(earlier_tip_ingress_receipt_id) = 64 "
        "AND length(later_capture_id) = 36 "
        "AND length(later_prefix_id) = 36 "
        "AND length(later_first_receipt_id) = 36 "
        "AND length(later_first_ingress_receipt_id) = 64 "
        "AND length(later_tip_receipt_id) = 36 "
        "AND length(later_tip_ingress_receipt_id) = 64",
        name="phase4_activity_cmp_id_lengths",
    ),
    sa.CheckConstraint(
        "(previous_receipt_sha256 IS NULL OR length(previous_receipt_sha256) = 64) "
        "AND length(fence_sha256) = 64 "
        "AND length(fence_policy_sha256) = 64 "
        "AND length(commit_fence_lease_sha256) = 64 "
        "AND length(commit_fence_receipt_sha256) = 64 "
        "AND length(authentication_policy_sha256) = 64 "
        "AND length(comparison_policy_sha256) = 64 "
        "AND length(traversal_profile_sha256) = 64 "
        "AND length(earlier_plan_sha256) = 64 "
        "AND length(earlier_head_sha256) = 64 "
        "AND length(earlier_state_sha256) = 64 "
        "AND length(earlier_prefix_sha256) = 64 "
        "AND length(earlier_capture_sha256) = 64 "
        "AND length(earlier_first_receipt_sha256) = 64 "
        "AND length(earlier_first_persisted_page_sha256) = 64 "
        "AND length(earlier_first_ingress_receipt_sha256) = 64 "
        "AND length(earlier_tip_receipt_sha256) = 64 "
        "AND length(earlier_tip_persisted_page_sha256) = 64 "
        "AND length(earlier_tip_ingress_receipt_sha256) = 64 "
        "AND length(earlier_view_sha256) = 64 "
        "AND length(later_plan_sha256) = 64 "
        "AND length(later_head_sha256) = 64 "
        "AND length(later_state_sha256) = 64 "
        "AND length(later_prefix_sha256) = 64 "
        "AND length(later_capture_sha256) = 64 "
        "AND length(later_first_receipt_sha256) = 64 "
        "AND length(later_first_persisted_page_sha256) = 64 "
        "AND length(later_first_ingress_receipt_sha256) = 64 "
        "AND length(later_tip_receipt_sha256) = 64 "
        "AND length(later_tip_persisted_page_sha256) = 64 "
        "AND length(later_tip_ingress_receipt_sha256) = 64 "
        "AND length(later_view_sha256) = 64 "
        "AND length(comparison_sha256) = 64 "
        "AND length(evidence_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_activity_cmp_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(observed_utc_separation_microseconds) BETWEEN 1 AND 32 "
        "AND length(added_provider_activity_ids_payload) BETWEEN 2 AND 262144 "
        "AND length(removed_provider_activity_ids_payload) BETWEEN 2 AND 262144 "
        "AND length(changed_provider_activity_ids_payload) BETWEEN 2 AND 262144 "
        "AND length(canonical_payload) BETWEEN 2 AND 1048576",
        name="phase4_activity_cmp_payload_sizes",
    ),
)
sa.Index(
    "ix_phase4_activity_cmp_account_recorded",
    phase4_alpaca_paper_account_activity_comparisons.c.account_id,
    phase4_alpaca_paper_account_activity_comparisons.c.recorded_at,
)
sa.Index(
    "ix_phase4_activity_cmp_sources",
    phase4_alpaca_paper_account_activity_comparisons.c.earlier_capture_id,
    phase4_alpaca_paper_account_activity_comparisons.c.later_capture_id,
)

phase4_alpaca_paper_account_activity_comparison_heads = sa.Table(
    "phase4_alpaca_paper_account_activity_comparison_heads",
    metadata,
    sa.Column("account_id", sa.String(64), primary_key=True),
    sa.Column("last_account_sequence", sa.BigInteger(), nullable=False),
    sa.Column("last_receipt_id", sa.String(36), nullable=False),
    sa.Column("last_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("last_recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False),
    sa.UniqueConstraint(
        "account_id",
        "semantic_sha256",
        name="uq_phase4_activity_cmp_head_semantic",
    ),
    sa.ForeignKeyConstraint(
        ["account_id"],
        ["phase2_account_lease_heads.account_id"],
        name="fk_phase4_activity_cmp_head_account",
    ),
    sa.ForeignKeyConstraint(
        [
            "account_id",
            "last_account_sequence",
            "last_receipt_id",
            "last_receipt_sha256",
            "last_recorded_at",
        ],
        [
            "phase4_alpaca_paper_account_activity_comparisons.account_id",
            "phase4_alpaca_paper_account_activity_comparisons.account_sequence",
            "phase4_alpaca_paper_account_activity_comparisons.receipt_id",
            "phase4_alpaca_paper_account_activity_comparisons.semantic_sha256",
            "phase4_alpaca_paper_account_activity_comparisons.recorded_at",
        ],
        name="fk_phase4_activity_cmp_head_tip",
    ),
    sa.CheckConstraint(
        "last_account_sequence > 0 "
        "AND length(last_receipt_id) = 36 "
        "AND length(last_receipt_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_activity_cmp_head_shape",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 16384",
        name="phase4_activity_cmp_head_payload",
    ),
)
sa.Index(
    "ix_phase4_activity_cmp_head_recorded",
    phase4_alpaca_paper_account_activity_comparison_heads.c.last_recorded_at,
)

# Phase 4AA reserves one exact ordered pair before either order traversal is
# prepared.  Claims are page-granular immutable facts and consumptions bind
