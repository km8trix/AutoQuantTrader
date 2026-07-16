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
