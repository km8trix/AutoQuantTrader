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
