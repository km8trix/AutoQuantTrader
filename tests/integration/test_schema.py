from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

from packages.domain.account_coordinator import (
    ACCOUNT_COORDINATOR_CONTRACT_VERSION,
    ACCOUNT_LEASE_CONTRACT_VERSION,
    AccountCoordinatorError,
    AccountLease,
    AccountLeasePolicy,
    _account_lease_release,
    _legacy_account_lease,
)
from packages.domain.batch_risk import BatchRiskDecisionStatus
from packages.domain.broker_ingress import BrokerIngressDelivery
from packages.domain.canonical import canonical_json_text
from packages.domain.clock import FixedClock
from packages.domain.identifiers import canonical_id
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
    account_lease_from_row,
    account_lease_release_from_row,
    immutable_account_lease_release_values,
    immutable_account_lease_values,
)
from packages.persistence.batch_risk import (
    LEGACY_CAPACITY_OBSERVATION_CONTRACT,
    _decision_fact_payload,
    _decode_active_capacity,
    load_batch_risk_decision,
)
from packages.persistence.broker_ingress import SqlBrokerIngressRepository
from packages.persistence.database import (
    EXPECTED_SCHEMA_REVISION,
    DatabaseSchemaNotReady,
    _verify_phase2_durability_integrity,
    create_database_engine,
    verify_operational_schema,
)
from packages.persistence.reservation_lifecycle import SqlReservationLifecycleRepository
from packages.persistence.schema import (
    metadata,
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
    phase2_batch_decisions,
    phase2_ledger_entries,
    phase2_ledger_postings,
    phase2_order_events,
    phase2_reservation_release_events,
    phase2_simulation_horizon_facts,
    phase2_submission_attempt_events,
    phase4_alpaca_paper_account_activity_comparisons,
    phase4_alpaca_paper_account_binding_heads,
    phase4_alpaca_paper_account_bindings,
    phase4_alpaca_paper_asset_binding_heads,
    phase4_alpaca_paper_asset_bindings,
    phase4_alpaca_paper_lookup_observation_heads,
    phase4_alpaca_paper_lookup_observations,
    phase4_alpaca_paper_order_snapshot_heads,
    phase4_alpaca_paper_order_snapshot_pages,
    phase4_alpaca_paper_order_snapshot_plans,
    phase4_alpaca_paper_order_snapshot_preparations,
    phase4_alpaca_paper_order_transition_claims,
    phase4_alpaca_paper_order_transition_consumptions,
    phase4_alpaca_paper_order_transition_members,
    phase4_alpaca_paper_order_view_comparison_heads,
    phase4_alpaca_paper_order_view_comparisons,
    phase4_alpaca_paper_position_snapshot_plans,
    phase4_alpaca_paper_position_snapshots,
    phase4_alpaca_paper_position_transition_claims,
    phase4_alpaca_paper_position_transition_consumptions,
    phase4_alpaca_paper_position_transition_members,
    phase4_alpaca_paper_position_view_comparison_heads,
    phase4_alpaca_paper_position_view_comparisons,
    phase4_broker_inbox_application_receipts,
    phase4_broker_inbox_heads,
    phase4_broker_inbox_source_links,
    phase4_broker_ingress_heads,
    phase4_broker_ingress_receipts,
    phase4_broker_normalized_facts,
    phase4_broker_reconciliation_facts,
    phase4_broker_reconciliation_heads,
    phase5_critical_alert_delivery_attempts,
    phase5_critical_alert_delivery_results,
    phase5_critical_alert_failure_control_receipts,
    phase5_critical_alert_incidents,
    phase5_operational_control_completions,
    phase5_operational_control_heads,
    phase5_operational_control_transitions,
    phase5_strategy_invocation_claims,
    phase5_strategy_invocation_finalizations,
)
from tests.integration.test_phase2_batch_risk_persistence import _repository
from tests.unit.test_batch_risk import (
    EVALUATED_AT,
    MutableClock,
    make_batch,
    make_portfolio,
    snapshot,
)

ROOT = Path(__file__).resolve().parents[2]
PHASE2_TABLE_NAMES = frozenset(
    {
        "phase2_account_lease_heads",
        "phase2_account_lease_releases",
        "phase2_account_leases",
        "phase2_authorization_consumptions",
        "phase2_backtest_audit_events",
        "phase2_backtest_fixtures",
        "phase2_backtest_job_events",
        "phase2_backtest_job_heads",
        "phase2_backtest_jobs",
        "phase2_backtest_reports",
        "phase2_backtest_run_manifests",
        "phase2_batch_authorizations",
        "phase2_batch_decisions",
        "phase2_batch_members",
        "phase2_batch_reservations",
        "phase2_ledger_entries",
        "phase2_ledger_postings",
        "phase2_logical_orders",
        "phase2_order_events",
        "phase2_reservation_release_events",
        "phase2_simulation_horizon_facts",
        "phase2_submission_attempt_events",
        "phase2_submission_attempts",
        "phase2_strategy_configurations",
        "phase2_strategy_versions",
    }
)
PHASE3_TABLE_NAMES = frozenset(
    {
        "phase3_experiment_attempt_events",
        "phase3_experiment_attempts",
        "phase3_experiment_audit_events",
        "phase3_experiment_families",
        "phase3_experiment_tape_claims",
        "phase3_experiment_tape_policies",
        "phase3_holdout_reveals",
    }
)
PHASE3_FIXTURE_WORKER_TABLE_NAMES = frozenset(
    {
        "phase3_fixture_segment_job_events",
        "phase3_fixture_segment_job_heads",
        "phase3_fixture_segment_jobs",
        "phase3_fixture_segment_transcript_artifacts",
    }
)
PHASE4_TABLE_NAMES = frozenset(
    {
        "phase4_alpaca_paper_account_binding_heads",
        "phase4_alpaca_paper_account_bindings",
        "phase4_alpaca_paper_account_activity_heads",
        "phase4_alpaca_paper_account_activity_pages",
        "phase4_alpaca_paper_account_activity_plans",
        "phase4_alpaca_paper_account_activity_preparations",
        "phase4_alpaca_paper_account_activity_comparison_heads",
        "phase4_alpaca_paper_account_activity_comparisons",
        "phase4_alpaca_paper_asset_binding_heads",
        "phase4_alpaca_paper_asset_bindings",
        "phase4_alpaca_paper_lookup_observation_heads",
        "phase4_alpaca_paper_lookup_observations",
        "phase4_alpaca_paper_order_snapshot_heads",
        "phase4_alpaca_paper_order_snapshot_pages",
        "phase4_alpaca_paper_order_snapshot_plans",
        "phase4_alpaca_paper_order_snapshot_preparations",
        "phase4_alpaca_paper_order_transition_claims",
        "phase4_alpaca_paper_order_transition_consumptions",
        "phase4_alpaca_paper_order_transition_members",
        "phase4_alpaca_paper_order_view_comparison_heads",
        "phase4_alpaca_paper_order_view_comparisons",
        "phase4_alpaca_paper_position_snapshot_plans",
        "phase4_alpaca_paper_position_snapshots",
        "phase4_alpaca_paper_position_transition_claims",
        "phase4_alpaca_paper_position_transition_consumptions",
        "phase4_alpaca_paper_position_transition_members",
        "phase4_alpaca_paper_position_view_comparison_heads",
        "phase4_alpaca_paper_position_view_comparisons",
        "phase4_broker_inbox_application_receipts",
        "phase4_broker_inbox_heads",
        "phase4_broker_inbox_source_links",
        "phase4_broker_ingress_heads",
        "phase4_broker_ingress_receipts",
        "phase4_broker_normalized_facts",
        "phase4_broker_reconciliation_facts",
        "phase4_broker_reconciliation_heads",
        "phase4_broker_request_heads",
        "phase4_broker_request_permits",
        "phase4_unknown_lookup_recovery_events",
        "phase4_unknown_lookup_recovery_heads",
        "phase4_unknown_lookup_recovery_plans",
    }
)
PHASE5_TABLE_NAMES = frozenset(
    {
        "phase5_advanced_risk_assignment_heads",
        "phase5_advanced_risk_assignments",
        "phase5_advanced_risk_assessments",
        "phase5_advanced_risk_batch_admissions",
        "phase5_advanced_risk_batch_outcomes",
        "phase5_advanced_risk_enforcement_heads",
        "phase5_advanced_risk_evidence",
        "phase5_advanced_risk_evidence_sources",
        "phase5_advanced_risk_policies",
        "phase5_critical_alert_delivery_attempts",
        "phase5_critical_alert_delivery_results",
        "phase5_critical_alert_failure_control_receipts",
        "phase5_critical_alert_incidents",
        "phase5_operational_control_completions",
        "phase5_operational_control_heads",
        "phase5_operational_control_transitions",
        "phase5_strategy_invocation_claims",
        "phase5_strategy_invocation_finalizations",
        "phase5_strategy_supervision_results",
    }
)
PHASE6_TABLE_NAMES = frozenset(
    {
        "phase6_trusted_time_epoch_registrations",
        "phase6_trusted_time_head_anchor_intents",
        "phase6_trusted_time_head_anchor_receipts",
        "phase6_trusted_time_host_heads",
        "phase6_trusted_time_probe_evaluations",
    }
)


def _legacy_lease_values(lease: AccountLease) -> dict[str, object]:
    assert lease.contract_version == ACCOUNT_COORDINATOR_CONTRACT_VERSION
    return {
        "lease_sha256": lease.semantic_sha256,
        "account_id": lease.account_id,
        "owner_id": lease.owner_id,
        "lease_id": lease.lease_id,
        "fencing_generation": lease.fencing_generation,
        "acquired_at": lease.acquired_at,
        "heartbeat_at": lease.heartbeat_at,
        "expires_at": lease.expires_at,
        "policy_sha256": lease.policy_sha256,
        "canonical_payload": canonical_json_text(
            (
                ACCOUNT_COORDINATOR_CONTRACT_VERSION,
                "lease",
                lease.account_id,
                lease.owner_id,
                lease.lease_id,
                lease.fencing_generation,
                lease.acquired_at,
                lease.heartbeat_at,
                lease.expires_at,
                lease.policy_sha256,
            )
        ),
    }


def _legacy_lease_pair(
    *,
    account_id: str,
    owner_id: str,
    acquired_at: datetime,
    policy_sha256: str,
) -> tuple[AccountLease, AccountLease]:
    lease_id = canonical_id(
        "account-coordinator-lease",
        account_id,
        1,
        owner_id,
        acquired_at,
        policy_sha256,
    )
    first = _legacy_account_lease(
        account_id=account_id,
        owner_id=owner_id,
        lease_id=lease_id,
        fencing_generation=1,
        revision_number=1,
        previous_lease_sha256=None,
        acquired_at=acquired_at,
        heartbeat_at=acquired_at,
        expires_at=acquired_at + timedelta(seconds=30),
        policy_sha256=policy_sha256,
    )
    second = _legacy_account_lease(
        account_id=account_id,
        owner_id=owner_id,
        lease_id=lease_id,
        fencing_generation=1,
        revision_number=2,
        previous_lease_sha256=first.semantic_sha256,
        acquired_at=acquired_at,
        heartbeat_at=acquired_at + timedelta(seconds=10),
        expires_at=acquired_at + timedelta(seconds=40),
        policy_sha256=policy_sha256,
    )
    return first, second


def test_operational_schema_can_be_created_without_postgresql() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")

    metadata.create_all(engine)

    assert set(inspect(engine).get_table_names()) == {
        "calendar_sessions",
        "calendar_versions",
        "corporate_action_revisions",
        "corporate_action_set_members",
        "corporate_action_sets",
        "data_objects",
        "data_quality_issues",
        "data_quality_runs",
        "dataset_manifest_partitions",
        "dataset_manifests",
        "dataset_partitions",
        "fills",
        "ingestion_jobs",
        "instrument_identifiers",
        "instruments",
        "ledger_entries",
        "ledger_postings",
        "market_data_admission_checks",
        "market_data_admission_profiles",
        "market_data_admission_runs",
        "market_data_entitlements",
        "market_data_sources",
        "orders",
        "partition_quarantines",
        "phase2_account_lease_heads",
        "phase2_account_lease_releases",
        "phase2_account_leases",
        "phase2_authorization_consumptions",
        "phase2_backtest_audit_events",
        "phase2_backtest_fixtures",
        "phase2_backtest_job_events",
        "phase2_backtest_job_heads",
        "phase2_backtest_jobs",
        "phase2_backtest_reports",
        "phase2_backtest_run_manifests",
        "phase2_batch_authorizations",
        "phase2_batch_decisions",
        "phase2_batch_members",
        "phase2_batch_reservations",
        "phase2_ledger_entries",
        "phase2_ledger_postings",
        "phase2_logical_orders",
        "phase2_order_events",
        "phase2_reservation_release_events",
        "phase2_simulation_horizon_facts",
        "phase2_submission_attempt_events",
        "phase2_submission_attempts",
        "phase2_strategy_configurations",
        "phase2_strategy_versions",
        "phase3_experiment_attempt_events",
        "phase3_experiment_attempts",
        "phase3_experiment_audit_events",
        "phase3_experiment_families",
        "phase3_experiment_tape_claims",
        "phase3_experiment_tape_policies",
        "phase3_fixture_segment_job_events",
        "phase3_fixture_segment_job_heads",
        "phase3_fixture_segment_jobs",
        "phase3_fixture_segment_transcript_artifacts",
        "phase3_holdout_reveals",
        "phase4_alpaca_paper_account_binding_heads",
        "phase4_alpaca_paper_account_bindings",
        "phase4_alpaca_paper_account_activity_heads",
        "phase4_alpaca_paper_account_activity_pages",
        "phase4_alpaca_paper_account_activity_plans",
        "phase4_alpaca_paper_account_activity_preparations",
        "phase4_alpaca_paper_account_activity_comparison_heads",
        "phase4_alpaca_paper_account_activity_comparisons",
        "phase4_alpaca_paper_asset_binding_heads",
        "phase4_alpaca_paper_asset_bindings",
        "phase4_alpaca_paper_lookup_observation_heads",
        "phase4_alpaca_paper_lookup_observations",
        "phase4_alpaca_paper_order_snapshot_heads",
        "phase4_alpaca_paper_order_snapshot_pages",
        "phase4_alpaca_paper_order_snapshot_plans",
        "phase4_alpaca_paper_order_snapshot_preparations",
        "phase4_alpaca_paper_order_transition_claims",
        "phase4_alpaca_paper_order_transition_consumptions",
        "phase4_alpaca_paper_order_transition_members",
        "phase4_alpaca_paper_order_view_comparison_heads",
        "phase4_alpaca_paper_order_view_comparisons",
        "phase4_alpaca_paper_position_snapshot_plans",
        "phase4_alpaca_paper_position_snapshots",
        "phase4_alpaca_paper_position_transition_claims",
        "phase4_alpaca_paper_position_transition_consumptions",
        "phase4_alpaca_paper_position_transition_members",
        "phase4_alpaca_paper_position_view_comparison_heads",
        "phase4_alpaca_paper_position_view_comparisons",
        "phase4_broker_inbox_application_receipts",
        "phase4_broker_inbox_heads",
        "phase4_broker_inbox_source_links",
        "phase4_broker_ingress_heads",
        "phase4_broker_ingress_receipts",
        "phase4_broker_normalized_facts",
        "phase4_broker_reconciliation_facts",
        "phase4_broker_reconciliation_heads",
        "phase4_broker_request_heads",
        "phase4_broker_request_permits",
        "phase4_unknown_lookup_recovery_events",
        "phase4_unknown_lookup_recovery_heads",
        "phase4_unknown_lookup_recovery_plans",
        "phase5_advanced_risk_assignment_heads",
        "phase5_advanced_risk_assignments",
        "phase5_advanced_risk_assessments",
        "phase5_advanced_risk_batch_admissions",
        "phase5_advanced_risk_batch_outcomes",
        "phase5_advanced_risk_enforcement_heads",
        "phase5_advanced_risk_evidence",
        "phase5_advanced_risk_evidence_sources",
        "phase5_advanced_risk_policies",
        "phase5_critical_alert_delivery_attempts",
        "phase5_critical_alert_delivery_results",
        "phase5_critical_alert_failure_control_receipts",
        "phase5_critical_alert_incidents",
        "phase5_operational_control_completions",
        "phase5_operational_control_heads",
        "phase5_operational_control_transitions",
        "phase5_strategy_invocation_claims",
        "phase5_strategy_invocation_finalizations",
        "phase5_strategy_supervision_results",
        "phase6_trusted_time_epoch_registrations",
        "phase6_trusted_time_head_anchor_intents",
        "phase6_trusted_time_head_anchor_receipts",
        "phase6_trusted_time_host_heads",
        "phase6_trusted_time_probe_evaluations",
        "risk_account_guards",
        "risk_decisions",
        "risk_reservations",
        "replay_run_manifests",
        "submission_attempts",
        "universe_memberships",
        "universe_versions",
    }


def test_readiness_revision_pin_matches_the_single_alembic_head() -> None:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))

    assert ScriptDirectory.from_config(config).get_current_head() == EXPECTED_SCHEMA_REVISION


def test_account_activity_comparison_unique_names_match_migration() -> None:
    singleton_unique_constraints = {
        constraint.name: tuple(column.name for column in constraint.columns)
        for constraint in phase4_alpaca_paper_account_activity_comparisons.constraints
        if isinstance(constraint, sa.UniqueConstraint) and len(constraint.columns) == 1
    }

    assert singleton_unique_constraints == {
        "uq_phase4_activity_cmp_comparison": ("comparison_id",),
        "uq_phase4_activity_cmp_evidence": ("evidence_id",),
        "uq_phase4_activity_cmp_evidence_sha": ("evidence_sha256",),
        "uq_phase4_activity_cmp_semantic": ("semantic_sha256",),
    }


def test_phase5_critical_alert_schema_preserves_exact_delivery_bindings() -> None:
    assert tuple(phase5_critical_alert_incidents.c.keys()) == (
        "incident_id",
        "scope_id",
        "source_id",
        "idempotency_key",
        "alert_code",
        "evidence_sha256",
        "detected_at",
        "recorded_at",
        "correlation_sha256",
        "canonical_payload",
        "semantic_sha256",
    )
    assert tuple(phase5_critical_alert_delivery_attempts.c.keys()) == (
        "attempt_id",
        "incident_id",
        "incident_sha256",
        "sequence_number",
        "previous_attempt_id",
        "previous_attempt_sha256",
        "route",
        "provider_id",
        "idempotency_key",
        "request_sha256",
        "requested_at",
        "claimed_at",
        "command_sha256",
        "canonical_payload",
        "semantic_sha256",
    )
    assert tuple(phase5_critical_alert_delivery_results.c.keys()) == (
        "result_id",
        "incident_id",
        "incident_sha256",
        "attempt_id",
        "attempt_sha256",
        "outcome",
        "completed_at",
        "elapsed_microseconds",
        "provider_receipt_sha256",
        "failure_code",
        "canonical_payload",
        "semantic_sha256",
    )
    assert tuple(phase5_critical_alert_failure_control_receipts.c.keys()) == (
        "receipt_id",
        "account_id",
        "incident_id",
        "incident_sha256",
        "route_plan_id",
        "route_plan_version",
        "route_plan_sha256",
        "primary_provider_id",
        "primary_destination_sha256",
        "primary_recipient_set_sha256",
        "escalation_provider_id",
        "escalation_destination_sha256",
        "escalation_recipient_set_sha256",
        "supervisor_evidence_sha256",
        "supervisor_disposition",
        "supervisor_reason",
        "observed_at",
        "selected_route",
        "attempt_id",
        "attempt_sha256",
        "result_id",
        "result_sha256",
        "provider_called",
        "unresolved_claim",
        "actor_authority_sha256",
        "control_policy_sha256",
        "control_command_id",
        "control_command_sha256",
        "pre_control_transition_id",
        "pre_control_transition_sha256",
        "pre_control_state",
        "final_control_transition_id",
        "final_control_transition_sha256",
        "final_control_state",
        "bound_at",
        "canonical_payload",
        "semantic_sha256",
    )


def test_phase5_strategy_invocation_schema_preserves_exact_lifecycle_bindings() -> None:
    assert tuple(phase5_strategy_invocation_claims.c.keys()) == (
        "claim_id",
        "account_id",
        "invocation_id",
        "invocation_sha256",
        "owner_id",
        "lease_id",
        "fencing_generation",
        "lease_sha256",
        "fence_sha256",
        "fence_receipt_sha256",
        "policy_sha256",
        "claimed_at",
        "claim_valid_until",
        "recoverable_at",
        "invocation_payload",
        "semantic_sha256",
    )
    assert tuple(phase5_strategy_invocation_finalizations.c.keys()) == (
        "claim_id",
        "claim_sha256",
        "account_id",
        "invocation_id",
        "invocation_sha256",
        "result_record_sha256",
        "finalized_at",
        "semantic_sha256",
    )


def test_phase5_operational_control_schema_preserves_exact_chain_bindings() -> None:
    assert tuple(phase5_operational_control_transitions.c.keys()) == (
        "transition_id",
        "account_id",
        "sequence_number",
        "previous_transition_id",
        "previous_transition_sha256",
        "command_id",
        "actor_kind",
        "actor_id",
        "actor_authority_sha256",
        "actor_authenticated_at",
        "idempotency_key",
        "command_kind",
        "target_state",
        "requested_at",
        "reason_code",
        "reason_evidence_sha256",
        "rearm_evidence_sha256",
        "trip_rule_id",
        "trip_policy_sha256",
        "trip_observation_sha256",
        "command_canonical_payload",
        "command_sha256",
        "prior_state",
        "effective_state",
        "state_changed",
        "state_epoch_id",
        "blocking_event_count",
        "blocking_event_ids_payload",
        "blocking_event_ids_sha256",
        "blocker_overflowed",
        "active_operation_attempt_id",
        "active_operation_kind",
        "active_operation_state_epoch_id",
        "active_operation_opened_by_command_id",
        "active_operation_opened_at",
        "active_operation_sha256",
        "operation_started",
        "decided_at",
        "canonical_payload",
        "semantic_sha256",
    )
    assert tuple(phase5_operational_control_heads.c.keys()) == (
        "account_id",
        "sequence_number",
        "transition_id",
        "transition_sha256",
        "effective_state",
        "state_epoch_id",
        "blocking_event_count",
        "blocking_event_ids_payload",
        "blocking_event_ids_sha256",
        "blocker_overflowed",
        "active_operation_attempt_id",
        "active_operation_kind",
        "active_operation_state_epoch_id",
        "active_operation_opened_by_command_id",
        "active_operation_opened_at",
        "active_operation_sha256",
        "decided_at",
        "canonical_payload",
        "semantic_sha256",
    )
    assert tuple(phase5_operational_control_completions.c.keys()) == (
        "completion_id",
        "account_id",
        "idempotency_key",
        "operation_attempt_id",
        "operation_kind",
        "state_epoch_id",
        "operation_state_epoch_id",
        "operation_attempt_sha256",
        "operation_opened_by_command_id",
        "operation_opened_at",
        "opener_transition_id",
        "opener_sequence_number",
        "opener_transition_sha256",
        "opener_operation_started",
        "head_transition_id",
        "head_sequence_number",
        "head_transition_sha256",
        "outcome",
        "observed_at",
        "evidence_sha256",
        "terminal_order_count",
        "working_order_count",
        "working_order_ids_payload",
        "working_order_ids_sha256",
        "unknown_order_count",
        "unknown_order_ids_payload",
        "unknown_order_ids_sha256",
        "pending_cancel_order_count",
        "pending_cancel_order_ids_payload",
        "pending_cancel_order_ids_sha256",
        "reconciliation_clean",
        "source_evidence_sha256",
        "incomplete_reason",
        "deadline_at",
        "residual_position_count",
        "residual_gross_exposure",
        "residual_positions_payload",
        "residual_positions_sha256",
        "residual_facts_sha256",
        "canonical_payload",
        "semantic_sha256",
    )
    assert {
        tuple(column.name for column in constraint.columns)
        for constraint in phase5_operational_control_transitions.constraints
        if isinstance(constraint, sa.UniqueConstraint)
    } >= {
        ("semantic_sha256",),
        ("account_id", "sequence_number"),
        ("account_id", "semantic_sha256"),
        ("account_id", "actor_kind", "actor_id", "idempotency_key"),
        (
            "account_id",
            "transition_id",
            "sequence_number",
            "effective_state",
            "state_epoch_id",
            "blocking_event_count",
            "blocking_event_ids_sha256",
            "blocker_overflowed",
            "semantic_sha256",
        ),
    }
    completion_foreign_keys = {
        constraint.name: tuple(column.name for column in constraint.columns)
        for constraint in phase5_operational_control_completions.constraints
        if isinstance(constraint, sa.ForeignKeyConstraint)
    }
    assert completion_foreign_keys["fk_phase5_control_completion_opener"] == (
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
    )
    assert completion_foreign_keys["fk_phase5_control_completion_head"] == (
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
    )
    exposure_type = phase5_operational_control_completions.c.residual_gross_exposure.type
    assert isinstance(exposure_type, sa.Numeric)
    assert (exposure_type.precision, exposure_type.scale) == (32, 10)


def test_phase5_operational_control_schema_compiles_for_postgresql() -> None:
    from sqlalchemy.dialects import postgresql
    from sqlalchemy.schema import CreateIndex, CreateTable

    dialect = postgresql.dialect()
    for table in (
        phase5_operational_control_transitions,
        phase5_operational_control_heads,
        phase5_operational_control_completions,
    ):
        assert str(CreateTable(table).compile(dialect=dialect))
        assert all(
            constraint.name is None or len(constraint.name) <= dialect.max_identifier_length
            for constraint in table.constraints
        )
        for index in table.indexes:
            assert index.name is None or len(index.name) <= dialect.max_identifier_length
            assert str(CreateIndex(index).compile(dialect=dialect))


def test_complete_schema_compiles_for_postgresql() -> None:
    """Every checked-in table and index must fit PostgreSQL's identifier rules."""

    from sqlalchemy.dialects import postgresql
    from sqlalchemy.schema import CreateIndex, CreateTable

    dialect = postgresql.dialect()
    for table in metadata.tables.values():
        assert str(CreateTable(table).compile(dialect=dialect))
        for index in table.indexes:
            assert str(CreateIndex(index).compile(dialect=dialect))


def test_index_backed_constraint_names_are_schema_wide_unique() -> None:
    """PostgreSQL places indexes for primary/unique constraints in one namespace."""

    owners: dict[str, list[str]] = {}
    for table in metadata.tables.values():
        index_backed = [
            constraint
            for constraint in table.constraints
            if isinstance(constraint, sa.PrimaryKeyConstraint | sa.UniqueConstraint)
        ]
        for schema_item in (*index_backed, *table.indexes):
            name = schema_item.name
            assert isinstance(name, str)
            owners.setdefault(name, []).append(table.name)

    assert {name: table_names for name, table_names in owners.items() if len(table_names) > 1} == {}


def test_simulation_horizon_schema_preserves_exact_proof_bindings() -> None:
    assert tuple(phase2_simulation_horizon_facts.c.keys()) == (
        "horizon_id",
        "horizon_reference",
        "horizon_source_sha256",
        "reservation_id",
        "parent_decision_id",
        "authorization_id",
        "attempt_id",
        "order_id",
        "final_order_event_id",
        "replay_run_id",
        "replay_manifest_sha256",
        "replay_event_count",
        "replay_watermark_count",
        "simulation_result_id",
        "horizon_at",
        "recorded_at",
        "canonical_payload",
        "semantic_sha256",
    )
    assert {
        tuple(column.target_fullname for column in constraint.elements)
        for constraint in phase2_simulation_horizon_facts.foreign_key_constraints
    } == {
        ("phase2_batch_reservations.reservation_id",),
        ("phase2_batch_decisions.decision_id",),
        ("phase2_batch_authorizations.authorization_id",),
        ("phase2_submission_attempts.attempt_id",),
        ("phase2_logical_orders.order_id",),
        ("phase2_order_events.event_id",),
        ("replay_run_manifests.run_id",),
        ("replay_run_manifests.manifest_sha256",),
    }
    assert {index.name for index in phase2_simulation_horizon_facts.indexes} == {
        "ix_phase2_simulation_horizon_facts_reservation_recorded"
    }


def test_account_lease_schema_preserves_gap_free_revision_bindings() -> None:
    assert tuple(phase2_account_leases.c.keys()) == (
        "lease_sha256",
        "account_id",
        "owner_id",
        "lease_id",
        "fencing_generation",
        "revision_number",
        "previous_lease_sha256",
        "acquired_at",
        "heartbeat_at",
        "expires_at",
        "policy_sha256",
        "canonical_payload",
    )
    assert {
        tuple(column.target_fullname for column in constraint.elements)
        for constraint in phase2_account_leases.foreign_key_constraints
    } == {
        (
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        )
    }
    assert {
        tuple(column.name for column in constraint.columns)
        for constraint in phase2_account_leases.constraints
        if isinstance(constraint, sa.UniqueConstraint)
    } >= {
        ("account_id", "fencing_generation", "lease_sha256"),
        ("account_id", "fencing_generation", "revision_number"),
    }


def test_broker_ingress_schema_preserves_raw_provenance_and_account_chain() -> None:
    assert tuple(phase4_broker_ingress_receipts.c.keys()) == (
        "receipt_id",
        "account_id",
        "ingress_sequence",
        "previous_receipt_sha256",
        "delivery_idempotency_key",
        "provider_id",
        "adapter_version",
        "environment",
        "channel",
        "operation",
        "correlation_sha256",
        "transport_status",
        "provider_request_id",
        "media_type",
        "received_at",
        "recorded_at",
        "body",
        "body_size_bytes",
        "body_sha256",
        "delivery_sha256",
        "canonical_payload",
        "semantic_sha256",
    )
    assert {
        tuple(column.target_fullname for column in constraint.elements)
        for constraint in phase4_broker_ingress_receipts.foreign_key_constraints
    } == {
        ("phase2_account_lease_heads.account_id",),
        (
            "phase4_broker_ingress_receipts.account_id",
            "phase4_broker_ingress_receipts.semantic_sha256",
        ),
    }
    assert {
        tuple(column.name for column in constraint.columns)
        for constraint in phase4_broker_ingress_receipts.constraints
        if isinstance(constraint, sa.UniqueConstraint)
    } >= {
        ("account_id", "ingress_sequence"),
        ("account_id", "delivery_idempotency_key"),
        ("account_id", "semantic_sha256"),
        ("delivery_sha256",),
        ("semantic_sha256",),
    }
    assert {
        index.name: tuple(column.name for column in index.columns)
        for index in phase4_broker_ingress_receipts.indexes
    } == {
        "ix_phase4_broker_ingress_account_received": ("account_id", "received_at"),
        "ix_phase4_broker_ingress_provider_request": (
            "provider_id",
            "provider_request_id",
        ),
        "ux_phase4_broker_ingress_account_receipt_semantic": (
            "account_id",
            "receipt_id",
            "semantic_sha256",
        ),
    }
    assert tuple(phase4_broker_ingress_heads.c.keys()) == (
        "account_id",
        "last_ingress_sequence",
        "last_receipt_sha256",
    )
    assert {
        tuple(column.target_fullname for column in constraint.elements)
        for constraint in phase4_broker_ingress_heads.foreign_key_constraints
    } == {
        ("phase2_account_lease_heads.account_id",),
        (
            "phase4_broker_ingress_receipts.account_id",
            "phase4_broker_ingress_receipts.semantic_sha256",
        ),
    }


def test_alpaca_account_binding_schema_is_secret_free_and_source_bound() -> None:
    assert tuple(phase4_alpaca_paper_account_bindings.c.keys()) == (
        "binding_id",
        "account_id",
        "sequence_number",
        "previous_binding_sha256",
        "provider_id",
        "environment",
        "expected_provider_account_id",
        "observed_provider_account_id",
        "secret_ref",
        "secret_version",
        "credential_reference_sha256",
        "credential_resolution_sha256",
        "resolver_id",
        "resolver_version",
        "capability_sha256",
        "description_sha256",
        "policy_sha256",
        "demand_id",
        "demand_sha256",
        "permit_id",
        "permit_sha256",
        "permit_freshness_sha256",
        "pre_fence_receipt_sha256",
        "post_fence_receipt_sha256",
        "ingress_receipt_id",
        "ingress_receipt_sha256",
        "observation_sha256",
        "transport_request_sha256",
        "transport_response_sha256",
        "requested_at",
        "resolved_at",
        "permit_checked_at",
        "pre_fence_validated_at",
        "request_started_at",
        "received_at",
        "raw_recorded_at",
        "qualified_at",
        "post_fence_valid_until",
        "valid_until",
        "evidence_sha256",
        "canonical_payload",
        "semantic_sha256",
    )
    assert not {
        "api_key",
        "api_key_id",
        "secret_key",
        "secret_value",
        "credential_value",
    } & set(phase4_alpaca_paper_account_bindings.c.keys())
    assert {
        tuple(column.target_fullname for column in constraint.elements)
        for constraint in phase4_alpaca_paper_account_bindings.foreign_key_constraints
    } == {
        ("phase2_account_lease_heads.account_id",),
        (
            "phase4_alpaca_paper_account_bindings.account_id",
            "phase4_alpaca_paper_account_bindings.expected_provider_account_id",
            "phase4_alpaca_paper_account_bindings.semantic_sha256",
        ),
        (
            "phase4_broker_request_permits.account_id",
            "phase4_broker_request_permits.permit_id",
            "phase4_broker_request_permits.semantic_sha256",
        ),
        (
            "phase4_broker_ingress_receipts.account_id",
            "phase4_broker_ingress_receipts.receipt_id",
            "phase4_broker_ingress_receipts.semantic_sha256",
        ),
    }
    assert tuple(phase4_alpaca_paper_account_binding_heads.c.keys()) == (
        "account_id",
        "provider_id",
        "environment",
        "expected_provider_account_id",
        "last_sequence_number",
        "last_binding_sha256",
        "last_qualified_at",
        "last_valid_until",
    )
    assert {
        tuple(column.target_fullname for column in constraint.elements)
        for constraint in phase4_alpaca_paper_account_binding_heads.foreign_key_constraints
    } == {
        ("phase2_account_lease_heads.account_id",),
        (
            "phase4_alpaca_paper_account_bindings.account_id",
            "phase4_alpaca_paper_account_bindings.sequence_number",
            "phase4_alpaca_paper_account_bindings.semantic_sha256",
            "phase4_alpaca_paper_account_bindings.expected_provider_account_id",
        ),
    }


def test_alpaca_asset_binding_schema_is_pinned_secret_free_and_source_bound() -> None:
    assert tuple(phase4_alpaca_paper_asset_bindings.c.keys()) == (
        "binding_id",
        "account_id",
        "instrument_id",
        "sequence_number",
        "previous_binding_sha256",
        "provider_id",
        "environment",
        "expected_provider_account_id",
        "symbol",
        "expected_provider_asset_id",
        "observed_provider_asset_id",
        "asset_class",
        "exchange",
        "asset_status",
        "tradable",
        "secret_ref",
        "secret_version",
        "credential_reference_sha256",
        "security_reference_sha256",
        "credential_resolution_sha256",
        "resolver_id",
        "resolver_version",
        "capability_sha256",
        "account_binding_id",
        "account_binding_sha256",
        "pre_account_binding_freshness_sha256",
        "post_account_binding_freshness_sha256",
        "description_sha256",
        "policy_sha256",
        "demand_id",
        "demand_sha256",
        "permit_id",
        "permit_sha256",
        "permit_freshness_sha256",
        "pre_fence_receipt_sha256",
        "post_fence_receipt_sha256",
        "ingress_receipt_id",
        "ingress_receipt_sha256",
        "observation_sha256",
        "transport_request_sha256",
        "transport_response_sha256",
        "requested_at",
        "resolved_at",
        "pre_fence_validated_at",
        "permit_checked_at",
        "pre_account_binding_checked_at",
        "request_started_at",
        "received_at",
        "raw_recorded_at",
        "post_fence_validated_at",
        "post_account_binding_checked_at",
        "account_binding_valid_until",
        "post_fence_valid_until",
        "qualified_at",
        "valid_until",
        "evidence_sha256",
        "canonical_payload",
        "semantic_sha256",
    )
    assert not {
        "api_key",
        "api_key_id",
        "secret_key",
        "secret_value",
        "credential_value",
    } & set(phase4_alpaca_paper_asset_bindings.c.keys())
    assert {
        tuple(column.target_fullname for column in constraint.elements)
        for constraint in phase4_alpaca_paper_asset_bindings.foreign_key_constraints
    } == {
        ("phase2_account_lease_heads.account_id",),
        ("instruments.instrument_id",),
        (
            "phase4_alpaca_paper_asset_bindings.account_id",
            "phase4_alpaca_paper_asset_bindings.instrument_id",
            "phase4_alpaca_paper_asset_bindings.expected_provider_asset_id",
            "phase4_alpaca_paper_asset_bindings.semantic_sha256",
        ),
        (
            "phase4_alpaca_paper_account_bindings.account_id",
            "phase4_alpaca_paper_account_bindings.binding_id",
            "phase4_alpaca_paper_account_bindings.semantic_sha256",
            "phase4_alpaca_paper_account_bindings.expected_provider_account_id",
        ),
        (
            "phase4_broker_request_permits.account_id",
            "phase4_broker_request_permits.permit_id",
            "phase4_broker_request_permits.semantic_sha256",
        ),
        (
            "phase4_broker_ingress_receipts.account_id",
            "phase4_broker_ingress_receipts.receipt_id",
            "phase4_broker_ingress_receipts.semantic_sha256",
        ),
    }
    assert tuple(phase4_alpaca_paper_asset_binding_heads.c.keys()) == (
        "account_id",
        "instrument_id",
        "provider_id",
        "environment",
        "expected_provider_account_id",
        "symbol",
        "expected_provider_asset_id",
        "last_sequence_number",
        "last_binding_sha256",
        "last_qualified_at",
        "last_valid_until",
    )
    assert {
        tuple(column.target_fullname for column in constraint.elements)
        for constraint in phase4_alpaca_paper_asset_binding_heads.foreign_key_constraints
    } == {
        ("phase2_account_lease_heads.account_id",),
        ("instruments.instrument_id",),
        (
            "phase4_alpaca_paper_asset_bindings.account_id",
            "phase4_alpaca_paper_asset_bindings.instrument_id",
            "phase4_alpaca_paper_asset_bindings.sequence_number",
            "phase4_alpaca_paper_asset_bindings.semantic_sha256",
            "phase4_alpaca_paper_asset_bindings.expected_provider_asset_id",
        ),
    }


def test_alpaca_lookup_observation_schema_is_pinned_secret_free_and_source_bound() -> None:
    assert tuple(phase4_alpaca_paper_lookup_observations.c.keys()) == (
        "receipt_id",
        "account_id",
        "provider_id",
        "environment",
        "attempt_id",
        "attempt_sha256",
        "terminal_event_id",
        "terminal_event_sha256",
        "terminal_event_sequence",
        "parent_decision_id",
        "reservation_id",
        "order_id",
        "client_order_id",
        "instrument_id",
        "symbol",
        "expected_provider_account_id",
        "expected_provider_asset_id",
        "outcome",
        "provider_order_id",
        "provider_order_status",
        "observed_provider_asset_id",
        "mismatch_fields_payload",
        "secret_ref",
        "secret_version",
        "credential_reference_sha256",
        "security_reference_sha256",
        "credential_resolution_sha256",
        "resolver_id",
        "resolver_version",
        "capability_sha256",
        "account_binding_id",
        "account_binding_sha256",
        "pre_attempt_freshness_sha256",
        "post_attempt_freshness_sha256",
        "pre_account_identity_sha256",
        "post_account_identity_sha256",
        "description_sha256",
        "submission_sha256",
        "policy_sha256",
        "demand_id",
        "demand_sha256",
        "permit_id",
        "permit_sha256",
        "permit_freshness_sha256",
        "fence_owner_id",
        "fence_lease_id",
        "fence_fencing_generation",
        "fence_sha256",
        "fence_policy_sha256",
        "pre_fence_lease_sha256",
        "post_fence_lease_sha256",
        "pre_fence_receipt_sha256",
        "post_fence_receipt_sha256",
        "ingress_receipt_id",
        "ingress_receipt_sha256",
        "observation_sha256",
        "transport_request_sha256",
        "transport_response_sha256",
        "http_status",
        "provider_request_id",
        "requested_at",
        "credential_resolution_started_at",
        "resolved_at",
        "credential_resolution_valid_until",
        "permit_checked_at",
        "pre_fence_validated_at",
        "pre_fence_valid_until",
        "pre_attempt_checked_at",
        "pre_account_identity_checked_at",
        "request_started_at",
        "received_at",
        "raw_recorded_at",
        "post_fence_validated_at",
        "post_fence_valid_until",
        "post_attempt_checked_at",
        "post_account_identity_checked_at",
        "authenticated_at",
        "commit_checked_at",
        "sequence_number",
        "previous_receipt_sha256",
        "evidence_sha256",
        "canonical_payload",
        "semantic_sha256",
    )
    assert not {
        "api_key",
        "api_key_id",
        "secret_key",
        "secret_value",
        "credential_value",
    } & set(phase4_alpaca_paper_lookup_observations.c.keys())
    assert {
        tuple(column.target_fullname for column in constraint.elements)
        for constraint in (phase4_alpaca_paper_lookup_observations.foreign_key_constraints)
    } == {
        ("phase2_account_lease_heads.account_id",),
        ("phase2_submission_attempts.attempt_id",),
        ("instruments.instrument_id",),
        (
            "phase2_submission_attempt_events.attempt_id",
            "phase2_submission_attempt_events.event_id",
            "phase2_submission_attempt_events.semantic_sha256",
        ),
        (
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ),
        (
            "phase4_alpaca_paper_account_bindings.account_id",
            "phase4_alpaca_paper_account_bindings.binding_id",
            "phase4_alpaca_paper_account_bindings.semantic_sha256",
            "phase4_alpaca_paper_account_bindings.expected_provider_account_id",
        ),
        (
            "phase4_broker_request_permits.account_id",
            "phase4_broker_request_permits.permit_id",
            "phase4_broker_request_permits.semantic_sha256",
        ),
        (
            "phase4_broker_ingress_receipts.account_id",
            "phase4_broker_ingress_receipts.receipt_id",
            "phase4_broker_ingress_receipts.semantic_sha256",
        ),
        (
            "phase4_alpaca_paper_lookup_observations.account_id",
            "phase4_alpaca_paper_lookup_observations.attempt_id",
            "phase4_alpaca_paper_lookup_observations.semantic_sha256",
        ),
    }
    assert tuple(phase4_alpaca_paper_lookup_observation_heads.c.keys()) == (
        "account_id",
        "attempt_id",
        "terminal_event_id",
        "terminal_event_sha256",
        "last_sequence_number",
        "last_receipt_sha256",
        "last_authenticated_at",
    )
    assert {
        tuple(column.target_fullname for column in constraint.elements)
        for constraint in (phase4_alpaca_paper_lookup_observation_heads.foreign_key_constraints)
    } == {
        ("phase2_account_lease_heads.account_id",),
        ("phase2_submission_attempts.attempt_id",),
        (
            "phase4_alpaca_paper_lookup_observations.account_id",
            "phase4_alpaca_paper_lookup_observations.attempt_id",
            "phase4_alpaca_paper_lookup_observations.sequence_number",
            "phase4_alpaca_paper_lookup_observations.semantic_sha256",
            "phase4_alpaca_paper_lookup_observations.terminal_event_id",
            "phase4_alpaca_paper_lookup_observations.terminal_event_sha256",
        ),
    }


def test_order_snapshot_schema_preserves_preparation_and_exact_source_bindings() -> None:
    assert tuple(phase4_alpaca_paper_order_snapshot_plans.c.keys()) == (
        "snapshot_id",
        "account_id",
        "capture_idempotency_key",
        "capability_sha256",
        "traversal_profile_sha256",
        "page_limit",
        "maximum_pages",
        "prepared_at",
        "canonical_payload",
        "semantic_sha256",
    )
    assert {
        tuple(column.target_fullname for column in constraint.elements)
        for constraint in phase4_alpaca_paper_order_snapshot_plans.foreign_key_constraints
    } == {("phase2_account_lease_heads.account_id",)}
    assert tuple(phase4_alpaca_paper_order_snapshot_preparations.c.keys()) == (
        "preparation_sha256",
        "snapshot_id",
        "account_id",
        "page_number",
        "plan_sha256",
        "before_order_id",
        "description_sha256",
        "prefix_capture_sha256",
        "prefix_page_count",
        "previous_page_receipt_id",
        "previous_page_receipt_sha256",
        "previous_persisted_page_sha256",
        "prepared_at",
    )
    assert {
        tuple(column.target_fullname for column in constraint.elements)
        for constraint in (phase4_alpaca_paper_order_snapshot_preparations.foreign_key_constraints)
    } == {
        (
            "phase4_alpaca_paper_order_snapshot_pages.snapshot_id",
            "phase4_alpaca_paper_order_snapshot_pages.page_number",
            "phase4_alpaca_paper_order_snapshot_pages.receipt_id",
            "phase4_alpaca_paper_order_snapshot_pages.semantic_sha256",
            "phase4_alpaca_paper_order_snapshot_pages.persisted_page_sha256",
        ),
        (
            "phase4_alpaca_paper_order_snapshot_plans.snapshot_id",
            "phase4_alpaca_paper_order_snapshot_plans.account_id",
            "phase4_alpaca_paper_order_snapshot_plans.semantic_sha256",
        ),
    }
    assert tuple(phase4_alpaca_paper_order_snapshot_heads.c.keys()) == (
        "snapshot_id",
        "account_id",
        "plan_sha256",
        "committed_page_count",
        "last_page_receipt_id",
        "last_page_receipt_sha256",
        "last_persisted_page_sha256",
        "next_page_number",
        "next_before_order_id",
        "next_previous_page_sha256",
        "prepared_description_sha256",
        "prepared_prefix_capture_sha256",
        "prepared_prefix_page_count",
        "prepared_previous_page_receipt_id",
        "prepared_previous_page_receipt_sha256",
        "preparation_sha256",
        "prepared_at",
        "state",
        "updated_at",
        "canonical_payload",
        "semantic_sha256",
    )
    assert tuple(phase4_alpaca_paper_order_snapshot_pages.c.keys()) == (
        "receipt_id",
        "snapshot_id",
        "account_id",
        "page_number",
        "plan_sha256",
        "previous_page_receipt_sha256",
        "previous_persisted_page_sha256",
        "description_sha256",
        "preparation_sha256",
        "prefix_capture_sha256",
        "prefix_page_count",
        "preparation_previous_page_receipt_id",
        "preparation_previous_page_receipt_sha256",
        "prepared_at",
        "provider_id",
        "environment",
        "capability_sha256",
        "expected_provider_account_id",
        "secret_ref",
        "secret_version",
        "credential_reference_sha256",
        "credential_resolution_sha256",
        "resolver_id",
        "resolver_version",
        "credential_resolution_started_at",
        "resolved_at",
        "credential_resolution_valid_until",
        "account_binding_id",
        "account_binding_sha256",
        "pre_account_identity_sha256",
        "post_account_identity_sha256",
        "pre_account_identity_checked_at",
        "post_account_identity_checked_at",
        "policy_sha256",
        "demand_id",
        "demand_sha256",
        "requested_at",
        "permit_id",
        "permit_sha256",
        "permit_freshness_sha256",
        "permit_checked_at",
        "fence_owner_id",
        "fence_lease_id",
        "fence_fencing_generation",
        "fence_sha256",
        "fence_policy_sha256",
        "pre_fence_lease_sha256",
        "pre_fence_receipt_sha256",
        "pre_fence_validated_at",
        "pre_fence_valid_until",
        "transport_request_sha256",
        "transport_response_sha256",
        "request_started_at",
        "http_status",
        "provider_request_id",
        "received_at",
        "ingress_receipt_id",
        "ingress_receipt_sha256",
        "ingress_sequence",
        "raw_recorded_at",
        "observation_sha256",
        "persisted_page_sha256",
        "before_order_id",
        "next_before_order_id",
        "terminal_page",
        "bounded_truncation",
        "post_fence_lease_sha256",
        "post_fence_receipt_sha256",
        "post_fence_validated_at",
        "post_fence_valid_until",
        "authenticated_at",
        "evidence_sha256",
        "commit_fence_lease_sha256",
        "commit_fence_receipt_sha256",
        "commit_fence_validated_at",
        "commit_fence_valid_until",
        "canonical_payload",
        "semantic_sha256",
    )
    assert not {
        "api_key",
        "api_key_id",
        "secret_key",
        "secret_value",
        "credential_value",
        "response_body",
    } & set(phase4_alpaca_paper_order_snapshot_pages.c.keys())
    assert {
        tuple(column.target_fullname for column in constraint.elements)
        for constraint in phase4_alpaca_paper_order_snapshot_pages.foreign_key_constraints
    } == {
        (
            "phase4_alpaca_paper_order_snapshot_plans.snapshot_id",
            "phase4_alpaca_paper_order_snapshot_plans.account_id",
            "phase4_alpaca_paper_order_snapshot_plans.semantic_sha256",
        ),
        (
            "phase4_alpaca_paper_order_snapshot_pages.snapshot_id",
            "phase4_alpaca_paper_order_snapshot_pages.semantic_sha256",
        ),
        (
            "phase4_alpaca_paper_account_bindings.account_id",
            "phase4_alpaca_paper_account_bindings.binding_id",
            "phase4_alpaca_paper_account_bindings.semantic_sha256",
            "phase4_alpaca_paper_account_bindings.expected_provider_account_id",
        ),
        (
            "phase4_broker_request_permits.account_id",
            "phase4_broker_request_permits.permit_id",
            "phase4_broker_request_permits.semantic_sha256",
            "phase4_broker_request_permits.demand_id",
            "phase4_broker_request_permits.demand_sha256",
            "phase4_broker_request_permits.policy_sha256",
        ),
        (
            "phase4_broker_ingress_receipts.account_id",
            "phase4_broker_ingress_receipts.receipt_id",
            "phase4_broker_ingress_receipts.semantic_sha256",
        ),
        (
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ),
    }
    assert {
        tuple(column.target_fullname for column in constraint.elements)
        for constraint in phase4_alpaca_paper_order_snapshot_heads.foreign_key_constraints
    } == {
        (
            "phase4_alpaca_paper_order_snapshot_plans.snapshot_id",
            "phase4_alpaca_paper_order_snapshot_plans.account_id",
            "phase4_alpaca_paper_order_snapshot_plans.semantic_sha256",
        ),
        (
            "phase4_alpaca_paper_order_snapshot_pages.snapshot_id",
            "phase4_alpaca_paper_order_snapshot_pages.page_number",
            "phase4_alpaca_paper_order_snapshot_pages.receipt_id",
            "phase4_alpaca_paper_order_snapshot_pages.semantic_sha256",
            "phase4_alpaca_paper_order_snapshot_pages.persisted_page_sha256",
        ),
    }
    time_order = next(
        constraint
        for constraint in phase4_alpaca_paper_order_snapshot_pages.constraints
        if constraint.name is not None
        and constraint.name.endswith("phase4_order_snapshot_page_time_order")
    )
    assert "post_account_identity_checked_at <= authenticated_at" in str(time_order.sqltext)


def test_order_view_comparison_schema_binds_exact_sources_fence_and_account_chain() -> None:
    assert tuple(phase4_alpaca_paper_order_view_comparisons.c.keys()) == (
        "receipt_id",
        "evidence_id",
        "comparison_id",
        "account_id",
        "account_sequence",
        "previous_receipt_sha256",
        "fence_owner_id",
        "fence_lease_id",
        "fence_fencing_generation",
        "fence_sha256",
        "fence_policy_sha256",
        "commit_fence_lease_sha256",
        "commit_fence_receipt_sha256",
        "commit_fence_validated_at",
        "commit_fence_valid_until",
        "authentication_policy_sha256",
        "comparison_policy_sha256",
        "traversal_profile_sha256",
        "earlier_snapshot_id",
        "earlier_plan_sha256",
        "earlier_head_sha256",
        "earlier_prefix_id",
        "earlier_prefix_sha256",
        "earlier_capture_sha256",
        "earlier_page_count",
        "earlier_tip_receipt_id",
        "earlier_tip_receipt_sha256",
        "earlier_tip_persisted_page_sha256",
        "earlier_source_committed_at",
        "earlier_window_started_at",
        "earlier_window_ended_at",
        "earlier_view_sha256",
        "later_snapshot_id",
        "later_plan_sha256",
        "later_head_sha256",
        "later_prefix_id",
        "later_prefix_sha256",
        "later_capture_sha256",
        "later_page_count",
        "later_tip_receipt_id",
        "later_tip_receipt_sha256",
        "later_tip_persisted_page_sha256",
        "later_source_committed_at",
        "later_window_started_at",
        "later_window_ended_at",
        "later_view_sha256",
        "observed_utc_separation_microseconds",
        "disposition",
        "added_provider_order_ids_payload",
        "removed_provider_order_ids_payload",
        "changed_provider_order_ids_payload",
        "added_count",
        "removed_count",
        "changed_count",
        "comparison_sha256",
        "evidence_sha256",
        "recorded_at",
        "canonical_payload",
        "semantic_sha256",
    )
    assert tuple(phase4_alpaca_paper_order_view_comparison_heads.c.keys()) == (
        "account_id",
        "last_account_sequence",
        "last_receipt_id",
        "last_receipt_sha256",
        "last_recorded_at",
        "canonical_payload",
        "semantic_sha256",
    )
    assert not {
        "api_key",
        "api_key_id",
        "secret_key",
        "secret_value",
        "credential_value",
        "response_body",
    } & set(phase4_alpaca_paper_order_view_comparisons.c.keys())
    unique_columns = {
        constraint.name: tuple(column.name for column in constraint.columns)
        for constraint in phase4_alpaca_paper_order_view_comparisons.constraints
        if isinstance(constraint, sa.UniqueConstraint)
    }
    assert unique_columns["uq_phase4_order_view_cmp_exact"] == (
        "account_id",
        "account_sequence",
        "receipt_id",
        "semantic_sha256",
        "recorded_at",
    )
    assert {
        tuple(column.target_fullname for column in constraint.elements)
        for constraint in phase4_alpaca_paper_order_view_comparisons.foreign_key_constraints
    } == {
        ("phase2_account_lease_heads.account_id",),
        (
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ),
        (
            "phase4_alpaca_paper_order_snapshot_plans.snapshot_id",
            "phase4_alpaca_paper_order_snapshot_plans.account_id",
            "phase4_alpaca_paper_order_snapshot_plans.semantic_sha256",
        ),
        (
            "phase4_alpaca_paper_order_snapshot_heads.snapshot_id",
            "phase4_alpaca_paper_order_snapshot_heads.account_id",
            "phase4_alpaca_paper_order_snapshot_heads.semantic_sha256",
        ),
        (
            "phase4_alpaca_paper_order_snapshot_pages.snapshot_id",
            "phase4_alpaca_paper_order_snapshot_pages.page_number",
            "phase4_alpaca_paper_order_snapshot_pages.receipt_id",
            "phase4_alpaca_paper_order_snapshot_pages.semantic_sha256",
            "phase4_alpaca_paper_order_snapshot_pages.persisted_page_sha256",
        ),
        (
            "phase4_alpaca_paper_order_view_comparisons.account_id",
            "phase4_alpaca_paper_order_view_comparisons.semantic_sha256",
        ),
    }
    assert {
        tuple(column.target_fullname for column in constraint.elements)
        for constraint in phase4_alpaca_paper_order_view_comparison_heads.foreign_key_constraints
    } == {
        ("phase2_account_lease_heads.account_id",),
        (
            "phase4_alpaca_paper_order_view_comparisons.account_id",
            "phase4_alpaca_paper_order_view_comparisons.account_sequence",
            "phase4_alpaca_paper_order_view_comparisons.receipt_id",
            "phase4_alpaca_paper_order_view_comparisons.semantic_sha256",
            "phase4_alpaca_paper_order_view_comparisons.recorded_at",
        ),
    }
    fence_check = next(
        constraint
        for constraint in phase4_alpaca_paper_order_view_comparisons.constraints
        if constraint.name is not None
        and constraint.name.endswith("phase4_order_view_cmp_commit_fence")
    )
    assert "commit_fence_validated_at = recorded_at" in str(fence_check.sqltext)


def test_broker_reconciliation_schema_preserves_authenticated_source_chain() -> None:
    assert tuple(phase4_broker_reconciliation_facts.c.keys()) == (
        "fact_id",
        "account_id",
        "account_sequence",
        "previous_fact_sha256",
        "provider_id",
        "environment",
        "attempt_id",
        "order_id",
        "client_order_id",
        "instrument_id",
        "symbol",
        "outcome",
        "expected_provider_asset_id",
        "provider_order_id",
        "provider_order_status",
        "provider_replaced_by",
        "provider_replaces",
        "observed_provider_asset_id",
        "mismatch_fields_payload",
        "provider_timestamps_payload",
        "requested_quantity",
        "requested_notional",
        "cumulative_filled_quantity",
        "cumulative_filled_average_price",
        "provider_source",
        "source_lookup_receipt_id",
        "source_lookup_receipt_sha256",
        "source_ingress_receipt_id",
        "source_ingress_receipt_sha256",
        "source_ingress_sequence",
        "source_delivery_idempotency_key",
        "source_observation_sha256",
        "source_body_sha256",
        "http_status",
        "provider_request_id",
        "received_at",
        "raw_recorded_at",
        "authenticated_at",
        "source_committed_at",
        "normalized_at",
        "canonical_payload",
        "semantic_sha256",
    )
    assert {
        tuple(column.target_fullname for column in constraint.elements)
        for constraint in phase4_broker_reconciliation_facts.foreign_key_constraints
    } == {
        ("phase2_account_lease_heads.account_id",),
        (
            "phase4_broker_reconciliation_facts.account_id",
            "phase4_broker_reconciliation_facts.semantic_sha256",
        ),
        (
            "phase4_alpaca_paper_lookup_observations.account_id",
            "phase4_alpaca_paper_lookup_observations.attempt_id",
            "phase4_alpaca_paper_lookup_observations.receipt_id",
            "phase4_alpaca_paper_lookup_observations.semantic_sha256",
        ),
        (
            "phase4_broker_ingress_receipts.account_id",
            "phase4_broker_ingress_receipts.receipt_id",
            "phase4_broker_ingress_receipts.semantic_sha256",
        ),
    }
    assert {
        tuple(column.name for column in constraint.columns)
        for constraint in phase4_broker_reconciliation_facts.constraints
        if isinstance(constraint, sa.UniqueConstraint)
    } == {
        ("semantic_sha256",),
        ("account_id", "account_sequence"),
        ("account_id", "semantic_sha256"),
        ("account_id", "account_sequence", "fact_id", "semantic_sha256"),
        ("source_lookup_receipt_id",),
        ("source_ingress_receipt_id",),
    }
    assert {
        index.name: tuple(column.name for column in index.columns)
        for index in phase4_broker_reconciliation_facts.indexes
    } == {
        "ix_phase4_broker_reconciliation_account_normalized": (
            "account_id",
            "normalized_at",
        ),
        "ix_phase4_broker_reconciliation_attempt": (
            "account_id",
            "attempt_id",
            "account_sequence",
        ),
    }
    assert tuple(phase4_broker_reconciliation_heads.c.keys()) == (
        "account_id",
        "last_account_sequence",
        "last_fact_id",
        "last_fact_sha256",
        "last_normalized_at",
    )
    assert {
        tuple(column.target_fullname for column in constraint.elements)
        for constraint in phase4_broker_reconciliation_heads.foreign_key_constraints
    } == {
        ("phase2_account_lease_heads.account_id",),
        (
            "phase4_broker_reconciliation_facts.account_id",
            "phase4_broker_reconciliation_facts.account_sequence",
            "phase4_broker_reconciliation_facts.fact_id",
            "phase4_broker_reconciliation_facts.semantic_sha256",
        ),
    }


def test_broker_inbox_schema_preserves_source_scoped_non_application_history() -> None:
    assert tuple(phase4_broker_normalized_facts.c.keys()) == (
        "request_id",
        "observation_id",
        "account_id",
        "provider_id",
        "environment",
        "source_kind",
        "identity_profile_id",
        "identity_profile_sha256",
        "identity_sha256",
        "source_reconciliation_fact_id",
        "source_reconciliation_fact_sha256",
        "source_reconciliation_evidence_sha256",
        "source_reconciliation_account_sequence",
        "source_fact_normalized_at",
        "source_lookup_receipt_id",
        "source_lookup_receipt_sha256",
        "source_ingress_receipt_id",
        "source_ingress_receipt_sha256",
        "source_observation_sha256",
        "canonical_payload",
        "semantic_sha256",
    )
    assert {
        tuple(column.name for column in constraint.columns)
        for constraint in phase4_broker_normalized_facts.constraints
        if isinstance(constraint, sa.UniqueConstraint)
    } == {
        ("observation_id",),
        ("identity_sha256",),
        ("source_reconciliation_fact_id",),
        ("source_lookup_receipt_id",),
        ("source_ingress_receipt_id",),
        ("semantic_sha256",),
        ("request_id", "account_id", "observation_id", "semantic_sha256"),
        (
            "request_id",
            "account_id",
            "observation_id",
            "source_reconciliation_fact_id",
            "source_reconciliation_fact_sha256",
            "source_ingress_receipt_id",
            "source_ingress_receipt_sha256",
            "semantic_sha256",
        ),
    }
    assert {
        index.name: tuple(column.name for column in index.columns)
        for index in phase4_broker_normalized_facts.indexes
    } == {
        "ix_phase4_broker_normalized_account_source_time": (
            "account_id",
            "source_fact_normalized_at",
        ),
    }

    assert tuple(phase4_broker_inbox_source_links.c.keys()) == (
        "link_id",
        "account_id",
        "account_sequence",
        "previous_link_sha256",
        "request_id",
        "request_sha256",
        "observation_id",
        "source_reconciliation_fact_id",
        "source_reconciliation_fact_sha256",
        "source_reconciliation_evidence_sha256",
        "source_reconciliation_account_sequence",
        "source_lookup_receipt_id",
        "source_lookup_receipt_sha256",
        "source_ingress_receipt_id",
        "source_ingress_receipt_sha256",
        "source_observation_sha256",
        "linked_at",
        "canonical_payload",
        "semantic_sha256",
    )
    assert {
        tuple(column.target_fullname for column in constraint.elements)
        for constraint in phase4_broker_inbox_source_links.foreign_key_constraints
    } == {
        ("phase2_account_lease_heads.account_id",),
        (
            "phase4_broker_inbox_source_links.account_id",
            "phase4_broker_inbox_source_links.semantic_sha256",
        ),
        (
            "phase4_broker_normalized_facts.request_id",
            "phase4_broker_normalized_facts.account_id",
            "phase4_broker_normalized_facts.observation_id",
            "phase4_broker_normalized_facts.source_reconciliation_fact_id",
            "phase4_broker_normalized_facts.source_reconciliation_fact_sha256",
            "phase4_broker_normalized_facts.source_ingress_receipt_id",
            "phase4_broker_normalized_facts.source_ingress_receipt_sha256",
            "phase4_broker_normalized_facts.semantic_sha256",
        ),
        (
            "phase4_broker_reconciliation_facts.account_id",
            "phase4_broker_reconciliation_facts.account_sequence",
            "phase4_broker_reconciliation_facts.fact_id",
            "phase4_broker_reconciliation_facts.semantic_sha256",
        ),
        (
            "phase4_broker_ingress_receipts.account_id",
            "phase4_broker_ingress_receipts.receipt_id",
            "phase4_broker_ingress_receipts.semantic_sha256",
        ),
    }
    assert {
        tuple(column.name for column in constraint.columns)
        for constraint in phase4_broker_inbox_source_links.constraints
        if isinstance(constraint, sa.UniqueConstraint)
    } == {
        ("request_id",),
        ("observation_id",),
        ("source_reconciliation_fact_id",),
        ("source_lookup_receipt_id",),
        ("source_ingress_receipt_id",),
        ("semantic_sha256",),
        ("account_id", "account_sequence"),
        ("account_id", "semantic_sha256"),
        ("account_id", "account_sequence", "link_id", "semantic_sha256"),
        (
            "account_id",
            "account_sequence",
            "link_id",
            "request_id",
            "semantic_sha256",
        ),
        ("link_id", "account_id", "request_id", "semantic_sha256"),
    }
    assert {
        index.name: tuple(column.name for column in index.columns)
        for index in phase4_broker_inbox_source_links.indexes
    } == {
        "ix_phase4_broker_inbox_link_account_time": (
            "account_id",
            "linked_at",
        ),
    }

    assert tuple(phase4_broker_inbox_heads.c.keys()) == (
        "account_id",
        "last_account_sequence",
        "last_link_id",
        "last_link_sha256",
        "last_linked_at",
    )
    assert {
        tuple(column.target_fullname for column in constraint.elements)
        for constraint in phase4_broker_inbox_heads.foreign_key_constraints
    } == {
        ("phase2_account_lease_heads.account_id",),
        (
            "phase4_broker_inbox_source_links.account_id",
            "phase4_broker_inbox_source_links.account_sequence",
            "phase4_broker_inbox_source_links.link_id",
            "phase4_broker_inbox_source_links.semantic_sha256",
        ),
    }

    assert tuple(phase4_broker_inbox_application_receipts.c.keys()) == (
        "decision_id",
        "account_id",
        "request_id",
        "request_sha256",
        "observation_id",
        "source_link_id",
        "source_link_sha256",
        "disposition",
        "policy_id",
        "policy_sha256",
        "decided_at",
        "recorded_at",
        "canonical_payload",
        "semantic_sha256",
    )
    assert {
        tuple(column.target_fullname for column in constraint.elements)
        for constraint in phase4_broker_inbox_application_receipts.foreign_key_constraints
    } == {
        (
            "phase4_broker_normalized_facts.request_id",
            "phase4_broker_normalized_facts.account_id",
            "phase4_broker_normalized_facts.observation_id",
            "phase4_broker_normalized_facts.semantic_sha256",
        ),
        (
            "phase4_broker_inbox_source_links.link_id",
            "phase4_broker_inbox_source_links.account_id",
            "phase4_broker_inbox_source_links.request_id",
            "phase4_broker_inbox_source_links.semantic_sha256",
        ),
    }
    assert {
        tuple(column.name for column in constraint.columns)
        for constraint in phase4_broker_inbox_application_receipts.constraints
        if isinstance(constraint, sa.UniqueConstraint)
    } == {
        ("request_id",),
        ("observation_id",),
        ("source_link_id",),
        ("semantic_sha256",),
        ("decision_id", "account_id", "request_id", "semantic_sha256"),
    }


def test_phase2_durability_migration_is_additive_and_reversible(tmp_path: Path) -> None:
    database_path = tmp_path / "phase2-durability.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(config, "0006_replay_run_manifests")
    engine = create_engine(database_url)
    legacy_tables = set(inspect(engine).get_table_names())
    legacy_columns = {
        table_name: tuple(column["name"] for column in inspect(engine).get_columns(table_name))
        for table_name in legacy_tables
    }

    command.upgrade(config, "head")

    upgraded_tables = set(inspect(engine).get_table_names())
    assert upgraded_tables == (
        legacy_tables
        | PHASE2_TABLE_NAMES
        | PHASE3_TABLE_NAMES
        | PHASE3_FIXTURE_WORKER_TABLE_NAMES
        | PHASE4_TABLE_NAMES
        | PHASE5_TABLE_NAMES
        | PHASE6_TABLE_NAMES
    )
    assert {
        table_name: tuple(column["name"] for column in inspect(engine).get_columns(table_name))
        for table_name in legacy_tables
    } == legacy_columns
    upgraded_inspector = inspect(engine)
    migrated_lease_columns = {
        column["name"]: column for column in upgraded_inspector.get_columns("phase2_account_leases")
    }
    assert set(migrated_lease_columns) == set(phase2_account_leases.c.keys())
    assert migrated_lease_columns["revision_number"]["nullable"] is False
    assert migrated_lease_columns["previous_lease_sha256"]["nullable"] is True
    assert any(
        foreign_key["constrained_columns"]
        == ["account_id", "fencing_generation", "previous_lease_sha256"]
        and foreign_key["referred_columns"] == ["account_id", "fencing_generation", "lease_sha256"]
        for foreign_key in upgraded_inspector.get_foreign_keys("phase2_account_leases")
    )
    assert {
        tuple(constraint["column_names"])
        for constraint in upgraded_inspector.get_unique_constraints("phase2_account_leases")
    } >= {
        ("account_id", "fencing_generation", "lease_sha256"),
        ("account_id", "fencing_generation", "revision_number"),
        ("account_id", "lease_id", "heartbeat_at"),
    }
    assert {
        index["name"]: tuple(index["column_names"])
        for index in upgraded_inspector.get_indexes("phase2_account_leases")
    }["ix_phase2_account_leases_account_generation"] == (
        "account_id",
        "fencing_generation",
        "revision_number",
    )

    engine.dispose()
    command.downgrade(config, "0006_replay_run_manifests")
    downgraded_engine = create_engine(database_url)
    assert set(inspect(downgraded_engine).get_table_names()) == legacy_tables
    downgraded_engine.dispose()


def test_phase3_governance_migration_is_additive_and_reversible(tmp_path: Path) -> None:
    database_path = tmp_path / "phase3-governance.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(config, "0009_lease_revision_chain")
    engine = create_engine(database_url)
    prior_tables = set(inspect(engine).get_table_names())
    prior_columns = {
        table_name: tuple(column["name"] for column in inspect(engine).get_columns(table_name))
        for table_name in prior_tables
    }

    command.upgrade(config, "head")

    assert set(inspect(engine).get_table_names()) == (
        prior_tables
        | PHASE3_TABLE_NAMES
        | PHASE3_FIXTURE_WORKER_TABLE_NAMES
        | PHASE4_TABLE_NAMES
        | PHASE5_TABLE_NAMES
        | PHASE6_TABLE_NAMES
    )
    assert {
        table_name: tuple(column["name"] for column in inspect(engine).get_columns(table_name))
        for table_name in prior_tables
    } == prior_columns
    engine.dispose()
    command.downgrade(config, "0009_lease_revision_chain")
    downgraded_engine = create_engine(database_url)
    assert set(inspect(downgraded_engine).get_table_names()) == prior_tables
    downgraded_engine.dispose()


def test_phase4_broker_ingress_migration_is_additive_and_reversible(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "phase4-broker-ingress.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(config, "0010_phase3_governance")
    engine = create_engine(database_url)
    prior_tables = set(inspect(engine).get_table_names())
    prior_columns = {
        table_name: tuple(column["name"] for column in inspect(engine).get_columns(table_name))
        for table_name in prior_tables
    }

    command.upgrade(config, "head")

    assert set(inspect(engine).get_table_names()) == (
        prior_tables
        | PHASE3_FIXTURE_WORKER_TABLE_NAMES
        | PHASE4_TABLE_NAMES
        | PHASE5_TABLE_NAMES
        | PHASE6_TABLE_NAMES
    )
    assert {
        table_name: tuple(column["name"] for column in inspect(engine).get_columns(table_name))
        for table_name in prior_tables
    } == prior_columns
    assert tuple(
        column["name"] for column in inspect(engine).get_columns("phase4_broker_ingress_receipts")
    ) == tuple(phase4_broker_ingress_receipts.c.keys())
    assert tuple(
        column["name"] for column in inspect(engine).get_columns("phase4_broker_ingress_heads")
    ) == tuple(phase4_broker_ingress_heads.c.keys())
    assert tuple(
        column["name"]
        for column in inspect(engine).get_columns("phase4_broker_reconciliation_facts")
    ) == tuple(phase4_broker_reconciliation_facts.c.keys())
    assert tuple(
        column["name"]
        for column in inspect(engine).get_columns("phase4_broker_reconciliation_heads")
    ) == tuple(phase4_broker_reconciliation_heads.c.keys())
    assert tuple(
        column["name"] for column in inspect(engine).get_columns("phase4_broker_normalized_facts")
    ) == tuple(phase4_broker_normalized_facts.c.keys())
    assert tuple(
        column["name"] for column in inspect(engine).get_columns("phase4_broker_inbox_source_links")
    ) == tuple(phase4_broker_inbox_source_links.c.keys())
    assert tuple(
        column["name"] for column in inspect(engine).get_columns("phase4_broker_inbox_heads")
    ) == tuple(phase4_broker_inbox_heads.c.keys())
    assert tuple(
        column["name"]
        for column in inspect(engine).get_columns("phase4_broker_inbox_application_receipts")
    ) == tuple(phase4_broker_inbox_application_receipts.c.keys())
    assert tuple(
        column["name"]
        for column in inspect(engine).get_columns("phase4_alpaca_paper_order_snapshot_plans")
    ) == tuple(phase4_alpaca_paper_order_snapshot_plans.c.keys())
    assert tuple(
        column["name"]
        for column in inspect(engine).get_columns("phase4_alpaca_paper_order_snapshot_pages")
    ) == tuple(phase4_alpaca_paper_order_snapshot_pages.c.keys())
    assert tuple(
        column["name"]
        for column in inspect(engine).get_columns("phase4_alpaca_paper_order_snapshot_heads")
    ) == tuple(phase4_alpaca_paper_order_snapshot_heads.c.keys())
    assert tuple(
        column["name"]
        for column in inspect(engine).get_columns("phase4_alpaca_paper_order_transition_members")
    ) == tuple(phase4_alpaca_paper_order_transition_members.c.keys())
    assert tuple(
        column["name"]
        for column in inspect(engine).get_columns("phase4_alpaca_paper_order_transition_claims")
    ) == tuple(phase4_alpaca_paper_order_transition_claims.c.keys())
    assert tuple(
        column["name"]
        for column in inspect(engine).get_columns(
            "phase4_alpaca_paper_order_transition_consumptions"
        )
    ) == tuple(phase4_alpaca_paper_order_transition_consumptions.c.keys())
    assert tuple(
        column["name"]
        for column in inspect(engine).get_columns("phase4_alpaca_paper_order_view_comparisons")
    ) == tuple(phase4_alpaca_paper_order_view_comparisons.c.keys())
    assert tuple(
        column["name"]
        for column in inspect(engine).get_columns("phase4_alpaca_paper_order_view_comparison_heads")
    ) == tuple(phase4_alpaca_paper_order_view_comparison_heads.c.keys())
    assert tuple(
        column["name"]
        for column in inspect(engine).get_columns("phase4_alpaca_paper_position_snapshot_plans")
    ) == tuple(phase4_alpaca_paper_position_snapshot_plans.c.keys())
    assert tuple(
        column["name"]
        for column in inspect(engine).get_columns("phase4_alpaca_paper_position_snapshots")
    ) == tuple(phase4_alpaca_paper_position_snapshots.c.keys())
    assert tuple(
        column["name"]
        for column in inspect(engine).get_columns("phase4_alpaca_paper_position_transition_members")
    ) == tuple(phase4_alpaca_paper_position_transition_members.c.keys())
    assert tuple(
        column["name"]
        for column in inspect(engine).get_columns("phase4_alpaca_paper_position_transition_claims")
    ) == tuple(phase4_alpaca_paper_position_transition_claims.c.keys())
    assert tuple(
        column["name"]
        for column in inspect(engine).get_columns(
            "phase4_alpaca_paper_position_transition_consumptions"
        )
    ) == tuple(phase4_alpaca_paper_position_transition_consumptions.c.keys())
    assert tuple(
        column["name"]
        for column in inspect(engine).get_columns("phase4_alpaca_paper_position_view_comparisons")
    ) == tuple(phase4_alpaca_paper_position_view_comparisons.c.keys())
    assert tuple(
        column["name"]
        for column in inspect(engine).get_columns(
            "phase4_alpaca_paper_position_view_comparison_heads"
        )
    ) == tuple(phase4_alpaca_paper_position_view_comparison_heads.c.keys())
    engine.dispose()

    command.downgrade(config, "0010_phase3_governance")
    downgraded_engine = create_engine(database_url)
    assert set(inspect(downgraded_engine).get_table_names()) == prior_tables
    downgraded_engine.dispose()


def test_phase4_broker_ingress_migration_refuses_data_loss_on_downgrade(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "phase4-broker-ingress-downgrade.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    observed_at = datetime(2026, 7, 26, 15, 0, tzinfo=UTC)
    with engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_account_lease_heads).values(
                account_id="phase4-downgrade-account",
                last_fencing_generation=0,
                current_fencing_generation=None,
                current_lease_sha256=None,
                updated_at=observed_at,
            )
        )
    SqlBrokerIngressRepository(engine).record(
        BrokerIngressDelivery(
            account_id="phase4-downgrade-account",
            delivery_idempotency_key="downgrade-proof-delivery",
            provider_id="alpaca",
            adapter_version="1.0.0",
            environment="paper",
            channel="trading-rest",
            operation="get-order-by-client-order-id",
            received_at=observed_at,
            recorded_at=observed_at,
            body=b'{"id":"durable-provider-order"}',
        )
    )
    engine.dispose()

    with pytest.raises(
        RuntimeError,
        match="cannot downgrade after durable broker ingress receipts",
    ):
        command.downgrade(config, "0010_phase3_governance")

    preserved_engine = create_engine(database_url)
    with preserved_engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
            "0011_phase4_broker_ingress"
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_broker_ingress_receipts)
            )
            == 1
        )
        assert not inspect(preserved_engine).has_table("phase4_broker_request_permits")
        assert not inspect(preserved_engine).has_table("phase4_broker_request_heads")
    preserved_engine.dispose()


def test_operational_readiness_rejects_truncated_broker_ingress_tail(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "phase4-broker-ingress-readiness.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    observed_at = datetime(2026, 7, 26, 15, 0, tzinfo=UTC)
    account_id = "phase4-readiness-account"
    policy = AccountLeasePolicy(
        policy_id="phase4-readiness-coordinator",
        policy_version="1.0.0",
        lease_ttl=timedelta(minutes=5),
        maximum_in_flight_duration=timedelta(seconds=5),
        takeover_safety_interval=timedelta(seconds=10),
    )
    coordinator = SqlAccountCoordinator(
        account_id=account_id,
        authority=SqlAccountCoordinatorAuthority(
            engine=engine,
            policy=policy,
            clock=FixedClock(observed_at),
        ),
    )
    coordinator.acquire("phase4-readiness-worker")
    repository = SqlBrokerIngressRepository(engine)
    receipts = tuple(
        repository.record(
            BrokerIngressDelivery(
                account_id=account_id,
                delivery_idempotency_key=f"readiness-delivery-{sequence}",
                provider_id="alpaca",
                adapter_version="1.0.0",
                environment="paper",
                channel="trading-rest",
                operation="get-order-by-client-order-id",
                received_at=observed_at + timedelta(seconds=sequence),
                recorded_at=observed_at + timedelta(seconds=sequence),
                body=f'{{"sequence":{sequence}}}'.encode(),
            )
        )
        for sequence in (1, 2)
    )
    verify_operational_schema(engine, require_phase_zero_facts=False)

    # Simulate storage corruption below the relational guard. The durable head
    # must let readiness distinguish a truncated journal from a shorter history.
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys = OFF")
        connection.execute(
            sa.delete(phase4_broker_ingress_receipts).where(
                phase4_broker_ingress_receipts.c.semantic_sha256 == receipts[-1].semantic_sha256
            )
        )
        connection.commit()
        connection.exec_driver_sql("PRAGMA foreign_keys = ON")

    with pytest.raises(
        DatabaseSchemaNotReady,
        match="Phase 4 broker-ingress integrity verification failed",
    ):
        verify_operational_schema(engine, require_phase_zero_facts=False)
    engine.dispose()


def test_operational_readiness_rejects_corrupt_phase5_control_history(
    tmp_path: Path,
) -> None:
    from packages.domain.operational_control import (
        OperationalControlActor,
        OperationalControlActorKind,
        OperationalControlCommand,
        OperationalControlCommandKind,
        OperationalControlState,
    )
    from packages.persistence.operational_control import SqlOperationalControlRepository

    database_path = tmp_path / "phase5-control-readiness.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    instant = datetime(2026, 7, 28, 20, 30, tzinfo=UTC)
    account_id = "phase5-readiness-account"
    coordinator = SqlAccountCoordinator(
        account_id=account_id,
        authority=SqlAccountCoordinatorAuthority(
            engine=engine,
            policy=AccountLeasePolicy(
                policy_id="phase5-readiness-coordinator",
                policy_version="1.0.0",
                lease_ttl=timedelta(minutes=5),
                maximum_in_flight_duration=timedelta(seconds=5),
                takeover_safety_interval=timedelta(seconds=10),
            ),
            clock=FixedClock(instant),
        ),
    )
    coordinator.acquire("phase5-readiness-worker")
    repository = SqlOperationalControlRepository(
        engine=engine,
        clock=FixedClock(instant),
    )
    initial = repository.apply(
        OperationalControlCommand(
            scope_id=account_id,
            idempotency_key="initialize-0001",
            kind=OperationalControlCommandKind.INITIALIZE_HALTED,
            target_state=OperationalControlState.HALTED,
            actor=OperationalControlActor(
                actor_id="startup",
                kind=OperationalControlActorKind.SYSTEM,
                authority_sha256="a" * 64,
                authenticated_at=None,
            ),
            reason_code="startup",
            reason_evidence_sha256="b" * 64,
            requested_at=instant,
        )
    )
    verify_operational_schema(engine, require_phase_zero_facts=False)

    with engine.begin() as connection:
        connection.execute(
            sa.update(phase5_operational_control_transitions)
            .where(phase5_operational_control_transitions.c.transition_id == initial.transition_id)
            .values(reason_code="tampered")
        )

    with pytest.raises(
        DatabaseSchemaNotReady,
        match="Phase 5 operational-control integrity verification failed",
    ):
        verify_operational_schema(engine, require_phase_zero_facts=False)
    engine.dispose()


def test_lease_revision_upgrade_preserves_v1_history_and_transitions_to_v2(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "lease-revision-upgrade.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "0008_phase2_research")
    engine = create_engine(database_url)

    assert "revision_number" not in {
        column["name"] for column in inspect(engine).get_columns("phase2_account_leases")
    }
    base = datetime(2026, 7, 20, 13, 30, tzinfo=UTC)
    policy = AccountLeasePolicy(
        policy_id="phase2-upgrade-coordinator",
        policy_version="1.0.0",
        lease_ttl=timedelta(seconds=30),
        maximum_in_flight_duration=timedelta(seconds=5),
        takeover_safety_interval=timedelta(seconds=10),
    )
    released_first, released_second = _legacy_lease_pair(
        account_id="legacy-released-account",
        owner_id="legacy-worker-a",
        acquired_at=base,
        policy_sha256=policy.semantic_sha256,
    )
    active_first, active_second = _legacy_lease_pair(
        account_id="legacy-active-account",
        owner_id="legacy-worker-b",
        acquired_at=base,
        policy_sha256=policy.semantic_sha256,
    )
    release = _account_lease_release(
        fence=released_second.fence,
        released_at=base + timedelta(seconds=15),
        policy_sha256=policy.semantic_sha256,
        lease_sha256=released_second.semantic_sha256,
    )
    legacy_leases = sa.table(
        "phase2_account_leases",
        sa.column("lease_sha256", sa.String(64)),
        sa.column("account_id", sa.String(64)),
        sa.column("owner_id", sa.String(128)),
        sa.column("lease_id", sa.String(64)),
        sa.column("fencing_generation", sa.BigInteger()),
        sa.column("acquired_at", sa.DateTime(timezone=True)),
        sa.column("heartbeat_at", sa.DateTime(timezone=True)),
        sa.column("expires_at", sa.DateTime(timezone=True)),
        sa.column("policy_sha256", sa.String(64)),
        sa.column("canonical_payload", sa.Text()),
    )
    with engine.begin() as connection:
        connection.execute(
            sa.insert(legacy_leases),
            [
                _legacy_lease_values(active_second),
                _legacy_lease_values(released_second),
                _legacy_lease_values(active_first),
                _legacy_lease_values(released_first),
            ],
        )
        connection.execute(
            sa.insert(phase2_account_lease_heads),
            [
                {
                    "account_id": active_second.account_id,
                    "last_fencing_generation": 1,
                    "current_fencing_generation": 1,
                    "current_lease_sha256": active_second.semantic_sha256,
                    "updated_at": active_second.heartbeat_at,
                },
                {
                    "account_id": released_second.account_id,
                    "last_fencing_generation": 1,
                    "current_fencing_generation": None,
                    "current_lease_sha256": None,
                    "updated_at": release.released_at,
                },
            ],
        )
        connection.execute(
            sa.insert(phase2_account_lease_releases),
            immutable_account_lease_release_values(release),
        )

    command.upgrade(config, "head")

    with engine.connect() as connection:
        upgraded_rows = tuple(
            connection.execute(
                sa.select(phase2_account_leases).order_by(
                    phase2_account_leases.c.account_id,
                    phase2_account_leases.c.revision_number,
                )
            ).mappings()
        )
        decoded = tuple(account_lease_from_row(row) for row in upgraded_rows)
        release_row = connection.execute(sa.select(phase2_account_lease_releases)).mappings().one()
    assert decoded == (active_first, active_second, released_first, released_second)
    assert [lease.revision_number for lease in decoded] == [1, 2, 1, 2]
    assert [lease.previous_lease_sha256 for lease in decoded] == [
        None,
        active_first.semantic_sha256,
        None,
        released_first.semantic_sha256,
    ]
    assert account_lease_release_from_row(release_row) == release
    with pytest.raises(AccountCoordinatorError, match="requires the v2 contract"):
        immutable_account_lease_values(active_first)

    command.downgrade(config, "0008_phase2_research")
    downgraded_columns = {
        column["name"] for column in inspect(engine).get_columns("phase2_account_leases")
    }
    assert "revision_number" not in downgraded_columns
    assert "previous_lease_sha256" not in downgraded_columns
    with engine.connect() as connection:
        assert connection.scalar(sa.select(sa.func.count()).select_from(legacy_leases)) == 4
        assert (
            connection.scalar(
                sa.select(phase2_account_lease_heads.c.current_lease_sha256).where(
                    phase2_account_lease_heads.c.account_id == active_second.account_id
                )
            )
            == active_second.semantic_sha256
        )
        assert (
            connection.scalar(sa.select(phase2_account_lease_releases.c.release_sha256))
            == release.semantic_sha256
        )

    command.upgrade(config, "head")
    authority = SqlAccountCoordinatorAuthority(
        engine=engine,
        policy=policy,
        clock=FixedClock(base + timedelta(seconds=20)),
    )
    active = SqlAccountCoordinator(
        account_id=active_second.account_id,
        authority=authority,
    )
    released = SqlAccountCoordinator(
        account_id=released_second.account_id,
        authority=authority,
    )
    assert active.current() == active_second
    assert released.current() is None

    renewed = active.renew(active_second.fence)
    reacquired = released.acquire("post-upgrade-worker")

    assert renewed.contract_version == ACCOUNT_LEASE_CONTRACT_VERSION
    assert renewed.revision_number == 3
    assert renewed.previous_lease_sha256 == active_second.semantic_sha256
    assert reacquired.contract_version == ACCOUNT_LEASE_CONTRACT_VERSION
    assert reacquired.fencing_generation == 2
    assert reacquired.revision_number == 1
    assert reacquired.previous_lease_sha256 is None

    with pytest.raises(
        RuntimeError,
        match="cannot downgrade after a v2 account lease revision has been persisted",
    ):
        command.downgrade(config, "0008_phase2_research")
    command.upgrade(config, "head")
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
            EXPECTED_SCHEMA_REVISION
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(phase2_account_leases)
                .where(
                    phase2_account_leases.c.previous_lease_sha256 == active_second.semantic_sha256
                )
            )
            == 1
        )

    released.release(reacquired.fence)
    legacy_after_v2 = _legacy_account_lease(
        account_id=reacquired.account_id,
        owner_id="corrupt-legacy-worker",
        lease_id=canonical_id(
            "account-coordinator-lease",
            reacquired.account_id,
            3,
            "corrupt-legacy-worker",
            base + timedelta(seconds=21),
            policy.semantic_sha256,
        ),
        fencing_generation=3,
        revision_number=1,
        previous_lease_sha256=None,
        acquired_at=base + timedelta(seconds=21),
        heartbeat_at=base + timedelta(seconds=21),
        expires_at=base + timedelta(seconds=51),
        policy_sha256=policy.semantic_sha256,
    )
    corrupt_values = {
        **_legacy_lease_values(legacy_after_v2),
        "revision_number": 1,
        "previous_lease_sha256": None,
    }
    with engine.begin() as connection:
        connection.execute(sa.insert(phase2_account_leases), corrupt_values)
        connection.execute(
            sa.update(phase2_account_lease_heads)
            .where(phase2_account_lease_heads.c.account_id == legacy_after_v2.account_id)
            .values(
                last_fencing_generation=3,
                current_fencing_generation=3,
                current_lease_sha256=legacy_after_v2.semantic_sha256,
                updated_at=legacy_after_v2.heartbeat_at,
            )
        )
    with pytest.raises(
        AccountCoordinatorError,
        match="legacy account lease revision cannot follow a v2 revision",
    ):
        released.current()
    engine.dispose()


def test_0008_decision_first_equal_time_release_upgrades_without_reinterpretation(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "phase2-capacity-ordering-upgrade.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")
    engine = create_database_engine(database_url)

    portfolio = make_portfolio(
        current={},
        instruments=("US-ETF-QQQ", "US-ETF-SPY"),
    )
    first_target, first_batch = make_batch(
        portfolio,
        desired={"US-ETF-SPY": Decimal("5")},
        target_id="legacy-same-time-parent",
    )
    second_target, second_batch = make_batch(
        portfolio,
        desired={"US-ETF-QQQ": Decimal("5")},
        target_id="legacy-same-time-observer",
    )
    capacity = snapshot(portfolio, available_cash=Decimal("700"))
    policy = AccountLeasePolicy(
        policy_id="phase2-sql-test-coordinator",
        policy_version="1.0.0",
        lease_ttl=timedelta(minutes=5),
        maximum_in_flight_duration=timedelta(seconds=5),
        takeover_safety_interval=timedelta(seconds=10),
    )
    legacy_lease = _legacy_account_lease(
        account_id=capacity.account_id,
        owner_id="legacy-ordering-worker",
        lease_id=canonical_id(
            "account-coordinator-lease",
            capacity.account_id,
            1,
            "legacy-ordering-worker",
            EVALUATED_AT,
            policy.semantic_sha256,
        ),
        fencing_generation=1,
        revision_number=1,
        previous_lease_sha256=None,
        acquired_at=EVALUATED_AT,
        heartbeat_at=EVALUATED_AT,
        expires_at=EVALUATED_AT + timedelta(minutes=5),
        policy_sha256=policy.semantic_sha256,
    )
    with engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_account_leases),
            {
                **_legacy_lease_values(legacy_lease),
                "revision_number": 1,
                "previous_lease_sha256": None,
            },
        )
        connection.execute(
            sa.insert(phase2_account_lease_heads),
            {
                "account_id": capacity.account_id,
                "last_fencing_generation": 1,
                "current_fencing_generation": 1,
                "current_lease_sha256": legacy_lease.semantic_sha256,
                "updated_at": EVALUATED_AT,
            },
        )
    authority = SqlAccountCoordinatorAuthority(
        engine=engine,
        policy=policy,
        clock=MutableClock(EVALUATED_AT),
    )
    coordinator = SqlAccountCoordinator(
        account_id=capacity.account_id,
        authority=authority,
    )
    assert coordinator.current() == legacy_lease
    first_risk = _repository(engine, capacity, coordinator, MutableClock(EVALUATED_AT))
    first = first_risk.authorize(first_batch, first_target, legacy_lease.fence)
    assert first.reservation is not None
    release_at = first.expires_at
    second_risk = _repository(engine, capacity, coordinator, MutableClock(release_at))
    second = second_risk.authorize(second_batch, second_target, legacy_lease.fence)
    assert second.status is BatchRiskDecisionStatus.REJECTED
    lifecycle = SqlReservationLifecycleRepository(engine=engine, coordinator=coordinator)
    released = lifecycle.expire_unsent(
        reservation_id=first.reservation.reservation_id,
        authorization_id=first.authorizations[0].decision_id,
        fence=legacy_lease.fence,
        finality_reference="legacy-decision-first-same-time-release",
        observed_at=release_at,
        recorded_at=release_at,
    )
    assert second_risk.get_batch(second.decision_id) == second

    with engine.connect() as connection:
        rows = tuple(
            connection.execute(
                sa.select(phase2_batch_decisions).order_by(
                    phase2_batch_decisions.c.account_observation_sequence
                )
            ).mappings()
        )
        legacy_payloads: dict[str, str] = {}
        for row in rows:
            decision_id = str(row["decision_id"])
            decision = load_batch_risk_decision(connection, decision_id)
            assert decision is not None
            legacy_payloads[decision_id] = _decision_fact_payload(
                decision,
                _decode_active_capacity(row["active_capacity_payload"]),
                int(row["account_observation_sequence"]),
                capacity_observation_contract=LEGACY_CAPACITY_OBSERVATION_CONTRACT,
                fencing_generation=int(row["fencing_generation"]),
                lease_sha256=str(row["lease_sha256"]),
                fence_sha256=str(row["fence_sha256"]),
            )
    with engine.begin() as connection:
        for decision_id, canonical_payload in legacy_payloads.items():
            connection.execute(
                sa.update(phase2_batch_decisions)
                .where(phase2_batch_decisions.c.decision_id == decision_id)
                .values(
                    capacity_observation_contract=LEGACY_CAPACITY_OBSERVATION_CONTRACT,
                    canonical_payload=canonical_payload,
                )
            )
        connection.execute(
            sa.update(phase2_reservation_release_events).values(
                visible_after_observation_sequence=0,
                capacity_visibility_sha256=None,
            )
        )
    with engine.connect() as connection:
        assert load_batch_risk_decision(connection, second.decision_id) == second
        _verify_phase2_durability_integrity(connection)

    engine.dispose()
    command.downgrade(config, "0008_phase2_research")
    legacy_engine = create_engine(database_url)
    assert "capacity_observation_contract" not in {
        column["name"] for column in inspect(legacy_engine).get_columns("phase2_batch_decisions")
    }
    assert "visible_after_observation_sequence" not in {
        column["name"]
        for column in inspect(legacy_engine).get_columns("phase2_reservation_release_events")
    }
    legacy_engine.dispose()

    command.upgrade(config, "head")
    upgraded_engine = create_database_engine(database_url)
    upgraded_authority = SqlAccountCoordinatorAuthority(
        engine=upgraded_engine,
        policy=policy,
        clock=MutableClock(release_at),
    )
    upgraded_coordinator = SqlAccountCoordinator(
        account_id=capacity.account_id,
        authority=upgraded_authority,
    )
    upgraded_risk = _repository(
        upgraded_engine,
        capacity,
        upgraded_coordinator,
        MutableClock(release_at),
    )
    assert upgraded_risk.get_batch(second.decision_id) == second
    upgraded_lifecycle = SqlReservationLifecycleRepository(
        engine=upgraded_engine,
        coordinator=upgraded_coordinator,
    )
    assert upgraded_lifecycle.history(first.reservation.reservation_id) == (released.fact,)
    with upgraded_engine.connect() as connection:
        migrated_decisions = tuple(
            connection.scalars(sa.select(phase2_batch_decisions.c.capacity_observation_contract))
        )
        marker, visibility_sha256 = connection.execute(
            sa.select(
                phase2_reservation_release_events.c.visible_after_observation_sequence,
                phase2_reservation_release_events.c.capacity_visibility_sha256,
            )
        ).one()
        assert migrated_decisions == (
            LEGACY_CAPACITY_OBSERVATION_CONTRACT,
            LEGACY_CAPACITY_OBSERVATION_CONTRACT,
        )
        assert marker == 0
        assert visibility_sha256 is None
        _verify_phase2_durability_integrity(connection)
    upgraded_engine.dispose()


def test_phase2_durability_checks_reject_ambiguous_facts_and_allow_unit_postings() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    metadata.create_all(engine)
    instant = datetime(2026, 7, 20, 14, 30, tzinfo=UTC)

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_submission_attempt_events).values(
                event_id="pending-not-first",
                attempt_id="attempt-not-required-for-check",
                sequence_number=2,
                state="pending",
                occurred_at=instant,
                recorded_at=instant,
                response_sha256=None,
                broker_order_id=None,
                error_class=None,
                canonical_payload="{}",
                semantic_sha256="a" * 64,
            )
        )

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_submission_attempt_events).values(
                event_id="in-flight-without-dispatch-receipt",
                attempt_id="attempt-not-required-for-check",
                sequence_number=2,
                state="in_flight",
                occurred_at=instant,
                recorded_at=instant,
                previous_event_sha256="a" * 64,
                canonical_payload="{}",
                semantic_sha256="b" * 64,
            )
        )

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_submission_attempt_events).values(
                event_id="abandoned-without-recovery-reason",
                attempt_id="attempt-not-required-for-check",
                sequence_number=2,
                state="abandoned",
                occurred_at=instant,
                recorded_at=instant,
                previous_event_sha256="a" * 64,
                canonical_payload="{}",
                semantic_sha256="c" * 64,
            )
        )

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_order_events).values(
                event_id="accepted-with-execution-fields",
                order_id="order-not-required-for-check",
                broker_order_id="broker-order",
                broker_sequence=1,
                occurred_at=instant,
                received_at=instant,
                kind="accepted",
                reason=None,
                execution_id="unexpected-execution",
                execution_revision=1,
                supersedes_event_id=None,
                quantity=Decimal(1),
                price=Decimal(1),
                fee=Decimal(0),
                canonical_payload="{}",
                semantic_sha256="d" * 64,
            )
        )

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_reservation_release_events).values(
                release_event_id="zero-release",
                reservation_id="reservation-not-required-for-check",
                authorization_id="authorization-not-required-for-check",
                order_id=None,
                attempt_id=None,
                order_event_id=None,
                reason="approval_expired_unsent",
                finality_reference="durably-never-dispatched",
                source_sha256="e" * 64,
                released_cash=Decimal(0),
                released_buy_exposure=Decimal(0),
                released_sell_quantity=Decimal(0),
                occurred_at=instant,
                recorded_at=instant,
                canonical_payload="{}",
                semantic_sha256="f" * 64,
            )
        )

    with engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_ledger_entries).values(
                entry_id="split-entry",
                account_id="simulation-account",
                kind="stock_split",
                reference_id="split-reference",
                source_sha256="e" * 64,
                effective_at=instant,
                recorded_at=instant,
                canonical_payload="{}",
                semantic_sha256="f" * 64,
            )
        )
        connection.execute(
            sa.insert(phase2_ledger_postings).values(
                entry_id="split-entry",
                line_number=1,
                account="security_units:instrument-a",
                currency="USD",
                debit=Decimal(0),
                credit=Decimal(0),
                units_delta=Decimal(5),
                instrument_id="instrument-a",
                semantic_sha256="1" * 64,
            )
        )

    with engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_ledger_postings)) == 1
        )


def test_phase_zero_database_upgrades_to_point_in_time_catalog(tmp_path: Path) -> None:
    database_path = tmp_path / "upgrade.sqlite"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{database_path}")

    command.upgrade(config, "0003_submission_attempts")
    engine = create_engine(f"sqlite+pysqlite:///{database_path}")
    assert "dataset_manifests" not in inspect(engine).get_table_names()

    command.upgrade(config, "0004_point_in_time_data")

    assert "dataset_manifests" in inspect(engine).get_table_names()
    assert "market_data_admission_runs" not in inspect(engine).get_table_names()

    command.upgrade(config, "0005_market_data_admission")

    assert "market_data_admission_runs" in inspect(engine).get_table_names()
    assert "replay_run_manifests" not in inspect(engine).get_table_names()
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO data_objects "
                "(object_id, object_key, byte_checksum, semantic_checksum, format, size_bytes, "
                "created_at) VALUES (:object_id, :object_key, :byte_checksum, "
                ":semantic_checksum, 'parquet', 1, :created_at)"
            ),
            {
                "object_id": "a" * 64,
                "object_key": f"normalized/sha256/aa/{'a' * 64}.parquet",
                "byte_checksum": "a" * 64,
                "semantic_checksum": "b" * 64,
                "created_at": "2026-07-18T00:00:00+00:00",
            },
        )
        connection.execute(
            text(
                "INSERT INTO dataset_partitions "
                "(partition_id, object_id, job_id, source_id, layer, status, schema_version, "
                "price_basis, row_count, event_time_start, event_time_end, available_at_start, "
                "available_at_end, semantic_checksum, created_at) VALUES "
                "(:partition_id, :object_id, :job_id, :source_id, 'normalized', 'published', "
                "'raw-bar-v1', 'raw', 1, :instant, :instant, :instant, :instant, "
                ":semantic_checksum, :instant)"
            ),
            {
                "partition_id": "c" * 64,
                "object_id": "a" * 64,
                "job_id": "d" * 64,
                "source_id": "legacy-fixture",
                "semantic_checksum": "b" * 64,
                "instant": "2026-07-18T00:00:00+00:00",
            },
        )
        connection.execute(
            text(
                "INSERT INTO calendar_versions "
                "(calendar_version, name, timezone, tzdata_version, content_hash, created_at) "
                "VALUES ('legacy-calendar', 'Legacy', 'UTC', '2026a', :hash, :created_at)"
            ),
            {"hash": "e" * 64, "created_at": "2026-07-18T00:00:00+00:00"},
        )
        connection.execute(
            text(
                "INSERT INTO universe_versions "
                "(universe_version, name, effective_as_of, created_at, content_hash) "
                "VALUES ('legacy-universe', 'Legacy', :created_at, :created_at, :hash)"
            ),
            {"hash": "f" * 64, "created_at": "2026-07-18T00:00:00+00:00"},
        )
        connection.execute(
            text(
                "INSERT INTO corporate_action_sets "
                "(corporate_action_version, name, content_hash, created_at) "
                "VALUES ('legacy-actions', 'Legacy', :hash, :created_at)"
            ),
            {"hash": "0" * 64, "created_at": "2026-07-18T00:00:00+00:00"},
        )

    command.upgrade(config, "head")

    assert "replay_run_manifests" in inspect(engine).get_table_names()
    assert "phase2_batch_members" in inspect(engine).get_table_names()
    assert "phase2_batch_reservations" in inspect(engine).get_table_names()
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
            EXPECTED_SCHEMA_REVISION
        )
        assert (
            connection.scalar(text("SELECT semantic_checksum_version FROM data_objects"))
            == "input-v1"
        )
        assert (
            connection.scalar(text("SELECT semantic_checksum_version FROM dataset_partitions"))
            == "input-v1"
        )
        for table_name in (
            "calendar_versions",
            "universe_versions",
            "corporate_action_sets",
        ):
            assert (
                connection.scalar(text(f"SELECT content_hash_version FROM {table_name}"))
                == "input-v1"
            )


def test_phase5_operational_control_migration_is_additive_and_reversible(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "phase5-operational-control.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(config, "0024_phase4_order_transition")
    engine = create_engine(database_url)
    prior_tables = set(inspect(engine).get_table_names())
    prior_columns = {
        table_name: tuple(column["name"] for column in inspect(engine).get_columns(table_name))
        for table_name in prior_tables
    }

    command.upgrade(config, "head")

    assert set(inspect(engine).get_table_names()) == (
        prior_tables
        | PHASE3_FIXTURE_WORKER_TABLE_NAMES
        | PHASE4_TABLE_NAMES
        | PHASE5_TABLE_NAMES
        | PHASE6_TABLE_NAMES
    )
    assert {
        table_name: tuple(column["name"] for column in inspect(engine).get_columns(table_name))
        for table_name in prior_tables
    } == prior_columns
    assert tuple(
        column["name"]
        for column in inspect(engine).get_columns("phase5_operational_control_transitions")
    ) == tuple(phase5_operational_control_transitions.c.keys())
    assert tuple(
        column["name"] for column in inspect(engine).get_columns("phase5_operational_control_heads")
    ) == tuple(phase5_operational_control_heads.c.keys())
    assert tuple(
        column["name"]
        for column in inspect(engine).get_columns("phase5_operational_control_completions")
    ) == tuple(phase5_operational_control_completions.c.keys())

    engine.dispose()
    command.downgrade(config, "0024_phase4_order_transition")
    downgraded_engine = create_engine(database_url)
    assert set(inspect(downgraded_engine).get_table_names()) == prior_tables
    downgraded_engine.dispose()


def test_phase5_operational_control_migration_refuses_nonempty_downgrade(
    tmp_path: Path,
) -> None:
    from packages.domain.operational_control import (
        OperationalControlActor,
        OperationalControlActorKind,
        OperationalControlCommand,
        OperationalControlCommandKind,
        OperationalControlState,
        apply_operational_control_command,
    )
    from packages.persistence.operational_control import _transition_values

    database_path = tmp_path / "phase5-operational-control-nonempty.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    instant = datetime(2026, 7, 28, 20, 0, tzinfo=UTC)
    initialization = OperationalControlCommand(
        scope_id="phase5-downgrade-account",
        idempotency_key="initialize-0001",
        kind=OperationalControlCommandKind.INITIALIZE_HALTED,
        target_state=OperationalControlState.HALTED,
        actor=OperationalControlActor(
            actor_id="startup",
            kind=OperationalControlActorKind.SYSTEM,
            authority_sha256="a" * 64,
            authenticated_at=None,
        ),
        reason_code="startup",
        reason_evidence_sha256="b" * 64,
        requested_at=instant,
    )
    transition = apply_operational_control_command(
        None,
        initialization,
        decided_at=instant,
    )
    with engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_account_lease_heads).values(
                account_id="phase5-downgrade-account",
                last_fencing_generation=0,
                current_fencing_generation=None,
                current_lease_sha256=None,
                updated_at=instant,
            )
        )
        connection.execute(
            sa.insert(phase5_operational_control_transitions).values(
                **_transition_values(
                    command=initialization,
                    transition=transition,
                    previous=None,
                )
            )
        )
    engine.dispose()

    with pytest.raises(
        RuntimeError,
        match="refusing to downgrade nonempty operational-control history",
    ):
        command.downgrade(config, "0024_phase4_order_transition")
