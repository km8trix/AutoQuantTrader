"""Database engine factory kept outside the pure domain packages."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from typing import Literal

import sqlalchemy as sa
from sqlalchemy import Connection, Engine, create_engine, make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import StaticPool

from packages.domain.replay_manifest import (
    ReplayManifestDecodeError,
    ReplayRunManifest,
)
from packages.domain.risk import RiskAuthorizationError
from packages.persistence.immutable import ImmutableFactConflict, as_aware_utc
from packages.persistence.postgres_tls import pinned_verify_full_connect_args
from packages.persistence.schema import (
    calendar_sessions,
    calendar_versions,
    corporate_action_revisions,
    corporate_action_set_members,
    corporate_action_sets,
    data_objects,
    data_quality_issues,
    data_quality_runs,
    dataset_manifest_partitions,
    dataset_manifests,
    dataset_partitions,
    fills,
    ingestion_jobs,
    instrument_identifiers,
    instruments,
    ledger_entries,
    ledger_postings,
    market_data_admission_checks,
    market_data_admission_profiles,
    market_data_admission_runs,
    market_data_entitlements,
    market_data_sources,
    orders,
    partition_quarantines,
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
    phase2_authorization_consumptions,
    phase2_backtest_audit_events,
    phase2_backtest_fixtures,
    phase2_backtest_job_events,
    phase2_backtest_job_heads,
    phase2_backtest_jobs,
    phase2_backtest_reports,
    phase2_backtest_run_manifests,
    phase2_batch_authorizations,
    phase2_batch_decisions,
    phase2_batch_members,
    phase2_batch_reservations,
    phase2_ledger_entries,
    phase2_ledger_postings,
    phase2_logical_orders,
    phase2_order_events,
    phase2_reservation_release_events,
    phase2_simulation_horizon_facts,
    phase2_strategy_configurations,
    phase2_strategy_versions,
    phase2_submission_attempt_events,
    phase2_submission_attempts,
    phase3_experiment_attempt_events,
    phase3_experiment_attempts,
    phase3_experiment_audit_events,
    phase3_experiment_families,
    phase3_experiment_tape_claims,
    phase3_experiment_tape_policies,
    phase3_holdout_reveals,
    phase4_alpaca_paper_account_activity_comparison_heads,
    phase4_alpaca_paper_account_activity_comparisons,
    phase4_alpaca_paper_account_activity_heads,
    phase4_alpaca_paper_account_activity_pages,
    phase4_alpaca_paper_account_activity_plans,
    phase4_alpaca_paper_account_activity_preparations,
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
    phase4_broker_request_heads,
    phase4_broker_request_permits,
    phase4_unknown_lookup_recovery_events,
    phase4_unknown_lookup_recovery_heads,
    phase4_unknown_lookup_recovery_plans,
    phase5_advanced_risk_assessments,
    phase5_advanced_risk_assignment_heads,
    phase5_advanced_risk_assignments,
    phase5_advanced_risk_batch_admissions,
    phase5_advanced_risk_batch_outcomes,
    phase5_advanced_risk_enforcement_heads,
    phase5_advanced_risk_evidence,
    phase5_advanced_risk_evidence_sources,
    phase5_advanced_risk_policies,
    phase5_critical_alert_delivery_attempts,
    phase5_critical_alert_delivery_results,
    phase5_critical_alert_failure_control_receipts,
    phase5_critical_alert_incidents,
    phase5_operational_control_completions,
    phase5_operational_control_heads,
    phase5_operational_control_transitions,
    phase5_strategy_invocation_claims,
    phase5_strategy_invocation_finalizations,
    phase5_strategy_supervision_results,
    phase6_trusted_time_epoch_registrations,
    phase6_trusted_time_head_anchor_intents,
    phase6_trusted_time_head_anchor_receipts,
    phase6_trusted_time_host_heads,
    phase6_trusted_time_probe_evaluations,
    replay_run_manifests,
    risk_account_guards,
    risk_decisions,
    risk_reservations,
    submission_attempts,
    universe_memberships,
    universe_versions,
)
from packages.persistence.sqlite_config import enforce_sqlite_foreign_keys

EXPECTED_SCHEMA_REVISION = "0036_phase6_time_anchors"


class DatabaseSchemaNotReady(RuntimeError):
    """The durable store is reachable but not at the required operational schema."""


def _verify_sealed_replay_integrity(connection: Connection) -> None:
    """Decode each sealed row and reuse the repository's full catalog verifier."""

    from packages.persistence.replay import verify_replay_dataset_catalog

    replay_rows = connection.execute(sa.select(replay_run_manifests)).mappings()
    for row in replay_rows:
        try:
            manifest = ReplayRunManifest.from_canonical_json(
                str(row["manifest_payload"]),
                expected_run_id=str(row["run_id"]),
                expected_manifest_sha256=str(row["manifest_sha256"]),
            )
        except ReplayManifestDecodeError as error:
            raise DatabaseSchemaNotReady(
                "sealed replay manifest payload verification failed"
            ) from error
        duplicated_values = {
            "idempotency_key": manifest.input_sha256,
            "dataset_manifest_id": manifest.dataset.manifest_id,
            "dataset_manifest_hash": manifest.dataset.manifest_sha256,
            "tape_sha256": manifest.tape_sha256,
            "replay_semantic_sha256": manifest.replay_semantic_sha256,
            "started_at": manifest.started_at,
            "completed_at": manifest.completed_at,
            "processed_event_count": manifest.processed_event_count,
            "batch_count": manifest.batch_count,
            "complete_batch_count": manifest.complete_batch_count,
            "skipped_batch_count": manifest.skipped_batch_count,
        }
        for field_name, expected in duplicated_values.items():
            actual = row[field_name]
            if isinstance(expected, datetime):
                if not isinstance(actual, datetime):
                    raise DatabaseSchemaNotReady(
                        "sealed replay manifest duplicated fields are malformed"
                    )
                actual = as_aware_utc(actual)
            if actual != expected:
                raise DatabaseSchemaNotReady(
                    "sealed replay manifest duplicated fields are inconsistent"
                )
        try:
            verify_replay_dataset_catalog(connection, manifest.dataset, manifest.plan)
        except ImmutableFactConflict as error:
            raise DatabaseSchemaNotReady(
                "sealed replay manifest catalog verification failed"
            ) from error


def _verify_data_plane_integrity(connection: Connection) -> None:
    _verify_sealed_replay_integrity(connection)
    queries = (
        """
        SELECT 1
        FROM dataset_partitions AS partition
        LEFT JOIN data_objects AS object
          ON object.object_id = partition.object_id
        WHERE object.object_id IS NULL
           OR object.semantic_checksum <> partition.semantic_checksum
           OR (
             partition.status = 'quarantined'
             AND NOT EXISTS (
               SELECT 1 FROM partition_quarantines AS quarantine
               WHERE quarantine.partition_id = partition.partition_id
             )
           )
           OR (
             partition.status = 'published'
             AND EXISTS (
               SELECT 1 FROM partition_quarantines AS quarantine
               WHERE quarantine.partition_id = partition.partition_id
             )
           )
        LIMIT 1
        """,
        """
        SELECT 1
        FROM phase2_batch_decisions AS decision
        LEFT JOIN (
          SELECT decision_id, COUNT(*) AS member_count
          FROM phase2_batch_members
          GROUP BY decision_id
        ) AS member
          ON member.decision_id = decision.decision_id
        WHERE COALESCE(member.member_count, 0) <> decision.intent_count
        UNION ALL
        SELECT 1
        FROM phase2_batch_members AS member
        JOIN phase2_batch_decisions AS decision
          ON decision.decision_id = member.decision_id
        WHERE member.intent_batch_id <> decision.intent_batch_id
           OR member.intent_batch_sha256 <> decision.intent_batch_sha256
        UNION ALL
        SELECT 1
        FROM phase2_batch_authorizations AS authz
        LEFT JOIN phase2_batch_members AS member
          ON member.decision_id = authz.parent_decision_id
         AND member.intent_id = authz.intent_id
        WHERE member.membership_id IS NULL
           OR member.intent_payload_sha256 <> authz.intent_payload_sha256
        LIMIT 1
        """,
        """
        SELECT 1
        FROM dataset_manifests AS manifest
        LEFT JOIN dataset_manifest_partitions AS member
          ON member.manifest_id = manifest.manifest_id
        LEFT JOIN dataset_partitions AS partition
          ON partition.partition_id = member.partition_id
        GROUP BY manifest.manifest_id, manifest.row_count
        HAVING COUNT(member.partition_id) = 0
            OR COUNT(member.partition_id) <> COUNT(partition.partition_id)
            OR MIN(partition.status) <> 'published'
            OR MAX(partition.status) <> 'published'
            OR MIN(partition.layer) <> 'normalized'
            OR MAX(partition.layer) <> 'normalized'
            OR COALESCE(SUM(partition.row_count), 0) <> manifest.row_count
            OR MIN(member.ordinal) <> 0
            OR MAX(member.ordinal) <> COUNT(member.ordinal) - 1
        LIMIT 1
        """,
        """
        SELECT 1
        FROM market_data_admission_runs AS run
        LEFT JOIN market_data_admission_profiles AS profile
          ON profile.profile_id = run.profile_id
        LEFT JOIN market_data_sources AS source
          ON source.source_id = run.source_id
        LEFT JOIN (
          SELECT admission_run_id,
                 SUM(CASE WHEN status = 'passed' THEN 1 ELSE 0 END) AS passed_count,
                 SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed_count,
                 SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending_count
          FROM market_data_admission_checks
          GROUP BY admission_run_id
        ) AS check_counts
          ON check_counts.admission_run_id = run.admission_run_id
        WHERE profile.profile_id IS NULL
           OR source.source_id IS NULL
           OR profile.source_id <> run.source_id
           OR COALESCE(check_counts.passed_count, 0) <> run.passed_check_count
           OR COALESCE(check_counts.failed_count, 0) <> run.failed_check_count
           OR COALESCE(check_counts.pending_count, 0) <> run.pending_check_count
           OR (
             run.status = 'admitted'
             AND (
               run.manifest_id IS NULL
               OR source.kind <> 'vendor'
               OR NOT source.licensed
               OR run.review_decision <> 'approved'
               OR run.reviewed_by = run.executed_by
               OR run.failed_check_count <> 0
               OR run.pending_check_count <> 0
               OR NOT EXISTS (
                 SELECT 1
                 FROM market_data_entitlements AS entitlement
                 WHERE entitlement.source_id = run.source_id
                   AND entitlement.status = 'active'
                   AND entitlement.effective_from <= run.executed_at
                   AND (
                     entitlement.effective_to IS NULL
                     OR run.executed_at < entitlement.effective_to
                   )
               )
             )
           )
        LIMIT 1
        """,
        """
        SELECT 1
        FROM replay_run_manifests AS run
        LEFT JOIN dataset_manifests AS manifest
          ON manifest.manifest_id = run.dataset_manifest_id
        LEFT JOIN market_data_sources AS source
          ON source.source_id = manifest.source_id
        WHERE manifest.manifest_id IS NULL
           OR source.source_id IS NULL
           OR run.dataset_manifest_hash <> manifest.manifest_hash
           OR run.run_id <> run.manifest_sha256
           OR length(run.run_id) <> 64
           OR length(run.idempotency_key) <> 64
           OR length(run.dataset_manifest_id) <> 64
           OR length(run.dataset_manifest_hash) <> 64
           OR length(run.manifest_sha256) <> 64
           OR length(run.tape_sha256) <> 64
           OR length(run.replay_semantic_sha256) <> 64
           OR length(run.manifest_payload) > 65536
           OR run.completed_at < run.started_at
           OR run.processed_event_count < 0
           OR run.batch_count <= 0
           OR run.complete_batch_count < 0
           OR run.skipped_batch_count < 0
           OR run.complete_batch_count + run.skipped_batch_count <> run.batch_count
           OR source.kind NOT IN ('synthetic_fixture', 'recorded_fixture')
           OR source.licensed
           OR NOT EXISTS (
             SELECT 1
             FROM market_data_entitlements AS entitlement
             WHERE entitlement.source_id = source.source_id
               AND entitlement.status = 'fixture_only'
           )
        LIMIT 1
        """,
    )
    for query in queries:
        if connection.scalar(sa.text(query)) is not None:
            raise DatabaseSchemaNotReady("point-in-time data catalog integrity verification failed")


def _verify_phase2_canonical_execution_facts(connection: Connection) -> None:
    """Strictly decode every immutable Phase 2 execution fact and projection source."""

    from packages.domain.account_coordinator import (
        AccountCoordinatorError,
        AccountLease,
        AccountLeaseRelease,
    )
    from packages.domain.batch_risk import BatchRiskDecision, BatchRiskFactConflict
    from packages.domain.ledger_reducer import (
        CanonicalLedgerEntry,
        LedgerEntryKind,
        LedgerReductionError,
        reduce_execution_ledger,
    )
    from packages.domain.order_reducer import BrokerOrderEventKind
    from packages.domain.reservation_lifecycle import (
        ReservationLifecycleError,
        ReservationReleaseFact,
        ReservationReleaseReason,
    )
    from packages.domain.submission_attempt import SubmissionAttemptError
    from packages.persistence.account_coordinator import (
        _lease_head_from_row,
        account_lease_from_row,
        account_lease_release_from_row,
        verify_account_lease_history,
    )
    from packages.persistence.batch_risk import load_batch_risk_decision
    from packages.persistence.phase2_ledger import (
        load_phase2_ledger_entry,
        verify_phase2_ledger_integrity,
    )
    from packages.persistence.reservation_lifecycle import (
        load_canonical_order_state,
        verify_reservation_correction_integrity,
        verify_reservation_release_integrity,
        verify_simulation_horizon_release_binding,
    )
    from packages.persistence.simulation_horizon import (
        SimulationHorizonPersistenceError,
        load_simulation_horizon_fact,
        verify_simulation_horizon_integrity,
    )
    from packages.persistence.submission_attempt import load_submission_attempt

    try:
        leases = tuple(
            account_lease_from_row(row)
            for row in connection.execute(sa.select(phase2_account_leases)).mappings()
        )
        heads = tuple(
            _lease_head_from_row(row)
            for row in connection.execute(sa.select(phase2_account_lease_heads)).mappings()
        )
        releases = tuple(
            account_lease_release_from_row(row)
            for row in connection.execute(sa.select(phase2_account_lease_releases)).mappings()
        )
        heads_by_account = {head.account_id: head for head in heads}
        leases_by_account: dict[str, list[AccountLease]] = {}
        for lease in leases:
            leases_by_account.setdefault(lease.account_id, []).append(lease)
        releases_by_account: dict[str, list[AccountLeaseRelease]] = {}
        for release in releases:
            releases_by_account.setdefault(release.fence.account_id, []).append(release)
        if set(heads_by_account) != set(leases_by_account) or not set(releases_by_account).issubset(
            heads_by_account
        ):
            raise AccountCoordinatorError(
                "account lease history and durable heads cover different accounts"
            )
        for account_id, account_leases in leases_by_account.items():
            verify_account_lease_history(
                account_id=account_id,
                head=heads_by_account[account_id],
                leases=account_leases,
                releases=releases_by_account.get(account_id, ()),
            )

        decisions: dict[str, BatchRiskDecision] = {}
        for decision_id in connection.scalars(sa.select(phase2_batch_decisions.c.decision_id)):
            decision = load_batch_risk_decision(connection, decision_id)
            if decision is None:
                raise BatchRiskFactConflict("persisted batch decision disappeared during verify")
            decisions[decision_id] = decision
        for attempt_id in connection.scalars(sa.select(phase2_submission_attempts.c.attempt_id)):
            if load_submission_attempt(connection, attempt_id) is None:
                raise SubmissionAttemptError(
                    "persisted submission attempt disappeared during verify"
                )
        expected_execution_entries: dict[str, tuple[str, CanonicalLedgerEntry]] = {}
        expected_execution_chains: dict[tuple[str, str], frozenset[str]] = {}
        expected_execution_visibility: dict[str, int] = {}
        order_rows = connection.execute(
            sa.select(
                phase2_logical_orders.c.submission_attempt_id,
                phase2_logical_orders.c.parent_decision_id,
            )
        ).mappings()
        for order_row in order_rows:
            attempt_id = str(order_row["submission_attempt_id"])
            order_state = load_canonical_order_state(connection, attempt_id)
            if order_state is None:
                raise ReservationLifecycleError("persisted logical order disappeared during verify")
            decision = decisions.get(str(order_row["parent_decision_id"]))
            if decision is None:
                raise BatchRiskFactConflict("persisted logical order lacks its risk decision")
            reduced_entries = reduce_execution_ledger(
                order_states=(order_state,),
                execution_currency=decision.currency,
            ).entries
            entries_by_reference = {entry.reference_id: entry for entry in reduced_entries}
            event_visibility = {
                str(event_id): int(visible_after)
                for event_id, visible_after in connection.execute(
                    sa.select(
                        phase2_order_events.c.event_id,
                        phase2_order_events.c.visible_after_observation_sequence,
                    ).where(phase2_order_events.c.order_id == order_state.submission.order_id)
                )
            }
            chain_entry_ids: dict[str, set[str]] = {}
            for event in order_state.broker_events:
                if event.kind not in {
                    BrokerOrderEventKind.EXECUTION,
                    BrokerOrderEventKind.EXECUTION_CORRECTION,
                }:
                    continue
                assert event.execution_id is not None
                entry = entries_by_reference.get(event.event_id)
                if entry is not None:
                    chain_entry_ids.setdefault(event.execution_id, set()).add(entry.entry_id)
                    expected_execution_visibility[entry.entry_id] = event_visibility[event.event_id]
            for execution_id, entry_ids in chain_entry_ids.items():
                expected_execution_chains[(order_state.submission.order_id, execution_id)] = (
                    frozenset(entry_ids)
                )
            for entry in reduced_entries:
                expected = (decision.account_id, entry)
                prior = expected_execution_entries.get(entry.entry_id)
                if prior is not None and prior != expected:
                    raise LedgerReductionError(
                        "execution ledger identity has conflicting order economics"
                    )
                expected_execution_entries[entry.entry_id] = expected
        reservation_releases: list[ReservationReleaseFact] = []
        for reservation_id in connection.scalars(
            sa.select(phase2_batch_reservations.c.reservation_id)
        ):
            verify_reservation_correction_integrity(connection, str(reservation_id))
            reservation_releases.extend(
                verify_reservation_release_integrity(connection, str(reservation_id))
            )
        verify_simulation_horizon_integrity(connection)
        horizon_release_ids: set[str] = set()
        for horizon_id in connection.scalars(
            sa.select(phase2_simulation_horizon_facts.c.horizon_id)
        ):
            horizon = load_simulation_horizon_fact(connection, str(horizon_id))
            if horizon is None:
                raise SimulationHorizonPersistenceError(
                    "persisted simulation horizon disappeared during verification"
                )
            horizon_release_ids.add(
                verify_simulation_horizon_release_binding(
                    connection,
                    horizon,
                ).release_event_id
            )
        persisted_horizon_release_ids = {
            release.release_event_id
            for release in reservation_releases
            if release.reason is ReservationReleaseReason.SIMULATION_HORIZON_FINAL
        }
        if horizon_release_ids != persisted_horizon_release_ids:
            raise SimulationHorizonPersistenceError(
                "simulation-horizon proofs and releases are not one-to-one"
            )
        legacy_execution_entry_ids = frozenset(
            str(entry_id)
            for entry_id in connection.scalars(
                sa.select(phase2_reservation_release_events.c.finality_reference).where(
                    phase2_reservation_release_events.c.reason
                    == ReservationReleaseReason.EXECUTION_ACCOUNTED.value,
                    phase2_reservation_release_events.c.visible_after_observation_sequence == 0,
                    phase2_reservation_release_events.c.capacity_visibility_sha256.is_(None),
                )
            )
        )
        verify_phase2_ledger_integrity(connection)
        for reservation_release in reservation_releases:
            if reservation_release.reason is not ReservationReleaseReason.EXECUTION_ACCOUNTED:
                continue
            release_ledger = load_phase2_ledger_entry(
                connection,
                reservation_release.finality_reference,
            )
            release_decision = decisions.get(reservation_release.parent_decision_id)
            expected_ledger = expected_execution_entries.get(reservation_release.finality_reference)
            if (
                release_ledger is None
                or release_decision is None
                or expected_ledger != release_ledger
            ):
                raise LedgerReductionError(
                    "accounted execution release lacks its exact canonical ledger evidence"
                )
            account_id, entry = release_ledger
            if (
                account_id != release_decision.account_id
                or entry.entry_id != reservation_release.finality_reference
                or entry.reference_id != reservation_release.order_event_id
                or entry.source_sha256 != reservation_release.order_event_sha256
                or entry.semantic_sha256 != reservation_release.source_sha256
                or entry.effective_at > reservation_release.occurred_at
                or entry.recorded_at > reservation_release.occurred_at
            ):
                raise LedgerReductionError(
                    "accounted execution release conflicts with its canonical ledger evidence"
                )
        persisted_execution_entry_ids: set[str] = set()
        for entry_id in connection.scalars(sa.select(phase2_ledger_entries.c.entry_id)):
            persisted = load_phase2_ledger_entry(connection, entry_id)
            if persisted is None:
                raise LedgerReductionError("Phase 2 ledger entry disappeared during verify")
            _, entry = persisted
            if (
                entry.kind
                in {
                    LedgerEntryKind.EXECUTION,
                    LedgerEntryKind.EXECUTION_CORRECTION,
                }
                and expected_execution_entries.get(entry.entry_id) != persisted
            ):
                raise LedgerReductionError(
                    "Phase 2 execution ledger entry conflicts with reducer-derived economics"
                )
            if entry.kind in {
                LedgerEntryKind.EXECUTION,
                LedgerEntryKind.EXECUTION_CORRECTION,
            }:
                persisted_execution_entry_ids.add(entry.entry_id)
        for expected_chain in expected_execution_chains.values():
            persisted_chain = expected_chain & persisted_execution_entry_ids
            missing_chain = expected_chain - persisted_chain
            legacy_partial = persisted_chain.issubset(legacy_execution_entry_ids) and all(
                expected_execution_visibility[entry_id] == 0 for entry_id in missing_chain
            )
            if persisted_chain and persisted_chain != expected_chain and not legacy_partial:
                raise LedgerReductionError(
                    "Phase 2 execution ledger contains a partial execution revision chain"
                )
    except (
        AccountCoordinatorError,
        BatchRiskFactConflict,
        LedgerReductionError,
        ReservationLifecycleError,
        SimulationHorizonPersistenceError,
        SubmissionAttemptError,
    ) as error:
        raise DatabaseSchemaNotReady(
            "Phase 2 canonical execution evidence verification failed"
        ) from error


def _verify_phase2_durability_integrity(connection: Connection) -> None:
    """Reject relationally inconsistent Phase 2 execution evidence."""

    queries = (
        """
        SELECT 1
        FROM phase2_account_lease_heads AS head
        LEFT JOIN phase2_account_leases AS lease
          ON lease.account_id = head.account_id
         AND lease.fencing_generation = head.current_fencing_generation
         AND lease.lease_sha256 = head.current_lease_sha256
        WHERE head.current_lease_sha256 IS NOT NULL
          AND lease.lease_sha256 IS NULL
        LIMIT 1
        """,
        """
        SELECT 1
        FROM phase2_account_lease_releases AS release
        JOIN phase2_account_leases AS lease
          ON lease.lease_sha256 = release.lease_sha256
        WHERE lease.account_id <> release.account_id
           OR lease.owner_id <> release.owner_id
           OR lease.lease_id <> release.lease_id
           OR lease.fencing_generation <> release.fencing_generation
           OR lease.policy_sha256 <> release.policy_sha256
        LIMIT 1
        """,
        """
        SELECT 1
        FROM phase2_batch_decisions AS decision
        LEFT JOIN phase2_batch_reservations AS reservation
          ON reservation.parent_decision_id = decision.decision_id
        LEFT JOIN (
          SELECT parent_decision_id, COUNT(*) AS authorization_count
          FROM phase2_batch_authorizations
          GROUP BY parent_decision_id
        ) AS authz_summary
          ON authz_summary.parent_decision_id = decision.decision_id
        WHERE (
                decision.status = 'approved'
                AND (
                  reservation.reservation_id IS NULL
                  OR COALESCE(authz_summary.authorization_count, 0) <> decision.intent_count
                )
              )
           OR (
                decision.status <> 'approved'
                AND (
                  reservation.reservation_id IS NOT NULL
                  OR COALESCE(authz_summary.authorization_count, 0) <> 0
                )
              )
           OR (
                reservation.reservation_id IS NOT NULL
                AND (
                  reservation.intent_batch_id <> decision.intent_batch_id
                  OR reservation.intent_batch_sha256 <> decision.intent_batch_sha256
                  OR reservation.account_id <> decision.account_id
                  OR reservation.fencing_generation <> decision.fencing_generation
                  OR reservation.lease_sha256 <> decision.lease_sha256
                  OR reservation.fence_sha256 <> decision.fence_sha256
                  OR reservation.snapshot_sha256 <> decision.snapshot_sha256
                  OR reservation.policy_sha256 <> decision.policy_sha256
                  OR reservation.currency <> decision.currency
                  OR reservation.authorization_count <> decision.intent_count
                )
              )
        LIMIT 1
        """,
        """
        SELECT 1
        FROM phase2_batch_reservations AS reservation
        LEFT JOIN (
          SELECT reservation_id,
                 COUNT(*) AS child_count,
                 COALESCE(SUM(reserved_cash), 0) AS reserved_cash,
                 COALESCE(SUM(reserved_buy_exposure), 0) AS reserved_buy_exposure
          FROM phase2_batch_authorizations
          GROUP BY reservation_id
        ) AS child
          ON child.reservation_id = reservation.reservation_id
        WHERE COALESCE(child.child_count, 0) <> reservation.authorization_count
           OR COALESCE(child.reserved_cash, 0) <> reservation.initial_cash
           OR COALESCE(child.reserved_buy_exposure, 0) <> reservation.initial_buy_exposure
        LIMIT 1
        """,
        """
        SELECT 1
        FROM phase2_logical_orders AS submitted_order
        LEFT JOIN phase2_batch_authorizations AS authz
          ON authz.authorization_id = submitted_order.authorization_id
        LEFT JOIN phase2_authorization_consumptions AS consumption
          ON consumption.authorization_id = submitted_order.authorization_id
        LEFT JOIN phase2_submission_attempts AS attempt
          ON attempt.attempt_id = submitted_order.submission_attempt_id
        WHERE authz.authorization_id IS NULL
           OR authz.parent_decision_id <> submitted_order.parent_decision_id
           OR authz.reservation_id <> submitted_order.reservation_id
           OR authz.intent_batch_id <> submitted_order.intent_batch_id
           OR authz.intent_id <> submitted_order.intent_id
           OR authz.intent_payload_sha256 <> submitted_order.intent_payload_sha256
           OR authz.account_id <> submitted_order.account_id
           OR authz.fencing_generation <> submitted_order.fencing_generation
           OR authz.fence_sha256 <> submitted_order.fence_sha256
           OR consumption.consumption_id IS NULL
           OR consumption.order_id <> submitted_order.order_id
           OR consumption.reservation_id <> submitted_order.reservation_id
           OR consumption.intent_id <> submitted_order.intent_id
           OR consumption.intent_payload_sha256 <> submitted_order.intent_payload_sha256
           OR attempt.attempt_id IS NULL
           OR attempt.order_id <> submitted_order.order_id
           OR attempt.client_order_id <> submitted_order.client_order_id
           OR attempt.parent_decision_id <> submitted_order.parent_decision_id
           OR attempt.authorization_id <> submitted_order.authorization_id
           OR attempt.reservation_id <> submitted_order.reservation_id
           OR attempt.intent_id <> submitted_order.intent_id
           OR attempt.intent_payload_sha256 <> submitted_order.intent_payload_sha256
           OR attempt.account_id <> submitted_order.account_id
           OR attempt.fencing_generation <> submitted_order.fencing_generation
           OR attempt.lease_sha256 <> submitted_order.lease_sha256
           OR attempt.fence_sha256 <> submitted_order.fence_sha256
           OR attempt.risk_decision_sha256 <> (
                SELECT semantic_sha256
                FROM phase2_batch_decisions
                WHERE decision_id = submitted_order.parent_decision_id
              )
           OR attempt.authorization_sha256 <> authz.semantic_sha256
        LIMIT 1
        """,
        """
        SELECT 1
        FROM phase2_submission_attempts AS attempt
        LEFT JOIN (
          SELECT attempt_id,
                 COUNT(*) AS event_count,
                 MIN(sequence_number) AS first_sequence,
                 MAX(sequence_number) AS last_sequence,
                 SUM(CASE WHEN sequence_number = 1 AND state = 'pending' THEN 1 ELSE 0 END)
                   AS pending_first_count
          FROM phase2_submission_attempt_events
          GROUP BY attempt_id
        ) AS event
          ON event.attempt_id = attempt.attempt_id
        WHERE COALESCE(event.event_count, 0) = 0
           OR event.first_sequence <> 1
           OR event.last_sequence <> event.event_count
           OR event.pending_first_count <> 1
        LIMIT 1
        """,
        """
        SELECT 1
        FROM (
          SELECT attempt_id,
                 sequence_number,
                 state,
                 previous_event_sha256,
                 LAG(state) OVER (
                   PARTITION BY attempt_id ORDER BY sequence_number
                 ) AS prior_state,
                 LAG(semantic_sha256) OVER (
                   PARTITION BY attempt_id ORDER BY sequence_number
                 ) AS prior_sha256
          FROM phase2_submission_attempt_events
        ) AS history
        WHERE (history.sequence_number > 1
               AND history.previous_event_sha256 <> history.prior_sha256)
           OR (history.sequence_number > 1 AND NOT (
                (history.prior_state = 'pending' AND history.state = 'in_flight')
                OR (history.prior_state = 'pending' AND history.state = 'abandoned')
                OR (history.prior_state = 'in_flight'
                    AND history.state IN ('confirmed', 'unknown'))
                OR (history.prior_state = 'unknown' AND history.state = 'resolved')
              ))
        LIMIT 1
        """,
        """
        SELECT 1
        FROM phase2_submission_attempt_events AS dispatch
        JOIN phase2_submission_attempts AS attempt
          ON attempt.attempt_id = dispatch.attempt_id
        LEFT JOIN phase2_account_leases AS lease
          ON lease.account_id = dispatch.dispatch_account_id
         AND lease.fencing_generation = dispatch.dispatch_fencing_generation
         AND lease.lease_sha256 = dispatch.dispatch_lease_sha256
        WHERE dispatch.state = 'in_flight'
          AND (
            lease.lease_sha256 IS NULL
            OR dispatch.dispatch_account_id <> attempt.account_id
            OR dispatch.dispatch_fencing_generation <> attempt.fencing_generation
            OR dispatch.dispatch_fence_sha256 <> attempt.fence_sha256
            OR dispatch.dispatch_fence_validated_at <> dispatch.occurred_at
            OR dispatch.dispatch_fence_validated_at < lease.heartbeat_at
            OR dispatch.dispatch_fence_valid_until <> lease.expires_at
          )
        LIMIT 1
        """,
        """
        SELECT 1
        FROM phase2_submission_attempt_events
        WHERE state = 'resolved'
        LIMIT 1
        """,
        """
        WITH attempt_heads AS (
          SELECT event.attempt_id, event.state
          FROM phase2_submission_attempt_events AS event
          JOIN (
            SELECT attempt_id, MAX(sequence_number) AS sequence_number
            FROM phase2_submission_attempt_events
            GROUP BY attempt_id
          ) AS head
            ON head.attempt_id = event.attempt_id
           AND head.sequence_number = event.sequence_number
        ), frozen_parents AS (
          SELECT attempt.reservation_id,
                 SUM(CASE WHEN head.state = 'unknown' THEN 1 ELSE 0 END) AS unknown_count
          FROM phase2_submission_attempts AS attempt
          JOIN attempt_heads AS head ON head.attempt_id = attempt.attempt_id
          GROUP BY attempt.reservation_id
        ), correction_frozen AS (
          SELECT DISTINCT attempt.reservation_id
          FROM phase2_order_events AS correction
          JOIN phase2_submission_attempts AS attempt
            ON attempt.order_id = correction.order_id
          JOIN phase2_order_events AS predecessor
            ON predecessor.event_id = correction.supersedes_event_id
           AND predecessor.order_id = correction.order_id
           AND predecessor.execution_id = correction.execution_id
          WHERE correction.kind = 'execution_correction'
            AND NOT EXISTS (
              SELECT 1
              FROM phase2_submission_attempts AS retry
              WHERE retry.order_id = attempt.order_id
                AND retry.attempt_number > attempt.attempt_number
            )
            AND predecessor.broker_sequence < correction.broker_sequence
            AND correction.quantity <= predecessor.quantity
            AND NOT EXISTS (
              SELECT 1
              FROM phase2_reservation_release_events AS legacy_accounting
              WHERE legacy_accounting.reservation_id = attempt.reservation_id
                AND legacy_accounting.authorization_id = attempt.authorization_id
                AND legacy_accounting.attempt_id = attempt.attempt_id
                AND legacy_accounting.order_id = attempt.order_id
                AND legacy_accounting.order_event_id = correction.event_id
                AND legacy_accounting.reason = 'execution_accounted'
                AND legacy_accounting.visible_after_observation_sequence = 0
                AND legacy_accounting.capacity_visibility_sha256 IS NULL
            )
            AND NOT EXISTS (
              SELECT 1
              FROM phase2_reservation_release_events AS closure
              WHERE closure.reservation_id = attempt.reservation_id
                AND closure.authorization_id = attempt.authorization_id
                AND closure.attempt_id = attempt.attempt_id
                AND closure.order_id = attempt.order_id
                AND closure.reason IN (
                  'reconciled_terminal',
                  'simulation_horizon_final'
                )
                AND closure.occurred_at >= correction.received_at
            )
        )
        SELECT 1
        FROM phase2_batch_reservations AS reservation
        LEFT JOIN frozen_parents AS parent
          ON parent.reservation_id = reservation.reservation_id
        LEFT JOIN correction_frozen AS correction
          ON correction.reservation_id = reservation.reservation_id
        WHERE (COALESCE(parent.unknown_count, 0) > 0 AND reservation.state <> 'frozen')
           OR (
                correction.reservation_id IS NOT NULL
                AND reservation.state NOT IN ('frozen', 'released')
              )
           OR (
                reservation.state = 'frozen'
                AND COALESCE(parent.unknown_count, 0) = 0
                AND correction.reservation_id IS NULL
              )
        LIMIT 1
        """,
        """
        SELECT 1
        FROM phase2_reservation_release_events AS release
        JOIN phase2_submission_attempts AS attempt
          ON attempt.attempt_id = release.attempt_id
        WHERE EXISTS (
          SELECT 1
          FROM phase2_submission_attempts AS retry
          WHERE retry.order_id = attempt.order_id
            AND retry.authorization_id = attempt.authorization_id
            AND retry.attempt_number > attempt.attempt_number
        )
        LIMIT 1
        """,
        """
        SELECT 1
        FROM phase2_reservation_release_events AS release
        WHERE release.reason = 'reconciled_terminal'
        LIMIT 1
        """,
        """
        SELECT 1
        FROM phase2_reservation_release_events AS release
        JOIN phase2_batch_authorizations AS authz
          ON authz.authorization_id = release.authorization_id
        WHERE authz.reservation_id <> release.reservation_id
        UNION ALL
        SELECT 1
        FROM phase2_batch_authorizations AS authz
        JOIN (
          SELECT authorization_id,
                 COALESCE(SUM(released_cash), 0) AS released_cash,
                 COALESCE(SUM(released_buy_exposure), 0) AS released_buy_exposure,
                 COALESCE(SUM(released_sell_quantity), 0) AS released_sell_quantity
          FROM phase2_reservation_release_events
          GROUP BY authorization_id
        ) AS release_totals
          ON release_totals.authorization_id = authz.authorization_id
        WHERE release_totals.released_cash > authz.reserved_cash
           OR release_totals.released_buy_exposure > authz.reserved_buy_exposure
           OR release_totals.released_sell_quantity > authz.reserved_sell_quantity
        LIMIT 1
        """,
        """
        SELECT 1
        FROM phase2_logical_orders AS submitted_order
        JOIN (
          SELECT order_id,
                 COUNT(*) AS event_count,
                 MIN(broker_sequence) AS first_sequence,
                 MAX(broker_sequence) AS last_sequence
          FROM phase2_order_events
          GROUP BY order_id
        ) AS event
          ON event.order_id = submitted_order.order_id
        WHERE event.first_sequence <> 1
           OR event.last_sequence <> event.event_count
        LIMIT 1
        """,
        """
        SELECT 1
        FROM phase2_ledger_entries AS entry
        LEFT JOIN phase2_ledger_postings AS posting
          ON posting.entry_id = entry.entry_id
        GROUP BY entry.entry_id
        HAVING COUNT(posting.posting_id) = 0
            OR COALESCE(SUM(posting.debit), 0) <> COALESCE(SUM(posting.credit), 0)
            OR COUNT(DISTINCT posting.currency) <> 1
        LIMIT 1
        """,
    )
    for query in queries:
        if connection.scalar(sa.text(query)) is not None:
            raise DatabaseSchemaNotReady("Phase 2 durable execution integrity verification failed")
    _verify_phase2_canonical_execution_facts(connection)
    from packages.domain.batch_risk import BatchRiskFactConflict
    from packages.persistence.batch_risk import verify_batch_reservation_heads

    try:
        verify_batch_reservation_heads(connection)
    except BatchRiskFactConflict as error:
        raise DatabaseSchemaNotReady(
            "Phase 2 durable reservation head verification failed"
        ) from error


def _verify_phase2_research_integrity(connection: Connection) -> None:
    """Reject corrupt job chains, cached heads, catalogs, and result artifacts."""

    digest_payloads = (
        (phase2_strategy_versions, "semantic_sha256", "canonical_payload"),
        (
            phase2_strategy_versions,
            "parameter_schema_sha256",
            "parameter_schema_payload",
        ),
        (
            phase2_strategy_versions,
            "presentation_sha256",
            "presentation_payload",
        ),
        (phase2_strategy_configurations, "semantic_sha256", "canonical_payload"),
        (phase2_backtest_fixtures, "semantic_sha256", "canonical_payload"),
        (phase2_backtest_jobs, "semantic_sha256", "canonical_payload"),
        (phase2_backtest_reports, "report_sha256", "semantic_payload"),
        (phase2_backtest_reports, "report_artifact_sha256", "artifact_payload"),
        (phase2_backtest_reports, "query_payload_sha256", "query_payload"),
        (phase2_backtest_run_manifests, "manifest_sha256", "canonical_payload"),
        (phase2_backtest_job_events, "event_sha256", "canonical_payload"),
        (phase2_backtest_audit_events, "semantic_sha256", "canonical_payload"),
    )
    for table, digest_column, payload_column in digest_payloads:
        statement = sa.select(table.c[digest_column], table.c[payload_column])
        for digest, payload in connection.execute(statement):
            if type(digest) is not str or type(payload) is not str:
                raise DatabaseSchemaNotReady("Phase 2 research evidence is malformed")
            if hashlib.sha256(payload.encode("utf-8")).hexdigest() != digest:
                raise DatabaseSchemaNotReady("Phase 2 research evidence digest is invalid")

    from packages.persistence.backtest_workflow import (
        BacktestWorkflowError,
        _verify_backtest_workflow_integrity,
    )

    try:
        _verify_backtest_workflow_integrity(connection)
    except BacktestWorkflowError as error:
        raise DatabaseSchemaNotReady(
            "Phase 2 research auxiliary evidence verification failed"
        ) from error

    queries = (
        """
        SELECT 1
        FROM phase2_backtest_jobs AS job
        LEFT JOIN phase2_backtest_fixtures AS fixture
          ON fixture.fixture_id = job.fixture_id
         AND fixture.fixture_version = job.fixture_version
         AND fixture.dataset_manifest_sha256 = job.dataset_manifest_sha256
         AND fixture.replay_run_id = job.replay_run_id
        LEFT JOIN phase2_strategy_versions AS strategy
          ON strategy.strategy_version_id = job.strategy_version_id
        LEFT JOIN phase2_strategy_configurations AS configuration
          ON configuration.configuration_sha256 = job.strategy_configuration_sha256
        WHERE fixture.fixture_sha256 IS NULL
           OR strategy.strategy_version_id IS NULL
           OR configuration.configuration_sha256 IS NULL
           OR job.dataset_manifest_id <> job.dataset_manifest_sha256
           OR fixture.strategy_version_id <> job.strategy_version_id
           OR fixture.strategy_id <> job.strategy_id
           OR fixture.strategy_version <> job.strategy_version
           OR fixture.strategy_configuration_sha256
                <> job.strategy_configuration_sha256
           OR fixture.benchmark_sha256 <> job.benchmark_sha256
           OR fixture.cost_model_sha256 <> job.cost_model_sha256
           OR fixture.fill_model_sha256 <> job.fill_model_sha256
           OR fixture.metric_conventions_sha256 <> job.metric_conventions_sha256
           OR strategy.strategy_id <> job.strategy_id
           OR strategy.strategy_version <> job.strategy_version
           OR configuration.strategy_version_id <> job.strategy_version_id
           OR configuration.strategy_id <> job.strategy_id
           OR configuration.strategy_version <> job.strategy_version
        LIMIT 1
        """,
        """
        SELECT 1
        FROM phase2_backtest_jobs AS job
        LEFT JOIN (
          SELECT job_id,
                 COUNT(*) AS event_count,
                 MIN(sequence_number) AS first_sequence,
                 MAX(sequence_number) AS last_sequence,
                 SUM(CASE WHEN sequence_number = 0 AND status = 'queued' THEN 1 ELSE 0 END)
                   AS queued_first_count
          FROM phase2_backtest_job_events
          GROUP BY job_id
        ) AS event
          ON event.job_id = job.job_id
        LEFT JOIN phase2_backtest_job_heads AS head
          ON head.job_id = job.job_id
        LEFT JOIN phase2_backtest_audit_events AS audit
          ON audit.job_id = job.job_id
        WHERE COALESCE(event.event_count, 0) = 0
           OR event.first_sequence <> 0
           OR event.last_sequence <> event.event_count - 1
           OR event.queued_first_count <> 1
           OR head.job_id IS NULL
           OR audit.audit_sha256 IS NULL
           OR audit.action <> 'launch'
           OR audit.actor_id <> job.requested_by
           OR audit.idempotency_key <> job.idempotency_key
           OR audit.request_sha256 <> job.input_sha256
           OR audit.audit_sha256 <> audit.semantic_sha256
        LIMIT 1
        """,
        """
        SELECT 1
        FROM (
          SELECT job_id,
                 sequence_number,
                 status,
                 occurred_at,
                 actor_id,
                 attempt_number,
                 previous_event_sha256,
                 worker_id,
                 claim_expires_at,
                 LAG(status) OVER (
                   PARTITION BY job_id ORDER BY sequence_number
                 ) AS prior_status,
                 LAG(event_sha256) OVER (
                   PARTITION BY job_id ORDER BY sequence_number
                 ) AS prior_sha256,
                 LAG(occurred_at) OVER (
                   PARTITION BY job_id ORDER BY sequence_number
                 ) AS prior_occurred_at,
                 LAG(actor_id) OVER (
                   PARTITION BY job_id ORDER BY sequence_number
                 ) AS prior_actor_id,
                 LAG(attempt_number) OVER (
                   PARTITION BY job_id ORDER BY sequence_number
                 ) AS prior_attempt_number,
                 LAG(worker_id) OVER (
                   PARTITION BY job_id ORDER BY sequence_number
                 ) AS prior_worker_id,
                 LAG(claim_expires_at) OVER (
                   PARTITION BY job_id ORDER BY sequence_number
                 ) AS prior_claim_expires_at
          FROM phase2_backtest_job_events
        ) AS history
        WHERE (history.sequence_number > 0
               AND history.previous_event_sha256 <> history.prior_sha256)
           OR (history.sequence_number > 0
               AND history.occurred_at < history.prior_occurred_at)
           OR (history.sequence_number > 0 AND NOT (
                (history.prior_status = 'queued'
                 AND history.status IN ('running', 'canceled'))
                OR (history.prior_status = 'running'
                    AND history.status IN ('running', 'completed', 'failed', 'canceled'))
              ))
           OR (history.prior_status = 'running'
               AND history.status IN ('completed', 'failed', 'canceled')
               AND (history.actor_id <> history.prior_worker_id
                    OR history.attempt_number <> history.prior_attempt_number
                    OR history.occurred_at > history.prior_claim_expires_at))
           OR (history.prior_status = 'running'
               AND history.status = 'running'
               AND history.occurred_at <= history.prior_claim_expires_at
               AND (history.worker_id <> history.prior_worker_id
                    OR history.attempt_number <> history.prior_attempt_number))
           OR (history.prior_status = 'running'
               AND history.status = 'running'
               AND history.occurred_at > history.prior_claim_expires_at
               AND history.attempt_number <> history.prior_attempt_number + 1)
        LIMIT 1
        """,
        """
        WITH latest AS (
          SELECT event.*
          FROM phase2_backtest_job_events AS event
          JOIN (
            SELECT job_id, MAX(sequence_number) AS sequence_number
            FROM phase2_backtest_job_events
            GROUP BY job_id
          ) AS tail
            ON tail.job_id = event.job_id
           AND tail.sequence_number = event.sequence_number
        )
        SELECT 1
        FROM phase2_backtest_job_heads AS head
        LEFT JOIN latest
          ON latest.job_id = head.job_id
        WHERE latest.event_sha256 IS NULL
           OR head.last_sequence_number <> latest.sequence_number
           OR head.last_event_sha256 <> latest.event_sha256
           OR head.status <> latest.status
           OR head.attempt_number <> latest.attempt_number
           OR COALESCE(head.worker_id, '') <> COALESCE(latest.worker_id, '')
           OR head.claim_expires_at <> latest.claim_expires_at
           OR (head.claim_expires_at IS NULL AND latest.claim_expires_at IS NOT NULL)
           OR (head.claim_expires_at IS NOT NULL AND latest.claim_expires_at IS NULL)
           OR COALESCE(head.run_manifest_sha256, '')
                <> COALESCE(latest.run_manifest_sha256, '')
           OR COALESCE(head.report_sha256, '') <> COALESCE(latest.report_sha256, '')
           OR COALESCE(head.report_artifact_sha256, '')
                <> COALESCE(latest.report_artifact_sha256, '')
           OR COALESCE(head.terminal_reason_code, '')
                <> COALESCE(latest.terminal_reason_code, '')
           OR COALESCE(head.terminal_reason_sha256, '')
                <> COALESCE(latest.terminal_reason_sha256, '')
           OR head.updated_at <> latest.occurred_at
        LIMIT 1
        """,
        """
        SELECT 1
        FROM phase2_backtest_run_manifests AS manifest
        JOIN phase2_backtest_jobs AS job ON job.job_id = manifest.job_id
        LEFT JOIN phase2_backtest_reports AS report
          ON report.report_sha256 = manifest.report_sha256
         AND report.report_artifact_sha256 = manifest.report_artifact_sha256
        LEFT JOIN phase2_backtest_job_events AS event
          ON event.job_id = manifest.job_id
         AND event.run_manifest_sha256 = manifest.manifest_sha256
        WHERE manifest.run_id <> manifest.manifest_sha256
           OR event.event_sha256 IS NULL
           OR event.status <> manifest.status
           OR event.report_sha256 <> manifest.report_sha256
           OR event.report_artifact_sha256 <> manifest.report_artifact_sha256
           OR (manifest.status = 'completed' AND report.report_artifact_sha256 IS NULL)
        LIMIT 1
        """,
    )
    for query in queries:
        if connection.scalar(sa.text(query)) is not None:
            raise DatabaseSchemaNotReady("Phase 2 durable research integrity verification failed")


def create_database_engine(database_url: str) -> Engine:
    url = make_url(database_url)
    if url.get_backend_name() == "sqlite" and (url.database is None or url.database == ":memory:"):
        engine = create_engine(
            url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    else:
        engine = create_engine(
            url,
            connect_args=pinned_verify_full_connect_args(database_url, required=False),
            pool_pre_ping=True,
        )
    return enforce_sqlite_foreign_keys(engine)


def persistence_mode(engine: Engine) -> Literal["ephemeral", "durable"]:
    url = engine.url
    if url.get_backend_name() == "sqlite" and (url.database is None or url.database == ":memory:"):
        return "ephemeral"
    return "durable"


@contextmanager
def _repeatable_read_transaction(engine: Engine) -> Iterator[Connection]:
    """Hold one stable database snapshot across a multi-query read."""

    with engine.connect() as connection:
        if connection.dialect.name == "postgresql":
            connection = connection.execution_options(isolation_level="REPEATABLE READ")
            connection.begin()
        elif connection.dialect.name == "sqlite":
            connection.exec_driver_sql("BEGIN")
        else:
            connection.begin()
        try:
            yield connection
        finally:
            connection.rollback()


def verify_operational_schema(
    engine: Engine,
    *,
    require_phase_zero_facts: bool = True,
    expected_revision: str = EXPECTED_SCHEMA_REVISION,
) -> None:
    """Fail closed unless migrations and every Phase 0 operational table are readable."""

    if expected_revision not in {
        "0035_phase6_time_uncertainty",
        EXPECTED_SCHEMA_REVISION,
    }:
        raise DatabaseSchemaNotReady("requested database revision is not supported")
    try:
        with _repeatable_read_transaction(engine) as connection:
            revision = connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
            if revision != expected_revision:
                raise DatabaseSchemaNotReady(
                    f"database revision {revision!r} is not {expected_revision!r}"
                )
            required_tables: tuple[sa.Table, ...] = (
                risk_account_guards,
                risk_decisions,
                risk_reservations,
                submission_attempts,
                orders,
                fills,
                ledger_entries,
                ledger_postings,
                market_data_sources,
                market_data_entitlements,
                market_data_admission_profiles,
                market_data_admission_runs,
                market_data_admission_checks,
                instruments,
                instrument_identifiers,
                universe_versions,
                universe_memberships,
                calendar_versions,
                calendar_sessions,
                corporate_action_revisions,
                corporate_action_sets,
                corporate_action_set_members,
                ingestion_jobs,
                data_objects,
                dataset_partitions,
                data_quality_runs,
                data_quality_issues,
                partition_quarantines,
                dataset_manifests,
                dataset_manifest_partitions,
                replay_run_manifests,
                phase2_account_leases,
                phase2_account_lease_heads,
                phase2_account_lease_releases,
                phase2_batch_decisions,
                phase2_batch_members,
                phase2_batch_reservations,
                phase2_batch_authorizations,
                phase2_logical_orders,
                phase2_authorization_consumptions,
                phase2_submission_attempts,
                phase2_submission_attempt_events,
                phase2_order_events,
                phase2_simulation_horizon_facts,
                phase2_reservation_release_events,
                phase2_ledger_entries,
                phase2_ledger_postings,
                phase2_strategy_versions,
                phase2_strategy_configurations,
                phase2_backtest_fixtures,
                phase2_backtest_jobs,
                phase2_backtest_reports,
                phase2_backtest_run_manifests,
                phase2_backtest_job_events,
                phase2_backtest_job_heads,
                phase2_backtest_audit_events,
                phase3_experiment_families,
                phase3_experiment_attempts,
                phase3_experiment_attempt_events,
                phase3_holdout_reveals,
                phase3_experiment_audit_events,
                phase3_experiment_tape_claims,
                phase3_experiment_tape_policies,
                phase4_alpaca_paper_account_binding_heads,
                phase4_alpaca_paper_account_bindings,
                phase4_alpaca_paper_account_activity_comparison_heads,
                phase4_alpaca_paper_account_activity_comparisons,
                phase4_alpaca_paper_account_activity_heads,
                phase4_alpaca_paper_account_activity_pages,
                phase4_alpaca_paper_account_activity_plans,
                phase4_alpaca_paper_account_activity_preparations,
                phase4_alpaca_paper_asset_binding_heads,
                phase4_alpaca_paper_asset_bindings,
                phase4_alpaca_paper_lookup_observation_heads,
                phase4_alpaca_paper_lookup_observations,
                phase4_alpaca_paper_order_snapshot_heads,
                phase4_alpaca_paper_order_snapshot_pages,
                phase4_alpaca_paper_order_snapshot_plans,
                phase4_alpaca_paper_order_snapshot_preparations,
                phase4_alpaca_paper_order_transition_members,
                phase4_alpaca_paper_order_transition_claims,
                phase4_alpaca_paper_order_transition_consumptions,
                phase4_alpaca_paper_order_view_comparison_heads,
                phase4_alpaca_paper_order_view_comparisons,
                phase4_alpaca_paper_position_snapshot_plans,
                phase4_alpaca_paper_position_snapshots,
                phase4_alpaca_paper_position_transition_members,
                phase4_alpaca_paper_position_transition_claims,
                phase4_alpaca_paper_position_transition_consumptions,
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
                phase4_broker_request_heads,
                phase4_broker_request_permits,
                phase4_unknown_lookup_recovery_events,
                phase4_unknown_lookup_recovery_heads,
                phase4_unknown_lookup_recovery_plans,
                phase5_advanced_risk_policies,
                phase5_advanced_risk_assignments,
                phase5_advanced_risk_assignment_heads,
                phase5_advanced_risk_evidence,
                phase5_advanced_risk_evidence_sources,
                phase5_advanced_risk_assessments,
                phase5_advanced_risk_batch_admissions,
                phase5_advanced_risk_batch_outcomes,
                phase5_advanced_risk_enforcement_heads,
                phase5_critical_alert_incidents,
                phase5_critical_alert_delivery_attempts,
                phase5_critical_alert_delivery_results,
                phase5_critical_alert_failure_control_receipts,
                phase5_operational_control_completions,
                phase5_operational_control_heads,
                phase5_operational_control_transitions,
                phase5_strategy_invocation_claims,
                phase5_strategy_invocation_finalizations,
                phase5_strategy_supervision_results,
                phase6_trusted_time_epoch_registrations,
                phase6_trusted_time_probe_evaluations,
                phase6_trusted_time_host_heads,
            )
            if expected_revision == EXPECTED_SCHEMA_REVISION:
                required_tables += (
                    phase6_trusted_time_head_anchor_intents,
                    phase6_trusted_time_head_anchor_receipts,
                )
            for table in required_tables:
                connection.execute(sa.select(table).limit(0))
            from packages.persistence.advanced_batch_risk import (
                AdvancedBatchRiskPersistenceError,
                _verify_advanced_batch_risk_integrity,
            )

            try:
                _verify_advanced_batch_risk_integrity(connection)
            except AdvancedBatchRiskPersistenceError as error:
                raise DatabaseSchemaNotReady(
                    "Phase 5 advanced-risk outcome integrity verification failed"
                ) from error
            from packages.domain.operational_control import OperationalControlError
            from packages.persistence.operational_control import (
                _verify_operational_control_integrity,
            )

            try:
                _verify_operational_control_integrity(connection)
            except OperationalControlError as error:
                raise DatabaseSchemaNotReady(
                    "Phase 5 operational-control integrity verification failed"
                ) from error
            from packages.domain.critical_alert import CriticalAlertError
            from packages.persistence.critical_alert import (
                _verify_critical_alert_integrity,
            )

            try:
                _verify_critical_alert_integrity(connection)
            except CriticalAlertError as error:
                raise DatabaseSchemaNotReady(
                    "Phase 5 critical-alert integrity verification failed"
                ) from error
            from packages.persistence.critical_alert_failure_control import (
                CriticalAlertFailureControlPersistenceError,
                _verify_critical_alert_failure_control_integrity,
            )

            try:
                _verify_critical_alert_failure_control_integrity(connection)
            except CriticalAlertFailureControlPersistenceError as error:
                raise DatabaseSchemaNotReady(
                    "Phase 5 critical-alert failure-control integrity verification failed"
                ) from error
            from packages.persistence.strategy_supervision import (
                StrategySupervisionPersistenceError,
                _verify_strategy_supervision_integrity,
            )

            try:
                _verify_strategy_supervision_integrity(connection)
            except StrategySupervisionPersistenceError as error:
                raise DatabaseSchemaNotReady(
                    "Phase 5 strategy-supervision integrity verification failed"
                ) from error
            from packages.persistence.strategy_invocation_lifecycle import (
                StrategyInvocationLifecyclePersistenceError,
                _verify_strategy_invocation_lifecycle_integrity,
            )

            try:
                _verify_strategy_invocation_lifecycle_integrity(connection)
            except StrategyInvocationLifecyclePersistenceError as error:
                raise DatabaseSchemaNotReady(
                    "Phase 5 strategy-invocation lifecycle integrity verification failed"
                ) from error
            from packages.domain.broker_ingress import BrokerIngressError
            from packages.persistence.broker_ingress import (
                _verify_broker_ingress_integrity,
            )

            try:
                _verify_broker_ingress_integrity(connection)
            except BrokerIngressError as error:
                raise DatabaseSchemaNotReady(
                    "Phase 4 broker-ingress integrity verification failed"
                ) from error
            from packages.domain.broker_request_budget import BrokerRequestBudgetError
            from packages.persistence.broker_request_budget import (
                _verify_broker_request_budget_integrity,
            )

            try:
                _verify_broker_request_budget_integrity(connection)
            except BrokerRequestBudgetError as error:
                raise DatabaseSchemaNotReady(
                    "Phase 4 broker-request budget integrity verification failed"
                ) from error
            from packages.adapters.broker.alpaca_paper_account_runtime import (
                AlpacaPaperAccountRuntimeError,
            )
            from packages.persistence.alpaca_paper_account_binding import (
                _verify_alpaca_paper_account_binding_integrity,
            )

            try:
                _verify_alpaca_paper_account_binding_integrity(connection)
            except AlpacaPaperAccountRuntimeError as error:
                raise DatabaseSchemaNotReady(
                    "Phase 4 Alpaca paper account-binding integrity verification failed"
                ) from error
            from packages.adapters.broker.alpaca_paper_asset_runtime import (
                AlpacaPaperAssetRuntimeError,
            )
            from packages.persistence.alpaca_paper_asset_binding import (
                _verify_alpaca_paper_asset_binding_integrity,
            )

            try:
                _verify_alpaca_paper_asset_binding_integrity(connection)
            except AlpacaPaperAssetRuntimeError as error:
                raise DatabaseSchemaNotReady(
                    "Phase 4 Alpaca paper asset-binding integrity verification failed"
                ) from error
            from packages.adapters.broker.alpaca_paper_lookup_runtime import (
                AlpacaPaperLookupRuntimeError,
            )
            from packages.persistence.alpaca_paper_lookup_observation import (
                _verify_alpaca_paper_lookup_observation_integrity,
            )

            try:
                _verify_alpaca_paper_lookup_observation_integrity(connection)
            except AlpacaPaperLookupRuntimeError as error:
                raise DatabaseSchemaNotReady(
                    "Phase 4 Alpaca paper lookup-observation integrity verification failed"
                ) from error
            from packages.adapters.broker.alpaca_paper_order_snapshot_runtime import (
                AlpacaPaperOrderSnapshotRuntimeError,
            )
            from packages.persistence.alpaca_paper_order_snapshot import (
                _verify_alpaca_paper_order_snapshot_integrity,
            )

            try:
                _verify_alpaca_paper_order_snapshot_integrity(connection)
            except AlpacaPaperOrderSnapshotRuntimeError as error:
                raise DatabaseSchemaNotReady(
                    "Phase 4 Alpaca paper order-snapshot integrity verification failed"
                ) from error
            from packages.adapters.broker.alpaca_paper_account_activity_runtime import (
                AlpacaPaperAccountActivityRuntimeError,
            )
            from packages.persistence.alpaca_paper_account_activity import (
                _verify_alpaca_paper_account_activity_integrity,
            )

            try:
                _verify_alpaca_paper_account_activity_integrity(connection)
            except AlpacaPaperAccountActivityRuntimeError as error:
                raise DatabaseSchemaNotReady(
                    "Phase 4 Alpaca paper account-activity integrity verification failed"
                ) from error
            from packages.persistence.alpaca_paper_account_activity_comparison import (
                AlpacaPaperAccountActivityComparisonPersistenceError,
                _verify_alpaca_paper_account_activity_comparison_integrity,
            )

            try:
                _verify_alpaca_paper_account_activity_comparison_integrity(connection)
            except AlpacaPaperAccountActivityComparisonPersistenceError as error:
                raise DatabaseSchemaNotReady(
                    "Phase 4 Alpaca paper account-activity comparison integrity verification failed"
                ) from error
            from packages.persistence.alpaca_paper_order_view_transition import (
                AlpacaPaperOrderViewTransitionPersistenceError,
                _verify_alpaca_paper_order_view_transition_integrity,
            )

            try:
                _verify_alpaca_paper_order_view_transition_integrity(connection)
            except AlpacaPaperOrderViewTransitionPersistenceError as error:
                raise DatabaseSchemaNotReady(
                    "Phase 4 Alpaca paper order-transition integrity verification failed"
                ) from error
            from packages.persistence.alpaca_paper_order_view_comparison import (
                AlpacaPaperOrderViewComparisonPersistenceError,
                _verify_alpaca_paper_order_view_comparison_integrity,
            )

            try:
                _verify_alpaca_paper_order_view_comparison_integrity(connection)
            except AlpacaPaperOrderViewComparisonPersistenceError as error:
                raise DatabaseSchemaNotReady(
                    "Phase 4 Alpaca paper order-view comparison integrity verification failed"
                ) from error
            from packages.persistence.alpaca_paper_position_snapshot import (
                AlpacaPaperPositionSnapshotPersistenceError,
                _verify_alpaca_paper_position_snapshot_integrity,
            )

            try:
                _verify_alpaca_paper_position_snapshot_integrity(connection)
            except AlpacaPaperPositionSnapshotPersistenceError as error:
                raise DatabaseSchemaNotReady(
                    "Phase 4 Alpaca paper position-snapshot integrity verification failed"
                ) from error
            from packages.persistence.alpaca_paper_position_view_transition import (
                AlpacaPaperPositionViewTransitionPersistenceError,
                _verify_alpaca_paper_position_view_transition_integrity,
            )

            try:
                _verify_alpaca_paper_position_view_transition_integrity(connection)
            except AlpacaPaperPositionViewTransitionPersistenceError as error:
                raise DatabaseSchemaNotReady(
                    "Phase 4 Alpaca paper position-transition integrity verification failed"
                ) from error
            from packages.persistence.alpaca_paper_position_view_comparison import (
                AlpacaPaperPositionViewComparisonPersistenceError,
                _verify_alpaca_paper_position_view_comparison_integrity,
            )

            try:
                _verify_alpaca_paper_position_view_comparison_integrity(connection)
            except AlpacaPaperPositionViewComparisonPersistenceError as error:
                raise DatabaseSchemaNotReady(
                    "Phase 4 Alpaca paper position-view comparison integrity verification failed"
                ) from error
            from packages.persistence.unknown_submission_recovery import (
                UnknownSubmissionRecoveryPersistenceError,
                _verify_unknown_submission_recovery_integrity,
            )

            try:
                _verify_unknown_submission_recovery_integrity(connection)
            except UnknownSubmissionRecoveryPersistenceError as error:
                raise DatabaseSchemaNotReady(
                    "Phase 4 UNKNOWN lookup-schedule integrity verification failed"
                ) from error
            from packages.persistence.broker_reconciliation import (
                BrokerReconciliationPersistenceError,
                _verify_broker_reconciliation_integrity,
            )

            try:
                _verify_broker_reconciliation_integrity(connection)
            except BrokerReconciliationPersistenceError as error:
                raise DatabaseSchemaNotReady(
                    "Phase 4 broker-reconciliation integrity verification failed"
                ) from error
            from packages.persistence.broker_inbox import (
                BrokerInboxPersistenceError,
                _verify_broker_inbox_integrity,
            )

            try:
                _verify_broker_inbox_integrity(connection)
            except BrokerInboxPersistenceError as error:
                raise DatabaseSchemaNotReady(
                    "Phase 4 broker-inbox integrity verification failed"
                ) from error
            from packages.persistence.trusted_time import (
                TrustedTimePersistenceError,
                _verify_global_integrity,
            )

            try:
                _verify_global_integrity(connection)
            except TrustedTimePersistenceError as error:
                raise DatabaseSchemaNotReady(
                    "Phase 6 trusted-time integrity verification failed"
                ) from error
            _verify_phase2_durability_integrity(connection)
            _verify_phase2_research_integrity(connection)
            from packages.persistence.experiment_governance import (
                ExperimentGovernanceError,
                _verify_experiment_governance_integrity,
            )

            try:
                _verify_experiment_governance_integrity(connection)
            except ExperimentGovernanceError as error:
                raise DatabaseSchemaNotReady(
                    "Phase 3 experiment-governance integrity verification failed"
                ) from error
            if not require_phase_zero_facts:
                _verify_data_plane_integrity(connection)
                return
            from packages.persistence.risk import decision_from_row

            try:
                for row in connection.execute(sa.select(risk_decisions)).mappings():
                    decision_from_row(row)
            except RiskAuthorizationError as error:
                raise DatabaseSchemaNotReady(
                    "persisted risk-decision evidence is malformed"
                ) from error
            integrity_queries = (
                """
                SELECT 1
                FROM risk_decisions AS decision
                LEFT JOIN risk_reservations AS reservation
                  ON reservation.decision_id = decision.decision_id
                LEFT JOIN submission_attempts AS attempt
                  ON attempt.decision_id = decision.decision_id
                WHERE decision.status NOT IN ('approved', 'rejected')
                   OR (decision.status = 'rejected' AND reservation.decision_id IS NOT NULL)
                   OR (
                     decision.status = 'approved'
                     AND (
                       reservation.decision_id IS NULL
                       OR reservation.cash_amount <> decision.reserved_cash
                       OR reservation.expires_at <> decision.expires_at
                     )
                   )
                   OR (
                     decision.consumed_at IS NULL
                     AND (
                       attempt.attempt_id IS NOT NULL
                       OR (
                         decision.status = 'approved'
                         AND reservation.state <> 'approved'
                       )
                     )
                   )
                   OR (
                     decision.consumed_at IS NOT NULL
                     AND (
                       decision.status <> 'approved'
                       OR reservation.state <> 'consumed'
                       OR attempt.attempt_id IS NULL
                       OR attempt.submitted_at <> decision.consumed_at
                     )
                   )
                LIMIT 1
                """,
                """
                SELECT 1
                FROM risk_account_guards AS guard
                LEFT JOIN risk_reservations AS reservation
                  ON reservation.account_id = guard.account_id
                 AND reservation.snapshot_version = guard.snapshot_version
                GROUP BY guard.account_id, guard.reserved_cash
                HAVING guard.reserved_cash <> COALESCE(
                  SUM(
                    CASE
                      WHEN reservation.state IN ('approved', 'consumed')
                      THEN reservation.cash_amount
                      ELSE 0
                    END
                  ),
                  0
                )
                LIMIT 1
                """,
                """
                SELECT 1
                WHERE NOT EXISTS (
                  SELECT 1
                  FROM submission_attempts
                  WHERE state = 'recorded'
                )
                """,
                """
                SELECT 1
                FROM submission_attempts AS attempt
                LEFT JOIN orders AS submitted_order
                  ON submitted_order.order_id = attempt.order_id
                WHERE attempt.state = 'recorded'
                  AND (
                    submitted_order.order_id IS NULL
                    OR submitted_order.risk_decision_id <> attempt.decision_id
                    OR submitted_order.intent_id <> attempt.intent_id
                    OR submitted_order.submitted_at <> attempt.submitted_at
                  )
                LIMIT 1
                """,
                """
                SELECT 1
                FROM orders AS submitted_order
                JOIN risk_decisions AS decision
                  ON decision.decision_id = submitted_order.risk_decision_id
                LEFT JOIN submission_attempts AS attempt
                  ON attempt.decision_id = decision.decision_id
                WHERE decision.consumed_at IS NULL
                   OR submitted_order.intent_id <> decision.intent_id
                   OR attempt.state <> 'recorded'
                   OR attempt.order_id <> submitted_order.order_id
                   OR attempt.intent_id <> submitted_order.intent_id
                LIMIT 1
                """,
                """
                SELECT 1
                FROM orders AS submitted_order
                LEFT JOIN fills AS execution_fill
                  ON execution_fill.order_id = submitted_order.order_id
                GROUP BY submitted_order.order_id,
                         submitted_order.status,
                         submitted_order.filled_quantity,
                         submitted_order.quantity
                HAVING submitted_order.status NOT IN ('working', 'filled')
                    OR (
                      submitted_order.status = 'working'
                      AND (
                        submitted_order.filled_quantity <> 0
                        OR COUNT(execution_fill.fill_id) <> 0
                      )
                    )
                    OR (
                      submitted_order.status = 'filled'
                      AND (
                        submitted_order.filled_quantity <> submitted_order.quantity
                        OR COUNT(execution_fill.fill_id) = 0
                        OR COALESCE(SUM(execution_fill.quantity), 0)
                           <> submitted_order.filled_quantity
                      )
                    )
                LIMIT 1
                """,
                """
                SELECT 1
                FROM fills AS execution_fill
                LEFT JOIN ledger_entries AS entry
                  ON entry.reference_id = execution_fill.fill_id
                 AND entry.event_type = 'fill'
                WHERE entry.entry_id IS NULL
                LIMIT 1
                """,
                """
                SELECT 1
                WHERE NOT EXISTS (
                  SELECT 1
                  FROM ledger_entries
                  WHERE event_type = 'opening_balance'
                )
                """,
                """
                SELECT 1
                FROM ledger_entries AS entry
                LEFT JOIN ledger_postings AS posting
                  ON posting.entry_id = entry.entry_id
                GROUP BY entry.entry_id
                HAVING COUNT(posting.posting_id) < 2
                    OR COALESCE(SUM(posting.debit), 0)
                       <> COALESCE(SUM(posting.credit), 0)
                    OR COUNT(DISTINCT posting.currency) <> 1
                LIMIT 1
                """,
            )
            for query in integrity_queries:
                if connection.scalar(sa.text(query)) is not None:
                    raise DatabaseSchemaNotReady(
                        "operational database integrity verification failed"
                    )
            _verify_data_plane_integrity(connection)
    except DatabaseSchemaNotReady:
        raise
    except SQLAlchemyError as error:
        raise DatabaseSchemaNotReady("operational database schema is unavailable") from error
