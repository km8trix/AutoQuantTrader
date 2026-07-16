"""Database engine factory kept outside the pure domain packages."""

from __future__ import annotations

from typing import Literal

import sqlalchemy as sa
from sqlalchemy import Connection, Engine, create_engine, make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import StaticPool

from packages.domain.risk import RiskAuthorizationError
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
    risk_account_guards,
    risk_decisions,
    risk_reservations,
    submission_attempts,
    universe_memberships,
    universe_versions,
)

EXPECTED_SCHEMA_REVISION = "0005_market_data_admission"


class DatabaseSchemaNotReady(RuntimeError):
    """The durable store is reachable but not at the required operational schema."""


def _verify_data_plane_integrity(connection: Connection) -> None:
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
    )
    for query in queries:
        if connection.scalar(sa.text(query)) is not None:
            raise DatabaseSchemaNotReady("point-in-time data catalog integrity verification failed")


def create_database_engine(database_url: str) -> Engine:
    url = make_url(database_url)
    if url.get_backend_name() == "sqlite" and (url.database is None or url.database == ":memory:"):
        return create_engine(
            url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    return create_engine(url, pool_pre_ping=True)


def persistence_mode(engine: Engine) -> Literal["ephemeral", "durable"]:
    url = engine.url
    if url.get_backend_name() == "sqlite" and (url.database is None or url.database == ":memory:"):
        return "ephemeral"
    return "durable"


def verify_operational_schema(
    engine: Engine,
    *,
    require_phase_zero_facts: bool = True,
) -> None:
    """Fail closed unless migrations and every Phase 0 operational table are readable."""

    try:
        with engine.connect() as connection:
            revision = connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
            if revision != EXPECTED_SCHEMA_REVISION:
                raise DatabaseSchemaNotReady(
                    f"database revision {revision!r} is not {EXPECTED_SCHEMA_REVISION!r}"
                )
            required_tables = (
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
            )
            for table in required_tables:
                connection.execute(sa.select(table).limit(0))
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
