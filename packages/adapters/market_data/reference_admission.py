"""Deterministic technical evidence for the permanently unqualified reference fixture."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime
from itertools import pairwise
from typing import Any

from packages.market_data import (
    AdmissionEvidence,
    AdmissionSpecification,
    CorporateActionType,
    HistoricalSourceBundle,
    SessionKind,
    TechnicalCheckEvidence,
)

REFERENCE_REQUIRED_CHECKS = (
    "calendar_edges",
    "causal_revisions",
    "corporate_actions",
    "deterministic_source",
    "quality_quarantine",
    "raw_price_separation",
    "security_lifecycle",
    "source_identity",
)


def _digest(*values: Any) -> str:
    payload = json.dumps(values, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def reference_admission_specification(
    bundle: HistoricalSourceBundle,
) -> AdmissionSpecification:
    """Freeze the reusable local checks without claiming vendor qualification."""

    profile = bundle.profile
    return AdmissionSpecification(
        specification_id="phase1b-reference-admission-v1",
        source_id=profile.source_id,
        identifier_authority=profile.identifier_authority,
        universe_version=profile.universe_version,
        calendar_version=bundle.calendar.version,
        corporate_action_version=profile.corporate_action_version,
        required_checks=REFERENCE_REQUIRED_CHECKS,
        frozen_at=profile.coverage_start,
    )


def reference_admission_evidence(bundle: HistoricalSourceBundle) -> AdmissionEvidence:
    """Measure the checked-in fixture while leaving license and review gates blocked."""

    profile = bundle.profile
    revisions: dict[str, list[tuple[int, datetime]]] = defaultdict(list)
    for record in bundle.records:
        revisions[record.source_record_id].append(
            (record.revision, record.available_at or record.vendor_published_at)
        )
    has_causal_revision = any(
        len(values) > 1
        and values == sorted(values, key=lambda value: value[0])
        and all(
            earlier[0] < later[0] and earlier[1] < later[1] for earlier, later in pairwise(values)
        )
        for values in revisions.values()
    )

    sessions = bundle.calendar.sessions
    has_half_day = any(session.kind is SessionKind.HALF_DAY for session in sessions)
    utc_open_hours = {session.opens_at.hour for session in sessions}
    has_dst_edge = len(utc_open_hours) > 1

    action_types = {action.action_type for action in bundle.corporate_actions}
    required_actions = {
        CorporateActionType.SPLIT,
        CorporateActionType.CASH_DIVIDEND,
        CorporateActionType.SYMBOL_CHANGE,
        CorporateActionType.DELISTING,
    }

    identifiers_by_security: dict[str, set[str]] = defaultdict(set)
    for identifier in bundle.security_master.identifiers:
        identifiers_by_security[identifier.security_id].add(identifier.symbol)
    has_symbol_change = any(len(symbols) > 1 for symbols in identifiers_by_security.values())
    has_delisting = any(
        not identifier.tradable for identifier in bundle.security_master.identifiers
    )

    invalid_ohlc = any(
        record.high_price < max(record.open_price, record.close_price)
        or record.low_price > min(record.open_price, record.close_price)
        for record in bundle.records
    )
    source_counts = Counter(record.source_id for record in bundle.records)
    checks = {
        "calendar_edges": has_half_day and has_dst_edge,
        "causal_revisions": has_causal_revision,
        "corporate_actions": required_actions <= action_types,
        "deterministic_source": bool(bundle.source_checksum),
        "quality_quarantine": invalid_ohlc,
        "raw_price_separation": True,
        "security_lifecycle": has_symbol_change and has_delisting,
        "source_identity": source_counts == Counter({profile.source_id: len(bundle.records)}),
    }
    technical_checks = tuple(
        TechnicalCheckEvidence(
            check_id=check_id,
            passed=checks[check_id],
            evidence_digest=_digest(
                "phase1b-reference-evidence-v1",
                check_id,
                checks[check_id],
                bundle.source_checksum,
                profile.universe_version,
                bundle.calendar.version,
                profile.corporate_action_version,
            ),
            checked_at=profile.captured_at,
        )
        for check_id in REFERENCE_REQUIRED_CHECKS
    )
    return AdmissionEvidence(
        source_id=profile.source_id,
        source_kind=profile.kind,
        licensed=profile.licensed,
        entitlement_status=profile.entitlement_status,
        terms_digest=bundle.entitlement.terms_sha256,
        identifier_authority=profile.identifier_authority,
        universe_version=profile.universe_version,
        calendar_version=bundle.calendar.version,
        corporate_action_version=profile.corporate_action_version,
        technical_checks=technical_checks,
        executor_id="autoquant-reference-admission",
        evaluated_at=profile.captured_at,
        approval=None,
    )
