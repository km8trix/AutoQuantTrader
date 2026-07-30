"""Source-authenticated, non-authorizing Alpaca account-activity comparison.

Phase 4AG reloads two exact terminal Phase 4AE traversal states, reconstructs
and revalidates every authenticated page, and derives the exact Phase 4AF
comparison.  The resulting evidence binds one historical provider-account
UUID and both terminal durable-head digests.  A repository may append that
evidence under an exact account fence, but neither the evidence nor its append
receipt establishes current account status, complete history, convergence,
canonical execution, reconciliation, readiness, broker, or trading authority.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from packages.adapters.broker.alpaca_paper_account_activities import (
    AlpacaPaperAccountActivityCapture,
    AlpacaPaperAccountActivityPlan,
)
from packages.adapters.broker.alpaca_paper_account_activity_comparison import (
    ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_CONTRACT_VERSION,
    ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_POLICY_SHA256,
    AlpacaPaperAccountActivityComparison,
    AlpacaPaperAccountActivityComparisonDisposition,
    AlpacaPaperAccountActivityComparisonError,
    _timedelta_microseconds,
    _traversal_profile_sha256,
    _utc_separation,
    _view_sha256,
    compare_alpaca_paper_account_activity_captures,
)
from packages.adapters.broker.alpaca_paper_account_activity_runtime import (
    ALPACA_PAPER_ACCOUNT_ACTIVITY_RUNTIME_CONTRACT_VERSION,
    AlpacaPaperAccountActivityConflict,
    AlpacaPaperAccountActivityTraversalStage,
    AlpacaPaperAuthenticatedAccountActivityPrefix,
    AlpacaPaperAuthenticatedAccountActivityTraversalState,
)
from packages.domain.account_coordinator import (
    AccountCoordinatorError,
    AccountFence,
    AccountFenceReceipt,
)
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.identifiers import canonical_id

ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_CONTRACT_VERSION = (
    "phase4ag-source-authenticated-account-activity-comparison-v1"
)
ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_POLICY_ID = (
    "phase4ag-exact-source-authenticated-account-activity-comparison-policy-v1"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_POLICY_SHA256 = _semantic_sha256(
    (
        ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_CONTRACT_VERSION,
        "comparison_policy",
        ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_POLICY_ID,
        ALPACA_PAPER_ACCOUNT_ACTIVITY_RUNTIME_CONTRACT_VERSION,
        ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_CONTRACT_VERSION,
        ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_POLICY_SHA256,
        "two_distinct_exact_phase4ad_plans",
        "two_nonempty_terminal_phase4ae_states",
        "every_authenticated_page_is_reconstructed_and_revalidated",
        "one_canonical_historical_provider_account_uuid",
        "exact_terminal_source_head_digests",
        "exact_phase4af_recomputation",
        "positive_identical_process_local_runtime_store_identity",
        "transaction_internal_exact_account_fence_for_append",
        "historical_source_lineage_without_current_status_or_authority",
    )
)


class AlpacaPaperAuthenticatedAccountActivityComparisonError(RuntimeError):
    """Phase 4AG could not derive or append exact source-authenticated evidence."""


class AlpacaPaperAuthenticatedAccountActivityComparisonSourceMissing(
    AlpacaPaperAuthenticatedAccountActivityComparisonError
):
    """A requested Phase 4AE traversal is absent, empty, active, or stalled."""


class AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
    AlpacaPaperAuthenticatedAccountActivityComparisonError
):
    """Loaded sources, derived evidence, or a durable append proof conflict."""


class _NoAuthenticatedAccountActivityComparisonAuthority:
    __slots__ = ()

    @property
    def request_budget_enforced(self) -> bool:
        return False

    @property
    def authenticated_provider_evidence(self) -> bool:
        return False

    @property
    def raw_response_persisted(self) -> bool:
        return False

    @property
    def provider_io_performed(self) -> bool:
        return False

    @property
    def runtime_current(self) -> bool:
        return False

    @property
    def account_status_current(self) -> bool:
        return False

    @property
    def provider_account_status_current(self) -> bool:
        return False

    @property
    def capture_authenticated(self) -> bool:
        return False

    @property
    def durable_source_positions_authenticated(self) -> bool:
        return False

    @property
    def comparison_durably_recorded(self) -> bool:
        return False

    @property
    def snapshot_isolation_qualified(self) -> bool:
        return False

    @property
    def provider_snapshot_complete(self) -> bool:
        return False

    @property
    def snapshot_complete(self) -> bool:
        return False

    @property
    def activity_history_complete(self) -> bool:
        return False

    @property
    def activity_history_consistent(self) -> bool:
        return False

    @property
    def converged(self) -> bool:
        return False

    @property
    def monotonic_timing_qualified(self) -> bool:
        return False

    @property
    def provider_activity_identity_qualified(self) -> bool:
        return False

    @property
    def provider_activity_sequence_identity_qualified(self) -> bool:
        return False

    @property
    def provider_activity_revision_identity_qualified(self) -> bool:
        return False

    @property
    def provider_execution_identity_qualified(self) -> bool:
        return False

    @property
    def canonical_execution_identity_qualified(self) -> bool:
        return False

    @property
    def provider_revision_identity_qualified(self) -> bool:
        return False

    @property
    def execution_revision_identity_qualified(self) -> bool:
        return False

    @property
    def provider_deduplication_identity_qualified(self) -> bool:
        return False

    @property
    def provider_bust_identity_qualified(self) -> bool:
        return False

    @property
    def provider_correction_identity_qualified(self) -> bool:
        return False

    @property
    def provider_deduplication_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_revision_authorized(self) -> bool:
        return False

    @property
    def canonical_account_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_ledger_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_cash_fact_authorized(self) -> bool:
        return False

    @property
    def execution_application_authorized(self) -> bool:
        return False

    @property
    def bust_application_authorized(self) -> bool:
        return False

    @property
    def correction_application_authorized(self) -> bool:
        return False

    @property
    def manual_activity_application_authorized(self) -> bool:
        return False

    @property
    def normalized_fact_authorized(self) -> bool:
        return False

    @property
    def inbox_application_authorized(self) -> bool:
        return False

    @property
    def lifecycle_application_authorized(self) -> bool:
        return False

    @property
    def reconciliation_application_authorized(self) -> bool:
        return False

    @property
    def reconciliation_completion_authorized(self) -> bool:
        return False

    @property
    def reconciliation_complete(self) -> bool:
        return False

    @property
    def unknown_resolution_authorized(self) -> bool:
        return False

    @property
    def reservation_release_authorized(self) -> bool:
        return False

    @property
    def resubmission_authorized(self) -> bool:
        return False

    @property
    def readiness_transition_authorized(self) -> bool:
        return False

    @property
    def activity_snapshot_pagination_ready(self) -> bool:
        return False

    @property
    def decode_quarantine_ready(self) -> bool:
        return False

    @property
    def reconciliation_ready(self) -> bool:
        return False

    @property
    def dispatch_preflight_ready(self) -> bool:
        return False

    @property
    def paper_startup_ready(self) -> bool:
        return False

    @property
    def transport_submission_ready(self) -> bool:
        return False

    @property
    def submission_authorized(self) -> bool:
        return False

    @property
    def transport_authorized(self) -> bool:
        return False

    @property
    def broker_call_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


def _require_sha256(value: object, field_name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            f"{field_name} must be a lowercase SHA-256 digest"
        )
    return value


def _require_plan(
    value: object,
    field_name: str,
) -> AlpacaPaperAccountActivityPlan:
    if type(value) is not AlpacaPaperAccountActivityPlan:
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            f"{field_name} must be an exact Phase 4AD plan"
        )
    try:
        value.__post_init__()
    except Exception:
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            f"{field_name} is invalid"
        ) from None
    return value


def _runtime_store_identity(value: object, field_name: str) -> int:
    try:
        identity = value.runtime_store_identity  # type: ignore[attr-defined]
    except Exception:
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            f"{field_name} process-local runtime-store identity is unavailable"
        ) from None
    if type(identity) is not int or identity <= 0:
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            f"{field_name} process-local runtime-store identity is invalid"
        )
    return identity


def _validate_runtime_store_composition(
    *,
    state_loader: object,
    comparison_repository: object,
) -> int:
    loader_identity = _runtime_store_identity(
        state_loader,
        "account-activity state loader",
    )
    repository_identity = _runtime_store_identity(
        comparison_repository,
        "account-activity comparison repository",
    )
    if loader_identity != repository_identity:
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            "account-activity comparison ports do not share one process-local runtime store"
        )
    return loader_identity


def _terminal_state(
    value: object,
    *,
    field_name: str,
) -> AlpacaPaperAuthenticatedAccountActivityTraversalState:
    if value is None:
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceMissing(
            f"{field_name} is absent"
        )
    if type(value) is not AlpacaPaperAuthenticatedAccountActivityTraversalState:
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            f"{field_name} must be an exact Phase 4AE traversal state"
        )
    try:
        prefix = value.prefix
        if type(prefix) is AlpacaPaperAuthenticatedAccountActivityPrefix and prefix.page_count == 0:
            raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceMissing(
                f"{field_name} has no committed page"
            )
        stage = value.stage
    except AlpacaPaperAuthenticatedAccountActivityComparisonError:
        raise
    except Exception:
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            f"{field_name} failed exact authenticated reconstruction"
        ) from None
    if stage in {
        AlpacaPaperAccountActivityTraversalStage.ABSENT,
        AlpacaPaperAccountActivityTraversalStage.ACTIVE,
        AlpacaPaperAccountActivityTraversalStage.STALLED,
    }:
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceMissing(
            f"{field_name} is not terminal"
        )
    try:
        value._validate()
        _require_sha256(
            value.source_head_sha256,
            f"{field_name} source head",
        )
    except AlpacaPaperAuthenticatedAccountActivityComparisonError:
        raise
    except Exception:
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            f"{field_name} failed exact authenticated reconstruction"
        ) from None
    return value


def _canonical_provider_account_id(
    state: AlpacaPaperAuthenticatedAccountActivityTraversalState,
    *,
    field_name: str,
) -> str:
    provider_account_ids: set[str] = set()
    try:
        for page_receipt in state.prefix.page_receipts:
            evidence = page_receipt.evidence
            values = (
                evidence.reference.expected_provider_account_id,
                evidence.account_binding.expected_provider_account_id,
                evidence.account_binding.observed_provider_account_id,
                evidence.pre_account_identity.expected_provider_account_id,
                evidence.post_account_identity.expected_provider_account_id,
            )
            for value in values:
                if type(value) is not str:
                    raise TypeError("provider account identity is not text")
                parsed = UUID(value)
                if str(parsed) != value:
                    raise ValueError("provider account identity is not canonical")
                provider_account_ids.add(value)
    except Exception:
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            f"{field_name} has malformed provider-account identity evidence"
        ) from None
    if len(provider_account_ids) != 1:
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            f"{field_name} pages bind different provider-account identities"
        )
    return next(iter(provider_account_ids))


@dataclass(frozen=True, slots=True)
class _AuthenticatedAccountActivityPageMaterialization:
    receipt_id: str
    receipt_sha256: str
    evidence_id: str
    evidence_sha256: str
    persisted_page_sha256: str
    ingress_receipt_id: str
    ingress_receipt_sha256: str
    ingress_sequence: int
    account_binding_id: str
    account_binding_sha256: str
    provider_account_id: str
    commit_fence_receipt_id: str
    commit_fence_receipt_sha256: str
    committed_at: datetime

    @property
    def source_material(self) -> tuple[object, ...]:
        return (
            self.receipt_id,
            self.receipt_sha256,
            self.evidence_id,
            self.evidence_sha256,
            self.persisted_page_sha256,
            self.ingress_receipt_id,
            self.ingress_receipt_sha256,
            self.ingress_sequence,
            self.account_binding_id,
            self.account_binding_sha256,
            self.provider_account_id,
            self.commit_fence_receipt_id,
            self.commit_fence_receipt_sha256,
            self.committed_at,
        )


@dataclass(frozen=True, slots=True)
class _AuthenticatedAccountActivitySourceMaterialization:
    capture: AlpacaPaperAccountActivityCapture
    capture_id: str
    plan_sha256: str
    state_sha256: str
    source_head_sha256: str
    prefix_id: str
    prefix_sha256: str
    capture_sha256: str
    pages: tuple[_AuthenticatedAccountActivityPageMaterialization, ...]
    semantic_material: tuple[object, ...]

    @property
    def provider_account_id(self) -> str:
        return self.pages[0].provider_account_id

    @property
    def committed_at(self) -> datetime:
        return self.pages[-1].committed_at


def _materialize_authenticated_source(
    state: AlpacaPaperAuthenticatedAccountActivityTraversalState,
    *,
    capture: AlpacaPaperAccountActivityCapture,
) -> _AuthenticatedAccountActivitySourceMaterialization:
    """Materialize one already-authenticated terminal source without rewalking it."""

    prefix = state.prefix
    pages: list[_AuthenticatedAccountActivityPageMaterialization] = []
    for receipt in prefix.page_receipts:
        evidence_sha256 = _semantic_sha256(receipt.evidence._semantic_material())
        persisted_page_sha256 = receipt.persisted_page.semantic_sha256
        commit_fence_receipt_sha256 = receipt.commit_fence_receipt.semantic_sha256
        receipt_sha256 = _semantic_sha256(
            (
                ALPACA_PAPER_ACCOUNT_ACTIVITY_RUNTIME_CONTRACT_VERSION,
                "authenticated_account_activity_page_receipt",
                evidence_sha256,
                commit_fence_receipt_sha256,
                receipt.previous_page_receipt_sha256,
                receipt.page_number,
                persisted_page_sha256,
            )
        )
        account_binding = receipt.evidence.account_binding
        account_binding_sha256 = account_binding.semantic_sha256
        ingress_receipt = receipt.persisted_page.receipt
        pages.append(
            _AuthenticatedAccountActivityPageMaterialization(
                receipt_id=canonical_id(
                    "alpaca-paper-authenticated-account-activity-page",
                    receipt_sha256,
                ),
                receipt_sha256=receipt_sha256,
                evidence_id=canonical_id(
                    "alpaca-paper-authenticated-account-activity-page-evidence",
                    evidence_sha256,
                ),
                evidence_sha256=evidence_sha256,
                persisted_page_sha256=persisted_page_sha256,
                ingress_receipt_id=ingress_receipt.receipt_id,
                ingress_receipt_sha256=ingress_receipt.semantic_sha256,
                ingress_sequence=ingress_receipt.ingress_sequence,
                account_binding_id=canonical_id(
                    "alpaca-paper-authenticated-account-binding",
                    account_binding_sha256,
                ),
                account_binding_sha256=account_binding_sha256,
                provider_account_id=account_binding.expected_provider_account_id,
                commit_fence_receipt_id=canonical_id(
                    "account-fence-receipt",
                    commit_fence_receipt_sha256,
                ),
                commit_fence_receipt_sha256=commit_fence_receipt_sha256,
                committed_at=receipt.commit_fence_receipt.validated_at,
            )
        )
    page_materializations = tuple(pages)
    plan_sha256 = prefix.plan.semantic_sha256
    capture_sha256 = capture.semantic_sha256
    receipt_sha256s = tuple(page.receipt_sha256 for page in page_materializations)
    prefix_sha256 = _semantic_sha256(
        (
            ALPACA_PAPER_ACCOUNT_ACTIVITY_RUNTIME_CONTRACT_VERSION,
            "authenticated_account_activity_prefix",
            plan_sha256,
            receipt_sha256s,
            capture_sha256,
            capture.pagination_exhausted,
            capture.bounded_truncation,
        )
    )
    state_sha256 = _semantic_sha256(
        (
            ALPACA_PAPER_ACCOUNT_ACTIVITY_RUNTIME_CONTRACT_VERSION,
            "authenticated_account_activity_traversal_state",
            state.stage,
            prefix_sha256,
            (None if state.preparation is None else state.preparation.semantic_sha256),
            state.source_head_sha256,
        )
    )
    source_head_sha256 = _require_sha256(
        state.source_head_sha256,
        "authenticated account-activity source head",
    )
    prefix_id = canonical_id(
        "alpaca-paper-authenticated-account-activity-prefix",
        prefix_sha256,
    )
    source_material = (
        prefix.plan.capture_id,
        plan_sha256,
        state_sha256,
        source_head_sha256,
        prefix_id,
        prefix_sha256,
        capture_sha256,
        prefix.page_count,
        tuple(page.source_material for page in page_materializations),
        page_materializations[-1].receipt_id,
        page_materializations[-1].receipt_sha256,
        capture.pagination_exhausted,
        capture.bounded_truncation,
    )
    return _AuthenticatedAccountActivitySourceMaterialization(
        capture=capture,
        capture_id=prefix.plan.capture_id,
        plan_sha256=plan_sha256,
        state_sha256=state_sha256,
        source_head_sha256=source_head_sha256,
        prefix_id=prefix_id,
        prefix_sha256=prefix_sha256,
        capture_sha256=capture_sha256,
        pages=page_materializations,
        semantic_material=source_material,
    )


@dataclass(frozen=True, slots=True)
class _AuthenticatedAccountActivityComparisonEvidenceMaterialization:
    evidence_id: str
    semantic_sha256: str
    canonical_json: str
    comparison_id: str
    comparison_sha256: str
    account_id: str
    provider_account_id: str
    traversal_profile_sha256: str
    earlier_source: _AuthenticatedAccountActivitySourceMaterialization
    later_source: _AuthenticatedAccountActivitySourceMaterialization
    semantic_material: tuple[object, ...]


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedAccountActivityComparisonEvidence(
    _NoAuthenticatedAccountActivityComparisonAuthority
):
    """Exact Phase 4AF result from two authenticated terminal Phase 4AE states."""

    earlier_state: AlpacaPaperAuthenticatedAccountActivityTraversalState
    later_state: AlpacaPaperAuthenticatedAccountActivityTraversalState
    comparison: AlpacaPaperAccountActivityComparison

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "AlpacaPaperAuthenticatedAccountActivityComparisonEvidence must be proof-constructed"
        )

    def _validate(self) -> None:
        earlier = _terminal_state(
            self.earlier_state,
            field_name="earlier authenticated account-activity state",
        )
        later = _terminal_state(
            self.later_state,
            field_name="later authenticated account-activity state",
        )
        earlier_provider_account_id = _canonical_provider_account_id(
            earlier,
            field_name="earlier authenticated account-activity state",
        )
        later_provider_account_id = _canonical_provider_account_id(
            later,
            field_name="later authenticated account-activity state",
        )
        if earlier_provider_account_id != later_provider_account_id:
            raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
                "account-activity sources bind different provider-account UUIDs"
            )
        earlier_head = _require_sha256(
            earlier.source_head_sha256,
            "earlier authenticated account-activity source head",
        )
        later_head = _require_sha256(
            later.source_head_sha256,
            "later authenticated account-activity source head",
        )
        if earlier_head == later_head:
            raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
                "distinct account-activity sources require distinct terminal heads"
            )
        if type(self.comparison) is not AlpacaPaperAccountActivityComparison:
            raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
                "authenticated account-activity evidence requires an exact Phase 4AF comparison"
            )
        try:
            expected = compare_alpaca_paper_account_activity_captures(
                earlier.prefix.capture,
                later.prefix.capture,
            )
        except (
            AlpacaPaperAccountActivityComparisonError,
            AlpacaPaperAccountActivityConflict,
            TypeError,
            ValueError,
        ):
            raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
                "authenticated account-activity sources cannot be compared exactly"
            ) from None
        if self.comparison != expected:
            raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
                "authenticated account-activity comparison conflicts with exact sources"
            )

    @property
    def earlier_prefix(self) -> AlpacaPaperAuthenticatedAccountActivityPrefix:
        self._validate()
        return self.earlier_state.prefix

    @property
    def later_prefix(self) -> AlpacaPaperAuthenticatedAccountActivityPrefix:
        self._validate()
        return self.later_state.prefix

    @property
    def account_id(self) -> str:
        self._validate()
        return self.comparison.earlier_capture.plan.account_id

    @property
    def provider_account_id(self) -> str:
        self._validate()
        return self.earlier_state.prefix.page_receipts[
            0
        ].evidence.account_binding.expected_provider_account_id

    @property
    def traversal_profile_sha256(self) -> str:
        self._validate()
        return _traversal_profile_sha256(self.comparison.earlier_capture)

    @property
    def earlier_source_head_sha256(self) -> str:
        self._validate()
        return _require_sha256(
            self.earlier_state.source_head_sha256,
            "earlier authenticated account-activity source head",
        )

    @property
    def later_source_head_sha256(self) -> str:
        self._validate()
        return _require_sha256(
            self.later_state.source_head_sha256,
            "later authenticated account-activity source head",
        )

    @property
    def earlier_capture_sha256(self) -> str:
        self._validate()
        return self.comparison.earlier_capture.semantic_sha256

    @property
    def later_capture_sha256(self) -> str:
        self._validate()
        return self.comparison.later_capture.semantic_sha256

    @property
    def latest_source_committed_at(self) -> datetime:
        self._validate()
        return max(
            receipt.commit_fence_receipt.validated_at
            for prefix in (self.earlier_state.prefix, self.later_state.prefix)
            for receipt in prefix.page_receipts
        )

    @property
    def bounded_traversal_incomplete(self) -> bool:
        self._validate()
        return self.comparison.disposition is (
            AlpacaPaperAccountActivityComparisonDisposition.BOUNDED_TRAVERSAL_INCOMPLETE
        )

    @property
    def provider_activity_ids_are_opaque_set_keys(self) -> bool:
        self._validate()
        return True

    @property
    def additional_reconciliation_required(self) -> bool:
        self._validate()
        return True

    @property
    def source_request_budgets_authenticated(self) -> bool:
        self._validate()
        return True

    @property
    def source_provider_evidence_authenticated(self) -> bool:
        self._validate()
        return True

    @property
    def source_raw_responses_authenticated(self) -> bool:
        self._validate()
        return True

    @property
    def source_account_identity_authenticated(self) -> bool:
        self._validate()
        return True

    @property
    def source_terminal_heads_authenticated(self) -> bool:
        self._validate()
        return True

    @property
    def captures_authenticated(self) -> bool:
        self._validate()
        return True

    @property
    def historical_provider_account_identity_authenticated(self) -> bool:
        self._validate()
        return True

    @property
    def evidence_id(self) -> str:
        return _materialize_authenticated_comparison_evidence(self).evidence_id

    def _semantic_material(self) -> tuple[object, ...]:
        return _materialize_authenticated_comparison_evidence(self).semantic_material

    @property
    def semantic_sha256(self) -> str:
        return _materialize_authenticated_comparison_evidence(self).semantic_sha256

    @property
    def canonical_json(self) -> str:
        return _materialize_authenticated_comparison_evidence(self).canonical_json


def _materialize_authenticated_comparison_evidence(
    evidence: AlpacaPaperAuthenticatedAccountActivityComparisonEvidence,
    *,
    authenticate: bool = True,
) -> _AuthenticatedAccountActivityComparisonEvidenceMaterialization:
    """Authenticate once, then derive every evidence identity from one snapshot."""

    if authenticate:
        evidence._validate()
    comparison = evidence.comparison
    earlier_capture = comparison.earlier_capture
    later_capture = comparison.later_capture
    earlier_source = _materialize_authenticated_source(
        evidence.earlier_state,
        capture=earlier_capture,
    )
    later_source = _materialize_authenticated_source(
        evidence.later_state,
        capture=later_capture,
    )
    comparison_material = comparison._semantic_material(authenticate=False)
    comparison_id_value = comparison_material[2]
    if type(comparison_id_value) is not str:
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            "account-activity comparison identity material is malformed"
        )
    comparison_sha256 = _semantic_sha256(comparison_material)
    evidence_id = canonical_id(
        "alpaca-paper-authenticated-account-activity-comparison-evidence",
        ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_POLICY_SHA256,
        earlier_source.capture_id,
        earlier_source.state_sha256,
        later_source.capture_id,
        later_source.state_sha256,
        comparison_sha256,
    )
    account_id = earlier_capture.plan.account_id
    provider_account_id = earlier_source.provider_account_id
    traversal_profile_sha256 = _traversal_profile_sha256(earlier_capture)
    material = (
        ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_CONTRACT_VERSION,
        "authenticated_account_activity_comparison_evidence",
        evidence_id,
        ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_POLICY_ID,
        ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_POLICY_SHA256,
        account_id,
        provider_account_id,
        traversal_profile_sha256,
        earlier_source.semantic_material,
        later_source.semantic_material,
        comparison_id_value,
        comparison_sha256,
        comparison.disposition,
        _view_sha256(earlier_capture),
        _view_sha256(later_capture),
        _timedelta_microseconds(
            _utc_separation(
                earlier_capture,
                later_capture,
            )
        ),
        comparison.added_provider_activity_ids,
        comparison.removed_provider_activity_ids,
        comparison.changed_provider_activity_ids,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        evidence.account_status_current,
        evidence.provider_account_status_current,
        evidence.snapshot_isolation_qualified,
        evidence.provider_snapshot_complete,
        evidence.snapshot_complete,
        evidence.activity_history_complete,
        evidence.activity_history_consistent,
        evidence.converged,
        evidence.monotonic_timing_qualified,
        evidence.provider_activity_identity_qualified,
        evidence.provider_activity_sequence_identity_qualified,
        evidence.provider_activity_revision_identity_qualified,
        evidence.provider_execution_identity_qualified,
        evidence.canonical_execution_identity_qualified,
        evidence.provider_revision_identity_qualified,
        evidence.execution_revision_identity_qualified,
        evidence.provider_deduplication_identity_qualified,
        evidence.provider_bust_identity_qualified,
        evidence.provider_correction_identity_qualified,
        evidence.provider_deduplication_authorized,
        evidence.canonical_execution_fact_authorized,
        evidence.canonical_execution_revision_authorized,
        evidence.canonical_account_fact_authorized,
        evidence.canonical_ledger_fact_authorized,
        evidence.canonical_cash_fact_authorized,
        evidence.execution_application_authorized,
        evidence.bust_application_authorized,
        evidence.correction_application_authorized,
        evidence.manual_activity_application_authorized,
        evidence.normalized_fact_authorized,
        evidence.inbox_application_authorized,
        evidence.lifecycle_application_authorized,
        evidence.reconciliation_application_authorized,
        evidence.reconciliation_completion_authorized,
        evidence.reconciliation_complete,
        evidence.unknown_resolution_authorized,
        evidence.reservation_release_authorized,
        evidence.resubmission_authorized,
        evidence.readiness_transition_authorized,
        evidence.activity_snapshot_pagination_ready,
        evidence.decode_quarantine_ready,
        evidence.reconciliation_ready,
        evidence.dispatch_preflight_ready,
        evidence.paper_startup_ready,
        evidence.transport_submission_ready,
        evidence.submission_authorized,
        evidence.transport_authorized,
        evidence.broker_call_authorized,
        evidence.trading_effect_authorized,
    )
    semantic_sha256 = _semantic_sha256(material)
    return _AuthenticatedAccountActivityComparisonEvidenceMaterialization(
        evidence_id=evidence_id,
        semantic_sha256=semantic_sha256,
        canonical_json=canonical_json_text(material),
        comparison_id=comparison_id_value,
        comparison_sha256=comparison_sha256,
        account_id=account_id,
        provider_account_id=provider_account_id,
        traversal_profile_sha256=traversal_profile_sha256,
        earlier_source=earlier_source,
        later_source=later_source,
        semantic_material=material,
    )


def _alpaca_paper_authenticated_account_activity_comparison_evidence(
    *,
    earlier_state: AlpacaPaperAuthenticatedAccountActivityTraversalState,
    later_state: AlpacaPaperAuthenticatedAccountActivityTraversalState,
) -> AlpacaPaperAuthenticatedAccountActivityComparisonEvidence:
    """Construct evidence only after exact Phase 4AE state authentication."""

    earlier = _terminal_state(
        earlier_state,
        field_name="earlier authenticated account-activity state",
    )
    later = _terminal_state(
        later_state,
        field_name="later authenticated account-activity state",
    )
    try:
        comparison = compare_alpaca_paper_account_activity_captures(
            earlier.prefix.capture,
            later.prefix.capture,
        )
    except (AlpacaPaperAccountActivityComparisonError, TypeError, ValueError):
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            "authenticated account-activity sources cannot be compared exactly"
        ) from None
    evidence = object.__new__(AlpacaPaperAuthenticatedAccountActivityComparisonEvidence)
    object.__setattr__(evidence, "earlier_state", earlier)
    object.__setattr__(evidence, "later_state", later)
    object.__setattr__(evidence, "comparison", comparison)
    evidence._validate()
    return evidence


@dataclass(frozen=True, slots=True)
class _AuthenticatedAccountActivityComparisonReceiptMaterialization:
    receipt_id: str
    semantic_sha256: str
    canonical_json: str
    evidence: _AuthenticatedAccountActivityComparisonEvidenceMaterialization
    semantic_material: tuple[object, ...]


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedAccountActivityComparisonReceipt(
    _NoAuthenticatedAccountActivityComparisonAuthority
):
    """Repository-produced append proof for exact Phase 4AG evidence."""

    evidence: AlpacaPaperAuthenticatedAccountActivityComparisonEvidence
    earlier_source_head_sha256: str
    later_source_head_sha256: str
    commit_fence_receipt: AccountFenceReceipt
    account_sequence: int
    previous_receipt_sha256: str | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "AlpacaPaperAuthenticatedAccountActivityComparisonReceipt must be repository-produced"
        )

    def _validate(self) -> None:
        if type(self.evidence) is not AlpacaPaperAuthenticatedAccountActivityComparisonEvidence:
            raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
                "durable account-activity comparison requires exact Phase 4AG evidence"
            )
        self.evidence._validate()
        earlier_head = _require_sha256(
            self.earlier_source_head_sha256,
            "earlier durable account-activity source head",
        )
        later_head = _require_sha256(
            self.later_source_head_sha256,
            "later durable account-activity source head",
        )
        if (
            earlier_head != self.evidence.earlier_state.source_head_sha256
            or later_head != self.evidence.later_state.source_head_sha256
        ):
            raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
                "durable account-activity receipt changed an exact source head"
            )
        if earlier_head == later_head:
            raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
                "distinct account-activity sources require distinct durable heads"
            )
        if type(self.commit_fence_receipt) is not AccountFenceReceipt:
            raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
                "durable account-activity comparison requires an exact commit fence"
            )
        try:
            self.commit_fence_receipt._validate()
        except (AccountCoordinatorError, TypeError, ValueError):
            raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
                "durable account-activity comparison commit fence is invalid"
            ) from None
        if (
            self.commit_fence_receipt.fence.account_id
            != self.evidence.comparison.earlier_capture.plan.account_id
        ):
            raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
                "durable account-activity comparison fence crosses account identities"
            )
        latest_source_committed_at = max(
            receipt.commit_fence_receipt.validated_at
            for prefix in (
                self.evidence.earlier_state.prefix,
                self.evidence.later_state.prefix,
            )
            for receipt in prefix.page_receipts
        )
        if self.commit_fence_receipt.validated_at < latest_source_committed_at:
            raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
                "durable account-activity comparison predates a source commit"
            )
        if type(self.account_sequence) is not int or self.account_sequence <= 0:
            raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
                "durable account-activity comparison sequence must be positive"
            )
        if self.account_sequence == 1:
            if self.previous_receipt_sha256 is not None:
                raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
                    "first durable account-activity comparison cannot name a predecessor"
                )
        else:
            _require_sha256(
                self.previous_receipt_sha256,
                "durable account-activity comparison predecessor",
            )

    @property
    def account_id(self) -> str:
        self._validate()
        return self.evidence.comparison.earlier_capture.plan.account_id

    @property
    def recorded_at(self) -> datetime:
        self._validate()
        return self.commit_fence_receipt.validated_at

    @property
    def committed_at(self) -> datetime:
        return self.recorded_at

    @property
    def receipt_id(self) -> str:
        return _materialize_authenticated_comparison_receipt(self).receipt_id

    def _semantic_material(self) -> tuple[object, ...]:
        return _materialize_authenticated_comparison_receipt(self).semantic_material

    @property
    def semantic_sha256(self) -> str:
        return _materialize_authenticated_comparison_receipt(self).semantic_sha256

    @property
    def canonical_json(self) -> str:
        return _materialize_authenticated_comparison_receipt(self).canonical_json

    @property
    def source_request_budgets_authenticated(self) -> bool:
        self._validate()
        return True

    @property
    def source_provider_evidence_authenticated(self) -> bool:
        self._validate()
        return True

    @property
    def source_raw_responses_authenticated(self) -> bool:
        self._validate()
        return True

    @property
    def source_account_identity_authenticated(self) -> bool:
        self._validate()
        return True

    @property
    def source_terminal_heads_authenticated(self) -> bool:
        self._validate()
        return True

    @property
    def captures_authenticated(self) -> bool:
        self._validate()
        return True

    @property
    def historical_provider_account_identity_authenticated(self) -> bool:
        self._validate()
        return True

    @property
    def provider_activity_ids_are_opaque_set_keys(self) -> bool:
        self._validate()
        return True

    @property
    def additional_reconciliation_required(self) -> bool:
        self._validate()
        return True

    @property
    def durable_source_positions_authenticated(self) -> bool:
        self._validate()
        return True

    @property
    def comparison_durably_recorded(self) -> bool:
        self._validate()
        return True


def _materialize_authenticated_comparison_receipt(
    receipt: AlpacaPaperAuthenticatedAccountActivityComparisonReceipt,
    *,
    authenticate: bool = True,
) -> _AuthenticatedAccountActivityComparisonReceiptMaterialization:
    """Authenticate once, then derive every durable receipt representation."""

    if authenticate:
        receipt._validate()
    evidence = _materialize_authenticated_comparison_evidence(
        receipt.evidence,
        authenticate=False,
    )
    receipt_id = canonical_id(
        "alpaca-paper-authenticated-account-activity-comparison",
        evidence.evidence_id,
    )
    commit_fence_receipt_sha256 = receipt.commit_fence_receipt.semantic_sha256
    material = (
        ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_CONTRACT_VERSION,
        "authenticated_account_activity_comparison_receipt",
        receipt_id,
        evidence.evidence_id,
        evidence.semantic_sha256,
        receipt.earlier_source_head_sha256,
        receipt.later_source_head_sha256,
        canonical_id(
            "account-fence-receipt",
            commit_fence_receipt_sha256,
        ),
        commit_fence_receipt_sha256,
        receipt.commit_fence_receipt.validated_at,
        receipt.account_sequence,
        receipt.previous_receipt_sha256,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        receipt.account_status_current,
        receipt.provider_account_status_current,
        receipt.snapshot_isolation_qualified,
        receipt.provider_snapshot_complete,
        receipt.snapshot_complete,
        receipt.activity_history_complete,
        receipt.activity_history_consistent,
        receipt.converged,
        receipt.monotonic_timing_qualified,
        receipt.provider_activity_identity_qualified,
        receipt.provider_activity_sequence_identity_qualified,
        receipt.provider_activity_revision_identity_qualified,
        receipt.provider_execution_identity_qualified,
        receipt.canonical_execution_identity_qualified,
        receipt.provider_revision_identity_qualified,
        receipt.execution_revision_identity_qualified,
        receipt.provider_deduplication_identity_qualified,
        receipt.provider_bust_identity_qualified,
        receipt.provider_correction_identity_qualified,
        receipt.provider_deduplication_authorized,
        receipt.canonical_execution_fact_authorized,
        receipt.canonical_execution_revision_authorized,
        receipt.canonical_account_fact_authorized,
        receipt.canonical_ledger_fact_authorized,
        receipt.canonical_cash_fact_authorized,
        receipt.execution_application_authorized,
        receipt.bust_application_authorized,
        receipt.correction_application_authorized,
        receipt.manual_activity_application_authorized,
        receipt.normalized_fact_authorized,
        receipt.inbox_application_authorized,
        receipt.lifecycle_application_authorized,
        receipt.reconciliation_application_authorized,
        receipt.reconciliation_completion_authorized,
        receipt.reconciliation_complete,
        receipt.unknown_resolution_authorized,
        receipt.reservation_release_authorized,
        receipt.resubmission_authorized,
        receipt.readiness_transition_authorized,
        receipt.activity_snapshot_pagination_ready,
        receipt.decode_quarantine_ready,
        receipt.reconciliation_ready,
        receipt.dispatch_preflight_ready,
        receipt.paper_startup_ready,
        receipt.transport_submission_ready,
        receipt.submission_authorized,
        receipt.transport_authorized,
        receipt.broker_call_authorized,
        receipt.trading_effect_authorized,
    )
    semantic_sha256 = _semantic_sha256(material)
    return _AuthenticatedAccountActivityComparisonReceiptMaterialization(
        receipt_id=receipt_id,
        semantic_sha256=semantic_sha256,
        canonical_json=canonical_json_text(material),
        evidence=evidence,
        semantic_material=material,
    )


def _alpaca_paper_authenticated_account_activity_comparison_receipt(
    evidence: AlpacaPaperAuthenticatedAccountActivityComparisonEvidence,
    *,
    earlier_source_head_sha256: str,
    later_source_head_sha256: str,
    commit_fence_receipt: AccountFenceReceipt,
    account_sequence: int,
    previous_receipt_sha256: str | None,
) -> AlpacaPaperAuthenticatedAccountActivityComparisonReceipt:
    """Construct exactly the value a durable repository appended."""

    receipt = object.__new__(AlpacaPaperAuthenticatedAccountActivityComparisonReceipt)
    for field_name, value in (
        ("evidence", evidence),
        ("earlier_source_head_sha256", earlier_source_head_sha256),
        ("later_source_head_sha256", later_source_head_sha256),
        ("commit_fence_receipt", commit_fence_receipt),
        ("account_sequence", account_sequence),
        ("previous_receipt_sha256", previous_receipt_sha256),
    ):
        object.__setattr__(receipt, field_name, value)
    receipt._validate()
    return receipt


class AlpacaPaperAccountActivityStateLoader(Protocol):
    """Reload one exact durable Phase 4AE traversal state."""

    @property
    def runtime_store_identity(self) -> int: ...

    def load_state(
        self,
        plan: AlpacaPaperAccountActivityPlan,
    ) -> AlpacaPaperAuthenticatedAccountActivityTraversalState | None: ...


class AlpacaPaperAccountActivityComparisonRepository(Protocol):
    """Append one exact Phase 4AG evidence value under an account fence."""

    @property
    def runtime_store_identity(self) -> int: ...

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedAccountActivityComparisonEvidence,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedAccountActivityComparisonReceipt: ...


def _load_exact_terminal_state(
    plan: AlpacaPaperAccountActivityPlan,
    *,
    loader: AlpacaPaperAccountActivityStateLoader,
    field_name: str,
) -> AlpacaPaperAuthenticatedAccountActivityTraversalState:
    try:
        value = loader.load_state(plan)
    except AlpacaPaperAuthenticatedAccountActivityComparisonError:
        raise
    except Exception:
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            f"{field_name} could not be reloaded and authenticated"
        ) from None
    state = _terminal_state(value, field_name=field_name)
    if state.prefix.plan != plan:
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            f"{field_name} loader returned another plan"
        )
    return state


def compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
    earlier_plan: AlpacaPaperAccountActivityPlan,
    later_plan: AlpacaPaperAccountActivityPlan,
    *,
    fence: AccountFence,
    state_loader: AlpacaPaperAccountActivityStateLoader,
    comparison_repository: AlpacaPaperAccountActivityComparisonRepository,
) -> AlpacaPaperAuthenticatedAccountActivityComparisonReceipt:
    """Reload, compare, and append one exact source-authenticated pair."""

    _validate_runtime_store_composition(
        state_loader=state_loader,
        comparison_repository=comparison_repository,
    )
    earlier_plan = _require_plan(
        earlier_plan,
        "earlier account-activity plan",
    )
    later_plan = _require_plan(
        later_plan,
        "later account-activity plan",
    )
    if earlier_plan.capture_id == later_plan.capture_id:
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            "authenticated account-activity comparison requires distinct plans"
        )
    if type(fence) is not AccountFence:
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            "authenticated account-activity comparison requires an exact account fence"
        )
    try:
        fence.__post_init__()
    except (AccountCoordinatorError, TypeError, ValueError):
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            "authenticated account-activity comparison fence is invalid"
        ) from None
    if fence.account_id != earlier_plan.account_id or fence.account_id != later_plan.account_id:
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            "authenticated account-activity comparison fence crosses account identities"
        )
    if not callable(getattr(state_loader, "load_state", None)):
        raise AlpacaPaperAuthenticatedAccountActivityComparisonError(
            "account-activity state loader does not implement load_state"
        )
    if not callable(getattr(comparison_repository, "record", None)):
        raise AlpacaPaperAuthenticatedAccountActivityComparisonError(
            "account-activity comparison repository does not implement record"
        )

    earlier_state = _load_exact_terminal_state(
        earlier_plan,
        loader=state_loader,
        field_name="earlier authenticated account-activity state",
    )
    later_state = _load_exact_terminal_state(
        later_plan,
        loader=state_loader,
        field_name="later authenticated account-activity state",
    )
    evidence = _alpaca_paper_authenticated_account_activity_comparison_evidence(
        earlier_state=earlier_state,
        later_state=later_state,
    )
    try:
        receipt = comparison_repository.record(evidence, fence=fence)
    except AlpacaPaperAuthenticatedAccountActivityComparisonError:
        raise
    except Exception:
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            "authenticated account-activity comparison append failed"
        ) from None
    if type(receipt) is not AlpacaPaperAuthenticatedAccountActivityComparisonReceipt:
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            "account-activity comparison repository returned a non-canonical receipt"
        )
    try:
        receipt._validate()
    except (
        AlpacaPaperAuthenticatedAccountActivityComparisonError,
        TypeError,
        ValueError,
    ):
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            "account-activity comparison repository returned invalid durable evidence"
        ) from None
    if receipt.evidence != evidence:
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            "account-activity comparison repository changed authenticated evidence"
        )
    if (
        receipt.earlier_source_head_sha256 != earlier_state.source_head_sha256
        or receipt.later_source_head_sha256 != later_state.source_head_sha256
    ):
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            "account-activity comparison repository changed source terminal heads"
        )
    if receipt.commit_fence_receipt.fence != fence:
        raise AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict(
            "account-activity comparison repository changed the exact account fence"
        )
    return receipt


__all__ = [
    "ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_CONTRACT_VERSION",
    "ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_POLICY_ID",
    "ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_POLICY_SHA256",
    "AlpacaPaperAccountActivityComparisonRepository",
    "AlpacaPaperAccountActivityStateLoader",
    "AlpacaPaperAuthenticatedAccountActivityComparisonError",
    "AlpacaPaperAuthenticatedAccountActivityComparisonEvidence",
    "AlpacaPaperAuthenticatedAccountActivityComparisonReceipt",
    "AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict",
    "AlpacaPaperAuthenticatedAccountActivityComparisonSourceMissing",
    "compare_and_record_authenticated_alpaca_paper_account_activity_prefixes",
]
