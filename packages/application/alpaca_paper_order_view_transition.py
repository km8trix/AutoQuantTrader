"""Durable-admission proofs for one ordered pair of paginated order views.

Phase 4AA reserves an exact pair and admits one exact next page at a time.
Claims and consumptions are historical, non-authorizing values.  Persistence
must prove source eligibility, global membership, atomic preparation, and
same-lease commit; Phase 4AB will compose those proofs through provider I/O.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from packages.adapters.broker.alpaca_paper_order_snapshot_comparison import (
    ALPACA_PAPER_ORDER_SNAPSHOT_MINIMUM_UTC_SEPARATION,
)
from packages.adapters.broker.alpaca_paper_order_snapshot_runtime import (
    ALPACA_PAPER_ORDER_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
    AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    AlpacaPaperOrderSnapshotConflict,
    AlpacaPaperOrderSnapshotPagePreparationReceipt,
)
from packages.adapters.broker.alpaca_paper_order_snapshots import (
    ALPACA_PAPER_ORDER_SNAPSHOT_CONTRACT_VERSION,
    AlpacaPaperOrderSnapshotError,
    AlpacaPaperOrderSnapshotPageDescription,
    AlpacaPaperOrderSnapshotPlan,
)
from packages.domain.account_coordinator import (
    AccountCoordinatorError,
    AccountFenceReceipt,
)
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.identifiers import canonical_id

ALPACA_PAPER_ORDER_VIEW_TRANSITION_CONTRACT_VERSION = (
    "phase4aa-durable-order-view-transition-admission-v1"
)
ALPACA_PAPER_ORDER_VIEW_TRANSITION_POLICY_ID = "phase4aa-exact-pair-next-page-transition-policy-v1"
ALPACA_PAPER_ORDER_VIEW_TRANSITION_MINIMUM_START_SEPARATION = (
    ALPACA_PAPER_ORDER_SNAPSHOT_MINIMUM_UTC_SEPARATION
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _duration_microseconds(value: timedelta) -> int:
    if type(value) is not timedelta:
        raise TypeError("transition duration must be an exact timedelta")
    return (value.days * 86_400 + value.seconds) * 1_000_000 + value.microseconds


ALPACA_PAPER_ORDER_VIEW_TRANSITION_POLICY_SHA256 = _semantic_sha256(
    (
        ALPACA_PAPER_ORDER_VIEW_TRANSITION_CONTRACT_VERSION,
        "transition_policy",
        ALPACA_PAPER_ORDER_VIEW_TRANSITION_POLICY_ID,
        ALPACA_PAPER_ORDER_SNAPSHOT_CONTRACT_VERSION,
        ALPACA_PAPER_ORDER_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
        _duration_microseconds(ALPACA_PAPER_ORDER_VIEW_TRANSITION_MINIMUM_START_SEPARATION),
        "one_exact_ordered_pair_membership",
        "one_plan_may_belong_to_only_one_round_in_either_role",
        "one_claim_per_exact_next_page",
        "gap_free_same_role_claim_predecessor",
        "later_requires_exact_terminal_earlier_prefix",
        "later_selection_requires_minimum_receive_time_boundary",
        "claim_consumed_with_immutable_page_preparation",
        "unscoped_preparation_of_registered_members_is_forbidden",
        "historical_claim_retry_reauthenticates_current_fence",
        "new_claim_and_consumption_require_final_same_lease_validation",
        "no_provider_io_or_reconciliation_authority",
    )
)


class AlpacaPaperOrderViewTransitionError(RuntimeError):
    """An exact order-pair page transition could not be admitted."""


class AlpacaPaperOrderViewTransitionConflict(AlpacaPaperOrderViewTransitionError):
    """Pair, page, source, preparation, or fence evidence conflicts."""


class AlpacaPaperOrderViewTransitionRole(StrEnum):
    """The two ordered paginated captures in one transition round."""

    EARLIER = "earlier"
    LATER = "later"


class _NoOrderViewTransitionAuthority:
    __slots__ = ()

    @property
    def authenticated_provider_evidence(self) -> bool:
        return False

    @property
    def request_budget_enforced(self) -> bool:
        return False

    @property
    def raw_response_persisted(self) -> bool:
        return False

    @property
    def runtime_current(self) -> bool:
        return False

    @property
    def capture_authenticated(self) -> bool:
        return False

    @property
    def durable_source_positions_authenticated(self) -> bool:
        return False

    @property
    def snapshot_isolation_qualified(self) -> bool:
        return False

    @property
    def provider_snapshot_complete(self) -> bool:
        return False

    @property
    def monotonic_timing_qualified(self) -> bool:
        return False

    @property
    def provider_revision_identity_qualified(self) -> bool:
        return False

    @property
    def provider_deduplication_authorized(self) -> bool:
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
    def resubmission_authorized(self) -> bool:
        return False

    @property
    def reservation_release_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_fact_authorized(self) -> bool:
        return False

    @property
    def readiness_transition_authorized(self) -> bool:
        return False

    @property
    def reconciliation_ready(self) -> bool:
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

    @property
    def converged(self) -> bool:
        return False


def _require_sha256(value: object, field_name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise AlpacaPaperOrderViewTransitionConflict(
            f"{field_name} must be a lowercase SHA-256 digest"
        )
    return value


def _require_plan(
    value: object,
    field_name: str,
) -> AlpacaPaperOrderSnapshotPlan:
    if type(value) is not AlpacaPaperOrderSnapshotPlan:
        raise AlpacaPaperOrderViewTransitionConflict(
            f"{field_name} must be an exact order-snapshot plan"
        )
    try:
        value.__post_init__()
    except (AlpacaPaperOrderSnapshotError, TypeError, ValueError):
        raise AlpacaPaperOrderViewTransitionConflict(f"{field_name} is invalid") from None
    return value


def _require_prefix(
    value: object,
    field_name: str,
) -> AlpacaPaperAuthenticatedOrderSnapshotPrefix:
    if type(value) is not AlpacaPaperAuthenticatedOrderSnapshotPrefix:
        raise AlpacaPaperOrderViewTransitionConflict(
            f"{field_name} must be an exact authenticated prefix"
        )
    try:
        value._validate()
    except (AlpacaPaperOrderSnapshotConflict, TypeError, ValueError):
        raise AlpacaPaperOrderViewTransitionConflict(f"{field_name} is invalid") from None
    return value


def _require_fence(
    value: object,
    field_name: str,
) -> AccountFenceReceipt:
    if type(value) is not AccountFenceReceipt:
        raise AlpacaPaperOrderViewTransitionConflict(
            f"{field_name} must be an exact account-fence receipt"
        )
    try:
        value._validate()
    except (AccountCoordinatorError, TypeError, ValueError):
        raise AlpacaPaperOrderViewTransitionConflict(f"{field_name} is invalid") from None
    return value


@dataclass(frozen=True, slots=True)
class AlpacaPaperOrderViewTransitionPlan(_NoOrderViewTransitionAuthority):
    """One exact ordered pair reserved for Phase 4AA page claims."""

    earlier_plan: AlpacaPaperOrderSnapshotPlan
    later_plan: AlpacaPaperOrderSnapshotPlan

    def __post_init__(self) -> None:
        earlier = _require_plan(self.earlier_plan, "earlier transition plan")
        later = _require_plan(self.later_plan, "later transition plan")
        if earlier.snapshot_id == later.snapshot_id:
            raise AlpacaPaperOrderViewTransitionConflict(
                "order-view transition requires two distinct plans"
            )
        if earlier.account_id != later.account_id:
            raise AlpacaPaperOrderViewTransitionConflict(
                "order-view transition plans cross account identities"
            )
        if earlier.page_limit != later.page_limit or earlier.maximum_pages != later.maximum_pages:
            raise AlpacaPaperOrderViewTransitionConflict(
                "order-view transition plans use different traversal profiles"
            )

    @property
    def account_id(self) -> str:
        self.__post_init__()
        return self.earlier_plan.account_id

    @property
    def round_id(self) -> str:
        self.__post_init__()
        return canonical_id(
            "alpaca-paper-order-view-transition-round",
            ALPACA_PAPER_ORDER_VIEW_TRANSITION_POLICY_SHA256,
            self.earlier_plan.snapshot_id,
            self.earlier_plan.semantic_sha256,
            self.later_plan.snapshot_id,
            self.later_plan.semantic_sha256,
        )

    def selected_plan(
        self,
        role: AlpacaPaperOrderViewTransitionRole,
    ) -> AlpacaPaperOrderSnapshotPlan:
        if type(role) is not AlpacaPaperOrderViewTransitionRole:
            raise AlpacaPaperOrderViewTransitionConflict("order-view transition role is invalid")
        return (
            self.earlier_plan
            if role is AlpacaPaperOrderViewTransitionRole.EARLIER
            else self.later_plan
        )

    def _semantic_material(self) -> tuple[object, ...]:
        self.__post_init__()
        return (
            ALPACA_PAPER_ORDER_VIEW_TRANSITION_CONTRACT_VERSION,
            "transition_plan",
            self.round_id,
            ALPACA_PAPER_ORDER_VIEW_TRANSITION_POLICY_ID,
            ALPACA_PAPER_ORDER_VIEW_TRANSITION_POLICY_SHA256,
            self.account_id,
            self.earlier_plan.snapshot_id,
            self.earlier_plan.semantic_sha256,
            self.later_plan.snapshot_id,
            self.later_plan.semantic_sha256,
            self.earlier_plan.page_limit,
            self.earlier_plan.maximum_pages,
            False,
            False,
            False,
            False,
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


def create_alpaca_paper_order_view_transition_plan(
    *,
    earlier_plan: AlpacaPaperOrderSnapshotPlan,
    later_plan: AlpacaPaperOrderSnapshotPlan,
) -> AlpacaPaperOrderViewTransitionPlan:
    return AlpacaPaperOrderViewTransitionPlan(
        earlier_plan=earlier_plan,
        later_plan=later_plan,
    )


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperOrderViewTransitionClaim(_NoOrderViewTransitionAuthority):
    """Repository-produced admission of one exact next page."""

    plan: AlpacaPaperOrderViewTransitionPlan
    selected_role: AlpacaPaperOrderViewTransitionRole
    selected_prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix
    previous_claim: AlpacaPaperOrderViewTransitionClaim | None
    prior_earlier_prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix | None
    prior_earlier_source_head_sha256: str | None
    commit_fence_receipt: AccountFenceReceipt

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("order-view transition claims must be repository-produced")

    def _validate_fence_only(self) -> None:
        fence = _require_fence(
            self.commit_fence_receipt,
            "order-view transition claim fence",
        )
        if fence.fence.account_id != self.plan.account_id:
            raise AlpacaPaperOrderViewTransitionConflict(
                "order-view transition claim fence crosses account identities"
            )

    def _validate_previous_claim(
        self,
        prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    ) -> None:
        previous_receipt = None if not prefix.page_receipts else prefix.page_receipts[-1]
        if previous_receipt is None:
            if self.previous_claim is not None:
                raise AlpacaPaperOrderViewTransitionConflict(
                    "first-page transition claim cannot name a predecessor claim"
                )
            return
        if type(self.previous_claim) is not AlpacaPaperOrderViewTransitionClaim:
            raise AlpacaPaperOrderViewTransitionConflict(
                "continued transition claim requires its exact predecessor claim"
            )
        previous = self.previous_claim
        previous._validate()
        previous_predecessor = (
            None
            if not previous.selected_prefix.page_receipts
            else previous.selected_prefix.page_receipts[-1]
        )
        preparation = previous_receipt.evidence.preparation
        if (
            previous.plan != self.plan
            or previous.selected_role is not self.selected_role
            or previous.selected_prefix.page_receipts != prefix.page_receipts[:-1]
            or previous.description != previous_receipt.description
            or previous.description.page_number + 1 != self.description.page_number
            or self.selected_at < previous.selected_at
            or self.selected_at < previous_receipt.commit_fence_receipt.validated_at
            or previous.description.previous_page_sha256
            != (
                None
                if not previous.selected_prefix.page_receipts
                else previous.selected_prefix.page_receipts[-1].persisted_page.semantic_sha256
            )
            or preparation.description != previous.description
            or preparation.prefix_capture_sha256 != previous.selected_prefix.capture.semantic_sha256
            or preparation.prefix_page_count != previous.selected_prefix.page_count
            or preparation.previous_page_receipt_id
            != (None if previous_predecessor is None else previous_predecessor.receipt_id)
            or preparation.previous_page_receipt_sha256
            != (None if previous_predecessor is None else previous_predecessor.semantic_sha256)
            or preparation.prepared_at < previous.selected_at
        ):
            raise AlpacaPaperOrderViewTransitionConflict(
                "continued transition claim conflicts with its predecessor chain"
            )

    def _validate_later_source(self) -> None:
        if self.selected_role is AlpacaPaperOrderViewTransitionRole.EARLIER:
            if (
                self.prior_earlier_prefix is not None
                or self.prior_earlier_source_head_sha256 is not None
            ):
                raise AlpacaPaperOrderViewTransitionConflict(
                    "earlier transition claim cannot name a prior earlier source"
                )
            return
        earlier = _require_prefix(
            self.prior_earlier_prefix,
            "later transition earlier source",
        )
        _require_sha256(
            self.prior_earlier_source_head_sha256,
            "later transition earlier source head",
        )
        capture = earlier.capture
        if (
            earlier.plan != self.plan.earlier_plan
            or not earlier.page_receipts
            or not (capture.pagination_exhausted or capture.bounded_truncation)
        ):
            raise AlpacaPaperOrderViewTransitionConflict(
                "later transition requires the exact terminal earlier prefix"
            )
        previous = self.previous_claim
        if previous is not None and (
            previous.prior_earlier_prefix != earlier
            or previous.prior_earlier_source_head_sha256 != self.prior_earlier_source_head_sha256
        ):
            raise AlpacaPaperOrderViewTransitionConflict(
                "continued later transition changed its terminal earlier source"
            )
        eligible_at = self.eligible_at
        assert eligible_at is not None
        earlier_tip = earlier.page_receipts[-1]
        if (
            self.selected_at < eligible_at
            or self.selected_at < earlier_tip.commit_fence_receipt.validated_at
        ):
            raise AlpacaPaperOrderViewTransitionConflict(
                "later transition was selected before its terminal-source boundary"
            )

    def _validate(self) -> None:
        if type(self.plan) is not AlpacaPaperOrderViewTransitionPlan:
            raise AlpacaPaperOrderViewTransitionConflict(
                "order-view transition claim requires an exact plan"
            )
        self.plan.__post_init__()
        if type(self.selected_role) is not AlpacaPaperOrderViewTransitionRole:
            raise AlpacaPaperOrderViewTransitionConflict(
                "order-view transition claim role is invalid"
            )
        prefix = _require_prefix(
            self.selected_prefix,
            "order-view transition selected prefix",
        )
        if prefix.plan != self.selected_plan or prefix.next_page_description is None:
            raise AlpacaPaperOrderViewTransitionConflict(
                "order-view transition claim does not select an exact next page"
            )
        self._validate_fence_only()
        self._validate_previous_claim(prefix)
        self._validate_later_source()

    @property
    def selected_plan(self) -> AlpacaPaperOrderSnapshotPlan:
        if type(self.plan) is not AlpacaPaperOrderViewTransitionPlan:
            raise AlpacaPaperOrderViewTransitionConflict(
                "order-view transition claim requires an exact plan"
            )
        return self.plan.selected_plan(self.selected_role)

    @property
    def description(self) -> AlpacaPaperOrderSnapshotPageDescription:
        description = self.selected_prefix.next_page_description
        if description is None:
            raise AlpacaPaperOrderViewTransitionConflict(
                "order-view transition claim has no next page"
            )
        return description

    @property
    def selected_at(self) -> datetime:
        self._validate_fence_only()
        return self.commit_fence_receipt.validated_at

    @property
    def eligible_at(self) -> datetime | None:
        if self.selected_role is AlpacaPaperOrderViewTransitionRole.EARLIER:
            return None
        earlier = _require_prefix(
            self.prior_earlier_prefix,
            "later transition earlier source",
        )
        if not earlier.page_receipts:
            raise AlpacaPaperOrderViewTransitionConflict(
                "later transition earlier source has no terminal page"
            )
        return (
            earlier.page_receipts[-1].persisted_page.observation.received_at
            + ALPACA_PAPER_ORDER_VIEW_TRANSITION_MINIMUM_START_SEPARATION
        )

    @property
    def previous_page_receipt_id(self) -> str | None:
        if not self.selected_prefix.page_receipts:
            return None
        return self.selected_prefix.page_receipts[-1].receipt_id

    @property
    def previous_page_receipt_sha256(self) -> str | None:
        if not self.selected_prefix.page_receipts:
            return None
        return self.selected_prefix.page_receipts[-1].semantic_sha256

    @property
    def previous_persisted_page_sha256(self) -> str | None:
        return self.description.previous_page_sha256

    @property
    def claim_id(self) -> str:
        self._validate()
        return alpaca_paper_order_view_transition_claim_id(
            self.plan,
            selected_role=self.selected_role,
            selected_prefix=self.selected_prefix,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        self._validate()
        previous = self.previous_claim
        earlier = self.prior_earlier_prefix
        earlier_tip = None if earlier is None else earlier.page_receipts[-1]
        return (
            ALPACA_PAPER_ORDER_VIEW_TRANSITION_CONTRACT_VERSION,
            "transition_claim",
            self.claim_id,
            ALPACA_PAPER_ORDER_VIEW_TRANSITION_POLICY_ID,
            ALPACA_PAPER_ORDER_VIEW_TRANSITION_POLICY_SHA256,
            self.plan.round_id,
            self.plan.semantic_sha256,
            self.selected_role,
            self.selected_plan.snapshot_id,
            self.selected_plan.semantic_sha256,
            self.description.page_number,
            self.description.semantic_sha256,
            self.description.before_order_id,
            self.selected_prefix.prefix_id,
            self.selected_prefix.semantic_sha256,
            self.selected_prefix.capture.semantic_sha256,
            self.selected_prefix.page_count,
            self.previous_page_receipt_id,
            self.previous_page_receipt_sha256,
            self.previous_persisted_page_sha256,
            None if previous is None else previous.claim_id,
            None if previous is None else previous.semantic_sha256,
            None if earlier is None else earlier.prefix_id,
            None if earlier is None else earlier.semantic_sha256,
            self.prior_earlier_source_head_sha256,
            None if earlier_tip is None else earlier_tip.receipt_id,
            None if earlier_tip is None else earlier_tip.semantic_sha256,
            None if earlier_tip is None else earlier_tip.persisted_page.observation.received_at,
            self.selected_at,
            self.eligible_at,
            self.commit_fence_receipt.receipt_id,
            self.commit_fence_receipt.semantic_sha256,
            False,
            False,
            False,
            False,
            False,
            False,
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


def alpaca_paper_order_view_transition_claim_id(
    plan: AlpacaPaperOrderViewTransitionPlan,
    *,
    selected_role: AlpacaPaperOrderViewTransitionRole,
    selected_prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
) -> str:
    """Return the stable identity of one exact pair/page admission."""

    if type(plan) is not AlpacaPaperOrderViewTransitionPlan:
        raise AlpacaPaperOrderViewTransitionConflict(
            "transition claim identity requires an exact plan"
        )
    plan.__post_init__()
    if type(selected_role) is not AlpacaPaperOrderViewTransitionRole:
        raise AlpacaPaperOrderViewTransitionConflict(
            "transition claim identity requires an exact role"
        )
    prefix = _require_prefix(
        selected_prefix,
        "transition claim identity prefix",
    )
    if prefix.plan != plan.selected_plan(selected_role):
        raise AlpacaPaperOrderViewTransitionConflict(
            "transition claim identity prefix selects another plan"
        )
    description = prefix.next_page_description
    if description is None:
        raise AlpacaPaperOrderViewTransitionConflict(
            "transition claim identity requires an exact next page"
        )
    return canonical_id(
        "alpaca-paper-order-view-transition-claim",
        ALPACA_PAPER_ORDER_VIEW_TRANSITION_POLICY_SHA256,
        plan.round_id,
        selected_role,
        description.semantic_sha256,
        prefix.semantic_sha256,
    )


def _alpaca_paper_order_view_transition_claim(
    *,
    plan: AlpacaPaperOrderViewTransitionPlan,
    selected_role: AlpacaPaperOrderViewTransitionRole,
    selected_prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    previous_claim: AlpacaPaperOrderViewTransitionClaim | None,
    prior_earlier_prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix | None,
    prior_earlier_source_head_sha256: str | None,
    commit_fence_receipt: AccountFenceReceipt,
) -> AlpacaPaperOrderViewTransitionClaim:
    value = object.__new__(AlpacaPaperOrderViewTransitionClaim)
    for field_name, field_value in (
        ("plan", plan),
        ("selected_role", selected_role),
        ("selected_prefix", selected_prefix),
        ("previous_claim", previous_claim),
        ("prior_earlier_prefix", prior_earlier_prefix),
        ("prior_earlier_source_head_sha256", prior_earlier_source_head_sha256),
        ("commit_fence_receipt", commit_fence_receipt),
    ):
        object.__setattr__(value, field_name, field_value)
    value._validate()
    return value


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperOrderViewTransitionConsumption(_NoOrderViewTransitionAuthority):
    claim: AlpacaPaperOrderViewTransitionClaim
    preparation: AlpacaPaperOrderSnapshotPagePreparationReceipt
    commit_fence_receipt: AccountFenceReceipt

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("order-view transition consumptions must be repository-produced")

    def _validate(self) -> None:
        if type(self.claim) is not AlpacaPaperOrderViewTransitionClaim:
            raise AlpacaPaperOrderViewTransitionConflict(
                "transition consumption requires an exact claim"
            )
        self.claim._validate()
        if type(self.preparation) is not AlpacaPaperOrderSnapshotPagePreparationReceipt:
            raise AlpacaPaperOrderViewTransitionConflict(
                "transition consumption requires an exact page preparation"
            )
        try:
            self.preparation._validate()
        except (AlpacaPaperOrderSnapshotConflict, TypeError, ValueError):
            raise AlpacaPaperOrderViewTransitionConflict(
                "transition consumption preparation is invalid"
            ) from None
        previous = (
            None
            if not self.claim.selected_prefix.page_receipts
            else self.claim.selected_prefix.page_receipts[-1]
        )
        if (
            self.preparation.description != self.claim.description
            or self.preparation.prefix_capture_sha256
            != self.claim.selected_prefix.capture.semantic_sha256
            or self.preparation.prefix_page_count != self.claim.selected_prefix.page_count
            or self.preparation.previous_page_receipt_id
            != (None if previous is None else previous.receipt_id)
            or self.preparation.previous_page_receipt_sha256
            != (None if previous is None else previous.semantic_sha256)
            or self.preparation.prepared_at < self.claim.selected_at
        ):
            raise AlpacaPaperOrderViewTransitionConflict(
                "transition consumption prepared another page or prefix"
            )
        fence = _require_fence(
            self.commit_fence_receipt,
            "order-view transition consumption fence",
        )
        claim_fence = self.claim.commit_fence_receipt
        if (
            fence.fence != claim_fence.fence
            or fence.policy_sha256 != claim_fence.policy_sha256
            or fence.lease_sha256 != claim_fence.lease_sha256
            or fence.valid_until != claim_fence.valid_until
            or fence.validated_at < claim_fence.validated_at
            or fence.validated_at < self.preparation.prepared_at
            or fence.validated_at >= fence.valid_until
        ):
            raise AlpacaPaperOrderViewTransitionConflict(
                "transition consumption fence conflicts with its claim or preparation"
            )

    @property
    def consumed_at(self) -> datetime:
        self._validate()
        return self.commit_fence_receipt.validated_at

    @property
    def consumption_id(self) -> str:
        self._validate()
        return alpaca_paper_order_view_transition_consumption_id(
            self.claim,
            self.preparation,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        self._validate()
        return (
            ALPACA_PAPER_ORDER_VIEW_TRANSITION_CONTRACT_VERSION,
            "transition_consumption",
            self.consumption_id,
            self.claim.claim_id,
            self.claim.semantic_sha256,
            self.claim.plan.round_id,
            self.claim.selected_role,
            self.claim.description.page_number,
            self.claim.description.semantic_sha256,
            self.preparation.preparation_id,
            self.preparation.semantic_sha256,
            self.preparation.prefix_capture_sha256,
            self.preparation.prefix_page_count,
            self.preparation.prepared_at,
            self.commit_fence_receipt.receipt_id,
            self.commit_fence_receipt.semantic_sha256,
            self.consumed_at,
            False,
            False,
            False,
            False,
            False,
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


def alpaca_paper_order_view_transition_consumption_id(
    claim: AlpacaPaperOrderViewTransitionClaim,
    preparation: AlpacaPaperOrderSnapshotPagePreparationReceipt,
) -> str:
    """Return the stable identity of one exact claim consumption."""

    if type(claim) is not AlpacaPaperOrderViewTransitionClaim:
        raise AlpacaPaperOrderViewTransitionConflict(
            "transition consumption identity requires an exact claim"
        )
    claim._validate()
    if type(preparation) is not AlpacaPaperOrderSnapshotPagePreparationReceipt:
        raise AlpacaPaperOrderViewTransitionConflict(
            "transition consumption identity requires an exact preparation"
        )
    try:
        preparation._validate()
    except (AlpacaPaperOrderSnapshotConflict, TypeError, ValueError):
        raise AlpacaPaperOrderViewTransitionConflict(
            "transition consumption identity preparation is invalid"
        ) from None
    if preparation.description != claim.description:
        raise AlpacaPaperOrderViewTransitionConflict(
            "transition consumption identity prepared another page"
        )
    return canonical_id(
        "alpaca-paper-order-view-transition-consumption",
        ALPACA_PAPER_ORDER_VIEW_TRANSITION_POLICY_SHA256,
        claim.claim_id,
        preparation.preparation_id,
    )


def _alpaca_paper_order_view_transition_consumption(
    *,
    claim: AlpacaPaperOrderViewTransitionClaim,
    preparation: AlpacaPaperOrderSnapshotPagePreparationReceipt,
    commit_fence_receipt: AccountFenceReceipt,
) -> AlpacaPaperOrderViewTransitionConsumption:
    value = object.__new__(AlpacaPaperOrderViewTransitionConsumption)
    for field_name, field_value in (
        ("claim", claim),
        ("preparation", preparation),
        ("commit_fence_receipt", commit_fence_receipt),
    ):
        object.__setattr__(value, field_name, field_value)
    value._validate()
    return value


__all__ = [
    "ALPACA_PAPER_ORDER_VIEW_TRANSITION_CONTRACT_VERSION",
    "ALPACA_PAPER_ORDER_VIEW_TRANSITION_MINIMUM_START_SEPARATION",
    "ALPACA_PAPER_ORDER_VIEW_TRANSITION_POLICY_ID",
    "ALPACA_PAPER_ORDER_VIEW_TRANSITION_POLICY_SHA256",
    "AlpacaPaperOrderViewTransitionClaim",
    "AlpacaPaperOrderViewTransitionConflict",
    "AlpacaPaperOrderViewTransitionConsumption",
    "AlpacaPaperOrderViewTransitionError",
    "AlpacaPaperOrderViewTransitionPlan",
    "AlpacaPaperOrderViewTransitionRole",
    "_alpaca_paper_order_view_transition_claim",
    "_alpaca_paper_order_view_transition_consumption",
    "alpaca_paper_order_view_transition_claim_id",
    "alpaca_paper_order_view_transition_consumption_id",
    "create_alpaca_paper_order_view_transition_plan",
]
