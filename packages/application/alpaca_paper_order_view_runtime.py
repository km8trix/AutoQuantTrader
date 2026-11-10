"""Pair-admitted composition for one bounded Alpaca order-view step.

Phase 4AB composes the durable Phase 4AA per-page claims with the unchanged
Phase 4O page runtime and Phase 4Q supervisor.  Every committed page is
reauthenticated against the claim and consumption for its exact preceding
prefix.  A newly selected page is claimed using the exact prefix and durable
source-head digest that Phase 4Q observed, then its claim is atomically
consumed by the unchanged Phase 4O preparation before credentials, request
admission, or provider I/O.

Claims and consumptions are historical proofs.  This composition does not
loop, retry a stalled page, infer snapshot isolation or convergence, apply
orders, advance readiness, or authorize trading.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from packages.adapters.broker.alpaca_paper_order_snapshot_runtime import (
    ALPACA_PAPER_ORDER_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
    AlpacaPaperAuthenticatedOrderSnapshotPageEvidence,
    AlpacaPaperAuthenticatedOrderSnapshotPageReceipt,
    AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    AlpacaPaperOrderSnapshotConflict,
    AlpacaPaperOrderSnapshotPagePreparationReceipt,
    AlpacaPaperOrderSnapshotPageRuntimePort,
    _alpaca_paper_authenticated_order_snapshot_prefix,
)
from packages.adapters.broker.alpaca_paper_order_snapshots import (
    AlpacaPaperOrderSnapshotPageDescription,
    AlpacaPaperOrderSnapshotPlan,
)
from packages.application.alpaca_paper_order_view_supervisor import (
    ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_CONTRACT_VERSION,
    AlpacaPaperAuthenticatedOrderSnapshotSupervisorState,
    AlpacaPaperAuthenticatedOrderViewSupervisorConflict,
    AlpacaPaperAuthenticatedOrderViewSupervisorError,
    AlpacaPaperAuthenticatedOrderViewSupervisorResult,
    AlpacaPaperOrderSnapshotSupervisorSourceStage,
    AlpacaPaperOrderViewSupervisorComparisonRepository,
    AlpacaPaperOrderViewSupervisorStage,
    supervise_authenticated_alpaca_paper_order_views_once,
)
from packages.application.alpaca_paper_order_view_transition import (
    ALPACA_PAPER_ORDER_VIEW_TRANSITION_CONTRACT_VERSION,
    AlpacaPaperOrderViewTransitionClaim,
    AlpacaPaperOrderViewTransitionConsumption,
    AlpacaPaperOrderViewTransitionError,
    AlpacaPaperOrderViewTransitionPlan,
    AlpacaPaperOrderViewTransitionRole,
    alpaca_paper_order_view_transition_claim_id,
    alpaca_paper_order_view_transition_consumption_id,
)
from packages.domain.account_coordinator import (
    AccountCoordinatorError,
    AccountCoordinatorPort,
    AccountFence,
    AccountFenceReceipt,
)
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.clock import Clock
from packages.domain.identifiers import canonical_id
from packages.domain.models import require_utc

ALPACA_PAPER_PAIR_ADMITTED_ORDER_VIEW_RUNTIME_CONTRACT_VERSION = (
    "phase4ab-pair-admitted-order-view-runtime-v1"
)
ALPACA_PAPER_PAIR_ADMITTED_ORDER_VIEW_RUNTIME_POLICY_ID = (
    "phase4ab-one-claimed-page-per-bounded-step-policy-v1"
)


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


ALPACA_PAPER_PAIR_ADMITTED_ORDER_VIEW_RUNTIME_POLICY_SHA256 = _semantic_sha256(
    (
        ALPACA_PAPER_PAIR_ADMITTED_ORDER_VIEW_RUNTIME_CONTRACT_VERSION,
        "runtime_policy",
        ALPACA_PAPER_PAIR_ADMITTED_ORDER_VIEW_RUNTIME_POLICY_ID,
        ALPACA_PAPER_ORDER_VIEW_TRANSITION_CONTRACT_VERSION,
        ALPACA_PAPER_ORDER_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
        ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_CONTRACT_VERSION,
        "one_process_local_durable_store_identity_for_all_ports",
        "every_committed_page_requires_its_exact_claim_and_consumption",
        "each_page_receipt_is_bound_to_its_own_consumption_lease",
        "every_later_claim_binds_exact_authenticated_terminal_earlier_source",
        "selected_prefix_and_source_head_are_the_phase4q_observation",
        "selected_page_claimed_before_credentials_permit_or_transport",
        "claim_consumption_is_the_unchanged_single_use_page_preparation",
        "claim_and_consumption_transactions_close_before_provider_io",
        "every_phase4q_and_phase4p_source_load_is_pair_authenticated",
        "stalled_consumption_never_resends",
        "one_selected_page_or_wait_or_comparison_per_invocation",
        "post_effect_exact_claim_consumption_and_source_reload",
        "unselected_phase4o_source_must_remain_unchanged",
        "historical_non_authorizing_result",
    )
)


class AlpacaPaperPairAdmittedOrderViewRuntimeError(
    AlpacaPaperAuthenticatedOrderViewSupervisorError
):
    """The Phase 4AB bounded composition could not be executed safely."""


class AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
    AlpacaPaperAuthenticatedOrderViewSupervisorConflict,
    AlpacaPaperPairAdmittedOrderViewRuntimeError,
):
    """A runtime port or durable page-admission proof conflicts."""


class AlpacaPaperPairAdmittedOrderSnapshotRuntime(Protocol):
    """Combined Phase 4O persistence used by supervision and page execution."""

    @property
    def runtime_store_identity(self) -> int: ...

    def load_state(
        self,
        plan: AlpacaPaperOrderSnapshotPlan,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotSupervisorState: ...

    def prepare_next(
        self,
        description: AlpacaPaperOrderSnapshotPageDescription,
        *,
        checked_at: datetime,
    ) -> AlpacaPaperOrderSnapshotPagePreparationReceipt: ...

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedOrderSnapshotPageEvidence,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPageReceipt: ...

    def load_prefix(
        self,
        plan: AlpacaPaperOrderSnapshotPlan,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPrefix: ...


class AlpacaPaperPairAdmittedOrderAccountCoordinator(AccountCoordinatorPort, Protocol):
    """Account coordinator pinned to the same process-local SQL store."""

    @property
    def runtime_store_identity(self) -> int: ...


class AlpacaPaperOrderViewTransitionRuntimeRepository(Protocol):
    """Claim, consume, and reload exact Phase 4AA page admissions."""

    @property
    def runtime_store_identity(self) -> int: ...

    def claim(
        self,
        transition: AlpacaPaperOrderViewTransitionPlan,
        *,
        selected_role: AlpacaPaperOrderViewTransitionRole,
        selected_prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
        selected_source_head_sha256: str | None,
        fence: AccountFence,
    ) -> AlpacaPaperOrderViewTransitionClaim: ...

    def prepare_claimed(
        self,
        claim: AlpacaPaperOrderViewTransitionClaim,
        *,
        checked_at: datetime,
        fence: AccountFence,
    ) -> AlpacaPaperOrderViewTransitionConsumption: ...

    def load_claim(
        self,
        claim_id: str,
    ) -> AlpacaPaperOrderViewTransitionClaim | None: ...

    def load_consumption(
        self,
        consumption_id: str,
    ) -> AlpacaPaperOrderViewTransitionConsumption | None: ...

    def load_consumption_for_claim(
        self,
        claim_id: str,
    ) -> AlpacaPaperOrderViewTransitionConsumption | None: ...


class AlpacaPaperClaimedOrderSnapshotPageWorkflow(Protocol):
    """Execute unchanged Phase 4O with the supplied claim-bound ports."""

    @property
    def runtime_store_identity(self) -> int: ...

    def advance_one_page(
        self,
        description: AlpacaPaperOrderSnapshotPageDescription,
        *,
        fence: AccountFence,
        page_runtime: AlpacaPaperOrderSnapshotPageRuntimePort,
        coordinator: AccountCoordinatorPort,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPageReceipt: ...


def _require_utc(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            f"{field_name} must be an exact datetime"
        )
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(str(error)) from error
    return value


def _validate_transition(value: object) -> AlpacaPaperOrderViewTransitionPlan:
    if type(value) is not AlpacaPaperOrderViewTransitionPlan:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "pair-admitted runtime requires an exact order transition plan"
        )
    try:
        value.__post_init__()
    except (AlpacaPaperOrderViewTransitionError, TypeError, ValueError) as error:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "pair-admitted runtime order transition plan is invalid"
        ) from error
    return value


def _validate_fence(
    value: object,
    *,
    account_id: str,
) -> AccountFence:
    if type(value) is not AccountFence:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "pair-admitted runtime requires an exact account fence"
        )
    try:
        value.__post_init__()
    except (AccountCoordinatorError, TypeError, ValueError) as error:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "pair-admitted runtime fence is invalid"
        ) from error
    if value.account_id != account_id:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "pair-admitted runtime fence crosses account identities"
        )
    return value


def _prefix_before_page(
    prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    page_index: int,
) -> AlpacaPaperAuthenticatedOrderSnapshotPrefix:
    return _alpaca_paper_authenticated_order_snapshot_prefix(
        prefix.plan,
        page_receipts=prefix.page_receipts[:page_index],
    )


def _load_exact_claim(
    transition: AlpacaPaperOrderViewTransitionPlan,
    role: AlpacaPaperOrderViewTransitionRole,
    selected_prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    *,
    repository: AlpacaPaperOrderViewTransitionRuntimeRepository,
) -> AlpacaPaperOrderViewTransitionClaim | None:
    claim_id = alpaca_paper_order_view_transition_claim_id(
        transition,
        selected_role=role,
        selected_prefix=selected_prefix,
    )
    try:
        value = repository.load_claim(claim_id)
    except AlpacaPaperOrderViewTransitionError:
        raise
    except Exception as error:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "order transition claim could not be reauthenticated"
        ) from error
    if value is None:
        return None
    if type(value) is not AlpacaPaperOrderViewTransitionClaim:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "order transition claim loader returned a non-canonical value"
        )
    try:
        value._validate()
    except (AlpacaPaperOrderViewTransitionError, TypeError, ValueError) as error:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "order transition claim loader returned invalid evidence"
        ) from error
    if (
        value.claim_id != claim_id
        or value.plan != transition
        or value.selected_role is not role
        or value.selected_prefix != selected_prefix
        or value.selected_plan != transition.selected_plan(role)
    ):
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "order transition claim loader substituted another page, role, or pair"
        )
    return value


def _load_claim_consumption(
    claim: AlpacaPaperOrderViewTransitionClaim,
    *,
    repository: AlpacaPaperOrderViewTransitionRuntimeRepository,
) -> AlpacaPaperOrderViewTransitionConsumption | None:
    try:
        value = repository.load_consumption_for_claim(claim.claim_id)
    except AlpacaPaperOrderViewTransitionError:
        raise
    except Exception as error:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "order transition claim consumption could not be reauthenticated"
        ) from error
    if value is None:
        return None
    if type(value) is not AlpacaPaperOrderViewTransitionConsumption:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "order transition claim-consumption loader returned a non-canonical value"
        )
    try:
        value._validate()
    except (AlpacaPaperOrderViewTransitionError, TypeError, ValueError) as error:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "order transition claim-consumption loader returned invalid evidence"
        ) from error
    if value.claim != claim:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "order transition claim-consumption loader substituted another claim"
        )
    return value


def _load_exact_consumption(
    claim: AlpacaPaperOrderViewTransitionClaim,
    preparation: AlpacaPaperOrderSnapshotPagePreparationReceipt,
    *,
    repository: AlpacaPaperOrderViewTransitionRuntimeRepository,
) -> AlpacaPaperOrderViewTransitionConsumption:
    consumption_id = alpaca_paper_order_view_transition_consumption_id(
        claim,
        preparation,
    )
    try:
        value = repository.load_consumption(consumption_id)
    except AlpacaPaperOrderViewTransitionError:
        raise
    except Exception as error:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "order transition consumption could not be reauthenticated"
        ) from error
    if type(value) is not AlpacaPaperOrderViewTransitionConsumption:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "order transition consumption loader returned a non-canonical value"
        )
    try:
        value._validate()
    except (AlpacaPaperOrderViewTransitionError, TypeError, ValueError) as error:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "order transition consumption loader returned invalid evidence"
        ) from error
    if (
        value.consumption_id != consumption_id
        or value.claim != claim
        or value.preparation != preparation
    ):
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "order transition consumption loader substituted another preparation"
        )
    by_claim = _load_claim_consumption(
        claim,
        repository=repository,
    )
    if by_claim != value:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "order transition consumption indexes disagree"
        )
    return value


def _same_consumed_lease(
    receipt: AccountFenceReceipt,
    consumption: AlpacaPaperOrderViewTransitionConsumption,
) -> bool:
    admitted = consumption.commit_fence_receipt
    return (
        receipt.fence == admitted.fence
        and receipt.policy_sha256 == admitted.policy_sha256
        and receipt.lease_sha256 == admitted.lease_sha256
        and receipt.valid_until == admitted.valid_until
        and receipt.validated_at >= admitted.validated_at
        and receipt.validated_at < receipt.valid_until
    )


def _validate_completed_page_lease(
    receipt: AlpacaPaperAuthenticatedOrderSnapshotPageReceipt,
    consumption: AlpacaPaperOrderViewTransitionConsumption,
) -> None:
    try:
        receipt._validate()
    except (AlpacaPaperOrderSnapshotConflict, TypeError, ValueError) as error:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "pair-admitted order page receipt is invalid"
        ) from error
    fence_receipts = (
        receipt.evidence.pre_fence_receipt,
        receipt.evidence.post_fence_receipt,
        receipt.commit_fence_receipt,
    )
    if any(
        not _same_consumed_lease(fence_receipt, consumption) for fence_receipt in fence_receipts
    ):
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "completed order page escaped its consumed pair-claim lease"
        )
    if not (
        consumption.consumed_at
        <= fence_receipts[0].validated_at
        <= fence_receipts[1].validated_at
        <= receipt.evidence.authenticated_at
        <= fence_receipts[2].validated_at
    ):
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "completed pair-admitted order page fence evidence regressed"
        )


@dataclass(frozen=True, slots=True)
class _StateAdmission:
    claims: tuple[AlpacaPaperOrderViewTransitionClaim, ...]
    consumptions: tuple[AlpacaPaperOrderViewTransitionConsumption, ...]
    current_claim: AlpacaPaperOrderViewTransitionClaim | None
    current_consumption: AlpacaPaperOrderViewTransitionConsumption | None


def _require_later_claims_bind_terminal_earlier(
    earlier_state: AlpacaPaperAuthenticatedOrderSnapshotSupervisorState,
    *,
    existing_claims: tuple[AlpacaPaperOrderViewTransitionClaim, ...],
    current_claim: AlpacaPaperOrderViewTransitionClaim | None,
) -> None:
    claims = existing_claims if current_claim is None else (*existing_claims, current_claim)
    if not claims:
        return
    if not earlier_state.terminal or earlier_state.source_head_sha256 is None:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "later order claims require the authenticated terminal earlier source"
        )
    for claim in claims:
        if type(claim) is not AlpacaPaperOrderViewTransitionClaim:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "later order admission contains a non-canonical claim"
            )
        try:
            claim._validate()
        except (AlpacaPaperOrderViewTransitionError, TypeError, ValueError) as error:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "later order admission contains an invalid claim"
            ) from error
        if (
            claim.selected_role is not AlpacaPaperOrderViewTransitionRole.LATER
            or claim.prior_earlier_prefix != earlier_state.prefix
            or claim.prior_earlier_source_head_sha256 != earlier_state.source_head_sha256
        ):
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "later order claim does not bind the exact authenticated terminal earlier source"
            )


def _authenticate_state_admission(
    transition: AlpacaPaperOrderViewTransitionPlan,
    role: AlpacaPaperOrderViewTransitionRole,
    state: AlpacaPaperAuthenticatedOrderSnapshotSupervisorState,
    *,
    repository: AlpacaPaperOrderViewTransitionRuntimeRepository,
) -> _StateAdmission:
    expected_plan = transition.selected_plan(role)
    if state.plan != expected_plan:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "pair admission state names another transition member"
        )
    claims: list[AlpacaPaperOrderViewTransitionClaim] = []
    consumptions: list[AlpacaPaperOrderViewTransitionConsumption] = []
    previous_claim: AlpacaPaperOrderViewTransitionClaim | None = None
    for page_index, receipt in enumerate(state.prefix.page_receipts):
        selected_prefix = _prefix_before_page(state.prefix, page_index)
        claim = _load_exact_claim(
            transition,
            role,
            selected_prefix,
            repository=repository,
        )
        if claim is None:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "committed order page lacks its exact pair claim"
            )
        if claim.previous_claim != previous_claim:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "committed order page claim chain is not gap-free"
            )
        consumption = _load_exact_consumption(
            claim,
            receipt.evidence.preparation,
            repository=repository,
        )
        _validate_completed_page_lease(receipt, consumption)
        claims.append(claim)
        consumptions.append(consumption)
        previous_claim = claim

    current_claim: AlpacaPaperOrderViewTransitionClaim | None = None
    current_consumption: AlpacaPaperOrderViewTransitionConsumption | None = None
    if state.prefix.next_page_description is not None:
        current_claim = _load_exact_claim(
            transition,
            role,
            state.prefix,
            repository=repository,
        )
        if current_claim is not None:
            if current_claim.previous_claim != previous_claim:
                raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                    "current order page claim does not continue its exact page history"
                )
            current_consumption = _load_claim_consumption(
                current_claim,
                repository=repository,
            )

    if state.stage is AlpacaPaperOrderSnapshotSupervisorSourceStage.STALLED:
        preparation = state.preparation
        if current_claim is None or current_consumption is None or preparation is None:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "stalled order source lacks its exact pair claim consumption"
            )
        exact = _load_exact_consumption(
            current_claim,
            preparation,
            repository=repository,
        )
        if exact != current_consumption:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "stalled order source conflicts with its pair consumption"
            )
    elif current_consumption is not None:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "non-stalled order source has an unresolved consumed pair claim"
        )

    return _StateAdmission(
        claims=tuple(claims),
        consumptions=tuple(consumptions),
        current_claim=current_claim,
        current_consumption=current_consumption,
    )


def _load_exact_state(
    plan: AlpacaPaperOrderSnapshotPlan,
    *,
    runtime: AlpacaPaperPairAdmittedOrderSnapshotRuntime,
) -> AlpacaPaperAuthenticatedOrderSnapshotSupervisorState:
    try:
        value = runtime.load_state(plan)
    except AlpacaPaperAuthenticatedOrderViewSupervisorError:
        raise
    except Exception as error:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "pair-admitted order source state could not be loaded"
        ) from error
    if type(value) is not AlpacaPaperAuthenticatedOrderSnapshotSupervisorState:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "order source-state loader returned a non-canonical value"
        )
    try:
        value._validate()
    except (
        AlpacaPaperAuthenticatedOrderViewSupervisorError,
        AlpacaPaperOrderSnapshotConflict,
        TypeError,
        ValueError,
    ) as error:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "order source-state loader returned invalid evidence"
        ) from error
    if value.plan != plan:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "order source-state loader substituted another plan"
        )
    return value


class _PairAuthenticatedOrderSnapshotLoader:
    """Authenticate Phase 4AA on every Phase 4Q and Phase 4P source load."""

    __slots__ = (
        "_admissions",
        "_repository",
        "_runtime",
        "_states",
        "_transition",
    )

    def __init__(
        self,
        *,
        transition: AlpacaPaperOrderViewTransitionPlan,
        repository: AlpacaPaperOrderViewTransitionRuntimeRepository,
        runtime: AlpacaPaperPairAdmittedOrderSnapshotRuntime,
    ) -> None:
        self._transition = transition
        self._repository = repository
        self._runtime = runtime
        self._states: dict[str, AlpacaPaperAuthenticatedOrderSnapshotSupervisorState] = {}
        self._admissions: dict[str, _StateAdmission] = {}

    @property
    def runtime_store_identity(self) -> int:
        return self._runtime.runtime_store_identity

    def _role(
        self,
        plan: AlpacaPaperOrderSnapshotPlan,
    ) -> AlpacaPaperOrderViewTransitionRole:
        if plan == self._transition.earlier_plan:
            return AlpacaPaperOrderViewTransitionRole.EARLIER
        if plan == self._transition.later_plan:
            return AlpacaPaperOrderViewTransitionRole.LATER
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "pair-authenticated order source loader received another plan"
        )

    def load_state(
        self,
        plan: AlpacaPaperOrderSnapshotPlan,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotSupervisorState:
        role = self._role(plan)
        state = _load_exact_state(plan, runtime=self._runtime)
        admission = _authenticate_state_admission(
            self._transition,
            role,
            state,
            repository=self._repository,
        )
        self._states[plan.snapshot_id] = state
        self._admissions[plan.snapshot_id] = admission
        return state

    def load_prefix(
        self,
        plan: AlpacaPaperOrderSnapshotPlan,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPrefix:
        return self.load_state(plan).prefix

    def selected_state(
        self,
        plan: AlpacaPaperOrderSnapshotPlan,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotSupervisorState:
        try:
            return self._states[plan.snapshot_id]
        except KeyError:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4Q selected a page without an authenticated source state"
            ) from None

    def admission(
        self,
        plan: AlpacaPaperOrderSnapshotPlan,
    ) -> _StateAdmission:
        try:
            return self._admissions[plan.snapshot_id]
        except KeyError:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "pair-admitted source lacks final admission authentication"
            ) from None


class _ClaimBoundOrderSnapshotRuntime:
    """Supply one Phase 4AA preparation to unchanged Phase 4O."""

    __slots__ = (
        "_claim",
        "_consumption",
        "_fence",
        "_loaded_prefix",
        "_recorded_receipt",
        "_snapshot_runtime",
        "_transition_repository",
    )

    def __init__(
        self,
        *,
        claim: AlpacaPaperOrderViewTransitionClaim,
        fence: AccountFence,
        transition_repository: AlpacaPaperOrderViewTransitionRuntimeRepository,
        snapshot_runtime: AlpacaPaperPairAdmittedOrderSnapshotRuntime,
    ) -> None:
        self._claim = claim
        self._fence = fence
        self._transition_repository = transition_repository
        self._snapshot_runtime = snapshot_runtime
        self._consumption: AlpacaPaperOrderViewTransitionConsumption | None = None
        self._recorded_receipt: AlpacaPaperAuthenticatedOrderSnapshotPageReceipt | None = None
        self._loaded_prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix | None = None

    @property
    def runtime_store_identity(self) -> int:
        return self._snapshot_runtime.runtime_store_identity

    @property
    def consumption(self) -> AlpacaPaperOrderViewTransitionConsumption | None:
        return self._consumption

    @property
    def recorded_receipt(self) -> AlpacaPaperAuthenticatedOrderSnapshotPageReceipt | None:
        return self._recorded_receipt

    @property
    def loaded_prefix(self) -> AlpacaPaperAuthenticatedOrderSnapshotPrefix | None:
        return self._loaded_prefix

    def prepare_next(
        self,
        description: AlpacaPaperOrderSnapshotPageDescription,
        *,
        checked_at: datetime,
    ) -> AlpacaPaperOrderSnapshotPagePreparationReceipt:
        if description != self._claim.description:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4O requested preparation for another pair page"
            )
        if self._consumption is not None:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4O attempted to consume one page claim more than once"
            )
        checked_at = _require_utc(
            checked_at,
            "pair-claimed order page preparation checked_at",
        )
        try:
            value = self._transition_repository.prepare_claimed(
                self._claim,
                checked_at=checked_at,
                fence=self._fence,
            )
        except AlpacaPaperOrderViewTransitionError:
            raise
        except Exception as error:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "order page claim consumption failed before Phase 4O external effects"
            ) from error
        if type(value) is not AlpacaPaperOrderViewTransitionConsumption:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "order page claim preparer returned a non-canonical consumption"
            )
        try:
            value._validate()
        except (AlpacaPaperOrderViewTransitionError, TypeError, ValueError) as error:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "order page claim preparer returned invalid consumption evidence"
            ) from error
        if (
            value.claim != self._claim
            or value.preparation.description != description
            or value.preparation.prepared_at != checked_at
        ):
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "order page claim consumption substituted another preparation"
            )
        reloaded_claim = _load_exact_claim(
            self._claim.plan,
            self._claim.selected_role,
            self._claim.selected_prefix,
            repository=self._transition_repository,
        )
        reloaded_consumption = _load_exact_consumption(
            self._claim,
            value.preparation,
            repository=self._transition_repository,
        )
        if reloaded_claim != self._claim or reloaded_consumption != value:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "order page claim consumption failed exact durable readback"
            )
        self._consumption = value
        return value.preparation

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedOrderSnapshotPageEvidence,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
        consumption = self._consumption
        if consumption is None:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4O attempted to record before consuming its page claim"
            )
        if type(evidence) is not AlpacaPaperAuthenticatedOrderSnapshotPageEvidence:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4O recorder received non-canonical order evidence"
            )
        try:
            evidence._validate()
        except (AlpacaPaperOrderSnapshotConflict, TypeError, ValueError) as error:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4O recorder received invalid order evidence"
            ) from error
        if (
            evidence.description != self._claim.description
            or evidence.preparation != consumption.preparation
        ):
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4O evidence conflicts with the consumed page preparation"
            )
        for receipt in (
            evidence.pre_fence_receipt,
            evidence.post_fence_receipt,
        ):
            if not _same_consumed_lease(receipt, consumption):
                raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                    "Phase 4O evidence escaped the consumed page-claim lease"
                )
        if evidence.pre_fence_receipt.validated_at > evidence.post_fence_receipt.validated_at:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4O pair-bound fence evidence regressed"
            )
        if self._recorded_receipt is not None:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4O attempted to record one page claim more than once"
            )
        try:
            value = self._snapshot_runtime.record(evidence)
        except Exception as error:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4O authenticated order page commit failed"
            ) from error
        if type(value) is not AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4O recorder returned a non-canonical receipt"
            )
        try:
            value._validate()
        except (AlpacaPaperOrderSnapshotConflict, TypeError, ValueError) as error:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4O recorder returned invalid evidence"
            ) from error
        if value.evidence != evidence:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4O receipt substituted the consumed runtime evidence"
            )
        _validate_completed_page_lease(value, consumption)
        self._recorded_receipt = value
        return value

    def load_prefix(
        self,
        plan: AlpacaPaperOrderSnapshotPlan,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPrefix:
        if plan != self._claim.selected_plan:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4O requested reload for another pair member"
            )
        if self._consumption is None:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4O attempted to load its prefix before consuming the page claim"
            )
        if self._loaded_prefix is not None:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4O attempted to load one claimed prefix more than once"
            )
        try:
            value = self._snapshot_runtime.load_prefix(plan)
        except Exception as error:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4O authenticated order prefix load failed"
            ) from error
        if type(value) is not AlpacaPaperAuthenticatedOrderSnapshotPrefix:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4O prefix loader returned a non-canonical value"
            )
        try:
            value._validate()
        except (AlpacaPaperOrderSnapshotConflict, TypeError, ValueError) as error:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4O prefix loader returned invalid evidence"
            ) from error
        if value != self._claim.selected_prefix:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4O prefix load differs from the exact claimed prefix"
            )
        self._loaded_prefix = value
        return value


class _ClaimBoundAccountCoordinator:
    """Permit Phase 4O fence checks only under this page consumption lease."""

    __slots__ = ("_coordinator", "_runtime")

    def __init__(
        self,
        *,
        coordinator: AccountCoordinatorPort,
        runtime: _ClaimBoundOrderSnapshotRuntime,
    ) -> None:
        self._coordinator = coordinator
        self._runtime = runtime

    @property
    def account_id(self) -> str:
        return self._runtime._claim.plan.account_id

    @property
    def runtime_store_identity(self) -> int:
        return _port_identity(self._coordinator, "account coordinator")

    def revalidate(self, fence: AccountFence) -> AccountFenceReceipt:
        consumption = self._runtime.consumption
        if consumption is None:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4O fence authentication preceded page-claim consumption"
            )
        if fence != consumption.claim.commit_fence_receipt.fence:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4O fence authentication substituted another account fence"
            )
        try:
            value = self._coordinator.revalidate(fence)
        except AlpacaPaperPairAdmittedOrderViewRuntimeError:
            raise
        except Exception as error:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4O pair-bound account fence authentication failed"
            ) from error
        if type(value) is not AccountFenceReceipt:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "account coordinator returned non-canonical pair-bound evidence"
            )
        try:
            value._validate()
        except (AccountCoordinatorError, TypeError, ValueError) as error:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "account coordinator returned invalid pair-bound evidence"
            ) from error
        if not _same_consumed_lease(value, consumption):
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4O account lease changed after page-claim consumption"
            )
        return value

    def acquire(self, owner_id: str) -> None:
        del owner_id
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "pair-bound coordinator cannot acquire account leases"
        )

    def current(self) -> None:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "pair-bound coordinator cannot inspect mutable lease heads"
        )

    def renew(self, fence: AccountFence) -> None:
        del fence
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "pair-bound coordinator cannot renew account leases"
        )

    def run_fenced(self, fence: AccountFence, operation: object) -> None:
        del fence, operation
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "pair-bound coordinator cannot run arbitrary fenced effects"
        )

    def release(self, fence: AccountFence) -> None:
        del fence
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "pair-bound coordinator cannot release account leases"
        )


class _PairAdmittedPageWorkflow:
    """Adapt one Phase 4Q-selected page to claim-bound Phase 4O execution."""

    __slots__ = (
        "_coordinator",
        "_page_workflow",
        "_snapshot_runtime",
        "_source_loader",
        "_transition",
        "_transition_repository",
        "selected_claim",
        "selected_consumption",
        "selected_receipt",
    )

    def __init__(
        self,
        *,
        transition: AlpacaPaperOrderViewTransitionPlan,
        transition_repository: AlpacaPaperOrderViewTransitionRuntimeRepository,
        snapshot_runtime: AlpacaPaperPairAdmittedOrderSnapshotRuntime,
        source_loader: _PairAuthenticatedOrderSnapshotLoader,
        page_workflow: AlpacaPaperClaimedOrderSnapshotPageWorkflow,
        coordinator: AlpacaPaperPairAdmittedOrderAccountCoordinator,
    ) -> None:
        self._transition = transition
        self._transition_repository = transition_repository
        self._snapshot_runtime = snapshot_runtime
        self._source_loader = source_loader
        self._page_workflow = page_workflow
        self._coordinator = coordinator
        self.selected_claim: AlpacaPaperOrderViewTransitionClaim | None = None
        self.selected_consumption: AlpacaPaperOrderViewTransitionConsumption | None = None
        self.selected_receipt: AlpacaPaperAuthenticatedOrderSnapshotPageReceipt | None = None

    @property
    def runtime_store_identity(self) -> int:
        return self._snapshot_runtime.runtime_store_identity

    def _role(
        self,
        plan: AlpacaPaperOrderSnapshotPlan,
    ) -> AlpacaPaperOrderViewTransitionRole:
        if plan == self._transition.earlier_plan:
            return AlpacaPaperOrderViewTransitionRole.EARLIER
        if plan == self._transition.later_plan:
            return AlpacaPaperOrderViewTransitionRole.LATER
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "Phase 4Q selected a plan outside the exact transition pair"
        )

    def advance_one_page(
        self,
        description: AlpacaPaperOrderSnapshotPageDescription,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
        if self.selected_claim is not None:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "one Phase 4AB invocation cannot select two pages"
            )
        if type(description) is not AlpacaPaperOrderSnapshotPageDescription:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4Q selected a non-canonical page description"
            )
        try:
            description.__post_init__()
        except (TypeError, ValueError) as error:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4Q selected an invalid page description"
            ) from error
        role = self._role(description.plan)
        selected_state = self._source_loader.selected_state(description.plan)
        if (
            selected_state.stage
            not in (
                AlpacaPaperOrderSnapshotSupervisorSourceStage.ABSENT,
                AlpacaPaperOrderSnapshotSupervisorSourceStage.ACTIVE,
            )
            or selected_state.prefix.next_page_description != description
        ):
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4Q page selection conflicts with its cached source state"
            )
        try:
            value = self._transition_repository.claim(
                self._transition,
                selected_role=role,
                selected_prefix=selected_state.prefix,
                selected_source_head_sha256=selected_state.source_head_sha256,
                fence=fence,
            )
        except AlpacaPaperOrderViewTransitionError:
            raise
        except Exception as error:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "order page admission failed before Phase 4O external effects"
            ) from error
        if type(value) is not AlpacaPaperOrderViewTransitionClaim:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "order page admission returned a non-canonical claim"
            )
        try:
            value._validate()
        except (AlpacaPaperOrderViewTransitionError, TypeError, ValueError) as error:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "order page admission returned invalid evidence"
            ) from error
        exact_claim = _load_exact_claim(
            self._transition,
            role,
            selected_state.prefix,
            repository=self._transition_repository,
        )
        if (
            exact_claim != value
            or value.description != description
            or value.commit_fence_receipt.fence != fence
        ):
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "order page admission conflicts with the selected source state"
            )
        if role is AlpacaPaperOrderViewTransitionRole.LATER:
            _require_later_claims_bind_terminal_earlier(
                self._source_loader.selected_state(
                    self._transition.earlier_plan,
                ),
                existing_claims=(),
                current_claim=value,
            )
        self.selected_claim = value
        claimed_runtime = _ClaimBoundOrderSnapshotRuntime(
            claim=value,
            fence=fence,
            transition_repository=self._transition_repository,
            snapshot_runtime=self._snapshot_runtime,
        )
        claimed_coordinator = _ClaimBoundAccountCoordinator(
            coordinator=self._coordinator,
            runtime=claimed_runtime,
        )
        try:
            receipt = self._page_workflow.advance_one_page(
                description,
                fence=fence,
                page_runtime=claimed_runtime,
                coordinator=claimed_coordinator,  # type: ignore[arg-type]
            )
        except AlpacaPaperAuthenticatedOrderViewSupervisorError:
            raise
        except Exception as error:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "claim-bound Phase 4O page workflow failed"
            ) from error
        if type(receipt) is not AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "claim-bound Phase 4O workflow returned a non-canonical receipt"
            )
        try:
            receipt._validate()
        except (AlpacaPaperOrderSnapshotConflict, TypeError, ValueError) as error:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "claim-bound Phase 4O workflow returned invalid evidence"
            ) from error
        consumption = claimed_runtime.consumption
        if (
            consumption is None
            or claimed_runtime.recorded_receipt != receipt
            or claimed_runtime.loaded_prefix != selected_state.prefix
            or receipt.description != description
            or receipt.evidence.preparation != consumption.preparation
        ):
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "Phase 4O result lacks its exact consumed-and-loaded page preparation"
            )
        _validate_completed_page_lease(receipt, consumption)
        reloaded = _load_exact_consumption(
            value,
            consumption.preparation,
            repository=self._transition_repository,
        )
        if reloaded != consumption:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "selected page consumption changed after Phase 4O execution"
            )
        self.selected_consumption = consumption
        self.selected_receipt = receipt
        return receipt


class _NoPairAdmittedOrderViewAuthority:
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


def _validate_result_history(
    transition: AlpacaPaperOrderViewTransitionPlan,
    role: AlpacaPaperOrderViewTransitionRole,
    state: AlpacaPaperAuthenticatedOrderSnapshotSupervisorState,
    claims: object,
    consumptions: object,
) -> None:
    if type(claims) is not tuple or type(consumptions) is not tuple:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "pair-admitted result histories must be exact tuples"
        )
    if len(claims) != len(state.prefix.page_receipts) or len(consumptions) != len(claims):
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "pair-admitted result history does not cover every committed page"
        )
    previous_claim: AlpacaPaperOrderViewTransitionClaim | None = None
    for page_index, (claim, consumption, receipt) in enumerate(
        zip(claims, consumptions, state.prefix.page_receipts, strict=True)
    ):
        if type(claim) is not AlpacaPaperOrderViewTransitionClaim:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "pair-admitted result contains a non-canonical page claim"
            )
        if type(consumption) is not AlpacaPaperOrderViewTransitionConsumption:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "pair-admitted result contains a non-canonical page consumption"
            )
        claim._validate()
        consumption._validate()
        selected_prefix = _prefix_before_page(state.prefix, page_index)
        if (
            claim.plan != transition
            or claim.selected_role is not role
            or claim.selected_prefix != selected_prefix
            or claim.previous_claim != previous_claim
            or consumption.claim != claim
            or consumption.preparation != receipt.evidence.preparation
        ):
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "pair-admitted result page history changed its exact admission chain"
            )
        _validate_completed_page_lease(receipt, consumption)
        previous_claim = claim


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperPairAdmittedOrderViewRuntimeResult(_NoPairAdmittedOrderViewAuthority):
    """Proof that one unchanged Phase 4Q result used exact Phase 4AA history."""

    transition: AlpacaPaperOrderViewTransitionPlan
    supervisor_result: AlpacaPaperAuthenticatedOrderViewSupervisorResult
    earlier_claims: tuple[AlpacaPaperOrderViewTransitionClaim, ...]
    earlier_consumptions: tuple[AlpacaPaperOrderViewTransitionConsumption, ...]
    later_claims: tuple[AlpacaPaperOrderViewTransitionClaim, ...]
    later_consumptions: tuple[AlpacaPaperOrderViewTransitionConsumption, ...]
    selected_claim: AlpacaPaperOrderViewTransitionClaim | None
    selected_consumption: AlpacaPaperOrderViewTransitionConsumption | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperPairAdmittedOrderViewRuntimeResult must be proof-constructed")

    def _validate(self) -> None:
        transition = _validate_transition(self.transition)
        if type(self.supervisor_result) is not AlpacaPaperAuthenticatedOrderViewSupervisorResult:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "pair-admitted result requires an exact Phase 4Q result"
            )
        self.supervisor_result._validate()
        result = self.supervisor_result
        if (
            result.earlier_state.plan != transition.earlier_plan
            or result.later_state.plan != transition.later_plan
        ):
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "pair-admitted result changed its exact transition plans"
            )
        _validate_result_history(
            transition,
            AlpacaPaperOrderViewTransitionRole.EARLIER,
            result.earlier_state,
            self.earlier_claims,
            self.earlier_consumptions,
        )
        _validate_result_history(
            transition,
            AlpacaPaperOrderViewTransitionRole.LATER,
            result.later_state,
            self.later_claims,
            self.later_consumptions,
        )
        _require_later_claims_bind_terminal_earlier(
            result.earlier_state,
            existing_claims=self.later_claims,
            current_claim=None,
        )

        selected_role: AlpacaPaperOrderViewTransitionRole | None = None
        selected_prior: AlpacaPaperAuthenticatedOrderSnapshotSupervisorState | None = None
        selected_claims: tuple[AlpacaPaperOrderViewTransitionClaim, ...] = ()
        selected_consumptions: tuple[AlpacaPaperOrderViewTransitionConsumption, ...] = ()
        if result.stage is AlpacaPaperOrderViewSupervisorStage.EARLIER_PAGE_ADVANCED:
            selected_role = AlpacaPaperOrderViewTransitionRole.EARLIER
            selected_prior = result.prior_earlier_state
            selected_claims = self.earlier_claims
            selected_consumptions = self.earlier_consumptions
        elif result.stage is AlpacaPaperOrderViewSupervisorStage.LATER_PAGE_ADVANCED:
            selected_role = AlpacaPaperOrderViewTransitionRole.LATER
            selected_prior = result.prior_later_state
            selected_claims = self.later_claims
            selected_consumptions = self.later_consumptions

        if selected_role is None:
            if self.selected_claim is not None or self.selected_consumption is not None:
                raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                    "non-page Phase 4Q result unexpectedly carries a selected admission"
                )
            return
        if (
            type(self.selected_claim) is not AlpacaPaperOrderViewTransitionClaim
            or type(self.selected_consumption) is not AlpacaPaperOrderViewTransitionConsumption
            or selected_prior is None
            or not selected_claims
            or not selected_consumptions
        ):
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "page-advanced result lacks its selected claim and consumption"
            )
        value = result.value
        if type(value) is not AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "page-advanced result lacks its exact page receipt"
            )
        if (
            self.selected_claim != selected_claims[-1]
            or self.selected_consumption != selected_consumptions[-1]
            or self.selected_claim.selected_role is not selected_role
            or self.selected_claim.selected_prefix != selected_prior.prefix
            or self.selected_consumption.claim != self.selected_claim
            or self.selected_consumption.preparation != value.evidence.preparation
        ):
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "selected page result conflicts with its exact transition admission"
            )

    @property
    def stage(self) -> AlpacaPaperOrderViewSupervisorStage:
        self._validate()
        return self.supervisor_result.stage

    @property
    def value(self) -> object:
        self._validate()
        return self.supervisor_result.value

    @property
    def selected_pair(
        self,
    ) -> (
        tuple[
            AlpacaPaperOrderViewTransitionClaim,
            AlpacaPaperOrderViewTransitionConsumption,
        ]
        | None
    ):
        self._validate()
        if self.selected_claim is None or self.selected_consumption is None:
            return None
        return self.selected_claim, self.selected_consumption

    @property
    def result_id(self) -> str:
        self._validate()
        return canonical_id(
            "alpaca-paper-pair-admitted-order-view-runtime-result",
            ALPACA_PAPER_PAIR_ADMITTED_ORDER_VIEW_RUNTIME_POLICY_SHA256,
            self.transition.round_id,
            self.supervisor_result.result_id,
            tuple(claim.claim_id for claim in self.earlier_claims),
            tuple(consumption.consumption_id for consumption in self.earlier_consumptions),
            tuple(claim.claim_id for claim in self.later_claims),
            tuple(consumption.consumption_id for consumption in self.later_consumptions),
            None if self.selected_claim is None else self.selected_claim.claim_id,
            (
                None
                if self.selected_consumption is None
                else self.selected_consumption.consumption_id
            ),
        )

    def _semantic_material(self) -> tuple[object, ...]:
        self._validate()
        return (
            ALPACA_PAPER_PAIR_ADMITTED_ORDER_VIEW_RUNTIME_CONTRACT_VERSION,
            "pair_admitted_order_view_runtime_result",
            self.result_id,
            ALPACA_PAPER_PAIR_ADMITTED_ORDER_VIEW_RUNTIME_POLICY_ID,
            ALPACA_PAPER_PAIR_ADMITTED_ORDER_VIEW_RUNTIME_POLICY_SHA256,
            self.transition.round_id,
            self.transition.semantic_sha256,
            self.supervisor_result.result_id,
            self.supervisor_result.semantic_sha256,
            tuple((claim.claim_id, claim.semantic_sha256) for claim in self.earlier_claims),
            tuple(
                (consumption.consumption_id, consumption.semantic_sha256)
                for consumption in self.earlier_consumptions
            ),
            tuple((claim.claim_id, claim.semantic_sha256) for claim in self.later_claims),
            tuple(
                (consumption.consumption_id, consumption.semantic_sha256)
                for consumption in self.later_consumptions
            ),
            (
                None
                if self.selected_claim is None
                else (self.selected_claim.claim_id, self.selected_claim.semantic_sha256)
            ),
            (
                None
                if self.selected_consumption is None
                else (
                    self.selected_consumption.consumption_id,
                    self.selected_consumption.semantic_sha256,
                )
            ),
            False,
            False,
            False,
            False,
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


def _pair_admitted_order_view_runtime_result(
    *,
    transition: AlpacaPaperOrderViewTransitionPlan,
    supervisor_result: AlpacaPaperAuthenticatedOrderViewSupervisorResult,
    earlier_claims: tuple[AlpacaPaperOrderViewTransitionClaim, ...],
    earlier_consumptions: tuple[AlpacaPaperOrderViewTransitionConsumption, ...],
    later_claims: tuple[AlpacaPaperOrderViewTransitionClaim, ...],
    later_consumptions: tuple[AlpacaPaperOrderViewTransitionConsumption, ...],
    selected_claim: AlpacaPaperOrderViewTransitionClaim | None,
    selected_consumption: AlpacaPaperOrderViewTransitionConsumption | None,
) -> AlpacaPaperPairAdmittedOrderViewRuntimeResult:
    value = object.__new__(AlpacaPaperPairAdmittedOrderViewRuntimeResult)
    for field_name, field_value in (
        ("transition", transition),
        ("supervisor_result", supervisor_result),
        ("earlier_claims", earlier_claims),
        ("earlier_consumptions", earlier_consumptions),
        ("later_claims", later_claims),
        ("later_consumptions", later_consumptions),
        ("selected_claim", selected_claim),
        ("selected_consumption", selected_consumption),
    ):
        object.__setattr__(value, field_name, field_value)
    value._validate()
    return value


def _port_identity(value: object, field_name: str) -> int:
    try:
        identity = value.runtime_store_identity  # type: ignore[attr-defined]
    except Exception:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            f"{field_name} durable-store identity is unavailable"
        ) from None
    if type(identity) is not int or identity <= 0:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            f"{field_name} durable-store identity is invalid"
        )
    return identity


def _validate_ports(
    *,
    transition_repository: object,
    snapshot_runtime: object,
    page_workflow: object,
    coordinator: object,
    comparison_repository: object,
    clock: object,
) -> None:
    identities = (
        _port_identity(transition_repository, "order transition repository"),
        _port_identity(snapshot_runtime, "Phase 4O snapshot runtime"),
        _port_identity(page_workflow, "Phase 4O page workflow"),
        _port_identity(coordinator, "account coordinator"),
        _port_identity(comparison_repository, "Phase 4P comparison repository"),
    )
    if len(set(identities)) != 1:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "pair-admitted order runtime ports do not share one durable store"
        )
    for value, method_name, field_name in (
        (transition_repository, "claim", "order transition claimer"),
        (transition_repository, "prepare_claimed", "order claim consumer"),
        (transition_repository, "load_claim", "order claim loader"),
        (
            transition_repository,
            "load_consumption",
            "order consumption loader",
        ),
        (
            transition_repository,
            "load_consumption_for_claim",
            "order claim-consumption loader",
        ),
        (snapshot_runtime, "load_state", "Phase 4O state loader"),
        (snapshot_runtime, "prepare_next", "Phase 4O preparer"),
        (snapshot_runtime, "record", "Phase 4O recorder"),
        (snapshot_runtime, "load_prefix", "Phase 4O prefix loader"),
        (page_workflow, "advance_one_page", "claim-bound Phase 4O workflow"),
        (coordinator, "revalidate", "pair-bound account coordinator"),
        (comparison_repository, "record", "Phase 4P comparison recorder"),
        (comparison_repository, "load", "Phase 4P comparison loader"),
        (clock, "now", "trusted clock"),
    ):
        try:
            method = getattr(value, method_name)
        except Exception:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                f"pair-admitted order runtime {field_name} access failed"
            ) from None
        if not callable(method):
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                f"pair-admitted order runtime requires a {field_name}"
            )


def supervise_pair_admitted_alpaca_paper_order_views_once(
    transition: AlpacaPaperOrderViewTransitionPlan,
    *,
    fence: AccountFence,
    clock: Clock,
    transition_repository: AlpacaPaperOrderViewTransitionRuntimeRepository,
    snapshot_runtime: AlpacaPaperPairAdmittedOrderSnapshotRuntime,
    page_workflow: AlpacaPaperClaimedOrderSnapshotPageWorkflow,
    coordinator: AlpacaPaperPairAdmittedOrderAccountCoordinator,
    comparison_repository: AlpacaPaperOrderViewSupervisorComparisonRepository,
) -> AlpacaPaperPairAdmittedOrderViewRuntimeResult:
    """Perform one Phase 4Q step with every page admitted by Phase 4AA."""

    transition = _validate_transition(transition)
    fence = _validate_fence(fence, account_id=transition.account_id)
    _validate_ports(
        transition_repository=transition_repository,
        snapshot_runtime=snapshot_runtime,
        page_workflow=page_workflow,
        coordinator=coordinator,
        comparison_repository=comparison_repository,
        clock=clock,
    )
    try:
        coordinator_account_id = coordinator.account_id
    except Exception:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "pair-bound account coordinator identity is unavailable"
        ) from None
    if coordinator_account_id != transition.account_id:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "pair-bound account coordinator belongs to another account"
        )

    authenticated_sources = _PairAuthenticatedOrderSnapshotLoader(
        transition=transition,
        repository=transition_repository,
        runtime=snapshot_runtime,
    )

    # Authenticate all existing pages and any stalled preparation before Phase
    # 4Q may read the trusted clock, append a comparison, or select a page.
    for role in AlpacaPaperOrderViewTransitionRole:
        authenticated_sources.load_state(transition.selected_plan(role))
    _require_later_claims_bind_terminal_earlier(
        authenticated_sources.selected_state(transition.earlier_plan),
        existing_claims=authenticated_sources.admission(
            transition.later_plan,
        ).claims,
        current_claim=authenticated_sources.admission(
            transition.later_plan,
        ).current_claim,
    )

    admitted_page = _PairAdmittedPageWorkflow(
        transition=transition,
        transition_repository=transition_repository,
        snapshot_runtime=snapshot_runtime,
        source_loader=authenticated_sources,
        page_workflow=page_workflow,
        coordinator=coordinator,
    )
    result = supervise_authenticated_alpaca_paper_order_views_once(
        transition.earlier_plan,
        transition.later_plan,
        fence=fence,
        clock=clock,
        state_loader=authenticated_sources,
        page_workflow=admitted_page,
        comparison_repository=comparison_repository,
    )
    if type(result) is not AlpacaPaperAuthenticatedOrderViewSupervisorResult:
        raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
            "Phase 4Q returned a non-canonical supervisor result"
        )
    result._validate()

    expected_role: AlpacaPaperOrderViewTransitionRole | None = None
    if result.stage is AlpacaPaperOrderViewSupervisorStage.EARLIER_PAGE_ADVANCED:
        expected_role = AlpacaPaperOrderViewTransitionRole.EARLIER
    elif result.stage is AlpacaPaperOrderViewSupervisorStage.LATER_PAGE_ADVANCED:
        expected_role = AlpacaPaperOrderViewTransitionRole.LATER
    if expected_role is None:
        if (
            admitted_page.selected_claim is not None
            or admitted_page.selected_consumption is not None
            or admitted_page.selected_receipt is not None
        ):
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "non-page Phase 4Q result unexpectedly consumed a page claim"
            )
    else:
        selected_claim = admitted_page.selected_claim
        selected_consumption = admitted_page.selected_consumption
        selected_receipt = admitted_page.selected_receipt
        if (
            selected_claim is None
            or selected_consumption is None
            or selected_receipt is None
            or selected_claim.selected_role is not expected_role
            or selected_consumption.claim != selected_claim
            or result.value != selected_receipt
            or selected_receipt.evidence.preparation != selected_consumption.preparation
        ):
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "page result conflicts with its exact selected transition admission"
            )

    # Re-read both source heads and every page admission.  This binds the
    # result to the exact post-step durable state and catches a concurrent
    # append or substitution after Phase 4Q's own unchanged-source checks.
    final_admissions: dict[AlpacaPaperOrderViewTransitionRole, _StateAdmission] = {}
    for role, expected_state in (
        (AlpacaPaperOrderViewTransitionRole.EARLIER, result.earlier_state),
        (AlpacaPaperOrderViewTransitionRole.LATER, result.later_state),
    ):
        plan = transition.selected_plan(role)
        final_state = authenticated_sources.load_state(plan)
        if final_state != expected_state:
            raise AlpacaPaperPairAdmittedOrderViewRuntimeConflict(
                "pair-admitted source changed before final authentication"
            )
        final_admissions[role] = authenticated_sources.admission(plan)

    earlier = final_admissions[AlpacaPaperOrderViewTransitionRole.EARLIER]
    later = final_admissions[AlpacaPaperOrderViewTransitionRole.LATER]
    _require_later_claims_bind_terminal_earlier(
        result.earlier_state,
        existing_claims=later.claims,
        current_claim=later.current_claim,
    )
    return _pair_admitted_order_view_runtime_result(
        transition=transition,
        supervisor_result=result,
        earlier_claims=earlier.claims,
        earlier_consumptions=earlier.consumptions,
        later_claims=later.claims,
        later_consumptions=later.consumptions,
        selected_claim=admitted_page.selected_claim,
        selected_consumption=admitted_page.selected_consumption,
    )


__all__ = [
    "ALPACA_PAPER_PAIR_ADMITTED_ORDER_VIEW_RUNTIME_CONTRACT_VERSION",
    "ALPACA_PAPER_PAIR_ADMITTED_ORDER_VIEW_RUNTIME_POLICY_ID",
    "ALPACA_PAPER_PAIR_ADMITTED_ORDER_VIEW_RUNTIME_POLICY_SHA256",
    "AlpacaPaperClaimedOrderSnapshotPageWorkflow",
    "AlpacaPaperOrderViewTransitionRuntimeRepository",
    "AlpacaPaperPairAdmittedOrderAccountCoordinator",
    "AlpacaPaperPairAdmittedOrderSnapshotRuntime",
    "AlpacaPaperPairAdmittedOrderViewRuntimeConflict",
    "AlpacaPaperPairAdmittedOrderViewRuntimeError",
    "AlpacaPaperPairAdmittedOrderViewRuntimeResult",
    "_pair_admitted_order_view_runtime_result",
    "supervise_pair_admitted_alpaca_paper_order_views_once",
]
