"""Pair-admitted composition for one bounded Alpaca position-view step.

Phase 4Y composes the durable Phase 4X role claim with the unchanged Phase 4T
single-use runtime and Phase 4W supervisor.  A selected capture receives a
runtime adapter whose ``prepare`` operation atomically consumes the exact
pair claim with the canonical Phase 4U preparation.  The adapter delegates the
unchanged Phase 4T ``record`` and ``load`` operations to Phase 4U after that
consumption transaction has closed, so no database transaction spans
credentials, request admission, or provider I/O.

The composition remains a bounded historical reconciliation input.  It does
not loop, retry a consumed preparation, infer convergence, apply positions,
advance readiness, or authorize trading.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from packages.adapters.broker.alpaca_paper_position_snapshot_runtime import (
    ALPACA_PAPER_POSITION_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
    AlpacaPaperAuthenticatedPositionSnapshotEvidence,
    AlpacaPaperAuthenticatedPositionSnapshotReceipt,
    AlpacaPaperPositionSnapshotConflict,
    AlpacaPaperPositionSnapshotPreparationReceipt,
    AlpacaPaperPositionSnapshotRuntimePlan,
    AlpacaPaperPositionSnapshotRuntimePort,
)
from packages.application.alpaca_paper_position_view_supervisor import (
    ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_CONTRACT_VERSION,
    AlpacaPaperAuthenticatedPositionSnapshotSupervisorState,
    AlpacaPaperAuthenticatedPositionViewSupervisorConflict,
    AlpacaPaperAuthenticatedPositionViewSupervisorError,
    AlpacaPaperAuthenticatedPositionViewSupervisorResult,
    AlpacaPaperPositionSnapshotSupervisorSourceStage,
    AlpacaPaperPositionViewSupervisorComparisonRepository,
    AlpacaPaperPositionViewSupervisorStage,
    supervise_authenticated_alpaca_paper_position_views_once,
)
from packages.application.alpaca_paper_position_view_transition import (
    ALPACA_PAPER_POSITION_VIEW_TRANSITION_CONTRACT_VERSION,
    AlpacaPaperPositionViewTransitionClaim,
    AlpacaPaperPositionViewTransitionConsumption,
    AlpacaPaperPositionViewTransitionError,
    AlpacaPaperPositionViewTransitionPlan,
    AlpacaPaperPositionViewTransitionRole,
    alpaca_paper_position_view_transition_claim_id,
    alpaca_paper_position_view_transition_consumption_id,
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

ALPACA_PAPER_PAIR_ADMITTED_POSITION_VIEW_RUNTIME_CONTRACT_VERSION = (
    "phase4y-pair-admitted-position-view-runtime-v1"
)
ALPACA_PAPER_PAIR_ADMITTED_POSITION_VIEW_RUNTIME_POLICY_ID = (
    "phase4y-one-claimed-consumption-per-bounded-step-policy-v1"
)


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


ALPACA_PAPER_PAIR_ADMITTED_POSITION_VIEW_RUNTIME_POLICY_SHA256 = _semantic_sha256(
    (
        ALPACA_PAPER_PAIR_ADMITTED_POSITION_VIEW_RUNTIME_CONTRACT_VERSION,
        "runtime_policy",
        ALPACA_PAPER_PAIR_ADMITTED_POSITION_VIEW_RUNTIME_POLICY_ID,
        ALPACA_PAPER_POSITION_VIEW_TRANSITION_CONTRACT_VERSION,
        ALPACA_PAPER_POSITION_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
        ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_CONTRACT_VERSION,
        "one_process_local_durable_store_identity_for_all_ports",
        "existing_nonabsent_sources_require_exact_claim_consumption",
        "selected_role_claimed_before_credentials_permit_or_transport",
        "claim_consumption_is_the_unchanged_single_use_preparation",
        "claim_and_consumption_transactions_close_before_provider_io",
        "every_phase4w_and_phase4v_source_load_is_pair_authenticated",
        "absent_source_must_not_have_a_consumption",
        "nonabsent_source_requires_exact_role_claim_and_consumption",
        "all_phase4t_and_phase4u_fence_receipts_share_consumption_lease_revision",
        "restarted_complete_receipts_share_consumption_lease_revision",
        "later_claim_names_the_exact_result_earlier_receipt",
        "one_selected_capture_or_wait_or_comparison_per_invocation",
        "post_effect_exact_claim_consumption_and_source_reload",
        "unselected_phase4u_source_must_remain_unchanged",
        "stalled_consumption_never_resends",
        "historical_non_authorizing_result",
    )
)


class AlpacaPaperPairAdmittedPositionViewRuntimeError(
    AlpacaPaperAuthenticatedPositionViewSupervisorError
):
    """The Phase 4Y bounded composition could not be executed safely."""


class AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
    AlpacaPaperAuthenticatedPositionViewSupervisorConflict,
    AlpacaPaperPairAdmittedPositionViewRuntimeError,
):
    """A runtime port or durable pair proof conflicts with the exact step."""


class AlpacaPaperPairAdmittedPositionSnapshotRuntime(Protocol):
    """Combined Phase 4U port used by supervision and the Phase 4T adapter."""

    @property
    def runtime_store_identity(self) -> int: ...

    def load_state(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotSupervisorState: ...

    def prepare(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
        *,
        checked_at: datetime,
    ) -> AlpacaPaperPositionSnapshotPreparationReceipt: ...

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedPositionSnapshotEvidence,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt: ...

    def load(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt | None: ...


class AlpacaPaperPairAdmittedAccountCoordinator(AccountCoordinatorPort, Protocol):
    """Account coordinator pinned to the same process-local SQL store."""

    @property
    def runtime_store_identity(self) -> int: ...


class AlpacaPaperPositionViewTransitionRuntimeRepository(Protocol):
    """Durably claim, consume, and reload exact Phase 4X admissions."""

    @property
    def runtime_store_identity(self) -> int: ...

    def claim(
        self,
        transition: AlpacaPaperPositionViewTransitionPlan,
        *,
        selected_role: AlpacaPaperPositionViewTransitionRole,
        fence: AccountFence,
    ) -> AlpacaPaperPositionViewTransitionClaim: ...

    def prepare_claimed(
        self,
        claim: AlpacaPaperPositionViewTransitionClaim,
        *,
        checked_at: datetime,
        fence: AccountFence,
    ) -> AlpacaPaperPositionViewTransitionConsumption: ...

    def load_claim(
        self,
        claim_id: str,
    ) -> AlpacaPaperPositionViewTransitionClaim | None: ...

    def load_consumption(
        self,
        consumption_id: str,
    ) -> AlpacaPaperPositionViewTransitionConsumption | None: ...

    def load_consumption_for_claim(
        self,
        claim_id: str,
    ) -> AlpacaPaperPositionViewTransitionConsumption | None: ...


class AlpacaPaperClaimedPositionSnapshotCaptureWorkflow(Protocol):
    """Execute unchanged Phase 4T with the supplied pair-claimed runtime."""

    @property
    def runtime_store_identity(self) -> int: ...

    def capture_once(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
        *,
        fence: AccountFence,
        snapshot_runtime: AlpacaPaperPositionSnapshotRuntimePort,
        coordinator: AccountCoordinatorPort,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt: ...


def _require_utc(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            f"{field_name} must be an exact datetime"
        )
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(str(error)) from error
    return value


def _validate_transition(value: object) -> AlpacaPaperPositionViewTransitionPlan:
    if type(value) is not AlpacaPaperPositionViewTransitionPlan:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair-admitted runtime requires an exact transition plan"
        )
    try:
        value.__post_init__()
    except (AlpacaPaperPositionViewTransitionError, TypeError, ValueError) as error:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair-admitted runtime transition plan is invalid"
        ) from error
    return value


def _validate_fence(
    value: object,
    *,
    account_id: str,
) -> AccountFence:
    if type(value) is not AccountFence:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair-admitted runtime requires an exact account fence"
        )
    try:
        value.__post_init__()
    except (AccountCoordinatorError, TypeError, ValueError) as error:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair-admitted runtime fence is invalid"
        ) from error
    if value.account_id != account_id:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair-admitted runtime fence crosses account identities"
        )
    return value


def _load_exact_claim(
    transition: AlpacaPaperPositionViewTransitionPlan,
    role: AlpacaPaperPositionViewTransitionRole,
    *,
    repository: AlpacaPaperPositionViewTransitionRuntimeRepository,
) -> AlpacaPaperPositionViewTransitionClaim | None:
    claim_id = alpaca_paper_position_view_transition_claim_id(transition, role)
    try:
        value = repository.load_claim(claim_id)
    except AlpacaPaperPositionViewTransitionError:
        raise
    except Exception as error:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair transition claim could not be reauthenticated"
        ) from error
    if value is None:
        return None
    if type(value) is not AlpacaPaperPositionViewTransitionClaim:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair transition claim loader returned a non-canonical value"
        )
    try:
        value._validate()
    except (AlpacaPaperPositionViewTransitionError, TypeError, ValueError) as error:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair transition claim loader returned invalid evidence"
        ) from error
    if (
        value.claim_id != claim_id
        or value.plan != transition
        or value.selected_role is not role
        or value.selected_plan != transition.selected_plan(role)
    ):
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair transition claim loader substituted another role or pair"
        )
    return value


def _load_exact_consumption(
    claim: AlpacaPaperPositionViewTransitionClaim,
    preparation: AlpacaPaperPositionSnapshotPreparationReceipt,
    *,
    repository: AlpacaPaperPositionViewTransitionRuntimeRepository,
) -> AlpacaPaperPositionViewTransitionConsumption:
    consumption_id = alpaca_paper_position_view_transition_consumption_id(
        claim,
        preparation,
    )
    try:
        value = repository.load_consumption(consumption_id)
    except AlpacaPaperPositionViewTransitionError:
        raise
    except Exception as error:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair transition consumption could not be reauthenticated"
        ) from error
    if type(value) is not AlpacaPaperPositionViewTransitionConsumption:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair transition consumption loader returned a non-canonical value"
        )
    try:
        value._validate()
    except (AlpacaPaperPositionViewTransitionError, TypeError, ValueError) as error:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair transition consumption loader returned invalid evidence"
        ) from error
    if (
        value.consumption_id != consumption_id
        or value.claim != claim
        or value.preparation != preparation
    ):
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair transition consumption loader substituted another preparation"
        )
    return value


def _load_claim_consumption(
    claim: AlpacaPaperPositionViewTransitionClaim,
    *,
    repository: AlpacaPaperPositionViewTransitionRuntimeRepository,
) -> AlpacaPaperPositionViewTransitionConsumption | None:
    try:
        value = repository.load_consumption_for_claim(claim.claim_id)
    except AlpacaPaperPositionViewTransitionError:
        raise
    except Exception as error:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair transition claim consumption could not be reauthenticated"
        ) from error
    if value is None:
        return None
    if type(value) is not AlpacaPaperPositionViewTransitionConsumption:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair transition claim-consumption loader returned a non-canonical value"
        )
    try:
        value._validate()
    except (AlpacaPaperPositionViewTransitionError, TypeError, ValueError) as error:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair transition claim-consumption loader returned invalid evidence"
        ) from error
    if value.claim != claim:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair transition claim-consumption loader substituted another claim"
        )
    return value


def _load_exact_state(
    plan: AlpacaPaperPositionSnapshotRuntimePlan,
    *,
    runtime: AlpacaPaperPairAdmittedPositionSnapshotRuntime,
) -> AlpacaPaperAuthenticatedPositionSnapshotSupervisorState:
    try:
        value = runtime.load_state(plan)
    except AlpacaPaperAuthenticatedPositionViewSupervisorError:
        raise
    except Exception as error:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair-admitted position source state could not be loaded"
        ) from error
    if type(value) is not AlpacaPaperAuthenticatedPositionSnapshotSupervisorState:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "position source-state loader returned a non-canonical value"
        )
    try:
        value._validate()
    except (
        AlpacaPaperAuthenticatedPositionViewSupervisorError,
        AlpacaPaperPositionSnapshotConflict,
        TypeError,
        ValueError,
    ) as error:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "position source-state loader returned invalid evidence"
        ) from error
    if value.plan != plan:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "position source-state loader substituted another plan"
        )
    return value


def _validate_complete_source_lease(
    state: AlpacaPaperAuthenticatedPositionSnapshotSupervisorState,
    consumption: AlpacaPaperPositionViewTransitionConsumption,
) -> None:
    if state.stage is not AlpacaPaperPositionSnapshotSupervisorSourceStage.COMPLETE:
        return
    receipt = state.receipt
    if receipt is None:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "complete pair-admitted position source lacks its receipt"
        )
    admitted = consumption.commit_fence_receipt
    receipts = (
        receipt.evidence.pre_fence_receipt,
        receipt.evidence.post_fence_receipt,
        receipt.evidence.final_fence_receipt,
        receipt.commit_fence_receipt,
    )
    for fence_receipt in receipts:
        if (
            fence_receipt.fence != admitted.fence
            or fence_receipt.policy_sha256 != admitted.policy_sha256
            or fence_receipt.lease_sha256 != admitted.lease_sha256
            or fence_receipt.valid_until != admitted.valid_until
            or fence_receipt.validated_at < admitted.validated_at
            or fence_receipt.validated_at >= fence_receipt.valid_until
        ):
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "complete position source escaped its consumed pair-claim lease"
            )
    if not (
        receipts[0].validated_at
        <= receipts[1].validated_at
        <= receipts[2].validated_at
        <= receipt.evidence.authenticated_at
        <= receipts[3].validated_at
    ):
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "complete pair-admitted position fence evidence regressed"
        )


def _authenticate_state_admission(
    transition: AlpacaPaperPositionViewTransitionPlan,
    role: AlpacaPaperPositionViewTransitionRole,
    state: AlpacaPaperAuthenticatedPositionSnapshotSupervisorState,
    *,
    repository: AlpacaPaperPositionViewTransitionRuntimeRepository,
) -> tuple[
    AlpacaPaperPositionViewTransitionClaim | None,
    AlpacaPaperPositionViewTransitionConsumption | None,
]:
    expected_plan = transition.selected_plan(role)
    if state.plan != expected_plan:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair admission state names another transition member"
        )
    claim = _load_exact_claim(transition, role, repository=repository)
    if state.stage is AlpacaPaperPositionSnapshotSupervisorSourceStage.ABSENT:
        if (
            claim is not None
            and _load_claim_consumption(
                claim,
                repository=repository,
            )
            is not None
        ):
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "absent position source has a consumed pair admission"
            )
        return claim, None
    if claim is None or state.preparation is None:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "non-absent position source lacks its exact pair admission"
        )
    consumption = _load_claim_consumption(
        claim,
        repository=repository,
    )
    if consumption is None:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "non-absent position source lacks its exact pair consumption"
        )
    expected_consumption = _load_exact_consumption(
        claim,
        state.preparation,
        repository=repository,
    )
    if consumption != expected_consumption:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "position source pair consumption conflicts with its preparation"
        )
    _validate_complete_source_lease(state, consumption)
    return claim, consumption


class _PairAuthenticatedPositionSnapshotLoader:
    """Authenticate Phase 4X on every Phase 4W and Phase 4V source load."""

    __slots__ = ("_repository", "_runtime", "_transition")

    def __init__(
        self,
        *,
        transition: AlpacaPaperPositionViewTransitionPlan,
        repository: AlpacaPaperPositionViewTransitionRuntimeRepository,
        runtime: AlpacaPaperPairAdmittedPositionSnapshotRuntime,
    ) -> None:
        self._transition = transition
        self._repository = repository
        self._runtime = runtime

    @property
    def runtime_store_identity(self) -> int:
        return self._runtime.runtime_store_identity

    def _role(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
    ) -> AlpacaPaperPositionViewTransitionRole:
        if plan == self._transition.earlier_plan:
            return AlpacaPaperPositionViewTransitionRole.EARLIER
        if plan == self._transition.later_plan:
            return AlpacaPaperPositionViewTransitionRole.LATER
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair-authenticated source loader received another plan"
        )

    def load_state(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotSupervisorState:
        role = self._role(plan)
        state = _load_exact_state(plan, runtime=self._runtime)
        _authenticate_state_admission(
            self._transition,
            role,
            state,
            repository=self._repository,
        )
        return state

    def load(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt | None:
        state = self.load_state(plan)
        return state.receipt


class _ClaimBoundPositionSnapshotRuntime:
    """Supply exactly one Phase 4X preparation to unchanged Phase 4T."""

    __slots__ = (
        "_claim",
        "_consumption",
        "_fence",
        "_loaded_receipt",
        "_recorded_receipt",
        "_snapshot_runtime",
        "_transition_repository",
    )

    def __init__(
        self,
        *,
        claim: AlpacaPaperPositionViewTransitionClaim,
        fence: AccountFence,
        transition_repository: AlpacaPaperPositionViewTransitionRuntimeRepository,
        snapshot_runtime: AlpacaPaperPairAdmittedPositionSnapshotRuntime,
    ) -> None:
        self._claim = claim
        self._fence = fence
        self._transition_repository = transition_repository
        self._snapshot_runtime = snapshot_runtime
        self._consumption: AlpacaPaperPositionViewTransitionConsumption | None = None
        self._recorded_receipt: AlpacaPaperAuthenticatedPositionSnapshotReceipt | None = None
        self._loaded_receipt: AlpacaPaperAuthenticatedPositionSnapshotReceipt | None = None

    @property
    def runtime_store_identity(self) -> int:
        return self._snapshot_runtime.runtime_store_identity

    @property
    def consumption(self) -> AlpacaPaperPositionViewTransitionConsumption | None:
        return self._consumption

    @property
    def recorded_receipt(self) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt | None:
        return self._recorded_receipt

    @property
    def loaded_receipt(self) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt | None:
        return self._loaded_receipt

    def prepare(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
        *,
        checked_at: datetime,
    ) -> AlpacaPaperPositionSnapshotPreparationReceipt:
        if plan != self._claim.selected_plan:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "Phase 4T requested preparation for another pair member"
            )
        if self._consumption is not None:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "Phase 4T attempted to consume one pair claim more than once"
            )
        checked_at = _require_utc(
            checked_at,
            "pair-claimed position preparation checked_at",
        )
        try:
            value = self._transition_repository.prepare_claimed(
                self._claim,
                checked_at=checked_at,
                fence=self._fence,
            )
        except AlpacaPaperPositionViewTransitionError:
            raise
        except Exception as error:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "pair claim consumption failed before Phase 4T external effects"
            ) from error
        if type(value) is not AlpacaPaperPositionViewTransitionConsumption:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "pair claim preparer returned a non-canonical consumption"
            )
        try:
            value._validate()
        except (AlpacaPaperPositionViewTransitionError, TypeError, ValueError) as error:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "pair claim preparer returned invalid consumption evidence"
            ) from error
        if (
            value.claim != self._claim
            or value.preparation.plan != plan
            or value.preparation.prepared_at != checked_at
        ):
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "pair claim consumption substituted another Phase 4U preparation"
            )
        reloaded_claim = _load_exact_claim(
            self._claim.plan,
            self._claim.selected_role,
            repository=self._transition_repository,
        )
        reloaded_consumption = _load_exact_consumption(
            self._claim,
            value.preparation,
            repository=self._transition_repository,
        )
        if reloaded_claim != self._claim or reloaded_consumption != value:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "pair claim consumption failed exact durable readback"
            )
        self._consumption = value
        return value.preparation

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedPositionSnapshotEvidence,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt:
        consumption = self._consumption
        if consumption is None:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "Phase 4T attempted to record before consuming its pair claim"
            )
        if type(evidence) is not AlpacaPaperAuthenticatedPositionSnapshotEvidence:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "Phase 4T recorder received non-canonical position evidence"
            )
        try:
            evidence._validate()
        except (AlpacaPaperPositionSnapshotConflict, TypeError, ValueError) as error:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "Phase 4T recorder received invalid position evidence"
            ) from error
        if (
            evidence.plan != self._claim.selected_plan
            or evidence.preparation != consumption.preparation
        ):
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "Phase 4T evidence conflicts with the consumed pair preparation"
            )
        admitted = consumption.commit_fence_receipt
        fence_receipts = (
            evidence.pre_fence_receipt,
            evidence.post_fence_receipt,
            evidence.final_fence_receipt,
        )
        for receipt in fence_receipts:
            if (
                receipt.fence != admitted.fence
                or receipt.policy_sha256 != admitted.policy_sha256
                or receipt.lease_sha256 != admitted.lease_sha256
                or receipt.valid_until != admitted.valid_until
                or receipt.validated_at < admitted.validated_at
                or receipt.validated_at >= receipt.valid_until
            ):
                raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                    "Phase 4T evidence escaped the consumed pair-claim lease"
                )
        if not (
            fence_receipts[0].validated_at
            <= fence_receipts[1].validated_at
            <= fence_receipts[2].validated_at
        ):
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "Phase 4T pair-bound fence evidence regressed"
            )
        if self._recorded_receipt is not None:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "Phase 4T attempted to record one pair claim more than once"
            )
        try:
            value = self._snapshot_runtime.record(evidence)
        except Exception as error:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "Phase 4U authenticated position commit failed"
            ) from error
        if type(value) is not AlpacaPaperAuthenticatedPositionSnapshotReceipt:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "Phase 4U recorder returned a non-canonical receipt"
            )
        try:
            value._validate()
        except (AlpacaPaperPositionSnapshotConflict, TypeError, ValueError) as error:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "Phase 4U recorder returned invalid evidence"
            ) from error
        if value.evidence != evidence:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "Phase 4U receipt substituted the consumed runtime evidence"
            )
        self._recorded_receipt = value
        return value

    def load(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt | None:
        if plan != self._claim.selected_plan:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "Phase 4T requested reload for another pair member"
            )
        if self._recorded_receipt is None:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "Phase 4T attempted to reload before its exact Phase 4U commit"
            )
        try:
            value = self._snapshot_runtime.load(plan)
        except Exception as error:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "Phase 4U authenticated position reload failed"
            ) from error
        if type(value) is not AlpacaPaperAuthenticatedPositionSnapshotReceipt:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "Phase 4U loader returned a non-canonical receipt"
            )
        try:
            value._validate()
        except (AlpacaPaperPositionSnapshotConflict, TypeError, ValueError) as error:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "Phase 4U loader returned invalid evidence"
            ) from error
        if value != self._recorded_receipt:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "Phase 4U reload differs from the exact committed receipt"
            )
        self._loaded_receipt = value
        return value


class _ClaimBoundAccountCoordinator:
    """Permit Phase 4T fence checks only under the consumed Phase 4X lease."""

    __slots__ = ("_coordinator", "_runtime")

    def __init__(
        self,
        *,
        coordinator: AccountCoordinatorPort,
        runtime: _ClaimBoundPositionSnapshotRuntime,
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
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "Phase 4T fence authentication preceded pair-claim consumption"
            )
        if fence != consumption.claim.commit_fence_receipt.fence:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "Phase 4T fence authentication substituted another account fence"
            )
        try:
            value = self._coordinator.revalidate(fence)
        except AlpacaPaperPairAdmittedPositionViewRuntimeError:
            raise
        except Exception as error:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "Phase 4T pair-bound account fence authentication failed"
            ) from error
        if type(value) is not AccountFenceReceipt:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "account coordinator returned non-canonical pair-bound evidence"
            )
        try:
            value._validate()
        except (AccountCoordinatorError, TypeError, ValueError) as error:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "account coordinator returned invalid pair-bound evidence"
            ) from error
        admitted = consumption.commit_fence_receipt
        if (
            value.fence != admitted.fence
            or value.policy_sha256 != admitted.policy_sha256
            or value.lease_sha256 != admitted.lease_sha256
            or value.valid_until != admitted.valid_until
            or value.validated_at < admitted.validated_at
            or value.validated_at >= value.valid_until
        ):
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "Phase 4T account lease changed after pair-claim consumption"
            )
        return value

    # The Phase 4T capture contract needs only account_id and revalidate. These
    # explicit failures keep a delegated workflow from broadening this adapter
    # into lease-management authority while retaining structural compatibility
    # with AccountCoordinatorPort.
    def acquire(self, owner_id: str) -> None:
        del owner_id
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair-bound coordinator cannot acquire account leases"
        )

    def current(self) -> None:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair-bound coordinator cannot inspect mutable lease heads"
        )

    def renew(self, fence: AccountFence) -> None:
        del fence
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair-bound coordinator cannot renew account leases"
        )

    def run_fenced(self, fence: AccountFence, operation: object) -> None:
        del fence, operation
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair-bound coordinator cannot run arbitrary fenced effects"
        )

    def release(self, fence: AccountFence) -> None:
        del fence
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair-bound coordinator cannot release account leases"
        )


class _PairAdmittedCaptureWorkflow:
    """Adapt one Phase 4W selected plan to claim-bound Phase 4T execution."""

    __slots__ = (
        "_capture_workflow",
        "_coordinator",
        "_snapshot_runtime",
        "_transition",
        "_transition_repository",
        "selected_claim",
        "selected_consumption",
    )

    def __init__(
        self,
        *,
        transition: AlpacaPaperPositionViewTransitionPlan,
        transition_repository: AlpacaPaperPositionViewTransitionRuntimeRepository,
        snapshot_runtime: AlpacaPaperPairAdmittedPositionSnapshotRuntime,
        capture_workflow: AlpacaPaperClaimedPositionSnapshotCaptureWorkflow,
        coordinator: AlpacaPaperPairAdmittedAccountCoordinator,
    ) -> None:
        self._transition = transition
        self._transition_repository = transition_repository
        self._snapshot_runtime = snapshot_runtime
        self._capture_workflow = capture_workflow
        self._coordinator = coordinator
        self.selected_claim: AlpacaPaperPositionViewTransitionClaim | None = None
        self.selected_consumption: AlpacaPaperPositionViewTransitionConsumption | None = None

    @property
    def runtime_store_identity(self) -> int:
        return self._snapshot_runtime.runtime_store_identity

    def capture_once(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt:
        if self.selected_claim is not None:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "one Phase 4Y invocation cannot select two captures"
            )
        if plan == self._transition.earlier_plan:
            role = AlpacaPaperPositionViewTransitionRole.EARLIER
        elif plan == self._transition.later_plan:
            role = AlpacaPaperPositionViewTransitionRole.LATER
        else:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "Phase 4W selected a plan outside the exact transition pair"
            )
        try:
            value = self._transition_repository.claim(
                self._transition,
                selected_role=role,
                fence=fence,
            )
        except AlpacaPaperPositionViewTransitionError:
            raise
        except Exception as error:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "pair role admission failed before Phase 4T external effects"
            ) from error
        if type(value) is not AlpacaPaperPositionViewTransitionClaim:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "pair role admission returned a non-canonical claim"
            )
        try:
            value._validate()
        except (AlpacaPaperPositionViewTransitionError, TypeError, ValueError) as error:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "pair role admission returned invalid evidence"
            ) from error
        exact_claim = _load_exact_claim(
            self._transition,
            role,
            repository=self._transition_repository,
        )
        if (
            exact_claim != value
            or value.plan != self._transition
            or value.selected_plan != plan
            or value.commit_fence_receipt.fence != fence
        ):
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "pair role admission conflicts with the selected transition"
            )
        self.selected_claim = value
        claimed_runtime = _ClaimBoundPositionSnapshotRuntime(
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
            receipt = self._capture_workflow.capture_once(
                plan,
                fence=fence,
                snapshot_runtime=claimed_runtime,
                coordinator=claimed_coordinator,  # type: ignore[arg-type]
            )
        except AlpacaPaperAuthenticatedPositionViewSupervisorError:
            raise
        except Exception as error:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "claim-bound Phase 4T capture workflow failed"
            ) from error
        if type(receipt) is not AlpacaPaperAuthenticatedPositionSnapshotReceipt:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "claim-bound Phase 4T workflow returned a non-canonical receipt"
            )
        try:
            receipt._validate()
        except (AlpacaPaperPositionSnapshotConflict, TypeError, ValueError) as error:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "claim-bound Phase 4T workflow returned invalid evidence"
            ) from error
        consumption = claimed_runtime.consumption
        if (
            consumption is None
            or claimed_runtime.recorded_receipt != receipt
            or claimed_runtime.loaded_receipt != receipt
            or receipt.plan != plan
            or receipt.evidence.preparation != consumption.preparation
        ):
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "Phase 4T result lacks its exact consumed-and-reloaded pair preparation"
            )
        reloaded = _load_exact_consumption(
            value,
            consumption.preparation,
            repository=self._transition_repository,
        )
        if reloaded != consumption:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "selected pair consumption changed after Phase 4T execution"
            )
        self.selected_consumption = consumption
        return receipt


class _NoPairAdmittedPositionViewAuthority:
    __slots__ = ()

    @property
    def runtime_current(self) -> bool:
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
    def monotonic_timing_qualified(self) -> bool:
        return False

    @property
    def provider_revision_identity_qualified(self) -> bool:
        return False

    @property
    def provider_deduplication_authorized(self) -> bool:
        return False

    @property
    def canonical_position_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_fact_authorized(self) -> bool:
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
    def readiness_transition_authorized(self) -> bool:
        return False

    @property
    def reconciliation_ready(self) -> bool:
        return False

    @property
    def paper_startup_ready(self) -> bool:
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


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperPairAdmittedPositionViewRuntimeResult(_NoPairAdmittedPositionViewAuthority):
    """Proof that one unchanged Phase 4W result used exact Phase 4X history."""

    transition: AlpacaPaperPositionViewTransitionPlan
    supervisor_result: AlpacaPaperAuthenticatedPositionViewSupervisorResult
    earlier_claim: AlpacaPaperPositionViewTransitionClaim
    earlier_consumption: AlpacaPaperPositionViewTransitionConsumption
    later_claim: AlpacaPaperPositionViewTransitionClaim | None
    later_consumption: AlpacaPaperPositionViewTransitionConsumption | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "AlpacaPaperPairAdmittedPositionViewRuntimeResult must be proof-constructed"
        )

    def _validate(self) -> None:
        transition = _validate_transition(self.transition)
        if type(self.supervisor_result) is not AlpacaPaperAuthenticatedPositionViewSupervisorResult:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "pair-admitted result requires an exact Phase 4W result"
            )
        self.supervisor_result._validate()
        if (
            self.supervisor_result.earlier_state.plan != transition.earlier_plan
            or self.supervisor_result.later_state.plan != transition.later_plan
        ):
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "pair-admitted result changed its exact transition plans"
            )
        if type(self.earlier_claim) is not AlpacaPaperPositionViewTransitionClaim:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "pair-admitted result requires the earlier role claim"
            )
        self.earlier_claim._validate()
        if (
            self.earlier_claim.plan != transition
            or self.earlier_claim.selected_role is not AlpacaPaperPositionViewTransitionRole.EARLIER
        ):
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "pair-admitted result earlier claim names another role or pair"
            )
        if type(self.earlier_consumption) is not AlpacaPaperPositionViewTransitionConsumption:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "pair-admitted result requires the earlier role consumption"
            )
        self.earlier_consumption._validate()
        earlier_state = self.supervisor_result.earlier_state
        if (
            self.earlier_consumption.claim != self.earlier_claim
            or earlier_state.preparation != self.earlier_consumption.preparation
            or earlier_state.stage is AlpacaPaperPositionSnapshotSupervisorSourceStage.ABSENT
        ):
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "pair-admitted result earlier source lacks exact admission history"
            )
        _validate_complete_source_lease(earlier_state, self.earlier_consumption)

        later_state = self.supervisor_result.later_state
        if self.later_claim is None:
            if (
                self.later_consumption is not None
                or later_state.stage is not AlpacaPaperPositionSnapshotSupervisorSourceStage.ABSENT
            ):
                raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                    "pair-admitted result later source lacks exact admission history"
                )
        else:
            if type(self.later_claim) is not AlpacaPaperPositionViewTransitionClaim:
                raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                    "pair-admitted result later claim is non-canonical"
                )
            self.later_claim._validate()
            if (
                self.later_claim.plan != transition
                or self.later_claim.selected_role is not AlpacaPaperPositionViewTransitionRole.LATER
                or self.later_claim.prior_earlier_receipt != earlier_state.receipt
            ):
                raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                    "pair-admitted result later claim names another role, pair, or source"
                )
            if later_state.stage is AlpacaPaperPositionSnapshotSupervisorSourceStage.ABSENT:
                if self.later_consumption is not None:
                    raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                        "absent later source cannot carry a pair consumption"
                    )
            else:
                if type(self.later_consumption) is not AlpacaPaperPositionViewTransitionConsumption:
                    raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                        "non-absent later source requires its pair consumption"
                    )
                self.later_consumption._validate()
                if (
                    self.later_consumption.claim != self.later_claim
                    or later_state.preparation != self.later_consumption.preparation
                ):
                    raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                        "later source conflicts with exact admission history"
                    )
                _validate_complete_source_lease(later_state, self.later_consumption)

        if self.supervisor_result.stage in (
            AlpacaPaperPositionViewSupervisorStage.LATER_CAPTURE_RECORDED,
            AlpacaPaperPositionViewSupervisorStage.COMPARISON_RECORDED,
        ) and (self.later_claim is None or self.later_consumption is None):
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "terminal pair step requires both exact role consumptions"
            )

    @property
    def stage(self) -> AlpacaPaperPositionViewSupervisorStage:
        self._validate()
        return self.supervisor_result.stage

    @property
    def value(
        self,
    ) -> object:
        self._validate()
        return self.supervisor_result.value

    @property
    def result_id(self) -> str:
        self._validate()
        return canonical_id(
            "alpaca-paper-pair-admitted-position-view-runtime-result",
            ALPACA_PAPER_PAIR_ADMITTED_POSITION_VIEW_RUNTIME_POLICY_SHA256,
            self.transition.round_id,
            self.supervisor_result.result_id,
            self.earlier_claim.claim_id,
            self.earlier_consumption.consumption_id,
            None if self.later_claim is None else self.later_claim.claim_id,
            (None if self.later_consumption is None else self.later_consumption.consumption_id),
        )

    def _semantic_material(self) -> tuple[object, ...]:
        self._validate()
        return (
            ALPACA_PAPER_PAIR_ADMITTED_POSITION_VIEW_RUNTIME_CONTRACT_VERSION,
            "pair_admitted_position_view_runtime_result",
            self.result_id,
            ALPACA_PAPER_PAIR_ADMITTED_POSITION_VIEW_RUNTIME_POLICY_ID,
            ALPACA_PAPER_PAIR_ADMITTED_POSITION_VIEW_RUNTIME_POLICY_SHA256,
            self.transition.round_id,
            self.transition.semantic_sha256,
            self.supervisor_result.result_id,
            self.supervisor_result.semantic_sha256,
            self.earlier_claim.claim_id,
            self.earlier_claim.semantic_sha256,
            self.earlier_consumption.consumption_id,
            self.earlier_consumption.semantic_sha256,
            None if self.later_claim is None else self.later_claim.claim_id,
            None if self.later_claim is None else self.later_claim.semantic_sha256,
            (None if self.later_consumption is None else self.later_consumption.consumption_id),
            (None if self.later_consumption is None else self.later_consumption.semantic_sha256),
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


def _pair_admitted_position_view_runtime_result(
    *,
    transition: AlpacaPaperPositionViewTransitionPlan,
    supervisor_result: AlpacaPaperAuthenticatedPositionViewSupervisorResult,
    earlier_claim: AlpacaPaperPositionViewTransitionClaim,
    earlier_consumption: AlpacaPaperPositionViewTransitionConsumption,
    later_claim: AlpacaPaperPositionViewTransitionClaim | None,
    later_consumption: AlpacaPaperPositionViewTransitionConsumption | None,
) -> AlpacaPaperPairAdmittedPositionViewRuntimeResult:
    value = object.__new__(AlpacaPaperPairAdmittedPositionViewRuntimeResult)
    for field_name, field_value in (
        ("transition", transition),
        ("supervisor_result", supervisor_result),
        ("earlier_claim", earlier_claim),
        ("earlier_consumption", earlier_consumption),
        ("later_claim", later_claim),
        ("later_consumption", later_consumption),
    ):
        object.__setattr__(value, field_name, field_value)
    value._validate()
    return value


def _port_identity(value: object, field_name: str) -> int:
    try:
        identity = value.runtime_store_identity  # type: ignore[attr-defined]
    except Exception:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            f"{field_name} durable-store identity is unavailable"
        ) from None
    if type(identity) is not int or identity <= 0:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            f"{field_name} durable-store identity is invalid"
        )
    return identity


def _validate_ports(
    *,
    transition_repository: object,
    snapshot_runtime: object,
    capture_workflow: object,
    coordinator: object,
    comparison_repository: object,
    clock: object,
) -> None:
    for value, method_name, field_name in (
        (transition_repository, "claim", "pair transition claimer"),
        (transition_repository, "prepare_claimed", "pair claim consumer"),
        (transition_repository, "load_claim", "pair claim loader"),
        (transition_repository, "load_consumption", "pair consumption loader"),
        (
            transition_repository,
            "load_consumption_for_claim",
            "pair claim-consumption loader",
        ),
        (snapshot_runtime, "load_state", "Phase 4U state loader"),
        (snapshot_runtime, "record", "Phase 4U recorder"),
        (snapshot_runtime, "load", "Phase 4U receipt loader"),
        (capture_workflow, "capture_once", "claim-bound Phase 4T workflow"),
        (coordinator, "revalidate", "pair-bound account coordinator"),
        (comparison_repository, "record", "Phase 4V comparison recorder"),
        (comparison_repository, "load", "Phase 4V comparison loader"),
        (clock, "now", "trusted clock"),
    ):
        try:
            method = getattr(value, method_name)
        except Exception:
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                f"pair-admitted runtime {field_name} access failed"
            ) from None
        if not callable(method):
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                f"pair-admitted runtime requires a {field_name}"
            )
    identities = (
        _port_identity(transition_repository, "pair transition repository"),
        _port_identity(snapshot_runtime, "Phase 4U snapshot runtime"),
        _port_identity(capture_workflow, "Phase 4T capture workflow"),
        _port_identity(coordinator, "account coordinator"),
        _port_identity(comparison_repository, "Phase 4V comparison repository"),
    )
    if len(set(identities)) != 1:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair-admitted runtime ports do not share one durable store"
        )


def supervise_pair_admitted_alpaca_paper_position_views_once(
    transition: AlpacaPaperPositionViewTransitionPlan,
    *,
    fence: AccountFence,
    clock: Clock,
    transition_repository: AlpacaPaperPositionViewTransitionRuntimeRepository,
    snapshot_runtime: AlpacaPaperPairAdmittedPositionSnapshotRuntime,
    capture_workflow: AlpacaPaperClaimedPositionSnapshotCaptureWorkflow,
    coordinator: AlpacaPaperPairAdmittedAccountCoordinator,
    comparison_repository: AlpacaPaperPositionViewSupervisorComparisonRepository,
) -> AlpacaPaperPairAdmittedPositionViewRuntimeResult:
    """Perform one Phase 4W step with every new capture admitted by Phase 4X."""

    transition = _validate_transition(transition)
    fence = _validate_fence(fence, account_id=transition.account_id)
    _validate_ports(
        transition_repository=transition_repository,
        snapshot_runtime=snapshot_runtime,
        capture_workflow=capture_workflow,
        coordinator=coordinator,
        comparison_repository=comparison_repository,
        clock=clock,
    )
    try:
        coordinator_account_id = coordinator.account_id
    except Exception:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair-bound account coordinator identity is unavailable"
        ) from None
    if coordinator_account_id != transition.account_id:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "pair-bound account coordinator belongs to another account"
        )

    authenticated_sources = _PairAuthenticatedPositionSnapshotLoader(
        transition=transition,
        repository=transition_repository,
        runtime=snapshot_runtime,
    )

    # Authenticate any existing Phase 4U state as pair-derived before Phase 4W
    # may read the clock, append a comparison, or select a capture.
    for role in AlpacaPaperPositionViewTransitionRole:
        authenticated_sources.load_state(transition.selected_plan(role))

    admitted_capture = _PairAdmittedCaptureWorkflow(
        transition=transition,
        transition_repository=transition_repository,
        snapshot_runtime=snapshot_runtime,
        capture_workflow=capture_workflow,
        coordinator=coordinator,
    )
    result = supervise_authenticated_alpaca_paper_position_views_once(
        transition.earlier_plan,
        transition.later_plan,
        fence=fence,
        clock=clock,
        state_loader=authenticated_sources,
        capture_workflow=admitted_capture,
        comparison_repository=comparison_repository,
    )
    if type(result) is not AlpacaPaperAuthenticatedPositionViewSupervisorResult:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "Phase 4W returned a non-canonical supervisor result"
        )
    result._validate()

    expected_role: AlpacaPaperPositionViewTransitionRole | None = None
    if result.stage is AlpacaPaperPositionViewSupervisorStage.EARLIER_CAPTURE_RECORDED:
        expected_role = AlpacaPaperPositionViewTransitionRole.EARLIER
    elif result.stage is AlpacaPaperPositionViewSupervisorStage.LATER_CAPTURE_RECORDED:
        expected_role = AlpacaPaperPositionViewTransitionRole.LATER
    if expected_role is None:
        if (
            admitted_capture.selected_claim is not None
            or admitted_capture.selected_consumption is not None
        ):
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "non-capture Phase 4W result unexpectedly consumed a pair role"
            )
    else:
        selected_claim = admitted_capture.selected_claim
        selected_consumption = admitted_capture.selected_consumption
        if (
            selected_claim is None
            or selected_consumption is None
            or selected_claim.selected_role is not expected_role
            or selected_consumption.claim != selected_claim
            or type(result.value) is not AlpacaPaperAuthenticatedPositionSnapshotReceipt
            or result.value.evidence.preparation != selected_consumption.preparation
        ):
            raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
                "capture result conflicts with its exact selected pair transition"
            )

    # Reauthenticate final admission history for every non-absent source. Phase
    # 4W already proves that the unselected Phase 4U state is byte-for-byte
    # unchanged, while this reload proves the selected plan is still bound to
    # the exact X claim/consumption that Phase 4T used.
    final_admissions: dict[
        AlpacaPaperPositionViewTransitionRole,
        tuple[
            AlpacaPaperPositionViewTransitionClaim | None,
            AlpacaPaperPositionViewTransitionConsumption | None,
        ],
    ] = {}
    for role, state in (
        (AlpacaPaperPositionViewTransitionRole.EARLIER, result.earlier_state),
        (AlpacaPaperPositionViewTransitionRole.LATER, result.later_state),
    ):
        final_admissions[role] = _authenticate_state_admission(
            transition,
            role,
            state,
            repository=transition_repository,
        )
    earlier_claim, earlier_consumption = final_admissions[
        AlpacaPaperPositionViewTransitionRole.EARLIER
    ]
    later_claim, later_consumption = final_admissions[AlpacaPaperPositionViewTransitionRole.LATER]
    if earlier_claim is None or earlier_consumption is None:
        raise AlpacaPaperPairAdmittedPositionViewRuntimeConflict(
            "Phase 4Y result lacks the required earlier admission history"
        )
    return _pair_admitted_position_view_runtime_result(
        transition=transition,
        supervisor_result=result,
        earlier_claim=earlier_claim,
        earlier_consumption=earlier_consumption,
        later_claim=later_claim,
        later_consumption=later_consumption,
    )


__all__ = [
    "ALPACA_PAPER_PAIR_ADMITTED_POSITION_VIEW_RUNTIME_CONTRACT_VERSION",
    "ALPACA_PAPER_PAIR_ADMITTED_POSITION_VIEW_RUNTIME_POLICY_ID",
    "ALPACA_PAPER_PAIR_ADMITTED_POSITION_VIEW_RUNTIME_POLICY_SHA256",
    "AlpacaPaperClaimedPositionSnapshotCaptureWorkflow",
    "AlpacaPaperPairAdmittedAccountCoordinator",
    "AlpacaPaperPairAdmittedPositionSnapshotRuntime",
    "AlpacaPaperPairAdmittedPositionViewRuntimeConflict",
    "AlpacaPaperPairAdmittedPositionViewRuntimeError",
    "AlpacaPaperPairAdmittedPositionViewRuntimeResult",
    "AlpacaPaperPositionViewTransitionRuntimeRepository",
    "supervise_pair_admitted_alpaca_paper_position_views_once",
]
