"""Restart-safe composition for one durably claimed strategy invocation."""

from __future__ import annotations

from typing import Protocol

from packages.domain.account_coordinator import AccountFence
from packages.domain.market_batch import MarketBatch
from packages.domain.strategy_invocation_lifecycle import (
    StrategyInvocationClaim,
    StrategyInvocationDisposition,
    StrategyInvocationLifecycleDecision,
    StrategyInvocationLifecycleError,
    StrategyInvocationNewClaim,
    StrategyInvocationStartAuthorization,
)
from packages.domain.strategy_supervision import (
    StrategyInvocation,
    StrategySupervisionResult,
)


class DurableStrategyInvocationError(RuntimeError):
    """The durable strategy workflow cannot authenticate its current state."""


class DurableStrategyRunnerInterrupted(DurableStrategyInvocationError):
    """The runner did not return a durable, classifiable result.

    The committed claim remains pending.  A subsequent workflow call must not
    invoke the runner again; the repository may classify the orphan only after
    the claim's fixed recovery instant.
    """


class StrategyInvocationRunnerPort(Protocol):
    """Injected effect port; the lifecycle never selects a runtime artifact."""

    def run(
        self,
        *,
        invocation: StrategyInvocation,
        market_batch: MarketBatch,
        start_authorization: StrategyInvocationStartAuthorization,
    ) -> StrategySupervisionResult: ...


class StrategyInvocationLifecycleRepositoryPort(Protocol):
    """Durable claim and atomic finalization surface required by the workflow."""

    def claim(
        self,
        invocation: StrategyInvocation,
        fence: AccountFence,
    ) -> StrategyInvocationNewClaim | StrategyInvocationLifecycleDecision: ...

    def authorize_start(
        self,
        start_capability: object,
        fence: AccountFence,
    ) -> StrategyInvocationStartAuthorization | StrategyInvocationLifecycleDecision: ...

    def finalize(
        self,
        claim: StrategyInvocationClaim,
        result: StrategySupervisionResult,
        fence: AccountFence,
    ) -> StrategyInvocationLifecycleDecision: ...

    def recover(
        self,
        claim: StrategyInvocationClaim,
        fence: AccountFence,
    ) -> StrategyInvocationLifecycleDecision: ...


def _validate_request(
    *,
    invocation: StrategyInvocation,
    market_batch: MarketBatch,
    fence: AccountFence,
) -> None:
    if type(invocation) is not StrategyInvocation:
        raise DurableStrategyInvocationError(
            "durable strategy workflow requires an exact invocation"
        )
    if type(market_batch) is not MarketBatch:
        raise DurableStrategyInvocationError(
            "durable strategy workflow requires an exact market batch"
        )
    if type(fence) is not AccountFence:
        raise DurableStrategyInvocationError(
            "durable strategy workflow requires an exact account fence"
        )
    try:
        invocation.__post_init__()
        invocation.require_batch(market_batch)
        fence.__post_init__()
    except (StrategyInvocationLifecycleError, ValueError) as error:
        raise DurableStrategyInvocationError(str(error)) from error
    if fence.account_id != invocation.control_scope_id:
        raise DurableStrategyInvocationError(
            "durable strategy workflow fence belongs to another account"
        )


def _validate_decision(
    value: object,
    *,
    invocation: StrategyInvocation,
) -> StrategyInvocationLifecycleDecision:
    if type(value) is not StrategyInvocationLifecycleDecision:
        raise DurableStrategyInvocationError(
            "strategy lifecycle repository returned a noncanonical decision"
        )
    try:
        value.__post_init__()
    except StrategyInvocationLifecycleError as error:
        raise DurableStrategyInvocationError(str(error)) from error
    if value.claim.invocation != invocation:
        raise DurableStrategyInvocationError(
            "strategy lifecycle repository substituted another invocation"
        )
    if value.disposition is StrategyInvocationDisposition.NEW:
        raise DurableStrategyInvocationError(
            "durable NEW authority requires an opaque winning-claim envelope"
        )
    return value


def _validate_new_claim(
    value: object,
    *,
    invocation: StrategyInvocation,
    fence: AccountFence,
) -> StrategyInvocationNewClaim:
    if type(value) is not StrategyInvocationNewClaim:
        raise DurableStrategyInvocationError(
            "strategy lifecycle repository returned a noncanonical claim result"
        )
    try:
        value.__post_init__()
    except StrategyInvocationLifecycleError as error:
        raise DurableStrategyInvocationError(str(error)) from error
    if value.claim.invocation != invocation or value.claim.account_fence != fence:
        raise DurableStrategyInvocationError(
            "new strategy claim crossed invocation or fence identities"
        )
    return value


def _validate_runner_result(
    value: object,
    *,
    authorization: StrategyInvocationStartAuthorization,
) -> StrategySupervisionResult:
    claim = authorization.claim
    if type(value) is not StrategySupervisionResult:
        raise DurableStrategyRunnerInterrupted(
            "strategy runner returned a noncanonical result; durable claim remains pending"
        )
    try:
        value.__post_init__()
    except ValueError as error:
        raise DurableStrategyRunnerInterrupted(
            "strategy runner returned an invalid result; durable claim remains pending"
        ) from error
    if (
        value.invocation_id != claim.invocation.invocation_id
        or value.invocation_sha256 != claim.invocation.semantic_sha256
    ):
        raise DurableStrategyRunnerInterrupted(
            "strategy runner crossed invocation identities; durable claim remains pending"
        )
    if (
        value.started_at < claim.fence_receipt.validated_at
        or value.completed_at >= claim.recoverable_at
    ):
        raise DurableStrategyRunnerInterrupted(
            "strategy runner result falls outside its claimed execution window"
        )
    try:
        authorization.require_start_at(value.started_at)
    except StrategyInvocationLifecycleError as error:
        raise DurableStrategyRunnerInterrupted(
            "strategy runner started outside its fresh authorization window"
        ) from error
    return value


def run_durable_supervised_strategy_once(
    *,
    invocation: StrategyInvocation,
    market_batch: MarketBatch,
    fence: AccountFence,
    repository: StrategyInvocationLifecycleRepositoryPort,
    runner: StrategyInvocationRunnerPort,
) -> StrategyInvocationLifecycleDecision:
    """Advance one invocation without ever rerunning a retained durable claim.

    A new claim is committed and fence-authenticated before ``runner.run`` is
    called.  A pending claim is passed only to fail-closed recovery.  A final
    claim returns its retained result exactly.
    """

    _validate_request(
        invocation=invocation,
        market_batch=market_batch,
        fence=fence,
    )
    for dependency, methods, field_name in (
        (
            repository,
            ("claim", "authorize_start", "finalize", "recover"),
            "repository",
        ),
        (runner, ("run",), "runner"),
    ):
        if any(not callable(getattr(dependency, method, None)) for method in methods):
            raise DurableStrategyInvocationError(
                f"durable strategy workflow requires an injected {field_name} port"
            )

    try:
        raw_claim_result = repository.claim(invocation, fence)
    except StrategyInvocationLifecycleError as error:
        raise DurableStrategyInvocationError(str(error)) from error
    if type(raw_claim_result) is StrategyInvocationLifecycleDecision:
        decision = _validate_decision(raw_claim_result, invocation=invocation)
        if decision.disposition is StrategyInvocationDisposition.FINAL:
            return decision
        if decision.disposition is not StrategyInvocationDisposition.PENDING:
            raise DurableStrategyInvocationError(
                "strategy lifecycle repository returned an unsupported retained state"
            )
        try:
            raw_recovered = repository.recover(decision.claim, fence)
        except StrategyInvocationLifecycleError as error:
            raise DurableStrategyInvocationError(str(error)) from error
        recovered = _validate_decision(raw_recovered, invocation=invocation)
        if recovered.claim != decision.claim:
            raise DurableStrategyInvocationError(
                "strategy recovery substituted another durable claim"
            )
        if recovered.disposition is StrategyInvocationDisposition.NEW:
            raise DurableStrategyInvocationError(
                "strategy recovery cannot authorize a subprocess rerun"
            )
        return recovered

    new_claim = _validate_new_claim(
        raw_claim_result,
        invocation=invocation,
        fence=fence,
    )
    try:
        raw_authorization = repository.authorize_start(
            new_claim.start_capability,
            fence,
        )
    except StrategyInvocationLifecycleError as error:
        raise DurableStrategyInvocationError(str(error)) from error
    if type(raw_authorization) is StrategyInvocationLifecycleDecision:
        refreshed = _validate_decision(
            raw_authorization,
            invocation=invocation,
        )
        if refreshed.claim != new_claim.claim:
            raise DurableStrategyInvocationError(
                "strategy start authorization substituted another durable claim"
            )
        if refreshed.disposition is not StrategyInvocationDisposition.FINAL:
            raise DurableStrategyInvocationError(
                "strategy start authorization returned a nonterminal lifecycle state"
            )
        return refreshed
    if type(raw_authorization) is not StrategyInvocationStartAuthorization:
        raise DurableStrategyInvocationError(
            "strategy lifecycle repository returned a noncanonical start authorization"
        )
    try:
        raw_authorization.__post_init__()
    except StrategyInvocationLifecycleError as error:
        raise DurableStrategyInvocationError(str(error)) from error
    if raw_authorization.claim != new_claim.claim or raw_authorization.fence_receipt.fence != fence:
        raise DurableStrategyInvocationError(
            "strategy start authorization crossed claim or fence identities"
        )
    authorization = raw_authorization
    try:
        raw_result = runner.run(
            invocation=invocation,
            market_batch=market_batch,
            start_authorization=authorization,
        )
    except Exception as error:
        raise DurableStrategyRunnerInterrupted(
            "strategy runner was interrupted; durable claim remains pending"
        ) from error
    result = _validate_runner_result(
        raw_result,
        authorization=authorization,
    )
    try:
        raw_finalized = repository.finalize(new_claim.claim, result, fence)
    except StrategyInvocationLifecycleError as error:
        raise DurableStrategyInvocationError(str(error)) from error
    finalized = _validate_decision(raw_finalized, invocation=invocation)
    if (
        finalized.claim != new_claim.claim
        or finalized.disposition is not StrategyInvocationDisposition.FINAL
        or finalized.result != result
    ):
        raise DurableStrategyInvocationError(
            "strategy finalization did not retain the exact claimed result"
        )
    return finalized


__all__ = [
    "DurableStrategyInvocationError",
    "DurableStrategyRunnerInterrupted",
    "StrategyInvocationLifecycleRepositoryPort",
    "StrategyInvocationRunnerPort",
    "run_durable_supervised_strategy_once",
]
