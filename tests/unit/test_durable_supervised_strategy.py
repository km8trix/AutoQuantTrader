from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta

import pytest

from packages.application.durable_supervised_strategy import (
    DurableStrategyInvocationError,
    DurableStrategyRunnerInterrupted,
    run_durable_supervised_strategy_once,
)
from packages.domain.account_coordinator import (
    AccountFence,
    _account_fence_receipt,
)
from packages.domain.market_batch import MarketBatch
from packages.domain.strategy_invocation_lifecycle import (
    STRATEGY_INVOCATION_INTERRUPTED_DETAIL_CODE,
    STRATEGY_INVOCATION_RECOVERY_INTERVAL,
    StrategyInvocationClaim,
    StrategyInvocationDisposition,
    StrategyInvocationLifecycleConflict,
    StrategyInvocationLifecycleDecision,
    StrategyInvocationLifecycleError,
    StrategyInvocationNewClaim,
    StrategyInvocationStartAuthorization,
    _strategy_invocation_start_authorization,
    interrupted_strategy_supervision_result,
)
from packages.domain.strategy_supervision import (
    StrategyInvocation,
    StrategySupervisionOutcome,
    StrategySupervisionResult,
)
from tests.unit.test_strategy_supervision import _invocation

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


@dataclass(slots=True)
class _TestStartAuthorizationUse:
    issuer_identity: object
    capability_nonce: object
    consumed: bool = False

    def validate(
        self,
        *,
        issuer_identity: object,
        capability_nonce: object,
    ) -> None:
        if (
            issuer_identity is not self.issuer_identity
            or capability_nonce is not self.capability_nonce
        ):
            raise StrategyInvocationLifecycleConflict(
                "strategy start authorization belongs to another repository process"
            )

    def consume(
        self,
        *,
        issuer_identity: object,
        capability_nonce: object,
    ) -> None:
        self.validate(
            issuer_identity=issuer_identity,
            capability_nonce=capability_nonce,
        )
        if self.consumed:
            raise StrategyInvocationLifecycleConflict(
                "strategy start authorization was already consumed"
            )
        self.consumed = True


def _facts() -> tuple[MarketBatch, StrategyInvocation, AccountFence, datetime]:
    batch, invocation_value = _invocation()
    assert type(invocation_value) is StrategyInvocation
    invocation = invocation_value
    fence = AccountFence(
        account_id=invocation.control_scope_id,
        owner_id="phase5c-worker",
        lease_id="phase5c-lease",
        fencing_generation=1,
    )
    claimed_at = invocation.requested_at + timedelta(milliseconds=1)
    return batch, invocation, fence, claimed_at


def _claim(
    invocation: StrategyInvocation,
    fence: AccountFence,
    claimed_at: datetime,
    *,
    valid_for: timedelta = timedelta(minutes=5),
) -> StrategyInvocationClaim:
    receipt = _account_fence_receipt(
        fence=fence,
        validated_at=claimed_at,
        valid_until=claimed_at + valid_for,
        policy_sha256="a" * 64,
        lease_sha256="b" * 64,
    )
    return StrategyInvocationClaim(
        invocation=invocation,
        fence_receipt=receipt,
        recoverable_at=claimed_at + STRATEGY_INVOCATION_RECOVERY_INTERVAL,
    )


def _runner_result(claim: StrategyInvocationClaim) -> StrategySupervisionResult:
    started_at = claim.claimed_at + timedelta(microseconds=1)
    return StrategySupervisionResult(
        invocation_id=claim.invocation.invocation_id,
        invocation_sha256=claim.invocation.semantic_sha256,
        outcome=StrategySupervisionOutcome.RESOURCE_EXCEEDED,
        started_at=started_at,
        completed_at=started_at + timedelta(microseconds=10),
        elapsed_microseconds=10,
        process_started=False,
        exit_code=None,
        stdout_bytes=0,
        stdout_sha256=EMPTY_SHA256,
        stderr_bytes=0,
        stderr_sha256=EMPTY_SHA256,
        detail_code="request_too_large",
    )


@dataclass(slots=True)
class FakeRepository:
    now: datetime
    stored_claim: StrategyInvocationClaim | None = None
    final_result: StrategySupervisionResult | None = None
    fail_finalize: str | None = None
    authorize_delay: timedelta | None = None
    claim_calls: int = 0
    authorize_calls: int = 0
    finalize_calls: int = 0
    recover_calls: int = 0
    start_capability: object | None = None

    def _decision(
        self,
        disposition: StrategyInvocationDisposition,
    ) -> StrategyInvocationLifecycleDecision:
        assert self.stored_claim is not None
        return StrategyInvocationLifecycleDecision(
            claim=self.stored_claim,
            disposition=disposition,
            result=(
                self.final_result if disposition is StrategyInvocationDisposition.FINAL else None
            ),
        )

    def claim(
        self,
        invocation: StrategyInvocation,
        fence: AccountFence,
    ) -> StrategyInvocationNewClaim | StrategyInvocationLifecycleDecision:
        self.claim_calls += 1
        if self.stored_claim is None:
            self.stored_claim = _claim(invocation, fence, self.now)
            self.start_capability = object()
            return StrategyInvocationNewClaim(
                claim=self.stored_claim,
                start_capability=self.start_capability,
            )
        if self.stored_claim.invocation != invocation:
            raise StrategyInvocationLifecycleConflict("invocation conflict")
        return self._decision(
            StrategyInvocationDisposition.FINAL
            if self.final_result is not None
            else StrategyInvocationDisposition.PENDING
        )

    def authorize_start(
        self,
        start_capability: object,
        fence: AccountFence,
    ) -> StrategyInvocationStartAuthorization | StrategyInvocationLifecycleDecision:
        self.authorize_calls += 1
        if self.start_capability is None or start_capability is not self.start_capability:
            raise StrategyInvocationLifecycleConflict(
                "start capability was not issued by this repository"
            )
        self.start_capability = None
        assert self.stored_claim is not None
        claim = self.stored_claim
        assert claim == self.stored_claim
        assert claim.account_fence == fence
        if self.authorize_delay is not None:
            self.now += self.authorize_delay
        if self.now >= claim.recoverable_at:
            self.final_result = interrupted_strategy_supervision_result(claim)
            return self._decision(StrategyInvocationDisposition.FINAL)
        issuer_identity = self
        return _strategy_invocation_start_authorization(
            claim,
            fence_receipt=_account_fence_receipt(
                fence=fence,
                validated_at=self.now,
                valid_until=claim.fence_receipt.valid_until,
                policy_sha256=claim.fence_receipt.policy_sha256,
                lease_sha256=claim.fence_receipt.lease_sha256,
            ),
            issuer_identity=issuer_identity,
            capability_nonce=start_capability,
            use=_TestStartAuthorizationUse(
                issuer_identity=issuer_identity,
                capability_nonce=start_capability,
            ),
        )

    def finalize(
        self,
        claim: StrategyInvocationClaim,
        result: StrategySupervisionResult,
        fence: AccountFence,
    ) -> StrategyInvocationLifecycleDecision:
        del fence
        self.finalize_calls += 1
        assert claim == self.stored_claim
        if self.fail_finalize == "before":
            raise RuntimeError("simulated crash before finalization commit")
        self.final_result = result
        if self.fail_finalize == "after":
            raise RuntimeError("simulated response loss after finalization commit")
        return self._decision(StrategyInvocationDisposition.FINAL)

    def recover(
        self,
        claim: StrategyInvocationClaim,
        fence: AccountFence,
    ) -> StrategyInvocationLifecycleDecision:
        del fence
        self.recover_calls += 1
        assert claim == self.stored_claim
        if self.now < claim.recoverable_at:
            return self._decision(StrategyInvocationDisposition.PENDING)
        self.final_result = interrupted_strategy_supervision_result(claim)
        return self._decision(StrategyInvocationDisposition.FINAL)


@dataclass(slots=True)
class FakeRunner:
    result: StrategySupervisionResult | None = None
    error: Exception | None = None
    calls: int = 0
    seen_invocation: StrategyInvocation | None = None
    seen_batch: MarketBatch | None = None
    seen_authorization: StrategyInvocationStartAuthorization | None = None

    def run(
        self,
        *,
        invocation: StrategyInvocation,
        market_batch: MarketBatch,
        start_authorization: StrategyInvocationStartAuthorization,
    ) -> StrategySupervisionResult:
        self.calls += 1
        self.seen_invocation = invocation
        self.seen_batch = market_batch
        self.seen_authorization = start_authorization
        if self.error is not None:
            raise self.error
        assert self.result is not None
        return self.result


def test_claim_is_committed_before_runner_and_exact_retry_never_reruns() -> None:
    batch, invocation, fence, claimed_at = _facts()
    repository = FakeRepository(now=claimed_at)
    expected_claim = _claim(invocation, fence, claimed_at)
    runner = FakeRunner(result=_runner_result(expected_claim))

    first = run_durable_supervised_strategy_once(
        invocation=invocation,
        market_batch=batch,
        fence=fence,
        repository=repository,
        runner=runner,
    )
    second = run_durable_supervised_strategy_once(
        invocation=invocation,
        market_batch=batch,
        fence=fence,
        repository=repository,
        runner=runner,
    )

    assert first == second
    assert first.disposition is StrategyInvocationDisposition.FINAL
    assert first.result == runner.result
    assert runner.calls == 1
    assert runner.seen_invocation == invocation
    assert runner.seen_batch == batch
    assert repository.claim_calls == 2
    assert repository.authorize_calls == 1
    assert repository.finalize_calls == 1
    assert repository.recover_calls == 0
    assert runner.seen_authorization is not None
    assert runner.seen_authorization.claim == first.claim


def test_restart_after_claim_never_calls_runner_and_recovers_only_when_safe() -> None:
    batch, invocation, fence, claimed_at = _facts()
    repository = FakeRepository(
        now=claimed_at,
        stored_claim=_claim(invocation, fence, claimed_at),
    )
    runner = FakeRunner(error=AssertionError("retained claim must not rerun"))

    pending = run_durable_supervised_strategy_once(
        invocation=invocation,
        market_batch=batch,
        fence=fence,
        repository=repository,
        runner=runner,
    )
    assert pending.disposition is StrategyInvocationDisposition.PENDING
    assert runner.calls == 0

    assert repository.stored_claim is not None
    repository.now = repository.stored_claim.recoverable_at
    recovered = run_durable_supervised_strategy_once(
        invocation=invocation,
        market_batch=batch,
        fence=fence,
        repository=repository,
        runner=runner,
    )

    assert recovered.disposition is StrategyInvocationDisposition.FINAL
    assert recovered.result is not None
    assert recovered.result.outcome is StrategySupervisionOutcome.CRASH
    assert recovered.result.detail_code == STRATEGY_INVOCATION_INTERRUPTED_DETAIL_CODE
    assert recovered.result.process_started is False
    assert recovered.result.requested_control_state is not None
    assert runner.calls == 0


def test_new_claim_that_expires_before_start_authorization_never_calls_runner() -> None:
    batch, invocation, fence, claimed_at = _facts()
    repository = FakeRepository(
        now=claimed_at,
        authorize_delay=STRATEGY_INVOCATION_RECOVERY_INTERVAL,
    )
    runner = FakeRunner(error=AssertionError("expired NEW authority must not reach runner"))

    recovered = run_durable_supervised_strategy_once(
        invocation=invocation,
        market_batch=batch,
        fence=fence,
        repository=repository,
        runner=runner,
    )

    assert recovered.disposition is StrategyInvocationDisposition.FINAL
    assert recovered.result is not None
    assert recovered.result == interrupted_strategy_supervision_result(recovered.claim)
    assert repository.claim_calls == 1
    assert repository.authorize_calls == 1
    assert repository.finalize_calls == 0
    assert runner.calls == 0


def test_runner_interruption_leaves_claim_pending_and_never_retries_effect() -> None:
    batch, invocation, fence, claimed_at = _facts()
    repository = FakeRepository(now=claimed_at)
    runner = FakeRunner(error=RuntimeError("spawned supervisor disappeared"))

    with pytest.raises(DurableStrategyRunnerInterrupted, match="remains pending"):
        run_durable_supervised_strategy_once(
            invocation=invocation,
            market_batch=batch,
            fence=fence,
            repository=repository,
            runner=runner,
        )

    assert runner.calls == 1
    runner.error = AssertionError("must not be called again")
    pending = run_durable_supervised_strategy_once(
        invocation=invocation,
        market_batch=batch,
        fence=fence,
        repository=repository,
        runner=runner,
    )
    assert pending.disposition is StrategyInvocationDisposition.PENDING
    assert runner.calls == 1

    assert repository.stored_claim is not None
    repository.now = repository.stored_claim.recoverable_at
    recovered = run_durable_supervised_strategy_once(
        invocation=invocation,
        market_batch=batch,
        fence=fence,
        repository=repository,
        runner=runner,
    )
    assert recovered.result == interrupted_strategy_supervision_result(repository.stored_claim)
    assert runner.calls == 1


def test_crash_between_result_and_record_does_not_rerun_and_recovers_fail_closed() -> None:
    batch, invocation, fence, claimed_at = _facts()
    repository = FakeRepository(now=claimed_at, fail_finalize="before")
    expected_claim = _claim(invocation, fence, claimed_at)
    runner = FakeRunner(result=_runner_result(expected_claim))

    with pytest.raises(RuntimeError, match="before finalization"):
        run_durable_supervised_strategy_once(
            invocation=invocation,
            market_batch=batch,
            fence=fence,
            repository=repository,
            runner=runner,
        )
    assert runner.calls == 1

    assert repository.stored_claim is not None
    repository.now = repository.stored_claim.recoverable_at
    runner.error = AssertionError("must not rerun after returned result")
    recovered = run_durable_supervised_strategy_once(
        invocation=invocation,
        market_batch=batch,
        fence=fence,
        repository=repository,
        runner=runner,
    )

    assert recovered.result == interrupted_strategy_supervision_result(repository.stored_claim)
    assert runner.calls == 1


def test_response_loss_after_record_returns_retained_exact_result_without_rerun() -> None:
    batch, invocation, fence, claimed_at = _facts()
    repository = FakeRepository(now=claimed_at, fail_finalize="after")
    expected_claim = _claim(invocation, fence, claimed_at)
    expected_result = _runner_result(expected_claim)
    runner = FakeRunner(result=expected_result)

    with pytest.raises(RuntimeError, match="after finalization"):
        run_durable_supervised_strategy_once(
            invocation=invocation,
            market_batch=batch,
            fence=fence,
            repository=repository,
            runner=runner,
        )

    retained = run_durable_supervised_strategy_once(
        invocation=invocation,
        market_batch=batch,
        fence=fence,
        repository=repository,
        runner=runner,
    )
    assert retained.result == expected_result
    assert runner.calls == 1


def test_claim_requires_request_time_and_full_recovery_window_readiness() -> None:
    _, invocation, fence, claimed_at = _facts()

    with pytest.raises(
        StrategyInvocationLifecycleConflict,
        match="execution window",
    ):
        _claim(
            invocation,
            fence,
            claimed_at,
            valid_for=STRATEGY_INVOCATION_RECOVERY_INTERVAL,
        )

    with pytest.raises(
        StrategyInvocationLifecycleConflict,
        match="predates its request",
    ):
        _claim(
            invocation,
            fence,
            invocation.requested_at - timedelta(microseconds=1),
        )


def test_new_authority_requires_an_opaque_repository_envelope() -> None:
    _, invocation, fence, claimed_at = _facts()
    claim = _claim(invocation, fence, claimed_at)

    with pytest.raises(
        StrategyInvocationLifecycleError,
        match="opaque winning-claim envelope",
    ):
        StrategyInvocationLifecycleDecision(
            claim=claim,
            disposition=StrategyInvocationDisposition.NEW,
            result=None,
        )
    with pytest.raises(
        TypeError,
        match="issued by the durable claim repository",
    ):
        StrategyInvocationStartAuthorization()


def test_repository_or_runner_substitution_fails_closed() -> None:
    batch, invocation, fence, claimed_at = _facts()
    repository = FakeRepository(now=claimed_at)
    expected_claim = _claim(invocation, fence, claimed_at)
    other_invocation = StrategyInvocation(
        control_scope_id=invocation.control_scope_id,
        environment=invocation.environment,
        market_batch_id=invocation.market_batch_id,
        market_batch_sha256=invocation.market_batch_sha256,
        market_batch_as_of=invocation.market_batch_as_of,
        strategy_id=invocation.strategy_id,
        strategy_version=invocation.strategy_version,
        strategy_configuration_sha256=invocation.strategy_configuration_sha256,
        input_state_sha256="f" * 64,
        runtime=invocation.runtime,
        requested_at=invocation.requested_at,
    )
    tampered_result = StrategySupervisionResult(
        invocation_id=other_invocation.invocation_id,
        invocation_sha256=other_invocation.semantic_sha256,
        outcome=StrategySupervisionOutcome.CRASH,
        started_at=claimed_at,
        completed_at=claimed_at + timedelta(microseconds=1),
        elapsed_microseconds=1,
        process_started=False,
        exit_code=None,
        stdout_bytes=0,
        stdout_sha256=EMPTY_SHA256,
        stderr_bytes=0,
        stderr_sha256=EMPTY_SHA256,
        detail_code="wrong_invocation",
    )
    runner = FakeRunner(result=tampered_result)

    with pytest.raises(DurableStrategyRunnerInterrupted, match="identities"):
        run_durable_supervised_strategy_once(
            invocation=invocation,
            market_batch=batch,
            fence=fence,
            repository=repository,
            runner=runner,
        )
    assert repository.stored_claim == expected_claim
    assert repository.final_result is None

    with pytest.raises(
        DurableStrategyInvocationError,
        match="invocation conflict",
    ):
        run_durable_supervised_strategy_once(
            invocation=other_invocation,
            market_batch=batch,
            fence=fence,
            repository=repository,
            runner=runner,
        )


def test_retained_final_result_outside_claim_window_is_rejected() -> None:
    _, invocation, fence, claimed_at = _facts()
    claim = _claim(invocation, fence, claimed_at)
    result = _runner_result(claim)

    with pytest.raises(
        StrategyInvocationLifecycleConflict,
        match="claim-window",
    ):
        StrategyInvocationLifecycleDecision(
            claim=claim,
            disposition=StrategyInvocationDisposition.FINAL,
            result=result.__class__(
                invocation_id=result.invocation_id,
                invocation_sha256=result.invocation_sha256,
                outcome=result.outcome,
                started_at=claimed_at - timedelta(microseconds=1),
                completed_at=claimed_at,
                elapsed_microseconds=1,
                process_started=result.process_started,
                exit_code=result.exit_code,
                stdout_bytes=result.stdout_bytes,
                stdout_sha256=result.stdout_sha256,
                stderr_bytes=result.stderr_bytes,
                stderr_sha256=result.stderr_sha256,
                detail_code=result.detail_code,
            ),
        )


def test_recovery_boundary_belongs_to_orphan_recovery_not_runner_finalization() -> None:
    batch, invocation, fence, claimed_at = _facts()
    claim = _claim(invocation, fence, claimed_at)
    timely = _runner_result(claim)
    equality_result = timely.__class__(
        invocation_id=timely.invocation_id,
        invocation_sha256=timely.invocation_sha256,
        outcome=timely.outcome,
        started_at=timely.started_at,
        completed_at=claim.recoverable_at,
        elapsed_microseconds=int(
            (claim.recoverable_at - timely.started_at).total_seconds() * 1_000_000
        ),
        process_started=timely.process_started,
        exit_code=timely.exit_code,
        stdout_bytes=timely.stdout_bytes,
        stdout_sha256=timely.stdout_sha256,
        stderr_bytes=timely.stderr_bytes,
        stderr_sha256=timely.stderr_sha256,
        detail_code=timely.detail_code,
        response=timely.response,
    )

    with pytest.raises(
        StrategyInvocationLifecycleConflict,
        match="claim-window",
    ):
        StrategyInvocationLifecycleDecision(
            claim=claim,
            disposition=StrategyInvocationDisposition.FINAL,
            result=equality_result,
        )

    repository = FakeRepository(now=claimed_at)
    runner = FakeRunner(result=equality_result)
    with pytest.raises(
        DurableStrategyRunnerInterrupted,
        match="execution window",
    ):
        run_durable_supervised_strategy_once(
            invocation=invocation,
            market_batch=batch,
            fence=fence,
            repository=repository,
            runner=runner,
        )
    assert runner.calls == 1
    assert repository.final_result is None
