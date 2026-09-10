"""Adapter from the frozen daily callback view to the two reference rules."""

from __future__ import annotations

from decimal import Decimal

from packages.domain.accounting_contracts import AccountSnapshot
from packages.domain.daily_reference import ReferenceConfiguration, reference_targets
from packages.domain.engine_contracts import (
    DailyStrategyContext,
    DailyStrategyState,
    DailyStrategyTransition,
    DailyTarget,
)
from packages.domain.models import Side
from packages.domain.personal_contracts import content_digest, require_amount


class ReferenceStrategy:
    """A configurable engineering reference; acceptance remains the risk port's job."""

    def __init__(
        self,
        *,
        reserve_fraction: Decimal = Decimal("0.01"),
        fee_per_share: Decimal = Decimal("0.01"),
    ) -> None:
        require_amount(reserve_fraction, "strategy reserve", nonnegative=True)
        require_amount(fee_per_share, "strategy fee", nonnegative=True)
        self.reserve_fraction = reserve_fraction
        self.fee_per_share = fee_per_share

    def initialize(
        self, *, configuration: ReferenceConfiguration, initial_snapshot: AccountSnapshot
    ) -> DailyStrategyState:
        return DailyStrategyState(previously_allocated=self._allocated(initial_snapshot))

    @staticmethod
    def _allocated(snapshot: AccountSnapshot) -> bool:
        return any(position.quantity > 0 for position in snapshot.positions) or any(
            commitment.side is Side.BUY and commitment.state != "terminal"
            for commitment in snapshot.commitments
        )

    def on_decision(self, context: DailyStrategyContext) -> DailyStrategyTransition:
        # An emitted but rejected target is not an acknowledged allocation.
        acknowledged = context.state.previously_allocated or self._allocated(context.account)
        decision = reference_targets(
            context.configuration,
            instrument_symbols=context.instrument_symbols,
            history=context.history,
            expected_sessions=context.expected_sessions,
            current_quantities=tuple(
                (position.instrument_id, position.quantity)
                for position in context.account.positions
            ),
            nav=context.account.nav,
            reference_prices=tuple(
                (mark.instrument_id, mark.price)
                for mark in context.account.marks
                if mark.quality == "current" and mark.session == context.trigger.source_session
            ),
            scored_session_index=context.scored_session_index,
            previously_allocated=acknowledged,
            reserve_fraction=self.reserve_fraction,
            fee_per_share=self.fee_per_share,
        )
        state = DailyStrategyState(
            generation=context.state.generation + 1,
            predecessor_sha256=context.state.semantic_sha256,
            previously_allocated=acknowledged,
        )
        if not decision.should_emit:
            return DailyStrategyTransition(state, None, decision.reasons)
        configuration_sha = content_digest(context.configuration)
        target_id = "target-" + content_digest(
            (
                context.trigger,
                configuration_sha,
                decision.targets,
                context.not_before,
                context.expires_at,
            )
        )
        return DailyStrategyTransition(
            state,
            DailyTarget(
                target_id=target_id,
                trigger=context.trigger,
                configuration_sha256=configuration_sha,
                targets=decision.targets,
                not_before=context.not_before,
                expires_at=context.expires_at,
                explanation=f"{context.configuration.kind} reference with whole-share cash sizing",
            ),
            (),
        )
