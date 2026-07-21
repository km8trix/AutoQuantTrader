"""Provider-neutral execution ports."""

from __future__ import annotations

from typing import Protocol

from packages.domain.models import OrderIntent


class BrokerPort[ResultT](Protocol):
    """Submit one exactly authorized intent through a configured broker boundary."""

    def submit(
        self,
        intent: OrderIntent,
        risk_decision_id: str,
        submission_attempt_id: str,
    ) -> ResultT: ...
