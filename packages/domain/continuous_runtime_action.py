"""An internal account action at an already closed source boundary; no authority."""

from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar

from packages.domain.accounting_contracts import (
    AccountingCommand,
    ActivateRuntimeCommitments,
    ReleaseRuntimeUnsent,
)
from packages.domain.daily_attempt_contracts import DailyAttemptEvent
from packages.domain.identifiers import canonical_id
from packages.domain.personal_contracts import ContractRecord, require_digest, require_text
from packages.domain.submission_attempt import SubmissionAttemptState


@dataclass(frozen=True, slots=True, kw_only=True)
class ContinuousRuntimeAction(ContractRecord):
    contract_version: ClassVar[str] = "personal-continuous-runtime-action/1"
    action_id: str
    stream_id: str
    previous_checkpoint_sha256: str
    source_closure_sha256: str
    checked_at: datetime
    command: AccountingCommand | None = None
    attempt_events: tuple[DailyAttemptEvent, ...] = ()

    def __post_init__(self) -> None:
        super(ContinuousRuntimeAction, self).__post_init__()
        require_text(self.action_id, "runtime action")
        require_text(self.stream_id, "runtime stream")
        require_digest(self.previous_checkpoint_sha256, "runtime predecessor checkpoint")
        require_digest(self.source_closure_sha256, "runtime action source closure")
        if self.command is None:
            if (
                type(self.attempt_events) is not tuple
                or not 1 <= len(self.attempt_events) <= 4
                or any(type(item) is not DailyAttemptEvent for item in self.attempt_events)
                or tuple(item.attempt_id for item in self.attempt_events)
                != tuple(sorted({item.attempt_id for item in self.attempt_events}))
                or any(
                    item.recorded_at != self.checked_at
                    or item.state
                    not in (
                        SubmissionAttemptState.PENDING,
                        SubmissionAttemptState.UNKNOWN,
                        SubmissionAttemptState.CONFIRMED,
                        SubmissionAttemptState.RESOLVED,
                    )
                    for item in self.attempt_events
                )
            ):
                raise ValueError(
                    "metadata action requires a complete bounded original attempt event group"
                )
            return
        if self.attempt_events:
            raise ValueError("accounting action cannot mix metadata-only attempt events")
        if type(self.command.payload) not in (ActivateRuntimeCommitments, ReleaseRuntimeUnsent):
            raise ValueError(
                "runtime action requires a canonical activation or proven-unsent release"
            )
        assert isinstance(self.command.payload, (ActivateRuntimeCommitments, ReleaseRuntimeUnsent))
        at = (
            self.command.payload.checked_at
            if isinstance(self.command.payload, ActivateRuntimeCommitments)
            else self.command.payload.proof_at
        )
        if at != self.checked_at:
            raise ValueError("runtime action cannot refresh its original check time")

    @property
    def retained_id(self) -> str:
        return canonical_id("continuous-runtime-action", self.action_id)
