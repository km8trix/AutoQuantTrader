"""Immutable linkage between a continuous checkpoint and its account transaction."""

from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar, Literal

from packages.domain.personal_contracts import ContractRecord, require_digest, require_text
from packages.domain.reconciliation_contracts import ReconciliationHeads
from packages.domain.research_job_contracts import ObjectRef


@dataclass(frozen=True, slots=True, kw_only=True)
class CanonicalAccountTransitionRef(ContractRecord):
    """Content reference only; a durable producer must authenticate its closure.

    The referenced bytes hold the full checkpoint. The scope and before/after
    heads are verified in the caller's fenced account transaction, alongside the
    separately retained source closure. Constructors grant no execution authority.
    """

    contract_version: ClassVar[str] = "personal-continuous-account-transition/1"
    account_id: str
    account_binding_sha256: str
    command_id: str
    command_sha256: str
    previous_checkpoint_sha256: str | None
    checkpoint: ObjectRef
    checkpoint_sha256: str
    expected_heads: ReconciliationHeads
    resulting_heads: ReconciliationHeads
    source_closure_sha256: str
    applied_at: datetime
    environment: Literal["stateful_simulation"] = "stateful_simulation"

    def __post_init__(self) -> None:
        super(CanonicalAccountTransitionRef, self).__post_init__()
        for name in ("account_id", "command_id"):
            require_text(getattr(self, name), name)
        for name in (
            "account_binding_sha256",
            "command_sha256",
            "checkpoint_sha256",
            "source_closure_sha256",
        ):
            require_digest(getattr(self, name), name)
        if self.previous_checkpoint_sha256 is not None:
            require_digest(self.previous_checkpoint_sha256, "previous checkpoint")
        if (
            self.checkpoint.codec_version != "personal-record/1"
            or self.checkpoint.byte_count > 32 * 1024 * 1024
        ):
            raise ValueError("canonical transition requires a bounded typed checkpoint object")
