"""Bounded retained checkpoint references; values confer no account authority."""

from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar, Literal

from packages.domain.continuous_account_contracts import CanonicalAccountTransitionRef
from packages.domain.durable_journal_contracts import JournalReceipt, journal_identifier
from packages.domain.personal_contracts import ContractRecord, require_digest
from packages.domain.research_job_contracts import ObjectRef

MAX_CONTINUOUS_OBJECT_BYTES = 32 * 1024 * 1024
MAX_CONTINUOUS_COMMIT_BYTES = 16 * 1024
MAX_CONTINUOUS_PAGE = 64
CONTINUOUS_COMMIT_SCHEMA = "continuous-account-commit/1"
CONTINUOUS_REQUEST_SCHEMA = "continuous-account-request/1"
CONTINUOUS_RUNTIME_ACTION_SCHEMA = "continuous-runtime-action/1"


class ContinuousPersistenceRecord(ContractRecord):
    __slots__ = ()
    contract_version: ClassVar[str] = "personal-continuous-persistence/1"


@dataclass(frozen=True, slots=True)
class ContinuousAccountScope(ContinuousPersistenceRecord):
    account_id: str
    account_binding_sha256: str
    stream_id: str
    environment: Literal["stateful_simulation"] = "stateful_simulation"

    def __post_init__(self) -> None:
        super(ContinuousAccountScope, self).__post_init__()
        journal_identifier(self.account_id)
        journal_identifier(self.stream_id)
        require_digest(self.account_binding_sha256, "account binding")


@dataclass(frozen=True, slots=True)
class ContinuousEvidenceRef(ContinuousPersistenceRecord):
    schema_id: str
    object_ref: ObjectRef
    semantic_sha256: str

    def __post_init__(self) -> None:
        super(ContinuousEvidenceRef, self).__post_init__()
        journal_identifier(self.schema_id)
        require_digest(self.semantic_sha256, "evidence semantic identity")
        if self.object_ref.codec_version != "personal-record/1" or (
            self.object_ref.byte_count > MAX_CONTINUOUS_OBJECT_BYTES
        ):
            raise ValueError("continuous evidence requires bounded typed objects")


@dataclass(frozen=True, slots=True)
class ContinuousAccountCommit(ContinuousPersistenceRecord):
    scope: ContinuousAccountScope
    sequence: int
    previous_commit_sha256: str | None
    transition: CanonicalAccountTransitionRef
    request: ContinuousEvidenceRef
    source_evidence: ContinuousEvidenceRef
    decision_evidence: ContinuousEvidenceRef

    def __post_init__(self) -> None:
        super(ContinuousAccountCommit, self).__post_init__()
        if not 1 <= self.sequence <= 2**63 - 1:
            raise ValueError("continuous sequence outside bounds")
        if self.previous_commit_sha256 is not None:
            require_digest(self.previous_commit_sha256, "previous continuous commit")
        if (self.sequence == 1) != (self.previous_commit_sha256 is None):
            raise ValueError("continuous genesis predecessor differs")
        if self.request.schema_id not in (
            CONTINUOUS_REQUEST_SCHEMA,
            CONTINUOUS_RUNTIME_ACTION_SCHEMA,
        ) or (self.sequence == 1 and self.request.schema_id != CONTINUOUS_REQUEST_SCHEMA):
            raise ValueError("continuous request schema differs")
        if self.transition.account_id != self.scope.account_id or (
            self.transition.account_binding_sha256 != self.scope.account_binding_sha256
        ):
            raise ValueError("continuous transition scope differs")


@dataclass(frozen=True, slots=True)
class ContinuousFenceReference(ContinuousPersistenceRecord):
    owner_id: str
    lease_id: str
    fencing_generation: int
    lease_sha256: str
    policy_sha256: str
    valid_until: datetime

    def __post_init__(self) -> None:
        super(ContinuousFenceReference, self).__post_init__()
        for value in (self.owner_id, self.lease_id):
            journal_identifier(value)
        for value in (self.lease_sha256, self.policy_sha256):
            require_digest(value, "recorded fence")
        if not 1 <= self.fencing_generation <= 2**63 - 1:
            raise ValueError("recorded fence generation outside bounds")


@dataclass(frozen=True, slots=True)
class ContinuousAccountRecord(ContinuousPersistenceRecord):
    """Preencoded before SQL; in-transaction timestamps stay separate scalars."""

    commit: ContinuousAccountCommit
    journal: JournalReceipt

    def __post_init__(self) -> None:
        super(ContinuousAccountRecord, self).__post_init__()
        if (
            self.journal.command_id != self.commit.transition.command_id
            or self.journal.command_sha256 != self.commit.transition.command_sha256
            or self.journal.committed_head.sequence != self.commit.sequence
            or self.journal.previous_head.sequence + 1 != self.commit.sequence
            or self.journal.record_ids != (self.commit.semantic_sha256,)
        ):
            raise ValueError("continuous journal record bindings differ")


@dataclass(frozen=True, slots=True)
class ContinuousAccountReceipt(ContinuousPersistenceRecord):
    commit: ContinuousAccountCommit
    journal: JournalReceipt
    recorded_at: datetime
    fence_reference: ContinuousFenceReference

    def __post_init__(self) -> None:
        super(ContinuousAccountReceipt, self).__post_init__()
        if (
            self.journal.command_id != self.commit.transition.command_id
            or self.journal.command_sha256 != self.commit.transition.command_sha256
            or self.journal.committed_head.sequence != self.commit.sequence
            or self.journal.previous_head.sequence + 1 != self.commit.sequence
            or self.journal.record_ids != (self.commit.semantic_sha256,)
            or self.recorded_at >= self.fence_reference.valid_until
            or self.commit.transition.applied_at > self.recorded_at
            or self.commit.transition.resulting_heads.lease_generation
            != self.fence_reference.fencing_generation
        ):
            raise ValueError("continuous receipt bindings differ")
