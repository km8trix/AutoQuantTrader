"""Exact retained daily captures selected at one continuous knowledge boundary."""

from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar, Literal

from packages.domain.forward_capture_contracts import CaptureEvidenceClass, CapturePublication
from packages.domain.forward_contracts import ForwardDataState
from packages.domain.personal_contracts import ContractRecord
from packages.domain.research_job_contracts import require_identifier

MAX_CLOSURE_CAPTURES = 64
MAX_CLOSURE_RAW_BYTES = 32 * 1024 * 1024
MAX_CLOSURE_RECORD_BYTES = 16 * 1024 * 1024


def validate_continuous_capture_inventory(
    *,
    account_id: str,
    closure_id: str,
    initial_state: ForwardDataState,
    publications: tuple[CapturePublication, ...],
    observation_ids: tuple[str, ...],
    admitted_at: datetime,
    evidence_class: CaptureEvidenceClass,
    kind: Literal["daily", "quote"],
) -> None:
    """Common unchanged raw-capture bounds; each caller keeps its distinct schema."""
    require_identifier(account_id, "source closure account")
    require_identifier(closure_id, "source closure identity")
    if initial_state.mode != "recorded" or initial_state.observations or initial_state.frontiers:
        raise ValueError("CAPTURE_CLOSURE_REQUIRES_EMPTY_RECORDED_ORIGIN")
    if not 1 <= len(publications) <= MAX_CLOSURE_CAPTURES:
        raise ValueError("CAPTURE_CLOSURE_COUNT_LIMIT")
    identities = tuple(
        (p.record.request.journal_key.semantic_sha256, p.record.request.capture_id)
        for p in publications
    )
    if len(set(identities)) != len(identities):
        raise ValueError("CAPTURE_CLOSURE_DUPLICATE_PUBLICATION")
    if sum(p.record.raw_object.byte_count for p in publications) > MAX_CLOSURE_RAW_BYTES:
        raise ValueError("CAPTURE_CLOSURE_RAW_LIMIT")
    for publication in publications:
        record, request = publication.record, publication.record.request
        if (
            request.kind != kind
            or request.journal_key.account_scope != account_id
            or request.evidence_class != evidence_class
            or record.receipt.validated_at > admitted_at
        ):
            raise ValueError("CAPTURE_CLOSURE_SCOPE_CLASS_OR_TIME_DIFFERS")
    if (
        not observation_ids
        or observation_ids != tuple(sorted(set(observation_ids)))
        or len(observation_ids) > 2048
    ):
        raise ValueError("CAPTURE_CLOSURE_SELECTION_LIMIT")


@dataclass(frozen=True, slots=True, kw_only=True)
class ContinuousForwardClosure(ContractRecord):
    contract_version: ClassVar[str] = "personal-continuous-forward-closure/1"
    account_id: str
    closure_id: str
    initial_state: ForwardDataState
    publications: tuple[CapturePublication, ...]
    observation_ids: tuple[str, ...]
    admitted_at: datetime
    evidence_class: CaptureEvidenceClass

    def __post_init__(self) -> None:
        super(ContinuousForwardClosure, self).__post_init__()
        validate_continuous_capture_inventory(
            account_id=self.account_id,
            closure_id=self.closure_id,
            initial_state=self.initial_state,
            publications=self.publications,
            observation_ids=self.observation_ids,
            admitted_at=self.admitted_at,
            evidence_class=self.evidence_class,
            kind="daily",
        )
