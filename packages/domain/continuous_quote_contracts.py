"""Original capture/side/clock selections; values confer no freshness authority."""

from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar

from packages.domain.continuous_forward_contracts import validate_continuous_capture_inventory
from packages.domain.forward_capture_contracts import CaptureEvidenceClass, CapturePublication
from packages.domain.forward_contracts import ForwardDataState, ForwardRequirement
from packages.domain.models import Side
from packages.domain.personal_contracts import ContractRecord, VersionPin, require_text

CONTINUOUS_QUOTE_CLOSURE_SCHEMA = "continuous-quote-closure/1"


@dataclass(frozen=True, slots=True)
class ContinuousQuoteSelection(ContractRecord):
    observation_id: str
    expected: ForwardRequirement
    side: Side
    producer: VersionPin

    def __post_init__(self) -> None:
        super(ContinuousQuoteSelection, self).__post_init__()
        require_text(self.observation_id, "selected quote observation")
        if self.expected.kind != "quote":
            raise ValueError("continuous quote selection requires an exact quote slot")


@dataclass(frozen=True, slots=True, kw_only=True)
class ContinuousQuoteClosure(ContractRecord):
    contract_version: ClassVar[str] = "personal-continuous-quote-closure/1"
    account_id: str
    closure_id: str
    initial_state: ForwardDataState
    publications: tuple[CapturePublication, ...]
    selections: tuple[ContinuousQuoteSelection, ...]
    admitted_at: datetime
    boot_id: str
    admitted_monotonic_ns: int
    evidence_class: CaptureEvidenceClass

    def __post_init__(self) -> None:
        super(ContinuousQuoteClosure, self).__post_init__()
        require_text(self.boot_id, "original quote closure boot")
        instruments = tuple(value.expected.instrument_id for value in self.selections)
        if not 1 <= len(instruments) <= 4 or instruments != tuple(sorted(set(instruments))):
            raise ValueError("continuous quote closure requires one to four distinct instruments")
        if not 0 <= self.admitted_monotonic_ns < 2**63:
            raise ValueError("continuous quote closure monotonic instant is outside its bound")
        if len(self.observation_ids) != len(set(self.observation_ids)):
            raise ValueError("continuous quote selection repeats an observation")
        validate_continuous_capture_inventory(
            account_id=self.account_id,
            closure_id=self.closure_id,
            initial_state=self.initial_state,
            publications=self.publications,
            observation_ids=self.observation_ids,
            admitted_at=self.admitted_at,
            evidence_class=self.evidence_class,
            kind="quote",
        )

    @property
    def observation_ids(self) -> tuple[str, ...]:
        return tuple(sorted(value.observation_id for value in self.selections))
