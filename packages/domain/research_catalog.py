"""Immutable catalog references; registration conveys no strategy qualification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Literal

from packages.domain.personal_contracts import ContractRecord, require_digest, require_text
from packages.domain.personal_evaluation import PriorAccessDeclaration
from packages.domain.research_dataset import ResearchDataClass
from packages.domain.research_job_contracts import MAX_INPUT_BYTES, ObjectRef


@dataclass(frozen=True, slots=True)
class ResearchCatalogEntry(ContractRecord):
    contract_version: ClassVar[str] = "personal-research-catalog/1"
    display_name: str
    prior_access: PriorAccessDeclaration
    source_inputs: ObjectRef
    archive: ObjectRef | None
    settlement_calendar: ObjectRef
    dataset_id: str
    dataset_sha256: str
    source_spec_sha256: str
    data_class: ResearchDataClass
    availability_mode: Literal["modeled", "recorded"]
    instruments: tuple[tuple[str, str], ...]
    calendar_sha256: str
    settlement_calendar_sha256: str

    def __post_init__(self) -> None:
        super(ResearchCatalogEntry, self).__post_init__()
        require_text(self.display_name, "catalog display name")
        require_text(self.dataset_id, "source dataset identity")
        if len(self.display_name) > 160:
            raise ValueError("catalog display name exceeds its bound")
        for name in (
            "dataset_sha256",
            "source_spec_sha256",
            "calendar_sha256",
            "settlement_calendar_sha256",
        ):
            require_digest(getattr(self, name), name)
        for reference in (self.source_inputs, self.archive, self.settlement_calendar):
            if reference is not None and reference.byte_count > MAX_INPUT_BYTES:
                raise ValueError("catalog input exceeds the 32 MiB cap")
        if (
            self.source_inputs.codec_version != "personal-record/1"
            or self.settlement_calendar.codec_version != "personal-record/1"
        ):
            raise ValueError("catalog inputs and settlement calendar require typed records")
        if (
            self.archive is not None
            and self.archive.codec_version != "personal-research-dataset-v1"
        ):
            raise ValueError("catalog archive requires the W1 dataset codec")
        if self.data_class is ResearchDataClass.VALIDATED_CURRENT_VINTAGE and self.archive is None:
            raise ValueError("current-vintage catalog entry requires its retained archive")
        ids = tuple(i for i, _ in self.instruments)
        if (
            not ids
            or len(ids) > 4
            or ids != tuple(sorted(set(ids)))
            or any(s not in ("DIA", "IWM", "QQQ", "SPY") for _, s in self.instruments)
        ):
            raise ValueError("catalog instruments require sorted unique supported identities")

    @property
    def catalog_id(self) -> str:
        return "catalog-" + self.semantic_sha256
