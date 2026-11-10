"""Immutable browser intent and preregistered evaluation/job bindings."""

from dataclasses import dataclass
from typing import ClassVar

from packages.domain.personal_contracts import ContractRecord, content_digest, require_digest
from packages.domain.personal_evaluation import EvaluationProtocol, EvaluationTrial
from packages.domain.research_job_contracts import ObjectRef, require_identifier


@dataclass(frozen=True, slots=True)
class ResearchExperimentRegistration(ContractRecord):
    contract_version: ClassVar[str] = "personal-research-registration/1"
    owner_id: str
    idempotency_key: str
    request_json: str
    catalog_id: str
    protocol: EvaluationProtocol
    trials: tuple[EvaluationTrial, ...]
    job_ids: tuple[str, ...]
    source_inputs: ObjectRef
    fit_objects: tuple[ObjectRef, ...]

    def __post_init__(self) -> None:
        super(ResearchExperimentRegistration, self).__post_init__()
        require_identifier(self.owner_id, "owner")
        require_identifier(self.idempotency_key, "idempotency key")
        if not 8 <= len(self.idempotency_key) <= 128 or not 0 < len(self.request_json) <= 65536:
            raise ValueError("experiment intent exceeds its bounds")
        if self.catalog_id != "catalog-" + self.catalog_id.removeprefix("catalog-"):
            raise ValueError("invalid catalog identity")
        require_digest(self.catalog_id.removeprefix("catalog-"), "catalog content")
        if (
            not 1 <= len(self.trials) <= 256
            or len(self.trials) != self.protocol.planned_trial_count
            or len(self.job_ids) != len(self.trials)
            or len(set(self.job_ids)) != len(self.job_ids)
            or tuple(trial.ordinal for trial in self.trials) != tuple(range(len(self.trials)))
            or any(trial.protocol_sha256 != self.protocol.semantic_sha256 for trial in self.trials)
            or not 1 <= len(self.fit_objects) <= 64
        ):
            raise ValueError("experiment must bind its complete bounded trial inventory")
        for job_id in self.job_ids:
            require_digest(job_id, "registered job")

    @property
    def experiment_id(self) -> str:
        return content_digest((self.contract_version, self.owner_id, self.idempotency_key))
