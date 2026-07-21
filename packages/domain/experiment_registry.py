"""Pure immutable contracts for fixture-only experiment governance.

This module records canonical research declarations and trial snapshots.  It
does not persist jobs, reveal data, execute strategies, or grant promotion or
trading authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from types import MappingProxyType
from typing import Self

from packages.domain.canonical import (
    canonical_decimal,
    canonical_json_bytes,
    canonical_json_text,
    canonical_persisted_decimal,
)

EXPERIMENT_REGISTRY_CONTRACT_VERSION = "phase2-experiment-registry-v1"
MAX_CONFIGURATION_FIELDS = 128
MAX_CONFIGURATION_STRING_LENGTH = 4096
MAX_CONFIGURATION_BYTES = 65_536
MAX_CONFIGURATION_INTEGER_BITS = 256
MAX_PARAMETER_SCHEMA_BYTES = 65_536

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")

type ConfigurationValue = None | bool | int | str | Decimal
type _ParameterSchemaRule = tuple[str, bool, object]


class StrategyParameterSchemaError(ValueError):
    """The declared strategy parameter schema is malformed or unsupported."""


class StrategyConfigurationSchemaMismatch(ValueError):
    """Canonical strategy parameters do not satisfy their declared schema."""


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(value: str, field_name: str, *, maximum: int = 128) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"{field_name} must be non-empty and trimmed")
    if len(value) > maximum or any(ord(character) < 32 for character in value):
        raise ValueError(f"{field_name} contains unsupported text")


def _require_sha256(value: str, field_name: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_optional_sha256(value: str | None, field_name: str) -> None:
    if value is not None:
        _require_sha256(value, field_name)


def _require_utc(value: datetime, field_name: str) -> None:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{field_name} must be UTC")


def _duration_microseconds(value: timedelta) -> int:
    return value.days * 86_400_000_000 + value.seconds * 1_000_000 + value.microseconds


def _configuration_value(value: object) -> ConfigurationValue:
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if value.bit_length() > MAX_CONFIGURATION_INTEGER_BITS:
            raise ValueError("strategy configuration integer exceeds its size limit")
        return value
    if type(value) is str:
        if len(value) > MAX_CONFIGURATION_STRING_LENGTH or any(
            ord(character) < 32 for character in value
        ):
            raise ValueError("strategy configuration string contains unsupported text")
        return value
    if type(value) is Decimal:
        if not value.is_finite():
            raise ValueError("strategy configuration Decimal must be finite")
        return canonical_decimal(value)
    raise ValueError("strategy configuration values must be null, bool, int, str, or Decimal")


def _reject_duplicate_schema_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"parameter schema contains duplicate key {key!r}")
        result[key] = value
    return result


def _reject_nonstandard_json_constant(value: str) -> object:
    raise ValueError(f"parameter schema contains non-standard JSON constant {value!r}")


def _parameter_schema_rules(
    parameter_schema_payload: str,
) -> tuple[dict[str, _ParameterSchemaRule], frozenset[str]]:
    if type(parameter_schema_payload) is not str:
        raise ValueError("parameter schema payload must be text")
    if not 2 <= len(parameter_schema_payload.encode("utf-8")) <= MAX_PARAMETER_SCHEMA_BYTES:
        raise ValueError("parameter schema payload exceeds its encoded size limit")
    try:
        document: object = json.loads(
            parameter_schema_payload,
            object_pairs_hook=_reject_duplicate_schema_keys,
            parse_constant=_reject_nonstandard_json_constant,
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise ValueError("parameter schema must be strict JSON without duplicate keys") from error
    if type(document) is not dict:
        raise ValueError("parameter schema root must be an object")

    supported_root_keys = frozenset({"additionalProperties", "properties", "required", "type"})
    document_keys = frozenset(document)
    if document_keys != supported_root_keys:
        unsupported = sorted(document_keys - supported_root_keys)
        missing = sorted(supported_root_keys - document_keys)
        detail = unsupported or missing
        qualifier = "unsupported" if unsupported else "missing"
        raise ValueError(f"parameter schema has {qualifier} root fields: {detail!r}")
    if document["type"] != "object":
        raise ValueError("parameter schema root type must be 'object'")
    if document["additionalProperties"] is not False:
        raise ValueError("parameter schema must set additionalProperties to false")

    raw_properties = document["properties"]
    if type(raw_properties) is not dict:
        raise ValueError("parameter schema properties must be an object")
    if len(raw_properties) > MAX_CONFIGURATION_FIELDS:
        raise ValueError("parameter schema exceeds its property-count limit")

    raw_required = document["required"]
    if type(raw_required) is not list:
        raise ValueError("parameter schema required must be an array")
    if len(raw_required) > MAX_CONFIGURATION_FIELDS:
        raise ValueError("parameter schema exceeds its required-field limit")
    required: set[str] = set()
    for field_name in raw_required:
        if type(field_name) is not str:
            raise ValueError("parameter schema required fields must be strings")
        _require_text(field_name, "parameter schema required field")
        if field_name in required:
            raise ValueError(f"parameter schema repeats required field {field_name!r}")
        required.add(field_name)

    rules: dict[str, _ParameterSchemaRule] = {}
    supported_property_keys = frozenset({"const", "type"})
    supported_types = frozenset({"boolean", "integer", "null", "string"})
    for field_name, raw_rule in raw_properties.items():
        _require_text(field_name, "parameter schema property")
        if type(raw_rule) is not dict:
            raise ValueError(f"parameter schema property {field_name!r} must be an object")
        rule_keys = frozenset(raw_rule)
        if "type" not in rule_keys:
            raise ValueError(f"parameter schema property {field_name!r} must declare a type")
        unsupported = sorted(rule_keys - supported_property_keys)
        if unsupported:
            raise ValueError(
                f"parameter schema property {field_name!r} has unsupported fields: {unsupported!r}"
            )
        type_name = raw_rule["type"]
        if type(type_name) is not str or type_name not in supported_types:
            raise ValueError(
                f"parameter schema property {field_name!r} has unsupported type {type_name!r}"
            )
        has_const = "const" in raw_rule
        const_value = raw_rule.get("const")
        if has_const and not _parameter_matches_schema_type(const_value, type_name):
            raise ValueError(
                f"parameter schema property {field_name!r} const conflicts with its type"
            )
        if has_const:
            try:
                _configuration_value(const_value)
            except ValueError as error:
                raise ValueError(
                    f"parameter schema property {field_name!r} const is unsupported"
                ) from error
        rules[field_name] = (type_name, has_const, const_value)
    undeclared_required = sorted(required - rules.keys())
    if undeclared_required:
        raise ValueError(
            f"parameter schema has required fields without properties: {undeclared_required!r}"
        )
    return rules, frozenset(required)


def _parameter_matches_schema_type(value: object, type_name: str) -> bool:
    if type_name == "null":
        return value is None
    if type_name == "boolean":
        return type(value) is bool
    if type_name == "integer":
        return type(value) is int
    return type_name == "string" and type(value) is str


def _parameter_schema_value(value: ConfigurationValue) -> None | bool | int | str:
    if isinstance(value, Decimal):
        canonical = canonical_decimal(value)
        sign, digits, raw_exponent = canonical.as_tuple()
        exponent = int(raw_exponent)
        if not any(digits):
            rendered_length = 1
        elif exponent >= 0:
            rendered_length = int(sign) + len(digits) + exponent
        else:
            decimal_index = len(digits) + exponent
            rendered_length = (
                int(sign) + len(digits) + 1
                if decimal_index > 0
                else int(sign) + 2 - decimal_index + len(digits)
            )
        if rendered_length > MAX_CONFIGURATION_STRING_LENGTH:
            raise StrategyConfigurationSchemaMismatch(
                "strategy configuration Decimal schema value exceeds its string-length limit"
            )
        return format(canonical, "f")
    return value


def validate_strategy_configuration_parameters(
    parameter_schema_payload: str,
    parameters: Mapping[str, ConfigurationValue],
) -> None:
    """Validate canonical strategy parameters against the supported schema subset.

    The accepted vocabulary is intentionally limited to a closed object with
    required fields and scalar ``type``/``const`` property rules. Decimal
    parameters are exposed as bounded canonical fixed-point strings.
    """

    try:
        rules, required = _parameter_schema_rules(parameter_schema_payload)
    except ValueError as error:
        raise StrategyParameterSchemaError(str(error)) from error
    parameter_names = frozenset(parameters)
    missing = sorted(required - parameter_names)
    if missing:
        raise StrategyConfigurationSchemaMismatch(
            f"strategy configuration is missing required parameters: {missing!r}"
        )
    undeclared = sorted(parameter_names - rules.keys())
    if undeclared:
        raise StrategyConfigurationSchemaMismatch(
            f"strategy configuration contains undeclared parameters: {undeclared!r}"
        )
    for field_name, value in parameters.items():
        schema_value = _parameter_schema_value(value)
        type_name, has_const, const_value = rules[field_name]
        if not _parameter_matches_schema_type(schema_value, type_name):
            raise StrategyConfigurationSchemaMismatch(
                f"strategy configuration parameter {field_name!r} must have type {type_name!r}"
            )
        if has_const and schema_value != const_value:
            raise StrategyConfigurationSchemaMismatch(
                f"strategy configuration parameter {field_name!r} conflicts with schema const"
            )


class FixtureSourceKind(StrEnum):
    SYNTHETIC = "synthetic_fixture"
    RECORDED = "recorded_fixture"


class EvaluationSegmentKind(StrEnum):
    TRAIN = "train"
    VALIDATION = "validation"
    TEST = "test"


class PromotionComparison(StrEnum):
    GREATER_THAN_OR_EQUAL = "greater_than_or_equal"
    LESS_THAN_OR_EQUAL = "less_than_or_equal"


class ExperimentTrialStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"
    ABANDONED = "abandoned"


_TERMINAL_TRIAL_STATUSES = frozenset(
    {
        ExperimentTrialStatus.COMPLETED,
        ExperimentTrialStatus.FAILED,
        ExperimentTrialStatus.CANCELED,
        ExperimentTrialStatus.ABANDONED,
    }
)


@dataclass(frozen=True, slots=True)
class StrategyVersionRecord:
    """Content-addressed strategy implementation and parameter schema."""

    strategy_id: str
    strategy_version: str
    code_sha256: str
    parameter_schema_sha256: str
    state_schema_version: str
    source_revision: str
    registered_at: datetime
    registered_by: str

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.strategy_id, "strategy ID"),
            (self.strategy_version, "strategy version"),
            (self.state_schema_version, "strategy state schema version"),
            (self.registered_by, "strategy registrar"),
        ):
            _require_text(value, field_name)
        _require_sha256(self.code_sha256, "strategy code digest")
        _require_sha256(self.parameter_schema_sha256, "parameter schema digest")
        if (
            type(self.source_revision) is not str
            or _SOURCE_REVISION.fullmatch(self.source_revision) is None
        ):
            raise ValueError("source_revision must be a lowercase source commit digest")
        _require_utc(self.registered_at, "strategy registered_at")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            EXPERIMENT_REGISTRY_CONTRACT_VERSION,
            "strategy_version",
            self.strategy_id,
            self.strategy_version,
            self.code_sha256,
            self.parameter_schema_sha256,
            self.state_schema_version,
            self.source_revision,
            self.registered_at,
            self.registered_by,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def strategy_version_id(self) -> str:
        return self.semantic_sha256


@dataclass(frozen=True, slots=True, init=False)
class StrategyConfigurationRecord:
    """Bounded canonical parameters for one exact strategy version."""

    strategy_version_sha256: str
    configuration_name: str
    registered_at: datetime
    registered_by: str
    _parameters: tuple[tuple[str, ConfigurationValue], ...]
    configuration_sha256: str

    def __init__(
        self,
        *,
        strategy_version_sha256: str,
        configuration_name: str,
        parameters: Mapping[str, object],
        registered_at: datetime,
        registered_by: str,
    ) -> None:
        _require_sha256(strategy_version_sha256, "strategy version digest")
        _require_text(configuration_name, "strategy configuration name")
        _require_utc(registered_at, "strategy configuration registered_at")
        _require_text(registered_by, "strategy configuration registrar")
        if not isinstance(parameters, Mapping):
            raise ValueError("strategy configuration parameters must be a mapping")
        if len(parameters) > MAX_CONFIGURATION_FIELDS:
            raise ValueError("strategy configuration exceeds its field-count limit")
        normalized: list[tuple[str, ConfigurationValue]] = []
        for key, value in parameters.items():
            _require_text(key, "strategy configuration key")
            normalized.append((key, _configuration_value(value)))
        canonical_parameters = tuple(sorted(normalized))
        if len({key for key, _ in canonical_parameters}) != len(canonical_parameters):
            raise ValueError("strategy configuration keys must be unique")
        if len(canonical_json_bytes(canonical_parameters)) > MAX_CONFIGURATION_BYTES:
            raise ValueError("strategy configuration exceeds its encoded payload limit")
        material = (
            EXPERIMENT_REGISTRY_CONTRACT_VERSION,
            "strategy_configuration",
            strategy_version_sha256,
            configuration_name,
            canonical_parameters,
            registered_at,
            registered_by,
        )
        object.__setattr__(self, "strategy_version_sha256", strategy_version_sha256)
        object.__setattr__(self, "configuration_name", configuration_name)
        object.__setattr__(self, "registered_at", registered_at)
        object.__setattr__(self, "registered_by", registered_by)
        object.__setattr__(self, "_parameters", canonical_parameters)
        object.__setattr__(self, "configuration_sha256", _sha256(material))

    @property
    def parameters(self) -> Mapping[str, ConfigurationValue]:
        return MappingProxyType(dict(self._parameters))

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            EXPERIMENT_REGISTRY_CONTRACT_VERSION,
            "strategy_configuration",
            self.strategy_version_sha256,
            self.configuration_name,
            self._parameters,
            self.registered_at,
            self.registered_by,
        )

    @property
    def semantic_sha256(self) -> str:
        return self.configuration_sha256

    @property
    def configuration_id(self) -> str:
        return self.configuration_sha256


@dataclass(frozen=True, slots=True)
class ExperimentDatasetReplayPin:
    """Fixture-only dataset and sealed replay proof available to the family."""

    source_id: str
    source_kind: FixtureSourceKind
    price_basis: str
    dataset_manifest_sha256: str
    source_tape_sha256: str
    replay_run_id: str
    replay_manifest_sha256: str
    replay_input_sha256: str
    replay_semantic_sha256: str
    coverage_start: datetime
    coverage_end: datetime
    replay_completed_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.source_id, "experiment dataset source ID")
        if type(self.source_kind) is not FixtureSourceKind:
            raise ValueError("experiment datasets must use an exact fixture source kind")
        if type(self.price_basis) is not str or self.price_basis != "raw":
            raise ValueError("experiment datasets must use raw prices")
        for value, field_name in (
            (self.dataset_manifest_sha256, "dataset manifest digest"),
            (self.source_tape_sha256, "source tape digest"),
            (self.replay_run_id, "replay run ID"),
            (self.replay_manifest_sha256, "replay manifest digest"),
            (self.replay_input_sha256, "replay input digest"),
            (self.replay_semantic_sha256, "replay semantic digest"),
        ):
            _require_sha256(value, field_name)
        if self.replay_run_id != self.replay_manifest_sha256:
            raise ValueError("replay run ID must equal its content-addressed manifest digest")
        _require_utc(self.coverage_start, "dataset coverage_start")
        _require_utc(self.coverage_end, "dataset coverage_end")
        _require_utc(self.replay_completed_at, "dataset replay_completed_at")
        if self.coverage_end <= self.coverage_start:
            raise ValueError("dataset coverage_end must follow coverage_start")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            EXPERIMENT_REGISTRY_CONTRACT_VERSION,
            "dataset_replay_pin",
            self.source_id,
            self.source_kind.value,
            self.price_basis,
            self.dataset_manifest_sha256,
            self.source_tape_sha256,
            self.replay_run_id,
            self.replay_manifest_sha256,
            self.replay_input_sha256,
            self.replay_semantic_sha256,
            self.coverage_start,
            self.coverage_end,
            self.replay_completed_at,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


@dataclass(frozen=True, slots=True)
class EvaluationSegment:
    """One chronological evaluation segment with explicit leakage controls."""

    kind: EvaluationSegmentKind
    coverage_start: datetime
    coverage_end: datetime
    dataset_replay_sha256: str
    purge_before: timedelta = timedelta(0)
    embargo_after: timedelta = timedelta(0)

    def __post_init__(self) -> None:
        if type(self.kind) is not EvaluationSegmentKind:
            raise ValueError("evaluation segment kind must be exact")
        _require_utc(self.coverage_start, "segment coverage_start")
        _require_utc(self.coverage_end, "segment coverage_end")
        if self.coverage_end <= self.coverage_start:
            raise ValueError("segment coverage_end must follow coverage_start")
        _require_sha256(self.dataset_replay_sha256, "segment dataset replay digest")
        for field_name in ("purge_before", "embargo_after"):
            value = getattr(self, field_name)
            if type(value) is not timedelta or value < timedelta(0):
                raise ValueError(f"{field_name} must be a non-negative exact timedelta")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            EXPERIMENT_REGISTRY_CONTRACT_VERSION,
            "evaluation_segment",
            self.kind.value,
            self.coverage_start,
            self.coverage_end,
            self.dataset_replay_sha256,
            _duration_microseconds(self.purge_before),
            _duration_microseconds(self.embargo_after),
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


@dataclass(frozen=True, slots=True)
class ExperimentEvaluationPlan:
    """One explicit chronological train/validation/final-test declaration."""

    plan_version: str
    segments: tuple[EvaluationSegment, ...]

    def __post_init__(self) -> None:
        _require_text(self.plan_version, "evaluation plan version")
        if type(self.segments) is not tuple or any(
            type(segment) is not EvaluationSegment for segment in self.segments
        ):
            raise ValueError("evaluation plan segments must be immutable exact values")
        expected_kinds = (
            EvaluationSegmentKind.TRAIN,
            EvaluationSegmentKind.VALIDATION,
            EvaluationSegmentKind.TEST,
        )
        if tuple(segment.kind for segment in self.segments) != expected_kinds:
            raise ValueError("evaluation plan must declare ordered train, validation, and test")
        if len({segment.dataset_replay_sha256 for segment in self.segments}) != 1:
            raise ValueError("evaluation segments must share one dataset replay pin")
        train, validation, test = self.segments
        if train.coverage_end >= validation.coverage_start:
            raise ValueError("training and validation segments must not overlap")
        if validation.coverage_end >= test.coverage_start:
            raise ValueError("validation and final test segments must not overlap")

    @property
    def train(self) -> EvaluationSegment:
        return self.segments[0]

    @property
    def validation(self) -> EvaluationSegment:
        return self.segments[1]

    @property
    def test(self) -> EvaluationSegment:
        return self.segments[2]

    def segment(self, kind: EvaluationSegmentKind) -> EvaluationSegment:
        if type(kind) is not EvaluationSegmentKind:
            raise ValueError("evaluation segment lookup kind must be exact")
        return self.segments[
            {
                EvaluationSegmentKind.TRAIN: 0,
                EvaluationSegmentKind.VALIDATION: 1,
                EvaluationSegmentKind.TEST: 2,
            }[kind]
        ]

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            EXPERIMENT_REGISTRY_CONTRACT_VERSION,
            "evaluation_plan",
            self.plan_version,
            tuple(segment.semantic_sha256 for segment in self.segments),
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


@dataclass(frozen=True, slots=True)
class PromotionCriterion:
    """One exact final-test metric threshold."""

    metric_name: str
    comparison: PromotionComparison
    threshold: Decimal
    minimum_observations: int

    def __post_init__(self) -> None:
        _require_text(self.metric_name, "promotion metric name")
        if type(self.comparison) is not PromotionComparison:
            raise ValueError("promotion comparison must be exact")
        if type(self.threshold) is not Decimal:
            raise ValueError("promotion threshold must be an exact Decimal")
        object.__setattr__(
            self,
            "threshold",
            canonical_persisted_decimal(self.threshold, "promotion threshold"),
        )
        if type(self.minimum_observations) is not int or self.minimum_observations <= 0:
            raise ValueError("minimum_observations must be a positive integer")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            EXPERIMENT_REGISTRY_CONTRACT_VERSION,
            "promotion_criterion",
            self.metric_name,
            self.comparison.value,
            self.threshold,
            self.minimum_observations,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


@dataclass(frozen=True, slots=True)
class FrozenPromotionCriteria:
    """Human-declared promotion gate sealed before final-holdout access."""

    criteria_version: str
    criteria: tuple[PromotionCriterion, ...]
    selection_rule: str
    multiple_testing_method: str
    maximum_pre_holdout_trials: int
    frozen_at: datetime
    frozen_by: str

    def __post_init__(self) -> None:
        _require_text(self.criteria_version, "promotion criteria version")
        if (
            type(self.criteria) is not tuple
            or not self.criteria
            or any(type(criterion) is not PromotionCriterion for criterion in self.criteria)
        ):
            raise ValueError("promotion criteria must be a non-empty immutable tuple")
        keys = tuple(
            (criterion.metric_name, criterion.comparison.value) for criterion in self.criteria
        )
        if keys != tuple(sorted(set(keys))):
            raise ValueError("promotion criteria must be unique and canonically ordered")
        _require_text(self.selection_rule, "promotion selection rule", maximum=1024)
        _require_text(self.multiple_testing_method, "multiple-testing method")
        if type(self.maximum_pre_holdout_trials) is not int or self.maximum_pre_holdout_trials <= 0:
            raise ValueError("maximum_pre_holdout_trials must be a positive integer")
        _require_utc(self.frozen_at, "promotion criteria frozen_at")
        _require_text(self.frozen_by, "promotion criteria freezer")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            EXPERIMENT_REGISTRY_CONTRACT_VERSION,
            "frozen_promotion_criteria",
            self.criteria_version,
            tuple(criterion.semantic_sha256 for criterion in self.criteria),
            self.selection_rule,
            self.multiple_testing_method,
            self.maximum_pre_holdout_trials,
            self.frozen_at,
            self.frozen_by,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


@dataclass(frozen=True, slots=True)
class ExperimentFamily:
    """Immutable hypothesis, inputs, split, and predeclared promotion gate."""

    family_name: str
    hypothesis: str
    owner_id: str
    created_at: datetime
    strategy_version: StrategyVersionRecord
    dataset_replay: ExperimentDatasetReplayPin
    evaluation_plan: ExperimentEvaluationPlan
    promotion_criteria: FrozenPromotionCriteria
    family_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _require_text(self.family_name, "experiment family name")
        _require_text(self.hypothesis, "experiment hypothesis", maximum=4096)
        _require_text(self.owner_id, "experiment owner ID")
        _require_utc(self.created_at, "experiment family created_at")
        if type(self.strategy_version) is not StrategyVersionRecord:
            raise ValueError("experiment family requires an exact strategy version")
        if type(self.dataset_replay) is not ExperimentDatasetReplayPin:
            raise ValueError("experiment family requires an exact dataset replay pin")
        if type(self.evaluation_plan) is not ExperimentEvaluationPlan:
            raise ValueError("experiment family requires an exact evaluation plan")
        if type(self.promotion_criteria) is not FrozenPromotionCriteria:
            raise ValueError("experiment family requires exact frozen promotion criteria")
        if self.strategy_version.registered_at > self.created_at:
            raise ValueError("strategy version must be registered before the experiment family")
        if self.dataset_replay.replay_completed_at > self.created_at:
            raise ValueError("dataset replay must complete before the experiment family is created")
        if self.promotion_criteria.frozen_at < self.created_at:
            raise ValueError("promotion criteria cannot be frozen before family creation")
        if any(
            segment.dataset_replay_sha256 != self.dataset_replay.semantic_sha256
            for segment in self.evaluation_plan.segments
        ):
            raise ValueError("evaluation plan must bind the family dataset replay pin")
        if any(
            segment.coverage_start < self.dataset_replay.coverage_start
            or segment.coverage_end > self.dataset_replay.coverage_end
            for segment in self.evaluation_plan.segments
        ):
            raise ValueError("evaluation segments must remain inside dataset coverage")
        object.__setattr__(self, "family_sha256", _sha256(self._semantic_material()))

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            EXPERIMENT_REGISTRY_CONTRACT_VERSION,
            "experiment_family",
            self.family_name,
            self.hypothesis,
            self.owner_id,
            self.created_at,
            self.strategy_version.semantic_sha256,
            self.dataset_replay.semantic_sha256,
            self.evaluation_plan.semantic_sha256,
            self.promotion_criteria.semantic_sha256,
        )

    @property
    def family_id(self) -> str:
        return self.family_sha256


@dataclass(frozen=True, slots=True)
class ExperimentTrial:
    """Current immutable lifecycle snapshot for one exact family attempt."""

    sequence: int
    attempt_number: int
    family_id: str
    configuration: StrategyConfigurationRecord
    segment_kind: EvaluationSegmentKind
    segment_sha256: str
    status: ExperimentTrialStatus
    requested_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    run_manifest_sha256: str | None
    terminal_reason_code: str | None = None
    terminal_reason_sha256: str | None = None
    holdout_reveal_sha256: str | None = None
    trial_id: str = field(init=False)
    trial_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence < 0:
            raise ValueError("trial sequence must be a non-negative integer")
        if type(self.attempt_number) is not int or self.attempt_number <= 0:
            raise ValueError("trial attempt_number must be a positive integer")
        _require_sha256(self.family_id, "trial family ID")
        if type(self.configuration) is not StrategyConfigurationRecord:
            raise ValueError("trial requires an exact strategy configuration")
        if type(self.segment_kind) is not EvaluationSegmentKind:
            raise ValueError("trial segment kind must be exact")
        _require_sha256(self.segment_sha256, "trial segment digest")
        if type(self.status) is not ExperimentTrialStatus:
            raise ValueError("trial status must be exact")
        _require_utc(self.requested_at, "trial requested_at")
        if self.started_at is not None:
            _require_utc(self.started_at, "trial started_at")
            if self.started_at < self.requested_at:
                raise ValueError("trial cannot start before it is requested")
        if self.finished_at is not None:
            _require_utc(self.finished_at, "trial finished_at")
            if self.finished_at < (self.started_at or self.requested_at):
                raise ValueError("trial cannot finish before it starts or is requested")
        _require_optional_sha256(self.run_manifest_sha256, "trial run manifest digest")
        _require_optional_sha256(self.terminal_reason_sha256, "trial terminal reason digest")
        _require_optional_sha256(self.holdout_reveal_sha256, "trial holdout reveal digest")
        self._validate_status()
        if self.segment_kind is EvaluationSegmentKind.TEST:
            if self.holdout_reveal_sha256 is None:
                raise ValueError("final-test trial requires holdout reveal evidence")
        elif self.holdout_reveal_sha256 is not None:
            raise ValueError("non-test trial cannot retain holdout reveal evidence")
        input_material = self._input_material()
        trial_id = _sha256(input_material)
        object.__setattr__(self, "trial_id", trial_id)
        object.__setattr__(
            self,
            "trial_sha256",
            _sha256((input_material, self._outcome_material())),
        )

    def _validate_status(self) -> None:
        if self.status is ExperimentTrialStatus.QUEUED:
            if any(
                value is not None
                for value in (
                    self.started_at,
                    self.finished_at,
                    self.run_manifest_sha256,
                    self.terminal_reason_code,
                    self.terminal_reason_sha256,
                )
            ):
                raise ValueError("queued trial cannot retain execution or terminal evidence")
            return
        if self.status is ExperimentTrialStatus.RUNNING:
            if self.started_at is None or any(
                value is not None
                for value in (
                    self.finished_at,
                    self.run_manifest_sha256,
                    self.terminal_reason_code,
                    self.terminal_reason_sha256,
                )
            ):
                raise ValueError("running trial requires only start evidence")
            return
        if self.finished_at is None:
            raise ValueError("terminal trial requires finished_at")
        if self.status is ExperimentTrialStatus.COMPLETED:
            if self.started_at is None or self.run_manifest_sha256 is None:
                raise ValueError("completed trial requires start and run manifest evidence")
            if self.terminal_reason_code is not None or self.terminal_reason_sha256 is not None:
                raise ValueError("completed trial cannot retain a terminal failure reason")
            return
        if self.terminal_reason_code is None or self.terminal_reason_sha256 is None:
            raise ValueError("unsuccessful terminal trial requires a reason code and digest")
        _require_text(self.terminal_reason_code, "trial terminal reason code")

    def _input_material(self) -> tuple[object, ...]:
        return (
            EXPERIMENT_REGISTRY_CONTRACT_VERSION,
            "trial_input",
            self.sequence,
            self.attempt_number,
            self.family_id,
            self.configuration.semantic_sha256,
            self.segment_kind.value,
            self.segment_sha256,
            self.requested_at,
            self.holdout_reveal_sha256,
        )

    def _outcome_material(self) -> tuple[object, ...]:
        return (
            "trial_outcome",
            self.status.value,
            self.started_at,
            self.finished_at,
            self.run_manifest_sha256,
            self.terminal_reason_code,
            self.terminal_reason_sha256,
        )

    @property
    def semantic_sha256(self) -> str:
        return self.trial_sha256


@dataclass(frozen=True, slots=True)
class HoldoutRevealRecord:
    """Audited final-test reveal bound to the exact pre-reveal registry."""

    family_id: str
    test_segment_sha256: str
    promotion_criteria_sha256: str
    selected_configuration_sha256: str
    pre_reveal_trial_count: int
    pre_reveal_trials_sha256: str
    revealed_at: datetime
    revealed_by: str
    access_reason: str
    authorization_sha256: str

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.family_id, "holdout reveal family ID"),
            (self.test_segment_sha256, "holdout test segment digest"),
            (self.promotion_criteria_sha256, "holdout promotion criteria digest"),
            (self.selected_configuration_sha256, "selected configuration digest"),
            (self.pre_reveal_trials_sha256, "pre-reveal trials digest"),
            (self.authorization_sha256, "holdout authorization digest"),
        ):
            _require_sha256(value, field_name)
        if type(self.pre_reveal_trial_count) is not int or self.pre_reveal_trial_count < 0:
            raise ValueError("pre_reveal_trial_count must be a non-negative integer")
        _require_utc(self.revealed_at, "holdout revealed_at")
        _require_text(self.revealed_by, "holdout revealer")
        _require_text(self.access_reason, "holdout access reason", maximum=1024)

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            EXPERIMENT_REGISTRY_CONTRACT_VERSION,
            "holdout_reveal",
            self.family_id,
            self.test_segment_sha256,
            self.promotion_criteria_sha256,
            self.selected_configuration_sha256,
            self.pre_reveal_trial_count,
            self.pre_reveal_trials_sha256,
            self.revealed_at,
            self.revealed_by,
            self.access_reason,
            self.authorization_sha256,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def reveal_id(self) -> str:
        return self.semantic_sha256


@dataclass(frozen=True, slots=True)
class ExperimentFamilyRegistry:
    """Canonical snapshot of every trial and optional final-holdout reveal."""

    family: ExperimentFamily
    trials: tuple[ExperimentTrial, ...]
    holdout_reveal: HoldoutRevealRecord | None = None
    registry_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.family) is not ExperimentFamily:
            raise ValueError("registry requires an exact experiment family")
        if type(self.trials) is not tuple or any(
            type(trial) is not ExperimentTrial for trial in self.trials
        ):
            raise ValueError("registry trials must be immutable exact values")
        if self.holdout_reveal is not None and type(self.holdout_reveal) is not HoldoutRevealRecord:
            raise ValueError("registry holdout reveal must be exact")
        if tuple(trial.sequence for trial in self.trials) != tuple(range(len(self.trials))):
            raise ValueError("registry trial sequences must be contiguous and ordered")
        trial_ids = tuple(trial.trial_id for trial in self.trials)
        if len(trial_ids) != len(set(trial_ids)):
            raise ValueError("registry trial identities must be unique")
        attempt_numbers = tuple(trial.attempt_number for trial in self.trials)
        if attempt_numbers != tuple(range(1, len(self.trials) + 1)):
            raise ValueError("registry attempt numbers must be contiguous and ordered")
        for trial in self.trials:
            self._validate_trial(trial)
        self._validate_holdout()
        object.__setattr__(self, "registry_sha256", _sha256(self._semantic_material()))

    def _validate_trial(self, trial: ExperimentTrial) -> None:
        if trial.family_id != self.family.family_id:
            raise ValueError("trial belongs to a different experiment family")
        segment = self.family.evaluation_plan.segment(trial.segment_kind)
        if trial.segment_sha256 != segment.semantic_sha256:
            raise ValueError("trial does not bind the declared evaluation segment")
        if (
            trial.configuration.strategy_version_sha256
            != self.family.strategy_version.semantic_sha256
        ):
            raise ValueError("trial configuration belongs to a different strategy version")
        if trial.configuration.registered_at > trial.requested_at:
            raise ValueError("trial configuration must be registered before the request")
        if trial.requested_at < self.family.created_at:
            raise ValueError("trial cannot be requested before family creation")
        if trial.requested_at < self.family.promotion_criteria.frozen_at:
            raise ValueError("trial cannot be requested before promotion criteria are frozen")

    def _validate_holdout(self) -> None:
        test_trials = tuple(
            trial for trial in self.trials if trial.segment_kind is EvaluationSegmentKind.TEST
        )
        if self.holdout_reveal is None:
            if test_trials:
                raise ValueError("final-test trials are forbidden before holdout reveal")
            if len(self.trials) > self.family.promotion_criteria.maximum_pre_holdout_trials:
                raise ValueError("pre-holdout trial budget is exhausted")
            return
        reveal = self.holdout_reveal
        if reveal.family_id != self.family.family_id:
            raise ValueError("holdout reveal belongs to a different experiment family")
        if reveal.test_segment_sha256 != self.family.evaluation_plan.test.semantic_sha256:
            raise ValueError("holdout reveal does not bind the final test segment")
        if reveal.promotion_criteria_sha256 != self.family.promotion_criteria.semantic_sha256:
            raise ValueError("holdout reveal does not bind the frozen promotion criteria")
        if self.family.promotion_criteria.frozen_at >= reveal.revealed_at:
            raise ValueError("promotion criteria must be frozen before holdout reveal")
        count = reveal.pre_reveal_trial_count
        if count > len(self.trials):
            raise ValueError("holdout reveal trial count exceeds the registry")
        pre_reveal_trials = self.trials[:count]
        post_reveal_trials = self.trials[count:]
        if any(trial.segment_kind is EvaluationSegmentKind.TEST for trial in pre_reveal_trials):
            raise ValueError("pre-reveal registry cannot contain final-test trials")
        if any(
            trial.segment_kind is not EvaluationSegmentKind.TEST for trial in post_reveal_trials
        ):
            raise ValueError("post-reveal registry cannot add exploratory trials")
        if any(trial.status not in _TERMINAL_TRIAL_STATUSES for trial in pre_reveal_trials):
            raise ValueError("holdout cannot be revealed while exploratory trials are active")
        if any(
            trial.finished_at is None or trial.finished_at > reveal.revealed_at
            for trial in pre_reveal_trials
        ):
            raise ValueError("pre-reveal trials must finish before holdout access")
        if len(pre_reveal_trials) > self.family.promotion_criteria.maximum_pre_holdout_trials:
            raise ValueError("pre-holdout trial budget is exhausted")
        selected_candidates = {trial.configuration.semantic_sha256 for trial in pre_reveal_trials}
        if reveal.selected_configuration_sha256 not in selected_candidates:
            raise ValueError(
                "holdout reveal must select a configuration from the exact pre-reveal trials"
            )
        expected_pre_reveal_sha256 = _sha256(
            tuple(trial.semantic_sha256 for trial in pre_reveal_trials)
        )
        if reveal.pre_reveal_trials_sha256 != expected_pre_reveal_sha256:
            raise ValueError("holdout reveal does not bind the exact pre-reveal trials")
        if len(post_reveal_trials) > 1:
            raise ValueError("final holdout permits only one selected-configuration trial")
        for trial in post_reveal_trials:
            if trial.requested_at < reveal.revealed_at:
                raise ValueError("final-test trial cannot be requested before holdout reveal")
            if trial.holdout_reveal_sha256 != reveal.semantic_sha256:
                raise ValueError("final-test trial does not bind the exact holdout reveal")
            if trial.configuration.semantic_sha256 != reveal.selected_configuration_sha256:
                raise ValueError(
                    "final-test trial must use the configuration selected before holdout reveal"
                )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            EXPERIMENT_REGISTRY_CONTRACT_VERSION,
            "experiment_family_registry",
            self.family.family_id,
            tuple(trial.semantic_sha256 for trial in self.trials),
            None if self.holdout_reveal is None else self.holdout_reveal.semantic_sha256,
        )

    @classmethod
    def empty(cls, family: ExperimentFamily) -> Self:
        return cls(family=family, trials=())

    def with_trial(self, trial: ExperimentTrial) -> Self:
        """Return a new snapshot with one newly attempted trial."""

        if type(trial) is not ExperimentTrial:
            raise ValueError("registry append requires an exact ExperimentTrial")
        return type(self)(
            family=self.family,
            trials=(*self.trials, trial),
            holdout_reveal=self.holdout_reveal,
        )

    def with_holdout_reveal(
        self,
        *,
        revealed_at: datetime,
        revealed_by: str,
        access_reason: str,
        authorization_sha256: str,
        selected_configuration_sha256: str,
    ) -> Self:
        """Seal an audited reveal against this exact pre-holdout snapshot."""

        if self.holdout_reveal is not None:
            raise ValueError("final holdout has already been revealed")
        if any(trial.status not in _TERMINAL_TRIAL_STATUSES for trial in self.trials):
            raise ValueError("holdout cannot be revealed while exploratory trials are active")
        reveal = HoldoutRevealRecord(
            family_id=self.family.family_id,
            test_segment_sha256=self.family.evaluation_plan.test.semantic_sha256,
            promotion_criteria_sha256=self.family.promotion_criteria.semantic_sha256,
            selected_configuration_sha256=selected_configuration_sha256,
            pre_reveal_trial_count=len(self.trials),
            pre_reveal_trials_sha256=_sha256(tuple(trial.semantic_sha256 for trial in self.trials)),
            revealed_at=revealed_at,
            revealed_by=revealed_by,
            access_reason=access_reason,
            authorization_sha256=authorization_sha256,
        )
        return type(self)(family=self.family, trials=self.trials, holdout_reveal=reveal)

    @property
    def family_id(self) -> str:
        return self.family.family_id

    @property
    def semantic_sha256(self) -> str:
        return self.registry_sha256

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())
