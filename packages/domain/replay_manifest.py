"""Immutable provenance for one successfully sealed deterministic replay.

This module deliberately performs no ambient discovery.  Callers must supply
source, dependency, runtime, and dataset pins explicitly; the resulting input
and run identities are derived only from those values and replay evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Self, cast

from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.decimal_math import DECIMAL_ARITHMETIC_VERSION
from packages.domain.market_batch import (
    MARKET_BATCH_CONTRACT_VERSION,
    LateEventPolicy,
    MissingDataPolicy,
    ReplayRevisionPolicy,
)
from packages.domain.replay import REPLAY_CONTRACT_VERSION, ReplayResult

REPLAY_RUN_MANIFEST_CONTRACT_VERSION = "phase2-replay-run-manifest-v1"
NOT_APPLICABLE = "not_applicable"
MAX_CANONICAL_MANIFEST_BYTES = 65_536
MAX_CANONICAL_NODE_DEPTH = 64

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_CANONICAL_INTEGER = re.compile(r"^(?:0|-[1-9][0-9]*|[1-9][0-9]*)$")
_ALLOWED_SOURCE_KINDS = frozenset({"synthetic_fixture", "recorded_fixture"})
_ALLOWED_INTERVALS = frozenset({"1m", "1d"})
_SCHEMA_PROVENANCE_CONTRACTS = {
    "raw-bar-v1": ("input-v1", "input-v1"),
    "raw-bar-v2": ("arrow-v2", "persisted-v2"),
}
_ALLOWED_SEMANTIC_CHECKSUM_VERSIONS = frozenset(
    version for version, _ in _SCHEMA_PROVENANCE_CONTRACTS.values()
)
_ALLOWED_REFERENCE_HASH_VERSIONS = frozenset(
    version for _, version in _SCHEMA_PROVENANCE_CONTRACTS.values()
)


class ReplayManifestDecodeError(ValueError):
    """Persisted replay-manifest bytes do not satisfy the exact v1 contract."""


def _require_text(value: str, field_name: str, *, maximum: int = 128) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"{field_name} must be non-empty and trimmed")
    if len(value) > maximum or any(ord(character) < 32 for character in value):
        raise ValueError(f"{field_name} contains unsupported text")


def _require_digest(value: str, field_name: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_utc(value: datetime, field_name: str) -> None:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{field_name} must be UTC")


def _require_nonnegative_integer(value: int, field_name: str) -> None:
    if type(value) is not int or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")


def _timedelta_microseconds(value: timedelta) -> int:
    return value.days * 86_400_000_000 + value.seconds * 1_000_000 + value.microseconds


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class DatasetPartitionPin:
    """One ordered normalized partition and both of its content identities."""

    ordinal: int
    partition_id: str
    object_id: str
    object_key: str
    format: str
    byte_sha256: str
    semantic_sha256: str
    semantic_checksum_version: str
    size_bytes: int
    row_count: int
    event_time_start: datetime
    event_time_end: datetime
    available_at_start: datetime
    available_at_end: datetime

    def __post_init__(self) -> None:
        _require_nonnegative_integer(self.ordinal, "partition ordinal")
        _require_digest(self.partition_id, "partition_id")
        _require_digest(self.object_id, "object_id")
        _require_digest(self.byte_sha256, "byte_sha256")
        _require_digest(self.semantic_sha256, "semantic_sha256")
        if (
            type(self.semantic_checksum_version) is not str
            or self.semantic_checksum_version not in _ALLOWED_SEMANTIC_CHECKSUM_VERSIONS
        ):
            raise ValueError("partition semantic_checksum_version is unsupported")
        if self.object_id != self.byte_sha256:
            raise ValueError("content-addressed object_id must equal byte_sha256")
        expected_object_key = f"normalized/sha256/{self.byte_sha256[:2]}/{self.byte_sha256}.parquet"
        if type(self.object_key) is not str or self.object_key != expected_object_key:
            raise ValueError("object_key must be the canonical normalized content address")
        if type(self.format) is not str or self.format != "parquet":
            raise ValueError("partition object format must be parquet")
        if type(self.size_bytes) is not int or self.size_bytes <= 0:
            raise ValueError("partition size_bytes must be a positive integer")
        if type(self.row_count) is not int or self.row_count <= 0:
            raise ValueError("partition row_count must be a positive integer")
        for value, field_name in (
            (self.event_time_start, "partition event_time_start"),
            (self.event_time_end, "partition event_time_end"),
            (self.available_at_start, "partition available_at_start"),
            (self.available_at_end, "partition available_at_end"),
        ):
            _require_utc(value, field_name)
        if self.event_time_end < self.event_time_start:
            raise ValueError("partition event-time range is inverted")
        if self.available_at_end < self.available_at_start:
            raise ValueError("partition availability range is inverted")

    def _semantic_material(self) -> dict[str, object]:
        return {
            "available_at_end": self.available_at_end,
            "available_at_start": self.available_at_start,
            "byte_sha256": self.byte_sha256,
            "event_time_end": self.event_time_end,
            "event_time_start": self.event_time_start,
            "format": self.format,
            "object_id": self.object_id,
            "object_key": self.object_key,
            "ordinal": self.ordinal,
            "partition_id": self.partition_id,
            "row_count": self.row_count,
            "semantic_sha256": self.semantic_sha256,
            "semantic_checksum_version": self.semantic_checksum_version,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True, slots=True)
class DatasetPin:
    """The exact immutable catalog and object facts consumed by replay."""

    manifest_id: str
    manifest_sha256: str
    source_tape_sha256: str
    source_id: str
    source_kind: str
    schema_version: str
    price_basis: str
    revision_policy: ReplayRevisionPolicy
    calendar_version: str
    calendar_sha256: str
    calendar_hash_version: str
    tzdata_version: str
    universe_version: str
    universe_sha256: str
    universe_hash_version: str
    corporate_action_version: str
    corporate_action_sha256: str
    corporate_action_hash_version: str
    row_count: int
    partitions: tuple[DatasetPartitionPin, ...]

    def __post_init__(self) -> None:
        _require_digest(self.manifest_id, "manifest_id")
        _require_digest(self.manifest_sha256, "manifest_sha256")
        if self.manifest_id != self.manifest_sha256:
            raise ValueError("content-addressed manifest_id must equal manifest_sha256")
        _require_digest(self.source_tape_sha256, "source_tape_sha256")
        for value, field_name in (
            (self.source_id, "source_id"),
            (self.schema_version, "schema_version"),
            (self.calendar_version, "calendar_version"),
            (self.tzdata_version, "tzdata_version"),
            (self.universe_version, "universe_version"),
            (self.corporate_action_version, "corporate_action_version"),
        ):
            _require_text(value, field_name)
        if type(self.source_kind) is not str or self.source_kind not in _ALLOWED_SOURCE_KINDS:
            raise ValueError("Phase 2A replay requires a repository-owned fixture source")
        if type(self.price_basis) is not str or self.price_basis != "raw":
            raise ValueError("Phase 2A replay requires raw prices")
        if not isinstance(self.revision_policy, ReplayRevisionPolicy):
            raise ValueError("dataset revision_policy is unsupported")
        _require_digest(self.calendar_sha256, "calendar_sha256")
        _require_digest(self.universe_sha256, "universe_sha256")
        _require_digest(self.corporate_action_sha256, "corporate_action_sha256")
        for value, field_name in (
            (self.calendar_hash_version, "calendar_hash_version"),
            (self.universe_hash_version, "universe_hash_version"),
            (self.corporate_action_hash_version, "corporate_action_hash_version"),
        ):
            if type(value) is not str or value not in _ALLOWED_REFERENCE_HASH_VERSIONS:
                raise ValueError(f"{field_name} is unsupported")
        if type(self.row_count) is not int or self.row_count <= 0:
            raise ValueError("dataset row_count must be a positive integer")
        if type(self.partitions) is not tuple or not self.partitions:
            raise ValueError("dataset partitions must be a non-empty immutable tuple")
        if any(type(partition) is not DatasetPartitionPin for partition in self.partitions):
            raise ValueError("dataset partitions must contain immutable DatasetPartitionPin values")
        provenance_contract = _SCHEMA_PROVENANCE_CONTRACTS.get(self.schema_version)
        if provenance_contract is None:
            raise ValueError("dataset schema_version has no replay provenance contract")
        semantic_version, reference_version = provenance_contract
        if any(
            partition.semantic_checksum_version != semantic_version for partition in self.partitions
        ):
            raise ValueError("partition checksum versions must match the dataset schema contract")
        if {
            self.calendar_hash_version,
            self.universe_hash_version,
            self.corporate_action_hash_version,
        } != {reference_version}:
            raise ValueError("reference hash versions must match the dataset schema contract")
        expected_ordinals = tuple(range(len(self.partitions)))
        actual_ordinals = tuple(partition.ordinal for partition in self.partitions)
        if actual_ordinals != expected_ordinals:
            raise ValueError("dataset partition ordinals must be contiguous and ordered")
        partition_ids = tuple(partition.partition_id for partition in self.partitions)
        if len(partition_ids) != len(set(partition_ids)):
            raise ValueError("dataset partitions must be unique")
        if sum(partition.row_count for partition in self.partitions) != self.row_count:
            raise ValueError("dataset row_count must equal the ordered partition total")

    def _semantic_material(self) -> dict[str, object]:
        return {
            "calendar_sha256": self.calendar_sha256,
            "calendar_hash_version": self.calendar_hash_version,
            "calendar_version": self.calendar_version,
            "corporate_action_sha256": self.corporate_action_sha256,
            "corporate_action_hash_version": self.corporate_action_hash_version,
            "corporate_action_version": self.corporate_action_version,
            "manifest_id": self.manifest_id,
            "manifest_sha256": self.manifest_sha256,
            "partitions": tuple(partition._semantic_material() for partition in self.partitions),
            "price_basis": self.price_basis,
            "revision_policy": self.revision_policy.value,
            "row_count": self.row_count,
            "schema_version": self.schema_version,
            "source_id": self.source_id,
            "source_kind": self.source_kind,
            "source_tape_sha256": self.source_tape_sha256,
            "tzdata_version": self.tzdata_version,
            "universe_sha256": self.universe_sha256,
            "universe_hash_version": self.universe_hash_version,
            "universe_version": self.universe_version,
        }


@dataclass(frozen=True, slots=True)
class ReplayPlanPin:
    """The exact event-time scope and deterministic watermark policy."""

    coverage_start: datetime
    coverage_end: datetime
    interval: str
    decision_lag: timedelta
    revision_policy: ReplayRevisionPolicy
    missing_data_policy: MissingDataPolicy
    late_event_policy: LateEventPolicy
    expected_instrument_ids: tuple[str, ...]
    watermark_count: int
    watermarks_sha256: str

    def __post_init__(self) -> None:
        _require_utc(self.coverage_start, "coverage_start")
        _require_utc(self.coverage_end, "coverage_end")
        if self.coverage_end < self.coverage_start:
            raise ValueError("coverage_end cannot precede coverage_start")
        if type(self.interval) is not str or self.interval not in _ALLOWED_INTERVALS:
            raise ValueError("replay interval is unsupported")
        if type(self.decision_lag) is not timedelta or self.decision_lag < timedelta(0):
            raise ValueError("decision_lag must be a non-negative timedelta")
        if not isinstance(self.revision_policy, ReplayRevisionPolicy):
            raise ValueError("replay revision_policy is unsupported")
        if self.missing_data_policy is not MissingDataPolicy.SKIP:
            raise ValueError("replay missing-data policy must be skip")
        if self.late_event_policy is not LateEventPolicy.HALT:
            raise ValueError("replay late-event policy must be halt")
        if type(self.expected_instrument_ids) is not tuple or not self.expected_instrument_ids:
            raise ValueError("expected instruments must be a non-empty immutable tuple")
        if self.expected_instrument_ids != tuple(sorted(set(self.expected_instrument_ids))):
            raise ValueError("expected instruments must be unique and sorted")
        for instrument_id in self.expected_instrument_ids:
            _require_text(instrument_id, "expected instrument_id")
        if type(self.watermark_count) is not int or self.watermark_count <= 0:
            raise ValueError("watermark_count must be a positive integer")
        _require_digest(self.watermarks_sha256, "watermarks_sha256")

    def _semantic_material(self) -> dict[str, object]:
        return {
            "coverage_end": self.coverage_end,
            "coverage_start": self.coverage_start,
            "decision_lag_microseconds": _timedelta_microseconds(self.decision_lag),
            "expected_instrument_ids": self.expected_instrument_ids,
            "interval": self.interval,
            "late_event_policy": self.late_event_policy.value,
            "missing_data_policy": self.missing_data_policy.value,
            "revision_policy": self.revision_policy.value,
            "watermark_count": self.watermark_count,
            "watermarks_sha256": self.watermarks_sha256,
        }


@dataclass(frozen=True, slots=True)
class EnginePin:
    """Versions that define conversion, ordering, batching, and arithmetic."""

    tape_adapter_version: str
    watermark_policy_version: str
    replay_contract_version: str = REPLAY_CONTRACT_VERSION
    market_batch_contract_version: str = MARKET_BATCH_CONTRACT_VERSION
    decimal_arithmetic_version: str = DECIMAL_ARITHMETIC_VERSION

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.tape_adapter_version, "tape_adapter_version"),
            (self.watermark_policy_version, "watermark_policy_version"),
            (self.replay_contract_version, "replay_contract_version"),
            (self.market_batch_contract_version, "market_batch_contract_version"),
            (self.decimal_arithmetic_version, "decimal_arithmetic_version"),
        ):
            _require_text(value, field_name)

    def _semantic_material(self) -> dict[str, object]:
        return {
            "decimal_arithmetic_version": self.decimal_arithmetic_version,
            "market_batch_contract_version": self.market_batch_contract_version,
            "replay_contract_version": self.replay_contract_version,
            "tape_adapter_version": self.tape_adapter_version,
            "watermark_policy_version": self.watermark_policy_version,
        }


@dataclass(frozen=True, slots=True)
class RuntimePin:
    """Explicit local-runtime provenance; no values are discovered implicitly."""

    source_revision: str
    dirty_patch_sha256: str
    dependency_lock_sha256: str
    schema_revision: str
    python_version: str
    pyarrow_version: str
    strategy_version: str = NOT_APPLICABLE
    cost_model_version: str = NOT_APPLICABLE
    fill_model_version: str = NOT_APPLICABLE
    benchmark_version: str = NOT_APPLICABLE
    rng_algorithm: str = NOT_APPLICABLE
    rng_seed: None = None

    def __post_init__(self) -> None:
        if (
            type(self.source_revision) is not str
            or _SOURCE_REVISION.fullmatch(self.source_revision) is None
        ):
            raise ValueError("source_revision must be a lowercase source commit digest")
        _require_digest(self.dirty_patch_sha256, "dirty_patch_sha256")
        _require_digest(self.dependency_lock_sha256, "dependency_lock_sha256")
        for value, field_name in (
            (self.schema_revision, "schema_revision"),
            (self.python_version, "python_version"),
            (self.pyarrow_version, "pyarrow_version"),
        ):
            _require_text(value, field_name)
        for value, field_name in (
            (self.strategy_version, "strategy_version"),
            (self.cost_model_version, "cost_model_version"),
            (self.fill_model_version, "fill_model_version"),
            (self.benchmark_version, "benchmark_version"),
            (self.rng_algorithm, "rng_algorithm"),
        ):
            if type(value) is not str or value != NOT_APPLICABLE:
                raise ValueError(f"{field_name} must be explicitly not_applicable")
        if self.rng_seed is not None:
            raise ValueError("rng_seed must be None when RNG is not applicable")

    def _semantic_material(self) -> dict[str, object]:
        return {
            "benchmark_version": self.benchmark_version,
            "cost_model_version": self.cost_model_version,
            "dependency_lock_sha256": self.dependency_lock_sha256,
            "dirty_patch_sha256": self.dirty_patch_sha256,
            "fill_model_version": self.fill_model_version,
            "pyarrow_version": self.pyarrow_version,
            "python_version": self.python_version,
            "rng_algorithm": self.rng_algorithm,
            "rng_seed": self.rng_seed,
            "schema_revision": self.schema_revision,
            "source_revision": self.source_revision,
            "strategy_version": self.strategy_version,
        }

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


@dataclass(frozen=True, slots=True)
class ReplayRunManifest:
    """A self-authenticating record of one successfully completed replay."""

    dataset: DatasetPin
    plan: ReplayPlanPin
    engine: EnginePin
    runtime: RuntimePin
    started_at: datetime
    completed_at: datetime
    tape_sha256: str
    replay_semantic_sha256: str
    processed_event_count: int
    batch_count: int
    complete_batch_count: int
    skipped_batch_count: int
    input_sha256: str = field(init=False)
    manifest_sha256: str = field(init=False)
    run_id: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.dataset) is not DatasetPin:
            raise ValueError("dataset must be an immutable DatasetPin")
        if type(self.plan) is not ReplayPlanPin:
            raise ValueError("plan must be an immutable ReplayPlanPin")
        if type(self.engine) is not EnginePin:
            raise ValueError("engine must be an immutable EnginePin")
        if type(self.runtime) is not RuntimePin:
            raise ValueError("runtime must be an immutable RuntimePin")
        if self.plan.revision_policy is not self.dataset.revision_policy:
            raise ValueError("replay revision policy must match the dataset manifest")
        _require_utc(self.started_at, "started_at")
        _require_utc(self.completed_at, "completed_at")
        if self.completed_at < self.started_at:
            raise ValueError("completed_at cannot precede started_at")
        _require_digest(self.tape_sha256, "tape_sha256")
        _require_digest(self.replay_semantic_sha256, "replay_semantic_sha256")
        _require_nonnegative_integer(self.processed_event_count, "processed_event_count")
        if type(self.batch_count) is not int or self.batch_count <= 0:
            raise ValueError("batch_count must be a positive integer")
        _require_nonnegative_integer(self.complete_batch_count, "complete_batch_count")
        _require_nonnegative_integer(self.skipped_batch_count, "skipped_batch_count")
        if self.complete_batch_count + self.skipped_batch_count != self.batch_count:
            raise ValueError("complete and skipped batch counts must cover every batch")
        if self.batch_count != self.plan.watermark_count:
            raise ValueError("batch_count must match the pinned watermark_count")

        input_sha256 = _sha256(self._input_material())
        object.__setattr__(self, "input_sha256", input_sha256)
        payload = canonical_json_text(self._manifest_material())
        if len(payload.encode("utf-8")) > MAX_CANONICAL_MANIFEST_BYTES:
            raise ValueError("canonical replay manifest exceeds its size limit")
        manifest_sha256 = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        object.__setattr__(self, "manifest_sha256", manifest_sha256)
        object.__setattr__(self, "run_id", manifest_sha256)

    @classmethod
    def from_replay_result(
        cls,
        *,
        dataset: DatasetPin,
        plan: ReplayPlanPin,
        engine: EnginePin,
        runtime: RuntimePin,
        result: ReplayResult,
        source_tape_sha256: str,
    ) -> Self:
        """Seal trusted pins and exact reducer evidence after successful replay."""

        if type(result) is not ReplayResult:
            raise ValueError("result must be an immutable ReplayResult")
        _require_digest(source_tape_sha256, "source_tape_sha256")
        if source_tape_sha256 != dataset.source_tape_sha256:
            raise ValueError("source_tape_sha256 must match the immutable dataset pin")
        processed_event_ids = set(result.processed_event_ids)
        if len(result.processed_event_ids) != len(processed_event_ids):
            raise ValueError("ReplayResult processed event identities must be unique")
        if any(
            event.event_id not in processed_event_ids
            for batch in result.batches
            for event in batch.events
        ):
            raise ValueError("ReplayResult batch event evidence is inconsistent")
        expected_complete = tuple(batch.batch_id for batch in result.batches if batch.complete)
        expected_skipped = tuple(batch.batch_id for batch in result.batches if not batch.complete)
        if result.complete_batch_ids != expected_complete:
            raise ValueError("ReplayResult complete batch evidence is inconsistent")
        if result.skipped_batch_ids != expected_skipped:
            raise ValueError("ReplayResult skipped batch evidence is inconsistent")
        return cls(
            dataset=dataset,
            plan=plan,
            engine=engine,
            runtime=runtime,
            started_at=result.started_at,
            completed_at=result.completed_at,
            tape_sha256=result.tape_sha256,
            replay_semantic_sha256=result.semantic_sha256,
            processed_event_count=len(result.processed_event_ids),
            batch_count=len(result.batches),
            complete_batch_count=len(result.complete_batch_ids),
            skipped_batch_count=len(result.skipped_batch_ids),
        )

    def _input_material(self) -> dict[str, object]:
        return {
            "contract_version": REPLAY_RUN_MANIFEST_CONTRACT_VERSION,
            "dataset": self.dataset._semantic_material(),
            "engine": self.engine._semantic_material(),
            "plan": self.plan._semantic_material(),
            "runtime": self.runtime._semantic_material(),
        }

    def _result_material(self) -> dict[str, object]:
        return {
            "batch_count": self.batch_count,
            "complete_batch_count": self.complete_batch_count,
            "completed_at": self.completed_at,
            "processed_event_count": self.processed_event_count,
            "replay_semantic_sha256": self.replay_semantic_sha256,
            "skipped_batch_count": self.skipped_batch_count,
            "started_at": self.started_at,
            "tape_sha256": self.tape_sha256,
        }

    def _manifest_material(self) -> dict[str, object]:
        return {
            "contract_version": REPLAY_RUN_MANIFEST_CONTRACT_VERSION,
            "input": self._input_material(),
            "input_sha256": self.input_sha256,
            "outcome": "completed",
            "result": self._result_material(),
        }

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._manifest_material())

    @property
    def idempotency_key(self) -> str:
        """Return the identity shared by retries of the exact pinned input."""

        return self.input_sha256

    @classmethod
    def from_canonical_json(
        cls,
        payload: str,
        *,
        expected_run_id: str | None = None,
        expected_manifest_sha256: str | None = None,
    ) -> Self:
        """Strictly decode, revalidate, and re-canonicalize persisted bytes."""

        if type(payload) is not str or not payload:
            raise ReplayManifestDecodeError("replay manifest payload must be non-empty text")
        if len(payload.encode("utf-8")) > MAX_CANONICAL_MANIFEST_BYTES:
            raise ReplayManifestDecodeError("replay manifest payload exceeds its size limit")
        try:
            root = _expect_mapping(_decode_canonical_typed_json(payload), "manifest")
            _require_keys(
                root,
                {"contract_version", "input", "input_sha256", "outcome", "result"},
                "manifest",
            )
            if _expect_string(root["contract_version"], "contract_version") != (
                REPLAY_RUN_MANIFEST_CONTRACT_VERSION
            ):
                raise ReplayManifestDecodeError("unsupported replay manifest contract version")
            if _expect_string(root["outcome"], "outcome") != "completed":
                raise ReplayManifestDecodeError("replay manifest outcome must be completed")
            input_values = _expect_mapping(root["input"], "input")
            _require_keys(
                input_values,
                {"contract_version", "dataset", "engine", "plan", "runtime"},
                "input",
            )
            if _expect_string(input_values["contract_version"], "input.contract_version") != (
                REPLAY_RUN_MANIFEST_CONTRACT_VERSION
            ):
                raise ReplayManifestDecodeError("input contract version is inconsistent")
            dataset = _decode_dataset(input_values["dataset"])
            engine = _decode_engine(input_values["engine"])
            plan = _decode_plan(input_values["plan"])
            runtime = _decode_runtime(input_values["runtime"])
            result_values = _expect_mapping(root["result"], "result")
            _require_keys(
                result_values,
                {
                    "batch_count",
                    "complete_batch_count",
                    "completed_at",
                    "processed_event_count",
                    "replay_semantic_sha256",
                    "skipped_batch_count",
                    "started_at",
                    "tape_sha256",
                },
                "result",
            )
            manifest = cls(
                dataset=dataset,
                plan=plan,
                engine=engine,
                runtime=runtime,
                started_at=_expect_datetime(result_values["started_at"], "started_at"),
                completed_at=_expect_datetime(result_values["completed_at"], "completed_at"),
                tape_sha256=_expect_string(result_values["tape_sha256"], "tape_sha256"),
                replay_semantic_sha256=_expect_string(
                    result_values["replay_semantic_sha256"],
                    "replay_semantic_sha256",
                ),
                processed_event_count=_expect_integer(
                    result_values["processed_event_count"],
                    "processed_event_count",
                ),
                batch_count=_expect_integer(result_values["batch_count"], "batch_count"),
                complete_batch_count=_expect_integer(
                    result_values["complete_batch_count"],
                    "complete_batch_count",
                ),
                skipped_batch_count=_expect_integer(
                    result_values["skipped_batch_count"],
                    "skipped_batch_count",
                ),
            )
            declared_input_sha256 = _expect_string(root["input_sha256"], "input_sha256")
            _require_digest(declared_input_sha256, "input_sha256")
            if manifest.input_sha256 != declared_input_sha256:
                raise ReplayManifestDecodeError("replay manifest input digest is inconsistent")
            if manifest.canonical_json != payload:
                raise ReplayManifestDecodeError("replay manifest payload is not canonical")
            if expected_run_id is not None:
                _require_digest(expected_run_id, "expected_run_id")
                if manifest.run_id != expected_run_id:
                    raise ReplayManifestDecodeError("replay manifest run identity is inconsistent")
            if expected_manifest_sha256 is not None:
                _require_digest(expected_manifest_sha256, "expected_manifest_sha256")
                if manifest.manifest_sha256 != expected_manifest_sha256:
                    raise ReplayManifestDecodeError("replay manifest digest is inconsistent")
            return manifest
        except ReplayManifestDecodeError:
            raise
        except (TypeError, ValueError, OverflowError) as error:
            raise ReplayManifestDecodeError("replay manifest payload is malformed") from error


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReplayManifestDecodeError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _decode_canonical_typed_json(payload: str) -> object:
    try:
        parsed = cast(
            object,
            json.loads(payload, object_pairs_hook=_unique_json_object),
        )
    except (json.JSONDecodeError, RecursionError) as error:
        raise ReplayManifestDecodeError("replay manifest payload is not valid JSON") from error
    return _decode_typed_node(parsed)


def _decode_typed_node(node: object, *, depth: int = 0) -> object:
    if depth > MAX_CANONICAL_NODE_DEPTH:
        raise ReplayManifestDecodeError("canonical replay manifest nesting is too deep")
    values = _expect_mapping(node, "canonical node")
    node_type = _expect_string(values.get("type"), "canonical node type")
    if node_type == "null":
        _require_keys(values, {"type", "value"}, "canonical null")
        if values["value"] is not None:
            raise ReplayManifestDecodeError("canonical null value is malformed")
        return None
    if node_type == "string":
        _require_keys(values, {"type", "value"}, "canonical string")
        return _expect_string(values["value"], "canonical string value")
    if node_type == "int":
        _require_keys(values, {"type", "value"}, "canonical integer")
        raw = _expect_string(values["value"], "canonical integer value")
        if _CANONICAL_INTEGER.fullmatch(raw) is None:
            raise ReplayManifestDecodeError("canonical integer value is malformed")
        return int(raw)
    if node_type == "datetime":
        _require_keys(values, {"type", "value"}, "canonical datetime")
        raw = _expect_string(values["value"], "canonical datetime value")
        if not raw.endswith("Z"):
            raise ReplayManifestDecodeError("canonical datetime must use UTC Z form")
        try:
            value = datetime.fromisoformat(f"{raw[:-1]}+00:00")
        except ValueError as error:
            raise ReplayManifestDecodeError("canonical datetime value is malformed") from error
        _require_utc(value, "canonical datetime")
        return value
    if node_type == "tuple":
        _require_keys(values, {"type", "value"}, "canonical tuple")
        raw_items = values["value"]
        if type(raw_items) is not list:
            raise ReplayManifestDecodeError("canonical tuple value is malformed")
        return tuple(_decode_typed_node(item, depth=depth + 1) for item in raw_items)
    if node_type == "mapping":
        _require_keys(values, {"type", "value"}, "canonical mapping")
        raw_entries = values["value"]
        if type(raw_entries) is not list:
            raise ReplayManifestDecodeError("canonical mapping value is malformed")
        result: dict[str, object] = {}
        for raw_entry in raw_entries:
            entry = _expect_mapping(raw_entry, "canonical mapping entry")
            _require_keys(entry, {"key", "value"}, "canonical mapping entry")
            key = _decode_typed_node(entry["key"], depth=depth + 1)
            if type(key) is not str:
                raise ReplayManifestDecodeError("replay manifest mapping keys must be strings")
            if key in result:
                raise ReplayManifestDecodeError(f"duplicate canonical mapping key {key!r}")
            result[key] = _decode_typed_node(entry["value"], depth=depth + 1)
        return result
    raise ReplayManifestDecodeError(f"unsupported canonical node type {node_type!r}")


def _expect_mapping(value: object, field_name: str) -> dict[str, object]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise ReplayManifestDecodeError(f"{field_name} must be a mapping")
    return cast(dict[str, object], value)


def _expect_string(value: object, field_name: str) -> str:
    if type(value) is not str:
        raise ReplayManifestDecodeError(f"{field_name} must be a string")
    return value


def _expect_integer(value: object, field_name: str) -> int:
    if type(value) is not int:
        raise ReplayManifestDecodeError(f"{field_name} must be an integer")
    return value


def _expect_datetime(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise ReplayManifestDecodeError(f"{field_name} must be a datetime")
    return value


def _expect_tuple(value: object, field_name: str) -> tuple[object, ...]:
    if type(value) is not tuple:
        raise ReplayManifestDecodeError(f"{field_name} must be a tuple")
    return cast(tuple[object, ...], value)


def _require_keys(values: dict[str, object], expected: set[str], field_name: str) -> None:
    if set(values) != expected:
        raise ReplayManifestDecodeError(f"{field_name} has unexpected fields")


def _enum_value[T: ReplayRevisionPolicy | MissingDataPolicy | LateEventPolicy](
    enum_type: type[T],
    value: object,
    field_name: str,
) -> T:
    try:
        return cast(T, enum_type(_expect_string(value, field_name)))
    except ValueError as error:
        raise ReplayManifestDecodeError(f"{field_name} is unsupported") from error


def _decode_partition(value: object) -> DatasetPartitionPin:
    values = _expect_mapping(value, "dataset partition")
    _require_keys(
        values,
        {
            "available_at_end",
            "available_at_start",
            "byte_sha256",
            "event_time_end",
            "event_time_start",
            "format",
            "object_id",
            "object_key",
            "ordinal",
            "partition_id",
            "row_count",
            "semantic_sha256",
            "semantic_checksum_version",
            "size_bytes",
        },
        "dataset partition",
    )
    return DatasetPartitionPin(
        ordinal=_expect_integer(values["ordinal"], "partition ordinal"),
        partition_id=_expect_string(values["partition_id"], "partition_id"),
        object_id=_expect_string(values["object_id"], "object_id"),
        object_key=_expect_string(values["object_key"], "object_key"),
        format=_expect_string(values["format"], "format"),
        byte_sha256=_expect_string(values["byte_sha256"], "byte_sha256"),
        semantic_sha256=_expect_string(values["semantic_sha256"], "semantic_sha256"),
        semantic_checksum_version=_expect_string(
            values["semantic_checksum_version"],
            "semantic_checksum_version",
        ),
        size_bytes=_expect_integer(values["size_bytes"], "partition size_bytes"),
        row_count=_expect_integer(values["row_count"], "partition row_count"),
        event_time_start=_expect_datetime(
            values["event_time_start"],
            "partition event_time_start",
        ),
        event_time_end=_expect_datetime(
            values["event_time_end"],
            "partition event_time_end",
        ),
        available_at_start=_expect_datetime(
            values["available_at_start"],
            "partition available_at_start",
        ),
        available_at_end=_expect_datetime(
            values["available_at_end"],
            "partition available_at_end",
        ),
    )


def _decode_dataset(value: object) -> DatasetPin:
    values = _expect_mapping(value, "dataset")
    _require_keys(
        values,
        {
            "calendar_sha256",
            "calendar_hash_version",
            "calendar_version",
            "corporate_action_sha256",
            "corporate_action_hash_version",
            "corporate_action_version",
            "manifest_id",
            "manifest_sha256",
            "partitions",
            "price_basis",
            "revision_policy",
            "row_count",
            "schema_version",
            "source_id",
            "source_kind",
            "source_tape_sha256",
            "tzdata_version",
            "universe_sha256",
            "universe_hash_version",
            "universe_version",
        },
        "dataset",
    )
    return DatasetPin(
        manifest_id=_expect_string(values["manifest_id"], "manifest_id"),
        manifest_sha256=_expect_string(values["manifest_sha256"], "manifest_sha256"),
        source_tape_sha256=_expect_string(
            values["source_tape_sha256"],
            "source_tape_sha256",
        ),
        source_id=_expect_string(values["source_id"], "source_id"),
        source_kind=_expect_string(values["source_kind"], "source_kind"),
        schema_version=_expect_string(values["schema_version"], "schema_version"),
        price_basis=_expect_string(values["price_basis"], "price_basis"),
        revision_policy=_enum_value(
            ReplayRevisionPolicy,
            values["revision_policy"],
            "dataset revision_policy",
        ),
        calendar_version=_expect_string(values["calendar_version"], "calendar_version"),
        calendar_sha256=_expect_string(values["calendar_sha256"], "calendar_sha256"),
        calendar_hash_version=_expect_string(
            values["calendar_hash_version"],
            "calendar_hash_version",
        ),
        tzdata_version=_expect_string(values["tzdata_version"], "tzdata_version"),
        universe_version=_expect_string(values["universe_version"], "universe_version"),
        universe_sha256=_expect_string(values["universe_sha256"], "universe_sha256"),
        universe_hash_version=_expect_string(
            values["universe_hash_version"],
            "universe_hash_version",
        ),
        corporate_action_version=_expect_string(
            values["corporate_action_version"],
            "corporate_action_version",
        ),
        corporate_action_sha256=_expect_string(
            values["corporate_action_sha256"],
            "corporate_action_sha256",
        ),
        corporate_action_hash_version=_expect_string(
            values["corporate_action_hash_version"],
            "corporate_action_hash_version",
        ),
        row_count=_expect_integer(values["row_count"], "dataset row_count"),
        partitions=tuple(
            _decode_partition(partition)
            for partition in _expect_tuple(values["partitions"], "dataset partitions")
        ),
    )


def _decode_plan(value: object) -> ReplayPlanPin:
    values = _expect_mapping(value, "plan")
    _require_keys(
        values,
        {
            "coverage_end",
            "coverage_start",
            "decision_lag_microseconds",
            "expected_instrument_ids",
            "interval",
            "late_event_policy",
            "missing_data_policy",
            "revision_policy",
            "watermark_count",
            "watermarks_sha256",
        },
        "plan",
    )
    return ReplayPlanPin(
        coverage_start=_expect_datetime(values["coverage_start"], "coverage_start"),
        coverage_end=_expect_datetime(values["coverage_end"], "coverage_end"),
        interval=_expect_string(values["interval"], "interval"),
        decision_lag=timedelta(
            microseconds=_expect_integer(
                values["decision_lag_microseconds"],
                "decision_lag_microseconds",
            )
        ),
        revision_policy=_enum_value(
            ReplayRevisionPolicy,
            values["revision_policy"],
            "plan revision_policy",
        ),
        missing_data_policy=_enum_value(
            MissingDataPolicy,
            values["missing_data_policy"],
            "missing_data_policy",
        ),
        late_event_policy=_enum_value(
            LateEventPolicy,
            values["late_event_policy"],
            "late_event_policy",
        ),
        expected_instrument_ids=tuple(
            _expect_string(instrument_id, "expected instrument_id")
            for instrument_id in _expect_tuple(
                values["expected_instrument_ids"],
                "expected instruments",
            )
        ),
        watermark_count=_expect_integer(values["watermark_count"], "watermark_count"),
        watermarks_sha256=_expect_string(values["watermarks_sha256"], "watermarks_sha256"),
    )


def _decode_engine(value: object) -> EnginePin:
    values = _expect_mapping(value, "engine")
    _require_keys(
        values,
        {
            "decimal_arithmetic_version",
            "market_batch_contract_version",
            "replay_contract_version",
            "tape_adapter_version",
            "watermark_policy_version",
        },
        "engine",
    )
    return EnginePin(
        tape_adapter_version=_expect_string(
            values["tape_adapter_version"],
            "tape_adapter_version",
        ),
        watermark_policy_version=_expect_string(
            values["watermark_policy_version"],
            "watermark_policy_version",
        ),
        replay_contract_version=_expect_string(
            values["replay_contract_version"],
            "replay_contract_version",
        ),
        market_batch_contract_version=_expect_string(
            values["market_batch_contract_version"],
            "market_batch_contract_version",
        ),
        decimal_arithmetic_version=_expect_string(
            values["decimal_arithmetic_version"],
            "decimal_arithmetic_version",
        ),
    )


def _decode_runtime(value: object) -> RuntimePin:
    values = _expect_mapping(value, "runtime")
    _require_keys(
        values,
        {
            "benchmark_version",
            "cost_model_version",
            "dependency_lock_sha256",
            "dirty_patch_sha256",
            "fill_model_version",
            "pyarrow_version",
            "python_version",
            "rng_algorithm",
            "rng_seed",
            "schema_revision",
            "source_revision",
            "strategy_version",
        },
        "runtime",
    )
    if values["rng_seed"] is not None:
        raise ReplayManifestDecodeError("runtime rng_seed must be null")
    return RuntimePin(
        source_revision=_expect_string(values["source_revision"], "source_revision"),
        dirty_patch_sha256=_expect_string(
            values["dirty_patch_sha256"],
            "dirty_patch_sha256",
        ),
        dependency_lock_sha256=_expect_string(
            values["dependency_lock_sha256"],
            "dependency_lock_sha256",
        ),
        schema_revision=_expect_string(values["schema_revision"], "schema_revision"),
        python_version=_expect_string(values["python_version"], "python_version"),
        pyarrow_version=_expect_string(values["pyarrow_version"], "pyarrow_version"),
        strategy_version=_expect_string(values["strategy_version"], "strategy_version"),
        cost_model_version=_expect_string(
            values["cost_model_version"],
            "cost_model_version",
        ),
        fill_model_version=_expect_string(values["fill_model_version"], "fill_model_version"),
        benchmark_version=_expect_string(values["benchmark_version"], "benchmark_version"),
        rng_algorithm=_expect_string(values["rng_algorithm"], "rng_algorithm"),
        rng_seed=None,
    )
