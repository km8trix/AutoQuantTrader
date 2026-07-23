"""Immutable Phase 3 feature lineage, snapshot, and parity contracts."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum

from packages.domain.canonical import canonical_decimal, canonical_json_bytes
from packages.domain.decimal_math import deterministic_decimal_divide, exact_decimal_sum
from packages.domain.market_batch import MarketBatch, ReplayRevisionPolicy
from packages.domain.models import MarketEvent
from packages.domain.replay import ReplayResult
from packages.domain.replay_manifest import ReplayRunManifest

FEATURE_CONTRACT_VERSION = "phase3-feature-artifact-v1"
FEATURE_REPLAY_CONTRACT_VERSION = "phase3-feature-replay-v1"
ROLLING_CLOSE_MEAN_NAME = "rolling_close_mean"
ROLLING_CLOSE_MEAN_VERSION = "1.0.0"
ROLLING_CLOSE_MEAN_INPUT_FIELD = "close_price"
ROLLING_CLOSE_MEAN_INPUT_SEMANTICS = "raw_point_in_time_close"
ROLLING_CLOSE_MEAN_LOOKBACK = 2
MAX_FEATURE_BATCHES = 250_000
MAX_FEATURE_SNAPSHOTS = 5_000_000


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


NO_TRAINING_WINDOW_SHA256 = _sha256((FEATURE_CONTRACT_VERSION, "no-training-window"))
EMPTY_FITTED_STATE_SHA256 = _sha256((FEATURE_CONTRACT_VERSION, "empty-fitted-state"))


def _require_text(value: str, field_name: str, *, maximum: int = 256) -> None:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"{field_name} must be bounded, non-empty, and trimmed")


def _require_sha256(value: str, field_name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_utc(value: datetime, field_name: str) -> None:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{field_name} must be UTC")


def _timedelta_microseconds(value: timedelta) -> int:
    return value.days * 86_400_000_000 + value.seconds * 1_000_000 + value.microseconds


class FeatureMissingDataPolicy(StrEnum):
    """Supported missing-input behavior for the bounded reference feature."""

    SKIP_AND_RESET = "skip_and_reset"


class FeatureStepStatus(StrEnum):
    """One input batch's explicit feature-reducer outcome."""

    WARMING = "warming"
    READY = "ready"
    SKIPPED_RESET = "skipped_reset"


class FeatureComputationMode(StrEnum):
    BATCH = "batch"
    INCREMENTAL = "incremental"


class FeatureParityStatus(StrEnum):
    PASS = "pass"


class FeatureParityError(ValueError):
    """Batch and incremental feature evidence did not agree exactly."""


@dataclass(frozen=True, slots=True)
class FeatureDefinition:
    """One exact, versioned feature implementation and temporal policy."""

    feature_name: str
    feature_version: str
    implementation_sha256: str
    publication_lag: timedelta
    input_field: str = ROLLING_CLOSE_MEAN_INPUT_FIELD
    input_semantics: str = ROLLING_CLOSE_MEAN_INPUT_SEMANTICS
    lookback_observations: int = ROLLING_CLOSE_MEAN_LOOKBACK
    missing_data_policy: FeatureMissingDataPolicy = FeatureMissingDataPolicy.SKIP_AND_RESET

    def __post_init__(self) -> None:
        _require_text(self.feature_name, "feature name")
        _require_text(self.feature_version, "feature version")
        _require_text(self.input_field, "feature input field")
        _require_text(self.input_semantics, "feature input semantics")
        _require_sha256(self.implementation_sha256, "feature implementation digest")
        if self.feature_name != ROLLING_CLOSE_MEAN_NAME:
            raise ValueError("the Phase 3A contract supports only rolling_close_mean")
        if self.feature_version != ROLLING_CLOSE_MEAN_VERSION:
            raise ValueError("the Phase 3A rolling feature version is unsupported")
        if self.input_field != ROLLING_CLOSE_MEAN_INPUT_FIELD:
            raise ValueError("the Phase 3A feature consumes only close_price")
        if self.input_semantics != ROLLING_CLOSE_MEAN_INPUT_SEMANTICS:
            raise ValueError("the Phase 3A feature requires raw point-in-time close semantics")
        if self.lookback_observations != ROLLING_CLOSE_MEAN_LOOKBACK:
            raise ValueError("the Phase 3A rolling feature requires lookback=2")
        if self.missing_data_policy is not FeatureMissingDataPolicy.SKIP_AND_RESET:
            raise ValueError("the Phase 3A feature requires SKIP_AND_RESET")
        if type(self.publication_lag) is not timedelta or self.publication_lag < timedelta(0):
            raise ValueError("feature publication lag must be a non-negative exact timedelta")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            FEATURE_CONTRACT_VERSION,
            "feature-definition",
            self.feature_name,
            self.feature_version,
            self.implementation_sha256,
            self.input_field,
            self.input_semantics,
            self.lookback_observations,
            _timedelta_microseconds(self.publication_lag),
            self.missing_data_policy.value,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def feature_definition_id(self) -> str:
        return self.semantic_sha256


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedFeatureReplayInput:
    """A sealed replay manifest and its exact, independently verified result."""

    manifest: ReplayRunManifest
    replay: ReplayResult
    proof_sha256: str = field(init=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError(
            "AuthenticatedFeatureReplayInput is proof-constructed by a manifest-tape adapter"
        )

    @classmethod
    def _from_verified_manifest_tape(
        cls,
        *,
        manifest: ReplayRunManifest,
        replay: ReplayResult,
    ) -> AuthenticatedFeatureReplayInput:
        """Seal evidence after a trusted adapter has authenticated the source tape."""

        instance = object.__new__(cls)
        object.__setattr__(instance, "manifest", manifest)
        object.__setattr__(instance, "replay", replay)
        instance._validate()
        object.__setattr__(
            instance,
            "proof_sha256",
            _sha256(
                (
                    FEATURE_CONTRACT_VERSION,
                    "authenticated-feature-replay-input",
                    manifest.manifest_sha256,
                    replay.semantic_sha256,
                    tuple(batch.semantic_sha256 for batch in replay.batches),
                )
            ),
        )
        return instance

    def _validate(self) -> None:
        if type(self.manifest) is not ReplayRunManifest:
            raise ValueError("feature input requires an exact sealed ReplayRunManifest")
        if type(self.replay) is not ReplayResult or not self.replay.batches:
            raise ValueError("feature input requires a non-empty exact ReplayResult")
        policies = {batch.watermark.revision_policy for batch in self.replay.batches}
        expected_instrument_ids = tuple(
            sorted(
                {
                    instrument_id
                    for batch in self.replay.batches
                    for instrument_id in batch.watermark.expected_instrument_ids
                }
            )
        )
        if policies != {self.manifest.dataset.revision_policy} or policies != {
            self.manifest.plan.revision_policy
        }:
            raise ValueError("feature input changed its sealed revision policy")
        if expected_instrument_ids != self.manifest.plan.expected_instrument_ids:
            raise ValueError("feature input changed its sealed instrument universe")
        if (
            self.manifest.replay_semantic_sha256 != self.replay.semantic_sha256
            or self.manifest.tape_sha256 != self.replay.tape_sha256
            or self.manifest.started_at != self.replay.started_at
            or self.manifest.completed_at != self.replay.completed_at
            or self.manifest.processed_event_count != len(self.replay.processed_event_ids)
            or self.manifest.batch_count != len(self.replay.batches)
            or self.manifest.complete_batch_count != len(self.replay.complete_batch_ids)
            or self.manifest.skipped_batch_count != len(self.replay.skipped_batch_ids)
            or self.manifest.plan.watermark_count != len(self.replay.batches)
        ):
            raise ValueError("feature input does not match its sealed replay-run manifest")

    @property
    def semantic_sha256(self) -> str:
        return self.proof_sha256


@dataclass(frozen=True, slots=True, init=False)
class FeatureReplayLineage:
    """Exact dataset, sealed-run, and replay transcript pins consumed by a feature."""

    manifest_id: str
    manifest_sha256: str
    manifest_tape_sha256: str
    replay_run_id: str
    replay_run_manifest_sha256: str
    replay_plan_sha256: str
    replay_result_sha256: str
    replay_tape_sha256: str
    revision_policy: ReplayRevisionPolicy
    started_at: datetime
    completed_at: datetime
    batch_sha256s: tuple[str, ...]
    complete_batch_ids: tuple[str, ...]
    skipped_batch_ids: tuple[str, ...]

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("FeatureReplayLineage is proof-constructed from authenticated input")

    @classmethod
    def _from_authenticated_input(
        cls,
        source: AuthenticatedFeatureReplayInput,
    ) -> FeatureReplayLineage:
        if type(source) is not AuthenticatedFeatureReplayInput:
            raise ValueError("feature lineage requires authenticated replay input")
        manifest = source.manifest
        replay = source.replay
        instance = object.__new__(cls)
        values = {
            "manifest_id": manifest.dataset.manifest_id,
            "manifest_sha256": manifest.dataset.manifest_sha256,
            "manifest_tape_sha256": manifest.dataset.source_tape_sha256,
            "replay_run_id": manifest.run_id,
            "replay_run_manifest_sha256": manifest.manifest_sha256,
            "replay_plan_sha256": manifest.plan.semantic_sha256,
            "replay_result_sha256": replay.semantic_sha256,
            "replay_tape_sha256": replay.tape_sha256,
            "revision_policy": manifest.plan.revision_policy,
            "started_at": replay.started_at,
            "completed_at": replay.completed_at,
            "batch_sha256s": tuple(batch.semantic_sha256 for batch in replay.batches),
            "complete_batch_ids": replay.complete_batch_ids,
            "skipped_batch_ids": replay.skipped_batch_ids,
        }
        for field_name, value in values.items():
            object.__setattr__(instance, field_name, value)
        instance._validate()
        return instance

    def _validate(self) -> None:
        _require_text(self.manifest_id, "feature manifest ID")
        for value, field_name in (
            (self.manifest_sha256, "feature manifest digest"),
            (self.manifest_tape_sha256, "feature manifest tape digest"),
            (self.replay_run_id, "feature replay run ID"),
            (self.replay_run_manifest_sha256, "feature replay run manifest digest"),
            (self.replay_plan_sha256, "feature replay plan digest"),
            (self.replay_result_sha256, "feature replay result digest"),
            (self.replay_tape_sha256, "feature replay tape digest"),
        ):
            _require_sha256(value, field_name)
        if self.manifest_id != self.manifest_sha256:
            raise ValueError("feature dataset manifest must retain content-addressed identity")
        if self.replay_run_id != self.replay_run_manifest_sha256:
            raise ValueError("feature replay run must retain content-addressed identity")
        if type(self.revision_policy) is not ReplayRevisionPolicy:
            raise ValueError("feature lineage requires an exact replay revision policy")
        _require_utc(self.started_at, "feature replay started_at")
        _require_utc(self.completed_at, "feature replay completed_at")
        if self.completed_at < self.started_at:
            raise ValueError("feature replay completion cannot precede its start")
        if (
            type(self.batch_sha256s) is not tuple
            or not self.batch_sha256s
            or len(self.batch_sha256s) > MAX_FEATURE_BATCHES
        ):
            raise ValueError("feature lineage requires a bounded immutable batch digest tuple")
        for digest in self.batch_sha256s:
            _require_sha256(digest, "feature batch digest")
        if len(self.batch_sha256s) != len(set(self.batch_sha256s)):
            raise ValueError("feature batch digests must be unique")
        for identities, field_name in (
            (self.complete_batch_ids, "complete feature batch IDs"),
            (self.skipped_batch_ids, "skipped feature batch IDs"),
        ):
            if type(identities) is not tuple or len(identities) > MAX_FEATURE_BATCHES:
                raise ValueError(f"{field_name} must be a bounded immutable tuple")
            if len(identities) != len(set(identities)):
                raise ValueError(f"{field_name} must be unique")
            for identity in identities:
                _require_text(identity, "feature batch ID")
        if set(self.complete_batch_ids) & set(self.skipped_batch_ids):
            raise ValueError("complete and skipped feature batch identities must be disjoint")
        if len(self.complete_batch_ids) + len(self.skipped_batch_ids) != len(self.batch_sha256s):
            raise ValueError("feature lineage must classify every replay batch")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            FEATURE_CONTRACT_VERSION,
            "feature-replay-lineage",
            self.manifest_id,
            self.manifest_sha256,
            self.manifest_tape_sha256,
            self.replay_run_id,
            self.replay_run_manifest_sha256,
            self.replay_plan_sha256,
            self.replay_result_sha256,
            self.replay_tape_sha256,
            self.revision_policy.value,
            self.started_at,
            self.completed_at,
            self.batch_sha256s,
            self.complete_batch_ids,
            self.skipped_batch_ids,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    def require_replay(self, replay: ReplayResult) -> None:
        if type(replay) is not ReplayResult:
            raise ValueError("feature computation requires an exact ReplayResult")
        policies = {batch.watermark.revision_policy for batch in replay.batches}
        if policies != {self.revision_policy}:
            raise ValueError("feature replay changed its manifest revision policy")
        if (
            replay.semantic_sha256 != self.replay_result_sha256
            or replay.tape_sha256 != self.replay_tape_sha256
            or replay.started_at != self.started_at
            or replay.completed_at != self.completed_at
            or tuple(batch.semantic_sha256 for batch in replay.batches) != self.batch_sha256s
            or replay.complete_batch_ids != self.complete_batch_ids
            or replay.skipped_batch_ids != self.skipped_batch_ids
        ):
            raise ValueError("feature replay does not match its exact immutable lineage")


@dataclass(frozen=True, slots=True)
class FeatureArtifact:
    """Content-addressed feature definition plus exact input and fitted-state pins."""

    definition: FeatureDefinition
    lineage: FeatureReplayLineage
    training_window_sha256: str = NO_TRAINING_WINDOW_SHA256
    fitted_state_sha256: str = EMPTY_FITTED_STATE_SHA256

    def __post_init__(self) -> None:
        if type(self.definition) is not FeatureDefinition:
            raise ValueError("feature artifact requires an exact FeatureDefinition")
        if type(self.lineage) is not FeatureReplayLineage:
            raise ValueError("feature artifact requires exact replay lineage")
        if self.training_window_sha256 != NO_TRAINING_WINDOW_SHA256:
            raise ValueError("the Phase 3A reference feature has no fitted training window")
        if self.fitted_state_sha256 != EMPTY_FITTED_STATE_SHA256:
            raise ValueError("the Phase 3A reference feature has immutable empty fitted state")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            FEATURE_CONTRACT_VERSION,
            "feature-artifact",
            self.definition.semantic_sha256,
            self.lineage.semantic_sha256,
            self.training_window_sha256,
            self.fitted_state_sha256,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def artifact_id(self) -> str:
        return self.semantic_sha256


@dataclass(frozen=True, slots=True)
class FeatureSourceObservation:
    """One exact replay-selected event and the batch that admitted it."""

    batch_id: str
    batch_sha256: str
    event: MarketEvent

    def __post_init__(self) -> None:
        _require_text(self.batch_id, "feature source batch ID")
        _require_sha256(self.batch_sha256, "feature source batch digest")
        if type(self.event) is not MarketEvent:
            raise ValueError("feature source observation requires an exact MarketEvent")

    @classmethod
    def from_batch(cls, batch: MarketBatch, event: MarketEvent) -> FeatureSourceObservation:
        if type(batch) is not MarketBatch or not batch.complete:
            raise ValueError("feature source observations require a complete MarketBatch")
        matches = tuple(
            candidate for candidate in batch.events if candidate.event_id == event.event_id
        )
        if len(matches) != 1 or matches[0] != event:
            raise ValueError("feature source event is not exact batch evidence")
        return cls(batch_id=batch.batch_id, batch_sha256=batch.semantic_sha256, event=event)

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            FEATURE_CONTRACT_VERSION,
            "feature-source-observation",
            self.batch_id,
            self.batch_sha256,
            self.event.semantic_sha256,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


@dataclass(frozen=True, slots=True, init=False)
class FeatureSnapshot:
    """One causal rolling feature value with its complete two-event lineage."""

    artifact: FeatureArtifact
    source_batch: MarketBatch
    instrument_id: str
    symbol: str
    source_observations: tuple[FeatureSourceObservation, ...]
    observation_time: datetime
    available_at: datetime
    value: Decimal
    snapshot_sha256: str = field(init=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("FeatureSnapshot values are proof-constructed by the feature reducer")

    @classmethod
    def _from_reducer(
        cls,
        *,
        artifact: FeatureArtifact,
        source_batch: MarketBatch,
        source_observations: tuple[FeatureSourceObservation, ...],
    ) -> FeatureSnapshot:
        if (
            type(source_observations) is not tuple
            or len(source_observations) != ROLLING_CLOSE_MEAN_LOOKBACK
        ):
            raise ValueError("rolling feature snapshot requires exactly two source observations")
        instance = object.__new__(cls)
        latest = source_observations[-1].event
        values = {
            "artifact": artifact,
            "source_batch": source_batch,
            "instrument_id": latest.instrument_id,
            "symbol": latest.symbol,
            "source_observations": source_observations,
            "observation_time": latest.event_time,
            "available_at": max(
                source_batch.as_of,
                *(observation.event.available_at for observation in source_observations),
            )
            + artifact.definition.publication_lag,
            "value": canonical_decimal(
                deterministic_decimal_divide(
                    exact_decimal_sum(
                        observation.event.close_price for observation in source_observations
                    ),
                    Decimal(ROLLING_CLOSE_MEAN_LOOKBACK),
                ),
            ),
        }
        for field_name, value in values.items():
            object.__setattr__(instance, field_name, value)
        instance._validate()
        object.__setattr__(instance, "snapshot_sha256", _sha256(instance._semantic_material()))
        return instance

    def _validate(self) -> None:
        if type(self.artifact) is not FeatureArtifact:
            raise ValueError("feature snapshot requires an exact FeatureArtifact")
        if type(self.source_batch) is not MarketBatch or not self.source_batch.complete:
            raise ValueError("feature snapshot requires a complete source MarketBatch")
        if (
            type(self.source_observations) is not tuple
            or len(self.source_observations) != ROLLING_CLOSE_MEAN_LOOKBACK
            or any(
                type(observation) is not FeatureSourceObservation
                for observation in self.source_observations
            )
        ):
            raise ValueError("rolling feature snapshot requires exactly two source observations")
        events = tuple(observation.event for observation in self.source_observations)
        if any(
            event.instrument_id != self.instrument_id or event.symbol != self.symbol
            for event in events
        ):
            raise ValueError("feature snapshot source observations changed instrument identity")
        ordering = tuple(
            (
                event.event_time,
                event.available_at,
                observation.batch_id,
                event.event_id,
            )
            for observation, event in zip(self.source_observations, events, strict=True)
        )
        if ordering != tuple(sorted(ordering)) or ordering[0] >= ordering[1]:
            raise ValueError("feature snapshot observations must be strictly ordered")
        latest = self.source_observations[-1]
        if (
            latest.batch_id != self.source_batch.batch_id
            or latest.batch_sha256 != self.source_batch.semantic_sha256
            or self.source_batch.event_for(self.instrument_id) != latest.event
        ):
            raise ValueError("feature snapshot does not end at its exact source batch")
        if self.observation_time != events[-1].event_time:
            raise ValueError("feature snapshot observation time must equal its latest input")
        expected_available_at = (
            max(
                self.source_batch.as_of,
                *(event.available_at for event in events),
            )
            + self.artifact.definition.publication_lag
        )
        if self.available_at != expected_available_at:
            raise ValueError("feature snapshot availability violates its publication lag")
        expected_value = canonical_decimal(
            deterministic_decimal_divide(
                exact_decimal_sum(event.close_price for event in events),
                Decimal(ROLLING_CLOSE_MEAN_LOOKBACK),
            ),
        )
        if self.value != expected_value:
            raise ValueError("feature snapshot value conflicts with its exact source observations")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            FEATURE_CONTRACT_VERSION,
            "feature-snapshot",
            self.artifact.semantic_sha256,
            self.source_batch.batch_id,
            self.source_batch.semantic_sha256,
            self.instrument_id,
            self.symbol,
            tuple(observation.semantic_sha256 for observation in self.source_observations),
            self.observation_time,
            self.available_at,
            self.value,
        )

    @property
    def semantic_sha256(self) -> str:
        return self.snapshot_sha256

    @property
    def snapshot_id(self) -> str:
        return self.snapshot_sha256


@dataclass(frozen=True, slots=True)
class FeatureReplayStep:
    """One explicit READY, warm-up, or gap-reset outcome."""

    sequence: int
    artifact_sha256: str
    source_batch: MarketBatch
    status: FeatureStepStatus
    snapshots: tuple[FeatureSnapshot, ...]
    reset_instrument_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence < 0:
            raise ValueError("feature replay step sequence must be non-negative")
        _require_sha256(self.artifact_sha256, "feature replay artifact digest")
        if type(self.source_batch) is not MarketBatch:
            raise ValueError("feature replay step requires an exact MarketBatch")
        if type(self.status) is not FeatureStepStatus:
            raise ValueError("feature replay step status must be exact")
        if type(self.snapshots) is not tuple or any(
            type(snapshot) is not FeatureSnapshot for snapshot in self.snapshots
        ):
            raise ValueError("feature replay snapshots must be immutable exact values")
        if type(self.reset_instrument_ids) is not tuple:
            raise ValueError("feature reset instruments must be an immutable tuple")
        if self.reset_instrument_ids != tuple(sorted(set(self.reset_instrument_ids))):
            raise ValueError("feature reset instruments must be unique and sorted")
        snapshot_instruments = tuple(snapshot.instrument_id for snapshot in self.snapshots)
        if snapshot_instruments != tuple(sorted(set(snapshot_instruments))):
            raise ValueError("feature snapshots must be unique and sorted by instrument")
        if any(
            snapshot.artifact.semantic_sha256 != self.artifact_sha256
            or snapshot.source_batch != self.source_batch
            for snapshot in self.snapshots
        ):
            raise ValueError("feature replay step snapshots conflict with their source batch")
        expected_instruments = self.source_batch.watermark.expected_instrument_ids
        if self.status is FeatureStepStatus.SKIPPED_RESET:
            if self.source_batch.complete or self.snapshots:
                raise ValueError("SKIPPED_RESET requires an incomplete batch and no snapshots")
            if self.reset_instrument_ids != expected_instruments:
                raise ValueError("SKIPPED_RESET must clear every expected instrument")
        elif self.status is FeatureStepStatus.WARMING:
            if not self.source_batch.complete or self.snapshots or self.reset_instrument_ids:
                raise ValueError("WARMING requires a complete batch without output or reset")
        elif (
            not self.source_batch.complete
            or snapshot_instruments != expected_instruments
            or self.reset_instrument_ids
        ):
            raise ValueError("READY requires one snapshot for every expected instrument")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            FEATURE_REPLAY_CONTRACT_VERSION,
            "feature-replay-step",
            self.sequence,
            self.artifact_sha256,
            self.source_batch.batch_id,
            self.source_batch.semantic_sha256,
            self.status.value,
            tuple(snapshot.semantic_sha256 for snapshot in self.snapshots),
            self.reset_instrument_ids,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())


@dataclass(frozen=True, slots=True, init=False)
class FeatureReplayResult:
    """Canonical feature transcript from one declared computation path."""

    mode: FeatureComputationMode
    artifact: FeatureArtifact
    source_replay: ReplayResult
    steps: tuple[FeatureReplayStep, ...]

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("FeatureReplayResult is proof-constructed by a feature reducer")

    @classmethod
    def _from_reducer(
        cls,
        *,
        mode: FeatureComputationMode,
        artifact: FeatureArtifact,
        source_replay: ReplayResult,
        steps: tuple[FeatureReplayStep, ...],
    ) -> FeatureReplayResult:
        instance = object.__new__(cls)
        object.__setattr__(instance, "mode", mode)
        object.__setattr__(instance, "artifact", artifact)
        object.__setattr__(instance, "source_replay", source_replay)
        object.__setattr__(instance, "steps", steps)
        instance._validate()
        return instance

    def _validate(self) -> None:
        if type(self.mode) is not FeatureComputationMode:
            raise ValueError("feature replay computation mode must be exact")
        if type(self.artifact) is not FeatureArtifact:
            raise ValueError("feature replay requires an exact FeatureArtifact")
        self.artifact.lineage.require_replay(self.source_replay)
        if (
            type(self.steps) is not tuple
            or len(self.steps) != len(self.source_replay.batches)
            or len(self.steps) > MAX_FEATURE_BATCHES
        ):
            raise ValueError("feature replay must classify every bounded source batch")
        for sequence, (step, batch) in enumerate(
            zip(self.steps, self.source_replay.batches, strict=True)
        ):
            if (
                type(step) is not FeatureReplayStep
                or step.sequence != sequence
                or step.source_batch != batch
                or step.artifact_sha256 != self.artifact.semantic_sha256
            ):
                raise ValueError("feature replay step chain conflicts with source replay order")
        self._validate_canonical_transitions()
        snapshot_count = sum(len(step.snapshots) for step in self.steps)
        if snapshot_count > MAX_FEATURE_SNAPSHOTS:
            raise ValueError("feature replay exceeds its snapshot bound")

    def _validate_canonical_transitions(self) -> None:
        """Reject structurally valid transcripts that violate the reference reducer."""

        previous_complete: MarketBatch | None = None
        for step in self.steps:
            batch = step.source_batch
            if not batch.complete:
                if step.status is not FeatureStepStatus.SKIPPED_RESET:
                    raise ValueError("incomplete feature batches must emit SKIPPED_RESET")
                previous_complete = None
                continue
            if previous_complete is None or (
                previous_complete.watermark.expected_instrument_ids
                != batch.watermark.expected_instrument_ids
            ):
                if step.status is not FeatureStepStatus.WARMING:
                    raise ValueError("feature history must warm after reset or universe change")
                previous_complete = batch
                continue
            if step.status is not FeatureStepStatus.READY:
                raise ValueError("eligible feature windows must emit READY")
            for snapshot, instrument_id in zip(
                step.snapshots,
                batch.watermark.expected_instrument_ids,
                strict=True,
            ):
                expected_observations = (
                    FeatureSourceObservation.from_batch(
                        previous_complete,
                        previous_complete.event_for(instrument_id),
                    ),
                    FeatureSourceObservation.from_batch(
                        batch,
                        batch.event_for(instrument_id),
                    ),
                )
                if snapshot.source_observations != expected_observations:
                    raise ValueError("feature snapshot does not use the canonical adjacent window")
            previous_complete = batch

    @property
    def snapshots(self) -> tuple[FeatureSnapshot, ...]:
        return tuple(snapshot for step in self.steps for snapshot in step.snapshots)

    def _transcript_material(self) -> tuple[object, ...]:
        return (
            FEATURE_REPLAY_CONTRACT_VERSION,
            "feature-replay-transcript",
            self.artifact.semantic_sha256,
            self.source_replay.semantic_sha256,
            tuple(step.semantic_sha256 for step in self.steps),
        )

    @property
    def transcript_sha256(self) -> str:
        return _sha256(self._transcript_material())

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                FEATURE_REPLAY_CONTRACT_VERSION,
                "feature-replay-result",
                self.mode.value,
                self.transcript_sha256,
            )
        )


@dataclass(frozen=True, slots=True, init=False)
class FeatureParityReceipt:
    """Proof constructed only after exact batch/incremental transcript equality."""

    artifact_sha256: str
    lineage_sha256: str
    batch_result_sha256: str
    incremental_result_sha256: str
    transcript_sha256: str
    snapshot_ids: tuple[str, ...]
    snapshot_count: int
    status: FeatureParityStatus
    receipt_sha256: str = field(init=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("FeatureParityReceipt is proof-constructed by differential replay")

    @classmethod
    def _from_equal_results(
        cls,
        batch_result: FeatureReplayResult,
        incremental_result: FeatureReplayResult,
    ) -> FeatureParityReceipt:
        if (
            type(batch_result) is not FeatureReplayResult
            or batch_result.mode is not FeatureComputationMode.BATCH
            or type(incremental_result) is not FeatureReplayResult
            or incremental_result.mode is not FeatureComputationMode.INCREMENTAL
        ):
            raise FeatureParityError("feature parity requires exact batch and incremental results")
        if (
            batch_result.artifact != incremental_result.artifact
            or batch_result.source_replay != incremental_result.source_replay
            or batch_result.steps != incremental_result.steps
            or batch_result.transcript_sha256 != incremental_result.transcript_sha256
        ):
            raise FeatureParityError("batch and incremental feature transcripts diverged")
        instance = object.__new__(cls)
        snapshot_ids = tuple(snapshot.snapshot_id for snapshot in batch_result.snapshots)
        values = {
            "artifact_sha256": batch_result.artifact.semantic_sha256,
            "lineage_sha256": batch_result.artifact.lineage.semantic_sha256,
            "batch_result_sha256": batch_result.semantic_sha256,
            "incremental_result_sha256": incremental_result.semantic_sha256,
            "transcript_sha256": batch_result.transcript_sha256,
            "snapshot_ids": snapshot_ids,
            "snapshot_count": len(snapshot_ids),
            "status": FeatureParityStatus.PASS,
        }
        for field_name, value in values.items():
            object.__setattr__(instance, field_name, value)
        object.__setattr__(instance, "receipt_sha256", _sha256(instance._semantic_material()))
        return instance

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            FEATURE_REPLAY_CONTRACT_VERSION,
            "feature-parity-receipt",
            self.artifact_sha256,
            self.lineage_sha256,
            self.batch_result_sha256,
            self.incremental_result_sha256,
            self.transcript_sha256,
            self.snapshot_ids,
            self.snapshot_count,
            self.status.value,
        )

    @property
    def semantic_sha256(self) -> str:
        return self.receipt_sha256


@dataclass(frozen=True, slots=True)
class CertifiedFeatureReplay:
    """The two exact reducer transcripts plus their successful parity proof."""

    artifact: FeatureArtifact
    batch_result: FeatureReplayResult
    incremental_result: FeatureReplayResult
    receipt: FeatureParityReceipt

    def __post_init__(self) -> None:
        if (
            type(self.artifact) is not FeatureArtifact
            or type(self.batch_result) is not FeatureReplayResult
            or type(self.incremental_result) is not FeatureReplayResult
            or type(self.receipt) is not FeatureParityReceipt
        ):
            raise ValueError("certified feature replay requires exact feature evidence")
        expected = FeatureParityReceipt._from_equal_results(
            self.batch_result,
            self.incremental_result,
        )
        if (
            self.batch_result.artifact != self.artifact
            or self.incremental_result.artifact != self.artifact
            or self.receipt != expected
        ):
            raise ValueError("certified feature replay evidence is inconsistent")

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                FEATURE_REPLAY_CONTRACT_VERSION,
                "certified-feature-replay",
                self.artifact.semantic_sha256,
                self.batch_result.semantic_sha256,
                self.incremental_result.semantic_sha256,
                self.receipt.semantic_sha256,
            )
        )
