"""Pure batch and incremental replay for the Phase 3 rolling-close feature."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from packages.domain.feature import (
    ROLLING_CLOSE_MEAN_NAME,
    ROLLING_CLOSE_MEAN_VERSION,
    AuthenticatedFeatureReplayInput,
    CertifiedFeatureReplay,
    FeatureArtifact,
    FeatureComputationMode,
    FeatureDefinition,
    FeatureParityReceipt,
    FeatureReplayLineage,
    FeatureReplayResult,
    FeatureReplayStep,
    FeatureSnapshot,
    FeatureSourceObservation,
    FeatureStepStatus,
)
from packages.domain.market_batch import MarketBatch
from packages.domain.replay import ReplayResult


def create_rolling_close_mean_artifact(
    *,
    source: AuthenticatedFeatureReplayInput,
    implementation_sha256: str,
    publication_lag: timedelta,
) -> FeatureArtifact:
    """Bind the bounded reference definition to authenticated manifest evidence."""

    if type(source) is not AuthenticatedFeatureReplayInput:
        raise ValueError("feature artifact construction requires authenticated replay input")
    definition = FeatureDefinition(
        feature_name=ROLLING_CLOSE_MEAN_NAME,
        feature_version=ROLLING_CLOSE_MEAN_VERSION,
        implementation_sha256=implementation_sha256,
        publication_lag=publication_lag,
    )
    lineage = FeatureReplayLineage._from_authenticated_input(source)
    lineage.require_replay(source.replay)
    return FeatureArtifact(definition=definition, lineage=lineage)


def _batch_window_snapshots(
    artifact: FeatureArtifact,
    previous_batch: MarketBatch,
    current_batch: MarketBatch,
) -> tuple[FeatureSnapshot, ...]:
    """Select one full-sequence batch window without incremental reducer state."""

    if (
        not previous_batch.complete
        or not current_batch.complete
        or previous_batch.watermark.expected_instrument_ids
        != current_batch.watermark.expected_instrument_ids
    ):
        raise ValueError("batch feature windows require adjacent complete matching universes")
    previous_events = {event.instrument_id: event for event in previous_batch.events}
    current_events = {event.instrument_id: event for event in current_batch.events}
    return tuple(
        FeatureSnapshot._from_reducer(
            artifact=artifact,
            source_batch=current_batch,
            source_observations=(
                FeatureSourceObservation.from_batch(
                    previous_batch,
                    previous_events[instrument_id],
                ),
                FeatureSourceObservation.from_batch(
                    current_batch,
                    current_events[instrument_id],
                ),
            ),
        )
        for instrument_id in current_batch.watermark.expected_instrument_ids
    )


def replay_rolling_close_mean_batch(
    artifact: FeatureArtifact,
    replay: ReplayResult,
) -> FeatureReplayResult:
    """Compute each window by indexing the immutable full replay sequence."""

    if type(artifact) is not FeatureArtifact:
        raise ValueError("batch feature replay requires an exact FeatureArtifact")
    artifact.lineage.require_replay(replay)
    steps: list[FeatureReplayStep] = []
    for sequence, batch in enumerate(replay.batches):
        if not batch.complete:
            step = FeatureReplayStep(
                sequence=sequence,
                artifact_sha256=artifact.semantic_sha256,
                source_batch=batch,
                status=FeatureStepStatus.SKIPPED_RESET,
                snapshots=(),
                reset_instrument_ids=batch.watermark.expected_instrument_ids,
            )
        elif sequence == 0:
            step = FeatureReplayStep(
                sequence=sequence,
                artifact_sha256=artifact.semantic_sha256,
                source_batch=batch,
                status=FeatureStepStatus.WARMING,
                snapshots=(),
            )
        else:
            previous_batch = replay.batches[sequence - 1]
            window_is_ready = previous_batch.complete and (
                previous_batch.watermark.expected_instrument_ids
                == batch.watermark.expected_instrument_ids
            )
            step = FeatureReplayStep(
                sequence=sequence,
                artifact_sha256=artifact.semantic_sha256,
                source_batch=batch,
                status=(FeatureStepStatus.READY if window_is_ready else FeatureStepStatus.WARMING),
                snapshots=(
                    _batch_window_snapshots(artifact, previous_batch, batch)
                    if window_is_ready
                    else ()
                ),
            )
        steps.append(step)
    return FeatureReplayResult._from_reducer(
        mode=FeatureComputationMode.BATCH,
        artifact=artifact,
        source_replay=replay,
        steps=tuple(steps),
    )


@dataclass(frozen=True, slots=True, init=False)
class RollingCloseMeanIncrementalState:
    """Proof-constructed online state with independently retained observations."""

    artifact_sha256: str
    next_sequence: int
    previous_instrument_ids: tuple[str, ...]
    previous_observations: tuple[FeatureSourceObservation, ...]
    last_event_time: datetime | None
    last_closed_at: datetime | None

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("RollingCloseMeanIncrementalState is proof-constructed")

    @classmethod
    def _create(
        cls,
        *,
        artifact_sha256: str,
        next_sequence: int,
        previous_instrument_ids: tuple[str, ...] = (),
        previous_observations: tuple[FeatureSourceObservation, ...] = (),
        last_event_time: datetime | None = None,
        last_closed_at: datetime | None = None,
    ) -> RollingCloseMeanIncrementalState:
        instance = object.__new__(cls)
        values = {
            "artifact_sha256": artifact_sha256,
            "next_sequence": next_sequence,
            "previous_instrument_ids": previous_instrument_ids,
            "previous_observations": previous_observations,
            "last_event_time": last_event_time,
            "last_closed_at": last_closed_at,
        }
        for field_name, value in values.items():
            object.__setattr__(instance, field_name, value)
        instance._validate()
        return instance

    def _validate(self) -> None:
        if (
            type(self.artifact_sha256) is not str
            or len(self.artifact_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.artifact_sha256)
        ):
            raise ValueError("incremental feature state requires an artifact digest")
        if type(self.next_sequence) is not int or self.next_sequence < 0:
            raise ValueError("incremental feature sequence must be non-negative")
        if self.previous_instrument_ids != tuple(sorted(set(self.previous_instrument_ids))):
            raise ValueError("incremental feature instruments must be unique and sorted")
        if type(self.previous_observations) is not tuple or any(
            type(observation) is not FeatureSourceObservation
            for observation in self.previous_observations
        ):
            raise ValueError("incremental feature history must be immutable observations")
        observation_instruments = tuple(
            observation.event.instrument_id for observation in self.previous_observations
        )
        if observation_instruments != self.previous_instrument_ids:
            raise ValueError("incremental feature observations changed instrument identity")
        if self.previous_observations:
            batch_evidence = {
                (observation.batch_id, observation.batch_sha256)
                for observation in self.previous_observations
            }
            if len(batch_evidence) != 1:
                raise ValueError("incremental feature history must come from one batch")
        if (self.last_event_time is None) != (self.last_closed_at is None):
            raise ValueError("incremental feature chronology must be wholly present or absent")
        for value, field_name in (
            (self.last_event_time, "incremental feature last event time"),
            (self.last_closed_at, "incremental feature last close time"),
        ):
            if value is not None and (
                type(value) is not datetime
                or value.tzinfo is None
                or value.utcoffset() != UTC.utcoffset(value)
            ):
                raise ValueError(f"{field_name} must be UTC")
        if self.last_event_time is not None and self.last_closed_at is not None:
            if self.last_closed_at < self.last_event_time:
                raise ValueError("incremental feature close cannot precede its event frontier")
            if self.previous_observations and any(
                observation.event.event_time != self.last_event_time
                for observation in self.previous_observations
            ):
                raise ValueError("incremental feature history conflicts with its chronology")

    @classmethod
    def initial(cls, artifact: FeatureArtifact) -> RollingCloseMeanIncrementalState:
        if type(artifact) is not FeatureArtifact:
            raise ValueError("incremental feature state requires an exact FeatureArtifact")
        return cls._create(artifact_sha256=artifact.semantic_sha256, next_sequence=0)

    def _require_next_lineage_batch(
        self,
        artifact: FeatureArtifact,
        batch: MarketBatch,
    ) -> None:
        if self.next_sequence >= len(artifact.lineage.batch_sha256s):
            raise ValueError("incremental feature replay already consumed its sealed lineage")
        expected_sha256 = artifact.lineage.batch_sha256s[self.next_sequence]
        if batch.semantic_sha256 != expected_sha256:
            raise ValueError("incremental batch does not match the exact next lineage batch")
        expected_complete = batch.batch_id in artifact.lineage.complete_batch_ids
        expected_skipped = batch.batch_id in artifact.lineage.skipped_batch_ids
        if expected_complete == expected_skipped or expected_complete != batch.complete:
            raise ValueError("incremental batch conflicts with sealed completeness evidence")

    def advance(
        self,
        artifact: FeatureArtifact,
        batch: MarketBatch,
    ) -> tuple[RollingCloseMeanIncrementalState, FeatureReplayStep]:
        if type(artifact) is not FeatureArtifact or (
            artifact.semantic_sha256 != self.artifact_sha256
        ):
            raise ValueError("incremental feature state changed artifact identity")
        if type(batch) is not MarketBatch:
            raise ValueError("incremental feature replay requires an exact MarketBatch")
        self._require_next_lineage_batch(artifact, batch)
        if self.last_event_time is not None and (
            batch.watermark.event_time_through <= self.last_event_time
            or (self.last_closed_at is not None and batch.as_of < self.last_closed_at)
        ):
            raise ValueError("incremental feature batches must be strictly ordered")
        if not batch.complete:
            step = FeatureReplayStep(
                sequence=self.next_sequence,
                artifact_sha256=self.artifact_sha256,
                source_batch=batch,
                status=FeatureStepStatus.SKIPPED_RESET,
                snapshots=(),
                reset_instrument_ids=batch.watermark.expected_instrument_ids,
            )
            return (
                type(self)._create(
                    artifact_sha256=self.artifact_sha256,
                    next_sequence=self.next_sequence + 1,
                    last_event_time=batch.watermark.event_time_through,
                    last_closed_at=batch.as_of,
                ),
                step,
            )

        current_instrument_ids = batch.watermark.expected_instrument_ids
        current_observations = tuple(
            FeatureSourceObservation.from_batch(batch, batch.event_for(instrument_id))
            for instrument_id in current_instrument_ids
        )
        can_emit = bool(self.previous_observations) and (
            self.previous_instrument_ids == current_instrument_ids
        )
        incremental_snapshots = (
            tuple(
                FeatureSnapshot._from_reducer(
                    artifact=artifact,
                    source_batch=batch,
                    source_observations=(previous, current),
                )
                for previous, current in zip(
                    self.previous_observations,
                    current_observations,
                    strict=True,
                )
            )
            if can_emit
            else ()
        )
        step = FeatureReplayStep(
            sequence=self.next_sequence,
            artifact_sha256=self.artifact_sha256,
            source_batch=batch,
            status=FeatureStepStatus.READY if can_emit else FeatureStepStatus.WARMING,
            snapshots=incremental_snapshots,
        )
        return (
            type(self)._create(
                artifact_sha256=self.artifact_sha256,
                next_sequence=self.next_sequence + 1,
                previous_instrument_ids=current_instrument_ids,
                previous_observations=current_observations,
                last_event_time=batch.watermark.event_time_through,
                last_closed_at=batch.as_of,
            ),
            step,
        )


def replay_rolling_close_mean_incremental(
    artifact: FeatureArtifact,
    replay: ReplayResult,
) -> FeatureReplayResult:
    """Consume the sealed lineage one authenticated batch at a time."""

    if type(artifact) is not FeatureArtifact:
        raise ValueError("incremental feature replay requires an exact FeatureArtifact")
    artifact.lineage.require_replay(replay)
    state = RollingCloseMeanIncrementalState.initial(artifact)
    steps: list[FeatureReplayStep] = []
    for batch in replay.batches:
        state, step = state.advance(artifact, batch)
        steps.append(step)
    if state.next_sequence != len(artifact.lineage.batch_sha256s):
        raise ValueError("incremental feature state did not consume the complete sealed lineage")
    return FeatureReplayResult._from_reducer(
        mode=FeatureComputationMode.INCREMENTAL,
        artifact=artifact,
        source_replay=replay,
        steps=tuple(steps),
    )


def certify_rolling_close_mean_parity(
    artifact: FeatureArtifact,
    replay: ReplayResult,
) -> CertifiedFeatureReplay:
    """Return evidence only when the independently traversed reducers agree exactly."""

    batch_result = replay_rolling_close_mean_batch(artifact, replay)
    incremental_result = replay_rolling_close_mean_incremental(artifact, replay)
    receipt = FeatureParityReceipt._from_equal_results(batch_result, incremental_result)
    return CertifiedFeatureReplay(
        artifact=artifact,
        batch_result=batch_result,
        incremental_result=incremental_result,
        receipt=receipt,
    )
