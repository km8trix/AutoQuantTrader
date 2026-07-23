"""Independent causal target reducers over certified feature transcripts."""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass

from packages.domain.feature import (
    CertifiedFeatureReplay,
    FeatureComputationMode,
    FeatureReplayStep,
    FeatureSnapshot,
)
from packages.domain.feature_target import (
    CertifiedFeatureTargetReplay,
    FeatureDecisionContext,
    FeatureTargetDecision,
    FeatureTargetParityReceipt,
    FeatureTargetReplayResult,
    FeatureTargetReplayStep,
    FeatureTargetRuntimePin,
    FeatureTargetStepStatus,
    FeatureVisibilityProof,
    RollingCloseMeanTargetPolicy,
)


def _batch_visibility_by_sequence(
    feature_steps: tuple[FeatureReplayStep, ...],
) -> tuple[tuple[FeatureSnapshot, ...], ...]:
    """Resolve every prefix from full-sequence epoch/availability indexes."""

    current_epoch = -1
    current_instrument_ids: tuple[str, ...] = ()
    epoch_by_sequence: list[int | None] = []
    histories: dict[tuple[int, str], list[tuple[int, FeatureSnapshot]]] = {}
    for step in feature_steps:
        batch = step.source_batch
        if not batch.complete:
            current_instrument_ids = ()
            epoch_by_sequence.append(None)
            continue
        if batch.watermark.expected_instrument_ids != current_instrument_ids:
            current_epoch += 1
            current_instrument_ids = batch.watermark.expected_instrument_ids
        epoch_by_sequence.append(current_epoch)
        for snapshot in step.snapshots:
            histories.setdefault((current_epoch, snapshot.instrument_id), []).append(
                (step.sequence, snapshot)
            )
    availability = {
        key: tuple((snapshot.available_at, source_sequence) for source_sequence, snapshot in items)
        for key, items in histories.items()
    }

    results: list[tuple[FeatureSnapshot, ...]] = []
    for sequence, step in enumerate(feature_steps):
        batch = step.source_batch
        epoch = epoch_by_sequence[sequence]
        if epoch is None:
            results.append(())
            continue
        selected: list[FeatureSnapshot] = []
        for instrument_id in batch.watermark.expected_instrument_ids:
            key = (epoch, instrument_id)
            snapshots = histories.get(key, [])
            index = bisect_right(availability.get(key, ()), (batch.as_of, sequence)) - 1
            if index < 0:
                continue
            source_sequence, snapshot = snapshots[index]
            if source_sequence > sequence or snapshot.source_batch.as_of > batch.as_of:
                raise ValueError("batch visibility index selected a future source batch")
            selected.append(snapshot)
        results.append(tuple(selected))
    return tuple(results)


def _complete_step(
    *,
    feature_step: FeatureReplayStep,
    visibility_proof: FeatureVisibilityProof,
    runtime_pin: FeatureTargetRuntimePin,
    policy: RollingCloseMeanTargetPolicy,
    visible_snapshots: tuple[FeatureSnapshot, ...],
    ready_generation: int,
) -> tuple[FeatureTargetReplayStep, int]:
    context = FeatureDecisionContext._from_visible_snapshots(
        visibility_proof=visibility_proof,
        sequence=feature_step.sequence,
        runtime_pin=runtime_pin,
        snapshots=visible_snapshots,
    )
    expected_ids = feature_step.source_batch.watermark.expected_instrument_ids
    visible_ids = tuple(snapshot.instrument_id for snapshot in visible_snapshots)
    if visible_ids != expected_ids:
        return (
            FeatureTargetReplayStep(
                sequence=feature_step.sequence,
                source_feature_step=feature_step,
                status=FeatureTargetStepStatus.WAITING,
                context=context,
            ),
            ready_generation,
        )
    next_generation = ready_generation + 1
    decision = FeatureTargetDecision._from_context(
        context=context,
        policy=policy,
        rebalance_generation=next_generation,
    )
    return (
        FeatureTargetReplayStep(
            sequence=feature_step.sequence,
            source_feature_step=feature_step,
            status=FeatureTargetStepStatus.READY,
            context=context,
            decision=decision,
        ),
        next_generation,
    )


def replay_rolling_close_mean_targets_batch(
    certification: CertifiedFeatureReplay,
    policy: RollingCloseMeanTargetPolicy,
) -> FeatureTargetReplayResult:
    """Derive decisions from a full-sequence immutable availability index."""

    if type(certification) is not CertifiedFeatureReplay:
        raise ValueError("batch feature target replay requires exact certified feature evidence")
    if type(policy) is not RollingCloseMeanTargetPolicy:
        raise ValueError("batch feature target replay requires an exact target policy")
    runtime_pin = FeatureTargetRuntimePin._from_evidence(
        policy,
        certification.artifact,
        certification.receipt,
    )
    feature_result = certification.batch_result
    visibility_proof = FeatureVisibilityProof._from_feature_result(
        feature_result,
        certification.receipt,
    )
    batch_visibility = _batch_visibility_by_sequence(feature_result.steps)
    steps: list[FeatureTargetReplayStep] = []
    ready_generation = 0
    for sequence, feature_step in enumerate(feature_result.steps):
        if not feature_step.source_batch.complete:
            steps.append(
                FeatureTargetReplayStep(
                    sequence=sequence,
                    source_feature_step=feature_step,
                    status=FeatureTargetStepStatus.SKIPPED_RESET,
                )
            )
            continue
        step, ready_generation = _complete_step(
            feature_step=feature_step,
            visibility_proof=visibility_proof,
            runtime_pin=runtime_pin,
            policy=policy,
            visible_snapshots=batch_visibility[sequence],
            ready_generation=ready_generation,
        )
        steps.append(step)
    return FeatureTargetReplayResult._from_reducer(
        mode=FeatureComputationMode.BATCH,
        policy=policy,
        runtime_pin=runtime_pin,
        feature_result=feature_result,
        feature_receipt=certification.receipt,
        steps=tuple(steps),
    )


@dataclass(frozen=True, slots=True, init=False)
class RollingCloseMeanTargetIncrementalState:
    """Authenticated pending and visible feature state for incremental decisions."""

    runtime_pin_sha256: str
    visibility_proof_sha256: str
    feature_step_count: int
    next_sequence: int
    next_pending_sequence: int
    expected_instrument_ids: tuple[str, ...]
    visible_snapshots: tuple[FeatureSnapshot, ...]
    ready_generation: int

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError(
            "RollingCloseMeanTargetIncrementalState is proof-constructed from feature evidence"
        )

    @classmethod
    def _create(
        cls,
        *,
        runtime_pin_sha256: str,
        visibility_proof_sha256: str,
        feature_step_count: int,
        next_sequence: int = 0,
        next_pending_sequence: int = 0,
        expected_instrument_ids: tuple[str, ...] = (),
        visible_snapshots: tuple[FeatureSnapshot, ...] = (),
        ready_generation: int = 0,
    ) -> RollingCloseMeanTargetIncrementalState:
        instance = object.__new__(cls)
        values = {
            "runtime_pin_sha256": runtime_pin_sha256,
            "visibility_proof_sha256": visibility_proof_sha256,
            "feature_step_count": feature_step_count,
            "next_sequence": next_sequence,
            "next_pending_sequence": next_pending_sequence,
            "expected_instrument_ids": expected_instrument_ids,
            "visible_snapshots": visible_snapshots,
            "ready_generation": ready_generation,
        }
        for field_name, value in values.items():
            object.__setattr__(instance, field_name, value)
        instance._validate()
        return instance

    @classmethod
    def initial(
        cls,
        *,
        runtime_pin: FeatureTargetRuntimePin,
        visibility_proof: FeatureVisibilityProof,
    ) -> RollingCloseMeanTargetIncrementalState:
        if type(runtime_pin) is not FeatureTargetRuntimePin:
            raise ValueError("incremental feature target state requires an exact runtime pin")
        if type(visibility_proof) is not FeatureVisibilityProof:
            raise ValueError("incremental feature target state requires exact visibility proof")
        feature_result = visibility_proof.feature_result
        if feature_result.mode is not FeatureComputationMode.INCREMENTAL:
            raise ValueError("incremental feature target state requires its incremental transcript")
        if (
            visibility_proof.artifact_sha256 != runtime_pin.artifact_sha256
            or visibility_proof.feature_receipt_sha256 != runtime_pin.feature_parity_receipt_sha256
        ):
            raise ValueError("incremental feature target state changed feature artifact identity")
        return cls._create(
            runtime_pin_sha256=runtime_pin.semantic_sha256,
            visibility_proof_sha256=visibility_proof.semantic_sha256,
            feature_step_count=len(feature_result.steps),
        )

    def _validate(self) -> None:
        for value, field_name in (
            (self.runtime_pin_sha256, "incremental feature target runtime pin"),
            (self.visibility_proof_sha256, "incremental feature visibility proof"),
        ):
            if (
                type(value) is not str
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise ValueError(f"{field_name} must be lowercase SHA-256")
        if type(self.feature_step_count) is not int or self.feature_step_count < 1:
            raise ValueError("incremental feature target state requires bounded source steps")
        if type(self.next_sequence) is not int or not 0 <= self.next_sequence <= (
            self.feature_step_count
        ):
            raise ValueError("incremental feature target sequence is outside its transcript")
        if (
            type(self.next_pending_sequence) is not int
            or not 0 <= self.next_pending_sequence <= self.next_sequence
        ):
            raise ValueError("incremental pending cursor is outside consumed evidence")
        if type(self.expected_instrument_ids) is not tuple or self.expected_instrument_ids != tuple(
            sorted(set(self.expected_instrument_ids))
        ):
            raise ValueError("incremental expected instruments must be unique and sorted")
        if type(self.visible_snapshots) is not tuple:
            raise ValueError("incremental visible features must be an immutable tuple")
        if any(type(snapshot) is not FeatureSnapshot for snapshot in self.visible_snapshots):
            raise ValueError("incremental visible features must be exact snapshots")
        visible_ids = tuple(snapshot.instrument_id for snapshot in self.visible_snapshots)
        if visible_ids != tuple(sorted(set(visible_ids))) or not set(visible_ids) <= set(
            self.expected_instrument_ids
        ):
            raise ValueError("incremental visible features conflict with the current universe")
        if type(self.ready_generation) is not int or self.ready_generation < 0:
            raise ValueError("incremental target generation must be non-negative")

    def advance(
        self,
        *,
        runtime_pin: FeatureTargetRuntimePin,
        visibility_proof: FeatureVisibilityProof,
        feature_step: FeatureReplayStep,
        policy: RollingCloseMeanTargetPolicy,
    ) -> tuple[RollingCloseMeanTargetIncrementalState, FeatureTargetReplayStep]:
        if type(runtime_pin) is not FeatureTargetRuntimePin or (
            runtime_pin.semantic_sha256 != self.runtime_pin_sha256
        ):
            raise ValueError("incremental feature target state changed runtime identity")
        if (
            type(visibility_proof) is not FeatureVisibilityProof
            or visibility_proof.feature_result.mode is not FeatureComputationMode.INCREMENTAL
            or visibility_proof.semantic_sha256 != self.visibility_proof_sha256
            or len(visibility_proof.feature_result.steps) != self.feature_step_count
        ):
            raise ValueError("incremental feature target state changed source transcript")
        if self.next_sequence >= self.feature_step_count:
            raise ValueError("incremental feature target replay already consumed its transcript")
        feature_result = visibility_proof.feature_result
        if (
            type(feature_step) is not FeatureReplayStep
            or feature_step != feature_result.steps[self.next_sequence]
        ):
            raise ValueError("incremental feature target step is not the exact next source step")
        if type(policy) is not RollingCloseMeanTargetPolicy:
            raise ValueError("incremental feature target replay requires an exact policy")
        if policy.semantic_sha256 != runtime_pin.policy_sha256:
            raise ValueError("incremental feature target state changed runtime policy")

        batch = feature_step.source_batch
        next_sequence = self.next_sequence + 1
        if not batch.complete:
            step = FeatureTargetReplayStep(
                sequence=self.next_sequence,
                source_feature_step=feature_step,
                status=FeatureTargetStepStatus.SKIPPED_RESET,
            )
            return (
                type(self)._create(
                    runtime_pin_sha256=self.runtime_pin_sha256,
                    visibility_proof_sha256=self.visibility_proof_sha256,
                    feature_step_count=self.feature_step_count,
                    next_sequence=next_sequence,
                    next_pending_sequence=next_sequence,
                    ready_generation=self.ready_generation,
                ),
                step,
            )

        expected_ids = batch.watermark.expected_instrument_ids
        if expected_ids == self.expected_instrument_ids:
            visible = {snapshot.instrument_id: snapshot for snapshot in self.visible_snapshots}
            next_pending_sequence = self.next_pending_sequence
        else:
            visible = {}
            next_pending_sequence = self.next_sequence
        while next_pending_sequence <= self.next_sequence:
            pending_step = feature_result.steps[next_pending_sequence]
            if not pending_step.snapshots:
                next_pending_sequence += 1
                continue
            if pending_step.snapshots[0].available_at > batch.as_of:
                break
            if any(snapshot.available_at > batch.as_of for snapshot in pending_step.snapshots):
                raise ValueError("incremental feature snapshots disagree on availability")
            for snapshot in pending_step.snapshots:
                visible[snapshot.instrument_id] = snapshot
            next_pending_sequence += 1
        visible_snapshots = tuple(
            visible[instrument_id] for instrument_id in expected_ids if instrument_id in visible
        )
        step, ready_generation = _complete_step(
            feature_step=feature_step,
            visibility_proof=visibility_proof,
            runtime_pin=runtime_pin,
            policy=policy,
            visible_snapshots=visible_snapshots,
            ready_generation=self.ready_generation,
        )
        return (
            type(self)._create(
                runtime_pin_sha256=self.runtime_pin_sha256,
                visibility_proof_sha256=self.visibility_proof_sha256,
                feature_step_count=self.feature_step_count,
                next_sequence=next_sequence,
                next_pending_sequence=next_pending_sequence,
                expected_instrument_ids=expected_ids,
                visible_snapshots=visible_snapshots,
                ready_generation=ready_generation,
            ),
            step,
        )


def replay_rolling_close_mean_targets_incremental(
    certification: CertifiedFeatureReplay,
    policy: RollingCloseMeanTargetPolicy,
) -> FeatureTargetReplayResult:
    """Derive decisions by advancing authenticated pending/visible state."""

    if type(certification) is not CertifiedFeatureReplay:
        raise ValueError(
            "incremental feature target replay requires exact certified feature evidence"
        )
    if type(policy) is not RollingCloseMeanTargetPolicy:
        raise ValueError("incremental feature target replay requires an exact target policy")
    runtime_pin = FeatureTargetRuntimePin._from_evidence(
        policy,
        certification.artifact,
        certification.receipt,
    )
    feature_result = certification.incremental_result
    visibility_proof = FeatureVisibilityProof._from_feature_result(
        feature_result,
        certification.receipt,
    )
    state = RollingCloseMeanTargetIncrementalState.initial(
        runtime_pin=runtime_pin,
        visibility_proof=visibility_proof,
    )
    steps: list[FeatureTargetReplayStep] = []
    for feature_step in feature_result.steps:
        state, step = state.advance(
            runtime_pin=runtime_pin,
            visibility_proof=visibility_proof,
            feature_step=feature_step,
            policy=policy,
        )
        steps.append(step)
    if state.next_sequence != len(feature_result.steps):
        raise ValueError("incremental feature target state did not consume its complete transcript")
    return FeatureTargetReplayResult._from_reducer(
        mode=FeatureComputationMode.INCREMENTAL,
        policy=policy,
        runtime_pin=runtime_pin,
        feature_result=feature_result,
        feature_receipt=certification.receipt,
        steps=tuple(steps),
    )


def certify_rolling_close_mean_target_parity(
    certification: CertifiedFeatureReplay,
    policy: RollingCloseMeanTargetPolicy,
) -> CertifiedFeatureTargetReplay:
    """Return target evidence only when the independent decision paths agree."""

    batch_result = replay_rolling_close_mean_targets_batch(certification, policy)
    incremental_result = replay_rolling_close_mean_targets_incremental(certification, policy)
    receipt = FeatureTargetParityReceipt._from_equal_results(batch_result, incremental_result)
    return CertifiedFeatureTargetReplay(
        feature_certification=certification,
        policy=policy,
        runtime_pin=batch_result.runtime_pin,
        batch_result=batch_result,
        incremental_result=incremental_result,
        receipt=receipt,
    )
