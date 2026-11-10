"""Immutable Phase 3 feature-decision and target-parity contracts."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from enum import StrEnum

from packages.domain.canonical import canonical_json_bytes, canonical_persisted_decimal
from packages.domain.decision import DecisionTrigger
from packages.domain.feature import (
    CertifiedFeatureReplay,
    FeatureArtifact,
    FeatureComputationMode,
    FeatureParityReceipt,
    FeatureReplayResult,
    FeatureReplayStep,
    FeatureSnapshot,
    FeatureStepStatus,
)
from packages.domain.identifiers import canonical_id
from packages.domain.market_batch import MarketBatch
from packages.domain.models import PositionTarget, TargetPortfolio

FEATURE_TARGET_CONTRACT_VERSION = "phase3-feature-target-v1"
REFERENCE_FEATURE_TARGET_STRATEGY_ID = "rolling-close-mean-cross"
REFERENCE_FEATURE_TARGET_STRATEGY_VERSION = "1.0.0"
MAX_TARGET_LIFETIME = timedelta(days=1)


class FeatureTargetStepStatus(StrEnum):
    """One source batch's explicit decision-consumer outcome."""

    SKIPPED_RESET = "skipped_reset"
    WAITING = "waiting"
    READY = "ready"


class FeatureTargetParityStatus(StrEnum):
    PASS = "pass"


class FeatureNotAvailableError(ValueError):
    """A decision attempted to inspect feature evidence that was not visible."""


class FeatureTargetParityError(ValueError):
    """Batch and incremental feature-target transcripts did not agree exactly."""


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_sha256(value: str, field_name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")


def _timedelta_microseconds(value: timedelta) -> int:
    return value.days * 86_400_000_000 + value.seconds * 1_000_000 + value.microseconds


@dataclass(frozen=True, slots=True)
class RollingCloseMeanTargetPolicy:
    """The bounded reference rule: long above the visible mean, flat otherwise."""

    long_quantity: Decimal
    target_lifetime: timedelta = timedelta(minutes=5)

    def __post_init__(self) -> None:
        if type(self.long_quantity) is not Decimal:
            raise ValueError("feature target quantity must be an exact Decimal")
        if (
            not self.long_quantity.is_finite()
            or self.long_quantity <= 0
            or self.long_quantity != self.long_quantity.to_integral_value()
        ):
            raise ValueError("feature target quantity must be positive and whole")
        if (
            type(self.target_lifetime) is not timedelta
            or self.target_lifetime <= timedelta(0)
            or self.target_lifetime > MAX_TARGET_LIFETIME
        ):
            raise ValueError("feature target lifetime must be positive and at most one day")
        object.__setattr__(
            self,
            "long_quantity",
            canonical_persisted_decimal(self.long_quantity, "feature target quantity"),
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                FEATURE_TARGET_CONTRACT_VERSION,
                "rolling-close-mean-target-policy",
                REFERENCE_FEATURE_TARGET_STRATEGY_ID,
                REFERENCE_FEATURE_TARGET_STRATEGY_VERSION,
                "latest_close_strictly_above_visible_mean",
                self.long_quantity,
                _timedelta_microseconds(self.target_lifetime),
            )
        )


@dataclass(frozen=True, slots=True, init=False)
class FeatureTargetRuntimePin:
    """One strategy configuration bound to exact certified feature evidence."""

    strategy_id: str
    strategy_version: str
    policy_sha256: str
    artifact_sha256: str
    feature_parity_receipt_sha256: str
    strategy_configuration_sha256: str = field(init=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("FeatureTargetRuntimePin is proof-constructed from certified evidence")

    @classmethod
    def _from_evidence(
        cls,
        policy: RollingCloseMeanTargetPolicy,
        artifact: FeatureArtifact,
        receipt: FeatureParityReceipt,
    ) -> FeatureTargetRuntimePin:
        if type(policy) is not RollingCloseMeanTargetPolicy:
            raise ValueError("feature target runtime pin requires an exact policy")
        if type(artifact) is not FeatureArtifact or type(receipt) is not FeatureParityReceipt:
            raise ValueError("feature target runtime pin requires exact feature evidence")
        if (
            receipt.artifact_sha256 != artifact.semantic_sha256
            or receipt.lineage_sha256 != artifact.lineage.semantic_sha256
        ):
            raise ValueError("feature target runtime pin received inconsistent feature evidence")
        instance = object.__new__(cls)
        values = {
            "strategy_id": REFERENCE_FEATURE_TARGET_STRATEGY_ID,
            "strategy_version": REFERENCE_FEATURE_TARGET_STRATEGY_VERSION,
            "policy_sha256": policy.semantic_sha256,
            "artifact_sha256": artifact.semantic_sha256,
            "feature_parity_receipt_sha256": receipt.semantic_sha256,
        }
        for field_name, value in values.items():
            object.__setattr__(instance, field_name, value)
        object.__setattr__(
            instance,
            "strategy_configuration_sha256",
            _sha256(instance._configuration_material()),
        )
        return instance

    def _configuration_material(self) -> tuple[object, ...]:
        return (
            FEATURE_TARGET_CONTRACT_VERSION,
            "feature-target-runtime-configuration",
            self.strategy_id,
            self.strategy_version,
            self.policy_sha256,
            self.artifact_sha256,
            self.feature_parity_receipt_sha256,
        )

    @property
    def semantic_sha256(self) -> str:
        return self.strategy_configuration_sha256


def _visibility_snapshots_by_sequence(
    feature_steps: tuple[FeatureReplayStep, ...],
) -> tuple[tuple[FeatureSnapshot, ...], ...]:
    """Build one linear canonical visibility oracle over the sealed transcript."""

    results: list[tuple[FeatureSnapshot, ...]] = []
    expected_instrument_ids: tuple[str, ...] = ()
    visible: dict[str, FeatureSnapshot] = {}
    next_pending_sequence = 0
    for sequence, step in enumerate(feature_steps):
        batch = step.source_batch
        if not batch.complete:
            expected_instrument_ids = ()
            visible.clear()
            next_pending_sequence = sequence + 1
            results.append(())
            continue
        if batch.watermark.expected_instrument_ids != expected_instrument_ids:
            expected_instrument_ids = batch.watermark.expected_instrument_ids
            visible.clear()
            next_pending_sequence = sequence
        while next_pending_sequence <= sequence:
            pending_step = feature_steps[next_pending_sequence]
            if not pending_step.snapshots:
                next_pending_sequence += 1
                continue
            if pending_step.snapshots[0].available_at > batch.as_of:
                break
            if any(snapshot.available_at > batch.as_of for snapshot in pending_step.snapshots):
                raise ValueError("feature step snapshots disagree on decision availability")
            for snapshot in pending_step.snapshots:
                visible[snapshot.instrument_id] = snapshot
            next_pending_sequence += 1
        results.append(
            tuple(
                visible[instrument_id]
                for instrument_id in expected_instrument_ids
                if instrument_id in visible
            )
        )
    return tuple(results)


@dataclass(frozen=True, slots=True, init=False)
class FeatureVisibilityProof:
    """Canonical per-trigger visibility derived from one parity-certified path."""

    feature_result: FeatureReplayResult
    feature_receipt: FeatureParityReceipt
    artifact_sha256: str
    lineage_sha256: str
    feature_transcript_sha256: str
    feature_receipt_sha256: str
    snapshots_by_sequence: tuple[tuple[FeatureSnapshot, ...], ...]
    proof_sha256: str = field(init=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("FeatureVisibilityProof is proof-constructed from feature evidence")

    @classmethod
    def _from_feature_result(
        cls,
        feature_result: FeatureReplayResult,
        feature_receipt: FeatureParityReceipt,
    ) -> FeatureVisibilityProof:
        if (
            type(feature_result) is not FeatureReplayResult
            or type(feature_receipt) is not FeatureParityReceipt
        ):
            raise ValueError("feature visibility requires exact parity-certified evidence")
        expected_result_sha256 = (
            feature_receipt.batch_result_sha256
            if feature_result.mode is FeatureComputationMode.BATCH
            else feature_receipt.incremental_result_sha256
        )
        if (
            feature_result.semantic_sha256 != expected_result_sha256
            or feature_result.transcript_sha256 != feature_receipt.transcript_sha256
            or feature_result.artifact.semantic_sha256 != feature_receipt.artifact_sha256
            or feature_result.artifact.lineage.semantic_sha256 != feature_receipt.lineage_sha256
        ):
            raise ValueError("feature visibility input is not bound to its parity receipt")
        instance = object.__new__(cls)
        object.__setattr__(instance, "feature_result", feature_result)
        object.__setattr__(instance, "feature_receipt", feature_receipt)
        object.__setattr__(instance, "artifact_sha256", feature_result.artifact.semantic_sha256)
        object.__setattr__(
            instance,
            "lineage_sha256",
            feature_result.artifact.lineage.semantic_sha256,
        )
        object.__setattr__(
            instance,
            "feature_transcript_sha256",
            feature_result.transcript_sha256,
        )
        object.__setattr__(
            instance,
            "feature_receipt_sha256",
            feature_receipt.semantic_sha256,
        )
        object.__setattr__(
            instance,
            "snapshots_by_sequence",
            _visibility_snapshots_by_sequence(feature_result.steps),
        )
        object.__setattr__(instance, "proof_sha256", _sha256(instance._semantic_material()))
        return instance

    def snapshots_for(self, sequence: int) -> tuple[FeatureSnapshot, ...]:
        if type(sequence) is not int or not 0 <= sequence < len(self.snapshots_by_sequence):
            raise ValueError("feature visibility sequence is outside its sealed transcript")
        return self.snapshots_by_sequence[sequence]

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            FEATURE_TARGET_CONTRACT_VERSION,
            "feature-visibility-proof",
            self.artifact_sha256,
            self.lineage_sha256,
            self.feature_transcript_sha256,
            self.feature_receipt_sha256,
            tuple(
                tuple(snapshot.snapshot_id for snapshot in snapshots)
                for snapshots in self.snapshots_by_sequence
            ),
        )

    @property
    def semantic_sha256(self) -> str:
        return self.proof_sha256


@dataclass(frozen=True, slots=True, init=False)
class FeatureDecisionContext:
    """The parity-certified feature subset visible at one complete batch trigger."""

    decision_trigger: DecisionTrigger
    source_batch: MarketBatch
    artifact: FeatureArtifact
    runtime_pin: FeatureTargetRuntimePin
    visibility_proof_sha256: str
    snapshots: tuple[FeatureSnapshot, ...]
    context_sha256: str = field(init=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("FeatureDecisionContext is proof-constructed by target replay")

    @classmethod
    def _from_visible_snapshots(
        cls,
        *,
        visibility_proof: FeatureVisibilityProof,
        sequence: int,
        runtime_pin: FeatureTargetRuntimePin,
        snapshots: tuple[FeatureSnapshot, ...],
    ) -> FeatureDecisionContext:
        if type(visibility_proof) is not FeatureVisibilityProof:
            raise ValueError("feature decision context requires an exact visibility proof")
        if type(runtime_pin) is not FeatureTargetRuntimePin:
            raise ValueError("feature decision context requires an exact runtime pin")
        expected_snapshots = visibility_proof.snapshots_for(sequence)
        source_batch = visibility_proof.feature_result.steps[sequence].source_batch
        if (
            runtime_pin.artifact_sha256 != visibility_proof.artifact_sha256
            or runtime_pin.feature_parity_receipt_sha256 != visibility_proof.feature_receipt_sha256
        ):
            raise ValueError("feature decision context changed certified feature evidence")
        instance = object.__new__(cls)
        object.__setattr__(
            instance, "decision_trigger", DecisionTrigger.from_market_batch(source_batch)
        )
        object.__setattr__(instance, "source_batch", source_batch)
        object.__setattr__(instance, "artifact", visibility_proof.feature_result.artifact)
        object.__setattr__(instance, "runtime_pin", runtime_pin)
        object.__setattr__(
            instance,
            "visibility_proof_sha256",
            visibility_proof.semantic_sha256,
        )
        object.__setattr__(instance, "snapshots", snapshots)
        instance._validate()
        if len(snapshots) != len(expected_snapshots) or any(
            snapshot is not expected
            for snapshot, expected in zip(snapshots, expected_snapshots, strict=True)
        ):
            raise ValueError("feature decision context is not the canonical visible prefix")
        object.__setattr__(instance, "context_sha256", _sha256(instance._semantic_material()))
        return instance

    def _validate(self) -> None:
        if type(self.source_batch) is not MarketBatch or not self.source_batch.complete:
            raise ValueError("feature decision context requires a complete MarketBatch")
        if type(self.artifact) is not FeatureArtifact:
            raise ValueError("feature decision context requires an exact feature artifact")
        if type(self.runtime_pin) is not FeatureTargetRuntimePin:
            raise ValueError("feature decision context requires an exact runtime pin")
        _require_sha256(self.visibility_proof_sha256, "feature visibility proof digest")
        self.decision_trigger.require_market_batch(self.source_batch)
        if type(self.snapshots) is not tuple or any(
            type(snapshot) is not FeatureSnapshot for snapshot in self.snapshots
        ):
            raise ValueError("feature decision snapshots must be immutable exact values")
        instrument_ids = tuple(snapshot.instrument_id for snapshot in self.snapshots)
        if instrument_ids != tuple(sorted(set(instrument_ids))):
            raise ValueError("feature decision snapshots must be unique and canonically ordered")
        expected_ids = set(self.source_batch.watermark.expected_instrument_ids)
        if not set(instrument_ids) <= expected_ids:
            raise ValueError("feature decision snapshots include an unexpected instrument")
        for snapshot in self.snapshots:
            if snapshot.artifact is not self.artifact:
                raise ValueError("feature decision snapshot changed artifact identity")
            if snapshot.source_batch.as_of > self.decision_trigger.as_of:
                raise FeatureNotAvailableError(
                    "feature snapshot source batch occurs after the decision trigger"
                )
            if snapshot.available_at > self.decision_trigger.as_of:
                raise FeatureNotAvailableError(
                    "feature snapshot is not available at the decision trigger"
                )

    @property
    def as_of(self) -> datetime:
        return self.decision_trigger.as_of

    @property
    def feature_snapshot_ids(self) -> tuple[str, ...]:
        return tuple(snapshot.snapshot_id for snapshot in self.snapshots)

    def snapshot_for(self, instrument_id: str) -> FeatureSnapshot:
        for snapshot in self.snapshots:
            if snapshot.instrument_id == instrument_id:
                return snapshot
        raise FeatureNotAvailableError(
            f"no parity-certified feature snapshot is available for {instrument_id!r}"
        )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            FEATURE_TARGET_CONTRACT_VERSION,
            "feature-decision-context",
            self.decision_trigger.semantic_sha256,
            self.source_batch.semantic_sha256,
            self.runtime_pin.semantic_sha256,
            self.visibility_proof_sha256,
            self.feature_snapshot_ids,
        )

    @property
    def semantic_sha256(self) -> str:
        return self.context_sha256


@dataclass(frozen=True, slots=True, init=False)
class FeatureTargetDecision:
    """One target bound to the exact visible feature evidence that caused it."""

    context: FeatureDecisionContext
    target: TargetPortfolio
    decision_sha256: str = field(init=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("FeatureTargetDecision is proof-constructed by target replay")

    @classmethod
    def _from_context(
        cls,
        *,
        context: FeatureDecisionContext,
        policy: RollingCloseMeanTargetPolicy,
        rebalance_generation: int,
    ) -> FeatureTargetDecision:
        if type(context) is not FeatureDecisionContext:
            raise ValueError("feature target decision requires an exact context")
        if type(policy) is not RollingCloseMeanTargetPolicy:
            raise ValueError("feature target decision requires an exact policy")
        if policy.semantic_sha256 != context.runtime_pin.policy_sha256:
            raise ValueError("feature target decision changed its runtime policy")
        expected_ids = context.source_batch.watermark.expected_instrument_ids
        if tuple(snapshot.instrument_id for snapshot in context.snapshots) != expected_ids:
            raise FeatureNotAvailableError(
                "a target requires one visible feature snapshot per expected instrument"
            )
        targets = tuple(
            PositionTarget(
                instrument_id=instrument_id,
                symbol=context.source_batch.event_for(instrument_id).symbol,
                quantity=(
                    policy.long_quantity
                    if context.source_batch.event_for(instrument_id).close_price
                    > context.snapshot_for(instrument_id).value
                    else Decimal(0)
                ),
            )
            for instrument_id in expected_ids
        )
        target = TargetPortfolio(
            target_id=canonical_id(
                "feature-target",
                context.runtime_pin.semantic_sha256,
                context.decision_trigger.semantic_sha256,
                context.feature_snapshot_ids,
                tuple((item.instrument_id, item.quantity) for item in targets),
                rebalance_generation,
            ),
            strategy_id=context.runtime_pin.strategy_id,
            strategy_version=context.runtime_pin.strategy_version,
            strategy_configuration_sha256=(context.runtime_pin.strategy_configuration_sha256),
            decision_trigger=context.decision_trigger,
            as_of=context.decision_trigger.as_of,
            expires_at=context.decision_trigger.as_of + policy.target_lifetime,
            targets=targets,
            rebalance_generation=rebalance_generation,
        )
        instance = object.__new__(cls)
        object.__setattr__(instance, "context", context)
        object.__setattr__(instance, "target", target)
        object.__setattr__(instance, "decision_sha256", _sha256(instance._semantic_material()))
        return instance

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            FEATURE_TARGET_CONTRACT_VERSION,
            "feature-target-decision",
            self.context.semantic_sha256,
            self.target.semantic_sha256,
        )

    @property
    def semantic_sha256(self) -> str:
        return self.decision_sha256


@dataclass(frozen=True, slots=True)
class FeatureTargetReplayStep:
    """One audited reset, waiting context, or feature-derived target."""

    sequence: int
    source_feature_step: FeatureReplayStep
    status: FeatureTargetStepStatus
    context: FeatureDecisionContext | None = None
    decision: FeatureTargetDecision | None = None

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence < 0:
            raise ValueError("feature target step sequence must be non-negative")
        if type(self.source_feature_step) is not FeatureReplayStep:
            raise ValueError("feature target step requires an exact feature step")
        if self.source_feature_step.sequence != self.sequence:
            raise ValueError("feature target and feature step sequences must agree")
        if type(self.status) is not FeatureTargetStepStatus:
            raise ValueError("feature target step status must be exact")
        if self.status is FeatureTargetStepStatus.SKIPPED_RESET:
            if (
                self.source_feature_step.status is not FeatureStepStatus.SKIPPED_RESET
                or self.context is not None
                or self.decision is not None
            ):
                raise ValueError("SKIPPED_RESET cannot expose a context or target")
            return
        if self.source_feature_step.status is FeatureStepStatus.SKIPPED_RESET:
            raise ValueError("a skipped feature step cannot reach a decision consumer")
        if type(self.context) is not FeatureDecisionContext:
            raise ValueError("a complete feature target step requires an exact context")
        if self.context.source_batch != self.source_feature_step.source_batch:
            raise ValueError("feature target context changed its source batch")
        expected_ids = self.source_feature_step.source_batch.watermark.expected_instrument_ids
        visible_ids = tuple(snapshot.instrument_id for snapshot in self.context.snapshots)
        if self.status is FeatureTargetStepStatus.WAITING:
            if visible_ids == expected_ids or self.decision is not None:
                raise ValueError("WAITING requires incomplete visible features and no target")
        elif (
            visible_ids != expected_ids
            or type(self.decision) is not FeatureTargetDecision
            or self.decision.context != self.context
        ):
            raise ValueError("READY requires a target from every expected visible feature")

    @property
    def target(self) -> TargetPortfolio | None:
        return None if self.decision is None else self.decision.target

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                FEATURE_TARGET_CONTRACT_VERSION,
                "feature-target-replay-step",
                self.sequence,
                self.source_feature_step.semantic_sha256,
                self.status.value,
                None if self.context is None else self.context.semantic_sha256,
                None if self.decision is None else self.decision.semantic_sha256,
            )
        )


@dataclass(frozen=True, slots=True, init=False)
class FeatureTargetReplayResult:
    """Canonical target-decision transcript from one feature computation path."""

    mode: FeatureComputationMode
    policy: RollingCloseMeanTargetPolicy
    runtime_pin: FeatureTargetRuntimePin
    feature_result: FeatureReplayResult
    feature_receipt: FeatureParityReceipt
    steps: tuple[FeatureTargetReplayStep, ...]

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("FeatureTargetReplayResult is proof-constructed by target replay")

    @classmethod
    def _from_reducer(
        cls,
        *,
        mode: FeatureComputationMode,
        policy: RollingCloseMeanTargetPolicy,
        runtime_pin: FeatureTargetRuntimePin,
        feature_result: FeatureReplayResult,
        feature_receipt: FeatureParityReceipt,
        steps: tuple[FeatureTargetReplayStep, ...],
    ) -> FeatureTargetReplayResult:
        instance = object.__new__(cls)
        object.__setattr__(instance, "mode", mode)
        object.__setattr__(instance, "policy", policy)
        object.__setattr__(instance, "runtime_pin", runtime_pin)
        object.__setattr__(instance, "feature_result", feature_result)
        object.__setattr__(instance, "feature_receipt", feature_receipt)
        object.__setattr__(instance, "steps", steps)
        instance._validate()
        return instance

    def _validate(self) -> None:
        if (
            type(self.feature_result) is not FeatureReplayResult
            or type(self.feature_receipt) is not FeatureParityReceipt
        ):
            raise ValueError("feature target replay requires exact feature evidence")
        if (
            type(self.mode) is not FeatureComputationMode
            or self.feature_result.mode is not self.mode
        ):
            raise ValueError("feature target mode must match its feature computation path")
        if type(self.policy) is not RollingCloseMeanTargetPolicy:
            raise ValueError("feature target replay requires an exact policy")
        expected_pin = FeatureTargetRuntimePin._from_evidence(
            self.policy,
            self.feature_result.artifact,
            self.feature_receipt,
        )
        if self.runtime_pin != expected_pin:
            raise ValueError("feature target replay changed its runtime configuration")
        expected_result_sha256 = (
            self.feature_receipt.batch_result_sha256
            if self.mode is FeatureComputationMode.BATCH
            else self.feature_receipt.incremental_result_sha256
        )
        if (
            self.feature_result.semantic_sha256 != expected_result_sha256
            or self.feature_result.transcript_sha256 != self.feature_receipt.transcript_sha256
        ):
            raise ValueError("feature target replay is not bound to its parity-certified path")
        if type(self.steps) is not tuple or len(self.steps) != len(self.feature_result.steps):
            raise ValueError("feature target replay must classify every feature step")
        visibility_proof = FeatureVisibilityProof._from_feature_result(
            self.feature_result,
            self.feature_receipt,
        )
        ready_generation = 0
        for sequence, (step, feature_step) in enumerate(
            zip(self.steps, self.feature_result.steps, strict=True)
        ):
            if (
                type(step) is not FeatureTargetReplayStep
                or step.sequence != sequence
                or step.source_feature_step != feature_step
            ):
                raise ValueError("feature target step chain conflicts with feature replay order")
            if not feature_step.source_batch.complete:
                continue
            expected_visible = visibility_proof.snapshots_for(sequence)
            if (
                step.context is None
                or step.context.visibility_proof_sha256 != visibility_proof.semantic_sha256
                or step.context.snapshots != expected_visible
            ):
                raise ValueError(
                    "feature target context does not expose the canonical visible prefix"
                )
            expected_ids = feature_step.source_batch.watermark.expected_instrument_ids
            visible_ids = tuple(snapshot.instrument_id for snapshot in expected_visible)
            if visible_ids != expected_ids:
                if step.status is not FeatureTargetStepStatus.WAITING:
                    raise ValueError("incomplete visible features must produce WAITING")
                continue
            ready_generation += 1
            expected_decision = FeatureTargetDecision._from_context(
                context=step.context,
                policy=self.policy,
                rebalance_generation=ready_generation,
            )
            if (
                step.status is not FeatureTargetStepStatus.READY
                or step.decision != expected_decision
            ):
                raise ValueError("feature target decision conflicts with the reference policy")

    @property
    def targets(self) -> tuple[TargetPortfolio, ...]:
        return tuple(step.target for step in self.steps if step.target is not None)

    @property
    def decisions(self) -> tuple[FeatureTargetDecision, ...]:
        return tuple(step.decision for step in self.steps if step.decision is not None)

    @property
    def transcript_sha256(self) -> str:
        return _sha256(
            (
                FEATURE_TARGET_CONTRACT_VERSION,
                "feature-target-transcript",
                self.runtime_pin.semantic_sha256,
                self.feature_result.transcript_sha256,
                self.feature_receipt.semantic_sha256,
                tuple(step.semantic_sha256 for step in self.steps),
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                FEATURE_TARGET_CONTRACT_VERSION,
                "feature-target-replay-result",
                self.mode.value,
                self.transcript_sha256,
            )
        )


@dataclass(frozen=True, slots=True, init=False)
class FeatureTargetParityReceipt:
    """Proof constructed only after exact batch/incremental target equality."""

    artifact_sha256: str
    lineage_sha256: str
    feature_parity_receipt_sha256: str
    runtime_pin_sha256: str
    batch_result_sha256: str
    incremental_result_sha256: str
    transcript_sha256: str
    step_sha256s: tuple[str, ...]
    decision_sha256s: tuple[str, ...]
    target_ids: tuple[str, ...]
    step_count: int
    target_count: int
    status: FeatureTargetParityStatus
    receipt_sha256: str = field(init=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("FeatureTargetParityReceipt is proof-constructed by differential replay")

    @classmethod
    def _from_equal_results(
        cls,
        batch_result: FeatureTargetReplayResult,
        incremental_result: FeatureTargetReplayResult,
    ) -> FeatureTargetParityReceipt:
        if (
            type(batch_result) is not FeatureTargetReplayResult
            or batch_result.mode is not FeatureComputationMode.BATCH
            or type(incremental_result) is not FeatureTargetReplayResult
            or incremental_result.mode is not FeatureComputationMode.INCREMENTAL
        ):
            raise FeatureTargetParityError(
                "feature target parity requires exact batch and incremental results"
            )
        if (
            batch_result.policy != incremental_result.policy
            or batch_result.runtime_pin != incremental_result.runtime_pin
            or batch_result.feature_receipt != incremental_result.feature_receipt
            or batch_result.feature_result.artifact != incremental_result.feature_result.artifact
            or batch_result.steps != incremental_result.steps
            or batch_result.transcript_sha256 != incremental_result.transcript_sha256
        ):
            raise FeatureTargetParityError(
                "batch and incremental feature target transcripts diverged"
            )
        instance = object.__new__(cls)
        decisions = batch_result.decisions
        values = {
            "artifact_sha256": batch_result.runtime_pin.artifact_sha256,
            "lineage_sha256": batch_result.feature_result.artifact.lineage.semantic_sha256,
            "feature_parity_receipt_sha256": batch_result.feature_receipt.semantic_sha256,
            "runtime_pin_sha256": batch_result.runtime_pin.semantic_sha256,
            "batch_result_sha256": batch_result.semantic_sha256,
            "incremental_result_sha256": incremental_result.semantic_sha256,
            "transcript_sha256": batch_result.transcript_sha256,
            "step_sha256s": tuple(step.semantic_sha256 for step in batch_result.steps),
            "decision_sha256s": tuple(decision.semantic_sha256 for decision in decisions),
            "target_ids": tuple(decision.target.target_id for decision in decisions),
            "step_count": len(batch_result.steps),
            "target_count": len(decisions),
            "status": FeatureTargetParityStatus.PASS,
        }
        for field_name, value in values.items():
            object.__setattr__(instance, field_name, value)
        object.__setattr__(instance, "receipt_sha256", _sha256(instance._semantic_material()))
        return instance

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            FEATURE_TARGET_CONTRACT_VERSION,
            "feature-target-parity-receipt",
            self.artifact_sha256,
            self.lineage_sha256,
            self.feature_parity_receipt_sha256,
            self.runtime_pin_sha256,
            self.batch_result_sha256,
            self.incremental_result_sha256,
            self.transcript_sha256,
            self.step_sha256s,
            self.decision_sha256s,
            self.target_ids,
            self.step_count,
            self.target_count,
            self.status.value,
        )

    @property
    def semantic_sha256(self) -> str:
        return self.receipt_sha256


@dataclass(frozen=True, slots=True)
class CertifiedFeatureTargetReplay:
    """Both target reducer transcripts plus their successful parity proof."""

    feature_certification: CertifiedFeatureReplay
    policy: RollingCloseMeanTargetPolicy
    runtime_pin: FeatureTargetRuntimePin
    batch_result: FeatureTargetReplayResult
    incremental_result: FeatureTargetReplayResult
    receipt: FeatureTargetParityReceipt

    def __post_init__(self) -> None:
        if (
            type(self.feature_certification) is not CertifiedFeatureReplay
            or type(self.policy) is not RollingCloseMeanTargetPolicy
            or type(self.runtime_pin) is not FeatureTargetRuntimePin
            or type(self.batch_result) is not FeatureTargetReplayResult
            or type(self.incremental_result) is not FeatureTargetReplayResult
            or type(self.receipt) is not FeatureTargetParityReceipt
        ):
            raise ValueError("certified feature target replay requires exact evidence")
        expected_pin = FeatureTargetRuntimePin._from_evidence(
            self.policy,
            self.feature_certification.artifact,
            self.feature_certification.receipt,
        )
        expected_receipt = FeatureTargetParityReceipt._from_equal_results(
            self.batch_result,
            self.incremental_result,
        )
        if (
            self.runtime_pin != expected_pin
            or self.batch_result.feature_result != self.feature_certification.batch_result
            or self.incremental_result.feature_result
            != self.feature_certification.incremental_result
            or self.batch_result.feature_receipt != self.feature_certification.receipt
            or self.incremental_result.feature_receipt != self.feature_certification.receipt
            or self.receipt != expected_receipt
        ):
            raise ValueError("certified feature target replay evidence is inconsistent")

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                FEATURE_TARGET_CONTRACT_VERSION,
                "certified-feature-target-replay",
                self.feature_certification.semantic_sha256,
                self.policy.semantic_sha256,
                self.runtime_pin.semantic_sha256,
                self.batch_result.semantic_sha256,
                self.incremental_result.semantic_sha256,
                self.receipt.semantic_sha256,
            )
        )
