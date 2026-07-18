"""Compose a verified manifest tape into one atomically sealed replay record."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from packages.datasets.replay_tape import (
    MANIFEST_REPLAY_TAPE_CONTRACT_VERSION,
    WATERMARK_POLICY_VERSION,
    ManifestReplayTape,
    replay_manifest_tape,
)
from packages.domain.replay import ReplayResult
from packages.domain.replay_manifest import (
    DatasetPartitionPin,
    DatasetPin,
    EnginePin,
    ReplayPlanPin,
    ReplayRunManifest,
    RuntimePin,
)


class ReplayRunManifestPublisher(Protocol):
    """Rehydrate replay input and atomically persist sealed-success evidence."""

    def publish(self, manifest: ReplayRunManifest, tape: ManifestReplayTape) -> bool: ...


@dataclass(frozen=True, slots=True)
class SealedManifestReplay:
    """In-memory replay evidence plus its immutable publication outcome."""

    result: ReplayResult
    manifest: ReplayRunManifest
    first_publication: bool


def _dataset_pin(tape: ManifestReplayTape) -> DatasetPin:
    return DatasetPin(
        manifest_id=tape.manifest_id,
        manifest_sha256=tape.manifest_hash,
        source_tape_sha256=tape.semantic_sha256,
        source_id=tape.source_id,
        source_kind=tape.source_kind,
        schema_version=tape.schema_version,
        price_basis=tape.price_basis.value,
        revision_policy=tape.revision_policy,
        calendar_version=tape.plan.calendar_version,
        calendar_sha256=tape.plan.calendar_hash,
        calendar_hash_version=tape.plan.calendar_hash_version,
        tzdata_version=tape.calendar_tzdata_version,
        universe_version=tape.plan.universe_version,
        universe_sha256=tape.plan.universe_hash,
        universe_hash_version=tape.plan.universe_hash_version,
        corporate_action_version=tape.corporate_action_version,
        corporate_action_sha256=tape.corporate_action_hash,
        corporate_action_hash_version=tape.corporate_action_hash_version,
        row_count=tape.row_count,
        partitions=tuple(
            DatasetPartitionPin(
                ordinal=partition.ordinal,
                partition_id=partition.partition_id,
                object_id=partition.object_id,
                object_key=partition.object_key,
                format=partition.format,
                byte_sha256=partition.byte_checksum,
                semantic_sha256=partition.semantic_checksum,
                semantic_checksum_version=partition.semantic_checksum_version,
                size_bytes=partition.size_bytes,
                row_count=partition.row_count,
                event_time_start=partition.event_time_start,
                event_time_end=partition.event_time_end,
                available_at_start=partition.available_at_start,
                available_at_end=partition.available_at_end,
            )
            for partition in tape.partitions
        ),
    )


def _plan_pin(tape: ManifestReplayTape) -> ReplayPlanPin:
    first_watermark = tape.plan.watermarks[0]
    return ReplayPlanPin(
        coverage_start=tape.plan.event_time_start,
        coverage_end=tape.plan.event_time_end,
        interval=tape.plan.interval.value,
        decision_lag=tape.plan.decision_lag,
        revision_policy=tape.plan.revision_policy,
        missing_data_policy=first_watermark.missing_data_policy,
        late_event_policy=first_watermark.late_event_policy,
        expected_instrument_ids=tape.plan.expected_instrument_ids,
        watermark_count=len(tape.plan.watermarks),
        watermarks_sha256=tape.plan.watermarks_sha256,
    )


def execute_and_seal_manifest_replay(
    *,
    tape: ManifestReplayTape,
    runtime: RuntimePin,
    repository: ReplayRunManifestPublisher,
) -> SealedManifestReplay:
    """Replay completely before publishing one immutable sealed-success row.

    No pending, running, failed, or canceled lifecycle is created in Phase 2A.
    Any tape, policy, replay, or persistence failure therefore leaves no run
    manifest. The publisher must independently rehydrate the supplied tape from
    its pinned catalog/object data before accepting it. Strategy callbacks and
    external side effects are intentionally outside this evidence-only workflow.
    """

    if type(tape) is not ManifestReplayTape:
        raise ValueError("manifest replay requires an exact ManifestReplayTape")
    if type(runtime) is not RuntimePin:
        raise ValueError("manifest replay requires an exact RuntimePin")
    result = replay_manifest_tape(tape)
    dataset = _dataset_pin(tape)
    manifest = ReplayRunManifest.from_replay_result(
        dataset=dataset,
        plan=_plan_pin(tape),
        engine=EnginePin(
            tape_adapter_version=MANIFEST_REPLAY_TAPE_CONTRACT_VERSION,
            watermark_policy_version=WATERMARK_POLICY_VERSION,
        ),
        runtime=runtime,
        result=result,
        source_tape_sha256=tape.semantic_sha256,
    )
    first_publication = repository.publish(manifest, tape)
    return SealedManifestReplay(
        result=result,
        manifest=manifest,
        first_publication=first_publication,
    )
