"""Manifest-authenticated construction of the bounded Phase 3 feature proof."""

from __future__ import annotations

from datetime import timedelta

from packages.datasets.replay_tape import (
    MANIFEST_REPLAY_TAPE_CONTRACT_VERSION,
    WATERMARK_POLICY_VERSION,
    ManifestReplayTape,
    replay_manifest_tape,
)
from packages.domain.feature import AuthenticatedFeatureReplayInput, CertifiedFeatureReplay
from packages.domain.feature_replay import (
    certify_rolling_close_mean_parity,
    create_rolling_close_mean_artifact,
)
from packages.domain.feature_target import (
    CertifiedFeatureTargetReplay,
    RollingCloseMeanTargetPolicy,
)
from packages.domain.feature_target_replay import certify_rolling_close_mean_target_parity
from packages.domain.replay_manifest import (
    DatasetPartitionPin,
    DatasetPin,
    EnginePin,
    ReplayPlanPin,
    ReplayRunManifest,
)


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


def certify_manifest_rolling_close_mean(
    tape: ManifestReplayTape,
    *,
    replay_run_manifest: ReplayRunManifest,
    implementation_sha256: str,
    publication_lag: timedelta,
) -> CertifiedFeatureReplay:
    """Authenticate one sealed manifest tape, then certify feature parity."""

    if type(tape) is not ManifestReplayTape:
        raise ValueError("manifest feature certification requires an exact ManifestReplayTape")
    if type(replay_run_manifest) is not ReplayRunManifest:
        raise ValueError("manifest feature certification requires a sealed replay-run manifest")
    tape._validate()
    replay = replay_manifest_tape(tape)
    expected_manifest = ReplayRunManifest.from_replay_result(
        dataset=_dataset_pin(tape),
        plan=_plan_pin(tape),
        engine=EnginePin(
            tape_adapter_version=MANIFEST_REPLAY_TAPE_CONTRACT_VERSION,
            watermark_policy_version=WATERMARK_POLICY_VERSION,
        ),
        runtime=replay_run_manifest.runtime,
        result=replay,
        source_tape_sha256=tape.semantic_sha256,
    )
    if replay_run_manifest != expected_manifest:
        raise ValueError("sealed replay-run manifest does not authenticate the supplied tape")
    source = AuthenticatedFeatureReplayInput._from_verified_manifest_tape(
        manifest=replay_run_manifest,
        replay=replay,
    )
    artifact = create_rolling_close_mean_artifact(
        source=source,
        implementation_sha256=implementation_sha256,
        publication_lag=publication_lag,
    )
    return certify_rolling_close_mean_parity(artifact, replay)


def certify_manifest_rolling_close_mean_targets(
    tape: ManifestReplayTape,
    *,
    replay_run_manifest: ReplayRunManifest,
    implementation_sha256: str,
    publication_lag: timedelta,
    target_policy: RollingCloseMeanTargetPolicy,
) -> CertifiedFeatureTargetReplay:
    """Authenticate one tape and certify both feature and target parity."""

    feature_certification = certify_manifest_rolling_close_mean(
        tape,
        replay_run_manifest=replay_run_manifest,
        implementation_sha256=implementation_sha256,
        publication_lag=publication_lag,
    )
    return certify_rolling_close_mean_target_parity(
        feature_certification,
        target_policy,
    )
