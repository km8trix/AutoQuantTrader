"""Manifest-pinned, all-revision RawBar input for deterministic replay."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy.engine import Engine

from packages.datasets.parquet import (
    NORMALIZED_BAR_SCHEMA,
    LocalParquetObjectStore,
    canonicalize_rows,
    parquet_semantic_checksum_version,
)
from packages.datasets.reader import DatasetDecodeError, _bar
from packages.domain.canonical import canonical_json_bytes
from packages.domain.identifiers import canonical_id
from packages.domain.market_batch import MarketWatermark, ReplayRevisionPolicy
from packages.domain.models import MarketEvent
from packages.domain.replay import CompleteBatchCallback, ReplayResult, replay_market_events
from packages.market_data import BarInterval, PriceBasis, RawBar
from packages.persistence.market_data import (
    ManifestObjects,
    ManifestPartitionObject,
    SqlMarketDataCatalog,
)

MANIFEST_REPLAY_TAPE_CONTRACT_VERSION = "phase2-manifest-replay-tape-v1"
WATERMARK_POLICY_VERSION = "phase2-reference-watermark-v1"
MAX_REPLAY_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_REPLAY_ROWS = 5_000_000
MAX_REPLAY_WATERMARKS = 250_000
MAX_REPLAY_PARTITIONS = 32
MAX_REPLAY_EXPECTED_INSTRUMENTS = 128
_ALLOWED_SOURCE_KINDS = frozenset({"synthetic_fixture", "recorded_fixture"})


def _require_utc(value: datetime, field_name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{field_name} must be UTC")


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _partition_semantics(partition: ManifestPartitionObject) -> tuple[object, ...]:
    return (
        partition.ordinal,
        partition.partition_id,
        partition.object_id,
        partition.object_key,
        partition.byte_checksum,
        partition.semantic_checksum,
        partition.semantic_checksum_version,
        partition.format,
        partition.size_bytes,
        partition.row_count,
        partition.event_time_start,
        partition.event_time_end,
        partition.available_at_start,
        partition.available_at_end,
    )


def _bar_semantics(bar: RawBar) -> tuple[object, ...]:
    return (
        bar.observation_id,
        bar.event_revision_id,
        bar.security_id,
        bar.source_id,
        bar.source_record_id,
        bar.schema_version,
        bar.payload_sha256,
        bar.symbol,
        bar.venue,
        bar.interval,
        bar.interval_start,
        bar.interval_end,
        bar.event_time,
        bar.vendor_published_at,
        bar.available_at,
        bar.ingested_at,
        bar.session_label,
        bar.open_price,
        bar.high_price,
        bar.low_price,
        bar.close_price,
        bar.volume,
        bar.revision,
        bar.capture_mode,
        bar.price_basis,
        bar.source_sequence,
        bar.received_at,
        bar.supersedes_event_revision_id,
        bar.trade_count,
    )


def market_event_from_raw_bar(bar: RawBar) -> MarketEvent:
    """Map one canonical RawBar revision without changing its causal identity."""

    if type(bar) is not RawBar:
        raise ValueError("replay tape facts must be exact RawBar values")
    return MarketEvent(
        event_id=bar.event_revision_id,
        instrument_id=bar.security_id,
        symbol=bar.symbol,
        event_time=bar.event_time,
        available_at=bar.available_at,
        close_price=bar.close_price,
        source=bar.source_id,
        source_sequence=bar.source_sequence,
        observation_id=bar.observation_id,
        revision=bar.revision,
        supersedes_event_revision_id=bar.supersedes_event_revision_id,
    )


@dataclass(frozen=True, slots=True, init=False)
class ReplayTapePlan:
    """Immutable decision schedule derived from pinned reference data, never rows."""

    manifest_id: str
    manifest_hash: str
    calendar_version: str
    calendar_hash: str
    calendar_hash_version: str
    calendar_tzdata_version: str
    universe_version: str
    universe_hash: str
    universe_hash_version: str
    event_time_start: datetime
    event_time_end: datetime
    interval: BarInterval
    decision_lag: timedelta
    revision_policy: ReplayRevisionPolicy
    watermarks: tuple[MarketWatermark, ...]

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("ReplayTapePlan is proof-constructed by build_replay_tape_plan")

    @classmethod
    def _from_verified_references(
        cls,
        *,
        manifest_id: str,
        manifest_hash: str,
        calendar_version: str,
        calendar_hash: str,
        calendar_hash_version: str,
        calendar_tzdata_version: str,
        universe_version: str,
        universe_hash: str,
        universe_hash_version: str,
        event_time_start: datetime,
        event_time_end: datetime,
        interval: BarInterval,
        decision_lag: timedelta,
        revision_policy: ReplayRevisionPolicy,
        watermarks: tuple[MarketWatermark, ...],
    ) -> ReplayTapePlan:
        instance = object.__new__(cls)
        values = {
            "manifest_id": manifest_id,
            "manifest_hash": manifest_hash,
            "calendar_version": calendar_version,
            "calendar_hash": calendar_hash,
            "calendar_hash_version": calendar_hash_version,
            "calendar_tzdata_version": calendar_tzdata_version,
            "universe_version": universe_version,
            "universe_hash": universe_hash,
            "universe_hash_version": universe_hash_version,
            "event_time_start": event_time_start,
            "event_time_end": event_time_end,
            "interval": interval,
            "decision_lag": decision_lag,
            "revision_policy": revision_policy,
            "watermarks": watermarks,
        }
        for field_name, value in values.items():
            object.__setattr__(instance, field_name, value)
        instance._validate()
        return instance

    def _validate(self) -> None:
        for value, field_name in (
            (self.manifest_id, "manifest_id"),
            (self.manifest_hash, "manifest_hash"),
            (self.calendar_version, "calendar_version"),
            (self.calendar_hash, "calendar_hash"),
            (self.calendar_hash_version, "calendar_hash_version"),
            (self.calendar_tzdata_version, "calendar_tzdata_version"),
            (self.universe_version, "universe_version"),
            (self.universe_hash, "universe_hash"),
            (self.universe_hash_version, "universe_hash_version"),
        ):
            if not value or value != value.strip():
                raise ValueError(f"{field_name} must be non-empty and trimmed")
        _require_utc(self.event_time_start, "event_time_start")
        _require_utc(self.event_time_end, "event_time_end")
        if self.event_time_end < self.event_time_start:
            raise ValueError("event_time_end cannot precede event_time_start")
        if not isinstance(self.interval, BarInterval):
            raise ValueError("replay tape interval is unsupported")
        if type(self.decision_lag) is not timedelta or self.decision_lag < timedelta(0):
            raise ValueError("decision_lag must be a non-negative timedelta")
        if not isinstance(self.revision_policy, ReplayRevisionPolicy):
            raise ValueError("replay tape revision policy is unsupported")
        if type(self.watermarks) is not tuple:
            raise ValueError("replay tape watermarks must be an immutable tuple")
        if not self.watermarks or len(self.watermarks) > MAX_REPLAY_WATERMARKS:
            raise ValueError("replay tape watermark count is outside the bounded contract")
        if any(type(watermark) is not MarketWatermark for watermark in self.watermarks):
            raise ValueError("replay tape watermarks must contain immutable MarketWatermark values")
        event_times = tuple(watermark.event_time_through for watermark in self.watermarks)
        if event_times != tuple(sorted(set(event_times))):
            raise ValueError("replay tape watermarks must be unique and event-time ordered")
        if event_times[0] != self.event_time_start or event_times[-1] != self.event_time_end:
            raise ValueError("replay tape coverage endpoints must be included exactly")
        for watermark in self.watermarks:
            if len(watermark.expected_instrument_ids) > MAX_REPLAY_EXPECTED_INSTRUMENTS:
                raise ValueError("replay watermark exceeds the expected-instrument bound")
            if watermark.revision_policy is not self.revision_policy:
                raise ValueError("watermark revision policy must match the manifest")
            if watermark.closed_at - watermark.event_time_through != self.decision_lag:
                raise ValueError("watermark closure must use the explicit decision_lag")

    @property
    def expected_instrument_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    instrument_id
                    for watermark in self.watermarks
                    for instrument_id in watermark.expected_instrument_ids
                }
            )
        )

    @property
    def watermarks_sha256(self) -> str:
        return _sha256(
            tuple(
                (
                    watermark.watermark_id,
                    watermark.event_time_through,
                    watermark.closed_at,
                    watermark.expected_instrument_ids,
                    watermark.revision_policy,
                    watermark.missing_data_policy,
                    watermark.late_event_policy,
                )
                for watermark in self.watermarks
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                MANIFEST_REPLAY_TAPE_CONTRACT_VERSION,
                WATERMARK_POLICY_VERSION,
                self.manifest_id,
                self.manifest_hash,
                self.calendar_version,
                self.calendar_hash,
                self.calendar_hash_version,
                self.calendar_tzdata_version,
                self.universe_version,
                self.universe_hash,
                self.universe_hash_version,
                self.event_time_start,
                self.event_time_end,
                self.interval,
                self.decision_lag.days,
                self.decision_lag.seconds,
                self.decision_lag.microseconds,
                self.revision_policy,
                self.watermarks_sha256,
            )
        )


@dataclass(frozen=True, slots=True, init=False)
class ManifestReplayTape:
    """Verified manifest lineage plus every selected RawBar revision and mapping."""

    plan: ReplayTapePlan
    source_id: str
    source_kind: str
    schema_version: str
    calendar_tzdata_version: str
    price_basis: PriceBasis
    corporate_action_version: str
    corporate_action_hash: str
    corporate_action_hash_version: str
    partitions: tuple[ManifestPartitionObject, ...]
    bars: tuple[RawBar, ...]
    events: tuple[MarketEvent, ...]

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("ManifestReplayTape is proof-constructed by ManifestReplayTapeReader")

    @classmethod
    def _from_verified_manifest(
        cls,
        *,
        plan: ReplayTapePlan,
        source_id: str,
        source_kind: str,
        schema_version: str,
        calendar_tzdata_version: str,
        price_basis: PriceBasis,
        corporate_action_version: str,
        corporate_action_hash: str,
        corporate_action_hash_version: str,
        partitions: tuple[ManifestPartitionObject, ...],
        bars: tuple[RawBar, ...],
        events: tuple[MarketEvent, ...],
    ) -> ManifestReplayTape:
        instance = object.__new__(cls)
        values = {
            "plan": plan,
            "source_id": source_id,
            "source_kind": source_kind,
            "schema_version": schema_version,
            "calendar_tzdata_version": calendar_tzdata_version,
            "price_basis": price_basis,
            "corporate_action_version": corporate_action_version,
            "corporate_action_hash": corporate_action_hash,
            "corporate_action_hash_version": corporate_action_hash_version,
            "partitions": partitions,
            "bars": bars,
            "events": events,
        }
        for field_name, value in values.items():
            object.__setattr__(instance, field_name, value)
        instance._validate()
        return instance

    def _validate(self) -> None:
        if type(self.plan) is not ReplayTapePlan:
            raise ValueError("manifest replay requires an exact proof-constructed plan")
        self.plan._validate()
        if self.source_kind not in _ALLOWED_SOURCE_KINDS:
            raise ValueError("manifest replay is restricted to fixture sources")
        if (
            not self.calendar_tzdata_version
            or self.calendar_tzdata_version != self.calendar_tzdata_version.strip()
        ):
            raise ValueError("calendar_tzdata_version must be non-empty and trimmed")
        if self.calendar_tzdata_version != self.plan.calendar_tzdata_version:
            raise ValueError("tape tzdata version must match its replay plan")
        if self.price_basis is not PriceBasis.RAW:
            raise ValueError("manifest replay requires raw prices")
        if self.schema_version == "raw-bar-v2":
            semantic_version = "arrow-v2"
            reference_version = "persisted-v2"
        elif self.schema_version == "raw-bar-v1":
            semantic_version = "input-v1"
            reference_version = "input-v1"
        else:
            raise ValueError("manifest replay schema has no provenance contract")
        if {
            self.plan.calendar_hash_version,
            self.plan.universe_hash_version,
            self.corporate_action_hash_version,
        } != {reference_version}:
            raise ValueError("manifest replay reference versions conflict with its schema")
        if (
            type(self.partitions) is not tuple
            or not self.partitions
            or len(self.partitions) > MAX_REPLAY_PARTITIONS
        ):
            raise ValueError("manifest replay requires immutable partition proofs")
        if any(type(partition) is not ManifestPartitionObject for partition in self.partitions):
            raise ValueError("manifest replay partition proofs have an unsupported type")
        if any(
            partition.semantic_checksum_version != semantic_version for partition in self.partitions
        ):
            raise ValueError("manifest replay checksum versions conflict with its schema")
        if type(self.bars) is not tuple:
            raise ValueError("manifest replay bars must be an immutable tuple")
        if any(type(bar) is not RawBar for bar in self.bars):
            raise ValueError("manifest replay bars must contain immutable RawBar values")
        if type(self.events) is not tuple or len(self.events) != len(self.bars):
            raise ValueError("manifest replay events must map every selected RawBar revision")
        expected_events = tuple(market_event_from_raw_bar(bar) for bar in self.bars)
        if self.events != expected_events:
            raise ValueError("manifest replay event mapping is not lossless")

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                MANIFEST_REPLAY_TAPE_CONTRACT_VERSION,
                self.plan.semantic_sha256,
                self.source_id,
                self.source_kind,
                self.schema_version,
                self.calendar_tzdata_version,
                self.price_basis,
                self.corporate_action_version,
                self.corporate_action_hash,
                self.corporate_action_hash_version,
                tuple(_partition_semantics(partition) for partition in self.partitions),
                tuple(_bar_semantics(bar) for bar in self.bars),
            )
        )

    @property
    def manifest_id(self) -> str:
        return self.plan.manifest_id

    @property
    def manifest_hash(self) -> str:
        return self.plan.manifest_hash

    @property
    def revision_policy(self) -> ReplayRevisionPolicy:
        return self.plan.revision_policy

    @property
    def row_count(self) -> int:
        return sum(partition.row_count for partition in self.partitions)


def _event_times(
    descriptor: ManifestObjects,
    *,
    interval: BarInterval,
    event_time_start: datetime,
    event_time_end: datetime,
) -> tuple[datetime, ...]:
    candidates: list[datetime] = []
    previous_close: datetime | None = None
    for session in descriptor.calendar_sessions:
        _require_utc(session.opens_at, "calendar opens_at")
        _require_utc(session.closes_at, "calendar closes_at")
        if session.closes_at <= session.opens_at:
            raise DatasetDecodeError("pinned calendar contains a nonpositive session")
        if previous_close is not None and session.opens_at < previous_close:
            raise DatasetDecodeError("pinned calendar sessions overlap or regress")
        previous_close = session.closes_at
        if session.closes_at < event_time_start or session.opens_at >= event_time_end:
            continue
        duration = interval.fixed_duration
        session_event_times: tuple[datetime, ...]
        if duration is None:
            session_event_times = (session.closes_at,)
        else:
            span = session.closes_at - session.opens_at
            if span % duration:
                raise DatasetDecodeError("pinned session is not divisible by the replay interval")
            count = span // duration
            if count > MAX_REPLAY_WATERMARKS:
                raise DatasetDecodeError("pinned session exceeds the watermark bound")
            session_event_times = tuple(
                session.opens_at + (index + 1) * duration for index in range(count)
            )
        for event_time in session_event_times:
            if event_time_start <= event_time <= event_time_end:
                candidates.append(event_time)
                if len(candidates) > MAX_REPLAY_WATERMARKS:
                    raise DatasetDecodeError("replay plan exceeds the watermark bound")
    event_times = tuple(candidates)
    if (
        not event_times
        or event_times != tuple(sorted(set(event_times)))
        or event_times[0] != event_time_start
        or event_times[-1] != event_time_end
    ):
        raise DatasetDecodeError(
            "inclusive replay coverage must align exactly to pinned calendar bar completions"
        )
    return event_times


def _validate_replay_descriptor(descriptor: ManifestObjects) -> None:
    if type(descriptor) is not ManifestObjects:
        raise DatasetDecodeError("manifest replay requires an exact catalog descriptor")
    if descriptor.source_kind not in _ALLOWED_SOURCE_KINDS:
        raise DatasetDecodeError("manifest replay is restricted to fixture sources")
    if descriptor.source_licensed or set(descriptor.entitlement_statuses) != {"fixture_only"}:
        raise DatasetDecodeError(
            "manifest replay requires an unlicensed, exclusively fixture-only source"
        )
    if descriptor.price_basis != PriceBasis.RAW.value:
        raise DatasetDecodeError("manifest replay requires raw prices")
    if descriptor.schema_version == "raw-bar-v2":
        semantic_version = "arrow-v2"
        reference_version = "persisted-v2"
    elif descriptor.schema_version == "raw-bar-v1":
        semantic_version = "input-v1"
        reference_version = "input-v1"
    else:
        raise DatasetDecodeError("manifest replay schema has no provenance contract")
    if {
        descriptor.calendar_hash_version,
        descriptor.universe_hash_version,
        descriptor.corporate_action_hash_version,
    } != {reference_version} or any(
        partition.semantic_checksum_version != semantic_version
        for partition in descriptor.partitions
    ):
        raise DatasetDecodeError("manifest replay provenance versions conflict with its schema")
    if not descriptor.partitions or len(descriptor.partitions) > MAX_REPLAY_PARTITIONS:
        raise DatasetDecodeError("manifest replay partition count exceeds its bounded contract")


def build_replay_tape_plan(
    descriptor: ManifestObjects,
    *,
    event_time_start: datetime,
    event_time_end: datetime,
    interval: BarInterval,
    decision_lag: timedelta,
) -> ReplayTapePlan:
    """Build inclusive watermarks solely from pinned calendar and universe facts."""

    _validate_replay_descriptor(descriptor)
    _require_utc(event_time_start, "event_time_start")
    _require_utc(event_time_end, "event_time_end")
    if event_time_end < event_time_start:
        raise ValueError("event_time_end cannot precede event_time_start")
    if not isinstance(interval, BarInterval):
        raise ValueError("replay tape interval is unsupported")
    if type(decision_lag) is not timedelta or decision_lag < timedelta(0):
        raise ValueError("decision_lag must be a non-negative timedelta")
    try:
        revision_policy = ReplayRevisionPolicy(descriptor.revision_policy)
    except ValueError as error:
        raise DatasetDecodeError("manifest revision policy is unsupported") from error
    event_times = _event_times(
        descriptor,
        interval=interval,
        event_time_start=event_time_start,
        event_time_end=event_time_end,
    )
    watermarks: list[MarketWatermark] = []
    for event_time in event_times:
        try:
            closed_at = event_time + decision_lag
        except OverflowError as error:
            raise ValueError("decision_lag overflows the replay clock") from error
        expected_instrument_ids = tuple(
            sorted(
                membership.instrument_id
                for membership in descriptor.universe_memberships
                if membership.included_from <= event_time
                and (membership.included_to is None or event_time < membership.included_to)
                and membership.available_at <= closed_at
            )
        )
        if not expected_instrument_ids or len(expected_instrument_ids) != len(
            set(expected_instrument_ids)
        ):
            raise DatasetDecodeError(
                "pinned universe has no unique causal membership for a replay slice"
            )
        if len(expected_instrument_ids) > MAX_REPLAY_EXPECTED_INSTRUMENTS:
            raise DatasetDecodeError("pinned universe exceeds the expected-instrument replay bound")
        watermark_id = canonical_id(
            "manifest-replay-watermark",
            WATERMARK_POLICY_VERSION,
            descriptor.manifest_id,
            descriptor.calendar_version,
            descriptor.calendar_hash,
            descriptor.calendar_hash_version,
            descriptor.calendar_tzdata_version,
            descriptor.universe_version,
            descriptor.universe_hash,
            descriptor.universe_hash_version,
            interval.value,
            event_time,
            closed_at,
            expected_instrument_ids,
            revision_policy.value,
        )
        watermarks.append(
            MarketWatermark(
                watermark_id=watermark_id,
                event_time_through=event_time,
                closed_at=closed_at,
                expected_instrument_ids=expected_instrument_ids,
                revision_policy=revision_policy,
            )
        )
    return ReplayTapePlan._from_verified_references(
        manifest_id=descriptor.manifest_id,
        manifest_hash=descriptor.manifest_hash,
        calendar_version=descriptor.calendar_version,
        calendar_hash=descriptor.calendar_hash,
        calendar_hash_version=descriptor.calendar_hash_version,
        calendar_tzdata_version=descriptor.calendar_tzdata_version,
        universe_version=descriptor.universe_version,
        universe_hash=descriptor.universe_hash,
        universe_hash_version=descriptor.universe_hash_version,
        event_time_start=event_time_start,
        event_time_end=event_time_end,
        interval=interval,
        decision_lag=decision_lag,
        revision_policy=revision_policy,
        watermarks=tuple(watermarks),
    )


def _validate_canonical_plan(plan: ReplayTapePlan, descriptor: ManifestObjects) -> None:
    canonical = build_replay_tape_plan(
        descriptor,
        event_time_start=plan.event_time_start,
        event_time_end=plan.event_time_end,
        interval=plan.interval,
        decision_lag=plan.decision_lag,
    )
    if plan != canonical:
        raise DatasetDecodeError("replay plan is not the exact canonical manifest plan")


class ManifestReplayTapeReader:
    """Verify a manifest and adapt all in-scope RawBar revisions for replay."""

    def __init__(
        self,
        *,
        catalog: SqlMarketDataCatalog,
        object_store: LocalParquetObjectStore,
    ) -> None:
        if type(catalog) is not SqlMarketDataCatalog:
            raise ValueError("replay reader requires an exact trusted SQL catalog")
        if type(object_store) is not LocalParquetObjectStore:
            raise ValueError("replay reader requires an exact trusted Parquet object store")
        self._catalog = catalog
        self._object_store = object_store

    @property
    def catalog_engine(self) -> Engine:
        """Expose the exact engine identity used to authenticate catalog facts."""

        return self._catalog.engine

    def build_plan(
        self,
        *,
        manifest_id: str,
        event_time_start: datetime,
        event_time_end: datetime,
        interval: BarInterval,
        decision_lag: timedelta,
    ) -> ReplayTapePlan:
        descriptor = self._catalog.manifest_objects(manifest_id)
        return build_replay_tape_plan(
            descriptor,
            event_time_start=event_time_start,
            event_time_end=event_time_end,
            interval=interval,
            decision_lag=decision_lag,
        )

    def read(self, plan: ReplayTapePlan) -> ManifestReplayTape:
        if type(plan) is not ReplayTapePlan:
            raise DatasetDecodeError("manifest replay requires an exact proof-constructed plan")
        descriptor = self._catalog.manifest_objects(plan.manifest_id)
        return self.read_verified_descriptor(plan, descriptor)

    def read_verified_descriptor(
        self,
        plan: ReplayTapePlan,
        descriptor: ManifestObjects,
    ) -> ManifestReplayTape:
        """Read bytes against an exact descriptor already verified by a caller."""

        if type(plan) is not ReplayTapePlan:
            raise DatasetDecodeError("manifest replay requires an exact proof-constructed plan")
        _validate_replay_descriptor(descriptor)
        _validate_canonical_plan(plan, descriptor)
        total_bytes = sum(partition.size_bytes for partition in descriptor.partitions)
        if total_bytes > MAX_REPLAY_TOTAL_BYTES or descriptor.row_count > MAX_REPLAY_ROWS:
            raise DatasetDecodeError("manifest replay input exceeds the bounded read contract")

        actual_total_bytes = 0
        for partition in descriptor.partitions:
            object_path = (self._object_store.root / partition.object_key).resolve()
            if not object_path.is_relative_to(self._object_store.root) or not object_path.is_file():
                raise DatasetDecodeError("manifest object is unavailable inside the dataset root")
            actual_size = object_path.stat().st_size
            if actual_size != partition.size_bytes:
                raise DatasetDecodeError("manifest object size does not match its catalog pin")
            actual_total_bytes += actual_size
            if actual_total_bytes > MAX_REPLAY_TOTAL_BYTES:
                raise DatasetDecodeError("manifest replay input exceeds the bounded read contract")

        all_bars: list[RawBar] = []
        for partition in descriptor.partitions:
            table = self._object_store.read_table(
                partition.object_key,
                expected_byte_checksum=partition.byte_checksum,
                expected_size_bytes=partition.size_bytes,
            )
            if not table.schema.remove_metadata().equals(
                NORMALIZED_BAR_SCHEMA.remove_metadata(),
                check_metadata=True,
            ):
                raise DatasetDecodeError("normalized partition schema does not match its exact pin")
            if table.num_rows != partition.row_count:
                raise DatasetDecodeError("normalized partition row count does not match its pin")
            table_rows = table.to_pylist()
            actual_semantic_version = parquet_semantic_checksum_version(table)
            if actual_semantic_version != partition.semantic_checksum_version:
                raise DatasetDecodeError(
                    "normalized partition checksum version does not match the catalog pin"
                )
            if actual_semantic_version == "arrow-v2":
                _, actual_semantic_checksum = canonicalize_rows(
                    table_rows,
                    semantic_checksum_version=actual_semantic_version,
                )
                if actual_semantic_checksum != partition.semantic_checksum:
                    raise DatasetDecodeError(
                        "normalized partition semantics do not match the catalog pin"
                    )
            partition_bars = tuple(_bar(row) for row in table_rows)
            if not partition_bars:
                raise DatasetDecodeError("normalized manifest partition cannot be empty")
            if (
                min(bar.event_time for bar in partition_bars) != partition.event_time_start
                or max(bar.event_time for bar in partition_bars) != partition.event_time_end
                or min(bar.available_at for bar in partition_bars) != partition.available_at_start
                or max(bar.available_at for bar in partition_bars) != partition.available_at_end
            ):
                raise DatasetDecodeError("normalized partition ranges do not match their pins")
            if any(
                bar.source_id != descriptor.source_id
                or bar.schema_version != descriptor.schema_version
                or bar.price_basis is not PriceBasis.RAW
                or bar.interval is not plan.interval
                for bar in partition_bars
            ):
                raise DatasetDecodeError(
                    "normalized rows do not match manifest source/schema/price/interval pins"
                )
            all_bars.extend(partition_bars)

        if len(all_bars) != descriptor.row_count:
            raise DatasetDecodeError("decoded manifest rows do not reconcile to the manifest")
        by_event_id: dict[str, RawBar] = {}
        observation_revisions: set[tuple[str, str, int]] = set()
        for bar in all_bars:
            if bar.event_revision_id in by_event_id:
                raise DatasetDecodeError("published manifest repeats an event revision identity")
            by_event_id[bar.event_revision_id] = bar
            observation_revision = (bar.source_id, bar.observation_id, bar.revision)
            if observation_revision in observation_revisions:
                raise DatasetDecodeError("published manifest repeats an observation revision")
            observation_revisions.add(observation_revision)

        selected_bars = tuple(
            bar
            for bar in all_bars
            if plan.event_time_start <= bar.event_time <= plan.event_time_end
        )
        planned_event_times = {
            watermark.event_time_through: set(watermark.expected_instrument_ids)
            for watermark in plan.watermarks
        }
        for bar in selected_bars:
            expected = planned_event_times.get(bar.event_time)
            if expected is None or bar.security_id not in expected:
                raise DatasetDecodeError("RawBar revision is outside the pinned replay plan")
        events = tuple(market_event_from_raw_bar(bar) for bar in selected_bars)
        return ManifestReplayTape._from_verified_manifest(
            plan=plan,
            source_id=descriptor.source_id,
            source_kind=descriptor.source_kind,
            schema_version=descriptor.schema_version,
            calendar_tzdata_version=descriptor.calendar_tzdata_version,
            price_basis=PriceBasis(descriptor.price_basis),
            corporate_action_version=descriptor.corporate_action_version,
            corporate_action_hash=descriptor.corporate_action_hash,
            corporate_action_hash_version=descriptor.corporate_action_hash_version,
            partitions=descriptor.partitions,
            bars=selected_bars,
            events=events,
        )


def replay_manifest_tape(
    tape: ManifestReplayTape,
    *,
    on_complete_batch: CompleteBatchCallback | None = None,
) -> ReplayResult:
    """Replay through only the immutable, manifest-policy-bound tape plan."""

    if type(tape) is not ManifestReplayTape:
        raise ValueError("manifest replay requires an exact ManifestReplayTape")
    tape._validate()
    return replay_market_events(
        events=tape.events,
        watermarks=tape.plan.watermarks,
        on_complete_batch=on_complete_batch,
    )


def validate_manifest_watermark_policy(
    plan: ReplayTapePlan,
    watermarks: Iterable[MarketWatermark],
) -> tuple[MarketWatermark, ...]:
    """Validate externally retained watermarks without permitting policy override."""

    pinned = tuple(watermarks)
    if pinned != plan.watermarks or any(
        watermark.revision_policy is not plan.revision_policy for watermark in pinned
    ):
        raise ValueError("watermarks must exactly match the manifest-pinned replay plan")
    return pinned
