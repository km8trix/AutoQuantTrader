"""One-use first sends to the independent local simulation venue only.

The original publisher proves a successful C/B COMMIT. This adapter separately
checks the actual current poststate and consumes one delivery opportunity. Lost
acknowledgment leaves durable IN_FLIGHT for observation; nothing here resends,
releases capacity, resolves UNKNOWN, or invokes a provider order endpoint.
"""

from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from threading import Lock
from weakref import WeakValueDictionary

from sqlalchemy import Engine

from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.domain.accounting_contracts import RegisterVenueSubmission
from packages.domain.canonical import canonical_json_bytes
from packages.domain.continuous_quote_contracts import ContinuousQuoteClosure
from packages.domain.forward_contracts import ForwardObservation, ForwardSource
from packages.domain.identifiers import canonical_id
from packages.domain.research_job_contracts import ObjectRef, ResearchRecordCodec
from packages.domain.stateful_venue_contracts import (
    MAX_VENUE_COMMAND_BYTES,
    VenueCommand,
    VenueModel,
    VenueReceipt,
    VenueSourceReference,
    VenueSubmit,
)
from packages.persistence.continuous_attempt_publication import (
    CommittedSimulationAttemptBatch,
    SqlContinuousAttemptPublication,
)
from packages.persistence.continuous_forward_sources import ResolvedContinuousForwardSources
from packages.persistence.continuous_runtime_attempt_sources import (
    PreparedContinuousRuntimeAttemptSource,
    ResolvedCommittedContinuousRuntimeAttemptSources,
    SqlContinuousRuntimeAttemptSources,
)
from packages.persistence.detached_journal_capture import detached_journal_value
from packages.persistence.stateful_venue import SqlStatefulVenue


@dataclass(frozen=True, slots=True, weakref_slot=True)
class _Delivery:
    batch: CommittedSimulationAttemptBatch
    source: PreparedContinuousRuntimeAttemptSource
    committed: ResolvedCommittedContinuousRuntimeAttemptSources
    packet: VenueSubmit
    packet_sha256: str


class SqlContinuousSimulationDelivery:
    def __init__(
        self,
        *,
        publisher: SqlContinuousAttemptPublication,
        sources: SqlContinuousRuntimeAttemptSources,
    ) -> None:
        if (
            type(publisher) is not SqlContinuousAttemptPublication
            or type(sources) is not SqlContinuousRuntimeAttemptSources
            or sources.accounts is not publisher.account
            or sources.daily is not publisher.composer.daily
            or sources.runtime_sources is not publisher.composer.producer_history
        ):
            raise ValueError("EXACT_SIMULATION_DELIVERY_OWNERS_REQUIRED")
        self.publisher, self.sources = publisher, sources
        self.runtime = sources.runtime_sources
        self.accounts, self.daily = sources.accounts, sources.daily
        self.model = self.runtime.venue_model
        self.venue: SqlStatefulVenue | None = None
        self._fixed = self._bindings()
        self._model_sha256 = self.model.semantic_sha256
        self._venue_bindings: tuple[object, ...] | None = None
        self._busy = Lock()
        self._active: _Delivery | None = None
        self._verified: _Delivery | None = None
        self._issued: WeakValueDictionary[int, _Delivery] = WeakValueDictionary()
        self._quotes: dict[str, ResolvedContinuousForwardSources] = {}

    def _bindings(self) -> tuple[object, ...]:
        return (
            self.publisher,
            self.sources,
            self.runtime,
            self.accounts,
            self.daily,
            self.model,
            self.publisher.account,
            self.publisher.composer,
            self.sources.accounts,
            self.sources.daily,
            self.sources.runtime_sources,
            self.accounts.engine,
            self.accounts.coordinator,
            self.accounts.preparer,
            self.runtime.operating,
            self.runtime.forward_sources,
            self.runtime.accounting,
            self.runtime.venue_model,
            self.runtime.venue_reference,
            self.runtime.artifacts,
            self.runtime.codec,
            self.runtime.current_fence,
        )

    def _require_owners(self) -> SqlStatefulVenue:
        if any(a is not b for a, b in zip(self._bindings(), self._fixed, strict=True)):
            raise ValueError("SIMULATION_DELIVERY_OWNERS_CHANGED")
        venue = self.venue
        if type(venue) is not SqlStatefulVenue or self._venue_bindings is None:
            raise ValueError("ACTUAL_INDEPENDENT_SIMULATION_VENUE_REQUIRED")
        if (
            any(
                a is not b
                for a, b in zip(
                    (
                        venue,
                        venue.model,
                        venue.journal,
                        venue.journal._engine,
                        venue.artifacts,
                        getattr(venue.artifacts, "_root", None),
                        getattr(self.runtime.artifacts, "_root", None),
                        venue.codec,
                        venue.accounting,
                        venue.verified_sources,
                    ),
                    self._venue_bindings,
                    strict=True,
                )
            )
            or self.model.semantic_sha256 != self._model_sha256
        ):
            raise ValueError("ORIGINAL_SIMULATION_VENUE_CHANGED")
        return venue

    def bind_venue(self, venue: SqlStatefulVenue) -> None:
        if (
            self.venue is not None
            or type(venue) is not SqlStatefulVenue
            or venue.model is not self.model
            or venue.accounting is not self.runtime.accounting
            or venue.codec is not self.runtime.codec
            or venue.verified_sources is not self
            or venue.journal._engine is self.accounts.engine
            or venue.journal._engine.url == self.accounts.engine.url
            or venue.artifacts is self.runtime.artifacts
            or type(venue.artifacts) is not LocalResearchArtifactStore
            or type(self.runtime.artifacts) is not LocalResearchArtifactStore
        ):
            raise ValueError("EXACT_DISTINCT_SIMULATION_VENUE_REQUIRED")
        left_objects = venue.artifacts._root.resolve(strict=True)
        right_objects = self.runtime.artifacts._root.resolve(strict=True)
        if left_objects == right_objects or left_objects.samefile(right_objects):
            raise ValueError("EXACT_DISTINCT_SIMULATION_VENUE_REQUIRED")
        if (
            venue.journal._engine.dialect.name == "sqlite"
            and self.accounts.engine.dialect.name == "sqlite"
        ):
            left = _sqlite_database_file(venue.journal._engine)
            right = _sqlite_database_file(self.accounts.engine)
            if left is None or right is None or left == right or left.samefile(right):
                raise ValueError("EXACT_DISTINCT_SIMULATION_VENUE_REQUIRED")
        self.venue = venue
        self._venue_bindings = (
            venue,
            venue.model,
            venue.journal,
            venue.journal._engine,
            venue.artifacts,
            venue.artifacts._root,
            self.runtime.artifacts._root,
            venue.codec,
            venue.accounting,
            venue.verified_sources,
        )

    def _copy_source(self, reference: VenueSourceReference) -> None:
        venue = self._require_owners()
        original = reference.object_ref
        payload = self.runtime.artifacts.read(original, max_bytes=MAX_VENUE_COMMAND_BYTES)
        if (
            type(payload) is not bytes
            or len(payload) != original.byte_count
            or sha256(payload).hexdigest() != original.object_sha256
            or venue.artifacts.put(payload, max_bytes=MAX_VENUE_COMMAND_BYTES) != original
        ):
            raise ValueError("EXACT_RETAINED_VENUE_SOURCE_BYTES_REQUIRED")

    def _prepare(
        self,
        batch: CommittedSimulationAttemptBatch,
        source: PreparedContinuousRuntimeAttemptSource,
        attempt_id: str,
    ) -> _Delivery:
        self._require_owners()
        self.publisher.require_completed(batch)
        self.sources.require_prepared(source)
        descriptor = source.descriptor
        if (
            source.closure.kind != "activation"
            or descriptor is None
            or descriptor.operating is None
            or batch.account.commit.source_evidence != source.reference
            or batch.attempts.snapshot.raw.requested_envelopes != source.envelopes
            or batch.attempts.snapshot.attempt_sources is None
        ):
            raise ValueError("ORIGINAL_ACTIVATION_DISPATCH_SOURCES_REQUIRED")
        self.runtime.require_resolved(descriptor)
        self.daily.require_prepared_attempt(batch.attempts)
        chosen = [item for item in source.envelopes if item.event.attempt_id == attempt_id]
        if len(chosen) != 1 or chosen[0].event.dispatch is None:
            raise ValueError("EXACT_ORIGINAL_BATCH_ATTEMPT_REQUIRED")
        claim = chosen[0].event.dispatch
        preparation = claim.record.preparation
        request = preparation.request
        if (
            request.venue_account_id != self.model.account_id
            or request.venue_model != self.runtime.venue_reference
            or request.source_account_id != batch.receipt.commit.scope.account_id
            or request.source_account_binding_sha256
            != batch.receipt.commit.scope.account_binding_sha256
        ):
            raise ValueError("ORIGINAL_SIMULATION_REQUEST_SCOPE_DIFFERS")
        commitments = [
            item
            for item in batch.attempts.result.accounting_state.commitments
            if item.commitment_id == request.original_commitment.commitment_id
        ]
        if len(commitments) != 1 or commitments[0].state != "active":
            raise ValueError("ACTUAL_COMMITTED_ACTIVATION_TERMS_REQUIRED")
        dispatch_ref = VenueSourceReference(
            self.model.producer, claim.record.semantic_sha256, claim.record_ref
        )
        packet = VenueSubmit(
            RegisterVenueSubmission(
                account_id=self.model.account_id,
                submission=request.submission,
                source_commitment=commitments[0],
                source_risk_admission_sha256=preparation.admission_source.semantic_sha256_ref,
                source_dispatch_sha256=claim.record.semantic_sha256,
                venue_model_sha256=self.model.execution_policy.semantic_sha256,
            ),
            preparation.admission_source,
            dispatch_ref,
        )
        self._copy_source(packet.risk_source)
        self._copy_source(packet.dispatch_source)
        with self.accounts.write_transaction() as connection:
            raw = self.accounts.capture_reference_in_transaction(
                connection,
                scope=batch.receipt.commit.scope,
                command_id=batch.receipt.commit.transition.command_id,
                source_lease_sha256=source.source.fence.lease_sha256,
            )
        if raw is None:
            raise ValueError("ACTUAL_COMMITTED_ACTIVATION_METADATA_REQUIRED")
        publication = self.accounts.resolve_reference(raw)
        if publication.receipt != batch.receipt:
            raise ValueError("ORIGINAL_SUCCESSFUL_COMMIT_METADATA_DIFFERS")
        committed = self.sources.resolve_committed_attempt_sources(
            batch.attempts.snapshot.attempt_sources, publication=publication
        )
        self.sources.require_committed_attempt_sources(committed)
        return _Delivery(batch, source, committed, packet, packet.semantic_sha256)

    def _recheck(self, delivery: _Delivery) -> datetime:
        self._require_owners()
        source, batch = delivery.source, delivery.batch
        self.publisher.require_completed(batch)
        self.sources.require_prepared(source)
        self.sources.require_committed_attempt_sources(delivery.committed)
        descriptor = source.descriptor
        assert descriptor is not None and descriptor.operating is not None
        self.runtime.require_resolved(descriptor)
        if delivery.packet.semantic_sha256 != delivery.packet_sha256:
            raise ValueError("ORIGINAL_SIMULATION_PACKET_CHANGED")
        fence = source.source.fence.fence
        if self.runtime.current_fence() != fence:
            raise ValueError("ORIGINAL_DISPATCH_OWNER_NO_LONGER_CURRENT")
        with self.accounts.write_transaction() as connection:
            self.daily.recheck_completed_attempt_in_transaction(
                connection,
                batch.attempts,
                fence=fence,
                committed_sources=delivery.committed,
            )
            if (
                self.accounts.capture_current_in_transaction(
                    connection, scope=batch.receipt.commit.scope
                )
                != delivery.committed.publication.snapshot.current
            ):
                raise ValueError("DISPATCH_CURRENT_ACCOUNT_POSTSTATE_CHANGED")
            self.accounts.journal.recheck_prepared_append_in_transaction(
                connection, batch.account.journal, require_current_head=True
            )
            # Source timestamps remain original. Read actual clock scalars at
            # this boundary without resampling or extending any expiry.
            self.runtime.operating.require_current_clock(descriptor.operating)
            checked = self.accounts.coordinator.revalidate_for_commit_in_transaction(
                connection, fence
            )
            if not source.source.checked_at <= checked.validated_at < source.source.valid_until:
                raise ValueError("ORIGINAL_DISPATCH_SOURCE_DEADLINE_EXPIRED")
        return checked.validated_at

    def deliver(
        self,
        batch: CommittedSimulationAttemptBatch,
        *,
        source: PreparedContinuousRuntimeAttemptSource,
        attempt_id: str,
    ) -> VenueReceipt:
        if not self._busy.acquire(blocking=False):
            raise ValueError("SIMULATION_DELIVERY_ALREADY_RUNNING")
        try:
            delivery = self._prepare(batch, source, attempt_id)
            at = self._recheck(delivery)
            self.publisher.claim_delivery(batch, attempt_id=attempt_id)
            self._issued[id(delivery)] = delivery
            self._active = delivery
            command = VenueCommand(
                canonical_id(
                    "continuous-venue-first-send/1",
                    batch.receipt.commit.scope.semantic_sha256,
                    attempt_id,
                ),
                at,
                delivery.packet,
            )
            receipt = self._require_owners().execute(command)
            if (
                type(receipt) is not VenueReceipt
                or receipt.acknowledgment.command_id != command.command_id
                or receipt.acknowledgment.command_sha256 != command.semantic_sha256
                or receipt.acknowledgment.disposition not in ("registered", "rejected")
                or (
                    receipt.acknowledgment.disposition == "registered"
                    and self._verified is not delivery
                )
            ):
                raise ValueError("ACTUAL_ONE_USE_VENUE_ACKNOWLEDGMENT_REQUIRED")
            if self._require_owners().read_command_receipt(command) != receipt:
                raise ValueError("ACTUAL_RETAINED_VENUE_ACKNOWLEDGMENT_REQUIRED")
            return receipt
        finally:
            if self._active is not None:
                self._issued.pop(id(self._active), None)
            self._active = None
            self._verified = None
            self._busy.release()

    def verify_submission(
        self, model: VenueModel, submit: VenueSubmit, *, received_at: datetime
    ) -> None:
        delivery = self._active
        if (
            delivery is None
            or self._issued.get(id(delivery)) is not delivery
            or model is not self.model
            or submit is not delivery.packet
        ):
            raise ValueError("ONE_USE_ACTUAL_SIMULATION_DELIVERY_REQUIRED")
        # Consume before checking: neither an error nor a second callback can
        # restore this original permission or a prior successful acknowledgment.
        self._active = None
        self._issued.pop(id(delivery), None)
        now = self._recheck(delivery)
        if not delivery.source.source.checked_at <= received_at <= now:
            raise ValueError("ACTUAL_SIMULATION_RECEIPT_TIME_DIFFERS")
        self._verified = delivery

    def retain_quote(self, value: ResolvedContinuousForwardSources) -> None:
        self._require_owners()
        self.runtime.forward_sources.require_resolved(value)
        if (
            self.model.source_mode != "recorded_as_observed"
            or type(value.closure) is not ContinuousQuoteClosure
            or value.closure.evidence_class != "provider_https_read"
        ):
            raise ValueError("SIMULATED_CAPTURE_CANNOT_QUALIFY_PROVIDER_QUOTES")
        quotes = dict(self._quotes)
        selected = {item.observation_id for item in value.closure.selections}
        for observation in value.state.observations:
            if observation.observation_id in selected and observation.source_id in {
                item.source_id for item in self.model.sources
            }:
                existing = quotes.get(observation.observation_id)
                if existing is not None and existing is not value:
                    raise ValueError("ORIGINAL_VENUE_QUOTE_SOURCE_ALREADY_RETAINED")
                quotes[observation.observation_id] = value
        if not quotes or len(quotes) > 2048:
            raise ValueError("BOUNDED_RETAINED_VENUE_QUOTES_REQUIRED")
        retained = {id(item): item for item in quotes.values()}
        for item in retained.values():
            self.runtime.forward_sources.require_resolved(item)
        _check_quote_budget(tuple(retained.values()), codec=self.runtime.codec)
        self._quotes = quotes

    def verify_quote(
        self, model: VenueModel, source: ForwardSource, observation: ForwardObservation
    ) -> None:
        self._require_owners()
        original = self._quotes.get(observation.observation_id)
        if (
            model is not self.model
            or source not in self.model.sources
            or original is None
            or source not in original.state.sources
            or observation not in original.state.observations
            or model.source_mode != "recorded_as_observed"
            or original.closure.evidence_class != "provider_https_read"
        ):
            raise ValueError("ORIGINAL_RETAINED_VENUE_QUOTE_REQUIRED")
        self.runtime.forward_sources.require_resolved(original)
        with self.accounts.write_transaction() as connection:
            self.runtime.forward_sources.recheck_in_transaction(connection, original)


def _sqlite_database_file(engine: Engine) -> Path | None:
    """Inspect SQLite's actual main file, including when SQLAlchemy uses a file URI."""
    with engine.connect() as connection:
        rows = connection.exec_driver_sql("PRAGMA database_list").fetchmany(3)
    main = [row for row in rows if row[1] == "main"]
    if len(rows) > 2 or len(main) != 1 or any(row[1] not in ("main", "temp") for row in rows):
        raise ValueError("EXACT_SIMULATION_DATABASE_FILE_REQUIRED")
    filename = main[0][2]
    if type(filename) is not str or not filename:
        return None
    path = Path(filename)
    if not path.is_absolute():
        raise ValueError("EXACT_SIMULATION_DATABASE_FILE_REQUIRED")
    return path.resolve(strict=True)


def _check_quote_budget(
    values: tuple[ResolvedContinuousForwardSources, ...], *, codec: ResearchRecordCodec
) -> int:
    """Count retained bytes only; ownership and provider class remain separate checks."""
    retained = {id(item): item for item in values}
    if not retained or len(retained) > 2048:
        raise ValueError("BOUNDED_RETAINED_VENUE_QUOTES_REQUIRED")
    total = 0
    raw_objects: dict[str, ObjectRef] = {}
    for item in retained.values():
        total += len(codec.encode_record(item.closure))
        total += len(codec.encode_record(item.state))
        total += len(canonical_json_bytes(detached_journal_value(item.reads)))
        total += _retained_journal_bytes(item.reads)
        for publication in item.closure.publications:
            reference = publication.record.raw_object
            if type(reference) is not ObjectRef:
                raise ValueError("ORIGINAL_RETAINED_VENUE_RAW_OBJECT_DIFFERS")
            reference.__post_init__()
            original = raw_objects.get(reference.object_sha256)
            if reference.codec_version != "personal-provider-json/1" or (
                original is not None and original != reference
            ):
                raise ValueError("ORIGINAL_RETAINED_VENUE_RAW_OBJECT_DIFFERS")
            if original is None:
                raw_objects[reference.object_sha256] = reference
                total += reference.byte_count
            if len(raw_objects) > 2048 or total > _MAX_RETAINED_QUOTE_BYTES:
                raise ValueError("RETAINED_VENUE_QUOTE_SOURCE_BUDGET_EXCEEDED")
        if total > _MAX_RETAINED_QUOTE_BYTES:
            raise ValueError("RETAINED_VENUE_QUOTE_SOURCE_BUDGET_EXCEEDED")
    return total


_MAX_RETAINED_QUOTE_BYTES = 32 * 1024 * 1024


def _retained_journal_bytes(value: object) -> int:
    """Charge the payload bytes represented only by digests in detached metadata."""
    if type(value) is bytes:
        return len(value)
    if isinstance(value, Mapping):
        return sum(_retained_journal_bytes(item) for item in value.values())
    if is_dataclass(value) and not isinstance(value, type):
        return sum(
            _retained_journal_bytes(getattr(value, field.name))
            for field in fields(value)
            if field.name not in {"_owner", "_validated_values"}
        )
    if type(value) is tuple:
        return sum(_retained_journal_bytes(item) for item in value)
    return 0
