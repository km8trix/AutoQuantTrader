"""One independent venue account stream using the common journal and private objects.

No new tables, financial reducer, account fence or transaction implementation.
Immutable objects may remain unreferenced after a failed CAS; only the committed
journal publishes a venue acknowledgment or state. Local blocking filesystem
calls are outside the SQL transaction, but this adapter is not a process sandbox.
"""

from __future__ import annotations

import hashlib
from dataclasses import fields

from sqlalchemy.engine import Engine

from packages.application.stateful_venue import (
    advance_stateful_venue,
    initialize_stateful_venue,
    project_stateful_venue,
    validate_venue_state,
    venue_fact_page,
)
from packages.domain.accounting_contracts import AccountingState, ExecutionAccountingPort
from packages.domain.durable_journal_contracts import (
    JournalAppend,
    JournalHead,
    JournalKey,
    JournalReceipt,
    JournalRecord,
    empty_head,
)
from packages.domain.forward_contracts import ForwardDataState
from packages.domain.identifiers import canonical_id
from packages.domain.personal_contracts import content_digest
from packages.domain.research_job_contracts import (
    ObjectRef,
    ResearchArtifactStore,
    ResearchRecordCodec,
)
from packages.domain.stateful_venue_contracts import (
    MAX_VENUE_COMMAND_BYTES,
    MAX_VENUE_COMMANDS,
    MAX_VENUE_OBJECT_BYTES,
    VenueAck,
    VenueCommand,
    VenueCommit,
    VenueFactPage,
    VenueModel,
    VenueRead,
    VenueReceipt,
    VenueState,
    VenueSubmit,
    VerifiedVenueSources,
)
from packages.persistence.durable_journal import JournalConflict, SqlDurableJournal

SCHEMA_ID = "personal-stateful-venue-commit/1"


class VenueStorageError(ValueError):
    """A bounded retained venue binding failed, without exposing storage paths."""


def venue_journal_key(model: VenueModel) -> JournalKey:
    # Venue facts remain modeled even when their quote inputs were actually
    # captured. Those distinct provider environments are retained in the model.
    return JournalKey(
        "venue",
        model.venue_id,
        model.account_id,
        model.venue_id,
        "synthetic",
        content_digest(("venue-account-scope/1", model.venue_id, model.account_id)),
    )


class SqlStatefulVenue:
    def __init__(
        self,
        engine: Engine,
        *,
        model: VenueModel,
        artifacts: ResearchArtifactStore,
        codec: ResearchRecordCodec,
        verified_sources: VerifiedVenueSources | None = None,
        accounting: ExecutionAccountingPort | None = None,
    ) -> None:
        model.__post_init__()
        self.model, self.artifacts, self.codec = model, artifacts, codec
        self.verified_sources, self.accounting = verified_sources, accounting
        self.key = venue_journal_key(model)
        self.journal = SqlDurableJournal(engine, codec=codec, record_types={SCHEMA_ID: VenueCommit})

    def _read_object(self, reference: ObjectRef, maximum: int) -> bytes:
        if reference.byte_count > maximum:
            raise VenueStorageError("VENUE_OBJECT_BOUND_EXCEEDED")
        payload = self.artifacts.read(reference, max_bytes=maximum)
        if (
            type(payload) is not bytes
            or len(payload) != reference.byte_count
            or hashlib.sha256(payload).hexdigest() != reference.object_sha256
        ):
            raise VenueStorageError("VENUE_OBJECT_BINDING_DIFFERS")
        return payload

    def _install(self, payload: bytes, maximum: int) -> ObjectRef:
        if not 0 < len(payload) <= maximum:
            raise VenueStorageError("VENUE_OBJECT_BOUND_EXCEEDED")
        reference = self.artifacts.put(payload, max_bytes=maximum)
        if (
            reference.byte_count != len(payload)
            or reference.object_sha256 != hashlib.sha256(payload).hexdigest()
        ):
            raise VenueStorageError("VENUE_INSTALLED_OBJECT_BINDING_DIFFERS")
        return reference

    def _write_state(self, state: VenueState) -> ObjectRef:
        # Preflight small detached records before building one JSON object.
        # Summing independently enveloped records conservatively overcounts
        # their final shared wrappers and avoids a history-sized encode before
        # learning that the bounded checkpoint cannot be retained.
        count = 4096
        for field in fields(state):
            value = getattr(state, field.name)
            if isinstance(value, (AccountingState, ForwardDataState)):
                parts = tuple(getattr(value, item.name) for item in fields(value))
            else:
                parts = (value,)
            for part in parts:
                for record in part if type(part) is tuple else (part,):
                    count += len(self.codec.encode_record(record)) + 256
                    if count > MAX_VENUE_OBJECT_BYTES:
                        raise VenueStorageError("VENUE_STATE_BUDGET_EXCEEDED")
        payload = self.codec.encode_record(state)
        if (
            not 0 < len(payload) <= MAX_VENUE_OBJECT_BYTES
            or self.codec.decode_record(payload, VenueState) != state
        ):
            raise VenueStorageError("VENUE_STATE_CODEC_OR_BOUND_DIFFERS")
        return self._install(payload, MAX_VENUE_OBJECT_BYTES)

    def _decode(self, record: JournalRecord) -> VenueCommit:
        if record.schema_id != SCHEMA_ID:
            raise VenueStorageError("VENUE_RECORD_SCHEMA_DIFFERS")
        commit = self.codec.decode_record(record.payload, VenueCommit)
        model_bytes = self.codec.encode_record(self.model)
        if (
            commit.model_sha256 != self.model.semantic_sha256
            or commit.model_object.object_sha256 != hashlib.sha256(model_bytes).hexdigest()
            or commit.model_object.byte_count != len(model_bytes)
        ):
            raise VenueStorageError("VENUE_COMMIT_MODEL_DIFFERS")
        return commit

    def _state(self, commit: VenueCommit) -> VenueState:
        model = self.codec.decode_record(
            self._read_object(commit.model_object, MAX_VENUE_COMMAND_BYTES), VenueModel
        )
        if model != self.model:
            raise VenueStorageError("VENUE_RETAINED_MODEL_DIFFERS")
        state = self.codec.decode_record(
            self._read_object(commit.state_object, MAX_VENUE_OBJECT_BYTES), VenueState
        )
        if state.semantic_sha256 != commit.state_sha256:
            raise VenueStorageError("VENUE_STATE_SEMANTIC_BINDING_DIFFERS")
        if commit.acknowledgment != (state.acknowledgments[-1] if state.acknowledgments else None):
            raise VenueStorageError("VENUE_STATE_ACK_BINDING_DIFFERS")
        validate_venue_state(self.model, state)
        projection = project_stateful_venue(self.model, state, accounting=self.accounting)
        journal = {e.entry_id: e for e in projection.journal_entries}
        for fact in state.facts:
            expected = tuple(
                e.entry_id
                for e in projection.journal_entries
                if e.source_sha256 == fact.payload.semantic_sha256
            )
            if set(fact.journal_entry_ids) != set(expected) or any(
                identity not in journal for identity in fact.journal_entry_ids
            ):
                raise VenueStorageError("VENUE_FACT_POSTING_BINDING_DIFFERS")
        return state

    def _append(
        self, state: VenueState, *, previous: VenueRead | None, acknowledgment: VenueAck | None
    ) -> JournalReceipt:
        reference = self._write_state(state)
        model_payload = self.codec.encode_record(self.model)
        if self.codec.decode_record(model_payload, VenueModel) != self.model:
            raise VenueStorageError("VENUE_MODEL_CODEC_DIFFERS")
        model_reference = self._install(model_payload, MAX_VENUE_COMMAND_BYTES)
        commit = VenueCommit(
            self.model.semantic_sha256,
            model_reference,
            None if previous is None else previous.state.semantic_sha256,
            state.semantic_sha256,
            reference,
            acknowledgment,
        )
        command_id = (
            canonical_id("venue-genesis/1", self.model.semantic_sha256)
            if acknowledgment is None
            else acknowledgment.command_id
        )
        command_sha = (
            self.model.semantic_sha256 if acknowledgment is None else acknowledgment.command_sha256
        )
        record = JournalRecord(
            canonical_id("venue-commit/1", self.model.semantic_sha256, command_id),
            SCHEMA_ID,
            self.codec.encode_record(commit),
        )
        return self.journal.append(
            self.key,
            JournalAppend(
                command_id,
                command_sha,
                empty_head(self.key) if previous is None else previous.head,
                (record,),
            ),
        )

    def initialize(self) -> VenueRead:
        if self.journal.read_head(self.key) == empty_head(self.key):
            state = initialize_stateful_venue(self.model, accounting=self.accounting)
            self._append(state, previous=None, acknowledgment=None)
        return self.read()

    def read(self, *, through_head: JournalHead | None = None) -> VenueRead:
        head = self.journal.read_head(self.key) if through_head is None else through_head
        if (
            head.key_sha256 != self.key.semantic_sha256
            or not 1 <= head.sequence <= MAX_VENUE_COMMANDS + 1
        ):
            raise VenueStorageError("VENUE_HEAD_UNINITIALIZED_OR_OUTSIDE_BOUND")
        after = empty_head(self.key)
        previous = None
        current = None
        # Every retained commit is small. Verify the complete bounded chain;
        # decode only the final immutable financial checkpoint object.
        while after != head:
            page = self.journal.read_page(self.key, through_head=head, after_head=after, limit=256)
            for entry in page.entries:
                current = self._decode(entry.record)
                ack = current.acknowledgment
                if (
                    current.previous_state_sha256 != previous
                    or (entry.sequence == 1) != (ack is None)
                    or (
                        ack is not None
                        and (
                            ack.sequence != entry.sequence - 1 or ack.command_id != entry.command_id
                        )
                    )
                ):
                    raise VenueStorageError("VENUE_CHECKPOINT_CHAIN_DIFFERS")
                previous = current.state_sha256
            if page.next_head == after:
                raise VenueStorageError("VENUE_PAGE_DID_NOT_ADVANCE")
            after = page.next_head
        assert current is not None
        state = self._state(current)
        if state.sequence != head.sequence - 1:
            raise VenueStorageError("VENUE_STATE_SEQUENCE_DIFFERS")
        return VenueRead(head, state)

    def _retry(self, command: VenueCommand, receipt: JournalReceipt) -> VenueReceipt:
        if receipt.command_sha256 != command.semantic_sha256:
            raise JournalConflict("VENUE_COMMAND_ID_CONFLICT")
        page = self.journal.read_page(
            self.key, through_head=receipt.committed_head, after_head=receipt.previous_head, limit=1
        )
        if len(page.entries) != 1 or not page.complete:
            raise VenueStorageError("VENUE_RETRY_RECORD_INVENTORY_DIFFERS")
        commit = self._decode(page.entries[0].record)
        acknowledgment = commit.acknowledgment
        if (
            acknowledgment is None
            or acknowledgment.command_id != command.command_id
            or acknowledgment.command_sha256 != command.semantic_sha256
        ):
            raise VenueStorageError("VENUE_RETRY_ACK_BINDING_DIFFERS")
        # Original bytes must remain available, even after later appends.
        state = self._state(commit)
        if state.commands[-1] != command:
            raise VenueStorageError("VENUE_RETRY_COMMAND_BINDING_DIFFERS")
        return VenueReceipt(acknowledgment, receipt)

    def read_command_receipt(self, command: VenueCommand) -> VenueReceipt | None:
        """Read an actually retained acknowledgment with its original bindings.

        A prepared receipt or returned transport value does not establish a
        journal append. This read authenticates the committed journal entry and
        original model, state, command and acknowledgment without executing it.
        """
        if type(command) is not VenueCommand:
            raise VenueStorageError("EXACT_VENUE_COMMAND_REQUIRED")
        command.__post_init__()
        receipt = self.journal.read_receipt(self.key, command.command_id)
        return None if receipt is None else self._retry(command, receipt)

    def execute(
        self, command: VenueCommand, *, expected_head: JournalHead | None = None
    ) -> VenueReceipt:
        command.__post_init__()
        encoded = self.codec.encode_record(command)
        if (
            not 0 < len(encoded) <= MAX_VENUE_COMMAND_BYTES
            or self.codec.decode_record(encoded, VenueCommand) != command
        ):
            raise VenueStorageError("VENUE_COMMAND_CODEC_OR_BOUND_DIFFERS")
        receipt = self.journal.read_receipt(self.key, command.command_id)
        if receipt is not None:
            return self._retry(command, receipt)
        current = self.read()
        if expected_head is not None and expected_head != current.head:
            raise JournalConflict("VENUE_EXPECTED_HEAD_DIFFERS")
        if isinstance(command.payload, VenueSubmit):
            # The injected verifier authenticates the declared record types and
            # dispatch permission. These checks retain the exact original bytes.
            self._read_object(command.payload.risk_source.object_ref, MAX_VENUE_COMMAND_BYTES)
            self._read_object(command.payload.dispatch_source.object_ref, MAX_VENUE_COMMAND_BYTES)
        transition = advance_stateful_venue(
            self.model,
            current.state,
            command,
            accounting=self.accounting,
            verified_sources=self.verified_sources,
        )
        receipt = self._append(
            transition.state, previous=current, acknowledgment=transition.acknowledgment
        )
        return VenueReceipt(transition.acknowledgment, receipt)

    def facts(
        self, *, through_head: JournalHead, offset: int = 0, limit: int = 200
    ) -> VenueFactPage:
        retained = self.read(through_head=through_head)
        return venue_fact_page(
            self.model,
            retained.state,
            through_sequence=retained.state.sequence,
            offset=offset,
            limit=limit,
        )
