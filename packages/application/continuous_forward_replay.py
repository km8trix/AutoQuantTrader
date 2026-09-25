"""Replay actual retained raw capture bytes; SQL authenticity is separately checked."""

from hashlib import sha256

from packages.application.personal_forward_capture import replay_capture
from packages.domain.continuous_forward_contracts import (
    MAX_CLOSURE_RECORD_BYTES,
    ContinuousForwardClosure,
)
from packages.domain.continuous_quote_contracts import ContinuousQuoteClosure
from packages.domain.durable_journal_contracts import JournalAppend, JournalEntry, JournalRecord
from packages.domain.forward_capture_contracts import CAPTURE_SCHEMA
from packages.domain.forward_contracts import ForwardDataState
from packages.domain.research_job_contracts import ResearchArtifactStore, ResearchRecordCodec


def replay_continuous_forward_closure(
    closure: ContinuousForwardClosure | ContinuousQuoteClosure,
    *,
    artifacts: ResearchArtifactStore,
    codec: ResearchRecordCodec,
) -> ForwardDataState:
    closure.__post_init__()
    state = closure.initial_state
    total = 0
    for publication in closure.publications:
        record, receipt = publication.record, publication.journal_receipt
        request = record.request
        payload = codec.encode_record(record)
        total += len(payload)
        if total > MAX_CLOSURE_RECORD_BYTES:
            raise ValueError("CAPTURE_CLOSURE_RECORD_LIMIT")
        entry_record = JournalRecord(request.capture_id, CAPTURE_SCHEMA, payload)
        append = JournalAppend(
            request.capture_id, request.semantic_sha256, receipt.previous_head, (entry_record,)
        )
        entry = JournalEntry(
            request.journal_key.semantic_sha256,
            receipt.previous_head.sequence + 1,
            request.capture_id,
            entry_record,
            receipt.previous_head.entry_sha256,
        )
        if (
            receipt.command_id != request.capture_id
            or receipt.command_sha256 != request.semantic_sha256
            or receipt.previous_head.key_sha256 != request.journal_key.semantic_sha256
            or receipt.committed_head != entry.head
            or receipt.append_sha256 != append.semantic_sha256
            or receipt.record_ids != (request.capture_id,)
            or receipt.record_hashes != (sha256(payload).hexdigest(),)
        ):
            raise ValueError("CAPTURE_CLOSURE_RECEIPT_BINDING_DIFFERS")
        state = replay_capture(record, state, artifacts=artifacts)
    if not set(closure.observation_ids) <= {
        observation.observation_id for observation in state.observations
    }:
        raise ValueError("CAPTURE_CLOSURE_SELECTED_OBSERVATION_MISSING")
    return state
