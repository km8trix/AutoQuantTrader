# ADR 0119: authenticated fixture-segment provenance views

- Status: Accepted
- Date: 2026-08-25
- Extends: [ADR 0117](0117-durable-fixture-segment-worker.md)

## Context

ADR 0117 durably retains a bounded repository-fixture job, immutable feature
and target transcript artifacts, append-only lifecycle events, a checked head,
and exact governance linkage. Its internal read path reconstructs those facts
to support worker commands, but no dedicated inspection surface exists. The
broader Phase 3 roadmap calls for queryable provenance without turning stored
transcripts into research results, exposing holdout material, or handing an API
object the worker's mutation methods.

The transcript payload contains ordered step digests and output identifiers.
Requester, actor, and physical-worker labels are caller-controlled strings.
Neither category is required to prove the public job relationship, and both
could carry material that is inappropriate for a general read response. A list
also cannot infer a continuation cursor from an unauthenticated lookahead row,
and an unbounded event response would defeat the worker's otherwise explicit
resource bounds.

## Decision

1. Implement Phase 3G as a dedicated `SqlFixtureSegmentProvenanceQuery`. It
   exposes only `get` and bounded `jobs` operations and is the sole Phase 3F
   object composed into the HTTP router. The worker repository and its enqueue,
   claim, renew, complete, and fail methods are not part of the query protocol.
2. Before constructing a view, load one repeatable-read snapshot and
   authenticate the immutable job digest, feature artifact, complete contiguous
   event chain, optional target artifact, checked head, complete family
   governance history, audit chain, current attempt identity, lifecycle status,
   and completion receipt linkage. The job and fixture sequence zero must bind
   the attempt's exact sequence-zero `QUEUED` event; every physical claim,
   renewal, or takeover must bind the attempt's single exact `RUNNING` event;
   and a terminal fixture event must bind the exact governed terminal status,
   time, and completion receipt. Extra or missing governed lifecycle facts fail
   closed. Feature-artifact segment, source-evidence, certification, parity,
   transcript, step-count, and output-count fields are cross-bound to the
   reconstructed `ExperimentSegmentEvidence`; a successful target artifact's
   corresponding fields, including configuration identity, are cross-bound to
   its `GovernedSegmentEvaluationReceipt`. A list authenticates every returned
   row and the one-row lookahead before emitting either results or a
   continuation cursor. A supplied cursor row is itself fully authenticated
   before its order key is used. Any missing link, corruption, substitution, or
   divergence makes the entire read unavailable.
3. Order job pages by `requested_at DESC, job_id ASC`. The opaque
   `before_job_id` keyset cursor resolves to the authenticated row's exact
   timestamp and identity; the next page admits earlier timestamps or, for a
   timestamp tie, lexically greater job identities. Page size is restricted to
   1 through 100. Missing job and cursor responses share one generic not-found
   shape, while malformed inputs are rejected by bounded transport validation.
   After authenticating each complete chain, list reads retain only a dedicated
   constant-size immutable summary; neither returned rows nor the authenticated
   lookahead retain an event collection or artifact object.
4. Authenticate the complete event chain but expose detail history in
   reverse-chronological pages of 1 through 100 events. The
   `before_sequence` cursor must name an event in that authenticated chain and
   returns only lower sequences. Total count and continuation metadata make
   truncation explicit; no response can contain more than 100 events.
5. Cross the query boundary only with frozen allowlisted provenance records.
   Job views include opaque family, attempt, configuration, validation,
   governance, certification, artifact, event, transcript, payload, parity, and
   completion digests; segment kind; bounded counts; status; physical-attempt
   ordinal; request/event/claim-expiry timestamps; and predecessor linkage.
   These values identify authenticated relationships but do not disclose the
   referenced content.
6. Never return transcript payloads, ordered step digests, output identifiers,
   segment/source-evidence identities, holdout commitment or reveal material,
   configuration values, requester/actor/worker labels, terminal-reason
   material, target values, positions, returns, P&L, metrics, criteria outcomes,
   or promotion decisions. Final-test jobs remain impossible before the ADR
   0117 audited reveal, but post-reveal views still receive the same metadata
   allowlist and no holdout-specific expansion.
7. Add only GET routes at
   `/api/v1/research/fixture-segment-jobs` and
   `/api/v1/research/fixture-segment-jobs/{job_id}`. Advertise the capability
   only with durable persistence. Corruption and malformed repository output
   produce one generic unavailable response without reflecting stored values.
8. Reuse the existing Phase 3F tables and authenticated constructors. Add no
   schema migration, write, repair, worker invocation, experiment mutation,
   filesystem or network I/O, credential access, provider operation, captured-
   tape admission, economic evaluation, promotion, deployment, broker call, or
   paper/live trading authority.

## Consequences

Operators and browser clients can traverse durable fixture-job provenance with
deterministic bounded pages while every presented relationship is derived from
a fully authenticated stored chain. The structural redaction boundary prevents
internal transcript members and caller-controlled labels from reaching the API
even if a future route accidentally inspects all fields of the query result.

These views remain proof metadata for a repository-owned synthetic fixture.
They do not make the transcript an economic report, qualify captured data,
compare experiments, adjudicate frozen criteria, or close Phase 3's captured-
tape, execution-isolation, reconnect, traceability, and reporting exit gates.
