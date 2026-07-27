# ADR 0040: durable pre-decode broker ingress

- Status: Accepted
- Date: 2026-07-26

## Context

ADR 0039 deliberately rejects unreviewed Alpaca response fields and statuses.
That fail-closed decoder behavior is safe only if the original delivery is
retained before parsing: malformed JSON, an empty body, a non-UTF-8 response,
or compatible provider schema drift must not disappear as an exception at the
decoder boundary.

The first durable boundary also cannot assume that every broker delivery
belongs to a known local order or submission attempt. Manual and otherwise
foreign account activity must remain observable. Nor can local arrival order be
reused as the canonical per-order broker sequence or the risk-observation
sequence. Those sequences have different meanings and trust requirements.

A complete inbox still depends on provider-qualified identities for stream
updates, paginated snapshots, executions, busts, and corrections. Defining
normalized-fact uniqueness or application semantics from the currently
qualified client-order lookup response alone would invent identities and
ordering that the provider evidence does not establish.

## Decision

1. Define Phase 4C as a bounded provider-neutral raw-ingress durability slice.
   `BrokerIngressDelivery` carries the exact response body plus only allowlisted
   versioned transport metadata: bounded account, provider, adapter version,
   environment, channel, operation, stable delivery idempotency key, optional
   correlation digest, optional HTTP status, optional provider request ID,
   optional media type, and explicit UTC receive and record times. It does not
   parse or reinterpret the body.
2. Bound one captured body at 1 MiB. Empty and arbitrary byte strings are valid
   raw deliveries. The journal commits the exact bytes, byte count, and body
   digest before any UTF-8, JSON, provider-schema, or status decoding. Malformed,
   empty, and schema-drift payloads therefore remain inspectable even when a
   later decoder fails.
3. Require the transport boundary to assign a stable delivery idempotency key.
   An exact retry uses the same account/key pair and returns the authenticated
   existing receipt. Reusing that pair with different immutable content fails
   closed as a conflict. A genuinely separate delivery receives a new key even
   when its bytes match an earlier response.
4. Append each new receipt to an independent, gap-free account-local ingress
   sequence. Sequence allocation and insertion occur while holding the existing
   Phase 2 account transition/capacity-serialization lock. Each receipt after
   the first binds the preceding receipt's semantic digest. A durable
   per-account head anchors the last sequence and terminal receipt digest;
   append point reads validate that terminal anchor, while full-history reads
   and startup integrity authenticate the contiguous sequence and predecessor
   chain from one repeatable database snapshot. Startup streams that
   authentication one receipt at a time rather than retaining every bounded raw
   body in memory. This sequence is not the account risk-observation sequence
   and is not a provider or canonical per-order broker sequence.
5. Store raw receipts without a local logical-order or submission-attempt
   foreign key. The account reference scopes the journal and gives it the
   durable account transition boundary; it does not assert a local order
   relationship. Optional correlation metadata is evidence, not adoption, so
   foreign and manual activity can be retained before classification.
6. Add an Alpaca paper client-order lookup wrapper that constructs the
   allowlisted raw delivery, waits for the recorder to commit it, and only then
   invokes the Phase 4B decoder. A decoder exception is allowed to escape after
   the independent raw-receipt transaction has committed. A successful decoded
   observation is cross-bound to the exact receipt bytes and metadata, but it
   is still only an offline observation.
7. Do not add a normalized provider-fact table, quarantine receipt, application
   receipt, order/submission reducer write, execution fact, or reconciliation
   transition in this slice. Stream, snapshot, execution, bust, and correction
   contracts must first qualify their stable provider identities, revisions,
   overlap behavior, and ordering. Only then can a later ADR define
   source-neutral deduplication and atomic application without manufacturing
   event IDs or treating arrival order as provider truth.
8. Keep every Alpaca runtime-readiness flag false. Phase 4C adds no credential
   resolution, HTTP or WebSocket transport, authenticated provider capture,
   stream or snapshot identity, pagination, request-budget enforcement,
   reconciliation barrier, lifecycle mutation, `UNKNOWN` resolution, broker
   dispatch, or paper/live trading authority.

## Consequences

Every supported future broker transport has a narrow durable commit point
before provider decoding. Exact retry is idempotent, changed content under a
reused delivery identity is rejected, and the append-only account-local hash
chain plus its retained terminal head makes missing, reordered, or modified raw
receipts within that anchored journal detectable. Decoder failures no longer
erase the delivery that caused them.

The journal is intentionally not yet a complete broker inbox. It does not
classify a retained payload as a provider fact or quarantine decision, dedupe
provider events across REST and streams, apply a fact to local lifecycle state,
or reconcile the account. A retained matching Alpaca lookup still cannot
resolve an `UNKNOWN` submission, and a retained 404 remains inconclusive.

Phase 4C is complete only as this bounded local persistence slice. Phase 4 and
its paper-broker exit gate remain open, all readiness flags remain false, and
Phase 3's independent captured-tape, reconnect, shadow, economic-evaluation,
and reporting gates remain open.
