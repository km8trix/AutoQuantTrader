# ADR 0104: Durable non-authorizing post-enrollment graceful-stop targeting

- Status: Accepted for code-only evidence construction; effecting shutdown remains absent
- Date: 2026-08-15
- Extends:
  [ADR 0099](0099-approval-bound-post-enrollment-start-and-graceful-stop.md),
  [ADR 0103](0103-atomic-operator-attested-post-enrollment-execution-admission.md)
- Extended by:
  [ADR 0111](0111-dormant-operation-bound-clean-stop-supervisor-bridge.md)

## Context

The retained controller-outcome v1 contract proves a terminal start disposition
but retains only the persistent-topology and observation-transcript digests. A
later process cannot reconstruct from that artifact the exact daemon endpoint,
container IDs, network ID and session-derived network name, named-volume
identities, or stable inspection projections needed to review a graceful stop.
Rewriting a historical v1 artifact would invalidate its content address and
commit markers. A separately persisted locator would introduce another
CALL/STORE ordering problem and could be orphaned from the terminal outcome.

Graceful stop also needs a protocol domain distinct from start. Reusing the
start decision or replay domain would permit cross-protocol interpretation. The
stop trust root, signature statement, verifier, replay slot, currentness proof,
effect admission, and host choreography are not yet designed and must not be
implied by a locator or a review target.

## Decision

### Retain the locator inside controller outcome v2

The current controller-outcome contract is
`phase6d-post-enrollment-start-retained-controller-outcome-v2`. Whenever the
outcome contains qualified persistent-topology evidence, it also embeds one
canonical `phase6d-post-enrollment-start-durable-shutdown-locator-v1` payload
and its SHA-256. The locator contains:

- the complete canonical
  `phase6d-post-enrollment-start-persistent-topology-snapshot-v1` payload and
  its snapshot and observation-transcript SHA-256 values;
- the active-controller session SHA-256 and the network name derived from that
  session;
- the fixed socket and state volume names;
- through the nested topology, the start operation, approval, claim, retained
  claim, active admission, successor, release/input-retirement, approved
  revision and image evidence, fixed Compose project, daemon
  context/endpoint/ID, volume identities, network ID/projection, and both exact
  container IDs, roles, image IDs, and stable inspection/running/configuration
  projection digests.

The locator status is `durable_shutdown_locator_unqualified`. Its public bound
is 64 KiB. The retained-outcome bound is 128 KiB so every locator accepted by
the frozen topology schema, including its maximum 4,096-codepoint canonical
Unix endpoint, can survive outcome persistence and reload.

The loader continues to recognize exact historical
`phase6d-post-enrollment-start-retained-controller-outcome-v1` payloads and
their v1 slot and commit markers. It never rewrites or migrates them. A v1
receipt has no locator and is structurally unavailable for graceful-stop
target construction. `durable_shutdown_locator_available` reports only the
presence of a v2 locator; it is not an authorization or currentness predicate.
A v2 `recovery_required` outcome may truthfully retain a locator while remaining
ineligible for the normal confirmed-start target.

### Freeze an inert target and a separate stop decision

`scripts/trusted_time_post_enrollment_graceful_stop.py` defines two sealed,
canonical, non-authorizing projections:

- `phase6d-post-enrollment-graceful-stop-target-v1`, status
  `graceful_stop_target_unqualified`, binds an exact structurally committed v2
  `post_enrollment_start_confirmed` outcome and its SHA-256, the exact embedded
  locator and its SHA-256, the start operation and approval, and caller-supplied
  SHA-256 bindings for the v3 start execution-attempt slot and operator-
  attestation envelope;
- `phase6d-post-enrollment-graceful-stop-decision-v1`, status
  `external_attestation_required`, binds a distinct stop operation UUID and the
  complete target plus its SHA-256 to decision
  `approve_one_post_enrollment_graceful_stop_attempt` under replay domain
  `github.com/km8trix/AutoQuantTrader/production/trusted-time/post-enrollment-graceful-stop/operator-attestation/v1`.

The stop decision and replay domain are deliberately distinct from the start
decision and replay domain. This ADR did not choose a key. ADR 0105 now freezes
a separate stop authority identity and requires its installed public key to be
distinct from the installed start authority; neither ADR installs real key
material or grants stop authority.

The v3 attempt-slot and envelope digests are exact target bindings only. This
slice does not load those artifacts or authenticate that they belong to the
start outcome. Every start, stop, currentness, freshness, authentication,
retention, runtime, topology-mutation, operational-control, broker, paper, and
live-trading fact or authority exposed by the locator, target, and decision is
false.

### Canonicalization and sealing

All three projections accept only exact ASCII canonical JSON with one trailing
newline. Decoders reject duplicate keys at every nesting level, floats and
non-finite values, oversized integers, surrogate code points, excessive depth
or node count, extra or missing fields, noncanonical bytes, and size overflow.
Nested objects are re-encoded and semantically decoded before construction;
content hashes and cross-layer start identities must agree. Stored nested
representations are immutable bytes and each payload accessor returns a fresh
decode. Target and decision construction is sealed; direct construction,
subclassing, field mutation, copy, deep copy, dataclass replacement, and pickle
serialization cannot create a usable projection.

The target/decision module is a side-effect-free structural bridge under
`scripts/`, not a domain primitive. Its receipt builder imports the existing
controller-outcome type and performs structural receipt validation, which can
consult process identity and lexical path normalization. It performs no file
read, persistence, Docker, database, provider, network, cryptographic,
signature, clock, or runtime action. Before an effecting stop exists, the
receipt-to-target bridge should be separated from dependency-pure codecs or be
re-reviewed with the exact effect admission.

### Keep shutdown hard closed

This ADR itself added no stop authority manifest, public or private stop key,
signer, signature statement/envelope, verifier, artifact loader, freshness witness,
current topology or trusted-head verifier, stop-attempt slot, admission,
outcome writer, recovery workflow, CLI, Make executor, Compose service, Docker
command, signal sender, database/provider caller, or runtime consumer.
`make trusted-time-stop` continues to report that no effecting approved
shutdown operator is implemented and exit 2 without invoking Docker. The
modules are excluded from Docker build context and have no production stop
caller.

ADR 0105 subsequently adds only inert public authority and detached-signature
code while preserving this closed runtime boundary. ADR 0106 additionally
loads and revalidates the current-v3 start-attempt slot and complete historical
confirmed-start chain before publishing an inert decision-v1 candidate. That
offline binder still establishes no currentness or stop admission. Before any
live stop, a later reviewed design must at minimum:

1. authenticate a dedicated stop attestation without cross-protocol replay;
2. reload and durably revalidate the exact committed v2 start outcome, exact
   v3 start slot/envelope relationships, and exact reviewed decision/envelope;
3. reserve one global stop attempt before any effect and define permanent
   ambiguity/no-automatic-retry semantics;
4. take the launcher lock and freshly authenticate the daemon, exact
   containers, network, volumes, and a bounded current trusted-head suffix;
5. signal only the exact supervisor ID, prove the terminal `clean_stop`
   successor and durable source evidence, then remove only the exact
   supervisor, source, and network IDs while preserving both named volumes;
6. retain progress-sensitive confirmed or recovery-required stop evidence
   across every CALL/STORE boundary.

ADR 0111 now carries this ADR's operation, target, locator, controller,
topology, and exact supervisor identities into a strict structural clean-stop
request and result correlation. Those carried values remain unqualified: the
bridge authenticates neither this target nor current topology and has no
production transport, reservation, lifecycle successor, or effect caller.

## Consequences

A later process can reconstruct a reviewable exact stop target without mutating
historical evidence or guessing Docker resources. Historical v1 outcomes remain
valid terminal evidence but are locator-unavailable. The new target and
decision can be reviewed and, through ADR 0106's separately authenticated
historical-chain candidate, externally attested, yet cannot authorize or
perform shutdown today.

The retained outcome and reviewed-input source graph are larger. This is an
intentional bounded cost of keeping the full locator inside the already atomic
slot/outcome/commit lifecycle instead of creating an independently durable
artifact.

## Rejected alternatives

- **Rewrite or upgrade retained v1 files.** This breaks content addresses,
  marker bindings, and historical immutability.
- **Persist a separate locator artifact.** This creates orphan and ordering
  states not covered by the terminal outcome transaction.
- **Treat a locator, target, or decision as authority.** They authenticate no
  current state and contain no approved stop signature or replay admission.
- **Reuse the start decision, replay domain, or key identity.** This creates
  cross-protocol ambiguity. ADR 0105 instead freezes a separate stop identity
  and requires installation-time public-key separation.
- **Wire `trusted-time-stop` to Compose or Docker now.** There is no approved
  currentness, clean-stop, replay, recovery, or teardown admission contract.
