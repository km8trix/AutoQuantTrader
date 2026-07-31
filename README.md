# AutoQuantTrader

AutoQuantTrader is a quantitative research, backtesting, paper-trading, and
eventually live-trading application with a desktop-oriented browser interface.
Implementation is proceeding in safety-complete vertical slices.

Start here:

- [Architecture and product scope](docs/ARCHITECTURE.md)
- [Implementation roadmap](docs/IMPLEMENTATION_PLAN.md)
- [Operational budgets](docs/OPERATIONAL_BUDGETS.md)
- [Architecture decisions](docs/adr/README.md)
- [Operational runbooks](docs/runbooks/README.md)

The first release targets a single operator, one trade-enabled strategy per
brokerage account, and a small universe of liquid U.S. ETFs using bar-based,
regular-hours, long-only trading. The React browser application is optimized for
desktop viewports; native desktop, PWA, and mobile applications are out of scope.
Live trading is gated behind point-in-time data validation, backtesting, shadow
replay, paper trading, reconciliation, and operational-readiness checks.

## Current implementation status

The local application implements the Phase 0 walking thread, a **local Phase
1A/1B point-in-time data plane and fail-closed admission framework**, and the
complete **Phase 2 deterministic-fixture engine and durable research workflow**.
Phase 3 has begun with bounded, pure-domain `rolling_close_mean` feature and
feature-derived target contracts, including exact batch/incremental parity
against repository-owned manifest-bound replay evidence, plus a durable bounded
experiment-governance registry with opaque pre-reveal holdout commitments and
read-only inspection. Configuration-neutral segment inputs and
configuration-bound target-parity completion receipts now close the reference
path from one governed attempt to its exact strategy policy. General segment
workers and process isolation, queryable replay transcripts, performance
evaluation, captured-tape and shadow workflows, and the rest of Phase 3 remain
incomplete.
Phase 4 has begun with bounded, non-authorizing Alpaca paper contracts. Phase
4A records the reviewed provider capability and deterministically describes a
candidate DIA, IWM, QQQ, and SPY whole-share market `DAY` request with
`extended_hours=false`. Phase 4B decodes a bounded, deliberately narrow local
wire profile for synthetic client-order lookup responses, preserves nanosecond
timestamps and exact response digests, distinguishes request-economics matches
from mismatches, and treats every 404 as inconclusive. The found fixture is
documentation-derived; the 404 body values are explicitly unqualified
synthetic examples. Phase 4C durably commits exact broker-response bytes and
allowlisted versioned metadata before decoding, with a 1 MiB capture bound,
stable delivery idempotency, and an independent terminal-head-anchored,
predecessor-linked account-local sequence. Phase 4D adds durable
rolling-window request permits with stable demand idempotency and protected
UNKNOWN-recovery/cancel/reconciliation capacity. Phase 4E adds strict offline
account and candidate-asset descriptions and observations, and routes their
exact bytes through the Phase 4C persist-before-decode boundary. Synthetic
fixtures can demonstrate a locally usable response shape but cannot bind a
provider account, establish a security master, or prove current account/asset
readiness. Phase 4F adds a pure dispatch-preflight assessment that cross-binds
the pending attempt, exact Alpaca request, parent UNKNOWN snapshot, risk
session and remaining reservation, stable fence receipt, raw-first
account/asset observations, and purpose-matched request permit. It derives the
budget correlation instead of accepting a caller readiness claim, but the
assessment explicitly retains every missing runtime gate and cannot mark the
attempt in flight. Phase 4G adds one bounded authenticated
`GET /v2/account` runtime. It requires an operator-pinned provider UUID and
versioned paper secret reference, durably reauthenticates reconciliation-tier
request capacity, validates the same stable fence before and after a strict
TLS/no-redirect/no-proxy request, persists raw bytes before decoding, and
commits a short-lived append-only account-binding chain. Credential values are
redacted and owned mutable buffers are zeroed. Phase 4H adds one exact
authenticated candidate-asset read,
requires that Phase 4G binding to remain the fresh durable terminal account
fact, independently pins the provider asset UUID, consumes another new
reconciliation permit, persists raw bytes first, and appends a short-lived
account/instrument binding without granting order authority.
Phase 4I adds one authenticated client-order-ID lookup for an exact durable
submission attempt that is still `UNKNOWN` immediately before send and again
after the raw response. It consumes protected UNKNOWN-recovery capacity,
requires the same current recovery fence and terminal provider-account
identity anchor before and after transport, persists bytes before decoding, and
compares the independent security-reference asset UUID on a 200 response. A
null or different canonical UUID remains a typed security-identity mismatch.
The result is historical observation evidence only: neither a current account
status window nor present asset tradability is required, a 404 remains
inconclusive, and no outcome resolves or resubmits the attempt.
Phase 4J adds a durable local schedule for that exact UNKNOWN lookup path. It
binds the original `IN_FLIGHT` and terminal `UNKNOWN` events, consumes at most
the latest due one-shot slot after a delayed poll, coalesces missed slots
instead of replaying a restart backlog, and stops issuing at the original
dispatch's 60-second uncertainty deadline. Every selected slot derives a fresh
request and raw-delivery identity; every scheduler result leaves the attempt
`UNKNOWN` and non-resubmittable.
Phase 4K reauthenticates an exact Phase 4I receipt and its Phase 4C raw source,
re-decodes the retained bytes, and appends a normalized historical
reconciliation-evidence fact. Matching orders remain non-applying candidates;
request-economics and security-identity mismatches are quarantined; and a 404
remains inconclusive. Exact provider timestamps and cumulative order values
are preserved without being promoted to event ordering, executions, fees, or
current broker state.
Phase 4L maps each exact authenticated Phase 4K fact into a versioned,
source-scoped historical inbox request. Its identity is deliberately limited
to that one lookup source, so separate authenticated lookups remain separate
even when their decoded values match. Durable normalized requests retain exact
Phase 4K payload/digest lineage; predecessor-linked account-local source links
and a terminal head order their admission; and one fixed-policy receipt
explicitly records non-application. A matching order is withheld for an
unqualified provider revision identity, economic/security mismatches remain
quarantined, and a qualified 404 remains inconclusive.
Phase 4M adds a pure bounded order-page traversal contract for descending
`GET /v2/orders` reads. Each page has a distinct reconciliation demand and
must enter the Phase 4C raw journal before strict decoding; later pages use
only the preceding full page's terminal order ID as `before_order_id`. A short
page ends only that non-isolated cursor walk, while a full eighth page is
bounded truncation. Phase 4M has no authenticated transport or durable
traversal workflow and grants no snapshot, revision, deduplication,
application, reconciliation, or trading authority.
Phase 4N adds a pure two-capture comparison for distinct, strictly ordered
Phase 4M sources with the same account and traversal profile, disjoint raw
receipts, and a fixed two-second qualification interval between the earlier
final and later first page observations. It compares page-boundary-independent
sorted provider-order ID and order-digest views and reports exact added,
removed, and changed IDs. Safety-truncated traversals remain incomplete,
too-close views remain waiting, and even an exact qualified match remains
explicitly unqualified with `converged=false`. Phase 4N adds no persistence,
runtime, readiness, or authority.
Phase 4O adds an authenticated, durable one-page-at-a-time runtime around the
Phase 4M traversal. It persists the exact next-page preparation before
credential resolution or permit issuance, consumes one fresh reconciliation
permit, holds the same account fence and terminal Phase 4G identity across a
strict raw-first request, and commits a contiguous page receipt under a final
transaction-internal fence check. A restart can derive only the exact next
page after a committed prefix; a durable preparation is single-use and any
crash after it cannot resend.
Cursor exhaustion remains non-isolated, an eighth full page remains bounded
truncation, and neither state establishes convergence or reconciliation.
Phase 4P reloads two exact terminal Phase 4O prefixes, reauthenticates their
durable sources, recomputes the Phase 4N result, and appends an immutable
account-local comparison receipt. The receipt binds both plans, terminal page
receipts, capture/view digests, derived differences, disposition, predecessor,
and current commit fence. Cursor-exhausted equality remains unqualified and a
bounded-truncated pair remains incomplete; persistence grants no convergence,
application, readiness, or trading authority.
Phase 4Q adds a deterministic one-step supervisor over an ordered pair of
Phase 4O plans. Each invocation reloads authenticated durable head state and
can append at most one exact page, return an explicit wait before the later
capture's two-second scheduling boundary, or invoke the idempotent Phase 4P
comparison after both captures end. Returned pages and reloaded states must
prove exact one-page advancement with the other capture unchanged. There is no
loop, sleep, automatic resend, deployed worker, convergence claim, or new
authority.
Phase 4R adds one bounded raw-first `GET /v2/positions` contract. Exact bytes
enter the Phase 4C journal before a strict USD U.S.-equity profile is decoded;
the response is capped at 512 positions and one mebibyte, preserves every
required decimal lexeme, and rejects duplicate asset identities, optional-field
or local-currency profile drift, and overflow without truncation. An empty
array remains historical evidence, not proof that the account is flat, and the
slice adds no transport, canonical position, reconciliation, readiness, or
trading authority.
Phase 4S compares two distinct Phase 4R sources by a stable sorted asset-ID and
exact-position-digest view. It reports added, removed, and changed asset UUIDs,
waits until the local receive observations are at least two seconds apart, and
then reports either a difference or an exact match that remains explicitly
unqualified. Raw JSON order and formatting do not affect the view, while exact
decimal lexeme changes remain visible. Local timing and equality establish no
provider revision, snapshot isolation, convergence, or authority.
Phase 4T wraps one Phase 4R capture in an authenticated single-use runtime. A
fresh durable preparation must succeed before credential resolution, permit
issuance, or transport; any stalled, completed, overlapping, or restarted use
of that capture fails before those effects. The runtime consumes one new
reconciliation permit, preserves the same terminal Phase 4G provider-account
identity and account fence around a strict raw-first `GET /v2/positions`, and
requires an independent in-transaction fence check before exact commit and
reload. It deliberately has no retry, SQL implementation, deployed resolver,
snapshot-completeness claim, canonical position state, convergence, readiness,
or trading authority.
Phase 4U supplies the concrete SQL repository for that port. One immutable plan
row is the durable claim and an optional one-to-one immutable receipt is the
only completed state; a claim without a receipt is conservatively stalled.
Stable capture and account-idempotency uniqueness prevent a changed binding or
credential reference from reusing the request identity. Commit and load
reauthenticate the exact binding, permit, raw receipt, fence history, and typed
capture; operational readiness verifies the complete store, and nonempty
history cannot be downgraded. The binding remains identity-only after its
five-second status TTL, and persistence adds no retry or account-state
authority.
Phase 4V reloads two exact Phase 4U receipts, requires the same pinned provider
account UUID, recomputes the Phase 4S comparison, and appends an immutable
account-local receipt under a current fence. Exact retries reauthenticate the
sources and current call fence while returning the original historical
receipt. Signed receive-time separation remains signed; raw-ingress order, not
wall-clock monotonicity, establishes the source roles. Phase 4W adds a
restart-derived one-step supervisor over the two single-use plans. Each call
can execute only the earlier capture, wait without I/O for the fixed
two-second boundary, execute only the later capture, or invoke Phase 4V after
both sources are complete. Stalled states observed at invocation fail before
effects; a concurrent unselected mutation is rejected after the single bounded
read. The later preparation, request, receive time, and ingress sequence must
authenticate the boundary. All three ports must identify the same process-local
durable store. Phase 4X closes the registered position-pair pre-effect race
with globally unique durable memberships, role claims, and atomic claim
consumption into the unchanged Phase 4U plan-as-claim. If ordinary Phase 4U
preparation wins the account lock first, pair admission records nothing; if
pair admission wins, unscoped preparation of either member fails before
credentials, request capacity, or transport. An unconsumed claim cannot cross
a lease renewal or takeover. Phase 4Y composes that admission through the
unchanged Phase 4T runtime and Phase 4W selector. Every W/V source load
reauthenticates its exact role claim and consumption; the selected Phase 4T
call receives a claim-consuming Phase 4U adapter and a coordinator adapter
pinned to the claim's exact lease digest and expiry. One call still performs at
most one capture, wait, or comparison, no database transaction spans provider
I/O, and the distinct result retains the unchanged Phase 4W/T/U evidence plus
its exact Phase 4X history.
Phase 4Z advances the Phase 4Q supervisor to a coherent-store version 2
contract. Its Phase 4O state loader, one-page workflow, and Phase 4P comparison
repository must expose the same exact positive process-local SQL-engine
identity before either source is read, the trusted clock is consulted, or any
page/comparison path can run. The opaque identity is never canonical evidence.
This rejects split-store composition before request capacity or provider I/O,
but it does not close the same-store race in which an unscoped caller prepares
the unselected order plan during the selected page request; durable order-pair
and per-page admission are supplied by the later Phase 4AA boundary.
Phase 4AA closes that pre-effect race with a durable two-member pair, gap-free
per-page claims, and one-to-one same-lease consumption of the unchanged Phase
4O preparation under the shared account lock. Public Phase 4O preparation
rejects registered members, while transition-aware reads and startup
verification require every registered stalled or committed preparation to
resolve to its exact consumption. Revision 0024 also normalizes every Phase 4O
preparation into an immutable fact, backfills completed pages and sole stalled
heads, and may safely regenerate that derived projection only when the
non-derived transition history is empty. Phase 4AB composes that admission
through the Phase 4Q/4O/4P runtime. Every source load authenticates its ordered
per-page claim/consumption history; the page workflow claims the exact
Q-selected prefix and source head, consumes it as the unchanged Phase 4O
preparation, and pins that page's own lease through credential, budget,
raw-first transport, commit, and reload checks. One call still performs at
most one page, no-I/O wait, or one comparison, and no transaction spans
provider I/O.
Phase 4AC composes the Phase 4J/I/K/L UNKNOWN-recovery evidence path. Before
any read, clock, credential lookup, or broker effect, every durable participant
must expose the same process-local SQL-store identity. A restarted invocation
attaches a Phase 4I receipt found under the Phase 4J ticket's deterministic
raw-ingress identity, then replays all attached receipts through idempotent
Phase 4K normalization and Phase 4L non-application before the schedule may
execute one new lookup. A final bounded pass repairs the same prefixes after
that step. The returned ordered evidence remains non-authorizing and cannot
resolve UNKNOWN, apply broker facts, release reservations, or resubmit.
Phase 4AD adds a local-only bounded raw-first account-activity traversal.
It freezes `GET /v2/account/activities` with `activity_types=FILL`,
`direction=asc`, page sizes no greater than 100, and exact last-activity-ID
page tokens. Each page has distinct reconciliation demand and durable raw
ingress before strict FILL decoding. The contract preserves exact IDs,
timestamp and decimal lexemes, rejects duplicate or overlapping activities,
and distinguishes a terminal short page from a full-page local truncation.
Phase 4AE advances exactly one such page through authenticated credentials,
request-budget admission, restricted transport, raw-first retention, and a
single-use durable preparation under one account fence. Migration 0029
persists tamper-evident plans, preparations, receipts, and traversal heads;
ambiguous post-preparation crashes fail closed instead of resending. Phase 4AF
purely compares two bounded captures, Phase 4AG reloads and authenticates both
exact Phase 4AE sources before recomputing that comparison, and migration 0033
lets Phase 4AH retain one immutable account-local comparison receipt and
authenticated predecessor chain. Phase 4AI selects at most one page effect,
one comparison append, or one explicit wait per invocation from reloaded
durable state. All of this evidence remains historical and non-authorizing:
it does not prove complete activity history, convergence, canonical
execution/correction identity, cross-channel deduplication, reconciliation,
application, readiness, or trading authority.
Phase 5A adds a local durable operational-control spine. Its fixed severity
order is `RUNNING < PAUSED < DRAINING < FLATTENING < HALTED`; every command
except manual re-arm preserves the stronger state. Account/actor-scoped
idempotency, immutable predecessor-linked transition history, authenticated
heads, breaker trips, and explicit drain/flatten completion or residual facts
survive restart. Explicit absence maps to batch-risk `HALTED`; unreadable or
corrupt evidence raises and every authorization caller must deny rather than
inventing a state. `DRAINING` and `FLATTENING` map to the existing batch-risk
`PAUSED` vocabulary. Re-arm is the only downgrade and remains unavailable
without an exact current head, authenticated human action, fresh readiness,
authoritative clean reconciliation, blocker dispositions, and any required
terminal operation result. An explicit retry after an incomplete drain or
flatten opens a distinct operation attempt at unchanged severity; unrelated
no-op commands preserve the active attempt.
Phase 5F adds a loopback-only authenticated operations API over that spine.
Reads and commands require the signed local-operator cookie and matching CSRF
token; mutations additionally require an idempotency key and accept only a
bounded reason code. `REARM` is proof-constructed from an injected
server-authoritative verifier and commits through a dedicated exact-head
repository path; browser assertions and the public raw repository path remain
unable to downgrade control. The authenticated durable local composition reads
one repeatable SQL snapshot and exposes database-only `PAUSE` and `HALT` over
an already initialized control head on that exact engine. It does not
initialize control or expose drain, flatten, re-arm, assignment, execution, or
broker authority. Missing composition fails unavailable, and the advanced-risk
assignment route is absent without a current-fence authority.
Phase 5B began with a separate approval-gated, observe-only advanced-risk
contract. Proposed measurement bindings, explicitly unapproved policy
candidates, causal source references, typed incomplete/overflow evidence, and
structurally complete bundles are content-addressed and bounded. Those
proposal artifacts remain non-authorizing. ADR 0068 now freezes a separate
owner-approved moderate policy specification for the exact paper-only,
regular-hours DIA/IWM/QQQ/SPY cash-account scope. The local evaluator, immutable
policy/assignment/evidence/assessment persistence, authoritative source-shape
adapters, and additive atomic cutover/admission implementation are locally
verified, including exact outcome retry, rollback, startup integrity, and the
final dispatch gate. The path remains disabled by default, and no deployment
assignment or source authority is inferred. The existing BatchRisk and Phase
5A policy digests remain unchanged.
Phase 5C runs each strategy decision in a strict one-request subprocess with
bounded input/output, a sanitized environment, no shell, a two-second warning,
and an inclusive five-second kill deadline. A durable pre-run claim under the
current account fence is the only authority to invoke the runner; retries and
restarts never rerun an unresolved claim. A repository-bound one-shot permit
expires after a strict one-second start window, and bounded due scans expose
recoverable claims without an unbounded walk. At the fixed nine-second
boundary—one second to start, five seconds to execute, and three seconds for
aggregate cleanup—the current fence may finalize an orphan as one
deterministic `CRASH`. Result, finalization, control, and alert facts commit
atomically; the legacy direct result writer is locked out when lifecycle
tables exist. Every timeout, crash, protocol error, or resource overflow
requests severity-preserving `PAUSED` and opens a critical-alert incident; a
completed invocation neither changes control nor re-arms the account. Order,
risk, broker-event, cancel, and reconciliation loops remain outside the child
process. ADR 0087 adds the first repository-owned executable for this boundary:
a standard-library-only no-exposure smoke strategy and canonical manifest. The
loader verifies stable bounded files and code-pinned manifest/artifact SHA-256
values before it constructs the strict subprocess spec; its trusted bootstrap
hashes and executes the same bounded source bytes, and the child returns only a
batch-bound `NO_EXPOSURE` observation with an empty intent list.
`make no-exposure-smoke-verify` performs credential-free offline byte/manifest
verification without running the child. The artifact has no deployment,
account assignment, startup, control, risk, dispatch, or broker authority.
Phase 5D adds a local durable, provider-neutral critical-alert boundary.
Source-idempotent incidents, claim-before-effect delivery attempts, and
sanitized receipt/failure results survive restart and are verified at
readiness. Strict one-/15-/30-second baseline milestones require both UTC and
monotonic evidence, equality misses, exact retries never resend, and concurrent
same-key claims converge on one provider request. A bounded history-first
worker scans with a stable cursor, resolves only the selected adapter, never
resends an unresolved claim, and derives total-delivery-failure evidence after
terminal route exhaustion or when an unresolved escalation reaches the
30-second equality boundary. Migration 0032 and the ADR 0085 same-store worker
reauthenticate the complete alert history and atomically bind eligible replay
evidence to exactly one fixed local, severity-preserving `PAUSED` transition
and source receipt. A provider-called terminal result must first become
durable and be replayed; terminal replay may bind immediately, while an
unresolved escalation cannot bind before its deadline. The older split
policy/writer path always fails unavailable. `PRIMARY` and `ESCALATION` remain
provider-neutral route classes. Secret-safe PagerDuty Events API v2 and Twilio
Messaging Service SMS adapters are implemented and tested locally, but amended
ADR 0088 defers both external providers. They are not composed into a route
plan or worker: destinations, recipients, credentials, escalation roster,
deployment schedule, probes, and policy activation remain absent.
Phase 5E adds local OpenTelemetry correlation for the six authoritative fact
types currently available together: market batch, target, reservation,
submission attempt, broker event, and ledger posting. Fill and reconciliation
remain explicitly missing rather than being relabeled from non-authoritative
inputs. Only opaque durable fact IDs and digests cross the local trace boundary;
W3C Trace Context is accepted without baggage, and bounded asynchronous export
cannot become trading authority. ADR 0088 selects Sentry for paper diagnostics.
A local Sentry Cloud OTLP/HTTP trace-exporter factory derives the fixed trace
endpoint and authentication header from a validated DSN while redacting that
header from representations and failures, pins service/release/environment, and
removes account/fact IDs and other non-allowlisted span data before delegation.
On 2026-07-29, the operator supplied a DSN outside the repository and observed
transport acceptance for one sanitized synthetic export. That is a dated,
non-durable setup observation, not checked-in readiness evidence. The exporter
remains uncomposed: no sampling/runtime wiring, retention/access enforcement,
outage probe, reproducible transport receipt, or queryable-ingestion evidence
exists.
Phase 5G adds a GET-only React operations snapshot plus a separate,
capability-gated fail-safe control client. The snapshot presents the
environment, freshness, strategy/deployment, orders, fills, account/ledger,
risk, reconciliation, alerts, and control history as one explicitly read-only
projection. The client exposes only advertised `PAUSE` and `HALT`, requires a
bounded reason and explicit confirmation, preserves one idempotency key for an
ambiguous retry, and refreshes the authenticated account overview after
success. Missing authorities are shown as unavailable, responses are
non-cacheable, and development fixtures cannot enable mutations. The routes
require the signed local-operator session, matching CSRF header, loopback
transport, and durable readiness. Neither surface calls a broker or claims a
broker-authoritative paper-account view.
Phase 5H adds a pure typed local fault-drill evidence contract for kill-state,
strategy-failure, total-alert-failure, data-gap, broker-disconnect, and
risk-trip scenarios. Inclusive deadlines, minimum control severity,
new-exposure withholding, unavailable evidence, and the prohibition on
automatic re-arm determine each result. The machine-readable pytest catalog
remains separate from this typed evidence, and neither can stand in for a
deployed provider, broker, telemetry, or wall-clock game day.
Phase 5I adds a digest-only historical paper-account enrollment attestation.
One repeatable-read snapshot authenticates every binding chain, reconstructs
the configured account's complete durable source lineage, and requires the
exact terminal binding to match all four nonsecret identity pins. It accepts
the expired five-second status window only as historical identity evidence and
grants no current-status, control, broker, exposure, automatic-rearm, or
strategy-invocation authority.
Phase 6A adds a pure provider-neutral trusted-time reducer, one injected probe
step, and a local durable evidence composition. It derives signed source offset
from an exact UTC probe midpoint, correlates monotonic cadence, applies the
reviewed `<250 ms` healthy, inclusive `250-1,000 ms` warning, and `>1,000 ms`
hard/latching bands, and requires a gap-free 60-second healthy chain before it
offers clock-recovery evidence. Every process registers a fresh, non-resumable
epoch; immutable attempt history records successes and sanitized failures, an
exact host-head compare-and-swap fences stale processes and concurrent probe
losers, and startup replay rebuilds state only through the public reducer. The
history is tamper-evident rather than externally authenticated or rollback
proof. No actual time source, watchdog, scheduler, reviewed source-uncertainty
bound, readiness/control/exposure gate, alert, or re-arm authority is selected
or deployed. On 2026-07-31, owner-approved migration 0034 was applied to the
runtime Supabase database; the three new tables were present with empty
histories and the full operational-schema integrity gate passed.
Phase 6B lazy-loads implemented browser feature routes behind an accessible
fallback, leaving the shared shell and the remaining production
browser-security, performance, SSE, and multi-browser work open.

These slices still cannot publish a general security master, prove an
exchange-calendar binding, a quote collar, a current canonical position or
reduce-only behavior, reconciliation, or dispatch authority. The production
worker/trading runtime does not configure a secret-store resolver or compose
the Phase 4G/4H/4I/4J request path, Phase 4K evidence workflow, Phase 4L inbox
admission, Phase 4M/4N traversal/comparison, Phase 4O page runtime, or Phase 4P
durable comparison workflow through the Phase 4Q one-step supervisor. Phase
4V's durable position comparison through Phase 4Y and Phase 4Z's coherent
order-view supervisor likewise have no deployed resolver, scheduler, or worker
composition. Phase 4AA's durable transition repository and Phase 4AB's
pair-admitted runtime composition are local and non-authorizing. Phase 4AC's
restart-safe UNKNOWN composition is likewise local and does not deploy the
lookup worker. Phase 4AD through Phase 4AI now provide bounded raw models,
authenticated one-page persistence/runtime, pure and authenticated
comparisons, durable comparison history, and one-step supervision locally.
No deployed resolver or scheduler uses them, and stream-overlap qualification,
canonical execution/correction identity, complete-history proof,
reconciliation, and application remain unimplemented.
Phase 5F exposes only the local authenticated operations boundary; the default
durable composition has an authenticated SQL overview and database-only
`PAUSE`/`HALT`, but no control initialization, drain/flatten executor, re-arm
verifier, assignment authority, or broker port. No route executes broker
cancel/drain/flatten actions, qualifies reconciliation, or enables remote/live
operations. Phase 5B has an approved paper-policy
specification and local persistence/evaluation/cutover work, but no deployed
runtime assignment or deployed authoritative metric producers; atomic
admission, final dispatch reauthentication, and startup-integrity verification
are locally complete.
Phase 5C selects no deployed strategy artifact or runtime sandbox and performs
no broker action. Phase 5G keeps its walking-thread snapshot observational; its
separate browser client can request only server-advertised `PAUSE`/`HALT` and
marks missing coordinator, reconciliation, alert, and control authorities
unavailable.
Phase 5D has tested local PagerDuty/Twilio adapters but no deployed worker,
credentialed route/recipient composition, channel probe, escalation roster, or
approval to activate the fixed local total-delivery-failure `PAUSED` policy and
its exact actor/authority digest. The atomic failure-control seam grants no
broker action.
Phase 5E has a tested local Sentry OTLP trace-exporter factory. A DSN and
sanitized transport acceptance were observed by the operator on 2026-07-29,
but that non-durable setup observation is not a checked-in or reproducible
receipt. Runtime composition, queryable-ingestion proof, and enforced telemetry
retention/access policy remain absent. Phase 5H records only deterministic
local drill evidence; deployment and wall-clock drills remain unrun. None of
these local slices closes the Phase 3, Phase 4, or Phase 5 deployment and drill
exit gates.
Amended ADR 0088 now selects a supervised local paper-smoke preflight without
activating trading: an unbound exact-image verification plus a separate
host-side database/Sentry check using the owner's Mac CPU/RAM, a Supabase Free
runtime database, one historically enrolled Alpaca paper account, the verified
no-exposure artifact, and Sentry diagnostic configuration. ADR 0089 adds an
exact read-only historical enrollment attestation without refreshing the
account or resolving or using Alpaca API credentials. Hosted or unattended
compute, PagerDuty, Twilio, paid Supabase capacity, and an external
stale-heartbeat watchdog are deferred. `PAUSED` is the configured
non-authorizing policy. The current preflight creates no control state and
authenticates no account-bound durable control head; its aggregate control scan
rejects any `RUNNING` head. Live credentials, public operations ingress,
automatic re-arm, and provider substitution fail closed.
With no external notification route or independent watchdog, the checks must
run during an operator-declared, directly observed window; they cannot qualify
as unattended or Phase 5 deployment evidence. The v2 typed deployment
assessment keeps smoke readiness separate from Phase 5 activation readiness and
permanently records local supervision and deferred external alerts as
activation blockers. The production image uses digest-pinned bases, is
non-root, has no inbound port, defaults to a nonzero paper admission, and keeps
the verified strategy inputs root-owned; the local workflow resolves its exact
inspected `sha256:` image ID rather than treating a mutable tag as immutable. CI
builds and executes the fail-closed image contract.
Current account-status evidence, Sentry queryable-ingestion proof, authoritative
risk/fill/reconciliation/time/re-arm facts, external alert and watchdog
evidence, and deployed timed drills remain required for later activation. See
[ADR 0088](docs/adr/0088-fail-closed-paper-smoke-deployment-profile.md),
[ADR 0089](docs/adr/0089-read-only-paper-account-enrollment-attestation.md), and the
[paper smoke deployment runbook](docs/runbooks/paper-smoke-deployment.md).
The credential-aware local preflight consumes the owner-only
`AQT_DATABASE_URL`, `AQT_TEST_POSTGRES_URL`, `AQT_SENTRY_DSN`, and all-or-none
nonsecret `AQT_PAPER_*` identity bindings, verifies distinct Supabase
session/TLS identities and the exact migrated schema, validates the inspected
local image ID and artifact pins, and can report `smoke_preflight_ready`. It
runs on the host and does not execute a credential-bound container. It leaves
the Alpaca API credential variables unrequested, unreturned, unresolved, and
unused, authenticates only the configured historical terminal enrollment,
reports external notifications unavailable and every authority flag false, and
keeps Phase 5 activation blocked. The shared dotenv parser still parses the
owner-only file before filtering selected variables, so the preflight process
remains inside that file's credential boundary. These checks are
preflight evidence only: durable strategy claims require an authenticated
account-bound `RUNNING` head, while this profile supplies only a configured
non-authorizing `PAUSED` policy. Its control observation remains aggregate and
unbound—either no heads or only non-running heads—and cannot authorize an
invocation. No durable strategy invocation has run, and Phase 5 remains open.
The owner-operated paper-account enrollment also has a fail-closed recovery
mode for exactly one reviewed generation-one raw-only checkpoint. It requires
a distinct new operation UUID and explicit approval for one second account
`GET`, atomically limits acquisition to generation two, retains all prior
evidence, and stops permanently after that attempt. The separately approved
recovery succeeded on 2026-07-31 and created the first account-local binding;
its status freshness has expired and ADR 0089 treats it only as historical
identity. See the
[paper smoke deployment runbook](docs/runbooks/paper-smoke-deployment.md).
The application does not ingest
from an admitted market-data vendor,
connect to a broker in a deployed process, submit paper orders, or submit live
orders. Secret-safe access probes and separately authorized research-capture
tools do not change that state.
Paper and live startup fail closed, the Phase 4 and Phase 5 exit gates remain
open, and the trader entrypoint is an explicit `not_ready` paper-profile
preflight rather than a trading loop.

The walking thread uses trusted clocks, payload-bound risk decisions, atomic
account cash reservations, single-use consumption, and a durable submission
attempt before the simulated order is recorded. Durable readiness requires the
exact Alembic schema revision plus read-only authorization, reservation,
submission, order, and ledger integrity checks; application startup never
creates production tables implicitly.

Phase 2 now adds durable SQL account leases and fences, gap-free generation and
predecessor-bound renewal history, transaction-internal trusted-clock checks,
and atomic intent-batch risk decisions bound to the exact authenticated
remaining-capacity universe. Decisions and every capacity-affecting submission,
order, and release fact serialize on the same account head. A monotone
per-account observation sequence plus authenticated mutation watermarks makes
historical reconstruction unambiguous even when timestamps are equal.
Broker-request preparation precedes dispatch; submission attempts are append-
only; stale `PENDING` may become
proven-unsent `ABANDONED`; UNKNOWN freezes its parent; and execution accounting
is canonical-ledger-bound, revision-ordered, and sticky on any non-monotone
correction. Partially released and frozen children continue to consume their
exact remaining holds; fully released children no longer consume capacity. The
typed simulation-horizon path replays its exact calendar, instrument universe,
model, request, and attempt chain before releasing residual fixture capacity.
Its fixture-only research path registers immutable strategy/configuration/
fixture pins, runs bounded durable jobs under rotating exact claim tokens and a
process-unique worker identity, and retains content-authenticated reports and
run manifests. The local API and React **Strategies** and **Backtests**
workspaces provide catalog selection, loopback-scoped signed and CSRF-protected
idempotent launch, job progress/history, and verified metrics, equity, trade,
position, ledger, and provenance views.

The worker now ingests a strict recorded JSONL adapter through a provider-neutral
historical-source port into immutable,
content-addressed raw and normalized Parquet objects. PostgreSQL atomically
publishes ingestion jobs, security lifecycle, calendar, universe, corporate
actions, feed entitlement, quality findings, quarantine, ordered partitions,
and manifests. Causal reads require an explicit manifest and `as_of` time. The
browser's **Datasets** and **Data quality** workspaces expose this evidence,
including the persisted admission profile, deterministic gate report, and
individual checks. The fixture is permanently blocked from admission. Selecting and admitting a real
licensed point-in-time vendor remains required before Phase 1 can be declared
complete or paper trading can begin.

The market-data boundary also supports session-defined daily bars and a bounded,
immutable Sharadar SFP research capture. SFP's adjusted OHLCV is preserved with
its actual basis and is deliberately blocked from the canonical raw execution
lane; it never enters canonical raw bars. Future exact-page capture is
fail-closed until a reviewed authorization artifact permits local research
storage for the requested dates and binds the digest of the applicable terms.
The capture does not alter admission or trading readiness.

ADR 0012's offline Tiingo EOD qualification slice is implemented against
repository-owned synthetic fixtures. It hardens strict schema parsing,
documented-raw-candidate versus adjusted field separation, corporate-action
candidates, symbol/session coverage, receipt-time causal knowledge, and
deterministic identity. Results are permanently marked `synthetic_contract_only`
and cannot emit canonical bars or admission evidence. The slice performs no
Tiingo capture and makes no claim about a live payload. Exact capture and a
production `HistoricalBarSource` remain blocked until Tiingo-specific storage
rights, the exact product and venue provenance, identity/calendar/action
authorities, publication/revision lineage, and observed bytes are reviewed and
qualified.

ADRs 0013-0015 implement the authorization-gated capture, pinned-calendar, and
descriptor-safe offline verification seams. On 2026-07-17, one bounded operation
passed its exact reviewed profile, local-retention/research authorization, and
calendar gates and retained the completed 2026-01-02 session for DIA, IWM, QQQ,
and SPY beneath the ignored owner-only capture tree. The offline verifier checked
the immutable tree, manifest and object digests, schema, calendar, and exact
four-row coverage. No response bytes are checked into Git, and this research
baseline has admission and trading effects of `none`. Every later request still
requires a fresh applicable authorization decision.

ADRs 0016-0019 add receipt-time local-lineage mechanics, exact retained-field
routing, security-identity/lifecycle contract mechanics, and market-semantics
and action-candidate contract mechanics. Lineage remains synthetic-only because
a second actual capture has not been authorized. The retained-field boundary has
qualified the exact baseline only as value-free documented candidates. No
production identity/lifecycle or market-semantics/action artifact has passed, so
the actual baseline remains neither identity-qualified nor
market-semantics/action-qualified. None of these boundaries invents vendor
publication time, historical vintages, corrections, raw-price authority,
corporate-action events, `HistoricalBarSource`, admission, or trading readiness.

ADR 0020 begins the first Phase 2 engine slice against repository-owned
synthetic events. It adds a UTC monotonic simulated clock, deterministic
availability-time ordering, non-regressing event-time watermarks in closed
order, proof-constructed complete/missing market batches, global
source/observation revision-chain binding, compact canonical decimals, typed
Phase 2 identifiers, exact versioned portfolio/risk arithmetic, and semantic
replay digests. Strategy contexts bind an
exact batch identity and digest, target tuples are immutable/sorted/unique, and
`ReplayResult.complete_batch_ids` names every strategy-eligible proof. The
walking thread now invokes its strategy through this canonical batch seam.

ADR 0021 connects repository-owned fixture manifests to that reducer through a
content-verified, all-revision RawBar tape. Calendar/universe pins produce the
inclusive decision schedule with an explicit lag, so quarantined or missing
rows remain visible as skipped evidence. A successful fixture replay can be
atomically sealed as a content-addressed run manifest with separate full-source
and projected-replay digests plus explicit runtime pins. Failed or late-event
runs write nothing. This reducer evidence is not by itself a backtester, mutable
job, API command, browser result, benchmark, or trading capability. ADR 0033
later composes it into the narrow fixture-only research workflow; paper/live
readiness remains unchanged.

ADR 0022 completes the synthetic Phase 2A strategy callback/state boundary. A
separate pure reducer canonically interleaves complete market batches with
explicit UTC clock schedules, gives every callback a typed market/clock cause
and immutable fixed-clock/context snapshot, and carries bounded versioned state
through exact predecessor-linked transitions. One captured runtime pin prevents
strategy identity, version, configuration, or state-schema drift during a run.
Its in-memory transcript hashes
the initial positions, schedule, every input/output state, and every complete
target payload. The existing sealed replay manifest remains callback-free and
unchanged.

ADR 0023 begins Phase 2B with immutable causal portfolio/price snapshots and
canonical multi-instrument intent batches. Both market- and clock-triggered
targets can now be converted without inventing price causality; full snapshots
liquidate omitted holdings, partial snapshots touch only named instruments, and
every intent carries the complete target, decision-trigger, source-price, and
strategy-configuration evidence into the risk payload hash. The Phase 0
one-position adapter remains compatible. This pure reducer itself adds no
durability or authority; later Phase 2 ADRs compose its evidence into the
durable fixture workflow.

ADR 0024 adds the first canonical order/execution lifecycle reducer. Immutable
submission evidence feeds normalized per-order broker sequences for acceptance,
rejection, cancellation, partial or late fills, and exact predecessor-linked
execution corrections. Current execution heads deterministically project
cumulative quantity, remaining quantity, fees, and status while the complete
superseded transcript remains hashed. Cancel requests bind the exact observed
non-terminal order state. This reducer itself creates no broker effect or
trading authority; later Phase 2 boundaries persist and compose its evidence.

ADR 0025 adds the first expanded-ledger reducer. Explicit contributions,
withdrawals, executions, corrections, and busts become balanced append-only
entries, and exact cash, security-unit, fee, and execution trade-value balances
are rebuilt from those entries. Corrections post predecessor-relative deltas and
never erase the original financial fact. The trade-value clearing account is
not cost basis or realized P&L; the follow-on account, settlement, and
corporate-action reducers supply those distinct economics without changing this
ledger contract.

ADR 0026 makes the first account economics explicit: long-only FIFO trade-date
lots, immediate execution-fee expense, and causally recorded position marks.
The pure, account-bound projector proof-constructs its state, rebuilds corrected
lot history, reconciles units and fees to the append-only ledger, and re-derives
cost basis, realized/unrealized P&L, exposure, cash, and equity from retained
evidence. Later Phase 2 reducers add settlement and corporate actions. Margin,
shorting, multi-currency translation, and paper/live authority remain gated.

ADR 0027 adds explicit account-bound execution settlement without rewriting
trade-date history. Its proof-constructed state re-derives all obligations,
balances, and cash views. Exact execution-revision instructions reclassify cash
into receivables/payables, and separate source-bound confirmations move only
settled amounts back through cash. The projection distinguishes trade-date, settled,
and conservative available cash; open payables reduce availability and
unsettled sale proceeds never increase it. The following corporate-action
boundary composes with this state; real broker effects and trading authority
remain gated.

ADR 0028 adds source-bound stock-split and cash-dividend accounting. Stable
source action identities distinguish an economic event from its exact revision
and digest; explicit entitlements must reconcile to both causal ledger units and
the FIFO lot book. Whole-share splits preserve each lot's total basis and require
a strictly post-split mark. Dividends accrue receivable and income separately
from a bound cash-payment fact. Corporate-action corrections, fractional shares,
cash-in-lieu, broader security lifecycle effects, real broker effects, and
trading authority remain gated.

ADR 0029 adds the first provider-neutral `BrokerPort` implementation: a pure,
conservative simulator for explicit regular-hours sessions, including shortened
half-days, and whole-share DAY market orders. It consumes an exact current
single-use risk approval, accepts deterministically, and considers only the first
sealed market slice strictly after activation. That slice can fill only when
complete and is never skipped for a later complete slice; otherwise the order
remains working or fails closed according to its authorization path. Exact
calendar/session, source event, model, adverse per-share price offsets, and fee evidence are bound
into the result and canonical order transcript. The current close-only facts do
not authorize limit, volume/participation, liquidity, partial-fill, or broker
expiry behavior.

ADR 0030 adds an independent process-local atomic risk boundary for complete
intent batches. It revalidates the exact causal portfolio, account, settlement,
session, operational-state, and policy evidence before approving every member
or rejecting the batch as a unit. Conservative reservations do not fund buys
with sale proceeds or credit pending sells against exposure: buffered buy cash,
all fees, sell shares, aggregate notional, and pending buy exposure remain held.
One parent decision creates exact-payload one-shot child authorizations consumed
by the existing broker boundary; exact retries cannot reserve twice and identity
conflicts fail closed. Capacity retains sealed account-bound projections and is
re-attested from them at risk trust boundaries; a process-local account registry
prevents duplicate providers from creating independent reservation authorities.
After a capped child is consumed, an
incomplete or invalid first source or a reserved-cap breach remains an auditable
accepted-working result. ADR 0032 later adds durable SQL batch transactions and
reservation release; real reconciliation, paper/live adapters, and trading
authority remain gated.

ADR 0031 adds the bounded process-local account coordinator. Renewable leases
carry monotonically increasing fencing generations, validation receipts bind
the current lease revision and expiry, and clean handoff advances the
generation. A fenced broker wrapper holds the account lock while revalidating
current ownership and invoking the complete submission call, rejects reentrant
lease transitions, and returns exact fence/request evidence with the delegate
result. Expired abandoned ownership fails closed; durable takeover,
reconciliation, and cross-process safety remain gated by this process-local
contract. ADR 0032 later adds SQL lease state and transaction-time fence checks
without enabling automatic takeover or broker authority.

ADR 0032 completes the local Phase 2B durability boundary. Immutable SQL lease
revisions and lockable heads serialize owners across workers. Renewal revisions
form a gap-free predecessor chain, and the additive schema upgrade preserves
authenticated legacy lease identities while all new revisions use the chained
lease contract. Every batch-risk, preparation, dispatch, and reservation
mutation performs its exact fence check inside the transaction and samples the
coordinator's trusted clock there, so caller event time cannot backdate an
effect past real lease expiry. Batch decisions bind and persist the complete
authenticated remaining-capacity universe and publish with all child holds
atomically. A monotone sequence allocated under the same account lock orders
every approved, rejected, and no-action observation, even when timestamps are
equal. Each new capacity mutation binds the decision watermark after which it
became visible, so decision `N` reconstructs exactly the authenticated mutation
prefix below `N` rather than using wall-clock tie-breaking. The additive schema
upgrade preserves v3 decisions and marker-zero legacy mutations without
rewriting their canonical identity; all new decisions and mutations use the v4
ordering contract. Partial releases contribute only their remaining cash,
exposure, and sell-share holds to later decisions, frozen children retain those
remaining holds, and fully released children disappear from active capacity. Exact
execution-correction deltas complete their canonical ledger revision chains,
but unresolved correction provenance quarantines new batch authorization even
when the affected reservation was already fully released.
Submission preparation atomically publishes the deterministic logical order,
one-shot authorization consumption, bounded request, and initial `PENDING`
event before any possible broker call. Dispatch appends a fresh transaction-
time receipt for the prepared stable fence and current lease revision; only a
stale `PENDING` head with no possible broker effect can close as proven-unsent
`ABANDONED` and retry safely. Stale `IN_FLIGHT` work becomes `UNKNOWN` and
freezes its complete parent. The durable runtime rejects every persisted
`RESOLVED` attempt and generic reconciled-terminal fact, so UNKNOWN retry and
external reconciliation remain blocked.

Execution-accounted release re-derives the exact canonical ledger entry and
postings from the persisted order event, including quantity, price, fee, cash,
units, source, and time. Each correction requires exact cumulative coverage of
its predecessor revision; only the positive predecessor-relative delta may
release capacity, and any historical non-monotone correction freezes the
reservation permanently and blocks new account authorization until authenticated
closure. The fixture runtime may release residual capacity at
`SIMULATION_HORIZON_FINAL` only through a typed deterministic proof. SQL
readiness reruns the exact replay events and watermarks, reproduces the sealed
replay manifest, verifies the pinned calendar and instrument universe, requires
the proof and release to share the exact durable recording instant, reruns
`ConservativeSimulatedBroker` from the pre-dispatch committed model and request,
and cross-binds the result to the complete safe-retry attempt chain,
authorization, reservation, order, and final event. Every final execution head
must already have exact canonical-ledger accounting before this proof can
release residual capacity; an unfilled sealed order requires no execution
accounting. Downward or stale
corrections and unresolved UNKNOWN attempts remain frozen. These SQL contracts
add no real reconciliation, automatic takeover, operator re-arm, or paper/live
broker authority; those remain Phase 4 gates.

ADR 0033 completes the local Phase 2C fixture workflow. The API and worker
idempotently install the immutable golden strategy, configuration, and fixture
catalog; launch inputs must reproduce every dataset, replay, strategy,
benchmark, cost, fill, and metric pin. Audited jobs use bounded, recoverable
worker claims and append-only events. Every claim has a rotating content-
addressed token bound to the job, worker, attempt, and latest `RUNNING` event;
the worker chooses one process-unique identity, so even a same-ID stale attempt
cannot renew, fail, or publish a result after recovery. Successful jobs
atomically retain a content-verified run manifest and immutable report. The
golden run proves the raw-price buy/split/dividend/sell lifecycle with USD
1,044.04 ending equity,
future-correction causality, and exact repeatability. Launch is local-only and
requires durable readiness, a validated loopback transport, a process-bound
signed capability cookie, CSRF token, and idempotency key; the catalog accepts
no arbitrary strategy, parameter, dataset, or date-range execution. This local
capability is not user identity authentication.

ADR 0034 begins Phase 3A with one deliberately narrow feature contract.
`rolling_close_mean` binds an authenticated source tape plus its sealed replay-
run manifest, raw-close input semantics, `lookback=2`, publication lag,
implementation identity, and the
`SKIP_AND_RESET` missing-data policy. Every emitted snapshot is causal and
source-bound. An incomplete or skipped batch emits nothing, clears the rolling
history for every expected instrument, and requires two new complete
observations, so a window never crosses a gap. Full-sequence batch window
selection and authenticated incremental state must produce the exact same
canonical snapshots before a parity receipt can be constructed. Snapshot
availability is part of the evidence consumed by the next bounded slice. This
Phase 3A feature proof remains pure and in memory.

ADR 0035 implements Phase 3B for one versioned reference target rule. Complete
batch triggers receive only the latest parity-certified feature snapshot per
instrument from the current post-reset epoch where
`snapshot.available_at <= trigger.as_of`. Incomplete batches clear both visible
and delayed pending snapshots; insufficient feature evidence emits an audited
`WAITING` step and no target. Independent full-sequence-index and incremental
visibility paths must produce the exact same contexts and `TargetPortfolio`
sequence before a target-parity receipt can exist. Target configuration binds
the feature artifact and Phase 3A
receipt, while intent conversion still uses the causal market event—not the
feature value—as its reference price. This repository-owned synthetic-tape
evidence does not satisfy the captured-tape gate. Durable feature evidence,
job/worker integration, live capture, reconnect freshness, shadow replay, and
fitted features remain later Phase 3 work.

ADR 0036 implements Phase 3C as a bounded experiment-governance registry.
Families declare non-overlapping train, validation, and final-test segments,
frozen criteria, and a pre-holdout attempt budget. Train and validation
evidence is segment-scoped; before reveal, the final test is represented only by
an opaque content commitment. Stable research attempts retain append-only
queued, running, completed, failed, canceled, or abandoned lifecycle events, so
updates do not consume extra budget and unsuccessful work cannot disappear.
Only an exact completed validation configuration is eligible for final-test
selection.

A typed reveal authorization binds the family, frozen criteria, selected
configuration, opaque holdout commitment, exact pre-reveal registry head,
actor, reason, and time; the audited reveal is the first object allowed to
retain the exact certificate-derived test-evidence receipt. A global tape-role
ledger permits exploratory reuse while preventing exploratory/holdout
crossover and reserving each holdout tape to one family. Canonical tape
policies, family claims, families, attempts, lifecycle events, reveals, and
audit facts are retained through authenticated SQL storage and exposed through
read-only API and browser inspection. Phase 3C deliberately does not connect
to the Phase 2 fixture worker: its fixed complete tape cannot truthfully serve
as a train, validation, or final-test run. There is no experiment mutation API,
parameter-sweep runner, holdout-byte isolation, automated promotion, paper/live
authority, or completed Phase 3 exit gate.

ADR 0037 implements Phase 3D for the bounded reference evaluator. Family
segment evidence and the sealed final-test commitment are now derived from
configuration-neutral `CertifiedFeatureReplay` input. Once an attempt is
running, its exact `long_quantity` and `target_lifetime_seconds` configuration
must reproduce the policy in a successful `CertifiedFeatureTargetReplay`.
Only then can the same recorded running-actor identifier proof-construct a
`GovernedSegmentEvaluationReceipt` and complete the attempt. The durable event
payload binds the configuration, schema-validation receipt, source evidence,
feature and target certifications, parity receipts, runtime pin, transcript
digest, counts, and actor-identifier continuity. Read-only views expose those
digests and counts, never transcript contents or held-out observations. This is
causal target-evaluation evidence, not a P&L report, criteria decision,
promotion, deployment, or trading authority.

ADR 0038 begins Phase 4A with a pure Alpaca paper contract boundary. The
versioned capability matrix freezes the paper endpoint, authentication-header
names, supported provider breadth, candidate instrument mapping and request
shape, client-ID and pagination constraints, lifecycle classification, and the
currently documented request ceiling as reviewed on 2026-07-26. The
translatable shape is a whole-share simple market `DAY` buy or sell for DIA,
IWM, QQQ, or SPY with `extended_hours=false`; an exact exchange-calendar
session and reduce-only proof for a sell are mandatory future dispatch gates,
not compiler conclusions. Unsupported shapes fail locally; rare, special, and
replacement lifecycle states require reconciliation. This slice does not read
credentials, perform network I/O, prove current asset tradability, enforce a
runtime request budget, dispatch an order, consume broker events or snapshots,
or enable paper authority. Phase 4 and its exit gate remain open, as do Phase
3's external captured-tape, reconnect, shadow, economic-evaluation, and
reporting gates.

ADR 0039 adds the Phase 4B offline client-order lookup observation boundary.
Lookup descriptions are derived from the exact Phase 4A submission description,
not arbitrary client IDs. The decoder retains bounded 200/404 response bytes,
provider request IDs, digests, and nanosecond-safe timestamps while applying a
versioned local accepted wire profile rather than claiming the complete Alpaca
schema. A same-ID order with different request economics is
reconciliation-required; `FOUND_MATCHED` validates neither provider asset
identity nor tradability. A 404 is only temporarily not visible, regardless of
its bounded integer code and message. REST cumulative fills cannot manufacture
execution identities, fees, broker sequence, ledger entries, or an `UNKNOWN`
resolution. The found fixture is documentation-derived synthetic evidence; the
404 body is an unqualified synthetic example, and neither is an authenticated
Alpaca capture. Unknown additive fields or statuses fail decoding until
reviewed. ADR 0040 now gives those failures durable raw retention but does not
create a normalized fact or quarantine receipt. All runtime-readiness flags
remain false.

ADR 0040 adds the bounded Phase 4C durable pre-decode ingress slice. The
provider-neutral journal commits exact raw bytes, byte count, digest, and
allowlisted versioned transport metadata before any UTF-8, JSON, status, or
provider-schema decoding. Provider, adapter version, environment, channel, and
operation remain explicit provenance. It accepts empty, malformed, and
otherwise arbitrary bodies up to 1 MiB so a decoder failure cannot erase its
input. A stable account-local delivery idempotency key makes exact retry safe
and changed-content reuse a conflict. New receipts receive an independent
contiguous account-local ingress sequence under the existing account transition
lock, bind the predecessor receipt digest, and atomically advance a durable
terminal head. This is neither the risk-observation sequence nor canonical
per-order broker sequence.

Raw receipts have no local-order or submission-attempt foreign key, allowing
future manual and foreign activity to be retained before classification. The
Alpaca lookup wrapper commits its raw delivery and only then runs the Phase 4B
decoder. Phase 4C intentionally defines no normalized provider fact,
quarantine receipt, application receipt, lifecycle mutation, `UNKNOWN`
resolution, or reconciliation path. Those schemas wait for qualified
stream/snapshot/execution/correction identities instead of inventing event IDs
or provider ordering from local arrival. It adds no transport, credential, or
trading authority, all readiness flags remain false, and Phase 4 remains open.

ADR 0041 adds the bounded Phase 4D durable broker-request admission slice.
Immutable permits consume account-local rolling-window capacity under the
existing SQL account-transition lock. Stable demand idempotency prevents exact
retries from double-debiting capacity, while changed demand or policy content
under the same identity fails closed. A transport path must use new-only
issuance: replaying an already admitted demand is rejected before network I/O
instead of sending twice under one debit. New submissions, UNKNOWN lookups, and
cancel/reconciliation traffic use progressively larger ceilings over the same
total active-permit count, preserving recovery and critical capacity. Permits
form a predecessor-linked account-local chain with a terminal head, issue time
cannot regress, active capacity prevents an implicit policy reset, and an
issued permit is never refunded even if it expires unused. Each permit remains
accounted through its three-second expiry plus the 60-second provider window,
so near-expiry use cannot age out before the 63-second local horizon.

This is still an offline, non-authorizing boundary. The provider limit is the
reviewed Phase 4A input; the rolling interpretation, protected tier ceilings,
and short permit lifetime are explicit local safety policy. No credential or
network client exists, no broker path is yet forced to present a permit, and a
permit contains neither fence nor risk/dispatch authority. Consequently
`request_budget_enforced` and every other runtime-readiness flag remain false,
and Phase 4's exit gate remains open.

ADR 0042 adds the bounded Phase 4E offline account/asset observation slice.
Deterministic non-I/O descriptions bind the Phase 4A capability digest, local
account alias, paper provenance, and exact account or candidate-symbol request.
Strict bounded decoders reject duplicate keys, malformed types and identifiers,
and any missing, unknown, or unreviewed fields. Account observations preserve
the provider UUID, status, currency, creation time, and explicit blocker flags;
retired PDT/day-trade fields are legacy-only, while balances, buying power, and
options levels remain noncanonical raw evidence. Asset observations preserve
provider identity, class, a closed exchange, status, tradability, and reviewed
attributes. Only an exact DIA/IWM/QQQ/SPY mapping on a reviewed listed-U.S.
exchange with `us_equity`, `active`, `tradable`, and no review-required PTP
attribute receives the local usable-candidate outcome; fractionable, shortable,
margin, and increment fields never broaden the v1 whole-share long-only
surface. The profiles pin their model and enum evidence to an exact official
SDK commit.

The account/asset wrappers durably commit their exact response bodies and
transport provenance before decoding, so schema drift remains inspectable.
Checked-in examples are synthetic and cannot establish authenticated identity,
freshness, reconciliation, or security-master facts. No normalized table or
migration is added. Every readiness and authority property remains false, and
Phase 4's exit gate remains open.

ADR 0043 adds the bounded Phase 4F offline dispatch-preflight evidence binder.
It accepts only exact typed evidence: one reducer-produced attempt and complete
parent snapshot, the intent-bound Alpaca submission description, the
authorization's session, the supplied active-capacity projection, a
same-stable-fence receipt, raw-first account and asset observations, and the
fixed Alpaca request-budget policy with an exact submission demand and permit.
The submission-demand correlation is derived from the preparation and request
description; callers may supply only the bounded admission idempotency key and
request time. Immutable identity conflicts fail immediately, while expected
states such as a non-pending attempt, UNKNOWN sibling, expired approval,
closed session, unavailable reservation capacity, expired permit, blocked
account, ineligible asset, or unproved reduce-only sell remain closed findings
in the assessment digest.

This assessment is intentionally not a dispatch receipt or authorization.
Offline account/asset bytes cannot prove authenticated identity or freshness,
and pure active-capacity and permit values cannot attest that their durable
heads are still current. Credential resolution, runtime calendar and quote
evidence, reconciliation/control state, and the final SQL-locked fence,
reservation, UNKNOWN-barrier, permit, and `PENDING -> IN_FLIGHT` transition
remain unresolved. Every transport, coordinator-dispatch, mark-in-flight, and
trading-effect property remains false; Phase 4F performs no persistence,
credential access, network I/O, or lifecycle mutation.

ADR 0044 adds the bounded Phase 4G authenticated Alpaca paper account-binding
slice. A nonsecret configuration pins one local account alias to an expected
canonical provider UUID and immutable `secret://paper/...` version. An injected
trusted resolver produces an opaque envelope and short-lived secret-free
receipt while closable credential bytes and exact authentication headers exist
only inside the restricted transport boundary. The pure broker-contract
package exports none of the credential material, header, session, standalone
resolution, or concrete transport APIs. The exact account demand consumes
protected reconciliation capacity; the durable repository then reauthenticates
a purpose-matched freshness receipt before the fixed `GET /v2/account` starts.
This path requires a newly issued permit, so an exact demand replay cannot
produce a second provider request under the original debit.

The runtime validates the same stable fence before and after transport, uses
verified TLS with no redirects or ambient proxies, requests identity content
coding, and applies a two-second timeout independently to HTTPX connect, pool,
read, and write waits—not as an end-to-end deadline. Once a bounded raw entity
body completes and trusted receive/record times are available, representable
metadata and exact `iter_raw()` bytes enter the Phase 4C journal before Phase
4E decoding. Invalid optional metadata becomes absent and cannot qualify. Only
a usable HTTP 200 JSON response with an `X-Request-ID`, current credential,
permit, and pre-fence windows, and the operator-pinned UUID can advance the
durable account-local binding chain. HTTP errors, malformed responses, blocked
account state, late responses, and UUID mismatches create no binding; bounded
bytes remain durable when the raw receipt boundary completes. Body-limit,
pre-response, clock, and recorder failures cannot claim a raw receipt.
Credential values and headers are absent from canonical or SQL evidence.

Phase 4G deliberately has no deployed secret-store resolver or API, worker,
trader, or startup wiring. Its short-lived binding proves only the exact
authenticated account observation; by itself it leaves security readiness,
quote/session, position, reduce-only, reconciliation, order transport,
`mark_in_flight`, coordinator dispatch, paper startup, and every trading effect
unavailable.

ADR 0045 adds the bounded Phase 4H authenticated candidate-asset binding. A
secret-free reference binds the exact Phase 4G credential reference, fixed
instrument/symbol, capability digest, and an independently operator/review-
pinned provider asset UUID. The runtime reauthenticates the supplied account
binding as the fresh durable terminal head before and after its one strict
`GET /v2/assets/{symbol}`, while new-only reconciliation capacity and the same
stable fence remain current. Completed bounded raw bytes enter the ingress
journal before decoding; a missing request ID, 404, schema drift, ineligible
state, late response, or UUID mismatch cannot bind.

Successful evidence advances a source-bound predecessor chain per account and
instrument for at most five seconds and never beyond the source account binding
or post-request fence. New facts recheck the exact terminal account source
under the shared commit lock; later reads remain historical and a timestamp
window by itself is not current-head authority. This proves only receipt-scoped
provider identity and reviewed tradability for one pinned candidate. It does
not publish a general security master or enable resolver deployment,
quote/session, position, reduce-only, reconciliation, order transport,
dispatch, startup, or any trading effect.

ADR 0046 adds the bounded Phase 4I authenticated client-order lookup. It
accepts only the exact Phase 4B description for a durable submission whose
complete event chain still terminates in `UNKNOWN`. That exact head, the
terminal Phase 4G provider-account identity anchor, and the current recovery
owner's same stable fence are authenticated immediately before transport and
again after the raw response. The account checks prove identity continuity,
not freshness of the earlier account status or blocker flags. The recovery
fence is deliberately independent of the original dispatch fence, so a
legitimate later owner may investigate an earlier generation's UNKNOWN attempt
without inheriting its broker-effect authority.

The lookup consumes a newly issued protected `unknown_lookup` permit and uses
the same ephemeral credential and restricted TLS/no-redirect/no-proxy
transport boundary; owned mutable credential buffers are zeroed, and values
remain absent from evidence, SQL, and bounded diagnostics. Completed bounded
bytes and representable metadata enter the raw ingress journal before decoding
or post-response source checks. A 200 compares the independently configured
provider asset UUID for the attempt's instrument; a null or different canonical
UUID produces a typed authenticated `SECURITY_IDENTITY_MISMATCH` that blocks
reconciliation. A wrong client order ID or decoder failure remains raw-only. A
current Phase 4H asset binding or current tradability is intentionally not
required for historical recovery, and a 404 retains only the Phase 4B
inconclusive meaning. If the UNKNOWN head, account identity continuity, or
fence check fails, the raw response remains durable but no typed attempt-bound
receipt is published.

Every qualified receipt remains historical and non-authorizing. A matching
200, an economic mismatch, a security-identity mismatch, and any number of
404s cannot resolve UNKNOWN, authorize resubmission, manufacture fills or fees,
release capacity, or mutate submission, order, ledger, or account state.

ADR 0047 adds the bounded Phase 4J durable UNKNOWN lookup schedule. One
immutable plan binds the exact dispatch event, terminal UNKNOWN event, stable
client order ID, and Phase 4I lookup correlation. Eligibility follows the
reviewed local offsets at 1, 2, 4, 8, 16, and 32 seconds after the durable
UNKNOWN commit, with every slot at or beyond 60 seconds from dispatch removed.
A late poll consumes only its latest due slot and records the earlier due range
as coalesced, preventing a reconnect catch-up burst.

Each durable one-shot ticket derives a new Phase 4D demand identity and Phase
4C delivery identity. A crash or unqualified response consumes the slot rather
than permitting another send under the same identity. A qualified 404 can wait
only for the next slot; a match stops scheduling for reconciliation, a
mismatch blocks scheduling, and deadline exhaustion remains inconclusive.
None changes the terminal submission state or releases its reservation.

ADR 0048 adds the bounded Phase 4K durable normalization boundary. It reloads
and authenticates the exact Phase 4I lookup receipt and Phase 4C raw source,
strictly re-decodes those retained bytes, and records one predecessor-linked
historical reconciliation-evidence fact. A matching 200 is only an
order-observed candidate; request-economics and independently pinned
security-identity mismatches are explicit quarantine dispositions; and a
qualified 404 remains inconclusive. Separate authenticated lookups remain
separate observations even when their decoded values match, while an exact
source replay is idempotent.

The fact preserves precise provider timestamps, order/request economics,
replacement links, cumulative fill quantity, and average price for future
comparison. Local append order and provider `updated_at` are not revision
authority, cumulative fields do not identify executions, and every application
or trading authority remains false. Phase 4K is not the general
stream/snapshot inbox and cannot resolve UNKNOWN, release a reservation, or
mutate order, fill, ledger, or reconciliation state.

ADR 0049 adds the bounded Phase 4L source-scoped inbox-admission boundary. A
versioned identity profile derives one historical observation and normalized
request from the exact Phase 4K fact ID, digest, evidence payload, lookup
receipt, and raw-ingress source. Separate lookup sources never collapse merely
because their Order values match. Durable source links form an account-local
predecessor chain and terminal head; a fixed non-application policy records
`WITHHELD_UNQUALIFIED_REVISION_IDENTITY`,
`QUARANTINED_ECONOMIC_MISMATCH`,
`QUARANTINED_SECURITY_MISMATCH`, or `INCONCLUSIVE_NOT_VISIBLE` with a trusted
decision time no earlier than the Phase 4K normalization.

The receipt has no canonical event, execution, fee, correction, reservation,
ledger, UNKNOWN-resolution, reconciliation-completion, readiness, or trading
target. Phase 4L is not general cross-channel deduplication and does not admit
raw decode failures. Deployed lookup supervision, provider-qualified
stream/snapshot revision identities, execution/bust/correction identities,
decode quarantine, authoritative inbox application, convergent reconciliation,
dispatch, startup, and all readiness flags remain open.

ADR 0050 adds the bounded Phase 4M raw-first order-page contract. One immutable
plan describes at most eight descending `GET /v2/orders` pages with
`status=all`, a limit no greater than 500, `nested=false`,
`asset_class=us_equity`, and no caller-selected time or order-ID cursor. The
first page has no cursor; each later page derives `before_order_id` only from
the preceding full page's final provider order ID. Every page has a distinct
reconciliation-purpose demand, but Phase 4M neither allocates a permit nor
authorizes a broker call.

Representable responses enter the Phase 4C journal before the strict Phase 4B
order profile runs. Typed pages bind the exact raw receipt, predecessor, cursor,
provider request ID, bytes, and descending order sequence. A short or empty
page means only that this exact non-isolated traversal was exhausted. A full
eighth page is bounded truncation, not completion. Phase 4M adds no
authenticated runtime, durable restart state, snapshot isolation, provider
revision/execution/correction identity, cross-channel deduplication, lifecycle
application, UNKNOWN resolution, convergence, or readiness. See
[ADR 0050](docs/adr/0050-bounded-raw-first-alpaca-order-snapshot-pages.md).

ADR 0051 adds the bounded Phase 4N non-authorizing order-snapshot comparison.
It accepts only two distinct, ended Phase 4M captures for the same account,
page limit, and maximum-page profile. Their ingress receipt IDs must be
disjoint, and the earlier capture's final source sequence must precede the
later capture's first source sequence. In-progress, cross-account,
profile-drifted, shared-source, same-capture, or reversed inputs fail closed.

Each capture becomes a page-boundary-independent sorted view of exact
`(provider_order_id, order_semantic_sha256)` pairs. The comparison reports
sorted added, removed, and changed provider order IDs. A bounded-truncated
source is `bounded_traversal_incomplete`; otherwise a later first observation
less than two seconds after the earlier last observation is
`waiting_minimum_separation`. A separated difference is
`order_view_different`, while equality is only
`exact_order_view_match_unqualified`. Even that exact match has
`converged=false` and supplies no monotonic timing, snapshot isolation,
provider revision, execution/correction identity, deduplication, lifecycle,
UNKNOWN-resolution, reconciliation, broker-call, or trading authority.
Phase 4N is pure: it adds no persistence, request, transport, worker, startup
composition, or readiness change. See
[ADR 0051](docs/adr/0051-bounded-non-authorizing-order-snapshot-comparison.md).

ADR 0052 adds the Phase 4O authenticated durable order-snapshot page runtime.
An immutable SQL plan and terminal head authenticate the exact next Phase 4M
description, predecessor, cursor, and page number before credentials or request
capacity are touched. Each public call can issue at most one restricted
`GET /v2/orders` page, consumes a new reconciliation-purpose permit, requires
the same current fence and terminal provider-account identity before and after
transport, and commits completed bytes through Phase 4C before qualification.

Committed pages form a contiguous, source-bound prefix. Exact committed retries
return the original receipt, while gaps, forks, source substitutions, and
orphaned rows fail closed. A durable page preparation is a single-use claim:
every overlapping or restarted prepare call fails before credentials, permit
issuance, or transport. A crash after preparation therefore leaves the capture
stalled. The runtime still grants no isolated snapshot, provider
revision/execution identity, convergence, lifecycle application, UNKNOWN
resolution, readiness, or trading authority, and it is not composed into a
deployed worker. See
[ADR 0052](docs/adr/0052-authenticated-durable-alpaca-order-snapshot-pages.md).

ADR 0053 adds the Phase 4P durable authenticated order-view comparison. It
reloads two terminal Phase 4O prefixes from SQL, authenticates their complete
source positions, and derives the exact Phase 4N comparison rather than
accepting caller-computed differences. Immutable receipts form an
account-local predecessor chain with a terminal head and bind both capture
identities, terminal page receipts and digests, view digests, differences,
disposition, and commit fence.

Exact retry returns the original receipt; source substitution, rollback,
forks, or orphaned rows fail closed. Cursor exhaustion remains non-isolated,
bounded truncation remains incomplete, and even an exact separated match has
`converged=false`. Phase 4P performs no provider request and grants no provider
revision, deduplication, lifecycle/application, reconciliation-completion,
readiness, or trading authority. See
[ADR 0053](docs/adr/0053-durable-authenticated-order-view-comparisons.md).

ADR 0054 adds the Phase 4Q bounded restart-safe order-view supervisor. One
invocation derives its action from two authenticated Phase 4O durable states,
executes at most one exact next page, waits without I/O until the later-start
scheduling boundary, or records the exact Phase 4P comparison after both
prefixes end. A successful page result is accepted only after reloading both
states and proving one-receipt append-only advancement with the unselected
state unchanged. A stalled state fails before page execution.

The two-second UTC gate is a scheduling lower bound, not monotonic provider
timing or convergence evidence. A later prefix is adoptable only when its
authenticated first-page preparation, request start, and receive times are all
at or beyond that boundary; an early durable prefix fails closed rather than
being reassigned to a different round. Exact Phase 4P retries keep their
original historical commit receipt while the repository revalidates the
current call's fence. The supervisor grants no lifecycle/application,
reconciliation-completion, readiness, broker-submission, or trading authority.
See
[ADR 0054](docs/adr/0054-bounded-restart-safe-order-view-supervision.md).

ADR 0055 adds the Phase 4R bounded raw-first position view. One immutable
description freezes `GET /v2/positions`; representable bytes are committed
through Phase 4C before the strict reviewed USD U.S.-equity array is decoded.
The item/body bounds reject the entire typed view without truncation, required
decimal strings retain their exact lexemes, and duplicate provider asset or
symbol identities fail closed. Empty and non-empty arrays alike remain
historical, non-isolated observations with no canonical-position,
reconciliation, readiness, broker-call, or trading authority. See
[ADR 0055](docs/adr/0055-bounded-raw-first-alpaca-position-views.md).

ADR 0056 adds the Phase 4S bounded position-view comparison. Two exact Phase
4R sources must share an account and profile, use distinct capture/raw
identities, and follow account-local ingress order. Stable sorted asset-ID
views expose exact additions, removals, and changes; a two-second local receive
boundary returns waiting before it is met and only unqualified equality after
it. Even two separated empty views retain `converged=false` and grant no
canonical-position, application, readiness, broker-call, or trading authority.
See
[ADR 0056](docs/adr/0056-bounded-non-authorizing-alpaca-position-view-comparison.md).

ADR 0057 adds the Phase 4T authenticated single-use position-view runtime. One
fresh durable preparation claims the exact Phase 4R description, credential
reference, and terminal Phase 4G account binding before secrets, capacity, or
transport. The runtime consumes one new reconciliation permit, holds the same
account identity and fence across a strict raw-first `GET /v2/positions`, and
requires the recorder to revalidate that fence independently in its commit
transaction before exact reload. A stalled or previously completed capture
cannot resend. The contract adds no concrete SQL repository, automatic retry,
snapshot completeness, canonical-position application, convergence, readiness,
or trading authority. See
[ADR 0057](docs/adr/0057-authenticated-single-use-alpaca-position-views.md).

ADR 0058 adds the Phase 4U durable single-use position-snapshot repository.
The immutable plan row is the fresh-only claim; no row is unclaimed, a plan
without its one-to-one receipt is stalled, and an exact receipt is complete.
Stable capture uniqueness, account locking, exact source foreign keys,
transaction-internal fence checks, full reconstruction, operational-readiness
verification, and guarded downgrade preserve the Phase 4T no-resend rule across
restart. Identity continuity deliberately outlives the Phase 4G account-status
TTL but cannot establish current account state, canonical positions,
convergence, readiness, or trading authority. See
[ADR 0058](docs/adr/0058-durable-single-use-alpaca-position-snapshots.md).

ADR 0059 adds the Phase 4V durable authenticated position-view comparison.
The workflow reloads and reconstructs two exact Phase 4U receipts for the same
local and provider account identities, recomputes Phase 4S internally, and
stores the signed timing, exact views/differences, sources, commit fence, and
account-local predecessor/head chain. Exact retry revalidates the current call
without rewriting historical evidence. Equality remains unqualified and grants
no canonical-position, application, convergence, readiness, or trading
authority. See
[ADR 0059](docs/adr/0059-durable-authenticated-position-view-comparisons.md).

ADR 0060 adds the Phase 4W bounded restart-safe position-view supervisor.
Repository-authenticated `ABSENT`, `STALLED`, and `COMPLETE` states select at
most one earlier capture, no-I/O wait, later capture, or Phase 4V comparison
per invocation. A stalled single-use claim never retries. Coherently wired
ports must identify the same process-local durable store. The later capture
must start after the fixed two-second eligibility boundary and this call's
trusted selection check, then reload as the sole exact state transition before
it can be compared. A concurrent unselected mutation is rejected after the
bounded selected read; durable pair-wide compare-and-swap remains pending. The
supervisor adds no loop, scheduler, canonical state, convergence, readiness,
submission, or trading authority. See
[ADR 0060](docs/adr/0060-bounded-restart-safe-position-view-supervision.md).

ADR 0061 adds Phase 4X durable position-pair transition admission. The first
earlier claim registers two globally unique role memberships under the account
lock; a later claim additionally binds the exact complete earlier Phase 4U
receipt and two-second receive boundary. Pair-aware preparation consumes one
exact same-lease claim while inserting the unchanged Phase 4U plan in the same
transaction. Ordinary Phase 4U preparation rejects registered plans. Claim
retry is historical and current-fence-authenticated, while consumed or
lease-changed claims cannot authorize another preparation. Phase 4X performs
no provider I/O and grants no reconciliation, readiness, submission, or
trading authority. See
[ADR 0061](docs/adr/0061-durable-position-pair-transition-admission.md).

ADR 0062 adds Phase 4Y pair-admitted position-view runtime composition. It
wraps every Phase 4W/4V source load so a non-absent Phase 4U source cannot
bypass its exact Phase 4X claim and consumption. A selected role is claimed
before Phase 4T, then a narrow runtime adapter atomically consumes it as the
unchanged Phase 4U preparation. A second adapter requires every Phase 4T fence
receipt to retain the claim's exact policy, lease digest, and expiry; renewal
before the request fails pre-transport, while a later change cannot commit
Phase 4U. The proof-constructed result binds unchanged Phase 4W/T/U evidence
to its exact transition history and grants no convergence, application,
readiness, submission, or trading authority. See
[ADR 0062](docs/adr/0062-pair-admitted-position-view-runtime-composition.md).

ADR 0063 advances Phase 4Q to the Phase 4Z coherent-store version 2 contract.
The authenticated Phase 4O state loader, one-page workflow, and Phase 4P
comparison repository must expose one exact positive process-local SQL-engine
identity before source loading, clock access, request capacity, provider I/O,
or comparison persistence. Distinct repositories over one engine compose;
split engines fail closed. The opaque identity is not canonical evidence, and
same-store ordered-pair/page admission is supplied by Phase 4AA. See
[ADR 0063](docs/adr/0063-coherent-order-view-supervision-wiring.md).

ADR 0064 defines Phase 4AA durable order-pair page-transition admission. Its
application contract binds globally exclusive earlier/later membership, one
gap-free claim per exact next page, the later-start boundary, immutable
preparation consumption, and same-lease crash semantics without granting
provider authority. Revision 0024 adds globally unique pair members, immutable
page claims, one-to-one consumptions, and the forward-compatible preparation
projection. Completed pages and the sole stalled head are backfilled into
exact immutable facts and heads remain authenticated pointer/caches. Public
Phase 4O preparation rejects registered plans; pair-aware preparation and
consumption commit atomically under the account lock with final same-lease
validation; whole-store readiness reconstructs the complete history. Downgrade
may remove the derived projection only when transition history is empty. Phase
4AA alone grants no provider I/O or reconciliation readiness; Phase 4AB
supplies the separate composition boundary. See
[ADR 0064](docs/adr/0064-durable-order-pair-page-transition-admission.md).

ADR 0065 defines Phase 4AB pair-admitted order-view runtime composition. A
pair-authenticating source loader reconstructs every committed page through
its exact Phase 4AA role claim, consumption, unchanged Phase 4O preparation,
page receipt, and page-local lease. The one-page workflow claims the exact
prefix and source head cached from Phase 4Q selection, then claim-bound
Phase 4O and coordinator adapters consume that claim and carry its lease
through the unchanged credential, budget, raw-first transport, commit, and
reload path. Later-page claims must also bind the exact authenticated terminal
earlier prefix and source head before effects and in the final proof. Waiting
and comparison calls create no claim; the comparison path
still authenticates both complete page histories. The proof result retains the
unchanged Phase 4Q result, ordered earlier/later transition histories, and the
one optional selected page pair. It adds no loop, retry, deployed worker,
convergence, reconciliation application, readiness, or trading authority. See
[ADR 0065](docs/adr/0065-pair-admitted-order-view-runtime-composition.md).

ADR 0069 defines Phase 4AC restart-safe UNKNOWN recovery composition. It adds
authenticated source-indexed reads for the Phase 4J/I/K/L chain, repairs
I-before-J, J-before-K, and K-before-L durable prefixes, and requires every
participant to share one process-local SQL store before any effect. Each
attached lookup must be fully accounted through the non-applying inbox before
another schedule step, while the proof result retains no lifecycle,
reconciliation, resubmission, or trading authority. See
[ADR 0069](docs/adr/0069-restart-safe-unknown-recovery-composition.md).

ADR 0070 defines the Phase 4AD bounded raw-first FILL-activity page contract.
The exact Trading API request walks ascending pages of at most 100 items using
the prior page's last activity ID unchanged. Eight-page, 800-item, per-page
one-mebibyte, and aggregate eight-mebibyte limits bound local work. Each page
has a distinct reconciliation demand and durable Phase 4C receipt before a
strict versioned FILL schema is decoded; exact IDs, timestamps, and decimal
lexemes remain retained. Duplicate keys, schema/type/time/decimal drift, and
within- or cross-page overlap fail closed. Terminal short-page evidence is
explicitly distinct from bounded truncation, and neither grants canonical
execution/revision, cross-channel deduplication, application, reconciliation,
readiness, or trading authority. See
[ADR 0070](docs/adr/0070-bounded-raw-first-alpaca-account-activity-pages.md).

ADR 0076 defines the Phase 4AE one-page authenticated durable runtime.
Migration 0029 binds each single-use preparation to the exact account,
request-budget permit, raw response, fence, and predecessor before recording
an authenticated traversal head. A prepared-but-unresolved page is not resent
after restart. Phase 4AF compares two supplied bounded captures without
authority, Phase 4AG reloads and authenticates both exact Phase 4AE histories
before recomputation, and Phase 4AI selects only one durable page, comparison,
or wait action per invocation. See
[ADR 0076](docs/adr/0076-durable-authenticated-account-activity-traversals.md).

ADR 0083 defines Phase 4AH durable comparison persistence. Migration 0033
records one immutable receipt for each exact ordered Phase 4AG source pair
under the account lock, recomputes all derived values, authenticates the
predecessor-linked history and both raw-backed sources, and refuses destructive
downgrade while evidence exists. Equal or bounded views remain historical and
do not prove completeness, isolation, canonical fills or corrections,
reconciliation, or trading authority. See
[ADR 0083](docs/adr/0083-durable-authenticated-account-activity-comparisons.md).

ADR 0066 defines the Phase 5A durable operational-control spine. It freezes the
five-state severity order, actor-bound exact-retry commands, fail-closed
absence, non-resetting breaker trips, explicit drain/flatten terminal facts,
and manual proof-bound re-arm. Revision 0025 retains a gap-free
predecessor-linked transition history plus an authenticated head and refuses
to destroy nonempty control history on downgrade. The compatibility projection
keeps the existing Phase 2 batch-risk vocabulary unchanged. This local slice
does not perform broker effects, qualify Phase 4 reconciliation, or grant
paper/live authority. ADR 0073 now exposes the spine through a separately
injected, authenticated local operations boundary without changing those
limits. See
[ADR 0066](docs/adr/0066-durable-operational-control-spine.md) and the
[operational-control runbook](docs/runbooks/operational-control.md).

ADR 0067 defines the Phase 5B approval boundary. A separate observe-only
contract can retain deterministic proposed measurement/evidence identities and
explicit source insufficiency without changing historical BatchRisk or
operational-control semantics. Its only evaluation-readiness result is
`OWNER_APPROVAL_REQUIRED`; its proposal facts remain non-authorizing even after
a separately versioned policy is approved.
See
[ADR 0067](docs/adr/0067-approval-gated-advanced-risk-evidence.md).

ADR 0068 freezes that separate owner-approved moderate paper policy. It defines
flow-adjusted session loss/drawdown, worst-case pending/unknown exposure,
cash-only concentration/leverage, 30-return volatility, fresh consolidated-SIP
spread, modeled and realized slippage, and definitive broker-reject windows.
`REJECT` applies only to a hypothetical batch; current/committed facts may
produce durable `PAUSED`/`HALTED` trips and never auto-resume. Owner approval
does not assign the policy to an account. The additive assessment binds the
pre-transition control head, an optional same-transaction trip binds the
assessment, and a sidecar binds the unchanged v2 decision plus final head.
Migrations 0026 and 0030, policy/assignment/evidence/assessment persistence,
source-shape adapters, and the additive atomic cutover/admission path are
implemented and locally verified. The path remains disabled by default;
deployed authoritative producers and an authenticated deployment assignment
remain open.
See
[ADR 0068](docs/adr/0068-owner-approved-moderate-paper-risk-policy.md).

ADR 0080 fixes the atomic Phase 5B cutover and admission boundary. The exact
assignment, evidence, batch, snapshot/capacity, current fence, pre-transition
control head, optional greatest-severity trip, unchanged Phase 2 decision, and
final admission sidecar commit as one account-serialized outcome. Missing or
stale facts, a rejected batch, a trip, a late insert failure, or a missing
sidecar leaves no dispatchable authorization. Exact retry, rollback, startup
integrity, legacy-writer lockout, and final dispatch reauthentication are
locally verified. See
[ADR 0080](docs/adr/0080-atomic-advanced-risk-admission.md).

ADR 0071 defines an eight-stage OpenTelemetry vocabulary and locally composes
the six authoritative fact types currently available together, without
exporting economic payloads or accepting baggage. Fill and reconciliation
remain explicitly missing. It uses opaque durable IDs/digests, explicit W3C
Trace Context, and a bounded asynchronous processor. ADR 0088 selects Sentry
diagnostics, and a local Sentry Cloud OTLP/HTTP trace-exporter factory now
enforces the paper service/release/environment pins and strips sensitive span
content. On 2026-07-29, the operator observed transport acceptance for one
sanitized synthetic export, but that non-durable setup observation is not
checked-in or reproducible evidence. Queryable ingestion, runtime composition,
sampling, retention/access enforcement, and outage testing remain open. See
[ADR 0071](docs/adr/0071-opentelemetry-trading-correlation.md).

ADR 0072 defines the local durable critical-alert boundary. It retains
source-idempotent incidents, a gap-free chain of provider request claims, and
one sanitized terminal result per claim. A claim commits before provider I/O;
an exact restart retry returns retained evidence and never resends an
unresolved effect. The baseline local, primary, and fallback milestones use
strict one-/15-/30-second bounds and authenticate both UTC and monotonic time.
Local secret-safe PagerDuty and Twilio HTTP adapters implement those provider
calls, but amended ADR 0088 defers both external providers. Destinations,
recipients, credentials, route/worker composition, channel probes,
independence evidence, escalation roster, and activation of the fixed local
failure-control policy remain unavailable. Strategy-supervision failures
already open their alert incident atomically with their breaker transition,
but that incident and the adapter tests are not proof of external delivery. See
[ADR 0072](docs/adr/0072-durable-critical-alert-delivery.md).

ADR 0078 layers one bounded provider-neutral worker over those durable facts.
It authenticates an exact injected route plan, scans with a stable cursor,
resolves only the selected adapter, performs at most one provider call per
incident step, and never resends an unresolved claim. At complete route
exhaustion or the unresolved 30-second boundary it derives stable total-failure
evidence. Its older split policy/writer seam is now retired. See
[ADR 0078](docs/adr/0078-bounded-critical-alert-worker.md).

ADR 0085 composes the bounded worker with migration 0032's same-store atomic
failure-control repository. Only replay-authenticated terminal failure or an
unresolved escalation at the 30-second boundary may bind the fixed local
`PAUSED` rule; the control transition and exact source receipt commit together,
and retries/concurrent workers converge. ADR 0085 itself selects no provider or
route; amended ADR 0088 defers the local PagerDuty/Twilio adapters, which still
lack credentials, recipients, schedule, deployment composition, probes, and
policy activation.
See
[ADR 0085](docs/adr/0085-atomic-critical-alert-worker-composition.md).

ADR 0073 defines the authenticated local operations API. It reuses the signed
loopback-only operator session and CSRF boundary, requires mutation
idempotency, exposes allowlisted projections, and accepts no client-authored
readiness or re-arm evidence. The dedicated re-arm path locks and authenticates
the exact head before committing server-proofed evidence. The durable local
composition supplies one allowlisted SQL snapshot reader and database-only
`PAUSE`/`HALT` service over the same engine; it still supplies no control
initialization, drain/flatten executor, re-arm verifier, assignment, or broker
authority. The optional advanced-risk assignment route exists only with a
current-fence authority. See
[ADR 0073](docs/adr/0073-authenticated-local-operations-api.md).

ADR 0081 authenticates that concrete local composition. Account coordinator,
control history, advanced-risk state, and active alert facts are read in one
bounded repeatable snapshot; corrupt or future-dated facts fail unavailable.
Only an already initialized control may receive `PAUSE` or `HALT`, and both
the query and control service must share the exact durable SQL engine. See
[ADR 0081](docs/adr/0081-durable-local-operations-composition.md).

ADR 0074 defines the GET-only operations dashboard at
`/api/v1/operations/dashboard`. The current React view renders a complete
walking-thread snapshot, marks stale or missing authorities explicitly,
disables caching, and requires the local signed-session/CSRF pair. The
projection has no mutation method or broker port and does not turn fixture
data into account authority. See
[ADR 0074](docs/adr/0074-read-only-local-operations-dashboard.md).

ADR 0082 adds the separate browser command client. It consumes only granular
`control_pause` and `control_halt` capabilities, requires a bounded reason and
stronger typed HALT confirmation, uses the exact session/CSRF/header contract,
and retains the same idempotency key only for an explicit retry after an
ambiguous network, `5xx`, or malformed-success outcome. Success clears the
intent and refreshes the authoritative account overview. No DRAIN, FLATTEN,
REARM, assignment, initialization, fixture mutation, or broker call is
available. See
[ADR 0082](docs/adr/0082-safe-browser-pause-halt-controls.md).

ADR 0075 defines the strict strategy subprocess protocol and resource/deadline
envelope. ADR 0077 composes each exact result durably under the account fence:
success leaves control unchanged, while every non-completed outcome atomically
records the result, a severity-preserving `PAUSED` breaker transition, and one
critical-alert incident. Strategy artifact selection, stronger OS sandboxing,
deployment, and external alert routing remain separate. See
[ADR 0075](docs/adr/0075-strict-supervised-strategy-subprocess.md) and
[ADR 0077](docs/adr/0077-durable-strategy-supervision-composition.md).

ADR 0087 supplies one deliberately non-production selection: the verified
`no-exposure-smoke@1.0.0` artifact. Its canonical manifest pins exact source
bytes and protocol/configuration/result identities, the loader pins the
reviewed digests, and the isolated bootstrap hashes the same bytes it executes.
The child emits only a batch-bound empty-intent observation. The offline
verifier neither runs the child nor changes readiness; no account or deployment
selects this artifact. See
[ADR 0087](docs/adr/0087-verified-no-exposure-smoke-strategy.md).

ADR 0079 closes the pre-run crash window with an immutable claim. Only a newly
committed exact claim returns a repository-bound, one-shot permit and a sealed
authorization whose final runner use is also process-bound and atomic; retained
pending claims never rerun. The strict one-second start window, five-second
execution deadline, and aggregate three-second cleanup budget yield the fixed
nine-second recovery boundary. At that boundary, the
current account fence can finalize an orphan as one deterministic `CRASH`,
while result, control, alert, and claim-finalization facts remain atomic.
Bounded indexed scans find due claims, and lifecycle-aware startup locks out
the legacy direct result writer. Migration 0031 owns that lifecycle schema,
migration 0032 adds atomic alert failure-control receipts, and the current
additive schema head is migration 0033 after the later Phase 4 account-activity
comparison slice. See
[ADR 0079](docs/adr/0079-durable-pre-run-strategy-invocation-claims.md).

The [Phase 5 deterministic fault-drill runbook](docs/runbooks/phase5-fault-drills.md)
executes the checked-in local matrix. It covers claim/finalization boundaries,
lease handoff, alert milestones, atomic fixed-`PAUSED` control binding, and
rejection of the retired split control seam, plus strict advanced-risk
thresholds and rollback, data gaps, uncertain exposure, database/lease loss,
and manual-only re-arm. Provider delivery, telemetry outage, paper broker/data,
and wall-clock game-day drills remain explicitly unperformed deployment work.
ADR 0084 separately defines typed, non-authorizing local observations for the
six required fault classes; neither a green catalog nor a green typed matrix
qualifies a deployment drill. See
[ADR 0084](docs/adr/0084-typed-local-operational-drill-evidence.md).

For a separately authorized future capture, start from the fail-closed
[acquisition-profile](docs/admission/tiingo-eod-acquisition-profile.template.json),
[capture-authorization](docs/admission/tiingo-eod-capture-authorization.template.json),
and [pinned-calendar](docs/admission/tiingo-eod-pinned-calendar.template.json)
templates. Copy all three to a gitignored, owner-only location, replace every
placeholder, and enable approval or permission fields only after the applicable
review. Explicitly run `chmod 600` on each copied file. Every venue, timezone,
session label, open, close, and kind in the calendar template is illustrative
and must also be reviewed and replaced where applicable, even when it is not
prefixed with `replace-`. Derive the normalized profile contract digest without
reading a credential or making a request:

```bash
make tiingo-eod-profile-inspect PROFILE=path/to/reviewed-profile.json
```

Put the printed `profile_contract_sha256` in an authorization reviewed no
earlier than the profile and in a calendar artifact reviewed no earlier than
the profile. Enable the authorization's two permission flags only when the
terms review supports them. Only then may an operator run:

```bash
make tiingo-eod-capture START_DATE=2026-07-14 \
  PROFILE=path/to/reviewed-profile.json \
  AUTHORIZATION=path/to/reviewed-authorization.json \
  CALENDAR=path/to/reviewed-calendar.json
```

The target defaults to all four Phase 1 symbols. Set, for example,
`SYMBOLS="DIA SPY"` only when the reviewed profile and calendar have that exact
sorted subset.

The command validates all three artifacts and the exact requested scope before
it reads `TIINGO_TOKEN`. The checked-in templates intentionally cannot authorize
a capture; the earlier bounded operation does not authorize another run.
It rejects group- or other-accessible existing capture-root components beneath
the repository; higher repository and OS ancestors are traversed without
following symlinks but need not be owner-only. Validated responses are written
to owner-only staging and become visible under their final name only through
the atomic commit rename; pre-commit faults never publish a final capture. A
process crash may leave a hidden inert staging or reservation entry, but never
a partially published final capture.

Its timeout is a finite per-request socket-I/O timeout, not a strict deadline for
the entire multi-symbol capture; use an external supervisor when a hard
whole-process deadline is required.

After a capture exists, verify it without loading credentials or making a
request:

```bash
make tiingo-eod-verify \
  CAPTURE=final-capture-basename \
  PROFILE=path/to/reviewed-profile.json \
  AUTHORIZATION=path/to/reviewed-authorization.json \
  CALENDAR=path/to/reviewed-calendar.json
```

The verifier uses the fixed ignored capture root, writes no state, and emits no
payloads or prices.

## Quickstart

Prerequisites are Docker with the Compose plugin and available local ports 5173,
8000, and 5432. From the repository root:

```bash
cp .env.example .env
make dev
```

The single command builds and starts PostgreSQL, applies migrations, starts the
API and desktop-oriented browser application, and starts the local worker. The
worker ingests the deterministic Phase 1A fixture, installs the Phase 2 golden
research catalog, and continuously processes fixture-backtest jobs. The trader
still runs only its fail-closed diagnostic. Wait for the API and web health
checks, then open:

- Browser application: <http://localhost:5173>
- API documentation: <http://localhost:8000/docs>
- API liveness: <http://localhost:8000/health/live>
- API readiness: <http://localhost:8000/health/ready>

Stop the foreground stack with `Ctrl-C`, then run `make down`. The PostgreSQL
and content-addressed data-lake volumes are preserved; deleting them is
intentionally not part of the normal shutdown command.

## Host development and checks

Host-based development requires Python 3.12, `uv` 0.11.28, Node.js 22, and pnpm
11.7.0. Install locked dependencies and run the complete current quality gates:

```bash
make bootstrap
make check
```

`make check` includes backend and browser tests. Useful focused commands are
`make test`, `make api`, `make web`, `make worker`, `make trader`, `make migrate`,
and `make compose-check`. `make migrate` uses only `AQT_DATABASE_URL` already in
the process environment; without it, Alembic uses its transient SQLite default.
Do not use the bare target for the external Supabase paper preflight—follow the
[paper smoke deployment runbook](docs/runbooks/paper-smoke-deployment.md) and
load the owner environment explicitly. After changing an HTTP response contract,
run `make api-contracts`; `make api-contracts-check` and CI fail when the
checked-in OpenAPI document or generated browser wire types are stale. These
generated types provide compile-time checking only; the HTTP client does not yet
perform runtime response validation. The browser calls same-origin `/api/v1`
endpoints through the Vite proxy; deterministic UI fixtures are off by default
and require an explicit `VITE_USE_DEV_FIXTURES=true` opt-in.

The reusable admission evaluator accepts strict, secret-free JSON specifications
and evidence bundles. It exits nonzero unless the result is actually admitted:

```bash
uv run python scripts/evaluate_market_data_admission.py \
  --specification path/to/frozen-specification.json \
  --evidence path/to/evidence.json
```

See [Market-data admission](docs/admission/README.md) before preparing a vendor
evidence bundle.

Candidate connectivity can be checked without printing credentials, downloading
bulk history, or changing admission state:

    make market-data-probe DATE=2026-07-14 SYMBOL=SPY

The probe parses the owner-only, gitignored .env without interpolation or shell
evaluation, loads only the three market-data keys into its process, makes one
bounded read per candidate, and reports sanitized access facts. A successful
probe is not license, point-in-time, or admission evidence by itself.

A completed Sharadar range can be archived for offline, research-only
qualification only after storage rights are reviewed:

```bash
make sharadar-sfp-capture START_DATE=2026-07-14 \
  AUTHORIZATION=path/to/reviewed-authorization.json
```

Start from the fail-closed
[authorization template](docs/admission/sharadar-sfp-capture-authorization.template.json),
replace its IDs and terms digest, and set its permission flags to `true` only
when the review supports both local snapshot storage and research use. Exact
pages and their secret-free manifest always stay under the fixed, gitignored
`.local/vendor-snapshots/sharadar-sfp` tree. The manifest binds the reviewed
authorization, terms, and observed response-column schema; offline loading also
binds the exact capture to the pinned calendar semantics. Admission and trading
effects remain `none`.
