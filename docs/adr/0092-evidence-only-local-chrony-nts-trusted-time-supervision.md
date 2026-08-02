# ADR 0092: evidence-only local Chrony NTS trusted-time supervision

- Status: Accepted
- Date: 2026-07-31

## Context

ADR 0086 defines the provider-neutral trusted-time reducer and one deadline-
bound probe. ADR 0090 adds fresh process epochs, durable replay, and stale-
process fencing. Those decisions deliberately select no deployed source, host
identity, source-uncertainty calculation, or recurring schedule.

The local paper profile needs a concrete source boundary before its clock
evidence can be exercised. That boundary must authenticate more than one
provider, conservatively include source uncertainty in the existing offset
bands, and keep every result non-authorizing. It must also fit the current
directly supervised local Docker topology without obtaining permission to
adjust the host clock, serving NTP, or creating a public monitoring surface.

At decision time, runtime Supabase was at migration 0034 with empty trusted-time
histories. Adding source uncertainty changes the exact sample and policy
identity, so an in-place reinterpretation of any prior history would be
invalid. The required migration must therefore refuse a nonempty history and
must not be described as applied until it is separately approved and verified.

## Decision

Approve the evidence-only local topology pinned by the now
[archived v1 source-authority manifest](evidence/0092-source-authority-v1.json),
SHA-256
`356723c84e30478f18ad99f3cfef2ee65b3bdd3fc26936a7d5c9910fd1bcb3ab`,
the historical Chrony configuration recorded by SHA-256
`82791d1c6f38017d2552e8d012e0ebd26d7112dce71431d9cae39d7150f185f5`,
[Supabase 2021 root CA](../../packages/persistence/certs/supabase-prod-ca-2021.crt), and
[operator runbook](../runbooks/trusted-time-supervisor.md).

The fixed authority contract is
`phase6c-local-chrony-nts-authority-v1`. It binds source ID
`chrony-nts-cloudflare-netnod-v1` to the single host ID
`local-paper-docker-primary-v1`; there is no failover host, source-set
override, or epoch-resume path. Any change to the providers, Chrony/config
identity, host ID, admission rules, or authority flags is a new reviewed
authority, not an environment override.

The source daemon is Chrony 4.8 running with `-x`. Its exact source set is:

- `time.cloudflare.com` over NTS, with admitted NTP port 123; and
- `nts.netnod.se` over NTS, with admitted NTP port 4123.

Both ordered sources are required. The
`phase6-chrony-4.8-nts-evidence-v1` adapter admits only the exact two-source
composite with one selected (`*`) source and one combined (`+`) source. Each
selection must be authenticated, each NTP report must show authenticated
packets, normal leap, NTPv4 server mode, the fixed 16-second poll, and passing
source tests, and the tracking report must be normal and cross-match the
selected name, reference ID, and stratum. NTS authentication admits only AEAD
15 with a 256-bit key or AEAD 30 with a 128-bit key, at least eight cookies,
a positive established key ID, zero NAKs, and zero key-establishment attempts.
Missing, extra, unauthenticated, stale, malformed, or otherwise
unselectable source evidence fails closed. There is no unauthenticated, pool,
local-reference, peer, manual, or single-provider fallback.

Each source request has a one-second monotonic deadline and no retry. Reference
age must be no more than 30 seconds. One fixed, C-locale `chronyc` monitoring
transaction first sets `retries 0`, then reads tracking, selection,
authentication, and NTP reports through the Unix socket; it does not invoke a
shell or control the daemon. The adapter conservatively binds root dispersion,
half the absolute root delay, half the inner observation duration, inner UTC/
monotonic divergence, and microsecond rounding to the reading; the monitor then
adds its outer cross-clock projection disagreement. The resulting exact decimal
uncertainty must be at most 100 milliseconds. Equality is admitted; a larger or
invalid uncertainty produces no sample.

The reducer classifies the conservative magnitude
`abs(point offset) + source uncertainty`, not the point estimate alone:

- `<250 ms` is healthy;
- `250 ms <= magnitude <= 1,000 ms` is warning evidence; and
- `>1,000 ms` is blocked and latches the hard-failure evidence.

The existing strict freshness, identity, sequence, UTC/monotonic continuity,
and 60-second recovery-chain rules remain in force.

The `phase6c-fixed-grid-trusted-time-supervision-v1` supervisor performs one
durable probe immediately and schedules later probes on an absolute monotonic
20-second grid. Probe completion does not move the grid. A late wake performs
only the oldest due tick and advances to the first future boundary; it does not
issue a catch-up burst. There is no same-tick retry. A source, deadline, or
identity failure becomes fail-closed durable evidence, while a fatal
dependency, repository, clock, or wait failure terminates the supervisor. A
gap greater than 30 seconds blocks on the next evaluation.

Migration `0035_phase6_time_uncertainty` adds the nullable exact-decimal source
uncertainty field for recorded samples, updates the fixed policy identity, and
replaces the related database constraints. Upgrade and downgrade both acquire
the relevant protection and refuse to proceed if any trusted-time epoch,
evaluation, or host-head row exists. The migration is checked in but is not
applied to runtime Supabase by this decision.

The local Docker source and supervisor use fixed UID/GID 10001, read-only root
filesystems, dropped capabilities, `no-new-privileges`, bounded local CPU/RAM,
and a dedicated ephemeral Unix command-socket tmpfs. The source publishes no
host/container port, has no `SYS_TIME` capability, runs Chrony with `-x`, and
cannot set the shared host clock. The fixed-UID containers share that mode-0750
scratch volume read-write because unmodified Chrony 4.8 requires `chronyc` to
create its short-lived reply socket beside the daemon socket. Chrony's state
volume remains source-only. The supervisor receives the database URL only
through the Compose secret boundary and accepts only an exact Psycopg DSN with
`sslmode=verify-full`; missing, weaker, duplicated, or additional connection
query options fail closed. Host and supervisor database clients explicitly use
the checked-in Supabase 2021 root CA instead of a user or system default trust
path. Its PEM SHA-256 is
`700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7`,
its certificate fingerprint is
`807025ad50d4ed219d2c9c7d299c004f824eb00cf7f65afef607d07b72e6cafa`,
and it expires at `2031-04-26T10:56:53Z`. The supervisor image installs it
root-owned and read-only at the manifest-pinned path. A certificate change or
rotation requires a new reviewed authority and image; no fallback CA is used.

The source history still has no authenticated external head anchor and remains
tamper-evident rather than independently rollback-proof. The
[archived v1 authority manifest](evidence/0092-source-authority-v1.json) pins
readiness, operational-control, new-exposure, alert-delivery, automatic-rearm,
paper-trading, live-trading, and external-head authority false. No local result
grants arming or broker-action authority either.

## Consequences

The repository now has a precise local source selection, authenticated two-
provider composite, reviewed uncertainty cap, conservative point-plus-
uncertainty classification, and deterministic recurring schedule that can be
qualified without granting trading authority. The fixed 20-second grid leaves
headroom below the strict 30-second continuity/freshness boundary, but it does
not guarantee process liveness.

The supervisor has no independent watchdog. If it dies, no separate component
immediately turns silence into an alert or control transition. Persisted
evidence stops advancing, and staleness or an over-30-second gap is recognized
only when a later evaluation occurs. Direct operator supervision therefore
remains mandatory for any local qualification window.

Migration 0035 was applied to runtime Supabase on 2026-08-01 through the exact
purpose-built operator. The retained mode-`0600` postflight artifact has
SHA-256
`73085244cad0c24f22a06b22e8cf106c26f9e69a3bf5b32b9a296e995e165e6a`
and verifies the exact catalog, full operational schema, pinned TLS binding,
and zero trusted-time histories. A directly supervised live topology on
2026-08-01 authenticated immutable launch images, runtime hardening, PID1 and
zero-offset clock domains, durable chains, fixed cadence, and clean shutdown.
Its retained canonical artifact is `not_qualified`, with qualification SHA-256
`d65a1270b91865ef674af5ea91d23daa0872c392af6b6aa05de3708056c919ac`:
five of five current-epoch attempts were `source_unavailable` because Netnod
was selectable but excluded from the exact selected-plus-combined composite.
The reviewed image-admission digest was
`2de1fa43994a3918b956ccc749da834ea0636f1983bf33207b0745b8bd3f9c12`,
but its canonical bytes predated content-addressed retention and no repository
file is claimed for that digest.
Changing a provider, `combinelimit`, the absolute bound, or acceptance of that
state is a new reviewed authority and requires owner approval. No source/head
evidence is externally anchored, no alert route consumes failures, and no
readiness, control, final-dispatch, exposure, re-arm, paper, or live consumer
is composed. This decision does not satisfy the Phase 6 clock-drift game day or
authorize paper/live trading.

[ADR 0093](0093-system76-virginia-nts-authority-rotation.md) subsequently
rotated the current checked-in authority and configuration to System76
Virginia. That amendment does not rewrite this v1 decision, its archived
manifest, or its retained `not_qualified` evidence.
