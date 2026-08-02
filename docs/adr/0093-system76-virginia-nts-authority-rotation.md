# ADR 0093: System76 Virginia NTS authority rotation

- Status: Accepted
- Date: 2026-08-01
- Amends: [ADR 0092](0092-evidence-only-local-chrony-nts-trusted-time-supervision.md)

## Context

ADR 0092 approved an evidence-only local Chrony topology using Cloudflare and
Netnod. The retained 2026-08-01 qualification is immutable historical evidence:
its five current-epoch attempts were all `source_unavailable` because Netnod
was selectable but excluded from Chrony's required selected-plus-combined
composite. Its qualification SHA-256 remains
`d65a1270b91865ef674af5ea91d23daa0872c392af6b6aa05de3708056c919ac`,
and its artifact-file SHA-256 remains
`d1a36e8e96dd14a2552d5f911a16062122cb8fa2b5b55aca42bafa4fe104b2e7`.
Its recorded image-admission digest remains
`2de1fa43994a3918b956ccc749da834ea0636f1983bf33207b0745b8bd3f9c12`,
but those canonical admission bytes predated content-addressed retention, so
this decision does not claim that an old admission file exists.
This decision does not reinterpret, replace, or make that run successful.

The owner approved investigating a geographically closer, independently
operated NTS source without weakening the two-source admission boundary,
changing Chrony's selection policy, increasing the uncertainty cap, or adding
a fallback. System76 publishes a Virginia NTS endpoint, but it publishes no
service-level agreement, upstream time-source ensemble, deployment-redundancy
commitment, or leap-smear policy for this endpoint. Those unknowns prohibit any
availability, independence-of-upstreams, redundancy, or leap-behavior claim.

## Decision

Approve and implement the authority contract
`phase6c-local-chrony-nts-authority-v2` with source ID
`chrony-nts-cloudflare-system76-virginia-v2` and adapter contract
`phase6-chrony-4.8-nts-evidence-v2`. The fixed host remains
`local-paper-docker-primary-v1`. The exact ordered source set is:

- `time.cloudflare.com`, NTS-KE TCP 4460 and NTP UDP 123; and
- `virginia.time.system76.com`, NTS-KE TCP 4460 and negotiated NTP UDP 123.

Both sources remain required. Admission still requires exactly one selected
(`*`) source and exactly one combined (`+`) source. Both must be selectable,
NTS-authenticated, fresh, normal-leap NTPv4 servers on the fixed 16-second poll,
with admitted AEAD/key shapes, authenticated packets, passing source tests,
and mutually consistent tracking evidence. Missing, extra, `D`/`d`,
unauthenticated, stale, malformed, or single-provider evidence fails closed.

All other ADR 0092 invariants remain unchanged: Chrony 4.8 runs with `-x`;
there is no `combinelimit` change, retry, pool, unauthenticated source, local
reference, peer, manual source, provider fallback, host failover, or automatic
restart. Each probe retains its one-second deadline and the conservative
source-uncertainty cap remains exactly 100 milliseconds. The immediate probe,
absolute 20-second grid, 30-second maximum gap, durable replay, process and
clock-domain binding, immutable-image admission, pinned database TLS, and clean
stop requirements remain in force.

The rotation required a new source-authority digest, Chrony-config digest,
reviewed-source digest, immutable source and supervisor image IDs, fresh image-
admission artifact, fresh durable epoch, and new qualification artifact. No
prior Netnod sample or failure could satisfy the new authority's qualification
window. The 100-millisecond policy and persistence schema did not change, so
no new database migration was required. Existing epoch, evaluation, and host-
head history remains immutable.

The executable
[v2 source-authority manifest](../../infra/trusted-time/source-authority.json),
Chrony configuration, adapter, inspector-v5 contract, tests, and immutable
images are implemented. The retained exact implementation and admission
evidence is:

- authority SHA-256
  `9b514dc25b0cd084aedf1841b305260f22b070b70e396defc9ecce2f9545506c`,
  Chrony-config SHA-256
  `5b59d843624fa3b1a923804e44df96a7fbce3848380bf0d5a4b888072310fa23`,
  and authority-registry SHA-256
  `8e7a822503c5f73359cc18ee62dee4f56fb3e67f10b725374f8ef24c94344e9e`;
- reviewed source revision SHA-256
  `db81102def51115d85e9584ff8539aae1eede787939d0268e552dba40e8953b4`;
- source image
  `sha256:8d704f59e4b627e38035b8056f9a63037e610f635cac12a8bf76ec4eff3422f3`
  and supervisor image
  `sha256:ca86611fc6177ec50d80ef0f4ed280bef93865d954c8aee0dceac403cf079d0c`;
  and
- retained content-addressed
  [`image-admission-b4519a60...e76e.json`](../../artifacts/trusted-time/image-admission-b4519a60ae77987b1f2459c26b9ccd9782dd36946a46767a14531cf84807e76e.json),
  whose semantic and artifact-file SHA-256 are both
  `b4519a60ae77987b1f2459c26b9ccd9782dd36946a46767a14531cf84807e76e`.

The directly supervised
[`inspector-v5 qualification`](../../artifacts/trusted-time/trusted-time-qualification-1eb6c9396d9c82a76a1b57ba0b3266b4a420905e3f29e33613693087f23a728c.json)
retains contract `phase6c-live-trusted-time-qualification-inspection-v5`,
qualification SHA-256
`1eb6c9396d9c82a76a1b57ba0b3266b4a420905e3f29e33613693087f23a728c`,
and artifact-file SHA-256
`0d0575adc139cc0ec2516d3d5011727986d17e0f856ca810da3bbe84ce0cdec2`.
Epoch sequence 8 contains eight current-epoch evaluations over
140,064,973,522 nanoseconds: seven recorded samples and one
`source_unavailable` outcome. Cadence qualified, uncertainty remained between
`11.0340560000` and `16.0458345000` milliseconds, and the fresh,
current-process-bound terminal evidence was `healthy`, `within_limit`, and
recovery-qualified. The canonical status is `qualified`.

The one failed evaluation retained an intermittent System76 uppercase `D`
state before the later selected-plus-combined samples qualified. That observed
recovery is point-in-time evidence, not a continuous-availability claim.

System76's unpublished SLA, upstream ensemble, redundancy, and leap-smear
policy remain explicit limitations after the qualified window. The retained
gate observed the exact endpoint from the approved local Docker path and proved
the strict selected-plus-combined composite, authentication, negotiated NTP
port, leap state, reference age, uncertainty, cadence, and fresh terminal state
for that window only. A future failure preserves a non-authorizing
`not_qualified` result; it does not authorize selection-rule or bound changes.

Readiness, operational control, new exposure, alert delivery, automatic re-arm,
paper trading, live trading, and external-head-anchor authority remain false.
Neither this decision nor the retained healthy clock artifact grants any of
them.

## Consequences

The implemented authority keeps two independently operated NTS providers and
may reduce network distance relative to Netnod for the approved local host.
That is still only a comparative hypothesis until directly measured on the
actual runtime path. The absence of published System76 operating commitments
makes the source best-effort and prevents this topology from claiming
production availability or redundant upstream traceability.

The
[archived v1 Netnod authority](evidence/0092-source-authority-v1.json), SHA-256
`356723c84e30478f18ad99f3cfef2ee65b3bdd3fc26936a7d5c9910fd1bcb3ab`,
and retained failed qualification artifact remain the record of the earlier
decision and run. The checked-in
[v2 System76 authority](../../infra/trusted-time/source-authority.json) and the
separate retained v5 evidence record the current implementation and qualified
point-in-time window without rewriting that history.

The supervisor was stopped before the source. Both containers and the project
network were removed, secret staging was empty, and both named volumes were
retained. An authenticated external head anchor, independent watchdog,
readiness and operational-control consumers, alerting, new-exposure gates,
exact-head manual re-arm, and paper/live authority remain Phase 6 work.
