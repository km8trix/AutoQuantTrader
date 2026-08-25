# Architecture decision records

Architecture decisions are immutable once accepted. A materially different
choice is recorded in a new ADR that supersedes the earlier decision.

- [ADR 0001: v1 scope and canonical decision path](0001-v1-scope-and-canonical-path.md)
- [ADR 0002: point-in-time data and storage](0002-point-in-time-data-and-storage.md)
- [ADR 0003: ledger accounting and mandatory risk](0003-ledger-accounting-and-mandatory-risk.md)
- [ADR 0004: broker submission and account ownership](0004-broker-submission-and-account-ownership.md)
  (same-client-ID `UNKNOWN` recovery assumption amended for the E\*TRADE target
  by ADR 0096)
- [ADR 0005: desktop-browser control plane](0005-desktop-browser-control-plane.md)
- [ADR 0006: canonical engine boundary and build strategy](0006-engine-boundary-and-build-strategy.md)
- [ADR 0007: experiment governance and live authority](0007-experiment-governance-and-live-authority.md)
- [ADR 0008: recorded point-in-time admission slice](0008-recorded-point-in-time-admission.md)
- [ADR 0009: fail-closed licensed market-data admission](0009-fail-closed-market-data-admission.md)
- [ADR 0010: market-data provider qualification routing](0010-market-data-provider-qualification-routing.md)
- [ADR 0011: daily-first capture and raw-lane separation](0011-daily-first-capture-and-raw-lane-separation.md)
- [ADR 0012: Tiingo EOD offline-first qualification](0012-tiingo-eod-offline-first-qualification.md)
- [ADR 0013: Tiingo EOD authorization-gated capture](0013-tiingo-eod-authorization-gated-capture.md)
- [ADR 0014: Tiingo EOD offline capture verification](0014-tiingo-eod-offline-capture-verification.md)
- [ADR 0015: Tiingo EOD pinned calendar artifact and operator verification](0015-tiingo-eod-pinned-calendar-and-operator-verification.md)
- [ADR 0016: Tiingo EOD receipt-time local delivery lineage](0016-tiingo-eod-receipt-time-local-lineage.md)
- [ADR 0017: Tiingo EOD exact-retained raw-candidate field-contract qualification](0017-tiingo-eod-exact-retained-field-contract-qualification.md)
- [ADR 0018: Tiingo EOD security-identity and lifecycle contract-only qualification](0018-tiingo-eod-security-identity-lifecycle-contract.md)
- [ADR 0019: Tiingo EOD market semantics and action-candidate qualification](0019-tiingo-eod-market-semantics-and-action-candidates.md)
- [ADR 0020: deterministic availability-time replay and watermark-complete market batches](0020-deterministic-availability-replay-and-market-batches.md)
- [ADR 0021: manifest replay tapes and sealed run evidence](0021-manifest-replay-tapes-and-sealed-run-evidence.md)
- [ADR 0022: deterministic clock callbacks and versioned strategy state](0022-deterministic-clock-callbacks-and-versioned-strategy-state.md)
- [ADR 0023: causal portfolio snapshots and canonical intent batches](0023-causal-portfolio-snapshots-and-intent-batches.md)
- [ADR 0024: canonical order and execution lifecycle reducer](0024-canonical-order-and-execution-lifecycle-reducer.md)
- [ADR 0025: append-only execution ledger reducer](0025-append-only-execution-ledger-reducer.md)
- [ADR 0026: FIFO cash account and causal valuation](0026-fifo-cash-account-and-causal-valuation.md)
- [ADR 0027: source-bound execution settlement ledger](0027-source-bound-execution-settlement-ledger.md)
- [ADR 0028: source-bound corporate-action accounting](0028-source-bound-corporate-action-accounting.md)
- [ADR 0029: conservative source-bound simulated broker](0029-conservative-source-bound-simulated-broker.md)
- [ADR 0030: process-local atomic intent-batch risk reservations](0030-process-local-atomic-intent-batch-risk-reservations.md)
- [ADR 0031: process-local account coordinator leases and fences](0031-process-local-account-coordinator-leases-and-fences.md)
- [ADR 0032: durable fenced batch execution lifecycle](0032-durable-fenced-batch-execution-lifecycle.md)
- [ADR 0033: durable fixture-only research workflow](0033-durable-fixture-research-workflow.md)
- [ADR 0034: versioned feature artifacts and differential parity](0034-versioned-feature-artifacts-and-differential-parity.md)
- [ADR 0035: causal feature consumers and target parity](0035-causal-feature-consumers-and-target-parity.md)
- [ADR 0036: bounded experiment governance and holdout commitments](0036-bounded-experiment-governance-and-holdout-commitments.md)
  (completion evidence superseded by ADR 0037)
- [ADR 0037: configuration-bound governed segment evaluation](0037-configuration-bound-governed-segment-evaluation.md)
- [ADR 0038: offline Alpaca paper contract boundary](0038-offline-alpaca-paper-contract-boundary.md)
  (status vocabulary amended by ADR 0039; the Alpaca paper chain remains
  historical/non-authorizing and is not the selected live broker; see ADR 0096)
- [ADR 0039: offline Alpaca client-order lookup observations](0039-offline-alpaca-client-order-lookup-observations.md)
- [ADR 0040: durable pre-decode broker ingress](0040-durable-pre-decode-broker-ingress.md)
- [ADR 0041: durable broker request budget admission](0041-durable-broker-request-budget-admission.md)
- [ADR 0042: offline Alpaca account and asset observations](0042-offline-alpaca-account-asset-observations.md)
- [ADR 0043: offline Alpaca dispatch-preflight evidence binder](0043-offline-alpaca-dispatch-preflight-evidence-binder.md)
- [ADR 0044: authenticated Alpaca paper account binding](0044-authenticated-alpaca-paper-account-binding.md)
- [ADR 0045: authenticated Alpaca paper asset binding](0045-authenticated-alpaca-paper-asset-binding.md)
- [ADR 0046: authenticated Alpaca paper client-order lookup](0046-authenticated-alpaca-paper-client-order-lookup.md)
- [ADR 0047: durable bounded UNKNOWN lookup scheduling](0047-durable-bounded-unknown-lookup-scheduling.md)
- [ADR 0048: durable normalized UNKNOWN-lookup reconciliation evidence](0048-durable-normalized-lookup-reconciliation-evidence.md)
- [ADR 0049: source-scoped broker inbox admission and non-application receipts](0049-source-scoped-broker-inbox-admission.md)
- [ADR 0050: bounded raw-first Alpaca order-snapshot pages](0050-bounded-raw-first-alpaca-order-snapshot-pages.md)
- [ADR 0051: bounded non-authorizing order-snapshot comparison](0051-bounded-non-authorizing-order-snapshot-comparison.md)
- [ADR 0052: authenticated durable Alpaca order-snapshot pages](0052-authenticated-durable-alpaca-order-snapshot-pages.md)
- [ADR 0053: durable authenticated Alpaca order-view comparisons](0053-durable-authenticated-order-view-comparisons.md)
- [ADR 0054: bounded restart-safe Alpaca order-view supervision](0054-bounded-restart-safe-order-view-supervision.md)
- [ADR 0055: bounded raw-first Alpaca position views](0055-bounded-raw-first-alpaca-position-views.md)
- [ADR 0056: bounded non-authorizing Alpaca position-view comparison](0056-bounded-non-authorizing-alpaca-position-view-comparison.md)
- [ADR 0057: authenticated single-use Alpaca position views](0057-authenticated-single-use-alpaca-position-views.md)
- [ADR 0058: durable single-use Alpaca position snapshots](0058-durable-single-use-alpaca-position-snapshots.md)
- [ADR 0059: durable authenticated Alpaca position-view comparisons](0059-durable-authenticated-position-view-comparisons.md)
- [ADR 0060: bounded restart-safe Alpaca position-view supervision](0060-bounded-restart-safe-position-view-supervision.md)
- [ADR 0061: durable Alpaca position-pair transition admission](0061-durable-position-pair-transition-admission.md)
- [ADR 0062: pair-admitted Alpaca position-view runtime composition](0062-pair-admitted-position-view-runtime-composition.md)
- [ADR 0063: coherent process-local order-view supervision wiring](0063-coherent-order-view-supervision-wiring.md)
- [ADR 0064: durable Alpaca order-pair page-transition admission](0064-durable-order-pair-page-transition-admission.md)
- [ADR 0065: pair-admitted Alpaca order-view runtime composition](0065-pair-admitted-order-view-runtime-composition.md)
- [ADR 0066: durable operational-control spine](0066-durable-operational-control-spine.md)
- [ADR 0067: approval-gated advanced-risk evidence boundary](0067-approval-gated-advanced-risk-evidence.md)
- [ADR 0068: owner-approved moderate paper risk policy](0068-owner-approved-moderate-paper-risk-policy.md)
- [ADR 0069: restart-safe UNKNOWN recovery composition](0069-restart-safe-unknown-recovery-composition.md)
- [ADR 0070: bounded raw-first Alpaca account-activity pages](0070-bounded-raw-first-alpaca-account-activity-pages.md)
- [ADR 0071: OpenTelemetry trading-chain correlation](0071-opentelemetry-trading-correlation.md)
- [ADR 0072: durable provider-neutral critical-alert delivery](0072-durable-critical-alert-delivery.md)
- [ADR 0073: authenticated local operations API](0073-authenticated-local-operations-api.md)
- [ADR 0074: read-only local operations dashboard](0074-read-only-local-operations-dashboard.md)
- [ADR 0075: strict supervised strategy subprocess](0075-strict-supervised-strategy-subprocess.md)
- [ADR 0076: durable authenticated account-activity traversals](0076-durable-authenticated-account-activity-traversals.md)
- [ADR 0077: durable strategy-supervision composition](0077-durable-strategy-supervision-composition.md)
- [ADR 0078: bounded provider-neutral critical-alert worker](0078-bounded-critical-alert-worker.md)
- [ADR 0079: durable pre-run strategy invocation claims](0079-durable-pre-run-strategy-invocation-claims.md)
- [ADR 0080: atomic advanced-risk admission, cutover, and dispatch](0080-atomic-advanced-risk-admission.md)
- [ADR 0081: durable local operations composition](0081-durable-local-operations-composition.md)
- [ADR 0082: safe browser PAUSE and HALT controls](0082-safe-browser-pause-halt-controls.md)
- [ADR 0083: durable authenticated account-activity comparisons](0083-durable-authenticated-account-activity-comparisons.md)
- [ADR 0084: typed local operational-drill evidence](0084-typed-local-operational-drill-evidence.md)
- [ADR 0085: atomic local critical-alert worker composition](0085-atomic-critical-alert-worker-composition.md)
- [ADR 0086: provider-neutral trusted-time monitor](0086-provider-neutral-trusted-time-monitor.md)
- [ADR 0087: verified no-exposure smoke strategy artifact](0087-verified-no-exposure-smoke-strategy.md)
- [ADR 0088: fail-closed paper smoke deployment profile (amended local preflight)](0088-fail-closed-paper-smoke-deployment-profile.md)
  (historical enrollment projection amended by ADR 0089)
- [ADR 0089: read-only paper-account enrollment attestation](0089-read-only-paper-account-enrollment-attestation.md)
- [ADR 0090: durable trusted-time persistence and one-shot supervision](0090-durable-trusted-time-persistence-and-one-shot-supervision.md)
- [ADR 0091: fail-closed production browser bundle admission](0091-fail-closed-production-browser-bundle-admission.md)
- [ADR 0092: evidence-only local Chrony NTS trusted-time supervision](0092-evidence-only-local-chrony-nts-trusted-time-supervision.md)
  (source authority amended by ADR 0093;
  [archived v1 Netnod manifest](evidence/0092-source-authority-v1.json) and
  retained `not_qualified` evidence remain historical)
- [ADR 0093: System76 Virginia NTS authority rotation](0093-system76-virginia-nts-authority-rotation.md)
  ([current v2 System76 manifest](../../infra/trusted-time/source-authority.json);
  retained inspector-v5 result is qualified but non-authorizing)
- [ADR 0094: Separate-Supabase signed sparse trusted-time head checkpoints](0094-separate-supabase-signed-sparse-trusted-time-head-checkpoints.md)
  (migration 0036, separate-project provisioning, and the v2 SELECT-policy
  correction are applied; the same-object proof and first external enrollment
  completed, with normal start still quarantined by ADRs 0097 and 0098)
- [ADR 0095: Dormant provider-neutral trusted-head watchdog state](0095-dormant-provider-neutral-trusted-head-watchdog-state.md)
  (pure preparatory reducer only; raw observations remain unqualified, while
  ADR 0109 adds only a clean-stop-specific terminal observer with no live or
  effect consumer except ADR 0111's dormant zero-caller composition; watchdog
  qualification, a dedicated reader, deployment, and every live consumer
  remain pending)
- [ADR 0096: E\*TRADE live broker and sandbox qualification boundary](0096-etrade-live-broker-and-sandbox-qualification.md)
  (selects the future live venue only; sandbox is protocol-only, all Alpaca
  artifacts remain historical, and implementation, credentials, and live
  activation remain gated)
- [ADR 0097: Approval-bound first trusted-time enrollment and recovery](0097-approval-bound-first-trusted-time-enrollment.md)
  (dedicated profile-only one-shot operator; the first `new` enrollment is
  confirmed with no sequence 2 or authority grant, while its retained claim
  continues to quarantine normal start/admission)
- [ADR 0098: Canonical post-enrollment start evidence review](0098-canonical-post-enrollment-start-evidence-review.md)
  (pure exact claim/outcome decoder, owner-only unambiguous loader, and
  non-authorizing old-evidence/new-target review projection; persistent start,
  sequence 2, and shutdown remain separately approval-blocked)
- [ADR 0099: Approval-bound post-enrollment start and graceful stop](0099-approval-bound-post-enrollment-start-and-graceful-stop.md)
  (freezes the single-use start/claim/outcome, fresh sequence-1
  reauthentication, sequence-2, crash, and supervisor-first stop contracts;
  the complete process-local start/controller chronology and standalone host
  are implemented code-only, while no live start was executed and graceful
  shutdown plus later operational consumers remain hard closed)
- [ADR 0100: Post-enrollment operator public-key provisioning](0100-post-enrollment-operator-public-key-provisioning.md)
  (two-phase isolated offline preparation and exact-digest installation of one
  dedicated canonical non-identity prime-subgroup Ed25519 trust root; the fixed
  source path remains absent until operator installation, private signing
  material remains external, and no execution approval or controller authority
  is added)
- [ADR 0101: Inert post-enrollment operator-attestation verification](0101-inert-post-enrollment-operator-attestation-verification.md)
  (pure canonical statement/v3-envelope codec and explicit-authority Ed25519
  verifier only; exact v2 bytes are signature-bound but semantically
  unqualified, with no loader, signer, caller, freshness, replay slot,
  admission, runtime, or operational use)
- [ADR 0102: Offline post-enrollment operator-attestation artifacts](0102-offline-post-enrollment-operator-attestation-artifacts.md)
  (two-stage external statement-candidate preparation and detached-signature
  verification/retention only; public artifacts remain content-addressed,
  owner-only, and non-authorizing outside the ADR-0103 admission composition)
- [ADR 0103: Atomic operator-attested post-enrollment execution admission](0103-atomic-operator-attested-post-enrollment-execution-admission.md)
  (code-only v3-only authority/signature/semantic/provenance admission and host
  cutover with historical-v2 slot preservation; the fixed authority remains
  absent, no Make executor exists, and no operational attempt was performed)
- [ADR 0104: Durable non-authorizing post-enrollment graceful-stop targeting](0104-durable-non-authorizing-post-enrollment-graceful-stop-targeting.md)
  (embeds a complete inert shutdown locator in controller outcome v2, preserves
  v1 as historical locator-unavailable evidence, and freezes a distinct
  unqualified stop target/replay decision; no stop key, attestation, admission,
  CLI, Docker caller, or effecting shutdown exists)
- [ADR 0105: Inert post-enrollment graceful-stop operator attestation](0105-inert-post-enrollment-graceful-stop-operator-attestation.md)
  (freezes a distinct strict public authority, signed decision statement,
  explicit-authority verifier, and offline public artifact workflows; the real
  authority remains absent and no currentness, replay slot, admission, caller,
  or shutdown effect is added)
- [ADR 0106: Authenticated historical start chain graceful-stop decision candidate](0106-authenticated-historical-start-chain-graceful-stop-decision-candidate.md)
  (strictly reloads and cross-binds the committed confirmed start outcome v2,
  locator, v3-format start-attempt slot, and signed start envelope before
  publishing one inert content-addressed decision-v1 candidate; currentness,
  stop admission, outcome/recovery, and every shutdown effect remain absent)
- [ADR 0107: Fail-closed clean-stop completion invariant](0107-fail-closed-clean-stop-completion-invariant.md)
  (requires a new receipt from the exact current `clean_stop` request before
  the worker may report clean completion; unchanged-head and recovered-receipt
  cases remain unconfirmed; ADR 0108 later adds only sealed process-local
  new-record evidence, not a no-new proof or shutdown effect)
- [ADR 0108: Sealed new-record clean-stop terminal result](0108-sealed-new-record-clean-stop-terminal-result.md)
  (seals the exact current record, receipt, reconciliation, and request identity
  into a one-shot process-local worker result; no provider-terminal currentness,
  durable outcome/recovery, authenticated live wire handoff or transport, slot,
  admission, signal, or effect is added)
- [ADR 0109: Code-only clean-stop terminal reauthentication](0109-code-only-clean-stop-terminal-reauthentication.md)
  (adds one one-shot S1/provider/S2 host observation with a full authenticated
  two-pass namespace audit, late terminal GET and empty-next check, final
  provider identity, and exact SQL equality; its only consumer is ADR 0111's
  dormant zero-caller composition, and it remains point-in-time, non-durable,
  non-authorizing, and absent from every CLI, watchdog, outcome, signal, and
  teardown path)
- [ADR 0110: Dormant durable graceful-stop lifecycle repository](0110-dormant-durable-graceful-stop-lifecycle-repository.md)
  (freezes one immutable global ordinal-zero attempt root that is also the
  permanent replay slot plus a typed append-only hash chain; no production
  reservation, post-signal constructor, confirmed-success outcome, caller,
  recovery executor, or shutdown effect is added; its only terminal is the
  non-authorizing recovery-required classification for unavailable live
  integration)
- [ADR 0111: Dormant operation-bound clean-stop supervisor bridge](0111-dormant-operation-bound-clean-stop-supervisor-bridge.md)
  (freezes strict structural request/result wire contracts, binds one exact
  preselected worker request to its sealed ADR-0108 result, and cross-binds it
  once to an ADR-0109 host observation; no production caller, authenticated
  transport, lifecycle advance, currentness, durable outcome, or effect is
  added)
- [ADR 0112: Durable graceful-stop decision-artifact receipt reauthentication](0112-durable-graceful-stop-decision-artifact-receipt-reauthentication.md)
  (reconstructs the unchanged ADR-0106 v1 receipt from one stable external
  decision candidate and the fully reauthenticated historical start chain;
  load is inert, explicit authentication consumes its exact pending binding and
  fresh-loads every source before activation, and revalidation consumes the
  active binding; the zero-caller flow adds no sidecar, CLI, currentness,
  admission, lifecycle advance, runtime consumer, or shutdown effect)
- [ADR 0113: Recorded-offline E\*TRADE provider foundation](0113-recorded-offline-etrade-provider-foundation.md)
  (implements Phase 4AJ's typed sandbox/production endpoint and nonsecret scope
  isolation, exact shared OAuth/OOB callback metadata, provider-specific
  account identifiers, and one deterministic Accounts List description; it
  adds no secrets, OAuth flow, decoder, provider call, persistence, account
  binding, broker mutation, or trading authority)
- [ADR 0114: Fail-closed captured-tape research validity](0114-fail-closed-captured-tape-research-validity.md)
  (adds a pure Phase 3E validity gate that rechecks Wave 1A prerequisites,
  separately recomputes source admission, binds immutable capture/replay/config
  evidence, and requires exact independent review; v1 has no authenticated-
  origin trust root and therefore cannot emit positive eligibility, while all
  source, admission, promotion, deployment, and trading effects remain absent)
- [ADR 0115: Bounded offline E\*TRADE Accounts List caller declarations](0115-bounded-recorded-offline-etrade-accounts-list-responses.md)
  (implements Phase 4AK's pure in-memory raw-first caller-declared response and
  strict decoder with exact internally consistent request/environment/origin/
  media/charset/declaration/schema bindings; provider origin remains
  unauthenticated, fixture relabeling is undetectable, and transport,
  persistence, account binding, mutation, and trading authority remain closed)
- [ADR 0116: Fail-closed replay-safe graceful-stop composition ordering](0116-fail-closed-replay-safe-graceful-stop-composition-ordering.md)
  (freezes the design-only transport → same-lock admission → lifecycle-v2 →
  fork-safety → ordered-effect dependency chain with a separately versioned
  lifecycle-v2-compatible request/result/host-binding family that rejects every
  v1↔v2 mix, a fresh pre-effect ADR-0109 cross-binding, distinct post-teardown
  terminal reauthentication, exact ambiguity, and recovery invariants; it adds
  no implementation, authority, reservation, runtime caller, shutdown effect,
  or change to the exit-2 stop target)
- [ADR 0117: Durable bounded fixture-segment worker](0117-durable-fixture-segment-worker.md)
  (implements Phase 3F's repository-fixture-only durable job, rotating physical
  claim, content-addressed feature/target transcripts, and atomic governed
  completion; economic evaluation, captured-tape eligibility, promotion,
  provider I/O, and every source, deployment, broker, or trading authority
  remain closed)
- [ADR 0118: Pure E\*TRADE OAuth 1.0a signing and supervised session](0118-pure-etrade-oauth1-signing-and-supervised-session.md)
  (implements Phase 4AL's deterministic HMAC-SHA1 signing and secret-free pure
  session reducer over the exact ADR-0113 endpoints, typed environment-bound
  nonsecret reference revisions, injected timestamp/nonce, bounded replay
  guard with per-scope signing-time/generation high-water, sealed one-use exact-
  verifier access exchange, OOB authorization, renewal, inactivity/expiry,
  revocation, and reauthorization transitions; all secrets and signing output
  remain ephemeral and every credential, persistence, provider, account,
  broker, and trading authority remains closed)
- [ADR 0119: Authenticated fixture-segment provenance views](0119-authenticated-fixture-segment-provenance-views.md)
  (implements Phase 3G's GET-only, keyset-paginated job and bounded event views
  over fully authenticated Phase 3F chains; only opaque digests, counts, safe
  lifecycle ordinals/timestamps, and status cross a structurally redacted query
  boundary, with no schema, mutation, economic, provider, or trading authority)

Related normative baseline: [Operational budgets](../OPERATIONAL_BUDGETS.md).
