import type {
  DashboardSummary,
  DataCatalogResponse,
  DataQualityResponse,
  UiBootstrap,
} from './types'

const isoBefore = (now: Date, milliseconds: number): string =>
  new Date(now.getTime() - milliseconds).toISOString()

const isoAfter = (now: Date, milliseconds: number): string =>
  new Date(now.getTime() + milliseconds).toISOString()

export function makeBootstrapFixture(now = new Date()): UiBootstrap {
  return {
    backtest_launch: {
      enabled: true,
      operator_id: 'local-operator',
      csrf_token: 'development-fixture-csrf-token',
      csrf_header: 'X-CSRF-Token',
      idempotency_header: 'Idempotency-Key',
      disabled_reason: null,
    },
    user: {
      id: 'local-operator',
      display_name: 'Local operator',
    },
    environment: {
      name: 'Local synthetic simulation',
      mode: 'local',
      account_id: 'synthetic-fixture',
    },
    market_clock: {
      status: 'closed',
      as_of: isoBefore(now, 3_000),
      next_transition_at: isoAfter(now, 52 * 60 * 1_000),
    },
    readiness: {
      status: 'ready',
      reasons: [],
      as_of: isoBefore(now, 2_000),
    },
    capabilities: ['research', 'simulation-only'],
    feature_flags: {
      walking_thread: true,
      controls: false,
      event_stream: false,
    },
    stream_cursor: 'dev-fixture-0007',
  }
}

export function makeDashboardFixture(now = new Date()): DashboardSummary {
  return {
    as_of: isoBefore(now, 2_000),
    account: {
      equity: '100248.32',
      cash: '75624.08',
      currency: 'USD',
      realized_pnl: '128.40',
      unrealized_pnl: '119.92',
      gross_exposure: '24624.24',
      net_exposure: '24624.24',
    },
    deployment: {
      id: 'deployment-walking-thread',
      name: 'Walking thread',
      strategy_name: 'Buy and hold fixture',
      state: 'shadow',
      mode: 'local',
    },
    health: [
      {
        id: 'market-data',
        label: 'Market data',
        status: 'healthy',
        as_of: isoBefore(now, 4_000),
        detail: 'Fixed one-minute tape is current.',
      },
      {
        id: 'risk',
        label: 'Risk engine',
        status: 'healthy',
        as_of: isoBefore(now, 2_500),
        detail: 'Mandatory approval persisted.',
      },
      {
        id: 'execution',
        label: 'Execution',
        status: 'healthy',
        as_of: isoBefore(now, 2_000),
        detail: 'Simulation adapter is ready.',
      },
      {
        id: 'ledger',
        label: 'Ledger',
        status: 'healthy',
        as_of: isoBefore(now, 1_800),
        detail: 'Balanced postings verified.',
      },
    ],
    alerts: {
      critical: 0,
      warning: 0,
    },
    pending_commands: 0,
    trace: [
      {
        id: 'trace-market-event',
        stage: 'market_event',
        status: 'completed',
        occurred_at: isoBefore(now, 8_000),
        title: 'Market event accepted',
        detail: 'SPY 1-minute bar passed temporal validation.',
      },
      {
        id: 'trace-target',
        stage: 'target',
        status: 'completed',
        occurred_at: isoBefore(now, 7_200),
        title: 'Target proposed',
        detail: 'Strategy requested a 100-share SPY position.',
      },
      {
        id: 'trace-risk',
        stage: 'risk',
        status: 'completed',
        occurred_at: isoBefore(now, 6_400),
        title: 'Risk approved',
        detail: 'Cash and exposure were reserved atomically.',
      },
      {
        id: 'trace-order',
        stage: 'order',
        status: 'completed',
        occurred_at: isoBefore(now, 5_400),
        title: 'Order simulated',
        detail: 'A deterministic client order ID was accepted.',
      },
      {
        id: 'trace-fill',
        stage: 'fill',
        status: 'completed',
        occurred_at: isoBefore(now, 4_200),
        title: 'Fill recorded',
        detail: '100 shares filled on the next eligible event.',
      },
      {
        id: 'trace-ledger',
        stage: 'ledger',
        status: 'completed',
        occurred_at: isoBefore(now, 3_300),
        title: 'Ledger balanced',
        detail: 'Cash and security postings reconcile to zero.',
      },
      {
        id: 'trace-position',
        stage: 'position',
        status: 'completed',
        occurred_at: isoBefore(now, 2_200),
        title: 'Position projected',
        detail: 'The account projection now holds 100 SPY shares.',
      },
    ],
  }
}

export function makeDataCatalogFixture(now = new Date()): DataCatalogResponse {
  const sessionStart = new Date('2026-07-14T13:30:00.000Z').toISOString()
  const sessionEnd = new Date('2026-07-14T20:00:00.000Z').toISOString()
  return {
    as_of: isoBefore(now, 4_000),
    source: {
      source_id: 'synthetic-pit-fixture-v1',
      name: 'Synthetic point-in-time fixture',
      kind: 'synthetic_fixture',
      licensed: false,
      entitlement_status: 'fixture_only',
      detail: 'Contract evidence only; no licensed vendor payload or live-feed entitlement is present.',
    },
    jobs: [
      {
        job_id: 'job-fixture-20260714-001',
        status: 'completed',
        source_id: 'synthetic-pit-fixture-v1',
        started_at: isoBefore(now, 75_000),
        completed_at: isoBefore(now, 68_000),
        source_record_count: 782,
        normalized_record_count: 781,
        published_partition_count: 2,
        quarantined_record_count: 1,
      },
    ],
    manifests: [
      {
        manifest_id: 'manifest-synthetic-xnys-20260714-v1',
        name: 'Synthetic XNYS one-minute raw bars',
        manifest_hash: '410c7a420dab74f88279bc9cf28e67010cad99e2e17347a47f74db3f3c0c8a73',
        schema_version: 'raw-bar-v1',
        calendar_version: 'XNYS-fixture-2026a',
        universe_version: 'etf-fixture-v1',
        corporate_action_version: 'actions-fixture-v1',
        revision_policy: 'revised_as_of',
        price_basis: 'raw',
        created_at: isoBefore(now, 68_000),
        row_count: 780,
        partitions: [
          {
            partition_id: 'partition-spy-20260714-v1',
            ordinal: 0,
            object_key: 'sha256/9f/9f32b9c4.parquet',
            layer: 'normalized',
            checksum: '9f32b9c4b38ad74c187e048b59012f93f683603a4d574d08524b3951efc59757',
            row_count: 390,
            event_time_start: sessionStart,
            event_time_end: sessionEnd,
            available_at_start: new Date('2026-07-14T13:31:02.000Z').toISOString(),
            available_at_end: new Date('2026-07-14T20:00:03.000Z').toISOString(),
            quality_status: 'passed',
          },
          {
            partition_id: 'partition-qqq-20260714-v1',
            ordinal: 1,
            object_key: 'sha256/1b/1b840f22.parquet',
            layer: 'normalized',
            checksum: '1b840f22c242ade5a1ac970330f73f022eb1dca04e5c193ffdfa317d785d979d',
            row_count: 390,
            event_time_start: sessionStart,
            event_time_end: sessionEnd,
            available_at_start: new Date('2026-07-14T13:31:03.000Z').toISOString(),
            available_at_end: new Date('2026-07-14T20:00:04.000Z').toISOString(),
            quality_status: 'passed',
          },
        ],
      },
    ],
    instruments: [
      {
        instrument_id: 'US-ETF-SPY',
        name: 'Synthetic SPY fixture',
        asset_class: 'etf',
        currency: 'USD',
        status: 'active',
        listed_at: '1993-01-22T14:30:00.000Z',
        delisted_at: null,
        mappings: [
          {
            symbol: 'SPY',
            venue: 'ARCX',
            valid_from: '1993-01-22T14:30:00.000Z',
            valid_to: null,
            available_at: '1993-01-22T14:30:00.000Z',
            tradable: true,
          },
        ],
      },
      {
        instrument_id: 'US-ETF-FIXTURE-DELISTED',
        name: 'Synthetic delisted fixture',
        asset_class: 'etf',
        currency: 'USD',
        status: 'delisted',
        listed_at: '2018-01-02T14:30:00.000Z',
        delisted_at: '2026-06-30T20:00:00.000Z',
        mappings: [
          {
            symbol: 'OLDX',
            venue: 'ARCX',
            valid_from: '2018-01-02T14:30:00.000Z',
            valid_to: '2024-01-02T14:30:00.000Z',
            available_at: '2018-01-02T14:30:00.000Z',
            tradable: true,
          },
          {
            symbol: 'NEWX',
            venue: 'ARCX',
            valid_from: '2024-01-02T14:30:00.000Z',
            valid_to: '2026-06-30T20:00:00.000Z',
            available_at: '2023-12-15T21:00:00.000Z',
            tradable: false,
          },
        ],
      },
    ],
    corporate_actions: [
      {
        action_revision_id: 'action-revision-fixture-split-1',
        action_id: 'action-fixture-split',
        revision: 1,
        instrument_id: 'US-ETF-SPY',
        symbol: 'SPY',
        action_type: 'split',
        effective_at: '2026-07-01T13:30:00.000Z',
        available_at: '2026-06-20T12:00:00.000Z',
        detail: 'Synthetic 2-for-1 split terms for contract testing.',
      },
      {
        action_revision_id: 'action-revision-fixture-symbol-change-1',
        action_id: 'action-fixture-symbol-change',
        revision: 1,
        instrument_id: 'US-ETF-FIXTURE-DELISTED',
        symbol: 'NEWX',
        action_type: 'symbol_change',
        effective_at: '2024-01-02T14:30:00.000Z',
        available_at: '2023-12-15T21:00:00.000Z',
        detail: 'Synthetic OLDX to NEWX mapping change.',
      },
    ],
    entitlements: [
      {
        source_id: 'synthetic-pit-fixture-v1',
        feed: 'Synthetic historical bars',
        licensed: false,
        status: 'fixture_only',
        scope: 'Repository-owned synthetic fixtures; contract and replay tests only.',
        verified_at: null,
      },
    ],
    admissions: [
      {
        admission_run_id: 'aa5522d3f4ad742ee55d692eb0dff5c49edbe1017ca366f0c70a79cb6cd5c8c8',
        profile_id: '635d41009cb3f9b1f63d90c0244db497d6dd7ddcbb049ecfae04abca5f3a76bb',
        source_id: 'synthetic-pit-fixture-v1',
        manifest_id: 'manifest-synthetic-xnys-20260714-v1',
        status: 'blocked',
        profile_name: 'Synthetic fixture admission contract',
        adapter_type: 'recorded-jsonl-v1',
        identifier_authority: 'fixture-internal-only',
        universe_version: 'etf-fixture-v1',
        calendar_version: 'XNYS-fixture-2026a',
        corporate_action_version: 'actions-fixture-v1',
        coverage_start: '2026-07-14T13:30:00.000Z',
        coverage_end: '2026-07-14T20:00:00.000Z',
        required_symbols: ['SPY'],
        specification_digest: '635d41009cb3f9b1f63d90c0244db497d6dd7ddcbb049ecfae04abca5f3a76bb',
        evidence_digest: 'a28a69c823fae08b50db7ce903f067bb25984cf65177544df57544b33ef62362',
        report_digest: 'aa5522d3f4ad742ee55d692eb0dff5c49edbe1017ca366f0c70a79cb6cd5c8c8',
        executed_at: isoBefore(now, 67_000),
        executed_by: 'local-admission-runner',
        reviewed_at: null,
        reviewed_by: null,
        review_decision: null,
        passed_check_count: 2,
        failed_check_count: 1,
        pending_check_count: 1,
        detail: 'Technical fixture evidence is present, but licensed entitlement and independent review are absent.',
        checks: [
          {
            code: 'deterministic_reingestion',
            status: 'passed',
            detail: 'Identical source bytes reproduced the same immutable manifest.',
            evidence_digest: 'd8156bae0c424f9dbb03d4d26c82f501e6b3b99ee479791c82652373962179cd',
            observed_at: isoBefore(now, 67_000),
          },
          {
            code: 'causal_corrections',
            status: 'passed',
            detail: 'The later correction remained invisible before its availability time.',
            evidence_digest: 'b575d26d04238b33cf2d5121886c942078767dc87310fbc701b82cf5fe17f120',
            observed_at: isoBefore(now, 67_000),
          },
          {
            code: 'licensed_entitlement',
            status: 'failed',
            detail: 'The checked-in source is synthetic and has no vendor license.',
            evidence_digest: null,
            observed_at: isoBefore(now, 67_000),
          },
          {
            code: 'independent_review',
            status: 'pending',
            detail: 'An independent reviewer has not approved this evidence bundle.',
            evidence_digest: null,
            observed_at: isoBefore(now, 67_000),
          },
        ],
      },
    ],
  }
}

export function makeDataQualityFixture(now = new Date()): DataQualityResponse {
  return {
    as_of: isoBefore(now, 3_000),
    issues: [
      {
        issue_id: 'quality-issue-invalid-ohlc-001',
        code: 'invalid_ohlc',
        severity: 'error',
        status: 'open',
        summary: 'High price is below the close price',
        detail: 'Synthetic row 391 violates the canonical raw-bar OHLC relationship.',
        detected_at: isoBefore(now, 69_000),
        partition_id: 'partition-fixture-quarantine-001',
        quarantined: true,
      },
      {
        issue_id: 'quality-issue-missing-session-001',
        code: 'missing_session',
        severity: 'warning',
        status: 'open',
        summary: 'Expected XNYS session has no source records',
        detail: 'The fixture intentionally omits one complete session to prove gap reporting.',
        detected_at: isoBefore(now, 69_000),
        partition_id: null,
        quarantined: false,
      },
    ],
    quarantine: [
      {
        partition_id: 'partition-fixture-quarantine-001',
        reason: 'Fatal invalid_ohlc finding; publication is prohibited.',
        quarantined_at: isoBefore(now, 69_000),
        row_count: 1,
      },
    ],
  }
}
