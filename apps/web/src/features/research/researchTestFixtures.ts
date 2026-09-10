/** Controlled HTTP responses for component tests only; never imported by product pages. */
import type { ResearchCatalog, ResearchComparison, ResearchEquityRow, ResearchExperiment, ResearchMetric, ResearchReport, ResearchRows, ResearchRun } from './researchApi'

export const digest = (character = 'a') => character.repeat(64)
export const asOf = '2026-09-09T12:00:00Z'

export function catalogFixture(): ResearchCatalog {
  return {
    as_of: asOf,
    datasets: [
      { dataset_id: 'catalog-synthetic', manifest_sha256: digest('a'), display_name: 'Synthetic engineering history', data_class: 'synthetic_fixture', symbols: ['SPY'], start_session: '2024-01-02', end_session: '2026-01-30', session_count: 520, availability_policy: 'synthetic-event-clock', prior_access: 'known_accessed', limitations: ['Engineering data; no historical profitability evidence.'] },
      { dataset_id: 'catalog-imported', manifest_sha256: digest('b'), display_name: 'Imported five-session sample', data_class: 'validated_current_vintage_history', symbols: ['SPY', 'QQQ'], start_session: '2026-07-20', end_session: '2026-07-24', session_count: 5, availability_policy: 'modeled-after-close', prior_access: 'known_accessed', limitations: ['Insufficient history for default warmup and annualized metrics.', 'Previously accessed; not untouched holdout.'] },
    ],
    strategies: ['buy_hold', 'trend_sma'].map((kind) => ({
      strategy_id: kind, version: 'reference/1', display_name: kind === 'buy_hold' ? 'Buy and hold' : 'SMA trend', description: 'Transparent reference rule.',
      default_configuration: { kind: kind === 'buy_hold' ? 'buy_hold' : 'trend_sma', lookback: 200, allocation: '0.25', rebalance_sessions: null }, minimum_lookback: 1, maximum_lookback: 10000, default_warmup_sessions: 252, limitations: ['No strategy qualification.'],
    })),
    cost_scenarios: ['base_1x', 'base_2x', 'base_3x', 'adverse'].map((scenario_id, index) => ({ scenario_id, display_name: scenario_id, slippage_bps: ['5', '10', '15', '20'][index] ?? '5', fee_per_share: ['0.01', '0.02', '0.03', '0.02'][index] ?? '0.01', assumptions: ['Assumed, not measured execution costs.'] })),
    launch: { enabled: true, reasons: [] }, cancel: { enabled: true, reasons: [] }, experiments: { enabled: true, reasons: [] }, limitations: [],
  }
}

export function runFixture(overrides: Partial<ResearchRun> = {}): ResearchRun {
  return {
    job_id: 'job-a', run_id: 'semantic-run-a', spec_sha256: digest('c'), dataset_id: 'actual-dataset-id', dataset_manifest_sha256: digest('a'), data_class: 'synthetic_fixture', strategy_id: 'buy_hold', strategy_version: 'reference/1', configuration: { kind: 'buy_hold', lookback: 200, allocation: '0.25', rebalance_sessions: null }, cost_scenario_id: 'base_1x', status: 'queued', cancel_requested: false, requested_at: asOf, updated_at: asOf, progress_completed: null, progress_total: null, progress_unit: null, attempts: [], report_sha256: null, result_sha256: null, reasons: [], limitations: [], ...overrides,
  }
}

export function metricFixture(name = 'total_return', value: string | null = '0.21', reasons: string[] = []): ResearchMetric {
  return {
    name, value, unit: name === 'total_return' ? 'ratio' : 'USD', status: value === null ? 'undefined' : 'defined',
    coverage: { interval_id: 'interval-a', expected_sessions: 5, observed_sessions: 5, valid_sessions: 5, valid_returns: 4, sample_count: 4, input_sha256: digest('a'), contributing_row_ids: ['baseline', 'terminal'], excluded: [], lineage_truncated: false },
    conventions_sha256: digest('b'), reasons, assumptions: ['Event-valued immutable source.'],
  }
}

export function reportFixture(overrides: Partial<ResearchReport> = {}): ResearchReport {
  return {
    job_id: 'job-a', run_id: 'semantic-run-a', report_sha256: digest('d'), result_sha256: digest('e'), artifact_sha256: digest('f'), attempt_id: 'artifact-attempt-2', generated_at: asOf, status: 'completed', currency: 'USD', dataset_id: 'actual-dataset-id', data_class: 'validated_current_vintage_history',
    interval: { interval_id: 'interval-a', fold_id: 'fold-a', scored_start: '2026-07-20', scored_end: '2026-07-24', warmup_start: null, warmup_end: null, expected_sessions: 5, reset_mode: 'independent', baseline_valuation_id: 'baseline', terminal_valuation_id: 'terminal' },
    metrics: [metricFixture(), metricFixture('ending_equity', '1210'), metricFixture('total_execution_costs', '1.12'), metricFixture('sharpe_ratio', null, ['insufficient-annualized-history']), metricFixture('sortino_ratio', null, ['zero-downside-denominator'])],
    benchmark_metrics: [metricFixture('total_return', '0.19')], cash_metrics: [metricFixture('total_return', '0')], benchmark_name: 'Analytical SPY matched-flow comparator', conventions: [{ name: 'returns_model', value: 'event-timed-twr-v1' }], provenance: [{ name: 'dataset_manifest_sha256', value: digest('a') }], assumptions: ['Analytical fractional SPY units; zero benchmark fees.'], limitations: ['Exploratory current-vintage history; insufficient annualized coverage.'], reasons: [], export_url: '/api/v1/research/personal/runs/job-a/artifact', ...overrides,
  }
}

export function equityFixture(sequence = 0, overrides: Partial<ResearchEquityRow> = {}): ResearchEquityRow {
  return {
    kind: 'equity', row_id: `valuation-${sequence}`, sequence, economic_at: asOf, knowledge_at: asOf, session: '2026-09-09', roles: sequence === 0 ? ['baseline'] : ['daily_close'], nav: '1000', wealth: '1', drawdown: '0', signed_flow: '0', flow_id: null, paired_row_id: null, last_known_nav: null, last_known_at: null, benchmark_nav: '1000', benchmark_wealth: '1', cash_nav: '1000', cash_wealth: '1', reasons: [], benchmark_reasons: [], cash_reasons: [], ...overrides,
  }
}

export function rowsFixture(overrides: Partial<ResearchRows> = {}): ResearchRows {
  return { job_id: 'job-a', report_sha256: digest('d'), kind: 'equity', offset: 0, limit: 200, total: 1, rows: [equityFixture()], ...overrides }
}

export function comparisonFixture(): ResearchComparison {
  return {
    comparison_sha256: digest('a'), comparable: false, reasons: ['scored-windows-differ'], differences: [{ name: 'Scored interval', value: 'The server reports different window boundaries.' }],
    runs: ['job-a', 'job-b'].map((job_id, index) => ({ job_id, run_id: `run-${job_id}`, report_sha256: digest(index ? 'b' : 'a'), dataset_id: 'actual-dataset-id', data_class: index ? 'synthetic_fixture' : 'validated_current_vintage_history', strategy_id: 'buy_hold', configuration: runFixture().configuration, cost_scenario_id: index ? 'adverse' : 'base_1x', interval: reportFixture().interval, metrics: [metricFixture('total_return', index ? null : '0.21', index ? ['missing-flow-valuation'] : [])], benchmark_metrics: [metricFixture('total_return', '0.19')], assumptions: ['Assumed execution costs.'], limitations: ['No historical PIT claim.'] })),
  }
}

export function experimentFixture(overrides: Partial<ResearchExperiment> = {}): ResearchExperiment {
  return {
    experiment_id: 'experiment-a', protocol_sha256: digest('a'), requested_at: asOf, updated_at: asOf,
    request: { name: 'Declared study', hypothesis: 'Inspect cost sensitivity without candidate selection.', dataset_id: 'catalog-synthetic', candidates: [{ candidate_id: 'candidate-1', configuration: runFixture().configuration }], folds: [{ fold_id: 'fold-1', train_start: '2024-01-02', train_end: '2024-12-31', validation_start: '2025-01-02', validation_end: '2025-06-30', test_start: '2025-07-01', test_end: '2025-12-31' }], warmup_sessions: 252, prior_access: { status: 'known_accessed', description: 'Owner has previously reviewed this history.' } },
    status: 'queued', evaluation_mode: 'descriptive_only', suitability: 'not_assessed', planned_trial_count: 12, cost_scenarios: catalogFixture().cost_scenarios, trials: [], provenance: [{ name: 'fit_boundary', value: 'Fixed reference configuration; training-scoped inputs.' }], limitations: ['Prior access prevents an untouched-holdout claim.'], reasons: [], export_url: null, ...overrides,
  }
}

export function jsonResponse(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
}

export function requestUrl(input: RequestInfo | URL) {
  return typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
}
