import type {
  BacktestReportResponse,
  BacktestsResponse,
  ExperimentAttemptStatus,
  ExperimentHoldoutState,
  ExperimentListResponse,
  ExperimentResponse,
  ExperimentSummaryView,
  ResearchStrategiesResponse,
} from './types'

const digest = (character: string): string => character.repeat(64)
export const DEVELOPMENT_EXPERIMENT_FAMILY_ID = digest('a')

export function makeResearchStrategiesFixture(
  now = new Date(),
): ResearchStrategiesResponse {
  return {
    as_of: now.toISOString(),
    strategies: [
      {
        strategy_version_id: digest('1'),
        strategy_id: 'buy-and-hold-fixture',
        strategy_version: '1.0.0',
        display_name: 'Buy and hold fixture',
        parameter_schema: {
          type: 'object',
          additionalProperties: false,
          properties: { quantity: { type: 'integer', minimum: 1 } },
        },
        configurations: [
          {
            configuration_sha256: digest('4'),
            configuration_name: 'Four-share golden path',
            parameters: { quantity: 4 },
            launch_inputs: [
              {
                fixture_id: 'phase2-golden-lifecycle',
                fixture_version: '1.0.0',
                display_name: 'Golden lifecycle fixture',
                description: 'Raw prices, next-event fills, fees, dividend, split, and settlement.',
                dataset_manifest_id: digest('5'),
                dataset_manifest_sha256: digest('5'),
                replay_run_id: digest('6'),
                benchmark_sha256: digest('7'),
                cost_model_sha256: digest('8'),
                fill_model_sha256: digest('9'),
                metric_conventions_sha256: digest('a'),
              },
            ],
          },
        ],
      },
    ],
    fixtures: [
      {
        fixture_id: 'phase2-golden-lifecycle',
        fixture_version: '1.0.0',
        display_name: 'Golden lifecycle fixture',
        description: 'Raw prices, next-event fills, fees, dividend, split, and settlement.',
        dataset_manifest_id: digest('5'),
        dataset_manifest_sha256: digest('5'),
        replay_run_id: digest('6'),
        benchmark_sha256: digest('7'),
        cost_model_sha256: digest('8'),
        fill_model_sha256: digest('9'),
        metric_conventions_sha256: digest('a'),
      },
    ],
  }
}

export function makeBacktestsFixture(now = new Date()): BacktestsResponse {
  const requestedAt = new Date(now.getTime() - 12_000).toISOString()
  const runningAt = new Date(now.getTime() - 8_000).toISOString()
  return {
    as_of: now.toISOString(),
    jobs: [
      {
        job_id: digest('b'),
        input_sha256: digest('c'),
        fixture_id: 'phase2-golden-lifecycle',
        fixture_version: '1.0.0',
        strategy_id: 'buy-and-hold-fixture',
        strategy_version: '1.0.0',
        strategy_configuration_sha256: digest('4'),
        requested_by: 'local-operator',
        requested_at: requestedAt,
        status: 'completed',
        attempt_number: 1,
        worker_id: null,
        claim_expires_at: null,
        updated_at: now.toISOString(),
        run_manifest_sha256: digest('d'),
        report_sha256: digest('e'),
        report_artifact_sha256: digest('f'),
        terminal_reason_code: null,
        history: [
          {
            sequence: 0,
            status: 'queued',
            occurred_at: requestedAt,
            actor_id: 'local-operator',
            attempt_number: 0,
            terminal_reason_code: null,
          },
          {
            sequence: 1,
            status: 'running',
            occurred_at: runningAt,
            actor_id: 'fixture-worker',
            attempt_number: 1,
            terminal_reason_code: null,
          },
          {
            sequence: 2,
            status: 'completed',
            occurred_at: now.toISOString(),
            actor_id: 'fixture-worker',
            attempt_number: 1,
            terminal_reason_code: null,
          },
        ],
      },
    ],
  }
}

export function makeBacktestReportFixture(now = new Date()): BacktestReportResponse {
  const start = new Date(now.getTime() - 86_400_000)
  const middle = new Date(now.getTime() - 43_200_000)
  return {
    report_sha256: digest('e'),
    report_artifact_sha256: digest('f'),
    account_id: 'fixture-backtest-account',
    currency: 'USD',
    period_start: start.toISOString(),
    period_end: now.toISOString(),
    generated_at: now.toISOString(),
    conventions: {
      convention_id: 'phase2-event-return',
      convention_version: '1.0.0',
      currency: 'USD',
      return_type: 'simple',
      return_frequency: 'event',
      annualization_periods: 252,
      annual_risk_free_rate: '0',
      risk_free_rate_version: 'fixture-zero-v1',
      external_cash_flow_treatment: 'time_weighted',
      uncertainty_method: 'none',
      absolute_tolerance: '0.00000001',
      relative_tolerance: '0.00000001',
    },
    metrics: {
      starting_equity: '1000.00',
      ending_equity: '1044.04',
      total_return: '0.04404',
      annualized_return: null,
      annualized_volatility: null,
      sharpe_ratio: null,
      sortino_ratio: null,
      maximum_drawdown: '0.00318',
      turnover: '0.84368',
      average_gross_exposure: '0.278',
      average_net_exposure: '0.278',
      trade_count: 1,
      winning_trade_count: 1,
      losing_trade_count: 0,
      breakeven_trade_count: 0,
      hit_rate: '1',
      profit_factor: null,
      total_execution_costs: '1.12',
      capacity_proxy: null,
      realized_pnl: '34.04',
      unrealized_pnl: '0',
      dividend_income: '10.00',
    },
    equity_curve: [
      {
        sequence: 0,
        as_of: start.toISOString(),
        cash: '1000.00',
        market_value: '0',
        equity: '1000.00',
        gross_exposure: '0',
        net_exposure: '0',
        cumulative_external_cash_flow: '0',
        period_return: '0',
        cumulative_return: '0',
        drawdown: '0',
      },
      {
        sequence: 1,
        as_of: middle.toISOString(),
        cash: '605.18',
        market_value: '416.00',
        equity: '1021.18',
        gross_exposure: '416.00',
        net_exposure: '416.00',
        cumulative_external_cash_flow: '0',
        period_return: '0.02118',
        cumulative_return: '0.02118',
        drawdown: '0',
      },
      {
        sequence: 2,
        as_of: now.toISOString(),
        cash: '1044.04',
        market_value: '0',
        equity: '1044.04',
        gross_exposure: '0',
        net_exposure: '0',
        cumulative_external_cash_flow: '0',
        period_return: '0.02239',
        cumulative_return: '0.04404',
        drawdown: '0',
      },
    ],
    trades: [
      {
        sequence: 0,
        trade_id: 'golden-trade-001',
        instrument_id: 'US-ETF-SPY',
        symbol: 'SPY',
        opened_at: start.toISOString(),
        closed_at: now.toISOString(),
        quantity: '4',
        cost_basis: '404.28',
        proceeds: '439.44',
        gross_pnl: '35.16',
        execution_costs: '1.12',
        net_pnl: '34.04',
        opening_execution_sha256: digest('1'),
        closing_execution_sha256: digest('2'),
      },
    ],
    positions: [
      {
        sequence: 0,
        as_of: middle.toISOString(),
        instrument_id: 'US-ETF-SPY',
        symbol: 'SPY',
        quantity: '8',
        cost_basis: '404.82',
        mark_price: '52.00',
        market_value: '416.00',
        realized_pnl: '0',
        unrealized_pnl: '11.18',
        execution_costs: '0.54',
        dividend_income: '10.00',
        source_projection_sha256: digest('3'),
      },
    ],
    ledger_trace: [
      {
        sequence: 0,
        entry_id: 'ledger-buy-001',
        entry_kind: 'fill',
        source_fact_id: 'fill-buy-001',
        effective_at: start.toISOString(),
        recorded_at: start.toISOString(),
        entry_sha256: digest('4'),
      },
    ],
    provenance: {
      execution_ledger_sha256: digest('5'),
      corporate_action_ledger_sha256: digest('6'),
      settlement_ledger_sha256: digest('7'),
      account_projection_sha256: digest('8'),
      accounting_evidence_sha256: digest('9'),
    },
  }
}

const experimentStatuses: ExperimentAttemptStatus[] = [
  'queued',
  'running',
  'completed',
  'failed',
  'canceled',
  'abandoned',
]

function experimentSummary(
  now: Date,
  holdoutState: ExperimentHoldoutState,
): ExperimentSummaryView {
  return {
    family_id: DEVELOPMENT_EXPERIMENT_FAMILY_ID,
    family_name: 'Synthetic rolling-close-mean stability study',
    hypothesis:
      'A pinned rolling-close-mean target configuration preserves parity across declared train and validation segments before one authorized holdout reveal.',
    owner_id: 'fixture-research-owner',
    created_at: new Date(now.getTime() - 14 * 86_400_000).toISOString(),
    strategy_id: 'rolling-close-mean-cross',
    strategy_version: '1.0.0',
    strategy_version_sha256: digest('b'),
    evaluation_plan_version: 'phase3d-reference-plan-v1',
    evaluation_plan_sha256: digest('c'),
    promotion_criteria_sha256: digest('d'),
    test_commitment_sha256: digest('e'),
    maximum_pre_holdout_trials: 8,
    pre_holdout_attempt_count: 6,
    remaining_pre_holdout_attempts: holdoutState === 'sealed' ? 2 : 0,
    attempt_count: holdoutState === 'sealed' ? 6 : 7,
    holdout_state: holdoutState,
    snapshot_sha256:
      holdoutState === 'sealed' ? digest('f') : 'ab'.repeat(32),
    registry_head_sha256:
      holdoutState === 'sealed' ? digest('0') : digest('8'),
  }
}

export function makeExperimentsFixture(
  now = new Date(),
  holdoutState: ExperimentHoldoutState = 'sealed',
): ExperimentListResponse {
  return {
    as_of: now.toISOString(),
    experiments: [experimentSummary(now, holdoutState)],
  }
}

export function makeExperimentFixture(
  now = new Date(),
  holdoutState: ExperimentHoldoutState = 'sealed',
): ExperimentResponse {
  const timestamp = (minutesAgo: number) =>
    new Date(now.getTime() - minutesAgo * 60_000).toISOString()
  let globalSequenceNumber = 0
  const latestStatuses =
    holdoutState === 'sealed'
      ? experimentStatuses
      : ([
          'canceled',
          'abandoned',
          'completed',
          'failed',
          'canceled',
          'abandoned',
          'completed',
        ] satisfies ExperimentAttemptStatus[])

  const attempts = latestStatuses.map((status, index) => {
    const isTestAttempt = holdoutState === 'revealed' && index === 6
    if (isTestAttempt) {
      globalSequenceNumber += 1
    }
    const queuedAt = isTestAttempt ? timestamp(4) : timestamp(180 - index * 20)
    const configurationSha256 = isTestAttempt
      ? digest('4')
      : digest(((index + 2) % 10).toString())
    const configurationValidationSha256 = isTestAttempt
      ? digest('5')
      : digest(((index + 3) % 10).toString())
    const attemptId = digest((index + 1).toString())
    const segmentKind = isTestAttempt
      ? ('test' as const)
      : index < 2
        ? ('train' as const)
        : ('validation' as const)
    const segmentSha256 =
      segmentKind === 'train'
        ? digest('1')
        : segmentKind === 'validation'
          ? digest('2')
          : digest('3')
    const holdoutRevealSha256 = isTestAttempt ? digest('8') : null
    const lifecycle: ExperimentAttemptStatus[] =
      status === 'queued'
        ? ['queued']
        : status === 'running'
          ? ['queued', 'running']
          : status === 'canceled'
            ? ['queued', 'canceled']
            : ['queued', 'running', status]
    const history = lifecycle.map((eventStatus, eventIndex) => {
      const occurredAt = new Date(
        new Date(queuedAt).getTime() + eventIndex * 60_000,
      ).toISOString()
      const terminalEvidenceSha256 = ['completed', 'failed', 'canceled', 'abandoned'].includes(
        eventStatus,
      )
        ? digest(((index + eventIndex + 3) % 10).toString())
        : null

      return {
        event_sha256: digest(((index + eventIndex + 1) % 10).toString()),
        global_sequence_number: globalSequenceNumber++,
        attempt_sequence_number: eventIndex,
        status: eventStatus,
        occurred_at: occurredAt,
        actor_id: eventIndex === 0 ? 'fixture-research-owner' : 'fixture-research-worker',
        terminal_evidence_sha256: terminalEvidenceSha256,
        terminal_reason_code:
          eventStatus === 'failed'
            ? 'synthetic_worker_failure'
            : eventStatus === 'canceled'
              ? 'synthetic_operator_cancel'
              : eventStatus === 'abandoned'
                ? 'synthetic_lease_expired'
                : null,
        evaluation:
          eventStatus === 'completed' && terminalEvidenceSha256
            ? {
                evidence_kind: 'governed_segment_evaluation',
                family_id: DEVELOPMENT_EXPERIMENT_FAMILY_ID,
                attempt_id: attemptId,
                receipt_sha256: terminalEvidenceSha256,
                strategy_version_sha256: digest('b'),
                configuration_sha256: configurationSha256,
                configuration_validation_sha256: configurationValidationSha256,
                segment_kind: segmentKind,
                segment_sha256: segmentSha256,
                source_evidence_sha256: digest('4'),
                holdout_reveal_sha256: holdoutRevealSha256,
                feature_certification_sha256: digest('5'),
                target_policy_sha256: digest('6'),
                target_runtime_pin_sha256: digest('7'),
                target_certification_sha256: digest('8'),
                batch_result_sha256: digest('9'),
                incremental_result_sha256: digest('0'),
                target_parity_receipt_sha256: digest('a'),
                target_transcript_sha256: digest('b'),
                step_count: 48,
                target_count: 31,
                running_event_sha256: digest(((index + 2) % 10).toString()),
                started_at: new Date(new Date(queuedAt).getTime() + 60_000).toISOString(),
                completed_at: occurredAt,
                evaluated_by: 'fixture-research-worker',
              }
            : null,
      }
    })

    return {
      attempt_id: attemptId,
      attempt_number: index + 1,
      configuration_sha256: configurationSha256,
      configuration_name: `Synthetic candidate ${index + 1}`,
      configuration_validation_sha256: configurationValidationSha256,
      segment_kind: segmentKind,
      segment_sha256: segmentSha256,
      requested_at: queuedAt,
      requested_by: 'fixture-research-owner',
      holdout_reveal_sha256: holdoutRevealSha256,
      status,
      history,
    }
  })

  return {
    as_of: now.toISOString(),
    experiment: {
      summary: experimentSummary(now, holdoutState),
      segments: [
        {
          kind: 'train',
          segment_sha256: digest('1'),
          coverage_start: '2022-01-03T00:00:00.000Z',
          coverage_end: '2023-06-30T23:59:59.000Z',
          dataset_replay_sha256: digest('4'),
          purge_before: 'P7D',
          embargo_after: 'P3D',
        },
        {
          kind: 'validation',
          segment_sha256: digest('2'),
          coverage_start: '2023-07-10T00:00:00.000Z',
          coverage_end: '2024-06-28T23:59:59.000Z',
          dataset_replay_sha256: digest('5'),
          purge_before: 'P7D',
          embargo_after: 'P3D',
        },
        {
          kind: 'test',
          segment_sha256: holdoutState === 'revealed' ? digest('3') : null,
          coverage_start: '2024-07-08T00:00:00.000Z',
          coverage_end: '2025-06-30T23:59:59.000Z',
          dataset_replay_sha256: holdoutState === 'revealed' ? digest('6') : null,
          purge_before: 'P7D',
          embargo_after: 'P3D',
        },
      ],
      promotion_criteria: {
        criteria_sha256: digest('d'),
        criteria_version: 'phase3c-promotion-v1',
        criteria: [
          {
            metric_name: 'annualized_sharpe_ratio',
            comparison: 'greater_than_or_equal',
            threshold: '1.25',
            minimum_observations: 252,
          },
          {
            metric_name: 'maximum_drawdown',
            comparison: 'less_than_or_equal',
            threshold: '0.15',
            minimum_observations: 252,
          },
        ],
        selection_rule: 'Select the highest validation Sharpe ratio among passing candidates.',
        multiple_testing_method: 'Bonferroni correction across the frozen attempt budget.',
        maximum_pre_holdout_trials: 8,
        frozen_at: new Date(now.getTime() - 14 * 86_400_000).toISOString(),
        frozen_by: 'fixture-research-owner',
      },
      attempts,
      holdout:
        holdoutState === 'sealed'
          ? {
              state: 'sealed',
              commitment_sha256: digest('e'),
              authorization_sha256: null,
              reveal_sha256: null,
              selected_configuration_sha256: null,
              pre_reveal_snapshot_sha256: null,
              pre_reveal_registry_head_sha256: null,
              pre_reveal_attempts_sha256: null,
              pre_reveal_attempt_count: null,
              revealed_at: null,
              revealed_by: null,
              access_reason: null,
            }
          : {
              state: 'revealed',
              commitment_sha256: digest('e'),
              authorization_sha256: digest('7'),
              reveal_sha256: digest('8'),
              selected_configuration_sha256: digest('4'),
              pre_reveal_snapshot_sha256: digest('f'),
              pre_reveal_registry_head_sha256: digest('0'),
              pre_reveal_attempts_sha256: digest('9'),
              pre_reveal_attempt_count: 6,
              revealed_at: timestamp(5),
              revealed_by: 'fixture-governance-reviewer',
              access_reason: 'Synthetic governance drill completed after frozen selection.',
            },
    },
  }
}
