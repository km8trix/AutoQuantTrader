import type { OperationsDashboardSnapshot } from './types'

const before = (now: Date, milliseconds: number): string =>
  new Date(now.getTime() - milliseconds).toISOString()

const after = (now: Date, milliseconds: number): string =>
  new Date(now.getTime() + milliseconds).toISOString()

const digest = (character: string): string => character.repeat(64)

export function makeOperationsDashboardFixture(
  now = new Date(),
): OperationsDashboardSnapshot {
  return {
    schema_version: 'phase5-operations-dashboard-v1',
    as_of: before(now, 900),
    read_only: true,
    coordinator: {
      status: 'active',
      owner_id: 'paper-trader-a',
      lease_id: 'lease-paper-0042',
      fencing_generation: 42,
      heartbeat_at: before(now, 700),
      expires_at: after(now, 4_300),
      detail: 'One authenticated coordinator lease owns paper-account-001.',
    },
    deployment: {
      deployment_id: 'paper-moderate-etf-rth-v1',
      strategy_id: 'equal-weight-rth',
      strategy_version: '1.4.2',
      strategy_configuration_sha256: digest('a'),
      state: 'paused',
      mode: 'paper',
      updated_at: before(now, 18_000),
    },
    freshness: [
      {
        source_id: 'market-data',
        label: 'SIP quotes',
        status: 'current',
        observed_at: before(now, 1_100),
        maximum_age_seconds: 5,
        detail: 'DIA, IWM, QQQ, and SPY quotes are inside the five-second budget.',
      },
      {
        source_id: 'risk',
        label: 'Advanced risk',
        status: 'current',
        observed_at: before(now, 900),
        maximum_age_seconds: 15,
        detail: 'The complete moderate-policy assessment is current.',
      },
      {
        source_id: 'ledger',
        label: 'Account ledger',
        status: 'current',
        observed_at: before(now, 1_300),
        maximum_age_seconds: 15,
        detail: 'The latest balanced ledger projection is current.',
      },
      {
        source_id: 'reconciliation',
        label: 'Broker reconciliation',
        status: 'current',
        observed_at: before(now, 8_000),
        maximum_age_seconds: 120,
        detail: 'The broker comparison is current and retains one blocked difference.',
      },
    ],
    account: {
      currency: 'USD',
      equity: '100248.32',
      cash: '75624.08',
      realized_pnl: '128.40',
      unrealized_pnl: '119.92',
      gross_exposure: '24624.24',
      net_exposure: '24624.24',
    },
    orders: [
      {
        order_id: 'order-spy-0048',
        client_order_id: 'aqt-paper-spy-0048',
        intent_id: 'intent-spy-0048',
        risk_decision_id: 'decision-spy-0048',
        symbol: 'SPY',
        side: 'buy',
        quantity: '10',
        filled_quantity: '10',
        status: 'filled',
        submitted_at: before(now, 90_000),
      },
      {
        order_id: 'order-qqq-0049',
        client_order_id: 'aqt-paper-qqq-0049',
        intent_id: 'intent-qqq-0049',
        risk_decision_id: 'decision-qqq-0049',
        symbol: 'QQQ',
        side: 'buy',
        quantity: '4',
        filled_quantity: '0',
        status: 'working',
        submitted_at: before(now, 22_000),
      },
    ],
    fills: [
      {
        fill_id: 'fill-spy-0048-01',
        order_id: 'order-spy-0048',
        symbol: 'SPY',
        side: 'buy',
        quantity: '10',
        price: '639.31',
        fee: '0',
        executed_at: before(now, 85_000),
      },
    ],
    positions: [
      {
        instrument_id: 'US-ETF-DIA',
        symbol: 'DIA',
        quantity: '12',
        average_cost: '456.10',
        market_price: '458.24',
        market_value: '5498.88',
      },
      {
        instrument_id: 'US-ETF-IWM',
        symbol: 'IWM',
        quantity: '26',
        average_cost: '224.18',
        market_price: '226.42',
        market_value: '5886.92',
      },
      {
        instrument_id: 'US-ETF-QQQ',
        symbol: 'QQQ',
        quantity: '12',
        average_cost: '565.40',
        market_price: '568.22',
        market_value: '6818.64',
      },
      {
        instrument_id: 'US-ETF-SPY',
        symbol: 'SPY',
        quantity: '10',
        average_cost: '639.31',
        market_price: '641.98',
        market_value: '6419.80',
      },
    ],
    ledger: {
      status: 'balanced',
      entry_count: 187,
      latest_entry_id: 'ledger-fill-spy-0048-01',
      latest_posted_at: before(now, 84_500),
      detail: 'All cash and security postings balance exactly.',
    },
    reservations: [
      {
        decision_id: 'decision-qqq-0049',
        intent_id: 'intent-qqq-0049',
        amount: '2278.88',
        currency: 'USD',
        state: 'active',
        expires_at: after(now, 8_000),
      },
    ],
    risk_decisions: [
      {
        decision_id: 'decision-qqq-0049',
        policy_version: 'phase5b-moderate-paper-rth-etf-v1',
        status: 'approved',
        evaluated_at: before(now, 23_000),
        expires_at: after(now, 8_000),
        rules: [
          {
            rule: 'concentration',
            passed: true,
            observed: '8.82%',
            limit: '35%',
          },
          {
            rule: 'gross_leverage',
            passed: true,
            observed: '0.27',
            limit: '1.00',
          },
          {
            rule: 'spread',
            passed: true,
            observed: '3.2 bps',
            limit: '20 bps',
          },
          {
            rule: 'reject_rate',
            passed: true,
            observed: '0 of 18',
            limit: '10%',
          },
        ],
      },
    ],
    reconciliation: {
      status: 'differences',
      observed_at: before(now, 8_000),
      differences: [
        {
          field: 'open_order:QQQ',
          local_value: 'working / 4 shares',
          broker_value: 'pending_new / 4 shares',
          disposition: 'blocked_pending_convergence',
        },
      ],
      detail: 'New exposure remains blocked until the order views converge.',
    },
    alerts: [
      {
        incident_id: 'incident-reconciliation-0049',
        severity: 'critical',
        category: 'reconciliation_difference',
        opened_at: before(now, 7_500),
        summary: 'The QQQ working-order state has not converged with the broker snapshot.',
        delivery_status: 'delivered',
        escalation_due_at: null,
      },
    ],
    control: {
      state: 'paused',
      transition_id: 'control-transition-0188',
      sequence_number: 188,
      blocking_event_count: 1,
      pending_operation: null,
      actions_available: false,
      history: [
        {
          transition_id: 'control-transition-0187',
          sequence_number: 187,
          state: 'running',
          command_kind: 'rearm',
          actor_id: 'local-operator',
          decided_at: before(now, 3_600_000),
        },
        {
          transition_id: 'control-transition-0188',
          sequence_number: 188,
          state: 'paused',
          command_kind: 'trip',
          actor_id: 'reconciliation-supervisor',
          decided_at: before(now, 7_700),
        },
      ],
      detail: 'A reconciliation breaker trip blocks new entries. Rearm is API-gated.',
    },
  }
}
