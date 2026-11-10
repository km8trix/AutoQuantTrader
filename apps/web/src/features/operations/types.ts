export type FreshnessStatus = 'current' | 'stale' | 'unavailable'
export type CoordinatorStatus = 'active' | 'expired' | 'unavailable'
export type ReconciliationStatus = 'clean' | 'differences' | 'unavailable'
export type AlertDeliveryStatus = 'delivered' | 'pending' | 'failed' | 'unknown'

export interface OperationalFreshness {
  source_id: string
  label: string
  status: FreshnessStatus
  observed_at: string | null
  maximum_age_seconds: number
  detail: string
}

export interface CoordinatorOwnership {
  status: CoordinatorStatus
  owner_id: string | null
  lease_id: string | null
  fencing_generation: number | null
  heartbeat_at: string | null
  expires_at: string | null
  detail: string
}

export interface StrategyDeployment {
  deployment_id: string
  strategy_id: string
  strategy_version: string
  strategy_configuration_sha256: string
  state: string
  mode: string
  updated_at: string
}

export interface OperationalAccount {
  currency: string
  equity: string
  cash: string
  realized_pnl: string
  unrealized_pnl: string
  gross_exposure: string
  net_exposure: string
}

export interface OperationalOrder {
  order_id: string
  client_order_id: string
  intent_id: string
  risk_decision_id: string
  symbol: string
  side: string
  quantity: string
  filled_quantity: string
  status: string
  submitted_at: string
}

export interface OperationalFill {
  fill_id: string
  order_id: string
  symbol: string
  side: string
  quantity: string
  price: string
  fee: string
  executed_at: string
}

export interface OperationalPosition {
  instrument_id: string
  symbol: string
  quantity: string
  average_cost: string
  market_price: string
  market_value: string
}

export interface LedgerIntegrity {
  status: 'balanced' | 'unavailable'
  entry_count: number
  latest_entry_id: string | null
  latest_posted_at: string | null
  detail: string
}

export interface RiskRuleObservation {
  rule: string
  passed: boolean
  observed: string
  limit: string
}

export interface RiskReservation {
  decision_id: string
  intent_id: string
  amount: string
  currency: string
  state: string
  expires_at: string
}

export interface OperationalRiskDecision {
  decision_id: string
  policy_version: string
  status: string
  evaluated_at: string
  expires_at: string
  rules: RiskRuleObservation[]
}

export interface ReconciliationDifference {
  field: string
  local_value: string
  broker_value: string
  disposition: string
}

export interface OperationalReconciliation {
  status: ReconciliationStatus
  observed_at: string | null
  differences: ReconciliationDifference[]
  detail: string
}

export interface OperationalAlert {
  incident_id: string
  severity: string
  category: string
  opened_at: string
  summary: string
  delivery_status: AlertDeliveryStatus
  escalation_due_at: string | null
}

export interface OperationalControlReceipt {
  transition_id: string
  sequence_number: number
  state: string
  command_kind: string
  actor_id: string
  decided_at: string
}

export interface OperationalControl {
  state: string
  transition_id: string | null
  sequence_number: number | null
  blocking_event_count: number
  pending_operation: string | null
  actions_available: false
  history: OperationalControlReceipt[]
  detail: string
}

export interface OperationsDashboardSnapshot {
  schema_version: 'phase5-operations-dashboard-v1'
  as_of: string
  read_only: true
  coordinator: CoordinatorOwnership
  deployment: StrategyDeployment
  freshness: OperationalFreshness[]
  account: OperationalAccount
  orders: OperationalOrder[]
  fills: OperationalFill[]
  positions: OperationalPosition[]
  ledger: LedgerIntegrity
  reservations: RiskReservation[]
  risk_decisions: OperationalRiskDecision[]
  reconciliation: OperationalReconciliation
  alerts: OperationalAlert[]
  control: OperationalControl
}
