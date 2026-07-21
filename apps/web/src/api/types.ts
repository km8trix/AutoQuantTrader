import type { components, paths } from './schema.generated'

type ApiSchemas = components['schemas']

export type EnvironmentMode = ApiSchemas['EnvironmentMode']
export type MarketStatus = ApiSchemas['MarketStatus']
export type ReadinessStatus = ApiSchemas['ReadinessStatus']
export type HealthStatus = ApiSchemas['HealthStatus']
export type DeploymentState = ApiSchemas['DeploymentState']
export type UserIdentity = ApiSchemas['UserIdentity']
export type EnvironmentIdentity = ApiSchemas['EnvironmentIdentity']
export type MarketClock = ApiSchemas['MarketClock']
export type Readiness = ApiSchemas['Readiness']
export type AccountSummary = ApiSchemas['AccountSummary']
export type DeploymentSummary = ApiSchemas['DeploymentSummary']
export type HealthCheck = ApiSchemas['HealthCheck']
export type TraceStatus = ApiSchemas['TraceStatus']
export type WalkingThreadStep = ApiSchemas['TraceStepView']
export type WalkingThreadTrace = ApiSchemas['WalkingThreadTrace']

export type UiBootstrap =
  paths['/api/v1/ui/bootstrap']['get']['responses']['200']['content']['application/json']

export type DashboardSummary =
  paths['/api/v1/dashboard/summary']['get']['responses']['200']['content']['application/json']

export type DataCatalogResponse = ApiSchemas['DataCatalogResponse']
export type DataQualityResponse = ApiSchemas['DataQualityResponse']

export interface UiEvent {
  id: string
  occurred_at: string
  type: string
  resource_type: string
  resource_id: string
  resource_version: number | string
}

export interface UiHeartbeat {
  occurred_at: string
}

export type EventStreamStatus =
  | 'disabled'
  | 'connecting'
  | 'connected'
  | 'stale'
  | 'disconnected'

export interface EventStreamState {
  status: EventStreamStatus
  cursor: string | null
  last_activity_at: string | null
  reconnect_attempt: number
  detail: string
}

export type ApiSource = 'api' | 'development-fixture'

export interface ApiResult<T> {
  data: T
  source: ApiSource
}

export interface ProblemDetails {
  type?: string
  title?: string
  status?: number
  detail?: string
  instance?: string
}

export interface ResearchStrategyConfiguration {
  configuration_sha256: string
  configuration_name: string
  parameters: Record<string, boolean | number | string>
  launch_inputs: ResearchFixture[]
}

export interface ResearchStrategy {
  strategy_version_id: string
  strategy_id: string
  strategy_version: string
  display_name: string
  parameter_schema: Record<string, unknown>
  configurations: ResearchStrategyConfiguration[]
}

export interface ResearchFixture {
  fixture_id: string
  fixture_version: string
  display_name: string
  description: string
  dataset_manifest_id: string
  dataset_manifest_sha256: string
  replay_run_id: string
  benchmark_sha256: string
  cost_model_sha256: string
  fill_model_sha256: string
  metric_conventions_sha256: string
}

export interface ResearchStrategiesResponse {
  as_of: string
  strategies: ResearchStrategy[]
  fixtures?: ResearchFixture[]
}

export type ResearchStrategyCatalogRecord = ApiSchemas['StrategyCatalogView']
export type ResearchStrategyCatalogResponse = ApiSchemas['StrategyCatalogResponse']
export type BacktestJobStatus = ApiSchemas['BacktestJobStatus']
export type BacktestJobEvent = ApiSchemas['BacktestJobEventView']
export type BacktestJob = ApiSchemas['BacktestJobView']
export type BacktestsResponse = ApiSchemas['BacktestJobListResponse']
export type BacktestLaunchRequest = ApiSchemas['BacktestLaunchRequest']

export interface ResearchMutationCredentials {
  idempotencyKey: string
  csrfToken: string
}

export type BacktestMetricConventions = ApiSchemas['BacktestMetricConventionsView']
export type BacktestMetrics = ApiSchemas['BacktestMetricsView']
export type BacktestEquityPoint = ApiSchemas['BacktestEquityPointView']
export type BacktestTrade = ApiSchemas['BacktestTradeView']
export type BacktestPosition = ApiSchemas['BacktestPositionView']
export type BacktestLedgerTraceEntry = ApiSchemas['BacktestLedgerTraceView']
export type BacktestProvenance = ApiSchemas['BacktestReportProvenanceView']
export type BacktestReportResponse = ApiSchemas['BacktestReportView']
