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
