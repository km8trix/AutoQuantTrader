import {
  makeBootstrapFixture,
  makeDashboardFixture,
  makeDataCatalogFixture,
  makeDataQualityFixture,
} from './fixtures'
import type {
  ApiResult,
  DashboardSummary,
  DataCatalogResponse,
  DataQualityResponse,
  ProblemDetails,
  UiBootstrap,
} from './types'

const API_ROOT = '/api/v1'

export class ApiError extends Error {
  readonly status: number
  readonly problem?: ProblemDetails

  constructor(message: string, status = 0, problem?: ProblemDetails) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.problem = problem
  }
}

function developmentFixturesEnabled(): boolean {
  return import.meta.env.DEV && import.meta.env.VITE_USE_DEV_FIXTURES === 'true'
}

async function requestJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(`${API_ROOT}${path}`, {
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json',
    },
    signal,
  })

  if (!response.ok) {
    let problem: ProblemDetails | undefined
    try {
      problem = (await response.json()) as ProblemDetails
    } catch {
      problem = undefined
    }

    throw new ApiError(
      problem?.detail ?? problem?.title ?? `Request failed with status ${response.status}`,
      response.status,
      problem,
    )
  }

  return (await response.json()) as T
}

async function withDevelopmentFallback<T>(
  request: () => Promise<T>,
  fixture: () => T,
): Promise<ApiResult<T>> {
  try {
    return {
      data: await request(),
      source: 'api',
    }
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw error
    }

    if (!developmentFixturesEnabled()) {
      throw error
    }

    return {
      data: fixture(),
      source: 'development-fixture',
    }
  }
}

export function fetchBootstrap(signal?: AbortSignal): Promise<ApiResult<UiBootstrap>> {
  return withDevelopmentFallback(
    () => requestJson<UiBootstrap>('/ui/bootstrap', signal),
    () => makeBootstrapFixture(),
  )
}

export function fetchDashboardSummary(
  signal?: AbortSignal,
): Promise<ApiResult<DashboardSummary>> {
  return withDevelopmentFallback(
    () => requestJson<DashboardSummary>('/dashboard/summary', signal),
    () => makeDashboardFixture(),
  )
}

export function fetchDataCatalog(signal?: AbortSignal): Promise<ApiResult<DataCatalogResponse>> {
  return withDevelopmentFallback(
    () => requestJson<DataCatalogResponse>('/data/catalog', signal),
    () => makeDataCatalogFixture(),
  )
}

export function fetchDataQuality(signal?: AbortSignal): Promise<ApiResult<DataQualityResponse>> {
  return withDevelopmentFallback(
    () => requestJson<DataQualityResponse>('/data/quality', signal),
    () => makeDataQualityFixture(),
  )
}
