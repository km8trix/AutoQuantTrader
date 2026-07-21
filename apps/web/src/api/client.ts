import {
  makeBootstrapFixture,
  makeDashboardFixture,
  makeDataCatalogFixture,
  makeDataQualityFixture,
} from './fixtures'
import {
  makeBacktestReportFixture,
  makeBacktestsFixture,
  makeResearchStrategiesFixture,
} from './researchFixtures'
import type {
  ApiResult,
  BacktestJob,
  BacktestLaunchRequest,
  BacktestReportResponse,
  BacktestsResponse,
  DashboardSummary,
  DataCatalogResponse,
  DataQualityResponse,
  ProblemDetails,
  ResearchMutationCredentials,
  ResearchStrategiesResponse,
  ResearchStrategyCatalogResponse,
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

interface RequestJsonOptions {
  signal?: AbortSignal
  method?: 'GET' | 'POST'
  headers?: Record<string, string>
  body?: unknown
}

async function requestJson<T>(path: string, options: RequestJsonOptions = {}): Promise<T> {
  const { body, headers = {}, method = 'GET', signal } = options
  const response = await fetch(`${API_ROOT}${path}`, {
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json',
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    method,
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isUnknownArray(value: unknown): value is unknown[] {
  return Array.isArray(value)
}

function parseObjectPayload(payload: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(payload)
    return isRecord(parsed) ? parsed : { value: parsed }
  } catch {
    return { payload }
  }
}

function parseParameterPayload(
  payload: string,
): Record<string, boolean | number | string> {
  try {
    const parsed: unknown = JSON.parse(payload)
    const entries =
      isRecord(parsed) && parsed.type === 'tuple' && isUnknownArray(parsed.value)
        ? parsed.value
        : parsed
    if (!isUnknownArray(entries)) return {}
    const parameters: Record<string, boolean | number | string> = {}
    for (const item of entries) {
      const pair =
        isRecord(item) && item.type === 'tuple' && isUnknownArray(item.value)
          ? item.value
          : item
      if (!isUnknownArray(pair) || pair.length !== 2) continue
      const rawKey = pair[0]
      const rawValue = pair[1]
      const key =
        isRecord(rawKey) && rawKey.type === 'string' && typeof rawKey.value === 'string'
          ? rawKey.value
          : typeof rawKey === 'string'
            ? rawKey
            : null
      let value: boolean | number | string | null = null
      if (isRecord(rawValue) && typeof rawValue.type === 'string') {
        if (rawValue.type === 'bool' && typeof rawValue.value === 'boolean') {
          value = rawValue.value
        } else if (rawValue.type === 'int' && typeof rawValue.value === 'string') {
          const integer = Number(rawValue.value)
          value = Number.isSafeInteger(integer) ? integer : rawValue.value
        } else if (
          (rawValue.type === 'decimal' || rawValue.type === 'string') &&
          typeof rawValue.value === 'string'
        ) {
          value = rawValue.value
        }
      } else if (['boolean', 'number', 'string'].includes(typeof rawValue)) {
        value = rawValue as boolean | number | string
      }
      if (key !== null && value !== null) parameters[key] = value
    }
    return parameters
  } catch {
    return {}
  }
}

function normalizeResearchStrategies(
  response: ResearchStrategyCatalogResponse,
): ResearchStrategiesResponse {
  const strategies = new Map<string, ResearchStrategiesResponse['strategies'][number]>()
  const fixtures = new Map<string, NonNullable<ResearchStrategiesResponse['fixtures']>[number]>()

  for (const record of response.strategies) {
    const fixtureKey = `${record.fixture_id}:${record.fixture_version}:${record.dataset_manifest_sha256}`
    const launchInput = {
      fixture_id: record.fixture_id,
      fixture_version: record.fixture_version,
      display_name: record.fixture_id.replaceAll('-', ' '),
      description: 'Repository-owned synthetic fixture with immutable replay and model pins.',
      dataset_manifest_id: record.dataset_manifest_sha256,
      dataset_manifest_sha256: record.dataset_manifest_sha256,
      replay_run_id: record.replay_run_id,
      benchmark_sha256: record.benchmark_sha256,
      cost_model_sha256: record.cost_model_sha256,
      fill_model_sha256: record.fill_model_sha256,
      metric_conventions_sha256: record.metric_conventions_sha256,
    }
    const strategy = strategies.get(record.strategy_version_id) ?? {
      strategy_version_id: record.strategy_version_id,
      strategy_id: record.strategy_id,
      strategy_version: record.strategy_version,
      display_name: record.display_name,
      parameter_schema: parseObjectPayload(record.parameter_schema_payload),
      configurations: [],
    }
    const configuration = strategy.configurations.find(
      (candidate) => candidate.configuration_sha256 === record.configuration_sha256,
    )
    if (configuration) {
      if (
        !configuration.launch_inputs.some(
          (candidate) =>
            `${candidate.fixture_id}:${candidate.fixture_version}:${candidate.dataset_manifest_sha256}` ===
            fixtureKey,
        )
      ) {
        configuration.launch_inputs.push(launchInput)
      }
    } else {
      strategy.configurations.push({
        configuration_sha256: record.configuration_sha256,
        configuration_name: record.configuration_name,
        parameters: parseParameterPayload(record.parameters_payload),
        launch_inputs: [launchInput],
      })
    }
    strategies.set(record.strategy_version_id, strategy)

    fixtures.set(fixtureKey, launchInput)
  }

  return {
    as_of: response.as_of,
    strategies: [...strategies.values()],
    fixtures: [...fixtures.values()],
  }
}

export function fetchBootstrap(signal?: AbortSignal): Promise<ApiResult<UiBootstrap>> {
  return withDevelopmentFallback(
    () => requestJson<UiBootstrap>('/ui/bootstrap', { signal }),
    () => makeBootstrapFixture(),
  )
}

export function fetchDashboardSummary(
  signal?: AbortSignal,
): Promise<ApiResult<DashboardSummary>> {
  return withDevelopmentFallback(
    () => requestJson<DashboardSummary>('/dashboard/summary', { signal }),
    () => makeDashboardFixture(),
  )
}

export function fetchDataCatalog(signal?: AbortSignal): Promise<ApiResult<DataCatalogResponse>> {
  return withDevelopmentFallback(
    () => requestJson<DataCatalogResponse>('/data/catalog', { signal }),
    () => makeDataCatalogFixture(),
  )
}

export function fetchDataQuality(signal?: AbortSignal): Promise<ApiResult<DataQualityResponse>> {
  return withDevelopmentFallback(
    () => requestJson<DataQualityResponse>('/data/quality', { signal }),
    () => makeDataQualityFixture(),
  )
}

export function fetchResearchStrategies(
  signal?: AbortSignal,
): Promise<ApiResult<ResearchStrategiesResponse>> {
  return withDevelopmentFallback(
    async () =>
      normalizeResearchStrategies(
        await requestJson<ResearchStrategyCatalogResponse>('/research/strategies', { signal }),
      ),
    () => makeResearchStrategiesFixture(),
  )
}

export function fetchBacktests(signal?: AbortSignal): Promise<ApiResult<BacktestsResponse>> {
  return withDevelopmentFallback(
    () => requestJson<BacktestsResponse>('/research/backtests', { signal }),
    () => makeBacktestsFixture(),
  )
}

export function fetchBacktestReport(
  jobId: string,
  signal?: AbortSignal,
): Promise<ApiResult<BacktestReportResponse>> {
  return withDevelopmentFallback(
    () =>
      requestJson<BacktestReportResponse>(
        `/research/backtests/${encodeURIComponent(jobId)}/report`,
        { signal },
      ),
    () => makeBacktestReportFixture(),
  )
}

export function launchBacktest(
  input: BacktestLaunchRequest,
  credentials: ResearchMutationCredentials,
): Promise<BacktestJob> {
  return requestJson<BacktestJob>('/research/backtests', {
    body: input,
    headers: {
      'Idempotency-Key': credentials.idempotencyKey,
      'X-CSRF-Token': credentials.csrfToken,
    },
    method: 'POST',
  })
}
