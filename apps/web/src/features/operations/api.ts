import { useQuery } from '@tanstack/react-query'

import { ApiError } from '../../api/client'
import type {
  ApiResult,
  OperationalControlAction,
  OperationalControlCommandRequest,
  OperationalControlMutationResponse,
  OperationsOverviewResponse,
  ProblemDetails,
} from '../../api/types'
import { makeOperationsDashboardFixture } from './fixtures'
import type { OperationsDashboardSnapshot } from './types'

const OPERATIONS_DASHBOARD_PATH = '/api/v1/operations/dashboard'
const OPERATIONS_ACCOUNT_ROOT = '/api/v1/operations/accounts'

export type SafeOperationalControlAction = Extract<
  OperationalControlAction,
  'pause' | 'halt'
>

export interface OperationalControlCredentials {
  csrfHeader: string
  csrfToken: string
  idempotencyHeader: string
  idempotencyKey: string
}

export interface OperationalControlIntent {
  action: SafeOperationalControlAction
  reasonCode: string
  credentials: OperationalControlCredentials
}

function developmentFixturesEnabled(): boolean {
  return import.meta.env.DEV && import.meta.env.VITE_USE_DEV_FIXTURES === 'true'
}

async function requestOperationsDashboard(
  csrfToken: string | undefined,
  signal?: AbortSignal,
): Promise<OperationsDashboardSnapshot> {
  const response = await fetch(OPERATIONS_DASHBOARD_PATH, {
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json',
      ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
    },
    method: 'GET',
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
      problem?.detail ??
        problem?.title ??
        `Operations dashboard request failed with status ${response.status}`,
      response.status,
      problem,
    )
  }
  return (await response.json()) as OperationsDashboardSnapshot
}

async function readProblem(response: Response): Promise<ProblemDetails | undefined> {
  try {
    return (await response.json()) as ProblemDetails
  } catch {
    return undefined
  }
}

function operationsAccountPath(accountId: string): string {
  return `${OPERATIONS_ACCOUNT_ROOT}/${encodeURIComponent(accountId)}`
}

export async function fetchOperationsOverview(
  accountId: string,
  csrfToken: string,
  csrfHeader: string,
  signal?: AbortSignal,
): Promise<OperationsOverviewResponse> {
  const response = await fetch(operationsAccountPath(accountId), {
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json',
      [csrfHeader]: csrfToken,
    },
    method: 'GET',
    signal,
  })
  if (!response.ok) {
    const problem = await readProblem(response)
    throw new ApiError(
      problem?.detail ??
        problem?.title ??
        `Operations overview request failed with status ${response.status}`,
      response.status,
      problem,
    )
  }
  return (await response.json()) as OperationsOverviewResponse
}

function isControlMutationResponse(
  value: unknown,
  action: SafeOperationalControlAction,
): value is OperationalControlMutationResponse {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
  const candidate = value as Record<string, unknown>
  if (candidate.action !== action) return false
  const control = candidate.control
  if (typeof control !== 'object' || control === null || Array.isArray(control)) {
    return false
  }
  const transition = control as Record<string, unknown>
  const effectiveState = transition.effective_state
  const stateConfirmsAction =
    action === 'halt'
      ? effectiveState === 'halted'
      : effectiveState === 'paused' || effectiveState === 'halted'
  return (
    typeof transition.transition_id === 'string' &&
    transition.transition_id.length > 0 &&
    typeof transition.state_epoch_id === 'string' &&
    transition.state_epoch_id.length > 0 &&
    Number.isSafeInteger(transition.sequence_number) &&
    (transition.sequence_number as number) > 0 &&
    stateConfirmsAction
  )
}

export async function executeOperationalControl(
  accountId: string,
  intent: OperationalControlIntent,
): Promise<OperationalControlMutationResponse> {
  if (intent.action !== 'pause' && intent.action !== 'halt') {
    throw new TypeError('Only PAUSE and HALT are supported by the browser client.')
  }
  const request: OperationalControlCommandRequest = {
    reason_code: intent.reasonCode,
  }
  const response = await fetch(
    `${operationsAccountPath(accountId)}/control/${intent.action}`,
    {
      body: JSON.stringify(request),
      credentials: 'same-origin',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        [intent.credentials.csrfHeader]: intent.credentials.csrfToken,
        [intent.credentials.idempotencyHeader]: intent.credentials.idempotencyKey,
      },
      method: 'POST',
    },
  )
  if (!response.ok) {
    const problem = await readProblem(response)
    throw new ApiError(
      problem?.detail ??
        problem?.title ??
        `Operational control request failed with status ${response.status}`,
      response.status,
      problem,
    )
  }
  let payload: unknown
  try {
    payload = await response.json()
  } catch {
    throw new ApiError(
      'Operational control response was malformed; the command outcome is ambiguous.',
    )
  }
  if (!isControlMutationResponse(payload, intent.action)) {
    throw new ApiError(
      'Operational control response did not confirm the requested action; the command outcome is ambiguous.',
    )
  }
  return payload
}

export function isAmbiguousOperationalControlError(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status >= 500
}

export async function fetchOperationsDashboard(
  csrfToken: string | undefined,
  signal?: AbortSignal,
): Promise<ApiResult<OperationsDashboardSnapshot>> {
  try {
    return { data: await requestOperationsDashboard(csrfToken, signal), source: 'api' }
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw error
    }
    if (!developmentFixturesEnabled()) {
      throw error
    }
    return { data: makeOperationsDashboardFixture(), source: 'development-fixture' }
  }
}

export const operationsDashboardQueryKey = ['operations', 'dashboard'] as const
export const operationsOverviewQueryKey = (accountId: string) =>
  ['operations', 'account', accountId] as const

export function useOperationsDashboard(csrfToken: string | undefined) {
  return useQuery({
    queryKey: [...operationsDashboardQueryKey, csrfToken !== undefined],
    queryFn: ({ signal }) => fetchOperationsDashboard(csrfToken, signal),
    retry: false,
    staleTime: 2_000,
    refetchInterval: 5_000,
    refetchIntervalInBackground: false,
    refetchOnWindowFocus: true,
  })
}

export function useOperationsOverview({
  accountId,
  csrfHeader,
  csrfToken,
  enabled,
}: {
  accountId: string
  csrfHeader: string | null | undefined
  csrfToken: string | null | undefined
  enabled: boolean
}) {
  return useQuery({
    queryKey: operationsOverviewQueryKey(accountId),
    queryFn: ({ signal }) =>
      fetchOperationsOverview(
        accountId,
        csrfToken ?? '',
        csrfHeader ?? 'X-CSRF-Token',
        signal,
      ),
    enabled: enabled && Boolean(csrfToken) && Boolean(csrfHeader),
    retry: false,
    staleTime: 2_000,
    refetchOnWindowFocus: true,
  })
}
