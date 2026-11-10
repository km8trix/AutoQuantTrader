import { ApiError, requestJson } from '../../api/client'
import type { components } from '../../api/schema.generated'
import type { ResearchMutationCredentials } from '../../api/types'

type Schemas = components['schemas']
export type ResearchCatalog = Schemas['PersonalResearchCatalog']
export type ResearchDataset = Schemas['PersonalDatasetView']
export type ResearchStrategy = Schemas['PersonalStrategyView']
export type ResearchConfiguration = Schemas['PersonalConfiguration']
export type ResearchRunRequest = Schemas['PersonalRunRequest']
export type ResearchRun = Schemas['PersonalRunView']
export type ResearchRunList = Schemas['PersonalRunList']
export type ResearchReport = Schemas['PersonalRunReport']
export type ResearchRows = Schemas['PersonalRunRows']
export type ResearchRowKind = ResearchRows['kind']
export type ResearchMetric = Schemas['PersonalMetric']
export type ResearchEquityRow = Schemas['PersonalEquityRow']
export type ResearchComparison = Schemas['PersonalComparison']
export type ResearchExperiment = Schemas['PersonalExperimentView']
export type ResearchExperimentRequest = Schemas['PersonalExperimentRequest']
export type ResearchExperimentList = Schemas['PersonalExperimentList']

export const RESEARCH_ROOT = '/research/personal'

export function researchError(error: unknown): string {
  const detail: unknown = error instanceof ApiError ? error.problem?.detail : undefined
  if (Array.isArray(detail)) {
    const entries: unknown[] = detail
    const messages: string[] = []
    for (const entry of entries) {
      if (typeof entry !== 'object' || entry === null || !('msg' in entry) || typeof entry.msg !== 'string') continue
      const location: unknown = 'loc' in entry ? entry.loc : undefined
      const fields: unknown[] = Array.isArray(location) ? location : []
      const path = fields.filter((field) => (typeof field === 'string' || typeof field === 'number') && field !== 'body').join('.')
      messages.push(path ? `${path}: ${entry.msg}` : entry.msg)
    }
    if (messages.length) return messages.join('; ')
  }
  return error instanceof Error ? error.message : 'The research API is unavailable.'
}

function mutationHeaders(credentials: ResearchMutationCredentials) {
  return {
    'Idempotency-Key': credentials.idempotencyKey,
    'X-CSRF-Token': credentials.csrfToken,
  }
}

export function fetchResearchCatalog(signal?: AbortSignal) {
  return requestJson<ResearchCatalog>(`${RESEARCH_ROOT}/catalog`, { signal })
}

export function fetchResearchRuns(signal?: AbortSignal) {
  return requestJson<ResearchRunList>(`${RESEARCH_ROOT}/runs`, { signal })
}

export async function fetchResearchRun(jobId: string, signal?: AbortSignal) {
  const run = await requestJson<ResearchRun>(`${RESEARCH_ROOT}/runs/${encodeURIComponent(jobId)}`, { signal })
  if (run.job_id !== jobId) throw new ApiError('The returned job identity differs from the selected run.')
  return run
}

export function launchResearchRun(input: ResearchRunRequest, credentials: ResearchMutationCredentials) {
  return requestJson<ResearchRun>(`${RESEARCH_ROOT}/runs`, { method: 'POST', body: input, headers: mutationHeaders(credentials) })
}

export function cancelResearchRun(jobId: string, credentials: ResearchMutationCredentials) {
  return requestJson<ResearchRun>(`${RESEARCH_ROOT}/runs/${encodeURIComponent(jobId)}/cancel`, {
    method: 'POST', body: {}, headers: mutationHeaders(credentials),
  })
}

export async function fetchResearchReport(jobId: string, reportSha: string, signal?: AbortSignal) {
  const report = await requestJson<ResearchReport>(`${RESEARCH_ROOT}/runs/${encodeURIComponent(jobId)}/report`, { signal })
  if (report.job_id !== jobId || report.report_sha256 !== reportSha) {
    throw new ApiError('The report identity changed. Refresh the selected run before loading its artifact.')
  }
  return report
}

export async function fetchResearchRows(jobId: string, reportSha: string, kind: ResearchRowKind, offset = 0, signal?: AbortSignal) {
  const params = new URLSearchParams({ kind, report_sha256: reportSha, offset: String(offset), limit: '200' })
  const page = await requestJson<ResearchRows>(`${RESEARCH_ROOT}/runs/${encodeURIComponent(jobId)}/rows?${params}`, { signal })
  if (page.job_id !== jobId || page.report_sha256 !== reportSha || page.kind !== kind || page.offset !== offset || page.rows.some((row) => row.kind !== kind)) {
    throw new ApiError('Report row identity differs from the selected immutable artifact.')
  }
  return page
}

export async function fetchResearchComparison(jobIds: string[], signal?: AbortSignal) {
  const comparison = await requestJson<ResearchComparison>(`${RESEARCH_ROOT}/comparison`, {
    method: 'POST', body: { job_ids: jobIds }, signal,
  })
  if (comparison.runs.length !== jobIds.length || new Set(comparison.runs.map((run) => run.job_id)).size !== jobIds.length || comparison.runs.some((run) => !jobIds.includes(run.job_id))) {
    throw new ApiError('The comparison does not contain the requested runs.')
  }
  return comparison
}

export function fetchResearchExperiments(signal?: AbortSignal) {
  return requestJson<ResearchExperimentList>(`${RESEARCH_ROOT}/experiments`, { signal })
}

export async function fetchResearchExperiment(experimentId: string, signal?: AbortSignal) {
  const experiment = await requestJson<ResearchExperiment>(`${RESEARCH_ROOT}/experiments/${encodeURIComponent(experimentId)}`, { signal })
  if (experiment.experiment_id !== experimentId) throw new ApiError('The experiment identity differs from the selected record.')
  return experiment
}

export function launchResearchExperiment(input: ResearchExperimentRequest, credentials: ResearchMutationCredentials) {
  return requestJson<ResearchExperiment>(`${RESEARCH_ROOT}/experiments`, { method: 'POST', body: input, headers: mutationHeaders(credentials) })
}

export function researchExportUrl(url: string | null): string | null {
  return url?.startsWith(`/api/v1${RESEARCH_ROOT}/`) ? url : null
}
