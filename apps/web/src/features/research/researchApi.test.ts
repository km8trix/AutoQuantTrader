import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { fetchResearchCatalog, fetchResearchComparison, fetchResearchReport, fetchResearchRows, launchResearchRun, researchError, researchExportUrl, type ResearchRunRequest } from './researchApi'
import { comparisonFixture, digest, jsonResponse, reportFixture, rowsFixture, runFixture } from './researchTestFixtures'

describe('actual research transport', () => {
  beforeEach(() => { vi.stubGlobal('fetch', vi.fn()) })
  afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs() })

  it('does not replace unavailable API data with a development fixture', async () => {
    vi.stubEnv('VITE_USE_DEV_FIXTURES', 'true')
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ detail: 'research store offline' }, 503))
    await expect(fetchResearchCatalog()).rejects.toThrow('research store offline')
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('posts exact decimal strings with same-origin credentials and stable mutation identity', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(runFixture(), 202))
    const input: ResearchRunRequest = { dataset_id: 'catalog-id', dataset_manifest_sha256: digest(), strategy_id: 'buy_hold', strategy_version: 'v1', configuration: runFixture().configuration, initial_cash: '10000.1234567890', warmup_sessions: 252, scored_start: null, scored_end: null, cost_scenario_id: 'base_1x' }
    await launchResearchRun(input, { idempotencyKey: 'request-a', csrfToken: 'session-csrf' })
    const options = vi.mocked(fetch).mock.calls[0]?.[1]
    expect(options?.credentials).toBe('same-origin')
    expect(options?.body).toBe(JSON.stringify(input))
    expect(options?.headers).toMatchObject({ 'Idempotency-Key': 'request-a', 'X-CSRF-Token': 'session-csrf' })
  })

  it('posts read-only comparisons without mutation credentials', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(comparisonFixture()))
    await fetchResearchComparison(['job-a', 'job-b'])
    const options = vi.mocked(fetch).mock.calls[0]?.[1]
    expect(options?.method).toBe('POST')
    expect(options?.body).toBe('{"job_ids":["job-a","job-b"]}')
    expect(options?.headers).not.toHaveProperty('X-CSRF-Token')
    expect(options?.headers).not.toHaveProperty('Idempotency-Key')
  })

  it('rejects a comparison that duplicates one job while omitting the other', async () => {
    const comparison = comparisonFixture()
    comparison.runs[1] = { ...comparison.runs[0]! }
    vi.mocked(fetch).mockResolvedValue(jsonResponse(comparison))
    await expect(fetchResearchComparison(['job-a', 'job-b'])).rejects.toThrow('requested runs')
  })

  it('binds the report and each row page to the selected report hash', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(reportFixture({ report_sha256: digest('c') })))
    await expect(fetchResearchReport('job-a', digest('d'))).rejects.toThrow('report identity changed')
    vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(rowsFixture({ report_sha256: digest('c') })))
    await expect(fetchResearchRows('job-a', digest('d'), 'equity')).rejects.toThrow('row identity')
  })

  it('rejects wrong row kind or page offset and forwards cancellation signals', async () => {
    const abort = new AbortController()
    vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(rowsFixture({ kind: 'positions' })))
    await expect(fetchResearchRows('job-a', digest('d'), 'equity', 0, abort.signal)).rejects.toThrow('row identity')
    expect(vi.mocked(fetch).mock.calls[0]?.[1]?.signal).toBe(abort.signal)
    vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(rowsFixture({ offset: 0 })))
    await expect(fetchResearchRows('job-a', digest('d'), 'equity', 200)).rejects.toThrow('row identity')
  })

  it('keeps export links within the actual research API namespace', () => {
    expect(researchExportUrl('/api/v1/research/personal/runs/job-a/artifact')).toContain('/personal/')
    expect(researchExportUrl('https://example.com/private')).toBeNull()
    expect(researchExportUrl('/private/archive.json')).toBeNull()
    expect(researchExportUrl(null)).toBeNull()
  })

  it('formats structured admission field errors without opaque object strings', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ detail: [{ loc: ['body', 'configuration', 'allocation'], msg: 'Input must be an exact decimal string' }] }, 422))
    const message = await fetchResearchCatalog().catch((error: unknown) => researchError(error))
    expect(message).toBe('configuration.allocation: Input must be an exact decimal string')
  })
})
