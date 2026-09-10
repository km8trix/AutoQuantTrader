import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { makeBootstrapFixture, makeDashboardFixture } from '../api/fixtures'
import { asOf, catalogFixture, comparisonFixture, digest, reportFixture, requestUrl, rowsFixture, runFixture } from '../features/research/researchTestFixtures'
import { renderWithProviders } from '../test/render'
import { AppRoutes } from './AppRoutes'
import { navigationGroups } from './navigation'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('AppRoutes', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  it('exposes an accessible loading state while a route chunk resolves', async () => {
    const now = new Date()
    vi.mocked(fetch).mockResolvedValue(jsonResponse(makeDashboardFixture(now)))

    renderWithProviders(
      <MemoryRouter initialEntries={['/risk']}>
        <AppRoutes bootstrap={makeBootstrapFixture(now)} />
      </MemoryRouter>,
    )

    expect(screen.getByRole('status', { name: 'Loading workspace page' })).toBeInTheDocument()
    expect(await screen.findByRole('heading', { level: 1, name: 'Risk' })).toBeInTheDocument()
    expect(
      screen.queryByRole('status', { name: 'Loading workspace page' }),
    ).not.toBeInTheDocument()
  })

  it.each([
    ['/risk', 'Risk'],
    ['/operations/reconciliation', 'Reconciliation'],
    ['/operations/audit', 'Audit log'],
    ['/settings', 'Settings'],
  ])('renders the Phase 5 page for %s', async (path, heading) => {
    const now = new Date()
    vi.mocked(fetch).mockResolvedValue(jsonResponse(makeDashboardFixture(now)))

    renderWithProviders(
      <MemoryRouter initialEntries={[path]}>
        <AppRoutes bootstrap={makeBootstrapFixture(now)} />
      </MemoryRouter>,
    )

    expect(
      await screen.findByRole('heading', { level: 1, name: heading }),
    ).toBeInTheDocument()
    expect(screen.queryByText('Workspace route reserved')).not.toBeInTheDocument()
  })

  it('retains placeholders for routes outside this slice', () => {
    renderWithProviders(
      <MemoryRouter initialEntries={['/trading/orders']}>
        <AppRoutes bootstrap={makeBootstrapFixture()} />
      </MemoryRouter>,
    )

    expect(screen.getByRole('heading', { level: 1, name: 'Orders' })).toBeInTheDocument()
    expect(screen.getByText('Workspace route reserved')).toBeInTheDocument()
  })

  it.each([
    ['/research/strategies', 'Reference strategies'],
    ['/research/backtests', 'Research runs'],
    ['/research/experiments', 'Descriptive experiments'],
  ])('uses actual research projections by default at %s', async (path, heading) => {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = requestUrl(input)
      if (url.endsWith('/personal/catalog')) return Promise.resolve(jsonResponse(catalogFixture()))
      if (url.endsWith('/personal/runs')) return Promise.resolve(jsonResponse({ as_of: asOf, jobs: [], truncated: false }))
      if (url.endsWith('/personal/experiments')) return Promise.resolve(jsonResponse({ as_of: asOf, experiments: [], truncated: false }))
      return Promise.reject(new Error(`Unexpected route request ${url}`))
    })
    renderWithProviders(<MemoryRouter initialEntries={[path]}><AppRoutes bootstrap={makeBootstrapFixture()} /></MemoryRouter>)
    expect(await screen.findByRole('heading', { level: 1, name: heading })).toBeInTheDocument()
    expect(vi.mocked(fetch).mock.calls.length).toBeGreaterThan(0)
    expect(vi.mocked(fetch).mock.calls.every(([input]) => requestUrl(input).includes('/api/v1/research/personal/'))).toBe(true)
  })

  it.each([
    ['/research/history/strategies?configuration=retained', 'Historical strategy diagnostics'],
    ['/research/history/backtests?strategy_version=retained', 'Historical golden diagnostics'],
    ['/research/history/experiments?family=retained', 'Historical governance diagnostics'],
  ])('keeps %s within explicit history diagnostics', async (path, heading) => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ detail: 'Diagnostic store unavailable' }, 503))
    renderWithProviders(<MemoryRouter initialEntries={[path]}><AppRoutes bootstrap={makeBootstrapFixture()} /></MemoryRouter>)
    expect(await screen.findByRole('heading', { level: 1, name: heading })).toBeInTheDocument()
    expect(vi.mocked(fetch).mock.calls.every(([input]) => !requestUrl(input).includes('/personal/'))).toBe(true)
    expect(vi.mocked(fetch).mock.calls.every(([, options]) => options?.method !== 'POST')).toBe(true)
  })

  it('runs dataset selection through publication and comparison on the default route using a controlled backend', async () => {
    const runA = runFixture({ status: 'completed', report_sha256: digest('d'), result_sha256: digest('e') })
    const runB = runFixture({ job_id: 'job-b', status: 'completed', report_sha256: digest('b'), cost_scenario_id: 'adverse' })
    vi.mocked(fetch).mockImplementation((input, options) => {
      const url = requestUrl(input)
      if (url.endsWith('/personal/catalog')) return Promise.resolve(jsonResponse(catalogFixture()))
      if (url.endsWith('/personal/comparison')) return Promise.resolve(jsonResponse(comparisonFixture()))
      if (url.endsWith('/personal/runs') && options?.method === 'POST') return Promise.resolve(jsonResponse(runA, 202))
      if (url.endsWith('/personal/runs')) return Promise.resolve(jsonResponse({ as_of: asOf, jobs: [runA, runB], truncated: false }))
      if (url.endsWith('/runs/job-a')) return Promise.resolve(jsonResponse(runA))
      if (url.endsWith('/runs/job-a/report')) return Promise.resolve(jsonResponse(reportFixture()))
      if (url.includes('/runs/job-a/rows?')) return Promise.resolve(jsonResponse(rowsFixture()))
      return Promise.reject(new Error(`Unexpected route request ${url}`))
    })
    const user = userEvent.setup()
    renderWithProviders(<MemoryRouter initialEntries={['/research/backtests']}><AppRoutes bootstrap={makeBootstrapFixture()} /></MemoryRouter>)
    await user.selectOptions(await screen.findByLabelText('Dataset'), 'catalog-imported')
    await user.click(screen.getByRole('button', { name: 'Launch research run' }))
    expect(await screen.findByRole('heading', { name: 'Worker report' })).toBeInTheDocument()
    await user.click(screen.getByRole('checkbox', { name: 'Compare job-a' }))
    await user.click(screen.getByRole('checkbox', { name: 'Compare job-b' }))
    expect(await screen.findByText(/These results are not directly comparable/)).toBeInTheDocument()
    const launch = vi.mocked(fetch).mock.calls.find(([input, options]) => requestUrl(input).endsWith('/personal/runs') && options?.method === 'POST')?.[1]
    if (typeof launch?.body !== 'string') throw new Error('Expected a JSON launch body')
    expect(JSON.parse(launch.body)).toMatchObject({ dataset_id: 'catalog-imported', dataset_manifest_sha256: digest('b') })
    expect(vi.mocked(fetch).mock.calls.every(([input]) => requestUrl(input).includes('/personal/'))).toBe(true)
  })

  it('names current research and historical diagnostics separately while preserving operations navigation', () => {
    expect(navigationGroups.find((group) => group.label === 'Research')?.items.map((item) => item.path)).toEqual(['/research/strategies', '/research/backtests', '/research/experiments'])
    expect(navigationGroups.find((group) => group.label === 'Research history')?.items.every((item) => item.path.startsWith('/research/history/'))).toBe(true)
    expect(navigationGroups.find((group) => group.label === 'Control')?.items.map((item) => item.path)).toEqual(['/operations/dashboard', '/risk', '/operations/reconciliation', '/operations/audit'])
  })
})
