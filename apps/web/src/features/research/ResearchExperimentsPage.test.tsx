import { fireEvent, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { makeBootstrapFixture } from '../../api/fixtures'
import { renderWithProviders } from '../../test/render'
import { ResearchExperimentsPage } from './ResearchExperimentsPage'
import { asOf, catalogFixture, experimentFixture, jsonResponse, metricFixture, requestUrl } from './researchTestFixtures'

function renderPage(path = '/research/experiments') {
  return renderWithProviders(<MemoryRouter initialEntries={[path]}><ResearchExperimentsPage bootstrap={makeBootstrapFixture()} /></MemoryRouter>)
}

async function fillDeclaration() {
  const user = userEvent.setup()
  await user.type(await screen.findByLabelText(/Experiment name/), 'A declared study')
  await user.type(screen.getByLabelText(/Hypothesis/), 'Inspect reference-rule cost sensitivity.')
  const dates = { 'Training start': '2024-01-02', 'Training end': '2024-12-31', 'Validation start': '2025-01-02', 'Validation end': '2025-06-30', 'Test start': '2025-07-01', 'Test end': '2025-12-31' }
  Object.entries(dates).forEach(([label, value]) => { fireEvent.change(screen.getByLabelText(new RegExp(label)), { target: { value } }) })
  return user
}

describe('descriptive experiment workflow', () => {
  beforeEach(() => { sessionStorage.clear(); vi.stubGlobal('fetch', vi.fn()) })
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); sessionStorage.clear() })

  it('requires a prior-access description before sending the declaration', async () => {
    const catalog = catalogFixture()
    catalog.datasets.forEach((dataset) => { dataset.prior_access = 'unknown' })
    vi.mocked(fetch).mockImplementation((input, options) => {
      const url = requestUrl(input)
      if (url.endsWith('/catalog')) return Promise.resolve(jsonResponse(catalog))
      if (options?.method === 'POST' || url.endsWith('/experiment-a')) return Promise.resolve(jsonResponse(experimentFixture(), options?.method === 'POST' ? 202 : 200))
      return Promise.resolve(jsonResponse({ as_of: asOf, experiments: [], truncated: false }))
    })
    renderPage()
    const user = await fillDeclaration()
    await user.click(screen.getByRole('button', { name: 'Declare and run experiment' }))
    expect(vi.mocked(fetch).mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false)
    await user.type(screen.getByLabelText(/Prior access description/), 'Earlier access to these periods is unknown.')
    await user.click(screen.getByRole('button', { name: 'Declare and run experiment' }))
    await screen.findByText('Declared study')
    const post = vi.mocked(fetch).mock.calls.find(([, options]) => options?.method === 'POST')?.[1]
    if (typeof post?.body !== 'string') throw new Error('Expected a JSON request body')
    expect(JSON.parse(post.body)).toMatchObject({ name: 'A declared study', prior_access: { status: 'unknown', description: 'Earlier access to these periods is unknown.' }, folds: [{ train_start: '2024-01-02', validation_start: '2025-01-02', test_start: '2025-07-01' }] })
    expect(post?.headers).toMatchObject({ 'X-CSRF-Token': 'development-fixture-csrf-token' })
    expect(screen.queryByRole('option', { name: /untouched/i })).not.toBeInTheDocument()
  })

  it('prefills catalog access and prevents a known-accessed dataset being downgraded', async () => {
    const catalog = catalogFixture()
    if (catalog.datasets[0]) catalog.datasets[0].prior_access = 'unknown'
    vi.mocked(fetch).mockImplementation((input) => Promise.resolve(jsonResponse(requestUrl(input).endsWith('/catalog') ? catalog : { as_of: asOf, experiments: [], truncated: false })))
    const user = userEvent.setup()
    renderPage()
    expect(await screen.findByLabelText('Prior access status')).toHaveValue('unknown')
    await user.selectOptions(screen.getByLabelText('Experiment dataset'), 'catalog-imported')
    expect(screen.getByLabelText('Prior access status')).toHaveValue('known_accessed')
    expect(screen.getByRole('option', { name: 'Unknown' })).toBeDisabled()
    expect(screen.getByText('This catalog records prior access. Its status cannot be downgraded to unknown.')).toBeInTheDocument()
    expect(screen.getByLabelText(/Prior access description/)).toHaveValue('')
  })

  it('preserves declaration identity on an ambiguous retry', async () => {
    let posts = 0
    vi.mocked(fetch).mockImplementation((input, options) => {
      const url = requestUrl(input)
      if (url.endsWith('/catalog')) return Promise.resolve(jsonResponse(catalogFixture()))
      if (options?.method === 'POST') return ++posts === 1 ? Promise.reject(new Error('response lost')) : Promise.resolve(jsonResponse(experimentFixture(), 202))
      if (url.endsWith('/experiment-a')) return Promise.resolve(jsonResponse(experimentFixture()))
      return Promise.resolve(jsonResponse({ as_of: asOf, experiments: [], truncated: false }))
    })
    const page = renderPage()
    const user = await fillDeclaration()
    await user.type(screen.getByLabelText(/Prior access description/), 'Previously inspected history.')
    await user.click(screen.getByRole('button', { name: 'Declare and run experiment' }))
    await screen.findByRole('button', { name: 'Retry same experiment' })
    page.unmount()
    renderPage()
    await screen.findByText(/unresolved declaration was restored/)
    expect(posts).toBe(1)
    expect(screen.getByLabelText(/Experiment name/)).toHaveValue('A declared study')
    await user.click(await screen.findByRole('button', { name: 'Retry same experiment' }))
    await screen.findByText('Declared study')
    const postsSeen = vi.mocked(fetch).mock.calls.filter(([, options]) => options?.method === 'POST').map(([, options]) => options)
    expect(postsSeen).toHaveLength(2)
    expect(postsSeen[0]?.body).toBe(postsSeen[1]?.body)
    expect(postsSeen[0]?.headers).toEqual(postsSeen[1]?.headers)
    expect(sessionStorage.getItem('personal-research-pending/1/experiment')).toBeNull()
  })

  it('blocks a declaration when storage fails and requires warned discard of malformed storage', async () => {
    vi.mocked(fetch).mockImplementation((input) => Promise.resolve(jsonResponse(requestUrl(input).endsWith('/catalog') ? catalogFixture() : { as_of: asOf, experiments: [], truncated: false })))
    const page = renderPage()
    const user = await fillDeclaration()
    await user.type(screen.getByLabelText(/Prior access description/), 'Previously inspected history.')
    const storageFailure = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new DOMException('storage disabled') })
    await user.click(screen.getByRole('button', { name: 'Declare and run experiment' }))
    expect(await screen.findByText(/No request was sent/)).toBeInTheDocument()
    expect(vi.mocked(fetch).mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false)
    page.unmount()
    storageFailure.mockRestore()
    sessionStorage.setItem('personal-research-pending/1/experiment', '{broken')
    renderPage()
    expect(await screen.findByText(/Retained request is malformed/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Declare and run experiment' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: 'Start a different declaration' }))
    expect(screen.getByText(/earlier declaration may already have created an experiment/)).toBeInTheDocument()
    expect(sessionStorage.getItem('personal-research-pending/1/experiment')).toBe('{broken')
    await user.click(screen.getByRole('button', { name: 'Discard retained declaration' }))
    expect(sessionStorage.getItem('personal-research-pending/1/experiment')).toBeNull()
    expect(screen.getByLabelText(/Experiment name/)).toBeEnabled()
  })

  it('shows all four costs, chronological windows, failed trials and benchmark metrics without selection', async () => {
    const experiment = experimentFixture({ status: 'incomplete', trials: catalogFixture().cost_scenarios.map((cost, index) => ({ trial_id: `trial-${index}`, candidate_id: 'candidate-1', fold_id: 'fold-1', window: 'test', cost_scenario_id: cost.scenario_id, status: (['completed', 'failed', 'cancelled', 'incomplete'] as const)[index] ?? 'failed', job_id: `job-${index}`, report_sha256: null, reasons: index ? ['trial-not-complete'] : [], metrics: [metricFixture('total_return', index ? null : '0.21', index ? ['insufficient-history'] : [])], benchmark_metrics: [metricFixture('total_return', '0.19')] })) })
    vi.mocked(fetch).mockImplementation((input) => Promise.resolve(jsonResponse(requestUrl(input).endsWith('/catalog') ? catalogFixture() : requestUrl(input).endsWith('/experiment-a') ? experiment : { as_of: asOf, experiments: [experiment], truncated: false })))
    renderPage('/research/experiments?experiment=experiment-a')
    expect(await screen.findByText('Four assumed cost scenarios')).toBeInTheDocument()
    expect(screen.getByText('Suitability: not_assessed')).toBeInTheDocument()
    expect(screen.getByText('Training 2024-01-02–2024-12-31')).toBeInTheDocument()
    expect(screen.getByText('Validation 2025-01-02–2025-06-30')).toBeInTheDocument()
    expect(screen.getByText('Test 2025-07-01–2025-12-31')).toBeInTheDocument()
    expect(screen.getByText('test · adverse')).toBeInTheDocument()
    expect(screen.getByText(/Prior access: known_accessed/)).toBeInTheDocument()
    expect(screen.getAllByText(/Benchmark total_return: 0.19/)).toHaveLength(4)
    expect(screen.getByText(/cancelled/)).toBeInTheDocument()
    expect(screen.queryByText(/learned parameters|selected candidate:/i)).not.toBeInTheDocument()
  })

  it('keeps pending results distinct from zero performance and unknown prior access visible', async () => {
    const experiment = experimentFixture()
    experiment.request.prior_access = { status: 'unknown', description: 'Access history has not been established.' }
    vi.mocked(fetch).mockImplementation((input) => Promise.resolve(jsonResponse(requestUrl(input).endsWith('/catalog') ? catalogFixture() : requestUrl(input).endsWith('/experiment-a') ? experiment : { as_of: asOf, experiments: [], truncated: false })))
    renderPage('/research/experiments?experiment=experiment-a')
    expect(await screen.findByText('Trial results are pending. No cost or performance result is available yet.')).toBeInTheDocument()
    expect(screen.getByText(/Prior access: unknown/)).toBeInTheDocument()
    expect(screen.queryByText(/total_return:/)).not.toBeInTheDocument()
  })

  it('reports unavailable experiments without fixture governance evidence', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ detail: 'experiment service offline' }, 503))
    renderPage()
    await waitFor(() => expect(screen.getAllByText('experiment service offline').length).toBeGreaterThan(0))
    expect(screen.queryByText('Declared study')).not.toBeInTheDocument()
  })
})
