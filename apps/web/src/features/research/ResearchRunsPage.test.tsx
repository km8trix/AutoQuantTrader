import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { makeBootstrapFixture } from '../../api/fixtures'
import { renderWithProviders } from '../../test/render'
import { ResearchRunsPage } from './ResearchRunsPage'
import type { ResearchCatalog, ResearchRun } from './researchApi'
import { asOf, catalogFixture, jsonResponse, requestUrl, runFixture } from './researchTestFixtures'

function renderPage(path = '/research/backtests') {
  return renderWithProviders(<MemoryRouter initialEntries={[path]}><ResearchRunsPage bootstrap={makeBootstrapFixture()} /></MemoryRouter>)
}

function readHandler(catalog: ResearchCatalog = catalogFixture(), run: ResearchRun = runFixture()) {
  return (input: RequestInfo | URL) => {
    const url = requestUrl(input)
    if (url.endsWith('/catalog')) return jsonResponse(catalog)
    if (url.endsWith('/runs')) return jsonResponse({ as_of: asOf, jobs: [], truncated: false })
    if (url.endsWith(`/runs/${run.job_id}`)) return jsonResponse(run)
    throw new Error(`Unexpected request: ${url}`)
  }
}

describe('actual research run workflow', () => {
  beforeEach(() => { sessionStorage.clear(); vi.stubGlobal('fetch', vi.fn()) })
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); sessionStorage.clear() })

  it('selects a registered real sample and posts the exact catalog identity and configuration', async () => {
    const read = readHandler()
    vi.mocked(fetch).mockImplementation((input, options) => Promise.resolve(options?.method === 'POST' ? jsonResponse(runFixture(), 202) : read(input)))
    const user = userEvent.setup()
    renderPage()
    await user.selectOptions(await screen.findByLabelText('Dataset'), 'catalog-imported')
    expect(screen.getByText('Insufficient history for default warmup and annualized metrics.')).toBeInTheDocument()
    await user.clear(screen.getByLabelText(/Initial cash/))
    await user.type(screen.getByLabelText(/Initial cash/), '10000.1234567890')
    await user.click(screen.getByRole('button', { name: 'Launch research run' }))
    expect(await screen.findByText(/was accepted as queued/)).toBeInTheDocument()
    const post = vi.mocked(fetch).mock.calls.find(([, options]) => options?.method === 'POST')?.[1]
    if (typeof post?.body !== 'string') throw new Error('Expected a JSON request body')
    expect(JSON.parse(post.body)).toMatchObject({ dataset_id: 'catalog-imported', dataset_manifest_sha256: 'b'.repeat(64), initial_cash: '10000.1234567890', configuration: { allocation: '0.25' } })
    expect(post?.headers).toMatchObject({ 'X-CSRF-Token': 'development-fixture-csrf-token' })
    expect(post?.credentials).toBe('same-origin')
    expect(await screen.findByText('The worker report is pending.')).toBeInTheDocument()
  })

  it('retains the exact request body and idempotency key after an ambiguous launch', async () => {
    let posts = 0
    const catalog = catalogFixture()
    const read = readHandler(catalog)
    vi.mocked(fetch).mockImplementation((input, options) => {
      if (options?.method === 'POST') return ++posts === 1 ? Promise.reject(new TypeError('response lost')) : Promise.resolve(jsonResponse(runFixture(), 202))
      return Promise.resolve(read(input))
    })
    const user = userEvent.setup()
    const page = renderPage()
    await user.click(await screen.findByRole('button', { name: 'Launch research run' }))
    await screen.findByRole('button', { name: 'Retry same launch' })
    page.unmount()
    catalog.datasets = []
    catalog.strategies = []
    catalog.cost_scenarios = []
    renderPage()
    await screen.findByText(/unresolved request was restored/)
    expect(posts).toBe(1)
    const retry = screen.getByRole('button', { name: 'Retry same launch' })
    expect(screen.getByLabelText('Dataset')).toBeDisabled()
    await user.click(retry)
    await screen.findByText('The worker report is pending.')
    const requests = vi.mocked(fetch).mock.calls.filter(([, options]) => options?.method === 'POST').map(([, options]) => options)
    expect(requests).toHaveLength(2)
    expect(requests[0]?.body).toBe(requests[1]?.body)
    expect(requests[0]?.headers).toEqual(requests[1]?.headers)
    expect(sessionStorage.getItem('personal-research-pending/1/run')).toBeNull()
  })

  it('does not post when session storage fails and requires warned discard of a malformed intent', async () => {
    vi.mocked(fetch).mockImplementation((input) => Promise.resolve(readHandler()(input)))
    const user = userEvent.setup()
    const page = renderPage()
    await screen.findByRole('button', { name: 'Launch research run' })
    const storageFailure = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new DOMException('storage disabled') })
    await user.click(screen.getByRole('button', { name: 'Launch research run' }))
    expect(await screen.findByText(/No request was sent/)).toBeInTheDocument()
    expect(vi.mocked(fetch).mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false)
    page.unmount()
    storageFailure.mockRestore()
    sessionStorage.setItem('personal-research-pending/1/run', '{broken')
    renderPage()
    expect(await screen.findByText(/Retained request is malformed/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Launch research run' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: 'Start a different request' }))
    expect(screen.getByText(/earlier request may already have created a run/)).toBeInTheDocument()
    expect(sessionStorage.getItem('personal-research-pending/1/run')).toBe('{broken')
    await user.click(screen.getByRole('button', { name: 'Discard retained request' }))
    expect(sessionStorage.getItem('personal-research-pending/1/run')).toBeNull()
    expect(screen.getByRole('button', { name: 'Launch research run' })).toBeEnabled()
  })

  it('keeps cancellation pending until the worker reports a terminal state', async () => {
    let run = runFixture({ status: 'running' })
    vi.mocked(fetch).mockImplementation((input, options) => {
      if (requestUrl(input).endsWith('/cancel') && options?.method === 'POST') {
        run = { ...run, cancel_requested: true }
        return Promise.resolve(jsonResponse(run))
      }
      return Promise.resolve(readHandler(catalogFixture(), run)(input))
    })
    const user = userEvent.setup()
    renderPage('/research/backtests?job=job-a')
    await user.click(await screen.findByRole('button', { name: 'Cancel run' }))
    expect(await screen.findByText(/Cancellation is pending/)).toBeInTheDocument()
    expect(screen.queryByText('cancelled')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Cancel run' })).toBeDisabled()
  })

  it('shows abandoned attempts and recovered running state from a deep link', async () => {
    const run = runFixture({ status: 'running', attempts: [{ attempt_id: 'old', attempt_number: 1, status: 'abandoned', started_at: asOf, ended_at: asOf, reasons: ['lease-expired'] }, { attempt_id: 'new', attempt_number: 2, status: 'running', started_at: asOf, ended_at: null, reasons: [] }] })
    vi.mocked(fetch).mockImplementation((input) => Promise.resolve(readHandler(catalogFixture(), run)(input)))
    renderPage('/research/backtests?job=job-a')
    expect(await screen.findByText(/Attempt 1: abandoned/)).toBeInTheDocument()
    expect(screen.getByText(/Attempt 2: running/)).toBeInTheDocument()
    expect(screen.getByText('Measured progress is unavailable.')).toBeInTheDocument()
  })

  it.each(['failed', 'cancelled', 'incomplete'] as const)('keeps %s runs without a report explicit', async (status) => {
    vi.mocked(fetch).mockImplementation((input) => Promise.resolve(readHandler(catalogFixture(), runFixture({ status, reasons: ['retained-terminal-reason'] }))(input)))
    renderPage('/research/backtests?job=job-a')
    expect(await screen.findByText('No performance report was published for this attempt.')).toBeInTheDocument()
    expect(screen.getByText(status)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Cancel run' })).not.toBeInTheDocument()
  })

  it('obeys a disabled server launch capability', async () => {
    const catalog = { ...catalogFixture(), launch: { enabled: false, reasons: ['research-store-unavailable'] } }
    vi.mocked(fetch).mockImplementation((input) => Promise.resolve(readHandler(catalog)(input)))
    renderPage()
    expect(await screen.findByRole('button', { name: 'Launch research run' })).toBeDisabled()
    expect(screen.getByText('research-store-unavailable')).toBeInTheDocument()
  })

  it('shows missing catalog data and cannot launch example work after an API error', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ detail: 'offline research catalog' }, 503))
    renderPage()
    await waitFor(() => expect(screen.getByText(/Research catalog unavailable: offline research catalog/)).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: 'Launch research run' })).not.toBeInTheDocument()
  })
})
