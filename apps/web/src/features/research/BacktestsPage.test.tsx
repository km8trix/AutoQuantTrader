import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { makeBootstrapFixture } from '../../api/fixtures'
import { makeBacktestReportFixture, makeBacktestsFixture } from '../../api/researchFixtures'
import type {
  BacktestJob,
  BacktestLaunchRequest,
  ResearchStrategyCatalogResponse,
} from '../../api/types'
import { renderWithProviders } from '../../test/render'
import { BacktestsPage } from './BacktestsPage'

const digest = (character: string): string => character.repeat(64)

function strategyCatalogResponse(): ResearchStrategyCatalogResponse {
  return {
    as_of: '2026-07-21T14:00:00.000Z',
    strategies: [
      {
        strategy_version_id: digest('1'),
        strategy_id: 'buy-and-hold-fixture',
        strategy_version: '1.0.0',
        display_name: 'Buy and hold fixture',
        configuration_sha256: digest('2'),
        configuration_name: 'Four-share golden path',
        parameter_schema_payload: JSON.stringify({ type: 'object' }),
        parameters_payload: JSON.stringify({
          type: 'tuple',
          value: [
            {
              type: 'tuple',
              value: [
                { type: 'string', value: 'quantity' },
                { type: 'int', value: '4' },
              ],
            },
          ],
        }),
        fixture_id: 'phase2-golden-lifecycle',
        fixture_version: '1.0.0',
        dataset_manifest_sha256: digest('3'),
        replay_run_id: digest('4'),
        benchmark_sha256: digest('5'),
        cost_model_sha256: digest('6'),
        fill_model_sha256: digest('7'),
        metric_conventions_sha256: digest('8'),
      },
    ],
  }
}

function multiVersionStrategyCatalogResponse(): ResearchStrategyCatalogResponse {
  const catalog = strategyCatalogResponse()
  const first = catalog.strategies[0]
  if (!first) throw new Error('Expected the golden catalog record')
  return {
    ...catalog,
    strategies: [
      first,
      {
        ...first,
        fixture_version: '2.0.0',
        dataset_manifest_sha256: digest('a'),
        replay_run_id: digest('b'),
        benchmark_sha256: digest('c'),
        cost_model_sha256: digest('d'),
        fill_model_sha256: digest('e'),
        metric_conventions_sha256: digest('f'),
      },
    ],
  }
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input
  return input instanceof URL ? input.href : input.url
}

function launchedJob(): BacktestJob {
  return {
    job_id: digest('9'),
    input_sha256: digest('a'),
    fixture_id: 'phase2-golden-lifecycle',
    fixture_version: '1.0.0',
    strategy_id: 'buy-and-hold-fixture',
    strategy_version: '1.0.0',
    strategy_configuration_sha256: digest('2'),
    requested_by: 'local-operator',
    requested_at: '2026-07-21T14:00:00.000Z',
    status: 'queued',
    attempt_number: 0,
    worker_id: null,
    claim_expires_at: null,
    updated_at: '2026-07-21T14:00:00.000Z',
    run_manifest_sha256: null,
    report_sha256: null,
    report_artifact_sha256: null,
    terminal_reason_code: null,
    history: [
      {
        sequence: 0,
        status: 'queued',
        occurred_at: '2026-07-21T14:00:00.000Z',
        actor_id: 'local-operator',
        attempt_number: 0,
        terminal_reason_code: null,
      },
    ],
  }
}

describe('BacktestsPage', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  it('launches only pinned fixture inputs with the session, CSRF, and idempotency contract', async () => {
    vi.mocked(fetch).mockImplementation((input, options) => {
      const url = requestUrl(input)
      if (url.endsWith('/research/strategies')) return Promise.resolve(jsonResponse(strategyCatalogResponse()))
      if (url.endsWith('/research/backtests') && options?.method === 'POST') return Promise.resolve(jsonResponse(launchedJob(), 202))
      if (url.endsWith('/research/backtests')) return Promise.resolve(jsonResponse({ as_of: '2026-07-21T14:00:00.000Z', jobs: [] }))
      return Promise.reject(new Error(`Unexpected request ${url}`))
    })
    const user = userEvent.setup()

    renderWithProviders(<MemoryRouter><BacktestsPage bootstrap={makeBootstrapFixture()} /></MemoryRouter>)

    const launchButton = await screen.findByRole('button', { name: 'Launch backtest' })
    await waitFor(() => expect(launchButton).toBeEnabled())
    expect(await screen.findByText('Four-share golden path')).toBeInTheDocument()
    await user.click(launchButton)

    expect(await screen.findByText(/was accepted as queued/)).toBeInTheDocument()
    const postCall = vi.mocked(fetch).mock.calls.find(([, options]) => options?.method === 'POST')
    expect(postCall).toBeDefined()
    const options = postCall?.[1]
    const headers = options?.headers as Record<string, string>
    expect(options?.credentials).toBe('same-origin')
    expect(headers['X-AQT-Operator-ID']).toBeUndefined()
    expect(headers['X-CSRF-Token']).toBe('development-fixture-csrf-token')
    expect(headers['Idempotency-Key']).toMatch(/^backtest-/)
    const requestBody = options?.body
    expect(typeof requestBody).toBe('string')
    if (typeof requestBody !== 'string') throw new Error('Expected a JSON request body')
    const body = JSON.parse(requestBody) as BacktestLaunchRequest
    expect(body).toEqual({
      fixture_id: 'phase2-golden-lifecycle',
      fixture_version: '1.0.0',
      dataset_manifest_id: digest('3'),
      dataset_manifest_sha256: digest('3'),
      replay_run_id: digest('4'),
      strategy_id: 'buy-and-hold-fixture',
      strategy_version: '1.0.0',
      strategy_configuration_sha256: digest('2'),
      benchmark_sha256: digest('5'),
      cost_model_sha256: digest('6'),
      fill_model_sha256: digest('7'),
      metric_conventions_sha256: digest('8'),
    })
  })

  it('reuses the exact request identity after an ambiguous launch failure', async () => {
    let launchCount = 0
    vi.mocked(fetch).mockImplementation((input, options) => {
      const url = requestUrl(input)
      if (url.endsWith('/research/strategies')) {
        return Promise.resolve(jsonResponse(strategyCatalogResponse()))
      }
      if (url.endsWith('/research/backtests') && options?.method === 'POST') {
        launchCount += 1
        if (launchCount === 1) return Promise.reject(new TypeError('network connection lost'))
        return Promise.resolve(jsonResponse(launchedJob(), 202))
      }
      if (url.endsWith('/research/backtests')) {
        return Promise.resolve(
          jsonResponse({ as_of: '2026-07-21T14:00:00.000Z', jobs: [] }),
        )
      }
      return Promise.reject(new Error(`Unexpected request ${url}`))
    })
    const user = userEvent.setup()

    renderWithProviders(
      <MemoryRouter>
        <BacktestsPage bootstrap={makeBootstrapFixture()} />
      </MemoryRouter>,
    )

    await user.click(await screen.findByRole('button', { name: 'Launch backtest' }))
    expect(await screen.findByText(/network connection lost/)).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'Strategy version' })).toHaveAttribute(
      'aria-disabled',
      'true',
    )
    await user.click(screen.getByRole('button', { name: 'Retry same request' }))
    expect(await screen.findByText(/was accepted as queued/)).toBeInTheDocument()

    const postCalls = vi.mocked(fetch).mock.calls.filter(([, request]) => request?.method === 'POST')
    expect(postCalls).toHaveLength(2)
    const firstHeaders = postCalls[0]?.[1]?.headers as Record<string, string>
    const secondHeaders = postCalls[1]?.[1]?.headers as Record<string, string>
    expect(secondHeaders['Idempotency-Key']).toBe(firstHeaders['Idempotency-Key'])
    expect(postCalls[1]?.[1]?.body).toBe(postCalls[0]?.[1]?.body)

    await user.click(screen.getByRole('button', { name: 'Launch backtest' }))
    await waitFor(() => expect(launchCount).toBe(3))
    const distinctHeaders = vi.mocked(fetch).mock.calls
      .filter(([, request]) => request?.method === 'POST')[2]?.[1]?.headers as Record<
      string,
      string
    >
    expect(distinctHeaders['Idempotency-Key']).not.toBe(firstHeaders['Idempotency-Key'])
  })

  it('selects fixture versions by their full immutable identity', async () => {
    vi.mocked(fetch).mockImplementation((input, options) => {
      const url = requestUrl(input)
      if (url.endsWith('/research/strategies')) {
        return Promise.resolve(jsonResponse(multiVersionStrategyCatalogResponse()))
      }
      if (url.endsWith('/research/backtests') && options?.method === 'POST') {
        return Promise.resolve(
          jsonResponse({ ...launchedJob(), fixture_version: '2.0.0' }, 202),
        )
      }
      if (url.endsWith('/research/backtests')) {
        return Promise.resolve(
          jsonResponse({ as_of: '2026-07-21T14:00:00.000Z', jobs: [] }),
        )
      }
      return Promise.reject(new Error(`Unexpected request ${url}`))
    })
    const user = userEvent.setup()

    renderWithProviders(
      <MemoryRouter>
        <BacktestsPage bootstrap={makeBootstrapFixture()} />
      </MemoryRouter>,
    )

    await user.click(await screen.findByRole('combobox', { name: 'Synthetic fixture' }))
    await user.click(await screen.findByRole('option', { name: /2\.0\.0/ }))
    await user.click(screen.getByRole('button', { name: 'Launch backtest' }))

    await waitFor(() => {
      expect(
        vi.mocked(fetch).mock.calls.some(([, options]) => options?.method === 'POST'),
      ).toBe(true)
    })
    const postCall = vi.mocked(fetch).mock.calls.find(([, options]) => options?.method === 'POST')
    const requestBody = postCall?.[1]?.body
    expect(typeof requestBody).toBe('string')
    if (typeof requestBody !== 'string') throw new Error('Expected a JSON request body')
    expect(JSON.parse(requestBody)).toMatchObject({
      fixture_id: 'phase2-golden-lifecycle',
      fixture_version: '2.0.0',
      dataset_manifest_id: digest('a'),
      dataset_manifest_sha256: digest('a'),
      replay_run_id: digest('b'),
    })
  })

  it('shows durable progress, lifecycle history, and the completed report evidence', async () => {
    const report = makeBacktestReportFixture(new Date('2026-07-21T14:00:00.000Z'))
    const jobs = makeBacktestsFixture(new Date('2026-07-21T14:00:00.000Z'))
    vi.mocked(fetch).mockImplementation((input) => {
      const url = requestUrl(input)
      if (url.endsWith('/research/strategies')) return Promise.resolve(jsonResponse(strategyCatalogResponse()))
      if (url.endsWith('/report')) return Promise.resolve(jsonResponse(report))
      if (url.endsWith('/research/backtests')) return Promise.resolve(jsonResponse(jobs))
      return Promise.reject(new Error(`Unexpected request ${url}`))
    })

    renderWithProviders(<MemoryRouter><BacktestsPage bootstrap={makeBootstrapFixture()} /></MemoryRouter>)

    expect(await screen.findByRole('table', { name: 'Backtest jobs' })).toBeInTheDocument()
    expect(screen.getByText('Job history')).toBeInTheDocument()
    const history = screen.getByRole('list', { name: 'Append-only job history' })
    expect(within(history).getAllByRole('listitem')).toHaveLength(3)
    expect(within(history).getByText('Queued')).toBeInTheDocument()
    expect(within(history).getByText('Running')).toBeInTheDocument()
    expect(within(history).getByText('Completed')).toBeInTheDocument()
    expect((await screen.findAllByText('$1,044.04')).length).toBeGreaterThan(0)
    expect(screen.getByRole('img', { name: /Equity curve from/ })).toBeInTheDocument()
    expect(screen.getByRole('table', { name: 'Backtest trade trace' })).toBeInTheDocument()
    expect(screen.getByText('golden-trade-001')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Ledger' })).toHaveAttribute('href', '#backtest-ledger')
    expect(screen.getByText('Run provenance')).toBeInTheDocument()
  })

  it('fails closed when bootstrap does not authorize a local mutation', async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = requestUrl(input)
      if (url.endsWith('/research/strategies')) return Promise.resolve(jsonResponse(strategyCatalogResponse()))
      return Promise.resolve(jsonResponse({ as_of: '2026-07-21T14:00:00.000Z', jobs: [] }))
    })
    const bootstrap = makeBootstrapFixture()
    bootstrap.backtest_launch = {
      enabled: false,
      operator_id: null,
      csrf_token: null,
      csrf_header: 'X-CSRF-Token',
      idempotency_header: 'Idempotency-Key',
      disabled_reason: 'Local operator authentication is unavailable.',
    }

    renderWithProviders(<MemoryRouter><BacktestsPage bootstrap={bootstrap} /></MemoryRouter>)

    expect(await screen.findByRole('button', { name: 'Launch backtest' })).toBeDisabled()
    expect(screen.getByText('Local operator authentication is unavailable.')).toBeInTheDocument()
    await waitFor(() => expect(fetch).toHaveBeenCalled())
    expect(vi.mocked(fetch).mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false)
  })
})
