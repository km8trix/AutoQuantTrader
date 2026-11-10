import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { renderWithProviders } from '../../test/render'
import { ResearchRunReport } from './ResearchRunReport'
import { digest, equityFixture, jsonResponse, metricFixture, reportFixture, requestUrl, rowsFixture } from './researchTestFixtures'

describe('actual worker report', () => {
  beforeEach(() => { vi.stubGlobal('fetch', vi.fn()) })
  afterEach(() => { vi.unstubAllGlobals() })

  it('shows authoritative metrics, undefined reasons, coverage and distinct artifact identity', async () => {
    vi.mocked(fetch).mockImplementation((input) => Promise.resolve(jsonResponse(requestUrl(input).endsWith('/report') ? reportFixture() : rowsFixture())))
    renderWithProviders(<ResearchRunReport jobId="job-a" reportSha={digest('d')} />)
    expect(await screen.findAllByText('Time-weighted return')).toHaveLength(3)
    expect(screen.getByText('0.21 ratio')).toBeInTheDocument()
    expect(screen.getAllByText('Undefined')).toHaveLength(2)
    expect(screen.getByText(/insufficient-annualized-history/)).toBeInTheDocument()
    expect(screen.getByText(/zero-downside-denominator/)).toBeInTheDocument()
    expect(screen.getAllByText(/5\/5 valid sessions; 4 valid returns/).length).toBeGreaterThan(0)
    expect(screen.getByText('artifact-attempt-2')).toBeInTheDocument()
    expect(screen.getByText('semantic-run-a')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Download immutable report artifact' })).toHaveAttribute('href', '/api/v1/research/personal/runs/job-a/artifact')
  })

  it('preserves known fees and open holdings when authoritative NAV is missing', async () => {
    const report = reportFixture({ status: 'incomplete', metrics: [metricFixture('ending_equity', null, ['missing-current-mark']), metricFixture('total_execution_costs', '1.12')] })
    vi.mocked(fetch).mockImplementation((input) => {
      const url = requestUrl(input)
      if (url.endsWith('/report')) return Promise.resolve(jsonResponse(report))
      if (url.includes('kind=positions')) return Promise.resolve(jsonResponse(rowsFixture({ kind: 'positions', rows: [{ kind: 'positions', symbol: 'SPY', quantity: '4', cost_basis: '400', market_value: null, unrealized_pnl: null, mark: null, mark_at: null, reasons: ['missing-current-mark'] }] })))
      return Promise.resolve(jsonResponse(rowsFixture({ rows: [equityFixture(0, { nav: null, wealth: null, reasons: ['missing-current-mark'] })] })))
    })
    const user = userEvent.setup()
    renderWithProviders(<ResearchRunReport jobId="job-a" reportSha={digest('d')} />)
    expect(await screen.findByText(/Incomplete result. Retained account facts/)).toBeInTheDocument()
    expect(screen.getByText('1.12 USD')).toBeInTheDocument()
    await user.click(await screen.findByRole('button', { name: 'Positions' }))
    expect(await screen.findByText('SPY · open holding')).toBeInTheDocument()
    expect(screen.getByText(/Quantity 4; cost basis 400; market value Unavailable/)).toBeInTheDocument()
  })

  it('renders server-grouped FIFO fee lineage and exact journal amounts', async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = requestUrl(input)
      if (url.endsWith('/report')) return Promise.resolve(jsonResponse(reportFixture()))
      if (url.includes('kind=fifo')) return Promise.resolve(jsonResponse(rowsFixture({ kind: 'fifo', rows: [{ kind: 'fifo', closing_order_id: 'closing-order-a', symbol: 'SPY', completed: true, quantity: '4', gross_pnl: '35.16', buy_fees: '0.56', sell_fees: '0.56', net_pnl: '34.04', match_ids: ['match-1', 'match-2'], execution_ids: ['buy-fill', 'sell-fill'], split_ids: ['split-a'] }] })))
      if (url.includes('kind=journal')) return Promise.resolve(jsonResponse(rowsFixture({ kind: 'journal', rows: [{ kind: 'journal', entry_id: 'journal-a', sequence: 8, occurred_at: '2026-09-09T12:00:00Z', event_type: 'fill', description: 'Canonical journal fact', amounts: [{ name: 'cash', value: '1044.0400000000' }], source_row_ids: ['sell-fill'] }] })))
      return Promise.resolve(jsonResponse(rowsFixture()))
    })
    const user = userEvent.setup()
    renderWithProviders(<ResearchRunReport jobId="job-a" reportSha={digest('d')} />)
    await user.click(await screen.findByRole('button', { name: 'FIFO trades' }))
    expect(await screen.findByText(/Gross P&L 35.16; buy fees 0.56; sell fees 0.56; net P&L 34.04/)).toBeInTheDocument()
    expect(screen.getByText(/Matches: match-1, match-2/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Journal' }))
    expect(await screen.findByText(/cash: 1044.0400000000/)).toBeInTheDocument()
  })

  it('paginates a bounded curve without substituting another report hash', async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = requestUrl(input)
      if (url.endsWith('/report')) return Promise.resolve(jsonResponse(reportFixture()))
      const offset = Number(new URL(url, 'http://local.test').searchParams.get('offset'))
      return Promise.resolve(jsonResponse(rowsFixture({ offset, total: 201, rows: offset ? [equityFixture(200)] : Array.from({ length: 200 }, (_, index) => equityFixture(index)) })))
    })
    const user = userEvent.setup()
    renderWithProviders(<ResearchRunReport jobId="job-a" reportSha={digest('d')} />)
    await user.click(await screen.findByRole('button', { name: 'Next rows' }))
    expect(await screen.findByText(/Showing 201–201 of 201 equity rows/)).toBeInTheDocument()
    const rowUrls = vi.mocked(fetch).mock.calls.map(([input]) => requestUrl(input)).filter((url) => url.includes('/rows?'))
    expect(rowUrls.at(-1)).toContain(`report_sha256=${digest('d')}&offset=200&limit=200`)
  })

  it('displays a report identity error rather than stale or unrelated results', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(reportFixture({ job_id: 'other-job' })))
    renderWithProviders(<ResearchRunReport jobId="job-a" reportSha={digest('d')} />)
    expect(await screen.findByText(/report identity changed/)).toBeInTheDocument()
    expect(screen.queryByText('0.21 ratio')).not.toBeInTheDocument()
  })
})
