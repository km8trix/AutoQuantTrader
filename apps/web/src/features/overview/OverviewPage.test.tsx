import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { makeBootstrapFixture, makeDashboardFixture } from '../../api/fixtures'
import type { DashboardSummary } from '../../api/types'
import { renderWithProviders } from '../../test/render'
import { OverviewPage } from './OverviewPage'

function jsonResponse(body: DashboardSummary, init?: ResponseInit): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
}

describe('OverviewPage', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  it('renders account metrics, health, and the canonical trace from the API', async () => {
    const now = new Date()
    const summary = makeDashboardFixture(now)
    vi.mocked(fetch).mockResolvedValue(jsonResponse(summary))

    renderWithProviders(<OverviewPage bootstrap={makeBootstrapFixture(now)} />)

    expect(await screen.findByText('$100,248.32')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'System health' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Canonical walking thread' })).toBeInTheDocument()
    expect(screen.getByText('Market event accepted')).toBeInTheDocument()
    expect(screen.getByText('Ledger balanced')).toBeInTheDocument()
    expect(screen.getByText('Control API')).toBeInTheDocument()
  })

  it('marks an old operational snapshot as stale', async () => {
    const now = new Date()
    const summary = makeDashboardFixture(now)
    summary.as_of = new Date(now.getTime() - 120_000).toISOString()
    vi.mocked(fetch).mockResolvedValue(jsonResponse(summary))

    renderWithProviders(<OverviewPage bootstrap={makeBootstrapFixture(now)} />)

    expect(
      await screen.findByText(/This operational snapshot is stale/),
    ).toBeInTheDocument()
  })

  it('shows an API error and lets the operator retry', async () => {
    const now = new Date()
    const summary = makeDashboardFixture(now)
    const unavailableResponse = () =>
      new Response(
        JSON.stringify({ title: 'Service unavailable', detail: 'Projection is rebuilding.' }),
        { status: 503, headers: { 'Content-Type': 'application/problem+json' } },
      )
    vi.mocked(fetch)
      .mockResolvedValueOnce(unavailableResponse())
      .mockResolvedValueOnce(jsonResponse(summary))

    const user = userEvent.setup()
    renderWithProviders(<OverviewPage bootstrap={makeBootstrapFixture(now)} />)

    expect(await screen.findByText(/Projection is rebuilding/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Retry' }))

    expect(await screen.findByText('$100,248.32')).toBeInTheDocument()
  })
})
