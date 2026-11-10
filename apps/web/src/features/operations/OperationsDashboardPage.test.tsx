import { screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { makeBootstrapFixture } from '../../api/fixtures'
import { renderWithProviders } from '../../test/render'
import { makeOperationsDashboardFixture } from './fixtures'
import { OperationsDashboardPage } from './OperationsDashboardPage'
import type { OperationsDashboardSnapshot } from './types'

function jsonResponse(body: OperationsDashboardSnapshot): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('OperationsDashboardPage', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  it('renders every required operational evidence surface from a GET snapshot', async () => {
    const now = new Date()
    vi.mocked(fetch).mockResolvedValue(jsonResponse(makeOperationsDashboardFixture(now)))

    renderWithProviders(
      <OperationsDashboardPage bootstrap={makeBootstrapFixture(now)} />,
    )

    expect(
      await screen.findByRole('heading', { name: 'Authority & freshness' }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('heading', { name: 'Strategy & deployment' }),
    ).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Orders & fills' })).toBeInTheDocument()
    expect(
      screen.getByRole('heading', { name: 'Account & ledger positions' }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('heading', { name: 'Risk reservations & decisions' }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('heading', { name: 'Reconciliation differences' }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('heading', { level: 2, name: 'Critical alerts' }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('heading', { name: 'Audited operational control' }),
    ).toBeInTheDocument()
    expect(screen.getByText('paper-trader-a')).toBeInTheDocument()
    expect(screen.getByText('phase5b-moderate-paper-rth-etf-v1')).toBeInTheDocument()
    expect(screen.queryByText('blocked_pending_convergence')).not.toBeInTheDocument()
    expect(screen.getByText('Blocked Pending Convergence')).toBeInTheDocument()
    expect(screen.getByText('Control API')).toBeInTheDocument()
    expect(
      screen.getByText(/This snapshot panel exposes no control action/),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Pause' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Halt' })).toBeDisabled()
    expect(screen.queryByRole('button', { name: /rearm/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /flatten/i })).not.toBeInTheDocument()
    const dashboardRequest = vi
      .mocked(fetch)
      .mock.calls.find(([input]) => input === '/api/v1/operations/dashboard')
    expect(dashboardRequest).toBeDefined()
    expect(dashboardRequest?.[1]?.method).toBe('GET')
    expect(new Headers(dashboardRequest?.[1]?.headers).get('X-CSRF-Token')).toBe(
      'development-fixture-csrf-token',
    )
  })

  it('warns instead of inferring readiness from a stale snapshot', async () => {
    const now = new Date()
    const snapshot = makeOperationsDashboardFixture(now)
    snapshot.as_of = new Date(now.getTime() - 60_000).toISOString()
    vi.mocked(fetch).mockResolvedValue(jsonResponse(snapshot))

    renderWithProviders(
      <OperationsDashboardPage bootstrap={makeBootstrapFixture(now)} />,
    )

    expect(
      await screen.findByText(/One or more operational facts are stale or unavailable/),
    ).toBeInTheDocument()
  })
})
