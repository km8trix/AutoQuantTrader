import { screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { makeBootstrapFixture, makeDashboardFixture } from '../api/fixtures'
import type { DashboardSummary } from '../api/types'
import { renderWithProviders } from '../test/render'
import { AppRoutes } from './AppRoutes'

function jsonResponse(body: DashboardSummary): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
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
})
