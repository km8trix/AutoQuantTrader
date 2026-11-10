import { fireEvent, screen, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { makeBootstrapFixture, makeDashboardFixture } from '../../api/fixtures'
import type { DashboardSummary } from '../../api/types'
import { renderWithProviders } from '../../test/render'
import { AuditPage } from './AuditPage'
import { ReconciliationPage } from './ReconciliationPage'
import { RiskPage } from './RiskPage'
import { SettingsPage } from './SettingsPage'

function jsonResponse(body: DashboardSummary): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('Phase 5 read-only operations pages', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  it('shows trusted risk context and marks every unavailable policy signal', async () => {
    const now = new Date()
    const summary = makeDashboardFixture(now)
    summary.alerts.critical = 2
    summary.alerts.warning = 1
    summary.pending_commands = 3
    vi.mocked(fetch).mockResolvedValue(jsonResponse(summary))

    renderWithProviders(<RiskPage bootstrap={makeBootstrapFixture(now)} />)

    expect(
      await screen.findByRole('heading', { name: 'Risk policy evidence' }),
    ).toBeInTheDocument()
    expect(screen.getByText('synthetic-fixture')).toBeInTheDocument()
    expect(screen.getAllByText('Not exposed')).toHaveLength(7)
    expect(screen.getByText('Session loss observations and approved loss thresholds are not exposed.')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(
      screen.getByText(/does not advertise operational controls/),
    ).toBeInTheDocument()

    const controls = screen.getByRole('group', { name: 'Operational controls' })
    expect(within(controls).getByRole('button', { name: 'Pause' })).toBeDisabled()
    expect(within(controls).getByRole('button', { name: 'Halt' })).toBeDisabled()
    expect(within(controls).queryByRole('button', { name: 'Rearm' })).not.toBeInTheDocument()
  })

  it('does not present readiness as authoritative reconciliation evidence', async () => {
    const now = new Date()
    const summary = makeDashboardFixture(now)
    vi.mocked(fetch).mockResolvedValue(jsonResponse(summary))

    renderWithProviders(<ReconciliationPage bootstrap={makeBootstrapFixture(now)} />)

    expect(
      await screen.findByRole('heading', {
        name: 'Reconciliation authority unavailable',
      }),
    ).toBeInTheDocument()
    expect(screen.getByText(/Current agreement is not authoritative/)).toBeInTheDocument()
    expect(
      screen.getByRole('heading', { name: 'Related subsystem health' }),
    ).toBeInTheDocument()
    expect(screen.getByText('Execution')).toBeInTheDocument()
    expect(screen.getByText('Ledger')).toBeInTheDocument()
  })

  it('separates dashboard causal steps from an operator audit history', async () => {
    const now = new Date()
    vi.mocked(fetch).mockResolvedValue(jsonResponse(makeDashboardFixture(now)))

    renderWithProviders(<AuditPage bootstrap={makeBootstrapFixture(now)} />)

    expect(
      await screen.findByRole('heading', {
        name: 'Authoritative audit history unavailable',
      }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('heading', { name: 'Recent causal trace — not audit history' }),
    ).toBeInTheDocument()
    expect(screen.getByText('Market event accepted')).toBeInTheDocument()
    expect(screen.getByText(/does not prove who initiated any historical action/)).toBeInTheDocument()
  })

  it('shows bootstrap capabilities and exposes only granular fail-safe controls', async () => {
    const now = new Date()
    const bootstrap = makeBootstrapFixture(now)
    bootstrap.feature_flags.controls = true
    bootstrap.feature_flags.operations_control = true
    bootstrap.feature_flags.control_pause = true
    bootstrap.feature_flags.control_halt = true
    vi.mocked(fetch).mockResolvedValue(jsonResponse(makeDashboardFixture(now)))

    renderWithProviders(<SettingsPage bootstrap={bootstrap} />)

    expect(
      await screen.findByRole('heading', { name: 'Advertised capabilities' }),
    ).toBeInTheDocument()
    expect(screen.getByText('Research')).toBeInTheDocument()
    const flags = screen.getByRole('list', { name: 'Feature flags' })
    expect(within(flags).getByText('controls')).toBeInTheDocument()
    expect(screen.getByText(/PAUSE and HALT are fail-safe actions/)).toBeInTheDocument()
    const controls = screen.getByRole('group', { name: 'Operational controls' })
    for (const name of ['Pause', 'Halt']) {
      expect(within(controls).getByRole('button', { name })).toBeDisabled()
    }
    for (const name of ['Drain', 'Flatten', 'Rearm']) {
      expect(within(controls).queryByRole('button', { name })).not.toBeInTheDocument()
    }
  })

  it('does not use stale readiness and dashboard evidence to block fail-safe controls', async () => {
    const now = new Date()
    const old = new Date(now.getTime() - 120_000).toISOString()
    const bootstrap = makeBootstrapFixture(now)
    bootstrap.feature_flags.operations_control = true
    bootstrap.feature_flags.control_pause = true
    bootstrap.feature_flags.control_halt = true
    bootstrap.readiness.as_of = old
    const summary = makeDashboardFixture(now)
    summary.as_of = old
    vi.mocked(fetch).mockResolvedValue(jsonResponse(summary))

    renderWithProviders(<RiskPage bootstrap={bootstrap} />)

    expect(
      await screen.findByText(/Operational evidence is stale/),
    ).toBeInTheDocument()
    expect(
      await screen.findByText(/Stale or not-ready evidence does not/),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Pause' })).toBeDisabled()
  })

  it('reads an explicitly named stored selection when operational dashboard data is unavailable', async () => {
    const bootstrap = makeBootstrapFixture(new Date())
    bootstrap.readiness.status = 'not_ready'
    const account = 'operator-explicit-account'
    const token = 'm'.repeat(43)
    const selectionPath = `/api/v1/operations/accounts/${account}/continuous-selection`
    vi.mocked(fetch).mockImplementation((input) => {
      const path = typeof input === 'string'
        ? input
        : input instanceof URL ? input.pathname : input.url
      const body = path === '/api/v1/ui/metadata-bootstrap'
        ? {
          enabled: true, operator_id: 'local-operator', csrf_token: token,
          csrf_header: 'X-Metadata-CSRF-Token', expires_at: '2026-10-22T12:00:00Z',
          disabled_reason: null, scope: 'continuous-selection-read/1',
          verification: 'row_integrity_only',
        }
        : path === selectionPath
          ? { account_id: account, state: 'absent', checkpoint: null, selection: null, verification: 'row_integrity_only' }
          : { detail: 'Operational dashboard unavailable' }
      return Promise.resolve(new Response(JSON.stringify(body), {
        status: path === '/api/v1/ui/metadata-bootstrap' || path === selectionPath ? 200 : 503,
        headers: { 'Content-Type': 'application/json' },
      }))
    })

    renderWithProviders(<SettingsPage bootstrap={bootstrap} />)
    const panel = screen.getByRole('region', { name: 'Stored continuous selection' })
    const input = within(panel).getByRole('textbox', { name: 'Account ID' })
    expect(input).toHaveValue('')
    expect(account).not.toBe(bootstrap.environment.account_id)
    expect(vi.mocked(fetch).mock.calls.some(([path]) => (
      typeof path === 'string' && path.includes('metadata-bootstrap')
    ))).toBe(false)
    fireEvent.change(input, { target: { value: account } })
    fireEvent.click(within(panel).getByRole('button', { name: 'Read stored selection' }))
    expect(await within(panel).findByText('No retained account checkpoint or selection was found.')).toBeInTheDocument()
    expect(await screen.findByText(/Operational data is unavailable: Operational dashboard unavailable/)).toBeInTheDocument()
    expect(within(panel).getByText(account)).toBeInTheDocument()
    const metadataCalls = vi.mocked(fetch).mock.calls.filter(([path]) => (
      path === '/api/v1/ui/metadata-bootstrap' || path === selectionPath
    ))
    expect(metadataCalls).toHaveLength(2)
    for (const [, options] of metadataCalls) {
      expect(options).toMatchObject({ method: 'GET', credentials: 'same-origin', cache: 'no-store' })
      expect(options?.body).toBeUndefined()
      expect(options?.headers).not.toHaveProperty('X-CSRF-Token')
      expect(options?.headers).not.toHaveProperty('Idempotency-Key')
    }
    expect(metadataCalls[1]?.[1]?.headers).toMatchObject({ 'X-Metadata-CSRF-Token': token })
    expect(screen.queryByRole('button', { name: 'Rearm' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Enable' })).not.toBeInTheDocument()
  })

  it('renders server-provided readiness blockers without inventing a cause', async () => {
    const now = new Date()
    const bootstrap = makeBootstrapFixture(now)
    bootstrap.feature_flags.operations_control = true
    bootstrap.feature_flags.control_pause = true
    bootstrap.feature_flags.control_halt = true
    bootstrap.readiness.status = 'not_ready'
    bootstrap.readiness.reasons = [
      'reconciliation_pending',
      'market_data_freshness_failed',
    ]
    vi.mocked(fetch).mockResolvedValue(jsonResponse(makeDashboardFixture(now)))

    renderWithProviders(<SettingsPage bootstrap={bootstrap} />)

    expect(await screen.findByText('reconciliation_pending')).toBeInTheDocument()
    expect(screen.getByText('market_data_freshness_failed')).toBeInTheDocument()
    expect(screen.getByText(/Stale or not-ready evidence does not/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Pause' })).toBeDisabled()
  })
})
