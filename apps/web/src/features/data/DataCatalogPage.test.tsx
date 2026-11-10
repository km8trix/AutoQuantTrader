import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { makeDataCatalogFixture } from '../../api/fixtures'
import type { DataCatalogResponse } from '../../api/types'
import { renderWithProviders } from '../../test/render'
import { DataCatalogPage } from './DataCatalogPage'

function jsonResponse(body: DataCatalogResponse): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('DataCatalogPage', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  it('shows the synthetic qualification boundary and complete catalog evidence', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(makeDataCatalogFixture()))

    renderWithProviders(<DataCatalogPage />)

    expect(screen.getByLabelText('Loading data catalog')).toBeInTheDocument()
    expect(screen.getByText(/Vendor admission is fail-closed/)).toBeInTheDocument()
    expect(await screen.findByRole('table', { name: 'Ingestion jobs' })).toBeInTheDocument()
    expect(screen.getByText('job-fixture-20260714-001')).toBeInTheDocument()
    expect(screen.getByText('Synthetic XNYS one-minute raw bars')).toBeInTheDocument()
    expect(
      screen.getByRole('table', { name: 'Synthetic XNYS one-minute raw bars ordered partitions' }),
    ).toBeInTheDocument()
    expect(screen.getAllByText('US-ETF-FIXTURE-DELISTED').length).toBeGreaterThan(0)
    expect(screen.getByText('Symbol Change')).toBeInTheDocument()
    expect(screen.getAllByText('Unlicensed').length).toBeGreaterThan(0)
    expect(screen.getByText('Synthetic fixture admission contract')).toBeInTheDocument()
    expect(
      screen.getByRole('table', { name: 'Synthetic fixture admission contract admission checks' }),
    ).toBeInTheDocument()
    expect(screen.getByText(/No market-data source is admitted/)).toBeInTheDocument()
    expect(screen.getByText(/not admitted for paper or live trading/)).toBeInTheDocument()
  })

  it('renders explicit empty states without inferring readiness', async () => {
    const catalog = makeDataCatalogFixture()
    catalog.source = null
    catalog.jobs = []
    catalog.manifests = []
    catalog.instruments = []
    catalog.corporate_actions = []
    catalog.entitlements = []
    catalog.admissions = []
    vi.mocked(fetch).mockResolvedValue(jsonResponse(catalog))

    renderWithProviders(<DataCatalogPage />)

    expect(await screen.findByText('No ingestion jobs')).toBeInTheDocument()
    expect(screen.getByText('No published manifests')).toBeInTheDocument()
    expect(screen.getByText('No security lifecycle records')).toBeInTheDocument()
    expect(screen.getByText('No corporate actions')).toBeInTheDocument()
    expect(screen.getByText('No entitlement evidence')).toBeInTheDocument()
    expect(screen.getByText('No admission evidence')).toBeInTheDocument()
    expect(screen.getByText(/No historical data source is configured/)).toBeInTheDocument()
  })

  it('shows API errors and retries the catalog request', async () => {
    const unavailable = new Response(
      JSON.stringify({ title: 'Catalog unavailable', detail: 'Manifest index is rebuilding.' }),
      { status: 503, headers: { 'Content-Type': 'application/problem+json' } },
    )
    vi.mocked(fetch)
      .mockResolvedValueOnce(unavailable)
      .mockResolvedValueOnce(jsonResponse(makeDataCatalogFixture()))

    const user = userEvent.setup()
    renderWithProviders(<DataCatalogPage />)

    expect(await screen.findByText(/Manifest index is rebuilding/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Retry' }))

    expect(await screen.findByText('job-fixture-20260714-001')).toBeInTheDocument()
  })
})
