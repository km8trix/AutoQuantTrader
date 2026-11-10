import { screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { makeDataQualityFixture } from '../../api/fixtures'
import type { DataQualityResponse } from '../../api/types'
import { renderWithProviders } from '../../test/render'
import { DataQualityPage } from './DataQualityPage'

function jsonResponse(body: DataQualityResponse): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('DataQualityPage', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  it('shows quality findings, quarantine, and the evidence boundary', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(makeDataQualityFixture()))

    renderWithProviders(<DataQualityPage />)

    expect(screen.getByLabelText('Loading data quality evidence')).toBeInTheDocument()
    expect(screen.getByText(/Synthetic fixture evidence only/)).toBeInTheDocument()
    expect(await screen.findByRole('table', { name: 'Data quality issues' })).toBeInTheDocument()
    expect(screen.getByText('Invalid Ohlc')).toBeInTheDocument()
    expect(screen.getByText('High price is below the close price')).toBeInTheDocument()
    expect(screen.getByRole('table', { name: 'Quarantined partitions' })).toBeInTheDocument()
    expect(screen.getByText(/excluded from dataset manifests/)).toBeInTheDocument()
    expect(screen.getByText(/does not qualify a licensed vendor feed/)).toBeInTheDocument()
  })

  it('distinguishes an empty quality projection from vendor qualification', async () => {
    const quality = makeDataQualityFixture()
    quality.issues = []
    quality.quarantine = []
    vi.mocked(fetch).mockResolvedValue(jsonResponse(quality))

    renderWithProviders(<DataQualityPage />)

    expect(await screen.findByText('No quality issues')).toBeInTheDocument()
    expect(screen.getByText('Quarantine is empty')).toBeInTheDocument()
    expect(screen.getByText(/does not qualify an external vendor feed/)).toBeInTheDocument()
  })

  it('shows a fail-closed API error instead of an empty healthy projection', async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(
        JSON.stringify({
          title: 'Quality unavailable',
          detail: 'The quality evidence projection is rebuilding.',
        }),
        { status: 503, headers: { 'Content-Type': 'application/problem+json' } },
      ),
    )

    renderWithProviders(<DataQualityPage />)

    expect(await screen.findByText(/quality evidence projection is rebuilding/)).toBeInTheDocument()
    expect(screen.queryByText('No quality issues')).not.toBeInTheDocument()
  })
})
