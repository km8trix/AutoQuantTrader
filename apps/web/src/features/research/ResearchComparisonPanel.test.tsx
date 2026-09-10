import { screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { renderWithProviders } from '../../test/render'
import { ResearchComparisonPanel } from './ResearchComparisonPanel'
import { comparisonFixture, jsonResponse } from './researchTestFixtures'

describe('authoritative research comparison', () => {
  beforeEach(() => { vi.stubGlobal('fetch', vi.fn()) })
  afterEach(() => { vi.unstubAllGlobals() })

  it('requires at least two retained reports without an automatic request', () => {
    renderWithProviders(<ResearchComparisonPanel jobIds={['job-a']} />)
    expect(screen.getByText('Select 2–8 runs with retained reports to compare.')).toBeInTheDocument()
    expect(fetch).not.toHaveBeenCalled()
  })

  it('shows mismatched windows, undefined metrics, cost scenarios and source classes', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(comparisonFixture()))
    renderWithProviders(<ResearchComparisonPanel jobIds={['job-a', 'job-b']} />)
    expect(await screen.findByText(/These results are not directly comparable.*scored-windows-differ/)).toBeInTheDocument()
    expect(screen.getByText(/Scored interval: The server reports different window boundaries/)).toBeInTheDocument()
    expect(screen.getByText('buy_hold · adverse')).toBeInTheDocument()
    expect(screen.getByText('buy_hold · base_1x')).toBeInTheDocument()
    expect(screen.getByText('Undefined')).toBeInTheDocument()
    expect(screen.getByText(/missing-flow-valuation/)).toBeInTheDocument()
    expect(screen.getByText('validated_current_vintage_history')).toBeInTheDocument()
    expect(screen.getByText('synthetic_fixture')).toBeInTheDocument()
    expect(screen.queryByText(/winner|best run|selected candidate/i)).not.toBeInTheDocument()
  })

  it('does not infer differences when the server supplies none', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ ...comparisonFixture(), comparable: true, reasons: [], differences: [] }))
    renderWithProviders(<ResearchComparisonPanel jobIds={['job-a', 'job-b']} />)
    expect(await screen.findByText('The server marks these results comparable.')).toBeInTheDocument()
    expect(screen.queryByText(/Scored interval:/)).not.toBeInTheDocument()
  })

  it('shows an unavailable comparison without fabricated performance', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ detail: 'second report not published' }, 409))
    renderWithProviders(<ResearchComparisonPanel jobIds={['job-a', 'job-b']} />)
    expect(await screen.findByText('second report not published')).toBeInTheDocument()
    expect(screen.queryByText('0.21 ratio')).not.toBeInTheDocument()
  })
})
