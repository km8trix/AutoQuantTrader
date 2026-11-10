import { screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { renderWithProviders } from '../../test/render'
import { ResearchStrategiesPage } from './ResearchStrategiesPage'
import { catalogFixture, jsonResponse } from './researchTestFixtures'

describe('actual reference strategies', () => {
  beforeEach(() => { vi.stubGlobal('fetch', vi.fn()) })
  afterEach(() => { vi.unstubAllGlobals() })

  it('shows registered parameters and links into actual run configuration', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(catalogFixture()))
    renderWithProviders(<MemoryRouter><ResearchStrategiesPage /></MemoryRouter>)
    expect(await screen.findByText('Buy and hold')).toBeInTheDocument()
    expect(screen.getByText('SMA trend')).toBeInTheDocument()
    expect(screen.getAllByRole('link', { name: 'Configure a research run' })[0]).toHaveAttribute('href', '/research/backtests?strategy=buy_hold')
    expect(screen.getByRole('link', { name: 'Historical strategy diagnostics' })).toHaveAttribute('href', '/research/history/strategies')
  })

  it('shows empty registered strategies instead of example results', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ ...catalogFixture(), strategies: [] }))
    renderWithProviders(<MemoryRouter><ResearchStrategiesPage /></MemoryRouter>)
    expect(await screen.findByText('No research strategies are registered.')).toBeInTheDocument()
    expect(screen.queryByText('Buy and hold')).not.toBeInTheDocument()
  })

  it('reports API errors without a fixture catalog', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ detail: 'catalog offline' }, 503))
    renderWithProviders(<MemoryRouter><ResearchStrategiesPage /></MemoryRouter>)
    expect(await screen.findByText('catalog offline')).toBeInTheDocument()
    expect(screen.queryByText('Buy and hold')).not.toBeInTheDocument()
  })
})
