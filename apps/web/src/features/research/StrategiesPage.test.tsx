import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { ResearchStrategyCatalogResponse } from '../../api/types'
import { renderWithProviders } from '../../test/render'
import { StrategiesPage } from './StrategiesPage'

const digest = (character: string): string => character.repeat(64)

export function strategyCatalogResponse(): ResearchStrategyCatalogResponse {
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
        parameter_schema_payload: JSON.stringify({ type: 'object', properties: { quantity: { type: 'integer' } } }),
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

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('StrategiesPage', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  it('presents immutable versions, validated parameters, and a pinned launch link', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(strategyCatalogResponse()))

    renderWithProviders(<MemoryRouter><StrategiesPage /></MemoryRouter>)

    expect(screen.getByLabelText('Loading immutable strategy catalog')).toBeInTheDocument()
    expect(await screen.findByText('Buy and hold fixture')).toBeInTheDocument()
    expect(screen.getByText('Version 1.0.0')).toBeInTheDocument()
    expect(screen.getByText('Four-share golden path')).toBeInTheDocument()
    expect(screen.getByText('quantity')).toBeInTheDocument()
    expect(screen.getByText('4')).toBeInTheDocument()
    expect(screen.getByText('Pinned version')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Use in fixture backtest' })).toHaveAttribute(
      'href',
      `/research/backtests?strategy_version=${digest('1')}&configuration=${digest('2')}`,
    )
  })

  it('keeps errors explicit and retries the catalog request', async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonResponse({ detail: 'Strategy evidence is rebuilding.' }, 503))
      .mockResolvedValueOnce(jsonResponse(strategyCatalogResponse()))
    const user = userEvent.setup()

    renderWithProviders(<MemoryRouter><StrategiesPage /></MemoryRouter>)

    expect(await screen.findByText(/Strategy evidence is rebuilding/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('Four-share golden path')).toBeInTheDocument()
  })
})
