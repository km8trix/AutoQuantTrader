import { screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { renderWithProviders } from '../../test/render'
import { ResearchEquityChart } from './ResearchEquityChart'
import { equityFixture } from './researchTestFixtures'

describe('event-valued research chart', () => {
  it('breaks NAV at a missing mark and preserves independent benchmark observations', () => {
    renderWithProviders(<ResearchEquityChart view="nav" points={[equityFixture(0), equityFixture(1, { nav: null, reasons: ['missing-current-mark'], last_known_nav: '1000', last_known_at: '2026-09-08T20:00:00Z' }), equityFixture(2, { nav: '1100' })]} />)
    expect(screen.getAllByLabelText(/Strategy segment/)).toHaveLength(2)
    expect(screen.getAllByLabelText(/Analytical SPY segment/)).toHaveLength(1)
    expect(screen.getByText(/missing-current-mark/)).toBeInTheDocument()
    expect(screen.getByText(/Last-known NAV estimate: 1000/)).toBeInTheDocument()
    expect(screen.getByText(/Strategy: Unavailable/)).toBeInTheDocument()
  })

  it('does not invent resumed wealth after a latched return gap', () => {
    renderWithProviders(<ResearchEquityChart view="wealth" points={[equityFixture(0), equityFixture(1, { wealth: null, reasons: ['missing-flow-valuation'] }), equityFixture(2, { nav: '1200', wealth: null, reasons: ['prior-path-unavailable'] })]} />)
    expect(screen.getAllByLabelText(/Strategy segment/)).toHaveLength(1)
    expect(screen.getAllByText(/Strategy: Unavailable/)).toHaveLength(2)
    expect(screen.getByText('Flow-neutral wealth index')).toBeInTheDocument()
  })

  it('preserves distinct same-time pre/post-flow rows and exact decimals', () => {
    renderWithProviders(<ResearchEquityChart view="nav" points={[equityFixture(4, { roles: ['pre_flow'], nav: '1000.1234567890123456789', flow_id: 'flow-a', paired_row_id: 'valuation-5' }), equityFixture(5, { roles: ['post_flow'], nav: '1100.1234567890123456789', signed_flow: '100', flow_id: 'flow-a', paired_row_id: 'valuation-4' })]} />)
    expect(screen.getByText(/sequence 4 · pre_flow/)).toBeInTheDocument()
    expect(screen.getByText(/sequence 5 · post_flow/)).toBeInTheDocument()
    expect(screen.getByText(/Strategy: 1000.1234567890123456789/)).toBeInTheDocument()
    const segment = screen.getByLabelText('Strategy segment 1').getAttribute('points')
    expect(segment?.split(' ')).toHaveLength(2)
    expect(segment?.split(' ')[0]).not.toBe(segment?.split(' ')[1])
  })

  it('shows unavailable series without null-to-zero conversion', () => {
    renderWithProviders(<ResearchEquityChart view="nav" points={[equityFixture(0, { nav: null, benchmark_nav: null, cash_nav: null })]} />)
    expect(screen.getByText('No defined values are available for this view.')).toBeInTheDocument()
    expect(screen.queryByRole('img')).not.toBeInTheDocument()
  })

  it('accepts a known zero NAV and rejects out-of-order sequences', () => {
    const { rerender } = renderWithProviders(<ResearchEquityChart view="nav" points={[equityFixture(0, { nav: '0' })]} />)
    expect(screen.getByText(/Strategy: 0;/)).toBeInTheDocument()
    rerender(<ResearchEquityChart view="nav" points={[equityFixture(2), equityFixture(1)]} />)
    expect(screen.getByText('Valuation sequences are not strictly ordered.')).toBeInTheDocument()
  })
})
