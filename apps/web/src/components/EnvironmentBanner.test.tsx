import { screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { renderWithProviders } from '../test/render'
import { EnvironmentBanner } from './EnvironmentBanner'

describe('EnvironmentBanner', () => {
  it('identifies paper mode with text and the account', () => {
    renderWithProviders(
      <EnvironmentBanner
        environment={{ account_id: 'paper-1234', mode: 'paper', name: 'Paper east' }}
      />,
    )

    expect(screen.getByRole('status', { name: 'Trading environment' })).toHaveTextContent(
      'Paper trading — Paper east',
    )
    expect(screen.getByText(/Account paper-1234/)).toBeInTheDocument()
  })

  it('fails visibly when environment identity is unavailable', () => {
    renderWithProviders(<EnvironmentBanner unavailable />)

    const banner = screen.getByRole('status')
    expect(banner).toHaveTextContent(
      'Environment unknown — control state unavailable',
    )
    expect(getComputedStyle(banner).color).toBe('rgb(255, 255, 255)')
  })
})
