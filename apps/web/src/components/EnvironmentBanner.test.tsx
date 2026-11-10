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

  it('keeps complete identity in a wrapping document-flow banner before desktop overrides', () => {
    const account = 'synthetic-account-with-a-long-explicit-identity'
    renderWithProviders(<div style={{ width: 319 }}><EnvironmentBanner environment={{ account_id: account, mode: 'local', name: 'Local retained research environment' }} /></div>)
    const banner = screen.getByRole('status', { name: 'Trading environment' })
    expect(banner).toHaveTextContent('Local simulation — Local retained research environment')
    expect(banner).toHaveTextContent(`Account ${account}`)
    expect(getComputedStyle(banner).position).toBe('relative')
    expect(getComputedStyle(banner).height).toBe('auto')
    expect(getComputedStyle(banner).flexWrap).toBe('wrap')
  })
})
