import { screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'

import { makeBootstrapFixture } from '../api/fixtures'
import { renderWithProviders } from '../test/render'
import { AppShell } from './AppShell'

describe('AppShell', () => {
  it('keeps environment identity and navigation visible around route content', () => {
    renderWithProviders(
      <MemoryRouter initialEntries={['/overview']}>
        <AppShell bootstrap={makeBootstrapFixture()}>
          <h1>Route content</h1>
        </AppShell>
      </MemoryRouter>,
    )

    expect(screen.getByRole('status', { name: 'Trading environment' })).toHaveTextContent(
      'Local simulation — Local synthetic simulation',
    )
    expect(screen.getByRole('status', { name: 'Trading environment' })).toHaveTextContent(
      'Account synthetic-fixture',
    )
    expect(screen.getByRole('navigation', { name: 'Primary navigation' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Overview/ })).toHaveClass('active')
    expect(screen.getByRole('main')).toContainElement(
      screen.getByRole('heading', { name: 'Route content' }),
    )
    expect(screen.getByRole('group', { name: 'Current operator session' })).not.toHaveAttribute(
      'tabindex',
    )
    expect(screen.queryByRole('button', { name: 'Current operator session' })).not.toBeInTheDocument()
  })

  it('downgrades stale market and readiness snapshots', () => {
    const oldSnapshot = makeBootstrapFixture(new Date(Date.now() - 120_000))
    renderWithProviders(
      <MemoryRouter initialEntries={['/overview']}>
        <AppShell bootstrap={oldSnapshot}>
          <h1>Route content</h1>
        </AppShell>
      </MemoryRouter>,
    )

    expect(screen.getByText('Readiness stale')).toBeInTheDocument()
    expect(screen.getByText('Market clock stale')).toBeInTheDocument()
  })
})
