import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { renderWithProviders } from '../test/render'
import { AppErrorBoundary } from './AppErrorBoundary'

describe('AppErrorBoundary', () => {
  it('enters a safe state and can remount the workspace', async () => {
    let shouldThrow = true
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const UnstableWorkspace = () => {
      if (shouldThrow) {
        throw new Error('render failed')
      }
      return <p>Workspace recovered</p>
    }

    const user = userEvent.setup()
    renderWithProviders(
      <AppErrorBoundary>
        <UnstableWorkspace />
      </AppErrorBoundary>,
    )

    expect(screen.getByRole('heading', { name: 'The workspace could not be rendered' })).toBeInTheDocument()
    expect(screen.getByRole('status', { name: 'Trading environment' })).toHaveTextContent(
      'Environment unknown',
    )

    shouldThrow = false
    await user.click(screen.getByRole('button', { name: 'Retry workspace' }))
    expect(screen.getByText('Workspace recovered')).toBeInTheDocument()
    consoleError.mockRestore()
  })
})
