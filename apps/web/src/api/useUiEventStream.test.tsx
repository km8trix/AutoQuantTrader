import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { renderHook } from '@testing-library/react'
import type { ReactNode } from 'react'
import { describe, expect, it, vi } from 'vitest'

import { useUiEventStream } from './useUiEventStream'

describe('useUiEventStream', () => {
  it('does not construct EventSource when the bootstrap feature flag is disabled', () => {
    const eventSource = vi.fn()
    vi.stubGlobal('EventSource', eventSource)
    const queryClient = new QueryClient()
    const wrapper = ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    )

    const { result } = renderHook(
      () => useUiEventStream({ enabled: false, initialCursor: 'bootstrap-cursor' }),
      { wrapper },
    )

    expect(result.current).toMatchObject({
      cursor: 'bootstrap-cursor',
      status: 'disabled',
    })
    expect(eventSource).not.toHaveBeenCalled()
  })
})
