import { useQueryClient } from '@tanstack/react-query'
import type { QueryKey } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'

import { disabledEventStreamState, UiEventStreamClient } from './eventStream'
import { queryKeys } from './queries'
import type { EventStreamState, UiEvent } from './types'

const bootstrapResources = new Set([
  'ui_bootstrap',
  'environment',
  'readiness',
  'market_clock',
  'capability',
  'feature_flags',
])

const dashboardResources = new Set([
  'dashboard_summary',
  'account',
  'deployment',
  'health',
  'alert',
  'command',
  'walking_thread',
  'risk',
  'reconciliation',
  'position',
  'order',
  'fill',
  'ledger',
])

export function queryKeysForUiEvent(event: UiEvent): QueryKey[] {
  const keys: QueryKey[] = []
  if (bootstrapResources.has(event.resource_type)) {
    keys.push(queryKeys.bootstrap)
  }
  if (dashboardResources.has(event.resource_type)) {
    keys.push(queryKeys.dashboardSummary)
  }
  return keys
}

interface UseUiEventStreamOptions {
  enabled: boolean
  initialCursor: string | null
}

export function useUiEventStream({
  enabled,
  initialCursor,
}: UseUiEventStreamOptions): EventStreamState {
  const queryClient = useQueryClient()
  const cursorRef = useRef<string | null>(null)
  const [state, setState] = useState<EventStreamState>(disabledEventStreamState)

  useEffect(() => {
    if (cursorRef.current === null && initialCursor) {
      cursorRef.current = initialCursor
    }
  }, [initialCursor])

  useEffect(() => {
    if (!enabled) {
      setState({
        ...disabledEventStreamState,
        cursor: cursorRef.current,
      })
      return undefined
    }

    if (typeof EventSource === 'undefined') {
      setState({
        status: 'disconnected',
        cursor: cursorRef.current,
        last_activity_at: null,
        reconnect_attempt: 0,
        detail: 'This browser does not support server-sent events.',
      })
      return undefined
    }

    const client = new UiEventStreamClient({
      initialCursor: cursorRef.current,
      onEvent: (event) => {
        for (const queryKey of queryKeysForUiEvent(event)) {
          void queryClient.invalidateQueries({ queryKey })
        }
      },
      onStateChange: (nextState) => {
        cursorRef.current = nextState.cursor
        setState(nextState)
      },
    })

    client.start()
    return () => {
      client.stop()
    }
  }, [enabled, queryClient])

  return state
}
