import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { EventSourceFactory, EventSourceLike } from './eventStream'
import { UiEventStreamClient } from './eventStream'
import type { EventStreamState, UiEvent } from './types'
import { queryKeysForUiEvent } from './useUiEventStream'

class MockEventSource implements EventSourceLike {
  readonly url: string
  closed = false
  private readonly listeners = new Map<string, Array<(event: Event) => void>>()

  constructor(url: string) {
    this.url = url
  }

  addEventListener(type: string, listener: (event: Event) => void): void {
    const listeners = this.listeners.get(type) ?? []
    listeners.push(listener)
    this.listeners.set(type, listeners)
  }

  close(): void {
    this.closed = true
  }

  emit(type: string, event: Event): void {
    for (const listener of this.listeners.get(type) ?? []) {
      listener(event)
    }
  }
}

function createMockFactory(instances: MockEventSource[]): EventSourceFactory {
  return (url) => {
    const source = new MockEventSource(url)
    instances.push(source)
    return source
  }
}

describe('UiEventStreamClient', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-07-15T14:00:00.000Z'))
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('resumes from the in-memory cursor and reconnects with the latest event ID', () => {
    const instances: MockEventSource[] = []
    const states: EventStreamState[] = []
    const events: UiEvent[] = []
    const client = new UiEventStreamClient({
      initialCursor: 'cursor 7',
      createEventSource: createMockFactory(instances),
      onEvent: (event) => events.push(event),
      onStateChange: (state) => states.push(state),
    })

    client.start()
    expect(instances[0]?.url).toBe('/api/v1/events/stream?after=cursor+7')

    instances[0]?.emit('open', new Event('open'))
    const event: UiEvent = {
      id: 'event-8',
      occurred_at: '2026-07-15T14:00:01.000Z',
      type: 'projection.updated',
      resource_type: 'dashboard_summary',
      resource_id: 'primary',
      resource_version: 8,
    }
    instances[0]?.emit(
      'message',
      new MessageEvent('message', {
        data: JSON.stringify(event),
        lastEventId: 'event-8',
      }),
    )

    expect(events).toEqual([event])
    expect(states.at(-1)).toMatchObject({ cursor: 'event-8', status: 'connected' })

    instances[0]?.emit('error', new Event('error'))
    expect(instances[0]?.closed).toBe(true)
    expect(states.at(-1)?.status).toBe('disconnected')

    vi.advanceTimersByTime(1_000)
    expect(instances[1]?.url).toBe('/api/v1/events/stream?after=event-8')
    expect(states.at(-1)?.status).toBe('connecting')
    client.stop()
  })

  it('marks a silent connection stale and restores freshness on heartbeat', () => {
    const instances: MockEventSource[] = []
    const states: EventStreamState[] = []
    const client = new UiEventStreamClient({
      initialCursor: null,
      createEventSource: createMockFactory(instances),
      onEvent: vi.fn(),
      onStateChange: (state) => states.push(state),
      staleAfterMilliseconds: 30_000,
      staleCheckMilliseconds: 5_000,
    })

    client.start()
    instances[0]?.emit('open', new Event('open'))
    vi.advanceTimersByTime(35_000)

    expect(states.at(-1)?.status).toBe('stale')
    instances[0]?.emit(
      'heartbeat',
      new MessageEvent('heartbeat', {
        data: JSON.stringify({ occurred_at: '2026-07-15T14:00:35.000Z' }),
      }),
    )
    expect(states.at(-1)?.status).toBe('connected')
    client.stop()
  })

  it('ignores malformed events without advancing the resume cursor', () => {
    const instances: MockEventSource[] = []
    const states: EventStreamState[] = []
    const onEvent = vi.fn()
    const client = new UiEventStreamClient({
      initialCursor: 'event-2',
      createEventSource: createMockFactory(instances),
      onEvent,
      onStateChange: (state) => states.push(state),
    })

    client.start()
    instances[0]?.emit('open', new Event('open'))
    instances[0]?.emit(
      'message',
      new MessageEvent('message', { data: '{invalid', lastEventId: 'event-3' }),
    )

    expect(onEvent).not.toHaveBeenCalled()
    expect(states.at(-1)).toMatchObject({ cursor: 'event-2', status: 'stale' })
    client.stop()
  })
})

describe('queryKeysForUiEvent', () => {
  const baseEvent: UiEvent = {
    id: 'event-1',
    occurred_at: '2026-07-15T14:00:00.000Z',
    type: 'projection.updated',
    resource_type: 'dashboard_summary',
    resource_id: 'primary',
    resource_version: 1,
  }

  it('targets dashboard projections without invalidating unrelated queries', () => {
    expect(queryKeysForUiEvent(baseEvent)).toEqual([['dashboard', 'summary']])
  })

  it('targets bootstrap state for readiness events', () => {
    expect(queryKeysForUiEvent({ ...baseEvent, resource_type: 'readiness' })).toEqual([
      ['ui', 'bootstrap'],
    ])
  })

  it('ignores unknown resources', () => {
    expect(queryKeysForUiEvent({ ...baseEvent, resource_type: 'future_resource' })).toEqual([])
  })
})
