import type { EventStreamState, UiEvent, UiHeartbeat } from './types'

const DEFAULT_STALE_AFTER_MS = 35_000
const DEFAULT_STALE_CHECK_MS = 5_000
const MAX_RECONNECT_DELAY_MS = 30_000

export interface EventSourceLike {
  addEventListener(type: string, listener: (event: Event) => void): void
  close(): void
}

export type EventSourceFactory = (url: string) => EventSourceLike

interface UiEventStreamClientOptions {
  initialCursor: string | null
  onEvent: (event: UiEvent) => void
  onStateChange: (state: EventStreamState) => void
  createEventSource?: EventSourceFactory
  staleAfterMilliseconds?: number
  staleCheckMilliseconds?: number
  now?: () => number
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function isUiEvent(value: unknown): value is UiEvent {
  if (!isRecord(value)) {
    return false
  }

  return (
    typeof value.id === 'string' &&
    typeof value.occurred_at === 'string' &&
    typeof value.type === 'string' &&
    typeof value.resource_type === 'string' &&
    typeof value.resource_id === 'string' &&
    (typeof value.resource_version === 'number' || typeof value.resource_version === 'string')
  )
}

function isUiHeartbeat(value: unknown): value is UiHeartbeat {
  return isRecord(value) && typeof value.occurred_at === 'string'
}

function nativeEventSourceFactory(url: string): EventSourceLike {
  return new EventSource(url, { withCredentials: true })
}

export const disabledEventStreamState: EventStreamState = {
  status: 'disabled',
  cursor: null,
  last_activity_at: null,
  reconnect_attempt: 0,
  detail: 'Live updates are disabled for this environment.',
}

export class UiEventStreamClient {
  private readonly onEvent: (event: UiEvent) => void
  private readonly onStateChange: (state: EventStreamState) => void
  private readonly createEventSource: EventSourceFactory
  private readonly staleAfterMilliseconds: number
  private readonly staleCheckMilliseconds: number
  private readonly now: () => number
  private cursor: string | null
  private source: EventSourceLike | null = null
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private staleTimer: ReturnType<typeof setInterval> | null = null
  private stopped = true
  private reconnectAttempt = 0
  private lastActivityAt: number | null = null
  private status: EventStreamState['status'] = 'disabled'

  constructor(options: UiEventStreamClientOptions) {
    this.cursor = options.initialCursor
    this.onEvent = options.onEvent
    this.onStateChange = options.onStateChange
    this.createEventSource = options.createEventSource ?? nativeEventSourceFactory
    this.staleAfterMilliseconds = options.staleAfterMilliseconds ?? DEFAULT_STALE_AFTER_MS
    this.staleCheckMilliseconds = options.staleCheckMilliseconds ?? DEFAULT_STALE_CHECK_MS
    this.now = options.now ?? Date.now
  }

  start(): void {
    if (!this.stopped) {
      return
    }

    this.stopped = false
    this.publishState('connecting', 'Connecting to live updates.')
    this.connect()
    this.staleTimer = setInterval(() => {
      this.checkFreshness()
    }, this.staleCheckMilliseconds)
  }

  stop(): void {
    this.stopped = true
    this.source?.close()
    this.source = null
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    if (this.staleTimer) {
      clearInterval(this.staleTimer)
      this.staleTimer = null
    }
  }

  private connect(): void {
    if (this.stopped) {
      return
    }

    const search = this.cursor ? `?${new URLSearchParams({ after: this.cursor }).toString()}` : ''
    try {
      this.source = this.createEventSource(`/api/v1/events/stream${search}`)
      this.source.addEventListener('open', this.handleOpen)
      this.source.addEventListener('message', this.handleMessage)
      this.source.addEventListener('heartbeat', this.handleHeartbeat)
      this.source.addEventListener('error', this.handleError)
    } catch (error) {
      const detail = error instanceof Error ? error.message : 'EventSource is unavailable.'
      this.scheduleReconnect(detail)
    }
  }

  private readonly handleOpen = () => {
    this.reconnectAttempt = 0
    this.recordActivity()
    this.publishState('connected', 'Live updates are connected.')
  }

  private readonly handleMessage = (event: Event) => {
    if (!(event instanceof MessageEvent)) {
      this.publishState('stale', 'A malformed live-update event was ignored.')
      return
    }

    try {
      const parsed: unknown = JSON.parse(String(event.data))
      if (!isUiEvent(parsed)) {
        this.publishState('stale', 'A live-update event failed contract validation.')
        return
      }

      this.cursor = event.lastEventId || parsed.id
      this.recordActivity()
      this.publishState('connected', 'Live updates are connected.')
      this.onEvent(parsed)
    } catch {
      this.publishState('stale', 'A live-update event contained invalid JSON.')
    }
  }

  private readonly handleHeartbeat = (event: Event) => {
    if (!(event instanceof MessageEvent)) {
      return
    }

    try {
      const parsed: unknown = JSON.parse(String(event.data))
      if (!isUiHeartbeat(parsed)) {
        return
      }

      if (event.lastEventId) {
        this.cursor = event.lastEventId
      }
      this.recordActivity()
      this.publishState('connected', 'Live updates are connected.')
    } catch {
      // A malformed heartbeat cannot advance freshness or the event cursor.
    }
  }

  private readonly handleError = () => {
    this.source?.close()
    this.source = null
    this.scheduleReconnect('The live-update connection was interrupted.')
  }

  private recordActivity(): void {
    this.lastActivityAt = this.now()
  }

  private checkFreshness(): void {
    if (
      this.lastActivityAt === null ||
      this.stopped ||
      (this.status !== 'connected' && this.status !== 'stale')
    ) {
      return
    }

    const age = this.now() - this.lastActivityAt
    if (age > this.staleAfterMilliseconds * 2) {
      this.source?.close()
      this.source = null
      this.scheduleReconnect('No heartbeat was received; reconnecting live updates.')
      return
    }

    if (age > this.staleAfterMilliseconds && this.status === 'connected') {
      this.publishState('stale', 'Live updates are stale; awaiting a heartbeat.')
    }
  }

  private scheduleReconnect(detail: string): void {
    if (this.stopped || this.reconnectTimer) {
      return
    }

    this.reconnectAttempt += 1
    const delay = Math.min(1_000 * 2 ** (this.reconnectAttempt - 1), MAX_RECONNECT_DELAY_MS)
    this.publishState('disconnected', `${detail} Retrying in ${Math.round(delay / 1_000)}s.`)
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null
      this.publishState('connecting', 'Reconnecting to live updates.')
      this.connect()
    }, delay)
  }

  private publishState(status: EventStreamState['status'], detail: string): void {
    this.status = status
    this.onStateChange({
      status,
      cursor: this.cursor,
      last_activity_at:
        this.lastActivityAt === null ? null : new Date(this.lastActivityAt).toISOString(),
      reconnect_attempt: this.reconnectAttempt,
      detail,
    })
  }
}
