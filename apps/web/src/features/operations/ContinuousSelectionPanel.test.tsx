import { act, fireEvent, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { renderWithProviders } from '../../test/render'
import { ContinuousSelectionPanel } from './ContinuousSelectionPanel'
import type { ContinuousSelection } from './continuousSelectionApi'

const ACCOUNT = 'explicit-account-001'
const OTHER_ACCOUNT = 'explicit-account-002'
const BOOTSTRAP = '/api/v1/ui/metadata-bootstrap'
const CSRF = 'm'.repeat(43)
const RECORDED_AT = '2026-10-21T12:34:56.123456Z'
const EFFECTIVE_AT = '2026-10-21T12:35:00+00:00'

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function bootstrap(): Response {
  return response({
    enabled: true,
    operator_id: 'local-operator',
    csrf_token: CSRF,
    csrf_header: 'X-Metadata-CSRF-Token',
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    disabled_reason: null,
    scope: 'continuous-selection-read/1',
    verification: 'row_integrity_only',
  })
}

function selection(accountId = ACCOUNT): ContinuousSelection {
  return {
    account_id: accountId,
    state: 'selected',
    checkpoint: {
      stream_id: 'retained-stream-001',
      sequence: '9007199254740993',
      recorded_at: RECORDED_AT,
    },
    selection: {
      generation: '9223372036854775807',
      strategy_name: 'reference-buy-and-hold',
      strategy_version: '1',
      configuration_sha256: 'a'.repeat(64),
      instruments: [{ instrument_id: 'instrument-spy', symbol: 'SPY' }],
      policy_id: 'product-daily-risk/1',
      enabled_for_new_exposure: false,
      live_authorized: false,
      recorded_at: RECORDED_AT,
      effective_at: EFFECTIVE_AT,
    },
    verification: 'row_integrity_only',
  }
}

function path(accountId = ACCOUNT): string {
  return `/api/v1/operations/accounts/${accountId}/continuous-selection`
}

function url(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input
  if (input instanceof URL) return input.toString()
  return input.url
}

function deferred() {
  let resolve!: (value: Response) => void
  let reject!: (reason: Error) => void
  const promise = new Promise<Response>((accept, deny) => {
    resolve = accept
    reject = deny
  })
  return { promise, resolve, reject }
}

function provide(record: ContinuousSelection) {
  vi.mocked(fetch).mockImplementation((input) => Promise.resolve(
    url(input) === BOOTSTRAP ? bootstrap() : response(record),
  ))
}

async function submit(accountId = ACCOUNT) {
  const user = userEvent.setup()
  await user.type(screen.getByRole('textbox', { name: 'Account ID' }), accountId)
  await user.click(screen.getByRole('button', { name: 'Read stored selection' }))
}

describe('Manual stored continuous-selection reads', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  it('starts empty and never infers an account or fetches before explicit submission', async () => {
    renderWithProviders(<ContinuousSelectionPanel />)
    expect(screen.getByRole('textbox', { name: 'Account ID' })).toHaveValue('')
    expect(screen.getByRole('button', { name: 'Read stored selection' })).toBeDisabled()
    expect(screen.getByText(/does not establish authenticated owner history/)).toBeInTheDocument()
    expect(fetch).not.toHaveBeenCalled()
    await userEvent.type(screen.getByRole('textbox', { name: 'Account ID' }), ACCOUNT)
    expect(screen.getByRole('button', { name: 'Read stored selection' })).toBeEnabled()
    expect(fetch).not.toHaveBeenCalled()
    for (const name of ['Enable', 'Rearm', 'Initialize', 'Pause', 'Halt', 'Assign']) {
      expect(screen.queryByRole('button', { name })).not.toBeInTheDocument()
    }
  })

  it.each([' leading', 'trailing ', 'account/name', '_account', 'a'.repeat(65)])(
    'rejects invalid account input without normalizing or requesting: %s',
    (value) => {
      renderWithProviders(<ContinuousSelectionPanel />)
      fireEvent.change(screen.getByRole('textbox', { name: 'Account ID' }), { target: { value } })
      expect(screen.getByRole('button', { name: 'Read stored selection' })).toBeDisabled()
      fireEvent.submit(screen.getByRole('form', { name: 'Read stored selection' }))
      expect(fetch).not.toHaveBeenCalled()
    },
  )

  it('uses only manual metadata GETs even when operational endpoints are unavailable', async () => {
    vi.mocked(fetch).mockImplementation((input) => Promise.resolve(
      url(input) === BOOTSTRAP
        ? bootstrap()
        : url(input) === path()
          ? response(selection())
          : response({ detail: 'operational readiness unavailable' }, 503),
    ))
    renderWithProviders(<ContinuousSelectionPanel />)
    await submit()
    expect(await screen.findByText('A retained selection record is stored.')).toBeInTheDocument()
    expect(fetch).toHaveBeenCalledTimes(2)
    expect(vi.mocked(fetch).mock.calls.map(([input]) => url(input))).toEqual([BOOTSTRAP, path()])
    for (const [, options] of vi.mocked(fetch).mock.calls) {
      expect(options?.method ?? 'GET').toBe('GET')
      expect(options?.body).toBeUndefined()
    }
    expect(new Headers(vi.mocked(fetch).mock.calls[1]?.[1]?.headers).get('X-Metadata-CSRF-Token')).toBe(CSRF)
    expect(screen.getByText('9007199254740993')).toBeInTheDocument()
    expect(screen.getByText('9223372036854775807')).toBeInTheDocument()
    expect(screen.queryByText('9007199254740992')).not.toBeInTheDocument()
    expect(screen.getAllByText(RECORDED_AT)).toHaveLength(2)
    expect(screen.getByText(EFFECTIVE_AT)).toBeInTheDocument()
    expect(screen.getByText('a'.repeat(64))).toBeInTheDocument()
    expect(screen.getByText('SPY (instrument-spy)')).toBeInTheDocument()
    expect(screen.getByText('retained-stream-001')).toBeInTheDocument()
    expect(screen.getByText('reference-buy-and-hold')).toBeInTheDocument()
    expect(screen.getAllByText('false')).toHaveLength(2)
    expect(screen.queryByText(/^(ready|active)$/i)).not.toBeInTheDocument()
  })

  it.each(['absent', 'unselected'] as const)('renders %s without invented selection values', async (state) => {
    const record = selection()
    record.state = state
    record.selection = null
    if (state === 'absent') record.checkpoint = null
    provide(record)
    renderWithProviders(<ContinuousSelectionPanel />)
    await submit()
    expect(await screen.findByText(state === 'absent'
      ? 'No retained account checkpoint or selection was found.'
      : 'A retained account checkpoint exists; no selection is stored.')).toBeInTheDocument()
    expect(screen.queryByText('Selection generation')).not.toBeInTheDocument()
    expect(screen.queryByText('Stored new-exposure flag')).not.toBeInTheDocument()
    if (state === 'absent') expect(screen.queryByText('Checkpoint sequence')).not.toBeInTheDocument()
    else expect(screen.getByText('9007199254740993')).toBeInTheDocument()
  })

  it.each([401, 403, 503, 500])('shows a static %s error without private response details or retries', async (status) => {
    vi.mocked(fetch).mockImplementation((input) => Promise.resolve(
      url(input) === BOOTSTRAP ? bootstrap() : response({ detail: 'PRIVATE-DIAGNOSTIC' }, status),
    ))
    renderWithProviders(<ContinuousSelectionPanel />)
    await submit()
    expect(await screen.findByRole('alert')).toHaveTextContent(
      status === 401 || status === 403
        ? 'Metadata read access is unavailable.'
        : status === 503
          ? 'Stored selection metadata is unavailable.'
          : 'The stored selection could not be read.',
    )
    expect(screen.queryByText(/PRIVATE-DIAGNOSTIC/)).not.toBeInTheDocument()
    expect(screen.queryByText('Selection generation')).not.toBeInTheDocument()
    expect(fetch).toHaveBeenCalledTimes(2)
    expect(screen.getByRole('button', { name: 'Read stored selection' })).toBeEnabled()
  })

  it('shows pending accessibly and clears the old record immediately when the account changes', async () => {
    provide(selection())
    renderWithProviders(<ContinuousSelectionPanel />)
    await submit()
    expect(await screen.findByText('A retained selection record is stored.')).toBeInTheDocument()
    fireEvent.change(screen.getByRole('textbox', { name: 'Account ID' }), { target: { value: OTHER_ACCOUNT } })
    expect(screen.queryByText('A retained selection record is stored.')).not.toBeInTheDocument()
    expect(fetch).toHaveBeenCalledTimes(2)
    const waiting = deferred()
    vi.mocked(fetch).mockImplementation((input) => url(input) === BOOTSTRAP
      ? Promise.resolve(bootstrap()) : waiting.promise)
    await userEvent.click(screen.getByRole('button', { name: 'Read stored selection' }))
    expect(screen.getByRole('status')).toHaveTextContent('Reading stored selection')
    expect(screen.getByRole('button', { name: 'Read stored selection' })).toBeDisabled()
    await act(async () => {
      waiting.resolve(response(selection(OTHER_ACCOUNT)))
      await waiting.promise
    })
    expect(await screen.findByText('A retained selection record is stored.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Read stored selection' })).toBeEnabled()
  })

  it('clears an error on account change without making another request', async () => {
    vi.mocked(fetch).mockResolvedValue(response({ detail: 'unavailable' }, 503))
    renderWithProviders(<ContinuousSelectionPanel />)
    await submit()
    expect(await screen.findByRole('alert')).toBeInTheDocument()
    fireEvent.change(screen.getByRole('textbox', { name: 'Account ID' }), { target: { value: OTHER_ACCOUNT } })
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it.each(['success', 'failure'] as const)('ignores a stale %s after account change and a newer completion', async (outcome) => {
    const old = deferred()
    let oldSignal: AbortSignal | null | undefined
    vi.mocked(fetch).mockImplementation((input, options) => {
      if (url(input) === BOOTSTRAP) return Promise.resolve(bootstrap())
      if (url(input) === path()) {
        oldSignal = options?.signal
        return old.promise
      }
      return Promise.resolve(response(selection(OTHER_ACCOUNT)))
    })
    renderWithProviders(<ContinuousSelectionPanel />)
    await submit()
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2))
    fireEvent.change(screen.getByRole('textbox', { name: 'Account ID' }), { target: { value: OTHER_ACCOUNT } })
    expect(oldSignal?.aborted).toBe(true)
    await userEvent.click(screen.getByRole('button', { name: 'Read stored selection' }))
    expect(await screen.findByText(OTHER_ACCOUNT)).toBeInTheDocument()
    await act(async () => {
      if (outcome === 'success') old.resolve(response(selection()))
      else old.reject(new Error('PRIVATE-STALE-ERROR'))
      await old.promise.catch(() => undefined)
    })
    expect(screen.getByText(OTHER_ACCOUNT)).toBeInTheDocument()
    expect(screen.queryByText(ACCOUNT)).not.toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(fetch).toHaveBeenCalledTimes(4)
  })

  it('cancels a superseded submission for the same account', async () => {
    const old = deferred()
    let oldSignal: AbortSignal | null | undefined
    let selectionCalls = 0
    vi.mocked(fetch).mockImplementation((input, options) => {
      if (url(input) === BOOTSTRAP) return Promise.resolve(bootstrap())
      selectionCalls += 1
      if (selectionCalls === 1) {
        oldSignal = options?.signal
        return old.promise
      }
      const next = selection()
      next.checkpoint!.sequence = '9007199254740995'
      return Promise.resolve(response(next))
    })
    renderWithProviders(<ContinuousSelectionPanel />)
    await submit()
    await waitFor(() => expect(selectionCalls).toBe(1))
    fireEvent.submit(screen.getByRole('form', { name: 'Read stored selection' }))
    expect(await screen.findByText('9007199254740995')).toBeInTheDocument()
    expect(oldSignal?.aborted).toBe(true)
    await act(async () => {
      old.resolve(response(selection()))
      await old.promise
    })
    expect(screen.getByText('9007199254740995')).toBeInTheDocument()
    expect(screen.queryByText('9007199254740993')).not.toBeInTheDocument()
  })

  it('aborts on unmount and ignores a transport that completes anyway', async () => {
    const waiting = deferred()
    let signal: AbortSignal | null | undefined
    vi.mocked(fetch).mockImplementation((input, options) => {
      if (url(input) === BOOTSTRAP) return Promise.resolve(bootstrap())
      signal = options?.signal
      return waiting.promise
    })
    const rendered = renderWithProviders(<ContinuousSelectionPanel />)
    await submit()
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2))
    rendered.unmount()
    expect(signal?.aborted).toBe(true)
    await act(async () => {
      waiting.resolve(response(selection()))
      await waiting.promise
    })
    expect(screen.queryByText('A retained selection record is stored.')).not.toBeInTheDocument()
    expect(fetch).toHaveBeenCalledTimes(2)
  })
})
