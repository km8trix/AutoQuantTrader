import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '../../api/client'
import { fetchContinuousSelection } from './continuousSelectionApi'

const ACCOUNT = 'synthetic-account:1'
const TOKEN = 'm'.repeat(43)
const RECORDED = '2026-10-21T14:30:00.123456Z'
const EFFECTIVE = '2026-10-21T14:30:00.123456+00:00'

function capability(overrides: Record<string, unknown> = {}) {
  return {
    enabled: true, operator_id: 'local-operator', csrf_token: TOKEN,
    csrf_header: 'X-Metadata-CSRF-Token', expires_at: '2026-10-21T22:30:00Z',
    disabled_reason: null, scope: 'continuous-selection-read/1', verification: 'row_integrity_only',
    ...overrides,
  }
}

function selected() {
  return {
    account_id: ACCOUNT, state: 'selected', verification: 'row_integrity_only',
    checkpoint: { stream_id: 'synthetic-stream', sequence: '9007199254740993', recorded_at: RECORDED },
    selection: {
      generation: '9223372036854775807', strategy_name: 'buy_hold', strategy_version: 'v1',
      configuration_sha256: 'a'.repeat(64), instruments: [{ instrument_id: 'SPY', symbol: 'SPY' }],
      policy_id: 'daily-risk/1', enabled_for_new_exposure: false, live_authorized: false,
      recorded_at: RECORDED, effective_at: EFFECTIVE,
    },
  }
}

function response(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status, headers: { 'Content-Type': 'application/json' },
  })
}

function serveSelection(value: unknown = selected()) {
  vi.mocked(fetch).mockResolvedValueOnce(response(capability())).mockResolvedValueOnce(response(value))
}

describe('purpose-separated retained continuous-selection transport', () => {
  beforeEach(() => { vi.stubGlobal('fetch', vi.fn()) })
  afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.restoreAllMocks() })

  it('performs exactly two uncached GETs with only the validated fixed metadata header', async () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem')
    const getItem = vi.spyOn(Storage.prototype, 'getItem')
    const abort = new AbortController()
    serveSelection()
    const result = await fetchContinuousSelection(ACCOUNT, abort.signal)
    expect(result).toEqual(selected())
    expect(fetch).toHaveBeenCalledTimes(2)
    expect(vi.mocked(fetch).mock.calls[0]).toEqual([
      '/api/v1/ui/metadata-bootstrap', {
        method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        signal: abort.signal, headers: { Accept: 'application/json' },
      },
    ])
    expect(vi.mocked(fetch).mock.calls[1]).toEqual([
      `/api/v1/operations/accounts/${encodeURIComponent(ACCOUNT)}/continuous-selection`, {
        method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        signal: abort.signal, headers: { Accept: 'application/json', 'X-Metadata-CSRF-Token': TOKEN },
      },
    ])
    expect(setItem).not.toHaveBeenCalled()
    expect(getItem).not.toHaveBeenCalled()
  })

  it('preserves counters beyond Number precision and original microsecond UTC text', async () => {
    serveSelection()
    const result = await fetchContinuousSelection(ACCOUNT)
    expect(result.checkpoint?.sequence).toBe('9007199254740993')
    expect(result.selection?.generation).toBe('9223372036854775807')
    expect(typeof result.checkpoint?.sequence).toBe('string')
    expect(typeof result.selection?.generation).toBe('string')
    expect(result.checkpoint?.recorded_at).toBe(RECORDED)
    expect(result.selection?.effective_at).toBe(EFFECTIVE)
  })

  it.each(['absent', 'unselected'])('accepts consistent %s metadata without inventing selection', async (state) => {
    const original = selected()
    const value = { ...original, state, checkpoint: state === 'absent' ? null : original.checkpoint, selection: null }
    serveSelection(value)
    await expect(fetchContinuousSelection(ACCOUNT)).resolves.toEqual(value)
  })

  it('retains a stored enabled flag without creating execution authority', async () => {
    const original = selected()
    const value = { ...original, selection: { ...original.selection, enabled_for_new_exposure: true } }
    serveSelection(value)
    await expect(fetchContinuousSelection(ACCOUNT)).resolves.toEqual(value)
    expect(fetch).toHaveBeenCalledTimes(2)
  })

  it('uses Unicode code-point bounds and ordering for retained identifiers', async () => {
    const original = selected()
    const value = { ...original, selection: { ...original.selection,
      strategy_name: '😀'.repeat(2048), instruments: [
        { instrument_id: '\ue000', symbol: 'DIA' },
        { instrument_id: '😀', symbol: 'SPY' },
      ],
    } }
    serveSelection(value)
    await expect(fetchContinuousSelection(ACCOUNT)).resolves.toEqual(value)
  })

  it.each(['', ' account', 'account ', '../account', 'a/b', 'a?b', 'a#b', 'a%2fb', '_account', 'a\n', 'x'.repeat(65)])(
    'rejects invalid explicit account identity %j before a request', async (account) => {
      await expect(fetchContinuousSelection(account)).rejects.toThrow('Enter a valid account ID')
      expect(fetch).not.toHaveBeenCalled()
    },
  )

  it.each([
    ['wrong scope', { scope: 'mutation/1' }],
    ['wrong verification', { verification: 'owner_authenticated' }],
    ['dynamic shared header', { csrf_header: 'X-CSRF-Token' }],
    ['native flag mismatch', { enabled: 1 }],
    ['missing token', { csrf_token: null }],
    ['short token', { csrf_token: 'm'.repeat(31) }],
    ['large token', { csrf_token: 'm'.repeat(129) }],
    ['header-injection token', { csrf_token: TOKEN + '\r\nX-CSRF-Token: secret' }],
    ['invalid operator', { operator_id: 'bad\noperator' }],
    ['missing operator', { operator_id: null }],
    ['non-UTC expiry', { expires_at: '2026-10-21T22:30:00+01:00' }],
    ['enabled reason', { disabled_reason: 'secret provider failure' }],
    ['authority field', { idempotency_header: 'Idempotency-Key' }],
  ])('rejects malformed capability: %s', async (_name, overrides) => {
    vi.mocked(fetch).mockResolvedValueOnce(response(capability(overrides)))
    await expect(fetchContinuousSelection(ACCOUNT)).rejects.toThrow('Metadata read capability was malformed.')
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('requires explicit capability scope and never falls back to a shared session', async () => {
    const value: Record<string, unknown> = capability()
    delete value.scope
    vi.mocked(fetch).mockResolvedValueOnce(response(value))
    await expect(fetchContinuousSelection(ACCOUNT)).rejects.toThrow('Metadata read capability was malformed.')
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('reports disabled metadata access statically and does not request account data', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(response(capability({
      enabled: false, operator_id: null, csrf_token: null, expires_at: null,
      disabled_reason: 'server-private-disabled-reason',
    })))
    await expect(fetchContinuousSelection(ACCOUNT)).rejects.toMatchObject({
      name: 'ApiError', status: 403, message: 'Metadata read access is unavailable.',
    })
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  const malformedSelections: Array<[string, unknown]> = [
    ['array root', []],
    ['foreign account', { ...selected(), account_id: 'foreign-account' }],
    ['authority verification', { ...selected(), verification: 'ready' }],
    ['extra authority field', { ...selected(), ready: true }],
    ['unknown state', { ...selected(), state: 'active' }],
    ['absent with checkpoint', { ...selected(), state: 'absent', selection: null }],
    ['unselected with assignment', { ...selected(), state: 'unselected' }],
    ['selected without checkpoint', { ...selected(), checkpoint: null }],
    ['selected without assignment', { ...selected(), selection: null }],
    ['oversized stream', { ...selected(), checkpoint: { ...selected().checkpoint, stream_id: 'x'.repeat(129) } }],
    ['trimmed stream', { ...selected(), checkpoint: { ...selected().checkpoint, stream_id: ' stream ' } }],
    ['extra checkpoint field', { ...selected(), checkpoint: { ...selected().checkpoint, equity: '10000' } }],
    ['numeric sequence', { ...selected(), checkpoint: { ...selected().checkpoint, sequence: 9007199254740992 } }],
    ['zero sequence', { ...selected(), checkpoint: { ...selected().checkpoint, sequence: '0' } }],
    ['leading-zero sequence', { ...selected(), checkpoint: { ...selected().checkpoint, sequence: '01' } }],
    ['signed sequence', { ...selected(), checkpoint: { ...selected().checkpoint, sequence: '+1' } }],
    ['sequence exponent', { ...selected(), checkpoint: { ...selected().checkpoint, sequence: '1e2' } }],
    ['sequence trailing newline', { ...selected(), checkpoint: { ...selected().checkpoint, sequence: '1\n' } }],
    ['sequence overflow', { ...selected(), checkpoint: { ...selected().checkpoint, sequence: '9223372036854775808' } }],
    ['numeric generation', { ...selected(), selection: { ...selected().selection, generation: 1 } }],
    ['negative generation', { ...selected(), selection: { ...selected().selection, generation: '-1' } }],
    ['generation overflow', { ...selected(), selection: { ...selected().selection, generation: '9999999999999999999' } }],
    ['non-native enabled', { ...selected(), selection: { ...selected().selection, enabled_for_new_exposure: 0 } }],
    ['live enabled', { ...selected(), selection: { ...selected().selection, live_authorized: true } }],
    ['live numeric zero', { ...selected(), selection: { ...selected().selection, live_authorized: 0 } }],
    ['uppercase digest', { ...selected(), selection: { ...selected().selection, configuration_sha256: 'A'.repeat(64) } }],
    ['digest newline', { ...selected(), selection: { ...selected().selection, configuration_sha256: 'a'.repeat(64) + '\n' } }],
    ['empty strategy', { ...selected(), selection: { ...selected().selection, strategy_name: '' } }],
    ['large version', { ...selected(), selection: { ...selected().selection, strategy_version: 'x'.repeat(2049) } }],
    ['invalid Unicode', { ...selected(), selection: { ...selected().selection, policy_id: '\ud800' } }],
    ['missing instruments', { ...selected(), selection: { ...selected().selection, instruments: [] } }],
    ['too many instruments', { ...selected(), selection: { ...selected().selection, instruments: Array.from({ length: 5 }, () => ({ instrument_id: 'SPY', symbol: 'SPY' })) } }],
    ['unsupported symbol', { ...selected(), selection: { ...selected().selection, instruments: [{ instrument_id: 'AAPL', symbol: 'AAPL' }] } }],
    ['duplicate IDs', { ...selected(), selection: { ...selected().selection, instruments: [{ instrument_id: 'same', symbol: 'DIA' }, { instrument_id: 'same', symbol: 'SPY' }] } }],
    ['duplicate symbols', { ...selected(), selection: { ...selected().selection, instruments: [{ instrument_id: 'a', symbol: 'SPY' }, { instrument_id: 'b', symbol: 'SPY' }] } }],
    ['unsorted IDs', { ...selected(), selection: { ...selected().selection, instruments: [{ instrument_id: 'b', symbol: 'DIA' }, { instrument_id: 'a', symbol: 'SPY' }] } }],
    ['extra instrument authority', { ...selected(), selection: { ...selected().selection, instruments: [{ instrument_id: 'SPY', symbol: 'SPY', approved: true }] } }],
    ['extra selection authority', { ...selected(), selection: { ...selected().selection, execution_authorized: true } }],
  ]
  it.each(malformedSelections)('rejects malformed or conflicting selection: %s', async (_name, payload) => {
    serveSelection(payload)
    await expect(fetchContinuousSelection(ACCOUNT)).rejects.toThrow('Stored metadata response was malformed.')
    expect(fetch).toHaveBeenCalledTimes(2)
  })

  it.each([
    '0000-01-01T00:00:00Z', '1900-02-29T00:00:00Z', '2026-02-30T00:00:00Z',
    '2026-01-01T24:00:00Z', '2026-01-01T00:00:60Z', '2026-01-01T00:00:00',
    '2026-01-01T00:00:00+01:00', '2026-01-01T00:00:00.1234567Z',
    '2026-01-01T00:00:00Z\n',
  ])('rejects non-UTC or impossible retained times: %j', async (recorded) => {
    const original = selected()
    serveSelection({ ...original, checkpoint: { ...original.checkpoint, recorded_at: recorded } })
    await expect(fetchContinuousSelection(ACCOUNT)).rejects.toThrow('Stored metadata response was malformed.')
  })

  it('accepts original leap-day and year boundary UTC text without host-clock comparison', async () => {
    const original = selected()
    const value = { ...original, checkpoint: { ...original.checkpoint, recorded_at: '0001-01-01T00:00:00Z' },
      selection: { ...original.selection, recorded_at: '2000-02-29T00:00:00Z', effective_at: '9999-12-31T23:59:59.999999Z' },
    }
    serveSelection(value)
    await expect(fetchContinuousSelection(ACCOUNT)).resolves.toEqual(value)
  })

  it.each([401, 403, 503])('keeps public status %s without parsing or exposing an error body', async (status) => {
    const failed = response({ detail: 'secret-path-or-token', ready: true }, status)
    const json = vi.spyOn(failed, 'json')
    vi.mocked(fetch).mockResolvedValueOnce(response(capability())).mockResolvedValueOnce(failed)
    await expect(fetchContinuousSelection(ACCOUNT)).rejects.toMatchObject({
      name: 'ApiError', message: 'Metadata read request failed.', status, problem: undefined,
    })
    expect(json).not.toHaveBeenCalled()
    expect(fetch).toHaveBeenCalledTimes(2)
  })

  it('does not retry failed bootstrap or use development fixtures', async () => {
    vi.stubEnv('VITE_USE_DEV_FIXTURES', 'true')
    vi.mocked(fetch).mockRejectedValueOnce(new Error('private-transport-detail'))
    await expect(fetchContinuousSelection(ACCOUNT)).rejects.toMatchObject({
      name: 'ApiError', message: 'Metadata read request failed.', status: 0,
    })
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('reacquires purpose-specific access on a later explicit request without token persistence', async () => {
    serveSelection()
    await fetchContinuousSelection(ACCOUNT)
    serveSelection()
    await fetchContinuousSelection(ACCOUNT)
    expect(vi.mocked(fetch).mock.calls.map(([path]) => path)).toEqual([
      '/api/v1/ui/metadata-bootstrap', `/api/v1/operations/accounts/${encodeURIComponent(ACCOUNT)}/continuous-selection`,
      '/api/v1/ui/metadata-bootstrap', `/api/v1/operations/accounts/${encodeURIComponent(ACCOUNT)}/continuous-selection`,
    ])
  })

  it('normalizes invalid JSON without reflecting parser or response details', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(new Response('secret-not-json', { status: 200 }))
    await expect(fetchContinuousSelection(ACCOUNT)).rejects.toMatchObject({
      name: 'ApiError', message: 'Metadata read response was malformed.',
    })
  })

  it('makes no request for an already-cancelled read', async () => {
    const abort = new AbortController()
    abort.abort()
    await expect(fetchContinuousSelection(ACCOUNT, abort.signal)).rejects.toMatchObject({ name: 'AbortError' })
    expect(fetch).not.toHaveBeenCalled()
  })

  it('does not start selection if a transport ignores cancellation during bootstrap', async () => {
    const abort = new AbortController()
    vi.mocked(fetch).mockImplementationOnce(() => {
      abort.abort()
      return Promise.resolve(response(capability()))
    })
    await expect(fetchContinuousSelection(ACCOUNT, abort.signal)).rejects.toMatchObject({ name: 'AbortError' })
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('preserves cancellation during selection and never substitutes a fixture', async () => {
    const abort = new DOMException('The operation was aborted.', 'AbortError')
    vi.mocked(fetch).mockResolvedValueOnce(response(capability())).mockRejectedValueOnce(abort)
    await expect(fetchContinuousSelection(ACCOUNT)).rejects.toBe(abort)
    expect(fetch).toHaveBeenCalledTimes(2)
  })

  it('throws the existing public ApiError type for rejected metadata', async () => {
    serveSelection({ ...selected(), account_id: 'another-account' })
    await expect(fetchContinuousSelection(ACCOUNT)).rejects.toBeInstanceOf(ApiError)
  })
})
