import { ApiError } from '../../api/client'
import type { components } from '../../api/schema.generated'

export type ContinuousSelection = components['schemas']['ContinuousSelectionResponse']

const BOOTSTRAP_PATH = '/api/v1/ui/metadata-bootstrap'
const ACCOUNT_ROOT = '/api/v1/operations/accounts'
const METADATA_HEADER = 'X-Metadata-CSRF-Token'
const REQUEST_ERROR = 'Metadata read request failed.'

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasFields(value: Record<string, unknown>, fields: readonly string[]): boolean {
  return Object.keys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field))
}

function isText(value: unknown, maximum: number): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2 * maximum ||
    value.trim() !== value) return false
  const characters = [...value]
  return characters.length <= maximum && characters.every((character) => {
    const point = character.codePointAt(0) ?? 0
    return !(point >= 0xd800 && point <= 0xdfff)
  })
}

function isAccountId(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 64 && value.trim() === value &&
    /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(value)
}

function isCounter(value: unknown): value is string {
  return typeof value === 'string' && value.trim() === value &&
    /^[1-9][0-9]{0,18}$/.test(value) && BigInt(value) <= 9223372036854775807n
}

function isUtc(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 32) return false
  const matched = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,6})?(?:Z|\+00:00)$/.exec(value)
  if (!matched || matched[0] !== value) return false
  const [year, month, day, hour, minute, second] = matched.slice(1, 7).map(Number)
  if (year === undefined || month === undefined || day === undefined || hour === undefined ||
    minute === undefined || second === undefined || year < 1 || month < 1 || month > 12) return false
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  return day >= 1 && day <= (days[month - 1] ?? 0) && hour <= 23 && minute <= 59 && second <= 59
}

function textBefore(left: string, right: string): boolean {
  const first = [...left]
  const second = [...right]
  for (let index = 0; index < Math.min(first.length, second.length); index += 1) {
    const a = first[index]?.codePointAt(0) ?? 0
    const b = second[index]?.codePointAt(0) ?? 0
    if (a !== b) return a < b
  }
  return first.length < second.length
}

function isCheckpoint(value: unknown): value is NonNullable<ContinuousSelection['checkpoint']> {
  return isObject(value) && hasFields(value, ['stream_id', 'sequence', 'recorded_at']) &&
    isText(value.stream_id, 128) && isCounter(value.sequence) && isUtc(value.recorded_at)
}

function isRetainedSelection(value: unknown): value is NonNullable<ContinuousSelection['selection']> {
  if (!isObject(value) || !hasFields(value, [
    'generation', 'strategy_name', 'strategy_version', 'configuration_sha256', 'instruments',
    'policy_id', 'enabled_for_new_exposure', 'live_authorized', 'recorded_at', 'effective_at',
  ]) || !isCounter(value.generation) || !isText(value.strategy_name, 2048) ||
    !isText(value.strategy_version, 2048) || !isText(value.policy_id, 2048) ||
    typeof value.configuration_sha256 !== 'string' || value.configuration_sha256.length !== 64 ||
    !/^[a-f0-9]{64}$/.test(value.configuration_sha256) ||
    typeof value.enabled_for_new_exposure !== 'boolean' || value.live_authorized !== false ||
    !isUtc(value.recorded_at) || !isUtc(value.effective_at) ||
    !Array.isArray(value.instruments) || value.instruments.length < 1 || value.instruments.length > 4) return false
  const instruments: unknown[] = value.instruments
  const symbols = new Set<string>()
  let previous: string | undefined
  for (const instrument of instruments) {
    if (!isObject(instrument) || !hasFields(instrument, ['instrument_id', 'symbol']) ||
      !isText(instrument.instrument_id, 2048) || typeof instrument.symbol !== 'string' ||
      !['DIA', 'IWM', 'QQQ', 'SPY'].includes(instrument.symbol) || symbols.has(instrument.symbol) ||
      (previous !== undefined && !textBefore(previous, instrument.instrument_id))) return false
    previous = instrument.instrument_id
    symbols.add(instrument.symbol)
  }
  return true
}

function isSelection(value: unknown, accountId: string): value is ContinuousSelection {
  if (!isObject(value) || !hasFields(value, [
    'account_id', 'state', 'checkpoint', 'selection', 'verification',
  ]) || value.account_id !== accountId || value.verification !== 'row_integrity_only') return false
  if (value.state === 'absent') return value.checkpoint === null && value.selection === null
  if (!isCheckpoint(value.checkpoint)) return false
  return (value.state === 'unselected' && value.selection === null) ||
    (value.state === 'selected' && isRetainedSelection(value.selection))
}

function metadataToken(value: unknown): string {
  if (!isObject(value) || !hasFields(value, [
    'enabled', 'operator_id', 'csrf_token', 'csrf_header', 'expires_at', 'disabled_reason',
    'scope', 'verification',
  ]) || typeof value.enabled !== 'boolean' || value.csrf_header !== METADATA_HEADER ||
    value.scope !== 'continuous-selection-read/1' || value.verification !== 'row_integrity_only') {
    throw new ApiError('Metadata read capability was malformed.')
  }
  if (!value.enabled) {
    if (value.operator_id !== null || value.csrf_token !== null || value.expires_at !== null ||
      !isText(value.disabled_reason, 2048)) throw new ApiError('Metadata read capability was malformed.')
    throw new ApiError('Metadata read access is unavailable.', 403)
  }
  if (!isText(value.operator_id, 128) ||
    [...value.operator_id].some((character) => (character.codePointAt(0) ?? 0) < 32) ||
    !isUtc(value.expires_at) || value.disabled_reason !== null ||
    !isText(value.csrf_token, 128) || value.csrf_token.length < 32 ||
    !/^[A-Za-z0-9_-]+$/.test(value.csrf_token)) throw new ApiError('Metadata read capability was malformed.')
  return value.csrf_token
}

function requireNotAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new DOMException('Metadata read cancelled.', 'AbortError')
}

async function requestPayload(path: string, signal?: AbortSignal, token?: string): Promise<unknown> {
  requireNotAborted(signal)
  let response: Response
  try {
    response = await fetch(path, {
      method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal,
      headers: { Accept: 'application/json', ...(token ? { [METADATA_HEADER]: token } : {}) },
    })
  } catch (error) {
    requireNotAborted(signal)
    if (error instanceof DOMException && error.name === 'AbortError') throw error
    throw new ApiError(REQUEST_ERROR)
  }
  requireNotAborted(signal)
  if (!response.ok) throw new ApiError(REQUEST_ERROR, response.status)
  try {
    const payload: unknown = await response.json()
    requireNotAborted(signal)
    return payload
  } catch (error) {
    requireNotAborted(signal)
    if (error instanceof DOMException && error.name === 'AbortError') throw error
    throw new ApiError('Metadata read response was malformed.')
  }
}

/** Read retained row metadata only; this confers no readiness or execution authority. */
export async function fetchContinuousSelection(
  accountId: string, signal?: AbortSignal,
): Promise<ContinuousSelection> {
  if (!isAccountId(accountId)) throw new ApiError('Enter a valid account ID for the metadata read.')
  const token = metadataToken(await requestPayload(BOOTSTRAP_PATH, signal))
  const payload = await requestPayload(
    `${ACCOUNT_ROOT}/${encodeURIComponent(accountId)}/continuous-selection`, signal, token,
  )
  if (!isSelection(payload, accountId)) throw new ApiError('Stored metadata response was malformed.')
  return payload
}
