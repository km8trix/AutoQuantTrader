import { useState } from 'react'

import type { UiBootstrap } from '../../api/types'
import type { ResearchExperimentRequest, ResearchRunRequest } from './researchApi'

type Requests = { run: ResearchRunRequest; experiment: ResearchExperimentRequest }
type Operation = keyof Requests
type Scope = { operator_id: string; environment: UiBootstrap['environment'] }
type Intent<O extends Operation> = Scope & {
  version: 1
  operation: O
  input: Requests[O]
  key: string
  created_at: string
}
type State<O extends Operation> = { intent: Intent<O> | null; error: string | null; recovered: boolean }

const MAX_STORED_CHARACTERS = 32768
const storageKey = (operation: Operation) => `personal-research-pending/1/${operation}`
const scopeOf = (bootstrap: UiBootstrap): Scope => ({ operator_id: bootstrap.backtest_launch?.operator_id ?? '', environment: { name: bootstrap.environment.name, mode: bootstrap.environment.mode, account_id: bootstrap.environment.account_id } })
const sameScope = (left: Scope, right: Scope) => left.operator_id === right.operator_id && left.environment.name === right.environment.name && left.environment.mode === right.environment.mode && left.environment.account_id === right.environment.account_id
const text = (value: unknown): value is string => typeof value === 'string' && value.length <= 8192
const integer = (value: unknown) => typeof value === 'number' && Number.isSafeInteger(value)
const nullableText = (value: unknown) => value === null || text(value)

function record(value: unknown, keys: string[]): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every((key) => key in value)
}

function configuration(value: unknown) {
  return record(value, ['kind', 'lookback', 'allocation', 'rebalance_sessions']) && (value.kind === 'buy_hold' || value.kind === 'trend_sma') && integer(value.lookback) && text(value.allocation) && (value.rebalance_sessions === null || integer(value.rebalance_sessions))
}

// Structural storage guards only. The generated API types define the request;
// the server remains responsible for dates, numeric semantics and admission.
function requestShape(operation: Operation, value: unknown): boolean {
  if (operation === 'run') {
    return record(value, ['dataset_id', 'dataset_manifest_sha256', 'strategy_id', 'strategy_version', 'configuration', 'initial_cash', 'warmup_sessions', 'scored_start', 'scored_end', 'cost_scenario_id']) && ['dataset_id', 'dataset_manifest_sha256', 'strategy_id', 'strategy_version', 'initial_cash', 'cost_scenario_id'].every((key) => text(value[key])) && configuration(value.configuration) && integer(value.warmup_sessions) && nullableText(value.scored_start) && nullableText(value.scored_end)
  }
  if (!record(value, ['name', 'hypothesis', 'dataset_id', 'candidates', 'folds', 'warmup_sessions', 'prior_access'])) return false
  return ['name', 'hypothesis', 'dataset_id'].every((key) => text(value[key])) && integer(value.warmup_sessions) && Array.isArray(value.candidates) && value.candidates.length >= 1 && value.candidates.length <= 8 && value.candidates.every((candidate: unknown) => record(candidate, ['candidate_id', 'configuration']) && text(candidate.candidate_id) && configuration(candidate.configuration)) && Array.isArray(value.folds) && value.folds.length >= 1 && value.folds.length <= 8 && value.folds.every((fold: unknown) => record(fold, ['fold_id', 'train_start', 'train_end', 'validation_start', 'validation_end', 'test_start', 'test_end']) && Object.values(fold).every(text)) && record(value.prior_access, ['status', 'description']) && (value.prior_access.status === 'known_accessed' || value.prior_access.status === 'unknown') && text(value.prior_access.description)
}

function load<O extends Operation>(operation: O, scope: Scope): State<O> {
  try {
    const raw = sessionStorage.getItem(storageKey(operation))
    if (raw === null) return { intent: null, error: null, recovered: false }
    if (raw.length > MAX_STORED_CHARACTERS) throw new Error('Retained request exceeds its storage limit.')
    const value: unknown = JSON.parse(raw)
    if (!record(value, ['version', 'operation', 'input', 'key', 'created_at', 'operator_id', 'environment']) || value.version !== 1 || value.operation !== operation || !text(value.key) || !/^[A-Za-z0-9._:-]{8,128}$/.test(value.key) || !text(value.created_at) || !Number.isFinite(Date.parse(value.created_at)) || !text(value.operator_id) || !value.operator_id || !record(value.environment, ['name', 'mode', 'account_id']) || !Object.values(value.environment).every(text) || !requestShape(operation, value.input)) {
      throw new Error('Retained request is malformed. New submissions are blocked until it is explicitly discarded.')
    }
    const intent = value as Intent<O>
    if (!sameScope(intent, scope)) throw new Error('Retained request belongs to a different operator or environment. Retry is blocked.')
    return { intent, error: null, recovered: true }
  } catch (error) {
    return { intent: null, error: error instanceof SyntaxError ? 'Retained request is malformed. New submissions are blocked until it is explicitly discarded.' : error instanceof Error ? error.message : 'Session storage is unavailable. Submission is blocked.', recovered: false }
  }
}

export function useResearchPendingIntent<O extends Operation>(operation: O, bootstrap: UiBootstrap) {
  const scope = scopeOf(bootstrap)
  const [state, setState] = useState(() => load(operation, scope))
  const mismatch = state.intent !== null && !sameScope(state.intent, scope)
  const error = mismatch ? 'Retained request belongs to a different operator or environment. Retry is blocked.' : state.error

  function retain(input: Requests[O]): Intent<O> | null {
    if (error) return null
    const intent: Intent<O> = state.intent ?? { version: 1, operation, input, key: `research${operation === 'experiment' ? '-experiment' : ''}-${crypto.randomUUID()}`, created_at: new Date().toISOString(), ...scope }
    try {
      if (!scope.operator_id || !requestShape(operation, intent.input)) throw new Error('Request cannot be retained safely. Submission is blocked.')
      const stored = sessionStorage.getItem(storageKey(operation))
      const raw = JSON.stringify(intent)
      if (raw.length > MAX_STORED_CHARACTERS || (stored !== null && stored !== raw)) throw new Error('Another retained request is present. Reload to review it before submitting.')
      sessionStorage.setItem(storageKey(operation), raw)
      if (sessionStorage.getItem(storageKey(operation)) !== raw) throw new Error('Session storage did not retain the request.')
      setState({ intent, error: null, recovered: state.recovered })
      return intent
    } catch {
      setState((current) => ({ ...current, error: 'Request could not be retained safely in session storage. No request was sent.' }))
      return null
    }
  }

  function clear(acknowledgedKey?: string): boolean {
    try {
      const raw = sessionStorage.getItem(storageKey(operation))
      if (acknowledgedKey && raw !== null) {
        const value: unknown = JSON.parse(raw)
        if (typeof value !== 'object' || value === null || !('key' in value) || value.key !== acknowledgedKey) throw new Error('Retained request identity changed.')
      }
      sessionStorage.removeItem(storageKey(operation))
      if (sessionStorage.getItem(storageKey(operation)) !== null) throw new Error('Retained request was not removed.')
      setState({ intent: null, error: null, recovered: false })
      return true
    } catch {
      setState((current) => ({ ...current, error: 'Session storage could not clear the retained request. New submissions remain blocked.' }))
      return false
    }
  }

  return { attempt: state.intent, error, recovered: state.recovered, retain, acknowledge: clear, discard: () => clear() }
}
