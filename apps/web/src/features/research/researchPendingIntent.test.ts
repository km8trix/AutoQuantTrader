import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { makeBootstrapFixture } from '../../api/fixtures'
import type { ResearchRunRequest } from './researchApi'
import { useResearchPendingIntent } from './researchPendingIntent'
import { experimentFixture, runFixture } from './researchTestFixtures'

function runInput(): ResearchRunRequest {
  const run = runFixture()
  return { dataset_id: 'catalog-synthetic', dataset_manifest_sha256: run.dataset_manifest_sha256, strategy_id: run.strategy_id, strategy_version: run.strategy_version, configuration: run.configuration, initial_cash: '10000.1234567890', warmup_sessions: 252, scored_start: null, scored_end: null, cost_scenario_id: run.cost_scenario_id }
}

describe.each(['run', 'experiment'] as const)('%s pending intent', (operation) => {
  const key = `personal-research-pending/1/${operation}`
  const input = () => operation === 'run' ? runInput() : experimentFixture().request
  beforeEach(() => sessionStorage.clear())
  afterEach(() => { vi.restoreAllMocks(); sessionStorage.clear() })

  it('retains exact input and identity before use, restores on remount, and clears acknowledgment', () => {
    const bootstrap = makeBootstrapFixture()
    const first = renderHook(() => useResearchPendingIntent(operation, bootstrap))
    act(() => { first.result.current.retain(input()) })
    const attempt = first.result.current.attempt
    expect(attempt?.input).toEqual(input())
    const raw = sessionStorage.getItem(key)
    expect(raw).toContain(bootstrap.backtest_launch?.operator_id)
    expect(raw).not.toContain(bootstrap.backtest_launch?.csrf_token)
    first.unmount()
    const second = renderHook(() => useResearchPendingIntent(operation, bootstrap))
    expect(second.result.current.recovered).toBe(true)
    expect(second.result.current.attempt).toEqual(attempt)
    act(() => { second.result.current.retain(input()) })
    expect(sessionStorage.getItem(key)).toBe(raw)
    act(() => { second.result.current.acknowledge(attempt?.key) })
    expect(second.result.current.attempt).toBeNull()
    expect(sessionStorage.getItem(key)).toBeNull()
  })

  it.each(['throws', 'drops'] as const)('blocks retention when storage %s a write', (fault) => {
    const hook = renderHook(() => useResearchPendingIntent(operation, makeBootstrapFixture()))
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { if (fault === 'throws') throw new DOMException('storage disabled') })
    act(() => { expect(hook.result.current.retain(input())).toBeNull() })
    expect(hook.result.current.error).toMatch(/No request was sent/)
    expect(hook.result.current.attempt).toBeNull()
  })

  it.each(['malformed', 'oversized', 'operator', 'environment', 'version', 'body'])('blocks %s storage until explicit discard', (fault) => {
    const bootstrap = makeBootstrapFixture()
    const first = renderHook(() => useResearchPendingIntent(operation, bootstrap))
    act(() => { first.result.current.retain(input()) })
    const raw = sessionStorage.getItem(key)
    if (!raw) throw new Error('Expected retained test request')
    const value = JSON.parse(raw) as Record<string, unknown>
    first.unmount()
    if (fault === 'malformed') sessionStorage.setItem(key, '{broken')
    else if (fault === 'oversized') sessionStorage.setItem(key, 'x'.repeat(32769))
    else {
      if (fault === 'operator') value.operator_id = 'different-operator'
      if (fault === 'environment') value.environment = { ...bootstrap.environment, account_id: 'different-scope' }
      if (fault === 'version') value.version = 2
      if (fault === 'body') value.input = { unrelated: 'data' }
      sessionStorage.setItem(key, JSON.stringify(value))
    }
    const second = renderHook(() => useResearchPendingIntent(operation, bootstrap))
    expect(second.result.current.error).not.toBeNull()
    act(() => { expect(second.result.current.retain(input())).toBeNull() })
    expect(sessionStorage.getItem(key)).not.toBeNull()
    act(() => { expect(second.result.current.discard()).toBe(true) })
    expect(second.result.current.error).toBeNull()
    expect(sessionStorage.getItem(key)).toBeNull()
  })

  it('blocks a changed scope while mounted and does not erase a different acknowledgment', () => {
    const bootstrap = makeBootstrapFixture()
    const hook = renderHook(({ scope }) => useResearchPendingIntent(operation, scope), { initialProps: { scope: bootstrap } })
    act(() => { hook.result.current.retain(input()) })
    hook.rerender({ scope: { ...bootstrap, environment: { ...bootstrap.environment, name: 'another environment' } } })
    expect(hook.result.current.error).toMatch(/different operator or environment/)
    act(() => { expect(hook.result.current.retain(input())).toBeNull() })
    act(() => { expect(hook.result.current.acknowledge('unrelated-key')).toBe(false) })
    expect(sessionStorage.getItem(key)).not.toBeNull()
  })
})
