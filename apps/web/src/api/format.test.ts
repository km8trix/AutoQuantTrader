import { describe, expect, it } from 'vitest'

import { formatCurrency, isTimestampStale, titleCase } from './format'

describe('format helpers', () => {
  it('formats decimal-string money at the presentation boundary', () => {
    expect(formatCurrency('1024.50', 'USD')).toBe('$1,024.50')
  })

  it('detects stale timestamps using the provided clock', () => {
    const now = Date.parse('2026-07-15T14:00:00.000Z')
    expect(isTimestampStale('2026-07-15T13:59:45.000Z', 30_000, now)).toBe(false)
    expect(isTimestampStale('2026-07-15T13:59:00.000Z', 30_000, now)).toBe(true)
  })

  it('turns wire enum values into readable labels', () => {
    expect(titleCase('not_ready')).toBe('Not Ready')
  })
})
