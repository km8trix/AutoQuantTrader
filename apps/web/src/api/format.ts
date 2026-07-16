const numberFormatters = new Map<string, Intl.NumberFormat>()

function getCurrencyFormatter(currency: string): Intl.NumberFormat {
  const key = currency.toUpperCase()
  const existing = numberFormatters.get(key)
  if (existing) {
    return existing
  }

  const formatter = new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: key,
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })
  numberFormatters.set(key, formatter)
  return formatter
}

export function formatCurrency(value: string, currency: string): string {
  const number = Number(value)
  return Number.isFinite(number) ? getCurrencyFormatter(currency).format(number) : 'Unavailable'
}

export function formatExposure(value: string, currency: string): string {
  return formatCurrency(value, currency)
}

export function formatDateTime(value: string | null): string {
  if (!value) {
    return 'Not scheduled'
  }

  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return 'Unavailable'
  }

  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    second: '2-digit',
    timeZoneName: 'short',
  }).format(date)
}

export function formatRelativeTime(value: string | null, now = Date.now()): string {
  if (!value) {
    return 'Never'
  }

  const then = new Date(value).getTime()
  if (!Number.isFinite(then)) {
    return 'Unknown'
  }

  const seconds = Math.round((then - now) / 1_000)
  const absoluteSeconds = Math.abs(seconds)

  if (absoluteSeconds < 5) {
    return 'just now'
  }

  const formatter = new Intl.RelativeTimeFormat('en-US', { numeric: 'auto' })
  if (absoluteSeconds < 60) {
    return formatter.format(seconds, 'second')
  }

  const minutes = Math.round(seconds / 60)
  if (Math.abs(minutes) < 60) {
    return formatter.format(minutes, 'minute')
  }

  const hours = Math.round(minutes / 60)
  return formatter.format(hours, 'hour')
}

export function isTimestampStale(
  value: string | null,
  thresholdMilliseconds = 30_000,
  now = Date.now(),
): boolean {
  if (!value) {
    return true
  }

  const timestamp = new Date(value).getTime()
  return !Number.isFinite(timestamp) || now - timestamp > thresholdMilliseconds
}

export function titleCase(value: string): string {
  return value
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (character) => character.toUpperCase())
}
