import { Alert, Box, Typography } from '@mui/material'

import type { ResearchEquityRow } from './researchApi'

const WIDTH = 800
const HEIGHT = 230

function finite(value: string | null): number | null {
  if (value === null || value.trim() === '') return null
  const number = Number(value)
  return Number.isFinite(number) ? number : null
}

export function ResearchEquityChart({ points, view }: { points: ResearchEquityRow[]; view: 'nav' | 'wealth' }) {
  const series = [
    { name: 'Strategy', color: '#53d5e8', values: points.map((point) => view === 'nav' ? point.nav : point.wealth) },
    { name: 'Analytical SPY', color: '#e7b66d', values: points.map((point) => view === 'nav' ? point.benchmark_nav : point.benchmark_wealth) },
    { name: 'Cash comparator', color: '#b399e8', values: points.map((point) => view === 'nav' ? point.cash_nav : point.cash_wealth) },
  ]
  const values = series.flatMap((item) => item.values.map(finite).filter((value): value is number => value !== null))
  if (points.some((point, index) => index > 0 && point.sequence <= (points[index - 1]?.sequence ?? -1))) {
    return <Alert severity="error">Valuation sequences are not strictly ordered.</Alert>
  }
  const minimum = Math.min(...values)
  const maximum = Math.max(...values)
  const range = maximum - minimum || 1
  const coordinate = (value: number, index: number) => `${(45 + index / Math.max(1, points.length - 1) * 735).toFixed(2)},${(20 + (maximum - value) / range * 170).toFixed(2)}`

  function segments(raw: (string | null)[]) {
    const result: string[][] = []
    let current: string[] = []
    raw.forEach((value, index) => {
      const number = finite(value)
      if (number === null) {
        if (current.length) result.push(current)
        current = []
      } else current.push(coordinate(number, index))
    })
    if (current.length) result.push(current)
    return result
  }

  return <Box>
    <Typography component="h3" variant="h2">{view === 'nav' ? 'Account NAV (USD)' : 'Flow-neutral wealth index'}</Typography>
    <Typography color="text.secondary" sx={{ my: 1 }}>{view === 'nav' ? 'NAV includes contributions and withdrawals.' : 'Returns and drawdown use the server’s linked wealth path.'} Missing observations break each line independently.</Typography>
    {values.length ? <Box component="svg" role="img" aria-label={`${view === 'nav' ? 'Account NAV' : 'Flow-neutral wealth'} for displayed valuation rows`} viewBox={`0 0 ${WIDTH} ${HEIGHT}`} sx={{ width: '100%', maxHeight: 320 }}>
      <line x1="45" x2="780" y1="190" y2="190" stroke="#506178" />
      <text x="45" y="14" fill="#93a5ba" fontSize="11">{maximum.toPrecision(5)}</text>
      <text x="45" y="185" fill="#93a5ba" fontSize="11">{minimum.toPrecision(5)}</text>
      <text x="45" y="214" fill="#93a5ba" fontSize="11">{points[0]?.session}</text>
      <text x="780" y="214" textAnchor="end" fill="#93a5ba" fontSize="11">{points.at(-1)?.session}</text>
      {series.flatMap((item) => segments(item.values).map((segment, index) => <g key={`${item.name}-${index}`}>
        <polyline aria-label={`${item.name} segment ${index + 1}`} points={segment.join(' ')} fill="none" stroke={item.color} strokeWidth="2" />
        {segment.length === 1 ? <circle cx={segment[0]?.split(',')[0]} cy={segment[0]?.split(',')[1]} r="3" fill={item.color} /> : null}
      </g>))}
    </Box> : <Alert severity="info">No defined values are available for this view.</Alert>}
    <Box sx={{ display: 'flex', gap: 2, my: 1 }}>{series.map((item) => <Typography key={item.name} sx={{ color: item.color }}>{item.name}</Typography>)}</Box>
    <Box component="details"><summary>Exact values and observation reasons</summary>
      <Box component="ol" aria-label="Exact valuation values" sx={{ pl: 2.5, maxHeight: 250, overflow: 'auto' }}>
        {points.map((point) => <li key={point.row_id}>
          <Typography variant="body2">{point.economic_at} · sequence {point.sequence} · {point.roles.join(', ')} · {point.row_id}</Typography>
          <Typography variant="body2">Strategy: {(view === 'nav' ? point.nav : point.wealth) ?? 'Unavailable'}; analytical SPY: {(view === 'nav' ? point.benchmark_nav : point.benchmark_wealth) ?? 'Unavailable'}; cash: {(view === 'nav' ? point.cash_nav : point.cash_wealth) ?? 'Unavailable'}; external flow: {point.signed_flow}.</Typography>
          <Typography variant="body2">Computable at {point.knowledge_at}. {point.reasons.join(' · ')} {point.benchmark_reasons.join(' · ')} {point.cash_reasons.join(' · ')}</Typography>
          {point.last_known_nav !== null ? <Typography variant="body2">Last-known NAV estimate: {point.last_known_nav}; source {point.last_known_at ?? 'unavailable'}.</Typography> : null}
        </li>)}
      </Box>
    </Box>
  </Box>
}
