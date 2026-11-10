import { Box, Typography } from '@mui/material'

import { formatCurrency, formatDateTime } from '../../api/format'
import type { BacktestEquityPoint } from '../../api/types'

const WIDTH = 800
const HEIGHT = 220
const LEFT = 46
const RIGHT = 18
const TOP = 16
const BOTTOM = 34

export function EquityCurveChart({
  currency,
  points,
}: {
  currency: string
  points: BacktestEquityPoint[]
}) {
  const values = points.map((point) => Number(point.equity))
  const finiteValues = values.filter(Number.isFinite)
  if (points.length === 0 || finiteValues.length !== points.length) {
    return (
      <Box
        sx={{ alignItems: 'center', display: 'flex', justifyContent: 'center', minHeight: 220 }}
      >
        <Typography color="text.secondary" sx={{ fontSize: 12 }}>
          No validated equity points are available.
        </Typography>
      </Box>
    )
  }

  const minimum = Math.min(...finiteValues)
  const maximum = Math.max(...finiteValues)
  const firstPoint = points[0]
  const firstValue = values[0]
  if (!firstPoint || firstValue === undefined) return null
  const range = maximum - minimum || 1
  const plotWidth = WIDTH - LEFT - RIGHT
  const plotHeight = HEIGHT - TOP - BOTTOM
  const coordinate = (value: number, index: number): [number, number] => [
    LEFT + (index / Math.max(points.length - 1, 1)) * plotWidth,
    TOP + ((maximum - value) / range) * plotHeight,
  ]
  const line = values
    .map((value, index) => coordinate(value, index).map((part) => part.toFixed(2)).join(','))
    .join(' ')
  const area = `${LEFT},${TOP + plotHeight} ${line} ${LEFT + plotWidth},${TOP + plotHeight}`

  return (
    <Box>
      <Box
        aria-label={`Equity curve from ${formatCurrency(firstValue.toString(), currency)} to ${formatCurrency(values.at(-1)?.toString() ?? '0', currency)}`}
        component="svg"
        role="img"
        sx={{ display: 'block', height: 'auto', maxHeight: 260, overflow: 'visible', width: '100%' }}
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
      >
        <defs>
          <linearGradient id="equity-area" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="#53d5e8" stopOpacity="0.28" />
            <stop offset="100%" stopColor="#53d5e8" stopOpacity="0.01" />
          </linearGradient>
        </defs>
        {[0, 0.5, 1].map((fraction) => {
          const y = TOP + fraction * plotHeight
          const value = maximum - fraction * range
          return (
            <g key={fraction}>
              <line stroke="#263a52" strokeDasharray="3 5" x1={LEFT} x2={WIDTH - RIGHT} y1={y} y2={y} />
              <text fill="#93a5ba" fontSize="10" textAnchor="end" x={LEFT - 7} y={y + 3}>
                {formatCurrency(value.toString(), currency)}
              </text>
            </g>
          )
        })}
        <polygon fill="url(#equity-area)" points={area} />
        <polyline fill="none" points={line} stroke="#53d5e8" strokeLinecap="round" strokeLinejoin="round" strokeWidth="3" />
        {points.map((point, index) => {
          const value = values[index]
          if (value === undefined) return null
          const [x, y] = coordinate(value, index)
          return (
            <circle key={point.sequence} cx={x} cy={y} fill="#07111f" r="4" stroke="#53d5e8" strokeWidth="2">
              <title>{`${formatDateTime(point.as_of)} — ${formatCurrency(point.equity, currency)}`}</title>
            </circle>
          )
        })}
        <text fill="#93a5ba" fontSize="10" x={LEFT} y={HEIGHT - 8}>
          {formatDateTime(firstPoint.as_of)}
        </text>
        <text fill="#93a5ba" fontSize="10" textAnchor="end" x={WIDTH - RIGHT} y={HEIGHT - 8}>
          {formatDateTime(points.at(-1)?.as_of ?? null)}
        </text>
      </Box>
      <Box
        aria-label="Equity curve values"
        component="ol"
        sx={{
          clip: 'rect(0 0 0 0)',
          clipPath: 'inset(50%)',
          height: 1,
          m: -1,
          overflow: 'hidden',
          p: 0,
          position: 'absolute',
          whiteSpace: 'nowrap',
          width: 1,
        }}
      >
        {points.map((point) => (
          <li key={point.sequence}>{`${formatDateTime(point.as_of)}: ${formatCurrency(point.equity, currency)}`}</li>
        ))}
      </Box>
    </Box>
  )
}
