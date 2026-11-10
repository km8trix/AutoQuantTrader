import ArrowDownwardRoundedIcon from '@mui/icons-material/ArrowDownwardRounded'
import ArrowUpwardRoundedIcon from '@mui/icons-material/ArrowUpwardRounded'
import RemoveRoundedIcon from '@mui/icons-material/RemoveRounded'
import { Box, Card, CardContent, Typography } from '@mui/material'
import type { ReactNode } from 'react'

interface MetricCardProps {
  label: string
  value: string
  detail: string
  icon: ReactNode
  direction?: 'positive' | 'negative' | 'neutral'
}

export function MetricCard({ label, value, detail, icon, direction = 'neutral' }: MetricCardProps) {
  const DirectionIcon =
    direction === 'positive'
      ? ArrowUpwardRoundedIcon
      : direction === 'negative'
        ? ArrowDownwardRoundedIcon
        : RemoveRoundedIcon
  const directionColor = direction === 'positive' ? 'success.main' : direction === 'negative' ? 'error.main' : 'text.secondary'

  return (
    <Card component="article" sx={{ height: '100%' }}>
      <CardContent sx={{ p: 2.25, '&:last-child': { pb: 2.25 } }}>
        <Box sx={{ alignItems: 'center', display: 'flex', justifyContent: 'space-between' }}>
          <Typography color="text.secondary" variant="subtitle2">
            {label}
          </Typography>
          <Box aria-hidden="true" sx={{ color: 'primary.main', display: 'flex' }}>
            {icon}
          </Box>
        </Box>
        <Typography sx={{ fontSize: '1.55rem', fontVariantNumeric: 'tabular-nums', fontWeight: 750, letterSpacing: '-0.025em', mt: 1.25 }}>
          {value}
        </Typography>
        <Box sx={{ alignItems: 'center', color: directionColor, display: 'flex', gap: 0.5, mt: 0.8 }}>
          <DirectionIcon aria-hidden="true" sx={{ fontSize: 15 }} />
          <Typography color="inherit" sx={{ fontSize: 12 }}>
            {detail}
          </Typography>
        </Box>
      </CardContent>
    </Card>
  )
}
