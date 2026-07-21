import LockOutlinedIcon from '@mui/icons-material/LockOutlined'
import { Box, Chip, Skeleton, Tooltip, Typography } from '@mui/material'
import type { ReactNode } from 'react'

export function ResearchPageSkeleton({ label }: { label: string }) {
  return (
    <Box aria-label={label} aria-live="polite">
      <Box
        sx={{
          display: 'grid',
          gap: 2,
          gridTemplateColumns: { xs: '1fr', lg: 'repeat(3, minmax(0, 1fr))' },
        }}
      >
        {Array.from({ length: 3 }, (_, index) => (
          <Skeleton height={150} key={index} variant="rounded" />
        ))}
      </Box>
      <Skeleton height={330} sx={{ mt: 2 }} variant="rounded" />
    </Box>
  )
}

export function DigestValue({ children, label }: { children: string; label: string }) {
  return (
    <Tooltip title={`${label}: ${children}`}>
      <Typography
        aria-label={`${label}: ${children}`}
        component="span"
        sx={{
          display: 'block',
          fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
          fontSize: 10.5,
          maxWidth: '100%',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}
      >
        {children}
      </Typography>
    </Tooltip>
  )
}

export function ImmutableChip({ label = 'Immutable' }: { label?: string }) {
  return (
    <Chip
      color="primary"
      icon={<LockOutlinedIcon aria-hidden="true" />}
      label={label}
      size="small"
      variant="outlined"
    />
  )
}

export function LabeledValue({
  label,
  children,
}: {
  label: string
  children: ReactNode
}) {
  return (
    <Box sx={{ minWidth: 0 }}>
      <Typography
        color="text.secondary"
        sx={{ fontSize: 9.5, fontWeight: 750, letterSpacing: '0.08em', textTransform: 'uppercase' }}
      >
        {label}
      </Typography>
      <Box sx={{ mt: 0.35 }}>{children}</Box>
    </Box>
  )
}
