import CircleRoundedIcon from '@mui/icons-material/CircleRounded'
import { Chip } from '@mui/material'

import { titleCase } from '../api/format'

type SemanticStatus = string

interface StatusChipProps {
  status: SemanticStatus
  label?: string
  size?: 'small' | 'medium'
}

function colorForStatus(status: SemanticStatus): 'success' | 'warning' | 'error' | 'default' {
  if (
    [
      'active',
      'approved',
      'balanced',
      'clean',
      'completed',
      'connected',
      'current',
      'delivered',
      'filled',
      'healthy',
      'open',
      'passed',
      'ready',
      'running',
    ].includes(status)
  ) {
    return 'success'
  }
  if (
    [
      'blocked_pending_convergence',
      'closed',
      'connecting',
      'differences',
      'paused',
      'pending',
      'reconciling',
      'stale',
      'warning',
      'working',
    ].includes(status)
  ) {
    return 'warning'
  }
  if (
    [
      'critical',
      'disconnected',
      'expired',
      'failed',
      'halted',
      'not_ready',
      'rejected',
      'unavailable',
    ].includes(status)
  ) {
    return 'error'
  }
  return 'default'
}

export function StatusChip({ status, label, size = 'small' }: StatusChipProps) {
  return (
    <Chip
      color={colorForStatus(status)}
      icon={<CircleRoundedIcon aria-hidden="true" />}
      label={label ?? titleCase(status)}
      size={size}
      variant="outlined"
      sx={{
        '& .MuiChip-icon': { fontSize: 9 },
        '& .MuiChip-label': { px: 1 },
      }}
    />
  )
}
