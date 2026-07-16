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
  if (['healthy', 'ready', 'running', 'completed', 'open', 'connected'].includes(status)) {
    return 'success'
  }
  if (['warning', 'reconciling', 'pending', 'closed', 'connecting', 'stale'].includes(status)) {
    return 'warning'
  }
  if (['critical', 'halted', 'failed', 'not_ready', 'disconnected'].includes(status)) {
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
