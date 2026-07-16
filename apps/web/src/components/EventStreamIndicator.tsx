import SyncRoundedIcon from '@mui/icons-material/SyncRounded'
import { Box, Tooltip, Typography } from '@mui/material'

import { formatRelativeTime } from '../api/format'
import type { EventStreamState } from '../api/types'
import { StatusChip } from './StatusChip'

interface EventStreamIndicatorProps {
  state: EventStreamState
}

const labels: Record<EventStreamState['status'], string> = {
  disabled: 'Live updates off',
  connecting: 'Live updates connecting',
  connected: 'Live updates connected',
  stale: 'Live updates stale',
  disconnected: 'Live updates disconnected',
}

export function EventStreamIndicator({ state }: EventStreamIndicatorProps) {
  return (
    <Tooltip
      title={
        <Box>
          <Typography sx={{ fontSize: 11, fontWeight: 700 }}>{state.detail}</Typography>
          <Typography sx={{ fontSize: 10, mt: 0.5 }}>
            Last activity: {formatRelativeTime(state.last_activity_at)}
          </Typography>
        </Box>
      }
    >
      <Box aria-label={labels[state.status]} sx={{ alignItems: 'center', display: 'flex' }}>
        <SyncRoundedIcon aria-hidden="true" sx={{ color: 'text.secondary', fontSize: 16, mr: 0.7 }} />
        <StatusChip label={labels[state.status]} status={state.status} />
      </Box>
    </Tooltip>
  )
}
