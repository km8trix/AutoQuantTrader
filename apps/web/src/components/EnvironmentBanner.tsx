import ErrorOutlineRoundedIcon from '@mui/icons-material/ErrorOutlineRounded'
import ScienceRoundedIcon from '@mui/icons-material/ScienceRounded'
import WarningAmberRoundedIcon from '@mui/icons-material/WarningAmberRounded'
import { Box, Typography } from '@mui/material'

import type { EnvironmentIdentity } from '../api/types'

interface EnvironmentBannerProps {
  environment?: EnvironmentIdentity
  unavailable?: boolean
}

export const ENVIRONMENT_BANNER_HEIGHT = 36

export function EnvironmentBanner({ environment, unavailable = false }: EnvironmentBannerProps) {
  const isLive = environment?.mode === 'live'
  const backgroundColor = unavailable ? 'error.dark' : isLive ? 'error.main' : 'warning.main'
  const foregroundColor = unavailable || isLive ? 'common.white' : '#1a1205'
  const Icon = unavailable ? ErrorOutlineRoundedIcon : isLive ? WarningAmberRoundedIcon : ScienceRoundedIcon
  const modeLabel =
    environment?.mode === 'paper'
      ? 'Paper trading'
      : environment?.mode === 'live'
        ? 'Live trading'
        : 'Local simulation'
  const label = unavailable
    ? 'Environment unknown — control state unavailable'
    : `${modeLabel} — ${environment?.name ?? 'Loading environment'}`

  return (
    <Box
      aria-label="Trading environment"
      role="status"
      sx={{
        alignItems: 'center',
        bgcolor: backgroundColor,
        color: foregroundColor,
        display: 'flex',
        height: ENVIRONMENT_BANNER_HEIGHT,
        inset: '0 0 auto 0',
        justifyContent: 'center',
        position: 'fixed',
        px: 2,
        zIndex: (theme) => theme.zIndex.appBar + 2,
      }}
    >
      <Icon aria-hidden="true" sx={{ fontSize: 17, mr: 1 }} />
      <Typography sx={{ fontSize: 12, fontWeight: 800, letterSpacing: '0.1em', textTransform: 'uppercase' }}>
        {label}
      </Typography>
      {environment?.account_id ? (
        <Typography component="span" sx={{ fontFamily: 'monospace', fontSize: 11, ml: 1.5, opacity: 0.82 }}>
          Account {environment.account_id}
        </Typography>
      ) : null}
    </Box>
  )
}
