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
      sx={(theme) => ({
        alignItems: 'center',
        bgcolor: backgroundColor,
        color: foregroundColor,
        display: 'flex',
        height: 'auto',
        minHeight: ENVIRONMENT_BANNER_HEIGHT,
        flexWrap: 'wrap',
        inset: '0 0 auto 0',
        justifyContent: 'center',
        position: 'relative',
        px: 2,
        py: 1,
        rowGap: 0.5,
        [theme.breakpoints.up('md')]: {
          height: ENVIRONMENT_BANNER_HEIGHT,
          flexWrap: 'nowrap',
          position: 'fixed',
          py: 0,
          rowGap: 0,
        },
        zIndex: theme.zIndex.appBar + 2,
      })}
    >
      <Icon aria-hidden="true" sx={{ fontSize: 17, mr: 1 }} />
      <Typography sx={{ fontSize: 12, fontWeight: 800, letterSpacing: '0.1em', textTransform: 'uppercase', textAlign: 'center', overflowWrap: 'anywhere' }}>
        {label}
      </Typography>
      {environment?.account_id ? (
        <Typography component="span" sx={{ fontFamily: 'monospace', fontSize: 11, ml: 1.5, opacity: 0.82, overflowWrap: 'anywhere' }}>
          Account {environment.account_id}
        </Typography>
      ) : null}
    </Box>
  )
}
