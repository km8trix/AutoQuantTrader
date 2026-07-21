import AccessTimeRoundedIcon from '@mui/icons-material/AccessTimeRounded'
import AutoGraphRoundedIcon from '@mui/icons-material/AutoGraphRounded'
import {
  AppBar,
  Avatar,
  Box,
  Divider,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  ListSubheader,
  Toolbar,
  Typography,
} from '@mui/material'
import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { NavLink } from 'react-router-dom'

import { formatDateTime, isTimestampStale } from '../api/format'
import { disabledEventStreamState } from '../api/eventStream'
import type { EventStreamState, UiBootstrap } from '../api/types'
import { EnvironmentBanner, ENVIRONMENT_BANNER_HEIGHT } from '../components/EnvironmentBanner'
import { EventStreamIndicator } from '../components/EventStreamIndicator'
import { StatusChip } from '../components/StatusChip'
import { navigationGroups } from './navigation'

const SIDEBAR_WIDTH = 244
const HEADER_HEIGHT = 68

interface AppShellProps {
  bootstrap?: UiBootstrap
  bootstrapUnavailable?: boolean
  eventStreamState?: EventStreamState
  children: ReactNode
}

function Sidebar() {
  return (
    <Box
      component="aside"
      sx={{
        bgcolor: 'background.paper',
        borderRight: 1,
        borderColor: 'divider',
        bottom: 0,
        display: 'flex',
        flexDirection: 'column',
        left: 0,
        position: 'fixed',
        top: ENVIRONMENT_BANNER_HEIGHT,
        width: SIDEBAR_WIDTH,
        zIndex: (theme) => theme.zIndex.appBar,
      }}
    >
      <Box sx={{ alignItems: 'center', display: 'flex', gap: 1.25, height: HEADER_HEIGHT, px: 2.25 }}>
        <Box
          aria-hidden="true"
          sx={{
            alignItems: 'center',
            bgcolor: 'primary.main',
            borderRadius: 1.5,
            color: 'background.default',
            display: 'flex',
            height: 34,
            justifyContent: 'center',
            width: 34,
          }}
        >
          <AutoGraphRoundedIcon sx={{ fontSize: 22 }} />
        </Box>
        <Box>
          <Typography sx={{ fontSize: 15, fontWeight: 800, letterSpacing: '-0.02em' }}>
            AutoQuantTrader
          </Typography>
          <Typography color="text.secondary" sx={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.12em', textTransform: 'uppercase' }}>
            Operator workspace
          </Typography>
        </Box>
      </Box>
      <Divider />
      <Box component="nav" aria-label="Primary navigation" sx={{ flex: 1, overflowY: 'auto', py: 1.25 }}>
        {navigationGroups.map((group) => (
          <List
            dense
            disablePadding
            key={group.label}
            subheader={
              <ListSubheader
                component="div"
                disableSticky
                sx={{ bgcolor: 'transparent', color: 'text.secondary', fontSize: 10, fontWeight: 800, letterSpacing: '0.12em', lineHeight: '28px', px: 2.25, textTransform: 'uppercase' }}
              >
                {group.label}
              </ListSubheader>
            }
            sx={{ mb: 0.75 }}
          >
            {group.items.map((item) => {
              const Icon = item.icon
              return (
                <ListItemButton
                  aria-label={`${item.label}: ${item.description}`}
                  component={NavLink}
                  key={item.path}
                  to={item.path}
                  sx={{
                    borderLeft: '3px solid transparent',
                    borderRadius: '0 7px 7px 0',
                    color: 'text.secondary',
                    mr: 1.25,
                    minHeight: 38,
                    pl: 2,
                    '&.active': {
                      bgcolor: 'rgba(83, 213, 232, 0.1)',
                      borderLeftColor: 'primary.main',
                      color: 'text.primary',
                    },
                    '&:hover': {
                      bgcolor: 'rgba(147, 165, 186, 0.08)',
                      color: 'text.primary',
                    },
                  }}
                >
                  <ListItemIcon sx={{ color: 'inherit', minWidth: 34 }}>
                    <Icon aria-hidden="true" sx={{ fontSize: 19 }} />
                  </ListItemIcon>
                  <ListItemText primary={item.label} slotProps={{ primary: { fontSize: 13, fontWeight: 650 } }} />
                </ListItemButton>
              )
            })}
          </List>
        ))}
      </Box>
      <Box sx={{ borderTop: 1, borderColor: 'divider', px: 2.25, py: 1.75 }}>
        <Typography color="text.secondary" sx={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.09em', textTransform: 'uppercase' }}>
          Phase 2 · Research
        </Typography>
        <Typography color="text.secondary" sx={{ fontSize: 11, mt: 0.4 }}>
          Durable fixture backtests
        </Typography>
      </Box>
    </Box>
  )
}

function WorkspaceHeader({
  bootstrap,
  eventStreamState,
}: {
  bootstrap?: UiBootstrap
  eventStreamState: EventStreamState
}) {
  const [now, setNow] = useState(() => Date.now())

  useEffect(() => {
    const timer = setInterval(() => {
      setNow(Date.now())
    }, 5_000)
    return () => clearInterval(timer)
  }, [])

  const readinessIsStale = bootstrap
    ? isTimestampStale(bootstrap.readiness.as_of, 30_000, now)
    : false
  const marketClockIsStale = bootstrap
    ? isTimestampStale(bootstrap.market_clock.as_of, 30_000, now)
    : false

  return (
    <AppBar
      color="transparent"
      component="header"
      elevation={0}
      position="fixed"
      sx={{
        backdropFilter: 'blur(16px)',
        bgcolor: 'rgba(7, 17, 31, 0.88)',
        borderBottom: 1,
        borderColor: 'divider',
        left: SIDEBAR_WIDTH,
        right: 0,
        top: ENVIRONMENT_BANNER_HEIGHT,
        width: 'auto',
      }}
    >
      <Toolbar disableGutters sx={{ height: HEADER_HEIGHT, minHeight: `${HEADER_HEIGHT}px !important`, px: 3 }}>
        <Box sx={{ alignItems: 'center', display: 'flex', gap: 1.25 }}>
          <AccessTimeRoundedIcon aria-hidden="true" color="primary" sx={{ fontSize: 19 }} />
          <Box>
            <Typography color="text.secondary" sx={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
              Market session
            </Typography>
            <Typography sx={{ fontSize: 12, fontWeight: 650 }}>
              {bootstrap ? formatDateTime(bootstrap.market_clock.as_of) : 'Loading market clock'}
            </Typography>
          </Box>
          <StatusChip
            label={marketClockIsStale ? 'Market clock stale' : undefined}
            status={marketClockIsStale ? 'unknown' : bootstrap?.market_clock.status ?? 'unknown'}
          />
        </Box>
        <Box sx={{ flex: 1 }} />
        <Box sx={{ alignItems: 'center', display: 'flex', gap: 1.5 }}>
          <EventStreamIndicator state={eventStreamState} />
          <StatusChip
            label={
              readinessIsStale
                ? 'Readiness stale'
                : bootstrap?.readiness.status === 'ready'
                  ? 'System ready'
                  : undefined
            }
            status={readinessIsStale ? 'not_ready' : bootstrap?.readiness.status ?? 'unknown'}
          />
          <Divider flexItem orientation="vertical" />
          <Box
            aria-label="Current operator session"
            role="group"
            sx={{ alignItems: 'center', display: 'flex', gap: 1.1, px: 0.75, py: 0.5 }}
          >
            <Avatar sx={{ bgcolor: 'primary.dark', fontSize: 12, fontWeight: 800, height: 30, width: 30 }}>
              {bootstrap?.user.display_name.slice(0, 1).toUpperCase() ?? '?'}
            </Avatar>
            <Box sx={{ textAlign: 'left' }}>
              <Typography sx={{ fontSize: 12, fontWeight: 700 }}>
                {bootstrap?.user.display_name ?? 'Operator'}
              </Typography>
              <Typography color="text.secondary" sx={{ fontSize: 10 }}>
                Administrator
              </Typography>
            </Box>
          </Box>
        </Box>
      </Toolbar>
    </AppBar>
  )
}

export function AppShell({
  bootstrap,
  bootstrapUnavailable = false,
  eventStreamState = disabledEventStreamState,
  children,
}: AppShellProps) {
  return (
    <Box sx={{ minHeight: 720, minWidth: 1280 }}>
      <Box
        component="a"
        href="#main-content"
        sx={{
          bgcolor: 'primary.main',
          borderRadius: 1,
          color: 'background.default',
          fontWeight: 800,
          left: 12,
          p: 1,
          position: 'fixed',
          top: -100,
          zIndex: (theme) => theme.zIndex.tooltip + 1,
          '&:focus': { top: 8 },
        }}
      >
        Skip to main content
      </Box>
      <EnvironmentBanner environment={bootstrap?.environment} unavailable={bootstrapUnavailable} />
      <Sidebar />
      <WorkspaceHeader bootstrap={bootstrap} eventStreamState={eventStreamState} />
      <Box
        component="main"
        id="main-content"
        sx={{
          ml: `${SIDEBAR_WIDTH}px`,
          minHeight: 720,
          pt: `${ENVIRONMENT_BANNER_HEIGHT + HEADER_HEIGHT}px`,
        }}
        tabIndex={-1}
      >
        <Box sx={{ mx: 'auto', maxWidth: 1680, p: 3 }}>{children}</Box>
      </Box>
    </Box>
  )
}
