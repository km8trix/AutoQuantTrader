import RefreshRoundedIcon from '@mui/icons-material/RefreshRounded'
import { Alert, Box, Button, Typography } from '@mui/material'
import { Component, Fragment } from 'react'
import type { ReactNode } from 'react'

import { EnvironmentBanner, ENVIRONMENT_BANNER_HEIGHT } from '../components/EnvironmentBanner'

interface AppErrorBoundaryProps {
  children: ReactNode
}

interface AppErrorBoundaryState {
  error: Error | null
  recoveryKey: number
}

export class AppErrorBoundary extends Component<
  AppErrorBoundaryProps,
  AppErrorBoundaryState
> {
  override state: AppErrorBoundaryState = {
    error: null,
    recoveryKey: 0,
  }

  static getDerivedStateFromError(error: Error): Partial<AppErrorBoundaryState> {
    return { error }
  }

  private readonly recover = () => {
    this.setState((state) => ({
      error: null,
      recoveryKey: state.recoveryKey + 1,
    }))
  }

  override render() {
    if (this.state.error) {
      return (
        <Box sx={{ minHeight: 720, minWidth: 1280 }}>
          <EnvironmentBanner unavailable />
          <Box
            component="main"
            sx={{ mx: 'auto', maxWidth: 900, px: 4, pt: `${ENVIRONMENT_BANNER_HEIGHT + 80}px` }}
          >
            <Typography color="primary.main" sx={{ fontSize: 11, fontWeight: 800, letterSpacing: '0.12em', textTransform: 'uppercase' }}>
              Safe state
            </Typography>
            <Typography component="h1" variant="h1" sx={{ mt: 1 }}>
              The workspace could not be rendered
            </Typography>
            <Alert
              action={
                <Button
                  color="inherit"
                  onClick={this.recover}
                  size="small"
                  startIcon={<RefreshRoundedIcon />}
                >
                  Retry workspace
                </Button>
              }
              severity="error"
              sx={{ mt: 3 }}
              variant="outlined"
            >
              The interface entered a safe read-only state. No trading command was submitted.
            </Alert>
          </Box>
        </Box>
      )
    }

    return <Fragment key={this.state.recoveryKey}>{this.props.children}</Fragment>
  }
}
