import AccountTreeRoundedIcon from '@mui/icons-material/AccountTreeRounded'
import NotificationsActiveRoundedIcon from '@mui/icons-material/NotificationsActiveRounded'
import PendingActionsRoundedIcon from '@mui/icons-material/PendingActionsRounded'
import { Box, Card, CardContent, Divider, Typography } from '@mui/material'

import { titleCase } from '../../api/format'
import type { DashboardSummary, Readiness } from '../../api/types'
import { StatusChip } from '../../components/StatusChip'

interface DeploymentStatusProps {
  summary: DashboardSummary
  readiness: Readiness
}

export function DeploymentStatus({ summary, readiness }: DeploymentStatusProps) {
  return (
    <Card component="section" aria-labelledby="deployment-status-title" sx={{ height: '100%' }}>
      <CardContent sx={{ p: 2.5, '&:last-child': { pb: 2.5 } }}>
        <Box sx={{ alignItems: 'center', display: 'flex', gap: 1, mb: 2 }}>
          <AccountTreeRoundedIcon aria-hidden="true" color="primary" sx={{ fontSize: 20 }} />
          <Typography component="h2" id="deployment-status-title" variant="h2">
            Active deployment
          </Typography>
        </Box>
        {summary.deployment ? (
          <>
            <Box sx={{ alignItems: 'flex-start', display: 'flex', justifyContent: 'space-between' }}>
              <Box>
                <Typography sx={{ fontSize: 15, fontWeight: 750 }}>{summary.deployment.name}</Typography>
                <Typography color="text.secondary" sx={{ fontSize: 11.5, mt: 0.35 }}>
                  {summary.deployment.strategy_name}
                </Typography>
              </Box>
              <StatusChip status={summary.deployment.state} />
            </Box>
            <Typography color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: 10.5, mt: 1.5 }}>
              {summary.deployment.id}
            </Typography>
          </>
        ) : (
          <Typography color="text.secondary" variant="body2">
            No deployment is active.
          </Typography>
        )}
        <Divider sx={{ my: 2 }} />
        <Box sx={{ alignItems: 'center', display: 'flex', justifyContent: 'space-between' }}>
          <Typography color="text.secondary" sx={{ fontSize: 11.5 }}>
            Account readiness
          </Typography>
          <StatusChip status={readiness.status} />
        </Box>
        {readiness.reasons.length > 0 ? (
          <Typography color="error.main" sx={{ fontSize: 10.5, mt: 1 }}>
            {readiness.reasons.join(' · ')}
          </Typography>
        ) : null}
        <Divider sx={{ my: 2 }} />
        <Box sx={{ display: 'grid', gap: 1.25, gridTemplateColumns: '1fr 1fr' }}>
          <Box>
            <Box sx={{ alignItems: 'center', color: summary.alerts.critical > 0 ? 'error.main' : 'text.secondary', display: 'flex', gap: 0.6 }}>
              <NotificationsActiveRoundedIcon aria-hidden="true" sx={{ fontSize: 16 }} />
              <Typography color="inherit" sx={{ fontSize: 10.5, fontWeight: 700 }}>
                Alerts
              </Typography>
            </Box>
            <Typography sx={{ fontSize: 19, fontWeight: 750, mt: 0.4 }}>{summary.alerts.critical + summary.alerts.warning}</Typography>
          </Box>
          <Box>
            <Box sx={{ alignItems: 'center', color: 'text.secondary', display: 'flex', gap: 0.6 }}>
              <PendingActionsRoundedIcon aria-hidden="true" sx={{ fontSize: 16 }} />
              <Typography color="inherit" sx={{ fontSize: 10.5, fontWeight: 700 }}>
                Commands
              </Typography>
            </Box>
            <Typography sx={{ fontSize: 19, fontWeight: 750, mt: 0.4 }}>{summary.pending_commands}</Typography>
          </Box>
        </Box>
        <Typography color="text.secondary" sx={{ fontSize: 10, mt: 1.5 }}>
          Mode: {summary.deployment ? titleCase(summary.deployment.mode) : 'None'}
        </Typography>
      </CardContent>
    </Card>
  )
}
