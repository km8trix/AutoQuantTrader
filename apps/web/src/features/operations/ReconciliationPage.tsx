import FactCheckRoundedIcon from '@mui/icons-material/FactCheckRounded'
import { Alert, Box, Card, CardContent, Typography } from '@mui/material'

import { titleCase } from '../../api/format'
import type { UiBootstrap } from '../../api/types'
import { StatusChip } from '../../components/StatusChip'
import { OperationalControlPanel } from './OperationalControlPanel'
import {
  HealthEvidenceList,
  OperationalCounters,
  OperationalPageFrame,
  UnavailableEvidence,
} from './OperationsPageComponents'

const reconciliationHealthTerms = [
  'reconcil',
  'broker',
  'ledger',
  'portfolio',
  'execution',
] as const

export function ReconciliationPage({ bootstrap }: { bootstrap: UiBootstrap }) {
  return (
    <OperationalPageFrame
      bootstrap={bootstrap}
      description="Read-only reconciliation evidence plus narrowly gated fail-safe PAUSE/HALT controls. Broker-versus-local agreement is never inferred from summary signals."
      eyebrow="Phase 5 · Operations"
      title="Reconciliation"
    >
      {({ readinessIsStale, summary }) => {
        const reconciliationChecks = summary.health.filter((check) => {
          const searchable = `${check.id} ${check.label}`.toLowerCase()
          return reconciliationHealthTerms.some((term) => searchable.includes(term))
        })

        return (
          <>
            <OperationalCounters summary={summary} />
            <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: '1fr 1fr' }}>
              <Card aria-labelledby="reconciliation-posture-title" component="section">
                <CardContent sx={{ p: 2.5, '&:last-child': { pb: 2.5 } }}>
                  <Box sx={{ alignItems: 'center', display: 'flex', gap: 1 }}>
                    <FactCheckRoundedIcon
                      aria-hidden="true"
                      color="primary"
                      sx={{ fontSize: 20 }}
                    />
                    <Typography
                      component="h2"
                      id="reconciliation-posture-title"
                      variant="h2"
                    >
                      Reported reconciliation posture
                    </Typography>
                    <Box sx={{ flex: 1 }} />
                    <StatusChip
                      label={
                        readinessIsStale
                          ? 'Readiness stale'
                          : titleCase(bootstrap.readiness.status)
                      }
                      status={
                        readinessIsStale ? 'not_ready' : bootstrap.readiness.status
                      }
                    />
                  </Box>
                  <Alert severity="info" sx={{ mt: 1.5 }} variant="outlined">
                    Account readiness is a gating signal, not proof that broker and
                    local state agree.
                  </Alert>
                  <Typography color="text.secondary" sx={{ fontSize: 11.5, mt: 1.5 }}>
                    {summary.deployment
                      ? `Deployment ${summary.deployment.name} reports ${titleCase(summary.deployment.state)} in ${titleCase(summary.deployment.mode)} mode.`
                      : 'No active deployment is reported by the dashboard summary.'}
                  </Typography>
                </CardContent>
              </Card>
              <UnavailableEvidence
                detail="No dedicated reconciliation run, broker snapshot, local projection digest, difference set, or signed completion receipt is available in UiBootstrap or DashboardSummary. Current agreement is not authoritative."
                title="Reconciliation authority unavailable"
              />
            </Box>

            <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: '1fr 1fr', mt: 2 }}>
              <HealthEvidenceList
                checks={reconciliationChecks}
                emptyMessage="No reconciliation-related subsystem health checks are present in the dashboard summary."
                title="Related subsystem health"
              />
              <OperationalControlPanel bootstrap={bootstrap} />
            </Box>
          </>
        )
      }}
    </OperationalPageFrame>
  )
}
