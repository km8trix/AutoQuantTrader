import AccountBalanceRoundedIcon from '@mui/icons-material/AccountBalanceRounded'
import NotificationsActiveRoundedIcon from '@mui/icons-material/NotificationsActiveRounded'
import PendingActionsRoundedIcon from '@mui/icons-material/PendingActionsRounded'
import RefreshRoundedIcon from '@mui/icons-material/RefreshRounded'
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
  Typography,
} from '@mui/material'
import type { ReactNode } from 'react'

import { ApiError } from '../../api/client'
import { formatDateTime, isTimestampStale, titleCase } from '../../api/format'
import { useDashboardSummary } from '../../api/queries'
import type { DashboardSummary, HealthCheck, UiBootstrap } from '../../api/types'
import { ErrorState, OverviewSkeleton } from '../../components/LoadState'
import { PageHeader } from '../../components/PageHeader'
import { StatusChip } from '../../components/StatusChip'

export interface OperationalSnapshotView {
  summary: DashboardSummary
  summaryIsStale: boolean
  readinessIsStale: boolean
}

interface OperationalPageFrameProps {
  bootstrap: UiBootstrap
  children: (snapshot: OperationalSnapshotView) => ReactNode
  description: string
  eyebrow: string
  title: string
}

function dashboardErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    return `Operational data is unavailable: ${error.message}`
  }
  if (error instanceof Error) {
    return `Operational data is unavailable: ${error.message}`
  }
  return 'Operational data is unavailable due to an unexpected error.'
}

function ContextField({
  children,
  label,
}: {
  children: ReactNode
  label: string
}) {
  return (
    <Box>
      <Typography
        color="text.secondary"
        component="dt"
        sx={{
          fontSize: 10,
          fontWeight: 800,
          letterSpacing: '0.09em',
          textTransform: 'uppercase',
        }}
      >
        {label}
      </Typography>
      <Box component="dd" sx={{ m: 0, mt: 0.55 }}>
        {children}
      </Box>
    </Box>
  )
}

function OperationalContext({
  bootstrap,
  readinessIsStale,
  summary,
  summaryIsStale,
}: {
  bootstrap: UiBootstrap
  readinessIsStale: boolean
  summary: DashboardSummary
  summaryIsStale: boolean
}) {
  const pauseAdvertised =
    bootstrap.feature_flags.operations_control === true &&
    bootstrap.feature_flags.control_pause === true
  const haltAdvertised =
    bootstrap.feature_flags.operations_control === true &&
    bootstrap.feature_flags.control_halt === true
  const failSafeControls = [
    ...(pauseAdvertised ? ['PAUSE'] : []),
    ...(haltAdvertised ? ['HALT'] : []),
  ]
  const readinessBlockers =
    bootstrap.readiness.reasons.length > 0
      ? bootstrap.readiness.reasons
      : bootstrap.readiness.status === 'ready'
        ? []
        : ['No blocker detail was provided by the bootstrap response.']

  return (
    <Card
      aria-labelledby="operational-context-title"
      component="section"
      sx={{ mb: 2 }}
    >
      <CardContent sx={{ p: 2.5, '&:last-child': { pb: 2.5 } }}>
        <Typography component="h2" id="operational-context-title" variant="h2">
          Authoritative workspace context
        </Typography>
        <Box
          component="dl"
          sx={{
            display: 'grid',
            gap: 2.5,
            gridTemplateColumns: '1.15fr 0.9fr 1.1fr 0.85fr',
            m: 0,
            mt: 2,
          }}
        >
          <ContextField label="Environment and account">
            <Typography sx={{ fontSize: 13, fontWeight: 750 }}>
              {bootstrap.environment.name}
            </Typography>
            <Typography color="text.secondary" sx={{ fontSize: 11, mt: 0.35 }}>
              {titleCase(bootstrap.environment.mode)} ·{' '}
              <Box component="span" sx={{ fontFamily: 'monospace' }}>
                {bootstrap.environment.account_id}
              </Box>
            </Typography>
          </ContextField>
          <ContextField label="Dashboard snapshot">
            <StatusChip
              label={summaryIsStale ? 'Stale' : 'Fresh'}
              status={summaryIsStale ? 'stale' : 'healthy'}
            />
            <Typography color="text.secondary" sx={{ fontSize: 10.5, mt: 0.55 }}>
              {formatDateTime(summary.as_of)}
            </Typography>
          </ContextField>
          <ContextField label="Account readiness">
            <StatusChip
              label={readinessIsStale ? 'Stale evidence' : undefined}
              status={readinessIsStale ? 'not_ready' : bootstrap.readiness.status}
            />
            <Typography color="text.secondary" sx={{ fontSize: 10.5, mt: 0.55 }}>
              Evidence {formatDateTime(bootstrap.readiness.as_of)}
            </Typography>
            {readinessBlockers.length > 0 ? (
              <Box component="ul" sx={{ color: 'error.main', m: 0, mt: 0.75, pl: 2 }}>
                {readinessBlockers.map((reason) => (
                  <Typography component="li" key={reason} sx={{ fontSize: 10.5 }}>
                    {reason}
                  </Typography>
                ))}
              </Box>
            ) : (
              <Typography color="success.main" sx={{ fontSize: 10.5, mt: 0.75 }}>
                No readiness blockers reported.
              </Typography>
            )}
          </ContextField>
          <ContextField label="Control capability">
            <StatusChip
              label={failSafeControls.length > 0 ? 'Fail-safe only' : 'Not advertised'}
              status={failSafeControls.length > 0 ? 'warning' : 'unknown'}
            />
            <Typography color="text.secondary" sx={{ fontSize: 10.5, mt: 0.55 }}>
              {failSafeControls.length > 0
                ? `${failSafeControls.join(' and ')} advertised; no broker or downgrade actions.`
                : 'No browser control action is advertised.'}
            </Typography>
          </ContextField>
        </Box>
      </CardContent>
    </Card>
  )
}

export function OperationalPageFrame({
  bootstrap,
  children,
  description,
  eyebrow,
  title,
}: OperationalPageFrameProps) {
  const summaryQuery = useDashboardSummary()
  const result = summaryQuery.data
  const summary = result?.data
  const summaryIsStale = summary ? isTimestampStale(summary.as_of) : false
  const readinessIsStale = isTimestampStale(bootstrap.readiness.as_of)

  const refresh = () => {
    void summaryQuery.refetch()
  }

  return (
    <>
      <PageHeader
        actions={
          <>
            {summary ? (
              <Box sx={{ textAlign: 'right' }}>
                <Typography
                  color="text.secondary"
                  sx={{
                    fontSize: 10,
                    fontWeight: 700,
                    letterSpacing: '0.07em',
                    textTransform: 'uppercase',
                  }}
                >
                  Snapshot as of
                </Typography>
                <Typography sx={{ fontSize: 11.5, mt: 0.25 }}>
                  {formatDateTime(summary.as_of)}
                </Typography>
              </Box>
            ) : null}
            <Button
              disabled={summaryQuery.isFetching}
              onClick={refresh}
              startIcon={
                summaryQuery.isFetching ? (
                  <CircularProgress size={15} />
                ) : (
                  <RefreshRoundedIcon />
                )
              }
              variant="outlined"
            >
              Refresh
            </Button>
          </>
        }
        description={description}
        eyebrow={eyebrow}
        title={title}
      />

      {result?.source === 'development-fixture' ? (
        <Alert severity="info" sx={{ mb: 2 }} variant="outlined">
          Development fixtures are active. Values on this page are deterministic
          examples, not broker or account data.
        </Alert>
      ) : null}

      {summaryIsStale || readinessIsStale ? (
        <Alert aria-live="assertive" severity="warning" sx={{ mb: 2 }} variant="outlined">
          Operational evidence is stale. Treat every value as read-only and do not
          infer current broker, risk, or reconciliation state.
        </Alert>
      ) : null}

      {summaryQuery.isPending ? <OverviewSkeleton /> : null}

      {summaryQuery.isError ? (
        <ErrorState message={dashboardErrorMessage(summaryQuery.error)} onRetry={refresh} />
      ) : null}

      {summary ? (
        <Box aria-live="polite">
          <OperationalContext
            bootstrap={bootstrap}
            readinessIsStale={readinessIsStale}
            summary={summary}
            summaryIsStale={summaryIsStale}
          />
          {children({ readinessIsStale, summary, summaryIsStale })}
          <Box
            sx={{
              alignItems: 'center',
              display: 'flex',
              gap: 1,
              justifyContent: 'flex-end',
              mt: 1.5,
            }}
          >
            <Typography color="text.secondary" sx={{ fontSize: 10.5 }}>
              Data source
            </Typography>
            <Chip
              label={result.source === 'api' ? 'Control API' : 'Development fixture'}
              size="small"
              variant="outlined"
            />
          </Box>
        </Box>
      ) : null}
    </>
  )
}

export function OperationalCounters({ summary }: { summary: DashboardSummary }) {
  return (
    <Box
      aria-label="Operational counts"
      component="section"
      sx={{
        display: 'grid',
        gap: 2,
        gridTemplateColumns: 'repeat(3, minmax(0, 1fr))',
        mb: 2,
      }}
    >
      <Card>
        <CardContent sx={{ p: 2, '&:last-child': { pb: 2 } }}>
          <Box sx={{ alignItems: 'center', display: 'flex', gap: 0.8 }}>
            <NotificationsActiveRoundedIcon
              aria-hidden="true"
              color={summary.alerts.critical > 0 ? 'error' : 'disabled'}
              sx={{ fontSize: 18 }}
            />
            <Typography color="text.secondary" sx={{ fontSize: 11, fontWeight: 750 }}>
              Critical alerts
            </Typography>
          </Box>
          <Typography sx={{ fontSize: 24, fontWeight: 780, mt: 0.75 }}>
            {summary.alerts.critical}
          </Typography>
        </CardContent>
      </Card>
      <Card>
        <CardContent sx={{ p: 2, '&:last-child': { pb: 2 } }}>
          <Box sx={{ alignItems: 'center', display: 'flex', gap: 0.8 }}>
            <NotificationsActiveRoundedIcon
              aria-hidden="true"
              color={summary.alerts.warning > 0 ? 'warning' : 'disabled'}
              sx={{ fontSize: 18 }}
            />
            <Typography color="text.secondary" sx={{ fontSize: 11, fontWeight: 750 }}>
              Warning alerts
            </Typography>
          </Box>
          <Typography sx={{ fontSize: 24, fontWeight: 780, mt: 0.75 }}>
            {summary.alerts.warning}
          </Typography>
        </CardContent>
      </Card>
      <Card>
        <CardContent sx={{ p: 2, '&:last-child': { pb: 2 } }}>
          <Box sx={{ alignItems: 'center', display: 'flex', gap: 0.8 }}>
            <PendingActionsRoundedIcon
              aria-hidden="true"
              color={summary.pending_commands > 0 ? 'warning' : 'disabled'}
              sx={{ fontSize: 18 }}
            />
            <Typography color="text.secondary" sx={{ fontSize: 11, fontWeight: 750 }}>
              Pending commands
            </Typography>
          </Box>
          <Typography sx={{ fontSize: 24, fontWeight: 780, mt: 0.75 }}>
            {summary.pending_commands}
          </Typography>
        </CardContent>
      </Card>
    </Box>
  )
}

export function HealthEvidenceList({
  checks,
  emptyMessage,
  title,
}: {
  checks: HealthCheck[]
  emptyMessage: string
  title: string
}) {
  return (
    <Card aria-labelledby="health-evidence-title" component="section">
      <CardContent sx={{ p: 2.5, '&:last-child': { pb: 2.5 } }}>
        <Box sx={{ alignItems: 'center', display: 'flex', gap: 1 }}>
          <AccountBalanceRoundedIcon aria-hidden="true" color="primary" sx={{ fontSize: 20 }} />
          <Typography component="h2" id="health-evidence-title" variant="h2">
            {title}
          </Typography>
        </Box>
        {checks.length > 0 ? (
          <Box component="ul" sx={{ listStyle: 'none', m: 0, mt: 1.5, p: 0 }}>
            {checks.map((check, index) => (
              <Box component="li" key={check.id}>
                {index > 0 ? <Divider /> : null}
                <Box
                  sx={{
                    alignItems: 'flex-start',
                    display: 'grid',
                    gap: 1,
                    gridTemplateColumns: 'minmax(0, 1fr) auto',
                    py: 1.25,
                  }}
                >
                  <Box>
                    <Typography sx={{ fontSize: 12.5, fontWeight: 700 }}>
                      {check.label}
                    </Typography>
                    <Typography color="text.secondary" sx={{ fontSize: 10.5, mt: 0.3 }}>
                      {check.detail}
                    </Typography>
                    <Typography color="text.secondary" sx={{ fontSize: 9.5, mt: 0.45 }}>
                      Reported {formatDateTime(check.as_of)}
                    </Typography>
                  </Box>
                  <StatusChip status={check.status} />
                </Box>
              </Box>
            ))}
          </Box>
        ) : (
          <Alert severity="info" sx={{ mt: 1.5 }} variant="outlined">
            {emptyMessage}
          </Alert>
        )}
      </CardContent>
    </Card>
  )
}

export function UnavailableEvidence({
  detail,
  title,
}: {
  detail: string
  title: string
}) {
  return (
    <Card aria-labelledby="unavailable-evidence-title" component="section">
      <CardContent sx={{ p: 2.5, '&:last-child': { pb: 2.5 } }}>
        <Typography component="h2" id="unavailable-evidence-title" variant="h2">
          {title}
        </Typography>
        <Alert severity="warning" sx={{ mt: 1.5 }} variant="outlined">
          {detail}
        </Alert>
      </CardContent>
    </Card>
  )
}
