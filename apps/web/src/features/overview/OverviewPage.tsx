import AccountBalanceWalletRoundedIcon from '@mui/icons-material/AccountBalanceWalletRounded'
import PaidRoundedIcon from '@mui/icons-material/PaidRounded'
import RefreshRoundedIcon from '@mui/icons-material/RefreshRounded'
import ShowChartRoundedIcon from '@mui/icons-material/ShowChartRounded'
import StackedLineChartRoundedIcon from '@mui/icons-material/StackedLineChartRounded'
import { Alert, Box, Button, CircularProgress, Chip, Typography } from '@mui/material'

import { ApiError } from '../../api/client'
import { formatCurrency, formatDateTime, formatExposure, isTimestampStale } from '../../api/format'
import { useDashboardSummary } from '../../api/queries'
import type { UiBootstrap } from '../../api/types'
import { ErrorState, OverviewSkeleton } from '../../components/LoadState'
import { MetricCard } from '../../components/MetricCard'
import { PageHeader } from '../../components/PageHeader'
import { DeploymentStatus } from './DeploymentStatus'
import { SystemHealth } from './SystemHealth'
import { WalkingThread } from './WalkingThread'

interface OverviewPageProps {
  bootstrap: UiBootstrap
}

function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    return `Dashboard data is unavailable: ${error.message}`
  }
  if (error instanceof Error) {
    return `Dashboard data is unavailable: ${error.message}`
  }
  return 'Dashboard data is unavailable due to an unexpected error.'
}

export function OverviewPage({ bootstrap }: OverviewPageProps) {
  const summaryQuery = useDashboardSummary()
  const result = summaryQuery.data
  const summary = result?.data
  const summaryIsStale = summary ? isTimestampStale(summary.as_of) : false

  const refresh = () => {
    void summaryQuery.refetch()
  }

  const currency = summary?.account.currency ?? 'USD'
  const totalPnl = summary
    ? (Number(summary.account.realized_pnl) + Number(summary.account.unrealized_pnl)).toFixed(2)
    : '0'
  const pnlDirection = Number(totalPnl) > 0 ? 'positive' : Number(totalPnl) < 0 ? 'negative' : 'neutral'

  return (
    <>
      <PageHeader
        actions={
          <>
            {summary ? (
              <Box sx={{ textAlign: 'right' }}>
                <Typography color="text.secondary" sx={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.07em', textTransform: 'uppercase' }}>
                  Snapshot as of
                </Typography>
                <Typography sx={{ fontSize: 11.5, mt: 0.25 }}>{formatDateTime(summary.as_of)}</Typography>
              </Box>
            ) : null}
            <Button
              disabled={summaryQuery.isFetching}
              onClick={refresh}
              startIcon={summaryQuery.isFetching ? <CircularProgress size={15} /> : <RefreshRoundedIcon />}
              variant="outlined"
            >
              Refresh
            </Button>
          </>
        }
        description="A read-only view of account state, system readiness, and the canonical decision path. Trading controls remain disabled in Phase 0."
        eyebrow="Operations"
        title="Overview"
      />

      {result?.source === 'development-fixture' ? (
        <Alert severity="info" sx={{ mb: 2 }} variant="outlined">
          Development fixtures are active. Values below are deterministic examples and are not broker or account data.
        </Alert>
      ) : null}

      {summaryIsStale ? (
        <Alert aria-live="assertive" severity="warning" sx={{ mb: 2 }} variant="outlined">
          This operational snapshot is stale. Treat all values as read-only until a fresh authoritative response arrives.
        </Alert>
      ) : null}

      {summaryQuery.isPending ? <OverviewSkeleton /> : null}

      {summaryQuery.isError ? (
        <ErrorState message={errorMessage(summaryQuery.error)} onRetry={refresh} />
      ) : null}

      {summary ? (
        <Box aria-live="polite">
          <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: 'repeat(4, minmax(0, 1fr))' }}>
            <MetricCard
              detail="Authoritative account value"
              icon={<PaidRoundedIcon />}
              label="Account equity"
              value={formatCurrency(summary.account.equity, currency)}
            />
            <MetricCard
              detail="Projected from balanced ledger"
              icon={<AccountBalanceWalletRoundedIcon />}
              label="Cash"
              value={formatCurrency(summary.account.cash, currency)}
            />
            <MetricCard
              detail={`${formatCurrency(summary.account.realized_pnl, currency)} realized`}
              direction={pnlDirection}
              icon={<ShowChartRoundedIcon />}
              label="Total P&L"
              value={formatCurrency(totalPnl, currency)}
            />
            <MetricCard
              detail={`${formatExposure(summary.account.net_exposure, currency)} net`}
              icon={<StackedLineChartRoundedIcon />}
              label="Gross exposure"
              value={formatExposure(summary.account.gross_exposure, currency)}
            />
          </Box>

          <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: 'minmax(0, 1.65fr) minmax(300px, 0.7fr)', mt: 2 }}>
            <SystemHealth checks={summary.health} />
            <DeploymentStatus readiness={bootstrap.readiness} summary={summary} />
          </Box>

          <Box sx={{ mt: 2 }}>
            <WalkingThread steps={summary.trace} />
          </Box>

          <Box sx={{ alignItems: 'center', display: 'flex', gap: 1, justifyContent: 'flex-end', mt: 1.5 }}>
            <Typography color="text.secondary" sx={{ fontSize: 10.5 }}>
              Data source
            </Typography>
            <Chip label={result.source === 'api' ? 'Control API' : 'Development fixture'} size="small" variant="outlined" />
          </Box>
        </Box>
      ) : null}
    </>
  )
}
