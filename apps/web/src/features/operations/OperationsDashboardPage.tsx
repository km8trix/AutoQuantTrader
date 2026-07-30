import AccountBalanceRoundedIcon from '@mui/icons-material/AccountBalanceRounded'
import AdminPanelSettingsRoundedIcon from '@mui/icons-material/AdminPanelSettingsRounded'
import NotificationsActiveRoundedIcon from '@mui/icons-material/NotificationsActiveRounded'
import ReceiptLongRoundedIcon from '@mui/icons-material/ReceiptLongRounded'
import RefreshRoundedIcon from '@mui/icons-material/RefreshRounded'
import RouterRoundedIcon from '@mui/icons-material/RouterRounded'
import ShieldRoundedIcon from '@mui/icons-material/ShieldRounded'
import ShoppingCartRoundedIcon from '@mui/icons-material/ShoppingCartRounded'
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material'
import type { ReactNode } from 'react'

import { ApiError } from '../../api/client'
import {
  formatCurrency,
  formatDateTime,
  formatRelativeTime,
  isTimestampStale,
  titleCase,
} from '../../api/format'
import type { UiBootstrap } from '../../api/types'
import { ErrorState } from '../../components/LoadState'
import { MetricCard } from '../../components/MetricCard'
import { PageHeader } from '../../components/PageHeader'
import { StatusChip } from '../../components/StatusChip'
import {
  DigestValue,
  ImmutableChip,
  LabeledValue,
  ResearchPageSkeleton,
} from '../research/ResearchPageComponents'
import { useOperationsDashboard } from './api'
import { OperationalControlPanel } from './OperationalControlPanel'
import type {
  OperationalAlert,
  OperationalControl,
  OperationalFill,
  OperationalOrder,
  OperationalPosition,
  OperationalReconciliation,
  OperationalRiskDecision,
  OperationsDashboardSnapshot,
  RiskReservation,
} from './types'

interface OperationsDashboardPageProps {
  bootstrap: UiBootstrap
}

interface SectionCardProps {
  title: string
  icon: ReactNode
  children: ReactNode
  action?: ReactNode
}

function SectionCard({ title, icon, children, action }: SectionCardProps) {
  return (
    <Card component="section" sx={{ height: '100%' }}>
      <CardContent sx={{ p: 2.5, '&:last-child': { pb: 2.5 } }}>
        <Box sx={{ alignItems: 'center', display: 'flex', gap: 1, mb: 2 }}>
          <Box aria-hidden="true" sx={{ color: 'primary.main', display: 'flex' }}>
            {icon}
          </Box>
          <Typography component="h2" variant="h2">
            {title}
          </Typography>
          <Box sx={{ flex: 1 }} />
          {action}
        </Box>
        {children}
      </CardContent>
    </Card>
  )
}

function EmptyValue({ children }: { children: ReactNode }) {
  return (
    <Typography color="text.secondary" sx={{ fontSize: 11.5, py: 1 }}>
      {children}
    </Typography>
  )
}

function MonospaceValue({ children }: { children: ReactNode }) {
  return (
    <Typography
      component="span"
      sx={{
        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
        fontSize: 10.5,
      }}
    >
      {children}
    </Typography>
  )
}

function AuthorityPanel({
  bootstrap,
  snapshot,
}: {
  bootstrap: UiBootstrap
  snapshot: OperationsDashboardSnapshot
}) {
  return (
    <SectionCard
      action={<StatusChip status={snapshot.coordinator.status} />}
      icon={<RouterRoundedIcon sx={{ fontSize: 20 }} />}
      title="Authority & freshness"
    >
      <Box
        sx={{
          display: 'grid',
          gap: 1.5,
          gridTemplateColumns: 'repeat(3, minmax(0, 1fr))',
          mb: 2,
        }}
      >
        <LabeledValue label="Environment">
          <Typography sx={{ fontSize: 12.5, fontWeight: 700 }}>
            {bootstrap.environment.name}
          </Typography>
        </LabeledValue>
        <LabeledValue label="Account">
          <MonospaceValue>{bootstrap.environment.account_id}</MonospaceValue>
        </LabeledValue>
        <LabeledValue label="Fence generation">
          <Typography sx={{ fontSize: 12.5, fontWeight: 700 }}>
            {snapshot.coordinator.fencing_generation ?? 'Unavailable'}
          </Typography>
        </LabeledValue>
      </Box>
      <Typography color="text.secondary" sx={{ fontSize: 11.5, mb: 1.25 }}>
        {snapshot.coordinator.detail}
      </Typography>
      <Box component="ul" sx={{ listStyle: 'none', m: 0, p: 0 }}>
        {snapshot.freshness.map((item) => (
          <Box
            component="li"
            key={item.source_id}
            sx={{
              alignItems: 'center',
              borderTop: 1,
              borderColor: 'divider',
              display: 'grid',
              gap: 1,
              gridTemplateColumns: 'minmax(130px, 0.7fr) minmax(240px, 1.3fr) auto',
              py: 1.2,
            }}
          >
            <Box>
              <Typography sx={{ fontSize: 12, fontWeight: 700 }}>{item.label}</Typography>
              <Typography color="text.secondary" sx={{ fontSize: 9.5 }}>
                Budget {item.maximum_age_seconds}s
              </Typography>
            </Box>
            <Typography color="text.secondary" sx={{ fontSize: 10.5 }}>
              {item.detail}
            </Typography>
            <Box sx={{ textAlign: 'right' }}>
              <StatusChip status={item.status} />
              <Typography color="text.secondary" sx={{ fontSize: 9.5, mt: 0.4 }}>
                {formatRelativeTime(item.observed_at)}
              </Typography>
            </Box>
          </Box>
        ))}
      </Box>
    </SectionCard>
  )
}

function DeploymentPanel({
  snapshot,
}: {
  snapshot: OperationsDashboardSnapshot
}) {
  const deployment = snapshot.deployment
  return (
    <SectionCard
      action={<StatusChip status={deployment.state} />}
      icon={<AdminPanelSettingsRoundedIcon sx={{ fontSize: 20 }} />}
      title="Strategy & deployment"
    >
      <Box sx={{ display: 'grid', gap: 1.7 }}>
        <LabeledValue label="Deployment">
          <Typography sx={{ fontSize: 13.5, fontWeight: 750 }}>
            {deployment.deployment_id}
          </Typography>
        </LabeledValue>
        <Box sx={{ display: 'grid', gap: 1.5, gridTemplateColumns: '1fr 1fr' }}>
          <LabeledValue label="Strategy">
            <Typography sx={{ fontSize: 12.5, fontWeight: 700 }}>
              {deployment.strategy_id}@{deployment.strategy_version}
            </Typography>
          </LabeledValue>
          <LabeledValue label="Mode">
            <Typography sx={{ fontSize: 12.5, fontWeight: 700 }}>
              {titleCase(deployment.mode)}
            </Typography>
          </LabeledValue>
        </Box>
        <LabeledValue label="Configuration digest">
          <DigestValue label="Strategy configuration digest">
            {deployment.strategy_configuration_sha256}
          </DigestValue>
        </LabeledValue>
        <LabeledValue label="Last transition">
          <Typography sx={{ fontSize: 11.5 }}>{formatDateTime(deployment.updated_at)}</Typography>
        </LabeledValue>
      </Box>
    </SectionCard>
  )
}

function OrdersTable({ orders }: { orders: OperationalOrder[] }) {
  if (orders.length === 0) {
    return <EmptyValue>No durable orders are present in this snapshot.</EmptyValue>
  }
  return (
    <TableContainer>
      <Table aria-label="Orders" size="small">
        <TableHead>
          <TableRow>
            <TableCell>Symbol</TableCell>
            <TableCell>Status</TableCell>
            <TableCell>Side</TableCell>
            <TableCell align="right">Filled / quantity</TableCell>
            <TableCell>Submitted</TableCell>
            <TableCell>Client order ID</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {orders.map((order) => (
            <TableRow key={order.order_id}>
              <TableCell sx={{ fontWeight: 750 }}>{order.symbol}</TableCell>
              <TableCell>
                <StatusChip status={order.status} />
              </TableCell>
              <TableCell>{titleCase(order.side)}</TableCell>
              <TableCell align="right">
                {order.filled_quantity} / {order.quantity}
              </TableCell>
              <TableCell>{formatDateTime(order.submitted_at)}</TableCell>
              <TableCell>
                <MonospaceValue>{order.client_order_id}</MonospaceValue>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  )
}

function FillsTable({
  fills,
  currency,
}: {
  fills: OperationalFill[]
  currency: string
}) {
  if (fills.length === 0) {
    return <EmptyValue>No fills are present in this snapshot.</EmptyValue>
  }
  return (
    <TableContainer>
      <Table aria-label="Fills" size="small">
        <TableHead>
          <TableRow>
            <TableCell>Symbol</TableCell>
            <TableCell>Side</TableCell>
            <TableCell align="right">Quantity</TableCell>
            <TableCell align="right">Price</TableCell>
            <TableCell align="right">Fee</TableCell>
            <TableCell>Executed</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {fills.map((fill) => (
            <TableRow key={fill.fill_id}>
              <TableCell sx={{ fontWeight: 750 }}>{fill.symbol}</TableCell>
              <TableCell>{titleCase(fill.side)}</TableCell>
              <TableCell align="right">{fill.quantity}</TableCell>
              <TableCell align="right">{formatCurrency(fill.price, currency)}</TableCell>
              <TableCell align="right">{formatCurrency(fill.fee, currency)}</TableCell>
              <TableCell>{formatDateTime(fill.executed_at)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  )
}

function TradingActivityPanel({
  orders,
  fills,
  currency,
}: {
  orders: OperationalOrder[]
  fills: OperationalFill[]
  currency: string
}) {
  return (
    <SectionCard
      action={<Chip label={`${orders.length} orders · ${fills.length} fills`} size="small" />}
      icon={<ShoppingCartRoundedIcon sx={{ fontSize: 20 }} />}
      title="Orders & fills"
    >
      <Typography color="text.secondary" sx={{ fontSize: 10, fontWeight: 750, mb: 0.7 }}>
        ORDER ACTIVITY
      </Typography>
      <OrdersTable orders={orders} />
      <Divider sx={{ my: 2 }} />
      <Typography color="text.secondary" sx={{ fontSize: 10, fontWeight: 750, mb: 0.7 }}>
        FILL ACTIVITY
      </Typography>
      <FillsTable currency={currency} fills={fills} />
    </SectionCard>
  )
}

function PositionsTable({
  positions,
  currency,
}: {
  positions: OperationalPosition[]
  currency: string
}) {
  if (positions.length === 0) {
    return <EmptyValue>No ledger-projected positions are present.</EmptyValue>
  }
  return (
    <TableContainer>
      <Table aria-label="Account positions" size="small">
        <TableHead>
          <TableRow>
            <TableCell>Symbol</TableCell>
            <TableCell align="right">Quantity</TableCell>
            <TableCell align="right">Average cost</TableCell>
            <TableCell align="right">Mark</TableCell>
            <TableCell align="right">Market value</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {positions.map((position) => (
            <TableRow key={position.instrument_id}>
              <TableCell sx={{ fontWeight: 750 }}>{position.symbol}</TableCell>
              <TableCell align="right">{position.quantity}</TableCell>
              <TableCell align="right">
                {formatCurrency(position.average_cost, currency)}
              </TableCell>
              <TableCell align="right">
                {formatCurrency(position.market_price, currency)}
              </TableCell>
              <TableCell align="right">
                {formatCurrency(position.market_value, currency)}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  )
}

function AccountPanel({ snapshot }: { snapshot: OperationsDashboardSnapshot }) {
  const { account, ledger } = snapshot
  const metrics: ReadonlyArray<readonly [string, string]> = [
    ['Equity', account.equity],
    ['Cash', account.cash],
    ['Gross exposure', account.gross_exposure],
    ['Net exposure', account.net_exposure],
  ]
  return (
    <SectionCard
      action={<StatusChip status={ledger.status} />}
      icon={<AccountBalanceRoundedIcon sx={{ fontSize: 20 }} />}
      title="Account & ledger positions"
    >
      <Box
        sx={{
          display: 'grid',
          gap: 1.5,
          gridTemplateColumns: 'repeat(4, minmax(0, 1fr))',
          mb: 2,
        }}
      >
        {metrics.map(([label, value]) => (
          <LabeledValue key={label} label={label}>
            <Typography sx={{ fontSize: 14, fontWeight: 750 }}>
              {formatCurrency(value, account.currency)}
            </Typography>
          </LabeledValue>
        ))}
      </Box>
      <PositionsTable currency={account.currency} positions={snapshot.positions} />
      <Divider sx={{ my: 1.7 }} />
      <Typography color="text.secondary" sx={{ fontSize: 10.5 }}>
        {ledger.detail} {ledger.entry_count} entries · latest{' '}
        {formatDateTime(ledger.latest_posted_at)}
      </Typography>
    </SectionCard>
  )
}

function ReservationList({
  reservations,
}: {
  reservations: RiskReservation[]
}) {
  if (reservations.length === 0) {
    return <EmptyValue>No active or retained reservations are present.</EmptyValue>
  }
  return (
    <Box component="ul" sx={{ listStyle: 'none', m: 0, p: 0 }}>
      {reservations.map((reservation) => (
        <Box
          component="li"
          key={`${reservation.decision_id}:${reservation.intent_id}`}
          sx={{
            alignItems: 'center',
            borderTop: 1,
            borderColor: 'divider',
            display: 'grid',
            gap: 1,
            gridTemplateColumns: 'minmax(0, 1fr) auto auto',
            py: 1,
            '&:first-of-type': { borderTop: 0 },
          }}
        >
          <DigestValue label="Reservation decision ID">
            {reservation.decision_id}
          </DigestValue>
          <Typography sx={{ fontSize: 11.5, fontWeight: 700 }}>
            {formatCurrency(reservation.amount, reservation.currency)}
          </Typography>
          <StatusChip status={reservation.state} />
        </Box>
      ))}
    </Box>
  )
}

function RiskDecisionList({
  decisions,
}: {
  decisions: OperationalRiskDecision[]
}) {
  if (decisions.length === 0) {
    return <EmptyValue>No risk decisions are present.</EmptyValue>
  }
  return (
    <Box sx={{ display: 'grid', gap: 1.5 }}>
      {decisions.map((decision) => (
        <Box
          key={decision.decision_id}
          sx={{ border: 1, borderColor: 'divider', borderRadius: 1.5, p: 1.5 }}
        >
          <Box sx={{ alignItems: 'center', display: 'flex', gap: 1 }}>
            <Box sx={{ minWidth: 0 }}>
              <DigestValue label="Risk decision ID">{decision.decision_id}</DigestValue>
              <Typography color="text.secondary" sx={{ fontSize: 9.5, mt: 0.25 }}>
                Policy version:{' '}
                <Box component="span" sx={{ fontFamily: 'monospace' }}>
                  {decision.policy_version}
                </Box>
              </Typography>
              <Typography color="text.secondary" sx={{ fontSize: 9.5, mt: 0.2 }}>
                Evaluated {formatDateTime(decision.evaluated_at)}
              </Typography>
            </Box>
            <Box sx={{ flex: 1 }} />
            <StatusChip status={decision.status} />
          </Box>
          <TableContainer sx={{ mt: 1 }}>
            <Table aria-label={`Risk rules for ${decision.decision_id}`} size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Rule</TableCell>
                  <TableCell>Observed</TableCell>
                  <TableCell>Limit</TableCell>
                  <TableCell align="right">Result</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {decision.rules.map((rule) => (
                  <TableRow key={rule.rule}>
                    <TableCell>{titleCase(rule.rule)}</TableCell>
                    <TableCell>{rule.observed}</TableCell>
                    <TableCell>{rule.limit}</TableCell>
                    <TableCell align="right">
                      <StatusChip status={rule.passed ? 'passed' : 'failed'} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Box>
      ))}
    </Box>
  )
}

function RiskPanel({ snapshot }: { snapshot: OperationsDashboardSnapshot }) {
  return (
    <SectionCard
      action={<ImmutableChip label="Durable evidence" />}
      icon={<ShieldRoundedIcon sx={{ fontSize: 20 }} />}
      title="Risk reservations & decisions"
    >
      <Typography color="text.secondary" sx={{ fontSize: 10, fontWeight: 750, mb: 0.7 }}>
        RESERVATIONS
      </Typography>
      <ReservationList reservations={snapshot.reservations} />
      <Divider sx={{ my: 2 }} />
      <Typography color="text.secondary" sx={{ fontSize: 10, fontWeight: 750, mb: 0.9 }}>
        DECISIONS
      </Typography>
      <RiskDecisionList decisions={snapshot.risk_decisions} />
    </SectionCard>
  )
}

function ReconciliationPanel({
  reconciliation,
}: {
  reconciliation: OperationalReconciliation
}) {
  return (
    <SectionCard
      action={<StatusChip status={reconciliation.status} />}
      icon={<ReceiptLongRoundedIcon sx={{ fontSize: 20 }} />}
      title="Reconciliation differences"
    >
      <Typography color="text.secondary" sx={{ fontSize: 11.5, mb: 1.2 }}>
        {reconciliation.detail}
      </Typography>
      {reconciliation.differences.length === 0 ? (
        <EmptyValue>No retained differences are present.</EmptyValue>
      ) : (
        <Box component="ul" sx={{ listStyle: 'none', m: 0, p: 0 }}>
          {reconciliation.differences.map((difference) => (
            <Box
              component="li"
              key={`${difference.field}:${difference.disposition}`}
              sx={{ borderTop: 1, borderColor: 'divider', py: 1.2 }}
            >
              <Box sx={{ alignItems: 'center', display: 'flex', gap: 1 }}>
                <Typography sx={{ fontSize: 12, fontWeight: 750 }}>
                  {difference.field}
                </Typography>
                <Box sx={{ flex: 1 }} />
                <StatusChip status={difference.disposition} />
              </Box>
              <Typography color="text.secondary" sx={{ fontSize: 10.5, mt: 0.6 }}>
                Local: {difference.local_value} · Broker: {difference.broker_value}
              </Typography>
            </Box>
          ))}
        </Box>
      )}
      <Typography color="text.secondary" sx={{ fontSize: 9.5, mt: 1 }}>
        Observed {formatDateTime(reconciliation.observed_at)}
      </Typography>
    </SectionCard>
  )
}

function AlertsPanel({ alerts }: { alerts: OperationalAlert[] }) {
  return (
    <SectionCard
      action={<Chip label={`${alerts.length} open`} size="small" />}
      icon={<NotificationsActiveRoundedIcon sx={{ fontSize: 20 }} />}
      title="Critical alerts"
    >
      {alerts.length === 0 ? (
        <EmptyValue>No open critical alerts are present.</EmptyValue>
      ) : (
        <Box component="ul" sx={{ listStyle: 'none', m: 0, p: 0 }}>
          {alerts.map((alert) => (
            <Box
              component="li"
              key={alert.incident_id}
              sx={{ borderTop: 1, borderColor: 'divider', py: 1.2, '&:first-of-type': { borderTop: 0 } }}
            >
              <Box sx={{ alignItems: 'center', display: 'flex', gap: 1 }}>
                <StatusChip status={alert.severity} />
                <Typography sx={{ fontSize: 11.5, fontWeight: 750 }}>
                  {titleCase(alert.category)}
                </Typography>
                <Box sx={{ flex: 1 }} />
                <StatusChip
                  label={`Delivery ${titleCase(alert.delivery_status)}`}
                  status={alert.delivery_status}
                />
              </Box>
              <Typography sx={{ fontSize: 11.5, mt: 0.9 }}>{alert.summary}</Typography>
              <Typography color="text.secondary" sx={{ fontSize: 9.5, mt: 0.5 }}>
                Opened {formatRelativeTime(alert.opened_at)}
              </Typography>
            </Box>
          ))}
        </Box>
      )}
    </SectionCard>
  )
}

function ControlAuditPanel({ control }: { control: OperationalControl }) {
  return (
    <SectionCard
      action={
        <Box sx={{ alignItems: 'center', display: 'flex', gap: 1 }}>
          <Chip label="Observation only" size="small" variant="outlined" />
          <StatusChip status={control.state} />
        </Box>
      }
      icon={<AdminPanelSettingsRoundedIcon sx={{ fontSize: 20 }} />}
      title="Audited operational control"
    >
      <Alert severity="info" sx={{ mb: 1.5 }} variant="outlined">
        This snapshot panel exposes no control action. The separate PAUSE/HALT client uses the
        authenticated operations API and cannot call a broker.
      </Alert>
      <Typography color="text.secondary" sx={{ fontSize: 11.5, mb: 1.2 }}>
        {control.detail}
      </Typography>
      {control.history.length === 0 ? (
        <EmptyValue>No authenticated control transition history is available.</EmptyValue>
      ) : (
        <TableContainer>
          <Table aria-label="Operational control audit history" size="small">
            <TableHead>
              <TableRow>
                <TableCell>Sequence</TableCell>
                <TableCell>State</TableCell>
                <TableCell>Command</TableCell>
                <TableCell>Actor</TableCell>
                <TableCell>Decided</TableCell>
                <TableCell>Receipt</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {control.history.map((receipt) => (
                <TableRow key={receipt.transition_id}>
                  <TableCell>{receipt.sequence_number}</TableCell>
                  <TableCell>
                    <StatusChip status={receipt.state} />
                  </TableCell>
                  <TableCell>{titleCase(receipt.command_kind)}</TableCell>
                  <TableCell>{receipt.actor_id}</TableCell>
                  <TableCell>{formatDateTime(receipt.decided_at)}</TableCell>
                  <TableCell>
                    <MonospaceValue>{receipt.transition_id}</MonospaceValue>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </SectionCard>
  )
}

function errorMessage(error: unknown): string {
  if (error instanceof ApiError || error instanceof Error) {
    return `Operations data is unavailable: ${error.message}`
  }
  return 'Operations data is unavailable due to an unexpected error.'
}

export function OperationsDashboardPage({
  bootstrap,
}: OperationsDashboardPageProps) {
  const query = useOperationsDashboard(bootstrap.backtest_launch?.csrf_token ?? undefined)
  const result = query.data
  const snapshot = result?.data
  const snapshotIsStale = snapshot ? isTimestampStale(snapshot.as_of, 15_000) : false
  const hasUnavailableOrStaleSource =
    snapshot?.freshness.some((item) => item.status !== 'current') ?? false
  const workingOrderCount =
    snapshot?.orders.filter((order) => !['filled', 'canceled', 'expired'].includes(order.status))
      .length ?? 0
  const criticalAlertCount =
    snapshot?.alerts.filter((alert) => alert.severity === 'critical').length ?? 0

  const refresh = () => {
    void query.refetch()
  }

  return (
    <>
      <PageHeader
        actions={
          <>
            <Chip color="primary" label="Snapshot read-only" size="small" variant="outlined" />
            {snapshot ? (
              <Box sx={{ textAlign: 'right' }}>
                <Typography color="text.secondary" sx={{ fontSize: 9.5, fontWeight: 750 }}>
                  SNAPSHOT
                </Typography>
                <Typography sx={{ fontSize: 11 }}>{formatDateTime(snapshot.as_of)}</Typography>
              </Box>
            ) : null}
            <Button
              disabled={query.isFetching}
              onClick={refresh}
              startIcon={
                query.isFetching ? <CircularProgress size={15} /> : <RefreshRoundedIcon />
              }
              variant="outlined"
            >
              Refresh
            </Button>
          </>
        }
        description="Observe authority, trading activity, account state, risk evidence, reconciliation, alerts, and audited controls in a read-only snapshot. A separate authenticated client below exposes only fail-safe PAUSE/HALT and cannot call the broker."
        eyebrow="Phase 5 operations"
        title="Operational dashboard"
      />

      {result?.source === 'development-fixture' ? (
        <Alert severity="info" sx={{ mb: 2 }} variant="outlined">
          Development fixtures are active. Values are deterministic examples, not broker or
          account data.
        </Alert>
      ) : null}

      {snapshotIsStale || hasUnavailableOrStaleSource ? (
        <Alert aria-live="assertive" severity="warning" sx={{ mb: 2 }} variant="outlined">
          One or more operational facts are stale or unavailable. Treat the whole dashboard as
          non-authoritative and do not infer trading readiness.
        </Alert>
      ) : null}

      {query.isPending ? <ResearchPageSkeleton label="Loading operational dashboard" /> : null}
      {query.isError ? (
        <ErrorState message={errorMessage(query.error)} onRetry={refresh} />
      ) : null}

      {snapshot ? (
        <Box aria-live="polite">
          <Box
            sx={{
              display: 'grid',
              gap: 2,
              gridTemplateColumns: 'repeat(4, minmax(0, 1fr))',
            }}
          >
            <MetricCard
              detail={`${snapshot.control.blocking_event_count} blocking event(s)`}
              direction={snapshot.control.state === 'running' ? 'positive' : 'negative'}
              icon={<AdminPanelSettingsRoundedIcon />}
              label="Control state"
              value={titleCase(snapshot.control.state)}
            />
            <MetricCard
              detail={`Fence generation ${snapshot.coordinator.fencing_generation ?? 'unavailable'}`}
              direction={snapshot.coordinator.status === 'active' ? 'positive' : 'negative'}
              icon={<RouterRoundedIcon />}
              label="Coordinator"
              value={snapshot.coordinator.owner_id ?? 'Unowned'}
            />
            <MetricCard
              detail={`${snapshot.orders.length} retained order(s)`}
              icon={<ShoppingCartRoundedIcon />}
              label="Working orders"
              value={String(workingOrderCount)}
            />
            <MetricCard
              detail={`${snapshot.alerts.length} open incident(s)`}
              direction={criticalAlertCount === 0 ? 'positive' : 'negative'}
              icon={<NotificationsActiveRoundedIcon />}
              label="Critical alerts"
              value={String(criticalAlertCount)}
            />
          </Box>

          <Box
            sx={{
              display: 'grid',
              gap: 2,
              gridTemplateColumns: 'minmax(0, 1.55fr) minmax(320px, 0.75fr)',
              mt: 2,
            }}
          >
            <AuthorityPanel bootstrap={bootstrap} snapshot={snapshot} />
            <DeploymentPanel snapshot={snapshot} />
          </Box>

          <Box sx={{ mt: 2 }}>
            <TradingActivityPanel
              currency={snapshot.account.currency}
              fills={snapshot.fills}
              orders={snapshot.orders}
            />
          </Box>

          <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: '1fr 1fr', mt: 2 }}>
            <AccountPanel snapshot={snapshot} />
            <RiskPanel snapshot={snapshot} />
          </Box>

          <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: '1fr 1fr', mt: 2 }}>
            <ReconciliationPanel reconciliation={snapshot.reconciliation} />
            <AlertsPanel alerts={snapshot.alerts} />
          </Box>

          <Box sx={{ mt: 2 }}>
            <ControlAuditPanel control={snapshot.control} />
          </Box>

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

      <Box sx={{ mt: 2 }}>
        <OperationalControlPanel bootstrap={bootstrap} />
      </Box>
    </>
  )
}
