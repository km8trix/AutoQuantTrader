import AccountBalanceOutlinedIcon from '@mui/icons-material/AccountBalanceOutlined'
import ExpandMoreRoundedIcon from '@mui/icons-material/ExpandMoreRounded'
import PaidOutlinedIcon from '@mui/icons-material/PaidOutlined'
import PercentRoundedIcon from '@mui/icons-material/PercentRounded'
import ReceiptLongOutlinedIcon from '@mui/icons-material/ReceiptLongOutlined'
import TimelineRoundedIcon from '@mui/icons-material/TimelineRounded'
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Box,
  Card,
  CardContent,
  Link,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material'

import { ApiError } from '../../api/client'
import { formatCurrency, formatDateTime, titleCase } from '../../api/format'
import { useBacktestReport } from '../../api/queries'
import type { BacktestReportResponse } from '../../api/types'
import { ErrorState } from '../../components/LoadState'
import { MetricCard } from '../../components/MetricCard'
import { EmptyDataState } from '../data/DataPageComponents'
import { DigestValue, LabeledValue } from './ResearchPageComponents'
import { EquityCurveChart } from './EquityCurveChart'

function reportErrorMessage(error: unknown): string {
  if (error instanceof ApiError || error instanceof Error) {
    return `The completed backtest report is unavailable: ${error.message}`
  }
  return 'The completed backtest report is unavailable due to an unexpected error.'
}

function formatPercent(value: string | null): string {
  if (value === null) return 'Unavailable'
  const numeric = Number(value)
  return Number.isFinite(numeric)
    ? new Intl.NumberFormat('en-US', { style: 'percent', maximumFractionDigits: 2 }).format(numeric)
    : 'Unavailable'
}

function ReportMetrics({ report }: { report: BacktestReportResponse }) {
  return (
    <Box
      sx={{
        display: 'grid',
        gap: 2,
        gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, minmax(0, 1fr))', xl: 'repeat(4, minmax(0, 1fr))' },
      }}
    >
      <MetricCard
        detail={`Started at ${formatCurrency(report.metrics.starting_equity, report.currency)}`}
        direction="positive"
        icon={<AccountBalanceOutlinedIcon />}
        label="Ending equity"
        value={formatCurrency(report.metrics.ending_equity, report.currency)}
      />
      <MetricCard
        detail="Simple, cash-flow-adjusted return"
        direction={Number(report.metrics.total_return) >= 0 ? 'positive' : 'negative'}
        icon={<PercentRoundedIcon />}
        label="Total return"
        value={formatPercent(report.metrics.total_return)}
      />
      <MetricCard
        detail="Peak-to-trough on retained curve"
        direction="negative"
        icon={<TimelineRoundedIcon />}
        label="Maximum drawdown"
        value={formatPercent(report.metrics.maximum_drawdown)}
      />
      <MetricCard
        detail={`${report.metrics.trade_count.toLocaleString()} closed trade${report.metrics.trade_count === 1 ? '' : 's'}`}
        icon={<PaidOutlinedIcon />}
        label="Execution costs"
        value={formatCurrency(report.metrics.total_execution_costs, report.currency)}
      />
    </Box>
  )
}

function TradeTrace({ report }: { report: BacktestReportResponse }) {
  if (report.trades.length === 0) {
    return <EmptyDataState detail="This completed run did not close a trade." title="No closed trades" />
  }
  return (
    <TableContainer>
      <Table aria-label="Backtest trade trace" size="small">
        <TableHead>
          <TableRow>
            <TableCell>Trade</TableCell>
            <TableCell>Opened / closed</TableCell>
            <TableCell align="right">Quantity</TableCell>
            <TableCell align="right">Cost basis</TableCell>
            <TableCell align="right">Proceeds</TableCell>
            <TableCell align="right">Execution costs</TableCell>
            <TableCell align="right">Net P&amp;L</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {report.trades.map((trade) => (
            <TableRow key={trade.trade_id}>
              <TableCell>
                <Typography sx={{ fontSize: 12, fontWeight: 750 }}>{trade.symbol}</Typography>
                <Typography color="text.secondary" sx={{ fontSize: 10 }}>{trade.trade_id}</Typography>
              </TableCell>
              <TableCell>
                <Typography sx={{ fontSize: 11 }}>{formatDateTime(trade.opened_at)}</Typography>
                <Typography color="text.secondary" sx={{ fontSize: 10 }}>to {formatDateTime(trade.closed_at)}</Typography>
              </TableCell>
              <TableCell align="right">{trade.quantity}</TableCell>
              <TableCell align="right">{formatCurrency(trade.cost_basis, report.currency)}</TableCell>
              <TableCell align="right">{formatCurrency(trade.proceeds, report.currency)}</TableCell>
              <TableCell align="right">{formatCurrency(trade.execution_costs, report.currency)}</TableCell>
              <TableCell align="right">
                <Typography color={Number(trade.net_pnl) >= 0 ? 'success.main' : 'error.main'} sx={{ fontSize: 12, fontWeight: 750 }}>
                  {formatCurrency(trade.net_pnl, report.currency)}
                </Typography>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  )
}

function EvidenceSections({ report }: { report: BacktestReportResponse }) {
  const provenanceRows: Array<[string, string]> = [
    ['report_sha256', report.report_sha256],
    ['report_artifact_sha256', report.report_artifact_sha256],
    ['execution_ledger_sha256', report.provenance.execution_ledger_sha256],
    ['corporate_action_ledger_sha256', report.provenance.corporate_action_ledger_sha256],
    ['settlement_ledger_sha256', report.provenance.settlement_ledger_sha256],
    ['account_projection_sha256', report.provenance.account_projection_sha256],
    ['accounting_evidence_sha256', report.provenance.accounting_evidence_sha256],
  ]
  return (
    <Box sx={{ mt: 2 }}>
      <Accordion id="backtest-ledger">
        <AccordionSummary expandIcon={<ExpandMoreRoundedIcon />}>
          <Typography component="h3" sx={{ fontSize: 13, fontWeight: 750 }}>
            Ledger trace ({report.ledger_trace.length})
          </Typography>
        </AccordionSummary>
        <AccordionDetails sx={{ pt: 0 }}>
          {report.ledger_trace.length === 0 ? (
            <Typography color="text.secondary" sx={{ fontSize: 12 }}>No ledger trace rows were retained.</Typography>
          ) : (
            <TableContainer>
              <Table aria-label="Backtest ledger trace" size="small">
                <TableHead><TableRow><TableCell>Entry</TableCell><TableCell>Kind</TableCell><TableCell>Effective</TableCell><TableCell>Recorded</TableCell><TableCell>Digest</TableCell></TableRow></TableHead>
                <TableBody>
                  {report.ledger_trace.map((entry) => (
                    <TableRow key={entry.entry_id}>
                      <TableCell>{entry.entry_id}</TableCell>
                      <TableCell>{titleCase(entry.entry_kind)}</TableCell>
                      <TableCell>{formatDateTime(entry.effective_at)}</TableCell>
                      <TableCell>{formatDateTime(entry.recorded_at)}</TableCell>
                      <TableCell><DigestValue label="Ledger entry SHA-256">{entry.entry_sha256}</DigestValue></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </AccordionDetails>
      </Accordion>
      <Accordion id="backtest-positions">
        <AccordionSummary expandIcon={<ExpandMoreRoundedIcon />}>
          <Typography component="h3" sx={{ fontSize: 13, fontWeight: 750 }}>
            Position trace ({report.positions.length})
          </Typography>
        </AccordionSummary>
        <AccordionDetails sx={{ pt: 0 }}>
          {report.positions.length === 0 ? (
            <Typography color="text.secondary" sx={{ fontSize: 12 }}>No position projections were retained.</Typography>
          ) : (
            <TableContainer>
              <Table aria-label="Backtest position trace" size="small">
                <TableHead><TableRow><TableCell>As of</TableCell><TableCell>Instrument</TableCell><TableCell align="right">Quantity</TableCell><TableCell align="right">Market value</TableCell><TableCell align="right">Realized P&amp;L</TableCell><TableCell align="right">Unrealized P&amp;L</TableCell></TableRow></TableHead>
                <TableBody>
                  {report.positions.map((position) => (
                    <TableRow key={`${position.sequence}-${position.instrument_id}`}>
                      <TableCell>{formatDateTime(position.as_of)}</TableCell>
                      <TableCell>{position.symbol}<Typography color="text.secondary" sx={{ fontSize: 10 }}>{position.instrument_id}</Typography></TableCell>
                      <TableCell align="right">{position.quantity}</TableCell>
                      <TableCell align="right">{formatCurrency(position.market_value, report.currency)}</TableCell>
                      <TableCell align="right">{formatCurrency(position.realized_pnl, report.currency)}</TableCell>
                      <TableCell align="right">{formatCurrency(position.unrealized_pnl, report.currency)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </AccordionDetails>
      </Accordion>
      <Accordion id="backtest-provenance">
        <AccordionSummary expandIcon={<ExpandMoreRoundedIcon />}>
          <Typography component="h3" sx={{ fontSize: 13, fontWeight: 750 }}>Run provenance</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Box sx={{ display: 'grid', gap: 1.5, gridTemplateColumns: { xs: '1fr', md: 'repeat(2, minmax(0, 1fr))' } }}>
            {provenanceRows.map(([name, value]) => (
              <LabeledValue key={name} label={titleCase(name)}>
                <DigestValue label={titleCase(name)}>{value}</DigestValue>
              </LabeledValue>
            ))}
          </Box>
        </AccordionDetails>
      </Accordion>
    </Box>
  )
}

export function BacktestReportPanel({ jobId }: { jobId: string | null }) {
  const reportQuery = useBacktestReport(jobId, Boolean(jobId))
  const report = reportQuery.data?.data
  const retry = () => { void reportQuery.refetch() }

  if (!jobId) {
    return (
      <Card component="section" sx={{ mt: 2 }}>
        <EmptyDataState detail="Select a completed job to load its immutable report artifact." title="No report selected" />
      </Card>
    )
  }
  if (reportQuery.isPending) {
    return <Skeleton aria-label="Loading completed backtest report" height={480} sx={{ mt: 2 }} variant="rounded" />
  }
  if (reportQuery.isError) {
    return <Box sx={{ mt: 2 }}><ErrorState message={reportErrorMessage(reportQuery.error)} onRetry={retry} /></Box>
  }
  if (!report) return null

  return (
    <Box aria-live="polite" sx={{ mt: 2 }}>
      <Box sx={{ alignItems: 'flex-end', display: 'flex', flexWrap: 'wrap', gap: 2, justifyContent: 'space-between', mb: 1.5 }}>
        <Box>
          <Typography color="primary.main" variant="subtitle2">Completed artifact</Typography>
          <Typography component="h2" sx={{ fontSize: 19, fontWeight: 750, mt: 0.35 }}>Performance report</Typography>
          <Typography color="text.secondary" sx={{ fontSize: 11.5, mt: 0.3 }}>
            {formatDateTime(report.period_start)} to {formatDateTime(report.period_end)} · generated {formatDateTime(report.generated_at)}
          </Typography>
        </Box>
        <Box component="nav" aria-label="Report evidence sections" sx={{ display: 'flex', gap: 1.5 }}>
          <Link href="#backtest-ledger">Ledger</Link>
          <Link href="#backtest-positions">Positions</Link>
          <Link href="#backtest-provenance">Provenance</Link>
        </Box>
      </Box>
      {reportQuery.data?.source === 'development-fixture' ? <Alert severity="warning" sx={{ mb: 2 }} variant="outlined">The Control API is unavailable and an explicit development report fixture is active.</Alert> : null}
      <ReportMetrics report={report} />
      <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: { xs: '1fr', xl: '1.35fr 1fr' }, mt: 2 }}>
        <Card component="section">
          <CardContent>
            <Typography component="h3" variant="h2">Equity and performance</Typography>
            <Typography color="text.secondary" sx={{ fontSize: 11.5, mt: 0.4 }}>Causally ordered account equity retained in the report.</Typography>
            <Box sx={{ mt: 1.5 }}><EquityCurveChart currency={report.currency} points={report.equity_curve} /></Box>
          </CardContent>
        </Card>
        <Card component="section">
          <CardContent>
            <Typography component="h3" variant="h2">Measurement contract</Typography>
            <Box sx={{ display: 'grid', gap: 1.5, gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', mt: 1.5 }}>
              <LabeledValue label="Return type"><Typography sx={{ fontSize: 12 }}>{titleCase(report.conventions.return_type)}</Typography></LabeledValue>
              <LabeledValue label="Frequency"><Typography sx={{ fontSize: 12 }}>{titleCase(report.conventions.return_frequency)}</Typography></LabeledValue>
              <LabeledValue label="Convention"><Typography sx={{ fontSize: 12 }}>{report.conventions.convention_id} · {report.conventions.convention_version}</Typography></LabeledValue>
              <LabeledValue label="Turnover"><Typography sx={{ fontSize: 12 }}>{formatPercent(report.metrics.turnover)}</Typography></LabeledValue>
              <LabeledValue label="Realized P&amp;L"><Typography sx={{ fontSize: 12 }}>{formatCurrency(report.metrics.realized_pnl, report.currency)}</Typography></LabeledValue>
              <LabeledValue label="Dividend income"><Typography sx={{ fontSize: 12 }}>{formatCurrency(report.metrics.dividend_income, report.currency)}</Typography></LabeledValue>
            </Box>
          </CardContent>
        </Card>
      </Box>
      <Card component="section" sx={{ mt: 2 }}>
        <CardContent sx={{ p: 0, '&:last-child': { pb: 0 } }}>
          <Box sx={{ borderBottom: 1, borderColor: 'divider', px: 2.25, py: 1.8 }}>
            <Box sx={{ alignItems: 'center', display: 'flex', gap: 1 }}><ReceiptLongOutlinedIcon color="primary" /><Typography component="h3" variant="h2">Trade trace</Typography></Box>
            <Typography color="text.secondary" sx={{ fontSize: 11.5, mt: 0.4 }}>Closed trades retain execution links and explicit cost attribution.</Typography>
          </Box>
          <TradeTrace report={report} />
        </CardContent>
      </Card>
      <EvidenceSections report={report} />
    </Box>
  )
}
