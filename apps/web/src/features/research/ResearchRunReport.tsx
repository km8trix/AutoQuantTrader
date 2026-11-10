import { Alert, Box, Button, Card, CardContent, Chip, Link, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography } from '@mui/material'
import { useState } from 'react'

import { titleCase } from '../../api/format'
import { ErrorState } from '../../components/LoadState'
import { ResearchEquityChart } from './ResearchEquityChart'
import { ResearchPageSkeleton } from './ResearchPageComponents'
import { researchError, researchExportUrl, type ResearchMetric, type ResearchRowKind, type ResearchRows } from './researchApi'
import { useResearchReport, useResearchRows } from './researchQueries'

function metricLabel(name: string) {
  return name === 'total_return' ? 'Time-weighted return' : titleCase(name)
}

export function ResearchMetricTable({ metrics, label = 'Reported metrics' }: { metrics: ResearchMetric[]; label?: string }) {
  return <TableContainer><Table size="small" aria-label={label}>
    <TableHead><TableRow><TableCell>Metric</TableCell><TableCell>Value</TableCell><TableCell>Coverage and assumptions</TableCell></TableRow></TableHead>
    <TableBody>{metrics.map((metric) => <TableRow key={metric.name}>
      <TableCell component="th" scope="row">{metricLabel(metric.name)}</TableCell>
      <TableCell sx={{ overflowWrap: 'anywhere' }}>
        {metric.value === null ? 'Undefined' : metric.value} {metric.value === null ? '' : metric.unit}
        {metric.status === 'approximate' ? <Chip size="small" label="Approximate" /> : null}
      </TableCell>
      <TableCell>
        <Typography variant="body2">{metric.coverage.valid_sessions}/{metric.coverage.expected_sessions} valid sessions; {metric.coverage.valid_returns} valid returns; {metric.coverage.sample_count} samples.</Typography>
        <Typography variant="body2">{[...metric.reasons, ...metric.assumptions].join(' · ')}</Typography>
        <Box component="details"><summary>Metric lineage</summary>
          <Typography variant="body2" sx={{ overflowWrap: 'anywhere' }}>Input: {metric.coverage.input_sha256}; convention: {metric.conventions_sha256}; interval: {metric.coverage.interval_id}.</Typography>
          <Typography variant="body2">Observed sessions: {metric.coverage.observed_sessions}. Rows: {metric.coverage.contributing_row_ids.join(', ') || 'None'}.</Typography>
          {metric.coverage.excluded.map((item) => <Typography key={item.row_id} variant="body2">Excluded {item.row_id}: {item.reasons.join(' · ')}</Typography>)}
          {metric.coverage.lineage_truncated ? <Typography variant="body2">This lineage preview is bounded. The full immutable artifact retains all source rows.</Typography> : null}
        </Box>
      </TableCell>
    </TableRow>)}</TableBody>
  </Table></TableContainer>
}

function FinancialRows({ page }: { page: ResearchRows }) {
  return <TableContainer><Table size="small" aria-label={`${titleCase(page.kind)} rows`}>
    <TableHead><TableRow><TableCell>Identity</TableCell><TableCell>Amounts and state</TableCell><TableCell>Lineage / availability</TableCell></TableRow></TableHead>
    <TableBody>{page.rows.map((row, index) => {
      if (row.kind === 'executions') return <TableRow key={`${row.execution_id}-${row.revision}`}>
        <TableCell>{row.symbol} {row.side}<br />{row.execution_id} revision {row.revision}</TableCell>
        <TableCell>{row.quantity} shares @ {row.price}; fee {row.fee}</TableCell>
        <TableCell>{row.occurred_at}<br />Order {row.order_id}; intent {row.intent_id}; {row.source_row_ids.join(', ')}</TableCell>
      </TableRow>
      if (row.kind === 'fifo') return <TableRow key={row.closing_order_id}>
        <TableCell>{row.symbol}<br />Closing order {row.closing_order_id}</TableCell>
        <TableCell>{row.completed ? 'Completed group' : 'Incomplete group'}; quantity {row.quantity}<br />Gross P&amp;L {row.gross_pnl}; buy fees {row.buy_fees}; sell fees {row.sell_fees}; net P&amp;L {row.net_pnl}</TableCell>
        <TableCell>Matches: {row.match_ids.join(', ')}<br />Executions: {row.execution_ids.join(', ')}<br />Splits: {row.split_ids.join(', ') || 'None'}</TableCell>
      </TableRow>
      if (row.kind === 'journal') return <TableRow key={row.entry_id}>
        <TableCell>{row.entry_id}<br />Sequence {row.sequence}; {row.event_type}</TableCell>
        <TableCell>{row.description}<br />{row.amounts.map((item) => `${item.name}: ${item.value}`).join('; ')}</TableCell>
        <TableCell>{row.occurred_at}<br />{row.source_row_ids.join(', ')}</TableCell>
      </TableRow>
      if (row.kind === 'positions') return <TableRow key={row.symbol}>
        <TableCell>{row.symbol} · open holding</TableCell>
        <TableCell>Quantity {row.quantity}; cost basis {row.cost_basis}; market value {row.market_value ?? 'Unavailable'}; unrealized P&amp;L {row.unrealized_pnl ?? 'Unavailable'}</TableCell>
        <TableCell>Mark {row.mark ?? 'Unavailable'} at {row.mark_at ?? 'Unavailable'}<br />{row.reasons.join(' · ')}</TableCell>
      </TableRow>
      return <TableRow key={index}><TableCell colSpan={3}>Unexpected row type</TableCell></TableRow>
    })}</TableBody>
  </Table></TableContainer>
}

function ReportRows({ jobId, reportSha }: { jobId: string; reportSha: string }) {
  const [kind, setKind] = useState<ResearchRowKind>('equity')
  const [offset, setOffset] = useState(0)
  const [view, setView] = useState<'nav' | 'wealth'>('wealth')
  const query = useResearchRows(jobId, reportSha, kind, offset)
  const page = query.data
  const kinds: ResearchRowKind[] = ['equity', 'executions', 'fifo', 'journal', 'positions']
  return <Card component="section" sx={{ mt: 2 }}><CardContent>
    <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" sx={{ mb: 2 }} aria-label="Report evidence sections">
      {kinds.map((item) => <Button key={item} variant={kind === item ? 'contained' : 'outlined'} onClick={() => { setKind(item); setOffset(0) }}>{item === 'fifo' ? 'FIFO trades' : titleCase(item)}</Button>)}
    </Stack>
    {query.isPending ? <Typography role="status">Loading immutable report rows…</Typography> : null}
    {query.isError ? <ErrorState message={researchError(query.error)} onRetry={() => { void query.refetch() }} /> : null}
    {page ? <>
      <Typography sx={{ my: 1 }}>Showing {page.rows.length ? page.offset + 1 : 0}–{page.offset + page.rows.length} of {page.total} {kind} rows. Report {page.report_sha256}.</Typography>
      {!page.rows.length ? <Alert severity="info">No {kind} rows are retained in this report.</Alert> : kind === 'equity' ? <>
        <Stack direction="row" spacing={1} sx={{ my: 1 }}><Button onClick={() => setView('wealth')} aria-pressed={view === 'wealth'}>Wealth</Button><Button onClick={() => setView('nav')} aria-pressed={view === 'nav'}>NAV</Button></Stack>
        <ResearchEquityChart points={page.rows.filter((row) => row.kind === 'equity')} view={view} />
      </> : <FinancialRows page={page} />}
      <Stack direction="row" spacing={1} sx={{ mt: 2 }}>
        <Button disabled={offset === 0 || query.isFetching} onClick={() => setOffset(Math.max(0, offset - page.limit))}>Previous rows</Button>
        <Button disabled={offset + page.rows.length >= page.total || query.isFetching} onClick={() => setOffset(offset + page.limit)}>Next rows</Button>
      </Stack>
    </> : null}
  </CardContent></Card>
}

export function ResearchRunReport({ jobId, reportSha }: { jobId: string; reportSha: string }) {
  const query = useResearchReport(jobId, reportSha)
  if (query.isPending) return <ResearchPageSkeleton label="Loading actual worker report" />
  if (query.isError) return <ErrorState message={researchError(query.error)} onRetry={() => { void query.refetch() }} />
  const report = query.data
  if (!report) return null
  const exportUrl = researchExportUrl(report.export_url)
  return <Box sx={{ mt: 3 }}>
    <Typography component="h2" variant="h2">Worker report</Typography>
    <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" sx={{ my: 1 }}><Chip label={report.status} /><Chip label={report.data_class} /><Chip label={report.currency} /></Stack>
    {report.status === 'incomplete' ? <Alert severity="warning" sx={{ my: 1 }}>Incomplete result. Retained account facts remain inspectable; affected performance values are unavailable.</Alert> : null}
    <Typography>{report.interval.scored_start ?? 'Unavailable'}–{report.interval.scored_end ?? 'Unavailable'}; {report.interval.expected_sessions} expected scored sessions. Warmup {report.interval.warmup_start ?? 'None'}–{report.interval.warmup_end ?? 'None'}; {report.interval.reset_mode}.</Typography>
    {[...report.reasons, ...report.limitations].map((reason, index) => <Typography color="text.secondary" key={`${index}-${reason}`}>{reason}</Typography>)}
    <ResearchMetricTable metrics={report.metrics} />
    <Box component="details" sx={{ mt: 2 }}><summary>{report.benchmark_name} and cash benchmark metrics</summary>
      <Typography>{report.benchmark_name}</Typography><ResearchMetricTable metrics={report.benchmark_metrics} label="Analytical benchmark metrics" />
      <Typography>Cash comparator</Typography><ResearchMetricTable metrics={report.cash_metrics} label="Cash comparator metrics" />
    </Box>
    <ReportRows key={`${jobId}-${reportSha}`} jobId={jobId} reportSha={reportSha} />
    <Card component="section" sx={{ mt: 2 }}><CardContent>
      <Typography component="h3" variant="h2">Assumptions and provenance</Typography>
      {report.assumptions.map((item) => <Typography key={item}>{item}</Typography>)}
      <Box component="dl" sx={{ overflowWrap: 'anywhere' }}>
        {[{ name: 'Run ID', value: report.run_id }, { name: 'Result SHA-256', value: report.result_sha256 }, { name: 'Report SHA-256', value: report.report_sha256 }, { name: 'Artifact SHA-256', value: report.artifact_sha256 }, { name: 'Artifact attempt', value: report.attempt_id }, { name: 'Generated at', value: report.generated_at }, ...report.conventions, ...report.provenance].map((item, index) => <Box key={`${item.name}-${index}`} sx={{ my: 1 }}><Typography component="dt" fontWeight="bold">{item.name}</Typography><Typography component="dd" sx={{ m: 0 }}>{item.value}</Typography></Box>)}
      </Box>
      {exportUrl ? <Link href={exportUrl} download>Download immutable report artifact</Link> : <Typography color="text.secondary">Artifact export is unavailable.</Typography>}
    </CardContent></Card>
  </Box>
}
