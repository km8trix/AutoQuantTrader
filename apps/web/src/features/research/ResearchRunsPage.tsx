import { Alert, Box, Button, Card, CardContent, Checkbox, Chip, Link, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography } from '@mui/material'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link as RouterLink, useSearchParams } from 'react-router-dom'

import type { UiBootstrap } from '../../api/types'
import { ErrorState } from '../../components/LoadState'
import { PageHeader } from '../../components/PageHeader'
import { ResearchComparisonPanel } from './ResearchComparisonPanel'
import { ResearchPageSkeleton } from './ResearchPageComponents'
import { ResearchRunForm } from './ResearchRunForm'
import { ResearchRunReport } from './ResearchRunReport'
import { cancelResearchRun, researchError, type ResearchCatalog } from './researchApi'
import { personalResearchKey, runIsActive, useResearchCatalog, useResearchRun, useResearchRuns } from './researchQueries'

function SelectedRun({ jobId, catalog, bootstrap }: { jobId: string; catalog: ResearchCatalog; bootstrap: UiBootstrap }) {
  const query = useResearchRun(jobId)
  const queryClient = useQueryClient()
  const [cancelKey, setCancelKey] = useState<string | null>(null)
  const capability = bootstrap.backtest_launch
  const mutation = useMutation({
    mutationFn: (key: string) => cancelResearchRun(jobId, { idempotencyKey: key, csrfToken: capability?.csrf_token ?? '' }),
    onSuccess: (run) => {
      queryClient.setQueryData([...personalResearchKey, 'run', jobId], run)
      void queryClient.invalidateQueries({ queryKey: [...personalResearchKey, 'runs'] })
    },
  })
  const run = query.data
  if (query.isPending) return <Typography role="status">Loading selected run…</Typography>
  const canCancel = run && runIsActive(run) && !run.cancel_requested && catalog.cancel.enabled && bootstrap.environment.mode === 'local' && capability?.enabled && capability.csrf_token && !query.isError
  return <Box sx={{ mt: 3 }}>
    {query.isError ? <ErrorState message={`Selected run unavailable or stale: ${researchError(query.error)}`} onRetry={() => { void query.refetch() }} /> : null}
    {run ? <>
      <Card component="section"><CardContent>
        <Typography component="h2" variant="h2">Selected run</Typography>
        <Typography sx={{ overflowWrap: 'anywhere' }}>{run.job_id}</Typography>
        <Stack direction="row" spacing={1} sx={{ my: 1 }}><Chip label={run.status} /><Chip label={run.data_class} />{run.cancel_requested ? <Chip label="Cancellation requested" /> : null}</Stack>
        <Typography>Updated {run.updated_at}</Typography>
        {run.progress_completed !== null && run.progress_total !== null ? <Typography>Measured progress: {run.progress_completed}/{run.progress_total} {run.progress_unit ?? 'units'}</Typography> : <Typography color="text.secondary">Measured progress is unavailable.</Typography>}
        {run.reasons.map((reason) => <Typography key={reason}>{reason}</Typography>)}
        {run.cancel_requested && runIsActive(run) ? <Alert severity="info" sx={{ my: 1 }}>Cancellation is pending. The worker has not yet published a terminal state.</Alert> : null}
        {runIsActive(run) ? <Button disabled={!canCancel || mutation.isPending} onClick={() => {
          const key = cancelKey ?? `research-cancel-${crypto.randomUUID()}`
          setCancelKey(key); mutation.mutate(key)
        }}>{mutation.isPending ? 'Requesting cancellation…' : mutation.isError ? 'Retry cancellation' : 'Cancel run'}</Button> : null}
        {!catalog.cancel.enabled && runIsActive(run) ? <Typography>{catalog.cancel.reasons.join(' · ')}</Typography> : null}
        {mutation.isError ? <Alert severity="error">{researchError(mutation.error)}</Alert> : null}
        <Box component="details" sx={{ mt: 1 }}><summary>Attempt and recovery history</summary>
          {run.attempts.length ? run.attempts.map((attempt) => <Typography key={attempt.attempt_id}>Attempt {attempt.attempt_number}: {attempt.status}; {attempt.started_at}–{attempt.ended_at ?? 'active'}. {attempt.reasons.join(' · ')}</Typography>) : <Typography>No worker attempt has been recorded.</Typography>}
          <Typography sx={{ overflowWrap: 'anywhere' }}>Run {run.run_id}; spec {run.spec_sha256}; result {run.result_sha256 ?? 'Not published'}.</Typography>
        </Box>
      </CardContent></Card>
      {run.report_sha256 ? <ResearchRunReport key={run.report_sha256} jobId={jobId} reportSha={run.report_sha256} /> : <Alert severity="info" sx={{ mt: 2 }}>{runIsActive(run) ? 'The worker report is pending.' : 'No performance report was published for this attempt.'}</Alert>}
    </> : null}
  </Box>
}

export function ResearchRunsPage({ bootstrap }: { bootstrap: UiBootstrap }) {
  const catalog = useResearchCatalog()
  const runs = useResearchRuns()
  const [params, setParams] = useSearchParams()
  const selectedId = params.get('job')
  const comparisonIds = [...new Set(params.getAll('compare'))].slice(0, 8)
  function selectJob(jobId: string) {
    setParams((current) => { const next = new URLSearchParams(current); next.set('job', jobId); return next })
  }
  function toggleComparison(jobId: string) {
    const selected = comparisonIds.includes(jobId) ? comparisonIds.filter((id) => id !== jobId) : [...comparisonIds, jobId]
    setParams((current) => { const next = new URLSearchParams(current); next.delete('compare'); selected.forEach((id) => next.append('compare', id)); return next })
  }
  return <>
    <PageHeader eyebrow="Research" title="Research runs" description="Select registered history, run a reproducible simulation, and inspect actual worker reports and comparisons." />
    <Link component={RouterLink} to="/research/history/backtests">Historical golden diagnostics</Link>
    {catalog.isPending ? <ResearchPageSkeleton label="Loading research catalog" /> : null}
    {catalog.isError ? <ErrorState message={`Research catalog unavailable: ${researchError(catalog.error)}`} onRetry={() => { void catalog.refetch() }} /> : null}
    {catalog.data && !catalog.isError ? <Box sx={{ mt: 2 }}><ResearchRunForm catalog={catalog.data} bootstrap={bootstrap} onLaunched={(run) => selectJob(run.job_id)} /></Box> : null}
    <Typography component="h2" variant="h2" sx={{ mt: 3 }}>Retained runs</Typography>
    {runs.isPending ? <Typography role="status">Loading retained runs…</Typography> : null}
    {runs.isError ? <ErrorState message={`Run list unavailable or stale: ${researchError(runs.error)}`} onRetry={() => { void runs.refetch() }} /> : null}
    {runs.data && !runs.data.jobs.length ? <Alert severity="info">No research runs have been registered.</Alert> : null}
    {runs.data?.jobs.length ? <TableContainer><Table size="small" aria-label="Retained research runs"><TableHead><TableRow><TableCell>Compare</TableCell><TableCell>Run</TableCell><TableCell>Inputs</TableCell><TableCell>State</TableCell></TableRow></TableHead><TableBody>
      {runs.data.jobs.map((run) => <TableRow key={run.job_id} selected={run.job_id === selectedId}>
        <TableCell><Checkbox checked={comparisonIds.includes(run.job_id)} disabled={!run.report_sha256 || (!comparisonIds.includes(run.job_id) && comparisonIds.length >= 8)} onChange={() => toggleComparison(run.job_id)} slotProps={{ input: { 'aria-label': `Compare ${run.job_id}` } }} /></TableCell>
        <TableCell><Button onClick={() => selectJob(run.job_id)}>{run.job_id}</Button></TableCell>
        <TableCell>{run.dataset_id} · {run.strategy_id} · {run.cost_scenario_id}<br />{run.data_class}</TableCell>
        <TableCell>{run.status}{run.cancel_requested ? ' · cancellation requested' : ''}</TableCell>
      </TableRow>)}
    </TableBody></Table></TableContainer> : null}
    {runs.data?.truncated ? <Typography color="text.secondary">The retained-run list is bounded; use a run deep link for older results.</Typography> : null}
    {selectedId && catalog.data ? <SelectedRun key={selectedId} jobId={selectedId} catalog={catalog.data} bootstrap={bootstrap} /> : null}
    <ResearchComparisonPanel jobIds={comparisonIds} />
  </>
}
