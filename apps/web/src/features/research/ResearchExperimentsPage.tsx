import { Alert, Box, Button, Card, CardContent, Chip, Link, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Typography } from '@mui/material'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link as RouterLink, useSearchParams } from 'react-router-dom'

import type { UiBootstrap } from '../../api/types'
import { ErrorState } from '../../components/LoadState'
import { PageHeader } from '../../components/PageHeader'
import { ResearchPageSkeleton } from './ResearchPageComponents'
import { launchResearchExperiment, researchError, researchExportUrl, type ResearchCatalog, type ResearchExperimentRequest } from './researchApi'
import { personalResearchKey, useResearchCatalog, useResearchExperiment, useResearchExperiments } from './researchQueries'
import { useResearchPendingIntent } from './researchPendingIntent'

function ExperimentForm({ catalog, bootstrap, onCreated }: { catalog: ResearchCatalog; bootstrap: UiBootstrap; onCreated: (id: string) => void }) {
  const pending = useResearchPendingIntent('experiment', bootstrap)
  const attempt = pending.attempt
  const restored = attempt?.input
  const [discardRequested, setDiscardRequested] = useState(false)
  const [name, setName] = useState(restored?.name ?? '')
  const [hypothesis, setHypothesis] = useState(restored?.hypothesis ?? '')
  const [datasetId, setDatasetId] = useState(restored?.dataset_id ?? catalog.datasets[0]?.dataset_id ?? '')
  const [strategyId, setStrategyId] = useState(restored ? catalog.strategies.find((item) => item.default_configuration.kind === restored.candidates[0]?.configuration.kind)?.strategy_id ?? restored.candidates[0]?.configuration.kind ?? '' : catalog.strategies[0]?.strategy_id ?? '')
  const [lookback, setLookback] = useState(String(restored?.candidates[0]?.configuration.lookback ?? catalog.strategies[0]?.default_configuration.lookback ?? 200))
  const [allocation, setAllocation] = useState(restored?.candidates[0]?.configuration.allocation ?? catalog.strategies[0]?.default_configuration.allocation ?? '0.25')
  const [warmup, setWarmup] = useState(String(restored?.warmup_sessions ?? 252))
  const [priorAccess, setPriorAccess] = useState<'known_accessed' | 'unknown'>(restored?.prior_access.status ?? catalog.datasets[0]?.prior_access ?? 'unknown')
  const [description, setDescription] = useState(restored?.prior_access.description ?? '')
  const [dates, setDates] = useState({ train_start: restored?.folds[0]?.train_start ?? '', train_end: restored?.folds[0]?.train_end ?? '', validation_start: restored?.folds[0]?.validation_start ?? '', validation_end: restored?.folds[0]?.validation_end ?? '', test_start: restored?.folds[0]?.test_start ?? '', test_end: restored?.folds[0]?.test_end ?? '' })
  const queryClient = useQueryClient()
  const capability = bootstrap.backtest_launch
  const strategy = catalog.strategies.find((item) => item.strategy_id === strategyId)
  const dataset = catalog.datasets.find((item) => item.dataset_id === datasetId)
  const effectivePriorAccess = attempt ? attempt.input.prior_access.status : dataset?.prior_access === 'known_accessed' ? 'known_accessed' : priorAccess
  const allowed = catalog.experiments.enabled && bootstrap.environment.mode === 'local' && capability?.enabled && capability.csrf_token && capability.csrf_header === 'X-CSRF-Token' && capability.idempotency_header === 'Idempotency-Key'
  const mutation = useMutation({
    mutationFn: (next: NonNullable<typeof attempt>) => launchResearchExperiment(next.input, { idempotencyKey: next.key, csrfToken: capability?.csrf_token ?? '' }),
    onSuccess: (experiment, submitted) => { pending.acknowledge(submitted.key); onCreated(experiment.experiment_id); void queryClient.invalidateQueries({ queryKey: personalResearchKey }) },
  })
  const labels = { train_start: 'Training start', train_end: 'Training end', validation_start: 'Validation start', validation_end: 'Validation end', test_start: 'Test start', test_end: 'Test end' }
  return <Card component="section" sx={{ my: 2 }}><CardContent>
    <Typography component="h2" variant="h2">Declare a descriptive experiment</Typography>
    <Typography color="text.secondary" sx={{ my: 1 }}>Record the hypothesis, configuration, ordered windows and prior access before evaluation. The server schedules all four cost scenarios and retains every attempted trial. Suitability is not assessed.</Typography>
    <Box component="form" onSubmit={(event) => {
      event.preventDefault()
      if (!allowed || pending.error || mutation.isPending) return
      let input: ResearchExperimentRequest | undefined = attempt?.input
      if (!input) {
        if (!strategy || !dataset) return
        input = {
          name, hypothesis, dataset_id: datasetId, warmup_sessions: Number(warmup),
          candidates: [{ candidate_id: 'candidate-1', configuration: { ...strategy.default_configuration, lookback: Number(lookback), allocation } }],
          folds: [{ fold_id: 'fold-1', ...dates }], prior_access: { status: effectivePriorAccess, description },
        }
      }
      const next = pending.retain(input)
      if (next) mutation.mutate(next)
    }}>
      <Box component="fieldset" disabled={Boolean(attempt) || Boolean(pending.error) || mutation.isPending} sx={{ border: 0, m: 0, p: 0, display: 'grid', gap: 2, gridTemplateColumns: { xs: '1fr', md: 'repeat(3, 1fr)' } }}>
        <TextField required label="Experiment name" value={name} onChange={(event) => setName(event.target.value)} />
        <TextField required label="Hypothesis" multiline value={hypothesis} onChange={(event) => setHypothesis(event.target.value)} />
        <TextField label="Experiment dataset" select value={datasetId} onChange={(event) => {
          setDatasetId(event.target.value)
          setPriorAccess(catalog.datasets.find((item) => item.dataset_id === event.target.value)?.prior_access ?? 'unknown')
        }} slotProps={{ select: { native: true } }}>{!dataset && attempt ? <option value={datasetId}>Retained dataset: {datasetId}</option> : null}{catalog.datasets.map((item) => <option key={item.dataset_id} value={item.dataset_id}>{item.display_name}</option>)}</TextField>
        <TextField label="Candidate strategy" select value={strategyId} onChange={(event) => {
          setStrategyId(event.target.value)
          const selected = catalog.strategies.find((item) => item.strategy_id === event.target.value)
          if (selected) { setLookback(String(selected.default_configuration.lookback)); setAllocation(selected.default_configuration.allocation) }
        }} slotProps={{ select: { native: true } }}>{!strategy && attempt ? <option value={strategyId}>Retained strategy: {strategyId}</option> : null}{catalog.strategies.map((item) => <option key={item.strategy_id} value={item.strategy_id}>{item.display_name}</option>)}</TextField>
        <TextField required label="Candidate lookback sessions" type="number" value={lookback} onChange={(event) => setLookback(event.target.value)} slotProps={{ htmlInput: { min: strategy?.minimum_lookback, max: strategy?.maximum_lookback, step: 1 } }} />
        <TextField required label="Candidate allocation" value={allocation} onChange={(event) => setAllocation(event.target.value)} />
        <TextField required label="Experiment warmup sessions" type="number" value={warmup} onChange={(event) => setWarmup(event.target.value)} slotProps={{ htmlInput: { min: 0, step: 1 } }} />
        {(Object.keys(labels) as (keyof typeof dates)[]).map((key) => <TextField required key={key} label={labels[key]} type="date" value={dates[key]} onChange={(event) => { const value = event.target.value; setDates((current) => ({ ...current, [key]: value })) }} slotProps={{ inputLabel: { shrink: true } }} />)}
        <TextField label="Prior access status" select value={effectivePriorAccess} onChange={(event) => { if (event.target.value === 'known_accessed' || event.target.value === 'unknown') setPriorAccess(event.target.value) }} helperText={dataset?.prior_access === 'known_accessed' ? 'This catalog records prior access. Its status cannot be downgraded to unknown.' : 'Record known access if you have viewed this data or its results.'} slotProps={{ select: { native: true } }}><option disabled={dataset?.prior_access === 'known_accessed'} value="unknown">Unknown</option><option value="known_accessed">Previously accessed</option></TextField>
        <TextField required label="Prior access description" multiline value={description} onChange={(event) => setDescription(event.target.value)} helperText="Describe previously seen data/results or what remains unknown." />
      </Box>
      {dataset ? <Typography sx={{ my: 1 }}>{dataset.data_class}; {dataset.start_session}–{dataset.end_session}; {dataset.session_count} sessions. {dataset.limitations.join(' · ')}</Typography> : null}
      <Alert severity="info" sx={{ my: 1 }}>Calendar dates do not prove untouched evidence. This declaration does not qualify a strategy or permit automatic selection.</Alert>
      {!allowed ? <Alert severity="info">{catalog.experiments.reasons.join(' · ') || 'Local experiment creation is unavailable.'}</Alert> : null}
      {pending.recovered && attempt ? <Alert severity="info">An unresolved declaration was restored from this tab. Retry sends the same declaration; nothing was submitted automatically.</Alert> : null}
      {pending.error ? <Alert severity="error">{pending.error}</Alert> : null}
      {mutation.isError ? <Alert severity="error">{researchError(mutation.error)} The same declaration and request identity are retained for retry.</Alert> : null}
      <Stack direction="row" spacing={1} sx={{ mt: 2 }}>
        <Button type="submit" variant="contained" disabled={!allowed || Boolean(pending.error) || (!attempt && (!strategy || !dataset)) || mutation.isPending}>{mutation.isPending ? 'Submitting declaration…' : attempt ? 'Retry same experiment' : 'Declare and run experiment'}</Button>
        {(attempt || pending.error) && !mutation.isPending ? <Button onClick={() => setDiscardRequested(true)}>Start a different declaration</Button> : null}
      </Stack>
      {discardRequested ? <Alert severity="warning" sx={{ my: 1 }}>The earlier declaration may already have created an experiment. Check the experiment list before discarding; this does not cancel its trials.
        <Stack direction="row" spacing={1}><Button onClick={() => { if (pending.discard()) { setDiscardRequested(false); mutation.reset() } }}>Discard retained declaration</Button><Button onClick={() => setDiscardRequested(false)}>Keep retained declaration</Button></Stack>
      </Alert> : null}
      {attempt ? <Typography variant="caption">Request {attempt.key}. A different declaration may create another experiment if this response was lost.</Typography> : null}
    </Box>
  </CardContent></Card>
}

function ExperimentDetail({ experimentId }: { experimentId: string }) {
  const query = useResearchExperiment(experimentId)
  if (query.isPending) return <ResearchPageSkeleton label="Loading experiment evidence" />
  if (query.isError) return <ErrorState message={researchError(query.error)} onRetry={() => { void query.refetch() }} />
  const experiment = query.data
  if (!experiment) return null
  const exportUrl = researchExportUrl(experiment.export_url)
  return <Card component="section" sx={{ mt: 2 }}><CardContent>
    <Typography component="h2" variant="h2">{experiment.request.name}</Typography>
    <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" sx={{ my: 1 }}><Chip label={experiment.status} /><Chip label={experiment.evaluation_mode} /><Chip label={`Suitability: ${experiment.suitability}`} /></Stack>
    <Typography>{experiment.request.hypothesis}</Typography>
    <Typography sx={{ mt: 1 }}>Prior access: {experiment.request.prior_access.status} — {experiment.request.prior_access.description}</Typography>
    <Typography>Declaration recorded {experiment.requested_at}; {experiment.request.warmup_sessions} requested warmup sessions.</Typography>
    {experiment.request.folds.map((fold) => <Box key={fold.fold_id} sx={{ my: 2 }}><Typography fontWeight="bold">{fold.fold_id}</Typography><Typography>Training {fold.train_start}–{fold.train_end}</Typography><Typography>Validation {fold.validation_start}–{fold.validation_end}</Typography><Typography>Test {fold.test_start}–{fold.test_end}</Typography></Box>)}
    <Typography component="h3" variant="h2">Four assumed cost scenarios</Typography>
    {experiment.cost_scenarios.map((cost) => <Typography key={cost.scenario_id}>{cost.display_name}: {cost.slippage_bps} bps/side + ${cost.fee_per_share}/share. {cost.assumptions.join(' · ')}</Typography>)}
    <Typography component="h3" variant="h2" sx={{ mt: 2 }}>Trial registry</Typography>
    <Typography>{experiment.planned_trial_count} planned trials; {experiment.trials.length} trial records available. Every cost scenario and window remains separately labeled.</Typography>
    {!experiment.trials.length ? <Alert severity="info">Trial results are pending. No cost or performance result is available yet.</Alert> : null}
    <TableContainer><Table size="small" aria-label="Experiment trial registry"><TableHead><TableRow><TableCell>Trial</TableCell><TableCell>Window / cost</TableCell><TableCell>State</TableCell><TableCell>Reported results</TableCell></TableRow></TableHead><TableBody>
      {experiment.trials.map((trial) => <TableRow key={trial.trial_id}>
        <TableCell>{trial.trial_id}<br />{trial.candidate_id} · {trial.fold_id}{trial.job_id ? <Box><Link component={RouterLink} to={`/research/backtests?job=${encodeURIComponent(trial.job_id)}`}>Inspect worker run</Link></Box> : null}</TableCell>
        <TableCell>{trial.window} · {trial.cost_scenario_id}</TableCell><TableCell>{trial.status}<br />{trial.reasons.join(' · ')}</TableCell>
        <TableCell>{trial.metrics.length ? trial.metrics.map((metric) => <Typography variant="body2" key={metric.name}>{metric.name}: {metric.value ?? 'Undefined'} {metric.value === null ? '' : metric.unit}. {metric.coverage.valid_sessions}/{metric.coverage.expected_sessions} valid sessions. {[...metric.reasons, ...metric.assumptions].join(' · ')}</Typography>) : 'Results unavailable or pending'}
          {trial.benchmark_metrics.map((metric) => <Typography variant="body2" key={`benchmark-${metric.name}`}>Benchmark {metric.name}: {metric.value ?? 'Undefined'} {metric.value === null ? '' : metric.unit}. {metric.coverage.valid_sessions}/{metric.coverage.expected_sessions} valid sessions. {[...metric.reasons, ...metric.assumptions].join(' · ')}</Typography>)}
        </TableCell>
      </TableRow>)}
    </TableBody></Table></TableContainer>
    {[...experiment.reasons, ...experiment.limitations].map((reason, index) => <Typography key={`${index}-${reason}`} color="text.secondary">{reason}</Typography>)}
    <Box component="details" sx={{ mt: 2 }}><summary>Protocol and source provenance</summary><Typography sx={{ overflowWrap: 'anywhere' }}>Protocol {experiment.protocol_sha256}</Typography>{experiment.provenance.map((item) => <Typography key={item.name} sx={{ overflowWrap: 'anywhere' }}>{item.name}: {item.value}</Typography>)}</Box>
    {exportUrl ? <Link href={exportUrl} download>Download immutable experiment artifact</Link> : <Typography color="text.secondary">Experiment export is unavailable.</Typography>}
  </CardContent></Card>
}

export function ResearchExperimentsPage({ bootstrap }: { bootstrap: UiBootstrap }) {
  const catalog = useResearchCatalog()
  const list = useResearchExperiments()
  const [params, setParams] = useSearchParams()
  const selectedId = params.get('experiment')
  function select(id: string) { setParams((current) => { const next = new URLSearchParams(current); next.set('experiment', id); return next }) }
  return <>
    <PageHeader eyebrow="Research" title="Descriptive experiments" description="Inspect chronological windows, attempted configurations, prior access, and benchmark/cost sensitivity without automatic candidate qualification." />
    <Link component={RouterLink} to="/research/history/experiments">Historical governance diagnostics</Link>
    {catalog.isPending ? <ResearchPageSkeleton label="Loading experiment catalog" /> : null}
    {catalog.isError ? <ErrorState message={researchError(catalog.error)} onRetry={() => { void catalog.refetch() }} /> : null}
    {catalog.data && !catalog.isError ? <ExperimentForm catalog={catalog.data} bootstrap={bootstrap} onCreated={select} /> : null}
    {list.isPending ? <Typography role="status">Loading experiment registry…</Typography> : null}
    {list.isError ? <ErrorState message={researchError(list.error)} onRetry={() => { void list.refetch() }} /> : null}
    {list.data && !list.data.experiments.length ? <Alert severity="info">No experiments have been declared.</Alert> : null}
    {list.data?.experiments.map((experiment) => <Button key={experiment.experiment_id} onClick={() => select(experiment.experiment_id)}>{experiment.request.name} · {experiment.status}</Button>)}
    {list.data?.truncated ? <Typography>The experiment registry preview is bounded. Earlier records remain available through their deep links.</Typography> : null}
    {selectedId ? <ExperimentDetail key={selectedId} experimentId={selectedId} /> : null}
  </>
}
