import { Alert, Box, Button, Card, CardContent, Chip, Stack, TextField, Typography } from '@mui/material'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'

import type { UiBootstrap } from '../../api/types'
import { launchResearchRun, researchError, type ResearchCatalog, type ResearchRun, type ResearchRunRequest } from './researchApi'
import { personalResearchKey } from './researchQueries'
import { useResearchPendingIntent } from './researchPendingIntent'

export function ResearchRunForm({ catalog, bootstrap, onLaunched }: {
  catalog: ResearchCatalog
  bootstrap: UiBootstrap
  onLaunched: (run: ResearchRun) => void
}) {
  const pending = useResearchPendingIntent('run', bootstrap)
  const attempt = pending.attempt
  const [discardRequested, setDiscardRequested] = useState(false)
  const [params] = useSearchParams()
  const initialStrategy = catalog.strategies.find((item) => item.strategy_id === (attempt?.input.strategy_id ?? params.get('strategy'))) ?? catalog.strategies[0]
  const [datasetId, setDatasetId] = useState(attempt?.input.dataset_id ?? params.get('dataset') ?? catalog.datasets[0]?.dataset_id ?? '')
  const [strategyId, setStrategyId] = useState(attempt?.input.strategy_id ?? initialStrategy?.strategy_id ?? '')
  const [lookback, setLookback] = useState(String(attempt?.input.configuration.lookback ?? initialStrategy?.default_configuration.lookback ?? 200))
  const [allocation, setAllocation] = useState(attempt?.input.configuration.allocation ?? initialStrategy?.default_configuration.allocation ?? '0.25')
  const [rebalance, setRebalance] = useState(attempt ? attempt.input.configuration.rebalance_sessions?.toString() ?? '' : initialStrategy?.default_configuration.rebalance_sessions?.toString() ?? '')
  const [warmup, setWarmup] = useState(String(attempt?.input.warmup_sessions ?? initialStrategy?.default_warmup_sessions ?? 252))
  const [cash, setCash] = useState(attempt?.input.initial_cash ?? '10000')
  const [start, setStart] = useState(attempt?.input.scored_start ?? '')
  const [end, setEnd] = useState(attempt?.input.scored_end ?? '')
  const [costId, setCostId] = useState(attempt?.input.cost_scenario_id ?? catalog.cost_scenarios[0]?.scenario_id ?? '')
  const queryClient = useQueryClient()
  const dataset = catalog.datasets.find((item) => item.dataset_id === datasetId)
  const strategy = catalog.strategies.find((item) => item.strategy_id === strategyId)
  const cost = catalog.cost_scenarios.find((item) => item.scenario_id === costId)
  const capability = bootstrap.backtest_launch
  const canLaunch = bootstrap.environment.mode === 'local' && catalog.launch.enabled && capability?.enabled && capability.csrf_token && capability.csrf_header === 'X-CSRF-Token' && capability.idempotency_header === 'Idempotency-Key'
  const mutation = useMutation({
    mutationFn: (next: NonNullable<typeof attempt>) => launchResearchRun(next.input, { csrfToken: capability?.csrf_token ?? '', idempotencyKey: next.key }),
    onSuccess: (run, submitted) => {
      pending.acknowledge(submitted.key)
      void queryClient.invalidateQueries({ queryKey: personalResearchKey })
      onLaunched(run)
    },
  })

  function submit(event: React.FormEvent) {
    event.preventDefault()
    if (!canLaunch || pending.error || mutation.isPending) return
    let input: ResearchRunRequest | undefined = attempt?.input
    if (!input) {
      if (!dataset || !strategy || !cost) return
      input = {
        dataset_id: dataset.dataset_id, dataset_manifest_sha256: dataset.manifest_sha256,
        strategy_id: strategy.strategy_id, strategy_version: strategy.version,
        configuration: { kind: strategy.default_configuration.kind, lookback: Number(lookback), allocation, rebalance_sessions: rebalance ? Number(rebalance) : null },
        initial_cash: cash, warmup_sessions: Number(warmup), scored_start: start || null, scored_end: end || null, cost_scenario_id: cost.scenario_id,
      }
    }
    const next = pending.retain(input)
    if (next) mutation.mutate(next)
  }

  if (!attempt && !pending.error && (!catalog.datasets.length || !catalog.strategies.length || !catalog.cost_scenarios.length)) {
    return <Alert severity="info">No runnable catalog is registered. Register an imported dataset and supported configuration to begin.</Alert>
  }

  return <Card component="section"><CardContent>
    <Typography component="h2" variant="h2">Create a research run</Typography>
    <Typography color="text.secondary" sx={{ my: 1 }}>Select registered history and a reference strategy. The worker validates and freezes the inputs before execution.</Typography>
    <Box component="form" onSubmit={submit}>
      <Box component="fieldset" disabled={Boolean(attempt) || Boolean(pending.error) || mutation.isPending} sx={{ border: 0, p: 0, m: 0, display: 'grid', gridTemplateColumns: { xs: '1fr', md: 'repeat(3, 1fr)' }, gap: 2 }}>
        <TextField label="Dataset" select value={datasetId} onChange={(event) => setDatasetId(event.target.value)} slotProps={{ select: { native: true } }}>
          {!dataset && attempt ? <option value={datasetId}>Retained dataset: {datasetId}</option> : null}
          {catalog.datasets.map((item) => <option key={item.dataset_id} value={item.dataset_id}>{item.display_name}</option>)}
        </TextField>
        <TextField label="Strategy" select value={strategyId} onChange={(event) => {
          const selected = catalog.strategies.find((item) => item.strategy_id === event.target.value)
          setStrategyId(event.target.value)
          if (selected) {
            setLookback(String(selected.default_configuration.lookback)); setAllocation(selected.default_configuration.allocation)
            setRebalance(selected.default_configuration.rebalance_sessions?.toString() ?? ''); setWarmup(String(selected.default_warmup_sessions))
          }
        }} slotProps={{ select: { native: true } }}>
          {!strategy && attempt ? <option value={strategyId}>Retained strategy: {strategyId}</option> : null}
          {catalog.strategies.map((item) => <option key={item.strategy_id} value={item.strategy_id}>{item.display_name} · {item.version}</option>)}
        </TextField>
        <TextField label="Cost scenario" select value={costId} onChange={(event) => setCostId(event.target.value)} slotProps={{ select: { native: true } }}>
          {!cost && attempt ? <option value={costId}>Retained costs: {costId}</option> : null}
          {catalog.cost_scenarios.map((item) => <option key={item.scenario_id} value={item.scenario_id}>{item.display_name}</option>)}
        </TextField>
        <TextField required label="Initial cash (USD)" value={cash} onChange={(event) => setCash(event.target.value)} />
        <TextField required label="Allocation per instrument" value={allocation} onChange={(event) => setAllocation(event.target.value)} />
        <TextField required label="Lookback sessions" type="number" value={lookback} onChange={(event) => setLookback(event.target.value)} slotProps={{ htmlInput: { min: strategy?.minimum_lookback, max: strategy?.maximum_lookback, step: 1 } }} />
        <TextField label="Rebalance every N sessions" type="number" value={rebalance} onChange={(event) => setRebalance(event.target.value)} helperText="Blank uses the strategy default." slotProps={{ htmlInput: { min: 1, step: 1 } }} />
        <TextField required label="Warmup sessions" type="number" value={warmup} onChange={(event) => setWarmup(event.target.value)} slotProps={{ htmlInput: { min: 0, step: 1 } }} />
        <TextField label="Scored start" type="date" value={start} onChange={(event) => setStart(event.target.value)} slotProps={{ inputLabel: { shrink: true } }} helperText="Blank uses the server-admitted interval." />
        <TextField label="Scored end" type="date" value={end} onChange={(event) => setEnd(event.target.value)} slotProps={{ inputLabel: { shrink: true } }} />
      </Box>
      {dataset ? <Box sx={{ my: 2 }}>
        <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap"><Chip label={dataset.data_class} /><Chip label={`Prior access: ${dataset.prior_access}`} /></Stack>
        <Typography sx={{ mt: 1 }}>{dataset.start_session}–{dataset.end_session} · {dataset.session_count} registered sessions · {dataset.symbols.join(', ')}</Typography>
        <Typography color="text.secondary">Availability: {dataset.availability_policy}</Typography>
        {dataset.limitations.map((reason) => <Typography key={reason} color="text.secondary">{reason}</Typography>)}
      </Box> : <Alert severity="warning">The selected dataset is no longer registered.</Alert>}
      {cost ? <Typography sx={{ my: 1 }}>Assumed costs: {cost.slippage_bps} bps per side and ${cost.fee_per_share}/share. {cost.assumptions.join(' · ')}</Typography> : null}
      {!canLaunch ? <Alert severity="info" sx={{ my: 1 }}>{catalog.launch.reasons.join(' · ') || capability?.disabled_reason || 'Local research launch is unavailable.'}</Alert> : null}
      {pending.recovered && attempt ? <Alert severity="info" sx={{ my: 1 }}>An unresolved request was restored from this tab. Retry sends the same request; nothing was submitted automatically.</Alert> : null}
      {pending.error ? <Alert severity="error" sx={{ my: 1 }}>{pending.error}</Alert> : null}
      {mutation.isError ? <Alert severity="error" sx={{ my: 1 }}>{researchError(mutation.error)} The retained request can be retried with the same identity.</Alert> : null}
      {mutation.isSuccess ? <Alert severity="success" sx={{ my: 1 }}>Run {mutation.data.job_id} was accepted as {mutation.data.status}.</Alert> : null}
      <Stack direction="row" spacing={1}>
        <Button type="submit" variant="contained" disabled={!canLaunch || Boolean(pending.error) || (!attempt && (!dataset || !strategy || !cost)) || mutation.isPending}>{mutation.isPending ? 'Submitting…' : attempt ? 'Retry same launch' : 'Launch research run'}</Button>
        {(attempt || pending.error) && !mutation.isPending ? <Button onClick={() => setDiscardRequested(true)}>Start a different request</Button> : null}
      </Stack>
      {discardRequested ? <Alert severity="warning" sx={{ my: 1 }}>The earlier request may already have created a run. Check the run list before discarding; this does not cancel that run.
        <Stack direction="row" spacing={1}><Button onClick={() => { if (pending.discard()) { setDiscardRequested(false); mutation.reset() } }}>Discard retained request</Button><Button onClick={() => setDiscardRequested(false)}>Keep retained request</Button></Stack>
      </Alert> : null}
      {attempt ? <Typography variant="caption">Request {attempt.key}. A different request may create another run if the earlier response was lost.</Typography> : null}
    </Box>
  </CardContent></Card>
}
