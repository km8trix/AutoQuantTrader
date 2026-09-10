import { Alert, Box, Card, CardContent, Chip, Typography } from '@mui/material'

import { ErrorState } from '../../components/LoadState'
import { ResearchMetricTable } from './ResearchRunReport'
import { researchError } from './researchApi'
import { useResearchComparison } from './researchQueries'

export function ResearchComparisonPanel({ jobIds }: { jobIds: string[] }) {
  const query = useResearchComparison(jobIds)
  return <Box component="section" sx={{ mt: 3 }}>
    <Typography component="h2" variant="h2">Compare retained runs</Typography>
    {jobIds.length < 2 ? <Alert severity="info" sx={{ my: 1 }}>Select 2–8 runs with retained reports to compare.</Alert> : null}
    {jobIds.length >= 2 && query.isPending ? <Typography role="status">Loading the authoritative comparison…</Typography> : null}
    {query.isError ? <ErrorState message={researchError(query.error)} onRetry={() => { void query.refetch() }} /> : null}
    {query.data ? <>
      <Alert severity={query.data.comparable ? 'info' : 'warning'} sx={{ my: 2 }}>{query.data.comparable ? 'The server marks these results comparable.' : 'These results are not directly comparable.'} {query.data.reasons.join(' · ')}</Alert>
      {query.data.differences.map((item) => <Typography key={item.name}>{item.name}: {item.value}</Typography>)}
      <Typography variant="caption" sx={{ overflowWrap: 'anywhere' }}>Comparison {query.data.comparison_sha256}</Typography>
      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', lg: 'repeat(2, minmax(0, 1fr))' }, gap: 2, mt: 2 }}>
        {query.data.runs.map((run) => <Card key={run.job_id}><CardContent>
          <Typography component="h3" variant="h2">{run.strategy_id} · {run.cost_scenario_id}</Typography>
          <Chip label={run.data_class} sx={{ my: 1 }} />
          <Typography>Dataset {run.dataset_id}; {run.interval.scored_start ?? 'Unavailable'}–{run.interval.scored_end ?? 'Unavailable'}; {run.interval.reset_mode}.</Typography>
          <Typography>Lookback {run.configuration.lookback}; allocation {run.configuration.allocation}; rebalance {run.configuration.rebalance_sessions ?? 'default'}.</Typography>
          <Typography variant="caption" sx={{ overflowWrap: 'anywhere' }}>Job {run.job_id}; report {run.report_sha256}</Typography>
          <ResearchMetricTable metrics={run.metrics} label={`Metrics for ${run.job_id}`} />
          <Box component="details"><summary>Benchmark metrics</summary><ResearchMetricTable metrics={run.benchmark_metrics} label={`Benchmark for ${run.job_id}`} /></Box>
          {[...run.assumptions, ...run.limitations].map((reason, index) => <Typography color="text.secondary" key={`${index}-${reason}`}>{reason}</Typography>)}
        </CardContent></Card>)}
      </Box>
    </> : null}
  </Box>
}
