import { Alert, Box, Button, Card, CardContent, Link, Typography } from '@mui/material'
import { Link as RouterLink } from 'react-router-dom'

import { ErrorState } from '../../components/LoadState'
import { PageHeader } from '../../components/PageHeader'
import { ResearchPageSkeleton } from './ResearchPageComponents'
import { researchError } from './researchApi'
import { useResearchCatalog } from './researchQueries'

export function ResearchStrategiesPage() {
  const query = useResearchCatalog()
  return <>
    <PageHeader eyebrow="Research" title="Reference strategies" description="Transparent strategies run through the same causal engine and accounting model on registered datasets." />
    <Link component={RouterLink} to="/research/history/strategies">Historical strategy diagnostics</Link>
    {query.isPending ? <ResearchPageSkeleton label="Loading research strategies" /> : null}
    {query.isError ? <ErrorState message={researchError(query.error)} onRetry={() => { void query.refetch() }} /> : null}
    {query.data && !query.data.strategies.length ? <Alert severity="info">No research strategies are registered.</Alert> : null}
    <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: '1fr 1fr' }, gap: 2, mt: 2 }}>
      {query.data?.strategies.map((strategy) => <Card key={strategy.strategy_id} component="section"><CardContent>
        <Typography component="h2" variant="h2">{strategy.display_name}</Typography>
        <Typography color="text.secondary">Version {strategy.version}</Typography>
        <Typography sx={{ my: 2 }}>{strategy.description}</Typography>
        <Typography>Default lookback: {strategy.default_configuration.lookback} sessions</Typography>
        <Typography>Allocation per instrument: {strategy.default_configuration.allocation}</Typography>
        <Typography>Warmup: {strategy.default_warmup_sessions} sessions</Typography>
        {strategy.limitations.map((reason) => <Typography color="text.secondary" key={reason}>{reason}</Typography>)}
        <Button component={RouterLink} to={`/research/backtests?strategy=${encodeURIComponent(strategy.strategy_id)}`} sx={{ mt: 2 }}>Configure a research run</Button>
      </CardContent></Card>)}
    </Box>
  </>
}
