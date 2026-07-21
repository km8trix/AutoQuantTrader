import ArrowForwardRoundedIcon from '@mui/icons-material/ArrowForwardRounded'
import CodeRoundedIcon from '@mui/icons-material/CodeRounded'
import SettingsSuggestOutlinedIcon from '@mui/icons-material/SettingsSuggestOutlined'
import ShieldOutlinedIcon from '@mui/icons-material/ShieldOutlined'
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Divider,
  Typography,
} from '@mui/material'
import { Link as RouterLink } from 'react-router-dom'

import { ApiError } from '../../api/client'
import { formatDateTime } from '../../api/format'
import { useResearchStrategies } from '../../api/queries'
import type { ResearchStrategy } from '../../api/types'
import { ErrorState } from '../../components/LoadState'
import { MetricCard } from '../../components/MetricCard'
import { PageHeader } from '../../components/PageHeader'
import { EmptyDataState, RefreshButton } from '../data/DataPageComponents'
import {
  DigestValue,
  ImmutableChip,
  LabeledValue,
  ResearchPageSkeleton,
} from './ResearchPageComponents'

function strategiesErrorMessage(error: unknown): string {
  if (error instanceof ApiError || error instanceof Error) {
    return `The immutable strategy catalog is unavailable: ${error.message}`
  }
  return 'The immutable strategy catalog is unavailable due to an unexpected error.'
}

function ConfigurationCard({
  configuration,
  strategy,
}: {
  configuration: ResearchStrategy['configurations'][number]
  strategy: ResearchStrategy
}) {
  const search = new URLSearchParams({
    strategy_version: strategy.strategy_version_id,
    configuration: configuration.configuration_sha256,
  })

  return (
    <Card component="article" variant="outlined">
      <CardContent sx={{ p: 1.75, '&:last-child': { pb: 1.75 } }}>
        <Box sx={{ alignItems: 'flex-start', display: 'flex', gap: 1.5, justifyContent: 'space-between' }}>
          <Box sx={{ minWidth: 0 }}>
            <Typography component="h3" sx={{ fontSize: 13, fontWeight: 750 }}>
              {configuration.configuration_name}
            </Typography>
            <Typography color="text.secondary" sx={{ fontSize: 11, mt: 0.3 }}>
              Validated parameters are content-addressed and cannot be edited in place.
            </Typography>
          </Box>
          <ImmutableChip />
        </Box>
        <Box sx={{ mt: 1.4 }}>
          <LabeledValue label="Configuration SHA-256">
            <DigestValue label="Configuration SHA-256">
              {configuration.configuration_sha256}
            </DigestValue>
          </LabeledValue>
        </Box>
        <Box
          component="dl"
          sx={{
            bgcolor: 'rgba(147, 165, 186, 0.05)',
            borderRadius: 1,
            display: 'grid',
            gap: 1,
            gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, minmax(0, 1fr))' },
            m: 0,
            mt: 1.4,
            p: 1.25,
          }}
        >
          {Object.entries(configuration.parameters).map(([name, value]) => (
            <Box key={name} sx={{ minWidth: 0 }}>
              <Typography component="dt" color="text.secondary" sx={{ fontSize: 10 }}>
                {name}
              </Typography>
              <Typography component="dd" sx={{ fontSize: 12, fontWeight: 700, m: 0, mt: 0.2 }}>
                {String(value)}
              </Typography>
            </Box>
          ))}
        </Box>
        <Button
          component={RouterLink}
          endIcon={<ArrowForwardRoundedIcon />}
          fullWidth
          sx={{ mt: 1.5 }}
          to={`/research/backtests?${search.toString()}`}
          variant="outlined"
        >
          Use in fixture backtest
        </Button>
      </CardContent>
    </Card>
  )
}

function StrategyCard({ strategy }: { strategy: ResearchStrategy }) {
  return (
    <Card component="section">
      <CardContent sx={{ p: 0, '&:last-child': { pb: 0 } }}>
        <Box sx={{ px: 2.25, py: 2 }}>
          <Box sx={{ alignItems: 'flex-start', display: 'flex', gap: 2, justifyContent: 'space-between' }}>
            <Box>
              <Typography component="h2" variant="h2">
                {strategy.display_name}
              </Typography>
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.75, mt: 0.8 }}>
                <Chip label={strategy.strategy_id} size="small" variant="outlined" />
                <Chip color="primary" label={`Version ${strategy.strategy_version}`} size="small" />
              </Box>
            </Box>
            <ImmutableChip label="Pinned version" />
          </Box>
          <Box
            sx={{
              display: 'grid',
              gap: 1.5,
              gridTemplateColumns: { xs: '1fr', md: 'repeat(3, minmax(0, 1fr))' },
              mt: 1.75,
            }}
          >
            <LabeledValue label="Version identity">
              <DigestValue label="Strategy version identity">{strategy.strategy_version_id}</DigestValue>
            </LabeledValue>
            <LabeledValue label="Parameter schema">
              <Typography sx={{ fontSize: 11.5 }}>
                {Object.keys(strategy.parameter_schema).length.toLocaleString()} top-level fields
              </Typography>
            </LabeledValue>
            <LabeledValue label="Validated configurations">
              <Typography sx={{ fontSize: 11.5 }}>
                {strategy.configurations.length.toLocaleString()} immutable set
                {strategy.configurations.length === 1 ? '' : 's'}
              </Typography>
            </LabeledValue>
          </Box>
        </Box>
        <Divider />
        <Box sx={{ p: 2.25 }}>
          <Typography color="text.secondary" variant="subtitle2">
            Validated configurations
          </Typography>
          <Box
            sx={{
              display: 'grid',
              gap: 1.5,
              gridTemplateColumns: { xs: '1fr', xl: 'repeat(2, minmax(0, 1fr))' },
              mt: 1.25,
            }}
          >
            {strategy.configurations.map((configuration) => (
              <ConfigurationCard
                configuration={configuration}
                key={configuration.configuration_sha256}
                strategy={strategy}
              />
            ))}
          </Box>
        </Box>
      </CardContent>
    </Card>
  )
}

export function StrategiesPage() {
  const strategiesQuery = useResearchStrategies()
  const result = strategiesQuery.data
  const catalog = result?.data
  const refresh = () => {
    void strategiesQuery.refetch()
  }
  const configurationCount =
    catalog?.strategies.reduce((total, strategy) => total + strategy.configurations.length, 0) ?? 0

  return (
    <>
      <PageHeader
        actions={<RefreshButton isFetching={strategiesQuery.isFetching} onRefresh={refresh} />}
        description="Inspect exact code versions, parameter schemas, and validated configurations before selecting immutable inputs for a reproducible run."
        eyebrow="Phase 2 · Research"
        title="Strategies"
      />
      <Alert icon={<ShieldOutlinedIcon />} severity="info" sx={{ mb: 2 }} variant="outlined">
        <strong>Research-only catalog.</strong> Strategy versions and configurations are immutable;
        launching is limited to repository-owned synthetic fixtures.
      </Alert>
      {result?.source === 'development-fixture' ? (
        <Alert severity="warning" sx={{ mb: 2 }} variant="outlined">
          The Control API is unavailable and explicit development fixtures are active.
        </Alert>
      ) : null}
      {strategiesQuery.isPending ? (
        <ResearchPageSkeleton label="Loading immutable strategy catalog" />
      ) : null}
      {strategiesQuery.isError ? (
        <ErrorState message={strategiesErrorMessage(strategiesQuery.error)} onRetry={refresh} />
      ) : null}
      {catalog ? (
        <Box aria-live="polite">
          <Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 1.25 }}>
            <Typography color="text.secondary" sx={{ fontSize: 10.5 }}>
              Catalog snapshot {formatDateTime(catalog.as_of)}
            </Typography>
          </Box>
          <Box
            sx={{
              display: 'grid',
              gap: 2,
              gridTemplateColumns: { xs: '1fr', md: 'repeat(3, minmax(0, 1fr))' },
            }}
          >
            <MetricCard
              detail="Content-addressed implementations"
              icon={<CodeRoundedIcon />}
              label="Strategy versions"
              value={catalog.strategies.length.toLocaleString()}
            />
            <MetricCard
              detail="Validated, immutable parameter sets"
              icon={<SettingsSuggestOutlinedIcon />}
              label="Configurations"
              value={configurationCount.toLocaleString()}
            />
            <MetricCard
              detail="No paper or live execution"
              direction="positive"
              icon={<ShieldOutlinedIcon />}
              label="Launch boundary"
              value="Fixture only"
            />
          </Box>
          <Box sx={{ display: 'grid', gap: 2, mt: 2 }}>
            {catalog.strategies.length === 0 ? (
              <Card>
                <EmptyDataState
                  detail="Register an immutable strategy version and validated configuration before launching a fixture backtest."
                  title="No strategies registered"
                />
              </Card>
            ) : (
              catalog.strategies.map((strategy) => (
                <StrategyCard key={strategy.strategy_version_id} strategy={strategy} />
              ))
            )}
          </Box>
        </Box>
      ) : null}
    </>
  )
}
