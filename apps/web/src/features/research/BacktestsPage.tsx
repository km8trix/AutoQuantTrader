import HistoryRoundedIcon from '@mui/icons-material/HistoryRounded'
import LockClockOutlinedIcon from '@mui/icons-material/LockClockOutlined'
import PlayArrowRoundedIcon from '@mui/icons-material/PlayArrowRounded'
import RefreshRoundedIcon from '@mui/icons-material/RefreshRounded'
import ScienceOutlinedIcon from '@mui/icons-material/ScienceOutlined'
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
  FormControl,
  InputLabel,
  LinearProgress,
  MenuItem,
  Select,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material'
import { useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'

import { ApiError } from '../../api/client'
import { formatDateTime, titleCase } from '../../api/format'
import { useBacktests, useLaunchBacktest, useResearchStrategies } from '../../api/queries'
import type {
  BacktestJob,
  BacktestLaunchRequest,
  ResearchFixture,
  UiBootstrap,
} from '../../api/types'
import { ErrorState } from '../../components/LoadState'
import { PageHeader } from '../../components/PageHeader'
import { StatusChip } from '../../components/StatusChip'
import { EmptyDataState } from '../data/DataPageComponents'
import { BacktestReportPanel } from './BacktestReportPanel'
import {
  DigestValue,
  ImmutableChip,
  LabeledValue,
  ResearchPageSkeleton,
} from './ResearchPageComponents'

interface BacktestsPageProps {
  bootstrap: UiBootstrap
}

interface LaunchAttempt {
  idempotencyKey: string
  input: BacktestLaunchRequest
}

function errorMessage(prefix: string, error: unknown): string {
  if (error instanceof ApiError || error instanceof Error) return `${prefix}: ${error.message}`
  return `${prefix} due to an unexpected error.`
}

function idempotencyKey(): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`
  return `backtest-${suffix}`
}

function fixtureSelectionKey(fixture: ResearchFixture): string {
  return JSON.stringify([fixture.fixture_id, fixture.fixture_version])
}

function LaunchPanel({ bootstrap }: BacktestsPageProps) {
  const [searchParams] = useSearchParams()
  const strategiesQuery = useResearchStrategies()
  const launchMutation = useLaunchBacktest()
  const catalog = strategiesQuery.data?.data
  const [strategyId, setStrategyId] = useState(
    searchParams.get('strategy_version') ?? searchParams.get('strategy') ?? '',
  )
  const [configurationSha, setConfigurationSha] = useState(
    searchParams.get('configuration') ?? '',
  )
  const [selectedFixtureKey, setSelectedFixtureKey] = useState('')
  const [lastIdempotencyKey, setLastIdempotencyKey] = useState<string | null>(null)
  const [launchAttempt, setLaunchAttempt] = useState<LaunchAttempt | null>(null)

  const strategies = catalog?.strategies ?? []
  const strategy =
    strategies.find(
      (candidate) =>
        candidate.strategy_version_id === strategyId || candidate.strategy_id === strategyId,
    ) ?? strategies[0]
  const configuration =
    strategy?.configurations.find(
      (candidate) => candidate.configuration_sha256 === configurationSha,
    ) ?? strategy?.configurations[0]
  const fixtures = configuration?.launch_inputs ?? []
  const fixture =
    fixtures.find((candidate) => fixtureSelectionKey(candidate) === selectedFixtureKey) ??
    fixtures[0]
  const launchConfig = bootstrap.backtest_launch
  const headersAreSupported =
    launchConfig !== null &&
    launchConfig.csrf_header.toLowerCase() === 'x-csrf-token' &&
    launchConfig.idempotency_header.toLowerCase() === 'idempotency-key'
  const mayLaunch =
    bootstrap.environment.mode === 'local' &&
    launchConfig?.enabled === true &&
    headersAreSupported &&
    Boolean(launchConfig.operator_id && launchConfig.csrf_token && strategy && configuration && fixture)

  const submit = () => {
    if (
      !mayLaunch ||
      !strategy ||
      !configuration ||
      !fixture ||
      !launchConfig?.operator_id ||
      !launchConfig.csrf_token
    ) return
    const attempt = launchAttempt ?? {
      idempotencyKey: idempotencyKey(),
      input: {
        fixture_id: fixture.fixture_id,
        fixture_version: fixture.fixture_version,
        dataset_manifest_id: fixture.dataset_manifest_id,
        dataset_manifest_sha256: fixture.dataset_manifest_sha256,
        replay_run_id: fixture.replay_run_id,
        strategy_id: strategy.strategy_id,
        strategy_version: strategy.strategy_version,
        strategy_configuration_sha256: configuration.configuration_sha256,
        benchmark_sha256: fixture.benchmark_sha256,
        cost_model_sha256: fixture.cost_model_sha256,
        fill_model_sha256: fixture.fill_model_sha256,
        metric_conventions_sha256: fixture.metric_conventions_sha256,
      },
    }
    setLaunchAttempt(attempt)
    setLastIdempotencyKey(attempt.idempotencyKey)
    launchMutation.mutate({
      credentials: {
        csrfToken: launchConfig.csrf_token,
        idempotencyKey: attempt.idempotencyKey,
      },
      input: attempt.input,
    }, {
      onSuccess: () => setLaunchAttempt(null),
    })
  }

  const resetAmbiguousLaunch = () => {
    launchMutation.reset()
    setLaunchAttempt(null)
  }

  const selectStrategy = (value: string) => {
    const next = strategies.find((candidate) => candidate.strategy_version_id === value)
    setStrategyId(value)
    setConfigurationSha(next?.configurations[0]?.configuration_sha256 ?? '')
  }

  return (
    <Card component="section">
      <CardContent>
        <Box sx={{ alignItems: 'flex-start', display: 'flex', gap: 2, justifyContent: 'space-between' }}>
          <Box>
            <Typography component="h2" variant="h2">Launch fixture backtest</Typography>
            <Typography color="text.secondary" sx={{ fontSize: 11.5, mt: 0.4 }}>
              Choose only registered, immutable inputs. The server revalidates every pin.
            </Typography>
          </Box>
          <ImmutableChip label="Fixture only" />
        </Box>
        {strategiesQuery.isPending ? <LinearProgress aria-label="Loading launch catalog" sx={{ mt: 2 }} /> : null}
        {strategiesQuery.isError ? (
          <Alert severity="error" sx={{ mt: 2 }} variant="outlined">
            {errorMessage('The launch catalog is unavailable', strategiesQuery.error)}
          </Alert>
        ) : null}
        {catalog && (strategies.length === 0 || fixtures.length === 0) ? (
          <Alert severity="warning" sx={{ mt: 2 }} variant="outlined">
            Launch is disabled until both a validated strategy configuration and a fixture input set are registered.
          </Alert>
        ) : null}
        <Box sx={{ display: 'grid', gap: 1.5, gridTemplateColumns: { xs: '1fr', md: 'repeat(3, minmax(0, 1fr))' }, mt: 2 }}>
          <FormControl disabled={strategies.length === 0 || launchAttempt !== null} fullWidth size="small">
            <InputLabel id="backtest-strategy-label">Strategy version</InputLabel>
            <Select
              label="Strategy version"
              labelId="backtest-strategy-label"
              onChange={(event) => selectStrategy(event.target.value)}
              value={strategy?.strategy_version_id ?? ''}
            >
              {strategies.map((candidate) => (
                <MenuItem key={candidate.strategy_version_id} value={candidate.strategy_version_id}>
                  {candidate.display_name} · {candidate.strategy_version}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl disabled={!strategy || strategy.configurations.length === 0 || launchAttempt !== null} fullWidth size="small">
            <InputLabel id="backtest-configuration-label">Validated configuration</InputLabel>
            <Select
              label="Validated configuration"
              labelId="backtest-configuration-label"
              onChange={(event) => setConfigurationSha(event.target.value)}
              value={configuration?.configuration_sha256 ?? ''}
            >
              {strategy?.configurations.map((candidate) => (
                <MenuItem key={candidate.configuration_sha256} value={candidate.configuration_sha256}>
                  {candidate.configuration_name}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl disabled={fixtures.length === 0 || launchAttempt !== null} fullWidth size="small">
            <InputLabel id="backtest-fixture-label">Synthetic fixture</InputLabel>
            <Select
              label="Synthetic fixture"
              labelId="backtest-fixture-label"
              onChange={(event) => setSelectedFixtureKey(event.target.value)}
              value={fixture ? fixtureSelectionKey(fixture) : ''}
            >
              {fixtures.map((candidate) => (
                <MenuItem
                  key={fixtureSelectionKey(candidate)}
                  value={fixtureSelectionKey(candidate)}
                >
                  {candidate.display_name} · {candidate.fixture_version}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Box>
        {strategy && configuration && fixture ? (
          <Box
            sx={{
              bgcolor: 'rgba(147, 165, 186, 0.05)',
              border: 1,
              borderColor: 'divider',
              borderRadius: 1,
              display: 'grid',
              gap: 1.4,
              gridTemplateColumns: { xs: '1fr', md: 'repeat(3, minmax(0, 1fr))' },
              mt: 1.5,
              p: 1.5,
            }}
          >
            <LabeledValue label="Configuration SHA-256"><DigestValue label="Configuration SHA-256">{configuration.configuration_sha256}</DigestValue></LabeledValue>
            <LabeledValue label="Dataset manifest SHA-256"><DigestValue label="Dataset manifest SHA-256">{fixture.dataset_manifest_sha256}</DigestValue></LabeledValue>
            <LabeledValue label="Replay run ID"><DigestValue label="Replay run ID">{fixture.replay_run_id}</DigestValue></LabeledValue>
            <LabeledValue label="Cost model SHA-256"><DigestValue label="Cost model SHA-256">{fixture.cost_model_sha256}</DigestValue></LabeledValue>
            <LabeledValue label="Fill model SHA-256"><DigestValue label="Fill model SHA-256">{fixture.fill_model_sha256}</DigestValue></LabeledValue>
            <LabeledValue label="Metrics SHA-256"><DigestValue label="Metric conventions SHA-256">{fixture.metric_conventions_sha256}</DigestValue></LabeledValue>
          </Box>
        ) : null}
        {!launchConfig?.enabled || bootstrap.environment.mode !== 'local' || !headersAreSupported ? (
          <Alert severity="warning" sx={{ mt: 1.5 }} variant="outlined">
            {launchConfig?.disabled_reason ?? 'Backtest launch is unavailable outside the authenticated local research environment.'}
          </Alert>
        ) : null}
        {launchMutation.isError ? (
          <Alert severity="error" sx={{ mt: 1.5 }} variant="outlined">
            {errorMessage('The backtest was not launched', launchMutation.error)}
            <Box sx={{ mt: 1 }}>
              <Button onClick={resetAmbiguousLaunch} size="small" variant="outlined">
                Start a different request
              </Button>
            </Box>
          </Alert>
        ) : null}
        {launchMutation.isSuccess ? (
          <Alert aria-live="polite" severity="success" sx={{ mt: 1.5 }} variant="outlined">
            Job {launchMutation.data.job_id.slice(0, 12)}… was accepted as {launchMutation.data.status}.
          </Alert>
        ) : null}
        <Box sx={{ alignItems: 'center', display: 'flex', flexWrap: 'wrap', gap: 1.25, justifyContent: 'space-between', mt: 2 }}>
          <Typography color="text.secondary" sx={{ fontSize: 10.5 }}>
            {lastIdempotencyKey ? `Last request key: ${lastIdempotencyKey}` : `Authenticated local operator: ${launchConfig?.operator_id ?? 'unavailable'}`}
          </Typography>
          <Button
            disabled={!mayLaunch || launchMutation.isPending}
            onClick={submit}
            startIcon={launchMutation.isPending ? <CircularProgress size={16} /> : <PlayArrowRoundedIcon />}
            variant="contained"
          >
            {launchMutation.isPending
              ? 'Launching…'
              : launchMutation.isError && launchAttempt
                ? 'Retry same request'
                : 'Launch backtest'}
          </Button>
        </Box>
      </CardContent>
    </Card>
  )
}

function JobHistory({ job }: { job: BacktestJob | undefined }) {
  if (!job) {
    return <EmptyDataState detail="Select a job from the history table to inspect its append-only lifecycle." title="No job selected" />
  }
  const history = job.history
  return (
    <Box
      aria-label="Append-only job history"
      component="ol"
      sx={{ listStyle: 'none', m: 0, p: 0 }}
    >
      {history.map((event, index) => (
        <Box component="li" key={`${event.sequence}-${event.status}`} sx={{ display: 'grid', gridTemplateColumns: '24px minmax(0, 1fr)', gap: 1.25 }}>
          <Box sx={{ alignItems: 'center', display: 'flex', flexDirection: 'column' }}>
            <Box sx={{ bgcolor: index === history.length - 1 ? 'primary.main' : 'divider', borderRadius: '50%', height: 9, mt: 0.65, width: 9 }} />
            {index < history.length - 1 ? <Box sx={{ bgcolor: 'divider', flex: 1, minHeight: 32, width: 1 }} /> : null}
          </Box>
          <Box sx={{ pb: index < history.length - 1 ? 1.5 : 0 }}>
            <Box sx={{ alignItems: 'center', display: 'flex', gap: 1 }}><StatusChip status={event.status} /><Typography color="text.secondary" sx={{ fontSize: 10.5 }}>Attempt {event.attempt_number}</Typography></Box>
            <Typography sx={{ fontSize: 11.5, mt: 0.45 }}>{formatDateTime(event.occurred_at)} · {event.actor_id}</Typography>
            {event.terminal_reason_code ? <Typography color="error.main" sx={{ fontSize: 10.5, mt: 0.25 }}>{titleCase(event.terminal_reason_code)}</Typography> : null}
          </Box>
        </Box>
      ))}
    </Box>
  )
}

function JobsWorkspace({
  onSelect,
  selectedJobId,
}: {
  onSelect: (jobId: string) => void
  selectedJobId: string | null
}) {
  const jobsQuery = useBacktests()
  const jobs = jobsQuery.data?.data.jobs ?? []
  const selectedJob = jobs.find((job) => job.job_id === selectedJobId) ?? jobs[0]
  const refresh = () => { void jobsQuery.refetch() }

  if (jobsQuery.isPending) return <ResearchPageSkeleton label="Loading backtest job history" />
  if (jobsQuery.isError) return <ErrorState message={errorMessage('Backtest job history is unavailable', jobsQuery.error)} onRetry={refresh} />

  return (
    <Box>
      {jobsQuery.data?.source === 'development-fixture' ? <Alert severity="warning" sx={{ mb: 2 }} variant="outlined">The Control API is unavailable and explicit development job fixtures are active.</Alert> : null}
      <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: { xs: '1fr', xl: 'minmax(0, 2.15fr) minmax(280px, 0.85fr)' } }}>
        <Card component="section">
          <CardContent sx={{ p: 0, '&:last-child': { pb: 0 } }}>
            <Box sx={{ alignItems: 'flex-start', borderBottom: 1, borderColor: 'divider', display: 'flex', gap: 2, justifyContent: 'space-between', px: 2.25, py: 1.8 }}>
              <Box><Typography component="h2" variant="h2">Job status and progress</Typography><Typography color="text.secondary" sx={{ fontSize: 11.5, mt: 0.4 }}>Durable requests and their latest append-only lifecycle state.</Typography></Box>
              <Button disabled={jobsQuery.isFetching} onClick={refresh} size="small" startIcon={jobsQuery.isFetching ? <CircularProgress size={14} /> : <RefreshRoundedIcon />}>Refresh</Button>
            </Box>
            {jobs.length === 0 ? <EmptyDataState detail="Launch a validated synthetic fixture to create the first durable job." title="No backtest jobs" /> : (
              <TableContainer>
                <Table aria-label="Backtest jobs" size="small">
                  <TableHead><TableRow><TableCell>Status</TableCell><TableCell>Job</TableCell><TableCell>Inputs</TableCell><TableCell>Requested</TableCell><TableCell>Progress</TableCell><TableCell align="right">Action</TableCell></TableRow></TableHead>
                  <TableBody>
                    {jobs.map((job) => (
                      <TableRow key={job.job_id} selected={job.job_id === selectedJob?.job_id}>
                        <TableCell><StatusChip status={job.status} /></TableCell>
                        <TableCell sx={{ maxWidth: 180 }}><DigestValue label="Job ID">{job.job_id}</DigestValue><Typography color="text.secondary" sx={{ fontSize: 10, mt: 0.3 }}>Attempt {job.attempt_number}</Typography></TableCell>
                        <TableCell><Typography sx={{ fontSize: 11.5, fontWeight: 700 }}>{job.strategy_id} · {job.strategy_version}</Typography><Typography color="text.secondary" sx={{ fontSize: 10 }}>{job.fixture_id} · {job.fixture_version}</Typography></TableCell>
                        <TableCell><Typography sx={{ fontSize: 11 }}>{formatDateTime(job.requested_at)}</Typography><Typography color="text.secondary" sx={{ fontSize: 10 }}>Updated {formatDateTime(job.updated_at)}</Typography></TableCell>
                        <TableCell sx={{ minWidth: 120 }}>
                          {job.status === 'queued' || job.status === 'running' ? (
                            <LinearProgress aria-label={`${job.job_id} ${job.status} progress`} />
                          ) : (
                            <LinearProgress
                              aria-label={`${job.job_id} ${job.status} progress`}
                              color={job.status === 'failed' ? 'error' : job.status === 'canceled' ? 'warning' : 'primary'}
                              value={100}
                              variant="determinate"
                            />
                          )}
                          <Typography color="text.secondary" sx={{ fontSize: 9.5, mt: 0.4 }}>{job.status === 'running' ? 'Worker executing' : titleCase(job.status)}</Typography>
                        </TableCell>
                        <TableCell align="right"><Button onClick={() => onSelect(job.job_id)} size="small" variant={job.job_id === selectedJob?.job_id ? 'contained' : 'outlined'}>Inspect</Button></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </CardContent>
        </Card>
        <Card component="section">
          <CardContent>
            <Box sx={{ alignItems: 'center', display: 'flex', gap: 1 }}><HistoryRoundedIcon color="primary" /><Typography component="h2" variant="h2">Job history</Typography></Box>
            {selectedJob ? <Box sx={{ mt: 1.2, mb: 1.5 }}><DigestValue label="Selected job ID">{selectedJob.job_id}</DigestValue></Box> : null}
            <Divider sx={{ mb: 1.5 }} />
            <JobHistory job={selectedJob} />
          </CardContent>
        </Card>
      </Box>
      <BacktestReportPanel jobId={selectedJob?.status === 'completed' && selectedJob.report_artifact_sha256 ? selectedJob.job_id : null} />
    </Box>
  )
}

export function BacktestsPage({ bootstrap }: BacktestsPageProps) {
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null)
  const summary = useMemo(() => bootstrap.environment.mode === 'local' ? 'Local, authenticated, fixture-only execution' : 'Launch disabled outside local mode', [bootstrap.environment.mode])
  return (
    <>
      <PageHeader
        description="Launch reproducible event-driven fixture runs, follow their durable lifecycle, and inspect retained performance and provenance."
        eyebrow="Phase 2 · Research"
        title="Backtests"
      />
      <Alert icon={<ScienceOutlinedIcon />} severity="info" sx={{ mb: 2 }} variant="outlined">
        <strong>{summary}.</strong> Every distinct launch carries an idempotency key and exact strategy, replay, dataset, model, and metric pins; ambiguous retries reuse the same request identity.
      </Alert>
      <LaunchPanel bootstrap={bootstrap} />
      <Box sx={{ alignItems: 'center', display: 'flex', gap: 1, mb: 1.5, mt: 3 }}><LockClockOutlinedIcon color="primary" /><Typography component="h2" sx={{ fontSize: 17, fontWeight: 750 }}>Run history and artifacts</Typography><Chip label="Append-only" size="small" variant="outlined" /></Box>
      <JobsWorkspace onSelect={setSelectedJobId} selectedJobId={selectedJobId} />
    </>
  )
}
