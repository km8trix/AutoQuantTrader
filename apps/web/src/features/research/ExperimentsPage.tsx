import AssignmentTurnedInOutlinedIcon from '@mui/icons-material/AssignmentTurnedInOutlined'
import HistoryRoundedIcon from '@mui/icons-material/HistoryRounded'
import LockOutlinedIcon from '@mui/icons-material/LockOutlined'
import NumbersOutlinedIcon from '@mui/icons-material/NumbersOutlined'
import ScienceOutlinedIcon from '@mui/icons-material/ScienceOutlined'
import VisibilityOutlinedIcon from '@mui/icons-material/VisibilityOutlined'
import {
  Alert,
  Box,
  Card,
  CardContent,
  Chip,
  Divider,
  FormControl,
  InputLabel,
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
import { useMemo } from 'react'
import type { ReactNode } from 'react'
import { useSearchParams } from 'react-router-dom'

import { ApiError } from '../../api/client'
import { formatDateTime, titleCase } from '../../api/format'
import { useExperiment, useExperiments } from '../../api/queries'
import type {
  ExperimentAttemptView,
  ExperimentEvaluationReceiptView,
  ExperimentHoldoutView,
  ExperimentPromotionCriteriaView,
  ExperimentSegmentView,
  ExperimentSummaryView,
} from '../../api/types'
import { ErrorState } from '../../components/LoadState'
import { MetricCard } from '../../components/MetricCard'
import { PageHeader } from '../../components/PageHeader'
import { StatusChip } from '../../components/StatusChip'
import { EmptyDataState, RefreshButton } from '../data/DataPageComponents'
import {
  DigestValue,
  ImmutableChip,
  LabeledValue,
  ResearchPageSkeleton,
} from './ResearchPageComponents'

function experimentsErrorMessage(error: unknown): string {
  if (error instanceof ApiError || error instanceof Error) {
    return `Experiment governance evidence is unavailable: ${error.message}`
  }
  return 'Experiment governance evidence is unavailable due to an unexpected error.'
}

function TextValue({ children }: { children: ReactNode }) {
  return <Typography sx={{ fontSize: 11.5 }}>{children}</Typography>
}

function DigestOrMissing({
  label,
  value,
}: {
  label: string
  value: string | null
}) {
  return value ? (
    <DigestValue label={label}>{value}</DigestValue>
  ) : (
    <Typography color="text.secondary" sx={{ fontSize: 11 }}>
      Not recorded
    </Typography>
  )
}

function SummaryPins({ summary }: { summary: ExperimentSummaryView }) {
  const pins = [
    ['Family ID', summary.family_id],
    ['Strategy version SHA-256', summary.strategy_version_sha256],
    ['Evaluation plan SHA-256', summary.evaluation_plan_sha256],
    ['Promotion criteria SHA-256', summary.promotion_criteria_sha256],
    ['Test commitment SHA-256', summary.test_commitment_sha256],
    ['Snapshot SHA-256', summary.snapshot_sha256],
    ['Registry head SHA-256', summary.registry_head_sha256],
  ] as const

  return (
    <Card component="section">
      <CardContent>
        <Box
          sx={{
            alignItems: 'flex-start',
            display: 'flex',
            gap: 2,
            justifyContent: 'space-between',
          }}
        >
          <Box>
            <Typography component="h2" variant="h2">
              Hypothesis and exact pins
            </Typography>
            <Typography color="text.secondary" sx={{ fontSize: 11.5, mt: 0.4 }}>
              The family declaration is content-addressed and cannot drift between attempts.
            </Typography>
          </Box>
          <ImmutableChip label="Frozen family" />
        </Box>
        <Alert severity="info" sx={{ mt: 1.75 }} variant="outlined">
          <strong>Hypothesis.</strong> {summary.hypothesis}
        </Alert>
        <Box
          component="dl"
          sx={{
            display: 'grid',
            gap: 1.5,
            gridTemplateColumns: { xs: '1fr', md: 'repeat(2, minmax(0, 1fr))' },
            m: 0,
            mt: 1.75,
          }}
        >
          <LabeledValue label="Family name">
            <TextValue>{summary.family_name}</TextValue>
          </LabeledValue>
          <LabeledValue label="Owner">
            <TextValue>{summary.owner_id}</TextValue>
          </LabeledValue>
          <LabeledValue label="Strategy pin">
            <TextValue>
              {summary.strategy_id} · {summary.strategy_version}
            </TextValue>
          </LabeledValue>
          <LabeledValue label="Evaluation plan">
            <TextValue>{summary.evaluation_plan_version}</TextValue>
          </LabeledValue>
          {pins.map(([label, value]) => (
            <LabeledValue key={label} label={label}>
              <DigestValue label={label}>{value}</DigestValue>
            </LabeledValue>
          ))}
        </Box>
      </CardContent>
    </Card>
  )
}

function SegmentCard({ segment }: { segment: ExperimentSegmentView }) {
  return (
    <Card component="article" variant="outlined">
      <CardContent sx={{ p: 1.75, '&:last-child': { pb: 1.75 } }}>
        <Box sx={{ alignItems: 'center', display: 'flex', justifyContent: 'space-between' }}>
          <Typography component="h3" sx={{ fontSize: 13, fontWeight: 750 }}>
            {titleCase(segment.kind)}
          </Typography>
          <ImmutableChip label="Declared" />
        </Box>
        <Box sx={{ display: 'grid', gap: 1.15, mt: 1.5 }}>
          <LabeledValue label="Coverage">
            <TextValue>
              {formatDateTime(segment.coverage_start)} – {formatDateTime(segment.coverage_end)}
            </TextValue>
          </LabeledValue>
          <Box
            sx={{
              display: 'grid',
              gap: 1,
              gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
            }}
          >
            <LabeledValue label="Purge before">
              <TextValue>{segment.purge_before}</TextValue>
            </LabeledValue>
            <LabeledValue label="Embargo after">
              <TextValue>{segment.embargo_after}</TextValue>
            </LabeledValue>
          </Box>
          <LabeledValue label="Segment SHA-256">
            {segment.segment_sha256 ? (
              <DigestValue label={`${segment.kind} segment SHA-256`}>
                {segment.segment_sha256}
              </DigestValue>
            ) : (
              <Typography color="text.secondary" sx={{ fontSize: 11 }}>
                Withheld until audited reveal
              </Typography>
            )}
          </LabeledValue>
          <LabeledValue label="Dataset replay SHA-256">
            {segment.dataset_replay_sha256 ? (
              <DigestValue label={`${segment.kind} dataset replay SHA-256`}>
                {segment.dataset_replay_sha256}
              </DigestValue>
            ) : (
              <Typography color="text.secondary" sx={{ fontSize: 11 }}>
                Withheld until audited reveal
              </Typography>
            )}
          </LabeledValue>
        </Box>
      </CardContent>
    </Card>
  )
}

function SegmentDeclarations({ segments }: { segments: ExperimentSegmentView[] }) {
  const segmentOrder = { train: 0, validation: 1, test: 2 }
  const orderedSegments = [...segments].sort(
    (left, right) => segmentOrder[left.kind] - segmentOrder[right.kind],
  )

  return (
    <Card component="section">
      <CardContent>
        <Typography component="h2" variant="h2">
          Train, validation, and test declarations
        </Typography>
        <Typography color="text.secondary" sx={{ fontSize: 11.5, mt: 0.4 }}>
          Exact time ranges, replay evidence, purge, and embargo boundaries declared before
          evaluation.
        </Typography>
        {orderedSegments.length === 0 ? (
          <EmptyDataState
            detail="This family has no immutable evaluation-segment declarations."
            title="No segments declared"
          />
        ) : (
          <Box
            sx={{
              display: 'grid',
              gap: 1.5,
              gridTemplateColumns: { xs: '1fr', xl: 'repeat(3, minmax(0, 1fr))' },
              mt: 1.75,
            }}
          >
            {orderedSegments.map((segment) => (
              <SegmentCard key={`${segment.kind}:${segment.segment_sha256}`} segment={segment} />
            ))}
          </Box>
        )}
        <Alert severity="warning" sx={{ mt: 1.75 }} variant="outlined">
          The test segment is a declaration only. This read-only surface does not return a
          held-out transcript or report.
        </Alert>
      </CardContent>
    </Card>
  )
}

function comparisonLabel(comparison: string): string {
  return comparison === 'greater_than_or_equal' ? '≥' : '≤'
}

function PromotionCriteria({
  criteria,
}: {
  criteria: ExperimentPromotionCriteriaView
}) {
  return (
    <Card component="section">
      <CardContent>
        <Box
          sx={{
            alignItems: 'flex-start',
            display: 'flex',
            gap: 2,
            justifyContent: 'space-between',
          }}
        >
          <Box>
            <Typography component="h2" variant="h2">
              Frozen promotion criteria
            </Typography>
            <Typography color="text.secondary" sx={{ fontSize: 11.5, mt: 0.4 }}>
              Selection and multiplicity rules were fixed before any governed attempt.
            </Typography>
          </Box>
          <ImmutableChip label="Frozen criteria" />
        </Box>
        <Box
          sx={{
            display: 'grid',
            gap: 1.5,
            gridTemplateColumns: { xs: '1fr', md: 'repeat(2, minmax(0, 1fr))' },
            mt: 1.75,
          }}
        >
          <LabeledValue label="Criteria version">
            <TextValue>{criteria.criteria_version}</TextValue>
          </LabeledValue>
          <LabeledValue label="Criteria SHA-256">
            <DigestValue label="Frozen criteria SHA-256">{criteria.criteria_sha256}</DigestValue>
          </LabeledValue>
          <LabeledValue label="Selection rule">
            <TextValue>{criteria.selection_rule}</TextValue>
          </LabeledValue>
          <LabeledValue label="Multiple-testing method">
            <TextValue>{criteria.multiple_testing_method}</TextValue>
          </LabeledValue>
          <LabeledValue label="Frozen by">
            <TextValue>{criteria.frozen_by}</TextValue>
          </LabeledValue>
          <LabeledValue label="Frozen at">
            <TextValue>{formatDateTime(criteria.frozen_at)}</TextValue>
          </LabeledValue>
        </Box>
        <TableContainer sx={{ mt: 1.75 }}>
          <Table aria-label="Frozen promotion thresholds" size="small">
            <TableHead>
              <TableRow>
                <TableCell>Metric</TableCell>
                <TableCell>Threshold</TableCell>
                <TableCell align="right">Minimum observations</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {criteria.criteria.map((criterion) => (
                <TableRow key={`${criterion.metric_name}:${criterion.comparison}`}>
                  <TableCell>{criterion.metric_name}</TableCell>
                  <TableCell>
                    {comparisonLabel(criterion.comparison)} {criterion.threshold}
                  </TableCell>
                  <TableCell align="right">
                    {criterion.minimum_observations.toLocaleString()}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </CardContent>
    </Card>
  )
}

function EvaluationEvidence({
  attemptNumber,
  evaluation,
}: {
  attemptNumber: number
  evaluation: ExperimentEvaluationReceiptView
}) {
  const digests = [
    ['Evaluation receipt SHA-256', evaluation.receipt_sha256],
    ['Source evidence SHA-256', evaluation.source_evidence_sha256],
    ['Feature certification SHA-256', evaluation.feature_certification_sha256],
    ['Target policy SHA-256', evaluation.target_policy_sha256],
    ['Target runtime pin SHA-256', evaluation.target_runtime_pin_sha256],
    ['Target certification SHA-256', evaluation.target_certification_sha256],
    ['Batch result SHA-256', evaluation.batch_result_sha256],
    ['Incremental result SHA-256', evaluation.incremental_result_sha256],
    ['Target parity receipt SHA-256', evaluation.target_parity_receipt_sha256],
    ['Target transcript SHA-256', evaluation.target_transcript_sha256],
    ['Running event SHA-256', evaluation.running_event_sha256],
  ] as const

  return (
    <Box
      aria-label={`Evaluation evidence for attempt ${attemptNumber}`}
      sx={{
        borderColor: 'divider',
        borderRadius: 1,
        borderStyle: 'solid',
        borderWidth: 1,
        gridColumn: '1 / -1',
        mt: 0.25,
        p: 1.25,
      }}
    >
      <Box sx={{ alignItems: 'center', display: 'flex', gap: 1, justifyContent: 'space-between' }}>
        <Typography sx={{ fontSize: 11.5, fontWeight: 750 }}>
          Configuration-bound evaluation proof
        </Typography>
        <Chip label={titleCase(evaluation.evidence_kind)} size="small" variant="outlined" />
      </Box>
      <Alert severity="info" sx={{ mt: 1 }} variant="outlined">
        Parity-certified target evaluation only. This is not a performance report, backtest,
        promotion decision, deployment approval, or trading authority.
      </Alert>
      <Box
        sx={{
          display: 'grid',
          gap: 1,
          gridTemplateColumns: { xs: '1fr', md: 'repeat(2, minmax(0, 1fr))' },
          mt: 1.25,
        }}
      >
        <LabeledValue label="Recorded evaluator actor">
          <TextValue>{evaluation.evaluated_by}</TextValue>
        </LabeledValue>
        <LabeledValue label="Segment">
          <TextValue>{titleCase(evaluation.segment_kind)}</TextValue>
        </LabeledValue>
        <LabeledValue label="Started">
          <TextValue>{formatDateTime(evaluation.started_at)}</TextValue>
        </LabeledValue>
        <LabeledValue label="Completed">
          <TextValue>{formatDateTime(evaluation.completed_at)}</TextValue>
        </LabeledValue>
        <LabeledValue label="Evaluated steps">
          <TextValue>{evaluation.step_count.toLocaleString()}</TextValue>
        </LabeledValue>
        <LabeledValue label="Produced targets">
          <TextValue>{evaluation.target_count.toLocaleString()}</TextValue>
        </LabeledValue>
        {digests.map(([label, value]) => (
          <LabeledValue key={label} label={label}>
            <DigestValue label={`Attempt ${attemptNumber} ${label}`}>{value}</DigestValue>
          </LabeledValue>
        ))}
      </Box>
    </Box>
  )
}

function AttemptCard({ attempt }: { attempt: ExperimentAttemptView }) {
  return (
    <Card component="article" variant="outlined">
      <CardContent sx={{ p: 0, '&:last-child': { pb: 0 } }}>
        <Box
          sx={{
            alignItems: 'flex-start',
            display: 'flex',
            gap: 2,
            justifyContent: 'space-between',
            p: 1.75,
          }}
        >
          <Box sx={{ minWidth: 0 }}>
            <Typography component="h3" sx={{ fontSize: 13, fontWeight: 750 }}>
              Attempt {attempt.attempt_number}: {attempt.configuration_name}
            </Typography>
            <Typography color="text.secondary" sx={{ fontSize: 10.5, mt: 0.3 }}>
              Requested by {attempt.requested_by} · {formatDateTime(attempt.requested_at)}
            </Typography>
          </Box>
          <StatusChip status={attempt.status} />
        </Box>
        <Divider />
        <Box
          sx={{
            display: 'grid',
            gap: 1.25,
            gridTemplateColumns: { xs: '1fr', md: 'repeat(2, minmax(0, 1fr))' },
            p: 1.75,
          }}
        >
          <LabeledValue label="Configuration SHA-256">
            <DigestValue label={`Attempt ${attempt.attempt_number} configuration SHA-256`}>
              {attempt.configuration_sha256}
            </DigestValue>
          </LabeledValue>
          <LabeledValue label="Validation receipt SHA-256">
            <DigestValue label={`Attempt ${attempt.attempt_number} validation SHA-256`}>
              {attempt.configuration_validation_sha256}
            </DigestValue>
          </LabeledValue>
          <LabeledValue label="Evaluation segment">
            <TextValue>{titleCase(attempt.segment_kind)}</TextValue>
          </LabeledValue>
          <LabeledValue label="Segment SHA-256">
            <DigestValue label={`Attempt ${attempt.attempt_number} segment SHA-256`}>
              {attempt.segment_sha256}
            </DigestValue>
          </LabeledValue>
        </Box>
        <Divider />
        <Box sx={{ p: 1.75 }}>
          <Typography
            color="text.secondary"
            sx={{ fontSize: 10, fontWeight: 750, letterSpacing: '0.07em', textTransform: 'uppercase' }}
          >
            Append-only lifecycle history
          </Typography>
          <Box
            aria-label={`Lifecycle history for attempt ${attempt.attempt_number}`}
            component="ol"
            sx={{ display: 'grid', gap: 1, listStyle: 'none', m: 0, mt: 1.25, p: 0 }}
          >
            {attempt.history.map((event) => (
              <Box
                component="li"
                key={`${event.global_sequence_number}:${event.event_sha256}`}
                sx={{
                  bgcolor: 'rgba(147, 165, 186, 0.05)',
                  borderRadius: 1,
                  display: 'grid',
                  gap: 1.25,
                  gridTemplateColumns: 'minmax(0, 1fr) auto',
                  p: 1,
                }}
              >
                <Box>
                  <Typography sx={{ fontSize: 11.5, fontWeight: 700 }}>
                    {titleCase(event.status)}
                  </Typography>
                  <Typography color="text.secondary" sx={{ fontSize: 10 }}>
                    #{event.attempt_sequence_number} by {event.actor_id} ·{' '}
                    {formatDateTime(event.occurred_at)}
                  </Typography>
                  {event.terminal_reason_code ? (
                    <Typography color="text.secondary" sx={{ fontSize: 10, mt: 0.3 }}>
                      Reason: {event.terminal_reason_code}
                    </Typography>
                  ) : null}
                </Box>
                <DigestValue label={`Lifecycle event ${event.global_sequence_number} SHA-256`}>
                  {event.event_sha256}
                </DigestValue>
                {event.evaluation ? (
                  <EvaluationEvidence
                    attemptNumber={attempt.attempt_number}
                    evaluation={event.evaluation}
                  />
                ) : null}
              </Box>
            ))}
          </Box>
        </Box>
      </CardContent>
    </Card>
  )
}

function AttemptHistory({ attempts }: { attempts: ExperimentAttemptView[] }) {
  const orderedAttempts = [...attempts].sort(
    (left, right) => left.attempt_number - right.attempt_number,
  )

  return (
    <Card component="section">
      <CardContent>
        <Box sx={{ alignItems: 'center', display: 'flex', gap: 1 }}>
          <HistoryRoundedIcon color="primary" fontSize="small" />
          <Typography component="h2" variant="h2">
            Governed attempt history
          </Typography>
          <Chip label={orderedAttempts.length.toLocaleString()} size="small" variant="outlined" />
        </Box>
        <Typography color="text.secondary" sx={{ fontSize: 11.5, mt: 0.4 }}>
          Every queued, running, and terminal state is retained as immutable lifecycle evidence.
        </Typography>
        {orderedAttempts.length === 0 ? (
          <EmptyDataState
            detail="No bounded evaluation attempts have been recorded for this family."
            title="No attempts recorded"
          />
        ) : (
          <Box
            sx={{
              display: 'grid',
              gap: 1.5,
              gridTemplateColumns: { xs: '1fr', xl: 'repeat(2, minmax(0, 1fr))' },
              mt: 1.75,
            }}
          >
            {orderedAttempts.map((attempt) => (
              <AttemptCard attempt={attempt} key={attempt.attempt_id} />
            ))}
          </Box>
        )}
      </CardContent>
    </Card>
  )
}

function HoldoutEvidence({ holdout }: { holdout: ExperimentHoldoutView }) {
  const revealed = holdout.state === 'revealed'

  return (
    <Card component="section">
      <CardContent>
        <Box
          sx={{
            alignItems: 'flex-start',
            display: 'flex',
            gap: 2,
            justifyContent: 'space-between',
          }}
        >
          <Box>
            <Typography component="h2" variant="h2">
              Final holdout
            </Typography>
            <Typography color="text.secondary" sx={{ fontSize: 11.5, mt: 0.4 }}>
              Reveal governance and target-evaluation proof metadata are inspectable. Held-out
              observations, transcript contents, and performance results are not exposed.
            </Typography>
          </Box>
          <StatusChip
            label={revealed ? 'Revealed' : 'Sealed'}
            status={revealed ? 'completed' : 'pending'}
          />
        </Box>
        <Alert
          icon={revealed ? <VisibilityOutlinedIcon /> : <LockOutlinedIcon />}
          severity={revealed ? 'warning' : 'success'}
          sx={{ mt: 1.75 }}
          variant="outlined"
        >
          <strong>
            {revealed
              ? 'Final holdout has been revealed.'
              : 'Final holdout remains sealed.'}
          </strong>{' '}
          {revealed
            ? 'The authorization and frozen pre-reveal state are shown below.'
            : 'Only its precommitted identity is visible; no governed reveal evidence is recorded.'}
        </Alert>
        <Box
          sx={{
            display: 'grid',
            gap: 1.5,
            gridTemplateColumns: { xs: '1fr', md: 'repeat(2, minmax(0, 1fr))' },
            mt: 1.75,
          }}
        >
          <LabeledValue label="Commitment SHA-256">
            <DigestValue label="Final holdout commitment SHA-256">
              {holdout.commitment_sha256}
            </DigestValue>
          </LabeledValue>
          {revealed ? (
            <>
              <LabeledValue label="Authorization SHA-256">
                <DigestOrMissing label="Holdout authorization SHA-256" value={holdout.authorization_sha256} />
              </LabeledValue>
              <LabeledValue label="Reveal SHA-256">
                <DigestOrMissing label="Holdout reveal SHA-256" value={holdout.reveal_sha256} />
              </LabeledValue>
              <LabeledValue label="Selected configuration SHA-256">
                <DigestOrMissing label="Selected configuration SHA-256" value={holdout.selected_configuration_sha256} />
              </LabeledValue>
              <LabeledValue label="Pre-reveal snapshot SHA-256">
                <DigestOrMissing label="Pre-reveal snapshot SHA-256" value={holdout.pre_reveal_snapshot_sha256} />
              </LabeledValue>
              <LabeledValue label="Pre-reveal registry head SHA-256">
                <DigestOrMissing label="Pre-reveal registry head SHA-256" value={holdout.pre_reveal_registry_head_sha256} />
              </LabeledValue>
              <LabeledValue label="Pre-reveal attempts SHA-256">
                <DigestOrMissing label="Pre-reveal attempts SHA-256" value={holdout.pre_reveal_attempts_sha256} />
              </LabeledValue>
              <LabeledValue label="Pre-reveal attempt count">
                <TextValue>{holdout.pre_reveal_attempt_count?.toLocaleString() ?? 'Not recorded'}</TextValue>
              </LabeledValue>
              <LabeledValue label="Revealed by">
                <TextValue>{holdout.revealed_by ?? 'Not recorded'}</TextValue>
              </LabeledValue>
              <LabeledValue label="Revealed at">
                <TextValue>
                  {holdout.revealed_at ? formatDateTime(holdout.revealed_at) : 'Not recorded'}
                </TextValue>
              </LabeledValue>
              <LabeledValue label="Access reason">
                <TextValue>{holdout.access_reason ?? 'Not recorded'}</TextValue>
              </LabeledValue>
            </>
          ) : null}
        </Box>
      </CardContent>
    </Card>
  )
}

export function ExperimentsPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const experimentsQuery = useExperiments()
  const summaries = useMemo(
    () =>
      [...(experimentsQuery.data?.data.experiments ?? [])].sort(
        (left, right) =>
          left.family_name.localeCompare(right.family_name) ||
          left.family_id.localeCompare(right.family_id),
      ),
    [experimentsQuery.data],
  )
  const requestedFamilyId = searchParams.get('family_id')
  const selectedSummary =
    summaries.find((summary) => summary.family_id === requestedFamilyId) ?? summaries[0] ?? null
  const experimentQuery = useExperiment(selectedSummary?.family_id ?? null)
  const detailExperiment = experimentQuery.data?.data.experiment
  const detailIdentityMismatch =
    detailExperiment !== undefined &&
    selectedSummary !== null &&
    detailExperiment.summary.family_id !== selectedSummary.family_id
  const experiment = detailIdentityMismatch ? undefined : detailExperiment
  const visibleSummary = experiment?.summary ?? selectedSummary
  const refresh = () => {
    void experimentsQuery.refetch()
    if (selectedSummary) void experimentQuery.refetch()
  }
  const selectFamily = (familyId: string) => {
    const next = new URLSearchParams(searchParams)
    next.set('family_id', familyId)
    setSearchParams(next, { replace: true })
  }
  const developmentFixtureActive =
    experimentsQuery.data?.source === 'development-fixture' ||
    experimentQuery.data?.source === 'development-fixture'
  const isFetching = experimentsQuery.isFetching || experimentQuery.isFetching

  return (
    <>
      <PageHeader
        actions={<RefreshButton isFetching={isFetching} onRefresh={refresh} />}
        description="Inspect frozen experiment declarations, bounded attempt history, and final-holdout governance without mutating research state."
        eyebrow="Phase 3 · Research governance"
        title="Experiments"
      />
      <Alert icon={<ScienceOutlinedIcon />} severity="info" sx={{ mb: 2 }} variant="outlined">
        <strong>Read-only governance evidence.</strong> This surface has no attempt, reveal,
        promotion, deployment, or trading controls.
      </Alert>
      {developmentFixtureActive ? (
        <Alert severity="warning" sx={{ mb: 2 }} variant="outlined">
          The Control API is unavailable and explicit synthetic development fixtures are active.
          Fixture data contains declarations and lifecycle mechanics only—no held-out transcript or
          report.
        </Alert>
      ) : null}
      {experimentsQuery.isPending ? (
        <ResearchPageSkeleton label="Loading governed experiment families" />
      ) : null}
      {experimentsQuery.isError ? (
        <ErrorState message={experimentsErrorMessage(experimentsQuery.error)} onRetry={refresh} />
      ) : null}
      {experimentsQuery.data && summaries.length === 0 ? (
        <Card>
          <EmptyDataState
            detail="Register and persist a frozen experiment family before inspecting governed attempts."
            title="No experiment families registered"
          />
        </Card>
      ) : null}
      {selectedSummary && visibleSummary ? (
        <Box aria-live="polite">
          <Card component="section" sx={{ mb: 2 }}>
            <CardContent>
              <Box
                sx={{
                  alignItems: { md: 'center' },
                  display: 'grid',
                  gap: 2,
                  gridTemplateColumns: { xs: '1fr', md: 'minmax(0, 1fr) minmax(260px, 0.55fr)' },
                }}
              >
                <Box>
                  <Typography color="text.secondary" variant="subtitle2">
                    Deterministic family selection
                  </Typography>
                  <Typography sx={{ fontSize: 12, mt: 0.4 }}>
                    Families are ordered by name and immutable ID. A valid URL pin takes precedence.
                  </Typography>
                </Box>
                <FormControl fullWidth size="small">
                  <InputLabel id="experiment-family-label">Experiment family</InputLabel>
                  <Select
                    label="Experiment family"
                    labelId="experiment-family-label"
                    onChange={(event) => selectFamily(event.target.value)}
                    value={selectedSummary.family_id}
                  >
                    {summaries.map((summary) => (
                      <MenuItem key={summary.family_id} value={summary.family_id}>
                        {summary.family_name}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Box>
            </CardContent>
          </Card>
          <Box
            sx={{
              display: 'grid',
              gap: 2,
              gridTemplateColumns: { xs: '1fr', md: 'repeat(3, minmax(0, 1fr))' },
            }}
          >
            <MetricCard
              detail={
                visibleSummary.holdout_state === 'revealed'
                  ? 'Exploratory budget locked after reveal'
                  : `${visibleSummary.remaining_pre_holdout_attempts.toLocaleString()} remaining before holdout`
              }
              direction={
                visibleSummary.remaining_pre_holdout_attempts > 0 ? 'neutral' : 'negative'
              }
              icon={<NumbersOutlinedIcon />}
              label="Stable attempt budget"
              value={`${visibleSummary.pre_holdout_attempt_count.toLocaleString()} / ${visibleSummary.maximum_pre_holdout_trials.toLocaleString()}`}
            />
            <MetricCard
              detail={`${visibleSummary.attempt_count.toLocaleString()} stable attempt identit${visibleSummary.attempt_count === 1 ? 'y' : 'ies'}`}
              icon={<HistoryRoundedIcon />}
              label="Governed attempts"
              value={visibleSummary.attempt_count.toLocaleString()}
            />
            <MetricCard
              detail={
                visibleSummary.holdout_state === 'sealed'
                  ? 'No reveal evidence recorded'
                  : 'Authorization trail available'
              }
              direction={visibleSummary.holdout_state === 'sealed' ? 'positive' : 'neutral'}
              icon={
                visibleSummary.holdout_state === 'sealed' ? (
                  <LockOutlinedIcon />
                ) : (
                  <AssignmentTurnedInOutlinedIcon />
                )
              }
              label="Final holdout"
              value={titleCase(visibleSummary.holdout_state)}
            />
          </Box>
          <Box sx={{ display: 'grid', gap: 2, mt: 2 }}>
            {experimentQuery.isPending ? (
              <ResearchPageSkeleton label="Loading selected experiment evidence" />
            ) : null}
            {experimentQuery.isError ? (
              <ErrorState
                message={experimentsErrorMessage(experimentQuery.error)}
                onRetry={() => {
                  void experimentQuery.refetch()
                }}
              />
            ) : null}
            {detailIdentityMismatch ? (
              <ErrorState
                message="Experiment detail identity does not match the selected governed family."
                onRetry={() => {
                  void experimentQuery.refetch()
                }}
              />
            ) : null}
            {experiment ? (
              <>
                <SummaryPins summary={experiment.summary} />
                <SegmentDeclarations segments={experiment.segments} />
                <PromotionCriteria criteria={experiment.promotion_criteria} />
                <AttemptHistory attempts={experiment.attempts} />
                <HoldoutEvidence holdout={experiment.holdout} />
                <Typography
                  color="text.secondary"
                  sx={{ fontSize: 10.5, textAlign: 'right' }}
                >
                  Experiment snapshot{' '}
                  {formatDateTime(
                    experimentQuery.data?.data.as_of ?? experiment.summary.created_at,
                  )}
                </Typography>
              </>
            ) : null}
          </Box>
        </Box>
      ) : null}
    </>
  )
}
