import ErrorOutlineRoundedIcon from '@mui/icons-material/ErrorOutlineRounded'
import GppGoodOutlinedIcon from '@mui/icons-material/GppGoodOutlined'
import Inventory2OutlinedIcon from '@mui/icons-material/Inventory2Outlined'
import WarningAmberRoundedIcon from '@mui/icons-material/WarningAmberRounded'
import {
  Alert,
  Box,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material'

import { ApiError } from '../../api/client'
import { formatDateTime, titleCase } from '../../api/format'
import { useDataQuality } from '../../api/queries'
import type { DataQualityResponse } from '../../api/types'
import { ErrorState } from '../../components/LoadState'
import { MetricCard } from '../../components/MetricCard'
import { PageHeader } from '../../components/PageHeader'
import { StatusChip } from '../../components/StatusChip'
import {
  DataPageSkeleton,
  DataSection,
  EmptyDataState,
  MonospaceValue,
  RefreshButton,
} from './DataPageComponents'

function qualityErrorMessage(error: unknown): string {
  if (error instanceof ApiError || error instanceof Error) {
    return `Data-quality evidence is unavailable: ${error.message}`
  }
  return 'Data-quality evidence is unavailable due to an unexpected error.'
}

function QualitySummary({ quality }: { quality: DataQualityResponse }) {
  const critical = quality.issues.filter((issue) => issue.severity === 'error').length
  const warnings = quality.issues.filter((issue) => issue.severity === 'warning').length
  const open = quality.issues.filter((issue) => issue.status === 'open').length

  return (
    <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: 'repeat(4, minmax(0, 1fr))' }}>
      <MetricCard
        detail={critical === 0 ? 'No critical findings' : 'Publication remains blocked'}
        direction={critical === 0 ? 'positive' : 'negative'}
        icon={<ErrorOutlineRoundedIcon />}
        label="Critical issues"
        value={critical.toLocaleString()}
      />
      <MetricCard
        detail="Requires operator review"
        direction={warnings === 0 ? 'positive' : 'neutral'}
        icon={<WarningAmberRoundedIcon />}
        label="Warnings"
        value={warnings.toLocaleString()}
      />
      <MetricCard
        detail="Unresolved deterministic findings"
        direction={open === 0 ? 'positive' : 'negative'}
        icon={<GppGoodOutlinedIcon />}
        label="Open issues"
        value={open.toLocaleString()}
      />
      <MetricCard
        detail="Excluded from every manifest"
        direction={quality.quarantine.length === 0 ? 'positive' : 'negative'}
        icon={<Inventory2OutlinedIcon />}
        label="Quarantined partitions"
        value={quality.quarantine.length.toLocaleString()}
      />
    </Box>
  )
}

function QualityIssues({ issues }: { issues: DataQualityResponse['issues'] }) {
  return (
    <DataSection
      count={issues.length}
      description="Deterministic findings for gaps, duplicates, prices, revisions, timezones, and sessions."
      title="Quality issues"
    >
      {issues.length === 0 ? (
        <EmptyDataState
          detail="The current fixture produced no quality findings. This does not qualify an external vendor feed."
          title="No quality issues"
        />
      ) : (
        <TableContainer>
          <Table aria-label="Data quality issues" size="small">
            <TableHead>
              <TableRow>
                <TableCell>Severity</TableCell>
                <TableCell>Check</TableCell>
                <TableCell>Finding</TableCell>
                <TableCell>Partition</TableCell>
                <TableCell>Detected</TableCell>
                <TableCell>Status</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {issues.map((issue) => (
                <TableRow key={issue.issue_id}>
                  <TableCell>
                    <StatusChip
                      status={issue.severity === 'error' ? 'critical' : issue.severity}
                    />
                  </TableCell>
                  <TableCell>
                    <Chip label={titleCase(issue.code)} size="small" variant="outlined" />
                  </TableCell>
                  <TableCell sx={{ maxWidth: 460 }}>
                    <Typography sx={{ fontSize: 12.5, fontWeight: 700 }}>{issue.summary}</Typography>
                    <Typography color="text.secondary" sx={{ fontSize: 11, mt: 0.25 }}>
                      {issue.detail}
                    </Typography>
                    {issue.quarantined ? (
                      <Typography color="warning.main" sx={{ fontSize: 10.5, fontWeight: 700, mt: 0.5 }}>
                        Output quarantined; no manifest may reference it.
                      </Typography>
                    ) : null}
                  </TableCell>
                  <TableCell>
                    {issue.partition_id ? (
                      <MonospaceValue>{issue.partition_id}</MonospaceValue>
                    ) : (
                      <Typography color="text.secondary" sx={{ fontSize: 11 }}>Job-level</Typography>
                    )}
                  </TableCell>
                  <TableCell>{formatDateTime(issue.detected_at)}</TableCell>
                  <TableCell><StatusChip label={titleCase(issue.status)} status="warning" /></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </DataSection>
  )
}

function Quarantine({ records }: { records: DataQualityResponse['quarantine'] }) {
  return (
    <DataSection
      count={records.length}
      description="Immutable objects may remain for audit, but quarantined partitions cannot be published."
      title="Quarantine"
    >
      {records.length === 0 ? (
        <EmptyDataState
          detail="No partition is currently excluded by a fatal validation finding."
          title="Quarantine is empty"
        />
      ) : (
        <TableContainer>
          <Table aria-label="Quarantined partitions" size="small">
            <TableHead>
              <TableRow>
                <TableCell>Partition</TableCell>
                <TableCell>Reason</TableCell>
                <TableCell>Quarantined</TableCell>
                <TableCell align="right">Rows isolated</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {records.map((record) => (
                <TableRow key={record.partition_id}>
                  <TableCell><MonospaceValue>{record.partition_id}</MonospaceValue></TableCell>
                  <TableCell>{record.reason}</TableCell>
                  <TableCell>{formatDateTime(record.quarantined_at)}</TableCell>
                  <TableCell align="right">{record.row_count.toLocaleString()}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </DataSection>
  )
}

export function DataQualityPage() {
  const qualityQuery = useDataQuality()
  const result = qualityQuery.data
  const quality = result?.data
  const refresh = () => {
    void qualityQuery.refetch()
  }

  return (
    <>
      <PageHeader
        actions={<RefreshButton isFetching={qualityQuery.isFetching} onRefresh={refresh} />}
        description="Review deterministic validation findings and every partition blocked from point-in-time publication."
        eyebrow="Phase 1A · Data plane"
        title="Data quality"
      />

      <Alert severity="warning" sx={{ mb: 2 }} variant="outlined">
        <strong>Synthetic fixture evidence only.</strong> Passing these checks does not qualify a licensed vendor feed or authorize trading.
      </Alert>

      {result?.source === 'development-fixture' ? (
        <Alert severity="info" sx={{ mb: 2 }} variant="outlined">
          The Control API is unavailable and explicit development fixtures are active.
        </Alert>
      ) : null}

      {qualityQuery.isPending ? <DataPageSkeleton label="Loading data quality evidence" /> : null}
      {qualityQuery.isError ? (
        <ErrorState message={qualityErrorMessage(qualityQuery.error)} onRetry={refresh} />
      ) : null}

      {quality ? (
        <Box aria-live="polite">
          {quality.quarantine.length > 0 ? (
            <Alert aria-live="assertive" severity="error" sx={{ mb: 2 }} variant="outlined">
              {quality.quarantine.length} partition{quality.quarantine.length === 1 ? ' is' : 's are'} quarantined and excluded from dataset manifests.
            </Alert>
          ) : null}
          <Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 1.5 }}>
            <Typography color="text.secondary" sx={{ fontSize: 10.5 }}>
              Quality snapshot {formatDateTime(quality.as_of)}
            </Typography>
          </Box>
          <QualitySummary quality={quality} />
          <Box sx={{ mt: 2 }}><QualityIssues issues={quality.issues} /></Box>
          <Box sx={{ mt: 2 }}><Quarantine records={quality.quarantine} /></Box>
        </Box>
      ) : null}
    </>
  )
}
