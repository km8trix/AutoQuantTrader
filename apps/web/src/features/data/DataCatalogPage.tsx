import ArticleOutlinedIcon from '@mui/icons-material/ArticleOutlined'
import CorporateFareOutlinedIcon from '@mui/icons-material/CorporateFareOutlined'
import DatasetOutlinedIcon from '@mui/icons-material/DatasetOutlined'
import FactCheckOutlinedIcon from '@mui/icons-material/FactCheckOutlined'
import {
  Alert,
  Box,
  Card,
  CardContent,
  Chip,
  Divider,
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
import { useDataCatalog } from '../../api/queries'
import type { DataCatalogResponse } from '../../api/types'
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

function catalogErrorMessage(error: unknown): string {
  if (error instanceof ApiError || error instanceof Error) {
    return `The point-in-time data catalog is unavailable: ${error.message}`
  }
  return 'The point-in-time data catalog is unavailable due to an unexpected error.'
}

function CatalogSummary({ catalog }: { catalog: DataCatalogResponse }) {
  const partitions = catalog.manifests.reduce(
    (total, manifest) => total + manifest.partitions.length,
    0,
  )
  const quarantined = catalog.jobs.reduce(
    (total, job) => total + job.quarantined_record_count,
    0,
  )

  return (
    <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: 'repeat(4, minmax(0, 1fr))' }}>
      <MetricCard
        detail="Immutable ordered snapshots"
        icon={<DatasetOutlinedIcon />}
        label="Dataset manifests"
        value={catalog.manifests.length.toLocaleString()}
      />
      <MetricCard
        detail="Content-addressed Parquet objects"
        icon={<ArticleOutlinedIcon />}
        label="Published partitions"
        value={partitions.toLocaleString()}
      />
      <MetricCard
        detail="Stable identities with dated mappings"
        icon={<CorporateFareOutlinedIcon />}
        label="Tracked instruments"
        value={catalog.instruments.length.toLocaleString()}
      />
      <MetricCard
        detail={quarantined === 0 ? 'No quarantined job outputs' : 'Review Data quality'}
        direction={quarantined === 0 ? 'positive' : 'negative'}
        icon={<FactCheckOutlinedIcon />}
        label="Quarantined outputs"
        value={quarantined.toLocaleString()}
      />
    </Box>
  )
}

function IngestionJobs({ jobs }: { jobs: DataCatalogResponse['jobs'] }) {
  return (
    <DataSection
      count={jobs.length}
      description="Every attempt is retained; publication counts exclude quarantined output."
      title="Ingestion jobs"
    >
      {jobs.length === 0 ? (
        <EmptyDataState
          detail="Run the local fixture ingestion worker to create the first durable job record."
          title="No ingestion jobs"
        />
      ) : (
        <TableContainer>
          <Table aria-label="Ingestion jobs" size="small">
            <TableHead>
              <TableRow>
                <TableCell>Status</TableCell>
                <TableCell>Job</TableCell>
                <TableCell>Source</TableCell>
                <TableCell>Started</TableCell>
                <TableCell align="right">Source records</TableCell>
                <TableCell align="right">Normalized</TableCell>
                <TableCell align="right">Published</TableCell>
                <TableCell align="right">Quarantined</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {jobs.map((job) => (
                <TableRow key={job.job_id}>
                  <TableCell>
                    <StatusChip
                      label={titleCase(job.status)}
                      status={job.status}
                    />
                  </TableCell>
                  <TableCell>
                    <MonospaceValue>{job.job_id}</MonospaceValue>
                  </TableCell>
                  <TableCell>{job.source_id}</TableCell>
                  <TableCell>
                    <Typography sx={{ fontSize: 12 }}>{formatDateTime(job.started_at)}</Typography>
                    <Typography color="text.secondary" sx={{ fontSize: 10.5 }}>
                      {job.completed_at ? `Finished ${formatDateTime(job.completed_at)}` : 'In progress'}
                    </Typography>
                  </TableCell>
                  <TableCell align="right">{job.source_record_count.toLocaleString()}</TableCell>
                  <TableCell align="right">{job.normalized_record_count.toLocaleString()}</TableCell>
                  <TableCell align="right">
                    {job.published_partition_count.toLocaleString()}
                  </TableCell>
                  <TableCell align="right">
                    <Typography
                      color={job.quarantined_record_count > 0 ? 'warning.main' : 'text.primary'}
                      sx={{ fontSize: 12, fontWeight: 700 }}
                    >
                      {job.quarantined_record_count.toLocaleString()}
                    </Typography>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </DataSection>
  )
}

function DatasetManifests({ manifests }: { manifests: DataCatalogResponse['manifests'] }) {
  return (
    <DataSection
      count={manifests.length}
      description="Each manifest freezes ordered partitions and all point-in-time policy versions."
      title="Dataset manifests and partitions"
    >
      {manifests.length === 0 ? (
        <EmptyDataState
          detail="No normalized partition has passed validation and been atomically published."
          title="No published manifests"
        />
      ) : (
        <Box>
          {manifests.map((manifest, manifestIndex) => (
            <Box key={manifest.manifest_id}>
              {manifestIndex > 0 ? <Divider /> : null}
              <Box sx={{ px: 2.25, py: 2 }}>
                <Box sx={{ alignItems: 'flex-start', display: 'flex', gap: 2, justifyContent: 'space-between' }}>
                  <Box>
                    <Typography component="h3" sx={{ fontSize: 14, fontWeight: 750 }}>
                      {manifest.name}
                    </Typography>
                    <Box sx={{ alignItems: 'center', display: 'flex', flexWrap: 'wrap', gap: 0.75, mt: 0.75 }}>
                      <Chip label={manifest.revision_policy.replaceAll('_', ' ')} size="small" variant="outlined" />
                      <Chip label={`${titleCase(manifest.price_basis)} prices`} size="small" variant="outlined" />
                      <Chip label={`${manifest.row_count.toLocaleString()} rows`} size="small" variant="outlined" />
                      <Chip label={`Schema ${manifest.schema_version}`} size="small" variant="outlined" />
                    </Box>
                  </Box>
                  <Box sx={{ textAlign: 'right' }}>
                    <Typography color="text.secondary" sx={{ fontSize: 10.5 }}>
                      Published
                    </Typography>
                    <Typography sx={{ fontSize: 11.5 }}>{formatDateTime(manifest.created_at)}</Typography>
                  </Box>
                </Box>
                <Box
                  sx={{
                    bgcolor: 'rgba(147, 165, 186, 0.04)',
                    border: 1,
                    borderColor: 'divider',
                    borderRadius: 1,
                    display: 'grid',
                    gap: 1.25,
                    gridTemplateColumns: '1.3fr repeat(3, minmax(0, 0.7fr))',
                    mt: 1.5,
                    p: 1.25,
                  }}
                >
                  <Box>
                    <Typography color="text.secondary" sx={{ fontSize: 10 }}>Manifest SHA-256</Typography>
                    <MonospaceValue>{manifest.manifest_hash}</MonospaceValue>
                  </Box>
                  <Box>
                    <Typography color="text.secondary" sx={{ fontSize: 10 }}>Calendar</Typography>
                    <Typography sx={{ fontSize: 11.5 }}>{manifest.calendar_version}</Typography>
                  </Box>
                  <Box>
                    <Typography color="text.secondary" sx={{ fontSize: 10 }}>Universe</Typography>
                    <Typography sx={{ fontSize: 11.5 }}>{manifest.universe_version}</Typography>
                  </Box>
                  <Box>
                    <Typography color="text.secondary" sx={{ fontSize: 10 }}>Corporate actions</Typography>
                    <Typography sx={{ fontSize: 11.5 }}>{manifest.corporate_action_version}</Typography>
                  </Box>
                </Box>
                {manifest.partitions.length === 0 ? (
                  <Alert severity="warning" sx={{ mt: 1.5 }} variant="outlined">
                    This manifest has no ordered partitions and is not research-consumable.
                  </Alert>
                ) : (
                  <TableContainer sx={{ mt: 1.5 }}>
                    <Table aria-label={`${manifest.name} ordered partitions`} size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>#</TableCell>
                          <TableCell>Partition</TableCell>
                          <TableCell>Event-time range</TableCell>
                          <TableCell>Available-time range</TableCell>
                          <TableCell align="right">Rows</TableCell>
                          <TableCell>Quality</TableCell>
                          <TableCell>Checksum</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {manifest.partitions.map((partition) => (
                          <TableRow key={partition.partition_id}>
                            <TableCell>{partition.ordinal + 1}</TableCell>
                            <TableCell>
                              <Typography sx={{ fontSize: 11.5 }}>{partition.partition_id}</Typography>
                              <Typography color="text.secondary" sx={{ fontSize: 10, maxWidth: 260, overflowWrap: 'anywhere' }}>
                                {titleCase(partition.layer)} · {partition.object_key}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Typography sx={{ fontSize: 11 }}>{formatDateTime(partition.event_time_start)}</Typography>
                              <Typography color="text.secondary" sx={{ fontSize: 10 }}>to {formatDateTime(partition.event_time_end)}</Typography>
                            </TableCell>
                            <TableCell>
                              <Typography sx={{ fontSize: 11 }}>{formatDateTime(partition.available_at_start)}</Typography>
                              <Typography color="text.secondary" sx={{ fontSize: 10 }}>to {formatDateTime(partition.available_at_end)}</Typography>
                            </TableCell>
                            <TableCell align="right">{partition.row_count.toLocaleString()}</TableCell>
                            <TableCell>
                              <StatusChip
                                label={titleCase(partition.quality_status)}
                                status={partition.quality_status === 'passed' ? 'healthy' : partition.quality_status}
                              />
                            </TableCell>
                            <TableCell><MonospaceValue>{partition.checksum}</MonospaceValue></TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                )}
              </Box>
            </Box>
          ))}
        </Box>
      )}
    </DataSection>
  )
}

function SecurityLifecycle({ instruments }: { instruments: DataCatalogResponse['instruments'] }) {
  return (
    <DataSection
      count={instruments.length}
      description="Opaque security IDs remain stable while symbols and tradability change over time."
      title="Security lifecycle"
    >
      {instruments.length === 0 ? (
        <EmptyDataState
          detail="The current catalog does not contain any effective-dated security mappings."
          title="No security lifecycle records"
        />
      ) : (
        <TableContainer>
          <Table aria-label="Security lifecycle" size="small">
            <TableHead>
              <TableRow>
                <TableCell>Instrument</TableCell>
                <TableCell>Class</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Effective-dated mappings</TableCell>
                <TableCell>Lifecycle</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {instruments.map((instrument) => (
                <TableRow key={instrument.instrument_id}>
                  <TableCell><MonospaceValue>{instrument.instrument_id}</MonospaceValue></TableCell>
                  <TableCell>{titleCase(instrument.asset_class)}</TableCell>
                  <TableCell>
                    <StatusChip
                      label={titleCase(instrument.status)}
                      status={instrument.status === 'active' ? 'ready' : 'not_ready'}
                    />
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.8 }}>
                      {instrument.mappings.map((mapping) => (
                        <Box key={`${mapping.symbol}-${mapping.venue}-${mapping.valid_from}`}>
                          <Box sx={{ alignItems: 'center', display: 'flex', gap: 0.75 }}>
                            <Typography sx={{ fontSize: 12.5, fontWeight: 750 }}>{mapping.symbol}</Typography>
                            <Chip label={mapping.venue} size="small" variant="outlined" />
                            <StatusChip
                              label={mapping.tradable ? 'Tradable' : 'Not tradable'}
                              status={mapping.tradable ? 'ready' : 'not_ready'}
                            />
                          </Box>
                          <Typography color="text.secondary" sx={{ fontSize: 10.5, mt: 0.2 }}>
                            {formatDateTime(mapping.valid_from)} — {mapping.valid_to ? formatDateTime(mapping.valid_to) : 'present'}
                          </Typography>
                          <Typography color="text.secondary" sx={{ fontSize: 10.5 }}>
                            Known from {formatDateTime(mapping.available_at)}
                          </Typography>
                        </Box>
                      ))}
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Typography sx={{ fontSize: 11.5 }}>Listed {formatDateTime(instrument.listed_at)}</Typography>
                    <Typography color="text.secondary" sx={{ fontSize: 10.5 }}>
                      {instrument.delisted_at ? `Delisted ${formatDateTime(instrument.delisted_at)}` : 'No delisting fact'}
                    </Typography>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </DataSection>
  )
}

function CorporateActions({ actions }: { actions: DataCatalogResponse['corporate_actions'] }) {
  return (
    <DataSection
      count={actions.length}
      description="Explicit raw-price events; adjusted values remain outside execution and ledger APIs."
      title="Corporate actions"
    >
      {actions.length === 0 ? (
        <EmptyDataState
          detail="No split, dividend, merger, symbol-change, or delisting facts are in this fixture."
          title="No corporate actions"
        />
      ) : (
        <TableContainer>
          <Table aria-label="Corporate actions" size="small">
            <TableHead>
              <TableRow>
                <TableCell>Type</TableCell>
                <TableCell>Security</TableCell>
                <TableCell>Effective</TableCell>
                <TableCell>Available</TableCell>
                <TableCell>Terms</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {actions.map((action) => (
                <TableRow key={action.action_revision_id}>
                  <TableCell><Chip label={titleCase(action.action_type)} size="small" variant="outlined" /></TableCell>
                  <TableCell>
                    <Typography sx={{ fontSize: 12.5, fontWeight: 750 }}>{action.symbol}</Typography>
                    <MonospaceValue>{action.instrument_id}</MonospaceValue>
                    <Typography color="text.secondary" sx={{ fontSize: 10.5 }}>
                      {action.action_id} · revision {action.revision}
                    </Typography>
                  </TableCell>
                  <TableCell>{formatDateTime(action.effective_at)}</TableCell>
                  <TableCell>{formatDateTime(action.available_at)}</TableCell>
                  <TableCell>{action.detail}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </DataSection>
  )
}

function FeedEntitlements({ entitlements }: { entitlements: DataCatalogResponse['entitlements'] }) {
  return (
    <DataSection
      count={entitlements.length}
      description="Entitlement records describe provenance; they never contain vendor credentials."
      title="Feed entitlement"
    >
      {entitlements.length === 0 ? (
        <EmptyDataState
          detail="No source entitlement has been recorded. Treat this catalog as unqualified."
          title="No entitlement evidence"
        />
      ) : (
        <Box sx={{ display: 'grid', gap: 1.25, gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', p: 2 }}>
          {entitlements.map((entitlement) => (
            <Card key={`${entitlement.source_id}-${entitlement.feed}`} variant="outlined">
              <CardContent sx={{ p: 1.75, '&:last-child': { pb: 1.75 } }}>
                <Box sx={{ alignItems: 'flex-start', display: 'flex', gap: 1, justifyContent: 'space-between' }}>
                  <Box>
                    <Typography sx={{ fontSize: 13, fontWeight: 750 }}>{entitlement.feed}</Typography>
                    <Typography color="text.secondary" sx={{ fontSize: 10.5 }}>{entitlement.source_id}</Typography>
                  </Box>
                  <StatusChip
                    label={entitlement.licensed ? titleCase(entitlement.status) : 'Unlicensed'}
                    status={entitlement.licensed ? entitlement.status : 'not_ready'}
                  />
                </Box>
                <Typography sx={{ fontSize: 12, mt: 1.25 }}>{entitlement.scope}</Typography>
                <Typography color="text.secondary" sx={{ fontSize: 10.5, mt: 0.8 }}>
                  Verified {entitlement.verified_at ? formatDateTime(entitlement.verified_at) : 'never'}
                </Typography>
              </CardContent>
            </Card>
          ))}
        </Box>
      )}
    </DataSection>
  )
}

function VendorAdmission({ admissions }: { admissions: DataCatalogResponse['admissions'] }) {
  return (
    <DataSection
      count={admissions.length}
      description="A source is eligible only after licensed entitlement, technical evidence, and independent approval all pass."
      title="Vendor admission"
    >
      {admissions.length === 0 ? (
        <EmptyDataState
          detail="No immutable admission report exists. Paper and live data use remain blocked."
          title="No admission evidence"
        />
      ) : (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5, p: 2 }}>
          {admissions.map((admission) => (
            <Card key={admission.admission_run_id} variant="outlined">
              <CardContent sx={{ p: 1.75, '&:last-child': { pb: 1.75 } }}>
                <Box sx={{ alignItems: 'flex-start', display: 'flex', gap: 1, justifyContent: 'space-between' }}>
                  <Box>
                    <Typography sx={{ fontSize: 13, fontWeight: 750 }}>{admission.profile_name}</Typography>
                    <Typography color="text.secondary" sx={{ fontSize: 10.5 }}>
                      {admission.adapter_type} · {admission.identifier_authority}
                    </Typography>
                  </Box>
                  <StatusChip
                    label={titleCase(admission.status)}
                    status={admission.status === 'admitted' ? 'ready' : 'not_ready'}
                  />
                </Box>

                <Typography sx={{ fontSize: 12, mt: 1.25 }}>{admission.detail}</Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.75, mt: 1.25 }}>
                  <Chip color="success" label={`${admission.passed_check_count} passed`} size="small" variant="outlined" />
                  <Chip color={admission.failed_check_count > 0 ? 'error' : 'default'} label={`${admission.failed_check_count} failed`} size="small" variant="outlined" />
                  <Chip color={admission.pending_check_count > 0 ? 'warning' : 'default'} label={`${admission.pending_check_count} pending`} size="small" variant="outlined" />
                  {admission.required_symbols.map((symbol) => (
                    <Chip key={symbol} label={symbol} size="small" />
                  ))}
                </Box>

                <Box sx={{ display: 'grid', gap: 1, gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', mt: 1.5 }}>
                  <Box>
                    <Typography color="text.secondary" sx={{ fontSize: 10 }}>Executed</Typography>
                    <Typography sx={{ fontSize: 11.5 }}>{formatDateTime(admission.executed_at)}</Typography>
                    <Typography color="text.secondary" sx={{ fontSize: 10 }}>{admission.executed_by}</Typography>
                  </Box>
                  <Box>
                    <Typography color="text.secondary" sx={{ fontSize: 10 }}>Independent review</Typography>
                    <Typography sx={{ fontSize: 11.5 }}>
                      {admission.reviewed_at ? formatDateTime(admission.reviewed_at) : 'Not reviewed'}
                    </Typography>
                    <Typography color="text.secondary" sx={{ fontSize: 10 }}>
                      {admission.reviewed_by ?? 'Reviewer required'}
                    </Typography>
                  </Box>
                  <Box>
                    <Typography color="text.secondary" sx={{ fontSize: 10 }}>Frozen versions</Typography>
                    <Typography sx={{ fontSize: 10.5 }}>{admission.universe_version}</Typography>
                    <Typography sx={{ fontSize: 10.5 }}>{admission.calendar_version}</Typography>
                    <Typography sx={{ fontSize: 10.5 }}>{admission.corporate_action_version}</Typography>
                  </Box>
                </Box>

                <Divider sx={{ my: 1.5 }} />
                <TableContainer>
                  <Table aria-label={`${admission.profile_name} admission checks`} size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Check</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell>Evidence</TableCell>
                        <TableCell>Observed</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {admission.checks.map((check) => (
                        <TableRow key={check.code}>
                          <TableCell>
                            <Typography sx={{ fontSize: 11.5, fontWeight: 700 }}>{titleCase(check.code)}</Typography>
                            <Typography color="text.secondary" sx={{ fontSize: 10.5 }}>{check.detail}</Typography>
                          </TableCell>
                          <TableCell>
                            <StatusChip
                              label={titleCase(check.status)}
                              status={check.status === 'passed' ? 'ready' : check.status === 'failed' ? 'critical' : 'warning'}
                            />
                          </TableCell>
                          <TableCell>
                            {check.evidence_digest ? <MonospaceValue>{check.evidence_digest}</MonospaceValue> : 'Required'}
                          </TableCell>
                          <TableCell>{formatDateTime(check.observed_at)}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </CardContent>
            </Card>
          ))}
        </Box>
      )}
    </DataSection>
  )
}

export function DataCatalogPage() {
  const catalogQuery = useDataCatalog()
  const result = catalogQuery.data
  const catalog = result?.data
  const refresh = () => {
    void catalogQuery.refetch()
  }

  return (
    <>
      <PageHeader
        actions={<RefreshButton isFetching={catalogQuery.isFetching} onRefresh={refresh} />}
        description="Inspect immutable point-in-time datasets, ingestion evidence, security identity, corporate actions, and source entitlements."
        eyebrow="Phase 1B · Vendor admission"
        title="Datasets"
      />

      <Alert severity="warning" sx={{ mb: 2 }} variant="outlined">
        <strong>Vendor admission is fail-closed.</strong> A published manifest alone is not admitted for paper or live trading.
      </Alert>

      {result?.source === 'development-fixture' ? (
        <Alert severity="info" sx={{ mb: 2 }} variant="outlined">
          The Control API is unavailable and explicit development fixtures are active.
        </Alert>
      ) : null}

      {catalogQuery.isPending ? <DataPageSkeleton label="Loading data catalog" /> : null}
      {catalogQuery.isError ? (
        <ErrorState message={catalogErrorMessage(catalogQuery.error)} onRetry={refresh} />
      ) : null}

      {catalog ? (
        <Box aria-live="polite">
          {!catalog.admissions.some((admission) => admission.status === 'admitted') ? (
            <Alert severity="error" sx={{ mb: 2 }} variant="outlined">
              No market-data source is admitted. Licensed entitlement, complete technical evidence, and independent approval are still required.
            </Alert>
          ) : null}
          {catalog.source === null ? (
            <Alert severity="error" sx={{ mb: 2 }} variant="outlined">
              No historical data source is configured. This empty catalog is unlicensed, unqualified, and unavailable for paper or live trading.
            </Alert>
          ) : !catalog.source.licensed ? (
            <Alert severity="warning" sx={{ mb: 2 }} variant="outlined">
              Source <strong>{catalog.source.name}</strong> uses the {titleCase(catalog.source.kind)} adapter and has no licensed-feed entitlement ({titleCase(catalog.source.entitlement_status)}). {catalog.source.detail}
            </Alert>
          ) : null}

          <Box sx={{ alignItems: 'center', display: 'flex', justifyContent: 'flex-end', mb: 1.5 }}>
            <Typography color="text.secondary" sx={{ fontSize: 10.5 }}>
              Catalog snapshot {formatDateTime(catalog.as_of)}
            </Typography>
          </Box>

          <CatalogSummary catalog={catalog} />
          <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: 'minmax(0, 1.25fr) minmax(380px, 0.75fr)', mt: 2 }}>
            <IngestionJobs jobs={catalog.jobs} />
            <FeedEntitlements entitlements={catalog.entitlements} />
          </Box>
          <Box sx={{ mt: 2 }}><VendorAdmission admissions={catalog.admissions} /></Box>
          <Box sx={{ mt: 2 }}><DatasetManifests manifests={catalog.manifests} /></Box>
          <Box sx={{ mt: 2 }}><SecurityLifecycle instruments={catalog.instruments} /></Box>
          <Box sx={{ mt: 2 }}><CorporateActions actions={catalog.corporate_actions} /></Box>
        </Box>
      ) : null}
    </>
  )
}
