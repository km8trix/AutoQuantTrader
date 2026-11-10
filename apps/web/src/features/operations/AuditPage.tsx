import FingerprintRoundedIcon from '@mui/icons-material/FingerprintRounded'
import HistoryRoundedIcon from '@mui/icons-material/HistoryRounded'
import { Alert, Box, Card, CardContent, Divider, Typography } from '@mui/material'

import { formatDateTime } from '../../api/format'
import type { UiBootstrap } from '../../api/types'
import { StatusChip } from '../../components/StatusChip'
import {
  OperationalCounters,
  OperationalPageFrame,
  UnavailableEvidence,
} from './OperationsPageComponents'

export function AuditPage({ bootstrap }: { bootstrap: UiBootstrap }) {
  return (
    <OperationalPageFrame
      bootstrap={bootstrap}
      description="Read-only identity and causal evidence from current UI contracts. The dashboard trace is clearly separated from an immutable operator audit history."
      eyebrow="Phase 5 · Operations"
      title="Audit log"
    >
      {({ summary }) => (
        <>
          <OperationalCounters summary={summary} />
          <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: '0.8fr 1.2fr' }}>
            <Box sx={{ display: 'grid', gap: 2 }}>
              <Card aria-labelledby="operator-identity-title" component="section">
                <CardContent sx={{ p: 2.5, '&:last-child': { pb: 2.5 } }}>
                  <Box sx={{ alignItems: 'center', display: 'flex', gap: 1 }}>
                    <FingerprintRoundedIcon
                      aria-hidden="true"
                      color="primary"
                      sx={{ fontSize: 20 }}
                    />
                    <Typography component="h2" id="operator-identity-title" variant="h2">
                      Current operator identity
                    </Typography>
                  </Box>
                  <Typography sx={{ fontSize: 14, fontWeight: 750, mt: 1.5 }}>
                    {bootstrap.user.display_name}
                  </Typography>
                  <Typography
                    color="text.secondary"
                    sx={{ fontFamily: 'monospace', fontSize: 10.5, mt: 0.35 }}
                  >
                    {bootstrap.user.id}
                  </Typography>
                  <Alert severity="info" sx={{ mt: 1.5 }} variant="outlined">
                    This is session identity only. It does not prove who initiated any
                    historical action.
                  </Alert>
                </CardContent>
              </Card>
              <UnavailableEvidence
                detail="UiBootstrap and DashboardSummary do not expose authenticated operator actions, idempotency records, control transitions, policy-assignment history, or immutable incident receipts."
                title="Authoritative audit history unavailable"
              />
            </Box>

            <Card aria-labelledby="causal-trace-title" component="section">
              <CardContent sx={{ p: 2.5, '&:last-child': { pb: 2.5 } }}>
                <Box sx={{ alignItems: 'center', display: 'flex', gap: 1 }}>
                  <HistoryRoundedIcon
                    aria-hidden="true"
                    color="primary"
                    sx={{ fontSize: 20 }}
                  />
                  <Typography component="h2" id="causal-trace-title" variant="h2">
                    Recent causal trace — not audit history
                  </Typography>
                </Box>
                <Typography color="text.secondary" sx={{ fontSize: 11.5, mt: 1 }}>
                  These dashboard trace steps describe system processing only. They do
                  not carry operator authentication or immutable audit provenance.
                </Typography>
                {summary.trace.length > 0 ? (
                  <Box component="ol" sx={{ listStyle: 'none', m: 0, mt: 1.25, p: 0 }}>
                    {summary.trace.map((step, index) => (
                      <Box component="li" key={step.id}>
                        {index > 0 ? <Divider /> : null}
                        <Box
                          sx={{
                            alignItems: 'flex-start',
                            display: 'grid',
                            gap: 1,
                            gridTemplateColumns: 'minmax(0, 1fr) auto',
                            py: 1.15,
                          }}
                        >
                          <Box>
                            <Typography sx={{ fontSize: 12, fontWeight: 700 }}>
                              {step.title}
                            </Typography>
                            <Typography color="text.secondary" sx={{ fontSize: 10.5, mt: 0.25 }}>
                              {step.detail}
                            </Typography>
                            <Typography color="text.secondary" sx={{ fontSize: 9.5, mt: 0.4 }}>
                              {formatDateTime(step.occurred_at)}
                            </Typography>
                          </Box>
                          <StatusChip status={step.status} />
                        </Box>
                      </Box>
                    ))}
                  </Box>
                ) : (
                  <Alert severity="info" sx={{ mt: 1.5 }} variant="outlined">
                    No causal trace steps are present in the dashboard summary.
                  </Alert>
                )}
              </CardContent>
            </Card>
          </Box>
        </>
      )}
    </OperationalPageFrame>
  )
}
