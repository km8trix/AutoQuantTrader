import BalanceRoundedIcon from '@mui/icons-material/BalanceRounded'
import PolicyRoundedIcon from '@mui/icons-material/PolicyRounded'
import { Box, Card, CardContent, Divider, Typography } from '@mui/material'

import { formatCurrency } from '../../api/format'
import type { UiBootstrap } from '../../api/types'
import { StatusChip } from '../../components/StatusChip'
import { OperationalControlPanel } from './OperationalControlPanel'
import {
  HealthEvidenceList,
  OperationalCounters,
  OperationalPageFrame,
} from './OperationsPageComponents'

const riskEvidence = [
  ['Loss', 'Session loss observations and approved loss thresholds are not exposed.'],
  ['Drawdown', 'Peak equity, current drawdown, and threshold evidence are not exposed.'],
  ['Concentration', 'Per-instrument concentration observations are not exposed.'],
  ['Leverage', 'Gross and absolute-net leverage decisions are not exposed.'],
  ['Volatility', 'Return-window volatility observations are not exposed.'],
  ['Spread / slippage', 'SIP spread and realized or projected cost evidence are not exposed.'],
  ['Reject rate', 'Rolling and consecutive rejection evidence is not exposed.'],
] as const

export function RiskPage({ bootstrap }: { bootstrap: UiBootstrap }) {
  return (
    <OperationalPageFrame
      bootstrap={bootstrap}
      description="Risk posture from the current account summary and readiness envelope, with narrowly gated fail-safe PAUSE/HALT controls. Missing policy evidence is shown as unavailable instead of inferred."
      eyebrow="Phase 5 · Risk"
      title="Risk"
    >
      {({ summary }) => {
        const riskChecks = summary.health.filter((check) =>
          `${check.id} ${check.label}`.toLowerCase().includes('risk'),
        )

        return (
          <>
            <OperationalCounters summary={summary} />
            <Box
              sx={{
                display: 'grid',
                gap: 2,
                gridTemplateColumns: 'minmax(0, 1fr) minmax(360px, 0.85fr)',
              }}
            >
              <Card aria-labelledby="exposure-snapshot-title" component="section">
                <CardContent sx={{ p: 2.5, '&:last-child': { pb: 2.5 } }}>
                  <Box sx={{ alignItems: 'center', display: 'flex', gap: 1 }}>
                    <BalanceRoundedIcon
                      aria-hidden="true"
                      color="primary"
                      sx={{ fontSize: 20 }}
                    />
                    <Typography component="h2" id="exposure-snapshot-title" variant="h2">
                      Account exposure snapshot
                    </Typography>
                  </Box>
                  <Typography color="text.secondary" sx={{ fontSize: 11.5, mt: 1 }}>
                    Values are copied from DashboardSummary. They are not a pre-trade
                    decision or a policy-utilization calculation.
                  </Typography>
                  <Box
                    component="dl"
                    sx={{
                      display: 'grid',
                      gap: 2,
                      gridTemplateColumns: 'repeat(3, minmax(0, 1fr))',
                      m: 0,
                      mt: 2,
                    }}
                  >
                    {[
                      ['Equity', formatCurrency(summary.account.equity, summary.account.currency)],
                      [
                        'Gross exposure',
                        formatCurrency(
                          summary.account.gross_exposure,
                          summary.account.currency,
                        ),
                      ],
                      [
                        'Net exposure',
                        formatCurrency(
                          summary.account.net_exposure,
                          summary.account.currency,
                        ),
                      ],
                    ].map(([label, value]) => (
                      <Box key={label}>
                        <Typography
                          color="text.secondary"
                          component="dt"
                          sx={{ fontSize: 10.5, fontWeight: 700 }}
                        >
                          {label}
                        </Typography>
                        <Typography
                          component="dd"
                          sx={{ fontSize: 16, fontWeight: 750, m: 0, mt: 0.5 }}
                        >
                          {value}
                        </Typography>
                      </Box>
                    ))}
                  </Box>
                </CardContent>
              </Card>
              <OperationalControlPanel bootstrap={bootstrap} />
            </Box>

            <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: '1fr 1fr', mt: 2 }}>
              <HealthEvidenceList
                checks={riskChecks}
                emptyMessage="No risk-engine health check is present in the dashboard summary."
                title="Reported risk health"
              />
              <Card aria-labelledby="risk-policy-evidence-title" component="section">
                <CardContent sx={{ p: 2.5, '&:last-child': { pb: 2.5 } }}>
                  <Box sx={{ alignItems: 'center', display: 'flex', gap: 1 }}>
                    <PolicyRoundedIcon
                      aria-hidden="true"
                      color="primary"
                      sx={{ fontSize: 20 }}
                    />
                    <Typography component="h2" id="risk-policy-evidence-title" variant="h2">
                      Risk policy evidence
                    </Typography>
                  </Box>
                  <Box component="ul" sx={{ listStyle: 'none', m: 0, mt: 1.25, p: 0 }}>
                    {riskEvidence.map(([label, detail], index) => (
                      <Box component="li" key={label}>
                        {index > 0 ? <Divider /> : null}
                        <Box
                          sx={{
                            alignItems: 'flex-start',
                            display: 'grid',
                            gap: 1,
                            gridTemplateColumns: '130px minmax(0, 1fr) auto',
                            py: 1,
                          }}
                        >
                          <Typography sx={{ fontSize: 11.5, fontWeight: 700 }}>
                            {label}
                          </Typography>
                          <Typography color="text.secondary" sx={{ fontSize: 10.5 }}>
                            {detail}
                          </Typography>
                          <StatusChip label="Not exposed" status="unknown" />
                        </Box>
                      </Box>
                    ))}
                  </Box>
                </CardContent>
              </Card>
            </Box>
          </>
        )
      }}
    </OperationalPageFrame>
  )
}
