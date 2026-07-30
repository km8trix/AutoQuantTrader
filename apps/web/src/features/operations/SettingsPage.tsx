import AdminPanelSettingsRoundedIcon from '@mui/icons-material/AdminPanelSettingsRounded'
import SettingsSuggestRoundedIcon from '@mui/icons-material/SettingsSuggestRounded'
import { Alert, Box, Card, CardContent, Chip, Divider, Typography } from '@mui/material'

import { formatDateTime, titleCase } from '../../api/format'
import type { UiBootstrap } from '../../api/types'
import { StatusChip } from '../../components/StatusChip'
import { OperationalControlPanel } from './OperationalControlPanel'
import {
  OperationalCounters,
  OperationalPageFrame,
  UnavailableEvidence,
} from './OperationsPageComponents'

export function SettingsPage({ bootstrap }: { bootstrap: UiBootstrap }) {
  const featureFlags = Object.entries(bootstrap.feature_flags).sort(([left], [right]) =>
    left.localeCompare(right),
  )
  const sessionFields: ReadonlyArray<readonly [string, string]> = [
    ['Environment', bootstrap.environment.name],
    ['Mode', titleCase(bootstrap.environment.mode)],
    ['Account ID', bootstrap.environment.account_id],
    ['Operator', bootstrap.user.display_name],
    ['Operator ID', bootstrap.user.id],
    ['Market clock', titleCase(bootstrap.market_clock.status)],
    ['Clock evidence', formatDateTime(bootstrap.market_clock.as_of)],
    ['Next transition', formatDateTime(bootstrap.market_clock.next_transition_at)],
  ]

  return (
    <OperationalPageFrame
      bootstrap={bootstrap}
      description="Environment identity, advertised capabilities, feature flags, market clock, session metadata, and narrowly gated fail-safe controls from the bootstrap contract."
      eyebrow="Phase 5 · Workspace"
      title="Settings"
    >
      {({ summary }) => (
        <>
          <OperationalCounters summary={summary} />
          <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: '1fr 1fr' }}>
            <Card aria-labelledby="session-settings-title" component="section">
              <CardContent sx={{ p: 2.5, '&:last-child': { pb: 2.5 } }}>
                <Box sx={{ alignItems: 'center', display: 'flex', gap: 1 }}>
                  <AdminPanelSettingsRoundedIcon
                    aria-hidden="true"
                    color="primary"
                    sx={{ fontSize: 20 }}
                  />
                  <Typography component="h2" id="session-settings-title" variant="h2">
                    Environment and session
                  </Typography>
                </Box>
                <Box
                  component="dl"
                  sx={{
                    display: 'grid',
                    gap: 1.25,
                    gridTemplateColumns: '140px minmax(0, 1fr)',
                    m: 0,
                    mt: 1.5,
                  }}
                >
                  {sessionFields.map(([label, value], index) => (
                    <Box
                      component="div"
                      key={label}
                      sx={{ display: 'contents' }}
                    >
                      {index > 0 ? (
                        <Divider sx={{ gridColumn: '1 / -1' }} />
                      ) : null}
                      <Typography
                        color="text.secondary"
                        component="dt"
                        sx={{ fontSize: 10.5, fontWeight: 700 }}
                      >
                        {label}
                      </Typography>
                      <Typography
                        component="dd"
                        sx={{
                          fontFamily: label.endsWith('ID') ? 'monospace' : 'inherit',
                          fontSize: 11.5,
                          m: 0,
                        }}
                      >
                        {value}
                      </Typography>
                    </Box>
                  ))}
                </Box>
              </CardContent>
            </Card>

            <Card aria-labelledby="capabilities-title" component="section">
              <CardContent sx={{ p: 2.5, '&:last-child': { pb: 2.5 } }}>
                <Box sx={{ alignItems: 'center', display: 'flex', gap: 1 }}>
                  <SettingsSuggestRoundedIcon
                    aria-hidden="true"
                    color="primary"
                    sx={{ fontSize: 20 }}
                  />
                  <Typography component="h2" id="capabilities-title" variant="h2">
                    Advertised capabilities
                  </Typography>
                </Box>
                {bootstrap.capabilities.length > 0 ? (
                  <Box
                    aria-label="Advertised capabilities"
                    component="ul"
                    sx={{
                      display: 'flex',
                      flexWrap: 'wrap',
                      gap: 0.75,
                      listStyle: 'none',
                      m: 0,
                      mt: 1.5,
                      p: 0,
                    }}
                  >
                    {bootstrap.capabilities.map((capability) => (
                      <Box component="li" key={capability}>
                        <Chip label={titleCase(capability)} size="small" variant="outlined" />
                      </Box>
                    ))}
                  </Box>
                ) : (
                  <Alert severity="info" sx={{ mt: 1.5 }} variant="outlined">
                    No capabilities were advertised.
                  </Alert>
                )}
                <Divider sx={{ my: 2 }} />
                <Typography component="h3" variant="h3">
                  Feature flags
                </Typography>
                {featureFlags.length > 0 ? (
                  <Box
                    aria-label="Feature flags"
                    component="ul"
                    sx={{ listStyle: 'none', m: 0, mt: 1, p: 0 }}
                  >
                    {featureFlags.map(([name, enabled]) => (
                      <Box
                        component="li"
                        key={name}
                        sx={{
                          alignItems: 'center',
                          display: 'flex',
                          justifyContent: 'space-between',
                          py: 0.65,
                        }}
                      >
                        <Typography sx={{ fontFamily: 'monospace', fontSize: 10.5 }}>
                          {name}
                        </Typography>
                        <StatusChip
                          label={enabled ? 'Enabled' : 'Disabled'}
                          status={enabled ? 'healthy' : 'unknown'}
                        />
                      </Box>
                    ))}
                  </Box>
                ) : (
                  <Alert severity="info" sx={{ mt: 1.5 }} variant="outlined">
                    No feature flags were returned.
                  </Alert>
                )}
              </CardContent>
            </Card>
          </Box>

          <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: '1fr 1fr', mt: 2 }}>
            <OperationalControlPanel bootstrap={bootstrap} />
            <UnavailableEvidence
              detail="The current contracts do not expose editable risk thresholds, policy assignments, alert destinations, broker credentials, or operator authorization settings. No local override is applied."
              title="Authoritative configuration unavailable"
            />
          </Box>
        </>
      )}
    </OperationalPageFrame>
  )
}
