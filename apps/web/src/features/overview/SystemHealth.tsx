import SensorsRoundedIcon from '@mui/icons-material/SensorsRounded'
import { Box, Card, CardContent, Typography } from '@mui/material'

import { formatRelativeTime } from '../../api/format'
import type { HealthCheck } from '../../api/types'
import { StatusChip } from '../../components/StatusChip'

interface SystemHealthProps {
  checks: HealthCheck[]
}

export function SystemHealth({ checks }: SystemHealthProps) {
  return (
    <Card component="section" aria-labelledby="system-health-title" sx={{ height: '100%' }}>
      <CardContent sx={{ p: 2.5, '&:last-child': { pb: 2.5 } }}>
        <Box sx={{ alignItems: 'center', display: 'flex', gap: 1, mb: 2 }}>
          <SensorsRoundedIcon aria-hidden="true" color="primary" sx={{ fontSize: 20 }} />
          <Typography component="h2" id="system-health-title" variant="h2">
            System health
          </Typography>
        </Box>
        <Box component="ul" sx={{ display: 'grid', gap: 0, listStyle: 'none', m: 0, p: 0 }}>
          {checks.map((check) => (
            <Box
              component="li"
              key={check.id}
              sx={{
                alignItems: 'center',
                borderTop: 1,
                borderColor: 'divider',
                display: 'grid',
                gap: 1,
                gridTemplateColumns: 'minmax(110px, 1fr) auto',
                py: 1.45,
                '&:first-of-type': { borderTop: 0, pt: 0.5 },
              }}
            >
              <Box>
                <Typography sx={{ fontSize: 12.5, fontWeight: 700 }}>{check.label}</Typography>
                <Typography color="text.secondary" sx={{ fontSize: 10.5, mt: 0.3 }}>
                  {check.detail}
                </Typography>
              </Box>
              <Box sx={{ textAlign: 'right' }}>
                <StatusChip status={check.status} />
                <Typography color="text.secondary" sx={{ fontSize: 9.5, mt: 0.45 }}>
                  {formatRelativeTime(check.as_of)}
                </Typography>
              </Box>
            </Box>
          ))}
        </Box>
      </CardContent>
    </Card>
  )
}
