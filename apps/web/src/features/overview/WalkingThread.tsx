import CheckCircleRoundedIcon from '@mui/icons-material/CheckCircleRounded'
import ErrorRoundedIcon from '@mui/icons-material/ErrorRounded'
import HourglassTopRoundedIcon from '@mui/icons-material/HourglassTopRounded'
import { Box, Card, CardContent, Chip, Typography } from '@mui/material'

import { formatRelativeTime, titleCase } from '../../api/format'
import type { TraceStatus, WalkingThreadStep } from '../../api/types'

function iconForStatus(status: TraceStatus) {
  if (status === 'completed') {
    return <CheckCircleRoundedIcon aria-hidden="true" color="success" />
  }
  if (status === 'failed') {
    return <ErrorRoundedIcon aria-hidden="true" color="error" />
  }
  return <HourglassTopRoundedIcon aria-hidden="true" color="warning" />
}

interface WalkingThreadProps {
  steps: WalkingThreadStep[]
}

export function WalkingThread({ steps }: WalkingThreadProps) {
  return (
    <Card component="section" aria-labelledby="walking-thread-title">
      <CardContent sx={{ p: 2.5, '&:last-child': { pb: 2.5 } }}>
        <Box sx={{ alignItems: 'flex-start', display: 'flex', justifyContent: 'space-between', mb: 2.25 }}>
          <Box>
            <Typography component="h2" id="walking-thread-title" variant="h2">
              Canonical walking thread
            </Typography>
            <Typography color="text.secondary" sx={{ mt: 0.5 }} variant="body2">
              One event traced through strategy, risk, execution, accounting, and projection.
            </Typography>
          </Box>
          <Chip label={`${steps.filter((step) => step.status === 'completed').length}/${steps.length} complete`} size="small" variant="outlined" />
        </Box>
        {steps.length === 0 ? (
          <Typography color="text.secondary" sx={{ py: 4, textAlign: 'center' }} variant="body2">
            No walking-thread trace is available.
          </Typography>
        ) : (
          <Box
            component="ol"
            sx={{
              display: 'grid',
              gap: 1,
              gridTemplateColumns: `repeat(${Math.min(steps.length, 7)}, minmax(0, 1fr))`,
              listStyle: 'none',
              m: 0,
              p: 0,
            }}
          >
            {steps.map((step, index) => (
              <Box
                component="li"
                key={step.id}
                sx={{
                  bgcolor: 'rgba(147, 165, 186, 0.045)',
                  border: 1,
                  borderColor: step.status === 'failed' ? 'error.main' : 'divider',
                  borderRadius: 1.5,
                  minHeight: 158,
                  p: 1.5,
                  position: 'relative',
                  '&::after':
                    index < steps.length - 1
                      ? {
                          bgcolor: step.status === 'completed' ? 'success.main' : 'divider',
                          content: '""',
                          height: 2,
                          position: 'absolute',
                          right: -10,
                          top: 27,
                          width: 10,
                          zIndex: 1,
                        }
                      : undefined,
                }}
              >
                <Box sx={{ alignItems: 'center', display: 'flex', justifyContent: 'space-between' }}>
                  {iconForStatus(step.status)}
                  <Typography color="text.secondary" sx={{ fontSize: 10, fontWeight: 800, letterSpacing: '0.08em' }}>
                    {String(index + 1).padStart(2, '0')}
                  </Typography>
                </Box>
                <Typography color="primary.main" sx={{ fontSize: 10, fontWeight: 800, letterSpacing: '0.08em', mt: 1.25, textTransform: 'uppercase' }}>
                  {titleCase(step.stage)}
                </Typography>
                <Typography sx={{ fontSize: 12, fontWeight: 700, lineHeight: 1.3, mt: 0.45 }}>
                  {step.title}
                </Typography>
                <Typography color="text.secondary" sx={{ fontSize: 10.5, lineHeight: 1.4, mt: 0.6 }}>
                  {step.detail}
                </Typography>
                <Typography color="text.secondary" sx={{ bottom: 10, fontSize: 10, position: 'absolute' }}>
                  {formatRelativeTime(step.occurred_at)}
                </Typography>
              </Box>
            ))}
          </Box>
        )}
      </CardContent>
    </Card>
  )
}
