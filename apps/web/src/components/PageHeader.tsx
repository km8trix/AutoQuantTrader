import { Box, Typography } from '@mui/material'
import type { ReactNode } from 'react'

interface PageHeaderProps {
  title: string
  description: string
  eyebrow?: string
  actions?: ReactNode
}

export function PageHeader({ title, description, eyebrow, actions }: PageHeaderProps) {
  return (
    <Box sx={{ alignItems: 'flex-start', display: 'flex', gap: 3, justifyContent: 'space-between', mb: 3 }}>
      <Box>
        {eyebrow ? (
          <Typography color="primary.main" sx={{ fontSize: 11, fontWeight: 800, letterSpacing: '0.14em', mb: 0.75, textTransform: 'uppercase' }}>
            {eyebrow}
          </Typography>
        ) : null}
        <Typography component="h1" variant="h1">
          {title}
        </Typography>
        <Typography color="text.secondary" sx={{ mt: 0.75, maxWidth: 720 }} variant="body2">
          {description}
        </Typography>
      </Box>
      {actions ? <Box sx={{ alignItems: 'center', display: 'flex', gap: 1.5 }}>{actions}</Box> : null}
    </Box>
  )
}
