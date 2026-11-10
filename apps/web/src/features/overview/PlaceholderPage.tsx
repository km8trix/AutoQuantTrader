import ConstructionRoundedIcon from '@mui/icons-material/ConstructionRounded'
import { Box, Card, CardContent, Typography } from '@mui/material'

import { PageHeader } from '../../components/PageHeader'

interface PlaceholderPageProps {
  title: string
  description: string
  phase: string
}

export function PlaceholderPage({ title, description, phase }: PlaceholderPageProps) {
  return (
    <>
      <PageHeader description={description} eyebrow={phase} title={title} />
      <Card>
        <CardContent sx={{ alignItems: 'center', display: 'flex', flexDirection: 'column', minHeight: 280, justifyContent: 'center', textAlign: 'center' }}>
          <Box sx={{ alignItems: 'center', bgcolor: 'rgba(83, 213, 232, 0.09)', borderRadius: '50%', color: 'primary.main', display: 'flex', height: 56, justifyContent: 'center', width: 56 }}>
            <ConstructionRoundedIcon aria-hidden="true" />
          </Box>
          <Typography component="h2" sx={{ fontSize: 17, fontWeight: 750, mt: 2 }}>
            Workspace route reserved
          </Typography>
          <Typography color="text.secondary" sx={{ maxWidth: 500, mt: 0.75 }} variant="body2">
            This route is part of the approved browser information architecture and will be enabled when its domain workflow is implemented.
          </Typography>
        </CardContent>
      </Card>
    </>
  )
}
