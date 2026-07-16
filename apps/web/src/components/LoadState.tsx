import RefreshRoundedIcon from '@mui/icons-material/RefreshRounded'
import { Alert, Box, Button, Skeleton } from '@mui/material'

export function OverviewSkeleton() {
  return (
    <Box aria-label="Loading dashboard" aria-live="polite">
      <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: 'repeat(4, minmax(0, 1fr))' }}>
        {Array.from({ length: 4 }, (_, index) => (
          <Skeleton height={140} key={index} variant="rounded" />
        ))}
      </Box>
      <Skeleton height={260} sx={{ mt: 2 }} variant="rounded" />
    </Box>
  )
}

interface ErrorStateProps {
  message: string
  onRetry: () => void
}

export function ErrorState({ message, onRetry }: ErrorStateProps) {
  return (
    <Alert
      action={
        <Button color="inherit" onClick={onRetry} size="small" startIcon={<RefreshRoundedIcon />}>
          Retry
        </Button>
      }
      severity="error"
      variant="outlined"
    >
      {message}
    </Alert>
  )
}
