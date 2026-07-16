import Inventory2OutlinedIcon from '@mui/icons-material/Inventory2Outlined'
import RefreshRoundedIcon from '@mui/icons-material/RefreshRounded'
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Skeleton,
  Typography,
} from '@mui/material'
import type { ReactNode } from 'react'

export function DataPageSkeleton({ label }: { label: string }) {
  return (
    <Box aria-label={label} aria-live="polite">
      <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: 'repeat(4, minmax(0, 1fr))' }}>
        {Array.from({ length: 4 }, (_, index) => (
          <Skeleton height={112} key={index} variant="rounded" />
        ))}
      </Box>
      <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: '1.35fr 1fr', mt: 2 }}>
        <Skeleton height={300} variant="rounded" />
        <Skeleton height={300} variant="rounded" />
      </Box>
    </Box>
  )
}

interface RefreshButtonProps {
  isFetching: boolean
  onRefresh: () => void
}

export function RefreshButton({ isFetching, onRefresh }: RefreshButtonProps) {
  return (
    <Button
      disabled={isFetching}
      onClick={onRefresh}
      startIcon={isFetching ? <CircularProgress size={15} /> : <RefreshRoundedIcon />}
      variant="outlined"
    >
      Refresh
    </Button>
  )
}

interface DataSectionProps {
  title: string
  description: string
  children: ReactNode
  count?: number
  action?: ReactNode
}

export function DataSection({ title, description, children, count, action }: DataSectionProps) {
  return (
    <Card component="section" sx={{ minWidth: 0 }}>
      <CardContent sx={{ p: 0, '&:last-child': { pb: 0 } }}>
        <Box
          sx={{
            alignItems: 'flex-start',
            borderBottom: 1,
            borderColor: 'divider',
            display: 'flex',
            gap: 2,
            justifyContent: 'space-between',
            px: 2.25,
            py: 1.8,
          }}
        >
          <Box>
            <Box sx={{ alignItems: 'center', display: 'flex', gap: 1 }}>
              <Typography component="h2" variant="h2">
                {title}
              </Typography>
              {typeof count === 'number' ? (
                <Chip label={count.toLocaleString()} size="small" variant="outlined" />
              ) : null}
            </Box>
            <Typography color="text.secondary" sx={{ fontSize: 12, mt: 0.4 }}>
              {description}
            </Typography>
          </Box>
          {action}
        </Box>
        {children}
      </CardContent>
    </Card>
  )
}

export function EmptyDataState({ title, detail }: { title: string; detail: string }) {
  return (
    <Box
      sx={{
        alignItems: 'center',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        minHeight: 180,
        px: 3,
        py: 4,
        textAlign: 'center',
      }}
    >
      <Box
        aria-hidden="true"
        sx={{
          alignItems: 'center',
          bgcolor: 'rgba(147, 165, 186, 0.08)',
          borderRadius: '50%',
          color: 'text.secondary',
          display: 'flex',
          height: 44,
          justifyContent: 'center',
          width: 44,
        }}
      >
        <Inventory2OutlinedIcon fontSize="small" />
      </Box>
      <Typography component="h3" sx={{ fontSize: 14, fontWeight: 750, mt: 1.5 }}>
        {title}
      </Typography>
      <Typography color="text.secondary" sx={{ fontSize: 12, maxWidth: 440, mt: 0.5 }}>
        {detail}
      </Typography>
    </Box>
  )
}

export function MonospaceValue({ children }: { children: ReactNode }) {
  return (
    <Typography
      component="span"
      sx={{
        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
        fontSize: 11,
        overflowWrap: 'anywhere',
      }}
    >
      {children}
    </Typography>
  )
}
