import { Box, Skeleton } from '@mui/material'

import { ApiError } from '../api/client'
import { useBootstrap } from '../api/queries'
import { useUiEventStream } from '../api/useUiEventStream'
import { ErrorState } from '../components/LoadState'
import { PageHeader } from '../components/PageHeader'
import { AppRoutes } from './AppRoutes'
import { AppShell } from './AppShell'

function bootstrapErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    return `The control API could not establish environment identity: ${error.message}`
  }
  if (error instanceof Error) {
    return `The control API could not establish environment identity: ${error.message}`
  }
  return 'The control API could not establish environment identity.'
}

export function WorkspaceApp() {
  const bootstrapQuery = useBootstrap()
  const bootstrap = bootstrapQuery.data?.data
  const eventStreamState = useUiEventStream({
    enabled: bootstrap?.feature_flags.event_stream === true,
    initialCursor: bootstrap?.stream_cursor ?? null,
  })

  const retry = () => {
    void bootstrapQuery.refetch()
  }

  return (
    <AppShell
      bootstrap={bootstrap}
      bootstrapUnavailable={bootstrapQuery.isError}
      eventStreamState={eventStreamState}
    >
      {bootstrapQuery.isPending ? (
        <Box aria-label="Loading workspace" aria-live="polite">
          <PageHeader
            description="Establishing environment identity and authoritative readiness before operational data is shown."
            eyebrow="Connecting"
            title="Loading workspace"
          />
          <Skeleton height={142} variant="rounded" />
          <Skeleton height={320} sx={{ mt: 2 }} variant="rounded" />
        </Box>
      ) : null}
      {bootstrapQuery.isError ? (
        <>
          <PageHeader
            description="Trading controls remain unavailable until the control API provides environment identity and readiness."
            eyebrow="Safe state"
            title="Workspace unavailable"
          />
          <ErrorState message={bootstrapErrorMessage(bootstrapQuery.error)} onRetry={retry} />
        </>
      ) : null}
      {bootstrap ? <AppRoutes bootstrap={bootstrap} /> : null}
    </AppShell>
  )
}
