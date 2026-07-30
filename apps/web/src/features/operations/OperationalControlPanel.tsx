import PauseCircleOutlineRoundedIcon from '@mui/icons-material/PauseCircleOutlineRounded'
import ReportRoundedIcon from '@mui/icons-material/ReportRounded'
import SecurityRoundedIcon from '@mui/icons-material/SecurityRounded'
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  TextField,
  Typography,
} from '@mui/material'
import { useMutation } from '@tanstack/react-query'
import { useState } from 'react'

import { ApiError } from '../../api/client'
import { titleCase } from '../../api/format'
import type { UiBootstrap } from '../../api/types'
import { StatusChip } from '../../components/StatusChip'
import {
  executeOperationalControl,
  isAmbiguousOperationalControlError,
  type OperationalControlIntent,
  type SafeOperationalControlAction,
  useOperationsOverview,
} from './api'

const MAX_REASON_LENGTH = 128
const CSRF_HEADER = 'x-csrf-token'
const IDEMPOTENCY_HEADER = 'idempotency-key'

interface RetainedControlIntent {
  accountId: string
  action: SafeOperationalControlAction
  idempotencyKey: string
  reasonCode: string
}

interface ControlConfirmation {
  accountId: string
  action: SafeOperationalControlAction
  reasonCode: string
}

function actionLabel(action: SafeOperationalControlAction): string {
  return action === 'pause' ? 'Pause' : 'Halt'
}

function controlReasonError(reason: string): string | null {
  if (!reason) return 'Enter an operator reason.'
  if (reason !== reason.trim()) return 'Remove leading or trailing whitespace.'
  if (reason.length > MAX_REASON_LENGTH) {
    return `Use ${MAX_REASON_LENGTH} characters or fewer.`
  }
  if ([...reason].some((character) => {
    const code = character.charCodeAt(0)
    return code < 32 || code === 127
  })) {
    return 'Use visible text without control characters.'
  }
  return null
}

function newIdempotencyKey(action: SafeOperationalControlAction): string {
  return `operations-${action}-${globalThis.crypto.randomUUID()}`
}

function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message
  if (error instanceof Error) return error.message
  return 'The operational control request failed unexpectedly.'
}

export function OperationalControlPanel({
  bootstrap,
}: {
  bootstrap: UiBootstrap
}) {
  const launchConfig = bootstrap.backtest_launch
  const csrfToken = launchConfig?.csrf_token
  const headerContractSupported =
    launchConfig !== null &&
    launchConfig.csrf_header.toLowerCase() === CSRF_HEADER &&
    launchConfig.idempotency_header.toLowerCase() === IDEMPOTENCY_HEADER
  const controlServiceAdvertised =
    bootstrap.feature_flags.operations_control === true
  const pauseAdvertised =
    controlServiceAdvertised && bootstrap.feature_flags.control_pause === true
  const haltAdvertised =
    controlServiceAdvertised && bootstrap.feature_flags.control_halt === true
  const credentialsAvailable =
    launchConfig?.enabled === true &&
    headerContractSupported &&
    typeof csrfToken === 'string' &&
    csrfToken.length > 0
  const overviewQuery = useOperationsOverview({
    accountId: bootstrap.environment.account_id,
    csrfHeader: launchConfig?.csrf_header,
    csrfToken,
    enabled:
      credentialsAvailable &&
      (bootstrap.feature_flags.operations_query === true ||
        pauseAdvertised ||
        haltAdvertised),
  })
  const mutation = useMutation({
    mutationFn: ({
      accountId: targetAccountId,
      intent,
    }: {
      accountId: string
      intent: OperationalControlIntent
    }) => executeOperationalControl(targetAccountId, intent),
    retry: false,
  })

  const [reason, setReason] = useState('')
  const [confirmation, setConfirmation] = useState<ControlConfirmation | null>(
    null,
  )
  const [haltConfirmation, setHaltConfirmation] = useState('')
  const [retainedIntents, setRetainedIntents] = useState<
    ReadonlyMap<string, RetainedControlIntent>
  >(() => new Map())
  const [failure, setFailure] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  const accountId = bootstrap.environment.account_id
  const retainedIntent = retainedIntents.get(accountId) ?? null
  const retainedForOtherAccounts = [...retainedIntents.values()].filter(
    (intent) => intent.accountId !== accountId,
  )
  const reasonError = controlReasonError(reason)
  const busy = mutation.isPending
  const commandsAvailable =
    bootstrap.environment.mode === 'local' && credentialsAvailable
  const currentState = overviewQuery.data?.control?.effective_state

  const actionAvailable = (action: SafeOperationalControlAction): boolean =>
    commandsAvailable &&
    (action === 'pause' ? pauseAdvertised : haltAdvertised)

  const beginConfirmation = (action: SafeOperationalControlAction) => {
    if (
      !actionAvailable(action) ||
      reasonError !== null ||
      busy ||
      retainedIntent !== null
    ) {
      return
    }
    setFailure(null)
    setSuccess(null)
    setHaltConfirmation('')
    setConfirmation({
      accountId,
      action,
      reasonCode: reason,
    })
  }

  const submit = async (intent: RetainedControlIntent) => {
    if (
      !credentialsAvailable ||
      !launchConfig ||
      !csrfToken ||
      intent.accountId !== accountId ||
      !actionAvailable(intent.action)
    ) {
      return
    }
    setFailure(null)
    setSuccess(null)
    try {
      const response = await mutation.mutateAsync({
        accountId: intent.accountId,
        intent: {
          action: intent.action,
          credentials: {
            csrfHeader: launchConfig.csrf_header,
            csrfToken,
            idempotencyHeader: launchConfig.idempotency_header,
            idempotencyKey: intent.idempotencyKey,
          },
          reasonCode: intent.reasonCode,
        },
      })
      setRetainedIntents((current) => {
        const next = new Map(current)
        next.delete(intent.accountId)
        return next
      })
      setReason('')
      setSuccess(
        `${actionLabel(intent.action)} confirmed at control sequence ${response.control.sequence_number}.`,
      )
      void overviewQuery.refetch()
    } catch (error) {
      if (isAmbiguousOperationalControlError(error)) {
        setRetainedIntents((current) =>
          new Map(current).set(intent.accountId, intent),
        )
        setFailure(
          `${errorMessage(error)} The outcome is ambiguous; retry this exact intent to reuse its idempotency key.`,
        )
      } else {
        setRetainedIntents((current) => {
          const next = new Map(current)
          next.delete(intent.accountId)
          return next
        })
        setFailure(errorMessage(error))
      }
    }
  }

  const confirm = () => {
    const pendingConfirmation = confirmation
    const action = pendingConfirmation?.action
    if (
      pendingConfirmation === null ||
      action === undefined ||
      pendingConfirmation.accountId !== accountId ||
      !actionAvailable(action) ||
      controlReasonError(pendingConfirmation.reasonCode) !== null ||
      (action === 'halt' && haltConfirmation !== 'HALT')
    ) {
      return
    }
    const intent: RetainedControlIntent = {
      accountId: pendingConfirmation.accountId,
      action,
      idempotencyKey: newIdempotencyKey(action),
      reasonCode: pendingConfirmation.reasonCode,
    }
    setConfirmation(null)
    setHaltConfirmation('')
    setRetainedIntents((current) =>
      new Map(current).set(intent.accountId, intent),
    )
    void submit(intent)
  }

  const retryRetainedIntent = () => {
    if (
      retainedIntent !== null &&
      !busy &&
      actionAvailable(retainedIntent.action)
    ) {
      void submit(retainedIntent)
    }
  }

  const status = !controlServiceAdvertised
    ? { label: 'Not advertised', status: 'unknown' }
    : !credentialsAvailable
      ? { label: 'Session unavailable', status: 'not_ready' }
      : { label: 'Fail-safe controls', status: 'warning' }

  return (
    <>
      <Card aria-labelledby="operational-control-title" component="section">
        <CardContent sx={{ p: 2.5, '&:last-child': { pb: 2.5 } }}>
          <Box sx={{ alignItems: 'center', display: 'flex', gap: 1 }}>
            <SecurityRoundedIcon aria-hidden="true" color="primary" sx={{ fontSize: 20 }} />
            <Typography component="h2" id="operational-control-title" variant="h2">
              Operational controls
            </Typography>
            <Box sx={{ flex: 1 }} />
            <StatusChip label={status.label} status={status.status} />
          </Box>

          <Typography color="text.secondary" sx={{ fontSize: 11.5, mt: 1.25 }}>
            PAUSE and HALT are fail-safe actions. Stale or not-ready evidence does not
            disable an advertised command; the durable server remains authoritative.
          </Typography>
          {currentState ? (
            <Typography sx={{ fontSize: 11.5, fontWeight: 700, mt: 1 }}>
              Authoritative control state: {titleCase(currentState)}
            </Typography>
          ) : null}
          {overviewQuery.isError ? (
            <Alert severity="warning" sx={{ mt: 1.5 }} variant="outlined">
              The authoritative overview is unavailable. Advertised PAUSE and HALT
              remain available as fail-safe actions.
            </Alert>
          ) : null}
          {!controlServiceAdvertised ? (
            <Alert severity="info" sx={{ mt: 1.5 }} variant="outlined">
              The bootstrap response does not advertise operational controls.
            </Alert>
          ) : null}
          {controlServiceAdvertised && !credentialsAvailable ? (
            <Alert severity="error" sx={{ mt: 1.5 }} variant="outlined">
              A supported CSRF and idempotency header contract is required before any
              command can be sent.
            </Alert>
          ) : null}
          {failure ? (
            <Alert aria-live="assertive" severity="error" sx={{ mt: 1.5 }}>
              {failure}
            </Alert>
          ) : null}
          {retainedForOtherAccounts.length > 0 ? (
            <Alert severity="warning" sx={{ mt: 1.5 }} variant="outlined">
              {retainedForOtherAccounts.length} ambiguous control intent(s) remain
              bound to another account. They cannot be retried against{' '}
              <Box component="span" sx={{ fontFamily: 'monospace' }}>
                {accountId}
              </Box>
              .
            </Alert>
          ) : null}
          {success ? (
            <Alert aria-live="polite" severity="success" sx={{ mt: 1.5 }}>
              {success}
            </Alert>
          ) : null}

          <TextField
            disabled={busy || retainedIntent !== null}
            error={reason.length > 0 && reasonError !== null}
            fullWidth
            helperText={
              reason.length > 0 && reasonError !== null
                ? reasonError
                : `${reason.length}/${MAX_REASON_LENGTH} visible characters`
            }
            inputProps={{ maxLength: MAX_REASON_LENGTH }}
            label="Operator reason"
            margin="normal"
            onChange={(event) => setReason(event.target.value)}
            value={reason}
          />

          <Box
            aria-label="Operational controls"
            role="group"
            sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 1 }}
          >
            <Button
              disabled={
                !actionAvailable('pause') ||
                reasonError !== null ||
                busy ||
                retainedIntent !== null
              }
              onClick={() => beginConfirmation('pause')}
              startIcon={<PauseCircleOutlineRoundedIcon />}
              variant="outlined"
            >
              Pause
            </Button>
            <Button
              color="error"
              disabled={
                !actionAvailable('halt') ||
                reasonError !== null ||
                busy ||
                retainedIntent !== null
              }
              onClick={() => beginConfirmation('halt')}
              startIcon={<ReportRoundedIcon />}
              variant="contained"
            >
              Halt
            </Button>
            {retainedIntent ? (
              <Button
                color="warning"
                disabled={busy || !actionAvailable(retainedIntent.action)}
                onClick={retryRetainedIntent}
                variant="contained"
              >
                {busy
                  ? 'Retrying…'
                  : `Retry ${actionLabel(retainedIntent.action)} intent`}
              </Button>
            ) : null}
            {busy ? <CircularProgress aria-label="Sending control command" size={22} /> : null}
          </Box>
        </CardContent>
      </Card>

      <Dialog
        aria-describedby="control-confirmation-detail"
        aria-labelledby="control-confirmation-title"
        onClose={() => {
          if (!busy) setConfirmation(null)
        }}
        open={confirmation !== null}
      >
        <DialogTitle id="control-confirmation-title">
          Confirm {confirmation ? actionLabel(confirmation.action) : ''} command
        </DialogTitle>
        <DialogContent>
          <Alert
            id="control-confirmation-detail"
            severity={confirmation?.action === 'halt' ? 'error' : 'warning'}
            variant="outlined"
          >
            {confirmation?.action === 'halt'
              ? 'HALT is the stronger fail-safe state. It blocks trading until a separately proven rearm workflow succeeds.'
              : 'PAUSE blocks new exposure while preserving the stronger HALT action if conditions worsen.'}
          </Alert>
          <Typography sx={{ fontSize: 12, mt: 2 }}>
            Account:{' '}
            <Box component="span" sx={{ fontFamily: 'monospace' }}>
              {confirmation?.accountId}
            </Box>
          </Typography>
          <Typography sx={{ fontSize: 12, mt: 1 }}>
            Reason: {confirmation?.reasonCode}
          </Typography>
          {confirmation && confirmation.accountId !== accountId ? (
            <Alert severity="error" sx={{ mt: 2 }} variant="outlined">
              The current account changed. Cancel and review a new command for{' '}
              <Box component="span" sx={{ fontFamily: 'monospace' }}>
                {accountId}
              </Box>
              .
            </Alert>
          ) : null}
          {confirmation?.action === 'halt' ? (
            <TextField
              autoComplete="off"
              fullWidth
              label="Type HALT to confirm"
              margin="normal"
              onChange={(event) => setHaltConfirmation(event.target.value)}
              value={haltConfirmation}
            />
          ) : null}
        </DialogContent>
        <DialogActions>
          <Button disabled={busy} onClick={() => setConfirmation(null)}>
            Cancel
          </Button>
          <Button
            color={confirmation?.action === 'halt' ? 'error' : 'warning'}
            disabled={
              busy ||
              confirmation === null ||
              confirmation.accountId !== accountId ||
              !actionAvailable(confirmation.action) ||
              (confirmation.action === 'halt' && haltConfirmation !== 'HALT')
            }
            onClick={confirm}
            variant="contained"
          >
            Confirm {confirmation ? actionLabel(confirmation.action) : ''}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  )
}
