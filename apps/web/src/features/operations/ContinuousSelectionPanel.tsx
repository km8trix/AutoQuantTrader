import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  CircularProgress,
  TextField,
  Typography,
} from '@mui/material'
import { useEffect, useId, useRef, useState } from 'react'

import { ApiError } from '../../api/client'
import {
  type ContinuousSelection,
  fetchContinuousSelection,
} from './continuousSelectionApi'

const ACCOUNT_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/

function readError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 401 || error.status === 403) {
      return 'Metadata read access is unavailable. No stored selection was loaded.'
    }
    if (error.status === 503) {
      return 'Stored selection metadata is unavailable. No account readiness is implied.'
    }
  }
  return 'The stored selection could not be read. No record is displayed.'
}

function RecordField({ label, value }: { label: string; value: string }) {
  return (
    <Box component="div" sx={{ display: 'contents' }}>
      <Typography color="text.secondary" component="dt" variant="body2">
        {label}
      </Typography>
      <Typography component="dd" sx={{ m: 0, overflowWrap: 'anywhere' }} variant="body2">
        {value}
      </Typography>
    </Box>
  )
}

export function ContinuousSelectionPanel() {
  const titleId = useId()
  const inputId = useId()
  const [accountId, setAccountId] = useState('')
  const [pending, setPending] = useState(false)
  const [record, setRecord] = useState<ContinuousSelection | null>(null)
  const [error, setError] = useState<string | null>(null)
  const request = useRef<AbortController | null>(null)
  const validAccount = ACCOUNT_ID.test(accountId)

  useEffect(() => () => {
    request.current?.abort()
    request.current = null
  }, [])

  function changeAccount(value: string) {
    request.current?.abort()
    request.current = null
    setAccountId(value)
    setPending(false)
    setRecord(null)
    setError(null)
  }

  async function readSelection() {
    if (!validAccount) return
    request.current?.abort()
    const current = new AbortController()
    request.current = current
    setPending(true)
    setRecord(null)
    setError(null)
    try {
      const next = await fetchContinuousSelection(accountId, current.signal)
      if (request.current === current && !current.signal.aborted) {
        setRecord(next)
      }
    } catch (failure) {
      if (request.current === current && !current.signal.aborted) {
        setError(readError(failure))
      }
    } finally {
      if (request.current === current) {
        request.current = null
        setPending(false)
      }
    }
  }

  return (
    <Card aria-labelledby={titleId} component="section">
      <CardContent sx={{ p: 2.5, '&:last-child': { pb: 2.5 } }}>
        <Typography component="h2" id={titleId} variant="h2">
          Stored continuous selection
        </Typography>
        <Typography color="text.secondary" sx={{ mt: 1 }} variant="body2">
          Read retained record metadata for an account you specify. Row integrity does not
          establish authenticated owner history, current financial state, account readiness,
          or permission to trade. This panel changes no controls or risk settings.
        </Typography>
        <Box
          aria-label="Read stored selection"
          component="form"
          onSubmit={(event) => {
            event.preventDefault()
            void readSelection()
          }}
          sx={{ alignItems: 'flex-start', display: 'flex', flexWrap: 'wrap', gap: 1.5, mt: 2 }}
        >
          <TextField
            autoComplete="off"
            error={accountId.length > 0 && !validAccount}
            helperText={accountId.length > 0 && !validAccount
              ? 'Use 1–64 letters, digits, periods, underscores, colons or hyphens; start with a letter or digit.'
              : 'Enter the exact account ID; it is not inferred from the workspace.'}
            id={inputId}
            label="Account ID"
            onChange={(event) => changeAccount(event.target.value)}
            size="small"
            slotProps={{ htmlInput: { maxLength: 64, spellCheck: false } }}
            sx={{ flex: '1 1 280px' }}
            value={accountId}
          />
          <Button disabled={!validAccount || pending} type="submit" variant="outlined">
            Read stored selection
          </Button>
        </Box>
        <Box aria-busy={pending} aria-live="polite" sx={{ mt: 2 }}>
          {pending ? (
            <Box role="status" sx={{ alignItems: 'center', display: 'flex', gap: 1 }}>
              <CircularProgress aria-hidden="true" size={16} />
              <Typography variant="body2">Reading stored selection…</Typography>
            </Box>
          ) : null}
          {error ? <Alert severity="error">{error}</Alert> : null}
          {record ? (
            <>
              <Typography sx={{ mb: 1 }} variant="body2">
                {record.state === 'absent'
                  ? 'No retained account checkpoint or selection was found.'
                  : record.state === 'unselected'
                    ? 'A retained account checkpoint exists; no selection is stored.'
                    : 'A retained selection record is stored.'}
              </Typography>
              <Box
                aria-label="Stored selection record"
                component="dl"
                sx={{ display: 'grid', gap: 1, gridTemplateColumns: 'minmax(120px, 1fr) minmax(0, 2fr)', m: 0 }}
              >
                <RecordField label="Account ID" value={record.account_id} />
                {record.checkpoint ? (
                  <>
                    <RecordField label="Checkpoint stream" value={record.checkpoint.stream_id} />
                    <RecordField label="Checkpoint sequence" value={record.checkpoint.sequence} />
                    <RecordField label="Checkpoint recorded at (UTC)" value={record.checkpoint.recorded_at} />
                  </>
                ) : null}
                {record.selection ? (
                  <>
                    <RecordField label="Selection generation" value={record.selection.generation} />
                    <RecordField label="Strategy name" value={record.selection.strategy_name} />
                    <RecordField label="Strategy version" value={record.selection.strategy_version} />
                    <RecordField label="Configuration SHA-256" value={record.selection.configuration_sha256} />
                    <RecordField label="Instruments" value={record.selection.instruments.map(({ instrument_id, symbol }) => `${symbol} (${instrument_id})`).join(', ')} />
                    <RecordField label="Policy ID" value={record.selection.policy_id} />
                    <RecordField label="Stored new-exposure flag" value={String(record.selection.enabled_for_new_exposure)} />
                    <RecordField label="Stored live-authorization flag" value={String(record.selection.live_authorized)} />
                    <RecordField label="Selection recorded at (UTC)" value={record.selection.recorded_at} />
                    <RecordField label="Selection effective at (UTC)" value={record.selection.effective_at} />
                  </>
                ) : null}
              </Box>
            </>
          ) : null}
        </Box>
      </CardContent>
    </Card>
  )
}
