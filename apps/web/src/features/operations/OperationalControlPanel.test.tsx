import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { makeBootstrapFixture } from '../../api/fixtures'
import type {
  OperationalControlMutationResponse,
  OperationsOverviewResponse,
  UiBootstrap,
} from '../../api/types'
import { renderWithProviders } from '../../test/render'
import { OperationalControlPanel } from './OperationalControlPanel'

const CSRF_TOKEN = 'csrf-token-for-phase-five-operations-0001'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function controlBootstrap(now = new Date()): UiBootstrap {
  const bootstrap = makeBootstrapFixture(now)
  bootstrap.environment.account_id = 'paper-account-001'
  bootstrap.backtest_launch = {
    enabled: true,
    operator_id: 'local-operator',
    csrf_token: CSRF_TOKEN,
    csrf_header: 'X-CSRF-Token',
    idempotency_header: 'Idempotency-Key',
    disabled_reason: null,
  }
  bootstrap.feature_flags.operations_query = true
  bootstrap.feature_flags.operations_control = true
  bootstrap.feature_flags.control_pause = true
  bootstrap.feature_flags.control_halt = true
  bootstrap.feature_flags.control_drain = true
  bootstrap.feature_flags.control_flatten = true
  bootstrap.feature_flags.control_rearm = true
  return bootstrap
}

function overview(
  effectiveState: 'running' | 'paused' | 'halted' = 'running',
): OperationsOverviewResponse {
  const decidedAt = new Date().toISOString()
  return {
    active_alerts: [],
    as_of: decidedAt,
    control: {
      active_operation: null,
      blocker_count: 0,
      blocker_overflowed: false,
      decided_at: decidedAt,
      effective_state: effectiveState,
      prior_state: null,
      sequence_number: 1,
      state_changed: true,
      state_epoch_id: 'state-epoch-001',
      transition_id: 'transition-001',
    },
    control_history: [],
    coordinator: {
      fencing_generation: 7,
      lease_expires_at: decidedAt,
      owner_id: 'coordinator-001',
      status: 'active',
    },
    current_risk_assessment: null,
    current_risk_assignment: null,
    environment: {
      account_id: 'paper-account-001',
      loopback_only: true,
      mode: 'local',
      name: 'Local paper',
    },
    readiness: {
      as_of: decidedAt,
      reasons: [],
      status: 'ready',
    },
  }
}

function mutationResponse(
  action: 'pause' | 'halt',
  sequenceNumber = 2,
): OperationalControlMutationResponse {
  return {
    action,
    control: {
      active_operation: null,
      blocker_count: 0,
      blocker_overflowed: false,
      decided_at: new Date().toISOString(),
      effective_state: action === 'pause' ? 'paused' : 'halted',
      prior_state: 'running',
      sequence_number: sequenceNumber,
      state_changed: true,
      state_epoch_id: `state-epoch-${sequenceNumber}`,
      transition_id: `transition-${sequenceNumber}`,
    },
  }
}

function methodOf(init: RequestInit | undefined): string {
  return init?.method ?? 'GET'
}

function headerValue(init: RequestInit | undefined, name: string): string | null {
  return new Headers(init?.headers).get(name)
}

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input
  if (input instanceof URL) return input.toString()
  return input.url
}

function AccountSwitchHarness({ bootstrap }: { bootstrap: UiBootstrap }) {
  const [accountId, setAccountId] = useState(bootstrap.environment.account_id)
  return (
    <>
      <button
        data-testid="switch-account"
        onClick={() =>
          setAccountId((current) =>
            current === 'paper-account-001'
              ? 'paper-account-002'
              : 'paper-account-001',
          )
        }
        type="button"
      >
        Switch account
      </button>
      <OperationalControlPanel
        bootstrap={{
          ...bootstrap,
          environment: {
            ...bootstrap.environment,
            account_id: accountId,
          },
        }}
      />
    </>
  )
}

async function enterReasonAndConfirmPause(reason = 'operator risk review'): Promise<void> {
  const user = userEvent.setup()
  await user.type(screen.getByLabelText('Operator reason'), reason)
  await user.click(screen.getByRole('button', { name: 'Pause' }))
  await user.click(
    screen.getByRole('button', { name: 'Confirm Pause' }),
  )
}

describe('Phase 5G safe operational controls', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  it('keeps development fixtures mutation-disabled and never renders forbidden controls', async () => {
    const bootstrap = makeBootstrapFixture()
    renderWithProviders(<OperationalControlPanel bootstrap={bootstrap} />)

    await userEvent.type(
      screen.getByLabelText('Operator reason'),
      'fixture must remain read only',
    )

    const controls = screen.getByRole('group', { name: 'Operational controls' })
    expect(within(controls).getByRole('button', { name: 'Pause' })).toBeDisabled()
    expect(within(controls).getByRole('button', { name: 'Halt' })).toBeDisabled()
    for (const name of ['Drain', 'Flatten', 'Rearm', 'Assign', 'Initialize']) {
      expect(within(controls).queryByRole('button', { name })).not.toBeInTheDocument()
    }
    expect(fetch).not.toHaveBeenCalled()
  })

  it('requires the granular action flag, supported headers, CSRF, and a bounded reason', () => {
    const bootstrap = controlBootstrap()
    bootstrap.feature_flags.control_pause = false
    bootstrap.backtest_launch = {
      ...bootstrap.backtest_launch!,
      csrf_header: 'Unsupported-CSRF',
    }
    renderWithProviders(<OperationalControlPanel bootstrap={bootstrap} />)

    const reason = screen.getByLabelText('Operator reason')
    fireEvent.change(reason, { target: { value: ' leading whitespace' } })
    expect(screen.getByText('Remove leading or trailing whitespace.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Pause' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Halt' })).toBeDisabled()
    expect(screen.getByText(/supported CSRF and idempotency header/)).toBeInTheDocument()
    expect(fetch).not.toHaveBeenCalled()
  })

  it('requires the exact enabled bootstrap credential capability even when a token is present', async () => {
    const bootstrap = controlBootstrap()
    bootstrap.backtest_launch = {
      ...bootstrap.backtest_launch!,
      enabled: false,
      disabled_reason: 'durable persistence unavailable',
    }
    renderWithProviders(<OperationalControlPanel bootstrap={bootstrap} />)

    await userEvent.type(
      screen.getByLabelText('Operator reason'),
      'pause despite contradictory capability',
    )

    expect(screen.getByRole('button', { name: 'Pause' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Halt' })).toBeDisabled()
    expect(fetch).not.toHaveBeenCalled()
  })

  it('does not let stale or not-ready bootstrap evidence block PAUSE or HALT', async () => {
    const bootstrap = controlBootstrap()
    bootstrap.readiness.status = 'not_ready'
    bootstrap.readiness.as_of = '2020-01-01T00:00:00.000Z'
    vi.mocked(fetch).mockResolvedValue(jsonResponse(overview()))

    renderWithProviders(<OperationalControlPanel bootstrap={bootstrap} />)
    await userEvent.type(screen.getByLabelText('Operator reason'), 'fail-safe review')

    expect(screen.getByRole('button', { name: 'Pause' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Halt' })).toBeEnabled()
  })

  it('sends the exact cookie, CSRF, idempotency, route, and bounded request body, then refreshes overview', async () => {
    const calls: Array<[RequestInfo | URL, RequestInit | undefined]> = []
    vi.mocked(fetch).mockImplementation((input, init) => {
      calls.push([input, init])
      if (methodOf(init) === 'POST') {
        return Promise.resolve(jsonResponse(mutationResponse('pause')))
      }
      return Promise.resolve(jsonResponse(overview()))
    })

    renderWithProviders(<OperationalControlPanel bootstrap={controlBootstrap()} />)
    await enterReasonAndConfirmPause('operator risk review')

    expect(
      await screen.findByText('Pause confirmed at control sequence 2.'),
    ).toBeInTheDocument()
    const post = calls.find(([, init]) => methodOf(init) === 'POST')
    expect(post).toBeDefined()
    expect(post?.[0]).toBe(
      '/api/v1/operations/accounts/paper-account-001/control/pause',
    )
    expect(post?.[1]?.credentials).toBe('same-origin')
    expect(headerValue(post?.[1], 'X-CSRF-Token')).toBe(CSRF_TOKEN)
    expect(headerValue(post?.[1], 'Idempotency-Key')).toMatch(
      /^operations-pause-[0-9a-f-]{36}$/,
    )
    expect(post?.[1]?.body).toBe(
      JSON.stringify({ reason_code: 'operator risk review' }),
    )
    await waitFor(() => {
      expect(calls.filter(([, init]) => methodOf(init) === 'GET')).toHaveLength(2)
    })
    for (const [, init] of calls.filter(([, init]) => methodOf(init) === 'GET')) {
      expect(init?.credentials).toBe('same-origin')
      expect(headerValue(init, 'X-CSRF-Token')).toBe(CSRF_TOKEN)
    }
  })

  it.each([
    ['network failure', () => Promise.reject(new TypeError('network unavailable'))],
    [
      'server failure',
      () =>
        Promise.resolve(
          jsonResponse({ detail: 'durable store response was interrupted' }, 503),
        ),
    ],
    [
      'malformed success',
      () =>
        Promise.resolve(
          new Response('not-json', {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
        ),
    ],
    [
      'mismatched success',
      () => Promise.resolve(jsonResponse(mutationResponse('halt'))),
    ],
  ])('reuses the exact idempotency key after an ambiguous %s', async (_label, fail) => {
    const postCalls: RequestInit[] = []
    let attempts = 0
    vi.mocked(fetch).mockImplementation((_input, init) => {
      if (methodOf(init) !== 'POST') return Promise.resolve(jsonResponse(overview()))
      postCalls.push(init ?? {})
      attempts += 1
      if (attempts === 1) return fail()
      return Promise.resolve(jsonResponse(mutationResponse('pause')))
    })

    renderWithProviders(<OperationalControlPanel bootstrap={controlBootstrap()} />)
    await enterReasonAndConfirmPause()

    const retry = await screen.findByRole('button', {
      name: 'Retry Pause intent',
    })
    expect(screen.getByText(/outcome is ambiguous/)).toBeInTheDocument()
    await userEvent.click(retry)
    expect(
      await screen.findByText('Pause confirmed at control sequence 2.'),
    ).toBeInTheDocument()

    expect(postCalls).toHaveLength(2)
    expect(headerValue(postCalls[0], 'Idempotency-Key')).toBe(
      headerValue(postCalls[1], 'Idempotency-Key'),
    )
    expect(postCalls[0]?.body).toBe(postCalls[1]?.body)
  })

  it('uses a distinct key for a later HALT intent and requires stronger typed confirmation', async () => {
    const postCalls: RequestInit[] = []
    vi.mocked(fetch).mockImplementation((_input, init) => {
      if (methodOf(init) !== 'POST') return Promise.resolve(jsonResponse(overview()))
      postCalls.push(init ?? {})
      const action = postCalls.length === 1 ? 'pause' : 'halt'
      return Promise.resolve(
        jsonResponse(mutationResponse(action, postCalls.length + 1)),
      )
    })

    renderWithProviders(<OperationalControlPanel bootstrap={controlBootstrap()} />)
    await enterReasonAndConfirmPause('pause for policy review')
    await screen.findByText('Pause confirmed at control sequence 2.')
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    })

    const user = userEvent.setup()
    await user.type(screen.getByLabelText('Operator reason'), 'halt after escalation')
    await user.click(screen.getByRole('button', { name: 'Halt' }))
    expect(
      screen.getByText(/HALT is the stronger fail-safe state/),
    ).toBeInTheDocument()
    const confirm = screen.getByRole('button', { name: 'Confirm Halt' })
    expect(confirm).toBeDisabled()
    await user.type(screen.getByLabelText('Type HALT to confirm'), 'HALT')
    expect(confirm).toBeEnabled()
    await user.click(confirm)
    await screen.findByText('Halt confirmed at control sequence 3.')

    expect(postCalls).toHaveLength(2)
    const pauseKey = headerValue(postCalls[0], 'Idempotency-Key')
    const haltKey = headerValue(postCalls[1], 'Idempotency-Key')
    expect(pauseKey).toMatch(/^operations-pause-/)
    expect(haltKey).toMatch(/^operations-halt-/)
    expect(haltKey).not.toBe(pauseKey)
  })

  it('fails closed when the account changes during confirmation and requires reconfirmation', async () => {
    const postCalls: Array<[RequestInfo | URL, RequestInit | undefined]> = []
    vi.mocked(fetch).mockImplementation((input, init) => {
      if (methodOf(init) === 'POST') {
        postCalls.push([input, init])
        return Promise.resolve(jsonResponse(mutationResponse('pause')))
      }
      return Promise.resolve(jsonResponse(overview()))
    })

    renderWithProviders(
      <AccountSwitchHarness bootstrap={controlBootstrap()} />,
    )
    const user = userEvent.setup()
    await user.type(screen.getByLabelText('Operator reason'), 'account-bound pause')
    await user.click(screen.getByRole('button', { name: 'Pause' }))
    expect(screen.getByText('paper-account-001')).toBeInTheDocument()

    fireEvent.click(screen.getByTestId('switch-account'))

    expect(screen.getByText(/current account changed/)).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: 'Confirm Pause' }),
    ).toBeDisabled()
    expect(postCalls).toHaveLength(0)
    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: 'Pause' }))
    expect(screen.getByText('paper-account-002')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Confirm Pause' }))
    await screen.findByText('Pause confirmed at control sequence 2.')

    expect(postCalls).toHaveLength(1)
    expect(requestUrl(postCalls[0]![0])).toContain(
      '/accounts/paper-account-002/control/pause',
    )
  })

  it('never replays an ambiguous retained key against a different account', async () => {
    const postCalls: Array<[RequestInfo | URL, RequestInit | undefined]> = []
    let attempts = 0
    vi.mocked(fetch).mockImplementation((input, init) => {
      if (methodOf(init) !== 'POST') return Promise.resolve(jsonResponse(overview()))
      postCalls.push([input, init])
      attempts += 1
      if (attempts === 1) {
        return Promise.reject(new TypeError('connection interrupted'))
      }
      return Promise.resolve(jsonResponse(mutationResponse('pause')))
    })

    renderWithProviders(
      <AccountSwitchHarness bootstrap={controlBootstrap()} />,
    )
    await enterReasonAndConfirmPause('account-bound retry')
    await screen.findByRole('button', { name: 'Retry Pause intent' })
    const originalKey = headerValue(postCalls[0]?.[1], 'Idempotency-Key')

    fireEvent.click(screen.getByTestId('switch-account'))

    expect(
      screen.queryByRole('button', { name: 'Retry Pause intent' }),
    ).not.toBeInTheDocument()
    expect(screen.getByText(/bound to another account/)).toBeInTheDocument()
    expect(postCalls).toHaveLength(1)

    fireEvent.click(screen.getByTestId('switch-account'))
    await userEvent.click(
      await screen.findByRole('button', { name: 'Retry Pause intent' }),
    )
    await screen.findByText('Pause confirmed at control sequence 2.')

    expect(postCalls).toHaveLength(2)
    for (const [input] of postCalls) {
      expect(requestUrl(input)).toContain(
        '/accounts/paper-account-001/control/pause',
      )
    }
    expect(headerValue(postCalls[1]?.[1], 'Idempotency-Key')).toBe(originalKey)
  })

  it('never calls a forbidden control action even when legacy flags advertise them', async () => {
    const calls: Array<[RequestInfo | URL, RequestInit | undefined]> = []
    vi.mocked(fetch).mockImplementation((input, init) => {
      calls.push([input, init])
      return Promise.resolve(jsonResponse(overview()))
    })

    renderWithProviders(<OperationalControlPanel bootstrap={controlBootstrap()} />)
    await waitFor(() => expect(fetch).toHaveBeenCalled())

    for (const name of ['Drain', 'Flatten', 'Rearm']) {
      expect(screen.queryByRole('button', { name })).not.toBeInTheDocument()
    }
    expect(
      calls.some(([input]) =>
        /control\/(drain|flatten|rearm)/.test(requestUrl(input)),
      ),
    ).toBe(false)
  })
})
