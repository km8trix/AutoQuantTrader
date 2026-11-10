import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  makeExperimentFixture,
  makeExperimentsFixture,
} from '../../api/researchFixtures'
import type { ExperimentListResponse } from '../../api/types'
import { renderWithProviders } from '../../test/render'
import { ExperimentsPage } from './ExperimentsPage'

const fixtureNow = new Date('2026-07-23T14:00:00.000Z')

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input
  return input instanceof URL ? input.href : input.url
}

function renderPage(initialEntry = '/research/experiments') {
  return renderWithProviders(
    <MemoryRouter initialEntries={[initialEntry]}>
      <ExperimentsPage />
    </MemoryRouter>,
  )
}

function mockExperimentApi(state: 'sealed' | 'revealed' = 'sealed') {
  const list = makeExperimentsFixture(fixtureNow, state)
  const detail = makeExperimentFixture(fixtureNow, state)
  vi.mocked(fetch).mockImplementation((input) => {
    const url = requestUrl(input)
    if (url.endsWith('/research/experiments')) {
      return Promise.resolve(jsonResponse(list))
    }
    if (url.includes('/research/experiments/')) {
      return Promise.resolve(jsonResponse(detail))
    }
    return Promise.reject(new Error(`Unexpected request ${url}`))
  })
  return { detail, list }
}

describe('ExperimentsPage', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllEnvs()
  })

  it('shows an explicit loading state while governed families are pending', () => {
    vi.mocked(fetch).mockReturnValue(new Promise<Response>(() => undefined))

    renderPage()

    expect(screen.getByLabelText('Loading governed experiment families')).toBeInTheDocument()
  })

  it('shows an empty state without requesting a detail record', async () => {
    const empty: ExperimentListResponse = {
      as_of: fixtureNow.toISOString(),
      experiments: [],
    }
    vi.mocked(fetch).mockResolvedValue(jsonResponse(empty))

    renderPage()

    expect(await screen.findByText('No experiment families registered')).toBeInTheDocument()
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('keeps list failures explicit and retries before selecting the family', async () => {
    const list = makeExperimentsFixture(fixtureNow)
    const detail = makeExperimentFixture(fixtureNow)
    let listRequestCount = 0
    vi.mocked(fetch).mockImplementation((input) => {
      const url = requestUrl(input)
      if (url.endsWith('/research/experiments')) {
        listRequestCount += 1
        return Promise.resolve(
          listRequestCount === 1
            ? jsonResponse({ detail: 'Experiment registry is rebuilding.' }, 503)
            : jsonResponse(list),
        )
      }
      return Promise.resolve(jsonResponse(detail))
    })
    const user = userEvent.setup()

    renderPage()

    expect(await screen.findByText(/Experiment registry is rebuilding/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('Hypothesis and exact pins')).toBeInTheDocument()
    expect(listRequestCount).toBe(2)
  })

  it('rejects detail evidence for a different governed family', async () => {
    const list = makeExperimentsFixture(fixtureNow)
    const summary = list.experiments[0]
    if (!summary) throw new Error('Expected the experiment fixture summary')
    list.experiments = [{ ...summary, family_id: 'b'.repeat(64) }]
    const detail = makeExperimentFixture(fixtureNow)
    vi.mocked(fetch).mockImplementation((input) => {
      const url = requestUrl(input)
      return Promise.resolve(
        jsonResponse(
          url.endsWith('/research/experiments') ? list : detail,
        ),
      )
    })

    renderPage()

    expect(
      await screen.findByText(
        'Experiment detail identity does not match the selected governed family.',
      ),
    ).toBeInTheDocument()
    expect(screen.queryByText('Hypothesis and exact pins')).not.toBeInTheDocument()
  })

  it('does not combine a real family list with an unrelated development fixture', async () => {
    vi.stubEnv('VITE_USE_DEV_FIXTURES', 'true')
    const list = makeExperimentsFixture(fixtureNow)
    const summary = list.experiments[0]
    if (!summary) throw new Error('Expected the experiment fixture summary')
    list.experiments = [{ ...summary, family_id: 'b'.repeat(64) }]
    vi.mocked(fetch).mockImplementation((input) => {
      const url = requestUrl(input)
      return url.endsWith('/research/experiments')
        ? Promise.resolve(jsonResponse(list))
        : Promise.reject(new TypeError('Detail API offline'))
    })

    renderPage()

    expect(
      await screen.findByText(/development experiment fixture does not match/i),
    ).toBeInTheDocument()
    expect(screen.queryByText('Hypothesis and exact pins')).not.toBeInTheDocument()
  })

  it('renders the stable budget, declarations, every lifecycle status, and sealed holdout', async () => {
    const { detail } = mockExperimentApi('sealed')

    renderPage()

    expect(await screen.findByText('Hypothesis and exact pins')).toBeInTheDocument()
    expect(screen.getByText('6 / 8')).toBeInTheDocument()
    expect(screen.getByText('2 remaining before holdout')).toBeInTheDocument()
    expect(screen.getByText('Train, validation, and test declarations')).toBeInTheDocument()
    expect(screen.getAllByText('Train').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Validation').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Test').length).toBeGreaterThan(0)
    expect(screen.getByText('Frozen promotion criteria')).toBeInTheDocument()
    for (const status of ['Queued', 'Running', 'Completed', 'Failed', 'Canceled', 'Abandoned']) {
      expect(screen.getAllByText(status).length).toBeGreaterThan(0)
    }
    expect(screen.getByText(/Final holdout remains sealed/)).toBeInTheDocument()
    expect(screen.getAllByText('Withheld until audited reveal')).toHaveLength(2)
    expect(screen.queryByRole('button', { name: /reveal holdout/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /promote/i })).not.toBeInTheDocument()
    const sealedTestSegment = detail.experiment.segments.find(
      (segment) => segment.kind === 'test',
    )
    expect(sealedTestSegment?.segment_sha256).toBeNull()
    expect(sealedTestSegment?.dataset_replay_sha256).toBeNull()
    const encoded = JSON.stringify(detail)
    for (const forbiddenField of [
      '"target_transcript"',
      '"steps"',
      '"targets"',
      '"positions"',
      '"pnl"',
      '"returns"',
    ]) {
      expect(encoded).not.toContain(forbiddenField)
    }
  })

  it('shows configuration-bound parity proof without claiming a performance result', async () => {
    const { detail } = mockExperimentApi('sealed')
    const completedAttempt = detail.experiment.attempts.find(
      (attempt) => attempt.status === 'completed',
    )
    const evaluation = completedAttempt?.history.find(
      (event) => event.status === 'completed',
    )?.evaluation
    if (!completedAttempt || !evaluation) {
      throw new Error('Expected a completed fixture attempt with evaluation proof')
    }

    renderPage()

    expect(await screen.findByText('Configuration-bound evaluation proof')).toBeInTheDocument()
    expect(
      screen.getByText(
        /Parity-certified target evaluation only. This is not a performance report/,
      ),
    ).toBeInTheDocument()
    expect(screen.getByText('Evaluated steps')).toBeInTheDocument()
    expect(screen.getByText(evaluation.step_count.toLocaleString())).toBeInTheDocument()
    expect(screen.getByText('Produced targets')).toBeInTheDocument()
    expect(screen.getByText(evaluation.target_count.toLocaleString())).toBeInTheDocument()
    expect(
      screen.getByLabelText(
        `Attempt ${completedAttempt.attempt_number} Target transcript SHA-256: ${evaluation.target_transcript_sha256}`,
      ),
    ).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /promote|deploy|trade/i })).not.toBeInTheDocument()
  })

  it('shows revealed governance evidence without adding a held-out result surface', async () => {
    const { detail, list } = mockExperimentApi('revealed')

    renderPage()

    expect(await screen.findByText(/Final holdout has been revealed/)).toBeInTheDocument()
    expect(screen.getByText('fixture-governance-reviewer')).toBeInTheDocument()
    expect(
      screen.getByText('Synthetic governance drill completed after frozen selection.'),
    ).toBeInTheDocument()
    expect(screen.getByText('Pre-reveal attempt count')).toBeInTheDocument()
    expect(screen.getByText('Exploratory budget locked after reveal')).toBeInTheDocument()
    expect(screen.queryByText('2 remaining before holdout')).not.toBeInTheDocument()
    expect(
      screen.getByText(/Held-out observations, transcript contents, and performance results/),
    ).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /reveal/i })).not.toBeInTheDocument()
    expect(
      detail.experiment.attempts.every((attempt) =>
        ['completed', 'failed', 'canceled', 'abandoned'].includes(attempt.status),
      ),
    ).toBe(true)
    expect(detail.experiment.summary).toEqual(list.experiments[0])
    expect(detail.experiment.summary.snapshot_sha256).not.toBe(
      detail.experiment.holdout.pre_reveal_snapshot_sha256,
    )
    expect(detail.experiment.summary.registry_head_sha256).not.toBe(
      detail.experiment.holdout.pre_reveal_registry_head_sha256,
    )
    expect(detail.experiment.summary.remaining_pre_holdout_attempts).toBe(0)
    const revealedTestSegment = detail.experiment.segments.find(
      (segment) => segment.kind === 'test',
    )
    expect(revealedTestSegment?.segment_sha256).not.toBeNull()
    expect(revealedTestSegment?.dataset_replay_sha256).not.toBeNull()
    const finalTestAttempt = detail.experiment.attempts.find(
      (attempt) => attempt.segment_kind === 'test',
    )
    if (!finalTestAttempt) {
      throw new Error('Expected a post-reveal final-test attempt')
    }
    expect(finalTestAttempt.holdout_reveal_sha256).toBe(
      detail.experiment.holdout.reveal_sha256,
    )
    expect(finalTestAttempt.history.at(-1)?.evaluation?.segment_kind).toBe('test')
    expect(
      screen.getByLabelText(`Evaluation evidence for attempt ${finalTestAttempt.attempt_number}`),
    ).toBeInTheDocument()
  })

  it('labels explicit synthetic fallback when the development flag is enabled', async () => {
    vi.stubEnv('VITE_USE_DEV_FIXTURES', 'true')
    vi.mocked(fetch).mockRejectedValue(new TypeError('Control API offline'))

    renderPage()

    expect(
      await screen.findByText(/explicit synthetic development fixtures are active/i),
    ).toBeInTheDocument()
    expect(
      await screen.findByText('Synthetic rolling-close-mean stability study'),
    ).toBeInTheDocument()
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2))
  })
})
