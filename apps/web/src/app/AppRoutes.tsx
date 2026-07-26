import { Navigate, Route, Routes } from 'react-router-dom'

import type { UiBootstrap } from '../api/types'
import { DataCatalogPage } from '../features/data/DataCatalogPage'
import { DataQualityPage } from '../features/data/DataQualityPage'
import { OverviewPage } from '../features/overview/OverviewPage'
import { PlaceholderPage } from '../features/overview/PlaceholderPage'
import { BacktestsPage } from '../features/research/BacktestsPage'
import { ExperimentsPage } from '../features/research/ExperimentsPage'
import { StrategiesPage } from '../features/research/StrategiesPage'

interface AppRoutesProps {
  bootstrap: UiBootstrap
}

const placeholderRoutes = [
  {
    path: '/trading/deployments',
    title: 'Deployments',
    description: 'Manage the approval and lifecycle of shadow, paper, and live deployments.',
    phase: 'Phase 4',
  },
  {
    path: '/trading/orders',
    title: 'Orders',
    description: 'Trace order intents, submission knowledge, broker states, and fills.',
    phase: 'Phase 4',
  },
  {
    path: '/trading/portfolio',
    title: 'Portfolio',
    description: 'Inspect authoritative cash, positions, exposures, and balanced ledger entries.',
    phase: 'Phase 4',
  },
  {
    path: '/risk',
    title: 'Risk',
    description: 'Monitor reservations, limit utilization, decisions, and circuit breakers.',
    phase: 'Phase 5',
  },
  {
    path: '/operations/reconciliation',
    title: 'Reconciliation',
    description: 'Compare local projections with broker-authoritative account state.',
    phase: 'Phase 4',
  },
  {
    path: '/operations/audit',
    title: 'Audit log',
    description: 'Review immutable operator actions and system state transitions.',
    phase: 'Phase 5',
  },
  {
    path: '/settings',
    title: 'Settings',
    description: 'Inspect environment identity, capabilities, entitlements, and session metadata.',
    phase: 'Phase 5',
  },
] as const

export function AppRoutes({ bootstrap }: AppRoutesProps) {
  return (
    <Routes>
      <Route element={<OverviewPage bootstrap={bootstrap} />} path="/overview" />
      <Route element={<DataCatalogPage />} path="/data/datasets" />
      <Route element={<DataQualityPage />} path="/data/quality" />
      <Route element={<StrategiesPage />} path="/research/strategies" />
      <Route element={<BacktestsPage bootstrap={bootstrap} />} path="/research/backtests" />
      <Route element={<ExperimentsPage />} path="/research/experiments" />
      {placeholderRoutes.map((route) => (
        <Route
          element={
            <PlaceholderPage
              description={route.description}
              phase={route.phase}
              title={route.title}
            />
          }
          key={route.path}
          path={route.path}
        />
      ))}
      <Route element={<Navigate replace to="/overview" />} path="*" />
    </Routes>
  )
}
