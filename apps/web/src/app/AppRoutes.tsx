import { Box, Skeleton } from '@mui/material'
import { lazy, Suspense } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'

import type { UiBootstrap } from '../api/types'
import { PlaceholderPage } from '../features/overview/PlaceholderPage'

const OverviewPage = lazy(() =>
  import('../features/overview/OverviewPage').then((module) => ({
    default: module.OverviewPage,
  })),
)
const DataCatalogPage = lazy(() =>
  import('../features/data/DataCatalogPage').then((module) => ({
    default: module.DataCatalogPage,
  })),
)
const DataQualityPage = lazy(() =>
  import('../features/data/DataQualityPage').then((module) => ({
    default: module.DataQualityPage,
  })),
)
const StrategiesPage = lazy(() =>
  import('../features/research/StrategiesPage').then((module) => ({
    default: module.StrategiesPage,
  })),
)
const BacktestsPage = lazy(() =>
  import('../features/research/BacktestsPage').then((module) => ({
    default: module.BacktestsPage,
  })),
)
const ExperimentsPage = lazy(() =>
  import('../features/research/ExperimentsPage').then((module) => ({
    default: module.ExperimentsPage,
  })),
)
const OperationsDashboardPage = lazy(() =>
  import('../features/operations/OperationsDashboardPage').then((module) => ({
    default: module.OperationsDashboardPage,
  })),
)
const RiskPage = lazy(() =>
  import('../features/operations/RiskPage').then((module) => ({
    default: module.RiskPage,
  })),
)
const ReconciliationPage = lazy(() =>
  import('../features/operations/ReconciliationPage').then((module) => ({
    default: module.ReconciliationPage,
  })),
)
const AuditPage = lazy(() =>
  import('../features/operations/AuditPage').then((module) => ({
    default: module.AuditPage,
  })),
)
const SettingsPage = lazy(() =>
  import('../features/operations/SettingsPage').then((module) => ({
    default: module.SettingsPage,
  })),
)

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
] as const

function RouteLoadingState() {
  return (
    <Box aria-label="Loading workspace page" aria-live="polite" role="status">
      <Skeleton height={48} width="38%" />
      <Skeleton height={160} sx={{ mt: 2 }} variant="rounded" />
      <Skeleton height={280} sx={{ mt: 2 }} variant="rounded" />
    </Box>
  )
}

export function AppRoutes({ bootstrap }: AppRoutesProps) {
  return (
    <Suspense fallback={<RouteLoadingState />}>
      <Routes>
        <Route element={<OverviewPage bootstrap={bootstrap} />} path="/overview" />
        <Route element={<DataCatalogPage />} path="/data/datasets" />
        <Route element={<DataQualityPage />} path="/data/quality" />
        <Route element={<StrategiesPage />} path="/research/strategies" />
        <Route element={<BacktestsPage bootstrap={bootstrap} />} path="/research/backtests" />
        <Route element={<ExperimentsPage />} path="/research/experiments" />
        <Route
          element={<OperationsDashboardPage bootstrap={bootstrap} />}
          path="/operations/dashboard"
        />
        <Route element={<RiskPage bootstrap={bootstrap} />} path="/risk" />
        <Route
          element={<ReconciliationPage bootstrap={bootstrap} />}
          path="/operations/reconciliation"
        />
        <Route element={<AuditPage bootstrap={bootstrap} />} path="/operations/audit" />
        <Route element={<SettingsPage bootstrap={bootstrap} />} path="/settings" />
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
    </Suspense>
  )
}
