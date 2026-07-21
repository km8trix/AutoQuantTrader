import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import {
  fetchBootstrap,
  fetchBacktestReport,
  fetchBacktests,
  fetchDashboardSummary,
  fetchDataCatalog,
  fetchDataQuality,
  fetchResearchStrategies,
  launchBacktest,
} from './client'
import type { BacktestLaunchRequest, ResearchMutationCredentials } from './types'

export const queryKeys = {
  bootstrap: ['ui', 'bootstrap'] as const,
  dashboardSummary: ['dashboard', 'summary'] as const,
  dataCatalog: ['data', 'catalog'] as const,
  dataQuality: ['data', 'quality'] as const,
  researchStrategies: ['research', 'strategies'] as const,
  backtests: ['research', 'backtests'] as const,
  backtestReport: (jobId: string) => ['research', 'backtests', jobId, 'report'] as const,
}

export function useBootstrap() {
  return useQuery({
    queryKey: queryKeys.bootstrap,
    queryFn: ({ signal }) => fetchBootstrap(signal),
    staleTime: 15_000,
    retry: false,
    refetchInterval: 10_000,
    refetchIntervalInBackground: false,
    refetchOnWindowFocus: true,
  })
}

export function useDashboardSummary(enabled = true) {
  return useQuery({
    queryKey: queryKeys.dashboardSummary,
    queryFn: ({ signal }) => fetchDashboardSummary(signal),
    enabled,
    staleTime: 10_000,
    refetchInterval: 10_000,
    refetchIntervalInBackground: false,
    retry: false,
  })
}

export function useDataCatalog() {
  return useQuery({
    queryKey: queryKeys.dataCatalog,
    queryFn: ({ signal }) => fetchDataCatalog(signal),
    staleTime: 30_000,
    retry: false,
    refetchOnWindowFocus: true,
  })
}

export function useDataQuality() {
  return useQuery({
    queryKey: queryKeys.dataQuality,
    queryFn: ({ signal }) => fetchDataQuality(signal),
    staleTime: 30_000,
    retry: false,
    refetchOnWindowFocus: true,
  })
}

export function useResearchStrategies() {
  return useQuery({
    queryKey: queryKeys.researchStrategies,
    queryFn: ({ signal }) => fetchResearchStrategies(signal),
    staleTime: 30_000,
    retry: false,
    refetchOnWindowFocus: true,
  })
}

export function useBacktests() {
  return useQuery({
    queryKey: queryKeys.backtests,
    queryFn: ({ signal }) => fetchBacktests(signal),
    staleTime: 2_000,
    retry: false,
    refetchInterval: (query) => {
      const jobs = query.state.data?.data.jobs ?? []
      return jobs.some((job) => job.status === 'queued' || job.status === 'running')
        ? 2_000
        : false
    },
    refetchIntervalInBackground: false,
  })
}

export function useLaunchBacktest() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({
      input,
      credentials,
    }: {
      input: BacktestLaunchRequest
      credentials: ResearchMutationCredentials
    }) => launchBacktest(input, credentials),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.backtests })
    },
  })
}

export function useBacktestReport(jobId: string | null, enabled = true) {
  return useQuery({
    queryKey: queryKeys.backtestReport(jobId ?? 'none'),
    queryFn: ({ signal }) => fetchBacktestReport(jobId ?? '', signal),
    enabled: enabled && Boolean(jobId),
    staleTime: Number.POSITIVE_INFINITY,
    retry: false,
  })
}
