import { useQuery } from '@tanstack/react-query'

import {
  fetchBootstrap,
  fetchDashboardSummary,
  fetchDataCatalog,
  fetchDataQuality,
} from './client'

export const queryKeys = {
  bootstrap: ['ui', 'bootstrap'] as const,
  dashboardSummary: ['dashboard', 'summary'] as const,
  dataCatalog: ['data', 'catalog'] as const,
  dataQuality: ['data', 'quality'] as const,
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
