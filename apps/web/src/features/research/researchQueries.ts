import { useQuery } from '@tanstack/react-query'

import {
  fetchResearchCatalog, fetchResearchComparison, fetchResearchExperiment, fetchResearchExperiments,
  fetchResearchReport, fetchResearchRows, fetchResearchRun, fetchResearchRuns,
  type ResearchRowKind, type ResearchRun,
} from './researchApi'

export const personalResearchKey = ['personal-research'] as const
export const runIsActive = (run: Pick<ResearchRun, 'status'>) => run.status === 'queued' || run.status === 'running'

export function useResearchCatalog() {
  return useQuery({ queryKey: [...personalResearchKey, 'catalog'], queryFn: ({ signal }) => fetchResearchCatalog(signal), retry: false })
}

export function useResearchRuns() {
  return useQuery({
    queryKey: [...personalResearchKey, 'runs'], queryFn: ({ signal }) => fetchResearchRuns(signal), retry: false,
    refetchInterval: (query) => query.state.data?.jobs.some(runIsActive) ? 2000 : false,
    refetchIntervalInBackground: false,
  })
}

export function useResearchRun(jobId: string | null) {
  return useQuery({
    queryKey: [...personalResearchKey, 'run', jobId], queryFn: ({ signal }) => fetchResearchRun(jobId ?? '', signal),
    enabled: Boolean(jobId), retry: false,
    refetchInterval: (query) => query.state.data && runIsActive(query.state.data) ? 2000 : false,
    refetchIntervalInBackground: false,
  })
}

export function useResearchReport(jobId: string, reportSha: string) {
  return useQuery({ queryKey: [...personalResearchKey, 'report', jobId, reportSha], queryFn: ({ signal }) => fetchResearchReport(jobId, reportSha, signal), staleTime: Infinity, retry: false })
}

export function useResearchRows(jobId: string, reportSha: string, kind: ResearchRowKind, offset: number) {
  return useQuery({ queryKey: [...personalResearchKey, 'rows', jobId, reportSha, kind, offset], queryFn: ({ signal }) => fetchResearchRows(jobId, reportSha, kind, offset, signal), staleTime: Infinity, retry: false })
}

export function useResearchComparison(jobIds: string[]) {
  return useQuery({ queryKey: [...personalResearchKey, 'comparison', ...jobIds], queryFn: ({ signal }) => fetchResearchComparison(jobIds, signal), enabled: jobIds.length >= 2 && jobIds.length <= 8, retry: false })
}

export function useResearchExperiments() {
  return useQuery({ queryKey: [...personalResearchKey, 'experiments'], queryFn: ({ signal }) => fetchResearchExperiments(signal), retry: false,
    refetchInterval: (query) => query.state.data?.experiments.some(runIsActive) ? 3000 : false, refetchIntervalInBackground: false,
  })
}

export function useResearchExperiment(experimentId: string | null) {
  return useQuery({ queryKey: [...personalResearchKey, 'experiment', experimentId], queryFn: ({ signal }) => fetchResearchExperiment(experimentId ?? '', signal), enabled: Boolean(experimentId), retry: false,
    refetchInterval: (query) => query.state.data && runIsActive(query.state.data) ? 3000 : false, refetchIntervalInBackground: false,
  })
}
