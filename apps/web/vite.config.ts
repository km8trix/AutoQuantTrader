import react from '@vitejs/plugin-react'
import type { Rollup } from 'vite'
import { defineConfig, loadEnv } from 'vite'

function createSharedRuntimeChunk(): Rollup.GetManualChunk {
  const entryDependencyCache = new Map<string, boolean>()

  function isStaticEntryDependency(
    moduleId: string,
    getModuleInfo: Rollup.GetModuleInfo,
    visiting: Set<string>,
  ): boolean {
    const cached = entryDependencyCache.get(moduleId)
    if (cached !== undefined) {
      return cached
    }
    if (visiting.has(moduleId)) {
      return false
    }

    visiting.add(moduleId)
    const moduleInfo = getModuleInfo(moduleId)
    const isEntryDependency =
      moduleInfo?.isEntry === true ||
      moduleInfo?.importers.some((importer) =>
        isStaticEntryDependency(importer, getModuleInfo, visiting),
      ) === true
    visiting.delete(moduleId)
    entryDependencyCache.set(moduleId, isEntryDependency)
    return isEntryDependency
  }

  return (moduleId, { getModuleInfo }) => {
    const normalizedId = moduleId.replaceAll('\\', '/')
    if (
      !normalizedId.includes('/node_modules/') ||
      !isStaticEntryDependency(moduleId, getModuleInfo, new Set())
    ) {
      return undefined
    }

    if (
      normalizedId.includes('/node_modules/react/') ||
      normalizedId.includes('/node_modules/react-dom/') ||
      normalizedId.includes('/node_modules/react-router/') ||
      normalizedId.includes('/node_modules/react-router-dom/') ||
      normalizedId.includes('/node_modules/scheduler/')
    ) {
      return 'react-runtime'
    }

    if (
      normalizedId.includes('/node_modules/@mui/') ||
      normalizedId.includes('/node_modules/@emotion/')
    ) {
      return 'mui-runtime'
    }

    if (normalizedId.includes('/node_modules/@tanstack/')) {
      return 'query-runtime'
    }

    return 'vendor-runtime'
  }
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')

  return {
    plugins: [react()],
    build: {
      manifest: true,
      rollupOptions: {
        output: {
          manualChunks: createSharedRuntimeChunk(),
        },
      },
    },
    server: {
      host: '0.0.0.0',
      port: 5173,
      strictPort: true,
      proxy: {
        '/api': {
          target: env.VITE_API_PROXY_TARGET ?? 'http://localhost:8000',
          changeOrigin: true,
        },
      },
    },
    preview: {
      host: '0.0.0.0',
      port: 4173,
    },
    test: {
      environment: 'jsdom',
      setupFiles: './src/test/setup.ts',
      css: true,
      restoreMocks: true,
      clearMocks: true,
    },
  }
})
