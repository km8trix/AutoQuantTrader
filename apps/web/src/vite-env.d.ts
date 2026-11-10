/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_PROXY_TARGET?: string
  readonly VITE_USE_DEV_FIXTURES?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
