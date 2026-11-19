/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** API origin for deployed builds; empty uses same-origin /api through the Vite proxy. */
  readonly VITE_CONTROLCENTER_API_URL?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
