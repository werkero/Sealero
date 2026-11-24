export const DEFAULT_API_PROXY_TARGET = 'http://localhost:3000'

export interface ApiProxyRule {
  target: string
  changeOrigin: boolean
}

export function resolveApiProxyTarget(configuredTarget: string | undefined): string {
  return configuredTarget?.trim() || DEFAULT_API_PROXY_TARGET
}

export function createApiProxy(target: string): Record<string, ApiProxyRule> {
  return {
    '/v1': {
      target,
      changeOrigin: true,
    },
  }
}
