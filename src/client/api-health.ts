export interface ApiHealthResponse {
  api_version: string
  supported_api_versions: string[]
  min_app_versions: {
    android: string | null
    ios: string | null
    web: string | null
  }
  server_time: string
  server_name: string
  /** Current privacy-policy version (SD §5.1); present when the server is configured with one. */
  policy_version?: string
}

export type ApiHealthClientErrorCode = 'http_error' | 'invalid_response' | 'timeout'

export class ApiHealthClientError extends Error {
  readonly code: ApiHealthClientErrorCode
  readonly status?: number

  constructor(code: ApiHealthClientErrorCode, status?: number) {
    super(code)
    this.name = 'ApiHealthClientError'
    this.code = code
    this.status = status
  }
}

export interface ApiHealthClientOptions {
  /** API origin or base path; an empty value uses the current origin. */
  apiBaseUrl?: string
  fetcher?: typeof fetch
  timeoutMs?: number
}

const HEALTH_FIELDS = [
  'api_version',
  'supported_api_versions',
  'min_app_versions',
  'server_time',
  'server_name',
] as const
const PLATFORM_FIELDS = ['android', 'ios', 'web'] as const
export const DEFAULT_API_HEALTH_TIMEOUT_MS = 8_000

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value)
  return keys.length === expected.length && expected.every((key) => Object.hasOwn(value, key))
}

function isUtcIsoTimestamp(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return false
  const milliseconds = Date.parse(value)
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value
}

function hasHealthKeys(value: Record<string, unknown>): boolean {
  const keys = Object.keys(value)
  return (
    HEALTH_FIELDS.every((key) => Object.hasOwn(value, key)) &&
    keys.every((key) => (HEALTH_FIELDS as readonly string[]).includes(key) || key === 'policy_version')
  )
}

/** Validates the documented response for GET /v1/health: the five required fields plus the optional policy_version (SD §5.1). Any other extra field still fails closed. */
export function isApiHealthResponse(value: unknown): value is ApiHealthResponse {
  if (!isRecord(value) || !hasHealthKeys(value)) return false
  if (Object.hasOwn(value, 'policy_version') && typeof value['policy_version'] !== 'string') return false
  if (typeof value['api_version'] !== 'string' || value['api_version'].length === 0) return false
  if (!Array.isArray(value['supported_api_versions']) ||
    !value['supported_api_versions'].every((version) => typeof version === 'string') ||
    !value['supported_api_versions'].includes('v1')) return false
  if (typeof value['server_name'] !== 'string' || value['server_name'].trim().length === 0) return false
  if (!isUtcIsoTimestamp(value['server_time'])) return false

  const versions = value['min_app_versions']
  if (!isRecord(versions) || !hasExactKeys(versions, PLATFORM_FIELDS)) return false
  return PLATFORM_FIELDS.every((platform) => versions[platform] === null || typeof versions[platform] === 'string')
}

function buildHealthUrl(apiBaseUrl: string): string {
  const base = apiBaseUrl.trim().replace(/\/+$/, '')
  return `${base}/v1/health`
}

/** A small, credential-free adapter for the public health/version endpoint. */
export function createApiHealthClient(options: ApiHealthClientOptions = {}) {
  const endpoint = buildHealthUrl(options.apiBaseUrl ?? '')
  const fetcher = options.fetcher ?? globalThis.fetch
  const timeoutMs = options.timeoutMs ?? DEFAULT_API_HEALTH_TIMEOUT_MS
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new RangeError('timeoutMs must be a positive finite number')
  }

  return {
    async getHealth(signal?: AbortSignal): Promise<ApiHealthResponse> {
      if (signal?.aborted) throw signal.reason
      const requestController = new AbortController()
      const abortFromCaller = () => requestController.abort(signal?.reason)
      signal?.addEventListener('abort', abortFromCaller, { once: true })
      let timedOut = false
      const timeoutId = setTimeout(() => {
        timedOut = true
        requestController.abort()
      }, timeoutMs)

      try {
        const response = await fetcher(endpoint, {
          method: 'GET',
          headers: { accept: 'application/json' },
          credentials: 'omit',
          cache: 'no-store',
          signal: requestController.signal,
        })
        if (!response.ok) throw new ApiHealthClientError('http_error', response.status)

        let payload: unknown
        try {
          payload = await response.json()
        } catch (error) {
          if (timedOut || requestController.signal.aborted) throw error
          throw new ApiHealthClientError('invalid_response', response.status)
        }
        if (!isApiHealthResponse(payload)) throw new ApiHealthClientError('invalid_response', response.status)
        return payload
      } catch (error) {
        if (timedOut) throw new ApiHealthClientError('timeout')
        throw error
      } finally {
        clearTimeout(timeoutId)
        signal?.removeEventListener('abort', abortFromCaller)
      }
    },
  }
}
