export const DEFAULT_ADMIN_STATUS_TIMEOUT_MS = 8_000

export interface AdminStatusProbeOptions {
  /** API origin or base path; an empty value uses the current origin. */
  apiBaseUrl?: string
  /** Returns the in-memory access JWT when the session adapter holds one. */
  getAccessToken?: () => string | null
  fetcher?: typeof fetch
  timeoutMs?: number
}

function buildAdminSettingsUrl(apiBaseUrl: string): string {
  const base = apiBaseUrl.trim().replace(/\/+$/, '')
  return `${base}/v1/admin/settings`
}

/**
 * Probes whether the current login session has the admin role.
 *
 * GET /v1/admin/settings is a cheap, side-effect-free admin read: the server
 * answers 200 for admins and 403 `admin_required` for authenticated
 * non-admins (401 without a valid session). Any other outcome — 404, 503,
 * network error, timeout — also means "not an admin" here, never an error.
 * The result is cached by the session hook; the probe runs once per login.
 */
export async function probeAdminAccess(
  options: AdminStatusProbeOptions = {},
  signal?: AbortSignal,
): Promise<boolean> {
  if (signal?.aborted) return false
  const endpoint = buildAdminSettingsUrl(options.apiBaseUrl ?? '')
  const fetcher = options.fetcher ?? globalThis.fetch
  const timeoutMs = options.timeoutMs ?? DEFAULT_ADMIN_STATUS_TIMEOUT_MS
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new RangeError('timeoutMs must be a positive finite number')
  }

  const requestController = new AbortController()
  const abortFromCaller = () => requestController.abort(signal?.reason)
  signal?.addEventListener('abort', abortFromCaller, { once: true })
  const timeoutId = setTimeout(() => requestController.abort(), timeoutMs)

  try {
    const accessToken = options.getAccessToken?.() ?? null
    const headers: Record<string, string> = { accept: 'application/json' }
    if (accessToken) headers.authorization = `Bearer ${accessToken}`
    const response = await fetcher(endpoint, {
      method: 'GET',
      headers,
      credentials: 'include',
      cache: 'no-store',
      signal: requestController.signal,
    })
    return response.ok
  } catch {
    return false
  } finally {
    clearTimeout(timeoutId)
    signal?.removeEventListener('abort', abortFromCaller)
  }
}
