/** API error carrying the server's error code (e.g. `not_found`, `confirmation_expired`). */
export class McpConfirmationApiError extends Error {
  readonly code: string
  readonly status: number

  constructor(code: string, status: number, message?: string) {
    super(message ?? code)
    this.name = 'McpConfirmationApiError'
    this.code = code
    this.status = status
  }
}

export interface McpConfirmationClientOptions {
  /** API origin or base path; an empty value uses the current origin. */
  apiBaseUrl?: string
  /** Returns the in-memory access JWT when the session adapter holds one. */
  getAccessToken?: () => string | null
  /**
   * Shared token refresher (the vault adapter's `refreshAccessToken`).
   * Prefer it over the local refresh: it deduplicates concurrent refreshes
   * across clients and writes the new token back to the vault adapter, so
   * a 401 here can never trigger the server's refresh-token reuse
   * detection. When absent the client refreshes through its own endpoint
   * (standalone / test use) and keeps the token in `refreshedToken`.
   */
  refreshAccessToken?: (signal?: AbortSignal) => Promise<string>
  fetcher?: typeof fetch
}

export interface McpConfirmationItem {
  confirmation_id: string
  item_id: string
  client_id: string
  client_name: string | null
  status: 'pending' | 'approved'
  expires_at: string
  created_at: string
}

export interface McpConfirmationListResponse {
  confirmations: McpConfirmationItem[]
}

export interface McpConfirmationDecisionResponse {
  confirmation_id: string
  status: 'approved' | 'denied'
}

export interface McpConfirmationClient {
  listConfirmations(signal?: AbortSignal): Promise<McpConfirmationListResponse>
  approveConfirmation(confirmationId: string, signal?: AbortSignal): Promise<McpConfirmationDecisionResponse>
  denyConfirmation(confirmationId: string, signal?: AbortSignal): Promise<McpConfirmationDecisionResponse>
}

/**
 * HTTP adapter for the trusted-confirmation UI endpoints (System Design §5.3).
 *
 * Same-origin `/v1/mcp/confirmations` calls (Vite proxies them in dev; the
 * deployed web and API share one origin). The access JWT lives in the vault
 * client's memory; this client reads it through `getAccessToken` and
 * refreshes it through the HttpOnly-cookie refresh endpoint when a request
 * answers 401.
 */
export function createMcpConfirmationClient(options: McpConfirmationClientOptions = {}): McpConfirmationClient {
  const base = (options.apiBaseUrl ?? '').trim().replace(/\/+$/, '')
  const fetcher = options.fetcher ?? globalThis.fetch
  let refreshedToken: string | null = null
  let refreshing: Promise<string> | null = null

  async function readErrorBody(response: Response): Promise<{ code: string | null; message: string | null }> {
    try {
      const body = (await response.json()) as { code?: unknown; message?: unknown }
      return {
        code: typeof body.code === 'string' ? body.code : null,
        message: typeof body.message === 'string' ? body.message : null,
      }
    } catch {
      return { code: null, message: null }
    }
  }

  function throwApiError(error: { code: string | null; message: string | null }, status: number): never {
    throw new McpConfirmationApiError(error.code ?? 'request_failed', status, error.message ?? undefined)
  }

  async function refreshAccessToken(signal?: AbortSignal): Promise<string> {
    if (refreshing) return refreshing
    refreshing = (async () => {
      const response = await fetcher(`${base}/v1/auth/refresh`, {
        method: 'POST',
        credentials: 'include',
        signal,
      })
      if (!response.ok) throwApiError(await readErrorBody(response), response.status)
      const body = (await response.json()) as { access_token?: unknown }
      if (typeof body.access_token !== 'string' || !body.access_token) {
        throw new McpConfirmationApiError('unauthorized', response.status)
      }
      refreshedToken = body.access_token
      return refreshedToken
    })()
    try {
      return await refreshing
    } finally {
      refreshing = null
    }
  }

  /**
   * Refreshes the access token, preferring the shared vault-adapter
   * refresher when one was provided. A shared refresh failure is
   * normalized to this client's error type (the session is gone either
   * way); its message is preserved for diagnosis.
   */
  async function refreshSharedOrLocal(signal?: AbortSignal): Promise<string> {
    if (options.refreshAccessToken) {
      try {
        return await options.refreshAccessToken(signal)
      } catch (error) {
        throw new McpConfirmationApiError('unauthorized', 401, error instanceof Error ? error.message : undefined)
      }
    }
    return refreshAccessToken(signal)
  }

  /** One authenticated request; on 401, refresh once and retry once. */
  async function request<T>(path: string, init: RequestInit, signal?: AbortSignal): Promise<T> {
    const send = async (token: string | null) => {
      const headers = new Headers(init.headers)
      headers.set('accept', 'application/json')
      if (token) headers.set('authorization', `Bearer ${token}`)
      return fetcher(`${base}${path}`, { ...init, headers, credentials: 'include', signal })
    }
    let response = await send(options.getAccessToken?.() ?? refreshedToken)
    if (response.status === 401) {
      const nextToken = await refreshSharedOrLocal(signal)
      response = await send(nextToken)
    }
    if (!response.ok) throwApiError(await readErrorBody(response), response.status)
    if (response.status === 204) return undefined as T
    return (await response.json()) as T
  }

  return {
    listConfirmations(signal) {
      return request<McpConfirmationListResponse>('/v1/mcp/confirmations', { method: 'GET' }, signal)
    },

    approveConfirmation(confirmationId, signal) {
      return request<McpConfirmationDecisionResponse>(
        `/v1/mcp/confirmations/${encodeURIComponent(confirmationId)}/approve`,
        { method: 'POST' },
        signal,
      )
    },

    denyConfirmation(confirmationId, signal) {
      return request<McpConfirmationDecisionResponse>(
        `/v1/mcp/confirmations/${encodeURIComponent(confirmationId)}/deny`,
        { method: 'POST' },
        signal,
      )
    },
  }
}
