import type {
  AdminAuditResponse,
  AdminOverviewResponse,
  AdminOverviewTrendResponse,
  AdminSettingsResponse,
  AdminSettingsUpdate,
  AdminUserDetailResponse,
  UsersResponse,
} from '../features/admin/contract'

/** API error carrying the server's error code (e.g. `admin_required`, `invalid_credentials`). */
export class AdminApiError extends Error {
  readonly code: string
  readonly status: number

  constructor(code: string, status: number, message?: string) {
    super(message ?? code)
    this.name = 'AdminApiError'
    this.code = code
    this.status = status
  }
}

export interface AdminClientOptions {
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

export interface AdminAuditListQuery {
  actorUserId?: string
  targetUserId?: string
  action?: string
  from?: string
  to?: string
  cursor?: string | null
  limit?: number
}

export interface AdminUserListQuery {
  search?: string
  status?: 'all' | 'active' | 'disabled'
  verified?: 'all' | 'verified' | 'unverified'
  role?: 'all' | 'admin' | 'user' | 'super_admin'
  cursor?: string | null
  limit?: number
}

export interface AdminClient {
  getOverview(signal?: AbortSignal): Promise<AdminOverviewResponse>
  getOverviewTrend(days: number, signal?: AbortSignal): Promise<AdminOverviewTrendResponse>
  getSettings(signal?: AbortSignal): Promise<AdminSettingsResponse>
  updateSettings(updates: AdminSettingsUpdate, signal?: AbortSignal): Promise<AdminSettingsResponse>
  listAudit(query: AdminAuditListQuery, signal?: AbortSignal): Promise<AdminAuditResponse>
  listUsers(query: AdminUserListQuery, signal?: AbortSignal): Promise<UsersResponse>
  getUserDetail(userId: string, loginCursor?: string | null, loginLimit?: number, signal?: AbortSignal): Promise<AdminUserDetailResponse>
  disableUser(userId: string, signal?: AbortSignal): Promise<void>
  enableUser(userId: string, signal?: AbortSignal): Promise<void>
  deleteUser(userId: string, loginPassword: string, signal?: AbortSignal): Promise<void>
  revokeAllDevices(userId: string, loginPassword: string, signal?: AbortSignal): Promise<void>
  makeAdmin(userId: string, signal?: AbortSignal): Promise<void>
  removeAdmin(userId: string, signal?: AbortSignal): Promise<void>
  revokeDevice(deviceId: string, signal?: AbortSignal): Promise<void>
  downloadDbDump(loginPassword: string, signal?: AbortSignal): Promise<{ filename: string; blob: Blob }>
}

/**
 * HTTP adapter for the admin console (System Design §5.2).
 *
 * Same-origin `/v1/admin/*` calls (Vite proxies them in dev; the deployed
 * web and API share one origin). The access JWT lives in the vault client's
 * memory; this client reads it through `getAccessToken` and refreshes it
 * through the HttpOnly-cookie refresh endpoint when a request answers 401.
 * The login password is sent only to the endpoints that require it
 * (db-dump, delete user, revoke all devices) and is never stored.
 */
export function createAdminClient(options: AdminClientOptions = {}): AdminClient {
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
    throw new AdminApiError(error.code ?? 'request_failed', status, error.message ?? undefined)
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
        throw new AdminApiError('unauthorized', response.status)
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
        throw new AdminApiError('unauthorized', 401, error instanceof Error ? error.message : undefined)
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

  function jsonBody(body: unknown): RequestInit {
    return { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
  }

  function withQuery(path: string, params: Record<string, string | undefined>): string {
    const query = new URLSearchParams()
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== '') query.set(key, value)
    }
    const suffix = query.toString()
    return suffix ? `${path}?${suffix}` : path
  }

  return {
    getOverview(signal) {
      return request<AdminOverviewResponse>('/v1/admin/overview', { method: 'GET' }, signal)
    },

    getOverviewTrend(days, signal) {
      return request<AdminOverviewTrendResponse>(withQuery('/v1/admin/overview/trend', { days: String(days) }), { method: 'GET' }, signal)
    },

    getSettings(signal) {
      return request<AdminSettingsResponse>('/v1/admin/settings', { method: 'GET' }, signal)
    },

    updateSettings(updates, signal) {
      return request<AdminSettingsResponse>('/v1/admin/settings', { method: 'PUT', ...jsonBody(updates) }, signal)
    },

    listAudit(query, signal) {
      return request<AdminAuditResponse>(withQuery('/v1/admin/audit', {
        actor_user_id: query.actorUserId,
        target_user_id: query.targetUserId,
        action: query.action,
        from: query.from,
        to: query.to,
        cursor: query.cursor ?? undefined,
        limit: query.limit === undefined ? undefined : String(query.limit),
      }), { method: 'GET' }, signal)
    },

    listUsers(query, signal) {
      return request<UsersResponse>(withQuery('/v1/admin/users', {
        search: query.search?.trim() || undefined,
        status: query.status,
        verified: query.verified,
        role: query.role,
        cursor: query.cursor ?? undefined,
        limit: query.limit === undefined ? undefined : String(query.limit),
      }), { method: 'GET' }, signal)
    },

    getUserDetail(userId, loginCursor, loginLimit, signal) {
      return request<AdminUserDetailResponse>(withQuery(`/v1/admin/users/${encodeURIComponent(userId)}`, {
        login_cursor: loginCursor ?? undefined,
        login_limit: loginLimit === undefined ? undefined : String(loginLimit),
      }), { method: 'GET' }, signal)
    },

    disableUser(userId, signal) {
      return request<void>(`/v1/admin/users/${encodeURIComponent(userId)}/disable`, { method: 'POST' }, signal)
    },

    enableUser(userId, signal) {
      return request<void>(`/v1/admin/users/${encodeURIComponent(userId)}/enable`, { method: 'POST' }, signal)
    },

    deleteUser(userId, loginPassword, signal) {
      return request<void>(`/v1/admin/users/${encodeURIComponent(userId)}/delete`, {
        method: 'POST',
        ...jsonBody({ login_password: loginPassword }),
      }, signal)
    },

    revokeAllDevices(userId, loginPassword, signal) {
      return request<void>(`/v1/admin/users/${encodeURIComponent(userId)}/revoke-all-devices`, {
        method: 'POST',
        ...jsonBody({ login_password: loginPassword }),
      }, signal)
    },

    makeAdmin(userId, signal) {
      return request<void>(`/v1/admin/users/${encodeURIComponent(userId)}/make-admin`, { method: 'POST' }, signal)
    },

    removeAdmin(userId, signal) {
      return request<void>(`/v1/admin/users/${encodeURIComponent(userId)}/remove-admin`, { method: 'POST' }, signal)
    },

    revokeDevice(deviceId, signal) {
      return request<void>(`/v1/admin/devices/${encodeURIComponent(deviceId)}/revoke`, { method: 'POST' }, signal)
    },

    async downloadDbDump(loginPassword, signal) {
      const send = async (token: string | null) => {
        const headers = new Headers({ 'Content-Type': 'application/json' })
        if (token) headers.set('authorization', `Bearer ${token}`)
        return fetcher(`${base}/v1/admin/db-dump`, {
          method: 'POST',
          headers,
          credentials: 'include',
          signal,
          body: JSON.stringify({ login_password: loginPassword }),
        })
      }
      let response = await send(options.getAccessToken?.() ?? refreshedToken)
      if (response.status === 401) {
        response = await send(await refreshSharedOrLocal(signal))
      }
      if (!response.ok) throwApiError(await readErrorBody(response), response.status)
      const blob = await response.blob()
      const disposition = response.headers.get('content-disposition') ?? ''
      const filename = /filename="([^"]+)"/.exec(disposition)?.[1] ?? 'sealero-db-dump.enc.json'
      return { filename, blob }
    },
  }
}
