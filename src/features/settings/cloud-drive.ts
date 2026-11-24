import { base64UrlEncode, isTokenExpired, parseOAuthTokenResponse, pkceChallenge, type CloudFile, type CloudStorage, type OAuthTokenSet } from './cloud-backup.ts'

/**
 * Google Drive destination (PRD §9.1: V1). Files live in a `Sealero` folder in
 * the user's Drive root (visible to the user, so they can delete backups
 * manually). Scope is `drive.file`: the app only sees files it created.
 *
 * OAuth is PKCE (public client, no client secret). The client id comes from
 * `VITE_GOOGLE_DRIVE_CLIENT_ID`; without it the provider reports
 * `not-configured` and connect stays disabled. Tokens live only in local
 * browser storage (System Design §6).
 */

export const DRIVE_FOLDER_NAME = 'Sealero'
export const DRIVE_SCOPE = 'https://www.googleapis.com/auth/drive.file'

export interface DriveOAuthConfig {
  clientId: string
  redirectUri: string
  fetchFn?: typeof fetch
}

export function buildDriveAuthUrl(config: { clientId: string; redirectUri: string; state: string; codeChallenge: string }): string {
  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: 'code',
    scope: DRIVE_SCOPE,
    state: config.state,
    code_challenge: config.codeChallenge,
    code_challenge_method: 'S256',
    access_type: 'offline',
    prompt: 'consent',
  })
  return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`
}

export async function exchangeDriveCode(config: DriveOAuthConfig & { code: string; codeVerifier: string }): Promise<OAuthTokenSet> {
  const fetchFn = config.fetchFn ?? fetch
  const body = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    code: config.code,
    code_verifier: config.codeVerifier,
    grant_type: 'authorization_code',
  })
  const response = await fetchFn('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  })
  if (!response.ok) throw new Error('cloud_oauth_exchange_failed')
  return parseOAuthTokenResponse(await response.json())
}

export async function refreshDriveToken(config: Pick<DriveOAuthConfig, 'clientId' | 'fetchFn'> & { refreshToken: string }): Promise<OAuthTokenSet> {
  const fetchFn = config.fetchFn ?? fetch
  const body = new URLSearchParams({
    client_id: config.clientId,
    grant_type: 'refresh_token',
    refresh_token: config.refreshToken,
  })
  const response = await fetchFn('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  })
  if (!response.ok) throw new Error('cloud_oauth_refresh_failed')
  const tokens = parseOAuthTokenResponse(await response.json())
  return { ...tokens, refreshToken: tokens.refreshToken ?? config.refreshToken }
}

interface DriveFileEntry {
  id: string
  name: string
  modifiedTime?: string
  size?: string
}

export class DriveClient implements CloudStorage {
  readonly destination = 'google-drive' as const
  private readonly clientId: string
  private readonly fetchFn: typeof fetch
  private tokens: OAuthTokenSet
  private folderId: string | null = null

  constructor(config: { clientId: string; tokens: OAuthTokenSet; fetchFn?: typeof fetch }) {
    if (!config.clientId) throw new Error('cloud_not_configured')
    this.clientId = config.clientId
    this.tokens = config.tokens
    this.fetchFn = config.fetchFn ?? fetch
  }

  /** Current tokens (updated after a refresh); the caller persists them. */
  get currentTokens(): OAuthTokenSet {
    return this.tokens
  }

  private async accessToken(): Promise<string> {
    if (!isTokenExpired(this.tokens)) return this.tokens.accessToken
    if (!this.tokens.refreshToken) throw new Error('cloud_oauth_refresh_failed')
    this.tokens = await refreshDriveToken({ clientId: this.clientId, refreshToken: this.tokens.refreshToken, fetchFn: this.fetchFn })
    return this.tokens.accessToken
  }

  private async authorizedFetch(url: string, init: RequestInit = {}): Promise<Response> {
    const token = await this.accessToken()
    return this.fetchFn(url, {
      ...init,
      headers: { Authorization: `Bearer ${token}`, ...(init.headers ?? {}) },
    })
  }

  private async findOrCreateFolder(): Promise<string> {
    if (this.folderId) return this.folderId
    // Only a folder in the Drive root counts: a same-named folder elsewhere
    // must not be reused. `orderBy=createdTime` makes the pick deterministic
    // when several root folders share the name (oldest wins).
    const query = `name = '${DRIVE_FOLDER_NAME}' and mimeType = 'application/vnd.google-apps.folder' and 'root' in parents and trashed = false`
    const listResponse = await this.authorizedFetch(`https://www.googleapis.com/drive/v3/files?q=${encodeURIComponent(query)}&fields=files(id,name)&orderBy=createdTime`)
    if (!listResponse.ok) throw new Error('cloud_list_failed')
    const list = (await listResponse.json()) as { files?: DriveFileEntry[] }
    const existing = list.files?.[0]
    if (existing) {
      this.folderId = existing.id
      return existing.id
    }
    const createResponse = await this.authorizedFetch('https://www.googleapis.com/drive/v3/files', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: DRIVE_FOLDER_NAME, mimeType: 'application/vnd.google-apps.folder' }),
    })
    if (!createResponse.ok) throw new Error('cloud_upload_failed')
    const created = (await createResponse.json()) as DriveFileEntry
    this.folderId = created.id
    return created.id
  }

  async upload(filename: string, data: Uint8Array): Promise<void> {
    const folderId = await this.findOrCreateFolder()
    const boundary = `sealero-${base64UrlEncode(crypto.getRandomValues(new Uint8Array(12)))}`
    const metadata = JSON.stringify({ name: filename, parents: [folderId] })
    const parts = [
      `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${metadata}\r\n`,
      `--${boundary}\r\nContent-Type: application/octet-stream\r\n\r\n`,
    ]
    const head = new TextEncoder().encode(parts.join(''))
    const tail = new TextEncoder().encode(`\r\n--${boundary}--`)
    const body = new Uint8Array(head.length + data.length + tail.length)
    body.set(head, 0)
    body.set(data, head.length)
    body.set(tail, head.length + data.length)
    const response = await this.authorizedFetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart', {
      method: 'POST',
      headers: { 'Content-Type': `multipart/related; boundary=${boundary}` },
      body: body as BodyInit,
    })
    if (!response.ok) throw new Error('cloud_upload_failed')
  }

  async list(): Promise<CloudFile[]> {
    const folderId = await this.findOrCreateFolder()
    const query = `'${folderId}' in parents and trashed = false`
    const response = await this.authorizedFetch(
      `https://www.googleapis.com/drive/v3/files?q=${encodeURIComponent(query)}&fields=files(id,name,modifiedTime,size)&orderBy=createdTime desc&pageSize=100`,
    )
    if (!response.ok) throw new Error('cloud_list_failed')
    const body = (await response.json()) as { files?: DriveFileEntry[] }
    return (body.files ?? []).map((file) => ({ id: file.id, name: file.name, modifiedAt: file.modifiedTime ?? null }))
  }

  async deleteFile(file: CloudFile): Promise<void> {
    if (!file.id) throw new Error('cloud_delete_failed')
    const response = await this.authorizedFetch(`https://www.googleapis.com/drive/v3/files/${encodeURIComponent(file.id)}`, { method: 'DELETE' })
    if (!response.ok && response.status !== 404) throw new Error('cloud_delete_failed')
  }
}

export { pkceChallenge }
