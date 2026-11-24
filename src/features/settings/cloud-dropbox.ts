import { isTokenExpired, parseOAuthTokenResponse, type CloudFile, type CloudStorage, type OAuthTokenSet } from './cloud-backup.ts'

/**
 * Dropbox destination (PRD §9.1: V1). Files live in `/Sealero` in the user's
 * Dropbox (visible to the user, so they can delete backups manually).
 * Upload auto-creates the folder. OAuth is PKCE (public client, no client
 * secret). The client id comes from `VITE_DROPBOX_CLIENT_ID`; without it the
 * provider reports `not-configured`. Tokens live only in local browser
 * storage (System Design §6).
 */

export const DROPBOX_FOLDER = '/Sealero'

export interface DropboxOAuthConfig {
  clientId: string
  redirectUri: string
  fetchFn?: typeof fetch
}

export function buildDropboxAuthUrl(config: { clientId: string; redirectUri: string; state: string; codeChallenge: string }): string {
  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: 'code',
    state: config.state,
    code_challenge: config.codeChallenge,
    code_challenge_method: 'S256',
    token_access_type: 'offline',
  })
  return `https://www.dropbox.com/oauth2/authorize?${params.toString()}`
}

export async function exchangeDropboxCode(config: DropboxOAuthConfig & { code: string; codeVerifier: string }): Promise<OAuthTokenSet> {
  const fetchFn = config.fetchFn ?? fetch
  const body = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    code: config.code,
    code_verifier: config.codeVerifier,
    grant_type: 'authorization_code',
  })
  const response = await fetchFn('https://api.dropboxapi.com/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  })
  if (!response.ok) throw new Error('cloud_oauth_exchange_failed')
  return parseOAuthTokenResponse(await response.json())
}

export async function refreshDropboxToken(config: Pick<DropboxOAuthConfig, 'clientId' | 'fetchFn'> & { refreshToken: string }): Promise<OAuthTokenSet> {
  const fetchFn = config.fetchFn ?? fetch
  const body = new URLSearchParams({
    client_id: config.clientId,
    grant_type: 'refresh_token',
    refresh_token: config.refreshToken,
  })
  const response = await fetchFn('https://api.dropboxapi.com/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  })
  if (!response.ok) throw new Error('cloud_oauth_refresh_failed')
  const tokens = parseOAuthTokenResponse(await response.json())
  return { ...tokens, refreshToken: tokens.refreshToken ?? config.refreshToken }
}

interface DropboxEntry {
  '.tag': string
  name: string
  path_lower?: string
  client_modified?: string
  server_modified?: string
  size?: number
}

export class DropboxClient implements CloudStorage {
  readonly destination = 'dropbox' as const
  private readonly clientId: string
  private readonly fetchFn: typeof fetch
  private tokens: OAuthTokenSet

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
    this.tokens = await refreshDropboxToken({ clientId: this.clientId, refreshToken: this.tokens.refreshToken, fetchFn: this.fetchFn })
    return this.tokens.accessToken
  }

  private async authorizedFetch(url: string, init: RequestInit = {}): Promise<Response> {
    const token = await this.accessToken()
    return this.fetchFn(url, {
      ...init,
      headers: { Authorization: `Bearer ${token}`, ...(init.headers ?? {}) },
    })
  }

  async upload(filename: string, data: Uint8Array): Promise<void> {
    const response = await this.authorizedFetch('https://content.dropboxapi.com/2/files/upload', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        // Overwrite the previous backup of the same second: with `add` the
        // upload would fail (409) whenever two backups land within one
        // second, and the filename only has second precision.
        'Dropbox-API-Arg': JSON.stringify({ path: `${DROPBOX_FOLDER}/${filename}`, mode: 'overwrite', autorename: false, mute: true }),
      },
      body: data as BodyInit,
    })
    if (!response.ok) throw new Error('cloud_upload_failed')
  }

  async list(): Promise<CloudFile[]> {
    const response = await this.authorizedFetch('https://api.dropboxapi.com/2/files/list_folder', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: DROPBOX_FOLDER, recursive: false, limit: 100 }),
    })
    if (response.status === 409) return []
    if (!response.ok) throw new Error('cloud_list_failed')
    const body = (await response.json()) as { entries?: DropboxEntry[] }
    return (body.entries ?? [])
      .filter((entry) => entry['.tag'] === 'file')
      .map((entry) => ({ name: entry.name, modifiedAt: entry.server_modified ?? entry.client_modified ?? null }))
  }

  async deleteFile(file: CloudFile): Promise<void> {
    const response = await this.authorizedFetch('https://api.dropboxapi.com/2/files/delete_v2', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: `${DROPBOX_FOLDER}/${file.name}` }),
    })
    if (!response.ok && response.status !== 409) throw new Error('cloud_delete_failed')
  }
}
