/**
 * Cloud backup orchestration (PRD §9.1 cloud backup, KYV-46 decision).
 *
 * V1 destinations: Google Drive, Dropbox, WebDAV / NAS. Auto-backup is off by
 * default; once enabled it runs at most once a day (first check after unlock,
 * when idle) and only uploads when the vault changed since the last successful
 * backup. Each destination keeps the latest 7 files; older ones are deleted.
 * Backup filenames carry only a timestamp, never site or entry names.
 * Cloud credentials live only in local browser storage, never in the vault
 * backup (System Design §6).
 *
 * This module takes backup bytes as input through `BackupSource`. The v3
 * container bytes come from `buildBackupContainer` once the vault adapter
 * (KYV-29) exposes the DEK; until then the source returns null and the UI
 * reports export as unavailable instead of pretending to back up.
 */

export type CloudDestination = 'google-drive' | 'dropbox' | 'webdav'

export const CLOUD_DESTINATIONS: CloudDestination[] = ['google-drive', 'dropbox', 'webdav']

export const CLOUD_RETENTION_COUNT = 7
export const CLOUD_AUTO_BACKUP_INTERVAL_MS = 24 * 60 * 60 * 1000

export interface CloudFile {
  name: string
  /** Provider id when the provider uses ids for deletion (Drive); otherwise the name. */
  id?: string
  modifiedAt?: string | null
}

export interface CloudStorage {
  readonly destination: CloudDestination
  upload(filename: string, data: Uint8Array): Promise<void>
  list(): Promise<CloudFile[]>
  deleteFile(file: CloudFile): Promise<void>
}

/** Returns the encrypted backup bytes, or null when no export source exists yet. */
export type BackupSource = () => Promise<Uint8Array | null>

export interface CloudDestinationState {
  enabled: boolean
  connected: boolean
  lastBackupAt: string | null
  lastFingerprint: string | null
  lastError: string | null
  lastFileName: string | null
}

export type CloudState = Record<CloudDestination, CloudDestinationState>

export function defaultCloudState(): CloudState {
  const state = {} as CloudState
  for (const destination of CLOUD_DESTINATIONS) {
    state[destination] = { enabled: false, connected: false, lastBackupAt: null, lastFingerprint: null, lastError: null, lastFileName: null }
  }
  return state
}

export const CLOUD_STATE_STORAGE_KEY = 'sealero.cloud.state.v1'
export const CLOUD_CREDENTIALS_STORAGE_KEY = 'sealero.cloud.credentials.v1'

export interface KeyValueStorage {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
  removeItem(key: string): void
}

export function loadCloudState(storage: KeyValueStorage): CloudState {
  const defaults = defaultCloudState()
  try {
    const raw = storage.getItem(CLOUD_STATE_STORAGE_KEY)
    if (!raw) return defaults
    const parsed = JSON.parse(raw) as Partial<Record<CloudDestination, Partial<CloudDestinationState>>>
    for (const destination of CLOUD_DESTINATIONS) {
      const saved = parsed[destination]
      if (!saved) continue
      defaults[destination] = {
        enabled: saved.enabled === true,
        connected: saved.connected === true,
        lastBackupAt: typeof saved.lastBackupAt === 'string' ? saved.lastBackupAt : null,
        lastFingerprint: typeof saved.lastFingerprint === 'string' ? saved.lastFingerprint : null,
        lastError: typeof saved.lastError === 'string' ? saved.lastError : null,
        lastFileName: typeof saved.lastFileName === 'string' ? saved.lastFileName : null,
      }
    }
  } catch {
    return defaultCloudState()
  }
  return defaults
}

export function saveCloudState(storage: KeyValueStorage, state: CloudState): void {
  storage.setItem(CLOUD_STATE_STORAGE_KEY, JSON.stringify(state))
}

export interface CloudCredentials {
  'google-drive'?: OAuthTokenSet
  dropbox?: OAuthTokenSet
  webdav?: { baseUrl: string; username: string; password: string }
}

export function loadCloudCredentials(storage: KeyValueStorage): CloudCredentials {
  try {
    const raw = storage.getItem(CLOUD_CREDENTIALS_STORAGE_KEY)
    if (!raw) return {}
    const parsed = JSON.parse(raw) as Record<string, unknown>
    const credentials: CloudCredentials = {}
    for (const destination of ['google-drive', 'dropbox'] as const) {
      const entry = parsed[destination]
      if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
        const record = entry as Record<string, unknown>
        if (typeof record.accessToken === 'string' && record.accessToken) {
          credentials[destination] = {
            accessToken: record.accessToken,
            refreshToken: typeof record.refreshToken === 'string' ? record.refreshToken : null,
            expiresAt: typeof record.expiresAt === 'number' ? record.expiresAt : null,
          }
        }
      }
    }
    const webdav = parsed.webdav
    if (webdav && typeof webdav === 'object' && !Array.isArray(webdav)) {
      const record = webdav as Record<string, unknown>
      if (typeof record.baseUrl === 'string' && typeof record.username === 'string' && typeof record.password === 'string') {
        credentials.webdav = { baseUrl: record.baseUrl, username: record.username, password: record.password }
      }
    }
    return credentials
  } catch {
    return {}
  }
}

export function saveCloudCredentials(storage: KeyValueStorage, credentials: CloudCredentials): void {
  storage.setItem(CLOUD_CREDENTIALS_STORAGE_KEY, JSON.stringify(credentials))
}

/** `sealero-backup-20261124-120000.enc.json` — UTC timestamp only, no site or entry names. */
export function backupFilename(now: Date): string {
  const pad = (value: number, length = 2): string => String(value).padStart(length, '0')
  return `sealero-backup-${now.getUTCFullYear()}${pad(now.getUTCMonth() + 1)}${pad(now.getUTCDate())}-${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}${pad(now.getUTCSeconds())}.enc.json`
}

function isBackupFilename(name: string): boolean {
  return /^sealero-backup-\d{8}-\d{6}\.enc\.json$/.test(name)
}

/**
 * Vault fingerprint: SHA-256 over `id:updatedAt` lines sorted by id. The list
 * API does not expose item versions to the web, so updatedAt is the change
 * signal; when the adapter exposes versions, add them to the line format.
 */
export async function vaultFingerprint(items: { id: string; updatedAt: string }[]): Promise<string> {
  const lines = [...items]
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
    .map((item) => `${item.id}:${item.updatedAt}`)
    .join('\n')
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(lines))
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

/**
 * Files to delete so only the newest `keep` backup files remain. Sorts by
 * modified time, falling back to the timestamp embedded in the filename.
 */
export function selectRetentionDeletions(files: CloudFile[], keep: number = CLOUD_RETENTION_COUNT): CloudFile[] {
  const backups = files.filter((file) => isBackupFilename(file.name))
  const sorted = [...backups].sort((a, b) => {
    const aTime = a.modifiedAt ?? a.name
    const bTime = b.modifiedAt ?? b.name
    return aTime < bTime ? 1 : aTime > bTime ? -1 : 0
  })
  return sorted.slice(keep)
}

export type AutoBackupDecision =
  | { due: false; reason: 'disabled' | 'not-connected' | 'too-soon' | 'unchanged' }
  | { due: true; reason: 'due' }

/** Daily cadence, only when the vault changed since the last successful backup. */
export function shouldAutoBackup(state: CloudDestinationState, fingerprint: string, now: Date): AutoBackupDecision {
  if (!state.enabled) return { due: false, reason: 'disabled' }
  if (!state.connected) return { due: false, reason: 'not-connected' }
  if (state.lastBackupAt) {
    const last = new Date(state.lastBackupAt).getTime()
    if (Number.isFinite(last) && now.getTime() - last < CLOUD_AUTO_BACKUP_INTERVAL_MS) return { due: false, reason: 'too-soon' }
  }
  if (state.lastFingerprint !== null && state.lastFingerprint === fingerprint) return { due: false, reason: 'unchanged' }
  return { due: true, reason: 'due' }
}

export interface CloudBackupResult {
  filename: string
  deleted: string[]
}

/**
 * Uploads one backup and enforces retention. Throws on upload failure without
 * touching the stored state; the caller records `lastError` and leaves
 * `lastBackupAt`/`lastFingerprint` at their previous successful values.
 */
export async function runCloudBackup(
  storage: CloudStorage,
  backupBytes: Uint8Array,
  now: Date,
  keep: number = CLOUD_RETENTION_COUNT,
): Promise<CloudBackupResult> {
  const filename = backupFilename(now)
  await storage.upload(filename, backupBytes)
  const files = await storage.list()
  const deletions = selectRetentionDeletions(files, keep)
  const deleted: string[] = []
  for (const file of deletions) {
    await storage.deleteFile(file)
    deleted.push(file.name)
  }
  return { filename, deleted }
}

// ---------------------------------------------------------------------------
// OAuth PKCE helpers (Google Drive, Dropbox). Public clients: no client
// secret. The authorization code is exchanged by the settings page after the
// provider redirects back with `?cloud=<destination>&code=...&state=...`.
// ---------------------------------------------------------------------------

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}

export function randomPkceVerifier(randomBytes: (length: number) => Uint8Array = defaultRandomBytes): string {
  const bytes = randomBytes(32)
  return base64UrlEncode(bytes)
}

export async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return base64UrlEncode(new Uint8Array(digest))
}

function defaultRandomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)
  return bytes
}

export interface OAuthTokenSet {
  accessToken: string
  refreshToken: string | null
  /** Epoch milliseconds when the access token expires, or null when unknown. */
  expiresAt: number | null
}

export function parseOAuthTokenResponse(body: unknown): OAuthTokenSet {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('cloud_oauth_invalid_response')
  const record = body as Record<string, unknown>
  if (typeof record.access_token !== 'string' || !record.access_token) throw new Error('cloud_oauth_invalid_response')
  const expiresIn = typeof record.expires_in === 'number' ? record.expires_in : null
  return {
    accessToken: record.access_token,
    refreshToken: typeof record.refresh_token === 'string' ? record.refresh_token : null,
    expiresAt: expiresIn !== null ? Date.now() + expiresIn * 1000 : null,
  }
}

export function isTokenExpired(tokens: OAuthTokenSet, now: number = Date.now()): boolean {
  return tokens.expiresAt !== null && now >= tokens.expiresAt - 60_000
}
