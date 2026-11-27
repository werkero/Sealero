import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { VaultIdentity, VaultListItem } from '../../client/contracts'
import { Button } from '../../components/ui/button'
import { Input } from '../../components/ui/input'
import {
  CLOUD_DESTINATIONS,
  loadCloudCredentials,
  loadCloudState,
  pkceChallenge,
  randomPkceVerifier,
  runCloudBackup,
  saveCloudCredentials,
  saveCloudState,
  shouldAutoBackup,
  vaultFingerprint,
  type CloudCredentials,
  type CloudDestination,
  type CloudState,
  type KeyValueStorage,
} from './cloud-backup.ts'
import { buildDriveAuthUrl, DriveClient, exchangeDriveCode } from './cloud-drive.ts'
import { buildDropboxAuthUrl, DropboxClient, exchangeDropboxCode } from './cloud-dropbox.ts'
import { WebDavClient } from './cloud-webdav.ts'

/**
 * Cloud backup settings (PRD §9.1, KYV-46). V1 destinations: Google Drive,
 * Dropbox, WebDAV / NAS. Auto-backup defaults off; once enabled it runs at
 * most once a day and only when the vault changed. Each destination keeps the
 * latest 7 files. Credentials live only in local browser storage.
 *
 * The backup bytes come from the vault adapter's narrow `exportBackup`
 * (KEK-only v3 container, System Design §7.4); the DEK never leaves the
 * adapter. When the vault is locked the source returns null and the panel
 * reports export as unavailable instead of uploading an empty or fake file.
 */

const OAUTH_STATE_KEY = 'sealero.cloud.oauth.state'
const OAUTH_VERIFIER_KEY = 'sealero.cloud.oauth.verifier'

const providerLabels: Record<CloudDestination, string> = {
  'google-drive': 'Google Drive',
  dropbox: 'Dropbox',
  webdav: 'WebDAV / NAS',
}

const providerMarks: Record<CloudDestination, string> = {
  'google-drive': 'G',
  dropbox: 'D',
  webdav: 'W',
}

function browserStorage(): KeyValueStorage {
  if (typeof localStorage !== 'undefined') return localStorage
  const store = new Map<string, string>()
  return {
    getItem: (key) => store.get(key) ?? null,
    setItem: (key, value) => { store.set(key, value) },
    removeItem: (key) => { store.delete(key) },
  }
}

const storage = browserStorage()

function oauthClientId(destination: 'google-drive' | 'dropbox'): string | undefined {
  const value = destination === 'google-drive'
    ? (import.meta.env.VITE_GOOGLE_DRIVE_CLIENT_ID as string | undefined)
    : (import.meta.env.VITE_DROPBOX_CLIENT_ID as string | undefined)
  return value?.trim() ? value.trim() : undefined
}

export function CloudBackupPanel({ user, items, exportBackup }: {
  user: VaultIdentity
  items: VaultListItem[]
  /** KEK-only v3 container from the vault adapter; null when the vault is locked. */
  exportBackup: () => Promise<Uint8Array | null>
}) {
  const { t } = useTranslation(['backup'])
  const [cloudState, setCloudState] = useState<CloudState>(() => loadCloudState(storage))
  const [cloudCredentials, setCloudCredentials] = useState<CloudCredentials>(() => loadCloudCredentials(storage))
  const [cloudBusy, setCloudBusy] = useState<Record<CloudDestination, boolean>>({ 'google-drive': false, dropbox: false, webdav: false })
  const [cloudNotice, setCloudNotice] = useState<Record<CloudDestination, string>>({ 'google-drive': '', dropbox: '', webdav: '' })
  const [fingerprint, setFingerprint] = useState<string | null>(null)
  const [webdavForm, setWebdavForm] = useState(() => ({
    baseUrl: '',
    username: '',
    password: '',
  }))
  const [webdavEditing, setWebdavEditing] = useState(false)

  useEffect(() => {
    let active = true
    void vaultFingerprint(items)
      .then((value) => { if (active) setFingerprint(value) })
      .catch(() => {})
    return () => { active = false }
  }, [items])

  useEffect(() => {
    setWebdavForm((current) => ({
      baseUrl: current.baseUrl || cloudCredentials.webdav?.baseUrl || '',
      username: current.username || cloudCredentials.webdav?.username || '',
      password: current.password,
    }))
  }, [cloudCredentials.webdav])

  /**
   * Applies a state update and persists the resulting value. Updates are
   * functional (`prev => next`) so concurrent backups (one per destination,
   * fired together by the auto-backup effect) never overwrite each other
   * with a stale mount-time closure. Persisting inside the updater saves
   * the same JSON twice under StrictMode's dev double-invoke; the write
   * is idempotent.
   */
  const persistState = useCallback((update: (current: CloudState) => CloudState) => {
    setCloudState((current) => {
      const next = update(current)
      saveCloudState(storage, next)
      return next
    })
  }, [])

  const persistCredentials = useCallback((update: (current: CloudCredentials) => CloudCredentials) => {
    setCloudCredentials((current) => {
      const next = update(current)
      saveCloudCredentials(storage, next)
      return next
    })
  }, [])

  const redirectUri = (import.meta.env.VITE_OAUTH_REDIRECT_URI as string | undefined)
    ?? `${window.location.origin}/users/${user.id}/settings`

  // Completes an OAuth redirect: ?cloud=<destination>&code=...&state=...
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const destination = params.get('cloud')
    const code = params.get('code')
    const state = params.get('state')
    if ((destination !== 'google-drive' && destination !== 'dropbox') || !code || !state) return
    let savedState: { destination: string; nonce: string } | null = null
    try {
      savedState = JSON.parse(sessionStorage.getItem(OAUTH_STATE_KEY) ?? 'null') as { destination: string; nonce: string } | null
    } catch {
      savedState = null
    }
    const verifier = sessionStorage.getItem(OAUTH_VERIFIER_KEY)
    sessionStorage.removeItem(OAUTH_STATE_KEY)
    sessionStorage.removeItem(OAUTH_VERIFIER_KEY)
    window.history.replaceState({}, '', window.location.pathname)
    if (!savedState || savedState.destination !== destination || savedState.nonce !== state || !verifier) {
      setCloudNotice((current) => ({ ...current, [destination]: 'backup:authFailed' }))
      return
    }
    const clientId = oauthClientId(destination)
    if (!clientId) {
      setCloudNotice((current) => ({ ...current, [destination]: 'backup:notConfigured' }))
      return
    }
    const exchange = destination === 'google-drive'
      ? exchangeDriveCode({ clientId, redirectUri, code, codeVerifier: verifier })
      : exchangeDropboxCode({ clientId, redirectUri, code, codeVerifier: verifier })
    void exchange.then((tokens) => {
      persistCredentials((current) => ({ ...current, [destination]: tokens }))
      persistState((current) => ({ ...current, [destination]: { ...current[destination], connected: true, lastError: null } }))
      setCloudNotice((current) => ({ ...current, [destination]: 'backup:connected' }))
    }).catch(() => {
      setCloudNotice((current) => ({ ...current, [destination]: 'backup:authFailed' }))
    })
    // Runs once on mount to consume the OAuth redirect.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const buildStorage = useCallback((destination: CloudDestination) => {
    if (destination === 'webdav') {
      const credentials = cloudCredentials.webdav
      if (!credentials) throw new Error('cloud_not_connected')
      return new WebDavClient({ baseUrl: credentials.baseUrl, username: credentials.username, password: credentials.password })
    }
    const tokens = cloudCredentials[destination]
    if (!tokens) throw new Error('cloud_not_connected')
    const clientId = oauthClientId(destination)
    if (!clientId) throw new Error('cloud_not_configured')
    return destination === 'google-drive'
      ? new DriveClient({ clientId, tokens })
      : new DropboxClient({ clientId, tokens })
  }, [cloudCredentials])

  // In-flight guard as a ref (not the `cloudBusy` state): two backups for
  // the same destination started in one tick must not both pass the check.
  const cloudBusyRef = useRef(new Set<CloudDestination>())
  const attemptBackup = useCallback(async (destination: CloudDestination) => {
    if (cloudBusyRef.current.has(destination)) return
    cloudBusyRef.current.add(destination)
    setCloudBusy((current) => ({ ...current, [destination]: true }))
    setCloudNotice((current) => ({ ...current, [destination]: '' }))
    try {
      const bytes = await exportBackup()
      if (!bytes) {
        setCloudNotice((current) => ({ ...current, [destination]: 'backup:exportVaultLocked' }))
        return
      }
      const client = buildStorage(destination)
      const result = await runCloudBackup(client, bytes, new Date())
      if ((client instanceof DriveClient || client instanceof DropboxClient) && destination !== 'webdav' && client.currentTokens.accessToken !== cloudCredentials[destination]?.accessToken) {
        persistCredentials((current) => ({ ...current, [destination]: client.currentTokens }))
      }
      persistState((current) => ({
        ...current,
        [destination]: { ...current[destination], lastBackupAt: new Date().toISOString(), lastFingerprint: fingerprint, lastError: null, lastFileName: result.filename },
      }))
      setCloudNotice((current) => ({ ...current, [destination]: 'backup:backupDone' }))
    } catch {
      persistState((current) => ({
        ...current,
        [destination]: { ...current[destination], lastError: 'cloud_upload_failed' },
      }))
      setCloudNotice((current) => ({ ...current, [destination]: 'backup:backupFailed' }))
    } finally {
      cloudBusyRef.current.delete(destination)
      setCloudBusy((current) => ({ ...current, [destination]: false }))
    }
  }, [buildStorage, cloudCredentials, exportBackup, fingerprint, persistCredentials, persistState])

  // Auto-backup: once per mount, after the vault fingerprint is known, run
  // every enabled + connected destination whose backup is due (daily
  // cadence, only when the vault changed). The busy guard inside
  // attemptBackup keeps a destination from running twice.
  const autoBackupRanRef = useRef(false)
  useEffect(() => {
    if (!fingerprint || autoBackupRanRef.current) return
    autoBackupRanRef.current = true
    for (const destination of CLOUD_DESTINATIONS) {
      if (shouldAutoBackup(cloudState[destination], fingerprint, new Date()).due) {
        void attemptBackup(destination)
      }
    }
    // Intentionally once per mount; state is read from the mount-time closure.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fingerprint])

  const connectOAuth = useCallback(async (destination: 'google-drive' | 'dropbox') => {
    const clientId = oauthClientId(destination)
    if (!clientId) {
      setCloudNotice((current) => ({ ...current, [destination]: 'backup:notConfigured' }))
      return
    }
    setCloudBusy((current) => ({ ...current, [destination]: true }))
    try {
      const verifier = randomPkceVerifier()
      const challenge = await pkceChallenge(verifier)
      const nonce = randomPkceVerifier()
      sessionStorage.setItem(OAUTH_STATE_KEY, JSON.stringify({ destination, nonce }))
      sessionStorage.setItem(OAUTH_VERIFIER_KEY, verifier)
      const url = destination === 'google-drive'
        ? buildDriveAuthUrl({ clientId, redirectUri, state: nonce, codeChallenge: challenge })
        : buildDropboxAuthUrl({ clientId, redirectUri, state: nonce, codeChallenge: challenge })
      window.location.assign(url)
    } finally {
      setCloudBusy((current) => ({ ...current, [destination]: false }))
    }
  }, [redirectUri])

  const connectWebdav = useCallback(async () => {
    const baseUrl = webdavForm.baseUrl.trim()
    const username = webdavForm.username.trim()
    if (!baseUrl || !username || !webdavForm.password) {
      setCloudNotice((current) => ({ ...current, webdav: 'backup:connectionFailed' }))
      return
    }
    setCloudBusy((current) => ({ ...current, webdav: true }))
    try {
      const client = new WebDavClient({ baseUrl, username, password: webdavForm.password })
      await client.testConnection()
      persistCredentials((current) => ({ ...current, webdav: { baseUrl, username, password: webdavForm.password } }))
      persistState((current) => ({ ...current, webdav: { ...current.webdav, connected: true, lastError: null } }))
      setWebdavEditing(false)
      setCloudNotice((current) => ({ ...current, webdav: 'backup:connectionOk' }))
    } catch {
      setCloudNotice((current) => ({ ...current, webdav: 'backup:connectionFailed' }))
    } finally {
      setCloudBusy((current) => ({ ...current, webdav: false }))
    }
  }, [persistCredentials, persistState, webdavForm])

  const disconnect = useCallback((destination: CloudDestination) => {
    persistCredentials((current) => {
      const next = { ...current }
      delete next[destination]
      return next
    })
    persistState((current) => ({
      ...current,
      [destination]: { ...current[destination], connected: false, enabled: false, lastBackupAt: null, lastFingerprint: null, lastError: null, lastFileName: null },
    }))
    setCloudNotice((current) => ({ ...current, [destination]: '' }))
    if (destination === 'webdav') {
      setWebdavForm({ baseUrl: '', username: '', password: '' })
      setWebdavEditing(false)
    }
  }, [persistCredentials, persistState])

  const toggleAutoBackup = useCallback((destination: CloudDestination) => {
    persistState((current) => ({
      ...current,
      [destination]: { ...current[destination], enabled: !current[destination].enabled },
    }))
  }, [persistState])

  const formatLastBackup = (value: string | null): string => {
    if (!value) return t('backup:neverBackedUp')
    try {
      return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
    } catch {
      return value
    }
  }

  return (
    <>
      <p className="text-sm text-muted-foreground">{t('backup:cloudPosition')}</p>
      <div className="flex flex-col gap-3">
        {CLOUD_DESTINATIONS.map((destination) => {
          const state = cloudState[destination]
          const isOAuth = destination !== 'webdav'
          const clientId = isOAuth ? oauthClientId(destination) : undefined
          const configured = !isOAuth || clientId !== undefined
          const decision = fingerprint ? shouldAutoBackup(state, fingerprint, new Date()) : null
          return (
            <div className="flex flex-wrap items-start gap-3 rounded-lg bg-muted px-4 py-3" key={destination}>
              <span className="grid size-9 shrink-0 place-items-center rounded-lg bg-background text-sm font-bold" aria-hidden="true">{providerMarks[destination]}</span>
              <div className="min-w-0 flex-1">
                <strong className="block text-sm font-medium">{providerLabels[destination]}</strong>
                <span className="block text-xs text-muted-foreground">{t('backup:providerV1')}</span>
                <span className="block text-xs text-muted-foreground">{state.connected ? t('backup:connected') : configured ? t('backup:notConnected') : t('backup:notConfigured')}</span>
                <span className="block text-xs text-muted-foreground">{t('backup:lastBackup')}: {formatLastBackup(state.lastBackupAt)}</span>
                {state.connected && decision ? <span className="block text-xs text-muted-foreground">{decision.due ? t('backup:dueNow') : decision.reason === 'unchanged' ? t('backup:upToDate') : decision.reason === 'too-soon' ? t('backup:tooSoon') : t('backup:autoBackupOff')}</span> : null}
                {cloudNotice[destination] ? <span className="block text-xs font-medium text-primary" role="status">{t(cloudNotice[destination])}</span> : null}
                {destination === 'webdav' && (!state.connected || webdavEditing) ? (
                  <span className="mt-2 grid gap-2">
                    <label className="grid gap-1.5"><span className="text-xs font-medium">{t('backup:webdavUrl')}</span><Input type="url" value={webdavForm.baseUrl} placeholder="https://nas.example.test/dav/Sealero" onChange={(event) => setWebdavForm((current) => ({ ...current, baseUrl: event.target.value }))} /></label>
                    {webdavForm.baseUrl.trim().toLowerCase().startsWith('http://') ? (
                      <span className="text-xs font-medium text-amber-600 dark:text-amber-400" role="note">{t('backup:webdavInsecureWarning')}</span>
                    ) : null}
                    <label className="grid gap-1.5"><span className="text-xs font-medium">{t('backup:webdavUsername')}</span><Input type="text" value={webdavForm.username} autoComplete="username" onChange={(event) => setWebdavForm((current) => ({ ...current, username: event.target.value }))} /></label>
                    <label className="grid gap-1.5"><span className="text-xs font-medium">{t('backup:webdavPassword')}</span><Input type="password" value={webdavForm.password} autoComplete="current-password" onChange={(event) => setWebdavForm((current) => ({ ...current, password: event.target.value }))} /></label>
                  </span>
                ) : null}
              </div>
              {state.connected ? (
                <>
                  <Button variant="outline" size="sm" type="button" disabled={cloudBusy[destination]} onClick={() => void attemptBackup(destination)}>
                    {cloudBusy[destination] ? t('backup:backingUp') : t('backup:backupNow')}
                  </Button>
                  <Button variant="outline" size="sm" type="button" onClick={() => toggleAutoBackup(destination)} aria-pressed={state.enabled}>
                    {state.enabled ? t('backup:autoBackupOn') : t('backup:autoBackupOff')}
                  </Button>
                  <Button variant="outline" size="sm" type="button" onClick={() => disconnect(destination)}>{t('backup:disconnect')}</Button>
                </>
              ) : destination === 'webdav' ? (
                <>
                  <Button variant="outline" size="sm" type="button" disabled={cloudBusy.webdav} onClick={() => void connectWebdav()}>
                    {t('backup:saveAndTest')}
                  </Button>
                  {webdavEditing ? (
                    <Button variant="outline" size="sm" type="button" onClick={() => setWebdavEditing(false)}>{t('backup:cancel')}</Button>
                  ) : null}
                </>
              ) : (
                <Button variant="outline" size="sm" type="button" disabled={!configured || cloudBusy[destination]} onClick={() => void connectOAuth(destination)}>
                  {configured ? t('backup:connect') : t('backup:connectUnavailable')}
                </Button>
              )}
              {destination === 'webdav' && state.connected && !webdavEditing ? (
                <Button variant="outline" size="sm" type="button" onClick={() => setWebdavEditing(true)}>{t('backup:edit')}</Button>
              ) : null}
            </div>
          )
        })}
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="grid gap-1 rounded-lg bg-muted px-4 py-3"><span className="text-xs text-muted-foreground">{t('backup:autoBackupLabel')}</span><strong className="text-sm font-medium">{t('backup:autoBackupOff')}</strong><small className="text-xs text-muted-foreground">{t('backup:autoBackupPolicy')}</small></div>
        <div className="grid gap-1 rounded-lg bg-muted px-4 py-3"><span className="text-xs text-muted-foreground">{t('backup:retentionLabel')}</span><strong className="text-sm font-medium">{t('backup:retentionValue')}</strong><small className="text-xs text-muted-foreground">{t('backup:retentionPolicy')}</small></div>
      </div>
      <p className="text-xs leading-relaxed text-muted-foreground">{t('backup:credentialsBoundary')}</p>
    </>
  )
}
