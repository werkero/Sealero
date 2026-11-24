import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import test from 'node:test'
import {
  backupFilename,
  base64UrlEncode,
  defaultCloudState,
  isTokenExpired,
  loadCloudState,
  parseOAuthTokenResponse,
  pkceChallenge,
  randomPkceVerifier,
  runCloudBackup,
  saveCloudState,
  selectRetentionDeletions,
  shouldAutoBackup,
  vaultFingerprint,
  type CloudFile,
  type CloudStorage,
  type KeyValueStorage,
} from '../src/features/settings/cloud-backup.ts'

function memoryStorage(initial: Record<string, string> = {}): KeyValueStorage {
  const store = new Map(Object.entries(initial))
  return {
    getItem: (key) => store.get(key) ?? null,
    setItem: (key, value) => { store.set(key, value) },
    removeItem: (key) => { store.delete(key) },
  }
}

test('backup filenames carry only a UTC timestamp, never site or entry names', () => {
  assert.equal(backupFilename(new Date('2026-11-24T12:34:56.789Z')), 'sealero-backup-20261124-123456.enc.json')
  assert.equal(backupFilename(new Date('2026-01-05T03:04:05.000Z')), 'sealero-backup-20260105-030405.enc.json')
})

test('vault fingerprint is order-independent and changes on any update', async () => {
  const a = [{ id: 'id-2', updatedAt: '2026-11-21T10:00:00.000Z' }, { id: 'id-1', updatedAt: '2026-11-20T08:00:00.000Z' }]
  const b = [{ id: 'id-1', updatedAt: '2026-11-20T08:00:00.000Z' }, { id: 'id-2', updatedAt: '2026-11-21T10:00:00.000Z' }]
  const fingerprintA = await vaultFingerprint(a)
  assert.equal(fingerprintA, await vaultFingerprint(b))
  assert.equal(fingerprintA.length, 64)
  const changed = await vaultFingerprint([{ id: 'id-1', updatedAt: '2026-11-20T08:00:00.000Z' }, { id: 'id-2', updatedAt: '2026-11-22T10:00:00.000Z' }])
  assert.notEqual(changed, fingerprintA)
  // Cross-check against Node crypto on the canonical line format.
  const expected = createHash('sha256').update('id-1:2026-11-20T08:00:00.000Z\nid-2:2026-11-21T10:00:00.000Z').digest('hex')
  assert.equal(fingerprintA, expected)
})

test('retention keeps the newest 7 backup files and deletes the oldest', () => {
  const files: CloudFile[] = Array.from({ length: 10 }, (_, index) => ({
    name: `sealero-backup-202611${String(index + 1).padStart(2, '0')}-120000.enc.json`,
    modifiedAt: `2026-11-${String(index + 1).padStart(2, '0')}T12:00:00.000Z`,
  }))
  files.push({ name: 'notes.txt' }, { name: 'sealero-backup-20261111-120000.enc.json' })
  const deletions = selectRetentionDeletions(files, 7)
  assert.deepEqual(deletions.map((file) => file.name), [
    'sealero-backup-20261104-120000.enc.json',
    'sealero-backup-20261103-120000.enc.json',
    'sealero-backup-20261102-120000.enc.json',
    'sealero-backup-20261101-120000.enc.json',
  ])
  assert.equal(selectRetentionDeletions(files.slice(0, 7), 7).length, 0)
  assert.equal(selectRetentionDeletions([], 7).length, 0)
})

test('auto-backup is off by default, daily, and only when the vault changed', () => {
  const state = defaultCloudState()['google-drive']
  const now = new Date('2026-11-24T12:00:00.000Z')
  assert.deepEqual(shouldAutoBackup(state, 'abc', now), { due: false, reason: 'disabled' })

  const enabled = { ...state, enabled: true }
  assert.deepEqual(shouldAutoBackup(enabled, 'abc', now), { due: false, reason: 'not-connected' })

  const connected = { ...enabled, connected: true }
  assert.deepEqual(shouldAutoBackup(connected, 'abc', now), { due: true, reason: 'due' })

  const recent = { ...connected, lastBackupAt: '2026-11-24T06:00:00.000Z', lastFingerprint: 'xyz' }
  assert.deepEqual(shouldAutoBackup(recent, 'abc', now), { due: false, reason: 'too-soon' })

  const oldSame = { ...connected, lastBackupAt: '2026-11-23T06:00:00.000Z', lastFingerprint: 'abc' }
  assert.deepEqual(shouldAutoBackup(oldSame, 'abc', now), { due: false, reason: 'unchanged' })

  const oldChanged = { ...connected, lastBackupAt: '2026-11-23T06:00:00.000Z', lastFingerprint: 'xyz' }
  assert.deepEqual(shouldAutoBackup(oldChanged, 'abc', now), { due: true, reason: 'due' })
})

test('cloud state survives a localStorage round-trip and corrupt data falls back to defaults', () => {
  const storage = memoryStorage()
  const state = defaultCloudState()
  state.dropbox = { enabled: true, connected: true, lastBackupAt: '2026-11-24T12:00:00.000Z', lastFingerprint: 'abc', lastError: null, lastFileName: 'sealero-backup-20261124-120000.enc.json' }
  saveCloudState(storage, state)
  const loaded = loadCloudState(storage)
  assert.equal(loaded.dropbox.enabled, true)
  assert.equal(loaded.dropbox.lastFileName, 'sealero-backup-20261124-120000.enc.json')
  assert.equal(loaded['google-drive'].enabled, false)

  const corrupt = memoryStorage({ 'sealero.cloud.state.v1': '{not json' })
  assert.deepEqual(loadCloudState(corrupt), defaultCloudState())
  assert.deepEqual(loadCloudState(memoryStorage()), defaultCloudState())
})

test('PKCE verifier and challenge follow RFC 7636', async () => {
  const verifier = randomPkceVerifier()
  assert.match(verifier, /^[A-Za-z0-9_-]{43}$/)
  const challenge = await pkceChallenge(verifier)
  const expected = createHash('sha256').update(verifier).digest('base64').replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
  assert.equal(challenge, expected)
  assert.equal(base64UrlEncode(new Uint8Array([0, 1, 2, 255])), 'AAEC_w')
})

test('OAuth token parsing keeps refresh tokens and expiry; expiry has a 60s margin', () => {
  const tokens = parseOAuthTokenResponse({ access_token: 'at', refresh_token: 'rt', expires_in: 3600 })
  assert.equal(tokens.accessToken, 'at')
  assert.equal(tokens.refreshToken, 'rt')
  assert.ok(tokens.expiresAt !== null && tokens.expiresAt > Date.now())
  assert.equal(isTokenExpired({ accessToken: 'at', refreshToken: null, expiresAt: Date.now() + 30_000 }), true)
  assert.equal(isTokenExpired({ accessToken: 'at', refreshToken: null, expiresAt: Date.now() + 3600_000 }), false)
  assert.equal(isTokenExpired({ accessToken: 'at', refreshToken: null, expiresAt: null }), false)
  assert.throws(() => parseOAuthTokenResponse({}), /cloud_oauth_invalid_response/)
  assert.throws(() => parseOAuthTokenResponse({ access_token: '' }), /cloud_oauth_invalid_response/)
})

class FakeStorage implements CloudStorage {
  readonly destination = 'webdav' as const
  readonly uploaded: { filename: string; data: Uint8Array }[] = []
  readonly deleted: string[] = []
  files: CloudFile[]

  constructor(files: CloudFile[]) {
    this.files = files
  }

  async upload(filename: string, data: Uint8Array): Promise<void> {
    this.uploaded.push({ filename, data })
    this.files.push({ name: filename, modifiedAt: new Date().toISOString() })
  }

  async list(): Promise<CloudFile[]> {
    return [...this.files]
  }

  async deleteFile(file: CloudFile): Promise<void> {
    this.deleted.push(file.name)
    this.files = this.files.filter((entry) => entry.name !== file.name)
  }
}

test('runCloudBackup uploads once and deletes only files beyond the newest 7', async () => {
  const existing: CloudFile[] = Array.from({ length: 7 }, (_, index) => ({
    name: `sealero-backup-202611${String(index + 1).padStart(2, '0')}-120000.enc.json`,
    modifiedAt: `2026-11-${String(index + 1).padStart(2, '0')}T12:00:00.000Z`,
  }))
  const storage = new FakeStorage(existing)
  const result = await runCloudBackup(storage, new Uint8Array([1, 2, 3]), new Date('2026-11-24T12:00:00.000Z'))
  assert.equal(result.filename, 'sealero-backup-20261124-120000.enc.json')
  assert.equal(storage.uploaded.length, 1)
  assert.deepEqual(result.deleted, ['sealero-backup-20261101-120000.enc.json'])
  assert.deepEqual(storage.deleted, ['sealero-backup-20261101-120000.enc.json'])
})

test('runCloudBackup throws on upload failure without touching the file list', async () => {
  const storage = new FakeStorage([])
  storage.upload = async () => { throw new Error('cloud_upload_failed') }
  await assert.rejects(runCloudBackup(storage, new Uint8Array([1]), new Date('2026-11-24T12:00:00.000Z')), /cloud_upload_failed/)
  assert.equal(storage.deleted.length, 0)
})
