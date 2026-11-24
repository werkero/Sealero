import assert from 'node:assert/strict'
import test from 'node:test'
import { parsePropfindHrefs, WebDavClient } from '../src/features/settings/cloud-webdav.ts'
import { buildDriveAuthUrl, DriveClient, exchangeDriveCode, refreshDriveToken } from '../src/features/settings/cloud-drive.ts'
import { buildDropboxAuthUrl, DropboxClient, exchangeDropboxCode } from '../src/features/settings/cloud-dropbox.ts'
import type { OAuthTokenSet } from '../src/features/settings/cloud-backup.ts'

type FetchCall = { url: string; init: RequestInit }
type FetchMock = (url: string, init?: RequestInit) => Promise<Response>

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function mockFetch(handler: (call: FetchCall) => Promise<Response>): { fetchFn: FetchMock; calls: FetchCall[] } {
  const calls: FetchCall[] = []
  const fetchFn: FetchMock = async (url, init = {}) => {
    const call = { url, init }
    calls.push(call)
    return handler(call)
  }
  return { fetchFn, calls }
}

const tokens: OAuthTokenSet = { accessToken: 'access-1', refreshToken: 'refresh-1', expiresAt: Date.now() + 3600_000 }

// --- WebDAV ---

test('WebDAV PROPFIND parsing extracts child names and ignores the collection itself', () => {
  const body = `<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:">
  <d:response><d:href>/dav/Sealero/</d:href></d:response>
  <d:response><d:href>/dav/Sealero/sealero-backup-20261124-120000.enc.json</d:href></d:response>
  <d:response><d:href>/dav/Sealero/sealero-backup-20261123-120000.enc.json</d:href></d:response>
</d:multistatus>`
  assert.deepEqual(parsePropfindHrefs(body), [
    '/dav/Sealero/',
    '/dav/Sealero/sealero-backup-20261124-120000.enc.json',
    '/dav/Sealero/sealero-backup-20261123-120000.enc.json',
  ])
})

test('WebDAV client uploads, lists, deletes and checks the connection with Basic auth', async () => {
  const { fetchFn, calls } = mockFetch(async (call) => {
    if (call.init.method === 'PUT') return new Response(null, { status: 201 })
    if (call.init.method === 'PROPFIND') {
      const depth = (call.init.headers as Record<string, string>).Depth
      if (depth === '0') return new Response(null, { status: 207 })
      return new Response(
        `<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/Sealero/</d:href></d:response><d:response><d:href>/dav/Sealero/sealero-backup-20261124-120000.enc.json</d:href></d:response></d:multistatus>`,
        { status: 207 },
      )
    }
    if (call.init.method === 'DELETE') return new Response(null, { status: 204 })
    return new Response(null, { status: 500 })
  })
  const client = new WebDavClient({ baseUrl: 'https://nas.example.test/dav/Sealero/', username: 'alice', password: 'secret', fetchFn })
  await client.testConnection()
  await client.upload('sealero-backup-20261124-120000.enc.json', new Uint8Array([1, 2, 3]))
  const files = await client.list()
  assert.deepEqual(files, [{ name: 'sealero-backup-20261124-120000.enc.json' }])
  await client.deleteFile({ name: 'sealero-backup-20261124-120000.enc.json' })

  const authHeader = `Basic ${Buffer.from('alice:secret').toString('base64')}`
  for (const call of calls) {
    assert.equal((call.init.headers as Record<string, string>).Authorization, authHeader)
  }
  assert.equal(calls[1]!.url, 'https://nas.example.test/dav/Sealero/sealero-backup-20261124-120000.enc.json')
  assert.equal(calls[1]!.init.method, 'PUT')
})

test('WebDAV rejects non-HTTP base URLs and missing usernames', () => {
  assert.throws(() => new WebDavClient({ baseUrl: 'ftp://example.test/dav', username: 'a', password: 'b' }), /cloud_webdav_invalid_url/)
  assert.throws(() => new WebDavClient({ baseUrl: 'https://nas.example.test/dav', username: '', password: 'b' }), /cloud_webdav_missing_credentials/)
})

test('WebDAV rejects plain HTTP to public hosts but allows local NAS addresses', () => {
  // Plain HTTP sends the Basic password in cleartext: only loopback and
  // private-network hosts are acceptable.
  assert.throws(() => new WebDavClient({ baseUrl: 'http://example.com/dav', username: 'a', password: 'b' }), /cloud_webdav_insecure_url/)
  assert.doesNotThrow(() => new WebDavClient({ baseUrl: 'http://192.168.1.10:8080/dav', username: 'a', password: 'b' }))
  assert.doesNotThrow(() => new WebDavClient({ baseUrl: 'http://10.0.0.5/dav', username: 'a', password: 'b' }))
  assert.doesNotThrow(() => new WebDavClient({ baseUrl: 'http://localhost:8080/dav', username: 'a', password: 'b' }))
  assert.doesNotThrow(() => new WebDavClient({ baseUrl: 'http://nas/dav', username: 'a', password: 'b' }))
})

test('WebDAV Basic auth encodes non-ASCII credentials as UTF-8', async () => {
  const { fetchFn, calls } = mockFetch(async () => new Response(null, { status: 207 }))
  const client = new WebDavClient({ baseUrl: 'https://nas.example.test/dav', username: 'alice', password: 'pässwörd', fetchFn })
  await client.testConnection()
  const expected = `Basic ${Buffer.from('alice:pässwörd', 'utf8').toString('base64')}`
  assert.equal((calls[0]!.init.headers as Record<string, string>).Authorization, expected)
})

// --- Google Drive ---

test('Drive OAuth URL carries PKCE, drive.file scope and offline access', () => {
  const url = new URL(buildDriveAuthUrl({ clientId: 'cid', redirectUri: 'https://app.example.test/settings', state: 's1', codeChallenge: 'cc1' }))
  assert.equal(url.hostname, 'accounts.google.com')
  assert.equal(url.searchParams.get('client_id'), 'cid')
  assert.equal(url.searchParams.get('scope'), 'https://www.googleapis.com/auth/drive.file')
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256')
  assert.equal(url.searchParams.get('access_type'), 'offline')
  assert.equal(url.searchParams.get('state'), 's1')
})

test('Drive code exchange and refresh parse tokens and keep the refresh token', async () => {
  const { fetchFn, calls } = mockFetch(async () => jsonResponse({ access_token: 'at2', refresh_token: 'rt2', expires_in: 3600 }))
  const exchanged = await exchangeDriveCode({ clientId: 'cid', redirectUri: 'https://app.example.test/settings', code: 'code1', codeVerifier: 'verifier1', fetchFn })
  assert.equal(exchanged.accessToken, 'at2')
  assert.equal(exchanged.refreshToken, 'rt2')
  assert.ok(exchanged.expiresAt !== null && exchanged.expiresAt > Date.now())
  const form = calls[0]!.init.body as URLSearchParams
  assert.equal(form.get('grant_type'), 'authorization_code')
  assert.equal(form.get('code_verifier'), 'verifier1')

  const { fetchFn: refreshFetch } = mockFetch(async () => jsonResponse({ access_token: 'at3', expires_in: 3600 }))
  const refreshed = await refreshDriveToken({ clientId: 'cid', refreshToken: 'rt2', fetchFn: refreshFetch })
  assert.equal(refreshed.accessToken, 'at3')
  assert.equal(refreshed.refreshToken, 'rt2')
})

test('Drive folder search only matches a folder in the Drive root', async () => {
  const { fetchFn, calls } = mockFetch(async () => jsonResponse({ files: [{ id: 'folder-9', name: 'Sealero' }] }))
  const client = new DriveClient({ clientId: 'cid', tokens, fetchFn })
  assert.equal(await client.findOrCreateFolder(), 'folder-9')
  const searchCall = calls.find((call) => call.url.includes('/drive/v3/files?q='))!
  const query = new URL(searchCall.url).searchParams.get('q')!
  // A same-named folder elsewhere in Drive must not be reused.
  assert.match(query, /'root' in parents/)
  assert.match(query, /name = 'Sealero'/)
})

test('Drive client finds or creates the Sealero folder, uploads, lists and deletes', async () => {
  const { fetchFn, calls } = mockFetch(async (call) => {
    if (call.url.includes('in%20parents')) {
      return jsonResponse({ files: [{ id: 'file-1', name: 'sealero-backup-20261124-120000.enc.json', modifiedTime: '2026-11-24T12:00:00.000Z' }] })
    }
    if (call.url.includes('/drive/v3/files?q=')) return jsonResponse({ files: [] })
    if (call.url === 'https://www.googleapis.com/drive/v3/files') return jsonResponse({ id: 'folder-1', name: 'Sealero' })
    if (call.url.includes('/upload/drive/v3/files')) return jsonResponse({ id: 'file-1', name: 'sealero-backup-20261124-120000.enc.json' })
    if (call.init.method === 'DELETE') return new Response(null, { status: 204 })
    return new Response(null, { status: 404 })
  })
  const client = new DriveClient({ clientId: 'cid', tokens, fetchFn })
  await client.upload('sealero-backup-20261124-120000.enc.json', new Uint8Array([1, 2, 3]))
  const files = await client.list()
  assert.deepEqual(files, [{ id: 'file-1', name: 'sealero-backup-20261124-120000.enc.json', modifiedAt: '2026-11-24T12:00:00.000Z' }])
  await client.deleteFile({ id: 'file-1', name: 'sealero-backup-20261124-120000.enc.json' })

  const uploadCall = calls.find((call) => call.url.includes('/upload/drive/v3/files'))!
  assert.equal((uploadCall.init.headers as Record<string, string>).Authorization, 'Bearer access-1')
  assert.match((uploadCall.init.headers as Record<string, string>)['Content-Type'], /^multipart\/related; boundary=/)
  const deleteCall = calls.find((call) => call.init.method === 'DELETE')!
  assert.equal(deleteCall.url, 'https://www.googleapis.com/drive/v3/files/file-1')
})

test('Drive client refreshes an expired access token before uploading', async () => {
  let refreshCalled = false
  const { fetchFn } = mockFetch(async (call) => {
    if (call.url === 'https://oauth2.googleapis.com/token') {
      refreshCalled = true
      return jsonResponse({ access_token: 'fresh-token', refresh_token: 'refresh-1', expires_in: 3600 })
    }
    if (call.url.includes('/drive/v3/files?q=')) return jsonResponse({ files: [{ id: 'folder-1' }] })
    if (call.url.includes('/upload/drive/v3/files')) return jsonResponse({ id: 'file-1' })
    return new Response(null, { status: 404 })
  })
  const expired: OAuthTokenSet = { accessToken: 'old', refreshToken: 'refresh-1', expiresAt: Date.now() - 1000 }
  const client = new DriveClient({ clientId: 'cid', tokens: expired, fetchFn })
  await client.upload('sealero-backup-20261124-120000.enc.json', new Uint8Array([1]))
  assert.equal(refreshCalled, true)
  assert.equal(client.currentTokens.accessToken, 'fresh-token')
})

// --- Dropbox ---

test('Dropbox OAuth URL carries PKCE and offline token access', () => {
  const url = new URL(buildDropboxAuthUrl({ clientId: 'cid', redirectUri: 'https://app.example.test/settings', state: 's2', codeChallenge: 'cc2' }))
  assert.equal(url.hostname, 'www.dropbox.com')
  assert.equal(url.searchParams.get('token_access_type'), 'offline')
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256')
})

test('Dropbox code exchange parses tokens', async () => {
  const { fetchFn } = mockFetch(async () => jsonResponse({ access_token: 'dat', refresh_token: 'drt', expires_in: 14400 }))
  const exchanged = await exchangeDropboxCode({ clientId: 'cid', redirectUri: 'https://app.example.test/settings', code: 'code9', codeVerifier: 'verifier9', fetchFn })
  assert.equal(exchanged.accessToken, 'dat')
  assert.equal(exchanged.refreshToken, 'drt')
})

test('Dropbox client uploads, lists and deletes under /Sealero', async () => {
  const { fetchFn, calls } = mockFetch(async (call) => {
    if (call.url.endsWith('/2/files/upload')) return jsonResponse({ name: 'sealero-backup-20261124-120000.enc.json' })
    if (call.url.endsWith('/2/files/list_folder')) {
      return jsonResponse({ entries: [{ '.tag': 'file', name: 'sealero-backup-20261124-120000.enc.json', server_modified: '2026-11-24T12:00:00Z' }, { '.tag': 'folder', name: 'other' }] })
    }
    if (call.url.endsWith('/2/files/delete_v2')) return jsonResponse({})
    return new Response(null, { status: 404 })
  })
  const client = new DropboxClient({ clientId: 'cid', tokens, fetchFn })
  await client.upload('sealero-backup-20261124-120000.enc.json', new Uint8Array([1, 2, 3]))
  const files = await client.list()
  assert.deepEqual(files, [{ name: 'sealero-backup-20261124-120000.enc.json', modifiedAt: '2026-11-24T12:00:00Z' }])
  await client.deleteFile({ name: 'sealero-backup-20261124-120000.enc.json' })

  const uploadCall = calls.find((call) => call.url.endsWith('/2/files/upload'))!
  const arg = JSON.parse((uploadCall.init.headers as Record<string, string>)['Dropbox-API-Arg'])
  assert.equal(arg.path, '/Sealero/sealero-backup-20261124-120000.enc.json')
  // Overwrite, not add: filenames only have second precision, so a second
  // backup within the same second must replace the first instead of 409ing.
  assert.equal(arg.mode, 'overwrite')
  const deleteCall = calls.find((call) => call.url.endsWith('/2/files/delete_v2'))!
  assert.equal(JSON.parse(deleteCall.init.body as string).path, '/Sealero/sealero-backup-20261124-120000.enc.json')
})

test('Dropbox list returns an empty list when the folder does not exist yet', async () => {
  const { fetchFn } = mockFetch(async () => new Response(JSON.stringify({ error_summary: 'path/not_found/' }), { status: 409 }))
  const client = new DropboxClient({ clientId: 'cid', tokens, fetchFn })
  assert.deepEqual(await client.list(), [])
})
