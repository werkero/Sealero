import assert from 'node:assert/strict'
import test from 'node:test'
import { AdminApiError, createAdminClient } from '../src/client/admin.ts'

function jsonResponse(body: unknown, status = 200): Response {
  return Response.json(body, { status })
}

test('overview request sends the bearer token and returns the parsed body', async () => {
  let requestedUrl: RequestInfo | URL | undefined
  let requestInit: RequestInit | undefined
  const client = createAdminClient({
    apiBaseUrl: 'https://api.sealero.test/',
    getAccessToken: () => 'access-token',
    fetcher: async (input, init) => {
      requestedUrl = input
      requestInit = init
      return jsonResponse({
        total_users: 2,
        today_new_users: 1,
        today_active_users: 1,
        total_devices: 3,
        db_connections: 1,
        tombstone_cleanup: { last_cleanup_at: null, last_cleanup_status: null },
      })
    },
  })

  const overview = await client.getOverview()
  assert.equal(overview.total_users, 2)
  assert.equal(overview.tombstone_cleanup.last_cleanup_status, null)
  assert.equal(requestedUrl, 'https://api.sealero.test/v1/admin/overview')
  assert.equal(requestInit?.method, 'GET')
  const headers = new Headers(requestInit?.headers)
  assert.equal(headers.get('accept'), 'application/json')
  assert.equal(headers.get('authorization'), 'Bearer access-token')
  assert.equal(requestInit?.credentials, 'include')
})

test('user list builds the filter query and omits an empty search', async () => {
  let requestedUrl: RequestInfo | URL | undefined
  const client = createAdminClient({
    getAccessToken: () => 'access-token',
    fetcher: async (input) => {
      requestedUrl = input
      return jsonResponse({ users: [], total_count: 0, has_more: false, next_cursor: null })
    },
  })

  await client.listUsers({ search: '  ', status: 'disabled', verified: 'verified', role: 'admin', limit: 100 })
  const url = new URL(String(requestedUrl), 'https://web.sealero.test')
  assert.equal(url.pathname, '/v1/admin/users')
  assert.equal(url.searchParams.get('search'), null)
  assert.equal(url.searchParams.get('status'), 'disabled')
  assert.equal(url.searchParams.get('verified'), 'verified')
  assert.equal(url.searchParams.get('role'), 'admin')
  assert.equal(url.searchParams.get('limit'), '100')
})

test('user detail passes the login-history cursor through', async () => {
  let requestedUrl: RequestInfo | URL | undefined
  const client = createAdminClient({
    fetcher: async (input) => {
      requestedUrl = input
      return jsonResponse({ user: {}, devices: [], login_history: { items: [], total_count: 0, has_more: false, next_cursor: null } })
    },
  })

  await client.getUserDetail('2d647bb6-74b3-4f90-a5b8-4cf5dc41fef0', '9a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d', 50)
  const url = new URL(String(requestedUrl), 'https://web.sealero.test')
  assert.equal(url.pathname, '/v1/admin/users/2d647bb6-74b3-4f90-a5b8-4cf5dc41fef0')
  assert.equal(url.searchParams.get('login_cursor'), '9a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d')
  assert.equal(url.searchParams.get('login_limit'), '50')
})

test('settings update sends a PUT with only the supplied keys', async () => {
  let requestInit: RequestInit | undefined
  const client = createAdminClient({
    getAccessToken: () => 'access-token',
    fetcher: async (_input, init) => {
      requestInit = init
      return jsonResponse({ settings: {}, sources: {}, smtp_pass_configured: false, tombstone_retention_days: 30 })
    },
  })

  await client.updateSettings({ server_name: 'Sealero', max_vault_size_mb: 50, smtp_host: null })
  assert.equal(requestInit?.method, 'PUT')
  assert.equal(requestInit?.body, JSON.stringify({ server_name: 'Sealero', max_vault_size_mb: 50, smtp_host: null }))
})

test('a 401 refreshes the token once and retries with the new token', async () => {
  const calls: { url: string; authorization: string | null }[] = []
  let overviewCalls = 0
  const client = createAdminClient({
    getAccessToken: () => 'stale-token',
    fetcher: async (input, init) => {
      const url = String(input)
      const headers = new Headers(init?.headers)
      calls.push({ url, authorization: headers.get('authorization') })
      if (url.endsWith('/v1/auth/refresh')) {
        return jsonResponse({ access_token: 'fresh-token', device_id: 'device-1' })
      }
      overviewCalls += 1
      if (overviewCalls === 1) return jsonResponse({ code: 'invalid_token' }, 401)
      return jsonResponse({ total_users: 1 })
    },
  })

  const overview = await client.getOverview()
  assert.equal(overview.total_users, 1)
  assert.deepEqual(calls.map((call) => call.authorization), ['Bearer stale-token', null, 'Bearer fresh-token'])
  assert.equal(calls[1]?.url.endsWith('/v1/auth/refresh'), true)
  assert.equal(overviewCalls, 2)
})

test('a failed admin request surfaces the server error code and status', async () => {
  const client = createAdminClient({
    getAccessToken: () => 'access-token',
    fetcher: async () => jsonResponse({ code: 'admin_required', message: 'Administrator access is required.' }, 403),
  })

  await assert.rejects(
    client.disableUser('2d647bb6-74b3-4f90-a5b8-4cf5dc41fef0'),
    (error: unknown) => {
      assert.ok(error instanceof AdminApiError)
      assert.equal(error.code, 'admin_required')
      assert.equal(error.status, 403)
      assert.equal(error.message, 'Administrator access is required.')
      return true
    },
  )
})

test('password actions send only login_password in the JSON body', async () => {
  const bodies: string[] = []
  const client = createAdminClient({
    getAccessToken: () => 'access-token',
    fetcher: async (_input, init) => {
      bodies.push(String(init?.body ?? ''))
      return new Response(null, { status: 204 })
    },
  })

  await client.deleteUser('2d647bb6-74b3-4f90-a5b8-4cf5dc41fef0', 'correct-horse')
  await client.revokeAllDevices('2d647bb6-74b3-4f90-a5b8-4cf5dc41fef0', 'correct-horse')
  assert.deepEqual(bodies, [
    JSON.stringify({ login_password: 'correct-horse' }),
    JSON.stringify({ login_password: 'correct-horse' }),
  ])
})

test('db-dump download returns the filename from the response header and the blob', async () => {
  let requestedUrl: RequestInfo | URL | undefined
  const client = createAdminClient({
    getAccessToken: () => 'access-token',
    fetcher: async (input, init) => {
      requestedUrl = input
      assert.equal(init?.method, 'POST')
      assert.equal(init?.body, JSON.stringify({ login_password: 'correct-horse' }))
      return new Response(new Blob(['encrypted-bytes']), {
        status: 200,
        headers: {
          'content-type': 'application/octet-stream',
          'content-disposition': 'attachment; filename="sealero-db-dump-20261124-000000.enc.json"',
        },
      })
    },
  })

  const dump = await client.downloadDbDump('correct-horse')
  assert.equal(requestedUrl, '/v1/admin/db-dump')
  assert.equal(dump.filename, 'sealero-db-dump-20261124-000000.enc.json')
  assert.equal(await dump.blob.text(), 'encrypted-bytes')
})

test('no authorization header is sent when no token is held', async () => {
  let requestInit: RequestInit | undefined
  const client = createAdminClient({
    fetcher: async (_input, init) => {
      requestInit = init
      return jsonResponse({ total_users: 0 })
    },
  })

  await client.getOverview()
  const headers = new Headers(requestInit?.headers)
  assert.equal(headers.get('accept'), 'application/json')
  assert.equal(headers.get('authorization'), null)
})

test('a 401 uses the shared refresher and never calls the local refresh endpoint', async () => {
  const calls: { url: string; authorization: string | null }[] = []
  let sharedRefreshCalls = 0
  let overviewCalls = 0
  const client = createAdminClient({
    getAccessToken: () => 'stale-token',
    refreshAccessToken: async () => {
      sharedRefreshCalls += 1
      return 'shared-fresh-token'
    },
    fetcher: async (input, init) => {
      const url = String(input)
      const headers = new Headers(init?.headers)
      calls.push({ url, authorization: headers.get('authorization') })
      overviewCalls += 1
      if (overviewCalls === 1) return jsonResponse({ code: 'invalid_token' }, 401)
      return jsonResponse({ total_users: 1 })
    },
  })

  const overview = await client.getOverview()
  assert.equal(overview.total_users, 1)
  assert.equal(sharedRefreshCalls, 1)
  assert.equal(calls.some((call) => call.url.endsWith('/v1/auth/refresh')), false)
  assert.deepEqual(calls.map((call) => call.authorization), ['Bearer stale-token', 'Bearer shared-fresh-token'])
})

test('concurrent 401s share a single local refresh', async () => {
  let overviewCalls = 0
  let refreshCalls = 0
  const client = createAdminClient({
    getAccessToken: () => 'stale-token',
    fetcher: async (input, init) => {
      const url = String(input)
      if (url.endsWith('/v1/auth/refresh')) {
        refreshCalls += 1
        return jsonResponse({ access_token: 'fresh-token', device_id: 'device-1' })
      }
      overviewCalls += 1
      if (overviewCalls <= 2) return jsonResponse({ code: 'invalid_token' }, 401)
      return jsonResponse({ total_users: 1 })
    },
  })

  const [first, second] = await Promise.all([client.getOverview(), client.getOverview()])
  assert.equal(first.total_users, 1)
  assert.equal(second.total_users, 1)
  // One refresh for both requests: without the dedup guard each 401 would
  // fire its own refresh, and the server would see the second one as a
  // refresh-token reuse (revoking every device).
  assert.equal(refreshCalls, 1)
  assert.equal(overviewCalls, 4)
})
