import assert from 'node:assert/strict'
import test from 'node:test'
import { McpConfirmationApiError, createMcpConfirmationClient } from '../src/client/mcp-confirmations.ts'

function jsonResponse(body: unknown, status = 200): Response {
  return Response.json(body, { status })
}

const CONFIRMATION_ID = '00000000-0000-4000-8000-000000000405'

test('list request sends the bearer token and returns the parsed body', async () => {
  let requestedUrl: RequestInfo | URL | undefined
  let requestInit: RequestInit | undefined
  const client = createMcpConfirmationClient({
    apiBaseUrl: 'https://api.sealero.test/',
    getAccessToken: () => 'access-token',
    fetcher: async (input, init) => {
      requestedUrl = input
      requestInit = init
      return jsonResponse({
        confirmations: [{
          confirmation_id: CONFIRMATION_ID,
          item_id: '00000000-0000-4000-8000-000000000404',
          client_id: 'client-123',
          client_name: 'Test Connector',
          status: 'pending',
          expires_at: '2026-11-24T12:05:00.000Z',
          created_at: '2026-11-24T12:00:00.000Z',
        }],
      })
    },
  })

  const list = await client.listConfirmations()
  assert.equal(list.confirmations.length, 1)
  assert.equal(list.confirmations[0].status, 'pending')
  assert.equal(requestedUrl, 'https://api.sealero.test/v1/mcp/confirmations')
  assert.equal(requestInit?.method, 'GET')
  const headers = new Headers(requestInit?.headers)
  assert.equal(headers.get('accept'), 'application/json')
  assert.equal(headers.get('authorization'), 'Bearer access-token')
  assert.equal(requestInit?.credentials, 'include')
})

test('approve and deny post to the confirmation decision endpoints', async () => {
  const requestedUrls: string[] = []
  const client = createMcpConfirmationClient({
    getAccessToken: () => 'access-token',
    fetcher: async (input, init) => {
      requestedUrls.push(String(input))
      const method = init?.method
      assert.equal(method, 'POST')
      return jsonResponse({ confirmation_id: CONFIRMATION_ID, status: 'approved' })
    },
  })

  const approved = await client.approveConfirmation(CONFIRMATION_ID)
  assert.equal(approved.status, 'approved')
  const denied = await client.denyConfirmation(CONFIRMATION_ID)
  assert.equal(denied.confirmation_id, CONFIRMATION_ID)
  assert.deepEqual(requestedUrls, [
    `/v1/mcp/confirmations/${CONFIRMATION_ID}/approve`,
    `/v1/mcp/confirmations/${CONFIRMATION_ID}/deny`,
  ])
})

test('a 401 refreshes the token once and retries with the new token', async () => {
  const calls: { url: string; authorization: string | null }[] = []
  let listCalls = 0
  const client = createMcpConfirmationClient({
    getAccessToken: () => 'stale-token',
    fetcher: async (input, init) => {
      const url = String(input)
      const headers = new Headers(init?.headers)
      calls.push({ url, authorization: headers.get('authorization') })
      if (url.endsWith('/v1/auth/refresh')) {
        return jsonResponse({ access_token: 'fresh-token' })
      }
      listCalls += 1
      if (listCalls === 1) return jsonResponse({ code: 'invalid_token' }, 401)
      return jsonResponse({ confirmations: [] })
    },
  })

  const list = await client.listConfirmations()
  assert.deepEqual(list.confirmations, [])
  assert.deepEqual(calls.map((call) => call.authorization), ['Bearer stale-token', null, 'Bearer fresh-token'])
  assert.equal(calls[1]?.url.endsWith('/v1/auth/refresh'), true)
  assert.equal(listCalls, 2)
})

test('a failed confirmation request surfaces the server error code and status', async () => {
  const client = createMcpConfirmationClient({
    getAccessToken: () => 'access-token',
    fetcher: async () => jsonResponse({ code: 'confirmation_expired', message: 'This confirmation has expired.' }, 409),
  })

  await assert.rejects(
    client.approveConfirmation(CONFIRMATION_ID),
    (error: unknown) => {
      assert.ok(error instanceof McpConfirmationApiError)
      assert.equal(error.code, 'confirmation_expired')
      assert.equal(error.status, 409)
      assert.equal(error.message, 'This confirmation has expired.')
      return true
    },
  )
})

test('a 401 uses the shared refresher and never calls the local refresh endpoint', async () => {
  const calls: { url: string; authorization: string | null }[] = []
  let sharedRefreshCalls = 0
  let listCalls = 0
  const client = createMcpConfirmationClient({
    getAccessToken: () => 'stale-token',
    refreshAccessToken: async () => {
      sharedRefreshCalls += 1
      return 'shared-fresh-token'
    },
    fetcher: async (input, init) => {
      const url = String(input)
      const headers = new Headers(init?.headers)
      calls.push({ url, authorization: headers.get('authorization') })
      listCalls += 1
      if (listCalls === 1) return jsonResponse({ code: 'invalid_token' }, 401)
      return jsonResponse({ confirmations: [] })
    },
  })

  const list = await client.listConfirmations()
  assert.deepEqual(list.confirmations, [])
  assert.equal(sharedRefreshCalls, 1)
  assert.equal(calls.some((call) => call.url.endsWith('/v1/auth/refresh')), false)
  assert.deepEqual(calls.map((call) => call.authorization), ['Bearer stale-token', 'Bearer shared-fresh-token'])
})

test('concurrent 401s share a single local refresh', async () => {
  let listCalls = 0
  let refreshCalls = 0
  const client = createMcpConfirmationClient({
    getAccessToken: () => 'stale-token',
    fetcher: async (input, init) => {
      const url = String(input)
      if (url.endsWith('/v1/auth/refresh')) {
        refreshCalls += 1
        return jsonResponse({ access_token: 'fresh-token' })
      }
      listCalls += 1
      if (listCalls <= 2) return jsonResponse({ code: 'invalid_token' }, 401)
      return jsonResponse({ confirmations: [] })
    },
  })

  const [first, second] = await Promise.all([client.listConfirmations(), client.listConfirmations()])
  assert.deepEqual(first.confirmations, [])
  assert.deepEqual(second.confirmations, [])
  // One refresh for both requests: without the dedup guard each 401 would
  // fire its own refresh, and the server would see the second one as a
  // refresh-token reuse (revoking every device).
  assert.equal(refreshCalls, 1)
  assert.equal(listCalls, 4)
})
