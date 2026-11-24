import assert from 'node:assert/strict'
import test from 'node:test'
import { probeAdminAccess } from '../src/client/admin-status.ts'

test('admin probe returns true on 200 and sends the bearer token when one is held', async () => {
  let requestedUrl: RequestInfo | URL | undefined
  let requestInit: RequestInit | undefined
  const result = await probeAdminAccess({
    apiBaseUrl: 'https://api.sealero.test/',
    getAccessToken: () => 'access-token',
    fetcher: async (input, init) => {
      requestedUrl = input
      requestInit = init
      return Response.json({ settings: {} }, { status: 200 })
    },
  })

  assert.equal(result, true)
  assert.equal(requestedUrl, 'https://api.sealero.test/v1/admin/settings')
  assert.equal(requestInit?.method, 'GET')
  assert.deepEqual(requestInit?.headers, { accept: 'application/json', authorization: 'Bearer access-token' })
  assert.equal(requestInit?.credentials, 'include')
  assert.equal(requestInit?.body, undefined)
})

test('admin probe returns false on 403 for an authenticated non-admin', async () => {
  const result = await probeAdminAccess({
    getAccessToken: () => 'access-token',
    fetcher: async () => Response.json({ code: 'admin_required' }, { status: 403 }),
  })
  assert.equal(result, false)
})

test('admin probe returns false on 401 without a token and sends no authorization header', async () => {
  let requestInit: RequestInit | undefined
  const result = await probeAdminAccess({
    fetcher: async (_input, init) => {
      requestInit = init
      return Response.json({ code: 'invalid_token' }, { status: 401 })
    },
  })
  assert.equal(result, false)
  assert.deepEqual(requestInit?.headers, { accept: 'application/json' })
})

test('admin probe returns false on network failure instead of throwing', async () => {
  const result = await probeAdminAccess({
    fetcher: async () => {
      throw new TypeError('fetch failed')
    },
  })
  assert.equal(result, false)
})
