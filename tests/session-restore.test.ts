import assert from 'node:assert/strict'
import { afterEach, describe, test } from 'node:test'
import { createHttpVaultClient, VaultApiError } from '../src/client/http-vault-client.ts'

/**
 * Client-level coverage for the startup session restore (AppShell calls
 * refreshAccessToken, then getCurrentUser). The React hook itself and the
 * landing markup are not covered here: this repo has no jsdom or component
 * renderer, so those paths are verified by typecheck, build, and a browser
 * click-through.
 */

interface FetchCall {
  readonly url: string
  readonly method: string
  readonly authorization: string | null
}

const originalFetch = globalThis.fetch
afterEach(() => {
  globalThis.fetch = originalFetch
})

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function installStub(refreshStatus: number, meBody: unknown): FetchCall[] {
  const calls: FetchCall[] = []
  globalThis.fetch = async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(typeof input === 'string' ? input : input.url)
    const headers = new Headers(init?.headers)
    calls.push({ url, method: init?.method ?? 'GET', authorization: headers.get('authorization') })
    if (url.endsWith('/v1/auth/refresh')) {
      return refreshStatus === 200
        ? jsonResponse({ access_token: 'new-access-token', device_id: 'device-1' }, 200)
        : jsonResponse({ code: 'unauthorized' }, refreshStatus)
    }
    if (url.endsWith('/v1/auth/me')) {
      return jsonResponse(meBody, 200)
    }
    return jsonResponse({ code: 'not_found' }, 404)
  }
  return calls
}

describe('startup session restore', () => {
  test('refresh + /me recovers the login identity', async () => {
    const calls = installStub(200, { id: 'user-1', email: 'alice@example.test' })
    const client = createHttpVaultClient()
    const token = await client.refreshAccessToken()
    assert.equal(token, 'new-access-token')
    const identity = await client.getCurrentUser()
    assert.deepEqual(identity, { id: 'user-1', email: 'alice@example.test' })
    assert.deepEqual(
      calls.map((call) => `${call.method} ${call.url}`),
      ['POST /v1/auth/refresh', 'GET /v1/auth/me'],
    )
    assert.equal(calls[1]!.authorization, 'Bearer new-access-token')
  })

  test('a 401 from refresh keeps the session logged out', async () => {
    installStub(401, { id: 'user-1', email: 'alice@example.test' })
    const client = createHttpVaultClient()
    await assert.rejects(
      client.refreshAccessToken(),
      (error: unknown) => error instanceof VaultApiError && error.status === 401,
    )
  })

  test('getCurrentUser without a refresh throws before any fetch', async () => {
    const calls = installStub(200, { id: 'user-1', email: 'alice@example.test' })
    const client = createHttpVaultClient()
    await assert.rejects(
      client.getCurrentUser(),
      (error: unknown) => error instanceof VaultApiError && error.status === 401,
    )
    assert.equal(calls.length, 0)
  })

  test('a malformed /me body is treated as unauthorized', async () => {
    installStub(200, { id: 1, email: null })
    const client = createHttpVaultClient()
    await client.refreshAccessToken()
    await assert.rejects(
      client.getCurrentUser(),
      (error: unknown) => error instanceof VaultApiError && error.status === 401,
    )
  })
})
