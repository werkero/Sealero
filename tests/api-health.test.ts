import assert from 'node:assert/strict'
import test from 'node:test'
import {
  ApiHealthClientError,
  createApiHealthClient,
  type ApiHealthResponse,
} from '../src/client/api-health.ts'

const healthResponse: ApiHealthResponse = {
  api_version: 'v1',
  supported_api_versions: ['v1'],
  min_app_versions: { android: null, ios: null, web: '1.2.0' },
  server_time: '2026-11-23T05:00:00.123Z',
  server_name: 'Sealero staging',
}

test('GET /v1/health sends no credentials or body and accepts the exact documented response', async () => {
  let requestedUrl: RequestInfo | URL | undefined
  let requestInit: RequestInit | undefined
  const client = createApiHealthClient({
    apiBaseUrl: 'https://api.sealero.test/',
    fetcher: async (input, init) => {
      requestedUrl = input
      requestInit = init
      return Response.json(healthResponse)
    },
  })

  assert.deepEqual(await client.getHealth(), healthResponse)
  assert.equal(requestedUrl, 'https://api.sealero.test/v1/health')
  assert.equal(requestInit?.method, 'GET')
  assert.deepEqual(requestInit?.headers, { accept: 'application/json' })
  assert.equal(requestInit?.credentials, 'omit')
  assert.equal(requestInit?.cache, 'no-store')
  assert.equal(requestInit?.body, undefined)
  assert.ok(requestInit?.signal instanceof AbortSignal)
})

test('GET /v1/health uses the same-origin route by default and supplies a cancellable signal', async () => {
  let requestedUrl: RequestInfo | URL | undefined
  let receivedSignal: AbortSignal | null | undefined
  const client = createApiHealthClient({
    fetcher: async (input, init) => {
      requestedUrl = input
      receivedSignal = init?.signal
      return Response.json(healthResponse)
    },
  })

  await client.getHealth()
  assert.equal(requestedUrl, '/v1/health')
  assert.ok(receivedSignal instanceof AbortSignal)
  assert.equal(receivedSignal.aborted, false)
})

test('non-2xx responses surface only a safe status error', async () => {
  const client = createApiHealthClient({
    fetcher: async () => Response.json({ code: 'auth_runtime_unavailable', message: 'details are not shown' }, { status: 503 }),
  })

  await assert.rejects(client.getHealth(), (error: unknown) => (
    error instanceof ApiHealthClientError && error.code === 'http_error' && error.status === 503
  ))
})

test('malformed JSON and contract drift fail closed', async () => {
  const invalidPayloads = [
    new Response('{', { status: 200, headers: { 'content-type': 'application/json' } }),
    Response.json({ ...healthResponse, unexpected: true }),
    Response.json({ ...healthResponse, min_app_versions: { android: null, ios: null } }),
    Response.json({ ...healthResponse, supported_api_versions: ['v2'] }),
    Response.json({ ...healthResponse, server_time: 'not-a-time' }),
  ]

  for (const response of invalidPayloads) {
    const client = createApiHealthClient({ fetcher: async () => response })
    await assert.rejects(client.getHealth(), (error: unknown) => (
      error instanceof ApiHealthClientError && error.code === 'invalid_response'
    ))
  }
})

test('caller cancellation aborts the active fetch without being classified as a timeout', async () => {
  const callerController = new AbortController()
  let fetchSignal: AbortSignal | null | undefined
  const client = createApiHealthClient({
    timeoutMs: 1_000,
    fetcher: async (_input, init) => new Promise<Response>((_resolve, reject) => {
      fetchSignal = init?.signal
      fetchSignal?.addEventListener('abort', () => reject(fetchSignal?.reason), { once: true })
    }),
  })

  const request = client.getHealth(callerController.signal)
  callerController.abort()
  await assert.rejects(request, (error: unknown) => error instanceof Error && error.name === 'AbortError')
  assert.equal(fetchSignal?.aborted, true)
})

test('a hanging health request is aborted at the timeout and returns a safe timeout error', async () => {
  let fetchSignal: AbortSignal | null | undefined
  const client = createApiHealthClient({
    timeoutMs: 10,
    fetcher: async (_input, init) => new Promise<Response>((_resolve, reject) => {
      fetchSignal = init?.signal
      fetchSignal?.addEventListener('abort', () => reject(fetchSignal?.reason), { once: true })
    }),
  })

  await assert.rejects(client.getHealth(), (error: unknown) => (
    error instanceof ApiHealthClientError && error.code === 'timeout'
  ))
  assert.equal(fetchSignal?.aborted, true)
})

test('a completed health request clears its pending timeout', async () => {
  let fetchSignal: AbortSignal | null | undefined
  const client = createApiHealthClient({
    timeoutMs: 10,
    fetcher: async (_input, init) => {
      fetchSignal = init?.signal
      return Response.json(healthResponse)
    },
  })

  assert.deepEqual(await client.getHealth(), healthResponse)
  await new Promise((resolve) => setTimeout(resolve, 20))
  assert.equal(fetchSignal?.aborted, false)
})

test('the health client can be retried successfully after a timed-out request', async () => {
  let attempts = 0
  const client = createApiHealthClient({
    timeoutMs: 10,
    fetcher: async (_input, init) => {
      attempts += 1
      if (attempts === 1) {
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(init.signal?.reason), { once: true })
        })
      }
      return Response.json(healthResponse)
    },
  })

  await assert.rejects(client.getHealth(), (error: unknown) => (
    error instanceof ApiHealthClientError && error.code === 'timeout'
  ))
  assert.deepEqual(await client.getHealth(), healthResponse)
  assert.equal(attempts, 2)
})
