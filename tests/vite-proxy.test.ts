import assert from 'node:assert/strict'
import test from 'node:test'
import { createApiProxy, DEFAULT_API_PROXY_TARGET, resolveApiProxyTarget } from '../vite-proxy.ts'

test('Vite proxies same-origin /v1 calls to the README API port by default and supports an override', () => {
  const defaultTarget = resolveApiProxyTarget(undefined)
  assert.equal(defaultTarget, 'http://localhost:3000')
  assert.equal(defaultTarget, DEFAULT_API_PROXY_TARGET)
  assert.deepEqual(createApiProxy(defaultTarget), {
    '/v1': { target: 'http://localhost:3000', changeOrigin: true },
  })

  const configuredTarget = resolveApiProxyTarget(' http://127.0.0.1:3100/ ')
  assert.equal(configuredTarget, 'http://127.0.0.1:3100/')
  assert.deepEqual(createApiProxy(configuredTarget), {
    '/v1': { target: 'http://127.0.0.1:3100/', changeOrigin: true },
  })
})
