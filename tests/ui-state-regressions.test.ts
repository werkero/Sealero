import assert from 'node:assert/strict'
import test from 'node:test'
import { hasIdleExpired, IDLE_LOCK_MS, remainingIdleMs } from '../src/hooks/auto-lock-policy.ts'
import { clearClipboardIfStillCurrent, createClipboardOperationQueue } from '../src/features/password-security/clipboard.ts'
import { buildDetailJson, decryptBlock, encryptBlock, importDek, parseDetailJson } from '../src/client/crypto.ts'

test('idle lock fires at exactly 15 minutes but not before', () => {
  assert.equal(IDLE_LOCK_MS, 15 * 60_000)
  assert.equal(hasIdleExpired(1_000, 1_000 + 15 * 60_000 - 1), false)
  assert.equal(hasIdleExpired(1_000, 1_000 + 15 * 60_000), true)
  assert.equal(hasIdleExpired(1_000, 1_000 + 16 * 60_000), true)
  assert.equal(remainingIdleMs(1_000, 1_000 + 60_000), 14 * 60_000)
})

test('clipboard expiry clears only the same still-current app copy', async () => {
  let clipboardValue = 'copied-secret'
  let writes = 0
  const clipboard = {
    async readText() { return clipboardValue },
    async writeText(value: string) { clipboardValue = value; writes += 1 },
  }
  const outcome = await clearClipboardIfStillCurrent(clipboard, 'copied-secret', () => true)
  assert.equal(outcome, 'cleared')
  assert.equal(clipboardValue, '')
  assert.equal(writes, 1)
})

test('a newer serialized copy wins when it starts during an in-flight cleanup write', async () => {
  let clipboardValue = 'copied-secret'
  let releaseClear!: () => void
  let notifyClearStarted!: () => void
  const clearStarted = new Promise<void>((resolve) => { notifyClearStarted = resolve })
  const pendingClear = new Promise<void>((resolve) => { releaseClear = resolve })
  const clipboard = {
    async readText() { return clipboardValue },
    async writeText(value: string) {
      if (value === '') {
        notifyClearStarted()
        await pendingClear
      }
      clipboardValue = value
    },
  }
  const queue = createClipboardOperationQueue()
  const cleanup = queue.run(() => clearClipboardIfStillCurrent(clipboard, 'copied-secret', () => true))
  await clearStarted
  const newerCopy = queue.run(async () => clipboard.writeText('newer-copy'))

  assert.equal(clipboardValue, 'copied-secret')
  releaseClear()
  assert.equal(await cleanup, 'cleared')
  await newerCopy
  assert.equal(clipboardValue, 'newer-copy')
})

test('stale clipboard timers cannot clear a newer copy and external clipboard values are preserved', async () => {
  let readCount = 0
  let writeCount = 0
  const clipboard = {
    async readText() { readCount += 1; return 'newer-external-value' },
    async writeText() { writeCount += 1 },
  }
  assert.equal(await clearClipboardIfStillCurrent(clipboard, 'old-value', () => false), 'stale')
  assert.equal(readCount, 0)
  assert.equal(await clearClipboardIfStillCurrent(clipboard, 'old-value', () => true), 'replaced')
  assert.equal(writeCount, 0)
})

test('clipboard read/write permission failure is explicit to the caller and never silently clears another value', async () => {
  let writeCount = 0
  const clipboard = {
    async readText() { throw new Error('permission_denied') },
    async writeText() { writeCount += 1 },
  }
  assert.equal(await clearClipboardIfStillCurrent(clipboard, 'copied-secret', () => true), 'failed')
  assert.equal(writeCount, 0)
})

test('recovery-code used state is UI-only: the stored detail carries no used flag', async () => {
  const dekBytes = new Uint8Array(32)
  crypto.getRandomValues(dekBytes)
  const dek = await importDek(dekBytes)
  const input = {
    name: 'Example',
    url: 'https://example.com',
    username: 'alice',
    password: 'correct-horse-battery-staple',
    note: '',
    category: '',
    tags: [],
    favorite: false,
    icon: 'E',
    recoveryCodes: [{ id: 'recovery-1', value: 'DEMO-7H2K-Q9PX' }],
  }
  const sealed = await encryptBlock(dek, 'user-1', 'item-1', 'detail', buildDetailJson(input))
  const reopened = parseDetailJson(await decryptBlock(dek, 'user-1', 'item-1', 'detail', sealed.ciphertext, sealed.nonce))
  assert.ok(reopened.recoveryCodes?.some((code) => code.id === 'recovery-1'))
  assert.equal('used' in (reopened.recoveryCodes?.[0] ?? {}), false)
  assert.deepEqual(reopened.recoveryCodes, [{ id: 'recovery-1', value: 'DEMO-7H2K-Q9PX' }])
})
