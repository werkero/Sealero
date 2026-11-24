import assert from 'node:assert/strict'
import { createCipheriv, randomBytes } from 'node:crypto'
import test from 'node:test'
import { createHttpVaultClient, VaultApiError } from '../src/client/http-vault-client.ts'
import { buildDetailJson, buildOverviewJson, deriveKek, deriveRecoveryWrappingKey } from '../src/client/crypto.ts'
import { inspectBackupContainer } from '../src/features/settings/backup-local.ts'
import { decryptBackupBlock, unwrapBackupDek, verifyBackupIntegrity } from '../src/features/settings/backup-export.ts'

const userId = '123e4567-e89b-42d3-a456-426614174000'
const masterPassword = 'correct-horse-battery-staple'
const recoveryKey = `${'abandon '.repeat(23)}art`
const kdfParams = '{"algorithm":"argon2id","m":65536,"output_len":32,"p":4,"t":3}'
const kdfSalt = Buffer.alloc(16, 2).toString('base64')
const dek = new Uint8Array(32).fill(9)
const itemId = '10000000-0000-4000-8000-000000000001'

/** AES-256-GCM seal with node:crypto; ciphertext is ct+tag, base64. */
function sealBytes(key: Uint8Array, aad: string, plaintext: Uint8Array): { ciphertext: string; nonce: string } {
  const nonce = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(key), nonce)
  cipher.setAAD(Buffer.from(aad, 'utf8'))
  const sealed = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final(), cipher.getAuthTag()])
  return { ciphertext: sealed.toString('base64'), nonce: nonce.toString('base64') }
}

function fakeJwt(sub: string): string {
  const b64url = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url')
  return `${b64url({ alg: 'RS256', typ: 'JWT' })}.${b64url({ sub })}.signature`
}

interface Fixture {
  kek: Uint8Array
  vaultKey: Record<string, unknown>
  listPage: Record<string, unknown>
}

async function buildFixture(): Promise<Fixture> {
  const kek = await deriveKek(masterPassword, kdfSalt, JSON.parse(kdfParams) as { algorithm: 'argon2id'; m: number; t: number; p: number; output_len: number })
  const wrapped = sealBytes(kek, `sealero-v1\n${userId}\nvault-key\n1`, dek)
  const vaultKey = {
    wrapped_dek: wrapped.ciphertext,
    nonce: wrapped.nonce,
    kdf_salt: kdfSalt,
    kdf_params: kdfParams,
    dek_version: 1,
    master_password_version: 1,
    wrapping_state_hash: 'test-hash',
  }
  const input = {
    name: 'Example', url: 'https://example.com', username: 'alice',
    password: 'correct-horse-battery-staple', note: 'test',
    category: '', tags: [], favorite: false, icon: '',
  }
  const overview = sealBytes(dek, `sealero-v1\n${userId}\n${itemId}\noverview`, new TextEncoder().encode(buildOverviewJson(input)))
  const detail = sealBytes(dek, `sealero-v1\n${userId}\n${itemId}\ndetail`, new TextEncoder().encode(buildDetailJson(input)))
  const listPage = {
    items: [{
      id: itemId,
      version: 1,
      overview_ciphertext: overview.ciphertext,
      overview_nonce: overview.nonce,
      detail_ciphertext: detail.ciphertext,
      detail_nonce: detail.nonce,
      domain_hmac: null,
      updated_at: '2026-11-24T12:00:00Z',
      device_id: null,
    }],
    has_more: false,
    next_cursor: null,
    server_time: '2026-11-24T12:00:00Z',
    master_password_version: 1,
    dek_version: 1,
  }
  return { kek, vaultKey, listPage }
}

function installFetchStub(fixture: Fixture): () => void {
  const originalFetch = globalThis.fetch
  globalThis.fetch = (async (input: unknown) => {
    const url = String(input)
    const body = async () => {
      if (url.endsWith('/v1/auth/login')) return { access_token: fakeJwt(userId), device_id: 'device-1' }
      if (url.endsWith('/v1/vault-key')) return fixture.vaultKey
      if (url.includes('/v1/vault/list')) return fixture.listPage
      throw new Error(`unexpected request: ${url}`)
    }
    return { ok: true, status: 200, json: body } as Response
  }) as typeof fetch
  return () => {
    globalThis.fetch = originalFetch
  }
}

async function unlockedClient(fixture: Fixture) {
  const restore = installFetchStub(fixture)
  const client = createHttpVaultClient()
  await client.login('alice@example.test', 'login-password')
  await client.unlock(masterPassword)
  return { client, restore }
}

test('exportBackup returns a KEK-only container that opens with the master password', async () => {
  const fixture = await buildFixture()
  const { client, restore } = await unlockedClient(fixture)
  try {
    const bytes = await client.exportBackup()
    assert.ok(bytes)
    const container = new TextDecoder().decode(bytes)
    const summary = inspectBackupContainer(container)
    assert.equal(summary.version, 3)
    assert.equal(summary.itemCountInContainer, 1)
    assert.equal(summary.sourceUserId, userId)
    const parsed = JSON.parse(container) as { dek_wrappings: { kind: string; ciphertext: string; nonce: string; kdf_salt: string; kdf_params: string }[]; items: { item_id: string; overview: { ciphertext: string; nonce: string }; detail: { ciphertext: string; nonce: string } }[] }
    assert.equal(parsed.dek_wrappings.length, 1)
    assert.equal(parsed.dek_wrappings[0]!.kind, 'kek')
    const integrity = await verifyBackupIntegrity(container, dek)
    assert.equal(integrity.itemCount, 1)
    const unwrapped = await unwrapBackupDek(parsed.dek_wrappings[0]!, fixture.kek, userId, 1, kdfSalt, kdfParams)
    assert.deepEqual([...unwrapped], [...dek])
    const overview = await decryptBackupBlock(dek, userId, itemId, 'overview', 1, parsed.items[0]!.overview)
    assert.equal(JSON.parse(overview).name, 'Example')
  } finally {
    restore()
  }
})

test('exportBackup returns null when the vault is locked', async () => {
  const fixture = await buildFixture()
  const restore = installFetchStub(fixture)
  try {
    const client = createHttpVaultClient()
    await client.login('alice@example.test', 'login-password')
    assert.equal(await client.exportBackup(), null)
    await client.unlock(masterPassword)
    assert.ok(await client.exportBackup())
    client.lock()
    assert.equal(await client.exportBackup(), null)
  } finally {
    restore()
  }
})

test('exportBackupFull rejects a wrong master password and a malformed recovery key', async () => {
  const fixture = await buildFixture()
  const { client, restore } = await unlockedClient(fixture)
  try {
    await assert.rejects(client.exportBackupFull('wrong-password', recoveryKey), (error: unknown) => error instanceof VaultApiError && error.code === 'invalid_master_password')
    await assert.rejects(client.exportBackupFull(masterPassword, 'abandon ability'), (error: unknown) => error instanceof VaultApiError && error.code === 'invalid_recovery_key')
  } finally {
    restore()
  }
})

test('exportBackupFull returns a full container with both wrappings', async () => {
  const fixture = await buildFixture()
  const { client, restore } = await unlockedClient(fixture)
  try {
    const bytes = await client.exportBackupFull(masterPassword, recoveryKey)
    const container = new TextDecoder().decode(bytes)
    const summary = inspectBackupContainer(container)
    assert.equal(summary.version, 3)
    assert.equal(summary.itemCountInContainer, 1)
    const parsed = JSON.parse(container) as { dek_wrappings: { kind: string; ciphertext: string; nonce: string; kdf_salt: string; kdf_params: string }[] }
    assert.equal(parsed.dek_wrappings.length, 2)
    assert.equal(parsed.dek_wrappings[0]!.kind, 'kek')
    assert.equal(parsed.dek_wrappings[1]!.kind, 'recovery_key')
    const integrity = await verifyBackupIntegrity(container, dek)
    assert.equal(integrity.itemCount, 1)
    const unwrappedKek = await unwrapBackupDek(parsed.dek_wrappings[0]!, fixture.kek, userId, 1, kdfSalt, kdfParams)
    assert.deepEqual([...unwrappedKek], [...dek])
    const recoveryWrappingKey = await deriveRecoveryWrappingKey(recoveryKey, parsed.dek_wrappings[1]!.kdf_salt, JSON.parse(kdfParams) as { algorithm: 'argon2id'; m: number; t: number; p: number; output_len: number })
    const unwrappedRecovery = await unwrapBackupDek(parsed.dek_wrappings[1]!, recoveryWrappingKey, userId, 1, parsed.dek_wrappings[1]!.kdf_salt, kdfParams)
    assert.deepEqual([...unwrappedRecovery], [...dek])
  } finally {
    restore()
  }
})
