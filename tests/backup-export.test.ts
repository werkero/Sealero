import assert from 'node:assert/strict'
import { createCipheriv, createHash } from 'node:crypto'
import test from 'node:test'
import {
  buildBackupContainer,
  decryptBackupBlock,
  unwrapBackupDek,
  verifyBackupIntegrity,
  type BackupExportItem,
} from '../src/features/settings/backup-export.ts'
import { inspectBackupContainer } from '../src/features/settings/backup-local.ts'

const userId = '123e4567-e89b-42d3-a456-426614174000'
const dek = new Uint8Array(32).fill(9)
const kekKey = new Uint8Array(32).fill(3)
const recoveryKey = new Uint8Array(32).fill(5)
const kdfParams = '{"algorithm":"argon2id","m":65536,"output_len":32,"p":4,"t":3}'
const kdfSalt = Buffer.alloc(16, 2).toString('base64')

/** Deterministic bytes so the built container is reproducible in tests. */
function deterministicRandomBytes(seed: number) {
  let state = seed
  return (length: number): Uint8Array => {
    const bytes = new Uint8Array(length)
    for (let index = 0; index < length; index += 1) {
      state = (state * 1103515245 + 12345) & 0x7fffffff
      bytes[index] = state % 256
    }
    return bytes
  }
}

function sampleItems(): BackupExportItem[] {
  return [
    {
      itemId: '10000000-0000-4000-8000-000000000002',
      version: 2,
      overview: { name: 'Northstar Mail', url: 'https://mail.example.test', username: 'alex@example.test', category: 'Personal', tags: ['Personal'], favorite: false, icon: 'N' },
      detail: { password: 'Mail_Pass_1', note: '', totp_secret: null, passkey: null, recovery_codes: null, mnemonic: null },
      domainHmac: null,
    },
    {
      itemId: '10000000-0000-4000-8000-000000000001',
      version: 1,
      overview: { name: 'Gitea Workspace', url: 'https://git.example.test', username: 'alex@example.test', category: 'Developer tools', tags: ['Work', 'Code'], favorite: true, icon: 'G' },
      detail: { password: 'Git_Pass_2', note: 'sample', totp_secret: 'JBSWY3DPEHPK3PXP', passkey: null, recovery_codes: [{ id: 'r1', value: 'DEMO-7H2K-Q9PX' }], mnemonic: null },
      domainHmac: 'a'.repeat(64),
    },
  ]
}

async function buildSample() {
  return buildBackupContainer({
    sourceUserId: userId,
    dek,
    dekVersion: 1,
    kekWrapping: { wrappingKey: kekKey, kdfSalt, kdfParams, kind: 'kek', masterPasswordVersion: 1 },
    recoveryWrapping: { wrappingKey: recoveryKey, kdfSalt, kdfParams, kind: 'recovery_key' },
    items: sampleItems(),
    createdAt: new Date('2026-11-24T12:00:00.000Z'),
    randomBytes: deterministicRandomBytes(42),
  })
}

test('v3 container round-trips: inspect, integrity, unwrap, decrypt', async () => {
  const container = await buildSample()
  const summary = inspectBackupContainer(container)
  assert.equal(summary.version, 3)
  assert.equal(summary.sourceUserId, userId)
  assert.equal(summary.itemCountInContainer, 2)
  assert.equal(summary.createdAt, '2026-11-24T12:00:00Z')

  const parsed = JSON.parse(container) as Record<string, unknown>
  // Canonical JSON: keys ASCII-sorted, no spaces, single document ending in }.
  assert.deepEqual(Object.keys(parsed), ['backup_format_version', 'created_at', 'dek_wrappings', 'items', 'manifest', 'source_user_id'])
  assert.equal(container.endsWith('}'), true)
  // Items sorted by item_id ascending even though input was not sorted.
  const items = parsed.items as { item_id: string }[]
  assert.deepEqual(items.map((entry) => entry.item_id), ['10000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000002'])

  const integrity = await verifyBackupIntegrity(container, dek)
  assert.equal(integrity.itemCount, 2)
  assert.equal(integrity.createdAt, '2026-11-24T12:00:00Z')
  assert.deepEqual(integrity.items, [
    { itemId: '10000000-0000-4000-8000-000000000001', version: 1 },
    { itemId: '10000000-0000-4000-8000-000000000002', version: 2 },
  ])

  const wrappings = parsed.dek_wrappings as { ciphertext: string; nonce: string }[]
  const unwrappedKek = await unwrapBackupDek(wrappings[0]!, kekKey, userId, 1, kdfSalt, kdfParams)
  const unwrappedRecovery = await unwrapBackupDek(wrappings[1]!, recoveryKey, userId, 1, kdfSalt, kdfParams)
  assert.deepEqual([...unwrappedKek], [...dek])
  assert.deepEqual([...unwrappedRecovery], [...dek])

  const first = items[0] as { detail: { ciphertext: string; nonce: string }; overview: { ciphertext: string; nonce: string } }
  const overview = await decryptBackupBlock(dek, userId, '10000000-0000-4000-8000-000000000001', 'overview', 1, first.overview)
  const detail = await decryptBackupBlock(dek, userId, '10000000-0000-4000-8000-000000000001', 'detail', 1, first.detail)
  assert.equal(overview, '{"category":"Developer tools","favorite":true,"icon":"G","name":"Gitea Workspace","tags":["Work","Code"],"url":"https://git.example.test","username":"alex@example.test"}')
  assert.equal(detail, '{"mnemonic":null,"note":"sample","passkey":null,"password":"Git_Pass_2","recovery_codes":[{"id":"r1","value":"DEMO-7H2K-Q9PX"}],"totp_secret":"JBSWY3DPEHPK3PXP"}')
})

test('AES-GCM output matches Node crypto for the same key, nonce, AAD and plaintext', async () => {
  const key = new Uint8Array(32).fill(1)
  const nonce = new Uint8Array(12).fill(2)
  const aad = 'sealero-v1\nuser-1\nitem-1\noverview\nbackup_format_version=3\n1'
  const plaintext = new TextEncoder().encode('{"name":"Example"}')
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(Buffer.from(aad, 'utf8'))
  const sealed = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()])

  // Build a one-item container with fixed nonces and compare its overview block.
  const container = await buildBackupContainer({
    sourceUserId: 'user-1',
    dek: key,
    dekVersion: 1,
    kekWrapping: { wrappingKey: key, kdfSalt, kdfParams, kind: 'kek', masterPasswordVersion: 1 },
    recoveryWrapping: { wrappingKey: key, kdfSalt, kdfParams, kind: 'recovery_key' },
    items: [{ itemId: 'item-1', version: 1, overview: { name: 'Example', url: '', username: '', category: '', tags: [], favorite: false, icon: '' }, detail: { password: '', note: '', totp_secret: null, passkey: null, recovery_codes: null, mnemonic: null }, domainHmac: null }],
    createdAt: new Date('2026-11-24T00:00:00.000Z'),
    randomBytes: () => nonce,
  })
  const parsed = JSON.parse(container) as { items: { overview: { ciphertext: string; nonce: string } }[] }
  const block = parsed.items[0]!.overview
  // The builder encrypts overview with the same AAD shape; compare against Node's output
  // for the identical plaintext the builder produced (canonical JSON of the overview object).
  const expectedPlaintext = '{"category":"","favorite":false,"icon":"","name":"Example","tags":[],"url":"","username":""}'
  const expectedCipher = createCipheriv('aes-256-gcm', key, nonce)
  expectedCipher.setAAD(Buffer.from(aad, 'utf8'))
  const expectedSealed = Buffer.concat([expectedCipher.update(Buffer.from(expectedPlaintext, 'utf8')), expectedCipher.final(), expectedCipher.getAuthTag()])
  assert.equal(block.nonce, Buffer.from(nonce).toString('base64'))
  assert.equal(block.ciphertext, expectedSealed.toString('base64'))
  void sealed
})

test('integrity check fails on a tampered block and on a wrong DEK', async () => {
  const container = await buildSample()
  const parsed = JSON.parse(container) as { items: { overview: { ciphertext: string } }[] }
  const tampered = JSON.parse(container) as Record<string, unknown>
  const tamperedItems = tampered.items as { overview: { ciphertext: string } }[]
  tamperedItems[0]!.overview.ciphertext = `A${parsed.items[0]!.overview.ciphertext.slice(1)}`
  await assert.rejects(verifyBackupIntegrity(JSON.stringify(tampered), dek), /backup_corrupt/)
  await assert.rejects(verifyBackupIntegrity(container, new Uint8Array(32).fill(8)), /backup_decrypt_failed/)
})

test('builder rejects duplicate ids, bad versions and bad key material', async () => {
  const base = {
    sourceUserId: userId,
    dek,
    dekVersion: 1,
    kekWrapping: { wrappingKey: kekKey, kdfSalt, kdfParams, kind: 'kek' as const, masterPasswordVersion: 1 },
    recoveryWrapping: { wrappingKey: recoveryKey, kdfSalt, kdfParams, kind: 'recovery_key' as const },
    items: sampleItems(),
    randomBytes: deterministicRandomBytes(7),
  }
  await assert.rejects(buildBackupContainer({ ...base, items: [sampleItems()[0]!, sampleItems()[0]!] }), /backup_duplicate_item_id/)
  await assert.rejects(buildBackupContainer({ ...base, items: [{ ...sampleItems()[0]!, version: 0 }] }), /backup_invalid_item_version/)
  await assert.rejects(buildBackupContainer({ ...base, dek: new Uint8Array(16) }), /backup_invalid_dek/)
  await assert.rejects(buildBackupContainer({ ...base, kekWrapping: { ...base.kekWrapping, masterPasswordVersion: undefined } }), /backup_invalid_master_password_version/)
})

test('KEK-only container (auto-backup): one wrapping, inspects and verifies, opens with the KEK', async () => {
  const container = await buildBackupContainer({
    sourceUserId: userId,
    dek,
    dekVersion: 1,
    kekWrapping: { wrappingKey: kekKey, kdfSalt, kdfParams, kind: 'kek', masterPasswordVersion: 1 },
    items: sampleItems(),
    createdAt: new Date('2026-11-24T12:00:00.000Z'),
    randomBytes: deterministicRandomBytes(42),
  })
  const summary = inspectBackupContainer(container)
  assert.equal(summary.version, 3)
  assert.equal(summary.itemCountInContainer, 2)
  const parsed = JSON.parse(container) as { dek_wrappings: { kind: string; ciphertext: string; nonce: string }[] }
  assert.equal(parsed.dek_wrappings.length, 1)
  assert.equal(parsed.dek_wrappings[0]!.kind, 'kek')
  const integrity = await verifyBackupIntegrity(container, dek)
  assert.equal(integrity.itemCount, 2)
  const unwrapped = await unwrapBackupDek(parsed.dek_wrappings[0]!, kekKey, userId, 1, kdfSalt, kdfParams)
  assert.deepEqual([...unwrapped], [...dek])
})

test('manifest hash equals SHA-256 of nonce bytes plus ciphertext bytes', async () => {
  const container = await buildSample()
  const parsed = JSON.parse(container) as {
    items: { detail: { ciphertext: string; nonce: string }; item_id: string; overview: { ciphertext: string; nonce: string }; version: number }[]
    manifest: { ciphertext: string; nonce: string }
  }
  // Decrypt the manifest block with its own AAD and compare the stored hashes
  // against independently computed SHA-256 values (Node crypto) over
  // nonce||ciphertext bytes.
  const manifestKey = await crypto.subtle.importKey('raw', dek, 'AES-GCM', false, ['decrypt'])
  const manifestSealed = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: Buffer.from(parsed.manifest.nonce, 'base64'), additionalData: new TextEncoder().encode(`sealero-v1\n${userId}\nmanifest\nbackup_format_version=3`) },
    manifestKey,
    Buffer.from(parsed.manifest.ciphertext, 'base64'),
  )
  const manifest = JSON.parse(new TextDecoder().decode(manifestSealed)) as {
    item_count: number
    items: { detail_hash: string; item_id: string; overview_hash: string; version: number }[]
  }
  assert.equal(manifest.item_count, 2)
  for (const entry of manifest.items) {
    const item = parsed.items.find((candidate) => candidate.item_id === entry.item_id)!
    assert.equal(entry.version, item.version)
    const overviewBytes = Buffer.concat([Buffer.from(item.overview.nonce, 'base64'), Buffer.from(item.overview.ciphertext, 'base64')])
    const detailBytes = Buffer.concat([Buffer.from(item.detail.nonce, 'base64'), Buffer.from(item.detail.ciphertext, 'base64')])
    assert.equal(entry.overview_hash, createHash('sha256').update(overviewBytes).digest('hex'))
    assert.equal(entry.detail_hash, createHash('sha256').update(detailBytes).digest('hex'))
  }
})
