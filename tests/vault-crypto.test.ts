import assert from 'node:assert/strict'
import test from 'node:test'
import {
  buildDetailJson,
  buildOverviewJson,
  computeDomainHmac,
  decryptBlock,
  deriveKek,
  deriveRecoveryWrappingKey,
  encryptBlock,
  importDek,
  normalizeRecoveryKey,
  parseDetailJson,
  parseKdfParams,
  parseOverviewJson,
  unwrapDek,
  validateRecoveryKey,
} from '../src/client/crypto.ts'

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return bytes
}

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64')
}

const VECTOR_KEY_HEX = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'

async function vectorKey(): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', hexToBytes(VECTOR_KEY_HEX) as BufferSource, { name: 'AES-GCM', length: 256 }, false, ['decrypt'])
}

test('SD §7.6 overview test vector decrypts to the documented plaintext', async () => {
  const key = await vectorKey()
  const ciphertext = '3c20b87aa880e021af04efeadc991408a1faa54182177d461a0f91f16d1a3a9d2e75d69dc2b17efd5ac71080aaab0a4d9d3c12e33bbbc6f805b54b75718090cc8d'
  const tag = '59a3a452e7ec2b2df49f25f3db02ab6a'
  const plain = await decryptBlock(
    key,
    'user-1',
    'item-1',
    'overview',
    toBase64(Buffer.concat([hexToBytes(ciphertext), hexToBytes(tag)])),
    toBase64(hexToBytes('000102030405060708090a0b')),
  )
  assert.equal(plain, '{"name":"Example","url":"https://example.com","username":"alice"}')
})

test('SD §7.6 detail test vector decrypts to the documented plaintext', async () => {
  const key = await vectorKey()
  const ciphertext = '5bdf2973451b1af28ddab84141ae486ff57ed1cd3e75d0c66b9e7408c4a7454e86227c4a7f066f22550e38d792446d7bce5b2d0265277e9804'
  const tag = 'fdeecfec974195866a59933b162e6965'
  const plain = await decryptBlock(
    key,
    'user-1',
    'item-1',
    'detail',
    toBase64(Buffer.concat([hexToBytes(ciphertext), hexToBytes(tag)])),
    toBase64(hexToBytes('0b0a09080706050403020100')),
  )
  assert.equal(plain, '{"password":"correct-horse-battery-staple","note":"test"}')
})

test('overview/detail round-trip preserves fields and the tag is 16 bytes', async () => {
  const dekBytes = new Uint8Array(32)
  crypto.getRandomValues(dekBytes)
  const dek = await importDek(dekBytes)
  const input = {
    name: 'Example',
    url: 'https://example.com',
    username: 'alice',
    password: 'correct-horse-battery-staple',
    note: 'test note',
    category: 'Work',
    tags: ['a', 'b'],
    favorite: true,
    icon: 'E',
    totpSecret: 'JBSWY3DPEHPK3PXP',
    recoveryCodes: [{ id: 'recovery-1', value: 'DEMO-7H2K-Q9PX' }],
    mnemonic: ['amber', 'birch'],
  }
  const overview = await encryptBlock(dek, 'user-1', 'item-1', 'overview', buildOverviewJson(input))
  const detail = await encryptBlock(dek, 'user-1', 'item-1', 'detail', buildDetailJson(input))
  // Ciphertext is Base64(ciphertext || 16-byte tag): plaintext bytes + 16.
  assert.equal(Buffer.from(overview.ciphertext, 'base64').length, Buffer.byteLength(buildOverviewJson(input)) + 16)
  assert.equal(Buffer.from(detail.ciphertext, 'base64').length, Buffer.byteLength(buildDetailJson(input)) + 16)
  const parsedOverview = parseOverviewJson(await decryptBlock(dek, 'user-1', 'item-1', 'overview', overview.ciphertext, overview.nonce))
  assert.deepEqual(parsedOverview, {
    name: 'Example',
    url: 'https://example.com',
    username: 'alice',
    category: 'Work',
    tags: ['a', 'b'],
    favorite: true,
    icon: 'E',
  })
  const parsedDetail = parseDetailJson(await decryptBlock(dek, 'user-1', 'item-1', 'detail', detail.ciphertext, detail.nonce))
  assert.deepEqual(parsedDetail, {
    password: 'correct-horse-battery-staple',
    note: 'test note',
    totpSecret: 'JBSWY3DPEHPK3PXP',
    recoveryCodes: [{ id: 'recovery-1', value: 'DEMO-7H2K-Q9PX' }],
    mnemonic: ['amber', 'birch'],
  })
})

test('wrong AAD fails decryption (overview ciphertext cannot open as detail)', async () => {
  const dekBytes = new Uint8Array(32)
  crypto.getRandomValues(dekBytes)
  const dek = await importDek(dekBytes)
  const sealed = await encryptBlock(dek, 'user-1', 'item-1', 'overview', '{"name":"Example"}')
  await assert.rejects(decryptBlock(dek, 'user-1', 'item-1', 'detail', sealed.ciphertext, sealed.nonce))
})

test('canonical JSON uses the documented field order and omits absent optionals', () => {
  assert.equal(
    buildOverviewJson({ name: 'N', url: 'https://x.test', username: 'u', password: 'p', note: '', category: 'C', tags: [], favorite: false, icon: 'N' }),
    '{"name":"N","url":"https://x.test","username":"u","category":"C","tags":[],"favorite":false,"icon":"N"}',
  )
  assert.equal(
    buildDetailJson({ name: 'N', url: '', username: '', password: 'p', note: 'n', category: '', tags: [], favorite: false, icon: 'N' }),
    '{"password":"p","note":"n"}',
  )
  assert.equal(
    buildDetailJson({ name: 'N', url: '', username: '', password: 'p', note: '', category: '', tags: [], favorite: false, icon: 'N', totpSecret: 'ABC', mnemonic: ['a', 'b'] }),
    '{"password":"p","note":"","totp_secret":"ABC","mnemonic":["a","b"]}',
  )
})

test('kdf_params canonical string parses to the P0 Argon2id tier', () => {
  assert.deepEqual(
    parseKdfParams('{"algorithm":"argon2id","m":65536,"output_len":32,"p":4,"t":3}'),
    { algorithm: 'argon2id', m: 65536, t: 3, p: 4, output_len: 32 },
  )
  assert.throws(() => parseKdfParams('{"algorithm":"argon2id","m":65536}'), /invalid_kdf_params/)
})

test('KEK unwrap round-trip recovers the DEK (Argon2id + AES-GCM vault-key AAD)', async () => {
  const dekBytes = new Uint8Array(32)
  crypto.getRandomValues(dekBytes)
  const salt = new Uint8Array(16)
  crypto.getRandomValues(salt)
  const params = { algorithm: 'argon2id', m: 1024, t: 1, p: 1, output_len: 32 }
  const kek = await deriveKek('correct-horse-battery-staple', toBase64(salt), params)
  assert.equal(kek.length, 32)
  const kekKey = await crypto.subtle.importKey('raw', kek as BufferSource, { name: 'AES-GCM', length: 256 }, false, ['encrypt'])
  const nonce = new Uint8Array(12)
  crypto.getRandomValues(nonce)
  const aad = new TextEncoder().encode('sealero-v1\nuser-1\nvault-key\n1')
  const sealed = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: aad, tagLength: 128 },
    kekKey,
    dekBytes as BufferSource,
  )
  const recovered = await unwrapDek(toBase64(new Uint8Array(sealed)), toBase64(nonce), kek, 'user-1', 1)
  assert.deepEqual(recovered, dekBytes)
  // Wrong master password must fail the GCM tag check, not return a wrong DEK.
  const wrongKek = await deriveKek('wrong-password', toBase64(salt), params)
  await assert.rejects(unwrapDek(toBase64(new Uint8Array(sealed)), toBase64(nonce), wrongKek, 'user-1', 1))
})

test('domain_hmac normalizes the URL and is deterministic hex', async () => {
  const dekBytes = new Uint8Array(32)
  crypto.getRandomValues(dekBytes)
  const first = await computeDomainHmac(dekBytes, 'https://WWW.Example.com:8080/path?q=1#frag')
  const second = await computeDomainHmac(dekBytes, 'example.com')
  assert.match(first ?? '', /^[0-9a-f]{64}$/)
  assert.equal(first, second)
  const other = await computeDomainHmac(dekBytes, 'https://other.test/login')
  assert.notEqual(first, other)
  assert.equal(await computeDomainHmac(dekBytes, ''), null)
  assert.equal(await computeDomainHmac(dekBytes, 'not a url at all !!!'), null)
})

test('domain_hmac is pinned: fixed DEK and URL always produce the same digest (cross-client contract)', async () => {
  // Pinned vector for the HKDF-SHA256 domain search key (SD §7.5, salt is
  // 32 zero bytes) — the Flutter client must produce this exact digest for
  // the same DEK and domain, or MCP domain search diverges across clients.
  const dekBytes = new Uint8Array(32)
  for (let index = 0; index < 32; index += 1) dekBytes[index] = index
  assert.equal(
    await computeDomainHmac(dekBytes, 'https://example.com/login'),
    '526243da20d659300a631c69f68ac2ff4b6684ba487f0434825b72f7b403d089',
  )
  // A trailing dot is the same domain.
  assert.equal(
    await computeDomainHmac(dekBytes, 'https://example.com./login'),
    '526243da20d659300a631c69f68ac2ff4b6684ba487f0434825b72f7b403d089',
  )
})

const RECOVERY_KEY = `${'abandon '.repeat(23)}art`

test('recovery key input normalizes casing and extra whitespace', async () => {
  assert.equal(normalizeRecoveryKey('  Abandon  ABILITY\table\nAbout  '), 'abandon ability able about')
  assert.equal(await validateRecoveryKey(RECOVERY_KEY.toUpperCase()), RECOVERY_KEY)
  assert.equal(await validateRecoveryKey(`  ${RECOVERY_KEY}  `), RECOVERY_KEY)
})

test('recovery key validation rejects wrong word counts and non-letters', async () => {
  await assert.rejects(validateRecoveryKey('abandon ability'), /invalid_recovery_key/)
  await assert.rejects(validateRecoveryKey(`${RECOVERY_KEY} extra`), /invalid_recovery_key/)
  await assert.rejects(validateRecoveryKey(RECOVERY_KEY.replace('abandon', 'abandon1')), /invalid_recovery_key/)
  await assert.rejects(validateRecoveryKey(''), /invalid_recovery_key/)
})

test('recovery key validation enforces the BIP39 wordlist and checksum', async () => {
  // 'abandon' x23 + 'art' is the canonical BIP39 test vector: valid checksum.
  assert.equal(await validateRecoveryKey(RECOVERY_KEY), RECOVERY_KEY)
  // Same words, wrong 24th word: 'zoo' is in the list but the checksum fails.
  await assert.rejects(validateRecoveryKey(`${'abandon '.repeat(23)}zoo`), /invalid_recovery_key/)
  // One word swapped for another list word: still in the list, checksum fails.
  await assert.rejects(validateRecoveryKey(RECOVERY_KEY.replace('art', 'ability')), /invalid_recovery_key/)
  // A word outside the 2048-word list is rejected even before the checksum.
  await assert.rejects(validateRecoveryKey(`${'abandon '.repeat(23)}sealero`), /invalid_recovery_key/)
})

test('recovery wrapping key derives deterministically per salt (Argon2id, 32 bytes)', async () => {
  const params = { algorithm: 'argon2id', m: 1024, t: 1, p: 1, output_len: 32 }
  const saltA = toBase64(new Uint8Array(16).fill(1))
  const saltB = toBase64(new Uint8Array(16).fill(2))
  const first = await deriveRecoveryWrappingKey(RECOVERY_KEY, saltA, params)
  const second = await deriveRecoveryWrappingKey(RECOVERY_KEY, saltA, params)
  const other = await deriveRecoveryWrappingKey(RECOVERY_KEY, saltB, params)
  assert.equal(first.length, 32)
  assert.deepEqual(first, second)
  assert.notDeepEqual(first, other)
})
