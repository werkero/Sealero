import type { Passkey, RecoveryCode, VaultItemInput } from './types'
import { BIP39_ENGLISH_WORDLIST } from './bip39-english-wordlist.ts'

/**
 * Browser-side vault cryptography, per System Design §7.1/§7.5/§7.6.
 *
 * - AES-256-GCM, 12-byte random nonce, 128-bit tag. Stored ciphertext is
 *   Base64(ciphertext || 16-byte tag); stored nonce is Base64(12 bytes).
 * - Overview plaintext is canonical JSON in schema order:
 *   name, url, username, category, tags, favorite, icon.
 * - Detail plaintext is canonical JSON in schema order:
 *   password, note, totp_secret?, passkey?, recovery_codes?, mnemonic?
 *   Absent optional fields are omitted (matching the §7.6 test vectors).
 * - AAD: `sealero-v1\n<user_id>\n<item_id>\noverview|detail`;
 *   DEK wrap AAD: `sealero-v1\n<user_id>\nvault-key\n<dek_version>`.
 * - domain_hmac (§7.5): HKDF-SHA256(DEK, info "sealero-domain-search-v1")
 *   then HMAC-SHA256 over the normalized domain, hex lowercase.
 * - KEK: Argon2id (hash-wasm, loaded on demand) per the kdf_params that
 *   travel with the wrapped DEK; m is KiB, output 32 bytes.
 */

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

export function toBase64(bytes: Uint8Array): string {
  let binary = ''
  const chunk = 0x8000
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk))
  }
  return btoa(binary)
}

export function fromBase64(value: string): Uint8Array {
  // Accepts standard and URL-safe Base64; pads to a multiple of 4 so a
  // strict decoder does not fail on unpadded input (e.g. a JWT payload,
  // where the browser's lenient atob happens to tolerate the missing `=`).
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4)
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i)
  return bytes
}

export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)
  return bytes
}

export function randomUuid(): string {
  return crypto.randomUUID()
}

async function importAesKey(keyBytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', keyBytes as BufferSource, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}

export async function encryptBlock(
  dek: CryptoKey,
  userId: string,
  itemId: string,
  kind: 'overview' | 'detail',
  plaintext: string,
): Promise<{ ciphertext: string; nonce: string }> {
  const nonce = randomBytes(12)
  const aad = textEncoder.encode(`sealero-v1\n${userId}\n${itemId}\n${kind}`)
  const sealed = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: aad, tagLength: 128 },
    dek,
    textEncoder.encode(plaintext),
  )
  return { ciphertext: toBase64(new Uint8Array(sealed)), nonce: toBase64(nonce) }
}

export async function decryptBlock(
  dek: CryptoKey,
  userId: string,
  itemId: string,
  kind: 'overview' | 'detail',
  ciphertext: string,
  nonce: string,
): Promise<string> {
  const aad = textEncoder.encode(`sealero-v1\n${userId}\n${itemId}\n${kind}`)
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(nonce) as BufferSource, additionalData: aad, tagLength: 128 },
    dek,
    fromBase64(ciphertext) as BufferSource,
  )
  return textDecoder.decode(plain)
}

/** Overview plaintext: all seven fields, in the documented schema order. */
export function buildOverviewJson(input: VaultItemInput): string {
  return JSON.stringify({
    name: input.name,
    url: input.url,
    username: input.username,
    category: input.category,
    tags: input.tags,
    favorite: input.favorite,
    icon: input.icon,
  })
}

export function parseOverviewJson(text: string): {
  name: string
  url: string
  username: string
  category: string
  tags: string[]
  favorite: boolean
  icon: string
} {
  const data = JSON.parse(text) as Record<string, unknown>
  if (typeof data['name'] !== 'string' || typeof data['url'] !== 'string' || typeof data['username'] !== 'string') {
    throw new Error('invalid_overview')
  }
  return {
    name: data['name'],
    url: data['url'],
    username: data['username'],
    category: typeof data['category'] === 'string' ? data['category'] : '',
    tags: Array.isArray(data['tags']) ? data['tags'].filter((tag): tag is string => typeof tag === 'string') : [],
    favorite: data['favorite'] === true,
    icon: typeof data['icon'] === 'string' && data['icon'] ? data['icon'] : (data['name'].slice(0, 1).toUpperCase() || '?'),
  }
}

interface StoredDetail {
  password: string
  note: string
  totp_secret?: string
  passkey?: { credential_id: string; public_key: string; rp_id: string }
  recovery_codes?: Array<{ id: string; value: string } | string>
  mnemonic?: string[]
}

/** Detail plaintext: required fields first, absent optionals omitted. */
export function buildDetailJson(input: VaultItemInput): string {
  const detail: Record<string, unknown> = { password: input.password, note: input.note }
  if (input.totpSecret) detail['totp_secret'] = input.totpSecret
  if (input.passkey) {
    detail['passkey'] = {
      credential_id: input.passkey.credentialId,
      public_key: input.passkey.publicKey,
      rp_id: input.passkey.rpId,
    }
  }
  if (input.recoveryCodes?.length) {
    detail['recovery_codes'] = input.recoveryCodes.map((code) => ({ id: code.id, value: code.value }))
  }
  if (input.mnemonic?.length) detail['mnemonic'] = input.mnemonic
  return JSON.stringify(detail)
}

export function parseDetailJson(text: string): {
  password: string
  note: string
  totpSecret?: string
  passkey?: Passkey
  recoveryCodes?: RecoveryCode[]
  mnemonic?: string[]
} {
  const data = JSON.parse(text) as StoredDetail
  if (typeof data.password !== 'string' || typeof data.note !== 'string') {
    throw new Error('invalid_detail')
  }
  const out: ReturnType<typeof parseDetailJson> = { password: data.password, note: data.note }
  if (typeof data.totp_secret === 'string' && data.totp_secret) out.totpSecret = data.totp_secret
  if (data.passkey && typeof data.passkey.credential_id === 'string') {
    out.passkey = {
      credentialId: data.passkey.credential_id,
      publicKey: typeof data.passkey.public_key === 'string' ? data.passkey.public_key : '',
      rpId: typeof data.passkey.rp_id === 'string' ? data.passkey.rp_id : '',
    }
  }
  if (Array.isArray(data.recovery_codes)) {
    out.recoveryCodes = data.recovery_codes
      .map((code, index) => (typeof code === 'string'
        ? { id: `recovery-${index + 1}`, value: code }
        : { id: code.id, value: code.value }))
      .filter((code) => typeof code.value === 'string' && code.value.length > 0)
  }
  if (Array.isArray(data.mnemonic)) {
    out.mnemonic = data.mnemonic.filter((word): word is string => typeof word === 'string')
  }
  return out
}

export interface KdfParams {
  algorithm: string
  m: number
  t: number
  p: number
  output_len: number
}

export function parseKdfParams(raw: string): KdfParams {
  const data = JSON.parse(raw) as Record<string, unknown>
  if (
    data['algorithm'] !== 'argon2id' ||
    typeof data['m'] !== 'number' || typeof data['t'] !== 'number' ||
    typeof data['p'] !== 'number' || typeof data['output_len'] !== 'number'
  ) {
    throw new Error('invalid_kdf_params')
  }
  return { algorithm: 'argon2id', m: data['m'], t: data['t'], p: data['p'], output_len: data['output_len'] }
}

/** Derive the 32-byte KEK from the master password (Argon2id, WASM). */
export async function deriveKek(masterPassword: string, kdfSaltBase64: string, params: KdfParams): Promise<Uint8Array> {
  const { argon2id } = await import('hash-wasm')
  return argon2id({
    password: masterPassword,
    salt: fromBase64(kdfSaltBase64),
    parallelism: params.p,
    iterations: params.t,
    memorySize: params.m,
    hashLength: params.output_len,
    outputType: 'binary',
  })
}

/**
 * Recovery key (System Design §7.1): 24 BIP39 words. Input is normalized to
 * lowercase single-space-joined words; a malformed key throws
 * `invalid_recovery_key`. Every word must be in the BIP39 English wordlist
 * and the checksum must verify: 24 words encode 256 bits of entropy plus an
 * 8-bit checksum (the first byte of SHA-256 over the entropy). A mistyped
 * word is therefore caught here, at input time, instead of only when the
 * wrapping fails to open at restore time.
 */
export function normalizeRecoveryKey(input: string): string {
  return input.trim().toLowerCase().split(/\s+/).filter((word) => word.length > 0).join(' ')
}

const BIP39_WORD_INDEX = new Map<string, number>(BIP39_ENGLISH_WORDLIST.map((word, index) => [word, index]))

export async function validateRecoveryKey(input: string): Promise<string> {
  const normalized = normalizeRecoveryKey(input)
  const words = normalized === '' ? [] : normalized.split(' ')
  if (words.length !== 24 || words.some((word) => !BIP39_WORD_INDEX.has(word))) {
    throw new Error('invalid_recovery_key')
  }
  // 24 words x 11 bits = 264 bits: the first 256 are entropy, the last 8
  // are the checksum (first byte of SHA-256 over the entropy).
  const bits = words.map((word) => (BIP39_WORD_INDEX.get(word) as number).toString(2).padStart(11, '0')).join('')
  const entropy = new Uint8Array(32)
  for (let index = 0; index < 32; index += 1) {
    entropy[index] = Number.parseInt(bits.slice(index * 8, index * 8 + 8), 2)
  }
  const checksum = Number.parseInt(bits.slice(256), 2)
  const digest = await crypto.subtle.digest('SHA-256', entropy as BufferSource)
  if (new Uint8Array(digest)[0] !== checksum) throw new Error('invalid_recovery_key')
  return normalized
}

/**
 * Derive the 32-byte recovery wrapping key from the recovery words
 * (Argon2id, same parameters as the KEK, §7.1). The salt is the fresh
 * 16-byte salt stored in the new wrapping entry.
 */
export async function deriveRecoveryWrappingKey(recoveryKey: string, kdfSaltBase64: string, params: KdfParams): Promise<Uint8Array> {
  return deriveKek(await validateRecoveryKey(recoveryKey), kdfSaltBase64, params)
}

/** Unwrap the DEK with the KEK; returns the raw 32-byte DEK. */
export async function unwrapDek(
  wrappedDekBase64: string,
  nonceBase64: string,
  kekBytes: Uint8Array,
  userId: string,
  dekVersion: number,
): Promise<Uint8Array> {
  const kek = await importAesKey(kekBytes)
  const aad = textEncoder.encode(`sealero-v1\n${userId}\nvault-key\n${dekVersion}`)
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(nonceBase64) as BufferSource, additionalData: aad, tagLength: 128 },
    kek,
    fromBase64(wrappedDekBase64) as BufferSource,
  )
  return new Uint8Array(plain)
}

export async function importDek(dekBytes: Uint8Array): Promise<CryptoKey> {
  return importAesKey(dekBytes)
}

function normalizeDomain(url: string): string | null {
  const trimmed = url.trim()
  if (!trimmed) return null
  let parsed: URL
  try {
    parsed = new URL(trimmed.includes('://') ? trimmed : `https://${trimmed}`)
  } catch {
    return null
  }
  const host = parsed.hostname.replace(/^www\./, '').replace(/\.$/, '')
  return host || null
}

async function deriveDomainSearchKey(dekBytes: Uint8Array): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey('raw', dekBytes as BufferSource, 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32) as BufferSource, info: textEncoder.encode('sealero-domain-search-v1') },
    baseKey,
    256,
  )
  return crypto.subtle.importKey('raw', bits, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
}

/** HMAC-SHA256 of the normalized domain, hex lowercase; null when there is no domain. */
export async function computeDomainHmac(dekBytes: Uint8Array, url: string): Promise<string | null> {
  const domain = normalizeDomain(url)
  if (!domain) return null
  const searchKey = await deriveDomainSearchKey(dekBytes)
  const signature = await crypto.subtle.sign('HMAC', searchKey, textEncoder.encode(domain))
  return [...new Uint8Array(signature)].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

/** Read the `sub` claim of a JWT without verifying it (identity only, never trust). */
export function decodeJwtSub(accessToken: string): string | null {
  const parts = accessToken.split('.')
  if (parts.length !== 3) return null
  try {
    const payload = JSON.parse(textDecoder.decode(fromBase64(parts[1]))) as Record<string, unknown>
    return typeof payload['sub'] === 'string' ? payload['sub'] : null
  } catch {
    return null
  }
}
