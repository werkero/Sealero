import { canonicalJson } from './backup-local.ts'

/**
 * Encrypted backup container builder (System Design §7.4, format v3).
 *
 * Pure crypto: builds the canonical-JSON v3 container from decrypted items and
 * explicit key material. It takes wrapping keys as already-derived 32-byte keys
 * (Argon2id derivation happens in the vault adapter, which owns the KEK and the
 * recovery key); this module never sees a master password or recovery words.
 *
 * AADs are System Design §7.6 backup AADs. Block hashes are SHA-256 over
 * nonce bytes + ciphertext bytes (including the 16-byte GCM tag).
 */

export interface BackupExportOverview {
  name: string
  url: string
  username: string
  category: string
  tags: string[]
  favorite: boolean
  icon: string
}

export interface BackupExportDetail {
  password: string
  note: string
  totp_secret: string | null
  passkey: { credential_id: string; public_key: string; rp_id: string } | null
  recovery_codes: { id: string; value: string }[] | null
  mnemonic: string[] | null
}

export interface BackupExportItem {
  itemId: string
  version: number
  overview: BackupExportOverview
  detail: BackupExportDetail
  domainHmac: string | null
}

export interface BackupDekWrappingInput {
  /** Already-derived 32-byte wrapping key (KEK-derived or recovery-derived). */
  wrappingKey: Uint8Array
  /** Base64 of the 16 random salt bytes stored in this wrapping entry. */
  kdfSalt: string
  /** Canonical JSON kdf_params string stored in this wrapping entry. */
  kdfParams: string
  kind: 'kek' | 'recovery_key'
  /** Only for kind=kek. */
  masterPasswordVersion?: number
}

export interface BuildBackupContainerInput {
  sourceUserId: string
  /** Raw 32-byte DEK. */
  dek: Uint8Array
  dekVersion: number
  kekWrapping: BackupDekWrappingInput
  /**
   * Omitted for auto-backup containers (System Design §7.4): those carry
   * only the KEK wrapping, so they open with the master password alone.
   * Manual export always passes both wrappings.
   */
  recoveryWrapping?: BackupDekWrappingInput
  items: BackupExportItem[]
  /** Defaults to now. Serialized as ISO-8601 UTC, second precision, Z suffix. */
  createdAt?: Date
  /** Injectable for tests. Defaults to crypto.getRandomValues. */
  randomBytes?: (length: number) => Uint8Array
}

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

function base64Encode(bytes: Uint8Array): string {
  let binary = ''
  const chunk = 0x8000
  for (let index = 0; index < bytes.length; index += chunk) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunk))
  }
  return btoa(binary)
}

function base64Decode(value: string): Uint8Array {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index)
  return bytes
}

function toUtcSecondTimestamp(date: Date): string {
  const iso = date.toISOString()
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(iso)) throw new Error('backup_invalid_timestamp')
  return `${iso.slice(0, 19)}Z`
}

function defaultRandomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)
  return bytes
}

async function importAesKey(keyBytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', keyBytes as BufferSource, 'AES-GCM', false, ['encrypt', 'decrypt'])
}

async function aesGcmEncrypt(key: CryptoKey, nonce: Uint8Array, aad: string, plaintext: Uint8Array): Promise<{ ciphertext: string; nonce: string }> {
  const sealed = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: textEncoder.encode(aad) },
    key,
    plaintext as BufferSource,
  )
  return { ciphertext: base64Encode(new Uint8Array(sealed)), nonce: base64Encode(nonce) }
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', data as BufferSource)
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

function backupDekAad(sourceUserId: string, dekVersion: number, kdfSalt: string, kdfParams: string): string {
  return `sealero-v1\n${sourceUserId}\nvault-key\n${dekVersion}\nbackup_format_version=3\n${kdfSalt}\n${kdfParams}`
}

function backupItemAad(sourceUserId: string, itemId: string, kind: 'overview' | 'detail', version: number): string {
  return `sealero-v1\n${sourceUserId}\n${itemId}\n${kind}\nbackup_format_version=3\n${version}`
}

function backupManifestAad(sourceUserId: string): string {
  return `sealero-v1\n${sourceUserId}\nmanifest\nbackup_format_version=3`
}

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}

/**
 * Builds the full v3 container as canonical JSON. Items are sorted by item_id;
 * duplicate ids or versions below 1 throw. Throws on invalid key material.
 * With `recoveryWrapping` omitted the container carries only the KEK
 * wrapping (auto-backup); with it, both wrappings (manual export).
 */
export async function buildBackupContainer(input: BuildBackupContainerInput): Promise<string> {
  const { sourceUserId, dek, dekVersion, kekWrapping, recoveryWrapping } = input
  if (dek.length !== 32) throw new Error('backup_invalid_dek')
  if (kekWrapping.wrappingKey.length !== 32) throw new Error('backup_invalid_wrapping_key')
  if (kekWrapping.kind !== 'kek') throw new Error('backup_invalid_wrapping_kind')
  if (!Number.isSafeInteger(kekWrapping.masterPasswordVersion) || (kekWrapping.masterPasswordVersion as number) < 1) throw new Error('backup_invalid_master_password_version')
  if (recoveryWrapping) {
    if (recoveryWrapping.wrappingKey.length !== 32) throw new Error('backup_invalid_wrapping_key')
    if (recoveryWrapping.kind !== 'recovery_key') throw new Error('backup_invalid_wrapping_kind')
    if (recoveryWrapping.masterPasswordVersion !== undefined) throw new Error('backup_invalid_wrapping_kind')
  }
  if (!Number.isSafeInteger(dekVersion) || dekVersion < 1) throw new Error('backup_invalid_dek_version')
  const createdAt = toUtcSecondTimestamp(input.createdAt ?? new Date())
  const randomBytes = input.randomBytes ?? defaultRandomBytes

  const sortedItems = [...input.items].sort((a, b) => compareStrings(a.itemId, b.itemId))
  const seen = new Set<string>()
  for (const item of sortedItems) {
    if (seen.has(item.itemId)) throw new Error('backup_duplicate_item_id')
    seen.add(item.itemId)
    if (!Number.isSafeInteger(item.version) || item.version < 1) throw new Error('backup_invalid_item_version')
  }

  const dekKey = await importAesKey(dek)
  const wrapDek = async (wrapping: BackupDekWrappingInput) => {
    const key = await importAesKey(wrapping.wrappingKey)
    const nonce = randomBytes(12)
    const aad = backupDekAad(sourceUserId, dekVersion, wrapping.kdfSalt, wrapping.kdfParams)
    const sealed = await aesGcmEncrypt(key, nonce, aad, dek)
    return {
      ciphertext: sealed.ciphertext,
      dek_version: dekVersion,
      kdf_params: wrapping.kdfParams,
      kdf_salt: wrapping.kdfSalt,
      kind: wrapping.kind,
      ...(wrapping.kind === 'kek' ? { master_password_version: wrapping.masterPasswordVersion } : {}),
      nonce: sealed.nonce,
    }
  }
  const dekWrappings = recoveryWrapping
    ? [await wrapDek(kekWrapping), await wrapDek(recoveryWrapping)]
    : [await wrapDek(kekWrapping)]

  const manifestItems: { detail_hash: string; item_id: string; overview_hash: string; version: number }[] = []
  const containerItems: Record<string, unknown>[] = []
  for (const item of sortedItems) {
    const overviewPlaintext = textEncoder.encode(canonicalJson(item.overview))
    const detailPlaintext = textEncoder.encode(canonicalJson(item.detail))
    const overviewNonce = randomBytes(12)
    const detailNonce = randomBytes(12)
    const overview = await aesGcmEncrypt(dekKey, overviewNonce, backupItemAad(sourceUserId, item.itemId, 'overview', item.version), overviewPlaintext)
    const detail = await aesGcmEncrypt(dekKey, detailNonce, backupItemAad(sourceUserId, item.itemId, 'detail', item.version), detailPlaintext)
    const overviewHash = await sha256Hex(concatBytes(base64Decode(overview.nonce), base64Decode(overview.ciphertext)))
    const detailHash = await sha256Hex(concatBytes(base64Decode(detail.nonce), base64Decode(detail.ciphertext)))
    manifestItems.push({ detail_hash: detailHash, item_id: item.itemId, overview_hash: overviewHash, version: item.version })
    containerItems.push({ detail, domain_hmac: item.domainHmac, item_id: item.itemId, overview, version: item.version })
  }

  const manifestPlaintext = textEncoder.encode(canonicalJson({ created_at: createdAt, item_count: sortedItems.length, items: manifestItems }))
  const manifestNonce = randomBytes(12)
  const manifest = await aesGcmEncrypt(dekKey, manifestNonce, backupManifestAad(sourceUserId), manifestPlaintext)

  return canonicalJson({
    backup_format_version: 3,
    created_at: createdAt,
    dek_wrappings: dekWrappings,
    items: containerItems,
    manifest,
    source_user_id: sourceUserId,
  })
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length)
  out.set(a, 0)
  out.set(b, a.length)
  return out
}

export interface BackupIntegrityResult {
  itemCount: number
  createdAt: string
  items: { itemId: string; version: number }[]
}

/**
 * Verifies a v3 container against a raw DEK (steps 2–3 of the §7.4 restore
 * checklist): decrypts the manifest block and checks item_count, the
 * (item_id, version) set, ordering, and every block's SHA-256. Throws
 * `backup_corrupt` on any mismatch and `backup_decrypt_failed` when the
 * manifest tag does not verify (wrong DEK). Does not decrypt item plaintext.
 */
export async function verifyBackupIntegrity(source: string, dek: Uint8Array): Promise<BackupIntegrityResult> {
  const container = JSON.parse(source) as Record<string, unknown>
  if (container.backup_format_version !== 3) throw new Error('backup_invalid_version')
  const sourceUserId = container.source_user_id as string
  const manifestBlock = container.manifest as { ciphertext: string; nonce: string }
  const dekKey = await importAesKey(dek)
  let manifestPlaintext: Uint8Array
  try {
    const sealed = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64Decode(manifestBlock.nonce) as BufferSource, additionalData: textEncoder.encode(backupManifestAad(sourceUserId)) },
      dekKey,
      base64Decode(manifestBlock.ciphertext) as BufferSource,
    )
    manifestPlaintext = new Uint8Array(sealed)
  } catch {
    throw new Error('backup_decrypt_failed')
  }
  const manifest = JSON.parse(textDecoder.decode(manifestPlaintext)) as {
    created_at: string
    item_count: number
    items: { detail_hash: string; item_id: string; overview_hash: string; version: number }[]
  }
  const items = container.items as {
    detail: { ciphertext: string; nonce: string }
    item_id: string
    overview: { ciphertext: string; nonce: string }
    version: number
  }[]
  if (manifest.item_count !== items.length || manifest.items.length !== items.length) throw new Error('backup_corrupt')
  const manifestIds = manifest.items.map((entry) => `${entry.item_id}:${entry.version}`).sort()
  const containerIds = items.map((entry) => `${entry.item_id}:${entry.version}`).sort()
  if (manifestIds.some((id, index) => id !== containerIds[index])) throw new Error('backup_corrupt')
  const sortedIds = items.map((entry) => entry.item_id)
  if (sortedIds.some((id, index) => index > 0 && id <= sortedIds[index - 1]!)) throw new Error('backup_corrupt')
  for (const entry of manifest.items) {
    const item = items.find((candidate) => candidate.item_id === entry.item_id)
    if (!item) throw new Error('backup_corrupt')
    const overviewHash = await sha256Hex(concatBytes(base64Decode(item.overview.nonce), base64Decode(item.overview.ciphertext)))
    const detailHash = await sha256Hex(concatBytes(base64Decode(item.detail.nonce), base64Decode(item.detail.ciphertext)))
    if (overviewHash !== entry.overview_hash || detailHash !== entry.detail_hash) throw new Error('backup_corrupt')
  }
  return { itemCount: manifest.item_count, createdAt: manifest.created_at, items: manifest.items.map((entry) => ({ itemId: entry.item_id, version: entry.version })) }
}

/** Decrypts one backup item block with the raw DEK (used by restore; AAD per §7.6). */
export async function decryptBackupBlock(
  dek: Uint8Array,
  sourceUserId: string,
  itemId: string,
  kind: 'overview' | 'detail',
  version: number,
  block: { ciphertext: string; nonce: string },
): Promise<string> {
  const key = await importAesKey(dek)
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64Decode(block.nonce) as BufferSource, additionalData: textEncoder.encode(backupItemAad(sourceUserId, itemId, kind, version)) },
      key,
      base64Decode(block.ciphertext) as BufferSource,
    )
    return textDecoder.decode(plaintext)
  } catch {
    throw new Error('backup_decrypt_failed')
  }
}

/** Unwraps the DEK from one dek_wrappings entry with its already-derived key. */
export async function unwrapBackupDek(wrapping: { ciphertext: string; nonce: string }, wrappingKey: Uint8Array, sourceUserId: string, dekVersion: number, kdfSalt: string, kdfParams: string): Promise<Uint8Array> {
  const key = await importAesKey(wrappingKey)
  try {
    const dek = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64Decode(wrapping.nonce) as BufferSource, additionalData: textEncoder.encode(backupDekAad(sourceUserId, dekVersion, kdfSalt, kdfParams)) },
      key,
      base64Decode(wrapping.ciphertext) as BufferSource,
    )
    return new Uint8Array(dek)
  } catch {
    throw new Error('backup_decrypt_failed')
  }
}
