import type { EncryptedVaultItemDto, VaultIdentity, VaultItem, VaultItemInput, VaultListItem, VaultListPageDto } from './types'
import type { VaultClient } from './contracts'
import { buildBackupContainer, type BackupExportItem } from '../features/settings/backup-export.ts'
import {
  buildDetailJson,
  buildOverviewJson,
  computeDomainHmac,
  decodeJwtSub,
  decryptBlock,
  deriveKek,
  deriveRecoveryWrappingKey,
  encryptBlock,
  importDek,
  parseDetailJson,
  parseKdfParams,
  parseOverviewJson,
  randomBytes,
  randomUuid,
  toBase64,
  unwrapDek,
  validateRecoveryKey,
} from './crypto.ts'

const DEVICE_ID_STORAGE_KEY = 'sealero.device_id'

/** API error carrying the server's error code (e.g. `conflict`, `consent_required`). */
export class VaultApiError extends Error {
  readonly code: string
  readonly status: number

  constructor(code: string, status: number, message?: string) {
    super(message ?? code)
    this.name = 'VaultApiError'
    this.code = code
    this.status = status
  }
}

interface VaultKeyRecord {
  wrapped_dek: string
  nonce: string
  kdf_salt: string
  kdf_params: string
  dek_version: number
  master_password_version: number
  wrapping_state_hash: string
}

function throwIfAborted(signal?: AbortSignal) {
  if (!signal?.aborted) return
  const error = new Error('operation_aborted')
  error.name = 'AbortError'
  throw error
}

function deviceName(): string {
  const platform = (navigator as Navigator & { userAgentData?: { platform?: string } }).userAgentData?.platform
  return platform ? `Web · ${platform}` : 'Web'
}

function loadStoredDeviceId(): string | undefined {
  try {
    return localStorage.getItem(DEVICE_ID_STORAGE_KEY) ?? undefined
  } catch {
    return undefined
  }
}

function storeDeviceId(deviceId: string): void {
  try {
    localStorage.setItem(DEVICE_ID_STORAGE_KEY, deviceId)
  } catch {
    // Device reuse is a convenience; login still works without it.
  }
}

/**
 * Production HTTP adapter for the Web vault (online thin client).
 *
 * Same-origin `/v1/*` calls (Vite proxies them in dev; the deployed web and
 * API share one origin). The access JWT, DEK, derived keys, decrypted items
 * and ciphertext cache live in memory only and are dropped on lock/logout.
 * The refresh token lives exclusively in its HttpOnly cookie; the master
 * password is used locally and is never sent to the API. Only the device id
 * is persisted (localStorage) so login can reuse the server device row.
 */
export function createHttpVaultClient(baseUrl = ''): VaultClient {
  let accessToken: string | null = null
  let userId: string | null = null
  let deviceId: string | undefined = loadStoredDeviceId()
  let dekBytes: Uint8Array | null = null
  let dekKey: CryptoKey | null = null
  let dekVersion: number | null = null
  /**
   * Session KEK + vault-key record, retained from unlock in memory only
   * (never persisted) so auto-backup can build the KEK wrapping without
   * asking for the master password again. Cleared on lock/logout/drop.
   */
  let kekBytes: Uint8Array | null = null
  let vaultKeyRecord: VaultKeyRecord | null = null
  let refreshing: Promise<string> | null = null
  const versions = new Map<string, number>()
  const dtoCache = new Map<string, EncryptedVaultItemDto>()

  function dropVaultState() {
    dekBytes = null
    dekKey = null
    dekVersion = null
    kekBytes = null
    vaultKeyRecord = null
    versions.clear()
    dtoCache.clear()
  }

  function dropSession() {
    accessToken = null
    userId = null
    dropVaultState()
  }

  async function refreshAccessToken(signal?: AbortSignal): Promise<string> {
    if (refreshing) return refreshing
    refreshing = (async () => {
      throwIfAborted(signal)
      const response = await fetch(`${baseUrl}/v1/auth/refresh`, { method: 'POST', credentials: 'include', signal })
      if (!response.ok) {
        const code = await readErrorCode(response)
        throw new VaultApiError(code ?? 'unauthorized', response.status)
      }
      const body = (await response.json()) as { access_token?: unknown; device_id?: unknown }
      if (typeof body.access_token !== 'string' || !body.access_token) {
        throw new VaultApiError('unauthorized', response.status)
      }
      accessToken = body.access_token
      if (typeof body.device_id === 'string' && body.device_id) {
        deviceId = body.device_id
        storeDeviceId(deviceId)
      }
      return accessToken
    })()
    try {
      return await refreshing
    } finally {
      refreshing = null
    }
  }

  async function readErrorCode(response: Response): Promise<string | null> {
    try {
      const body = (await response.json()) as { code?: unknown }
      return typeof body.code === 'string' ? body.code : null
    } catch {
      return null
    }
  }

  /** One authenticated request; on 401, refresh once and retry once. */
  async function request<T>(path: string, init: RequestInit, signal?: AbortSignal): Promise<T> {
    throwIfAborted(signal)
    const send = async (token: string | null) => {
      const headers = new Headers(init.headers)
      if (token) headers.set('Authorization', `Bearer ${token}`)
      return fetch(`${baseUrl}${path}`, { ...init, headers, credentials: 'include', signal })
    }
    let response = await send(accessToken)
    if (response.status === 401 && accessToken) {
      try {
        const nextToken = await refreshAccessToken(signal)
        response = await send(nextToken)
      } catch {
        dropSession()
        throw new VaultApiError('unauthorized', 401)
      }
    }
    if (!response.ok) {
      const code = await readErrorCode(response)
      throw new VaultApiError(code ?? 'request_failed', response.status)
    }
    if (response.status === 204) return undefined as T
    return (await response.json()) as T
  }

  function requireDek(): { dek: CryptoKey; bytes: Uint8Array; version: number } {
    if (!dekKey || !dekBytes || dekVersion === null || !userId) throw new VaultApiError('vault_locked', 401, 'vault_locked')
    return { dek: dekKey, bytes: dekBytes, version: dekVersion }
  }

  async function fetchVaultKey(signal?: AbortSignal): Promise<VaultKeyRecord> {
    return request<VaultKeyRecord>('/v1/vault-key', { method: 'GET' }, signal)
  }

  async function loadDek(masterPassword: string, signal?: AbortSignal): Promise<void> {
    const record = await fetchVaultKey(signal)
    const params = parseKdfParams(record.kdf_params)
    const kek = await deriveKek(masterPassword, record.kdf_salt, params)
    throwIfAborted(signal)
    const dek = await unwrapDek(record.wrapped_dek, record.nonce, kek, userId ?? '', record.dek_version)
    dekBytes = dek
    dekKey = await importDek(dek)
    dekVersion = record.dek_version
    kekBytes = kek
    vaultKeyRecord = record
  }

  async function decryptOverview(dto: EncryptedVaultItemDto): Promise<VaultListItem> {
    const { dek } = requireDek()
    const overview = parseOverviewJson(await decryptBlock(dek, userId ?? '', dto.id, 'overview', dto.overview_ciphertext, dto.overview_nonce))
    versions.set(dto.id, dto.version)
    dtoCache.set(dto.id, dto)
    return { id: dto.id, ...overview, updatedAt: dto.updated_at }
  }

  async function decryptDetail(dto: EncryptedVaultItemDto, overview: VaultListItem): Promise<VaultItem> {
    const { dek } = requireDek()
    const detail = parseDetailJson(await decryptBlock(dek, userId ?? '', dto.id, 'detail', dto.detail_ciphertext, dto.detail_nonce))
    return { ...overview, ...detail }
  }

  async function fetchItemVersion(itemId: string, signal?: AbortSignal): Promise<number> {
    const known = versions.get(itemId)
    if (known !== undefined) return known
    const status = await request<{ version?: unknown }>('/v1/vault/items/' + itemId + '/status', { method: 'GET' }, signal)
    if (typeof status.version !== 'number') throw new VaultApiError('not_found', 404)
    versions.set(itemId, status.version)
    return status.version
  }

  async function encryptInput(itemId: string, input: VaultItemInput): Promise<{
    overview_ciphertext: string
    overview_nonce: string
    detail_ciphertext: string
    detail_nonce: string
    domain_hmac: string | null
  }> {
    const { dek, bytes } = requireDek()
    const overview = await encryptBlock(dek, userId ?? '', itemId, 'overview', buildOverviewJson(input))
    const detail = await encryptBlock(dek, userId ?? '', itemId, 'detail', buildDetailJson(input))
    const domainHmac = await computeDomainHmac(bytes, input.url)
    return {
      overview_ciphertext: overview.ciphertext,
      overview_nonce: overview.nonce,
      detail_ciphertext: detail.ciphertext,
      detail_nonce: detail.nonce,
      domain_hmac: domainHmac,
    }
  }

  /**
   * Decrypts every item into backup-export shape (overview/detail as
   * structured plaintext, version from the list, domain_hmac recomputed
   * from the DEK). Reads fresh from the server so an export never uses a
   * stale page snapshot.
   */
  async function collectExportItems(signal?: AbortSignal): Promise<BackupExportItem[]> {
    const { bytes } = requireDek()
    const overviews = await client.list(signal)
    const items: BackupExportItem[] = []
    for (const overview of overviews) {
      const item = await client.getItem(overview.id, signal)
      const version = versions.get(overview.id) ?? dtoCache.get(overview.id)?.version
      if (!Number.isSafeInteger(version) || (version as number) < 1) {
        throw new VaultApiError('export_failed', 500, 'export_failed')
      }
      items.push({
        itemId: item.id,
        version: version as number,
        overview: {
          name: item.name,
          url: item.url,
          username: item.username,
          category: item.category,
          tags: item.tags,
          favorite: item.favorite,
          icon: item.icon,
        },
        detail: {
          password: item.password,
          note: item.note,
          totp_secret: item.totpSecret ?? null,
          passkey: item.passkey
            ? { credential_id: item.passkey.credentialId, public_key: item.passkey.publicKey, rp_id: item.passkey.rpId }
            : null,
          recovery_codes: item.recoveryCodes?.length
            ? item.recoveryCodes.map((code) => ({ id: code.id, value: code.value }))
            : null,
          mnemonic: item.mnemonic?.length ? item.mnemonic : null,
        },
        domainHmac: await computeDomainHmac(bytes, item.url),
      })
    }
    return items
  }

  const client: VaultClient = {
    async login(email: string, loginPassword: string, signal?: AbortSignal): Promise<VaultIdentity> {
      throwIfAborted(signal)
      dropSession()
      const response = await fetch(`${baseUrl}/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        signal,
        body: JSON.stringify({
          email: email.trim(),
          login_password: loginPassword,
          device_name: deviceName(),
          device_type: 'web',
          ...(deviceId ? { device_id: deviceId } : {}),
        }),
      })
      if (!response.ok) {
        const code = await readErrorCode(response)
        throw new VaultApiError(code ?? 'login_failed', response.status)
      }
      const body = (await response.json()) as { device_id?: unknown; access_token?: unknown }
      if (typeof body.access_token !== 'string' || !body.access_token) {
        throw new VaultApiError('login_failed', response.status)
      }
      accessToken = body.access_token
      if (typeof body.device_id === 'string' && body.device_id) {
        deviceId = body.device_id
        storeDeviceId(deviceId)
      }
      const sub = decodeJwtSub(accessToken)
      if (!sub) throw new VaultApiError('login_failed', response.status)
      userId = sub
      return { id: sub, email: email.trim() }
    },

    async unlock(masterPassword: string, signal?: AbortSignal): Promise<void> {
      throwIfAborted(signal)
      if (!accessToken || !userId) throw new VaultApiError('unauthorized', 401)
      dropVaultState()
      try {
        await loadDek(masterPassword, signal)
      } catch (error) {
        dropVaultState()
        if (error instanceof VaultApiError) throw error
        // GCM tag mismatch (wrong master password) or bad KDF params surface here.
        throw new VaultApiError('invalid_master_password', 401, 'invalid_master_password')
      }
    },

    async list(signal?: AbortSignal): Promise<VaultListItem[]> {
      throwIfAborted(signal)
      requireDek()
      const items: VaultListItem[] = []
      let cursor: string | null = null
      let serverDekVersion: number | null = null
      for (;;) {
        throwIfAborted(signal)
        const query: string = cursor ? `?cursor=${encodeURIComponent(cursor)}&limit=100` : '?limit=100'
        const page: VaultListPageDto = await request<VaultListPageDto>(`/v1/vault/list${query}`, { method: 'GET' }, signal)
        serverDekVersion = page.dek_version
        for (const dto of page.items) {
          items.push(await decryptOverview(dto))
        }
        if (!page.has_more || !page.next_cursor) break
        cursor = page.next_cursor
      }
      if (serverDekVersion !== null && serverDekVersion !== dekVersion) {
        // The DEK rotated between the vault-key download and this list;
        // the loaded DEK is stale, so the user must unlock again.
        dropVaultState()
        throw new VaultApiError('dek_rotated', 409, 'dek_rotated')
      }
      items.sort((a, b) => (a.updatedAt < b.updatedAt ? 1 : a.updatedAt > b.updatedAt ? -1 : 0))
      return items
    },

    async getItem(itemId: string, signal?: AbortSignal): Promise<VaultItem> {
      throwIfAborted(signal)
      requireDek()
      let dto = dtoCache.get(itemId)
      if (!dto) {
        await client.list(signal)
        dto = dtoCache.get(itemId)
      }
      if (!dto) throw new VaultApiError('not_found', 404)
      const overview = await decryptOverview(dto)
      return decryptDetail(dto, overview)
    },

    async createItem(input: VaultItemInput, signal?: AbortSignal): Promise<VaultItem> {
      throwIfAborted(signal)
      requireDek()
      let itemId = randomUuid()
      let payload = await encryptInput(itemId, input)
      const createBody = () => ({
        id: itemId,
        base_version: 0,
        version: 1,
        ...payload,
      })
      let created: { id: string; version: number; updated_at: string }
      try {
        created = await request<{ id: string; version: number; updated_at: string }>('/v1/vault/items', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(createBody()),
        }, signal)
      } catch (error) {
        if (error instanceof VaultApiError && error.code === 'item_id_conflict') {
          // The ciphertext embeds the item id in its AAD, so a new id needs
          // a fresh encryption — reusing the old ciphertext would store an
          // item that can never be decrypted again.
          itemId = randomUuid()
          payload = await encryptInput(itemId, input)
          created = await request<{ id: string; version: number; updated_at: string }>('/v1/vault/items', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(createBody()),
          }, signal)
        } else {
          throw error
        }
      }
      const dto: EncryptedVaultItemDto = {
        id: created.id,
        version: created.version,
        overview_ciphertext: payload.overview_ciphertext,
        overview_nonce: payload.overview_nonce,
        detail_ciphertext: payload.detail_ciphertext,
        detail_nonce: payload.detail_nonce,
        domain_hmac: payload.domain_hmac,
        updated_at: created.updated_at,
        device_id: deviceId ?? null,
      }
      versions.set(created.id, created.version)
      dtoCache.set(created.id, dto)
      const overview = await decryptOverview(dto)
      return decryptDetail(dto, overview)
    },

    async updateItem(itemId: string, input: VaultItemInput, signal?: AbortSignal): Promise<VaultItem> {
      throwIfAborted(signal)
      requireDek()
      const baseVersion = await fetchItemVersion(itemId, signal)
      const payload = await encryptInput(itemId, input)
      const updated = await request<{ id: string; version: number; updated_at: string }>(`/v1/vault/items/${itemId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ base_version: baseVersion, version: baseVersion + 1, ...payload }),
      }, signal)
      const dto: EncryptedVaultItemDto = {
        id: updated.id,
        version: updated.version,
        overview_ciphertext: payload.overview_ciphertext,
        overview_nonce: payload.overview_nonce,
        detail_ciphertext: payload.detail_ciphertext,
        detail_nonce: payload.detail_nonce,
        domain_hmac: payload.domain_hmac,
        updated_at: updated.updated_at,
        device_id: deviceId ?? null,
      }
      versions.set(updated.id, updated.version)
      dtoCache.set(updated.id, dto)
      const overview = await decryptOverview(dto)
      return decryptDetail(dto, overview)
    },

    async deleteItem(itemId: string, signal?: AbortSignal): Promise<void> {
      throwIfAborted(signal)
      requireDek()
      const baseVersion = await fetchItemVersion(itemId, signal)
      await request<{ id: string; version: number; updated_at: string }>(`/v1/vault/items/${itemId}`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ base_version: baseVersion }),
      }, signal)
      versions.delete(itemId)
      dtoCache.delete(itemId)
    },

    async exportBackup(signal?: AbortSignal): Promise<Uint8Array | null> {
      throwIfAborted(signal)
      if (!dekBytes || !kekBytes || !vaultKeyRecord || !userId) return null
      const items = await collectExportItems(signal)
      const container = await buildBackupContainer({
        sourceUserId: userId,
        dek: dekBytes,
        dekVersion: vaultKeyRecord.dek_version,
        kekWrapping: {
          wrappingKey: kekBytes,
          kdfSalt: vaultKeyRecord.kdf_salt,
          kdfParams: vaultKeyRecord.kdf_params,
          kind: 'kek',
          masterPasswordVersion: vaultKeyRecord.master_password_version,
        },
        items,
      })
      return new TextEncoder().encode(container)
    },

    async exportBackupFull(masterPassword: string, recoveryKeyInput: string, signal?: AbortSignal): Promise<Uint8Array> {
      throwIfAborted(signal)
      const { bytes: dek, version: currentDekVersion } = requireDek()
      if (!vaultKeyRecord || !userId) throw new VaultApiError('vault_locked', 401, 'vault_locked')
      let recoveryKey: string
      try {
        recoveryKey = await validateRecoveryKey(recoveryKeyInput)
      } catch {
        throw new VaultApiError('invalid_recovery_key', 400, 'invalid_recovery_key')
      }
      const params = parseKdfParams(vaultKeyRecord.kdf_params)
      // Verify the re-entered master password against the retained wrapped
      // DEK before building: a wrong password must fail here, never produce
      // a backup whose KEK wrapping cannot be opened.
      const kekCandidate = await deriveKek(masterPassword, vaultKeyRecord.kdf_salt, params)
      try {
        await unwrapDek(vaultKeyRecord.wrapped_dek, vaultKeyRecord.nonce, kekCandidate, userId, vaultKeyRecord.dek_version)
      } catch {
        kekCandidate.fill(0)
        throw new VaultApiError('invalid_master_password', 401, 'invalid_master_password')
      }
      throwIfAborted(signal)
      const recoverySalt = toBase64(randomBytes(16))
      const recoveryWrappingKey = await deriveRecoveryWrappingKey(recoveryKey, recoverySalt, params)
      try {
        const items = await collectExportItems(signal)
        const container = await buildBackupContainer({
          sourceUserId: userId,
          dek,
          dekVersion: currentDekVersion,
          kekWrapping: {
            wrappingKey: kekCandidate,
            kdfSalt: vaultKeyRecord.kdf_salt,
            kdfParams: vaultKeyRecord.kdf_params,
            kind: 'kek',
            masterPasswordVersion: vaultKeyRecord.master_password_version,
          },
          recoveryWrapping: {
            wrappingKey: recoveryWrappingKey,
            kdfSalt: recoverySalt,
            kdfParams: vaultKeyRecord.kdf_params,
            kind: 'recovery_key',
          },
          items,
        })
        return new TextEncoder().encode(container)
      } finally {
        kekCandidate.fill(0)
        recoveryWrappingKey.fill(0)
      }
    },

    lock() {
      dropVaultState()
    },

    refreshAccessToken,

    async logout() {
      try {
        await fetch(`${baseUrl}/v1/auth/logout`, { method: 'POST', credentials: 'include' })
      } catch {
        // The local session is cleared regardless; a failed server logout is not fatal.
      }
      dropSession()
    },

    getAccessToken() {
      return accessToken
    },
  }

  return client
}
