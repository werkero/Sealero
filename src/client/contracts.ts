import type { EncryptedVaultItemDto, VaultIdentity, VaultItem, VaultItemInput, VaultListItem, VaultListPageDto } from './types'

/**
 * Client-side boundary for the Web vault, backed by the production HTTP
 * adapter (`./http-vault-client`). The adapter keeps the access JWT, derived
 * keys, and decrypted items in memory only; the refresh token belongs
 * exclusively in an HttpOnly, Secure, SameSite=Lax cookie. It must never
 * persist vault/session/queue data in browser storage. The master password
 * is used locally and must not be sent to the API. Only the device id is
 * persisted (localStorage) so login can reuse the server device row.
 *
 * `list` follows GET /v1/vault/list and decrypts overview fields only. Ciphertext
 * detail blocks may remain in adapter memory, but `getItem` decrypts only the
 * selected entry when the user opens it. Async operations must honor their
 * AbortSignal at every await boundary and discard aborted results before mutating
 * adapter-held credentials, keys, or plaintext.
 */
export interface VaultClient {
  login(email: string, loginPassword: string, signal?: AbortSignal): Promise<VaultIdentity>
  unlock(masterPassword: string, signal?: AbortSignal): Promise<void>
  list(signal?: AbortSignal): Promise<VaultListItem[]>
  getItem(itemId: string, signal?: AbortSignal): Promise<VaultItem>
  createItem(input: VaultItemInput, signal?: AbortSignal): Promise<VaultItem>
  updateItem(itemId: string, input: VaultItemInput, signal?: AbortSignal): Promise<VaultItem>
  deleteItem(itemId: string, signal?: AbortSignal): Promise<void>
  /**
   * Builds a v3 backup container with only the KEK wrapping (auto-backup /
   * "back up now"). Uses the KEK retained in memory from unlock; the DEK
   * never leaves the adapter and no master password or recovery key is
   * needed. Returns null when the vault is locked. The container opens
   * with the master password alone (System Design §7.4).
   */
  exportBackup(signal?: AbortSignal): Promise<Uint8Array | null>
  /**
   * Builds a full v3 backup container (KEK + recovery-key wrappings) for
   * manual export. Re-derives the KEK from the given master password and
   * verifies it against the wrapped DEK before building; throws
   * `invalid_master_password` on a wrong master password and
   * `invalid_recovery_key` on a malformed recovery key. The master
   * password and recovery key are used only for this call and never
   * retained. Throws `vault_locked` when the vault is locked.
   */
  exportBackupFull(masterPassword: string, recoveryKey: string, signal?: AbortSignal): Promise<Uint8Array>
  lock(): void
  logout(): Promise<void>
  /**
   * Refreshes the access JWT through the HttpOnly refresh cookie and
   * returns the new token. Concurrent callers share one in-flight refresh,
   * and the new token is stored in the adapter so `getAccessToken` returns
   * it afterwards. The admin and MCP-confirmation clients call this on 401
   * instead of refreshing on their own, so one refresh serves every client
   * and a concurrent 401 can never trigger the server's refresh-token
   * reuse detection.
   */
  refreshAccessToken(signal?: AbortSignal): Promise<string>
  /**
   * Returns the in-memory access JWT when the adapter holds one; a production
   * HTTP adapter implements it so the admin-status probe can authenticate.
   * The token itself is never persisted or rendered anywhere.
   */
  getAccessToken?: () => string | null
}

/** API response DTOs defined by System Design v1.46 §5.1; these are ciphertext, not UI models. */
export type { EncryptedVaultItemDto, VaultListPageDto }

/** Decrypted view models are held only in the page's live React state. */
export type { VaultItem, VaultIdentity, VaultListItem, VaultItemInput }
