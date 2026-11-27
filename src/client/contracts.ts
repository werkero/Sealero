import type { EncryptedVaultItemDto, VaultIdentity, VaultItem, VaultItemInput, VaultListItem, VaultListPageDto } from './types'

/** Input for POST /v1/vault-key (System Design §5.1). `expected_wrapping_state_hash` is null on the first upload. */
export interface VaultKeyUploadInput {
  wrapped_dek: string
  nonce: string
  kdf_salt: string
  kdf_params: string
  dek_version: number
  master_password_version: number
  expected_wrapping_state_hash: string | null
}

/** The 7 fields GET/POST /v1/vault-key return (System Design §5.1). */
export interface VaultKeyRecord {
  wrapped_dek: string
  nonce: string
  kdf_salt: string
  kdf_params: string
  dek_version: number
  master_password_version: number
  wrapping_state_hash: string
}

/** Serializable unlocked session: base64 DEK + KEK, dek version, vault-key record. Stored in the current tab's sessionStorage only, so a refresh inside the idle window restores the unlock; cleared on tab close, lock, or logout. */
export interface UnlockedSessionBlob {
  dek: string
  kek: string
  version: number
  record: VaultKeyRecord
}

/**
 * Client-side boundary for the Web vault, backed by the production HTTP
 * adapter (`./http-vault-client`). The adapter keeps the access JWT, derived
 * keys, and decrypted items in memory only; the refresh token belongs
 * exclusively in an HttpOnly, Secure, SameSite=Lax cookie. The unlocked
 * DEK + KEK may be exported (see `exportSessionUnlock`) so the session
 * layer can keep them in the current tab's sessionStorage — the vault
 * stays unlocked across a refresh inside the 15-minute idle window, and
 * the blob dies with the tab. The master password is never stored, and
 * no vault data ever goes to localStorage, IndexedDB, or the server.
 * Only the device id is persisted (localStorage) so login can reuse the
 * server device row.
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
  /**
   * Registration (System Design §5.1). Creates the account; the server
   * response is generic by design (anti-enumeration) and reveals neither
   * whether the email already exists nor whether registration is open.
   * It does report the global `emailVerificationRequired` setting, which
   * is the same for every email: when false the caller skips the
   * verification step and proceeds to set the master password. When the
   * setting changes mid-flow, `verifyEmail` throws
   * `email_verification_disabled` and the caller skips that step.
   */
  register(email: string, loginPassword: string, signal?: AbortSignal): Promise<{ emailVerificationRequired: boolean }>
  /**
   * Whether the current user (JWT only, never another account) already has
   * a wrapped DEK on the server. GET /v1/vault-key answers 200 when one
   * exists and 404 when none was ever uploaded; a 403 `consent_required`
   * is resolved by submitting the current consent first and retrying once,
   * because vault setup submits that consent anyway. Other errors (for
   * example 403 `email_verification_required`) are thrown so the caller
   * falls back to the unlock page.
   */
  hasVaultKey(signal?: AbortSignal): Promise<boolean>
  /**
   * Reads the current login identity (GET /v1/auth/me, System Design §5.1).
   * Used to restore the session after a page refresh: refresh the access
   * token first, then call this. It returns only {id, email}; the vault
   * is then restored from the tab's sessionStorage when the idle window
   * has not expired, otherwise it stays locked until the user unlocks
   * with the master password.
   */
  getCurrentUser(signal?: AbortSignal): Promise<VaultIdentity>
  /**
   * Reads the current user's preferences (GET /v1/user/preferences,
   * System Design §5.1). Returns the stored auto-lock timeout in
   * minutes, or the 15-minute default when the user never set one.
   */
  getUserPreferences(signal?: AbortSignal): Promise<{ auto_lock_minutes: number }>
  /**
   * Replaces the current user's auto-lock timeout (PUT
   * /v1/user/preferences). The value must be one of 5 / 15 / 30 / 60;
   * anything else is rejected by the server with 400 invalid_request.
   */
  updateUserPreferences(autoLockMinutes: number, signal?: AbortSignal): Promise<{ auto_lock_minutes: number }>
  verifyEmail(email: string, code: string, signal?: AbortSignal): Promise<void>
  resendVerification(email: string, signal?: AbortSignal): Promise<void>
  /**
   * Reads the public `policy_version` from GET /v1/health (System Design
   * §5.1). The client needs it to submit consent before uploading the
   * vault key at registration.
   */
  fetchPolicyVersion(signal?: AbortSignal): Promise<string>
  /** Submits the current privacy consent (POST /v1/auth/consent). Requires a login session. */
  submitConsent(policyVersion: string, signal?: AbortSignal): Promise<void>
  /** Uploads the KEK-wrapped DEK for a new account (POST /v1/vault-key). Requires a login session. */
  uploadVaultKey(input: VaultKeyUploadInput, signal?: AbortSignal): Promise<VaultKeyRecord>
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
  /**
   * Exports the unlocked session (base64 DEK + KEK, dek version,
   * vault-key record) for the session layer to keep in the current
   * tab's sessionStorage, so a refresh inside the idle window restores
   * the unlock without the master password. Returns null when the
   * vault is locked. The KEK is included because `exportBackup` needs
   * it; a DEK-only restore would silently break auto-backup after
   * every refresh.
   */
  exportSessionUnlock(): UnlockedSessionBlob | null
  /**
   * Restores an unlocked session exported by `exportSessionUnlock`
   * (sets DEK/KEK/record in memory). The caller must check the idle
   * window first and call `list()` afterwards: its built-in
   * dek_version check throws `dek_rotated` when the server-side key
   * has changed since the export.
   */
  restoreSessionUnlock(blob: UnlockedSessionBlob): Promise<void>
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
