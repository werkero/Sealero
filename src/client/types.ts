export interface VaultIdentity {
  id: string
  email: string
}

export interface RecoveryCode {
  id: string
  value: string
}

export interface Passkey {
  credentialId: string
  rpId: string
  publicKey: string
}

/** Decrypted list/search fields only; detail secrets are intentionally absent. */
export interface VaultListItem {
  id: string
  name: string
  url: string
  username: string
  category: string
  tags: string[]
  favorite: boolean
  icon: string
  updatedAt: string
}

/** A selected, decrypted detail merged with its overview; keep only while opened. */
export interface VaultItem extends VaultListItem {
  password: string
  note: string
  totpSecret?: string
  passkey?: Passkey
  recoveryCodes?: RecoveryCode[]
  mnemonic?: string[]
}

/** Decrypted field set the UI hands to the adapter for create/update; the adapter encrypts it. */
export interface VaultItemInput {
  name: string
  url: string
  username: string
  password: string
  note: string
  category: string
  tags: string[]
  favorite: boolean
  icon: string
  totpSecret?: string
  passkey?: Passkey
  recoveryCodes?: RecoveryCode[]
  mnemonic?: string[]
}

/** Ciphertext-only row returned by GET /v1/vault/list (System Design v1.46 §5.1). */
export interface EncryptedVaultItemDto {
  id: string
  version: number
  overview_ciphertext: string
  overview_nonce: string
  detail_ciphertext: string
  detail_nonce: string
  domain_hmac: string | null
  updated_at: string
  device_id: string | null
}

/** A single cursor-paginated response from GET /v1/vault/list. */
export interface VaultListPageDto {
  items: EncryptedVaultItemDto[]
  has_more: boolean
  next_cursor: string | null
  server_time: string
  master_password_version: number
  dek_version: number
}
