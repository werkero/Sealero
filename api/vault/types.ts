export type VaultTimestamp = Date | string | null;

export interface VaultPayload {
  readonly overview_ciphertext: string;
  readonly overview_nonce: string;
  readonly detail_ciphertext: string;
  readonly detail_nonce: string;
  readonly domain_hmac: string | null;
}

export interface VaultItemInput extends VaultPayload {
  readonly id: string;
  readonly version: number;
}

export interface VaultItemResponse {
  readonly id: string;
  readonly version: number;
  readonly updated_at: string;
}

/** Full ciphertext of one item, for the atomic confirmation consume-and-read (SD §5.3). */
export interface VaultItemPayload extends VaultPayload {
  readonly id: string;
  readonly version: number;
  readonly deletedAt: VaultTimestamp;
}

export interface VaultListItem extends VaultPayload {
  readonly id: string;
  readonly version: number;
  readonly updated_at: string;
  readonly device_id: string | null;
}

export interface VaultPage {
  readonly items: readonly VaultListItem[];
  readonly has_more: boolean;
  readonly next_cursor: string | null;
  readonly server_time: string;
  readonly master_password_version: number;
  readonly dek_version: number;
}

export interface VaultItemStatus {
  readonly id: string;
  readonly status: 'active' | 'deleted';
  readonly version: number;
  readonly device_id: string | null;
  readonly deleted_at?: string;
}

export interface VaultAccessStatus {
  readonly emailVerifiedAt: VaultTimestamp;
  readonly requireEmailVerification: boolean;
  readonly hasCurrentPrivacyConsent: boolean;
}

export interface VaultKeyRecord {
  readonly wrapped_dek: string;
  readonly nonce: string;
  readonly kdf_salt: string;
  readonly kdf_params: string;
  readonly dek_version: number;
  readonly master_password_version: number;
}

export interface VaultKeyWriteInput extends VaultKeyRecord {
  readonly expected_wrapping_state_hash: string | null;
}

export type VaultKeyWriteOutcome =
  | { readonly kind: 'ok'; readonly record: VaultKeyRecord }
  | { readonly kind: 'conflict' };

export interface VaultKeyStore {
  getVaultKey(userId: string): Promise<VaultKeyRecord | null>;
  saveVaultKey(userId: string, input: VaultKeyWriteInput): Promise<VaultKeyWriteOutcome>;
}

export type VaultCreateOutcome =
  | { readonly kind: 'ok'; readonly item: VaultItemResponse; readonly replayed: boolean }
  | { readonly kind: 'deleted' }
  | { readonly kind: 'item_id_conflict' }
  | { readonly kind: 'payload_conflict' };

export type VaultUpdateOutcome =
  | { readonly kind: 'ok'; readonly item: VaultItemResponse; readonly replayed: boolean }
  | { readonly kind: 'not_found' }
  | { readonly kind: 'deleted' }
  | { readonly kind: 'version_conflict' }
  | { readonly kind: 'server_behind' }
  | { readonly kind: 'already_applied_payload_mismatch' };

export interface VaultDeleteResponse {
  readonly id: string;
  readonly version: number;
  readonly deleted_at: string;
}

export type VaultDeleteOutcome =
  | { readonly kind: 'ok'; readonly item: VaultDeleteResponse; readonly replayed: boolean }
  | { readonly kind: 'not_found' }
  | { readonly kind: 'version_conflict' };

export interface VaultDomainMatch {
  readonly id: string;
  readonly overview_ciphertext: string;
  readonly overview_nonce: string;
}

/** Storage capabilities required by the authenticated vault routes. */
export interface VaultStore {
  getVaultAccessStatus(userId: string, policyVersion: string): Promise<VaultAccessStatus | null>;
  /**
   * Active items whose domain_hmac matches exactly, for MCP search (SD §5.3).
   * Only ciphertext is returned; the server never decrypts.
   */
  findVaultItemsByDomainHmac(
    userId: string,
    domainHmac: string,
    limit: number,
  ): Promise<readonly VaultDomainMatch[]>;
  listVaultPage(userId: string, cursor: string | null, limit: number, serverTime: Date): Promise<VaultPage | null>;
  getVaultItemStatus(userId: string, itemId: string): Promise<VaultItemStatus | null>;
  /**
   * deviceId is null for items created without a device (MCP OAuth has no
   * device); the column is nullable and idempotency does not compare it.
   */
  createVaultItem(userId: string, deviceId: string | null, input: VaultItemInput): Promise<VaultCreateOutcome>;
  updateVaultItem(
    userId: string,
    deviceId: string,
    itemId: string,
    baseVersion: number,
    input: VaultItemInput,
  ): Promise<VaultUpdateOutcome>;
  deleteVaultItem(
    userId: string,
    deviceId: string,
    itemId: string,
    baseVersion: number,
  ): Promise<VaultDeleteOutcome>;
  cleanupExpiredTombstones(now: Date): Promise<number>;
}
