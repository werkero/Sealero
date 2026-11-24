/**
 * Shared vault-item payload validation (SD §5.1, §9). Used by the
 * /v1/vault routes and the MCP create_vault_item tool so both enforce the
 * same shape: non-empty ciphertext fields, a lowercase-hex domain_hmac
 * (or null), and a combined octet length within the 1 MB per-item cap.
 */

export const DOMAIN_HMAC_PATTERN = /^[0-9a-f]{64}$/;

/** Per-item cap on the four ciphertext TEXT columns together (SD §5.1). */
export const MAX_VAULT_ITEM_BYTES = 1024 * 1024;

const PAYLOAD_TEXT_KEYS = [
  'overview_ciphertext',
  'overview_nonce',
  'detail_ciphertext',
  'detail_nonce',
] as const;

type JsonRecord = Record<string, unknown>;

export function isValidDomainHmac(value: unknown): value is string | null {
  return value === null || (typeof value === 'string' && DOMAIN_HMAC_PATTERN.test(value));
}

/** Combined UTF-8 octet length of the four ciphertext fields. */
export function vaultPayloadByteLength(value: JsonRecord): number {
  let total = 0;
  for (const key of PAYLOAD_TEXT_KEYS) {
    const field = value[key];
    if (typeof field === 'string') total += Buffer.byteLength(field, 'utf8');
  }
  return total;
}

/**
 * Validates the payload fields shared by vault create/update and MCP
 * create: the four ciphertext fields are non-empty strings, domain_hmac
 * is a 64-character lowercase hex string or null, and the four fields
 * together stay within the 1 MB cap.
 */
export function isVaultPayloadFields(value: JsonRecord): boolean {
  return typeof value['overview_ciphertext'] === 'string' && value['overview_ciphertext'].length > 0 &&
    typeof value['overview_nonce'] === 'string' && value['overview_nonce'].length > 0 &&
    typeof value['detail_ciphertext'] === 'string' && value['detail_ciphertext'].length > 0 &&
    typeof value['detail_nonce'] === 'string' && value['detail_nonce'].length > 0 &&
    isValidDomainHmac(value['domain_hmac']) &&
    vaultPayloadByteLength(value) <= MAX_VAULT_ITEM_BYTES;
}
