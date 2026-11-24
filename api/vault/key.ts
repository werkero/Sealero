import { createHash } from 'node:crypto';
import type { VaultKeyRecord } from './types.js';

export interface KdfParams {
  readonly algorithm: 'argon2id';
  readonly m: number;
  readonly output_len: number;
  readonly p: number;
  readonly t: number;
}

export const KDF_TIERS: readonly KdfParams[] = [
  { algorithm: 'argon2id', m: 65_536, output_len: 32, p: 4, t: 3 },
  { algorithm: 'argon2id', m: 131_072, output_len: 32, p: 4, t: 3 },
  { algorithm: 'argon2id', m: 131_072, output_len: 32, p: 4, t: 4 },
  { algorithm: 'argon2id', m: 262_144, output_len: 32, p: 4, t: 4 },
] as const;

const KDF_PARAM_KEYS = ['algorithm', 'm', 'output_len', 'p', 't'] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Parse only the exact compact JSON representation required by System Design §7.1. */
export function parseCanonicalKdfParams(raw: unknown): KdfParams | null {
  if (typeof raw !== 'string') return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    return null;
  }
  if (!isRecord(parsed)) return null;
  const keys = Object.keys(parsed);
  if (keys.length !== KDF_PARAM_KEYS.length || !KDF_PARAM_KEYS.every((key) => keys.includes(key))) return null;

  const { algorithm, m, output_len: outputLen, p, t } = parsed;
  if (
    algorithm !== 'argon2id' ||
    typeof m !== 'number' || !Number.isSafeInteger(m) || m < 1 ||
    typeof outputLen !== 'number' || !Number.isSafeInteger(outputLen) || outputLen < 1 ||
    typeof p !== 'number' || !Number.isSafeInteger(p) || p < 1 ||
    typeof t !== 'number' || !Number.isSafeInteger(t) || t < 1
  ) {
    return null;
  }

  const normalized: KdfParams = { algorithm, m, output_len: outputLen, p, t };
  if (JSON.stringify(normalized) !== raw) return null;
  return normalized;
}

/** Returns the fixed-order KDF tier index, or null for parameters outside the published whitelist. */
export function kdfTierIndex(raw: string): number | null {
  const params = parseCanonicalKdfParams(raw);
  if (params === null) return null;
  const index = KDF_TIERS.findIndex((tier) =>
    tier.algorithm === params.algorithm &&
    tier.m === params.m &&
    tier.output_len === params.output_len &&
    tier.p === params.p &&
    tier.t === params.t,
  );
  return index === -1 ? null : index;
}

/** Hashes the canonical, newline-delimited server state defined in System Design §7.1. */
export function computeWrappingStateHash(userId: string, record: VaultKeyRecord): string {
  const state = [
    'sealero-dek-wrap-v1',
    userId.toLowerCase(),
    String(record.dek_version),
    String(record.master_password_version),
    record.wrapped_dek,
    record.nonce,
    record.kdf_salt,
    record.kdf_params,
  ].join('\n');
  return createHash('sha256').update(state, 'utf8').digest('hex');
}
