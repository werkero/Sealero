import { Hono } from 'hono';
import type { Context } from 'hono';
import { ApiError } from '../app.js';
import type { AuthenticatedEnvironment } from '../middleware/authentication.js';
import { computeWrappingStateHash, parseCanonicalKdfParams } from '../vault/key.js';
import type { VaultKeyRecord, VaultKeyStore, VaultKeyWriteInput, VaultStore } from '../vault/types.js';

const REQUEST_KEYS = [
  'wrapped_dek',
  'nonce',
  'kdf_salt',
  'kdf_params',
  'dek_version',
  'master_password_version',
  'expected_wrapping_state_hash',
] as const;
const HASH_PATTERN = /^[0-9a-f]{64}$/;

type JsonRecord = Record<string, unknown>;
type VaultKeyContext = Context<AuthenticatedEnvironment>;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(value: JsonRecord, allowed: readonly string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

async function readJson(context: VaultKeyContext): Promise<unknown> {
  try {
    return await context.req.json();
  } catch {
    throw new ApiError(400, 'invalid_request', 'The request body must be valid JSON.');
  }
}

function isVersion(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isWriteInput(value: unknown): value is VaultKeyWriteInput {
  if (!isRecord(value) || !hasOnlyKeys(value, REQUEST_KEYS)) return false;
  const expectedHash = value['expected_wrapping_state_hash'];
  return typeof value['wrapped_dek'] === 'string' && value['wrapped_dek'].length > 0 &&
    typeof value['nonce'] === 'string' && value['nonce'].length > 0 &&
    typeof value['kdf_salt'] === 'string' && value['kdf_salt'].length > 0 &&
    typeof value['kdf_params'] === 'string' && parseCanonicalKdfParams(value['kdf_params']) !== null &&
    isVersion(value['dek_version']) && isVersion(value['master_password_version']) &&
    (expectedHash === null || (typeof expectedHash === 'string' && HASH_PATTERN.test(expectedHash)));
}

async function requireVaultAccess(store: VaultStore, userId: string, policyVersion: string): Promise<void> {
  const access = await store.getVaultAccessStatus(userId, policyVersion);
  if (access === null) {
    throw new ApiError(401, 'unauthorized', 'A valid access token is required.');
  }
  if (access.requireEmailVerification && access.emailVerifiedAt === null) {
    throw new ApiError(403, 'email_verification_required', 'Verify your email before using the vault.');
  }
  if (!access.hasCurrentPrivacyConsent) {
    throw new ApiError(403, 'consent_required', 'Accept the current privacy policy before using the vault.');
  }
}

function response(record: VaultKeyRecord, userId: string): VaultKeyRecord & { readonly wrapping_state_hash: string } {
  return { ...record, wrapping_state_hash: computeWrappingStateHash(userId, record) };
}

export function createVaultKeyRoutes(
  store: VaultStore & VaultKeyStore,
  policyVersion: string,
): Hono<AuthenticatedEnvironment> {
  const routes = new Hono<AuthenticatedEnvironment>();

  routes.get('/vault-key', async (context) => {
    const userId = context.get('auth').sub;
    await requireVaultAccess(store, userId, policyVersion);
    const record = await store.getVaultKey(userId);
    if (record === null) {
      throw new ApiError(404, 'vault_key_not_found', 'No wrapped DEK is stored for this account.');
    }
    return context.json(response(record, userId));
  });

  routes.post('/vault-key', async (context) => {
    const userId = context.get('auth').sub;
    await requireVaultAccess(store, userId, policyVersion);
    const body: unknown = await readJson(context);
    if (!isWriteInput(body)) {
      throw new ApiError(400, 'invalid_request', 'The vault key request is invalid.');
    }

    const outcome = await store.saveVaultKey(userId, body);
    if (outcome.kind === 'conflict') {
      throw new ApiError(409, 'vault_key_conflict', 'The vault key changed or the requested update is not allowed. Fetch the latest key and retry.');
    }
    return context.json(response(outcome.record, userId));
  });

  return routes;
}
