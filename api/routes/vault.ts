import { Hono } from 'hono';
import type { Context } from 'hono';
import { ApiError } from '../app.js';
import type { AuthenticatedEnvironment } from '../middleware/authentication.js';
import type { VaultItemInput, VaultPayload, VaultStore } from '../vault/types.js';
import { isVaultPayloadFields } from '../vault/validation.js';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PAYLOAD_KEYS = [
  'overview_ciphertext',
  'overview_nonce',
  'detail_ciphertext',
  'detail_nonce',
  'domain_hmac',
] as const;
const CREATE_KEYS = ['id', 'base_version', 'version', ...PAYLOAD_KEYS] as const;
const UPDATE_KEYS = ['base_version', 'version', ...PAYLOAD_KEYS] as const;
const DELETE_KEYS = ['base_version'] as const;

type JsonRecord = Record<string, unknown>;
type VaultContext = Context<AuthenticatedEnvironment>;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(value: JsonRecord, allowed: readonly string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

async function readJson(context: VaultContext): Promise<unknown> {
  try {
    return await context.req.json();
  } catch {
    throw new ApiError(400, 'invalid_request', 'The request body must be valid JSON.');
  }
}

function isVersion(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isPayload(value: JsonRecord): value is JsonRecord & VaultPayload {
  return isVaultPayloadFields(value);
}

function invalidPathId(): ApiError {
  return new ApiError(400, 'invalid_request', 'The item ID must be a UUID.');
}

function requireUuid(value: string): void {
  if (!UUID_PATTERN.test(value)) throw invalidPathId();
}

export function createVaultRoutes(
  store: VaultStore,
  policyVersion: string,
  now: () => Date = () => new Date(),
): Hono<AuthenticatedEnvironment> {
  const routes = new Hono<AuthenticatedEnvironment>();

  routes.use('/vault/*', async (context, next) => {
    const access = await store.getVaultAccessStatus(context.get('auth').sub, policyVersion);
    if (access === null) {
      throw new ApiError(401, 'unauthorized', 'A valid access token is required.');
    }
    if (access.requireEmailVerification && access.emailVerifiedAt === null) {
      throw new ApiError(403, 'email_verification_required', 'Verify your email before using the vault.');
    }
    if (!access.hasCurrentPrivacyConsent) {
      throw new ApiError(403, 'consent_required', 'Accept the current privacy policy before using the vault.');
    }
    await next();
  });

  routes.get('/vault/list', async (context) => {
    const rawLimit = context.req.query('limit');
    const limit = rawLimit === undefined ? 100 : Number(rawLimit);
    if (rawLimit !== undefined && (!/^\d+$/.test(rawLimit) || !Number.isSafeInteger(limit) || limit < 1 || limit > 500)) {
      throw new ApiError(400, 'invalid_pagination', 'The limit must be an integer from 1 to 500.');
    }

    const rawCursor = context.req.query('cursor');
    if (rawCursor !== undefined && !UUID_PATTERN.test(rawCursor)) {
      throw new ApiError(400, 'invalid_cursor', 'The cursor must be an item UUID.');
    }
    const page = await store.listVaultPage(
      context.get('auth').sub,
      rawCursor ?? null,
      limit,
      now(),
    );
    if (page === null) {
      throw new ApiError(400, 'invalid_cursor', 'The cursor does not identify an item in this account.');
    }
    return context.json(page);
  });

  routes.get('/vault/items/:id/status', async (context) => {
    const itemId = context.req.param('id');
    requireUuid(itemId);
    const status = await store.getVaultItemStatus(context.get('auth').sub, itemId);
    if (status === null) {
      throw new ApiError(404, 'not_found', 'The requested resource was not found.');
    }
    return context.json(status);
  });

  routes.post('/vault/items', async (context) => {
    const body: unknown = await readJson(context);
    if (
      !isRecord(body) || !hasOnlyKeys(body, CREATE_KEYS) ||
      typeof body['id'] !== 'string' || !UUID_PATTERN.test(body['id']) ||
      body['base_version'] !== 0 || body['version'] !== 1 || !isPayload(body)
    ) {
      throw new ApiError(400, 'invalid_request', 'The new vault item request is invalid.');
    }

    const input: VaultItemInput = {
      id: body['id'],
      version: 1,
      overview_ciphertext: body['overview_ciphertext'],
      overview_nonce: body['overview_nonce'],
      detail_ciphertext: body['detail_ciphertext'],
      detail_nonce: body['detail_nonce'],
      domain_hmac: body['domain_hmac'],
    };
    const auth = context.get('auth');
    const result = await store.createVaultItem(auth.sub, auth.device_id, input);
    if (result.kind === 'deleted') {
      throw new ApiError(410, 'item_deleted', 'This item ID has already been deleted.');
    }
    if (result.kind === 'item_id_conflict') {
      throw new ApiError(409, 'item_id_conflict', 'This item ID is already in use.');
    }
    if (result.kind === 'payload_conflict') {
      throw new ApiError(409, 'item_payload_conflict', 'This item ID already exists with a different payload.');
    }
    return context.json(result.item);
  });

  routes.put('/vault/items/:id', async (context) => {
    const itemId = context.req.param('id');
    requireUuid(itemId);
    const body: unknown = await readJson(context);
    if (
      !isRecord(body) || !hasOnlyKeys(body, UPDATE_KEYS) ||
      !isVersion(body['base_version']) || !isVersion(body['version']) || !isPayload(body)
    ) {
      throw new ApiError(400, 'invalid_request', 'The vault item update request is invalid.');
    }

    const input: VaultItemInput = {
      id: itemId,
      version: body['version'],
      overview_ciphertext: body['overview_ciphertext'],
      overview_nonce: body['overview_nonce'],
      detail_ciphertext: body['detail_ciphertext'],
      detail_nonce: body['detail_nonce'],
      domain_hmac: body['domain_hmac'],
    };
    const auth = context.get('auth');
    const result = await store.updateVaultItem(auth.sub, auth.device_id, itemId, body['base_version'], input);
    if (result.kind === 'not_found') {
      throw new ApiError(404, 'not_found', 'The requested resource was not found.');
    }
    if (result.kind === 'deleted') {
      throw new ApiError(410, 'item_deleted', 'This item has already been deleted.');
    }
    if (result.kind === 'server_behind') {
      throw new ApiError(409, 'server_behind', 'The server version is behind the client version; pull the item first.');
    }
    if (result.kind === 'already_applied_payload_mismatch') {
      throw new ApiError(409, 'already_applied_payload_mismatch', 'This version was already applied with a different payload.');
    }
    if (result.kind === 'version_conflict') {
      throw new ApiError(409, 'conflict', 'The vault item version conflicts with the server version.');
    }
    return context.json(result.item);
  });

  routes.delete('/vault/items/:id', async (context) => {
    const itemId = context.req.param('id');
    requireUuid(itemId);
    const body: unknown = await readJson(context);
    if (!isRecord(body) || !hasOnlyKeys(body, DELETE_KEYS) || !isVersion(body['base_version'])) {
      throw new ApiError(400, 'invalid_request', 'The vault item delete request is invalid.');
    }

    const auth = context.get('auth');
    const result = await store.deleteVaultItem(auth.sub, auth.device_id, itemId, body['base_version']);
    if (result.kind === 'not_found') {
      throw new ApiError(404, 'not_found', 'The requested resource was not found.');
    }
    if (result.kind === 'version_conflict') {
      throw new ApiError(409, 'conflict', 'The vault item version conflicts with the server version.');
    }
    return context.json(result.item);
  });

  return routes;
}
