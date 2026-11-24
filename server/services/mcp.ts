import { ApiError } from '../app.js';
import type { AuthStore, AuthTransaction } from '../auth/types.js';
import { MCP_CONFIRMATION_TTL_MS } from '../oauth/types.js';
import type { OAuthStore } from '../oauth/types.js';
import type { VaultItemInput, VaultItemPayload, VaultStore } from '../vault/types.js';
import { DOMAIN_HMAC_PATTERN, isVaultPayloadFields } from '../vault/validation.js';

/**
 * MCP Streamable HTTP tools (System Design §5.3). The server only matches
 * domain_hmac and returns ciphertext; decryption happens in the connector's
 * trusted unlock step, never on the server.
 *
 * Tool names, result envelopes and audit actions are `search_vault_items` /
 * `get_vault_item` / `create_vault_item` and `mcp_search` / `mcp_get_item` /
 * `mcp_create_item`. `get_vault_item` needs a trusted confirmation (SD §5.3):
 * the first call for an item creates a confirmation record and answers 403
 * `confirmation_required` with its id; the user approves or denies it in
 * the trusted web UI; a retry after approval delivers the ciphertext once
 * and consumes the confirmation. The AI cannot approve its own request.
 */

export interface McpAuth {
  readonly userId: string;
  readonly authorizationId: string;
  readonly scopes: readonly string[];
  readonly clientId: string;
}

export type McpStore = AuthStore & OAuthStore & VaultStore;

const MCP_SEARCH_LIMIT = 100;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const MCP_PROTOCOL_VERSIONS = ['2025-03-26', '2025-06-18', '2024-11-05'] as const;

export interface McpToolDefinition {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Record<string, unknown>;
}

export const MCP_TOOLS: readonly McpToolDefinition[] = [
  {
    name: 'search_vault_items',
    description: 'Search vault items by domain HMAC. Returns matching item IDs with overview ciphertext for local domain verification. Requires mcp:read.',
    inputSchema: {
      type: 'object',
      properties: {
        domain_hmac: { type: 'string', description: 'Lowercase hex HMAC-SHA256 of the normalized domain (SD §7.5).' },
      },
      required: ['domain_hmac'],
      additionalProperties: false,
    },
  },
  {
    name: 'get_vault_item',
    description: 'Get one vault item by ID. Requires trusted confirmation: the first call returns 403 confirmation_required with a confirmation_id; the user approves it in the Sealero web UI, then retrying this tool delivers the item once. Requires mcp:read.',
    inputSchema: {
      type: 'object',
      properties: {
        item_id: { type: 'string', description: 'Vault item UUID.' },
      },
      required: ['item_id'],
      additionalProperties: false,
    },
  },
  {
    name: 'create_vault_item',
    description: 'Create one vault item. Requires mcp:write.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'New item UUID.' },
        base_version: { type: 'integer', description: 'Must be 0 for a new item.' },
        version: { type: 'integer', description: 'Must be 1 for a new item.' },
        overview_ciphertext: { type: 'string' },
        overview_nonce: { type: 'string' },
        detail_ciphertext: { type: 'string' },
        detail_nonce: { type: 'string' },
        domain_hmac: { type: ['string', 'null'], description: 'Lowercase hex HMAC-SHA256, or null when the item has no domain.' },
      },
      required: ['id', 'base_version', 'version', 'overview_ciphertext', 'overview_nonce', 'detail_ciphertext', 'detail_nonce', 'domain_hmac'],
      additionalProperties: false,
    },
  },
];

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasScope(auth: McpAuth, scope: string): boolean {
  return auth.scopes.includes(scope);
}

function textResult(text: string): Record<string, unknown> {
  return { content: [{ type: 'text', text }] };
}

function jsonRpcResult(id: unknown, result: unknown): Record<string, unknown> {
  return { jsonrpc: '2.0', id, result };
}

function jsonRpcError(id: unknown, code: number, message: string, data?: unknown): Record<string, unknown> {
  return {
    jsonrpc: '2.0',
    id,
    error: data === undefined ? { code, message } : { code, message, data },
  };
}

/**
 * Writes one MCP audit row. Audit must never fail the tool call itself:
 * the vault operation already committed, so a lost audit row is better
 * than a false 500 (whose retry would hit item_id_conflict). Failures
 * are logged with the action name only — audit metadata never holds
 * secrets, so there is nothing sensitive to leak here.
 */
async function writeMcpAudit(
  store: McpStore,
  auth: McpAuth,
  action: string,
  targetType: string,
  metadata: JsonRecord,
  now: Date,
): Promise<void> {
  try {
    await store.transaction((transaction) => transaction.insertAuditLog({
      actorUserId: auth.userId,
      targetUserId: auth.userId,
      action,
      targetType,
      metadata: JSON.stringify(metadata),
      ipAddress: null,
      createdAt: now,
    }));
  } catch {
    console.error(JSON.stringify({ level: 'error', event: 'mcp_audit_failed', action }));
  }
}

async function insertGetItemAudit(
  transaction: AuthTransaction,
  auth: McpAuth,
  itemId: string,
  outcome: string,
  now: Date,
): Promise<void> {
  await transaction.insertAuditLog({
    actorUserId: auth.userId,
    targetUserId: auth.userId,
    action: 'mcp_get_item',
    targetType: 'oauth_authorization',
    metadata: JSON.stringify({ item_id: itemId, outcome }),
    ipAddress: null,
    createdAt: now,
  });
}

type GetVaultItemOutcome =
  | { kind: 'delivered'; payload: VaultItemPayload }
  | { kind: 'confirmation_required'; confirmationId: string }
  | { kind: 'confirmation_pending'; confirmationId: string }
  | { kind: 'not_found' }
  | { kind: 'item_deleted' };

/**
 * Trusted-confirmation flow for one item (SD §5.3). The item read, the
 * approval lookup and the consume happen in one transaction, so a
 * concurrent delete cannot leak a just-deleted item's ciphertext and a
 * confirmation can only be spent once. Every call writes one
 * `mcp_get_item` audit row with an outcome; creating a confirmation also
 * writes `mcp_confirmation_requested`. A retry is a plain retry with the
 * same `item_id`: the server matches by (user, authorization, item), so
 * no token has to be passed back by the client.
 */
async function getVaultItem(
  store: McpStore,
  auth: McpAuth,
  itemId: string,
  now: Date,
): Promise<Record<string, unknown>> {
  const outcome = await store.transaction<GetVaultItemOutcome>(async (transaction) => {
    const payload = await transaction.findVaultItemPayloadForUpdate(auth.userId, itemId);
    if (payload === null) {
      await insertGetItemAudit(transaction, auth, itemId, 'not_found', now);
      return { kind: 'not_found' };
    }
    if (payload.deletedAt !== null) {
      await insertGetItemAudit(transaction, auth, itemId, 'item_deleted', now);
      return { kind: 'item_deleted' };
    }
    const approved = await transaction.findApprovedMcpConfirmationForUpdate(
      auth.userId, auth.authorizationId, itemId, now);
    if (approved !== null) {
      const consumed = await transaction.consumeMcpConfirmation(approved.id, now);
      if (consumed) {
        await insertGetItemAudit(transaction, auth, itemId, 'delivered', now);
        return { kind: 'delivered', payload };
      }
      // A concurrent retry spent the approval first; fall through and
      // ask for a fresh confirmation instead of failing the call.
    }
    const pending = await transaction.findPendingMcpConfirmationForUpdate(
      auth.userId, auth.authorizationId, itemId, now);
    if (pending !== null) {
      await insertGetItemAudit(transaction, auth, itemId, 'confirmation_pending', now);
      return { kind: 'confirmation_pending', confirmationId: pending.id };
    }
    const confirmationId = await transaction.insertMcpConfirmation({
      userId: auth.userId,
      authorizationId: auth.authorizationId,
      itemId,
      expiresAt: new Date(now.getTime() + MCP_CONFIRMATION_TTL_MS),
      createdAt: now,
    });
    await transaction.insertAuditLog({
      actorUserId: auth.userId,
      targetUserId: auth.userId,
      action: 'mcp_confirmation_requested',
      targetType: 'oauth_authorization',
      metadata: JSON.stringify({ item_id: itemId, confirmation_id: confirmationId }),
      ipAddress: null,
      createdAt: now,
    });
    await insertGetItemAudit(transaction, auth, itemId, 'confirmation_required', now);
    return { kind: 'confirmation_required', confirmationId };
  });

  if (outcome.kind === 'delivered') {
    return {
      result: textResult(JSON.stringify({
        item_id: outcome.payload.id,
        version: outcome.payload.version,
        overview_ciphertext: outcome.payload.overview_ciphertext,
        overview_nonce: outcome.payload.overview_nonce,
        detail_ciphertext: outcome.payload.detail_ciphertext,
        detail_nonce: outcome.payload.detail_nonce,
      })),
    };
  }
  if (outcome.kind === 'not_found') {
    throw new ApiError(404, 'item_not_found', 'No such vault item.');
  }
  if (outcome.kind === 'item_deleted') {
    throw new ApiError(410, 'item_deleted', 'This vault item has been deleted.');
  }
  throw new ApiError(
    403,
    'confirmation_required',
    outcome.kind === 'confirmation_pending'
      ? 'This item needs trusted confirmation; the request is already waiting for the user to approve it in the Sealero web UI.'
      : 'Getting item details requires trusted confirmation. Ask the user to approve this request in the Sealero web UI, then retry.',
    undefined,
    { confirmation_id: outcome.confirmationId },
  );
}

function parseToolArguments(params: unknown): JsonRecord {
  if (!isRecord(params) || !isRecord(params['arguments'])) {
    throw new Error('invalid_params');
  }
  return params['arguments'];
}

function isPayload(value: JsonRecord): value is JsonRecord & VaultItemInput {
  return typeof value['id'] === 'string' && UUID_PATTERN.test(value['id']) &&
    value['base_version'] === 0 && value['version'] === 1 &&
    isVaultPayloadFields(value);
}

async function callTool(
  store: McpStore,
  auth: McpAuth,
  name: string,
  params: unknown,
  now: Date,
): Promise<Record<string, unknown>> {
  const args = parseToolArguments(params);

  if (name === 'search_vault_items') {
    if (!hasScope(auth, 'mcp:read')) {
      return { error: { code: -32001, message: 'insufficient_scope: mcp:read is required.' } };
    }
    const domainHmac = args['domain_hmac'];
    if (typeof domainHmac !== 'string' || !DOMAIN_HMAC_PATTERN.test(domainHmac)) {
      return { error: { code: -32602, message: 'domain_hmac must be a 64-character lowercase hex HMAC-SHA256.' } };
    }
    const matches = await store.findVaultItemsByDomainHmac(auth.userId, domainHmac, MCP_SEARCH_LIMIT);
    await writeMcpAudit(store, auth, 'mcp_search', 'oauth_authorization', { matched_count: matches.length }, now);
    return {
      result: textResult(JSON.stringify({
        items: matches.map((item) => ({
          item_id: item.id,
          overview_ciphertext: item.overview_ciphertext,
          overview_nonce: item.overview_nonce,
        })),
      })),
    };
  }

  if (name === 'get_vault_item') {
    if (!hasScope(auth, 'mcp:read')) {
      return { error: { code: -32001, message: 'insufficient_scope: mcp:read is required.' } };
    }
    const itemId = args['item_id'];
    if (typeof itemId !== 'string' || !UUID_PATTERN.test(itemId)) {
      return { error: { code: -32602, message: 'item_id must be a UUID.' } };
    }
    return getVaultItem(store, auth, itemId, now);
  }

  if (name === 'create_vault_item') {
    if (!hasScope(auth, 'mcp:write')) {
      return { error: { code: -32001, message: 'insufficient_scope: mcp:write is required.' } };
    }
    if (!isPayload(args)) {
      return { error: { code: -32602, message: 'The vault item payload is invalid.' } };
    }
    const input: VaultItemInput = {
      id: args['id'] as string,
      version: 1,
      overview_ciphertext: args['overview_ciphertext'] as string,
      overview_nonce: args['overview_nonce'] as string,
      detail_ciphertext: args['detail_ciphertext'] as string,
      detail_nonce: args['detail_nonce'] as string,
      domain_hmac: args['domain_hmac'] as string | null,
    };
    // OAuth authorizations have no device; the item records a null device.
    const result = await store.createVaultItem(auth.userId, null, input);
    await writeMcpAudit(store, auth, 'mcp_create_item', 'vault_item', { item_id: input.id }, now);
    if (result.kind === 'deleted') {
      throw new ApiError(410, 'item_deleted', 'This item ID has already been deleted.');
    }
    if (result.kind === 'item_id_conflict') {
      throw new ApiError(409, 'item_id_conflict', 'This item ID is already in use.');
    }
    if (result.kind === 'payload_conflict') {
      throw new ApiError(409, 'item_payload_conflict', 'This item ID already exists with a different payload.');
    }
    return {
      result: textResult(JSON.stringify({
        item_id: result.item.id,
        version: result.item.version,
        updated_at: result.item.updated_at,
      })),
    };
  }

  return { error: { code: -32602, message: `Unknown tool: ${name}.` } };
}

/**
 * Handles one JSON-RPC 2.0 request. Returns null for notifications (no
 * response). Throws ApiError for the fail-closed confirmation case and for
 * the HTTP-status item errors (404 not found / 410 deleted / 409 conflict),
 * which the route renders as HTTP statuses per SD §5.3.
 */
export async function handleMcpRequest(
  store: McpStore,
  body: unknown,
  auth: McpAuth,
  now: () => Date = () => new Date(),
): Promise<Record<string, unknown> | null> {
  if (!isRecord(body)) {
    return jsonRpcError(null, -32600, 'The request must be a JSON-RPC 2.0 object.');
  }
  const id = body['id'] ?? null;
  const isNotification = body['id'] === undefined;
  const method = body['method'];
  if (body['jsonrpc'] !== '2.0' || typeof method !== 'string') {
    if (isNotification) return null;
    return jsonRpcError(id, -32600, 'The request must be a JSON-RPC 2.0 object with a method.');
  }
  if (typeof method !== 'string' || method.startsWith('notifications/')) {
    return null;
  }

  if (method === 'initialize') {
    const params = isRecord(body['params']) ? body['params'] : {};
    const requested = typeof params['protocolVersion'] === 'string' ? params['protocolVersion'] : '';
    const protocolVersion = (MCP_PROTOCOL_VERSIONS as readonly string[]).includes(requested)
      ? requested
      : '2025-03-26';
    return jsonRpcResult(id, {
      protocolVersion,
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: 'sealero', version: '1.0.0' },
    });
  }

  if (method === 'ping') {
    return jsonRpcResult(id, {});
  }

  if (method === 'tools/list') {
    return jsonRpcResult(id, { tools: MCP_TOOLS });
  }

  if (method === 'tools/call') {
    const params = isRecord(body['params']) ? body['params'] : null;
    const name = params !== null && typeof params['name'] === 'string' ? params['name'] : '';
    let outcome: { readonly result?: Record<string, unknown>; readonly error?: Record<string, unknown> };
    try {
      outcome = await callTool(store, auth, name, params, now());
    } catch (error) {
      if (error instanceof ApiError) throw error;
      if (error instanceof Error && error.message === 'invalid_params') {
        return jsonRpcError(id, -32602, 'The tools/call params are invalid.');
      }
      throw error;
    }
    if (outcome.error !== undefined) {
      return jsonRpcError(id, outcome.error['code'] as number, outcome.error['message'] as string,
        (outcome.error as JsonRecord)['data']);
    }
    return jsonRpcResult(id, outcome.result);
  }

  return jsonRpcError(id, -32601, `Method not found: ${method}.`);
}
