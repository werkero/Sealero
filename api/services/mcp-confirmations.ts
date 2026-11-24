import { ApiError } from '../app.js';
import type { AuthStore } from '../auth/types.js';
import type {
  McpConfirmationRecord,
  McpConfirmationStatus,
  McpConfirmationStore,
} from '../oauth/types.js';

/**
 * Trusted-confirmation UI endpoints (SD §5.3). Only the user, in the
 * trusted web UI behind their login session and unlocked vault, can
 * approve or deny a confirmation; the AI that requested it cannot.
 */
export type McpConfirmationServiceStore = AuthStore & McpConfirmationStore;

/** List cap for the trusted-UI confirmation page (SD §5.3). */
export const MCP_CONFIRMATION_LIST_LIMIT = 100;

export interface McpConfirmationListItem {
  readonly confirmation_id: string;
  readonly item_id: string;
  readonly client_id: string;
  readonly client_name: string | null;
  readonly status: McpConfirmationStatus;
  readonly expires_at: string;
  readonly created_at: string;
}

export interface McpConfirmationListResponse {
  readonly confirmations: readonly McpConfirmationListItem[];
}

export interface McpConfirmationDecisionResult {
  readonly confirmation_id: string;
  readonly status: 'approved' | 'denied';
}

function toIso(value: Date | string | null): string | null {
  if (value === null) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error('The database returned an invalid confirmation timestamp.');
  return date.toISOString();
}

function confirmationStatus(record: McpConfirmationRecord): McpConfirmationStatus {
  return record.approvedAt !== null ? 'approved' : 'pending';
}

export async function listMcpConfirmations(
  store: McpConfirmationServiceStore,
  userId: string,
  now: Date,
): Promise<McpConfirmationListResponse> {
  const records = await store.listMcpConfirmations(userId, now, MCP_CONFIRMATION_LIST_LIMIT);
  return {
    confirmations: records.map((record) => {
      const expiresAt = toIso(record.expiresAt);
      const createdAt = toIso(record.createdAt);
      if (expiresAt === null || createdAt === null) {
        throw new Error('An MCP confirmation must have expires_at and created_at.');
      }
      return {
        confirmation_id: record.id,
        item_id: record.itemId,
        client_id: record.clientId,
        client_name: record.clientName,
        status: confirmationStatus(record),
        expires_at: expiresAt,
        created_at: createdAt,
      };
    }),
  };
}

type DecisionOutcome =
  | { kind: 'decided'; status: 'approved' | 'denied' }
  | { kind: 'not_found' }
  | { kind: 'expired' }
  | { kind: 'already_decided' }
  | { kind: 'invalid' };

export async function decideMcpConfirmation(
  store: McpConfirmationServiceStore,
  userId: string,
  confirmationId: string,
  decision: 'approve' | 'deny',
  now: Date,
): Promise<McpConfirmationDecisionResult> {
  const outcome = await store.transaction<DecisionOutcome>(async (transaction) => {
    const record = await transaction.findMcpConfirmationForUpdate(confirmationId);
    if (record === null || record.userId !== userId) return { kind: 'not_found' };
    if (record.approvedAt !== null || record.deniedAt !== null || record.consumedAt !== null) {
      return { kind: 'already_decided' };
    }
    const expiresAt = record.expiresAt === null
      ? null
      : record.expiresAt instanceof Date ? record.expiresAt : new Date(record.expiresAt);
    if (expiresAt === null || Number.isNaN(expiresAt.getTime()) || expiresAt <= now) {
      return { kind: 'expired' };
    }
    if (decision === 'approve') {
      // Approving a stale request must not succeed: the item may have been
      // deleted after the request, or the authorization revoked. Denying
      // needs no such check — refusing a stale request is always safe.
      const payload = await transaction.findVaultItemPayloadForUpdate(userId, record.itemId);
      if (payload === null || payload.deletedAt !== null) return { kind: 'invalid' };
      if (record.authorizationRevokedAt !== null) return { kind: 'invalid' };
    }
    const decided = decision === 'approve'
      ? await transaction.approveMcpConfirmation(confirmationId, now)
      : await transaction.denyMcpConfirmation(confirmationId, now);
    if (!decided) return { kind: 'already_decided' };
    await transaction.insertAuditLog({
      actorUserId: userId,
      targetUserId: userId,
      action: decision === 'approve' ? 'mcp_confirmation_approved' : 'mcp_confirmation_denied',
      targetType: 'oauth_authorization',
      metadata: JSON.stringify({ confirmation_id: confirmationId, item_id: record.itemId }),
      ipAddress: null,
      createdAt: now,
    });
    return { kind: 'decided', status: decision === 'approve' ? 'approved' : 'denied' };
  });
  if (outcome.kind === 'not_found') {
    throw new ApiError(404, 'not_found', 'The requested resource was not found.');
  }
  if (outcome.kind === 'expired') {
    throw new ApiError(
      409,
      'confirmation_expired',
      'This confirmation has expired. Ask the connector to request access again.',
    );
  }
  if (outcome.kind === 'already_decided') {
    throw new ApiError(409, 'confirmation_already_decided', 'This confirmation has already been decided.');
  }
  if (outcome.kind === 'invalid') {
    throw new ApiError(
      409,
      'confirmation_invalid',
      'This confirmation is no longer valid: the item was deleted or the authorization was revoked.',
    );
  }
  return { confirmation_id: confirmationId, status: outcome.status };
}
