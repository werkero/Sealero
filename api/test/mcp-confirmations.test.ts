import { afterEach, assert, describe, expect, it, vi } from 'vitest';

// PGlite harness creation takes 3-9s on the 1.5-CPU sandbox; the 5s default flakes.
vi.setConfig({ testTimeout: 30_000 });
import type { AuthTransaction } from '../auth/types.js';
import type { McpConfirmationRecord } from '../oauth/types.js';
import {
  decideMcpConfirmation,
  listMcpConfirmations,
} from '../services/mcp-confirmations.js';
import type { McpConfirmationServiceStore } from '../services/mcp-confirmations.js';
import {
  closeOAuthHarnesses,
  createOAuthHarness,
  fetchApp,
} from './support/oauth-harness.js';

const USER_ID = '00000000-0000-4000-8000-000000000401';
const OTHER_USER_ID = '00000000-0000-4000-8000-000000000402';
const AUTHORIZATION_ID = '00000000-0000-4000-8000-000000000403';
const ITEM_ID = '00000000-0000-4000-8000-000000000404';
const CONFIRMATION_ID = '00000000-0000-4000-8000-000000000405';
const NOW = new Date('2026-11-24T12:00:00.000Z');

function confirmationRecord(overrides: Partial<McpConfirmationRecord> = {}): McpConfirmationRecord {
  return {
    id: CONFIRMATION_ID,
    userId: USER_ID,
    authorizationId: AUTHORIZATION_ID,
    itemId: ITEM_ID,
    clientId: 'client-123',
    clientName: 'Test Connector',
    authorizationRevokedAt: null,
    expiresAt: new Date(NOW.getTime() + 5 * 60 * 1000),
    approvedAt: null,
    deniedAt: null,
    consumedAt: null,
    createdAt: NOW,
    ...overrides,
  };
}

function toDate(value: Date | string | null): Date | null {
  if (value === null) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

interface FakeAudit {
  readonly action: string;
  readonly metadata: string;
}

/**
 * In-memory stand-in for SqlAuthStore, implementing only the methods the
 * confirmation service uses, with the same row-level semantics as the SQL
 * (pending = all three decision timestamps null; decisions only succeed
 * while pending and unexpired). `items` maps item ids to their deleted
 * state (null entry = the item does not exist); items absent from the map
 * count as live (the real SQL would treat a missing item as stale and
 * hide it from the list).
 */
function createFakeStore(
  records: McpConfirmationRecord[],
  items: Readonly<Record<string, { readonly deletedAt: Date | null } | null>> = {},
): {
  store: McpConfirmationServiceStore;
  audits: FakeAudit[];
} {
  const audits: FakeAudit[] = [];
  const byId = new Map(records.map((record) => [record.id, { ...record }]));
  const isPending = (record: McpConfirmationRecord, at: Date): boolean => {
    const expiresAt = toDate(record.expiresAt);
    return record.approvedAt === null && record.deniedAt === null && record.consumedAt === null &&
      expiresAt !== null && expiresAt > at;
  };
  const isActionable = (record: McpConfirmationRecord): boolean => {
    if (record.authorizationRevokedAt !== null) return false;
    const item = items[record.itemId];
    return item === undefined || (item !== null && item.deletedAt === null);
  };
  const transaction = {
    async findMcpConfirmationForUpdate(id: string): Promise<McpConfirmationRecord | null> {
      const record = byId.get(id);
      return record === undefined ? null : { ...record };
    },
    async findVaultItemPayloadForUpdate(userId: string, itemId: string): Promise<{ deletedAt: Date | null } | null> {
      void userId;
      const item = items[itemId];
      if (item === undefined) return { deletedAt: null };
      if (item === null) return null;
      return { deletedAt: item.deletedAt };
    },
    async approveMcpConfirmation(id: string, at: Date): Promise<boolean> {
      const record = byId.get(id);
      if (record === undefined || !isPending(record, at)) return false;
      record.approvedAt = at;
      return true;
    },
    async denyMcpConfirmation(id: string, at: Date): Promise<boolean> {
      const record = byId.get(id);
      if (record === undefined || !isPending(record, at)) return false;
      record.deniedAt = at;
      return true;
    },
    async insertAuditLog(input: { action: string; metadata: string }): Promise<void> {
      audits.push({ action: input.action, metadata: input.metadata });
    },
  };
  const store = {
    async listMcpConfirmations(userId: string, now: Date, limit: number) {
      return [...byId.values()]
        .filter((record) => record.userId === userId && record.deniedAt === null &&
          record.consumedAt === null && (toDate(record.expiresAt) ?? new Date(0)) > now &&
          isActionable(record))
        .sort((a, b) => (toDate(b.createdAt)?.getTime() ?? 0) - (toDate(a.createdAt)?.getTime() ?? 0))
        .slice(0, limit);
    },
    async transaction<T>(callback: (tx: AuthTransaction) => Promise<T>): Promise<T> {
      return callback(transaction as unknown as AuthTransaction);
    },
  } as unknown as McpConfirmationServiceStore;
  return { store, audits };
}

describe('MCP trusted confirmations service (SD §5.3)', () => {
  it('lists pending and approved confirmations, newest first', async () => {
    const older = confirmationRecord({ id: '00000000-0000-4000-8000-000000000406', createdAt: new Date(NOW.getTime() - 1000) });
    const approved = confirmationRecord({
      id: '00000000-0000-4000-8000-000000000407',
      approvedAt: NOW,
      createdAt: new Date(NOW.getTime() + 1000),
    });
    const denied = confirmationRecord({ id: '00000000-0000-4000-8000-000000000408', deniedAt: NOW });
    const consumed = confirmationRecord({ id: '00000000-0000-4000-8000-000000000409', approvedAt: NOW, consumedAt: NOW });
    const expired = confirmationRecord({
      id: '00000000-0000-4000-8000-000000000410',
      expiresAt: new Date(NOW.getTime() - 1000),
    });
    const otherUser = confirmationRecord({ id: '00000000-0000-4000-8000-000000000411', userId: OTHER_USER_ID });
    const { store } = createFakeStore([older, approved, denied, consumed, expired, otherUser, confirmationRecord()]);
    const response = await listMcpConfirmations(store, USER_ID, NOW);
    expect(response.confirmations.map((item) => item.confirmation_id)).toEqual([
      approved.id,
      CONFIRMATION_ID,
      older.id,
    ]);
    const newest = response.confirmations[0];
    const middle = response.confirmations[1];
    assert.ok(newest !== undefined && middle !== undefined);
    expect(newest).toMatchObject({
      confirmation_id: approved.id,
      item_id: ITEM_ID,
      client_id: 'client-123',
      client_name: 'Test Connector',
      status: 'approved',
      expires_at: new Date(NOW.getTime() + 5 * 60 * 1000).toISOString(),
      created_at: new Date(NOW.getTime() + 1000).toISOString(),
    });
    expect(middle).toMatchObject({ status: 'pending' });
  });

  it('approves a pending confirmation and audits it', async () => {
    const { store, audits } = createFakeStore([confirmationRecord()]);
    const result = await decideMcpConfirmation(store, USER_ID, CONFIRMATION_ID, 'approve', NOW);
    expect(result).toEqual({ confirmation_id: CONFIRMATION_ID, status: 'approved' });
    expect(audits).toHaveLength(1);
    const firstAudit = audits[0];
    assert.ok(firstAudit !== undefined);
    expect(firstAudit.action).toBe('mcp_confirmation_approved');
    expect(JSON.parse(firstAudit.metadata)).toEqual({ confirmation_id: CONFIRMATION_ID, item_id: ITEM_ID });
  });

  it('denies a pending confirmation and audits it', async () => {
    const { store, audits } = createFakeStore([confirmationRecord()]);
    const result = await decideMcpConfirmation(store, USER_ID, CONFIRMATION_ID, 'deny', NOW);
    expect(result).toEqual({ confirmation_id: CONFIRMATION_ID, status: 'denied' });
    expect(audits).toHaveLength(1);
    const firstAudit = audits[0];
    assert.ok(firstAudit !== undefined);
    expect(firstAudit.action).toBe('mcp_confirmation_denied');
  });

  it('rejects unknown and other-user confirmations with 404', async () => {
    const { store } = createFakeStore([confirmationRecord()]);
    await expect(decideMcpConfirmation(store, USER_ID, '00000000-0000-4000-8000-000000000499', 'approve', NOW))
      .rejects.toMatchObject({ status: 404, code: 'not_found' });
    await expect(decideMcpConfirmation(store, OTHER_USER_ID, CONFIRMATION_ID, 'approve', NOW))
      .rejects.toMatchObject({ status: 404, code: 'not_found' });
  });

  it('rejects already-decided confirmations with 409', async () => {
    const { store } = createFakeStore([
      confirmationRecord({ approvedAt: NOW }),
      confirmationRecord({ id: '00000000-0000-4000-8000-000000000412', deniedAt: NOW }),
    ]);
    await expect(decideMcpConfirmation(store, USER_ID, CONFIRMATION_ID, 'deny', NOW))
      .rejects.toMatchObject({ status: 409, code: 'confirmation_already_decided' });
    await expect(decideMcpConfirmation(store, USER_ID, '00000000-0000-4000-8000-000000000412', 'approve', NOW))
      .rejects.toMatchObject({ status: 409, code: 'confirmation_already_decided' });
  });

  it('rejects expired confirmations with 409', async () => {
    const { store } = createFakeStore([
      confirmationRecord({ expiresAt: new Date(NOW.getTime() - 1000) }),
    ]);
    await expect(decideMcpConfirmation(store, USER_ID, CONFIRMATION_ID, 'approve', NOW))
      .rejects.toMatchObject({ status: 409, code: 'confirmation_expired' });
  });
});

describe('MCP trusted confirmation routes (SD §5.3)', () => {
  afterEach(async () => {
    await closeOAuthHarnesses();
  });

  it('rejects unauthenticated calls and blocks the list without consent', async () => {
    const harness = await createOAuthHarness();
    const noToken = await fetchApp(harness.app, 'GET', '/v1/mcp/confirmations');
    expect(noToken.status).toBe(401);
    expect(await noToken.json()).toMatchObject({ code: 'unauthorized' });

    const blocked = await fetchApp(harness.app, 'GET', '/v1/mcp/confirmations', undefined, {
      authorization: `Bearer ${harness.token}`,
    });
    expect(blocked.status).toBe(403);
    expect(await blocked.json()).toMatchObject({ code: 'consent_required' });
  });

  it('lists, approves and denies confirmations over HTTP', async () => {
    const harness = await createOAuthHarness();
    expect((await harness.consent()).status).toBe(200);
    const headers = { authorization: `Bearer ${harness.token}` };

    const empty = await fetchApp(harness.app, 'GET', '/v1/mcp/confirmations', undefined, headers);
    expect(empty.status).toBe(200);
    expect(await empty.json()).toEqual({ confirmations: [] });

    const badId = await fetchApp(harness.app, 'POST', '/v1/mcp/confirmations/not-a-uuid/approve', undefined, headers);
    expect(badId.status).toBe(400);
    expect(await badId.json()).toMatchObject({ code: 'invalid_request' });

    const unknown = await fetchApp(
      harness.app,
      'POST',
      '/v1/mcp/confirmations/00000000-0000-4000-8000-000000000499/approve',
      undefined,
      headers,
    );
    expect(unknown.status).toBe(404);
    expect(await unknown.json()).toMatchObject({ code: 'not_found' });
  });
});
