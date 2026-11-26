import { Hono } from 'hono';
import { afterEach, describe, expect, it } from 'vitest';
import { createApp } from '../app.js';
import { loadConfig } from '../config.js';
import { SqlAuthStore } from '../db/auth-store.js';
import { LocalPGliteAuthDatabase } from '../db/local-pglite-auth.js';
import { createMaintenanceRoutes } from '../routes/maintenance.js';

const NOW = new Date('2026-11-26T12:00:00.000Z');
const SECRET = 'test-cleanup-secret';
const USER_ID = '00000000-0000-4000-8000-000000000101';

const openDatabases: LocalPGliteAuthDatabase[] = [];

afterEach(async () => {
  await Promise.all(openDatabases.splice(0).map((database) => database.close()));
});

async function createHarness(cleanupSecret: string | undefined) {
  const database = await LocalPGliteAuthDatabase.create();
  openDatabases.push(database);
  const store = new SqlAuthStore(database);
  const routes = new Hono();
  routes.route('/admin/maintenance', createMaintenanceRoutes({
    store,
    database,
    cleanupSecret,
    now: () => new Date(NOW),
  }));
  // createApp supplies the shared ApiError -> status error mapping.
  const app = createApp(loadConfig({}), { log: () => undefined }, routes);
  await database.query(
    `INSERT INTO users (id, email, login_password_hash, created_at, email_verified_at)
     VALUES ($1, 'owner@example.com', 'hash', $2, $2)`,
    [USER_ID, NOW],
  );
  return { database, store, app };
}

async function seedVaultItem(
  database: LocalPGliteAuthDatabase,
  id: string,
  deletedAt: Date | null,
): Promise<void> {
  await database.query(
    `INSERT INTO vault_items
       (id, user_id, overview_ciphertext, overview_nonce, detail_ciphertext, detail_nonce,
        domain_hmac, version, updated_at, deleted_at, device_id, deleted_by_device_id)
     VALUES ($1, $2, 'ov', 'ov-n', 'de', 'de-n', 'hmac', 1, $3, $4, NULL, 'device-1')`,
    [id, USER_ID, NOW, deletedAt],
  );
}

async function seedOAuthCode(
  database: LocalPGliteAuthDatabase,
  id: string,
  expiresAt: Date,
  consumedAt: Date | null,
): Promise<void> {
  await database.query(
    `INSERT INTO oauth_auth_codes
       (id, user_id, client_id, redirect_uri, scopes, code_hash, code_challenge,
        code_challenge_method, expires_at, consumed_at, created_at)
     VALUES ($1, $2, 'client-1', 'https://app.example.com/callback', 'vault',
             $3, 'challenge', 'S256', $4, $5, $6)`,
    [id, USER_ID, `hash-${id}`, expiresAt, consumedAt, NOW],
  );
}

describe('maintenance cleanup', () => {
  it('rejects a wrong or missing bearer secret', async () => {
    const { app } = await createHarness(SECRET);
    const wrong = await app.request('/v1/admin/maintenance/cleanup', {
      headers: { authorization: 'Bearer wrong-secret' },
    });
    expect(wrong.status).toBe(401);
    const missing = await app.request('/v1/admin/maintenance/cleanup');
    expect(missing.status).toBe(401);
  });

  it('fails closed when no cleanup secret is configured', async () => {
    const { app } = await createHarness(undefined);
    const response = await app.request('/v1/admin/maintenance/cleanup', {
      headers: { authorization: 'Bearer anything' },
    });
    expect(response.status).toBe(503);
  });

  it('cleans old tombstones and expired OAuth codes, and records the run', async () => {
    const { database, store, app } = await createHarness(SECRET);
    const oldItem = '00000000-0000-4000-8000-000000000201';
    const recentItem = '00000000-0000-4000-8000-000000000202';
    await seedVaultItem(database, oldItem, new Date('2026-10-17T12:00:00.000Z'));
    await seedVaultItem(database, recentItem, new Date('2026-11-16T12:00:00.000Z'));
    await seedOAuthCode(database, '00000000-0000-4000-8000-000000000301',
      new Date('2026-11-26T11:00:00.000Z'), null);
    await seedOAuthCode(database, '00000000-0000-4000-8000-000000000302',
      new Date('2026-11-25T11:10:00.000Z'), new Date('2026-11-25T11:00:00.000Z'));
    await seedOAuthCode(database, '00000000-0000-4000-8000-000000000303',
      new Date('2026-11-26T11:10:00.000Z'), new Date('2026-11-26T11:00:00.000Z'));
    await seedOAuthCode(database, '00000000-0000-4000-8000-000000000304',
      new Date('2026-11-26T12:10:00.000Z'), null);

    const response = await app.request('/v1/admin/maintenance/cleanup', {
      headers: { authorization: `Bearer ${SECRET}` },
    });
    expect(response.status).toBe(200);
    const body = await response.json() as Record<string, unknown>;
    expect(body).toEqual({
      cleaned_tombstones: 1,
      deleted_oauth_codes: 2,
      cleaned_at: '2026-11-26T12:00:00.000Z',
    });

    const items = await database.query<{ id: string; overview_ciphertext: string | null; updated_at: string | null }>(
      'SELECT id, overview_ciphertext, updated_at FROM vault_items ORDER BY id',
    );
    expect(items.rows).toEqual([
      { id: oldItem, overview_ciphertext: null, updated_at: null },
      { id: recentItem, overview_ciphertext: 'ov', updated_at: expect.any(Date) },
    ]);
    const codes = await database.query<{ id: string }>(
      'SELECT id FROM oauth_auth_codes ORDER BY id',
    );
    expect(codes.rows.map((row) => row.id)).toEqual([
      '00000000-0000-4000-8000-000000000303',
      '00000000-0000-4000-8000-000000000304',
    ]);

    const overview = await store.getAdminOverview(new Date(NOW));
    expect(overview.tombstone_cleanup).toEqual({
      last_cleanup_at: '2026-11-26T12:00:00.000Z',
      last_cleanup_status: 'success',
    });
  });

  it('accepts POST for manual runs', async () => {
    const { app } = await createHarness(SECRET);
    const response = await app.request('/v1/admin/maintenance/cleanup', {
      method: 'POST',
      headers: { authorization: `Bearer ${SECRET}` },
    });
    expect(response.status).toBe(200);
    const body = await response.json() as Record<string, unknown>;
    expect(body).toEqual({
      cleaned_tombstones: 0,
      deleted_oauth_codes: 0,
      cleaned_at: '2026-11-26T12:00:00.000Z',
    });
  });
});
