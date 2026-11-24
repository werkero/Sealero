import { generateKeyPairSync } from 'node:crypto';
import { Hono } from 'hono';
import { afterEach, describe, expect, it } from 'vitest';
import { createAuthenticatedApp } from '../auth/app.js';
import { issueAccessToken } from '../auth/jwt.js';
import type { JwtKeySet, PublicJwk } from '../auth/jwt.js';
import type { AuthNotification } from '../auth/types.js';
import { SqlAuthStore } from '../db/auth-store.js';
import { LocalPGliteAuthDatabase } from '../db/local-pglite-auth.js';
import { loadConfig } from '../config.js';
import type { AuthenticatedEnvironment } from '../middleware/authentication.js';

const USER_ID = '00000000-0000-4000-8000-000000000101';
const OTHER_USER_ID = '00000000-0000-4000-8000-000000000102';
const DEVICE_ID = '00000000-0000-4000-8000-000000000111';
const SECOND_DEVICE_ID = '00000000-0000-4000-8000-000000000112';
const PRE_REVOKED_DEVICE_ID = '00000000-0000-4000-8000-000000000113';
const OTHER_DEVICE_ID = '00000000-0000-4000-8000-000000000121';
const TARGET_ACTIVE_TOKEN_ID = '00000000-0000-4000-8000-000000000201';
const TARGET_ROTATED_TOKEN_ID = '00000000-0000-4000-8000-000000000202';
const SECOND_ACTIVE_TOKEN_ID = '00000000-0000-4000-8000-000000000203';
const FOREIGN_ACTIVE_TOKEN_ID = '00000000-0000-4000-8000-000000000204';
const NOW = new Date('2026-11-22T20:00:00.000Z');
const PREVIOUSLY_REVOKED_AT = new Date('2026-11-21T20:00:00.000Z');
const silentLogger = { log: () => undefined };

const generatedKeys = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 0x10001 });
const exportedJwk = generatedKeys.publicKey.export({ format: 'jwk' });
if (typeof exportedJwk.n !== 'string' || typeof exportedJwk.e !== 'string') {
  throw new Error('Test key did not export RSA public parameters.');
}
const publicJwk: PublicJwk = {
  kty: 'RSA',
  use: 'sig',
  alg: 'RS256',
  kid: 'devices-test-key',
  n: exportedJwk.n,
  e: exportedJwk.e,
};
const jwtKeys: JwtKeySet = {
  activeKid: publicJwk.kid,
  issuer: 'https://api.sealero.test',
  privateKey: generatedKeys.privateKey,
  publicKeys: new Map([[publicJwk.kid, generatedKeys.publicKey]]),
  jwks: { keys: [publicJwk] },
};

interface Harness {
  readonly database: LocalPGliteAuthDatabase;
  readonly app: ReturnType<typeof createAuthenticatedApp>;
  token(userId?: string, deviceId?: string): string;
}

const openDatabases: LocalPGliteAuthDatabase[] = [];
const notifications: AuthNotification = {
  async sendVerificationCode(): Promise<void> {},
  async sendPasswordResetCode(): Promise<void> {},
  async sendDeleteAccountCode(): Promise<void> {},
  async sendNewDeviceLogin(): Promise<void> {},
  async sendRefreshReuseAlert(): Promise<void> {},
};

async function createHarness(): Promise<Harness> {
  const database = await LocalPGliteAuthDatabase.create();
  openDatabases.push(database);
  await database.query(
    `INSERT INTO users (id, email, login_password_hash, email_verified_at) VALUES
       ($1, 'owner@example.test', 'test-hash', $3),
       ($2, 'other@example.test', 'test-hash', $3)`,
    [USER_ID, OTHER_USER_ID, NOW],
  );
  await database.query(
    `INSERT INTO devices (id, user_id, device_name, device_type, revoked_at) VALUES
       ($1, $4, 'primary', 'app', NULL),
       ($2, $4, 'secondary', 'web', NULL),
       ($3, $4, 'previously revoked', 'app', $6),
       ($5, $7, 'other user device', 'app', NULL)`,
    [DEVICE_ID, SECOND_DEVICE_ID, PRE_REVOKED_DEVICE_ID, USER_ID, OTHER_DEVICE_ID, PREVIOUSLY_REVOKED_AT, OTHER_USER_ID],
  );

  const expiresAt = new Date(NOW.getTime() + 60 * 24 * 60 * 60 * 1000);
  const absoluteExpiresAt = new Date(NOW.getTime() + 90 * 24 * 60 * 60 * 1000);
  const refreshTokens = [
    { id: TARGET_ACTIVE_TOKEN_ID, userId: USER_ID, deviceId: DEVICE_ID, hash: 'target-active-hash', revokedAt: null, reason: null },
    { id: TARGET_ROTATED_TOKEN_ID, userId: USER_ID, deviceId: DEVICE_ID, hash: 'target-rotated-hash', revokedAt: PREVIOUSLY_REVOKED_AT, reason: 'rotated' },
    { id: SECOND_ACTIVE_TOKEN_ID, userId: USER_ID, deviceId: SECOND_DEVICE_ID, hash: 'second-active-hash', revokedAt: null, reason: null },
    { id: FOREIGN_ACTIVE_TOKEN_ID, userId: OTHER_USER_ID, deviceId: OTHER_DEVICE_ID, hash: 'foreign-active-hash', revokedAt: null, reason: null },
  ] as const;
  for (const token of refreshTokens) {
    await database.query(
      `INSERT INTO refresh_tokens
         (id, user_id, device_id, token_hash, expires_at, absolute_expires_at, revoked_at, revoked_reason)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [token.id, token.userId, token.deviceId, token.hash, expiresAt, absoluteExpiresAt, token.revokedAt, token.reason],
    );
  }

  const store = new SqlAuthStore(database);
  const protectedRoutes = new Hono<AuthenticatedEnvironment>();
  protectedRoutes.get('/__test/protected', (context) => context.json({ ok: true }));
  const app = createAuthenticatedApp(loadConfig({}), {
    store,
    jwtKeys,
    notifications,
    authCodeHmacSecret: 'devices-test-secret-long-enough-for-hmac-key',
    serviceOptions: { now: () => NOW },
    protectedRoutes,
  }, silentLogger);
  return {
    database,
    app,
    token(userId = USER_ID, deviceId = DEVICE_ID): string {
      return issueAccessToken(jwtKeys, userId, deviceId, NOW);
    },
  };
}

afterEach(async () => {
  await Promise.all(openDatabases.splice(0).map((database) => database.close()));
});

async function request(
  harness: Harness,
  path: string,
  token = harness.token(),
  method = 'GET',
): Promise<Response> {
  return harness.app.fetch(new Request(`https://api.sealero.test${path}`, {
    method,
    headers: { authorization: `Bearer ${token}` },
  }));
}

describe('authenticated device revocation API', () => {
  it('lists only the current user devices with stable cursor order and last successful activity', async () => {
    const harness = await createHarness();
    const primaryCreatedAt = '2026-11-20T00:00:00.123455Z';
    const secondaryCreatedAt = '2026-11-20T00:00:00.123456Z';
    const newestCreatedAt = '2026-11-21T00:00:00.654321Z';
    await harness.database.query(
      `UPDATE devices SET created_at = CASE id
         WHEN $1 THEN $3 WHEN $2 THEN $4 WHEN $5 THEN $6 ELSE created_at END
       WHERE id = ANY($7::uuid[])`,
      [DEVICE_ID, SECOND_DEVICE_ID, primaryCreatedAt, secondaryCreatedAt, PRE_REVOKED_DEVICE_ID, newestCreatedAt,
        [DEVICE_ID, SECOND_DEVICE_ID, PRE_REVOKED_DEVICE_ID]],
    );
    await harness.database.query(
      `INSERT INTO login_logs (user_id, device_id, device_name, result, created_at)
       VALUES ($1, $2, 'primary', 'success', $3),
              ($1, $2, 'primary', 'failed', $4)`,
      [USER_ID, DEVICE_ID, new Date('2026-11-22T10:00:00.000Z'), new Date('2026-11-22T23:00:00.000Z')],
    );
    await harness.database.query(
      `INSERT INTO vault_items
         (user_id, device_id, overview_ciphertext, overview_nonce, detail_ciphertext, detail_nonce, updated_at)
       VALUES ($1, $2, 'overview', 'overview-nonce', 'detail', 'detail-nonce', $3)`,
      [USER_ID, SECOND_DEVICE_ID, new Date('2026-11-22T12:00:00.000Z')],
    );
    await harness.database.query(
      `INSERT INTO vault_items
         (user_id, device_id, overview_ciphertext, overview_nonce, detail_ciphertext, detail_nonce,
          updated_at, deleted_at, deleted_by_device_id)
       VALUES ($1, $2, 'deleted-overview', 'deleted-overview-nonce', 'deleted-detail',
          'deleted-detail-nonce', $3, $4, $5)`,
      [USER_ID, DEVICE_ID, new Date('2026-11-22T11:00:00.000Z'), new Date('2026-11-22T14:00:00.000Z'), DEVICE_ID],
    );

    const first = await request(harness, '/v1/devices?limit=2');
    expect(first.status).toBe(200);
    const firstPage = await first.json() as {
      devices: Array<{ id: string; created_at: string; revoked_at: string | null; last_active_at: string | null }>;
      total_count: number;
      has_more: boolean;
      next_cursor: string | null;
    };
    expect(firstPage.total_count).toBe(3);
    expect(firstPage.has_more).toBe(true);
    expect(firstPage.devices.map((device) => device.id)).toEqual([PRE_REVOKED_DEVICE_ID, SECOND_DEVICE_ID]);
    expect(firstPage.devices[0]?.revoked_at).toBeTruthy();
    expect(firstPage.devices[0]?.last_active_at).toBeNull();
    expect(firstPage.devices[1]?.created_at).toBe(secondaryCreatedAt);
    expect(firstPage.devices[1]?.last_active_at).toBe('2026-11-22T12:00:00.000Z');
    expect(firstPage.next_cursor).toBeTruthy();
    expect(Buffer.from(firstPage.next_cursor ?? '', 'base64url').toString('utf8'))
      .toBe(`${secondaryCreatedAt}|${SECOND_DEVICE_ID}`);

    const second = await request(harness, `/v1/devices?cursor=${firstPage.next_cursor}&limit=2`);
    expect(second.status).toBe(200);
    const secondPage = await second.json() as {
      devices: Array<{ id: string; last_active_at: string | null }>;
      total_count: number;
      has_more: boolean;
      next_cursor: string | null;
    };
    expect(secondPage.total_count).toBe(3);
    expect(secondPage.devices).toEqual([{
      id: DEVICE_ID,
      device_name: 'primary',
      device_type: 'app',
      created_at: primaryCreatedAt,
      revoked_at: null,
      last_active_at: '2026-11-22T14:00:00.000Z',
    }]);
    expect(secondPage.has_more).toBe(false);
    expect(secondPage.next_cursor).toBeNull();

    const invalidCursor = await request(harness, '/v1/devices?cursor=not-a-cursor');
    expect(invalidCursor.status).toBe(400);
    expect(await invalidCursor.json()).toMatchObject({ code: 'invalid_cursor' });
    const impossibleDate = Buffer.from(`2026-02-30T00:00:00.000000Z|${DEVICE_ID}`, 'utf8').toString('base64url');
    const invalidDateCursor = await request(harness, `/v1/devices?cursor=${impossibleDate}`);
    expect(invalidDateCursor.status).toBe(400);
    expect(await invalidDateCursor.json()).toMatchObject({ code: 'invalid_cursor' });
    const invalidLimit = await request(harness, '/v1/devices?limit=501');
    expect(invalidLimit.status).toBe(400);
    expect(await invalidLimit.json()).toMatchObject({ code: 'invalid_pagination' });
  });

  it('atomically revokes the owned device and active refresh tokens, then rejects its existing Access JWT', async () => {
    const harness = await createHarness();
    const response = await request(harness, `/v1/devices/${DEVICE_ID}`, harness.token(), 'DELETE');
    expect(response.status).toBe(204);
    expect(await response.text()).toBe('');

    const device = await harness.database.query<{ revoked_at: Date | string | null }>(
      'SELECT revoked_at FROM devices WHERE id = $1', [DEVICE_ID],
    );
    expect(device.rows[0]?.revoked_at).not.toBeNull();

    const tokens = await harness.database.query<{
      id: string;
      revoked_at: Date | string | null;
      revoked_reason: string | null;
    }>(
      `SELECT id, revoked_at, revoked_reason FROM refresh_tokens WHERE id = ANY($1::uuid[])`,
      [[TARGET_ACTIVE_TOKEN_ID, TARGET_ROTATED_TOKEN_ID, SECOND_ACTIVE_TOKEN_ID, FOREIGN_ACTIVE_TOKEN_ID]],
    );
    const tokenById = new Map(tokens.rows.map((token) => [token.id, token]));
    expect(tokenById.get(TARGET_ACTIVE_TOKEN_ID)?.revoked_at).not.toBeNull();
    expect(tokenById.get(TARGET_ACTIVE_TOKEN_ID)?.revoked_reason).toBe('device_revoked');
    expect(tokenById.get(TARGET_ROTATED_TOKEN_ID)?.revoked_reason).toBe('rotated');
    expect(tokenById.get(SECOND_ACTIVE_TOKEN_ID)?.revoked_at).toBeNull();
    expect(tokenById.get(FOREIGN_ACTIVE_TOKEN_ID)?.revoked_at).toBeNull();

    const rejectedJwt = await request(harness, '/v1/__test/protected', harness.token());
    expect(rejectedJwt.status).toBe(401);
    expect(await rejectedJwt.json()).toMatchObject({ code: 'device_revoked' });

    const otherOwnDeviceStillWorks = await request(harness, '/v1/__test/protected', harness.token(USER_ID, SECOND_DEVICE_ID));
    expect(otherOwnDeviceStillWorks.status).toBe(200);
    const otherUserStillWorks = await request(harness, '/v1/__test/protected', harness.token(OTHER_USER_ID, OTHER_DEVICE_ID));
    expect(otherUserStillWorks.status).toBe(200);
  });

  it('revokes every owner OAuth authorization without changing prior revocations or another user', async () => {
    const harness = await createHarness();
    const expiresAt = new Date(NOW.getTime() + 15 * 60 * 1000);
    const refreshExpiresAt = new Date(NOW.getTime() + 30 * 24 * 60 * 60 * 1000);
    const grantIds = [
      '00000000-0000-4000-8000-000000000301',
      '00000000-0000-4000-8000-000000000302',
      '00000000-0000-4000-8000-000000000303',
      '00000000-0000-4000-8000-000000000304',
    ] as const;
    await harness.database.query(
      `INSERT INTO oauth_authorizations
         (id, user_id, client_id, redirect_uri, scopes, access_token_hash, refresh_token_hash,
          expires_at, refresh_expires_at, revoked_at)
       VALUES
         ($1, $2, 'owner-client-a', 'https://client.example/a', 'mcp:read', 'access-a', 'refresh-a', $5, $6, NULL),
         ($3, $2, 'owner-client-b', 'https://client.example/b', 'mcp:read mcp:write', 'access-b', 'refresh-b', $5, $6, NULL),
         ($4, $2, 'owner-client-old', 'https://client.example/old', 'mcp:read', 'access-old', 'refresh-old', $5, $6, $7),
         ($8, $9, 'foreign-client', 'https://other.example/callback', 'mcp:read', 'access-foreign', 'refresh-foreign', $5, $6, NULL)`,
      [
        grantIds[0], USER_ID, grantIds[1], grantIds[2], expiresAt, refreshExpiresAt,
        PREVIOUSLY_REVOKED_AT, grantIds[3], OTHER_USER_ID,
      ],
    );

    const response = await request(
      harness,
      `/v1/devices/${DEVICE_ID}`,
      harness.token(USER_ID, SECOND_DEVICE_ID),
      'DELETE',
    );
    expect(response.status).toBe(204);

    const result = await harness.database.query<{
      id: string;
      revoked_at: Date | string | null;
    }>(
      'SELECT id, revoked_at FROM oauth_authorizations WHERE id = ANY($1::uuid[])',
      [grantIds],
    );
    const byId = new Map(result.rows.map((row) => [row.id, row.revoked_at]));
    for (const ownerGrantId of grantIds.slice(0, 2)) {
      expect(new Date(byId.get(ownerGrantId) as Date | string).toISOString()).toBe(NOW.toISOString());
    }
    expect(new Date(byId.get(grantIds[2]) as Date | string).toISOString()).toBe(PREVIOUSLY_REVOKED_AT.toISOString());
    expect(byId.get(grantIds[3])).toBeNull();
  });

  it('does not reveal or revoke another user’s device, validates IDs, and treats repeated revocation as success', async () => {
    const harness = await createHarness();
    const foreign = await request(harness, `/v1/devices/${OTHER_DEVICE_ID}`, harness.token(USER_ID, SECOND_DEVICE_ID), 'DELETE');
    expect(foreign.status).toBe(404);
    expect(await foreign.json()).toMatchObject({ code: 'not_found' });

    const missing = await request(
      harness,
      '/v1/devices/00000000-0000-4000-8000-000000000199',
      harness.token(USER_ID, SECOND_DEVICE_ID),
      'DELETE',
    );
    expect(missing.status).toBe(404);

    const malformed = await request(harness, '/v1/devices/not-a-uuid', harness.token(USER_ID, SECOND_DEVICE_ID), 'DELETE');
    expect(malformed.status).toBe(400);
    expect(await malformed.json()).toMatchObject({ code: 'invalid_request' });

    const first = await request(
      harness,
      `/v1/devices/${PRE_REVOKED_DEVICE_ID}`,
      harness.token(USER_ID, SECOND_DEVICE_ID),
      'DELETE',
    );
    const repeated = await request(
      harness,
      `/v1/devices/${PRE_REVOKED_DEVICE_ID}`,
      harness.token(USER_ID, SECOND_DEVICE_ID),
      'DELETE',
    );
    expect(first.status).toBe(204);
    expect(repeated.status).toBe(204);

    const preserved = await harness.database.query<{ revoked_at: Date | string | null }>(
      'SELECT revoked_at FROM devices WHERE id = $1', [PRE_REVOKED_DEVICE_ID],
    );
    expect(new Date(preserved.rows[0]?.revoked_at as Date | string).toISOString()).toBe(PREVIOUSLY_REVOKED_AT.toISOString());
  });
});
