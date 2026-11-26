import { createHash, generateKeyPairSync } from 'node:crypto';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { Hono } from 'hono';
import { createAuthenticatedApp } from '../auth/app.js';
import { issueAccessToken } from '../auth/jwt.js';
import type { JwtKeySet, PublicJwk } from '../auth/jwt.js';
import { hashLoginPassword, verifyLoginPassword } from '../auth/password.js';
import type { AuthNotification } from '../auth/types.js';
import { SqlAuthStore } from '../db/auth-store.js';
import { LocalPGliteAuthDatabase } from '../db/local-pglite-auth.js';
import { loadConfig } from '../config.js';
import type { AuthenticatedEnvironment } from '../middleware/authentication.js';

const EMAIL = 'security-owner@example.test';
const OTHER_EMAIL = 'security-other@example.test';
const INITIAL_PASSWORD = 'old-login-password-123';
const NEW_PASSWORD = 'new-login-password-456';
const NOW = new Date('2026-11-22T20:00:00.000Z');
const USER_ID = '00000000-0000-4000-8000-000000000101';
const OTHER_USER_ID = '00000000-0000-4000-8000-000000000102';
const DEVICE_ID = '00000000-0000-4000-8000-000000000111';
const SECOND_DEVICE_ID = '00000000-0000-4000-8000-000000000112';
const OTHER_DEVICE_ID = '00000000-0000-4000-8000-000000000121';
const ACTIVE_TOKEN_ID = '00000000-0000-4000-8000-000000000201';
const PREVIOUSLY_REVOKED_TOKEN_ID = '00000000-0000-4000-8000-000000000202';
const SECOND_ACTIVE_TOKEN_ID = '00000000-0000-4000-8000-000000000203';
const OTHER_ACTIVE_TOKEN_ID = '00000000-0000-4000-8000-000000000204';
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
  kid: 'auth-security-test-key',
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
  readonly delays: number[];
  token(userId?: string, deviceId?: string): string;
}

let initialPasswordHash = '';
const openDatabases: LocalPGliteAuthDatabase[] = [];
const notifications: AuthNotification = {
  async sendVerificationCode(): Promise<void> {},
  async sendPasswordResetCode(): Promise<void> {},
  async sendDeleteAccountCode(): Promise<void> {},
  async sendNewDeviceLogin(): Promise<void> {},
  async sendRefreshReuseAlert(): Promise<void> {},
};

beforeAll(async () => {
  initialPasswordHash = await hashLoginPassword(INITIAL_PASSWORD);
});

afterEach(async () => {
  await Promise.all(openDatabases.splice(0).map((database) => database.close()));
});

async function createHarness(): Promise<Harness> {
  const database = await LocalPGliteAuthDatabase.create();
  openDatabases.push(database);
  await database.query(
    `INSERT INTO users (id, email, login_password_hash, email_verified_at) VALUES
       ($1, $3, $5, $7),
       ($2, $4, $6, $7)`,
    [USER_ID, OTHER_USER_ID, EMAIL, OTHER_EMAIL, initialPasswordHash, initialPasswordHash, NOW],
  );
  await database.query(
    `INSERT INTO devices (id, user_id, device_name, device_type) VALUES
       ($1, $4, 'desktop', 'app'),
       ($2, $4, 'phone', 'web'),
       ($3, $5, 'other-user-device', 'app')`,
    [DEVICE_ID, SECOND_DEVICE_ID, OTHER_DEVICE_ID, USER_ID, OTHER_USER_ID],
  );
  const expiresAt = new Date(NOW.getTime() + 60 * 24 * 60 * 60 * 1000);
  const absoluteExpiresAt = new Date(NOW.getTime() + 90 * 24 * 60 * 60 * 1000);
  const refreshTokens = [
    { id: ACTIVE_TOKEN_ID, userId: USER_ID, deviceId: DEVICE_ID, hash: 'active-refresh-hash', revokedAt: null, reason: null },
    { id: PREVIOUSLY_REVOKED_TOKEN_ID, userId: USER_ID, deviceId: DEVICE_ID, hash: 'rotated-refresh-hash', revokedAt: new Date(NOW.getTime() - 60_000), reason: 'rotated' },
    { id: SECOND_ACTIVE_TOKEN_ID, userId: USER_ID, deviceId: SECOND_DEVICE_ID, hash: 'second-active-refresh-hash', revokedAt: null, reason: null },
    { id: OTHER_ACTIVE_TOKEN_ID, userId: OTHER_USER_ID, deviceId: OTHER_DEVICE_ID, hash: 'other-active-refresh-hash', revokedAt: null, reason: null },
  ] as const;
  for (const token of refreshTokens) {
    await database.query(
      `INSERT INTO refresh_tokens
         (id, user_id, device_id, token_hash, expires_at, absolute_expires_at, revoked_at, revoked_reason)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [token.id, token.userId, token.deviceId, token.hash, expiresAt, absoluteExpiresAt, token.revokedAt, token.reason],
    );
  }
  await database.query(
    `INSERT INTO oauth_authorizations
       (user_id, client_id, redirect_uri, scopes, access_token_hash, refresh_token_hash, expires_at, refresh_expires_at)
     VALUES
       ($1, 'owner-client', 'https://client.example/callback', 'mcp:read', 'owner-access-hash', 'owner-refresh-hash', $3, $4),
       ($2, 'other-client', 'https://other.example/callback', 'mcp:read', 'other-access-hash', 'other-refresh-hash', $3, $4)`,
    [USER_ID, OTHER_USER_ID, expiresAt, absoluteExpiresAt],
  );

  const store = new SqlAuthStore(database);
  const protectedRoutes = new Hono<AuthenticatedEnvironment>();
  protectedRoutes.get('/__test/protected', (context) => context.json({ ok: true }));
  const delays: number[] = [];
  const app = createAuthenticatedApp(loadConfig({}), {
    store,
    jwtKeys,
    notifications,
    authCodeHmacSecret: 'auth-security-test-secret-long-enough-for-hmac',
    serviceOptions: {
      now: () => NOW,
      delayLoginFailure: async (milliseconds) => { delays.push(milliseconds); },
    },
    protectedRoutes,
  }, silentLogger);

  return {
    database,
    app,
    delays,
    token(userId = USER_ID, deviceId = DEVICE_ID): string {
      return issueAccessToken(jwtKeys, userId, deviceId, NOW);
    },
  };
}

async function postJson(
  harness: Harness,
  path: string,
  body: unknown,
  token: string | null = harness.token(),
  urlProtocol: 'https' | 'http' = 'https',
): Promise<Response> {
  const headers = new Headers({
    'content-type': 'application/json',
    'x-forwarded-for': '192.0.2.1',
  });
  if (token !== null) headers.set('authorization', `Bearer ${token}`);
  return harness.app.fetch(new Request(`${urlProtocol}://api.sealero.test${path}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  }));
}

async function getProtected(harness: Harness, token = harness.token()): Promise<Response> {
  return harness.app.fetch(new Request('https://api.sealero.test/v1/__test/protected', {
    headers: { authorization: `Bearer ${token}` },
  }));
}

async function revocationSnapshot(harness: Harness): Promise<{
  readonly revokedDevices: number;
  readonly activeRefreshTokens: number;
  readonly revokedOAuth: number;
}> {
  const devices = await harness.database.query<{ count: string }>(
    'SELECT COUNT(*)::text AS count FROM devices WHERE user_id = $1 AND revoked_at IS NOT NULL', [USER_ID],
  );
  const refresh = await harness.database.query<{ count: string }>(
    'SELECT COUNT(*)::text AS count FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL', [USER_ID],
  );
  const oauth = await harness.database.query<{ count: string }>(
    'SELECT COUNT(*)::text AS count FROM oauth_authorizations WHERE user_id = $1 AND revoked_at IS NOT NULL', [USER_ID],
  );
  return {
    revokedDevices: Number(devices.rows[0]?.count ?? '0'),
    activeRefreshTokens: Number(refresh.rows[0]?.count ?? '0'),
    revokedOAuth: Number(oauth.rows[0]?.count ?? '0'),
  };
}

describe('authenticated sensitive password operations', () => {
  it('requires an access JWT, HTTPS, and the exact v1.46 request fields', async () => {
    const harness = await createHarness();
    const unauthenticated = await postJson(
      harness,
      '/v1/auth/change-password',
      { old_login_password: INITIAL_PASSWORD, new_login_password: NEW_PASSWORD },
      null,
    );
    expect(unauthenticated.status).toBe(401);

    const insecure = await postJson(
      harness,
      '/v1/auth/change-password',
      { old_login_password: INITIAL_PASSWORD, new_login_password: NEW_PASSWORD },
      harness.token(),
      'http',
    );
    expect(insecure.status).toBe(400);
    expect(await insecure.json()).toMatchObject({ code: 'https_required' });

    const extraField = await postJson(harness, '/v1/auth/revoke-all-devices', {
      login_password: INITIAL_PASSWORD,
      unexpected: true,
    });
    expect(extraField.status).toBe(400);
    expect(await revocationSnapshot(harness)).toEqual({ revokedDevices: 0, activeRefreshTokens: 2, revokedOAuth: 0 });
  });

  it('does not revoke anything for a wrong old password or invalid new password', async () => {
    const harness = await createHarness();
    const wrongOldPassword = await postJson(harness, '/v1/auth/change-password', {
      old_login_password: 'incorrect-password',
      new_login_password: NEW_PASSWORD,
    });
    expect(wrongOldPassword.status).toBe(401);
    expect(await wrongOldPassword.json()).toMatchObject({ code: 'invalid_credentials' });
    expect(harness.delays).toEqual([]);
    expect(await revocationSnapshot(harness)).toEqual({ revokedDevices: 0, activeRefreshTokens: 2, revokedOAuth: 0 });

    const correctOldInvalidNew = await postJson(harness, '/v1/auth/change-password', {
      old_login_password: INITIAL_PASSWORD,
      new_login_password: 'x'.repeat(4097),
    });
    expect(correctOldInvalidNew.status).toBe(400);
    expect(await correctOldInvalidNew.json()).toMatchObject({ code: 'invalid_login_password' });
    expect(await revocationSnapshot(harness)).toEqual({ revokedDevices: 0, activeRefreshTokens: 2, revokedOAuth: 0 });
    const rateLimits = await harness.database.query<{ scope: string; count: number }>(
      "SELECT scope, count FROM rate_limits WHERE scope IN ('login_email', 'login_ip') ORDER BY scope",
    );
    expect(rateLimits.rows).toEqual([
      { scope: 'login_email', count: 1 },
      { scope: 'login_ip', count: 1 },
    ]);
    const user = await harness.database.query<{ login_password_hash: string }>(
      'SELECT login_password_hash FROM users WHERE id = $1', [USER_ID],
    );
    expect(user.rows[0]?.login_password_hash).toBe(initialPasswordHash);
  });

  it('changes the password and atomically revokes all device, refresh, and OAuth sessions', async () => {
    const harness = await createHarness();
    const response = await postJson(harness, '/v1/auth/change-password', {
      old_login_password: INITIAL_PASSWORD,
      new_login_password: NEW_PASSWORD,
    });
    expect(response.status).toBe(204);
    expect(await response.text()).toBe('');
    expect(response.body).toBeNull();

    const user = await harness.database.query<{ login_password_hash: string }>(
      'SELECT login_password_hash FROM users WHERE id = $1', [USER_ID],
    );
    expect(user.rows[0]?.login_password_hash).not.toBe(initialPasswordHash);
    expect(await verifyLoginPassword(user.rows[0]!.login_password_hash, NEW_PASSWORD)).toBe(true);
    expect(await verifyLoginPassword(user.rows[0]!.login_password_hash, INITIAL_PASSWORD)).toBe(false);
    expect(await revocationSnapshot(harness)).toEqual({ revokedDevices: 2, activeRefreshTokens: 0, revokedOAuth: 1 });

    const reasons = await harness.database.query<{ id: string; revoked_reason: string | null }>(
      'SELECT id, revoked_reason FROM refresh_tokens WHERE user_id = $1 ORDER BY id', [USER_ID],
    );
    const reasonById = new Map(reasons.rows.map((row) => [row.id, row.revoked_reason]));
    expect(reasonById.get(ACTIVE_TOKEN_ID)).toBe('password_changed');
    expect(reasonById.get(SECOND_ACTIVE_TOKEN_ID)).toBe('password_changed');
    expect(reasonById.get(PREVIOUSLY_REVOKED_TOKEN_ID)).toBe('rotated');

    const currentJwt = await getProtected(harness);
    expect(currentJwt.status).toBe(401);
    expect(await currentJwt.json()).toMatchObject({ code: 'device_revoked' });
    const otherUserJwt = await getProtected(harness, harness.token(OTHER_USER_ID, OTHER_DEVICE_ID));
    expect(otherUserJwt.status).toBe(200);
  });

  it('requires the old login password before revoking all devices and preserves other users’ sessions', async () => {
    const harness = await createHarness();
    const wrongPassword = await postJson(harness, '/v1/auth/revoke-all-devices', { login_password: 'wrong-password' });
    expect(wrongPassword.status).toBe(401);
    expect(await revocationSnapshot(harness)).toEqual({ revokedDevices: 0, activeRefreshTokens: 2, revokedOAuth: 0 });

    const response = await postJson(harness, '/v1/auth/revoke-all-devices', { login_password: INITIAL_PASSWORD });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ code: 'devices_revoked' });
    expect(await revocationSnapshot(harness)).toEqual({ revokedDevices: 2, activeRefreshTokens: 0, revokedOAuth: 1 });

    const reasons = await harness.database.query<{ id: string; revoked_reason: string | null }>(
      'SELECT id, revoked_reason FROM refresh_tokens WHERE id = ANY($1::uuid[])',
      [[ACTIVE_TOKEN_ID, SECOND_ACTIVE_TOKEN_ID, PREVIOUSLY_REVOKED_TOKEN_ID, OTHER_ACTIVE_TOKEN_ID]],
    );
    const reasonById = new Map(reasons.rows.map((row) => [row.id, row.revoked_reason]));
    expect(reasonById.get(ACTIVE_TOKEN_ID)).toBe('device_revoked');
    expect(reasonById.get(SECOND_ACTIVE_TOKEN_ID)).toBe('device_revoked');
    expect(reasonById.get(PREVIOUSLY_REVOKED_TOKEN_ID)).toBe('rotated');
    expect(reasonById.get(OTHER_ACTIVE_TOKEN_ID)).toBeNull();

    const currentJwt = await getProtected(harness);
    expect(currentJwt.status).toBe(401);
    expect(await currentJwt.json()).toMatchObject({ code: 'device_revoked' });
    const otherUserJwt = await getProtected(harness, harness.token(OTHER_USER_ID, OTHER_DEVICE_ID));
    expect(otherUserJwt.status).toBe(200);
  });

  it('applies login failure delay and rate-limit counters to wrong sensitive-operation passwords', async () => {
    const harness = await createHarness();
    const request = () => postJson(harness, '/v1/auth/revoke-all-devices', { login_password: 'wrong-password' });
    expect((await request()).status).toBe(401);
    expect((await request()).status).toBe(401);
    expect(harness.delays).toEqual([100]);

    const emailKey = createHash('sha256').update(EMAIL, 'utf8').digest('hex');
    const ipKey = createHash('sha256').update('192.0.2.1', 'utf8').digest('hex');
    const counters = await harness.database.query<{ scope: string; key: string; count: number }>(
      "SELECT scope, key, count FROM rate_limits WHERE scope IN ('login_email', 'login_ip') ORDER BY scope",
    );
    expect(counters.rows).toEqual([
      { scope: 'login_email', key: emailKey, count: 2 },
      { scope: 'login_ip', key: ipKey, count: 2 },
    ]);
  });

  it('returns 429 with Retry-After after 11 wrong sensitive-operation passwords', async () => {
    const harness = await createHarness();
    const wrongOldPassword = 'wrong-old-password';
    const newPassword = 'new-password-2';
    const request = () => postJson(harness, '/v1/auth/change-password', {
      old_login_password: wrongOldPassword,
      new_login_password: newPassword,
    });

    // The login email window allows 10 failures; the 11th is rate-limited.
    for (let attempt = 0; attempt < 10; attempt++) {
      expect((await request()).status).toBe(401);
    }
    const limited = await request();
    expect(limited.status).toBe(429);
    expect(await limited.json()).toMatchObject({ code: 'rate_limited' });
    const retryAfter = Number(limited.headers.get('retry-after'));
    expect(Number.isFinite(retryAfter)).toBe(true);
    expect(retryAfter).toBeGreaterThan(0);
  });
});

describe('GET /v1/auth/me', () => {
  async function getMe(harness: Harness, token: string | null): Promise<Response> {
    const headers = new Headers();
    if (token !== null) headers.set('authorization', `Bearer ${token}`);
    return harness.app.fetch(new Request('https://api.sealero.test/v1/auth/me', { headers }));
  }

  it('returns only {id, email} for the current JWT', async () => {
    const harness = await createHarness();
    const response = await getMe(harness, harness.token());
    expect(response.status).toBe(200);
    const body = await response.json() as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual(['email', 'id']);
    expect(body).toEqual({ id: USER_ID, email: EMAIL });
  });

  it('returns 401 without an access token', async () => {
    const harness = await createHarness();
    const response = await getMe(harness, null);
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ code: 'unauthorized' });
  });

  it('returns 401 when the token device is revoked', async () => {
    const harness = await createHarness();
    await harness.database.query(
      'UPDATE devices SET revoked_at = $2 WHERE id = $1',
      [DEVICE_ID, NOW],
    );
    const response = await getMe(harness, harness.token());
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ code: 'device_revoked' });
  });

  it('returns 403 when the account is disabled', async () => {
    const harness = await createHarness();
    await harness.database.query(
      'UPDATE users SET disabled_at = $2 WHERE id = $1',
      [USER_ID, NOW],
    );
    const response = await getMe(harness, harness.token());
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ code: 'account_disabled' });
  });
});
