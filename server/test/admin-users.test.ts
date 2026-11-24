import { generateKeyPairSync } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';

// PGlite harness creation takes 3-9s on the 1.5-CPU sandbox; the 5s default flakes.
vi.setConfig({ testTimeout: 30_000 });
import { createAuthenticatedApp } from '../auth/app.js';
import { issueAccessToken } from '../auth/jwt.js';
import type { JwtKeySet, PublicJwk } from '../auth/jwt.js';
import { hashLoginPassword } from '../auth/password.js';
import type { AuthNotification, UserRole } from '../auth/types.js';
import { SqlAuthStore } from '../db/auth-store.js';
import { LocalPGliteAuthDatabase } from '../db/local-pglite-auth.js';
import { loadConfig } from '../config.js';

const PASSWORD = 'admin-owner-login-password';
const AUTH_CODE_SECRET = 'admin-users-test-hmac-secret-with-at-least-32-bytes';
const INITIAL_TIME = new Date('2026-11-23T00:00:00.000Z');
const ADMIN_ID = '00000000-0000-4000-8000-000000000101';
const SUPER_ADMIN_ID = '00000000-0000-4000-8000-000000000102';
const USER_ID = '00000000-0000-4000-8000-000000000103';
const DISABLED_USER_ID = '00000000-0000-4000-8000-000000000104';
const TARGET_ID = '00000000-0000-4000-8000-000000000105';
const ADMIN_DEVICE_ID = '00000000-0000-4000-8000-000000000201';
const SUPER_DEVICE_ID = '00000000-0000-4000-8000-000000000202';
const USER_DEVICE_ID = '00000000-0000-4000-8000-000000000203';
const DISABLED_DEVICE_ID = '00000000-0000-4000-8000-000000000204';
const TARGET_DEVICE_ID = '00000000-0000-4000-8000-000000000205';
const LOGIN_LOG_ID_1 = '00000000-0000-4000-8000-000000000301';
const LOGIN_LOG_ID_2 = '00000000-0000-4000-8000-000000000302';
const REFRESH_TOKEN_ID = '00000000-0000-4000-8000-000000000401';
const VAULT_ITEM_ID = '00000000-0000-4000-8000-000000000501';
const OAUTH_ACTIVE_ID = '00000000-0000-4000-8000-000000000601';
const OAUTH_ACTIVE_ID_2 = '00000000-0000-4000-8000-000000000602';
const OAUTH_REVOKED_ID = '00000000-0000-4000-8000-000000000603';
const OAUTH_FOREIGN_ID = '00000000-0000-4000-8000-000000000604';
const TARGET_DEVICE_ID_2 = '00000000-0000-4000-8000-000000000206';
const OAUTH_TARGET_ALL_ID = '00000000-0000-4000-8000-000000000605';
const OAUTH_TARGET_ALL_ID_2 = '00000000-0000-4000-8000-000000000606';
const OAUTH_FOREIGN_ALL_ID = '00000000-0000-4000-8000-000000000607';
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
  kid: 'admin-users-test-key',
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
  readonly passwordHash: string;
  setNow(value: Date): void;
  now(): Date;
  token(userId?: string, deviceId?: string): string;
}

const openDatabases: LocalPGliteAuthDatabase[] = [];

afterEach(async () => {
  await Promise.all(openDatabases.splice(0).map((database) => database.close()));
});

async function createHarness(): Promise<Harness> {
  const database = await LocalPGliteAuthDatabase.create();
  openDatabases.push(database);
  const passwordHash = await hashLoginPassword(PASSWORD);
  for (const role of ['admin', 'user', 'super_admin'] as const) {
    await database.query('INSERT INTO roles (name) VALUES ($1) ON CONFLICT (name) DO NOTHING', [role]);
  }
  let time = new Date(INITIAL_TIME);
  const notifications: AuthNotification = {
    async sendVerificationCode(): Promise<void> {},
    async sendPasswordResetCode(): Promise<void> {},
    async sendDeleteAccountCode(): Promise<void> {},
    async sendNewDeviceLogin(): Promise<void> {},
    async sendRefreshReuseAlert(): Promise<void> {},
  };
  const store = new SqlAuthStore(database);
  const app = createAuthenticatedApp(loadConfig({}), {
    store,
    jwtKeys,
    notifications,
    authCodeHmacSecret: AUTH_CODE_SECRET,
    serviceOptions: { now: () => new Date(time), delayLoginFailure: async () => undefined },
  }, silentLogger);
  return {
    database,
    app,
    passwordHash,
    setNow(value): void {
      time = new Date(value);
    },
    now(): Date {
      return new Date(time);
    },
    token(userId = ADMIN_ID, deviceId = ADMIN_DEVICE_ID): string {
      return issueAccessToken(jwtKeys, userId, deviceId, new Date(time));
    },
  };
}

async function seedUser(
  harness: Harness,
  id: string,
  email: string,
  roles: readonly UserRole[],
  options: { readonly createdAt?: Date; readonly verifiedAt?: Date | null; readonly disabledAt?: Date | null } = {},
): Promise<void> {
  await harness.database.query(
    `INSERT INTO users (id, email, login_password_hash, created_at, email_verified_at, disabled_at)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [id, email, harness.passwordHash, options.createdAt ?? INITIAL_TIME,
      options.verifiedAt === undefined ? INITIAL_TIME : options.verifiedAt,
      options.disabledAt === undefined ? null : options.disabledAt],
  );
  for (const role of roles) {
    const roleRow = await harness.database.query<{ id: string }>('SELECT id FROM roles WHERE name = $1', [role]);
    await harness.database.query(
      'INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)',
      [id, roleRow.rows[0]!.id],
    );
  }
}

async function seedDevice(
  harness: Harness,
  id: string,
  userId: string,
  name: string,
  createdAt = INITIAL_TIME,
): Promise<void> {
  await harness.database.query(
    `INSERT INTO devices (id, user_id, device_name, device_type, created_at)
     VALUES ($1, $2, $3, 'app', $4)`,
    [id, userId, name, createdAt],
  );
}

async function seedStandardUsers(harness: Harness): Promise<void> {
  await seedUser(harness, ADMIN_ID, 'admin@example.test', ['admin']);
  await seedUser(harness, SUPER_ADMIN_ID, 'root@example.test', ['super_admin']);
  await seedUser(harness, USER_ID, 'Alice+vault@example.test', ['user']);
  await seedUser(harness, DISABLED_USER_ID, 'disabled@example.test', ['user'], {
    createdAt: new Date(INITIAL_TIME.getTime() + 1_000),
    verifiedAt: null,
    disabledAt: new Date(INITIAL_TIME.getTime() + 2_000),
  });
  await seedUser(harness, TARGET_ID, 'target@example.test', ['user']);
  await seedDevice(harness, ADMIN_DEVICE_ID, ADMIN_ID, 'admin device');
  await seedDevice(harness, SUPER_DEVICE_ID, SUPER_ADMIN_ID, 'root device');
  await seedDevice(harness, USER_DEVICE_ID, USER_ID, 'alice device');
  await seedDevice(harness, DISABLED_DEVICE_ID, DISABLED_USER_ID, 'disabled device');
  await seedDevice(harness, TARGET_DEVICE_ID, TARGET_ID, 'target device');
}

async function get(
  harness: Harness,
  path: string,
  token: string | null = harness.token(),
): Promise<Response> {
  const headers = new Headers();
  if (token !== null) headers.set('authorization', `Bearer ${token}`);
  return harness.app.fetch(new Request(`https://api.sealero.test${path}`, { headers }));
}

async function post(
  harness: Harness,
  path: string,
  body?: unknown,
  token: string | null = harness.token(),
): Promise<Response> {
  const headers = new Headers();
  if (token !== null) headers.set('authorization', `Bearer ${token}`);
  if (body !== undefined) headers.set('content-type', 'application/json');
  return harness.app.fetch(new Request(`https://api.sealero.test${path}`, {
    method: 'POST',
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  }));
}

async function countRows(
  harness: Harness,
  table: 'users' | 'devices' | 'refresh_tokens' | 'vault_items' | 'auth_codes' | 'login_logs' | 'audit_logs',
): Promise<number> {
  const result = await harness.database.query<{ count: string }>(`SELECT COUNT(*)::text AS count FROM ${table}`);
  return Number(result.rows[0]?.count ?? '0');
}

async function seedSuccessfulLogin(
  harness: Harness,
  id: string,
  userId: string,
  deviceId: string,
  deviceName: string,
  createdAt: Date,
): Promise<void> {
  await harness.database.query(
    `INSERT INTO login_logs (id, user_id, device_id, device_name, ip_address, user_agent, result, created_at)
     VALUES ($1, $2, $3, $4, '192.0.2.4', 'test-agent', 'success', $5)`,
    [id, userId, deviceId, deviceName, createdAt],
  );
}

describe('admin user APIs', () => {
  it('requires an administrator and returns exact list metrics without vault ciphertext', async () => {
    const harness = await createHarness();
    await seedStandardUsers(harness);
    await seedSuccessfulLogin(harness, LOGIN_LOG_ID_1, USER_ID, USER_DEVICE_ID, 'alice device', new Date(INITIAL_TIME.getTime() + 5_000));
    await harness.database.query(
      `INSERT INTO vault_items (id, user_id, overview_ciphertext, overview_nonce, detail_ciphertext, detail_nonce,
                               domain_hmac, device_id)
       VALUES ($1, $2, 'é', 'n', 'xy', 'z', 'domain-hmac', $3)`,
      [VAULT_ITEM_ID, USER_ID, USER_DEVICE_ID],
    );
    await harness.database.query(
      `INSERT INTO vault_items (user_id, overview_ciphertext, overview_nonce, detail_ciphertext, detail_nonce,
                               domain_hmac, deleted_at, deleted_by_device_id, device_id)
       VALUES ($1, 'deleted-secret', 'deleted-nonce', 'deleted-detail', 'deleted-detail-nonce', 'deleted-hmac',
               $2, $3, $4)`,
      [USER_ID, INITIAL_TIME, USER_DEVICE_ID, USER_DEVICE_ID],
    );

    const missingToken = await get(harness, '/v1/admin/users', null);
    expect(missingToken.status).toBe(401);
    const nonAdmin = await get(harness, '/v1/admin/users', harness.token(USER_ID, USER_DEVICE_ID));
    expect(nonAdmin.status).toBe(403);

    const response = await get(harness, '/v1/admin/users');
    expect(response.status).toBe(200);
    const body = await response.json() as {
      users: Array<Record<string, unknown>>;
      total_count: number;
      has_more: boolean;
      next_cursor: string | null;
    };
    expect(body.total_count).toBe(5);
    expect(body.has_more).toBe(false);
    expect(body.next_cursor).toBeNull();
    const alice = body.users.find((user) => user['id'] === USER_ID);
    expect(alice).toEqual({
      id: USER_ID,
      email: 'Alice+vault@example.test',
      created_at: INITIAL_TIME.toISOString(),
      email_verified_at: INITIAL_TIME.toISOString(),
      disabled_at: null,
      is_admin: false,
      is_super_admin: false,
      device_count: 1,
      last_login_at: new Date(INITIAL_TIME.getTime() + 5_000).toISOString(),
      ciphertext_total_bytes: 6,
    });
    expect(JSON.stringify(body)).not.toContain('deleted-secret');
    expect(JSON.stringify(body)).not.toContain('domain-hmac');

    const filtered = await get(harness, '/v1/admin/users?search=ALICE%2BVAULT&verified=verified&role=user&status=active');
    expect(filtered.status).toBe(200);
    const filteredBody = await filtered.json() as { users: Array<{ id: string }>; total_count: number };
    expect(filteredBody.total_count).toBe(1);
    expect(filteredBody.users.map((user) => user.id)).toEqual([USER_ID]);
    const disabled = await get(harness, '/v1/admin/users?status=disabled&verified=unverified&role=user');
    const disabledBody = await disabled.json() as { users: Array<{ id: string }> };
    expect(disabledBody.users.map((user) => user.id)).toEqual([DISABLED_USER_ID]);
  });

  it('paginates users and login history by created_at/id with stable totals', async () => {
    const harness = await createHarness();
    await seedStandardUsers(harness);
    const first = await get(harness, '/v1/admin/users?search=example.test&limit=2');
    const firstBody = await first.json() as {
      users: Array<{ id: string }>;
      total_count: number;
      has_more: boolean;
      next_cursor: string | null;
    };
    expect(firstBody.total_count).toBe(5);
    expect(firstBody.users.map((user) => user.id)).toEqual([DISABLED_USER_ID, TARGET_ID]);
    expect(firstBody.has_more).toBe(true);
    expect(firstBody.next_cursor).toBe(TARGET_ID);
    const second = await get(harness, `/v1/admin/users?search=example.test&limit=2&cursor=${firstBody.next_cursor}`);
    const secondBody = await second.json() as typeof firstBody;
    expect(secondBody.total_count).toBe(5);
    expect(secondBody.users.map((user) => user.id)).toEqual([USER_ID, SUPER_ADMIN_ID]);
    expect(secondBody.has_more).toBe(true);
    expect(secondBody.next_cursor).toBe(SUPER_ADMIN_ID);
    const third = await get(harness, `/v1/admin/users?search=example.test&limit=2&cursor=${secondBody.next_cursor}`);
    const thirdBody = await third.json() as typeof firstBody;
    expect(thirdBody.users.map((user) => user.id)).toEqual([ADMIN_ID]);
    expect(thirdBody.has_more).toBe(false);
    expect(thirdBody.next_cursor).toBeNull();

    await seedSuccessfulLogin(harness, LOGIN_LOG_ID_1, USER_ID, USER_DEVICE_ID, 'older login', INITIAL_TIME);
    await seedSuccessfulLogin(harness, LOGIN_LOG_ID_2, USER_ID, USER_DEVICE_ID, 'newer login', new Date(INITIAL_TIME.getTime() + 1_000));
    const detailResponse = await get(harness, `/v1/admin/users/${USER_ID}?login_limit=1`);
    expect(detailResponse.status).toBe(200);
    const detail = await detailResponse.json() as {
      devices: Array<{ id: string; device_name: string }>;
      login_history: { items: Array<{ id: string; device_name: string }>; total_count: number; has_more: boolean; next_cursor: string | null };
    };
    expect(detail.devices.map((device) => device.id)).toEqual([USER_DEVICE_ID]);
    expect(detail.login_history.total_count).toBe(2);
    expect(detail.login_history.items.map((item) => item.id)).toEqual([LOGIN_LOG_ID_2]);
    expect(detail.login_history.next_cursor).toBe(LOGIN_LOG_ID_2);
    const next = await get(harness, `/v1/admin/users/${USER_ID}?login_limit=1&login_cursor=${LOGIN_LOG_ID_2}`);
    const nextBody = await next.json() as typeof detail;
    expect(nextBody.login_history.items.map((item) => item.id)).toEqual([LOGIN_LOG_ID_1]);
    expect(nextBody.login_history.has_more).toBe(false);

    const invalidCursor = await get(harness, `/v1/admin/users/${USER_ID}?login_cursor=00000000-0000-4000-8000-000000000999`);
    const invalidBody = await invalidCursor.json() as { code: string };
    expect(invalidBody.code).toBe('invalid_cursor');
  });

  it('rejects invalid filters, pagination, UUIDs and unknown cursors', async () => {
    const harness = await createHarness();
    await seedStandardUsers(harness);
    expect((await get(harness, '/v1/admin/users?role=super_admin')).status).toBe(400);
    expect((await get(harness, '/v1/admin/users?limit=0')).status).toBe(400);
    expect((await get(harness, '/v1/admin/users?limit=501')).status).toBe(400);
    expect((await get(harness, '/v1/admin/users?cursor=not-a-uuid')).status).toBe(400);
    const missing = await get(harness, '/v1/admin/users?cursor=00000000-0000-4000-8000-000000000999');
    expect((await missing.json() as { code: string }).code).toBe('invalid_cursor');
    const invalidId = await get(harness, '/v1/admin/users/not-a-uuid');
    expect(invalidId.status).toBe(400);
    const missingUser = await get(harness, '/v1/admin/users/00000000-0000-4000-8000-000000000999');
    expect((await missingUser.json() as { code: string }).code).toBe('user_not_found');
  });

  it('disables and enables users transactionally without reviving revoked devices or refresh tokens', async () => {
    const harness = await createHarness();
    await seedStandardUsers(harness);
    await harness.database.query(
      `INSERT INTO refresh_tokens (id, user_id, device_id, token_hash, expires_at, absolute_expires_at)
       VALUES ($1, $2, $3, 'disable-refresh-hash', $4, $5)`,
      [REFRESH_TOKEN_ID, DISABLED_USER_ID, DISABLED_DEVICE_ID,
        new Date(INITIAL_TIME.getTime() + 86_400_000), new Date(INITIAL_TIME.getTime() + 7 * 86_400_000)],
    );
    await harness.database.query(
      `INSERT INTO oauth_authorizations
         (user_id, client_id, redirect_uri, scopes, access_token_hash, refresh_token_hash, expires_at, refresh_expires_at)
       VALUES ($1, 'test-client', 'https://client.example/callback', 'mcp:read', 'disable-access-hash',
         'disable-oauth-refresh-hash', $2, $3)`,
      [DISABLED_USER_ID, new Date(INITIAL_TIME.getTime() + 900_000), new Date(INITIAL_TIME.getTime() + 86_400_000)],
    );
    const disabled = await post(harness, `/v1/admin/users/${DISABLED_USER_ID}/disable`);
    expect(disabled.status).toBe(204);
    const state = await harness.database.query<{
      disabled_at: Date | string | null;
      revoked_at: Date | string | null;
      revoked_reason: string | null;
      oauth_revoked_at: Date | string | null;
    }>(
      `SELECT u.disabled_at, d.revoked_at, r.revoked_reason, o.revoked_at AS oauth_revoked_at
       FROM users u JOIN devices d ON d.user_id = u.id
       JOIN refresh_tokens r ON r.user_id = u.id
       JOIN oauth_authorizations o ON o.user_id = u.id
       WHERE u.id = $1`,
      [DISABLED_USER_ID],
    );
    expect(state.rows[0]?.disabled_at).not.toBeNull();
    expect(state.rows[0]?.revoked_at).not.toBeNull();
    expect(state.rows[0]?.revoked_reason).toBe('account_disabled');
    expect(state.rows[0]?.oauth_revoked_at).not.toBeNull();
    expect((await get(harness, '/v1/admin/users', harness.token(DISABLED_USER_ID, DISABLED_DEVICE_ID))).status).toBe(401);

    harness.setNow(new Date(INITIAL_TIME.getTime() + 1_000));
    const enabled = await post(harness, `/v1/admin/users/${DISABLED_USER_ID}/enable`);
    expect(enabled.status).toBe(204);
    const afterEnable = await harness.database.query<{
      disabled_at: Date | string | null;
      revoked_at: Date | string | null;
      oauth_revoked_at: Date | string | null;
    }>(
      `SELECT u.disabled_at, d.revoked_at, o.revoked_at AS oauth_revoked_at
       FROM users u JOIN devices d ON d.user_id = u.id
       JOIN oauth_authorizations o ON o.user_id = u.id
       WHERE u.id = $1`,
      [DISABLED_USER_ID],
    );
    expect(afterEnable.rows[0]?.disabled_at).toBeNull();
    expect(afterEnable.rows[0]?.revoked_at).not.toBeNull();
    expect(afterEnable.rows[0]?.oauth_revoked_at).not.toBeNull();
    expect((await get(harness, '/v1/admin/users', harness.token(DISABLED_USER_ID, DISABLED_DEVICE_ID))).status).toBe(401);
    const audit = await harness.database.query<{ action: string; metadata: string }>(
      `SELECT action, metadata FROM audit_logs WHERE target_user_id = $1 ORDER BY created_at, id`,
      [DISABLED_USER_ID],
    );
    expect(audit.rows.map((row) => [row.action, row.metadata])).toEqual([
      ['user_disable', '{}'],
      ['user_enable', '{}'],
    ]);
  });

  it('applies administrator guards and records only allowlisted metadata for role changes', async () => {
    const harness = await createHarness();
    await seedStandardUsers(harness);
    const madeAdmin = await post(harness, `/v1/admin/users/${TARGET_ID}/make-admin`);
    expect(madeAdmin.status).toBe(204);
    const roles = await harness.database.query<{ name: string }>(
      `SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = $1 ORDER BY r.name`,
      [TARGET_ID],
    );
    expect(roles.rows.map((row) => row.name)).toEqual(['admin', 'user']);

    harness.setNow(new Date(INITIAL_TIME.getTime() + 1_000));
    const removedAdmin = await post(harness, `/v1/admin/users/${TARGET_ID}/remove-admin`);
    expect(removedAdmin.status).toBe(204);
    expect(await new SqlAuthStore(harness.database).hasAdminRole(TARGET_ID)).toBe(false);
    const selfDemotion = await post(harness, `/v1/admin/users/${ADMIN_ID}/remove-admin`);
    expect(selfDemotion.status).toBe(403);
    const superDemotion = await post(harness, `/v1/admin/users/${SUPER_ADMIN_ID}/remove-admin`);
    expect(superDemotion.status).toBe(403);

    const audits = await harness.database.query<{ action: string; metadata: string }>(
      `SELECT action, metadata FROM audit_logs WHERE target_user_id = $1 ORDER BY created_at, id`,
      [TARGET_ID],
    );
    expect(audits.rows.map((row) => [row.action, row.metadata])).toEqual([
      ['make_admin', '{}'],
      ['remove_admin', '{}'],
    ]);
  });

  it('requires the admin password, protects super-admin deletion, and cascades allowed deletion', async () => {
    const harness = await createHarness();
    await seedStandardUsers(harness);
    await seedSuccessfulLogin(harness, LOGIN_LOG_ID_1, TARGET_ID, TARGET_DEVICE_ID, 'target login', INITIAL_TIME);
    await harness.database.query(
      `INSERT INTO auth_codes (email, code_hash, purpose, expires_at)
       VALUES ('target@example.test', 'test-hash', 'reset', $1)`,
      [new Date(INITIAL_TIME.getTime() + 60_000)],
    );
    await harness.database.query(
      `INSERT INTO rate_limits (scope, key, count, window_start, expires_at)
       VALUES ('login_email', encode(digest('target@example.test', 'sha256'), 'hex'), 2, $1, $2)`,
      [INITIAL_TIME, new Date(INITIAL_TIME.getTime() + 60_000)],
    );

    const wrongPassword = await post(harness, `/v1/admin/users/${TARGET_ID}/delete`, { login_password: 'incorrect-password' });
    expect(wrongPassword.status).toBe(401);
    expect(await countRows(harness, 'users')).toBe(5);
    const selfDelete = await post(harness, `/v1/admin/users/${ADMIN_ID}/delete`, { login_password: PASSWORD });
    expect(selfDelete.status).toBe(403);
    await harness.database.query(
      `INSERT INTO user_roles (user_id, role_id)
       SELECT $1, id FROM roles WHERE name = 'admin' ON CONFLICT (user_id, role_id) DO NOTHING`,
      [TARGET_ID],
    );
    harness.setNow(new Date(INITIAL_TIME.getTime() + 1_000));
    const deniedSuperDelete = await post(harness, `/v1/admin/users/${SUPER_ADMIN_ID}/delete`, { login_password: PASSWORD });
    expect(deniedSuperDelete.status).toBe(403);
    expect(await countRows(harness, 'users')).toBe(5);

    harness.setNow(new Date(INITIAL_TIME.getTime() + 2_000));
    const deleted = await post(harness, `/v1/admin/users/${TARGET_ID}/delete`, { login_password: PASSWORD });
    expect(deleted.status).toBe(204);
    expect(await countRows(harness, 'users')).toBe(4);
    expect(await countRows(harness, 'devices')).toBe(4);
    const targetAuthCodes = await harness.database.query<{ count: string }>(
      "SELECT COUNT(*)::text AS count FROM auth_codes WHERE email = 'target@example.test'",
    );
    expect(Number(targetAuthCodes.rows[0]?.count ?? '0')).toBe(0);
    const targetLimits = await harness.database.query<{ count: string }>(
      "SELECT COUNT(*)::text AS count FROM rate_limits WHERE key = encode(digest('target@example.test', 'sha256'), 'hex')",
    );
    expect(Number(targetLimits.rows[0]?.count ?? '0')).toBe(0);
    const preservedLogin = await harness.database.query<{ user_id: string | null; device_id: string | null }>(
      'SELECT user_id, device_id FROM login_logs WHERE id = $1', [LOGIN_LOG_ID_1],
    );
    expect(preservedLogin.rows[0]).toEqual({ user_id: null, device_id: null });
    const audit = await harness.database.query<{ action: string; target_user_id: string | null; metadata: string }>(
      `SELECT action, target_user_id, metadata FROM audit_logs ORDER BY created_at, id`,
    );
    expect(audit.rows).toEqual([
      { action: 'user_delete', target_user_id: ADMIN_ID, metadata: '{}' },
      { action: 'user_delete', target_user_id: SUPER_ADMIN_ID, metadata: '{}' },
      { action: 'user_delete', target_user_id: null, metadata: '{}' },
    ]);
  });

  it('revokes a device, its refresh tokens, and owner OAuth grants with an exact audit metadata allowlist', async () => {
    const harness = await createHarness();
    await seedStandardUsers(harness);
    await harness.database.query(
      `INSERT INTO refresh_tokens (user_id, device_id, token_hash, expires_at, absolute_expires_at)
       VALUES ($1, $2, 'device-refresh-hash', $3, $4)`,
      [USER_ID, USER_DEVICE_ID, new Date(INITIAL_TIME.getTime() + 86_400_000), new Date(INITIAL_TIME.getTime() + 7 * 86_400_000)],
    );
    const oauthExpiresAt = new Date(INITIAL_TIME.getTime() + 86_400_000);
    const oauthRefreshExpiresAt = new Date(INITIAL_TIME.getTime() + 7 * 86_400_000);
    const previouslyRevokedAt = new Date(INITIAL_TIME.getTime() - 60_000);
    await harness.database.query(
      `INSERT INTO oauth_authorizations
         (id, user_id, client_id, redirect_uri, scopes, access_token_hash, refresh_token_hash,
          expires_at, refresh_expires_at, revoked_at)
       VALUES
         ($1, $2, 'client-a', 'https://client.example/a', 'mcp:read', 'access-a', 'refresh-a', $6, $7, NULL),
         ($3, $2, 'client-b', 'https://client.example/b', 'mcp:write', 'access-b', 'refresh-b', $6, $7, NULL),
         ($4, $2, 'client-old', 'https://client.example/old', 'mcp:read', 'access-old', 'refresh-old', $6, $7, $8),
         ($5, $9, 'foreign', 'https://other.example/callback', 'mcp:read', 'access-f', 'refresh-f', $6, $7, NULL)`,
      [OAUTH_ACTIVE_ID, USER_ID, OAUTH_ACTIVE_ID_2, OAUTH_REVOKED_ID, OAUTH_FOREIGN_ID,
        oauthExpiresAt, oauthRefreshExpiresAt, previouslyRevokedAt, TARGET_ID],
    );
    const revoked = await post(harness, `/v1/admin/devices/${USER_DEVICE_ID}/revoke`);
    expect(revoked.status).toBe(204);
    const row = await harness.database.query<{ revoked_at: Date | string | null; revoked_reason: string | null }>(
      `SELECT d.revoked_at, r.revoked_reason FROM devices d JOIN refresh_tokens r ON r.device_id = d.id WHERE d.id = $1`,
      [USER_DEVICE_ID],
    );
    expect(row.rows[0]?.revoked_at).not.toBeNull();
    expect(row.rows[0]?.revoked_reason).toBe('device_revoked');
    const oauth = await harness.database.query<{ id: string; revoked_at: Date | string | null }>(
      'SELECT id, revoked_at FROM oauth_authorizations WHERE id = ANY($1::uuid[])',
      [[OAUTH_ACTIVE_ID, OAUTH_ACTIVE_ID_2, OAUTH_REVOKED_ID, OAUTH_FOREIGN_ID]],
    );
    const oauthById = new Map(oauth.rows.map((grant) => [grant.id, grant.revoked_at]));
    expect(new Date(oauthById.get(OAUTH_ACTIVE_ID) as Date | string).toISOString()).toBe(INITIAL_TIME.toISOString());
    expect(new Date(oauthById.get(OAUTH_ACTIVE_ID_2) as Date | string).toISOString()).toBe(INITIAL_TIME.toISOString());
    expect(new Date(oauthById.get(OAUTH_REVOKED_ID) as Date | string).toISOString()).toBe(previouslyRevokedAt.toISOString());
    expect(oauthById.get(OAUTH_FOREIGN_ID)).toBeNull();
    const audit = await harness.database.query<{ action: string; target_type: string; metadata: string }>(
      "SELECT action, target_type, metadata FROM audit_logs WHERE action = 'device_revoke'",
    );
    expect(audit.rows).toEqual([{
      action: 'device_revoke',
      target_type: 'device',
      metadata: JSON.stringify({ device_id: USER_DEVICE_ID }),
    }]);
    const missing = await post(harness, '/v1/admin/devices/00000000-0000-4000-8000-000000000999/revoke');
    expect(missing.status).toBe(404);
  });

  it('revokes all of a user\'s devices, refresh tokens and OAuth grants while keeping the account enabled', async () => {
    const harness = await createHarness();
    await seedStandardUsers(harness);
    await seedDevice(harness, TARGET_DEVICE_ID_2, TARGET_ID, 'target device 2');
    const expiresAt = new Date(INITIAL_TIME.getTime() + 86_400_000);
    const absoluteExpiresAt = new Date(INITIAL_TIME.getTime() + 7 * 86_400_000);
    await harness.database.query(
      `INSERT INTO refresh_tokens (user_id, device_id, token_hash, expires_at, absolute_expires_at)
       VALUES
         ($1, $2, 'target-refresh-1', $4, $5),
         ($1, $3, 'target-refresh-2', $4, $5),
         ($6, $7, 'foreign-refresh', $4, $5)`,
      [TARGET_ID, TARGET_DEVICE_ID, TARGET_DEVICE_ID_2, expiresAt, absoluteExpiresAt, USER_ID, USER_DEVICE_ID],
    );
    await harness.database.query(
      `INSERT INTO oauth_authorizations
         (id, user_id, client_id, redirect_uri, scopes, access_token_hash, refresh_token_hash,
          expires_at, refresh_expires_at, revoked_at)
       VALUES
         ($1, $2, 'client-a', 'https://client.example/a', 'mcp:read', 'access-a', 'refresh-a', $4, $5, NULL),
         ($3, $2, 'client-b', 'https://client.example/b', 'mcp:write', 'access-b', 'refresh-b', $4, $5, NULL),
         ($6, $7, 'foreign', 'https://other.example/callback', 'mcp:read', 'access-f', 'refresh-f', $4, $5, NULL)`,
      [OAUTH_TARGET_ALL_ID, TARGET_ID, OAUTH_TARGET_ALL_ID_2, expiresAt, absoluteExpiresAt,
        OAUTH_FOREIGN_ALL_ID, USER_ID],
    );

    const revoked = await post(harness, `/v1/admin/users/${TARGET_ID}/revoke-all-devices`, { login_password: PASSWORD });
    expect(revoked.status).toBe(204);
    const devices = await harness.database.query<{ id: string; revoked_at: Date | string | null }>(
      'SELECT id, revoked_at FROM devices WHERE user_id = $1 ORDER BY id', [TARGET_ID],
    );
    expect(devices.rows).toHaveLength(2);
    for (const device of devices.rows) {
      expect(new Date(device.revoked_at as Date | string).toISOString()).toBe(INITIAL_TIME.toISOString());
    }
    const tokens = await harness.database.query<{ token_hash: string; revoked_at: Date | string | null; revoked_reason: string | null }>(
      'SELECT token_hash, revoked_at, revoked_reason FROM refresh_tokens ORDER BY token_hash',
    );
    expect(tokens.rows).toEqual([
      { token_hash: 'foreign-refresh', revoked_at: null, revoked_reason: null },
      { token_hash: 'target-refresh-1', revoked_at: INITIAL_TIME, revoked_reason: 'device_revoked' },
      { token_hash: 'target-refresh-2', revoked_at: INITIAL_TIME, revoked_reason: 'device_revoked' },
    ]);
    const oauth = await harness.database.query<{ id: string; revoked_at: Date | string | null }>(
      'SELECT id, revoked_at FROM oauth_authorizations WHERE id = ANY($1::uuid[])',
      [[OAUTH_TARGET_ALL_ID, OAUTH_TARGET_ALL_ID_2, OAUTH_FOREIGN_ALL_ID]],
    );
    const oauthById = new Map(oauth.rows.map((grant) => [grant.id, grant.revoked_at]));
    expect(new Date(oauthById.get(OAUTH_TARGET_ALL_ID) as Date | string).toISOString()).toBe(INITIAL_TIME.toISOString());
    expect(new Date(oauthById.get(OAUTH_TARGET_ALL_ID_2) as Date | string).toISOString()).toBe(INITIAL_TIME.toISOString());
    expect(oauthById.get(OAUTH_FOREIGN_ALL_ID)).toBeNull();
    const target = await harness.database.query<{ disabled_at: Date | string | null }>(
      'SELECT disabled_at FROM users WHERE id = $1', [TARGET_ID],
    );
    expect(target.rows[0]?.disabled_at).toBeNull();
    const audit = await harness.database.query<{ action: string; target_user_id: string | null; metadata: string }>(
      "SELECT action, target_user_id, metadata FROM audit_logs WHERE action = 'device_revoke_all'",
    );
    expect(audit.rows).toEqual([{
      action: 'device_revoke_all',
      target_user_id: TARGET_ID,
      metadata: JSON.stringify({ target_user_id: TARGET_ID, device_count: 2 }),
    }]);
  });

  it('requires the admin password and an existing target for revoke-all-devices', async () => {
    const harness = await createHarness();
    await seedStandardUsers(harness);

    const missingToken = await post(harness, `/v1/admin/users/${TARGET_ID}/revoke-all-devices`, { login_password: PASSWORD }, null);
    expect(missingToken.status).toBe(401);
    const nonAdmin = await post(harness, `/v1/admin/users/${TARGET_ID}/revoke-all-devices`, { login_password: PASSWORD },
      harness.token(USER_ID, USER_DEVICE_ID));
    expect(nonAdmin.status).toBe(403);
    const wrongPassword = await post(harness, `/v1/admin/users/${TARGET_ID}/revoke-all-devices`, { login_password: 'wrong-password' });
    expect(wrongPassword.status).toBe(401);
    const wrongBody = await wrongPassword.json() as { code: string };
    expect(wrongBody.code).toBe('invalid_credentials');
    const missingField = await post(harness, `/v1/admin/users/${TARGET_ID}/revoke-all-devices`, {});
    expect(missingField.status).toBe(400);
    const missingUser = await post(harness, '/v1/admin/users/00000000-0000-4000-8000-000000000999/revoke-all-devices', { login_password: PASSWORD });
    expect(missingUser.status).toBe(404);
    const devices = await harness.database.query<{ count: string }>(
      'SELECT COUNT(*)::text AS count FROM devices WHERE user_id = $1 AND revoked_at IS NOT NULL', [TARGET_ID],
    );
    expect(Number(devices.rows[0]?.count ?? '0')).toBe(0);
  });

  it('forbids revoke-all-devices for a super_admin target and for an admin revoking self', async () => {
    const harness = await createHarness();
    await seedStandardUsers(harness);

    const selfRevoke = await post(harness, `/v1/admin/users/${ADMIN_ID}/revoke-all-devices`, { login_password: PASSWORD });
    expect(selfRevoke.status).toBe(403);
    expect(await selfRevoke.json()).toMatchObject({ code: 'admin_action_forbidden' });

    const superRevoke = await post(harness, `/v1/admin/users/${SUPER_ADMIN_ID}/revoke-all-devices`, { login_password: PASSWORD });
    expect(superRevoke.status).toBe(403);
    expect(await superRevoke.json()).toMatchObject({ code: 'admin_action_forbidden' });

    const devices = await harness.database.query<{ count: string }>(
      'SELECT COUNT(*)::text AS count FROM devices WHERE user_id = ANY($1::uuid[]) AND revoked_at IS NOT NULL',
      [[ADMIN_ID, SUPER_ADMIN_ID]],
    );
    expect(Number(devices.rows[0]?.count ?? '0')).toBe(0);
    const audit = await harness.database.query<{ action: string; target_user_id: string | null; metadata: string }>(
      'SELECT action, target_user_id, metadata FROM audit_logs',
    );
    // Audit ids are random UUIDs and the clock is frozen, so row order is
    // nondeterministic; compare as a set. Blocked revoke-all audits carry
    // the SD §5.2 metadata (target_user_id, device_count: 0), not '{}'.
    expect(audit.rows).toHaveLength(2);
    expect(audit.rows).toEqual(expect.arrayContaining([
      { action: 'device_revoke_all', target_user_id: ADMIN_ID, metadata: JSON.stringify({ target_user_id: ADMIN_ID, device_count: 0 }) },
      { action: 'device_revoke_all', target_user_id: SUPER_ADMIN_ID, metadata: JSON.stringify({ target_user_id: SUPER_ADMIN_ID, device_count: 0 }) },
    ]));
  });
});
