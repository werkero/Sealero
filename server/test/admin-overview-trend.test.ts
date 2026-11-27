import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createAuthenticatedApp } from '../auth/app.js';
import { issueAccessToken } from '../auth/jwt.js';
import type { JwtKeySet, PublicJwk } from '../auth/jwt.js';
import { hashLoginPassword } from '../auth/password.js';
import type { AuthNotification, UserRole } from '../auth/types.js';
import { SqlAuthStore } from '../db/auth-store.js';
import { LocalPGliteAuthDatabase } from '../db/local-pglite-auth.js';
import { loadConfig } from '../config.js';

vi.setConfig({ testTimeout: 30_000 });

const PASSWORD = 'admin-overview-trend-test-password';
const AUTH_CODE_SECRET = randomBytes(32).toString("hex");
const INITIAL_TIME = new Date('2026-11-23T00:00:00.000Z');
const ADMIN_ID = '00000000-0000-4000-8000-000000000101';
const USER_ID = '00000000-0000-4000-8000-000000000103';
const TARGET_ID = '00000000-0000-4000-8000-000000000105';
const ADMIN_DEVICE_ID = '00000000-0000-4000-8000-000000000201';
const USER_DEVICE_ID = '00000000-0000-4000-8000-000000000203';
const TARGET_DEVICE_ID = '00000000-0000-4000-8000-000000000205';
const LOGIN_LOG_ID_1 = '00000000-0000-4000-8000-000000000301';
const LOGIN_LOG_ID_2 = '00000000-0000-4000-8000-000000000302';
const LOGIN_LOG_ID_3 = '00000000-0000-4000-8000-000000000303';
const LOGIN_LOG_ID_4 = '00000000-0000-4000-8000-000000000304';
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
  kid: 'admin-overview-trend-test-key',
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
  const time = new Date(INITIAL_TIME);
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
  createdAt = INITIAL_TIME,
): Promise<void> {
  await harness.database.query(
    `INSERT INTO users (id, email, login_password_hash, created_at, email_verified_at, disabled_at)
     VALUES ($1, $2, $3, $4, $5, NULL)`,
    [id, email, harness.passwordHash, createdAt, createdAt],
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
): Promise<void> {
  await harness.database.query(
    `INSERT INTO devices (id, user_id, device_name, device_type, created_at)
     VALUES ($1, $2, $3, 'app', $4)`,
    [id, userId, name, INITIAL_TIME],
  );
}

async function seedLogin(
  harness: Harness,
  id: string,
  userId: string,
  deviceId: string,
  result: 'success' | 'failed',
  createdAt: Date,
): Promise<void> {
  await harness.database.query(
    `INSERT INTO login_logs (id, user_id, device_id, device_name, ip_address, user_agent, result, created_at)
     VALUES ($1, $2, $3, 'test device', '192.0.2.4', 'test-agent', $4, $5)`,
    [id, userId, deviceId, result, createdAt],
  );
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

interface TrendDay {
  date: string;
  new_users: number;
  active_users: number;
}

async function seedTrendData(harness: Harness): Promise<void> {
  await seedUser(harness, ADMIN_ID, 'admin@example.test', ['admin']);
  await seedUser(harness, USER_ID, 'alice@example.test', ['user']);
  await seedUser(harness, TARGET_ID, 'target@example.test', ['user'], new Date('2026-11-22T23:00:00.000Z'));
  await seedDevice(harness, ADMIN_DEVICE_ID, ADMIN_ID, 'admin device');
  await seedDevice(harness, USER_DEVICE_ID, USER_ID, 'alice device');
  await seedDevice(harness, TARGET_DEVICE_ID, TARGET_ID, 'target device');
  await seedLogin(harness, LOGIN_LOG_ID_1, USER_ID, USER_DEVICE_ID, 'success', new Date('2026-11-21T10:00:00.000Z'));
  await seedLogin(harness, LOGIN_LOG_ID_2, TARGET_ID, TARGET_DEVICE_ID, 'success', new Date('2026-11-22T23:30:00.000Z'));
  await seedLogin(harness, LOGIN_LOG_ID_3, USER_ID, USER_DEVICE_ID, 'success', new Date(INITIAL_TIME.getTime() + 5_000));
  await seedLogin(harness, LOGIN_LOG_ID_4, USER_ID, USER_DEVICE_ID, 'failed', new Date(INITIAL_TIME.getTime() + 6_000));
}

describe('admin overview trend API', () => {
  it('returns daily new/active users for the requested UTC days, filling empty days with zero', async () => {
    const harness = await createHarness();
    await seedTrendData(harness);

    const response = await get(harness, '/v1/admin/overview/trend?days=7');
    expect(response.status).toBe(200);
    const body = await response.json() as { days: TrendDay[] };
    expect(body.days).toEqual([
      { date: '2026-11-17', new_users: 0, active_users: 0 },
      { date: '2026-11-18', new_users: 0, active_users: 0 },
      { date: '2026-11-19', new_users: 0, active_users: 0 },
      { date: '2026-11-20', new_users: 0, active_users: 0 },
      { date: '2026-11-21', new_users: 0, active_users: 1 },
      { date: '2026-11-22', new_users: 1, active_users: 1 },
      { date: '2026-11-23', new_users: 2, active_users: 1 },
    ]);
  });

  it('defaults to 14 days ending today', async () => {
    const harness = await createHarness();
    await seedTrendData(harness);

    const response = await get(harness, '/v1/admin/overview/trend');
    expect(response.status).toBe(200);
    const body = await response.json() as { days: TrendDay[] };
    expect(body.days).toHaveLength(14);
    expect(body.days[0]!.date).toBe('2026-11-10');
    expect(body.days[13]!.date).toBe('2026-11-23');
    expect(body.days[13]).toEqual({ date: '2026-11-23', new_users: 2, active_users: 1 });
  });

  it('rejects an out-of-range or non-integer days parameter with 400 invalid_request', async () => {
    const harness = await createHarness();
    await seedTrendData(harness);

    for (const query of ['days=6', 'days=31', 'days=abc', 'days=1.5']) {
      const response = await get(harness, `/v1/admin/overview/trend?${query}`);
      expect(response.status).toBe(400);
      expect(((await response.json()) as { code: string }).code).toBe('invalid_request');
    }
  });

  it('requires an administrator', async () => {
    const harness = await createHarness();
    await seedTrendData(harness);

    const missingToken = await get(harness, '/v1/admin/overview/trend', null);
    expect(missingToken.status).toBe(401);
    const nonAdmin = await get(harness, '/v1/admin/overview/trend', harness.token(USER_ID, USER_DEVICE_ID));
    expect(nonAdmin.status).toBe(403);
    expect(((await nonAdmin.json()) as { code: string }).code).toBe('admin_required');
  });
});
