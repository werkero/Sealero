import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import argon2 from 'argon2';
import { Hono } from 'hono';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createAuthenticatedApp, createConfiguredAuthenticatedApp } from '../auth/app.js';
import { loadJwtKeySet } from '../auth/keyring.js';
import { verifyAccessToken } from '../auth/jwt.js';
import type { JwtKeySet, PublicJwk } from '../auth/jwt.js';
import { hashLoginPassword, loginPasswordNeedsRehash } from '../auth/password.js';
import { AuthService, AuthServiceError } from '../auth/auth-service.js';
import type { AuthNotification, TokenPair } from '../auth/types.js';
import { REFRESH_REUSE_WINDOW_MS } from '../auth/tokens.js';
import { SqlAuthStore } from '../db/auth-store.js';
import type { SqlConnection, TransactionalSqlDatabase } from '../db/auth-store.js';
import type { AuthenticatedEnvironment } from '../middleware/authentication.js';
import { loadConfig } from '../config.js';
import { PGliteAuthDatabase } from './support/pglite-auth.js';

const TEST_PASSWORD = 'correct-horse-battery-staple';
const TEST_AUTH_CODE_SECRET = 'local-test-auth-code-hmac-secret-with-at-least-32-bytes';
const INITIAL_TIME = new Date('2026-11-22T00:00:00.000Z');
const USER_ID = '00000000-0000-4000-8000-000000000001';
const OTHER_USER_ID = '00000000-0000-4000-8000-000000000002';
const ACTIVE_DEVICE_ID = '00000000-0000-4000-8000-000000000011';
const FOREIGN_DEVICE_ID = '00000000-0000-4000-8000-000000000012';
const REVOKED_DEVICE_ID = '00000000-0000-4000-8000-000000000013';
const silentLogger = { log: () => undefined };

const generatedKeys = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 0x10001 });
const exportedPublicJwk = generatedKeys.publicKey.export({ format: 'jwk' });
if (typeof exportedPublicJwk.n !== 'string' || typeof exportedPublicJwk.e !== 'string') {
  throw new Error('Test key did not export RSA public parameters.');
}
const publicJwk: PublicJwk = {
  kty: 'RSA',
  use: 'sig',
  alg: 'RS256',
  kid: 'test-kid-2026-11',
  n: exportedPublicJwk.n,
  e: exportedPublicJwk.e,
};
const jwtKeys: JwtKeySet = {
  activeKid: publicJwk.kid,
  issuer: 'https://api.sealero.test',
  privateKey: generatedKeys.privateKey,
  publicKeys: new Map([[publicJwk.kid, generatedKeys.publicKey]]),
  jwks: { keys: [publicJwk] },
};

let currentPasswordHash = '';
const openDatabases: PGliteAuthDatabase[] = [];

interface ReuseCommitSnapshot {
  readonly revokedDeviceCount: number;
  readonly activeRefreshTokenCount: number;
}

interface NewDeviceCommitSnapshot {
  readonly deviceCount: number;
  readonly activeRefreshTokenCount: number;
  readonly successfulLoginLogCount: number;
}

interface Harness {
  readonly database: PGliteAuthDatabase;
  readonly store: SqlAuthStore;
  readonly service: AuthService;
  readonly notifications: AuthNotification;
  readonly verificationEmails: Array<{ readonly email: string; readonly code: string; readonly expiresAt: Date }>;
  readonly passwordResetEmails: Array<{ readonly email: string; readonly code: string; readonly expiresAt: Date }>;
  readonly newDeviceEvents: string[];
  readonly newDeviceCommitSnapshots: NewDeviceCommitSnapshot[];
  readonly reuseEvents: string[];
  readonly reuseCommitSnapshots: ReuseCommitSnapshot[];
  setNow(value: Date): void;
  now(): Date;
}

beforeAll(async () => {
  currentPasswordHash = await hashLoginPassword(TEST_PASSWORD);
});

afterEach(async () => {
  await Promise.all(openDatabases.splice(0).map((database) => database.close()));
});

async function createHarness(): Promise<Harness> {
  const database = await PGliteAuthDatabase.create();
  openDatabases.push(database);
  const store = new SqlAuthStore(database);
  let time = new Date(INITIAL_TIME);
  const newDeviceEvents: string[] = [];
  const newDeviceCommitSnapshots: NewDeviceCommitSnapshot[] = [];
  const reuseEvents: string[] = [];
  const reuseCommitSnapshots: ReuseCommitSnapshot[] = [];
  const verificationEmails: Array<{ readonly email: string; readonly code: string; readonly expiresAt: Date }> = [];
  const passwordResetEmails: Array<{ readonly email: string; readonly code: string; readonly expiresAt: Date }> = [];
  const notifications: AuthNotification = {
    async sendVerificationCode(input): Promise<void> {
      verificationEmails.push(input);
    },
    async sendPasswordResetCode(input): Promise<void> {
      passwordResetEmails.push(input);
    },
    async sendDeleteAccountCode(): Promise<void> {},
    async sendNewDeviceLogin(input): Promise<void> {
      newDeviceEvents.push(input.deviceId);
      const device = await database.query<{ count: string }>(
        'SELECT COUNT(*)::text AS count FROM devices WHERE id = $1 AND user_id = $2',
        [input.deviceId, input.userId],
      );
      const refresh = await database.query<{ count: string }>(
        'SELECT COUNT(*)::text AS count FROM refresh_tokens WHERE user_id = $1 AND device_id = $2 AND revoked_at IS NULL',
        [input.userId, input.deviceId],
      );
      const log = await database.query<{ count: string }>(
        "SELECT COUNT(*)::text AS count FROM login_logs WHERE user_id = $1 AND device_id = $2 AND result = 'success'",
        [input.userId, input.deviceId],
      );
      newDeviceCommitSnapshots.push({
        deviceCount: Number(device.rows[0]?.count ?? '0'),
        activeRefreshTokenCount: Number(refresh.rows[0]?.count ?? '0'),
        successfulLoginLogCount: Number(log.rows[0]?.count ?? '0'),
      });
    },
    async sendRefreshReuseAlert(input): Promise<void> {
      reuseEvents.push(input.deviceId);
      const devices = await database.query<{ count: string }>(
        'SELECT COUNT(*)::text AS count FROM devices WHERE user_id = $1 AND revoked_at IS NOT NULL',
        [input.userId],
      );
      const activeTokens = await database.query<{ count: string }>(
        'SELECT COUNT(*)::text AS count FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL',
        [input.userId],
      );
      reuseCommitSnapshots.push({
        revokedDeviceCount: Number(devices.rows[0]?.count ?? '0'),
        activeRefreshTokenCount: Number(activeTokens.rows[0]?.count ?? '0'),
      });
    },
  };
  const service = new AuthService(store, jwtKeys, notifications, {
    authCodeHmacSecret: TEST_AUTH_CODE_SECRET,
    now: () => new Date(time),
  });
  return {
    database,
    store,
    service,
    notifications,
    verificationEmails,
    passwordResetEmails,
    newDeviceEvents,
    newDeviceCommitSnapshots,
    reuseEvents,
    reuseCommitSnapshots,
    setNow(value): void {
      time = new Date(value);
    },
    now(): Date {
      return new Date(time);
    },
  };
}

async function seedUser(
  harness: Harness,
  email: string,
  id = USER_ID,
  passwordHash = currentPasswordHash,
  disabledAt: Date | null = null,
  emailVerifiedAt: Date | null = new Date(INITIAL_TIME),
): Promise<void> {
  await harness.database.query(
    `INSERT INTO users (id, email, login_password_hash, disabled_at, email_verified_at)
     VALUES ($1, $2, $3, $4, $5)`,
    [id, email, passwordHash, disabledAt, emailVerifiedAt],
  );
}

async function seedDevice(
  harness: Harness,
  id: string,
  ownerId: string,
  name: string,
  revokedAt: Date | null = null,
): Promise<void> {
  await harness.database.query(
    `INSERT INTO devices (id, user_id, device_name, device_type, revoked_at)
     VALUES ($1, $2, $3, 'app', $4)`,
    [id, ownerId, name, revokedAt],
  );
}

function appFor(harness: Harness): Hono {
  return createAuthenticatedApp(loadConfig({}), {
    store: harness.store,
    jwtKeys,
    notifications: harness.notifications,
    authCodeHmacSecret: TEST_AUTH_CODE_SECRET,
    serviceOptions: { now: harness.now },
  }, silentLogger);
}

async function postJson(
  app: Hono,
  path: string,
  body: unknown,
  scheme = 'https',
  extraHeaders: Record<string, string> = {},
): Promise<Response> {
  return app.fetch(new Request(`${scheme}://api.sealero.test${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...extraHeaders },
    body: JSON.stringify(body),
  }));
}

function recordingDatabase(database: PGliteAuthDatabase, traces: string[][]): TransactionalSqlDatabase {
  return {
    query: <Row extends Record<string, unknown>>(text: string, values?: readonly unknown[]) =>
      database.query<Row>(text, values),
    transaction<T>(callback: (connection: SqlConnection) => Promise<T>): Promise<T> {
      const trace: string[] = [];
      traces.push(trace);
      return database.transaction((connection) => callback({
        async query<Row extends Record<string, unknown>>(text: string, values?: readonly unknown[]) {
          if (text.includes('SELECT user_id FROM refresh_tokens WHERE token_hash')) trace.push('owner_lookup');
          else if (text.includes('SELECT id FROM users WHERE id = $1 FOR UPDATE')) trace.push('account_lock');
          else if (text.includes('FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE')) trace.push('token_lock');
          return connection.query<Row>(text, values);
        },
      }));
    },
  };
}

function loginInput(email: string, options: Partial<{
  loginPassword: string;
  deviceName: string;
  deviceType: 'app' | 'web';
  deviceId: string;
}> = {}) {
  return {
    email,
    loginPassword: options.loginPassword ?? TEST_PASSWORD,
    deviceName: options.deviceName ?? 'test device',
    deviceType: options.deviceType ?? 'app',
    ...(options.deviceId === undefined ? {} : { deviceId: options.deviceId }),
  } as const;
}

async function login(harness: Harness, email: string, options: Parameters<typeof loginInput>[1] = {}): Promise<TokenPair> {
  return harness.service.login(loginInput(email, options), {
    ipAddress: '192.0.2.45',
    userAgent: 'auth-test/1.0',
  });
}

async function refreshRows(harness: Harness): Promise<readonly {
  id: string;
  user_id: string;
  device_id: string | null;
  token_hash: string;
  expires_at: Date | string;
  absolute_expires_at: Date | string;
  revoked_at: Date | string | null;
  revoked_reason: string | null;
  reuse_alerted_at: Date | string | null;
}[]> {
  const result = await harness.database.query<{
    id: string;
    user_id: string;
    device_id: string | null;
    token_hash: string;
    expires_at: Date | string;
    absolute_expires_at: Date | string;
    revoked_at: Date | string | null;
    revoked_reason: string | null;
    reuse_alerted_at: Date | string | null;
  }>('SELECT * FROM refresh_tokens ORDER BY created_at, id');
  return result.rows;
}

async function countRows(harness: Harness, table: 'devices' | 'refresh_tokens' | 'login_logs' | 'users'): Promise<number> {
  const result = await harness.database.query<{ count: string }>(`SELECT COUNT(*)::text AS count FROM ${table}`);
  return Number(result.rows[0]?.count ?? '0');
}

async function expectUnauthorized(operation: Promise<unknown>): Promise<void> {
  await expect(operation).rejects.toMatchObject({ status: 401 });
}

describe('authentication routes and account-enumeration resistance', () => {
  it('requires HTTPS for password routes and returns an indistinguishable generic registration response', async () => {
    const harness = await createHarness();
    await harness.database.query(
      "INSERT INTO server_settings (key, value) VALUES ('require_email_verification', 'true')",
    );
    const app = appFor(harness);
    const registration = { email: 'Tai@Example.test', login_password: TEST_PASSWORD };

    const insecure = await postJson(app, '/v1/auth/register', registration, 'http');
    expect(insecure.status).toBe(400);
    expect(await insecure.json()).toMatchObject({ code: 'https_required' });
    expect(await countRows(harness, 'users')).toBe(0);

    const insecureRefresh = await postJson(app, '/v1/auth/refresh', { refresh_token: 'A'.repeat(43) }, 'http', {
      'x-forwarded-proto': 'https',
    });
    const insecureLogout = await postJson(app, '/v1/auth/logout', { refresh_token: 'A'.repeat(43) }, 'http', {
      'x-forwarded-proto': 'https',
    });
    expect(insecureRefresh.status).toBe(400);
    expect(await insecureRefresh.json()).toMatchObject({ code: 'https_required' });
    expect(insecureLogout.status).toBe(400);
    expect(await insecureLogout.json()).toMatchObject({ code: 'https_required' });

    const first = await postJson(app, '/v1/auth/register', registration);
    const duplicate = await postJson(app, '/v1/auth/register', registration);
    expect(first.status).toBe(202);
    expect(duplicate.status).toBe(202);
    expect(await first.json()).toEqual(await duplicate.json());
    expect(await countRows(harness, 'users')).toBe(1);

    const stored = await harness.database.query<{
      email: string;
      login_password_hash: string;
      email_verified_at: Date | string | null;
    }>('SELECT email, login_password_hash, email_verified_at FROM users');
    expect(stored.rows[0]?.email).toBe('tai@example.test');
    expect(stored.rows[0]?.login_password_hash).toMatch(/^\$argon2id\$v=19\$m=32768,t=2,p=1\$/);
    expect(stored.rows[0]?.email_verified_at).toBeNull();

    const loginResponse = await postJson(app, '/v1/auth/login', {
      email: 'tai@example.test',
      login_password: TEST_PASSWORD,
      device_name: 'unverified but allowed',
      device_type: 'app',
    });
    expect(loginResponse.status).toBe(200);
    expect(await loginResponse.json()).toHaveProperty('device_id');

    const invalidDeviceId = await postJson(app, '/v1/auth/login', {
      email: 'tai@example.test',
      login_password: TEST_PASSWORD,
      device_name: 'invalid device id',
      device_type: 'app',
      device_id: 'not-a-uuid',
    });
    expect(invalidDeviceId.status).toBe(400);
    expect(await countRows(harness, 'devices')).toBe(1);

    const v1DisallowsExtension = await postJson(app, '/v1/auth/login', {
      email: 'tai@example.test',
      login_password: TEST_PASSWORD,
      device_name: 'extension client',
      device_type: 'extension',
    });
    expect(v1DisallowsExtension.status).toBe(400);
    expect(await countRows(harness, 'devices')).toBe(1);

    const limited = await harness.database.query<{ count: string }>(
      "SELECT COUNT(*)::text AS count FROM login_logs WHERE result = 'success'",
    );
    expect(Number(limited.rows[0]?.count)).toBe(1);
  });

  it('reports whether email verification is required in the generic registration response', async () => {
    const harness = await createHarness();
    const app = appFor(harness);

    // No setting stored: the default (on) applies.
    const byDefault = await postJson(app, '/v1/auth/register', {
      email: 'default@example.test',
      login_password: TEST_PASSWORD,
    });
    expect(byDefault.status).toBe(202);
    expect(await byDefault.json()).toMatchObject({
      code: 'registration_received',
      email_verification_required: true,
    });

    // Verification off: the same generic response reports false, so the
    // client can skip the verification step without learning anything
    // about this email.
    await harness.database.query(
      "INSERT INTO server_settings (key, value) VALUES ('require_email_verification', 'false')",
    );
    const whenOff = await postJson(app, '/v1/auth/register', {
      email: 'off@example.test',
      login_password: TEST_PASSWORD,
    });
    expect(whenOff.status).toBe(202);
    expect(await whenOff.json()).toMatchObject({
      code: 'registration_received',
      email_verification_required: false,
    });
  });

  it('rejects login passwords shorter than 8 characters with invalid_login_password', async () => {
    const harness = await createHarness();
    const app = appFor(harness);

    const shortRegister = await postJson(app, '/v1/auth/register', {
      email: 'short@example.test',
      login_password: 'short12',
    });
    expect(shortRegister.status).toBe(400);
    expect(await shortRegister.json()).toMatchObject({ code: 'invalid_login_password' });
    expect(await countRows(harness, 'users')).toBe(0);

    const shortLogin = await postJson(app, '/v1/auth/login', {
      email: 'short@example.test',
      login_password: 'short12',
      device_name: 'phone',
      device_type: 'app',
    });
    expect(shortLogin.status).toBe(400);
    expect(await shortLogin.json()).toMatchObject({ code: 'invalid_login_password' });
  });

  it('accepts an exactly 8-character login password and enforces the 4096-byte cap', async () => {
    const harness = await createHarness();
    const app = appFor(harness);
    const eightChars = '12345678';
    const maxBytesPassword = 'é'.repeat(2048); // 2 bytes each = exactly 4096 bytes
    const overMaxPassword = 'a'.repeat(4097);

    const exactEight = await postJson(app, '/v1/auth/register', {
      email: 'exact-eight@example.test',
      login_password: eightChars,
    });
    expect(exactEight.status).toBe(202);
    expect(await countRows(harness, 'users')).toBe(1);

    const maxBytes = await postJson(app, '/v1/auth/register', {
      email: 'max-bytes@example.test',
      login_password: maxBytesPassword,
    });
    expect(maxBytes.status).toBe(202);

    const overMax = await postJson(app, '/v1/auth/register', {
      email: 'over-max@example.test',
      login_password: overMaxPassword,
    });
    expect(overMax.status).toBe(400);
    expect(await overMax.json()).toMatchObject({ code: 'invalid_login_password' });
  });

  it('returns the same public status and body for unknown, wrong-password, and disabled accounts', async () => {
    const harness = await createHarness();
    await seedUser(harness, 'known@example.test', USER_ID);
    await seedUser(harness, 'disabled@example.test', OTHER_USER_ID, currentPasswordHash, new Date(INITIAL_TIME));
    const app = appFor(harness);
    const request = (email: string, password: string) => postJson(app, '/v1/auth/login', {
      email,
      login_password: password,
      device_name: 'enumeration test',
      device_type: 'web',
    });

    const wrongPassword = await request('known@example.test', 'not-the-password');
    const unknownAccount = await request('not-found@example.test', TEST_PASSWORD);
    const disabledAccount = await request('disabled@example.test', TEST_PASSWORD);
    expect(wrongPassword.status).toBe(401);
    const wrongBody = await wrongPassword.json();
    expect(wrongBody).toEqual(await unknownAccount.json());
    expect(wrongBody).toEqual(await disabledAccount.json());
    expect(await countRows(harness, 'devices')).toBe(0);
    const failureLogs = await harness.database.query<{ count: string }>(
      "SELECT COUNT(*)::text AS count FROM login_logs WHERE result = 'failed'",
    );
    expect(Number(failureLogs.rows[0]?.count)).toBe(3);
  });
});

describe('device binding and access JWT contract', () => {
  it('reuses only this user’s active device and creates a server UUID for every other hint', async () => {
    const harness = await createHarness();
    await seedUser(harness, 'owner@example.test', USER_ID);
    await seedUser(harness, 'other@example.test', OTHER_USER_ID);
    await seedDevice(harness, ACTIVE_DEVICE_ID, USER_ID, 'old name');
    await seedDevice(harness, FOREIGN_DEVICE_ID, OTHER_USER_ID, 'foreign');
    await seedDevice(harness, REVOKED_DEVICE_ID, USER_ID, 'revoked', new Date(INITIAL_TIME));

    const reused = await login(harness, 'owner@example.test', {
      deviceId: ACTIVE_DEVICE_ID,
      deviceName: 'renamed web browser',
      deviceType: 'web',
    });
    expect(reused.device_id).toBe(ACTIVE_DEVICE_ID);
    expect(harness.newDeviceEvents).toEqual([]);
    const changed = await harness.database.query<{ device_name: string; device_type: string }>(
      'SELECT device_name, device_type FROM devices WHERE id = $1', [ACTIVE_DEVICE_ID],
    );
    expect(changed.rows[0]).toEqual({ device_name: 'renamed web browser', device_type: 'web' });

    const invalidHints = [
      '00000000-0000-4000-8000-000000000099',
      FOREIGN_DEVICE_ID,
      REVOKED_DEVICE_ID,
    ];
    const created = await Promise.all(invalidHints.map((deviceId, index) => login(
      harness,
      'owner@example.test',
      { deviceId, deviceName: `new device ${index}`, deviceType: 'app' },
    )));
    for (const [index, pair] of created.entries()) {
      expect(pair.device_id).not.toBe(invalidHints[index]);
      expect(pair.device_id).toMatch(/^[0-9a-f-]{36}$/i);
      expect(verifyAccessToken(jwtKeys, pair.access_token, harness.now()).device_id).toBe(pair.device_id);
    }
    expect(new Set(created.map((pair) => pair.device_id)).size).toBe(3);
    expect(harness.newDeviceEvents).toHaveLength(3);
    expect(harness.newDeviceCommitSnapshots).toEqual(Array.from({ length: 3 }, () => ({
      deviceCount: 1,
      activeRefreshTokenCount: 1,
      successfulLoginLogCount: 1,
    })));

    const foreign = await harness.database.query<{ device_name: string; revoked_at: Date | string | null }>(
      'SELECT device_name, revoked_at FROM devices WHERE id = $1', [FOREIGN_DEVICE_ID],
    );
    expect(foreign.rows[0]?.device_name).toBe('foreign');
    expect(foreign.rows[0]?.revoked_at).toBeNull();
    const revoked = await harness.database.query<{ device_name: string; revoked_at: Date | string | null }>(
      'SELECT device_name, revoked_at FROM devices WHERE id = $1', [REVOKED_DEVICE_ID],
    );
    expect(revoked.rows[0]?.device_name).toBe('revoked');
    expect(revoked.rows[0]?.revoked_at).not.toBeNull();

    const allTokens = await refreshRows(harness);
    expect(allTokens).toHaveLength(4);
    expect(allTokens.every((row) => row.device_id !== null)).toBe(true);
    expect(new Set(allTokens.map((row) => row.device_id))).toEqual(new Set([
      ACTIVE_DEVICE_ID,
      ...created.map((pair) => pair.device_id),
    ]));
  });

  it('issues RS256 JWTs with the required claims, a 15-minute lifetime, and no refresh plaintext at rest', async () => {
    const harness = await createHarness();
    await seedUser(harness, 'jwt@example.test', USER_ID);
    const pair = await login(harness, 'jwt@example.test');
    const claims = verifyAccessToken(jwtKeys, pair.access_token, harness.now());
    const [headerSegment] = pair.access_token.split('.');
    const header = JSON.parse(Buffer.from(headerSegment!, 'base64url').toString('utf8')) as Record<string, unknown>;

    expect(header).toEqual({ alg: 'RS256', kid: publicJwk.kid, typ: 'JWT' });
    expect(claims).toEqual({
      sub: USER_ID,
      device_id: pair.device_id,
      exp: Math.floor(INITIAL_TIME.getTime() / 1000) + 900,
      iat: Math.floor(INITIAL_TIME.getTime() / 1000),
      iss: 'https://api.sealero.test',
      aud: 'sealero-api',
    });
    const rows = await refreshRows(harness);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.device_id).toBe(pair.device_id);
    expect(rows[0]?.token_hash).toBe(createHash('sha256').update(pair.refresh_token).digest('hex'));
    expect(rows[0]?.token_hash).not.toBe(pair.refresh_token);
    expect(Buffer.from(pair.refresh_token, 'base64url')).toHaveLength(32);
    expect(pair.refresh_token).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('checks exact JWT expiry without leeway and publishes the configured JWKS', async () => {
    const harness = await createHarness();
    await seedUser(harness, 'expiry@example.test', USER_ID);
    const pair = await login(harness, 'expiry@example.test');
    const claims = verifyAccessToken(jwtKeys, pair.access_token, harness.now());
    expect(verifyAccessToken(jwtKeys, pair.access_token, new Date((claims.exp - 1) * 1000))).toEqual(claims);
    expect(() => verifyAccessToken(jwtKeys, pair.access_token, new Date(claims.exp * 1000))).toThrow();

    const response = await appFor(harness).fetch(new Request('https://api.sealero.test/.well-known/jwks.json'));
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('public, max-age=300');
    expect(response.headers.get('content-type')).toContain('application/jwk-set+json');
    expect(await response.json()).toEqual({ keys: [publicJwk] });
  });

  it('loads only a matching normalized HTTPS issuer and active key, and fails closed when configuration is incomplete', () => {
    const directory = mkdtempSync(join(tmpdir(), 'sealero-jwt-test-'));
    try {
      const privateKeyPath = join(directory, 'private.pem');
      const mismatchedPrivateKeyPath = join(directory, 'mismatched-private.pem');
      const jwksPath = join(directory, 'jwks.json');
      writeFileSync(privateKeyPath, generatedKeys.privateKey.export({ type: 'pkcs8', format: 'pem' }));
      const mismatchedKeys = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 0x10001 });
      writeFileSync(mismatchedPrivateKeyPath, mismatchedKeys.privateKey.export({ type: 'pkcs8', format: 'pem' }));
      writeFileSync(jwksPath, JSON.stringify({ keys: [publicJwk] }));
      const environment = {
        JWT_PRIVATE_KEY_PATH: privateKeyPath,
        JWT_PUBLIC_KEY_PATH: jwksPath,
        JWT_ACTIVE_KID: publicJwk.kid,
        JWT_ISSUER: 'https://api.sealero.test',
      };
      expect(loadJwtKeySet(environment).activeKid).toBe(publicJwk.kid);
      expect(() => loadJwtKeySet({ ...environment, JWT_ACTIVE_KID: 'missing-kid' })).toThrow('JWT_ACTIVE_KID');
      expect(() => loadJwtKeySet({ ...environment, JWT_PRIVATE_KEY_PATH: mismatchedPrivateKeyPath }))
        .toThrow('does not match');
      expect(() => loadJwtKeySet({ ...environment, JWT_ISSUER: 'https://api.sealero.test/' })).toThrow('JWT_ISSUER');
      expect(() => loadJwtKeySet({})).toThrow('JWT_PRIVATE_KEY_PATH');
      expect(() => createConfiguredAuthenticatedApp(loadConfig({}), {
        store: {} as SqlAuthStore,
        notifications: {} as AuthNotification,
      }, {})).toThrow('JWT_PRIVATE_KEY_PATH');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('rejects access tokens immediately after device revocation and account disable, with no cached status', async () => {
    const harness = await createHarness();
    await seedUser(harness, 'middleware@example.test', USER_ID);
    const pair = await login(harness, 'middleware@example.test');
    const routes = new Hono<AuthenticatedEnvironment>();
    routes.get('/protected', (context) =>
      context.json({ subject: context.get('auth').sub }));
    const app = createAuthenticatedApp(loadConfig({}), {
      store: harness.store,
      jwtKeys,
      notifications: harness.notifications,
      authCodeHmacSecret: TEST_AUTH_CODE_SECRET,
      serviceOptions: { now: harness.now },
      protectedRoutes: routes,
    }, silentLogger);

    const request = (authorization?: string) => app.fetch(new Request('https://api.sealero.test/v1/protected', {
      headers: authorization === undefined ? {} : { authorization },
    }));
    const missing = await request();
    expect(missing.status).toBe(401);
    const valid = await request(`Bearer ${pair.access_token}`);
    expect(valid.status).toBe(200);
    expect(await valid.json()).toEqual({ subject: USER_ID });

    await harness.database.query('UPDATE devices SET revoked_at = $2 WHERE id = $1', [pair.device_id, harness.now()]);
    const revoked = await request(`Bearer ${pair.access_token}`);
    expect(revoked.status).toBe(401);
    expect(await revoked.json()).toMatchObject({ code: 'device_revoked' });

    await harness.database.query('UPDATE users SET disabled_at = $2 WHERE id = $1', [USER_ID, harness.now()]);
    await harness.database.query('UPDATE devices SET revoked_at = NULL WHERE id = $1', [pair.device_id]);
    const disabled = await request(`Bearer ${pair.access_token}`);
    expect(disabled.status).toBe(403);
    expect(await disabled.json()).toMatchObject({ code: 'account_disabled' });
  });
});

describe('refresh-token rotation, expiry, reuse handling, and logout', () => {
  it('rolls back device and refresh-token creation when the success log cannot commit', async () => {
    const harness = await createHarness();
    await seedUser(harness, 'login-rollback@example.test', USER_ID);
    await harness.database.query(`
      CREATE FUNCTION auth_test_fail_login_log() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'test-only login-log failure'; END; $$
    `);
    await harness.database.query(`
      CREATE TRIGGER auth_test_fail_login_log_trigger
      BEFORE INSERT ON login_logs FOR EACH ROW
      WHEN (NEW.result = 'success')
      EXECUTE FUNCTION auth_test_fail_login_log()
    `);

    await expect(login(harness, 'login-rollback@example.test')).rejects.toThrow('test-only login-log failure');
    expect(await countRows(harness, 'devices')).toBe(0);
    expect(await countRows(harness, 'refresh_tokens')).toBe(0);
    expect(await countRows(harness, 'login_logs')).toBe(0);
    expect(harness.newDeviceEvents).toEqual([]);
    expect(harness.newDeviceCommitSnapshots).toEqual([]);
  });

  it('rotates refresh tokens, preserves the fixed 90-day session limit, and strictly rejects expiry', async () => {
    const harness = await createHarness();
    await seedUser(harness, 'refresh@example.test', USER_ID);
    const first = await login(harness, 'refresh@example.test');
    const firstRows = await refreshRows(harness);
    const absoluteExpiry = new Date(firstRows[0]!.absolute_expires_at).getTime();
    expect(absoluteExpiry).toBe(INITIAL_TIME.getTime() + 90 * 24 * 60 * 60 * 1000);

    harness.setNow(new Date(INITIAL_TIME.getTime() + 28 * 24 * 60 * 60 * 1000));
    const second = await harness.service.refresh(first.refresh_token);
    let rows = await refreshRows(harness);
    expect(rows[0]?.revoked_reason).toBe('rotated');
    expect(new Date(rows[1]!.expires_at).getTime()).toBe(INITIAL_TIME.getTime() + 58 * 24 * 60 * 60 * 1000);
    expect(new Date(rows[1]!.absolute_expires_at).getTime()).toBe(absoluteExpiry);

    harness.setNow(new Date(INITIAL_TIME.getTime() + 57 * 24 * 60 * 60 * 1000));
    const third = await harness.service.refresh(second.refresh_token);
    harness.setNow(new Date(INITIAL_TIME.getTime() + 86 * 24 * 60 * 60 * 1000));
    const fourth = await harness.service.refresh(third.refresh_token);
    rows = await refreshRows(harness);
    expect(rows).toHaveLength(4);
    expect(new Date(rows[3]!.expires_at).getTime()).toBe(absoluteExpiry);
    expect(new Date(rows[3]!.absolute_expires_at).getTime()).toBe(absoluteExpiry);
    expect(verifyAccessToken(jwtKeys, fourth.access_token, harness.now()).device_id).toBe(first.device_id);

    harness.setNow(new Date(absoluteExpiry));
    await expectUnauthorized(harness.service.refresh(fourth.refresh_token));
    expect(await countRows(harness, 'refresh_tokens')).toBe(4);
  });

  it('rejects an unrevoked token at its exact 30-day expiry without issuing another token', async () => {
    const harness = await createHarness();
    await seedUser(harness, 'single-expiry@example.test', USER_ID);
    const pair = await login(harness, 'single-expiry@example.test');
    const expiry = new Date((await refreshRows(harness))[0]!.expires_at).getTime();
    harness.setNow(new Date(expiry));
    await expectUnauthorized(harness.service.refresh(pair.refresh_token));
    expect(await countRows(harness, 'refresh_tokens')).toBe(1);
    expect((await refreshRows(harness))[0]?.revoked_at).toBeNull();
  });

  it('logs out only the current refresh token and does not invoke reuse handling', async () => {
    const harness = await createHarness();
    await seedUser(harness, 'logout@example.test', USER_ID);
    const pair = await login(harness, 'logout@example.test');
    await harness.service.logout(pair.refresh_token);
    const row = (await refreshRows(harness))[0];
    expect(row?.revoked_reason).toBe('logout');
    expect(row?.revoked_at).not.toBeNull();
    await expectUnauthorized(harness.service.refresh(pair.refresh_token));
    expect(harness.reuseEvents).toEqual([]);
  });

  it('exposes refresh and logout through the HTTP API and rejects malformed or extra refresh fields', async () => {
    const harness = await createHarness();
    await seedUser(harness, 'route-refresh@example.test', USER_ID);
    const initial = await login(harness, 'route-refresh@example.test');
    const app = appFor(harness);

    const malformed = await postJson(app, '/v1/auth/refresh', {
      refresh_token: initial.refresh_token,
      unexpected: 'field',
    });
    expect(malformed.status).toBe(400);
    const refreshed = await postJson(app, '/v1/auth/refresh', { refresh_token: initial.refresh_token });
    expect(refreshed.status).toBe(200);
    const pair = await refreshed.json() as TokenPair;
    expect(pair.device_id).toBe(initial.device_id);
    expect(pair.refresh_token).not.toBe(initial.refresh_token);
    expect(verifyAccessToken(jwtKeys, pair.access_token, harness.now()).device_id).toBe(initial.device_id);

    const loggedOut = await postJson(app, '/v1/auth/logout', { refresh_token: pair.refresh_token });
    expect(loggedOut.status).toBe(204);
    const records = await refreshRows(harness);
    expect(records.find((row) => row.token_hash === createHash('sha256').update(initial.refresh_token).digest('hex'))?.revoked_reason)
      .toBe('rotated');
    expect(records.find((row) => row.token_hash === createHash('sha256').update(pair.refresh_token).digest('hex'))?.revoked_reason)
      .toBe('logout');
  });

  it('uses an HttpOnly Secure SameSite=Lax cookie for web refresh and enforces configured Origin', async () => {
    const harness = await createHarness();
    await seedUser(harness, 'web-cookie@example.test', USER_ID);
    const app = appFor(harness);
    const loginResponse = await postJson(app, '/v1/auth/login', {
      email: 'web-cookie@example.test',
      login_password: TEST_PASSWORD,
      device_name: 'web browser',
      device_type: 'web',
    });
    expect(loginResponse.status).toBe(200);
    const loginCookie = loginResponse.headers.get('set-cookie');
    expect(loginCookie).toContain('__Host-sealero_refresh=');
    expect(loginCookie).toContain('Path=/');
    expect(loginCookie).toContain('HttpOnly');
    expect(loginCookie).toContain('Secure');
    expect(loginCookie).toContain('SameSite=Lax');
    const loginCookiePair = loginCookie!.split(';', 1)[0]!;
    const loginBody = await loginResponse.json() as Record<string, unknown>;
    expect(loginBody).toHaveProperty('device_id');
    expect(loginBody).toHaveProperty('access_token');
    expect(loginBody).not.toHaveProperty('refresh_token');

    const noOrigin = await app.fetch(new Request('https://api.sealero.test/v1/auth/refresh', {
      method: 'POST',
      headers: { cookie: loginCookiePair },
    }));
    const spoofedOrigin = await app.fetch(new Request('https://api.sealero.test/v1/auth/refresh', {
      method: 'POST',
      headers: {
        cookie: loginCookiePair,
        origin: 'https://evil.example',
        'x-forwarded-host': 'api.sealero.test',
        'x-forwarded-proto': 'https',
      },
    }));
    expect(noOrigin.status).toBe(403);
    expect(spoofedOrigin.status).toBe(403);
    expect(await countRows(harness, 'refresh_tokens')).toBe(1);
    expect((await refreshRows(harness))[0]?.revoked_at).toBeNull();

    const refreshed = await app.fetch(new Request('https://api.sealero.test/v1/auth/refresh', {
      method: 'POST',
      headers: { cookie: loginCookiePair, origin: jwtKeys.issuer },
    }));
    expect(refreshed.status).toBe(200);
    const refreshedCookie = refreshed.headers.get('set-cookie');
    expect(refreshedCookie).toContain('__Host-sealero_refresh=');
    expect(refreshedCookie).toContain('HttpOnly');
    expect(refreshedCookie).toContain('Secure');
    expect(refreshedCookie).toContain('SameSite=Lax');
    const refreshedCookiePair = refreshedCookie!.split(';', 1)[0]!;
    expect(refreshedCookiePair).not.toBe(loginCookiePair);
    const refreshedBody = await refreshed.json() as Record<string, unknown>;
    expect(refreshedBody).toHaveProperty('device_id');
    expect(refreshedBody).toHaveProperty('access_token');
    expect(refreshedBody).not.toHaveProperty('refresh_token');

    const loggedOut = await app.fetch(new Request('https://api.sealero.test/v1/auth/logout', {
      method: 'POST',
      headers: { cookie: refreshedCookiePair, origin: jwtKeys.issuer },
    }));
    expect(loggedOut.status).toBe(204);
    expect(loggedOut.headers.get('set-cookie')).toContain('Max-Age=0');
    const records = await refreshRows(harness);
    expect(records.find((row) => row.token_hash === createHash('sha256')
      .update(refreshedCookiePair.slice(refreshedCookiePair.indexOf('=') + 1)).digest('hex'))?.revoked_reason)
      .toBe('logout');
  });

  it('does not fan out on unknown, non-rotated, old, or already-revoked-device tokens', async () => {
    const harness = await createHarness();
    await seedUser(harness, 'branches@example.test', USER_ID);
    await expectUnauthorized(harness.service.refresh('A'.repeat(43)));
    expect(await countRows(harness, 'devices')).toBe(0);

    const loggedOut = await login(harness, 'branches@example.test');
    await harness.service.logout(loggedOut.refresh_token);
    await expectUnauthorized(harness.service.refresh(loggedOut.refresh_token));
    expect(harness.reuseEvents).toEqual([]);

    const stale = await login(harness, 'branches@example.test');
    const rotated = await harness.service.refresh(stale.refresh_token);
    harness.setNow(new Date(harness.now().getTime() + REFRESH_REUSE_WINDOW_MS + 1));
    await expectUnauthorized(harness.service.refresh(stale.refresh_token));
    expect(harness.reuseEvents).toEqual([]);
    const stillActive = await harness.database.query<{ revoked_at: Date | string | null }>(
      'SELECT revoked_at FROM devices WHERE id = $1', [rotated.device_id],
    );
    expect(stillActive.rows[0]?.revoked_at).toBeNull();

    const revoked = await login(harness, 'branches@example.test');
    await harness.service.refresh(revoked.refresh_token);
    await harness.database.query('UPDATE devices SET revoked_at = $2 WHERE id = $1', [revoked.device_id, harness.now()]);
    await expectUnauthorized(harness.service.refresh(revoked.refresh_token));
    expect(harness.reuseEvents).toEqual([]);
  });

  it('atomically claims one concurrent reuse, revokes every device/session, and notifies once after commit', async () => {
    const harness = await createHarness();
    await seedUser(harness, 'reuse@example.test', USER_ID);
    const first = await login(harness, 'reuse@example.test', { deviceName: 'desktop' });
    const second = await login(harness, 'reuse@example.test', { deviceName: 'phone' });
    const rotated = await harness.service.refresh(first.refresh_token);

    const outcomes = await Promise.allSettled([
      harness.service.refresh(first.refresh_token),
      harness.service.refresh(first.refresh_token),
    ]);
    expect(outcomes.every((outcome) => outcome.status === 'rejected')).toBe(true);
    for (const outcome of outcomes) {
      if (outcome.status === 'rejected') expect(outcome.reason).toMatchObject({ status: 401 });
    }

    expect(harness.reuseEvents).toEqual([first.device_id]);
    expect(harness.reuseCommitSnapshots).toEqual([{ revokedDeviceCount: 2, activeRefreshTokenCount: 0 }]);
    const devices = await harness.database.query<{ id: string; revoked_at: Date | string | null }>(
      'SELECT id, revoked_at FROM devices WHERE user_id = $1 ORDER BY id', [USER_ID],
    );
    expect(devices.rows).toHaveLength(2);
    expect(devices.rows.every((device) => device.revoked_at !== null)).toBe(true);

    const tokens = await refreshRows(harness);
    const replayed = tokens.find((row) => row.token_hash === createHash('sha256').update(first.refresh_token).digest('hex'));
    expect(replayed?.revoked_reason).toBe('rotated');
    expect(replayed?.reuse_alerted_at).not.toBeNull();
    const revokedActive = tokens.filter((row) => row.revoked_reason === 'device_revoked');
    expect(revokedActive).toHaveLength(2);
    expect(revokedActive.every((row) => row.device_id === first.device_id || row.device_id === second.device_id)).toBe(true);
    expect(rotated.device_id).toBe(first.device_id);
  });

  it('serializes replay against another device refresh with account-first locks and one committed fanout', async () => {
    const harness = await createHarness();
    await seedUser(harness, 'cross-token-race@example.test', USER_ID);
    const desktop = await login(harness, 'cross-token-race@example.test', { deviceName: 'desktop' });
    const phone = await login(harness, 'cross-token-race@example.test', { deviceName: 'phone' });
    await harness.service.refresh(desktop.refresh_token);

    const lockTraces: string[][] = [];
    const tracedService = new AuthService(
      new SqlAuthStore(recordingDatabase(harness.database, lockTraces)),
      jwtKeys,
      harness.notifications,
      { authCodeHmacSecret: TEST_AUTH_CODE_SECRET, now: harness.now },
    );
    const outcomes = await Promise.allSettled([
      tracedService.refresh(desktop.refresh_token),
      tracedService.refresh(phone.refresh_token),
    ]);

    expect(outcomes).toHaveLength(2);
    expect(outcomes[0]).toMatchObject({ status: 'rejected', reason: { status: 401 } });
    if (outcomes[1]?.status === 'rejected') expect(outcomes[1].reason).toMatchObject({ status: 401 });
    expect(lockTraces).toHaveLength(2);
    expect(lockTraces.every((trace) => trace.slice(0, 3).join(',') === 'owner_lookup,account_lock,token_lock')).toBe(true);
    expect(harness.reuseEvents).toEqual([desktop.device_id]);
    expect(harness.reuseCommitSnapshots).toEqual([{ revokedDeviceCount: 2, activeRefreshTokenCount: 0 }]);
    const activeTokens = await harness.database.query<{ count: string }>(
      'SELECT COUNT(*)::text AS count FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL', [USER_ID],
    );
    expect(Number(activeTokens.rows[0]?.count)).toBe(0);
    const replayed = await harness.database.query<{ reuse_alerted_at: Date | string | null }>(
      'SELECT reuse_alerted_at FROM refresh_tokens WHERE token_hash = $1',
      [createHash('sha256').update(desktop.refresh_token).digest('hex')],
    );
    expect(replayed.rows[0]?.reuse_alerted_at).not.toBeNull();
  });

  it('rolls back a reuse claim and all revocations together when the transaction fails, then can claim once', async () => {
    const harness = await createHarness();
    await seedUser(harness, 'rollback@example.test', USER_ID);
    const first = await login(harness, 'rollback@example.test');
    await login(harness, 'rollback@example.test', { deviceName: 'second device' });
    await harness.service.refresh(first.refresh_token);
    const hash = createHash('sha256').update(first.refresh_token).digest('hex');

    await harness.database.query(`
      CREATE FUNCTION auth_test_fail_device_revoke() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'test-only revoke failure'; END; $$
    `);
    await harness.database.query(`
      CREATE TRIGGER auth_test_fail_device_revoke_trigger
      BEFORE UPDATE ON devices FOR EACH ROW
      WHEN (NEW.revoked_at IS NOT NULL)
      EXECUTE FUNCTION auth_test_fail_device_revoke()
    `);
    await expect(harness.service.refresh(first.refresh_token)).rejects.toThrow('test-only revoke failure');

    let row = (await harness.database.query<{ reuse_alerted_at: Date | string | null }>(
      'SELECT reuse_alerted_at FROM refresh_tokens WHERE token_hash = $1', [hash],
    )).rows[0];
    expect(row?.reuse_alerted_at).toBeNull();
    expect(await countRows(harness, 'devices')).toBe(2);
    expect(harness.reuseEvents).toEqual([]);

    await harness.database.query('DROP TRIGGER auth_test_fail_device_revoke_trigger ON devices');
    await harness.database.query('DROP FUNCTION auth_test_fail_device_revoke()');
    await expectUnauthorized(harness.service.refresh(first.refresh_token));
    row = (await harness.database.query<{ reuse_alerted_at: Date | string | null }>(
      'SELECT reuse_alerted_at FROM refresh_tokens WHERE token_hash = $1', [hash],
    )).rows[0];
    expect(row?.reuse_alerted_at).not.toBeNull();
    expect(harness.reuseEvents).toHaveLength(1);
  });

  it('upgrades an outdated Argon2id PHC hash only after a successful login', async () => {
    const harness = await createHarness();
    const outdatedHash = await argon2.hash(TEST_PASSWORD, {
      type: argon2.argon2id,
      memoryCost: 8 * 1024,
      timeCost: 1,
      parallelism: 1,
      hashLength: 32,
    });
    await seedUser(harness, 'rehash@example.test', USER_ID, outdatedHash);
    const pair = await login(harness, 'rehash@example.test');
    expect(pair.refresh_token).toBeTruthy();

    const row = await harness.database.query<{ login_password_hash: string }>(
      'SELECT login_password_hash FROM users WHERE id = $1', [USER_ID],
    );
    expect(row.rows[0]?.login_password_hash).not.toBe(outdatedHash);
    expect(row.rows[0]?.login_password_hash).toMatch(/^\$argon2id\$v=19\$m=32768,t=2,p=1\$/);
    expect(loginPasswordNeedsRehash(row.rows[0]!.login_password_hash)).toBe(false);

    await expect(harness.service.login(loginInput('rehash@example.test', { loginPassword: 'incorrect' }), {
      ipAddress: null,
      userAgent: null,
    })).rejects.toBeInstanceOf(AuthServiceError);
    const unchanged = await harness.database.query<{ login_password_hash: string }>(
      'SELECT login_password_hash FROM users WHERE id = $1', [USER_ID],
    );
    expect(unchanged.rows[0]?.login_password_hash).toBe(row.rows[0]?.login_password_hash);
  });
});
