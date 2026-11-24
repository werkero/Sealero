import { createDecipheriv, generateKeyPairSync } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { createAuthenticatedApp } from '../auth/app.js';
import { issueAccessToken } from '../auth/jwt.js';
import type { JwtKeySet, PublicJwk } from '../auth/jwt.js';
import { hashLoginPassword } from '../auth/password.js';
import type { AuthNotification, UserRole } from '../auth/types.js';
import { SqlAuthStore } from '../db/auth-store.js';
import { LocalPGliteAuthDatabase } from '../db/local-pglite-auth.js';
import { loadConfig } from '../config.js';

const PASSWORD = 'admin-owner-login-password';
const AUTH_CODE_SECRET = 'admin-db-dump-test-secret-at-least-32-bytes';
const INITIAL_TIME = new Date('2026-11-23T00:00:00.000Z');
const ADMIN_ID = '00000000-0000-4000-8000-000000000101';
const USER_ID = '00000000-0000-4000-8000-000000000103';
const ADMIN_DEVICE_ID = '00000000-0000-4000-8000-000000000201';
const USER_DEVICE_ID = '00000000-0000-4000-8000-000000000203';
const VAULT_ITEM_ID = '00000000-0000-4000-8000-000000000501';
// Fixed 32-byte test key; never a production key.
const TEST_DUMP_KEY = Buffer.from(
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hex');
const DB_DUMP_TABLES = [
  'users', 'devices', 'vault_items', 'refresh_tokens', 'auth_codes',
  'server_settings', 'roles', 'user_roles', 'audit_logs', 'login_logs',
  'rate_limits', 'user_consents', 'oauth_authorizations', 'dek_wrappings',
  'oauth_auth_codes', 'mcp_confirmations',
] as const;
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
  kid: 'admin-db-dump-test-key',
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

async function createHarness(dbDumpKey: Buffer | null = TEST_DUMP_KEY): Promise<Harness> {
  const database = await LocalPGliteAuthDatabase.create();
  openDatabases.push(database);
  const passwordHash = await hashLoginPassword(PASSWORD);
  for (const role of ['admin', 'user', 'super_admin'] as const) {
    await database.query('INSERT INTO roles (name) VALUES ($1) ON CONFLICT (name) DO NOTHING', [role]);
  }
  const now = new Date(INITIAL_TIME);
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
    ...(dbDumpKey === null ? {} : { dbDumpKey }),
    serviceOptions: { now: () => new Date(now), delayLoginFailure: async () => undefined },
  }, silentLogger);
  return {
    database,
    app,
    passwordHash,
    token(userId = ADMIN_ID, deviceId = ADMIN_DEVICE_ID): string {
      return issueAccessToken(jwtKeys, userId, deviceId, new Date(now));
    },
  };
}

async function seedUser(
  harness: Harness,
  id: string,
  email: string,
  roles: readonly UserRole[],
): Promise<void> {
  await harness.database.query(
    `INSERT INTO users (id, email, login_password_hash, created_at, email_verified_at, disabled_at)
     VALUES ($1, $2, $3, $4, $5, NULL)`,
    [id, email, harness.passwordHash, INITIAL_TIME, INITIAL_TIME],
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

interface DbDumpDocument {
  header: {
    format_version: number;
    exported_at: string;
    row_counts: Record<string, number>;
  };
  tables: Record<string, Array<Record<string, string | number | boolean | null>>>;
}

async function decryptDump(response: Response): Promise<{ headerLine: Record<string, unknown>; document: DbDumpDocument }> {
  const buffer = Buffer.from(await response.arrayBuffer());
  const newline = buffer.indexOf(0x0a);
  expect(newline).toBeGreaterThan(0);
  const headerLine = JSON.parse(buffer.subarray(0, newline).toString('utf8')) as Record<string, unknown>;
  const ciphertext = buffer.subarray(newline + 1);
  expect(typeof headerLine['nonce']).toBe('string');
  const decipher = createDecipheriv('aes-256-gcm', TEST_DUMP_KEY,
    Buffer.from(headerLine['nonce'] as string, 'base64url'));
  decipher.setAAD(Buffer.from('1', 'utf8'));
  decipher.setAuthTag(ciphertext.subarray(ciphertext.length - 16));
  const plaintext = Buffer.concat([
    decipher.update(ciphertext.subarray(0, ciphertext.length - 16)),
    decipher.final(),
  ]).toString('utf8');
  return { headerLine, document: JSON.parse(plaintext) as DbDumpDocument };
}

describe('admin db-dump API', () => {
  it('returns an encrypted dump covering all 16 tables with smtp_pass nulled', async () => {
    const harness = await createHarness();
    await seedUser(harness, ADMIN_ID, 'admin@example.test', ['admin']);
    await seedUser(harness, USER_ID, 'alice@example.test', ['user']);
    await seedDevice(harness, ADMIN_DEVICE_ID, ADMIN_ID, 'admin device');
    await seedDevice(harness, USER_DEVICE_ID, USER_ID, 'alice device');
    await harness.database.query(
      `INSERT INTO vault_items (id, user_id, overview_ciphertext, overview_nonce, detail_ciphertext, detail_nonce,
                               domain_hmac, device_id)
       VALUES ($1, $2, 'overview', 'nonce', 'detail', 'nonce', 'domain-hmac', $3)`,
      [VAULT_ITEM_ID, USER_ID, USER_DEVICE_ID],
    );
    await harness.database.query(
      `INSERT INTO server_settings (key, value) VALUES
         ('smtp_host', 'smtp.example.test'),
         ('smtp_pass', 'super-secret-smtp-password'),
         ('max_vault_size_mb', '100')`,
    );

    const response = await post(harness, '/v1/admin/db-dump', { login_password: PASSWORD });
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('application/octet-stream');
    expect(response.headers.get('content-disposition'))
      .toBe('attachment; filename="sealero-db-dump-20261123-000000.enc.json"');

    const { headerLine, document } = await decryptDump(response);
    expect(headerLine['format_version']).toBe(1);
    expect(document.header.format_version).toBe(1);
    expect(document.header.exported_at).toBe(INITIAL_TIME.toISOString());
    expect(Object.keys(document.tables).sort()).toEqual([...DB_DUMP_TABLES].sort());
    expect(Object.keys(document.header.row_counts).sort()).toEqual([...DB_DUMP_TABLES].sort());
    expect(document.header.row_counts['users']).toBe(2);
    expect(document.header.row_counts['devices']).toBe(2);
    expect(document.header.row_counts['vault_items']).toBe(1);
    expect(document.header.row_counts['server_settings']).toBe(3);
    expect(document.header.row_counts['roles']).toBe(3);
    expect(document.tables['users']?.map((user) => user['email']).sort())
      .toEqual(['admin@example.test', 'alice@example.test']);
    const settings = new Map(document.tables['server_settings']?.map((row) => [row['key'], row['value']]));
    expect(settings.get('smtp_host')).toBe('smtp.example.test');
    expect(settings.get('smtp_pass')).toBeNull();
    expect(settings.get('max_vault_size_mb')).toBe('100');
    expect(JSON.stringify(document)).not.toContain('super-secret-smtp-password');

    const audit = await harness.database.query<{ action: string; metadata: string }>(
      "SELECT action, metadata FROM audit_logs WHERE action = 'db_dump'",
    );
    expect(audit.rows).toEqual([{ action: 'db_dump', metadata: '{}' }]);
  });

  it('rejects a wrong login password with 401 and no file', async () => {
    const harness = await createHarness();
    await seedUser(harness, ADMIN_ID, 'admin@example.test', ['admin']);
    await seedDevice(harness, ADMIN_DEVICE_ID, ADMIN_ID, 'admin device');

    const response = await post(harness, '/v1/admin/db-dump', { login_password: 'wrong-password' });
    expect(response.status).toBe(401);
    const body = await response.json() as { code: string };
    expect(body.code).toBe('invalid_credentials');
    const audit = await harness.database.query<{ count: string }>(
      "SELECT COUNT(*)::text AS count FROM audit_logs WHERE action = 'db_dump'",
    );
    expect(Number(audit.rows[0]?.count ?? '0')).toBe(0);
  });

  it('requires an administrator and a login_password field', async () => {
    const harness = await createHarness();
    await seedUser(harness, ADMIN_ID, 'admin@example.test', ['admin']);
    await seedUser(harness, USER_ID, 'alice@example.test', ['user']);
    await seedDevice(harness, ADMIN_DEVICE_ID, ADMIN_ID, 'admin device');
    await seedDevice(harness, USER_DEVICE_ID, USER_ID, 'alice device');

    const missingToken = await post(harness, '/v1/admin/db-dump', { login_password: PASSWORD }, null);
    expect(missingToken.status).toBe(401);
    const nonAdmin = await post(harness, '/v1/admin/db-dump', { login_password: PASSWORD },
      harness.token(USER_ID, USER_DEVICE_ID));
    expect(nonAdmin.status).toBe(403);
    const nonAdminBody = await nonAdmin.json() as { code: string };
    expect(nonAdminBody.code).toBe('admin_required');
    const missingField = await post(harness, '/v1/admin/db-dump', {});
    expect(missingField.status).toBe(400);
    const extraField = await post(harness, '/v1/admin/db-dump', { login_password: PASSWORD, extra: true });
    expect(extraField.status).toBe(400);
  });

  it('fails closed with 503 when no dump key is configured', async () => {
    const harness = await createHarness(null);
    await seedUser(harness, ADMIN_ID, 'admin@example.test', ['admin']);
    await seedDevice(harness, ADMIN_DEVICE_ID, ADMIN_ID, 'admin device');

    const response = await post(harness, '/v1/admin/db-dump', { login_password: PASSWORD });
    expect(response.status).toBe(503);
    const body = await response.json() as { code: string };
    expect(body.code).toBe('db_dump_unavailable');
  });
});
