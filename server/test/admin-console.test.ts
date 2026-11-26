import { generateKeyPairSync } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { createAuthenticatedApp } from '../auth/app.js';
import { issueAccessToken } from '../auth/jwt.js';
import type { JwtKeySet, PublicJwk } from '../auth/jwt.js';
import { hashLoginPassword } from '../auth/password.js';
import type { AuthNotification, UserRole } from '../auth/types.js';
import { SqlAuthStore } from '../db/auth-store.js';
import { LocalPGliteAuthDatabase } from '../db/local-pglite-auth.js';
import { loadConfig } from '../config.js';

const PASSWORD = 'admin-console-test-password';
const AUTH_CODE_SECRET = 'admin-console-test-hmac-secret-at-least-32-bytes';
const INITIAL_TIME = new Date('2026-11-23T00:00:00.000Z');
const ADMIN_ID = '00000000-0000-4000-8000-000000000101';
const USER_ID = '00000000-0000-4000-8000-000000000102';
const ADMIN_DEVICE_ID = '00000000-0000-4000-8000-000000000201';
const USER_DEVICE_ID = '00000000-0000-4000-8000-000000000202';
const AUDIT_ID_1 = '00000000-0000-4000-8000-000000000301';
const AUDIT_ID_2 = '00000000-0000-4000-8000-000000000302';
const AUDIT_ID_3 = '00000000-0000-4000-8000-000000000303';
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
  kid: 'admin-console-test-key',
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
  setNow(value: Date): void;
  token(userId?: string, deviceId?: string): string;
}

const openDatabases: LocalPGliteAuthDatabase[] = [];

afterEach(async () => {
  await Promise.all(openDatabases.splice(0).map((database) => database.close()));
});

async function seedUser(
  database: LocalPGliteAuthDatabase,
  passwordHash: string,
  id: string,
  email: string,
  role: UserRole,
): Promise<void> {
  await database.query(
    `INSERT INTO users (id, email, login_password_hash, created_at, email_verified_at)
     VALUES ($1, $2, $3, $4, $4)`,
    [id, email, passwordHash, INITIAL_TIME],
  );
  await database.query('INSERT INTO user_roles (user_id, role_id) SELECT $1, id FROM roles WHERE name = $2', [id, role]);
  await database.query(
    `INSERT INTO devices (id, user_id, device_name, device_type, created_at)
     VALUES ($1, $2, 'test device', 'app', $3)`,
    [id === ADMIN_ID ? ADMIN_DEVICE_ID : USER_DEVICE_ID, id, INITIAL_TIME],
  );
}

async function createHarness(
  environment: NodeJS.ProcessEnv = { SERVER_NAME: 'Environment Sealero', SMTP_PASS: 'environment-secret-value' },
): Promise<Harness> {
  const database = await LocalPGliteAuthDatabase.create();
  openDatabases.push(database);
  const passwordHash = await hashLoginPassword(PASSWORD);
  for (const role of ['admin', 'user', 'super_admin'] as const) {
    await database.query('INSERT INTO roles (name) VALUES ($1) ON CONFLICT (name) DO NOTHING', [role]);
  }
  await seedUser(database, passwordHash, ADMIN_ID, 'admin@example.test', 'admin');
  await seedUser(database, passwordHash, USER_ID, 'user@example.test', 'user');

  let time = new Date(INITIAL_TIME);
  const notifications: AuthNotification = {
    async sendVerificationCode(): Promise<void> {},
    async sendPasswordResetCode(): Promise<void> {},
    async sendDeleteAccountCode(): Promise<void> {},
    async sendNewDeviceLogin(): Promise<void> {},
    async sendRefreshReuseAlert(): Promise<void> {},
  };
  const store = new SqlAuthStore(database);
  const app = createAuthenticatedApp(loadConfig(environment), {
    store,
    jwtKeys,
    notifications,
    authCodeHmacSecret: AUTH_CODE_SECRET,
    serviceOptions: { now: () => new Date(time), delayLoginFailure: async () => undefined },
  }, silentLogger);
  return {
    database,
    app,
    setNow(value): void {
      time = new Date(value);
    },
    token(userId = ADMIN_ID, deviceId = ADMIN_DEVICE_ID): string {
      return issueAccessToken(jwtKeys, userId, deviceId, new Date(time));
    },
  };
}

async function call(
  harness: Harness,
  path: string,
  method = 'GET',
  body?: unknown,
  token: string | null = harness.token(),
  protocol: 'http' | 'https' = 'https',
): Promise<Response> {
  const headers = new Headers();
  if (token !== null) headers.set('authorization', `Bearer ${token}`);
  if (body !== undefined) headers.set('content-type', 'application/json');
  return harness.app.fetch(new Request(`${protocol}://api.sealero.test${path}`, {
    method,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  }));
}

async function put(harness: Harness, path: string, body: unknown): Promise<Response> {
  return call(harness, path, 'PUT', body);
}

async function errorCode(response: Response): Promise<string> {
  return (await response.json() as { code: string }).code;
}

describe('admin settings and audit APIs', () => {
  it('requires an authenticated administrator over HTTPS and returns effective settings without the SMTP password', async () => {
    const harness = await createHarness();
    expect((await call(harness, '/v1/admin/settings', 'GET', undefined, null)).status).toBe(401);
    expect((await call(harness, '/v1/admin/settings', 'GET', undefined, harness.token(USER_ID, USER_DEVICE_ID))).status).toBe(403);

    const httpResponse = await call(harness, '/v1/admin/settings', 'GET', undefined, harness.token(), 'http');
    expect(httpResponse.status).toBe(400);
    expect(await errorCode(httpResponse)).toBe('https_required');

    const response = await call(harness, '/v1/admin/settings');
    expect(response.status).toBe(200);
    const body = await response.json() as Record<string, unknown>;
    expect(body).toEqual({
      settings: {
        server_name: 'Environment Sealero',
        allow_registration: true,
        require_email_verification: true,
        max_vault_size_mb: 100,
        smtp_host: null,
        smtp_port: null,
        smtp_user: null,
        smtp_from: null,
        smtp_secure: false,
        min_app_version_android: null,
        min_app_version_ios: null,
        min_app_version_web: null,
      },
      sources: {
        server_name: 'env',
        allow_registration: 'default',
        require_email_verification: 'default',
        max_vault_size_mb: 'default',
        smtp_host: 'default',
        smtp_port: 'default',
        smtp_user: 'default',
        smtp_pass: 'env',
        smtp_from: 'default',
        smtp_secure: 'default',
        min_app_version_android: 'default',
        min_app_version_ios: 'default',
        min_app_version_web: 'default',
      },
      smtp_pass_configured: true,
      tombstone_retention_days: 30,
    });
    expect('smtp_pass' in (body['settings'] as Record<string, unknown>)).toBe(false);
    expect(JSON.stringify(body)).not.toContain('environment-secret-value');
  });

  it('atomically updates the allowlisted settings, audits key names only, and lets explicit null fall back to the environment', async () => {
    const harness = await createHarness();
    const secret = 'database-smtp-password-marker';
    const updated = await put(harness, '/v1/admin/settings', {
      server_name: 'Database Sealero',
      require_email_verification: true,
      max_vault_size_mb: 512,
      smtp_host: 'smtp.example.test',
      smtp_port: 587,
      smtp_user: 'mailer',
      smtp_pass: secret,
      smtp_from: 'noreply@example.test',
      smtp_secure: true,
      min_app_version_android: '1.2.3',
    });
    expect(updated.status).toBe(200);
    const responseBody = await updated.text();
    expect(responseBody).not.toContain(secret);
    const body = JSON.parse(responseBody) as {
      settings: Record<string, unknown>;
      sources: Record<string, string>;
      smtp_pass_configured: boolean;
    };
    expect(body.settings).toMatchObject({
      server_name: 'Database Sealero',
      require_email_verification: true,
      max_vault_size_mb: 512,
      smtp_host: 'smtp.example.test',
      smtp_port: 587,
      smtp_user: 'mailer',
      smtp_from: 'noreply@example.test',
      smtp_secure: true,
      min_app_version_android: '1.2.3',
    });
    expect(body.settings).not.toHaveProperty('smtp_pass');
    expect(body.sources['server_name']).toBe('db');
    expect(body.sources['smtp_pass']).toBe('db');
    expect(body.smtp_pass_configured).toBe(true);

    const healthResponse = await call(harness, '/v1/health');
    expect(healthResponse.status).toBe(200);
    const healthBody = await healthResponse.json() as {
      server_name: string;
      min_app_versions: { android: string | null; ios: string | null; web: string | null };
    };
    expect(healthBody).toMatchObject({
      server_name: 'Database Sealero',
      min_app_versions: { android: '1.2.3', ios: null, web: null },
    });

    const stored = await harness.database.query<{ value: string }>(
      "SELECT value FROM server_settings WHERE key = 'smtp_pass'",
    );
    expect(stored.rows[0]?.value).toBe(secret);
    const audit = await harness.database.query<{ action: string; metadata: string | null }>(
      "SELECT action, metadata FROM audit_logs WHERE action = 'settings_update'",
    );
    expect(audit.rows).toHaveLength(1);
    expect(JSON.parse(audit.rows[0]?.metadata ?? 'null')).toEqual({
      keys_changed: [
        'server_name', 'require_email_verification', 'max_vault_size_mb', 'smtp_host', 'smtp_port',
        'smtp_user', 'smtp_pass', 'smtp_from', 'smtp_secure', 'min_app_version_android',
      ],
    });
    expect(JSON.stringify(audit.rows)).not.toContain(secret);

    const cleared = await put(harness, '/v1/admin/settings', { server_name: null, smtp_pass: null });
    expect(cleared.status).toBe(200);
    const clearedBody = await cleared.json() as {
      settings: Record<string, unknown>;
      sources: Record<string, string>;
      smtp_pass_configured: boolean;
    };
    expect(clearedBody.settings['server_name']).toBe('Environment Sealero');
    expect(clearedBody.sources['server_name']).toBe('env');
    expect(clearedBody.sources['smtp_pass']).toBe('env');
    expect(clearedBody.smtp_pass_configured).toBe(true);
    const remaining = await harness.database.query<{ key: string }>(
      "SELECT key FROM server_settings WHERE key IN ('server_name', 'smtp_pass') ORDER BY key",
    );
    expect(remaining.rows).toEqual([]);
  });

  it('rejects unknown keys, invalid values, and incomplete SMTP combinations without writes', async () => {
    const harness = await createHarness();

    const unknown = await put(harness, '/v1/admin/settings', { server_name: 'Must not write', mystery: true });
    expect(unknown.status).toBe(400);
    expect(await errorCode(unknown)).toBe('unknown_setting_key');
    const invalid = await put(harness, '/v1/admin/settings', { server_name: 'Must not write', max_vault_size_mb: 0 });
    expect(invalid.status).toBe(400);
    expect(await errorCode(invalid)).toBe('invalid_setting_value');
    for (const smtpFrom of ['a..b@example.test', 'valid@example..test']) {
      const invalidEmail = await put(harness, '/v1/admin/settings', {
        smtp_host: 'smtp.example.test',
        smtp_port: 587,
        smtp_from: smtpFrom,
      });
      expect(invalidEmail.status).toBe(400);
      expect(await errorCode(invalidEmail)).toBe('invalid_setting_value');
    }
    const missingSmtp = await put(harness, '/v1/admin/settings', { require_email_verification: true });
    expect(missingSmtp.status).toBe(400);
    expect(await errorCode(missingSmtp)).toBe('smtp_not_configured');
    const partialSmtp = await put(harness, '/v1/admin/settings', { smtp_host: 'smtp.example.test' });
    expect(partialSmtp.status).toBe(400);
    expect(await errorCode(partialSmtp)).toBe('smtp_incomplete');

    const rows = await harness.database.query<{ count: string }>('SELECT COUNT(*)::text AS count FROM server_settings');
    const audits = await harness.database.query<{ count: string }>(
      "SELECT COUNT(*)::text AS count FROM audit_logs WHERE action = 'settings_update'",
    );
    expect(Number(rows.rows[0]?.count)).toBe(0);
    expect(Number(audits.rows[0]?.count)).toBe(0);
  });

  it('rolls back setting writes when the audit insert fails', async () => {
    const harness = await createHarness();
    await harness.database.query(
      "ALTER TABLE audit_logs ADD CONSTRAINT reject_settings_update CHECK (action <> 'settings_update')",
    );

    // Verification is on by default, so the update must carry complete SMTP
    // to pass validation and reach the audit insert that is meant to fail.
    const failed = await put(harness, '/v1/admin/settings', {
      server_name: 'Must rollback',
      smtp_host: 'smtp.example.test',
      smtp_port: 587,
      smtp_from: 'noreply@example.test',
    });
    expect(failed.status).toBe(500);
    expect(await errorCode(failed)).toBe('internal_error');
    const rows = await harness.database.query<{ count: string }>('SELECT COUNT(*)::text AS count FROM server_settings');
    expect(Number(rows.rows[0]?.count)).toBe(0);
  });

  it('filters, paginates, and sanitizes audit metadata', async () => {
    const harness = await createHarness();
    await harness.database.query(
      `INSERT INTO audit_logs (id, actor_user_id, action, target_type, metadata, ip_address, created_at)
       VALUES
       ($1, $2, 'settings_update', 'server_settings', $3, '192.0.2.1', $4),
       ($5, $2, 'device_revoke', 'device', $6, '192.0.2.2', $7),
       ($8, $2, 'settings_update', 'server_settings', $9, '192.0.2.3', $10)`,
      [
        AUDIT_ID_1, ADMIN_ID,
        JSON.stringify({ keys_changed: ['server_name', 'smtp_pass', 'unknown_key'], smtp_pass: 'do-not-return', token: 'do-not-return' }),
        new Date(INITIAL_TIME.getTime() + 3_000),
        AUDIT_ID_2, JSON.stringify({ device_id: USER_DEVICE_ID, token: 'do-not-return' }),
        new Date(INITIAL_TIME.getTime() + 2_000),
        AUDIT_ID_3, JSON.stringify({ keys_changed: ['max_vault_size_mb'], password: 'do-not-return' }),
        new Date(INITIAL_TIME.getTime() + 1_000),
      ],
    );

    const first = await call(harness, '/v1/admin/audit?action=settings_update&limit=1');
    expect(first.status).toBe(200);
    const firstBody = await first.json() as {
      items: Array<{ id: string; metadata: Record<string, unknown> }>;
      total_count: number;
      has_more: boolean;
      next_cursor: string | null;
    };
    expect(firstBody.total_count).toBe(2);
    expect(firstBody.items.map((item) => item.id)).toEqual([AUDIT_ID_1]);
    expect(firstBody.items[0]?.metadata).toEqual({ keys_changed: ['server_name', 'smtp_pass'] });
    expect(firstBody.has_more).toBe(true);
    expect(firstBody.next_cursor).toBe(AUDIT_ID_1);
    expect(JSON.stringify(firstBody)).not.toContain('do-not-return');

    const second = await call(harness, `/v1/admin/audit?action=settings_update&limit=1&cursor=${AUDIT_ID_1}`);
    const secondBody = await second.json() as typeof firstBody;
    expect(secondBody.total_count).toBe(2);
    expect(secondBody.items.map((item) => item.id)).toEqual([AUDIT_ID_3]);
    expect(secondBody.items[0]?.metadata).toEqual({ keys_changed: ['max_vault_size_mb'] });
    expect(secondBody.has_more).toBe(false);
    expect(secondBody.next_cursor).toBeNull();

    const unknownAction = await call(harness, '/v1/admin/audit?action=not-a-known-action');
    expect(unknownAction.status).toBe(200);
    const emptyBody = await unknownAction.json() as { items: unknown[]; total_count: number; has_more: boolean; next_cursor: string | null };
    expect(emptyBody).toEqual({ items: [], total_count: 0, has_more: false, next_cursor: null });

    const deviceAudit = await call(harness, '/v1/admin/audit?action=device_revoke');
    const deviceBody = await deviceAudit.json() as { items: Array<{ metadata: Record<string, unknown> }> };
    expect(deviceBody.items[0]?.metadata).toEqual({ device_id: USER_DEVICE_ID });

    const invalidCursor = await call(harness, '/v1/admin/audit?cursor=00000000-0000-4000-8000-000000000999');
    expect(invalidCursor.status).toBe(400);
    expect(await errorCode(invalidCursor)).toBe('invalid_cursor');
  });
});
