import { createHash, createHmac, generateKeyPairSync } from 'node:crypto';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createAuthenticatedApp } from '../auth/app.js';
import { issueAccessToken } from '../auth/jwt.js';
import type { JwtKeySet, PublicJwk } from '../auth/jwt.js';
import { hashLoginPassword } from '../auth/password.js';
import type { AuthNotification, UserRole } from '../auth/types.js';
import { SqlAuthStore } from '../db/auth-store.js';
import { LocalPGliteAuthDatabase } from '../db/local-pglite-auth.js';
import { loadConfig } from '../config.js';

const EMAIL = 'delete-owner@example.test';
const PASSWORD = 'delete-account-login-password';
const HMAC_SECRET = 'delete-account-test-hmac-secret-with-at-least-32-bytes';
const INITIAL_TIME = new Date('2026-11-23T00:00:00.000Z');
const USER_ID = '00000000-0000-4000-8000-000000000101';
const DEVICE_ID = '00000000-0000-4000-8000-000000000111';
const VAULT_ITEM_ID = '00000000-0000-4000-8000-000000000201';
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
  kid: 'auth-delete-test-key',
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

interface DeliveredCode {
  readonly email: string;
  readonly code: string;
  readonly expiresAt: Date;
}

interface Harness {
  readonly database: LocalPGliteAuthDatabase;
  readonly app: ReturnType<typeof createAuthenticatedApp>;
  readonly deleteEmails: DeliveredCode[];
  setNow(value: Date): void;
  now(): Date;
  token(): string;
}

let passwordHash = '';
const openDatabases: LocalPGliteAuthDatabase[] = [];

beforeAll(async () => {
  passwordHash = await hashLoginPassword(PASSWORD);
});

afterEach(async () => {
  await Promise.all(openDatabases.splice(0).map((database) => database.close()));
});

async function createHarness(role?: UserRole): Promise<Harness> {
  const database = await LocalPGliteAuthDatabase.create();
  openDatabases.push(database);
  await database.query(
    `INSERT INTO users (id, email, login_password_hash, email_verified_at)
     VALUES ($1, $2, $3, $4)`,
    [USER_ID, EMAIL, passwordHash, INITIAL_TIME],
  );
  await database.query(
    `INSERT INTO devices (id, user_id, device_name, device_type)
     VALUES ($1, $2, 'test device', 'app')`,
    [DEVICE_ID, USER_ID],
  );
  if (role !== undefined) {
    await database.query('INSERT INTO roles (name) VALUES ($1) ON CONFLICT (name) DO NOTHING', [role]);
    const roleRow = await database.query<{ id: string }>('SELECT id FROM roles WHERE name = $1', [role]);
    await database.query('INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)', [USER_ID, roleRow.rows[0]!.id]);
  }

  let time = new Date(INITIAL_TIME);
  const deleteEmails: DeliveredCode[] = [];
  const notifications: AuthNotification = {
    async sendVerificationCode(): Promise<void> {},
    async sendPasswordResetCode(): Promise<void> {},
    async sendDeleteAccountCode(input): Promise<void> {
      deleteEmails.push(input);
    },
    async sendNewDeviceLogin(): Promise<void> {},
    async sendRefreshReuseAlert(): Promise<void> {},
  };
  const store = new SqlAuthStore(database);
  const now = (): Date => new Date(time);
  const app = createAuthenticatedApp(loadConfig({}), {
    store,
    jwtKeys,
    notifications,
    authCodeHmacSecret: HMAC_SECRET,
    serviceOptions: { now, delayLoginFailure: async () => undefined },
  }, silentLogger);
  return {
    database,
    app,
    deleteEmails,
    setNow(value): void {
      time = new Date(value);
    },
    now,
    token(): string {
      return issueAccessToken(jwtKeys, USER_ID, DEVICE_ID, now());
    },
  };
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

async function requestDeleteCode(harness: Harness): Promise<Response> {
  return post(harness, '/v1/auth/request-delete-code');
}

async function deleteAccount(
  harness: Harness,
  loginPassword: string,
  emailCode: string,
  backupExportedConfirmed: boolean,
): Promise<Response> {
  return post(harness, '/v1/auth/delete-account', {
    login_password: loginPassword,
    email_code: emailCode,
    backup_exported_confirmed: backupExportedConfirmed,
  });
}

function codeHash(email: string, code: string): string {
  return createHmac('sha256', HMAC_SECRET)
    .update('delete', 'utf8')
    .update('\0', 'utf8')
    .update(email, 'utf8')
    .update('\0', 'utf8')
    .update(code, 'utf8')
    .digest('hex');
}

async function countRows(
  harness: Harness,
  table: 'users' | 'devices' | 'refresh_tokens' | 'oauth_authorizations' | 'dek_wrappings' |
    'user_consents' | 'vault_items' | 'auth_codes' | 'login_logs' | 'audit_logs',
): Promise<number> {
  const result = await harness.database.query<{ count: string }>(`SELECT COUNT(*)::text AS count FROM ${table}`);
  return Number(result.rows[0]?.count ?? '0');
}

async function seedUserData(harness: Harness): Promise<void> {
  const expires = new Date(INITIAL_TIME.getTime() + 24 * 60 * 60 * 1000);
  const absoluteExpires = new Date(INITIAL_TIME.getTime() + 90 * 24 * 60 * 60 * 1000);
  await harness.database.query(
    `INSERT INTO refresh_tokens (user_id, device_id, token_hash, expires_at, absolute_expires_at)
     VALUES ($1, $2, 'test-refresh-hash', $3, $4)`,
    [USER_ID, DEVICE_ID, expires, absoluteExpires],
  );
  await harness.database.query(
    `INSERT INTO oauth_authorizations
       (user_id, client_id, redirect_uri, scopes, access_token_hash, refresh_token_hash, expires_at, refresh_expires_at)
     VALUES ($1, 'test-client', 'https://client.example/callback', 'mcp:read', 'test-access-hash', 'test-oauth-refresh-hash', $2, $3)`,
    [USER_ID, expires, absoluteExpires],
  );
  await harness.database.query(
    `INSERT INTO dek_wrappings
       (user_id, dek_version, wrapped_dek, nonce, kdf_salt, kdf_params, master_password_version)
     VALUES ($1, 1, 'wrapped', 'nonce', 'salt', '{"name":"test"}', 1)`,
    [USER_ID],
  );
  await harness.database.query(
    `INSERT INTO user_consents (user_id, policy_type, policy_version)
     VALUES ($1, 'privacy', '1.0')`,
    [USER_ID],
  );
  await harness.database.query(
    `INSERT INTO vault_items
       (id, user_id, overview_ciphertext, overview_nonce, detail_ciphertext, detail_nonce, domain_hmac, device_id)
     VALUES ($1, $2, 'overview-cipher', 'overview-nonce', 'detail-cipher', 'detail-nonce', 'domain-hmac', $3)`,
    [VAULT_ITEM_ID, USER_ID, DEVICE_ID],
  );
  await harness.database.query(
    `INSERT INTO login_logs (user_id, device_id, device_name, ip_address, user_agent, result, created_at)
     VALUES ($1, $2, 'test device', '192.0.2.19', 'auth-delete-test/1.0', 'success', $3)`,
    [USER_ID, DEVICE_ID, INITIAL_TIME],
  );
}

describe('self-service account deletion', () => {
  it('requires JWT, issues one 15-minute HMAC-only code, and enforces the 60-second resend interval', async () => {
    const harness = await createHarness();
    const unauthorizedDirect = await post(harness, '/v1/auth/request-delete-code', undefined, null);
    expect(unauthorizedDirect.status).toBe(401);
    const extraBody = await post(harness, '/v1/auth/request-delete-code', { email: EMAIL });
    expect(extraBody.status).toBe(400);
    expect(harness.deleteEmails).toHaveLength(0);

    const firstResponse = await requestDeleteCode(harness);
    expect(firstResponse.status).toBe(202);
    expect(await firstResponse.json()).toMatchObject({ code: 'delete_code_requested' });
    const first = harness.deleteEmails[0]!;
    expect(first.email).toBe(EMAIL);
    expect(first.code).toMatch(/^\d{6}$/);
    expect(first.expiresAt.getTime()).toBe(INITIAL_TIME.getTime() + 15 * 60_000);

    const stored = await harness.database.query<{
      email: string;
      purpose: string;
      code_hash: string;
      expires_at: Date | string;
      used_at: Date | string | null;
    }>('SELECT email, purpose, code_hash, expires_at, used_at FROM auth_codes');
    expect(stored.rows).toHaveLength(1);
    expect(stored.rows[0]?.email).toBe(EMAIL);
    expect(stored.rows[0]?.purpose).toBe('delete');
    expect(stored.rows[0]?.code_hash).toBe(codeHash(EMAIL, first.code));
    expect(stored.rows[0]?.code_hash).not.toBe(first.code);

    harness.setNow(new Date(INITIAL_TIME.getTime() + 59_999));
    expect((await requestDeleteCode(harness)).status).toBe(202);
    expect(harness.deleteEmails).toHaveLength(1);

    harness.setNow(new Date(INITIAL_TIME.getTime() + 60_000));
    expect((await requestDeleteCode(harness)).status).toBe(202);
    expect(harness.deleteEmails).toHaveLength(2);
    const second = harness.deleteEmails[1]!;
    expect(second.code).not.toBe(first.code);
    const codes = await harness.database.query<{ code_hash: string; used_at: Date | string | null }>(
      "SELECT code_hash, used_at FROM auth_codes WHERE email = $1 AND purpose = 'delete' ORDER BY created_at, id",
      [EMAIL],
    );
    expect(codes.rows).toHaveLength(2);
    expect(codes.rows[0]?.used_at).not.toBeNull();
    expect(codes.rows[1]?.used_at).toBeNull();

    harness.setNow(new Date(INITIAL_TIME.getTime() + 60_000 + 15 * 60_000));
    const expired = await deleteAccount(harness, PASSWORD, second.code, true);
    expect(expired.status).toBe(400);
    expect(await expired.json()).toMatchObject({ code: 'invalid_auth_code' });
    expect(await countRows(harness, 'users')).toBe(1);
  });

  it('checks password before the code, invalidates after five failures, consumes confirmation codes, then cascades deletion', async () => {
    const harness = await createHarness();
    await seedUserData(harness);
    await requestDeleteCode(harness);
    const originalCode = harness.deleteEmails[0]!.code;

    const wrongPassword = await deleteAccount(harness, 'wrong-password', '000000', false);
    expect(wrongPassword.status).toBe(401);
    const attemptsAfterWrongPassword = await harness.database.query<{ attempts: number }>(
      "SELECT attempts FROM auth_codes WHERE email = $1 AND purpose = 'delete'", [EMAIL],
    );
    expect(attemptsAfterWrongPassword.rows[0]?.attempts).toBe(0);

    for (let attempt = 0; attempt < 5; attempt += 1) {
      const incorrect = await deleteAccount(harness, PASSWORD, originalCode === '000000' ? '000001' : '000000', true);
      expect(incorrect.status).toBe(400);
    }
    const exhausted = await harness.database.query<{ attempts: number; used_at: Date | string | null }>(
      "SELECT attempts, used_at FROM auth_codes WHERE email = $1 AND purpose = 'delete'", [EMAIL],
    );
    expect(exhausted.rows[0]?.attempts).toBe(5);
    expect(exhausted.rows[0]?.used_at).not.toBeNull();
    expect((await deleteAccount(harness, PASSWORD, originalCode, true)).status).toBe(400);

    harness.setNow(new Date(INITIAL_TIME.getTime() + 60_000));
    await requestDeleteCode(harness);
    const unconfirmedCode = harness.deleteEmails[1]!.code;
    const unconfirmed = await deleteAccount(harness, PASSWORD, unconfirmedCode, false);
    expect(unconfirmed.status).toBe(400);
    expect(await unconfirmed.json()).toMatchObject({ code: 'backup_export_required' });
    expect(await countRows(harness, 'users')).toBe(1);
    const consumed = await harness.database.query<{ used_at: Date | string | null }>(
      "SELECT used_at FROM auth_codes WHERE email = $1 AND purpose = 'delete' ORDER BY created_at DESC LIMIT 1", [EMAIL],
    );
    expect(consumed.rows[0]?.used_at).not.toBeNull();

    harness.setNow(new Date(INITIAL_TIME.getTime() + 120_000));
    await requestDeleteCode(harness);
    const finalCode = harness.deleteEmails[2]!.code;
    const deleted = await deleteAccount(harness, PASSWORD, finalCode, true);
    expect(deleted.status).toBe(200);
    expect(await deleted.json()).toEqual({
      code: 'account_deleted',
      message: 'The account has been permanently deleted.',
    });
    for (const table of [
      'users', 'devices', 'refresh_tokens', 'oauth_authorizations', 'dek_wrappings',
      'user_consents', 'vault_items', 'auth_codes',
    ] as const) {
      expect(await countRows(harness, table)).toBe(0);
    }
    const emailKey = createHash('sha256').update(EMAIL, 'utf8').digest('hex');
    const residualEmailRateLimits = await harness.database.query<{ count: string }>(
      "SELECT COUNT(*)::text AS count FROM rate_limits WHERE key = $1 AND scope IN ('login_email', 'password_recovery_email')",
      [emailKey],
    );
    expect(residualEmailRateLimits.rows[0]?.count).toBe('0');
    const loginLog = await harness.database.query<{ user_id: string | null; device_id: string | null }>(
      'SELECT user_id, device_id FROM login_logs',
    );
    expect(loginLog.rows).toEqual([{ user_id: null, device_id: null }]);
    const auditLog = await harness.database.query<{
      actor_user_id: string | null;
      target_user_id: string | null;
      action: string;
      target_type: string | null;
      ip_address: string | null;
    }>('SELECT actor_user_id, target_user_id, action, target_type, ip_address FROM audit_logs');
    expect(auditLog.rows).toEqual([{
      actor_user_id: null,
      target_user_id: null,
      action: 'account.self_delete',
      target_type: 'user',
      ip_address: null,
    }]);

    const oldJwtAfterDeletion = await requestDeleteCode(harness);
    expect(oldJwtAfterDeletion.status).toBe(401);
  });

  it.each(['admin', 'super_admin'] as const)(
    'rejects %s self-deletion and writes a durable audit log', async (role) => {
      const harness = await createHarness(role);
      await requestDeleteCode(harness);
      const response = await deleteAccount(harness, PASSWORD, harness.deleteEmails[0]!.code, true);
      expect(response.status).toBe(403);
      expect(await response.json()).toMatchObject({ code: 'self_deletion_forbidden' });
      expect(await countRows(harness, 'users')).toBe(1);
      const audit = await harness.database.query<{
        actor_user_id: string;
        target_user_id: string;
        action: string;
        metadata: string;
      }>('SELECT actor_user_id, target_user_id, action, metadata FROM audit_logs');
      expect(audit.rows).toHaveLength(1);
      expect(audit.rows[0]?.actor_user_id).toBe(USER_ID);
      expect(audit.rows[0]?.target_user_id).toBe(USER_ID);
      expect(audit.rows[0]?.action).toBe('account.self_delete_denied');
      expect(JSON.parse(audit.rows[0]!.metadata)).toEqual({});
    },
  );
});
