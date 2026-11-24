import { generateKeyPairSync } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { createAuthenticatedApp } from '../auth/app.js';
import { issueAccessToken } from '../auth/jwt.js';
import type { JwtKeySet, PublicJwk } from '../auth/jwt.js';
import type { AuthNotification } from '../auth/types.js';
import { SqlAuthStore } from '../db/auth-store.js';
import { LocalPGliteAuthDatabase } from '../db/local-pglite-auth.js';
import { loadConfig } from '../config.js';

const USER_ID = '00000000-0000-4000-8000-000000000101';
const DEVICE_ID = '00000000-0000-4000-8000-000000000111';
const POLICY_VERSION = 'test-privacy-v1';
const INITIAL_TIME = new Date('2026-11-23T01:00:00.000Z');
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
  kid: 'consent-test-key',
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
  readonly token: string;
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
    `INSERT INTO users (id, email, login_password_hash, email_verified_at)
     VALUES ($1, 'owner@example.test', 'test-hash', $2)`,
    [USER_ID, INITIAL_TIME],
  );
  await database.query(
    `INSERT INTO devices (id, user_id, device_name, device_type)
     VALUES ($1, $2, 'primary', 'app')`,
    [DEVICE_ID, USER_ID],
  );

  const currentTime = INITIAL_TIME;
  const store = new SqlAuthStore(database);
  const app = createAuthenticatedApp(loadConfig({}), {
    store,
    jwtKeys,
    notifications,
    authCodeHmacSecret: 'consent-test-secret-long-enough-for-hmac-key',
    policyVersion: POLICY_VERSION,
    serviceOptions: { now: () => currentTime },
  }, silentLogger);
  return {
    database,
    app,
    token: issueAccessToken(jwtKeys, USER_ID, DEVICE_ID, INITIAL_TIME),
  };
}

afterEach(async () => {
  await Promise.all(openDatabases.splice(0).map((database) => database.close()));
});

async function request(
  harness: Harness,
  method: 'GET' | 'POST' | 'DELETE',
  path: string,
  body?: unknown,
  extraHeaders: Record<string, string> = {},
): Promise<Response> {
  return harness.app.fetch(new Request(`https://api.sealero.test${path}`, {
    method,
    headers: {
      authorization: `Bearer ${harness.token}`,
      ...extraHeaders,
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  }));
}

describe('authenticated privacy consent API', () => {
  it('records current consent with the approved response shape and keeps withdrawal unsupported', async () => {
    const harness = await createHarness();

    const devices = await request(harness, 'GET', '/v1/devices');
    expect(devices.status).toBe(200);

    const vaultBlocked = await request(harness, 'GET', '/v1/vault/list');
    expect(vaultBlocked.status).toBe(403);
    expect(await vaultBlocked.json()).toMatchObject({ code: 'consent_required' });
    const keyBlocked = await request(harness, 'GET', '/v1/vault-key');
    expect(keyBlocked.status).toBe(403);
    expect(await keyBlocked.json()).toMatchObject({ code: 'consent_required' });

    const consentResponse = await request(
      harness,
      'POST',
      '/v1/auth/consent',
      { policy_version: POLICY_VERSION },
      { 'x-forwarded-for': '203.0.113.10, 203.0.113.11' },
    );
    expect(consentResponse.status).toBe(200);
    expect(await consentResponse.json()).toEqual({
      policy_type: 'privacy',
      policy_version: POLICY_VERSION,
      consented_at: INITIAL_TIME.toISOString(),
    });

    const saved = await harness.database.query<{
      policy_version: string;
      consented_at: Date | string;
      ip_address: string | null;
    }>(
      `SELECT policy_version, consented_at, ip_address FROM user_consents
       WHERE user_id = $1 AND policy_type = 'privacy'`,
      [USER_ID],
    );
    expect(saved.rows).toHaveLength(1);
    expect(saved.rows[0]?.policy_version).toBe(POLICY_VERSION);
    expect(new Date(saved.rows[0]?.consented_at as Date | string).toISOString()).toBe(INITIAL_TIME.toISOString());
    expect(saved.rows[0]?.ip_address).toBe('203.0.113.10');

    const keyAllowed = await request(harness, 'GET', '/v1/vault-key');
    expect(keyAllowed.status).toBe(404);
    expect(await keyAllowed.json()).toMatchObject({ code: 'vault_key_not_found' });

    const unsupportedWithdrawal = await request(harness, 'DELETE', '/v1/auth/consent');
    expect(unsupportedWithdrawal.ok).toBe(false);
    const savedAfterUnsupportedWithdrawal = await harness.database.query(
      'SELECT id FROM user_consents WHERE user_id = $1 AND policy_type = $2', [USER_ID, 'privacy'],
    );
    expect(savedAfterUnsupportedWithdrawal.rows).toHaveLength(1);
    const keyStillAllowed = await request(harness, 'GET', '/v1/vault-key');
    expect(keyStillAllowed.status).toBe(404);
    expect(await keyStillAllowed.json()).toMatchObject({ code: 'vault_key_not_found' });

    const audits = await harness.database.query<{ count: string }>(
      'SELECT COUNT(*)::text AS count FROM audit_logs WHERE actor_user_id = $1', [USER_ID],
    );
    expect(audits.rows[0]?.count).toBe('0');
  });

  it('requires authentication and does not record consent for an unauthenticated POST', async () => {
    const harness = await createHarness();
    const response = await harness.app.fetch(new Request('https://api.sealero.test/v1/auth/consent', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ policy_version: POLICY_VERSION }),
    }));

    expect(response.status).toBe(401);
    const saved = await harness.database.query(
      'SELECT id FROM user_consents WHERE user_id = $1 AND policy_type = $2', [USER_ID, 'privacy'],
    );
    expect(saved.rows).toHaveLength(0);
  });

  it('checks email verification before consent for vault access', async () => {
    const harness = await createHarness();
    await harness.database.query(
      `UPDATE users SET email_verified_at = NULL WHERE id = $1`, [USER_ID],
    );
    await harness.database.query(
      `INSERT INTO server_settings (key, value) VALUES ('require_email_verification', 'true')`,
    );

    const response = await request(harness, 'GET', '/v1/vault/list');
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ code: 'email_verification_required' });
  });
});
