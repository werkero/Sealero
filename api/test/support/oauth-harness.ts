import { generateKeyPairSync } from 'node:crypto';
import { createAuthenticatedApp } from '../../auth/app.js';
import { issueAccessToken } from '../../auth/jwt.js';
import type { JwtKeySet, PublicJwk } from '../../auth/jwt.js';
import type { AuthNotification } from '../../auth/types.js';
import { SqlAuthStore } from '../../db/auth-store.js';
import { LocalPGliteAuthDatabase } from '../../db/local-pglite-auth.js';
import { loadConfig } from '../../config.js';

export const OAUTH_TEST_USER_ID = '00000000-0000-4000-8000-000000000201';
export const OAUTH_TEST_DEVICE_ID = '00000000-0000-4000-8000-000000000211';
export const OAUTH_TEST_POLICY_VERSION = 'test-privacy-v1';
export const OAUTH_TEST_INITIAL_TIME = new Date('2026-11-24T00:00:00.000Z');
export const OAUTH_TEST_AUTH_CODE_SECRET = 'oauth-test-secret-long-enough-for-hmac-key';

const generatedKeys = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 0x10001 });
const exportedJwk = generatedKeys.publicKey.export({ format: 'jwk' });
if (typeof exportedJwk.n !== 'string' || typeof exportedJwk.e !== 'string') {
  throw new Error('Test key did not export RSA public parameters.');
}
const publicJwk: PublicJwk = {
  kty: 'RSA',
  use: 'sig',
  alg: 'RS256',
  kid: 'oauth-test-key',
  n: exportedJwk.n,
  e: exportedJwk.e,
};
export const oauthTestJwtKeys: JwtKeySet = {
  activeKid: publicJwk.kid,
  issuer: 'https://api.sealero.test',
  privateKey: generatedKeys.privateKey,
  publicKeys: new Map([[publicJwk.kid, generatedKeys.publicKey]]),
  jwks: { keys: [publicJwk] },
};

const silentLogger = { log: () => undefined };
const silentNotifications: AuthNotification = {
  async sendVerificationCode(): Promise<void> {},
  async sendPasswordResetCode(): Promise<void> {},
  async sendDeleteAccountCode(): Promise<void> {},
  async sendNewDeviceLogin(): Promise<void> {},
  async sendRefreshReuseAlert(): Promise<void> {},
};

export interface OAuthHarness {
  readonly database: LocalPGliteAuthDatabase;
  readonly store: SqlAuthStore;
  readonly app: ReturnType<typeof createAuthenticatedApp>;
  readonly token: string;
  readonly userId: string;
  readonly deviceId: string;
  now(): Date;
  setNow(value: Date): void;
  /** Records current-version privacy consent for the test user. */
  consent(): Promise<Response>;
}

const openDatabases: LocalPGliteAuthDatabase[] = [];

export async function closeOAuthHarnesses(): Promise<void> {
  await Promise.all(openDatabases.splice(0).map((database) => database.close()));
}

export async function createOAuthHarness(): Promise<OAuthHarness> {
  const database = await LocalPGliteAuthDatabase.create();
  openDatabases.push(database);
  await database.query(
    `INSERT INTO users (id, email, login_password_hash, email_verified_at)
     VALUES ($1, 'oauth-owner@example.test', 'test-hash', $2)`,
    [OAUTH_TEST_USER_ID, OAUTH_TEST_INITIAL_TIME],
  );
  await database.query(
    `INSERT INTO devices (id, user_id, device_name, device_type)
     VALUES ($1, $2, 'primary', 'app')`,
    [OAUTH_TEST_DEVICE_ID, OAUTH_TEST_USER_ID],
  );

  let time = new Date(OAUTH_TEST_INITIAL_TIME);
  const store = new SqlAuthStore(database);
  const app = createAuthenticatedApp(loadConfig({}), {
    store,
    jwtKeys: oauthTestJwtKeys,
    notifications: silentNotifications,
    authCodeHmacSecret: OAUTH_TEST_AUTH_CODE_SECRET,
    policyVersion: OAUTH_TEST_POLICY_VERSION,
    serviceOptions: { now: () => new Date(time) },
  }, silentLogger);
  const token = issueAccessToken(oauthTestJwtKeys, OAUTH_TEST_USER_ID, OAUTH_TEST_DEVICE_ID, OAUTH_TEST_INITIAL_TIME);
  const harness: OAuthHarness = {
    database,
    store,
    app,
    token,
    userId: OAUTH_TEST_USER_ID,
    deviceId: OAUTH_TEST_DEVICE_ID,
    now(): Date {
      return new Date(time);
    },
    setNow(value: Date): void {
      time = new Date(value);
    },
    async consent(): Promise<Response> {
      return app.fetch(new Request('https://api.sealero.test/v1/auth/consent', {
        method: 'POST',
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ policy_version: OAUTH_TEST_POLICY_VERSION }),
      }));
    },
  };
  return harness;
}

export async function fetchApp(
  app: ReturnType<typeof createAuthenticatedApp>,
  method: 'GET' | 'POST',
  path: string,
  body?: unknown,
  extraHeaders: Record<string, string> = {},
): Promise<Response> {
  const isForm = typeof body === 'string';
  return app.fetch(new Request(`https://api.sealero.test${path}`, {
    method,
    headers: {
      ...extraHeaders,
      ...(body === undefined ? {} : { 'content-type': isForm ? 'application/x-www-form-urlencoded' : 'application/json' }),
    },
    ...(body === undefined ? {} : { body: isForm ? body : JSON.stringify(body) }),
  }));
}
