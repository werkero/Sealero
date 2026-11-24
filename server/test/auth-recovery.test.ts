import { createHmac, generateKeyPairSync } from 'node:crypto';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

// PGlite harness creation takes 3-9s on the 1.5-CPU sandbox; the 5s default flakes.
vi.setConfig({ testTimeout: 30_000 });
import { Hono } from 'hono';
import { createAuthenticatedApp } from '../auth/app.js';
import type { JwtKeySet, PublicJwk } from '../auth/jwt.js';
import type { AuthNotification, LoginRequestMetadata } from '../auth/types.js';
import { AuthService } from '../auth/auth-service.js';
import { hashLoginPassword } from '../auth/password.js';
import { SqlAuthStore } from '../db/auth-store.js';
import { LocalPGliteAuthDatabase as PGliteAuthDatabase } from '../db/local-pglite-auth.js';
import { loadConfig } from '../config.js';
import type { AuthenticatedEnvironment } from '../middleware/authentication.js';

const TEST_PASSWORD = 'test-login-password-234';
const NEW_PASSWORD = 'new-test-login-password-567';
const HMAC_SECRET = 'test-only-auth-code-hmac-secret-with-32-or-more-bytes';
const INITIAL_TIME = new Date('2026-11-22T00:00:00.000Z');
const USER_ID = '00000000-0000-4000-8000-000000000101';
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
  kid: 'auth-recovery-test-kid',
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

interface RecoveryHarness {
  readonly database: PGliteAuthDatabase;
  readonly store: SqlAuthStore;
  readonly service: AuthService;
  readonly app: Hono;
  readonly verificationEmails: DeliveredCode[];
  readonly resetEmails: DeliveredCode[];
  readonly delays: number[];
  setNow(value: Date): void;
  now(): Date;
}

let passwordHash = '';
const openDatabases: PGliteAuthDatabase[] = [];

beforeAll(async () => {
  passwordHash = await hashLoginPassword(TEST_PASSWORD);
});

afterEach(async () => {
  await Promise.all(openDatabases.splice(0).map((database) => database.close()));
});

async function createHarness(verificationEnabled = true): Promise<RecoveryHarness> {
  const database = await PGliteAuthDatabase.create();
  openDatabases.push(database);
  await database.query(
    "INSERT INTO server_settings (key, value) VALUES ('require_email_verification', $1)",
    [verificationEnabled ? 'true' : 'false'],
  );
  const store = new SqlAuthStore(database);
  let time = new Date(INITIAL_TIME);
  const verificationEmails: DeliveredCode[] = [];
  const resetEmails: DeliveredCode[] = [];
  const delays: number[] = [];
  const notifications: AuthNotification = {
    async sendVerificationCode(input): Promise<void> {
      verificationEmails.push(input);
    },
    async sendPasswordResetCode(input): Promise<void> {
      resetEmails.push(input);
    },
    async sendDeleteAccountCode(): Promise<void> {},
    async sendNewDeviceLogin(): Promise<void> {},
    async sendRefreshReuseAlert(): Promise<void> {},
  };
  const now = (): Date => new Date(time);
  const service = new AuthService(store, jwtKeys, notifications, {
    authCodeHmacSecret: HMAC_SECRET,
    now,
    delayLoginFailure: async (milliseconds) => {
      delays.push(milliseconds);
    },
  });
  const app = createAuthenticatedApp(loadConfig({}), {
    store,
    jwtKeys,
    notifications,
    authCodeHmacSecret: HMAC_SECRET,
    serviceOptions: {
      now,
      delayLoginFailure: async (milliseconds) => {
        delays.push(milliseconds);
      },
    },
  }, silentLogger);

  return {
    database,
    store,
    service,
    app,
    verificationEmails,
    resetEmails,
    delays,
    setNow(value): void {
      time = new Date(value);
    },
    now,
  };
}

async function seedUser(
  harness: RecoveryHarness,
  email: string,
  id = USER_ID,
  hash = passwordHash,
): Promise<void> {
  await harness.database.query(
    `INSERT INTO users (id, email, login_password_hash, email_verified_at)
     VALUES ($1, $2, $3, $4)`,
    [id, email, hash, INITIAL_TIME],
  );
}

async function postJson(app: Hono, path: string, body: unknown): Promise<Response> {
  return app.fetch(new Request(`https://api.sealero.test${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  }));
}

function codeHash(purpose: 'verify' | 'reset', email: string, code: string): string {
  return createHmac('sha256', HMAC_SECRET)
    .update(purpose, 'utf8')
    .update('\0', 'utf8')
    .update(email, 'utf8')
    .update('\0', 'utf8')
    .update(code, 'utf8')
    .digest('hex');
}

const recoveryMetadata: LoginRequestMetadata = {
  ipAddress: '192.0.2.91',
  userAgent: 'auth-recovery-test/1.0',
};

describe('email verification and password recovery', () => {
  it('stores only HMACs, verifies a registration code once, and rejects replay', async () => {
    const harness = await createHarness(true);
    const registration = await postJson(harness.app, '/v1/auth/register', {
      email: 'Tai@Example.test',
      login_password: TEST_PASSWORD,
    });
    expect(registration.status).toBe(202);
    expect(harness.verificationEmails).toHaveLength(1);
    const delivered = harness.verificationEmails[0]!;
    expect(delivered.email).toBe('tai@example.test');
    expect(delivered.code).toMatch(/^\d{6}$/);
    expect(delivered.expiresAt.getTime()).toBe(INITIAL_TIME.getTime() + 15 * 60_000);

    const stored = await harness.database.query<{
      email: string;
      code_hash: string;
      purpose: string;
      expires_at: Date | string;
      used_at: Date | string | null;
    }>('SELECT email, code_hash, purpose, expires_at, used_at FROM auth_codes');
    expect(stored.rows).toHaveLength(1);
    expect(stored.rows[0]?.email).toBe('tai@example.test');
    expect(stored.rows[0]?.purpose).toBe('verify');
    expect(stored.rows[0]?.code_hash).toBe(codeHash('verify', 'tai@example.test', delivered.code));
    expect(stored.rows[0]?.code_hash).not.toBe(delivered.code);

    const verified = await postJson(harness.app, '/v1/auth/verify-email', {
      email: 'TAI@example.test',
      code: delivered.code,
    });
    expect(verified.status).toBe(200);
    expect(await verified.json()).toMatchObject({ code: 'email_verified' });
    const user = await harness.database.query<{ email_verified_at: Date | string | null }>(
      'SELECT email_verified_at FROM users WHERE email = $1', ['tai@example.test'],
    );
    expect(user.rows[0]?.email_verified_at).not.toBeNull();

    const replay = await postJson(harness.app, '/v1/auth/verify-email', {
      email: 'tai@example.test',
      code: delivered.code,
    });
    expect(replay.status).toBe(400);
    expect(await replay.json()).toMatchObject({ code: 'invalid_auth_code' });
    const reused = await harness.database.query<{ used_at: Date | string | null }>(
      'SELECT used_at FROM auth_codes',
    );
    expect(reused.rows[0]?.used_at).not.toBeNull();
  });

  it('invalidates a prior verification code after the 60-second resend interval', async () => {
    const harness = await createHarness(true);
    await postJson(harness.app, '/v1/auth/register', { email: 'resend@example.test', login_password: TEST_PASSWORD });
    const first = harness.verificationEmails[0]!;

    harness.setNow(new Date(INITIAL_TIME.getTime() + 59_999));
    const cooling = await postJson(harness.app, '/v1/auth/resend-verification', { email: 'resend@example.test' });
    expect(cooling.status).toBe(202);
    expect(await cooling.json()).toEqual({
      code: 'verification_code_requested',
      message: 'If the account is eligible, a verification email will be sent.',
    });
    expect(harness.verificationEmails).toHaveLength(1);

    harness.setNow(new Date(INITIAL_TIME.getTime() + 60_000));
    const resent = await postJson(harness.app, '/v1/auth/resend-verification', { email: 'resend@example.test' });
    expect(resent.status).toBe(202);
    expect(harness.verificationEmails).toHaveLength(2);
    const second = harness.verificationEmails[1]!;
    expect(second.code).not.toBe(first.code);

    const rows = await harness.database.query<{ code_hash: string; used_at: Date | string | null }>(
      "SELECT code_hash, used_at FROM auth_codes WHERE email = $1 AND purpose = 'verify' ORDER BY created_at, id",
      ['resend@example.test'],
    );
    expect(rows.rows).toHaveLength(2);
    expect(rows.rows[0]?.used_at).not.toBeNull();
    expect(rows.rows[1]?.used_at).toBeNull();

    const oldCode = await postJson(harness.app, '/v1/auth/verify-email', {
      email: 'resend@example.test',
      code: first.code,
    });
    expect(oldCode.status).toBe(400);
    const newCode = await postJson(harness.app, '/v1/auth/verify-email', {
      email: 'resend@example.test',
      code: second.code,
    });
    expect(newCode.status).toBe(200);
  });

  it('expires verification and reset codes at their specified 15- and 30-minute boundaries', async () => {
    const verifyHarness = await createHarness(true);
    await postJson(verifyHarness.app, '/v1/auth/register', { email: 'expire-verify@example.test', login_password: TEST_PASSWORD });
    const verifyCode = verifyHarness.verificationEmails[0]!.code;
    verifyHarness.setNow(new Date(INITIAL_TIME.getTime() + 15 * 60_000));
    const verifyExpired = await postJson(verifyHarness.app, '/v1/auth/verify-email', {
      email: 'expire-verify@example.test',
      code: verifyCode,
    });
    expect(verifyExpired.status).toBe(400);
    expect(await verifyExpired.json()).toMatchObject({ code: 'invalid_auth_code' });

    const resetHarness = await createHarness(true);
    await seedUser(resetHarness, 'expire-reset@example.test');
    await resetHarness.service.forgotPassword('expire-reset@example.test', recoveryMetadata);
    expect(resetHarness.resetEmails[0]?.expiresAt.getTime()).toBe(INITIAL_TIME.getTime() + 30 * 60_000);
    const resetCode = resetHarness.resetEmails[0]!.code;
    resetHarness.setNow(new Date(INITIAL_TIME.getTime() + 30 * 60_000));
    const resetExpired = await postJson(resetHarness.app, '/v1/auth/reset-password', {
      email: 'expire-reset@example.test',
      code: resetCode,
      new_login_password: NEW_PASSWORD,
    });
    expect(resetExpired.status).toBe(400);
    expect(await resetExpired.json()).toMatchObject({ code: 'invalid_auth_code' });
  }, 30_000);

  it('invalidates each code after five wrong attempts', async () => {
    const harness = await createHarness(true);
    await postJson(harness.app, '/v1/auth/register', { email: 'attempts@example.test', login_password: TEST_PASSWORD });
    const correct = harness.verificationEmails[0]!.code;

    for (let attempt = 0; attempt < 5; attempt += 1) {
      const response = await postJson(harness.app, '/v1/auth/verify-email', {
        email: 'attempts@example.test',
        code: correct === '000000' ? '000001' : '000000',
      });
      expect(response.status).toBe(400);
    }
    const failed = await harness.database.query<{ attempts: number; used_at: Date | string | null }>(
      'SELECT attempts, used_at FROM auth_codes',
    );
    expect(failed.rows[0]?.attempts).toBe(5);
    expect(failed.rows[0]?.used_at).not.toBeNull();

    const correctAfterLockout = await postJson(harness.app, '/v1/auth/verify-email', {
      email: 'attempts@example.test',
      code: correct,
    });
    expect(correctAfterLockout.status).toBe(400);
  });

  it('returns identical forgot-password responses for known, unknown, cooldown and email-failure cases', async () => {
    const harness = await createHarness(true);
    await seedUser(harness, 'known@example.test');
    const known = await harness.service.forgotPassword('known@example.test', recoveryMetadata);
    const unknown = await harness.service.forgotPassword('missing@example.test', recoveryMetadata);
    const cooldown = await harness.service.forgotPassword('known@example.test', recoveryMetadata);
    expect(known).toEqual(unknown);
    expect(known).toEqual(cooldown);
    expect(harness.resetEmails).toHaveLength(1);

    harness.setNow(new Date(INITIAL_TIME.getTime() + 61_000));
    const failingMailerService = new AuthService(harness.store, jwtKeys, {
      async sendVerificationCode(): Promise<void> {},
      async sendPasswordResetCode(): Promise<void> { throw new Error('mailer failed'); },
      async sendDeleteAccountCode(): Promise<void> {},
      async sendNewDeviceLogin(): Promise<void> {},
      async sendRefreshReuseAlert(): Promise<void> {},
    }, {
      authCodeHmacSecret: HMAC_SECRET,
      now: harness.now,
      delayLoginFailure: async () => undefined,
    });
    const failedDelivery = await failingMailerService.forgotPassword('known@example.test', recoveryMetadata);
    expect(failedDelivery).toEqual(known);
    const saved = await harness.database.query<{ code_hash: string; used_at: Date | string | null }>(
      "SELECT code_hash, used_at FROM auth_codes WHERE email = 'known@example.test' AND purpose = 'reset'",
    );
    expect(saved.rows).toHaveLength(1);
    expect(saved.rows[0]?.code_hash).toBe(codeHash('reset', 'known@example.test', harness.resetEmails[0]!.code));
    expect(saved.rows[0]?.used_at).toBeNull();
  }, 30_000);

  it('enforces the database-backed 3-per-hour/email and 10-per-hour/IP recovery limits', async () => {
    const emailHarness = await createHarness(true);
    await seedUser(emailHarness, 'email-limit@example.test');
    const sentAt: number[] = [];
    for (let request = 0; request < 3; request += 1) {
      emailHarness.setNow(new Date(INITIAL_TIME.getTime() + request * 61_000));
      await emailHarness.service.forgotPassword('email-limit@example.test', recoveryMetadata);
      sentAt.push(emailHarness.resetEmails.length);
    }
    emailHarness.setNow(new Date(INITIAL_TIME.getTime() + 3 * 61_000));
    await expect(emailHarness.service.forgotPassword('email-limit@example.test', recoveryMetadata))
      .rejects.toMatchObject({ status: 429, code: 'rate_limited', retryAfterSeconds: 3417 });
    sentAt.push(emailHarness.resetEmails.length);
    expect(sentAt).toEqual([1, 2, 3, 3]);
    const emailCounters = await emailHarness.database.query<{ count: number }>(
      "SELECT count FROM rate_limits WHERE scope = 'password_recovery_email'",
    );
    expect(emailCounters.rows[0]?.count).toBe(4);

    const ipHarness = await createHarness(true);
    await seedUser(ipHarness, 'ip-limit-target@example.test');
    for (let request = 0; request < 10; request += 1) {
      await ipHarness.service.forgotPassword(`unknown-${request}@example.test`, recoveryMetadata);
    }
    await expect(ipHarness.service.forgotPassword('ip-limit-target@example.test', recoveryMetadata))
      .rejects.toMatchObject({ status: 429, code: 'rate_limited', retryAfterSeconds: 3600 });
    expect(ipHarness.resetEmails).toHaveLength(0);
    const ipCounters = await ipHarness.database.query<{ count: number }>(
      "SELECT count FROM rate_limits WHERE scope = 'password_recovery_ip'",
    );
    expect(ipCounters.rows[0]?.count).toBe(11);
  }, 30_000);

  it('resets the login password atomically and revokes devices, refresh tokens, OAuth grants and old access JWTs', async () => {
    const harness = await createHarness(true);
    await seedUser(harness, 'reset-all@example.test');
    const loginOne = await harness.service.login({
      email: 'reset-all@example.test',
      loginPassword: TEST_PASSWORD,
      deviceName: 'desktop',
      deviceType: 'app',
    }, recoveryMetadata);
    await harness.service.login({
      email: 'reset-all@example.test',
      loginPassword: TEST_PASSWORD,
      deviceName: 'phone',
      deviceType: 'app',
    }, recoveryMetadata);
    await harness.database.query(
      `INSERT INTO oauth_authorizations
       (user_id, client_id, redirect_uri, scopes, access_token_hash, refresh_token_hash, expires_at, refresh_expires_at)
       VALUES ($1, 'test-client', 'https://client.example/callback', 'mcp:read', 'access-hash', 'refresh-hash', $2, $3)`,
      [USER_ID, new Date(INITIAL_TIME.getTime() + 60_000), new Date(INITIAL_TIME.getTime() + 60_000)],
    );
    await harness.service.forgotPassword('reset-all@example.test', recoveryMetadata);
    const delivered = harness.resetEmails[0]!;

    const reset = await postJson(harness.app, '/v1/auth/reset-password', {
      email: 'reset-all@example.test',
      code: delivered.code,
      new_login_password: NEW_PASSWORD,
    });
    expect(reset.status).toBe(200);
    expect(await reset.json()).toMatchObject({ code: 'password_reset' });

    const revokedDevices = await harness.database.query<{ count: string }>(
      'SELECT COUNT(*)::text AS count FROM devices WHERE user_id = $1 AND revoked_at IS NOT NULL', [USER_ID],
    );
    const revokedRefresh = await harness.database.query<{ count: string; reasons: string[] }>(
      `SELECT COUNT(*)::text AS count, array_agg(DISTINCT revoked_reason) AS reasons
       FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NOT NULL`, [USER_ID],
    );
    const revokedOauth = await harness.database.query<{ count: string }>(
      'SELECT COUNT(*)::text AS count FROM oauth_authorizations WHERE user_id = $1 AND revoked_at IS NOT NULL', [USER_ID],
    );
    expect(revokedDevices.rows[0]?.count).toBe('2');
    expect(revokedRefresh.rows[0]?.count).toBe('2');
    expect(revokedRefresh.rows[0]?.reasons).toEqual(['password_changed']);
    expect(revokedOauth.rows[0]?.count).toBe('1');

    const protectedRoutes = new Hono<AuthenticatedEnvironment>();
    protectedRoutes.get('/probe', (context) => context.json({ subject: context.get('auth').sub }));
    const protectedApp = createAuthenticatedApp(loadConfig({}), {
      store: harness.store,
      jwtKeys,
      notifications: {
        async sendVerificationCode(): Promise<void> {},
        async sendPasswordResetCode(): Promise<void> {},
        async sendDeleteAccountCode(): Promise<void> {},
        async sendNewDeviceLogin(): Promise<void> {},
        async sendRefreshReuseAlert(): Promise<void> {},
      },
      authCodeHmacSecret: HMAC_SECRET,
      serviceOptions: { now: harness.now, delayLoginFailure: async () => undefined },
      protectedRoutes,
    }, silentLogger);
    const oldAccess = await protectedApp.fetch(new Request('https://api.sealero.test/v1/probe', {
      headers: { authorization: `Bearer ${loginOne.access_token}` },
    }));
    expect(oldAccess.status).toBe(401);
    expect(await oldAccess.json()).toMatchObject({ code: 'device_revoked' });

    await expect(harness.service.login({
      email: 'reset-all@example.test',
      loginPassword: TEST_PASSWORD,
      deviceName: 'old credentials',
      deviceType: 'app',
    }, recoveryMetadata)).rejects.toMatchObject({ status: 401 });
    const newLogin = await harness.service.login({
      email: 'reset-all@example.test',
      loginPassword: NEW_PASSWORD,
      deviceName: 'new credentials',
      deviceType: 'app',
    }, recoveryMetadata);
    expect(newLogin.access_token).toBeTruthy();
  });

  it('returns the specified disabled errors without consuming recovery codes and registers as verified', async () => {
    const harness = await createHarness(false);
    const email = 'disabled@example.test';
    const code = '042817';
    await seedUser(harness, email);
    await harness.database.query(
      `INSERT INTO auth_codes (email, code_hash, purpose, expires_at, created_at)
       VALUES ($1, $2, 'reset', $3, $4)`,
      [email, codeHash('reset', email, code), new Date(INITIAL_TIME.getTime() + 30 * 60_000), INITIAL_TIME],
    );

    const verification = await postJson(harness.app, '/v1/auth/verify-email', { email, code });
    const resend = await postJson(harness.app, '/v1/auth/resend-verification', { email });
    const forgot = await postJson(harness.app, '/v1/auth/forgot-password', { email });
    const reset = await postJson(harness.app, '/v1/auth/reset-password', {
      email,
      code,
      new_login_password: NEW_PASSWORD,
    });
    expect(verification.status).toBe(400);
    expect(await verification.json()).toMatchObject({ code: 'email_verification_disabled' });
    expect(resend.status).toBe(400);
    expect(await resend.json()).toMatchObject({ code: 'email_verification_disabled' });
    expect(forgot.status).toBe(400);
    expect(await forgot.json()).toMatchObject({ code: 'password_recovery_disabled' });
    expect(reset.status).toBe(400);
    expect(await reset.json()).toMatchObject({ code: 'password_recovery_disabled' });

    const unchanged = await harness.database.query<{ used_at: Date | string | null }>(
      'SELECT used_at FROM auth_codes WHERE email = $1', [email],
    );
    expect(unchanged.rows[0]?.used_at).toBeNull();
    expect(harness.resetEmails).toHaveLength(0);

    const registration = await postJson(harness.app, '/v1/auth/register', {
      email: 'auto-verified@example.test',
      login_password: TEST_PASSWORD,
    });
    expect(registration.status).toBe(202);
    const autoVerified = await harness.database.query<{ email_verified_at: Date | string | null }>(
      'SELECT email_verified_at FROM users WHERE email = $1', ['auto-verified@example.test'],
    );
    expect(autoVerified.rows[0]?.email_verified_at).not.toBeNull();
    expect(harness.verificationEmails).toHaveLength(0);
  });

  it('allows only one concurrent successful verification-code consumption', async () => {
    const harness = await createHarness(true);
    await postJson(harness.app, '/v1/auth/register', { email: 'parallel@example.test', login_password: TEST_PASSWORD });
    const code = harness.verificationEmails[0]!.code;
    const body = { email: 'parallel@example.test', code };
    const outcomes = await Promise.all([
      postJson(harness.app, '/v1/auth/verify-email', body),
      postJson(harness.app, '/v1/auth/verify-email', body),
    ]);
    expect(outcomes.map((response) => response.status).sort()).toEqual([200, 400]);
    const used = await harness.database.query<{ count: string }>(
      "SELECT COUNT(*)::text AS count FROM auth_codes WHERE email = $1 AND used_at IS NOT NULL",
      ['parallel@example.test'],
    );
    expect(used.rows[0]?.count).toBe('1');
  });

  it('persists login failure limits and bounded delays, then allows login when the window expires', async () => {
    const harness = await createHarness(true);
    await seedUser(harness, 'login-limit@example.test');
    const concurrentAttempts = await Promise.allSettled(Array.from({ length: 11 }, () =>
      harness.service.login({
        email: 'login-limit@example.test',
        loginPassword: 'wrong-login-password',
        deviceName: 'brute-force-test',
        deviceType: 'app',
      }, recoveryMetadata)));
    expect(concurrentAttempts.every((attempt) => attempt.status === 'rejected')).toBe(true);
    expect(harness.delays).toContain(100);
    expect(harness.delays).toContain(200);
    expect(harness.delays).toContain(3_200);

    const persisted = await harness.database.query<{ count: number }>(
      "SELECT count FROM rate_limits WHERE scope = 'login_email'",
    );
    expect(persisted.rows[0]?.count).toBe(11);
    const outcomes = await harness.database.query<{ failure_code: string; count: string }>(
      `SELECT failure_code, COUNT(*)::text AS count FROM login_logs
       WHERE user_id = $1 AND result = 'failed' GROUP BY failure_code`, [USER_ID],
    );
    expect(outcomes.rows).toContainEqual({ failure_code: 'wrong_password', count: '10' });
    expect(outcomes.rows).toContainEqual({ failure_code: 'rate_limited', count: '1' });

    const restartedService = new AuthService(harness.store, jwtKeys, {
      async sendVerificationCode(): Promise<void> {},
      async sendPasswordResetCode(): Promise<void> {},
      async sendDeleteAccountCode(): Promise<void> {},
      async sendNewDeviceLogin(): Promise<void> {},
      async sendRefreshReuseAlert(): Promise<void> {},
    }, {
      authCodeHmacSecret: HMAC_SECRET,
      now: harness.now,
      delayLoginFailure: async (milliseconds) => {
        harness.delays.push(milliseconds);
      },
    });
    await expect(restartedService.login({
      email: 'login-limit@example.test',
      loginPassword: TEST_PASSWORD,
      deviceName: 'still-limited',
      deviceType: 'app',
    }, recoveryMetadata)).rejects.toMatchObject({ status: 429, code: 'rate_limited', retryAfterSeconds: 900 });

    harness.setNow(new Date(INITIAL_TIME.getTime() + 15 * 60_000));
    const allowed = await restartedService.login({
      email: 'login-limit@example.test',
      loginPassword: TEST_PASSWORD,
      deviceName: 'window-expired',
      deviceType: 'app',
    }, recoveryMetadata);
    expect(allowed.access_token).toBeTruthy();
  }, 30_000);

  it('returns 429 rate_limited with a Retry-After header when login is rate limited over HTTP', async () => {
    const harness = await createHarness(true);
    await seedUser(harness, 'login-http-limit@example.test');
    let last: Response | null = null;
    for (let attempt = 0; attempt < 11; attempt += 1) {
      last = await postJson(harness.app, '/v1/auth/login', {
        email: 'login-http-limit@example.test',
        login_password: 'wrong-login-password',
        device_name: 'brute-force-test',
        device_type: 'app',
      });
    }
    expect(last?.status).toBe(429);
    expect(await last?.json()).toMatchObject({ code: 'rate_limited' });
    expect(last?.headers.get('retry-after')).toBe('900');
  }, 30_000);

  it('returns 429 rate_limited with a Retry-After header when password recovery is rate limited over HTTP', async () => {
    const harness = await createHarness(true);
    await seedUser(harness, 'recovery-http-limit@example.test');
    const statuses: number[] = [];
    for (let request = 0; request < 4; request += 1) {
      const response = await postJson(harness.app, '/v1/auth/forgot-password', {
        email: 'recovery-http-limit@example.test',
      });
      statuses.push(response.status);
      if (request === 3) {
        expect(await response.json()).toMatchObject({ code: 'rate_limited' });
        expect(response.headers.get('retry-after')).toBe('3600');
      }
    }
    expect(statuses).toEqual([202, 202, 202, 429]);
    expect(harness.resetEmails).toHaveLength(1);
  }, 30_000);

  it('rejects a reset password shorter than 8 characters with invalid_login_password', async () => {
    const harness = await createHarness(true);
    const reset = await postJson(harness.app, '/v1/auth/reset-password', {
      email: 'reset-short@example.test',
      code: '000000',
      new_login_password: 'short12',
    });
    expect(reset.status).toBe(400);
    expect(await reset.json()).toMatchObject({ code: 'invalid_login_password' });
  });
});
