import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * Exercises the Vercel entry point (`api/index.ts`) without any network:
 * the deployment app is built against a fake database URL that is never
 * contacted (the Neon pool connects lazily), and a throwaway JWT key pair.
 * The production private key is never used here.
 */
const DEPLOYMENT_ENV_KEYS = [
  'DATABASE_URL',
  'POSTGRES_URL',
  'JWT_PRIVATE_KEY',
  'JWT_PRIVATE_KEY_PATH',
  'JWT_PUBLIC_KEY_PATH',
  'JWT_ACTIVE_KID',
  'JWT_ISSUER',
  'AUTH_CODE_HMAC_SECRET',
  'DB_DUMP_KEY',
  'TOMBSTONE_CLEANUP_SECRET',
  'SMTP_HOST',
  'SMTP_PORT',
  'SMTP_USER',
  'SMTP_PASS',
  'SMTP_FROM',
  'SMTP_SECURE',
] as const;

let savedEnv: Record<string, string | undefined> = {};

beforeEach(() => {
  savedEnv = {};
  for (const key of DEPLOYMENT_ENV_KEYS) {
    savedEnv[key] = process.env[key];
    delete process.env[key];
  }
  vi.resetModules();
});

afterEach(() => {
  for (const key of DEPLOYMENT_ENV_KEYS) {
    const value = savedEnv[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  vi.resetModules();
});

async function importEntry(): Promise<{ default: { request: (url: string, init?: RequestInit) => Promise<Response> } }> {
  return (await import('../../api/index.js')) as unknown as {
    default: { request: (url: string, init?: RequestInit) => Promise<Response> };
  };
}

describe('deployment entry point', () => {
  it('fails closed (health only) when deployment env is missing', async () => {
    const { default: app } = await importEntry();
    const health = await app.request('https://sealero.vercel.app/v1/health');
    expect(health.status).toBe(200);
    const healthBody = await health.json() as Record<string, unknown>;
    expect(healthBody['api_version']).toBe('v1');
    expect(healthBody['policy_version']).toBeUndefined();
    const register = await app.request('https://sealero.vercel.app/v1/auth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'a@example.com', login_password: 'password-123' }),
    });
    expect(register.status).toBe(503);
    const registerBody = await register.json() as Record<string, unknown>;
    expect(registerBody['code']).toBe('auth_runtime_unavailable');
  });

  it('builds the real app and serves the bundled JWKS when env is present', async () => {
    const pair = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 0x10001 });
    const exported = pair.publicKey.export({ format: 'jwk' });
    if (typeof exported.n !== 'string' || typeof exported.e !== 'string') {
      throw new Error('Test key did not export RSA public parameters.');
    }
    const dir = mkdtempSync(join(tmpdir(), 'sealero-jwks-'));
    const jwksPath = join(dir, 'jwks.json');
    writeFileSync(jwksPath, JSON.stringify({
      keys: [{ kty: 'RSA', use: 'sig', alg: 'RS256', kid: 'test-key-1', n: exported.n, e: exported.e }],
    }));
    process.env['DATABASE_URL'] = 'postgresql://user:pass@localhost:5432/sealero';
    process.env['JWT_PRIVATE_KEY'] = pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    process.env['JWT_PUBLIC_KEY_PATH'] = jwksPath;
    process.env['JWT_ACTIVE_KID'] = 'test-key-1';
    process.env['JWT_ISSUER'] = 'https://sealero.vercel.app';
    process.env['AUTH_CODE_HMAC_SECRET'] = 'test-auth-code-hmac-secret-32-bytes!';
    process.env['DB_DUMP_KEY'] = randomBytes(32).toString('base64');
    process.env['TOMBSTONE_CLEANUP_SECRET'] = 'test-cleanup-secret';
    process.env['SMTP_HOST'] = 'smtp.resend.com';
    process.env['SMTP_PORT'] = '465';
    process.env['SMTP_USER'] = 'resend';
    process.env['SMTP_PASS'] = 're_test';
    process.env['SMTP_FROM'] = 'noreply@email.a1l.xyz';
    process.env['SMTP_SECURE'] = 'true';

    const { default: app } = await importEntry();

    // The bundled JWKS is served without touching the database.
    const jwks = await app.request('https://sealero.vercel.app/.well-known/jwks.json');
    expect(jwks.status).toBe(200);
    const jwksBody = await jwks.json() as { keys: Array<Record<string, unknown>> };
    expect(jwksBody.keys).toHaveLength(1);
    expect(jwksBody.keys[0]?.['kid']).toBe('test-key-1');
    expect(jwksBody.keys[0]?.['kty']).toBe('RSA');
    expect(jwksBody.keys[0]?.['alg']).toBe('RS256');

    // The real app is built, not the fail-closed placeholder: a business
    // route reaches the auth service (and fails here only because the test
    // database URL is fake), instead of answering 503 auth_runtime_unavailable.
    // /v1/health is not asserted here: it reads server_settings, so it needs
    // a live database.
    const register = await app.request('https://sealero.vercel.app/v1/auth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'a@example.com', login_password: 'password-123' }),
    });
    expect(register.status).toBe(500);
    const registerBody = await register.json() as Record<string, unknown>;
    expect(registerBody['code']).toBe('internal_error');
  });
});
