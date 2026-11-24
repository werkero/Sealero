import { generateKeyPairSync } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { createAuthenticatedApp } from '../auth/app.js';
import { issueAccessToken } from '../auth/jwt.js';
import type { JwtKeySet, PublicJwk } from '../auth/jwt.js';
import type { AuthNotification } from '../auth/types.js';
import { SqlAuthStore } from '../db/auth-store.js';
import { LocalPGliteAuthDatabase } from '../db/local-pglite-auth.js';
import { loadConfig } from '../config.js';
import type { VaultKeyRecord, VaultKeyWriteInput } from '../vault/types.js';
import { computeWrappingStateHash } from '../vault/key.js';

const USER_ID = '00000000-0000-4000-8000-000000000101';
const OTHER_USER_ID = '00000000-0000-4000-8000-000000000102';
const DEVICE_ID = '00000000-0000-4000-8000-000000000111';
const OTHER_DEVICE_ID = '00000000-0000-4000-8000-000000000121';
const POLICY_VERSION = 'test-policy-v1';
const NOW = new Date('2026-11-22T20:00:00.000Z');
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
  kid: 'vault-key-test-key',
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
  token(userId?: string, deviceId?: string): string;
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
    `INSERT INTO users (id, email, login_password_hash, email_verified_at) VALUES
       ($1, 'owner@example.test', 'test-hash', $3),
       ($2, 'other@example.test', 'test-hash', $3)`,
    [USER_ID, OTHER_USER_ID, NOW],
  );
  await database.query(
    `INSERT INTO devices (id, user_id, device_name, device_type, revoked_at) VALUES
       ($1, $3, 'primary', 'app', NULL),
       ($2, $4, 'other user device', 'app', NULL)`,
    [DEVICE_ID, OTHER_DEVICE_ID, USER_ID, OTHER_USER_ID],
  );
  await database.query(
    `INSERT INTO user_consents (user_id, policy_type, policy_version, consented_at)
     VALUES ($1, 'privacy', $2, $3), ($4, 'privacy', $2, $3)`,
    [USER_ID, POLICY_VERSION, NOW, OTHER_USER_ID],
  );

  const store = new SqlAuthStore(database);
  const app = createAuthenticatedApp(loadConfig({}), {
    store,
    jwtKeys,
    notifications,
    authCodeHmacSecret: 'vault-key-test-secret-long-enough-for-hmac-key',
    policyVersion: POLICY_VERSION,
    serviceOptions: { now: () => NOW },
  }, silentLogger);
  return {
    database,
    app,
    token(userId = USER_ID, deviceId = DEVICE_ID): string {
      return issueAccessToken(jwtKeys, userId, deviceId, NOW);
    },
  };
}

afterEach(async () => {
  await Promise.all(openDatabases.splice(0).map((database) => database.close()));
});

async function request(
  harness: Harness,
  method: 'GET' | 'POST',
  body?: unknown,
  token = harness.token(),
): Promise<Response> {
  return harness.app.fetch(new Request('https://api.sealero.test/v1/vault-key', {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  }));
}

function kdfParams(m: number, t: number): string {
  return JSON.stringify({ algorithm: 'argon2id', m, output_len: 32, p: 4, t });
}

function writeInput(
  overrides: Partial<VaultKeyWriteInput> = {},
): VaultKeyWriteInput {
  return {
    wrapped_dek: 'd3JhcHBlZC1kZWs=',
    nonce: 'bm9uY2U=',
    kdf_salt: 'c2FsdA==',
    kdf_params: kdfParams(65_536, 3),
    dek_version: 1,
    master_password_version: 1,
    expected_wrapping_state_hash: null,
    ...overrides,
  };
}

async function getRecord(harness: Harness): Promise<VaultKeyRecord & { wrapping_state_hash: string }> {
  const response = await request(harness, 'GET');
  expect(response.status).toBe(200);
  return await response.json() as VaultKeyRecord & { wrapping_state_hash: string };
}

async function createInitialRecord(harness: Harness): Promise<VaultKeyRecord & { wrapping_state_hash: string }> {
  const response = await request(harness, 'POST', writeInput());
  expect(response.status).toBe(200);
  return await response.json() as VaultKeyRecord & { wrapping_state_hash: string };
}

describe('authenticated vault-key API', () => {
  it('matches the published wrapping_state_hash test vector', () => {
    const record: VaultKeyRecord = {
      wrapped_dek: 'dGVzdA==',
      nonce: 'bm9uY2U=',
      kdf_salt: 'c2FsdA==',
      kdf_params: '{"algorithm":"argon2id","m":65536,"output_len":32,"p":4,"t":3}',
      dek_version: 1,
      master_password_version: 1,
    };
    expect(computeWrappingStateHash('00000000-0000-0000-0000-000000000001', record))
      .toBe('aeacc33ca28ec65244895a53e2c1797fb962eac439ab3be2485e9e01dc30c145');
  });

  it('requires JWT, returns the specified missing-key error, and isolates keys by JWT subject', async () => {
    const harness = await createHarness();
    const unauthenticated = await request(harness, 'GET', undefined, '');
    expect(unauthenticated.status).toBe(401);

    const missing = await request(harness, 'GET');
    expect(missing.status).toBe(404);
    expect(await missing.json()).toMatchObject({ code: 'vault_key_not_found' });

    await createInitialRecord(harness);
    const foreign = await request(harness, 'GET', undefined, harness.token(OTHER_USER_ID, OTHER_DEVICE_ID));
    expect(foreign.status).toBe(404);
    expect(await foreign.json()).toMatchObject({ code: 'vault_key_not_found' });
  });

  it('creates the first P0 wrapper and returns the server-computed hash on POST and GET', async () => {
    const harness = await createHarness();
    const created = await createInitialRecord(harness);
    expect(created).toMatchObject({
      wrapped_dek: 'd3JhcHBlZC1kZWs=',
      dek_version: 1,
      master_password_version: 1,
      wrapping_state_hash: computeWrappingStateHash(USER_ID, writeInput()),
    });
    expect(await getRecord(harness)).toEqual(created);

    const count = await harness.database.query<{ count: string }>(
      'SELECT COUNT(*)::text AS count FROM dek_wrappings WHERE user_id = $1', [USER_ID],
    );
    expect(count.rows[0]?.count).toBe('1');
  });

  it('rejects invalid canonical JSON, empty or malformed CAS hashes, and non-whitelisted KDF tiers', async () => {
    const harness = await createHarness();
    const nonCanonical = await request(harness, 'POST', writeInput({
      kdf_params: '{ "algorithm":"argon2id", "m":65536, "output_len":32, "p":4, "t":3 }',
    }));
    expect(nonCanonical.status).toBe(400);
    expect(await nonCanonical.json()).toMatchObject({ code: 'invalid_request' });

    const malformedHash = await request(harness, 'POST', writeInput({ expected_wrapping_state_hash: 'not-a-hash' }));
    expect(malformedHash.status).toBe(400);
    const emptyHash = await request(harness, 'POST', writeInput({ expected_wrapping_state_hash: '' }));
    expect(emptyHash.status).toBe(400);
    expect(await emptyHash.json()).toMatchObject({ code: 'invalid_request' });

    const unsupported = await request(harness, 'POST', writeInput({ kdf_params: kdfParams(65_536, 4) }));
    expect(unsupported.status).toBe(409);
    expect(await unsupported.json()).toMatchObject({ code: 'vault_key_conflict' });

    const missingExpectedHash = await request(harness, 'POST', writeInput({ expected_wrapping_state_hash: 'a'.repeat(64) }));
    expect(missingExpectedHash.status).toBe(409);
    const missingRow = await harness.database.query<{ count: string }>(
      'SELECT COUNT(*)::text AS count FROM dek_wrappings WHERE user_id = $1', [USER_ID],
    );
    expect(missingRow.rows[0]?.count).toBe('0');
  });

  it('allows a same-version KDF upgrade but rejects stale hashes, regressions, and non-advancing writes', async () => {
    const harness = await createHarness();
    const initial = await createInitialRecord(harness);
    const upgraded = await request(harness, 'POST', writeInput({
      wrapped_dek: 'cG0xLXdyYXBwZWQ=',
      kdf_salt: 'cG0xLXNhbHQ=',
      kdf_params: kdfParams(131_072, 3),
      expected_wrapping_state_hash: initial.wrapping_state_hash,
    }));
    expect(upgraded.status).toBe(200);
    const current = await upgraded.json() as VaultKeyRecord & { wrapping_state_hash: string };
    expect(current.kdf_params).toBe(kdfParams(131_072, 3));

    const stale = await request(harness, 'POST', writeInput({
      dek_version: 2,
      expected_wrapping_state_hash: initial.wrapping_state_hash,
    }));
    expect(stale.status).toBe(409);

    const regression = await request(harness, 'POST', writeInput({
      dek_version: 0,
      expected_wrapping_state_hash: current.wrapping_state_hash,
    }));
    expect(regression.status).toBe(409);

    const staleVersion = await request(harness, 'POST', writeInput({
      dek_version: 1,
      master_password_version: 1,
      kdf_params: kdfParams(131_072, 3),
      expected_wrapping_state_hash: current.wrapping_state_hash,
    }));
    expect(staleVersion.status).toBe(409);

    const downgrade = await request(harness, 'POST', writeInput({
      dek_version: 2,
      kdf_params: kdfParams(65_536, 3),
      expected_wrapping_state_hash: current.wrapping_state_hash,
    }));
    expect(downgrade.status).toBe(409);
  });

  it('fails closed for P3 because no global P3 setting is defined in the published settings contract', async () => {
    const harness = await createHarness();
    const p3 = await request(harness, 'POST', writeInput({ kdf_params: kdfParams(262_144, 4) }));
    expect(p3.status).toBe(409);
    expect(await p3.json()).toMatchObject({ code: 'vault_key_conflict' });
    const row = await harness.database.query<{ count: string }>(
      'SELECT COUNT(*)::text AS count FROM dek_wrappings WHERE user_id = $1', [USER_ID],
    );
    expect(row.rows[0]?.count).toBe('0');
  });

  it('uses an atomic row-lock CAS so only one concurrent write with a shared expected hash succeeds', async () => {
    const harness = await createHarness();
    const initial = await createInitialRecord(harness);
    const [first, second] = await Promise.all([
      request(harness, 'POST', writeInput({
        kdf_params: kdfParams(131_072, 3),
        expected_wrapping_state_hash: initial.wrapping_state_hash,
      })),
      request(harness, 'POST', writeInput({
        kdf_params: kdfParams(131_072, 4),
        expected_wrapping_state_hash: initial.wrapping_state_hash,
      })),
    ]);
    expect([first.status, second.status].sort()).toEqual([200, 409]);
    const final = await getRecord(harness);
    expect([kdfParams(131_072, 3), kdfParams(131_072, 4)]).toContain(final.kdf_params);
  });

  it('applies the existing email-verification gate to vault-key access', async () => {
    const harness = await createHarness();
    await harness.database.query(
      "UPDATE users SET email_verified_at = NULL WHERE id = $1", [USER_ID],
    );
    await harness.database.query(
      "INSERT INTO server_settings (key, value) VALUES ('require_email_verification', 'true')",
    );
    const response = await request(harness, 'GET');
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ code: 'email_verification_required' });
  });
});
