import { createHash, generateKeyPairSync } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { createAuthenticatedApp } from '../auth/app.js';
import type { JwtKeySet, PublicJwk } from '../auth/jwt.js';
import { issueAccessToken } from '../auth/jwt.js';
import type { AuthNotification } from '../auth/types.js';
import { SqlAuthStore } from '../db/auth-store.js';
import { LocalPGliteAuthDatabase } from '../db/local-pglite-auth.js';
import { loadConfig } from '../config.js';
import type { VaultPayload } from '../vault/types.js';

const USER_ID = '00000000-0000-4000-8000-000000000101';
const OTHER_USER_ID = '00000000-0000-4000-8000-000000000102';
const DEVICE_ID = '00000000-0000-4000-8000-000000000111';
const SECOND_DEVICE_ID = '00000000-0000-4000-8000-000000000112';
const OTHER_DEVICE_ID = '00000000-0000-4000-8000-000000000121';
const ITEM_ONE = '10000000-0000-4000-8000-000000000001';
const ITEM_TWO = '10000000-0000-4000-8000-000000000002';
const POLICY_VERSION = 'test-policy-v1';
const INITIAL_TIME = new Date('2026-11-22T00:00:00.000Z');
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
  kid: 'vault-test-key',
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
  readonly store: SqlAuthStore;
  readonly app: ReturnType<typeof createAuthenticatedApp>;
  readonly token: (userId?: string, deviceId?: string) => string;
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
    [USER_ID, OTHER_USER_ID, INITIAL_TIME],
  );
  await database.query(
    `INSERT INTO devices (id, user_id, device_name, device_type) VALUES
       ($1, $3, 'primary', 'app'),
       ($2, $3, 'secondary', 'web'),
       ($4, $5, 'other user device', 'app')`,
    [DEVICE_ID, SECOND_DEVICE_ID, USER_ID, OTHER_DEVICE_ID, OTHER_USER_ID],
  );
  await database.query(
    `INSERT INTO user_consents (user_id, policy_type, policy_version, consented_at)
     VALUES ($1, 'privacy', $2, $3), ($4, 'privacy', $2, $3)`,
    [USER_ID, POLICY_VERSION, INITIAL_TIME, OTHER_USER_ID],
  );
  await database.query(
    `INSERT INTO dek_wrappings
       (user_id, dek_version, wrapped_dek, nonce, kdf_salt, kdf_params, master_password_version)
     VALUES ($1, 4, 'wrapped-test', 'nonce-test', 'salt-test', '{}', 7),
            ($2, 1, 'wrapped-test-2', 'nonce-test-2', 'salt-test-2', '{}', 1)`,
    [USER_ID, OTHER_USER_ID],
  );
  const store = new SqlAuthStore(database);
  const app = createAuthenticatedApp(loadConfig({}), {
    store,
    jwtKeys,
    notifications,
    authCodeHmacSecret: 'vault-test-secret-long-enough-for-hmac-key',
    policyVersion: POLICY_VERSION,
    serviceOptions: { now: () => INITIAL_TIME },
  }, silentLogger);
  return {
    database,
    store,
    app,
    token(userId = USER_ID, deviceId = DEVICE_ID): string {
      return issueAccessToken(jwtKeys, userId, deviceId, INITIAL_TIME);
    },
  };
}

afterEach(async () => {
  await Promise.all(openDatabases.splice(0).map((database) => database.close()));
});

function payload(tag: string): VaultPayload {
  return {
    overview_ciphertext: `overview-${tag}`,
    overview_nonce: `overview-nonce-${tag}`,
    detail_ciphertext: `detail-${tag}`,
    detail_nonce: `detail-nonce-${tag}`,
    // SD §7.5: domain_hmac is a 64-character lowercase hex HMAC-SHA256;
    // the route rejects anything else, so derive a valid one per tag.
    domain_hmac: createHash('sha256').update(tag, 'utf8').digest('hex'),
  };
}

function authHeaders(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}`, 'content-type': 'application/json' };
}

async function request(
  harness: Harness,
  path: string,
  token = harness.token(),
  options: { readonly method?: string; readonly body?: unknown } = {},
): Promise<Response> {
  return harness.app.fetch(new Request(`https://api.sealero.test${path}`, {
    method: options.method ?? 'GET',
    headers: authHeaders(token),
    ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
  }));
}

function createBody(id: string, itemPayload: VaultPayload): Record<string, unknown> {
  return { id, base_version: 0, version: 1, ...itemPayload };
}

async function createItem(harness: Harness, id: string, itemPayload: VaultPayload, token?: string): Promise<Response> {
  return request(harness, '/v1/vault/items', token ?? harness.token(), {
    method: 'POST',
    body: createBody(id, itemPayload),
  });
}

async function rowCount(harness: Harness, id: string): Promise<number> {
  const result = await harness.database.query<{ count: string }>(
    'SELECT COUNT(*)::text AS count FROM vault_items WHERE id = $1', [id],
  );
  return Number(result.rows[0]?.count ?? '0');
}

describe('authenticated vault API', () => {
  it('requires a valid access JWT and enforces the configured email-verification gate', async () => {
    const harness = await createHarness();
    const unauthenticated = await harness.app.fetch(new Request('https://api.sealero.test/v1/vault/list'));
    expect(unauthenticated.status).toBe(401);

    await harness.database.query(
      'UPDATE users SET email_verified_at = NULL WHERE id = $1',
      [USER_ID],
    );
    await harness.database.query(
      "INSERT INTO server_settings (key, value) VALUES ('require_email_verification', 'true')",
    );
    const blocked = await request(harness, '/v1/vault/list');
    expect(blocked.status).toBe(403);
    expect(await blocked.json()).toMatchObject({ code: 'email_verification_required' });

    await harness.database.query('UPDATE users SET email_verified_at = $2 WHERE id = $1', [USER_ID, INITIAL_TIME]);
    const allowed = await request(harness, '/v1/vault/list');
    expect(allowed.status).toBe(200);
  });

  it('creates items and returns a full, ordered, active-only cursor-paginated list', async () => {
    const harness = await createHarness();
    const second = await createItem(harness, ITEM_TWO, payload('two'));
    const first = await createItem(harness, ITEM_ONE, payload('one'));
    expect(second.status).toBe(200);
    expect(first.status).toBe(200);

    const pageOneResponse = await request(harness, '/v1/vault/list?limit=1');
    expect(pageOneResponse.status).toBe(200);
    const pageOne = await pageOneResponse.json() as Record<string, unknown>;
    expect(pageOne).toMatchObject({
      items: [{ id: ITEM_ONE, version: 1, ...payload('one') }],
      has_more: true,
      next_cursor: ITEM_ONE,
      master_password_version: 7,
      dek_version: 4,
    });
    expect(pageOne['server_time']).toBe(INITIAL_TIME.toISOString());
    const firstItem = (pageOne['items'] as Array<Record<string, unknown>>)[0];
    expect(firstItem).toHaveProperty('updated_at');
    expect(firstItem).toHaveProperty('device_id', DEVICE_ID);

    const pageTwoResponse = await request(harness, `/v1/vault/list?cursor=${ITEM_ONE}&limit=1`);
    expect(pageTwoResponse.status).toBe(200);
    expect(await pageTwoResponse.json()).toMatchObject({
      items: [{ id: ITEM_TWO }],
      has_more: false,
      next_cursor: null,
    });

    const badLimit = await request(harness, '/v1/vault/list?limit=501');
    expect(badLimit.status).toBe(400);
    expect(await badLimit.json()).toMatchObject({ code: 'invalid_pagination' });
    const missingCursor = await request(harness, '/v1/vault/list?cursor=10000000-0000-4000-8000-000000000099');
    expect(missingCursor.status).toBe(400);
    expect(await missingCursor.json()).toMatchObject({ code: 'invalid_cursor' });
    const malformedCursor = await request(harness, '/v1/vault/list?cursor=not-a-uuid');
    expect(malformedCursor.status).toBe(400);
    expect(await malformedCursor.json()).toMatchObject({ code: 'invalid_cursor' });
  });

  it('replays an identical POST across devices, rejects changed payload, masks cross-user IDs, and never revives a tombstone', async () => {
    const harness = await createHarness();
    const itemPayload = payload('stable');
    expect((await createItem(harness, ITEM_ONE, itemPayload)).status).toBe(200);

    const crossDeviceReplay = await createItem(harness, ITEM_ONE, itemPayload, harness.token(USER_ID, SECOND_DEVICE_ID));
    expect(crossDeviceReplay.status).toBe(200);
    expect(await crossDeviceReplay.json()).toHaveProperty('version', 1);
    expect(await rowCount(harness, ITEM_ONE)).toBe(1);

    const changedRetry = await createItem(harness, ITEM_ONE, payload('changed'));
    expect(changedRetry.status).toBe(409);
    expect(await changedRetry.json()).toMatchObject({ code: 'item_payload_conflict' });

    const foreignIdConflict = await createItem(harness, ITEM_ONE, itemPayload, harness.token(OTHER_USER_ID, OTHER_DEVICE_ID));
    expect(foreignIdConflict.status).toBe(409);
    expect(await foreignIdConflict.json()).toMatchObject({ code: 'item_id_conflict' });

    const deletion = await request(harness, `/v1/vault/items/${ITEM_ONE}`, harness.token(), {
      method: 'DELETE',
      body: { base_version: 1 },
    });
    expect(deletion.status).toBe(200);
    const resurrect = await createItem(harness, ITEM_ONE, itemPayload);
    expect(resurrect.status).toBe(410);
    expect(await resurrect.json()).toMatchObject({ code: 'item_deleted' });
    expect(await rowCount(harness, ITEM_ONE)).toBe(1);
  });

  it('enforces PUT base/version rules, exact same-device replay, and tombstone responses', async () => {
    const harness = await createHarness();
    expect((await createItem(harness, ITEM_ONE, payload('before'))).status).toBe(200);
    const updatedPayload = payload('after');
    const updateBody = { base_version: 1, version: 2, ...updatedPayload };
    const firstUpdate = await request(harness, `/v1/vault/items/${ITEM_ONE}`, harness.token(), {
      method: 'PUT', body: updateBody,
    });
    expect(firstUpdate.status).toBe(200);
    expect(await firstUpdate.json()).toMatchObject({ id: ITEM_ONE, version: 2 });

    const replay = await request(harness, `/v1/vault/items/${ITEM_ONE}`, harness.token(), {
      method: 'PUT', body: updateBody,
    });
    expect(replay.status).toBe(200);
    expect(await replay.json()).toMatchObject({ version: 2 });

    const changedReplay = await request(harness, `/v1/vault/items/${ITEM_ONE}`, harness.token(), {
      method: 'PUT', body: { ...updateBody, ...payload('mismatch') },
    });
    expect(changedReplay.status).toBe(409);
    expect(await changedReplay.json()).toMatchObject({ code: 'already_applied_payload_mismatch' });

    const otherDeviceReplay = await request(harness, `/v1/vault/items/${ITEM_ONE}`, harness.token(USER_ID, SECOND_DEVICE_ID), {
      method: 'PUT', body: updateBody,
    });
    expect(otherDeviceReplay.status).toBe(409);
    expect(await otherDeviceReplay.json()).toMatchObject({ code: 'conflict' });

    const serverBehind = await request(harness, `/v1/vault/items/${ITEM_ONE}`, harness.token(), {
      method: 'PUT', body: { base_version: 3, version: 4, ...payload('ahead') },
    });
    expect(serverBehind.status).toBe(409);
    expect(await serverBehind.json()).toMatchObject({ code: 'server_behind' });

    const invalidVersionOrder = await request(harness, `/v1/vault/items/${ITEM_ONE}`, harness.token(), {
      method: 'PUT', body: { base_version: 2, version: 2, ...payload('same') },
    });
    expect(invalidVersionOrder.status).toBe(409);
    expect(await invalidVersionOrder.json()).toMatchObject({ code: 'conflict' });

    const status = await request(harness, `/v1/vault/items/${ITEM_ONE}/status`);
    const statusBody = await status.json();
    expect(statusBody).toMatchObject({ id: ITEM_ONE, status: 'active', version: 2, device_id: DEVICE_ID });
    expect(JSON.stringify(statusBody)).not.toContain('ciphertext');

    const deleteResponse = await request(harness, `/v1/vault/items/${ITEM_ONE}`, harness.token(), {
      method: 'DELETE', body: { base_version: 2 },
    });
    expect(deleteResponse.status).toBe(200);
    const deletedUpdate = await request(harness, `/v1/vault/items/${ITEM_ONE}`, harness.token(), {
      method: 'PUT', body: { base_version: 2, version: 3, ...payload('late') },
    });
    expect(deletedUpdate.status).toBe(410);
    const deletedStatus = await request(harness, `/v1/vault/items/${ITEM_ONE}/status`);
    expect(await deletedStatus.json()).toMatchObject({
      id: ITEM_ONE,
      status: 'deleted',
      version: 3,
      device_id: DEVICE_ID,
      deleted_at: expect.any(String),
    });
  });

  it('accepts DELETE retries only when version and deleting device match, and hides foreign IDs as 404', async () => {
    const harness = await createHarness();
    expect((await createItem(harness, ITEM_ONE, payload('delete-me'))).status).toBe(200);

    const firstDelete = await request(harness, `/v1/vault/items/${ITEM_ONE}`, harness.token(), {
      method: 'DELETE', body: { base_version: 1 },
    });
    expect(firstDelete.status).toBe(200);
    const replay = await request(harness, `/v1/vault/items/${ITEM_ONE}`, harness.token(), {
      method: 'DELETE', body: { base_version: 1 },
    });
    expect(replay.status).toBe(200);
    expect(await replay.json()).toMatchObject({ id: ITEM_ONE, version: 2 });

    const otherDeviceReplay = await request(harness, `/v1/vault/items/${ITEM_ONE}`, harness.token(USER_ID, SECOND_DEVICE_ID), {
      method: 'DELETE', body: { base_version: 1 },
    });
    expect(otherDeviceReplay.status).toBe(409);
    expect(await otherDeviceReplay.json()).toMatchObject({ code: 'conflict' });
    const wrongBase = await request(harness, `/v1/vault/items/${ITEM_ONE}`, harness.token(), {
      method: 'DELETE', body: { base_version: 2 },
    });
    expect(wrongBase.status).toBe(409);
    expect(await wrongBase.json()).toMatchObject({ code: 'conflict' });

    const foreignStatus = await request(harness, `/v1/vault/items/${ITEM_ONE}/status`, harness.token(OTHER_USER_ID, OTHER_DEVICE_ID));
    expect(foreignStatus.status).toBe(404);
    expect(await foreignStatus.json()).toMatchObject({ code: 'not_found' });
    const missingStatus = await request(harness, '/v1/vault/items/10000000-0000-4000-8000-000000000099/status');
    expect(missingStatus.status).toBe(404);
  });

  it('converts expired soft tombstones to minimal permanent tombstones without changing identity or version', async () => {
    const harness = await createHarness();
    expect((await createItem(harness, ITEM_ONE, payload('expire'))).status).toBe(200);
    const deleted = await request(harness, `/v1/vault/items/${ITEM_ONE}`, harness.token(), {
      method: 'DELETE', body: { base_version: 1 },
    });
    expect(deleted.status).toBe(200);
    await harness.database.query(
      "UPDATE vault_items SET deleted_at = $2 WHERE id = $1",
      [ITEM_ONE, new Date(INITIAL_TIME.getTime() - 31 * 24 * 60 * 60 * 1000)],
    );

    expect(await harness.store.cleanupExpiredTombstones(INITIAL_TIME)).toBe(1);
    const row = await harness.database.query<{
      id: string;
      user_id: string;
      version: number;
      updated_at: string | null;
      deleted_at: string | null;
      deleted_by_device_id: string | null;
      overview_ciphertext: string | null;
      overview_nonce: string | null;
      detail_ciphertext: string | null;
      detail_nonce: string | null;
      domain_hmac: string | null;
      device_id: string | null;
    }>(
      `SELECT id, user_id, version, updated_at, deleted_at, deleted_by_device_id,
              overview_ciphertext, overview_nonce, detail_ciphertext, detail_nonce, domain_hmac, device_id
       FROM vault_items WHERE id = $1`, [ITEM_ONE],
    );
    expect(row.rows[0]).toMatchObject({
      id: ITEM_ONE,
      user_id: USER_ID,
      version: 2,
      updated_at: null,
      deleted_by_device_id: DEVICE_ID,
      overview_ciphertext: null,
      overview_nonce: null,
      detail_ciphertext: null,
      detail_nonce: null,
      domain_hmac: null,
      device_id: null,
    });
    expect(row.rows[0]?.deleted_at).toBeTruthy();
    expect(await harness.store.cleanupExpiredTombstones(INITIAL_TIME)).toBe(0);

    const hiddenFromList = await request(harness, '/v1/vault/list');
    expect(await hiddenFromList.json()).toMatchObject({ items: [], has_more: false });
    const permanentStatus = await request(harness, `/v1/vault/items/${ITEM_ONE}/status`);
    expect(await permanentStatus.json()).toMatchObject({ status: 'deleted', version: 2, device_id: DEVICE_ID });
    const resurrection = await createItem(harness, ITEM_ONE, payload('expire'));
    expect(resurrection.status).toBe(410);
  });
});
