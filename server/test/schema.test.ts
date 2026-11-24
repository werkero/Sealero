import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { PGlite } from '@electric-sql/pglite';
import { pgcrypto } from '@electric-sql/pglite/contrib/pgcrypto';

// Local-only contract checks for System Design v1.48 §§3.1 and 4.1.
// Runtime checks use a fresh in-memory PostgreSQL instance and never read DATABASE_URL.
const schema = readFileSync(new URL('../db/schema.sql', import.meta.url), 'utf8');
const tableDefinitions = new Map(
  [...schema.matchAll(/CREATE TABLE\s+([a-z_]+)\s*\(([\s\S]*?)\n\);/g)].map(
    ([, name, body]) => [name!, body!] as const,
  ),
);
const normalizeSql = (sql: string) => sql.replace(/\s+/g, ' ').trim();
const normalizedSchema = normalizeSql(schema);

const expectedColumns: Record<string, string[]> = {
  users: [
    'id', 'email', 'login_password_hash', 'email_verified_at', 'disabled_at', 'created_at', 'updated_at',
  ],
  devices: [
    'id', 'user_id', 'device_name', 'device_public_key', 'device_type', 'revoked_at', 'created_at', 'updated_at',
  ],
  vault_items: [
    'id', 'user_id', 'overview_ciphertext', 'overview_nonce', 'detail_ciphertext', 'detail_nonce',
    'domain_hmac', 'version', 'updated_at', 'deleted_at', 'device_id', 'deleted_by_device_id',
  ],
  refresh_tokens: [
    'id', 'user_id', 'device_id', 'token_hash', 'expires_at', 'absolute_expires_at', 'revoked_at',
    'revoked_reason', 'reuse_alerted_at', 'created_at',
  ],
  auth_codes: ['id', 'email', 'code_hash', 'purpose', 'expires_at', 'attempts', 'used_at', 'created_at'],
  server_settings: ['key', 'value'],
  roles: ['id', 'name', 'description', 'created_at'],
  user_roles: ['user_id', 'role_id', 'assigned_at', 'assigned_by'],
  audit_logs: ['id', 'actor_user_id', 'target_user_id', 'action', 'target_type', 'metadata', 'ip_address', 'created_at'],
  login_logs: ['id', 'user_id', 'device_id', 'device_name', 'ip_address', 'user_agent', 'result', 'failure_code', 'created_at'],
  rate_limits: ['id', 'scope', 'key', 'count', 'window_start', 'expires_at'],
  user_consents: ['id', 'user_id', 'policy_type', 'policy_version', 'consented_at', 'ip_address'],
  oauth_authorizations: [
    'id', 'user_id', 'client_id', 'client_name', 'redirect_uri', 'scopes', 'access_token_hash',
    'refresh_token_hash', 'expires_at', 'refresh_expires_at', 'revoked_at', 'last_used_at', 'created_at',
  ],
  oauth_auth_codes: [
    'id', 'user_id', 'client_id', 'client_name', 'redirect_uri', 'scopes', 'code_hash', 'code_challenge',
    'code_challenge_method', 'expires_at', 'consumed_at', 'created_at',
  ],
  dek_wrappings: [
    'id', 'user_id', 'dek_version', 'wrapped_dek', 'nonce', 'kdf_salt', 'kdf_params',
    'master_password_version', 'created_at',
  ],
  mcp_confirmations: [
    'id', 'user_id', 'authorization_id', 'item_id', 'expires_at', 'approved_at', 'denied_at',
    'consumed_at', 'created_at',
  ],
};

const expectedIndexes = [
  'idx_devices_user_id',
  'idx_vault_items_user_updated',
  'idx_vault_items_user_deleted',
  'idx_vault_items_user_domain_hmac',
  'idx_refresh_tokens_user_id',
  'idx_refresh_tokens_token_hash',
  'idx_audit_logs_actor_created',
  'idx_audit_logs_target_created',
  'idx_login_logs_user_created',
  'idx_login_logs_ip_created',
  'idx_oauth_authorizations_user_id',
  'idx_dek_wrappings_user_id',
  'idx_oauth_auth_codes_user_id',
  'idx_oauth_auth_codes_expires_at',
  'mcp_confirmations_expires_idx',
  'mcp_confirmations_user_created_idx',
].sort();

function tableBody(name: string): string {
  const body = tableDefinitions.get(name);
  if (!body) throw new Error(`Missing CREATE TABLE ${name}`);
  return body;
}

function expectSql(table: string, fragment: string): void {
  expect(normalizeSql(tableBody(table))).toContain(normalizeSql(fragment));
}

describe('server schema contract (System Design v1.48 §§3.1, 4.1)', () => {
  it('contains exactly the documented server tables and columns', () => {
    expect([...tableDefinitions.keys()].sort()).toEqual(Object.keys(expectedColumns).sort());

    for (const [table, columns] of Object.entries(expectedColumns)) {
      const actualColumns = tableBody(table)
        .split(/\r?\n/)
        .map((line) => line.match(/^    ([a-z][a-z0-9_]*)\s+/)?.[1])
        .filter((column): column is string => column !== undefined);
      expect(actualColumns, `columns in ${table}`).toEqual(columns);
    }
  });

  it('preserves documented key, nullability, foreign-key, and uniqueness contracts', () => {
    expectSql('users', 'id UUID PRIMARY KEY DEFAULT gen_random_uuid()');
    expectSql('users', 'email VARCHAR(255) NOT NULL UNIQUE');
    expectSql('users', 'login_password_hash TEXT NOT NULL');
    expectSql('devices', 'user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE');
    expectSql('devices', "device_type TEXT NOT NULL CHECK (device_type IN ('app', 'extension', 'web'))");
    expectSql('devices', 'updated_at TIMESTAMPTZ NOT NULL DEFAULT now()');

    expectSql('vault_items', 'user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE');
    expectSql('vault_items', 'version BIGINT NOT NULL DEFAULT 1');
    expectSql('vault_items', 'device_id UUID REFERENCES devices(id) ON DELETE SET NULL');
    expectSql('vault_items', 'deleted_by_device_id TEXT');

    expectSql('refresh_tokens', 'token_hash TEXT NOT NULL');
    expectSql('refresh_tokens', 'absolute_expires_at TIMESTAMPTZ NOT NULL');
    expectSql('auth_codes', "purpose TEXT NOT NULL CHECK (purpose IN ('verify', 'reset', 'delete'))");
    expectSql('user_roles', 'PRIMARY KEY (user_id, role_id)');
    expectSql('rate_limits', 'UNIQUE (scope, key, window_start)');
    expectSql('user_consents', 'UNIQUE (user_id, policy_type, policy_version)');
    expectSql('oauth_authorizations', 'refresh_token_hash TEXT NOT NULL');
    expectSql('oauth_authorizations', 'refresh_expires_at TIMESTAMPTZ NOT NULL');
    expectSql('oauth_auth_codes', "code_challenge_method TEXT NOT NULL CHECK (code_challenge_method = 'S256')");
    expectSql('dek_wrappings', 'UNIQUE(user_id, dek_version)');
    expectSql('dek_wrappings', 'UNIQUE(user_id)');
    expectSql('mcp_confirmations', 'id UUID PRIMARY KEY');
    expectSql('mcp_confirmations', 'user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE');
    expectSql('mcp_confirmations', 'authorization_id UUID NOT NULL REFERENCES oauth_authorizations(id) ON DELETE CASCADE');
    expectSql('mcp_confirmations', 'item_id UUID NOT NULL REFERENCES vault_items(id) ON DELETE CASCADE');
    expectSql('mcp_confirmations', 'expires_at TIMESTAMPTZ NOT NULL');
  });

  it('keeps all three vault tombstone row shapes and the documented counterexample guards', () => {
    expectSql(
      'vault_items',
      'deleted_at IS NULL AND deleted_by_device_id IS NULL AND overview_ciphertext IS NOT NULL AND overview_nonce IS NOT NULL AND detail_ciphertext IS NOT NULL AND detail_nonce IS NOT NULL AND updated_at IS NOT NULL',
    );
    expectSql(
      'vault_items',
      'deleted_at IS NOT NULL AND deleted_by_device_id IS NOT NULL AND overview_ciphertext IS NOT NULL AND overview_nonce IS NOT NULL AND detail_ciphertext IS NOT NULL AND detail_nonce IS NOT NULL AND updated_at IS NOT NULL',
    );
    expectSql(
      'vault_items',
      'deleted_at IS NOT NULL AND deleted_by_device_id IS NOT NULL AND overview_ciphertext IS NULL AND overview_nonce IS NULL AND detail_ciphertext IS NULL AND detail_nonce IS NULL AND domain_hmac IS NULL AND updated_at IS NULL AND device_id IS NULL',
    );

    // §3.1's required invalid shapes: active row with NULL updated_at; permanent tombstone with
    // non-NULL device_id; permanent tombstone with non-NULL updated_at. Their opposites must be
    // explicitly required by the CHECK branches above.
    const check = normalizeSql(tableBody('vault_items'));
    expect(check).toContain('deleted_at IS NULL AND deleted_by_device_id IS NULL');
    expect(check).toContain('updated_at IS NOT NULL');
    expect(check).toContain('domain_hmac IS NULL AND updated_at IS NULL AND device_id IS NULL');
  });

  it('executes the schema locally and enforces tombstone and user-delete cascades', async () => {
    const database = new PGlite({ extensions: { pgcrypto } });
    try {
      await database.exec(schema);

      const userId = '00000000-0000-4000-8000-000000000001';
      const deviceId = '00000000-0000-4000-8000-000000000002';
      await database.query(
        'INSERT INTO users (id, email, login_password_hash) VALUES ($1, $2, $3)',
        [userId, 'schema-test@example.invalid', 'not-a-real-hash'],
      );
      await database.query(
        'INSERT INTO devices (id, user_id, device_name, device_type) VALUES ($1, $2, $3, $4)',
        [deviceId, userId, 'schema test', 'app'],
      );

      const encryptedFields = 'overview_ciphertext, overview_nonce, detail_ciphertext, detail_nonce';
      const activeId = '00000000-0000-4000-8000-000000000003';
      await database.query(
        `INSERT INTO vault_items (id, user_id, ${encryptedFields}) VALUES ($1, $2, 'overview', 'nonce-1', 'detail', 'nonce-2')`,
        [activeId, userId],
      );

      const softDeletedId = '00000000-0000-4000-8000-000000000004';
      await database.query(
        `INSERT INTO vault_items (id, user_id, ${encryptedFields}, deleted_at, deleted_by_device_id) VALUES ($1, $2, 'overview', 'nonce-1', 'detail', 'nonce-2', now(), $3)`,
        [softDeletedId, userId, deviceId],
      );

      const permanentId = '00000000-0000-4000-8000-000000000005';
      await database.query(
        'INSERT INTO vault_items (id, user_id, deleted_at, deleted_by_device_id, updated_at) VALUES ($1, $2, now(), $3, NULL)',
        [permanentId, userId, deviceId],
      );

      // §3.1 required counterexamples: active updated_at NULL; permanent tombstone device_id
      // non-NULL; permanent tombstone updated_at non-NULL. Each must fail the actual CHECK.
      await expect(
        database.query(
          `INSERT INTO vault_items (id, user_id, ${encryptedFields}, updated_at) VALUES ($1, $2, 'overview', 'nonce-1', 'detail', 'nonce-2', NULL)`,
          ['00000000-0000-4000-8000-000000000006', userId],
        ),
      ).rejects.toMatchObject({ code: '23514' });
      await expect(
        database.query(
          'INSERT INTO vault_items (id, user_id, deleted_at, deleted_by_device_id, device_id, updated_at) VALUES ($1, $2, now(), $3, $4, NULL)',
          ['00000000-0000-4000-8000-000000000007', userId, deviceId, deviceId],
        ),
      ).rejects.toMatchObject({ code: '23514' });
      await expect(
        database.query(
          'INSERT INTO vault_items (id, user_id, deleted_at, deleted_by_device_id, updated_at) VALUES ($1, $2, now(), $3, now())',
          ['00000000-0000-4000-8000-000000000008', userId, deviceId],
        ),
      ).rejects.toMatchObject({ code: '23514' });

      const validRows = await database.query<{ id: string }>(
        'SELECT id FROM vault_items ORDER BY id',
      );
      expect(validRows.rows.map((row) => row.id)).toEqual([activeId, softDeletedId, permanentId]);

      await database.query('UPDATE vault_items SET deleted_by_device_id = $2 WHERE id = $1', [permanentId, deviceId]);
      const permanentRow = await database.query<{ updated_at: string | null }>(
        'SELECT updated_at FROM vault_items WHERE id = $1',
        [permanentId],
      );
      expect(permanentRow.rows[0]?.updated_at).toBeNull();

      await database.query('DELETE FROM users WHERE id = $1', [userId]);
      const remainingVaultItems = await database.query<{ id: string }>(
        'SELECT id FROM vault_items WHERE user_id = $1',
        [userId],
      );
      const remainingDevices = await database.query<{ id: string }>(
        'SELECT id FROM devices WHERE user_id = $1',
        [userId],
      );
      expect(remainingVaultItems.rows).toEqual([]);
      expect(remainingDevices.rows).toEqual([]);
    } finally {
      await database.close();
    }
  });

  it('preserves the documented index inventory and uniqueness declarations', () => {
    const actualIndexes = [...schema.matchAll(/CREATE (?:UNIQUE )?INDEX\s+([a-z_]+)/g)]
      .map(([, name]) => name!)
      .sort();
    expect(actualIndexes).toEqual(expectedIndexes);
    expect(normalizedSchema).toContain('CREATE UNIQUE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash)');
    expect(normalizedSchema).toContain('CREATE INDEX idx_dek_wrappings_user_id ON dek_wrappings(user_id)');
    expect(normalizedSchema).toContain('CREATE INDEX mcp_confirmations_user_created_idx ON mcp_confirmations(user_id, created_at DESC)');
    expect(normalizedSchema).toContain('CREATE INDEX mcp_confirmations_expires_idx ON mcp_confirmations(expires_at)');
  });

  it('keeps updated_at triggers, including permanent-tombstone NULL handling', () => {
    const actualTriggers = [...schema.matchAll(/CREATE TRIGGER\s+([a-z_]+)/g)]
      .map(([, name]) => name!)
      .sort();
    expect(actualTriggers).toEqual([
      'trg_devices_updated_at',
      'trg_users_updated_at',
      'trg_vault_items_updated_at',
    ]);
    expect(normalizedSchema).toContain('CREATE OR REPLACE FUNCTION set_updated_at() RETURNS TRIGGER');
    expect(normalizedSchema).toContain('CREATE OR REPLACE FUNCTION set_vault_updated_at() RETURNS TRIGGER');
    expect(normalizedSchema).toContain(
      'IF NEW.deleted_at IS NOT NULL AND NEW.overview_ciphertext IS NULL THEN NEW.updated_at := NULL; ELSE NEW.updated_at := now();',
    );
    expect(normalizedSchema).toContain(
      'CREATE TRIGGER trg_vault_items_updated_at BEFORE UPDATE ON vault_items FOR EACH ROW EXECUTE FUNCTION set_vault_updated_at()',
    );
  });
});
