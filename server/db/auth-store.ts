import { randomUUID } from 'node:crypto';
import type {
  AccessOwnerStatus,
  AuthAuditLogInput,
  AuthCodePurpose,
  AuthCodeRecord,
  AuthDevice,
  AuthStore,
  AuthTransaction,
  AuthUser,
  LoginLogInput,
  NewRefreshTokenInput,
  RateLimitWindow,
  RefreshOwnerStatus,
  RefreshTokenRecord,
} from '../auth/types.js';
import type { DeviceType } from '../auth/types.js';
import type { PrivacyConsentStore } from '../auth/consent-types.js';
import type {
  VaultAccessStatus,
  VaultCreateOutcome,
  VaultDeleteOutcome,
  VaultDomainMatch,
  VaultItemInput,
  VaultItemPayload,
  VaultItemResponse,
  VaultItemStatus,
  VaultListItem,
  VaultPage,
  VaultStore,
  VaultKeyRecord,
  VaultKeyStore,
  VaultKeyWriteInput,
  VaultKeyWriteOutcome,
  VaultTimestamp,
  VaultUpdateOutcome,
} from '../vault/types.js';
import { computeWrappingStateHash, kdfTierIndex } from '../vault/key.js';
import type { DeviceListCursor } from '../devices/cursor.js';
import type { DeviceListItem, DeviceListStore, DeviceRevocationStore } from '../devices/types.js';
import type {
  AdminDeviceSummary,
  AdminDeviceType,
  AdminLoginHistoryEntry,
  AdminPage,
  AdminUserDetailBase,
  AdminUserListQuery,
  AdminUserReadStore,
  AdminUserSummary,
  AdminAuditEntry,
  AdminAuditMetadata,
  AdminAuditQuery,
  AdminConsoleReadStore,
  AdminOverview,
  AdminOverviewTrend,
  AdminOverviewTrendDay,
  AdminPermission,
  AdminRole,
  AdminRoleStore,
  AdminSettingKey,
  DbDumpRow,
  DbDumpTables,
} from '../admin/types.js';
import { ADMIN_SETTING_KEYS } from '../admin/types.js';
import type {
  McpConfirmationInput,
  McpConfirmationRecord,
  McpConfirmationStore,
  OAuthAuthCodeInput,
  OAuthAuthCodeRecord,
  OAuthAuthorizationAccess,
  OAuthAuthorizationInput,
  OAuthAuthorizationRecord,
  OAuthAuthorizationRotation,
  OAuthStore,
} from '../oauth/types.js';

export interface SqlResult<Row> {
  readonly rows: readonly Row[];
}

export interface SqlConnection {
  query<Row extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    values?: readonly unknown[],
  ): Promise<SqlResult<Row>>;
}

export interface TransactionalSqlDatabase extends SqlConnection {
  transaction<T>(callback: (connection: SqlConnection) => Promise<T>): Promise<T>;
}

interface UserRow extends Record<string, unknown> {
  id: string;
  email: string;
  login_password_hash: string;
  disabled_at: Date | string | null;
  email_verified_at: Date | string | null;
}

interface DeviceRow extends Record<string, unknown> {
  id: string;
  device_name: string;
  device_type: string;
}

interface DeviceListRow extends Record<string, unknown> {
  id: string;
  device_name: string;
  device_type: string;
  created_at: string;
  revoked_at: Date | string | null;
  last_active_at: Date | string | null;
}

interface RefreshRow extends Record<string, unknown> {
  id: string;
  user_id: string;
  device_id: string | null;
  token_hash: string;
  expires_at: Date | string;
  absolute_expires_at: Date | string;
  revoked_at: Date | string | null;
  revoked_reason: RefreshTokenRecord['revokedReason'];
  reuse_alerted_at: Date | string | null;
}

interface OwnerStatusRow extends Record<string, unknown> {
  email: string;
  account_disabled_at: Date | string | null;
  device_revoked_at: Date | string | null;
}

interface VaultKeyRow extends Record<string, unknown> {
  wrapped_dek: string;
  nonce: string;
  kdf_salt: string;
  kdf_params: string;
  dek_version: string | number | bigint;
  master_password_version: string | number | bigint;
}

function mapUser(row: UserRow): AuthUser {
  return {
    id: row.id,
    email: row.email,
    passwordHash: row.login_password_hash,
    disabledAt: row.disabled_at,
    emailVerifiedAt: row.email_verified_at,
  };
}

function mapRefresh(row: RefreshRow): RefreshTokenRecord {
  return {
    id: row.id,
    userId: row.user_id,
    deviceId: row.device_id,
    tokenHash: row.token_hash,
    expiresAt: row.expires_at,
    absoluteExpiresAt: row.absolute_expires_at,
    revokedAt: row.revoked_at,
    revokedReason: row.revoked_reason,
    reuseAlertedAt: row.reuse_alerted_at,
  };
}

function mapVaultKey(row: VaultKeyRow): VaultKeyRecord {
  const dekVersion = Number(row.dek_version);
  const masterPasswordVersion = Number(row.master_password_version);
  if (
    !Number.isSafeInteger(dekVersion) || dekVersion < 1 ||
    !Number.isSafeInteger(masterPasswordVersion) || masterPasswordVersion < 1
  ) {
    throw new Error('The database returned an invalid vault key version.');
  }
  return {
    wrapped_dek: row.wrapped_dek,
    nonce: row.nonce,
    kdf_salt: row.kdf_salt,
    kdf_params: row.kdf_params,
    dek_version: dekVersion,
    master_password_version: masterPasswordVersion,
  };
}

interface AuthCodeRow extends Record<string, unknown> {
  id: string;
  email: string;
  code_hash: string;
  purpose: AuthCodePurpose;
  expires_at: Date | string;
  attempts: number;
  used_at: Date | string | null;
  created_at: Date | string;
}

interface AdminUserRow extends Record<string, unknown> {
  id: string;
  email: string;
  display_name: string | null;
  avatar_url: string | null;
  created_at: Date | string;
  email_verified_at: Date | string | null;
  disabled_at: Date | string | null;
  is_admin: boolean;
  is_super_admin: boolean;
  device_count: string | number | bigint;
  last_login_at: Date | string | null;
  ciphertext_total_bytes: string | number | bigint;
}

interface AdminRoleRow extends Record<string, unknown> {
  id: string;
  name: string;
  description: string | null;
  created_at: Date | string;
  is_system: boolean;
  permission_keys: string;
  user_count: string | number | bigint;
}

function mapAdminRole(row: AdminRoleRow): AdminRole {
  const createdAt = adminTimestamp(row.created_at);
  if (createdAt === null) throw new Error('A role must have created_at.');
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    created_at: createdAt,
    is_system: row.is_system,
    permission_keys: row.permission_keys === '' ? [] : row.permission_keys.split(','),
    user_count: adminInteger(row.user_count),
  };
}

interface AdminDeviceRow extends Record<string, unknown> {
  id: string;
  device_name: string;
  device_type: string;
  revoked_at: Date | string | null;
  created_at: Date | string;
  last_login_at: Date | string | null;
}

interface AdminLoginHistoryRow extends Record<string, unknown> {
  id: string;
  device_id: string | null;
  device_name: string | null;
  ip_address: string | null;
  user_agent: string | null;
  result: 'success' | 'failed';
  failure_code: string | null;
  created_at: Date | string;
}

interface AdminAuditRow extends Record<string, unknown> {
  id: string;
  actor_user_id: string | null;
  target_user_id: string | null;
  action: string;
  target_type: string | null;
  metadata: string | null;
  ip_address: string | null;
  created_at: Date | string;
}

interface OAuthAuthCodeRow extends Record<string, unknown> {
  id: string;
  user_id: string;
  client_id: string;
  client_name: string | null;
  redirect_uri: string;
  scopes: string;
  code_hash: string;
  code_challenge: string;
  expires_at: Date | string;
  consumed_at: Date | string | null;
}

interface OAuthAuthorizationRow extends Record<string, unknown> {
  id: string;
  user_id: string;
  client_id: string;
  client_name: string | null;
  redirect_uri: string;
  scopes: string;
  access_token_hash: string;
  refresh_token_hash: string;
  expires_at: Date | string;
  refresh_expires_at: Date | string;
  revoked_at: Date | string | null;
  created_at: Date | string;
}

function oauthTimestamp(value: Date | string | null): Date | null {
  if (value === null) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error('Database returned an invalid OAuth timestamp.');
  return date;
}

function mapOAuthAuthCode(row: OAuthAuthCodeRow): OAuthAuthCodeRecord {
  const expiresAt = oauthTimestamp(row.expires_at);
  if (expiresAt === null) throw new Error('An OAuth authorization code must have expires_at.');
  return {
    id: row.id,
    userId: row.user_id,
    clientId: row.client_id,
    clientName: row.client_name,
    redirectUri: row.redirect_uri,
    scopes: row.scopes,
    codeHash: row.code_hash,
    codeChallenge: row.code_challenge,
    expiresAt,
    consumedAt: oauthTimestamp(row.consumed_at),
  };
}

function mapOAuthAuthorization(row: OAuthAuthorizationRow): OAuthAuthorizationRecord {
  const expiresAt = oauthTimestamp(row.expires_at);
  const refreshExpiresAt = oauthTimestamp(row.refresh_expires_at);
  const createdAt = oauthTimestamp(row.created_at);
  if (expiresAt === null || refreshExpiresAt === null || createdAt === null) {
    throw new Error('An OAuth authorization must have expires_at, refresh_expires_at and created_at.');
  }
  return {
    id: row.id,
    userId: row.user_id,
    clientId: row.client_id,
    clientName: row.client_name,
    redirectUri: row.redirect_uri,
    scopes: row.scopes,
    accessTokenHash: row.access_token_hash,
    refreshTokenHash: row.refresh_token_hash,
    expiresAt,
    refreshExpiresAt,
    revokedAt: oauthTimestamp(row.revoked_at),
    createdAt,
  };
}

interface McpConfirmationRow extends Record<string, unknown> {
  id: string;
  user_id: string;
  authorization_id: string;
  item_id: string;
  client_id: string;
  client_name: string | null;
  authorization_revoked_at: Date | string | null;
  expires_at: Date | string;
  approved_at: Date | string | null;
  denied_at: Date | string | null;
  consumed_at: Date | string | null;
  created_at: Date | string;
}

function mapMcpConfirmation(row: McpConfirmationRow): McpConfirmationRecord {
  const expiresAt = oauthTimestamp(row.expires_at);
  const createdAt = oauthTimestamp(row.created_at);
  if (expiresAt === null || createdAt === null) {
    throw new Error('An MCP confirmation must have expires_at and created_at.');
  }
  return {
    id: row.id,
    userId: row.user_id,
    authorizationId: row.authorization_id,
    itemId: row.item_id,
    clientId: row.client_id,
    clientName: row.client_name,
    authorizationRevokedAt: oauthTimestamp(row.authorization_revoked_at),
    expiresAt,
    approvedAt: oauthTimestamp(row.approved_at),
    deniedAt: oauthTimestamp(row.denied_at),
    consumedAt: oauthTimestamp(row.consumed_at),
    createdAt,
  };
}

function adminTimestamp(value: Date | string | null): string | null {
  if (value === null) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error('Database returned an invalid admin timestamp.');
  return date.toISOString();
}

function adminInteger(value: string | number | bigint): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error('Database returned an admin count outside the supported JSON integer range.');
  }
  return parsed;
}

/**
 * The 16 tables of the encrypted database dump (System Design §5.2), in dump
 * order, with the primary-key ordering that keeps every dump deterministic.
 */
const DB_DUMP_TABLES: readonly { readonly name: string; readonly orderBy: string }[] = [
  { name: 'users', orderBy: 'id' },
  { name: 'devices', orderBy: 'id' },
  { name: 'vault_items', orderBy: 'id' },
  { name: 'refresh_tokens', orderBy: 'id' },
  { name: 'auth_codes', orderBy: 'id' },
  { name: 'server_settings', orderBy: 'key' },
  { name: 'roles', orderBy: 'id' },
  { name: 'user_roles', orderBy: 'user_id, role_id' },
  { name: 'permissions', orderBy: 'key' },
  { name: 'role_permissions', orderBy: 'role_id, permission_id' },
  { name: 'audit_logs', orderBy: 'id' },
  { name: 'login_logs', orderBy: 'id' },
  { name: 'rate_limits', orderBy: 'id' },
  { name: 'user_consents', orderBy: 'id' },
  { name: 'oauth_authorizations', orderBy: 'id' },
  { name: 'dek_wrappings', orderBy: 'id' },
  { name: 'oauth_auth_codes', orderBy: 'id' },
  { name: 'mcp_confirmations', orderBy: 'id' },
];

/** Normalizes one raw row for canonical JSON: dates become ISO 8601 strings. */
function normalizeDbDumpRow(row: Record<string, unknown>): DbDumpRow {
  const normalized: Record<string, string | number | boolean | null> = {};
  for (const [key, value] of Object.entries(row)) {
    if (value === null || value === undefined) normalized[key] = null;
    else if (value instanceof Date) normalized[key] = value.toISOString();
    else if (typeof value === 'bigint') normalized[key] = value.toString();
    else if (value instanceof Uint8Array) normalized[key] = Buffer.from(value).toString('base64');
    else if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') normalized[key] = value;
    else normalized[key] = String(value);
  }
  return normalized;
}

function mapDeviceListItem(row: DeviceListRow): DeviceListItem {
  if (Number.isNaN(Date.parse(row.created_at))) throw new Error('Database returned an invalid device timestamp.');
  return {
    id: row.id,
    device_name: row.device_name,
    device_type: row.device_type,
    created_at: row.created_at,
    revoked_at: adminTimestamp(row.revoked_at),
    last_active_at: adminTimestamp(row.last_active_at),
  };
}

const ADMIN_SETTING_KEY_SET = new Set<string>(ADMIN_SETTING_KEYS);
const AUDIT_UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function sanitizedAuditMetadata(action: string, raw: string | null): AdminAuditMetadata {
  let parsed: unknown;
  try {
    parsed = raw === null ? {} : JSON.parse(raw) as unknown;
  } catch {
    return {};
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return {};
  const metadata = parsed as Record<string, unknown>;
  if (action === 'settings_update') {
    const keys = metadata['keys_changed'];
    const safeKeys = Array.isArray(keys)
      ? keys.filter((key): key is AdminSettingKey => typeof key === 'string' && ADMIN_SETTING_KEY_SET.has(key))
      : [];
    return { keys_changed: safeKeys };
  }
  if (action === 'device_revoke') {
    const deviceId = metadata['device_id'];
    return typeof deviceId === 'string' && AUDIT_UUID_PATTERN.test(deviceId)
      ? { device_id: deviceId }
      : {};
  }
  return {};
}

function mapAdminUser(row: AdminUserRow): AdminUserSummary {
  const createdAt = adminTimestamp(row.created_at);
  if (createdAt === null) throw new Error('A user must have created_at.');
  return {
    id: row.id,
    email: row.email,
    display_name: row.display_name,
    avatar_url: row.avatar_url,
    created_at: createdAt,
    email_verified_at: adminTimestamp(row.email_verified_at),
    disabled_at: adminTimestamp(row.disabled_at),
    is_admin: row.is_admin,
    is_super_admin: row.is_super_admin,
    device_count: adminInteger(row.device_count),
    last_login_at: adminTimestamp(row.last_login_at),
    ciphertext_total_bytes: adminInteger(row.ciphertext_total_bytes),
  };
}

function mapAdminDeviceType(value: string): AdminDeviceType {
  if (value === 'app' || value === 'extension' || value === 'web') return value;
  throw new Error('Database returned an unknown device type.');
}

function mapAdminDevice(row: AdminDeviceRow): AdminDeviceSummary {
  const createdAt = adminTimestamp(row.created_at);
  if (createdAt === null) throw new Error('A device must have created_at.');
  return {
    id: row.id,
    device_name: row.device_name,
    device_type: mapAdminDeviceType(row.device_type),
    revoked_at: adminTimestamp(row.revoked_at),
    created_at: createdAt,
    last_login_at: adminTimestamp(row.last_login_at),
  };
}

function mapAuthCode(row: AuthCodeRow): AuthCodeRecord {
  return {
    id: row.id,
    email: row.email,
    codeHash: row.code_hash,
    purpose: row.purpose,
    expiresAt: row.expires_at,
    attempts: row.attempts,
    usedAt: row.used_at,
    createdAt: row.created_at,
  };
}

async function first<Row extends Record<string, unknown>>(
  connection: SqlConnection,
  text: string,
  values: readonly unknown[] = [],
): Promise<Row | null> {
  const result = await connection.query<Row>(text, values);
  return result.rows[0] ?? null;
}

class SqlAuthTransaction implements AuthTransaction {
  constructor(private readonly connection: SqlConnection) {}

  async getSetting(key: string): Promise<string | null> {
    const row = await first<{ value: string }>(this.connection,
      'SELECT value FROM server_settings WHERE key = $1', [key]);
    return row?.value ?? null;
  }

  async lockSettingsForUpdate(): Promise<void> {
    await this.connection.query('LOCK TABLE server_settings IN SHARE ROW EXCLUSIVE MODE');
  }

  async listSettings(): Promise<readonly { readonly key: string; readonly value: string }[]> {
    const result = await this.connection.query<{ key: string; value: string }>(
      'SELECT key, value FROM server_settings ORDER BY key',
    );
    return result.rows;
  }

  async setSetting(key: string, value: string): Promise<void> {
    await this.connection.query(
      `INSERT INTO server_settings (key, value) VALUES ($1, $2)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, [key, value],
    );
  }

  async deleteSetting(key: string): Promise<void> {
    await this.connection.query('DELETE FROM server_settings WHERE key = $1', [key]);
  }

  async insertUser(email: string, passwordHash: string, emailVerifiedAt: Date | null): Promise<string | null> {
    const row = await first<{ id: string }>(this.connection,
      `INSERT INTO users (email, login_password_hash, email_verified_at)
       VALUES ($1, $2, $3)
       ON CONFLICT (email) DO NOTHING
       RETURNING id`, [email, passwordHash, emailVerifiedAt]);
    return row?.id ?? null;
  }

  async findUserByEmailForUpdate(email: string): Promise<AuthUser | null> {
    const row = await first<UserRow>(this.connection,
      `SELECT id, email, login_password_hash, disabled_at, email_verified_at
       FROM users WHERE email = $1 FOR UPDATE`, [email]);
    return row ? mapUser(row) : null;
  }

  async setEmailVerified(userId: string, verifiedAt: Date): Promise<void> {
    await this.connection.query(
      'UPDATE users SET email_verified_at = COALESCE(email_verified_at, $2) WHERE id = $1',
      [userId, verifiedAt],
    );
  }

  async insertAuthCode(input: {
    readonly email: string;
    readonly codeHash: string;
    readonly purpose: AuthCodePurpose;
    readonly expiresAt: Date;
    readonly createdAt: Date;
  }): Promise<void> {
    await this.connection.query(
      `INSERT INTO auth_codes (email, code_hash, purpose, expires_at, created_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [input.email, input.codeHash, input.purpose, input.expiresAt, input.createdAt],
    );
  }

  async invalidateAuthCodes(email: string, purpose: AuthCodePurpose, invalidatedAt: Date): Promise<void> {
    await this.connection.query(
      `UPDATE auth_codes SET used_at = $3
       WHERE email = $1 AND purpose = $2 AND used_at IS NULL`,
      [email, purpose, invalidatedAt],
    );
  }

  async findLatestAuthCodeForUpdate(email: string, purpose: AuthCodePurpose): Promise<AuthCodeRecord | null> {
    const row = await first<AuthCodeRow>(this.connection,
      `SELECT id, email, code_hash, purpose, expires_at, attempts, used_at, created_at
       FROM auth_codes WHERE email = $1 AND purpose = $2
       ORDER BY created_at DESC, id DESC LIMIT 1 FOR UPDATE`, [email, purpose]);
    return row ? mapAuthCode(row) : null;
  }

  async recordAuthCodeFailure(authCodeId: string, attemptedAt: Date): Promise<void> {
    await this.connection.query(
      `UPDATE auth_codes
       SET attempts = attempts + 1,
           used_at = CASE WHEN attempts + 1 >= 5 THEN $2 ELSE used_at END
       WHERE id = $1 AND used_at IS NULL`,
      [authCodeId, attemptedAt],
    );
  }

  async consumeAuthCode(authCodeId: string, consumedAt: Date): Promise<boolean> {
    const row = await first<{ id: string }>(this.connection,
      `UPDATE auth_codes SET used_at = $2
       WHERE id = $1 AND used_at IS NULL AND attempts < 5 AND expires_at > $2
       RETURNING id`, [authCodeId, consumedAt]);
    return row !== null;
  }

  async incrementRateLimit(window: RateLimitWindow): Promise<number> {
    const row = await first<{ count: number }>(this.connection,
      `INSERT INTO rate_limits (scope, key, count, window_start, expires_at)
       VALUES ($1, $2, 1, $3, $4)
       ON CONFLICT (scope, key, window_start)
       DO UPDATE SET count = rate_limits.count + 1, expires_at = EXCLUDED.expires_at
       RETURNING count`,
      [window.scope, window.key, window.windowStart, window.expiresAt],
    );
    if (!row) throw new Error('Rate-limit increment did not return a count.');
    return row.count;
  }

  async decrementRateLimit(window: RateLimitWindow): Promise<void> {
    await this.connection.query(
      `UPDATE rate_limits SET count = GREATEST(count - 1, 0)
       WHERE scope = $1 AND key = $2 AND window_start = $3`,
      [window.scope, window.key, window.windowStart],
    );
  }

  async findUserForUpdate(userId: string): Promise<AuthUser | null> {
    const row = await first<UserRow>(this.connection,
      `SELECT id, email, login_password_hash, disabled_at, email_verified_at
       FROM users WHERE id = $1 FOR UPDATE`, [userId]);
    return row ? mapUser(row) : null;
  }

  async findUsersForUpdate(userIds: readonly string[]): Promise<readonly AuthUser[]> {
    const uniqueIds = [...new Set(userIds)].sort();
    if (uniqueIds.length === 0) return [];
    const result = await this.connection.query<UserRow>(
      `SELECT id, email, login_password_hash, disabled_at, email_verified_at
       FROM users WHERE id = ANY($1::uuid[]) ORDER BY id FOR UPDATE`,
      [uniqueIds],
    );
    return result.rows.map(mapUser);
  }

  async setUserDisabledAt(userId: string, disabledAt: Date | null): Promise<boolean> {
    const row = await first<{ id: string }>(this.connection,
      'UPDATE users SET disabled_at = $2 WHERE id = $1 RETURNING id', [userId, disabledAt]);
    return row !== null;
  }

  async grantAdminRole(userId: string, assignedBy: string, assignedAt: Date): Promise<boolean> {
    const role = await first<{ id: string }>(this.connection,
      "SELECT id FROM roles WHERE name = 'admin'");
    if (role === null) return false;
    await this.connection.query(
      `INSERT INTO user_roles (user_id, role_id, assigned_at, assigned_by)
       VALUES ($1, $2, $3, $4) ON CONFLICT (user_id, role_id) DO NOTHING`,
      [userId, role.id, assignedAt, assignedBy],
    );
    return true;
  }

  async ensureDefaultRoles(): Promise<void> {
    await this.connection.query(
      `INSERT INTO roles (name) VALUES ('admin'), ('user'), ('super_admin')
       ON CONFLICT (name) DO NOTHING`,
    );
  }

  async ensureDefaultPermissions(): Promise<void> {
    await this.connection.query(
      `INSERT INTO permissions (key, module, description) VALUES
         ('overview:read', 'overview', '看控制台总览与用户趋势'),
         ('users:read', 'users', '看用户列表与详情'),
         ('users:manage', 'users', '停用/启用/删除用户、指定/取消管理员、吊销设备'),
         ('settings:manage', 'settings', '看与改服务器设置'),
         ('audit:read', 'audit', '看审计日志'),
         ('roles:manage', 'roles', '增删改角色、改角色权限、指派/移除角色用户'),
         ('dump:read', 'dump', '下载数据库密文 dump')
       ON CONFLICT (key) DO NOTHING`,
    );
    await this.connection.query(
      `INSERT INTO role_permissions (role_id, permission_id)
       SELECT r.id, p.id FROM roles r CROSS JOIN permissions p WHERE r.name = 'admin'
       ON CONFLICT (role_id, permission_id) DO NOTHING`,
    );
  }

  async findRoleForUpdate(roleId: string): Promise<{ readonly id: string; readonly name: string; readonly description: string | null } | null> {
    return first<{ id: string; name: string; description: string | null }>(this.connection,
      'SELECT id, name, description FROM roles WHERE id = $1 FOR UPDATE', [roleId]);
  }

  async findRoleByNameForUpdate(name: string): Promise<{ readonly id: string; readonly name: string; readonly description: string | null } | null> {
    return first<{ id: string; name: string; description: string | null }>(this.connection,
      'SELECT id, name, description FROM roles WHERE name = $1 FOR UPDATE', [name]);
  }

  async updateRoleDescription(roleId: string, description: string | null): Promise<boolean> {
    const row = await first<{ id: string }>(this.connection,
      'UPDATE roles SET description = $2 WHERE id = $1 RETURNING id', [roleId, description]);
    return row !== null;
  }

  async findUserPermissionsForUpdate(userId: string): Promise<readonly string[]> {
    const result = await this.connection.query<{ key: string }>(
      `SELECT p.key FROM permissions p
       WHERE EXISTS (
         SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id
         WHERE ur.user_id = $1 AND r.name = 'super_admin'
       ) OR EXISTS (
         SELECT 1 FROM user_roles ur JOIN role_permissions rp ON rp.role_id = ur.role_id
         WHERE ur.user_id = $1 AND rp.permission_id = p.id
       )
       ORDER BY p.key`,
      [userId],
    );
    return result.rows.map((row) => row.key);
  }

  async insertRole(name: string, description: string | null): Promise<string> {
    const row = await first<{ id: string }>(this.connection,
      'INSERT INTO roles (name, description) VALUES ($1, $2) RETURNING id', [name, description]);
    if (row === null) throw new Error('Role insert did not return an id.');
    return row.id;
  }

  async setRolePermissions(roleId: string, permissionKeys: readonly string[], grantedBy: string): Promise<void> {
    await this.connection.query('DELETE FROM role_permissions WHERE role_id = $1', [roleId]);
    if (permissionKeys.length === 0) return;
    await this.connection.query(
      `INSERT INTO role_permissions (role_id, permission_id, granted_by)
       SELECT $1, p.id, $2 FROM permissions p WHERE p.key = ANY($3::text[])
       ON CONFLICT (role_id, permission_id) DO NOTHING`,
      [roleId, grantedBy, permissionKeys],
    );
  }

  async deleteRoleById(roleId: string): Promise<boolean> {
    const row = await first<{ id: string }>(this.connection,
      'DELETE FROM roles WHERE id = $1 RETURNING id', [roleId]);
    return row !== null;
  }

  async assignUserRole(userId: string, roleId: string, assignedBy: string, assignedAt: Date): Promise<boolean> {
    const row = await first<{ user_id: string }>(this.connection,
      `INSERT INTO user_roles (user_id, role_id, assigned_at, assigned_by)
       VALUES ($1, $2, $3, $4) ON CONFLICT (user_id, role_id) DO NOTHING RETURNING user_id`,
      [userId, roleId, assignedAt, assignedBy]);
    return row !== null;
  }

  async removeUserRole(userId: string, roleId: string): Promise<boolean> {
    const row = await first<{ user_id: string }>(this.connection,
      'DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2 RETURNING user_id', [userId, roleId]);
    return row !== null;
  }

  async grantRegistrationRoles(userId: string, assignedAt: Date): Promise<boolean> {
    // Backfill for databases created before schema.sql seeded roles: without
    // these rows the grants below would silently grant nothing.
    await this.ensureDefaultRoles();
    await this.ensureDefaultPermissions();
    // Serialize the first-user check. SHARE ROW EXCLUSIVE conflicts with
    // itself (the same lock lockSettingsForUpdate uses), so a concurrent
    // registration waits here until this transaction commits, and its count
    // then sees this user. Plain INSERTs are not blocked (ROW EXCLUSIVE
    // does not conflict), only the role decision waits.
    await this.connection.query('LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE');
    const count = await first<{ total_count: string | number | bigint }>(this.connection,
      'SELECT COUNT(*)::bigint AS total_count FROM users');
    if (count === null) throw new Error('User count query returned no row.');
    const isFirstUser = adminInteger(count.total_count) === 1;
    const roleNames = isFirstUser ? ['super_admin', 'admin'] : ['user'];
    await this.connection.query(
      `INSERT INTO user_roles (user_id, role_id, assigned_at, assigned_by)
       SELECT $1, r.id, $2, NULL FROM roles r WHERE r.name = ANY($3::text[])
       ON CONFLICT (user_id, role_id) DO NOTHING`,
      [userId, assignedAt, roleNames],
    );
    return isFirstUser;
  }

  async removeAdminRole(userId: string): Promise<boolean> {
    const result = await this.connection.query<{ user_id: string }>(
      `DELETE FROM user_roles ur USING roles r
       WHERE ur.role_id = r.id AND ur.user_id = $1 AND r.name = 'admin'
       RETURNING ur.user_id`,
      [userId],
    );
    return result.rows.length > 0;
  }

  async revokeUserDevice(userId: string, deviceId: string, revokedAt: Date): Promise<boolean> {
    const device = await first<{ id: string }>(this.connection,
      'SELECT id FROM devices WHERE id = $1 AND user_id = $2 FOR UPDATE', [deviceId, userId]);
    if (device === null) return false;
    await this.connection.query(
      `UPDATE devices SET revoked_at = COALESCE(revoked_at, $3)
       WHERE id = $1 AND user_id = $2`,
      [deviceId, userId, revokedAt],
    );
    await this.connection.query(
      `UPDATE refresh_tokens SET revoked_at = $3, revoked_reason = 'device_revoked'
       WHERE user_id = $1 AND device_id = $2 AND revoked_at IS NULL`,
      [userId, deviceId, revokedAt],
    );
    return true;
  }

  async updatePasswordHash(userId: string, expectedHash: string, newHash: string): Promise<boolean> {
    const row = await first<{ id: string }>(this.connection,
      `UPDATE users SET login_password_hash = $3
       WHERE id = $1 AND login_password_hash = $2
       RETURNING id`, [userId, expectedHash, newHash]);
    return row !== null;
  }

  async findReusableDevice(userId: string, deviceId: string): Promise<AuthDevice | null> {
    const row = await first<DeviceRow>(this.connection,
      `SELECT id, device_name, device_type FROM devices
       WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
       FOR UPDATE`, [deviceId, userId]);
    return row ? { id: row.id, deviceName: row.device_name, deviceType: row.device_type } : null;
  }

  async updateDevice(deviceId: string, userId: string, deviceName: string, deviceType: DeviceType): Promise<boolean> {
    const row = await first<{ id: string }>(this.connection,
      `UPDATE devices SET device_name = $3, device_type = $4
       WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
       RETURNING id`, [deviceId, userId, deviceName, deviceType]);
    return row !== null;
  }

  async insertDevice(userId: string, deviceName: string, deviceType: DeviceType): Promise<string> {
    const row = await first<{ id: string }>(this.connection,
      `INSERT INTO devices (user_id, device_name, device_type)
       VALUES ($1, $2, $3)
       RETURNING id`, [userId, deviceName, deviceType]);
    if (!row) throw new Error('Device insert did not return an ID.');
    return row.id;
  }

  async insertRefreshToken(input: NewRefreshTokenInput): Promise<void> {
    if (!input.deviceId) throw new Error('Refresh tokens must bind a non-empty device ID.');
    await this.connection.query(
      `INSERT INTO refresh_tokens
       (user_id, device_id, token_hash, expires_at, absolute_expires_at, created_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [input.userId, input.deviceId, input.tokenHash, input.expiresAt, input.absoluteExpiresAt, input.createdAt],
    );
  }

  async findRefreshUserIdByHash(tokenHash: string): Promise<string | null> {
    const row = await first<{ user_id: string }>(this.connection,
      'SELECT user_id FROM refresh_tokens WHERE token_hash = $1', [tokenHash]);
    return row?.user_id ?? null;
  }

  async lockRefreshUser(userId: string): Promise<boolean> {
    const row = await first<{ id: string }>(this.connection,
      'SELECT id FROM users WHERE id = $1 FOR UPDATE', [userId]);
    return row !== null;
  }

  async findRefreshTokenForUpdate(tokenHash: string): Promise<RefreshTokenRecord | null> {
    const row = await first<RefreshRow>(this.connection,
      `SELECT id, user_id, device_id, token_hash, expires_at, absolute_expires_at,
              revoked_at, revoked_reason, reuse_alerted_at
       FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE`, [tokenHash]);
    return row ? mapRefresh(row) : null;
  }

  async findRefreshOwnerStatus(userId: string, deviceId: string): Promise<RefreshOwnerStatus | null> {
    const row = await first<OwnerStatusRow>(this.connection,
      `SELECT u.email, u.disabled_at AS account_disabled_at, d.revoked_at AS device_revoked_at
       FROM users u
       JOIN devices d ON d.user_id = u.id
       WHERE u.id = $1 AND d.id = $2
       FOR UPDATE OF u, d`, [userId, deviceId]);
    return row ? {
      email: row.email,
      accountDisabledAt: row.account_disabled_at,
      deviceRevokedAt: row.device_revoked_at,
    } : null;
  }

  async claimRefreshReuseAlert(refreshTokenId: string, claimedAt: Date): Promise<boolean> {
    const row = await first<{ id: string }>(this.connection,
      `UPDATE refresh_tokens SET reuse_alerted_at = $2
       WHERE id = $1 AND reuse_alerted_at IS NULL
       RETURNING id`, [refreshTokenId, claimedAt]);
    return row !== null;
  }

  async revokeAllDevices(userId: string, revokedAt: Date): Promise<void> {
    await this.connection.query(
      `UPDATE devices SET revoked_at = $2
       WHERE user_id = $1 AND revoked_at IS NULL`, [userId, revokedAt]);
  }

  async revokeAllDevicesAndCount(userId: string, revokedAt: Date): Promise<number> {
    const result = await this.connection.query<{ id: string }>(
      `UPDATE devices SET revoked_at = $2
       WHERE user_id = $1 AND revoked_at IS NULL
       RETURNING id`, [userId, revokedAt]);
    return result.rows.length;
  }

  async readDbDumpTables(): Promise<DbDumpTables> {
    const tables: Record<string, readonly DbDumpRow[]> = {};
    for (const table of DB_DUMP_TABLES) {
      const result = await this.connection.query<Record<string, unknown>>(
        `SELECT * FROM ${table.name} ORDER BY ${table.orderBy}`,
      );
      tables[table.name] = result.rows.map(normalizeDbDumpRow);
    }
    return tables;
  }

  async revokeAllUnrevokedRefreshTokens(userId: string, revokedAt: Date): Promise<void> {
    await this.connection.query(
      `UPDATE refresh_tokens SET revoked_at = $2, revoked_reason = 'device_revoked'
       WHERE user_id = $1 AND revoked_at IS NULL`, [userId, revokedAt]);
  }

  async revokeAllRefreshTokensForAccountDisabled(userId: string, revokedAt: Date): Promise<void> {
    await this.connection.query(
      `UPDATE refresh_tokens SET revoked_at = $2, revoked_reason = 'account_disabled'
       WHERE user_id = $1 AND revoked_at IS NULL`, [userId, revokedAt]);
  }

  async revokeAllPasswordResetRefreshTokens(userId: string, revokedAt: Date): Promise<void> {
    await this.connection.query(
      `UPDATE refresh_tokens SET revoked_at = $2, revoked_reason = 'password_changed'
       WHERE user_id = $1 AND revoked_at IS NULL`, [userId, revokedAt]);
  }

  async revokeAllOAuthAuthorizations(userId: string, revokedAt: Date): Promise<void> {
    await this.connection.query(
      `UPDATE oauth_authorizations SET revoked_at = $2
       WHERE user_id = $1 AND revoked_at IS NULL`, [userId, revokedAt]);
  }

  async insertOAuthAuthCode(input: OAuthAuthCodeInput): Promise<void> {
    await this.connection.query(
      `INSERT INTO oauth_auth_codes
         (user_id, client_id, client_name, redirect_uri, scopes, code_hash, code_challenge,
          code_challenge_method, expires_at, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'S256', $8, $9)`,
      [input.userId, input.clientId, input.clientName, input.redirectUri, input.scopes, input.codeHash,
        input.codeChallenge, input.expiresAt, input.createdAt]);
  }

  async findOAuthAuthCodeForUpdate(codeHash: string): Promise<OAuthAuthCodeRecord | null> {
    const row = await first<OAuthAuthCodeRow>(this.connection,
      `SELECT id, user_id, client_id, client_name, redirect_uri, scopes, code_hash, code_challenge,
              expires_at, consumed_at
       FROM oauth_auth_codes WHERE code_hash = $1 FOR UPDATE`, [codeHash]);
    return row === null ? null : mapOAuthAuthCode(row);
  }

  async consumeOAuthAuthCode(codeHash: string, consumedAt: Date): Promise<boolean> {
    const row = await first<{ id: string }>(this.connection,
      `UPDATE oauth_auth_codes SET consumed_at = $2
       WHERE code_hash = $1 AND consumed_at IS NULL
       RETURNING id`, [codeHash, consumedAt]);
    return row !== null;
  }

  async deleteOAuthAuthorizationCode(codeHash: string): Promise<void> {
    await this.connection.query(
      'DELETE FROM oauth_auth_codes WHERE code_hash = $1',
      [codeHash],
    );
  }

  async insertMcpConfirmation(input: McpConfirmationInput): Promise<string> {
    const id = randomUUID();
    await this.connection.query(
      `INSERT INTO mcp_confirmations
         (id, user_id, authorization_id, item_id, expires_at, created_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [id, input.userId, input.authorizationId, input.itemId, input.expiresAt, input.createdAt]);
    return id;
  }

  async findMcpConfirmationForUpdate(id: string): Promise<McpConfirmationRecord | null> {
    const row = await first<McpConfirmationRow>(this.connection,
      `SELECT mc.id, mc.user_id, mc.authorization_id, mc.item_id, oa.client_id, oa.client_name, oa.revoked_at AS authorization_revoked_at,
              mc.expires_at, mc.approved_at, mc.denied_at, mc.consumed_at, mc.created_at
       FROM mcp_confirmations mc
       JOIN oauth_authorizations oa ON oa.id = mc.authorization_id
       WHERE mc.id = $1
       FOR UPDATE OF mc`, [id]);
    return row === null ? null : mapMcpConfirmation(row);
  }

  async findPendingMcpConfirmationForUpdate(
    userId: string,
    authorizationId: string,
    itemId: string,
    now: Date,
  ): Promise<McpConfirmationRecord | null> {
    const row = await first<McpConfirmationRow>(this.connection,
      `SELECT mc.id, mc.user_id, mc.authorization_id, mc.item_id, oa.client_id, oa.client_name, oa.revoked_at AS authorization_revoked_at,
              mc.expires_at, mc.approved_at, mc.denied_at, mc.consumed_at, mc.created_at
       FROM mcp_confirmations mc
       JOIN oauth_authorizations oa ON oa.id = mc.authorization_id
       WHERE mc.user_id = $1 AND mc.authorization_id = $2 AND mc.item_id = $3
         AND mc.approved_at IS NULL AND mc.denied_at IS NULL AND mc.consumed_at IS NULL
         AND mc.expires_at > $4
       ORDER BY mc.created_at DESC
       LIMIT 1
       FOR UPDATE OF mc`, [userId, authorizationId, itemId, now]);
    return row === null ? null : mapMcpConfirmation(row);
  }

  async findApprovedMcpConfirmationForUpdate(
    userId: string,
    authorizationId: string,
    itemId: string,
    now: Date,
  ): Promise<McpConfirmationRecord | null> {
    const row = await first<McpConfirmationRow>(this.connection,
      `SELECT mc.id, mc.user_id, mc.authorization_id, mc.item_id, oa.client_id, oa.client_name, oa.revoked_at AS authorization_revoked_at,
              mc.expires_at, mc.approved_at, mc.denied_at, mc.consumed_at, mc.created_at
       FROM mcp_confirmations mc
       JOIN oauth_authorizations oa ON oa.id = mc.authorization_id
       WHERE mc.user_id = $1 AND mc.authorization_id = $2 AND mc.item_id = $3
         AND mc.approved_at IS NOT NULL AND mc.denied_at IS NULL AND mc.consumed_at IS NULL
         AND mc.expires_at > $4
       ORDER BY mc.created_at DESC
       LIMIT 1
       FOR UPDATE OF mc`, [userId, authorizationId, itemId, now]);
    return row === null ? null : mapMcpConfirmation(row);
  }

  async approveMcpConfirmation(id: string, approvedAt: Date): Promise<boolean> {
    const row = await first<{ id: string }>(this.connection,
      `UPDATE mcp_confirmations SET approved_at = $2
       WHERE id = $1 AND approved_at IS NULL AND denied_at IS NULL AND consumed_at IS NULL
         AND expires_at > $2
       RETURNING id`, [id, approvedAt]);
    return row !== null;
  }

  async denyMcpConfirmation(id: string, deniedAt: Date): Promise<boolean> {
    const row = await first<{ id: string }>(this.connection,
      `UPDATE mcp_confirmations SET denied_at = $2
       WHERE id = $1 AND approved_at IS NULL AND denied_at IS NULL AND consumed_at IS NULL
         AND expires_at > $2
       RETURNING id`, [id, deniedAt]);
    return row !== null;
  }

  async consumeMcpConfirmation(id: string, consumedAt: Date): Promise<boolean> {
    const row = await first<{ id: string }>(this.connection,
      `UPDATE mcp_confirmations SET consumed_at = $2
       WHERE id = $1 AND approved_at IS NOT NULL AND denied_at IS NULL AND consumed_at IS NULL
         AND expires_at > $2
       RETURNING id`, [id, consumedAt]);
    return row !== null;
  }

  async findVaultItemPayloadForUpdate(userId: string, itemId: string): Promise<VaultItemPayload | null> {
    const row = await first<VaultRow>(this.connection,
      `SELECT id, user_id, version, overview_ciphertext, overview_nonce,
              detail_ciphertext, detail_nonce, domain_hmac, updated_at, deleted_at,
              device_id, deleted_by_device_id
       FROM vault_items WHERE user_id = $1 AND id = $2 FOR UPDATE`, [userId, itemId]);
    return row === null ? null : mapVaultItemPayload(row);
  }

  async insertOAuthAuthorization(input: OAuthAuthorizationInput): Promise<string> {
    const row = await first<{ id: string }>(this.connection,
      `INSERT INTO oauth_authorizations
         (user_id, client_id, client_name, redirect_uri, scopes, access_token_hash,
          refresh_token_hash, expires_at, refresh_expires_at, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING id`,
      [input.userId, input.clientId, input.clientName, input.redirectUri, input.scopes,
        input.accessTokenHash, input.refreshTokenHash, input.expiresAt,
        input.refreshExpiresAt, input.createdAt]);
    if (row === null) throw new Error('The OAuth authorization insert did not return an id.');
    return row.id;
  }

  async findOAuthAuthorizationByRefreshTokenHashForUpdate(
    tokenHash: string,
  ): Promise<OAuthAuthorizationRecord | null> {
    const row = await first<OAuthAuthorizationRow>(this.connection,
      `SELECT id, user_id, client_id, client_name, redirect_uri, scopes, access_token_hash,
              refresh_token_hash, expires_at, refresh_expires_at, revoked_at, created_at
       FROM oauth_authorizations WHERE refresh_token_hash = $1 FOR UPDATE`, [tokenHash]);
    return row === null ? null : mapOAuthAuthorization(row);
  }

  async rotateOAuthAuthorization(id: string, rotation: OAuthAuthorizationRotation): Promise<boolean> {
    const row = await first<{ id: string }>(this.connection,
      `UPDATE oauth_authorizations
       SET access_token_hash = $2, refresh_token_hash = $3, expires_at = $4, refresh_expires_at = $5
       WHERE id = $1 AND revoked_at IS NULL
       RETURNING id`,
      [id, rotation.accessTokenHash, rotation.refreshTokenHash, rotation.expiresAt,
        rotation.refreshExpiresAt]);
    return row !== null;
  }

  async revokeOAuthAuthorizationByTokenHash(tokenHash: string, revokedAt: Date): Promise<boolean> {
    const row = await first<{ id: string }>(this.connection,
      `UPDATE oauth_authorizations SET revoked_at = $2
       WHERE (access_token_hash = $1 OR refresh_token_hash = $1) AND revoked_at IS NULL
       RETURNING id`, [tokenHash, revokedAt]);
    return row !== null;
  }

  async findUserRolesForUpdate(userId: string): Promise<readonly string[]> {
    const result = await this.connection.query<{ name: string }>(
      `SELECT r.name FROM user_roles ur
       JOIN roles r ON r.id = ur.role_id
       WHERE ur.user_id = $1
       ORDER BY r.name
       FOR UPDATE OF ur`, [userId]);
    return result.rows.map((row) => row.name);
  }

  async deleteAuthCodesForEmail(email: string): Promise<void> {
    await this.connection.query('DELETE FROM auth_codes WHERE email = $1', [email]);
  }

  async deleteEmailRateLimits(emailKey: string): Promise<void> {
    await this.connection.query(
      `DELETE FROM rate_limits
       WHERE key = $1 AND scope IN ('login_email', 'password_recovery_email')`,
      [emailKey],
    );
  }

  async deleteUser(userId: string): Promise<boolean> {
    const row = await first<{ id: string }>(this.connection,
      'DELETE FROM users WHERE id = $1 RETURNING id', [userId]);
    return row !== null;
  }

  async insertAuditLog(input: AuthAuditLogInput): Promise<void> {
    await this.connection.query(
      `INSERT INTO audit_logs
       (actor_user_id, target_user_id, action, target_type, metadata, ip_address, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [input.actorUserId, input.targetUserId, input.action, input.targetType,
        input.metadata, input.ipAddress, input.createdAt],
    );
  }

  async markRefreshTokenRotated(refreshTokenId: string, revokedAt: Date): Promise<boolean> {
    const row = await first<{ id: string }>(this.connection,
      `UPDATE refresh_tokens SET revoked_at = $2, revoked_reason = 'rotated'
       WHERE id = $1 AND revoked_at IS NULL
       RETURNING id`, [refreshTokenId, revokedAt]);
    return row !== null;
  }

  async revokeRefreshTokenForLogout(refreshTokenId: string, revokedAt: Date): Promise<void> {
    await this.connection.query(
      `UPDATE refresh_tokens SET revoked_at = $2, revoked_reason = 'logout'
       WHERE id = $1 AND revoked_at IS NULL`, [refreshTokenId, revokedAt]);
  }

  async insertLoginLog(input: LoginLogInput): Promise<void> {
    await this.connection.query(
      `INSERT INTO login_logs
       (user_id, device_id, device_name, ip_address, user_agent, result, failure_code, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [input.userId, input.deviceId, input.deviceName, input.ipAddress, input.userAgent,
        input.result, input.failureCode, input.createdAt],
    );
  }
}

interface VaultRow extends Record<string, unknown> {
  id: string;
  user_id: string;
  version: string | number | bigint;
  overview_ciphertext: string | null;
  overview_nonce: string | null;
  detail_ciphertext: string | null;
  detail_nonce: string | null;
  domain_hmac: string | null;
  updated_at: Date | string | null;
  deleted_at: Date | string | null;
  device_id: string | null;
  deleted_by_device_id: string | null;
}

interface VaultWriteRow extends Record<string, unknown> {
  id: string;
  version: string | number | bigint;
  updated_at: Date | string | null;
  deleted_at?: Date | string | null;
}

function timestampIso(value: VaultTimestamp): string | null {
  if (value === null) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error('Database returned an invalid vault timestamp.');
  return date.toISOString();
}

function apiVersion(value: string | number | bigint): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error('Database returned a vault version outside the supported JSON integer range.');
  }
  return parsed;
}

function samePayload(row: VaultRow, input: VaultItemInput): boolean {
  return row.overview_ciphertext === input.overview_ciphertext &&
    row.overview_nonce === input.overview_nonce &&
    row.detail_ciphertext === input.detail_ciphertext &&
    row.detail_nonce === input.detail_nonce &&
    row.domain_hmac === input.domain_hmac;
}

function mapVaultItemResponse(row: VaultWriteRow): VaultItemResponse {
  const updatedAt = timestampIso(row.updated_at);
  if (updatedAt === null) throw new Error('An active vault item must have updated_at.');
  return { id: row.id, version: apiVersion(row.version), updated_at: updatedAt };
}

function mapVaultItemPayload(row: VaultRow): VaultItemPayload {
  if (row.overview_ciphertext === null || row.overview_nonce === null ||
      row.detail_ciphertext === null || row.detail_nonce === null) {
    throw new Error('A vault item must have overview and detail ciphertext.');
  }
  return {
    id: row.id,
    version: apiVersion(row.version),
    overview_ciphertext: row.overview_ciphertext,
    overview_nonce: row.overview_nonce,
    detail_ciphertext: row.detail_ciphertext,
    detail_nonce: row.detail_nonce,
    domain_hmac: row.domain_hmac,
    deletedAt: row.deleted_at,
  };
}

function existingPostOutcome(row: VaultRow, userId: string, input: VaultItemInput): VaultCreateOutcome {
  if (row.user_id !== userId) return { kind: 'item_id_conflict' };
  if (row.deleted_at !== null) return { kind: 'deleted' };
  if (samePayload(row, input)) {
    return { kind: 'ok', item: mapVaultItemResponse(row), replayed: true };
  }
  return { kind: 'payload_conflict' };
}

const ADMIN_USER_SUMMARY_SELECT = `
  SELECT u.id, u.email, u.display_name, u.avatar_url, u.created_at, u.email_verified_at, u.disabled_at,
         EXISTS (
           SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id
           WHERE ur.user_id = u.id AND r.name IN ('admin', 'super_admin')
         ) AS is_admin,
         EXISTS (
           SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id
           WHERE ur.user_id = u.id AND r.name = 'super_admin'
         ) AS is_super_admin,
         (SELECT COUNT(*)::bigint FROM devices d WHERE d.user_id = u.id) AS device_count,
         (SELECT MAX(ll.created_at) FROM login_logs ll
          WHERE ll.user_id = u.id AND ll.result = 'success') AS last_login_at,
         COALESCE((
           SELECT SUM(octet_length(v.overview_ciphertext) + octet_length(v.overview_nonce) +
                      octet_length(v.detail_ciphertext) + octet_length(v.detail_nonce))
           FROM vault_items v WHERE v.user_id = u.id AND v.deleted_at IS NULL
         ), 0)::bigint AS ciphertext_total_bytes
  FROM users u`;

export interface SqlAuthStoreOptions {
  /** Live pool size for `GET /v1/admin/overview`. Defaults to 1 (single connection). */
  readonly connectionCount?: () => number;
}

/** SQL implementation; the host supplies a transactional PostgreSQL-compatible driver. */
export class SqlAuthStore implements AuthStore, VaultStore, VaultKeyStore, DeviceRevocationStore, DeviceListStore,
  PrivacyConsentStore, AdminUserReadStore, AdminConsoleReadStore, AdminRoleStore, OAuthStore, McpConfirmationStore {
  constructor(
    private readonly database: TransactionalSqlDatabase,
    private readonly options: SqlAuthStoreOptions = {},
  ) {}

  async findUserByEmail(email: string): Promise<AuthUser | null> {
    const row = await first<UserRow>(this.database,
      `SELECT id, email, login_password_hash, disabled_at, email_verified_at
       FROM users WHERE email = $1`, [email]);
    return row ? mapUser(row) : null;
  }

  async findUserById(userId: string): Promise<{ readonly id: string; readonly email: string; readonly display_name: string | null; readonly avatar_url: string | null } | null> {
    const row = await first<{ id: string; email: string; display_name: string | null; avatar_url: string | null }>(this.database,
      'SELECT id, email, display_name, avatar_url FROM users WHERE id = $1', [userId]);
    return row === null ? null : { id: row.id, email: row.email, display_name: row.display_name, avatar_url: row.avatar_url };
  }

  async hasAdminRole(userId: string): Promise<boolean> {
    const row = await first<{ is_admin: boolean }>(this.database,
      `SELECT EXISTS (
         SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id
         WHERE ur.user_id = $1 AND r.name IN ('admin', 'super_admin')
       ) AS is_admin`, [userId]);
    return row?.is_admin === true;
  }

  async hasPermission(userId: string, permissionKey: string): Promise<boolean> {
    const row = await first<{ has_permission: boolean }>(this.database,
      `SELECT EXISTS (
         SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id
         WHERE ur.user_id = $1 AND (r.name = 'super_admin' OR EXISTS (
           SELECT 1 FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id
           WHERE rp.role_id = ur.role_id AND p.key = $2
         ))
       ) AS has_permission`, [userId, permissionKey]);
    return row?.has_permission === true;
  }

  async getUserPermissions(userId: string): Promise<readonly string[]> {
    const result = await this.database.query<{ key: string }>(
      `SELECT p.key FROM permissions p
       WHERE EXISTS (
         SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id
         WHERE ur.user_id = $1 AND r.name = 'super_admin'
       ) OR EXISTS (
         SELECT 1 FROM user_roles ur JOIN role_permissions rp ON rp.role_id = ur.role_id
         WHERE ur.user_id = $1 AND rp.permission_id = p.id
       )
       ORDER BY p.key`,
      [userId],
    );
    return result.rows.map((row) => row.key);
  }

  async listPermissions(): Promise<readonly AdminPermission[]> {
    const result = await this.database.query<{ key: string; module: string; description: string | null }>(
      'SELECT key, module, description FROM permissions ORDER BY module, key');
    return result.rows.map((row) => ({ key: row.key, module: row.module, description: row.description }));
  }

  async listRoles(): Promise<readonly AdminRole[]> {
    const result = await this.database.query<AdminRoleRow>(
      `SELECT r.id, r.name, r.description, r.created_at,
              (r.name IN ('admin', 'user', 'super_admin')) AS is_system,
              CASE WHEN r.name = 'super_admin'
                THEN (SELECT COALESCE(string_agg(key, ',' ORDER BY key), '') FROM permissions)
                ELSE COALESCE((SELECT string_agg(p.key, ',' ORDER BY p.key)
                               FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id
                               WHERE rp.role_id = r.id), '')
              END AS permission_keys,
              (SELECT COUNT(*)::bigint FROM user_roles ur WHERE ur.role_id = r.id) AS user_count
       FROM roles r
       ORDER BY CASE r.name WHEN 'super_admin' THEN 0 WHEN 'admin' THEN 1 WHEN 'user' THEN 2 ELSE 3 END,
                r.created_at ASC, r.name ASC`,
    );
    return result.rows.map(mapAdminRole);
  }

  async getRole(roleId: string): Promise<AdminRole | null> {
    const row = await first<AdminRoleRow>(this.database,
      `SELECT r.id, r.name, r.description, r.created_at,
              (r.name IN ('admin', 'user', 'super_admin')) AS is_system,
              CASE WHEN r.name = 'super_admin'
                THEN (SELECT COALESCE(string_agg(key, ',' ORDER BY key), '') FROM permissions)
                ELSE COALESCE((SELECT string_agg(p.key, ',' ORDER BY p.key)
                               FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id
                               WHERE rp.role_id = r.id), '')
              END AS permission_keys,
              (SELECT COUNT(*)::bigint FROM user_roles ur WHERE ur.role_id = r.id) AS user_count
       FROM roles r WHERE r.id = $1`, [roleId]);
    return row === null ? null : mapAdminRole(row);
  }

  async listRoleUsers(roleId: string, cursor: string | null, limit: number): Promise<AdminPage<AdminUserSummary> | null> {
    if (cursor !== null) {
      const cursorRow = await first<{ id: string }>(this.database,
        'SELECT id FROM users WHERE id = $1', [cursor]);
      if (cursorRow === null) return null;
    }
    const role = await first<{ id: string }>(this.database,
      'SELECT id FROM roles WHERE id = $1', [roleId]);
    if (role === null) return null;
    const count = await first<{ total_count: string | number | bigint }>(this.database,
      `SELECT COUNT(*)::bigint AS total_count FROM users u
       JOIN user_roles ur ON ur.user_id = u.id WHERE ur.role_id = $1`, [roleId]);
    if (count === null) throw new Error('Role user count query returned no row.');
    const result = await this.database.query<AdminUserRow>(
      `${ADMIN_USER_SUMMARY_SELECT}
       JOIN user_roles ur ON ur.user_id = u.id
       WHERE ur.role_id = $1
         AND ($2::uuid IS NULL OR (u.created_at, u.id) < (
           SELECT cursor_user.created_at, cursor_user.id FROM users cursor_user WHERE cursor_user.id = $2::uuid
         ))
       ORDER BY u.created_at DESC, u.id DESC
       LIMIT $3`,
      [roleId, cursor, limit + 1],
    );
    const hasMore = result.rows.length > limit;
    const items = result.rows.slice(0, limit).map(mapAdminUser);
    return {
      items,
      total_count: adminInteger(count.total_count),
      has_more: hasMore,
      next_cursor: hasMore ? (items.at(-1)?.id ?? null) : null,
    };
  }

  async listAdminUsers(query: AdminUserListQuery): Promise<AdminPage<AdminUserSummary> | null> {
    if (query.cursor !== null) {
      const cursor = await first<{ id: string }>(this.database,
        'SELECT id FROM users WHERE id = $1', [query.cursor]);
      if (cursor === null) return null;
    }

    const filterSql = `
      WHERE ($1::text IS NULL OR position(lower($1) in lower(u.email)) > 0)
        AND ($2::text = 'all' OR ($2 = 'active' AND u.disabled_at IS NULL)
             OR ($2 = 'disabled' AND u.disabled_at IS NOT NULL))
        AND ($3::text = 'all' OR ($3 = 'verified' AND u.email_verified_at IS NOT NULL)
             OR ($3 = 'unverified' AND u.email_verified_at IS NULL))
        AND ($4::text = 'all'
             OR ($4 = 'admin' AND EXISTS (
               SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id
               WHERE ur.user_id = u.id AND r.name IN ('admin', 'super_admin')
             ))
             OR ($4 = 'super_admin' AND EXISTS (
               SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id
               WHERE ur.user_id = u.id AND r.name = 'super_admin'
             ))
             OR ($4 = 'user' AND NOT EXISTS (
               SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id
               WHERE ur.user_id = u.id AND r.name IN ('admin', 'super_admin')
             )))`;
    const filterValues = [query.search, query.status, query.verified, query.role] as const;
    const count = await first<{ total_count: string | number | bigint }>(this.database,
      `SELECT COUNT(*)::bigint AS total_count FROM users u ${filterSql}`, filterValues);
    if (count === null) throw new Error('Admin user count query returned no row.');

    const result = await this.database.query<AdminUserRow>(
      `${ADMIN_USER_SUMMARY_SELECT}
       ${filterSql}
         AND ($5::uuid IS NULL OR (u.created_at, u.id) < (
           SELECT cursor_user.created_at, cursor_user.id FROM users cursor_user WHERE cursor_user.id = $5::uuid
         ))
       ORDER BY u.created_at DESC, u.id DESC
       LIMIT $6`,
      [...filterValues, query.cursor, query.limit + 1],
    );
    const hasMore = result.rows.length > query.limit;
    const items = result.rows.slice(0, query.limit).map(mapAdminUser);
    return {
      items,
      total_count: adminInteger(count.total_count),
      has_more: hasMore,
      next_cursor: hasMore ? (items.at(-1)?.id ?? null) : null,
    };
  }

  async getAdminUser(userId: string): Promise<AdminUserDetailBase | null> {
    const user = await this.findAdminUserSummary(userId);
    if (user === null) return null;
    const result = await this.database.query<AdminDeviceRow>(
      `SELECT d.id, d.device_name, d.device_type, d.revoked_at, d.created_at,
              (SELECT MAX(ll.created_at) FROM login_logs ll
               WHERE ll.user_id = d.user_id AND ll.device_id = d.id AND ll.result = 'success') AS last_login_at
       FROM devices d WHERE d.user_id = $1 ORDER BY d.created_at ASC, d.id ASC`,
      [userId],
    );
    return { user, devices: result.rows.map(mapAdminDevice) };
  }

  async listAdminUserLoginHistory(
    userId: string,
    cursor: string | null,
    limit: number,
  ): Promise<AdminPage<AdminLoginHistoryEntry> | null> {
    if (cursor !== null) {
      const cursorRow = await first<{ id: string }>(this.database,
        'SELECT id FROM login_logs WHERE id = $1 AND user_id = $2', [cursor, userId]);
      if (cursorRow === null) return null;
    }
    const count = await first<{ total_count: string | number | bigint }>(this.database,
      'SELECT COUNT(*)::bigint AS total_count FROM login_logs WHERE user_id = $1', [userId]);
    if (count === null) throw new Error('Admin login history count query returned no row.');
    const result = await this.database.query<AdminLoginHistoryRow>(
      `SELECT ll.id, ll.device_id, ll.device_name, ll.ip_address, ll.user_agent,
              ll.result, ll.failure_code, ll.created_at
       FROM login_logs ll
       WHERE ll.user_id = $1
         AND ($2::uuid IS NULL OR (ll.created_at, ll.id) < (
           SELECT cursor_log.created_at, cursor_log.id FROM login_logs cursor_log
           WHERE cursor_log.id = $2::uuid AND cursor_log.user_id = $1
         ))
       ORDER BY ll.created_at DESC, ll.id DESC
       LIMIT $3`,
      [userId, cursor, limit + 1],
    );
    const hasMore = result.rows.length > limit;
    const items: AdminLoginHistoryEntry[] = result.rows.slice(0, limit).map((row) => {
      const createdAt = adminTimestamp(row.created_at);
      if (createdAt === null) throw new Error('A login history entry must have created_at.');
      return {
        id: row.id,
        device_id: row.device_id,
        device_name: row.device_name,
        ip_address: row.ip_address,
        user_agent: row.user_agent,
        result: row.result,
        failure_code: row.failure_code,
        created_at: createdAt,
      };
    });
    return {
      items,
      total_count: adminInteger(count.total_count),
      has_more: hasMore,
      next_cursor: hasMore ? (items.at(-1)?.id ?? null) : null,
    };
  }

  async findAdminDeviceOwner(deviceId: string): Promise<string | null> {
    const row = await first<{ user_id: string }>(this.database,
      'SELECT user_id FROM devices WHERE id = $1', [deviceId]);
    return row?.user_id ?? null;
  }

  async listAdminSettings(): Promise<Readonly<Record<string, string>>> {
    const result = await this.database.query<{ key: string; value: string }>(
      'SELECT key, value FROM server_settings ORDER BY key',
    );
    return Object.fromEntries(result.rows.map((row) => [row.key, row.value]));
  }

  async listAdminAuditLogs(query: AdminAuditQuery): Promise<AdminPage<AdminAuditEntry> | null> {
    if (query.cursor !== null) {
      const cursor = await first<{ id: string }>(this.database,
        'SELECT id FROM audit_logs WHERE id = $1', [query.cursor]);
      if (cursor === null) return null;
    }
    const filterSql = `
      WHERE ($1::uuid IS NULL OR actor_user_id = $1::uuid)
        AND ($2::uuid IS NULL OR target_user_id = $2::uuid)
        AND ($3::text IS NULL OR action = $3)
        AND ($4::timestamptz IS NULL OR created_at >= $4::timestamptz)
        AND ($5::timestamptz IS NULL OR created_at <= $5::timestamptz)`;
    const filters = [query.actorUserId, query.targetUserId, query.action, query.from, query.to] as const;
    const count = await first<{ total_count: string | number | bigint }>(this.database,
      `SELECT COUNT(*)::bigint AS total_count FROM audit_logs ${filterSql}`, filters);
    if (count === null) throw new Error('Admin audit count query returned no row.');
    const result = await this.database.query<AdminAuditRow>(
      `SELECT id, actor_user_id, target_user_id, action, target_type, metadata, ip_address, created_at
       FROM audit_logs
       ${filterSql}
         AND ($6::uuid IS NULL OR (created_at, id) < (
           SELECT cursor_log.created_at, cursor_log.id FROM audit_logs cursor_log WHERE cursor_log.id = $6::uuid
         ))
       ORDER BY created_at DESC, id DESC
       LIMIT $7`,
      [...filters, query.cursor, query.limit + 1],
    );
    const hasMore = result.rows.length > query.limit;
    const items: AdminAuditEntry[] = result.rows.slice(0, query.limit).map((row) => {
      const createdAt = adminTimestamp(row.created_at);
      if (createdAt === null) throw new Error('An audit log entry must have created_at.');
      return {
        id: row.id,
        actor_user_id: row.actor_user_id,
        target_user_id: row.target_user_id,
        action: row.action,
        target_type: row.target_type,
        metadata: sanitizedAuditMetadata(row.action, row.metadata),
        ip_address: row.ip_address,
        created_at: createdAt,
      };
    });
    return {
      items,
      total_count: adminInteger(count.total_count),
      has_more: hasMore,
      next_cursor: hasMore ? (items.at(-1)?.id ?? null) : null,
    };
  }

  async getAdminOverview(now: Date): Promise<AdminOverview> {
    const dayStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
    const dayEnd = new Date(dayStart.getTime() + 24 * 60 * 60 * 1000);
    const row = await first<{
      total_users: string | number | bigint;
      today_new_users: string | number | bigint;
      today_active_users: string | number | bigint;
      total_devices: string | number | bigint;
    }>(this.database,
      `SELECT
         (SELECT COUNT(*)::bigint FROM users) AS total_users,
         (SELECT COUNT(*)::bigint FROM users WHERE created_at >= $1::timestamptz AND created_at < $2::timestamptz) AS today_new_users,
         (SELECT COUNT(DISTINCT user_id)::bigint FROM login_logs
          WHERE result = 'success' AND user_id IS NOT NULL
            AND created_at >= $1::timestamptz AND created_at < $2::timestamptz) AS today_active_users,
         (SELECT COUNT(*)::bigint FROM devices) AS total_devices`,
      [dayStart, dayEnd]);
    if (row === null) throw new Error('Admin overview query returned no row.');
    // Cleanup runs are recorded in server_settings by the maintenance
    // endpoint (System Design §7.4, §8); until the first run, both stay null.
    const cleanupRows = await this.database.query<{ key: string; value: string }>(
      `SELECT key, value FROM server_settings
       WHERE key IN ('tombstone_last_cleanup_at', 'tombstone_last_cleanup_status')`,
    );
    const cleanupByKey = new Map(cleanupRows.rows.map((entry) => [entry.key, entry.value]));
    const lastCleanupAt = cleanupByKey.get('tombstone_last_cleanup_at') ?? null;
    const lastCleanupStatusRaw = cleanupByKey.get('tombstone_last_cleanup_status') ?? null;
    const lastCleanupStatus =
      lastCleanupStatusRaw === 'success' || lastCleanupStatusRaw === 'failed'
        ? lastCleanupStatusRaw
        : null;
    return {
      total_users: adminInteger(row.total_users),
      today_new_users: adminInteger(row.today_new_users),
      today_active_users: adminInteger(row.today_active_users),
      total_devices: adminInteger(row.total_devices),
      // Live connection-pool size for a pooled store (Neon); 1 for the
      // single-connection local adapter. See SqlAuthStoreOptions.
      db_connections: this.options.connectionCount?.() ?? 1,
      tombstone_cleanup: { last_cleanup_at: lastCleanupAt, last_cleanup_status: lastCleanupStatus },
    };
  }

  async getAdminOverviewTrend(now: Date, days: number): Promise<AdminOverviewTrend> {
    const todayStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
    const rangeStart = new Date(todayStart.getTime() - (days - 1) * 24 * 60 * 60 * 1000);
    const rangeEnd = new Date(todayStart.getTime() + 24 * 60 * 60 * 1000);
    const newUsers = await this.database.query<{ day: string; count: string | number | bigint }>(
      `SELECT TO_CHAR(DATE_TRUNC('day', created_at AT TIME ZONE 'UTC'), 'YYYY-MM-DD') AS day, COUNT(*)::bigint AS count
       FROM users
       WHERE created_at >= $1::timestamptz AND created_at < $2::timestamptz
       GROUP BY DATE_TRUNC('day', created_at AT TIME ZONE 'UTC')`,
      [rangeStart, rangeEnd],
    );
    const activeUsers = await this.database.query<{ day: string; count: string | number | bigint }>(
      `SELECT TO_CHAR(DATE_TRUNC('day', created_at AT TIME ZONE 'UTC'), 'YYYY-MM-DD') AS day, COUNT(DISTINCT user_id)::bigint AS count
       FROM login_logs
       WHERE result = 'success' AND user_id IS NOT NULL
         AND created_at >= $1::timestamptz AND created_at < $2::timestamptz
       GROUP BY DATE_TRUNC('day', created_at AT TIME ZONE 'UTC')`,
      [rangeStart, rangeEnd],
    );
    const newByDay = new Map(newUsers.rows.map((row) => [row.day, adminInteger(row.count)]));
    const activeByDay = new Map(activeUsers.rows.map((row) => [row.day, adminInteger(row.count)]));
    const result: AdminOverviewTrendDay[] = [];
    for (let offset = 0; offset < days; offset += 1) {
      const date = new Date(rangeStart.getTime() + offset * 24 * 60 * 60 * 1000);
      const day = date.toISOString().slice(0, 10);
      result.push({ date: day, new_users: newByDay.get(day) ?? 0, active_users: activeByDay.get(day) ?? 0 });
    }
    return { days: result };
  }

  private async findAdminUserSummary(userId: string): Promise<AdminUserSummary | null> {
    const row = await first<AdminUserRow>(this.database,
      `${ADMIN_USER_SUMMARY_SELECT} WHERE u.id = $1`, [userId]);
    return row === null ? null : mapAdminUser(row);
  }

  async getAccessOwnerStatus(userId: string, deviceId: string): Promise<AccessOwnerStatus | null> {
    const row = await first<OwnerStatusRow>(this.database,
      `SELECT u.email, u.disabled_at AS account_disabled_at, d.revoked_at AS device_revoked_at
       FROM users u
       JOIN devices d ON d.user_id = u.id
       WHERE u.id = $1 AND d.id = $2`, [userId, deviceId]);
    return row ? {
      accountDisabledAt: row.account_disabled_at,
      deviceRevokedAt: row.device_revoked_at,
    } : null;
  }

  async findOAuthAuthorizationByAccessTokenHash(
    tokenHash: string,
  ): Promise<OAuthAuthorizationAccess | null> {
    const row = await first<OAuthAuthorizationRow & { user_disabled_at: Date | string | null }>(
      this.database,
      `SELECT oa.id, oa.user_id, oa.client_id, oa.client_name, oa.redirect_uri, oa.scopes,
              oa.access_token_hash, oa.refresh_token_hash, oa.expires_at, oa.refresh_expires_at,
              oa.revoked_at, oa.created_at, u.disabled_at AS user_disabled_at
       FROM oauth_authorizations oa
       JOIN users u ON u.id = oa.user_id
       WHERE oa.access_token_hash = $1`, [tokenHash]);
    if (row === null) return null;
    return { ...mapOAuthAuthorization(row), userDisabledAt: oauthTimestamp(row.user_disabled_at) };
  }

  async listMcpConfirmations(
    userId: string,
    now: Date,
    limit: number,
  ): Promise<readonly McpConfirmationRecord[]> {
    const result = await this.database.query<McpConfirmationRow>(
      `SELECT mc.id, mc.user_id, mc.authorization_id, mc.item_id, oa.client_id, oa.client_name, oa.revoked_at AS authorization_revoked_at,
              mc.expires_at, mc.approved_at, mc.denied_at, mc.consumed_at, mc.created_at
       FROM mcp_confirmations mc
       JOIN oauth_authorizations oa ON oa.id = mc.authorization_id
       WHERE mc.user_id = $1
         AND mc.denied_at IS NULL AND mc.consumed_at IS NULL
         AND mc.expires_at > $2
         AND oa.revoked_at IS NULL
         AND EXISTS (
           SELECT 1 FROM vault_items vi
           WHERE vi.id = mc.item_id AND vi.user_id = mc.user_id AND vi.deleted_at IS NULL
         )
       ORDER BY mc.created_at DESC
       LIMIT $3`, [userId, now, limit]);
    return result.rows.map(mapMcpConfirmation);
  }

  async touchOAuthAuthorizationLastUsed(id: string, usedAt: Date): Promise<void> {
    await this.database.query(
      'UPDATE oauth_authorizations SET last_used_at = $2 WHERE id = $1', [id, usedAt]);
  }

  async transaction<T>(callback: (transaction: AuthTransaction) => Promise<T>): Promise<T> {
    return this.database.transaction((connection) => callback(new SqlAuthTransaction(connection)));
  }

  async revokeDevice(userId: string, deviceId: string, revokedAt: Date): Promise<boolean> {
    return this.database.transaction(async (connection) => {
      // Match login and refresh transaction ordering so no token is issued after revocation commits.
      const user = await first<{ id: string }>(connection,
        'SELECT id FROM users WHERE id = $1 FOR UPDATE', [userId]);
      if (user === null) return false;

      const device = await first<{ id: string }>(connection,
        'SELECT id FROM devices WHERE id = $1 AND user_id = $2 FOR UPDATE', [deviceId, userId]);
      if (device === null) return false;

      await connection.query(
        `UPDATE devices SET revoked_at = $3
         WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`,
        [deviceId, userId, revokedAt],
      );
      await connection.query(
        `UPDATE refresh_tokens
         SET revoked_at = $3, revoked_reason = 'device_revoked'
         WHERE user_id = $1 AND device_id = $2 AND revoked_at IS NULL`,
        [userId, deviceId, revokedAt],
      );
      await connection.query(
        `UPDATE oauth_authorizations SET revoked_at = $2
         WHERE user_id = $1 AND revoked_at IS NULL`,
        [userId, revokedAt],
      );
      return true;
    });
  }

  async listDevices(
    userId: string,
    cursor: DeviceListCursor | null,
    limit: number,
  ): Promise<{ readonly devices: readonly DeviceListItem[]; readonly total_count: number }> {
    const count = await first<{ total_count: string | number | bigint }>(this.database,
      'SELECT COUNT(*)::bigint AS total_count FROM devices WHERE user_id = $1', [userId]);
    if (count === null) throw new Error('Device count query returned no row.');

    const result = await this.database.query<DeviceListRow>(
      `SELECT d.id, d.device_name, d.device_type,
              to_char(d.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at,
              d.revoked_at,
              GREATEST(login.last_successful_login_at, vault.last_vault_write_at) AS last_active_at
       FROM devices d
       LEFT JOIN LATERAL (
         SELECT MAX(ll.created_at) AS last_successful_login_at
         FROM login_logs ll
         WHERE ll.user_id = d.user_id AND ll.device_id = d.id AND ll.result = 'success'
       ) login ON TRUE
       LEFT JOIN LATERAL (
         SELECT MAX(GREATEST(v.updated_at, v.deleted_at)) AS last_vault_write_at
         FROM vault_items v
         WHERE v.user_id = d.user_id AND (v.device_id = d.id OR v.deleted_by_device_id = d.id::text)
       ) vault ON TRUE
       WHERE d.user_id = $1
         AND ($2::timestamptz IS NULL OR d.created_at < $2::timestamptz
              OR (d.created_at = $2::timestamptz AND d.id < $3::uuid))
       ORDER BY d.created_at DESC, d.id DESC
       LIMIT $4`,
      [userId, cursor?.createdAt ?? null, cursor?.id ?? null, limit + 1],
    );
    return {
      devices: result.rows.map(mapDeviceListItem),
      total_count: adminInteger(count.total_count),
    };
  }

  async getVaultAccessStatus(userId: string, policyVersion: string): Promise<VaultAccessStatus | null> {
    const row = await first<{
      email_verified_at: Date | string | null;
      require_email_verification: string | null;
      has_current_privacy_consent: boolean;
    }>(this.database,
      `SELECT u.email_verified_at, s.value AS require_email_verification,
              EXISTS (
                SELECT 1 FROM user_consents uc
                WHERE uc.user_id = u.id AND uc.policy_type = 'privacy' AND uc.policy_version = $2
              ) AS has_current_privacy_consent
       FROM users u
       LEFT JOIN server_settings s ON s.key = 'require_email_verification'
       WHERE u.id = $1`, [userId, policyVersion]);
    if (row === null) return null;
    return {
      emailVerifiedAt: row.email_verified_at,
      requireEmailVerification: row.require_email_verification !== 'false',
      hasCurrentPrivacyConsent: row.has_current_privacy_consent,
    };
  }

  async recordPrivacyConsent(
    userId: string,
    policyVersion: string,
    ipAddress: string | null,
    consentedAt: Date,
  ): Promise<string> {
    return this.database.transaction(async (connection) => {
      await connection.query(
        `INSERT INTO user_consents (user_id, policy_type, policy_version, consented_at, ip_address)
         VALUES ($1, 'privacy', $2, $3, $4)
         ON CONFLICT (user_id, policy_type, policy_version) DO NOTHING`,
        [userId, policyVersion, consentedAt, ipAddress],
      );
      const row = await first<{ consented_at: Date | string }>(connection,
        `SELECT consented_at FROM user_consents
         WHERE user_id = $1 AND policy_type = 'privacy' AND policy_version = $2`,
        [userId, policyVersion],
      );
      if (row === null) throw new Error('Privacy consent was not persisted.');
      const timestamp = adminTimestamp(row.consented_at);
      if (timestamp === null) throw new Error('Privacy consent must include a timestamp.');
      return timestamp;
    });
  }

  async getVaultKey(userId: string): Promise<VaultKeyRecord | null> {
    const row = await first<VaultKeyRow>(this.database,
      `SELECT wrapped_dek, nonce, kdf_salt, kdf_params, dek_version, master_password_version
       FROM dek_wrappings WHERE user_id = $1`, [userId]);
    return row === null ? null : mapVaultKey(row);
  }

  async saveVaultKey(userId: string, input: VaultKeyWriteInput): Promise<VaultKeyWriteOutcome> {
    const targetTier = kdfTierIndex(input.kdf_params);
    // System Design v1.46 requires a global P3 gate but does not define its setting key in §3.1 or §5.2.
    // Until that contract is resolved, all P3 uploads fail closed.
    if (
      targetTier === null || targetTier === 3 ||
      !Number.isSafeInteger(input.dek_version) || input.dek_version < 1 ||
      !Number.isSafeInteger(input.master_password_version) || input.master_password_version < 1
    ) {
      return { kind: 'conflict' };
    }

    return this.database.transaction(async (connection) => {
      const row = await first<VaultKeyRow>(connection,
        `SELECT wrapped_dek, nonce, kdf_salt, kdf_params, dek_version, master_password_version
         FROM dek_wrappings WHERE user_id = $1 FOR UPDATE`, [userId]);

      if (row === null) {
        if (input.expected_wrapping_state_hash !== null) return { kind: 'conflict' };
        const inserted = await first<VaultKeyRow>(connection,
          `INSERT INTO dek_wrappings
             (user_id, wrapped_dek, nonce, kdf_salt, kdf_params, dek_version, master_password_version)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (user_id) DO NOTHING
           RETURNING wrapped_dek, nonce, kdf_salt, kdf_params, dek_version, master_password_version`,
          [userId, input.wrapped_dek, input.nonce, input.kdf_salt, input.kdf_params,
            input.dek_version, input.master_password_version]);
        return inserted === null
          ? { kind: 'conflict' }
          : { kind: 'ok', record: mapVaultKey(inserted) };
      }

      const current = mapVaultKey(row);
      if (input.expected_wrapping_state_hash !== computeWrappingStateHash(userId, current)) {
        return { kind: 'conflict' };
      }
      const currentTier = kdfTierIndex(current.kdf_params);
      if (
        currentTier === null ||
        input.dek_version < current.dek_version ||
        input.master_password_version < current.master_password_version ||
        targetTier < currentTier
      ) {
        return { kind: 'conflict' };
      }

      const versionAdvanced = input.dek_version > current.dek_version ||
        input.master_password_version > current.master_password_version;
      if (!versionAdvanced && targetTier <= currentTier) return { kind: 'conflict' };

      const updated = await first<VaultKeyRow>(connection,
        `UPDATE dek_wrappings
         SET wrapped_dek = $2, nonce = $3, kdf_salt = $4, kdf_params = $5,
             dek_version = $6, master_password_version = $7
         WHERE user_id = $1
         RETURNING wrapped_dek, nonce, kdf_salt, kdf_params, dek_version, master_password_version`,
        [userId, input.wrapped_dek, input.nonce, input.kdf_salt, input.kdf_params,
          input.dek_version, input.master_password_version]);
      return updated === null
        ? { kind: 'conflict' }
        : { kind: 'ok', record: mapVaultKey(updated) };
    });
  }

  async findVaultItemsByDomainHmac(
    userId: string,
    domainHmac: string,
    limit: number,
  ): Promise<readonly VaultDomainMatch[]> {
    const result = await this.database.query<{
      id: string;
      overview_ciphertext: string | null;
      overview_nonce: string | null;
    }>(
      `SELECT id, overview_ciphertext, overview_nonce
       FROM vault_items
       WHERE user_id = $1 AND domain_hmac = $2 AND deleted_at IS NULL
       ORDER BY id ASC
       LIMIT $3`,
      [userId, domainHmac, limit],
    );
    return result.rows.map((row) => {
      if (row.overview_ciphertext === null || row.overview_nonce === null) {
        throw new Error('An active vault item is missing its overview ciphertext.');
      }
      return {
        id: row.id,
        overview_ciphertext: row.overview_ciphertext,
        overview_nonce: row.overview_nonce,
      };
    });
  }

  async listVaultPage(
    userId: string,
    cursor: string | null,
    limit: number,
    serverTime: Date,
  ): Promise<VaultPage | null> {
    if (cursor !== null) {
      const cursorRow = await first<{ id: string }>(this.database,
        'SELECT id FROM vault_items WHERE id = $1 AND user_id = $2', [cursor, userId]);
      if (cursorRow === null) return null;
    }

    const metadata = await first<{
      master_password_version: string | number | bigint | null;
      dek_version: string | number | bigint | null;
    }>(this.database,
      `SELECT d.master_password_version, d.dek_version
       FROM users u
       LEFT JOIN dek_wrappings d ON d.user_id = u.id
       WHERE u.id = $1`, [userId]);
    if (metadata === null) return null;

    const result = await this.database.query<VaultRow>(
      `SELECT id, user_id, version, overview_ciphertext, overview_nonce,
              detail_ciphertext, detail_nonce, domain_hmac, updated_at, deleted_at,
              device_id, deleted_by_device_id
       FROM vault_items
       WHERE user_id = $1 AND deleted_at IS NULL AND ($2::uuid IS NULL OR id > $2::uuid)
       ORDER BY id ASC
       LIMIT $3`,
      [userId, cursor, limit + 1],
    );
    const hasMore = result.rows.length > limit;
    const pageRows = result.rows.slice(0, limit);
    const items: VaultListItem[] = pageRows.map((row) => {
      if (
        row.overview_ciphertext === null || row.overview_nonce === null ||
        row.detail_ciphertext === null || row.detail_nonce === null
      ) {
        throw new Error('An active vault item is missing an encrypted field.');
      }
      const updatedAt = timestampIso(row.updated_at);
      if (updatedAt === null) throw new Error('An active vault item must have updated_at.');
      return {
        id: row.id,
        version: apiVersion(row.version),
        overview_ciphertext: row.overview_ciphertext,
        overview_nonce: row.overview_nonce,
        detail_ciphertext: row.detail_ciphertext,
        detail_nonce: row.detail_nonce,
        domain_hmac: row.domain_hmac,
        updated_at: updatedAt,
        device_id: row.device_id,
      };
    });
    const masterPasswordVersion = metadata.master_password_version;
    const dekVersion = metadata.dek_version;
    return {
      items,
      has_more: hasMore,
      next_cursor: hasMore ? (items.at(-1)?.id ?? null) : null,
      server_time: serverTime.toISOString(),
      master_password_version: masterPasswordVersion === null ? 0 : apiVersion(masterPasswordVersion),
      dek_version: dekVersion === null ? 0 : apiVersion(dekVersion),
    };
  }

  async getVaultItemStatus(userId: string, itemId: string): Promise<VaultItemStatus | null> {
    const row = await first<VaultRow>(this.database,
      `SELECT id, user_id, version, device_id, deleted_by_device_id, deleted_at
       FROM vault_items WHERE id = $1 AND user_id = $2`, [itemId, userId]);
    if (row === null) return null;
    const deletedAt = timestampIso(row.deleted_at);
    if (deletedAt !== null) {
      return {
        id: row.id,
        status: 'deleted',
        version: apiVersion(row.version),
        device_id: row.deleted_by_device_id,
        deleted_at: deletedAt,
      };
    }
    return {
      id: row.id,
      status: 'active',
      version: apiVersion(row.version),
      device_id: row.device_id,
    };
  }

  async createVaultItem(userId: string, deviceId: string | null, input: VaultItemInput): Promise<VaultCreateOutcome> {
    return this.database.transaction(async (connection) => {
      const existing = await first<VaultRow>(connection,
        `SELECT id, user_id, version, overview_ciphertext, overview_nonce,
                detail_ciphertext, detail_nonce, domain_hmac, updated_at, deleted_at,
                device_id, deleted_by_device_id
         FROM vault_items WHERE id = $1 FOR UPDATE`, [input.id]);
      if (existing !== null) return existingPostOutcome(existing, userId, input);

      const inserted = await first<VaultWriteRow>(connection,
        `INSERT INTO vault_items
           (id, user_id, overview_ciphertext, overview_nonce, detail_ciphertext, detail_nonce,
            domain_hmac, version, device_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8)
         ON CONFLICT (id) DO NOTHING
         RETURNING id, version, updated_at`,
        [input.id, userId, input.overview_ciphertext, input.overview_nonce,
          input.detail_ciphertext, input.detail_nonce, input.domain_hmac, deviceId]);
      if (inserted !== null) {
        return { kind: 'ok', item: mapVaultItemResponse(inserted), replayed: false };
      }

      // A concurrent POST may have inserted this primary key after the initial read.
      const raced = await first<VaultRow>(connection,
        `SELECT id, user_id, version, overview_ciphertext, overview_nonce,
                detail_ciphertext, detail_nonce, domain_hmac, updated_at, deleted_at,
                device_id, deleted_by_device_id
         FROM vault_items WHERE id = $1 FOR UPDATE`, [input.id]);
      if (raced === null) throw new Error('A conflicting vault insert disappeared before it could be read.');
      return existingPostOutcome(raced, userId, input);
    });
  }

  async updateVaultItem(
    userId: string,
    deviceId: string,
    itemId: string,
    baseVersion: number,
    input: VaultItemInput,
  ): Promise<VaultUpdateOutcome> {
    return this.database.transaction(async (connection) => {
      const row = await first<VaultRow>(connection,
        `SELECT id, user_id, version, overview_ciphertext, overview_nonce,
                detail_ciphertext, detail_nonce, domain_hmac, updated_at, deleted_at,
                device_id, deleted_by_device_id
         FROM vault_items WHERE id = $1 FOR UPDATE`, [itemId]);
      if (row === null || row.user_id !== userId) return { kind: 'not_found' };
      if (row.deleted_at !== null) return { kind: 'deleted' };

      const currentVersion = BigInt(row.version);
      const base = BigInt(baseVersion);
      const clientVersion = BigInt(input.version);
      if (clientVersion <= base) return { kind: 'version_conflict' };

      if (currentVersion === clientVersion && row.device_id === deviceId) {
        if (samePayload(row, input)) {
          return { kind: 'ok', item: mapVaultItemResponse(row), replayed: true };
        }
        return { kind: 'already_applied_payload_mismatch' };
      }
      if (base > currentVersion) return { kind: 'server_behind' };
      if (base < currentVersion) return { kind: 'version_conflict' };

      const updated = await first<VaultWriteRow>(connection,
        `UPDATE vault_items
         SET overview_ciphertext = $3, overview_nonce = $4,
             detail_ciphertext = $5, detail_nonce = $6, domain_hmac = $7,
             version = $8, device_id = $9
         WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL
         RETURNING id, version, updated_at`,
        [itemId, userId, input.overview_ciphertext, input.overview_nonce,
          input.detail_ciphertext, input.detail_nonce, input.domain_hmac, input.version, deviceId]);
      if (updated === null) return { kind: 'not_found' };
      return { kind: 'ok', item: mapVaultItemResponse(updated), replayed: false };
    });
  }

  async deleteVaultItem(
    userId: string,
    deviceId: string,
    itemId: string,
    baseVersion: number,
  ): Promise<VaultDeleteOutcome> {
    return this.database.transaction(async (connection) => {
      const row = await first<VaultRow>(connection,
        `SELECT id, user_id, version, overview_ciphertext, overview_nonce,
                detail_ciphertext, detail_nonce, domain_hmac, updated_at, deleted_at,
                device_id, deleted_by_device_id
         FROM vault_items WHERE id = $1 FOR UPDATE`, [itemId]);
      if (row === null || row.user_id !== userId) return { kind: 'not_found' };

      const base = BigInt(baseVersion);
      const currentVersion = BigInt(row.version);
      if (row.deleted_at !== null) {
        if (currentVersion === base + 1n && row.deleted_by_device_id === deviceId) {
          const deletedAt = timestampIso(row.deleted_at);
          if (deletedAt === null) throw new Error('A deleted vault item must have deleted_at.');
          return {
            kind: 'ok',
            item: { id: row.id, version: apiVersion(row.version), deleted_at: deletedAt },
            replayed: true,
          };
        }
        return { kind: 'version_conflict' };
      }
      if (currentVersion !== base || base >= BigInt(Number.MAX_SAFE_INTEGER)) {
        return { kind: 'version_conflict' };
      }

      const newVersion = base + 1n;
      const deleted = await first<VaultWriteRow>(connection,
        `UPDATE vault_items
         SET deleted_at = now(), deleted_by_device_id = $3, version = $4
         WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL
         RETURNING id, version, deleted_at`,
        [itemId, userId, deviceId, newVersion.toString()]);
      if (deleted === null) return { kind: 'version_conflict' };
      const deletedAt = timestampIso(deleted.deleted_at ?? null);
      if (deletedAt === null) throw new Error('The delete operation did not set deleted_at.');
      return {
        kind: 'ok',
        item: { id: deleted.id, version: apiVersion(deleted.version), deleted_at: deletedAt },
        replayed: false,
      };
    });
  }

  async cleanupExpiredTombstones(now: Date): Promise<number> {
    const cutoff = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    return this.database.transaction(async (connection) => {
      const result = await connection.query<{ id: string }>(
        `UPDATE vault_items
         SET overview_ciphertext = NULL,
             overview_nonce = NULL,
             detail_ciphertext = NULL,
             detail_nonce = NULL,
             domain_hmac = NULL,
             device_id = NULL,
             updated_at = NULL
         WHERE deleted_at IS NOT NULL
           AND deleted_at <= $1
           AND overview_ciphertext IS NOT NULL
         RETURNING id`,
        [cutoff],
      );
      return result.rows.length;
    });
  }
}
