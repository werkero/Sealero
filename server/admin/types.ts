export type AdminUserStatusFilter = 'all' | 'active' | 'disabled';
export type AdminUserVerifiedFilter = 'all' | 'verified' | 'unverified';
export type AdminUserRoleFilter = 'all' | 'admin' | 'user' | 'super_admin';

export interface AdminUserListQuery {
  readonly search: string | null;
  readonly status: AdminUserStatusFilter;
  readonly verified: AdminUserVerifiedFilter;
  readonly role: AdminUserRoleFilter;
  readonly cursor: string | null;
  readonly limit: number;
}

export interface AdminPage<T> {
  readonly items: readonly T[];
  readonly total_count: number;
  readonly has_more: boolean;
  readonly next_cursor: string | null;
}

export interface AdminUserSummary {
  readonly id: string;
  readonly email: string;
  readonly created_at: string;
  readonly email_verified_at: string | null;
  readonly disabled_at: string | null;
  readonly is_admin: boolean;
  readonly is_super_admin: boolean;
  readonly device_count: number;
  readonly last_login_at: string | null;
  readonly ciphertext_total_bytes: number;
}

export type AdminDeviceType = 'app' | 'extension' | 'web';

export interface AdminDeviceSummary {
  readonly id: string;
  readonly device_name: string;
  readonly device_type: AdminDeviceType;
  readonly revoked_at: string | null;
  readonly created_at: string;
  readonly last_login_at: string | null;
}

export interface AdminLoginHistoryEntry {
  readonly id: string;
  readonly device_id: string | null;
  readonly device_name: string | null;
  readonly ip_address: string | null;
  readonly user_agent: string | null;
  readonly result: 'success' | 'failed';
  readonly failure_code: string | null;
  readonly created_at: string;
}

export interface AdminUserDetailBase {
  readonly user: AdminUserSummary;
  readonly devices: readonly AdminDeviceSummary[];
}

export const ADMIN_SETTING_KEYS = [
  'server_name',
  'allow_registration',
  'require_email_verification',
  'max_vault_size_mb',
  'smtp_host',
  'smtp_port',
  'smtp_user',
  'smtp_pass',
  'smtp_from',
  'smtp_secure',
  'min_app_version_android',
  'min_app_version_ios',
  'min_app_version_web',
] as const;

export type AdminSettingKey = (typeof ADMIN_SETTING_KEYS)[number];
export type AdminSettingSource = 'db' | 'env' | 'default';
export type PublicAdminSettingKey = Exclude<AdminSettingKey, 'smtp_pass'>;
export type AdminSettingEnvironmentValue = string | number | boolean;

export interface AdminSettingsEnvironment {
  readonly values: Readonly<Partial<Record<PublicAdminSettingKey, AdminSettingEnvironmentValue>>>;
  readonly smtpPassConfigured: boolean;
}

export interface AdminSettings {
  readonly server_name: string;
  readonly allow_registration: boolean;
  readonly require_email_verification: boolean;
  readonly max_vault_size_mb: number;
  readonly smtp_host: string | null;
  readonly smtp_port: number | null;
  readonly smtp_user: string | null;
  readonly smtp_from: string | null;
  readonly smtp_secure: boolean;
  readonly min_app_version_android: string | null;
  readonly min_app_version_ios: string | null;
  readonly min_app_version_web: string | null;
}

export interface AdminSettingsResponse {
  readonly settings: AdminSettings;
  readonly sources: Readonly<Record<AdminSettingKey, AdminSettingSource>>;
  readonly smtp_pass_configured: boolean;
  readonly tombstone_retention_days: 30;
}

export interface AdminHealthSettings {
  readonly server_name: string;
  readonly min_app_versions: {
    readonly android: string | null;
    readonly ios: string | null;
    readonly web: string | null;
  };
}

export type AdminAuditMetadata =
  | { readonly keys_changed: readonly AdminSettingKey[] }
  | { readonly device_id: string }
  | Readonly<Record<string, never>>;

export interface AdminAuditEntry {
  readonly id: string;
  readonly actor_user_id: string | null;
  readonly target_user_id: string | null;
  readonly action: string;
  readonly target_type: string | null;
  readonly metadata: AdminAuditMetadata;
  readonly ip_address: string | null;
  readonly created_at: string;
}

export interface AdminAuditQuery {
  readonly actorUserId: string | null;
  readonly targetUserId: string | null;
  readonly action: string | null;
  readonly from: Date | null;
  readonly to: Date | null;
  readonly cursor: string | null;
  readonly limit: number;
}

export interface AdminUserReadStore {
  hasAdminRole(userId: string): Promise<boolean>;
  listAdminUsers(query: AdminUserListQuery): Promise<AdminPage<AdminUserSummary> | null>;
  getAdminUser(userId: string): Promise<AdminUserDetailBase | null>;
  listAdminUserLoginHistory(
    userId: string,
    cursor: string | null,
    limit: number,
  ): Promise<AdminPage<AdminLoginHistoryEntry> | null>;
  findAdminDeviceOwner(deviceId: string): Promise<string | null>;
}

export interface AdminOverview {
  readonly total_users: number;
  readonly today_new_users: number;
  readonly today_active_users: number;
  readonly total_devices: number;
  readonly db_connections: number;
  readonly tombstone_cleanup: {
    readonly last_cleanup_at: string | null;
    readonly last_cleanup_status: 'success' | 'failed' | null;
  };
}

/** One UTC day in the admin overview trend. */
export interface AdminOverviewTrendDay {
  readonly date: string;
  readonly new_users: number;
  readonly active_users: number;
}

/** Daily new/active users for the last `days` UTC days, ending today. */
export interface AdminOverviewTrend {
  readonly days: readonly AdminOverviewTrendDay[];
}

/** One dumped table row: column name to its JSON value (dates as ISO 8601 strings). */
export type DbDumpRow = Readonly<Record<string, string | number | boolean | null>>;

/** All 18 tables by name, in dump order, each row already normalized for canonical JSON. */
export type DbDumpTables = Readonly<Record<string, readonly DbDumpRow[]>>;

export interface AdminConsoleReadStore {
  listAdminSettings(): Promise<Readonly<Record<string, string>>>;
  listAdminAuditLogs(query: AdminAuditQuery): Promise<AdminPage<AdminAuditEntry> | null>;
  getAdminOverview(now: Date): Promise<AdminOverview>;
  getAdminOverviewTrend(now: Date, days: number): Promise<AdminOverviewTrend>;
}

/** One RBAC permission: a `<module>:<action>` key from the catalog (SD §3.1). */
export interface AdminPermission {
  readonly key: string;
  readonly module: string;
  readonly description: string | null;
}

/** One role with its permission keys and user count (SD §3.1, §5.2). */
export interface AdminRole {
  readonly id: string;
  readonly name: string;
  readonly description: string | null;
  readonly created_at: string;
  /** True for the seed roles admin, user, super_admin. */
  readonly is_system: boolean;
  /** Permission keys; super_admin always lists all 7. */
  readonly permission_keys: readonly string[];
  readonly user_count: number;
}

export type AdminRoleMutationOutcome =
  | 'success'
  | 'not_found'
  | 'forbidden'
  | 'action_forbidden'
  | 'invalid_name'
  | 'name_taken'
  | 'invalid_permissions'
  | 'actor_missing'
  | 'actor_disabled'
  | 'target_missing';

export interface AdminRoleStore {
  hasPermission(userId: string, permissionKey: string): Promise<boolean>;
  getUserPermissions(userId: string): Promise<readonly string[]>;
  listPermissions(): Promise<readonly AdminPermission[]>;
  listRoles(): Promise<readonly AdminRole[]>;
  getRole(roleId: string): Promise<AdminRole | null>;
  listRoleUsers(roleId: string, cursor: string | null, limit: number): Promise<AdminPage<AdminUserSummary> | null>;
}
