export const ADMIN_SETTING_FIELDS = [
  { key: 'server_name', kind: 'string', defaultValue: 'Sealero', constraintKey: 'constraints.serverName' },
  { key: 'allow_registration', kind: 'boolean', defaultValue: true, constraintKey: 'constraints.boolean' },
  { key: 'require_email_verification', kind: 'boolean', defaultValue: true, constraintKey: 'constraints.boolean' },
  { key: 'max_vault_size_mb', kind: 'integer', defaultValue: 100, constraintKey: 'constraints.maxVaultSize' },
  { key: 'smtp_host', kind: 'nullable-string', defaultValue: null, constraintKey: 'constraints.smtpHost' },
  { key: 'smtp_port', kind: 'nullable-integer', defaultValue: null, constraintKey: 'constraints.smtpPort' },
  { key: 'smtp_user', kind: 'nullable-string', defaultValue: null, constraintKey: 'constraints.smtpUser' },
  { key: 'smtp_pass', kind: 'write-only-secret', defaultValue: null, constraintKey: 'constraints.smtpPass' },
  { key: 'smtp_from', kind: 'nullable-email', defaultValue: null, constraintKey: 'constraints.smtpFrom' },
  { key: 'smtp_secure', kind: 'boolean', defaultValue: false, constraintKey: 'constraints.boolean' },
  { key: 'min_app_version_android', kind: 'nullable-semver', defaultValue: null, constraintKey: 'constraints.semver' },
  { key: 'min_app_version_ios', kind: 'nullable-semver', defaultValue: null, constraintKey: 'constraints.semver' },
  { key: 'min_app_version_web', kind: 'nullable-semver', defaultValue: null, constraintKey: 'constraints.semver' },
] as const

export type AdminSettingKey = (typeof ADMIN_SETTING_FIELDS)[number]['key']
export type AdminSettingSource = 'db' | 'env' | 'default'

/** GET /v1/admin/settings never includes the SMTP password value. */
export interface AdminSettings {
  readonly server_name: string
  readonly allow_registration: boolean
  readonly require_email_verification: boolean
  readonly max_vault_size_mb: number
  readonly smtp_host: string | null
  readonly smtp_port: number | null
  readonly smtp_user: string | null
  readonly smtp_from: string | null
  readonly smtp_secure: boolean
  readonly min_app_version_android: string | null
  readonly min_app_version_ios: string | null
  readonly min_app_version_web: string | null
}

export interface AdminOverviewResponse {
  readonly total_users: number
  readonly today_new_users: number
  readonly today_active_users: number
  readonly total_devices: number
  readonly db_connections: number
  readonly tombstone_cleanup: {
    readonly last_cleanup_at: string | null
    readonly last_cleanup_status: 'success' | 'failed' | null
  }
}

export interface AdminOverviewTrendDay {
  readonly date: string
  readonly new_users: number
  readonly active_users: number
}

export interface AdminOverviewTrendResponse {
  readonly days: readonly AdminOverviewTrendDay[]
}

/** PUT /v1/admin/settings body: only changed keys; null clears a nullable key. */
export type AdminSettingsUpdate = Partial<Record<AdminSettingKey, string | number | boolean | null>>

export interface AdminSettingsResponse {
  readonly settings: AdminSettings
  /** Includes smtp_pass, whose value is represented only by its source. */
  readonly sources: Readonly<Record<AdminSettingKey, AdminSettingSource>>
  readonly smtp_pass_configured: boolean
  readonly tombstone_retention_days: 30
}

export interface AdminPage<T> {
  readonly items: readonly T[]
  readonly total_count: number
  readonly has_more: boolean
  readonly next_cursor: string | null
}
/** GET /v1/admin/users returns `users`, not the generic page's `items` field. */
export interface UsersResponse {
  readonly users: readonly AdminUserListItem[]
  readonly total_count: number
  readonly has_more: boolean
  readonly next_cursor: string | null
}
export interface AdminUserDevice {
  readonly id: string
  readonly device_name: string
  readonly device_type: 'app' | 'extension' | 'web'
  readonly revoked_at: string | null
  readonly created_at: string
  readonly last_login_at: string | null
}
export interface AdminLoginHistoryEntry {
  readonly id: string
  readonly device_id: string | null
  readonly device_name: string | null
  readonly ip_address: string | null
  readonly user_agent: string | null
  readonly result: 'success' | 'failed'
  readonly failure_code: string | null
  readonly created_at: string
}
export interface AdminUserDetailResponse {
  readonly user: AdminUserListItem
  readonly devices: readonly AdminUserDevice[]
  readonly login_history: AdminPage<AdminLoginHistoryEntry>
}

export const ADMIN_AUDIT_ACTIONS = [
  'user_disable',
  'user_enable',
  'user_delete',
  'device_revoke',
  'settings_update',
  'make_admin',
  'remove_admin',
] as const

export type AdminAuditAction = (typeof ADMIN_AUDIT_ACTIONS)[number]
export type AdminAuditMetadata =
  | { readonly keys_changed: readonly AdminSettingKey[] }
  | { readonly device_id: string }
  | Readonly<Record<string, never>>

export interface AdminAuditRow {
  readonly id: string
  readonly actor_user_id: string | null
  readonly target_user_id: string | null
  readonly action: string
  readonly target_type: string | null
  readonly metadata: AdminAuditMetadata
  readonly ip_address: string | null
  readonly created_at: string
}
/** GET /v1/admin/audit uses the generic `items` page shape. */
export type AdminAuditResponse = AdminPage<AdminAuditRow>

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const settingKeySet = new Set<string>(ADMIN_SETTING_FIELDS.map(({ key }) => key))

/** Keep only metadata explicitly allowed by System Design v1.46 §5.2. */
export function sanitizeAuditMetadata(action: string, metadata: unknown): Record<string, string | string[]> {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) return {}
  const record = metadata as Record<string, unknown>

  if (action === 'settings_update' && Array.isArray(record.keys_changed)) {
    const keysChanged = [...new Set(record.keys_changed.filter(
      (key): key is string => typeof key === 'string' && settingKeySet.has(key),
    ))]
    return { keys_changed: keysChanged }
  }

  if (action === 'device_revoke' && typeof record.device_id === 'string' && uuidPattern.test(record.device_id)) {
    return { device_id: record.device_id }
  }

  return {}
}

export const ADMIN_USER_FILTER_OPTIONS = {
  status: ['all', 'active', 'disabled'],
  verified: ['all', 'verified', 'unverified'],
  role: ['all', 'admin', 'user'],
} as const

export const ADMIN_USER_LIST_COLUMNS = [
  'email',
  'created_at',
  'last_login_at',
  'email_verified_at',
  'is_admin',
  'is_super_admin',
  'disabled_at',
  'device_count',
  'ciphertext_total_bytes',
] as const

export const ADMIN_USER_DEVICE_COLUMNS = [
  'device_name',
  'device_type',
  'created_at',
  'last_login_at',
] as const

export const ADMIN_USER_LOGIN_COLUMNS = [
  'created_at',
  'device_name',
  'device_id',
  'ip_address',
  'user_agent',
  'result',
  'failure_code',
] as const

export const ADMIN_USER_ACTIONS = [
  'disable',
  'enable',
  'delete',
  'make_admin',
  'remove_admin',
] as const

/**
 * User actions that require the administrator to re-enter their login
 * password (System Design §5.2). Kept separate from ADMIN_USER_ACTIONS:
 * that list is pinned by contract tests, and revoke-all is not part of it.
 */
export const ADMIN_USER_PASSWORD_ACTIONS = [
  'delete',
  'revoke_all_devices',
] as const

/** Single-device revocation is per-device; revoking all of a user's devices is a user action. */
export const ADMIN_DEVICE_ACTIONS = ['revoke'] as const

export interface AdminUserListItem {
  readonly id: string
  readonly email: string
  readonly created_at: string
  readonly email_verified_at: string | null
  readonly disabled_at: string | null
  readonly is_admin: boolean
  readonly is_super_admin: boolean
  readonly device_count: number
  readonly last_login_at: string | null
  readonly ciphertext_total_bytes: number
}
