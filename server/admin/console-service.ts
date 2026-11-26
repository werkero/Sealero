import { isIP } from 'node:net';
import { ApiError } from '../app.js';
import type { AppConfig } from '../config.js';
import type { AuthService } from '../auth/auth-service.js';
import { AuthServiceError } from '../auth/auth-service.js';
import { verifyLoginPassword } from '../auth/password.js';
import type { AuthStore, AuthTransaction, LoginRequestMetadata } from '../auth/types.js';
import type {
  AdminHealthSettings,
  AdminAuditQuery,
  AdminConsoleReadStore,
  AdminOverview,
  AdminSettingKey,
  AdminSettingSource,
  AdminSettings,
  AdminSettingsEnvironment,
  AdminSettingsResponse,
} from './types.js';
import { ADMIN_SETTING_KEYS } from './types.js';
import {
  buildDbDumpDocument,
  canonicalJson,
  dbDumpFilename,
  encryptDbDump,
  type EncryptedDbDump,
} from './db-dump.js';

const DEFAULT_SETTINGS: AdminSettings = {
  server_name: 'Sealero',
  allow_registration: true,
  require_email_verification: true,
  max_vault_size_mb: 100,
  smtp_host: null,
  smtp_port: null,
  smtp_user: null,
  smtp_from: null,
  smtp_secure: false,
  min_app_version_android: null,
  min_app_version_ios: null,
  min_app_version_web: null,
};

const SETTING_KEY_SET = new Set<string>(ADMIN_SETTING_KEYS);
const VALID_ADMIN_SETTING_KEYS = new Set<AdminSettingKey>(ADMIN_SETTING_KEYS);
const NULLABLE_SETTING_KEYS = new Set<AdminSettingKey>([
  'smtp_host',
  'smtp_port',
  'smtp_user',
  'smtp_pass',
  'smtp_from',
  'min_app_version_android',
  'min_app_version_ios',
  'min_app_version_web',
]);
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

type AdminSettingsStore = AuthStore & AdminConsoleReadStore;
type SettingScalar = string | number | boolean;
type ValidatedUpdates = ReadonlyMap<AdminSettingKey, SettingScalar | null>;
type EffectiveSettings = {
  readonly settings: AdminSettings;
  readonly sources: Readonly<Record<AdminSettingKey, AdminSettingSource>>;
  readonly smtpPassConfigured: boolean;
};
type SettingValidationSource = 'request' | 'stored' | 'environment';
type RoleOutcome = 'success' | 'not_found' | 'disabled' | 'forbidden';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function rejectSettingValue(key: string, source: SettingValidationSource): never {
  if (source === 'request') {
    throw new ApiError(400, 'invalid_setting_value', `The ${key} value is invalid.`);
  }
  throw new Error(`Configured ${key} setting is invalid.`);
}

function stringLength(value: string): number {
  return [...value].length;
}

function validHostname(value: string): boolean {
  if (isIP(value) !== 0) return true;
  if (value.length > 253 || value.includes('://') || /[\s/:?#@]/.test(value)) return false;
  const hostname = value.endsWith('.') ? value.slice(0, -1) : value;
  if (hostname.length === 0) return false;
  return hostname.split('.').every((label) =>
    label.length >= 1 && label.length <= 63 &&
    /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(label),
  );
}

function validEmail(value: string): boolean {
  if (stringLength(value) > 255 || /\s/.test(value)) return false;
  const at = value.indexOf('@');
  if (at <= 0 || at !== value.lastIndexOf('@') || at === value.length - 1) return false;

  const local = value.slice(0, at);
  const domain = value.slice(at + 1);
  if (stringLength(local) > 64 || domain.length > 253) return false;
  const localAtoms = local.split('.');
  if (!localAtoms.every((atom) => /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+$/.test(atom))) return false;

  const labels = domain.split('.');
  return labels.length >= 2 && labels.every((label) =>
    label.length >= 1 && label.length <= 63 &&
    /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(label),
  );
}

function validateSettingValue(
  key: AdminSettingKey,
  value: unknown,
  source: SettingValidationSource,
): SettingScalar | null {
  if (value === null) {
    if (source === 'request' || NULLABLE_SETTING_KEYS.has(key)) return null;
    return rejectSettingValue(key, source);
  }

  if (key === 'server_name') {
    if (typeof value !== 'string') return rejectSettingValue(key, source);
    const normalized = value.trim();
    const length = stringLength(normalized);
    return length >= 1 && length <= 100 ? normalized : rejectSettingValue(key, source);
  }
  if (key === 'allow_registration' || key === 'require_email_verification' || key === 'smtp_secure') {
    return typeof value === 'boolean' ? value : rejectSettingValue(key, source);
  }
  if (key === 'max_vault_size_mb') {
    return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1 && value <= 1024
      ? value
      : rejectSettingValue(key, source);
  }
  if (key === 'smtp_port') {
    return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1 && value <= 65535
      ? value
      : rejectSettingValue(key, source);
  }
  if (key === 'smtp_host') {
    return typeof value === 'string' && stringLength(value) >= 1 && stringLength(value) <= 255 && validHostname(value)
      ? value
      : rejectSettingValue(key, source);
  }
  if (key === 'smtp_user') {
    return typeof value === 'string' && stringLength(value) >= 1 && stringLength(value) <= 255
      ? value
      : rejectSettingValue(key, source);
  }
  if (key === 'smtp_pass') {
    return typeof value === 'string' && stringLength(value) >= 1 && stringLength(value) <= 1024
      ? value
      : rejectSettingValue(key, source);
  }
  if (key === 'smtp_from') {
    return typeof value === 'string' && stringLength(value) >= 1 && stringLength(value) <= 255 && validEmail(value)
      ? value
      : rejectSettingValue(key, source);
  }

  if (
    key === 'min_app_version_android' || key === 'min_app_version_ios' || key === 'min_app_version_web'
  ) {
    if (typeof value !== 'string' || !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(value)) {
      return rejectSettingValue(key, source);
    }
    const segments = value.split('.').map(Number);
    return segments.every(Number.isSafeInteger) ? value : rejectSettingValue(key, source);
  }

  return rejectSettingValue(key, source);
}

function parseStoredSetting(key: AdminSettingKey, value: string): SettingScalar {
  let parsed: unknown = value;
  if (key === 'allow_registration' || key === 'require_email_verification' || key === 'smtp_secure') {
    if (value !== 'true' && value !== 'false') return rejectSettingValue(key, 'stored');
    parsed = value === 'true';
  } else if (key === 'max_vault_size_mb' || key === 'smtp_port') {
    if (!/^[0-9]+$/.test(value)) return rejectSettingValue(key, 'stored');
    parsed = Number(value);
  }
  const normalized = validateSettingValue(key, parsed, 'stored');
  if (normalized === null) return rejectSettingValue(key, 'stored');
  return normalized;
}

function parseEnvironmentSetting(
  key: Exclude<AdminSettingKey, 'smtp_pass'>,
  value: SettingScalar,
): SettingScalar {
  const normalized = validateSettingValue(key, value, 'environment');
  if (normalized === null) return rejectSettingValue(key, 'environment');
  return normalized;
}

function environmentFromConfig(config: AppConfig): AdminSettingsEnvironment {
  if (config.adminSettingsEnvironment !== undefined) return config.adminSettingsEnvironment;
  if (config.serverName === 'Sealero') return { values: {}, smtpPassConfigured: false };
  return {
    values: { server_name: config.serverName },
    smtpPassConfigured: false,
  };
}

function effectiveSettings(
  databaseSettings: Readonly<Record<string, string>>,
  environment: AdminSettingsEnvironment,
): EffectiveSettings {
  const settings = { ...DEFAULT_SETTINGS };
  const sources = {} as Record<AdminSettingKey, AdminSettingSource>;

  for (const key of ADMIN_SETTING_KEYS) {
    const stored = databaseSettings[key];
    if (stored !== undefined) {
      sources[key] = 'db';
      if (key === 'smtp_pass') {
        if (validateSettingValue(key, stored, 'stored') === null) throw new Error('A stored SMTP password cannot be null.');
        continue;
      }
      const parsed = parseStoredSetting(key, stored);
      (settings as unknown as Record<string, SettingScalar | null>)[key] = parsed;
      continue;
    }
    if (key === 'smtp_pass') {
      sources[key] = environment.smtpPassConfigured ? 'env' : 'default';
      continue;
    }
    const configuredValue = environment.values[key];
    if (configuredValue !== undefined) {
      sources[key] = 'env';
      (settings as unknown as Record<string, SettingScalar | null>)[key] = parseEnvironmentSetting(key, configuredValue);
    } else {
      sources[key] = 'default';
    }
  }

  return {
    settings,
    sources,
    smtpPassConfigured: databaseSettings['smtp_pass'] !== undefined || environment.smtpPassConfigured,
  };
}

function settingsResponse(effective: EffectiveSettings): AdminSettingsResponse {
  return {
    settings: effective.settings,
    sources: effective.sources,
    smtp_pass_configured: effective.smtpPassConfigured,
    tombstone_retention_days: 30,
  };
}

function parseUpdates(input: unknown): ValidatedUpdates {
  if (!isRecord(input)) {
    throw new ApiError(400, 'invalid_setting_value', 'The settings body must be an object.');
  }
  const updates = new Map<AdminSettingKey, SettingScalar | null>();
  for (const [key, value] of Object.entries(input)) {
    if (!SETTING_KEY_SET.has(key)) {
      throw new ApiError(400, 'unknown_setting_key', `The ${key} setting is not recognized.`);
    }
    const settingKey = key as AdminSettingKey;
    updates.set(settingKey, validateSettingValue(settingKey, value, 'request'));
  }
  return updates;
}

function serializeSetting(value: SettingScalar): string {
  return typeof value === 'string' ? value : String(value);
}

function validateSmtpCombination(effective: EffectiveSettings): void {
  const settings = effective.settings;
  const smtpTriplet = [settings.smtp_host, settings.smtp_port, settings.smtp_from];
  const hasCompleteSmtp = smtpTriplet.every((value) => value !== null);
  const hasAnySmtp = smtpTriplet.some((value) => value !== null);

  // A partially configured SMTP triplet is the more specific error and is
  // reported first, whether or not verification is required; otherwise the
  // smtp_incomplete branch would be unreachable now that verification is
  // on by default. No SMTP at all with verification on is smtp_not_configured.
  if (hasAnySmtp && !hasCompleteSmtp) {
    throw new ApiError(400, 'smtp_incomplete', 'The smtp_host, smtp_port, and smtp_from settings must be configured together.');
  }
  if (settings.require_email_verification && !hasCompleteSmtp) {
    throw new ApiError(400, 'smtp_not_configured', 'SMTP must be configured before email verification is required.');
  }
  if (settings.smtp_user !== null && !effective.smtpPassConfigured) {
    throw new ApiError(400, 'smtp_incomplete', 'The smtp_user setting requires smtp_pass to be configured.');
  }
}

function hasAdminRole(roles: readonly string[]): boolean {
  return roles.includes('admin') || roles.includes('super_admin');
}

async function actorRoleOutcome(transaction: AuthTransaction, actorId: string): Promise<RoleOutcome> {
  const actor = await transaction.findUserForUpdate(actorId);
  if (actor === null) return 'not_found';
  if (actor.disabledAt !== null) return 'disabled';
  return hasAdminRole(await transaction.findUserRolesForUpdate(actorId)) ? 'success' : 'forbidden';
}

function requireActorRole(outcome: RoleOutcome): void {
  if (outcome === 'success') return;
  if (outcome === 'not_found') throw new ApiError(401, 'unauthorized', 'A valid access token is required.');
  if (outcome === 'disabled') throw new ApiError(403, 'account_disabled', 'This account is disabled.');
  throw new ApiError(403, 'admin_required', 'Administrator access is required.');
}

export interface AdminDbDumpFile extends EncryptedDbDump {
  readonly filename: string;
}

type DbDumpOutcome =
  | 'success'
  | 'actor_missing'
  | 'actor_disabled'
  | 'forbidden'
  | 'invalid_password';

export class AdminConsoleService {
  private readonly environment: AdminSettingsEnvironment;

  constructor(
    private readonly store: AdminSettingsStore,
    config: AppConfig,
    private readonly now: () => Date = () => new Date(),
    private readonly options: {
      readonly authService?: AuthService | undefined;
      readonly dbDumpKey?: Buffer | undefined;
    } = {},
  ) {
    this.environment = environmentFromConfig(config);
  }

  async getOverview(): Promise<AdminOverview> {
    return this.store.getAdminOverview(this.now());
  }

  /**
   * Builds the encrypted database dump (System Design §5.2). The caller
   * streams the returned header line and ciphertext back without writing a
   * temporary file. The whole-database read and the db_dump audit log run in
   * the same transaction as the password check, so the dump is one snapshot.
   */
  async createDbDump(
    actorId: string,
    loginPassword: string,
    metadata: LoginRequestMetadata,
  ): Promise<AdminDbDumpFile> {
    const authService = this.options.authService;
    const dbDumpKey = this.options.dbDumpKey;
    if (authService === undefined || dbDumpKey === undefined) {
      throw new ApiError(503, 'db_dump_unavailable', 'The encrypted database dump is not configured.');
    }
    const now = this.now();
    let outcome: DbDumpOutcome;
    let tables: Awaited<ReturnType<AuthTransaction['readDbDumpTables']>> | null = null;
    try {
      outcome = await authService.withVerifiedSensitivePassword(
        actorId,
        loginPassword,
        metadata,
        async (transaction, initialActor) => {
          const actor = await transaction.findUserForUpdate(actorId);
          if (actor === null) return 'actor_missing' as const;
          if (actor.disabledAt !== null) return 'actor_disabled' as const;
          const passwordStillMatches = actor.passwordHash === initialActor.passwordHash
            ? true
            : await verifyLoginPassword(actor.passwordHash, loginPassword);
          if (!passwordStillMatches) return 'invalid_password' as const;
          if (!hasAdminRole(await transaction.findUserRolesForUpdate(actorId))) return 'forbidden' as const;
          tables = await transaction.readDbDumpTables();
          await transaction.insertAuditLog({
            actorUserId: actorId,
            targetUserId: null,
            action: 'db_dump',
            targetType: null,
            metadata: JSON.stringify({}),
            ipAddress: metadata.ipAddress,
            createdAt: now,
          });
          return 'success' as const;
        },
      );
    } catch (error) {
      if (error instanceof AuthServiceError) {
        throw new ApiError(error.status, error.code, error.message, error.retryAfterSeconds);
      }
      throw error;
    }
    if (outcome !== 'success' || tables === null) {
      if (outcome === 'actor_missing') throw new ApiError(401, 'unauthorized', 'A valid access token is required.');
      if (outcome === 'actor_disabled') throw new ApiError(403, 'account_disabled', 'This account is disabled.');
      if (outcome === 'invalid_password') throw new ApiError(401, 'invalid_credentials', 'The login password is incorrect.');
      throw new ApiError(403, 'admin_required', 'Administrator access is required.');
    }
    const document = buildDbDumpDocument(tables, now);
    const encrypted = encryptDbDump(canonicalJson(document), dbDumpKey);
    return { filename: dbDumpFilename(now), ...encrypted };
  }

  async getSettings(): Promise<AdminSettingsResponse> {
    return settingsResponse(effectiveSettings(await this.store.listAdminSettings(), this.environment));
  }

  async getHealthSettings(): Promise<AdminHealthSettings> {
    const settings = effectiveSettings(await this.store.listAdminSettings(), this.environment).settings;
    return {
      server_name: settings.server_name,
      min_app_versions: {
        android: settings.min_app_version_android,
        ios: settings.min_app_version_ios,
        web: settings.min_app_version_web,
      },
    };
  }

  async updateSettings(
    actorId: string,
    ipAddress: string | null,
    input: unknown,
  ): Promise<AdminSettingsResponse> {
    const updates = parseUpdates(input);
    const now = this.now();
    const result = await this.store.transaction(async (transaction) => {
      const roleOutcome = await actorRoleOutcome(transaction, actorId);
      if (roleOutcome !== 'success') return { kind: roleOutcome } as const;

      await transaction.lockSettingsForUpdate();
      const currentRows = await transaction.listSettings();
      const currentSettings: Record<string, string> = Object.fromEntries(
        currentRows.map((row) => [row.key, row.value]),
      );
      const nextSettings: Record<string, string> = { ...currentSettings };
      for (const [key, value] of updates) {
        if (value === null) delete nextSettings[key];
        else nextSettings[key] = serializeSetting(value);
      }
      const effective = effectiveSettings(nextSettings, this.environment);
      validateSmtpCombination(effective);

      const keysChanged: AdminSettingKey[] = [];
      for (const [key, value] of updates) {
        const nextValue = value === null ? undefined : serializeSetting(value);
        if (currentSettings[key] !== nextValue) keysChanged.push(key);
      }
      for (const key of keysChanged) {
        const value = nextSettings[key];
        if (value === undefined) await transaction.deleteSetting(key);
        else await transaction.setSetting(key, value);
      }
      await transaction.insertAuditLog({
        actorUserId: actorId,
        targetUserId: null,
        action: 'settings_update',
        targetType: null,
        metadata: JSON.stringify({ keys_changed: keysChanged }),
        ipAddress,
        createdAt: now,
      });
      return { kind: 'success', settings: nextSettings } as const;
    });

    if (result.kind !== 'success') {
      requireActorRole(result.kind);
      throw new Error('Unreachable admin setting update result.');
    }
    return settingsResponse(effectiveSettings(result.settings, this.environment));
  }

  listAudit(query: AdminAuditQuery) {
    return this.store.listAdminAuditLogs(query);
  }
}

export function parseAdminSettingUpdates(input: unknown): ValidatedUpdates {
  return parseUpdates(input);
}

export function isAdminSettingKey(value: string): value is AdminSettingKey {
  return VALID_ADMIN_SETTING_KEYS.has(value as AdminSettingKey);
}

export function isUuid(value: string): boolean {
  return UUID_PATTERN.test(value);
}
