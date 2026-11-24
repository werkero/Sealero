import type { AdminSettingsEnvironment, AdminSettingEnvironmentValue } from './admin/types.js';

export const ENVIRONMENT_VARIABLE_NAMES = [
  'DATABASE_URL',
  'JWT_PRIVATE_KEY_PATH',
  'JWT_PUBLIC_KEY_PATH',
  'JWT_ACTIVE_KID',
  'JWT_ISSUER',
  'JWT_EXPIRES_IN',
  'REFRESH_TOKEN_EXPIRES_IN',
  'API_BASE_URL',
  'AUTH_MODE',
  'AUTH_CODE_HMAC_SECRET',
  'SERVER_NAME',
  'SMTP_HOST',
  'SMTP_PORT',
  'SMTP_USER',
  'SMTP_PASS',
  'SMTP_FROM',
  'SMTP_SECURE',
  'TOMBSTONE_CLEANUP_SECRET',
  'DB_DUMP_KEY',
] as const satisfies readonly string[];

export type EnvironmentVariableName = (typeof ENVIRONMENT_VARIABLE_NAMES)[number];

export interface AppConfig {
  readonly serverName: string;
  /** Only non-secret values are retained here; SMTP_PASS is represented by a configured flag. */
  readonly adminSettingsEnvironment?: AdminSettingsEnvironment;
}

/** Reads only configuration whose behavior is specified for this scaffold. */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const rawServerName = env['SERVER_NAME'];
  let serverName = 'Sealero';
  if (rawServerName !== undefined) {
    serverName = rawServerName.trim();
    const characterCount = [...serverName].length;
    if (characterCount < 1 || characterCount > 100) {
      throw new Error('SERVER_NAME must contain between 1 and 100 characters.');
    }
  }

  const values: Partial<Record<string, AdminSettingEnvironmentValue>> = {};
  if (rawServerName !== undefined) values['server_name'] = serverName;
  if (env['SMTP_HOST'] !== undefined) values['smtp_host'] = env['SMTP_HOST'];
  if (env['SMTP_PORT'] !== undefined) {
    const rawPort = env['SMTP_PORT'];
    values['smtp_port'] = /^[0-9]+$/.test(rawPort) ? Number(rawPort) : rawPort;
  }
  if (env['SMTP_USER'] !== undefined) values['smtp_user'] = env['SMTP_USER'];
  if (env['SMTP_FROM'] !== undefined) values['smtp_from'] = env['SMTP_FROM'];
  if (env['SMTP_SECURE'] !== undefined) {
    const rawSecure = env['SMTP_SECURE'].trim().toLowerCase();
    values['smtp_secure'] = rawSecure === 'true' ? true : rawSecure === 'false' ? false : env['SMTP_SECURE'];
  }

  const hasAdminSettingsEnvironment = rawServerName !== undefined || [
    'SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS', 'SMTP_FROM', 'SMTP_SECURE',
  ].some((name) => env[name] !== undefined);
  return {
    serverName,
    ...(hasAdminSettingsEnvironment ? {
      adminSettingsEnvironment: {
        values,
        smtpPassConfigured: (env['SMTP_PASS']?.length ?? 0) > 0,
      },
    } : {}),
  };
}
