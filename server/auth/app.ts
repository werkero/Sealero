import { Hono } from 'hono';
import type { Logger } from '../app.js';
import { createApp } from '../app.js';
import type { AppConfig } from '../config.js';
import { createHealthRoutes } from '../routes/health.js';
import { createAuthRoutes } from '../routes/auth.js';
import { AuthService } from './auth-service.js';
import type { AuthServiceOptions } from './auth-service.js';
import type { AuthNotification, AuthStore } from './types.js';
import type { JwtKeySet } from './jwt.js';
import { loadJwtKeySet } from './keyring.js';
import type { JwtKeyEnvironment } from './keyring.js';
import { requireAccessToken } from '../middleware/authentication.js';
import type { AuthenticatedEnvironment } from '../middleware/authentication.js';
import { createSensitiveAuthRoutes } from '../routes/auth-security.js';
import { createVaultRoutes } from '../routes/vault.js';
import { createVaultKeyRoutes } from '../routes/vault-key.js';
import type { VaultKeyStore, VaultStore } from '../vault/types.js';
import { createDeviceRoutes } from '../routes/devices.js';
import type { DeviceRevocationStore } from '../devices/types.js';
import { AdminUserService } from '../admin/admin-user-service.js';
import type { AdminUserReadStore } from '../admin/types.js';
import { createAdminUserRoutes } from '../admin/users.js';
import { AdminConsoleService } from '../admin/console-service.js';
import type { AdminConsoleReadStore } from '../admin/types.js';
import { createAdminConsoleRoutes } from '../admin/console.js';
import { parseDbDumpKey } from '../admin/db-dump.js';
import { createConsentRoutes } from '../routes/consent.js';
import type { PrivacyConsentStore } from './consent-types.js';
import type { DeviceListStore } from '../devices/types.js';
import { isValidPolicyVersion, loadReleaseManifest } from '../release-manifest.js';
import { OAuthService } from '../oauth/oauth-service.js';
import type { McpConfirmationStore, OAuthStore } from '../oauth/types.js';
import { createOAuthRoutes } from '../routes/oauth.js';
import { createMcpRoutes } from '../routes/mcp.js';
import { createMcpConfirmationRoutes } from '../routes/mcp-confirmations.js';

export interface AuthenticatedAppDependencies {
  readonly store: AuthStore & VaultStore & VaultKeyStore & DeviceRevocationStore & DeviceListStore &
    PrivacyConsentStore & AdminUserReadStore & AdminConsoleReadStore & OAuthStore & McpConfirmationStore;
  readonly jwtKeys: JwtKeySet;
  readonly notifications: AuthNotification;
  readonly authCodeHmacSecret: string;
  /** Explicit only for local/test app construction; deployment loads this from release.json. */
  readonly policyVersion?: string;
  readonly serviceOptions?: Omit<AuthServiceOptions, 'authCodeHmacSecret'>;
  /** Defaults to the validated JWT issuer; only local dev may configure a separate loopback origin. */
  readonly siteOrigin?: string;
  /** Must be used only by a server bound to loopback and never enabled in deployment. */
  readonly allowInsecureHttp?: boolean;
  /**
   * AES-256-GCM key for the encrypted database dump (System Design §5.2).
   * Required in deployment (validated at startup by
   * createConfiguredAuthenticatedApp); when absent, POST /v1/admin/db-dump
   * fails closed with 503.
   */
  readonly dbDumpKey?: Buffer;
  /** Business routes mounted behind the per-request account/device status check. */
  readonly protectedRoutes?: Hono<AuthenticatedEnvironment>;
}

export type ConfiguredAuthenticatedAppDependencies = Omit<
  AuthenticatedAppDependencies,
  'jwtKeys' | 'authCodeHmacSecret' | 'policyVersion'
>;

/** Loads and validates the deployment keyring before exposing any authenticated routes. */
export function createConfiguredAuthenticatedApp(
  config: AppConfig,
  dependencies: ConfiguredAuthenticatedAppDependencies,
  env: JwtKeyEnvironment = process.env,
  logger?: Logger,
): Hono {
  const jwtKeys = loadJwtKeySet(env);
  const authCodeHmacSecret = env.AUTH_CODE_HMAC_SECRET;
  if (typeof authCodeHmacSecret !== 'string' || Buffer.byteLength(authCodeHmacSecret, 'utf8') < 32) {
    throw new Error('AUTH_CODE_HMAC_SECRET must contain at least 32 UTF-8 bytes for authentication startup.');
  }
  const dbDumpKey = parseDbDumpKey(env.DB_DUMP_KEY);
  const policyVersion = loadReleaseManifest().policy_version;
  return createAuthenticatedApp(config, { ...dependencies, jwtKeys, authCodeHmacSecret, dbDumpKey, policyVersion }, logger);
}

/** Builds the auth-enabled app; key loading/validation must finish before this factory is called. */
export function createAuthenticatedApp(
  config: AppConfig,
  dependencies: AuthenticatedAppDependencies,
  logger?: Logger,
): Hono {
  if (!dependencies.jwtKeys.publicKeys.has(dependencies.jwtKeys.activeKid)) {
    throw new Error('The active JWT key is missing from the configured JWKS.');
  }
  const policyVersion = dependencies.policyVersion ?? 'local-development';
  if (!isValidPolicyVersion(policyVersion)) {
    throw new Error('A valid privacy policy version is required before authenticated routes can start.');
  }
  const service = new AuthService(
    dependencies.store,
    dependencies.jwtKeys,
    dependencies.notifications,
    {
      authCodeHmacSecret: dependencies.authCodeHmacSecret,
      ...dependencies.serviceOptions,
    },
  );
  const adminConsoleService = new AdminConsoleService(dependencies.store, config, dependencies.serviceOptions?.now, {
    authService: service,
    dbDumpKey: dependencies.dbDumpKey,
  });
  const routes = createHealthRoutes(config, () => adminConsoleService.getHealthSettings(), policyVersion);
  routes.route('/auth', createAuthRoutes(service, {
    siteOrigin: dependencies.siteOrigin ?? dependencies.jwtKeys.issuer,
    allowInsecureHttp: dependencies.allowInsecureHttp ?? false,
  }));
  const securedRoutes = new Hono<AuthenticatedEnvironment>();
  securedRoutes.use('*', requireAccessToken(dependencies.jwtKeys, dependencies.store, dependencies.serviceOptions?.now));
  securedRoutes.route('/auth', createSensitiveAuthRoutes(service, {
    allowInsecureHttp: dependencies.allowInsecureHttp ?? false,
  }));
  const adminUserService = new AdminUserService(dependencies.store, service, dependencies.serviceOptions?.now);
  securedRoutes.route('/admin', createAdminUserRoutes(adminUserService, dependencies.store, {
    allowInsecureHttp: dependencies.allowInsecureHttp ?? false,
  }));
  securedRoutes.route('/admin', createAdminConsoleRoutes(adminConsoleService, dependencies.store, {
    allowInsecureHttp: dependencies.allowInsecureHttp ?? false,
  }));
  securedRoutes.route('/auth', createConsentRoutes(dependencies.store, policyVersion, dependencies.serviceOptions?.now));
  securedRoutes.route('/', createVaultRoutes(dependencies.store, policyVersion, dependencies.serviceOptions?.now));
  securedRoutes.route('/', createMcpConfirmationRoutes(dependencies.store, policyVersion, dependencies.serviceOptions?.now));
  securedRoutes.route('/', createVaultKeyRoutes(dependencies.store, policyVersion));
  securedRoutes.route('/', createDeviceRoutes(dependencies.store, dependencies.serviceOptions?.now));
  if (dependencies.protectedRoutes !== undefined) {
    securedRoutes.route('/', dependencies.protectedRoutes);
  }
  routes.route('/', securedRoutes);

  const app = logger === undefined
    ? createApp(config, undefined, routes)
    : createApp(config, logger, routes);
  app.get('/.well-known/jwks.json', () => {
    return new Response(JSON.stringify(dependencies.jwtKeys.jwks), {
      headers: {
        'cache-control': 'public, max-age=300',
        'content-type': 'application/jwk-set+json; charset=utf-8',
      },
    });
  });
  const oauthService = new OAuthService(
    dependencies.store,
    dependencies.jwtKeys,
    dependencies.serviceOptions?.now,
  );
  app.route('/', createOAuthRoutes(oauthService, {
    issuer: dependencies.jwtKeys.issuer,
    jwtKeys: dependencies.jwtKeys,
    store: dependencies.store,
    now: dependencies.serviceOptions?.now,
  }));
  app.route('/', createMcpRoutes(
    dependencies.store,
    policyVersion,
    dependencies.jwtKeys,
    dependencies.serviceOptions?.now,
  ));
  return app;
}
