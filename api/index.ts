import { existsSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { Hono } from 'hono';
import { createApp, type Logger } from '../server/app.js';
import { createConfiguredAuthenticatedApp } from '../server/auth/app.js';
import type { ConfiguredAuthenticatedAppDependencies } from '../server/auth/app.js';
import type { JwtKeyEnvironment } from '../server/auth/keyring.js';
import { loadConfig } from '../server/config.js';
import { SqlAuthStore } from '../server/db/auth-store.js';
import { NeonAuthDatabase, resolveNeonConnectionString } from '../server/db/neon-store.js';
import { createMaintenanceRoutes } from '../server/routes/maintenance.js';
import { SmtpNotifications } from '../server/services/smtp-notifications.js';

export type DeploymentAuthDependencies = Omit<
  ConfiguredAuthenticatedAppDependencies,
  'siteOrigin' | 'allowInsecureHttp'
>;

/**
 * Deployment bootstrap boundary. The host must inject a real durable AuthStore and real notification
 * provider; JWT key material is loaded and validated from the deployment environment.
 */
export function createDeploymentApp(
  dependencies: DeploymentAuthDependencies,
  keyEnvironment: JwtKeyEnvironment = process.env,
  logger?: Logger,
): Hono {
  if (Object.hasOwn(dependencies, 'siteOrigin') || Object.hasOwn(dependencies, 'allowInsecureHttp')) {
    throw new Error('Deployment auth must use the configured HTTPS issuer origin and transport.');
  }
  return createConfiguredAuthenticatedApp(loadConfig(), dependencies, keyEnvironment, logger);
}

const DEFAULT_JWT_ISSUER = 'https://sealero.vercel.app';
const DEFAULT_JWT_ACTIVE_KID = 'key-1';
const PRIVATE_KEY_TMP_PATH = resolve(tmpdir(), 'sealero-jwt-private.pem');

/**
 * Resolves the private key for this deployment. On Vercel there is no key
 * file to read, so the PEM content is supplied as the `JWT_PRIVATE_KEY`
 * environment variable and written to the function's writable /tmp at cold
 * start (mode 0600, never logged, never committed). Any other deployment
 * keeps using `JWT_PRIVATE_KEY_PATH` as before.
 */
function resolvePrivateKeyPath(env: NodeJS.ProcessEnv): string {
  const inline = env['JWT_PRIVATE_KEY'];
  if (typeof inline === 'string' && inline.trim() !== '') {
    writeFileSync(PRIVATE_KEY_TMP_PATH, inline, { mode: 0o600 });
    return PRIVATE_KEY_TMP_PATH;
  }
  if (typeof env['JWT_PRIVATE_KEY_PATH'] === 'string' && env['JWT_PRIVATE_KEY_PATH'].trim() !== '') {
    return env['JWT_PRIVATE_KEY_PATH'].trim();
  }
  throw new Error('JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_PATH is required for deployment startup.');
}

/**
 * The public JWKS is public key material: it is committed at `api/jwks.json`
 * and bundled with the function. An explicit `JWT_PUBLIC_KEY_PATH` still
 * wins when set (self-hosted deployments with their own key pair).
 */
function resolvePublicKeyPath(env: NodeJS.ProcessEnv): string {
  if (typeof env['JWT_PUBLIC_KEY_PATH'] === 'string' && env['JWT_PUBLIC_KEY_PATH'].trim() !== '') {
    return env['JWT_PUBLIC_KEY_PATH'].trim();
  }
  const candidates = [
    resolve(process.cwd(), 'api', 'jwks.json'),
    resolve(process.cwd(), 'jwks.json'),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  return candidates[0] as string;
}

function buildDeploymentApp(env: NodeJS.ProcessEnv = process.env): Hono {
  const database = NeonAuthDatabase.create(resolveNeonConnectionString(env));
  const store = new SqlAuthStore(database, {
    connectionCount: () => database.connectionCount,
  });
  const notifications = new SmtpNotifications({
    env,
    getDatabaseSettings: () => store.listAdminSettings(),
  });
  const keyEnvironment: JwtKeyEnvironment = {
    ...env,
    JWT_PRIVATE_KEY_PATH: resolvePrivateKeyPath(env),
    JWT_PUBLIC_KEY_PATH: resolvePublicKeyPath(env),
    JWT_ACTIVE_KID: env['JWT_ACTIVE_KID']?.trim() || DEFAULT_JWT_ACTIVE_KID,
    JWT_ISSUER: env['JWT_ISSUER']?.trim() || DEFAULT_JWT_ISSUER,
  };
  const app = createDeploymentApp({ store, notifications }, keyEnvironment);
  app.route(
    '/v1/admin/maintenance',
    createMaintenanceRoutes({
      store,
      database,
      cleanupSecret: env['TOMBSTONE_CLEANUP_SECRET'],
    }),
  );
  return app;
}

// The deployment app is built at cold start. Any missing required piece
// (database URL, JWT key material, secrets, release manifest) fails closed:
// the health endpoint keeps answering and every business route stays 503
// with `auth_runtime_unavailable`. Never substitute the local PGlite store
// or fake notification provider here.
let deploymentApp: Hono | null = null;
try {
  deploymentApp = buildDeploymentApp();
} catch (error) {
  console.error(JSON.stringify({
    level: 'error',
    event: 'deployment_app_startup_failed',
    message: error instanceof Error ? error.message : 'unknown error',
  }));
}

const unavailableApp = createApp(loadConfig());
unavailableApp.notFound((context) => context.json({
  code: 'auth_runtime_unavailable',
  message: 'The authentication runtime has not been configured.',
}, 503));

export default deploymentApp ?? unavailableApp;
