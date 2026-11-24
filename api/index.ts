import { Hono } from 'hono';
import { createApp, type Logger } from './app.js';
import { createConfiguredAuthenticatedApp } from './auth/app.js';
import type { ConfiguredAuthenticatedAppDependencies } from './auth/app.js';
import type { JwtKeyEnvironment } from './auth/keyring.js';
import { loadConfig } from './config.js';

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

// Expose the documented health endpoint without enabling business routes before production adapters
// are supplied. Never substitute the local PGlite store or fake notification provider here.
const unavailableApp = createApp(loadConfig());
unavailableApp.notFound((context) => context.json({
  code: 'auth_runtime_unavailable',
  message: 'The authentication runtime has not been configured.',
}, 503));

export default unavailableApp;
