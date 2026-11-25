import { Hono } from 'hono';
import type { AdminHealthSettings } from '../admin/types.js';
import type { AppConfig } from '../config.js';

/**
 * Creates the documented v1 health endpoint.
 *
 * `policyVersion` is the current privacy-policy version from the release
 * manifest. It is public (clients need it to submit consent before using
 * the vault, e.g. when registering) and is only present when the caller
 * provides it; the fail-closed app has no manifest and omits it.
 */
export function createHealthRoutes(
  config: AppConfig,
  readHealthSettings?: () => Promise<AdminHealthSettings>,
  policyVersion?: string,
): Hono {
  const routes = new Hono();

  routes.get('/health', async (context) => {
    const settings = await readHealthSettings?.();
    return context.json({
      api_version: 'v1',
      supported_api_versions: ['v1'],
      min_app_versions: settings?.min_app_versions ?? {
        android: null,
        ios: null,
        web: null,
      },
      server_time: new Date().toISOString(),
      server_name: settings?.server_name ?? config.serverName,
      ...(policyVersion === undefined ? {} : { policy_version: policyVersion }),
    });
  });

  return routes;
}
