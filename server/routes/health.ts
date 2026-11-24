import { Hono } from 'hono';
import type { AdminHealthSettings } from '../admin/types.js';
import type { AppConfig } from '../config.js';

/** Creates the documented v1 health endpoint. */
export function createHealthRoutes(
  config: AppConfig,
  readHealthSettings?: () => Promise<AdminHealthSettings>,
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
    });
  });

  return routes;
}
