import { Hono } from 'hono';
import { ApiError } from '../app.js';
import { decodeDeviceListCursor, encodeDeviceListCursor } from '../devices/cursor.js';
import type { DeviceListStore, DeviceRevocationStore } from '../devices/types.js';
import type { AuthenticatedEnvironment } from '../middleware/authentication.js';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function createDeviceRoutes(
  store: DeviceRevocationStore & DeviceListStore,
  now: () => Date = () => new Date(),
): Hono<AuthenticatedEnvironment> {
  const routes = new Hono<AuthenticatedEnvironment>();

  routes.get('/devices', async (context) => {
    const rawLimit = context.req.query('limit');
    const limit = rawLimit === undefined ? 100 : Number(rawLimit);
    if (rawLimit !== undefined && (!/^\d+$/.test(rawLimit) || !Number.isSafeInteger(limit) || limit < 1 || limit > 500)) {
      throw new ApiError(400, 'invalid_pagination', 'The limit must be an integer from 1 to 500.');
    }

    const rawCursor = context.req.query('cursor');
    const cursor = rawCursor === undefined ? null : decodeDeviceListCursor(rawCursor);
    if (rawCursor !== undefined && cursor === null) {
      throw new ApiError(400, 'invalid_cursor', 'The device cursor is invalid.');
    }

    const page = await store.listDevices(context.get('auth').sub, cursor, limit);
    const hasMore = page.devices.length > limit;
    const devices = hasMore ? page.devices.slice(0, limit) : page.devices;
    const lastDevice = devices.at(-1);
    return context.json({
      devices,
      total_count: page.total_count,
      has_more: hasMore,
      next_cursor: hasMore && lastDevice !== undefined
        ? encodeDeviceListCursor({ createdAt: lastDevice.created_at, id: lastDevice.id })
        : null,
    });
  });

  routes.delete('/devices/:id', async (context) => {
    const deviceId = context.req.param('id');
    if (!UUID_PATTERN.test(deviceId)) {
      throw new ApiError(400, 'invalid_request', 'The device ID must be a UUID.');
    }

    const revoked = await store.revokeDevice(context.get('auth').sub, deviceId, now());
    if (!revoked) {
      throw new ApiError(404, 'not_found', 'The requested resource was not found.');
    }
    return context.body(null, 204);
  });

  return routes;
}
