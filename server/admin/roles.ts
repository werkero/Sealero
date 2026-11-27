import { Hono } from 'hono';
import type { Context } from 'hono';
import { ApiError } from '../app.js';
import type { AdminRoleService } from './admin-role-service.js';
import { requirePermission } from './require-permission.js';
import type { AdminRoleStore } from './types.js';
import type { AuthenticatedEnvironment } from '../middleware/authentication.js';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface AdminRoleRouteOptions {
  readonly allowInsecureHttp?: boolean;
}

function requireHttps(context: Context<AuthenticatedEnvironment>, allowInsecureHttp: boolean): void {
  let protocol: string;
  try {
    protocol = new URL(context.req.url).protocol;
  } catch {
    protocol = '';
  }
  if (protocol !== 'https:' && !(allowInsecureHttp && protocol === 'http:')) {
    throw new ApiError(400, 'https_required', 'Administrator requests must use HTTPS.');
  }
}

function requestIp(headers: Headers): string | null {
  const forwarded = headers.get('x-forwarded-for');
  if (forwarded === null) return null;
  const first = forwarded.split(',', 1)[0]?.trim();
  return first ? first.slice(0, 128) : null;
}

function requireUuid(value: string, name: string): string {
  if (!UUID_PATTERN.test(value)) {
    throw new ApiError(400, 'invalid_request', `The ${name} must be a UUID.`);
  }
  return value;
}

function queryCursor(context: Context<AuthenticatedEnvironment>, name: string): string | null {
  const value = context.req.query(name);
  if (value === undefined) return null;
  if (!UUID_PATTERN.test(value)) throw new ApiError(400, 'invalid_cursor', `The ${name} must be a UUID.`);
  return value;
}

function queryLimit(context: Context<AuthenticatedEnvironment>, name: string): number {
  const value = context.req.query(name);
  if (value === undefined) return 100;
  if (!/^[0-9]+$/.test(value)) {
    throw new ApiError(400, 'invalid_pagination', `The ${name} must be an integer from 1 to 500.`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 500) {
    throw new ApiError(400, 'invalid_pagination', `The ${name} must be an integer from 1 to 500.`);
  }
  return parsed;
}

async function readJson(context: Context<AuthenticatedEnvironment>): Promise<unknown> {
  let text: string;
  try {
    text = await context.req.text();
  } catch {
    throw new ApiError(400, 'invalid_request', 'The request body must be valid JSON.');
  }
  if (text.trim() === '') throw new ApiError(400, 'invalid_request', 'The request body must be valid JSON.');
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new ApiError(400, 'invalid_request', 'The request body must be valid JSON.');
  }
}

function readAssignBody(body: unknown): string {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new ApiError(400, 'invalid_request', 'The role assignment body is invalid.');
  }
  const record = body as Record<string, unknown>;
  if (Object.keys(record).some((key) => key !== 'user_id') || typeof record['user_id'] !== 'string') {
    throw new ApiError(400, 'invalid_request', 'The role assignment must include only user_id.');
  }
  return requireUuid(record['user_id'] as string, 'user_id');
}

export function createAdminRoleRoutes(
  service: AdminRoleService,
  store: AdminRoleStore,
  options: AdminRoleRouteOptions = {},
): Hono<AuthenticatedEnvironment> {
  const routes = new Hono<AuthenticatedEnvironment>();
  const allowInsecureHttp = options.allowInsecureHttp ?? false;

  routes.use('*', async (context, next) => {
    requireHttps(context, allowInsecureHttp);
    await next();
  });

  routes.get('/roles', async (context) => {
    await requirePermission(store, context, 'roles:manage');
    return context.json({ roles: await service.listRoles() });
  });

  routes.get('/permissions', async (context) => {
    await requirePermission(store, context, 'roles:manage');
    return context.json({ permissions: await service.listPermissions() });
  });

  routes.get('/me/permissions', async (context) => {
    return context.json({ permissions: await service.getMyPermissions(context.get('auth').sub) });
  });

  routes.post('/roles', async (context) => {
    await requirePermission(store, context, 'roles:manage');
    const role = await service.createRole(context.get('auth').sub, requestIp(context.req.raw.headers), await readJson(context));
    return context.json({ role }, 201);
  });

  routes.patch('/roles/:id', async (context) => {
    await requirePermission(store, context, 'roles:manage');
    const roleId = requireUuid(context.req.param('id'), 'id');
    const role = await service.updateRole(context.get('auth').sub, roleId, requestIp(context.req.raw.headers), await readJson(context));
    return context.json({ role });
  });

  routes.delete('/roles/:id', async (context) => {
    await requirePermission(store, context, 'roles:manage');
    const roleId = requireUuid(context.req.param('id'), 'id');
    await service.deleteRole(context.get('auth').sub, roleId, requestIp(context.req.raw.headers));
    return context.body(null, 204);
  });

  routes.get('/roles/:id/users', async (context) => {
    await requirePermission(store, context, 'roles:manage');
    const roleId = requireUuid(context.req.param('id'), 'id');
    const result = await service.listRoleUsers(roleId, queryCursor(context, 'cursor'), queryLimit(context, 'limit'));
    switch (result.kind) {
      case 'not_found':
        throw new ApiError(404, 'role_not_found', 'The role was not found.');
      case 'invalid_cursor':
        throw new ApiError(400, 'invalid_cursor', 'The cursor does not identify a user.');
      case 'ok':
        return context.json({
          users: result.value.items,
          total_count: result.value.total_count,
          has_more: result.value.has_more,
          next_cursor: result.value.next_cursor,
        });
    }
  });

  routes.post('/roles/:id/users', async (context) => {
    await requirePermission(store, context, 'roles:manage');
    const roleId = requireUuid(context.req.param('id'), 'id');
    const userId = readAssignBody(await readJson(context));
    const result = await service.assignRole(context.get('auth').sub, roleId, userId, requestIp(context.req.raw.headers));
    return context.json({ role: result.role, user: result.user });
  });

  routes.delete('/roles/:id/users/:userId', async (context) => {
    await requirePermission(store, context, 'roles:manage');
    const roleId = requireUuid(context.req.param('id'), 'id');
    const userId = requireUuid(context.req.param('userId'), 'userId');
    await service.removeRole(context.get('auth').sub, roleId, userId, requestIp(context.req.raw.headers));
    return context.body(null, 204);
  });

  return routes;
}
