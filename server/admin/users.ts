import { Hono } from 'hono';
import type { Context } from 'hono';
import { ApiError } from '../app.js';
import type { AdminUserService } from './admin-user-service.js';
import { requirePermission } from './require-permission.js';
import type { AdminRoleStore, AdminUserReadStore, AdminUserRoleFilter, AdminUserStatusFilter, AdminUserVerifiedFilter } from './types.js';
import type { AuthenticatedEnvironment } from '../middleware/authentication.js';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface AdminUserRouteOptions {
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

function requestMetadata(context: Context<AuthenticatedEnvironment>) {
  return {
    ipAddress: requestIp(context.req.raw.headers),
    userAgent: context.req.header('user-agent') ?? null,
  };
}

function requireUuid(value: string, name: string, errorCode = 'invalid_request'): string {
  if (!UUID_PATTERN.test(value)) {
    throw new ApiError(400, errorCode, `The ${name} must be a UUID.`);
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

function queryFilter<T extends string>(
  context: Context<AuthenticatedEnvironment>,
  name: string,
  allowed: readonly T[],
  defaultValue: T,
): T {
  const value = context.req.query(name);
  if (value === undefined) return defaultValue;
  if (!allowed.includes(value as T)) {
    throw new ApiError(400, 'invalid_filter', `The ${name} filter is invalid.`);
  }
  return value as T;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function readOptionalJson(context: Context<AuthenticatedEnvironment>): Promise<unknown | undefined> {
  let text: string;
  try {
    text = await context.req.text();
  } catch {
    throw new ApiError(400, 'invalid_request', 'The request body must be valid JSON.');
  }
  if (text.trim() === '') return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new ApiError(400, 'invalid_request', 'The request body must be valid JSON.');
  }
}

async function readDeletePassword(context: Context<AuthenticatedEnvironment>): Promise<string> {
  let body: unknown;
  try {
    body = await context.req.json();
  } catch {
    throw new ApiError(400, 'invalid_request', 'The delete request body must be valid JSON.');
  }
  if (
    !isRecord(body) ||
    Object.keys(body).some((key) => key !== 'login_password') ||
    typeof body['login_password'] !== 'string'
  ) {
    throw new ApiError(400, 'invalid_request', 'The delete request must include only login_password.');
  }
  return body['login_password'];
}

async function readLoginPassword(context: Context<AuthenticatedEnvironment>, action: string): Promise<string> {
  let body: unknown;
  try {
    body = await context.req.json();
  } catch {
    throw new ApiError(400, 'invalid_request', `The ${action} request body must be valid JSON.`);
  }
  if (
    !isRecord(body) ||
    Object.keys(body).some((key) => key !== 'login_password') ||
    typeof body['login_password'] !== 'string'
  ) {
    throw new ApiError(400, 'invalid_request', `The ${action} request must include only login_password.`);
  }
  return body['login_password'];
}

async function requireEmptyBody(context: Context<AuthenticatedEnvironment>): Promise<void> {
  const body = await readOptionalJson(context);
  if (body !== undefined && (!isRecord(body) || Object.keys(body).length !== 0)) {
    throw new ApiError(400, 'invalid_request', 'This request does not accept body fields.');
  }
}

export function createAdminUserRoutes(
  service: AdminUserService,
  store: AdminUserReadStore & AdminRoleStore,
  options: AdminUserRouteOptions = {},
): Hono<AuthenticatedEnvironment> {
  const routes = new Hono<AuthenticatedEnvironment>();
  const allowInsecureHttp = options.allowInsecureHttp ?? false;

  routes.use('*', async (context, next) => {
    requireHttps(context, allowInsecureHttp);
    await next();
  });

  routes.get('/users', async (context) => {
    await requirePermission(store, context, 'users:read');
    const status = queryFilter<AdminUserStatusFilter>(context, 'status', ['all', 'active', 'disabled'], 'all');
    const verified = queryFilter<AdminUserVerifiedFilter>(context, 'verified', ['all', 'verified', 'unverified'], 'all');
    const role = queryFilter<AdminUserRoleFilter>(context, 'role', ['all', 'admin', 'user', 'super_admin'], 'all');
    const searchInput = context.req.query('search');
    const search = searchInput === undefined ? null : searchInput.trim() || null;
    const page = await service.listUsers({
      search,
      status,
      verified,
      role,
      cursor: queryCursor(context, 'cursor'),
      limit: queryLimit(context, 'limit'),
    });
    if (page === null) throw new ApiError(400, 'invalid_cursor', 'The cursor does not identify a user.');
    return context.json({
      users: page.items,
      total_count: page.total_count,
      has_more: page.has_more,
      next_cursor: page.next_cursor,
    });
  });

  routes.get('/users/:id', async (context) => {
    await requirePermission(store, context, 'users:read');
    const userId = requireUuid(context.req.param('id'), 'id');
    const loginCursor = queryCursor(context, 'login_cursor');
    const loginLimit = queryLimit(context, 'login_limit');
    const result = await service.getUserDetail(userId, loginCursor, loginLimit);
    switch (result.kind) {
      case 'not_found':
        throw new ApiError(404, 'user_not_found', 'The user was not found.');
      case 'invalid_cursor':
        throw new ApiError(400, 'invalid_cursor', 'The login_cursor does not identify login history for this user.');
      case 'ok':
        return context.json(result.value);
    }
  });

  routes.post('/users/:id/disable', async (context) => {
    await requirePermission(store, context, 'users:manage');
    requireUuid(context.req.param('id'), 'id');
    await requireEmptyBody(context);
    await service.disableUser(context.get('auth').sub, context.req.param('id'), requestIp(context.req.raw.headers));
    return context.body(null, 204);
  });

  routes.post('/users/:id/enable', async (context) => {
    await requirePermission(store, context, 'users:manage');
    requireUuid(context.req.param('id'), 'id');
    await requireEmptyBody(context);
    await service.enableUser(context.get('auth').sub, context.req.param('id'), requestIp(context.req.raw.headers));
    return context.body(null, 204);
  });

  routes.post('/users/:id/delete', async (context) => {
    await requirePermission(store, context, 'users:manage');
    const userId = requireUuid(context.req.param('id'), 'id');
    const loginPassword = await readDeletePassword(context);
    await service.deleteUser(context.get('auth').sub, userId, loginPassword, requestMetadata(context));
    return context.body(null, 204);
  });

  routes.post('/users/:id/revoke-all-devices', async (context) => {
    await requirePermission(store, context, 'users:manage');
    const userId = requireUuid(context.req.param('id'), 'id');
    const loginPassword = await readLoginPassword(context, 'revoke-all-devices');
    await service.revokeAllDevices(context.get('auth').sub, userId, loginPassword, requestMetadata(context));
    return context.body(null, 204);
  });

  routes.post('/users/:id/make-admin', async (context) => {
    await requirePermission(store, context, 'users:manage');
    const userId = requireUuid(context.req.param('id'), 'id');
    await requireEmptyBody(context);
    await service.makeAdmin(context.get('auth').sub, userId, requestIp(context.req.raw.headers));
    return context.body(null, 204);
  });

  routes.post('/users/:id/remove-admin', async (context) => {
    await requirePermission(store, context, 'users:manage');
    const userId = requireUuid(context.req.param('id'), 'id');
    await requireEmptyBody(context);
    await service.removeAdmin(context.get('auth').sub, userId, requestIp(context.req.raw.headers));
    return context.body(null, 204);
  });

  routes.post('/devices/:id/revoke', async (context) => {
    await requirePermission(store, context, 'users:manage');
    const deviceId = requireUuid(context.req.param('id'), 'id');
    await requireEmptyBody(context);
    await service.revokeDevice(context.get('auth').sub, deviceId, requestIp(context.req.raw.headers));
    return context.body(null, 204);
  });

  return routes;
}
