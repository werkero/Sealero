import { Hono } from 'hono';
import type { Context } from 'hono';
import { ApiError } from '../app.js';
import type { AdminConsoleService } from './console-service.js';
import { isUuid } from './console-service.js';
import type { AdminConsoleReadStore, AdminUserReadStore } from './types.js';
import type { AuthenticatedEnvironment } from '../middleware/authentication.js';

const ISO_DATE_PATTERN = /^\d{4}-\d{2}-\d{2}(?:T(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d{1,9})?)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)?)?$/i;

export interface AdminConsoleRouteOptions {
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function readLoginPassword(context: Context<AuthenticatedEnvironment>): Promise<string> {
  let body: unknown;
  try {
    body = await context.req.json();
  } catch {
    throw new ApiError(400, 'invalid_request', 'The db-dump request body must be valid JSON.');
  }
  if (
    !isRecord(body) ||
    Object.keys(body).some((key) => key !== 'login_password') ||
    typeof body['login_password'] !== 'string'
  ) {
    throw new ApiError(400, 'invalid_request', 'The db-dump request must include only login_password.');
  }
  return body['login_password'];
}

function queryUuid(context: Context<AuthenticatedEnvironment>, name: string): string | null {
  const value = context.req.query(name);
  if (value === undefined) return null;
  if (!isUuid(value)) throw new ApiError(400, 'invalid_request', `The ${name} must be a UUID.`);
  return value;
}

function queryCursor(context: Context<AuthenticatedEnvironment>): string | null {
  const value = context.req.query('cursor');
  if (value === undefined) return null;
  if (!isUuid(value)) throw new ApiError(400, 'invalid_cursor', 'The cursor must be a UUID.');
  return value;
}

function queryLimit(context: Context<AuthenticatedEnvironment>): number {
  const value = context.req.query('limit');
  if (value === undefined) return 100;
  if (!/^[0-9]+$/.test(value)) {
    throw new ApiError(400, 'invalid_pagination', 'The limit must be an integer from 1 to 500.');
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 500) {
    throw new ApiError(400, 'invalid_pagination', 'The limit must be an integer from 1 to 500.');
  }
  return parsed;
}

function queryDays(context: Context<AuthenticatedEnvironment>): number {
  const value = context.req.query('days');
  if (value === undefined) return 14;
  if (!/^[0-9]+$/.test(value)) {
    throw new ApiError(400, 'invalid_request', 'The days parameter must be an integer from 7 to 30.');
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 7 || parsed > 30) {
    throw new ApiError(400, 'invalid_request', 'The days parameter must be an integer from 7 to 30.');
  }
  return parsed;
}

function queryDate(context: Context<AuthenticatedEnvironment>, name: 'from' | 'to'): Date | null {
  const value = context.req.query(name);
  if (value === undefined) return null;
  if (!ISO_DATE_PATTERN.test(value)) {
    throw new ApiError(400, 'invalid_request', `The ${name} parameter must be an ISO 8601 date or timestamp.`);
  }
  const datePart = value.slice(0, 10);
  const dateCheck = new Date(`${datePart}T00:00:00.000Z`);
  const date = new Date(value);
  if (
    Number.isNaN(date.getTime()) || Number.isNaN(dateCheck.getTime()) ||
    dateCheck.toISOString().slice(0, 10) !== datePart
  ) {
    throw new ApiError(400, 'invalid_request', `The ${name} parameter must be an ISO 8601 date or timestamp.`);
  }
  return date;
}

async function readJsonBody(context: Context<AuthenticatedEnvironment>): Promise<unknown> {
  try {
    return await context.req.json();
  } catch {
    throw new ApiError(400, 'invalid_request', 'The settings body must be valid JSON.');
  }
}

export function createAdminConsoleRoutes(
  service: AdminConsoleService,
  store: AdminConsoleReadStore & Pick<AdminUserReadStore, 'hasAdminRole'>,
  options: AdminConsoleRouteOptions = {},
): Hono<AuthenticatedEnvironment> {
  const routes = new Hono<AuthenticatedEnvironment>();
  const allowInsecureHttp = options.allowInsecureHttp ?? false;

  routes.use('*', async (context, next) => {
    requireHttps(context, allowInsecureHttp);
    if (!await store.hasAdminRole(context.get('auth').sub)) {
      throw new ApiError(403, 'admin_required', 'Administrator access is required.');
    }
    await next();
  });

  routes.get('/overview', async (context) => context.json(await service.getOverview()));

  routes.get('/overview/trend', async (context) => context.json(await service.getOverviewTrend(queryDays(context))));

  routes.post('/db-dump', async (context) => {
    const loginPassword = await readLoginPassword(context);
    const dump = await service.createDbDump(context.get('auth').sub, loginPassword, requestMetadata(context));
    const header = new TextEncoder().encode(`${dump.headerLine}\n`);
    const chunks: Uint8Array[] = [header];
    const chunkSize = 64 * 1024;
    for (let offset = 0; offset < dump.ciphertext.length; offset += chunkSize) {
      chunks.push(dump.ciphertext.subarray(offset, Math.min(offset + chunkSize, dump.ciphertext.length)));
    }
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        for (const chunk of chunks) controller.enqueue(chunk);
        controller.close();
      },
    });
    return new Response(stream, {
      status: 200,
      headers: {
        'content-type': 'application/octet-stream',
        'content-disposition': `attachment; filename="${dump.filename}"`,
      },
    });
  });

  routes.get('/settings', async (context) => context.json(await service.getSettings()));

  routes.put('/settings', async (context) => {
    const response = await service.updateSettings(
      context.get('auth').sub,
      requestIp(context.req.raw.headers),
      await readJsonBody(context),
    );
    return context.json(response);
  });

  routes.get('/audit', async (context) => {
    const page = await service.listAudit({
      actorUserId: queryUuid(context, 'actor_user_id'),
      targetUserId: queryUuid(context, 'target_user_id'),
      action: context.req.query('action') ?? null,
      from: queryDate(context, 'from'),
      to: queryDate(context, 'to'),
      cursor: queryCursor(context),
      limit: queryLimit(context),
    });
    if (page === null) throw new ApiError(400, 'invalid_cursor', 'The cursor does not identify an audit log entry.');
    return context.json(page);
  });

  return routes;
}
