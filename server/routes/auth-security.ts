import { Hono } from 'hono';
import type { Context } from 'hono';
import { AuthServiceError } from '../auth/auth-service.js';
import type { AuthService } from '../auth/auth-service.js';
import type { AuthenticatedEnvironment } from '../middleware/authentication.js';

export interface SensitiveAuthRouteOptions {
  /** Only enabled by the loopback-bound local development server. */
  readonly allowInsecureHttp?: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

async function readJson(context: Context<AuthenticatedEnvironment>): Promise<unknown> {
  try {
    return await context.req.json();
  } catch {
    throw new AuthServiceError(400, 'invalid_request', 'The request body must be valid JSON.');
  }
}

async function readOptionalJson(context: Context<AuthenticatedEnvironment>): Promise<unknown | undefined> {
  let text: string;
  try {
    text = await context.req.text();
  } catch {
    throw new AuthServiceError(400, 'invalid_request', 'The request body must be valid JSON.');
  }
  if (text.trim() === '') return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new AuthServiceError(400, 'invalid_request', 'The request body must be valid JSON.');
  }
}

function requireHttps(context: Context<AuthenticatedEnvironment>, allowInsecureHttp: boolean): void {
  let protocol: string;
  try {
    protocol = new URL(context.req.url).protocol;
  } catch {
    protocol = '';
  }
  if (protocol !== 'https:' && !(allowInsecureHttp && protocol === 'http:')) {
    throw new AuthServiceError(400, 'https_required', 'Authentication requests must use HTTPS.');
  }
}

function requestIp(headers: Headers): string | null {
  const forwarded = headers.get('x-forwarded-for');
  if (forwarded !== null) {
    const first = forwarded.split(',', 1)[0]?.trim();
    if (first) return first.slice(0, 128);
  }
  const connecting = headers.get('cf-connecting-ip');
  return connecting === null ? null : connecting.slice(0, 128);
}

function requestMetadata(context: Context<AuthenticatedEnvironment>) {
  return {
    ipAddress: requestIp(context.req.raw.headers),
    userAgent: context.req.header('user-agent') ?? null,
  };
}

function authErrorResponse(context: Context<AuthenticatedEnvironment>, error: unknown): Response {
  if (error instanceof AuthServiceError) {
    if (error.retryAfterSeconds !== undefined) context.header('Retry-After', String(error.retryAfterSeconds));
    return context.json({ code: error.code, message: error.message }, error.status);
  }
  return context.json({ code: 'internal_error', message: 'An internal server error occurred.' }, 500);
}

export function createSensitiveAuthRoutes(
  service: AuthService,
  options: SensitiveAuthRouteOptions = {},
): Hono<AuthenticatedEnvironment> {
  const routes = new Hono<AuthenticatedEnvironment>();
  const allowInsecureHttp = options.allowInsecureHttp ?? false;

  routes.get('/me', async (context) => {
    try {
      requireHttps(context, allowInsecureHttp);
      const identity = await service.getCurrentUser(context.get('auth').sub);
      return context.json({ id: identity.id, email: identity.email });
    } catch (error) {
      return authErrorResponse(context, error);
    }
  });

  routes.post('/request-delete-code', async (context) => {
    try {
      requireHttps(context, allowInsecureHttp);
      const body = await readOptionalJson(context);
      if (body !== undefined && (!isRecord(body) || Object.keys(body).length !== 0)) {
        throw new AuthServiceError(400, 'invalid_request', 'The delete-code request must not include fields.');
      }
      const result = await service.requestDeleteCode(context.get('auth').sub, requestMetadata(context));
      return context.json({ code: result.code, message: result.message }, result.status);
    } catch (error) {
      return authErrorResponse(context, error);
    }
  });

  routes.post('/delete-account', async (context) => {
    try {
      requireHttps(context, allowInsecureHttp);
      const body: unknown = await readJson(context);
      if (
        !isRecord(body) ||
        !hasOnlyKeys(body, ['login_password', 'email_code', 'backup_exported_confirmed']) ||
        typeof body['login_password'] !== 'string' ||
        typeof body['email_code'] !== 'string' ||
        typeof body['backup_exported_confirmed'] !== 'boolean'
      ) {
        throw new AuthServiceError(400, 'invalid_request', 'The account deletion request is invalid.');
      }
      const result = await service.deleteAccount(
        context.get('auth').sub,
        body['login_password'],
        body['email_code'],
        body['backup_exported_confirmed'],
        requestMetadata(context),
      );
      return context.json({ code: result.code, message: result.message }, result.status);
    } catch (error) {
      return authErrorResponse(context, error);
    }
  });

  routes.post('/change-password', async (context) => {
    try {
      requireHttps(context, allowInsecureHttp);
      const body: unknown = await readJson(context);
      if (
        !isRecord(body) ||
        !hasOnlyKeys(body, ['old_login_password', 'new_login_password']) ||
        typeof body['old_login_password'] !== 'string' ||
        typeof body['new_login_password'] !== 'string'
      ) {
        throw new AuthServiceError(400, 'invalid_request', 'The password change request is invalid.');
      }
      await service.changePassword(
        context.get('auth').sub,
        body['old_login_password'],
        body['new_login_password'],
        requestMetadata(context),
      );
      return context.body(null, 204);
    } catch (error) {
      return authErrorResponse(context, error);
    }
  });

  routes.post('/revoke-all-devices', async (context) => {
    try {
      requireHttps(context, allowInsecureHttp);
      const body: unknown = await readJson(context);
      if (
        !isRecord(body) ||
        !hasOnlyKeys(body, ['login_password']) ||
        typeof body['login_password'] !== 'string'
      ) {
        throw new AuthServiceError(400, 'invalid_request', 'The device revocation request is invalid.');
      }
      const result = await service.revokeAllDevices(
        context.get('auth').sub,
        body['login_password'],
        requestMetadata(context),
      );
      return context.json({ code: result.code, message: result.message }, result.status);
    } catch (error) {
      return authErrorResponse(context, error);
    }
  });

  return routes;
}
