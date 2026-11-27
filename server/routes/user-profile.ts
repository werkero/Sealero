import { Hono } from 'hono';
import type { Context } from 'hono';
import { AuthServiceError } from '../auth/auth-service.js';
import type { AuthService } from '../auth/auth-service.js';
import type { AuthenticatedEnvironment } from '../middleware/authentication.js';

export interface UserProfileRouteOptions {
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

function authErrorResponse(context: Context<AuthenticatedEnvironment>, error: unknown): Response {
  if (error instanceof AuthServiceError) {
    if (error.retryAfterSeconds !== undefined) context.header('Retry-After', String(error.retryAfterSeconds));
    return context.json({ code: error.code, message: error.message }, error.status);
  }
  return context.json({ code: 'internal_error', message: 'An internal server error occurred.' }, 500);
}

export function createUserProfileRoutes(
  service: AuthService,
  options: UserProfileRouteOptions = {},
): Hono<AuthenticatedEnvironment> {
  const routes = new Hono<AuthenticatedEnvironment>();
  const allowInsecureHttp = options.allowInsecureHttp ?? false;

  routes.put('/profile', async (context) => {
    try {
      requireHttps(context, allowInsecureHttp);
      const body: unknown = await readJson(context);
      if (!isRecord(body) || !hasOnlyKeys(body, ['display_name', 'avatar_url'])) {
        throw new AuthServiceError(400, 'invalid_request', 'The request body must only include display_name and avatar_url.');
      }
      const profile = await service.updateUserProfile(context.get('auth').sub, body['display_name'], body['avatar_url']);
      return context.json({ id: profile.id, email: profile.email, display_name: profile.display_name, avatar_url: profile.avatar_url });
    } catch (error) {
      return authErrorResponse(context, error);
    }
  });

  return routes;
}
