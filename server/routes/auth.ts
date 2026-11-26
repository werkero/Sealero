import { Hono } from 'hono';
import type { Context } from 'hono';
import { AuthService, AuthServiceError } from '../auth/auth-service.js';
import type { DeviceType } from '../auth/types.js';

export const REFRESH_COOKIE_NAME = '__Host-sealero_refresh';
const REFRESH_COOKIE_MAX_AGE_SECONDS = 30 * 24 * 60 * 60;

type AuthContext = Context;

export interface AuthRouteOptions {
  /** Trusted, configured site/API origin. Never derived from Host or forwarded headers. */
  readonly siteOrigin: string;
  /** Only enabled by the loopback-bound local development server. */
  readonly allowInsecureHttp?: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function readJson(context: AuthContext): Promise<unknown> {
  try {
    return await context.req.json();
  } catch {
    throw new AuthServiceError(400, 'invalid_request', 'The request body must be valid JSON.');
  }
}

async function readOptionalJson(context: AuthContext): Promise<unknown | undefined> {
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

function hasOnlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function isEmptyCookieBody(value: unknown | undefined): boolean {
  return value === undefined || (isRecord(value) && Object.keys(value).length === 0);
}

function validateSiteOrigin(value: string, allowInsecureHttp: boolean): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error('The configured auth site origin is invalid.');
  }
  const localHost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1' || parsed.hostname === '[::1]';
  const validProtocol = parsed.protocol === 'https:' || (allowInsecureHttp && parsed.protocol === 'http:' && localHost);
  if (
    !validProtocol || parsed.origin !== value || parsed.username !== '' || parsed.password !== '' ||
    parsed.pathname !== '/' || parsed.search !== '' || parsed.hash !== ''
  ) {
    throw new Error('The configured auth site origin must be a normalized HTTPS origin.');
  }
  return parsed.origin;
}

function requireHttps(context: AuthContext, allowInsecureHttp: boolean): void {
  let protocol: string;
  try {
    // Use only the request transport scheme. Host and forwarded headers are not consulted.
    protocol = new URL(context.req.url).protocol;
  } catch {
    protocol = '';
  }
  if (protocol !== 'https:' && !(allowInsecureHttp && protocol === 'http:')) {
    throw new AuthServiceError(400, 'https_required', 'Authentication requests must use HTTPS.');
  }
}

function requireSiteOrigin(context: AuthContext, siteOrigin: string): void {
  if (context.req.header('origin') !== siteOrigin) {
    throw new AuthServiceError(403, 'origin_not_allowed', 'The request origin is not allowed.');
  }
}

function readRefreshCookie(request: Request): { readonly present: boolean; readonly value: string | null } {
  const header = request.headers.get('cookie');
  if (header === null) return { present: false, value: null };
  let found = false;
  let value: string | null = null;
  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator < 0 || part.slice(0, separator).trim() !== REFRESH_COOKIE_NAME) continue;
    if (found) return { present: true, value: null };
    found = true;
    value = part.slice(separator + 1).trim();
  }
  return { present: found, value };
}

function refreshCookie(value: string): string {
  return `${REFRESH_COOKIE_NAME}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${REFRESH_COOKIE_MAX_AGE_SECONDS}`;
}

function clearRefreshCookie(): string {
  return `${REFRESH_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

function requiredString(value: unknown): value is string {
  return typeof value === 'string';
}

export function createAuthRoutes(service: AuthService, options: AuthRouteOptions): Hono {
  const routes = new Hono();
  const allowInsecureHttp = options.allowInsecureHttp ?? false;
  const siteOrigin = validateSiteOrigin(options.siteOrigin, allowInsecureHttp);

  routes.post('/register', async (context) => {
    try {
      requireHttps(context, allowInsecureHttp);
      const body: unknown = await readJson(context);
      if (!isRecord(body) || !hasOnlyKeys(body, ['email', 'login_password']) ||
          !requiredString(body['email']) || !requiredString(body['login_password'])) {
        throw new AuthServiceError(400, 'invalid_request', 'The registration request is invalid.');
      }
      const result = await service.register(body['email'], body['login_password'], {
        ipAddress: requestIp(context.req.raw.headers),
        userAgent: context.req.header('user-agent') ?? null,
      });
      return context.json({
        code: result.code,
        message: result.message,
        email_verification_required: result.email_verification_required,
      }, result.status);
    } catch (error) {
      return authErrorResponse(context, error);
    }
  });

  routes.post('/verify-email', async (context) => {
    try {
      requireHttps(context, allowInsecureHttp);
      const body: unknown = await readJson(context);
      if (!isRecord(body) || !hasOnlyKeys(body, ['email', 'code']) ||
          !requiredString(body['email']) || !requiredString(body['code'])) {
        throw new AuthServiceError(400, 'invalid_request', 'The verification request is invalid.');
      }
      const result = await service.verifyEmail(body['email'], body['code']);
      return context.json({ code: result.code, message: result.message }, result.status);
    } catch (error) {
      return authErrorResponse(context, error);
    }
  });

  routes.post('/resend-verification', async (context) => {
    try {
      requireHttps(context, allowInsecureHttp);
      const body: unknown = await readJson(context);
      if (!isRecord(body) || !hasOnlyKeys(body, ['email']) || !requiredString(body['email'])) {
        throw new AuthServiceError(400, 'invalid_request', 'The verification request is invalid.');
      }
      const result = await service.resendVerification(body['email'], {
        ipAddress: requestIp(context.req.raw.headers),
        userAgent: context.req.header('user-agent') ?? null,
      });
      return context.json({ code: result.code, message: result.message }, result.status);
    } catch (error) {
      return authErrorResponse(context, error);
    }
  });

  routes.post('/forgot-password', async (context) => {
    try {
      requireHttps(context, allowInsecureHttp);
      const body: unknown = await readJson(context);
      if (!isRecord(body) || !hasOnlyKeys(body, ['email']) || !requiredString(body['email'])) {
        throw new AuthServiceError(400, 'invalid_request', 'The password recovery request is invalid.');
      }
      const result = await service.forgotPassword(body['email'], {
        ipAddress: requestIp(context.req.raw.headers),
        userAgent: context.req.header('user-agent') ?? null,
      });
      return context.json({ code: result.code, message: result.message }, result.status);
    } catch (error) {
      return authErrorResponse(context, error);
    }
  });

  routes.post('/reset-password', async (context) => {
    try {
      requireHttps(context, allowInsecureHttp);
      const body: unknown = await readJson(context);
      if (!isRecord(body) || !hasOnlyKeys(body, ['email', 'code', 'new_login_password']) ||
          !requiredString(body['email']) || !requiredString(body['code']) ||
          !requiredString(body['new_login_password'])) {
        throw new AuthServiceError(400, 'invalid_request', 'The password reset request is invalid.');
      }
      const result = await service.resetPassword(body['email'], body['code'], body['new_login_password']);
      return context.json({ code: result.code, message: result.message }, result.status);
    } catch (error) {
      return authErrorResponse(context, error);
    }
  });

  routes.post('/login', async (context) => {
    try {
      requireHttps(context, allowInsecureHttp);
      const body: unknown = await readJson(context);
      if (
        !isRecord(body) ||
        !hasOnlyKeys(body, ['email', 'login_password', 'device_name', 'device_type', 'device_id']) ||
        !requiredString(body['email']) ||
        !requiredString(body['login_password']) ||
        !requiredString(body['device_name']) ||
        (body['device_type'] !== 'app' && body['device_type'] !== 'web') ||
        (body['device_id'] !== undefined && (typeof body['device_id'] !== 'string' || !isUuid(body['device_id'])))
      ) {
        throw new AuthServiceError(400, 'invalid_request', 'The login request is invalid.');
      }
      const deviceType: DeviceType = body['device_type'];
      const pair = await service.login({
        email: body['email'],
        loginPassword: body['login_password'],
        deviceName: body['device_name'],
        deviceType,
        ...(typeof body['device_id'] === 'string' ? { deviceId: body['device_id'] } : {}),
      }, {
        ipAddress: requestIp(context.req.raw.headers),
        userAgent: context.req.header('user-agent') ?? null,
      });
      if (deviceType === 'web') {
        context.header('Set-Cookie', refreshCookie(pair.refresh_token));
        return context.json({ device_id: pair.device_id, access_token: pair.access_token });
      }
      return context.json(pair);
    } catch (error) {
      return authErrorResponse(context, error);
    }
  });

  routes.post('/refresh', async (context) => {
    try {
      requireHttps(context, allowInsecureHttp);
      const cookie = readRefreshCookie(context.req.raw);
      if (cookie.present) {
        requireSiteOrigin(context, siteOrigin);
        const body = await readOptionalJson(context);
        if (!isEmptyCookieBody(body)) {
          throw new AuthServiceError(400, 'invalid_request', 'Cookie refresh requests must not include a token body.');
        }
        const pair = await service.refresh(cookie.value ?? '');
        context.header('Set-Cookie', refreshCookie(pair.refresh_token));
        return context.json({ device_id: pair.device_id, access_token: pair.access_token });
      }

      const body: unknown = await readOptionalJson(context);
      if (!isRecord(body) || !hasOnlyKeys(body, ['refresh_token']) || !requiredString(body['refresh_token'])) {
        throw new AuthServiceError(400, 'invalid_request', 'The refresh request is invalid.');
      }
      return context.json(await service.refresh(body['refresh_token']));
    } catch (error) {
      return authErrorResponse(context, error);
    }
  });

  routes.post('/logout', async (context) => {
    try {
      requireHttps(context, allowInsecureHttp);
      const cookie = readRefreshCookie(context.req.raw);
      if (cookie.present) {
        requireSiteOrigin(context, siteOrigin);
        const body = await readOptionalJson(context);
        if (!isEmptyCookieBody(body)) {
          throw new AuthServiceError(400, 'invalid_request', 'Cookie logout requests must not include a token body.');
        }
        await service.logout(cookie.value ?? '');
        context.header('Set-Cookie', clearRefreshCookie());
        return context.body(null, 204);
      }

      const body: unknown = await readOptionalJson(context);
      if (!isRecord(body) || !hasOnlyKeys(body, ['refresh_token']) || !requiredString(body['refresh_token'])) {
        throw new AuthServiceError(400, 'invalid_request', 'The logout request is invalid.');
      }
      await service.logout(body['refresh_token']);
      return context.body(null, 204);
    } catch (error) {
      return authErrorResponse(context, error);
    }
  });

  return routes;
}

function authErrorResponse(context: AuthContext, error: unknown): Response {
  if (error instanceof AuthServiceError) {
    if (error.retryAfterSeconds !== undefined) context.header('Retry-After', String(error.retryAfterSeconds));
    return context.json({ code: error.code, message: error.message }, error.status);
  }
  return context.json({ code: 'internal_error', message: 'An internal server error occurred.' }, 500);
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

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
}
