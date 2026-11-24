import type { MiddlewareHandler } from 'hono';
import { Hono } from 'hono';
import { ApiError } from '../app.js';
import type { JwtKeySet } from '../auth/jwt.js';
import { handleMcpRequest } from '../services/mcp.js';
import type { McpAuth, McpStore } from '../services/mcp.js';
import { InvalidOAuthAccessTokenError, verifyOAuthAccessToken } from '../oauth/oauth-service.js';
import { hashOAuthToken } from '../oauth/oauth-service.js';

export interface McpVariables {
  oauth: McpAuth;
}

export interface McpEnvironment {
  Variables: McpVariables;
}

function toDate(value: Date | string | null): Date | null {
  if (value === null) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

/**
 * Verifies the OAuth access token and performs the per-request checks of
 * SD §5.3: authorization row (not revoked, not expired), account not
 * disabled, email-verification gate, then the privacy-consent gate — the
 * same gates as the vault routes, checked on every request, never cached.
 */
export function requireOAuthAccessToken(
  keys: JwtKeySet,
  store: McpStore,
  policyVersion: string,
  now: () => Date = () => new Date(),
): MiddlewareHandler<McpEnvironment> {
  return async (context, next) => {
    const authorization = context.req.header('authorization');
    if (authorization === undefined || !authorization.startsWith('Bearer ')) {
      return context.json({ code: 'unauthorized', message: 'A valid OAuth access token is required.' }, 401);
    }

    const rawToken = authorization.slice('Bearer '.length);
    let userId: string;
    try {
      userId = verifyOAuthAccessToken(keys, rawToken, now()).sub;
    } catch (error) {
      if (error instanceof InvalidOAuthAccessTokenError) {
        return context.json({ code: 'unauthorized', message: 'A valid OAuth access token is required.' }, 401);
      }
      throw error;
    }

    const row = await store.findOAuthAuthorizationByAccessTokenHash(hashOAuthToken(rawToken));
    if (row === null || row.userId !== userId) {
      return context.json({ code: 'unauthorized', message: 'A valid OAuth access token is required.' }, 401);
    }
    if (row.revokedAt !== null) {
      return context.json({ code: 'unauthorized', message: 'This OAuth authorization has been revoked.' }, 401);
    }
    const expiresAt = toDate(row.expiresAt);
    if (expiresAt === null || expiresAt.getTime() <= now().getTime()) {
      return context.json({ code: 'unauthorized', message: 'A valid OAuth access token is required.' }, 401);
    }
    if (row.userDisabledAt !== null) {
      return context.json({ code: 'account_disabled', message: 'This account is disabled.' }, 403);
    }

    const access = await store.getVaultAccessStatus(userId, policyVersion);
    if (access === null) {
      return context.json({ code: 'unauthorized', message: 'A valid OAuth access token is required.' }, 401);
    }
    if (access.requireEmailVerification && access.emailVerifiedAt === null) {
      return context.json({ code: 'email_verification_required', message: 'Verify your email before using the vault.' }, 403);
    }
    if (!access.hasCurrentPrivacyConsent) {
      return context.json({ code: 'consent_required', message: 'Accept the current privacy policy before using the vault.' }, 403);
    }

    await store.touchOAuthAuthorizationLastUsed(row.id, now());
    context.set('oauth', {
      userId,
      authorizationId: row.id,
      scopes: row.scopes.split(/\s+/).filter((scope) => scope.length > 0),
      clientId: row.clientId,
    });
    await next();
    return;
  };
}

/** MCP Streamable HTTP endpoint (SD §5.3). Mounted at the app root, not under /v1. */
export function createMcpRoutes(
  store: McpStore,
  policyVersion: string,
  jwtKeys: JwtKeySet,
  now: () => Date = () => new Date(),
): Hono<McpEnvironment> {
  const routes = new Hono<McpEnvironment>();
  routes.use('/mcp', requireOAuthAccessToken(jwtKeys, store, policyVersion, now));

  routes.post('/mcp', async (context) => {
    let body: unknown;
    try {
      body = await context.req.json();
    } catch {
      throw new ApiError(400, 'invalid_request', 'The request body must be valid JSON.');
    }
    const response = await handleMcpRequest(store, body, context.get('oauth'), now);
    if (response === null) {
      // JSON-RPC notification: accepted, no response.
      return context.body(null, 202);
    }
    return context.json(response);
  });

  return routes;
}
