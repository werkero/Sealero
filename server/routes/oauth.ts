import { Hono } from 'hono';
import { ApiError } from '../app.js';
import { requireAccessToken } from '../middleware/authentication.js';
import type { AuthenticatedEnvironment } from '../middleware/authentication.js';
import type { JwtKeySet } from '../auth/jwt.js';
import type { AuthStore } from '../auth/types.js';
import { OAuthService } from '../oauth/oauth-service.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
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

async function readJson(context: { req: { json(): Promise<unknown> } }): Promise<unknown> {
  try {
    return await context.req.json();
  } catch {
    throw new ApiError(400, 'invalid_request', 'The request body must be valid JSON.');
  }
}

/**
 * Reads OAuth form fields, accepting application/x-www-form-urlencoded (RFC
 * 6749 / RFC 7009) or JSON. All values must be strings.
 */
async function readFormFields(context: {
  req: {
    header(name: string): string | undefined;
    parseBody(): Promise<Record<string, string | File>>;
    json(): Promise<unknown>;
  };
}): Promise<Record<string, string>> {
  const contentType = context.req.header('content-type') ?? '';
  if (contentType.includes('application/x-www-form-urlencoded')) {
    const body = await context.req.parseBody();
    const fields: Record<string, string> = {};
    for (const [key, value] of Object.entries(body)) {
      if (typeof value !== 'string') {
        throw new ApiError(400, 'invalid_request', 'Form fields must be strings.');
      }
      fields[key] = value;
    }
    return fields;
  }
  const json = await readJson(context);
  if (!isRecord(json)) {
    throw new ApiError(400, 'invalid_request', 'The request body must be a JSON object.');
  }
  const fields: Record<string, string> = {};
  for (const [key, value] of Object.entries(json)) {
    if (typeof value !== 'string') {
      throw new ApiError(400, 'invalid_request', 'Request fields must be strings.');
    }
    fields[key] = value;
  }
  return fields;
}

export interface OAuthRouteOptions {
  readonly issuer: string;
  readonly jwtKeys: JwtKeySet;
  readonly store: AuthStore;
  readonly now?: (() => Date) | undefined;
}

/**
 * OAuth 2.1 endpoints (SD §5.3). Mounted at the app root, not under /v1.
 *
 * TODO (SD §5.3): the document names the two .well-known endpoints but does
 * not spell out their response bodies. The shapes below follow RFC 8414
 * (authorization server metadata) and RFC 9728 (protected resource
 * metadata).
 */
export function createOAuthRoutes(service: OAuthService, options: OAuthRouteOptions): Hono<AuthenticatedEnvironment> {
  const now = options.now ?? (() => new Date());
  const routes = new Hono<AuthenticatedEnvironment>();

  routes.get('/.well-known/oauth-protected-resource', (context) => {
    return context.json({
      resource: `${options.issuer}/mcp`,
      authorization_servers: [options.issuer],
      scopes_supported: ['mcp:read', 'mcp:write'],
      bearer_methods_supported: ['header'],
    });
  });

  routes.get('/.well-known/oauth-authorization-server', (context) => {
    return context.json({
      issuer: options.issuer,
      authorization_endpoint: `${options.issuer}/oauth/authorize`,
      token_endpoint: `${options.issuer}/oauth/token`,
      revocation_endpoint: `${options.issuer}/oauth/revoke`,
      registration_endpoint: `${options.issuer}/oauth/register`,
      scopes_supported: ['mcp:read', 'mcp:write'],
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none'],
    });
  });

  routes.post('/oauth/register', async (context) => {
    const body = await readJson(context);
    if (
      !isRecord(body) ||
      Object.keys(body).some((key) => key !== 'redirect_uri' && key !== 'client_name') ||
      typeof body['redirect_uri'] !== 'string' ||
      (body['client_name'] !== undefined && typeof body['client_name'] !== 'string')
    ) {
      throw new ApiError(400, 'invalid_request', 'The register request must include a redirect_uri and optionally a client_name.');
    }
    const result = service.registerClient(
      body['redirect_uri'],
      body['client_name'] as string | undefined,
    );
    return context.json(result, 201);
  });

  routes.use('/oauth/authorize', requireAccessToken(options.jwtKeys, options.store, now));
  routes.get('/oauth/authorize', async (context) => {
    const result = await service.authorize(context.get('auth').sub, {
      clientId: context.req.query('client_id') ?? '',
      clientName: context.req.query('client_name'),
      redirectUri: context.req.query('redirect_uri') ?? '',
      responseType: context.req.query('response_type') ?? '',
      scope: context.req.query('scope'),
      state: context.req.query('state'),
      codeChallenge: context.req.query('code_challenge'),
      codeChallengeMethod: context.req.query('code_challenge_method'),
      instance: context.req.query('instance'),
    });
    const target = new URL(result.redirectUri);
    target.searchParams.set('code', result.code);
    target.searchParams.set('state', result.state);
    return context.redirect(target.toString(), 302);
  });

  routes.post('/oauth/token', async (context) => {
    const fields = await readFormFields(context);
    const grantType = fields['grant_type'];
    if (grantType === undefined) {
      throw new ApiError(400, 'invalid_request', 'The grant_type field is required.');
    }
    if (grantType === 'authorization_code') {
      const code = fields['code'];
      const redirectUri = fields['redirect_uri'];
      const codeVerifier = fields['code_verifier'];
      const clientId = fields['client_id'];
      if (
        code === undefined || redirectUri === undefined ||
        codeVerifier === undefined || clientId === undefined
      ) {
        throw new ApiError(400, 'invalid_request', 'The authorization_code grant requires code, redirect_uri, code_verifier and client_id.');
      }
      return context.json(await service.exchangeAuthorizationCode({
        code,
        redirectUri,
        codeVerifier,
        clientId,
        ipAddress: requestIp(context.req.raw.headers),
      }));
    }
    if (grantType === 'refresh_token') {
      const refreshToken = fields['refresh_token'];
      const clientId = fields['client_id'];
      if (refreshToken === undefined || clientId === undefined) {
        throw new ApiError(400, 'invalid_request', 'The refresh_token grant requires refresh_token and client_id.');
      }
      return context.json(await service.refreshTokens({
        refreshToken,
        clientId,
        ipAddress: requestIp(context.req.raw.headers),
      }));
    }
    throw new ApiError(400, 'unsupported_grant_type', 'Only authorization_code and refresh_token grants are supported.');
  });

  routes.post('/oauth/revoke', async (context) => {
    const fields = await readFormFields(context);
    const token = fields['token'];
    if (token === undefined) {
      throw new ApiError(400, 'invalid_request', 'The revoke request requires a token.');
    }
    await service.revoke({ token, ipAddress: requestIp(context.req.raw.headers) });
    // RFC 7009: always 200, even for unknown tokens.
    return context.json({});
  });

  return routes;
}
