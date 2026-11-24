import { createHash, randomBytes, randomUUID, sign as signBytes, verify as verifyBytes } from 'node:crypto';
import { ApiError } from '../app.js';
import type { JwtKeySet } from '../auth/jwt.js';
import { rateLimitKey, rateLimitWindow, retryAfterSeconds } from '../auth/rate-limit.js';
import { createRefreshToken } from '../auth/tokens.js';
import type { AuthStore } from '../auth/types.js';
import {
  OAUTH_ABSOLUTE_SESSION_TTL_MS,
  OAUTH_ACCESS_TOKEN_TTL_SECONDS,
  OAUTH_AUTHORIZATION_CODE_TTL_MS,
  OAUTH_JWT_AUDIENCE,
  OAUTH_REFRESH_TOKEN_TTL_MS,
  OAUTH_SCOPES,
} from './types.js';
import type { OAuthAccessClaims, OAuthScope, OAuthStore } from './types.js';

export class InvalidOAuthAccessTokenError extends Error {
  constructor() {
    super('Invalid OAuth access token.');
    this.name = 'InvalidOAuthAccessTokenError';
  }
}

export function hashOAuthToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

// The token + revoke endpoints are unauthenticated, so they are capped
// per IP (60 requests per hour each, SD §5.3). They only bound abuse,
// not normal use.
const OAUTH_TOKEN_RATE_WINDOW_MS = 60 * 60_000;
const OAUTH_TOKEN_IP_LIMIT = 60;
const OAUTH_REVOKE_RATE_WINDOW_MS = 60 * 60_000;
const OAUTH_REVOKE_IP_LIMIT = 60;

function encodeJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function decodeBase64Url(segment: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) throw new InvalidOAuthAccessTokenError();
  const decoded = Buffer.from(segment, 'base64url');
  if (decoded.toString('base64url') !== segment) throw new InvalidOAuthAccessTokenError();
  return decoded;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

/**
 * Issues an OAuth access token. Claims are deliberately distinct from the
 * login JWT (no device_id, aud 'sealero-mcp') so a login token can never
 * pass as an MCP token and vice versa.
 *
 * TODO (SD §5.3): the document says the OAuth access token is a 15-minute
 * RS256 JWT but does not spell out its claims. aud 'sealero-mcp' and the
 * {sub, exp, iat, iss, aud, jti} claim set are this implementation's choice.
 */
export function issueOAuthAccessToken(keys: JwtKeySet, userId: string, now: Date): string {
  if (!isUuid(userId) || !Number.isFinite(now.getTime())) {
    throw new Error('Cannot issue OAuth access token with invalid identity or time.');
  }
  const issuedAt = Math.floor(now.getTime() / 1000);
  const claims: OAuthAccessClaims = {
    sub: userId,
    exp: issuedAt + OAUTH_ACCESS_TOKEN_TTL_SECONDS,
    iat: issuedAt,
    iss: keys.issuer,
    aud: OAUTH_JWT_AUDIENCE,
    jti: randomUUID(),
  };
  const header = { alg: 'RS256', kid: keys.activeKid, typ: 'JWT' } as const;
  const signingInput = `${encodeJson(header)}.${encodeJson(claims)}`;
  const signature = signBytes('RSA-SHA256', Buffer.from(signingInput, 'ascii'), keys.privateKey);
  return `${signingInput}.${signature.toString('base64url')}`;
}

export function verifyOAuthAccessToken(
  keys: JwtKeySet,
  token: string,
  now: Date = new Date(),
): OAuthAccessClaims {
  try {
    if (!Number.isFinite(now.getTime())) throw new InvalidOAuthAccessTokenError();
    const segments = token.split('.');
    if (segments.length !== 3) throw new InvalidOAuthAccessTokenError();
    const [encodedHeader, encodedPayload, encodedSignature] = segments;
    if (!encodedHeader || !encodedPayload || !encodedSignature) throw new InvalidOAuthAccessTokenError();

    const headerValue: unknown = JSON.parse(decodeBase64Url(encodedHeader).toString('utf8'));
    const payloadValue: unknown = JSON.parse(decodeBase64Url(encodedPayload).toString('utf8'));
    if (!isRecord(headerValue) || !hasExactKeys(headerValue, ['alg', 'kid', 'typ'])) {
      throw new InvalidOAuthAccessTokenError();
    }
    if (headerValue['alg'] !== 'RS256' || headerValue['typ'] !== 'JWT' || typeof headerValue['kid'] !== 'string') {
      throw new InvalidOAuthAccessTokenError();
    }
    if (!isRecord(payloadValue) || !hasExactKeys(payloadValue, ['sub', 'exp', 'iat', 'iss', 'aud', 'jti'])) {
      throw new InvalidOAuthAccessTokenError();
    }

    const publicKey = keys.publicKeys.get(headerValue['kid']);
    if (!publicKey) throw new InvalidOAuthAccessTokenError();
    const signature = decodeBase64Url(encodedSignature);
    const verified = verifyBytes(
      'RSA-SHA256',
      Buffer.from(`${encodedHeader}.${encodedPayload}`, 'ascii'),
      publicKey,
      signature,
    );
    if (!verified) throw new InvalidOAuthAccessTokenError();

    const { sub, exp, iat, iss, aud, jti } = payloadValue;
    if (
      !isUuid(sub) ||
      !isUuid(jti) ||
      !Number.isSafeInteger(exp) ||
      !Number.isSafeInteger(iat) ||
      typeof iss !== 'string' ||
      iss !== keys.issuer ||
      aud !== OAUTH_JWT_AUDIENCE ||
      (exp as number) <= Math.floor(now.getTime() / 1000) ||
      (exp as number) <= (iat as number)
    ) {
      throw new InvalidOAuthAccessTokenError();
    }

    return payloadValue as unknown as OAuthAccessClaims;
  } catch {
    throw new InvalidOAuthAccessTokenError();
  }
}

/** https, no fragment, no wildcard (SD §5.3, same rule as register). */
export function isValidRedirectUri(value: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  return parsed.protocol === 'https:' && parsed.hash === '' &&
    parsed.hostname.length > 0 && !parsed.hostname.includes('*');
}

function sha256Base64Url(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('base64url');
}

function toDate(value: Date | string | null): Date | null {
  if (value === null) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

export interface TokenResponse {
  readonly access_token: string;
  readonly token_type: 'Bearer';
  readonly expires_in: number;
  readonly refresh_token: string;
  readonly scope: string;
}

export interface AuthorizeParams {
  readonly clientId: string;
  /** Optional client display name, carried into the authorization row. */
  readonly clientName?: string | undefined;
  readonly redirectUri: string;
  readonly responseType: string;
  readonly scope?: string | undefined;
  readonly state?: string | undefined;
  readonly codeChallenge?: string | undefined;
  readonly codeChallengeMethod?: string | undefined;
  /** V1 only accepts the official cloud; any other value is rejected. */
  readonly instance?: string | undefined;
}

export interface AuthorizeResult {
  readonly redirectUri: string;
  readonly code: string;
  readonly state: string;
}

function parseScopes(scope: string | undefined): OAuthScope[] {
  if (scope === undefined || scope.trim() === '') return ['mcp:read'];
  const parts = scope.trim().split(/\s+/);
  const valid: OAuthScope[] = [];
  for (const part of parts) {
    if (!(OAUTH_SCOPES as readonly string[]).includes(part)) {
      throw new ApiError(400, 'invalid_scope', 'The requested scope is not supported.');
    }
    if (!valid.includes(part as OAuthScope)) valid.push(part as OAuthScope);
  }
  return valid;
}

/**
 * Validates an optional client display name (SD §5.3: shown on the trusted
 * confirmation page next to client_id). Returns null when omitted.
 */
function validClientName(value: string | undefined): string | null {
  if (value === undefined) return null;
  const name = value.trim();
  if (name.length === 0 || name.length > 128) {
    throw new ApiError(400, 'invalid_request', 'The client_name must be 1-128 characters.');
  }
  return name;
}

export class OAuthService {
  constructor(
    private readonly store: AuthStore & OAuthStore,
    private readonly jwtKeys: JwtKeySet,
    private readonly now: () => Date = () => new Date(),
  ) {}

  /**
   * Dynamic client registration (SD §5.3). Creates no database row — there
   * is no oauth_clients table; only the client_id is returned. An optional
   * client_name is accepted (and validated) here so clients can declare
   * it; the name itself is carried into the authorization row at authorize
   * time, since registration persists nothing.
   *
   * TODO (SD §5.3): the document only specifies that client_id is returned.
   * The 201 status follows RFC 7591; the client_id format (32 random bytes,
   * base64url) is this implementation's choice.
   */
  registerClient(redirectUri: string, clientName?: string | undefined): { readonly client_id: string } {
    if (!isValidRedirectUri(redirectUri)) {
      throw new ApiError(400, 'invalid_redirect_uri', 'The redirect_uri must be https without a fragment or wildcard.');
    }
    // Validated for consistency with authorize; the value is not stored
    // (registration creates no row) and is not returned.
    validClientName(clientName);
    return { client_id: randomBytes(32).toString('base64url') };
  }

  /**
   * Authorization with forced PKCE S256 (SD §5.3). The caller must already be
   * authenticated as the user (login JWT); the granted scopes come from the
   * scope parameter, which the web frontend renders as checkboxes. An
   * optional client_name is stored on the authorization code and carried
   * into the authorization row at exchange, so the trusted-confirmation
   * page can show it next to the client_id.
   *
   * TODO (SD §5.3): the document does not define the authorize error
   * behavior (redirect with ?error= vs JSON 400), the client_id format, or
   * the instance-selection parameter. Failures here return 400 JSON and
   * never redirect.
   */
  async authorize(userId: string, params: AuthorizeParams): Promise<AuthorizeResult> {
    const now = this.now();
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(params.clientId)) {
      throw new ApiError(400, 'invalid_request', 'The client_id is invalid.');
    }
    const clientName = validClientName(params.clientName);
    if (!isValidRedirectUri(params.redirectUri)) {
      throw new ApiError(400, 'invalid_request', 'The redirect_uri must be https without a fragment or wildcard.');
    }
    if (params.responseType !== 'code') {
      throw new ApiError(400, 'invalid_request', 'Only response_type=code is supported.');
    }
    const scopes = parseScopes(params.scope);
    if (params.state === undefined || params.state === '') {
      throw new ApiError(400, 'invalid_request', 'The state parameter is required.');
    }
    if (params.codeChallenge === undefined || !/^[A-Za-z0-9_-]{43}$/.test(params.codeChallenge)) {
      throw new ApiError(400, 'invalid_request', 'A PKCE S256 code_challenge is required.');
    }
    if (params.codeChallengeMethod !== 'S256') {
      throw new ApiError(400, 'invalid_request', 'Only PKCE S256 is supported.');
    }
    if (params.instance !== undefined && params.instance !== 'official') {
      throw new ApiError(400, 'invalid_request', 'V1 MCP only connects to the official cloud.');
    }

    const code = randomBytes(32).toString('base64url');
    await this.store.transaction(async (transaction) => {
      await transaction.insertOAuthAuthCode({
        userId,
        clientId: params.clientId,
        clientName,
        redirectUri: params.redirectUri,
        scopes: scopes.join(' '),
        codeHash: hashOAuthToken(code),
        codeChallenge: params.codeChallenge as string,
        expiresAt: new Date(now.getTime() + OAUTH_AUTHORIZATION_CODE_TTL_MS),
        createdAt: now,
      });
    });
    return { redirectUri: params.redirectUri, code, state: params.state };
  }

  /**
   * Authorization-code exchange (SD §5.3). The code is consumed and the
   * authorization row is created in one transaction: if token issuance
   * fails, the transaction rolls back and the code is not burned. A
   * client_id / redirect_uri / PKCE mismatch burns the code and writes an
   * audit log, then returns invalid_grant.
   *
   * TODO (SD §5.3): the document requires an audit log on mismatch but does
   * not name the action or its metadata. The action used here is
   * oauth_token_invalid_grant with empty metadata. The token response field
   * names follow RFC 6749 §5.1; the document does not spell them out.
   */
  async exchangeAuthorizationCode(input: {
    readonly code: string;
    readonly redirectUri: string;
    readonly codeVerifier: string;
    readonly clientId: string;
    readonly ipAddress: string | null;
  }): Promise<TokenResponse> {
    const now = this.now();
    const ipWindow = input.ipAddress === null
      ? null
      : rateLimitWindow('oauth_token_ip', rateLimitKey(input.ipAddress), now, OAUTH_TOKEN_RATE_WINDOW_MS);
    const outcome = await this.store.transaction(async (transaction) => {
      const ipCount = ipWindow === null ? 0 : await transaction.incrementRateLimit(ipWindow);
      if (ipCount > OAUTH_TOKEN_IP_LIMIT) return { kind: 'rate_limited' } as const;
      const codeRow = await transaction.findOAuthAuthCodeForUpdate(hashOAuthToken(input.code));
      if (codeRow === null) return { kind: 'invalid_grant' } as const;
      if (codeRow.consumedAt !== null) return { kind: 'invalid_grant' } as const;
      const expiresAt = toDate(codeRow.expiresAt);
      if (expiresAt === null || expiresAt.getTime() <= now.getTime()) {
        // SD §5.3: an expired code is deleted when encountered.
        await transaction.deleteOAuthAuthorizationCode(codeRow.codeHash);
        return { kind: 'invalid_grant' } as const;
      }
      if (
        codeRow.clientId !== input.clientId ||
        codeRow.redirectUri !== input.redirectUri ||
        !/^[A-Za-z0-9_-]{43,128}$/.test(input.codeVerifier) ||
        sha256Base64Url(input.codeVerifier) !== codeRow.codeChallenge
      ) {
        await transaction.consumeOAuthAuthCode(codeRow.codeHash, now);
        await transaction.insertAuditLog({
          actorUserId: codeRow.userId,
          targetUserId: codeRow.userId,
          action: 'oauth_token_invalid_grant',
          targetType: 'oauth_authorization',
          metadata: '{}',
          ipAddress: input.ipAddress,
          createdAt: now,
        });
        return { kind: 'invalid_grant' } as const;
      }
      // A disabled account cannot exchange a code. The code is not
      // consumed here, so it stays usable if the account is re-enabled.
      const owner = await transaction.findUserForUpdate(codeRow.userId);
      if (owner === null || owner.disabledAt !== null) return { kind: 'disabled' } as const;

      const accessToken = issueOAuthAccessToken(this.jwtKeys, codeRow.userId, now);
      const refreshToken = createRefreshToken();
      const expiresAtOut = new Date(now.getTime() + OAUTH_ACCESS_TOKEN_TTL_SECONDS * 1000);
      const refreshExpiresAt = new Date(now.getTime() + OAUTH_REFRESH_TOKEN_TTL_MS);
      await transaction.insertOAuthAuthorization({
        userId: codeRow.userId,
        clientId: codeRow.clientId,
        clientName: codeRow.clientName,
        redirectUri: codeRow.redirectUri,
        scopes: codeRow.scopes,
        accessTokenHash: hashOAuthToken(accessToken),
        refreshTokenHash: hashOAuthToken(refreshToken),
        expiresAt: expiresAtOut,
        refreshExpiresAt,
        createdAt: now,
      });
      await transaction.consumeOAuthAuthCode(codeRow.codeHash, now);
      return {
        kind: 'ok',
        accessToken,
        refreshToken,
        scopes: codeRow.scopes,
      } as const;
    });
    if (outcome.kind === 'invalid_grant') {
      throw new ApiError(400, 'invalid_grant', 'The authorization code is invalid, expired, or already used.');
    }
    if (outcome.kind === 'disabled') {
      throw new ApiError(401, 'unauthorized', 'This account is disabled.');
    }
    if (outcome.kind === 'rate_limited') {
      const retryAfter = ipWindow === null ? undefined : retryAfterSeconds(ipWindow, this.now());
      throw new ApiError(429, 'rate_limited', 'Too many token requests. Please try again later.', retryAfter);
    }
    return {
      access_token: outcome.accessToken,
      token_type: 'Bearer',
      expires_in: OAUTH_ACCESS_TOKEN_TTL_SECONDS,
      refresh_token: outcome.refreshToken,
      scope: outcome.scopes,
    };
  }

  /**
   * Refresh-token rotation (SD §5.3). The same authorization row is updated
   * atomically; the old refresh token then only returns 401 — no reuse
   * detection, no revocation cascade, no email (unlike the login refresh
   * flow in §7.2).
   */
  async refreshTokens(input: {
    readonly refreshToken: string;
    readonly clientId: string;
    readonly ipAddress?: string | null;
  }): Promise<TokenResponse> {
    const now = this.now();
    const ipWindow = input.ipAddress == null
      ? null
      : rateLimitWindow('oauth_token_ip', rateLimitKey(input.ipAddress), now, OAUTH_TOKEN_RATE_WINDOW_MS);
    const outcome = await this.store.transaction(async (transaction) => {
      const ipCount = ipWindow === null ? 0 : await transaction.incrementRateLimit(ipWindow);
      if (ipCount > OAUTH_TOKEN_IP_LIMIT) return { kind: 'rate_limited' } as const;
      const authorization = await transaction.findOAuthAuthorizationByRefreshTokenHashForUpdate(
        hashOAuthToken(input.refreshToken),
      );
      if (authorization === null) return { kind: 'unauthorized' } as const;
      if (authorization.revokedAt !== null) return { kind: 'unauthorized' } as const;
      if (authorization.clientId !== input.clientId) return { kind: 'unauthorized' } as const;
      const refreshExpiresAt = toDate(authorization.refreshExpiresAt);
      const createdAt = toDate(authorization.createdAt);
      if (refreshExpiresAt === null || createdAt === null || refreshExpiresAt.getTime() <= now.getTime()) {
        return { kind: 'unauthorized' } as const;
      }
      // A disabled account must not rotate tokens for the rest of its
      // 90-day absolute session; /mcp would refuse the token anyway.
      const owner = await transaction.findUserForUpdate(authorization.userId);
      if (owner === null || owner.disabledAt !== null) return { kind: 'unauthorized' } as const;

      const accessToken = issueOAuthAccessToken(this.jwtKeys, authorization.userId, now);
      const refreshToken = createRefreshToken();
      const expiresAt = new Date(now.getTime() + OAUTH_ACCESS_TOKEN_TTL_SECONDS * 1000);
      const nextRefreshExpiresAt = new Date(Math.min(
        now.getTime() + OAUTH_REFRESH_TOKEN_TTL_MS,
        createdAt.getTime() + OAUTH_ABSOLUTE_SESSION_TTL_MS,
      ));
      const rotated = await transaction.rotateOAuthAuthorization(authorization.id, {
        accessTokenHash: hashOAuthToken(accessToken),
        refreshTokenHash: hashOAuthToken(refreshToken),
        expiresAt,
        refreshExpiresAt: nextRefreshExpiresAt,
      });
      if (!rotated) return { kind: 'unauthorized' } as const;
      return {
        kind: 'ok',
        accessToken,
        refreshToken,
        scopes: authorization.scopes,
      } as const;
    });
    if (outcome.kind === 'unauthorized') {
      throw new ApiError(401, 'unauthorized', 'The refresh token is invalid or expired.');
    }
    if (outcome.kind === 'rate_limited') {
      const retryAfter = ipWindow === null ? undefined : retryAfterSeconds(ipWindow, this.now());
      throw new ApiError(429, 'rate_limited', 'Too many token requests. Please try again later.', retryAfter);
    }
    return {
      access_token: outcome.accessToken,
      token_type: 'Bearer',
      expires_in: OAUTH_ACCESS_TOKEN_TTL_SECONDS,
      refresh_token: outcome.refreshToken,
      scope: outcome.scopes,
    };
  }

  /** Revokes by access- or refresh-token hash (RFC 7009: always 200 at the route). */
  async revoke(input: { readonly token: string; readonly ipAddress?: string | null }): Promise<boolean> {
    const now = this.now();
    const ipWindow = input.ipAddress == null
      ? null
      : rateLimitWindow('oauth_revoke_ip', rateLimitKey(input.ipAddress), now, OAUTH_REVOKE_RATE_WINDOW_MS);
    const outcome = await this.store.transaction(async (transaction) => {
      const ipCount = ipWindow === null ? 0 : await transaction.incrementRateLimit(ipWindow);
      if (ipCount > OAUTH_REVOKE_IP_LIMIT) return { kind: 'rate_limited' } as const;
      const revoked = await transaction.revokeOAuthAuthorizationByTokenHash(hashOAuthToken(input.token), now);
      return { kind: 'ok', revoked } as const;
    });
    if (outcome.kind === 'rate_limited') {
      const retryAfter = ipWindow === null ? undefined : retryAfterSeconds(ipWindow, this.now());
      throw new ApiError(429, 'rate_limited', 'Too many revoke requests. Please try again later.', retryAfter);
    }
    return outcome.revoked;
  }
}
