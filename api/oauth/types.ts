/** OAuth 2.1 + MCP types (System Design §5.3). */

export type OAuthScope = 'mcp:read' | 'mcp:write';

export const OAUTH_SCOPES: readonly OAuthScope[] = ['mcp:read', 'mcp:write'];

export const OAUTH_JWT_AUDIENCE = 'sealero-mcp' as const;

/** Access-token lifetime: 15 minutes, same as the login JWT (SD §5.3, §7.2). */
export const OAUTH_ACCESS_TOKEN_TTL_SECONDS = 15 * 60;

export const OAUTH_AUTHORIZATION_CODE_TTL_MS = 10 * 60 * 1000;
export const OAUTH_REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;
export const OAUTH_ABSOLUTE_SESSION_TTL_MS = 90 * 24 * 60 * 60 * 1000;

/** Trusted-confirmation lifetime: 5 minutes, single use (SD §5.3). */
export const MCP_CONFIRMATION_TTL_MS = 5 * 60 * 1000;

/**
 * One trusted-confirmation request for a vault item detail (SD §5.3).
 * Persisted server-side in mcp_confirmations (SD §3.1, §4.1). Status is
 * derived from the timestamps: pending (none set, unexpired), approved
 * (approved_at set, unconsumed, unexpired), denied, consumed, expired.
 */
export interface McpConfirmationRecord {
  readonly id: string;
  readonly userId: string;
  readonly authorizationId: string;
  readonly itemId: string;
  readonly clientId: string;
  readonly clientName: string | null;
  /** Revocation timestamp of the requesting authorization (null = live). */
  readonly authorizationRevokedAt: Date | null;
  readonly expiresAt: DbTimestamp;
  readonly approvedAt: DbTimestamp;
  readonly deniedAt: DbTimestamp;
  readonly consumedAt: DbTimestamp;
  readonly createdAt: DbTimestamp;
}

export type McpConfirmationStatus = 'pending' | 'approved';

export interface McpConfirmationInput {
  readonly userId: string;
  readonly authorizationId: string;
  readonly itemId: string;
  readonly expiresAt: Date;
  readonly createdAt: Date;
}

/**
 * Non-transactional confirmation reads, used by the trusted-UI list
 * endpoint. Mutations live on AuthTransaction (row-locked, audited).
 */
export interface McpConfirmationStore {
  /**
   * Actionable confirmations for the user: pending plus approved-but-
   * unconsumed, unexpired, newest first. Denied, consumed and expired
   * rows are history (audit_logs) and are not listed.
   */
  listMcpConfirmations(userId: string, now: Date, limit: number): Promise<readonly McpConfirmationRecord[]>;
}

type DbTimestamp = Date | string | null;

export interface OAuthAccessClaims {
  readonly sub: string;
  readonly exp: number;
  readonly iat: number;
  readonly iss: string;
  readonly aud: 'sealero-mcp';
  /** Random per-token ID: two tokens issued in the same second must differ,
   * so the access_token_hash lookup always identifies one authorization. */
  readonly jti: string;
}

export interface OAuthAuthCodeRecord {
  readonly id: string;
  readonly userId: string;
  readonly clientId: string;
  /** Optional client name snapshot, carried into the authorization row at exchange. */
  readonly clientName: string | null;
  readonly redirectUri: string;
  readonly scopes: string;
  readonly codeHash: string;
  readonly codeChallenge: string;
  readonly expiresAt: DbTimestamp;
  readonly consumedAt: DbTimestamp;
}

export interface OAuthAuthorizationRecord {
  readonly id: string;
  readonly userId: string;
  readonly clientId: string;
  readonly clientName: string | null;
  readonly redirectUri: string;
  readonly scopes: string;
  readonly accessTokenHash: string;
  readonly refreshTokenHash: string;
  readonly expiresAt: DbTimestamp;
  readonly refreshExpiresAt: DbTimestamp;
  readonly revokedAt: DbTimestamp;
  readonly createdAt: DbTimestamp;
}

/** Authorization row joined with the owner's account status, for the per-request /mcp check. */
export interface OAuthAuthorizationAccess extends OAuthAuthorizationRecord {
  readonly userDisabledAt: DbTimestamp;
}

export interface OAuthAuthCodeInput {
  readonly userId: string;
  readonly clientId: string;
  readonly clientName: string | null;
  readonly redirectUri: string;
  readonly scopes: string;
  readonly codeHash: string;
  readonly codeChallenge: string;
  readonly expiresAt: Date;
  readonly createdAt: Date;
}

export interface OAuthAuthorizationInput {
  readonly userId: string;
  readonly clientId: string;
  readonly clientName: string | null;
  readonly redirectUri: string;
  readonly scopes: string;
  readonly accessTokenHash: string;
  readonly refreshTokenHash: string;
  readonly expiresAt: Date;
  readonly refreshExpiresAt: Date;
  readonly createdAt: Date;
}

export interface OAuthAuthorizationRotation {
  readonly accessTokenHash: string;
  readonly refreshTokenHash: string;
  readonly expiresAt: Date;
  readonly refreshExpiresAt: Date;
}

/** Non-transactional OAuth reads, used by the per-request /mcp check. */
export interface OAuthStore {
  findOAuthAuthorizationByAccessTokenHash(
    tokenHash: string,
  ): Promise<OAuthAuthorizationAccess | null>;
  /** Records the last successful /mcp call on the authorization row. */
  touchOAuthAuthorizationLastUsed(id: string, usedAt: Date): Promise<void>;
}
