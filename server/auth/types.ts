import type { DbDumpTables } from '../admin/types.js';
import type {
  McpConfirmationInput,
  McpConfirmationRecord,
  OAuthAuthCodeInput,
  OAuthAuthCodeRecord,
  OAuthAuthorizationInput,
  OAuthAuthorizationRecord,
  OAuthAuthorizationRotation,
} from '../oauth/types.js';
import type { VaultItemPayload } from '../vault/types.js';

export type DeviceType = 'app' | 'web';
export type RefreshRevocationReason =
  | 'rotated'
  | 'device_revoked'
  | 'password_changed'
  | 'logout'
  | 'account_disabled';

type DbTimestamp = Date | string | null;

export type AuthCodePurpose = 'verify' | 'reset' | 'delete';
export type UserRole = 'admin' | 'user' | 'super_admin';

export interface AuthCodeRecord {
  readonly id: string;
  readonly email: string;
  readonly codeHash: string;
  readonly purpose: AuthCodePurpose;
  readonly expiresAt: DbTimestamp;
  readonly attempts: number;
  readonly usedAt: DbTimestamp;
  readonly createdAt: DbTimestamp;
}

export interface RateLimitWindow {
  readonly scope: string;
  readonly key: string;
  readonly windowStart: Date;
  readonly expiresAt: Date;
}

export interface AuthUser {
  readonly id: string;
  readonly email: string;
  readonly passwordHash: string;
  readonly disabledAt: DbTimestamp;
  readonly emailVerifiedAt: DbTimestamp;
}

export interface AuthAuditLogInput {
  readonly actorUserId: string | null;
  readonly targetUserId: string | null;
  readonly action: string;
  readonly targetType: string | null;
  readonly metadata: string | null;
  readonly ipAddress: string | null;
  readonly createdAt: Date;
}

export interface AuthDevice {
  readonly id: string;
  readonly deviceName: string;
  readonly deviceType: string;
}

export interface RefreshTokenRecord {
  readonly id: string;
  readonly userId: string;
  readonly deviceId: string | null;
  readonly tokenHash: string;
  readonly expiresAt: DbTimestamp;
  readonly absoluteExpiresAt: DbTimestamp;
  readonly revokedAt: DbTimestamp;
  readonly revokedReason: RefreshRevocationReason | null;
  readonly reuseAlertedAt: DbTimestamp;
}

export interface RefreshOwnerStatus {
  readonly email: string;
  readonly accountDisabledAt: DbTimestamp;
  readonly deviceRevokedAt: DbTimestamp;
}

export interface AccessOwnerStatus {
  readonly accountDisabledAt: DbTimestamp;
  readonly deviceRevokedAt: DbTimestamp;
}

export interface LoginLogInput {
  readonly userId: string | null;
  readonly deviceId: string | null;
  readonly deviceName: string | null;
  readonly ipAddress: string | null;
  readonly userAgent: string | null;
  readonly result: 'success' | 'failed';
  readonly failureCode: string | null;
  readonly createdAt: Date;
}

export interface NewRefreshTokenInput {
  readonly userId: string;
  readonly deviceId: string;
  readonly tokenHash: string;
  readonly expiresAt: Date;
  readonly absoluteExpiresAt: Date;
  readonly createdAt: Date;
}

export interface AuthTransaction {
  getSetting(key: string): Promise<string | null>;
  lockSettingsForUpdate(): Promise<void>;
  listSettings(): Promise<readonly { readonly key: string; readonly value: string }[]>;
  setSetting(key: string, value: string): Promise<void>;
  deleteSetting(key: string): Promise<void>;
  insertUser(email: string, passwordHash: string, emailVerifiedAt: Date | null): Promise<string | null>;
  findUserByEmailForUpdate(email: string): Promise<AuthUser | null>;
  findUserForUpdate(userId: string): Promise<AuthUser | null>;
  /** Locks the requested accounts in UUID order to keep multi-user mutations deadlock-safe. */
  findUsersForUpdate(userIds: readonly string[]): Promise<readonly AuthUser[]>;
  setUserDisabledAt(userId: string, disabledAt: Date | null): Promise<boolean>;
  grantAdminRole(userId: string, assignedBy: string, assignedAt: Date): Promise<boolean>;
  removeAdminRole(userId: string): Promise<boolean>;
  revokeUserDevice(userId: string, deviceId: string, revokedAt: Date): Promise<boolean>;
  updatePasswordHash(userId: string, expectedHash: string, newHash: string): Promise<boolean>;
  setEmailVerified(userId: string, verifiedAt: Date): Promise<void>;
  insertAuthCode(input: {
    readonly email: string;
    readonly codeHash: string;
    readonly purpose: AuthCodePurpose;
    readonly expiresAt: Date;
    readonly createdAt: Date;
  }): Promise<void>;
  invalidateAuthCodes(email: string, purpose: AuthCodePurpose, invalidatedAt: Date): Promise<void>;
  findLatestAuthCodeForUpdate(email: string, purpose: AuthCodePurpose): Promise<AuthCodeRecord | null>;
  recordAuthCodeFailure(authCodeId: string, attemptedAt: Date): Promise<void>;
  consumeAuthCode(authCodeId: string, consumedAt: Date): Promise<boolean>;
  incrementRateLimit(window: RateLimitWindow): Promise<number>;
  decrementRateLimit(window: RateLimitWindow): Promise<void>;
  findReusableDevice(userId: string, deviceId: string): Promise<AuthDevice | null>;
  updateDevice(deviceId: string, userId: string, deviceName: string, deviceType: DeviceType): Promise<boolean>;
  insertDevice(userId: string, deviceName: string, deviceType: DeviceType): Promise<string>;
  insertRefreshToken(input: NewRefreshTokenInput): Promise<void>;
  /** Non-locking lookup used only to discover the account before taking account-level locks. */
  findRefreshUserIdByHash(tokenHash: string): Promise<string | null>;
  /** Serializes all login-refresh transactions for one account before any refresh-token row lock. */
  lockRefreshUser(userId: string): Promise<boolean>;
  findRefreshTokenForUpdate(tokenHash: string): Promise<RefreshTokenRecord | null>;
  findRefreshOwnerStatus(userId: string, deviceId: string): Promise<RefreshOwnerStatus | null>;
  claimRefreshReuseAlert(refreshTokenId: string, claimedAt: Date): Promise<boolean>;
  revokeAllDevices(userId: string, revokedAt: Date): Promise<void>;
  /**
   * Revokes every unrevoked device of the user and returns how many devices
   * changed state in this call (already-revoked devices are not counted).
   */
  revokeAllDevicesAndCount(userId: string, revokedAt: Date): Promise<number>;
  /**
   * Reads every row of all 16 tables in one snapshot, ordered by primary key,
   * with values normalized for canonical JSON (dates as ISO 8601 strings).
   * The server_settings smtp_pass value is returned as stored; callers that
   * emit the dump must null it before serializing (System Design §5.2).
   */
  readDbDumpTables(): Promise<DbDumpTables>;
  revokeAllUnrevokedRefreshTokens(userId: string, revokedAt: Date): Promise<void>;
  revokeAllRefreshTokensForAccountDisabled(userId: string, revokedAt: Date): Promise<void>;
  revokeAllPasswordResetRefreshTokens(userId: string, revokedAt: Date): Promise<void>;
  revokeAllOAuthAuthorizations(userId: string, revokedAt: Date): Promise<void>;
  insertOAuthAuthCode(input: OAuthAuthCodeInput): Promise<void>;
  findOAuthAuthCodeForUpdate(codeHash: string): Promise<OAuthAuthCodeRecord | null>;
  /** Marks the code consumed only when it is still unconsumed; false means already burned. */
  consumeOAuthAuthCode(codeHash: string, consumedAt: Date): Promise<boolean>;
  /** Deletes an authorization code row (expired codes are removed when encountered, SD §5.3). */
  deleteOAuthAuthorizationCode(codeHash: string): Promise<void>;
  /** Creates one trusted-confirmation record (SD §5.3) and returns its id. */
  insertMcpConfirmation(input: McpConfirmationInput): Promise<string>;
  /** Row-locked lookup for the trusted-UI approve/deny endpoints. */
  findMcpConfirmationForUpdate(id: string): Promise<McpConfirmationRecord | null>;
  /** Row-locked pending, unexpired confirmation for one (user, authorization, item). */
  findPendingMcpConfirmationForUpdate(
    userId: string,
    authorizationId: string,
    itemId: string,
    now: Date,
  ): Promise<McpConfirmationRecord | null>;
  /** Row-locked approved, unexpired, unconsumed confirmation for one (user, authorization, item). */
  findApprovedMcpConfirmationForUpdate(
    userId: string,
    authorizationId: string,
    itemId: string,
    now: Date,
  ): Promise<McpConfirmationRecord | null>;
  /** Sets approved_at only when the row is still pending; false means already decided or expired. */
  approveMcpConfirmation(id: string, approvedAt: Date): Promise<boolean>;
  /** Sets denied_at only when the row is still pending; false means already decided or expired. */
  denyMcpConfirmation(id: string, deniedAt: Date): Promise<boolean>;
  /** Sets consumed_at only when the row is still approved, unexpired and unconsumed. */
  consumeMcpConfirmation(id: string, consumedAt: Date): Promise<boolean>;
  /**
   * Row-locked full ciphertext of one item for the atomic confirmation
   * consume-and-read (SD §5.3): the item must be verified active in the
   * same transaction that consumes the confirmation, so a concurrent
   * delete cannot leak a just-deleted item's ciphertext.
   */
  findVaultItemPayloadForUpdate(userId: string, itemId: string): Promise<VaultItemPayload | null>;
  insertOAuthAuthorization(input: OAuthAuthorizationInput): Promise<string>;
  findOAuthAuthorizationByRefreshTokenHashForUpdate(
    tokenHash: string,
  ): Promise<OAuthAuthorizationRecord | null>;
  /** Atomically replaces the tokens and expiries of one authorization row. */
  rotateOAuthAuthorization(id: string, rotation: OAuthAuthorizationRotation): Promise<boolean>;
  /** Revokes by access- or refresh-token hash; false when no live row matches. */
  revokeOAuthAuthorizationByTokenHash(tokenHash: string, revokedAt: Date): Promise<boolean>;
  findUserRolesForUpdate(userId: string): Promise<readonly UserRole[]>;
  deleteAuthCodesForEmail(email: string): Promise<void>;
  deleteEmailRateLimits(emailKey: string): Promise<void>;
  deleteUser(userId: string): Promise<boolean>;
  insertAuditLog(input: AuthAuditLogInput): Promise<void>;
  markRefreshTokenRotated(refreshTokenId: string, revokedAt: Date): Promise<boolean>;
  revokeRefreshTokenForLogout(refreshTokenId: string, revokedAt: Date): Promise<void>;
  insertLoginLog(input: LoginLogInput): Promise<void>;
}

export interface AuthStore {
  findUserByEmail(email: string): Promise<AuthUser | null>;
  getAccessOwnerStatus(userId: string, deviceId: string): Promise<AccessOwnerStatus | null>;
  transaction<T>(callback: (transaction: AuthTransaction) => Promise<T>): Promise<T>;
}

export interface AuthNotification {
  sendVerificationCode(input: {
    readonly email: string;
    readonly code: string;
    readonly expiresAt: Date;
  }): Promise<void>;
  sendPasswordResetCode(input: {
    readonly email: string;
    readonly code: string;
    readonly expiresAt: Date;
  }): Promise<void>;
  sendDeleteAccountCode(input: {
    readonly email: string;
    readonly code: string;
    readonly expiresAt: Date;
  }): Promise<void>;
  sendNewDeviceLogin(input: {
    readonly email: string;
    readonly userId: string;
    readonly deviceId: string;
    readonly deviceName: string;
    readonly occurredAt: Date;
  }): Promise<void>;
  sendRefreshReuseAlert(input: {
    readonly email: string;
    readonly userId: string;
    readonly deviceId: string;
    readonly occurredAt: Date;
  }): Promise<void>;
}

export type AuthNotificationKind =
  | 'verification_code'
  | 'password_reset_code'
  | 'delete_account_code'
  | 'new_device'
  | 'refresh_reuse';

export interface LoginRequestMetadata {
  readonly ipAddress: string | null;
  readonly userAgent: string | null;
}

export interface LoginInput {
  readonly email: string;
  readonly loginPassword: string;
  readonly deviceName: string;
  readonly deviceType: DeviceType;
  readonly deviceId?: string;
}

export interface TokenPair {
  readonly device_id: string;
  readonly access_token: string;
  readonly refresh_token: string;
}

export interface AccessClaims {
  readonly sub: string;
  readonly device_id: string;
  readonly exp: number;
  readonly iat: number;
  readonly iss: string;
  readonly aud: 'sealero-api';
}
