import { createHmac, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import { hashLoginPassword, loginPasswordNeedsRehash, verifyLoginPassword } from './password.js';
import { rateLimitKey, rateLimitWindow, retryAfterSeconds } from './rate-limit.js';
import { createTokenPair, hashRefreshToken, isCanonicalRefreshToken, createRefreshToken,
  ABSOLUTE_SESSION_TTL_MS, REFRESH_REUSE_WINDOW_MS, REFRESH_TOKEN_TTL_MS } from './tokens.js';
import type { JwtKeySet } from './jwt.js';
import type {
  AuthCodePurpose,
  AuthCodeRecord,
  AuthNotification,
  AuthNotificationKind,
  AuthStore,
  AuthTransaction,
  AuthUser,
  LoginInput,
  LoginRequestMetadata,
  LoginLogInput,
  RateLimitWindow,
  TokenPair,
} from './types.js';

const INVALID_CREDENTIALS = {
  status: 401 as const,
  code: 'invalid_credentials',
  message: 'Email or password is incorrect.',
};

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const GENERIC_REGISTRATION_RESPONSE = {
  status: 202 as const,
  code: 'registration_received',
  message: 'If registration can proceed, the account is ready for sign-in.',
};

const GENERIC_VERIFICATION_RESPONSE = {
  status: 202 as const,
  code: 'verification_code_requested',
  message: 'If the account is eligible, a verification email will be sent.',
};
const GENERIC_RECOVERY_RESPONSE = {
  status: 202 as const,
  code: 'password_recovery_requested',
  message: 'If the account is eligible, a password recovery email will be sent.',
};
const GENERIC_DELETE_CODE_RESPONSE = {
  status: 202 as const,
  code: 'delete_code_requested',
  message: 'If the account is eligible, a deletion confirmation email will be sent.',
};
const CODE_TTL_MS = { verify: 15 * 60_000, reset: 30 * 60_000, delete: 15 * 60_000 } as const satisfies Record<AuthCodePurpose, number>;
const CODE_RESEND_INTERVAL_MS = 60_000;
const LOGIN_RATE_WINDOW_MS = 15 * 60_000;
const LOGIN_EMAIL_FAILURE_LIMIT = 10;
const LOGIN_IP_FAILURE_LIMIT = 30;
const RECOVERY_RATE_WINDOW_MS = 60 * 60_000;
const RECOVERY_EMAIL_LIMIT = 3;
const RECOVERY_IP_LIMIT = 10;
// Registration, verification resend and delete-code use the recovery
// calibre: 3 attempts per email/user per hour, 10 per IP per hour.
const REGISTRATION_RATE_WINDOW_MS = 60 * 60_000;
const REGISTRATION_EMAIL_LIMIT = 3;
const REGISTRATION_IP_LIMIT = 10;
const VERIFICATION_RESEND_RATE_WINDOW_MS = 60 * 60_000;
const VERIFICATION_RESEND_EMAIL_LIMIT = 3;
const VERIFICATION_RESEND_IP_LIMIT = 10;
const DELETE_CODE_RATE_WINDOW_MS = 60 * 60_000;
const DELETE_CODE_USER_LIMIT = 3;
const DELETE_CODE_IP_LIMIT = 10;
const AUTH_CODE_PATTERN = /^\d{6}$/;

interface CodeDispatch {
  readonly email: string;
  readonly code: string;
  readonly expiresAt: Date;
}

type CodeOperationResult = 'success' | 'invalid' | 'disabled';

class AuthCodeNotificationFailure extends Error {
  constructor(readonly kind: 'verification_code' | 'password_reset_code' | 'delete_account_code') {
    super('Authentication-code notification delivery failed.');
    this.name = 'AuthCodeNotificationFailure';
  }
}

/** Allowed auto-lock timeouts in minutes (System Design §3.1/§5.1). */
const AUTO_LOCK_MINUTES_OPTIONS: readonly number[] = [5, 15, 30, 60];
/** Auto-lock timeout when the user never set one. */
const DEFAULT_AUTO_LOCK_MINUTES = 15;

export class AuthServiceError extends Error {
  constructor(
    readonly status: 400 | 401 | 403 | 429,
    readonly code: string,
    message: string,
    /**
     * Seconds until the caller may retry. Set only on 429 `rate_limited`
     * errors; route handlers surface it as a `Retry-After` header.
     */
    readonly retryAfterSeconds?: number,
  ) {
    super(message);
    this.name = 'AuthServiceError';
  }
}

export interface AuthServiceOptions {
  readonly authCodeHmacSecret: string;
  readonly now?: () => Date;
  readonly delayLoginFailure?: (milliseconds: number) => Promise<void>;
  /** Receives only a fixed event label; request data and secrets are never logged. */
  readonly onNotificationFailure?: (kind: AuthNotificationKind) => void;
}

interface ServiceClock {
  now(): Date;
}

interface SensitivePasswordContext {
  readonly user: AuthUser;
  readonly emailWindow: RateLimitWindow;
  readonly ipWindow: RateLimitWindow | null;
}

interface LoginSuccess {
  readonly tokenPair: TokenPair;
  readonly newDevice: boolean;
  readonly email: string;
}

type LoginTransactionResult =
  | { readonly kind: 'success'; readonly value: LoginSuccess }
  | { readonly kind: 'failure' };

type RefreshTransactionResult =
  | { readonly kind: 'success'; readonly tokenPair: TokenPair }
  | { readonly kind: 'reuse_claimed'; readonly userId: string; readonly email: string; readonly deviceId: string }
  | { readonly kind: 'invalid' };

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function validEmail(email: string): boolean {
  return email.length <= 255 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function dateValue(value: Date | string | null): Date | null {
  if (value === null) return null;
  const parsed = value instanceof Date ? value : new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed : null;
}

function isSet(value: Date | string | null): boolean {
  return value !== null;
}

function databaseBoolean(value: string | null, defaultValue: boolean, invalidValue: boolean): boolean {
  if (value === null) return defaultValue;
  if (value === 'true') return true;
  if (value === 'false') return false;
  return invalidValue;
}

function makeLoginLog(
  metadata: LoginRequestMetadata,
  fields: Pick<LoginLogInput, 'userId' | 'deviceId' | 'deviceName' | 'result' | 'failureCode'>,
  now: Date,
): LoginLogInput {
  return { ...fields, ipAddress: metadata.ipAddress, userAgent: metadata.userAgent, createdAt: now };
}

function authCodeHash(secret: string, purpose: AuthCodePurpose, email: string, code: string): string {
  return createHmac('sha256', secret)
    .update(purpose, 'utf8')
    .update('\0', 'utf8')
    .update(email, 'utf8')
    .update('\0', 'utf8')
    .update(code, 'utf8')
    .digest('hex');
}

function digestMatches(expectedHex: string, actualHex: string): boolean {
  const expected = Buffer.from(expectedHex, 'hex');
  const actual = Buffer.from(actualHex, 'hex');
  return expected.length === 32 && actual.length === 32 && timingSafeEqual(expected, actual);
}

function makeVerificationCode(): string {
  return randomInt(0, 1_000_000).toString().padStart(6, '0');
}

function loginFailureDelayMs(failuresInWindow: number): number {
  if (failuresInWindow <= 0) return 0;
  return Math.min(3_200, 100 * (2 ** Math.min(failuresInWindow - 1, 5)));
}

function defaultDelay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

/**
 * System Design §5.1 login-password rule: at least 8 characters, at most
 * 4096 UTF-8 bytes, verbatim. Violations return 400 `invalid_login_password`.
 * The master password is never checked here; it is client-validated.
 */
function requirePassword(value: string, errorCode = 'invalid_login_password'): void {
  if (value.length < 8 || Buffer.byteLength(value, 'utf8') > 4096) {
    throw new AuthServiceError(400, errorCode, 'The login password is invalid.');
  }
}

export class AuthService {
  private dummyPasswordHash: Promise<string> | null = null;
  private readonly clock: ServiceClock;
  private readonly authCodeHmacSecret: string;
  private readonly delayLoginFailure: (milliseconds: number) => Promise<void>;
  private readonly notifyFailure: (kind: AuthNotificationKind) => void;

  constructor(
    private readonly store: AuthStore,
    private readonly jwtKeys: JwtKeySet,
    private readonly notifications: AuthNotification,
    options: AuthServiceOptions,
  ) {
    if (Buffer.byteLength(options.authCodeHmacSecret, 'utf8') < 32) {
      throw new Error('AUTH_CODE_HMAC_SECRET must contain at least 32 UTF-8 bytes.');
    }
    this.authCodeHmacSecret = options.authCodeHmacSecret;
    this.clock = { now: options.now ?? (() => new Date()) };
    this.delayLoginFailure = options.delayLoginFailure ?? defaultDelay;
    this.notifyFailure = options.onNotificationFailure ?? (() => undefined);
  }

  /**
   * Returns the login identity for GET /v1/auth/me (System Design §5.1):
   * {id, email, display_name, avatar_url} for the JWT's own account.
   * The caller already passed
   * the per-request revocation check, so a missing row here only means the
   * account was deleted after the token was issued.
   */
  async getCurrentUser(userId: string): Promise<{ readonly id: string; readonly email: string; readonly display_name: string | null; readonly avatar_url: string | null }> {
    const user = await this.store.findUserById(userId);
    if (user === null) {
      throw new AuthServiceError(401, 'unauthorized', 'A valid access token is required.');
    }
    return user;
  }

  /** Reads the caller's auto-lock timeout; no preference row means the 15-minute default. */
  async getUserPreferences(userId: string): Promise<{ readonly auto_lock_minutes: number }> {
    const user = await this.store.findUserById(userId);
    if (user === null) {
      throw new AuthServiceError(401, 'unauthorized', 'A valid access token is required.');
    }
    const preferences = await this.store.getUserPreferences(userId);
    return { auto_lock_minutes: preferences?.auto_lock_minutes ?? DEFAULT_AUTO_LOCK_MINUTES };
  }

  /** Replaces the caller's auto-lock timeout; creates the preference row when missing. */
  async updateUserPreferences(userId: string, autoLockMinutes: unknown): Promise<{ readonly auto_lock_minutes: number }> {
    if (typeof autoLockMinutes !== 'number' || !Number.isInteger(autoLockMinutes) || !AUTO_LOCK_MINUTES_OPTIONS.includes(autoLockMinutes)) {
      throw new AuthServiceError(400, 'invalid_request', 'auto_lock_minutes must be one of 5, 15, 30, 60.');
    }
    const user = await this.store.findUserById(userId);
    if (user === null) {
      throw new AuthServiceError(401, 'unauthorized', 'A valid access token is required.');
    }
    return this.store.upsertUserPreferences(userId, autoLockMinutes);
  }

  /** Updates the caller's display name and/or avatar URL; an empty string clears the field. */
  async updateUserProfile(userId: string, displayName: unknown, avatarUrl: unknown): Promise<{ readonly id: string; readonly email: string; readonly display_name: string | null; readonly avatar_url: string | null }> {
    let displayNameValue: string | null | undefined;
    if (displayName !== undefined) {
      if (typeof displayName !== 'string') {
        throw new AuthServiceError(400, 'invalid_request', 'display_name must be a string.');
      }
      const trimmed = displayName.trim();
      if (trimmed.length > 64) {
        throw new AuthServiceError(400, 'invalid_request', 'display_name must be at most 64 characters.');
      }
      displayNameValue = trimmed === '' ? null : trimmed;
    }
    let avatarUrlValue: string | null | undefined;
    if (avatarUrl !== undefined) {
      if (typeof avatarUrl !== 'string') {
        throw new AuthServiceError(400, 'invalid_request', 'avatar_url must be a string.');
      }
      const trimmed = avatarUrl.trim();
      if (trimmed === '') {
        avatarUrlValue = null;
      } else {
        let parsed: URL;
        try {
          parsed = new URL(trimmed);
        } catch {
          throw new AuthServiceError(400, 'invalid_request', 'avatar_url must be a valid https URL.');
        }
        if (parsed.protocol !== 'https:' || trimmed.length > 2048) {
          throw new AuthServiceError(400, 'invalid_request', 'avatar_url must be a valid https URL.');
        }
        avatarUrlValue = trimmed;
      }
    }
    const patch: { displayName?: string | null; avatarUrl?: string | null } = {};
    if (displayNameValue !== undefined) patch.displayName = displayNameValue;
    if (avatarUrlValue !== undefined) patch.avatarUrl = avatarUrlValue;
    const updated = await this.store.updateUserProfile(userId, patch);
    if (updated === null) {
      throw new AuthServiceError(401, 'unauthorized', 'A valid access token is required.');
    }
    return updated;
  }

  async register(
    emailInput: string,
    loginPassword: string,
    metadata: LoginRequestMetadata,
  ): Promise<typeof GENERIC_REGISTRATION_RESPONSE & { readonly email_verification_required: boolean }> {
    const email = normalizeEmail(emailInput);
    if (!validEmail(email)) throw new AuthServiceError(400, 'invalid_request', 'A valid email and login password are required.');
    requirePassword(loginPassword);

    // Count the attempt before the Argon2 hash: hashing is the expensive
    // part, and an uncapped register endpoint would let one IP burn CPU.
    const now = this.clock.now();
    const emailWindow = rateLimitWindow('registration_email', rateLimitKey(email), now, REGISTRATION_RATE_WINDOW_MS);
    const ipWindow = metadata.ipAddress === null
      ? null
      : rateLimitWindow('registration_ip', rateLimitKey(metadata.ipAddress), now, REGISTRATION_RATE_WINDOW_MS);
    const limited = await this.store.transaction(async (transaction) => {
      const emailCount = await transaction.incrementRateLimit(emailWindow);
      const ipCount = ipWindow === null ? 0 : await transaction.incrementRateLimit(ipWindow);
      return emailCount > REGISTRATION_EMAIL_LIMIT || ipCount > REGISTRATION_IP_LIMIT;
    });
    if (limited) {
      throw new AuthServiceError(
        429,
        'rate_limited',
        'Too many registration attempts. Please try again later.',
        retryAfterSeconds(emailWindow, this.clock.now()),
      );
    }

    // Hash regardless of registration availability or duplicate email so the external response is uniform.
    const passwordHash = await hashLoginPassword(loginPassword);
    // The flag is the global setting, read even when registration is closed
    // or the email already exists, so the response stays uniform: it reveals
    // nothing about this email, only whether verification is required at all.
    let emailVerificationRequired = true;
    try {
      await this.store.transaction(async (transaction) => {
        const allowRegistration = databaseBoolean(await transaction.getSetting('allow_registration'), true, false);
        emailVerificationRequired = databaseBoolean(await transaction.getSetting('require_email_verification'), true, true);
        if (!allowRegistration) return;
        const requireVerification = emailVerificationRequired;
        const userId = await transaction.insertUser(email, passwordHash, requireVerification ? null : now);
        if (userId) {
          // Roles are granted whether or not email verification is required:
          // the first user is the admin even on deployments with verification
          // off. A duplicate email inserts nothing, so no roles are granted.
          await transaction.grantRegistrationRoles(userId, now);
        }
        if (!userId || !requireVerification) return;
        const verification = await this.createCodeWithinTransaction(transaction, email, 'verify', now);
        await this.sendAuthCodeWithinTransaction('verification_code', () =>
          this.notifications.sendVerificationCode(verification));
      });
    } catch (error) {
      if (!(error instanceof AuthCodeNotificationFailure)) throw error;
    }
    return { ...GENERIC_REGISTRATION_RESPONSE, email_verification_required: emailVerificationRequired };
  }

  async verifyEmail(emailInput: string, code: string): Promise<{ readonly status: 200; readonly code: 'email_verified'; readonly message: string }> {
    const email = normalizeEmail(emailInput);
    if (!validEmail(email) || !AUTH_CODE_PATTERN.test(code)) {
      throw new AuthServiceError(400, 'invalid_request', 'The verification request is invalid.');
    }

    const now = this.clock.now();
    const result = await this.store.transaction<CodeOperationResult>(async (transaction) => {
      const verificationEnabled = databaseBoolean(await transaction.getSetting('require_email_verification'), true, true);
      if (!verificationEnabled) return 'disabled';

      const user = await transaction.findUserByEmailForUpdate(email);
      const authCode = await transaction.findLatestAuthCodeForUpdate(email, 'verify');
      if (!this.isUsableAuthCode(authCode, now)) return 'invalid';
      if (!digestMatches(authCode.codeHash, authCodeHash(this.authCodeHmacSecret, 'verify', email, code))) {
        await transaction.recordAuthCodeFailure(authCode.id, now);
        return 'invalid';
      }
      if (!await transaction.consumeAuthCode(authCode.id, now)) return 'invalid';
      if (user === null) return 'invalid';
      await transaction.setEmailVerified(user.id, now);
      return 'success';
    });

    if (result === 'disabled') {
      throw new AuthServiceError(400, 'email_verification_disabled', 'Email verification is disabled.');
    }
    if (result !== 'success') {
      throw new AuthServiceError(400, 'invalid_auth_code', 'The email code is invalid or expired.');
    }
    return { status: 200, code: 'email_verified', message: 'Email address verified.' };
  }

  async resendVerification(
    emailInput: string,
    metadata: LoginRequestMetadata,
  ): Promise<typeof GENERIC_VERIFICATION_RESPONSE> {
    const email = normalizeEmail(emailInput);
    if (!validEmail(email)) throw new AuthServiceError(400, 'invalid_request', 'A valid email address is required.');

    const now = this.clock.now();
    const emailWindow = rateLimitWindow('verification_resend_email', rateLimitKey(email), now, VERIFICATION_RESEND_RATE_WINDOW_MS);
    const ipWindow = metadata.ipAddress === null
      ? null
      : rateLimitWindow('verification_resend_ip', rateLimitKey(metadata.ipAddress), now, VERIFICATION_RESEND_RATE_WINDOW_MS);
    let result: boolean | 'disabled' | 'rate_limited' | null;
    try {
      result = await this.store.transaction<boolean | 'disabled' | 'rate_limited' | null>(async (transaction) => {
        const verificationEnabled = databaseBoolean(await transaction.getSetting('require_email_verification'), true, true);
        if (!verificationEnabled) return 'disabled';

        const emailCount = await transaction.incrementRateLimit(emailWindow);
        const ipCount = ipWindow === null ? 0 : await transaction.incrementRateLimit(ipWindow);
        if (emailCount > VERIFICATION_RESEND_EMAIL_LIMIT || ipCount > VERIFICATION_RESEND_IP_LIMIT) {
          return 'rate_limited';
        }

        const user = await transaction.findUserByEmailForUpdate(email);
        if (user === null || user.emailVerifiedAt !== null || user.disabledAt !== null) return null;
        const latest = await transaction.findLatestAuthCodeForUpdate(email, 'verify');
        if (this.isWithinResendInterval(latest, now)) return null;
        const verification = await this.createCodeWithinTransaction(transaction, email, 'verify', now);
        await this.sendAuthCodeWithinTransaction('verification_code', () =>
          this.notifications.sendVerificationCode(verification));
        return true;
      });
    } catch (error) {
      if (!(error instanceof AuthCodeNotificationFailure)) throw error;
      // The issuing transaction rolled back; count the failed delivery attempt separately.
      await this.store.transaction(async (transaction) => {
        await transaction.incrementRateLimit(emailWindow);
        if (ipWindow !== null) await transaction.incrementRateLimit(ipWindow);
      });
      return GENERIC_VERIFICATION_RESPONSE;
    }

    if (result === 'disabled') {
      throw new AuthServiceError(400, 'email_verification_disabled', 'Email verification is disabled.');
    }
    if (result === 'rate_limited') {
      throw new AuthServiceError(
        429,
        'rate_limited',
        'Too many verification code requests. Please try again later.',
        retryAfterSeconds(emailWindow, this.clock.now()),
      );
    }
    return GENERIC_VERIFICATION_RESPONSE;
  }

  async forgotPassword(
    emailInput: string,
    metadata: LoginRequestMetadata,
  ): Promise<typeof GENERIC_RECOVERY_RESPONSE> {
    const email = normalizeEmail(emailInput);
    if (!validEmail(email)) throw new AuthServiceError(400, 'invalid_request', 'A valid email address is required.');

    const now = this.clock.now();
    const emailWindow = rateLimitWindow('password_recovery_email', rateLimitKey(email), now, RECOVERY_RATE_WINDOW_MS);
    const ipWindow = metadata.ipAddress === null
      ? null
      : rateLimitWindow('password_recovery_ip', rateLimitKey(metadata.ipAddress), now, RECOVERY_RATE_WINDOW_MS);
    let result: boolean | 'disabled' | 'rate_limited' | null;
    try {
      result = await this.store.transaction<boolean | 'disabled' | 'rate_limited' | null>(async (transaction) => {
        const recoveryEnabled = databaseBoolean(await transaction.getSetting('require_email_verification'), true, true);
        if (!recoveryEnabled) return 'disabled';

        const emailCount = await transaction.incrementRateLimit(emailWindow);
        const ipCount = ipWindow === null ? 0 : await transaction.incrementRateLimit(ipWindow);
        if (emailCount > RECOVERY_EMAIL_LIMIT || ipCount > RECOVERY_IP_LIMIT) return 'rate_limited';

        const user = await transaction.findUserByEmailForUpdate(email);
        if (user === null || user.disabledAt !== null) return null;
        const latest = await transaction.findLatestAuthCodeForUpdate(email, 'reset');
        if (this.isWithinResendInterval(latest, now)) return null;
        const recovery = await this.createCodeWithinTransaction(transaction, email, 'reset', now);
        await this.sendAuthCodeWithinTransaction('password_reset_code', () =>
          this.notifications.sendPasswordResetCode(recovery));
        return true;
      });
    } catch (error) {
      if (!(error instanceof AuthCodeNotificationFailure)) throw error;
      // The issuing transaction rolled back; count the failed delivery attempt separately.
      await this.store.transaction(async (transaction) => {
        await transaction.incrementRateLimit(emailWindow);
        if (ipWindow !== null) await transaction.incrementRateLimit(ipWindow);
      });
      return GENERIC_RECOVERY_RESPONSE;
    }

    if (result === 'disabled') {
      throw new AuthServiceError(400, 'password_recovery_disabled', 'Password recovery is disabled.');
    }
    if (result === 'rate_limited') {
      throw new AuthServiceError(
        429,
        'rate_limited',
        'Too many password recovery attempts. Please try again later.',
        retryAfterSeconds(emailWindow, this.clock.now()),
      );
    }
    return GENERIC_RECOVERY_RESPONSE;
  }

  async resetPassword(emailInput: string, code: string, newLoginPassword: string): Promise<{
    readonly status: 200;
    readonly code: 'password_reset';
    readonly message: string;
  }> {
    const email = normalizeEmail(emailInput);
    if (!validEmail(email) || !AUTH_CODE_PATTERN.test(code)) {
      throw new AuthServiceError(400, 'invalid_request', 'The password reset request is invalid.');
    }
    requirePassword(newLoginPassword);

    const now = this.clock.now();
    const result = await this.store.transaction<CodeOperationResult>(async (transaction) => {
      const recoveryEnabled = databaseBoolean(await transaction.getSetting('require_email_verification'), true, true);
      if (!recoveryEnabled) return 'disabled';

      const user = await transaction.findUserByEmailForUpdate(email);
      const authCode = await transaction.findLatestAuthCodeForUpdate(email, 'reset');
      if (!this.isUsableAuthCode(authCode, now)) return 'invalid';
      if (!digestMatches(authCode.codeHash, authCodeHash(this.authCodeHmacSecret, 'reset', email, code))) {
        await transaction.recordAuthCodeFailure(authCode.id, now);
        return 'invalid';
      }
      if (user === null || !await transaction.consumeAuthCode(authCode.id, now)) return 'invalid';

      const newPasswordHash = await hashLoginPassword(newLoginPassword);
      const passwordUpdated = await transaction.updatePasswordHash(user.id, user.passwordHash, newPasswordHash);
      if (!passwordUpdated) throw new Error('Password reset lost its account row lock.');
      await transaction.revokeAllDevices(user.id, now);
      await transaction.revokeAllPasswordResetRefreshTokens(user.id, now);
      await transaction.revokeAllOAuthAuthorizations(user.id, now);
      return 'success';
    });

    if (result === 'disabled') {
      throw new AuthServiceError(400, 'password_recovery_disabled', 'Password recovery is disabled.');
    }
    if (result !== 'success') {
      throw new AuthServiceError(400, 'invalid_auth_code', 'The email code is invalid or expired.');
    }
    return { status: 200, code: 'password_reset', message: 'The login password has been updated.' };
  }

  async requestDeleteCode(
    userId: string,
    metadata: LoginRequestMetadata,
  ): Promise<typeof GENERIC_DELETE_CODE_RESPONSE> {
    const now = this.clock.now();
    const userWindow = rateLimitWindow('delete_code_user', rateLimitKey(userId), now, DELETE_CODE_RATE_WINDOW_MS);
    const ipWindow = metadata.ipAddress === null
      ? null
      : rateLimitWindow('delete_code_ip', rateLimitKey(metadata.ipAddress), now, DELETE_CODE_RATE_WINDOW_MS);
    let outcome: 'sent' | 'cooldown' | 'missing' | 'disabled' | 'rate_limited';
    try {
      outcome = await this.store.transaction(async (transaction) => {
        const userCount = await transaction.incrementRateLimit(userWindow);
        const ipCount = ipWindow === null ? 0 : await transaction.incrementRateLimit(ipWindow);
        if (userCount > DELETE_CODE_USER_LIMIT || ipCount > DELETE_CODE_IP_LIMIT) return 'rate_limited';

        const user = await transaction.findUserForUpdate(userId);
        if (user === null) return 'missing';
        if (isSet(user.disabledAt)) return 'disabled';

        const latest = await transaction.findLatestAuthCodeForUpdate(user.email, 'delete');
        if (this.isWithinResendInterval(latest, now)) return 'cooldown';

        const deletionCode = await this.createCodeWithinTransaction(transaction, user.email, 'delete', now);
        await this.sendAuthCodeWithinTransaction('delete_account_code', () =>
          this.notifications.sendDeleteAccountCode(deletionCode));
        return 'sent';
      });
    } catch (error) {
      if (!(error instanceof AuthCodeNotificationFailure) || error.kind !== 'delete_account_code') throw error;
      // The issuing transaction rolled back; count the failed delivery attempt separately.
      await this.store.transaction(async (transaction) => {
        await transaction.incrementRateLimit(userWindow);
        if (ipWindow !== null) await transaction.incrementRateLimit(ipWindow);
      });
      return GENERIC_DELETE_CODE_RESPONSE;
    }

    if (outcome === 'missing') {
      throw new AuthServiceError(401, 'unauthorized', 'A valid access token is required.');
    }
    if (outcome === 'disabled') {
      throw new AuthServiceError(403, 'account_disabled', 'This account is disabled.');
    }
    if (outcome === 'rate_limited') {
      throw new AuthServiceError(
        429,
        'rate_limited',
        'Too many delete-code requests. Please try again later.',
        retryAfterSeconds(userWindow, this.clock.now()),
      );
    }
    return GENERIC_DELETE_CODE_RESPONSE;
  }

  async deleteAccount(
    userId: string,
    loginPassword: string,
    emailCode: string,
    backupExportedConfirmed: boolean,
    metadata: LoginRequestMetadata,
  ): Promise<{ readonly status: 200; readonly code: 'account_deleted'; readonly message: string }> {
    const sensitive = await this.verifySensitivePassword(userId, loginPassword, metadata);
    const now = this.clock.now();
    const outcome = await this.store.transaction(async (transaction) => {
      const releasePasswordReservation = async (): Promise<void> => {
        await transaction.decrementRateLimit(sensitive.emailWindow);
        if (sensitive.ipWindow !== null) await transaction.decrementRateLimit(sensitive.ipWindow);
      };

      const user = await transaction.findUserForUpdate(userId);
      if (user === null) {
        await releasePasswordReservation();
        return 'missing' as const;
      }
      if (isSet(user.disabledAt)) {
        await releasePasswordReservation();
        return 'disabled' as const;
      }
      const passwordStillMatches = user.passwordHash === sensitive.user.passwordHash
        ? true
        : await verifyLoginPassword(user.passwordHash, loginPassword);
      if (!passwordStillMatches) {
        await releasePasswordReservation();
        return 'password_changed' as const;
      }

      const authCode = await transaction.findLatestAuthCodeForUpdate(user.email, 'delete');
      if (!this.isUsableAuthCode(authCode, now)) {
        await releasePasswordReservation();
        return 'invalid_code' as const;
      }
      if (
        !AUTH_CODE_PATTERN.test(emailCode) ||
        !digestMatches(authCode.codeHash, authCodeHash(this.authCodeHmacSecret, 'delete', user.email, emailCode))
      ) {
        await transaction.recordAuthCodeFailure(authCode.id, now);
        await releasePasswordReservation();
        return 'invalid_code' as const;
      }
      if (!await transaction.consumeAuthCode(authCode.id, now)) {
        await releasePasswordReservation();
        return 'invalid_code' as const;
      }

      if (!backupExportedConfirmed) {
        await releasePasswordReservation();
        return 'backup_required' as const;
      }

      const roles = await transaction.findUserRolesForUpdate(userId);
      const protectedRoles = roles.filter((role) => role === 'admin' || role === 'super_admin');
      if (protectedRoles.length > 0) {
        await transaction.insertAuditLog({
          actorUserId: userId,
          targetUserId: userId,
          action: 'account.self_delete_denied',
          targetType: 'user',
          metadata: JSON.stringify({}),
          ipAddress: metadata.ipAddress,
          createdAt: now,
        });
        await releasePasswordReservation();
        return 'forbidden' as const;
      }

      await transaction.insertAuditLog({
        actorUserId: userId,
        targetUserId: userId,
        action: 'account.self_delete',
        targetType: 'user',
        metadata: null,
        ipAddress: metadata.ipAddress,
        createdAt: now,
      });
      await transaction.deleteAuthCodesForEmail(user.email);
      await transaction.deleteEmailRateLimits(rateLimitKey(user.email));
      await releasePasswordReservation();
      if (!await transaction.deleteUser(userId)) {
        throw new Error('Account deletion lost its user row lock.');
      }
      return 'success' as const;
    });

    if (outcome === 'missing') {
      throw new AuthServiceError(401, 'invalid_credentials', 'The login password is incorrect.');
    }
    if (outcome === 'disabled') {
      throw new AuthServiceError(403, 'account_disabled', 'This account is disabled.');
    }
    if (outcome === 'password_changed') {
      throw new AuthServiceError(401, 'invalid_credentials', 'The login password is incorrect.');
    }
    if (outcome === 'invalid_code') {
      throw new AuthServiceError(400, 'invalid_auth_code', 'The email code is invalid or expired.');
    }
    if (outcome === 'backup_required') {
      throw new AuthServiceError(400, 'backup_export_required', 'Confirm that you saved a DEK-encrypted vault backup before deleting the account.');
    }
    if (outcome === 'forbidden') {
      throw new AuthServiceError(403, 'self_deletion_forbidden', 'Administrator accounts cannot delete themselves.');
    }
    return { status: 200, code: 'account_deleted', message: 'The account has been permanently deleted.' };
  }

  async changePassword(
    userId: string,
    oldLoginPassword: string,
    newLoginPassword: string,
    metadata: LoginRequestMetadata,
  ): Promise<void> {
    const sensitive = await this.verifySensitivePassword(userId, oldLoginPassword, metadata);
    // The current password is checked first as required by the sensitive-operation contract.
    let newPasswordHash: string;
    try {
      requirePassword(newLoginPassword);
      newPasswordHash = await hashLoginPassword(newLoginPassword);
    } catch (error) {
      await this.releaseSensitiveRateLimitReservation(sensitive);
      throw error;
    }
    const now = this.clock.now();
    const result = await this.store.transaction(async (transaction) => {
      const user = await transaction.findUserForUpdate(userId);
      if (user === null) return 'invalid' as const;
      if (isSet(user.disabledAt)) return 'disabled' as const;
      const oldPasswordStillMatches = user.passwordHash === sensitive.user.passwordHash
        ? true
        : await verifyLoginPassword(user.passwordHash, oldLoginPassword);
      if (!oldPasswordStillMatches) return 'invalid' as const;

      const updated = await transaction.updatePasswordHash(userId, user.passwordHash, newPasswordHash);
      if (!updated) throw new Error('Password change lost its account row lock.');
      await transaction.revokeAllDevices(userId, now);
      await transaction.revokeAllPasswordResetRefreshTokens(userId, now);
      await transaction.revokeAllOAuthAuthorizations(userId, now);
      await transaction.decrementRateLimit(sensitive.emailWindow);
      if (sensitive.ipWindow !== null) await transaction.decrementRateLimit(sensitive.ipWindow);
      return 'success' as const;
    });

    if (result === 'disabled') {
      throw new AuthServiceError(403, 'account_disabled', 'This account is disabled.');
    }
    if (result !== 'success') {
      throw new AuthServiceError(401, 'invalid_credentials', 'The login password is incorrect.');
    }
  }

  async revokeAllDevices(
    userId: string,
    loginPassword: string,
    metadata: LoginRequestMetadata,
  ): Promise<{ readonly status: 200; readonly code: 'devices_revoked'; readonly message: string }> {
    const sensitive = await this.verifySensitivePassword(userId, loginPassword, metadata);
    const now = this.clock.now();
    const result = await this.store.transaction(async (transaction) => {
      const user = await transaction.findUserForUpdate(userId);
      if (user === null) return 'invalid' as const;
      if (isSet(user.disabledAt)) return 'disabled' as const;
      const passwordStillMatches = user.passwordHash === sensitive.user.passwordHash
        ? true
        : await verifyLoginPassword(user.passwordHash, loginPassword);
      if (!passwordStillMatches) return 'invalid' as const;

      await transaction.revokeAllDevices(userId, now);
      await transaction.revokeAllUnrevokedRefreshTokens(userId, now);
      await transaction.revokeAllOAuthAuthorizations(userId, now);
      await transaction.decrementRateLimit(sensitive.emailWindow);
      if (sensitive.ipWindow !== null) await transaction.decrementRateLimit(sensitive.ipWindow);
      return 'success' as const;
    });

    if (result === 'disabled') {
      throw new AuthServiceError(403, 'account_disabled', 'This account is disabled.');
    }
    if (result !== 'success') {
      throw new AuthServiceError(401, 'invalid_credentials', 'The login password is incorrect.');
    }
    return { status: 200, code: 'devices_revoked', message: 'All devices have been signed out. Please sign in again.' };
  }

  /**
   * Runs a privileged mutation after the existing login-password check and rate-limit reservation.
   * The callback must lock the actor row, verify it remains enabled and re-check the password hash
   * before performing any irreversible work.
   */
  async withVerifiedSensitivePassword<T>(
    userId: string,
    password: string,
    metadata: LoginRequestMetadata,
    operation: (transaction: AuthTransaction, initialUser: AuthUser) => Promise<T>,
  ): Promise<T> {
    const sensitive = await this.verifySensitivePassword(userId, password, metadata);
    let committed = false;
    try {
      const result = await this.store.transaction(async (transaction) => {
        const operationResult = await operation(transaction, sensitive.user);
        await transaction.decrementRateLimit(sensitive.emailWindow);
        if (sensitive.ipWindow !== null) await transaction.decrementRateLimit(sensitive.ipWindow);
        return operationResult;
      });
      committed = true;
      return result;
    } finally {
      if (!committed) await this.releaseSensitiveRateLimitReservation(sensitive);
    }
  }

  async login(input: LoginInput, metadata: LoginRequestMetadata): Promise<TokenPair> {
    const email = normalizeEmail(input.email);
    if (!validEmail(email) || input.deviceName.trim().length === 0 ||
      (input.deviceId !== undefined && !UUID_PATTERN.test(input.deviceId))) {
      throw new AuthServiceError(400, 'invalid_request', 'The login request is invalid.');
    }
    requirePassword(input.loginPassword);

    const rateTime = this.clock.now();
    const emailWindow = rateLimitWindow('login_email', rateLimitKey(email), rateTime, LOGIN_RATE_WINDOW_MS);
    const ipWindow = metadata.ipAddress === null
      ? null
      : rateLimitWindow('login_ip', rateLimitKey(metadata.ipAddress), rateTime, LOGIN_RATE_WINDOW_MS);
    const attemptCounts = await this.store.transaction(async (transaction) => ({
      email: await transaction.incrementRateLimit(emailWindow),
      ip: ipWindow === null ? 0 : await transaction.incrementRateLimit(ipWindow),
    }));
    const maximumPriorFailures = Math.max(attemptCounts.email - 1, attemptCounts.ip - 1, 0);
    const delayMs = loginFailureDelayMs(maximumPriorFailures);
    if (delayMs > 0) await this.delayLoginFailure(delayMs);

    const rateLimited = attemptCounts.email > LOGIN_EMAIL_FAILURE_LIMIT ||
      (ipWindow !== null && attemptCounts.ip > LOGIN_IP_FAILURE_LIMIT);
    const initialUser = await this.store.findUserByEmail(email);
    const initialHash = initialUser?.passwordHash ?? await this.getDummyPasswordHash();
    const passwordMatches = !rateLimited && await verifyLoginPassword(initialHash, input.loginPassword);
    if (!initialUser || !passwordMatches || isSet(initialUser.disabledAt)) {
      const failureCode = rateLimited
        ? 'rate_limited'
        : !initialUser ? 'user_not_found' : isSet(initialUser.disabledAt) ? 'account_disabled' : 'wrong_password';
      await this.recordLoginFailure(initialUser, input.deviceName, metadata, failureCode);
      if (rateLimited) {
        throw new AuthServiceError(
          429,
          'rate_limited',
          'Too many login attempts. Please try again later.',
          retryAfterSeconds(emailWindow, this.clock.now()),
        );
      }
      throw new AuthServiceError(INVALID_CREDENTIALS.status, INVALID_CREDENTIALS.code, INVALID_CREDENTIALS.message);
    }

    const now = this.clock.now();
    const upgradedHash = loginPasswordNeedsRehash(initialUser.passwordHash)
      ? await hashLoginPassword(input.loginPassword)
      : null;

    const result = await this.store.transaction<LoginTransactionResult>(async (transaction) => {
      const currentUser = await transaction.findUserForUpdate(initialUser.id);
      if (!currentUser) {
        await this.writeFailure(transaction, null, input.deviceName, metadata, 'user_not_found', now);
        return { kind: 'failure' };
      }

      // Re-check the current password/state under a user-row lock to avoid racing a password reset or disable.
      const currentPasswordMatches = currentUser.passwordHash === initialUser.passwordHash
        ? true
        : await verifyLoginPassword(currentUser.passwordHash, input.loginPassword);
      if (isSet(currentUser.disabledAt) || !currentPasswordMatches) {
        const failureCode = isSet(currentUser.disabledAt) ? 'account_disabled' : 'wrong_password';
        await this.writeFailure(transaction, currentUser, input.deviceName, metadata, failureCode, now);
        return { kind: 'failure' };
      }

      if (currentUser.passwordHash === initialUser.passwordHash && upgradedHash !== null) {
        const changed = await transaction.updatePasswordHash(currentUser.id, currentUser.passwordHash, upgradedHash);
        if (!changed) throw new Error('Password rehash lost its row lock.');
      } else if (loginPasswordNeedsRehash(currentUser.passwordHash)) {
        const replacementHash = await hashLoginPassword(input.loginPassword);
        const changed = await transaction.updatePasswordHash(currentUser.id, currentUser.passwordHash, replacementHash);
        if (!changed) throw new Error('Password rehash lost its row lock.');
      }

      let deviceId: string | null = null;
      let newDevice = true;
      if (input.deviceId !== undefined) {
        const reusable = await transaction.findReusableDevice(currentUser.id, input.deviceId);
        if (reusable !== null) {
          const updated = await transaction.updateDevice(input.deviceId, currentUser.id, input.deviceName, input.deviceType);
          if (updated) {
            deviceId = input.deviceId;
            newDevice = false;
          }
        }
      }
      if (deviceId === null) deviceId = await transaction.insertDevice(currentUser.id, input.deviceName, input.deviceType);
      if (!deviceId) throw new Error('A refresh token cannot be issued without a device.');

      const refreshToken = createRefreshToken();
      const absoluteExpiresAt = new Date(now.getTime() + ABSOLUTE_SESSION_TTL_MS);
      const expiresAt = new Date(Math.min(now.getTime() + REFRESH_TOKEN_TTL_MS, absoluteExpiresAt.getTime()));
      await transaction.insertRefreshToken({
        userId: currentUser.id,
        deviceId,
        tokenHash: hashRefreshToken(refreshToken),
        expiresAt,
        absoluteExpiresAt,
        createdAt: now,
      });
      await transaction.insertLoginLog(makeLoginLog(metadata, {
        userId: currentUser.id,
        deviceId,
        deviceName: input.deviceName,
        result: 'success',
        failureCode: null,
      }, now));
      await transaction.decrementRateLimit(emailWindow);
      if (ipWindow !== null) await transaction.decrementRateLimit(ipWindow);

      const issued = createTokenPair(this.jwtKeys, currentUser.id, deviceId, refreshToken, now);
      return {
        kind: 'success',
        value: {
          tokenPair: { device_id: issued.deviceId, access_token: issued.accessToken, refresh_token: issued.refreshToken },
          newDevice,
          email: currentUser.email,
        },
      };
    });

    if (result.kind !== 'success') {
      throw new AuthServiceError(INVALID_CREDENTIALS.status, INVALID_CREDENTIALS.code, INVALID_CREDENTIALS.message);
    }
    if (result.value.newDevice) {
      await this.notifySafely('new_device', () => this.notifications.sendNewDeviceLogin({
        email: result.value.email,
        userId: initialUser.id,
        deviceId: result.value.tokenPair.device_id,
        deviceName: input.deviceName,
        occurredAt: now,
      }));
    }
    return result.value.tokenPair;
  }

  async refresh(refreshToken: string): Promise<TokenPair> {
    if (!isCanonicalRefreshToken(refreshToken)) {
      throw new AuthServiceError(401, 'invalid_token', 'The refresh token is invalid or expired.');
    }
    const now = this.clock.now();
    const tokenHash = hashRefreshToken(refreshToken);
    const result = await this.store.transaction<RefreshTransactionResult>(async (transaction) => {
      // All refresh transactions acquire locks in account -> token -> device -> remaining tokens order.
      // The owner lookup is deliberately non-locking so no request can hold one token row while waiting
      // for the account row that a replay transaction holds before its fanout.
      const ownerUserId = await transaction.findRefreshUserIdByHash(tokenHash);
      if (ownerUserId === null) return { kind: 'invalid' };
      if (!await transaction.lockRefreshUser(ownerUserId)) return { kind: 'invalid' };
      const token = await transaction.findRefreshTokenForUpdate(tokenHash);
      if (token === null || token.userId !== ownerUserId) return { kind: 'invalid' };

      if (token.revokedAt !== null) {
        if (token.revokedReason !== 'rotated') return { kind: 'invalid' };
        const revokedAt = dateValue(token.revokedAt);
        if (revokedAt === null) return { kind: 'invalid' };
        const age = now.getTime() - revokedAt.getTime();
        if (age < 0 || age > REFRESH_REUSE_WINDOW_MS) return { kind: 'invalid' };
        if (token.deviceId === null || token.deviceId === '') return { kind: 'invalid' };

        // This status check is intentionally before the atomic claim, matching the fixed reuse-check order.
        const owner = await transaction.findRefreshOwnerStatus(token.userId, token.deviceId);
        if (owner === null || isSet(owner.deviceRevokedAt) || isSet(owner.accountDisabledAt)) {
          return { kind: 'invalid' };
        }
        const claimed = await transaction.claimRefreshReuseAlert(token.id, now);
        if (!claimed) return { kind: 'invalid' };

        await transaction.revokeAllDevices(token.userId, now);
        await transaction.revokeAllUnrevokedRefreshTokens(token.userId, now);
        return {
          kind: 'reuse_claimed',
          userId: token.userId,
          email: owner.email,
          deviceId: token.deviceId,
        };
      }

      const expiresAt = dateValue(token.expiresAt);
      const absoluteExpiresAt = dateValue(token.absoluteExpiresAt);
      if (
        expiresAt === null || absoluteExpiresAt === null ||
        now.getTime() >= expiresAt.getTime() ||
        now.getTime() >= absoluteExpiresAt.getTime() ||
        token.deviceId === null || token.deviceId === ''
      ) {
        return { kind: 'invalid' };
      }
      const owner = await transaction.findRefreshOwnerStatus(token.userId, token.deviceId);
      if (owner === null || isSet(owner.deviceRevokedAt) || isSet(owner.accountDisabledAt)) {
        return { kind: 'invalid' };
      }

      const rotated = await transaction.markRefreshTokenRotated(token.id, now);
      if (!rotated) return { kind: 'invalid' };
      const newRefreshToken = createRefreshToken();
      const nextExpiresAt = new Date(Math.min(now.getTime() + REFRESH_TOKEN_TTL_MS, absoluteExpiresAt.getTime()));
      await transaction.insertRefreshToken({
        userId: token.userId,
        deviceId: token.deviceId,
        tokenHash: hashRefreshToken(newRefreshToken),
        expiresAt: nextExpiresAt,
        absoluteExpiresAt,
        createdAt: now,
      });
      const issued = createTokenPair(this.jwtKeys, token.userId, token.deviceId, newRefreshToken, now);
      return {
        kind: 'success',
        tokenPair: { device_id: issued.deviceId, access_token: issued.accessToken, refresh_token: issued.refreshToken },
      };
    });

    if (result.kind === 'reuse_claimed') {
      await this.notifySafely('refresh_reuse', () => this.notifications.sendRefreshReuseAlert({
        email: result.email,
        userId: result.userId,
        deviceId: result.deviceId,
        occurredAt: now,
      }));
      throw new AuthServiceError(401, 'invalid_token', 'The refresh token is invalid or expired.');
    }
    if (result.kind !== 'success') {
      throw new AuthServiceError(401, 'invalid_token', 'The refresh token is invalid or expired.');
    }
    return result.tokenPair;
  }

  async logout(refreshToken: string): Promise<void> {
    if (!isCanonicalRefreshToken(refreshToken)) {
      throw new AuthServiceError(401, 'invalid_token', 'The refresh token is invalid or expired.');
    }
    const result = await this.store.transaction(async (transaction) => {
      const token = await transaction.findRefreshTokenForUpdate(hashRefreshToken(refreshToken));
      if (token === null) return false;
      await transaction.revokeRefreshTokenForLogout(token.id, this.clock.now());
      return true;
    });
    if (!result) throw new AuthServiceError(401, 'invalid_token', 'The refresh token is invalid or expired.');
  }

  private async verifySensitivePassword(
    userId: string,
    password: string,
    metadata: LoginRequestMetadata,
  ): Promise<SensitivePasswordContext> {
    const now = this.clock.now();
    const reservation = await this.store.transaction(async (transaction) => {
      const user = await transaction.findUserForUpdate(userId);
      if (user === null) return { kind: 'missing' as const };
      if (isSet(user.disabledAt)) return { kind: 'disabled' as const };

      const emailWindow = rateLimitWindow('login_email', rateLimitKey(user.email), now, LOGIN_RATE_WINDOW_MS);
      const ipWindow = metadata.ipAddress === null
        ? null
        : rateLimitWindow('login_ip', rateLimitKey(metadata.ipAddress), now, LOGIN_RATE_WINDOW_MS);
      const emailCount = await transaction.incrementRateLimit(emailWindow);
      const ipCount = ipWindow === null ? 0 : await transaction.incrementRateLimit(ipWindow);
      return { kind: 'ready' as const, user, emailWindow, ipWindow, emailCount, ipCount };
    });

    if (reservation.kind === 'disabled') {
      throw new AuthServiceError(403, 'account_disabled', 'This account is disabled.');
    }
    if (reservation.kind === 'missing') {
      throw new AuthServiceError(401, 'invalid_credentials', 'The login password is incorrect.');
    }

    const priorFailures = Math.max(reservation.emailCount - 1, reservation.ipCount - 1, 0);
    const delayMs = loginFailureDelayMs(priorFailures);
    if (delayMs > 0) await this.delayLoginFailure(delayMs);

    const rateLimited = reservation.emailCount > LOGIN_EMAIL_FAILURE_LIMIT ||
      (reservation.ipWindow !== null && reservation.ipCount > LOGIN_IP_FAILURE_LIMIT);
    const passwordMatches = !rateLimited && Buffer.byteLength(password, 'utf8') <= 4096 &&
      await verifyLoginPassword(reservation.user.passwordHash, password);
    if (!passwordMatches) {
      if (rateLimited) {
        throw new AuthServiceError(
          429,
          'rate_limited',
          'Too many login attempts. Please try again later.',
          retryAfterSeconds(reservation.emailWindow, this.clock.now()),
        );
      }
      throw new AuthServiceError(401, 'invalid_credentials', 'The login password is incorrect.');
    }
    return {
      user: reservation.user,
      emailWindow: reservation.emailWindow,
      ipWindow: reservation.ipWindow,
    };
  }

  private async releaseSensitiveRateLimitReservation(sensitive: SensitivePasswordContext): Promise<void> {
    await this.store.transaction(async (transaction) => {
      await transaction.decrementRateLimit(sensitive.emailWindow);
      if (sensitive.ipWindow !== null) await transaction.decrementRateLimit(sensitive.ipWindow);
    });
  }

  private async createCodeWithinTransaction(
    transaction: AuthTransaction,
    email: string,
    purpose: AuthCodePurpose,
    now: Date,
  ): Promise<CodeDispatch> {
    const code = makeVerificationCode();
    const expiresAt = new Date(now.getTime() + CODE_TTL_MS[purpose]);
    await transaction.invalidateAuthCodes(email, purpose, now);
    await transaction.insertAuthCode({
      email,
      codeHash: authCodeHash(this.authCodeHmacSecret, purpose, email, code),
      purpose,
      expiresAt,
      createdAt: now,
    });
    return { email, code, expiresAt };
  }

  private isUsableAuthCode(authCode: AuthCodeRecord | null, now: Date): authCode is AuthCodeRecord {
    if (authCode === null || authCode.usedAt !== null || authCode.attempts >= 5) return false;
    const expiresAt = dateValue(authCode.expiresAt);
    return expiresAt !== null && now.getTime() < expiresAt.getTime();
  }

  private isWithinResendInterval(authCode: AuthCodeRecord | null, now: Date): boolean {
    if (authCode === null) return false;
    const createdAt = dateValue(authCode.createdAt);
    return createdAt === null || now.getTime() - createdAt.getTime() < CODE_RESEND_INTERVAL_MS;
  }

  private async getDummyPasswordHash(): Promise<string> {
    this.dummyPasswordHash ??= hashLoginPassword(randomBytes(32).toString('base64url'));
    return this.dummyPasswordHash;
  }

  private async recordLoginFailure(
    user: AuthUser | null,
    deviceName: string,
    metadata: LoginRequestMetadata,
    failureCode: string,
  ): Promise<void> {
    const now = this.clock.now();
    await this.store.transaction((transaction) =>
      this.writeFailure(transaction, user, deviceName, metadata, failureCode, now));
  }

  private async writeFailure(
    transaction: AuthTransaction,
    user: AuthUser | null,
    deviceName: string,
    metadata: LoginRequestMetadata,
    failureCode: string,
    now: Date,
  ): Promise<void> {
    await transaction.insertLoginLog(makeLoginLog(metadata, {
      userId: user?.id ?? null,
      deviceId: null,
      deviceName,
      result: 'failed',
      failureCode,
    }, now));
  }

  private async notifySafely(
    kind: AuthNotificationKind,
    send: () => Promise<void>,
  ): Promise<void> {
    try {
      await send();
    } catch {
      this.reportNotificationFailure(kind);
    }
  }

  private async sendAuthCodeWithinTransaction(
    kind: 'verification_code' | 'password_reset_code' | 'delete_account_code',
    send: () => Promise<void>,
  ): Promise<void> {
    try {
      await send();
    } catch {
      this.reportNotificationFailure(kind);
      throw new AuthCodeNotificationFailure(kind);
    }
  }

  private reportNotificationFailure(kind: AuthNotificationKind): void {
    try {
      this.notifyFailure(kind);
    } catch {
      // Notification diagnostics must never change an authentication response.
    }
  }
}
