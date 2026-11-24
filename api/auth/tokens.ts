import { createHash, randomBytes } from 'node:crypto';
import { ACCESS_TOKEN_TTL_SECONDS, issueAccessToken } from './jwt.js';
import type { JwtKeySet } from './jwt.js';

export const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;
export const ABSOLUTE_SESSION_TTL_MS = 90 * 24 * 60 * 60 * 1000;
export const REFRESH_REUSE_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

export function createRefreshToken(): string {
  return randomBytes(32).toString('base64url');
}

export function hashRefreshToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export function isCanonicalRefreshToken(token: string): boolean {
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return false;
  try {
    const decoded = Buffer.from(token, 'base64url');
    return decoded.length === 32 && decoded.toString('base64url') === token;
  } catch {
    return false;
  }
}

export function createTokenPair(
  keys: JwtKeySet,
  userId: string,
  deviceId: string,
  refreshToken: string,
  now: Date,
): {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly deviceId: string;
  readonly accessExpiresIn: number;
} {
  return {
    accessToken: issueAccessToken(keys, userId, deviceId, now),
    refreshToken,
    deviceId,
    accessExpiresIn: ACCESS_TOKEN_TTL_SECONDS,
  };
}
