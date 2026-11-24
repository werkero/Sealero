import { createHash } from 'node:crypto';
import type { RateLimitWindow } from './types.js';

/** SHA-256 hex of a rate-limit key, so raw emails/IPs never land in rate_limits. */
export function rateLimitKey(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/** Fixed window containing `now` for the given scope and duration. */
export function rateLimitWindow(scope: string, key: string, now: Date, durationMs: number): RateLimitWindow {
  const windowStart = new Date(Math.floor(now.getTime() / durationMs) * durationMs);
  return { scope, key, windowStart, expiresAt: new Date(windowStart.getTime() + durationMs) };
}

/** Whole seconds until a fixed rate-limit window expires (at least 1). */
export function retryAfterSeconds(window: RateLimitWindow, now: Date): number {
  return Math.max(1, Math.ceil((window.expiresAt.getTime() - now.getTime()) / 1000));
}
