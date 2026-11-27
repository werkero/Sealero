/**
 * Idle-lock policy for the web vault (System Design §3.3): one idle
 * timer only. The vault locks after the user's own idle timeout
 * (per-user setting from user_preferences, default 15 minutes); time
 * in the background counts as idle, and a page refresh neither locks
 * nor resets the countdown — the last-activity timestamp lives in
 * localStorage and survives reloads, so the remaining budget is
 * recomputed from wall-clock time. Pure functions, no storage access
 * at import: node tests import this module directly.
 */

/** Default idle-lock timeout in minutes, when the user never set one. */
export const DEFAULT_AUTO_LOCK_MINUTES = 15

/** Default idle-lock threshold: 15 minutes without activity. */
export const IDLE_LOCK_MS = DEFAULT_AUTO_LOCK_MINUTES * 60_000

/** Milliseconds of idle budget left at `nowMs` given the last activity at `lastActiveAtMs`. */
export function remainingIdleMs(lastActiveAtMs: number, nowMs: number, idleLockMs: number = IDLE_LOCK_MS): number {
  return idleLockMs - (nowMs - lastActiveAtMs)
}

export function hasIdleExpired(lastActiveAtMs: number, nowMs: number, idleLockMs: number = IDLE_LOCK_MS): boolean {
  return remainingIdleMs(lastActiveAtMs, nowMs, idleLockMs) <= 0
}
