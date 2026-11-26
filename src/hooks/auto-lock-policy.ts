/**
 * Idle-lock policy for the web vault (System Design §3.3): one idle
 * timer only. The vault locks after 15 minutes without activity; time
 * in the background counts as idle, and a page refresh neither locks
 * nor resets the countdown — the last-activity timestamp lives in
 * localStorage and survives reloads, so the remaining budget is
 * recomputed from wall-clock time. Pure functions, no storage access
 * at import: node tests import this module directly.
 */

/** Idle-lock threshold: 15 minutes without activity. */
export const IDLE_LOCK_MS = 15 * 60_000

/** Milliseconds of idle budget left at `nowMs` given the last activity at `lastActiveAtMs`. */
export function remainingIdleMs(lastActiveAtMs: number, nowMs: number): number {
  return IDLE_LOCK_MS - (nowMs - lastActiveAtMs)
}

export function hasIdleExpired(lastActiveAtMs: number, nowMs: number): boolean {
  return remainingIdleMs(lastActiveAtMs, nowMs) <= 0
}
