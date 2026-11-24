export const HIDDEN_LOCK_DURATION_MS = 60_000

export function hasExceededHiddenLockDuration(hiddenAtMonotonicMs: number, visibleAtMonotonicMs: number): boolean {
  return visibleAtMonotonicMs - hiddenAtMonotonicMs >= HIDDEN_LOCK_DURATION_MS
}
