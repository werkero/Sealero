import type { UnlockedSessionBlob } from '../client/contracts'

/**
 * Browser storage for the web vault's unlock state (System Design §3.3).
 *
 * The unlocked session blob lives in sessionStorage, keyed per user, so
 * it survives a page refresh in the same tab but dies with the tab. The
 * master password is never stored; the DEK and KEK in the blob are the
 * only key material kept, and they never go to localStorage, IndexedDB,
 * or the server. The last-activity timestamp lives in localStorage so
 * the 15-minute idle countdown is shared across tabs and survives a
 * refresh. Every helper is guarded: in non-browser environments (node
 * tests) storage is absent and the helpers no-op / return null.
 */

const SESSION_KEY_PREFIX = 'sealero.vault.session.'
export const LAST_ACTIVE_KEY = 'sealero.vault.lastActiveAt'

function sessionStore(): Storage | null {
  return typeof sessionStorage === 'undefined' ? null : sessionStorage
}

function localStore(): Storage | null {
  return typeof localStorage === 'undefined' ? null : localStorage
}

export function saveUnlockedSession(userId: string, blob: UnlockedSessionBlob): void {
  try {
    sessionStore()?.setItem(SESSION_KEY_PREFIX + userId, JSON.stringify(blob))
  } catch {
    // Storage unavailable or full: the vault simply stays locked after a refresh.
  }
}

export function readUnlockedSession(userId: string): UnlockedSessionBlob | null {
  try {
    const raw = sessionStore()?.getItem(SESSION_KEY_PREFIX + userId)
    if (!raw) return null
    const parsed = JSON.parse(raw) as UnlockedSessionBlob
    if (
      typeof parsed.dek !== 'string'
      || typeof parsed.kek !== 'string'
      || typeof parsed.version !== 'number'
      || !parsed.record
      || typeof parsed.record !== 'object'
    ) return null
    return parsed
  } catch {
    return null
  }
}

export function clearUnlockedSession(userId: string): void {
  try {
    sessionStore()?.removeItem(SESSION_KEY_PREFIX + userId)
  } catch {
    // Ignore: nothing to clear, or storage already gone.
  }
}

export function readLastActiveAt(): number | null {
  try {
    const raw = localStore()?.getItem(LAST_ACTIVE_KEY)
    if (!raw) return null
    const value = Number(raw)
    return Number.isFinite(value) && value > 0 ? value : null
  } catch {
    return null
  }
}

export function writeLastActiveAt(nowMs: number): void {
  try {
    localStore()?.setItem(LAST_ACTIVE_KEY, String(nowMs))
  } catch {
    // Storage unavailable: the idle timer still runs in memory for this page load.
  }
}

export function clearLastActiveAt(): void {
  try {
    localStore()?.removeItem(LAST_ACTIVE_KEY)
  } catch {
    // Ignore: nothing to clear, or storage already gone.
  }
}
