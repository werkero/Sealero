import type { UnlockedSessionBlob } from '../client/contracts'

/**
 * Cross-tab unlock-session sharing (System Design §3.3).
 *
 * The unlock blob (DEK + KEK) still lives only in each tab's sessionStorage
 * and is never written to localStorage, IndexedDB, or the server. A tab that
 * is already unlocked may hand its blob to another tab of the same origin
 * over a BroadcastChannel — in memory only, nothing is persisted — so a new
 * tab can unlock without the master password. A tab the user explicitly
 * locked never accepts a shared session until it is unlocked by hand (or
 * logged in again); that flag lives in the tab's own sessionStorage and
 * dies with the tab. Auto-lock does not set the flag: a tab that locked
 * itself for idling may be re-unlocked by another tab's unlock.
 */

export const SESSION_CHANNEL_NAME = 'sealero.vault.session'

export type SessionChannelMessage =
  | { type: 'session'; userId: string; blob: UnlockedSessionBlob }
  | { type: 'session-request'; userId: string }

const EXPLICIT_LOCK_KEY_PREFIX = 'sealero.vault.explicitlyLocked.'

function explicitLockStore(): Storage | null {
  return typeof sessionStorage === 'undefined' ? null : sessionStorage
}

export function markExplicitlyLocked(userId: string): void {
  try {
    explicitLockStore()?.setItem(EXPLICIT_LOCK_KEY_PREFIX + userId, '1')
  } catch {
    // Storage unavailable: the tab simply never accepts a shared session.
  }
}

export function clearExplicitlyLocked(userId: string): void {
  try {
    explicitLockStore()?.removeItem(EXPLICIT_LOCK_KEY_PREFIX + userId)
  } catch {
    // Ignore: nothing to clear, or storage already gone.
  }
}

export function isExplicitlyLocked(userId: string): boolean {
  try {
    return explicitLockStore()?.getItem(EXPLICIT_LOCK_KEY_PREFIX + userId) === '1'
  } catch {
    return false
  }
}

export function createSessionChannel(): BroadcastChannel | null {
  try {
    return typeof BroadcastChannel === 'undefined' ? null : new BroadcastChannel(SESSION_CHANNEL_NAME)
  } catch {
    return null
  }
}

function isUnlockedSessionBlob(value: unknown): value is UnlockedSessionBlob {
  if (typeof value !== 'object' || value === null) return false
  const blob = value as { dek?: unknown; kek?: unknown; version?: unknown; record?: unknown }
  return typeof blob.dek === 'string'
    && typeof blob.kek === 'string'
    && typeof blob.version === 'number'
    && typeof blob.record === 'object'
    && blob.record !== null
}

export function isSessionChannelMessage(value: unknown): value is SessionChannelMessage {
  if (typeof value !== 'object' || value === null) return false
  const message = value as { type?: unknown; userId?: unknown; blob?: unknown }
  if (typeof message.userId !== 'string') return false
  if (message.type === 'session-request') return true
  if (message.type === 'session') return isUnlockedSessionBlob(message.blob)
  return false
}
