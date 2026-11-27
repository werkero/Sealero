import { useEffect, useRef } from 'react'
import { hasIdleExpired, IDLE_LOCK_MS, remainingIdleMs } from './auto-lock-policy'
import { LAST_ACTIVE_KEY, readLastActiveAt, writeLastActiveAt } from './vault-session-storage'

/** Activity writes to localStorage are throttled so pointer moves do not hammer storage. */
const LAST_ACTIVE_WRITE_THROTTLE_MS = 5_000

/**
 * One idle timer (System Design §3.3). The idle budget is the user's
 * own timeout in milliseconds (default 15 minutes). Activity in any tab
 * counts: a storage event from another tab re-arms this tab's timer, so
 * the vault only locks once every tab has been idle for the full budget.
 * A page refresh neither locks nor resets the countdown: the
 * last-activity timestamp lives in localStorage, so the timer resumes
 * with the remaining budget. Tab close still locks, because the unlock
 * itself lives only in sessionStorage. Changing the timeout re-arms
 * the timer with the new budget.
 */
export function useAutoLock(enabled: boolean, onLock: () => void, idleLockMs: number = IDLE_LOCK_MS) {
  const onLockRef = useRef(onLock)

  useEffect(() => {
    onLockRef.current = onLock
  }, [onLock])

  useEffect(() => {
    if (!enabled) return

    let idleTimer = 0
    let lastWriteMs = 0

    const lock = () => onLockRef.current()
    const clearIdleTimer = () => window.clearTimeout(idleTimer)
    const armIdleTimer = (delayMs: number) => {
      clearIdleTimer()
      idleTimer = window.setTimeout(lock, delayMs)
    }
    const noteActivity = (nowMs: number) => {
      if (nowMs - lastWriteMs >= LAST_ACTIVE_WRITE_THROTTLE_MS) {
        lastWriteMs = nowMs
        writeLastActiveAt(nowMs)
      }
      armIdleTimer(idleLockMs)
    }
    const handleActivity = () => {
      if (document.visibilityState === 'visible') noteActivity(Date.now())
    }

    const lastActiveAt = readLastActiveAt()
    const now = Date.now()
    if (lastActiveAt !== null) {
      if (hasIdleExpired(lastActiveAt, now, idleLockMs)) {
        lock()
        return
      }
      lastWriteMs = lastActiveAt
      armIdleTimer(remainingIdleMs(lastActiveAt, now, idleLockMs))
    } else {
      // No stored timestamp (for example a fresh unlock before the
      // session hook wrote one): start a full idle window.
      lastWriteMs = now
      writeLastActiveAt(now)
      armIdleTimer(idleLockMs)
    }

    const activityEvents: (keyof WindowEventMap)[] = ['pointerdown', 'pointermove', 'keydown', 'scroll', 'touchstart']
    for (const eventName of activityEvents) {
      window.addEventListener(eventName, handleActivity, { passive: true })
    }

    // Another tab's activity counts too: when it writes a newer
    // last-activity timestamp, re-arm this tab's timer with the remaining
    // budget instead of locking while the user is working elsewhere. The
    // event never fires in the tab that wrote, so there is no feedback loop.
    // A stale or older timestamp never shortens this tab's timer.
    const handleStorage = (event: StorageEvent) => {
      if (event.key !== LAST_ACTIVE_KEY || !event.newValue) return
      const otherActiveAt = Number(event.newValue)
      if (!Number.isFinite(otherActiveAt) || otherActiveAt <= 0 || otherActiveAt <= lastWriteMs) return
      const nowMs = Date.now()
      if (hasIdleExpired(otherActiveAt, nowMs, idleLockMs)) {
        lock()
        return
      }
      lastWriteMs = otherActiveAt
      armIdleTimer(remainingIdleMs(otherActiveAt, nowMs, idleLockMs))
    }
    window.addEventListener('storage', handleStorage)

    return () => {
      clearIdleTimer()
      for (const eventName of activityEvents) {
        window.removeEventListener(eventName, handleActivity)
      }
      window.removeEventListener('storage', handleStorage)
    }
  }, [enabled, idleLockMs])
}
