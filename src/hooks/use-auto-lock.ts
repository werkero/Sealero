import { useEffect, useRef } from 'react'
import { hasIdleExpired, IDLE_LOCK_MS, remainingIdleMs } from './auto-lock-policy'
import { readLastActiveAt, writeLastActiveAt } from './vault-session-storage'

/** Activity writes to localStorage are throttled so pointer moves do not hammer storage. */
const LAST_ACTIVE_WRITE_THROTTLE_MS = 5_000

/**
 * One 15-minute idle timer (System Design §3.3). Time in the background
 * counts as idle — there is no separate hidden-tab rule. A page refresh
 * neither locks nor resets the countdown: the last-activity timestamp
 * lives in localStorage, so the timer resumes with the remaining budget.
 * Tab close still locks, because the unlock itself lives only in
 * sessionStorage. Signature unchanged: `(enabled, onLock)`.
 */
export function useAutoLock(enabled: boolean, onLock: () => void) {
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
      armIdleTimer(IDLE_LOCK_MS)
    }
    const handleActivity = () => {
      if (document.visibilityState === 'visible') noteActivity(Date.now())
    }

    const lastActiveAt = readLastActiveAt()
    const now = Date.now()
    if (lastActiveAt !== null) {
      if (hasIdleExpired(lastActiveAt, now)) {
        lock()
        return
      }
      lastWriteMs = lastActiveAt
      armIdleTimer(remainingIdleMs(lastActiveAt, now))
    } else {
      // No stored timestamp (for example a fresh unlock before the
      // session hook wrote one): start a full idle window.
      lastWriteMs = now
      writeLastActiveAt(now)
      armIdleTimer(IDLE_LOCK_MS)
    }

    const activityEvents: (keyof WindowEventMap)[] = ['pointerdown', 'keydown', 'scroll', 'touchstart']
    for (const eventName of activityEvents) {
      window.addEventListener(eventName, handleActivity, { passive: true })
    }

    return () => {
      clearIdleTimer()
      for (const eventName of activityEvents) {
        window.removeEventListener(eventName, handleActivity)
      }
    }
  }, [enabled])
}
