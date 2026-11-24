import { useEffect, useRef } from 'react'
import { hasExceededHiddenLockDuration, HIDDEN_LOCK_DURATION_MS } from './auto-lock-policy'

const IDLE_LOCK_MS = 5 * 60_000
export function useAutoLock(enabled: boolean, onLock: () => void) {
  const onLockRef = useRef(onLock)

  useEffect(() => {
    onLockRef.current = onLock
  }, [onLock])

  useEffect(() => {
    if (!enabled) return

    let idleTimer = 0
    let hiddenTimer = 0
    let hiddenAt: number | null = null

    const lock = () => onLockRef.current()
    const clearIdleTimer = () => window.clearTimeout(idleTimer)
    const clearHiddenTimer = () => window.clearTimeout(hiddenTimer)

    const resetIdleTimer = () => {
      clearIdleTimer()
      idleTimer = window.setTimeout(lock, IDLE_LOCK_MS)
    }

    const handleVisibilityChange = () => {
      if (document.visibilityState === 'hidden') {
        hiddenAt ??= performance.now()
        clearHiddenTimer()
        hiddenTimer = window.setTimeout(lock, HIDDEN_LOCK_DURATION_MS)
        return
      }

      const wasHiddenAt = hiddenAt
      hiddenAt = null
      clearHiddenTimer()
      if (wasHiddenAt !== null && hasExceededHiddenLockDuration(wasHiddenAt, performance.now())) {
        lock()
        return
      }
      resetIdleTimer()
    }

    const handleActivity = () => {
      if (document.visibilityState === 'visible') resetIdleTimer()
    }

    const activityEvents: (keyof WindowEventMap)[] = ['pointerdown', 'keydown', 'scroll', 'touchstart']
    for (const eventName of activityEvents) {
      window.addEventListener(eventName, handleActivity, { passive: true })
    }
    document.addEventListener('visibilitychange', handleVisibilityChange)
    resetIdleTimer()
    if (document.visibilityState === 'hidden') handleVisibilityChange()

    return () => {
      clearIdleTimer()
      clearHiddenTimer()
      for (const eventName of activityEvents) {
        window.removeEventListener(eventName, handleActivity)
      }
      document.removeEventListener('visibilitychange', handleVisibilityChange)
    }
  }, [enabled])
}
