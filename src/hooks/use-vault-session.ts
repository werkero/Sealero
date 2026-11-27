import { useCallback, useEffect, useRef, useState } from 'react'
import type { VaultClient, VaultIdentity, VaultItem, VaultItemInput, VaultListItem } from '../client/contracts'
import { probeAdminAccess } from '../client/admin-status'
import { DEFAULT_AUTO_LOCK_MINUTES, hasIdleExpired } from './auto-lock-policy'
import { clearLastActiveAt, clearUnlockedSession, readLastActiveAt, readUnlockedSession, saveUnlockedSession, writeLastActiveAt } from './vault-session-storage'

function toListItem(item: VaultItem): VaultListItem {
  return {
    id: item.id,
    name: item.name,
    url: item.url,
    username: item.username,
    category: item.category,
    tags: [...item.tags],
    favorite: item.favorite,
    icon: item.icon,
    updatedAt: item.updatedAt,
  }
}

function byUpdatedDesc(a: VaultListItem, b: VaultListItem): number {
  return a.updatedAt < b.updatedAt ? 1 : a.updatedAt > b.updatedAt ? -1 : 0
}

interface PendingOperation {
  generation: number
  controller: AbortController
}

/** Keeps identity, overview, and only the currently opened plaintext detail in React memory. */
export function useVaultSession(client: VaultClient) {
  const [user, setUser] = useState<VaultIdentity | null>(null)
  const [isUnlocked, setIsUnlocked] = useState(false)
  /** The user's own auto-lock timeout in minutes (user_preferences; 15 when never set). */
  const [autoLockMinutes, setAutoLockMinutes] = useState(DEFAULT_AUTO_LOCK_MINUTES)
  /** True once the startup session-restore attempt has finished (restored or not). */
  const [sessionChecked, setSessionChecked] = useState(false)
  /** Cached admin-role probe result for this login session; false until proven. */
  const [isAdmin, setIsAdmin] = useState(false)
  const [items, setItems] = useState<VaultListItem[]>([])
  const [selectedItem, setSelectedItem] = useState<VaultItem | null>(null)
  const [loadingItemId, setLoadingItemId] = useState<string | null>(null)
  const generationRef = useRef(0)
  const pendingRef = useRef<PendingOperation | null>(null)
  /** Last known user id, for clearing that user's stored unlock on lock/logout/login even after `user` state is cleared. */
  const userIdRef = useRef<string | null>(null)

  useEffect(() => {
    userIdRef.current = user?.id ?? null
  }, [user])

  const cancelPending = useCallback(() => {
    generationRef.current += 1
    pendingRef.current?.controller.abort()
    pendingRef.current = null
  }, [])

  const beginOperation = useCallback(() => {
    pendingRef.current?.controller.abort()
    const operation = { generation: ++generationRef.current, controller: new AbortController() }
    pendingRef.current = operation
    return operation
  }, [])

  const isCurrent = useCallback((operation: PendingOperation) => (
    pendingRef.current === operation
    && generationRef.current === operation.generation
    && !operation.controller.signal.aborted
  ), [])

  const finishOperation = useCallback((operation: PendingOperation) => {
    if (pendingRef.current === operation) pendingRef.current = null
  }, [])

  /**
   * Restores the login identity after a page refresh: the refresh token
   * lives in its HttpOnly cookie, so a fresh access token is fetched first
   * and GET /v1/auth/me supplies the identity. A missing, expired, or
   * revoked refresh token fails here and the session simply stays logged
   * out — never an error to the user. The vault is then restored from
   * this tab's sessionStorage when the user's idle window has not
   * expired; otherwise it stays locked until the user unlocks with the
   * master password. The idle countdown is not reset by the restore.
   * The preference is read here so the restore-time idle check already
   * uses the user's own timeout; a failed read falls back to 15.
   */
  const restoreSession = useCallback(async () => {
    const operation = beginOperation()
    try {
      await client.refreshAccessToken(operation.controller.signal)
      if (!isCurrent(operation)) return false
      const identity = await client.getCurrentUser(operation.controller.signal)
      if (!isCurrent(operation)) return false
      setUser(identity)
      const admin = await probeAdminAccess(
        { getAccessToken: client.getAccessToken },
        operation.controller.signal,
      )
      if (isCurrent(operation)) setIsAdmin(admin)
      const preferences = await client.getUserPreferences(operation.controller.signal)
        .catch(() => ({ auto_lock_minutes: DEFAULT_AUTO_LOCK_MINUTES }))
      if (!isCurrent(operation)) return false
      if (isCurrent(operation)) setAutoLockMinutes(preferences.auto_lock_minutes)
      if (isCurrent(operation)) {
        const blob = readUnlockedSession(identity.id)
        const lastActiveAt = readLastActiveAt()
        if (blob && lastActiveAt !== null && !hasIdleExpired(lastActiveAt, Date.now(), preferences.auto_lock_minutes * 60_000)) {
          try {
            await client.restoreSessionUnlock(blob)
            if (!isCurrent(operation)) return false
            const overviews = await client.list(operation.controller.signal)
            if (!isCurrent(operation)) return false
            setItems(overviews)
            setIsUnlocked(true)
          } catch {
            clearUnlockedSession(identity.id)
            if (isCurrent(operation)) {
              client.lock()
              setIsUnlocked(false)
            }
          }
        }
      }
      return true
    } catch {
      if (!isCurrent(operation)) return false
      return false
    } finally {
      finishOperation(operation)
      setSessionChecked(true)
    }
  }, [beginOperation, client, finishOperation, isCurrent])

  const login = useCallback(async (email: string, loginPassword: string) => {
    cancelPending()
    if (userIdRef.current) clearUnlockedSession(userIdRef.current)
    clearLastActiveAt()
    client.lock()
    setUser(null)
    setIsUnlocked(false)
    setIsAdmin(false)
    setAutoLockMinutes(DEFAULT_AUTO_LOCK_MINUTES)
    setItems([])
    setSelectedItem(null)
    setLoadingItemId(null)
    const operation = beginOperation()

    try {
      const identity = await client.login(email, loginPassword, operation.controller.signal)
      if (!isCurrent(operation)) return null
      setUser(identity)
      // One admin probe per login; the vault stays locked until the user
      // unlocks with the master password, but admin status needs no unlock.
      const admin = await probeAdminAccess(
        { getAccessToken: client.getAccessToken },
        operation.controller.signal,
      )
      if (isCurrent(operation)) setIsAdmin(admin)
      const preferences = await client.getUserPreferences(operation.controller.signal)
        .catch(() => ({ auto_lock_minutes: DEFAULT_AUTO_LOCK_MINUTES }))
      if (isCurrent(operation)) setAutoLockMinutes(preferences.auto_lock_minutes)
      return identity
    } catch (error) {
      if (!isCurrent(operation)) return null
      throw error
    } finally {
      finishOperation(operation)
    }
  }, [beginOperation, cancelPending, client, finishOperation, isCurrent])

  const unlock = useCallback(async (masterPassword: string) => {
    if (!user) throw new Error('not_authenticated')
    const operation = beginOperation()
    setIsUnlocked(false)
    setItems([])
    setSelectedItem(null)
    setLoadingItemId(null)

    try {
      await client.unlock(masterPassword, operation.controller.signal)
      if (!isCurrent(operation)) return false
      const overviews = await client.list(operation.controller.signal)
      if (!isCurrent(operation)) return false
      setItems(overviews)
      setIsUnlocked(true)
      const blob = client.exportSessionUnlock()
      if (blob) saveUnlockedSession(user.id, blob)
      writeLastActiveAt(Date.now())
      return true
    } catch (error) {
      if (!isCurrent(operation)) return false
      client.lock()
      setItems([])
      setSelectedItem(null)
      setIsUnlocked(false)
      throw error
    } finally {
      finishOperation(operation)
    }
  }, [beginOperation, client, finishOperation, isCurrent, user])

  const loadItem = useCallback(async (itemId: string) => {
    if (!user || !isUnlocked) return null
    const operation = beginOperation()
    setSelectedItem(null)
    setLoadingItemId(itemId)

    try {
      const item = await client.getItem(itemId, operation.controller.signal)
      if (!isCurrent(operation)) return null
      setSelectedItem(item)
      setLoadingItemId(null)
      return item
    } catch (error) {
      if (!isCurrent(operation)) return null
      setLoadingItemId(null)
      throw error
    } finally {
      finishOperation(operation)
    }
  }, [beginOperation, client, finishOperation, isCurrent, isUnlocked, user])

  const clearSelectedItem = useCallback(() => {
    cancelPending()
    setSelectedItem(null)
    setLoadingItemId(null)
  }, [cancelPending])

  const createItem = useCallback(async (input: VaultItemInput) => {
    if (!user || !isUnlocked) throw new Error('vault_locked')
    const operation = beginOperation()
    try {
      const created = await client.createItem(input, operation.controller.signal)
      if (!isCurrent(operation)) return null
      setItems((current) => [toListItem(created), ...current].sort(byUpdatedDesc))
      return created
    } catch (error) {
      if (!isCurrent(operation)) return null
      throw error
    } finally {
      finishOperation(operation)
    }
  }, [beginOperation, client, finishOperation, isCurrent, isUnlocked, user])

  const updateItem = useCallback(async (itemId: string, input: VaultItemInput) => {
    if (!user || !isUnlocked) throw new Error('vault_locked')
    const operation = beginOperation()
    try {
      const updated = await client.updateItem(itemId, input, operation.controller.signal)
      if (!isCurrent(operation)) return null
      setItems((current) => current.map((entry) => (entry.id === itemId ? toListItem(updated) : entry)).sort(byUpdatedDesc))
      setSelectedItem((current) => (current?.id === itemId ? updated : current))
      return updated
    } catch (error) {
      if (!isCurrent(operation)) return null
      throw error
    } finally {
      finishOperation(operation)
    }
  }, [beginOperation, client, finishOperation, isCurrent, isUnlocked, user])

  const deleteItem = useCallback(async (itemId: string) => {
    if (!user || !isUnlocked) throw new Error('vault_locked')
    const operation = beginOperation()
    try {
      await client.deleteItem(itemId, operation.controller.signal)
      if (!isCurrent(operation)) return false
      setItems((current) => current.filter((entry) => entry.id !== itemId))
      setSelectedItem((current) => (current?.id === itemId ? null : current))
      return true
    } catch (error) {
      if (!isCurrent(operation)) return false
      throw error
    } finally {
      finishOperation(operation)
    }
  }, [beginOperation, client, finishOperation, isCurrent, isUnlocked, user])

  const lock = useCallback(() => {
    cancelPending()
    if (userIdRef.current) clearUnlockedSession(userIdRef.current)
    clearLastActiveAt()
    client.lock()
    setItems([])
    setSelectedItem(null)
    setLoadingItemId(null)
    setIsUnlocked(false)
  }, [cancelPending, client])

  const updateAutoLockMinutes = useCallback(async (minutes: number): Promise<boolean> => {
    try {
      const preferences = await client.updateUserPreferences(minutes)
      setAutoLockMinutes(preferences.auto_lock_minutes)
      return true
    } catch {
      return false
    }
  }, [client])

  const logout = useCallback(() => {
    cancelPending()
    if (userIdRef.current) clearUnlockedSession(userIdRef.current)
    clearLastActiveAt()
    client.lock()
    setItems([])
    setSelectedItem(null)
    setLoadingItemId(null)
    setIsUnlocked(false)
    setIsAdmin(false)
    setUser(null)
    void client.logout().catch(() => {
      // Clear the local UI immediately; a production adapter can report remote logout failures separately.
    })
  }, [cancelPending, client])

  useEffect(() => () => {
    cancelPending()
    client.lock()
  }, [cancelPending, client])

  return { user, isUnlocked, isAdmin, sessionChecked, items, selectedItem, loadingItemId, autoLockMinutes, updateAutoLockMinutes, restoreSession, login, unlock, loadItem, createItem, updateItem, deleteItem, clearSelectedItem, lock, logout }
}
