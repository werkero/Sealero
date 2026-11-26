import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { Check, ChevronDown, Copy, LayoutGrid, Lock, LogOut, Settings, Sparkles, Star } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { BrowserRouter, useLocation, useNavigate } from 'react-router-dom'
import { Brand } from './components/Brand'
import { LanguageSelector } from './components/LanguageSelector'
import { ThemeToggle } from './components/ThemeToggle'
import { Dialog, DialogContent, DialogTitle } from './components/ui/dialog'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from './components/ui/dropdown-menu'
import { Button } from './components/ui/button'
import type { AppearancePreference } from './features/settings/preferences'
import type { VaultIdentity, VaultItemInput } from './client/contracts'
import { createHttpVaultClient, VaultApiError } from './client/http-vault-client'
import { useAutoLock } from './hooks/use-auto-lock'
import { useVaultSession } from './hooks/use-vault-session'
import { useAppearancePreference } from './features/settings/preferences'
import { clearClipboardIfStillCurrent, createClipboardOperationQueue } from './features/password-security/clipboard'
import { AppRoutes, useRouteMatch } from './routes'
import './app.css'

export type VaultFilter = 'all' | 'favorites'

export function AuthShell({ children, onNavigate, onAppearanceChange }: {
  children: ReactNode
  onNavigate: (path: string) => void
  onAppearanceChange: (preference: AppearancePreference) => void
}) {
  return (
    <div className="auth-shell">
      <header className="auth-header">
        <Brand onNavigate={onNavigate} />
        <div className="public-header-actions">
          <ThemeToggle onAppearanceChange={onAppearanceChange} />
          <LanguageSelector />
        </div>
      </header>
      <main className="auth-main">
        {children}
      </main>
    </div>
  )
}

function VaultHeader({ user, onNavigate, onLock, onRequestSignOut }: {
  user: VaultIdentity
  onNavigate: (path: string) => void
  onLock: () => void
  onRequestSignOut: () => void
}) {
  const { t } = useTranslation(['common', 'vault', 'settings'])

  return (
    <header className="vault-header">
      <div className="vault-header-brand"><Brand onNavigate={onNavigate} /><span className="header-divider" /><span className="vault-header-label">{t('vault:vaultHeading')}</span></div>
      <div className="vault-header-actions">
        <LanguageSelector />
        <div className="profile-menu-wrap">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button className="profile-button" type="button" aria-label={user.email} title={user.email}>
                <span className="profile-avatar">{user.email.slice(0, 1).toUpperCase()}</span>
                <span className="profile-email">{user.email}</span>
                <span className="profile-chevron" aria-hidden="true"><ChevronDown size={12} aria-hidden="true" /></span>
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent className="profile-menu" align="end">
              <DropdownMenuItem className="profile-menu-item" onClick={onLock}>
                <span aria-hidden="true"><Lock size={15} aria-hidden="true" /></span>{t('vault:lockVault')}
              </DropdownMenuItem>
              <DropdownMenuItem className="profile-menu-item" onClick={() => onNavigate(`/users/${user.id}/settings`)}>
                <span aria-hidden="true"><Settings size={15} aria-hidden="true" /></span>{t('settings:title')}
              </DropdownMenuItem>
              <DropdownMenuSeparator className="profile-menu-divider" />
              <DropdownMenuItem className="profile-menu-item" onClick={onRequestSignOut}>
                <span aria-hidden="true"><LogOut size={15} aria-hidden="true" /></span>{t('common:signOut')}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  )
}

function SignOutConfirmDialog({ open, onConfirm, onClose }: { open: boolean; onConfirm: () => void; onClose: () => void }) {
  const { t } = useTranslation(['common'])

  return (
    <Dialog open={open} onOpenChange={(nextOpen) => { if (!nextOpen) onClose() }}>
      <DialogContent className="confirm-dialog gap-0" showCloseButton={false}>
        <DialogTitle className="confirm-dialog-text">{t('common:signOutConfirm')}</DialogTitle>
        <div className="confirm-dialog-actions">
          <Button className="security-button security-button--quiet" type="button" onClick={onClose}>{t('common:cancel')}</Button>
          <Button className="button button-primary" type="button" onClick={onConfirm}>{t('common:confirmSignOut')}</Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}

export function VaultLayout({ user, filter, itemCount, isAdmin, onFilterChange, onNavigate, onLock, onLogout, children }: {
  user: VaultIdentity
  filter: VaultFilter
  itemCount: number
  /** Shows the admin-console entry in the sidebar when the session is an admin. */
  isAdmin?: boolean
  onFilterChange: (filter: VaultFilter) => void
  onNavigate: (path: string) => void
  onLock: () => void
  onLogout: () => void
  children: ReactNode
}) {
  const { t } = useTranslation(['common', 'vault', 'settings', 'admin'])
  const [confirmSignOutOpen, setConfirmSignOutOpen] = useState(false)
  return (
    <div className="vault-app-shell">
      <VaultHeader user={user} onNavigate={onNavigate} onLock={onLock} onRequestSignOut={() => setConfirmSignOutOpen(true)} />
      <div className="vault-workspace">
        <aside className="vault-sidebar" aria-label={t('vault:navigation')}>
          <div className="sidebar-section-label">{t('vault:yourVault')}</div>
          <nav className="sidebar-nav">
            <button type="button" className={`sidebar-link ${filter === 'all' ? 'is-active' : ''}`} onClick={() => { onFilterChange('all'); onNavigate(`/users/${user.id}`) }}>
              <span className="nav-icon" aria-hidden="true"><LayoutGrid size={15} aria-hidden="true" /></span><span>{t('vault:allItems')}</span><span className="nav-count">{itemCount}</span>
            </button>
            <button type="button" className={`sidebar-link ${filter === 'favorites' ? 'is-active' : ''}`} onClick={() => { onFilterChange('favorites'); onNavigate(`/users/${user.id}`) }}>
              <span className="nav-icon nav-star" aria-hidden="true"><Star size={12} aria-hidden="true" /></span><span>{t('vault:favorites')}</span>
            </button>
            <button type="button" className="sidebar-link" onClick={() => onNavigate(`/users/${user.id}/generator`)}>
              <span className="nav-icon" aria-hidden="true"><Sparkles size={15} aria-hidden="true" /></span><span>{t('vault:generator.title')}</span>
            </button>
            <button type="button" className="sidebar-link" onClick={() => onNavigate(`/users/${user.id}/settings`)}>
              <span className="nav-icon" aria-hidden="true"><Settings size={15} aria-hidden="true" /></span><span>{t('settings:title')}</span>
            </button>
            <button type="button" className="sidebar-link" onClick={() => onNavigate(`/users/${user.id}/confirmations`)}>
              <span className="nav-icon" aria-hidden="true"><Check size={15} aria-hidden="true" /></span><span>{t('vault:mcpConfirmations.title')}</span>
            </button>
            {isAdmin ? (
              <button type="button" className="sidebar-link" onClick={() => onNavigate('/admin')}>
                <span className="nav-icon" aria-hidden="true"><Lock size={15} aria-hidden="true" /></span><span>{t('admin:header.navigation')}</span>
              </button>
            ) : null}
          </nav>
          <div className="sidebar-bottom">
            <div className="sidebar-lock-card">
              <span className="sidebar-lock-icon" aria-hidden="true"><Lock size={14} aria-hidden="true" /></span>
              <strong>{t('vault:autoLockTitle')}</strong>
              <span>{t('vault:autoLockDescription')}</span>
            </div>
            <button className="sidebar-sign-out" type="button" onClick={() => setConfirmSignOutOpen(true)}><span aria-hidden="true"><LogOut size={12} aria-hidden="true" /></span>{t('common:signOut')}</button>
          </div>
        </aside>
        <main className="vault-main">{children}</main>
      </div>
      <ToastLayer />
      <SignOutConfirmDialog open={confirmSignOutOpen} onConfirm={onLogout} onClose={() => setConfirmSignOutOpen(false)} />
    </div>
  )
}

export function SecretRow({ label, value, maskedValue, visible, onToggle, onCopy, copyLabel }: {
  label: string
  value: string
  maskedValue: string
  visible?: boolean
  onToggle?: () => void
  onCopy: () => void
  copyLabel: string
}) {
  const { t } = useTranslation('common')
  return (
    <div className="detail-field">
      <div className="detail-field-label">{label}</div>
      <div className="detail-field-value">{visible === false ? maskedValue : value}</div>
      <div className="detail-field-actions">
        {onToggle ? <button className="quiet-button" type="button" onClick={onToggle}>{visible ? t('hide') : t('show')}</button> : null}
        <button className="copy-button" type="button" onClick={onCopy} aria-label={`${t('copy')} ${copyLabel}`} title={`${t('copy')} ${copyLabel}`}><CopyIcon /></button>
      </div>
    </div>
  )
}

export function CopyIcon() {
  return <Copy size={15} strokeWidth={1.5} aria-hidden="true" />
}

function ToastLayer() {
  const [message, setMessage] = useState('')

  useEffect(() => {
    let timer = 0
    const showToast = (event: Event) => {
      const nextMessage = (event as CustomEvent<string>).detail
      setMessage(nextMessage)
      window.clearTimeout(timer)
      timer = window.setTimeout(() => setMessage(''), 3_500)
    }
    window.addEventListener('sealero:toast', showToast)
    return () => {
      window.clearTimeout(timer)
      window.removeEventListener('sealero:toast', showToast)
    }
  }, [])

  return message ? <div className="toast-message" role="status" aria-live="polite">{message}</div> : null
}

export function iconTone(icon: string) {
  const tones = ['icon-violet', 'icon-coral', 'icon-green', 'icon-blue']
  const code = icon.codePointAt(0) ?? 0
  return tones[code % tones.length]
}

export function hostname(url: string) {
  try {
    return new URL(url).hostname
  } catch {
    return url
  }
}

function AppShell() {
  const { t, i18n: activeI18n } = useTranslation(['common', 'auth', 'vault', 'settings', 'admin'])
  const [appearancePreference, setAppearancePreference] = useAppearancePreference()
  const { pathname } = useLocation()
  const routerNavigate = useNavigate()
  const navigate = useCallback((nextPath: string, replace = false) => {
    routerNavigate(nextPath, { replace })
  }, [routerNavigate])
  const [vaultClient] = useState(() => createHttpVaultClient())
  const getAccessToken = useCallback(() => vaultClient.getAccessToken?.() ?? null, [vaultClient])
  /** Shared token refresher: the vault adapter deduplicates concurrent refreshes. */
  const refreshAccessToken = useCallback((signal?: AbortSignal) => vaultClient.refreshAccessToken(signal), [vaultClient])
  const { user, isUnlocked, isAdmin, sessionChecked, items, selectedItem, loadingItemId, restoreSession, login, unlock, loadItem, createItem, updateItem, deleteItem, clearSelectedItem, lock, logout } = useVaultSession(vaultClient)
  const copyTimers = useRef<number[]>([])
  const copyGenerationRef = useRef(0)
  const [clipboardQueue] = useState(createClipboardOperationQueue)
  const loadHealthItem = useCallback((itemId: string) => vaultClient.getItem(itemId), [vaultClient])
  const exportBackup = useCallback(() => vaultClient.exportBackup(), [vaultClient])
  const exportBackupFull = useCallback((masterPassword: string, recoveryKey: string) => vaultClient.exportBackupFull(masterPassword, recoveryKey), [vaultClient])
  const lastDetailIdRef = useRef<string | null>(null)
  const [detailLoadErrorId, setDetailLoadErrorId] = useState<string | null>(null)
  const protectedRoute = useRouteMatch()

  const lockVault = useCallback(() => {
    lock()
    if (user) navigate(`/users/${user.id}/unlock`, true)
  }, [lock, navigate, user])

  useAutoLock(isUnlocked, lockVault)

  // Restore the login identity once on startup: the refresh token survives
  // a page refresh in its HttpOnly cookie, but the user lived only in
  // React state. A failed restore simply stays logged out, silently.
  const restoreRef = useRef(false)
  useEffect(() => {
    if (restoreRef.current) return
    restoreRef.current = true
    void restoreSession()
  }, [restoreSession])

  useEffect(() => {
    document.documentElement.lang = activeI18n.resolvedLanguage ?? 'en'
  }, [activeI18n.resolvedLanguage])

  useEffect(() => {
    const isAdminPath = pathname === '/admin' || pathname === '/admin/'
    const pageTitle = isAdminPath ? t('admin:header.console') : protectedRoute?.screen === 'unlock' ? t('auth:unlockTitle') : protectedRoute?.screen === 'setup' ? t('auth:setupVaultTitle') : protectedRoute?.screen === 'generator' ? t('vault:generator.title') : protectedRoute?.screen === 'settings' ? t('settings:title') : protectedRoute?.screen === 'health' ? t('vault:health.title') : protectedRoute?.screen === 'confirmations' ? t('vault:mcpConfirmations.title') : protectedRoute?.itemId ? t('vault:detailEyebrow') : protectedRoute ? t('vault:vaultHeading') : pathname === '/login' ? t('auth:loginTitle') : t('common:landingTitle')
    document.title = `${pageTitle} · Sealero`
  }, [pathname, protectedRoute, t, activeI18n.resolvedLanguage])

  useEffect(() => {
    // Wait for the startup restore before redirecting: without this, a
    // refresh on a vault page would bounce to /login while the session was
    // still being restored from the refresh-token cookie.
    if (!sessionChecked) return
    if (protectedRoute && !user) {
      navigate('/login', true)
      return
    }
    if (protectedRoute && user && protectedRoute.userId !== user.id) {
      navigate(isUnlocked ? `/users/${user.id}` : `/users/${user.id}/unlock`, true)
      return
    }
    // The setup page is exempt like unlock: it is for accounts with no
    // vault key yet, so there is nothing to unlock.
    if (protectedRoute && protectedRoute.screen !== 'unlock' && protectedRoute.screen !== 'setup' && user && !isUnlocked) {
      navigate(`/users/${user.id}/unlock`, true)
    }
  }, [isUnlocked, navigate, protectedRoute, sessionChecked, user])

  useEffect(() => {
    const itemId = protectedRoute?.itemId
    if (!itemId) return
    if (!user || !isUnlocked || protectedRoute.userId !== user.id || selectedItem?.id === itemId) return

    let active = true
    void loadItem(itemId).catch(() => {
      if (active) setDetailLoadErrorId(itemId)
    })
    return () => { active = false }
  }, [isUnlocked, loadItem, protectedRoute?.itemId, protectedRoute?.userId, selectedItem?.id, user])

  useEffect(() => {
    if (protectedRoute?.itemId) {
      lastDetailIdRef.current = protectedRoute.itemId
      return
    }
    if (lastDetailIdRef.current) {
      lastDetailIdRef.current = null
      clearSelectedItem()
    }
  }, [clearSelectedItem, protectedRoute?.itemId])

  useEffect(() => () => {
    copyGenerationRef.current += 1
    for (const timer of copyTimers.current) window.clearTimeout(timer)
    copyTimers.current = []
  }, [])

  /**
   * Returns the auth-copy key of the failure (e.g. `loginInvalidCredentials`),
   * or null when login succeeded. The Login page renders the mapped copy.
   */
  const handleLogin = async (email: string, loginPassword: string): Promise<string | null> => {
    try {
      const identity = await login(email, loginPassword)
      if (identity) {
        // Never ask for a master password that was never set: accounts
        // whose registration never reached the master-password step have
        // no vault key, and go straight to vault setup instead of unlock.
        // Any check failure falls back to unlock (its previous behavior).
        const hasKey = await vaultClient.hasVaultKey().catch(() => null)
        navigate(hasKey === false ? `/users/${identity.id}/setup` : `/users/${identity.id}/unlock`)
      }
      return null
    } catch (error) {
      if (error instanceof VaultApiError) {
        if (error.code === 'invalid_credentials') return 'loginInvalidCredentials'
        if (error.code === 'rate_limited') return 'loginRateLimited'
      }
      return 'loginFailed'
    }
  }

  /**
   * Returns the auth-copy key of the failure, or null when unlock succeeded.
   * The Unlock page renders the mapped copy; 403 means the consent gate
   * blocked the request. A 404 means no vault key exists yet, which is not
   * an unlock failure to display — it redirects to vault setup instead.
   */
  const handleUnlock = async (masterPassword: string): Promise<string | null> => {
    if (!user) return 'unlockFailed'
    try {
      const didUnlock = await unlock(masterPassword)
      if (didUnlock) navigate(`/users/${user.id}`)
      return null
    } catch (error) {
      if (error instanceof VaultApiError) {
        if (error.code === 'invalid_master_password') return 'unlockWrongPassword'
        if (error.status === 404) {
          navigate(`/users/${user.id}/setup`)
          return null
        }
        if (error.status === 403) return 'unlockConsentRequired'
      }
      return 'unlockFailed'
    }
  }

  const handleOpenItem = useCallback((itemId: string) => {
    if (!user || !isUnlocked) return
    navigate(`/users/${user.id}/items/${itemId}`)
  }, [isUnlocked, navigate, user])

  const handleCreateItem = useCallback(async (input: VaultItemInput) => {
    const created = await createItem(input)
    if (created) navigate(`/users/${user?.id}/items/${created.id}`)
    return created
  }, [createItem, navigate, user?.id])

  const handleUpdateItem = useCallback(async (itemId: string, input: VaultItemInput) => {
    return updateItem(itemId, input)
  }, [updateItem])

  const handleDeleteItem = useCallback(async (itemId: string) => {
    const deleted = await deleteItem(itemId)
    if (deleted && user) navigate(`/users/${user.id}`)
    return deleted
  }, [deleteItem, navigate, user])

  const handleLogout = () => {
    logout()
    navigate('/')
  }

  const copyToClipboard = useCallback(async (value: string, label: string) => {
    const generation = ++copyGenerationRef.current
    for (const timer of copyTimers.current) window.clearTimeout(timer)
    copyTimers.current = []
    try {
      const wroteCurrentCopy = await clipboardQueue.run(async () => {
        if (generation !== copyGenerationRef.current) return false
        await navigator.clipboard.writeText(value)
        return true
      })
      if (!wroteCurrentCopy || generation !== copyGenerationRef.current) return
      const timer = window.setTimeout(async () => {
        copyTimers.current = copyTimers.current.filter((scheduledTimer) => scheduledTimer !== timer)
        const outcome = await clipboardQueue.run(async () => {
          if (generation !== copyGenerationRef.current) return 'stale'
          return clearClipboardIfStillCurrent(
            navigator.clipboard,
            value,
            () => generation === copyGenerationRef.current,
          )
        })
        if (outcome === 'failed' && generation === copyGenerationRef.current) {
          window.dispatchEvent(new CustomEvent('sealero:toast', { detail: t('vault:clipboardClearFailed') }))
        }
      }, 30_000)
      copyTimers.current.push(timer)
      window.dispatchEvent(new CustomEvent('sealero:toast', { detail: t('common:copiedField', { label }) }))
    } catch {
      if (generation === copyGenerationRef.current) window.dispatchEvent(new CustomEvent('sealero:toast', { detail: t('common:copyFailed') }))
    }
  }, [clipboardQueue, t])

  // While the startup restore is pending, a protected route shows a loading
  // line instead of flashing the login page for a session that is about to
  // be restored. Public routes (landing, login, register) render at once.
  if (protectedRoute && !sessionChecked) {
    return <div className="detail-loading" role="status" aria-live="polite">{t('vault:loadingEntry')}</div>
  }

  return (
    <AppRoutes
      vaultClient={vaultClient}
      onSessionLogin={login}
      user={user}
      isUnlocked={isUnlocked}
      isAdmin={isAdmin}
      items={items}
      selectedItem={selectedItem}
      loadingItemId={loadingItemId}
      detailLoadErrorId={detailLoadErrorId}
      appearancePreference={appearancePreference}
      onAppearanceChange={setAppearancePreference}
      onNavigate={navigate}
      onLogin={handleLogin}
      onUnlock={handleUnlock}
      onOpenItem={(itemId) => void handleOpenItem(itemId)}
      onCreateItem={handleCreateItem}
      onUpdateItem={handleUpdateItem}
      onDeleteItem={handleDeleteItem}
      onLock={lockVault}
      onLogout={handleLogout}
      onCopy={(value, label) => void copyToClipboard(value, label)}
      loadHealthItem={loadHealthItem}
      getAccessToken={getAccessToken}
      refreshAccessToken={refreshAccessToken}
      onExportBackup={exportBackup}
      onExportBackupFull={exportBackupFull}
    />
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AppShell />
    </BrowserRouter>
  )
}
