import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { Check, ChevronLeft, ChevronUp, Copy, Languages, LayoutGrid, Lock, LogOut, PanelLeft, Settings, Shield, ShieldCheck, Sparkles, Star, Sun, X } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { BrowserRouter, useLocation, useNavigate } from 'react-router-dom'
import { Brand } from './components/Brand'
import { DetailLoading } from './components/DetailLoading'
import { UserAvatar } from './components/UserAvatar'
import { LanguageSelector } from './components/LanguageSelector'
import { ThemeToggle } from './components/ThemeToggle'
import { Dialog, DialogContent, DialogTitle } from './components/ui/dialog'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuSeparator, DropdownMenuSub, DropdownMenuSubContent, DropdownMenuSubTrigger, DropdownMenuTrigger } from './components/ui/dropdown-menu'
import { Button } from './components/ui/button'
import { Sidebar, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupContent, SidebarHeader, SidebarInset, SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarProvider, SidebarSeparator, SidebarTrigger, useSidebar } from './components/ui/sidebar'
import { applyLanguagePreference } from './features/settings/preferences'
import { isLanguage, languages, type Language } from './i18n-config'
import type { AppearancePreference } from './features/settings/preferences'
import type { VaultIdentity, VaultItemInput } from './client/contracts'
import { createHttpVaultClient, VaultApiError } from './client/http-vault-client'
import { DEFAULT_AUTO_LOCK_MINUTES } from './hooks/auto-lock-policy'
import { useAutoLock } from './hooks/use-auto-lock'
import { useVaultSession } from './hooks/use-vault-session'
import { useAppearancePreference } from './features/settings/preferences'
import { clearClipboardIfStillCurrent, createClipboardOperationQueue } from './features/password-security/clipboard'
import { AppRoutes, useRouteMatch } from './routes'
import './app.css'

export type VaultFilter = 'all' | 'favorites'

/** localStorage flag set when the user dismisses the auto-lock notice; once set, the card stays hidden. */
const AUTO_LOCK_NOTICE_KEY = 'sealero.vault.autoLockNoticeDismissed'

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

/**
 * Shared shell for both backends (vault + admin console), built on the
 * shadcn/ui Sidebar: a collapsible icon rail on desktop, a sheet drawer
 * on mobile, and a slim top bar with the sidebar trigger. The sidebar
 * menu differs per backend, so the caller supplies it as a function
 * receiving `requestSignOut` (which opens the shared sign-out confirm
 * dialog); the shell appends the appearance + language submenus and the
 * sign-out item itself, so sign-out is always last. The user menu opens
 * upward (side="top") because the trigger sits at the bottom of the
 * sidebar. Toasts are event-driven and render nothing when empty, so
 * both backends can share this shell.
 */
export function BackendShell({ user, nav, bottom, menu, title, topbarAction, topbarEndAction, appearancePreference, onNavigate, onLogout, onAppearanceChange, children }: {
  user: VaultIdentity
  nav: ReactNode
  bottom?: ReactNode
  menu: (requestSignOut: () => void) => ReactNode
  title?: ReactNode
  /** One tool shown in the top bar next to the collapse button. */
  topbarAction?: ReactNode
  /** One action shown at the far right end of the top bar. */
  topbarEndAction?: ReactNode
  appearancePreference: AppearancePreference
  onNavigate: (path: string) => void
  onLogout: () => void
  onAppearanceChange: (preference: AppearancePreference) => void
  children: ReactNode
}) {
  const { t, i18n } = useTranslation(['common', 'settings'])
  const [confirmSignOutOpen, setConfirmSignOutOpen] = useState(false)
  const currentLanguage = isLanguage(i18n.resolvedLanguage) ? i18n.resolvedLanguage : 'en'
  return (
    <SidebarProvider>
      <Sidebar collapsible="icon">
        <SidebarHeader>
          <div className="flex items-center justify-between gap-2 group-data-[collapsible=icon]:hidden">
            <Brand onNavigate={onNavigate} />
            <SidebarTrigger className="shrink-0" />
          </div>
          <div className="hidden justify-center group-data-[collapsible=icon]:flex">
            <LogoToggle />
          </div>
        </SidebarHeader>
        <SidebarContent>
          {nav}
        </SidebarContent>
        <SidebarFooter>
          {bottom ? <div className="group-data-[collapsible=icon]:hidden">{bottom}</div> : null}
          <SidebarMenu>
            <SidebarMenuItem>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <SidebarMenuButton size="lg" tooltip={user.email}>
                    <UserAvatar displayName={user.display_name} avatarUrl={user.avatar_url} email={user.email} className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-sidebar-primary text-xs font-medium text-sidebar-primary-foreground" />
                    <span className="min-w-0 flex-1 truncate text-left">{user.display_name ?? user.email}</span>
                    <ChevronUp className="ml-auto size-4" aria-hidden="true" />
                  </SidebarMenuButton>
                </DropdownMenuTrigger>
                <DropdownMenuContent side="top" align="end" className="w-(--radix-dropdown-menu-trigger-width) min-w-56 rounded-lg bg-sidebar/80 backdrop-blur-[18px] backdrop-saturate-[1.35]">
                  {menu(() => setConfirmSignOutOpen(true))}
                  <DropdownMenuSeparator />
                  <DropdownMenuSub>
                    <DropdownMenuSubTrigger>
                      <Sun className="size-4" aria-hidden="true" />
                      <span>{t('settings:appearanceTitle')}</span>
                    </DropdownMenuSubTrigger>
                    <DropdownMenuSubContent className="bg-sidebar/80 backdrop-blur-[18px] backdrop-saturate-[1.35]">
                      <DropdownMenuRadioGroup value={appearancePreference} onValueChange={(value) => onAppearanceChange(value as AppearancePreference)}>
                        <DropdownMenuRadioItem value="system">{t('settings:followSystem')}</DropdownMenuRadioItem>
                        <DropdownMenuRadioItem value="light">{t('settings:light')}</DropdownMenuRadioItem>
                        <DropdownMenuRadioItem value="dark">{t('settings:dark')}</DropdownMenuRadioItem>
                      </DropdownMenuRadioGroup>
                    </DropdownMenuSubContent>
                  </DropdownMenuSub>
                  <DropdownMenuSub>
                    <DropdownMenuSubTrigger>
                      <Languages className="size-4" aria-hidden="true" />
                      <span>{t('common:language')}</span>
                    </DropdownMenuSubTrigger>
                    <DropdownMenuSubContent className="bg-sidebar/80 backdrop-blur-[18px] backdrop-saturate-[1.35]">
                      <DropdownMenuRadioGroup value={currentLanguage} onValueChange={(value) => void applyLanguagePreference(value as Language)}>
                        {languages.map((language) => (
                          <DropdownMenuRadioItem key={language.code} value={language.code}>{language.label}</DropdownMenuRadioItem>
                        ))}
                      </DropdownMenuRadioGroup>
                    </DropdownMenuSubContent>
                  </DropdownMenuSub>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={() => setConfirmSignOutOpen(true)}>
                    <LogOut className="size-4" aria-hidden="true" />
                    <span>{t('common:signOut')}</span>
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarFooter>
      </Sidebar>
      <SidebarInset className="bg-sidebar">
        <header className="relative flex h-12 shrink-0 items-center gap-2 border-b px-4">
          <SidebarTrigger className="-ml-1 md:hidden" />
          {topbarAction}
          {title ? <>
            <SidebarSeparator orientation="vertical" className="mr-2 h-4 md:hidden" />
            <span className="absolute left-1/2 top-1/2 max-w-[70%] -translate-x-1/2 -translate-y-1/2 truncate text-sm font-medium">{title}</span>
          </> : null}
          {topbarEndAction ? <span className="ml-auto flex items-center">{topbarEndAction}</span> : null}
        </header>
        <div className="flex min-w-0 flex-1 flex-col">{children}</div>
      </SidebarInset>
      <ToastLayer />
      <SignOutConfirmDialog open={confirmSignOutOpen} onConfirm={onLogout} onClose={() => setConfirmSignOutOpen(false)} />
    </SidebarProvider>
  )
}

function SignOutConfirmDialog({ open, onConfirm, onClose }: { open: boolean; onConfirm: () => void; onClose: () => void }) {
  const { t } = useTranslation(['common'])

  return (
    <Dialog open={open} onOpenChange={(nextOpen) => { if (!nextOpen) onClose() }}>
      <DialogContent className="gap-0" showCloseButton={false}>
        <DialogTitle className="text-base font-semibold">{t('common:signOutConfirm')}</DialogTitle>
        <div className="mt-4 flex justify-end gap-2">
          <Button variant="outline" type="button" onClick={onClose}>{t('common:cancel')}</Button>
          <Button type="button" onClick={onConfirm}>{t('common:confirmSignOut')}</Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}

/**
 * Collapsed sidebar only: the icon logo is the expand control — hovering
 * it turns the logo itself into the toggle icon, and clicking expands the
 * sidebar. The logo stays in place, only invisible, so the button never
 * changes size under the cursor.
 */
function LogoToggle() {
  const { toggleSidebar } = useSidebar()
  return (
    <button
      type="button"
      onClick={toggleSidebar}
      aria-label="Toggle Sidebar"
      className="group/logotoggle relative flex h-8 cursor-pointer items-center rounded-md border-0 bg-transparent p-0 hover:bg-accent"
    >
      <span className="wordmark group-hover/logotoggle:invisible group-focus-visible/logotoggle:invisible">
        <img className="wordmark-logo" src="/sealero-logo.svg" alt="" aria-hidden="true" />
      </span>
      <span className="absolute inset-0 hidden items-center justify-center group-hover/logotoggle:flex group-focus-visible/logotoggle:flex" aria-hidden="true">
        <PanelLeft className="size-5" />
      </span>
    </button>
  )
}

export function TopbarBackButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <Button type="button" variant="ghost" size="icon" className="size-7" aria-label={label} title={label} onClick={onClick}>
      <ChevronLeft className="size-4" aria-hidden="true" />
    </Button>
  )
}

export function VaultLayout({ user, filter, activeNav = filter === 'favorites' ? 'favorites' : 'vault', isAdmin, autoLockMinutes = DEFAULT_AUTO_LOCK_MINUTES, title, topbarAction, topbarEndAction, appearancePreference, onFilterChange, onNavigate, onLock, onLogout, onAppearanceChange, children }: {
  user: VaultIdentity
  filter: VaultFilter
  /** Which nav item shows as selected; defaults to the vault filter ('vault' or 'favorites'). */
  activeNav?: 'vault' | 'favorites' | 'generator' | 'health' | 'confirmations' | 'none'
  /** Shows the admin-console entry in the user menu when the session is an admin. */
  isAdmin?: boolean
  /** The user's own auto-lock timeout in minutes, shown in the auto-lock notice. */
  autoLockMinutes?: number
  title?: ReactNode
  /** One tool shown in the top bar next to the collapse button. */
  topbarAction?: ReactNode
  /** One action shown at the far right end of the top bar. */
  topbarEndAction?: ReactNode
  appearancePreference: AppearancePreference
  onFilterChange: (filter: VaultFilter) => void
  onNavigate: (path: string) => void
  onLock: () => void
  onLogout: () => void
  onAppearanceChange: (preference: AppearancePreference) => void
  children: ReactNode
}) {
  const { t } = useTranslation(['common', 'vault', 'settings', 'admin'])
  // The auto-lock notice shows until the user dismisses it; the dismissal
  // is remembered in localStorage, so it never comes back on its own.
  const [autoLockNoticeVisible, setAutoLockNoticeVisible] = useState(() => {
    try {
      return localStorage.getItem(AUTO_LOCK_NOTICE_KEY) !== '1'
    } catch {
      return true
    }
  })
  const dismissAutoLockNotice = () => {
    try {
      localStorage.setItem(AUTO_LOCK_NOTICE_KEY, '1')
    } catch {
      // Storage may be unavailable; the notice still hides for this session.
    }
    setAutoLockNoticeVisible(false)
  }
  return (
    <BackendShell
      user={user}
      onNavigate={onNavigate}
      onLogout={onLogout}
      title={title}
      topbarAction={topbarAction}
      topbarEndAction={topbarEndAction}
      appearancePreference={appearancePreference}
      onAppearanceChange={onAppearanceChange}
      nav={
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              <SidebarMenuItem>
                <SidebarMenuButton isActive={activeNav === 'vault'} tooltip={t('vault:allItems')} onClick={() => { onFilterChange('all'); onNavigate(`/users/${user.id}`) }}>
                  <LayoutGrid />
                  <span>{t('vault:allItems')}</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
              <SidebarMenuItem>
                <SidebarMenuButton isActive={activeNav === 'favorites'} tooltip={t('vault:favorites')} onClick={() => { onFilterChange('favorites'); onNavigate(`/users/${user.id}`) }}>
                  <Star />
                  <span>{t('vault:favorites')}</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
              <SidebarMenuItem>
                <SidebarMenuButton isActive={activeNav === 'generator'} tooltip={t('vault:generator.title')} onClick={() => onNavigate(`/users/${user.id}/generator`)}>
                  <Sparkles />
                  <span>{t('vault:generator.title')}</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
              <SidebarMenuItem>
                <SidebarMenuButton isActive={activeNav === 'health'} tooltip={t('vault:health.title')} onClick={() => onNavigate(`/users/${user.id}/health`)}>
                  <ShieldCheck />
                  <span>{t('vault:health.title')}</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
              <SidebarMenuItem>
                <SidebarMenuButton isActive={activeNav === 'confirmations'} tooltip={t('vault:mcpConfirmations.title')} onClick={() => onNavigate(`/users/${user.id}/confirmations`)}>
                  <Check />
                  <span>{t('vault:mcpConfirmations.title')}</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      }
      bottom={autoLockNoticeVisible ? (
        <div className="rounded-lg bg-muted p-3 text-xs leading-relaxed text-muted-foreground">
          <div className="mb-1.5 flex items-center gap-1.5">
            <span className="flex items-center gap-1.5 font-semibold text-foreground">
              <Lock className="size-3.5" aria-hidden="true" />
              {t('vault:autoLockTitle')}
            </span>
            <button className="ml-auto -mr-1 -mt-0.5 flex size-5 shrink-0 cursor-pointer items-center justify-center rounded-md border-0 bg-transparent text-muted-foreground hover:bg-accent hover:text-foreground" type="button" onClick={dismissAutoLockNotice} aria-label={t('common:close')}>
              <X size={14} aria-hidden="true" />
            </button>
          </div>
          {t('vault:autoLockDescription', { minutes: autoLockMinutes })}
        </div>
      ) : undefined}
      menu={() => (<>
        <DropdownMenuItem onClick={onLock}>
          <Lock className="size-4" aria-hidden="true" />
          <span>{t('vault:lockVault')}</span>
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => onNavigate(`/users/${user.id}/settings`)}>
          <Settings className="size-4" aria-hidden="true" />
          <span>{t('settings:title')}</span>
        </DropdownMenuItem>
        {isAdmin ? (
          <DropdownMenuItem onClick={() => onNavigate('/admin')}>
            <Shield className="size-4" aria-hidden="true" />
            <span>{t('admin:header.navigation')}</span>
          </DropdownMenuItem>
        ) : null}
      </>)}
    >
      {children}
    </BackendShell>
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
    <div className="grid gap-1">
      <div className="text-xs font-medium text-muted-foreground">{label}</div>
      <div className="flex items-center gap-2">
        <div className="min-w-0 flex-1 break-all text-sm">{visible === false ? maskedValue : value}</div>
        {onToggle ? <Button variant="ghost" size="sm" type="button" onClick={onToggle}>{visible ? t('hide') : t('show')}</Button> : null}
        <Button variant="ghost" size="icon" className="size-7 shrink-0" type="button" onClick={onCopy} aria-label={`${t('copy')} ${copyLabel}`} title={`${t('copy')} ${copyLabel}`}><CopyIcon /></Button>
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

  return message ? <div className="fixed bottom-6 left-1/2 z-50 -translate-x-1/2 rounded-full bg-foreground px-4 py-2 text-sm text-background shadow-lg" role="status" aria-live="polite">{message}</div> : null
}

export function iconTone(icon: string) {
  const tones = [
    'bg-violet-100 text-violet-700 dark:bg-violet-950 dark:text-violet-300',
    'bg-orange-100 text-orange-700 dark:bg-orange-950 dark:text-orange-300',
    'bg-emerald-100 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300',
    'bg-blue-100 text-blue-700 dark:bg-blue-950 dark:text-blue-300',
  ]
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
  const { user, isUnlocked, isAdmin, sessionChecked, items, selectedItem, loadingItemId, autoLockMinutes, updateAutoLockMinutes, restoreSession, login, unlock, loadItem, createItem, updateItem, deleteItem, clearSelectedItem, lock, logout } = useVaultSession(vaultClient)
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

  useAutoLock(isUnlocked, lockVault, autoLockMinutes * 60_000)

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
    return <DetailLoading />
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
      autoLockMinutes={autoLockMinutes}
      onAutoLockMinutesChange={updateAutoLockMinutes}
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
