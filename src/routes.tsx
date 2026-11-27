import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Navigate, Route, Routes, matchPath, useLocation, useParams } from 'react-router-dom'
import type { VaultClient, VaultIdentity, VaultItem, VaultItemInput, VaultListItem } from './client/contracts'
import type { AppearancePreference } from './features/settings/preferences'
import { PasswordGeneratorPage, PasswordHealthDashboard } from './features/password-security/PasswordSecurity'
import { SettingsPage } from './features/settings/SettingsPage'
import { DetailLoading } from './components/DetailLoading'
import Landing from './pages/Landing'
import { LegalPage } from './pages/Legal'
import { Console } from './pages/Console'
import { McpConfirmations } from './pages/McpConfirmations'
import { VaultLayout } from './App'
import { ItemDetail } from './pages/ItemDetail'
import { Login } from './pages/Login'
import { NotFound } from './pages/NotFound'
import { Register } from './pages/Register'
import { Unlock } from './pages/Unlock'
import { VaultSetup } from './pages/VaultSetup'
import { VaultList } from './pages/VaultList'

export type RouteScreen = 'vault' | 'unlock' | 'setup' | 'generator' | 'settings' | 'health' | 'confirmations'

export interface RouteMatch {
  userId: string
  itemId: string | null
  screen: RouteScreen
}

function matchProtectedPath(pathname: string): RouteMatch | null {
  const unlock = matchPath('/users/:userId/unlock', pathname)
  if (unlock?.params.userId) return { userId: unlock.params.userId, itemId: null, screen: 'unlock' }

  const setup = matchPath('/users/:userId/setup', pathname)
  if (setup?.params.userId) return { userId: setup.params.userId, itemId: null, screen: 'setup' }

  const item = matchPath('/users/:userId/items/:itemId', pathname)
  if (item?.params.userId && item?.params.itemId) return { userId: item.params.userId, itemId: item.params.itemId, screen: 'vault' }

  const generator = matchPath('/users/:userId/generator', pathname)
  if (generator?.params.userId) return { userId: generator.params.userId, itemId: null, screen: 'generator' }

  const health = matchPath('/users/:userId/health', pathname)
  if (health?.params.userId) return { userId: health.params.userId, itemId: null, screen: 'health' }

  const confirmations = matchPath('/users/:userId/confirmations', pathname)
  if (confirmations?.params.userId) return { userId: confirmations.params.userId, itemId: null, screen: 'confirmations' }

  const settings = matchPath('/users/:userId/settings', pathname)
  if (settings?.params.userId) return { userId: settings.params.userId, itemId: null, screen: 'settings' }

  const vault = matchPath('/users/:userId', pathname)
  if (vault?.params.userId) return { userId: vault.params.userId, itemId: null, screen: 'vault' }

  return null
}

/** Matches the current URL against the /users/:userId route family using React Router's matcher. */
export function useRouteMatch(): RouteMatch | null {
  const { pathname } = useLocation()
  return useMemo(() => matchProtectedPath(pathname), [pathname])
}

export interface AppRoutesProps {
  vaultClient: VaultClient
  /** Session login (sets the user, no navigation); the Register page uses it to get a JWT before uploading the vault key. */
  onSessionLogin: (email: string, loginPassword: string) => Promise<VaultIdentity | null>
  user: VaultIdentity | null
  isUnlocked: boolean
  /** Cached admin-role probe result for this login session. */
  isAdmin: boolean
  items: VaultListItem[]
  selectedItem: VaultItem | null
  loadingItemId: string | null
  detailLoadErrorId: string | null
  appearancePreference: AppearancePreference
  onAppearanceChange: (preference: AppearancePreference) => void
  onNavigate: (path: string, replace?: boolean) => void
  onLogin: (email: string, password: string) => Promise<string | null>
  onUnlock: (password: string) => Promise<string | null>
  onOpenItem: (itemId: string) => void
  onCreateItem: (input: VaultItemInput) => Promise<VaultItem | null>
  onUpdateItem: (itemId: string, input: VaultItemInput) => Promise<VaultItem | null>
  onDeleteItem: (itemId: string) => Promise<boolean>
  /** Locks the vault (clears the in-memory DEK) and returns to the unlock page. */
  onLock: () => void
  onLogout: () => void
  onCopy: (value: string, label: string) => void
  loadHealthItem: (itemId: string) => Promise<VaultItem>
  /** Returns the in-memory access JWT when the session adapter holds one. */
  getAccessToken: () => string | null
  /** Shared token refresher (the vault adapter's); admin/MCP clients call it on 401. */
  refreshAccessToken: (signal?: AbortSignal) => Promise<string>
  /** KEK-only v3 container for cloud backup; null when the vault is locked. */
  onExportBackup: () => Promise<Uint8Array | null>
  /** Full v3 container (KEK + recovery-key wrappings) for manual export. */
  onExportBackupFull: (masterPassword: string, recoveryKey: string) => Promise<Uint8Array>
}

function UnlockRoute(props: AppRoutesProps) {
  const { userId } = useParams()
  const { user, onUnlock, onLogout, onNavigate, onLogin, onAppearanceChange } = props
  if (user && userId === user.id) {
    return <Unlock user={user} onUnlock={onUnlock} onBackToLogin={onLogout} onNavigate={onNavigate} onAppearanceChange={onAppearanceChange} />
  }
  return <Login onLogin={onLogin} onNavigate={onNavigate} onAppearanceChange={onAppearanceChange} />
}

/**
 * Vault setup for a logged-in account with no vault key yet. Like the
 * admin console it needs only the login session — never a vault unlock,
 * since there is no master password yet to unlock with.
 */
function SetupRoute(props: AppRoutesProps) {
  const { userId } = useParams()
  const { user, vaultClient, onNavigate, onAppearanceChange } = props
  if (user && userId === user.id) {
    return <VaultSetup user={user} vaultClient={vaultClient} onNavigate={onNavigate} onAppearanceChange={onAppearanceChange} />
  }
  return <Login onLogin={props.onLogin} onNavigate={onNavigate} onAppearanceChange={onAppearanceChange} />
}

/**
 * Role-gated admin entry. The admin console needs only the login session
 * plus the admin role — never a vault unlock (no master password). Non-admin
 * sessions are sent back to their own vault instead of a dead end.
 */
function AdminRoute(props: AppRoutesProps) {
  const { user, isAdmin, appearancePreference, onNavigate, getAccessToken, refreshAccessToken, onAppearanceChange, onLogout } = props
  if (!user) return <Navigate to="/login" replace />
  if (!isAdmin) return <Navigate to={`/users/${user.id}`} replace />
  return <Console user={user} appearancePreference={appearancePreference} onNavigate={onNavigate} getAccessToken={getAccessToken} refreshAccessToken={refreshAccessToken} currentUserId={user.id} onAppearanceChange={onAppearanceChange} onLogout={onLogout} />
}

function VaultRoute(props: AppRoutesProps & { screen: 'vault' | 'generator' | 'settings' | 'health' | 'confirmations' }) {
  const { userId, itemId } = useParams()
  const { t } = useTranslation(['common', 'vault', 'settings'])
  const { user, isUnlocked, isAdmin, items, selectedItem, loadingItemId, detailLoadErrorId, screen, onNavigate, onLogin, onLock, onLogout, onOpenItem, onCreateItem, onUpdateItem, onDeleteItem, onCopy, loadHealthItem, appearancePreference, onAppearanceChange, onExportBackup, onExportBackupFull, getAccessToken, refreshAccessToken } = props

  if (!user || userId !== user.id || !isUnlocked) {
    return <Login onLogin={onLogin} onNavigate={onNavigate} onAppearanceChange={onAppearanceChange} />
  }

  const loading = (
    <VaultLayout user={user} filter="all" isAdmin={isAdmin} onFilterChange={() => onNavigate(`/users/${user.id}`)} onNavigate={onNavigate} onLock={onLock} onLogout={onLogout} appearancePreference={appearancePreference} onAppearanceChange={onAppearanceChange}>
      <DetailLoading />
    </VaultLayout>
  )

  if (screen === 'generator') {
    return (
      <VaultLayout user={user} filter="all" activeNav="generator" isAdmin={isAdmin} title={t('vault:generator.title')} onFilterChange={() => onNavigate(`/users/${user.id}`)} onNavigate={onNavigate} onLock={onLock} onLogout={onLogout} appearancePreference={appearancePreference} onAppearanceChange={onAppearanceChange}>
        <PasswordGeneratorPage onCopy={(value, label) => onCopy(value, label)} />
      </VaultLayout>
    )
  }
  if (screen === 'settings') {
    return (
      <VaultLayout user={user} filter="all" activeNav="none" isAdmin={isAdmin} title={t('settings:title')} onFilterChange={() => onNavigate(`/users/${user.id}`)} onNavigate={onNavigate} onLock={onLock} onLogout={onLogout} appearancePreference={appearancePreference} onAppearanceChange={onAppearanceChange}>
        <SettingsPage user={user} items={items} loadItem={loadHealthItem} onExportBackup={onExportBackup} onExportBackupFull={onExportBackupFull} />
      </VaultLayout>
    )
  }
  if (screen === 'health') {
    return (
      <VaultLayout user={user} filter="all" activeNav="health" isAdmin={isAdmin} title={t('vault:health.title')} onFilterChange={() => onNavigate(`/users/${user.id}`)} onNavigate={onNavigate} onLock={onLock} onLogout={onLogout} appearancePreference={appearancePreference} onAppearanceChange={onAppearanceChange}>
        <PasswordHealthDashboard items={items} loadItem={loadHealthItem} />
      </VaultLayout>
    )
  }
  if (screen === 'confirmations') {
    return <McpConfirmations user={user} items={items} isAdmin={isAdmin} onNavigate={onNavigate} onLock={onLock} onLogout={onLogout} appearancePreference={appearancePreference} onAppearanceChange={onAppearanceChange} getAccessToken={getAccessToken} refreshAccessToken={refreshAccessToken} />
  }
  if (itemId) {
    if (!selectedItem || selectedItem.id !== itemId) {
      if (loadingItemId === itemId) return loading
      if (detailLoadErrorId === itemId) return <NotFound onNavigate={onNavigate} onAppearanceChange={onAppearanceChange} />
      return loading
    }
    return <ItemDetail key={selectedItem.id} user={user} item={selectedItem} items={items} isAdmin={isAdmin} loadItem={loadHealthItem} onNavigate={onNavigate} onLock={onLock} onLogout={onLogout} appearancePreference={appearancePreference} onAppearanceChange={onAppearanceChange} onCopy={(value, label) => onCopy(value, label)} onUpdateItem={onUpdateItem} onDeleteItem={onDeleteItem} />
  }
  return <VaultList user={user} items={items} isAdmin={isAdmin} onNavigate={onNavigate} onOpenItem={onOpenItem} onLock={onLock} onLogout={onLogout} appearancePreference={appearancePreference} onAppearanceChange={onAppearanceChange} onCreateItem={onCreateItem} />
}

export function AppRoutes(props: AppRoutesProps) {
  const { vaultClient, onSessionLogin, onNavigate, onLogin, onAppearanceChange, user } = props
  return (
    <Routes>
      <Route path="/" element={<Landing user={user} onNavigate={onNavigate} onAppearanceChange={onAppearanceChange} />} />
      <Route path="/terms" element={<LegalPage doc="terms" onNavigate={onNavigate} onAppearanceChange={onAppearanceChange} />} />
      <Route path="/privacy" element={<LegalPage doc="privacy" onNavigate={onNavigate} onAppearanceChange={onAppearanceChange} />} />
      <Route path="/login" element={<Login onLogin={onLogin} onNavigate={onNavigate} onAppearanceChange={onAppearanceChange} />} />
      <Route path="/register" element={<Register vaultClient={vaultClient} onSessionLogin={onSessionLogin} onNavigate={onNavigate} onAppearanceChange={onAppearanceChange} />} />
      <Route path="/admin" element={<AdminRoute {...props} />} />
      <Route path="/users/:userId" element={<VaultRoute {...props} screen="vault" />} />
      <Route path="/users/:userId/unlock" element={<UnlockRoute {...props} />} />
      <Route path="/users/:userId/setup" element={<SetupRoute {...props} />} />
      <Route path="/users/:userId/items/:itemId" element={<VaultRoute {...props} screen="vault" />} />
      <Route path="/users/:userId/generator" element={<VaultRoute {...props} screen="generator" />} />
      <Route path="/users/:userId/settings" element={<VaultRoute {...props} screen="settings" />} />
      <Route path="/users/:userId/health" element={<VaultRoute {...props} screen="health" />} />
      <Route path="/users/:userId/confirmations" element={<VaultRoute {...props} screen="confirmations" />} />
      <Route path="*" element={<NotFound onNavigate={onNavigate} onAppearanceChange={onAppearanceChange} />} />
    </Routes>
  )
}
