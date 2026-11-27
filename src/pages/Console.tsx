import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from 'react'
import { Activity, ChevronLeft, ChevronRight, Database, LayoutGrid, ScrollText, Settings, Shield, Smartphone, UserPlus, Users as UsersIcon } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'
import { BackendShell } from '../App'
import { Alert, AlertDescription } from '../components/ui/alert'
import { Button } from '../components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '../components/ui/card'
import { Checkbox } from '../components/ui/checkbox'
import { DropdownMenuItem } from '../components/ui/dropdown-menu'
import { SidebarGroup, SidebarGroupContent, SidebarMenu, SidebarMenuButton, SidebarMenuItem } from '../components/ui/sidebar'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import type { AppearancePreference } from '../features/settings/preferences'
import type { VaultIdentity } from '../client/contracts'
import { AdminApiError, createAdminClient, type AdminClient } from '../client/admin'
import {
  ADMIN_AUDIT_ACTIONS,
  ADMIN_SETTING_FIELDS,
  sanitizeAuditMetadata,
  type AdminAuditResponse,
  type AdminOverviewResponse,
  type AdminPermission,
  type AdminRole,
  type AdminOverviewTrendResponse,
  type AdminSettingKey,
  type AdminUserListItem,
  type AdminSettings,
  type AdminSettingsResponse,
  type AdminSettingsUpdate,
} from '../features/admin/contract'
import { OverviewTrendChart } from '../features/admin/OverviewTrendChart'


/** i18n suffix for each permission key (admin.json `permissions.descriptions.*`). */
const permissionDescriptionKey: Record<string, string> = {
  'overview:read': 'overviewRead',
  'users:read': 'usersRead',
  'users:manage': 'usersManage',
  'settings:manage': 'settingsManage',
  'audit:read': 'auditRead',
  'roles:manage': 'rolesManage',
  'dump:read': 'dumpRead',
}

type AdminSection = 'overview' | 'users' | 'roles' | 'settings' | 'audit'
const Users = lazy(() => import('./Users').then(({ Users: component }) => ({ default: component })))

type AdminTFunction = TFunction<'admin', undefined>

function formatDateTime(value: string | null): string {
  if (value === null) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function formatDefault(value: string | number | boolean | null, t: AdminTFunction) {
  if (value === null) return t('settings.notConfigured')
  if (typeof value === 'boolean') return value ? t('common.yes') : t('common.no')
  return String(value)
}

/** Maps a failed admin request to display copy; the server code is kept so the cause stays visible. */
function errorText(error: unknown, t: AdminTFunction): string {
  if (error instanceof AdminApiError) {
    if (error.code === 'invalid_credentials') return t('dump.wrongPassword')
    if (error.code === 'admin_action_forbidden') return t('users.actionForbidden')
    if (error.message && error.message !== error.code) return `${t('loadFailed')} ${error.message}`
    return `${t('loadFailed')} (${error.code})`
  }
  if (error instanceof Error && error.name === 'AbortError') return ''
  return t('loadFailed')
}

type SettingsDraft = Partial<Record<AdminSettingKey, string | boolean>>

function settingsRecord(settings: AdminSettings): Partial<Record<AdminSettingKey, string | number | boolean | null>> {
  return settings as Partial<Record<AdminSettingKey, string | number | boolean | null>>
}

function draftFromSettings(settings: AdminSettings): SettingsDraft {
  const draft: SettingsDraft = {}
  for (const field of ADMIN_SETTING_FIELDS) {
    if (field.key === 'smtp_pass') continue
    const value = settingsRecord(settings)[field.key]
    if (typeof value === 'boolean') draft[field.key] = value
    else if (value === null || value === undefined) draft[field.key] = ''
    else draft[field.key] = String(value)
  }
  return draft
}

const SEMVER_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/

/**
 * Parses the draft into a PUT body of changed keys only. Returns the key of
 * the first value that fails client-side validation, so the form can name it.
 */
function buildSettingsUpdates(draft: SettingsDraft, current: AdminSettings): { updates: AdminSettingsUpdate; errorKey: AdminSettingKey | null } {
  const updates: AdminSettingsUpdate = {}
  for (const field of ADMIN_SETTING_FIELDS) {
    const raw = draft[field.key]
    if (field.key === 'smtp_pass') {
      if (typeof raw === 'string' && raw !== '') updates.smtp_pass = raw
      continue
    }
    const currentValue = settingsRecord(current)[field.key] ?? null
    let value: string | number | boolean | null
    if (field.kind === 'boolean') {
      value = raw === true
    } else if (typeof raw !== 'string' || raw === '') {
      value = null
    } else if (field.kind === 'integer' || field.kind === 'nullable-integer') {
      if (!/^[0-9]+$/.test(raw)) return { updates, errorKey: field.key }
      value = Number(raw)
    } else {
      value = raw
    }
    if (field.key === 'server_name' && (typeof value !== 'string' || value.trim().length < 1 || [...value.trim()].length > 100)) {
      return { updates, errorKey: field.key }
    }
    if (field.key === 'max_vault_size_mb' && (typeof value !== 'number' || value < 1 || value > 1024)) {
      return { updates, errorKey: field.key }
    }
    if (field.key === 'smtp_port' && value !== null && (typeof value !== 'number' || value < 1 || value > 65535)) {
      return { updates, errorKey: field.key }
    }
    if (field.key === 'smtp_from' && value !== null && (typeof value !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value))) {
      return { updates, errorKey: field.key }
    }
    if (
      (field.key === 'min_app_version_android' || field.key === 'min_app_version_ios' || field.key === 'min_app_version_web') &&
      value !== null && (typeof value !== 'string' || !SEMVER_PATTERN.test(value))
    ) {
      return { updates, errorKey: field.key }
    }
    if (value !== currentValue) updates[field.key] = value
  }
  return { updates, errorKey: null }
}

function sourceLabel(source: string, t: AdminTFunction): string {
  if (source === 'db') return t('settings.sourceDb')
  if (source === 'env') return t('settings.sourceEnv')
  return t('settings.sourceDefault')
}

export function Console({ user, appearancePreference, onNavigate, getAccessToken, refreshAccessToken, currentUserId, onAppearanceChange, onLogout }: {
  user: VaultIdentity
  appearancePreference: AppearancePreference
  onNavigate: (path: string) => void
  getAccessToken: () => string | null
  /** Shared token refresher (the vault adapter's); the admin client calls it on 401. */
  refreshAccessToken: (signal?: AbortSignal) => Promise<string>
  currentUserId: string
  onAppearanceChange: (preference: AppearancePreference) => void
  onLogout: () => void
}) {
  const { t } = useTranslation(['admin', 'common'])
  const [section, setSection] = useState<AdminSection>('overview')
  const sections: AdminSection[] = ['overview', 'users', 'roles', 'settings', 'audit']
  const adminClient: AdminClient = useMemo(() => createAdminClient({ getAccessToken, refreshAccessToken }), [getAccessToken, refreshAccessToken])

  const [myPermissions, setMyPermissions] = useState<readonly string[] | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    let active = true
    void adminClient.getMyPermissions(controller.signal).then(
      (data) => { if (active) setMyPermissions(data.permissions) },
      () => { if (active) setMyPermissions([]) },
    )
    return () => { active = false; controller.abort() }
  }, [adminClient])

  const can = useCallback(
    (key: string) => myPermissions === null ? true : myPermissions.includes(key),
    [myPermissions],
  )
  const visibleSections = sections.filter((item) =>
    item === 'overview' ? can('overview:read')
      : item === 'users' ? can('users:read')
      : item === 'roles' ? can('roles:manage')
      : item === 'settings' ? can('settings:manage')
      : can('audit:read'),
  )

  useEffect(() => {
    if (myPermissions !== null && !visibleSections.includes(section)) {
      setSection(visibleSections[0] ?? 'overview')
    }
  }, [myPermissions, section, visibleSections])

  const [overview, setOverview] = useState<AdminOverviewResponse | null>(null)
  const [overviewError, setOverviewError] = useState('')
  const [overviewLoading, setOverviewLoading] = useState(true)

  useEffect(() => {
    const controller = new AbortController()
    let active = true
    void adminClient.getOverview(controller.signal).then(
      (data) => { if (active) { setOverview(data); setOverviewLoading(false) } },
      (error: unknown) => {
        if (!active) return
        if (!(error instanceof Error && error.name === 'AbortError')) setOverviewError(errorText(error, t))
        setOverviewLoading(false)
      },
    )
    return () => { active = false; controller.abort() }
  }, [adminClient, t])

  const [trend, setTrend] = useState<AdminOverviewTrendResponse | null>(null)
  const [trendError, setTrendError] = useState('')
  const [trendLoading, setTrendLoading] = useState(true)

  useEffect(() => {
    const controller = new AbortController()
    let active = true
    void adminClient.getOverviewTrend(14, controller.signal).then(
      (data) => { if (active) { setTrend(data); setTrendLoading(false) } },
      (error: unknown) => {
        if (!active) return
        if (!(error instanceof Error && error.name === 'AbortError')) setTrendError(errorText(error, t))
        setTrendLoading(false)
      },
    )
    return () => { active = false; controller.abort() }
  }, [adminClient, t])

  const [roles, setRoles] = useState<readonly AdminRole[] | null>(null)
  const [roleCatalog, setRoleCatalog] = useState<readonly AdminPermission[] | null>(null)
  const [rolesLoading, setRolesLoading] = useState(true)
  const [rolesError, setRolesError] = useState('')
  const [rolesMessage, setRolesMessage] = useState('')
  const [editingRole, setEditingRole] = useState<AdminRole | 'new' | null>(null)
  const [editorName, setEditorName] = useState('')
  const [editorDescription, setEditorDescription] = useState('')
  const [editorKeys, setEditorKeys] = useState<readonly string[]>([])
  const [editorSaving, setEditorSaving] = useState(false)
  const [detailRole, setDetailRole] = useState<AdminRole | null>(null)
  const [detailUsers, setDetailUsers] = useState<readonly AdminUserListItem[] | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [detailError, setDetailError] = useState('')
  const [addUserEmail, setAddUserEmail] = useState('')
  const [detailPendingUserId, setDetailPendingUserId] = useState<string | null>(null)
  const [confirmDeleteRole, setConfirmDeleteRole] = useState<AdminRole | null>(null)

  const loadRoles = useCallback(async (signal?: AbortSignal) => {
    setRolesLoading(true)
    setRolesError('')
    try {
      const [rolesResponse, permissionsResponse] = await Promise.all([
        adminClient.listRoles(signal),
        adminClient.listPermissions(signal),
      ])
      setRoles(rolesResponse.roles)
      setRoleCatalog(permissionsResponse.permissions)
      setRolesLoading(false)
    } catch (error: unknown) {
      if (error instanceof Error && error.name === 'AbortError') return
      setRolesError(errorText(error, t))
      setRolesLoading(false)
    }
  }, [adminClient, t])

  useEffect(() => {
    if (section !== 'roles') return
    const controller = new AbortController()
    void loadRoles(controller.signal)
    return () => controller.abort()
  }, [loadRoles, section])

  const openRoleEditor = useCallback((role: AdminRole | 'new') => {
    setEditingRole(role)
    setRolesMessage('')
    if (role === 'new') {
      setEditorName('')
      setEditorDescription('')
      setEditorKeys([])
    } else {
      setEditorName(role.name)
      setEditorDescription(role.description ?? '')
      setEditorKeys(role.permission_keys)
    }
  }, [])

  const saveRoleEditor = useCallback(async (event: FormEvent) => {
    event.preventDefault()
    if (editorSaving || editingRole === null) return
    setEditorSaving(true)
    setRolesMessage('')
    try {
      const description = editorDescription.trim() === '' ? null : editorDescription.trim()
      if (editingRole === 'new') {
        await adminClient.createRole({ name: editorName.trim(), description, permission_keys: editorKeys })
      } else {
        await adminClient.updateRole(editingRole.id, { description, permission_keys: editorKeys })
      }
      setRolesMessage(t('roles.actionDone'))
      setEditingRole(null)
      await loadRoles()
    } catch (error: unknown) {
      setRolesMessage(errorText(error, t))
    } finally {
      setEditorSaving(false)
    }
  }, [adminClient, editorDescription, editorKeys, editorName, editorSaving, editingRole, loadRoles, t])

  const deleteRole = useCallback(async () => {
    if (confirmDeleteRole === null) return
    setRolesMessage('')
    try {
      await adminClient.deleteRole(confirmDeleteRole.id)
      setRolesMessage(t('roles.actionDone'))
      setConfirmDeleteRole(null)
      await loadRoles()
    } catch (error: unknown) {
      setRolesMessage(errorText(error, t))
    }
  }, [adminClient, confirmDeleteRole, loadRoles, t])

  const loadDetailUsers = useCallback(async (role: AdminRole, signal?: AbortSignal) => {
    setDetailLoading(true)
    setDetailError('')
    try {
      const response = await adminClient.listRoleUsers(role.id, null, 100, signal)
      setDetailUsers(response.users)
      setDetailLoading(false)
    } catch (error: unknown) {
      if (error instanceof Error && error.name === 'AbortError') return
      setDetailError(errorText(error, t))
      setDetailLoading(false)
    }
  }, [adminClient, t])

  const openRoleDetail = useCallback((role: AdminRole) => {
    setDetailRole(role)
    setDetailUsers(null)
    setAddUserEmail('')
    void loadDetailUsers(role)
  }, [loadDetailUsers])

  const addRoleUser = useCallback(async (event: FormEvent) => {
    event.preventDefault()
    if (detailRole === null || addUserEmail.trim() === '') return
    setRolesMessage('')
    try {
      const found = await adminClient.listUsers({ search: addUserEmail.trim(), status: 'all', verified: 'all', role: 'all', cursor: null, limit: 1 })
      const target = found.users[0]
      if (!target) {
        setRolesMessage(t('roles.userNotFound'))
        return
      }
      await adminClient.assignRole(detailRole.id, target.id)
      setRolesMessage(t('roles.actionDone'))
      setAddUserEmail('')
      await loadDetailUsers(detailRole)
      await loadRoles()
    } catch (error: unknown) {
      setRolesMessage(errorText(error, t))
    }
  }, [addUserEmail, adminClient, detailRole, loadDetailUsers, loadRoles, t])

  const removeRoleUser = useCallback(async (target: AdminUserListItem) => {
    if (detailRole === null) return
    setDetailPendingUserId(target.id)
    setRolesMessage('')
    try {
      await adminClient.removeRole(detailRole.id, target.id)
      setRolesMessage(t('roles.actionDone'))
      await loadDetailUsers(detailRole)
      await loadRoles()
    } catch (error: unknown) {
      setRolesMessage(errorText(error, t))
    } finally {
      setDetailPendingUserId(null)
    }
  }, [adminClient, detailRole, loadDetailUsers, loadRoles, t])

  const [dumpPassword, setDumpPassword] = useState('')
  const [dumpBusy, setDumpBusy] = useState(false)
  const [dumpMessage, setDumpMessage] = useState('')

  const downloadDump = useCallback(async (event: FormEvent) => {
    event.preventDefault()
    if (dumpBusy || dumpPassword === '') return
    setDumpBusy(true)
    setDumpMessage('')
    try {
      const { filename, blob } = await adminClient.downloadDbDump(dumpPassword)
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = filename
      anchor.click()
      // Revoking synchronously can truncate the download in some browsers;
      // the Settings page already defers this by the same 1000 ms.
      setTimeout(() => URL.revokeObjectURL(url), 1000)
      setDumpPassword('')
      setDumpMessage(t('dump.downloaded', { filename }))
    } catch (error) {
      setDumpMessage(errorText(error, t))
    } finally {
      setDumpBusy(false)
    }
  }, [adminClient, dumpBusy, dumpPassword, t])

  const [settingsResponse, setSettingsResponse] = useState<AdminSettingsResponse | null>(null)
  const [settingsError, setSettingsError] = useState('')
  const [settingsLoading, setSettingsLoading] = useState(true)
  const [settingsDraft, setSettingsDraft] = useState<SettingsDraft>({})
  const [settingsSaving, setSettingsSaving] = useState(false)
  const [settingsMessage, setSettingsMessage] = useState('')
  const settingsLoadedRef = useRef(false)

  useEffect(() => {
    if (section !== 'settings' || settingsLoadedRef.current) return
    const controller = new AbortController()
    let active = true
    void adminClient.getSettings(controller.signal).then(
      (response) => {
        if (!active) return
        setSettingsResponse(response)
        setSettingsDraft(draftFromSettings(response.settings))
        settingsLoadedRef.current = true
        setSettingsLoading(false)
      },
      (error: unknown) => {
        if (!active) return
        if (!(error instanceof Error && error.name === 'AbortError')) setSettingsError(errorText(error, t))
        setSettingsLoading(false)
      },
    )
    return () => { active = false; controller.abort() }
  }, [section, adminClient, t])

  const saveSettings = useCallback(async () => {
    if (!settingsResponse || settingsSaving) return
    const { updates, errorKey } = buildSettingsUpdates(settingsDraft, settingsResponse.settings)
    if (errorKey) {
      setSettingsMessage(t('settings.invalidValue', { key: errorKey }))
      return
    }
    if (Object.keys(updates).length === 0) {
      setSettingsMessage(t('settings.saved'))
      return
    }
    setSettingsSaving(true)
    setSettingsMessage('')
    try {
      const response = await adminClient.updateSettings(updates)
      setSettingsResponse(response)
      setSettingsDraft(draftFromSettings(response.settings))
      setSettingsMessage(t('settings.saved'))
    } catch (error) {
      setSettingsMessage(errorText(error, t))
    } finally {
      setSettingsSaving(false)
    }
  }, [adminClient, settingsDraft, settingsResponse, settingsSaving, t])

  const clearSetting = useCallback(async (key: AdminSettingKey) => {
    if (settingsSaving) return
    setSettingsSaving(true)
    setSettingsMessage('')
    try {
      const response = await adminClient.updateSettings({ [key]: null })
      setSettingsResponse(response)
      setSettingsDraft(draftFromSettings(response.settings))
      setSettingsMessage(t('settings.saved'))
    } catch (error) {
      setSettingsMessage(errorText(error, t))
    } finally {
      setSettingsSaving(false)
    }
  }, [adminClient, settingsSaving, t])

  const [auditFilters, setAuditFilters] = useState({ actor: '', target: '', action: '', from: '', to: '' })
  const [auditDraft, setAuditDraft] = useState(auditFilters)
  const [auditPage, setAuditPage] = useState<AdminAuditResponse | null>(null)
  const [auditError, setAuditError] = useState('')
  const [auditLoading, setAuditLoading] = useState(true)
  const [auditCursorStack, setAuditCursorStack] = useState<(string | null)[]>([null])
  const auditLoadedRef = useRef(false)

  const loadAudit = useCallback(async (cursor: string | null, filters: typeof auditFilters, signal?: AbortSignal) => {
    setAuditLoading(true)
    setAuditError('')
    try {
      setAuditPage(await adminClient.listAudit({
        actorUserId: filters.actor.trim() || undefined,
        targetUserId: filters.target.trim() || undefined,
        action: filters.action || undefined,
        from: filters.from ? new Date(filters.from).toISOString() : undefined,
        to: filters.to ? new Date(filters.to).toISOString() : undefined,
        cursor,
        limit: 100,
      }, signal))
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') return
      setAuditError(errorText(error, t))
    } finally {
      setAuditLoading(false)
    }
  }, [adminClient, t])

  useEffect(() => {
    if (section !== 'audit' || auditLoadedRef.current) return
    const controller = new AbortController()
    let active = true
    void adminClient.listAudit({ cursor: null, limit: 100 }, controller.signal).then(
      (page) => {
        if (!active) return
        setAuditPage(page)
        auditLoadedRef.current = true
        setAuditLoading(false)
      },
      (error: unknown) => {
        if (!active) return
        if (!(error instanceof Error && error.name === 'AbortError')) setAuditError(errorText(error, t))
        setAuditLoading(false)
      },
    )
    return () => { active = false; controller.abort() }
  }, [section, adminClient, t])

  const applyAuditFilters = useCallback(() => {
    setAuditFilters(auditDraft)
    setAuditCursorStack([null])
    void loadAudit(null, auditDraft)
  }, [auditDraft, loadAudit])

  const auditNextPage = useCallback(() => {
    if (!auditPage?.has_more || !auditPage.next_cursor) return
    const nextStack = [...auditCursorStack, auditPage.next_cursor]
    setAuditCursorStack(nextStack)
    void loadAudit(auditPage.next_cursor, auditFilters)
  }, [auditCursorStack, auditFilters, auditPage, loadAudit])

  const auditPreviousPage = useCallback(() => {
    if (auditCursorStack.length < 2) return
    const nextStack = auditCursorStack.slice(0, -1)
    setAuditCursorStack(nextStack)
    void loadAudit(nextStack[nextStack.length - 1] ?? null, auditFilters)
  }, [auditCursorStack, auditFilters, loadAudit])

  const renderOverview = () => {
    const metrics: [string, string, string, string, typeof UsersIcon][] = [
      ['totalUsers', t('overview.totalUsers'), t('overview.allTime'), overview === null ? '—' : String(overview.total_users), UsersIcon],
      ['todayNewUsers', t('overview.todayNewUsers'), t('overview.utcDay'), overview === null ? '—' : String(overview.today_new_users), UserPlus],
      ['todayActiveUsers', t('overview.todayActiveUsers'), t('overview.utcDay'), overview === null ? '—' : String(overview.today_active_users), Activity],
      ['totalDevices', t('overview.totalDevices'), t('overview.allDevices'), overview === null ? '—' : String(overview.total_devices), Smartphone],
      ['databaseConnections', t('overview.databaseConnections'), t('overview.livePool'), overview === null ? '—' : String(overview.db_connections), Database],
    ]
    return (
      <>
        {overviewError ? <Alert variant="destructive"><AlertDescription>{overviewError}</AlertDescription></Alert> : null}

        <section className="grid grid-cols-5 gap-4 max-[1100px]:grid-cols-3 max-[760px]:grid-cols-2" aria-label={t('overview.metricsLabel')}>
          {metrics.map(([key, label, detail, value, Icon]) => (
            <Card className="gap-0 p-4" key={key}>
              <div className="flex w-full items-start justify-between gap-2">
                <span className="text-xs font-medium leading-snug text-muted-foreground">{label}</span>
                <Icon className="size-5 shrink-0 text-muted-foreground" aria-hidden="true" />
              </div>
              <strong className="mt-4 text-3xl font-semibold tabular-nums tracking-tight text-foreground">{overviewLoading && overview === null ? t('loading') : value}</strong>
              <span className="mt-1 text-xs text-muted-foreground">{detail}</span>
            </Card>
          ))}
        </section>

        <Card className="mt-4">
          <CardHeader>
            <CardTitle id="admin-trend-title">{t('overview.trendTitle')}</CardTitle>
          </CardHeader>
          <CardContent>
            {trendError ? <Alert variant="destructive"><AlertDescription>{trendError}</AlertDescription></Alert>
              : trendLoading && trend === null ? <p className="text-xs text-muted-foreground">{t('loading')}</p>
              : trend === null ? null
              : <OverviewTrendChart days={trend.days} newUsersLabel={t('overview.trendNewUsers')} activeUsersLabel={t('overview.trendActiveUsers')} />}
          </CardContent>
        </Card>

        <Card className="mt-4">
          <CardHeader>
            <CardTitle id="admin-cleanup-title">{t('overview.cleanupTitle')}</CardTitle>
            <CardAction><span className="mt-1 size-2 shrink-0 rounded-full bg-amber-500" aria-hidden="true" /></CardAction>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-3 max-[430px]:grid-cols-1">
              <div className="flex items-center justify-between gap-2 rounded-lg bg-muted px-3 py-2.5"><span className="text-xs text-muted-foreground">{t('overview.lastCleanup')}</span><strong className="text-xs font-medium text-muted-foreground">{overview === null ? '—' : formatDateTime(overview.tombstone_cleanup.last_cleanup_at)}</strong></div>
              <div className="flex items-center justify-between gap-2 rounded-lg bg-muted px-3 py-2.5"><span className="text-xs text-muted-foreground">{t('overview.cleanupStatus')}</span><strong className="text-xs font-medium text-muted-foreground">{overview === null ? '—' : overview.tombstone_cleanup.last_cleanup_status === 'success' ? t('overview.cleanupSuccess') : overview.tombstone_cleanup.last_cleanup_status === 'failed' ? t('overview.cleanupFailed') : t('overview.cleanupNever')}</strong></div>
            </div>
          </CardContent>
        </Card>

        <Card className="mt-4">
          <CardHeader>
            <CardDescription className="text-xs font-bold uppercase tracking-widest">{t('dump.eyebrow')}</CardDescription>
            <CardTitle id="admin-dump-title">{t('dump.title')}</CardTitle>
            <CardAction><Database className="size-5 text-muted-foreground" aria-hidden="true" /></CardAction>
          </CardHeader>
          <CardContent>
            <form className="grid grid-cols-[minmax(0,1fr)_auto] items-end gap-3 max-[430px]:grid-cols-1" onSubmit={(event) => void downloadDump(event)}>
              <div className="grid gap-1.5">
                <Label htmlFor="admin-dump-password">{t('dump.passwordLabel')}</Label>
                <Input id="admin-dump-password" type="password" autoComplete="current-password" value={dumpPassword} onChange={(event) => setDumpPassword(event.target.value)} disabled={dumpBusy} placeholder={t('dump.passwordLabel')} />
              </div>
              <Button type="submit" disabled={dumpBusy || dumpPassword === ''} variant={dumpBusy || dumpPassword === '' ? 'outline' : 'default'} className="max-[430px]:w-full">{dumpBusy ? t('dump.downloading') : t('dump.download')}</Button>
            </form>
            {dumpMessage ? <p className="mt-2 text-xs leading-relaxed text-muted-foreground" role="status">{dumpMessage}</p> : <p className="mt-2 text-xs leading-relaxed text-muted-foreground">{t('dump.loginPasswordNote')}</p>}
          </CardContent>
        </Card>
      </>
    )
  }

  const renderSettings = () => (
    <>
      {settingsError ? <Alert variant="destructive"><AlertDescription>{settingsError}</AlertDescription></Alert> : null}
      {settingsLoading && settingsResponse === null ? <p className="mt-2 text-xs leading-relaxed text-muted-foreground" role="status">{t('loading')}</p> : null}

      {settingsResponse === null ? null : (
        <Card className="mt-4">
          <CardContent>
            {ADMIN_SETTING_FIELDS.map((field) => {
              const source = settingsResponse.sources[field.key]
              const draftValue = settingsDraft[field.key]
              return (
                <article className="grid min-h-24 grid-cols-[minmax(150px,0.9fr)_minmax(190px,1.2fr)_auto] items-center gap-4 py-3 max-[760px]:grid-cols-[minmax(0,1fr)_auto] max-[760px]:gap-2.5" key={field.key}>
                  <div>
                    <h2 className="text-xs font-semibold text-foreground">{t(`fields.${field.key}`)}</h2>
                    <code className="mt-1 inline-block font-mono text-xs text-muted-foreground">{field.key}</code>
                    <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{t(field.constraintKey)}</p>
                  </div>
                  <div className="grid justify-items-start gap-1 max-[760px]:col-[1/2] max-[760px]:row-[2]">
                    {field.key === 'smtp_pass' ? (
                      <Input
                        type="password"
                        autoComplete="new-password"
                        value={typeof draftValue === 'string' ? draftValue : ''}
                        onChange={(event) => setSettingsDraft((prev) => ({ ...prev, smtp_pass: event.target.value }))}
                        placeholder={t('settings.writeOnly')}
                        aria-label={t(`fields.${field.key}`)}
                      />
                    ) : field.kind === 'boolean' ? (
                      <Select
                        value={draftValue === true ? 'true' : 'false'}
                        onValueChange={(value) => setSettingsDraft((prev) => ({ ...prev, [field.key]: value === 'true' }))}
                      >
                        <SelectTrigger aria-label={t(`fields.${field.key}`)}>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="true">{t('common.yes')}</SelectItem>
                          <SelectItem value="false">{t('common.no')}</SelectItem>
                        </SelectContent>
                      </Select>
                    ) : (
                      <Input
                        type="text"
                        inputMode={field.kind === 'integer' || field.kind === 'nullable-integer' ? 'numeric' : 'text'}
                        value={typeof draftValue === 'string' ? draftValue : ''}
                        onChange={(event) => setSettingsDraft((prev) => ({ ...prev, [field.key]: event.target.value }))}
                        aria-label={t(`fields.${field.key}`)}
                      />
                    )}
                    <span className="text-xs leading-relaxed text-muted-foreground">{sourceLabel(source, t)}</span>
                    <span className="text-xs leading-relaxed text-muted-foreground">
                      {t('settings.builtInDefault', { value: formatDefault(field.defaultValue, t) })}
                    </span>
                  </div>
                  <Button variant="outline" size="sm" type="button" disabled={settingsSaving} onClick={() => void clearSetting(field.key)} aria-label={`${t('settings.clearOverride')} ${field.key}`}>
                    {t('settings.clearOverride')}
                  </Button>
                </article>
              )
            })}
          </CardContent>
          <CardFooter className="justify-between gap-4 max-[430px]:flex-col max-[430px]:items-start">
            {settingsMessage ? <p className="text-xs leading-relaxed text-muted-foreground">{settingsMessage}</p> : <span />}
            <Button type="button" disabled={settingsSaving} onClick={() => void saveSettings()} variant={settingsSaving ? 'outline' : 'default'}>{settingsSaving ? t('loading') : t('settings.saveChanges')}</Button>
          </CardFooter>
        </Card>
      )}

      <Card className="mt-4">
        <CardContent className="flex flex-wrap items-center justify-between gap-4">
          <CardTitle id="admin-retention-title">{t('settings.tombstoneRetention')}</CardTitle>
          <strong className="ml-auto whitespace-nowrap text-sm font-semibold text-muted-foreground max-[760px]:ml-0">30 {t('settings.days')}</strong>
          <span className="whitespace-nowrap text-xs text-muted-foreground">{t('settings.fixedReadOnly')}</span>
        </CardContent>
      </Card>
      <Card className="mt-4">
        <CardContent className="flex flex-wrap items-center justify-between gap-4">
          <CardTitle id="admin-smtp-title">{t('settings.smtpPasswordStatus')}</CardTitle>
          <strong className="text-xs font-medium">{settingsResponse === null ? '—' : settingsResponse.smtp_pass_configured ? t('settings.smtpConfigured') : t('settings.smtpNotConfigured')}</strong>
        </CardContent>
      </Card>
    </>
  )

  const renderAudit = () => (
    <>
      {auditError ? <Alert variant="destructive"><AlertDescription>{auditError}</AlertDescription></Alert> : null}

      <Card className="mt-4">
        <CardContent className="space-y-4">
          <div className="grid grid-cols-[repeat(5,minmax(100px,1fr))_auto] items-end gap-2.5 max-[1100px]:grid-cols-[repeat(3,minmax(120px,1fr))] max-[760px]:grid-cols-2 max-[430px]:grid-cols-1">
          <div className="grid gap-1.5">
            <Label>{t('audit.actorFilter')}</Label>
            <Input type="text" value={auditDraft.actor} onChange={(event) => setAuditDraft((prev) => ({ ...prev, actor: event.target.value }))} placeholder={t('audit.uuidPlaceholder')} />
          </div>
          <div className="grid gap-1.5">
            <Label>{t('audit.targetFilter')}</Label>
            <Input type="text" value={auditDraft.target} onChange={(event) => setAuditDraft((prev) => ({ ...prev, target: event.target.value }))} placeholder={t('audit.uuidPlaceholder')} />
          </div>
          <div className="grid gap-1.5">
            <Label>{t('audit.actionFilter')}</Label>
            <Select value={auditDraft.action === '' ? '__all__' : auditDraft.action} onValueChange={(value) => setAuditDraft((prev) => ({ ...prev, action: value === '__all__' ? '' : value }))}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="__all__">{t('audit.allActions')}</SelectItem>{ADMIN_AUDIT_ACTIONS.map((action) => <SelectItem key={action} value={action}>{action}</SelectItem>)}</SelectContent></Select>
          </div>
          <div className="grid gap-1.5">
            <Label>{t('audit.fromFilter')}</Label>
            <Input type="datetime-local" value={auditDraft.from} onChange={(event) => setAuditDraft((prev) => ({ ...prev, from: event.target.value }))} />
          </div>
          <div className="grid gap-1.5">
            <Label>{t('audit.toFilter')}</Label>
            <Input type="datetime-local" value={auditDraft.to} onChange={(event) => setAuditDraft((prev) => ({ ...prev, to: event.target.value }))} />
          </div>
          <Button type="button" disabled={auditLoading} onClick={applyAuditFilters} variant="outline" className="max-[760px]:col-span-full max-[430px]:col-auto">{t('audit.applyFilters')}</Button>
        </div>
          <div className="overflow-x-auto">
            <Table>
            <TableHeader><TableRow>
              <TableHead scope="col">{t('audit.time')}</TableHead>
              <TableHead scope="col">{t('audit.actor')}</TableHead>
              <TableHead scope="col">{t('audit.target')}</TableHead>
              <TableHead scope="col">{t('audit.action')}</TableHead>
              <TableHead scope="col">{t('audit.metadata')}</TableHead>
            </TableRow></TableHeader>
            <TableBody>
              {auditLoading && auditPage === null ? (
                <TableRow><TableCell colSpan={5} className="h-[110px] whitespace-normal break-anywhere px-[11px] py-3 text-center text-[12px] text-muted-foreground">{t('loading')}</TableCell></TableRow>
              ) : auditPage !== null && auditPage.items.length > 0 ? auditPage.items.map((row) => (
                <TableRow key={row.id}>
                  <TableCell className="whitespace-nowrap px-2 py-3 text-xs text-muted-foreground">{formatDateTime(row.created_at)}</TableCell>
                  <TableCell className="whitespace-normal break-all px-2 py-3 text-xs text-muted-foreground">{row.actor_user_id ?? '—'}</TableCell>
                  <TableCell className="whitespace-normal break-all px-2 py-3 text-xs text-muted-foreground">{row.target_user_id ?? '—'}</TableCell>
                  <TableCell className="whitespace-nowrap px-2 py-3 text-xs text-muted-foreground">{row.action}</TableCell>
                  <TableCell className="whitespace-normal break-all px-2 py-3 text-xs text-muted-foreground">{JSON.stringify(sanitizeAuditMetadata(row.action, row.metadata))}</TableCell>
                </TableRow>
              )) : (
                <TableRow><TableCell colSpan={5} className="h-[110px] whitespace-normal break-anywhere px-[11px] py-3 text-center text-[12px] text-muted-foreground">{t('audit.noRows')}</TableCell></TableRow>
              )}
            </TableBody>
          </Table>
        </div>
          <div className="flex items-center justify-between gap-3 text-xs leading-relaxed text-muted-foreground max-[430px]:flex-col max-[430px]:items-start">
            <span>{t('audit.metadataPolicy')}</span>
            <div className="flex items-center gap-2">
            <Button type="button" disabled={auditCursorStack.length < 2 || auditLoading} onClick={auditPreviousPage} aria-label={t('audit.previousPage')} variant="outline" size="icon" className="size-7">‹</Button>
            <span>{auditPage === null ? '—' : `${t('audit.totalCount', { count: auditPage.total_count })}`}</span>
            <Button type="button" disabled={!auditPage?.has_more || auditLoading} onClick={auditNextPage} aria-label={t('audit.nextPage')} variant="outline" size="icon" className="size-7"><ChevronRight size={16} aria-hidden="true" /></Button>
          </div>
          </div>
        </CardContent>
      </Card>
      <p className="mt-3 text-xs leading-relaxed text-muted-foreground">{t('audit.sensitiveDataWarning')}</p>
    </>
  )

  const renderRoleEditor = () => {
    const role = editingRole
    if (role === null) return null
    const isNew = role === 'new'
    const isSuperAdmin = role !== 'new' && role.name === 'super_admin'
    const moduleOrder = ['overview', 'users', 'settings', 'audit', 'roles', 'dump']
    const grouped = moduleOrder
      .map((module) => ({ module, permissions: (roleCatalog ?? []).filter((permission) => permission.module === module) }))
      .filter((group) => group.permissions.length > 0)
    const toggleKey = (key: string) => {
      setEditorKeys((current) => current.includes(key) ? current.filter((item) => item !== key) : [...current, key])
    }
    return (
      <>
        {rolesMessage ? <Alert><AlertDescription>{rolesMessage}</AlertDescription></Alert> : null}
        <form onSubmit={(event) => void saveRoleEditor(event)}>
          <Button type="button" onClick={() => setEditingRole(null)} variant="outline">
            <ChevronLeft size={16} aria-hidden="true" /> {t('roles.backToList')}
          </Button>
          <Card className="mt-4">
            <CardHeader>
              <CardTitle id="admin-role-editor-title">
                {isNew ? t('roles.newRole') : isSuperAdmin ? t('roles.viewRole') : t('roles.editRole')}
              </CardTitle>
            </CardHeader>
            <CardContent className="grid gap-4">
              <div className="grid gap-1.5">
                <Label>{t('roles.nameLabel')}</Label>
                {isNew ? (
                  <Input value={editorName} onChange={(event) => setEditorName(event.target.value)} placeholder={t('roles.namePlaceholder')} required />
                ) : (
                  <span className="text-xs font-medium text-foreground">{editorName}</span>
                )}
              </div>
              <div className="grid gap-1.5">
                <Label>{t('roles.descriptionLabel')}</Label>
                <Input value={editorDescription} onChange={(event) => setEditorDescription(event.target.value)} placeholder={t('roles.descriptionPlaceholder')} disabled={isSuperAdmin} />
              </div>
              <div className="grid gap-2.5">
                <span className="text-xs font-medium text-muted-foreground">{t('roles.permissionsLabel')}</span>
                {grouped.map(({ module, permissions }) => (
                  <div key={module}>
                    <p className="mb-2 text-xs font-semibold text-foreground">{t(`permissions.modules.${module}`)}</p>
                    <div className="grid gap-2">
                      {permissions.map((permission) => (
                        <Label key={permission.key} className="flex cursor-pointer items-start gap-2 text-xs leading-relaxed font-normal text-muted-foreground">
                          <Checkbox checked={editorKeys.includes(permission.key)} disabled={isSuperAdmin} onCheckedChange={() => toggleKey(permission.key)} className="mt-0.5" />
                          <span>
                            <code className="text-foreground">{permission.key}</code>
                            {' — '}
                            {t(`permissions.descriptions.${permissionDescriptionKey[permission.key] ?? 'overviewRead'}`)}
                          </span>
                        </Label>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
            {!isSuperAdmin ? (
              <CardFooter className="gap-2">
                <Button type="submit" disabled={editorSaving || (isNew && editorName.trim() === '')}>
                  {isNew ? t('roles.createRole') : t('roles.saveRole')}
                </Button>
                <Button type="button" onClick={() => setEditingRole(null)} variant="outline">{t('common:cancel')}</Button>
              </CardFooter>
            ) : null}
          </Card>
        </form>
      </>
    )
  }

  const renderRoleDetail = () => {
    const role = detailRole
    if (role === null) return null
    const isSuperAdmin = role.name === 'super_admin'
    return (
      <>
        {rolesMessage ? <Alert><AlertDescription>{rolesMessage}</AlertDescription></Alert> : null}
        {detailError ? <Alert variant="destructive"><AlertDescription>{detailError}</AlertDescription></Alert> : null}
        <Button type="button" onClick={() => { setDetailRole(null); setDetailUsers(null) }} variant="outline">
          <ChevronLeft size={16} aria-hidden="true" /> {t('roles.backToList')}
        </Button>
        <Card className="mt-4">
          <CardHeader>
            <CardTitle id="admin-role-users-title">{t('roles.roleUsers')} · {role.name}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {!isSuperAdmin ? (
              <form onSubmit={(event) => void addRoleUser(event)} className="flex items-center gap-2">
                <Input value={addUserEmail} onChange={(event) => setAddUserEmail(event.target.value)} placeholder={t('roles.addUserPlaceholder')} type="email" required />
                <Button type="submit" variant="outline">{t('roles.addUser')}</Button>
              </form>
            ) : null}
            <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('users.columns.email')}</TableHead>
                  <TableHead>{t('users.columns.created_at')}</TableHead>
                  <TableHead>{t('roles.tableActions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {detailLoading && detailUsers === null ? (
                  <TableRow><TableCell colSpan={3} className="h-[92px] px-2.5 py-3 text-center text-[12px] text-muted-foreground">{t('loading')}</TableCell></TableRow>
                ) : detailUsers !== null && detailUsers.length === 0 ? (
                  <TableRow><TableCell colSpan={3} className="h-[92px] px-2.5 py-3 text-center text-[12px] text-muted-foreground">{t('roles.empty')}</TableCell></TableRow>
                ) : (detailUsers ?? []).map((target) => (
                  <TableRow key={target.id}>
                    <TableCell className="whitespace-normal break-all px-2 py-3 text-xs">{target.email}</TableCell>
                    <TableCell className="whitespace-nowrap px-2 py-3 text-xs text-muted-foreground">{formatDateTime(target.created_at)}</TableCell>
                    <TableCell className="whitespace-nowrap px-2 py-3 text-xs text-muted-foreground">
                      {isSuperAdmin ? (
                        <span className="text-xs text-muted-foreground">{t('roles.unchangeable')}</span>
                      ) : (
                        <Button type="button" disabled={detailPendingUserId !== null || target.id === currentUserId} onClick={() => void removeRoleUser(target)} variant="outline">{t('roles.removeUser')}</Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
            {detailUsers !== null && detailUsers.length >= 100 ? <p className="text-xs leading-relaxed text-muted-foreground">{t('roles.showsFirst', { count: detailUsers.length })}</p> : null}
          </CardContent>
        </Card>
      </>
    )
  }

  const renderRoles = () => {
    if (editingRole !== null) return renderRoleEditor()
    if (detailRole !== null) return renderRoleDetail()
    return (
      <>
        {rolesError ? <Alert variant="destructive"><AlertDescription>{rolesError}</AlertDescription></Alert> : null}
        {rolesMessage ? <Alert><AlertDescription>{rolesMessage}</AlertDescription></Alert> : null}
        {confirmDeleteRole !== null ? (
          <Alert variant="destructive">
            <AlertDescription>{t('roles.confirmDelete', { name: confirmDeleteRole.name })}</AlertDescription>
            <div className="mt-2 flex gap-2">
              <Button type="button" onClick={() => void deleteRole()} variant="destructive" size="sm">{t('roles.confirmDeleteButton')}</Button>
              <Button type="button" onClick={() => setConfirmDeleteRole(null)} variant="outline" size="sm">{t('common:cancel')}</Button>
            </div>
          </Alert>
        ) : null}
        <Card className="mt-4">
          <CardHeader>
            <CardTitle id="admin-roles-title">{t('roles.title')}</CardTitle>
            <CardAction><Button type="button" onClick={() => openRoleEditor('new')} variant="outline">{t('roles.newRole')}</Button></CardAction>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('roles.tableRole')}</TableHead>
                  <TableHead>{t('roles.tableUsers')}</TableHead>
                  <TableHead>{t('roles.tablePermissions')}</TableHead>
                  <TableHead>{t('roles.tableActions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rolesLoading && roles === null ? (
                  <TableRow><TableCell colSpan={4} className="h-[92px] px-2.5 py-3 text-center text-[12px] text-muted-foreground">{t('loading')}</TableCell></TableRow>
                ) : roles !== null && roles.length === 0 ? (
                  <TableRow><TableCell colSpan={4} className="h-[92px] px-2.5 py-3 text-center text-[12px] text-muted-foreground">{t('roles.empty')}</TableCell></TableRow>
                ) : (roles ?? []).map((role) => (
                  <TableRow key={role.id}>
                    <TableCell className="whitespace-normal break-all px-2 py-3 text-xs">
                      <span className="font-medium">{role.name}</span>
                      {role.description ? <span className="block text-muted-foreground">{role.description}</span> : null}
                    </TableCell>
                    <TableCell className="whitespace-nowrap px-2 py-3 text-xs tabular-nums text-muted-foreground">{role.user_count}</TableCell>
                    <TableCell className="whitespace-normal break-all px-2 py-3 text-xs text-muted-foreground">
                      {role.name === 'super_admin' ? t('roles.allPermissions')
                        : role.permission_keys.length === 0 ? t('roles.noPermissions')
                        : t('roles.permissionCount', { count: role.permission_keys.length })}
                    </TableCell>
                    <TableCell className="whitespace-nowrap px-2 py-3 text-xs text-muted-foreground">
                      <div className="flex gap-2">
                        <Button type="button" onClick={() => openRoleDetail(role)} variant="outline">{t('roles.roleUsers')}</Button>
                        <Button type="button" onClick={() => openRoleEditor(role)} variant="outline">{role.name === 'super_admin' ? t('roles.viewRole') : t('roles.editRole')}</Button>
                        {!role.is_system ? (
                          <Button type="button" onClick={() => setConfirmDeleteRole(role)} variant="outline">{t('roles.deleteRole')}</Button>
                        ) : null}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </>
    )
  }

  return (
    <BackendShell
      user={user}
      onLogout={onLogout}
      title={section === 'overview' ? t('overview.title') : section === 'users' ? t('users.title') : section === 'roles' ? t('roles.title') : section === 'settings' ? t('settings.title') : t('audit.title')}
      appearancePreference={appearancePreference}
      onAppearanceChange={onAppearanceChange}
      nav={
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              {visibleSections.map((item) => (
                <SidebarMenuItem key={item}>
                  <SidebarMenuButton isActive={section === item} tooltip={t(`navigation.${item}`)} onClick={() => setSection(item)}>
                    {item === 'overview' ? <LayoutGrid /> : item === 'users' ? <UsersIcon /> : item === 'roles' ? <Shield /> : item === 'settings' ? <Settings /> : <ScrollText />}
                    <span>{t(`navigation.${item}`)}</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      }
      menu={() => (<>
        <DropdownMenuItem onClick={() => onNavigate(`/users/${user.id}`)}>
          <LayoutGrid className="size-4" aria-hidden="true" />
          <span>{t('header.backToVault')}</span>
        </DropdownMenuItem>
      </>)}
    >
      <div className="min-w-0 px-[clamp(20px,4vw,54px)] pb-[26px] pt-[34px] max-[760px]:px-4 max-[760px]:pb-5 max-[760px]:pt-6">
        {section === 'overview' ? renderOverview() : section === 'users' ? <Suspense fallback={<p className="inline-flex items-center rounded-[5px] bg-muted px-1.5 py-[3px] text-[12px] font-[550] text-muted-foreground" role="status">{t('loading')}</p>}><Users adminClient={adminClient} currentUserId={currentUserId} /></Suspense> : section === 'roles' ? renderRoles() : section === 'settings' ? renderSettings() : renderAudit()}
      </div>
    </BackendShell>
  )
}
