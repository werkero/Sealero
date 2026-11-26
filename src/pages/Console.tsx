import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from 'react'
import { ChevronRight, Database, LayoutGrid, ScrollText, Settings, Users as UsersIcon } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'
import { Brand } from '../components/Brand'
import { LanguageSelector } from '../components/LanguageSelector'
import { AdminApiError, createAdminClient, type AdminClient } from '../client/admin'
import {
  ADMIN_AUDIT_ACTIONS,
  ADMIN_SETTING_FIELDS,
  sanitizeAuditMetadata,
  type AdminAuditResponse,
  type AdminOverviewResponse,
  type AdminSettingKey,
  type AdminSettings,
  type AdminSettingsResponse,
  type AdminSettingsUpdate,
} from '../features/admin/contract'

const pill = 'inline-flex items-center whitespace-nowrap rounded-full border border-[#e4e9f2] bg-[#f5f7fb] px-2.5 py-1.5 text-[10px] font-[650] text-[#5c6f8e]'
const panel = 'mt-[17px] min-w-0 rounded-xl border border-[#e8ebef] bg-white p-[19px] shadow-[0_4px_14px_rgb(28_39_58/3%)] max-[760px]:p-[15px]'
const panelTitle = 'm-0 text-sm font-[640] text-[#303947]'
const panelDesc = 'mt-1.5 text-[10px] leading-[1.6] text-[#7c8795]'
const actionButton = 'min-h-[38px] rounded-[7px] border border-[#dfe3e9] bg-[#f5f6f8] px-[13px] text-[10px] font-semibold text-[#929aa5] disabled:cursor-not-allowed disabled:opacity-76'
const enabledButton = 'min-h-[38px] cursor-pointer rounded-[7px] border border-[#c8d6ee] bg-[#eef3fb] px-[13px] text-[10px] font-semibold text-[#33507e] hover:bg-[#e3ecf9] disabled:cursor-not-allowed disabled:opacity-60'
const filterInput = 'min-h-[35px] w-full min-w-0 rounded-[7px] border border-[#e4e7eb] bg-[#f9fafb] px-[7px] text-[9px] text-[#7d8794] disabled:cursor-not-allowed disabled:opacity-76'
const filterLabel = 'grid gap-[5px] text-[9px] font-[570] text-[#687381]'
const pagerButton = 'h-[27px] w-[27px] rounded-md border border-[#e7eaee] bg-[#f8f9fa] text-[#9aa2ac] disabled:cursor-not-allowed'
const auditTh = 'whitespace-nowrap border-b border-[#edf0f3] bg-[#fafbfc] px-[11px] py-2.5 text-[9px] font-[630] text-[#7d8794]'
const noteBox = 'flex flex-col gap-1 rounded-lg border border-[#e8edf4] bg-[#f8fafd] p-3 text-[10px] leading-[1.55] text-[#586a83]'
const statusText = 'mt-[9px] text-[9px] leading-[1.55] text-[#8d96a2]'

type AdminSection = 'overview' | 'users' | 'settings' | 'audit'
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

function navLink(active: boolean) {
  return active
    ? 'flex min-h-[42px] cursor-pointer items-center gap-[11px] rounded-lg border border-[#e8edf5] bg-[#f3f6fb] px-[11px] text-left text-xs font-[650] text-[#30486f] max-[760px]:flex-col max-[760px]:justify-center max-[760px]:gap-0.5 max-[760px]:px-1.5 max-[760px]:text-[9px]'
    : 'flex min-h-[42px] cursor-pointer items-center gap-[11px] rounded-lg border border-transparent bg-transparent px-[11px] text-left text-xs font-[560] text-[#5f6977] hover:bg-[#f7f9fc] hover:text-[#34435c] max-[760px]:flex-col max-[760px]:justify-center max-[760px]:gap-0.5 max-[760px]:px-1.5 max-[760px]:text-[9px]'
}

function navIcon(active: boolean) {
  return active
    ? 'w-[18px] text-center text-[15px] text-[#4b6da4] max-[760px]:w-auto max-[760px]:text-[13px]'
    : 'w-[18px] text-center text-[15px] text-[#8794a7] max-[760px]:w-auto max-[760px]:text-[13px]'
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

export function Console({ onNavigate, getAccessToken, refreshAccessToken, currentUserId }: {
  onNavigate: (path: string) => void
  getAccessToken: () => string | null
  /** Shared token refresher (the vault adapter's); the admin client calls it on 401. */
  refreshAccessToken: (signal?: AbortSignal) => Promise<string>
  currentUserId: string
}) {
  const { t } = useTranslation('admin')
  const [section, setSection] = useState<AdminSection>('overview')
  const sections: AdminSection[] = ['overview', 'users', 'settings', 'audit']
  const adminClient: AdminClient = useMemo(() => createAdminClient({ getAccessToken, refreshAccessToken }), [getAccessToken, refreshAccessToken])

  const [overview, setOverview] = useState<AdminOverviewResponse | null>(null)
  const [overviewError, setOverviewError] = useState('')
  const [overviewLoading, setOverviewLoading] = useState(true)

  const loadOverview = useCallback(async (signal?: AbortSignal) => {
    setOverviewLoading(true)
    setOverviewError('')
    try {
      setOverview(await adminClient.getOverview(signal))
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') return
      setOverviewError(errorText(error, t))
    } finally {
      setOverviewLoading(false)
    }
  }, [adminClient, t])

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
    const metrics: [string, string, string, string][] = [
      ['totalUsers', t('overview.totalUsers'), t('overview.allTime'), overview === null ? '—' : String(overview.total_users)],
      ['todayNewUsers', t('overview.todayNewUsers'), t('overview.utcDay'), overview === null ? '—' : String(overview.today_new_users)],
      ['todayActiveUsers', t('overview.todayActiveUsers'), t('overview.utcDay'), overview === null ? '—' : String(overview.today_active_users)],
      ['totalDevices', t('overview.totalDevices'), t('overview.allDevices'), overview === null ? '—' : String(overview.total_devices)],
      ['databaseConnections', t('overview.databaseConnections'), t('overview.livePool'), overview === null ? '—' : String(overview.db_connections)],
    ]
    return (
      <>
        <div className="mb-[25px] flex items-start justify-between gap-[18px] max-[430px]:flex-col max-[430px]:gap-2.5">
          <div>
            <p className="m-0 mb-2 text-[9px] font-bold uppercase tracking-[0.1em] text-[#8a93a0]">{t('overview.eyebrow')}</p>
            <h1 className="m-0 text-[clamp(23px,3vw,29px)] font-[650] tracking-[-0.04em] text-[#202631]">{t('overview.title')}</h1>
            <p className="mt-2 max-w-[690px] text-xs leading-[1.6] text-[#798391]">{t('overview.description')}</p>
          </div>
          <button type="button" disabled={overviewLoading} onClick={() => void loadOverview()} className={overviewLoading ? actionButton : enabledButton}>{overviewLoading ? t('loading') : t('retry')}</button>
        </div>

        {overviewError ? <div className={noteBox} role="alert"><strong className="text-[11px]">{overviewError}</strong></div> : null}

        <section className="grid grid-cols-[repeat(5,minmax(0,1fr))] gap-3 max-[1100px]:grid-cols-3 max-[760px]:grid-cols-2 max-[760px]:gap-2" aria-label={t('overview.metricsLabel')}>
          {metrics.map(([key, label, detail, value]) => (
            <article className="flex min-h-[142px] min-w-0 flex-col items-start rounded-xl border border-[#e8ebef] bg-white p-[15px] shadow-[0_4px_14px_rgb(28_39_58/3%)] max-[760px]:min-h-[124px] max-[760px]:p-3" key={key}>
              <span className="text-[10px] font-[580] leading-[1.4] text-[#6d7784]">{label}</span>
              <strong className="mt-[17px] text-[28px] font-[620] tabular-nums tracking-[-0.04em] text-[#333d4c] max-[760px]:mt-[13px] max-[760px]:text-2xl">{overviewLoading && overview === null ? t('loading') : value}</strong>
              <span className="mt-[3px] text-[9px] text-[#99a1ad]">{detail}</span>
            </article>
          ))}
        </section>

        <section className={panel} aria-labelledby="admin-cleanup-title">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 id="admin-cleanup-title" className={panelTitle}>{t('overview.cleanupTitle')}</h2>
              <p className={panelDesc}>{t('overview.cleanupDescription')}</p>
            </div>
            <span className="mt-1 h-[7px] w-[7px] shrink-0 rounded-full bg-[#c1a570]" aria-hidden="true" />
          </div>
          <div className="mt-[18px] grid grid-cols-2 gap-[14px] max-[430px]:grid-cols-1">
            <div className="flex items-center justify-between gap-2.5 rounded-lg bg-[#f8f9fb] px-3 py-[11px]"><span className="text-[10px] text-[#788291]">{t('overview.lastCleanup')}</span><strong className="text-[10px] font-[590] text-[#626d7b]">{overview === null ? '—' : formatDateTime(overview.tombstone_cleanup.last_cleanup_at)}</strong></div>
            <div className="flex items-center justify-between gap-2.5 rounded-lg bg-[#f8f9fb] px-3 py-[11px]"><span className="text-[10px] text-[#788291]">{t('overview.cleanupStatus')}</span><strong className="text-[10px] font-[590] text-[#626d7b]">{overview === null ? '—' : overview.tombstone_cleanup.last_cleanup_status === 'success' ? t('overview.cleanupSuccess') : overview.tombstone_cleanup.last_cleanup_status === 'failed' ? t('overview.cleanupFailed') : t('overview.cleanupNever')}</strong></div>
          </div>
        </section>

        <section className={panel} aria-labelledby="admin-dump-title">
          <div className="flex items-start justify-between gap-4">
            <div>
              <p className="m-0 mb-1.5 text-[9px] font-bold uppercase tracking-[0.1em] text-[#8a93a0]">{t('dump.eyebrow')}</p>
              <h2 id="admin-dump-title" className={panelTitle}>{t('dump.title')}</h2>
              <p className={panelDesc}>{t('dump.description')}</p>
            </div>
            <span className="text-[19px] text-[#8492a8]" aria-hidden="true"><Database size={19} aria-hidden="true" /></span>
          </div>
          <form className="mt-[17px] grid grid-cols-[minmax(0,1fr)_auto] items-end gap-x-3 gap-y-[9px] max-[430px]:grid-cols-1" onSubmit={(event) => void downloadDump(event)}>
            <label htmlFor="admin-dump-password" className="col-span-full text-[10px] font-[560] text-[#66717f]">{t('dump.passwordLabel')}</label>
            <input id="admin-dump-password" type="password" autoComplete="current-password" value={dumpPassword} onChange={(event) => setDumpPassword(event.target.value)} disabled={dumpBusy} placeholder={t('dump.passwordLabel')} className="min-h-[38px] w-full min-w-0 rounded-[7px] border border-[#e4e7eb] bg-[#f9fafb] px-2.5 text-[10px] text-[#7d8794] disabled:cursor-not-allowed disabled:opacity-76" />
            <button type="submit" disabled={dumpBusy || dumpPassword === ''} className={`${dumpBusy || dumpPassword === '' ? actionButton : enabledButton} max-[430px]:w-full`}>{dumpBusy ? t('dump.downloading') : t('dump.download')}</button>
          </form>
          {dumpMessage ? <p className={statusText} role="status">{dumpMessage}</p> : <p className={statusText}>{t('dump.loginPasswordNote')}</p>}
        </section>
      </>
    )
  }

  const renderSettings = () => (
    <>
      <div className="mb-[25px] flex items-start justify-between gap-[18px] max-[430px]:flex-col max-[430px]:gap-2.5">
        <div>
          <p className="m-0 mb-2 text-[9px] font-bold uppercase tracking-[0.1em] text-[#8a93a0]">{t('settings.eyebrow')}</p>
          <h1 className="m-0 text-[clamp(23px,3vw,29px)] font-[650] tracking-[-0.04em] text-[#202631]">{t('settings.title')}</h1>
          <p className="mt-2 max-w-[690px] text-xs leading-[1.6] text-[#798391]">{t('settings.description')}</p>
        </div>
        <span className={pill}>{t('settings.whitelistCount')}</span>
      </div>

      {settingsError ? <div className={noteBox} role="alert"><strong className="text-[11px]">{settingsError}</strong></div> : null}
      {settingsLoading && settingsResponse === null ? <p className={statusText} role="status">{t('loading')}</p> : null}

      {settingsResponse === null ? null : (
        <section className={panel} aria-label={t('settings.title')}>
          <div className="mt-2">
            {ADMIN_SETTING_FIELDS.map((field) => {
              const source = settingsResponse.sources[field.key]
              const draftValue = settingsDraft[field.key]
              return (
                <article className="grid min-h-[94px] grid-cols-[minmax(150px,0.9fr)_minmax(190px,1.2fr)_auto] items-center gap-[15px] border-b border-[#eff1f4] px-0.5 py-[13px] max-[760px]:grid-cols-[minmax(0,1fr)_auto] max-[760px]:gap-2.5" key={field.key}>
                  <div>
                    <h2 className="m-0 text-[11px] font-[650] text-[#343d4a]">{t(`fields.${field.key}`)}</h2>
                    <code className="mt-1 inline-block font-[ui-monospace,SFMono-Regular,Menlo,monospace] text-[8px] text-[#8792a1]">{field.key}</code>
                    <p className="mt-[5px] text-[9px] leading-[1.45] text-[#929ba7]">{t(field.constraintKey)}</p>
                  </div>
                  <div className="grid justify-items-start gap-1 max-[760px]:col-[1/2] max-[760px]:row-[2]">
                    {field.key === 'smtp_pass' ? (
                      <input
                        type="password"
                        autoComplete="new-password"
                        value={typeof draftValue === 'string' ? draftValue : ''}
                        onChange={(event) => setSettingsDraft((prev) => ({ ...prev, smtp_pass: event.target.value }))}
                        placeholder={t('settings.writeOnly')}
                        aria-label={t(`fields.${field.key}`)}
                        className="min-h-[35px] w-full min-w-0 rounded-[7px] border border-[#e4e7eb] bg-[#f9fafb] px-2 text-[9px] text-[#7d8794]"
                      />
                    ) : field.kind === 'boolean' ? (
                      <select
                        value={draftValue === true ? 'true' : 'false'}
                        onChange={(event) => setSettingsDraft((prev) => ({ ...prev, [field.key]: event.target.value === 'true' }))}
                        aria-label={t(`fields.${field.key}`)}
                        className="min-h-[35px] w-full min-w-0 rounded-[7px] border border-[#e4e7eb] bg-[#f9fafb] px-2 text-[9px] text-[#7d8794]"
                      >
                        <option value="true">{t('common.yes')}</option>
                        <option value="false">{t('common.no')}</option>
                      </select>
                    ) : (
                      <input
                        type="text"
                        inputMode={field.kind === 'integer' || field.kind === 'nullable-integer' ? 'numeric' : 'text'}
                        value={typeof draftValue === 'string' ? draftValue : ''}
                        onChange={(event) => setSettingsDraft((prev) => ({ ...prev, [field.key]: event.target.value }))}
                        aria-label={t(`fields.${field.key}`)}
                        className="min-h-[35px] w-full min-w-0 rounded-[7px] border border-[#e4e7eb] bg-[#f9fafb] px-2 text-[9px] text-[#7d8794]"
                      />
                    )}
                    <span className="text-[9px] leading-[1.45] text-[#8b95a2]">{sourceLabel(source, t)}</span>
                    <span className="text-[9px] leading-[1.45] text-[#8b95a2]">
                      {t('settings.builtInDefault', { value: formatDefault(field.defaultValue, t) })}
                    </span>
                  </div>
                  <button className="min-h-[30px] whitespace-nowrap rounded-md border border-[#e7e9ed] bg-[#fafbfc] px-2 text-[8px] text-[#9199a4] disabled:cursor-not-allowed max-[760px]:col-[2] max-[760px]:row-[1/span_2]" type="button" disabled={settingsSaving} onClick={() => void clearSetting(field.key)} aria-label={`${t('settings.clearOverride')} ${field.key}`}>
                    {t('settings.clearOverride')}
                  </button>
                </article>
              )
            })}
          </div>
          <div className="flex items-center justify-between gap-[14px] pt-[14px] max-[430px]:flex-col max-[430px]:items-start">
            <p className="m-0 text-[9px] leading-[1.55] text-[#848e9b]">{settingsMessage || t('settings.nullClearNote')}</p>
            <button type="button" disabled={settingsSaving} onClick={() => void saveSettings()} className={settingsSaving ? actionButton : enabledButton}>{settingsSaving ? t('loading') : t('settings.saveChanges')}</button>
          </div>
        </section>
      )}

      <section className={`${panel} flex items-center justify-between gap-4 max-[760px]:flex-wrap max-[760px]:items-start`} aria-labelledby="admin-retention-title">
        <div>
          <h2 id="admin-retention-title" className={panelTitle}>{t('settings.tombstoneRetention')}</h2>
          <p className={panelDesc}>{t('settings.tombstoneRetentionDescription')}</p>
        </div>
        <strong className="ml-auto whitespace-nowrap text-[15px] font-[650] text-[#46536a] max-[760px]:ml-0">30 {t('settings.days')}</strong>
        <span className="whitespace-nowrap text-[9px] text-[#87919d]">{t('settings.fixedReadOnly')}</span>
      </section>
      <section className={`${panel} flex items-center justify-between gap-4 max-[760px]:flex-wrap max-[760px]:items-start`} aria-labelledby="admin-smtp-title">
        <div>
          <h2 id="admin-smtp-title" className={panelTitle}>{t('settings.smtpPasswordStatus')}</h2>
          <p className={panelDesc}>{t('settings.smtpPasswordStatusDescription')}</p>
        </div>
        <strong className="text-[10px] font-[550]">{settingsResponse === null ? '—' : settingsResponse.smtp_pass_configured ? t('settings.smtpConfigured') : t('settings.smtpNotConfigured')}</strong>
      </section>
    </>
  )

  const renderAudit = () => (
    <>
      <div className="mb-[25px] flex items-start justify-between gap-[18px] max-[430px]:flex-col max-[430px]:gap-2.5">
        <div>
          <p className="m-0 mb-2 text-[9px] font-bold uppercase tracking-[0.1em] text-[#8a93a0]">{t('audit.eyebrow')}</p>
          <h1 className="m-0 text-[clamp(23px,3vw,29px)] font-[650] tracking-[-0.04em] text-[#202631]">{t('audit.title')}</h1>
          <p className="mt-2 max-w-[690px] text-xs leading-[1.6] text-[#798391]">{t('audit.description')}</p>
        </div>
      </div>

      {auditError ? <div className={noteBox} role="alert"><strong className="text-[11px]">{auditError}</strong></div> : null}

      <section className={panel} aria-label={t('audit.title')}>
        <div className="grid grid-cols-[repeat(5,minmax(100px,1fr))_auto] items-end gap-2.5 pb-[17px] max-[1100px]:grid-cols-[repeat(3,minmax(120px,1fr))] max-[760px]:grid-cols-2 max-[430px]:grid-cols-1">
          <label className={filterLabel}>{t('audit.actorFilter')}<input type="text" value={auditDraft.actor} onChange={(event) => setAuditDraft((prev) => ({ ...prev, actor: event.target.value }))} placeholder={t('audit.uuidPlaceholder')} className={filterInput} /></label>
          <label className={filterLabel}>{t('audit.targetFilter')}<input type="text" value={auditDraft.target} onChange={(event) => setAuditDraft((prev) => ({ ...prev, target: event.target.value }))} placeholder={t('audit.uuidPlaceholder')} className={filterInput} /></label>
          <label className={filterLabel}>{t('audit.actionFilter')}<select value={auditDraft.action} onChange={(event) => setAuditDraft((prev) => ({ ...prev, action: event.target.value }))} className={filterInput}><option value="">{t('audit.allActions')}</option>{ADMIN_AUDIT_ACTIONS.map((action) => <option key={action} value={action}>{action}</option>)}</select></label>
          <label className={filterLabel}>{t('audit.fromFilter')}<input type="datetime-local" value={auditDraft.from} onChange={(event) => setAuditDraft((prev) => ({ ...prev, from: event.target.value }))} className={filterInput} /></label>
          <label className={filterLabel}>{t('audit.toFilter')}<input type="datetime-local" value={auditDraft.to} onChange={(event) => setAuditDraft((prev) => ({ ...prev, to: event.target.value }))} className={filterInput} /></label>
          <button type="button" disabled={auditLoading} onClick={applyAuditFilters} className="min-h-[35px] rounded-[7px] border border-[#dfe3e9] bg-[#f5f6f8] px-[9px] text-[9px] font-semibold text-[#929aa5] disabled:cursor-not-allowed disabled:opacity-76 max-[760px]:col-span-full max-[430px]:col-auto">{t('audit.applyFilters')}</button>
        </div>
        <div className="overflow-x-auto rounded-lg border border-[#edf0f3]">
          <table className="w-full border-collapse text-left">
            <thead><tr>
              <th scope="col" className={auditTh}>{t('audit.time')}</th>
              <th scope="col" className={auditTh}>{t('audit.actor')}</th>
              <th scope="col" className={auditTh}>{t('audit.target')}</th>
              <th scope="col" className={auditTh}>{t('audit.action')}</th>
              <th scope="col" className={auditTh}>{t('audit.metadata')}</th>
            </tr></thead>
            <tbody>
              {auditLoading && auditPage === null ? (
                <tr><td colSpan={5} className="h-[110px] break-anywhere border-b border-[#f0f2f4] px-[11px] py-3 text-center text-[9px] text-[#9099a5]">{t('loading')}</td></tr>
              ) : auditPage !== null && auditPage.items.length > 0 ? auditPage.items.map((row) => (
                <tr key={row.id}>
                  <td className="whitespace-nowrap border-b border-[#f0f2f4] px-[11px] py-3 text-[9px] text-[#5f6977]">{formatDateTime(row.created_at)}</td>
                  <td className="break-all border-b border-[#f0f2f4] px-[11px] py-3 text-[9px] text-[#5f6977]">{row.actor_user_id ?? '—'}</td>
                  <td className="break-all border-b border-[#f0f2f4] px-[11px] py-3 text-[9px] text-[#5f6977]">{row.target_user_id ?? '—'}</td>
                  <td className="whitespace-nowrap border-b border-[#f0f2f4] px-[11px] py-3 text-[9px] text-[#5f6977]">{row.action}</td>
                  <td className="break-all border-b border-[#f0f2f4] px-[11px] py-3 text-[9px] text-[#5f6977]">{JSON.stringify(sanitizeAuditMetadata(row.action, row.metadata))}</td>
                </tr>
              )) : (
                <tr><td colSpan={5} className="h-[110px] break-anywhere border-b border-[#f0f2f4] px-[11px] py-3 text-center text-[9px] text-[#9099a5]">{t('audit.noRows')}</td></tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="mt-[14px] flex items-center justify-between gap-3 text-[9px] leading-[1.5] text-[#8a94a1] max-[430px]:flex-col max-[430px]:items-start">
          <span>{t('audit.metadataPolicy')}</span>
          <div className="flex items-center gap-[9px]">
            <button type="button" disabled={auditCursorStack.length < 2 || auditLoading} onClick={auditPreviousPage} aria-label={t('audit.previousPage')} className={pagerButton}>‹</button>
            <span>{auditPage === null ? '—' : `${t('audit.totalCount', { count: auditPage.total_count })}`}</span>
            <button type="button" disabled={!auditPage?.has_more || auditLoading} onClick={auditNextPage} aria-label={t('audit.nextPage')} className={pagerButton}><ChevronRight size={16} aria-hidden="true" /></button>
          </div>
        </div>
      </section>
      <p className="mx-[1px] mt-3 text-[9px] leading-[1.6] text-[#999fa8]">{t('audit.sensitiveDataWarning')}</p>
    </>
  )

  return (
    <div className="min-h-screen bg-[#f7f8fa] text-(--ink)">
      <header className="flex min-h-[76px] items-center justify-between gap-5 border-b border-(--line) bg-white px-[clamp(20px,4vw,52px)] max-[760px]:min-h-[66px] max-[760px]:px-4">
        <div className="flex items-center gap-[18px] max-[760px]:gap-2.5"><Brand onNavigate={onNavigate} /><span className="h-[22px] w-px bg-(--line-strong)" /><span className="text-[13px] font-[560] text-[#677180] max-[760px]:text-[11px]">{t('header.console')}</span></div>
        <div className="flex items-center gap-[18px] max-[760px]:gap-2.5"><LanguageSelector /></div>
      </header>

      <div className="mx-auto grid min-h-[calc(100vh-130px)] w-[min(100%,1440px)] grid-cols-[230px_minmax(0,1fr)] max-[760px]:min-h-[calc(100vh-120px)] max-[760px]:grid-cols-1">
        <aside className="flex flex-col border-r border-(--line) bg-white px-4 pb-5 pt-7 max-[760px]:border-b max-[760px]:border-r-0 max-[760px]:px-[15px] max-[760px]:py-3">
          <p className="m-0 mb-[14px] text-[9px] font-bold uppercase tracking-[0.1em] text-[#8a93a0] max-[760px]:hidden">{t('header.navigation')}</p>
          <nav aria-label={t('header.navigation')} className="grid gap-[5px] max-[760px]:grid-cols-4 max-[760px]:gap-1.5">
            {sections.map((item) => (
              <button
                key={item}
                type="button"
                className={navLink(section === item)}
                aria-current={section === item ? 'page' : undefined}
                onClick={() => setSection(item)}
              >
                <span className={navIcon(section === item)} aria-hidden="true">{item === 'overview' ? <LayoutGrid size={15} aria-hidden="true" /> : item === 'users' ? <UsersIcon size={15} aria-hidden="true" /> : item === 'settings' ? <Settings size={15} aria-hidden="true" /> : <ScrollText size={15} aria-hidden="true" />}</span>
                {t(`navigation.${item}`)}
              </button>
            ))}
          </nav>
          <div className="mt-auto flex items-start gap-2 rounded-[9px] border border-[#edf0f4] bg-[#fafbfc] p-2.5 text-[10px] leading-[1.55] text-[#778191] max-[760px]:hidden"><span className="mt-1 h-[7px] w-[7px] shrink-0 rounded-full bg-[#c1a570]" aria-hidden="true" /><span>{t('authentication.loginPasswordOnly')}</span></div>
          <button className="mt-4 inline-flex cursor-pointer items-center gap-2 border-0 bg-transparent px-[5px] py-2 text-left text-[11px] text-[#737d8b] hover:text-(--blue) max-[760px]:hidden" type="button" onClick={() => onNavigate('/')}><span aria-hidden="true">←</span>{t('header.backToSite')}</button>
        </aside>

        <main className="min-w-0 px-[clamp(20px,4vw,54px)] pb-[26px] pt-[34px] max-[760px]:px-4 max-[760px]:pb-5 max-[760px]:pt-6">
          {section === 'overview' ? renderOverview() : section === 'users' ? <Suspense fallback={<p className="inline-flex items-center rounded-[5px] bg-[#f5f6f8] px-1.5 py-[3px] text-[9px] font-[550] text-[#7b8491]" role="status">{t('loading')}</p>}><Users adminClient={adminClient} currentUserId={currentUserId} /></Suspense> : section === 'settings' ? renderSettings() : renderAudit()}
        </main>
      </div>
    </div>
  )
}
