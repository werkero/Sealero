import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'
import { AdminApiError, type AdminClient } from '../client/admin'
import {
  ADMIN_USER_ACTIONS,
  ADMIN_USER_DEVICE_COLUMNS,
  ADMIN_USER_FILTER_OPTIONS,
  ADMIN_USER_LIST_COLUMNS,
  ADMIN_USER_LOGIN_COLUMNS,
  type AdminLoginHistoryEntry,
  type AdminUserDetailResponse,
  type AdminUserListItem,
  type UsersResponse,
} from '../features/admin/contract'

const pill = 'inline-flex items-center whitespace-nowrap rounded-full border border-[#e4e9f2] bg-[#f5f7fb] px-2.5 py-1.5 text-[10px] font-[650] text-[#5c6f8e]'
const panel = 'mt-[17px] min-w-0 rounded-xl border border-[#e8ebef] bg-white p-[19px] shadow-[0_4px_14px_rgb(28_39_58/3%)] max-[760px]:p-[15px]'
const panelTitle = 'm-0 text-sm font-[640] text-[#303947]'
const panelDesc = 'mt-1.5 text-[10px] leading-[1.6] text-[#7c8795]'
const filterLabel = 'grid gap-[5px] text-[9px] font-[570] text-[#687381]'
const usersInput = 'min-h-[35px] w-full min-w-0 rounded-[7px] border border-[#e4e7eb] bg-[#f9fafb] px-2 text-[9px] text-[#7d8794] disabled:cursor-not-allowed disabled:opacity-76'
const usersButton = 'min-h-[35px] cursor-pointer rounded-[7px] border border-[#dfe3e9] bg-[#f5f6f8] px-2.5 text-[9px] font-semibold text-[#5c6f8e] hover:bg-[#eef2f8] disabled:cursor-not-allowed disabled:opacity-60'
const disabledUsersButton = 'min-h-[35px] rounded-[7px] border border-[#dfe3e9] bg-[#f5f6f8] px-2.5 text-[9px] font-semibold text-[#929aa5] disabled:cursor-not-allowed disabled:opacity-76'
const pagerButton = 'h-[27px] w-[27px] rounded-md border border-[#e7eaee] bg-[#f8f9fa] text-[#9aa2ac] disabled:cursor-not-allowed'
const usersTh = 'whitespace-nowrap border-b border-[#edf0f3] bg-[#fafbfc] px-2.5 py-2.5 text-[9px] font-[630] text-[#7d8794]'
const tableWrap = 'mt-[14px] min-w-0 overflow-x-auto rounded-lg border border-[#edf0f3]'
const noteBox = 'flex flex-col gap-1 rounded-lg border border-[#e8edf4] bg-[#f8fafd] p-3 text-[10px] leading-[1.55] text-[#586a83]'
const statusText = 'mt-2.5 text-[9px] leading-[1.55] text-[#8993a0]'

type AdminTFunction = TFunction<'admin', undefined>

function formatDateTime(value: string | null): string {
  if (value === null) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`
  return `${(value / (1024 * 1024)).toFixed(1)} MB`
}

/** Maps a failed admin request to display copy; the server code is kept so the cause stays visible. */
function actionErrorText(error: unknown, t: AdminTFunction): string {
  if (error instanceof AdminApiError) {
    if (error.code === 'invalid_credentials') return t('users.wrongPassword')
    if (error.code === 'admin_action_forbidden') return t('users.actionForbidden')
    if (error.message && error.message !== error.code) return `${t('users.actionFailed')} ${error.message}`
    return `${t('users.actionFailed')} (${error.code})`
  }
  if (error instanceof Error && error.name === 'AbortError') return ''
  return t('users.actionFailed')
}

interface UserFilters {
  search: string
  status: 'all' | 'active' | 'disabled'
  verified: 'all' | 'verified' | 'unverified'
  role: 'all' | 'admin' | 'user'
}

const DEFAULT_FILTERS: UserFilters = { search: '', status: 'all', verified: 'all', role: 'all' }

export function Users({ adminClient, currentUserId }: { adminClient: AdminClient; currentUserId: string }) {
  const { t } = useTranslation('admin')
  const mountedRef = useRef(true)
  useEffect(() => () => { mountedRef.current = false }, [])

  const [draftFilters, setDraftFilters] = useState<UserFilters>(DEFAULT_FILTERS)
  const [appliedFilters, setAppliedFilters] = useState<UserFilters>(DEFAULT_FILTERS)
  const [list, setList] = useState<UsersResponse | null>(null)
  const [listError, setListError] = useState('')
  const [listLoading, setListLoading] = useState(true)
  const [cursorStack, setCursorStack] = useState<(string | null)[]>([null])

  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [detail, setDetail] = useState<AdminUserDetailResponse | null>(null)
  const [detailError, setDetailError] = useState('')
  const [detailLoading, setDetailLoading] = useState(false)
  const [extraLoginHistory, setExtraLoginHistory] = useState<AdminLoginHistoryEntry[]>([])
  const [loginHistoryCursor, setLoginHistoryCursor] = useState<string | null>(null)
  const [loginHistoryHasMore, setLoginHistoryHasMore] = useState(false)
  const [loginHistoryLoading, setLoginHistoryLoading] = useState(false)

  const [pendingAction, setPendingAction] = useState<string | null>(null)
  const [actionMessage, setActionMessage] = useState('')
  const [confirmAction, setConfirmAction] = useState<'delete' | 'revoke_all_devices' | null>(null)
  const [confirmPassword, setConfirmPassword] = useState('')

  const loadList = useCallback(async (cursor: string | null, filters: UserFilters, signal?: AbortSignal) => {
    setListLoading(true)
    setListError('')
    try {
      setList(await adminClient.listUsers({
        search: filters.search.trim() || undefined,
        status: filters.status,
        verified: filters.verified,
        role: filters.role,
        cursor,
        limit: 100,
      }, signal))
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') return
      setListError(errorText(error, t))
    } finally {
      setListLoading(false)
    }
  }, [adminClient, t])

  useEffect(() => {
    const controller = new AbortController()
    let active = true
    void adminClient.listUsers({ status: 'all', verified: 'all', role: 'all', cursor: null, limit: 100 }, controller.signal).then(
      (page) => { if (active) { setList(page); setListLoading(false) } },
      (error: unknown) => {
        if (!active) return
        if (!(error instanceof Error && error.name === 'AbortError')) setListError(errorText(error, t))
        setListLoading(false)
      },
    )
    return () => { active = false; controller.abort() }
  }, [adminClient, t])

  const applyFilters = useCallback(() => {
    setAppliedFilters(draftFilters)
    setCursorStack([null])
    setSelectedId(null)
    setDetail(null)
    void loadList(null, draftFilters)
  }, [draftFilters, loadList])

  const nextPage = useCallback(() => {
    if (!list?.has_more || !list.next_cursor) return
    const nextStack = [...cursorStack, list.next_cursor]
    setCursorStack(nextStack)
    void loadList(list.next_cursor, appliedFilters)
  }, [appliedFilters, cursorStack, list, loadList])

  const previousPage = useCallback(() => {
    if (cursorStack.length < 2) return
    const nextStack = cursorStack.slice(0, -1)
    setCursorStack(nextStack)
    void loadList(nextStack[nextStack.length - 1] ?? null, appliedFilters)
  }, [appliedFilters, cursorStack, loadList])

  // Generation guard for selectUser: rapid clicks must not let an older
  // detail response overwrite a newer selection.
  const selectUserGenerationRef = useRef(0)
  const selectUser = useCallback(async (userId: string, signal?: AbortSignal) => {
    const generation = selectUserGenerationRef.current + 1
    selectUserGenerationRef.current = generation
    setSelectedId(userId)
    setDetail(null)
    setDetailError('')
    setExtraLoginHistory([])
    setLoginHistoryCursor(null)
    setLoginHistoryHasMore(false)
    setConfirmAction(null)
    setConfirmPassword('')
    setActionMessage('')
    setDetailLoading(true)
    try {
      const response = await adminClient.getUserDetail(userId, null, 100, signal)
      if (signal?.aborted) return
      if (selectUserGenerationRef.current !== generation) return
      setDetail(response)
      setLoginHistoryCursor(response.login_history.next_cursor)
      setLoginHistoryHasMore(response.login_history.has_more)
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') return
      if (selectUserGenerationRef.current !== generation) return
      setDetailError(errorText(error, t))
    } finally {
      if (selectUserGenerationRef.current === generation) setDetailLoading(false)
    }
  }, [adminClient, t])

  const loadMoreLoginHistory = useCallback(async () => {
    if (!selectedId || !loginHistoryHasMore || !loginHistoryCursor || loginHistoryLoading) return
    setLoginHistoryLoading(true)
    try {
      const response = await adminClient.getUserDetail(selectedId, loginHistoryCursor, 100)
      if (!mountedRef.current) return
      setExtraLoginHistory((prev) => [...prev, ...response.login_history.items])
      setLoginHistoryCursor(response.login_history.next_cursor)
      setLoginHistoryHasMore(response.login_history.has_more)
    } catch (error) {
      if (mountedRef.current) setDetailError(errorText(error, t))
    } finally {
      if (mountedRef.current) setLoginHistoryLoading(false)
    }
  }, [adminClient, loginHistoryCursor, loginHistoryHasMore, loginHistoryLoading, selectedId, t])

  const refreshCurrent = useCallback(async (options?: { skipDetail?: boolean }) => {
    void loadList(cursorStack[cursorStack.length - 1] ?? null, appliedFilters)
    if (selectedId && !options?.skipDetail) {
      try {
        const response = await adminClient.getUserDetail(selectedId, null, 100)
        if (!mountedRef.current) return
        setDetail(response)
        setExtraLoginHistory([])
        setLoginHistoryCursor(response.login_history.next_cursor)
        setLoginHistoryHasMore(response.login_history.has_more)
      } catch (error) {
        // The selected user may have been deleted (by this action or another
        // admin): a 404 means the detail is gone, not that the refresh
        // failed — clear the selection instead of overwriting the success
        // message with an error.
        if (error instanceof AdminApiError && error.status === 404) {
          if (mountedRef.current) {
            setSelectedId(null)
            setDetail(null)
            setDetailError('')
          }
          return
        }
        throw error
      }
    }
  }, [adminClient, appliedFilters, cursorStack, loadList, selectedId])

  const runDirectAction = useCallback(async (action: 'disable' | 'enable' | 'make_admin' | 'remove_admin', user: AdminUserListItem) => {
    setPendingAction(action)
    setActionMessage('')
    try {
      if (action === 'disable') await adminClient.disableUser(user.id)
      else if (action === 'enable') await adminClient.enableUser(user.id)
      else if (action === 'make_admin') await adminClient.makeAdmin(user.id)
      else await adminClient.removeAdmin(user.id)
      if (!mountedRef.current) return
      setActionMessage(t('users.actionDone'))
      await refreshCurrent()
    } catch (error) {
      if (mountedRef.current) setActionMessage(actionErrorText(error, t))
    } finally {
      if (mountedRef.current) setPendingAction(null)
    }
  }, [adminClient, refreshCurrent, t])

  const runPasswordAction = useCallback(async () => {
    if (!selectedId || !confirmAction || confirmPassword === '' || pendingAction) return
    setPendingAction(confirmAction)
    setActionMessage('')
    try {
      if (confirmAction === 'delete') await adminClient.deleteUser(selectedId, confirmPassword)
      else await adminClient.revokeAllDevices(selectedId, confirmPassword)
      if (!mountedRef.current) return
      setActionMessage(t('users.actionDone'))
      setConfirmAction(null)
      setConfirmPassword('')
      if (confirmAction === 'delete') {
        setSelectedId(null)
        setDetail(null)
      }
      // After a delete the detail no longer exists: skip its reload so the
      // success message is not overwritten by a 404.
      await refreshCurrent(confirmAction === 'delete' ? { skipDetail: true } : undefined)
    } catch (error) {
      if (mountedRef.current) setActionMessage(actionErrorText(error, t))
    } finally {
      if (mountedRef.current) setPendingAction(null)
    }
  }, [adminClient, confirmAction, confirmPassword, pendingAction, refreshCurrent, selectedId, t])

  const revokeDevice = useCallback(async (deviceId: string) => {
    setPendingAction(`revoke-device-${deviceId}`)
    setActionMessage('')
    try {
      await adminClient.revokeDevice(deviceId)
      if (!mountedRef.current) return
      setActionMessage(t('users.deviceRevoked'))
      await refreshCurrent()
    } catch (error) {
      if (mountedRef.current) setActionMessage(actionErrorText(error, t))
    } finally {
      if (mountedRef.current) setPendingAction(null)
    }
  }, [adminClient, refreshCurrent, t])

  const selectedUser: AdminUserListItem | null = detail?.user ?? null
  const loginHistory = detail === null ? [] : [...detail.login_history.items, ...extraLoginHistory]
  const isSelf = selectedUser !== null && selectedUser.id === currentUserId

  return (
    <>
      <div className="mb-[25px] flex items-start justify-between gap-[18px] max-[430px]:flex-col max-[430px]:gap-2.5">
        <div>
          <p className="m-0 mb-2 text-[9px] font-bold uppercase tracking-[0.1em] text-[#8a93a0]">{t('users.eyebrow')}</p>
          <h1 className="m-0 text-[clamp(23px,3vw,29px)] font-[650] tracking-[-0.04em] text-[#202631]">{t('users.title')}</h1>
          <p className="mt-2 max-w-[690px] text-xs leading-[1.6] text-[#798391]">{t('users.description')}</p>
        </div>
        <span className={pill}>{list === null ? '—' : `${list.total_count}`}</span>
      </div>

      {listError ? <div className={noteBox} role="alert"><strong className="text-[11px]">{listError}</strong></div> : null}

      <section className={panel} aria-label={t('users.title')}>
        <div className="mt-4 grid grid-cols-[minmax(170px,1.5fr)_repeat(3,minmax(105px,1fr))_auto] items-end gap-2.5 max-[760px]:grid-cols-2 max-[430px]:grid-cols-1" aria-label={t('users.filtersLabel')}>
          <label className={`${filterLabel} max-[760px]:col-span-full max-[430px]:col-auto`}>
            {t('users.searchLabel')}
            <input type="search" value={draftFilters.search} onChange={(event) => setDraftFilters((prev) => ({ ...prev, search: event.target.value }))} placeholder={t('users.searchPlaceholder')} className={usersInput} />
          </label>
          <label className={filterLabel}>
            {t('users.statusLabel')}
            <select value={draftFilters.status} onChange={(event) => setDraftFilters((prev) => ({ ...prev, status: event.target.value as UserFilters['status'] }))} className={usersInput}>
              {ADMIN_USER_FILTER_OPTIONS.status.map((value) => (
                <option key={value} value={value}>{t(`users.status.${value}`)}</option>
              ))}
            </select>
          </label>
          <label className={filterLabel}>
            {t('users.verifiedLabel')}
            <select value={draftFilters.verified} onChange={(event) => setDraftFilters((prev) => ({ ...prev, verified: event.target.value as UserFilters['verified'] }))} className={usersInput}>
              {ADMIN_USER_FILTER_OPTIONS.verified.map((value) => (
                <option key={value} value={value}>{t(`users.verified.${value}`)}</option>
              ))}
            </select>
          </label>
          <label className={filterLabel}>
            {t('users.roleLabel')}
            <select value={draftFilters.role} onChange={(event) => setDraftFilters((prev) => ({ ...prev, role: event.target.value as UserFilters['role'] }))} className={usersInput}>
              {ADMIN_USER_FILTER_OPTIONS.role.map((value) => (
                <option key={value} value={value}>{t(`users.roles.${value}`)}</option>
              ))}
            </select>
          </label>
          <button type="button" disabled={listLoading} onClick={applyFilters} className={`${usersButton} max-[760px]:col-span-full max-[430px]:col-auto`}>{t('users.applyFilters')}</button>
        </div>

        <div className={tableWrap}>
          <table className="w-full min-w-[970px] border-collapse text-left">
            <thead>
              <tr>{ADMIN_USER_LIST_COLUMNS.map((column) => <th key={column} scope="col" className={usersTh}>{t(`users.columns.${column}`)}</th>)}</tr>
            </thead>
            <tbody>
              {listLoading && list === null ? (
                <tr><td colSpan={ADMIN_USER_LIST_COLUMNS.length} className="h-[92px] break-anywhere border-b border-[#f0f2f4] px-2.5 py-3 text-center text-[9px] text-[#9099a5] max-[760px]:pl-[14px] max-[760px]:text-left">{t('loading')}</td></tr>
              ) : list !== null && list.users.length > 0 ? list.users.map((user) => (
                <tr key={user.id} className={selectedId === user.id ? 'bg-[#f3f6fb]' : undefined}>
                  <td className="break-all border-b border-[#f0f2f4] px-2.5 py-3 text-[9px] text-[#5f6977]"><button type="button" onClick={() => void selectUser(user.id)} className="cursor-pointer border-0 bg-transparent p-0 text-left text-[9px] font-[600] text-[#33507e] underline-offset-2 hover:underline">{user.email}</button></td>
                  <td className="whitespace-nowrap border-b border-[#f0f2f4] px-2.5 py-3 text-[9px] text-[#5f6977]">{formatDateTime(user.created_at)}</td>
                  <td className="whitespace-nowrap border-b border-[#f0f2f4] px-2.5 py-3 text-[9px] text-[#5f6977]">{formatDateTime(user.last_login_at)}</td>
                  <td className="whitespace-nowrap border-b border-[#f0f2f4] px-2.5 py-3 text-[9px] text-[#5f6977]">{formatDateTime(user.email_verified_at)}</td>
                  <td className="whitespace-nowrap border-b border-[#f0f2f4] px-2.5 py-3 text-[9px] text-[#5f6977]">{user.is_admin ? t('common.yes') : t('common.no')}</td>
                  <td className="whitespace-nowrap border-b border-[#f0f2f4] px-2.5 py-3 text-[9px] text-[#5f6977]">{user.is_super_admin ? t('common.yes') : t('common.no')}</td>
                  <td className="whitespace-nowrap border-b border-[#f0f2f4] px-2.5 py-3 text-[9px] text-[#5f6977]">{formatDateTime(user.disabled_at)}</td>
                  <td className="whitespace-nowrap border-b border-[#f0f2f4] px-2.5 py-3 text-[9px] text-[#5f6977]">{user.device_count}</td>
                  <td className="whitespace-nowrap border-b border-[#f0f2f4] px-2.5 py-3 text-[9px] text-[#5f6977]">{formatBytes(user.ciphertext_total_bytes)}</td>
                </tr>
              )) : (
                <tr><td colSpan={ADMIN_USER_LIST_COLUMNS.length} className="h-[92px] break-anywhere border-b border-[#f0f2f4] px-2.5 py-3 text-center text-[9px] text-[#9099a5] max-[760px]:pl-[14px] max-[760px]:text-left">{t('users.noUsers')}</td></tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="mt-[14px] flex items-center justify-between gap-3 text-[9px] leading-[1.5] text-[#8a94a1]">
          <span>{t('users.listMeta')}</span>
          <div className="flex items-center gap-[9px]">
            <button type="button" disabled={cursorStack.length < 2 || listLoading} onClick={previousPage} aria-label={t('audit.previousPage')} className={pagerButton}>‹</button>
            <span>{list === null ? '—' : `${list.total_count}`}</span>
            <button type="button" disabled={!list?.has_more || listLoading} onClick={nextPage} aria-label={t('audit.nextPage')} className={pagerButton}>›</button>
          </div>
        </div>
      </section>

      <div className="mt-4 grid grid-cols-2 gap-4 max-[760px]:grid-cols-1">
        <section className={`${panel} col-span-full max-[760px]:col-auto`} aria-labelledby="admin-user-detail-title">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 id="admin-user-detail-title" className={panelTitle}>{t('users.detailsTitle')}</h2>
              <p className={panelDesc}>{selectedUser === null ? t('users.selectUserHint') : selectedUser.email}</p>
            </div>
          </div>
          {detailError ? <div className={`${noteBox} mt-3`} role="alert"><strong className="text-[11px]">{detailError}</strong></div> : null}
          {detailLoading ? <p className={statusText} role="status">{t('loading')}</p> : null}
          {selectedUser === null ? null : (
            <dl className="mt-4 grid grid-cols-[repeat(3,minmax(0,1fr))] gap-x-4 gap-y-3 max-[760px]:grid-cols-2">
              {([
                ['email', selectedUser.email],
                ['created_at', formatDateTime(selectedUser.created_at)],
                ['last_login_at', formatDateTime(selectedUser.last_login_at)],
                ['email_verified_at', formatDateTime(selectedUser.email_verified_at)],
                ['disabled_at', formatDateTime(selectedUser.disabled_at)],
                ['is_admin', selectedUser.is_admin ? t('common.yes') : t('common.no')],
                ['is_super_admin', selectedUser.is_super_admin ? t('common.yes') : t('common.no')],
                ['device_count', String(selectedUser.device_count)],
                ['ciphertext_total_bytes', formatBytes(selectedUser.ciphertext_total_bytes)],
              ] as [string, string][]).map(([key, value]) => (
                <div key={key}>
                  <dt className="text-[9px] font-[570] text-[#687381]">{t(`users.columns.${key}`)}</dt>
                  <dd className="m-0 mt-1 break-all text-[10px] text-[#343d4a]">{value}</dd>
                </div>
              ))}
            </dl>
          )}
        </section>

        <section className={panel} aria-labelledby="admin-user-devices-title">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 id="admin-user-devices-title" className={panelTitle}>{t('users.devicesTitle')}</h2>
              <p className={panelDesc}>{t('users.devicesDescription')}</p>
            </div>
          </div>
          <div className={tableWrap}>
            <table className="w-full min-w-[650px] border-collapse text-left">
              <thead><tr>{ADMIN_USER_DEVICE_COLUMNS.map((column) => <th key={column} scope="col" className={usersTh}>{t(`users.deviceColumns.${column}`)}</th>)}<th scope="col" className={usersTh}><span className="sr-only">{t('users.revokeDevice')}</span></th></tr></thead>
              <tbody>
                {detail === null ? (
                  <tr><td colSpan={ADMIN_USER_DEVICE_COLUMNS.length + 1} className="h-[92px] break-anywhere border-b border-[#f0f2f4] px-2.5 py-3 text-center text-[9px] text-[#9099a5] max-[760px]:pl-[14px] max-[760px]:text-left">{t('users.selectUserHint')}</td></tr>
                ) : detail.devices.length === 0 ? (
                  <tr><td colSpan={ADMIN_USER_DEVICE_COLUMNS.length + 1} className="h-[92px] break-anywhere border-b border-[#f0f2f4] px-2.5 py-3 text-center text-[9px] text-[#9099a5] max-[760px]:pl-[14px] max-[760px]:text-left">{t('users.devicesEmpty')}</td></tr>
                ) : detail.devices.map((device) => (
                  <tr key={device.id}>
                    <td className="break-all border-b border-[#f0f2f4] px-2.5 py-3 text-[9px] text-[#5f6977]">{device.device_name}</td>
                    <td className="whitespace-nowrap border-b border-[#f0f2f4] px-2.5 py-3 text-[9px] text-[#5f6977]">{device.device_type}</td>
                    <td className="whitespace-nowrap border-b border-[#f0f2f4] px-2.5 py-3 text-[9px] text-[#5f6977]">{formatDateTime(device.created_at)}</td>
                    <td className="whitespace-nowrap border-b border-[#f0f2f4] px-2.5 py-3 text-[9px] text-[#5f6977]">{formatDateTime(device.last_login_at)}</td>
                    <td className="whitespace-nowrap border-b border-[#f0f2f4] px-2.5 py-3 text-[9px] text-[#5f6977]">{formatDateTime(device.revoked_at)}</td>
                    <td className="whitespace-nowrap border-b border-[#f0f2f4] px-2.5 py-3 text-[9px] text-[#5f6977]">
                      <button type="button" disabled={device.revoked_at !== null || pendingAction !== null} onClick={() => void revokeDevice(device.id)} className={device.revoked_at !== null || pendingAction !== null ? disabledUsersButton : usersButton}>{t('users.revokeDevice')}</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className={panel} aria-labelledby="admin-user-login-title">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 id="admin-user-login-title" className={panelTitle}>{t('users.loginHistoryTitle')}</h2>
              <p className={panelDesc}>{t('users.loginHistoryDescription')}</p>
            </div>
          </div>
          <div className={tableWrap}>
            <table className="w-full min-w-[650px] border-collapse text-left">
              <thead><tr>{ADMIN_USER_LOGIN_COLUMNS.map((column) => <th key={column} scope="col" className={usersTh}>{t(`users.loginColumns.${column}`)}</th>)}</tr></thead>
              <tbody>
                {detail === null ? (
                  <tr><td colSpan={ADMIN_USER_LOGIN_COLUMNS.length} className="h-[92px] break-anywhere border-b border-[#f0f2f4] px-2.5 py-3 text-center text-[9px] text-[#9099a5] max-[760px]:pl-[14px] max-[760px]:text-left">{t('users.selectUserHint')}</td></tr>
                ) : loginHistory.length === 0 ? (
                  <tr><td colSpan={ADMIN_USER_LOGIN_COLUMNS.length} className="h-[92px] break-anywhere border-b border-[#f0f2f4] px-2.5 py-3 text-center text-[9px] text-[#9099a5] max-[760px]:pl-[14px] max-[760px]:text-left">{t('users.loginHistoryEmpty')}</td></tr>
                ) : loginHistory.map((entry) => (
                  <tr key={entry.id}>
                    <td className="whitespace-nowrap border-b border-[#f0f2f4] px-2.5 py-3 text-[9px] text-[#5f6977]">{formatDateTime(entry.created_at)}</td>
                    <td className="break-all border-b border-[#f0f2f4] px-2.5 py-3 text-[9px] text-[#5f6977]">{entry.device_name ?? '—'}</td>
                    <td className="break-all border-b border-[#f0f2f4] px-2.5 py-3 text-[9px] text-[#5f6977]">{entry.device_id ?? '—'}</td>
                    <td className="break-all border-b border-[#f0f2f4] px-2.5 py-3 text-[9px] text-[#5f6977]">{entry.ip_address ?? '—'}</td>
                    <td className="break-all border-b border-[#f0f2f4] px-2.5 py-3 text-[9px] text-[#5f6977]">{entry.user_agent ?? '—'}</td>
                    <td className="whitespace-nowrap border-b border-[#f0f2f4] px-2.5 py-3 text-[9px] text-[#5f6977]">{entry.result}</td>
                    <td className="break-all border-b border-[#f0f2f4] px-2.5 py-3 text-[9px] text-[#5f6977]">{entry.failure_code ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {detail !== null && loginHistoryHasMore ? (
            <button type="button" disabled={loginHistoryLoading} onClick={() => void loadMoreLoginHistory()} className={`${usersButton} mt-3`}>{loginHistoryLoading ? t('loading') : t('users.showMore')}</button>
          ) : detail !== null && loginHistory.length > 0 ? <p className={statusText}>{t('users.noMoreRecords')}</p> : null}
        </section>
      </div>

      <section className={panel} aria-labelledby="admin-user-actions-title">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 id="admin-user-actions-title" className={panelTitle}>{t('users.actionsTitle')}</h2>
            <p className={panelDesc}>{selectedUser === null ? t('users.selectUserHint') : selectedUser.email}</p>
          </div>
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          {ADMIN_USER_ACTIONS.map((action) => {
            const disabled = selectedUser === null || pendingAction !== null ||
              (action === 'disable' && selectedUser?.disabled_at !== null) ||
              (action === 'enable' && selectedUser?.disabled_at === null) ||
              (action === 'delete' && (isSelf || selectedUser?.is_super_admin === true)) ||
              (action === 'make_admin' && selectedUser?.is_admin === true) ||
              (action === 'remove_admin' && (selectedUser?.is_admin !== true || isSelf || selectedUser?.is_super_admin === true))
            return (
              <button
                key={action}
                type="button"
                disabled={disabled}
                onClick={() => {
                  if (selectedUser === null) return
                  if (action === 'delete') { setConfirmAction('delete'); setConfirmPassword(''); setActionMessage('') }
                  else void runDirectAction(action, selectedUser)
                }}
                className={disabled ? disabledUsersButton : usersButton}
              >
                {t(`users.actions.${action}`)}
              </button>
            )
          })}
          <button
            type="button"
            disabled={selectedUser === null || pendingAction !== null}
            onClick={() => { setConfirmAction('revoke_all_devices'); setConfirmPassword(''); setActionMessage('') }}
            className={selectedUser === null || pendingAction !== null ? disabledUsersButton : usersButton}
          >
            {t('users.revokeAllDevices')}
          </button>
        </div>
        {confirmAction !== null && selectedUser !== null ? (
          <div className="mt-4 grid gap-2 rounded-lg border border-[#edf0f4] bg-[#fafbfc] p-3">
            <strong className="text-[11px] text-[#343d4a]">{confirmAction === 'delete' ? t('users.confirmDelete') : t('users.confirmRevokeAll')}</strong>
            <label className={filterLabel}>
              {t('users.adminPasswordLabel')}
              <input type="password" autoComplete="current-password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} className={usersInput} />
            </label>
            <div className="flex gap-2">
              <button type="button" disabled={confirmPassword === '' || pendingAction !== null} onClick={() => void runPasswordAction()} className={confirmPassword === '' || pendingAction !== null ? disabledUsersButton : usersButton}>{pendingAction !== null ? t('loading') : t('confirm')}</button>
              <button type="button" disabled={pendingAction !== null} onClick={() => { setConfirmAction(null); setConfirmPassword('') }} className={usersButton}>{t('cancel')}</button>
            </div>
          </div>
        ) : null}
        {actionMessage ? <p className={statusText} role="status">{actionMessage}</p> : null}
        <p className="mt-2.5 text-[9px] leading-[1.55] text-[#8993a0]">{t('users.deleteRequirement')}</p>
        <p className="mt-2.5 text-[9px] leading-[1.55] text-[#8993a0]">{t('users.roleGuardrail')}</p>
        <p className="mt-2.5 text-[9px] leading-[1.55] text-[#8993a0]">{t('users.vaultGuardrail')}</p>
      </section>
    </>
  )
}

function errorText(error: unknown, t: AdminTFunction): string {
  if (error instanceof AdminApiError) {
    if (error.message && error.message !== error.code) return `${t('loadFailed')} ${error.message}`
    return `${t('loadFailed')} (${error.code})`
  }
  if (error instanceof Error && error.name === 'AbortError') return ''
  return t('loadFailed')
}
