import { useCallback, useEffect, useRef, useState } from 'react'
import { ChevronRight } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'
import { AdminApiError, type AdminClient } from '../client/admin'
import { Alert, AlertDescription } from '../components/ui/alert'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { UserAvatar } from '../components/UserAvatar'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import {
  ADMIN_USER_ACTIONS,
  ADMIN_USER_DEVICE_COLUMNS,
  ADMIN_USER_FILTER_OPTIONS,
  ADMIN_USER_LIST_COLUMNS,
  ADMIN_USER_LOGIN_COLUMNS,
  type AdminUserDetailResponse,
  type AdminUserListItem,
  type UsersResponse,
} from '../features/admin/contract'


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

export function Users({ adminClient, currentUserId, onDetailBack }: { adminClient: AdminClient; currentUserId: string; onDetailBack: (back: (() => void) | null) => void }) {
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
    setConfirmAction(null)
    setConfirmPassword('')
    setActionMessage('')
    setDetailLoading(true)
    try {
      const response = await adminClient.getUserDetail(userId, null, 10, signal)
      if (signal?.aborted) return
      if (selectUserGenerationRef.current !== generation) return
      setDetail(response)
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') return
      if (selectUserGenerationRef.current !== generation) return
      setDetailError(errorText(error, t))
    } finally {
      if (selectUserGenerationRef.current === generation) setDetailLoading(false)
    }
  }, [adminClient, t])

  const refreshCurrent = useCallback(async (options?: { skipDetail?: boolean }) => {
    void loadList(cursorStack[cursorStack.length - 1] ?? null, appliedFilters)
    if (selectedId && !options?.skipDetail) {
      try {
        const response = await adminClient.getUserDetail(selectedId, null, 10)
        if (!mountedRef.current) return
        setDetail(response)
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
  const loginHistory = detail === null ? [] : detail.login_history.items.slice(0, 10)
  const activeDevices = detail === null ? [] : detail.devices.filter((device) => device.revoked_at === null)
  const isSelf = selectedUser !== null && selectedUser.id === currentUserId

  const backToList = useCallback(() => {
    setSelectedId(null)
    setDetail(null)
    setDetailError('')
    setConfirmAction(null)
    setConfirmPassword('')
    setActionMessage('')
  }, [])

  useEffect(() => {
    onDetailBack(selectedId !== null ? backToList : null)
  }, [selectedId, backToList, onDetailBack])

  if (selectedId !== null) {
    return (
      <>
        <div className="mt-4 grid grid-cols-2 gap-4 max-[760px]:grid-cols-1">
          <Card className="col-span-full max-[760px]:col-auto">
            <CardHeader>
              <div className="flex items-center gap-3">
                {selectedUser === null ? null : (
                  <UserAvatar displayName={selectedUser.display_name} avatarUrl={selectedUser.avatar_url} email={selectedUser.email} className="flex size-10 shrink-0 items-center justify-center rounded-full bg-primary text-sm font-medium text-primary-foreground" />
                )}
                <div className="min-w-0">
                  <CardTitle id="admin-user-detail-title">{selectedUser === null ? (detailLoading ? t('loading') : t('users.selectUserHint')) : (selectedUser.display_name ?? selectedUser.email)}</CardTitle>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {detailError ? <Alert variant="destructive"><AlertDescription>{detailError}</AlertDescription></Alert> : null}
              {detailLoading ? <p className="text-xs leading-relaxed text-muted-foreground" role="status">{t('loading')}</p> : null}
              {selectedUser === null ? null : (
                <dl className="grid grid-cols-3 gap-x-4 gap-y-3 max-[760px]:grid-cols-2">
                {([
                  ['email', selectedUser.email],
                  ['display_name', selectedUser.display_name ?? '—'],
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
                    <dt className="text-xs font-medium text-muted-foreground">{t(`users.columns.${key}`)}</dt>
                    <dd className="mt-1 break-all text-xs text-foreground">{value}</dd>
                  </div>
                ))}
                </dl>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle id="admin-user-devices-title">{t('users.devicesTitle')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="min-w-0 overflow-x-auto">
                <Table className="w-full min-w-[650px]">
                  <TableHeader><TableRow>{ADMIN_USER_DEVICE_COLUMNS.map((column) => <TableHead key={column} scope="col">{t(`users.deviceColumns.${column}`)}</TableHead>)}<TableHead scope="col"><span className="sr-only">{t('users.revokeDevice')}</span></TableHead></TableRow></TableHeader>
                <TableBody>
                  {detail === null ? (
                    <TableRow><TableCell colSpan={ADMIN_USER_DEVICE_COLUMNS.length + 1} className="h-[92px] whitespace-normal break-anywhere px-2.5 py-3 text-center text-[12px] text-muted-foreground max-[760px]:pl-[14px] max-[760px]:text-left">{detailLoading ? t('loading') : t('users.selectUserHint')}</TableCell></TableRow>
                  ) : activeDevices.length === 0 ? (
                    <TableRow><TableCell colSpan={ADMIN_USER_DEVICE_COLUMNS.length + 1} className="h-[92px] whitespace-normal break-anywhere px-2.5 py-3 text-center text-[12px] text-muted-foreground max-[760px]:pl-[14px] max-[760px]:text-left">{t('users.devicesEmpty')}</TableCell></TableRow>
                  ) : activeDevices.map((device) => (
                    <TableRow key={device.id}>
                      <TableCell className="whitespace-normal break-all px-2 py-3 text-xs text-muted-foreground">{device.device_name}</TableCell>
                      <TableCell className="whitespace-nowrap px-2 py-3 text-xs text-muted-foreground">{device.device_type}</TableCell>
                      <TableCell className="whitespace-nowrap px-2 py-3 text-xs text-muted-foreground">{formatDateTime(device.created_at)}</TableCell>
                      <TableCell className="whitespace-nowrap px-2 py-3 text-xs text-muted-foreground">{formatDateTime(device.last_login_at)}</TableCell>
                      <TableCell className="whitespace-nowrap px-2 py-3 text-xs text-muted-foreground">
                        <Button type="button" disabled={pendingAction !== null} onClick={() => void revokeDevice(device.id)} variant="outline" size="sm">{t('users.revokeDevice')}</Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle id="admin-user-login-title">{t('users.loginHistoryTitle')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="min-w-0 overflow-x-auto">
                <Table className="w-full min-w-[650px]">
                  <TableHeader><TableRow>{ADMIN_USER_LOGIN_COLUMNS.map((column) => <TableHead key={column} scope="col">{t(`users.loginColumns.${column}`)}</TableHead>)}</TableRow></TableHeader>
                <TableBody>
                  {detail === null ? (
                    <TableRow><TableCell colSpan={ADMIN_USER_LOGIN_COLUMNS.length} className="h-[92px] whitespace-normal break-anywhere px-2.5 py-3 text-center text-[12px] text-muted-foreground max-[760px]:pl-[14px] max-[760px]:text-left">{detailLoading ? t('loading') : t('users.selectUserHint')}</TableCell></TableRow>
                  ) : loginHistory.length === 0 ? (
                    <TableRow><TableCell colSpan={ADMIN_USER_LOGIN_COLUMNS.length} className="h-[92px] whitespace-normal break-anywhere px-2.5 py-3 text-center text-[12px] text-muted-foreground max-[760px]:pl-[14px] max-[760px]:text-left">{t('users.loginHistoryEmpty')}</TableCell></TableRow>
                  ) : loginHistory.map((entry) => (
                    <TableRow key={entry.id}>
                      <TableCell className="whitespace-nowrap px-2 py-3 text-xs text-muted-foreground">{formatDateTime(entry.created_at)}</TableCell>
                      <TableCell className="whitespace-normal break-all px-2 py-3 text-xs text-muted-foreground">{entry.device_name ?? '—'}</TableCell>
                      <TableCell className="whitespace-normal break-all px-2 py-3 text-xs text-muted-foreground">{entry.device_id ?? '—'}</TableCell>
                      <TableCell className="whitespace-normal break-all px-2 py-3 text-xs text-muted-foreground">{entry.ip_address ?? '—'}</TableCell>
                      <TableCell className="whitespace-normal break-all px-2 py-3 text-xs text-muted-foreground">{entry.user_agent ?? '—'}</TableCell>
                      <TableCell className="whitespace-nowrap px-2 py-3 text-xs text-muted-foreground">{entry.result}</TableCell>
                      <TableCell className="whitespace-normal break-all px-2 py-3 text-xs text-muted-foreground">{entry.failure_code ?? '—'}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            </CardContent>
          </Card>
        </div>

        <Card className="mt-4">
          <CardHeader>
            <CardTitle id="admin-user-actions-title">{t('users.actionsTitle')}</CardTitle>
            <CardDescription>{selectedUser === null ? (detailLoading ? t('loading') : t('users.selectUserHint')) : selectedUser.email}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex flex-wrap gap-2">
            {ADMIN_USER_ACTIONS.map((action) => {
              const disabled = selectedUser === null || pendingAction !== null ||
                (action === 'disable' && selectedUser?.disabled_at !== null) ||
                (action === 'enable' && selectedUser?.disabled_at === null) ||
                (action === 'delete' && (isSelf || selectedUser?.is_super_admin === true)) ||
                (action === 'make_admin' && selectedUser?.is_admin === true) ||
                (action === 'remove_admin' && (selectedUser?.is_admin !== true || isSelf || selectedUser?.is_super_admin === true))
              return (
                <Button
                  key={action}
                  type="button"
                  disabled={disabled}
                  onClick={() => {
                    if (selectedUser === null) return
                    if (action === 'delete') { setConfirmAction('delete'); setConfirmPassword(''); setActionMessage('') }
                    else void runDirectAction(action, selectedUser)
                  }}
                  variant="outline"
                >
                  {t(`users.actions.${action}`)}
                </Button>
              )
            })}
            <Button
              type="button"
              disabled={selectedUser === null || pendingAction !== null}
              onClick={() => { setConfirmAction('revoke_all_devices'); setConfirmPassword(''); setActionMessage('') }}
              variant="outline"
            >
              {t('users.revokeAllDevices')}
            </Button>
          </div>
            {confirmAction !== null && selectedUser !== null ? (
              <div className="grid gap-2 rounded-lg border bg-muted p-3">
                <strong className="text-xs text-foreground">{confirmAction === 'delete' ? t('users.confirmDelete') : t('users.confirmRevokeAll')}</strong>
                <div className="grid gap-1.5">
                  <Label>{t('users.adminPasswordLabel')}</Label>
                  <Input type="password" autoComplete="current-password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} />
                </div>
                <div className="flex gap-2">
                  <Button type="button" disabled={confirmPassword === '' || pendingAction !== null} onClick={() => void runPasswordAction()} variant="outline">{pendingAction !== null ? t('loading') : t('confirm')}</Button>
                  <Button type="button" disabled={pendingAction !== null} onClick={() => { setConfirmAction(null); setConfirmPassword('') }} variant="outline">{t('cancel')}</Button>
                </div>
              </div>
            ) : null}
            {actionMessage ? <p className="text-xs leading-relaxed text-muted-foreground" role="status">{actionMessage}</p> : null}
            <p className="text-xs leading-relaxed text-muted-foreground">{t('users.deleteRequirement')}</p>
          </CardContent>
        </Card>
      </>
    )
  }

  return (
    <>
      {listError ? <Alert variant="destructive"><AlertDescription>{listError}</AlertDescription></Alert> : null}

      <Card className="mt-4">
        <CardContent className="space-y-4">
          <div className="grid grid-cols-[minmax(170px,1.5fr)_repeat(3,minmax(105px,1fr))_auto] items-end gap-2.5 max-[760px]:grid-cols-2 max-[430px]:grid-cols-1" aria-label={t('users.filtersLabel')}>
            <div className="grid gap-1.5 max-[760px]:col-span-full max-[430px]:col-auto">
              <Label>{t('users.searchLabel')}</Label>
              <Input type="search" value={draftFilters.search} onChange={(event) => setDraftFilters((prev) => ({ ...prev, search: event.target.value }))} placeholder={t('users.searchPlaceholder')} />
            </div>
            <div className="grid gap-1.5">
              <Label>{t('users.statusLabel')}</Label>
              <Select value={draftFilters.status} onValueChange={(value) => setDraftFilters((prev) => ({ ...prev, status: value as UserFilters['status'] }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {ADMIN_USER_FILTER_OPTIONS.status.map((value) => (
                  <SelectItem key={value} value={value}>{t(`users.status.${value}`)}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-1.5">
            <Label>{t('users.verifiedLabel')}</Label>
            <Select value={draftFilters.verified} onValueChange={(value) => setDraftFilters((prev) => ({ ...prev, verified: value as UserFilters['verified'] }))}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {ADMIN_USER_FILTER_OPTIONS.verified.map((value) => (
                  <SelectItem key={value} value={value}>{t(`users.verified.${value}`)}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-1.5">
            <Label>{t('users.roleLabel')}</Label>
            <Select value={draftFilters.role} onValueChange={(value) => setDraftFilters((prev) => ({ ...prev, role: value as UserFilters['role'] }))}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {ADMIN_USER_FILTER_OPTIONS.role.map((value) => (
                  <SelectItem key={value} value={value}>{t(`users.roles.${value}`)}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <Button type="button" disabled={listLoading} onClick={applyFilters} variant="outline" className="max-[760px]:col-span-full max-[430px]:col-auto">{t('users.applyFilters')}</Button>
          </div>

          <div className="min-w-0 overflow-x-auto">
            <Table className="w-full min-w-[970px]">
              <TableHeader>
                <TableRow>{ADMIN_USER_LIST_COLUMNS.map((column) => <TableHead key={column} scope="col">{t(`users.columns.${column}`)}</TableHead>)}</TableRow>
              </TableHeader>
            <TableBody>
              {listLoading && list === null ? (
                <TableRow><TableCell colSpan={ADMIN_USER_LIST_COLUMNS.length} className="h-[92px] whitespace-normal break-anywhere px-2.5 py-3 text-center text-[12px] text-muted-foreground max-[760px]:pl-[14px] max-[760px]:text-left">{t('loading')}</TableCell></TableRow>
              ) : list !== null && list.users.length > 0 ? list.users.map((user) => (
                <TableRow key={user.id} className={selectedId === user.id ? 'bg-muted' : undefined}>
                  <TableCell className="whitespace-normal break-all px-2 py-3 text-xs text-muted-foreground"><button type="button" onClick={() => void selectUser(user.id)} className="cursor-pointer border-0 bg-transparent p-0 text-left text-xs font-semibold text-primary underline-offset-2 hover:underline">{user.email}</button></TableCell>
                  <TableCell className="whitespace-nowrap px-2 py-3 text-xs text-muted-foreground">{formatDateTime(user.created_at)}</TableCell>
                  <TableCell className="whitespace-nowrap px-2 py-3 text-xs text-muted-foreground">{formatDateTime(user.last_login_at)}</TableCell>
                  <TableCell className="whitespace-nowrap px-2 py-3 text-xs text-muted-foreground">{formatDateTime(user.email_verified_at)}</TableCell>
                  <TableCell className="whitespace-nowrap px-2 py-3 text-xs text-muted-foreground">{user.is_admin ? t('common.yes') : t('common.no')}</TableCell>
                  <TableCell className="whitespace-nowrap px-2 py-3 text-xs text-muted-foreground">{user.is_super_admin ? t('common.yes') : t('common.no')}</TableCell>
                  <TableCell className="whitespace-nowrap px-2 py-3 text-xs text-muted-foreground">{formatDateTime(user.disabled_at)}</TableCell>
                  <TableCell className="whitespace-nowrap px-2 py-3 text-xs text-muted-foreground">{user.device_count}</TableCell>
                  <TableCell className="whitespace-nowrap px-2 py-3 text-xs text-muted-foreground">{formatBytes(user.ciphertext_total_bytes)}</TableCell>
                </TableRow>
              )) : (
                <TableRow><TableCell colSpan={ADMIN_USER_LIST_COLUMNS.length} className="h-[92px] whitespace-normal break-anywhere px-2.5 py-3 text-center text-[12px] text-muted-foreground max-[760px]:pl-[14px] max-[760px]:text-left">{t('users.noUsers')}</TableCell></TableRow>
              )}
            </TableBody>
          </Table>
        </div>
          <div className="flex items-center justify-end gap-3 text-xs leading-relaxed text-muted-foreground">
            <div className="flex items-center gap-2">
              <Button type="button" disabled={cursorStack.length < 2 || listLoading} onClick={previousPage} aria-label={t('audit.previousPage')} variant="outline" size="icon" className="size-7">‹</Button>
              <span>{list === null ? '—' : `${list.total_count}`}</span>
              <Button type="button" disabled={!list?.has_more || listLoading} onClick={nextPage} aria-label={t('audit.nextPage')} variant="outline" size="icon" className="size-7"><ChevronRight size={16} aria-hidden="true" /></Button>
            </div>
          </div>
        </CardContent>
      </Card>
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
