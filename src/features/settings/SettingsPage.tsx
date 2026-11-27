import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent } from 'react'
import { useTranslation } from 'react-i18next'
import type { VaultIdentity, VaultItem, VaultListItem } from '../../client/contracts'
import { getCsvHeaders, getImportFileModifiedAt, inspectBackupContainer, parseCsvWithMapping, parseImportText, type BackupContainerSummary, type ImportField, type ImportedVaultEntry, type ParsedImportFile } from './backup-local'
import { backupFilename } from './cloud-backup'
import { CloudBackupPanel } from './CloudBackupPanel'
import { Badge } from '../../components/ui/badge'
import { Button } from '../../components/ui/button'
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '../../components/ui/card'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '../../components/ui/dialog'
import { Input } from '../../components/ui/input'
import { UserAvatar } from '../../components/UserAvatar'

const requiredImportFields: ImportField[] = ['name', 'url', 'username', 'password']
const importFields: ImportField[] = ['name', 'url', 'username', 'password', 'note', 'category', 'tags', 'favorite']

type ImportMatch = { entry: ImportedVaultEntry; kind: 'new' | 'same' | 'changed'; matchedName?: string }
type ImportChoice = 'update' | 'keep-both' | 'skip'

function normalizeImportUrl(value: string): string {
  return value.trim().toLowerCase().replace(/\/+$/, '')
}

function importMatches(entry: ImportedVaultEntry, existing: VaultItem[]): ImportMatch {
  const url = normalizeImportUrl(entry.url)
  if (!url || !entry.username) return { entry, kind: 'new' }
  const matches = existing.filter((item) => normalizeImportUrl(item.url) === url && item.username === entry.username)
  const exact = matches.find((item) => item.password === entry.password)
  if (exact) return { entry, kind: 'same', matchedName: exact.name }
  if (matches[0]) return { entry, kind: 'changed', matchedName: matches[0].name }
  return { entry, kind: 'new' }
}

function importErrorTranslationKey(code: string): string {
  const known: Record<string, string> = {
    csv_empty: 'errors.emptyFile',
    csv_missing_header: 'errors.missingHeaders',
    csv_unclosed_quote: 'errors.malformedCsv',
    csv_mapping_required: 'errors.mappingRequired',
    csv_invalid_mapping: 'errors.invalidMapping',
    bitwarden_json_invalid: 'errors.invalidBitwarden',
    bitwarden_encrypted_export: 'errors.encryptedBitwarden',
    import_unsupported_file: 'errors.unsupportedFile',
  }
  return known[code] ?? 'errors.parseFailed'
}

export function SettingsPage({ user, items, loadItem, onExportBackup, onExportBackupFull, autoLockMinutes, onAutoLockMinutesChange, onUpdateUserProfile }: {
  user: VaultIdentity
  items: VaultListItem[]
  loadItem: (itemId: string) => Promise<VaultItem>
  /** KEK-only v3 container for cloud backup; null when the vault is locked. */
  onExportBackup: () => Promise<Uint8Array | null>
  /** Full v3 container (KEK + recovery-key wrappings) for manual export. */
  onExportBackupFull: (masterPassword: string, recoveryKey: string) => Promise<Uint8Array>
  autoLockMinutes: number
  onAutoLockMinutesChange: (minutes: number) => Promise<boolean>
  onUpdateUserProfile: (input: { display_name?: string; avatar_url?: string }) => Promise<boolean>
}) {
  const { t, i18n: activeI18n } = useTranslation(['settings', 'backup', 'vault'])
  const [selectedFileName, setSelectedFileName] = useState('')
  const [sourceFileModifiedAt, setSourceFileModifiedAt] = useState<string | null>(null)
  const [importError, setImportError] = useState('')
  const [mappingHeaders, setMappingHeaders] = useState<string[]>([])
  const [columnMapping, setColumnMapping] = useState<Partial<Record<ImportField, number>>>({})
  const [parsedImport, setParsedImport] = useState<ParsedImportFile | null>(null)
  const [importPreview, setImportPreview] = useState<ImportMatch[] | null>(null)
  const [isCheckingImport, setIsCheckingImport] = useState(false)
  const [choices, setChoices] = useState<Record<number, ImportChoice>>({})
  const [backupSummary, setBackupSummary] = useState<BackupContainerSummary | null>(null)
  const [backupError, setBackupError] = useState('')
  const [backupFileName, setBackupFileName] = useState('')
  const [exportDialogOpen, setExportDialogOpen] = useState(false)
  const [exportMasterPassword, setExportMasterPassword] = useState('')
  const [exportRecoveryKey, setExportRecoveryKey] = useState('')
  const [exportBusy, setExportBusy] = useState(false)
  const [exportError, setExportError] = useState('')
  const [exportDoneFile, setExportDoneFile] = useState('')
  const [profileDisplayName, setProfileDisplayName] = useState(user.display_name ?? '')
  const [profileAvatarUrl, setProfileAvatarUrl] = useState(user.avatar_url ?? '')
  const [profileBusy, setProfileBusy] = useState(false)
  const [profileError, setProfileError] = useState('')
  const csvSourceRef = useRef<string | null>(null)
  const importInputRef = useRef<HTMLInputElement>(null)
  const backupInputRef = useRef<HTMLInputElement>(null)
  const exportRecoveryKeyWordCount = useMemo(() => {
    const trimmed = exportRecoveryKey.trim()
    return trimmed === '' ? 0 : trimmed.split(/\s+/).length
  }, [exportRecoveryKey])

  const importCounts = useMemo(() => {
    const rows = importPreview ?? []
    return {
      new: rows.filter((row) => row.kind === 'new' || (row.kind === 'changed' && choices[row.entry.sourceIndex] === 'keep-both')).length,
      skipped: rows.filter((row) => row.kind === 'same' || (row.kind === 'changed' && choices[row.entry.sourceIndex] === 'skip')).length,
      changed: rows.filter((row) => row.kind === 'changed').length,
    }
  }, [choices, importPreview])

  const clearImportPreview = useCallback(() => {
    csvSourceRef.current = null
    setSelectedFileName('')
    setSourceFileModifiedAt(null)
    setImportError('')
    setMappingHeaders([])
    setColumnMapping({})
    setParsedImport(null)
    setImportPreview(null)
    setChoices({})
    if (importInputRef.current) importInputRef.current.value = ''
  }, [])

  const parseSelectedFile = useCallback(async (file: File) => {
    clearImportPreview()
    setSelectedFileName(file.name)
    setSourceFileModifiedAt(getImportFileModifiedAt(file.lastModified))
    let source = ''
    try {
      source = await file.text()
      const parsed = parseImportText(file.name, source)
      setParsedImport(parsed)
      if (parsed.rows.length === 0) setImportError('errors.noLoginRows')
    } catch (error) {
      const code = error instanceof Error ? error.message : 'import_parse_failed'
      if (code === 'csv_mapping_required') {
        csvSourceRef.current = source
        const csvSource = source
        try {
          setMappingHeaders(getCsvHeaders(csvSource))
        } catch {
          const headerRows = csvSource.split(/\r?\n/, 1)[0]?.split(',').map((header) => header.trim()) ?? []
          setMappingHeaders(headerRows)
        }
        setImportError('errors.mappingRequired')
      } else {
        setImportError(importErrorTranslationKey(code))
      }
    }
  }, [clearImportPreview])

  const onImportFileChange = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.currentTarget.files?.[0]
    if (file) void parseSelectedFile(file)
  }

  const onBackupFileChange = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.currentTarget.files?.[0]
    if (!file) return
    setBackupFileName(file.name)
    setBackupSummary(null)
    setBackupError('')
    try {
      const content = await file.text()
      setBackupSummary(inspectBackupContainer(content))
    } catch (error) {
      const code = error instanceof Error ? error.message : 'backup_invalid_container'
      setBackupError(code === 'backup_future_version' ? 'backup:errors.futureVersion' : 'backup:errors.invalidContainer')
    }
  }

  const openExportDialog = useCallback(() => {
    setExportMasterPassword('')
    setExportRecoveryKey('')
    setExportError('')
    setExportDoneFile('')
    setExportDialogOpen(true)
  }, [])

  const closeExportDialog = useCallback(() => {
    setExportMasterPassword('')
    setExportRecoveryKey('')
    setExportError('')
    setExportDialogOpen(false)
  }, [])

  useEffect(() => {
    setProfileDisplayName(user.display_name ?? '')
    setProfileAvatarUrl(user.avatar_url ?? '')
  }, [user.display_name, user.avatar_url])

  const profileChanged = profileDisplayName !== (user.display_name ?? '') || profileAvatarUrl !== (user.avatar_url ?? '')

  const saveProfile = useCallback(async () => {
    if (profileBusy || !profileChanged) return
    setProfileBusy(true)
    setProfileError('')
    const ok = await onUpdateUserProfile({ display_name: profileDisplayName, avatar_url: profileAvatarUrl })
    setProfileBusy(false)
    if (!ok) setProfileError('vault:saveFailed')
  }, [profileBusy, profileChanged, profileDisplayName, profileAvatarUrl, onUpdateUserProfile])

  const confirmExport = useCallback(async () => {
    if (exportBusy || !exportMasterPassword || !exportRecoveryKey.trim()) return
    setExportBusy(true)
    setExportError('')
    try {
      const bytes = await onExportBackupFull(exportMasterPassword, exportRecoveryKey)
      const filename = backupFilename(new Date())
      const blob = new Blob([bytes as BlobPart], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = filename
      document.body.appendChild(anchor)
      anchor.click()
      anchor.remove()
      window.setTimeout(() => URL.revokeObjectURL(url), 1000)
      setExportDoneFile(filename)
      setExportMasterPassword('')
      setExportRecoveryKey('')
      setExportDialogOpen(false)
    } catch (error) {
      const code = error instanceof Error ? error.message : 'export_failed'
      setExportError(
        code === 'invalid_master_password' ? 'backup:exportWrongPassword'
          : code === 'invalid_recovery_key' ? 'backup:exportInvalidRecoveryKey'
            : code === 'vault_locked' ? 'backup:exportVaultLocked'
              : 'backup:exportFailed',
      )
    } finally {
      setExportBusy(false)
    }
  }, [exportBusy, exportMasterPassword, exportRecoveryKey, onExportBackupFull])

  const updateCsvMapping = (field: ImportField, value: string) => {
    const next = { ...columnMapping }
    if (value === '') delete next[field]
    else next[field] = Number(value)
    setColumnMapping(next)
  }

  const finishManualMapping = () => {
    if (!csvSourceRef.current || requiredImportFields.some((field) => columnMapping[field] === undefined)) return
    try {
      const mapped = parseCsvWithMapping(csvSourceRef.current, columnMapping)
      setParsedImport(mapped)
      setImportError('')
      csvSourceRef.current = null
    } catch (error) {
      setImportError(importErrorTranslationKey(error instanceof Error ? error.message : 'import_parse_failed'))
    }
  }

  const buildPreview = async () => {
    if (!parsedImport) return
    setIsCheckingImport(true)
    setImportError('')
    try {
      const currentItems = await Promise.all(items.map((item) => loadItem(item.id)))
      setImportPreview(parsedImport.rows.map((entry) => importMatches(entry, currentItems)))
      setChoices(Object.fromEntries(parsedImport.rows.map((entry) => [entry.sourceIndex, 'skip'])))
    } catch {
      setImportError('errors.localCompareUnavailable')
      setImportPreview(null)
    } finally {
      setIsCheckingImport(false)
    }
  }

  return (
    <div className="w-full space-y-6 px-[clamp(20px,4vw,48px)] pb-10 pt-8">
      <Card aria-labelledby="settings-account-title">
        <CardHeader>
          <CardTitle id="settings-account-title" className="text-lg tracking-tight">{t('settings:accountTitle')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-3">
            <UserAvatar displayName={user.display_name} avatarUrl={user.avatar_url} email={user.email} className="grid size-10 shrink-0 place-items-center overflow-hidden rounded-full bg-primary text-sm font-semibold text-primary-foreground" />
            <strong className="min-w-0 flex-1 truncate text-sm font-medium">{user.email}</strong>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="grid gap-1.5"><span className="text-sm font-medium">{t('settings:displayName')}</span><Input value={profileDisplayName} placeholder={user.email} maxLength={64} onChange={(event) => setProfileDisplayName(event.target.value)} /></label>
            <label className="grid gap-1.5"><span className="text-sm font-medium">{t('settings:avatarUrl')}</span><Input value={profileAvatarUrl} placeholder="https://" onChange={(event) => setProfileAvatarUrl(event.target.value)} /></label>
          </div>
          {profileError ? <p className="text-sm font-medium text-destructive" role="alert">{t(profileError)}</p> : null}
        </CardContent>
        <CardFooter className="border-t"><small className="block min-w-0 flex-1 truncate text-xs text-muted-foreground">{t('settings:accountId')} · {user.id}</small><Button type="button" className="ml-auto" disabled={profileBusy || !profileChanged} onClick={() => void saveProfile()}>{t('settings:save')}</Button></CardFooter>
      </Card>

      <Card aria-labelledby="settings-server-title">
        <CardHeader>
          <CardTitle id="settings-server-title" className="text-lg tracking-tight">{t('settings:serverTitle')}</CardTitle>
        </CardHeader>
        <CardContent className="flex items-center gap-3">
          <div className="flex min-w-0 flex-1 items-center gap-3"><span className="grid size-9 shrink-0 place-items-center rounded-lg bg-primary text-sm font-bold text-primary-foreground" aria-hidden="true">S</span><strong className="block text-sm font-medium">{t('settings:officialCloud')}</strong></div>
        </CardContent>
        <CardFooter className="border-t"><span className="text-xs text-muted-foreground">{t('settings:v1ReadOnly')}</span><Badge variant="secondary" className="ml-auto">{t('settings:readOnly')}</Badge></CardFooter>
      </Card>

      <Card aria-labelledby="settings-device-title">
        <CardHeader>
          <CardTitle id="settings-device-title" className="text-lg tracking-tight">{t('settings:devicesTitle')}</CardTitle>
        </CardHeader>
      </Card>

      <Card aria-labelledby="settings-import-title">
        <CardHeader>
          <CardTitle id="settings-import-title" className="text-lg tracking-tight">{t('backup:importTitle')}</CardTitle>
        </CardHeader>
          <CardContent className="space-y-4">
          <div className="flex items-start justify-between gap-3"><div><strong className="block text-sm font-medium">{t('backup:localImportTitle')}</strong><p className="mt-0.5 text-xs text-muted-foreground">{t('backup:localImportDescription')}</p></div><Badge variant="secondary">{t('backup:localOnly')}</Badge></div>
          <div className="flex flex-wrap items-center gap-2">
            <input ref={importInputRef} className="visually-hidden" id="vault-import-file" type="file" accept=".csv,.json,text/csv,application/json" onChange={onImportFileChange} />
            <Button asChild variant="outline"><label htmlFor="vault-import-file">{t('backup:chooseImportFile')}</label></Button>
            {parsedImport ? <Button variant="outline" type="button" onClick={clearImportPreview}>{t('backup:clearImport')}</Button> : null}
          </div>
          {selectedFileName ? <p className="text-sm text-muted-foreground">{t('backup:selectedFile')}: <strong className="font-medium text-foreground">{selectedFileName}</strong></p> : null}
          {mappingHeaders.length > 0 && !parsedImport ? (
            <div className="grid gap-3 rounded-lg bg-muted p-4" aria-label={t('backup:mappingTitle')}>
              <h3 className="text-sm font-semibold">{t('backup:mappingTitle')}</h3><p className="text-xs text-muted-foreground">{t('backup:mappingDescription')}</p>
              <div className="grid gap-3 sm:grid-cols-2">
                {importFields.map((field) => <label key={field} className="grid gap-1.5"><span className="text-sm font-medium">{t(`backup:fields.${field}`)}{requiredImportFields.includes(field) ? ' *' : ''}</span><select className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm" value={columnMapping[field] ?? '' } onChange={(event) => updateCsvMapping(field, event.target.value)}><option value="">{t('backup:chooseColumn')}</option>{mappingHeaders.map((header, index) => <option key={`${index}-${header}`} value={index}>{header || t('backup:unnamedColumn', { index: index + 1 })}</option>)}</select></label>)}
              </div>
              <Button type="button" onClick={finishManualMapping} disabled={requiredImportFields.some((field) => columnMapping[field] === undefined)}>{t('backup:useMapping')}</Button>
            </div>
          ) : null}
          {importError ? <p className="text-sm font-medium text-destructive" role="alert">{t(importError)}</p> : null}
          {parsedImport ? (
            <div className="space-y-4">
              <div className="flex items-start justify-between gap-3"><div><h3 className="text-sm font-semibold">{t('backup:previewTitle')}</h3><p className="mt-0.5 text-xs text-muted-foreground">{t('backup:previewCount', { count: parsedImport.rows.length })}</p></div><Badge variant="secondary">{parsedImport.format === 'csv' ? t('backup:csvFormat') : t('backup:bitwardenFormat')}</Badge></div>
              <p className="text-xs leading-relaxed text-muted-foreground">{sourceFileModifiedAt ? t('backup:importFileModifiedAt', { date: new Intl.DateTimeFormat(activeI18n.resolvedLanguage ?? 'en', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(sourceFileModifiedAt)) }) : t('backup:importFileTimeUnknown')}</p>
              <p className="text-xs leading-relaxed text-muted-foreground">{t('backup:passwordsMasked')} {t('backup:sourceFileReminder')}</p>
              <Button variant="outline" type="button" disabled={isCheckingImport || parsedImport.rows.length === 0} onClick={() => void buildPreview()}>{isCheckingImport ? t('backup:checkingDuplicates') : t('backup:checkDuplicates')}</Button>
              {importPreview ? (
                <>
                  <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground"><span>{t('backup:summaryNew', { count: importCounts.new })}</span><span>{t('backup:summarySame', { count: importPreview.filter((row) => row.kind === 'same').length })}</span><span>{t('backup:summaryChanged', { count: importCounts.changed })}</span><span>{t('backup:summarySkipped', { count: importCounts.skipped })}</span></div>
                  <div className="flex flex-col gap-2">
                    {importPreview.map(({ entry, kind, matchedName }) => (
                      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg bg-muted px-3 py-2" key={entry.sourceIndex}>
                        <div className="min-w-0 flex-1"><strong className="block truncate text-sm font-medium">{entry.name || entry.url || t('backup:unnamedEntry', { name: entry.username || t('backup:noWebsite') })}</strong><span className="block truncate text-xs text-muted-foreground">{entry.url || t('backup:noWebsite')} · {entry.username || t('backup:noUsername')}</span><small className="block text-xs text-muted-foreground">{t('backup:maskedPassword')}</small></div>
                        <div className="flex items-center gap-2">
                          {kind === 'same' ? <Badge variant="secondary">{t('backup:exactDuplicate')}</Badge> : null}
                          {kind === 'new' ? <Badge>{t('backup:newEntry')}</Badge> : null}
                          {kind === 'changed' ? <label className="flex flex-wrap items-center gap-2"><span className="text-xs text-muted-foreground">{t('backup:passwordDiffers', { name: matchedName ?? '' })}</span><select className="h-9 rounded-md border border-input bg-background px-3 text-sm" value={choices[entry.sourceIndex] ?? 'skip'} onChange={(event) => setChoices((current) => ({ ...current, [entry.sourceIndex]: event.target.value as ImportChoice }))}><option value="skip">{t('backup:skip')}</option><option value="update">{t('backup:updateExisting')}</option><option value="keep-both">{t('backup:keepBoth')}</option></select></label> : null}
                        </div>
                      </div>
                    ))}
                  </div>
                </>
              ) : null}
              <p className="text-xs leading-relaxed text-muted-foreground" role="status">{t('backup:importWriteUnavailable')}</p>
              <Button type="button" disabled>{t('backup:applyImport')}</Button>
            </div>
          ) : null}
          </CardContent>
        </Card>

      <Card aria-labelledby="settings-export-title">
        <CardHeader>
          <CardTitle id="settings-export-title" className="text-lg tracking-tight">{t('backup:exportTitle')}</CardTitle>
        </CardHeader>
          <CardContent className="space-y-4">
          <div className="flex items-start justify-between gap-3"><div><strong className="block text-sm font-medium">{t('backup:encryptedBackupTitle')}</strong><p className="mt-0.5 text-xs text-muted-foreground">{t('backup:encryptedBackupDescription')}</p></div><Badge variant="secondary">{t('backup:formatV3')}</Badge></div>
          {exportDoneFile ? <p className="text-sm text-muted-foreground" role="status">{t('backup:exportDone')}: <strong className="font-medium text-foreground">{exportDoneFile}</strong></p> : null}
          <div className="flex items-start justify-between gap-3"><div><strong className="block text-sm font-medium">{t('backup:restoreTitle')}</strong><p className="mt-0.5 text-xs text-muted-foreground">{t('backup:restoreDescription')}</p></div></div>
          <input ref={backupInputRef} className="visually-hidden" id="vault-backup-file" type="file" accept=".json,application/json" onChange={(event) => void onBackupFileChange(event)} />
          <div className="flex flex-wrap items-center gap-2"><Button asChild variant="outline"><label htmlFor="vault-backup-file">{t('backup:chooseBackupFile')}</label></Button><span className="text-sm text-muted-foreground">{backupFileName}</span></div>
          {backupError ? <p className="text-sm font-medium text-destructive" role="alert">{t(backupError)}</p> : null}
          {backupSummary ? <div className="grid gap-1 rounded-lg bg-muted p-3" role="status"><strong className="text-sm font-medium">{t('backup:containerRecognized', { version: backupSummary.version })}</strong><p className="text-xs text-muted-foreground">{t('backup:integrityNotChecked')}</p><span className="text-xs text-muted-foreground">{t('backup:restoreUnavailable')}</span></div> : null}
          </CardContent>
        <CardFooter className="border-t"><div className="min-w-0 flex-1 text-xs leading-relaxed text-muted-foreground">{t('backup:secretBoundary')}</div><Button type="button" onClick={openExportDialog} className="ml-auto">{t('backup:exportButton')}</Button></CardFooter>
        </Card>

      <Dialog open={exportDialogOpen} onOpenChange={(open) => { if (!open) closeExportDialog() }}>
        <DialogContent className="max-h-[calc(100dvh-4rem)] overflow-y-auto sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{t('backup:exportDialogTitle')}</DialogTitle>
            <DialogDescription>{t('backup:exportDialogDescription')}</DialogDescription>
          </DialogHeader>
          <div className="grid gap-3">
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="grid gap-1.5"><span className="text-sm font-medium">{t('backup:exportMasterPassword')}</span><Input type="password" value={exportMasterPassword} autoComplete="current-password" onChange={(event) => setExportMasterPassword(event.target.value)} /></label>
              <label className="grid gap-1.5"><span className="text-sm font-medium">{t('backup:exportRecoveryKey')}</span><Input type="password" value={exportRecoveryKey} autoComplete="off" placeholder={t('backup:exportRecoveryKeyPlaceholder')} onChange={(event) => setExportRecoveryKey(event.target.value)} /><span className="text-xs text-muted-foreground">{exportRecoveryKeyWordCount} / 24</span></label>
            </div>
            {exportError ? <p className="text-sm font-medium text-destructive" role="alert">{t(exportError)}</p> : null}
            <div className="flex flex-wrap items-center gap-2">
              <Button type="button" disabled={exportBusy || !exportMasterPassword || !exportRecoveryKey.trim()} onClick={() => void confirmExport()}>{exportBusy ? t('backup:backingUp') : t('backup:exportButton')}</Button>
              <Button variant="outline" type="button" onClick={closeExportDialog}>{t('backup:cancel')}</Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      <Card aria-labelledby="settings-cloud-title">
        <CardHeader>
          <CardTitle id="settings-cloud-title" className="text-lg tracking-tight">{t('backup:cloudTitle')}</CardTitle>
        </CardHeader>
          <CardContent className="space-y-4">
          <CloudBackupPanel user={user} items={items} exportBackup={onExportBackup} />
          </CardContent>
        </Card>

      <Card aria-labelledby="settings-autolock-title">
        <CardHeader>
          <CardTitle id="settings-autolock-title" className="text-lg tracking-tight">{t('settings:autoLockTitle')}</CardTitle>
        </CardHeader>
        <CardContent className="flex items-center justify-between gap-3"><label className="text-sm text-muted-foreground" htmlFor="settings-autolock-minutes">{t('settings:idleLabel')}</label><select id="settings-autolock-minutes" className="h-9 rounded-md border border-input bg-background px-3 text-sm" value={autoLockMinutes} onChange={(event) => void onAutoLockMinutesChange(Number(event.target.value))} aria-label={t('settings:autoLockTitle')}>{[5, 15, 30, 60].map((minutes) => <option key={minutes} value={minutes}>{minutes} {t('settings:minutes')}</option>)}</select></CardContent>
      </Card>
    </div>
  )
}
