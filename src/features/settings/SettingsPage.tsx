import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent } from 'react'
import { Lock } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { isLanguage, languages } from '../../i18n-config'
import i18n from '../../i18n'
import type { VaultIdentity, VaultItem, VaultListItem } from '../../client/contracts'
import { PasswordHealthDashboard } from '../password-security/PasswordSecurity'
import { getCsvHeaders, getImportFileModifiedAt, inspectBackupContainer, parseCsvWithMapping, parseImportText, type BackupContainerSummary, type ImportField, type ImportedVaultEntry, type ParsedImportFile } from './backup-local'
import { backupFilename } from './cloud-backup'
import { CloudBackupPanel } from './CloudBackupPanel'
import { Button } from '../../components/ui/button'
import { applyLanguagePreference, getLanguagePreference, type AppearancePreference, type LanguagePreference } from './preferences'
import './settings.css'

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

export function SettingsPage({ user, items, loadItem, onNavigate, appearancePreference, onAppearanceChange, onExportBackup, onExportBackupFull }: {
  user: VaultIdentity
  items: VaultListItem[]
  loadItem: (itemId: string) => Promise<VaultItem>
  onNavigate: (path: string) => void
  appearancePreference: AppearancePreference
  onAppearanceChange: (preference: AppearancePreference) => void
  /** KEK-only v3 container for cloud backup; null when the vault is locked. */
  onExportBackup: () => Promise<Uint8Array | null>
  /** Full v3 container (KEK + recovery-key wrappings) for manual export. */
  onExportBackupFull: (masterPassword: string, recoveryKey: string) => Promise<Uint8Array>
}) {
  const { t, i18n: activeI18n } = useTranslation(['settings', 'backup', 'vault'])
  const [languagePreference, setLanguagePreference] = useState<LanguagePreference>(getLanguagePreference)
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
  const csvSourceRef = useRef<string | null>(null)
  const importInputRef = useRef<HTMLInputElement>(null)
  const backupInputRef = useRef<HTMLInputElement>(null)
  const rootPath = `/users/${user.id}`
  const importCounts = useMemo(() => {
    const rows = importPreview ?? []
    return {
      new: rows.filter((row) => row.kind === 'new' || (row.kind === 'changed' && choices[row.entry.sourceIndex] === 'keep-both')).length,
      skipped: rows.filter((row) => row.kind === 'same' || (row.kind === 'changed' && choices[row.entry.sourceIndex] === 'skip')).length,
      changed: rows.filter((row) => row.kind === 'changed').length,
    }
  }, [choices, importPreview])

  useEffect(() => {
    const updatePreference = () => setLanguagePreference(getLanguagePreference())
    i18n.on('languageChanged', updatePreference)
    return () => { i18n.off('languageChanged', updatePreference) }
  }, [])

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

  const changeLanguage = (value: string) => {
    const nextPreference: LanguagePreference = value === 'system' || isLanguage(value) ? value : 'system'
    setLanguagePreference(nextPreference)
    void applyLanguagePreference(nextPreference)
  }

  return (
    <div className="settings-content">
      <section className="settings-section" aria-labelledby="settings-account-title">
        <div className="settings-section-heading"><span className="settings-section-icon" aria-hidden="true">◉</span><div><h2 id="settings-account-title">{t('settings:accountTitle')}</h2></div></div>
        <div className="settings-card settings-account-card">
          <div className="settings-account-avatar" aria-hidden="true">{user.email.slice(0, 1).toUpperCase()}</div>
          <div className="settings-account-copy"><strong>{user.email}</strong><small>{t('settings:accountId')} · {user.id}</small></div>
        </div>
      </section>

      <section className="settings-section" aria-labelledby="settings-server-title">
        <div className="settings-section-heading"><span className="settings-section-icon" aria-hidden="true">⌘</span><div><h2 id="settings-server-title">{t('settings:serverTitle')}</h2></div></div>
        <div className="settings-card settings-row-card">
          <div className="settings-row-leading"><span className="settings-cloud-mark" aria-hidden="true">S</span><div><strong>{t('settings:officialCloud')}</strong><span>{t('settings:v1ReadOnly')}</span></div></div>
          <span className="settings-readonly-pill">{t('settings:readOnly')}</span>
        </div>
      </section>

      <section className="settings-section" aria-labelledby="settings-device-title">
        <div className="settings-section-heading"><span className="settings-section-icon" aria-hidden="true">▣</span><div><h2 id="settings-device-title">{t('settings:devicesTitle')}</h2></div></div>
      </section>

      <section className="settings-section" aria-labelledby="settings-import-title">
        <div className="settings-section-heading"><span className="settings-section-icon" aria-hidden="true">⇧</span><div><h2 id="settings-import-title">{t('backup:importTitle')}</h2><p>{t('backup:importDescription')}</p></div></div>
        <div className="settings-card settings-data-card">
          <div className="settings-card-topline"><div><strong>{t('backup:localImportTitle')}</strong><p>{t('backup:localImportDescription')}</p></div><span className="settings-local-badge">{t('backup:localOnly')}</span></div>
          <div className="settings-file-actions">
            <input ref={importInputRef} className="visually-hidden" id="vault-import-file" type="file" accept=".csv,.json,text/csv,application/json" onChange={onImportFileChange} />
            <Button asChild className="button button-secondary"><label htmlFor="vault-import-file">{t('backup:chooseImportFile')}</label></Button>
            {parsedImport ? <Button className="security-button security-button--quiet" type="button" onClick={clearImportPreview}>{t('backup:clearImport')}</Button> : null}
          </div>
          {selectedFileName ? <p className="settings-file-name">{t('backup:selectedFile')}: <strong>{selectedFileName}</strong></p> : null}
          {mappingHeaders.length > 0 && !parsedImport ? (
            <div className="import-mapping" aria-label={t('backup:mappingTitle')}>
              <h3>{t('backup:mappingTitle')}</h3><p>{t('backup:mappingDescription')}</p>
              <div className="import-mapping-grid">
                {importFields.map((field) => <label key={field}><span>{t(`backup:fields.${field}`)}{requiredImportFields.includes(field) ? ' *' : ''}</span><select value={columnMapping[field] ?? ''} onChange={(event) => updateCsvMapping(field, event.target.value)}><option value="">{t('backup:chooseColumn')}</option>{mappingHeaders.map((header, index) => <option key={`${index}-${header}`} value={index}>{header || t('backup:unnamedColumn', { index: index + 1 })}</option>)}</select></label>)}
              </div>
              <Button className="button button-primary" type="button" onClick={finishManualMapping} disabled={requiredImportFields.some((field) => columnMapping[field] === undefined)}>{t('backup:useMapping')}</Button>
            </div>
          ) : null}
          {importError ? <p className="settings-inline-error" role="alert">{t(importError)}</p> : null}
          {parsedImport ? (
            <div className="import-preview-shell">
              <div className="import-preview-heading"><div><h3>{t('backup:previewTitle')}</h3><p>{t('backup:previewCount', { count: parsedImport.rows.length })}</p></div><span className="settings-local-badge">{parsedImport.format === 'csv' ? t('backup:csvFormat') : t('backup:bitwardenFormat')}</span></div>
              <p className="settings-security-note">{sourceFileModifiedAt ? t('backup:importFileModifiedAt', { date: new Intl.DateTimeFormat(activeI18n.resolvedLanguage ?? 'en', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(sourceFileModifiedAt)) }) : t('backup:importFileTimeUnknown')}</p>
              <p className="settings-security-note">{t('backup:passwordsMasked')} {t('backup:sourceFileReminder')}</p>
              <Button className="button button-secondary" type="button" disabled={isCheckingImport || parsedImport.rows.length === 0} onClick={() => void buildPreview()}>{isCheckingImport ? t('backup:checkingDuplicates') : t('backup:checkDuplicates')}</Button>
              {importPreview ? (
                <>
                  <div className="import-count-summary"><span>{t('backup:summaryNew', { count: importCounts.new })}</span><span>{t('backup:summarySame', { count: importPreview.filter((row) => row.kind === 'same').length })}</span><span>{t('backup:summaryChanged', { count: importCounts.changed })}</span><span>{t('backup:summarySkipped', { count: importCounts.skipped })}</span></div>
                  <div className="import-preview-list">
                    {importPreview.map(({ entry, kind, matchedName }) => (
                      <div className="import-preview-row" key={entry.sourceIndex}>
                        <div className="import-preview-main"><strong>{entry.name || entry.url || t('backup:unnamedEntry', { name: entry.username || t('backup:noWebsite') })}</strong><span>{entry.url || t('backup:noWebsite')} · {entry.username || t('backup:noUsername')}</span><small>{t('backup:maskedPassword')}</small></div>
                        <div className="import-preview-resolution">
                          {kind === 'same' ? <span className="import-result-pill is-same">{t('backup:exactDuplicate')}</span> : null}
                          {kind === 'new' ? <span className="import-result-pill is-new">{t('backup:newEntry')}</span> : null}
                          {kind === 'changed' ? <label><span>{t('backup:passwordDiffers', { name: matchedName ?? '' })}</span><select value={choices[entry.sourceIndex] ?? 'skip'} onChange={(event) => setChoices((current) => ({ ...current, [entry.sourceIndex]: event.target.value as ImportChoice }))}><option value="skip">{t('backup:skip')}</option><option value="update">{t('backup:updateExisting')}</option><option value="keep-both">{t('backup:keepBoth')}</option></select></label> : null}
                        </div>
                      </div>
                    ))}
                  </div>
                </>
              ) : null}
              <p className="settings-blocked-note" role="status">{t('backup:importWriteUnavailable')}</p>
              <Button className="button button-primary" type="button" disabled>{t('backup:applyImport')}</Button>
            </div>
          ) : null}
        </div>
      </section>

      <section className="settings-section" aria-labelledby="settings-export-title">
        <div className="settings-section-heading"><span className="settings-section-icon" aria-hidden="true">⇩</span><div><h2 id="settings-export-title">{t('backup:exportTitle')}</h2><p>{t('backup:exportDescription')}</p></div></div>
        <div className="settings-card settings-data-card">
          <div className="settings-card-topline"><div><strong>{t('backup:encryptedBackupTitle')}</strong><p>{t('backup:encryptedBackupDescription')}</p></div><span className="settings-local-badge">{t('backup:formatV3')}</span></div>
          <div className="settings-security-note">{t('backup:secretBoundary')}</div>
          <div className="settings-file-actions"><Button className="button button-primary" type="button" onClick={openExportDialog}>{t('backup:exportButton')}</Button></div>
          {exportDoneFile ? <p className="settings-file-name" role="status">{t('backup:exportDone')}: <strong>{exportDoneFile}</strong></p> : null}
          {exportDialogOpen ? (
            <div className="import-mapping" aria-label={t('backup:exportDialogTitle')}>
              <h3>{t('backup:exportDialogTitle')}</h3>
              <p>{t('backup:exportDialogDescription')}</p>
              <div className="export-dialog-form">
                <label><span>{t('backup:exportMasterPassword')}</span><input type="password" value={exportMasterPassword} autoComplete="current-password" onChange={(event) => setExportMasterPassword(event.target.value)} /></label>
                <label><span>{t('backup:exportRecoveryKey')}</span><input type="password" value={exportRecoveryKey} autoComplete="off" onChange={(event) => setExportRecoveryKey(event.target.value)} /></label>
              </div>
              {exportError ? <p className="settings-inline-error" role="alert">{t(exportError)}</p> : null}
              <div className="settings-file-actions">
                <Button className="button button-primary" type="button" disabled={exportBusy || !exportMasterPassword || !exportRecoveryKey.trim()} onClick={() => void confirmExport()}>{exportBusy ? t('backup:backingUp') : t('backup:exportButton')}</Button>
                <Button className="security-button security-button--quiet" type="button" onClick={closeExportDialog}>{t('backup:cancel')}</Button>
              </div>
            </div>
          ) : null}
          <div className="backup-restore-divider" />
          <div className="settings-card-topline"><div><strong>{t('backup:restoreTitle')}</strong><p>{t('backup:restoreDescription')}</p></div></div>
          <input ref={backupInputRef} className="visually-hidden" id="vault-backup-file" type="file" accept=".json,application/json" onChange={(event) => void onBackupFileChange(event)} />
          <div className="settings-file-actions"><Button asChild className="button button-secondary"><label htmlFor="vault-backup-file">{t('backup:chooseBackupFile')}</label></Button><span className="settings-file-name">{backupFileName}</span></div>
          {backupError ? <p className="settings-inline-error" role="alert">{t(backupError)}</p> : null}
          {backupSummary ? <div className="backup-inspection-result" role="status"><strong>{t('backup:containerRecognized', { version: backupSummary.version })}</strong><p>{t('backup:integrityNotChecked')}</p><span>{t('backup:restoreUnavailable')}</span></div> : null}
        </div>
      </section>

      <section className="settings-section" aria-labelledby="settings-cloud-title">
        <div className="settings-section-heading"><span className="settings-section-icon" aria-hidden="true">☁</span><div><h2 id="settings-cloud-title">{t('backup:cloudTitle')}</h2><p>{t('backup:cloudDescription')}</p></div></div>
        <div className="settings-card settings-data-card">
          <CloudBackupPanel user={user} items={items} exportBackup={onExportBackup} />
        </div>
      </section>

      <section className="settings-section" aria-labelledby="settings-health-title">
        <div className="settings-section-heading"><span className="settings-section-icon" aria-hidden="true">✳</span><div><h2 id="settings-health-title">{t('settings:healthTitle')}</h2><p>{t('settings:healthDescription')}</p></div></div>
        <div className="settings-card settings-row-card"><div><strong>{t('vault:health.title')}</strong><span>{t('settings:healthLocal')}</span></div><Button className="security-button security-button--quiet" type="button" onClick={() => onNavigate(`${rootPath}/settings/health`)}>{t('settings:openHealth')}</Button></div>
      </section>

      <section className="settings-section" aria-labelledby="settings-autolock-title">
        <div className="settings-section-heading"><span className="settings-section-icon" aria-hidden="true"><Lock size={14} aria-hidden="true" /></span><div><h2 id="settings-autolock-title">{t('settings:autoLockTitle')}</h2><p>{t('settings:autoLockDescription')}</p></div></div>
        <div className="settings-card settings-policy-grid"><div><span>{t('settings:idleLabel')}</span><strong>{t('settings:fifteenMinutes')}</strong></div></div>
      </section>

      <section className="settings-section" aria-labelledby="settings-language-title">
        <div className="settings-section-heading"><span className="settings-section-icon" aria-hidden="true">文</span><div><h2 id="settings-language-title">{t('settings:languageTitle')}</h2><p>{t('settings:languageDescription')}</p></div></div>
        <div className="settings-card settings-preference-row"><div><strong>{t('settings:languageTitle')}</strong><span>{t('settings:preferenceLocal')}</span></div><label className="settings-select-control"><span className="visually-hidden">{t('settings:languageTitle')}</span><select value={languagePreference} onChange={(event) => changeLanguage(event.target.value)}><option value="system">{t('settings:followSystem')}</option>{languages.map((language) => <option value={language.code} key={language.code}>{language.label}</option>)}</select></label></div>
      </section>

      <section className="settings-section" aria-labelledby="settings-appearance-title">
        <div className="settings-section-heading"><span className="settings-section-icon" aria-hidden="true">◐</span><div><h2 id="settings-appearance-title">{t('settings:appearanceTitle')}</h2><p>{t('settings:appearanceDescription')}</p></div></div>
        <div className="settings-card settings-preference-row"><div><strong>{t('settings:appearanceTitle')}</strong><span>{t('settings:preferenceLocal')}</span></div><div className="appearance-choice-group" role="group" aria-label={t('settings:appearanceTitle')}>{(['system', 'light', 'dark'] as const).map((value) => <button key={value} type="button" className={appearancePreference === value ? 'is-selected' : ''} aria-pressed={appearancePreference === value} onClick={() => onAppearanceChange(value)}>{t(`settings:${value === 'system' ? 'followSystem' : value}`)}</button>)}</div></div>
      </section>
    </div>
  )
}

export function SettingsHealthPage({ items, loadItem }: {
  items: VaultListItem[]
  loadItem: (itemId: string) => Promise<VaultItem>
}) {
  return <PasswordHealthDashboard items={items} loadItem={loadItem} />
}
