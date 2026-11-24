import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { VaultItem, VaultListItem } from '../../client/contracts'
import {
  assessPasswordHealth,
  DEFAULT_PASSWORD_OPTIONS,
  findReusedPasswordItemIds,
  generateVerifiedPassword,
  type PasswordAssessment,
  type PasswordCharacterClass,
  type PasswordGeneratorOptions,
} from './password-security'
import './password-security.css'

interface PasswordGeneratorPageProps {
  onBack: () => void
  onCopy: (password: string, label: string) => void
}

interface PasswordHealthPageProps {
  items: VaultListItem[]
  loadItem: (itemId: string) => Promise<VaultItem>
  onBack: () => void
}

interface PasswordHealthInlineProps {
  itemId: string
  password: string
  itemName: string
  items: VaultListItem[]
  loadItem: (itemId: string) => Promise<VaultItem>
}

interface PasswordHealthRow {
  id: string
  name: string
  assessment: PasswordAssessment
}

const CHARACTER_OPTIONS: Array<{ key: PasswordCharacterClass; label: string }> = [
  { key: 'lowercase', label: 'lowercase' },
  { key: 'uppercase', label: 'uppercase' },
  { key: 'numbers', label: 'numbers' },
  { key: 'symbols', label: 'symbols' },
]

function PasswordAssessmentView({ assessment }: { assessment: PasswordAssessment }) {
  const { t } = useTranslation('vault')
  return (
    <div className="security-assessment" aria-live="polite">
      <span className={`security-badge security-badge--${assessment.leakStatus === 'unavailable' && assessment.strength !== 'must-change' ? 'unknown' : assessment.strength}`}>
        {assessment.leakStatus === 'unavailable' && assessment.strength !== 'must-change' ? t('health.unverified') : t(`strength.${assessment.strength}`)}
      </span>
      <ul className="security-findings">
        <li>{t('health.lengthAndClasses', { length: assessment.length, count: assessment.characterClassCount })}</li>
        {assessment.commonWeak ? <li>{t('health.commonWeak')}</li> : null}
        {assessment.reused ? <li>{t('health.reused')}</li> : null}
        {assessment.leakStatus === 'leaked' ? <li>{t('health.leaked')}</li> : null}
        {assessment.leakStatus === 'unavailable' ? <li className="security-warning">{t('health.unavailable')}</li> : null}
      </ul>
      {assessment.strength === 'acceptable' ? <p className="security-recommendation">{t('health.acceptableHint')}</p> : null}
    </div>
  )
}

export function PasswordHealthInline({ itemId, password, itemName, items, loadItem }: PasswordHealthInlineProps) {
  const { t } = useTranslation('vault')
  const [assessment, setAssessment] = useState<PasswordAssessment | null>(null)
  const [checking, setChecking] = useState(false)
  const [loadFailed, setLoadFailed] = useState(false)
  const controllerRef = useRef<AbortController | null>(null)

  useEffect(() => () => controllerRef.current?.abort(), [])

  const checkPassword = async () => {
    controllerRef.current?.abort()
    const controller = new AbortController()
    controllerRef.current = controller
    setChecking(true)
    setAssessment(null)
    setLoadFailed(false)
    try {
      const passwords = [{ id: itemId, password }]
      for (const item of items) {
        if (controller.signal.aborted) return
        if (item.id === itemId) continue
        const detail = await loadItem(item.id)
        passwords.push({ id: detail.id, password: detail.password })
      }
      if (controller.signal.aborted) return
      const reusedIds = findReusedPasswordItemIds(passwords)
      const result = await assessPasswordHealth(password, reusedIds.has(itemId), { signal: controller.signal })
      if (!controller.signal.aborted) setAssessment(result)
    } catch {
      // Aborted or unavailable detail loads are discarded; no password or hash is logged.
      if (!controller.signal.aborted) setLoadFailed(true)
    } finally {
      if (!controller.signal.aborted) setChecking(false)
    }
  }

  return (
    <section className="security-inline" aria-label={t('health.itemCheckLabel', { name: itemName })}>
      <div className="security-inline-copy">
        <strong>{t('health.itemCheckTitle')}</strong>
        <span>{t('health.localOnlyHint')}</span>
      </div>
      <button className="security-button security-button--quiet" type="button" onClick={() => void checkPassword()} disabled={checking}>
        {checking ? t('health.checking') : t('health.checkPassword')}
      </button>
      {loadFailed ? <p className="security-warning" role="alert">{t('health.loadFailed')}</p> : null}
      {assessment ? <PasswordAssessmentView assessment={assessment} /> : null}
    </section>
  )
}

export function PasswordHealthDashboard({ items, loadItem, onBack }: PasswordHealthPageProps) {
  const { t } = useTranslation('vault')
  const [rows, setRows] = useState<PasswordHealthRow[]>([])
  const [phase, setPhase] = useState<'idle' | 'loading' | 'checking' | 'complete' | 'error'>('idle')
  const [progress, setProgress] = useState(0)
  const controllerRef = useRef<AbortController | null>(null)
  const progressText = useMemo(() => t('health.progress', { current: progress, total: items.length }), [items.length, progress, t])

  useEffect(() => () => controllerRef.current?.abort(), [])

  const runHealthCheck = async () => {
    controllerRef.current?.abort()
    const controller = new AbortController()
    controllerRef.current = controller
    setRows([])
    setProgress(0)
    setPhase('loading')

    try {
      const details: Array<{ id: string; name: string; password: string }> = []
      for (const item of items) {
        if (controller.signal.aborted) return
        const detail = await loadItem(item.id)
        details.push({ id: item.id, name: item.name, password: detail.password })
      }

      if (controller.signal.aborted) return
      const reusedIds = findReusedPasswordItemIds(details)
      setPhase('checking')
      const completedRows: PasswordHealthRow[] = []
      for (const [index, detail] of details.entries()) {
        const assessment = await assessPasswordHealth(detail.password, reusedIds.has(detail.id), { signal: controller.signal })
        if (controller.signal.aborted) return
        completedRows.push({ id: detail.id, name: detail.name, assessment })
        setRows([...completedRows])
        setProgress(index + 1)
      }
      if (!controller.signal.aborted) setPhase('complete')
    } catch {
      if (!controller.signal.aborted) setPhase('error')
    }
  }

  const isWorking = phase === 'loading' || phase === 'checking'

  return (
    <div className="vault-content security-page">
      <button className="back-button security-back" type="button" onClick={onBack}><span aria-hidden="true">←</span>{t('vault:backToVault')}</button>
      <header className="security-page-heading">
        <p className="eyebrow">{t('health.settingsEyebrow')}</p>
        <h1>{t('health.title')}</h1>
        <p className="vault-page-subtitle">{t('health.description')}</p>
      </header>
      <section className="security-panel" aria-labelledby="health-panel-title">
        <div className="security-panel-heading">
          <div>
            <h2 id="health-panel-title">{t('health.settingsTitle')}</h2>
            <p>{t('health.localOnlyHint')}</p>
          </div>
          <button className="security-button security-button--primary" type="button" onClick={() => void runHealthCheck()} disabled={isWorking || items.length === 0}>
            {isWorking ? t('health.checking') : rows.length ? t('health.checkAgain') : t('health.runHealthCheck')}
          </button>
        </div>
        <p className="security-privacy-note">{t('health.privacyNote')}</p>
        {items.length === 0 ? <p className="security-empty">{t('health.emptyVault')}</p> : null}
        {isWorking ? (
          <div className="security-progress" role="status" aria-live="polite">
            <span>{phase === 'loading' ? t('health.loadingDetails') : progressText}</span>
            {phase === 'checking' ? <progress max={Math.max(items.length, 1)} value={progress} /> : null}
          </div>
        ) : null}
        {phase === 'error' ? <p className="security-warning" role="alert">{t('health.loadFailed')}</p> : null}
        {phase === 'complete' && rows.length === 0 ? <p className="security-empty">{t('health.noResults')}</p> : null}
        {rows.length ? (
          <ul className="security-result-list">
            {rows.map((row) => (
              <li className="security-result-row" key={row.id}>
                <div className="security-result-name"><strong>{row.name}</strong><small>{t('health.lengthAndClasses', { length: row.assessment.length, count: row.assessment.characterClassCount })}</small></div>
                <div className="security-result-badges">
                  <span className={`security-badge security-badge--${row.assessment.leakStatus === 'unavailable' && row.assessment.strength !== 'must-change' ? 'unknown' : row.assessment.strength}`}>{row.assessment.leakStatus === 'unavailable' && row.assessment.strength !== 'must-change' ? t('health.unverified') : t(`strength.${row.assessment.strength}`)}</span>
                  {row.assessment.reused ? <span className="security-badge security-badge--reused">{t('health.reusedBadge')}</span> : null}
                </div>
                <ul className="security-findings">
                  {row.assessment.commonWeak ? <li>{t('health.commonWeak')}</li> : null}
                  {row.assessment.reused ? <li>{t('health.reused')}</li> : null}
                  {row.assessment.leakStatus === 'leaked' ? <li>{t('health.leaked')}</li> : null}
                  {row.assessment.leakStatus === 'unavailable' ? <li className="security-warning">{t('health.unavailable')}</li> : null}
                  {row.assessment.strength === 'acceptable' ? <li>{t('health.acceptableHint')}</li> : null}
                </ul>
              </li>
            ))}
          </ul>
        ) : null}
      </section>
    </div>
  )
}

export function PasswordGeneratorPage({ onBack, onCopy }: PasswordGeneratorPageProps) {
  const { t } = useTranslation('vault')
  const [options, setOptions] = useState<PasswordGeneratorOptions>(DEFAULT_PASSWORD_OPTIONS)
  const [password, setPassword] = useState<string | null>(null)
  const [phase, setPhase] = useState<'idle' | 'generating' | 'generated' | 'exhausted' | 'unavailable'>('idle')
  const [notice, setNotice] = useState('')
  const controllerRef = useRef<AbortController | null>(null)
  const classCount = CHARACTER_OPTIONS.filter(({ key }) => options[key]).length

  useEffect(() => () => controllerRef.current?.abort(), [])

  const updateLength = (length: number) => {
    setOptions((current) => ({ ...current, length }))
    setPassword(null)
    setPhase('idle')
    setNotice('')
  }

  const updateCharacterClass = (key: PasswordCharacterClass, enabled: boolean) => {
    if (!enabled && classCount <= 2) {
      setNotice(t('generator.twoClassesRequired'))
      return
    }
    setOptions((current) => ({ ...current, [key]: enabled }))
    setPassword(null)
    setPhase('idle')
    setNotice('')
  }

  const createPassword = async () => {
    controllerRef.current?.abort()
    const controller = new AbortController()
    controllerRef.current = controller
    setPassword(null)
    setPhase('generating')
    setNotice('')
    try {
      const result = await generateVerifiedPassword(options, { signal: controller.signal })
      if (controller.signal.aborted) return
      if (result.password) {
        setPassword(result.password)
        setPhase('generated')
      } else {
        setPhase('exhausted')
        setNotice(t('generator.exhausted', { attempts: result.attempts }))
      }
    } catch {
      if (!controller.signal.aborted) {
        setPhase('unavailable')
        setNotice(t('generator.verificationUnavailable'))
      }
    }
  }

  return (
    <div className="vault-content security-page">
      <button className="back-button security-back" type="button" onClick={onBack}><span aria-hidden="true">←</span>{t('generator.backToVault')}</button>
      <header className="security-page-heading">
        <p className="eyebrow">{t('generator.eyebrow')}</p>
        <h1>{t('generator.title')}</h1>
        <p className="vault-page-subtitle">{t('generator.description')}</p>
      </header>
      <section className="security-panel generator-panel" aria-labelledby="generator-panel-title">
        <h2 id="generator-panel-title">{t('generator.settingsTitle')}</h2>
        <label className="security-length-label" htmlFor="security-password-length">
          <span>{t('generator.length')}</span><strong>{t('generator.lengthValue', { length: options.length })}</strong>
        </label>
        <input
          id="security-password-length"
          className="security-range"
          type="range"
          min={12}
          max={64}
          step={1}
          value={options.length}
          onChange={(event) => updateLength(Number(event.target.value))}
          aria-valuetext={t('generator.lengthValue', { length: options.length })}
          disabled={phase === 'generating'}
        />
        <fieldset className="security-class-options" disabled={phase === 'generating'}>
          <legend>{t('generator.characterClasses')}</legend>
          <div className="security-class-grid">
            {CHARACTER_OPTIONS.map(({ key, label }) => (
              <label className="security-checkbox" key={key}>
                <input type="checkbox" checked={options[key]} onChange={(event) => updateCharacterClass(key, event.target.checked)} />
                <span>{t(`generator.classes.${label}`)}</span>
              </label>
            ))}
          </div>
          <p className="security-help">{t('generator.twoClassesRequired')}</p>
        </fieldset>
        <button className="security-button security-button--primary security-generate" type="button" onClick={() => void createPassword()} disabled={phase === 'generating' || classCount < 2}>
          {phase === 'generating' ? t('generator.generating') : t('generator.generate')}
        </button>
        {notice ? <p className={`security-notice ${phase === 'unavailable' ? 'security-warning' : ''}`} role="status">{notice}</p> : null}
        {password ? (
          <div className="security-generated-result">
            <label htmlFor="security-generated-password">{t('generator.resultLabel')}</label>
            <div className="security-password-output">
              <input id="security-generated-password" type="text" value={password} readOnly autoComplete="off" spellCheck={false} />
              <button className="security-button security-button--quiet" type="button" onClick={() => onCopy(password, t('generator.passwordLabel'))}>{t('generator.copy')}</button>
            </div>
            <p>{t('generator.verifiedHint')}</p>
          </div>
        ) : null}
      </section>
    </div>
  )
}
