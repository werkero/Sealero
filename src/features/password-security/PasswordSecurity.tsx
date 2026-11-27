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
import { Badge } from '../../components/ui/badge'
import { Button } from '../../components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card'
import { Checkbox } from '../../components/ui/checkbox'
import { Input } from '../../components/ui/input'
import { Label } from '../../components/ui/label'

interface PasswordGeneratorPageProps {
  onCopy: (password: string, label: string) => void
}

interface PasswordHealthPageProps {
  items: VaultListItem[]
  loadItem: (itemId: string) => Promise<VaultItem>
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

function strengthBadgeVariant(strength: PasswordAssessment['strength'], unknown: boolean): 'default' | 'secondary' | 'destructive' | 'outline' {
  if (unknown) return 'outline'
  if (strength === 'must-change') return 'destructive'
  if (strength === 'acceptable') return 'secondary'
  return 'default'
}

function PasswordAssessmentView({ assessment }: { assessment: PasswordAssessment }) {
  const { t } = useTranslation('vault')
  return (
    <div className="grid gap-2" aria-live="polite">
      <Badge variant={strengthBadgeVariant(assessment.strength, assessment.leakStatus === 'unavailable' && assessment.strength !== 'must-change')} className="w-fit">
        {assessment.leakStatus === 'unavailable' && assessment.strength !== 'must-change' ? t('health.unverified') : t(`strength.${assessment.strength}`)}
      </Badge>
      <ul className="grid gap-1 text-xs text-muted-foreground">
        <li>{t('health.lengthAndClasses', { length: assessment.length, count: assessment.characterClassCount })}</li>
        {assessment.commonWeak ? <li>{t('health.commonWeak')}</li> : null}
        {assessment.reused ? <li>{t('health.reused')}</li> : null}
        {assessment.leakStatus === 'leaked' ? <li>{t('health.leaked')}</li> : null}
        {assessment.leakStatus === 'unavailable' ? <li className="font-medium text-amber-600 dark:text-amber-400">{t('health.unavailable')}</li> : null}
      </ul>
      {assessment.strength === 'acceptable' ? <p className="text-xs leading-relaxed text-muted-foreground">{t('health.acceptableHint')}</p> : null}
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
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg bg-muted px-4 py-3" aria-label={t('health.itemCheckLabel', { name: itemName })}>
      <div className="min-w-0 flex-1">
        <strong className="block text-sm font-medium">{t('health.itemCheckTitle')}</strong>
        <span className="block text-xs text-muted-foreground">{t('health.localOnlyHint')}</span>
      </div>
      <Button variant="outline" type="button" onClick={() => void checkPassword()} disabled={checking}>
        {checking ? t('health.checking') : t('health.checkPassword')}
      </Button>
      {loadFailed ? <p className="w-full text-xs font-medium text-destructive" role="alert">{t('health.loadFailed')}</p> : null}
      {assessment ? <div className="w-full"><PasswordAssessmentView assessment={assessment} /></div> : null}
    </div>
  )
}

export function PasswordHealthDashboard({ items, loadItem }: PasswordHealthPageProps) {
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
    <div className="w-full space-y-4 px-[clamp(20px,4vw,48px)] pb-10 pt-8">
      <Card>
        <CardHeader>
          <CardTitle id="health-panel-title">{t('health.settingsTitle')}</CardTitle>
          <CardDescription>{t('health.localOnlyHint')}</CardDescription>
          <CardAction>
            <Button type="button" onClick={() => void runHealthCheck()} disabled={isWorking || items.length === 0}>
              {isWorking ? t('health.checking') : rows.length ? t('health.checkAgain') : t('health.runHealthCheck')}
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-xs leading-relaxed text-muted-foreground">{t('health.privacyNote')}</p>
          {items.length === 0 ? <p className="py-8 text-center text-sm text-muted-foreground">{t('health.emptyVault')}</p> : null}
          {isWorking ? (
            <div className="space-y-2" role="status" aria-live="polite">
              <span className="text-sm text-muted-foreground">{phase === 'loading' ? t('health.loadingDetails') : progressText}</span>
              {phase === 'checking' ? <div className="h-1.5 overflow-hidden rounded-full bg-muted"><span className="block h-full bg-primary transition-all" style={{ width: `${(progress / Math.max(items.length, 1)) * 100}%` }} /></div> : null}
            </div>
          ) : null}
          {phase === 'error' ? <p className="text-sm font-medium text-destructive" role="alert">{t('health.loadFailed')}</p> : null}
          {phase === 'complete' && rows.length === 0 ? <p className="py-8 text-center text-sm text-muted-foreground">{t('health.noResults')}</p> : null}
          {rows.length ? (
            <ul className="flex flex-col gap-2">
              {rows.map((row) => (
                <li className="grid gap-2 rounded-lg bg-muted px-4 py-3" key={row.id}>
                  <div className="flex flex-wrap items-baseline justify-between gap-2"><strong className="text-sm font-medium">{row.name}</strong><small className="text-xs text-muted-foreground">{t('health.lengthAndClasses', { length: row.assessment.length, count: row.assessment.characterClassCount })}</small></div>
                  <div className="flex flex-wrap gap-2">
                    <Badge variant={strengthBadgeVariant(row.assessment.strength, row.assessment.leakStatus === 'unavailable' && row.assessment.strength !== 'must-change')}>{row.assessment.leakStatus === 'unavailable' && row.assessment.strength !== 'must-change' ? t('health.unverified') : t(`strength.${row.assessment.strength}`)}</Badge>
                    {row.assessment.reused ? <Badge variant="secondary">{t('health.reusedBadge')}</Badge> : null}
                  </div>
                  <ul className="grid gap-1 text-xs text-muted-foreground">
                    {row.assessment.commonWeak ? <li>{t('health.commonWeak')}</li> : null}
                    {row.assessment.reused ? <li>{t('health.reused')}</li> : null}
                    {row.assessment.leakStatus === 'leaked' ? <li>{t('health.leaked')}</li> : null}
                    {row.assessment.leakStatus === 'unavailable' ? <li className="font-medium text-amber-600 dark:text-amber-400">{t('health.unavailable')}</li> : null}
                    {row.assessment.strength === 'acceptable' ? <li>{t('health.acceptableHint')}</li> : null}
                  </ul>
                </li>
              ))}
            </ul>
          ) : null}
        </CardContent>
      </Card>
    </div>
  )
}

export function PasswordGeneratorPage({ onCopy }: PasswordGeneratorPageProps) {
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
    <div className="w-full space-y-4 px-[clamp(20px,4vw,48px)] pb-10 pt-8">
      <Card>
        <CardHeader>
          <CardTitle id="generator-panel-title">{t('generator.settingsTitle')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-2">
            <label className="flex items-center justify-between text-sm" htmlFor="security-password-length">
              <span className="font-medium">{t('generator.length')}</span><strong>{t('generator.lengthValue', { length: options.length })}</strong>
            </label>
            <input
              id="security-password-length"
              className="w-full accent-primary"
              type="range"
              min={12}
              max={64}
              step={1}
              value={options.length}
              onChange={(event) => updateLength(Number(event.target.value))}
              aria-valuetext={t('generator.lengthValue', { length: options.length })}
              disabled={phase === 'generating'}
            />
          </div>
          <fieldset className="grid gap-2" disabled={phase === 'generating'}>
            <legend className="text-sm font-medium">{t('generator.characterClasses')}</legend>
            <div className="grid grid-cols-2 gap-2">
              {CHARACTER_OPTIONS.map(({ key, label }) => (
                <Label className="flex items-center gap-2 rounded-lg bg-muted px-3 py-2 text-sm font-normal" key={key}>
                  <Checkbox checked={options[key]} onCheckedChange={(checked) => updateCharacterClass(key, checked === true)} />
                  {t(`generator.classes.${label}`)}
                </Label>
              ))}
            </div>
            <p className="text-xs text-muted-foreground">{t('generator.twoClassesRequired')}</p>
          </fieldset>
          <Button className="w-full" type="button" onClick={() => void createPassword()} disabled={phase === 'generating' || classCount < 2}>
            {phase === 'generating' ? t('generator.generating') : t('generator.generate')}
          </Button>
          {notice ? <p className={phase === 'unavailable' ? 'text-sm font-medium text-destructive' : 'text-sm text-muted-foreground'} role="status">{notice}</p> : null}
          {password ? (
            <div className="grid gap-2">
              <label className="text-sm font-medium" htmlFor="security-generated-password">{t('generator.resultLabel')}</label>
              <div className="flex gap-2">
                <Input id="security-generated-password" type="text" value={password} readOnly autoComplete="off" spellCheck={false} className="font-mono" />
                <Button variant="outline" type="button" onClick={() => onCopy(password, t('generator.passwordLabel'))}>{t('generator.copy')}</Button>
              </div>
              <p className="text-xs text-muted-foreground">{t('generator.verifiedHint')}</p>
            </div>
          ) : null}
        </CardContent>
      </Card>
    </div>
  )
}
