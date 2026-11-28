import { useEffect, useState, type FormEvent } from 'react'
import { Copy, Download, Eye, EyeOff, Printer } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { AuthShell } from '../App'
import { Checkbox } from '../components/ui/checkbox'
import type { VaultClient, VaultIdentity } from '../client/contracts'
import { VaultApiError } from '../client/http-vault-client'
import {
  deriveKek,
  generateRecoveryKey,
  KDF_PARAMS_P0,
  kdfParamsToCanonicalJson,
  randomBytes,
  recoveryKeyFileContent,
  toBase64,
  wrapDekForServer,
} from '../client/crypto'
import type { AppearancePreference } from '../features/settings/preferences'

/** Picks `count` distinct random positions (0-based) out of `total`. */
function pickRandomPositions(total: number, count: number): number[] {
  const positions = new Set<number>()
  while (positions.size < count) {
    positions.add(Math.floor(Math.random() * total))
  }
  return [...positions].sort((a, b) => a - b)
}

type SetupStep = 'master' | 'recovery'

/**
 * The master-password + recovery-key steps shared by registration and by
 * the vault-setup flow for accounts that never finished registering.
 * The caller supplies how to obtain the logged-in user id: registration
 * logs in first (it only has the email + login password), while the setup
 * page already has the session. On completion the caller navigates onward
 * (normally to the unlock page).
 */
export function VaultSetupForm({ vaultClient, resolveUserId, onComplete }: {
  vaultClient: VaultClient
  resolveUserId: () => Promise<string>
  onComplete: (userId: string) => void
}) {
  const { t } = useTranslation(['common', 'auth'])
  const [step, setStep] = useState<SetupStep>('master')
  const [masterPassword, setMasterPassword] = useState('')
  const [confirmMasterPassword, setConfirmMasterPassword] = useState('')
  const [masterVisible, setMasterVisible] = useState(false)
  const [recoveryKey, setRecoveryKey] = useState('')
  const [savedConfirmed, setSavedConfirmed] = useState(false)
  const [recoveryStage, setRecoveryStage] = useState<'words' | 'confirm'>('words')
  const [copied, setCopied] = useState(false)
  const [confirmPositions, setConfirmPositions] = useState<number[]>([])
  const [confirmWords, setConfirmWords] = useState<string[]>(['', '', ''])
  const [userId, setUserId] = useState('')
  const [errorKey, setErrorKey] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submitMaster = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setErrorKey(null)
    if (masterPassword.length < 8) {
      setErrorKey('masterPasswordTooShort')
      return
    }
    if (masterPassword !== confirmMasterPassword) {
      setErrorKey('masterPasswordMismatch')
      return
    }
    setBusy(true)
    try {
      // Resolve the logged-in user id (registration logs in here; the setup
      // page already has the session).
      const id = await resolveUserId()
      setUserId(id)
      // Consent is required before the vault-key upload (System Design §5.1).
      const policyVersion = await vaultClient.fetchPolicyVersion()
      await vaultClient.submitConsent(policyVersion)
      // Create the vault key: a fresh DEK, KEK-wrapped with the master password.
      const dek = randomBytes(32)
      const kdfSalt = randomBytes(16)
      const kek = await deriveKek(masterPassword, toBase64(kdfSalt), KDF_PARAMS_P0)
      const wrapped = await wrapDekForServer(kek, id, 1, dek)
      await vaultClient.uploadVaultKey({
        wrapped_dek: wrapped.wrapped_dek,
        nonce: wrapped.nonce,
        kdf_salt: toBase64(kdfSalt),
        kdf_params: kdfParamsToCanonicalJson(KDF_PARAMS_P0),
        dek_version: 1,
        master_password_version: 1,
        expected_wrapping_state_hash: null,
      })
      const words = await generateRecoveryKey()
      setRecoveryKey(words)
      setConfirmPositions(pickRandomPositions(24, 3))
      setConfirmWords(['', '', ''])
      setStep('recovery')
    } catch (error) {
      if (error instanceof VaultApiError && error.code === 'rate_limited') setErrorKey('registerRateLimited')
      else if (error instanceof VaultApiError && error.code === 'consent_required') setErrorKey('registerConsentRequired')
      else setErrorKey('registerSetupFailed')
    } finally {
      setBusy(false)
    }
  }

  const submitRecovery = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setErrorKey(null)
    const words = recoveryKey.split(' ')
    const matches = confirmPositions.every((position, index) => {
      const expected = words[position]
      const entered = (confirmWords[index] ?? '').trim().toLowerCase()
      return expected !== undefined && entered !== '' && entered === expected
    })
    if (!matches) {
      setErrorKey('recoveryKeyMismatch')
      return
    }
    onComplete(userId)
  }

  const recoveryWords = recoveryKey ? recoveryKey.split(' ') : []

  const downloadRecoveryKey = () => {
    const blob = new Blob([recoveryKeyFileContent(recoveryKey)], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'sealero-recovery-key.txt'
    document.body.appendChild(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(url)
  }

  const copyRecoveryKey = async () => {
    try {
      await navigator.clipboard.writeText(recoveryKey)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 2000)
    } catch {
      // Clipboard unavailable (e.g. insecure context); the user can still download.
    }
  }

  const printRecoveryKey = () => {
    window.print()
  }

  if (step === 'recovery' && recoveryStage === 'words') {
    return (
      <>
        <p className="auth-subtitle">{t('auth:recoveryKeySubtitle')}</p>
        <ol className="recovery-words">
          {recoveryWords.map((word, index) => (
            <li key={`${index}-${word}`}><span className="recovery-word-index">{index + 1}</span><span>{word}</span></li>
          ))}
        </ol>
        <div className="mt-4 flex gap-2">
          <button className="button button-secondary min-w-0 flex-1" type="button" onClick={downloadRecoveryKey}><Download className="size-4 shrink-0" />{t('auth:downloadRecoveryKeyButton')}</button>
          <button className="button button-secondary min-w-0 flex-1" type="button" onClick={copyRecoveryKey}><Copy className="size-4 shrink-0" />{copied ? t('auth:copied') : t('auth:copyRecoveryKeyButton')}</button>
          <button className="button button-secondary min-w-0 flex-1" type="button" onClick={printRecoveryKey}><Printer className="size-4 shrink-0" />{t('auth:printRecoveryKeyButton')}</button>
        </div>
        <label className="mt-4 flex cursor-pointer items-center gap-2 text-sm">
          <Checkbox checked={savedConfirmed} onCheckedChange={(checked) => setSavedConfirmed(checked === true)} />
          <span>{t('auth:savedRecoveryKeyLabel')}</span>
        </label>
        <button className="button button-primary button-full mt-4 disabled:opacity-50" type="button" disabled={!savedConfirmed} onClick={() => setRecoveryStage('confirm')}>{t('auth:nextButton')}</button>
      </>
    )
  }

  if (step === 'recovery') {
    return (
      <form className="auth-form gap-4" onSubmit={submitRecovery}>
        <p className="field-label">{t('auth:recoveryKeyConfirmLabel')}</p>
        {confirmPositions.map((position, index) => (
          <div key={position} className="recovery-confirm-row">
            <label className="field-label" htmlFor={`recovery-word-${position}`}>{t('auth:recoveryKeyWordLabel', { n: position + 1 })}</label>
            <input
              className="text-input"
              id={`recovery-word-${position}`}
              name={`recovery-word-${position}`}
              type="text"
              autoComplete="off"
              placeholder={t('auth:recoveryKeyWordPlaceholder')}
              value={confirmWords[index] ?? ''}
              onChange={(event) => {
                const next = [...confirmWords]
                next[index] = event.target.value
                setConfirmWords(next)
              }}
              required
            />
          </div>
        ))}
        {errorKey ? <p className="auth-error" role="alert">{t(`auth:${errorKey}`)}</p> : null}
        <div className="flex gap-2">
          <button className="button button-secondary min-w-0 flex-1" type="button" onClick={() => setRecoveryStage('words')}>{t('auth:previousButton')}</button>
          <button className="button button-primary min-w-0 flex-1" type="submit">{t('auth:registerCompleteButton')}</button>
        </div>
      </form>
    )
  }

  return (
    <>
      <p className="auth-subtitle">{t('auth:registerMasterSubtitle')}</p>
      <form className="auth-form gap-4" onSubmit={submitMaster}>
        <label className="field-label" htmlFor="setup-master-password">{t('auth:masterPasswordLabel')}</label>
        <div className="password-input-wrap password-input-wrap--icon">
          <input
            className="text-input"
            id="setup-master-password"
            name="master-password"
            type={masterVisible ? 'text' : 'password'}
            autoComplete="new-password"
            placeholder={t('auth:masterPasswordPlaceholder')}
            value={masterPassword}
            onChange={(event) => setMasterPassword(event.target.value)}
            required
          />
          <button className="input-action" type="button" onClick={() => setMasterVisible((visible) => !visible)} aria-label={masterVisible ? t('common:hide') : t('common:show')}>
            {masterVisible ? (
              <EyeOff size={18} aria-hidden="true" />
            ) : (
              <Eye size={18} aria-hidden="true" />
            )}
          </button>
        </div>
        <label className="field-label" htmlFor="setup-master-password-confirm">{t('auth:masterPasswordConfirmLabel')}</label>
        <div className="password-input-wrap password-input-wrap--icon">
          <input
            className="text-input"
            id="setup-master-password-confirm"
            name="master-password-confirm"
            type={masterVisible ? 'text' : 'password'}
            autoComplete="new-password"
            placeholder={t('auth:masterPasswordConfirmPlaceholder')}
            value={confirmMasterPassword}
            onChange={(event) => setConfirmMasterPassword(event.target.value)}
            required
          />
        </div>
        {errorKey ? <p className="auth-error" role="alert">{t(`auth:${errorKey}`)}</p> : null}
        <button className="button button-primary button-full" type="submit" disabled={busy}>{t('auth:createVaultButton')}</button>
      </form>
    </>
  )
}

/**
 * Vault setup for a logged-in account that has no vault key yet (its
 * registration never reached the master-password step). If a key turns
 * out to exist after all — or the existence check itself fails — the user
 * is sent to the unlock page instead of being shown this form.
 */
export function VaultSetup({ user, vaultClient, onNavigate, onAppearanceChange }: {
  user: VaultIdentity
  vaultClient: VaultClient
  onNavigate: (path: string, replace?: boolean) => void
  onAppearanceChange: (preference: AppearancePreference) => void
}) {
  const { t } = useTranslation(['common', 'auth'])
  const [ready, setReady] = useState(false)

  useEffect(() => {
    let cancelled = false
    vaultClient.hasVaultKey().then((hasKey) => {
      if (cancelled) return
      if (hasKey) onNavigate(`/users/${user.id}/unlock`, true)
      else setReady(true)
    }).catch(() => {
      if (!cancelled) onNavigate(`/users/${user.id}/unlock`, true)
    })
    return () => { cancelled = true }
  }, [vaultClient, user, onNavigate])

  return (
    <AuthShell onNavigate={onNavigate} onAppearanceChange={onAppearanceChange}>
      <section className="auth-card" aria-labelledby="setup-vault-title">
        <h1 id="setup-vault-title">{t('auth:setupVaultTitle')}</h1>
        {ready ? (
          <>
            <p className="auth-subtitle">{t('auth:setupVaultSubtitle')}</p>
            <VaultSetupForm
              vaultClient={vaultClient}
              resolveUserId={async () => user.id}
              onComplete={(id) => onNavigate(`/users/${id}/unlock`)}
            />
          </>
        ) : null}
      </section>
    </AuthShell>
  )
}
