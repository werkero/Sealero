import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { AuthShell } from '../App'
import type { VaultIdentity } from '../client/contracts'

export function Unlock({ user, onUnlock, onBackToLogin, onNavigate }: {
  user: VaultIdentity
  onUnlock: (password: string) => Promise<string | null>
  onBackToLogin: () => void
  onNavigate: (path: string) => void
}) {
  const { t } = useTranslation(['common', 'auth'])
  const [masterPassword, setMasterPassword] = useState('')
  const [passwordVisible, setPasswordVisible] = useState(false)
  const [errorKey, setErrorKey] = useState<string | null>(null)

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const failure = await onUnlock(masterPassword)
    setErrorKey(failure)
    setMasterPassword('')
  }

  return (
    <AuthShell onNavigate={onNavigate}>
      <section className="auth-card unlock-card" aria-labelledby="unlock-title">
        <button className="back-button" type="button" onClick={onBackToLogin}><span aria-hidden="true">←</span>{t('auth:backToLogin')}</button>
        <div className="auth-card-mark lock-mark" aria-hidden="true"><span>⌑</span></div>
        <p className="eyebrow">{t('auth:unlockEyebrow')}</p>
        <h1 id="unlock-title">{t('auth:unlockTitle')}</h1>
        <p className="auth-subtitle">{t('auth:unlockSubtitle')}</p>
        <div className="account-chip"><span className="account-avatar">{user.email.slice(0, 1).toUpperCase()}</span><span>{user.email}</span><span className="account-chip-check">✓</span></div>
        <form className="auth-form" onSubmit={submit}>
          <label className="field-label" htmlFor="master-password">{t('auth:masterPasswordLabel')}</label>
          <div className="password-input-wrap">
            <input
              className="text-input"
              id="master-password"
              name="master-password"
              type={passwordVisible ? 'text' : 'password'}
              autoComplete="off"
              placeholder={t('auth:masterPasswordPlaceholder')}
              value={masterPassword}
              onChange={(event) => setMasterPassword(event.target.value)}
              required
              autoFocus
            />
            <button className="input-action" type="button" onClick={() => setPasswordVisible((visible) => !visible)} aria-label={passwordVisible ? t('common:hide') : t('common:show')}>
              {passwordVisible ? t('common:hide') : t('common:show')}
            </button>
          </div>
          <p className="field-hint">{t('auth:masterPasswordHint')}</p>
          {errorKey ? <p className="auth-error" role="alert">{t(`auth:${errorKey}`)}</p> : null}
          <button className="button button-primary button-full" type="submit">{t('auth:unlockButton')}<span aria-hidden="true">→</span></button>
        </form>
      </section>
    </AuthShell>
  )
}
