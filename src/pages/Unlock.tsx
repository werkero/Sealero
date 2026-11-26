import { useState, type FormEvent } from 'react'
import { Check, Eye, EyeOff } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { AuthShell } from '../App'
import type { VaultIdentity } from '../client/contracts'
import type { AppearancePreference } from '../features/settings/preferences'

export function Unlock({ user, onUnlock, onBackToLogin, onNavigate, onAppearanceChange }: {
  user: VaultIdentity
  onUnlock: (password: string) => Promise<string | null>
  onBackToLogin: () => void
  onNavigate: (path: string) => void
  onAppearanceChange: (preference: AppearancePreference) => void
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
    <AuthShell onNavigate={onNavigate} onAppearanceChange={onAppearanceChange}>
      <section className="auth-card unlock-card" aria-labelledby="unlock-title">
        <button className="back-button" type="button" onClick={onBackToLogin}><span aria-hidden="true">←</span>{t('auth:backToLogin')}</button>
        <h1 id="unlock-title">{t('auth:unlockTitle')}</h1>
        <p className="auth-subtitle">{t('auth:unlockSubtitle')}</p>
        <div className="account-chip"><span className="account-avatar">{user.email.slice(0, 1).toUpperCase()}</span><span>{user.email}</span><span className="account-chip-check"><Check size={14} aria-hidden="true" /></span></div>
        <form className="auth-form" onSubmit={submit}>
          <label className="field-label" htmlFor="master-password">{t('auth:masterPasswordLabel')}</label>
          <div className="password-input-wrap password-input-wrap--icon">
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
              {passwordVisible ? (
                <EyeOff size={18} aria-hidden="true" />
              ) : (
                <Eye size={18} aria-hidden="true" />
              )}
            </button>
          </div>
          {errorKey ? <p className="auth-error" role="alert">{t(`auth:${errorKey}`)}</p> : null}
          <button className="button button-primary button-full" type="submit">{t('auth:unlockButton')}</button>
        </form>
      </section>
    </AuthShell>
  )
}
