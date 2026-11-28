import { useState, type FormEvent } from 'react'
import { Check, Eye, EyeOff } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { AuthShell } from '../App'
import type { VaultIdentity } from '../client/contracts'
import type { AppearancePreference } from '../features/settings/preferences'

export function Unlock({ user, onUnlock, onSignOut, lockedAfterLogin, onNavigate, onAppearanceChange }: {
  user: VaultIdentity
  onUnlock: (password: string) => Promise<string | null>
  onSignOut: () => void
  lockedAfterLogin: boolean
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
        <h1 id="unlock-title">{lockedAfterLogin ? t('auth:lockedTitle') : t('auth:unlockTitle')}</h1>
        <div className="account-chip"><span className="account-avatar">{user.email.slice(0, 1).toUpperCase()}</span><span>{user.email}</span><span className="account-chip-check"><Check size={14} aria-hidden="true" /></span></div>
        <form className="auth-form gap-4" onSubmit={submit}>
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
        <div className="mt-5 flex items-center gap-3" aria-hidden="true">
          <span className="h-px flex-1 bg-border" />
          <span className="text-xs text-muted-foreground">{t('auth:or')}</span>
          <span className="h-px flex-1 bg-border" />
        </div>
        <button className="button button-secondary button-full unlock-signout" type="button" onClick={onSignOut}>{t('auth:signOut')}</button>
      </section>
    </AuthShell>
  )
}
