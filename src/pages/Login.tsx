import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { AuthShell } from '../App'
import type { AppearancePreference } from '../features/settings/preferences'

export function Login({ onLogin, onNavigate, onAppearanceChange }: {
  onLogin: (email: string, password: string) => Promise<string | null>
  onNavigate: (path: string) => void
  onAppearanceChange: (preference: AppearancePreference) => void
}) {
  const { t } = useTranslation(['common', 'auth'])
  const [email, setEmail] = useState('')
  const [loginPassword, setLoginPassword] = useState('')
  const [passwordVisible, setPasswordVisible] = useState(false)
  const [errorKey, setErrorKey] = useState<string | null>(null)

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const failure = await onLogin(email, loginPassword)
    setErrorKey(failure)
    setLoginPassword('')
  }

  return (
    <AuthShell onNavigate={onNavigate} onAppearanceChange={onAppearanceChange}>
      <section className="auth-card" aria-labelledby="login-title">
        <h1 id="login-title">{t('auth:loginTitle')}</h1>
        <p className="auth-subtitle">{t('auth:loginSubtitle')}</p>
        <form className="auth-form" onSubmit={submit}>
          <label className="field-label" htmlFor="login-email">{t('auth:emailLabel')}</label>
          <input
            className="text-input"
            id="login-email"
            name="email"
            type="email"
            autoComplete="username"
            placeholder={t('auth:emailPlaceholder')}
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            required
          />
          <label className="field-label" htmlFor="login-password">{t('auth:loginPasswordLabel')}</label>
          <div className="password-input-wrap password-input-wrap--icon">
            <input
              className="text-input"
              id="login-password"
              name="login-password"
              type={passwordVisible ? 'text' : 'password'}
              autoComplete="current-password"
              placeholder={t('auth:loginPasswordPlaceholder')}
              value={loginPassword}
              onChange={(event) => setLoginPassword(event.target.value)}
              required
            />
            <button className="input-action" type="button" onClick={() => setPasswordVisible((visible) => !visible)} aria-label={passwordVisible ? t('common:hide') : t('common:show')}>
              {passwordVisible ? (
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                  <line x1="1" y1="1" x2="23" y2="23" />
                </svg>
              ) : (
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
              )}
            </button>
          </div>
          {errorKey ? <p className="auth-error" role="alert">{t(`auth:${errorKey}`)}</p> : null}
          <button className="button button-primary button-full" type="submit">{t('auth:continueButton')}<span aria-hidden="true">→</span></button>
        </form>
        <p className="auth-switch">{t('auth:noAccount')} <a href="/register" onClick={(event) => { event.preventDefault(); onNavigate('/register') }}>{t('auth:createAccount')}</a></p>
      </section>
    </AuthShell>
  )
}
