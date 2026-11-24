import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { AuthShell } from '../App'

export function Login({ onLogin, onNavigate }: { onLogin: (email: string, password: string) => Promise<string | null>; onNavigate: (path: string) => void }) {
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
    <AuthShell onNavigate={onNavigate}>
      <section className="auth-card" aria-labelledby="login-title">
        <div className="auth-card-mark" aria-hidden="true"><span>↗</span></div>
        <p className="eyebrow">{t('auth:loginEyebrow')}</p>
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
          <div className="password-input-wrap">
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
              {passwordVisible ? t('common:hide') : t('common:show')}
            </button>
          </div>
          <p className="field-hint">{t('auth:loginPasswordHint')}</p>
          {errorKey ? <p className="auth-error" role="alert">{t(`auth:${errorKey}`)}</p> : null}
          <button className="button button-primary button-full" type="submit">{t('auth:continueButton')}<span aria-hidden="true">→</span></button>
        </form>
        <p className="auth-switch">{t('auth:noAccount')} <a href="/register" onClick={(event) => { event.preventDefault(); onNavigate('/register') }}>{t('auth:createAccount')}</a></p>
      </section>
    </AuthShell>
  )
}
