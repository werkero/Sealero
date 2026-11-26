import { useState, type FormEvent } from 'react'
import { Eye, EyeOff } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { AuthShell } from '../App'
import type { VaultClient } from '../client/contracts'
import { VaultApiError } from '../client/http-vault-client'
import type { VaultIdentity } from '../client/types'
import type { AppearancePreference } from '../features/settings/preferences'
import { Checkbox } from '../components/ui/checkbox'
import { VaultSetupForm } from './VaultSetup'

type RegisterStep = 'account' | 'verify' | 'master'

export function Register({ vaultClient, onSessionLogin, onNavigate, onAppearanceChange }: {
  vaultClient: VaultClient
  onSessionLogin: (email: string, loginPassword: string) => Promise<VaultIdentity | null>
  onNavigate: (path: string) => void
  onAppearanceChange: (preference: AppearancePreference) => void
}) {
  const { t } = useTranslation(['common', 'auth'])
  const [step, setStep] = useState<RegisterStep>('account')
  const [email, setEmail] = useState('')
  const [loginPassword, setLoginPassword] = useState('')
  const [confirmLoginPassword, setConfirmLoginPassword] = useState('')
  const [code, setCode] = useState('')
  const [passwordVisible, setPasswordVisible] = useState(false)
  const [consentAgreed, setConsentAgreed] = useState(false)
  const [errorKey, setErrorKey] = useState<string | null>(null)
  const [infoKey, setInfoKey] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [resendCooldown, setResendCooldown] = useState(0)

  const submitAccount = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setErrorKey(null)
    if (loginPassword.length < 8) {
      setErrorKey('registerPasswordTooShort')
      return
    }
    if (loginPassword !== confirmLoginPassword) {
      setErrorKey('registerPasswordMismatch')
      return
    }
    setBusy(true)
    try {
      const { emailVerificationRequired } = await vaultClient.register(email, loginPassword)
      // Verification off: skip the code step entirely — it must not appear.
      setStep(emailVerificationRequired ? 'verify' : 'master')
    } catch (error) {
      if (error instanceof VaultApiError && error.code === 'rate_limited') setErrorKey('registerRateLimited')
      else if (error instanceof VaultApiError && error.code === 'invalid_request') setErrorKey('registerFailed')
      else setErrorKey('registerFailed')
    } finally {
      setBusy(false)
    }
  }

  const submitVerify = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setErrorKey(null)
    setBusy(true)
    try {
      await vaultClient.verifyEmail(email, code)
      setStep('master')
    } catch (error) {
      if (error instanceof VaultApiError && error.code === 'email_verification_disabled') {
        // The server has email verification off; the account is already verified.
        setStep('master')
      } else if (error instanceof VaultApiError && error.code === 'invalid_auth_code') {
        setErrorKey('verifyInvalidCode')
      } else {
        setErrorKey('verifyFailed')
      }
    } finally {
      setBusy(false)
    }
  }

  const resendCode = async () => {
    if (resendCooldown > 0) return
    setErrorKey(null)
    setInfoKey(null)
    try {
      await vaultClient.resendVerification(email)
      setInfoKey('resendCodeSent')
      setResendCooldown(60)
      const timer = window.setInterval(() => {
        setResendCooldown((remaining) => {
          if (remaining <= 1) {
            window.clearInterval(timer)
            return 0
          }
          return remaining - 1
        })
      }, 1000)
    } catch (error) {
      if (error instanceof VaultApiError && error.code === 'rate_limited') setErrorKey('registerRateLimited')
      else setErrorKey('resendCodeFailed')
    }
  }

  return (
    <AuthShell onNavigate={onNavigate} onAppearanceChange={onAppearanceChange}>
      <section className="auth-card" aria-labelledby="register-title">
        <h1 id="register-title">{t('auth:registerTitle')}</h1>
        {step === 'account' ? (
          <>
            <p className="auth-subtitle">{t('auth:registerSubtitle')}</p>
            <form className="auth-form" onSubmit={submitAccount}>
              <label className="field-label" htmlFor="register-email">{t('auth:emailLabel')}</label>
              <input
                className="text-input"
                id="register-email"
                name="email"
                type="email"
                autoComplete="username"
                placeholder={t('auth:emailPlaceholder')}
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                required
              />
              <label className="field-label" htmlFor="register-login-password">{t('auth:loginPasswordLabel')}</label>
              <div className="password-input-wrap password-input-wrap--icon">
                <input
                  className="text-input"
                  id="register-login-password"
                  name="login-password"
                  type={passwordVisible ? 'text' : 'password'}
                  autoComplete="new-password"
                  placeholder={t('auth:loginPasswordPlaceholder')}
                  value={loginPassword}
                  onChange={(event) => setLoginPassword(event.target.value)}
                  required
                />
                <button className="input-action" type="button" onClick={() => setPasswordVisible((visible) => !visible)} aria-label={passwordVisible ? t('common:hide') : t('common:show')}>
                  {passwordVisible ? (
                    <EyeOff size={18} aria-hidden="true" />
                  ) : (
                    <Eye size={18} aria-hidden="true" />
                  )}
                </button>
              </div>
              <label className="field-label" htmlFor="register-login-password-confirm">{t('auth:loginPasswordConfirmLabel')}</label>
              <div className="password-input-wrap password-input-wrap--icon">
                <input
                  className="text-input"
                  id="register-login-password-confirm"
                  name="login-password-confirm"
                  type={passwordVisible ? 'text' : 'password'}
                  autoComplete="new-password"
                  placeholder={t('auth:loginPasswordConfirmPlaceholder')}
                  value={confirmLoginPassword}
                  onChange={(event) => setConfirmLoginPassword(event.target.value)}
                  required
                />
              </div>
              <div className="consent-row">
                <Checkbox
                  id="register-consent"
                  className="consent-checkbox"
                  checked={consentAgreed}
                  onCheckedChange={(checked) => setConsentAgreed(checked === true)}
                />
                <label className="consent-text" htmlFor="register-consent">
                  {t('auth:registerConsentBefore')}
                  <a href="/terms" onClick={(event) => { event.stopPropagation(); event.preventDefault(); onNavigate('/terms') }}>{t('common:termsTitle')}</a>
                  {t('auth:registerConsentBetween')}
                  <a href="/privacy" onClick={(event) => { event.stopPropagation(); event.preventDefault(); onNavigate('/privacy') }}>{t('common:privacyTitle')}</a>
                  {t('auth:registerConsentAfter')}
                </label>
              </div>
              {errorKey ? <p className="auth-error" role="alert">{t(`auth:${errorKey}`)}</p> : null}
              <button className="button button-primary button-full" type="submit" disabled={busy || !consentAgreed}>{t('auth:continueButton')}</button>
            </form>
            <p className="auth-switch">{t('auth:haveAccount')} <a href="/login" onClick={(event) => { event.preventDefault(); onNavigate('/login') }}>{t('auth:loginTitle')}</a></p>
          </>
        ) : null}
        {step === 'verify' ? (
          <>
            <p className="auth-subtitle">{t('auth:registerVerifySubtitle', { email })}</p>
            <form className="auth-form" onSubmit={submitVerify}>
              <label className="field-label" htmlFor="register-code">{t('auth:verificationCodeLabel')}</label>
              <input
                className="text-input"
                id="register-code"
                name="code"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder={t('auth:verificationCodePlaceholder')}
                value={code}
                onChange={(event) => setCode(event.target.value.replace(/[^0-9]/g, '').slice(0, 6))}
                required
              />
              {errorKey ? <p className="auth-error" role="alert">{t(`auth:${errorKey}`)}</p> : null}
              {infoKey ? <p className="auth-info" role="status">{t(`auth:${infoKey}`)}</p> : null}
              <button className="button button-primary button-full" type="submit" disabled={busy}>{t('auth:verifyButton')}</button>
              <button className="button button-secondary button-full" type="button" onClick={resendCode} disabled={busy || resendCooldown > 0}>
                {resendCooldown > 0 ? t('auth:resendCodeCooldown', { seconds: resendCooldown }) : t('auth:resendCode')}
              </button>
            </form>
          </>
        ) : null}
        {step === 'master' ? (
          <VaultSetupForm
            vaultClient={vaultClient}
            resolveUserId={async () => {
              const identity = await onSessionLogin(email, loginPassword)
              if (!identity) throw new Error('register_login_failed')
              return identity.id
            }}
            onComplete={(id) => onNavigate(`/users/${id}/unlock`)}
          />
        ) : null}
      </section>
    </AuthShell>
  )
}
