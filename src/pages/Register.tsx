import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { AuthShell } from '../App'
import type { VaultClient } from '../client/contracts'
import { VaultApiError } from '../client/http-vault-client'
import type { VaultIdentity } from '../client/types'
import {
  deriveKek,
  generateRecoveryKey,
  KDF_PARAMS_P0,
  kdfParamsToCanonicalJson,
  randomBytes,
  toBase64,
  wrapDekForServer,
} from '../client/crypto'
import type { AppearancePreference } from '../features/settings/preferences'

type RegisterStep = 'account' | 'verify' | 'master' | 'recovery'

/** Picks `count` distinct random positions (0-based) out of `total`. */
function pickRandomPositions(total: number, count: number): number[] {
  const positions = new Set<number>()
  while (positions.size < count) {
    positions.add(Math.floor(Math.random() * total))
  }
  return [...positions].sort((a, b) => a - b)
}

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
  const [masterPassword, setMasterPassword] = useState('')
  const [confirmMasterPassword, setConfirmMasterPassword] = useState('')
  const [passwordVisible, setPasswordVisible] = useState(false)
  const [masterVisible, setMasterVisible] = useState(false)
  const [recoveryKey, setRecoveryKey] = useState('')
  const [confirmPositions, setConfirmPositions] = useState<number[]>([])
  const [confirmWords, setConfirmWords] = useState<string[]>(['', '', ''])
  const [userId, setUserId] = useState('')
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
      await vaultClient.register(email, loginPassword)
      setStep('verify')
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
      // Log in to get the JWT and user id (no navigation yet).
      const identity = await onSessionLogin(email, loginPassword)
      if (!identity) throw new Error('register_login_failed')
      setUserId(identity.id)
      // Consent is required before the vault-key upload (System Design §5.1).
      const policyVersion = await vaultClient.fetchPolicyVersion()
      await vaultClient.submitConsent(policyVersion)
      // Create the vault key: a fresh DEK, KEK-wrapped with the master password.
      const dek = randomBytes(32)
      const kdfSalt = randomBytes(16)
      const kek = await deriveKek(masterPassword, toBase64(kdfSalt), KDF_PARAMS_P0)
      const wrapped = await wrapDekForServer(kek, identity.id, 1, dek)
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
    onNavigate(`/users/${userId}/unlock`)
  }

  const recoveryWords = recoveryKey ? recoveryKey.split(' ') : []

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
              {errorKey ? <p className="auth-error" role="alert">{t(`auth:${errorKey}`)}</p> : null}
              <button className="button button-primary button-full" type="submit" disabled={busy}>{t('auth:continueButton')}<span aria-hidden="true">→</span></button>
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
              <button className="button button-primary button-full" type="submit" disabled={busy}>{t('auth:verifyButton')}<span aria-hidden="true">→</span></button>
              <button className="button button-secondary button-full" type="button" onClick={resendCode} disabled={busy || resendCooldown > 0}>
                {resendCooldown > 0 ? t('auth:resendCodeCooldown', { seconds: resendCooldown }) : t('auth:resendCode')}
              </button>
            </form>
          </>
        ) : null}
        {step === 'master' ? (
          <>
            <p className="auth-subtitle">{t('auth:registerMasterSubtitle')}</p>
            <form className="auth-form" onSubmit={submitMaster}>
              <label className="field-label" htmlFor="register-master-password">{t('auth:masterPasswordLabel')}</label>
              <div className="password-input-wrap password-input-wrap--icon">
                <input
                  className="text-input"
                  id="register-master-password"
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
              <label className="field-label" htmlFor="register-master-password-confirm">{t('auth:masterPasswordConfirmLabel')}</label>
              <div className="password-input-wrap password-input-wrap--icon">
                <input
                  className="text-input"
                  id="register-master-password-confirm"
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
              <button className="button button-primary button-full" type="submit" disabled={busy}>{t('auth:createVaultButton')}<span aria-hidden="true">→</span></button>
            </form>
          </>
        ) : null}
        {step === 'recovery' ? (
          <>
            <p className="auth-subtitle">{t('auth:recoveryKeySubtitle')}</p>
            <ol className="recovery-words">
              {recoveryWords.map((word, index) => (
                <li key={`${index}-${word}`}><span className="recovery-word-index">{index + 1}</span><span>{word}</span></li>
              ))}
            </ol>
            <form className="auth-form" onSubmit={submitRecovery}>
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
              <button className="button button-primary button-full" type="submit">{t('auth:registerCompleteButton')}<span aria-hidden="true">→</span></button>
            </form>
          </>
        ) : null}
      </section>
    </AuthShell>
  )
}
