import { useState, type FormEvent } from 'react'
import { Eye, EyeOff } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { AuthShell } from '../App'
import type { VaultClient } from '../client/contracts'
import { VaultApiError } from '../client/http-vault-client'
import type { VaultIdentity } from '../client/types'
import type { AppearancePreference } from '../features/settings/preferences'
import { Button } from '../components/ui/button'
import { Card } from '../components/ui/card'
import { Checkbox } from '../components/ui/checkbox'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
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
      <Card className="mt-[19px] gap-[0px] rounded-[16px]! pt-[clamp(24px,4vw,31px)] pb-[clamp(20px,3vw,25px)] px-[clamp(20px,4vw,34px)] [box-shadow:0_12px_42px_rgb(23_32_52/5%)] max-[700px]:p-[26px_22px_22px] max-[390px]:rounded-[14px] max-[390px]:px-[17px] dark:shadow-[0_18px_52px_rgb(0_0_0/24%)]" aria-labelledby="register-title">
        <h1 id="register-title" className="m-0 text-[clamp(24px,3vw,30px)] font-[640] tracking-[-0.05em] leading-[1.15] text-foreground">{t('auth:registerTitle')}</h1>
        {step === 'account' ? (
          <>
            <p className="mt-[9px] text-[13px] leading-[1.65] text-[#737b88] dark:text-[oklch(0.865_0.01_264.5)]">{t('auth:registerSubtitle')}</p>
            <form className="mt-[25px] flex flex-col gap-4" onSubmit={submitAccount}>
              <Label className="text-xs! font-[620]! text-[#38404c] dark:text-[oklch(0.865_0.01_264.5)]" htmlFor="register-email">{t('auth:emailLabel')}</Label>
              <Input
                className="h-[45px] rounded-[9px]! px-3 text-[13px]! bg-white/55 placeholder:text-[#a0a6b0] md:text-[13px]! dark:bg-white/5 dark:placeholder:text-[oklch(0.774_0.022_261.8)]"
                id="register-email"
                name="email"
                type="email"
                autoComplete="username"
                placeholder={t('auth:emailPlaceholder')}
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                required
              />
              <Label className="text-xs! font-[620]! text-[#38404c] dark:text-[oklch(0.865_0.01_264.5)]" htmlFor="register-login-password">{t('auth:loginPasswordLabel')}</Label>
              <div className="relative">
                <Input
                  className="h-[45px] rounded-[9px]! pl-3 pr-12 text-[13px]! bg-white/55 placeholder:text-[#a0a6b0] md:text-[13px]! dark:bg-white/5 dark:placeholder:text-[oklch(0.774_0.022_261.8)]"
                  id="register-login-password"
                  name="login-password"
                  type={passwordVisible ? 'text' : 'password'}
                  autoComplete="new-password"
                  placeholder={t('auth:loginPasswordPlaceholder')}
                  value={loginPassword}
                  onChange={(event) => setLoginPassword(event.target.value)}
                  required
                />
                <button className="absolute top-1/2 right-2 -translate-y-1/2 inline-flex items-center justify-center border-0 bg-transparent p-1.5 text-xs font-[580] text-muted-foreground hover:text-primary cursor-pointer" type="button" onClick={() => setPasswordVisible((visible) => !visible)} aria-label={passwordVisible ? t('common:hide') : t('common:show')}>
                  {passwordVisible ? (
                    <EyeOff size={18} aria-hidden="true" />
                  ) : (
                    <Eye size={18} aria-hidden="true" />
                  )}
                </button>
              </div>
              <Label className="text-xs! font-[620]! text-[#38404c] dark:text-[oklch(0.865_0.01_264.5)]" htmlFor="register-login-password-confirm">{t('auth:loginPasswordConfirmLabel')}</Label>
              <div className="relative">
                <Input
                  className="h-[45px] rounded-[9px]! pl-3 pr-12 text-[13px]! bg-white/55 placeholder:text-[#a0a6b0] md:text-[13px]! dark:bg-white/5 dark:placeholder:text-[oklch(0.774_0.022_261.8)]"
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
              <div className="flex items-start gap-2.5">
                <Checkbox
                  id="register-consent"
                  className="mt-0.5"
                  checked={consentAgreed}
                  onCheckedChange={(checked) => setConsentAgreed(checked === true)}
                />
                <label className="text-[13px] leading-[1.6] text-muted-foreground cursor-pointer" htmlFor="register-consent">
                  {t('auth:registerConsentBefore')}
                  <a className="text-primary no-underline hover:underline focus-visible:outline-3 focus-visible:outline-[#a9c3ff] focus-visible:outline-offset-[3px]" href="/terms" onClick={(event) => { event.stopPropagation(); event.preventDefault(); onNavigate('/terms') }}>{t('common:termsTitle')}</a>
                  {t('auth:registerConsentBetween')}
                  <a className="text-primary no-underline hover:underline focus-visible:outline-3 focus-visible:outline-[#a9c3ff] focus-visible:outline-offset-[3px]" href="/privacy" onClick={(event) => { event.stopPropagation(); event.preventDefault(); onNavigate('/privacy') }}>{t('common:privacyTitle')}</a>
                  {t('auth:registerConsentAfter')}
                </label>
              </div>
              {errorKey ? <p className="mt-3 text-xs leading-[1.6] text-[#b3261e] dark:text-[#ff9d94]" role="alert">{t(`auth:${errorKey}`)}</p> : null}
              <Button className="h-12 w-full rounded-[11px]! px-[18px] gap-[14px] font-[620]! text-sm! hover:-translate-y-px" type="submit" disabled={busy || !consentAgreed}>{t('auth:continueButton')}</Button>
            </form>
            <p className="mt-5 text-center text-xs text-muted-foreground">{t('auth:haveAccount')} <a className="font-semibold text-primary no-underline hover:underline focus-visible:outline-3 focus-visible:outline-[#a9c3ff] focus-visible:outline-offset-[3px]" href="/login" onClick={(event) => { event.preventDefault(); onNavigate('/login') }}>{t('auth:loginTitle')}</a></p>
          </>
        ) : null}
        {step === 'verify' ? (
          <>
            <p className="mt-[9px] text-[13px] leading-[1.65] text-[#737b88] dark:text-[oklch(0.865_0.01_264.5)]">{t('auth:registerVerifySubtitle', { email })}</p>
            <form className="mt-[25px] flex flex-col gap-4" onSubmit={submitVerify}>
              <Label className="text-xs! font-[620]! text-[#38404c] dark:text-[oklch(0.865_0.01_264.5)]" htmlFor="register-code">{t('auth:verificationCodeLabel')}</Label>
              <Input
                className="h-[45px] rounded-[9px]! px-3 text-[13px]! bg-white/55 placeholder:text-[#a0a6b0] md:text-[13px]! dark:bg-white/5 dark:placeholder:text-[oklch(0.774_0.022_261.8)]"
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
              {errorKey ? <p className="mt-3 text-xs leading-[1.6] text-[#b3261e] dark:text-[#ff9d94]" role="alert">{t(`auth:${errorKey}`)}</p> : null}
              {infoKey ? <p className="mt-3 text-xs leading-[1.6] text-[#2e7d32] dark:text-[#7ec98a]" role="status">{t(`auth:${infoKey}`)}</p> : null}
              <Button className="h-12 w-full rounded-[11px]! px-[18px] gap-[14px] font-[620]! text-sm! hover:-translate-y-px" type="submit" disabled={busy}>{t('auth:verifyButton')}</Button>
              <Button variant="outline" className="h-12 w-full rounded-[11px]! px-[18px] gap-[14px] font-[620]! text-sm! hover:-translate-y-px" type="button" onClick={resendCode} disabled={busy || resendCooldown > 0}>
                {resendCooldown > 0 ? t('auth:resendCodeCooldown', { seconds: resendCooldown }) : t('auth:resendCode')}
              </Button>
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
      </Card>
    </AuthShell>
  )
}
