import { useState, type FormEvent } from 'react'
import { Eye, EyeOff } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { AuthShell } from '../App'
import { Button } from '../components/ui/button'
import { Card } from '../components/ui/card'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
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
      <Card className="mt-[19px] gap-[0px] rounded-[16px]! pt-[clamp(24px,4vw,31px)] pb-[clamp(20px,3vw,25px)] px-[clamp(20px,4vw,34px)] [box-shadow:0_12px_42px_rgb(23_32_52/5%)] max-[700px]:p-[26px_22px_22px] max-[390px]:rounded-[14px] max-[390px]:px-[17px] dark:shadow-[0_18px_52px_rgb(0_0_0/24%)]" aria-labelledby="login-title">
        <h1 id="login-title" className="m-0 text-[clamp(24px,3vw,30px)] font-[640] tracking-[-0.05em] leading-[1.15] text-foreground">{t('auth:loginTitle')}</h1>
        <p className="mt-[9px] text-[13px] leading-[1.65] text-[#737b88] dark:text-[oklch(0.865_0.01_264.5)]">{t('auth:loginSubtitle')}</p>
        <form className="mt-[25px] flex flex-col gap-4" onSubmit={submit}>
          <Label className="text-xs! font-[620]! text-[#38404c] dark:text-[oklch(0.865_0.01_264.5)]" htmlFor="login-email">{t('auth:emailLabel')}</Label>
          <Input
            className="h-[45px] rounded-[9px]! px-3 text-[13px]! bg-white/55 placeholder:text-[#a0a6b0] md:text-[13px]! dark:bg-white/5 dark:placeholder:text-[oklch(0.774_0.022_261.8)]"
            id="login-email"
            name="email"
            type="email"
            autoComplete="username"
            placeholder={t('auth:emailPlaceholder')}
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            required
          />
          <Label className="text-xs! font-[620]! text-[#38404c] dark:text-[oklch(0.865_0.01_264.5)]" htmlFor="login-password">{t('auth:loginPasswordLabel')}</Label>
          <div className="relative">
            <Input
              className="h-[45px] rounded-[9px]! pl-3 pr-12 text-[13px]! bg-white/55 placeholder:text-[#a0a6b0] md:text-[13px]! dark:bg-white/5 dark:placeholder:text-[oklch(0.774_0.022_261.8)]"
              id="login-password"
              name="login-password"
              type={passwordVisible ? 'text' : 'password'}
              autoComplete="current-password"
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
          {errorKey ? <p className="mt-3 text-xs leading-[1.6] text-[#b3261e] dark:text-[#ff9d94]" role="alert">{t(`auth:${errorKey}`)}</p> : null}
          <Button className="h-12 w-full rounded-[11px]! px-[18px] gap-[14px] font-[620]! text-sm! hover:-translate-y-px" type="submit">{t('auth:loginButton')}</Button>
        </form>
        <p className="mt-5 text-center text-xs text-muted-foreground">{t('auth:noAccount')} <a className="font-semibold text-primary no-underline hover:underline focus-visible:outline-3 focus-visible:outline-[#a9c3ff] focus-visible:outline-offset-[3px]" href="/register" onClick={(event) => { event.preventDefault(); onNavigate('/register') }}>{t('auth:createAccount')}</a></p>
      </Card>
    </AuthShell>
  )
}
