import { useState, type FormEvent } from 'react'
import { Check, Eye, EyeOff } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { AuthShell } from '../App'
import { Button } from '../components/ui/button'
import { Card } from '../components/ui/card'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
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
      <Card className="mt-[19px] gap-[0px] rounded-[16px]! pt-[24px] pb-[clamp(20px,3vw,25px)] px-[clamp(20px,4vw,34px)] [box-shadow:0_12px_42px_rgb(23_32_52/5%)] max-[700px]:p-[26px_22px_22px] max-[390px]:rounded-[14px] max-[390px]:px-[17px] dark:shadow-[0_18px_52px_rgb(0_0_0/24%)]" aria-labelledby="unlock-title">
        <h1 id="unlock-title" className="m-0 text-[clamp(24px,3vw,30px)] font-[640] tracking-[-0.05em] leading-[1.15] text-foreground">{lockedAfterLogin ? t('auth:lockedTitle') : t('auth:unlockTitle')}</h1>
        <div className="mt-[19px] flex min-h-[45px] items-center gap-2.5 rounded-[10px] border border-[#edf0f3] bg-[#fafbfc] px-2.5 py-[7px] text-xs text-[#55606d] dark:border-border dark:bg-white/5 dark:text-foreground"><span className="grid size-[27px] flex-none place-items-center rounded-full bg-primary/10 text-xs font-[650] text-primary">{user.email.slice(0, 1).toUpperCase()}</span><span>{user.email}</span><span className="ml-auto font-bold text-[#14845d]"><Check size={14} aria-hidden="true" /></span></div>
        <form className="mt-[22px] flex flex-col gap-4" onSubmit={submit}>
          <Label className="text-xs! font-[620]! text-[#38404c] dark:text-[oklch(0.865_0.01_264.5)]" htmlFor="master-password">{t('auth:masterPasswordLabel')}</Label>
          <div className="relative">
            <Input
              className="h-[45px] rounded-[9px]! pl-3 pr-12 text-[13px]! bg-white/55 placeholder:text-[#a0a6b0] md:text-[13px]! dark:bg-white/5 dark:placeholder:text-[oklch(0.774_0.022_261.8)]"
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
            <button className="absolute top-1/2 right-2 -translate-y-1/2 inline-flex items-center justify-center border-0 bg-transparent p-1.5 text-xs font-[580] text-muted-foreground hover:text-primary cursor-pointer" type="button" onClick={() => setPasswordVisible((visible) => !visible)} aria-label={passwordVisible ? t('common:hide') : t('common:show')}>
              {passwordVisible ? (
                <EyeOff size={18} aria-hidden="true" />
              ) : (
                <Eye size={18} aria-hidden="true" />
              )}
            </button>
          </div>
          {errorKey ? <p className="mt-3 text-xs leading-[1.6] text-[#b3261e] dark:text-[#ff9d94]" role="alert">{t(`auth:${errorKey}`)}</p> : null}
          <Button className="h-12 w-full rounded-[11px]! px-[18px] gap-[14px] font-[620]! text-sm! hover:-translate-y-px" type="submit">{t('auth:unlockButton')}</Button>
        </form>
        <div className="mt-5 flex items-center gap-3" aria-hidden="true">
          <span className="h-px flex-1 bg-border" />
          <span className="text-xs text-muted-foreground">{t('auth:or')}</span>
          <span className="h-px flex-1 bg-border" />
        </div>
        <Button variant="outline" className="mt-[14px] h-12 w-full rounded-[11px]! px-[18px] gap-[14px] font-[620]! text-sm! hover:-translate-y-px" type="button" onClick={onSignOut}>{t('auth:signOut')}</Button>
      </Card>
    </AuthShell>
  )
}
