import { useTranslation } from 'react-i18next'
import { AuthShell } from '../App'
import { Button } from '../components/ui/button'
import type { AppearancePreference } from '../features/settings/preferences'

export function NotFound({ onNavigate, onAppearanceChange }: {
  onNavigate: (path: string) => void
  onAppearanceChange: (preference: AppearancePreference) => void
}) {
  const { t } = useTranslation(['common', 'auth'])
  return <AuthShell onNavigate={onNavigate} onAppearanceChange={onAppearanceChange}><section className="mt-[19px] rounded-[16px] border border-[rgb(23_26_33/9%)] bg-[rgb(255_255_255/62%)] px-[clamp(20px,4vw,34px)] pb-[clamp(20px,3vw,25px)] pt-[clamp(24px,4vw,31px)] shadow-[0_12px_42px_rgb(23_32_52/5%)] backdrop-blur-[18px] backdrop-saturate-[1.35] dark:border-[rgb(255_255_255/10%)] dark:bg-[rgb(255_255_255/6%)] dark:shadow-[0_18px_52px_rgb(0_0_0/24%)] max-[700px]:px-[22px] max-[700px]:pb-[22px] max-[700px]:pt-[26px] max-[390px]:rounded-[14px] max-[390px]:px-[17px]"><h1 className="m-0 text-[clamp(24px,3vw,30px)] font-[640] tracking-[-0.05em] leading-[1.15] text-foreground">{t('common:notFoundTitle')}</h1><p className="mt-[9px] text-[13px] leading-[1.65] text-[#737b88] dark:text-[oklch(0.865_0.01_264.5)]">{t('common:notFoundBody')}</p><Button className="h-12 w-full rounded-[11px]! px-[18px] font-[620]! text-sm! hover:-translate-y-px motion-reduce:transition-none" type="button" onClick={() => onNavigate('/')}>{t('common:openHome')}</Button></section></AuthShell>
}
