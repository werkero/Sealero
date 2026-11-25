import { useTranslation } from 'react-i18next'
import { AuthShell } from '../App'
import type { AppearancePreference } from '../features/settings/preferences'

export function NotFound({ onNavigate, onAppearanceChange }: {
  onNavigate: (path: string) => void
  onAppearanceChange: (preference: AppearancePreference) => void
}) {
  const { t } = useTranslation(['common', 'auth'])
  return <AuthShell onNavigate={onNavigate} onAppearanceChange={onAppearanceChange}><section className="auth-card"><h1>{t('common:notFoundTitle')}</h1><p className="auth-subtitle">{t('common:notFoundBody')}</p><button className="button button-primary button-full" type="button" onClick={() => onNavigate('/')}>{t('common:openHome')}</button></section></AuthShell>
}
