import { useTranslation } from 'react-i18next'
import { AuthShell } from '../App'
import type { AppearancePreference } from '../features/settings/preferences'

export function RegisterPreview({ onNavigate, onAppearanceChange }: {
  onNavigate: (path: string) => void
  onAppearanceChange: (preference: AppearancePreference) => void
}) {
  const { t } = useTranslation(['common', 'auth'])
  return (
    <AuthShell onNavigate={onNavigate} onAppearanceChange={onAppearanceChange}>
      <section className="auth-card" aria-labelledby="register-title">
        <div className="auth-card-mark" aria-hidden="true"><span>↗</span></div>
        <p className="eyebrow">{t('common:previewMode')}</p>
        <h1 id="register-title">{t('auth:registerTitle')}</h1>
        <p className="auth-subtitle">{t('auth:registerBody')}</p>
        <button className="button button-primary button-full" type="button" onClick={() => onNavigate('/login')}>{t('auth:loginTitle')}<span aria-hidden="true">→</span></button>
      </section>
    </AuthShell>
  )
}
