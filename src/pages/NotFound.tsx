import { useTranslation } from 'react-i18next'
import { AuthShell } from '../App'

export function NotFound({ onNavigate }: { onNavigate: (path: string) => void }) {
  const { t } = useTranslation(['common', 'auth'])
  return <AuthShell onNavigate={onNavigate}><section className="auth-card"><h1>{t('common:notFoundTitle')}</h1><p className="auth-subtitle">{t('common:notFoundBody')}</p><button className="button button-primary button-full" type="button" onClick={() => onNavigate('/')}>{t('common:openHome')}</button></section></AuthShell>
}
