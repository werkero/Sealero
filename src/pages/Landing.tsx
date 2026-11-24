import { useTranslation } from 'react-i18next'
import { Brand } from '../components/Brand'
import { LanguageSelector } from '../components/LanguageSelector'
import { ApiHealthCard } from '../features/api-health/ApiHealthCard'

function PublicHeader({ onNavigate }: { onNavigate: (path: string) => void }) {
  const { t } = useTranslation(['common', 'auth'])
  return (
    <header className="public-header">
      <Brand onNavigate={onNavigate} />
      <div className="public-header-actions">
        <LanguageSelector />
        <a className="text-link" href="/login" onClick={(event) => { event.preventDefault(); onNavigate('/login') }}>
          {t('auth:loginTitle')}
        </a>
      </div>
    </header>
  )
}

export default function Landing({ onNavigate }: { onNavigate: (path: string) => void }) {
  const { t } = useTranslation(['common', 'auth'])
  return (
    <div className="public-shell">
      <PublicHeader onNavigate={onNavigate} />
      <main className="landing-main">
        <section className="landing-copy" aria-labelledby="landing-title">
          <h1 id="landing-title">{t('common:landingTitle')}</h1>
          <p className="landing-description">{t('common:landingBody')}</p>
          <div className="landing-actions">
            <a className="button button-primary" href="/register" onClick={(event) => { event.preventDefault(); onNavigate('/register') }}>
              {t('auth:createAccount')}
              <span aria-hidden="true">→</span>
            </a>
          </div>
          <p className="landing-footnote">{t('common:landingFootnote')}</p>
          <ApiHealthCard />
        </section>
      </main>
    </div>
  )
}
