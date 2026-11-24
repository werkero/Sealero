import { useTranslation } from 'react-i18next'
import { Brand } from '../components/Brand'
import { LanguageSelector } from '../components/LanguageSelector'
import { ApiHealthDot } from '../features/api-health/ApiHealthDot'

const GITHUB_REPO_URL = 'https://github.com/werkero/Sealero'
const WERKERO_URL = 'https://werkero.vercel.app'

function PublicHeader({ onNavigate }: { onNavigate: (path: string) => void }) {
  const { t } = useTranslation(['common', 'auth'])
  return (
    <header className="public-header">
      <Brand onNavigate={onNavigate} />
      <div className="public-header-actions">
        <ApiHealthDot />
        <LanguageSelector />
        <a className="text-link" href="/login" onClick={(event) => { event.preventDefault(); onNavigate('/login') }}>
          {t('auth:loginTitle')}
        </a>
      </div>
    </header>
  )
}

function Pricing({ onNavigate }: { onNavigate: (path: string) => void }) {
  const { t } = useTranslation('common')
  return (
    <section className="landing-section pricing-section" aria-labelledby="pricing-title">
      <h2 id="pricing-title">{t('pricingTitle')}</h2>
      <p className="section-subtitle">{t('pricingSubtitle')}</p>
      <div className="pricing-grid">
        <article className="pricing-card">
          <h3>{t('pricingFreeName')}</h3>
          <p className="pricing-price">
            {t('pricingFreePrice')}
            <span className="pricing-period">{t('pricingFreePeriod')}</span>
          </p>
          <p className="pricing-desc">{t('pricingFreeDesc')}</p>
          <ul className="pricing-features">
            <li>{t('pricingFreeF1')}</li>
            <li>{t('pricingFreeF2')}</li>
            <li>{t('pricingFreeF3')}</li>
            <li>{t('pricingFreeF4')}</li>
          </ul>
          <a
            className="button button-secondary pricing-cta"
            href={GITHUB_REPO_URL}
            target="_blank"
            rel="noreferrer"
          >
            {t('pricingOpenSource')}
            <span aria-hidden="true">↗</span>
          </a>
          <a className="button button-primary pricing-cta" href="/register" onClick={(event) => { event.preventDefault(); onNavigate('/register') }}>
            {t('pricingFreeCta')}
            <span aria-hidden="true">→</span>
          </a>
        </article>
        <article className="pricing-card pricing-card-pro">
          <h3>{t('pricingProName')}</h3>
          <p className="pricing-price">
            {t('pricingProPrice')}
            <span className="pricing-period">{t('pricingProPeriod')}</span>
          </p>
          <p className="pricing-yearly">{t('pricingProYearly')}</p>
          <p className="pricing-desc">{t('pricingProDesc')}</p>
          <ul className="pricing-features">
            <li>{t('pricingProF1')}</li>
            <li>{t('pricingProF2')}</li>
            <li>{t('pricingProF3')}</li>
            <li>{t('pricingProF4')}</li>
          </ul>
          <a className="button button-primary pricing-cta" href="/register" onClick={(event) => { event.preventDefault(); onNavigate('/register') }}>
            {t('pricingProCta')}
            <span aria-hidden="true">→</span>
          </a>
        </article>
      </div>
      <p className="pricing-note">{t('pricingNote')}</p>
    </section>
  )
}

function Faq() {
  const { t } = useTranslation('common')
  const items = [1, 2, 3, 4, 5].map((n) => ({
    q: t(`faqQ${n}`),
    a: t(`faqA${n}`),
  }))
  return (
    <section className="landing-section faq-section" aria-labelledby="faq-title">
      <h2 id="faq-title">{t('faqTitle')}</h2>
      <div className="faq-list">
        {items.map((item, i) => (
          <details className="faq-item" key={i}>
            <summary>{item.q}</summary>
            <p>{item.a}</p>
          </details>
        ))}
      </div>
    </section>
  )
}

function PublicFooter() {
  const { t } = useTranslation('common')
  return (
    <footer className="public-footer">
      <a className="footer-by" href={WERKERO_URL} target="_blank" rel="noreferrer">
        {t('footerBy')}
      </a>
      <span className="footer-copyright">{t('footerCopyright')}</span>
    </footer>
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
        </section>
      </main>
      <Pricing onNavigate={onNavigate} />
      <Faq />
      <PublicFooter />
    </div>
  )
}
