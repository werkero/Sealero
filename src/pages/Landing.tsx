import { motion, MotionConfig } from 'motion/react'
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
    <motion.section
      className="landing-section pricing-section"
      aria-labelledby="pricing-title"
      initial={{ opacity: 0, y: 24 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-80px' }}
      transition={{ duration: 0.5, ease: 'easeOut' }}
    >
      <h2 id="pricing-title">{t('pricingTitle')}</h2>
      <p className="section-subtitle">{t('pricingSubtitle')}</p>
      <div className="pricing-grid">
        <motion.article
          className="pricing-card"
          whileHover={{ y: -4 }}
          transition={{ duration: 0.2, ease: 'easeOut' }}
        >
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
        </motion.article>
        <motion.article
          className="pricing-card pricing-card-pro"
          whileHover={{ y: -4 }}
          transition={{ duration: 0.2, ease: 'easeOut' }}
        >
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
        </motion.article>
      </div>
      <p className="pricing-note">{t('pricingNote')}</p>
    </motion.section>
  )
}

function Faq() {
  const { t } = useTranslation('common')
  const items = [1, 2, 3, 4, 5].map((n) => ({
    q: t(`faqQ${n}`),
    a: t(`faqA${n}`),
  }))
  return (
    <motion.section
      className="landing-section faq-section"
      aria-labelledby="faq-title"
      initial={{ opacity: 0, y: 24 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-80px' }}
      transition={{ duration: 0.5, ease: 'easeOut' }}
    >
      <h2 id="faq-title">{t('faqTitle')}</h2>
      <div className="faq-list">
        {items.map((item, i) => (
          <details className="faq-item" key={i}>
            <summary>{item.q}</summary>
            <p>{item.a}</p>
          </details>
        ))}
      </div>
    </motion.section>
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
    <MotionConfig reducedMotion="user">
      <div className="public-shell">
        <PublicHeader onNavigate={onNavigate} />
        <main className="landing-main">
          <section className="landing-copy" aria-labelledby="landing-title">
            <motion.h1
              id="landing-title"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.55, ease: 'easeOut' }}
            >
              {t('common:landingTitle')}
            </motion.h1>
            <motion.p
              className="landing-description"
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.55, ease: 'easeOut', delay: 0.1 }}
            >
              {t('common:landingBody')}
            </motion.p>
            <motion.div
              className="landing-actions"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, ease: 'easeOut', delay: 0.2 }}
            >
              <a className="button button-primary" href="/register" onClick={(event) => { event.preventDefault(); onNavigate('/register') }}>
                {t('auth:createAccount')}
                <span aria-hidden="true">→</span>
              </a>
            </motion.div>
          </section>
        </main>
        <Pricing onNavigate={onNavigate} />
        <Faq />
        <PublicFooter />
      </div>
    </MotionConfig>
  )
}
