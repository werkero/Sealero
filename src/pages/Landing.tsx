import { useCallback, useEffect, useState } from 'react'
import { ArrowUpRight, Clock, KeyRound, ShieldCheck, Sparkles } from 'lucide-react'
import { motion, MotionConfig, useReducedMotion } from 'motion/react'
import { useTranslation } from 'react-i18next'
import { Brand } from '../components/Brand'
import { UserAvatar } from '../components/UserAvatar'
import { LanguageSelector } from '../components/LanguageSelector'
import { ThemeToggle } from '../components/ThemeToggle'
import type { VaultIdentity } from '../client/contracts'
import type { AppearancePreference } from '../features/settings/preferences'
import { FooterStatus } from '../features/api-health/FooterStatus'

const GITHUB_REPO_URL = 'https://github.com/werkero/Sealero'
const WERKERO_URL = 'https://werkero.vercel.app'

function TypewriterTitle({ text, onDone }: { text: string; onDone: () => void }) {
  const reduceMotion = useReducedMotion()
  const [count, setCount] = useState(reduceMotion ? text.length : 0)

  useEffect(() => {
    if (reduceMotion) {
      setCount(text.length)
      onDone()
      return
    }
    setCount(0)
    const interval = Math.max(30, Math.min(70, 1400 / Math.max(text.length, 1)))
    let index = 0
    let timer: ReturnType<typeof setInterval> | undefined
    const start = setTimeout(() => {
      timer = setInterval(() => {
        index += 1
        setCount(index)
        if (index >= text.length) {
          if (timer) clearInterval(timer)
          onDone()
        }
      }, interval)
    }, 150)
    return () => {
      clearTimeout(start)
      if (timer) clearInterval(timer)
    }
  }, [text, reduceMotion, onDone])

  const done = count >= text.length
  return (
    <span aria-hidden="true">
      {text.slice(0, count)}
      {!done && <span className="typewriter-caret" />}
      <span className="typewriter-rest">{text.slice(count)}</span>
    </span>
  )
}

function PublicHeader({ user, onNavigate, onAppearanceChange }: { user: VaultIdentity | null; onNavigate: (path: string) => void; onAppearanceChange: (preference: AppearancePreference) => void }) {
  const { t } = useTranslation(['common', 'auth'])
  return (
    <header className="public-header">
      <Brand onNavigate={onNavigate} />
      <div className="public-header-actions">
        <ThemeToggle onAppearanceChange={onAppearanceChange} />
        <LanguageSelector />
        {user ? (
          <button type="button" className="theme-toggle" aria-label={t('common:landingEnterVaultButton')} title={t('common:landingEnterVaultButton')} onClick={() => onNavigate(`/users/${user.id}`)}>
            <UserAvatar displayName={user.display_name} avatarUrl={user.avatar_url} email={user.email} className="profile-avatar" />
          </button>
        ) : (
          <a className="text-link" href="/login" onClick={(event) => { event.preventDefault(); onNavigate('/login') }}>
            {t('auth:loginTitle')}
          </a>
        )}
      </div>
    </header>
  )
}

const AI_DEMO_PHASE_MS = [1800, 2000, 2800]

/** The three flow cubes on the 3x3 grid diagonal: ask -> confirm -> fetch. */
const AI_CUBE_FLOW = [
  { icon: Sparkles, phase: 0, position: 0 },
  { icon: ShieldCheck, phase: 1, position: 4 },
  { icon: KeyRound, phase: 2, position: 8 },
] as const

function AiCall() {
  const { t } = useTranslation('common')
  const reduceMotion = useReducedMotion()
  const [phase, setPhase] = useState(0)
  useEffect(() => {
    if (reduceMotion) {
      setPhase(2)
      return
    }
    const timer = setTimeout(() => setPhase((phase + 1) % 3), AI_DEMO_PHASE_MS[phase])
    return () => clearTimeout(timer)
  }, [phase, reduceMotion])

  const points = [
    { icon: Sparkles, title: t('aiCallPoint1Title'), body: t('aiCallPoint1Body') },
    { icon: ShieldCheck, title: t('aiCallPoint2Title'), body: t('aiCallPoint2Body') },
    { icon: KeyRound, title: t('aiCallPoint3Title'), body: t('aiCallPoint3Body') },
    { icon: Clock, title: t('aiCallPoint4Title'), body: t('aiCallPoint4Body') },
  ]

  return (
    <motion.section
      className="ai-screen"
      aria-labelledby="ai-title"
      initial={{ opacity: 0, y: 24 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-80px' }}
      transition={{ duration: 0.5, ease: 'easeOut' }}
    >
      <div className="ai-screen-inner">
        <div className="ai-cubes-stage">
          <div className="ai-cubes" aria-hidden="true">
            {Array.from({ length: 9 }, (_, index) => {
              const flow = AI_CUBE_FLOW.find((cube) => cube.position === index)
              const state = !flow ? 'idle' : flow.phase === phase ? 'active' : flow.phase < phase ? 'done' : 'idle'
              const Icon = flow?.icon
              return (
                <div key={index} className={`ai-cube ai-cube--${state}`}>
                  <div className="ai-cube-face ai-cube-face--front" />
                  <div className="ai-cube-face ai-cube-face--back" />
                  <div className="ai-cube-face ai-cube-face--right" />
                  <div className="ai-cube-face ai-cube-face--left" />
                  <div className="ai-cube-face ai-cube-face--top">
                    {Icon ? (
                      <span className="ai-cube-icon">
                        <Icon size={30} aria-hidden="true" />
                      </span>
                    ) : null}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
        <div className="ai-copy">
          <h2 id="ai-title">{t('aiCallTitle')}</h2>
          <p className="section-subtitle">{t('aiCallDescription')}</p>
          <ul className="ai-points">
            {points.map((point, index) => (
              <li
                key={point.title}
                className={index === phase || (phase === 2 && index === 3) ? 'ai-point ai-point--active' : 'ai-point'}
              >
                <span className="ai-point-icon" aria-hidden="true">
                  <point.icon size={20} />
                </span>
                <div>
                  <h3>{point.title}</h3>
                  <p>{point.body}</p>
                </div>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </motion.section>
  )
}

function Pricing({ user, onNavigate }: { user: VaultIdentity | null; onNavigate: (path: string) => void }) {
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
            <li>{t('pricingFreeF5')}</li>
            <li>{t('pricingFreeF6')}</li>
          </ul>
          <a
            className="button button-secondary pricing-cta"
            href={GITHUB_REPO_URL}
            target="_blank"
            rel="noreferrer"
          >
            {t('pricingOpenSource')}
            <span aria-hidden="true"><ArrowUpRight size={12} aria-hidden="true" /></span>
          </a>
          {user ? null : (
            <a className="button button-primary pricing-cta" href="/register" onClick={(event) => { event.preventDefault(); onNavigate('/register') }}>
              {t('pricingFreeCta')}
            </a>
          )}
        </motion.article>
        <motion.article
          className="pricing-card"
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
            <li>{t('pricingProF5')}</li>
            <li>{t('pricingProF6')}</li>
            <li>{t('pricingProF7')}</li>
          </ul>
          {user ? null : (
            <a className="button button-primary pricing-cta" href="/register" onClick={(event) => { event.preventDefault(); onNavigate('/register') }}>
              {t('pricingProCta')}
            </a>
          )}
        </motion.article>
        <motion.article
          className="pricing-card pricing-card-pro"
          whileHover={{ y: -4 }}
          transition={{ duration: 0.2, ease: 'easeOut' }}
        >
          <h3>{t('pricingCloudName')}</h3>
          <p className="pricing-price">
            {t('pricingCloudPrice')}
            <span className="pricing-period">{t('pricingCloudPeriod')}</span>
          </p>
          <p className="pricing-yearly">{t('pricingCloudYearly')}</p>
          <p className="pricing-desc">{t('pricingCloudDesc')}</p>
          <ul className="pricing-features">
            <li>{t('pricingCloudF1')}</li>
            <li>{t('pricingCloudF2')}</li>
          </ul>
          {user ? null : (
            <a className="button button-primary pricing-cta" href="/register" onClick={(event) => { event.preventDefault(); onNavigate('/register') }}>
              {t('pricingCloudCta')}
            </a>
          )}
        </motion.article>
      </div>
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

function GithubIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
    </svg>
  )
}

function PublicFooter({ onNavigate }: { onNavigate: (path: string) => void }) {
  const { t } = useTranslation('common')
  return (
    <footer className="public-footer">
      <div className="footer-top">
        <div className="footer-brand">
          <Brand onNavigate={onNavigate} />
          <span className="footer-divider" aria-hidden="true" />
          <a className="footer-social" href={GITHUB_REPO_URL} target="_blank" rel="noreferrer" aria-label="GitHub">
            <GithubIcon />
          </a>
        </div>
        <nav className="footer-links" aria-label="Legal">
          <a href="/terms" onClick={(event) => { event.preventDefault(); onNavigate('/terms') }}>
            {t('footerTerms')}
          </a>
          <a href="/privacy" onClick={(event) => { event.preventDefault(); onNavigate('/privacy') }}>
            {t('footerPrivacy')}
          </a>
        </nav>
      </div>
      <div className="footer-status-row">
        <FooterStatus />
      </div>
      <div className="footer-bottom">
        <span className="footer-copyright">{t('footerCopyright')}</span>
        <a className="footer-by" href={WERKERO_URL} target="_blank" rel="noreferrer">
          {t('footerBy')}
        </a>
      </div>
    </footer>
  )
}

export default function Landing({ user, onNavigate, onAppearanceChange }: { user: VaultIdentity | null; onNavigate: (path: string) => void; onAppearanceChange: (preference: AppearancePreference) => void }) {
  const { t } = useTranslation(['common', 'auth'])
  const reduceMotion = useReducedMotion()
  const title = t('common:landingTitle')
  const [titleDone, setTitleDone] = useState(false)
  // 语言切换时重播序列：渲染期间重置（不能用 useEffect，
  // 父组件 effect 在子组件 effect 之后跑，会把减弱动态下
  // TypewriterTitle 同步触发的 onDone 又清回 false）。
  const [prevTitle, setPrevTitle] = useState(title)
  if (prevTitle !== title) {
    setPrevTitle(title)
    setTitleDone(false)
  }
  const handleTitleDone = useCallback(() => setTitleDone(true), [])

  return (
    <MotionConfig reducedMotion="user">
      <div className="public-shell">
        <PublicHeader user={user} onNavigate={onNavigate} onAppearanceChange={onAppearanceChange} />
        <main className="landing-main">
          <section className="landing-copy" aria-labelledby="landing-title">
            <motion.div
              className="landing-logo"
              initial={{ opacity: 0, scale: 0.92 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.5, ease: 'easeOut' }}
            >
              <motion.img
                src="/sealero-logo.svg"
                alt="Sealero"
                width="120"
                height="120"
                animate={reduceMotion ? undefined : { y: [0, -6, 0] }}
                transition={{ duration: 3.5, repeat: Infinity, ease: 'easeInOut', delay: 0.6 }}
              />
            </motion.div>
            <h1 id="landing-title" aria-label={title}>
              <TypewriterTitle text={title} onDone={handleTitleDone} />
            </h1>
            <motion.p
              className="landing-description"
              initial={{ opacity: 0, y: 16 }}
              animate={titleDone ? { opacity: 1, y: 0 } : { opacity: 0, y: 16 }}
              transition={{ duration: 0.55, ease: 'easeOut' }}
            >
              {t('common:landingBody')}
            </motion.p>
            <motion.div
              className="landing-actions"
              initial={{ opacity: 0, y: 12 }}
              animate={titleDone ? { opacity: 1, y: 0 } : { opacity: 0, y: 12 }}
              transition={{ duration: 0.5, ease: 'easeOut', delay: 0.12 }}
            >
              {user ? (
                <a className="button button-primary" href={`/users/${user.id}`} onClick={(event) => { event.preventDefault(); onNavigate(`/users/${user.id}`) }}>
                  {t('common:landingEnterVaultButton')}
                </a>
              ) : (
                <a className="button button-primary" href="/register" onClick={(event) => { event.preventDefault(); onNavigate('/register') }}>
                  {t('auth:createAccount')}
                </a>
              )}
            </motion.div>
          </section>
        </main>
        <AiCall />
        <Pricing user={user} onNavigate={onNavigate} />
        <Faq />
        <PublicFooter onNavigate={onNavigate} />
      </div>
    </MotionConfig>
  )
}
