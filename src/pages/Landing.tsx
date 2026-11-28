import { useCallback, useEffect, useState } from 'react'
import { ArrowUpRight, Clock, KeyRound, ShieldCheck, Sparkles } from 'lucide-react'
import { motion, MotionConfig, useReducedMotion } from 'motion/react'
import { useTranslation } from 'react-i18next'
import { Brand } from '../components/Brand'
import { UserAvatar } from '../components/UserAvatar'
import { LanguageSelector } from '../components/LanguageSelector'
import { ThemeToggle } from '../components/ThemeToggle'
import { Button } from '../components/ui/button'
import { Card } from '../components/ui/card'
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
      {!done && (
        <motion.span
          aria-hidden="true"
          className="ml-1 inline-block h-[0.85em] w-[3px] bg-primary align-[-0.05em]"
          animate={{ opacity: [1, 1, 0, 0] }}
          transition={{ duration: 0.9, repeat: Infinity, times: [0, 0.5, 0.501, 1] }}
        />
      )}
      <span className="opacity-0">{text.slice(count)}</span>
    </span>
  )
}

function PublicHeader({ user, onNavigate, onAppearanceChange }: { user: VaultIdentity | null; onNavigate: (path: string) => void; onAppearanceChange: (preference: AppearancePreference) => void }) {
  const { t } = useTranslation(['common', 'auth'])
  return (
    <header className="flex min-h-[88px] items-center justify-between max-[700px]:min-h-[70px]">
      <Brand onNavigate={onNavigate} />
      <div className="flex items-center gap-[26px] max-[390px]:gap-[9px]">
        <ThemeToggle onAppearanceChange={onAppearanceChange} />
        <LanguageSelector />
        {user ? (
          <button type="button" className="inline-flex h-9 w-9 cursor-pointer items-center justify-center rounded-[9px] border border-transparent bg-transparent p-0 text-muted-foreground hover:border-border hover:bg-muted hover:text-foreground focus-visible:outline-3 focus-visible:outline-[#a9c3ff] focus-visible:outline-offset-[3px]" aria-label={t('common:landingEnterVaultButton')} title={t('common:landingEnterVaultButton')} onClick={() => onNavigate(`/users/${user.id}`)}>
            <UserAvatar displayName={user.display_name} avatarUrl={user.avatar_url} email={user.email} className="grid size-[29px] flex-none place-items-center rounded-full bg-primary/10 text-xs font-[650] text-primary" />
          </button>
        ) : (
          <a className="text-sm! font-[550] text-[#414958] no-underline underline-offset-4 hover:text-primary hover:underline focus-visible:outline-3 focus-visible:outline-[#a9c3ff] focus-visible:outline-offset-[3px] dark:text-[oklch(0.865_0.01_264.5)]" href="/login" onClick={(event) => { event.preventDefault(); onNavigate('/login') }}>
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
      className="box-border flex min-h-svh w-full items-center px-[clamp(20px,5vw,64px)] py-[clamp(48px,8vw,96px)]"
      aria-labelledby="ai-title"
      initial={{ opacity: 0, y: 24 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-80px' }}
      transition={{ duration: 0.5, ease: 'easeOut' }}
    >
      <div className="mx-auto grid w-[min(100%,1200px)] grid-cols-[minmax(0,6fr)_minmax(0,5fr)] items-center gap-[clamp(32px,5vw,72px)] max-[900px]:grid-cols-1">
        <div className="flex min-h-[420px] items-center justify-center max-[900px]:min-h-[340px]">
          <div className="grid grid-cols-[repeat(3,92px)] gap-[22px] [transform:rotateX(58deg)_rotateZ(45deg)] [transform-style:preserve-3d] max-[900px]:grid-cols-[repeat(3,72px)] max-[900px]:gap-4" aria-hidden="true">
            {Array.from({ length: 9 }, (_, index) => {
              const flow = AI_CUBE_FLOW.find((cube) => cube.position === index)
              const state = !flow ? 'idle' : flow.phase === phase ? 'active' : flow.phase < phase ? 'done' : 'idle'
              const Icon = flow?.icon
              return (
                <div key={index} className="relative h-[92px] w-[92px] [transform-style:preserve-3d] max-[900px]:h-[72px] max-[900px]:w-[72px]">
                  <div className="absolute inset-0 border border-border bg-card brightness-[0.88] [transform:translateZ(46px)] max-[900px]:[transform:translateZ(36px)]" />
                  <div className="absolute inset-0 border border-border bg-card brightness-[0.64] [transform:rotateY(180deg)_translateZ(46px)] max-[900px]:[transform:rotateY(180deg)_translateZ(36px)]" />
                  <div className="absolute inset-0 border border-border bg-card brightness-[0.76] [transform:rotateY(90deg)_translateZ(46px)] max-[900px]:[transform:rotateY(90deg)_translateZ(36px)]" />
                  <div className="absolute inset-0 border border-border bg-card brightness-[0.52] [transform:rotateY(-90deg)_translateZ(46px)] max-[900px]:[transform:rotateY(-90deg)_translateZ(36px)]" />
                  <div className={state === 'active'
                    ? 'absolute inset-0 flex items-center justify-center border border-primary bg-card shadow-[0_0_0_1px_var(--primary),0_0_28px_rgb(8_50_170/0.35)] [transform:rotateX(90deg)_translateZ(46px)] max-[900px]:[transform:rotateX(90deg)_translateZ(36px)]'
                    : 'absolute inset-0 flex items-center justify-center border border-border bg-card [transform:rotateX(90deg)_translateZ(46px)] max-[900px]:[transform:rotateX(90deg)_translateZ(36px)]'}>
                    {Icon ? (
                      <span className={state === 'active'
                        ? 'flex text-primary [transform:scaleY(1.9)_rotate(-45deg)] transition-colors duration-200 motion-reduce:transition-none motion-reduce:animate-none'
                        : state === 'done'
                          ? 'flex text-[#15966a] [transform:scaleY(1.9)_rotate(-45deg)] transition-colors duration-200 motion-reduce:transition-none motion-reduce:animate-none'
                          : 'flex text-muted-foreground [transform:scaleY(1.9)_rotate(-45deg)] transition-colors duration-200 motion-reduce:transition-none motion-reduce:animate-none'}>
                        <Icon size={30} aria-hidden="true" />
                      </span>
                    ) : null}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
        <div className="max-[900px]:order-first">
          <h2 id="ai-title" className="m-0 text-[clamp(28px,4vw,40px)] font-[650] tracking-[-0.04em] leading-[1.15] text-foreground">{t('aiCallTitle')}</h2>
          <p className="mt-3 text-base leading-[1.6] text-muted-foreground">{t('aiCallDescription')}</p>
          <ul className="mt-8 grid list-none gap-5 p-0">
            {points.map((point, index) => {
              const active = index === phase || (phase === 2 && index === 3)
              return (
                <li
                  key={point.title}
                  className={active
                    ? 'flex items-start gap-[14px] opacity-100 transition-opacity duration-200 motion-reduce:transition-none motion-reduce:animate-none'
                    : 'flex items-start gap-[14px] opacity-55 transition-opacity duration-200 motion-reduce:transition-none motion-reduce:animate-none'}
                >
                  <span
                    className={active
                      ? 'flex h-10 w-10 flex-none items-center justify-center rounded-xl bg-primary text-primary-foreground'
                      : 'flex h-10 w-10 flex-none items-center justify-center rounded-xl bg-primary/10 text-primary'}
                    aria-hidden="true"
                  >
                    <point.icon size={20} />
                  </span>
                  <div>
                    <h3 className="m-0 text-[17px] font-[650] text-foreground">{point.title}</h3>
                    <p className="mt-1 text-[15px] leading-[1.6] text-muted-foreground">{point.body}</p>
                  </div>
                </li>
              )
            })}
          </ul>
        </div>
      </div>
    </motion.section>
  )
}

function Pricing({ user, onNavigate }: { user: VaultIdentity | null; onNavigate: (path: string) => void }) {
  const { t } = useTranslation('common')
  const ctaButtonClass = 'mt-[10px] h-12 w-full justify-center rounded-[11px]! px-[18px] font-[620]! text-sm! duration-[140ms] hover:-translate-y-px motion-reduce:transition-none motion-reduce:animate-none'
  const featureItemClass = "relative py-[7px] pl-6 text-sm leading-[1.55] text-[#414958] dark:text-[oklch(0.865_0.01_264.5)] before:absolute before:left-[2px] before:top-[9px] before:h-2 before:w-[14px] before:border-b-2 before:border-l-2 before:border-primary before:content-[''] before:[transform:rotate(-45deg)_translateY(-2px)]"
  return (
    <motion.section
      className="mx-auto w-[min(100%,1200px)] px-0 py-[clamp(40px,6vw,64px)] text-center"
      aria-labelledby="pricing-title"
      initial={{ opacity: 0, y: 24 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-80px' }}
      transition={{ duration: 0.5, ease: 'easeOut' }}
    >
      <h2 id="pricing-title" className="m-0 text-[clamp(28px,4vw,40px)] font-[650] tracking-[-0.04em] leading-[1.15] text-foreground">{t('pricingTitle')}</h2>
      <p className="mx-auto mt-3 text-base leading-[1.6] text-muted-foreground">{t('pricingSubtitle')}</p>
      <div className="mt-9 grid grid-cols-3 gap-4 text-left max-[900px]:mx-auto max-[900px]:max-w-[520px] max-[900px]:grid-cols-1">
        <Card className="gap-[0px] rounded-[16px]! px-7 py-7 [box-shadow:0_0_#0000] transition-transform duration-200 hover:-translate-y-1 motion-reduce:transition-none motion-reduce:animate-none max-[390px]:px-[22px] max-[390px]:py-[22px]">
          <h3 className="m-0 text-lg font-[650] text-foreground">{t('pricingFreeName')}</h3>
          <p className="mt-[14px] text-[40px] font-[650] leading-none tracking-[-0.04em] text-foreground">
            {t('pricingFreePrice')}
            <span className="ml-1.5 text-sm font-medium tracking-normal text-muted-foreground">{t('pricingFreePeriod')}</span>
          </p>
          <p className="mt-3 text-sm leading-[1.6] text-muted-foreground">{t('pricingFreeDesc')}</p>
          <ul className="my-5 flex-1 list-none p-0">
            <li className={featureItemClass}>{t('pricingFreeF1')}</li>
            <li className={featureItemClass}>{t('pricingFreeF2')}</li>
            <li className={featureItemClass}>{t('pricingFreeF3')}</li>
            <li className={featureItemClass}>{t('pricingFreeF4')}</li>
            <li className={featureItemClass}>{t('pricingFreeF5')}</li>
            <li className={featureItemClass}>{t('pricingFreeF6')}</li>
          </ul>
          <Button asChild variant="outline" className={ctaButtonClass}>
            <a href={GITHUB_REPO_URL} target="_blank" rel="noreferrer">
              {t('pricingOpenSource')}
              <span aria-hidden="true"><ArrowUpRight size={12} aria-hidden="true" /></span>
            </a>
          </Button>
          {user ? null : (
            <Button asChild className={ctaButtonClass}>
              <a href="/register" onClick={(event) => { event.preventDefault(); onNavigate('/register') }}>
                {t('pricingFreeCta')}
              </a>
            </Button>
          )}
        </Card>
        <Card className="gap-[0px] rounded-[16px]! px-7 py-7 [box-shadow:0_0_#0000] transition-transform duration-200 hover:-translate-y-1 motion-reduce:transition-none motion-reduce:animate-none max-[390px]:px-[22px] max-[390px]:py-[22px]">
          <h3 className="m-0 text-lg font-[650] text-foreground">{t('pricingProName')}</h3>
          <p className="mt-[14px] text-[40px] font-[650] leading-none tracking-[-0.04em] text-foreground">
            {t('pricingProPrice')}
            <span className="ml-1.5 text-sm font-medium tracking-normal text-muted-foreground">{t('pricingProPeriod')}</span>
          </p>
          <p className="mt-2 text-[13px] text-muted-foreground">{t('pricingProYearly')}</p>
          <p className="mt-3 text-sm leading-[1.6] text-muted-foreground">{t('pricingProDesc')}</p>
          <ul className="my-5 flex-1 list-none p-0">
            <li className={featureItemClass}>{t('pricingProF1')}</li>
            <li className={featureItemClass}>{t('pricingProF2')}</li>
            <li className={featureItemClass}>{t('pricingProF3')}</li>
            <li className={featureItemClass}>{t('pricingProF4')}</li>
            <li className={featureItemClass}>{t('pricingProF5')}</li>
            <li className={featureItemClass}>{t('pricingProF6')}</li>
            <li className={featureItemClass}>{t('pricingProF7')}</li>
          </ul>
          {user ? null : (
            <Button asChild className={ctaButtonClass}>
              <a href="/register" onClick={(event) => { event.preventDefault(); onNavigate('/register') }}>
                {t('pricingProCta')}
              </a>
            </Button>
          )}
        </Card>
        <Card className="gap-[0px] rounded-[16px]! border-primary px-7 py-7 [box-shadow:0_0_0_1px_var(--primary)] transition-transform duration-200 hover:-translate-y-1 motion-reduce:transition-none motion-reduce:animate-none max-[390px]:px-[22px] max-[390px]:py-[22px]">
          <h3 className="m-0 text-lg font-[650] text-foreground">{t('pricingCloudName')}</h3>
          <p className="mt-[14px] text-[40px] font-[650] leading-none tracking-[-0.04em] text-foreground">
            {t('pricingCloudPrice')}
            <span className="ml-1.5 text-sm font-medium tracking-normal text-muted-foreground">{t('pricingCloudPeriod')}</span>
          </p>
          <p className="mt-2 text-[13px] text-muted-foreground">{t('pricingCloudYearly')}</p>
          <p className="mt-3 text-sm leading-[1.6] text-muted-foreground">{t('pricingCloudDesc')}</p>
          <ul className="my-5 flex-1 list-none p-0">
            <li className={featureItemClass}>{t('pricingCloudF1')}</li>
            <li className={featureItemClass}>{t('pricingCloudF2')}</li>
          </ul>
          {user ? null : (
            <Button asChild className={ctaButtonClass}>
              <a href="/register" onClick={(event) => { event.preventDefault(); onNavigate('/register') }}>
                {t('pricingCloudCta')}
              </a>
            </Button>
          )}
        </Card>
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
      className="mx-auto w-[min(100%,1200px)] px-0 py-[clamp(40px,6vw,64px)] text-center"
      aria-labelledby="faq-title"
      initial={{ opacity: 0, y: 24 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-80px' }}
      transition={{ duration: 0.5, ease: 'easeOut' }}
    >
      <h2 id="faq-title" className="m-0 text-[clamp(28px,4vw,40px)] font-[650] tracking-[-0.04em] leading-[1.15] text-foreground">{t('faqTitle')}</h2>
      <div className="mt-10 text-left">
        {items.map((item, i) => (
          <details className="group border-t border-border p-0 last:border-b" key={i}>
            <summary className="flex cursor-pointer list-none select-none items-center justify-between gap-6 py-[22px] text-[17px] font-semibold leading-[1.5] text-foreground transition-colors duration-150 hover:text-primary focus-visible:outline-2 focus-visible:outline-primary focus-visible:outline-offset-2 motion-reduce:transition-none motion-reduce:animate-none after:h-2 after:w-2 after:shrink-0 after:translate-y-[-2px] after:rotate-45 after:border-r-[1.5px] after:border-b-[1.5px] after:border-[#818895] after:transition-transform after:duration-200 after:content-[''] after:motion-reduce:transition-none group-open:after:rotate-[225deg] [&::-webkit-details-marker]:hidden max-[390px]:py-[18px] max-[390px]:text-base">{item.q}</summary>
            <p className="mb-[22px] max-w-[680px] text-[15px] leading-[1.75] text-muted-foreground group-open:animate-in group-open:fade-in group-open:slide-in-from-top-1 group-open:duration-[250ms] motion-reduce:animate-none motion-reduce:transition-none max-[390px]:text-sm">{item.a}</p>
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
    <footer className="w-full px-0 pt-8 pb-10 text-[13px] leading-[1.5] text-muted-foreground">
      <div className="flex items-center justify-between gap-6 max-[700px]:flex-col max-[700px]:items-start max-[700px]:gap-4">
        <div className="flex items-center gap-4">
          <Brand onNavigate={onNavigate} />
          <span className="h-5 w-px bg-border" aria-hidden="true" />
          <a className="inline-flex items-center text-[#414958] no-underline hover:text-primary focus-visible:outline-3 focus-visible:outline-[#a9c3ff] focus-visible:outline-offset-[3px] dark:text-[oklch(0.865_0.01_264.5)]" href={GITHUB_REPO_URL} target="_blank" rel="noreferrer" aria-label="GitHub">
            <GithubIcon />
          </a>
        </div>
        <nav className="flex items-center gap-7" aria-label="Legal">
          <a className="text-sm! font-[550] text-[#414958] no-underline hover:text-primary hover:underline hover:underline-offset-[3px] focus-visible:outline-3 focus-visible:outline-[#a9c3ff] focus-visible:outline-offset-[3px] dark:text-[oklch(0.865_0.01_264.5)]" href="/terms" onClick={(event) => { event.preventDefault(); onNavigate('/terms') }}>
            {t('footerTerms')}
          </a>
          <a className="text-sm! font-[550] text-[#414958] no-underline hover:text-primary hover:underline hover:underline-offset-[3px] focus-visible:outline-3 focus-visible:outline-[#a9c3ff] focus-visible:outline-offset-[3px] dark:text-[oklch(0.865_0.01_264.5)]" href="/privacy" onClick={(event) => { event.preventDefault(); onNavigate('/privacy') }}>
            {t('footerPrivacy')}
          </a>
        </nav>
      </div>
      <div className="mt-6">
        <FooterStatus />
      </div>
      <div className="mt-4 flex items-center justify-between gap-4 max-[700px]:flex-col max-[700px]:items-start max-[700px]:gap-2">
        <span className="text-muted-foreground">{t('footerCopyright')}</span>
        <a className="font-semibold text-foreground no-underline hover:text-primary hover:underline hover:underline-offset-[3px] focus-visible:outline-3 focus-visible:outline-[#a9c3ff] focus-visible:outline-offset-[3px]" href={WERKERO_URL} target="_blank" rel="noreferrer">
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
  const heroButtonClass = 'h-12 rounded-[11px]! px-[18px] font-[620]! text-sm! duration-[140ms] hover:-translate-y-px motion-reduce:transition-none motion-reduce:animate-none max-[390px]:px-4 max-[390px]:text-[13px]!'

  return (
    <MotionConfig reducedMotion="user">
      <div className="mx-auto flex min-h-svh w-full flex-col bg-background px-[clamp(20px,5vw,64px)] text-foreground max-[700px]:px-[22px] max-[390px]:px-[17px]">
        <PublicHeader user={user} onNavigate={onNavigate} onAppearanceChange={onAppearanceChange} />
        <main className="flex min-h-[calc(100svh-88px)] flex-1 items-center justify-center px-0 pt-[clamp(24px,3vw,32px)] pb-[clamp(64px,8vw,92px)] text-center max-[700px]:min-h-[calc(100svh-70px)] max-[700px]:pt-[46px] max-[700px]:pb-[78px] max-[390px]:pt-[35px] max-[390px]:pb-[58px]">
          <section className="mx-auto w-full p-0" aria-labelledby="landing-title">
            <motion.div
              className="mb-[clamp(28px,4vw,44px)] flex justify-center max-[390px]:mb-[22px]"
              initial={{ opacity: 0, scale: 0.92 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.5, ease: 'easeOut' }}
            >
              <motion.img
                src="/sealero-logo.svg"
                alt="Sealero"
                width="120"
                height="120"
                className="h-[120px] w-[120px] dark:brightness-[1.7] dark:saturate-[1.25] max-[390px]:h-[90px] max-[390px]:w-[90px]"
                animate={reduceMotion ? undefined : { y: [0, -6, 0] }}
                transition={{ duration: 3.5, repeat: Infinity, ease: 'easeInOut', delay: 0.6 }}
              />
            </motion.div>
            <h1 id="landing-title" aria-label={title} className="mx-auto max-w-[920px] text-[clamp(46px,7.5vw,88px)] font-[650] tracking-[-0.067em] leading-[1.05] text-foreground text-balance max-[700px]:max-w-[700px] max-[390px]:text-[36px]">
              <TypewriterTitle text={title} onDone={handleTitleDone} />
            </h1>
            <motion.p
              className="mx-auto mt-[clamp(24px,3vw,36px)] max-w-[610px] text-[clamp(17px,1.8vw,20px)] leading-[1.65] text-muted-foreground max-[700px]:max-w-[520px] max-[700px]:text-base max-[390px]:text-[15px]"
              initial={{ opacity: 0, y: 16 }}
              animate={titleDone ? { opacity: 1, y: 0 } : { opacity: 0, y: 16 }}
              transition={{ duration: 0.55, ease: 'easeOut' }}
            >
              {t('common:landingBody')}
            </motion.p>
            <motion.div
              className="mt-[clamp(32px,4vw,48px)] flex items-center justify-center"
              initial={{ opacity: 0, y: 12 }}
              animate={titleDone ? { opacity: 1, y: 0 } : { opacity: 0, y: 12 }}
              transition={{ duration: 0.5, ease: 'easeOut', delay: 0.12 }}
            >
              {user ? (
                <Button asChild className={heroButtonClass}>
                  <a href={`/users/${user.id}`} onClick={(event) => { event.preventDefault(); onNavigate(`/users/${user.id}`) }}>
                    {t('common:landingEnterVaultButton')}
                  </a>
                </Button>
              ) : (
                <Button asChild className={heroButtonClass}>
                  <a href="/register" onClick={(event) => { event.preventDefault(); onNavigate('/register') }}>
                    {t('auth:createAccount')}
                  </a>
                </Button>
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
