import { ArrowLeft } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Brand } from '../components/Brand'
import { LanguageSelector } from '../components/LanguageSelector'
import { ThemeToggle } from '../components/ThemeToggle'
import { Button } from '../components/ui/button'
import type { AppearancePreference } from '../features/settings/preferences'

export type LegalDoc = 'terms' | 'privacy'

const SECTION_COUNTS: Record<LegalDoc, number> = { terms: 12, privacy: 14 }

export function LegalPage({ doc, onNavigate, onAppearanceChange }: {
  doc: LegalDoc
  onNavigate: (path: string) => void
  onAppearanceChange: (preference: AppearancePreference) => void
}) {
  const { t } = useTranslation('common')
  const prefix = doc === 'terms' ? 'terms' : 'privacy'
  const sections = Array.from({ length: SECTION_COUNTS[doc] }, (_, i) => i + 1).map((n) => ({
    title: t(`${prefix}S${n}Title`),
    body: t(`${prefix}S${n}Body`),
  }))
  return (
    <div className="mx-auto flex min-h-svh w-full flex-col bg-background px-[clamp(20px,5vw,64px)] text-foreground max-[700px]:px-[22px] max-[390px]:px-[17px]">
      <header className="flex min-h-[88px] items-center justify-between max-[700px]:min-h-[70px]">
        <Brand onNavigate={onNavigate} />
        <div className="flex items-center gap-[26px] max-[390px]:gap-[9px]">
          <ThemeToggle onAppearanceChange={onAppearanceChange} />
          <LanguageSelector />
        </div>
      </header>
      <main className="flex flex-1 justify-center px-0 py-12 pb-24">
        <article className="w-[min(100%,720px)]">
          <h1 className="m-0 text-[clamp(30px,4vw,40px)] font-[650] tracking-[-0.04em] leading-[1.15] text-foreground">{t(`${prefix}Title`)}</h1>
          <p className="m-0 text-[15px] leading-[1.75] text-[#414958] dark:text-[oklch(0.865_0.01_264.5)]">{t(`${prefix}Updated`)}</p>
          {sections.map((section) => (
            <section key={section.title} className="mt-8">
              <h2 className="mb-2 text-lg font-[650] text-foreground">{section.title}</h2>
              <p className="m-0 text-[15px] leading-[1.75] text-[#414958] dark:text-[oklch(0.865_0.01_264.5)]">{section.body}</p>
            </section>
          ))}
          <Button
            asChild
            className="mt-10 h-12 rounded-[11px]! px-[18px] font-[620]! text-sm! hover:-translate-y-px motion-reduce:transition-none"
          >
            <a
              href="/"
              onClick={(event) => { event.preventDefault(); onNavigate('/') }}
            >
              <ArrowLeft size={16} aria-hidden="true" /> {t('footerBackHome')}
            </a>
          </Button>
        </article>
      </main>
    </div>
  )
}
