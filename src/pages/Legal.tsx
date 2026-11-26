import { ArrowLeft } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Brand } from '../components/Brand'
import { LanguageSelector } from '../components/LanguageSelector'
import { ThemeToggle } from '../components/ThemeToggle'
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
    <div className="public-shell">
      <header className="public-header">
        <Brand onNavigate={onNavigate} />
        <div className="public-header-actions">
          <ThemeToggle onAppearanceChange={onAppearanceChange} />
          <LanguageSelector />
        </div>
      </header>
      <main className="legal-main">
        <article className="legal-doc">
          <h1>{t(`${prefix}Title`)}</h1>
          <p className="legal-updated">{t(`${prefix}Updated`)}</p>
          {sections.map((section) => (
            <section key={section.title}>
              <h2>{section.title}</h2>
              <p>{section.body}</p>
            </section>
          ))}
          <a
            className="button button-primary legal-back-home"
            href="/"
            onClick={(event) => { event.preventDefault(); onNavigate('/') }}
          >
            <ArrowLeft size={16} aria-hidden="true" /> {t('footerBackHome')}
          </a>
        </article>
      </main>
    </div>
  )
}
