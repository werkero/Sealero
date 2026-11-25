import { useTranslation } from 'react-i18next'
import { Brand } from '../components/Brand'

export type LegalDoc = 'terms' | 'privacy'

const SECTION_COUNT = 4

export function LegalPage({ doc, onNavigate }: { doc: LegalDoc; onNavigate: (path: string) => void }) {
  const { t } = useTranslation('common')
  const prefix = doc === 'terms' ? 'terms' : 'privacy'
  const sections = Array.from({ length: SECTION_COUNT }, (_, i) => i + 1).map((n) => ({
    title: t(`${prefix}S${n}Title`),
    body: t(`${prefix}S${n}Body`),
  }))
  return (
    <div className="public-shell">
      <header className="public-header">
        <Brand onNavigate={onNavigate} />
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
            className="text-link"
            href="/"
            onClick={(event) => { event.preventDefault(); onNavigate('/') }}
          >
            ← {t('footerBackHome')}
          </a>
        </article>
      </main>
    </div>
  )
}
