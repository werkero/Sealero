import { useEffect, useState } from 'react'
import { Moon, Sun } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { AppearancePreference } from '../features/settings/preferences'

/** Sun/moon switch for page headers. Toggles an explicit light/dark choice. */
export function ThemeToggle({
  onAppearanceChange,
}: {
  onAppearanceChange: (preference: AppearancePreference) => void
}) {
  const { t } = useTranslation('common')
  const [isDark, setIsDark] = useState(
    () =>
      typeof document !== 'undefined' &&
      document.documentElement.dataset.theme === 'dark',
  )
  useEffect(() => {
    const update = () =>
      setIsDark(document.documentElement.dataset.theme === 'dark')
    update()
    const observer = new MutationObserver(update)
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme'],
    })
    return () => observer.disconnect()
  }, [])
  return (
    <button
      type="button"
      className="inline-flex h-9 min-h-9 w-9 cursor-pointer items-center justify-center rounded-[9px] border border-transparent bg-transparent p-0 text-muted-foreground hover:border-border hover:bg-muted hover:text-foreground focus-visible:outline-3 focus-visible:outline-[#a9c3ff] focus-visible:outline-offset-[3px]"
      aria-label={t('toggleTheme')}
      title={t('toggleTheme')}
      aria-pressed={isDark}
      onClick={() => onAppearanceChange(isDark ? 'light' : 'dark')}
    >
      {isDark ? (
        <Sun size={18} aria-hidden="true" />
      ) : (
        <Moon size={18} aria-hidden="true" />
      )}
    </button>
  )
}
