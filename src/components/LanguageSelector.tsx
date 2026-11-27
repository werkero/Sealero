import { Languages } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import i18n from '../i18n'
import { isLanguage, languages } from '../i18n-config'
import { saveLanguageSelection } from './language-preference'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from './ui/dropdown-menu'

/** One language icon in page headers; clicking it opens the language menu. */
export function LanguageSelector() {
  const { t } = useTranslation('common')
  const selectedLanguage = i18n.resolvedLanguage ?? 'en'
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button type="button" className="theme-toggle" aria-label={t('language')} title={t('language')}>
          <Languages size={18} aria-hidden="true" />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuRadioGroup
          value={isLanguage(selectedLanguage) ? selectedLanguage : 'en'}
          onValueChange={(value) => {
            if (!isLanguage(value)) return
            try {
              saveLanguageSelection(value, window.localStorage)
            } catch {
              // Language switching still works when local config storage is unavailable.
            }
            void i18n.changeLanguage(value)
          }}
        >
          {languages.map((language) => (
            <DropdownMenuRadioItem key={language.code} value={language.code}>
              {language.label}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
