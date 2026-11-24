import { useTranslation } from 'react-i18next'
import i18n from '../i18n'
import { isLanguage, languages } from '../i18n-config'
import { saveLanguageSelection } from './language-preference'

export function LanguageSelector() {
  const { t } = useTranslation('common')
  const selectedLanguage = i18n.resolvedLanguage ?? 'en'
  return (
    <label className="language-control">
      <span className="visually-hidden">{t('language')}</span>
      <select
        aria-label={t('language')}
        value={isLanguage(selectedLanguage) ? selectedLanguage : 'en'}
        onChange={(event) => {
          const language = event.target.value
          if (!isLanguage(language)) return
          try {
            saveLanguageSelection(language, window.localStorage)
          } catch {
            // Language switching still works when local config storage is unavailable.
          }
          void i18n.changeLanguage(language)
        }}
      >
        {languages.map((language) => (
          <option key={language.code} value={language.code}>{language.label}</option>
        ))}
      </select>
    </label>
  )
}
