import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import { i18nOptions, isLanguage, localeStorageKey, resolveInitialLanguage } from './i18n-config'

export { languages, localeStorageKey, namespaces } from './i18n-config'
export type { Language } from './i18n-config'

function getInitialLanguage() {
  const systemLanguages = navigator.languages?.length ? navigator.languages : [navigator.language]
  return resolveInitialLanguage(() => window.localStorage.getItem(localeStorageKey), systemLanguages)
}

const localeFiles = import.meta.glob<Record<string, string>>('./locales/*/*.json', {
  eager: true,
  import: 'default',
})

const resources: Record<string, Record<string, Record<string, string>>> = {}
for (const [path, dictionary] of Object.entries(localeFiles)) {
  const match = path.match(/^\.\/locales\/([^/]+)\/([^/]+)\.json$/)
  if (!match) continue
  const [, language, namespace] = match
  resources[language] ??= {}
  resources[language][namespace] = dictionary
}

void i18n.use(initReactI18next).init({
  ...i18nOptions,
  resources,
  lng: getInitialLanguage(),
  interpolation: { escapeValue: false },
  react: { useSuspense: false },
})

i18n.on('languageChanged', (language) => {
  if (!isLanguage(language)) return
  document.documentElement.lang = language
})

document.documentElement.lang = isLanguage(i18n.resolvedLanguage) ? i18n.resolvedLanguage : 'en'
window.addEventListener('languagechange', () => {
  let hasManualLanguage = false
  try {
    hasManualLanguage = isLanguage(window.localStorage.getItem(localeStorageKey))
  } catch {
    // Fall back to system-language behavior when storage is unavailable.
  }
  if (hasManualLanguage) return
  const systemLanguages = navigator.languages?.length ? navigator.languages : [navigator.language]
  void i18n.changeLanguage(resolveInitialLanguage(() => null, systemLanguages))
})

export default i18n
