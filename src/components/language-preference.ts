import { isLanguage, localeStorageKey, resolveInitialLanguage, type Language } from '../i18n-config.ts'

export interface LanguagePreferenceStorage {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
}

export function saveLanguageSelection(language: Language, storage: LanguagePreferenceStorage): void {
  storage.setItem(localeStorageKey, language)
}

export function restoreLanguageSelection(
  storage: Pick<LanguagePreferenceStorage, 'getItem'>,
  systemLanguages: readonly string[],
): Language {
  return resolveInitialLanguage(() => storage.getItem(localeStorageKey), systemLanguages)
}

export function isManualLanguageSelection(value: string | null): value is Language {
  return isLanguage(value)
}
