export const languages = [
  { code: 'en', label: 'English' },
  { code: 'zh-Hans', label: '简体中文' },
  { code: 'zh-Hant', label: '繁體中文' },
  { code: 'fr', label: 'Français' },
  { code: 'de', label: 'Deutsch' },
  { code: 'ru', label: 'Русский' },
] as const

export type Language = (typeof languages)[number]['code']

export const localeStorageKey = 'sealero.language'
export const namespaces = ['common', 'auth', 'vault', 'settings', 'backup', 'admin'] as const
export const i18nOptions = {
  fallbackLng: 'en',
  supportedLngs: languages.map(({ code }) => code),
  ns: [...namespaces],
  defaultNS: 'common',
  returnEmptyString: false,
  parseMissingKeyHandler: () => '',
} as const

export function isLanguage(value: string | null | undefined): value is Language {
  return languages.some((language) => language.code === value)
}

export function detectSystemLanguage(candidates: readonly string[] | null | undefined): Language {
  for (const candidate of candidates ?? []) {
    const locale = candidate.trim().replaceAll('_', '-').toLowerCase()
    if (!locale) continue

    const parts = locale.split('-')
    if (parts[0] === 'zh') {
      const script = parts.slice(1).find((part) => /^[a-z]{4}$/.test(part))
      if (script === 'hant') return 'zh-Hant'
      if (script === 'hans') return 'zh-Hans'
      if (parts.slice(1).some((part) => ['tw', 'hk', 'mo'].includes(part))) return 'zh-Hant'
      return 'zh-Hans'
    }

    const match = languages.find(({ code }) => {
      const normalizedCode = code.toLowerCase()
      return locale === normalizedCode || locale.startsWith(`${normalizedCode}-`)
    })
    if (match) return match.code
  }

  return 'en'
}

export function resolveInitialLanguage(
  readSavedLanguage: () => string | null,
  systemCandidates: readonly string[] | null | undefined,
): Language {
  try {
    const savedLanguage = readSavedLanguage()
    if (isLanguage(savedLanguage)) return savedLanguage
  } catch {
    // Browser storage can be unavailable; system-language detection remains available.
  }

  return detectSystemLanguage(systemCandidates)
}
