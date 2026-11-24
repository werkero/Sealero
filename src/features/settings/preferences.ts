import { useCallback, useEffect, useState } from 'react'
import i18n from '../../i18n'
import { detectSystemLanguage, isLanguage, localeStorageKey, type Language } from '../../i18n-config'

export type LanguagePreference = 'system' | Language
export type AppearancePreference = 'system' | 'light' | 'dark'
export const appearanceStorageKey = 'sealero.appearance'

function safeStorageRead(key: string): string | null {
  try {
    return window.localStorage.getItem(key)
  } catch {
    return null
  }
}

export function getLanguagePreference(): LanguagePreference {
  const saved = safeStorageRead(localeStorageKey)
  return isLanguage(saved) ? saved : 'system'
}

export function resolveSystemLanguage(): Language {
  const candidates = navigator.languages?.length ? navigator.languages : [navigator.language]
  return detectSystemLanguage(candidates)
}

export async function applyLanguagePreference(preference: LanguagePreference): Promise<void> {
  try {
    if (preference === 'system') window.localStorage.removeItem(localeStorageKey)
    else window.localStorage.setItem(localeStorageKey, preference)
  } catch {
    // The current session can still use the selected language if local preferences cannot be saved.
  }
  await i18n.changeLanguage(preference === 'system' ? resolveSystemLanguage() : preference)
}

export function readAppearancePreference(): AppearancePreference {
  const saved = safeStorageRead(appearanceStorageKey)
  return saved === 'light' || saved === 'dark' ? saved : 'system'
}

function resolveAppearance(preference: AppearancePreference, systemDark: boolean): 'light' | 'dark' {
  return preference === 'system' ? (systemDark ? 'dark' : 'light') : preference
}

function applyAppearanceImmediately(): void {
  if (typeof window === 'undefined' || typeof document === 'undefined') return
  const systemDark = window.matchMedia?.('(prefers-color-scheme: dark)').matches ?? false
  const theme = resolveAppearance(readAppearancePreference(), systemDark)
  document.documentElement.dataset.theme = theme
  document.documentElement.style.colorScheme = theme
}

export function useAppearancePreference(): [AppearancePreference, (preference: AppearancePreference) => void] {
  const [preference, setPreferenceState] = useState<AppearancePreference>(readAppearancePreference)
  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: dark)')
    const apply = () => {
      const theme = resolveAppearance(preference, media.matches)
      document.documentElement.dataset.theme = theme
      document.documentElement.style.colorScheme = theme
    }
    apply()
    media.addEventListener('change', apply)
    return () => media.removeEventListener('change', apply)
  }, [preference])
  const setPreference = useCallback((next: AppearancePreference) => {
    setPreferenceState(next)
    try {
      if (next === 'system') window.localStorage.removeItem(appearanceStorageKey)
      else window.localStorage.setItem(appearanceStorageKey, next)
    } catch {
      // The chosen theme remains active for this page session.
    }
  }, [])
  return [preference, setPreference]
}

applyAppearanceImmediately()
