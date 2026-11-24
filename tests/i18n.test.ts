import assert from 'node:assert/strict'
import { readdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import i18next from 'i18next'
import test from 'node:test'
import {
  detectSystemLanguage,
  i18nOptions,
  isLanguage,
  languages,
  namespaces,
  resolveInitialLanguage,
} from '../src/i18n-config.ts'
import { restoreLanguageSelection, saveLanguageSelection } from '../src/components/language-preference.ts'

const localesDirectory = fileURLToPath(new URL('../src/locales', import.meta.url))

async function readDictionary(language: string, namespace: string): Promise<Record<string, unknown>> {
  const filePath = join(localesDirectory, language, `${namespace}.json`)
  return JSON.parse(await readFile(filePath, 'utf8')) as Record<string, unknown>
}

function leafKeys(value: unknown, prefix = ''): string[] {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return Object.entries(value).flatMap(([key, child]) => leafKeys(child, prefix ? `${prefix}.${key}` : key))
  }
  return [prefix]
}

function leafValues(value: unknown): unknown[] {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return Object.values(value).flatMap(leafValues)
  }
  return [value]
}

test('V1 exposes only the six fixed languages and six fixed translation modules', async () => {
  assert.deepEqual(languages.map(({ code }) => code), ['en', 'zh-Hans', 'zh-Hant', 'fr', 'de', 'ru'])
  assert.deepEqual(namespaces, ['common', 'auth', 'vault', 'settings', 'backup', 'admin'])
  assert.deepEqual(i18nOptions.supportedLngs, languages.map(({ code }) => code))
  assert.equal(i18nOptions.fallbackLng, 'en')

  const localeDirectories = (await readdir(localesDirectory, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort()
  assert.deepEqual(localeDirectories, languages.map(({ code }) => code).sort())

  for (const language of languages) {
    const files = (await readdir(join(localesDirectory, language.code)))
      .filter((file) => file.endsWith('.json'))
      .map((file) => file.replace(/\.json$/, ''))
      .sort()
    assert.deepEqual(files, [...namespaces].sort(), `${language.code} must have exactly the fixed module files`)
  }
})

test('all six language dictionaries have the same nonempty module key sets as English', async () => {
  const english = new Map<string, string[]>()
  for (const namespace of namespaces) {
    english.set(namespace, leafKeys(await readDictionary('en', namespace)).sort())
  }

  for (const { code } of languages) {
    for (const namespace of namespaces) {
      const dictionary = await readDictionary(code, namespace)
      assert.deepEqual(leafKeys(dictionary).sort(), english.get(namespace), `${code}/${namespace} keys must match English`)
      assert.ok(leafValues(dictionary).every((value) => typeof value === 'string' && value.trim().length > 0), `${code}/${namespace} must not contain empty translations`)
    }
  }
})

test('API status copy describes only the health endpoint in all six languages', async () => {
  const expectedCopy: Record<string, { checking: string; online: string; unavailable: string }> = {
    en: {
      checking: 'Checking health endpoint…',
      online: 'Health endpoint reachable',
      unavailable: 'Health endpoint unavailable',
    },
    'zh-Hans': {
      checking: '正在检查健康端点…',
      online: '健康检查端点可访问',
      unavailable: '健康端点不可访问',
    },
    'zh-Hant': {
      checking: '正在檢查健康端點…',
      online: '健康檢查端點可連線',
      unavailable: '健康端點無法存取',
    },
    de: {
      checking: 'Health-Endpunkt wird geprüft …',
      online: 'Health-Endpunkt erreichbar',
      unavailable: 'Health-Endpunkt nicht erreichbar',
    },
    fr: {
      checking: 'Vérification du point de terminaison de santé…',
      online: 'Point de terminaison de santé joignable',
      unavailable: 'Point de terminaison de santé indisponible',
    },
    ru: {
      checking: 'Проверка эндпоинта состояния…',
      online: 'Эндпоинт проверки состояния доступен',
      unavailable: 'Эндпоинт проверки состояния недоступен',
    },
  }

  for (const { code } of languages) {
    const common = await readDictionary(code, 'common')
    assert.deepEqual({
      checking: common.apiStatusChecking,
      online: common.apiStatusOnline,
      unavailable: common.apiStatusUnavailable,
    }, expectedCopy[code], `${code} API status copy must refer specifically to the health endpoint`)
  }
})

test('admin users section lives in the central admin dictionary with matching nonempty keys in all six languages', async () => {
  const english = (await readDictionary('en', 'admin'))['users'] as Record<string, unknown>
  const expectedKeys = leafKeys(english).sort()

  for (const { code } of languages) {
    const users = (await readDictionary(code, 'admin'))['users'] as Record<string, unknown>
    assert.deepEqual(leafKeys(users).sort(), expectedKeys, `${code}/admin users keys must match English`)
    assert.ok(leafValues(users).every((value) => typeof value === 'string' && value.trim().length > 0), `${code}/admin users must not contain empty translations`)
  }
})

test('system-language detection maps regional preferences and Chinese scripts correctly', () => {
  assert.equal(detectSystemLanguage(['fr-CA', 'en-US']), 'fr')
  assert.equal(detectSystemLanguage(['de-AT']), 'de')
  assert.equal(detectSystemLanguage(['ru-RU']), 'ru')
  assert.equal(detectSystemLanguage(['zh-Hant-HK']), 'zh-Hant')
  assert.equal(detectSystemLanguage(['zh-TW']), 'zh-Hant')
  assert.equal(detectSystemLanguage(['zh-Hans-SG']), 'zh-Hans')
  assert.equal(detectSystemLanguage(['zh-CN']), 'zh-Hans')
  assert.equal(detectSystemLanguage(['es-ES', 'fr-FR']), 'fr')
  assert.equal(detectSystemLanguage([]), 'en')
})

test('a valid locally saved language overrides system detection; invalid or unavailable storage falls back to the system', () => {
  assert.equal(isLanguage('zh-Hans'), true)
  assert.equal(isLanguage('zh'), false)
  assert.equal(resolveInitialLanguage(() => 'zh-Hant', ['fr-FR']), 'zh-Hant')
  assert.equal(resolveInitialLanguage(() => 'unsupported', ['de-DE']), 'de')
  assert.equal(resolveInitialLanguage(() => { throw new Error('storage_unavailable') }, ['ru-RU']), 'ru')
})

test('the language selector saves sealero.language and restores the saved choice after reload', () => {
  const values = new Map<string, string>()
  const storage = {
    getItem(key: string) { return values.get(key) ?? null },
    setItem(key: string, value: string) { values.set(key, value) },
  }
  saveLanguageSelection('zh-Hant', storage)
  assert.equal(values.get('sealero.language'), 'zh-Hant')
  assert.equal(restoreLanguageSelection(storage, ['fr-FR']), 'zh-Hant')
})

test('a missing localized key falls back to English in the same namespace and never renders its key', async () => {
  const englishVault = await readDictionary('en', 'vault')
  const frenchVault = await readDictionary('fr', 'vault')
  englishVault.i18nFallbackProbe = 'English vault fallback'
  delete frenchVault.i18nFallbackProbe
  const englishCommon = await readDictionary('en', 'common')
  englishCommon.i18nFallbackProbe = 'Wrong common namespace'

  const fallbackResources = {
    en: { vault: englishVault, common: englishCommon },
    fr: { vault: frenchVault, common: await readDictionary('fr', 'common') },
  }
  const instance = i18next.createInstance()
  await instance.init({ ...i18nOptions, lng: 'fr', resources: fallbackResources as never })

  assert.equal(instance.t('vault:i18nFallbackProbe'), 'English vault fallback')
  assert.equal(instance.t('vault:keyNotDefinedInAnyLanguage'), '')
})
