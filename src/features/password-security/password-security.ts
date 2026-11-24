export type PasswordCharacterClass = 'lowercase' | 'uppercase' | 'numbers' | 'symbols'
export type PasswordStrength = 'must-change' | 'acceptable' | 'strong'
export type LeakCheckStatus = 'clean' | 'leaked' | 'unavailable'

export interface PasswordGeneratorOptions {
  length: number
  lowercase: boolean
  uppercase: boolean
  numbers: boolean
  symbols: boolean
}

export interface PasswordAssessment {
  strength: PasswordStrength
  length: number
  characterClassCount: number
  commonWeak: boolean
  reused: boolean
  leakStatus: LeakCheckStatus
}

export interface PasswordCheckDependencies {
  fetcher?: FetchLike
  cryptoProvider?: Pick<Crypto, 'getRandomValues' | 'subtle'>
  signal?: AbortSignal
}

export interface PasswordGenerationDependencies extends PasswordCheckDependencies {
  leakChecker?: (password: string, signal?: AbortSignal) => Promise<boolean>
  candidateGenerator?: (options: PasswordGeneratorOptions) => string
}

export interface PasswordGenerationResult {
  password: string | null
  attempts: number
}

export type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>

export const DEFAULT_PASSWORD_OPTIONS: PasswordGeneratorOptions = {
  length: 20,
  lowercase: true,
  uppercase: true,
  numbers: true,
  symbols: true,
}

export const MAX_GENERATION_ATTEMPTS = 5
export const HIBP_RANGE_ENDPOINT = 'https://api.pwnedpasswords.com/range/'

const CHARACTER_SETS: Record<PasswordCharacterClass, string> = {
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  numbers: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?~',
}

const commonWeakPasswords = new Set([
  '123456', '1234567', '12345678', '123456789', '1234567890', '111111', '000000', '00000000',
  '654321', '121212', 'password', 'password1', 'password123', 'password1234', 'passw0rd',
  'p@ssw0rd', 'qwerty', 'qwerty123', 'qwertyuiop', '1q2w3e4r', 'asdfghjkl', 'zxcvbnm',
  'qazwsx', 'abc123', 'letmein', 'welcome', 'admin', 'admin123', 'root', 'login', 'secret',
  'changeme', 'default', 'iloveyou', 'dragon', 'monkey', 'football', 'sunshine', 'princess',
  'trustno1',
])

const CLASS_TESTS: Record<PasswordCharacterClass, RegExp> = {
  lowercase: /\p{Ll}/u,
  uppercase: /\p{Lu}/u,
  numbers: /\p{N}/u,
  symbols: /[^\p{L}\p{N}\s]/u,
}

function enabledClasses(options: PasswordGeneratorOptions): PasswordCharacterClass[] {
  return (Object.keys(CHARACTER_SETS) as PasswordCharacterClass[]).filter((key) => options[key])
}

function validateGeneratorOptions(options: PasswordGeneratorOptions): void {
  if (!Number.isInteger(options.length) || options.length < 12 || options.length > 64) {
    throw new Error('password_length_out_of_range')
  }
  if (enabledClasses(options).length < 2) throw new Error('at_least_two_character_classes_required')
}

function secureRandomIndex(max: number, cryptoProvider: Pick<Crypto, 'getRandomValues'>): number {
  if (!Number.isInteger(max) || max < 1) throw new Error('invalid_random_range')
  const fullRange = 0x1_0000_0000
  const unbiasedLimit = Math.floor(fullRange / max) * max
  const value = new Uint32Array(1)
  do {
    cryptoProvider.getRandomValues(value)
  } while (value[0] >= unbiasedLimit)
  return value[0] % max
}

/** Generate an ASCII password using Web Crypto only, including an unbiased secure shuffle. */
export function generatePasswordCandidate(
  options: PasswordGeneratorOptions = DEFAULT_PASSWORD_OPTIONS,
  cryptoProvider: Pick<Crypto, 'getRandomValues'> = globalThis.crypto,
): string {
  validateGeneratorOptions(options)
  if (!cryptoProvider?.getRandomValues) throw new Error('secure_randomness_unavailable')

  const classes = enabledClasses(options)
  const allCharacters = classes.map((key) => CHARACTER_SETS[key]).join('')
  const characters = classes.map((key) => {
    const characterSet = CHARACTER_SETS[key]
    return characterSet[secureRandomIndex(characterSet.length, cryptoProvider)]
  })

  while (characters.length < options.length) {
    characters.push(allCharacters[secureRandomIndex(allCharacters.length, cryptoProvider)])
  }

  for (let index = characters.length - 1; index > 0; index -= 1) {
    const swapIndex = secureRandomIndex(index + 1, cryptoProvider)
    ;[characters[index], characters[swapIndex]] = [characters[swapIndex], characters[index]]
  }
  return characters.join('')
}

export function getPasswordCharacterClasses(password: string): PasswordCharacterClass[] {
  return (Object.keys(CLASS_TESTS) as PasswordCharacterClass[]).filter((key) => CLASS_TESTS[key].test(password))
}

export function isCommonWeakPassword(password: string): boolean {
  return commonWeakPasswords.has(password.toLocaleLowerCase('en-US'))
}

/** Query HIBP's k-anonymity endpoint; only the first five SHA-1 hex characters leave the browser. */
export async function isPasswordLeaked(
  password: string,
  dependencies: PasswordCheckDependencies = {},
): Promise<boolean> {
  const cryptoProvider = dependencies.cryptoProvider ?? globalThis.crypto
  if (!cryptoProvider?.subtle || !cryptoProvider?.getRandomValues) throw new Error('web_crypto_unavailable')
  const digest = await cryptoProvider.subtle.digest('SHA-1', new TextEncoder().encode(password))
  const fullHash = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('').toUpperCase()
  const prefix = fullHash.slice(0, 5)
  const suffix = fullHash.slice(5)
  const fetcher = dependencies.fetcher ?? globalThis.fetch
  const response = await fetcher(`${HIBP_RANGE_ENDPOINT}${prefix}`, {
    method: 'GET',
    headers: { Accept: 'text/plain' },
    cache: 'no-store',
    credentials: 'omit',
    referrerPolicy: 'no-referrer',
    redirect: 'error',
    signal: dependencies.signal,
  })
  if (!response.ok) throw new Error('hibp_unavailable')

  const suffixes = await response.text()
  return suffixes.split(/\r?\n/).some((line) => {
    const separator = line.indexOf(':')
    if (separator < 0) return false
    return line.slice(0, separator).trim().toUpperCase() === suffix
  })
}

export function assessPasswordLocally(
  password: string,
  options: { leaked?: boolean; reused?: boolean } = {},
): Omit<PasswordAssessment, 'leakStatus'> {
  const length = [...password].length
  const characterClassCount = getPasswordCharacterClasses(password).length
  const commonWeak = isCommonWeakPassword(password)
  const mustChange = length < 12 || characterClassCount <= 1 || commonWeak || options.leaked === true
  const strength: PasswordStrength = mustChange
    ? 'must-change'
    : length >= 20 && characterClassCount >= 3
      ? 'strong'
      : 'acceptable'

  return { strength, length, characterClassCount, commonWeak, reused: options.reused ?? false }
}

export async function assessPasswordHealth(
  password: string,
  reused = false,
  dependencies: PasswordCheckDependencies = {},
): Promise<PasswordAssessment> {
  try {
    const leaked = await isPasswordLeaked(password, dependencies)
    return { ...assessPasswordLocally(password, { leaked, reused }), leakStatus: leaked ? 'leaked' : 'clean' }
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') throw error
    return { ...assessPasswordLocally(password, { reused }), leakStatus: 'unavailable' }
  }
}

export function findReusedPasswordItemIds(items: Array<{ id: string; password: string }>): Set<string> {
  const groups = new Map<string, string[]>()
  for (const item of items) {
    if (!item.password) continue
    const ids = groups.get(item.password) ?? []
    ids.push(item.id)
    groups.set(item.password, ids)
  }

  const reusedIds = new Set<string>()
  for (const ids of groups.values()) {
    if (ids.length < 2) continue
    for (const id of ids) reusedIds.add(id)
  }
  return reusedIds
}

/** Generate and verify candidates serially; no rejected candidate is returned or persisted. */
export async function generateVerifiedPassword(
  options: PasswordGeneratorOptions = DEFAULT_PASSWORD_OPTIONS,
  dependencies: PasswordGenerationDependencies = {},
): Promise<PasswordGenerationResult> {
  const cryptoProvider = dependencies.cryptoProvider ?? globalThis.crypto
  const leakChecker = dependencies.leakChecker ?? ((password, signal) => isPasswordLeaked(password, { ...dependencies, signal }))
  const candidateGenerator = dependencies.candidateGenerator ?? ((candidateOptions) => generatePasswordCandidate(candidateOptions, cryptoProvider))

  for (let attempts = 1; attempts <= MAX_GENERATION_ATTEMPTS; attempts += 1) {
    if (dependencies.signal?.aborted) throw new DOMException('Aborted', 'AbortError')
    const candidate = candidateGenerator(options)
    if (isCommonWeakPassword(candidate)) continue
    if (await leakChecker(candidate, dependencies.signal)) continue
    return { password: candidate, attempts }
  }
  return { password: null, attempts: MAX_GENERATION_ATTEMPTS }
}
