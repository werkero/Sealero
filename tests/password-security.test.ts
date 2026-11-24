import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import test from 'node:test'
import {
  assessPasswordHealth,
  assessPasswordLocally,
  DEFAULT_PASSWORD_OPTIONS,
  findReusedPasswordItemIds,
  generatePasswordCandidate,
  generateVerifiedPassword,
  HIBP_RANGE_ENDPOINT,
  isCommonWeakPassword,
  isPasswordLeaked,
  MAX_GENERATION_ATTEMPTS,
} from '../src/features/password-security/password-security.ts'

const randomPasswordOptions = {
  length: 12,
  lowercase: true,
  uppercase: false,
  numbers: true,
  symbols: false,
}
const symbolCharacters = '!@#$%^&*()-_=+[]{};:,.?~'

test('generator respects 12, 20, and 64 character boundaries with default length 20', () => {
  assert.equal(DEFAULT_PASSWORD_OPTIONS.length, 20)
  for (const length of [12, 20, 64]) {
    const candidate = generatePasswordCandidate({ ...DEFAULT_PASSWORD_OPTIONS, length })
    assert.equal([...candidate].length, length)
  }
})

test('every enabled character class appears at least once and all four default classes are represented', () => {
  for (let count = 0; count < 30; count += 1) {
    const candidate = generatePasswordCandidate(randomPasswordOptions)
    assert.match(candidate, /[a-z]/)
    assert.match(candidate, /\d/)
    assert.doesNotMatch(candidate, /[A-Z]/)
    assert.equal([...symbolCharacters].some((character) => candidate.includes(character)), false)

    const defaultCandidate = generatePasswordCandidate()
    assert.match(defaultCandidate, /[a-z]/)
    assert.match(defaultCandidate, /[A-Z]/)
    assert.match(defaultCandidate, /\d/)
    assert.equal([...symbolCharacters].some((character) => defaultCandidate.includes(character)), true)
  }
})

test('generator rejects out-of-range lengths and fewer than two classes', () => {
  assert.throws(() => generatePasswordCandidate({ ...DEFAULT_PASSWORD_OPTIONS, length: 11 }), /password_length_out_of_range/)
  assert.throws(() => generatePasswordCandidate({ ...DEFAULT_PASSWORD_OPTIONS, length: 65 }), /password_length_out_of_range/)
  assert.throws(() => generatePasswordCandidate({ ...DEFAULT_PASSWORD_OPTIONS, lowercase: false, uppercase: false, numbers: true, symbols: false }), /at_least_two_character_classes_required/)
})

test('after five leaked candidates the generator returns no password', async () => {
  let checks = 0
  const result = await generateVerifiedPassword(DEFAULT_PASSWORD_OPTIONS, {
    leakChecker: async () => {
      checks += 1
      return true
    },
  })
  assert.equal(MAX_GENERATION_ATTEMPTS, 5)
  assert.equal(checks, 5)
  assert.deepEqual(result, { password: null, attempts: 5 })
})

test('a common weak candidate is discarded before HIBP and the next safe candidate is returned', async () => {
  const candidates = ['Password1234', 'Abcdefghij123456!xyz']
  const checkedPasswords: string[] = []
  const result = await generateVerifiedPassword(DEFAULT_PASSWORD_OPTIONS, {
    candidateGenerator: () => candidates.shift() ?? '',
    leakChecker: async (password) => {
      checkedPasswords.push(password)
      return false
    },
  })
  assert.deepEqual(result, { password: 'Abcdefghij123456!xyz', attempts: 2 })
  assert.deepEqual(checkedPasswords, ['Abcdefghij123456!xyz'])
})

test('weak, acceptable, and strong thresholds honor exact length boundaries', () => {
  assert.equal(assessPasswordLocally('abcdefghijk', { leaked: false }).strength, 'must-change')
  assert.equal(assessPasswordLocally('Abcd1234!xyz', { leaked: false }).strength, 'acceptable')
  assert.equal(assessPasswordLocally('Abcdefghij123456!xy', { leaked: false }).strength, 'acceptable')
  assert.equal(assessPasswordLocally('Abcdefghij123456!xyz', { leaked: false }).strength, 'strong')
  assert.equal(assessPasswordLocally('password1234', { leaked: false }).strength, 'must-change')
  assert.equal(assessPasswordLocally('Abcdefghij123456!xyz', { leaked: true }).strength, 'must-change')
  assert.equal(isCommonWeakPassword('Password123'), true)
  assert.equal(isCommonWeakPassword('Password1234'), true)
})

test('reused passwords are detected across item IDs without exposing their values in the result', () => {
  const reused = findReusedPasswordItemIds([
    { id: 'a', password: 'same-password' },
    { id: 'b', password: 'same-password' },
    { id: 'c', password: 'different-password' },
    { id: 'd', password: '' },
    { id: 'e', password: '' },
  ])
  assert.deepEqual([...reused].sort(), ['a', 'b'])
  assert.equal(assessPasswordLocally('Abcd1234!xyz', { reused: true }).reused, true)
})

test('HIBP request contains only the five-character SHA-1 prefix and never the password or full hash', async () => {
  const password = 'safe-Fruit-41!xQ'
  const fullHash = createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase()
  let requestedUrl = ''
  let requestInit: RequestInit | undefined
  const fetcher = async (input: RequestInfo | URL, init?: RequestInit) => {
    requestedUrl = String(input)
    requestInit = init
    return new Response(`${fullHash.slice(5)}:42\n`, { status: 200 })
  }

  assert.equal(await isPasswordLeaked(password, { fetcher }), true)
  assert.equal(requestedUrl, `${HIBP_RANGE_ENDPOINT}${fullHash.slice(0, 5)}`)
  assert.equal(requestedUrl.includes(password), false)
  assert.equal(requestedUrl.includes(fullHash), false)
  assert.equal(JSON.stringify(requestInit).includes(password), false)
  assert.equal(JSON.stringify(requestInit).includes(fullHash), false)
  assert.equal(requestInit?.method, 'GET')
  assert.equal(requestInit?.body, undefined)
  assert.equal(requestInit?.cache, 'no-store')
  assert.equal(requestInit?.credentials, 'omit')
  assert.equal(requestInit?.referrerPolicy, 'no-referrer')
})

test('breach-check network failure stays an unknown status and does not leak the password in errors', async () => {
  const password = 'LongEnough-Mixed-14!'
  const assessment = await assessPasswordHealth(password, false, {
    fetcher: async () => new Response('', { status: 503 }),
  })
  assert.equal(assessment.leakStatus, 'unavailable')
  assert.equal(assessment.strength, 'strong')
  await assert.rejects(
    isPasswordLeaked(password, { fetcher: async () => new Response('', { status: 503 }) }),
    (error: unknown) => error instanceof Error && error.message === 'hibp_unavailable' && !error.message.includes(password),
  )
})
