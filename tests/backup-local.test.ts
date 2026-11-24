import assert from 'node:assert/strict'
import test from 'node:test'
import {
  getCsvHeaders,
  getImportFileModifiedAt,
  inspectBackupContainer,
  parseCsvWithMapping,
  parseImportText,
} from '../src/features/settings/backup-local.ts'

const userId = '123e4567-e89b-42d3-a456-426614174000'
const base64 = (length: number) => Buffer.alloc(length, 7).toString('base64')
const kdfParams = '{"algorithm":"argon2id","m":65536,"output_len":32,"p":4,"t":3}'

test('import file modification metadata is usable only when the browser provides a valid timestamp', () => {
  assert.equal(getImportFileModifiedAt(Date.UTC(2026, 10, 21, 10, 0, 0)), '2026-11-21T10:00:00.000Z')
  assert.equal(getImportFileModifiedAt(0), null)
  assert.equal(getImportFileModifiedAt(-1), null)
  assert.equal(getImportFileModifiedAt(Number.NaN), null)
  assert.equal(getImportFileModifiedAt(Number.POSITIVE_INFINITY), null)
  assert.equal(getImportFileModifiedAt(Number.MAX_VALUE), null)
})

function v3Container() {
  const wrap = (kind: 'kek' | 'recovery_key') => ({
    ciphertext: base64(16),
    dek_version: 1,
    kdf_params: kdfParams,
    kdf_salt: base64(16),
    kind,
    nonce: base64(12),
    ...(kind === 'kek' ? { master_password_version: 1 } : {}),
  })
  return {
    backup_format_version: 3,
    created_at: '2026-11-22T12:00:00Z',
    dek_wrappings: [wrap('kek'), wrap('recovery_key')],
    items: [],
    manifest: { ciphertext: base64(16), nonce: base64(12) },
    source_user_id: userId,
  }
}

test('CSV import detects standard columns, quoted commas, tags, and UTF-8 BOM', () => {
  const source = '\uFEFFname,url,username,password,note,tags,favorite\r\n"Work, email",https://example.test,user,secret,"a note","one; two",yes\r\n'
  const parsed = parseImportText('vault.csv', source)
  assert.equal(parsed.format, 'csv')
  assert.deepEqual(parsed.rows, [{
    sourceIndex: 2,
    name: 'Work, email',
    url: 'https://example.test',
    username: 'user',
    password: 'secret',
    note: 'a note',
    category: '',
    tags: ['one', 'two'],
    favorite: true,
  }])
})

test('CSV manual mapping exposes headers and maps optional fields without persisting secrets', () => {
  const source = 'Title,Site,Login,Secret,Folder\nMail,https://mail.example.test,alice,very-secret,Personal\n'
  assert.deepEqual(getCsvHeaders(source), ['Title', 'Site', 'Login', 'Secret', 'Folder'])
  const parsed = parseCsvWithMapping(source, { name: 0, url: 1, username: 2, password: 3, category: 4 })
  assert.equal(parsed.rows[0].category, 'Personal')
  assert.equal(parsed.rows[0].password, 'very-secret')
  assert.throws(() => parseCsvWithMapping(source, { name: 0, url: 1, username: 2, password: 8 }), { message: 'csv_invalid_mapping' })
})

test('CSV import preserves leading and trailing whitespace in passwords', () => {
  const source = 'Title,Website,Login,Password\nMail,https://mail.example.test,alice,"  secret  "\n'
  const detected = parseImportText('vault.csv', source)
  const mapped = parseCsvWithMapping(source, { name: 0, url: 1, username: 2, password: 3 })
  assert.equal(detected.rows[0]?.password, '  secret  ')
  assert.equal(mapped.rows[0]?.password, '  secret  ')
})

test('CSV import rejects incomplete mappings and malformed quoted fields', () => {
  assert.throws(() => parseImportText('bad.csv', 'title,site\nMail,https://example.test'), { message: 'csv_mapping_required' })
  assert.throws(() => parseImportText('bad.csv', 'name,url,username,password\n"unfinished,https://example.test,user,secret'), { message: 'csv_unclosed_quote' })
})

test('Bitwarden JSON imports login records, tags, favorites, notes, and folder names', () => {
  const source = JSON.stringify({
    encrypted: false,
    folders: [{ id: 'folder-1', name: 'Personal' }],
    items: [{
      type: 1,
      name: 'Email',
      notes: 'private note',
      favorite: true,
      folderId: 'folder-1',
      tags: ['mail'],
      login: { username: 'alice', password: 'pw', uris: [{ uri: 'https://mail.example.test' }] },
    }, { type: 2, name: 'Card' }],
  })
  const parsed = parseImportText('vault.json', source)
  assert.equal(parsed.format, 'bitwarden-json')
  assert.deepEqual(parsed.rows, [{
    sourceIndex: 1,
    name: 'Email',
    url: 'https://mail.example.test',
    username: 'alice',
    password: 'pw',
    note: 'private note',
    category: 'Personal',
    tags: ['mail'],
    favorite: true,
  }])
})

test('Bitwarden rejects encrypted, malformed, and unsupported exports', () => {
  assert.throws(() => parseImportText('vault.json', '{"encrypted":true,"items":[]}'), { message: 'bitwarden_encrypted_export' })
  assert.throws(() => parseImportText('vault.json', '{'), { message: 'bitwarden_json_invalid' })
  assert.throws(() => parseImportText('vault.txt', 'name'), { message: 'import_unsupported_file' })
})

test('legacy v1 and v2 containers are recognized without imposing the v3 wrapper schema', () => {
  const v1 = inspectBackupContainer(JSON.stringify({ backup_format_version: 1, source_user_id: userId, dek_wrappings: [], items: [] }) + '\n')
  assert.equal(v1.version, 1)
  assert.equal(v1.itemCountInContainer, 0)
  const v2 = inspectBackupContainer(JSON.stringify({ backup_format_version: 2, source_user_id: userId, dek_wrappings: [], items: [], manifest: { ciphertext: 'old-format' } }) + '\n')
  assert.equal(v2.version, 2)
})

test('v3 backup container accepts exact current shapes and reports that integrity remains unchecked', () => {
  const summary = inspectBackupContainer(JSON.stringify(v3Container()))
  assert.deepEqual(summary, {
    version: 3,
    sourceUserId: userId,
    createdAt: '2026-11-22T12:00:00Z',
    itemCountInContainer: 0,
    integrityCheck: 'not-run',
  })
})

test('v3 backup container accepts a KEK-only container (auto-backup) but rejects zero wrappings', () => {
  const kekOnly = v3Container()
  kekOnly.dek_wrappings = [kekOnly.dek_wrappings[0]!]
  assert.equal(inspectBackupContainer(JSON.stringify(kekOnly)).version, 3)

  const none = v3Container()
  none.dek_wrappings = []
  assert.throws(() => inspectBackupContainer(JSON.stringify(none)), { message: 'backup_invalid_container' })
})

test('v3 backup allows one previous DEK wrapped by the recovery key and enforces generation order', () => {
  const rotated = v3Container()
  rotated.dek_wrappings[0].dek_version = 2
  rotated.dek_wrappings[1].dek_version = 2
  rotated.dek_wrappings.push({ ...rotated.dek_wrappings[1], dek_version: 1 })
  assert.equal(inspectBackupContainer(JSON.stringify(rotated)).version, 3)

  const misordered = v3Container()
  misordered.dek_wrappings[1].dek_version = 2
  assert.throws(() => inspectBackupContainer(JSON.stringify(misordered)), { message: 'backup_invalid_container' })

  const tooMany = v3Container()
  tooMany.dek_wrappings.push({ ...tooMany.dek_wrappings[1], dek_version: 0 })
  assert.throws(() => inspectBackupContainer(JSON.stringify(tooMany)), { message: 'backup_invalid_container' })
})

test('v3 backup validation rejects unknown fields, trailing bytes, duplicate keys, and non-whitelisted KDF profiles', () => {
  const extra = v3Container() as Record<string, unknown>
  extra.unexpected = true
  assert.throws(() => inspectBackupContainer(JSON.stringify(extra)), { message: 'backup_invalid_container' })
  const prototypeKey = `${JSON.stringify(v3Container()).slice(0, -1)},"__proto__":{"unexpected":true}}`
  assert.throws(() => inspectBackupContainer(prototypeKey), { message: 'backup_invalid_container' })
  assert.throws(() => inspectBackupContainer(JSON.stringify(v3Container()) + '\n'), { message: 'backup_trailing_bytes' })
  assert.throws(() => inspectBackupContainer('{"backup_format_version":3,"backup_format_version":3}'), { message: 'backup_duplicate_key' })

  const invalidKdf = v3Container()
  invalidKdf.dek_wrappings[0].kdf_params = '{"algorithm":"argon2id","m":65536,"output_len":32,"p":2,"t":3}'
  assert.throws(() => inspectBackupContainer(JSON.stringify(invalidKdf)), { message: 'backup_invalid_container' })

  const invalidDate = v3Container()
  invalidDate.created_at = '2026-13-22T12:00:00Z'
  assert.throws(() => inspectBackupContainer(JSON.stringify(invalidDate)), { message: 'backup_invalid_container' })
})

test('backup version whitelist rejects future formats distinctly', () => {
  assert.throws(() => inspectBackupContainer(JSON.stringify({ backup_format_version: 4 })), { message: 'backup_future_version' })
  assert.throws(() => inspectBackupContainer(JSON.stringify({ backup_format_version: 0 })), { message: 'backup_invalid_version' })
})
