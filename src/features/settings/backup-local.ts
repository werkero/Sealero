export interface ImportedVaultEntry {
  sourceIndex: number
  name: string
  url: string
  username: string
  password: string
  note: string
  category: string
  tags: string[]
  favorite: boolean
}

export interface ParsedImportFile {
  format: 'csv' | 'bitwarden-json'
  headers: string[]
  rows: ImportedVaultEntry[]
}

export type ImportField = 'name' | 'url' | 'username' | 'password' | 'note' | 'category' | 'tags' | 'favorite'

export function getImportFileModifiedAt(lastModified: number): string | null {
  if (!Number.isFinite(lastModified) || lastModified <= 0) return null
  const modifiedAt = new Date(lastModified)
  return Number.isNaN(modifiedAt.getTime()) ? null : modifiedAt.toISOString()
}

const importAliases: Record<ImportField, string[]> = {
  name: ['name', 'title', 'item name', 'login name'],
  url: ['url', 'website', 'hostname', 'login_uri', 'login uri', 'uri'],
  username: ['username', 'user name', 'login_username', 'login username', 'login'],
  password: ['password', 'login_password', 'login password'],
  note: ['note', 'notes', 'comments'],
  category: ['category', 'folder', 'group'],
  tags: ['tags', 'tag'],
  favorite: ['favorite', 'favourite', 'starred'],
}

const emptyEntry = (sourceIndex: number): ImportedVaultEntry => ({
  sourceIndex,
  name: '',
  url: '',
  username: '',
  password: '',
  note: '',
  category: '',
  tags: [],
  favorite: false,
})

function csvRows(source: string): string[][] {
  const rows: string[][] = []
  let row: string[] = []
  let field = ''
  let quoted = false
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index]
    if (quoted) {
      if (character === '"' && source[index + 1] === '"') {
        field += '"'
        index += 1
      } else if (character === '"') {
        quoted = false
      } else {
        field += character
      }
      continue
    }
    if (character === '"' && field.length === 0) {
      quoted = true
    } else if (character === ',') {
      row.push(field)
      field = ''
    } else if (character === '\n' || character === '\r') {
      if (character === '\r' && source[index + 1] === '\n') index += 1
      row.push(field)
      field = ''
      if (row.some((value) => value.length > 0)) rows.push(row)
      row = []
    } else {
      field += character
    }
  }
  if (quoted) throw new Error('csv_unclosed_quote')
  row.push(field)
  if (row.some((value) => value.length > 0)) rows.push(row)
  if (rows.length < 1) throw new Error('csv_empty')
  return rows
}

function normalizedHeader(header: string): string {
  return header.trim().toLowerCase().replaceAll('-', '_').replaceAll('_', ' ')
}

export function findImportColumn(headers: string[], field: ImportField): number {
  const normalized = headers.map(normalizedHeader)
  const aliases = importAliases[field].map(normalizedHeader)
  return normalized.findIndex((header) => aliases.includes(header))
}

export function mapCsvRows(rows: string[][], mapping: Partial<Record<ImportField, number>> = {}): ParsedImportFile {
  if (rows.length < 1) throw new Error('csv_empty')
  const headers = rows[0].map((header, index) => (index === 0 ? header.replace(/^\uFEFF/, '') : header).trim())
  if (!headers.length || headers.every((header) => !header)) throw new Error('csv_missing_header')
  const columnMap: Partial<Record<ImportField, number>> = { ...mapping }
  for (const column of Object.values(columnMap)) {
    if (!Number.isInteger(column) || column! < 0 || column! >= headers.length) throw new Error('csv_invalid_mapping')
  }
  for (const field of Object.keys(importAliases) as ImportField[]) {
    if (columnMap[field] === undefined) {
      const detected = findImportColumn(headers, field)
      if (detected >= 0) columnMap[field] = detected
    }
  }
  const requiredFields: ImportField[] = ['name', 'url', 'username', 'password']
  if (requiredFields.some((field) => columnMap[field] === undefined)) throw new Error('csv_mapping_required')
  const entries = rows.slice(1).map((cells, rowIndex) => {
    const get = (field: ImportField) => {
      const column = columnMap[field]
      if (column === undefined) return ''
      const value = cells[column] ?? ''
      // Passwords are opaque user data; unlike labels and metadata, whitespace is significant.
      return field === 'password' ? value : value.trim()
    }
    return {
      ...emptyEntry(rowIndex + 2),
      name: get('name'),
      url: get('url'),
      username: get('username'),
      password: get('password'),
      note: get('note'),
      category: get('category'),
      tags: get('tags').split(/[;,]/).map((tag) => tag.trim()).filter(Boolean),
      favorite: ['true', 'yes', '1', 'favorite', 'favourite'].includes(get('favorite').toLowerCase()),
    }
  }).filter((entry) => entry.name || entry.url || entry.username || entry.password || entry.note)
  return { format: 'csv', headers, rows: entries }
}

export function getCsvHeaders(source: string): string[] {
  const rows = csvRows(source)
  return rows[0].map((header) => header.trim())
}

export function parseCsvWithMapping(source: string, mapping: Partial<Record<ImportField, number>>): ParsedImportFile {
  return mapCsvRows(csvRows(source), mapping)
}

function bitwardenRows(source: string): ParsedImportFile {
  let document: unknown
  try {
    document = JSON.parse(source) as unknown
  } catch {
    throw new Error('bitwarden_json_invalid')
  }
  if (!document || typeof document !== 'object' || Array.isArray(document)) throw new Error('bitwarden_json_invalid')
  const root = document as Record<string, unknown>
  if (root.encrypted === true || root.encrypted === 'true') throw new Error('bitwarden_encrypted_export')
  if (!Array.isArray(root.items)) throw new Error('bitwarden_json_invalid')
  const folders = new Map<string, string>()
  if (Array.isArray(root.folders)) {
    for (const folder of root.folders) {
      if (!isRecord(folder) || typeof folder.id !== 'string' || typeof folder.name !== 'string') continue
      folders.set(folder.id, folder.name)
    }
  }
  const rows: ImportedVaultEntry[] = []
  root.items.forEach((rawItem, index) => {
    if (!rawItem || typeof rawItem !== 'object' || Array.isArray(rawItem)) return
    const item = rawItem as Record<string, unknown>
    const login = item.login && typeof item.login === 'object' && !Array.isArray(item.login)
      ? item.login as Record<string, unknown>
      : null
    if (item.type !== 1 || !login) return
    const uris = Array.isArray(login.uris) ? login.uris : []
    const uri = uris.find((value) => value && typeof value === 'object' && typeof (value as Record<string, unknown>).uri === 'string') as Record<string, unknown> | undefined
    const tags = Array.isArray(item.tags) ? item.tags.filter((tag): tag is string => typeof tag === 'string') : []
    rows.push({
      ...emptyEntry(index + 1),
      name: typeof item.name === 'string' ? item.name : '',
      url: typeof uri?.uri === 'string' ? uri.uri : '',
      username: typeof login.username === 'string' ? login.username : '',
      password: typeof login.password === 'string' ? login.password : '',
      note: typeof item.notes === 'string' ? item.notes : '',
      category: typeof item.folderName === 'string' ? item.folderName : typeof item.folderId === 'string' ? folders.get(item.folderId) ?? '' : '',
      tags,
      favorite: item.favorite === true,
    })
  })
  return { format: 'bitwarden-json', headers: [], rows }
}

export function parseImportText(filename: string, source: string): ParsedImportFile {
  const lowerName = filename.toLowerCase()
  if (lowerName.endsWith('.json')) return bitwardenRows(source)
  if (!lowerName.endsWith('.csv')) throw new Error('import_unsupported_file')
  return mapCsvRows(csvRows(source))
}

export interface BackupContainerSummary {
  version: 1 | 2 | 3
  sourceUserId: string
  createdAt: string | null
  itemCountInContainer: number | null
  integrityCheck: 'not-run'
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function parseJsonWithoutDuplicateKeys(source: string): unknown {
  let cursor = 0
  const whitespace = () => { while (/\s/.test(source[cursor] ?? '') && cursor < source.length) cursor += 1 }
  const parseString = (): string => {
    const start = cursor
    if (source[cursor] !== '"') throw new Error('backup_invalid_json')
    cursor += 1
    while (cursor < source.length) {
      const character = source[cursor]
      if (character === '\\') {
        cursor += 2
        continue
      }
      if (character === '"') {
        cursor += 1
        return JSON.parse(source.slice(start, cursor)) as string
      }
      if (character.charCodeAt(0) < 0x20) throw new Error('backup_invalid_json')
      cursor += 1
    }
    throw new Error('backup_invalid_json')
  }
  const parseValue = (): unknown => {
    whitespace()
    const character = source[cursor]
    if (character === '"') return parseString()
    if (character === '{') {
      cursor += 1
      whitespace()
      const result = Object.create(null) as Record<string, unknown>
      const keys = new Set<string>()
      if (source[cursor] === '}') { cursor += 1; return result }
      while (cursor < source.length) {
        whitespace()
        const key = parseString()
        if (keys.has(key)) throw new Error('backup_duplicate_key')
        keys.add(key)
        whitespace()
        if (source[cursor] !== ':') throw new Error('backup_invalid_json')
        cursor += 1
        result[key] = parseValue()
        whitespace()
        if (source[cursor] === '}') { cursor += 1; return result }
        if (source[cursor] !== ',') throw new Error('backup_invalid_json')
        cursor += 1
      }
      throw new Error('backup_invalid_json')
    }
    if (character === '[') {
      cursor += 1
      whitespace()
      const result: unknown[] = []
      if (source[cursor] === ']') { cursor += 1; return result }
      while (cursor < source.length) {
        result.push(parseValue())
        whitespace()
        if (source[cursor] === ']') { cursor += 1; return result }
        if (source[cursor] !== ',') throw new Error('backup_invalid_json')
        cursor += 1
      }
      throw new Error('backup_invalid_json')
    }
    const literal = source.slice(cursor).match(/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/)?.[0]
    if (!literal) throw new Error('backup_invalid_json')
    cursor += literal.length
    return JSON.parse(literal) as unknown
  }
  const value = parseValue()
  whitespace()
  if (cursor !== source.length) throw new Error('backup_trailing_bytes')
  return value
}

function assertExactKeys(value: Record<string, unknown>, keys: string[], code = 'backup_invalid_container'): void {
  const actual = Object.keys(value).sort()
  const expected = [...keys].sort()
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error(code)
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)
}

function isUtcSecondTimestamp(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) return false
  try {
    return new Date(value).toISOString().replace('.000Z', 'Z') === value
  } catch {
    return false
  }
}

function validBlock(value: unknown): boolean {
  if (!isRecord(value)) return false
  assertExactKeys(value, ['ciphertext', 'nonce'])
  if (typeof value.ciphertext !== 'string' || typeof value.nonce !== 'string') return false
  try {
    const ciphertext = atob(value.ciphertext)
    const nonce = atob(value.nonce)
    return nonce.length === 12 && ciphertext.length >= 16 && btoa(ciphertext) === value.ciphertext && btoa(nonce) === value.nonce
  } catch {
    return false
  }
}

function parseKdfParams(value: unknown): boolean {
  if (typeof value !== 'string') return false
  try {
    const params = parseJsonWithoutDuplicateKeys(value)
    if (!isRecord(params)) return false
    assertExactKeys(params, ['algorithm', 'm', 'output_len', 'p', 't'])
    if (params.algorithm !== 'argon2id' || params.output_len !== 32) return false
    if (!Number.isSafeInteger(params.m) || !Number.isSafeInteger(params.p) || !Number.isSafeInteger(params.t)) return false
    const allowedProfiles = [[65_536, 3, 4], [131_072, 3, 4], [131_072, 4, 4], [262_144, 4, 4]]
    return allowedProfiles.some(([memory, iterations, parallelism]) => params.m === memory && params.t === iterations && params.p === parallelism) && canonicalJson(params) === value
  } catch {
    return false
  }
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  const object = value as Record<string, unknown>
  return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`).join(',')}}`
}

export function inspectBackupContainer(source: string): BackupContainerSummary {
  const container = parseJsonWithoutDuplicateKeys(source)
  if (!isRecord(container)) throw new Error('backup_invalid_container')
  const version = container.backup_format_version
  if (version !== 1 && version !== 2 && version !== 3) {
    if (typeof version === 'number' && version > 3) throw new Error('backup_future_version')
    throw new Error('backup_invalid_version')
  }
  if (version !== 3) {
    if (!isUuid(container.source_user_id) || !Array.isArray(container.dek_wrappings) || !Array.isArray(container.items)) throw new Error('backup_invalid_container')
    if (version === 1 && 'manifest' in container) throw new Error('backup_invalid_container')
    if (version === 2 && !isRecord(container.manifest)) throw new Error('backup_invalid_container')
    return { version, sourceUserId: container.source_user_id, createdAt: typeof container.created_at === 'string' ? container.created_at : null, itemCountInContainer: container.items.length, integrityCheck: 'not-run' }
  }
  if (!source.endsWith('}')) throw new Error('backup_trailing_bytes')
  assertExactKeys(container, ['backup_format_version', 'created_at', 'dek_wrappings', 'items', 'manifest', 'source_user_id'])
  if (!isUuid(container.source_user_id) || !isUtcSecondTimestamp(container.created_at)) throw new Error('backup_invalid_container')
  if (!Array.isArray(container.items) || !Array.isArray(container.dek_wrappings) || container.dek_wrappings.length < 1 || container.dek_wrappings.length > 3 || !validBlock(container.manifest)) throw new Error('backup_invalid_container')
  let currentDekVersion: number | null = null
  for (const [index, raw] of container.dek_wrappings.entries()) {
    if (!isRecord(raw)) throw new Error('backup_invalid_container')
    const kind = raw.kind
    assertExactKeys(raw, kind === 'kek'
      ? ['ciphertext', 'dek_version', 'kdf_params', 'kdf_salt', 'kind', 'master_password_version', 'nonce']
      : ['ciphertext', 'dek_version', 'kdf_params', 'kdf_salt', 'kind', 'nonce'])
    if (kind !== (index === 0 ? 'kek' : 'recovery_key') || !Number.isSafeInteger(raw.dek_version) || (raw.dek_version as number) < 1 || !parseKdfParams(raw.kdf_params)) throw new Error('backup_invalid_container')
    if (index === 0) currentDekVersion = raw.dek_version as number
    else if (index === 1 && raw.dek_version !== currentDekVersion) throw new Error('backup_invalid_container')
    else if (index === 2 && (currentDekVersion === null || raw.dek_version !== currentDekVersion - 1)) throw new Error('backup_invalid_container')
    if (typeof raw.kdf_salt !== 'string' || typeof raw.ciphertext !== 'string' || typeof raw.nonce !== 'string') throw new Error('backup_invalid_container')
    try {
      const salt = atob(raw.kdf_salt)
      const ciphertext = atob(raw.ciphertext)
      const nonce = atob(raw.nonce)
      if (salt.length !== 16 || ciphertext.length < 16 || nonce.length !== 12 || btoa(salt) !== raw.kdf_salt || btoa(ciphertext) !== raw.ciphertext || btoa(nonce) !== raw.nonce) throw new Error('backup_invalid_container')
    } catch {
      throw new Error('backup_invalid_container')
    }
    if (kind === 'kek' && (!Number.isSafeInteger(raw.master_password_version) || (raw.master_password_version as number) < 1)) throw new Error('backup_invalid_container')
  }
  let previousId = ''
  const ids = new Set<string>()
  for (const raw of container.items) {
    if (!isRecord(raw)) throw new Error('backup_invalid_container')
    assertExactKeys(raw, ['detail', 'domain_hmac', 'item_id', 'overview', 'version'])
    if (!isUuid(raw.item_id) || !Number.isSafeInteger(raw.version) || (raw.version as number) < 1 || !validBlock(raw.overview) || !validBlock(raw.detail)) throw new Error('backup_invalid_container')
    if (raw.domain_hmac !== null && (typeof raw.domain_hmac !== 'string' || !/^[0-9a-f]{64}$/.test(raw.domain_hmac))) throw new Error('backup_invalid_container')
    if (ids.has(raw.item_id) || raw.item_id <= previousId) throw new Error('backup_invalid_container')
    ids.add(raw.item_id)
    previousId = raw.item_id
  }
  return { version: 3, sourceUserId: container.source_user_id, createdAt: container.created_at, itemCountInContainer: container.items.length, integrityCheck: 'not-run' }
}
