import { createCipheriv, randomBytes } from 'node:crypto';
import type { DbDumpTables } from './types.js';

/**
 * Encrypted database dump file format (System Design §5.2).
 *
 * The doc fixes the pieces but not their exact assembly, so the assembly
 * below is this implementation's reading of §5.2 — confirm it with Tai
 * before treating a dump file as a cross-version artifact:
 *
 * - Plaintext: one canonical JSON document, `{header, tables}`. `header`
 *   holds `format_version`, `exported_at` and per-table `row_counts`;
 *   `tables` maps each of the 15 table names to its rows.
 * - File: a UTF-8 JSON header line `{"format_version":<n>,"nonce":"<base64url>"}`
 *   followed by `\n`, then the raw AES-256-GCM ciphertext with the 16-byte
 *   auth tag appended. The nonce lives in the file header (§5.2) so a
 *   decryptor can read it before decrypting.
 * - AAD is `String(format_version)` as UTF-8 (§5.2 says the AAD is
 *   format_version; its encoding is not specified, so the decimal string
 *   is used).
 * - The header line is canonical JSON (keys sorted); the plaintext document
 *   is canonical JSON (keys sorted recursively, no extra whitespace).
 */

// TODO (System Design §5.2): the doc requires a `format_version` in the dump
// header but never gives its value. 1 is used as the first version of this
// dump format; confirm the value with Tai before shipping dumps that must
// be readable by a future restore implementation.
export const DB_DUMP_FORMAT_VERSION = 1;

const DB_DUMP_NONCE_BYTES = 12;
const DB_DUMP_KEY_BYTES = 32;

export function parseDbDumpKey(value: string | undefined): Buffer {
  if (value === undefined || value.trim() === '') {
    throw new Error('DB_DUMP_KEY must be set to a Base64-encoded 32-byte key.');
  }
  let key: Buffer;
  try {
    key = Buffer.from(value, 'base64');
  } catch {
    throw new Error('DB_DUMP_KEY must be a Base64-encoded 32-byte key.');
  }
  if (key.length !== DB_DUMP_KEY_BYTES) {
    throw new Error('DB_DUMP_KEY must be a Base64-encoded 32-byte key.');
  }
  return key;
}

/** Canonical JSON: object keys sorted recursively, arrays in order, no whitespace. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
  return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`).join(',')}}`;
}

export interface DbDumpDocument {
  readonly header: {
    readonly format_version: number;
    readonly exported_at: string;
    readonly row_counts: Readonly<Record<string, number>>;
  };
  readonly tables: DbDumpTables;
}

/**
 * Builds the dump document. The only transformation applied to the stored
 * rows is the §5.2 exception: server_settings `smtp_pass` is nulled in the
 * dump (the administrator re-enters it after a restore).
 */
export function buildDbDumpDocument(tables: DbDumpTables, exportedAt: Date): DbDumpDocument {
  const rowCounts: Record<string, number> = {};
  const dumpTables: Record<string, readonly (Readonly<Record<string, string | number | boolean | null>>)[]> = {};
  for (const [table, rows] of Object.entries(tables)) {
    rowCounts[table] = rows.length;
    if (table === 'server_settings') {
      dumpTables[table] = rows.map((row) =>
        row['key'] === 'smtp_pass' ? { ...row, value: null } : row,
      );
    } else {
      dumpTables[table] = rows;
    }
  }
  return {
    header: {
      format_version: DB_DUMP_FORMAT_VERSION,
      exported_at: exportedAt.toISOString(),
      row_counts: rowCounts,
    },
    tables: dumpTables,
  };
}

export interface EncryptedDbDump {
  /** The UTF-8 JSON header line, without its trailing newline. */
  readonly headerLine: string;
  /** AES-256-GCM ciphertext with the 16-byte auth tag appended. */
  readonly ciphertext: Buffer;
}

/** Encrypts the canonical dump document. A fresh random nonce is used per dump. */
export function encryptDbDump(documentJson: string, key: Buffer): EncryptedDbDump {
  const nonce = randomBytes(DB_DUMP_NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.from(String(DB_DUMP_FORMAT_VERSION), 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(documentJson, 'utf8'), cipher.final(), cipher.getAuthTag()]);
  const headerLine = canonicalJson({
    format_version: DB_DUMP_FORMAT_VERSION,
    nonce: nonce.toString('base64url'),
  });
  return { headerLine, ciphertext };
}

/** `sealero-db-dump-YYYYMMDD-HHmmss.enc.json`, in UTC (System Design §5.2). */
export function dbDumpFilename(now: Date): string {
  const pad = (value: number): string => String(value).padStart(2, '0');
  const date = `${now.getUTCFullYear()}${pad(now.getUTCMonth() + 1)}${pad(now.getUTCDate())}`;
  const time = `${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}${pad(now.getUTCSeconds())}`;
  return `sealero-db-dump-${date}-${time}.enc.json`;
}
