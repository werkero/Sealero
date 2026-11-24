export interface DeviceListCursor {
  readonly createdAt: string;
  readonly id: string;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ISO_TIMESTAMP_PATTERN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{6})Z$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

function isTimestamp(value: string): boolean {
  const match = ISO_TIMESTAMP_PATTERN.exec(value);
  if (match === null) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  if (
    year < 1 || month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59
  ) return false;
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day >= 1 && day <= (daysInMonth[month - 1] ?? 0);
}

export function encodeDeviceListCursor(cursor: DeviceListCursor): string {
  return Buffer.from(`${cursor.createdAt}|${cursor.id}`, 'utf8').toString('base64url');
}

export function decodeDeviceListCursor(value: string): DeviceListCursor | null {
  if (!BASE64URL_PATTERN.test(value)) return null;

  let decoded: Buffer;
  try {
    decoded = Buffer.from(value, 'base64url');
  } catch {
    return null;
  }
  if (decoded.toString('base64url') !== value) return null;

  const text = decoded.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(decoded)) return null;
  const separator = text.indexOf('|');
  if (separator < 0 || separator !== text.lastIndexOf('|')) return null;

  const timestamp = text.slice(0, separator);
  const id = text.slice(separator + 1);
  if (!isTimestamp(timestamp) || !UUID_PATTERN.test(id)) return null;

  return { createdAt: timestamp, id };
}
