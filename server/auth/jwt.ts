import { sign as signBytes, verify as verifyBytes } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import type { AccessClaims } from './types.js';

export const ACCESS_TOKEN_TTL_SECONDS = 15 * 60;
export const JWT_AUDIENCE = 'sealero-api' as const;

export interface PublicJwk {
  readonly kty: 'RSA';
  readonly use: 'sig';
  readonly alg: 'RS256';
  readonly kid: string;
  readonly n: string;
  readonly e: string;
}

export interface JsonWebKeySet {
  readonly keys: readonly PublicJwk[];
}

export interface JwtKeySet {
  readonly activeKid: string;
  readonly issuer: string;
  readonly privateKey: KeyObject;
  readonly publicKeys: ReadonlyMap<string, KeyObject>;
  readonly jwks: JsonWebKeySet;
}

export class InvalidAccessTokenError extends Error {
  constructor() {
    super('Invalid access token.');
    this.name = 'InvalidAccessTokenError';
  }
}

function encodeJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function decodeBase64Url(segment: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) throw new InvalidAccessTokenError();
  const decoded = Buffer.from(segment, 'base64url');
  if (decoded.toString('base64url') !== segment) throw new InvalidAccessTokenError();
  return decoded;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

export function issueAccessToken(
  keys: JwtKeySet,
  userId: string,
  deviceId: string,
  now: Date,
): string {
  if (!isUuid(userId) || !isUuid(deviceId) || !Number.isFinite(now.getTime())) {
    throw new Error('Cannot issue access token with invalid identity or time.');
  }
  const issuedAt = Math.floor(now.getTime() / 1000);
  const claims: AccessClaims = {
    sub: userId,
    device_id: deviceId,
    exp: issuedAt + ACCESS_TOKEN_TTL_SECONDS,
    iat: issuedAt,
    iss: keys.issuer,
    aud: JWT_AUDIENCE,
  };
  const header = { alg: 'RS256', kid: keys.activeKid, typ: 'JWT' } as const;
  const signingInput = `${encodeJson(header)}.${encodeJson(claims)}`;
  const signature = signBytes('RSA-SHA256', Buffer.from(signingInput, 'ascii'), keys.privateKey);
  return `${signingInput}.${signature.toString('base64url')}`;
}

export function verifyAccessToken(
  keys: JwtKeySet,
  token: string,
  now: Date = new Date(),
): AccessClaims {
  try {
    if (!Number.isFinite(now.getTime())) throw new InvalidAccessTokenError();
    const segments = token.split('.');
    if (segments.length !== 3) throw new InvalidAccessTokenError();
    const [encodedHeader, encodedPayload, encodedSignature] = segments;
    if (!encodedHeader || !encodedPayload || !encodedSignature) throw new InvalidAccessTokenError();

    const headerValue: unknown = JSON.parse(decodeBase64Url(encodedHeader).toString('utf8'));
    const payloadValue: unknown = JSON.parse(decodeBase64Url(encodedPayload).toString('utf8'));
    if (!isRecord(headerValue) || !hasExactKeys(headerValue, ['alg', 'kid', 'typ'])) {
      throw new InvalidAccessTokenError();
    }
    if (headerValue['alg'] !== 'RS256' || headerValue['typ'] !== 'JWT' || typeof headerValue['kid'] !== 'string') {
      throw new InvalidAccessTokenError();
    }
    if (!isRecord(payloadValue) || !hasExactKeys(payloadValue, ['sub', 'device_id', 'exp', 'iat', 'iss', 'aud'])) {
      throw new InvalidAccessTokenError();
    }

    const publicKey = keys.publicKeys.get(headerValue['kid']);
    if (!publicKey) throw new InvalidAccessTokenError();
    const signature = decodeBase64Url(encodedSignature);
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const verified = verifyBytes(
      'RSA-SHA256',
      Buffer.from(signingInput, 'ascii'),
      publicKey,
      signature,
    );
    if (!verified) throw new InvalidAccessTokenError();

    const { sub, device_id: deviceId, exp, iat, iss, aud } = payloadValue;
    if (
      !isUuid(sub) ||
      !isUuid(deviceId) ||
      !Number.isSafeInteger(exp) ||
      !Number.isSafeInteger(iat) ||
      typeof iss !== 'string' ||
      iss !== keys.issuer ||
      aud !== JWT_AUDIENCE ||
      (exp as number) <= Math.floor(now.getTime() / 1000) ||
      (exp as number) <= (iat as number)
    ) {
      throw new InvalidAccessTokenError();
    }

    return payloadValue as unknown as AccessClaims;
  } catch {
    throw new InvalidAccessTokenError();
  }
}
