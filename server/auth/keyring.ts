import { readFileSync } from 'node:fs';
import {
  createPrivateKey,
  createPublicKey,
  timingSafeEqual,
} from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import type { JwtKeySet, JsonWebKeySet, PublicJwk } from './jwt.js';

export interface JwtKeyEnvironment {
  readonly JWT_PRIVATE_KEY_PATH?: string;
  readonly JWT_PUBLIC_KEY_PATH?: string;
  readonly JWT_ACTIVE_KID?: string;
  readonly JWT_ISSUER?: string;
  readonly AUTH_CODE_HMAC_SECRET?: string;
  readonly DB_DUMP_KEY?: string;
}

function requiredEnvironmentValue(env: JwtKeyEnvironment, name: keyof JwtKeyEnvironment): string {
  const value = env[name];
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`${name} is required for authentication startup.`);
  }
  return value.trim();
}

function normalizedIssuer(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error('JWT_ISSUER must be a normalized HTTPS API origin.');
  }
  if (
    parsed.protocol !== 'https:' ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.pathname !== '/' ||
    parsed.search !== '' ||
    parsed.hash !== '' ||
    parsed.origin !== value
  ) {
    throw new Error('JWT_ISSUER must be a normalized HTTPS API origin.');
  }
  return parsed.origin;
}

function requireRsaKey(key: KeyObject, label: string): void {
  const modulusLength = key.asymmetricKeyDetails?.modulusLength;
  if (key.asymmetricKeyType !== 'rsa' || modulusLength === undefined || modulusLength < 2048) {
    throw new Error(`${label} must be an RSA key with at least 2048 bits.`);
  }
}

function publicJwkFromKey(kid: string, key: KeyObject): PublicJwk {
  const jwk = key.export({ format: 'jwk' });
  if (typeof jwk.n !== 'string' || typeof jwk.e !== 'string') {
    throw new Error('JWT public key is not a valid RSA JWK.');
  }
  return { kty: 'RSA', use: 'sig', alg: 'RS256', kid, n: jwk.n, e: jwk.e };
}

function readPublicKeys(path: string, activeKid: string): { keys: Map<string, KeyObject>; jwks: JsonWebKeySet } {
  let source: string;
  try {
    source = readFileSync(path, 'utf8');
  } catch {
    throw new Error('JWT_PUBLIC_KEY_PATH could not be read.');
  }

  const publicKeys = new Map<string, KeyObject>();
  let jwks: JsonWebKeySet;
  if (source.trimStart().startsWith('{')) {
    let value: unknown;
    try {
      value = JSON.parse(source);
    } catch {
      throw new Error('JWT_PUBLIC_KEY_PATH is not valid JWKS JSON.');
    }
    if (typeof value !== 'object' || value === null || !('keys' in value) || !Array.isArray(value.keys)) {
      throw new Error('JWT_PUBLIC_KEY_PATH must contain a JWKS keys array.');
    }
    const parsedJwks: PublicJwk[] = [];
    for (const entry of value.keys) {
      if (
        typeof entry !== 'object' || entry === null ||
        !('kid' in entry) || typeof entry.kid !== 'string' || entry.kid.trim() === '' ||
        !('kty' in entry) || entry.kty !== 'RSA' ||
        !('n' in entry) || typeof entry.n !== 'string' ||
        !('e' in entry) || typeof entry.e !== 'string' ||
        ('alg' in entry && entry.alg !== 'RS256') ||
        ('use' in entry && entry.use !== 'sig')
      ) {
        throw new Error('JWT_PUBLIC_KEY_PATH contains an unsupported JWKS key.');
      }
      const item = entry as PublicJwk;
      if (publicKeys.has(item.kid)) throw new Error('JWT_PUBLIC_KEY_PATH contains duplicate kid values.');
      let key: KeyObject;
      try {
        const nodeJwk = { kty: 'RSA', n: item.n, e: item.e } satisfies Record<string, string>;
        key = createPublicKey({ key: nodeJwk, format: 'jwk' });
      } catch {
        throw new Error('JWT_PUBLIC_KEY_PATH contains an invalid public key.');
      }
      requireRsaKey(key, 'JWT JWKS public key');
      publicKeys.set(item.kid, key);
      parsedJwks.push(publicJwkFromKey(item.kid, key));
    }
    jwks = { keys: parsedJwks };
  } else {
    let key: KeyObject;
    try {
      key = createPublicKey(source);
    } catch {
      throw new Error('JWT_PUBLIC_KEY_PATH is not a valid public key.');
    }
    requireRsaKey(key, 'JWT public key');
    publicKeys.set(activeKid, key);
    jwks = { keys: [publicJwkFromKey(activeKid, key)] };
  }
  return { keys: publicKeys, jwks };
}

export function loadJwtKeySet(env: JwtKeyEnvironment = process.env): JwtKeySet {
  const privatePath = requiredEnvironmentValue(env, 'JWT_PRIVATE_KEY_PATH');
  const publicPath = requiredEnvironmentValue(env, 'JWT_PUBLIC_KEY_PATH');
  const activeKid = requiredEnvironmentValue(env, 'JWT_ACTIVE_KID');
  const issuer = normalizedIssuer(requiredEnvironmentValue(env, 'JWT_ISSUER'));
  if (activeKid.length > 128 || /\s/.test(activeKid)) {
    throw new Error('JWT_ACTIVE_KID must be a non-empty kid without whitespace.');
  }

  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey(readFileSync(privatePath));
  } catch {
    throw new Error('JWT_PRIVATE_KEY_PATH could not be read as a private key.');
  }
  requireRsaKey(privateKey, 'JWT private key');

  const { keys: publicKeys, jwks } = readPublicKeys(publicPath, activeKid);
  const activePublicKey = publicKeys.get(activeKid);
  if (!activePublicKey) {
    throw new Error('JWT_ACTIVE_KID is not present in the configured JWKS.');
  }
  const derivedPublicKey = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  const configuredPublicKey = activePublicKey.export({ type: 'spki', format: 'der' });
  if (
    derivedPublicKey.length !== configuredPublicKey.length ||
    !timingSafeEqual(derivedPublicKey, configuredPublicKey)
  ) {
    throw new Error('JWT active private key does not match its JWKS public key.');
  }

  return { activeKid, issuer, privateKey, publicKeys, jwks };
}
