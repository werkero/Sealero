import argon2 from 'argon2';

export const LOGIN_PASSWORD_ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 32 * 1024,
  timeCost: 2,
  parallelism: 1,
  hashLength: 32,
} as const;

/** Hashes a login password using the server's current Argon2id profile. */
export async function hashLoginPassword(password: string): Promise<string> {
  return argon2.hash(password, LOGIN_PASSWORD_ARGON2_OPTIONS);
}

/** Verifies a stored PHC Argon2 hash without exposing its parameters to callers. */
export async function verifyLoginPassword(hash: string, password: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch {
    // Malformed or unsupported stored hashes fail closed like an incorrect password.
    return false;
  }
}

/** Returns true when a valid PHC hash no longer matches the current server profile. */
export function loginPasswordNeedsRehash(hash: string): boolean {
  try {
    return argon2.needsRehash(hash, LOGIN_PASSWORD_ARGON2_OPTIONS);
  } catch {
    return true;
  }
}
