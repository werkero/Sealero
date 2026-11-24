import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface ReleaseManifest {
  readonly policy_version: string;
}

const POLICY_VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export function isValidPolicyVersion(value: unknown): value is string {
  return typeof value === 'string' && POLICY_VERSION_PATTERN.test(value);
}

export function parseReleaseManifest(contents: string): ReleaseManifest {
  let parsed: unknown;
  try {
    parsed = JSON.parse(contents) as unknown;
  } catch {
    throw new Error('The release manifest must contain valid JSON.');
  }
  if (
    typeof parsed !== 'object' || parsed === null || Array.isArray(parsed) ||
    !isValidPolicyVersion((parsed as Record<string, unknown>)['policy_version'])
  ) {
    throw new Error('The release manifest must include a valid policy_version.');
  }
  return { policy_version: (parsed as { policy_version: string }).policy_version };
}

/** Loads the immutable release manifest from the deployment artifact, never from runtime settings. */
export function loadReleaseManifest(): ReleaseManifest {
  const moduleDirectory = resolve(fileURLToPath(new URL('.', import.meta.url)));
  const candidates = [...new Set([
    resolve(process.cwd(), 'release.json'),
    resolve(process.cwd(), 'api', 'release.json'),
    resolve(moduleDirectory, 'release.json'),
    resolve(moduleDirectory, '..', 'release.json'),
    resolve(moduleDirectory, '..', '..', 'release.json'),
  ])];

  for (const path of candidates) {
    try {
      return parseReleaseManifest(readFileSync(path, 'utf8'));
    } catch (error) {
      if (error instanceof Error && !('code' in error && error.code === 'ENOENT')) throw error;
    }
  }
  throw new Error('A release.json containing policy_version is required before authenticated routes can start.');
}
