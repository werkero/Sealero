import { describe, expect, it } from 'vitest';
import { isValidPolicyVersion, parseReleaseManifest } from '../release-manifest.js';

describe('release manifest policy version', () => {
  it('reads the immutable policy version while allowing other release metadata', () => {
    expect(parseReleaseManifest(JSON.stringify({ version: 'v1.0.0', policy_version: 'privacy-1.0' })))
      .toEqual({ policy_version: 'privacy-1.0' });
  });

  it('fails closed for malformed JSON, absent policy version, or invalid version tokens', () => {
    expect(() => parseReleaseManifest('{')).toThrow('valid JSON');
    expect(() => parseReleaseManifest(JSON.stringify({ version: 'v1.0.0' }))).toThrow('policy_version');
    expect(() => parseReleaseManifest(JSON.stringify({ policy_version: '  ' }))).toThrow('policy_version');
    expect(isValidPolicyVersion('privacy-2026.11')).toBe(true);
    expect(isValidPolicyVersion('privacy version')).toBe(false);
    expect(isValidPolicyVersion('x'.repeat(65))).toBe(false);
  });
});
