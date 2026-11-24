import { Hono } from 'hono';
import { ApiError } from '../app.js';
import type { PrivacyConsentStore } from '../auth/consent-types.js';
import type { AuthenticatedEnvironment } from '../middleware/authentication.js';
import { isValidPolicyVersion } from '../release-manifest.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requestIp(headers: Headers): string | null {
  const forwarded = headers.get('x-forwarded-for');
  if (forwarded !== null) {
    const first = forwarded.split(',', 1)[0]?.trim();
    if (first) return first.slice(0, 128);
  }
  const connecting = headers.get('cf-connecting-ip');
  return connecting === null ? null : connecting.slice(0, 128);
}

export function createConsentRoutes(
  store: PrivacyConsentStore,
  policyVersion: string,
  now: () => Date = () => new Date(),
): Hono<AuthenticatedEnvironment> {
  if (!isValidPolicyVersion(policyVersion)) {
    throw new Error('The configured privacy policy version is invalid.');
  }

  const routes = new Hono<AuthenticatedEnvironment>();

  routes.post('/consent', async (context) => {
    let body: unknown;
    try {
      body = await context.req.json();
    } catch {
      throw new ApiError(400, 'invalid_request', 'The consent request must be valid JSON.');
    }
    if (
      !isRecord(body) || Object.keys(body).length !== 1 ||
      !isValidPolicyVersion(body['policy_version'])
    ) {
      throw new ApiError(400, 'invalid_request', 'The consent request must include only a valid policy_version.');
    }
    if (body['policy_version'] !== policyVersion) {
      throw new ApiError(400, 'policy_version_mismatch', 'The submitted privacy policy version is not current.');
    }

    const consentedAt = await store.recordPrivacyConsent(
      context.get('auth').sub,
      policyVersion,
      requestIp(context.req.raw.headers),
      now(),
    );
    return context.json({
      policy_type: 'privacy',
      policy_version: policyVersion,
      consented_at: consentedAt,
    }, 200);
  });

  return routes;
}
