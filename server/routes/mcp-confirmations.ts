import type { MiddlewareHandler } from 'hono';
import { Hono } from 'hono';
import { ApiError } from '../app.js';
import type { AuthenticatedEnvironment } from '../middleware/authentication.js';
import {
  decideMcpConfirmation,
  listMcpConfirmations,
} from '../services/mcp-confirmations.js';
import type { McpConfirmationServiceStore } from '../services/mcp-confirmations.js';
import type { VaultStore } from '../vault/types.js';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Trusted-confirmation UI endpoints (SD §5.3), mounted under /v1 in the
 * secured routes: `GET /v1/mcp/confirmations`,
 * `POST /v1/mcp/confirmations/{id}/approve`,
 * `POST /v1/mcp/confirmations/{id}/deny`. Login JWT plus the same email
 * and privacy-consent gates as the vault routes; the page itself also
 * requires the vault to be unlocked, enforced by the web route.
 */
export function createMcpConfirmationRoutes(
  store: McpConfirmationServiceStore & VaultStore,
  policyVersion: string,
  now: () => Date = () => new Date(),
): Hono<AuthenticatedEnvironment> {
  const routes = new Hono<AuthenticatedEnvironment>();

  const requireVaultGates: MiddlewareHandler<AuthenticatedEnvironment> = async (context, next) => {
    const access = await store.getVaultAccessStatus(context.get('auth').sub, policyVersion);
    if (access === null) {
      throw new ApiError(401, 'unauthorized', 'A valid access token is required.');
    }
    if (access.requireEmailVerification && access.emailVerifiedAt === null) {
      throw new ApiError(403, 'email_verification_required', 'Verify your email before using the vault.');
    }
    if (!access.hasCurrentPrivacyConsent) {
      throw new ApiError(403, 'consent_required', 'Accept the current privacy policy before using the vault.');
    }
    await next();
  };
  routes.use('/mcp/confirmations', requireVaultGates);
  routes.use('/mcp/confirmations/*', requireVaultGates);

  routes.get('/mcp/confirmations', async (context) => {
    const response = await listMcpConfirmations(store, context.get('auth').sub, now());
    return context.json(response);
  });

  routes.post('/mcp/confirmations/:id/approve', async (context) => {
    const id = context.req.param('id');
    if (!UUID_PATTERN.test(id)) {
      throw new ApiError(400, 'invalid_request', 'The confirmation ID must be a UUID.');
    }
    const response = await decideMcpConfirmation(store, context.get('auth').sub, id, 'approve', now());
    return context.json(response);
  });

  routes.post('/mcp/confirmations/:id/deny', async (context) => {
    const id = context.req.param('id');
    if (!UUID_PATTERN.test(id)) {
      throw new ApiError(400, 'invalid_request', 'The confirmation ID must be a UUID.');
    }
    const response = await decideMcpConfirmation(store, context.get('auth').sub, id, 'deny', now());
    return context.json(response);
  });

  return routes;
}
