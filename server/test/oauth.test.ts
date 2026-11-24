import { createHash, randomBytes } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';

// PGlite harness creation takes 3-9s on the 1.5-CPU sandbox; the 5s default flakes.
vi.setConfig({ testTimeout: 30_000 });
import { verifyOAuthAccessToken } from '../oauth/oauth-service.js';
import {
  OAUTH_TEST_INITIAL_TIME,
  closeOAuthHarnesses,
  createOAuthHarness,
  fetchApp,
  oauthTestJwtKeys,
} from './support/oauth-harness.js';
import type { OAuthHarness } from './support/oauth-harness.js';

const REDIRECT_URI = 'https://client.example/callback';

afterEach(async () => {
  await closeOAuthHarnesses();
});

function pkcePair(): { verifier: string; challenge: string } {
  // RFC 7636: verifier must be 43-128 characters.
  const verifier = `oauth-test-verifier-${randomBytes(24).toString('base64url')}`;
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

async function registerClient(harness: OAuthHarness, redirectUri = REDIRECT_URI): Promise<string> {
  const response = await fetchApp(harness.app, 'POST', '/oauth/register', { redirect_uri: redirectUri });
  expect(response.status).toBe(201);
  const body = await response.json() as { client_id: string };
  // 32 random bytes, base64url (this implementation's choice; SD §5.3 does
  // not specify the client_id format).
  expect(body.client_id).toMatch(/^[A-Za-z0-9_-]{43}$/);
  return body.client_id;
}

async function authorize(
  harness: OAuthHarness,
  clientId: string,
  options: {
    redirectUri?: string;
    scope?: string;
    state?: string;
    challenge?: string;
    challengeMethod?: string;
    instance?: string;
    token?: string;
  } = {},
): Promise<Response> {
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: options.redirectUri ?? REDIRECT_URI,
    response_type: 'code',
    scope: options.scope ?? 'mcp:read mcp:write',
    state: options.state ?? 'test-state-1',
    code_challenge: options.challenge ?? pkcePair().challenge,
    code_challenge_method: options.challengeMethod ?? 'S256',
    ...(options.instance === undefined ? {} : { instance: options.instance }),
  });
  return fetchApp(harness.app, 'GET', `/oauth/authorize?${params}`, undefined, {
    authorization: `Bearer ${options.token ?? harness.token}`,
  });
}

async function authorizeAndGetCode(
  harness: OAuthHarness,
  clientId: string,
  challenge: string,
  state = 'test-state-1',
  scope = 'mcp:read mcp:write',
): Promise<string> {
  const response = await authorize(harness, clientId, { challenge, state, scope });
  expect(response.status).toBe(302);
  const location = new URL(response.headers.get('location') ?? '');
  expect(location.origin + location.pathname).toBe(REDIRECT_URI);
  expect(location.searchParams.get('state')).toBe(state);
  const code = location.searchParams.get('code');
  expect(typeof code).toBe('string');
  return code as string;
}

async function exchangeCode(
  harness: OAuthHarness,
  input: { code: string; verifier: string; clientId: string; redirectUri?: string },
): Promise<Response> {
  const form = new URLSearchParams({
    grant_type: 'authorization_code',
    code: input.code,
    redirect_uri: input.redirectUri ?? REDIRECT_URI,
    code_verifier: input.verifier,
    client_id: input.clientId,
  });
  return fetchApp(harness.app, 'POST', '/oauth/token', form.toString());
}

describe('OAuth 2.1 discovery and dynamic registration (SD §5.3)', () => {
  it('serves the protected-resource and authorization-server metadata', async () => {
    const harness = await createOAuthHarness();
    const resource = await fetchApp(harness.app, 'GET', '/.well-known/oauth-protected-resource');
    expect(resource.status).toBe(200);
    expect(await resource.json()).toMatchObject({
      resource: 'https://api.sealero.test/mcp',
      authorization_servers: ['https://api.sealero.test'],
      scopes_supported: ['mcp:read', 'mcp:write'],
    });

    const server = await fetchApp(harness.app, 'GET', '/.well-known/oauth-authorization-server');
    expect(server.status).toBe(200);
    expect(await server.json()).toMatchObject({
      issuer: 'https://api.sealero.test',
      authorization_endpoint: 'https://api.sealero.test/oauth/authorize',
      token_endpoint: 'https://api.sealero.test/oauth/token',
      revocation_endpoint: 'https://api.sealero.test/oauth/revoke',
      registration_endpoint: 'https://api.sealero.test/oauth/register',
      code_challenge_methods_supported: ['S256'],
    });
  });

  it('registers a public client and rejects invalid redirect URIs', async () => {
    const harness = await createOAuthHarness();
    const response = await fetchApp(harness.app, 'POST', '/oauth/register', { redirect_uri: REDIRECT_URI });
    expect(response.status).toBe(201);
    // SD §5.3 only specifies client_id in the register response.
    const body = await response.json() as Record<string, unknown>;
    expect(Object.keys(body)).toEqual(['client_id']);
    expect(typeof body['client_id']).toBe('string');

    const bad = await fetchApp(harness.app, 'POST', '/oauth/register', { redirect_uri: 'http://client.example/callback' });
    expect(bad.status).toBe(400);
    expect(await bad.json()).toMatchObject({ code: 'invalid_redirect_uri' });
  });
});

describe('OAuth authorization flow (SD §5.3)', () => {
  it('issues a single-use code and exchanges it for an OAuth access token', async () => {
    const harness = await createOAuthHarness();
    const clientId = await registerClient(harness);
    const { verifier, challenge } = pkcePair();
    const code = await authorizeAndGetCode(harness, clientId, challenge);

    const codes = await harness.database.query<{ code_hash: string; consumed_at: Date | string | null }>(
      'SELECT code_hash, consumed_at FROM oauth_auth_codes WHERE client_id = $1',
      [clientId],
    );
    expect(codes.rows).toHaveLength(1);
    expect(codes.rows[0]?.consumed_at).toBeNull();

    const tokenResponse = await exchangeCode(harness, { code, verifier, clientId });
    expect(tokenResponse.status).toBe(200);
    const tokens = await tokenResponse.json() as Record<string, unknown>;
    expect(tokens['token_type']).toBe('Bearer');
    expect(tokens['expires_in']).toBe(900);
    expect(tokens['scope']).toBe('mcp:read mcp:write');
    expect(typeof tokens['access_token']).toBe('string');
    expect(typeof tokens['refresh_token']).toBe('string');

    const claims = verifyOAuthAccessToken(
      oauthTestJwtKeys,
      tokens['access_token'] as string,
      harness.now(),
    );
    expect(claims.sub).toBe(harness.userId);
    expect(claims.aud).toBe('sealero-mcp');
    expect(claims.iss).toBe('https://api.sealero.test');

    const consumed = await harness.database.query<{ consumed_at: Date | string | null }>(
      'SELECT consumed_at FROM oauth_auth_codes WHERE client_id = $1',
      [clientId],
    );
    expect(consumed.rows[0]?.consumed_at).not.toBeNull();

    const authorizations = await harness.database.query<{ client_id: string; scopes: string; revoked_at: Date | string | null }>(
      'SELECT client_id, scopes, revoked_at FROM oauth_authorizations',
    );
    expect(authorizations.rows).toHaveLength(1);
    expect(authorizations.rows[0]).toMatchObject({ client_id: clientId, scopes: 'mcp:read mcp:write', revoked_at: null });

    // The code is single-use: replay is rejected.
    const replay = await exchangeCode(harness, { code, verifier, clientId });
    expect(replay.status).toBe(400);
    expect(await replay.json()).toMatchObject({ code: 'invalid_grant' });
  });

  it('rejects a wrong PKCE verifier, a wrong redirect URI, and an expired code', async () => {
    const harness = await createOAuthHarness();
    const clientId = await registerClient(harness);

    const { verifier, challenge } = pkcePair();
    const code = await authorizeAndGetCode(harness, clientId, challenge);
    const wrongVerifier = await exchangeCode(harness, { code, verifier: `wrong-${verifier}`, clientId });
    expect(wrongVerifier.status).toBe(400);
    expect(await wrongVerifier.json()).toMatchObject({ code: 'invalid_grant' });

    // A fresh, unused code for the redirect test: the code above is already
    // burned by the mismatch, so reusing it would not test redirect binding.
    const { verifier: verifierR, challenge: challengeR } = pkcePair();
    const codeR = await authorizeAndGetCode(harness, clientId, challengeR);
    const wrongRedirect = await exchangeCode(harness, { code: codeR, verifier: verifierR, clientId, redirectUri: 'https://client.example/other' });
    expect(wrongRedirect.status).toBe(400);
    expect(await wrongRedirect.json()).toMatchObject({ code: 'invalid_grant' });

    const { verifier: verifier2, challenge: challenge2 } = pkcePair();
    const code2 = await authorizeAndGetCode(harness, clientId, challenge2);
    harness.setNow(new Date(OAUTH_TEST_INITIAL_TIME.getTime() + 11 * 60_000));
    const expired = await exchangeCode(harness, { code: code2, verifier: verifier2, clientId });
    expect(expired.status).toBe(400);
    expect(await expired.json()).toMatchObject({ code: 'invalid_grant' });
  });

  it('rejects authorize requests without PKCE, with a bad scope, and for a non-official instance', async () => {
    const harness = await createOAuthHarness();
    const clientId = await registerClient(harness);

    const noPkce = await authorize(harness, clientId, { challenge: '' });
    expect(noPkce.status).toBe(400);
    expect(await noPkce.json()).toMatchObject({ code: 'invalid_request' });

    const badScope = await authorize(harness, clientId, { scope: 'vault:admin' });
    expect(badScope.status).toBe(400);
    expect(await badScope.json()).toMatchObject({ code: 'invalid_scope' });

    const selfHosted = await authorize(harness, clientId, { instance: 'self-hosted' });
    expect(selfHosted.status).toBe(400);
    expect(await selfHosted.json()).toMatchObject({ code: 'invalid_request' });

    const unauthenticated = await authorize(harness, clientId, { token: 'not-a-token' });
    expect(unauthenticated.status).toBe(401);
  });

  it('rotates the refresh token and enforces the 90-day absolute session', async () => {
    const harness = await createOAuthHarness();
    const clientId = await registerClient(harness);
    const { verifier, challenge } = pkcePair();
    const code = await authorizeAndGetCode(harness, clientId, challenge);
    const first = await exchangeCode(harness, { code, verifier, clientId });
    const firstTokens = await first.json() as Record<string, unknown>;

    const refreshForm = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: firstTokens['refresh_token'] as string,
      client_id: clientId,
    });
    const refreshed = await fetchApp(harness.app, 'POST', '/oauth/token', refreshForm.toString());
    expect(refreshed.status).toBe(200);
    const secondTokens = await refreshed.json() as Record<string, unknown>;
    expect(secondTokens['access_token']).not.toBe(firstTokens['access_token']);
    expect(secondTokens['refresh_token']).not.toBe(firstTokens['refresh_token']);

    // The old refresh token is now revoked: replay is rejected with 401
    // (SD §5.3: 旧 refresh 再来只回 401).
    const replay = await fetchApp(harness.app, 'POST', '/oauth/token', refreshForm.toString());
    expect(replay.status).toBe(401);
    expect(await replay.json()).toMatchObject({ code: 'unauthorized' });

    // After 91 days the absolute session is over.
    harness.setNow(new Date(OAUTH_TEST_INITIAL_TIME.getTime() + 91 * 24 * 60 * 60_000));
    const lateForm = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: secondTokens['refresh_token'] as string,
      client_id: clientId,
    });
    const late = await fetchApp(harness.app, 'POST', '/oauth/token', lateForm.toString());
    expect(late.status).toBe(401);
    expect(await late.json()).toMatchObject({ code: 'unauthorized' });
  });

  it('revokes an authorization and its tokens', async () => {
    const harness = await createOAuthHarness();
    const clientId = await registerClient(harness);
    const { verifier, challenge } = pkcePair();
    const code = await authorizeAndGetCode(harness, clientId, challenge);
    const first = await exchangeCode(harness, { code, verifier, clientId });
    const tokens = await first.json() as Record<string, unknown>;

    const revokeForm = new URLSearchParams({ token: tokens['refresh_token'] as string });
    const revoked = await fetchApp(harness.app, 'POST', '/oauth/revoke', revokeForm.toString());
    expect(revoked.status).toBe(200);

    const refreshForm = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: tokens['refresh_token'] as string,
      client_id: clientId,
    });
    const refreshAfterRevoke = await fetchApp(harness.app, 'POST', '/oauth/token', refreshForm.toString());
    // SD §5.3: a revoked refresh token only returns 401.
    expect(refreshAfterRevoke.status).toBe(401);
    expect(await refreshAfterRevoke.json()).toMatchObject({ code: 'unauthorized' });

    // The access token is rejected by the MCP endpoint after revocation.
    const mcp = await fetchApp(harness.app, 'POST', '/mcp', {
      jsonrpc: '2.0',
      id: 1,
      method: 'ping',
    }, { authorization: `Bearer ${tokens['access_token'] as string}` });
    expect(mcp.status).toBe(401);
    expect(await mcp.json()).toMatchObject({ code: 'unauthorized' });

    // Revoking an unknown token still returns 200 (RFC 7009).
    const unknown = await fetchApp(harness.app, 'POST', '/oauth/revoke', new URLSearchParams({ token: 'unknown-token' }).toString());
    expect(unknown.status).toBe(200);
  });

  it('issues distinct access tokens for two exchanges at the same frozen time', async () => {
    const harness = await createOAuthHarness();
    expect((await harness.consent()).status).toBe(200);
    const clientId = await registerClient(harness);

    // Read-only flow.
    const { verifier: verifier1, challenge: challenge1 } = pkcePair();
    const code1 = await authorizeAndGetCode(harness, clientId, challenge1, 'test-state-1', 'mcp:read');
    const first = await exchangeCode(harness, { code: code1, verifier: verifier1, clientId });
    expect(first.status).toBe(200);
    const firstTokens = await first.json() as Record<string, unknown>;
    expect(firstTokens['scope']).toBe('mcp:read');

    // Read+write flow at the same frozen time: identical iat/exp, so the
    // tokens must still differ (the jti fix).
    const { verifier: verifier2, challenge: challenge2 } = pkcePair();
    const code2 = await authorizeAndGetCode(harness, clientId, challenge2, 'test-state-2', 'mcp:read mcp:write');
    const second = await exchangeCode(harness, { code: code2, verifier: verifier2, clientId });
    expect(second.status).toBe(200);
    const secondTokens = await second.json() as Record<string, unknown>;

    expect(secondTokens['access_token']).not.toBe(firstTokens['access_token']);
    expect(secondTokens['refresh_token']).not.toBe(firstTokens['refresh_token']);
    const claims1 = verifyOAuthAccessToken(
      oauthTestJwtKeys,
      firstTokens['access_token'] as string,
      harness.now(),
    );
    const claims2 = verifyOAuthAccessToken(
      oauthTestJwtKeys,
      secondTokens['access_token'] as string,
      harness.now(),
    );
    expect(claims1.jti).toBeDefined();
    expect(claims2.jti).not.toBe(claims1.jti);

    const rows = await harness.database.query<{ access_token_hash: string; scopes: string }>(
      'SELECT access_token_hash, scopes FROM oauth_authorizations ORDER BY scopes',
    );
    expect(rows.rows).toHaveLength(2);
    expect(rows.rows[0]?.access_token_hash).not.toBe(rows.rows[1]?.access_token_hash);
    expect(rows.rows.map((row) => row.scopes).sort()).toEqual(['mcp:read', 'mcp:read mcp:write']);

    // Each token works per its own scope.
    const search = await fetchApp(harness.app, 'POST', '/mcp', {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'search_vault_items', arguments: { domain_hmac: 'a'.repeat(64) } },
    }, { authorization: `Bearer ${firstTokens['access_token'] as string}` });
    expect(search.status).toBe(200);

    const createArguments = {
      id: '00000000-0000-4000-8000-000000000310',
      base_version: 0,
      version: 1,
      overview_ciphertext: 'overview-scope',
      overview_nonce: 'nonce-scope',
      detail_ciphertext: 'detail-scope',
      detail_nonce: 'detail-nonce-scope',
      domain_hmac: null,
    };
    const readCreate = await fetchApp(harness.app, 'POST', '/mcp', {
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'create_vault_item', arguments: createArguments },
    }, { authorization: `Bearer ${firstTokens['access_token'] as string}` });
    const readCreateBody = await readCreate.json() as { error: { code: number } };
    expect(readCreateBody.error.code).toBe(-32001);

    const writeCreate = await fetchApp(harness.app, 'POST', '/mcp', {
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'create_vault_item', arguments: createArguments },
    }, { authorization: `Bearer ${secondTokens['access_token'] as string}` });
    expect(writeCreate.status).toBe(200);
    const writeCreateBody = await writeCreate.json() as { result: { content: Array<{ text: string }> } };
    expect(JSON.parse(writeCreateBody.result.content[0]?.text ?? '{}')).toMatchObject({ version: 1 });
  });

  it('exchanges a code with a JSON body', async () => {
    const harness = await createOAuthHarness();
    const clientId = await registerClient(harness);
    const { verifier, challenge } = pkcePair();
    const code = await authorizeAndGetCode(harness, clientId, challenge);

    const tokenResponse = await fetchApp(harness.app, 'POST', '/oauth/token', {
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
      client_id: clientId,
    });
    expect(tokenResponse.status).toBe(200);
    const tokens = await tokenResponse.json() as Record<string, unknown>;
    expect(tokens['token_type']).toBe('Bearer');
    expect(typeof tokens['access_token']).toBe('string');
  });
});
