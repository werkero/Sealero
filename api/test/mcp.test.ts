import { createHash, randomBytes } from 'node:crypto';
import { afterEach, assert, describe, expect, it, vi } from 'vitest';

// PGlite harness creation takes 3-9s on the 1.5-CPU sandbox; the 5s default flakes.
vi.setConfig({ testTimeout: 30_000 });
import {
  OAUTH_TEST_INITIAL_TIME,
  closeOAuthHarnesses,
  createOAuthHarness,
  fetchApp,
} from './support/oauth-harness.js';
import type { OAuthHarness } from './support/oauth-harness.js';

const REDIRECT_URI = 'https://client.example/callback';
const DOMAIN_HMAC = 'a'.repeat(64);
const OTHER_DOMAIN_HMAC = 'b'.repeat(64);
const ITEM_ID = '00000000-0000-4000-8000-000000000301';
const NEW_ITEM_ID = '00000000-0000-4000-8000-000000000302';

afterEach(async () => {
  await closeOAuthHarnesses();
});

async function mcpCall(
  harness: OAuthHarness,
  accessToken: string,
  body: unknown,
): Promise<Response> {
  return fetchApp(harness.app, 'POST', '/mcp', body, {
    authorization: `Bearer ${accessToken}`,
  });
}

async function oauthAccessToken(harness: OAuthHarness, scopes = 'mcp:read mcp:write'): Promise<string> {
  const register = await fetchApp(harness.app, 'POST', '/oauth/register', { redirect_uri: REDIRECT_URI });
  const { client_id: clientId } = await register.json() as { client_id: string };

  const verifier = `mcp-test-verifier-${randomBytes(24).toString('base64url')}`;
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: scopes,
    state: 'mcp-state',
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });
  const authorize = await fetchApp(harness.app, 'GET', `/oauth/authorize?${params}`, undefined, {
    authorization: `Bearer ${harness.token}`,
  });
  expect(authorize.status).toBe(302);
  const code = new URL(authorize.headers.get('location') ?? '').searchParams.get('code');
  expect(typeof code).toBe('string');

  const form = new URLSearchParams({
    grant_type: 'authorization_code',
    code: code as string,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier,
    client_id: clientId,
  });
  const tokenResponse = await fetchApp(harness.app, 'POST', '/oauth/token', form.toString());
  expect(tokenResponse.status).toBe(200);
  const tokens = await tokenResponse.json() as { access_token: string };
  return tokens.access_token;
}

async function seedVaultItem(harness: OAuthHarness, domainHmac: string, id = ITEM_ID): Promise<void> {
  const result = await harness.store.createVaultItem(harness.userId, harness.deviceId, {
    id,
    version: 1,
    overview_ciphertext: `overview-${id}`,
    overview_nonce: `nonce-${id}`,
    detail_ciphertext: `detail-${id}`,
    detail_nonce: `detail-nonce-${id}`,
    domain_hmac: domainHmac,
  });
  expect(result.kind).toBe('ok');
}

describe('MCP Streamable HTTP endpoint (SD §5.3)', () => {
  it('answers initialize, ping and tools/list', async () => {
    const harness = await createOAuthHarness();
    expect((await harness.consent()).status).toBe(200);
    const accessToken = await oauthAccessToken(harness);

    const initialize = await mcpCall(harness, accessToken, {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'test-client', version: '1.0' } },
    });
    expect(initialize.status).toBe(200);
    const initBody = await initialize.json() as { result: { protocolVersion: string; serverInfo: { name: string } } };
    expect(initBody.result.protocolVersion).toBe('2025-03-26');
    expect(initBody.result.serverInfo.name).toBe('sealero');

    const ping = await mcpCall(harness, accessToken, { jsonrpc: '2.0', id: 2, method: 'ping' });
    expect(ping.status).toBe(200);
    expect(await ping.json()).toMatchObject({ jsonrpc: '2.0', id: 2, result: {} });

    const list = await mcpCall(harness, accessToken, { jsonrpc: '2.0', id: 3, method: 'tools/list' });
    expect(list.status).toBe(200);
    const listBody = await list.json() as { result: { tools: Array<{ name: string }> } };
    expect(listBody.result.tools.map((tool) => tool.name).sort()).toEqual([
      'create_vault_item',
      'get_vault_item',
      'search_vault_items',
    ]);
  });

  it('searches by domain_hmac and returns only ciphertext', async () => {
    const harness = await createOAuthHarness();
    expect((await harness.consent()).status).toBe(200);
    const accessToken = await oauthAccessToken(harness);
    await seedVaultItem(harness, DOMAIN_HMAC);

    const search = await mcpCall(harness, accessToken, {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'search_vault_items', arguments: { domain_hmac: DOMAIN_HMAC } },
    });
    expect(search.status).toBe(200);
    const searchBody = await search.json() as {
      result: { content: Array<{ text: string }> };
    };
    const found = JSON.parse(searchBody.result.content[0]?.text ?? '{}') as {
      items: Array<{ item_id: string; overview_ciphertext: string }>;
    };
    expect(found.items).toHaveLength(1);
    expect(found.items[0]?.item_id).toBe(ITEM_ID);
    expect(found.items[0]?.overview_ciphertext).toBe(`overview-${ITEM_ID}`);

    const miss = await mcpCall(harness, accessToken, {
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: { name: 'search_vault_items', arguments: { domain_hmac: OTHER_DOMAIN_HMAC } },
    });
    const missBody = await miss.json() as { result: { content: Array<{ text: string }> } };
    const missed = JSON.parse(missBody.result.content[0]?.text ?? '{}') as { items: unknown[] };
    expect(missed.items).toHaveLength(0);

    const badHmac = await mcpCall(harness, accessToken, {
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'search_vault_items', arguments: { domain_hmac: 'not-a-hmac' } },
    });
    const badBody = await badHmac.json() as { error: { code: number } };
    expect(badBody.error.code).toBe(-32602);
  });

  it('creates an item through the MCP tool and enforces mcp:write', async () => {
    const harness = await createOAuthHarness();
    expect((await harness.consent()).status).toBe(200);
    const accessToken = await oauthAccessToken(harness);

    const create = await mcpCall(harness, accessToken, {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: {
        name: 'create_vault_item',
        arguments: {
          id: NEW_ITEM_ID,
          base_version: 0,
          version: 1,
          overview_ciphertext: 'overview-new',
          overview_nonce: 'nonce-new',
          detail_ciphertext: 'detail-new',
          detail_nonce: 'detail-nonce-new',
          domain_hmac: DOMAIN_HMAC,
        },
      },
    });
    expect(create.status).toBe(200);
    const createBody = await create.json() as { result: { content: Array<{ text: string }> } };
    const created = JSON.parse(createBody.result.content[0]?.text ?? '{}') as { item_id: string; version: number };
    expect(created).toEqual({ item_id: NEW_ITEM_ID, version: 1, updated_at: expect.any(String) });

    const readOnlyToken = await oauthAccessToken(harness, 'mcp:read');
    const denied = await mcpCall(harness, readOnlyToken, {
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: {
        name: 'create_vault_item',
        arguments: {
          id: '00000000-0000-4000-8000-000000000303',
          base_version: 0,
          version: 1,
          overview_ciphertext: 'overview-x',
          overview_nonce: 'nonce-x',
          detail_ciphertext: 'detail-x',
          detail_nonce: 'detail-nonce-x',
          domain_hmac: null,
        },
      },
    });
    const deniedBody = await denied.json() as { error: { code: number; message: string } };
    expect(deniedBody.error.code).toBe(-32001);
    expect(deniedBody.error.message).toContain('mcp:write');
  });

  it('get-one confirmation flow: 403, approve in trusted UI, retry delivers once', async () => {
    const harness = await createOAuthHarness();
    expect((await harness.consent()).status).toBe(200);
    const accessToken = await oauthAccessToken(harness);
    await seedVaultItem(harness, DOMAIN_HMAC);

    const getBody = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'get_vault_item', arguments: { item_id: ITEM_ID } },
    };
    const first = await mcpCall(harness, accessToken, getBody);
    expect(first.status).toBe(403);
    const firstBody = await first.json() as { code: string; details: { confirmation_id: string } };
    expect(firstBody.code).toBe('confirmation_required');
    const confirmationId = firstBody.details.confirmation_id;
    expect(typeof confirmationId).toBe('string');

    // A retry before approval reuses the same pending confirmation.
    const second = await mcpCall(harness, accessToken, getBody);
    expect(second.status).toBe(403);
    const secondBody = await second.json() as { code: string; details: { confirmation_id: string } };
    expect(secondBody.details.confirmation_id).toBe(confirmationId);

    // The trusted UI lists the pending request.
    const list = await fetchApp(harness.app, 'GET', '/v1/mcp/confirmations', undefined, {
      authorization: `Bearer ${harness.token}`,
    });
    expect(list.status).toBe(200);
    const listBody = await list.json() as {
      confirmations: { confirmation_id: string; item_id: string; status: string }[];
    };
    expect(listBody.confirmations).toHaveLength(1);
    expect(listBody.confirmations[0]).toMatchObject({
      confirmation_id: confirmationId,
      item_id: ITEM_ID,
      status: 'pending',
    });

    // The user approves in the trusted UI; the AI cannot do this itself.
    const approve = await fetchApp(
      harness.app,
      'POST',
      `/v1/mcp/confirmations/${confirmationId}/approve`,
      undefined,
      { authorization: `Bearer ${harness.token}` },
    );
    expect(approve.status).toBe(200);
    expect(await approve.json()).toMatchObject({ confirmation_id: confirmationId, status: 'approved' });

    // The retry now delivers the full ciphertext once.
    const delivered = await mcpCall(harness, accessToken, getBody);
    expect(delivered.status).toBe(200);
    const deliveredBody = await delivered.json() as { result: { content: { text: string }[] } };
    const firstContent = deliveredBody.result.content[0];
    assert.ok(firstContent !== undefined);
    const detail = JSON.parse(firstContent.text) as Record<string, unknown>;
    expect(detail).toMatchObject({
      item_id: ITEM_ID,
      version: 1,
      overview_ciphertext: `overview-${ITEM_ID}`,
      detail_ciphertext: `detail-${ITEM_ID}`,
    });

    // Single use: the next retry asks for a fresh confirmation.
    const after = await mcpCall(harness, accessToken, getBody);
    expect(after.status).toBe(403);
    const afterBody = await after.json() as { code: string; details: { confirmation_id: string } };
    expect(afterBody.code).toBe('confirmation_required');
    expect(afterBody.details.confirmation_id).not.toBe(confirmationId);
  });

  it('rejects unauthenticated calls and blocks MCP without consent', async () => {
    const harness = await createOAuthHarness();
    const accessToken = await oauthAccessToken(harness);

    const noToken = await fetchApp(harness.app, 'POST', '/mcp', { jsonrpc: '2.0', id: 1, method: 'ping' });
    expect(noToken.status).toBe(401);
    expect(await noToken.json()).toMatchObject({ code: 'unauthorized' });

    // No consent yet: the consent gate blocks vault access.
    const blocked = await mcpCall(harness, accessToken, { jsonrpc: '2.0', id: 2, method: 'ping' });
    expect(blocked.status).toBe(403);
    expect(await blocked.json()).toMatchObject({ code: 'consent_required' });

    expect((await harness.consent()).status).toBe(200);
    const allowed = await mcpCall(harness, accessToken, { jsonrpc: '2.0', id: 3, method: 'ping' });
    expect(allowed.status).toBe(200);
  });

  it('rejects a login JWT as an MCP token and answers notifications with 202', async () => {
    const harness = await createOAuthHarness();
    expect((await harness.consent()).status).toBe(200);

    const loginJwt = await mcpCall(harness, harness.token, { jsonrpc: '2.0', id: 1, method: 'ping' });
    expect(loginJwt.status).toBe(401);

    const accessToken = await oauthAccessToken(harness);
    const notification = await mcpCall(harness, accessToken, {
      jsonrpc: '2.0',
      method: 'notifications/initialized',
    });
    expect(notification.status).toBe(202);

    const unknown = await mcpCall(harness, accessToken, { jsonrpc: '2.0', id: 9, method: 'resources/list' });
    const unknownBody = await unknown.json() as { error: { code: number } };
    expect(unknownBody.error.code).toBe(-32601);
  });

  it('rejects an expired OAuth access token', async () => {
    const harness = await createOAuthHarness();
    expect((await harness.consent()).status).toBe(200);
    const accessToken = await oauthAccessToken(harness);
    harness.setNow(new Date(OAUTH_TEST_INITIAL_TIME.getTime() + 16 * 60_000));
    const expired = await mcpCall(harness, accessToken, { jsonrpc: '2.0', id: 1, method: 'ping' });
    expect(expired.status).toBe(401);
  });

  it('get_vault_item for a missing item returns HTTP 404', async () => {
    const harness = await createOAuthHarness();
    expect((await harness.consent()).status).toBe(200);
    const accessToken = await oauthAccessToken(harness);

    const missing = await getItemCall(harness, accessToken, '00000000-0000-4000-8000-000000000399');
    expect(missing.status).toBe(404);
    expect(await missing.json()).toMatchObject({ code: 'item_not_found' });
  });

  it('get_vault_item for a deleted item returns HTTP 410', async () => {
    const harness = await createOAuthHarness();
    expect((await harness.consent()).status).toBe(200);
    const accessToken = await oauthAccessToken(harness);
    await seedVaultItem(harness, DOMAIN_HMAC);
    const deleted = await harness.store.deleteVaultItem(harness.userId, harness.deviceId, ITEM_ID, 1);
    expect(deleted.kind).toBe('ok');

    const gone = await getItemCall(harness, accessToken, ITEM_ID);
    expect(gone.status).toBe(410);
    expect(await gone.json()).toMatchObject({ code: 'item_deleted' });
  });

  it('deny then retry creates a new confirmation', async () => {
    const harness = await createOAuthHarness();
    expect((await harness.consent()).status).toBe(200);
    const accessToken = await oauthAccessToken(harness);
    await seedVaultItem(harness, DOMAIN_HMAC);

    const first = await getItemCall(harness, accessToken, ITEM_ID);
    expect(first.status).toBe(403);
    const firstBody = await first.json() as { details: { confirmation_id: string } };
    const firstId = firstBody.details.confirmation_id;

    const denied = await decideConfirmation(harness, firstId, 'deny');
    expect(denied.status).toBe(200);
    expect(await denied.json()).toMatchObject({ confirmation_id: firstId, status: 'denied' });

    const second = await getItemCall(harness, accessToken, ITEM_ID);
    expect(second.status).toBe(403);
    const secondBody = await second.json() as { details: { confirmation_id: string } };
    expect(secondBody.details.confirmation_id).not.toBe(firstId);
  });

  it('pending expired then retry creates a new confirmation', async () => {
    const harness = await createOAuthHarness();
    expect((await harness.consent()).status).toBe(200);
    const accessToken = await oauthAccessToken(harness);
    await seedVaultItem(harness, DOMAIN_HMAC);

    const first = await getItemCall(harness, accessToken, ITEM_ID);
    expect(first.status).toBe(403);
    const firstBody = await first.json() as { details: { confirmation_id: string } };
    const firstId = firstBody.details.confirmation_id;

    // The 5-minute confirmation TTL lapses; the OAuth token is still valid.
    harness.setNow(new Date(OAUTH_TEST_INITIAL_TIME.getTime() + 6 * 60_000));
    const second = await getItemCall(harness, accessToken, ITEM_ID);
    expect(second.status).toBe(403);
    const secondBody = await second.json() as { details: { confirmation_id: string } };
    expect(secondBody.details.confirmation_id).not.toBe(firstId);
  });

  it('approve then delete the item then retry returns HTTP 410', async () => {
    const harness = await createOAuthHarness();
    expect((await harness.consent()).status).toBe(200);
    const accessToken = await oauthAccessToken(harness);
    await seedVaultItem(harness, DOMAIN_HMAC);

    const first = await getItemCall(harness, accessToken, ITEM_ID);
    expect(first.status).toBe(403);
    const firstBody = await first.json() as { details: { confirmation_id: string } };
    expect((await decideConfirmation(harness, firstBody.details.confirmation_id, 'approve')).status).toBe(200);

    const deleted = await harness.store.deleteVaultItem(harness.userId, harness.deviceId, ITEM_ID, 1);
    expect(deleted.kind).toBe('ok');

    const gone = await getItemCall(harness, accessToken, ITEM_ID);
    expect(gone.status).toBe(410);
    expect(await gone.json()).toMatchObject({ code: 'item_deleted' });
  });

  it('concurrent approve: one succeeds, one gets confirmation_already_decided', async () => {
    const harness = await createOAuthHarness();
    expect((await harness.consent()).status).toBe(200);
    const accessToken = await oauthAccessToken(harness);
    await seedVaultItem(harness, DOMAIN_HMAC);

    const first = await getItemCall(harness, accessToken, ITEM_ID);
    expect(first.status).toBe(403);
    const firstBody = await first.json() as { details: { confirmation_id: string } };
    const confirmationId = firstBody.details.confirmation_id;

    const [one, two] = await Promise.all([
      decideConfirmation(harness, confirmationId, 'approve'),
      decideConfirmation(harness, confirmationId, 'approve'),
    ]);
    const statuses = [one.status, two.status].sort();
    expect(statuses).toEqual([200, 409]);
    const loser = one.status === 409 ? one : two;
    expect(await loser.json()).toMatchObject({ code: 'confirmation_already_decided' });
  });

  it('concurrent consume after approve: one delivers, one asks for a fresh confirmation', async () => {
    const harness = await createOAuthHarness();
    expect((await harness.consent()).status).toBe(200);
    const accessToken = await oauthAccessToken(harness);
    await seedVaultItem(harness, DOMAIN_HMAC);

    const first = await getItemCall(harness, accessToken, ITEM_ID);
    expect(first.status).toBe(403);
    const firstBody = await first.json() as { details: { confirmation_id: string } };
    const confirmationId = firstBody.details.confirmation_id;
    expect((await decideConfirmation(harness, confirmationId, 'approve')).status).toBe(200);

    const [one, two] = await Promise.all([
      getItemCall(harness, accessToken, ITEM_ID),
      getItemCall(harness, accessToken, ITEM_ID),
    ]);
    const statuses = [one.status, two.status].sort();
    expect(statuses).toEqual([200, 403]);
    const loser = one.status === 403 ? one : two;
    const loserBody = await loser.json() as { code: string; details: { confirmation_id: string } };
    expect(loserBody.code).toBe('confirmation_required');
    expect(loserBody.details.confirmation_id).not.toBe(confirmationId);
  });

  it('/mcp email gate: unverified email returns 403 email_verification_required', async () => {
    const harness = await createOAuthHarness();
    expect((await harness.consent()).status).toBe(200);
    const accessToken = await oauthAccessToken(harness);
    await harness.database.query(
      "INSERT INTO server_settings (key, value) VALUES ('require_email_verification', 'true')",
    );
    await harness.database.query('UPDATE users SET email_verified_at = NULL WHERE id = $1', [harness.userId]);

    const blocked = await mcpCall(harness, accessToken, { jsonrpc: '2.0', id: 1, method: 'ping' });
    expect(blocked.status).toBe(403);
    expect(await blocked.json()).toMatchObject({ code: 'email_verification_required' });
  });

  it('disabled account calling /mcp returns 403 account_disabled', async () => {
    const harness = await createOAuthHarness();
    expect((await harness.consent()).status).toBe(200);
    const accessToken = await oauthAccessToken(harness);
    await harness.database.query('UPDATE users SET disabled_at = $1 WHERE id = $2', [harness.now(), harness.userId]);

    const blocked = await mcpCall(harness, accessToken, { jsonrpc: '2.0', id: 1, method: 'ping' });
    expect(blocked.status).toBe(403);
    expect(await blocked.json()).toMatchObject({ code: 'account_disabled' });
  });

  it('write-only token calling search gets -32001 insufficient_scope', async () => {
    const harness = await createOAuthHarness();
    expect((await harness.consent()).status).toBe(200);
    const writeOnlyToken = await oauthAccessToken(harness, 'mcp:write');

    const search = await mcpCall(harness, writeOnlyToken, {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'search_vault_items', arguments: { domain_hmac: DOMAIN_HMAC } },
    });
    const searchBody = await search.json() as { error: { code: number; message: string } };
    expect(searchBody.error.code).toBe(-32001);
    expect(searchBody.error.message).toContain('mcp:read');
  });

  it('revoke by access token then /mcp returns 401', async () => {
    const harness = await createOAuthHarness();
    expect((await harness.consent()).status).toBe(200);
    const accessToken = await oauthAccessToken(harness);

    const form = new URLSearchParams({ token: accessToken });
    const revoked = await fetchApp(harness.app, 'POST', '/oauth/revoke', form.toString());
    expect(revoked.status).toBe(200);

    const blocked = await mcpCall(harness, accessToken, { jsonrpc: '2.0', id: 1, method: 'ping' });
    expect(blocked.status).toBe(401);
    expect(await blocked.json()).toMatchObject({ code: 'unauthorized' });
  });

  it('initialize with an unknown protocol version defaults to 2025-03-26', async () => {
    const harness = await createOAuthHarness();
    expect((await harness.consent()).status).toBe(200);
    const accessToken = await oauthAccessToken(harness);

    const initialize = await mcpCall(harness, accessToken, {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2099-01-01', capabilities: {}, clientInfo: { name: 'test-client', version: '1.0' } },
    });
    expect(initialize.status).toBe(200);
    const initBody = await initialize.json() as { result: { protocolVersion: string } };
    expect(initBody.result.protocolVersion).toBe('2025-03-26');
  });
});

async function getItemCall(
  harness: OAuthHarness,
  accessToken: string,
  itemId: string,
): Promise<Response> {
  return mcpCall(harness, accessToken, {
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: { name: 'get_vault_item', arguments: { item_id: itemId } },
  });
}

async function decideConfirmation(
  harness: OAuthHarness,
  confirmationId: string,
  decision: 'approve' | 'deny',
): Promise<Response> {
  return fetchApp(
    harness.app,
    'POST',
    `/v1/mcp/confirmations/${confirmationId}/${decision}`,
    undefined,
    { authorization: `Bearer ${harness.token}` },
  );
}
