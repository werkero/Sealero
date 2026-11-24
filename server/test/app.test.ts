import { Hono } from 'hono';
import { describe, expect, it, vi } from 'vitest';
import vercelApp, { createDeploymentApp } from '../../api/index.js';
import type { DeploymentAuthDependencies } from '../../api/index.js';
import { ApiError, createApp, type Logger, type RequestLogEntry } from '../app.js';
import { ENVIRONMENT_VARIABLE_NAMES, loadConfig } from '../config.js';

const config = loadConfig({});

function captureLogger(): { entries: RequestLogEntry[]; logger: Logger } {
  const entries: RequestLogEntry[] = [];
  const logger: Logger = { log: (entry) => entries.push(entry) };
  return { entries, logger };
}

describe('API scaffold', () => {
  it('mounts registered v1 route modules under /v1', async () => {
    const routes = new Hono();
    routes.get('/probe', (context) => context.json({ ready: true }));
    const app = createApp(config, captureLogger().logger, routes);

    const response = await app.request('/v1/probe');
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ready: true });
    expect(response.headers.get('x-request-id')).toBeTruthy();
  });

  it('fails closed at the Vercel entry until a real auth runtime is injected', async () => {
    expect(typeof createDeploymentApp).toBe('function');
    expect(() => createDeploymentApp({
      siteOrigin: 'http://localhost:3000',
      allowInsecureHttp: true,
    } as unknown as DeploymentAuthDependencies, {})).toThrow('configured HTTPS issuer');
    expect(typeof vercelApp.fetch).toBe('function');
    const response = await vercelApp.fetch(
      new Request('https://sealero.test/v1/scaffold-probe'),
    );

    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({
      code: 'auth_runtime_unavailable',
      message: 'The authentication runtime has not been configured.',
    });
  });

  it('serves the documented health response from the default Vercel entry', async () => {
    const response = await vercelApp.fetch(
      new Request('https://sealero.test/v1/health'),
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      api_version: 'v1',
      supported_api_versions: ['v1'],
      min_app_versions: { android: null, ios: null, web: null },
      server_time: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/),
      server_name: 'Sealero',
    });
  });

  it('uses the shared {code, message} shape for unregistered routes', async () => {
    const app = createApp(config, captureLogger().logger);
    const response = await app.request('/v1/not-implemented');

    expect(response.status).toBe(404);
    expect(response.headers.get('content-type')).toContain('application/json');
    expect(await response.json()).toEqual({
      code: 'not_found',
      message: 'The requested resource was not found.',
    });
  });

  it('returns only the five documented health fields with a fresh RFC 3339 UTC time per request', async () => {
    const app = createApp(config, captureLogger().logger);
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date('2026-11-22T02:00:00.123Z'));
      const firstResponse = await app.request('/v1/health');
      expect(firstResponse.status).toBe(200);
      expect(firstResponse.headers.get('content-type')).toContain('application/json');
      expect(await firstResponse.json()).toEqual({
        api_version: 'v1',
        supported_api_versions: ['v1'],
        min_app_versions: { android: null, ios: null, web: null },
        server_time: '2026-11-22T02:00:00.123Z',
        server_name: 'Sealero',
      });

      vi.setSystemTime(new Date('2026-11-22T02:00:01.123Z'));
      const secondResponse = await app.request('/v1/health');
      expect(await secondResponse.json()).toEqual({
        api_version: 'v1',
        supported_api_versions: ['v1'],
        min_app_versions: { android: null, ios: null, web: null },
        server_time: '2026-11-22T02:00:01.123Z',
        server_name: 'Sealero',
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it('uses the configured SERVER_NAME in the health response', async () => {
    const app = createApp(loadConfig({ SERVER_NAME: '  Custom Sealero  ' }), captureLogger().logger);
    const response = await app.request('/v1/health');

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      api_version: 'v1',
      supported_api_versions: ['v1'],
      min_app_versions: { android: null, ios: null, web: null },
      server_time: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/),
      server_name: 'Custom Sealero',
    });
  });

  it('normalizes expected API errors to {code, message}', async () => {
    const routes = new Hono();
    routes.get('/disabled', () => {
      throw new ApiError(403, 'account_disabled', 'The account is disabled.');
    });
    const app = createApp(config, captureLogger().logger, routes);
    const response = await app.request('/v1/disabled');

    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({
      code: 'account_disabled',
      message: 'The account is disabled.',
    });
  });

  it('redacts unexpected error details and sensitive request inputs', async () => {
    const { entries, logger } = captureLogger();
    const routes = new Hono();
    routes.post('/fault', () => {
      throw new Error('secret-error-marker');
    });
    const app = createApp(config, logger, routes);
    const response = await app.request('/v1/fault?token=secret-query-marker', {
      method: 'POST',
      headers: {
        authorization: 'Bearer secret-header-marker',
        cookie: 'secret-cookie-marker',
      },
      body: 'secret-body-marker',
    });

    expect(response.status).toBe(500);
    expect(await response.json()).toEqual({
      code: 'internal_error',
      message: 'An internal server error occurred.',
    });
    const logs = JSON.stringify(entries);
    expect(entries).toHaveLength(1);
    expect(entries[0]?.status).toBe(500);
    expect(response.headers.get('x-request-id')).toBe(entries[0]?.request_id);
    expect(logs).not.toContain('secret-error-marker');
    expect(logs).not.toContain('secret-query-marker');
    expect(logs).not.toContain('secret-header-marker');
    expect(logs).not.toContain('secret-cookie-marker');
    expect(logs).not.toContain('secret-body-marker');
  });

  it('uses only documented environment names and the documented server-name default', () => {
    expect(loadConfig({})).toEqual({ serverName: 'Sealero' });
    expect(loadConfig({ SERVER_NAME: '  Custom Sealero  ' })).toEqual({
      serverName: 'Custom Sealero',
      adminSettingsEnvironment: {
        values: { server_name: 'Custom Sealero' },
        smtpPassConfigured: false,
      },
    });
    expect(() => loadConfig({ SERVER_NAME: '   ' })).toThrow('SERVER_NAME');
    expect(() => loadConfig({ SERVER_NAME: 'x'.repeat(101) })).toThrow('SERVER_NAME');
    expect(ENVIRONMENT_VARIABLE_NAMES).toEqual([
      'DATABASE_URL',
      'JWT_PRIVATE_KEY_PATH',
      'JWT_PUBLIC_KEY_PATH',
      'JWT_ACTIVE_KID',
      'JWT_ISSUER',
      'JWT_EXPIRES_IN',
      'REFRESH_TOKEN_EXPIRES_IN',
      'API_BASE_URL',
      'AUTH_MODE',
      'AUTH_CODE_HMAC_SECRET',
      'SERVER_NAME',
      'SMTP_HOST',
      'SMTP_PORT',
      'SMTP_USER',
      'SMTP_PASS',
      'SMTP_FROM',
      'SMTP_SECURE',
      'TOMBSTONE_CLEANUP_SECRET',
      'DB_DUMP_KEY',
    ]);
  });
});
