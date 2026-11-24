import { randomUUID } from 'node:crypto';
import { Hono } from 'hono';
import type { Context } from 'hono';
import type { AppConfig } from './config.js';
import { createHealthRoutes } from './routes/health.js';

export interface RequestLogEntry {
  readonly timestamp: string;
  readonly level: 'info' | 'warn' | 'error';
  readonly request_id: string;
  readonly method: string;
  readonly status: number;
  readonly duration_ms: number;
}

export interface Logger {
  log(entry: RequestLogEntry): void;
}

export type ApiErrorStatus = 400 | 401 | 403 | 404 | 409 | 410 | 426 | 429 | 503;
type ErrorResponseStatus = ApiErrorStatus | 500;

const consoleLogger: Logger = {
  log(entry): void {
    console.log(JSON.stringify(entry));
  },
};

/** An expected, safe-to-return API error. Never pass secrets in its message. */
export class ApiError extends Error {
  constructor(
    readonly status: ApiErrorStatus,
    readonly code: string,
    message: string,
    /**
     * Seconds until the caller may retry. Set only on 429 `rate_limited`
     * errors; the error handler surfaces it as a `Retry-After` header.
     */
    readonly retryAfterSeconds?: number,
    /**
     * Extra machine-readable error context, rendered as a `details` object
     * in the JSON error body when present (for example the
     * `confirmation_id` of a 403 `confirmation_required`, SD §5.3).
     * Whitelisted keys only: never put secrets, hashes, passwords,
     * ciphertext, or internal diagnostics here — anything passed in is
     * rendered verbatim into the response.
     */
    readonly details?: { readonly confirmation_id: string },
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

function errorResponse(
  context: Context,
  status: ErrorResponseStatus,
  code: string,
  message: string,
  retryAfterSeconds?: number,
  details?: { readonly confirmation_id: string },
): Response {
  if (retryAfterSeconds !== undefined) context.header('Retry-After', String(retryAfterSeconds));
  return context.json(
    details === undefined ? { code, message } : { code, message, details },
    status,
  );
}

/** Creates the shared Hono app used by local Node and Vercel entry points. */
export function createApp(
  config: AppConfig,
  logger: Logger = consoleLogger,
  routes: Hono = createHealthRoutes(config),
): Hono {
  const app = new Hono();

  app.use('*', async (context, next) => {
    const requestId = randomUUID();
    const startedAt = Date.now();
    let status = 500;
    context.header('x-request-id', requestId);

    try {
      await next();
      status = context.res.status;
    } catch (error) {
      status = 500;
      throw error;
    } finally {
      // Do not log URLs, query strings, headers, request bodies, or error text.
      logger.log({
        timestamp: new Date().toISOString(),
        level: status >= 500 ? 'error' : status >= 400 ? 'warn' : 'info',
        request_id: requestId,
        method: context.req.method,
        status,
        duration_ms: Math.max(0, Date.now() - startedAt),
      });
    }
  });

  app.route('/v1', routes);
  app.notFound((context) =>
    errorResponse(context, 404, 'not_found', 'The requested resource was not found.'),
  );
  app.onError((error, context) => {
    if (error instanceof ApiError) {
      return errorResponse(context, error.status, error.code, error.message, error.retryAfterSeconds, error.details);
    }

    // Deliberately omit the unexpected error and its details from the response.
    return errorResponse(context, 500, 'internal_error', 'An internal server error occurred.');
  });

  return app;
}
