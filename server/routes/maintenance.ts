import { timingSafeEqual } from 'node:crypto';
import { Hono } from 'hono';
import type { Context } from 'hono';
import { ApiError } from '../app.js';
import type { TransactionalSqlDatabase } from '../db/auth-store.js';
import type { VaultStore } from '../vault/types.js';

/**
 * Maintenance endpoints for the scheduled cleanup job (System Design §7.4,
 * §8). Vercel Cron calls `GET /v1/admin/maintenance/cleanup` with
 * `Authorization: Bearer <TOMBSTONE_CLEANUP_SECRET>`; the secret is never a
 * URL parameter. This is deliberately NOT behind the JWT middleware — the
 * cron caller has no user session, the bearer secret is its credential.
 *
 * One run does both cleanups: tombstones older than 30 days become permanent
 * minimal tombstones (via the store), and expired OAuth authorization codes
 * are deleted (unconsumed expired codes, plus consumed codes older than 24
 * hours, which are kept that long for audit and replay detection).
 */
export interface MaintenanceDependencies {
  readonly store: VaultStore;
  readonly database: TransactionalSqlDatabase;
  /** Undefined or empty means the endpoint is not configured: fail closed. */
  readonly cleanupSecret: string | undefined;
  readonly now?: () => Date;
}

async function deleteExpiredOAuthAuthCodes(
  database: TransactionalSqlDatabase,
  now: Date,
): Promise<number> {
  const consumedCutoff = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const result = await database.query<{ id: string }>(
    `DELETE FROM oauth_auth_codes
     WHERE (consumed_at IS NULL AND expires_at <= $1)
        OR (consumed_at IS NOT NULL AND consumed_at <= $2)
     RETURNING id`,
    [now, consumedCutoff],
  );
  return result.rows.length;
}

async function recordCleanupRun(
  database: TransactionalSqlDatabase,
  at: Date,
  status: 'success' | 'failed',
): Promise<void> {
  await database.query(
    `INSERT INTO server_settings (key, value) VALUES
       ('tombstone_last_cleanup_at', $1),
       ('tombstone_last_cleanup_status', $2)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
    [at.toISOString(), status],
  );
}

export function createMaintenanceRoutes(dependencies: MaintenanceDependencies): Hono {
  const routes = new Hono();

  const handler = async (context: Context): Promise<Response> => {
    const secret = dependencies.cleanupSecret;
    if (typeof secret !== 'string' || secret === '') {
      throw new ApiError(
        503,
        'maintenance_unavailable',
        'The maintenance endpoint is not configured.',
      );
    }
    const presented = context.req.header('authorization') ?? '';
    const token = presented.startsWith('Bearer ') ? presented.slice('Bearer '.length) : '';
    const expected = Buffer.from(secret, 'utf8');
    const actual = Buffer.from(token, 'utf8');
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
      throw new ApiError(401, 'unauthorized', 'Invalid maintenance credentials.');
    }

    const now = (dependencies.now ?? (() => new Date()))();
    try {
      const cleanedTombstones = await dependencies.store.cleanupExpiredTombstones(now);
      const deletedCodes = await deleteExpiredOAuthAuthCodes(dependencies.database, now);
      await recordCleanupRun(dependencies.database, now, 'success');
      return context.json(
        {
          cleaned_tombstones: cleanedTombstones,
          deleted_oauth_codes: deletedCodes,
          cleaned_at: now.toISOString(),
        },
        200,
      );
    } catch (error) {
      try {
        await recordCleanupRun(dependencies.database, now, 'failed');
      } catch {
        // The run already failed; a failed status write must not mask it.
      }
      throw error;
    }
  };

  // Vercel Cron invokes its path with GET; POST is accepted for manual runs.
  routes.get('/cleanup', handler);
  routes.post('/cleanup', handler);
  return routes;
}
