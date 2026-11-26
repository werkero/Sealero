import { Pool } from '@neondatabase/serverless';
import type { SqlConnection, SqlResult, TransactionalSqlDatabase } from './auth-store.js';

/**
 * Neon store for deployment, built on the Neon serverless driver's `Pool`.
 *
 * Why `Pool` and not the `neon()` HTTP query function: the store layer runs
 * callback-style transactions — `SqlAuthStore` interleaves sequential
 * queries with JavaScript logic inside `transaction()` (row locks, conditional
 * writes, code generation). The HTTP `neon()` function only supports
 * non-interactive transactions (a fixed array of queries, no logic between
 * them), so it cannot honour those transactional guarantees. `Pool` speaks
 * WebSocket to Neon and gives a real `node-postgres`-compatible client, so
 * `BEGIN` / interleaved queries / `COMMIT` / `ROLLBACK` work exactly like
 * the local PGlite adapter.
 *
 * The pooler connection string (host `*-pooler.*.neon.tech`) is supported by
 * the driver for both HTTP and WebSocket paths. Keep the pool small: each
 * Vercel Node function instance is single-threaded and Neon free-tier
 * connections are limited.
 */
export function resolveNeonConnectionString(
  env: Readonly<Record<string, string | undefined>> = process.env,
): string {
  const direct = env['DATABASE_URL'];
  if (typeof direct === 'string' && direct.trim() !== '') return direct.trim();
  const injected = env['POSTGRES_URL'];
  if (typeof injected === 'string' && injected.trim() !== '') return injected.trim();
  throw new Error(
    'A Neon connection string is required: set DATABASE_URL (preferred, System Design §8) or POSTGRES_URL.',
  );
}

function connectionFor(
  executor: {
    query<Row>(text: string, values?: unknown[]): Promise<{ readonly rows: Row[] }>;
  },
): SqlConnection {
  return {
    async query<Row extends Record<string, unknown>>(
      text: string,
      values?: readonly unknown[],
    ): Promise<SqlResult<Row>> {
      const result = await executor.query<Row>(
        text,
        values === undefined ? undefined : [...values],
      );
      return { rows: result.rows };
    },
  };
}

/** Neon-backed `TransactionalSqlDatabase`. Never use the PGlite adapter here. */
export class NeonAuthDatabase implements TransactionalSqlDatabase {
  private constructor(private readonly pool: Pool) {}

  static create(
    connectionString: string,
    options: { readonly max?: number } = {},
  ): NeonAuthDatabase {
    const pool = new Pool({
      connectionString,
      max: options.max ?? 2,
      connectionTimeoutMillis: 10_000,
      idleTimeoutMillis: 30_000,
    });
    // Pool errors (e.g. a stale socket after a frozen serverless instance
    // thaws) must not crash the function; the pool reconnects on next use.
    // Log only the event, never connection details.
    pool.on('error', () => {
      console.error(JSON.stringify({ level: 'error', event: 'neon_pool_error' }));
    });
    return new NeonAuthDatabase(pool);
  }

  /** Test-only seam: wrap an already-constructed pool (or a stub pool). */
  static fromPool(pool: Pool): NeonAuthDatabase {
    return new NeonAuthDatabase(pool);
  }

  async query<Row extends Record<string, unknown>>(
    text: string,
    values?: readonly unknown[],
  ): Promise<SqlResult<Row>> {
    return connectionFor(this.pool).query<Row>(text, values);
  }

  async transaction<T>(callback: (connection: SqlConnection) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      try {
        const result = await callback(connectionFor(client));
        await client.query('COMMIT');
        return result;
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      }
    } finally {
      client.release();
    }
  }

  /** Live connection count for `GET /v1/admin/overview` (`db_connections`). */
  get connectionCount(): number {
    return this.pool.totalCount;
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
