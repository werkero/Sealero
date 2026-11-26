import { describe, expect, it, vi } from 'vitest';
import type { Pool } from '@neondatabase/serverless';
import { NeonAuthDatabase, resolveNeonConnectionString } from '../db/neon-store.js';

interface StubClient {
  query(text: string, values?: unknown[]): Promise<{ readonly rows: readonly unknown[] }>;
  release(): void;
}

function createStubPool() {
  const poolCalls: Array<{ text: string; values: readonly unknown[] | undefined }> = [];
  const clientCalls: string[] = [];
  const released: string[] = [];
  const client: StubClient = {
    async query(text: string) {
      clientCalls.push(text);
      return { rows: [] };
    },
    release(): void {
      released.push('released');
    },
  };
  const pool = {
    async query(text: string, values?: unknown[]) {
      poolCalls.push({ text, values });
      return { rows: [{ echo: text }] };
    },
    async connect(): Promise<StubClient> {
      return client;
    },
    end: vi.fn(async () => undefined),
    on: (): void => undefined,
    totalCount: 3,
  };
  return { pool, client, poolCalls, clientCalls, released };
}

describe('resolveNeonConnectionString', () => {
  it('prefers DATABASE_URL', () => {
    expect(resolveNeonConnectionString({
      DATABASE_URL: 'postgresql://db.example/db',
      POSTGRES_URL: 'postgresql://pooler.example/db',
    })).toBe('postgresql://db.example/db');
  });

  it('falls back to POSTGRES_URL (Vercel Marketplace injection)', () => {
    expect(resolveNeonConnectionString({
      POSTGRES_URL: 'postgresql://pooler.example/db',
    })).toBe('postgresql://pooler.example/db');
  });

  it('throws when neither is set', () => {
    expect(() => resolveNeonConnectionString({})).toThrow('DATABASE_URL');
  });
});

describe('NeonAuthDatabase', () => {
  it('passes queries through to the pool and returns rows', async () => {
    const { pool, poolCalls } = createStubPool();
    const database = NeonAuthDatabase.fromPool(pool as unknown as Pool);
    const result = await database.query<{ echo: string }>(
      'SELECT $1 AS echo',
      ['hello'],
    );
    expect(result.rows).toEqual([{ echo: 'SELECT $1 AS echo' }]);
    expect(poolCalls).toEqual([{ text: 'SELECT $1 AS echo', values: ['hello'] }]);
  });

  it('runs callback transactions with BEGIN/COMMIT and releases the client', async () => {
    const { pool, clientCalls, released } = createStubPool();
    const database = NeonAuthDatabase.fromPool(pool as unknown as Pool);
    const value = await database.transaction(async (connection) => {
      const result = await connection.query<{ echo: string }>('SELECT 1');
      return result.rows.length;
    });
    expect(value).toBe(0);
    expect(clientCalls).toEqual(['BEGIN', 'SELECT 1', 'COMMIT']);
    expect(released).toEqual(['released']);
  });

  it('rolls back and still releases when the callback throws', async () => {
    const { pool, clientCalls, released } = createStubPool();
    const database = NeonAuthDatabase.fromPool(pool as unknown as Pool);
    await expect(database.transaction(async (connection) => {
      await connection.query('SELECT 1');
      throw new Error('boom');
    })).rejects.toThrow('boom');
    expect(clientCalls).toEqual(['BEGIN', 'SELECT 1', 'ROLLBACK']);
    expect(released).toEqual(['released']);
  });

  it('reports the live pool size and closes the pool', async () => {
    const { pool } = createStubPool();
    const database = NeonAuthDatabase.fromPool(pool as unknown as Pool);
    expect(database.connectionCount).toBe(3);
    await database.close();
    expect(pool.end).toHaveBeenCalledOnce();
  });
});
