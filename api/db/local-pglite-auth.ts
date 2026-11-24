import { readFileSync } from 'node:fs';
import { PGlite } from '@electric-sql/pglite';
import { pgcrypto } from '@electric-sql/pglite/contrib/pgcrypto';
import type { SqlConnection, SqlResult, TransactionalSqlDatabase } from './auth-store.js';

interface PgliteQueryExecutor {
  query<Row>(text: string, values?: unknown[]): Promise<{ readonly rows: Row[] }>;
}

function sqlValues(values: readonly unknown[] | undefined): unknown[] | undefined {
  if (values === undefined) return undefined;
  return values.map((value) => value instanceof Date ? value.toISOString() : value);
}

function connectionFor(executor: PgliteQueryExecutor): SqlConnection {
  return {
    async query<Row extends Record<string, unknown>>(
      text: string,
      values?: readonly unknown[],
    ): Promise<SqlResult<Row>> {
      const result = await executor.query<Row>(text, sqlValues(values));
      return { rows: result.rows };
    },
  };
}

/** Ephemeral local-only database; never use this adapter from a deployment entry. */
export class LocalPGliteAuthDatabase implements TransactionalSqlDatabase {
  private constructor(private readonly database: PGlite) {}

  static async create(): Promise<LocalPGliteAuthDatabase> {
    const database = new PGlite({ extensions: { pgcrypto } });
    try {
      const schema = readFileSync(new URL('./schema.sql', import.meta.url), 'utf8');
      await database.exec(schema);
      return new LocalPGliteAuthDatabase(database);
    } catch (error) {
      await database.close();
      throw error;
    }
  }

  async query<Row extends Record<string, unknown>>(
    text: string,
    values?: readonly unknown[],
  ): Promise<SqlResult<Row>> {
    return connectionFor(this.database).query<Row>(text, values);
  }

  async transaction<T>(callback: (connection: SqlConnection) => Promise<T>): Promise<T> {
    return this.database.transaction((transaction) => callback(connectionFor(transaction)));
  }

  async close(): Promise<void> {
    await this.database.close();
  }
}
