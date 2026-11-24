import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { verifyLoginPassword } from '../auth/password.js';
import { LocalPGliteAuthDatabase } from '../db/local-pglite-auth.js';
import { seedLocalDevelopmentAdmin } from '../seed-local-development-admin.js';

// Local-dev admin bootstrap: env-gated, never runs in production.
const EMAIL = 'admin@example.test';
const PASSWORD = 'local-dev-admin-password';

const openDatabases: LocalPGliteAuthDatabase[] = [];

async function createDatabase(): Promise<LocalPGliteAuthDatabase> {
  const database = await LocalPGliteAuthDatabase.create();
  openDatabases.push(database);
  return database;
}

async function userRow(database: LocalPGliteAuthDatabase, email: string) {
  const result = await database.query<{ id: string; login_password_hash: string; email_verified_at: Date | null }>(
    'SELECT id, login_password_hash, email_verified_at FROM users WHERE email = $1',
    [email.toLowerCase()],
  );
  return result.rows[0] ?? null;
}

async function roleNames(database: LocalPGliteAuthDatabase, userId: string): Promise<string[]> {
  const result = await database.query<{ name: string }>(
    `SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id
     WHERE ur.user_id = $1 ORDER BY r.name`,
    [userId],
  );
  return result.rows.map((row) => row.name);
}

function setSeedEnv(email: string | undefined, password: string | undefined): void {
  if (email === undefined) delete process.env['SEALERO_LOCAL_DEV_ADMIN_EMAIL'];
  else process.env['SEALERO_LOCAL_DEV_ADMIN_EMAIL'] = email;
  if (password === undefined) delete process.env['SEALERO_LOCAL_DEV_ADMIN_PASSWORD'];
  else process.env['SEALERO_LOCAL_DEV_ADMIN_PASSWORD'] = password;
}

describe('seedLocalDevelopmentAdmin', () => {
  const savedEmail = process.env['SEALERO_LOCAL_DEV_ADMIN_EMAIL'];
  const savedPassword = process.env['SEALERO_LOCAL_DEV_ADMIN_PASSWORD'];

  beforeEach(() => {
    vi.spyOn(console, 'info').mockImplementation(() => undefined);
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    setSeedEnv(savedEmail, savedPassword);
    await Promise.all(openDatabases.splice(0).map((database) => database.close()));
  });

  it('seeds the three roles and creates nothing when neither variable is set', async () => {
    const database = await createDatabase();
    setSeedEnv(undefined, undefined);

    await seedLocalDevelopmentAdmin(database);

    const roles = await database.query<{ name: string }>('SELECT name FROM roles ORDER BY name');
    expect(roles.rows.map((row) => row.name)).toEqual(['admin', 'super_admin', 'user']);
    expect(await userRow(database, EMAIL)).toBeNull();
  });

  it('throws when only the email is set', async () => {
    const database = await createDatabase();
    setSeedEnv(EMAIL, undefined);

    await expect(seedLocalDevelopmentAdmin(database))
      .rejects.toThrow('must be set together');
  });

  it('throws when only the password is set', async () => {
    const database = await createDatabase();
    setSeedEnv(undefined, PASSWORD);

    await expect(seedLocalDevelopmentAdmin(database))
      .rejects.toThrow('must be set together');
  });

  it('throws on an invalid email', async () => {
    const database = await createDatabase();
    setSeedEnv('not-an-email', PASSWORD);

    await expect(seedLocalDevelopmentAdmin(database))
      .rejects.toThrow('must be a valid email address');
  });

  it('throws on a password shorter than 8 characters', async () => {
    const database = await createDatabase();
    setSeedEnv(EMAIL, 'short7!');

    await expect(seedLocalDevelopmentAdmin(database))
      .rejects.toThrow('at least 8 characters');
  });

  it('throws on a password over 4096 bytes', async () => {
    const database = await createDatabase();
    setSeedEnv(EMAIL, 'a'.repeat(4097));

    await expect(seedLocalDevelopmentAdmin(database))
      .rejects.toThrow('at most 4096 bytes');
  });

  it('creates a verified admin + super_admin account, and accepts exactly 4096 bytes', async () => {
    const database = await createDatabase();
    const boundaryPassword = 'é'.repeat(2048); // 2 bytes each = exactly 4096 bytes
    setSeedEnv(EMAIL, boundaryPassword);

    await seedLocalDevelopmentAdmin(database);

    const user = await userRow(database, EMAIL);
    expect(user).not.toBeNull();
    expect(user?.email_verified_at).not.toBeNull();
    expect(await roleNames(database, user!.id)).toEqual(['admin', 'super_admin']);
    expect(await verifyLoginPassword(user!.login_password_hash, boundaryPassword)).toBe(true);
  });

  it('keeps the existing password when the account already exists', async () => {
    const database = await createDatabase();
    setSeedEnv(EMAIL, PASSWORD);
    await seedLocalDevelopmentAdmin(database);
    const first = await userRow(database, EMAIL);
    expect(first).not.toBeNull();

    setSeedEnv(EMAIL, 'a-completely-different-password');
    await seedLocalDevelopmentAdmin(database);

    const second = await userRow(database, EMAIL);
    expect(second?.id).toBe(first?.id);
    expect(second?.login_password_hash).toBe(first?.login_password_hash);
    expect(await verifyLoginPassword(second!.login_password_hash, PASSWORD)).toBe(true);
    expect(await verifyLoginPassword(second!.login_password_hash, 'a-completely-different-password')).toBe(false);
  });
});
