import { hashLoginPassword } from './auth/password.js';
import type { LocalPGliteAuthDatabase } from './db/local-pglite-auth.js';

/**
 * Local-development admin bootstrap (local dev only — server.ts refuses to
 * run in production, and deployment never seeds roles or accounts).
 *
 * Registration grants no roles (System Design §3.1: the official cloud's
 * admins are provisioned by the operator), so a fresh local database has no
 * way to reach the admin console. Seeding the three role rows makes
 * make-admin work at all; when SEALERO_LOCAL_DEV_ADMIN_EMAIL and
 * SEALERO_LOCAL_DEV_ADMIN_PASSWORD are both set, that account is created
 * (verified, so it can log in immediately) and granted super_admin + admin.
 * An existing account with the same email keeps its own password — the seed
 * never overwrites credentials. Without both variables no admin is created.
 */
export async function seedLocalDevelopmentAdmin(database: LocalPGliteAuthDatabase): Promise<void> {
  await database.query(
    `INSERT INTO roles (name) VALUES ('admin'), ('user'), ('super_admin')
     ON CONFLICT (name) DO NOTHING`,
  );

  const email = process.env['SEALERO_LOCAL_DEV_ADMIN_EMAIL'];
  const password = process.env['SEALERO_LOCAL_DEV_ADMIN_PASSWORD'];
  if (email === undefined && password === undefined) {
    console.info(JSON.stringify({
      level: 'info',
      event: 'local_dev_admin_not_seeded',
      note: 'Set SEALERO_LOCAL_DEV_ADMIN_EMAIL and SEALERO_LOCAL_DEV_ADMIN_PASSWORD to bootstrap a local admin.',
    }));
    return;
  }
  if (email === undefined || password === undefined) {
    throw new Error('SEALERO_LOCAL_DEV_ADMIN_EMAIL and SEALERO_LOCAL_DEV_ADMIN_PASSWORD must be set together.');
  }
  const normalizedEmail = email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail) || normalizedEmail.length > 255) {
    throw new Error('SEALERO_LOCAL_DEV_ADMIN_EMAIL must be a valid email address.');
  }
  if (password.length < 8) {
    throw new Error('SEALERO_LOCAL_DEV_ADMIN_PASSWORD must be at least 8 characters.');
  }
  if (Buffer.byteLength(password, 'utf8') > 4096) {
    throw new Error('SEALERO_LOCAL_DEV_ADMIN_PASSWORD must be at most 4096 bytes.');
  }
  const passwordHash = await hashLoginPassword(password);
  const created = await database.query<{ id: string }>(
    `INSERT INTO users (email, login_password_hash, email_verified_at)
     VALUES ($1, $2, now())
     ON CONFLICT (email) DO NOTHING
     RETURNING id`,
    [normalizedEmail, passwordHash],
  );
  let userId = created.rows[0]?.id;
  const createdAccount = userId !== undefined;
  if (userId === undefined) {
    const existing = await database.query<{ id: string }>(
      'SELECT id FROM users WHERE email = $1',
      [normalizedEmail],
    );
    userId = existing.rows[0]?.id;
    if (userId === undefined) throw new Error('Could not create or find the local development admin account.');
  }
  await database.query(
    `INSERT INTO user_roles (user_id, role_id, assigned_at, assigned_by)
     SELECT $1, r.id, now(), NULL FROM roles r WHERE r.name IN ('admin', 'super_admin')
     ON CONFLICT (user_id, role_id) DO NOTHING`,
    [userId],
  );
  console.info(JSON.stringify({
    level: 'info',
    event: 'local_dev_admin_seeded',
    email: normalizedEmail,
    created_account: createdAccount,
  }));
}
