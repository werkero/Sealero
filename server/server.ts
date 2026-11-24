import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { serve } from '@hono/node-server';
import { createAuthenticatedApp } from './auth/app.js';
import type { JwtKeySet, PublicJwk } from './auth/jwt.js';
import { loadConfig } from './config.js';
import { LocalPGliteAuthDatabase } from './db/local-pglite-auth.js';
import { SqlAuthStore } from './db/auth-store.js';
import type { AuthNotification } from './auth/types.js';
import { seedLocalDevelopmentAdmin } from './seed-local-development-admin.js';

const LOCAL_DEVELOPMENT_HOST = '127.0.0.1';
const LOCAL_DEVELOPMENT_PORT = 3000;
const LOCAL_DEVELOPMENT_SITE_ORIGIN = `http://${LOCAL_DEVELOPMENT_HOST}:${LOCAL_DEVELOPMENT_PORT}`;

function createEphemeralJwtKeys(): JwtKeySet {
  const pair = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 0x10001 });
  const exported = pair.publicKey.export({ format: 'jwk' });
  if (typeof exported.n !== 'string' || typeof exported.e !== 'string') {
    throw new Error('Could not create local JWT public key.');
  }
  const activeKid = `local-dev-${randomBytes(8).toString('hex')}`;
  const jwk: PublicJwk = {
    kty: 'RSA',
    use: 'sig',
    alg: 'RS256',
    kid: activeKid,
    n: exported.n,
    e: exported.e,
  };
  return {
    activeKid,
    issuer: 'https://localhost:3000',
    privateKey: pair.privateKey,
    publicKeys: new Map([[activeKid, pair.publicKey]]),
    jwks: { keys: [jwk] },
  };
}

const localOnlyNotifications: AuthNotification = {
  async sendVerificationCode(): Promise<void> {
    console.info(JSON.stringify({ level: 'info', event: 'local_fake_notification', kind: 'verification_code' }));
  },
  async sendPasswordResetCode(): Promise<void> {
    console.info(JSON.stringify({ level: 'info', event: 'local_fake_notification', kind: 'password_reset_code' }));
  },
  async sendDeleteAccountCode(): Promise<void> {
    console.info(JSON.stringify({ level: 'info', event: 'local_fake_notification', kind: 'delete_account_code' }));
  },
  async sendNewDeviceLogin(): Promise<void> {
    console.info(JSON.stringify({ level: 'info', event: 'local_fake_notification', kind: 'new_device' }));
  },
  async sendRefreshReuseAlert(): Promise<void> {
    console.info(JSON.stringify({ level: 'info', event: 'local_fake_notification', kind: 'refresh_reuse' }));
  },
};

async function startLocalDevelopmentServer(): Promise<void> {
  if (process.env['NODE_ENV'] === 'production' || process.env['SEALERO_LOCAL_DEV_AUTH'] !== '1') {
    throw new Error('The PGlite authentication server is local-only; use an injected production runtime for deployment.');
  }

  const database = await LocalPGliteAuthDatabase.create();
  try {
    await seedLocalDevelopmentAdmin(database);
    const app = createAuthenticatedApp(loadConfig(), {
      store: new SqlAuthStore(database),
      jwtKeys: createEphemeralJwtKeys(),
      notifications: localOnlyNotifications,
      authCodeHmacSecret: randomBytes(32).toString('base64url'),
      // Ephemeral dump key for local development only; deployment loads
      // DB_DUMP_KEY from the environment (System Design §5.2, §8).
      dbDumpKey: randomBytes(32),
      policyVersion: 'local-development',
      siteOrigin: LOCAL_DEVELOPMENT_SITE_ORIGIN,
      allowInsecureHttp: true,
    });
    const server = serve({
      fetch: app.fetch,
      hostname: LOCAL_DEVELOPMENT_HOST,
      port: LOCAL_DEVELOPMENT_PORT,
    }, (info) => {
      console.info(JSON.stringify({
        level: 'info',
        event: 'local_pglite_auth_server_started',
        host: LOCAL_DEVELOPMENT_HOST,
        port: info.port,
        note: 'Ephemeral PGlite database and JWT key; notifications are faked.',
      }));
    });

    const shutdown = async (): Promise<void> => {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
      await database.close();
    };
    process.once('SIGINT', () => {
      void shutdown().catch(() => {
        process.exitCode = 1;
      });
    });
    process.once('SIGTERM', () => {
      void shutdown().catch(() => {
        process.exitCode = 1;
      });
    });
  } catch (error) {
    await database.close();
    throw error;
  }
}

void startLocalDevelopmentServer().catch(() => {
  console.error(JSON.stringify({ level: 'error', event: 'local_auth_server_startup_failed' }));
  process.exitCode = 1;
});
