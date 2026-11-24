import type { MiddlewareHandler } from 'hono';
import type { JwtKeySet } from '../auth/jwt.js';
import { InvalidAccessTokenError, verifyAccessToken } from '../auth/jwt.js';
import type { AccessClaims, AuthStore } from '../auth/types.js';

export interface AuthenticatedVariables {
  auth: AccessClaims;
}

export interface AuthenticatedEnvironment {
  Variables: AuthenticatedVariables;
}

/** Verifies the signed token and performs a fresh joined account/device status read per request. */
export function requireAccessToken(
  keys: JwtKeySet,
  store: AuthStore,
  now: () => Date = () => new Date(),
): MiddlewareHandler<AuthenticatedEnvironment> {
  return async (context, next) => {
    const authorization = context.req.header('authorization');
    if (authorization === undefined || !authorization.startsWith('Bearer ')) {
      return context.json({ code: 'unauthorized', message: 'A valid access token is required.' }, 401);
    }

    let claims: AccessClaims;
    try {
      claims = verifyAccessToken(keys, authorization.slice('Bearer '.length), now());
    } catch (error) {
      if (error instanceof InvalidAccessTokenError) {
        return context.json({ code: 'unauthorized', message: 'A valid access token is required.' }, 401);
      }
      throw error;
    }

    const owner = await store.getAccessOwnerStatus(claims.sub, claims.device_id);
    if (owner === null) {
      return context.json({ code: 'unauthorized', message: 'A valid access token is required.' }, 401);
    }
    if (owner.deviceRevokedAt !== null) {
      return context.json({ code: 'device_revoked', message: 'This device has been revoked.' }, 401);
    }
    if (owner.accountDisabledAt !== null) {
      return context.json({ code: 'account_disabled', message: 'This account is disabled.' }, 403);
    }

    context.set('auth', claims);
    await next();
    return;
  };
}
