import type { Context } from 'hono';
import { ApiError } from '../app.js';
import type { AuthenticatedEnvironment } from '../middleware/authentication.js';
import type { AdminRoleStore } from './types.js';

/** Throws 403 `admin_required` unless the caller holds the permission (SD §5.2). */
export async function requirePermission(
  store: Pick<AdminRoleStore, 'hasPermission'>,
  context: Context<AuthenticatedEnvironment>,
  permissionKey: string,
): Promise<void> {
  const allowed = await store.hasPermission(context.get('auth').sub, permissionKey);
  if (!allowed) throw new ApiError(403, 'admin_required', `Permission ${permissionKey} is required.`);
}
