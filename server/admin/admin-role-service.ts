import { ApiError } from '../app.js';
import type { AuthStore, AuthTransaction } from '../auth/types.js';
import type {
  AdminPage,
  AdminPermission,
  AdminRole,
  AdminRoleMutationOutcome,
  AdminRoleStore,
  AdminUserReadStore,
  AdminUserSummary,
} from './types.js';

const SYSTEM_ROLE_NAMES = ['admin', 'user', 'super_admin'] as const;
const ROLE_NAME_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;
const MAX_DESCRIPTION_LENGTH = 200;

function isSystemRole(name: string): boolean {
  return (SYSTEM_ROLE_NAMES as readonly string[]).includes(name);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export interface AdminRoleCreateInput {
  readonly name: string;
  readonly description: string | null;
  readonly permissionKeys: readonly string[];
}

export interface AdminRoleUpdateInput {
  readonly description?: string | null;
  readonly permissionKeys?: readonly string[];
}

export class AdminRoleService {
  constructor(private readonly store: AuthStore & AdminRoleStore & AdminUserReadStore) {}

  listRoles(): Promise<readonly AdminRole[]> {
    return this.store.listRoles();
  }

  listPermissions(): Promise<readonly AdminPermission[]> {
    return this.store.listPermissions();
  }

  getMyPermissions(userId: string): Promise<readonly string[]> {
    return this.store.getUserPermissions(userId);
  }

  async listRoleUsers(
    roleId: string,
    cursor: string | null,
    limit: number,
  ): Promise<{ readonly kind: 'ok'; readonly value: AdminPage<AdminUserSummary> } | { readonly kind: 'not_found' | 'invalid_cursor' }> {
    const role = await this.store.getRole(roleId);
    if (role === null) return { kind: 'not_found' };
    const page = await this.store.listRoleUsers(roleId, cursor, limit);
    if (page === null) return { kind: 'invalid_cursor' };
    return { kind: 'ok', value: page };
  }

  async createRole(actorId: string, ipAddress: string | null, input: unknown): Promise<AdminRole> {
    const parsed = this.parseCreateInput(input);
    const catalog = new Set((await this.store.listPermissions()).map((permission) => permission.key));
    if (parsed.permissionKeys.some((key) => !catalog.has(key))) {
      throw new ApiError(400, 'invalid_request', 'Unknown permission key.');
    }
    const now = new Date();
    let roleId: string | null = null;
    const outcome = await this.store.transaction(async (transaction) => {
      const actorOutcome = await this.checkActor(transaction, actorId);
      if (actorOutcome !== 'success') return actorOutcome;
      const existing = await transaction.findRoleByNameForUpdate(parsed.name);
      if (existing !== null) return 'name_taken' as const;
      roleId = await transaction.insertRole(parsed.name, parsed.description);
      await transaction.setRolePermissions(roleId, parsed.permissionKeys, actorId);
      await transaction.insertAuditLog({
        actorUserId: actorId,
        targetUserId: null,
        action: 'role_create',
        targetType: 'role',
        metadata: JSON.stringify({ role_id: roleId, role_name: parsed.name, permission_keys: parsed.permissionKeys }),
        ipAddress,
        createdAt: now,
      });
      return 'success' as const;
    });
    this.requireOutcome(outcome);
    const role = roleId === null ? null : await this.store.getRole(roleId);
    if (role === null) throw new Error('The created role was not found.');
    return role;
  }

  async updateRole(actorId: string, roleId: string, ipAddress: string | null, input: unknown): Promise<AdminRole> {
    const parsed = this.parseUpdateInput(input);
    if (parsed.permissionKeys !== undefined) {
      const catalog = new Set((await this.store.listPermissions()).map((permission) => permission.key));
      if (parsed.permissionKeys.some((key) => !catalog.has(key))) {
        throw new ApiError(400, 'invalid_request', 'Unknown permission key.');
      }
    }
    const now = new Date();
    const outcome = await this.store.transaction(async (transaction) => {
      const actorOutcome = await this.checkActor(transaction, actorId);
      if (actorOutcome !== 'success') return actorOutcome;
      const role = await transaction.findRoleForUpdate(roleId);
      if (role === null) return 'not_found' as const;
      if (role.name === 'super_admin') return 'action_forbidden' as const;
      if (parsed.description !== undefined) {
        await transaction.updateRoleDescription(roleId, parsed.description);
      }
      if (parsed.permissionKeys !== undefined) {
        await transaction.setRolePermissions(roleId, parsed.permissionKeys, actorId);
      }
      const metadata: Record<string, unknown> = { role_id: roleId, role_name: role.name };
      if (parsed.permissionKeys !== undefined) metadata['permission_keys'] = parsed.permissionKeys;
      await transaction.insertAuditLog({
        actorUserId: actorId,
        targetUserId: null,
        action: 'role_update',
        targetType: 'role',
        metadata: JSON.stringify(metadata),
        ipAddress,
        createdAt: now,
      });
      return 'success' as const;
    });
    this.requireOutcome(outcome);
    const role = await this.store.getRole(roleId);
    if (role === null) throw new Error('The updated role was not found.');
    return role;
  }

  async deleteRole(actorId: string, roleId: string, ipAddress: string | null): Promise<void> {
    const now = new Date();
    const outcome = await this.store.transaction(async (transaction) => {
      const actorOutcome = await this.checkActor(transaction, actorId);
      if (actorOutcome !== 'success') return actorOutcome;
      const role = await transaction.findRoleForUpdate(roleId);
      if (role === null) return 'not_found' as const;
      if (isSystemRole(role.name)) return 'action_forbidden' as const;
      await transaction.deleteRoleById(roleId);
      await transaction.insertAuditLog({
        actorUserId: actorId,
        targetUserId: null,
        action: 'role_delete',
        targetType: 'role',
        metadata: JSON.stringify({ role_id: roleId, role_name: role.name }),
        ipAddress,
        createdAt: now,
      });
      return 'success' as const;
    });
    this.requireOutcome(outcome);
  }

  async assignRole(
    actorId: string,
    roleId: string,
    userId: string,
    ipAddress: string | null,
  ): Promise<{ readonly role: AdminRole; readonly user: AdminUserSummary }> {
    const now = new Date();
    const outcome = await this.store.transaction(async (transaction) => {
      const actorOutcome = await this.checkActor(transaction, actorId);
      if (actorOutcome !== 'success') return actorOutcome;
      const role = await transaction.findRoleForUpdate(roleId);
      if (role === null) return 'not_found' as const;
      if (role.name === 'super_admin') return 'action_forbidden' as const;
      if (actorId === userId) return 'action_forbidden' as const;
      const target = await transaction.findUserForUpdate(userId);
      if (target === null) return 'target_missing' as const;
      const granted = await transaction.assignUserRole(userId, roleId, actorId, now);
      if (granted) {
        await transaction.insertAuditLog({
          actorUserId: actorId,
          targetUserId: userId,
          action: 'role_assign',
          targetType: 'user',
          metadata: JSON.stringify({ role_id: roleId, role_name: role.name }),
          ipAddress,
          createdAt: now,
        });
      }
      return 'success' as const;
    });
    this.requireOutcome(outcome);
    const role = await this.store.getRole(roleId);
    const detail = await this.store.getAdminUser(userId);
    if (role === null || detail === null) throw new Error('The assigned role or user was not found.');
    return { role, user: detail.user };
  }

  async removeRole(actorId: string, roleId: string, userId: string, ipAddress: string | null): Promise<void> {
    const now = new Date();
    const outcome = await this.store.transaction(async (transaction) => {
      const actorOutcome = await this.checkActor(transaction, actorId);
      if (actorOutcome !== 'success') return actorOutcome;
      const role = await transaction.findRoleForUpdate(roleId);
      if (role === null) return 'not_found' as const;
      if (role.name === 'super_admin') return 'action_forbidden' as const;
      if (actorId === userId) return 'action_forbidden' as const;
      const target = await transaction.findUserForUpdate(userId);
      if (target === null) return 'target_missing' as const;
      const removed = await transaction.removeUserRole(userId, roleId);
      if (removed) {
        await transaction.insertAuditLog({
          actorUserId: actorId,
          targetUserId: userId,
          action: 'role_remove',
          targetType: 'user',
          metadata: JSON.stringify({ role_id: roleId, role_name: role.name }),
          ipAddress,
          createdAt: now,
        });
      }
      return 'success' as const;
    });
    this.requireOutcome(outcome);
  }

  private async checkActor(
    transaction: AuthTransaction,
    actorId: string,
  ): Promise<'success' | 'actor_missing' | 'actor_disabled' | 'forbidden'> {
    const actor = await transaction.findUserForUpdate(actorId);
    if (actor === null) return 'actor_missing';
    if (actor.disabledAt !== null) return 'actor_disabled';
    const permissions = await transaction.findUserPermissionsForUpdate(actorId);
    return permissions.includes('roles:manage') ? 'success' : 'forbidden';
  }

  private requireOutcome(outcome: AdminRoleMutationOutcome): void {
    if (outcome === 'success') return;
    if (outcome === 'not_found') throw new ApiError(404, 'role_not_found', 'The role was not found.');
    if (outcome === 'target_missing') throw new ApiError(404, 'user_not_found', 'The user was not found.');
    if (outcome === 'actor_missing') throw new ApiError(401, 'unauthorized', 'A valid access token is required.');
    if (outcome === 'actor_disabled') throw new ApiError(403, 'account_disabled', 'This account is disabled.');
    if (outcome === 'action_forbidden') throw new ApiError(403, 'admin_action_forbidden', 'This administrator action is not permitted.');
    if (outcome === 'invalid_name') throw new ApiError(400, 'invalid_request', 'The role name is invalid.');
    if (outcome === 'name_taken') throw new ApiError(400, 'invalid_request', 'The role name is already taken.');
    if (outcome === 'invalid_permissions') throw new ApiError(400, 'invalid_request', 'Unknown permission key.');
    throw new ApiError(403, 'admin_required', 'Administrator access is required.');
  }

  private parseCreateInput(input: unknown): AdminRoleCreateInput {
    if (!isRecord(input) || Object.keys(input).some((key) => key !== 'name' && key !== 'description' && key !== 'permission_keys')) {
      throw new ApiError(400, 'invalid_request', 'The role request body is invalid.');
    }
    const name = input['name'];
    if (typeof name !== 'string' || !ROLE_NAME_PATTERN.test(name) || isSystemRole(name)) {
      throw new ApiError(400, 'invalid_request', 'The role name is invalid.');
    }
    const description = input['description'] === undefined ? null : input['description'];
    if (description !== null && (typeof description !== 'string' || description.length > MAX_DESCRIPTION_LENGTH)) {
      throw new ApiError(400, 'invalid_request', 'The role description is invalid.');
    }
    const permissionKeys = input['permission_keys'];
    if (!Array.isArray(permissionKeys) || permissionKeys.some((key) => typeof key !== 'string')) {
      throw new ApiError(400, 'invalid_request', 'permission_keys must be an array of permission keys.');
    }
    return { name, description, permissionKeys };
  }

  private parseUpdateInput(input: unknown): AdminRoleUpdateInput {
    if (!isRecord(input) || Object.keys(input).some((key) => key !== 'description' && key !== 'permission_keys')) {
      throw new ApiError(400, 'invalid_request', 'The role request body is invalid.');
    }
    const parsed: { description?: string | null; permissionKeys?: readonly string[] } = {};
    if (input['description'] !== undefined) {
      if (input['description'] !== null && (typeof input['description'] !== 'string' || (input['description'] as string).length > MAX_DESCRIPTION_LENGTH)) {
        throw new ApiError(400, 'invalid_request', 'The role description is invalid.');
      }
      parsed.description = input['description'] as string | null;
    }
    if (input['permission_keys'] !== undefined) {
      if (!Array.isArray(input['permission_keys']) || (input['permission_keys'] as unknown[]).some((key) => typeof key !== 'string')) {
        throw new ApiError(400, 'invalid_request', 'permission_keys must be an array of permission keys.');
      }
      parsed.permissionKeys = input['permission_keys'] as readonly string[];
    }
    return parsed;
  }
}
