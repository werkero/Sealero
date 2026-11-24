import { createHash } from 'node:crypto';
import { ApiError } from '../app.js';
import { AuthServiceError } from '../auth/auth-service.js';
import type { AuthService } from '../auth/auth-service.js';
import { verifyLoginPassword } from '../auth/password.js';
import type { AuthStore, AuthTransaction, AuthUser, LoginRequestMetadata } from '../auth/types.js';
import type {
  AdminLoginHistoryEntry,
  AdminPage,
  AdminUserDetailBase,
  AdminUserListQuery,
  AdminUserReadStore,
  AdminUserSummary,
} from './types.js';

interface ServiceClock {
  now(): Date;
}

type UserMutationOutcome =
  | 'success'
  | 'not_found'
  | 'actor_missing'
  | 'actor_disabled'
  | 'forbidden'
  | 'action_forbidden';

type DeleteOutcome = UserMutationOutcome | 'invalid_password';

type AdminUserDetail = AdminUserDetailBase & {
  readonly login_history: AdminPage<AdminLoginHistoryEntry>;
};

function hasAdminRole(roles: readonly string[]): boolean {
  return roles.includes('admin') || roles.includes('super_admin');
}

function isSet(value: Date | string | null): boolean {
  return value !== null;
}

export class AdminUserService {
  private readonly clock: ServiceClock;

  constructor(
    private readonly store: AuthStore & AdminUserReadStore,
    private readonly authService: AuthService,
    now: () => Date = () => new Date(),
  ) {
    this.clock = { now };
  }

  listUsers(query: AdminUserListQuery): Promise<AdminPage<AdminUserSummary> | null> {
    return this.store.listAdminUsers(query);
  }

  async getUserDetail(
    userId: string,
    loginCursor: string | null,
    loginLimit: number,
  ): Promise<{ readonly kind: 'ok'; readonly value: AdminUserDetail } | { readonly kind: 'not_found' | 'invalid_cursor' }> {
    const base = await this.store.getAdminUser(userId);
    if (base === null) return { kind: 'not_found' };
    const loginHistory = await this.store.listAdminUserLoginHistory(userId, loginCursor, loginLimit);
    if (loginHistory === null) return { kind: 'invalid_cursor' };
    return { kind: 'ok', value: { ...base, login_history: loginHistory } };
  }

  async disableUser(actorId: string, targetId: string, ipAddress: string | null): Promise<void> {
    const now = this.clock.now();
    const outcome = await this.mutateUser(actorId, targetId, async (transaction, actor, target) => {
      if (!await transaction.setUserDisabledAt(target.id, now)) throw new Error('The locked target user disappeared.');
      await transaction.revokeAllDevices(target.id, now);
      await transaction.revokeAllRefreshTokensForAccountDisabled(target.id, now);
      await transaction.revokeAllOAuthAuthorizations(target.id, now);
      await transaction.insertAuditLog({
        actorUserId: actor.id,
        targetUserId: target.id,
        action: 'user_disable',
        targetType: 'user',
        metadata: JSON.stringify({}),
        ipAddress,
        createdAt: now,
      });
    }, { guardProtectedTarget: true });
    this.requireMutationSuccess(outcome);
  }

  async enableUser(actorId: string, targetId: string, ipAddress: string | null): Promise<void> {
    const now = this.clock.now();
    const outcome = await this.mutateUser(actorId, targetId, async (transaction, actor, target) => {
      if (!await transaction.setUserDisabledAt(target.id, null)) throw new Error('The locked target user disappeared.');
      await transaction.insertAuditLog({
        actorUserId: actor.id,
        targetUserId: target.id,
        action: 'user_enable',
        targetType: 'user',
        metadata: JSON.stringify({}),
        ipAddress,
        createdAt: now,
      });
    });
    this.requireMutationSuccess(outcome);
  }

  async deleteUser(
    actorId: string,
    targetId: string,
    loginPassword: string,
    metadata: LoginRequestMetadata,
  ): Promise<void> {
    const now = this.clock.now();
    let outcome: DeleteOutcome;
    try {
      outcome = await this.authService.withVerifiedSensitivePassword(
        actorId,
        loginPassword,
        metadata,
        async (transaction, initialActor) => {
        const users = await transaction.findUsersForUpdate([actorId, targetId]);
        const actor = users.find((user) => user.id === actorId) ?? null;
        if (actor === null) return 'actor_missing' as const;
        if (isSet(actor.disabledAt)) return 'actor_disabled' as const;
        const passwordStillMatches = actor.passwordHash === initialActor.passwordHash
          ? true
          : await verifyLoginPassword(actor.passwordHash, loginPassword);
        if (!passwordStillMatches) return 'invalid_password' as const;

        const actorRoles = await transaction.findUserRolesForUpdate(actorId);
        if (!hasAdminRole(actorRoles)) return 'forbidden' as const;
        const target = users.find((user) => user.id === targetId) ?? null;
        if (target === null) return 'not_found' as const;
        const targetRoles = targetId === actorId
          ? actorRoles
          : await transaction.findUserRolesForUpdate(targetId);
        const isProtectedTarget = targetRoles.includes('super_admin');
        const isAdminDeletingSelf = actorRoles.includes('admin') && !actorRoles.includes('super_admin') && actorId === targetId;
        if (isProtectedTarget || isAdminDeletingSelf) {
          await transaction.insertAuditLog({
            actorUserId: actorId,
            targetUserId: targetId,
            action: 'user_delete',
            targetType: 'user',
            metadata: JSON.stringify({}),
            ipAddress: metadata.ipAddress,
            createdAt: now,
          });
          return 'forbidden' as const;
        }

        await transaction.insertAuditLog({
          actorUserId: actorId,
          targetUserId: targetId,
          action: 'user_delete',
          targetType: 'user',
          metadata: JSON.stringify({}),
          ipAddress: metadata.ipAddress,
          createdAt: now,
        });
        await transaction.deleteAuthCodesForEmail(target.email);
        const emailKey = createHash('sha256').update(target.email, 'utf8').digest('hex');
        await transaction.deleteEmailRateLimits(emailKey);
        if (!await transaction.deleteUser(targetId)) throw new Error('The locked target user disappeared.');
        return 'success' as const;
        },
      );
    } catch (error) {
      if (error instanceof AuthServiceError) {
        throw new ApiError(error.status, error.code, error.message, error.retryAfterSeconds);
      }
      throw error;
    }
    this.requireDeleteSuccess(outcome);
  }

  /**
   * Revokes all of the target user's devices, refresh tokens and OAuth
   * authorizations (System Design §5.2). Unlike disableUser the account
   * stays enabled: the user can sign in again and the login endpoint creates
   * a new device. The super-admin/self guard matches deleteUser and
   * removeAdmin: a super_admin target is protected, and an admin (who is
   * not super_admin) cannot revoke their own devices.
   */
  async revokeAllDevices(
    actorId: string,
    targetId: string,
    loginPassword: string,
    metadata: LoginRequestMetadata,
  ): Promise<void> {
    const now = this.clock.now();
    let outcome: DeleteOutcome;
    try {
      outcome = await this.authService.withVerifiedSensitivePassword(
        actorId,
        loginPassword,
        metadata,
        async (transaction, initialActor) => {
          const users = await transaction.findUsersForUpdate([actorId, targetId]);
          const actor = users.find((user) => user.id === actorId) ?? null;
          if (actor === null) return 'actor_missing' as const;
          if (isSet(actor.disabledAt)) return 'actor_disabled' as const;
          const passwordStillMatches = actor.passwordHash === initialActor.passwordHash
            ? true
            : await verifyLoginPassword(actor.passwordHash, loginPassword);
          if (!passwordStillMatches) return 'invalid_password' as const;
          const actorRoles = await transaction.findUserRolesForUpdate(actorId);
          if (!hasAdminRole(actorRoles)) return 'forbidden' as const;
          const target = users.find((user) => user.id === targetId) ?? null;
          if (target === null) return 'not_found' as const;
          const targetRoles = targetId === actorId
            ? actorRoles
            : await transaction.findUserRolesForUpdate(targetId);
          const isProtectedTarget = targetRoles.includes('super_admin');
          const isAdminRevokingSelf = actorRoles.includes('admin') && !actorRoles.includes('super_admin') && actorId === targetId;
          if (isProtectedTarget || isAdminRevokingSelf) {
            await transaction.insertAuditLog({
              actorUserId: actor.id,
              targetUserId: target.id,
              action: 'device_revoke_all',
              targetType: 'user',
              // SD §5.2: device_revoke_all metadata is {target_user_id,
              // device_count}; a blocked attempt revokes 0 devices.
              metadata: JSON.stringify({ target_user_id: target.id, device_count: 0 }),
              ipAddress: metadata.ipAddress,
              createdAt: now,
            });
            return 'forbidden' as const;
          }
          const deviceCount = await transaction.revokeAllDevicesAndCount(target.id, now);
          await transaction.revokeAllUnrevokedRefreshTokens(target.id, now);
          await transaction.revokeAllOAuthAuthorizations(target.id, now);
          await transaction.insertAuditLog({
            actorUserId: actor.id,
            targetUserId: target.id,
            action: 'device_revoke_all',
            targetType: 'user',
            metadata: JSON.stringify({ target_user_id: target.id, device_count: deviceCount }),
            ipAddress: metadata.ipAddress,
            createdAt: now,
          });
          return 'success' as const;
        },
      );
    } catch (error) {
      if (error instanceof AuthServiceError) {
        throw new ApiError(error.status, error.code, error.message, error.retryAfterSeconds);
      }
      throw error;
    }
    if (outcome === 'success') return;
    if (outcome === 'not_found') throw new ApiError(404, 'user_not_found', 'The user was not found.');
    if (outcome === 'actor_missing') throw new ApiError(401, 'unauthorized', 'A valid access token is required.');
    if (outcome === 'actor_disabled') throw new ApiError(403, 'account_disabled', 'This account is disabled.');
    if (outcome === 'invalid_password') throw new ApiError(401, 'invalid_credentials', 'The login password is incorrect.');
    if (outcome === 'forbidden') throw new ApiError(403, 'admin_action_forbidden', 'This administrator action is not permitted.');
    throw new ApiError(403, 'admin_required', 'Administrator access is required.');
  }

  async makeAdmin(actorId: string, targetId: string, ipAddress: string | null): Promise<void> {
    const now = this.clock.now();
    const outcome = await this.mutateUser(actorId, targetId, async (transaction, actor, target) => {
      if (!await transaction.grantAdminRole(target.id, actor.id, now)) {
        throw new Error('The admin role is not configured.');
      }
      await transaction.insertAuditLog({
        actorUserId: actor.id,
        targetUserId: target.id,
        action: 'make_admin',
        targetType: 'user',
        metadata: JSON.stringify({}),
        ipAddress,
        createdAt: now,
      });
    });
    this.requireMutationSuccess(outcome);
  }

  async removeAdmin(actorId: string, targetId: string, ipAddress: string | null): Promise<void> {
    const now = this.clock.now();
    const outcome = await this.store.transaction(async (transaction) => {
      const users = await transaction.findUsersForUpdate([actorId, targetId]);
      const actor = users.find((user) => user.id === actorId) ?? null;
      if (actor === null) return 'actor_missing' as const;
      if (isSet(actor.disabledAt)) return 'actor_disabled' as const;
      const actorRoles = await transaction.findUserRolesForUpdate(actorId);
      if (!hasAdminRole(actorRoles)) return 'forbidden' as const;
      const target = users.find((user) => user.id === targetId) ?? null;
      if (target === null) return 'not_found' as const;
      const targetRoles = targetId === actorId
        ? actorRoles
        : await transaction.findUserRolesForUpdate(targetId);
      if (
        targetRoles.includes('super_admin') ||
        (actorRoles.includes('admin') && !actorRoles.includes('super_admin') && actorId === targetId)
      ) {
        return 'forbidden' as const;
      }
      await transaction.removeAdminRole(targetId);
      await transaction.insertAuditLog({
        actorUserId: actorId,
        targetUserId: targetId,
        action: 'remove_admin',
        targetType: 'user',
        metadata: JSON.stringify({}),
        ipAddress,
        createdAt: now,
      });
      return 'success' as const;
    });
    this.requireMutationSuccess(outcome);
  }

  async revokeDevice(actorId: string, deviceId: string, ipAddress: string | null): Promise<void> {
    const ownerId = await this.store.findAdminDeviceOwner(deviceId);
    if (ownerId === null) throw new ApiError(404, 'device_not_found', 'The device was not found.');
    const now = this.clock.now();
    const outcome = await this.store.transaction(async (transaction) => {
      const users = await transaction.findUsersForUpdate([actorId, ownerId]);
      const actor = users.find((user) => user.id === actorId) ?? null;
      if (actor === null) return 'actor_missing' as const;
      if (isSet(actor.disabledAt)) return 'actor_disabled' as const;
      const actorRoles = await transaction.findUserRolesForUpdate(actorId);
      if (!hasAdminRole(actorRoles)) return 'forbidden' as const;
      const owner = users.find((user) => user.id === ownerId) ?? null;
      if (owner === null) return 'not_found' as const;
      // Same guard as deleteUser / removeAdmin / revoke-all-devices: a
      // super_admin's devices are protected, and a plain admin cannot
      // revoke their own device. A single-device revoke otherwise
      // bypasses the revoke-all guard (it also revokes all of the
      // owner's OAuth authorizations).
      const ownerRoles = ownerId === actorId
        ? actorRoles
        : await transaction.findUserRolesForUpdate(ownerId);
      const isProtectedOwner = ownerRoles.includes('super_admin');
      const isAdminRevokingOwnDevice = actorRoles.includes('admin') && !actorRoles.includes('super_admin') && actorId === ownerId;
      if (isProtectedOwner || isAdminRevokingOwnDevice) return 'action_forbidden' as const;
      if (!await transaction.revokeUserDevice(ownerId, deviceId, now)) return 'not_found' as const;
      await transaction.revokeAllOAuthAuthorizations(ownerId, now);
      await transaction.insertAuditLog({
        actorUserId: actorId,
        targetUserId: ownerId,
        action: 'device_revoke',
        targetType: 'device',
        metadata: JSON.stringify({ device_id: deviceId }),
        ipAddress,
        createdAt: now,
      });
      return 'success' as const;
    });
    this.requireMutationSuccess(outcome);
  }

  private async mutateUser(
    actorId: string,
    targetId: string,
    mutation: (transaction: AuthTransaction, actor: AuthUser, target: AuthUser) => Promise<void>,
    options: { readonly guardProtectedTarget?: boolean } = {},
  ): Promise<UserMutationOutcome> {
    return this.store.transaction(async (transaction) => {
      const users = await transaction.findUsersForUpdate([actorId, targetId]);
      const actor = users.find((user) => user.id === actorId) ?? null;
      if (actor === null) return 'actor_missing';
      if (isSet(actor.disabledAt)) return 'actor_disabled';
      const actorRoles = await transaction.findUserRolesForUpdate(actorId);
      if (!hasAdminRole(actorRoles)) return 'forbidden';
      const target = users.find((user) => user.id === targetId) ?? null;
      if (target === null) return 'not_found';
      if (options.guardProtectedTarget === true) {
        // Same guard as deleteUser / removeAdmin / revoke-all-devices: a
        // super_admin target is protected, and a plain admin cannot act on
        // themselves. Without it, disableUser alone could lock out a
        // super_admin that the other guarded operations protect.
        const targetRoles = targetId === actorId
          ? actorRoles
          : await transaction.findUserRolesForUpdate(targetId);
        const isProtectedTarget = targetRoles.includes('super_admin');
        const isAdminActingOnSelf = actorRoles.includes('admin') && !actorRoles.includes('super_admin') && actorId === targetId;
        if (isProtectedTarget || isAdminActingOnSelf) return 'action_forbidden';
      }
      await mutation(transaction, actor, target);
      return 'success';
    });
  }

  private requireMutationSuccess(outcome: UserMutationOutcome): void {
    if (outcome === 'success') return;
    if (outcome === 'not_found') throw new ApiError(404, 'user_not_found', 'The user was not found.');
    if (outcome === 'actor_missing') throw new ApiError(401, 'unauthorized', 'A valid access token is required.');
    if (outcome === 'actor_disabled') throw new ApiError(403, 'account_disabled', 'This account is disabled.');
    if (outcome === 'action_forbidden') throw new ApiError(403, 'admin_action_forbidden', 'This administrator action is not permitted.');
    throw new ApiError(403, 'admin_required', 'Administrator access is required.');
  }

  private requireDeleteSuccess(outcome: DeleteOutcome): void {
    if (outcome === 'success') return;
    if (outcome === 'not_found') throw new ApiError(404, 'user_not_found', 'The user was not found.');
    if (outcome === 'actor_missing') throw new ApiError(401, 'unauthorized', 'A valid access token is required.');
    if (outcome === 'actor_disabled') throw new ApiError(403, 'account_disabled', 'This account is disabled.');
    if (outcome === 'invalid_password') throw new ApiError(401, 'invalid_credentials', 'The login password is incorrect.');
    throw new ApiError(403, 'admin_action_forbidden', 'This administrator action is not permitted.');
  }
}
