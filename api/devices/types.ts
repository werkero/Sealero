import type { DeviceListCursor } from './cursor.js';

export interface DeviceRevocationStore {
  /** Revokes an owned device, its active refresh tokens, and all OAuth authorizations for its user in one transaction. */
  revokeDevice(userId: string, deviceId: string, revokedAt: Date): Promise<boolean>;
}

export interface DeviceListItem {
  readonly id: string;
  readonly device_name: string;
  readonly device_type: string;
  readonly created_at: string;
  readonly revoked_at: string | null;
  readonly last_active_at: string | null;
}

export interface DeviceListResult {
  readonly devices: readonly DeviceListItem[];
  readonly total_count: number;
}

export interface DeviceListStore {
  /** Returns up to limit + 1 devices for the current user's keyset page. */
  listDevices(userId: string, cursor: DeviceListCursor | null, limit: number): Promise<DeviceListResult>;
}
